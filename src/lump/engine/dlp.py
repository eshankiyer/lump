"""Sensitive data detection and redaction (DLP).

Beyond regexes for credentials and personal data, three enterprise-grade
techniques are included that keep the protected data itself off the sensor:

* **Exact data match (EDM):** policies ship salted SHA-256 hashes of protected
  values (customer ids, account numbers ...). Tokens in the text are hashed and
  compared, so the sensor never holds the plaintext list.
* **Document fingerprinting:** hashed word shingles of protected documents.
  Pasting a substantial excerpt of a protected document into an AI tool is
  detected even after reformatting.
* **Custom patterns and keywords** from policy (project code names, internal
  id formats).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .normalize import shannon_entropy
from .rules import DLP_RULES, DlpRule
from .types import Finding, Severity, mask, snippet

_SEVERITY = {s.label: s for s in Severity}


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5|4[4-9]|22)|3(?:0[0-5]|[68])|35)")


def card_valid(number: str) -> bool:
    digits = "".join(c for c in number if c.isdigit())
    return bool(_CARD_PREFIX.match(digits)) and luhn_valid(digits)


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AT": 20, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GI": 23,
    "GL": 18, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
    "KZ": 20, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "TN": 24, "TR": 26, "UA": 29,
}


def iban_valid(value: str) -> bool:
    iban = value.replace(" ", "").upper()
    if _IBAN_LENGTHS.get(iban[:2]) != len(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def ssn_valid(match: re.Match[str]) -> bool:
    area, group, serial = match.group(1), match.group(2), match.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    # Well-known advertising / test numbers.
    return f"{area}-{group}-{serial}" not in {"078-05-1120", "219-09-9999", "123-45-6789"}


@dataclass
class CustomPattern:
    id: str
    title: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    flags: str = ""
    redact: bool = True


@dataclass
class DlpConfig:
    keywords: list[str] = field(default_factory=list)  # case-insensitive whole words / phrases
    custom_patterns: list[CustomPattern] = field(default_factory=list)
    edm_hashes: set[str] = field(default_factory=set)  # hex sha256(salt + normalised value)
    edm_salt: str = ""
    fingerprints: dict[str, set[int]] = field(default_factory=dict)  # doc name -> shingle hashes
    fingerprint_threshold: float = 0.2  # share of a doc's shingles that must appear
    fingerprint_min_shingles: int = 6
    detect_source_code: bool = True
    disabled_rules: set[str] = field(default_factory=set)


def edm_hash(value: str, salt: str) -> str:
    return hashlib.sha256((salt + normalise_edm(value)).encode()).hexdigest()


def normalise_edm(value: str) -> str:
    return re.sub(r"[\s\-_.]", "", value).lower()


_EDM_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-_.]{3,63}")
_FP_WORD_RE = re.compile(r"[a-z0-9]+")


def fingerprint_shingles(text: str, n: int = 8) -> set[int]:
    words = _FP_WORD_RE.findall(text.lower())
    out = set()
    for i in range(max(len(words) - n + 1, 0)):
        digest = hashlib.blake2b(" ".join(words[i : i + n]).encode(), digest_size=8).digest()
        out.add(int.from_bytes(digest, "big"))
    return out


_CODE_LINE_RE = re.compile(
    r"^\s*(?:def |class |import |from \S+ import|function |const |let |var |public |private |protected |"
    r"#include|package |using |func |fn |impl |SELECT |INSERT |UPDATE |CREATE TABLE|return |if \(|for \(|while \(|"
    r"try:|except |catch \(|@\w+|\}\s*$|\{\s*$|.*;\s*$|.*\)\s*\{\s*$|.*=>\s*\{?\s*$)",
    re.IGNORECASE,
)


def looks_like_source_code(text: str) -> tuple[bool, float]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 6:
        return False, 0.0
    hits = sum(1 for ln in lines if _CODE_LINE_RE.match(ln))
    ratio = hits / len(lines)
    return ratio >= 0.35, ratio


class DlpDetector:
    name = "dlp"

    def __init__(self, config: DlpConfig | None = None, rules: tuple[DlpRule, ...] = DLP_RULES):
        self.config = config or DlpConfig()
        self.rules = [
            (rule, re.compile(rule.pattern, re.IGNORECASE if "i" in rule.flags else 0))
            for rule in rules
            if rule.id not in self.config.disabled_rules
        ]
        self.custom = [
            (cp, re.compile(cp.pattern, re.IGNORECASE if "i" in cp.flags else 0)) for cp in self.config.custom_patterns
        ]
        self.keyword_re = None
        if self.config.keywords:
            alternatives = "|".join(re.escape(k.strip()) for k in self.config.keywords if k.strip())
            if alternatives:
                self.keyword_re = re.compile(rf"(?<!\w)(?:{alternatives})(?!\w)", re.IGNORECASE)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        taken: list[tuple[int, int]] = []

        def overlaps(start: int, end: int) -> bool:
            return any(start < e and s < end for s, e in taken)

        for rule, regex in self.rules:
            for match in regex.finditer(text):
                value = match.group(rule.group) if rule.group else match.group()
                start, end = match.span(rule.group) if rule.group else match.span()
                if not value or overlaps(start, end):
                    continue
                if not self._validate(rule, match, value):
                    continue
                taken.append((start, end))
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id=rule.id,
                        title=rule.title,
                        severity=_SEVERITY[rule.severity],
                        confidence=0.9 if rule.validator in ("luhn", "iban", "ssn") else 0.8,
                        category=rule.data_type,
                        evidence=mask(value),
                        span=(start, end),
                        atlas=("AML.T0057",),
                        owasp=("LLM02",),
                        attack=rule.attack,
                        metadata={"redact": rule.redact, "data_type": rule.data_type},
                    )
                )
                if len(findings) > 500:
                    return findings

        for cp, regex in self.custom:
            for match in regex.finditer(text):
                if overlaps(*match.span()):
                    continue
                taken.append(match.span())
                findings.append(
                    Finding(
                        detector=self.name, rule_id=cp.id, title=cp.title, severity=cp.severity, confidence=0.85,
                        category="custom." + cp.id.lower(), evidence=mask(match.group()), span=match.span(),
                        atlas=("AML.T0057",), owasp=("LLM02",),
                        metadata={"redact": cp.redact, "data_type": "custom"},
                    )
                )

        if self.keyword_re:
            for match in self.keyword_re.finditer(text):
                findings.append(
                    Finding(
                        detector=self.name, rule_id="DLP-KEYWORD", title="Protected keyword", severity=Severity.MEDIUM,
                        confidence=0.9, category="corp.keyword", evidence=snippet(text, *match.span()), span=match.span(),
                        atlas=("AML.T0057",), owasp=("LLM02",), metadata={"redact": False, "data_type": "keyword"},
                    )
                )

        findings.extend(self._edm(text, overlaps, taken))
        findings.extend(self._fingerprints(text))

        if self.config.detect_source_code:
            is_code, ratio = looks_like_source_code(text)
            if is_code:
                findings.append(
                    Finding(
                        detector=self.name, rule_id="DLP-SOURCE", title="Source code", severity=Severity.LOW,
                        confidence=round(min(0.5 + ratio / 2, 0.95), 3), category="corp.source_code",
                        evidence=f"{len(text.splitlines())} lines, {ratio:.0%} code-like",
                        atlas=("AML.T0057",), owasp=("LLM02",), metadata={"redact": False, "data_type": "source_code"},
                    )
                )
        return findings

    def _validate(self, rule: DlpRule, match: re.Match[str], value: str) -> bool:
        if rule.validator == "luhn":
            return card_valid(value)
        if rule.validator == "iban":
            return iban_valid(value)
        if rule.validator == "ssn":
            return ssn_valid(match)
        if rule.validator == "entropy" or rule.min_entropy:
            if _is_placeholder(value):
                return False
            return shannon_entropy(value) >= rule.min_entropy
        return True

    def _edm(self, text: str, overlaps, taken) -> Iterable[Finding]:
        if not self.config.edm_hashes:
            return []
        out = []
        for match in _EDM_TOKEN_RE.finditer(text):
            if edm_hash(match.group(), self.config.edm_salt) in self.config.edm_hashes:
                if overlaps(*match.span()):
                    continue
                taken.append(match.span())
                out.append(
                    Finding(
                        detector=self.name, rule_id="DLP-EDM", title="Exact match of protected record",
                        severity=Severity.HIGH, confidence=0.99, category="corp.exact_data_match",
                        evidence=mask(match.group(), keep=2), span=match.span(), atlas=("AML.T0057",), owasp=("LLM02",),
                        metadata={"redact": True, "data_type": "edm"},
                    )
                )
        return out

    def _fingerprints(self, text: str) -> Iterable[Finding]:
        if not self.config.fingerprints:
            return []
        grams = fingerprint_shingles(text)
        if not grams:
            return []
        out = []
        for name, doc in self.config.fingerprints.items():
            if not doc:
                continue
            common = len(grams & doc)
            share = common / len(doc)
            if common >= self.config.fingerprint_min_shingles and (share >= self.config.fingerprint_threshold or common >= 40):
                out.append(
                    Finding(
                        detector=self.name, rule_id="DLP-FINGERPRINT", title=f"Excerpt of protected document '{name}'",
                        severity=Severity.HIGH, confidence=round(min(0.6 + share, 0.99), 3), category="corp.document_fingerprint",
                        evidence=f"{common} matching passages ({share:.0%} of document)", atlas=("AML.T0057",), owasp=("LLM02",),
                        metadata={"redact": False, "data_type": "fingerprint", "document": name},
                    )
                )
        return out


_PLACEHOLDER_RE = re.compile(
    r"^(?:x+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\(?\w+\)?s?|changeme|password\d*|secret\d*|example\w*|your[_\-]?\w*|"
    r"placeholder|redacted|dummy|test\w*|sample\w*|none|null|undefined|xxx\w*|os\.environ.*|process\.env.*|getenv.*|env\(.*)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip("\"'")))


def redact(text: str, findings: list[Finding]) -> str:
    """Replace every redactable finding span with a typed placeholder."""

    spans = sorted(
        {(f.span[0], f.span[1], f.metadata.get("data_type", f.category)) for f in findings if f.span and f.metadata.get("redact", True)},
        key=lambda s: s[0],
    )
    out, cursor = [], 0
    for start, end, data_type in spans:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(f"[REDACTED:{data_type.split('.')[-1].upper()}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)
