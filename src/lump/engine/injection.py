"""Prompt injection and jailbreak detection.

Three independent signal families are combined:

1. Pattern rules (``rules.INJECTION_RULES``) over every de-obfuscated view.
2. Known-attack similarity: word-shingle containment against a signature set
   of widely circulated jailbreak templates, robust to light paraphrasing.
3. Obfuscation signals: hidden Unicode payloads, bidi overrides, homoglyphs,
   encoded natural language. Hiding text from a human reader is itself a
   strong indicator when the hidden text carries instructions.

Scores are weighted by trust: the same sentence is far more suspicious inside
a web page or tool result (indirect injection) than typed by the user.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources

from .normalize import Normalized
from .rules import INJECTION_RULES, PatternRule
from .types import Context, Finding, Severity, snippet

_FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def compile_pattern(pattern: str, flags: str) -> re.Pattern[str]:
    value = 0
    for flag in flags:
        value |= _FLAG_MAP[flag]
    return re.compile(pattern, value)


def severity_for(weight: float) -> Severity:
    if weight >= 0.85:
        return Severity.CRITICAL
    if weight >= 0.6:
        return Severity.HIGH
    if weight >= 0.35:
        return Severity.MEDIUM
    if weight >= 0.15:
        return Severity.LOW
    return Severity.INFO


def noisy_or(weights: list[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(w, 0.99))
    return 1.0 - remaining


_OBFUSCATED_VIEWS = {"unicode_tags", "variation_selectors", "base64", "hex", "percent", "rot13", "despaced", "deleet"}
_SHINGLE_WORD_RE = re.compile(r"[a-z0-9']+")


def shingles(text: str, n: int = 3) -> set[tuple[str, ...]]:
    words = _SHINGLE_WORD_RE.findall(text.lower())
    if len(words) < n:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


@dataclass(frozen=True)
class Signature:
    id: str
    family: str
    text: str
    grams: frozenset[tuple[str, ...]]


def load_signatures() -> list[Signature]:
    raw = resources.files("lump.data").joinpath("jailbreak_signatures.json").read_text("utf-8")
    data = json.loads(raw)
    return [
        Signature(s["id"], s["family"], s["text"], frozenset(shingles(s["text"])))
        for s in data["signatures"]
    ]


class InjectionDetector:
    name = "injection"

    def __init__(self, rules: tuple[PatternRule, ...] = INJECTION_RULES, signatures: list[Signature] | None = None):
        self.rules = [(rule, compile_pattern(rule.pattern, rule.flags)) for rule in rules]
        self.signatures = signatures if signatures is not None else load_signatures()

    def score(self, norm: Normalized, ctx: Context) -> tuple[float, list[Finding]]:
        findings = self.detect(norm, ctx)
        weights = [f.metadata.get("weight", f.confidence) for f in findings if f.rule_id != "PI-000"]
        return noisy_or(weights), findings

    def detect(self, norm: Normalized, ctx: Context) -> list[Finding]:
        untrusted = ctx.untrusted
        findings: list[Finding] = []
        weights: list[float] = []

        for rule, regex in self.rules:
            for label, text in norm.views:
                match = regex.search(text)
                if not match:
                    continue
                weight = rule.weight * (rule.untrusted_boost if untrusted else rule.trusted_factor)
                obfuscated = label in _OBFUSCATED_VIEWS
                if obfuscated:
                    # Hiding an instruction from the human reader escalates it.
                    weight *= 1.3
                weight = min(weight, 0.97)
                weights.append(weight)
                span = (match.start(), match.end()) if label == "original" else None
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id=rule.id,
                        title=rule.title + (f" (hidden in {label.replace('_', ' ')})" if obfuscated else ""),
                        severity=severity_for(weight),
                        confidence=round(weight, 3),
                        category=rule.category,
                        evidence=snippet(text, match.start(), match.end()),
                        span=span,
                        atlas=rule.atlas + (("AML.T0051.001",) if untrusted and "AML.T0051.001" not in rule.atlas and rule.category.startswith("prompt_injection") else ()),
                        owasp=rule.owasp,
                        metadata={"weight": round(weight, 3), "view": label},
                    )
                )
                break  # first view that matches is enough for this rule

        findings.extend(self._signature_findings(norm, untrusted, weights))
        findings.extend(self._obfuscation_findings(norm, untrusted, weights, bool(findings)))

        distinct = {f.rule_id for f in findings}
        combined = noisy_or(weights)
        if len(distinct) >= 2 and combined >= 0.75:
            findings.insert(
                0,
                Finding(
                    detector=self.name,
                    rule_id="PI-000",
                    title=f"Multiple injection indicators ({len(distinct)})",
                    severity=severity_for(combined),
                    confidence=round(combined, 3),
                    category="prompt_injection.aggregate",
                    evidence=", ".join(sorted(distinct))[:120],
                    atlas=("AML.T0051.001",) if untrusted else ("AML.T0051",),
                    owasp=("LLM01",),
                    metadata={"weight": round(combined, 3), "indicators": sorted(distinct)},
                ),
            )
        return findings

    def _signature_findings(self, norm: Normalized, untrusted: bool, weights: list[float]) -> list[Finding]:
        grams: set[tuple[str, ...]] = set()
        for _, text in norm.views:
            grams |= shingles(text)
        if not grams:
            return []
        best: tuple[float, Signature] | None = None
        for sig in self.signatures:
            if not sig.grams:
                continue
            containment = len(sig.grams & grams) / len(sig.grams)
            if containment >= 0.6 and (best is None or containment > best[0]):
                best = (containment, sig)
        if best is None:
            return []
        containment, sig = best
        weight = min(0.45 + 0.45 * containment + (0.05 if untrusted else 0.0), 0.95)
        weights.append(weight)
        return [
            Finding(
                detector=self.name,
                rule_id=sig.id,
                title=f"Known jailbreak template: {sig.family}",
                severity=severity_for(weight),
                confidence=round(weight, 3),
                category="jailbreak.known_template",
                evidence=sig.text[:120],
                atlas=("AML.T0054",),
                owasp=("LLM01",),
                metadata={"weight": round(weight, 3), "containment": round(containment, 3), "family": sig.family},
            )
        ]

    def _obfuscation_findings(
        self, norm: Normalized, untrusted: bool, weights: list[float], has_instructions: bool
    ) -> list[Finding]:
        out: list[Finding] = []
        boost = 1.2 if untrusted else 1.0
        for kind, detail in norm.signals:
            if kind in ("unicode_tags", "variation_selectors"):
                payload = next((p for k, p in norm.hidden_payloads if k == kind), "")
                weight = 0.75 if sum(c.isalpha() for c in payload) >= 6 else 0.4
                rule_id, title = ("OB-001", "Invisible Unicode tag payload (ASCII smuggling)") if kind == "unicode_tags" else (
                    "OB-002", "Data hidden in variation selectors")
                evidence = " ".join(payload.split())[:120]
            elif kind == "bidi_control":
                weight, rule_id, title, evidence = 0.35, "OB-003", "Bidirectional text override", detail
            elif kind == "zero_width":
                if norm.invisible_count < 3:
                    continue
                weight, rule_id, title, evidence = 0.25, "OB-004", "Zero-width characters inside text", detail
            elif kind == "homoglyphs":
                weight, rule_id, title, evidence = 0.3, "OB-005", "Homoglyph (look-alike) characters", detail
            elif kind == "encoded_overflow":
                # Too many encoded blobs to inspect them all: the classic way to
                # bury one payload among decoys. Never pass silently.
                weight, rule_id, title, evidence = 0.4, "OB-007", "More encoded segments than could be inspected", detail
            elif kind.startswith("encoded_"):
                # Encoded prose alone is weak; encoded prose that also carries
                # instructions is already escalated through the rule views.
                weight = 0.3 if has_instructions else 0.15
                rule_id, title, evidence = "OB-006", f"Encoded natural-language payload ({kind[8:]})", detail
            else:
                continue
            weight = min(weight * boost, 0.95)
            weights.append(weight)
            out.append(
                Finding(
                    detector=self.name,
                    rule_id=rule_id,
                    title=title,
                    severity=severity_for(weight),
                    confidence=round(weight, 3),
                    category="obfuscation." + kind,
                    evidence=evidence,
                    atlas=("AML.T0051", "AML.T0043"),
                    owasp=("LLM01",),
                    attack=("T1027",),
                    metadata={"weight": round(weight, 3)},
                )
            )
        # Deduplicate repeated signal kinds (e.g. several encoded segments).
        seen: set[str] = set()
        unique = []
        for f in out:
            if f.rule_id in seen:
                continue
            seen.add(f.rule_id)
            unique.append(f)
        return unique
