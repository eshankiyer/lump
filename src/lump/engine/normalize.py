"""Text canonicalisation and de-obfuscation.

Attackers hide instructions from humans (and from naive filters) with
invisible Unicode, homoglyphs, encodings and spacing tricks. Before any
detector runs, the engine builds several *views* of the input — the original,
a canonical form, and every hidden or encoded layer it can recover — and
detectors scan all of them. Each recovered layer is also reported as an
obfuscation signal in its own right.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Zero-width and formatting characters that render as nothing.
_ZERO_WIDTH = "\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u180e\u00ad"
# Bidirectional overrides/isolates ("Trojan Source").
_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"
_INVISIBLE_RE = re.compile(f"[{_ZERO_WIDTH}{_BIDI}]")
_BIDI_RE = re.compile(f"[{_BIDI}]")
# Unicode "tag" characters (U+E0000-U+E007F) mirror ASCII and are invisible:
# the basis of "ASCII smuggling" attacks.
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")
# Variation selectors can carry one byte each ("emoji smuggling").
_VS_RE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{4,}")

# Common Cyrillic / Greek / other look-alikes of Latin letters.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
        "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
        "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "υ": "u", "ε": "e",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
        "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
        "ı": "i", "ℓ": "l", "ⅰ": "i", "ⅴ": "v", "ⅹ": "x",
    }
)
# _CONFUSABLES is a str.maketrans table keyed by ordinal; recover the chars.
_CONFUSABLE_CHARS = frozenset(chr(k) for k in _CONFUSABLES)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LEET_WORD_RE = re.compile(r"\b(?=[A-Za-z0-9@$]*[A-Za-z])(?=[A-Za-z0-9@$]*[0-9@$])[A-Za-z0-9@$]{3,}\b")
# "i g n o r e   a l l" / "i.g.n.o.r.e" — letters separated by single spacers.
_SPACED_RE = re.compile(r"\b(?:[A-Za-z][ .\-_*]){4,}[A-Za-z]\b")

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")

MAX_DECODED_SEGMENTS = 24
MAX_SEGMENT_CHARS = 16384


@dataclass
class Normalized:
    original: str
    canonical: str
    views: list[tuple[str, str]] = field(default_factory=list)
    signals: list[tuple[str, str]] = field(default_factory=list)  # (kind, detail)
    invisible_count: int = 0
    confusable_count: int = 0
    hidden_payloads: list[tuple[str, str]] = field(default_factory=list)  # (kind, decoded text)

    def all_texts(self) -> list[tuple[str, str]]:
        return self.views


def _printable_ratio(data: str) -> float:
    if not data:
        return 0.0
    ok = sum(1 for ch in data if ch.isprintable() or ch in "\n\r\t")
    return ok / len(data)


def _looks_textual(data: str) -> bool:
    if len(data) < 6 or _printable_ratio(data) < 0.9:
        return False
    letters = sum(ch.isalpha() for ch in data)
    spaces = data.count(" ")
    return letters >= len(data) * 0.5 and spaces >= 1


def reveal_tags(text: str) -> str:
    """Decode Unicode tag characters back to the ASCII they mirror."""

    out = []
    for match in _TAG_RE.finditer(text):
        chunk = "".join(chr(ord(ch) - 0xE0000) for ch in match.group() if 0x20 <= ord(ch) - 0xE0000 < 0x7F)
        if chunk:
            out.append(chunk)
    return " ".join(out)


def decode_variation_selectors(text: str) -> str:
    out = []
    for match in _VS_RE.finditer(text):
        raw = bytearray()
        for ch in match.group():
            cp = ord(ch)
            if 0xFE00 <= cp <= 0xFE0F:
                raw.append(cp - 0xFE00)
            else:
                raw.append(cp - 0xE0100 + 16)
        decoded = raw.decode("utf-8", errors="ignore")
        if _printable_ratio(decoded) > 0.9 and len(decoded) >= 4:
            out.append(decoded)
    return " ".join(out)


def strip_invisible(text: str) -> str:
    text = _INVISIBLE_RE.sub("", text)
    text = _TAG_RE.sub("", text)
    return re.sub("[\ufe00-\ufe0f\U000e0100-\U000e01ef]", "", text)


def fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLES)


def canonicalize(text: str) -> str:
    """NFKC + strip invisibles + fold homoglyphs + collapse whitespace runs."""

    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = fold_confusables(text)
    return re.sub(r"[ \t\u00a0\u3000]+", " ", text)


def _decode_b64(candidate: str) -> str | None:
    s = candidate.strip()
    if len(s) % 4 == 1:
        return None
    padded = s + "=" * (-len(s) % 4)
    try:
        if "-" in s or "_" in s:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if _looks_textual(decoded) else None


def _decode_hex(candidate: str) -> str | None:
    try:
        decoded = bytes.fromhex(candidate).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _looks_textual(decoded) else None


def _decode_pct(candidate: str) -> str | None:
    decoded = urllib.parse.unquote(candidate)
    return decoded if decoded != candidate and _looks_textual(decoded) else None


def decode_layers(text: str, depth: int = 2) -> list[tuple[str, str]]:
    """Recover base64 / hex / percent-encoded natural-language payloads."""

    found: list[tuple[str, str]] = []
    frontier = [text]
    seen: set[tuple[str, str]] = set()  # per decoder: a hex run also matches the base64 pattern
    for _ in range(depth):
        nxt: list[str] = []
        for chunk in frontier:
            for kind, regex, decoder in (
                ("base64", _B64_RE, _decode_b64),
                ("hex", _HEX_RE, _decode_hex),
                ("percent", _PCT_RE, _decode_pct),
            ):
                for match in regex.finditer(chunk):
                    if len(found) >= MAX_DECODED_SEGMENTS:
                        return found
                    candidate = match.group()[:MAX_SEGMENT_CHARS]
                    if (kind, candidate) in seen:
                        continue
                    seen.add((kind, candidate))
                    decoded = decoder(candidate)
                    if decoded:
                        found.append((kind, decoded))
                        nxt.append(decoded)
        frontier = nxt
        if not frontier:
            break
    return found


def _collapse_spaced(text: str) -> str:
    return _SPACED_RE.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), text)


def _deleet(text: str) -> str:
    return _LEET_WORD_RE.sub(lambda m: m.group().translate(_LEET), text)


def normalize(text: str) -> Normalized:
    canonical = canonicalize(text)
    norm = Normalized(original=text, canonical=canonical)
    norm.views.append(("original", text))
    if canonical != text:
        norm.views.append(("canonical", canonical))

    norm.invisible_count = len(_INVISIBLE_RE.findall(text))
    if _BIDI_RE.search(text):
        norm.signals.append(("bidi_control", "bidirectional override characters present"))
    if norm.invisible_count:
        norm.signals.append(("zero_width", f"{norm.invisible_count} invisible formatting characters"))

    tags = reveal_tags(text)
    if tags:
        norm.signals.append(("unicode_tags", "hidden text encoded in Unicode tag characters"))
        norm.hidden_payloads.append(("unicode_tags", tags))
        norm.views.append(("unicode_tags", tags))

    vs = decode_variation_selectors(text)
    if vs:
        norm.signals.append(("variation_selectors", "hidden bytes encoded in variation selectors"))
        norm.hidden_payloads.append(("variation_selectors", vs))
        norm.views.append(("variation_selectors", vs))

    norm.confusable_count = sum(1 for ch in text if ch in _CONFUSABLE_CHARS)
    # Mixed-script words are a homoglyph signal; whole-script Cyrillic/Greek text is not.
    if norm.confusable_count and _has_mixed_script_word(text):
        norm.signals.append(("homoglyphs", f"{norm.confusable_count} look-alike characters in mixed-script words"))

    spaced = _collapse_spaced(canonical)
    if spaced != canonical:
        norm.views.append(("despaced", spaced))
    leet = _deleet(canonical)
    if leet != canonical:
        norm.views.append(("deleet", leet))

    for kind, decoded in decode_layers(canonical):
        norm.signals.append((f"encoded_{kind}", f"{kind}-encoded natural language payload"))
        norm.hidden_payloads.append((kind, decoded))
        norm.views.append((kind, canonicalize(decoded)))

    if re.search(r"\brot[- ]?13\b", canonical, re.IGNORECASE):
        norm.views.append(("rot13", codecs.decode(canonical, "rot_13")))
    return norm


_WORD_RE = re.compile(r"\w{3,}", re.UNICODE)


def _has_mixed_script_word(text: str) -> bool:
    for word in _WORD_RE.findall(text):
        has_confusable = any(ch in _CONFUSABLE_CHARS for ch in word)
        has_ascii_letter = any("a" <= ch.lower() <= "z" for ch in word)
        if has_confusable and has_ascii_letter:
            return True
    return False


def shannon_entropy(data: str) -> float:
    import math
    from collections import Counter

    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
