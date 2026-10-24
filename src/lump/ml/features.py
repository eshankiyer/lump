"""Hashed n-gram featurisation shared bit-for-bit with the browser extension.

The built-in model never sees raw text. Text is normalised, split into word
and character n-grams, and each n-gram is hashed (CRC-32 of a type prefix plus
its UTF-8 bytes) into a fixed-size feature space. CRC-32 is used because
``zlib.crc32`` runs in C, which keeps featurisation of a 2,000-character
prompt under 2 ms in CPython, and it is a few lines of table code in JS. The same algorithm is implemented in
``extension/ml.js``; ``tests/test_ml_parity.py`` and the Node parity test pin
the two together on a shared fixture, so a prompt gets the same score in the
browser as at the gateway.

Everything here is standard library only.
"""

from __future__ import annotations

import math
import re
import unicodedata
import zlib
from dataclasses import dataclass

# Characters removed before featurisation (mirrors engine.normalize, and the
# list is exported to JS). Kept local so the ML feature space never changes
# silently when the rule engine's normaliser evolves.
_INVISIBLE = (
    "\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u180e\u00ad"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE}]")
_TAGS_VS_RE = re.compile("[\U000e0000-\U000e007f\ufe00-\ufe0f\U000e0100-\U000e01ef]")
# Unpaired surrogates (possible after JSON decoding) cannot be UTF-8 encoded;
# JS TextEncoder turns them into U+FFFD, so do the same up front.
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
# Explicit whitespace class: Python's and JavaScript's \s differ at the edges.
_WS_CLASS = "\t\n\x0b\x0c\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
_WS_RE = re.compile(f"[{_WS_CLASS}]+")
_WORD_RE = re.compile(r"[a-z0-9]+")
_DIGITS_RE = re.compile(r"[0-9]")

_CHAR_SEED = zlib.crc32(b"c:")
_WORD_SEED = zlib.crc32(b"w:")


def crc32(data: bytes, seed: int = 0) -> int:
    """CRC-32 (IEEE), continuing from ``seed`` — ``crc32(b, crc32(a)) == crc32(a + b)``."""

    return zlib.crc32(data, seed)


@dataclass(frozen=True)
class FeatureConfig:
    """Featurisation hyper-parameters. Serialised into the model file header."""

    hash_bits: int = 18
    word_ngrams: tuple[int, ...] = (1, 2)
    char_ngrams: tuple[int, ...] = (3, 4, 5)
    max_chars: int = 2000  # longer text is scored window by window
    window_stride: int = 1500
    digits_to_zero: bool = True  # "v2" and "v7" share features; ids/years do not explode the space
    signed_hash: bool = True  # top hash bit chooses +/-1, cancelling collision bias

    def to_json(self) -> dict:
        return {
            "hash_bits": self.hash_bits,
            "word_ngrams": list(self.word_ngrams),
            "char_ngrams": list(self.char_ngrams),
            "max_chars": self.max_chars,
            "window_stride": self.window_stride,
            "digits_to_zero": self.digits_to_zero,
            "signed_hash": self.signed_hash,
        }

    @classmethod
    def from_json(cls, data: dict) -> FeatureConfig:
        return cls(
            hash_bits=int(data["hash_bits"]),
            word_ngrams=tuple(int(n) for n in data["word_ngrams"]),
            char_ngrams=tuple(int(n) for n in data["char_ngrams"]),
            max_chars=int(data["max_chars"]),
            window_stride=int(data["window_stride"]),
            digits_to_zero=bool(data["digits_to_zero"]),
            signed_hash=bool(data["signed_hash"]),
        )


def normalize(text: str, digits_to_zero: bool = True) -> str:
    """Canonical lower-case form used for features (NFKC, invisibles removed)."""

    text = _SURROGATE_RE.sub("�", text)
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_RE.sub("", text)
    text = _TAGS_VS_RE.sub("", text)
    text = text.lower()
    if digits_to_zero:
        text = _DIGITS_RE.sub("0", text)
    return _WS_RE.sub(" ", text).strip(" ")


def ngrams(norm: str, cfg: FeatureConfig) -> list[str]:
    """Typed n-gram strings for already-normalised text (``w:``, ``c:`` prefixes)."""

    out: list[str] = []
    words = _WORD_RE.findall(norm)
    for n in cfg.word_ngrams:
        for i in range(len(words) - n + 1):
            out.append("w:" + " ".join(words[i : i + n]))
    padded = " " + norm + " "
    chars = list(padded)  # code points, matching Array.from() in JS
    for n in cfg.char_ngrams:
        for i in range(len(chars) - n + 1):
            gram = "".join(chars[i : i + n])
            if gram.strip(" "):  # after normalize() the only whitespace left is " "
                out.append("c:" + gram)
    return out


def gram_hash(gram: str) -> int:
    """Hash of one typed n-gram string as produced by :func:`ngrams`."""

    return zlib.crc32(gram.encode("utf-8"))


def hashed_ngrams(norm: str, cfg: FeatureConfig) -> list[int]:
    """Hashes of every n-gram of ``norm`` — same values as ``map(gram_hash, ngrams(norm))``
    but without building the strings (this is the hot path)."""

    out: list[int] = []
    words = _WORD_RE.findall(norm)
    for n in cfg.word_ngrams:
        for i in range(len(words) - n + 1):
            out.append(zlib.crc32(" ".join(words[i : i + n]).encode("utf-8"), _WORD_SEED))
    padded = " " + norm + " "
    data = padded.encode("utf-8")
    if len(data) == len(padded):  # pure ASCII: byte offsets are code-point offsets
        offs: range | list[int] = range(len(data) + 1)
    else:
        offs = [0]
        for ch in padded:
            offs.append(offs[-1] + len(ch.encode("utf-8")))
    n_cp = len(padded)
    for n in cfg.char_ngrams:
        for i in range(n_cp - n + 1):
            gram = data[offs[i] : offs[i + n]]
            if gram.strip(b" "):
                out.append(zlib.crc32(gram, _CHAR_SEED))
    return out


def vectorize(hashes: list[int], cfg: FeatureConfig) -> dict[int, float]:
    """Fold n-gram hashes into a sparse, L2-normalised {index: value} vector."""

    mask = (1 << cfg.hash_bits) - 1
    counts: dict[int, int] = {}
    for h in hashes:
        idx = h & mask
        counts[idx] = counts.get(idx, 0) + (-1 if (cfg.signed_hash and h >> 31) else 1)
    # Sub-linear term frequency then L2 norm: long text does not dominate and
    # one repeated phrase cannot saturate the score.
    vec: dict[int, float] = {}
    sq = 0.0
    for idx, c in counts.items():
        if c:
            v = math.copysign(1.0 + math.log(abs(c)), c)
            vec[idx] = v
            sq += v * v
    if sq > 0:
        inv = 1.0 / math.sqrt(sq)
        for idx in vec:
            vec[idx] *= inv
    return vec


def hash_features(grams: list[str], cfg: FeatureConfig) -> dict[int, float]:
    """Vector for a list of typed n-gram strings (slow path, used for tests/explanations)."""

    return vectorize([gram_hash(g) for g in grams], cfg)


def windows(norm: str, cfg: FeatureConfig) -> list[str]:
    """Split long normalised text into overlapping windows (code-point based)."""

    chars = list(norm)
    if len(chars) <= cfg.max_chars:
        return [norm]
    out = []
    start = 0
    while start < len(chars):
        out.append("".join(chars[start : start + cfg.max_chars]))
        if start + cfg.max_chars >= len(chars):
            break
        start += cfg.window_stride
    return out


def featurize(text: str, cfg: FeatureConfig) -> list[dict[int, float]]:
    """Feature vectors for every window of ``text``."""

    norm = normalize(text, cfg.digits_to_zero)
    return [vectorize(hashed_ngrams(w, cfg), cfg) for w in windows(norm, cfg)]
