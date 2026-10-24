"""Built-in model file format and scorer (standard library only).

File layout (little-endian)::

    8 bytes   magic  b"LUMPML" + format major + minor (1, 0)
    4 bytes   uint32 header length H
    H bytes   UTF-8 JSON header (features, classes, bias, int8 scales,
              temperature, thresholds, metrics, provenance, weights sha256)
    D*C bytes int8 weights, feature-major (weight[i*C + c])

The same file is loaded by ``extension/ml.js``. The header carries the
sha256 of the weight block, verified on load, and the header itself is
validated (shapes, finite numbers, sane window sizes), so a corrupt or
truncated file is rejected instead of crashing or silently mis-scoring.
This is an integrity check, not authenticity: anyone who can write the file
can rewrite its header too, so protect the install like any other code.
"""

from __future__ import annotations

import array
import hashlib
import json
import math
import struct
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .features import FeatureConfig, clip, featurize, gram_hash, ngrams, normalize, windows

MAGIC = b"LUMPML\x01\x00"
DEFAULT_MODEL = "injection-v1.lumpml"


class ModelError(RuntimeError):
    pass


@dataclass
class Score:
    p_attack: float  # calibrated probability the text is an attack
    label: str  # most likely class
    probs: dict[str, float]  # per-class calibrated probabilities
    window: int  # index of the highest-scoring window
    windows: int  # number of windows scored
    explanation: list[tuple[str, float]] = field(default_factory=list)


class Model:
    def __init__(self, header: dict, weights: array.array):
        self.header = header
        self.features = FeatureConfig.from_json(header["features"])
        self.classes: list[str] = header["classes"]
        self.bias: list[float] = [float(x) for x in header["bias"]]
        self.scales: list[float] = [float(x) for x in header["quant"]["scales"]]
        self.temperature = float(header.get("temperature", 1.0))
        self.thresholds: dict[str, float] = {k: float(v) for k, v in (header.get("thresholds") or {}).items()}
        self.name = header.get("name", "lump-injection")
        self.version = header.get("version", "0")
        self.weights = weights
        self.C = len(self.classes)
        self._benign = self.classes.index("benign")
        # Pure-Python scoring is used everywhere: on sparse vectors of a few
        # thousand entries it is faster than numpy (per-call overhead
        # dominates) and it is the exact algorithm ml.js implements.

    # -- loading -------------------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes) -> Model:
        """Parse and validate a model file. Any problem raises :class:`ModelError`."""

        if len(data) < 12 or data[:8] != MAGIC:
            raise ModelError("not a Lump model file (bad magic)")
        (hlen,) = struct.unpack("<I", data[8:12])
        if 12 + hlen > len(data):
            raise ModelError("truncated model header")
        try:
            header = json.loads(data[12 : 12 + hlen].decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ModelError(f"unreadable model header: {exc}") from exc
        validate_header(header)
        blob = data[12 + hlen :]
        D = 1 << int(header["features"]["hash_bits"])
        C = len(header["classes"])
        if len(blob) != D * C:
            raise ModelError(f"weight block is {len(blob)} bytes, expected {D * C}")
        if hashlib.sha256(blob).hexdigest() != header.get("weights_sha256"):
            raise ModelError("weight checksum mismatch: model file is corrupt or was modified")
        weights = array.array("b")
        weights.frombytes(blob)
        return cls(header, weights)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Model:
        if path is None:
            data = resources.files("lump.data.models").joinpath(DEFAULT_MODEL).read_bytes()
        else:
            data = Path(path).read_bytes()
        return cls.from_bytes(data)

    def to_bytes(self) -> bytes:
        return serialize(self.header, self.weights.tobytes())

    # -- scoring -------------------------------------------------------------

    def _logits(self, vec: dict[int, float]) -> list[float]:
        C = self.C
        q = self.weights
        acc = [0.0] * C
        if C == 3:
            z0 = z1 = z2 = 0.0
            for i, v in vec.items():
                o = i * 3
                z0 += q[o] * v
                z1 += q[o + 1] * v
                z2 += q[o + 2] * v
            acc = [z0, z1, z2]
        else:
            for i, v in vec.items():
                o = i * C
                for c in range(C):
                    acc[c] += q[o + c] * v
        return [acc[c] * self.scales[c] + self.bias[c] for c in range(C)]

    def _probs(self, logits: list[float]) -> list[float]:
        t = self.temperature
        m = max(logits)
        e = [math.exp((z - m) / t) for z in logits]
        s = sum(e)
        return [x / s for x in e]

    def score(self, text: str, explain: bool = False, top_k: int = 6, limit: int | None = None) -> Score:
        """Score ``text``; ``limit`` bounds the normalised characters scored (head + tail)."""

        vecs = featurize(text, self.features, limit)
        best_p, best_probs, best_w = -1.0, None, 0
        for w, vec in enumerate(vecs):
            probs = self._probs(self._logits(vec))
            p = 1.0 - probs[self._benign]
            if p > best_p:
                best_p, best_probs, best_w = p, probs, w
        assert best_probs is not None
        label = self.classes[max(range(self.C), key=lambda c: best_probs[c])]
        result = Score(
            p_attack=best_p,
            label=label,
            probs={c: best_probs[i] for i, c in enumerate(self.classes)},
            window=best_w,
            windows=len(vecs),
        )
        if explain:
            result.explanation = self.explain(text, best_w, top_k, limit)
        return result

    def explain(self, text: str, window: int = 0, top_k: int = 6, limit: int | None = None) -> list[tuple[str, float]]:
        """Top n-grams pushing the text towards an attack class (word n-grams preferred).

        A gram's push is ``sign * tf * (w_attack - w_benign)`` for the attack
        class it favours most, where ``sign`` is its hash sign and ``tf`` the
        model's sub-linear term frequency. The L2 normalisation is common to
        all grams, so it does not change the ranking and is left out.
        """

        cfg = self.features
        norm = clip(normalize(text, cfg.digits_to_zero), limit)
        wins = windows(norm, cfg)
        counts: dict[str, int] = {}
        for g in ngrams(wins[min(window, len(wins) - 1)], cfg):
            counts[g] = counts.get(g, 0) + 1
        mask = (1 << cfg.hash_bits) - 1
        C, b = self.C, self._benign
        q, s = self.weights, self.scales
        contrib: dict[str, float] = {}
        for g, n in counts.items():
            h = gram_hash(g)
            o = (h & mask) * C
            sign = -1.0 if (cfg.signed_hash and h >> 31) else 1.0
            push = max(sign * (q[o + c] * s[c] - q[o + b] * s[b]) for c in range(C) if c != b)
            contrib[g] = push * (1.0 + math.log(n))
        ranked = sorted(((g, v) for g, v in contrib.items() if v > 0), key=lambda kv: -kv[1])
        words = [(g[2:], round(v, 4)) for g, v in ranked if g.startswith("w:")]
        chars = [(g[2:].strip(), round(v, 4)) for g, v in ranked if g.startswith("c:")]
        return (words + chars)[:top_k]

    def info(self) -> dict:
        keep = ("name", "version", "created", "classes", "temperature", "thresholds", "metrics", "training", "features")
        return {k: self.header[k] for k in keep if k in self.header}


def _reject_constant(name: str):
    raise ValueError(f"{name} is not allowed in a model header")


def _number(value, what: str, lo: float | None = None, hi: float | None = None, lo_open: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ModelError(f"model header: {what} must be a finite number")
    if lo is not None and (value <= lo if lo_open else value < lo):
        raise ModelError(f"model header: {what} = {value} is out of range")
    if hi is not None and value > hi:
        raise ModelError(f"model header: {what} = {value} is out of range")
    return float(value)


def validate_header(header) -> None:
    """Reject headers that would crash, hang or silently mis-score at inspection time."""

    if not isinstance(header, dict):
        raise ModelError("model header must be a JSON object")
    try:
        classes = header["classes"]
        feats = header["features"]
        bias = header["bias"]
        scales = header["quant"]["scales"]
    except (KeyError, TypeError) as exc:
        raise ModelError(f"model header is missing {exc}") from exc
    if (not isinstance(classes, list) or not all(isinstance(c, str) for c in classes) or "benign" not in classes
            or len(classes) < 2 or len(set(classes)) != len(classes)):
        raise ModelError("model header: classes must list 'benign' and at least one attack class")
    C = len(classes)
    if not isinstance(bias, list) or not isinstance(scales, list) or len(bias) != C or len(scales) != C:
        raise ModelError("model header: bias and scales need one entry per class")
    for i in range(C):
        _number(bias[i], "bias")
        _number(scales[i], "scale", lo=0.0, lo_open=True)
    _number(header.get("temperature", 1.0), "temperature", lo=0.0, lo_open=True)
    thresholds = header.get("thresholds")
    if thresholds is not None and not isinstance(thresholds, dict):
        raise ModelError("model header: thresholds must be an object")
    for name, value in (thresholds or {}).items():
        _number(value, f"threshold {name}", lo=0.0, hi=1.0, lo_open=True)
    if not isinstance(feats, dict):
        raise ModelError("model header: features must be an object")
    try:
        cfg = FeatureConfig.from_json(feats)
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelError(f"model header: bad features ({exc})") from exc
    if not isinstance(cfg.hash_bits, int) or not 8 <= cfg.hash_bits <= 24:
        raise ModelError("model header: hash_bits must be an integer between 8 and 24")
    if not (isinstance(cfg.max_chars, int) and isinstance(cfg.window_stride, int)
            and 0 < cfg.window_stride <= cfg.max_chars):
        raise ModelError("model header: need 0 < window_stride <= max_chars")
    if not cfg.word_ngrams and not cfg.char_ngrams:
        raise ModelError("model header: no n-gram features configured")
    for n in tuple(cfg.word_ngrams) + tuple(cfg.char_ngrams):
        if not isinstance(n, int) or not 1 <= n <= 8:
            raise ModelError("model header: n-gram sizes must be integers between 1 and 8")


def serialize(header: dict, weight_bytes: bytes) -> bytes:
    header = dict(header)
    header["weights_sha256"] = hashlib.sha256(weight_bytes).hexdigest()
    raw = json.dumps(header, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return MAGIC + struct.pack("<I", len(raw)) + raw + weight_bytes


_DEFAULT: Model | None = None


def default_model() -> Model | None:
    """The bundled model, loaded once; ``None`` if the package ships without one."""

    global _DEFAULT
    if _DEFAULT is None:
        try:
            _DEFAULT = Model.load()
        except (OSError, ModuleNotFoundError, ModelError):
            return None
    return _DEFAULT
