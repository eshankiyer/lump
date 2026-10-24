"""Quantise a trained model and write the shipped ``.lumpml`` file."""

from __future__ import annotations

import time

from ..features import FeatureConfig
from ..model import Model, serialize
from .sources import SOURCES
from .train import CLASSES


def quantize(W):
    """Per-class symmetric int8 quantisation. Returns (int8 bytes, scales)."""

    import numpy as np

    scales = np.maximum(np.abs(W).max(axis=0), 1e-12) / 127.0
    q = np.clip(np.rint(W / scales), -127, 127).astype(np.int8)
    return q.tobytes(order="C"), [float(s) for s in scales]


def build_header(result: dict, features: FeatureConfig, metrics: dict, version: str, scales: list[float],
                 augment_count: int = 0) -> dict:
    return {
        "name": "lump-injection",
        "version": version,
        "created": time.strftime("%Y-%m-%d", time.gmtime()),
        "format": 1,
        "classes": list(CLASSES),
        "features": features.to_json(),
        "bias": [float(x) for x in result["b"]],
        "quant": {"dtype": "int8", "layout": "feature-major", "scales": scales},
        "temperature": float(result["temperature"]),
        "thresholds": result["thresholds"],
        "metrics": metrics,
        "training": {
            "algorithm": "multinomial logistic regression on hashed word 1-2 / char 3-5 grams (Adam, early stopping), "
                         "temperature-scaled",
            "class_counts": result.get("class_counts", {}),
            "sources": [{"id": s.id, "license": s.license, "role": s.role, "revision": s.revision} for s in SOURCES],
            "augmentation": {"id": "lump/reworded-augment", "license": "Apache-2.0", "records": augment_count},
        },
    }


def export(result: dict, features: FeatureConfig, metrics: dict, version: str, augment_count: int = 0) -> bytes:
    """Serialise ``result`` (from :func:`train.train`) after checking quantisation error."""

    import numpy as np

    weight_bytes, scales = quantize(result["W"])
    header = build_header(result, features, metrics, version, scales, augment_count)
    blob = serialize(header, weight_bytes)
    model = Model.from_bytes(blob)
    # Quantisation must not move the decision: compare float vs int8 logits on
    # random sparse probes drawn from the trained weight rows.
    rng = np.random.default_rng(0)
    D = 1 << features.hash_bits
    worst = 0.0
    for _ in range(200):
        idx = rng.choice(D, size=400, replace=False)
        val = rng.normal(size=400)
        val /= np.linalg.norm(val)
        exact = (result["W"][idx] * val[:, None]).sum(axis=0) + result["b"]
        approx = np.asarray(model._logits(dict(zip(idx.tolist(), val.tolist(), strict=True))))
        worst = max(worst, float(np.abs(exact - approx).max()))
    if worst > 0.05:
        raise RuntimeError(f"int8 quantisation error too large (max logit delta {worst:.4f})")
    return blob
