"""Quantise a trained model and write the shipped ``.lumpml`` file."""

from __future__ import annotations

import time

from ..features import FeatureConfig
from ..model import Model, serialize
from .sources import SOURCES
from .train import CLASSES


def quantize(W):
    """Per-class symmetric int8 quantisation (scale = max |w| / 127).

    Returns (int8 bytes, scales). Clipping outliers was tried and made the
    float/int8 disagreement worse: the largest weights are the most
    informative n-grams.
    """

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


def export(result: dict, features: FeatureConfig, metrics: dict, version: str, augment_count: int = 0,
           check_records=None, max_delta: float = 0.02, min_agreement: float = 0.995) -> bytes:
    """Serialise ``result`` (from :func:`train.train`) after checking that
    int8 quantisation does not change what the model says.

    ``check_records`` (e.g. the validation split) are scored with the float
    weights and with the quantised file; the largest probability change must be
    below ``max_delta`` and warn/block decisions must agree on at least
    ``min_agreement`` of them.
    """

    import math

    import numpy as np

    weight_bytes, scales = quantize(result["W"])
    header = build_header(result, features, metrics, version, scales, augment_count)
    model = Model.from_bytes(serialize(header, weight_bytes))
    if check_records:
        from ..features import featurize

        W, b, T = result["W"], result["b"], float(result["temperature"])
        th = result["thresholds"]
        worst, agree, n = 0.0, 0, 0
        for rec in check_records:
            for vec in featurize(rec.text, features):
                if not vec:
                    continue
                idx = np.fromiter(vec.keys(), dtype=np.int64)
                val = np.fromiter(vec.values(), dtype=np.float64)
                z = (W[idx] * val[:, None]).sum(axis=0) + b
                e = np.exp((z - z.max()) / T)
                p_float = 1.0 - e[model._benign] / e.sum()
                pr = model._probs(model._logits(vec))
                p_int8 = 1.0 - pr[model._benign]
                worst = max(worst, abs(p_float - p_int8))
                same = all((p_float >= th[k]) == (p_int8 >= th[k]) for k in ("warn", "block"))
                agree += same
                n += 1
        rate = agree / n if n else 1.0
        header["quant"]["check"] = {"windows": n, "max_prob_delta": round(worst, 5), "decision_agreement": round(rate, 5)}
        if worst > max_delta or rate < min_agreement or math.isnan(worst):
            raise RuntimeError(f"int8 quantisation changed the model too much: max |dp|={worst:.4f}, "
                               f"decision agreement={rate:.4%} over {n} windows")
    return serialize(header, weight_bytes)
