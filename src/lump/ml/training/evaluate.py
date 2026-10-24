"""Evaluation for the built-in classifier: ML alone, rules alone, and the ensemble.

Every metric is reported per evaluation set so a strong in-distribution score
cannot hide a weak out-of-distribution one. The "rules" column is the
existing deterministic engine (verdict != allow), so the table answers the
question that motivated the model: how many reworded attacks the rules miss
that the ML layer catches, and at what false-positive cost.
"""

from __future__ import annotations

from dataclasses import dataclass

from .corpus import Record


@dataclass
class Metrics:
    n: int
    attacks: int
    auc: float
    precision: float
    recall: float
    f1: float
    fpr: float

    def row(self) -> str:
        return (f"n={self.n:6} atk={self.attacks:6}  AUC={self.auc:.4f}  P={self.precision:.3f}  "
                f"R={self.recall:.3f}  F1={self.f1:.3f}  FPR={self.fpr:.4f}")


def roc_auc(scores, labels) -> float:
    import numpy as np

    scores = np.asarray(scores, dtype=np.float64)
    labels = np.asarray(labels)
    pos, neg = int((labels == 1).sum()), int((labels == 0).sum())
    if not pos or not neg:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores))
    s = scores[order]
    i = 0
    while i < len(s):  # average ranks for ties
        j = i
        while j + 1 < len(s) and s[j + 1] == s[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return float((ranks[labels == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def binary_metrics(flags, labels, scores=None) -> Metrics:
    import numpy as np

    flags = np.asarray(flags, dtype=bool)
    labels = np.asarray(labels)
    tp = int((flags & (labels == 1)).sum())
    fp = int((flags & (labels == 0)).sum())
    fn = int((~flags & (labels == 1)).sum())
    neg = int((labels == 0).sum())
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    auc = roc_auc(scores, labels) if scores is not None else float("nan")
    return Metrics(len(labels), int((labels == 1).sum()), auc, p, r, f1, fp / neg if neg else 0.0)


def labels_of(records: list[Record]):
    return [r.label for r in records]


def rule_flags(records: list[Record]) -> list[bool]:
    """The deterministic engine's verdict: anything but allow counts as flagged."""

    from ...engine.engine import Engine
    from ...engine.types import Context, Direction

    engine = Engine()
    out = []
    for r in records:
        direction = Direction.DOCUMENT if r.kind == "indirect" else Direction.INPUT
        verdict = engine.inspect(r.text, Context(direction=direction))
        injection_like = any(f.detector in ("injection", "agentic", "output") for f in verdict.findings)
        out.append(verdict.action.value != "allow" and injection_like)
    return out


def transformer_scores(records: list[Record], backend, batch: int = 32) -> list[float]:
    """The optional transformer's attack probability per record (max over its windows)."""

    out: list[float] = []
    for i in range(0, len(records), batch):
        chunk = [backend.windows(r.text) for r in records[i : i + batch]]
        flat = [w for wins in chunk for w in wins]
        probs = backend.score_batch(flat) if flat else []
        k = 0
        for wins in chunk:
            out.append(max(probs[k : k + len(wins)], default=0.0))
            k += len(wins)
    return out
