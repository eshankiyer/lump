"""Train the built-in classifier with numpy only.

Model: multinomial logistic regression (benign / injection / jailbreak) over
the hashed, L2-normalised n-gram vectors from :mod:`lump.ml.features`.
Optimiser: mini-batch Adam on a dense weight matrix with decoupled weight
decay; early stopping on validation log-loss. Afterwards:

* **calibration** — a single temperature fitted on the validation set, so the
  attack probability means what it says;
* **operating points** — thresholds chosen on validation benign data for
  target false-positive rates (``warn`` and ``block``);
* **quantisation** — per-class symmetric int8, checked against the float
  model before it is accepted.

Long texts contribute one vector per window, each weighted 1/windows, so a
single long jailbreak template cannot outweigh many short prompts.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

from ..features import FeatureConfig, featurize
from .corpus import Record

CLASSES = ("benign", "injection", "jailbreak")
KIND_TO_CLASS = {"benign": 0, "hard_negative": 0, "injection": 1, "indirect": 1, "jailbreak": 2}


@dataclass
class TrainConfig:
    features: FeatureConfig = field(default_factory=FeatureConfig)
    epochs: int = 12
    batch_size: int = 512
    lr: float = 0.02
    weight_decay: float = 1e-6
    patience: int = 2
    hard_negative_weight: float = 2.0  # benign look-alikes matter most for false positives
    augment_weight: float = 2.0  # targeted reworded examples
    # Each source's total weight scales like n**source_power (0.5 = sqrt), so
    # one large single-style source cannot define the decision boundary — the
    # main cause of topic shortcuts in the first model.
    source_power: float = 0.5
    # Randomly zero this share of each training row's active features (inverted
    # dropout), so no decision can rest on one or two strong n-grams.
    feature_dropout: float = 0.0
    workers: int = 4
    seed: int = 7
    target_fpr_warn: float = 0.02
    target_fpr_block: float = 0.005
    target_fpr_critical: float = 0.001


@dataclass
class Matrix:
    """CSR rows: one row per window. ``owner`` maps rows back to records."""

    indptr: object
    indices: object
    values: object
    owner: object
    weight: object  # per-row sample weight (before class balancing)


def _featurize_chunk(args):
    """Worker: featurise a chunk of texts into compact numpy arrays."""

    import numpy as np

    texts, cfg_json = args
    cfg = FeatureConfig.from_json(cfg_json)
    lengths, owners, weights = [], [], []
    idx_parts, val_parts = [], []
    for i, t in enumerate(texts):
        wins = featurize(t, cfg)
        w = 1.0 / max(1, len(wins))
        for vec in wins:
            lengths.append(len(vec))
            owners.append(i)
            weights.append(w)
            if vec:
                idx_parts.append(np.fromiter(vec.keys(), dtype=np.int32, count=len(vec)))
                val_parts.append(np.fromiter(vec.values(), dtype=np.float32, count=len(vec)))
    return (
        np.concatenate(idx_parts) if idx_parts else np.zeros(0, np.int32),
        np.concatenate(val_parts) if val_parts else np.zeros(0, np.float32),
        np.asarray(lengths, dtype=np.int64),
        np.asarray(owners, dtype=np.int64),
        np.asarray(weights, dtype=np.float32),
        len(texts),
    )


def build_matrix(records: list[Record], cfg: FeatureConfig, workers: int = 4) -> Matrix:
    import numpy as np

    texts = [r.text for r in records]
    chunk = max(1, min(2000, len(texts) // max(1, workers * 4) + 1))
    jobs = [(texts[i : i + chunk], cfg.to_json()) for i in range(0, len(texts), chunk)]
    if workers > 1 and len(texts) > 2000:
        with ProcessPoolExecutor(workers) as ex:
            parts = list(ex.map(_featurize_chunk, jobs))
    else:
        parts = [_featurize_chunk(j) for j in jobs]
    offset = 0
    owners = []
    for part in parts:
        owners.append(part[3] + offset)
        offset += part[5]
    lengths = np.concatenate([p[2] for p in parts])
    indptr = np.zeros(len(lengths) + 1, dtype=np.int64)
    np.cumsum(lengths, out=indptr[1:])
    return Matrix(
        indptr,
        np.concatenate([p[0] for p in parts]).astype(np.int64),
        np.concatenate([p[1] for p in parts]),
        np.concatenate(owners),
        np.concatenate([p[4] for p in parts]),
    )


def _rows_slice(m: Matrix, rows):
    """Gather CSR rows -> (row_ids_per_nnz, indices, values)."""

    import numpy as np

    starts, ends = m.indptr[rows], m.indptr[rows + 1]
    lengths = ends - starts
    total = int(lengths.sum())
    if total == 0:
        return np.zeros(0, np.int64), np.zeros(0, np.int64), np.zeros(0, np.float32)
    row_ids = np.repeat(np.arange(len(rows)), lengths)
    offsets = np.repeat(starts - np.concatenate(([0], np.cumsum(lengths)[:-1])), lengths)
    flat = np.arange(total) + offsets
    return row_ids, m.indices[flat], m.values[flat]


def _scatter_rows(row_ids, contrib, n_rows: int):
    """Sum per-nnz contributions into rows (np.bincount per class: far faster than np.add.at)."""

    import numpy as np

    out = np.empty((n_rows, contrib.shape[1]), dtype=np.float64)
    for c in range(contrib.shape[1]):
        out[:, c] = np.bincount(row_ids, weights=contrib[:, c], minlength=n_rows)
    return out


def logits_for(m: Matrix, rows, W, b, chunk: int = 4096):
    import numpy as np

    parts = []
    for start in range(0, len(rows), chunk):
        sub = rows[start : start + chunk]
        row_ids, idx, val = _rows_slice(m, sub)
        if len(idx):
            parts.append(_scatter_rows(row_ids, W[idx] * val[:, None], len(sub)))
        else:
            parts.append(np.zeros((len(sub), W.shape[1])))
    return np.concatenate(parts) + b


def _softmax(z):
    import numpy as np

    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def train(train_recs: list[Record], val_recs: list[Record], cfg: TrainConfig, log=print) -> dict:
    import numpy as np

    rng = np.random.default_rng(cfg.seed)
    t0 = time.time()
    Xtr = build_matrix(train_recs, cfg.features, cfg.workers)
    Xva = build_matrix(val_recs, cfg.features, cfg.workers)
    log(f"  featurised {len(train_recs)} train / {len(val_recs)} val records "
        f"-> {len(Xtr.owner)} / {len(Xva.owner)} windows in {time.time() - t0:.0f}s")

    ytr = np.asarray([KIND_TO_CLASS[r.kind] for r in train_recs], dtype=np.int64)[Xtr.owner]
    yva = np.asarray([KIND_TO_CLASS[r.kind] for r in val_recs], dtype=np.int64)[Xva.owner]
    base_w = Xtr.weight.copy()
    kinds = np.asarray([r.kind for r in train_recs])[Xtr.owner]
    srcs = np.asarray([r.source for r in train_recs])[Xtr.owner]
    base_w[kinds == "hard_negative"] *= cfg.hard_negative_weight
    base_w[srcs == "lump/reworded-augment"] *= cfg.augment_weight
    if cfg.source_power != 1.0:
        rec_src = np.asarray([r.source for r in train_recs])
        names, counts = np.unique(rec_src, return_counts=True)
        per_src = {n: (c ** cfg.source_power) / c for n, c in zip(names, counts, strict=True)}
        scale = np.asarray([per_src[x] for x in srcs])
        base_w *= scale / scale.mean()
    # Balance classes by total weight.
    class_tot = np.bincount(ytr, weights=base_w, minlength=len(CLASSES))
    class_w = class_tot.sum() / (len(CLASSES) * np.maximum(class_tot, 1e-9))
    sample_w = base_w * class_w[ytr]
    log(f"  class weights {dict(zip(CLASSES, np.round(class_w, 3), strict=True))}")

    D = 1 << cfg.features.hash_bits
    C = len(CLASSES)
    W = np.zeros((D, C), dtype=np.float64)
    b = np.zeros(C, dtype=np.float64)
    mW, vW = np.zeros_like(W), np.zeros_like(W)
    mb, vb = np.zeros_like(b), np.zeros_like(b)
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    step = 0
    best = (math.inf, None, None, -1)
    n = len(ytr)
    rows_va = np.arange(len(yva))
    w_va = Xva.weight
    for epoch in range(cfg.epochs):
        order = rng.permutation(n)
        ep_loss = 0.0
        for start in range(0, n, cfg.batch_size):
            rows = order[start : start + cfg.batch_size]
            row_ids, idx, val = _rows_slice(Xtr, rows)
            if cfg.feature_dropout > 0:
                keep = rng.random(len(val)) >= cfg.feature_dropout
                val = val * keep / (1.0 - cfg.feature_dropout)
            z = _scatter_rows(row_ids, W[idx] * val[:, None], len(rows)) + b
            p = _softmax(z)
            sw = sample_w[rows]
            ep_loss += float(-(sw * np.log(p[np.arange(len(rows)), ytr[rows]] + 1e-12)).sum())
            delta = p
            delta[np.arange(len(rows)), ytr[rows]] -= 1.0
            delta *= (sw / sw.sum())[:, None]
            # Sparse gradient on the touched feature rows only.
            uniq, inv = np.unique(idx, return_inverse=True)
            g = _scatter_rows(inv, val[:, None] * delta[row_ids], len(uniq))
            gb = delta.sum(axis=0)
            step += 1
            lr_t = cfg.lr * math.sqrt(1 - beta2**step) / (1 - beta1**step)
            mW[uniq] = beta1 * mW[uniq] + (1 - beta1) * g
            vW[uniq] = beta2 * vW[uniq] + (1 - beta2) * g * g
            W[uniq] -= lr_t * (mW[uniq] / (np.sqrt(vW[uniq]) + eps) + cfg.weight_decay * W[uniq] / cfg.lr)
            mb = beta1 * mb + (1 - beta1) * gb
            vb = beta2 * vb + (1 - beta2) * gb * gb
            b -= lr_t * mb / (np.sqrt(vb) + eps)
        zv = logits_for(Xva, rows_va, W, b)
        pv = _softmax(zv)
        val_loss = float(-(w_va * np.log(pv[np.arange(len(yva)), yva] + 1e-12)).sum() / w_va.sum())
        acc = float((pv.argmax(1) == yva).mean())
        log(f"  epoch {epoch + 1:2}  train_loss={ep_loss / sample_w.sum():.4f}  val_loss={val_loss:.4f}  val_acc={acc:.4f}")
        if val_loss < best[0] - 1e-4:
            best = (val_loss, W.copy(), b.copy(), epoch)
        elif epoch - best[3] >= cfg.patience:
            log("  early stop")
            break
    _, W, b, best_epoch = best
    log(f"  best epoch {best_epoch + 1}, {time.time() - t0:.0f}s")

    # Record-level validation scores (max attack probability over windows).
    zv = logits_for(Xva, rows_va, W, b)
    temperature = fit_temperature(zv, yva, w_va)
    p_attack_rows = 1.0 - _softmax(zv / temperature)[:, 0]
    rec_scores = np.zeros(len(val_recs))
    np.maximum.at(rec_scores, Xva.owner, p_attack_rows)
    rec_labels = np.asarray([0 if KIND_TO_CLASS[r.kind] == 0 else 1 for r in val_recs])
    thresholds = pick_thresholds(rec_scores, rec_labels, cfg.target_fpr_warn, cfg.target_fpr_block,
                                 cfg.target_fpr_critical)
    log(f"  temperature={temperature:.3f}  thresholds={thresholds}")
    return {"W": W, "b": b, "temperature": temperature, "thresholds": thresholds,
            "class_counts": dict(Counter(CLASSES[c] for c in ytr.tolist()))}


def fit_temperature(z, y, w) -> float:
    """1-D search for the temperature minimising weighted validation NLL."""

    import numpy as np

    def nll(t):
        p = _softmax(z / t)
        return float(-(w * np.log(p[np.arange(len(y)), y] + 1e-12)).sum() / w.sum())

    lo, hi = 0.05, 20.0
    for _ in range(80):  # golden-section on log scale
        m1 = math.exp(math.log(lo) + (math.log(hi) - math.log(lo)) * 0.382)
        m2 = math.exp(math.log(lo) + (math.log(hi) - math.log(lo)) * 0.618)
        if nll(m1) < nll(m2):
            hi = m2
        else:
            lo = m1
    return round(math.sqrt(lo * hi), 4)


def pick_thresholds(scores, labels, fpr_warn: float, fpr_block: float, fpr_critical: float = 0.001) -> dict:
    """Smallest thresholds whose benign false-positive rate is within target."""

    import numpy as np

    benign = np.sort(scores[labels == 0])
    if not len(benign):
        return {"warn": 0.5, "block": 0.9, "critical": 0.99}

    def at(fpr):
        k = int(math.floor(len(benign) * (1 - fpr)))
        k = min(max(k, 0), len(benign) - 1)
        return float(min(max(benign[k] + 1e-6, 0.5), 0.999))

    warn, block, critical = at(fpr_warn), at(fpr_block), at(fpr_critical)
    block = max(block, warn)
    return {"warn": round(warn, 4), "block": round(block, 4), "critical": round(max(critical, block), 4)}
