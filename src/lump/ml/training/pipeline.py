"""``lump train``: corpus -> training -> evaluation -> model file + report.

Reproducible end to end from the pinned lockfile and the bundled
augmentation / reworded-attack sets.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from ..features import FeatureConfig
from . import corpus
from .corpus import Record
from .evaluate import binary_metrics, labels_of
from .train import TrainConfig, train

AUGMENT_FILE = "reworded_augment.jsonl"
# Benign texts that use attack vocabulary innocently ("the previous
# instructions for the printer"), written and independently reviewed for this
# project: counter-examples to the words-mean-attack shortcut.
HARD_NEGATIVES_FILE = "hard_negatives.jsonl"
REWORDED_EVAL_FILE = "reworded_eval.jsonl"


def bundled_records(name: str, source: str) -> list[Record]:
    try:
        raw = resources.files("lump.ml.training").joinpath("data", name).read_text("utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return []
    out = []
    for line in raw.splitlines():
        if line.strip():
            d = json.loads(line)
            out.append(Record(d["text"], int(d["label"]), d["kind"], source))
    return out


@dataclass
class EvalRow:
    """Metrics for one evaluation set.

    ``rules`` / ``ensemble`` treat every text as the user's own input;
    ``*_doc`` treat every text as untrusted third-party content (a document
    or tool result), where the default policy is stricter. ``ml_*`` are the
    model alone (context-free) at its warn and block points.
    """

    name: str
    rules: dict
    ml_warn: dict
    ml_block: dict
    ensemble: dict
    ensemble_block: dict
    rules_doc: dict
    ensemble_doc: dict
    ensemble_doc_block: dict
    by_kind: dict


def evaluate_all(splits: dict[str, list[Record]], model, log=print) -> list[EvalRow]:
    """Rules alone vs ML alone vs the full engine, per evaluation set, as input and as untrusted content."""

    from ...engine.engine import Engine, EngineConfig
    from ...engine.types import Context, Direction
    from ..detector import MLSettings

    rules_engine = Engine(config=EngineConfig(ml=MLSettings(enabled=False), load_plugins=False))
    full_engine = Engine(config=EngineConfig(ml=MLSettings(model=model), load_plugins=False))
    injection_like = {"injection", "agentic", "output", "ml"}
    contexts = {"input": Context(direction=Direction.INPUT), "doc": Context(direction=Direction.DOCUMENT)}

    def flagged(v) -> tuple[bool, bool]:
        hit = any(f.detector in injection_like for f in v.findings)
        return v.action.value != "allow" and hit, v.action.value == "block" and hit

    rows = []
    names = [n for n in splits if n not in ("train", "val")]
    for name in names:
        recs = splits[name]
        if not recs:
            continue
        t0 = time.time()
        labels = labels_of(recs)
        res = {k: {"rules": [], "flag": [], "block": []} for k in contexts}
        scores = []
        for r in recs:
            ml = None
            for key, ctx in contexts.items():
                res[key]["rules"].append(flagged(rules_engine.inspect(r.text, ctx))[0])
                fv = full_engine.inspect(r.text, ctx)
                f, b = flagged(fv)
                res[key]["flag"].append(f)
                res[key]["block"].append(b)
                ml = ml or next((x for x in fv.findings if x.detector == "ml"), None)
            scores.append(ml.confidence if ml else model.score(r.text).p_attack)
        th = model.thresholds
        ml_w = [x >= th["warn"] for x in scores]
        ml_b = [x >= th["block"] for x in scores]
        kinds = sorted({r.kind for r in recs if r.label == 1})
        by_kind = {}
        for k in kinds:
            idx = [i for i, r in enumerate(recs) if r.kind == k and r.label == 1]
            by_kind[k] = {
                "n": len(idx),
                "rules": round(sum(res["input"]["rules"][i] for i in idx) / len(idx), 4),
                "ml": round(sum(ml_w[i] for i in idx) / len(idx), 4),
                "ensemble": round(sum(res["input"]["flag"][i] for i in idx) / len(idx), 4),
                "ensemble_doc_block": round(sum(res["doc"]["block"][i] for i in idx) / len(idx), 4),
            }
        row = EvalRow(
            name=name,
            rules=binary_metrics(res["input"]["rules"], labels).__dict__,
            ml_warn=binary_metrics(ml_w, labels, scores).__dict__,
            ml_block=binary_metrics(ml_b, labels, scores).__dict__,
            ensemble=binary_metrics(res["input"]["flag"], labels).__dict__,
            ensemble_block=binary_metrics(res["input"]["block"], labels).__dict__,
            rules_doc=binary_metrics(res["doc"]["rules"], labels).__dict__,
            ensemble_doc=binary_metrics(res["doc"]["flag"], labels).__dict__,
            ensemble_doc_block=binary_metrics(res["doc"]["block"], labels).__dict__,
            by_kind=by_kind,
        )
        rows.append(row)
        log(f"  {name[:48]:48} n={len(recs):6}  recall rules={row.rules['recall']:.3f} ml={row.ml_warn['recall']:.3f} "
            f"ens={row.ensemble['recall']:.3f} | FPR rules={row.rules['fpr']:.3f} ml={row.ml_warn['fpr']:.3f} "
            f"ens={row.ensemble['fpr']:.3f} | as document: block recall={row.ensemble_doc_block['recall']:.3f} "
            f"FPR={row.ensemble_doc_block['fpr']:.3f} | AUC={row.ml_warn['auc']:.4f}  ({time.time() - t0:.0f}s)")
    return rows


def run(out: Path, report: Path | None = None, offline_dir: Path | None = None, corpus_cache: Path | None = None,
        hash_bits: int = 19, epochs: int = 12, version: str = "dev", workers: int = 4, log=print,
        weight_decay: float = 1e-6, feature_dropout: float = 0.0, card: Path | None = None,
        from_weights: Path | None = None, compare_transformer: str | None = None) -> dict:
    from ..model import Model
    from .export import export

    augment = bundled_records(AUGMENT_FILE, "lump/reworded-augment") + bundled_records(HARD_NEGATIVES_FILE, "lump/hard-negatives")
    reworded_eval = bundled_records(REWORDED_EVAL_FILE, "lump/reworded-eval")
    if corpus_cache and corpus_cache.exists():
        log(f"loading cached corpus {corpus_cache}")
        splits = corpus.load(corpus_cache)
    else:
        log("building corpus from pinned sources")
        splits = corpus.build(extra_train=augment, extra_eval={"reworded": reworded_eval} if reworded_eval else None,
                              offline_dir=offline_dir, log=log)
        if corpus_cache:
            corpus.save(splits, corpus_cache)
    cfg = TrainConfig(features=FeatureConfig(hash_bits=hash_bits), epochs=epochs, workers=workers,
                      weight_decay=weight_decay, feature_dropout=feature_dropout)
    import numpy as np

    if from_weights:
        # Re-evaluate / re-export a finished run without retraining.
        with np.load(from_weights) as z:
            result = {"W": z["W"], "b": z["b"], "temperature": float(z["temperature"]),
                      "thresholds": json.loads(str(z["thresholds"])), "class_counts": json.loads(str(z["class_counts"]))}
        if result["W"].shape[0] != 1 << hash_bits:
            raise ValueError(f"{from_weights} has {result['W'].shape[0]} feature rows; pass the --hash-bits it was trained with")
        log(f"loaded float weights from {from_weights}")
    else:
        log(f"training: {len(splits['train'])} train / {len(splits['val'])} val records, 2^{hash_bits} features")
        result = train(splits["train"], splits["val"], cfg, log=log)
        # Keep the float weights so a failed export never costs a training run.
        raw = out.with_suffix(".float.npz")
        raw.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(raw, W=result["W"], b=result["b"], temperature=result["temperature"],
                            thresholds=json.dumps(result["thresholds"]), class_counts=json.dumps(result["class_counts"]))
        log(f"saved float weights to {raw}")

    check = splits["val"][:3000]
    blob = export(result, cfg.features, metrics={}, version=version, augment_count=len(augment), check_records=check)
    model = Model.from_bytes(blob)
    log("evaluating rules vs ML vs ensemble")
    rows = evaluate_all(splits, model, log=log)
    metrics = {r.name: {"ml_auc": round(r.ml_warn["auc"], 4), "ml_recall": round(r.ml_warn["recall"], 4),
                        "ml_fpr": round(r.ml_warn["fpr"], 4), "rules_recall": round(r.rules["recall"], 4),
                        "ensemble_recall": round(r.ensemble["recall"], 4), "ensemble_fpr": round(r.ensemble["fpr"], 4)}
               for r in rows}
    blob = export(result, cfg.features, metrics=metrics, version=version, augment_count=len(augment), check_records=check)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    log(f"wrote {out} ({len(blob) / 1e6:.2f} MB)")
    summary = {"model": str(out), "bytes": len(blob), "thresholds": result["thresholds"],
               "temperature": result["temperature"], "evaluation": [r.__dict__ for r in rows]}
    if compare_transformer:
        summary["transformer"] = compare_with_transformer(splits, rows, compare_transformer, log)
    if report:
        report.write_text(json.dumps(summary, indent=1) + "\n")
    if card:
        from .card import render

        card.write_text(render(summary, model.header) + "\n")
    return summary


def compare_with_transformer(splits: dict[str, list[Record]], rows: list[EvalRow], base: str, log=print) -> dict:
    """Score every out-of-distribution set with the optional DeBERTa backend
    (same texts, full sets) so the model card can compare the two honestly."""

    from ..transformer import DEFAULT_THRESHOLDS, TransformerBackend
    from .evaluate import transformer_scores

    backend = TransformerBackend(base, threads=4)
    out = {"model": backend.model_id, "thresholds": DEFAULT_THRESHOLDS, "sets": {}}
    for row in rows:
        if row.name == "test_id":  # in-distribution for Lump only: not a fair comparison
            continue
        t0 = time.time()
        recs = splits[row.name]
        scores = transformer_scores(recs, backend)
        labels = labels_of(recs)
        m = binary_metrics([x >= DEFAULT_THRESHOLDS["warn"] for x in scores], labels, scores)
        out["sets"][row.name] = {"n": m.n, "auc": round(m.auc, 4), "recall": round(m.recall, 4), "fpr": round(m.fpr, 4)}
        log(f"  transformer {row.name[:48]:48} AUC={m.auc:.4f} recall={m.recall:.3f} FPR={m.fpr:.3f}  "
            f"(Lump ML AUC={row.ml_warn['auc']:.4f})  ({time.time() - t0:.0f}s)")
    return out
