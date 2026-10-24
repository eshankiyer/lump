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
    name: str
    rules: dict
    ml_warn: dict
    ml_block: dict
    ensemble: dict
    ensemble_block: dict
    by_kind: dict


def evaluate_all(splits: dict[str, list[Record]], model, log=print) -> list[EvalRow]:
    """Rules alone vs ML alone vs the full engine, per evaluation set."""

    from ...engine.engine import Engine, EngineConfig
    from ...engine.types import Context, Direction
    from ..detector import MLSettings

    rules_engine = Engine(config=EngineConfig(ml=MLSettings(enabled=False), load_plugins=False))
    full_engine = Engine(config=EngineConfig(ml=MLSettings(model=model), load_plugins=False))
    injection_like = {"injection", "agentic", "output", "ml"}
    rows = []
    names = [n for n in splits if n not in ("train", "val")]
    for name in names:
        recs = splits[name]
        if not recs:
            continue
        t0 = time.time()
        labels = labels_of(recs)
        rule_f, ens_f, ens_b, scores = [], [], [], []
        for r in recs:
            direction = Direction.DOCUMENT if r.kind == "indirect" else Direction.INPUT
            ctx = Context(direction=direction)
            rv = rules_engine.inspect(r.text, ctx)
            rule_f.append(rv.action.value != "allow" and any(f.detector in injection_like for f in rv.findings))
            fv = full_engine.inspect(r.text, ctx)
            hit = any(f.detector in injection_like for f in fv.findings)
            ens_f.append(fv.action.value != "allow" and hit)
            ens_b.append(fv.action.value == "block" and hit)
            ml = next((f for f in fv.findings if f.detector == "ml"), None)
            scores.append(ml.confidence if ml else model.score(r.text).p_attack)
        th = model.thresholds
        ml_w = [s >= th["warn"] for s in scores]
        ml_b = [s >= th["block"] for s in scores]
        kinds = sorted({r.kind for r in recs if r.label == 1})
        by_kind = {}
        for k in kinds:
            idx = [i for i, r in enumerate(recs) if r.kind == k and r.label == 1]
            by_kind[k] = {
                "n": len(idx),
                "rules": round(sum(rule_f[i] for i in idx) / len(idx), 4),
                "ml": round(sum(ml_w[i] for i in idx) / len(idx), 4),
                "ensemble": round(sum(ens_f[i] for i in idx) / len(idx), 4),
            }
        row = EvalRow(
            name=name,
            rules=binary_metrics(rule_f, labels).__dict__,
            ml_warn=binary_metrics(ml_w, labels, scores).__dict__,
            ml_block=binary_metrics(ml_b, labels, scores).__dict__,
            ensemble=binary_metrics(ens_f, labels).__dict__,
            ensemble_block=binary_metrics(ens_b, labels).__dict__,
            by_kind=by_kind,
        )
        rows.append(row)
        log(f"  {name[:48]:48} n={len(recs):6}  recall rules={row.rules['recall']:.3f} ml={row.ml_warn['recall']:.3f} "
            f"ens={row.ensemble['recall']:.3f} | FPR rules={row.rules['fpr']:.3f} ml={row.ml_warn['fpr']:.3f} "
            f"ens={row.ensemble['fpr']:.3f} | AUC={row.ml_warn['auc']:.4f}  ({time.time() - t0:.0f}s)")
    return rows


def run(out: Path, report: Path | None = None, offline_dir: Path | None = None, corpus_cache: Path | None = None,
        hash_bits: int = 19, epochs: int = 12, version: str = "dev", workers: int = 4, log=print,
        weight_decay: float = 1e-6, feature_dropout: float = 0.0, card: Path | None = None) -> dict:
    from ..model import Model
    from .export import export

    augment = bundled_records(AUGMENT_FILE, "lump/reworded-augment")
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
    log(f"training: {len(splits['train'])} train / {len(splits['val'])} val records, 2^{hash_bits} features")
    result = train(splits["train"], splits["val"], cfg, log=log)

    blob = export(result, cfg.features, metrics={}, version=version, augment_count=len(augment))
    model = Model.from_bytes(blob)
    log("evaluating rules vs ML vs ensemble")
    rows = evaluate_all(splits, model, log=log)
    metrics = {r.name: {"ml_auc": round(r.ml_warn["auc"], 4), "ml_recall": round(r.ml_warn["recall"], 4),
                        "ml_fpr": round(r.ml_warn["fpr"], 4), "rules_recall": round(r.rules["recall"], 4),
                        "ensemble_recall": round(r.ensemble["recall"], 4), "ensemble_fpr": round(r.ensemble["fpr"], 4)}
               for r in rows}
    blob = export(result, cfg.features, metrics=metrics, version=version, augment_count=len(augment))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    log(f"wrote {out} ({len(blob) / 1e6:.2f} MB)")
    summary = {"model": str(out), "bytes": len(blob), "thresholds": result["thresholds"],
               "temperature": result["temperature"], "evaluation": [r.__dict__ for r in rows]}
    if report:
        report.write_text(json.dumps(summary, indent=1) + "\n")
    if card:
        from .card import render

        card.write_text(render(summary, model.header) + "\n")
    return summary
