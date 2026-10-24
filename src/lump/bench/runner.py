"""Detection benchmark.

Runs the engine over a labelled corpus and reports precision / recall / F1 per
category plus overall accuracy and latency percentiles. ``label`` is "malicious"
or "benign"; a malicious sample is a true positive when the verdict is anything
stronger than ``allow``. This is how you tune thresholds and catch regressions —
``lump bench`` fails (non-zero exit) if F1 drops below the floor.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from importlib import resources
from pathlib import Path
from typing import Any

from ..config import LumpConfig
from ..engine.engine import Engine
from ..engine.types import Context

# Obviously fake, structurally valid credentials, assembled at runtime so the
# repository never contains a literal that looks like a live token.
_FAKES = {
    "github_token": "ghp" + "_" + "FAKE0TEST1" * 3 + "000000",
    "openai_key": "sk" + "-proj-" + "FakeTestValue0" * 3 + "xyz",
}
_FAKE_RE = re.compile(r"\{\{FAKE:([a-z_]+)\}\}")


def _expand(text: str) -> str:
    return _FAKE_RE.sub(lambda m: _FAKES.get(m.group(1), m.group(0)), text)


def load_corpus(path: str | None) -> list[dict[str, Any]]:
    if path:
        raw = Path(path).read_text("utf-8")
    else:
        raw = resources.files("lump.data").joinpath("corpus/benchmark.jsonl").read_text("utf-8")
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            row = json.loads(line)
            row["text"] = _expand(row["text"])
            rows.append(row)
    return rows


def run_benchmark(config: LumpConfig, corpus: str | None = None, as_json: bool = False, f1_floor: float = 0.80,
                  use_ml: bool = True) -> int:
    if not use_ml:
        config.engine.ml.enabled = False
    engine = Engine(config.policy, config.engine)
    rows = load_corpus(corpus)

    tp = fp = tn = fn = 0
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})
    latencies: list[float] = []
    failures: list[dict] = []

    for row in rows:
        text = row["text"]
        label = row["label"]  # malicious | benign
        direction = row.get("direction", "input")
        untrusted = row.get("untrusted")
        ctx = Context(direction=direction, trusted=(None if untrusted is None else not untrusted))
        t0 = time.perf_counter()
        verdict = engine.inspect(text, ctx)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        flagged = verdict.action.value != "allow"

        if label == "malicious":
            cat = row.get("category", "uncategorised")
            by_cat[cat]["total"] += 1
            if flagged:
                tp += 1
                by_cat[cat]["tp"] += 1
            else:
                fn += 1
                by_cat[cat]["fn"] += 1
                failures.append({"type": "false_negative", "category": cat, "text": text[:100]})
        else:
            if flagged:
                fp += 1
                failures.append({"type": "false_positive", "text": text[:100],
                                 "rules": [f.rule_id for f in verdict.findings][:4]})
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    latencies.sort()

    def pct(p: float) -> float:
        if not latencies:
            return 0.0
        return round(latencies[min(int(len(latencies) * p), len(latencies) - 1)], 3)

    report = {
        "samples": len(rows),
        "malicious": tp + fn,
        "benign": tn + fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(rows), 4) if rows else 0.0,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "mean": round(sum(latencies) / len(latencies), 3) if latencies else 0.0},
        "by_category": {
            cat: {
                "recall": round(d["tp"] / d["total"], 4) if d["total"] else 0.0,
                "detected": d["tp"], "missed": d["fn"], "total": d["total"],
            }
            for cat, d in sorted(by_cat.items())
        },
        "failures": failures[:30],
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)

    return 0 if f1 >= f1_floor else 1


def _print_report(r: dict) -> None:
    print(f"\nLump detection benchmark — {r['samples']} samples ({r['malicious']} malicious, {r['benign']} benign)\n")
    print(f"  precision {r['precision']:.3f}   recall {r['recall']:.3f}   F1 {r['f1']:.3f}   accuracy {r['accuracy']:.3f}")
    c = r["confusion"]
    print(f"  TP={c['tp']}  FP={c['fp']}  TN={c['tn']}  FN={c['fn']}")
    lat = r["latency_ms"]
    print(f"  latency  p50={lat['p50']}ms  p95={lat['p95']}ms  p99={lat['p99']}ms  mean={lat['mean']}ms\n")
    print("  recall by category:")
    for cat, d in r["by_category"].items():
        bar = "█" * int(d["recall"] * 20)
        print(f"    {cat:34} {d['recall']:.2f} {bar:<20} ({d['detected']}/{d['total']})")
    if r["failures"]:
        print(f"\n  {len(r['failures'])} shown failures:")
        for fail in r["failures"][:12]:
            kind = "MISS" if fail["type"] == "false_negative" else "FP  "
            print(f"    {kind} {fail.get('category', ''):22} {fail['text'][:70]!r}")
