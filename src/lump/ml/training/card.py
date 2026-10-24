"""Render the model card (Markdown) from a training report."""

from __future__ import annotations

from .sources import SOURCES

_PRETTY = {
    "test_id": "In-distribution test (held-out 10% of the training pool)",
    "reworded": "Reworded attacks + hard negatives (written for this project, never trained on)",
}


def _name(split: str) -> str:
    if split in _PRETTY:
        return _PRETTY[split]
    if split.startswith("ood:"):
        return f"`{split[4:]}` (out-of-distribution holdout)"
    return split


def render(summary: dict, header: dict) -> str:
    th = summary["thresholds"]
    lines = [
        "# Lump built-in prompt-injection classifier — model card",
        "",
        f"**Model:** `{header.get('name')}` version `{header.get('version')}`, {summary['bytes'] / 1e6:.2f} MB, "
        f"format {header.get('format')}, classes {', '.join(header.get('classes', []))}.",
        "",
        "## What it is",
        "",
        "A multinomial logistic-regression model over hashed word 1–2-grams and character 3–5-grams "
        f"(2^{header['features']['hash_bits']} buckets, signed hashing, sub-linear TF, L2 norm), int8-quantised. "
        "It runs with zero dependencies in Python and in the browser extension, from the same file, "
        "and scores a typical prompt in about a millisecond. It complements the rule engine: the rules are "
        "literal and precise, the model catches reworded attacks.",
        "",
        "## Operating points",
        "",
        "Chosen on the validation split so that a given share of benign validation prompts would be flagged.",
        "",
        "| Level | Threshold | Target benign FPR (validation) | Default policy |",
        "|---|---|---|---|",
        f"| warn | {th['warn']} | 2% | warn |",
        f"| block | {th['block']} | 0.5% | block on untrusted content; on direct input block when rules agree |",
        f"| critical | {th.get('critical', '–')} | 0.1% | block |",
        "",
        f"Calibration: temperature scaling, T = {summary['temperature']}.",
        "",
        "## Evaluation",
        "",
        "Recall / false-positive rate at the **warn** threshold. *Rules* is the deterministic engine alone, "
        "*ML* the model alone, *Lump* the full engine (rules + model under the default policy). "
        "Out-of-distribution sets were never trained on; exact and near-duplicates of every evaluation text "
        "were removed from the training pool. One caveat, stated plainly: the first model's false positives on "
        "`wambosec` (benign developer questions) are what motivated adding benign developer-question pools, so "
        "that row is partly a development set; the other out-of-distribution rows were not used to make any "
        "decision. Hyper-parameters were fixed in advance, not tuned on any evaluation set. The three "
        "`3nesdeniz` holdouts come from the same author as one training source (`agentic-prompt-injection-5k`), "
        "so they are same-family rather than fully independent.",
        "",
        "| Evaluation set | n | Rules recall | ML recall | Lump recall | Rules FPR | ML FPR | Lump FPR | ML AUC |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in summary["evaluation"]:
        r, m, e = row["rules"], row["ml_warn"], row["ensemble"]
        lines.append(
            f"| {_name(row['name'])} | {m['n']} | {r['recall']:.3f} | {m['recall']:.3f} | {e['recall']:.3f} | "
            f"{r['fpr']:.3f} | {m['fpr']:.3f} | {e['fpr']:.3f} | {m['auc']:.3f} |"
        )
    lines += [
        "",
        "## Known limitations",
        "",
        "- It is a bag-of-n-grams model: it has no understanding of *who* an instruction is addressed to, so "
        "carefully constructed benign look-alikes (e.g. a document that quotes an attack for analysis) can score "
        "high, and attacks phrased entirely in vocabulary it has only seen in benign text can score low. The "
        "agentic boundary-pair sets above are deliberately built from such near-identical pairs and are the "
        "hardest case; a 184M-parameter DeBERTa-v3 classifier also scores only about 0.72 AUC on them.",
        "- Training data is mostly English; other languages are covered by character n-grams only.",
        "- Thresholds were set on validation data drawn from the training sources; real traffic differs. "
        "Start in `mode = \"monitor\"`, look at what it flags, then tune `[ml] warn/block` if needed.",
        "",
        "## Training data",
        "",
        "Original public datasets only, each vetted for license, label meaning and noise by two independent "
        "reviews; aggregator datasets that re-mix other sources (some unlicensed) are excluded. Revisions and "
        "file hashes are pinned in `src/lump/ml/training/sources.lock.json`.",
        "",
        "| Dataset | License | Role | Revision |",
        "|---|---|---|---|",
    ]
    for s in SOURCES:
        lines.append(f"| [{s.id}](https://huggingface.co/datasets/{s.id}) | {s.license} | {s.role} | `{s.revision[:12]}` |")
    aug = header.get("training", {}).get("augmentation", {})
    lines += [
        f"| Lump reworded hard negatives (this repository) | Apache-2.0 | train | {aug.get('records', 0)} records |",
        "",
        "Attribution: datasets under CC-BY-4.0 and ODC-BY are used under those licenses; see each dataset's card. "
        "Rows inside mixed-license datasets whose upstream licenses are non-commercial or missing were filtered "
        "out (see `sources.py`).",
        "",
        "## Reproduce",
        "",
        "```bash",
        "pip install 'lump[train]'",
        f"lump train --hash-bits {header['features']['hash_bits']} --version {header.get('version')} --out injection-v1.lumpml --report report.json",
        "```",
        "",
    ]
    return "\n".join(lines)
