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
        "and scores a typical prompt in well under a millisecond (about 0.3 ms in CPython). It complements the "
        "rule engine: the rules are "
        "literal and precise, the model catches reworded attacks.",
        "",
        "## Operating points",
        "",
        "Chosen on the validation split so that a given share of benign validation prompts would be flagged. "
        "No threshold is set below 0.5, so when the model is cleaner than the target on validation data the warn "
        "point stays at 0.5 and flags fewer than 2%.",
        "",
        "| Level | Threshold | Target benign FPR (validation) | Default policy |",
        "|---|---|---|---|",
        f"| warn | {th['warn']} | 2% | warn |",
        f"| block | {th['block']} | 0.5% | block untrusted third-party content; on trusted input and model output, warn "
        "(block only if an injection rule also fired) |",
        f"| critical | {th.get('critical', '–')} | 0.1% | block |",
        "",
        f"Calibration: temperature scaling, T = {summary['temperature']}.",
        "",
        "## Evaluation",
        "",
        "As **direct input** (every text treated as the user's own prompt): recall / false-positive rate of "
        "anything but allow. *Rules* is the deterministic engine alone, *ML* the model alone at its warn point, "
        "*Lump* the full engine (rules + model under the default policy). "
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
        "As **untrusted content** (every text treated as a document or tool result the agent reads, where the "
        "default policy is stricter): *flag* = anything but allow, *block* = blocked. *ML block* is the model "
        "alone at its block point.",
        "",
        "| Evaluation set | Rules recall | Rules FPR | Lump flag recall | Lump flag FPR | ML block recall | ML block FPR "
        "| Lump block recall | Lump block FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in summary["evaluation"]:
        r, f, m, b = row["rules_doc"], row["ensemble_doc"], row["ml_block"], row["ensemble_doc_block"]
        lines.append(f"| {_name(row['name'])} | {r['recall']:.3f} | {r['fpr']:.3f} | {f['recall']:.3f} | {f['fpr']:.3f} | "
                     f"{m['recall']:.3f} | {m['fpr']:.3f} | {b['recall']:.3f} | {b['fpr']:.3f} |")
    tx = summary.get("transformer")
    if tx:
        tth = tx["thresholds"]["warn"]
        lines += [
            "",
            "## Compared with a transformer",
            "",
            f"The same full evaluation sets scored by `{tx['model']}` (184M parameters, about 740 MB, the optional "
            f"backend in `lump model pull`). Recall / FPR at each model's own warn point (Lump {th['warn']}, "
            f"transformer {tth}). The in-distribution row is left out: it is held-out data from Lump's own training "
            "sources, so it would flatter Lump.",
            "",
            "| Evaluation set | n | Lump AUC | Transformer AUC | Lump recall | Transformer recall | Lump FPR | Transformer FPR |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for row in summary["evaluation"]:
            t = tx["sets"].get(row["name"])
            if not t:
                continue
            m = row["ml_warn"]
            lines.append(f"| {_name(row['name'])} | {t['n']} | {m['auc']:.3f} | {t['auc']:.3f} | {m['recall']:.3f} | "
                         f"{t['recall']:.3f} | {m['fpr']:.3f} | {t['fpr']:.3f} |")
    lines += [
        "",
        "## Known limitations",
        "",
        "- It is a bag-of-n-grams model: it has no understanding of *who* an instruction is addressed to, so "
        "carefully constructed benign look-alikes (e.g. a document that quotes an attack for analysis) can score "
        "high, and attacks phrased entirely in vocabulary it has only seen in benign text can score low. The "
        "agentic boundary-pair and guardrail hard-negative sets above are deliberately built from such "
        "near-identical texts and are the hardest case for any classifier, the transformer included.",
        "- Training data is mostly English; other languages are covered by character n-grams only.",
        "- At the warn point it flags a few percent of ordinary prompts on some benign sets (see the FPR columns). "
        "That tier only warns by default; blocking needs the block point on untrusted content or a rule agreeing.",
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
        f"| Lump reworded attacks and hard negatives (this repository) | Apache-2.0 | train | {aug.get('records', 0)} records |",
        "",
        "Attribution: datasets under CC-BY-4.0 and ODC-BY are used under those licenses; see each dataset's card. "
        "Rows inside mixed-license datasets whose upstream licenses are non-commercial or missing were filtered "
        "out (see `sources.py`).",
        "",
        "## Reproduce",
        "",
        "```bash",
        "pip install 'lump[train]'",
        f"lump train --hash-bits {header['features']['hash_bits']} --feature-dropout 0.1 --version {header.get('version')} "
        "--out injection-v1.lumpml --report report.json --card MODEL_CARD.md",
        "# optional: compare with the transformer on the same sets",
        "pip install 'lump[ml]' && lump model pull",
        "lump train --from-weights injection-v1.float.npz --compare-transformer ~/.cache/lump ...",
        "```",
        "",
    ]
    return "\n".join(lines)
