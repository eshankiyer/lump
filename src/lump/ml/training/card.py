"""Render the model card (Markdown) from a training report."""

from __future__ import annotations

from .sources import SOURCES

_PRETTY = {
    "test_id": "In-distribution test (held-out 10% of the training pool)",
    "reworded": "Reworded attacks + hard negatives (written for this project, never trained on)",
}


# `lump train` defaults (see cli.py); the reproduce line names only the flags that differ.
_DEFAULTS = {"epochs": 12, "weight_decay": 1e-6, "feature_dropout": 0.0}


def _name(split: str) -> str:
    if split in _PRETTY:
        return _PRETTY[split]
    if split.startswith("ood:"):
        return f"`{split[4:]}` (out-of-distribution holdout)"
    return split


def _flags(summary: dict, header: dict) -> str:
    """Training flags for the reproduce line, from the run's recorded
    hyper-parameters (only the ones that differ from the CLI defaults)."""

    hp = summary.get("hyperparameters") or {}
    flags = [f"--hash-bits {hp.get('hash_bits', header['features']['hash_bits'])}"]
    for key, default in _DEFAULTS.items():
        if key in hp and hp[key] != default:
            flags.append(f"--{key.replace('_', '-')} {hp[key]}")
    return " ".join(flags)


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
        "any non-allow verdict that carries at least one injection-type finding (from the injection, agentic, "
        "output or ML detector); a verdict caused only by other findings, such as a DLP redaction of a card "
        "number or API key, is not counted. *Rules* is the deterministic engine alone, *ML* the model alone at "
        "its warn point, *Lump* the full engine (rules + model under the default policy).",
        "",
        "Out-of-distribution sets were never trained on. Exact duplicates (compared after lower-casing and "
        "collapsing everything but ASCII letters and digits) and near-duplicates (MinHash over word 5-grams, "
        "estimated Jaccard ≥ 0.7, for texts of five or more words) of every out-of-distribution and reworded "
        "evaluation text were removed from the training pool. The in-distribution test split is a hash split of "
        "that same pool: it shares no exact duplicates with the training split but is not near-deduplicated "
        "against it, so templated near-variants can appear in both.",
        "",
        "Caveats, stated plainly. The first model's false positives on `wambosec` (benign developer questions) "
        "are what motivated adding benign developer-question pools, so that row is partly a development set. "
        "Likewise, the benign Turkish texts in `3nesdeniz/guardrail-hard-negatives` exposed a false positive in "
        "the rules' homoglyph check (OB-005 flagged ordinary letters such as the Turkish dotless ı and, as "
        "untrusted content, blocked 618 of its 1,500 benign texts). That was fixed before this evaluation, so "
        "that row's Rules and Lump false-positive rates are partly development numbers. The remaining "
        "out-of-distribution rows were not used to make any decision. Hyper-parameters are the `lump train` "
        "defaults except feature dropout, set to 0.1 after an earlier run without it had been evaluated on "
        "every evaluation set; no systematic hyper-parameter search was run on the evaluation sets. The three "
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
        "default policy is stricter): *flag* = any verdict other than allow that carries an injection-type "
        "finding (from the injection, agentic, output or ML detector), *block* = blocked with such a finding; "
        "verdicts caused only by other detectors such as DLP are not counted (this applies to the Rules columns "
        "too). *ML block* is the model alone at its block point.",
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
            f"backend in `lump model pull`). The *Lump model* columns are the built-in model alone (the *ML* "
            f"columns above), not the full engine. Recall / FPR at each model's own warn point (Lump model "
            f"{th['warn']}, transformer {tth}). The in-distribution row is left out: it is held-out data from "
            "Lump's own training sources, so it would flatter Lump.",
            "",
            "| Evaluation set | n | Lump model AUC | Transformer AUC | Lump model recall | Transformer recall "
            "| Lump model FPR | Transformer FPR |",
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
        "- Training data is mostly English. Word n-grams are built only from runs of ASCII letters and digits, "
        "so text in non-Latin scripts is covered by character n-grams only, and words with accented or other "
        "non-ASCII letters are split at those letters and rely mainly on character n-grams. Texts with no ASCII "
        "letters or digits at all are skipped when the corpus is built, so the model has seen very little "
        "non-Latin-script text.",
        "- At the warn point it flags a few percent of ordinary prompts on some benign sets (see the FPR columns). "
        f"That tier only warns by default. The model blocks on its own at the block point ({th['block']}) on "
        "untrusted third-party content (documents, tool results, tool definitions, or input marked untrusted), "
        f"and at the critical point ({th.get('critical', '–')}) on any content, including the user's own input "
        "and model output. At the block point on trusted input or model output, it blocks only when an "
        "injection rule (medium or above) also fired.",
        "- Thresholds were set on validation data drawn from the training sources; real traffic differs. "
        "Start in `mode = \"monitor\"`, look at what it flags, then tune `[ml] warn/block` if needed.",
        "",
        "## Training data",
        "",
        "Public datasets, each vetted for license, label meaning and noise by two independent reviews. Most are "
        "original datasets; two are compilations of other sources (neuralchemy/Prompt-injection-dataset and "
        "djapp18/JailbreaksOverTime) and are used only for the rows whose upstream license allows it. Aggregator "
        "datasets that re-mix unlicensed sources are excluded. Revisions and file hashes are pinned in "
        "`src/lump/ml/training/sources.lock.json`.",
        "",
        "| Dataset | License | Role | Revision |",
        "|---|---|---|---|",
    ]
    for s in SOURCES:
        lines.append(f"| [{s.id}](https://huggingface.co/datasets/{s.id}) | {s.license} | {s.role} | `{s.revision[:12]}` |")
    aug = header.get("training", {}).get("augmentation", {})
    lines += [
        "| Lump benign hard negatives (this repository: reworded_augment.jsonl + hard_negatives.jsonl) "
        f"| Apache-2.0 | train | {aug.get('records', 0)} records |",
        "",
        "Attribution: datasets under CC-BY-4.0 and ODC-BY are used under those licenses; see each dataset's card. "
        "Rows inside mixed-license datasets whose upstream licenses do not permit this use were filtered out: "
        "non-commercial or research-only rows (BeaverTails-derived payloads in JailbreaksOverTime; WildGuard rows "
        "in neuralchemy/Prompt-injection-dataset and rgeada/tool-response-injections) and copyleft rows (GPL-3.0 "
        "NL2Bash rows in Aditi20/tool-guardrail-dataset; CC-BY-SA StackOverflow paraphrases, rows 0–31,003, in "
        "glaiveai/glaive-code-assistant). See `sources.py` and `corpus.py`.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "pip install '.[train]'          # from a clone of this repository",
        f"lump train {_flags(summary, header)} --version {header.get('version')} "
        "--out injection-v1.lumpml --report report.json --card MODEL_CARD.md",
        "# optional: compare with the transformer on the same sets",
        "pip install '.[ml]' && lump model pull",
        "lump train --from-weights injection-v1.float.npz --compare-transformer ~/.cache/lump ...",
        "```",
        "",
    ]
    return "\n".join(lines)
