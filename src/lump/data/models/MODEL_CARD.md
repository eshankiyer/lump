# Lump built-in prompt-injection classifier — model card

**Model:** `lump-injection` version `2026.10.1`, 1.58 MB, format 1, classes benign, injection, jailbreak.

## What it is

A multinomial logistic-regression model over hashed word 1–2-grams and character 3–5-grams (2^19 buckets, signed hashing, sub-linear TF, L2 norm), int8-quantised. It runs with zero dependencies in Python and in the browser extension, from the same file, and scores a typical prompt in well under a millisecond (about 0.3 ms in CPython). It complements the rule engine: the rules are literal and precise, the model catches reworded attacks.

## Operating points

Chosen on the validation split so that a given share of benign validation prompts would be flagged. No threshold is set below 0.5, so when the model is cleaner than the target on validation data the warn point stays at 0.5 and flags fewer than 2%.

| Level | Threshold | Target benign FPR (validation) | Default policy |
|---|---|---|---|
| warn | 0.5 | 2% | warn |
| block | 0.8807 | 0.5% | block untrusted third-party content; on trusted input and model output, warn (block only if an injection rule also fired) |
| critical | 0.9641 | 0.1% | block |

Calibration: temperature scaling, T = 1.0263.

## Evaluation

As **direct input** (every text treated as the user's own prompt): recall / false-positive rate of anything but allow. *Rules* is the deterministic engine alone, *ML* the model alone at its warn point, *Lump* the full engine (rules + model under the default policy). Out-of-distribution sets were never trained on; exact and near-duplicates of every evaluation text were removed from the training pool. One caveat, stated plainly: the first model's false positives on `wambosec` (benign developer questions) are what motivated adding benign developer-question pools, so that row is partly a development set; the other out-of-distribution rows were not used to make any decision. Hyper-parameters were fixed in advance, not tuned on any evaluation set. The three `3nesdeniz` holdouts come from the same author as one training source (`agentic-prompt-injection-5k`), so they are same-family rather than fully independent.

| Evaluation set | n | Rules recall | ML recall | Lump recall | Rules FPR | ML FPR | Lump FPR | ML AUC |
|---|---|---|---|---|---|---|---|---|
| In-distribution test (held-out 10% of the training pool) | 13604 | 0.222 | 0.964 | 0.968 | 0.010 | 0.017 | 0.025 | 0.997 |
| `wambosec/prompt-injections` (out-of-distribution holdout) | 5726 | 0.336 | 0.840 | 0.854 | 0.000 | 0.024 | 0.024 | 0.985 |
| `zachz/prompt-injection-benchmark` (out-of-distribution holdout) | 303 | 0.265 | 0.770 | 0.785 | 0.000 | 0.000 | 0.000 | 0.993 |
| `DavidTKeane/ai-prompt-ai-injection-dataset` (out-of-distribution holdout) | 86 | 0.262 | 0.590 | 0.623 | 0.000 | 0.000 | 0.000 | 0.908 |
| `3nesdeniz/agentic-prompt-injection-boundary-pairs` (out-of-distribution holdout) | 1200 | 0.185 | 0.648 | 0.662 | 0.100 | 0.240 | 0.272 | 0.748 |
| `3nesdeniz/english-prompt-injection-3k` (out-of-distribution holdout) | 3050 | 0.287 | 0.712 | 0.752 | 0.117 | 0.109 | 0.188 | 0.906 |
| `3nesdeniz/guardrail-hard-negatives` (out-of-distribution holdout) | 2500 | 0.086 | 0.550 | 0.557 | 0.061 | 0.077 | 0.111 | 0.782 |
| Reworded attacks + hard negatives (written for this project, never trained on) | 336 | 0.093 | 0.573 | 0.587 | 0.038 | 0.046 | 0.077 | 0.874 |

As **untrusted content** (every text treated as a document or tool result the agent reads, where the default policy is stricter): *flag* = anything but allow, *block* = blocked. *ML block* is the model alone at its block point.

| Evaluation set | Rules recall | Rules FPR | Lump flag recall | Lump flag FPR | ML block recall | ML block FPR | Lump block recall | Lump block FPR |
|---|---|---|---|---|---|---|---|---|
| In-distribution test (held-out 10% of the training pool) | 0.288 | 0.020 | 0.970 | 0.035 | 0.926 | 0.006 | 0.933 | 0.017 |
| `wambosec/prompt-injections` (out-of-distribution holdout) | 0.406 | 0.011 | 0.871 | 0.033 | 0.669 | 0.006 | 0.703 | 0.010 |
| `zachz/prompt-injection-benchmark` (out-of-distribution holdout) | 0.300 | 0.000 | 0.790 | 0.000 | 0.605 | 0.000 | 0.650 | 0.000 |
| `DavidTKeane/ai-prompt-ai-injection-dataset` (out-of-distribution holdout) | 0.262 | 0.000 | 0.623 | 0.000 | 0.443 | 0.000 | 0.475 | 0.000 |
| `3nesdeniz/agentic-prompt-injection-boundary-pairs` (out-of-distribution holdout) | 0.202 | 0.100 | 0.662 | 0.272 | 0.407 | 0.115 | 0.418 | 0.158 |
| `3nesdeniz/english-prompt-injection-3k` (out-of-distribution holdout) | 0.316 | 0.118 | 0.758 | 0.189 | 0.491 | 0.047 | 0.531 | 0.122 |
| `3nesdeniz/guardrail-hard-negatives` (out-of-distribution holdout) | 0.135 | 0.063 | 0.560 | 0.111 | 0.506 | 0.035 | 0.509 | 0.072 |
| Reworded attacks + hard negatives (written for this project, never trained on) | 0.107 | 0.057 | 0.587 | 0.092 | 0.293 | 0.008 | 0.307 | 0.034 |

## Compared with a transformer

The same full evaluation sets scored by `protectai/deberta-v3-base-prompt-injection-v2@90c9989b1a34` (184M parameters, about 740 MB, the optional backend in `lump model pull`). Recall / FPR at each model's own warn point (Lump 0.5, transformer 0.9). The in-distribution row is left out: it is held-out data from Lump's own training sources, so it would flatter Lump.

| Evaluation set | n | Lump AUC | Transformer AUC | Lump recall | Transformer recall | Lump FPR | Transformer FPR |
|---|---|---|---|---|---|---|---|
| `wambosec/prompt-injections` (out-of-distribution holdout) | 5726 | 0.985 | 0.987 | 0.840 | 0.867 | 0.024 | 0.013 |
| `zachz/prompt-injection-benchmark` (out-of-distribution holdout) | 303 | 0.993 | 0.987 | 0.770 | 0.745 | 0.000 | 0.000 |
| `DavidTKeane/ai-prompt-ai-injection-dataset` (out-of-distribution holdout) | 86 | 0.908 | 0.890 | 0.590 | 0.557 | 0.000 | 0.000 |
| `3nesdeniz/agentic-prompt-injection-boundary-pairs` (out-of-distribution holdout) | 1200 | 0.748 | 0.722 | 0.648 | 0.830 | 0.240 | 0.528 |
| `3nesdeniz/english-prompt-injection-3k` (out-of-distribution holdout) | 3050 | 0.906 | 0.852 | 0.712 | 0.904 | 0.109 | 0.347 |
| `3nesdeniz/guardrail-hard-negatives` (out-of-distribution holdout) | 2500 | 0.782 | 0.714 | 0.550 | 0.642 | 0.077 | 0.371 |
| Reworded attacks + hard negatives (written for this project, never trained on) | 336 | 0.874 | 0.907 | 0.573 | 0.893 | 0.046 | 0.195 |

## Known limitations

- It is a bag-of-n-grams model: it has no understanding of *who* an instruction is addressed to, so carefully constructed benign look-alikes (e.g. a document that quotes an attack for analysis) can score high, and attacks phrased entirely in vocabulary it has only seen in benign text can score low. The agentic boundary-pair and guardrail hard-negative sets above are deliberately built from such near-identical texts and are the hardest case for any classifier, the transformer included.
- Training data is mostly English; other languages are covered by character n-grams only.
- At the warn point it flags a few percent of ordinary prompts on some benign sets (see the FPR columns). That tier only warns by default; blocking needs the block point on untrusted content or a rule agreeing.
- Thresholds were set on validation data drawn from the training sources; real traffic differs. Start in `mode = "monitor"`, look at what it flags, then tune `[ml] warn/block` if needed.

## Training data

Original public datasets only, each vetted for license, label meaning and noise by two independent reviews; aggregator datasets that re-mix other sources (some unlicensed) are excluded. Revisions and file hashes are pinned in `src/lump/ml/training/sources.lock.json`.

| Dataset | License | Role | Revision |
|---|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | apache-2.0 | train | `4f61ecb038e9` |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | apache-2.0 | train | `2f2ceeb39658` |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | mit | train | `04737b65e90a` |
| [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | mit | train | `a10aab8eff1c` |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | mit | train | `02ce8084e979` |
| [nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1](https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1) | cc-by-4.0 | train | `d738d4f361cc` |
| [nvidia/Nemotron-RL-Jailbreak-Robustness-v1](https://huggingface.co/datasets/nvidia/Nemotron-RL-Jailbreak-Robustness-v1) | cc-by-4.0 | train | `9c0f85b03a57` |
| [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | apache-2.0 | train | `7d70432dfcf4` |
| [Bravansky/compact-jailbreaks](https://huggingface.co/datasets/Bravansky/compact-jailbreaks) | mit | train | `fdfb5b996723` |
| [djapp18/JailbreaksOverTime](https://huggingface.co/datasets/djapp18/JailbreaksOverTime) | cc-by-4.0 | train | `a5a467cbab4b` |
| [OpenAssistant/oasst2](https://huggingface.co/datasets/OpenAssistant/oasst2) | apache-2.0 | train | `179dd21fc551` |
| [HuggingFaceH4/ultrachat_200k](https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k) | mit | train | `8049631c405a` |
| [Open-Orca/OpenOrca](https://huggingface.co/datasets/Open-Orca/OpenOrca) | mit | train | `e9c87b4abb26` |
| [fka/awesome-chatgpt-prompts](https://huggingface.co/datasets/fka/awesome-chatgpt-prompts) | cc0-1.0 | train | `6e13221aadea` |
| [microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | mit | train | `1063bdf01ec8` |
| [rgeada/tool-response-injections](https://huggingface.co/datasets/rgeada/tool-response-injections) | apache-2.0 | train | `39050de797f2` |
| [Aditi20/tool-guardrail-dataset](https://huggingface.co/datasets/Aditi20/tool-guardrail-dataset) | apache-2.0 | train | `6525096f357c` |
| [glaiveai/glaive-code-assistant](https://huggingface.co/datasets/glaiveai/glaive-code-assistant) | apache-2.0 | train | `398ce0530964` |
| [ise-uiuc/Magicoder-OSS-Instruct-75K](https://huggingface.co/datasets/ise-uiuc/Magicoder-OSS-Instruct-75K) | mit | train | `5f839b1f368a` |
| [nvidia/OpenCodeInstruct](https://huggingface.co/datasets/nvidia/OpenCodeInstruct) | cc-by-4.0 | train | `8f3ba5bafe4d` |
| [nvidia/HelpSteer2](https://huggingface.co/datasets/nvidia/HelpSteer2) | cc-by-4.0 | train | `990b2711a361` |
| [wambosec/prompt-injections](https://huggingface.co/datasets/wambosec/prompt-injections) | mit | holdout | `071ee17a6011` |
| [zachz/prompt-injection-benchmark](https://huggingface.co/datasets/zachz/prompt-injection-benchmark) | mit | holdout | `dc0072ad6af8` |
| [DavidTKeane/ai-prompt-ai-injection-dataset](https://huggingface.co/datasets/DavidTKeane/ai-prompt-ai-injection-dataset) | mit | holdout | `73dd3b0063f3` |
| [3nesdeniz/agentic-prompt-injection-5k](https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k) | cc-by-4.0 | train | `e658d94dcafc` |
| [3nesdeniz/agentic-prompt-injection-boundary-pairs](https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-boundary-pairs) | cc-by-4.0 | holdout | `a5682e7573e1` |
| [3nesdeniz/english-prompt-injection-3k](https://huggingface.co/datasets/3nesdeniz/english-prompt-injection-3k) | cc-by-4.0 | holdout | `87f017347aff` |
| [3nesdeniz/guardrail-hard-negatives](https://huggingface.co/datasets/3nesdeniz/guardrail-hard-negatives) | cc-by-4.0 | holdout | `638188743abb` |
| Lump reworded attacks and hard negatives (this repository) | Apache-2.0 | train | 1028 records |

Attribution: datasets under CC-BY-4.0 and ODC-BY are used under those licenses; see each dataset's card. Rows inside mixed-license datasets whose upstream licenses are non-commercial or missing were filtered out (see `sources.py`).

## Reproduce

```bash
pip install 'lump[train]'
lump train --hash-bits 19 --feature-dropout 0.1 --version 2026.10.1 --out injection-v1.lumpml --report report.json --card MODEL_CARD.md
# optional: compare with the transformer on the same sets
pip install 'lump[ml]' && lump model pull
lump train --from-weights injection-v1.float.npz --compare-transformer ~/.cache/lump ...
```

