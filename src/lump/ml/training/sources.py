"""Pinned training and evaluation sources for the built-in classifier.

Every source is an *original* public dataset with a license that allows
training on it and shipping the derived weights in an Apache-2.0 project
(Apache-2.0, MIT, CC0, CC-BY-4.0, ODC-BY). Each was vetted (license, label
semantics, label noise, provenance) by two independent reviews; sources that
failed — e.g. unfiltered game logs, labels that only make sense relative to a
hidden system prompt, or "jailbreak" labels that actually mean "harmful
content" — are not used, and mixed-license sources are filtered row by row. Aggregator datasets that re-mix other
sources, some of which carry no license, are deliberately excluded. A
cross-dataset overlap analysis showed that several popular "prompt injection"
datasets are near-total copies of each other.

``role`` controls the split:

* ``train``   — eligible for train / validation / in-distribution test.
* ``holdout`` — never trained on. Used as out-of-distribution evaluation, and
  every text it contains is removed from the training pool (exact and
  near-duplicate) before splitting.

Revisions are pinned (dataset commit sha + sha256 of every parquet shard) so
``lump train`` is reproducible; a changed upstream file is reported, not
silently used.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Source:
    id: str
    license: str
    role: str  # train | holdout
    reader: str  # name of a reader function in corpus.py
    revision: str
    max_rows: int = 0  # 0 = no cap; otherwise a deterministic sample
    notes: str = ""
    citation: str = ""
    files: tuple[str, ...] = field(default=())  # parquet shard names to use (empty = all)


SOURCES: tuple[Source, ...] = (
    # --- attacks + benign, original sources ------------------------------------
    Source("deepset/prompt-injections", "apache-2.0", "train", "label_text", "4f61ecb038e9c3fb77e21034b22511b523772cdd",
           notes="English/German direct injections and benign questions; label 1 = injection."),
    Source("jackhhao/jailbreak-classification", "apache-2.0", "train", "jackhhao", "2f2ceeb39658696fd3f462403562b6eea5306287",
           notes="Jailbreak prompts vs benign prompts; type == 'jailbreak'."),
    Source("Lakera/gandalf_ignore_instructions", "mit", "train", "all_attack_text", "04737b65e90a6794ec227012e4a255a7def6344b",
           notes="Real player attempts at instruction override from the Gandalf game."),
    Source("TrustAIRLab/in-the-wild-jailbreak-prompts", "mit", "train", "trustairlab", "a10aab8eff1c73165a442d4464dce192bd28b9c5",
           notes="CCS'24 in-the-wild prompts. jailbreak=True -> attack; regular role-play prompts are excellent hard negatives.",
           citation="Shen et al., 'Do Anything Now': Characterizing and Evaluating In-The-Wild Jailbreak Prompts, CCS 2024."),
    Source("reshabhs/SPML_Chatbot_Prompt_Injection", "mit", "train", "spml", "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
           notes="Only the operator system prompts are used, as benign hard negatives. The user-prompt labels are relative to the paired system prompt (the card advises against training detectors on them)."),
    Source("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", "cc-by-4.0", "train", "nvidia_indirect", "d738d4f361cc38bb4d7a42b9066776dade5332f5",
           notes="Indirect injections planted in tool/document content for agents (unauthorised actions, exfiltration)."),
    Source("nvidia/Nemotron-RL-Jailbreak-Robustness-v1", "cc-by-4.0", "train", "nvidia_jailbreak", "9c0f85b03a577fa7ec5b15d458ea0380234e4f5e",
           notes="PAIR-paraphrased and encoded jailbreaks. Plain harmful requests without jailbreak framing (sdg_jailbreaks) are excluded."),
    Source("neuralchemy/Prompt-injection-dataset", "apache-2.0", "train", "neuralchemy", "7d70432dfcf47a821612cbf9d34e9d9e3ad20e75",
           notes="Filtered to sources original / neuralchemy_v1 / hackaprompt (CC-BY-4.0) / harmbench_benign; the mislabelled, research-licensed wildguard_judgecomp rows and plain harmful requests are dropped."),
    Source("Bravansky/compact-jailbreaks", "mit", "train", "bravansky", "fdfb5b996723b473945a9bb8113912cb86657c07", max_rows=6000,
           notes="Adversarially rewritten (persona / fiction framed) versions of requests; only the rewritten attack column is used."),
    Source("djapp18/JailbreaksOverTime", "cc-by-4.0", "train", "jailbreaks_over_time", "a5a467cbab4b17d7f1c83e6cd119c61722053868", max_rows=16000,
           notes="Jailbreaks over time plus real WildChat (ODC-BY) user prompts as benign. Rows whose payloads come from BeaverTails (CC-BY-NC-4.0) are excluded."),
    # --- benign pools ------------------------------------------------------------
    Source("OpenAssistant/oasst2", "apache-2.0", "train", "oasst2", "179dd21fc55192153d94adb0e0ce8f69e222bf75", max_rows=24000,
           notes="Human-written prompter turns in many languages."),
    Source("HuggingFaceH4/ultrachat_200k", "mit", "train", "ultrachat", "8049631c405ae6576f93f445c6b8166f76f5505a", max_rows=10000,
           notes="Assistant-style opening prompts."),
    Source("Open-Orca/OpenOrca", "mit", "train", "openorca", "e9c87b4abb2609913751f9b26553fdb9c061796c", max_rows=14000,
           files=("default__train__0.parquet",), notes="FLAN-style task prompts (reading comprehension, translation, QA)."),
    Source("fka/awesome-chatgpt-prompts", "cc0-1.0", "train", "awesome_prompts", "6e13221aadea7f803c2beecd5a8b4618c99d9d83",
           notes="Role-play 'act as' prompts: hard negatives for persona-style jailbreak detection."),
    # --- indirect / agentic injections and benign technical pools (round 2) -------
    Source("microsoft/llmail-inject-challenge", "mit", "train", "llmail", "1063bdf01ec8762b812d5e06ee768a06faa5a6f7", max_rows=9000,
           notes="Attacker emails from Microsoft's LLMail-Inject challenge (SaTML 2025): indirect injections planted in email an assistant reads. Deduplicated, capped per team, challenge-specific goal strings varied."),
    Source("rgeada/tool-response-injections", "apache-2.0", "train", "tool_response_injections", "39050de797f2694f0d72e1086003154de1919379",
           notes="Paired tool responses with and without a planted injection. Injections are joined back to neuralchemy: its benign edge cases, research-only and harmful-request rows, and a builder artifact are dropped."),
    Source("Aditi20/tool-guardrail-dataset", "apache-2.0", "train", "tool_guardrail", "6525096f357ca206f59d3e7f0949267ecc96d1ec",
           notes="Tool outputs with planted instructions and look-alike benign outputs; each attack also gets a format-matched benign twin. The GPL-3.0 NL2Bash rows are excluded."),
    Source("glaiveai/glaive-code-assistant", "apache-2.0", "train", "benign_question", "398ce053096475671e8d3872b8e5b28b59f8fcec", max_rows=9000,
           notes="Real-world style developer questions (encodings, passwords, regexes, shells): hard negatives against topic shortcuts."),
    Source("ise-uiuc/Magicoder-OSS-Instruct-75K", "mit", "train", "benign_problem", "5f839b1f368a76b161028bb9edff055db34022b2", max_rows=5000,
           notes="Programming problems (security-adjacent ones preferred: passwords, API keys, encodings, hashing)."),
    Source("nvidia/OpenCodeInstruct", "cc-by-4.0", "train", "benign_input", "8f3ba5bafe4d6e8db46082cf7ae6741bc370604d", max_rows=3000,
           notes="Programming tasks; the '**Input:**' / '**Sample Input:**' scaffolding is cut so the template is not a benign cue."),
    Source("nvidia/HelpSteer2", "cc-by-4.0", "train", "helpsteer", "990b2711a36180dd19d9c94b8627844866f8982a", max_rows=3000,
           notes="Real user prompts (mostly ShareGPT); opening user turn only, jailbreaks found in it are dropped."),
    # --- out-of-distribution holdouts (never trained on) ---------------------------
    Source("wambosec/prompt-injections", "mit", "holdout", "wambosec", "071ee17a60112b7f9f808398156b430aadfaf1d2",
           notes="88 attack categories incl. encodings; benign developer questions that look similar."),
    Source("zachz/prompt-injection-benchmark", "mit", "holdout", "zachz", "dc0072ad6af8d1be049cdb60959e3ff51df4bcae"),
    Source("DavidTKeane/ai-prompt-ai-injection-dataset", "mit", "holdout", "davidtkeane", "73dd3b0063f31de70fd48b9c75f1712995a27644"),
    Source("3nesdeniz/agentic-prompt-injection-5k", "cc-by-4.0", "train", "label_text", "e658d94dcafc133e3a4483f9f9aa13507f3848c4",
           notes="Agentic / RAG / memory-boundary injections and hard negatives. Trained on; the three sibling 3nesdeniz sets stay held out (texts they share with this one are removed from training)."),
    Source("3nesdeniz/agentic-prompt-injection-boundary-pairs", "cc-by-4.0", "holdout", "label_text", "a5682e7573e1c7bc4b12e64d49c0dcd90ca776cf"),
    Source("3nesdeniz/english-prompt-injection-3k", "cc-by-4.0", "holdout", "label_text", "87f017347aff7887b1de0d9457c9ec01bf7ba8b5"),
    Source("3nesdeniz/guardrail-hard-negatives", "cc-by-4.0", "holdout", "label_text", "638188743abb089708163b2408a0ef6279721869",
           notes="Benign texts that innocently use attack vocabulary (English and Turkish)."),
)
