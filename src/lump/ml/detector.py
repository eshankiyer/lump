"""Engine detector backed by the learned classifier(s).

The rules engine is precise but literal: a reworded attack that avoids its
vocabulary slips through. This detector scores text with the built-in model
(and, if installed, the optional transformer) and emits a finding whose
confidence is the model's calibrated attack probability. Severity follows the
model's own operating points, chosen at training time for target false-
positive rates on held-out benign data:

* ``warn``     (≈2% FPR)   -> MEDIUM
* ``block``    (≈0.5% FPR) -> HIGH
* ``critical`` (≈0.1% FPR) -> CRITICAL

Hidden payloads recovered by the normaliser (Unicode-tag smuggling, base64,
hex ...) are all scored, as are the homoglyph-folded, de-spaced and de-leeted
forms, so encoding an attack, swapping in look-alike letters, spacing it out
or writing it in leetspeak does not hide it from the model.
Very long text is scored within a budget (head and tail, see
:func:`lump.ml.features.clip`); the rules still scan all of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..engine.normalize import Normalized
from ..engine.types import Context, Finding, Severity
from .model import Model

# Recovered layers and de-obfuscated forms the model scores besides the original.
_HIDDEN_VIEWS = ("unicode_tags", "variation_selectors", "despaced", "deleet", "base64", "hex", "percent", "rot13")
_REFS_INJECTION = ("AML.T0051",)
_REFS_JAILBREAK = ("AML.T0054",)


_VIEW_TITLES = {"canonical": " (look-alike letters folded)", "despaced": " (spaced-out letters joined)",
                "deleet": " (leetspeak decoded)"}


@dataclass
class MLSettings:
    enabled: bool = True
    model_path: str | None = None  # None = bundled model
    warn: float | None = None  # override the model's operating points
    block: float | None = None
    critical: float | None = None
    explain: bool = True
    max_chars: int = 100_000  # per view; longer text is scored head + tail
    transformer: bool = False  # optional ONNX transformer backend (the "ml" extra)
    transformer_dir: str | None = None
    model: Model | None = None  # an already-loaded model (takes precedence over model_path)


def resolve_thresholds(model_thresholds: dict, settings: MLSettings | None = None) -> dict[str, float]:
    """Operating points: operator overrides, else the model's, else defaults.

    The result is always ordered (warn <= block <= critical), so overriding one
    tier can never leave another unreachable.
    """

    s = settings or MLSettings()
    t = model_thresholds or {}
    warn = s.warn if s.warn is not None else t.get("warn", 0.5)
    block = s.block if s.block is not None else t.get("block", 0.9)
    critical = s.critical if s.critical is not None else t.get("critical", max(block, 0.995))
    block = max(block, warn)
    critical = max(critical, block)
    return {"warn": float(warn), "block": float(block), "critical": float(critical)}


class MLDetector:
    name = "ml"

    def __init__(self, model: Model | None, settings: MLSettings | None = None, transformer=None):
        self.model = model  # None: only the optional transformer runs
        self.settings = settings or MLSettings()
        th = resolve_thresholds(model.thresholds if model else {}, self.settings)
        self.warn, self.block, self.critical = th["warn"], th["block"], th["critical"]
        self.transformer = transformer

    def _severity(self, p: float) -> Severity | None:
        if p >= self.critical:
            return Severity.CRITICAL
        if p >= self.block:
            return Severity.HIGH
        if p >= self.warn:
            return Severity.MEDIUM
        return None

    @staticmethod
    def views(norm: Normalized) -> list[tuple[str, str]]:
        """The texts the model scores: the original, the homoglyph-folded form
        (only when look-alike letters are present), the de-spaced / de-leeted
        forms and every hidden layer the normaliser recovered. No count cap:
        decoy layers placed in front of a payload must not push it out of view."""

        out = [("original", norm.original)]
        seen = {norm.original}
        if norm.confusable_count and norm.canonical not in seen:
            out.append(("canonical", norm.canonical))
            seen.add(norm.canonical)
        for label, text in norm.views:
            if label in _HIDDEN_VIEWS and text.strip() and text not in seen:
                out.append((label, text))
                seen.add(text)
        return out

    def detect(self, norm: Normalized, ctx: Context) -> list[Finding]:
        best = None
        limit = self.settings.max_chars or None
        for label, text in self.views(norm) if self.model else ():
            if not text.strip():
                continue
            score = self.model.score(text, limit=limit)
            if best is None or score.p_attack > best[1].p_attack:
                best = (label, score, text)
        findings: list[Finding] = []
        if best is not None:
            finding = self._finding("builtin", best[0], best[1], best[2], ctx)
            if finding:
                findings.append(finding)
        if self.transformer is not None:
            finding = self._transformer_finding(norm, ctx)
            if finding:
                findings.append(finding)
        return findings

    def _finding(self, backend: str, view: str, score, text: str, ctx: Context) -> Finding | None:
        p = score.p_attack
        severity = self._severity(p)
        if severity is None:
            return None
        attack_class = max((c for c in score.probs if c != "benign"), key=lambda c: score.probs[c])
        jailbreak = attack_class == "jailbreak"
        explanation = self.model.explain(text, score.window, limit=self.settings.max_chars or None) if self.settings.explain else []
        evidence = ", ".join(f'"{g}"' for g, _ in explanation[:4]) if explanation else f"p={p:.3f}"
        where = "" if view == "original" else _VIEW_TITLES.get(view, f" (hidden in {view.replace('_', ' ')})")
        return Finding(
            detector=self.name,
            rule_id="ML-JB" if jailbreak else "ML-PI",
            title=("Learned classifier: jailbreak" if jailbreak else "Learned classifier: prompt injection")
            + where
            + f" p={p:.2f}",
            severity=severity,
            confidence=round(p, 4),
            category="jailbreak.ml" if jailbreak else "prompt_injection.ml",
            evidence=evidence[:160],
            atlas=(_REFS_JAILBREAK if jailbreak else _REFS_INJECTION) + (("AML.T0051.001",) if ctx.untrusted else ()),
            owasp=("LLM01",),
            metadata={
                "backend": backend,
                "model": f"{self.model.name}@{self.model.version}",
                "p_attack": round(p, 4),
                "probs": {k: round(v, 4) for k, v in score.probs.items()},
                "view": view,
                "window": score.window,
                "windows": score.windows,
                "explanation": explanation,
                "thresholds": {"warn": self.warn, "block": self.block, "critical": self.critical},
            },
        )

    def _transformer_finding(self, norm: Normalized, ctx: Context) -> Finding | None:
        try:
            p = self.transformer.score(norm.original)
        except Exception:  # noqa: BLE001 - optional backend must never break inspection
            return None
        t = self.transformer.thresholds
        severity = (Severity.CRITICAL if p >= t["critical"] else Severity.HIGH if p >= t["block"]
                    else Severity.MEDIUM if p >= t["warn"] else None)
        if severity is None:
            return None
        return Finding(
            detector=self.name,
            rule_id="ML-TX",
            title=f"Transformer classifier: prompt injection p={p:.2f}",
            severity=severity,
            confidence=round(p, 4),
            category="prompt_injection.ml",
            evidence=f"{self.transformer.model_id} p={p:.3f}",
            atlas=_REFS_INJECTION + (("AML.T0051.001",) if ctx.untrusted else ()),
            owasp=("LLM01",),
            metadata={"backend": "transformer", "model": self.transformer.model_id, "p_attack": round(p, 4)},
        )
