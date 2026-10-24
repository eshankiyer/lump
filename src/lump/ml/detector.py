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
hex ...) are scored too, so encoding an attack does not hide it from the model.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..engine.normalize import Normalized
from ..engine.types import Context, Finding, Severity
from .model import Model

_HIDDEN_VIEWS = ("unicode_tags", "variation_selectors", "base64", "hex", "percent", "rot13")
_REFS_INJECTION = ("AML.T0051",)
_REFS_JAILBREAK = ("AML.T0054",)


@dataclass
class MLSettings:
    enabled: bool = True
    model_path: str | None = None  # None = bundled model
    warn: float | None = None  # override the model's operating points
    block: float | None = None
    critical: float | None = None
    explain: bool = True
    max_views: int = 4
    transformer: bool = False  # optional ONNX transformer backend (lump[ml])
    transformer_dir: str | None = None
    model: Model | None = None  # an already-loaded model (takes precedence over model_path)


class MLDetector:
    name = "ml"

    def __init__(self, model: Model, settings: MLSettings | None = None, transformer=None):
        self.model = model
        self.settings = settings or MLSettings()
        t = model.thresholds
        self.warn = self.settings.warn if self.settings.warn is not None else t.get("warn", 0.5)
        self.block = self.settings.block if self.settings.block is not None else t.get("block", 0.9)
        self.critical = self.settings.critical if self.settings.critical is not None else t.get("critical", max(self.block, 0.995))
        self.transformer = transformer

    def _severity(self, p: float) -> Severity | None:
        if p >= self.critical:
            return Severity.CRITICAL
        if p >= self.block:
            return Severity.HIGH
        if p >= self.warn:
            return Severity.MEDIUM
        return None

    def detect(self, norm: Normalized, ctx: Context) -> list[Finding]:
        candidates = [("original", norm.original)] + [(label, text) for label, text in norm.views if label in _HIDDEN_VIEWS]
        best = None
        for label, text in candidates[: self.settings.max_views]:
            if not text.strip():
                continue
            score = self.model.score(text)
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
        explanation = self.model.explain(text, score.window) if self.settings.explain else []
        evidence = ", ".join(f'"{g}"' for g, _ in explanation[:4]) if explanation else f"p={p:.3f}"
        hidden = view != "original"
        return Finding(
            detector=self.name,
            rule_id="ML-JB" if jailbreak else "ML-PI",
            title=("Learned classifier: jailbreak" if jailbreak else "Learned classifier: prompt injection")
            + (f" (hidden in {view.replace('_', ' ')})" if hidden else "")
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
