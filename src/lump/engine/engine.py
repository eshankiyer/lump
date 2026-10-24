"""The inspection engine: one entry point every enforcement surface calls.

``Engine.inspect(text, context)`` normalises the text, runs the relevant
detectors for the content's direction, redacts sensitive data when the policy
asks, and returns a single :class:`Verdict`. It is deliberately synchronous,
dependency-free and fast so it can sit inline on a gateway, a proxy, an
endpoint sensor or the browser.

A learned classifier (``lump.ml``) runs alongside the rules on anything a
model will read as instructions, catching reworded attacks the patterns miss.
It is pure standard library, bundled with the package, and can be disabled or
pointed at a custom model through :class:`EngineConfig`.

Extra detectors registered through the ``lump.detectors`` entry-point group are
discovered and run automatically.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..ml.detector import MLDetector, MLSettings
from ..policy.model import Policy, default_policy
from .agentic import AgenticDetector, AgentPolicy, ToolCall, ToolDefinition
from .code import CodeDetector
from .dlp import DlpConfig, DlpDetector, redact
from .injection import InjectionDetector
from .normalize import normalize
from .output import OutputDetector
from .types import Action, Context, Direction, Finding, Severity, Verdict

# Which detectors run for each direction. DLP runs everywhere (data can leak in
# any direction); injection runs on anything a model will read as instructions.
_log = logging.getLogger("lump")

_INJECTION_DIRECTIONS = {
    Direction.INPUT,
    Direction.DOCUMENT,
    Direction.TOOL_RESULT,
    Direction.TOOL_DEFINITION,
    Direction.OUTPUT,
    Direction.TOOL_CALL,  # arguments, as in inspect_tool_call
}
_OUTPUT_DIRECTIONS = {Direction.OUTPUT, Direction.TOOL_RESULT, Direction.DOCUMENT}
_CODE_DIRECTIONS = {Direction.OUTPUT, Direction.TOOL_CALL, Direction.ARTIFACT, Direction.TOOL_RESULT}


@dataclass
class EngineConfig:
    dlp: DlpConfig = field(default_factory=DlpConfig)
    enable_injection: bool = True
    enable_dlp: bool = True
    enable_code: bool = True
    enable_output: bool = True
    load_plugins: bool = True
    max_bytes: int = 1_000_000  # content larger than this is truncated for scanning
    ml: MLSettings = field(default_factory=MLSettings)


class Engine:
    def __init__(self, policy: Policy | None = None, config: EngineConfig | None = None):
        self.policy = policy or default_policy()
        self.config = config or EngineConfig()
        self.injection = InjectionDetector() if self.config.enable_injection else None
        self.dlp = DlpDetector(self.config.dlp) if self.config.enable_dlp else None
        self.code = CodeDetector() if self.config.enable_code else None
        self.output = OutputDetector() if self.config.enable_output else None
        self.agentic = AgenticDetector()
        self.ml = self._load_ml(self.config.ml)
        self.plugins = list(self._load_plugins()) if self.config.load_plugins else []

    def _load_ml(self, settings: MLSettings) -> MLDetector | None:
        """Load the learned classifier(s).

        An explicitly configured model or transformer that cannot be loaded is
        an error (the operator asked for it). A missing or damaged *bundled*
        model disables the built-in classifier with a logged warning, visible
        in :meth:`ml_status` and ``/healthz``, instead of failing silently.
        """

        self._ml_error: str | None = None
        if not settings.enabled:
            return None
        from ..ml.model import Model, ModelError, default_model

        if settings.model is not None:
            model = settings.model
        elif settings.model_path:
            try:
                model = Model.load(settings.model_path)
            except OSError as exc:
                raise ModelError(f"[ml] model_path {settings.model_path}: {exc.strerror or exc}") from exc
        else:
            model = default_model()
            if model is None:
                self._ml_error = "bundled model missing or invalid"
                _log.warning("lump: ML is enabled but the bundled model could not be loaded; running rules only")
        transformer = None
        if settings.transformer:
            from ..ml.transformer import TransformerBackend

            transformer = TransformerBackend(settings.transformer_dir)
        if model is None and transformer is None:
            return None
        return MLDetector(model, settings, transformer)

    def ml_status(self) -> dict:
        """What the learned layer is actually running (for /healthz and audits)."""

        ml = self.ml
        return {
            "enabled": self.config.ml.enabled,
            "builtin": f"{ml.model.name}@{ml.model.version}" if ml and ml.model else None,
            "transformer": ml.transformer.model_id if ml and ml.transformer else None,
            "error": self._ml_error,
        }

    # -- text inspection ---------------------------------------------------

    def _limit(self, text: str, findings: list[Finding]) -> str:
        """Cut ``text`` to the inspection limit, recording an ENG-TRUNC finding.

        Never truncate silently: content past the limit is uninspected, and
        padding an attack past it would otherwise be an evasion.
        """

        if len(text) <= self.config.max_bytes:
            return text
        scan_text = text[: self.config.max_bytes]
        findings.append(Finding(
            detector="engine", rule_id="ENG-TRUNC",
            title=f"Content exceeds the inspection limit; only the first {self.config.max_bytes} characters were inspected",
            severity=Severity.MEDIUM, confidence=1.0, category="engine.truncated",
            evidence=f"{len(text)} characters, {len(text) - len(scan_text)} uninspected",
            owasp=("LLM10",), metadata={"length": len(text), "inspected": len(scan_text)},
        ))
        return scan_text

    def inspect(self, text: str, context: Context | dict | None = None) -> Verdict:
        start = time.perf_counter()
        ctx = context if isinstance(context, Context) else Context.from_dict(context)
        findings: list[Finding] = []
        if text:
            scan_text = self._limit(argument_text(text) if ctx.direction is Direction.TOOL_CALL else text, findings)
            norm = normalize(scan_text)

            if self.injection and ctx.direction in _INJECTION_DIRECTIONS:
                findings += self.injection.detect(norm, ctx)
            if self.ml and ctx.direction in _INJECTION_DIRECTIONS:
                findings += self.ml.detect(norm, ctx)
            if self.dlp:
                findings += self.dlp.detect(scan_text)
            if self.code and ctx.direction in _CODE_DIRECTIONS:
                findings += self.code.detect(scan_text)
            if self.output and ctx.direction in _OUTPUT_DIRECTIONS:
                findings += self.output.detect(scan_text)
            for plugin in self.plugins:
                try:
                    findings += list(plugin(scan_text, ctx))
                except TypeError:
                    try:
                        findings += list(plugin(scan_text))
                    except Exception:  # noqa: BLE001
                        continue
                except Exception:  # noqa: BLE001 - a bad plugin must not break inspection
                    continue

        findings = _scrub_ml_evidence(findings, scan_text if text else "")
        verdict = self.policy.evaluate(findings, ctx)
        if self.policy.enforcing and (verdict.action is Action.REDACT or (self.policy.redact_secrets and self._has_redactable(findings))):
            redacted = redact(text, [f for f in findings if f.detector == "dlp"])
            if redacted != text:
                verdict.redacted_text = redacted
                if verdict.action is Action.ALLOW:
                    verdict.action = Action.REDACT
        verdict.latency_ms = (time.perf_counter() - start) * 1000.0
        return verdict

    def _has_redactable(self, findings: list[Finding]) -> bool:
        # Auto-redaction promotes ALLOW->REDACT only for consequential data
        # (secrets, cards, SSNs). Low-severity PII such as a bare email stays
        # visible unless a policy rule explicitly asks to redact it.
        return any(
            f.detector == "dlp" and f.metadata.get("redact", True) and f.span and f.severity >= Severity.MEDIUM
            for f in findings
        )

    # -- agentic inspection ------------------------------------------------

    def inspect_tool_call(self, call: ToolCall, policy: AgentPolicy | None = None, context: Context | dict | None = None) -> Verdict:
        start = time.perf_counter()
        ctx = context if isinstance(context, Context) else Context.from_dict(context)
        ctx.direction = Direction.TOOL_CALL
        findings = self.agentic.inspect_tool_call(call, policy)
        if call.arguments:
            # Arguments usually arrive as JSON with \\uXXXX escapes (json.dumps
            # defaults to ASCII); detectors must see the text as written.
            args_text = self._limit(argument_text(call.arguments), findings)
            norm = normalize(args_text)
            if self.injection:
                findings += self.injection.detect(norm, Context(direction=Direction.INPUT, trusted=False))
            if self.ml:
                findings += self.ml.detect(norm, Context(direction=Direction.INPUT, trusted=False))
            if self.dlp:
                findings += self.dlp.detect(args_text)
            if self.code:
                findings += self.code.detect(args_text)
            findings = _scrub_ml_evidence(findings, args_text)
        verdict = self.policy.evaluate(findings, ctx)
        verdict.latency_ms = (time.perf_counter() - start) * 1000.0
        return verdict

    def inspect_tool_definition(self, tool: ToolDefinition, context: Context | dict | None = None) -> Verdict:
        start = time.perf_counter()
        ctx = context if isinstance(context, Context) else Context.from_dict(context)
        ctx.direction = Direction.TOOL_DEFINITION
        findings = self.agentic.inspect_tool_definition(tool)
        blob = f"{tool.description}\n{argument_text(tool.schema)}"
        if blob.strip():
            norm = normalize(self._limit(blob, findings))
            if self.injection:
                findings += self.injection.detect(norm, ctx)
            if self.ml:
                findings += self.ml.detect(norm, ctx)
        verdict = self.policy.evaluate(findings, ctx)
        verdict.latency_ms = (time.perf_counter() - start) * 1000.0
        return verdict

    # -- plugin discovery --------------------------------------------------

    def _load_plugins(self) -> Iterable:
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover
            return
        try:
            eps = entry_points(group="lump.detectors")
        except TypeError:  # pragma: no cover - older API
            eps = entry_points().get("lump.detectors", [])
        for ep in eps:
            try:
                factory = ep.load()
                detector = factory() if callable(factory) else factory
                run = getattr(detector, "detect", detector)
                if callable(run):
                    yield run
            except Exception:  # noqa: BLE001
                continue


def argument_text(arguments: str) -> str:
    """Readable text of a JSON tool-call payload: one ``key: value`` line per
    leaf with string escapes decoded. Non-JSON input is returned unchanged."""

    try:
        data = json.loads(arguments)
    except (ValueError, RecursionError):
        return arguments
    if isinstance(data, str):
        return data
    lines: list[str] = []
    stack: list[tuple[str, object]] = [("", data)]
    while stack:  # iterative: arbitrarily deep JSON must not exhaust the stack
        key, obj = stack.pop()
        if isinstance(obj, (dict, list)):
            if key:  # keys can carry text too
                lines.append(key)
            items = [(str(k), v) for k, v in obj.items()] if isinstance(obj, dict) else [("", v) for v in obj]
            stack.extend(reversed(items))
        else:
            value = obj if isinstance(obj, str) else json.dumps(obj)
            lines.append(f"{key}: {value}" if key else value)
    return "\n".join(lines)


def _scrub_ml_evidence(findings: list[Finding], text: str) -> list[Finding]:
    """Drop ML explanation n-grams that come from text DLP flagged.

    DLP masks its own evidence; without this, the classifier's top n-grams
    could repeat part of the same secret in the same response.
    """

    spans = [f.span for f in findings if f.detector == "dlp" and f.span]
    if not spans or not any(f.detector == "ml" for f in findings):
        return findings
    from dataclasses import replace

    from ..ml.features import normalize as ml_normalize

    secrets = [ml_normalize(text[a:b]) for a, b in spans]
    out = []
    for f in findings:
        expl = f.metadata.get("explanation") if f.detector == "ml" else None
        if expl:
            kept = [(g, w) for g, w in expl if not any(g and g in s for s in secrets)]
            if len(kept) != len(expl):
                evidence = ", ".join(f'"{g}"' for g, _ in kept[:4]) or f"p={f.confidence:.3f}"
                f = replace(f, evidence=evidence[:160], metadata={**f.metadata, "explanation": kept})
        out.append(f)
    return out
