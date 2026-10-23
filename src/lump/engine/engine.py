"""The inspection engine: one entry point every enforcement surface calls.

``Engine.inspect(text, context)`` normalises the text, runs the relevant
detectors for the content's direction, redacts sensitive data when the policy
asks, and returns a single :class:`Verdict`. It is deliberately synchronous,
dependency-free and fast so it can sit inline on a gateway, a proxy, an
endpoint sensor or the browser.

Extra detectors registered through the ``lump.detectors`` entry-point group are
discovered and run automatically.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..policy.model import Policy, default_policy
from .agentic import AgenticDetector, AgentPolicy, ToolCall, ToolDefinition
from .code import CodeDetector
from .dlp import DlpConfig, DlpDetector, redact
from .injection import InjectionDetector
from .normalize import normalize
from .output import OutputDetector
from .types import Action, Context, Direction, Finding, Verdict

# Which detectors run for each direction. DLP runs everywhere (data can leak in
# any direction); injection runs on anything a model will read as instructions.
_INJECTION_DIRECTIONS = {
    Direction.INPUT,
    Direction.DOCUMENT,
    Direction.TOOL_RESULT,
    Direction.TOOL_DEFINITION,
    Direction.OUTPUT,
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


class Engine:
    def __init__(self, policy: Policy | None = None, config: EngineConfig | None = None):
        self.policy = policy or default_policy()
        self.config = config or EngineConfig()
        self.injection = InjectionDetector() if self.config.enable_injection else None
        self.dlp = DlpDetector(self.config.dlp) if self.config.enable_dlp else None
        self.code = CodeDetector() if self.config.enable_code else None
        self.output = OutputDetector() if self.config.enable_output else None
        self.agentic = AgenticDetector()
        self.plugins = list(self._load_plugins()) if self.config.load_plugins else []

    # -- text inspection ---------------------------------------------------

    def inspect(self, text: str, context: Context | dict | None = None) -> Verdict:
        start = time.perf_counter()
        ctx = context if isinstance(context, Context) else Context.from_dict(context)
        findings: list[Finding] = []
        if text:
            scan_text = text if len(text) <= self.config.max_bytes else text[: self.config.max_bytes]
            norm = normalize(scan_text)

            if self.injection and ctx.direction in _INJECTION_DIRECTIONS:
                findings += self.injection.detect(norm, ctx)
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

        verdict = self.policy.evaluate(findings, ctx)
        if verdict.action is Action.REDACT or (self.policy.redact_secrets and self._has_redactable(findings)):
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
        from .types import Severity

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
            norm = normalize(call.arguments)
            if self.injection:
                findings += self.injection.detect(norm, Context(direction=Direction.INPUT, trusted=False))
            if self.dlp:
                findings += self.dlp.detect(call.arguments)
            if self.code:
                findings += self.code.detect(call.arguments)
        verdict = self.policy.evaluate(findings, ctx)
        verdict.latency_ms = (time.perf_counter() - start) * 1000.0
        return verdict

    def inspect_tool_definition(self, tool: ToolDefinition, context: Context | dict | None = None) -> Verdict:
        start = time.perf_counter()
        ctx = context if isinstance(context, Context) else Context.from_dict(context)
        ctx.direction = Direction.TOOL_DEFINITION
        findings = self.agentic.inspect_tool_definition(tool)
        blob = f"{tool.description}\n{tool.schema}"
        if blob.strip() and self.injection:
            findings += self.injection.detect(normalize(blob), ctx)
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
