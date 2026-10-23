"""Core data types shared by every detector, sensor and the control plane."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


class Action(enum.Enum):
    """What should happen to the inspected content. Ordered by strictness."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]

    @classmethod
    def parse(cls, value: str | Action) -> Action:
        if isinstance(value, Action):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError:
            raise ValueError(f"unknown action {value!r}") from None

    @staticmethod
    def strictest(actions: list[Action] | tuple[Action, ...]) -> Action:
        return max(actions, key=lambda a: a.rank, default=Action.ALLOW)


_ACTION_RANK = {Action.ALLOW: 0, Action.WARN: 1, Action.REDACT: 2, Action.BLOCK: 3}


class Direction(enum.Enum):
    """Where the inspected content sits in an AI interaction."""

    INPUT = "input"  # a prompt the user (or an app) sends to a model
    OUTPUT = "output"  # a model response
    TOOL_CALL = "tool_call"  # an agent asking to run a tool
    TOOL_RESULT = "tool_result"  # data a tool returned to an agent
    DOCUMENT = "document"  # retrieved / uploaded content (RAG, files, web pages)
    ARTIFACT = "artifact"  # a file written to disk (scripts, binaries)
    TOOL_DEFINITION = "tool_definition"  # MCP / function tool metadata

    @classmethod
    def parse(cls, value: str | Direction) -> Direction:
        if isinstance(value, Direction):
            return value
        return cls(value.strip().lower())


# Content that did not come from the principal (the human user or the
# operator's system prompt) is untrusted: instructions inside it are a sign of
# indirect prompt injection.
UNTRUSTED_DIRECTIONS = frozenset(
    {Direction.TOOL_RESULT, Direction.DOCUMENT, Direction.TOOL_DEFINITION, Direction.OUTPUT}
)


@dataclass
class Context:
    """Who and what an inspection is about. All fields are optional."""

    direction: Direction = Direction.INPUT
    source: str = "api"  # browser | gateway | proxy | host | mcp | cli | api
    user: str | None = None
    app: str | None = None  # process name, extension origin, client id ...
    host: str | None = None  # machine the content came from
    destination: str | None = None  # AI service hostname
    service_id: str | None = None  # catalog id once resolved
    session_id: str | None = None  # agent / conversation id for correlation
    trusted: bool | None = None  # override the direction-based trust default

    def __post_init__(self) -> None:
        # Coerce a string direction to the enum so callers can pass either.
        if not isinstance(self.direction, Direction):
            self.direction = Direction.parse(self.direction)

    @property
    def untrusted(self) -> bool:
        if self.trusted is not None:
            return not self.trusted
        return self.direction in UNTRUSTED_DIRECTIONS

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["direction"] = self.direction.value
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Context:
        data = dict(data or {})
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in known}
        if "direction" in kwargs:
            kwargs["direction"] = Direction.parse(kwargs["direction"])
        if "trusted" in kwargs and kwargs["trusted"] is not None:
            kwargs["trusted"] = bool(kwargs["trusted"])
        for key in ("source", "user", "app", "host", "destination", "service_id", "session_id"):
            if key in kwargs and kwargs[key] is not None:
                kwargs[key] = str(kwargs[key])[:256]
        return cls(**kwargs)


@dataclass(frozen=True)
class Finding:
    detector: str  # injection | dlp | code | agentic | shadow_ai | output | hidden | mcp | canary | ...
    rule_id: str
    title: str
    severity: Severity
    confidence: float = 1.0
    category: str = ""
    evidence: str = ""  # always masked / truncated, never a raw secret
    span: tuple[int, int] | None = None
    atlas: tuple[str, ...] = ()  # MITRE ATLAS technique ids
    attack: tuple[str, ...] = ()  # MITRE ATT&CK technique ids
    owasp: tuple[str, ...] = ()  # OWASP LLM Top 10 (2025) / Agentic Top 10 (2026) ids
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "detector": self.detector,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": round(self.confidence, 3),
            "category": self.category,
            "evidence": self.evidence,
        }
        if self.span is not None:
            d["span"] = list(self.span)
        for key in ("atlas", "attack", "owasp"):
            value = getattr(self, key)
            if value:
                d[key] = list(value)
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class Verdict:
    action: Action
    risk: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None
    reasons: list[str] = field(default_factory=list)
    policy: str = "default"
    mode: str = "enforce"
    latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self, include_redacted: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "action": self.action.value,
            "risk": self.risk,
            "severity": self.max_severity.label,
            "findings": [f.to_dict() for f in self.findings],
            "reasons": self.reasons,
            "policy": self.policy,
            "mode": self.mode,
            "latency_ms": round(self.latency_ms, 3),
        }
        if include_redacted and self.redacted_text is not None:
            d["redacted_text"] = self.redacted_text
        return d


def mask(value: str, keep: int = 4, limit: int = 80) -> str:
    """Mask a sensitive value for display: keep a short prefix and the length."""

    value = value.replace("\n", " ").replace("\r", " ")
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}…[{len(value)} chars]"


def snippet(text: str, start: int, end: int, limit: int = 120) -> str:
    """A short, single-line excerpt of non-sensitive evidence."""

    excerpt = text[start:end]
    excerpt = " ".join(excerpt.split())
    if len(excerpt) > limit:
        excerpt = excerpt[: limit - 1] + "…"
    return excerpt
