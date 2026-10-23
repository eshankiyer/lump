"""Agentic risk detection: tool calls, tool results and tool definitions.

Covers the OWASP Agentic Top-10 surface that only appears once an LLM can act:
tool poisoning in MCP/function definitions (ASI04), goal hijack arriving
through tool results (ASI01/ASI06), and excessive-agency tool calls (ASI02).

It inspects the *structure* of an agent step, not just free text:

* **Tool definition** — a tool's name/description/schema. Hidden instructions
  here are a classic MCP "tool poisoning" / "rug pull" attack.
* **Tool call** — the tool the agent chose plus its arguments. Scored against a
  per-tool sensitivity model and optional allow/deny policy.
* **Tool result** — data returned to the agent, treated as untrusted and run
  through the injection detector by the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .types import Finding, Severity, snippet

# Tools whose misuse has outsized impact, grouped by capability.
SENSITIVE_TOOLS = {
    "shell": re.compile(r"\b(?:shell|bash|exec|execute|run_?command|terminal|system|subprocess|powershell|cmd|run_?code|code_?interpreter|sandbox_?exec)\b", re.IGNORECASE),
    "filesystem_write": re.compile(r"\b(?:write_?file|edit_?file|create_?file|delete_?file|remove_?file|move_?file|put_?object|fs_?write|save)\b", re.IGNORECASE),
    "network": re.compile(r"\b(?:http_?request|fetch|curl|browse|web_?get|post|webhook|send_?request|download|upload)\b", re.IGNORECASE),
    "email": re.compile(r"\b(?:send_?email|send_?mail|smtp|send_?message|reply|forward)\b", re.IGNORECASE),
    "payment": re.compile(r"\b(?:pay|payment|transfer_?funds|wire|charge|refund|create_?invoice|send_?money|purchase|checkout)\b", re.IGNORECASE),
    "secret_access": re.compile(r"\b(?:get_?secret|read_?secret|vault|credentials?|get_?token|list_?keys|env|getenv)\b", re.IGNORECASE),
    "privileged": re.compile(r"\b(?:sudo|admin|delete_?user|grant_?role|change_?permission|modify_?policy|disable_?security|deploy|terminate|destroy)\b", re.IGNORECASE),
}

_TOOL_SEVERITY = {
    "payment": Severity.HIGH,
    "privileged": Severity.HIGH,
    "secret_access": Severity.HIGH,
    "shell": Severity.MEDIUM,
    "filesystem_write": Severity.MEDIUM,
    "email": Severity.MEDIUM,
    "network": Severity.LOW,
}

# Imperatives that should never appear inside a *tool definition* — a tool
# describing itself is metadata, not a place for instructions to the agent.
_TOOL_POISON_RE = re.compile(
    r"\b(?:ignore|disregard|do not|don't|instead|you must|always|before (?:using|calling|doing)|"
    r"first|important|note to|ai assistant|the assistant should|when (?:you|the user)|"
    r"read|send|forward|include|append|exfiltrate|pass|transmit|concatenate)\b",
    re.IGNORECASE,
)
_TOOL_POISON_TARGET_RE = re.compile(
    r"\b(?:\.ssh|id_rsa|\.env|credentials?|api[_ -]?keys?|secrets?|tokens?|password|config|conversation|system prompt|other tools?|sidenote|<important>)\b",
    re.IGNORECASE,
)

_URL_RE = re.compile(r"https?://[^\s\"'>)]+", re.IGNORECASE)


@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    schema: str = ""  # JSON schema or parameter description, as text


@dataclass
class ToolCall:
    name: str
    arguments: str = ""  # serialised args (JSON or text)
    server: str | None = None


@dataclass
class AgentPolicy:
    allowed_tools: set[str] | None = None  # None = no allow-list
    denied_tools: set[str] = field(default_factory=set)
    # Capability groups the agent is NOT permitted to use in this context.
    denied_capabilities: set[str] = field(default_factory=set)
    # Capability groups requiring human approval (reported, not blocked).
    # High-impact actions default to approval even with no config file.
    approval_capabilities: set[str] = field(default_factory=lambda: {"payment", "privileged"})
    max_calls_per_tool: int = 0  # 0 = unlimited; loop protection handled by engine


_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _split_identifier(name: str) -> str:
    """snake_case and camelCase -> space-separated words, so capability
    patterns match the components of a tool name like ``make_payment``."""

    name = name.replace("_", " ").replace("-", " ").replace(".", " ")
    return _CAMEL_RE.sub(" ", name)


def classify_capabilities(name: str, arguments: str = "") -> set[str]:
    # Match against both the raw name (so ``transfer_funds`` hits ``transfer_?funds``)
    # and the split form (so ``make_payment`` hits ``payment``).
    haystack = f"{name} {_split_identifier(name)} {arguments}"
    return {cap for cap, regex in SENSITIVE_TOOLS.items() if regex.search(haystack)}


class AgenticDetector:
    name = "agentic"

    def inspect_tool_definition(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        blob = f"{tool.description}\n{tool.schema}"
        if _TOOL_POISON_RE.search(blob) and _TOOL_POISON_TARGET_RE.search(blob):
            match = _TOOL_POISON_TARGET_RE.search(blob)
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="AG-POISON-001",
                    title=f"Tool definition '{tool.name}' contains embedded instructions (tool poisoning)",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    category="agentic.tool_poisoning",
                    evidence=snippet(blob, max(match.start() - 40, 0), match.end() + 40),
                    atlas=("AML.T0051.001", "AML.T0053"),
                    owasp=("ASI04", "LLM03"),
                    metadata={"tool": tool.name},
                )
            )
        # Hidden-instruction markers frequently used in MCP rug-pulls.
        if re.search(r"<(?:important|secret|system|instructions?|hidden)>|\[\[system\]\]|sidenote\s*:", blob, re.IGNORECASE):
            findings.append(
                Finding(
                    detector=self.name, rule_id="AG-POISON-002",
                    title=f"Tool definition '{tool.name}' uses hidden-instruction markup",
                    severity=Severity.HIGH, confidence=0.7, category="agentic.tool_poisoning",
                    evidence=snippet(blob, 0, 160), atlas=("AML.T0051.001",), owasp=("ASI04",),
                    metadata={"tool": tool.name},
                )
            )
        for url in _URL_RE.findall(blob):
            findings.append(
                Finding(
                    detector=self.name, rule_id="AG-POISON-003",
                    title=f"Tool definition '{tool.name}' references an external URL",
                    severity=Severity.LOW, confidence=0.5, category="agentic.tool_definition_url",
                    evidence=url[:120], owasp=("ASI04",), metadata={"tool": tool.name, "url": url[:200]},
                )
            )
        return findings

    def inspect_tool_call(self, call: ToolCall, policy: AgentPolicy | None = None) -> list[Finding]:
        findings: list[Finding] = []
        caps = classify_capabilities(call.name, call.arguments)
        policy = policy or AgentPolicy()

        if policy.allowed_tools is not None and call.name not in policy.allowed_tools:
            findings.append(self._policy_finding("AG-CALL-001", f"Tool '{call.name}' is not in the allow-list", call, Severity.HIGH))
        if call.name in policy.denied_tools:
            findings.append(self._policy_finding("AG-CALL-002", f"Tool '{call.name}' is explicitly denied", call, Severity.HIGH))

        for cap in sorted(caps):
            if cap in policy.denied_capabilities:
                findings.append(
                    Finding(
                        detector=self.name, rule_id="AG-CALL-003",
                        title=f"Denied capability '{cap}' via tool '{call.name}'",
                        severity=Severity.HIGH, confidence=0.85, category=f"agentic.capability.{cap}",
                        evidence=snippet(call.arguments, 0, 120), owasp=("ASI02", "ASI03", "LLM06"),
                        metadata={"tool": call.name, "capability": cap, "decision": "block"},
                    )
                )
            elif cap in policy.approval_capabilities:
                findings.append(
                    Finding(
                        detector=self.name, rule_id="AG-CALL-004",
                        title=f"Capability '{cap}' requires human approval (tool '{call.name}')",
                        severity=_TOOL_SEVERITY.get(cap, Severity.MEDIUM), confidence=0.8,
                        category=f"agentic.capability.{cap}", evidence=snippet(call.arguments, 0, 120),
                        owasp=("ASI02", "ASI09", "LLM06"), metadata={"tool": call.name, "capability": cap, "decision": "approve"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        detector=self.name, rule_id="AG-CALL-005",
                        title=f"Sensitive capability '{cap}' exercised (tool '{call.name}')",
                        severity=Severity.INFO, confidence=0.6, category=f"agentic.capability.{cap}",
                        evidence=snippet(call.arguments, 0, 120), owasp=("ASI02",),
                        metadata={"tool": call.name, "capability": cap, "decision": "observe"},
                    )
                )
        return findings

    def _policy_finding(self, rule_id: str, title: str, call: ToolCall, severity: Severity) -> Finding:
        return Finding(
            detector=self.name, rule_id=rule_id, title=title, severity=severity, confidence=0.95,
            category="agentic.policy", evidence=snippet(call.arguments, 0, 120),
            owasp=("ASI02", "ASI03"), metadata={"tool": call.name, "decision": "block"},
        )
