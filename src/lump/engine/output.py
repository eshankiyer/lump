"""Model-output handling checks (OWASP LLM05: Improper Output Handling).

When a model's response is about to be rendered, stored or passed downstream,
these checks flag constructs that are dangerous in the destination context:
markdown image/link beacons that silently exfiltrate data, HTML/JS injection,
and `javascript:`/`data:` URIs. The DLP and code detectors handle secrets and
dangerous commands in output separately; this module focuses on rendering and
downstream-injection risks unique to output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .types import Finding, Severity, snippet


@dataclass(frozen=True)
class OutputRule:
    id: str
    title: str
    category: str
    pattern: str
    severity: Severity
    owasp: tuple[str, ...] = ("LLM05",)


S = Severity
OUTPUT_RULES: tuple[OutputRule, ...] = (
    OutputRule("OUT-001", "Markdown image auto-loads a parameterised URL (data beacon)", "output.image_beacon",
               r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,300}[?&#][^)\s]{0,200}\)", S.HIGH,
               ("LLM05", "LLM02", "LLM01")),
    OutputRule("OUT-002", "Markdown link to a script or data scheme", "output.dangerous_link",
               r"\]\(\s*(?:javascript|data|vbscript|file):", S.HIGH),
    OutputRule("OUT-003", "Inline <script> in output", "output.html_injection",
               r"<script\b[^<>]{0,500}?>", S.HIGH),
    OutputRule("OUT-004", "Event-handler or javascript: in HTML output", "output.html_injection",
               r"\son(?:error|load|click|mouseover|focus|submit)\s*=|javascript:\s*\w", S.MEDIUM),
    OutputRule("OUT-005", "<iframe>/<object>/<embed> in output", "output.html_injection",
               r"<(?:iframe|object|embed|form)\b", S.MEDIUM),
    OutputRule("OUT-006", "Hidden HTML element (possible second-order injection)", "output.hidden_html",
               r"<[^<>]{0,500}?\sstyle\s*=\s*[\"'][^\"'<>]{0,500}?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*transparent|opacity\s*:\s*0)", S.MEDIUM),
    OutputRule("OUT-007", "SQL meta-characters in a value field", "output.sql_risk",
               r"(?:';\s*(?:drop|delete|update|insert|select)\b|--\s*$|/\*[^\n]{0,500}?\*/|\bunion\s+select\b|\bor\s+1\s*=\s*1\b)", S.LOW),
    OutputRule("OUT-008", "Autolinked parameterised image via HTML <img>", "output.image_beacon",
               r"<img\b[^<>]{0,500}?\ssrc\s*=\s*[\"']https?://[^\"']{1,300}[?&#][^\"']{0,200}[\"']", S.HIGH,
               ("LLM05", "LLM02")),
)

_COMPILED = [(rule, re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)) for rule in OUTPUT_RULES]


class OutputDetector:
    name = "output"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule, regex in _COMPILED:
            match = regex.search(text)
            if match:
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=0.7,
                        category=rule.category,
                        evidence=snippet(text, *match.span()),
                        span=match.span(),
                        owasp=rule.owasp,
                        metadata={},
                    )
                )
        return findings
