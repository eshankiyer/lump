"""Policy model: how findings become an action.

A policy maps the set of findings produced for one inspection to a single
:class:`Action` and a 0-100 risk score, taking the detector mix, severities
and the direction of the content into account. Policies are data (loadable
from TOML/JSON) so operators can tune thresholds without touching code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..engine.types import Action, Context, Direction, Finding, Severity, Verdict

# Risk contribution per severity level, scaled by a finding's confidence.
_SEVERITY_RISK = {
    Severity.INFO: 2,
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 65,
    Severity.CRITICAL: 95,
}


@dataclass
class Rule:
    """One decision rule. Every rule is checked against every finding; the
    strictest matching action wins, so rule order does not matter."""

    action: Action
    min_severity: Severity = Severity.INFO
    detectors: tuple[str, ...] = ()  # empty = any detector
    categories: tuple[str, ...] = ()  # category prefixes; empty = any
    directions: tuple[Direction, ...] = ()  # empty = any
    min_confidence: float = 0.0
    min_risk: int = 0
    untrusted: bool | None = None  # None = either; True/False = only when ctx.untrusted is that
    # Detectors of which at least one must also have a MEDIUM+ finding in the
    # same inspection ("block when the rules agree").
    requires: tuple[str, ...] = ()

    def matches(self, finding: Finding, ctx: Context, risk: int, findings: list[Finding] | None = None) -> bool:
        if finding.severity < self.min_severity:
            return False
        if self.untrusted is not None and ctx.untrusted != self.untrusted:
            return False
        if self.requires and not any(
            f.detector in self.requires and f.severity >= Severity.MEDIUM for f in (findings or ())
        ):
            return False
        if self.detectors and finding.detector not in self.detectors:
            return False
        if self.categories and not any(finding.category.startswith(c) for c in self.categories):
            return False
        if self.directions and ctx.direction not in self.directions:
            return False
        if finding.confidence < self.min_confidence:
            return False
        if risk < self.min_risk:
            return False
        return True


@dataclass
class Policy:
    name: str = "default"
    mode: str = "enforce"  # enforce | monitor | off
    rules: list[Rule] = field(default_factory=list)
    block_risk: int = 80  # risk at/above which the default action is BLOCK
    warn_risk: int = 40
    redact_secrets: bool = True  # auto-redact DLP findings flagged redactable
    default_action: Action = Action.ALLOW
    # Detectors whose findings do not count towards the risk-threshold
    # fallback. The learned classifier's decisions are governed only by its
    # explicit rules, so an unrelated DLP hit (or a second ML backend) cannot
    # turn an ML warning into a block. Its findings still count in ``risk``.
    fallback_excludes: tuple[str, ...] = ("ml",)

    def score(self, findings: list[Finding]) -> int:
        """Combine findings into a 0-100 risk score (saturating noisy-OR)."""

        remaining = 1.0
        for f in findings:
            contribution = (_SEVERITY_RISK[f.severity] / 100.0) * max(0.05, min(f.confidence, 1.0))
            remaining *= 1.0 - contribution
        base = (1.0 - remaining) * 100.0
        # A single critical finding should dominate.
        top = max((_SEVERITY_RISK[f.severity] for f in findings), default=0)
        return int(round(max(base, top * 0.95)))

    def decide(self, findings: list[Finding], ctx: Context) -> Action:
        risk = self.score(findings)
        best = self.default_action
        # Explicit rules first.
        for rule in self.rules:
            for f in findings:
                if rule.matches(f, ctx, risk, findings) and rule.action.rank > best.rank:
                    best = rule.action
        # Threshold fallback.
        fallback = self.score([f for f in findings if f.detector not in self.fallback_excludes])
        if fallback >= self.block_risk and best.rank < Action.BLOCK.rank:
            best = Action.BLOCK
        elif fallback >= self.warn_risk and best.rank < Action.WARN.rank:
            best = Action.WARN
        return best

    def evaluate(self, findings: list[Finding], ctx: Context) -> Verdict:
        risk = self.score(findings)
        action = self.decide(findings, ctx)
        reasons = _reasons(findings)
        if self.mode == "off":
            # Findings are still reported; nothing is enforced or rewritten.
            if action is not Action.ALLOW:
                reasons.insert(0, f"policy off: would {action.value}")
            action = Action.ALLOW
        elif self.mode == "monitor" and action in (Action.BLOCK, Action.REDACT):
            # Monitor mode never interferes (no block, no rewrite) but records intent.
            reasons.insert(0, f"monitor mode: would {action.value}")
            action = Action.WARN
        return Verdict(action=action, risk=risk, findings=findings, reasons=reasons, policy=self.name, mode=self.mode)

    @property
    def enforcing(self) -> bool:
        return self.mode not in ("monitor", "off")


def _reasons(findings: list[Finding]) -> list[str]:
    by_sev = sorted(findings, key=lambda f: (f.severity, f.confidence), reverse=True)
    out = []
    for f in by_sev[:5]:
        out.append(f"[{f.severity.label}] {f.title} ({f.rule_id})")
    if len(findings) > 5:
        out.append(f"… and {len(findings) - 5} more")
    return out


def default_policy() -> Policy:
    """A sensible enforcing baseline used when no policy file is supplied."""

    return Policy(
        name="default",
        mode="enforce",
        redact_secrets=True,
        rules=[
            # Any critical finding blocks.
            Rule(Action.BLOCK, min_severity=Severity.CRITICAL),
            # High-confidence injection / jailbreak blocks.
            Rule(Action.BLOCK, detectors=("injection",), min_severity=Severity.HIGH, min_confidence=0.7),
            # Indirect injection coming from untrusted content blocks at a lower bar.
            Rule(
                Action.BLOCK,
                detectors=("injection",),
                categories=("prompt_injection.indirect", "obfuscation", "prompt_injection.exfiltration"),
                directions=(Direction.TOOL_RESULT, Direction.DOCUMENT, Direction.TOOL_DEFINITION),
                min_severity=Severity.MEDIUM,
            ),
            # Any detected injection/jailbreak pattern warns at minimum, even
            # from the user directly — it is a signal worth surfacing.
            Rule(Action.WARN, detectors=("injection",), min_severity=Severity.MEDIUM),
            # Learned classifier. Severity encodes the model's own operating
            # points (MEDIUM ~2% FPR, HIGH ~0.5%, CRITICAL ~0.1%; CRITICAL is
            # covered by the first rule). A HIGH score blocks on its own for
            # untrusted third-party content (documents, tool results, tool
            # definitions, or input explicitly marked untrusted); on trusted
            # input and on model output it warns, and blocks only when an
            # injection rule also fired. ML findings are left out of the
            # risk-threshold fallback (see Policy.fallback_excludes).
            Rule(Action.WARN, detectors=("ml",), min_severity=Severity.MEDIUM),
            Rule(
                Action.BLOCK,
                detectors=("ml",),
                min_severity=Severity.HIGH,
                directions=(Direction.INPUT, Direction.TOOL_RESULT, Direction.DOCUMENT, Direction.TOOL_DEFINITION),
                untrusted=True,
            ),
            Rule(Action.BLOCK, detectors=("ml",), min_severity=Severity.HIGH, requires=("injection",)),
            # Secrets and high-value PII in outbound content are redacted.
            Rule(Action.REDACT, detectors=("dlp",), min_severity=Severity.HIGH),
            Rule(Action.REDACT, detectors=("dlp",), categories=("pii.payment_card", "pii.us_ssn", "pii.iban")),
            # Denied / unapproved agent actions block.
            Rule(Action.BLOCK, detectors=("agentic",), categories=("agentic.policy", "agentic.tool_poisoning")),
            Rule(Action.WARN, detectors=("agentic",), min_severity=Severity.HIGH),
            # Dangerous code inside an agent *tool call* blocks (a model merely
            # printing the same command for a human only warns, below).
            Rule(Action.BLOCK, detectors=("code",), directions=(Direction.TOOL_CALL,), min_severity=Severity.HIGH),
            # Content too large to inspect fully is never silently allowed.
            Rule(Action.WARN, detectors=("engine",), categories=("engine.truncated",)),
            # Dangerous code / output is warned on (blocked only when critical, above).
            Rule(Action.WARN, detectors=("code", "output"), min_severity=Severity.MEDIUM),
            Rule(Action.WARN, detectors=("dlp",), min_severity=Severity.MEDIUM),
        ],
    )
