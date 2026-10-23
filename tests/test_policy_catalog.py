from lump.engine.catalog import Catalog
from lump.engine.types import Action, Context, Direction, Finding, Severity
from lump.policy.model import Policy, Rule, default_policy


def mkfinding(detector="injection", sev=Severity.HIGH, conf=0.8, cat="prompt_injection.override"):
    return Finding(detector=detector, rule_id="X", title="t", severity=sev, confidence=conf, category=cat)


def test_score_monotonic():
    p = default_policy()
    low = p.score([mkfinding(sev=Severity.LOW)])
    high = p.score([mkfinding(sev=Severity.HIGH)])
    crit = p.score([mkfinding(sev=Severity.CRITICAL)])
    assert low < high < crit
    assert crit >= 90


def test_default_policy_blocks_high_injection():
    p = default_policy()
    v = p.evaluate([mkfinding(sev=Severity.HIGH, conf=0.8)], Context(direction=Direction.INPUT))
    assert v.action is Action.BLOCK


def test_monitor_mode_downgrades_block():
    p = default_policy()
    p.mode = "monitor"
    v = p.evaluate([mkfinding(sev=Severity.CRITICAL)], Context())
    assert v.action is Action.WARN
    assert any("monitor" in r for r in v.reasons)


def test_rule_direction_filter():
    p = Policy(name="t", rules=[Rule(Action.BLOCK, detectors=("code",), directions=(Direction.TOOL_CALL,), min_severity=Severity.HIGH)], warn_risk=101, block_risk=101)
    code = mkfinding(detector="code", cat="execution")
    assert p.decide([code], Context(direction=Direction.TOOL_CALL)) is Action.BLOCK
    assert p.decide([code], Context(direction=Direction.OUTPUT)) is Action.ALLOW


def test_catalog_lookup_and_status():
    cat = Catalog.load_default()
    assert cat.lookup("api.openai.com").id == "openai"
    assert cat.lookup("foo.bar.api.anthropic.com").id == "anthropic"  # parent match
    assert cat.lookup("example.com") is None


def test_catalog_boundary_and_sanction():
    cat = Catalog.load_default()
    cat.sanctioned = {"openai"}
    cat.blocked_boundaries = {"cn"}
    cat.allowlist_mode = True
    assert cat.classify("api.openai.com").status == "sanctioned"
    assert cat.classify("chat.deepseek.com").status == "blocked"
    assert cat.classify("claude.ai").status == "unsanctioned"
