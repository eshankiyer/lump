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


def _f(detector, severity, category="x", confidence=0.95, rule_id="R"):
    from lump.engine.types import Finding

    return Finding(detector=detector, rule_id=rule_id, title=rule_id, severity=severity, confidence=confidence, category=category)


def test_ml_high_on_direct_input_blocks_only_when_injection_rules_agree():
    from lump.engine.types import Action, Context, Direction, Severity
    from lump.policy.model import default_policy

    p, ctx = default_policy(), Context(direction=Direction.INPUT)
    ml = _f("ml", Severity.HIGH, "prompt_injection.ml", 0.97, "ML-PI")
    assert p.evaluate([ml], ctx).action is Action.WARN
    # An unrelated secret is redacted, not turned into a block by the ML score.
    assert p.evaluate([ml, _f("dlp", Severity.HIGH, "secret.github_token")], ctx).action is Action.REDACT
    # A second ML backend is not "the rules agreeing".
    assert p.evaluate([ml, _f("ml", Severity.HIGH, "prompt_injection.ml", 0.99, "ML-TX")], ctx).action is Action.WARN
    assert p.evaluate([ml, _f("injection", Severity.MEDIUM, "prompt_injection.direct", 0.5)], ctx).action is Action.BLOCK


def test_ml_high_blocks_on_untrusted_content_by_trust_not_only_direction():
    from lump.engine.types import Action, Context, Direction, Severity
    from lump.policy.model import default_policy

    p = default_policy()
    ml = [_f("ml", Severity.HIGH, "prompt_injection.ml", 0.97, "ML-PI")]
    assert p.evaluate(ml, Context(direction=Direction.DOCUMENT)).action is Action.BLOCK
    assert p.evaluate(ml, Context(direction=Direction.INPUT, trusted=False)).action is Action.BLOCK  # lump scan --untrusted
    assert p.evaluate(ml, Context(direction=Direction.DOCUMENT, trusted=True)).action is Action.WARN
    assert p.evaluate(ml, Context(direction=Direction.OUTPUT)).action is Action.WARN


def test_mode_off_and_monitor_never_interfere():
    from lump import Engine, EngineConfig
    from lump.engine.types import Action
    from lump.policy.model import default_policy

    secret = "my token is ghp_" + "a" * 36
    for mode in ("off", "monitor"):
        p = default_policy()
        p.mode = mode
        v = Engine(policy=p, config=EngineConfig(load_plugins=False)).inspect(secret)
        assert v.action in (Action.ALLOW, Action.WARN) and v.redacted_text is None, mode
        assert v.findings and any(mode in r for r in v.reasons)
