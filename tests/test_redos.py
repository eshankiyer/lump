"""Every rule must stay fast on adversarial input.

A security filter that one crafted request can stall is itself a DoS vector,
so each regex is run against inputs designed to trigger catastrophic or
quadratic backtracking. This is a regression guard for new rules.
"""

import re
import time

import pytest

from lump.engine import normalize as norm_mod
from lump.engine.code import _COMPILED as CODE_RULES
from lump.engine.injection import compile_pattern
from lump.engine.output import _COMPILED as OUTPUT_RULES
from lump.engine.rules import DLP_RULES, INJECTION_RULES

N = 40_000
ADVERSARIAL = {
    "angle": "<" * N,
    "script": "<script" * (N // 7),
    "img": "<img " * (N // 5),
    "bracket": "![" * (N // 2),
    "paren-url": "](https://a.b/?" * (N // 15),
    "digits": "1 " * (N // 2),
    "dash-digits": "1-" * (N // 2),
    "words": "ignore previous " * (N // 16),
    "b64": "QUFB" * (N // 4),
    "hex": "ab" * (N // 2),
    "spaced": "a " * (N // 2),
    "at": "a@" * (N // 2),
    "colon": "a:" * (N // 2),
    "slash": "/*" * (N // 2),
    "quotes": "'\"" * (N // 2),
    "pipes": "curl a|" * (N // 7),
    "equals": "password=" * (N // 9),
    "newlines": "a\n" * (N // 2),
}


def _all_regexes():
    for r in INJECTION_RULES:
        yield r.id, compile_pattern(r.pattern, r.flags)
    for r in DLP_RULES:
        yield r.id, re.compile(r.pattern, re.IGNORECASE if "i" in r.flags else 0)
    for r, rx in CODE_RULES + OUTPUT_RULES:
        yield r.id, rx
    for name in ("_B64_RE", "_HEX_RE", "_PCT_RE", "_SPACED_RE", "_LEET_WORD_RE", "_TAG_RE", "_VS_RE"):
        yield name, getattr(norm_mod, name)


@pytest.mark.parametrize("rule_id,regex", list(_all_regexes()))
def test_rule_is_linear(rule_id, regex):
    for name, text in ADVERSARIAL.items():
        start = time.perf_counter()
        for _ in regex.finditer(text):
            pass
        elapsed = time.perf_counter() - start
        assert elapsed < 0.25, f"{rule_id} took {elapsed:.2f}s on '{name}' ({len(text)} chars)"


def test_engine_end_to_end_budget():
    from lump import Engine
    from lump.engine.types import Context

    engine = Engine()
    for name, text in ADVERSARIAL.items():
        for direction in ("input", "output", "document", "tool_call"):
            start = time.perf_counter()
            engine.inspect(text, Context(direction=direction))
            elapsed = time.perf_counter() - start
            assert elapsed < 1.5, f"engine took {elapsed:.2f}s on '{name}' ({direction})"
