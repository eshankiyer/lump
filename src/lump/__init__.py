"""Lump — open-source runtime AI threat prevention for every layer.

Browser, endpoint, network, API gateway and AI agents share one detection
engine, one policy model and one rule set.
"""

from .engine.engine import Engine, EngineConfig
from .engine.types import Action, Context, Direction, Finding, Severity, Verdict
from .policy.model import Policy, Rule, default_policy

__version__ = "0.1.0"

__all__ = [
    "Engine",
    "EngineConfig",
    "Action",
    "Context",
    "Direction",
    "Finding",
    "Severity",
    "Verdict",
    "Policy",
    "Rule",
    "default_policy",
    "__version__",
]
