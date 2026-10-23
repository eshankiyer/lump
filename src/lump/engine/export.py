"""Export the rule set to JSON so other runtimes (the browser extension, other
languages) can execute the exact same detection logic.

The injection patterns are authored in the regex subset common to Python ``re``
and ECMAScript, so they run unchanged in the browser. This module also emits the
normalisation constants (invisible/bidi characters, confusable map) the JS
normaliser needs, and the AI-service catalog for shadow-AI detection in-page.
"""

from __future__ import annotations

import json
from typing import Any

from . import normalize
from .catalog import Catalog
from .injection import load_signatures, shingles
from .rules import DLP_RULES, INJECTION_RULES


def export_rules(include_catalog: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 1,
        "injection": [r.to_json() for r in INJECTION_RULES],
        "dlp": [r.to_json() for r in DLP_RULES],
        "signatures": [
            {"id": s.id, "family": s.family, "grams": [" ".join(g) for g in sorted(s.grams)]}
            for s in load_signatures()
        ],
        "normalize": {
            "zero_width": list(normalize._ZERO_WIDTH),
            "bidi": list(normalize._BIDI),
            # _CONFUSABLES is a str.maketrans table keyed by ordinal; emit char->char.
            "confusables": {chr(k): v for k, v in normalize._CONFUSABLES.items() if isinstance(v, str)},
        },
    }
    if include_catalog:
        cat = Catalog.load_default()
        data["catalog"] = [
            {"id": s.id, "name": s.name, "vendor": s.vendor, "category": s.category,
             "domains": list(s.domains), "data_boundary": s.data_boundary}
            for s in cat.services
        ]
    return data


def export_json(indent: int | None = 2, include_catalog: bool = True) -> str:
    return json.dumps(export_rules(include_catalog), indent=indent, ensure_ascii=False)


# Re-export for the shingling helper used by tests.
__all__ = ["export_rules", "export_json", "shingles"]
