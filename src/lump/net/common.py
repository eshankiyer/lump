"""Shared egress-classification logic for the DNS filter and the proxy."""

from __future__ import annotations

from dataclasses import dataclass

from ..engine.catalog import Catalog
from ..server.audit import Event


@dataclass
class EgressDecision:
    host: str
    block: bool
    status: str  # sanctioned | unsanctioned | blocked | unknown | not_ai
    service_id: str | None = None
    service_name: str | None = None
    reason: str = ""


class EgressDecider:
    """Classifies an outbound hostname and records a shadow-AI audit event."""

    def __init__(self, catalog: Catalog, auditor):
        self.catalog = catalog
        self.auditor = auditor

    def decide_host(self, host: str, source: str, client: str | None = None) -> EgressDecision:
        match = self.catalog.classify(host)
        if match is None:
            return EgressDecision(host=host, block=False, status="not_ai")

        svc = match.service
        block = match.status == "blocked"
        action = "block" if block else ("allow" if match.status == "sanctioned" else "warn")
        reason = {
            "blocked": f"{svc.name} is blocked by policy"
            + (f" (data boundary '{svc.data_boundary}')" if svc.data_boundary in self.catalog.blocked_boundaries else ""),
            "unsanctioned": f"{svc.name} is not sanctioned (shadow AI)",
            "unknown": f"{svc.name} usage observed",
            "sanctioned": f"{svc.name} (sanctioned)",
        }.get(match.status, "")

        if self.auditor is not None:
            self.auditor.record_event(
                Event(
                    ts=__import__("time").time(),
                    source=source,
                    action=action,
                    risk=90 if block else (40 if match.status in ("unsanctioned", "unknown") else 0),
                    direction="egress",
                    rule_ids=[f"SHADOW-AI:{match.status.upper()}"],
                    detectors=["shadow_ai"],
                    destination=host,
                    service=svc.name,
                    app=client,
                    severity="high" if block else ("medium" if match.status != "sanctioned" else "info"),
                )
            )
        return EgressDecision(
            host=host, block=block, status=match.status,
            service_id=svc.id, service_name=svc.name, reason=reason,
        )
