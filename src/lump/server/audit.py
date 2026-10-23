"""Shared audit log and in-memory metrics for every enforcement surface.

The audit log is append-only JSON Lines: one event per inspection, carrying the
verdict, the matched rule ids and framework references — but never the raw
sensitive content (evidence is already masked/snippeted by the detectors). A
small ring buffer of recent events and running counters back the control-plane
dashboard without any external datastore.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

from ..engine.types import Verdict


@dataclass
class Event:
    ts: float
    source: str
    action: str
    risk: int
    direction: str
    rule_ids: list[str]
    detectors: list[str]
    destination: str | None = None
    service: str | None = None
    user: str | None = None
    app: str | None = None
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": round(self.ts, 3),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts)),
            "source": self.source,
            "action": self.action,
            "risk": self.risk,
            "severity": self.severity,
            "direction": self.direction,
            "rule_ids": self.rule_ids,
            "detectors": self.detectors,
            "destination": self.destination,
            "service": self.service,
            "user": self.user,
            "app": self.app,
        }


@dataclass
class Metrics:
    started: float = field(default_factory=time.time)
    total: int = 0
    by_action: Counter = field(default_factory=Counter)
    by_source: Counter = field(default_factory=Counter)
    by_rule: Counter = field(default_factory=Counter)
    by_service: Counter = field(default_factory=Counter)
    by_severity: Counter = field(default_factory=Counter)
    blocked: int = 0
    redacted: int = 0
    latency_sum: float = 0.0

    def snapshot(self) -> dict[str, Any]:
        return {
            "uptime_s": round(time.time() - self.started, 1),
            "total": self.total,
            "blocked": self.blocked,
            "redacted": self.redacted,
            "avg_latency_ms": round(self.latency_sum / self.total, 3) if self.total else 0.0,
            "by_action": dict(self.by_action),
            "by_source": dict(self.by_source),
            "by_severity": dict(self.by_severity),
            "top_rules": self.by_rule.most_common(20),
            "top_services": self.by_service.most_common(20),
        }


class Auditor:
    def __init__(self, log_path: str | None = None, ring_size: int = 500):
        self.metrics = Metrics()
        self.recent: deque[Event] = deque(maxlen=ring_size)
        self._lock = threading.Lock()
        self._fh = None
        if log_path:
            os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
            self._fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115

    def record(self, verdict: Verdict, source: str, *, destination: str | None = None,
               service: str | None = None, user: str | None = None, app: str | None = None,
               direction: str | None = None) -> Event:
        event = Event(
            ts=time.time(),
            source=source,
            action=verdict.action.value,
            risk=verdict.risk,
            direction=direction or (verdict.findings[0].metadata.get("view", "") if verdict.findings else ""),
            rule_ids=[f.rule_id for f in verdict.findings][:20],
            detectors=sorted({f.detector for f in verdict.findings}),
            destination=destination,
            service=service,
            user=user,
            app=app,
            severity=verdict.max_severity.label,
        )
        with self._lock:
            self.metrics.total += 1
            self.metrics.by_action[event.action] += 1
            self.metrics.by_source[source] += 1
            self.metrics.by_severity[event.severity] += 1
            self.metrics.latency_sum += verdict.latency_ms
            if verdict.action.value == "block":
                self.metrics.blocked += 1
            elif verdict.action.value == "redact":
                self.metrics.redacted += 1
            for rid in event.rule_ids:
                self.metrics.by_rule[rid] += 1
            if service:
                self.metrics.by_service[service] += 1
            self.recent.append(event)
            if self._fh:
                self._fh.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
                self._fh.flush()
        return event

    def record_event(self, event: Event) -> None:
        with self._lock:
            self.recent.append(event)
            if self._fh:
                self._fh.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
                self._fh.flush()

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [e.to_dict() for e in list(self.recent)[-limit:]][::-1]

    def prometheus(self) -> str:
        m = self.metrics
        lines = [
            "# HELP lump_inspections_total Total inspections performed.",
            "# TYPE lump_inspections_total counter",
            f"lump_inspections_total {m.total}",
            "# HELP lump_blocked_total Inspections that resulted in a block.",
            "# TYPE lump_blocked_total counter",
            f"lump_blocked_total {m.blocked}",
            "# HELP lump_redacted_total Inspections that resulted in redaction.",
            "# TYPE lump_redacted_total counter",
            f"lump_redacted_total {m.redacted}",
            "# HELP lump_avg_latency_ms Average inspection latency in milliseconds.",
            "# TYPE lump_avg_latency_ms gauge",
            f"lump_avg_latency_ms {round(m.latency_sum / m.total, 4) if m.total else 0.0}",
        ]
        for action, count in m.by_action.items():
            lines.append(f'lump_action_total{{action="{action}"}} {count}')
        for source, count in m.by_source.items():
            lines.append(f'lump_source_total{{source="{source}"}} {count}')
        for service, count in m.by_service.most_common(30):
            lines.append(f'lump_service_total{{service="{service}"}} {count}')
        return "\n".join(lines) + "\n"

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
