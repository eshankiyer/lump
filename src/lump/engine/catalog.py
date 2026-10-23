"""AI-service catalog for shadow-AI discovery and egress classification.

Resolves a hostname (or an SNI / Host header) to a known AI service, tags it
with vendor, category and data-residency boundary, and applies the operator's
sanctioned / unsanctioned / blocked policy. Used by the DNS filter, the egress
proxy and the host sensor to answer: *is this connection talking to an AI
service, which one, and are we allowed to?*
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources


@dataclass(frozen=True)
class Service:
    id: str
    name: str
    vendor: str
    category: str
    domains: tuple[str, ...]
    data_boundary: str = "unknown"


@dataclass
class ServiceMatch:
    service: Service
    matched_domain: str
    status: str  # sanctioned | unsanctioned | blocked | unknown


@dataclass
class Catalog:
    services: list[Service] = field(default_factory=list)
    # Operator policy by service id.
    sanctioned: set[str] = field(default_factory=set)
    blocked: set[str] = field(default_factory=set)
    # Governance: boundaries that are disallowed (e.g. {"cn"} to block CN hosts).
    blocked_boundaries: set[str] = field(default_factory=set)
    # When True, any catalog service not explicitly sanctioned is "unsanctioned".
    allowlist_mode: bool = False
    _by_domain: dict[str, Service] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._index()

    def _index(self) -> None:
        self._by_domain = {}
        for svc in self.services:
            for domain in svc.domains:
                self._by_domain[domain.lower().lstrip(".")] = svc

    def add(self, svc: Service) -> None:
        self.services.append(svc)
        for domain in svc.domains:
            self._by_domain[domain.lower().lstrip(".")] = svc

    def lookup(self, host: str | None) -> Service | None:
        if not host:
            return None
        host = host.strip().lower().rstrip(".")
        if ":" in host and not host.count(":") > 1:  # strip :port (not IPv6)
            host = host.split(":", 1)[0]
        if host in self._by_domain:
            return self._by_domain[host]
        # Match parent domains: api.foo.openai.com -> openai.com
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in self._by_domain:
                return self._by_domain[parent]
        return None

    def classify(self, host: str | None) -> ServiceMatch | None:
        svc = self.lookup(host)
        if svc is None:
            return None
        status = self._status(svc)
        return ServiceMatch(service=svc, matched_domain=(host or "").lower(), status=status)

    def _status(self, svc: Service) -> str:
        if svc.id in self.blocked or svc.data_boundary in self.blocked_boundaries:
            return "blocked"
        if svc.id in self.sanctioned:
            return "sanctioned"
        if self.allowlist_mode:
            return "unsanctioned"
        return "unknown"

    def is_ai_host(self, host: str | None) -> bool:
        return self.lookup(host) is not None

    @classmethod
    def load_default(cls) -> Catalog:
        raw = resources.files("lump.data").joinpath("ai_services.json").read_text("utf-8")
        data = json.loads(raw)
        services = [
            Service(
                id=s["id"], name=s["name"], vendor=s["vendor"], category=s["category"],
                domains=tuple(s["domains"]), data_boundary=s.get("data_boundary", "unknown"),
            )
            for s in data["services"]
        ]
        return cls(services=services)
