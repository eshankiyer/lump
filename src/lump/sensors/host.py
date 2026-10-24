"""Endpoint host sensor.

Associates every outbound AI connection with its originating process, so you
can answer "which app on this machine is talking to which AI service" without a
kernel driver. It uses the OS's own socket table (via ``psutil``) — no ring-0
component, no TLS interception. It complements the browser extension (which
sees prompts) and the network surfaces (which see hostnames) with
process-level attribution on the host itself.

Capabilities:
* enumerate established connections to catalogued AI services and attribute
  them to a process (name, pid, exe, user);
* flag shadow-AI: processes reaching unsanctioned or blocked services, or
  services that bypass the approved channel;
* scan AI-generated artifacts (recently written scripts) with the code
  detector before they run.

``psutil`` is an optional dependency (the ``host`` extra).
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field

from ..engine.catalog import Catalog
from ..engine.code import CodeDetector
from ..engine.types import Severity
from ..server.audit import Auditor, Event

try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore
    HAVE_PSUTIL = False


@dataclass
class Connection:
    pid: int | None
    process: str
    exe: str
    user: str
    raddr: str
    rport: int
    host: str | None
    service_id: str | None
    service_name: str | None
    status: str  # sanctioned | unsanctioned | blocked | unknown


@dataclass
class ReverseDnsCache:
    ttl: float = 900.0
    _cache: dict[str, tuple[float, str | None]] = field(default_factory=dict)

    def resolve(self, ip: str) -> str | None:
        now = time.time()
        hit = self._cache.get(ip)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        name: str | None = None
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            name = None
        self._cache[ip] = (now, name)
        return name


class HostSensor:
    def __init__(self, catalog: Catalog, auditor: Auditor, resolve_dns: bool = True):
        if not HAVE_PSUTIL:
            raise RuntimeError("the host sensor requires psutil (the 'host' extra: pip install psutil)")
        self.catalog = catalog
        self.auditor = auditor
        self.resolve_dns = resolve_dns
        self.rdns = ReverseDnsCache()
        self.code = CodeDetector()
        # Pre-resolve catalog domains to IPs so classification works without rDNS.
        self._ip_to_service = self._resolve_catalog_ips()

    def _resolve_catalog_ips(self) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for svc in self.catalog.services:
            for domain in svc.domains:
                try:
                    for res in socket.getaddrinfo(domain, None):
                        mapping[res[4][0]] = svc.id
                except OSError:
                    continue
        return mapping

    def refresh_catalog_ips(self) -> None:
        self._ip_to_service = self._resolve_catalog_ips()

    def _classify_remote(self, ip: str) -> tuple[str | None, object | None]:
        svc_id = self._ip_to_service.get(ip)
        if svc_id:
            svc = next((s for s in self.catalog.services if s.id == svc_id), None)
            return (self.rdns.resolve(ip) if self.resolve_dns else None), svc
        host = self.rdns.resolve(ip) if self.resolve_dns else None
        return host, self.catalog.lookup(host)

    def snapshot(self) -> list[Connection]:
        conns: list[Connection] = []
        proc_cache: dict[int, tuple[str, str, str]] = {}
        for c in psutil.net_connections(kind="inet"):  # type: ignore[union-attr]
            if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            ip = c.raddr.ip
            if ip.startswith(("127.", "::1", "10.", "192.168.", "169.254.")):
                continue
            host, svc = self._classify_remote(ip)
            if svc is None:
                continue
            pid = c.pid
            if pid and pid not in proc_cache:
                proc_cache[pid] = self._process_info(pid)
            name, exe, user = proc_cache.get(pid, ("?", "", ""))
            status = self.catalog._status(svc)
            conns.append(Connection(pid=pid, process=name, exe=exe, user=user, raddr=ip, rport=c.raddr.port,
                                    host=host, service_id=svc.id, service_name=svc.name, status=status))
        return conns

    def _process_info(self, pid: int) -> tuple[str, str, str]:
        try:
            p = psutil.Process(pid)  # type: ignore[union-attr]
            with p.oneshot():
                return p.name(), (p.exe() if _safe(p.exe) else ""), (p.username() if _safe(p.username) else "")
        except Exception:  # noqa: BLE001
            return "?", "", ""

    def report(self) -> list[Event]:
        events = []
        for conn in self.snapshot():
            block = conn.status == "blocked"
            action = "block" if block else ("allow" if conn.status == "sanctioned" else "warn")
            severity = "high" if block else ("medium" if conn.status in ("unsanctioned", "unknown") else "info")
            event = Event(
                ts=time.time(), source="host", action=action,
                risk=90 if block else (40 if conn.status in ("unsanctioned", "unknown") else 0),
                direction="egress", rule_ids=[f"SHADOW-AI:{conn.status.upper()}"], detectors=["shadow_ai"],
                destination=conn.host or conn.raddr, service=conn.service_name,
                app=f"{conn.process}({conn.pid})" if conn.pid else conn.process, severity=severity,
            )
            self.auditor.record_event(event)
            events.append(event)
        return events

    def scan_artifacts(self, paths: list[str], max_bytes: int = 2_000_000) -> list[Event]:
        """Scan files (AI-written scripts/artifacts) for malicious behaviour."""

        events = []
        for path in _iter_files(paths):
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            findings = self.code.detect(text)
            if not findings:
                continue
            top = max(findings, key=lambda f: f.severity)
            event = Event(
                ts=time.time(), source="host-artifact",
                action="block" if top.severity >= Severity.HIGH else "warn",
                risk=int(min(top.severity * 25, 95)), direction="artifact",
                rule_ids=[f.rule_id for f in findings][:10], detectors=["code"],
                destination=path, service=None, app=os.path.basename(path), severity=top.severity.label,
            )
            self.auditor.record_event(event)
            events.append(event)
        return events


def _safe(fn) -> bool:
    try:
        fn()
        return True
    except Exception:  # noqa: BLE001
        return False


def _iter_files(paths: list[str]):
    exts = {".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".js", ".mjs", ".cjs", ".vbs", ".bat", ".cmd", ".rb", ".pl"}
    for path in paths:
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if os.path.splitext(f)[1].lower() in exts:
                        yield os.path.join(root, f)
