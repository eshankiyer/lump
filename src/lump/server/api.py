"""HTTP inspection API and control-plane dashboard.

A dependency-free ``http.server`` app exposing the engine over HTTP so any
language or tool can call it, plus a live dashboard and Prometheus metrics.

Endpoints
---------
* ``POST /v1/inspect``               — inspect text, returns a verdict
* ``POST /v1/inspect/batch``         — inspect many items in one call
* ``POST /v1/inspect/tool_call``     — inspect an agent tool call
* ``POST /v1/inspect/tool_definition`` — inspect an MCP/function tool definition
* ``GET  /v1/catalog``               — the AI-service catalog
* ``GET  /healthz`` / ``GET /metrics`` (Prometheus) / ``GET /api/metrics`` (JSON)
* ``GET  /api/events``               — recent audit events
* ``POST /v1/events``                — ingest events from remote sensors / the browser extension

When ``server.api_keys`` is set, everything except ``/healthz`` and the static
dashboard page requires ``Authorization: Bearer <key>``.
* ``GET  /`` and ``/dashboard``      — the control-plane UI
"""

from __future__ import annotations

import hmac
import json
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from ..config import LumpConfig
from ..engine.agentic import ToolCall, ToolDefinition
from ..engine.engine import Engine
from .audit import Auditor, Event

MAX_BODY = 8 * 1024 * 1024


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "lump/0.1"
    protocol_version = "HTTP/1.1"

    # Injected by make_server via the server instance.
    engine: Engine
    auditor: Auditor
    config: LumpConfig

    def log_message(self, *args) -> None:  # silence default stderr logging
        pass

    # -- helpers -----------------------------------------------------------

    def _authorized(self) -> bool:
        keys = self.config.server.api_keys
        if not keys:
            return True
        header = self.headers.get("Authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else self.headers.get("X-API-Key", "")
        # Constant-time comparison against every configured key.
        return any(hmac.compare_digest(token.encode(), k.encode()) for k in keys)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _send(self, code: int, payload, content_type: str = "application/json", extra_headers: dict | None = None) -> None:
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, str):
            body = payload.encode("utf-8")
        else:
            body = payload
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/dashboard", "/index.html"):
            # The page itself is static; its data calls are authenticated.
            nonce = secrets.token_urlsafe(16)
            html = _dashboard_html().replace("<script>", f'<script nonce="{nonce}">', 1)
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
                   "connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            return self._send(200, html, "text/html; charset=utf-8",
                              {"Content-Security-Policy": csp, "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})
        if path == "/healthz":
            return self._send(200, {"status": "ok", "version": "0.1.0"})
        # Everything below exposes operational data: authenticate it.
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"}, extra_headers={"WWW-Authenticate": "Bearer"})
        if path == "/metrics":
            self._send(200, self.auditor.prometheus(), "text/plain; version=0.0.4")
        elif path == "/api/metrics":
            self._send(200, self.auditor.metrics.snapshot())
        elif path == "/api/events":
            q = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(q.get("limit", ["100"])[0]), 500))
            except ValueError:
                limit = 100
            self._send(200, {"events": self.auditor.recent_events(limit)})
        elif path == "/v1/catalog":
            self._send(200, {"services": [
                {"id": s.id, "name": s.name, "vendor": s.vendor, "category": s.category,
                 "domains": list(s.domains), "data_boundary": s.data_boundary,
                 "status": self.config.catalog._status(s)}
                for s in self.config.catalog.services
            ]})
        else:
            self._send(404, {"error": "not found"})

    do_HEAD = do_GET  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        data = self._read_json()
        if data is None:
            return self._send(400, {"error": "invalid or missing JSON body"})
        try:
            if path == "/v1/inspect":
                self._inspect(data)
            elif path == "/v1/inspect/batch":
                self._inspect_batch(data)
            elif path == "/v1/inspect/tool_call":
                self._inspect_tool_call(data)
            elif path == "/v1/inspect/tool_definition":
                self._inspect_tool_definition(data)
            elif path in ("/v1/events", "/api/events"):
                self._ingest_events(data)
            else:
                self._send(404, {"error": "not found"})
        except (ValueError, TypeError, KeyError) as exc:
            self._send(400, {"error": f"bad request: {type(exc).__name__}"})
        except Exception:  # noqa: BLE001 - never leak internals to the caller
            self._send(500, {"error": "internal error"})

    # -- event ingestion (browser extension, remote sensors) -----------------

    def _ingest_events(self, data: dict) -> None:
        items = data.get("events") if isinstance(data.get("events"), list) else [data]
        if len(items) > 500:
            return self._send(400, {"error": "at most 500 events per request"})
        accepted = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            action = str(item.get("action", "allow"))
            if action not in ("allow", "warn", "redact", "block"):
                continue
            try:
                risk = max(0, min(int(item.get("risk", 0)), 100))
            except (TypeError, ValueError):
                risk = 0
            rule_ids = [str(r)[:64] for r in item.get("rule_ids", []) if isinstance(r, (str, int))][:20]
            self.auditor.record_event(Event(
                ts=time.time(),
                source=_clip(item.get("source"), "remote"),
                action=action,
                risk=risk,
                direction=_clip(item.get("direction"), ""),
                rule_ids=rule_ids,
                detectors=[_clip(d, "") for d in item.get("detectors", []) if isinstance(d, str)][:8],
                destination=_clip(item.get("destination"), None, 256),
                service=_clip(item.get("service"), None),
                user=_clip(item.get("user"), None),
                app=_clip(item.get("app"), None),
                severity=_clip(item.get("severity"), "info"),
            ))
            accepted += 1
        self._send(202, {"accepted": accepted})

    # -- handlers ----------------------------------------------------------

    def _inspect(self, data: dict) -> None:
        text = data.get("text", "")
        if not isinstance(text, str):
            return self._send(400, {"error": "'text' must be a string"})
        ctx = data.get("context") or {}
        if not isinstance(ctx, dict):
            return self._send(400, {"error": "'context' must be an object"})
        verdict = self.engine.inspect(text, ctx)
        self.auditor.record(verdict, source=ctx.get("source", "api"),
                            user=ctx.get("user"), app=ctx.get("app"),
                            destination=ctx.get("destination"), direction=ctx.get("direction"))
        self._send(200, verdict.to_dict(include_redacted=data.get("return_redacted", True)))

    def _inspect_batch(self, data: dict) -> None:
        items = data.get("items", [])
        if not isinstance(items, list) or len(items) > 1000:
            return self._send(400, {"error": "'items' must be a list of <=1000"})
        results = []
        for item in items:
            text = item.get("text", "") if isinstance(item, dict) else str(item)
            ctx = item.get("context", {}) if isinstance(item, dict) else {}
            verdict = self.engine.inspect(text, ctx)
            self.auditor.record(verdict, source=ctx.get("source", "api"))
            results.append(verdict.to_dict())
        self._send(200, {"results": results})

    def _inspect_tool_call(self, data: dict) -> None:
        call = ToolCall(name=data.get("name", ""), arguments=_as_text(data.get("arguments", "")),
                        server=data.get("server"))
        verdict = self.engine.inspect_tool_call(call, self.config.agent_policy, data.get("context", {}))
        self.auditor.record(verdict, source="agent", app=call.name, direction="tool_call")
        self._send(200, verdict.to_dict())

    def _inspect_tool_definition(self, data: dict) -> None:
        tool = ToolDefinition(name=data.get("name", ""), description=data.get("description", ""),
                              schema=_as_text(data.get("schema", "")))
        verdict = self.engine.inspect_tool_definition(tool, data.get("context", {}))
        self.auditor.record(verdict, source="agent", app=tool.name, direction="tool_definition")
        self._send(200, verdict.to_dict())


def _as_text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def _clip(value, default, limit: int = 128):
    if value is None:
        return default
    return str(value)[:limit]


def _dashboard_html() -> str:
    return resources.files("lump.server.static").joinpath("dashboard.html").read_text("utf-8")


def make_server(config: LumpConfig, engine: Engine | None = None, auditor: Auditor | None = None) -> ThreadingHTTPServer:
    engine = engine or Engine(config.policy, config.engine)
    auditor = auditor or Auditor(config.server.audit_log)
    handler = type("BoundApiHandler", (ApiHandler,), {"engine": engine, "auditor": auditor, "config": config})
    httpd = ThreadingHTTPServer((config.server.host, config.server.port), handler)
    httpd.daemon_threads = True
    if config.server.tls_cert and config.server.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(config.server.tls_cert, config.server.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.lump_engine = engine  # type: ignore[attr-defined]
    httpd.lump_auditor = auditor  # type: ignore[attr-defined]
    return httpd
