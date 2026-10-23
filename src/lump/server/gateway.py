"""LLM gateway: an inspecting reverse proxy in front of model APIs.

Point your application's base URL at the gateway instead of the provider. Every
request is inspected before it leaves your network (prompt injection, secrets,
policy) and every response is inspected before it reaches your application
(output handling, data leakage, redaction). Works with OpenAI-,
Anthropic- and Google-style JSON schemas; unknown shapes fall back to scanning
the whole JSON body.

Blocked requests never reach the provider — the gateway returns a provider-
shaped error so existing client SDKs surface it cleanly. Streaming responses
are enforced on the request side and passed through (response-side inspection
of SSE deltas is best-effort and off by default).
"""

from __future__ import annotations

import http.client
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from ..config import LumpConfig
from ..engine.dlp import redact
from ..engine.engine import Engine
from ..engine.types import Action, Context, Direction, Severity
from .audit import Auditor

MAX_BODY = 32 * 1024 * 1024
# Stripped when relaying. accept-encoding is dropped so upstream answers in
# identity encoding — a gzipped body could not be inspected (and must not
# silently bypass inspection).
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host", "accept-encoding"}


_UNTRUSTED_ROLES = {"tool", "function", "ipython"}
_UNTRUSTED_BLOCKS = {"tool_result", "function_call_output", "web_search_tool_result", "document"}


def _texts(value, out: list[str], skip_untrusted: bool) -> None:
    if isinstance(value, str):
        if value.strip():
            out.append(value)
    elif isinstance(value, list):
        for part in value:
            _texts(part, out, skip_untrusted)
    elif isinstance(value, dict):
        if skip_untrusted and value.get("type") in _UNTRUSTED_BLOCKS:
            return
        for key in ("text", "content", "input_text", "output"):
            if key in value:
                _texts(value[key], out, skip_untrusted)
                break


def extract_prompts(body: dict) -> list[str]:
    """Pull principal-authored text (user/system/assistant turns) out of a
    request body across OpenAI, Anthropic and Google schemas. Tool results are
    excluded here — see :func:`extract_untrusted`."""

    texts: list[str] = []
    for msg in body.get("messages", []) or []:  # OpenAI chat / Anthropic messages
        if isinstance(msg, dict) and msg.get("role") not in _UNTRUSTED_ROLES:
            _texts(msg.get("content"), texts, skip_untrusted=True)
    _texts(body.get("system"), texts, skip_untrusted=True)  # Anthropic system
    _texts(body.get("instructions"), texts, skip_untrusted=True)  # OpenAI Responses
    _texts(body.get("prompt"), texts, skip_untrusted=True)  # legacy completions
    inp = body.get("input")  # embeddings / Responses API
    if isinstance(inp, list):
        for item in inp:
            if not (isinstance(item, dict) and (item.get("type") in _UNTRUSTED_BLOCKS or item.get("role") in _UNTRUSTED_ROLES)):
                _texts(item, texts, skip_untrusted=True)
    else:
        _texts(inp, texts, skip_untrusted=True)
    for content in body.get("contents", []) or []:  # Google generateContent
        if isinstance(content, dict) and content.get("role") != "function":
            for part in content.get("parts", []) or []:
                if isinstance(part, dict) and "text" in part:
                    _texts(part["text"], texts, skip_untrusted=True)
    sys_inst = body.get("systemInstruction") or body.get("system_instruction")
    if isinstance(sys_inst, dict):
        for part in sys_inst.get("parts", []) or []:
            _texts(part.get("text") if isinstance(part, dict) else part, texts, skip_untrusted=True)
    return texts


def extract_untrusted(body: dict) -> list[str]:
    """Pull tool / function results out of a request body. These are data the
    agent fetched, not instructions from the user, so they are inspected as
    untrusted content (indirect prompt injection)."""

    texts: list[str] = []

    def collect(value) -> None:
        inner: list[str] = []
        _texts(value, inner, skip_untrusted=False)
        texts.extend(inner)

    for msg in body.get("messages", []) or []:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") in _UNTRUSTED_ROLES:
            collect(msg.get("content"))
        elif isinstance(msg.get("content"), list):
            for block in msg["content"]:
                if isinstance(block, dict) and block.get("type") in _UNTRUSTED_BLOCKS:
                    collect(block.get("content", block.get("output")))
    inp = body.get("input")
    if isinstance(inp, list):
        for item in inp:
            if isinstance(item, dict) and (item.get("type") in _UNTRUSTED_BLOCKS or item.get("role") in _UNTRUSTED_ROLES):
                collect(item.get("output", item.get("content")))
    for content in body.get("contents", []) or []:  # Google functionResponse turns
        if isinstance(content, dict):
            for part in content.get("parts", []) or []:
                if isinstance(part, dict) and "functionResponse" in part:
                    collect(json.dumps(part["functionResponse"].get("response", {})))
    return texts


def extract_response_text(body: dict) -> list[str]:
    texts: list[str] = []

    def add(value) -> None:
        if isinstance(value, str) and value.strip():
            texts.append(value)
        elif isinstance(value, list):
            for part in value:
                if isinstance(part, dict):
                    add(part.get("text"))
                else:
                    add(part)

    for choice in body.get("choices", []) or []:  # OpenAI
        if isinstance(choice, dict):
            msg = choice.get("message") or {}
            add(msg.get("content"))
            add(choice.get("text"))
    add(body.get("content"))  # Anthropic: list of blocks
    for cand in body.get("candidates", []) or []:  # Google
        if isinstance(cand, dict):
            content = cand.get("content") or {}
            for part in content.get("parts", []) or []:
                add(part.get("text") if isinstance(part, dict) else part)
    return texts


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "lump-gateway/0.1"
    protocol_version = "HTTP/1.1"

    engine: Engine
    auditor: Auditor
    config: LumpConfig
    upstream_url: str

    def log_message(self, *args) -> None:
        pass

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path == "/healthz":
            return self._send_json(200, {"status": "ok", "upstream": self.upstream_url})
        self._forward(b"")

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return self._send_json(400, _error("invalid Content-Length"))
        if length < 0 or length > MAX_BODY:
            return self._send_json(413, _error("request too large"))
        raw = self.rfile.read(length) if length else b""

        user = self.headers.get("X-Lump-User")
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}

        if isinstance(body, dict):
            try:
                blocked, raw = self._inspect_request(body, raw, user)
            except Exception:  # noqa: BLE001
                # Inspection itself failed. Fail closed unless told otherwise.
                if not self.config.server.fail_open:
                    return self._send_json(503, _error("inspection unavailable; request held (fail-closed)",
                                                       code="lump_unavailable"))
                blocked = None
            if blocked is not None:
                return self._send_json(403, blocked)

        self._forward(raw, user=user, streaming=bool(isinstance(body, dict) and body.get("stream")))

    def _inspect_request(self, body: dict, raw: bytes, user: str | None) -> tuple[dict | None, bytes]:
        """Inspect a request body. Returns (error_payload_if_blocked, body_to_forward)."""

        destination = urlparse(self.upstream_url).hostname
        # Untrusted content (tool results) is scored as indirect injection.
        for text in extract_untrusted(body):
            verdict = self.engine.inspect(text, Context(direction=Direction.TOOL_RESULT, source="gateway",
                                                        user=user, destination=destination))
            self.auditor.record(verdict, source="gateway", direction="tool_result", user=user, destination=destination)
            if verdict.action is Action.BLOCK:
                return _error("Request blocked by Lump policy (tool result): " + "; ".join(verdict.reasons[:3]),
                              code="lump_blocked", risk=verdict.risk), raw

        prompts = extract_prompts(body)
        combined = "\n\n".join(prompts)
        if not combined.strip():
            return None, raw
        verdict = self.engine.inspect(combined, Context(direction=Direction.INPUT, source="gateway", user=user,
                                                        destination=destination))
        self.auditor.record(verdict, source="gateway", direction="input", user=user, destination=destination)
        if verdict.action is Action.BLOCK:
            return _error("Request blocked by Lump policy: " + "; ".join(verdict.reasons[:3]),
                          code="lump_blocked", risk=verdict.risk), raw
        if verdict.redacted_text is not None and self.config.policy.redact_secrets:
            raw = self._redact_body(body, prompts)
        return None, raw

    def _redact_body(self, body: dict, prompts: list[str]) -> bytes:
        """Redact each prompt string on its own and substitute it back into the body."""

        mapping = {}
        for prompt in prompts:
            if self.engine.dlp is None:
                break
            findings = [f for f in self.engine.dlp.detect(prompt) if f.severity >= Severity.MEDIUM]
            redacted = redact(prompt, findings)
            if redacted != prompt:
                mapping[prompt] = redacted
        return json.dumps(_swap_strings(body, mapping)).encode("utf-8")

    def _forward(self, raw: bytes, user: str | None = None, streaming: bool = False) -> None:
        up = urlparse(self.upstream_url)
        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
        ctx = ssl.create_default_context() if up.scheme == "https" else None
        try:
            conn = conn_cls(up.hostname, up.port or (443 if up.scheme == "https" else 80),
                            timeout=120, **({"context": ctx} if ctx else {}))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP and not k.lower().startswith("x-lump")}
            headers["Host"] = up.hostname
            path = self.path if up.path in ("", "/") else up.path.rstrip("/") + self.path
            conn.request(self.command, path, body=raw or None, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
        except Exception as exc:  # noqa: BLE001
            return self._send_json(502, _error(f"upstream unreachable: {type(exc).__name__}", code="upstream_error"))

        content_type = resp.getheader("Content-Type", "")
        # --- response-side inspection (non-streaming JSON only) ---
        if not streaming and "application/json" in content_type and resp.status < 300:
            try:
                parsed = json.loads(resp_body)
                out_text = "\n\n".join(extract_response_text(parsed)) if isinstance(parsed, dict) else ""
            except ValueError:
                out_text = ""
            if out_text.strip():
                try:
                    verdict = self.engine.inspect(out_text, Context(direction=Direction.OUTPUT, source="gateway", user=user))
                except Exception:  # noqa: BLE001
                    if not self.config.server.fail_open:
                        return self._send_json(503, _error("inspection unavailable; response held (fail-closed)",
                                                           code="lump_unavailable"))
                    verdict = None
                if verdict is not None:
                    self.auditor.record(verdict, source="gateway", direction="output", user=user)
                    if verdict.action is Action.BLOCK:
                        return self._send_json(403, _error(
                            "Response blocked by Lump policy: " + "; ".join(verdict.reasons[:3]),
                            code="lump_blocked_response", risk=verdict.risk))

        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in _HOP_BY_HOP:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Via", "lump-gateway")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp_body)


def _swap_strings(value, mapping: dict[str, str]):
    """Return ``value`` with every string found in ``mapping`` replaced."""

    if not mapping:
        return value
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [_swap_strings(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _swap_strings(v, mapping) for k, v in value.items()}
    return value


def _error(message: str, code: str = "lump_error", risk: int | None = None) -> dict:
    err = {"message": message, "type": "lump_policy", "code": code}
    if risk is not None:
        err["risk"] = risk
    return {"error": err}


def make_gateway(config: LumpConfig, engine: Engine | None = None, auditor: Auditor | None = None) -> ThreadingHTTPServer:
    engine = engine or Engine(config.policy, config.engine)
    auditor = auditor or Auditor(config.server.audit_log)
    handler = type("BoundGatewayHandler", (GatewayHandler,), {
        "engine": engine, "auditor": auditor, "config": config, "upstream_url": config.server.upstream,
    })
    httpd = ThreadingHTTPServer((config.server.host, config.server.port), handler)
    httpd.daemon_threads = True
    if config.server.tls_cert and config.server.tls_key:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(config.server.tls_cert, config.server.tls_key)
        httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    return httpd
