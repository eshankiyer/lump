"""Forward HTTP/HTTPS proxy for egress AI governance.

Set it as the system/HTTP(S) proxy and every outbound connection is classified
against the AI-service catalog by hostname. Sanctioned services pass through;
unsanctioned ("shadow AI") services are logged (and optionally blocked);
blocked services and disallowed data boundaries are refused.

For HTTPS (``CONNECT``) the proxy sees only the hostname and tunnels the
encrypted bytes untouched — no TLS interception. For plain HTTP it can
additionally hand the request body to the engine, but HTTP to AI providers is
rare; hostname governance is the primary control here.
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
from urllib.parse import urlparse

from ..engine.catalog import Catalog
from .common import EgressDecider

_BLOCK_RESPONSE = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"Via: lump-proxy\r\n"
    b"\r\n"
)


# CONNECT is only allowed to standard web ports by default, so the proxy cannot
# be used as a generic TCP pivot into the internal network.
DEFAULT_CONNECT_PORTS = frozenset({443, 8443})
DEFAULT_HTTP_PORTS = frozenset({80, 8080})


class _ProxyHandler(socketserver.StreamRequestHandler):
    decider: EgressDecider
    connect_ports: frozenset[int] = DEFAULT_CONNECT_PORTS
    timeout = 60

    def handle(self) -> None:
        try:
            request_line = self.rfile.readline(65536).decode("latin-1").strip()
        except (OSError, UnicodeDecodeError):
            return
        if not request_line:
            return
        parts = request_line.split()
        if len(parts) < 3:
            return
        method, target = parts[0], parts[1]
        # Drain the rest of the request headers.
        headers = []
        while True:
            line = self.rfile.readline(65536)
            headers.append(line)
            if line in (b"\r\n", b"\n", b""):
                break

        if method.upper() == "CONNECT":
            host, _, port_text = target.rpartition(":") if ":" in target else (target, "", "443")
            try:
                port = int(port_text or 443)
            except ValueError:
                return self._reply(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            if port not in self.connect_ports:
                return self._reply(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nVia: lump-proxy\r\n\r\nport not allowed")
            self._handle_connect(host.strip("[]"), port)
        else:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or 80
            self._handle_plain(method, target, host, port, headers)

    def _reply(self, data: bytes) -> None:
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _blocked(self, host: str) -> bool:
        client = self.client_address[0] if self.client_address else None
        decision = self.decider.decide_host(host, source="proxy", client=client)
        if decision.block:
            try:
                self.wfile.write(_BLOCK_RESPONSE + decision.reason.encode("utf-8", "ignore"))
            except OSError:
                pass
            return True
        return False

    def _handle_connect(self, host: str, port: int) -> None:
        if self._blocked(host):
            return
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            try:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return
        try:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\nVia: lump-proxy\r\n\r\n")
            self.wfile.flush()
        except OSError:
            upstream.close()
            return
        self._tunnel(self.connection, upstream)

    def _handle_plain(self, method: str, target: str, host: str, port: int, headers: list[bytes]) -> None:
        if port not in DEFAULT_HTTP_PORTS:
            return self._reply(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nVia: lump-proxy\r\n\r\nport not allowed")
        if not host or self._blocked(host):
            return
        parsed = urlparse(target)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            try:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return
        req = f"{method} {path} HTTP/1.1\r\n".encode("latin-1") + b"".join(headers)
        try:
            upstream.sendall(req)
        except OSError:
            upstream.close()
            return
        self._tunnel(self.connection, upstream)

    def _tunnel(self, a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored or not readable:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            b.close()


class ThreadingProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_proxy(catalog: Catalog, auditor, host: str = "127.0.0.1", port: int = 8888,
               connect_ports: frozenset[int] = DEFAULT_CONNECT_PORTS) -> ThreadingProxyServer:
    decider = EgressDecider(catalog, auditor)
    handler = type("BoundProxyHandler", (_ProxyHandler,), {"decider": decider, "connect_ports": frozenset(connect_ports)})
    return ThreadingProxyServer((host, port), handler)


def serve_proxy(server: ThreadingProxyServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
