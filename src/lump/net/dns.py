"""DNS filter for shadow-AI discovery and governance.

A lightweight UDP DNS forwarder that classifies every lookup against the AI
service catalog. Queries for AI services are logged (so you can *discover* which
AI tools your network actually uses) and, when a service is blocked by policy
or sits in a disallowed data-residency boundary, the query is answered with
NXDOMAIN or a sinkhole address instead of being resolved.

This is deployment-agnostic visibility: it needs no endpoint agent and no TLS
interception — it sees only hostnames, which is exactly enough for shadow-AI
governance. All other queries are forwarded unchanged to an upstream resolver.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading

from ..engine.catalog import Catalog
from .common import EgressDecider


def parse_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    """Parse the QNAME at ``offset``; return (name, offset-after-name)."""

    labels = []
    pos = offset
    jumped = False
    end = pos
    guard = 0
    while guard < 128:
        guard += 1
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if not jumped:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumped = True
            continue
        labels.append(data[pos + 1 : pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    return ".".join(labels), end


def build_response(query: bytes, qname_end: int, rcode: int = 0, sinkhole_ip: str | None = None) -> bytes:
    """Build a DNS response to ``query``: NXDOMAIN, or an A record sinkhole."""

    txid = query[:2]
    qtype, qclass = struct.unpack(">HH", query[qname_end : qname_end + 4])
    question = query[12 : qname_end + 4]
    answers = b""
    ancount = 0
    if rcode == 0 and sinkhole_ip and qtype == 1 and qclass == 1:  # A record sinkhole
        answers = (
            b"\xc0\x0c"  # pointer to the question name
            + struct.pack(">HHIH", 1, 1, 60, 4)
            + socket.inet_aton(sinkhole_ip)
        )
        ancount = 1
    flags = 0x8180 if rcode == 0 else (0x8180 | rcode)  # QR + RD + RA (+ rcode)
    header = txid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    return header + question + answers


class _DnsHandler(socketserver.BaseRequestHandler):
    decider: EgressDecider
    upstream: tuple[str, int]
    sinkhole_ip: str | None
    block_with_nxdomain: bool

    def handle(self) -> None:
        data, sock = self.request
        if len(data) < 13:
            return
        try:
            qname, qend = parse_qname(data)
            if qend + 4 > len(data):
                return  # truncated question section
        except Exception:  # noqa: BLE001
            return
        decision = self.decider.decide_host(qname, source="dns",
                                             client=self.client_address[0] if self.client_address else None)
        if decision.block:
            if self.block_with_nxdomain or not self.sinkhole_ip:
                resp = build_response(data, qend, rcode=3)  # NXDOMAIN
            else:
                resp = build_response(data, qend, rcode=0, sinkhole_ip=self.sinkhole_ip)
            sock.sendto(resp, self.client_address)
            return
        # Forward to the upstream resolver and relay the answer.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                up.settimeout(4.0)
                up.sendto(data, self.upstream)
                answer, _ = up.recvfrom(65535)
            sock.sendto(answer, self.client_address)
        except OSError:
            sock.sendto(build_response(data, qend, rcode=2), self.client_address)  # SERVFAIL


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 65535


def make_dns_filter(
    catalog: Catalog,
    auditor,
    host: str = "127.0.0.1",
    port: int = 5353,
    upstream: tuple[str, int] = ("1.1.1.1", 53),
    sinkhole_ip: str | None = "0.0.0.0",
    block_with_nxdomain: bool = True,
) -> ThreadingUDPServer:
    decider = EgressDecider(catalog, auditor)
    handler = type("BoundDnsHandler", (_DnsHandler,), {
        "decider": decider, "upstream": upstream, "sinkhole_ip": sinkhole_ip,
        "block_with_nxdomain": block_with_nxdomain,
    })
    return ThreadingUDPServer((host, port), handler)


def serve_dns(server: ThreadingUDPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
