# Deployment

Lump surfaces are independent processes — run only the ones you need. All read
the same config file.

## LLM gateway (recommended first step)

An inspecting reverse proxy in front of your model provider. No app code
changes beyond the base URL.

```bash
lump gateway -c lump.toml --upstream https://api.openai.com --port 8080
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="…")
```

Requests are inspected before they leave (prompt injection, secrets, policy);
JSON responses are inspected before they return (output handling, leakage).
Blocked requests return a provider-shaped `403` so SDKs surface them cleanly.
Streaming requests are enforced on the request side; streamed (SSE) responses
are passed through without inspection. Supports
OpenAI, Anthropic and Google schemas; unknown shapes fall back to scanning the
whole body. Set `fail_open = false` (default) so an internal error blocks rather
than leaks.

## MCP firewall

Wrap any stdio MCP server; put Lump where the client's launch command used to
be.

```jsonc
// before
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"] }
// after
{ "command": "lump", "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] }
```

Tool definitions are checked for poisoning before the agent sees them,
dangerous tool calls are blocked, and tool results/resources are scanned for
indirect injection and leakage.

## DNS filter (agentless, network-wide shadow-AI)

```bash
sudo lump dns -c lump.toml --host 0.0.0.0 --port 53 --resolver 1.1.1.1:53
# blocked services -> NXDOMAIN (or --sinkhole 0.0.0.0)
```

`--host 0.0.0.0` (or `[server] host`) makes it listen on every interface; the
default, 127.0.0.1, answers only the local machine. Point your resolver/DHCP at
the host. It needs only hostnames, so it works
without any endpoint agent or TLS interception.

## Egress proxy

```bash
lump proxy -c lump.toml --host 0.0.0.0 --port 8888
export HTTPS_PROXY=http://proxy-host:8888 HTTP_PROXY=http://proxy-host:8888
```

Classifies every CONNECT by hostname; blocks blocked services and disallowed
data boundaries, logs shadow AI. No TLS interception.

## Endpoint host sensor

```bash
pip install '.[host]'      # from a clone; or just: pip install psutil
lump sensor -c lump.toml --watch --interval 30 --scan-artifacts ~/ai-output
```

Attributes every AI connection to its originating process and scans AI-written
scripts — no kernel driver.

## Control plane (dashboard + API + metrics)

```bash
lump serve -c lump.toml --port 8080      # http://localhost:8080
```

- `GET /` live dashboard · `GET /metrics` Prometheus · `GET /api/events`
- `POST /v1/inspect` (and `/batch`, `/tool_call`, `/tool_definition`)

Set `server.api_keys` to require `Authorization: Bearer <key>`, and
`server.tls_cert`/`tls_key` for HTTPS.

## Docker

```bash
docker build -f deploy/Dockerfile -t lump .
docker run -p 8080:8080 -v "$PWD/lump.toml:/etc/lump/lump.toml:ro" \
  lump gateway -c /etc/lump/lump.toml --host 0.0.0.0 --upstream https://api.openai.com
```

See [`deploy/`](../deploy) for the `Dockerfile`, `docker-compose.yml` (gateway +
control plane + DNS) and a Kubernetes manifest.

## Hardening notes

- Run each surface as an unprivileged user; only the DNS filter on port 53 needs
  elevated privileges (or grant `CAP_NET_BIND_SERVICE`).
- Keep `fail_open = false` for the gateway in production.
- Ship the audit log (`server.audit_log`) to your SIEM; it is plain JSONL with
  masked evidence only.
- Start in `mode = "monitor"` to measure before you enforce.
