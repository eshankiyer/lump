# Architecture

Lump is one detection engine wrapped by many enforcement surfaces. The engine
is deliberately synchronous, dependency-free and fast (sub-millisecond on
typical prompts) so the same code can sit inline on a gateway, an endpoint, the
network or the browser.

## The inspection pipeline

Every piece of content flows through the same five stages:

```
  text + Context
       │
       ▼
  1. normalise ──▶ builds multiple *views*: original, canonical (NFKC, invisible
       │            stripped, homoglyphs folded, whitespace collapsed), and every
       │            recovered hidden layer (Unicode tags, variation selectors,
       │            base64/hex/percent, de-spaced, de-leet). Each hidden layer is
       │            also emitted as an obfuscation signal.
       ▼
  2. detect ─────▶ the relevant detectors run over all views:
       │              injection · dlp · code · output · agentic (+ plugins)
       ▼
  3. score ──────▶ findings combine into a 0-100 risk via a saturating noisy-OR,
       │            weighted by severity and confidence; a single critical finding
       │            dominates.
       ▼
  4. decide ─────▶ the Policy maps findings → an Action (allow/warn/redact/block)
       │            using explicit rules first, then risk thresholds.
       ▼
  5. act ────────▶ redact secrets if asked; downgrade blocks to warns in monitor
                   mode; return a single Verdict.
```

### Trust and direction

A `Context` carries a `direction` (input, output, document, tool_call,
tool_result, tool_definition, artifact) and an optional `trusted` flag.
Anything that did not come from the principal — tool results, documents,
retrieved web pages, tool definitions — is **untrusted** by default. The same
sentence scores much higher as untrusted content (indirect prompt injection)
than typed by the user. This is the single most important idea in the engine:
*where* text came from changes what it means.

## Detectors

| Detector | Module | Looks for |
|---|---|---|
| injection | `engine/injection.py` | prompt injection, jailbreaks, prompt extraction, obfuscation; pattern rules + known-template similarity + de-obfuscation signals |
| dlp | `engine/dlp.py` | secrets, PII (validated), exact-data-match, document fingerprints, source code |
| code | `engine/code.py` | malicious behaviour in generated scripts/commands (ATT&CK-mapped) + typosquatted installs |
| output | `engine/output.py` | unsafe rendering: markdown/image beacons, HTML/JS injection, dangerous URI schemes |
| agentic | `engine/agentic.py` | tool poisoning, denied/excessive tool use, capability classification |

Detectors are pure functions over text (and a `Context`). Third-party
detectors register through the `lump.detectors` entry-point group and run
automatically — a bad plugin can never break inspection.

## Rules are data

Injection patterns (`engine/rules.py`) use the regex subset common to Python
`re` and ECMAScript, so `lump export-rules` emits a JSON bundle the browser
extension executes unchanged. DLP rules, jailbreak signatures, the confusable
map and the AI-service catalog are all data too. This is what lets the browser,
the gateway and the API agree to the letter.

## Policy

A `Policy` (`policy/model.py`) is data: an ordered list of `Rule`s plus risk
thresholds and a mode (enforce / monitor / off). Each rule matches on detector,
category prefix, direction, minimum severity/confidence and minimum risk, and
yields an action; the strictest matching action wins, with a risk-threshold
fallback. Policies load from TOML/JSON/YAML, so operators tune behaviour
without touching code.

## Surfaces

Each surface is a thin adapter that extracts text, calls `engine.inspect(...)`
(or `inspect_tool_call` / `inspect_tool_definition`), and enforces the verdict
in its own protocol:

- `server/api.py` — HTTP inspection API + dashboard + Prometheus metrics
- `server/gateway.py` — inspecting reverse proxy for model APIs
- `mcp/firewall.py` — JSON-RPC guard for MCP servers
- `net/dns.py`, `net/proxy.py` — network egress governance by hostname
- `sensors/host.py` — endpoint process↔connection attribution and artifact scan
- `extension/` — in-browser detection reusing the exported rules

All surfaces write to a shared `Auditor` (`server/audit.py`): an append-only
JSONL log, an in-memory ring buffer and counters that back the dashboard and
`/metrics`. Masked evidence only — raw secrets never enter the log.
