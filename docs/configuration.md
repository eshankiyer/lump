# Configuration

Lump loads one file (TOML preferred; JSON and YAML supported) that configures
every surface. Pass it with `-c/--config`. With no config the built-in defaults
apply. A complete annotated example is in [`examples/lump.toml`](../examples/lump.toml).

## `[engine]`

| Key | Default | Meaning |
|---|---|---|
| `injection`, `dlp`, `code`, `output` | `true` | enable/disable detector families |
| `plugins` | `true` | load third-party detectors from the `lump.detectors` entry point |
| `max_bytes` | `1000000` | content larger than this is truncated before scanning |

## `[policy]`

| Key | Default | Meaning |
|---|---|---|
| `name` | `"custom"` | label shown in verdicts and audit |
| `mode` | `"enforce"` | `enforce`; `monitor` (record and warn, never block or rewrite); `off` (report findings, enforce nothing) |
| `block_risk` | `80` | risk ≥ this blocks by default |
| `warn_risk` | `40` | risk ≥ this warns by default |
| `redact_secrets` | `true` | auto-redact medium+ DLP findings |
| `default_action` | `"allow"` | action when nothing matches |
| `fallback_excludes` | `["ml"]` | detectors left out of the `block_risk`/`warn_risk` fallback (the ML layer acts only through its explicit rules) |
| `extend_default` | `true` | keep the built-in rules and add `[[policy.rules]]` below |

### `[[policy.rules]]`

Ordered; the strictest matching action wins. Fields: `action`
(`allow`/`warn`/`redact`/`block`), `detectors`, `categories` (prefix match),
`directions`, `min_severity`, `min_confidence`, `min_risk`, `untrusted`
(`true`/`false`: match only content of that trust), and `requires` (other
detectors that must also have a medium+ finding in the same inspection).

```toml
[[policy.rules]]
action = "block"
detectors = ["injection"]
categories = ["prompt_injection.indirect"]
directions = ["document", "tool_result"]
min_severity = "medium"

# Block a HIGH learned-classifier score on direct input when an injection rule agrees
# (this one is built in; shown as an example of `requires`).
[[policy.rules]]
action = "block"
detectors = ["ml"]
min_severity = "high"
requires = ["injection"]
```

## `[ml]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | run the learned classifier alongside the rules |
| `model_path` | *(bundled)* | a `.lumpml` file produced by `lump train` (relative to this config file) |
| `warn`, `block`, `critical` | *(the model's own)* | override operating points (probabilities; omit or 0 = default; must be in order) |
| `explain` | `true` | attach the top contributing phrases to findings |
| `max_chars` | `100000` | scoring budget per view; longer text is scored head + tail (the rules still scan all of it) |
| `transformer` | `false` | add the optional DeBERTa backend (`lump model pull`, `pip install 'lump[ml]'`) |
| `transformer_dir` | `~/.cache/lump` | where `lump model pull` stored it (relative to this config file) |

See [ml.md](ml.md).

## `[dlp]`

| Key | Default | Meaning |
|---|---|---|
| `keywords` | `[]` | protected words/phrases (whole-word, case-insensitive) |
| `disabled_rules` | `[]` | built-in DLP rule ids to turn off |
| `detect_source_code` | `true` | flag source code leaving via AI |
| `edm_salt`, `edm_hashes` | `""`, `[]` | Exact Data Match: salt + sha256 hashes |
| `edm_values`, `edm_files` | `[]` | plaintext values/files hashed at load time |
| `fingerprint_threshold` | `0.2` | share of a document's shingles needed to match |

`[[dlp.custom_patterns]]`: `id`, `title`, `pattern`, `severity`, `flags`,
`redact`.
`[[dlp.fingerprint_files]]`: `name`, `path`.

Generate EDM hashes without putting plaintext in config:

```bash
lump hash-edm customers.txt --salt "$SALT"   # prints {edm_salt, edm_hashes}
```

## `[catalog]` — shadow-AI governance

| Key | Default | Meaning |
|---|---|---|
| `allowlist_mode` | `false` | if true, any catalogued service not sanctioned is "unsanctioned" |
| `sanctioned` | `[]` | approved service ids |
| `blocked` | `[]` | blocked service ids |
| `blocked_boundaries` | `[]` | blocked data-residency regions, e.g. `["cn"]` |

`[[catalog.services]]` adds internal/extra services: `id`, `name`, `vendor`,
`category`, `domains`, `data_boundary`.

## `[agent]` — agentic controls

| Key | Default | Meaning |
|---|---|---|
| `allowed_tools` | *(unset)* | if present, only these tools are allowed |
| `denied_tools` | `[]` | tools always blocked |
| `denied_capabilities` | `[]` | capability groups to block (`shell`, `payment`, …) |
| `approval_capabilities` | `["payment","privileged"]` | capabilities needing human approval |

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `host`, `port` | `127.0.0.1`, `8080` | bind address |
| `upstream` | `https://api.openai.com` | provider base URL for `lump gateway` |
| `api_keys` | `[]` | if set, require `Authorization: Bearer <key>` |
| `tls_cert`, `tls_key` | *(unset)* | enable HTTPS |
| `fail_open` | `false` | on internal error, allow (`true`) or block (`false`) |
| `audit_log` | *(unset)* | path to the JSONL audit log |

CLI flags `--host`, `--port`, `--upstream`, `--audit-log`, `--mode` override the
file.
