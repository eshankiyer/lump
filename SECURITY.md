# Security policy

Lump is a security tool, so flaws in Lump itself matter. Please report
vulnerabilities privately through GitHub's **Report a vulnerability** button on
this repository (Security → Advisories) rather than in a public issue.

Useful reports include:

- detection bypasses with a minimal reproducing input (these also make good
  benchmark cases)
- ways to make an enforcement surface fail open, crash or hang, including
  regex denial of service
- ways to reach the control plane, audit data or upstream credentials without
  authorisation
- the browser extension leaking prompt content

## Design commitments

- **Fail closed.** If inspection errors, the gateway holds the request
  (`server.fail_open = false` by default).
- **No raw secrets in logs.** Evidence is masked or snippeted before it reaches
  the audit log, metrics or the dashboard.
- **Least exposure.** Every server binds to `127.0.0.1` by default. With
  `api_keys` set, everything except `/healthz` requires a key, compared in
  constant time. The egress proxy only tunnels to web ports.
- **Bounded work.** Request bodies are size-limited and every regex is
  regression-tested against adversarial input (`tests/test_redos.py`).
- **Minimal dependencies.** The core runs on the Python standard library alone.
