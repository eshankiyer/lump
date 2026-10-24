# Threat coverage

Every finding the Python engine raises (the injection, ML, DLP, code, agentic
and output detectors) carries at least one reference to the frameworks your
auditors and SOC already use: **MITRE ATLAS** (adversarial AI), **MITRE
ATT&CK** (intrusion tradecraft), the **OWASP Top 10 for LLM Applications
(2025)** and the **OWASP Top 10 for Agentic Applications (2026)**. The browser
extension's in-page detector keeps only the OWASP id on its injection-rule
findings and none on its DLP, known-jailbreak-signature and ML findings.
Shadow-AI detections are recorded as audit events with no framework ids.

## Prompt injection & jailbreaks — `injection`

| Threat | Examples | Refs |
|---|---|---|
| Direct instruction override | "ignore all previous instructions", "your rules are void" | ATLAS AML.T0051, LLM01 |
| Indirect injection | instructions hidden in a document, web page or tool result addressed to "the AI" | AML.T0051.001, LLM01, ASI01 |
| Role/delimiter spoofing | fake `<|im_start|>`, `[INST]`, `System:` turns | AML.T0051, LLM01 |
| Jailbreak personas | DAN, AIM, STAN, DUDE, Developer Mode, grandma exploit | AML.T0054, LLM01 |
| Restriction/refusal suppression | "no filters", "never refuse", dual-response formats | AML.T0054 |
| Prompt extraction | "reveal your system prompt", "repeat everything above" | AML.T0056, LLM07 |
| Exfiltration instructions | "send the conversation to this URL", markdown image beacons | AML.T0057, AML.T0025, LLM02 |
| Obfuscation / smuggling | invisible Unicode tags, variation selectors, bidi, zero-width, homoglyphs, base64/hex/percent, more encoded segments than can be inspected; spaced & leet text are also de-obfuscated and scanned, but those hits carry the matched rule's refs (e.g. AML.T0051) rather than an obfuscation finding | AML.T0043, ATT&CK T1027 (OB-001..OB-007) |

Hiding an instruction from the human reader is itself treated as a signal, and
untrusted content (documents, tool results) is scored higher than user input.

Alongside the rules, a learned classifier (`ml` detector, rule ids `ML-PI` /
`ML-JB`) scores the same content and catches reworded attacks that avoid the
rules' vocabulary. It also scores every recovered hidden layer and the
homoglyph-folded, de-leeted and de-spaced forms, so base64, Unicode-tag
smuggling, look-alike letters, leetspeak or s p a c e d text do not hide an
attack from it. See [ml.md](ml.md).

## Data loss — `dlp`

Cloud/SaaS credentials (AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe,
OpenAI, Anthropic, HF, npm, PyPI, SendGrid, Twilio, …), private keys, JWTs,
database URLs and hard-coded secrets (entropy-gated to cut false positives);
validated PII (payment cards via Luhn, IBAN via mod-97, US SSN); classification
markings; plus three content-aware techniques:

- **Exact Data Match** — salted SHA-256 comparison; the detector holds only
  hashes, and supplying precomputed `edm_hashes` (from `lump hash-edm`) keeps
  the plaintext list out of config and memory entirely. Plaintext `edm_values`
  and `edm_files` are also accepted and hashed at load.
- **Document fingerprinting** — hashed word-shingles detect a pasted excerpt of
  a protected document even after reformatting.
- **Source-code detection** — flags code leaving via an AI tool.

All map to ATLAS AML.T0057 and OWASP LLM02.

## Malicious AI-generated code — `code`

Behavioural signatures (mapped to ATT&CK) for download-and-execute cradles,
reverse shells, credential access, keylogging, persistence (registry Run,
cron/scheduled tasks, SSH keys, services, shell profiles), defense evasion
(AMSI, disabling EDR, log clearing), destructive/ransomware/anti-recovery
actions, cryptomining and privilege escalation — plus **slopsquatting**
detection (install commands naming packages that typo- or transposition-squat
popular ones, caught with a Damerau edit-distance check). Behavioural
signatures map to OWASP ASI05 and LLM05; slopsquatting findings (CODE-070) map
to OWASP LLM03 and ASI04, ATLAS AML.T0010 and ATT&CK T1195.

## Agentic & tool risk — `agentic`

Mapped to the OWASP Agentic Top-10:

- **Tool poisoning / rug pulls** (ASI04) — hidden instructions or
  hidden-instruction markup inside an MCP/function tool *definition*.
- **Excessive agency** (ASI02, LLM06) — capability classification of tool calls
  (shell, filesystem-write, network, email, payment, secret-access, privileged)
  with allow/deny lists. Calls in approval-required capability groups (payment
  and privileged by default) are flagged as needing human approval
  (AG-CALL-004, a warning; Lump does not hold the call for approval).
- **Identity & privilege abuse** (ASI03) — calls to denied tools, to tools
  outside the allow-list, or that use a denied capability (AG-CALL-003) are
  blocked.
- Indirect injection arriving through tool results (ASI01) is handled by the
  injection detector on untrusted content.

## Improper output handling — `output`

Markdown/HTML image beacons that silently exfiltrate data when rendered,
inline `<script>`/event handlers, `javascript:`/`data:` URIs, hidden HTML
elements and SQL meta-characters in model output. Maps to OWASP LLM05.

## Shadow AI & data residency — catalog

The DNS filter and egress proxy classify outbound traffic by hostname against
a catalog of 30+ AI services, attribute it (vendor, category, data boundary)
and enforce a sanctioned / unsanctioned / blocked policy — including blocking
by data-residency region (e.g. disallow `cn`-hosted services). The host sensor
applies the same classification to outbound connections on the endpoint
(matched via resolved catalog IPs and reverse DNS) and attributes them to the
originating process; connections to blocked services are recorded as `block`
audit events, not stopped.
