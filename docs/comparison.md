# How Lump compares

Lump was built as an open-source counterpart to commercial "AI runtime threat
prevention" products such as **Salience Cyber** (saliencecyber.ai). The
Salience column below is drawn from that company's public marketing material
as of October 2026 (its product is in private beta). It has not been
independently tested, and features not mentioned publicly are marked "not
stated" rather than "no".

| Capability | Salience Cyber (public claims) | Lump |
|---|---|---|
| License / availability | Proprietary, private beta | **Apache-2.0**, install today |
| Inspection without an LLM in the path | Yes | **Yes**: rules plus an on-device ML classifier, about 1 ms per prompt |
| Learned detection of reworded attacks | Claims a proprietary "CognitionAI" engine | **Yes**: open model trained on vetted, pinned public data, with published held-out metrics and a reproducible `lump train` |
| Browser coverage | Extension (Chrome, Chromium, Edge, Safari) | Extension (Chromium MV3; Firefox/Safari via conversion) |
| Endpoint coverage | "System Sensor", no kernel component | **Host sensor**, no kernel component (psutil) |
| Attribute AI connections to a process | Yes | **Yes** |
| Prompt injection (direct) | Yes | **Yes** |
| Indirect injection (documents, tool results) | Not stated in detail | **Yes**, untrusted-content scoring |
| Jailbreak detection | Not stated | **Yes**: patterns + known-template similarity |
| Hidden-text / Unicode smuggling | Not stated | **Yes**: tags, variation selectors, bidi, homoglyphs, encodings |
| Shadow-AI discovery | Yes | **Yes**: catalog of 30+ services, data-residency rules |
| AI-generated malware / dangerous code | Yes | **Yes**: ATT&CK-mapped behaviours + slopsquatting |
| Agentic exploitation | Yes | **Yes**: OWASP Agentic Top-10 controls |
| **Network-wide, agentless enforcement** | Not stated | **DNS filter + egress proxy** |
| **LLM API gateway** for apps and services | Not stated | **Yes**: OpenAI / Anthropic / Google schemas, both directions |
| **MCP firewall** (tool poisoning, tool calls, results) | Not stated | **Yes** |
| Data loss prevention | Not stated | **Yes**: validated secrets/PII, exact-data-match, fingerprints |
| Framework mapping | Not stated | **MITRE ATLAS, ATT&CK, OWASP LLM + Agentic** on every finding |
| Published detection metrics | Not stated | **`lump bench`**: precision/recall/F1/latency |
| Self-hosted control plane | Not stated | **Yes**: dashboard, API, Prometheus, JSONL audit |

"Secure all networks alike" is the design goal behind the extra surfaces. The
same engine and policy run in the browser, on the host, at the API gateway, in
front of MCP servers, and at the network edge (DNS and proxy). An unmanaged
device, a headless service or an autonomous agent gets the same protection as a
managed laptop.

## Honest limitations

- **The ML model is small by design.** The built-in classifier is a hashed n-gram
  linear model, so it runs everywhere, including the browser, at about 1 ms. It
  catches far more reworded attacks than the rules, but it has no deep
  understanding of who an instruction is addressed to. Carefully built benign
  look-alikes remain hard; [docs/ml.md](ml.md) and the model card give the
  per-dataset numbers. The optional transformer backend adds a stronger second
  opinion where its size and latency are acceptable.
- **`lump bench` is a regression guard, not an accuracy claim.** Its 77-sample
  corpus is self-authored. The ML model's held-out evaluation, thousands of
  samples from datasets by other authors, is in the model card. Still, run your
  own traffic in monitor mode before trusting any number.
- **The gateway does not inspect streaming responses.** Requests are always
  inspected; SSE responses pass through.
- **The proxy and DNS filter see hostnames only.** There is no TLS
  interception, so content inspection for web apps happens in the browser
  extension or at the gateway.
- **Host-sensor attribution is approximate for CDN-fronted services.** It
  relies on resolved IPs and reverse DNS, and shared CDN addresses can blur
  which AI service a connection belongs to.
- **Throughput.** The engine scans roughly 300 KB/s per thread in pure Python.
  Typical prompts take well under a millisecond, while megabyte-sized documents
  take seconds. `engine.max_bytes` caps the cost.
- **Browser support.** The extension is Chromium Manifest V3. Safari needs
  `xcrun safari-web-extension-converter`, and Firefox needs minor manifest
  changes.
