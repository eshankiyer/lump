# Lump browser extension

Local-first protection for AI web apps (ChatGPT, Claude, Gemini, AI Studio,
DeepSeek, Mistral, Grok, Perplexity, Poe, Copilot, Character.AI).

- **Outbound:** checks the prompt you're about to send for secrets, validated
  PII (cards, IBANs, SSNs) and injection/jailbreak text.
- **Inbound:** checks model responses for indirect prompt injection and strips
  auto-loading image beacons that could exfiltrate data.

All detection runs in the page using the same rule set as the Python engine.
Nothing leaves the browser unless you set a control-plane URL. If you do, only
the verdict, risk score, rule ids and **hostname** are sent. The prompt text
and the full URL are never sent.

## Modes

| Mode | Behaviour |
|---|---|
| `warn` (default) | The first send is held with an explanation. Sending again proceeds. |
| `block` | Policy blocks cannot be overridden. Lower-risk findings still warn. |
| `monitor` | Never interferes, only records. |

## Install (developer mode)

```bash
pip install -e ..                       # from the repo root
lump export-rules -o extension/rules.json
```

Then open `chrome://extensions`, enable **Developer mode**, click **Load
unpacked** and select this `extension/` folder.

Re-run `lump export-rules` whenever the engine's rules change, so the browser
and the server stay in lockstep. CI checks that every exported pattern compiles
in JavaScript and that the JS detector matches the Python engine on shared
cases:

```bash
node --test extension/test/detector.test.js
```

## Other browsers

- **Edge, Brave, Arc, other Chromium browsers:** load unpacked as above.
- **Safari:** `xcrun safari-web-extension-converter extension/`, then build in
  Xcode.
- **Firefox:** MV3 is supported. Add a `browser_specific_settings.gecko.id` to
  the manifest.
