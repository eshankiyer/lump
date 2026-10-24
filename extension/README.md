# Lump browser extension

Local-first protection for AI web apps (ChatGPT, Claude, Gemini, AI Studio,
DeepSeek, Mistral, Grok, Perplexity, Poe, Copilot, Character.AI).

- **Outbound:** checks the prompt you're about to send for secrets, validated
  PII (cards, IBANs, SSNs) and injection/jailbreak text.
- **Inbound:** checks model responses for indirect prompt injection and strips
  auto-loading image beacons that could exfiltrate data.

All detection runs in the page: the same rule set as the Python engine plus
the same on-device ML classifier (`ml.js` loading `models/injection-v1.lumpml`,
checksum-verified). The browser decodes the same hidden layers as the server
(Unicode tags, variation selectors, base64, hex, percent-encoding, rot13,
leetspeak, spaced-out letters) and applies the same policy, so a prompt gets
the same score and the same ML verdict in both places; CI checks this on a
shared fixture. The model loads in the background; until it is ready, rules
alone apply, and responses already on the page are rescanned once it loads.
The model file is readable only from the AI sites listed above, through a
per-session URL, so other pages cannot use it to detect the extension.
Nothing leaves the browser unless you set a control-plane URL. If you do, only
the verdict, risk score, rule ids and **hostname** are sent. The prompt text
and the full URL are never sent.

## Modes

| Mode | Behaviour |
|---|---|
| `warn` (default) | The first send is held with an explanation. Sending again proceeds. |
| `block` | Policy blocks cannot be overridden. Lower-risk findings still warn. |
| `monitor` | Never interferes: no held sends, no outlines, no stripped images. Only records. |

On model responses, a learned-classifier score alone warns; it does not block or
strip images. Images are neutralised when a response is blocked or looks like an
exfiltration attempt.

## Install (developer mode)

```bash
pip install -e ..                       # from the repo root
lump export-rules -o extension/rules.json
```

Then open `chrome://extensions`, enable **Developer mode**, click **Load
unpacked** and select this `extension/` folder.

Re-run `lump export-rules` whenever the engine's rules change, and copy the
model after retraining, so the browser and the server stay in lockstep. CI
checks that every exported pattern compiles in JavaScript, that the JS detector
matches the Python engine on shared cases, and that the JS model reproduces
Python's probabilities:

```bash
cp src/lump/data/models/injection-v1.lumpml extension/models/
python -m lump.ml.fixture > extension/test/ml_fixture.json     # bundled model
python -m lump.ml.fixture --tiny extension/test                # tiny model, always tested
node --test extension/test/detector.test.js extension/test/ml.test.js
```

## Other browsers

- **Edge, Brave, Arc, other Chromium browsers:** load unpacked as above.
- **Safari:** `xcrun safari-web-extension-converter extension/`, then build in
  Xcode.
- **Firefox:** MV3 is supported. Add a `browser_specific_settings.gecko.id` to
  the manifest.
