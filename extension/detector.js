/*
 * Lump in-browser detector.
 *
 * Mirrors the Python engine (normalisation + injection patterns + DLP + known
 * jailbreak signatures) using the rule set exported by `lump export-rules`.
 * The injection patterns are authored in the JS/Python-common regex subset, so
 * they run here unchanged. Shared by the content script (scanning prompts and
 * responses on AI web apps) and the options page tester.
 */

const Lump = (() => {
  let RULES = null;
  let injectionRegexes = [];
  let dlpRegexes = [];
  let signatures = [];
  let zeroWidthRe = null;
  let bidiRe = null;
  let tagRe = /[\u{E0000}-\u{E007F}]+/gu;
  let confusables = {};

  const ACTION_RANK = { allow: 0, warn: 1, redact: 2, block: 3 };

  function load(rules) {
    RULES = rules;
    const n = rules.normalize || {};
    const zw = (n.zero_width || []).map(escapeRe).join("");
    const bd = (n.bidi || []).map(escapeRe).join("");
    zeroWidthRe = zw ? new RegExp("[" + zw + bd + "]", "gu") : null;
    bidiRe = bd ? new RegExp("[" + bd + "]", "u") : null;
    confusables = n.confusables || {};
    injectionRegexes = (rules.injection || []).map((r) => ({ rule: r, re: compile(r.pattern, r.flags) }));
    dlpRegexes = (rules.dlp || []).map((r) => ({ rule: r, re: compile(r.pattern, (r.flags || "") + "g") }));
    signatures = (rules.signatures || []).map((s) => ({ id: s.id, family: s.family, grams: new Set(s.grams) }));
  }

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  function compile(pattern, flags) {
    let f = "";
    if ((flags || "").includes("i")) f += "i";
    if ((flags || "").includes("m")) f += "m";
    if ((flags || "").includes("s")) f += "s";
    if ((flags || "").includes("g")) f += "g";
    try { return new RegExp(pattern, f); }
    catch (e) { return new RegExp(pattern.replace(/\\p\{[^}]*\}/g, "."), f.replace("u", "")); }
  }

  // --- normalisation ---
  function stripInvisible(text) {
    let out = text;
    if (zeroWidthRe) out = out.replace(zeroWidthRe, "");
    return out.replace(tagRe, "");
  }
  function foldConfusables(text) {
    let out = "";
    for (const ch of text) out += confusables[ch] || ch;
    return out;
  }
  function revealTags(text) {
    const matches = text.match(tagRe) || [];
    return matches.map((m) => Array.from(m).map((c) => {
      const cp = c.codePointAt(0) - 0xE0000;
      return cp >= 0x20 && cp < 0x7f ? String.fromCharCode(cp) : "";
    }).join("")).join(" ");
  }
  const VS_ALL_RE = /[\ufe00-\ufe0f\u{E0100}-\u{E01EF}]/gu;
  function canonicalize(text) {
    let out = text.normalize("NFKC");
    out = stripInvisible(out).replace(VS_ALL_RE, "");
    out = foldConfusables(out);
    return out.replace(/[ \t\u00a0\u3000]+/g, " ");
  }

  // --- hidden layers (mirror engine/normalize.py) ---
  const NONPRINT_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;
  const LETTER_RE = /\p{L}/u;
  function printableRatio(s) {
    const chars = Array.from(s);
    if (!chars.length) return 0;
    let ok = 0;
    for (const ch of chars) if (ch === " " || ch === "\n" || ch === "\r" || ch === "\t" || !NONPRINT_RE.test(ch)) ok++;
    return ok / chars.length;
  }
  function looksTextual(s) {
    const chars = Array.from(s);
    if (chars.length < 6 || printableRatio(s) < 0.9) return false;
    let letters = 0, spaces = 0;
    for (const ch of chars) { if (LETTER_RE.test(ch)) letters++; if (ch === " ") spaces++; }
    return letters >= chars.length * 0.5 && spaces >= 1;
  }
  const UTF8 = new TextDecoder("utf-8", { fatal: true });
  const UTF8_LOSSY = new TextDecoder("utf-8");
  function utf8(bytes) { try { return UTF8.decode(bytes); } catch (e) { return null; } }

  const VS_RUN_RE = /[\ufe00-\ufe0f\u{E0100}-\u{E01EF}]{4,}/gu;
  function decodeVariationSelectors(text) {
    const out = [];
    for (const m of text.matchAll(VS_RUN_RE)) {
      const bytes = Array.from(m[0]).map((ch) => {
        const cp = ch.codePointAt(0);
        return cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16;
      });
      const decoded = new TextDecoder("utf-8", { ignoreBOM: true }).decode(new Uint8Array(bytes)).replace(/\ufffd/g, "");
      if (printableRatio(decoded) > 0.9 && Array.from(decoded).length >= 4) out.push(decoded);
    }
    return out.join(" ");
  }

  const B64_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])/g;
  const HEX_RE = /(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])/g;
  const PCT_RE = /(?:%[0-9A-Fa-f]{2}){6,}/g;
  const MAX_DECODED_SEGMENTS = 24, MAX_SEGMENT_CHARS = 16384;
  function decodeB64(c) {
    const s = c.trim();
    if (s.length % 4 === 1) return null;
    const padded = (s + "=".repeat((4 - (s.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/");
    let bin;
    try { bin = atob(padded); } catch (e) { return null; }
    const d = utf8(Uint8Array.from(bin, (ch) => ch.charCodeAt(0)));
    return d !== null && looksTextual(d) ? d : null;
  }
  function decodeHex(c) {
    const bytes = new Uint8Array(c.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(c.substr(i * 2, 2), 16);
    const d = utf8(bytes);
    return d !== null && looksTextual(d) ? d : null;
  }
  function decodePct(c) {
    const bytes = new Uint8Array(c.length / 3);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(c.substr(i * 3 + 1, 2), 16);
    const d = UTF8_LOSSY.decode(bytes);
    return d !== c && looksTextual(d) ? d : null;
  }
  function decodeLayers(text, depth = 2) {
    const found = [], seen = new Set();
    let frontier = [text];
    for (let level = 0; level < depth && frontier.length; level++) {
      const next = [];
      for (const chunk of frontier) {
        for (const [kind, re, dec] of [["base64", B64_RE, decodeB64], ["hex", HEX_RE, decodeHex], ["percent", PCT_RE, decodePct]]) {
          for (const m of chunk.matchAll(re)) {
            if (found.length >= MAX_DECODED_SEGMENTS) return found;
            const cand = m[0].slice(0, MAX_SEGMENT_CHARS);
            if (seen.has(kind + ":" + cand)) continue; // per decoder: hex runs also match base64
            seen.add(kind + ":" + cand);
            const d = dec(cand);
            if (d) { found.push([kind, d]); next.push(d); }
          }
        }
      }
      frontier = next;
    }
    return found;
  }
  function rot13(s) {
    return s.replace(/[A-Za-z]/g, (c) => {
      const b = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
    });
  }

  // Same views (and order) as engine/normalize.normalize, minus the
  // despaced / de-leet views the browser rule set does not use.
  function views(text) {
    const v = [["original", text]];
    const canon = canonicalize(text);
    if (canon !== text) v.push(["canonical", canon]);
    const tags = revealTags(text);
    if (tags) v.push(["unicode_tags", tags]);
    const vs = decodeVariationSelectors(text);
    if (vs) v.push(["variation_selectors", vs]);
    for (const [kind, decoded] of decodeLayers(canon)) v.push([kind, canonicalize(decoded)]);
    if (/\brot[- ]?13\b/i.test(canon)) v.push(["rot13", rot13(canon)]);
    return v;
  }
  function hasConfusables(text) {
    for (const ch of text) if (confusables[ch]) return true;
    return false;
  }

  function severityFor(w) {
    if (w >= 0.85) return "critical";
    if (w >= 0.6) return "high";
    if (w >= 0.35) return "medium";
    if (w >= 0.15) return "low";
    return "info";
  }
  function noisyOr(ws) {
    let rem = 1; for (const w of ws) rem *= 1 - Math.max(0, Math.min(w, 0.99));
    return 1 - rem;
  }

  function shingle(text, n = 3) {
    const words = (text.toLowerCase().match(/[a-z0-9']+/g) || []);
    const out = new Set();
    if (words.length < n) { if (words.length) out.add(words.join(" ")); return out; }
    for (let i = 0; i <= words.length - n; i++) out.add(words.slice(i, i + n).join(" "));
    return out;
  }

  // --- detection ---
  function inspectInjection(text, untrusted, precomputed) {
    const findings = [];
    const weights = [];
    const vs = precomputed || views(text);
    for (const { rule, re } of injectionRegexes) {
      for (const [label, t] of vs) {
        const m = re.exec(t); if (re.global) re.lastIndex = 0;
        if (!m) continue;
        let w = rule.weight * (untrusted ? (rule.untrusted_boost || 1) : (rule.trusted_factor || 1));
        if (label === "unicode_tags") w *= 1.3;
        w = Math.min(w, 0.97);
        weights.push(w);
        findings.push({ detector: "injection", rule_id: rule.id, title: rule.title, severity: severityFor(w),
                        confidence: +w.toFixed(3), category: rule.category, evidence: m[0].slice(0, 120), owasp: rule.owasp });
        break;
      }
    }
    // signatures
    let grams = new Set();
    for (const [, t] of vs) for (const g of shingle(t)) grams.add(g);
    for (const sig of signatures) {
      if (!sig.grams.size) continue;
      let hit = 0; for (const g of sig.grams) if (grams.has(g)) hit++;
      const c = hit / sig.grams.size;
      if (c >= 0.6) {
        const w = Math.min(0.45 + 0.45 * c + (untrusted ? 0.05 : 0), 0.95);
        weights.push(w);
        findings.push({ detector: "injection", rule_id: sig.id, title: "Known jailbreak template: " + sig.family,
                        severity: severityFor(w), confidence: +w.toFixed(3), category: "jailbreak.known_template" });
        break;
      }
    }
    return { findings, score: noisyOr(weights) };
  }

  // --- validators (mirror engine/dlp.py) ---
  const CARD_PREFIX = /^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5|4[4-9]|22)|3(?:0[0-5]|[68])|35)/;
  function luhn(num) {
    const d = num.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19 || new Set(d).size === 1) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let x = +d[d.length - 1 - i];
      if (i % 2 === 1) { x *= 2; if (x > 9) x -= 9; }
      sum += x;
    }
    return sum % 10 === 0 && CARD_PREFIX.test(d);
  }
  const IBAN_LEN = { AD: 24, AE: 23, AT: 20, BE: 16, BG: 22, CH: 21, CY: 28, CZ: 24, DE: 22, DK: 18, EE: 20, ES: 24,
    FI: 18, FR: 27, GB: 22, GR: 27, HR: 21, HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, LI: 21, LT: 20, LU: 20, LV: 21,
    MC: 27, MT: 31, NL: 18, NO: 15, PL: 28, PT: 25, RO: 24, SA: 24, SE: 24, SI: 19, SK: 24, TR: 26, UA: 29 };
  function iban(v) {
    const s = v.replace(/ /g, "").toUpperCase();
    if (IBAN_LEN[s.slice(0, 2)] !== s.length) return false;
    const r = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of r) {
      const n = parseInt(ch, 36);
      for (const digit of String(n)) rem = (rem * 10 + +digit) % 97;
    }
    return rem === 1;
  }
  function ssn(m) {
    const [a, g, s] = [m[1], m[2], m[3]];
    if (a === "000" || a === "666" || a[0] === "9" || g === "00" || s === "0000") return false;
    return !["078-05-1120", "219-09-9999", "123-45-6789"].includes(`${a}-${g}-${s}`);
  }
  function entropy(s) {
    const c = {}; for (const ch of s) c[ch] = (c[ch] || 0) + 1;
    let e = 0; for (const k in c) { const p = c[k] / s.length; e -= p * Math.log2(p); }
    return e;
  }
  const PLACEHOLDER = /^(?:x+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|changeme|password\d*|secret\d*|example\w*|your[_\-]?\w*|placeholder|redacted|dummy|test\w*|sample\w*|none|null|undefined|xxx\w*|os\.environ.*|process\.env.*|getenv.*|env\(.*)$/i;
  function valid(rule, m, value) {
    if (rule.validator === "luhn") return luhn(value);
    if (rule.validator === "iban") return iban(value);
    if (rule.validator === "ssn") return ssn(m);
    if (rule.validator === "entropy" || rule.min_entropy) {
      if (PLACEHOLDER.test(value.replace(/^["']|["']$/g, ""))) return false;
      return entropy(value) >= (rule.min_entropy || 0);
    }
    return true;
  }

  function inspectDlp(text) {
    const findings = [];
    for (const { rule, re } of dlpRegexes) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(text)) !== null) {
        const value = rule.group ? m[rule.group] : m[0];
        if (!value || !valid(rule, m, value)) { if (m.index === re.lastIndex) re.lastIndex++; continue; }
        findings.push({ detector: "dlp", rule_id: rule.id, title: rule.title, severity: rule.severity,
                        confidence: 0.85, category: rule.data_type, evidence: mask(value),
                        span: rule.group ? null : [m.index, m.index + value.length], redact: true });
        if (m.index === re.lastIndex) re.lastIndex++;
        if (findings.length > 200) return findings;
      }
    }
    return findings;
  }

  function mask(v) { v = String(v).replace(/[\r\n]/g, " "); return v.length <= 4 ? "*".repeat(v.length) : v.slice(0, 4) + "…[" + v.length + " chars]"; }

  // Learned-classifier finding (mirrors src/lump/ml/detector.py). ``model`` is
  // a LumpML model. Scored: the original, the homoglyph-folded text (when
  // look-alike letters are present) and every hidden layer, uncapped, so decoy
  // layers cannot push a payload out of view.
  const ML_HIDDEN = new Set(["unicode_tags", "variation_selectors", "base64", "hex", "percent", "rot13"]);
  const ML_MAX_CHARS = 100000; // per view, head + tail (MLSettings.max_chars)
  function mlThresholds(th = {}) { // ml.detector.resolve_thresholds without overrides
    const warn = th.warn ?? 0.5;
    const block = Math.max(th.block ?? 0.9, warn);
    const critical = Math.max(th.critical ?? Math.max(block, 0.995), block);
    return { warn, block, critical };
  }
  function mlViews(text, vs) {
    const out = [["original", text]], seen = new Set([text]);
    const canon = vs.find(([l]) => l === "canonical");
    if (canon && hasConfusables(text) && !seen.has(canon[1])) { out.push(canon); seen.add(canon[1]); }
    for (const [label, t] of vs) {
      if (ML_HIDDEN.has(label) && t.trim() && !seen.has(t)) { out.push([label, t]); seen.add(t); }
    }
    return out;
  }
  function mlFinding(model, text, vs) {
    let best = null;
    for (const [label, t] of mlViews(text, vs || views(text))) {
      if (!t.trim()) continue;
      const s = model.score(t, { limit: ML_MAX_CHARS });
      if (!best || s.p_attack > best.s.p_attack) best = { s, t, label };
    }
    if (!best) return null;
    const th = mlThresholds(model.thresholds), p = best.s.p_attack;
    const sev = p >= th.critical ? "critical" : p >= th.block ? "high" : p >= th.warn ? "medium" : null;
    if (!sev) return null;
    const jb = (best.s.probs.jailbreak || 0) > (best.s.probs.injection || 0);
    const expl = model.explain(best.t, best.s.window, 6, ML_MAX_CHARS);
    const where = best.label === "original" ? "" : best.label === "canonical" ? " (look-alike letters folded)"
      : " (hidden in " + best.label.replace(/_/g, " ") + ")";
    return {
      detector: "ml", rule_id: jb ? "ML-JB" : "ML-PI",
      title: (jb ? "Learned classifier: jailbreak" : "Learned classifier: prompt injection") + where + " p=" + p.toFixed(2),
      severity: sev, confidence: +p.toFixed(4), category: jb ? "jailbreak.ml" : "prompt_injection.ml",
      evidence: expl.length ? expl.slice(0, 4).map(([g]) => '"' + g + '"').join(", ") : "p=" + p.toFixed(3),
      explanation: expl, view: best.label,
    };
  }

  // Directions mirror engine.types.Direction. Untrusted = anything that is not
  // the user's own input; the ML block tier applies only to third-party
  // content the agent reads (as in the Python default policy).
  const ML_BLOCK_DIRECTIONS = new Set(["tool_result", "document", "tool_definition"]);
  function inspect(text, opts = {}) {
    const direction = opts.direction || (opts.untrusted ? "document" : "input");
    const untrusted = direction !== "input";
    const vs = views(text);
    const inj = opts.injection === false ? { findings: [], score: 0 } : inspectInjection(text, untrusted, vs);
    const dlp = opts.dlp === false ? [] : inspectDlp(text);
    const findings = inj.findings.concat(dlp);
    if (opts.model) {
      try { const f = mlFinding(opts.model, text, vs); if (f) findings.push(f); } catch (e) { /* never break inspection */ }
    }
    const risk = score(findings);
    let action = "allow";
    const bump = (a) => { if (ACTION_RANK[a] > ACTION_RANK[action]) action = a; };
    for (const f of findings) {
      if (f.severity === "critical") bump("block");
      if (f.detector === "injection" && (f.severity === "high") && (f.confidence >= 0.7)) bump("block");
      if (f.detector === "dlp" && (f.severity === "high" || f.severity === "critical")) bump("redact");
      // Python default policy: ML warns at MEDIUM and blocks at HIGH only on
      // tool results / documents / tool definitions; elsewhere (direct input,
      // model output) it blocks only when the combined risk crosses 80 below.
      if (f.detector === "ml") bump("warn");
      if (f.detector === "ml" && f.severity === "high" && ML_BLOCK_DIRECTIONS.has(direction)) bump("block");
    }
    if (risk >= 80) bump("block"); else if (risk >= 40) bump("warn");
    return { action, risk, findings, direction };
  }

  const SEV_RISK = { info: 2, low: 10, medium: 30, high: 65, critical: 95 };
  function score(findings) {
    let rem = 1, top = 0;
    for (const f of findings) {
      const c = (SEV_RISK[f.severity] / 100) * Math.max(0.05, Math.min(f.confidence || 0.5, 1));
      rem *= 1 - c; top = Math.max(top, SEV_RISK[f.severity]);
    }
    return roundHalfEven(Math.max((1 - rem) * 100, top * 0.95));
  }
  // Python's round(): ties go to the even integer (28.5 -> 28), unlike Math.round.
  function roundHalfEven(x) {
    const f = Math.floor(x), d = x - f;
    if (d > 0.5) return f + 1;
    if (d < 0.5) return f;
    return f % 2 === 0 ? f : f + 1;
  }

  function catalogLookup(host) {
    if (!RULES || !RULES.catalog || !host) return null;
    host = host.toLowerCase().replace(/\.$/, "");
    for (const s of RULES.catalog) for (const d of s.domains) {
      if (host === d || host.endsWith("." + d)) return s;
    }
    return null;
  }

  return { load, inspect, inspectInjection, inspectDlp, canonicalize, views, decodeLayers, mlThresholds, catalogLookup, riskScore: score,
           get rules() { return RULES; } };
})();

if (typeof module !== "undefined" && module.exports) module.exports = Lump;
if (typeof self !== "undefined") self.Lump = Lump;
