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
  function canonicalize(text) {
    let out = text.normalize("NFKC");
    out = stripInvisible(out);
    out = foldConfusables(out);
    return out.replace(/[ \t 　]+/g, " ");
  }
  function views(text) {
    const v = [["original", text]];
    const canon = canonicalize(text);
    if (canon !== text) v.push(["canonical", canon]);
    const tags = revealTags(text);
    if (tags) v.push(["unicode_tags", tags]);
    return v;
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
  function inspectInjection(text, untrusted) {
    const findings = [];
    const weights = [];
    const vs = views(text);
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

  function inspect(text, opts = {}) {
    const untrusted = !!opts.untrusted;
    const inj = opts.injection === false ? { findings: [], score: 0 } : inspectInjection(text, untrusted);
    const dlp = opts.dlp === false ? [] : inspectDlp(text);
    const findings = inj.findings.concat(dlp);
    const risk = score(findings);
    let action = "allow";
    const bump = (a) => { if (ACTION_RANK[a] > ACTION_RANK[action]) action = a; };
    for (const f of findings) {
      if (f.severity === "critical") bump("block");
      if (f.detector === "injection" && (f.severity === "high") && (f.confidence >= 0.7)) bump("block");
      if (f.detector === "dlp" && (f.severity === "high" || f.severity === "critical")) bump("redact");
    }
    if (risk >= 80) bump("block"); else if (risk >= 40) bump("warn");
    return { action, risk, findings };
  }

  const SEV_RISK = { info: 2, low: 10, medium: 30, high: 65, critical: 95 };
  function score(findings) {
    let rem = 1, top = 0;
    for (const f of findings) {
      const c = (SEV_RISK[f.severity] / 100) * Math.max(0.05, Math.min(f.confidence || 0.5, 1));
      rem *= 1 - c; top = Math.max(top, SEV_RISK[f.severity]);
    }
    return Math.round(Math.max((1 - rem) * 100, top * 0.95));
  }

  function catalogLookup(host) {
    if (!RULES || !RULES.catalog || !host) return null;
    host = host.toLowerCase().replace(/\.$/, "");
    for (const s of RULES.catalog) for (const d of s.domains) {
      if (host === d || host.endsWith("." + d)) return s;
    }
    return null;
  }

  return { load, inspect, inspectInjection, inspectDlp, canonicalize, views, catalogLookup, get rules() { return RULES; } };
})();

if (typeof module !== "undefined" && module.exports) module.exports = Lump;
if (typeof self !== "undefined") self.Lump = Lump;
