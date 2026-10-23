/*
 * Lump content script.
 *
 * Runs on known AI web apps. Two jobs:
 *   1. Egress protection — inspect what the user is about to send (the prompt
 *      box) for secrets/PII and obvious self-injected jailbreaks. On a block
 *      policy it intercepts the Enter key / send click and shows a warning.
 *   2. Indirect-injection & beacon protection — inspect model responses as they
 *      render for hidden instructions and data-exfiltration markdown/images.
 *
 * All detection is local (detector.js). Nothing is sent anywhere unless the
 * user configures a control-plane URL in options.
 */

(async function () {
  const { rules, config } = await chrome.runtime.sendMessage({ type: "getRules" });
  if (!rules || !config || !config.enabled) return;
  Lump.load(rules);

  const host = location.hostname;
  const service = Lump.catalogLookup(host);
  let lastPromptWarned = "";

  function toast(title, detail, color) {
    const el = document.createElement("div");
    el.style.cssText =
      "position:fixed;z-index:2147483647;right:16px;bottom:16px;max-width:360px;padding:12px 14px;" +
      "border-radius:10px;font:13px/1.4 system-ui,sans-serif;color:#fff;box-shadow:0 8px 28px rgba(0,0,0,.35);" +
      "background:" + color + ";";
    el.innerHTML = "<strong style='display:block;margin-bottom:3px'>" + esc(title) + "</strong>" +
      "<span style='opacity:.92'>" + esc(detail) + "</span>" +
      "<span style='opacity:.6;display:block;margin-top:5px;font-size:11px'>Lump</span>";
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 7000);
  }
  function esc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

  function report(action, verdict, direction) {
    chrome.runtime.sendMessage({
      type: "finding", action, risk: verdict.risk, direction,
      ruleIds: verdict.findings.map((f) => f.rule_id).slice(0, 8),
    });
  }

  // --- 1. prompt egress ---
  function promptText() {
    const el = document.activeElement;
    if (!el) return { text: "", el: null };
    if (el.tagName === "TEXTAREA") return { text: el.value, el };
    if (el.isContentEditable) return { text: el.innerText, el };
    const ta = document.querySelector("textarea, [contenteditable='true']");
    return { text: ta ? (ta.value || ta.innerText || "") : "", el: ta };
  }

  // Modes: "block" — policy blocks cannot be overridden; "warn" — the first
  // send is held with an explanation and a second send proceeds (coaching);
  // "monitor" — never interferes, only records.
  function guardSend(ev) {
    if (!config.scanPrompts) return;
    const { text } = promptText();
    if (!text || text.length < 3) return;
    const verdict = Lump.inspect(text, { untrusted: false });
    if (verdict.action === "allow") return;
    const top = verdict.findings[0] || {};
    const what = (top.title || "Sensitive content") + " (risk " + verdict.risk + ")";

    if (config.mode === "monitor") { report(verdict.action, verdict, "input"); return; }
    if (verdict.action === "block" && config.mode === "block") {
      ev.preventDefault(); ev.stopImmediatePropagation();
      report("block", verdict, "input");
      toast("Send blocked by policy", what + ". Remove the flagged content to continue.", "#f85149");
      return;
    }
    if (text === lastPromptWarned) return; // user saw the warning and chose to continue
    ev.preventDefault(); ev.stopImmediatePropagation();
    lastPromptWarned = text;
    report(verdict.action === "block" ? "warn" : verdict.action, verdict, "input");
    toast("Review before sending", what + ". Press send again to continue anyway.", "#d29922");
  }

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) guardSend(ev);
  }, true);
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest && ev.target.closest("button,[role=button]");
    if (t && /send|submit/i.test(t.getAttribute("aria-label") || t.dataset.testid || t.textContent || "")) guardSend(ev);
  }, true);

  // --- 2. response inspection ---
  const scanned = new WeakSet();
  function scanResponses() {
    if (!config.scanResponses) return;
    const nodes = document.querySelectorAll(
      "[data-message-author-role='assistant'], .assistant, [data-testid*='assistant'], .model-response, .markdown"
    );
    for (const node of nodes) {
      if (scanned.has(node)) continue;
      scanned.add(node);
      const text = node.innerText || "";
      if (text.length < 8) { scanned.delete(node); continue; }
      const verdict = Lump.inspect(text, { untrusted: true, dlp: false });
      if (verdict.action === "allow") continue;
      const top = verdict.findings[0] || {};
      report(verdict.action, verdict, "output");
      if (/indirect|beacon|exfil|obfusc/i.test(top.category || "") || verdict.action === "block") {
        node.style.outline = "2px solid #f85149";
        node.title = "Lump: " + (top.title || "suspicious content") + " (risk " + verdict.risk + ")";
        toast("Suspicious AI response", top.title || "Possible indirect prompt injection", "#f85149");
      }
      // Neutralise auto-loading image beacons.
      node.querySelectorAll("img[src*='?'],img[src*='#']").forEach((img) => {
        const svc = Lump.catalogLookup(new URL(img.src, location.href).hostname);
        if (!svc) { img.dataset.lumpBlockedSrc = img.src; img.removeAttribute("src"); }
      });
    }
  }
  const mo = new MutationObserver(() => { clearTimeout(window.__lumpT); window.__lumpT = setTimeout(scanResponses, 400); });
  mo.observe(document.body, { childList: true, subtree: true });
  scanResponses();

  if (service) console.debug("[Lump] active on " + service.name + " (" + service.category + ")");
})();
