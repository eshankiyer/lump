/*
 * Lump background service worker.
 *
 * Loads the exported rule set, holds configuration, receives findings from
 * content scripts, keeps per-tab badge counts, and (optionally) forwards audit
 * events to a Lump control plane for fleet-wide visibility.
 */

const DEFAULTS = {
  enabled: true,
  mode: "warn",            // warn | block | monitor
  scanPrompts: true,        // inspect what the user sends (DLP egress + injection)
  scanResponses: true,      // inspect model output (indirect injection / beacons)
  controlPlaneUrl: "",     // e.g. http://127.0.0.1:8080  (POSTs to /api/events)
  controlPlaneKey: "",
};

let RULES = null;
const tabStats = new Map();

async function loadRules() {
  try {
    const res = await fetch(chrome.runtime.getURL("rules.json"));
    RULES = await res.json();
  } catch (e) {
    RULES = { version: 1, injection: [], dlp: [], signatures: [], catalog: [], normalize: {} };
  }
}

async function getConfig() {
  const stored = await chrome.storage.local.get("config");
  return Object.assign({}, DEFAULTS, stored.config || {});
}

loadRules();

chrome.runtime.onInstalled.addListener(async () => {
  const cfg = await getConfig();
  await chrome.storage.local.set({ config: cfg });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "getRules") {
      if (!RULES) await loadRules();
      sendResponse({ rules: RULES, config: await getConfig() });
    } else if (msg.type === "finding") {
      await handleFinding(msg, sender);
      sendResponse({ ok: true });
    } else if (msg.type === "getStats") {
      sendResponse({ stats: tabStats.get(msg.tabId) || { blocked: 0, warned: 0, redacted: 0 } });
    }
  })();
  return true; // async
});

async function handleFinding(msg, sender) {
  const tabId = sender.tab && sender.tab.id;
  if (tabId != null) {
    const s = tabStats.get(tabId) || { blocked: 0, warned: 0, redacted: 0 };
    if (msg.action === "block") s.blocked++;
    else if (msg.action === "redact") s.redacted++;
    else if (msg.action === "warn") s.warned++;
    tabStats.set(tabId, s);
    const total = s.blocked + s.redacted + s.warned;
    if (total > 0) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: s.blocked ? "#f85149" : "#d29922" });
      chrome.action.setBadgeText({ tabId, text: String(total) });
    }
  }
  const cfg = await getConfig();
  if (cfg.controlPlaneUrl) {
    try {
      await fetch(cfg.controlPlaneUrl.replace(/\/$/, "") + "/v1/events", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" },
          cfg.controlPlaneKey ? { Authorization: "Bearer " + cfg.controlPlaneKey } : {}),
        body: JSON.stringify({
          source: "browser", action: msg.action, risk: msg.risk,
          destination: hostOf(sender.tab && sender.tab.url), rule_ids: msg.ruleIds || [],
          direction: msg.direction || "input",
        }),
      });
    } catch (e) { /* control plane optional; ignore */ }
  }
}

// Only the hostname leaves the browser — never the full URL (it can carry
// conversation ids) and never the prompt text itself.
function hostOf(url) { try { return new URL(url).hostname; } catch (e) { return ""; } }

chrome.tabs.onRemoved.addListener((tabId) => tabStats.delete(tabId));
