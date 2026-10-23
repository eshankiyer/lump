(async function () {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const cfg = (await chrome.storage.local.get("config")).config || {};
  document.getElementById("mode").value = cfg.mode || "warn";
  try { document.getElementById("site").textContent = new URL(tab.url).hostname; } catch (e) {}

  if (tab) {
    const { stats } = await chrome.runtime.sendMessage({ type: "getStats", tabId: tab.id });
    document.getElementById("blocked").textContent = stats.blocked;
    document.getElementById("redacted").textContent = stats.redacted;
    document.getElementById("warned").textContent = stats.warned;
  }

  document.getElementById("mode").addEventListener("change", async (e) => {
    const c = (await chrome.storage.local.get("config")).config || {};
    c.mode = e.target.value;
    await chrome.storage.local.set({ config: c });
  });
  document.getElementById("options").addEventListener("click", (e) => {
    e.preventDefault(); chrome.runtime.openOptionsPage();
  });
})();
