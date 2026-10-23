(async function () {
  const FIELDS = ["enabled", "scanPrompts", "scanResponses"];
  const TEXT = ["controlPlaneUrl", "controlPlaneKey"];
  const cfg = (await chrome.storage.local.get("config")).config || {};

  for (const f of FIELDS) document.getElementById(f).checked = cfg[f] !== false;
  for (const f of TEXT) document.getElementById(f).value = cfg[f] || "";
  document.getElementById("mode").value = cfg.mode || "warn";

  document.getElementById("save").addEventListener("click", async () => {
    const c = {};
    for (const f of FIELDS) c[f] = document.getElementById(f).checked;
    for (const f of TEXT) c[f] = document.getElementById(f).value.trim();
    c.mode = document.getElementById("mode").value;
    await chrome.storage.local.set({ config: c });
    const s = document.getElementById("saved"); s.style.opacity = 1; setTimeout(() => (s.style.opacity = 0), 1500);
  });

  // Live tester
  const { rules } = await chrome.runtime.sendMessage({ type: "getRules" });
  Lump.load(rules);
  const tester = document.getElementById("tester");
  const result = document.getElementById("result");
  function run() {
    const text = tester.value;
    if (!text.trim()) { result.textContent = "—"; return; }
    const v = Lump.inspect(text, { untrusted: true });
    result.textContent = "action=" + v.action + "  risk=" + v.risk + "\n" +
      v.findings.map((f) => `  [${f.severity}] ${f.rule_id} ${f.title} (${f.confidence})`).join("\n");
  }
  tester.addEventListener("input", run);
})();
