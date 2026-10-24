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
  let model = null;
  try {
    const buf = await (await fetch(chrome.runtime.getURL("models/injection-v1.lumpml"))).arrayBuffer();
    model = await LumpML.loadModel(buf);
  } catch (e) { /* rules only */ }
  const tester = document.getElementById("tester");
  const result = document.getElementById("result");
  function run() {
    const text = tester.value;
    if (!text.trim()) { result.textContent = "—"; return; }
    const v = Lump.inspect(text, { direction: document.getElementById("direction").value, model });
    result.textContent = "action=" + v.action + "  risk=" + v.risk + (model ? "" : "  (ML model not loaded)") + "\n" +
      v.findings.map((f) => `  [${f.severity}] ${f.rule_id} ${f.title} (${f.confidence})`).join("\n");
  }
  tester.addEventListener("input", run);
  document.getElementById("direction").addEventListener("change", run);
})();
