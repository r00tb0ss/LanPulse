/* AI Security Analyst drawer: read-only Q&A over LanPulse's own data. Providers: Ollama, OpenAI-compatible, Anthropic. */
(() => {
  let st = null, busy = false;
  const PROV = {
    ollama: ["Ollama (local)", "http://localhost:11434", "llama3.1"],
    openai: ["OpenAI-compatible (LM Studio, Groq, OpenRouter, OpenAI…)", "http://localhost:1234/v1", "gpt-4o-mini"],
    anthropic: ["Anthropic (Claude)", "https://api.anthropic.com", "claude-sonnet-5-5"],
  };
  const open = () => $("aiDrawer").classList.contains("hidden") === false;

  const SUGG_KEY = "lp_ai_sugg";           // suggested questions are hidden until asked for
  const suggOpen = () => { try { return localStorage.getItem(SUGG_KEY) === "1"; } catch (e) { return false; } };
  function renderSugg() {
    const box = $("aiSugg");
    if (!st || !st.enabled) { box.innerHTML = ""; return; }
    const on = suggOpen();
    box.innerHTML = `<button type="button" class="ai-chip" id="aiSuggTog">${on ? "Hide" : "Show"} suggested questions</button>`
      + (on ? (st.suggested || []).map(q => `<button type="button" class="ai-chip ai-q">${esc(q)}</button>`).join("") : "");
    $("aiSuggTog").onclick = () => { try { localStorage.setItem(SUGG_KEY, on ? "0" : "1"); } catch (e) { /* private mode */ } renderSugg(); };
    box.querySelectorAll(".ai-q").forEach(b => b.onclick = () => ask(b.textContent));
  }

  async function refresh() {
    st = await api("/api/ai", "GET");
    if (!st) return;
    $("aiSub").textContent = st.enabled ? `${st.model} · ${st.local ? "runs on your network" : "cloud provider"}`
                                        : "explains your network — never changes anything";
    renderSugg();
    if (!st.enabled) { showSetup(); if (!$("aiLog").children.length) note("The analyst is off. Choose a provider above to turn it on."); }
  }

  function note(text, cls) {
    const d = document.createElement("div"); d.className = "ai-msg " + (cls || "sys"); d.textContent = text;
    $("aiLog").appendChild(d); $("aiLog").scrollTop = $("aiLog").scrollHeight; return d;
  }

  async function ask(q) {
    q = (q || "").trim();
    if (!q || busy) return;
    if (!st || !st.enabled) { showSetup(); return; }
    busy = true; $("aiSend").disabled = true; $("aiQ").value = "";
    note(q, "me");
    const wait = note("Thinking…", "sys wait");
    const r = await api("/api/ai/ask", "POST", {question: q}, true);
    wait.remove();
    if (r && r.answer) {
      const m = note(r.answer, "bot");
      const f = document.createElement("div"); f.className = "ai-foot";
      f.textContent = `${r.model} · ${r.local ? "answered on your network" : "network summary was sent to " + r.provider} · read-only`;
      m.appendChild(f);
    } else note((r && r.error) || "No answer.", "err");
    busy = false; $("aiSend").disabled = false; $("aiQ").focus();
  }

  function showSetup() {
    const box = $("aiSetup"); box.classList.remove("hidden");
    const cur = (st && st.provider) || "ollama";
    box.innerHTML = `
      <label>Provider<select id="aiProv">${Object.entries(PROV).map(([k, v]) => `<option value="${k}" ${k === cur ? "selected" : ""}>${esc(v[0])}</option>`).join("")}</select></label>
      <label>Server address<input id="aiBase" placeholder=""></label>
      <label>Model<input id="aiModel" placeholder=""></label>
      <label id="aiKeyRow">API key<input id="aiKey" type="password" autocomplete="off" placeholder="stored on this box, never shown again"></label>
      <div class="ai-warn" id="aiWarn"></div>
      <div class="btns"><button class="btn" id="aiTest" type="button">Test</button>
        <button class="btn primary" id="aiSave" type="button">Save &amp; enable</button>
        <button class="btn" id="aiOff" type="button">Turn off</button></div>
      <div class="muted" id="aiMsg" style="font-size:12px"></div>`;
    const sync = () => {
      const p = $("aiProv").value, d = PROV[p];
      $("aiBase").placeholder = d[1]; $("aiModel").placeholder = d[2];
      $("aiKeyRow").style.display = p === "ollama" ? "none" : "";
      $("aiWarn").innerHTML = p === "anthropic"
        ? `<i class="fa-solid fa-triangle-exclamation"></i> A summary of your network (device names, IPs, open ports, vulnerabilities) is sent to this provider with each question.`
        : p === "openai" ? `<i class="fa-solid fa-circle-info"></i> Point this at a local server to keep data on your network; a hosted service receives a summary of your network with each question.`
        : `<i class="fa-solid fa-lock"></i> Nothing leaves your network.`;
    };
    $("aiProv").onchange = () => { $("aiBase").value = ""; $("aiModel").value = ""; sync(); };
    sync();
    const form = () => ({provider: $("aiProv").value, base_url: $("aiBase").value.trim(), model: $("aiModel").value.trim(), api_key: $("aiKey").value});
    $("aiTest").onclick = async () => {
      $("aiMsg").textContent = "Testing…";
      const r = await api("/api/ai/test", "POST", form(), true);
      $("aiMsg").textContent = r ? r.message : "Test failed."; $("aiMsg").style.color = r && r.ok ? "var(--green)" : "var(--red)";
    };
    $("aiSave").onclick = async () => {
      const f = form(); if (!f.api_key) delete f.api_key;
      if (await api("/api/settings", "POST", {ai: {...f, enabled: true}})) { toast("Analyst enabled"); box.classList.add("hidden"); $("aiLog").innerHTML = ""; refresh(); }
    };
    $("aiOff").onclick = async () => {
      if (await api("/api/settings", "POST", {ai: {enabled: false}})) { toast("Analyst turned off"); refresh(); }
    };
  }

  function toggle(force) {
    const d = $("aiDrawer"), show = force === undefined ? d.classList.contains("hidden") : force;
    d.classList.toggle("hidden", !show); d.setAttribute("aria-hidden", String(!show));
    if (show) { refresh().then(() => $("aiQ").focus()); }
  }
  document.addEventListener("DOMContentLoaded", () => {
    $("btnAi").onclick = () => toggle();
    $("aiClose").onclick = () => toggle(false);
    $("aiCfgBtn").onclick = () => { $("aiSetup").classList.contains("hidden") ? showSetup() : $("aiSetup").classList.add("hidden"); };
    $("aiForm").onsubmit = (e) => { e.preventDefault(); ask($("aiQ").value); };
    $("aiQ").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask($("aiQ").value); } };
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && open()) toggle(false); });
  });
})();
