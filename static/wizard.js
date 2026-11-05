// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* First-run setup guide: a few short steps to get the important things switched on. Shown once on a fresh install
   (existing installs are marked done), and any time from Settings > Setup guide. Every step can be skipped. */
(() => {
  let step = 0, cfg = null;
  const host = () => location.hostname;

  const STEPS = [
    {t: "Welcome to LanPulse", i: "fa-hand-wave", body: () => `
      <p>LanPulse watches your network, shows who is attacking it, and finds devices that could be broken into.
      This 2-minute guide switches on the important parts. You can skip any step and come back from
      <b>Settings &gt; Setup guide</b>.</p>
      <div class="wiz-facts"><div><b>${esc(meta.subnet || "—")}</b><span>your network</span></div>
        <div><b>${devices.size}</b><span>devices found so far</span></div>
        <div><b>${esc(meta.gateway || "—")}</b><span>router</span></div></div>
      <p class="muted">Anything new on your network shows a red dashed ring until you mark it as trusted.</p>`},
    {t: "Get alerts", i: "fa-bell", body: () => `
      <p>Choose where LanPulse should reach you when something serious happens: ntfy push, Telegram, email,
      Discord/Slack webhook or IRC.</p>
      <div class="btns"><button class="btn primary" data-go="channels"><i class="fa-solid fa-bell"></i>Set up alerts</button></div>`},
    {t: "See attacks on your network", i: "fa-earth-americas", body: () => `
      <p>To fill the attack map and catch devices talking to botnets, send your router's firewall log to LanPulse:</p>
      <ul><li>Syslog server: <code>${esc(host())}</code> port <code>514</code> (UDP)</li>
      <li><b>UniFi:</b> Settings &gt; CyberSecure / System Logging &gt; SIEM server (syslog), then enable firewall logging on your rules.</li>
      <li><b>Other routers:</b> enable remote syslog to the address above and log blocked and allowed traffic.</li></ul>
      <p class="muted">Without this LanPulse still maps your devices, scans them and runs the honeypot.</p>`},
    {t: "Turn on the honeypot", i: "fa-jar", body: () => `
      <p>The honeypot runs decoy Telnet, FTP, SMB, RDP and MySQL services. No real device should ever touch them, so
      <b>any hit is a warning</b>, and a hit from inside your network means a device is likely compromised.
      It never gives anyone a shell or real access.</p>
      <label class="chk"><input type="checkbox" id="wizPot" ${cfg.honeypot.enabled ? "checked" : ""}>Turn the honeypot on</label>
      <p class="muted">The decoys use ports that must be free on this server. You can change which ones in the Honeypot tab.</p>`,
     save: async () => { const on = $("wizPot")?.checked; if (on !== undefined && on !== cfg.honeypot.enabled)
       await api("/api/settings", "POST", {honeypot: {enabled: on}}); }},
    {t: "Find vulnerabilities accurately", i: "fa-bug", body: () => `
      <p>LanPulse's built-in scan (nmap) is a good first pass. For accurate results that find exploitable services
      banner-matching misses, install <b>OpenVAS</b> (Greenbone). LanPulse can install and run it for you. It needs about
      4 GB of RAM and 15 GB of disk, and downloads a vulnerability feed on first start.</p>
      <p>Tip: for lab machines turn on <b>Thorough scan</b> in a device's panel.</p>
      <div class="btns"><button class="btn primary" data-go="scanner"><i class="fa-solid fa-shield-halved"></i>Set up OpenVAS</button></div>`},
    {t: "Ask an AI about your network", i: "fa-wand-magic-sparkles", body: () => `
      <p>The <b>AI Security Analyst</b> answers questions like "what should I fix first?" using only your own network data.
      It can't change anything. Use a local model (Ollama) so nothing leaves your network, or any OpenAI-compatible
      server or Anthropic.</p>
      <div class="btns"><button class="btn primary" data-ai="1"><i class="fa-solid fa-wand-magic-sparkles"></i>Choose an AI</button></div>`},
    {t: "You're set", i: "fa-circle-check", body: () => `
      <p>LanPulse is watching. Things worth doing next:</p>
      <ul><li>Open the <b>Network</b> tab and mark the devices you recognise as <b>trusted</b>.</li>
      <li>Put a <b>login</b> on the dashboard (Settings &gt; Login) and use HTTPS.</li>
      <li>Run a <b>Thorough scan</b> on servers and lab machines, then check the Vulnerabilities tab.</li></ul>`},
  ];

  function draw() {
    const s = STEPS[step], last = step === STEPS.length - 1;
    $("wizCard").innerHTML = `
      <div class="wiz-dots">${STEPS.map((_, i) => `<span class="${i === step ? "on" : i < step ? "done" : ""}"></span>`).join("")}</div>
      <h3 id="wizTitle"><i class="fa-solid ${s.i}"></i>${esc(s.t)}</h3>
      <div class="wiz-body">${s.body()}</div>
      <div class="wiz-foot">
        <button class="btn" id="wizSkipAll">${last ? "" : "Skip guide"}</button>
        <span style="flex:1"></span>
        ${step > 0 ? `<button class="btn" id="wizBack">Back</button>` : ""}
        <button class="btn primary" id="wizNext">${last ? "Finish" : "Next"}</button>
      </div>`;
    $("wizSkipAll").onclick = () => finish();
    $("wizBack") && ($("wizBack").onclick = () => { step--; draw(); });
    $("wizNext").onclick = async () => { if (s.save) await s.save(); if (last) finish(); else { cfg = await api("/api/settings", "GET") || cfg; step++; draw(); } };
    $("wizCard").querySelectorAll("[data-go]").forEach((b) => b.onclick = async () => {
      await finish(false); setTab = b.dataset.go; await openSettings();
    });
    $("wizCard").querySelectorAll("[data-ai]").forEach((b) => b.onclick = async () => {
      await finish(false); $("btnAi").click(); setTimeout(() => $("aiCfgBtn")?.click(), 400);
    });
    $("wizNext").focus();
  }

  async function finish(done = true) {
    $("wiz").classList.add("hidden");
    await api("/api/settings", "POST", {wizard: {done: true}}, true);
  }

  async function start() {
    cfg = await api("/api/settings", "GET");
    if (!cfg) return;
    step = 0; $("wiz").classList.remove("hidden"); draw();
  }

  window.addEventListener("load", async () => {
    $("btnWizard")?.addEventListener("click", () => { closeSettings(); start(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("wiz").classList.contains("hidden")) finish(); });
    setTimeout(async () => {
      const s = await api("/api/settings", "GET", null, true);
      if (s && s.wizard && s.wizard.done === false) { cfg = s; step = 0; $("wiz").classList.remove("hidden"); draw(); }
    }, 1500);
  });
})();
