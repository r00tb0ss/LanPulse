// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* First-run setup guide: a few short steps to get the important things switched on. Shown once on a fresh install
   (existing installs are marked done), and any time from Settings > Setup guide. Every step can be skipped. */
(() => {
  let step = 0, cfg = null;
  const host = () => location.hostname;
  let router = "unifi";
  const ROUTERS = {
    unifi: {n: "UniFi (UDM, UCG, Gateway)", h: "Settings &gt; CyberSecure / System Logging &gt; SIEM server (syslog), then turn on logging for your firewall rules. One-click blocking is also supported on UniFi."},
    pfsense: {n: "pfSense / OPNsense", h: "Status &gt; System Logs &gt; Settings (pfSense) or System &gt; Settings &gt; Logging &gt; Remote (OPNsense): enable remote logging, enter the server above and include firewall events. Make sure your firewall rules have <b>Log</b> ticked."},
    openwrt: {n: "OpenWrt / DD-WRT / Linux (iptables, nftables)", h: "OpenWrt: System &gt; Logging &gt; External log server, port above, protocol UDP. Add LOG rules for the traffic you want to see (for example drops on WAN). Plain Linux: use a netfilter LOG rule and rsyslog forwarding."},
    mikrotik: {n: "MikroTik RouterOS", h: "System &gt; Logging: add an action of type <b>remote</b> to the address above, and a rule for topic <b>firewall</b>. On the firewall rules you want to see, set action <b>log</b> (or add a log rule) with a prefix containing <b>drop</b> for blocked traffic."},
    fortinet: {n: "Fortinet, SonicWall, Sophos, WatchGuard", h: "Enable remote syslog to the server above and log traffic/firewall events in key=value format (srcip, dstip, dstport, action). Blocked traffic should carry action=deny or drop."},
    other: {n: "Another router or firewall", h: "Look for <b>remote syslog</b> or <b>log server</b> in the router's settings, enter the server and port above, and turn on firewall logging for blocked and allowed traffic. LanPulse understands iptables/nftables, pfSense/OPNsense, MikroTik, UniFi, key=value and JSON formats."},
  };

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
    {t: "See attacks on your network", i: "fa-earth-americas", body: () => {
      const port = (cfg.threats && cfg.threats.syslog_port) || 514;
      const R = ROUTERS[router] || ROUTERS.other;
      return `
      <p>To fill the attack map and catch devices talking to botnets, send your router's firewall log to LanPulse
      as <b>syslog (UDP)</b>:</p>
      <ul><li>Server: <code>${esc(host())}</code> &nbsp; port: <code>${port}</code></li></ul>
      <label class="wiz-rt">Your router
        <select id="wizRouter">${Object.entries(ROUTERS).map(([k, v]) => `<option value="${k}" ${k === router ? "selected" : ""}>${esc(v.n)}</option>`).join("")}</select></label>
      <p class="wiz-how">${R.h}</p>
      <p class="muted">Without this LanPulse still maps your devices, scans them and runs the honeypot.</p>`;
    }},
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
    const rs = $("wizRouter"); if (rs) rs.onchange = () => { router = rs.value; draw(); };
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
