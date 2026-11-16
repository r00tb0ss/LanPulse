// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Settings > Scanner: install and use OpenVAS (Greenbone) for accurate vulnerability scanning. */

let ovPoll = null;
function ovOpen() { return !$("settings").classList.contains("hidden") && setTab === "scanner"; }

async function renderScanner(body) {
  clearInterval(ovPoll);
  body.innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Checking…</div>`;
  const s = await api("/api/openvas", "GET");
  if (!ovOpen()) return;
  if (!s) { body.innerHTML = `<p class="hint">The scanner isn't available here.</p>`; return; }
  drawScanner(body, s);
  const busy = s.helper.state === "installing" || s.helper.state === "queued" || (s.installed && !s.ready) ||
    s.scans.some((x) => ["Requested", "Queued", "Running", "New"].includes(x.status));
  if (busy) ovPoll = setInterval(async () => {
    if (!ovOpen()) { clearInterval(ovPoll); return; }
    const n = await api("/api/openvas", "GET", null, true);
    if (n && ovOpen()) drawScanner(body, n);
  }, 8000);
}

function drawScanner(body, s) {
  const h = s.helper || {};
  const installing = h.state === "installing" || h.state === "queued";
  const blocked = !s.helper_installed ? "helper" : !s.login ? "login" : "";
  const devs = [...devices.values()].filter((d) => d.ip && d.online && !d.is_self);
  const scanOf = Object.fromEntries((s.scans || []).map((x) => [x.ip, x]));
  const running = (x) => x && ["Requested", "Queued", "Running", "New"].includes(x.status);
  body.innerHTML = `
    <div class="upd-head"><i class="fa-solid fa-shield-halved"></i><div><b>OpenVAS vulnerability scanner</b>
      <span>${s.ready ? "ready" : s.installed ? "installed, loading its feed" : "not installed"}</span></div></div>
    <p class="hint">nmap can only guess from banners. <b>OpenVAS</b> (Greenbone Community Edition) runs tens of thousands of
      real vulnerability tests, so it finds exploitable services that LanPulse's built-in checks miss. LanPulse runs its
      normal non-destructive scan and shows results in the Vulnerabilities tab; confirmed ones rank first.</p>
    ${blocked === "helper" && !s.installed ? `<div class="upd-note warn"><i class="fa-solid fa-circle-info"></i><div>
      <b>One more terminal install first.</b> The OpenVAS helper ships with this version. Run once on the Ubuntu box:
      <code>unzip -o lanpulse.zip -d ~ &amp;&amp; cd ~/lanpulse &amp;&amp; sudo ./install.sh --upgrade</code></div></div>` : ""}
    ${blocked === "login" && !s.installed ? `<div class="upd-note warn"><i class="fa-solid fa-lock"></i><div>
      <b>Set a login first.</b> Installing runs with administrator rights, so LanPulse only allows it when the dashboard
      is password protected. <button class="linkbtn" id="ovToLogin">Go to Login</button></div></div>` : ""}
    ${installing ? `<div class="upd-note busy"><i class="fa-solid fa-spinner fa-spin"></i><div><b>${esc(h.message || "Working…")}</b>
      <span>This runs in the background and can take 10 to 30 minutes. You can close this window.</span></div></div>` : ""}
    ${h.state === "failed" ? `<div class="upd-note bad"><i class="fa-solid fa-triangle-exclamation"></i><div><b>${esc(h.message)}</b></div></div>` : ""}
    ${h.state === "done" && !installing && !s.ready ? `<div class="upd-note ok"><i class="fa-solid fa-circle-check"></i><div><b>${esc(h.message)}</b></div></div>` : ""}
    ${s.installed && !s.ready ? `<div class="upd-note busy"><i class="fa-solid fa-spinner fa-spin"></i><div><b>Waiting for OpenVAS to finish loading</b>
      <span>${esc(s.message || "")} The first load of the vulnerability feed takes 30 to 90 minutes.</span></div></div>` : ""}
    ${s.ready ? `<div class="upd-note ok"><i class="fa-solid fa-circle-check"></i><div><b>OpenVAS is ready.</b></div></div>` : ""}
    ${(!s.installed || /login doesn't match/.test(s.message || "")) && !installing ? `<div class="upd-staged"><div><b>Install OpenVAS on this server</b>
        <span class="muted">Needs about 4 GB of RAM, 15 GB of disk and internet access. It installs Docker (if missing) and the
        official Greenbone containers, and keeps their web page private to this machine.</span></div>
        <div class="btns"><button class="btn primary" id="ovInstall" ${blocked ? "disabled" : ""}><i class="fa-solid fa-download"></i>Install OpenVAS</button></div></div>` : ""}
    ${s.installed ? `<div class="form chan-fields" style="padding:0;margin-top:10px">
        <label class="chk full"><input type="checkbox" id="ovOn" ${s.enabled ? "checked" : ""}>Use OpenVAS for vulnerability scans</label>
        <label class="chk full"><input type="checkbox" id="ovAuto" ${s.auto ? "checked" : ""}>Rescan each online device automatically every week (one at a time; it's heavy on the network and the server)</label>
      </div>
      <h4 style="margin:14px 0 6px">Scan devices</h4>
      <div class="btns"><button class="btn primary" id="ovAll" ${s.ready && s.enabled ? "" : "disabled"}><i class="fa-solid fa-shield-halved"></i>Scan all online devices</button></div>
      <div class="ov-list">${devs.map((d) => { const x = scanOf[d.ip]; return `<div class="ov-row">
        <span><b>${esc(d.name || d.hostname || d.ip)}</b> <span class="muted">${esc(d.ip)}</span></span>
        <span class="muted">${x ? (running(x) ? `${esc(x.status)} ${x.progress || 0}%` : x.error ? esc(x.error) : x.finished ? `${x.count} findings · ${esc(ago(x.finished))}` : esc(x.status || "")) : "not scanned"}</span>
        <button class="btn sm" data-ip="${esc(d.ip)}" ${s.ready && s.enabled && !running(x) ? "" : "disabled"}>Scan</button></div>`; }).join("") || `<p class="hint">No online devices yet.</p>`}</div>
      <div class="btns" style="margin-top:12px"><button class="btn danger sm" id="ovRemove" ${blocked || installing ? "disabled" : ""}>Remove OpenVAS</button></div>
      <p class="hint" style="margin-top:8px">Only scan devices you own. Scans send many probe packets and can slow fragile or old devices.</p>` : ""}
    ${s.log ? `<details class="upd-log" ${installing || h.state === "failed" ? "open" : ""}><summary>Installer log</summary><pre>${esc(s.log)}</pre></details>` : ""}`;

  $("ovToLogin")?.addEventListener("click", () => { setTab = "account"; renderSettings(); });
  $("ovInstall")?.addEventListener("click", async () => {
    if (!confirm("Install OpenVAS? This downloads several GB, installs Docker if needed, and runs the official Greenbone containers on this server.")) return;
    const r = await api("/api/openvas/install", "POST", {action: "install"});
    if (r) { toast("Installing OpenVAS in the background"); renderScanner(body); }
  });
  $("ovRemove")?.addEventListener("click", async () => {
    if (!confirm("Remove OpenVAS and all of its data from this server?")) return;
    const r = await api("/api/openvas/install", "POST", {action: "remove"});
    if (r) { toast("Removing OpenVAS"); renderScanner(body); }
  });
  const save = async () => {
    await api("/api/settings", "POST", {openvas: {enabled: $("ovOn").checked, auto: $("ovAuto").checked}});
    renderScanner(body);
  };
  $("ovOn")?.addEventListener("change", save);
  $("ovAuto")?.addEventListener("change", save);
  $("ovAll")?.addEventListener("click", async () => {
    const r = await api("/api/openvas/scan", "POST", {all: true});
    if (r) { toast(`Started ${r.started} scan${r.started === 1 ? "" : "s"}`); renderScanner(body); }
  });
  body.querySelectorAll("[data-ip]").forEach((b) => b.onclick = async () => {
    const r = await api("/api/openvas/scan", "POST", {ip: b.dataset.ip});
    if (r) { toast("Scan started"); renderScanner(body); }
  });
}


/* Settings > YARA: install/repair the engine and manage the verified Forge Core rule feed. */
let yaraSettingsPoll = null;
function yaraSettingsOpen() {
  return !$("settings").classList.contains("hidden") && setTab === "yara";
}
async function renderYaraSettings(body) {
  clearInterval(yaraSettingsPoll);
  body.innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Checking YARA…</div>`;
  const [engine, task] = await Promise.all([
    api("/api/honeypot/yara/status", "GET"),
    api("/api/yara/manage/status", "GET")
  ]);
  if (!yaraSettingsOpen()) return;
  if (!engine || !task) {
    body.innerHTML = `<p class="hint">Couldn't retrieve YARA status. Check the LanPulse service and try again.</p>`;
    return;
  }
  drawYaraSettings(body, engine, task);
}
function drawYaraSettings(body, engine, task) {
  const running = ["queued", "installing"].includes(task.state);
  const available = !!engine.available;
  const helper = !!task.helper_installed;
  const login = !!task.login;
  const schedule = !!task.schedule_enabled;
  const managed = engine.managed || {};
  const errors = [...(engine.errors || [])];
  if (managed.last_error) errors.push(managed.last_error);
  const stamp = (v) => v ? esc(v.replace("T", " ").replace("Z", " UTC")) : "Not available";
  body.innerHTML = `
    <div class="upd-head"><i class="fa-solid fa-dna"></i><div><b>YARA malware rule scanner</b>
      <span>${available ? "engine available" : "engine unavailable"} · ${Number(engine.loaded || 0).toLocaleString()} rule files loaded</span></div></div>
    <p class="hint">YARA statically checks captured honeypot files against detection rules. LanPulse never executes captured samples.
      New installations install the engine and managed YARA Forge Core rules automatically. Use these controls to install, repair, or update them later.</p>
    ${!helper ? `<div class="upd-note warn"><i class="fa-solid fa-circle-info"></i><div><b>Settings management helper not installed.</b>
      Run <code>sudo ./install.sh --upgrade</code> on the LanPulse server once. This installs the restricted root helper and systemd watcher.</div></div>` : ""}
    ${!login ? `<div class="upd-note warn"><i class="fa-solid fa-lock"></i><div><b>Set a dashboard login first.</b>
      YARA setup changes system packages and services. These administrator actions are available only when LanPulse has a password-protected dashboard.</div></div>` : ""}
    ${task.message ? `<div class="upd-note ${task.state === "failed" ? "bad" : task.state === "done" ? "ok" : "busy"}"><i class="fa-solid fa-circle-info"></i><div><b>${esc(task.message)}</b></div></div>` : ""}
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-shield-halved ci"></i><div class="txt"><b>Engine and managed rules</b>
      <small>${esc(managed.package || "YARA Forge Core")} · ${esc(managed.version || "not installed")}</small></div></div>
      <div class="chan-fields">
        <div><b>Engine</b><div class="muted">${available ? "Available" : "Not available"}</div></div>
        <div><b>Rules loaded</b><div class="muted">${Number(engine.loaded || 0).toLocaleString()} files · ${Number(managed.rule_count || 0).toLocaleString()} rules in package</div></div>
        <div><b>Rule files</b><div class="muted">${Number(engine.managed_files || 0)} managed · ${Number(engine.custom_files || 0)} custom</div></div>
        <div><b>Last updated</b><div class="muted">${stamp(managed.updated_at)}</div></div>
        <div><b>Last checked</b><div class="muted">${stamp(managed.checked_at)}</div></div>
        <div><b>Weekly updates</b><div class="muted">${schedule ? "Enabled" : "Disabled"}</div></div>
      </div>
      ${errors.length ? `<div class="upd-note bad" style="margin-top:10px"><b>Reported issues</b><div>${errors.map(esc).join("<br>")}</div></div>` : `<div class="upd-note ok" style="margin-top:10px"><i class="fa-solid fa-circle-check"></i><b>No YARA loading errors reported.</b></div>`}
      <div class="btns" style="margin-top:12px">
        <button class="btn primary" id="yaraInstall" ${!helper || !login || running ? "disabled" : ""}><i class="fa-solid fa-screwdriver-wrench"></i>Install / Repair</button>
        <button class="btn" id="yaraUpdate" ${!helper || !login || running || !available ? "disabled" : ""}><i class="fa-solid fa-rotate"></i>Update rules now</button>
      </div>
    </div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-calendar-week ci"></i><div class="txt"><b>Automatic rule updates</b>
      <small>Managed YARA Forge Core rules are checked weekly by a systemd timer.</small></div></div>
      <div class="btns"><button class="btn" id="yaraSchedule" ${!helper || !login || running ? "disabled" : ""}>
        ${schedule ? "Disable weekly updates" : "Enable weekly updates"}</button></div>
    </div>
    ${task.log ? `<details class="upd-log" ${task.state === "failed" ? "open" : ""}><summary>YARA setup log</summary><pre>${esc(task.log)}</pre></details>` : ""}
    <p class="hint">Custom rules are kept separately under <code>/opt/lanpulse/data/yara-rules/</code>. Repairing or updating managed rules does not replace custom rules or the last known-good managed package if validation fails.</p>
  `;
  const send = async (action, prompt) => {
    if (prompt && !confirm(prompt)) return;
    const result = await api("/api/yara/manage", "POST", {action});
    if (result) {
      toast("YARA task queued");
      renderYaraSettings(body);
    }
  };
  $("yaraInstall")?.addEventListener("click", () => send("install",
    "Install or repair yara-python, validate the managed YARA Forge Core rules, and enable weekly updates?"));
  $("yaraUpdate")?.addEventListener("click", () => send("update",
    "Download and validate the latest YARA Forge Core rule package now?"));
  $("yaraSchedule")?.addEventListener("click", () => send(schedule ? "schedule_off" : "schedule_on",
    schedule ? "Disable automatic weekly YARA rule updates?" : "Enable automatic weekly YARA rule updates?"));
  if (running) yaraSettingsPoll = setInterval(() => {
    if (yaraSettingsOpen()) renderYaraSettings(body);
    else clearInterval(yaraSettingsPoll);
  }, 5000);
}
