// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Settings > System: network, scanning and web server options (formerly /etc/default/lanpulse). */

const SYS_LABEL = {iface: "network interface", subnet: "subnet", workers: "parallel scans", port: "port", https: "HTTPS", host: "listen address"};

async function renderSystem(body) {
  body.innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Loading…</div>`;
  const v = await api("/api/system", "GET");
  if (setTab !== "system") return;
  if (!v) { body.innerHTML = `<p class="hint">Couldn't load system settings.</p>`; return; }
  drawSystem(body, v);
}

function drawSystem(body, v, note = "") {
  const s = v.system, run = v.running;
  const opt = (val, label, cur) => `<option value="${esc(val)}" ${String(cur) === String(val) ? "selected" : ""}>${esc(label)}</option>`;
  const portsList = [[100, "Top 100 (fastest)"], [200, "Top 200"], [1000, "Top 1000 (recommended)"], [5000, "Top 5000"]];
  if (!portsList.some(([n]) => n === +s.top_ports)) portsList.push([+s.top_ports, `Top ${s.top_ports}`]);
  body.innerHTML = `
    <p class="hint">These used to live in <code>/etc/default/lanpulse</code>. Scanning changes apply right away; network and
      web server changes apply when LanPulse restarts.</p>
    ${note ? `<div class="upd-note bad"><i class="fa-solid fa-triangle-exclamation"></i><div>${esc(note)}</div></div>` : ""}
    ${v.pending.length ? `<div class="upd-note warn"><i class="fa-solid fa-rotate"></i><div><b>Restart LanPulse to apply:</b>
      ${v.pending.map((k) => esc(SYS_LABEL[k] || k)).join(", ")}.
      <div class="btns" style="margin-top:8px"><button class="btn primary sm" id="sysRestart"><i class="fa-solid fa-power-off"></i>Restart now</button></div></div></div>` : ""}

    <div class="chan"><div class="chan-head"><i class="fa-solid fa-satellite-dish ci"></i><div class="txt"><b>Scanning</b>
      <small>Applies right away.</small></div></div>
      <div class="chan-fields">
        <label>Check which devices are online every<select id="sy_interval">${[[5, "5 seconds"], [10, "10 seconds"], [20, "20 seconds"], [30, "30 seconds"], [60, "minute"]]
          .map(([n, l]) => opt(n, l, s.interval)).join("")}${[5, 10, 20, 30, 60].includes(+s.interval) ? "" : opt(s.interval, `${s.interval} seconds`, s.interval)}</select></label>
        <label>Mark a device offline after<select id="sy_offline">${[[0, "Automatic"], [60, "1 minute"], [180, "3 minutes"], [600, "10 minutes"], [1800, "30 minutes"]]
          .map(([n, l]) => opt(n, l, s.offline_after)).join("")}${[0, 60, 180, 600, 1800].includes(+s.offline_after) ? "" : opt(s.offline_after, `${s.offline_after} seconds`, s.offline_after)}</select></label>
        <label class="full chk-line"><input type="checkbox" id="sy_deep" ${s.deep ? "checked" : ""}> Port and OS scans (nmap). Needed for security checks and vulnerabilities.</label>
        <label>Ports in a quick scan<select id="sy_ports">${portsList.map(([n, l]) => opt(n, l, s.top_ports)).join("")}</select></label>
        <label>Re-scan each device every<select id="sy_rescan">${[[30, "30 minutes"], [60, "hour"], [360, "6 hours"], [1440, "day"]]
          .map(([n, l]) => opt(n, l, s.rescan)).join("")}${[30, 60, 360, 1440].includes(+s.rescan) ? "" : opt(s.rescan, `${s.rescan} minutes`, s.rescan)}</select></label>
        <label>Scans at the same time <span class="muted">(restart)</span><select id="sy_workers">${[1, 2, 3, 4].map((n) => opt(n, n, s.workers)).join("")}</select></label>
        <div class="full muted" style="font-size:12px">Lab machines and servers can get a thorough all-ports scan: open the device and click <b>Thorough scan</b>.</div>
      </div></div>

    <div class="chan"><div class="chan-head"><i class="fa-solid fa-network-wired ci"></i><div class="txt"><b>Network</b>
      <small>Now scanning <b>${esc(run.subnet)}</b> on <b>${esc(run.iface)}</b> (this machine is ${esc(run.my_ip)}, gateway ${esc(run.gateway || "unknown")}). Applies after a restart.</small></div></div>
      <div class="chan-fields">
        <label>Network interface<select id="sy_iface">${opt("", `Automatic (${run.iface})`, s.iface)}${v.interfaces.map((n) => opt(n, n, s.iface)).join("")}</select></label>
        <label>Subnet to scan<input id="sy_subnet" value="${esc(s.subnet)}" placeholder="Automatic (${esc(run.subnet)})"></label>
      </div></div>

    <div class="chan"><div class="chan-head"><i class="fa-solid fa-server ci"></i><div class="txt"><b>Web server</b>
      <small>Now at <b>${run.https ? "https" : "http"}://${esc(location.hostname)}:${esc(run.port)}</b>. Applies after a restart.</small></div></div>
      <div class="chan-fields">
        <label>Port<input id="sy_port" type="number" min="1" max="65535" value="${esc(s.port)}"></label>
        <label>Listen on<select id="sy_host">${opt("0.0.0.0", "All network addresses", s.host)}${opt("::", "All addresses (IPv4 + IPv6)", s.host)}${opt("127.0.0.1", "This machine only", s.host)}</select></label>
        <label class="full chk-line"><input type="checkbox" id="sy_https" ${s.https ? "checked" : ""}> HTTPS with a self-signed certificate (recommended: keeps your password private on the network)</label>
        <label class="full">Extra host names <span class="muted">(only needed without a login, e.g. lanpulse.mydomain.com)</span>
          <input id="sy_hosts" value="${esc((s.allow_hosts || []).join(", "))}" placeholder="none"></label>
        <div class="full muted" style="font-size:12px" id="sy_warn"></div>
      </div></div>

    <p class="hint" style="font-size:12px">Locked out after changing the port or HTTPS? On the LanPulse machine run
      <code>sudo /opt/lanpulse/venv/bin/python /opt/lanpulse/app.py --data-dir /opt/lanpulse/data --reset-web</code> then
      <code>sudo systemctl restart lanpulse</code>.</p>
    <div class="modal-foot"><span class="test-res" id="syRes"></span>
      <button class="btn primary" id="sySave"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>`;

  const warn = () => {
    const port = +$("sy_port").value, https = $("sy_https").checked, host = $("sy_host").value;
    const msgs = [];
    if (port !== +run.port && v.ufw) msgs.push(`The ufw firewall is on. Allow the new port first, or you won't be able to connect:
      <code>sudo ufw allow from 192.168.0.0/16 to any port ${port} proto tcp</code>`);
    if (port !== +run.port || https !== run.https) msgs.push(`After restarting, LanPulse will be at <b>${https ? "https" : "http"}://${esc(location.hostname)}:${port}</b>.`);
    if (https && !run.https) msgs.push("Your browser will warn about the self-signed certificate the first time; choose to continue.");
    if (host === "127.0.0.1") msgs.push(`<span style="color:#fca5a5">"This machine only" means you can't open LanPulse from other computers.</span>`);
    $("sy_warn").innerHTML = msgs.join("<br>");
  };
  ["sy_port", "sy_https", "sy_host"].forEach((id) => $(id).addEventListener("input", warn));
  warn();

  $("sySave").onclick = async () => {
    const payload = {interval: +$("sy_interval").value, offline_after: +$("sy_offline").value, deep: $("sy_deep").checked,
      top_ports: +$("sy_ports").value, rescan: +$("sy_rescan").value, workers: +$("sy_workers").value,
      iface: $("sy_iface").value, subnet: $("sy_subnet").value.trim(), port: +$("sy_port").value, host: $("sy_host").value,
      https: $("sy_https").checked, allow_hosts: $("sy_hosts").value.split(/[\s,]+/).filter(Boolean)};
    const r = await api("/api/system", "POST", payload, true);
    if (!r || r.error) { $("syRes").className = "test-res bad"; $("syRes").textContent = r?.error || "Couldn't save."; return; }
    drawSystem(body, r);
    toast(r.pending.length ? "Saved. Restart LanPulse to apply the network and web server changes." : "Saved and applied");
  };
  if ($("sysRestart")) $("sysRestart").onclick = () => restartLanPulse(v);
}

async function restartLanPulse(v) {
  const s = v.system;
  const target = `${s.https ? "https" : "http"}://${location.hostname}:${s.port}/`;
  const same = target === `${location.protocol}//${location.host}/`;
  if (!confirm(same ? "Restart LanPulse now? The dashboard will be back in a few seconds."
    : `Restart LanPulse now? It will move to ${target}`)) return;
  const r = await api("/api/system/restart", "POST");
  if (!r) return;
  closeSettings();
  const bar = document.createElement("div");
  bar.className = "updated-bar";
  bar.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i><span>Restarting LanPulse…${same ? "" : ` Moving to <a href="${esc(target)}">${esc(target)}</a>`}</span>`;
  document.body.appendChild(bar);
  if (!same) { setTimeout(() => { location.href = target; }, 9000); return; }
  await new Promise((res) => setTimeout(res, 4000));
  for (let i = 0; i < 60; i++) {
    try { const x = await fetch("/api/system"); if (x.ok || x.status === 401) { location.reload(); return; } } catch (_) {}
    await new Promise((res) => setTimeout(res, 2000));
  }
  bar.querySelector("span").textContent = "LanPulse is taking a while to come back. Check it with: sudo systemctl status lanpulse";
}
