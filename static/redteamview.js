// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Red Team view: ATT&CK mapping of what was found, Metasploit hand-off, and exports. LanPulse generates the
   commands and files; it never runs an exploit. */

let rtData = null, rtTechIndex = {};

// MITRE ATT&CK page for a technique, e.g. "T1021.001" -> .../techniques/T1021/001/
function attackUrl(id) {
  if (!/^T\d{4}(\.\d{3})?$/.test(id || "")) return "https://attack.mitre.org/techniques/";
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

async function loadRedteam() {
  const r = await api("/api/redteam", "GET");
  if (!r || view !== "redteam") return;
  rtData = r;
  renderRedteam();
}

function renderRedteam() {
  const s = rtData;
  if (!s || !$("rtKpis")) return;
  const t = s.totals;
  $("rtKpis").innerHTML = `
    <div class="kpi"><span class="k-lbl">Targets</span><span class="k-num">${t.targets}</span><span class="k-sub">devices with exposures</span></div>
    <div class="kpi"><span class="k-lbl">ATT&CK techniques</span><span class="k-num">${t.techniques}</span><span class="k-sub">mapped across the network</span></div>
    <div class="kpi ${t.modules ? "warn-kpi" : ""}"><span class="k-lbl">Metasploit modules</span><span class="k-num" style="${t.modules ? "color:#fdba74" : ""}">${t.modules}</span><span class="k-sub">ready to copy</span></div>`;

  rtTechIndex = {};
  $("rtTactics").innerHTML = s.tactics.length ? s.tactics.map((tac) => `
    <div class="rt-tactic"><h5>${esc(tac.tactic)}</h5>
      ${tac.techniques.map((te) => { rtTechIndex[te.id] = te; return `<button class="rt-tech" data-tech="${esc(te.id)}"
        title="Click for details">${""}<span class="rt-id">${esc(te.id)}</span>
        <span class="rt-name">${esc(te.name)}</span><span class="rt-count">${te.devices}</span>
        <i class="fa-solid fa-circle-info rt-ext"></i></button>`; }).join("")}
    </div>`).join("") : `<div class="muted">Nothing mapped yet. ATT&CK techniques appear once devices are port-scanned and checked for vulnerabilities.</div>`;

  $("rtDevs").innerHTML = s.devices.length ? s.devices.map((d) => `
    <div class="rt-row" data-dev-id="${esc(d.id)}">
      <div class="rt-dev"><b>${esc(d.name)}</b><span class="muted mono">${esc(d.ip)}</span></div>
      <div class="rt-tags">
        <span class="rt-score ${esc(d.band)}" title="Exploitability score (planning aid)">${d.score}</span>
        ${d.kev ? `<span class="tagchip bad">${d.kev} exploited</span>` : ""}
        ${d.modules ? `<span class="tagchip msf">${d.modules} module${d.modules === 1 ? "" : "s"}</span>` : ""}
        ${d.cleartext ? `<span class="tagchip">${d.cleartext} cleartext</span>` : ""}
        ${d.default_creds ? `<span class="tagchip">${d.default_creds} default-cred</span>` : ""}
        <span class="tagchip">${d.techniques.length} technique${d.techniques.length === 1 ? "" : "s"}</span></div>
    </div>`).join("") : `<div class="muted">No targets yet.</div>`;
}

// In-app detail for a clicked ATT&CK technique (offline summary + why it mapped + MITRE link).
function showTechnique(id) {
  const te = rtTechIndex[id];
  if (!te) return;
  const box = $("rtDetail");
  box.innerHTML = `
    <div class="rt-detail-card">
      <button class="icon-btn rt-detail-close" title="Close"><i class="fa-solid fa-xmark"></i></button>
      <div class="rt-detail-head"><span class="rt-id big">${esc(te.id)}</span><b>${esc(te.name)}</b></div>
      ${te.desc ? `<p>${esc(te.desc)}</p>` : ""}
      ${te.why && te.why.length ? `<h6>Why it's here</h6><ul>${te.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
      ${te.hosts && te.hosts.length ? `<h6>On these hosts (${te.devices})</h6><div class="rt-hostchips">${te.hosts.map((h) => `<span>${esc(h)}</span>`).join("")}</div>` : ""}
      ${te.detect ? `<h6>Detection</h6><p>${esc(te.detect)}</p>` : ""}
      ${te.mitigate ? `<h6>Mitigation</h6><p>${esc(te.mitigate)}</p>` : ""}
      <a class="btn sm" href="${esc(attackUrl(te.id))}" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square"></i>Full page on attack.mitre.org</a>
    </div>`;
  box.classList.remove("hidden");
  box.querySelector(".rt-detail-close").onclick = () => box.classList.add("hidden");
}

/* Metasploit commands inside a device panel (built from the CVE findings already loaded). */
function msfPanelSection(ip, items) {
  const withMod = items.filter((f) => (f.msf || []).length);
  if (!withMod.length) return "";
  const safeIp = /^[0-9a-fA-F:.]+$/.test(ip) ? ip : "";
  const blocks = withMod.slice(0, 8).map((f) => {
    const mod = f.msf[0][0];
    if (!/^(auxiliary|exploit|post)\/[\w./-]+$/.test(mod) || !safeIp) return "";
    const lines = [`use ${mod}`, `set RHOSTS ${safeIp}`];
    if (f.port) lines.push(`set RPORT ${f.port}`);
    const cmd = lines.join("\n");
    return `<div class="msf-block"><div class="msf-top"><span class="mono">${esc(f.cve)}</span>
        ${f.kev ? '<span class="tagchip bad">exploited</span>' : ""}
        <button class="linkbtn" data-msf="${esc(btoa(cmd))}"><i class="fa-regular fa-copy"></i>Copy</button></div>
      <pre class="msf-cmd">${esc(cmd)}</pre></div>`;
  }).join("");
  if (!blocks) return "";
  return `<div class="p-sec"><h4>Metasploit commands</h4>
    ${blocks}
    <div class="btns" style="margin-top:8px">
      <a class="btn" href="/api/export/metasploit.rc?device=${encodeURIComponent(selected)}"><i class="fa-solid fa-file-code"></i>Download .rc</a>
      <a class="btn" href="/api/export/nmap.xml?device=${encodeURIComponent(selected)}"><i class="fa-solid fa-file-export"></i>Nmap XML</a>
    </div></div>`;
}

(function initRedteam() {
  viewHooks.redteam = loadRedteam;
  const devs = $("rtDevs");
  // open the device panel without leaving the Red Team tab
  if (devs) devs.addEventListener("click", (e) => { const r = e.target.closest("[data-dev-id]"); if (r && devices.has(r.dataset.devId)) openPanel(r.dataset.devId); else if (r) toast("That device isn't on the network map"); });
  const tac = $("rtTactics");
  if (tac) tac.addEventListener("click", (e) => { const b = e.target.closest("[data-tech]"); if (b) showTechnique(b.dataset.tech); });
  // copy buttons for the per-device Metasploit blocks live in the panel
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-msf]");
    if (!b) return;
    try { copyText({value: atob(b.dataset.msf)}); } catch (_) {}
  });
})();
