// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Vulnerabilities tab: known flaws (CVEs) in the software your devices run, worst first. */

let vulnData = null, vulnOpen = new Set(), vulnDevOpen = new Set(), vulnDevSeen = new Set();

const SEV_COLOR = {critical: "#f43f5e", high: "#fb923c", medium: "#fbbf24", low: "#7dd3fc", unknown: "#8b9bb6"};
const sevOf = (s) => (s == null ? "unknown" : s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : "low");
const isCve = (id) => /^CVE-\d{4}-\d+$/i.test(id || "");
// "3 CVEs", "2 findings" (scanner tests with no CVE id), or a mix
function countLabel(total, cves) {
  const f = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  if (cves == null || cves === total) return f(total, "CVE");
  if (cves === 0) return f(total, "finding");
  return `${f(cves, "CVE")} + ${total - cves} other`;
}
const scoreChip = (s) => `<span class="score-chip ${sevOf(s)}">${s == null ? "?" : s.toFixed(1)}</span>`;
const nvdLink = (id) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;

async function loadVulns() {
  const r = await api("/api/vulns", "GET");
  if (!r) return;
  vulnData = r;
  renderVulns();
}

function renderVulns() {
  const s = vulnData;
  if (!s) return;
  const t = s.totals, st = s.status || {};
  $("vulnKpis").innerHTML = `
    ${t.confirmed ? `<div class="kpi danger"><span class="k-lbl">Confirmed</span><span class="k-num">${t.confirmed}</span>
      <span class="k-sub">verified by active check</span></div>` : ""}
    <div class="kpi ${t.kev ? "danger" : ""}"><span class="k-lbl">Actively exploited</span><span class="k-num">${t.kev}</span>
      <span class="k-sub">${t.kev ? "attackers use these now" : "none found"}</span></div>
    <div class="kpi ${t.exploits ? "warn-kpi" : ""}"><span class="k-lbl">Exploit available</span><span class="k-num" style="${t.exploits ? "color:#fdba74" : ""}">${t.exploits || 0}</span>
      <span class="k-sub">${t.msf ? `${t.msf} distinct Metasploit modules` : "public exploit code"}</span></div>
    <div class="kpi"><span class="k-lbl">Critical</span><span class="k-num" style="${t.critical ? "color:#fda4af" : ""}">${t.critical}</span><span class="k-sub">CVSS 9 or higher</span></div>
    <div class="kpi"><span class="k-lbl">Known flaws</span><span class="k-num">${t.cves}</span><span class="k-sub">different CVEs</span></div>
    <div class="kpi"><span class="k-lbl">Devices affected</span><span class="k-num">${t.devices}</span><span class="k-sub">of ${t.scanned} scanned</span></div>
`;
  const parts = [];
  if (!s.enabled) parts.push(`<b>Vulnerability checks are off.</b> Turn them on in Settings.`);
  else if (st.state === "checking") parts.push(`<i class="fa-solid fa-spinner fa-spin"></i> Looking up ${st.pending} product${st.pending === 1 ? "" : "s"} in the NVD database
    (about ${Math.max(1, Math.ceil(st.pending * (s.has_key ? 1 : 7) / 60))} min without an API key). Results fill in as they arrive.`);
  else if (st.last_run) parts.push(`<i class="fa-solid fa-circle-check" style="color:#86efac"></i> Checked ${ago(st.last_run)}: ${st.products} product${st.products === 1 ? "" : "s"} across your devices.`);
  else parts.push(`<i class="fa-solid fa-hourglass-half"></i> The first check starts shortly after LanPulse starts.`);
  if (st.error) parts.push(`<span style="color:#fca5a5"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(st.error)}</span>`);
  if (st.no_cpe) parts.push(`<span class="muted">${st.no_cpe} service${st.no_cpe === 1 ? " doesn't" : "s don't"} report a product ID, so ${st.no_cpe === 1 ? "it can't" : "they can't"} be checked.</span>`);
  if (!s.kev_list && !st.error && st.last_run) parts.push(`<span class="muted">CISA's exploited list hasn't downloaded yet.</span>`);
  const xd = s.exploit_db || {};
  if (xd.error) parts.push(`<span class="muted">Exploit lists: ${esc(xd.error)}</span>`);
  else if (!xd.cves && st.last_run) parts.push(`<span class="muted">Metasploit and Exploit-DB lists are downloading…</span>`);
  if (st.no_cpe) parts.push(`<span class="muted">Tip: for lab machines, open the device and turn on <b>Thorough scan</b> to find more software.</span>`);
  $("vulnStatus").innerHTML = `<div>${parts.join("<br>")}</div>`;

  const rowHtml = (g) => {
    const key = `${g.id}|${g.port}`;
    return `<div class="fix ${g.confidence === "confirmed" ? "confirmed-fix" : g.kev ? "kev" : ""}">
      <button class="fix-row" data-key="${esc(key)}" aria-expanded="${vulnOpen.has(key)}">
        ${g.confidence === "confirmed" && !g.max ? '<span class="score-chip confirmed-chip" title="Confirmed vulnerable by an active check (no CVSS score)">!</span>' : scoreChip(g.max)}
        <span class="fix-main"><b>${esc(g.software)}</b> ${g.port ? `<span class="muted">port ${g.port}</span>` : ""}<br>
          <span class="fix-dev">${esc(g.name)} · ${esc(g.ip)}</span></span>
        <span class="fix-tags">${g.confidence === "confirmed" ? '<span class="tagchip confirmed" title="An active check connected to this service and confirmed the flaw — not a version guess."><i class="fa-solid fa-circle-check"></i>confirmed</span>' : ""}
          ${g.kev ? `<span class="tagchip bad">${g.kev} exploited</span>` : ""}
          ${g.msf ? `<span class="tagchip msf">${g.msf} Metasploit</span>` : ""}${g.edb ? `<span class="tagchip edb">${g.edb} Exploit-DB</span>` : ""}
          ${g.os ? '<span class="tagchip" title="Windows was identified, but a scan can\'t see which updates are installed. If this machine has every update for its version, some of these are already fixed.">patch level unknown</span>' : g.unverified ? '<span class="tagchip">version unknown</span>' : ""}
          <span class="tagchip">${countLabel(g.count, g.cves)}</span>${g.distro ? '<span class="tagchip">may be patched</span>' : ""}</span>
        <i class="fa-solid fa-chevron-down chev"></i></button>
      <div class="fix-detail ${vulnOpen.has(key) ? "" : "hidden"}" data-detail="${esc(key)}"></div></div>`;
  };
  const byDev = new Map();
  for (const g of s.fix) { if (!byDev.has(g.id)) byDev.set(g.id, []); byDev.get(g.id).push(g); }
  if (byDev.size === 1 && !vulnDevSeen.size) vulnDevOpen.add([...byDev.keys()][0]);   // a lone device opens by itself
  for (const id of byDev.keys()) vulnDevSeen.add(id);
  $("vulnFix").innerHTML = s.fix.length ? [...byDev.entries()].map(([id, gs]) => {
    const top = gs.reduce((m, g) => Math.max(m, g.max || 0), 0) || null;
    const cves = gs.reduce((n, g) => n + g.count, 0), cveIds = gs.reduce((n, g) => n + (g.cves || 0), 0), conf = gs.filter((g) => g.confidence === "confirmed").length;
    const kev = gs.reduce((n, g) => n + (g.kev || 0), 0), msf = gs.reduce((n, g) => n + (g.msf || 0), 0);
    const open = vulnDevOpen.has(id);
    return `<div class="fixdev ${open ? "open" : ""}" data-devgrp="${esc(id)}">
      <button class="fixdev-head" data-devtoggle="${esc(id)}" aria-expanded="${open}">
        ${top == null && conf ? '<span class="score-chip confirmed-chip">!</span>' : scoreChip(top)}
        <span class="fix-main"><b>${esc(gs[0].name)}</b> <span class="muted mono">${esc(gs[0].ip)}</span><br>
          <span class="fix-dev">${gs.length} service${gs.length === 1 ? "" : "s"} with flaws</span></span>
        <span class="fix-tags">${conf ? `<span class="tagchip confirmed"><i class="fa-solid fa-circle-check"></i>${conf} confirmed</span>` : ""}
          ${kev ? `<span class="tagchip bad">${kev} exploited</span>` : ""}${msf ? `<span class="tagchip msf">${msf} Metasploit</span>` : ""}
          <span class="tagchip">${countLabel(cves, cveIds)}</span></span>
        <i class="fa-solid fa-chevron-down chev"></i></button>
      <div class="fixdev-body ${open ? "" : "hidden"}">${open ? gs.map(rowHtml).join("") : ""}</div></div>`;
  }).join("") : `<div class="all-clear" style="margin:0"><i class="fa-solid fa-circle-check"></i><div><b>No known flaws found</b>
      <span>${t.scanned ? "in the software versions LanPulse could identify." : "yet. Devices are checked after their first port scan."}</span></div></div>`;
  for (const key of vulnOpen) fillFixDetail(key);

  const dmax = Math.max(1, ...s.devices.map((d) => d.count));
  $("vulnDevs").innerHTML = s.devices.map((d) => { const ty = TYPES[d.type] || TYPES.unknown; return `<div class="rk click" data-dev-id="${esc(d.id)}">
      <span class="ico"><i class="${faClass(ty)}" style="color:${ty.color}"></i></span><span class="nm">${esc(d.name)}</span>
      <span class="ct">${ovBtn(devices.get(d.id)?.ip)}${xBtn("redteam", d.id)}${d.confirmed ? `<span style="color:#fecaca;font-weight:700">${d.confirmed} confirmed · </span>` : ""}${d.kev ? `<span style="color:#fca5a5">${d.kev} exploited · </span>` : ""}${d.msf_modules ? `<span style="color:#fdba74">${d.msf_modules} Metasploit modules · </span>` : ""}${d.exploits ? `<span style="color:#fdba74">${d.exploits} exploitable · </span>` : ""}${d.count}</span>
      <div class="bar"><i style="width:${(100 * d.count / dmax).toFixed(1)}%;background:${SEV_COLOR[sevOf(d.max)]}"></i></div></div>`; }).join("")
    || `<div class="muted">No affected devices.</div>`;

  $("vulnCfgN").textContent = s.config.length ? `(${s.config.length})` : "";
  $("vulnConfig").innerHTML = s.config.length ? s.config.map((c) => `<button class="cfg-row" data-dev-id="${esc(c.id)}">
      <span class="sev ${c.level}">${c.level}</span><span><b>${esc(c.name)}</b><br><span class="muted">${esc(c.text)}</span></span></button>`).join("")
    : `<div class="muted">Nothing risky found. Dismissed risks don't show here.</div>`;
  const badge = $("vulnBadge");
  if (badge) { badge.textContent = String(t.kev); badge.classList.toggle("hidden", !t.kev || view === "vulns"); }
}


// Jump between the findings view and the attacker view for one device, and flash its row.
function xJump(target, devId) {
  setView(target);
  const box = target === "redteam" ? "rtDevs" : "vulnDevs";
  let tries = 0;
  const t = setInterval(() => {
    const row = $(box) && [...$(box).querySelectorAll("[data-dev-id]")].find((r) => r.dataset.devId === devId);
    if (row) { clearInterval(t); row.scrollIntoView({block: "center", behavior: "smooth"}); row.classList.add("xflash"); setTimeout(() => row.classList.remove("xflash"), 2200); }
    else if (++tries > 20) clearInterval(t);
  }, 150);
}
const xBtn = (target, id) => `<button class="btn sm xjump" data-xjump="${target}" data-xdev="${esc(id)}" title="${target === "redteam" ? "See this device the way an attacker would: ATT&CK techniques and Metasploit modules" : "See this device's vulnerabilities and what to fix"}"><i class="fa-solid ${target === "redteam" ? "fa-crosshairs" : "fa-bug"}"></i>${target === "redteam" ? "Attack view" : "Findings"}</button>`;

async function fillFixDetail(key) {
  const [id, port] = key.split("|");
  const box = document.querySelector(`[data-detail="${CSS.escape(key)}"]`);
  if (!box) return;
  const r = await api(`/api/vulns/device/${encodeURIComponent(id)}`, "GET");
  if (!r) return;
  const items = r.items.filter((f) => String(f.port) === port);
  const foot = `<div class="btns" style="margin-top:8px"><button class="btn sm" data-dev-id="${esc(id)}"><i class="fa-solid fa-circle-info"></i>Open device</button>${xBtn("redteam", id)}</div>`;
  const draw = (n) => {
    box.innerHTML = items.slice(0, n).map(cveRow).join("") +
      (items.length > n ? `<button class="btn sm" data-showmore="1" style="margin-top:6px"><i class="fa-solid fa-angles-down"></i>Show all ${items.length}</button>` : "") + foot;
    const more = box.querySelector("[data-showmore]");
    if (more) more.onclick = (e) => { e.stopPropagation(); draw(items.length); };
  };
  draw(40);
}

function cveRow(f) {
  const msf = f.msf || [], edb = f.edb || [];
  return `<div class="cve ${f.confidence === "confirmed" ? "confirmed" : f.kev ? "kev" : msf.length ? "msf" : ""}">${scoreChip(f.score)}
    <div>${isCve(f.cve) ? `<a href="${esc(nvdLink(f.cve))}" target="_blank" rel="noopener"><b>${esc(f.cve)}</b></a>` : `<b title="A scanner test with no CVE id">${esc(f.software || f.cve)}</b>`}
      ${f.confidence === "confirmed" ? '<span class="tagchip confirmed" title="An active check confirmed this flaw on the device — not inferred from a version number."><i class="fa-solid fa-circle-check"></i>confirmed</span>' : ""}
      ${f.kev ? `<span class="tagchip bad">exploited${f.ransomware ? " · ransomware" : ""}</span>` : ""}
      ${msf.length ? '<span class="tagchip msf">Metasploit</span>' : ""}${edb.length ? '<span class="tagchip edb">Exploit-DB</span>' : ""}
      ${f.os ? '<span class="tagchip" title="Windows was identified, but a scan can\'t see which updates are installed, so only flaws with a public exploit are listed.">patch level unknown</span>' : f.unverified ? '<span class="tagchip" title="LanPulse recognised the software but not its exact version, so it lists only flaws with a public exploit. Check the version.">version unknown</span>' : ""}
      <span class="muted">${esc(f.pub || "")}</span><br><span class="cve-desc">${esc(f.kev_name || f.desc)}</span>
      ${msf.length ? `<div class="xrefs"><i class="fa-solid fa-terminal"></i>${msf.slice(0, 3).map((m) => `<code title="${esc(m[1])}">${esc(m[0])}</code>`).join("")}</div>` : ""}
      ${edb.length ? `<div class="xrefs"><i class="fa-solid fa-file-code"></i>${edb.slice(0, 3).map((e) =>
        `<a href="https://www.exploit-db.com/exploits/${encodeURIComponent(e[0])}" target="_blank" rel="noopener" title="${esc(e[1])}">EDB-${esc(e[0])}${e[2] ? " ✓" : ""}</a>`).join("")}</div>` : ""}
      ${researchLinks(f.cve)}
    </div></div>`;
}

// Passive research links for a CVE (opens each source in a new tab; no automated requests).
function researchLinks(cve) {
  if (!/^CVE-\d{4}-\d+$/i.test(cve || "")) return "";
  const q = encodeURIComponent(cve);
  return `<div class="cve-research"><i class="fa-solid fa-magnifying-glass"></i>
    <a href="https://www.exploit-db.com/search?cve=${q}" target="_blank" rel="noopener">Exploit-DB</a>
    <a href="https://github.com/search?q=${q}&type=repositories" target="_blank" rel="noopener">GitHub PoC</a>
    <a href="https://www.cvedetails.com/cve/${q}/" target="_blank" rel="noopener">CVE Details</a></div>`;
}

async function showVulnSetup() {
  const box = $("vulnSetup");
  if (!box.classList.contains("hidden")) { box.classList.add("hidden"); return; }
  const set = await api("/api/settings", "GET");
  if (!set) return;
  const c = set.vulns || {};
  box.classList.remove("hidden");
  box.innerHTML = `<div class="t-card"><h4><span><i class="fa-solid fa-gear"></i> Vulnerability checks</span></h4>
    <div class="chan-fields" style="padding:0">
      <label class="full chk-line"><input type="checkbox" id="vuOn" ${c.enabled !== false ? "checked" : ""}> Check scanned software against the NVD database</label>
      <label class="full">NVD API key (optional, free at nvd.nist.gov/developers/request-an-api-key)
        <input id="vuKey" type="password" value="${esc(c.nvd_key || "")}" autocomplete="off" placeholder="makes the first check about 8× faster"></label>
    </div>
    <p class="hint" style="font-size:12px">LanPulse sends NVD only product names (like "openbsd openssh"), never your IPs or device names.</p>
    <div class="modal-foot" style="position:static;padding:10px 0 0"><button class="btn primary" id="vuSave"><i class="fa-solid fa-floppy-disk"></i>Save</button></div></div>`;
  $("vuSave").onclick = async () => {
    if (await api("/api/settings", "POST", {vulns: {enabled: $("vuOn").checked, nvd_key: $("vuKey").value.trim()}})) {
      toast("Saved"); box.classList.add("hidden"); api("/api/vulns/refresh", "POST"); setTimeout(loadVulns, 1500);
    }
  };
}

/* ---- device panel */
const vulnPanelAll = new Set();
async function loadDeviceVulns(id) {
  const r = await api(`/api/vulns/device/${encodeURIComponent(id)}`, "GET");
  const box = $("vulnBox");
  if (!r || selected !== id || !box) return;
  if (!r.items.length) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const kev = r.items.filter((f) => f.kev).length;
  box.classList.remove("hidden");
  box.innerHTML = `<h4>Known vulnerabilities</h4>
    <div class="muted" style="font-size:12px;margin-bottom:6px">${r.items.length} CVE${r.items.length === 1 ? "" : "s"} in this device's software${kev ? `, <b style="color:#fca5a5">${kev} actively exploited</b>` : ""}
      ${r.items.some((f) => f.distro) ? " · some may already be patched by OS updates" : ""}</div>
    ${r.items.slice(0, vulnPanelAll.has(id) ? r.items.length : 6).map(cveRow).join("")}
    ${r.items.length > 6 ? `<button class="btn sm" data-vulnall="${esc(id)}" style="margin-top:6px"><i class="fa-solid ${vulnPanelAll.has(id) ? "fa-angles-up" : "fa-angles-down"}"></i>${vulnPanelAll.has(id) ? "Show fewer" : `Show all ${r.items.length}`}</button>` : ""}
    <div class="btns" style="margin-top:10px"><button class="btn" data-goto-vulns="1"><i class="fa-solid fa-bug"></i>Open Vulnerabilities</button></div>`;
  const dev = devices.get(id);
  if (dev && typeof msfPanelSection === "function") {
    const extra = msfPanelSection(dev.ip, r.items);
    if (extra) box.insertAdjacentHTML("beforeend", extra);
  }
}

/* ---- OpenVAS scan buttons: device panel and the Vulnerabilities device list (the full list stays in Settings) */
let ovInfo = null;
async function ovRefresh() { const r = await api("/api/openvas", "GET", null, true); ovInfo = r && !r.error ? r : null; return ovInfo; }
const ovScanOf = (ip) => ((ovInfo && ovInfo.scans) || []).find((x) => x.ip === ip);
const ovRunning = (x) => x && ["Requested", "Queued", "Running", "New"].includes(x.status);
const ovBtn = (ip) => ovInfo && ovInfo.installed && ovInfo.ready && ovInfo.enabled && ip && !ovRunning(ovScanOf(ip))
  ? `<button class="btn sm" data-ovscan="${esc(ip)}" title="Run an OpenVAS scan on this device"><i class="fa-solid fa-shield-halved"></i>OpenVAS scan</button>` : "";
async function ovStart(ip) {
  const r = await api("/api/openvas/scan", "POST", {ip});
  if (r) { toast("OpenVAS scan started"); await ovRefresh(); if (selected && devices.get(selected)?.ip === ip) loadDeviceOv(selected); if (view === "vulns") renderVulns(); }
}
let ovTimer = null;
async function loadDeviceOv(id) {
  clearTimeout(ovTimer);
  const box = $("ovBox"), dev = devices.get(id);
  if (!box || !dev || !dev.ip || selected !== id) return;
  const s = await ovRefresh();
  if (selected !== id || !$("ovBox")) return;
  if (!s || !s.installed) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const x = ovScanOf(dev.ip), run = ovRunning(x);
  const state = run ? `Scanning… ${esc(x.status)} ${x.progress || 0}%`
    : x && x.error ? esc(x.error) : x && x.finished ? `${x.count} finding${x.count === 1 ? "" : "s"} · ${esc(ago(x.finished))}` : "Not scanned yet";
  const why = !s.enabled ? "Turn on OpenVAS in Settings > Scanner first." : !s.ready ? "OpenVAS isn't ready yet. See Settings > Scanner." : "";
  box.classList.remove("hidden");
  box.innerHTML = `<h4>OpenVAS scan</h4>
    <div class="ov-row" style="grid-template-columns:1fr auto"><span class="muted">${state}</span>
      <button class="btn sm primary" data-ovscan="${esc(dev.ip)}" ${run || why ? "disabled" : ""} title="${esc(why || "Run an OpenVAS scan on this device")}"><i class="fa-solid fa-shield-halved"></i>${run ? "Scanning" : "Scan now"}</button></div>
    ${why ? `<p class="hint" style="margin:6px 0 0">${esc(why)}</p>` : ""}`;
  if (run) ovTimer = setTimeout(() => loadDeviceOv(id), 5000);
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-ovscan]");
  if (!b) return;
  e.stopPropagation();
  b.disabled = true;
  ovStart(b.dataset.ovscan).finally(() => { b.disabled = false; });
}, true);

(function initVulns() {
  viewHooks.vulns = () => { ovRefresh().then(() => { if (vulnData) renderVulns(); }); loadVulns(); };
  $("vulnCheck").onclick = async () => { if (await api("/api/vulns/refresh", "POST")) { toast("Checking now"); setTimeout(loadVulns, 2500); } };
  $("vulnCfgBtn").onclick = showVulnSetup;
  $("vulnFix").addEventListener("click", (e) => {
    const xj = e.target.closest("[data-xjump]");
    if (xj) { xJump(xj.dataset.xjump, xj.dataset.xdev); return; }
    const tg = e.target.closest("[data-devtoggle]");
    if (tg) { const id = tg.dataset.devtoggle; if (vulnDevOpen.has(id)) vulnDevOpen.delete(id); else vulnDevOpen.add(id); renderVulns(); return; }
    const dev = e.target.closest("[data-dev-id]");
    if (dev) { goDevice(dev.dataset.devId); return; }
    const b = e.target.closest(".fix-row"); if (!b) return;
    const key = b.dataset.key;
    const det = document.querySelector(`[data-detail="${CSS.escape(key)}"]`);
    if (vulnOpen.has(key)) { vulnOpen.delete(key); det.classList.add("hidden"); b.setAttribute("aria-expanded", "false"); }
    else { vulnOpen.add(key); det.classList.remove("hidden"); b.setAttribute("aria-expanded", "true"); fillFixDetail(key); }
  });
  for (const id of ["vulnDevs", "vulnConfig"]) $(id).addEventListener("click", (e) => {
    const xj = e.target.closest("[data-xjump]");
    if (xj) { xJump(xj.dataset.xjump, xj.dataset.xdev); return; }
    const r = e.target.closest("[data-dev-id]"); if (r) goDevice(r.dataset.devId); });
  $("panel").addEventListener("click", (e) => {
    if (e.target.closest("[data-goto-vulns]")) setView("vulns");
    const all = e.target.closest("[data-vulnall]");
    if (all) { const id = all.dataset.vulnall; if (vulnPanelAll.has(id)) vulnPanelAll.delete(id); else vulnPanelAll.add(id); loadDeviceVulns(id); }
  });
  setInterval(() => { if (view === "vulns" && vulnData?.status?.state === "checking") loadVulns(); }, 10000);
  setTimeout(async () => { const r = await api("/api/vulns", "GET"); if (r) { vulnData = r; renderVulns(); } }, 4000);
})();
