// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* LanPulse front-end: live map, device details, history, alerts settings. */

const TYPES = {
  internet:   {label: "Internet",            fa: "fa-cloud",                 icon: "", color: "#38bdf8"},
  router:     {label: "Router / Gateway",    fa: "fa-tower-broadcast",       icon: "", color: "#f59e0b"},
  ap:         {label: "Access Point",        fa: "fa-wifi",                  icon: "", color: "#fbbf24"},
  switch:     {label: "Network Switch",      fa: "fa-network-wired",         icon: "", color: "#fb923c"},
  scanner:    {label: "LanPulse Host",      fa: "fa-satellite-dish",        icon: "", color: "#38bdf8"},
  server:     {label: "Server",              fa: "fa-server",                icon: "", color: "#a78bfa"},
  nas:        {label: "NAS / Storage",       fa: "fa-hard-drive",            icon: "", color: "#c084fc"},
  desktop:    {label: "Desktop / PC",        fa: "fa-desktop",               icon: "", color: "#60a5fa"},
  laptop:     {label: "Laptop / Mac",        fa: "fa-laptop",                icon: "", color: "#3b82f6"},
  phone:      {label: "Phone",               fa: "fa-mobile-screen-button",  icon: "", color: "#34d399"},
  tablet:     {label: "Tablet",              fa: "fa-tablet-screen-button",  icon: "", color: "#10b981"},
  printer:    {label: "Printer",             fa: "fa-print",                 icon: "", color: "#f472b6"},
  tv:         {label: "TV / Streamer",       fa: "fa-tv",                    icon: "", color: "#fb7185"},
  camera:     {label: "IP Camera",           fa: "fa-video",                 icon: "", color: "#f87171"},
  game:       {label: "Game Console",        fa: "fa-gamepad",               icon: "", color: "#4ade80"},
  speaker:    {label: "Smart Speaker",       fa: "fa-volume-high",           icon: "", color: "#2dd4bf"},
  iot:        {label: "IoT / Smart Home",    fa: "fa-microchip",             icon: "", color: "#22d3ee"},
  raspberrypi:{label: "Raspberry Pi",        fa: "fa-raspberry-pi",          icon: "", color: "#e11d48", brand: true},
  unknown:    {label: "Unknown",             fa: "fa-circle-question",       icon: "", color: "#94a3b8"},
};
const typeOf = (d) => TYPES[d.type] || TYPES.unknown;
const faClass = (t) => `${t.brand ? "fa-brands" : "fa-solid"} ${t.fa}`;
const INTERNET = "__internet";
const HTTP_PORTS = new Set([80, 81, 443, 5000, 5001, 8000, 8006, 8080, 8081, 8443, 8888, 9000, 9090]);
const SEV_RANK = {high: 0, medium: 1, low: 2};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const nameOf = (d) => d.name || d.friendly || d.hostname || d.vendor || d.ip;
const risk = (d) => (d.findings || []).reduce((m, f) => (f.dismissed ? m : Math.min(m, SEV_RANK[f.level] ?? 9)), 9);
const hasIssue = (d) => risk(d) <= 1;          // high or medium findings

let meta = {};
let devices = new Map();
let selected = null;
let statFilter = "";
let layoutKey = "";
let historyTimer = null;
let lastHist = null;
const underAttack = new Map();     // device id -> time it was last hit by an attack

/* ------------------------------------------------------------ time helpers */
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 5) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
const full = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "—";

/* ------------------------------------------------------------ filtering */
function matches(d) {
  const q = $("q").value.trim().toLowerCase();
  const ft = $("fType").value;
  if (q) {
    const hay = `${nameOf(d)} ${d.hostname} ${d.ip} ${d.mac} ${d.vendor} ${typeOf(d).label} ${d.notes} ${d.model || ""}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  if (ft && d.type !== ft) return false;
  if (!$("fOffline").checked && !d.online) return false;
  if (statFilter === "__online" && !d.online) return false;
  if (statFilter === "__offline" && d.online) return false;
  if (statFilter === "__untrusted" && d.trusted) return false;
  if (statFilter === "__issues" && !hasIssue(d)) return false;
  return true;
}

/* ------------------------------------------------------------ map */
const nodes = new vis.DataSet();
const edges = new vis.DataSet();
let network;
let physicsOn = true;

function drawIcon(ctx, t, x, y, size) {
  ctx.font = `${t.brand ? 400 : 900} ${Math.round(size * 0.86)}px "Font Awesome 6 ${t.brand ? "Brands" : "Free"}"`;
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.fillText(t.icon, x, y);
}

function drawWarning(ctx, x, y, color) {
  ctx.beginPath();
  ctx.moveTo(x, y - 8); ctx.lineTo(x + 8.5, y + 6.5); ctx.lineTo(x - 8.5, y + 6.5); ctx.closePath();
  ctx.fillStyle = color; ctx.fill();
  ctx.lineWidth = 2; ctx.strokeStyle = "#0a0f1c"; ctx.stroke();
  ctx.fillStyle = "#0a0f1c"; ctx.font = "800 10px Inter, system-ui, sans-serif";
  ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("!", x, y + 1.5);
}

function nodeRenderer({ctx, id, x, y, state: {selected: sel, hover}}) {
  if (typeof id === "string" && id.startsWith("__grp_")) return groupRenderer({ctx, id, x, y, sel, hover});
  const d = id === INTERNET ? {type: "internet", online: true, trusted: true, ip: "WAN", name: "Internet"} : devices.get(id);
  const t = d ? typeOf(d) : TYPES.unknown;
  const big = d && (d.type === "router" || d.type === "internet");
  const r = big ? 30 : 23;
  const online = d ? d.online : false;
  return {
    drawNode() {
      ctx.save();
      ctx.globalAlpha = online ? 1 : 0.4;
      if (d && !d.trusted) {
        ctx.beginPath(); ctx.arc(x, y, r + 7, 0, 2 * Math.PI);
        ctx.setLineDash([5, 4]); ctx.lineWidth = 2; ctx.strokeStyle = "#ef4444"; ctx.stroke(); ctx.setLineDash([]);
      }
      if (d && typeof isLocalAttacker === "function" && isLocalAttacker(d.id)) {   // LAN device behaving badly
        ctx.beginPath(); ctx.arc(x, y, r + 9, 0, 2 * Math.PI);
        ctx.lineWidth = 4; ctx.strokeStyle = "#f43f5e"; ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y, r + 14, 0, 2 * Math.PI);
        ctx.lineWidth = 1; ctx.strokeStyle = "rgba(244,63,94,.45)"; ctx.stroke();
      }
      const hitAt = d && underAttack.get(d.id);
      if (hitAt && Date.now() - hitAt < 8000) {      // red shock-wave while under attack
        const ph = (Date.now() % 1000) / 1000;
        ctx.beginPath(); ctx.arc(x, y, r + 5 + ph * 16, 0, 2 * Math.PI);
        ctx.lineWidth = 3; ctx.strokeStyle = `rgba(244,63,94,${(1 - ph).toFixed(2)})`; ctx.stroke();
      }
      if (sel || hover) { ctx.shadowColor = t.color; ctx.shadowBlur = sel ? 28 : 14; }
      ctx.beginPath(); ctx.arc(x, y, r, 0, 2 * Math.PI);
      ctx.fillStyle = "#0f182c"; ctx.fill();
      ctx.shadowBlur = 0;
      ctx.lineWidth = sel ? 4 : 2.5; ctx.strokeStyle = t.color; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r - 5, 0, 2 * Math.PI);
      ctx.fillStyle = t.color + "1f"; ctx.fill();
      ctx.fillStyle = t.color;
      drawIcon(ctx, t, x, y + 1, r * 0.95);
      if (id !== INTERNET && d) {
        ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.arc(x + r * 0.72, y + r * 0.72, 6, 0, 2 * Math.PI);
        ctx.fillStyle = d.scanning ? "#f59e0b" : online ? "#22c55e" : "#ef4444";
        ctx.fill(); ctx.lineWidth = 2.5; ctx.strokeStyle = "#0a0f1c"; ctx.stroke();
        const rk = risk(d);
        if (rk <= 1) drawWarning(ctx, x - r * 0.72, y - r * 0.68, rk === 0 ? "#f87171" : "#fbbf24");
        if (d.watched) {
          ctx.beginPath(); ctx.arc(x + r * 0.72, y - r * 0.72, 5.5, 0, 2 * Math.PI);
          ctx.fillStyle = "#38bdf8"; ctx.fill(); ctx.lineWidth = 2.5; ctx.strokeStyle = "#0a0f1c"; ctx.stroke();
        }
      }
      ctx.restore();
    },
    drawExternalLabel() {
      if (!d) return;
      ctx.save();
      ctx.globalAlpha = online ? 1 : 0.5;
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      ctx.font = "600 12px Inter, system-ui, sans-serif";
      let label = nameOf(d);
      if (label.length > 22) label = label.slice(0, 21) + "…";
      const ly = y + r + (d.trusted ? 7 : 12);
      ctx.lineWidth = 4; ctx.strokeStyle = "#0a0f1c"; ctx.strokeText(label, x, ly);
      ctx.fillStyle = "#e2e8f0"; ctx.fillText(label, x, ly);
      ctx.font = "11px 'JetBrains Mono', monospace";
      ctx.fillStyle = "#8b9bb6"; ctx.fillText(d.ip, x, ly + 15);
      ctx.restore();
    },
    nodeDimensions: {width: r * 2, height: r * 2},
  };
}

function tooltip(d) {
  const el = document.createElement("div");
  const warn = (d.findings || []).filter((f) => f.level !== "low").length;
  el.innerHTML = `<b>${esc(nameOf(d))}</b><br><span style="color:#8b9bb6">${esc(typeOf(d).label)}</span><br>
    ${esc(d.ip)} · ${esc(d.mac || "no MAC")}<br>${d.online ? (d.rtt_ms != null ? `${d.rtt_ms} ms` : "online") : "offline · last seen " + ago(d.last_seen)}
    ${d.trusted ? "" : '<br><span style="color:#fca5a5">Not yet trusted</span>'}
    ${warn ? `<br><span style="color:#fcd34d">${warn} security warning${warn > 1 ? "s" : ""}</span>` : ""}`;
  return el;
}

function edgeStyle(d) {
  if (!d.online) return {color: {color: "#334155", opacity: 0.5}, dashes: [4, 6], width: 1};
  const rtt = d.rtt_ms ?? 0;
  const c = rtt > 80 ? "#ef4444" : rtt > 25 ? "#f59e0b" : "#2b4a7a";
  return {color: {color: c, highlight: "#38bdf8", hover: "#38bdf8"}, dashes: false, width: 1.6};
}

function initMap() {
  network = new vis.Network($("map"), {nodes, edges}, {
    autoResize: true,
    nodes: {shape: "custom", ctxRenderer: nodeRenderer},
    edges: {smooth: {type: "continuous"}, selectionWidth: 2, hoverWidth: 1},
    physics: {
      solver: "forceAtlas2Based",
      forceAtlas2Based: {gravitationalConstant: -110, centralGravity: 0.012, springLength: 150, springConstant: 0.06, avoidOverlap: 0.7},
      stabilization: {iterations: 250, fit: true},
      maxVelocity: 30,
    },
    interaction: {hover: true, tooltipDelay: 120, navigationButtons: false, keyboard: false},
  });
  network.on("click", (p) => {
    const id = p.nodes[0];
    if (id && id !== INTERNET) openPanel(id); else if (!p.nodes.length) closePanel();
  });
  network.once("stabilizationIterationsDone", () => network.fit({animation: {duration: 600}}));
}

function setPhysics(on) {
  physicsOn = on;
  network.setOptions({physics: {enabled: on}});
  $("btnPhysics").innerHTML = `<i class="fa-solid ${on ? "fa-lock-open" : "fa-lock"}"></i>`;
}

function syncMap(layout) {
  let gatewayId = null, selfId = null;
  for (const d of devices.values()) {
    if (d.is_gateway) gatewayId = d.id;
    if (d.is_self) selfId = d.id;
  }
  const hub = gatewayId || selfId;
  const wantNodes = new Map();
  const wantEdges = new Map();
  if (gatewayId) {
    wantNodes.set(INTERNET, {id: INTERNET, title: "Internet / WAN"});
    wantEdges.set(`e-${INTERNET}`, {id: `e-${INTERNET}`, from: INTERNET, to: gatewayId, width: 3,
      color: {color: "#38bdf8", opacity: 0.6}, dashes: false});
  }
  for (const d of devices.values()) {
    const hidden = !matches(d);
    wantNodes.set(d.id, {id: d.id, title: tooltip(d), hidden: hidden && d.id !== hub, mass: d.id === hub ? 4 : 1});
    if (hub && d.id !== hub) {
      wantEdges.set(`e-${d.id}`, {id: `e-${d.id}`, from: hub, to: d.id, hidden, ...edgeStyle(d)});
    }
  }
  if (typeof transformGraph === "function") transformGraph(wantNodes, wantEdges, hub, gatewayId);
  nodes.remove(nodes.getIds().filter((id) => !wantNodes.has(id)));
  edges.remove(edges.getIds().filter((id) => !wantEdges.has(id)));
  nodes.update([...wantNodes.values()]);
  edges.update([...wantEdges.values()]);

  // Apply a saved layout once (or whenever it changes on the server).
  const key = JSON.stringify(layout || {});
  const starMode = typeof netLayout === "undefined" || netLayout === "star";
  if (key !== layoutKey && starMode) {
    layoutKey = key;
    const pos = layout || {};
    const ids = Object.keys(pos).filter((id) => nodes.get(id));
    if (ids.length) {
      setPhysics(false);
      nodes.update(ids.map((id) => ({id, x: pos[id].x, y: pos[id].y})));
      setTimeout(() => network.fit({animation: {duration: 500}}), 50);
    }
  }
  network.redraw();
  $("empty").classList.toggle("hidden", devices.size > 0);
}

/* ------------------------------------------------------------ sidebar */
function sortKey(d) {
  const p = d.ip.split(".").map((n) => n.padStart(3, "0")).join(".");
  return `${d.online ? 0 : 1}-${p}`;
}

function renderList() {
  const list = [...devices.values()];
  if (typeof renderAltViews === "function") renderAltViews();
  const on = list.filter((d) => d.online).length;
  $("sOnline").textContent = on;
  $("sOffline").textContent = list.length - on;
  $("sUntrusted").textContent = list.filter((d) => !d.trusted).length;
  $("sIssues").textContent = list.filter(hasIssue).length;
  if (typeof renderSidebar === "function") renderSidebar();
}

const EV_ICON = {new: "fa-plus", online: "fa-arrow-up", offline: "fa-arrow-down", ip: "fa-right-left",
  port: "fa-door-open", security: "fa-triangle-exclamation", traffic: "fa-skull-crossbones"};
function renderEvents(events) {
  window.lpEvents = events || [];
  if (typeof setActivity === "function") setActivity(events);
}

function renderMeta() {
  $("mSubnet").textContent = meta.subnet || "—";
  $("mIface").textContent = meta.iface || "—";
  $("mGateway").textContent = meta.gateway ? `gw ${meta.gateway}` : "no gateway";
  if ($("mVer")) $("mVer").textContent = meta.version ? `v${meta.version}` : "";
  $("mDemo").classList.toggle("hidden", !meta.demo);
  $("mNoAuth").classList.toggle("hidden", !!meta.auth || !!meta.demo);
  $("btnLogout").classList.toggle("hidden", !meta.auth);
}

function tickClock() {
  if (meta.last_sweep) $("mLast").textContent = `Last sweep ${ago(meta.last_sweep)} · ${meta.sweep_ms} ms`;
  if (selected && devices.has(selected)) {
    const el = $("lastSeen");
    if (el) el.textContent = ago(devices.get(selected).last_seen);
  }
}

/* ------------------------------------------------------------ detail panel */
function openPanel(id) {
  selected = id;
  if (typeof selectedIp !== "undefined") selectedIp = null;
  renderPanel(true);
  $("panel").classList.add("open");
  $("panel").setAttribute("aria-hidden", "false");
  network.selectNodes([id]);
  renderList();
  if (window.innerWidth < 900) $("sidebar").classList.remove("open");
  loadHistory();
  if (typeof loadDeviceLocal === "function") loadDeviceLocal(id);
  if (typeof loadDeviceFlows === "function") loadDeviceFlows(id);
  if (typeof loadDeviceDns === "function") loadDeviceDns(id);
  if (typeof loadDeviceVulns === "function") loadDeviceVulns(id);
  if (typeof loadDeviceOv === "function") loadDeviceOv(id);
  if (typeof loadDeviceTimeline === "function") loadDeviceTimeline(id);
  clearInterval(historyTimer);
  historyTimer = setInterval(() => {
    loadHistory();
    if (typeof loadDeviceTimeline === "function" && selected) loadDeviceTimeline(selected, true);
  }, 60000);
}
function closePanel() {
  selected = null;
  if (typeof selectedIp !== "undefined") selectedIp = null;
  clearInterval(historyTimer);
  $("panel").classList.remove("open");
  $("panel").setAttribute("aria-hidden", "true");
  network.unselectAll();
  renderList();
}

/* Panel sections that fold. The choice is remembered, because the panel is redrawn on every update. */
const FOLD = (() => { try { return JSON.parse(localStorage.getItem("lp_fold") || "{}"); } catch (_) { return {}; } })();
document.addEventListener("toggle", (e) => {
  const k = e.target.dataset && e.target.dataset.fold;
  if (!k || FOLD[k] === e.target.open) return;
  FOLD[k] = e.target.open;
  try { localStorage.setItem("lp_fold", JSON.stringify(FOLD)); } catch (_) {}
}, true);

function renderPanel(force) {
  const d = devices.get(selected);
  if (!d) { closePanel(); return; }
  // Don't wipe a form the user is typing in.
  if (!force && $("panelBody").contains(document.activeElement) &&
      ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) return;
  const histHtml = !force && $("histBox") ? $("histBox").innerHTML : `<div class="muted">Loading history…</div>`;
  const localHtml = !force && $("localBox") ? $("localBox").innerHTML : "";
  const flowHtml = !force && $("flowBox") ? $("flowBox").innerHTML : "";
  const dnsHtml = !force && $("dnsBox") ? $("dnsBox").innerHTML : "";
  const vulnHtml = !force && $("vulnBox") ? $("vulnBox").innerHTML : "";
  const ovHtml = !force && $("ovBox") ? $("ovBox").innerHTML : "";
  const tlHtml = !force && $("tlBox") ? $("tlBox").innerHTML : `<div class="muted">Loading timeline…</div>`;
  const t = typeOf(d);
  const st = d.scanning ? `<span class="badge scan"><i class="fa-solid fa-spinner fa-spin"></i>Scanning</span>`
    : d.online ? `<span class="badge on"><span class="dot on"></span>Online</span>`
    : `<span class="badge off"><span class="dot off"></span>Offline</span>`;
  const ports = (d.ports || []).slice().sort((a, b) => a.port - b.port);
  const portRows = ports.map((p) => {
    const secure = p.service === "https" || [443, 5001, 8006, 8443].includes(p.port);
    const web = HTTP_PORTS.has(p.port) || (p.service || "").includes("http");
    const link = web ? `<a href="${secure ? "https" : "http"}://${esc(d.ip)}:${p.port}" target="_blank" rel="noopener">${p.port}</a>` : p.port;
    return `<tr><td>${link}/${esc(p.proto)}</td><td>${esc(p.service || "?")}</td><td class="muted">${esc(p.product || "")}</td></tr>`;
  }).join("");
  const finds = d.findings || [];
  const findHtml = finds.length
    ? finds.map((f) => `<div class="finding ${f.dismissed ? "dismissed" : ""}"><span class="sev ${f.dismissed ? "ok" : f.level}">${f.dismissed ? "accepted" : f.level}</span><span>${esc(f.text)}</span><span class="port">:${f.port}</span>
        ${f.level !== "low" ? `<button class="linkbtn" data-${f.dismissed ? "undismiss" : "dismiss"}="${esc(f.text)}" title="${f.dismissed ? "Start warning about this again" : "Accept this risk (a lab machine, say). It stays listed here but stops showing in Needs attention."}">${f.dismissed ? "Undo" : "Dismiss"}</button>` : ""}</div>`).join("")
    : d.deep_scanned_at ? `<div class="ok-line"><i class="fa-solid fa-circle-check"></i>No risky services found.</div>`
    : `<div class="muted">Waiting for the first port scan.</div>`;
  const typeOpts = [`<option value="auto">Auto-detect (${esc(TYPES[d.type_auto]?.label || d.type_auto)})</option>`]
    .concat(Object.entries(TYPES).filter(([k]) => k !== "internet")
      .map(([k, v]) => `<option value="${k}" ${d.type_override === k ? "selected" : ""}>${esc(v.label)}</option>`)).join("");
  const OS_PICK = {
    Windows: ["Windows 11", "Windows 10", "Windows 8.1", "Windows 8", "Windows 7", "Windows Vista", "Windows XP", "Windows 2000", "Windows Server 2022", "Windows Server 2019", "Windows Server 2016", "Windows Server 2012 R2", "Windows Server 2012", "Windows Server 2008 R2", "Windows Server 2008", "Windows Server 2003"],
    Linux: ["Ubuntu 24.04", "Ubuntu 22.04", "Ubuntu 20.04", "Ubuntu 18.04", "Debian 12", "Debian 11", "Debian 10", "Raspberry Pi OS", "Fedora", "Red Hat / CentOS / Rocky / Alma", "Arch Linux", "openSUSE / SUSE", "Alpine Linux", "Other Linux"],
    Other: ["macOS", "iOS / iPadOS", "Android", "ChromeOS", "FreeBSD", "OpenWrt", "Other"],
  };
  const osOpts = `<option value="auto">Auto-detect${d.os_override ? "" : d.os ? ` (${esc(d.os)})` : ""}</option>`
    + Object.entries(OS_PICK).map(([g, list]) => `<optgroup label="${g}">${list.map(o => `<option value="${esc(o)}" ${d.os_override === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</optgroup>`).join("");

  $("panelBody").innerHTML = `
    <div class="p-head" style="--c:${t.color}">
      <div class="p-icon"><i class="${faClass(t)}"></i></div>
      <div><div class="p-title">${esc(nameOf(d))}</div>
        <div class="badges">${st}<span class="badge"><i class="${faClass(t)}"></i>${esc(t.label)}</span>
        ${d.trusted ? "" : '<span class="badge warn"><i class="fa-solid fa-user-secret"></i>Not trusted</span>'}
        ${d.watched ? '<span class="badge watch"><i class="fa-solid fa-eye"></i>Watched</span>' : ""}
        ${d.is_gateway ? '<span class="badge">Gateway</span>' : ""}${d.is_self ? '<span class="badge">This host</span>' : ""}</div></div>
    </div>
    <div class="p-sec"><div class="actions">
      <button class="btn ${d.trusted ? "toggle-on" : ""}" id="bTrust" ${d.is_self || d.is_gateway ? "disabled" : ""}>
        <i class="fa-solid ${d.trusted ? "fa-shield-halved" : "fa-user-check"}"></i>${d.trusted ? "Trusted" : "Trust device"}</button>
      <button class="btn ${d.watched ? "toggle-on" : ""}" id="bWatch"><i class="fa-solid ${d.watched ? "fa-eye" : "fa-eye-slash"}"></i>${d.watched ? "Watching" : "Watch"}</button>
      <button class="btn" id="bWake" ${d.mac && !d.online ? "" : "disabled"} title="Send a Wake-on-LAN packet"><i class="fa-solid fa-power-off"></i>Wake</button>
      <button class="btn" id="bRescan" ${d.online ? "" : "disabled"}><i class="fa-solid fa-rotate"></i>Rescan</button>
      <button class="btn ${d.thorough ? "toggle-on" : ""}" id="bThorough" ${d.online || d.thorough ? "" : "disabled"}
        title="Scan all 65,535 ports with full version detection. Finds much more software to check for vulnerabilities; takes a few minutes. Good for lab machines and servers.">
        <i class="fa-solid fa-magnifying-glass-plus"></i>${d.thorough ? "Thorough scans on" : "Thorough scan"}</button>
    </div></div>
    <div class="p-sec"><h4>Last 24 hours</h4><div id="histBox">${histHtml}</div></div>
    <div class="p-sec ${localHtml ? "" : "hidden"}" id="localBox">${localHtml}</div>
    <div class="p-sec ${flowHtml ? "" : "hidden"}" id="flowBox">${flowHtml}</div>
    <div class="p-sec ${dnsHtml ? "" : "hidden"}" id="dnsBox">${dnsHtml}</div>
    <div class="p-sec ${vulnHtml ? "" : "hidden"}" id="vulnBox">${vulnHtml}</div>
    <div class="p-sec ${ovHtml ? "" : "hidden"}" id="ovBox">${ovHtml}</div>
    <div class="p-sec"><h4>Security</h4>${findHtml}</div>
    <details class="p-sec fold" data-fold="timeline" ${FOLD.timeline ? "open" : ""}><summary><h4>Timeline</h4></summary><div id="tlBox">${tlHtml}</div></details>
    ${d.model || d.friendly || (d.evidence || []).length || (d.services || []).length ? `<details class="p-sec fold" data-fold="ident" ${FOLD.ident ? "open" : ""}><summary><h4>Identification</h4><span class="hint muted">${esc(d.model || d.friendly || "")}</span></summary><dl class="kv">
      ${d.model ? `<dt>Model</dt><dd>${esc(d.model)}</dd>` : ""}
      ${d.friendly ? `<dt>Calls itself</dt><dd>${esc(d.friendly)}</dd>` : ""}
      ${(d.services || []).length ? `<dt>Services</dt><dd class="chips-wrap">${d.services.map((x) => `<span class="svc">${esc(x)}</span>`).join("")}</dd>` : ""}
      </dl>${(d.evidence || []).length ? `<div class="evid">${d.evidence.map((e) => `<span class="ev-chip"><i class="fa-solid fa-fingerprint"></i>${esc(e)}</span>`).join("")}</div>` : ""}
    </details>` : ""}
    <details class="p-sec fold" data-fold="network" ${FOLD.network ? "open" : ""}><summary><h4>Network</h4><span class="hint muted">${esc(d.ip)}${d.vendor ? ` · ${esc(d.vendor)}` : ""}</span></summary><dl class="kv">
      <dt>IP address</dt><dd>${esc(d.ip)}</dd>
      <dt>MAC address</dt><dd>${esc(d.mac || "—")}${d.randomized_mac ? ' <span class="muted">(private)</span>' : ""}</dd>
      <dt>Vendor</dt><dd>${esc(d.vendor || "Unknown")}</dd>
      <dt>Hostname</dt><dd>${esc(d.hostname || "—")}</dd>
      <dt>Latency</dt><dd>${d.online && d.rtt_ms != null ? d.rtt_ms + " ms" : "—"}</dd>
      ${(d.ip_history || []).length > 1 ? `<dt>Past IPs</dt><dd>${esc([...new Set(d.ip_history)].join(", "))}</dd>` : ""}
    </dl></details>
    <details class="p-sec fold" data-fold="system" ${FOLD.system ? "open" : ""}><summary><h4>System</h4><span class="hint muted">${esc(d.os || "")}</span></summary><dl class="kv">
      <dt>OS guess</dt><dd>${esc(d.os || "—")}</dd>
      ${d.os_accuracy ? `<dt>Confidence</dt><dd>${d.os_accuracy}%<div class="bar"><div style="width:${d.os_accuracy}%"></div></div></dd>` : ""}
      <dt>First seen</dt><dd>${esc(full(d.first_seen))}</dd>
      <dt>Last seen</dt><dd id="lastSeen">${ago(d.last_seen)}</dd>
      <dt>Port scan</dt><dd>${d.deep_scanned_at ? ago(d.deep_scanned_at) : d.scanning ? "in progress…" : "pending"}</dd>
    </dl></details>
    <details class="p-sec fold" data-fold="ports" ${FOLD.ports ? "open" : ""}><summary><h4>Open ports</h4><span class="hint muted">${ports.length}</span></summary>
      ${ports.length ? `<table class="ports"><tr><th>Port</th><th>Service</th><th>Product</th></tr>${portRows}</table>`
        : `<div class="muted">${d.deep_scanned_at ? "No open TCP ports found." : "Not scanned yet."}</div>`}
    </details>
    <details class="p-sec fold" data-fold="customize" ${FOLD.customize ? "open" : ""}><summary><h4>Customize</h4><span class="hint muted">name, type, OS, notes</span></summary><div class="form">
      <label for="eName">Display name</label><input id="eName" maxlength="64" placeholder="${esc(d.hostname || d.vendor || "e.g. Living room TV")}" value="${esc(d.name)}">
      <label for="eType">Device type</label><select id="eType">${typeOpts}</select>
      <label for="eOs">Operating system</label><select id="eOs">${osOpts}</select>
      <label for="eNotes">Notes</label><textarea id="eNotes" maxlength="2000" placeholder="Location, owner, purpose…">${esc(d.notes)}</textarea>
      <div class="btns">
        <button class="btn primary" id="bSave"><i class="fa-solid fa-floppy-disk"></i>Save</button>
        ${!d.online ? `<button class="btn danger" id="bForget"><i class="fa-solid fa-trash"></i>Forget device</button>` : ""}
      </div></div></details>`;

  const dev = (path = "") => `/api/devices/${encodeURIComponent(d.id)}${path}`;
  const post = async (body) => {        // change the device, then show the change on its timeline
    const r = await api(dev(), "POST", body);
    if (r && typeof loadDeviceTimeline === "function") loadDeviceTimeline(d.id, true);
    return r;
  };
  $("bSave").onclick = async () => {
    if (await post({name: $("eName").value.trim(), type: $("eType").value, os: $("eOs").value, notes: $("eNotes").value})) {
      document.activeElement.blur(); toast("Saved");
    }
  };
  $("bTrust").onclick = async () => {
    if (await post({trusted: !d.trusted})) toast(d.trusted ? "Marked as not trusted" : "Device trusted");
  };
  $("bWatch").onclick = async () => {
    if (await post({watched: !d.watched}))
      toast(d.watched ? "No longer watching" : "Watching: you'll get an alert when it goes offline");
  };
  $("bWake").onclick = async () => { if (await api(dev("/wake"), "POST")) toast("Wake-on-LAN packet sent"); };
  $("bRescan").onclick = async () => { if (await api(dev("/rescan"), "POST")) toast("Rescan queued"); };
  $("bThorough").onclick = async () => {
    if (await post({thorough: !d.thorough}))
      toast(d.thorough ? "Back to quick scans" : "Thorough scan started. It takes a few minutes; vulnerabilities update when it's done.");
  };
  if ($("bForget")) {
    $("bForget").onclick = async (e) => {
      const b = e.currentTarget;
      if (b.dataset.armed !== "1") {         // two-step confirm, no browser dialog
        b.dataset.armed = "1"; b.innerHTML = `<i class="fa-solid fa-trash"></i>Tap again to forget`;
        setTimeout(() => { if (b.isConnected) { b.dataset.armed = ""; b.innerHTML = `<i class="fa-solid fa-trash"></i>Forget device`; } }, 4000);
        return;
      }
      if (await api(dev(), "DELETE")) { closePanel(); toast("Device removed"); }
    };
  }
  if (!force && $("spark") && lastHist) drawSpark($("spark"), lastHist);
}

/* ------------------------------------------------------------ history */
async function loadHistory() {
  const id = selected;
  if (!id) return;
  const h = await api(`/api/devices/${encodeURIComponent(id)}/history?hours=24`, "GET");
  if (!h || id !== selected || !$("histBox")) return;
  lastHist = h;
  const segs = h.presence.map((p) => {
    const cls = p === null ? "na" : p >= 0.98 ? "" : p <= 0.02 ? "down" : "part";
    return `<span class="${cls}" title="${p === null ? "not tracked" : Math.round(p * 100) + "% online"}"></span>`;
  }).join("");
  $("histBox").innerHTML = `
    <div class="hist-head"><span class="muted">Uptime</span><span class="big">${h.uptime_pct != null ? h.uptime_pct + "%" : "—"}</span></div>
    <div class="upbar" role="img" aria-label="Online over the last 24 hours">${segs}</div>
    <div class="axis"><span>24h ago</span><span>18h</span><span>12h</span><span>6h</span><span>now</span></div>
    <canvas class="spark" id="spark" aria-label="Latency over the last 24 hours"></canvas>
    <div class="spark-cap"><span>Latency</span><span>avg ${h.rtt_avg ?? "—"} ms · max ${h.rtt_max ?? "—"} ms</span></div>`;
  drawSpark($("spark"), h);
}

function drawSpark(cv, h) {
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, ht = cv.clientHeight;
  cv.width = w * dpr; cv.height = ht * dpr;
  const ctx = cv.getContext("2d");
  ctx.scale(dpr, dpr);
  const padL = 30, padR = 8, padT = 8, padB = 8;
  const t0 = h.start, t1 = h.start + h.hours * 3600;
  const pts = h.rtt;
  const maxV = Math.max(5, ...pts.map((p) => p[1]));
  const nice = maxV <= 10 ? 10 : maxV <= 25 ? 25 : maxV <= 50 ? 50 : maxV <= 100 ? 100 : Math.ceil(maxV / 100) * 100;
  const X = (t) => padL + (t - t0) / (t1 - t0) * (w - padL - padR);
  const Y = (v) => padT + (1 - v / nice) * (ht - padT - padB);
  ctx.font = "10px 'JetBrains Mono', monospace"; ctx.textAlign = "right"; ctx.textBaseline = "middle";
  for (const v of [0, nice / 2, nice]) {
    ctx.strokeStyle = "#1f2a44"; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(padL, Y(v)); ctx.lineTo(w - padR, Y(v)); ctx.stroke();
    ctx.fillStyle = "#5b6b88"; ctx.fillText(String(v), padL - 5, Y(v));
  }
  if (!pts.length) {
    ctx.textAlign = "center"; ctx.fillStyle = "#8b9bb6"; ctx.font = "12px Inter, system-ui, sans-serif";
    ctx.fillText("No latency data yet", (w + padL) / 2, ht / 2); return;
  }
  // Break the line wherever the device was offline for more than 3 minutes.
  const runs = [[]];
  const gaps = pts.slice(1).map((p, i) => p[0] - pts[i][0]).sort((a, b) => a - b);
  const step = gaps.length ? gaps[Math.floor(gaps.length / 2)] : 60;
  const maxGap = Math.max(180, step * 2.5);
  pts.forEach((p, i) => { if (i && p[0] - pts[i - 1][0] > maxGap) runs.push([]); runs[runs.length - 1].push(p); });
  const grad = ctx.createLinearGradient(0, padT, 0, ht - padB);
  grad.addColorStop(0, "rgba(56,189,248,.35)"); grad.addColorStop(1, "rgba(56,189,248,0)");
  for (const run of runs) {
    if (run.length === 1) { ctx.fillStyle = "#38bdf8"; ctx.fillRect(X(run[0][0]) - 1, Y(run[0][1]) - 1, 2, 2); continue; }
    ctx.beginPath(); ctx.moveTo(X(run[0][0]), Y(0));
    run.forEach((p) => ctx.lineTo(X(p[0]), Y(p[1])));
    ctx.lineTo(X(run[run.length - 1][0]), Y(0)); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
    ctx.beginPath(); run.forEach((p, i) => (i ? ctx.lineTo : ctx.moveTo).call(ctx, X(p[0]), Y(p[1])));
    ctx.strokeStyle = "#38bdf8"; ctx.lineWidth = 1.5; ctx.stroke();
  }
  const last = pts[pts.length - 1];
  ctx.beginPath(); ctx.arc(X(last[0]), Y(last[1]), 3.5, 0, 2 * Math.PI);
  ctx.fillStyle = "#38bdf8"; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = "#0e1527"; ctx.stroke();
}

/* ------------------------------------------------------------ settings */
const CHANNELS = {
  ntfy: {label: "ntfy push", icon: "fa-bell", hint: "Phone notifications via ntfy.sh or your own ntfy server.",
    fields: [["url", "Topic URL", "full"], ["token", "Access token (optional)", "full", "password"]]},
  telegram: {label: "Telegram", icon: "fa-paper-plane", hint: "Messages from your own Telegram bot.",
    fields: [["bot_token", "Bot token", "full", "password"], ["chat_id", "Chat ID", "full"]]},
  webhook: {label: "Webhook", icon: "fa-link", hint: "Discord, Slack, Home Assistant or any URL that accepts JSON.",
    fields: [["url", "Webhook URL", "full"]]},
  email: {label: "Email", icon: "fa-envelope", hint: "Send through any SMTP server.",
    fields: [["host", "SMTP server"], ["port", "Port", "", "number"], ["user", "Username"], ["password", "Password", "", "password"],
      ["from", "From address"], ["to", "Send to"], ["starttls", "Use STARTTLS", "full", "checkbox"]]},
  irc: {label: "IRC", icon: "fa-hashtag", hint: "Post alerts into an IRC channel.",
    fields: [["host", "Server"], ["port", "Port", "", "number"], ["nick", "Nickname"], ["channel", "Channel"], ["key", "Channel key (optional)", "", "password"],
      ["tls", "Use TLS", "", "checkbox"], ["tls_verify", "Verify TLS certificate", "full", "checkbox"]]},
};
const RULES = [
  ["new_device", "New device joins", "Alert when a device that isn't trusted appears on the network."],
  ["watched_offline", "Watched device goes offline", "Alert when a watched device stops responding, and when it returns."],
  ["new_port", "New open port", "Alert when a device starts offering a service it didn't have before."],
  ["security", "Security warning", "Alert when a scan finds a high-risk service such as Telnet or VNC."],
  ["local_threats", "Threats inside your network", "Alert when a LAN device scans the network, impersonates the router or touches a honeypot."],
  ["attacks", "Attacks from the internet", "Alert when an attack gets through to a LAN device, or one IP makes a burst of attempts."],
];
let settings = null;
let setTab = "rules";

async function openSettings() {
  settings = await api("/api/settings", "GET");
  if (!settings) return;
  $("settings").classList.remove("hidden");
  renderSettings();
}
function closeSettings() { $("settings").classList.add("hidden"); }

function renderSettings() {
  document.querySelectorAll("#setTabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === setTab));
  const body = $("setBody");
  if (setTab === "rules") {
    const untrusted = [...devices.values()].filter((d) => !d.trusted).length;
    body.innerHTML = `<p class="hint">Choose what sends an alert. Pick where alerts go in the next tab.</p>
      ${RULES.map(([k, title, txt]) => `<div class="rule"><label class="switch"><input type="checkbox" id="r_${k}" ${settings.rules[k] ? "checked" : ""}><span></span></label>
        <div class="txt"><b>${title}</b><small>${txt}</small></div></div>`).join("")}
      <div class="rule"><div class="txt"><b>Trust every device on the map now</b><small>${untrusted} device${untrusted === 1 ? " isn't" : "s aren't"} trusted yet. Do this once after checking the list, so only newcomers alert.</small></div>
        <button class="btn" id="bTrustAll" ${untrusted ? "" : "disabled"}><i class="fa-solid fa-user-check"></i>Trust all</button></div>
      <div class="chan"><div class="chan-head"><i class="fa-solid fa-newspaper ci"></i>
        <div class="txt"><b>Daily summary</b><small>A short report of the last 24 hours, sent to your alert channels.</small></div>
        <label class="switch"><input type="checkbox" id="s_sum_on" ${settings.summary.enabled ? "checked" : ""}><span></span></label></div>
        <div class="chan-fields">
          <label>Send at (server time)<input id="s_sum_time" type="time" value="${esc(settings.summary.time || "08:00")}"></label>
          <div class="full btns"><button class="btn" id="bSumPrev"><i class="fa-solid fa-eye"></i>Preview</button>
            <button class="btn" id="bSumSend"><i class="fa-solid fa-paper-plane"></i>Send now</button><span class="test-res" id="sumRes"></span></div>
          <pre class="code full hidden" id="sumText"></pre>
        </div></div>
      <div class="modal-foot"><button class="btn primary" id="bSaveSet"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>`;
    $("bTrustAll").onclick = async () => { if (await api("/api/trust-all", "POST")) { toast("All devices trusted"); renderSettings(); } };
    $("bSumPrev").onclick = async () => {
      const r = await api("/api/summary/preview", "GET");
      if (r) { $("sumText").textContent = r.text; $("sumText").classList.remove("hidden"); }
    };
    $("bSumSend").onclick = async () => {
      $("sumRes").className = "test-res"; $("sumRes").textContent = "Sending…";
      const r = await api("/api/summary/send", "POST", null, true);
      $("sumRes").className = `test-res ${r && r.ok ? "ok" : "bad"}`;
      $("sumRes").textContent = r && r.ok ? "Sent." : `Failed: ${r ? (r.error || Object.values(r.errors || {}).join("; ")) : "no response"}`;
      if (r && r.text) { $("sumText").textContent = r.text; $("sumText").classList.remove("hidden"); }
    };
  } else if (setTab === "channels") {
    body.innerHTML = `<p class="hint">Turn on one or more ways to receive alerts, then send a test.</p>` +
      Object.entries(CHANNELS).map(([k, c]) => {
        const v = settings.channels[k];
        const fields = c.fields.map(([f, label, span, type]) => type === "checkbox"
          ? `<label class="chk ${span}"><input type="checkbox" id="c_${k}_${f}" ${v[f] ? "checked" : ""}>${label}</label>`
          : `<label class="${span}">${label}<input id="c_${k}_${f}" type="${type || "text"}" value="${esc(v[f])}" autocomplete="off"></label>`).join("");
        return `<div class="chan"><div class="chan-head"><i class="fa-solid ${c.icon} ci"></i>
          <div class="txt"><b>${c.label}</b><small>${c.hint}</small></div>
          <label class="switch"><input type="checkbox" id="c_${k}_enabled" ${v.enabled ? "checked" : ""}><span></span></label></div>
          <div class="chan-fields ${v.enabled ? "" : "hidden"}" id="cf_${k}">${fields}
          <div class="full btns"><button class="btn" data-test="${k}"><i class="fa-solid fa-vial"></i>Save &amp; send test</button>
          <span class="test-res" id="tr_${k}"></span></div></div></div>`;
      }).join("") +
      `<div class="modal-foot"><button class="btn primary" id="bSaveSet"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>`;
    Object.keys(CHANNELS).forEach((k) => {
      $(`c_${k}_enabled`).onchange = (e) => $(`cf_${k}`).classList.toggle("hidden", !e.target.checked);
    });
    body.querySelectorAll("[data-test]").forEach((b) => b.onclick = async () => {
      const k = b.dataset.test, res = $(`tr_${k}`);
      if (!(await saveSettings(true))) return;
      res.className = "test-res"; res.textContent = "Sending…";
      const r = await api(`/api/settings/test/${k}`, "POST");
      res.className = `test-res ${r && r.ok ? "ok" : "bad"}`;
      res.textContent = r && r.ok ? "Test sent. Check that it arrived." : `Failed: ${r ? r.error : "no response"}`;
    });
  } else if (setTab === "threats") {
    renderThreatSettings(body);
  } else if (setTab === "unifi") {
    renderUnifiSettings(body);
  } else if (setTab === "scanner") {
    renderScanner(body);
  } else if (setTab === "backup") {
    renderBackupSettings(body);
  } else if (setTab === "update") {
    renderUpdate(body);
  } else if (setTab === "system") {
    renderSystem(body);
  } else if (setTab === "appearance") {
    renderAppearance(body);
  } else {
    const on = !!meta.auth;
    body.innerHTML = `<p class="hint">${on ? "The dashboard requires a login. Change it here." :
      "Anyone on your network can open this dashboard. Set a username and password to require a login."}</p>
      <div class="form chan-fields" style="padding:0">
        ${on ? `<label class="full">Current password<input id="aCur" type="password" autocomplete="current-password"></label>` : ""}
        <label class="full">Username<input id="aUser" value="admin" autocomplete="username"></label>
        <label>New password<input id="aNew" type="password" autocomplete="new-password"></label>
        <label>Repeat password<input id="aRep" type="password" autocomplete="new-password"></label>
      </div>
      <div class="modal-foot"><span class="test-res bad" id="aErr"></span>
        <button class="btn primary" id="bAcct"><i class="fa-solid fa-key"></i>${on ? "Change login" : "Set login"}</button></div>`;
    $("bAcct").onclick = async () => {
      const nw = $("aNew").value;
      if (nw.length < 8) { $("aErr").textContent = "Use at least 8 characters."; return; }
      if (nw !== $("aRep").value) { $("aErr").textContent = "The two passwords don't match."; return; }
      const r = await api("/api/account", "POST", {user: $("aUser").value.trim(), new_password: nw,
        current_password: on ? $("aCur").value : ""}, true);
      if (r && r.ok) { toast("Login saved"); closeSettings(); } else $("aErr").textContent = r?.error || "Couldn't save the login.";
    };
  }
  const save = $("bSaveSet");
  if (save) save.onclick = () => saveSettings();
}

function renderBackupSettings(body) {
  body.innerHTML = `<p class="hint">Create a protected copy of LanPulse data. Backups include settings, history and credentials, so keep downloaded copies private.</p>
    <div class="chan">
      <div class="chan-head"><i class="fa-solid fa-database ci"></i><div class="txt"><b>Create a backup</b><small>Save a verified backup without stopping LanPulse.</small></div></div>
      <div class="chan-fields">
        <label class="full">Backup location<input id="backupLocation" value="" readonly></label>
        <div class="full btns"><button class="btn primary" id="bBackupNow"><i class="fa-solid fa-box-archive"></i>Create backup now</button><span class="test-res" id="backupResult"></span></div>
      </div>
    </div>
    <div class="chan">
      <div class="chan-head"><i class="fa-solid fa-clock-rotate-left ci"></i><div class="txt"><b>Saved backups</b><small>Download a copy to keep somewhere safe.</small></div>
        <button class="btn sm" id="bBackupRefresh" title="Refresh backup list"><i class="fa-solid fa-rotate"></i></button></div>
      <div id="backupList" style="padding:0 12px 12px"><p class="hint">Loading backups…</p></div>
    </div>
    <p class="hint">Downloading requires a dashboard login. Restoring remains a maintenance operation and is done with the documented command-line procedure.</p>`;
  const list = $("backupList");
  const refresh = async () => {
    list.innerHTML = '<p class="hint">Loading backups…</p>';
    const result = await api("/api/backups", "GET");
    if (!result) { list.innerHTML = '<p class="hint">Could not load backups.</p>'; return; }
    const locationField = $("backupLocation");
    if (locationField && result.location) locationField.value = result.location;
    if (!result.backups || !result.backups.length) { list.innerHTML = '<p class="hint">No backups yet. Select “Create backup now” to make the first one.</p>'; return; }
    list.innerHTML = result.backups.map((item) => {
      const size = item.size >= 1048576 ? (item.size / 1048576).toFixed(1) + " MB" : (item.size / 1024).toFixed(0) + " KB";
      const action = meta.auth ? `<a class="btn sm" href="/api/backups/${encodeURIComponent(item.name)}"><i class="fa-solid fa-download"></i>Download</a>` : '<span class="test-res">Set a login to download</span>';
      return `<div class="rule"><div class="txt"><b>${esc(item.name)}</b><small>${esc(item.created)} · ${size}</small></div>${action}</div>`;
    }).join("");
  };
  $("bBackupRefresh").onclick = refresh;
  $("bBackupNow").onclick = async () => {
    const button = $("bBackupNow"), status = $("backupResult");
    button.disabled = true; status.className = "test-res"; status.textContent = "Creating and verifying backup…";
    const result = await api("/api/backups", "POST", null, true);
    button.disabled = false;
    if (result && result.ok) { status.className = "test-res ok"; status.textContent = "Backup created successfully."; }
    else { status.className = "test-res bad"; status.textContent = result?.error || "Backup failed. Check the service log."; }
    await refresh();
  };
  refresh();
}

function collectSettings() {
  if (setTab === "threats") collectThreatSettings();
  if (setTab === "unifi") collectUnifiSettings();
  if (setTab === "rules" && $("s_sum_on")) {
    settings.summary.enabled = $("s_sum_on").checked;
    settings.summary.time = $("s_sum_time").value || "08:00";
  }
  if (setTab === "rules") RULES.forEach(([k]) => { settings.rules[k] = $(`r_${k}`).checked; });
  if (setTab === "channels") {
    for (const [k, c] of Object.entries(CHANNELS)) {
      settings.channels[k].enabled = $(`c_${k}_enabled`).checked;
      for (const [f, , , type] of c.fields) {
        const el = $(`c_${k}_${f}`);
        settings.channels[k][f] = type === "checkbox" ? el.checked : el.value;
      }
    }
  }
}
async function saveSettings(quiet) {
  collectSettings();
  const r = await api("/api/settings", "POST", settings);
  if (r) { settings = r; if (!quiet) toast("Settings saved"); }
  return !!r;
}

/* ------------------------------------------------------------ server calls */
async function api(url, method, body, keepErrors) {
  try {
    const r = await fetch(url, {method, headers: body ? {"Content-Type": "application/json"} : {},
      body: body ? JSON.stringify(body) : undefined});
    if (r.status === 401) { location.href = "/login"; return null; }
    const data = await r.json().catch(() => null);
    if (!r.ok) {
      if (keepErrors) return data;
      toast(data?.error || `Request failed (${r.status})`); return null;
    }
    return data || {};
  } catch (e) {
    toast("Can't reach LanPulse. Check that the service is running.");
    return null;
  }
}

let toastTimer;
function toast(msg) {
  const el = $("toast");
  el.textContent = msg; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

/* ------------------------------------------------------------ live data */
let bootVersion = "";
function applySnapshot(s) {
  const prevSweep = meta.last_sweep;
  meta = s.meta || {};
  if (!bootVersion) bootVersion = meta.version || "";
  else if (meta.version && meta.version !== bootVersion && typeof showUpdatedBar === "function") showUpdatedBar(meta.version);
  devices = new Map(s.devices.map((d) => [d.id, d]));
  renderMeta();
  syncMap(s.layout);
  renderList();
  renderEvents(s.events || []);
  if (selected) renderPanel(false);
  if (meta.last_sweep !== prevSweep) {
    const p = $("pulse"); p.classList.remove("beat"); void p.offsetWidth; p.classList.add("beat");
  }
  tickClock();
}

function setConn(state, text) {
  const c = $("conn");
  c.className = `conn ${state}`;
  c.querySelector("span").textContent = text;
}

let retry = 1000;
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  let ping;
  ws.onopen = () => { setConn("ok", "Live"); retry = 1000; ping = setInterval(() => ws.readyState === 1 && ws.send("ping"), 25000); };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "snapshot") applySnapshot(msg);
    else if (msg.type === "threat") addThreatEvent(msg.event);
    else if (msg.type === "threat_summary") onThreatSummary(msg);
    else if (msg.type === "local_threat") addLocalEvent(msg.event);
    else if (msg.type === "local_summary") onLocalSummary(msg);
    else if (msg.type === "flows" && typeof onFlows === "function") onFlows(msg);
    else if (msg.type === "dns" && typeof onDnsLive === "function") onDnsLive(msg);
    else if (msg.type === "services" && typeof onServicesLive === "function") onServicesLive(msg);
  };
  ws.onclose = (e) => {
    clearInterval(ping);
    if (e.code === 4401) { location.href = "/login"; return; }
    setConn("bad", "Reconnecting");
    setTimeout(connect, retry); retry = Math.min(retry * 2, 15000);
  };
  ws.onerror = () => ws.close();
}

/* ------------------------------------------------------------ boot */
function initUI() {
  $("fType").innerHTML = `<option value="">All device types</option>` +
    Object.entries(TYPES).filter(([k]) => k !== "internet").map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join("");
  $("legend").innerHTML = Object.entries(TYPES).map(([, v]) =>
    `<span><i class="${faClass(v)}" style="color:${v.color}"></i>${esc(v.label)}</span>`).join("") +
    `<span><i class="fa-regular fa-circle" style="color:#ef4444"></i>Red dashed ring: not trusted</span>
     <span><i class="fa-solid fa-triangle-exclamation" style="color:#fbbf24"></i>Security warning</span>
     <span><i class="fa-solid fa-circle" style="color:#38bdf8"></i>Blue dot: watched</span>`;
  const refilter = () => { syncMap(JSON.parse(layoutKey || "{}")); renderList(); };
  $("q").addEventListener("input", refilter);
  $("fType").addEventListener("change", refilter);
  $("fOffline").addEventListener("change", refilter);
  document.querySelectorAll(".stat").forEach((b) => b.addEventListener("click", () => {
    statFilter = statFilter === b.dataset.filter ? "" : b.dataset.filter;
    document.querySelectorAll(".stat").forEach((s) => s.classList.toggle("active", s.dataset.filter === statFilter));
    refilter();
  }));
  $("btnClose").onclick = closePanel;
  $("btnFit").onclick = () => network.fit({animation: {duration: 500}});
  $("btnPhysics").onclick = () => { setPhysics(!physicsOn); toast(physicsOn ? "Layout unlocked" : "Layout frozen. Drag devices where you like."); };
  $("btnSaveLayout").onclick = async () => {
    const pos = network.getPositions();
    delete pos[INTERNET];
    setPhysics(false);
    if (await api("/api/layout", "POST", {positions: pos})) toast("Layout saved for everyone");
  };
  $("btnResetLayout").onclick = async () => {
    if (await api("/api/layout", "POST", {positions: {}})) { setPhysics(true); network.stabilize(150); toast("Automatic layout restored"); }
  };
  $("btnLegend").onclick = () => $("legend").classList.toggle("hidden");
  $("btnSidebar").onclick = () => (typeof toggleSidebar === "function" ? toggleSidebar() : $("sidebar").classList.toggle("open"));
  $("btnSettings").onclick = openSettings;
  $("btnSetClose").onclick = closeSettings;
  $("settings").addEventListener("click", (e) => { if (e.target.id === "settings") closeSettings(); });
  document.querySelectorAll("#setTabs button").forEach((b) => b.onclick = () => {
    if (!["account", "update", "system", "scanner"].includes(setTab)) collectSettings();
    setTab = b.dataset.tab; renderSettings();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!$("settings").classList.contains("hidden")) closeSettings(); else closePanel();
  });
  window.addEventListener("resize", () => { if ($("spark")) loadHistory(); });
  setInterval(tickClock, 1000);
}

async function loadIconFonts() {
  try {
    await Promise.all([
      document.fonts.load('900 20px "Font Awesome 6 Free"'),
      document.fonts.load('400 20px "Font Awesome 6 Brands"'),
    ]);
  } catch (_) { /* icons fall back gracefully */ }
}

(async function boot() {
  initUI();
  initMap();
  await loadIconFonts();
  network.redraw();
  connect();
})();
