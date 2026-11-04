// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* LanPulse device traffic layer: where your devices connect on the internet. Loaded after threats.js. */

let tLayer = (() => { try { return localStorage.getItem("lp_layer") || "attacks"; } catch (_) { return "attacks"; } })();
let flowSummary = null;
let flowDevice = "";
let flowArcs = [];
let flowLoadedAt = 0;
const FLOW_COLORS = ["#2dd4bf", "#a78bfa", "#fbbf24", "#60a5fa", "#f472b6", "#34d399", "#fb923c", "#22d3ee", "#c084fc", "#facc15"];

const showAttacks = () => tLayer !== "traffic";
const showTraffic = () => tLayer !== "attacks";
const devColor = (ip) => FLOW_COLORS[[...String(ip)].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7) % FLOW_COLORS.length];

/* ------------------------------------------------------------ layer switching */
function setLayer(layer) {
  tLayer = layer;
  try { localStorage.setItem("lp_layer", layer); } catch (_) {}
  applyLayer();
  if (showTraffic()) loadFlows();
}

function applyLayer() {
  document.querySelectorAll("#tLayer button").forEach((b) => {
    b.classList.toggle("on", b.dataset.layer === tLayer);
    b.setAttribute("aria-pressed", String(b.dataset.layer === tLayer));
  });
  document.body.classList.toggle("traffic-on", showTraffic());
  $("tDevice").classList.toggle("hidden", !showTraffic());
  if (!showAttacks()) { arcs = []; drawArcs(); }
  if (!showTraffic()) { flowArcs = []; drawFlowArcs(); }
  updateWorld();
}

/* ------------------------------------------------------------ data */
async function loadFlows() {
  const r = await api(`/api/flows?hours=${tHours}${flowDevice ? `&device=${encodeURIComponent(flowDevice)}` : ""}`, "GET");
  if (!r) return;
  flowSummary = r;
  flowLoadedAt = Date.now();
  renderTraffic();
  updateWorld();
  if (!flowArcs.length) (r.recent || []).slice(0, 15).reverse().forEach((e, i) => setTimeout(() => pushFlowArc(e), i * 200));
}

function onFlows(msg) {
  const items = (msg.items || []).filter((e) => !flowDevice || e.src === flowDevice);
  if (!items.length) return;
  items.filter((e) => e.bad && e.src_id).forEach((e) => underAttack.set(e.src_id, Date.now()));
  if (view !== "threats" || !showTraffic()) return;
  items.slice(0, 12).forEach(pushFlowArc);
  const list = $("tFlowLive");
  if (list) {
    if (!list.querySelector(".fl")) list.innerHTML = "";
    list.insertAdjacentHTML("afterbegin", items.slice(0, 8).map(flowRow).join(""));
    [...list.querySelectorAll(".fl")].slice(0, 8).forEach((el) => el.classList.add("fresh"));
    while (list.childElementCount > 30) list.lastElementChild.remove();
  }
  if (flowSummary) {
    flowSummary.total += msg.total || items.length;
    const k = $("fkTotal");
    if (k) k.textContent = fmtN(flowSummary.total);
  }
  if (Date.now() - flowLoadedAt > 30000) loadFlows();
}

/* ------------------------------------------------------------ map */
function pushFlowArc(e) {
  const home = homeCoord();
  if (!tChart || !home || e.lat == null || !showTraffic()) return;
  const color = e.bad ? "#f43f5e" : devColor(e.src);
  flowArcs.push({at: Date.now(), coords: [home, [e.lon, e.lat]], lineStyle: {color, width: e.bad ? 2 : 1}});
  if (flowArcs.length > 30) flowArcs = flowArcs.slice(-30);
  drawFlowArcs();
}
function drawFlowArcs() {
  if (tChart) tChart.setOption({series: [{id: "flowArcs", data: flowArcs.map(({coords, lineStyle}) => ({coords, lineStyle}))}]});
}
setInterval(() => {
  const n = flowArcs.length;
  flowArcs = flowArcs.filter((a) => Date.now() - a.at < 6000);
  if (flowArcs.length !== n && view === "threats") drawFlowArcs();
}, 1000);

function updateTrafficLayer() {
  if (!tChart) return;
  const on = showTraffic() && flowSummary;
  const dests = on ? flowSummary.dests.filter((d) => d.lat != null) : [];
  const max = Math.max(1, ...dests.map((d) => d.count));
  tChart.setOption({series: [{id: "dests", data: dests.map((d) => ({
    name: d.ip, d, value: [d.lon, d.lat, d.count], size: 4 + 12 * Math.sqrt(d.count / max),
    itemStyle: {color: d.bad ? "#f43f5e" : "#2dd4bf", opacity: d.bad ? 1 : 0.85, borderColor: "#0a1122", borderWidth: 1,
      shadowBlur: d.bad ? 12 : 6, shadowColor: d.bad ? "#f43f5e" : "#2dd4bf"}}))}]});
  if (!showTraffic()) { flowArcs = []; drawFlowArcs(); }
  if (typeof updateCountryLabels === "function") updateCountryLabels();
}

/* ------------------------------------------------------------ card */
function flowRow(e) {
  return `<button class="fl ${e.bad ? "bad" : ""}" data-dst="${esc(e.dst)}" style="--c:${e.bad ? "#f43f5e" : devColor(e.src)}">
    <span class="fl-dev">${esc(e.src_name || e.src)}</span><i class="fa-solid fa-arrow-right-long"></i>
    <span class="fl-dst">${flag(e.iso)} ${esc(e.org || e.dst)}</span><span class="fl-port">:${e.dport}</span>
    <time>${clock(e.t)}</time></button>`;
}

function renderTraffic() {
  const f = flowSummary;
  if (!f || !$("tTrafficCard")) return;
  const empty = !f.total && !meta.demo;
  $("tTrafficSetup").classList.toggle("hidden", !empty);
  $("tTrafficGrid").classList.toggle("hidden", empty);
  $("tTrafficStatus").textContent = f.last_flow ? `last connection ${ago(f.last_flow)}` : "";
  if (empty) {
    $("tTrafficSetup").innerHTML = `<div class="t-setup" style="margin:0"><h3><i class="fa-solid fa-plug-circle-bolt"></i>Turn on outbound logging</h3>
      <p>LanPulse learns where devices connect from your router's log of outbound connections. On your UDM:</p>
      <ol><li>Settings → Policy Engine → create a policy: <b>Action</b> Allow, <b>Source zone</b> Internal, <b>Destination zone</b> External,
        <b>Connection state</b> New, and turn <b>Syslog Logging</b> on.</li>
      <li>Keep syslog going to this server on UDP ${esc(tSummary?.sources?.syslog_port || 514)} (already set up for the attack map).</li></ol>
      <p>Connections start appearing within a minute. Busy networks log a lot of lines; LanPulse stores them as per-minute totals.</p></div>`;
    return;
  }
  const bad = f.bad || [];
  $("tTrafficKpis").innerHTML = `
    <div class="kpi"><span class="k-lbl">Connections</span><span class="k-num" id="fkTotal">${fmtN(f.total)}</span><span class="k-sub">last ${f.hours === 168 ? "7 days" : f.hours + "h"}</span></div>
    <div class="kpi"><span class="k-lbl">Destinations</span><span class="k-num">${fmtN(f.destinations)}</span><span class="k-sub">${f.countries.length} countries</span></div>
    <div class="kpi ${bad.length ? "danger" : ""}"><span class="k-lbl">Talked to attackers</span><span class="k-num">${bad.length}</span>
      <span class="k-sub">${bad.length ? bad.slice(0, 2).map((b) => esc(b.srcs[0]?.name || b.ip)).join(", ") : "none"}</span></div>`;
  const omax = Math.max(1, ...f.orgs.map((o) => o.count));
  $("tOrgs").innerHTML = [
    ...bad.slice(0, 3).map((b) => `<div class="rk click hot" data-dst="${esc(b.ip)}"><span class="ico"><i class="fa-solid fa-skull-crossbones" style="color:#f43f5e"></i></span>
      <span class="nm"><b style="color:#fda4af">${esc(b.ip)}</b> <span class="muted">attacked you</span></span><span class="ct">${fmtN(b.count)}</span><div class="bar"><i style="width:100%"></i></div></div>`),
    ...f.orgs.slice(0, 8).map((o) => `<div class="rk click" data-org="${esc(o.org)}"><span class="ico"><i class="fa-solid fa-building" style="color:#5b6b88"></i></span>
      <span class="nm">${esc(o.org)}</span><span class="ct">${fmtN(o.count)}</span><div class="bar"><i style="width:${(100 * o.count / omax).toFixed(1)}%;background:#2dd4bf"></i></div></div>`),
  ].join("") || `<div class="muted">No connections yet.</div>`;
  const tmax = Math.max(1, ...f.talkers.map((t) => t.count));
  $("tTalkers").innerHTML = f.talkers.slice(0, 8).map((t) => { const ty = TYPES[t.type] || TYPES.unknown;
    return `<div class="rk click" data-dev-ip="${esc(t.ip)}" title="Show only this device"><span class="ico"><i class="${faClass(ty)}" style="color:${ty.color}"></i></span>
      <span class="nm">${esc(t.name)} <span class="muted">${fmtN(t.dests)} place${t.dests === 1 ? "" : "s"}</span></span><span class="ct">${fmtN(t.count)}</span>
      <div class="bar"><i style="width:${(100 * t.count / tmax).toFixed(1)}%;background:${devColor(t.ip)}"></i></div></div>`; }).join("") || `<div class="muted">—</div>`;
  if (!$("tFlowLive").querySelector(".fl")) $("tFlowLive").innerHTML = (f.recent || []).slice(0, 20).map(flowRow).join("") || `<div class="muted">Waiting for connections…</div>`;
  // device filter options
  const sel = $("tDevice"), cur = flowDevice;
  const opts = [...devices.values()].sort((a, b) => nameOf(a).localeCompare(nameOf(b)));
  sel.innerHTML = `<option value="">All devices</option>` + opts.map((d) => `<option value="${esc(d.ip)}" ${d.ip === cur ? "selected" : ""}>${esc(nameOf(d))}</option>`).join("");
}

/* ------------------------------------------------------------ destination panel */
function openDest(d) {
  selected = null; selectedIp = null;
  const srcs = d.srcs || [];
  $("panelBody").innerHTML = `
    <div class="p-head" style="--c:${d.bad ? "#f43f5e" : "#2dd4bf"}">
      <div class="p-icon"><i class="fa-solid ${d.bad ? "fa-skull-crossbones" : "fa-server"}"></i></div>
      <div><div class="p-title">${esc(d.org || "Unknown network")}</div>
        <div class="badges"><span class="badge">${flag(d.iso)} ${esc(placeOf(d))}</span>
        ${d.bad ? '<span class="badge risk-high"><i class="fa-solid fa-triangle-exclamation"></i>This IP attacked you</span>' : ""}</div></div>
    </div>
    ${d.bad ? `<div class="p-sec"><div class="lrow high" style="cursor:default"><span class="lic"><i class="fa-solid fa-triangle-exclamation"></i></span>
      <div class="ltxt"><b>A device on your network contacted an attacker</b><div class="muted">This address showed up in your attack log. A device calling it back can mean it's compromised.</div></div></div>
      <div class="btns" style="margin-top:10px"><button class="btn danger-solid" id="bDestInvestigate"><i class="fa-solid fa-user-ninja"></i>Investigate attacker</button></div></div>` : ""}
    <div class="p-sec"><div class="minis">
      <div class="mini"><b>${fmtN(d.count)}</b><small>connections</small></div>
      <div class="mini"><b>${d.devices}</b><small>device${d.devices === 1 ? "" : "s"}</small></div></div></div>
    <div class="p-sec"><h4>Destination</h4><dl class="kv">
      <dt>IP address</dt><dd>${esc(d.ip)}</dd>
      <dt>Owner</dt><dd>${esc(d.org || "Unknown")}${d.asn ? ` <span class="muted">AS${d.asn}</span>` : ""}</dd>
      <dt>Location</dt><dd>${esc(placeOf(d))}</dd>
      <dt>Ports</dt><dd>${(d.ports || []).join(", ") || "—"}</dd></dl></div>
    <div class="p-sec"><h4>Devices connecting</h4>${srcs.map((s) => { const dev = devices.get(s.id); const ty = dev ? typeOf(dev) : TYPES.unknown;
      return `<div class="tgt-row" data-dev="${esc(s.id)}" style="--c:${ty.color}"><div class="ic"><i class="${faClass(ty)}"></i></div>
        <div><b>${esc(s.name)}</b><div class="muted" style="font:11px var(--mono)">${esc(s.ip)}</div></div></div>`; }).join("") || '<div class="muted">—</div>'}</div>
    <div class="p-sec"><h4>Look it up</h4><div class="links">
      ${[["Shodan", `https://www.shodan.io/host/${d.ip}`], ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${d.ip}`],
         ["AbuseIPDB", `https://www.abuseipdb.com/check/${d.ip}`]].map(([n, u]) =>
        `<a href="${esc(u)}" target="_blank" rel="noopener">${n}<i class="fa-solid fa-arrow-up-right-from-square" style="font-size:10px"></i></a>`).join("")}</div></div>`;
  $("panel").classList.add("open");
  $("panel").setAttribute("aria-hidden", "false");
  $("panelBody").querySelectorAll("[data-dev]").forEach((el) => el.onclick = () => goDevice(el.dataset.dev));
  if ($("bDestInvestigate")) $("bDestInvestigate").onclick = () => openIp(d.ip);
  if (view === "threats" && d.lat != null) flyTo([d.lon, d.lat], Math.max(geoView().zoom, 3.5));
}

/* ------------------------------------------------------------ device panel: where it connects */
async function loadDeviceFlows(id) {
  const d = devices.get(id);
  if (!d) return;
  const f = await api(`/api/devices/${encodeURIComponent(id)}/flows?hours=24`, "GET");
  const box = $("flowBox");
  if (!f || selected !== id || !box) return;
  if (!f.total) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const max = Math.max(1, ...f.orgs.map((o) => o.count));
  box.classList.remove("hidden");
  box.innerHTML = `<h4>Where it connects · last 24h</h4>
    ${(f.bad || []).length ? `<div class="finding"><span class="sev high">alert</span><span>Contacted ${f.bad.length} IP${f.bad.length > 1 ? "s" : ""} that attacked you: ${f.bad.slice(0, 3).map((b) => esc(b.ip)).join(", ")}</span></div>` : ""}
    <div class="rank" style="margin-top:6px">${f.orgs.slice(0, 6).map((o) => `<div class="rk"><span class="ico"><i class="fa-solid fa-building" style="color:#5b6b88"></i></span>
      <span class="nm">${esc(o.org)}</span><span class="ct">${fmtN(o.count)}</span><div class="bar"><i style="width:${(100 * o.count / max).toFixed(1)}%;background:#2dd4bf"></i></div></div>`).join("")}</div>
    <div class="btns" style="margin-top:10px"><button class="btn" id="bShowFlows" data-ip="${esc(d.ip)}"><i class="fa-solid fa-earth-americas"></i>Show on map</button></div>`;
}

/* The panel re-renders on every snapshot and copies this section's HTML, which drops
   per-element handlers, so the button is handled by delegation instead. */
function showDeviceOnMap(ip) {
  flowDevice = ip;
  flowArcs = [];
  if (tLayer === "attacks") tLayer = "traffic";
  setView("threats");
  setLayer(tLayer);
  const sel = $("tDevice");
  if (![...sel.options].some((o) => o.value === ip)) sel.insertAdjacentHTML("beforeend", `<option value="${esc(ip)}">${esc(ip)}</option>`);
  sel.value = ip;
  $("tFlowLive").innerHTML = "";
  if ($("tRegion")) $("tRegion").value = "world";
  if (typeof flyToRegion === "function") flyToRegion("world");
  setTimeout(() => $("tTrafficCard")?.scrollIntoView({behavior: "smooth", block: "nearest"}), 400);
}

/* ------------------------------------------------------------ wiring */
(function initTraffic() {
  $("tLayer").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setLayer(b.dataset.layer); });
  $("panel").addEventListener("click", (e) => { const b = e.target.closest("#bShowFlows"); if (b) showDeviceOnMap(b.dataset.ip); });
  $("tDevice").onchange = (e) => { flowDevice = e.target.value; flowArcs = []; drawFlowArcs(); $("tFlowLive").innerHTML = ""; loadFlows(); };
  $("tOrgs").addEventListener("click", (e) => {
    const r = e.target.closest("[data-dst],[data-org]");
    if (!r || !flowSummary) return;
    const d = r.dataset.dst ? flowSummary.dests.find((x) => x.ip === r.dataset.dst)
      : flowSummary.dests.filter((x) => x.org === r.dataset.org).sort((a, b) => b.count - a.count)[0];
    if (d) openDest(d);
  });
  $("tTalkers").addEventListener("click", (e) => {
    const r = e.target.closest("[data-dev-ip]");
    if (!r) return;
    flowDevice = flowDevice === r.dataset.devIp ? "" : r.dataset.devIp;
    $("tDevice").value = flowDevice; flowArcs = []; drawFlowArcs(); $("tFlowLive").innerHTML = ""; loadFlows();
  });
  $("tFlowLive").addEventListener("click", (e) => {
    const r = e.target.closest("[data-dst]");
    const d = r && flowSummary && flowSummary.dests.find((x) => x.ip === r.dataset.dst);
    if (d) openDest(d); else if (r) toast("Details appear after the next refresh");
  });
  $("tRange").addEventListener("change", () => { if (showTraffic()) loadFlows(); });
  $("vThreat").addEventListener("click", () => { if (showTraffic()) loadFlows(); });
  applyLayer();
})();
