// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* NOC / wall-display mode: a full-screen live operations dashboard, for a TV or second monitor. Reuses the data
   the app already has (security score, attacks, devices, flows) and refreshes on a timer while open. */

let nocTimer = null, nocClockTimer = null, nocChart = null;

async function openNoc() {
  const el = $("noc");
  if (!el) return;
  el.classList.remove("hidden");
  el.setAttribute("aria-hidden", "false");
  document.body.classList.add("noc-open");
  nocTick();
  nocTimer = setInterval(nocTick, 15000);
  nocClockTimer = setInterval(nocClock, 1000);
  nocClock();
  setTimeout(nocInitMap, 60);
}

function closeNoc() {
  const el = $("noc");
  if (!el) return;
  el.classList.add("hidden");
  el.setAttribute("aria-hidden", "true");
  document.body.classList.remove("noc-open");
  clearInterval(nocTimer); clearInterval(nocClockTimer);
  if (nocChart) { try { nocChart.dispose(); } catch (_) {} nocChart = null; }
}

function nocClock() {
  const c = $("nocClock");
  if (c) c.textContent = new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
}

async function nocTick() {
  const [p, t] = await Promise.all([api("/api/posture?days=30", "GET"), api("/api/threats/summary?hours=24", "GET")]);
  if (p) { postureData = p; nocScore(p); }
  if (t) nocStats(t);
  nocMapUpdate(t);
  nocFeed();
  nocCompromised();
}

function nocScore(p) {
  const el = $("nocScore");
  if (!el) return;
  const col = (typeof GRADE_COLOR !== "undefined" && GRADE_COLOR[p.grade]) || "#38bdf8";
  el.style.setProperty("--gc", col);
  el.innerHTML = `<div class="noc-lbl">Risk Profile</div>
    <div class="noc-biggrade">${esc(p.grade)}</div>
    <div class="noc-scorenum">${p.score}<small>/100</small></div>
    <div class="noc-fixes">${(p.fixes || []).slice(0, 3).map((f) => `<div>• ${esc(f.text)}</div>`).join("") || "<div>No issues found</div>"}</div>`;
}

function nocStats(t) {
  const el = $("nocStats");
  if (!el) return;
  const online = [...devices.values()].filter((d) => d.online).length;
  const reached = Math.max(0, (t.total || 0) - (t.blocked || 0));
  const pct = t.total ? Math.round(100 * t.blocked / t.total) : 0;
  const tiles = [
    ["Devices online", `${online}<small>/${devices.size}</small>`, ""],
    ["Attacks 24h", fmtN(t.total || 0), ""],
    ["Blocked", pct + "%", ""],
    ["Reached LAN", fmtN(reached), reached ? "bad" : ""],
    ["Attacking IPs", fmtN(t.unique || 0), ""],
    ["Countries", fmtN(t.countries_n || 0), ""],
  ];
  el.innerHTML = tiles.map(([l, v, c]) => `<div class="noc-stat ${c}"><span class="nv">${v}</span><span class="nl">${esc(l)}</span></div>`).join("");
}

function nocCompromised() {
  const el = $("nocAlert");
  if (!el) return;
  const comp = (typeof flowSummary !== "undefined" && flowSummary && flowSummary.compromised) || [];
  if (comp.length) {
    el.className = "noc-tile noc-alert danger";
    el.innerHTML = `<div class="noc-alert-big"><i class="fa-solid fa-triangle-exclamation"></i> ${comp.length} POSSIBLY COMPROMISED</div>
      ${comp.slice(0, 3).map((c) => `<div class="noc-alert-row"><b>${esc(c.name)}</b> → known botnet C2 ${esc((c.c2s[0] || {}).ip || "")}</div>`).join("")}`;
  } else {
    el.className = "noc-tile noc-alert ok";
    el.innerHTML = `<div class="noc-alert-big"><i class="fa-solid fa-shield-halved"></i> No compromised devices</div>
      <div class="noc-alert-row muted">No device is talking to a known malware server.</div>`;
  }
}

function nocFeed() {
  const el = $("nocFeed");
  if (!el) return;
  const evs = (window.lpEvents || []).slice(-12).reverse();
  el.innerHTML = evs.map((e) => `<div class="noc-ev ${esc(e.kind || "")}"><span class="t">${clock(e.t)}</span><span>${esc(e.text)}</span></div>`).join("")
    || `<div class="muted">Waiting for activity…</div>`;
}

function nocCountries() {
  const el = $("nocCountries");
  if (!el || typeof tSummary === "undefined" || !tSummary) return;
  const cs = (tSummary.countries || []).slice(0, 8);
  const max = Math.max(1, ...cs.map((c) => c.count));
  el.innerHTML = cs.map((c) => `<div class="noc-cbar"><span class="cn">${typeof flag === "function" ? flag(c.iso) : ""} ${esc(c.country)}</span>
    <span class="cb"><span style="width:${Math.round(100 * c.count / max)}%"></span></span><span class="cc">${fmtN(c.count)}</span></div>`).join("")
    || `<div class="muted">No attacks recorded.</div>`;
}

// A dedicated small world map for the NOC (separate ECharts instance from the main map).
function nocInitMap() {
  const host = $("nocMap");
  if (!host || typeof echarts === "undefined" || !echarts.getMap || !echarts.getMap("world")) return;
  try {
    nocChart = echarts.init(host, null, {renderer: "canvas"});
    const area = (typeof cssVar === "function" ? cssVar("--map-area", "#16243f") : "#16243f");
    const border = (typeof cssVar === "function" ? cssVar("--map-border", "#2b4170") : "#2b4170");
    nocChart.setOption({
      backgroundColor: "transparent",
      geo: {map: "world", roam: false, zoom: 1.2, center: [12, 22], silent: true,
        itemStyle: {areaColor: area, borderColor: border, borderWidth: 0.5}, regions: []},
      series: [{id: "a", type: "effectScatter", coordinateSystem: "geo", data: [], zlevel: 2,
        rippleEffect: {brushType: "stroke", scale: 2.8}, symbolSize: (v) => v[2]}],
    });
    nocMapUpdate(typeof tSummary !== "undefined" ? tSummary : null);
    nocCountries();
  } catch (_) {}
}

function nocMapUpdate(t) {
  if (!nocChart || !t) return;
  const max = Math.max(1, ...(t.countries || []).map((c) => c.count));
  try {
    nocChart.setOption({
      geo: {regions: (t.countries || []).map((c) => ({name: (typeof MAP_NAMES !== "undefined" && MAP_NAMES[c.country]) || c.country,
        itemStyle: {areaColor: `rgba(244,63,94,${(0.1 + 0.5 * c.count / max).toFixed(2)})`}}))},
      series: [{id: "a", data: (t.attackers || []).filter((a) => a.lat != null).slice(0, 120).map((a) => ({
        value: [a.lon, a.lat, 4 + Math.min(14, Math.sqrt(a.count) * 1.3)],
        itemStyle: {color: a.tag ? "#8b9bb6" : "#f43f5e"}}))}],
    });
    nocCountries();
  } catch (_) {}
}

(function initNoc() {
  const b = $("btnNoc");
  if (b) b.onclick = openNoc;
  const c = $("nocClose");
  if (c) c.onclick = closeNoc;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("noc") && !$("noc").classList.contains("hidden")) closeNoc(); });
})();
