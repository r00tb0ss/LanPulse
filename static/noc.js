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

let nocMisses = 0;
async function nocTick() {
  const [p, t, topo, hp, sv, fl, fc] = await Promise.all([api("/api/posture?days=30", "GET"), api("/api/threats/summary?hours=24", "GET"),
    api("/api/topology", "GET"), api("/api/honeypot?hours=24", "GET"), api("/api/services", "GET"), api("/api/flows?hours=1", "GET"),
    api("/api/flows?hours=24", "GET")]);
  // a wall display runs unattended: say so on screen when the server stops answering instead of silently going stale
  nocMisses = p || t ? 0 : nocMisses + 1;
  if ($("nocStale")) $("nocStale").classList.toggle("hidden", nocMisses < 2);
  if (nocMisses) return;
  if ($("nocUpd")) $("nocUpd").textContent = "updated " + new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  if (p) { postureData = p; nocScore(p); }
  if (t) nocStats(t);
  nocMapUpdate(t);
  nocFeed();
  nocCompromised(fc);
  nocHealth(topo); nocServices(sv); nocHoneypot(hp); nocTalkers(fl);
}

const nocTileHead = (icon, title, sub) => `<h4><i class="fa-solid ${icon}"></i> ${esc(title)}${sub ? `<span class="muted">${sub}</span>` : ""}</h4>`;

function nocHealth(d) {
  const el = $("nocHealth");
  if (!el) return;
  if (!d || !d.nodes) { el.innerHTML = nocTileHead("fa-network-wired", "Network health") + `<div class="muted">Waiting for the network map…</div>`; return; }
  const infra = d.nodes.filter((n) => ["gateway", "switch", "ap"].includes(n.kind));
  const down = infra.filter((n) => !n.online);
  const wifi = d.nodes.filter((n) => n.link && n.link.medium === "wifi" && n.kind === "client");
  const weak = wifi.filter((n) => n.link.quality === "poor");
  const state = down.length ? "bad" : weak.length ? "warn" : "ok";
  el.innerHTML = nocTileHead("fa-network-wired", "Network health") + `
    <div class="noc-big ${state}">${down.length ? `${down.length} DOWN` : weak.length ? "FAIR" : "HEALTHY"}</div>
    <div class="noc-line"><span>Switches, APs, gateway</span><b class="${down.length ? "bad" : ""}">${infra.length - down.length}/${infra.length} up</b></div>
    ${down.length ? `<div class="noc-line bad">${down.slice(0, 3).map((n) => esc(n.name)).join(", ")} offline</div>` : ""}
    <div class="noc-line"><span>Wi-Fi clients</span><b>${wifi.length}${weak.length ? ` · <span class="warn">${weak.length} weak</span>` : ""}</b></div>`;
}

function nocServices(s) {
  const el = $("nocSvc");
  if (!el) return;
  if (!s || !s.total) { el.innerHTML = nocTileHead("fa-heart-pulse", "Services") + `<div class="muted">No services monitored yet. Add some in the Services tab.</div>`; return; }
  const bad = (s.checks || []).filter((c) => c.up === false);
  const slow = [...(s.checks || [])].filter((c) => c.up === true && c.ms != null).sort((a, b) => b.ms - a.ms)[0];
  el.innerHTML = nocTileHead("fa-heart-pulse", "Services") + `
    <div class="noc-big ${bad.length ? "bad" : "ok"}">${s.up}<small>/${s.total} up</small></div>
    ${bad.length ? bad.slice(0, 3).map((c) => `<div class="noc-line bad"><span>${esc(c.name)}</span><b>down</b></div>`).join("")
      : `<div class="noc-line"><span>Everything is answering</span></div>`}
    ${slow ? `<div class="noc-line"><span>Slowest: ${esc(slow.name)}</span><b>${Math.round(slow.ms)} ms</b></div>` : ""}`;
}

function nocHoneypot(h) {
  const el = $("nocPot");
  if (!el) return;
  if (!h || !h.totals) { el.innerHTML = nocTileHead("fa-jar", "Honeypot") + `<div class="muted">Waiting for data…</div>`; return; }
  if (!h.enabled && !h.totals.all_time) { el.innerHTML = nocTileHead("fa-jar", "Honeypot") + `<div class="muted">Off. Turn it on in the Honeypot tab.</div>`; return; }
  const t = h.totals, top = (h.attackers || []).find((a) => !a.internal), cred = (h.creds || [])[0];
  el.innerHTML = nocTileHead("fa-jar", "Honeypot", "24h") + `
    <div class="noc-big ${t.internal ? "bad" : ""}">${fmtN(t.hits)}<small> hits</small></div>
    <div class="noc-line"><span>From your own network</span><b class="${t.internal ? "bad" : ""}">${t.internal ? t.internal + " ⚠" : "none"}</b></div>
    ${top ? `<div class="noc-line"><span>Top: ${typeof flag === "function" && top.iso ? flag(top.iso) + " " : ""}<span class="mono">${esc(top.ip)}</span></span><b>${top.hits}×</b></div>` : ""}
    ${cred ? `<div class="noc-line"><span>Top login</span><b class="mono">${esc(cred.cred)}</b></div>` : ""}`;
}

function nocTalkers(f) {
  const el = $("nocTalk");
  if (!el) return;
  const tk = ((f && f.talkers) || []).slice(0, 4);
  if (!tk.length) { el.innerHTML = nocTileHead("fa-arrow-right-arrow-left", "Busiest devices", "last hour") + `<div class="muted">No device traffic logged yet.</div>`; return; }
  const max = Math.max(1, ...tk.map((x) => x.count));
  el.innerHTML = nocTileHead("fa-arrow-right-arrow-left", "Busiest devices", "last hour") +
    tk.map((x) => `<div class="noc-cbar"><span class="cn">${esc(x.name || x.ip)}</span><span class="cb"><span style="width:${Math.round(100 * x.count / max)}%;background:var(--accent)"></span></span><span class="cc">${fmtN(x.count)}</span></div>`).join("");
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

function nocCompromised(f) {
  const el = $("nocAlert");
  if (!el) return;
  // Use the flow summary this tick fetched. The Threats tab's copy is only loaded once someone opens its traffic layer,
  // so relying on it would show a green "all clear" on a wall display that never checked.
  const src = f || (typeof flowSummary !== "undefined" ? flowSummary : null);
  if (!src) {
    el.className = "noc-tile noc-alert";
    el.innerHTML = `<div class="noc-alert-big"><i class="fa-solid fa-hourglass-half"></i> Checking for compromised devices…</div>
      <div class="noc-alert-row muted">Waiting for connection data.</div>`;
    return;
  }
  const comp = src.compromised || [];
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
  if (!host) return;
  nocCountries();                                  // the country list doesn't need the map
  if (typeof echarts === "undefined" || !echarts.getMap || !echarts.getMap("world")) {
    // the map library loads on demand: if the Operations Center is the first thing opened, fetch it now (once)
    if (!nocInitMap.tried && typeof loadWorldLib === "function") {
      nocInitMap.tried = true;
      loadWorldLib().then(() => { if (typeof fixWorldMap === "function") fixWorldMap(); setTimeout(nocInitMap, 50); });
    }
    return;
  }
  if (nocChart) return;
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

function nocApplyDim(on) {
  const el = $("noc");
  if (el) el.classList.toggle("dim", on);
  const b = $("nocDim");
  if (b) b.setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("lp_noc_dim", on ? "1" : "0"); } catch (_) {}
}

(function initNoc() {
  const d = $("nocDim");
  if (d) {
    let on = false;
    try { on = localStorage.getItem("lp_noc_dim") === "1"; } catch (_) {}
    nocApplyDim(on);
    d.onclick = () => nocApplyDim(!$("noc").classList.contains("dim"));
  }
  const b = $("btnNoc");
  if (b) b.onclick = openNoc;
  const c = $("nocClose");
  if (c) c.onclick = closeNoc;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("noc") && !$("noc").classList.contains("hidden")) closeNoc(); });
})();
