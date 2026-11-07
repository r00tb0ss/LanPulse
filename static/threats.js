// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* LanPulse threats view: live world attack map, feed, stats and attacker investigation. Loaded after app.js. */

let view = "net";
let tSummary = null;
let tHours = 24;
let tChart = null;
let arcs = [];
let unseen = 0;
let selectedIp = null;
let lastRangeFetch = 0;
const reachedIps = new Set();
let hideScanners = (() => { try { return localStorage.getItem("nm_hide_scanners") === "1"; } catch (_) { return false; } })();
let blockedIps = new Set();
const leakIps = new Set();      // on the blocklist, yet still reaching a device (seen live): the UDM isn't enforcing the list
let unifiReady = false;
let localSummary = null;
const isScanner = (x) => !!(x && x.tag);
const SCANNER_COLOR = "#7c8aa5";
const feedKeys = new Set();

const flag = (iso) => iso && /^[A-Za-z]{2}$/.test(iso)
  ? String.fromCodePoint(...[...iso.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))) : "";
const flagHtml = (iso) => flag(iso) || '<i class="fa-solid fa-globe" style="color:#5b6b88;font-size:16px"></i>';
const placeOf = (e) => [e.city, e.country].filter(Boolean).join(", ") || "Unknown location";
const isReached = (e) => e.action !== "blocked" && !!e.lan;
const fmtN = (n) => (n ?? 0).toLocaleString();
const MAP_NAMES = {"South Korea": "Korea", "North Korea": "Dem. Rep. Korea", "Czechia": "Czech Rep.",
  "Bosnia and Herzegovina": "Bosnia and Herz.", "Dominican Republic": "Dominican Rep.", "Laos": "Lao PDR",
  "Central African Republic": "Central African Rep.", "South Sudan": "S. Sudan", "Ivory Coast": "Côte d'Ivoire"};

/* ------------------------------------------------------------ view switching */
const VIEWS = [["vNet", "net", "netView"], ["vThreat", "threats", "threatView"], ["vDns", "dns", "dnsView"],
  ["vVuln", "vulns", "vulnView"], ["vSvc", "svc", "svcView"], ["vRed", "redteam", "redView"],
  ["vPot", "honeypot", "potView"]];
const viewHooks = {};            // view name -> function run when it opens (registered by each view's script)

function setView(v) {
  view = v;
  document.body.classList.toggle("mode-threats", v !== "net");     // hides network-only controls
  for (const [btn, name, el] of VIEWS) {
    if (!$(btn) || !$(el)) continue;
    $(el).classList.toggle("hidden", v !== name);
    $(btn).classList.toggle("on", v === name);
    $(btn).setAttribute("aria-selected", String(v === name));
  }
  try { localStorage.setItem("lp_view", v); } catch (_) {}
  closePanel();
  if (viewHooks[v]) viewHooks[v]();
  if (v !== "threats" && mapIsFull()) toggleMapFull(false);
  if (v !== "threats" && tChart) {
    try { pendingGeoView = geoView(); } catch (_) { pendingGeoView = null; }
    try { tChart.dispose(); } catch (_) {}
    tChart = null;
    $("worldMap").innerHTML = "";
  }
  if (v === "threats") {
    // Build the map fresh each time the tab opens. A canvas that sat hidden can come back blank in some
    // browsers (the page keeps the chart, but the drawing is gone), and rebuilding is quick.
    if (tChart) {
      try { pendingGeoView = geoView(); } catch (_) { pendingGeoView = null; }
      try { tChart.dispose(); } catch (_) {}
      tChart = null;
      $("worldMap").innerHTML = "";
    }
    unseen = 0; updateBadge();
    loadBlocked().then(() => tSummary && renderThreats(tSummary, true));
    renderLocalCard();
    initWorld();
    if (tChart) setTimeout(() => tChart.resize(), 0);
    if (tSummary) renderThreats(tSummary, true);
    // If layout wasn't settled yet, try again on the next frames and make sure the canvas has a real size.
    requestAnimationFrame(healWorld);
    setTimeout(healWorld, 600);
  } else {
    setTimeout(() => network.redraw(), 0);
  }
}

function updateBadge() {
  const b = $("threatBadge");
  b.textContent = unseen > 99 ? "99+" : String(unseen);
  b.classList.toggle("hidden", !unseen || view === "threats");
}

/* ------------------------------------------------------------ world map */
const worldLibReady = () => !!(window.echarts && echarts.getMap && echarts.getMap("world"));
let worldLoading = null, worldTries = 0, pendingGeoView = null;
function loadScript(src) {
  return new Promise((ok, fail) => {
    const s = document.createElement("script");
    s.src = src; s.onload = ok; s.onerror = fail;
    document.head.appendChild(s);
  });
}
// Fetch the chart library and world outline again if they failed to load with the page.
function loadWorldLib() {
  if (worldLoading) return worldLoading;
  worldTries++;
  const bust = `?r=${Date.now()}`;
  const tryOne = async (local, cdn, ok) => {
    if (ok()) return;
    try { await loadScript(local + bust); } catch (_) {}
    if (!ok()) { try { await loadScript(cdn); } catch (_) {} }
  };
  worldLoading = (async () => {
    await tryOne("/static/vendor/echarts.min.js", "https://cdnjs.cloudflare.com/ajax/libs/echarts/5.4.3/echarts.min.js", () => !!window.echarts);
    await tryOne("/static/vendor/world.js", "https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/js/world.js", worldLibReady);
  })().finally(() => { worldLoading = null; });
  return worldLoading;
}

function initWorld() {
  if (tChart) return;
  const el = $("worldMap");
  // Only build the map when it's on screen: a chart created inside the hidden Threats tab is 0×0 and stays blank.
  if (view !== "threats" || el.clientWidth < 40 || el.clientHeight < 40) return;
  if (!worldLibReady()) {
    if (worldTries >= 3) {
      el.innerHTML = `<div class="loading-line"><i class="fa-solid fa-triangle-exclamation"></i>The world map couldn't load.
        <button class="btn" onclick="worldTries=0;initWorld()">Try again</button></div>`;
      return;
    }
    el.innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Loading the world map…</div>`;
    loadWorldLib().then(() => setTimeout(() => { initWorld(); if (tChart) { updateWorld(); drawArcs(); } }, 50));
    return;
  }
  el.innerHTML = "";
  fixWorldMap();
  tChart = echarts.init(el, null, {renderer: "canvas"});
  tChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item", confine: true, backgroundColor: "#111a2e", borderColor: "#2a3858", padding: [8, 10],
      textStyle: {color: "#e2e8f0", fontSize: 12, fontFamily: "Inter, system-ui, sans-serif"},
      formatter: (p) => p.seriesId === "attackers"
        ? `${flag(p.data.iso)} <b style="font-family:monospace">${esc(p.data.ip)}</b>${p.data.tag ? ` · <span style="color:#9fb0cc">${esc(p.data.tag.label)} (research scanner)</span>` : ""}<br>${esc(p.data.place)}<br>${fmtN(p.data.count)} attempts · ${esc(p.data.services)}`
        : p.seriesId === "home" ? `<b>Your network</b><br>${esc(p.data.place)}`
        : p.seriesId === "dests" ? `${flag(p.data.d.iso)} <b>${esc(p.data.d.org)}</b>${p.data.d.bad ? ' · <span style="color:#fca5a5">attacked you</span>' : ""}<br>
            <span style="font-family:monospace">${esc(p.data.d.ip)}</span> · ${esc(placeOf(p.data.d))}<br>
            ${fmtN(p.data.d.count)} connections from ${p.data.d.devices} device${p.data.d.devices === 1 ? "" : "s"}` : "",
    },
    geo: {
      map: "world", roam: mapRoam(), zoom: 1.15, center: [12, 22], scaleLimit: {min: 1, max: 10},
      select: {disabled: true}, tooltip: {show: false},
      label: {show: false},
      emphasis: {label: {show: true, color: "#e2e8f0", fontSize: 11, textShadowColor: "#0a0f1c", textShadowBlur: 4},
        itemStyle: {areaColor: "#1d3254"}},   // hover any country to see its name
      layoutCenter: ["50%", "54%"], layoutSize: "118%",
      itemStyle: {areaColor: (typeof cssVar === "function" ? cssVar("--map-area", "#16243f") : "#16243f"),
        borderColor: (typeof cssVar === "function" ? cssVar("--map-border", "#2b4170") : "#2b4170"), borderWidth: 0.6},
      regions: [],
    },
    series: [
      {id: "arcs", type: "lines", coordinateSystem: "geo", zlevel: 2, data: [],
        effect: {show: true, period: 1.6, trailLength: 0.55, symbol: "arrow", symbolSize: 6},
        lineStyle: {width: 1.2, opacity: 0.45, curveness: 0.28}},
      {id: "attackers", type: "effectScatter", coordinateSystem: "geo", zlevel: 3, data: [],
        rippleEffect: {brushType: "stroke", scale: 3.2, period: 3.5}, symbolSize: (v, p) => p.data.size},
      {id: "flowArcs", type: "lines", coordinateSystem: "geo", zlevel: 2, data: [],
        effect: {show: true, period: 2.2, trailLength: 0.35, symbol: "circle", symbolSize: 3.5},
        lineStyle: {width: 1, opacity: 0.35, curveness: -0.22}},
      {id: "dests", type: "scatter", coordinateSystem: "geo", zlevel: 3, data: [], symbolSize: (v, p) => p.data.size},
      {id: "home", type: "effectScatter", coordinateSystem: "geo", zlevel: 4, data: [],
        rippleEffect: {brushType: "fill", scale: 4.5, period: 2.5}, symbolSize: 13,
        itemStyle: {color: "#22c55e", shadowBlur: 14, shadowColor: "#22c55e"}},
    ],
  });
  tChart.on("click", (p) => {
    if (p.seriesId === "attackers") openIp(p.data.ip);
    else if (p.seriesId === "dests" && typeof openDest === "function") openDest(p.data.d);
  });
  // Re-place dots and arcs whenever the map is dragged or zoomed so they stay pinned to their locations.
  // ECharts moves the dots and arcs with the map on its own, so rebuilding everything on each drag frame only made
  // panning slow (about 6 redraws per frame). Do one tidy-up pass once the map stops moving.
  let roamTimer = 0;
  tChart.on("georoam", () => {
    clearTimeout(roamTimer);
    roamTimer = setTimeout(() => { updateWorld(); drawArcs(); }, 300);
  });
  if (pendingGeoView) {             // keep the zoom and position the person had before the rebuild
    tChart.setOption({geo: {center: pendingGeoView.center, zoom: pendingGeoView.zoom}});
    pendingGeoView = null;
  }
  setTimeout(() => { drawArcs(); if (typeof drawFlowArcs === "function") drawFlowArcs(); }, 0);
}

// A map that was sized or panned while hidden can end up with an invalid position and draw nothing.
// Check it whenever the Threats tab opens and rebuild it if it looks broken.
function worldLooksBroken() {
  if (!tChart) return false;
  try {
    const g = tChart.getOption().geo[0];
    const okView = Array.isArray(g.center) && g.center.every(Number.isFinite) && Number.isFinite(g.zoom) && g.zoom > 0;
    const px = tChart.convertToPixel({geoIndex: 0}, [0, 0]);
    const okPx = Array.isArray(px) && px.every(Number.isFinite);
    return !okView || !okPx;
  } catch (_) { return true; }
}
function healWorld() {
  if (view !== "threats") return;
  if (!tChart) { initWorld(); }
  else if ((tChart.resize(), worldLooksBroken())) {
    try { tChart.dispose(); } catch (_) {}
    tChart = null;
    initWorld();
  } else return;
  if (tChart) { updateWorld(); drawArcs(); if (typeof drawFlowArcs === "function") drawFlowArcs(); }
}

// Countries that cross the date line (Fiji, far-east Russia) draw streaks across the map: split them at 180°.
function fixWorldMap() {
  try {
    const m = echarts.getMap("world");
    const gj = m && (m.geoJson || m.geoJSON);
    if (!gj || gj.__fixed || !gj.features) return;
    if (gj.UTF8Encoding) {               // the bundled map is compressed; decode it the same way ECharts does
      const scale = gj.UTF8Scale || 1024;
      const dec = (str, off) => {
        const out = []; let px = off[0], py = off[1];
        for (let i = 0; i < str.length; i += 2) {
          let x = str.charCodeAt(i) - 64, y = str.charCodeAt(i + 1) - 64;
          x = (x >> 1) ^ -(x & 1); y = (y >> 1) ^ -(y & 1);
          x += px; y += py; px = x; py = y;
          out.push([x / scale, y / scale]);
        }
        return out;
      };
      for (const f of gj.features) {
        const g = f.geometry, off = g && g.encodeOffsets;
        if (!g || !off) continue;
        if (g.type === "Polygon") g.coordinates = g.coordinates.map((r, i) => (typeof r === "string" ? dec(r, off[i]) : r));
        else if (g.type === "MultiPolygon") g.coordinates = g.coordinates.map((poly, i) => poly.map((r, j) => (typeof r === "string" ? dec(r, off[i][j]) : r)));
        delete g.encodeOffsets;
      }
      gj.UTF8Encoding = false;
    }
    const fixRing = (ring) => {
      const west = ring.some(([x]) => x < -150), east = ring.some(([x]) => x > 150);
      return west && east ? ring.map(([x, y]) => [x < 0 ? x + 360 > 180 ? 180 : x + 360 : x, y]) : ring;
    };
    for (const f of gj.features) {
      const g = f.geometry;
      if (!g || !g.coordinates) continue;
      if (g.type === "Polygon") g.coordinates = g.coordinates.map(fixRing);
      else if (g.type === "MultiPolygon") g.coordinates = g.coordinates.map((poly) => poly.map(fixRing));
    }
    gj.__fixed = true;
    echarts.registerMap("world", gj);
  } catch (e) { /* keep the original map */ }
}

function homeCoord() {
  const h = tSummary && tSummary.home;
  return h && h.lat != null ? [h.lon, h.lat] : null;
}

function updateWorld() {
  if (!tChart || !tSummary) return;
  const s = tSummary;
  const max = Math.max(1, ...s.countries.map((c) => c.count));
  const home = homeCoord();
  const attacksOn = typeof showAttacks !== "function" || showAttacks();
  tChart.setOption({
    geo: {regions: (attacksOn ? s.countries : []).map((c) => ({name: MAP_NAMES[c.country] || c.country,
      itemStyle: {areaColor: `rgba(244,63,94,${(0.12 + 0.5 * c.count / max).toFixed(2)})`, borderColor: "#7f1d3a"}}))},
    series: [
      {id: "attackers", data: s.attackers.filter((a) => attacksOn && a.lat != null && !(hideScanners && isScanner(a))).map((a) => ({
        name: a.ip, ip: a.ip, iso: a.iso, count: a.count, tag: a.tag, place: placeOf(a), services: a.services.join(", "),
        value: [a.lon, a.lat, a.count], size: 5 + Math.min(16, Math.sqrt(a.count) * 1.4),
        itemStyle: {color: isScanner(a) ? SCANNER_COLOR : reachedIps.has(a.ip) ? "#f43f5e" : "#38bdf8", shadowBlur: isScanner(a) ? 0 : 10,
          shadowColor: reachedIps.has(a.ip) ? "#f43f5e" : "#38bdf8"}}))},
      {id: "home", data: home ? [{value: home, place: [s.home.city, s.home.country].filter(Boolean).join(", ") + (s.public_ip ? ` · ${s.public_ip}` : "")}] : []},
    ],
  });
  if (typeof updateTrafficLayer === "function") updateTrafficLayer();   // also refreshes the labels
  else updateCountryLabels();
}

// Country names on the map, for BOTH attacker countries (red) and device-traffic destination countries (teal).
// Every country with activity gets a name, busiest first; one that would land on a name already placed waits until you zoom in.
// Hovering any country always shows its name.
function updateCountryLabels() {
  if (!tChart) return;
  const attacksOn = typeof showAttacks !== "function" || showAttacks();
  const trafficOn = typeof showTraffic === "function" && showTraffic() && typeof flowSummary !== "undefined" && flowSummary;
  const label = {};   // map region name -> {name, atk, dst}
  const both = attacksOn && trafficOn;
  const top = (arr) => [...(arr || [])].sort((a, b) => b.count - a.count).slice(0, both ? 25 : 60);
  if (attacksOn && tSummary) top(tSummary.countries).forEach((c) => {
    if (c.count > 0) { const k = MAP_NAMES[c.country] || c.country; (label[k] = label[k] || {name: c.country}).atk = c.count; }
  });
  if (trafficOn) top(flowSummary.countries).forEach((c) => {
    if (c.country && c.count) { const k = MAP_NAMES[c.country] || c.country; (label[k] = label[k] || {name: c.country}).dst = c.count; }
  });
  // Labels can't be allowed to pile up (Europe is a few pixels wide at world zoom): walk the countries from busiest
  // down and skip any whose label would land on one already placed. Zooming in makes room, so more appear.
  // With both layers on, names are shown without counts (hover shows the name; the cards have numbers).
  {
    const total = (v) => (v.atk || 0) + (v.dst || 0);
    let gs = null;
    try { gs = tChart.getModel().getComponent("geo").coordinateSystem; } catch (_) {}
    const anchor = {};
    (tSummary ? tSummary.attackers || [] : []).forEach((a) => { const k = MAP_NAMES[a.country] || a.country; if (a.lat != null && !anchor[k]) anchor[k] = [a.lon, a.lat]; });
    if (trafficOn) (flowSummary.dests || []).forEach((d) => { const k = MAP_NAMES[d.country] || d.country; if (d.lat != null && !anchor[k]) anchor[k] = [d.lon, d.lat]; });
    const where = (k) => {
      try {
        const r = gs && gs.getRegion(k), c = r && r.getCenter && r.getCenter();
        const px = c ? gs.dataToPoint(c) : tChart.convertToPixel({geoIndex: 0}, anchor[k]);
        return px && px.every(Number.isFinite) ? px : null;
      } catch (_) { return null; }
    };
    const placed = [], kept = [];
    for (const [k, v] of Object.entries(label).sort((a, b) => total(b[1]) - total(a[1]))) {
      if (kept.length >= (both ? 25 : 60)) break;
      const px = where(k), w = (both ? v.name.length : v.name.length + 5) * 5.2 + 8;
      if (px && placed.some((q) => Math.abs(q[0] - px[0]) < (q[2] + w) / 2 && Math.abs(q[1] - px[1]) < 13)) continue;
      if (px) placed.push([px[0], px[1], w]);
      kept.push(k);
    }
    Object.keys(label).forEach((k) => { if (!kept.includes(k)) delete label[k]; });
  }
  const fmt = (v) => {
    const kind = v.atk && v.dst ? "both" : v.atk ? "atk" : "dst";
    const n = (v.atk || 0) + (v.dst || 0);
    return `{${kind}|${both ? v.name : `${v.name} (${fmtN(n)})`}}`;
  };
  tChart.setOption({geo: {label: {show: true, fontSize: 9, fontFamily: "Inter, system-ui, sans-serif",
    textShadowColor: "#0a0f1c", textShadowBlur: 3,
    rich: {atk: {color: "#fecaca"}, dst: {color: "#5eead4"}, both: {color: "#fca5a5"}},
    formatter: (p) => label[p.name] ? fmt(label[p.name]) : ""}}});
}

function pushArc(ev) {
  const home = homeCoord();
  if (!tChart || !home || ev.lat == null || (hideScanners && isScanner(ev))) return;
  if (typeof showAttacks === "function" && !showAttacks()) return;
  arcs.push({at: Date.now(), coords: [[ev.lon, ev.lat], home],
    lineStyle: {color: isScanner(ev) ? SCANNER_COLOR : isReached(ev) ? "#f43f5e" : "#38bdf8"}});
  if (arcs.length > 40) arcs = arcs.slice(-40);
  drawArcs();
}
let arcDrawTimer = 0;
function drawArcs(now) {
  if (!tChart) return;
  if (now) { clearTimeout(arcDrawTimer); arcDrawTimer = 0; }
  else if (arcDrawTimer) return;                       // a redraw is already queued: this arc rides along
  else { arcDrawTimer = setTimeout(() => drawArcs(true), 250); return; }
  tChart.setOption({series: [{id: "arcs", data: arcs.map(({coords, lineStyle}) => ({coords, lineStyle}))}]});
}
setInterval(() => {
  const before = arcs.length;
  arcs = arcs.filter((a) => Date.now() - a.at < 7000);
  if (arcs.length !== before && view === "threats") drawArcs();
}, 1000);

/* ------------------------------------------------------------ map navigation */
const REGIONS = {world: [[12, 22], 1.15], na: [[-98, 42], 3.2], sa: [[-60, -20], 3], eu: [[13, 51], 5], af: [[20, 2], 2.9],
  me: [[47, 28], 4.6], as: [[100, 32], 2.6], oc: [[142, -26], 3.6]};
const isTouch = () => window.matchMedia("(pointer: coarse)").matches;
const mapIsFull = () => $("mapCard").classList.contains("full");
// On phones the page needs one-finger scrolling, so the map pans only in full screen (pinch zoom always works).
const mapRoam = () => (mapIsFull() || !isTouch() ? true : "scale");
let flyAnim = 0;

function geoView() {
  const g = tChart && tChart.getOption().geo[0];
  return {center: (g && g.center) || REGIONS.world[0], zoom: (g && g.zoom) || REGIONS.world[1]};
}
function flyTo(center, zoom, ms = 650) {
  if (!tChart) return;
  const from = geoView();
  zoom = Math.max(1, Math.min(10, zoom));
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const t0 = performance.now(), id = ++flyAnim;
  const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const step = (now) => {
    if (id !== flyAnim) return;
    const k = reduce ? 1 : Math.min(1, (now - t0) / ms), e = ease(k);
    tChart.setOption({geo: {center: [from.center[0] + (center[0] - from.center[0]) * e, from.center[1] + (center[1] - from.center[1]) * e],
      zoom: from.zoom + (zoom - from.zoom) * e}});
    if (k < 1) requestAnimationFrame(step);
    else updateCountryLabels();                 // the labels that fit depend on the zoom, so redo them when it settles
  };
  requestAnimationFrame(step);
}
function zoomBy(f) { const v = geoView(); flyTo(v.center, v.zoom * f, 260); }
function panBy(dx, dy) { const v = geoView(); const s = 40 / v.zoom; flyTo([v.center[0] + dx * s, v.center[1] + dy * s], v.zoom, 200); }
function flyToRegion(key) { const r = REGIONS[key] || REGIONS.world; flyTo(r[0], r[1]); }
function toggleMapFull(on) {
  const full = on ?? !mapIsFull();
  $("mapCard").classList.toggle("full", full);
  document.body.classList.toggle("map-full", full);
  $("mapCtrl").querySelector('[data-act="full"]').innerHTML = `<i class="fa-solid ${full ? "fa-compress" : "fa-expand"}"></i>`;
  $("mapCtrl").querySelector('[data-act="full"]').title = full ? "Exit full screen" : "Full screen";
  if (tChart) { tChart.setOption({geo: {roam: mapRoam()}}); setTimeout(() => tChart.resize(), 30); }
}
function flyToCountry(iso) {
  const pts = (tSummary?.attackers || []).filter((a) => a.iso === iso && a.lat != null);
  if (!pts.length) return;
  const lon = pts.reduce((s, a) => s + a.lon, 0) / pts.length, lat = pts.reduce((s, a) => s + a.lat, 0) / pts.length;
  flyTo([lon, lat], 4.5);
  $("mapCard").scrollIntoView({behavior: "smooth", block: "center"});
}

/* ------------------------------------------------------------ dashboard panels */
function renderThreats(s, full) {
  tSummary = s;
  (s.recent || []).forEach((e) => { if (isReached(e)) reachedIps.add(e.src); });
  if (view !== "threats") return;
  const reached = s.total - s.blocked;
  $("kTotal").textContent = fmtN(s.total);
  $("kRange").textContent = s.hours === 1 ? "last hour" : s.hours === 168 ? "last 7 days" : `last ${s.hours} hours`;
  $("kUnique").textContent = fmtN(s.unique);
  $("kCountries").textContent = `${s.countries_n} ${s.countries_n === 1 ? "country" : "countries"}`;
  $("kBlocked").textContent = s.total ? `${Math.round(100 * s.blocked / s.total)}%` : "—";
  $("kBlockedN").textContent = `${fmtN(s.blocked)} attempts`;
  $("kReached").textContent = fmtN(reached);
  const hit = s.targets.length;
  $("kReachedSub").textContent = hit ? `${hit} device${hit > 1 ? "s" : ""} targeted` : "no devices hit";
  const tp = s.ports[0];
  $("kTopPort").textContent = tp ? tp.service : "—";
  $("kTopPortN").textContent = tp ? `port ${tp.port} · ${fmtN(tp.count)} attempts` : "";
  $("tPublic").textContent = s.public_ip ? `public IP ${s.public_ip}` : "public IP unknown";

  const src = s.sources || {};
  $("tSources").innerHTML = meta.demo ? `<span>Sample attack data</span>` : `
    <span class="${src.syslog ? "ok" : "bad"}"><i class="fa-solid ${src.syslog ? "fa-circle-check" : "fa-circle-xmark"}"></i> Syslog UDP ${esc(src.syslog_port)}</span>
    <span class="${src.geoip ? "ok" : "bad"}"><i class="fa-solid ${src.geoip ? "fa-circle-check" : "fa-circle-xmark"}"></i> GeoIP</span>
    ${src.ignored && src.ignored.on && src.ignored.total ? `<span title="Leftover replies to connections your own devices made (the router drops them after the connection closes) and routine network messages. They aren't attacks, so they're not counted or shown.">
      <i class="fa-solid fa-filter"></i> ${fmtN(src.ignored.total)} harmless ignored</span>` : ""}
    <span>Last event ${src.last_event ? ago(src.last_event) : "never"}</span>
    ${(src.rejected || []).slice(0, 1).map((r) => `<span class="bad" title="LanPulse only accepts router logs from your gateway (${esc(src.gateway || "?")}) and addresses you allow, so other devices can't feed it fake attacks.">
      <i class="fa-solid fa-ban"></i> Ignoring logs from ${esc(r.ip)} <button class="linkbtn" data-allow-syslog="${esc(r.ip)}">Allow</button></span>`).join("")}`;

  // hourly bars
  const hmax = Math.max(1, ...s.hist);
  $("tHist").innerHTML = s.hist.map((c, i) =>
    `<span style="height:${Math.max(2, 100 * c / hmax)}%" title="${fmtN(c)} attacks, ${s.hist.length - i}h ago"></span>`).join("");
  $("tHistMax").textContent = `peak ${fmtN(hmax)}/h`;
  const H = s.hist.length;
  $("tHistAxis").innerHTML = H === 168 ? "<span>7d ago</span><span>5d</span><span>3d</span><span>1d</span><span>now</span>"
    : H === 1 ? "<span>1h ago</span><span>now</span>"
    : `<span>${H}h ago</span><span>${Math.round(H * 3 / 4)}h</span><span>${H / 2}h</span><span>${Math.round(H / 4)}h</span><span>now</span>`;

  const rank = (rows, max, html) => rows.length ? rows.map((r) => html(r, `<div class="bar"><i style="width:${(100 * r.count / max).toFixed(1)}%"></i></div>`)).join("")
    : `<div class="muted">Nothing yet.</div>`;
  const cmax = Math.max(1, ...s.countries.map((c) => c.count));
  $("tCountries").innerHTML = rank(s.countries, cmax, (c, bar) =>
    `<div class="rk click" data-iso="${esc(c.iso)}" title="Show on map"><span class="ico">${flagHtml(c.iso)}</span><span class="nm">${esc(c.country)}</span><span class="ct">${fmtN(c.count)}</span>${bar}</div>`);
  const pmax = Math.max(1, ...s.ports.map((p) => p.count));
  $("tPorts").innerHTML = rank(s.ports, pmax, (p, bar) =>
    `<div class="rk"><span class="ico"><i class="fa-solid fa-door-open" style="color:#8b9bb6"></i></span><span class="nm">${esc(p.service)} <span class="muted">:${p.port ?? "—"}</span></span><span class="ct">${fmtN(p.count)}</span>${bar}</div>`);
  const tmax = Math.max(1, ...s.targets.map((t) => t.count));
  $("tTargets").innerHTML = s.targets.length ? rank(s.targets, tmax, (t, bar) => {
    const ty = TYPES[t.type] || TYPES.unknown;
    return `<div class="rk click ${t.allowed ? "hot" : ""}" data-dev="${esc(t.id)}"><span class="ico"><i class="${faClass(ty)}" style="color:${ty.color}"></i></span>
      <span class="nm">${esc(t.name)} <span class="muted">${esc(t.lan)}</span></span><span class="ct">${fmtN(t.count)}</span>${bar}</div>`;
  }) : `<div class="muted">No attacks reached a device inside your network.</div>`;

  $("tAttackers").innerHTML = s.attackers.length ? `<table><tr><th>Source</th><th>IP address</th><th>Attempts</th><th>Tried</th><th>Last seen</th></tr>
    ${s.attackers.filter((a) => !(hideScanners && isScanner(a))).slice(0, 15).map((a) => `<tr class="row ${isScanner(a) ? "scanner" : ""}" data-ip="${esc(a.ip)}">
      <td>${flagHtml(a.iso)} ${esc(placeOf(a))}</td><td class="mono">${esc(a.ip)}${reachedIps.has(a.ip) ? ' <i class="fa-solid fa-bullseye" style="color:#f43f5e" title="Reached a LAN device"></i>' : ""}${isScanner(a) ? ` <span class="tagchip">${esc(a.tag.label)}</span>` : ""}${blockChip(a.ip)}</td>
      <td class="mono">${fmtN(a.count)}</td><td>${a.services.map((x) => `<span class="svc">${esc(x)}</span>`).join("")}</td>
      <td class="muted">${ago(a.last)}</td></tr>`).join("")}</table>` : `<div class="muted">No attackers seen in this period.</div>`;

  const sigs = s.signatures || [];
  const smax = Math.max(1, ...sigs.map((g) => g.count));
  $("tSigs").innerHTML = sigs.length ? sigs.map((g) => `<div class="rk"><span class="ico"><i class="fa-solid fa-shield-virus" style="color:#f472b6"></i></span>
      <span class="nm" title="${esc(g.name)}">${esc(g.name)}</span><span class="ct">${fmtN(g.count)} · ${g.ips} IP${g.ips === 1 ? "" : "s"}</span>
      <div class="bar"><i style="width:${(100 * g.count / smax).toFixed(1)}%;background:#f472b6"></i></div></div>`).join("")
    : `<div class="muted">No IPS detections in this period. Turn on Intrusion Prevention in UniFi CyberSecure and include "Security Detections" in syslog.</div>`;
  renderSetup(s);
  if (full || !$("tFeed").childElementCount) renderFeed(s.recent || [], full);
  initWorld();
  updateWorld();
  if (full && !arcs.length) (s.recent || []).slice(0, 12).reverse().forEach((e, i) => setTimeout(() => pushArc(e), i * 350));
}

function renderSetup(s) {
  const box = $("tSetup");
  const show = !meta.demo && !s.total;
  box.classList.toggle("hidden", !show);
  if (!show) return;
  const src = s.sources || {};
  const ip = meta.my_ip || "this-machine";
  box.innerHTML = `<h3><i class="fa-solid fa-plug-circle-bolt"></i>Connect an attack source</h3>
    <p>LanPulse sees attacks when your router or a honeypot reports them. Use one or both:</p>
    <ol>
      <li><b>Router firewall logs:</b> in your router, turn on logging for blocked inbound traffic and send it to
        remote syslog <code>${esc(ip)}</code> port <code>${esc(src.syslog_port || 514)}</code> (UDP).
        Works with OpenWrt, UniFi, pfSense, OPNsense, MikroTik and most Linux firewalls.
        ${src.syslog === false ? `<br><span style="color:#fca5a5">The listener isn't running: ${esc(src.syslog_error)}.</span>` : ""}</li>
      <li><b>Honeypot or script:</b> POST JSON to <code>/api/threats/ingest</code> with your key from Settings &gt; Threats.</li>
      <li><b>Port forwards:</b> list them in Settings &gt; Threats so attacks are matched to the device they reach.</li>
    </ol>
    ${src.geoip ? "" : `<p style="color:#fcd34d">The GeoIP database is missing, so attacks can't be placed on the map. Re-run install.sh.</p>`}`;
}

function blockChip(ip) {
  if (!blockedIps.has(ip)) return "";
  return leakIps.has(ip)
    ? ' <span class="tagchip leak" title="This IP is on your blocklist but is still reaching your network, so your UniFi firewall has no working rule for the blocklist. See Settings > UniFi.">blocked, still connecting</span>'
    : ' <span class="tagchip blk">blocked</span>';
}
function leakNote() {
  const el = $("tFeedCount");
  if (!el) return;
  el.innerHTML = leakIps.size ? `<span class="leak-note" title="Settings > UniFi has the one-time setup steps"><i class="fa-solid fa-triangle-exclamation"></i> ${leakIps.size} blocked IP${leakIps.size === 1 ? " is" : "s are"} still connecting. Check your UniFi block policy.</span>` : "";
}

function feedItem(e) {
  const reached = isReached(e);
  const target = e.lan_name ? esc(e.lan_name) : e.lan ? esc(e.lan) : e.action === "blocked" ? "blocked at router" : "your router";
  return `<button class="fi ${reached ? "reached" : ""} ${isScanner(e) ? "scanner" : ""}" data-ip="${esc(e.src)}">
    <span class="flag">${flagHtml(e.iso)}</span><span class="ip">${esc(e.src)}${isScanner(e) ? ` <span class="tagchip">${esc(e.tag.label)}</span>` : ""}${blockChip(e.src)}</span><span class="when">${clock(e.t)}</span>
    <span class="what"><b>${esc(e.service)}</b>${e.dport ? ` :${e.dport}` : ""} → <span class="tgt">${target}</span>${e.detail ? ` · ${esc(e.detail)}` : ""}</span></button>`;
}
function renderFeed(list, full) {
  feedKeys.clear();
  list.forEach((e) => feedKeys.add(`${e.t}|${e.src}|${e.dport}`));
  $("tFeed").innerHTML = list.filter((e) => !(hideScanners && isScanner(e))).map(feedItem).join("") || `<div class="muted" style="padding:6px">Waiting for attacks…</div>`;
  leakNote();
}

function addThreatEvent(ev) {
  if (isReached(ev)) reachedIps.add(ev.src);
  if (isReached(ev) && blockedIps.has(ev.src) && !feedKeys.has(`${ev.t}|${ev.src}|${ev.dport}`) && !leakIps.has(ev.src)) { leakIps.add(ev.src); leakNote(); }
  if (ev.lan_id && isReached(ev)) underAttack.set(ev.lan_id, Date.now());   // blocked probes don't make a device pulse
  const key = `${ev.t}|${ev.src}|${ev.dport}`;
  if (feedKeys.has(key)) return;
  feedKeys.add(key);
  if (view !== "threats") { if (!isScanner(ev)) { unseen++; updateBadge(); } return; }
  if (hideScanners && isScanner(ev)) return;
  const feed = $("tFeed");
  if (!feed.querySelector(".fi")) feed.innerHTML = "";
  feed.insertAdjacentHTML("afterbegin", feedItem(ev));
  feed.firstElementChild.classList.add("fresh");
  while (feed.childElementCount > 80) feed.lastElementChild.remove();
  pushArc(ev);
  if (tSummary) {        // keep the headline numbers moving between summaries
    tSummary.total++; if (ev.action === "blocked") tSummary.blocked++;
    $("kTotal").textContent = fmtN(tSummary.total);
    if (!isReached(ev)) $("kBlockedN").textContent = `${fmtN(tSummary.blocked)} attempts`;
    $("kReached").textContent = fmtN(tSummary.total - tSummary.blocked);
  }
}

/* ------------------------------------------------------------ UDM blocking */
async function loadBlocked() {
  const r = await api("/api/unifi/blocked", "GET");
  if (!r) return;
  unifiReady = !!r.configured && !r.error;
  blockedIps = new Set(r.blocked || []);
  for (const ip of [...leakIps]) if (!blockedIps.has(ip)) leakIps.delete(ip);
  leakNote();
}

/* ------------------------------------------------------------ inside-the-LAN threats */
function renderLocalCard() {
  const L = localSummary;
  if (!L || !$("tLocal")) return;
  const st = L.status || {};
  $("tLocalStatus").innerHTML = meta.demo ? "sample data" : st.running ? `${fmtN(L.count)} in 24h · watching` :
    `<span style="color:#fca5a5">not watching: ${esc(st.error || "starting")}</span>`;
  const dh = st.dhcp_servers || [];
  const guard = meta.demo || !st.running ? "" : `<div class="guard-line muted">
      <span><i class="fa-solid fa-shield-halved"></i>Router: ${st.gateway_mac ? `<code>${esc(st.gateway_mac)}</code>` : "learning…"}</span>
      ${st.dhcp_check === false ? "" : `<span><i class="fa-solid fa-network-wired"></i>DHCP servers: ${dh.length
        ? dh.map((d) => `<span class="${d.allowed ? "" : "bad-txt"}">${esc(d.ip)}${d.allowed ? "" : " (unknown!)"}</span>`).join(", ")
        : "checking…"}</span>`}</div>`;
  $("tLocal").innerHTML = ((L.events || []).length ? L.events.slice(0, 12).map(localRow).join("")
    : `<div class="ok-line"><i class="fa-solid fa-circle-check"></i>No scans, spoofing or honeypot hits from devices inside your network.</div>`) + guard;
}
function onLocalSummary(L) {
  localSummary = L;
  const cutoff = Date.now() - LOCAL_WINDOW;
  (L.events || []).slice().reverse().forEach((e) => { if (e.t * 1000 > cutoff) noteLocalEvent(e); });
  syncMap(JSON.parse(layoutKey || "{}"));
  renderLocalCard();
}
function addLocalEvent(e) {
  noteLocalEvent(e);
  if (localSummary) { localSummary.events = [e, ...(localSummary.events || [])].slice(0, 60); localSummary.count++; }
  renderLocalCard();
  syncMap(JSON.parse(layoutKey || "{}"));
  renderAltViews();
  if (selected && (devices.get(selected)?.ip === e.src || devices.get(selected)?.ip === e.target)) loadDeviceLocal(selected);
  if (view !== "threats") { unseen++; updateBadge(); }
  toast(`${e.title}: ${e.src_name || e.src || e.mac}`);
}

async function onThreatSummary(s) {
  if (tHours === s.hours) { renderThreats(s, false); return; }
  if (Date.now() - lastRangeFetch < 10000) return;
  lastRangeFetch = Date.now();
  const r = await api(`/api/threats/summary?hours=${tHours}`, "GET");
  if (r) renderThreats(r, false);
}

/* ------------------------------------------------------------ attacker investigation */
async function openIp(ip) {
  selected = null; selectedIp = ip;
  clearInterval(historyTimer);
  $("panelBody").innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Looking up ${esc(ip)}…</div>`;
  $("panel").classList.add("open");
  $("panel").setAttribute("aria-hidden", "false");
  const d = await api(`/api/threats/ip/${encodeURIComponent(ip)}`, "GET");
  if (!d || selectedIp !== ip) return;
  renderIpPanel(d);
  if (view === "threats" && d.geo && d.geo.lat != null) flyTo([d.geo.lon, d.geo.lat], Math.max(geoView().zoom, 4));
}

function blockRules(ip) {
  return {
    "OpenWrt": `nft insert rule inet fw4 input_wan ip saddr ${ip} drop\nnft insert rule inet fw4 forward_wan ip saddr ${ip} drop`,
    "UFW": `sudo ufw insert 1 deny from ${ip}`,
    "iptables": `sudo iptables -I INPUT -s ${ip} -j DROP\nsudo iptables -I FORWARD -s ${ip} -j DROP`,
    "MikroTik": `/ip firewall address-list add list=blocklist address=${ip} comment="LanPulse"`,
    "pfSense / OPNsense": `Firewall > Aliases: add ${ip} to an alias (e.g. "Blocklist"),\nthen add a WAN rule that blocks that alias as the source.`,
  };
}

function renderIpPanel(d) {
  const g = d.geo || {}, it = d.intel || {}, ab = it.abuse, sh = it.shodan;
  const score = ab && ab.score != null ? ab.score : null;
  const level = score != null ? (score >= 75 ? "high" : score >= 25 ? "med" : "low") : (d.count >= 100 ? "high" : d.count >= 10 ? "med" : "low");
  const levelTxt = {high: "High risk", med: "Suspicious", low: "Low activity"}[level];
  const reached = d.reached != null ? d.reached : d.count - d.blocked;
  const hmax = Math.max(1, ...d.hourly);
  const flags = [it.hosting && "Hosting / data center", it.proxy && "Proxy or VPN", it.mobile && "Mobile network", ab && ab.tor && "Tor exit node"].filter(Boolean);
  const rules = blockRules(d.ip);
  const firstRule = Object.keys(rules)[0];
  const row = (k, v) => v ? `<dt>${k}</dt><dd>${v}</dd>` : "";
  $("panelBody").innerHTML = `
    <div class="p-head attacker">
      <div class="p-icon"><i class="fa-solid fa-user-ninja"></i></div>
      <div><div class="p-title" style="font-family:var(--mono)">${esc(d.ip)}</div>
        <div class="badges"><span class="badge risk-${level}"><i class="fa-solid fa-skull-crossbones"></i>${levelTxt}</span>
        <span class="badge">${flag(g.iso)} ${esc(placeOf(g))}</span>
        ${flags.map((f) => `<span class="badge">${esc(f)}</span>`).join("")}
        ${d.tag ? `<span class="badge scanner-b" title="${esc(d.tag.host || "")}"><i class="fa-solid fa-satellite"></i>Research scanner: ${esc(d.tag.label)}</span>` : ""}
        ${blockedIps.has(d.ip) ? (leakIps.has(d.ip) ? '<span class="badge risk-high"><i class="fa-solid fa-triangle-exclamation"></i>On blocklist, but still connecting</span>' : '<span class="badge risk-low"><i class="fa-solid fa-ban"></i>Blocked on UDM</span>') : ""}</div></div>
    </div>
    <div class="p-sec"><div class="minis">
      <div class="mini"><b>${fmtN(d.count)}</b><small>attempts</small></div>
      <div class="mini"><b style="color:${reached ? "#fda4af" : "inherit"}">${fmtN(reached)}</b><small>reached your LAN</small></div>
      <div class="mini"><b>${d.first ? ago(d.first) : "—"}</b><small>first seen</small></div>
      <div class="mini"><b>${d.last ? ago(d.last) : "—"}</b><small>last seen</small></div>
    </div>
    <div class="hrs" title="Attempts per hour, last 24 hours">${d.hourly.map((c, i) => `<span style="height:${Math.max(3, 100 * c / hmax)}%" title="${c} attempts, ${24 - i}h ago"></span>`).join("")}</div>
    <div class="axis"><span>24h ago</span><span>12h</span><span>now</span></div></div>
    <div class="p-sec"><div class="actions">
      ${unifiReady ? `<button class="btn ${blockedIps.has(d.ip) ? "toggle-on" : "danger-solid"}" id="bBlock">
          <i class="fa-solid ${blockedIps.has(d.ip) ? "fa-unlock" : "fa-ban"}"></i>${blockedIps.has(d.ip) ? "Unblock on UDM" : "Block on UDM"}</button>`
        : `<button class="btn" id="bBlockSetup"><i class="fa-solid fa-ban"></i>Set up one-click block</button>`}
      <button class="btn" id="bGoRules"><i class="fa-solid fa-terminal"></i>Block rules</button>
    </div>
    ${d.tag ? `<p class="muted" style="font-size:12px;margin:8px 0 0">Research scanners map the whole internet and rarely mean harm. Blocking them is optional.</p>` : ""}</div>

    <div class="p-sec"><h4>What it tried</h4>
      <div class="chips-wrap">${d.ports.map((p) => `<span class="pchip">${esc(p.service)} :${p.port ?? "—"}<b>×${fmtN(p.count)}</b></span>`).join("") || '<span class="muted">—</span>'}</div>
      ${d.credentials.length ? `<h4 style="margin-top:14px">Logins and requests captured</h4><table class="ev-table">${d.credentials.map((c) =>
        `<tr><td style="font-family:var(--mono)">${esc(c.text)}</td><td class="muted" style="text-align:right">×${c.count}</td></tr>`).join("")}</table>` : ""}
    </div>

    ${d.honeypot ? `<div class="p-sec"><h4>Hit your honeypot <span class="muted">${fmtN(d.honeypot.total)}×</span></h4>
      <div class="chips-wrap">${d.honeypot.services.map((x) => `<span class="pchip">${esc(x.label)}<b>×${fmtN(x.count)}</b></span>`).join("")}</div>
      <table class="ev-table" style="margin-top:10px">${d.honeypot.hits.slice(0, 15).map((h) => `<tr><td class="muted">${esc(ago(h.t))}</td>
        <td>${esc(h.service)} :${h.port}</td><td style="font-family:var(--mono)">${esc(h.creds || h.data || "connected, sent nothing")}</td></tr>`).join("")}</table>
      <p class="muted" style="font-size:12px;margin:8px 0 0">These only touched a decoy, nothing real. The Honeypot tab has the full list.</p></div>` : ""}
    ${(d.signatures || []).length ? `<div class="p-sec"><h4>IPS detections</h4>${d.signatures.map((g) =>
      `<div class="finding"><span class="sev high">IPS</span><span>${esc(g.name)}</span><span class="port">×${fmtN(g.count)}</span></div>`).join("")}</div>` : ""}
    <div class="p-sec"><h4>Targets in your network</h4>
      ${d.targets.length ? d.targets.map((t) => { const ty = TYPES[t.type] || TYPES.unknown;
        return `<div class="tgt-row" data-dev="${esc(t.id)}" style="--c:${ty.color}"><div class="ic"><i class="${faClass(ty)}"></i></div>
          <div><b>${esc(t.name)}</b><div class="muted" style="font:11px var(--mono)">${esc(t.lan)}</div></div><span class="ct">×${fmtN(t.count)}</span></div>`; }).join("")
        : `<div class="ok-line"><i class="fa-solid fa-shield-halved"></i>Every attempt was stopped at your router.</div>`}
    </div>

    <div class="p-sec"><h4>IP intelligence</h4><dl class="kv">
      ${row("Location", esc([g.city, g.region, g.country].filter(Boolean).join(", ") || "Unknown"))}
      ${row("ISP", esc(it.isp))}${row("Organization", esc(it.org))}
      ${row("Network", esc([it.asn, it.as_name].filter(Boolean).join(" ")))}
      ${row("Reverse DNS", esc(it.rdns))}
      ${it.greynoise ? `<dt>GreyNoise</dt><dd>${it.greynoise.classification === "benign" ? `<span style="color:#86efac">Benign</span> · ${esc(it.greynoise.name)}`
        : it.greynoise.classification === "malicious" ? '<span style="color:#fca5a5">Known malicious</span>'
        : it.greynoise.noise ? "Seen scanning the internet" : "Not seen scanning the internet"}</dd>` : ""}
      ${it.threatfox ? `<dt>ThreatFox</dt><dd>${it.threatfox.found
        ? `<span style="color:#fca5a5">Known malicious IOC</span>${it.threatfox.malware && it.threatfox.malware.length ? ` · ${esc(it.threatfox.malware.join(", "))}` : ""}<span class="muted"> (abuse.ch)</span>`
        : it.threatfox.need_key ? '<span class="muted">Add a free abuse.ch Auth-Key in Settings &gt; DNS to enable</span>'
        : '<span style="color:#86efac">Not listed</span> <span class="muted">(abuse.ch)</span>'}</dd>` : ""}
      ${it.tor === true ? '<dt>Tor</dt><dd><span style="color:#fca5a5">Tor exit node</span> <span class="muted">— traffic is anonymised</span></dd>'
        : it.tor === false ? '<dt>Tor</dt><dd class="muted">Not a Tor exit node</dd>' : ""}
      ${ab ? `<dt>Abuse score</dt><dd><div class="score"><b>${score}%</b><div class="bar"><div style="width:${score}%"></div></div></div>
        <span class="muted">${fmtN(ab.reports)} reports · ${esc(ab.usage || "")}</span></dd>`
        : `<dt>Abuse score</dt><dd class="muted">Add a free AbuseIPDB key in Settings &gt; Threats</dd>`}
      ${sh ? `<dt>Its open ports</dt><dd>${sh.ports.length ? esc(sh.ports.join(", ")) : "none known"}</dd>
        ${sh.tags.length ? `<dt>Tags</dt><dd>${sh.tags.map((t) => `<span class="svc">${esc(t)}</span>`).join("")}</dd>` : ""}
        ${sh.vulns.length ? `<dt>Known CVEs</dt><dd class="chips-wrap">${sh.vulns.map((v) =>
          `<a class="pchip cve" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}" target="_blank" rel="noopener">${esc(v)}</a>`).join("")}</dd>` : ""}` : ""}
    </dl>
    ${Object.keys(it.errors || {}).length ? `<p class="muted" style="font-size:12px;margin:8px 0 0">Some lookups failed: ${esc(Object.keys(it.errors).join(", "))}.</p>` : ""}
    </div>

    <div class="p-sec"><h4>Recent attempts</h4><table class="ev-table">
      ${d.recent.slice(0, 20).map((e) => `<tr><td class="muted" style="white-space:nowrap">${clock(e.t)}</td>
        <td>${esc(e.service)}${e.dport ? ` :${e.dport}` : ""}<div class="muted">${esc(e.lan_name || e.lan || "")}${e.detail ? ` · ${esc(e.detail)}` : ""}</div></td>
        <td class="res ${esc(e.action)}" style="text-align:right">${e.action === "blocked" ? "Blocked" : e.action === "logged" ? "Honeypot" : "Reached"}</td></tr>`).join("")}
    </table></div>

    <div class="p-sec"><h4>Block this IP</h4>
      <div class="rules-tabs" id="ruleTabs">${Object.keys(rules).map((k) => `<button data-k="${esc(k)}" class="${k === firstRule ? "on" : ""}">${esc(k)}</button>`).join("")}</div>
      <pre class="code" id="ruleText">${esc(rules[firstRule])}</pre>
      <div class="btns"><button class="btn" id="bCopyRule"><i class="fa-regular fa-copy"></i>Copy</button></div>
    </div>

    <div class="p-sec"><h4>Look it up elsewhere</h4><div class="links">
      ${[["AbuseIPDB", `https://www.abuseipdb.com/check/${d.ip}`], ["Shodan", `https://www.shodan.io/host/${d.ip}`],
         ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${d.ip}`], ["GreyNoise", `https://viz.greynoise.io/ip/${d.ip}`],
         ["Censys", `https://platform.censys.io/hosts/${d.ip}`], ["Whois", `https://bgp.he.net/ip/${d.ip}#_whois`]]
        .map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener">${n}<i class="fa-solid fa-arrow-up-right-from-square" style="font-size:10px"></i></a>`).join("")}
    </div></div>`;

  $("panelBody").querySelectorAll("[data-dev]").forEach((el) => el.onclick = () => goDevice(el.dataset.dev));
  $("ruleTabs").onclick = (e) => {
    const b = e.target.closest("button"); if (!b) return;
    $("ruleTabs").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    $("ruleText").textContent = rules[b.dataset.k];
  };
  $("bCopyRule").onclick = () => copyText($("ruleText"));
  $("bGoRules").onclick = () => $("ruleTabs").scrollIntoView({behavior: "smooth", block: "center"});
  if ($("bBlockSetup")) $("bBlockSetup").onclick = () => { setTab = "unifi"; openSettings(); };
  if ($("bBlock")) $("bBlock").onclick = async (e) => {
    const b = e.currentTarget, unblock = blockedIps.has(d.ip);
    b.disabled = true; b.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i>${unblock ? "Unblocking" : "Blocking"}…`;
    const r = await api(`/api/threats/${unblock ? "unblock" : "block"}`, "POST", {ip: d.ip});
    if (r) { blockedIps = new Set(r.blocked); toast(unblock ? `${d.ip} unblocked` : `${d.ip} blocked on your UDM`); if (tSummary) renderThreats(tSummary, true); }
    if (selectedIp === d.ip) renderIpPanel(d);
  };
}

function copyText(el) {
  const text = el.value ?? el.textContent;
  const done = () => toast("Copied");
  const fallback = () => {
    const range = document.createRange(); range.selectNodeContents(el);
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range);
    toast("Selected. Press Ctrl+C to copy");
  };
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
}

function goDevice(id) {
  if (!id || !devices.has(id)) { toast("That device isn't on the network map"); return; }
  openPanel(id);                       // open the detail panel without leaving the current tab
  if (view === "net" && typeof network !== "undefined" && network) {
    try { network.focus(id, {scale: 1.2, animation: {duration: 500}}); } catch (_) {}
  }
}

/* ------------------------------------------------------------ settings tab */
function renderThreatSettings(body) {
  const t = settings.threats;
  const devs = [...devices.values()].sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
  const devOpts = (sel) => devs.map((d) => `<option value="${esc(d.ip)}" ${d.ip === sel ? "selected" : ""}>${esc(nameOf(d))} (${esc(d.ip)})</option>`).join("")
    + (sel && !devs.some((d) => d.ip === sel) ? `<option value="${esc(sel)}" selected>${esc(sel)}</option>` : "");
  const url = `${location.origin}/api/threats/ingest`;
  body.innerHTML = `
    <div class="rule"><label class="switch"><input type="checkbox" id="t_enabled" ${t.enabled ? "checked" : ""}><span></span></label>
      <div class="txt"><b>Listen for router firewall logs</b><small>Point your router's remote syslog at ${esc(meta.my_ip || "this machine")}, UDP port below. Restart LanPulse after changing the port.</small></div></div>
    <div class="chan"><div class="chan-fields" style="padding:12px">
      <label>Syslog port (UDP)<input id="t_port" type="number" min="1" max="65535" value="${esc(t.syslog_port)}"></label>
      <label class="full">Also accept router logs from (your gateway is always accepted)
        <input id="t_from" value="${esc((t.syslog_from || []).join(", "))}" placeholder="e.g. 192.168.0.50 for a honeypot"></label>
      <label class="full chk-line"><input type="checkbox" id="t_any" ${t.syslog_any ? "checked" : ""}> Accept router logs from any address (not recommended: any device could send fake attacks)</label>
      <label>Burst alert after<input id="t_burst" type="number" min="3" value="${esc(t.burst_threshold)}"></label>
      <label class="full">AbuseIPDB API key (optional, free at abuseipdb.com)<input id="t_abuse" type="password" value="${esc(t.abuseipdb_key)}" autocomplete="off"></label>
      <label class="full chk-line"><input type="checkbox" id="t_autointel" ${t.auto_intel !== false ? "checked" : ""}> Auto-enrich your top attackers (geo, reputation, ThreatFox, Tor) in the background</label>
      <div class="full" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <a class="btn sm" href="/api/export/iocs.txt" download><i class="fa-solid fa-file-arrow-down"></i>Export attacker IPs</a>
        <a class="btn sm ghost" href="/api/export/iocs.txt?reached=1" download><i class="fa-solid fa-triangle-exclamation"></i>Only those that got through</a>
      </div>
      <div class="full muted" style="font-size:12px">A burst alert fires when one IP makes that many attempts within 5 minutes.
        The Tor exit check is free and needs no key. <b>ThreatFox</b> needs a free abuse.ch Auth-Key — add it under
        <b>Settings &gt; DNS</b> (the same key the malware list uses).</div>
    </div></div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-filter ci"></i><div class="txt"><b>Ignore harmless traffic (recommended)</b>
      <small>Routers log leftover replies after your own connections close (from Google, Microsoft, CDNs…) and routine network messages.
      These aren't attacks. Turn off to count every blocked packet.</small></div>
      <label class="switch"><input type="checkbox" id="t_noise" ${t.ignore_noise !== false ? "checked" : ""}><span></span></label></div></div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-house-crack ci"></i><div class="txt"><b>Watch inside the network</b>
      <small>Detect network sweeps, router impersonation (ARP spoofing) and port scans against this server.</small></div>
      <label class="switch"><input type="checkbox" id="l_enabled" ${settings.local.enabled ? "checked" : ""}><span></span></label></div>
      <div class="chan-fields">
        <label>Sweep alert after (addresses / 30 s)<input id="l_sweep" type="number" min="10" value="${esc(settings.local.sweep_threshold)}"></label>
        <label>Scan alert after (ports / 60 s)<input id="l_scan" type="number" min="5" value="${esc(settings.local.scan_threshold)}"></label>
        <label class="full">Never flag these IPs (comma separated)<input id="l_ignore" value="${esc((settings.local.ignore || []).join(", "))}" placeholder="e.g. 192.168.0.50"></label>
        <label class="full check"><input type="checkbox" id="l_dhcp" ${settings.local.dhcp_check !== false ? "checked" : ""}>
          Watch for rogue DHCP servers (listens only)</label>
        <label class="full check"><input type="checkbox" id="l_dhcpprobe" ${settings.local.dhcp_probe ? "checked" : ""}>
          Also ask "who hands out addresses?" every 15 minutes (finds quiet rogue servers; shows up in UniFi as a client named
          02:4C:50:…)</label>
        <label class="full">Allowed DHCP servers besides your router (comma separated)<input id="l_dhcpok" value="${esc((settings.local.dhcp_servers || []).join(", "))}" placeholder="e.g. a Pi-hole that serves DHCP"></label>
        <div class="full muted" style="font-size:12px">Router's hardware address: <b>${esc(settings.local.gateway_mac || "not learned yet")}</b>.
          LanPulse learns it from its own scans and warns if anything else claims to be the router.
          ${settings.local.gateway_mac ? `<button class="linkbtn" id="bRelearnGw">Learn it again</button> (only after replacing or resetting the router)` : ""}</div>
      </div></div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-route ci"></i><div class="txt"><b>Port forwards</b>
      <small>Tell LanPulse which device each forwarded port reaches, so attacks are matched to it.</small></div></div>
      <div class="chan-fields" style="grid-template-columns:1fr" id="fwRows">
        ${(t.forwards.length ? t.forwards : []).map((f, i) => fwRow(f, i, devOpts)).join("")}
        <div><button class="btn" id="bAddFw"><i class="fa-solid fa-plus"></i>Add port forward</button></div>
      </div></div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-bug ci"></i><div class="txt"><b>Honeypot / API feed</b>
      <small>Send attacks from a honeypot or script as JSON.</small></div></div>
      <div class="chan-fields" style="grid-template-columns:1fr">
        <label>Ingest key<span class="keybox"><input id="t_key" readonly value="${esc(t.ingest_key)}"><button class="btn" id="bCopyKey" title="Copy key"><i class="fa-regular fa-copy"></i></button></span></label>
        <pre class="code">curl -X POST ${esc(url)} \\
  -H "X-API-Key: ${esc(t.ingest_key)}" -H "Content-Type: application/json" \\
  -d '{"src":"203.0.113.9","dst_port":23,"service":"telnet",
       "detail":"login root/admin","sensor":"esp32-honeypot",
       "lan_ip":"192.168.1.50"}'</pre>
      </div></div>
    <div class="modal-foot"><button class="btn primary" id="bSaveSet"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>`;
  const rebind = () => body.querySelectorAll("[data-delfw]").forEach((b) => b.onclick = () => { collectThreatSettings(); settings.threats.forwards.splice(+b.dataset.delfw, 1); renderSettings(); });
  rebind();
  $("bAddFw").onclick = () => { collectThreatSettings(); settings.threats.forwards.push({port: "", proto: "tcp", lan_ip: devs[0]?.ip || ""}); renderSettings(); };
  $("bCopyKey").onclick = () => copyText($("t_key"));
  $("bRelearnGw")?.addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    const r = await api("/api/settings", "POST", {local: {reset_gateway: true}});
    if (r) { settings = r; toast("LanPulse will learn the router's address on the next scan"); renderSettings(); }
  });
}
function fwRow(f, i, devOpts) {
  return `<div class="fw-row"><input id="fw_port_${i}" type="number" placeholder="Port" value="${esc(f.port)}" aria-label="Port">
    <select id="fw_proto_${i}" aria-label="Protocol">${["tcp", "udp", "both"].map((p) => `<option ${f.proto === p ? "selected" : ""}>${p}</option>`).join("")}</select>
    <select id="fw_ip_${i}" aria-label="Device">${devOpts(f.lan_ip)}</select>
    <button class="icon-btn" data-delfw="${i}" title="Remove"><i class="fa-solid fa-trash"></i></button></div>`;
}
function collectThreatSettings() {
  const t = settings.threats;
  if (!$("t_port")) return;
  settings.local.enabled = $("l_enabled").checked;
  settings.local.sweep_threshold = $("l_sweep").value;
  settings.local.scan_threshold = $("l_scan").value;
  settings.local.ignore = $("l_ignore").value.split(/[\s,]+/).filter(Boolean);
  if ($("l_dhcp")) settings.local.dhcp_check = $("l_dhcp").checked;
  if ($("l_dhcpprobe")) settings.local.dhcp_probe = $("l_dhcpprobe").checked;
  if ($("l_dhcpok")) settings.local.dhcp_servers = $("l_dhcpok").value.split(/[\s,]+/).filter(Boolean);
  t.enabled = $("t_enabled").checked;
  t.syslog_port = $("t_port").value;
  t.burst_threshold = $("t_burst").value;
  t.abuseipdb_key = $("t_abuse").value;
  if ($("t_autointel")) t.auto_intel = $("t_autointel").checked;
  if ($("t_noise")) t.ignore_noise = $("t_noise").checked;
  if ($("t_from")) t.syslog_from = $("t_from").value.split(/[\s,]+/).filter(Boolean);
  if ($("t_any")) t.syslog_any = $("t_any").checked;
  t.forwards = t.forwards.map((f, i) => ({port: $(`fw_port_${i}`).value, proto: $(`fw_proto_${i}`).value, lan_ip: $(`fw_ip_${i}`).value}));
}

function renderUnifiSettings(body) {
  const u = settings.unifi, sn = settings.snmp || {};
  body.innerHTML = `<p class="hint">Connect your UniFi gateway so you can block an attacker with one tap. LanPulse keeps an IP group
      called <b>${esc(u.group || "LanPulse Blocklist")}</b> up to date.</p>
    <div class="chan"><div class="chan-fields" style="padding:12px">
      <label>Gateway address<input id="u_host" value="${esc(u.host)}" placeholder="${esc(meta.gateway || "192.168.0.1")} (blank = your router)"></label>
      <label>Site<input id="u_site" value="${esc(u.site || "default")}"></label>
      <label class="full">API key<input id="u_key" type="password" value="${esc(u.api_key)}" autocomplete="off" placeholder="Recommended"></label>
      <div class="full muted" style="font-size:12px">Or use a local-only admin account instead of an API key:</div>
      <label>Username<input id="u_user" value="${esc(u.username)}" autocomplete="off"></label>
      <label>Password<input id="u_pass" type="password" value="${esc(u.password)}" autocomplete="new-password"></label>
      <label class="full">IP group name<input id="u_group" value="${esc(u.group || "LanPulse Blocklist")}"></label>
      <label class="chk full"><input type="checkbox" id="u_verify" ${u.verify_tls ? "checked" : ""}>Verify the gateway's HTTPS certificate (leave off for the default self-signed one)</label>
      <div class="full btns"><button class="btn" id="bUniTest"><i class="fa-solid fa-plug"></i>Save &amp; test</button><span class="test-res" id="uniRes"></span></div>
    </div></div>
    <div class="t-setup"><h3><i class="fa-solid fa-list-check"></i>One-time setup in UniFi</h3><ol>
      <li><b>API key:</b> in UniFi go to Settings &gt; Control Plane &gt; Integrations (or Network &gt; Integrations), create an API key and paste it above.</li>
      <li><b>Block an IP</b> once from an attacker's panel. That creates the <b>${esc(u.group || "LanPulse Blocklist")}</b> IP group on the UDM.</li>
      <li><b>Create one block policy</b> in Settings &gt; Policy Engine: Source zone External with the IP group <b>${esc(u.group || "LanPulse Blocklist")}</b>,
        Destination zone <b>Internal</b> (that is where port-forwarded traffic, like the honeypot's, arrives), Action Block, Protocol All.
        Every IP LanPulse adds is then blocked. Until this policy exists the badge only means "in the group". LanPulse warns if a blocked IP keeps connecting.</li>
    </ol></div>
    <div class="chan"><div class="chan-head"><i class="fa-solid fa-sitemap ci"></i>
      <div class="txt"><b>Other routers and switches (SNMP)</b><small>Read-only. Learns which device is plugged into which port using LLDP and the switch's MAC table, so the Topology map works without UniFi.</small></div>
      <label class="switch"><input type="checkbox" id="sn_on" ${sn.enabled ? "checked" : ""}><span></span></label></div>
      <div class="chan-fields" style="padding:12px">
        <label class="full">Router / switch addresses (private IPs, comma or space separated)<input id="sn_hosts" value="${esc((sn.hosts || []).join(", "))}" placeholder="192.168.1.2, 192.168.1.3"></label>
        <label class="full">SNMP v2c community (read-only)<input id="sn_comm" type="password" value="${esc(sn.community)}" autocomplete="off" placeholder="public"></label>
        <div class="full btns"><button class="btn" id="bSnTest"><i class="fa-solid fa-plug"></i>Save &amp; test</button><span class="test-res" id="snRes"></span></div>
        <div class="full muted" style="font-size:12px">Turn on SNMP (v2c, read-only) and LLDP on the device first. SNMP v2c sends the community string in clear text, so use a read-only community and keep it on your LAN. Untested against real devices so far: please report what works.</div>
      </div></div>
    <div class="modal-foot"><button class="btn primary" id="bSaveSet"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>`;
  $("bSnTest").onclick = async () => {
    if (!(await saveSettings(true))) return;
    const res = $("snRes");
    res.className = "test-res"; res.textContent = "Asking…";
    const r = await api("/api/snmp/test", "POST", null, true);
    res.className = `test-res ${r && r.ok ? "ok" : "bad"}`;
    res.textContent = !r ? "Failed: no response" : r.error ? `Failed: ${r.error}`
      : r.hosts.map((h) => h.ok ? `${h.ip}: ${h.name || "ok"}, ${h.lldp} LLDP neighbours, ${h.fdb} MACs` : `${h.ip}: ${h.error}`).join(" | ");
  };
  $("bUniTest").onclick = async () => {
    if (!(await saveSettings(true))) return;
    const res = $("uniRes");
    res.className = "test-res"; res.textContent = "Connecting…";
    const r = await api("/api/unifi/test", "POST", null, true);
    res.className = `test-res ${r && r.ok ? "ok" : "bad"}`;
    res.textContent = r && r.ok ? `Connected (${r.ms} ms). ${r.group_exists ? `${r.blocked} IPs in the blocklist.` : "The blocklist group will be created on your first block."}`
      : `Failed: ${r ? r.error : "no response"}`;
    loadBlocked();
  };
}
function collectUnifiSettings() {
  if (!$("u_host")) return;
  settings.snmp = Object.assign(settings.snmp || {}, {enabled: $("sn_on").checked, community: $("sn_comm").value,
    hosts: $("sn_hosts").value.split(/[\s,;]+/).filter(Boolean)});
  Object.assign(settings.unifi, {host: $("u_host").value, site: $("u_site").value, api_key: $("u_key").value,
    username: $("u_user").value, password: $("u_pass").value, group: $("u_group").value, verify_tls: $("u_verify").checked});
}

/* ------------------------------------------------------------ wiring */
function initThreatUI() {
  for (const [btn, name] of VIEWS) if ($(btn)) $(btn).onclick = () => setView(name);
  $("tRange").onchange = async (e) => {
    tHours = +e.target.value;
    const r = await api(`/api/threats/summary?hours=${tHours}`, "GET");
    if (r) renderThreats(r, true);
  };
  $("tFeed").addEventListener("click", (e) => { const b = e.target.closest(".fi"); if (b) openIp(b.dataset.ip); });
  $("mapCtrl").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    ({in: () => zoomBy(1.6), out: () => zoomBy(1 / 1.6), reset: () => { $("tRegion").value = "world"; flyToRegion("world"); },
      home: () => { const h = homeCoord(); if (h) flyTo(h, 4.5); else toast("Your network's location isn't known yet"); },
      full: () => toggleMapFull()})[b.dataset.act]?.();
  });
  $("tRegion").onchange = (e) => flyToRegion(e.target.value);
  $("tCountries").addEventListener("click", (e) => { const r = e.target.closest("[data-iso]"); if (r) flyToCountry(r.dataset.iso); });
  $("mapCard").addEventListener("keydown", (e) => {
    if (e.target !== $("mapCard")) return;
    const k = {"+": () => zoomBy(1.6), "=": () => zoomBy(1.6), "-": () => zoomBy(1 / 1.6), "0": () => flyToRegion("world"),
      f: () => toggleMapFull(), ArrowLeft: () => panBy(-1, 0), ArrowRight: () => panBy(1, 0), ArrowUp: () => panBy(0, 1),
      ArrowDown: () => panBy(0, -1)}[e.key];
    if (k) { e.preventDefault(); k(); }
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && mapIsFull() && !$("panel").classList.contains("open")) toggleMapFull(false); });
  $("tLocal").addEventListener("click", (e) => {
    const r = e.target.closest(".lrow");
    if (r && r.dataset.src) goDevice(r.dataset.src); else if (r) toast("That device isn't on the network map yet");
  });
  $("tHideScanners").checked = hideScanners;
  $("tHideScanners").onchange = (e) => {
    hideScanners = e.target.checked;
    try { localStorage.setItem("nm_hide_scanners", hideScanners ? "1" : "0"); } catch (_) {}
    arcs = []; drawArcs(true);
    if (tSummary) renderThreats(tSummary, true);
  };
  loadBlocked();
  $("tAttackers").addEventListener("click", (e) => { const r = e.target.closest("tr.row"); if (r) openIp(r.dataset.ip); });
  $("tTargets").addEventListener("click", (e) => { const r = e.target.closest("[data-dev]"); if (r) goDevice(r.dataset.dev); });
  // Pulse devices that are being attacked right now on the network map.
  setInterval(() => {
    const now = Date.now();
    for (const [id, t] of underAttack) if (now - t > 8000) underAttack.delete(id);
    if (view === "net" && underAttack.size && !document.hidden && $("altView").classList.contains("hidden")) network.redraw();
  }, 140);
  // Refresh "x ago" labels in the feed now and then.
  setInterval(() => { if (view === "threats" && tSummary) renderThreats(tSummary, false); }, 30000);
}
initThreatUI();

// Coming back to a background browser tab can leave the canvas stale; re-check the map.
document.addEventListener("visibilitychange", () => { if (!document.hidden) setTimeout(healWorld, 200); });

// Build the map the moment its box gets a real size (some layouts settle a little after the tab opens),
// and keep it sized afterwards. Ignore the 0×0 size it has while the tab is hidden.
(function watchWorldBox() {
  const el = $("worldMap");
  if (!el || !window.ResizeObserver) return;
  new ResizeObserver(() => {
    if (view !== "threats" || el.clientWidth < 40 || el.clientHeight < 40) return;
    if (!tChart) { initWorld(); if (tChart) { updateWorld(); drawArcs(); if (typeof drawFlowArcs === "function") drawFlowArcs(); } }
    else tChart.resize();
  }).observe(el);
})();

// Paste lpMapDebug() into the browser console if the map ever misbehaves.
window.lpMapDebug = () => {
  const el = $("worldMap");
  const c = el.querySelector("canvas");
  return {version: (document.querySelector('script[src*="threats.js"]')?.src.split("?v=")[1]) || "?", view,
    box: [el.clientWidth, el.clientHeight], chart: !!tChart, chartSize: tChart ? [tChart.getWidth(), tChart.getHeight()] : null,
    canvas: c ? [c.width, c.height] : null, echarts: window.echarts?.version, worldMap: worldLibReady(),
    geo: tChart ? tChart.getOption().geo[0].center.concat(tChart.getOption().geo[0].zoom) : null,
    message: el.textContent.trim().slice(0, 80)};
};

// "Allow" on an ignored router-log sender
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-allow-syslog]");
  if (!b) return;
  b.disabled = true;
  if (await api("/api/threats/syslog-allow", "POST", {ip: b.dataset.allowSyslog})) {
    toast(`Router logs from ${b.dataset.allowSyslog} are now accepted`);
    if (settings?.threats) settings.threats.syslog_from = [...new Set([...(settings.threats.syslog_from || []), b.dataset.allowSyslog])];
    b.closest("span")?.remove();
  }
  b.disabled = false;
});
