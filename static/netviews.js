// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Network map view modes (star, groups, tree, rings, tiles, table) and local-threat display. Loaded after app.js. */

const NET_LAYOUTS = [
  ["star", "fa-circle-nodes", "Star"], ["groups", "fa-object-group", "Groups"], ["tree", "fa-sitemap", "Tree"],
  ["rings", "fa-bullseye", "Rings"], ["tiles", "fa-grip", "Tiles"], ["table", "fa-table-list", "Table"],
  ["topo", "fa-diagram-project", "Topology"],
];
let netLayout = (() => { try { return localStorage.getItem("nm_layout") || "star"; } catch (_) { return "star"; } })();
if (!NET_LAYOUTS.some(([k]) => k === netLayout)) netLayout = "star";
let tableSort = {key: "ip", dir: 1};
let ringGuides = [];
const localAttackers = new Map();        // device id -> {t, kind, targetId}
const RING_OF = {router: 0, ap: 1, switch: 1, scanner: 1, server: 1, nas: 1, raspberrypi: 1, desktop: 2, laptop: 2,
  phone: 2, tablet: 2, printer: 3, tv: 3, camera: 3, game: 3, speaker: 3, iot: 3, unknown: 3};
const RING_NAMES = ["", "Infrastructure", "Computers & phones", "Smart home & media"];
const TYPE_ORDER = Object.keys(TYPES);
const LOCAL_WINDOW = 15 * 60 * 1000;

function isLocalAttacker(id) {
  const a = localAttackers.get(id);
  return !!a && Date.now() - a.t < LOCAL_WINDOW;
}

/* ------------------------------------------------------------ group hub nodes */
function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r); ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y); ctx.closePath();
}

function groupRenderer({ctx, id, x, y, sel, hover}) {
  const type = id.slice(6);
  const t = TYPES[type] || TYPES.unknown;
  const n = [...devices.values()].filter((d) => (TYPES[d.type] ? d.type : "unknown") === type && matches(d)).length;
  const label = `${t.label} · ${n}`;
  ctx.font = "600 12px Inter, system-ui, sans-serif";
  const w = ctx.measureText(label).width + 46, h = 30;
  return {
    drawNode() {
      ctx.save();
      if (sel || hover) { ctx.shadowColor = t.color; ctx.shadowBlur = 16; }
      roundRect(ctx, x - w / 2, y - h / 2, w, h, 15);
      ctx.fillStyle = "#0f182c"; ctx.fill();
      ctx.shadowBlur = 0;
      ctx.lineWidth = sel ? 2.5 : 1.5; ctx.strokeStyle = t.color; ctx.stroke();
      ctx.fillStyle = t.color;
      drawIcon(ctx, t, x - w / 2 + 17, y + 0.5, 15);
      ctx.fillStyle = "#e2e8f0"; ctx.font = "600 12px Inter, system-ui, sans-serif";
      ctx.textAlign = "left"; ctx.textBaseline = "middle";
      ctx.fillText(label, x - w / 2 + 32, y + 0.5);
      ctx.restore();
    },
    nodeDimensions: {width: w, height: h},
  };
}

/* ------------------------------------------------------------ graph transforms */
function transformGraph(N, E, hub, gw) {
  const grouped = netLayout === "groups" || netLayout === "tree";
  if (grouped) {
    const groups = new Map();
    for (const d of devices.values()) {
      if (d.id === hub) continue;
      const e = E.get(`e-${d.id}`);
      if (!e) continue;
      const gid = `__grp_${TYPES[d.type] ? d.type : "unknown"}`;
      groups.set(gid, (groups.get(gid) || 0) + (e.hidden ? 0 : 1));
      e.from = gid;
    }
    for (const [gid, n] of groups) {
      N.set(gid, {id: gid, hidden: n === 0, mass: 2, title: `${(TYPES[gid.slice(6)] || TYPES.unknown).label}: ${n}`});
      if (hub) E.set(`g-${gid}`, {id: `g-${gid}`, from: hub, to: gid, hidden: n === 0, width: 2, dashes: false,
        color: {color: "#2b4a7a", highlight: "#38bdf8", hover: "#38bdf8"}});
    }
  }
  for (const [id, n] of N) {
    n.fixed = false;
    n.level = netLayout !== "tree" ? undefined : id === INTERNET ? 0 : id === hub ? 1 : id.startsWith("__grp_") ? 2 : 3;
  }
  ringGuides = [];
  if (netLayout === "rings") {
    const rings = [[], [], [], []];
    [...devices.values()].filter((d) => d.id !== hub && N.get(d.id) && !N.get(d.id).hidden)
      .sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) || sortKey(a).localeCompare(sortKey(b)))
      .forEach((d) => rings[Math.max(1, RING_OF[d.type] ?? 3)].push(d));
    let r = 0;
    rings.forEach((ring, i) => {
      if (!i || !ring.length) return;
      r = Math.max(r + 170, (ring.length * 78) / (2 * Math.PI));
      ring.forEach((d, k) => {
        const a = -Math.PI / 2 + (2 * Math.PI * k) / ring.length + (i % 2 ? 0 : Math.PI / ring.length);
        Object.assign(N.get(d.id), {x: r * Math.cos(a), y: r * Math.sin(a), fixed: true});
      });
      ringGuides.push({r, label: RING_NAMES[i]});
    });
    if (hub && N.get(hub)) Object.assign(N.get(hub), {x: 0, y: 0, fixed: true});
    if (N.get(INTERNET)) Object.assign(N.get(INTERNET), {x: 0, y: -(r + 120), fixed: true});
    for (const e of E.values()) if (e.id.startsWith("e-") && e.id !== `e-${INTERNET}`) e.color = {...(e.color || {}), opacity: 0.25};
  }
  // Red arrows from a LAN device that is attacking to its target.
  for (const [id, a] of localAttackers) {
    if (Date.now() - a.t > LOCAL_WINDOW || !a.targetId || !N.get(id) || !N.get(a.targetId)) continue;
    E.set(`la-${id}`, {id: `la-${id}`, from: id, to: a.targetId, arrows: {to: {enabled: true, scaleFactor: 0.8}},
      dashes: [7, 5], width: 2.5, physics: false, smooth: {type: "curvedCW", roundness: 0.25},
      color: {color: "#f43f5e", highlight: "#fb7185", hover: "#fb7185"}, title: a.title || "Suspicious activity"});
  }
}

function drawRingGuides(ctx) {
  if (netLayout !== "rings") return;
  ctx.save();
  for (const g of ringGuides) {
    ctx.beginPath(); ctx.arc(0, 0, g.r, 0, 2 * Math.PI);
    ctx.setLineDash([4, 8]); ctx.lineWidth = 1; ctx.strokeStyle = "rgba(56,189,248,.18)"; ctx.stroke();
    ctx.setLineDash([]);
    ctx.font = "600 11px Inter, system-ui, sans-serif"; ctx.fillStyle = "rgba(139,155,182,.8)";
    ctx.textAlign = "center"; ctx.fillText(g.label.toUpperCase(), 0, g.r + 18);
  }
  ctx.restore();
}

function setLayout(mode) {
  netLayout = mode;
  try { localStorage.setItem("nm_layout", mode); } catch (_) {}
  applyLayoutMode();
}

function applyLayoutMode() {
  const graph = !["tiles", "table", "topo"].includes(netLayout);
  if (netLayout === "topo" && typeof TOPO !== "undefined") TOPO.fit = true;
  $("map").classList.toggle("hidden", !graph);
  $("altView").classList.toggle("hidden", graph);
  $("legend").classList.add("hidden");
  for (const id of ["btnPhysics", "btnSaveLayout", "btnResetLayout"]) $(id).classList.toggle("hidden", netLayout !== "star");
  for (const id of ["btnFit", "btnLegend"]) $(id).classList.toggle("hidden", !graph);
  document.querySelectorAll("#layoutPick button").forEach((b) => {
    b.classList.toggle("on", b.dataset.mode === netLayout);
    b.setAttribute("aria-pressed", String(b.dataset.mode === netLayout));
  });
  if (graph) {
    const tree = netLayout === "tree";
    network.setOptions({
      layout: {hierarchical: tree ? {enabled: true, direction: "UD", sortMethod: "directed", levelSeparation: 130,
        nodeSpacing: 96, treeSpacing: 150, shakeTowards: "roots"} : {enabled: false}},
      physics: {enabled: netLayout === "groups" || (netLayout === "star" && physicsOn), solver: "forceAtlas2Based"},
    });
    const lay = JSON.parse(layoutKey || "{}");
    layoutKey = "";                      // re-apply a saved star layout when coming back to star
    syncMap(lay);
    if (netLayout === "star" && !Object.keys(lay).length && !physicsOn) setPhysics(true);
    setTimeout(() => network.fit({animation: {duration: 500}}), 150);
  }
  renderAltViews();
}

/* ------------------------------------------------------------ tiles and table */
function flagsHtml(d) {
  const rk = risk(d);
  return [
    isLocalAttacker(d.id) ? '<i class="fa-solid fa-user-ninja" style="color:#f43f5e" title="Suspicious activity"></i>' : "",
    d.trusted ? "" : '<i class="fa-solid fa-user-secret" style="color:#f87171" title="Not trusted yet"></i>',
    rk <= 1 ? `<i class="fa-solid fa-triangle-exclamation" style="color:${rk ? "#fbbf24" : "#f87171"}" title="Security warning"></i>` : "",
    d.watched ? '<i class="fa-solid fa-eye" style="color:#38bdf8" title="Watched"></i>' : "",
  ].join("");
}

function renderAltViews() {
  if (netLayout === "tiles") renderTiles();
  else if (netLayout === "table") renderTable();
  else if (netLayout === "topo" && typeof renderTopology === "function") renderTopology();
}

function renderTiles() {
  const list = [...devices.values()].filter(matches);
  const SECTIONS = [["Network & servers", "fa-network-wired", "#f59e0b"], ["Computers & phones", "fa-laptop", "#60a5fa"],
    ["Smart home & media", "fa-house-signal", "#22d3ee"]];
  const groups = new Map();
  list.sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) || sortKey(a).localeCompare(sortKey(b)))
    .forEach((d) => {
      const k = Math.max(0, (RING_OF[d.type] ?? 3) - 1);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(d);
    });
  const order = [...groups.keys()].sort();
  $("altView").innerHTML = list.length ? `<div class="tiles-wrap">${order.map((k) => {
    const [title, icon, color] = SECTIONS[k];
    return `<section class="tile-group"><h4><i class="fa-solid ${icon}" style="color:${color}"></i>${esc(title)}<span>${groups.get(k).length}</span></h4>
      <div class="tiles">${groups.get(k).map((d) => { const t = typeOf(d); return `
        <button class="tile ${d.online ? "" : "off"} ${isLocalAttacker(d.id) ? "bad" : ""} ${selected === d.id ? "sel" : ""}" data-id="${esc(d.id)}" style="--c:${t.color}">
          <div class="tile-top"><span class="ic"><i class="${faClass(t)}"></i></span>
            <span class="flags">${flagsHtml(d)}</span><span class="dot ${d.scanning ? "scan" : d.online ? "on" : "off"}"></span></div>
          <div class="tile-name">${esc(nameOf(d))}</div>
          <div class="tile-ip">${esc(d.ip)}</div>
          <div class="tile-sub">${esc(d.vendor || "Unknown vendor")}</div>
          <div class="tile-foot"><span>${d.online ? (d.rtt_ms != null ? `${d.rtt_ms} ms` : "online") : `seen ${ago(d.last_seen)}`}</span>
            <span>${(d.ports || []).length} port${(d.ports || []).length === 1 ? "" : "s"}</span></div>
        </button>`; }).join("")}</div></section>`;
  }).join("")}</div>` : `<div class="alt-empty">No devices match.</div>`;
}

const TABLE_COLS = [
  ["status", "Status", (d) => (d.online ? 0 : 1)], ["name", "Name", (d) => nameOf(d).toLowerCase()],
  ["type", "Type", (d) => typeOf(d).label], ["ip", "IP address", (d) => d.ip.split(".").map((n) => n.padStart(3, "0")).join(".")],
  ["mac", "MAC", (d) => d.mac || ""], ["vendor", "Vendor", (d) => (d.vendor || "").toLowerCase()],
  ["rtt", "Latency", (d) => (d.online && d.rtt_ms != null ? d.rtt_ms : 1e9)], ["ports", "Open ports", (d) => -(d.ports || []).length],
  ["seen", "Last seen", (d) => -d.last_seen], ["flags", "Flags", (d) => -(isLocalAttacker(d.id) * 8 + !d.trusted * 4 + (risk(d) <= 1) * 2 + !!d.watched)],
];

function renderTable() {
  const col = TABLE_COLS.find(([k]) => k === tableSort.key) || TABLE_COLS[3];
  const list = [...devices.values()].filter(matches).sort((a, b) => {
    const x = col[2](a), y = col[2](b);
    return (x < y ? -1 : x > y ? 1 : 0) * tableSort.dir;
  });
  $("altView").innerHTML = `<div class="dtable-wrap"><table class="dtable"><thead><tr>${TABLE_COLS.map(([k, label]) =>
    `<th data-sort="${k}" class="${k === tableSort.key ? "sorted" : ""}" tabindex="0">${label}${k === tableSort.key ? ` <i class="fa-solid fa-caret-${tableSort.dir > 0 ? "up" : "down"}"></i>` : ""}</th>`).join("")}</tr></thead>
    <tbody>${list.map((d) => { const t = typeOf(d); return `<tr data-id="${esc(d.id)}" class="${d.online ? "" : "off"} ${selected === d.id ? "sel" : ""}" tabindex="0">
      <td><span class="dot ${d.scanning ? "scan" : d.online ? "on" : "off"}"></span></td>
      <td class="nm"><i class="${faClass(t)}" style="color:${t.color}"></i>${esc(nameOf(d))}</td>
      <td class="muted">${esc(t.label)}</td><td class="mono">${esc(d.ip)}</td><td class="mono muted">${esc(d.mac || "—")}</td>
      <td class="muted">${esc(d.vendor || "—")}</td><td class="mono">${d.online && d.rtt_ms != null ? d.rtt_ms + " ms" : "—"}</td>
      <td class="mono">${(d.ports || []).map((p) => p.port).slice(0, 6).join(", ") || "—"}</td>
      <td class="muted">${d.online ? "now" : ago(d.last_seen)}</td><td class="flags">${flagsHtml(d)}</td></tr>`; }).join("")}
    </tbody></table>${list.length ? "" : `<div class="alt-empty">No devices match.</div>`}</div>`;
}

/* ------------------------------------------------------------ local threats */
const LOCAL_ICON = {arp_sweep: "fa-magnifying-glass-location", arp_spoof: "fa-masks-theater", rogue_dhcp: "fa-tower-broadcast", router_changed: "fa-arrows-rotate", ip_conflict: "fa-clone", port_scan: "fa-crosshairs", lateral: "fa-diagram-project",
  honeypot: "fa-bug", ips: "fa-shield-virus", firewall: "fa-road-barrier"};

function localRow(e) {
  const who = e.src_name || e.src || e.mac || "Unknown device";
  const tgt = e.target_name || e.target;
  return `<div class="lrow ${e.severity}" data-src="${esc(e.src_id)}">
    <span class="lic"><i class="fa-solid ${LOCAL_ICON[e.kind] || "fa-triangle-exclamation"}"></i></span>
    <div class="ltxt"><div><b>${esc(e.title || e.kind)}</b> <span class="sev ${esc(e.severity)}">${esc(e.severity)}</span></div>
      <div class="lwho"><span class="mono">${esc(who)}</span>${tgt ? ` → <span class="mono">${esc(tgt)}</span>` : ""}${e.dport ? ` :${e.dport}` : ""}</div>
      ${e.detail ? `<div class="muted">${esc(e.detail)}</div>` : ""}</div>
    <time>${ago(e.t)}</time></div>`;
}

function noteLocalEvent(e) {
  if (e.src_id) localAttackers.set(e.src_id, {t: e.t * 1000, kind: e.kind, targetId: e.target_id, title: e.title});
  if (e.target_id) underAttack.set(e.target_id, Date.now());
}

async function loadDeviceLocal(id) {
  const d = devices.get(id);
  if (!d) return;
  const list = await api(`/api/devices/${encodeURIComponent(id)}/local`, "GET");
  const box = $("localBox");
  if (!list || selected !== id || !box) return;
  if (!list.length) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const scanner = list.some((e) => (e.src === d.ip || (e.mac && e.mac === d.mac)) && ["arp_sweep", "port_scan"].includes(e.kind));
  box.classList.remove("hidden");
  box.innerHTML = `<h4>Suspicious activity</h4><div class="lrows">${list.slice(0, 8).map(localRow).join("")}</div>
    ${scanner ? `<label class="chk-line"><input type="checkbox" id="scansOk" ${d.scans_ok ? "checked" : ""}>
      This device is allowed to scan the network (it runs Fing, nmap or similar)</label>` : ""}`;
  if ($("scansOk")) $("scansOk").onchange = async (ev) => {
    if (await api(`/api/devices/${encodeURIComponent(id)}`, "POST", {scans_ok: ev.target.checked}))
      toast(ev.target.checked ? "Scans from this device won't raise alerts" : "Scans from this device will alert again");
  };
}

/* ------------------------------------------------------------ wiring */
(function initNetViews() {
  $("layoutPick").innerHTML = NET_LAYOUTS.map(([k, icon, label]) =>
    `<button data-mode="${k}" title="${label} view" aria-pressed="false"><i class="fa-solid ${icon}"></i><span>${label}</span></button>`).join("");
  $("layoutPick").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setLayout(b.dataset.mode); });
  $("altView").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (th) {
      tableSort = {key: th.dataset.sort, dir: tableSort.key === th.dataset.sort ? -tableSort.dir : 1};
      renderTable(); return;
    }
    const el = e.target.closest("[data-id]");
    if (el) openPanel(el.dataset.id);
  });
  $("altView").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const th = e.target.closest("th[data-sort]");
    if (th) { th.click(); return; }
    const el = e.target.closest("[data-id]");
    if (el) openPanel(el.dataset.id);
  });
  network.on("beforeDrawing", drawRingGuides);
  // Expire attacker rings and arrows quietly.
  setInterval(() => {
    let changed = false;
    for (const [id, a] of localAttackers) if (Date.now() - a.t > LOCAL_WINDOW) { localAttackers.delete(id); changed = true; }
    if (changed) { syncMap(JSON.parse(layoutKey || "{}")); renderAltViews(); }
  }, 30000);
  applyLayoutMode();
})();
