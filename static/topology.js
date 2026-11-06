// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Topology layout of the Network tab: internet > gateway > switches and access points > devices, with Wi-Fi/wired
   link details, zones (VLANs), colour modes, focus, a change feed, export and a minimap. Drawn as plain SVG so it
   can be exported. Data comes from /api/topology (UniFi where connected, manual choices for any other router). */

const TOPO = {data: null, sel: null, view: {x: 0, y: 0, k: 1}, fit: true, color: "type", zone: "", traffic: false,
  talkers: new Map(), collapsed: new Set(), expanded: new Set(), pop: "", layout: null, timer: null, loading: false};
try { TOPO.color = localStorage.getItem("nm_topo_color") || "type"; } catch (_) {}
TOPO.spread = (() => { try { return localStorage.getItem("nm_topo_spread") !== "0"; } catch (_) { return true; } })();
TOPO.pos = (() => { try { return JSON.parse(localStorage.getItem("nm_topo_pos") || "{}") || {}; } catch (_) { return {}; } })();
const topoSavePos = () => { try { localStorage.setItem("nm_topo_pos", JSON.stringify(TOPO.pos)); } catch (_) {} };
const TOPO_INFRA = new Set(["gateway", "switch", "ap"]);
const TOPO_SIZE = {hw: 224, hh: 74, cw: 164, ch: 46, gap: 10, pad: 12, vgap: 54, hgap: 28, maxChips: 24};
const TOPO_COLORS = [["type", "Device type"], ["status", "Status"], ["risk", "Security risk"], ["zone", "Zone / VLAN"],
  ["signal", "Wi-Fi signal"], ["age", "New devices"]];
const SIGNAL_CLR = {good: "#22c55e", fair: "#f59e0b", poor: "#ef4444"};
const FA = `font-family="'Font Awesome 6 Free','Font Awesome 7 Free','Font Awesome 5 Free'" font-weight="900"`;
const FAB = `font-family="'Font Awesome 6 Brands','Font Awesome 7 Brands','Font Awesome 5 Brands'" font-weight="400"`;

/* ------------------------------------------------------------ data */
async function loadTopology(force = false) {
  if (TOPO.loading) return;
  TOPO.loading = true;
  try {
    const r = await api(force ? "/api/topology/refresh" : "/api/topology", force ? "POST" : "GET");
    if (r) { TOPO.data = r; if (netLayout === "topo") renderTopology(); }
    if (TOPO.traffic) loadTopoTraffic();
  } finally { TOPO.loading = false; }
}

async function loadTopoTraffic() {
  const f = await api("/api/flows?hours=1&talkers=1000", "GET");
  if (!f) return;
  TOPO.talkers = new Map((f.talkers || []).filter((t) => t.id).map((t) => [t.id, t.count]));
  TOPO.trafficTotal = f.total || 0;
  if (netLayout === "topo") renderTopology();
}

/* connections per device, and summed up the tree for switches, access points and links */
function topoTraffic(data) {
  // Real throughput from UniFi when it supplies it; otherwise connection counts from the router logs
  // ...but only when several devices report a speed; a lone reading would leave the rest of the map still
  const live = data.nodes.filter((n) => n.kind === "client" && n.rate > 0).length;
  const infraLive = data.nodes.some((n) => n.kind !== "client" && n.uplink_rate > 0);
  const rates = !!(data.sources && data.sources.rates) && (live >= 3 || infraLive || !TOPO.talkers.size);
  const own = rates ? new Map(data.nodes.filter((n) => n.rate > 0).map((n) => [n.id, n.rate])) : TOPO.talkers;
  const sub = new Map(), byId = new Map(data.nodes.map((n) => [n.id, n]));
  for (const n of data.nodes) {
    const c = own.get(n.id) || 0;
    if (!c) continue;
    for (let cur = n, i = 0; cur && i < 20; i++) { sub.set(cur.id, (sub.get(cur.id) || 0) + c); cur = byId.get(cur.parent); }
  }
  if (rates) {
    // A switch or AP reports the speed of its own uplink, which includes devices UniFi doesn't list individually,
    // so a link is at least that busy, and the link above it at least as busy as the busiest link below.
    const kids = new Map();
    for (const n of data.nodes) if (n.parent) (kids.get(n.parent) || kids.set(n.parent, []).get(n.parent)).push(n);
    const walk = (n, depth) => {
      let v = sub.get(n.id) || 0;
      if (depth < 20) for (const k of kids.get(n.id) || []) v = Math.max(v, walk(k, depth + 1));
      if (n.kind !== "client" && n.uplink_rate > 0) v = Math.max(v, n.uplink_rate);
      if (v > 0) sub.set(n.id, v);
      return v;
    };
    for (const n of data.nodes) if (n.parent === "__internet" || !byId.has(n.parent)) walk(n, 0);
  }
  const max = Math.max(1, ...data.nodes.filter((n) => n.kind === "client").map((n) => own.get(n.id) || 0));
  const maxSub = Math.max(1, ...data.nodes.filter((n) => n.kind !== "gateway").map((n) => sub.get(n.id) || 0));
  const lg = (c, m) => (c > 0 ? Math.max(0.08, Math.log1p(c) / Math.log1p(m)) : 0);   // log scale: a busy device doesn't flatten the rest
  const fmt = rates ? topoBps : (c) => c.toLocaleString() + " conn/h";
  return {own, sub, max, maxSub, lg, rates, fmt};
}

/* bytes per second -> "4.2 Mbps" */
function topoBps(b) {
  const bits = b * 8;
  if (bits >= 1e9) return (bits / 1e9).toFixed(1) + " Gbps";
  if (bits >= 1e6) return (bits / 1e6).toFixed(bits >= 1e7 ? 0 : 1) + " Mbps";
  if (bits >= 1e3) return Math.round(bits / 1e3) + " Kbps";
  return Math.round(bits) + " bps";
}

function startTopoTimer() {
  clearInterval(TOPO.timer);
  TOPO.timer = setInterval(() => { if (netLayout === "topo" && view === "net") loadTopology(); }, 30000);
}

/* ------------------------------------------------------------ colours */
function topoTheme() {
  const v = (n, f) => cssVar(n, f);
  return {panel: v("--panel", "#111a2e"), panel2: v("--panel2", "#18233b"), border: v("--border", "#25324d"), border2: v("--border2", "#34456a"),
    text: v("--text", "#e5e9f2"), muted: v("--muted", "#8b9bb6"), dim: v("--dim", "#5d6f8f"), accent: v("--accent", "#38bdf8"),
    bg: v("--bg", "#0a0f1c"), green: v("--green", "#22c55e"), red: v("--red", "#f43f5e"), amber: v("--amber", "#f59e0b")};
}

function topoNodeColor(n, T) {
  const d = devices.get(n.id);
  switch (TOPO.color) {
    case "status": return !n.online ? T.dim : d && !d.trusted ? T.red : T.green;
    case "risk": { const r = d ? risk(d) : 9; return r === 0 ? T.red : r === 1 ? T.amber : r === 2 ? "#60a5fa" : T.green; }
    case "zone": { const z = (TOPO.data.zones || []).find((x) => x.name === n.zone); return z ? z.color : T.dim; }
    case "signal": return n.link && n.link.quality ? SIGNAL_CLR[n.link.quality] : n.link && n.link.medium === "wired" ? T.dim : T.muted;
    case "age": return n.first_seen && Date.now() / 1000 - n.first_seen < 86400 ? T.accent : T.dim;
    default: return (TYPES[n.type] || TYPES.unknown).color;
  }
}

/* ------------------------------------------------------------ layout */
function topoLayout(data) {
  const S = {...TOPO_SIZE, vgap: TOPO.spread ? 115 : TOPO_SIZE.vgap, hgap: TOPO.spread ? 100 : TOPO_SIZE.hgap}, nodes = data.nodes;   // Spread gives the cables room to fan out
  const ch = new Map();
  for (const n of nodes) { const p = n.parent || "__internet"; if (!ch.has(p)) ch.set(p, []); ch.get(p).push(n); }
  const byName = (a, b) => (a.zone || "").localeCompare(b.zone || "") || (a.name || "").localeCompare(b.name || "");
  const zoneOk = (n) => !TOPO.zone || n.zone === TOPO.zone;
  const root = data.gateway ? nodes.find((n) => n.id === data.gateway) : null;

  function build(X, depth) {
    const kids = (ch.get(X.id) || []).slice();
    const infra = kids.filter((k) => TOPO_INFRA.has(k.kind)).sort(byName);
    const cl = kids.filter((k) => !TOPO_INFRA.has(k.kind) && zoneOk(k)).sort(byName);
    const folded = TOPO.collapsed.has(X.id);
    const subs = folded ? [] : infra.map((k) => build(k, depth + 1));
    let cb = null;
    if (!folded && cl.length) {
      const all = TOPO.expanded.has(X.id), shown = all ? cl : cl.slice(0, S.maxChips);
      const cols = Math.max(1, Math.min(shown.length <= 3 ? shown.length : 4, Math.ceil(Math.sqrt(shown.length * 1.5))));
      const rows = Math.ceil(shown.length / cols), more = cl.length - shown.length;
      const sp = TOPO.spread, gx = sp ? 64 : S.gap, gy = sp ? 84 : S.gap, pd = sp ? 0 : S.pad, extra = (more > 0 || all && cl.length > S.maxChips ? 24 : 0);
      cb = {list: shown, cols, rows, more, total: cl.length, all, spread: sp, gx, gy, pd,
        w: cols * S.cw + (cols - 1) * gx + pd * 2, h: rows * S.ch + (rows - 1) * gy + pd * 2 + (sp ? 0 : 22) + extra};
    }
    const parts = [cb, ...subs].filter(Boolean);
    const contentW = parts.reduce((s, p) => s + p.w, 0) + S.hgap * Math.max(0, parts.length - 1);
    const w = Math.max(S.hw, contentW), contentH = parts.reduce((m, p) => Math.max(m, p.h), 0);
    return {node: X, depth, w, h: S.hh + (parts.length ? S.vgap + contentH : 0), cb, subs, parts, contentW, folded,
      hiddenKids: folded ? infra.length + cl.length : 0};
  }
  if (!root) return null;
  const tree = build(root, 0);
  const pos = {headers: [], blocks: [], chips: [], links: []};
  function place(t, ox, oy) {
    const hx = ox + (t.w - S.hw) / 2;
    t.x = hx; t.y = oy; t.cx = hx + S.hw / 2;
    pos.headers.push(t);
    let x = ox + (t.w - t.contentW) / 2;
    const y = oy + S.hh + S.vgap;
    for (const p of t.parts) {
      if (p === t.cb) {
        p.x = x; p.y = y; p.cx = x + p.w / 2; p.parent = t;
        pos.blocks.push(p);
        p.list.forEach((n, i) => {
          const top = p.spread ? 0 : S.pad + 22, o = p.spread ? TOPO.pos[n.id] || [0, 0] : [0, 0];
          const bx = x + p.pd + (i % p.cols) * (S.cw + p.gx), by = y + top + Math.floor(i / p.cols) * (S.ch + p.gy);
          pos.chips.push({node: n, x: bx + o[0], y: by + o[1], block: p, parent: t});
        });
      } else {
        place(p, x, y);
        pos.links.push({from: t, to: p});
      }
      x += p.w + S.hgap;
    }
  }
  place(tree, 0, S.hh + 40 + S.vgap * 0.7);
  const inet = {x: tree.cx - 78, y: 0, w: 156, h: 44};
  const all = [...pos.headers.map((h) => ({x: h.x, y: h.y, w: S.hw, h: S.hh})), ...pos.blocks, inet];
  const ex = pos.chips.map((c) => ({x: c.x, y: c.y, w: S.cw, h: S.ch}));      // dragged devices count too
  const b = {x0: Math.min(...all.map((a) => a.x), ...ex.map((a) => a.x)), y0: 0, x1: Math.max(...all.map((a) => a.x + a.w), ...ex.map((a) => a.x + a.w)),
    y1: Math.max(...all.map((a) => a.y + a.h), ...ex.map((a) => a.y + a.h))};
  return {tree, inet, ...pos, bounds: b};
}

/* ------------------------------------------------------------ drawing helpers */
const tx = (s, n = 24) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const fmtRate = (kbps) => (kbps ? (kbps >= 1000 ? `${Math.round(kbps / 1000)} Mbps` : `${kbps} kbps`) : "");
const fmtSpeed = (m) => (m ? (m >= 1000 ? `${m / 1000}G` : `${m}M`) : "");
const fmtUp = (s) => (s ? (s > 86400 ? `${Math.floor(s / 86400)}d` : s > 3600 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 60)}m`) : "");

function topoLinkLabel(n) {
  const l = n.link || {};
  if (l.medium === "wired") return [l.port ? `Port ${l.port}` : "", fmtSpeed(l.speed)].filter(Boolean).join(" · ");
  if (l.medium === "wifi") return l.mesh ? "Wireless uplink" : "Wi-Fi";
  return "";
}

function sigBars(x, y, q, T) {
  const lvl = q === "good" ? 3 : q === "fair" ? 2 : q === "poor" ? 1 : 0;
  return [0, 1, 2].map((i) => `<rect x="${x + i * 5}" y="${y - 4 - i * 3}" width="3.4" height="${4 + i * 3}" rx="1" fill="${i < lvl ? SIGNAL_CLR[q] : T.border2}"/>`).join("");
}

function infraSummary(n) {
  const e = n.extra || {};
  if (n.kind === "ap") return [`${e.clients || 0} client${e.clients === 1 ? "" : "s"}`, (e.ssids || []).length ? `${e.ssids.length} SSID${e.ssids.length === 1 ? "" : "s"}` : ""].filter(Boolean).join(" · ");
  if (n.kind === "switch") return [e.ports_total ? `${e.ports_up}/${e.ports_total} ports up` : `${e.clients || 0} devices`, e.poe_watts ? `${e.poe_watts} W PoE` : ""].filter(Boolean).join(" · ");
  return `${e.clients || 0} connected`;
}

/* traffic colour: green when quiet through orange to red when busy (not the theme accent, so it stands out from the map) */
const topoHeat = (lv) => `hsl(${Math.round(140 - 125 * Math.max(0, Math.min(1, lv)))} 92% 56%)`;

/* A link drawn like a cable: dark jacket, lighter core, and packets travelling toward the parent when there is traffic. */
function topoCable(d, o) {
  const {T, wired, w, lv, hot, exp} = o, heatc = topoHeat(lv);
  let g = "";
  if (wired) {
    g += `<path d="${d}" fill="none" stroke="${T.bg}" stroke-width="${w + 4}" stroke-linecap="round" opacity=".95"/>`;
    g += `<path d="${d}" fill="none" stroke="${hot ? T.accent : T.muted}" stroke-width="${w}" stroke-linecap="round" opacity="${hot ? 1 : 0.45}"/>`;
    if (lv) g += `<path d="${d}" fill="none" stroke="${heatc}" stroke-width="${w}" stroke-linecap="round" opacity="${0.18 + lv * 0.3}"/>`;
  } else {
    g += `<path d="${d}" fill="none" stroke="${hot ? T.accent : "#f59e0b"}" stroke-width="${hot ? 2.2 : 1.5}" stroke-dasharray="5 5" opacity=".75"/>`;
  }
  if (lv && !exp) g += `<path class="tp-pulse" d="${d}" fill="none" stroke="${heatc}" stroke-width="${(w + 1.5 + lv * 2.5).toFixed(1)}" stroke-linecap="round" stroke-dasharray="0.1 15.9" style="animation-duration:${(1.7 - lv * 1.2).toFixed(2)}s"/>`;
  return g;
}

function weakClients(data) {
  return data.nodes.filter((n) => n.link && n.link.quality === "poor" && n.online);
}

/* ------------------------------------------------------------ render */
function topoSvg(L, T, opts = {}) {
  const S = TOPO_SIZE, d = TOPO.data, glyph = !opts.export;
  const focus = !opts.export && TOPO.sel ? topoFocusSet(L) : null;
  const dim = (id) => (focus && !focus.has(id) ? ' class="tp-dim"' : "");
  const out = [];
  const TR = TOPO.traffic ? topoTraffic(d) : null;
  // internet + gateway
  const g = L.tree;
  out.push(`<g${dim("__internet")}><rect x="${L.inet.x}" y="${L.inet.y}" width="${L.inet.w}" height="${L.inet.h}" rx="22" fill="${T.panel}" stroke="${T.accent}" stroke-width="1.5"/>
    ${glyph ? `<text x="${L.inet.x + 26}" y="${L.inet.y + 28}" ${FA} font-size="16" fill="${T.accent}"></text>` : ""}
    <text x="${L.inet.x + 52}" y="${L.inet.y + 27}" font-size="13" font-weight="600" fill="${T.text}">Internet</text></g>`);
  out.push(`<path d="M${g.cx},${L.inet.y + 44} V${g.y}" stroke="${T.accent}" stroke-width="2.4" fill="none" opacity=".7"/>`);
  // links between infrastructure
  for (const l of L.links) {
    const a = l.from, b = l.to, n = b.node, my = (a.y + S.hh + b.y) / 2, wired = (n.link || {}).medium !== "wifi";
    const w = wired ? ((n.link || {}).speed >= 2500 ? 3.4 : (n.link || {}).speed >= 1000 ? 2.6 : 1.8) : 2.2;
    const hot = focus && focus.has(n.id) && focus.has(a.node.id);
    const tf = TR ? TR.lg(TR.sub.get(n.id) || 0, TR.maxSub) : 0;
    out.push(`<g${dim(n.id)}>${topoCable(`M${a.cx},${a.y + S.hh} C${a.cx},${my} ${b.cx},${my} ${b.cx},${b.y}`, {T, wired, w, lv: tf, hot, exp: opts.export})}
      ${topoLinkLabel(n) ? `<text x="${(a.cx + b.cx) / 2 + 8}" y="${my + 4}" font-size="10.5" fill="${T.muted}">${esc(topoLinkLabel(n))}</text>` : ""}</g>`);
  }
  // blocks of devices
  for (const b of L.blocks) {
    const owner = b.parent.node, wifi = b.list.filter((n) => (n.link || {}).medium === "wifi").length;
    const label = `${b.total} device${b.total === 1 ? "" : "s"}${wifi ? ` · ${wifi} Wi-Fi` : ""}`;
    out.push(`<g${dim(owner.id)}>
      ${b.spread ? "" : `<path d="M${b.parent.cx},${b.parent.y + S.hh} C${b.parent.cx},${b.y - 22} ${b.cx},${b.y - 30} ${b.cx},${b.y}" stroke="${T.border2}" stroke-width="1.8" fill="none"/>
      <rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="12" fill="${T.panel2}" fill-opacity=".45" stroke="${T.border}"/>
      <text x="${b.x + S.pad}" y="${b.y + 19}" font-size="11" font-weight="600" fill="${T.muted}" letter-spacing=".4">${esc(label.toUpperCase())}</text>`}
      ${b.more > 0 ? `<g class="tp-more" data-more="${esc(owner.id)}" cursor="pointer"><rect x="${b.x + S.pad}" y="${b.y + b.h - 30}" width="${b.w - S.pad * 2}" height="22" rx="8" fill="${T.panel}" stroke="${T.border2}"/>
        <text x="${b.x + b.w / 2}" y="${b.y + b.h - 15}" font-size="11" text-anchor="middle" fill="${T.accent}">Show ${b.more} more</text></g>` : ""}
      ${b.all && b.total > S.maxChips ? `<g class="tp-more" data-less="${esc(owner.id)}" cursor="pointer"><rect x="${b.x + S.pad}" y="${b.y + b.h - 30}" width="${b.w - S.pad * 2}" height="22" rx="8" fill="${T.panel}" stroke="${T.border2}"/>
        <text x="${b.x + b.w / 2}" y="${b.y + b.h - 15}" font-size="11" text-anchor="middle" fill="${T.accent}">Show fewer</text></g>` : ""}</g>`);
  }
  // one link per device (spread view): thickness and flow follow its traffic
  if (TOPO.spread) {
    for (const c of L.chips) {
      const n = c.node, p = c.parent, x1 = p.cx, y1 = p.y + S.hh, x2 = c.x + S.cw / 2, y2 = c.y, my = y1 + (y2 - y1) * 0.55, wifi = (n.link || {}).medium === "wifi";
      const cnt = TR ? TR.own.get(n.id) || 0 : 0, lv = cnt ? TR.lg(cnt, TR.max) : 0, hot = focus && focus.has(n.id);
      out.push(`<g${focus && !focus.has(n.id) ? ' opacity=".2"' : ""}>${topoCable(`M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`,
        {T, wired: !wifi, w: (n.link || {}).speed >= 2500 ? 3 : (n.link || {}).speed >= 1000 ? 2.4 : 1.8, lv, hot, exp: opts.export})}</g>`);
    }
  }
  // device chips
  for (const c of L.chips) {
    const n = c.node, col = topoNodeColor(n, T), t = TYPES[n.type] || TYPES.unknown, l = n.link || {};
    const d0 = devices.get(n.id), faded = d0 && typeof matches === "function" && !matches(d0);
    const cnt = TR ? TR.own.get(n.id) || 0 : 0, act = cnt ? TR.lg(cnt, TR.max) : 0;
    out.push(`<g class="tp-chip${TOPO.sel === n.id ? " tp-sel" : ""}${!n.online ? " tp-off" : ""}${faded ? " tp-faded" : ""}" data-id="${esc(n.id)}" cursor="pointer"${focus && !focus.has(n.id) ? ' opacity=".22"' : ""}>
      <rect x="${c.x}" y="${c.y}" width="${S.cw}" height="${S.ch}" rx="9" fill="${T.panel}" stroke="${TOPO.sel === n.id ? T.accent : T.border}" stroke-width="${TOPO.sel === n.id ? 2 : 1}"/>
      <rect x="${c.x}" y="${c.y + 6}" width="4" height="${S.ch - 12}" rx="2" fill="${col}"/>
      ${glyph ? `<text x="${c.x + 17}" y="${c.y + 29}" ${t.brand ? FAB : FA} font-size="15" fill="${col}" text-anchor="middle">${t.icon}</text>` : `<circle cx="${c.x + 17}" cy="${c.y + 24}" r="6" fill="${col}"/>`}
      <text x="${c.x + 32}" y="${c.y + 20}" font-size="12" font-weight="600" fill="${T.text}">${esc(tx(n.name, 15))}</text>
      <text x="${c.x + 32}" y="${c.y + 36}" font-size="10.5" fill="${T.muted}">${esc(tx(n.ip, 16))}</text>
      ${l.medium === "wifi" ? sigBars(c.x + S.cw - 20, c.y + 26, l.quality, T) : l.medium === "wired" && glyph ? `<text x="${c.x + S.cw - 12}" y="${c.y + 28}" ${FA} font-size="11" fill="${T.dim}" text-anchor="end"></text>` : ""}
      ${TR ? `<rect x="${c.x + 32}" y="${c.y + S.ch - 7}" width="${S.cw - 44}" height="4" rx="2" fill="${T.border}"/>${act ? `<rect x="${c.x + 32}" y="${c.y + S.ch - 7}" width="${(S.cw - 44) * act}" height="4" rx="2" fill="${topoHeat(act)}"/>` : ""}` : ""}
      ${TR && TOPO.spread ? `<text x="${c.x + S.cw / 2}" y="${c.y + S.ch + 13}" font-size="10" text-anchor="middle" fill="${cnt ? topoHeat(act) : T.dim}">${cnt ? TR.fmt(cnt) : TR.rates ? "idle" : "no traffic"}</text>` : ""}
      ${!n.online ? `<line x1="${c.x + 6}" y1="${c.y + S.ch - 3}" x2="${c.x + S.cw - 6}" y2="${c.y + S.ch - 3}" stroke="${T.dim}" stroke-dasharray="2 3"/>` : ""}
    </g>`);
  }
  if (focus) out.push(topoPathSvg(L, T));   // behind the cards, so the highlight runs between them
  // infrastructure cards (drawn last so links tuck underneath)
  for (const h of L.headers) {
    const n = h.node, col = n.kind === "gateway" ? "#f59e0b" : n.kind === "ap" ? "#fbbf24" : "#fb923c", t = TYPES[n.kind === "ap" ? "ap" : n.kind === "switch" ? "switch" : "router"];
    const e = n.extra || {}, radios = (e.radios || []).slice(0, 3), act = TR && n.kind !== "gateway" ? TR.lg(TR.sub.get(n.id) || 0, TR.maxSub) : 0;
    out.push(`<g class="tp-head${TOPO.sel === n.id ? " tp-sel" : ""}" data-id="${esc(n.id)}" cursor="pointer"${focus && !focus.has(n.id) ? ' opacity=".22"' : ""}>
      <rect x="${h.x}" y="${h.y}" width="${S.hw}" height="${S.hh}" rx="14" fill="${T.panel}" stroke="${TOPO.sel === n.id ? T.accent : col}" stroke-width="${TOPO.sel === n.id ? 2.4 : 1.6}"/>
      <rect x="${h.x}" y="${h.y}" width="${S.hw}" height="5" rx="2.5" fill="${col}" opacity=".9"/>
      ${glyph ? `<text x="${h.x + 26}" y="${h.y + 36}" ${FA} font-size="20" fill="${col}" text-anchor="middle">${t.icon}</text>` : `<circle cx="${h.x + 26}" cy="${h.y + 32}" r="9" fill="${col}"/>`}
      <text x="${h.x + 48}" y="${h.y + 28}" font-size="13.5" font-weight="700" fill="${T.text}">${esc(tx(n.name, radios.length ? 14 : 22))}</text>
      <text x="${h.x + 48}" y="${h.y + 44}" font-size="11" fill="${T.muted}">${esc(tx([n.model, n.ip].filter(Boolean).join(" · "), 28))}</text>
      <text x="${h.x + 48}" y="${h.y + 60}" font-size="11" fill="${T.accent}">${esc(infraSummary(n))}</text>
      ${radios.map((r, i) => `<g><rect x="${h.x + S.hw - 10 - (radios.length - i) * 38}" y="${h.y + 12}" width="34" height="15" rx="7" fill="${T.panel2}" stroke="${T.border2}"/>
        <text x="${h.x + S.hw - 10 - (radios.length - i) * 38 + 17}" y="${h.y + 23}" font-size="9" text-anchor="middle" fill="${T.muted}">${esc(r.band.replace(" GHz", "G"))}</text></g>`).join("")}
      ${n.online ? "" : `<text x="${h.x + S.hw - 12}" y="${h.y + 24}" font-size="10" text-anchor="end" fill="${T.red}">offline</text>`}
      ${act ? `<rect x="${h.x + 14}" y="${h.y + S.hh - 7}" width="${S.hw - 28}" height="4" rx="2" fill="${T.border}"/><rect x="${h.x + 14}" y="${h.y + S.hh - 7}" width="${(S.hw - 28) * act}" height="4" rx="2" fill="${topoHeat(act)}"/>` : ""}
      ${(ch2(L, n.id)) ? `<g class="tp-fold" data-fold="${esc(n.id)}" cursor="pointer"><circle cx="${h.x + S.hw / 2}" cy="${h.y + S.hh}" r="9" fill="${T.panel}" stroke="${T.border2}"/>
        <text x="${h.x + S.hw / 2}" y="${h.y + S.hh + 4}" font-size="12" text-anchor="middle" fill="${T.muted}">${h.folded ? "+" : "−"}</text></g>` : ""}
    </g>`);
    if (h.folded && h.hiddenKids) out.push(`<text x="${h.cx}" y="${h.y + S.hh + 28}" font-size="11" text-anchor="middle" fill="${T.muted}">${h.hiddenKids} hidden</text>`);
  }
  return out.join("");
}

function ch2(L, id) {   // does this header have anything beneath it to fold?
  const h = L.headers.find((x) => x.node.id === id);
  return h && (h.folded || h.parts.length);
}

function topoFocusSet(L) {
  const s = new Set(), id = TOPO.sel;
  s.add(id); s.add("__internet");
  const byId = new Map(TOPO.data.nodes.map((n) => [n.id, n]));
  for (let c = byId.get(id), i = 0; c && i < 20; i++) { s.add(c.id); c = byId.get(c.parent); }
  for (const n of TOPO.data.nodes) { if (n.parent === id) s.add(n.id); }
  for (const n of TOPO.data.nodes) {   // descendants of an infrastructure node
    let c = n, i = 0;
    while (c && i++ < 20) { if (c.parent === id) { s.add(n.id); break; } c = byId.get(c.parent); }
  }
  return s;
}

function topoPathSvg(L, T) {
  const S = TOPO_SIZE, byId = new Map(TOPO.data.nodes.map((n) => [n.id, n]));
  const hdr = new Map(L.headers.map((h) => [h.node.id, h])), chip = new Map(L.chips.map((c) => [c.node.id, c]));
  const pts = [];
  let cur = byId.get(TOPO.sel);
  if (!cur) return "";
  if (chip.has(cur.id)) {
    const c = chip.get(cur.id); pts.push([c.x + S.cw / 2, c.y]);
    if (!c.block.spread) pts.push([c.block.cx, c.block.y]);
    cur = byId.get(cur.parent);
  }
  for (let i = 0; cur && i < 20; i++) {
    const h = hdr.get(cur.id);
    if (!h) break;
    pts.push([h.cx, h.y + S.hh]); pts.push([h.cx, h.y]);
    cur = byId.get(cur.parent);
  }
  pts.push([L.tree.cx, L.inet.y + 44]);
  return `<polyline points="${pts.map((p) => p.join(",")).join(" ")}" fill="none" stroke="${T.accent}" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" opacity=".85" pointer-events="none"/>`;
}

/* ------------------------------------------------------------ view shell */
function topoShell() {
  const alt = $("altView");
  if ($("topoStage")) return;
  alt.innerHTML = `<div class="topo">
    <div class="topo-bar" id="topoBar"></div>
    <div class="topo-stage" id="topoStage">
      <svg id="topoSvg" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Network topology"><g id="topoRoot"></g></svg>
      <div class="topo-mini" id="topoMini"><svg id="topoMiniSvg"></svg></div>
      <div class="topo-info hidden" id="topoInfo"></div>
      <div class="topo-pop hidden" id="topoPop"></div>
    </div></div>`;
  const svg = $("topoSvg");
  let drag = null;
  const ptrs = new Map();
  let pinch = null;
  let nd = null;      // a device being dragged (spread view)
  svg.addEventListener("pointerdown", (e) => {
    const chip = e.target.closest(".tp-chip");
    if (chip && TOPO.spread && !ptrs.size) {
      const id = chip.dataset.id, c = TOPO.layout && TOPO.layout.chips.find((x) => x.node.id === id);
      if (c) nd = {id, sx: e.clientX, sy: e.clientY, o: (TOPO.pos[id] || [0, 0]).slice(), moved: false, pid: e.pointerId};
      return;
    }
    if (e.target.closest(".tp-chip,.tp-head,.tp-fold,.tp-more")) return;
    ptrs.set(e.pointerId, {x: e.clientX, y: e.clientY});
    svg.setPointerCapture(e.pointerId); svg.classList.add("grab");
    if (ptrs.size === 2) { const [p1, p2] = [...ptrs.values()]; pinch = {d: Math.hypot(p1.x - p2.x, p1.y - p2.y), k: TOPO.view.k}; drag = null; }
    else drag = {x: e.clientX, y: e.clientY, vx: TOPO.view.x, vy: TOPO.view.y};
  });
  svg.addEventListener("pointermove", (e) => {
    if (nd && e.pointerId === nd.pid) {
      const dx = e.clientX - nd.sx, dy = e.clientY - nd.sy;
      if (!nd.moved && Math.abs(dx) + Math.abs(dy) < 5) return;
      if (!nd.moved) { nd.moved = true; try { svg.setPointerCapture(e.pointerId); } catch (_) {} svg.classList.add("grab"); }
      TOPO.pos[nd.id] = [Math.round(nd.o[0] + dx / TOPO.view.k), Math.round(nd.o[1] + dy / TOPO.view.k)];
      if (!nd.raf) nd.raf = requestAnimationFrame(() => { nd.raf = 0; topoRedraw(); });
      return;
    }
    if (!ptrs.has(e.pointerId)) return;
    ptrs.set(e.pointerId, {x: e.clientX, y: e.clientY});
    if (pinch && ptrs.size >= 2) {
      const [p1, p2] = [...ptrs.values()], r = svg.getBoundingClientRect();
      topoZoomAt(pinch.k * Math.hypot(p1.x - p2.x, p1.y - p2.y) / pinch.d, (p1.x + p2.x) / 2 - r.left, (p1.y + p2.y) / 2 - r.top);
    } else if (drag) { TOPO.view.x = drag.vx + (e.clientX - drag.x); TOPO.view.y = drag.vy + (e.clientY - drag.y); topoApplyView(); }
  });
  const endPtr = (e) => {
    if (nd && e.pointerId === nd.pid) {
      if (nd.moved) { topoSavePos(); TOPO.noClick = true; setTimeout(() => { TOPO.noClick = false; }, 350); topoRedraw(); svg.classList.remove("grab"); }
      nd = null; return;
    }
    const was = ptrs.size;
    ptrs.delete(e.pointerId);
    if (was === 1 && drag && Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) < 4) { TOPO.sel = null; $("topoInfo").classList.add("hidden"); renderTopology(); }
    if (ptrs.size < 2) pinch = null;
    if (!ptrs.size) { drag = null; svg.classList.remove("grab"); }
  };
  svg.addEventListener("pointerup", endPtr); svg.addEventListener("pointercancel", endPtr);
  svg.addEventListener("dblclick", (e) => { if (e.target.closest(".tp-chip,.tp-head")) return; const r = svg.getBoundingClientRect(); topoZoomAt(TOPO.view.k * 1.6, e.clientX - r.left, e.clientY - r.top); });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    topoZoomAt(TOPO.view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12), e.clientX - r.left, e.clientY - r.top);
  }, {passive: false});
  svg.addEventListener("click", (e) => {
    const more = e.target.closest("[data-more]"), less = e.target.closest("[data-less]"), fold = e.target.closest("[data-fold]");
    e.stopPropagation();       // the map re-draws below
    if (TOPO.noClick) return;      // that was the end of a drag, not a tap; don't let older handlers see a detached target
    if (more) { TOPO.expanded.add(more.dataset.more); renderTopology(); return; }
    if (less) { TOPO.expanded.delete(less.dataset.less); renderTopology(); return; }
    if (fold) { const id = fold.dataset.fold; TOPO.collapsed.has(id) ? TOPO.collapsed.delete(id) : TOPO.collapsed.add(id); renderTopology(); return; }
    const n = e.target.closest("[data-id]");
    if (n) topoSelect(n.dataset.id);
  });
  $("topoMini").addEventListener("pointerdown", (e) => {
    const L = TOPO.layout; if (!L) return;
    const r = $("topoMini").getBoundingClientRect(), b = L.bounds, s = topoMiniScale(L, r);
    const wx = (e.clientX - r.left) / s + b.x0 - 10, wy = (e.clientY - r.top) / s + b.y0 - 10, sr = svg.getBoundingClientRect();
    TOPO.view.x = sr.width / 2 - wx * TOPO.view.k; TOPO.view.y = sr.height / 2 - wy * TOPO.view.k; topoApplyView();
  });
}

function topoRedraw() {      // re-draw after a drag without refitting or closing the inspector
  const d = TOPO.data;
  if (!d || netLayout !== "topo") return;
  const L = topoLayout(d);
  if (!L) return;
  TOPO.layout = L;
  $("topoRoot").innerHTML = topoSvg(L, topoTheme()); TOPO.lastSvg = null;
  topoMini();
}

function topoApplyView() {
  const v = TOPO.view;
  $("topoRoot").setAttribute("transform", `translate(${v.x},${v.y}) scale(${v.k})`);
  topoMini();
}

function topoZoomAt(k, mx, my) {
  const v = TOPO.view;
  k = Math.max(0.1, Math.min(3, k));
  v.x = mx - (mx - v.x) * (k / v.k); v.y = my - (my - v.y) * (k / v.k); v.k = k;
  topoApplyView();
}
function topoZoomBy(f) { const r = $("topoSvg").getBoundingClientRect(); topoZoomAt(TOPO.view.k * f, r.width / 2, r.height / 2); }

function topoFitView() {
  const L = TOPO.layout, svg = $("topoSvg");
  if (!L || !svg) return;
  const r = svg.getBoundingClientRect(), b = L.bounds, pad = 24;
  if (r.width < 50) return;
  const fit = Math.min((r.width - pad * 2) / (b.x1 - b.x0), (r.height - pad * 2) / (b.y1 - b.y0));
  // Keep text readable: never shrink below 0.45 (pan and pinch to explore); a very wide map opens centred on the gateway.
  const k = Math.max(Math.min(fit, 1.2), Math.min(0.45, fit > 0.45 ? fit : 0.45));
  const w = (b.x1 - b.x0) * k;
  TOPO.view = {k, x: w <= r.width - pad * 2 ? (r.width - w) / 2 - b.x0 * k : r.width / 2 - L.tree.cx * k, y: pad};
  topoApplyView();
}

function topoMiniScale(L, r) { const b = L.bounds; return Math.min((r.width - 20) / (b.x1 - b.x0 + 1), (r.height - 20) / (b.y1 - b.y0 + 1)); }

function topoMini() {
  const L = TOPO.layout, box = $("topoMini");
  if (!L || !box) return;
  const r = box.getBoundingClientRect();
  if (r.width < 40) return;
  const s = topoMiniScale(L, r), b = L.bounds, S = TOPO_SIZE, T = topoTheme();
  const X = (x) => (x - b.x0) * s + 10, Y = (y) => (y - b.y0) * s + 10;
  const sr = $("topoSvg").getBoundingClientRect(), v = TOPO.view;
  $("topoMiniSvg").innerHTML = [
    ...L.blocks.map((k) => `<rect x="${X(k.x)}" y="${Y(k.y)}" width="${k.w * s}" height="${k.h * s}" rx="2" fill="${T.panel2}" stroke="${T.border}" stroke-width=".6"/>`),
    ...L.chips.map((c) => `<rect x="${X(c.x)}" y="${Y(c.y)}" width="${Math.max(1.5, S.cw * s)}" height="${Math.max(1, S.ch * s)}" fill="${topoNodeColor(c.node, T)}" opacity=".75"/>`),
    ...L.headers.map((h) => `<rect x="${X(h.x)}" y="${Y(h.y)}" width="${S.hw * s}" height="${S.hh * s}" rx="2" fill="${T.accent}" opacity=".55"/>`),
    `<rect x="${X(-v.x / v.k)}" y="${Y(-v.y / v.k)}" width="${sr.width / v.k * s}" height="${sr.height / v.k * s}" fill="none" stroke="${T.accent}" stroke-width="1.4"/>`].join("");
}

function renderTopology() {
  if (netLayout !== "topo") return;
  topoShell();
  const d = TOPO.data;
  if (!d) { $("topoRoot").innerHTML = ""; $("topoBar").innerHTML = '<span class="muted">Loading topology…</span>'; loadTopology(); return; }
  const T = topoTheme(), L = topoLayout(d);
  TOPO.layout = L;
  renderTopoBar(d);
  if (!L) {
    $("topoRoot").innerHTML = `<text x="40" y="60" fill="${T.muted}" font-size="14">LanPulse hasn't found your gateway yet. Once it has, the map appears here.</text>`;
    return;
  }
  // Only touch the SVG when it actually changed, so the cable animation isn't restarted by every background refresh
  const svgNow = topoSvg(L, T);
  if (svgNow !== TOPO.lastSvg || !$("topoRoot").firstChild) { $("topoRoot").innerHTML = svgNow; TOPO.lastSvg = svgNow; }
  if (TOPO.fit) { TOPO.fit = false; requestAnimationFrame(topoFitView); } else topoApplyView();
  if (TOPO.sel) renderTopoInfo();
}

function renderTopoBar(d) {
  const u = d.sources.unifi, weak = weakClients(d), wifi = d.nodes.filter((n) => (n.link || {}).medium === "wifi").length;
  const src = u.configured ? (u.ok ? `<span class="tp-src ok"><i class="fa-solid fa-circle-check"></i>UniFi · ${u.devices} devices · ${u.clients} clients</span>`
      : `<span class="tp-src bad" title="${esc(u.error)}"><i class="fa-solid fa-triangle-exclamation"></i>UniFi: ${esc(tx(u.error, 60))}</span>`)
    : `<span class="tp-src" title="Connect UniFi in Settings for automatic connections, or choose where a device connects by clicking it."><i class="fa-solid fa-circle-info"></i>Connections inferred. Click a device to set them${d.sources.manual ? ` (${d.sources.manual} set)` : ""}</span>`;
  const sn = d.sources.snmp || {};
  const snmpChip = sn.configured ? (sn.ok ? `<span class="tp-src ok" title="${esc(sn.error)}"><i class="fa-solid fa-circle-check"></i>SNMP · ${sn.hosts} devices · ${sn.links} LLDP links</span>`
    : `<span class="tp-src bad" title="${esc(sn.error)}"><i class="fa-solid fa-triangle-exclamation"></i>SNMP: ${esc(tx(sn.error, 60))}</span>`) : "";
  const zones = d.zones.length > 1 || TOPO.zone ? `<select id="tpZone" title="Show one zone"><option value="">All zones</option>${d.zones.map((z) => `<option ${TOPO.zone === z.name ? "selected" : ""} value="${esc(z.name)}">${esc(z.name)}${z.vlan ? ` (VLAN ${z.vlan})` : ""} · ${z.count}</option>`).join("")}</select>` : "";
  $("topoBar").innerHTML = `
    <label class="tp-lbl">Color by <select id="tpColor">${TOPO_COLORS.map(([k, n]) => `<option value="${k}" ${TOPO.color === k ? "selected" : ""}>${n}</option>`).join("")}</select></label>
    ${zones}
    <button class="btn sm ${TOPO.traffic ? "on" : ""}" id="tpTraffic" title="Show how active each device was in the last hour"><i class="fa-solid fa-wave-square"></i>Traffic</button>
    <button class="btn sm" id="tpChanges"><i class="fa-solid fa-clock-rotate-left"></i>Changes${d.changes.length ? `<b class="tp-n">${d.changes.length}</b>` : ""}</button>
    <button class="btn sm" id="tpZones"><i class="fa-solid fa-layer-group"></i>Zones</button>
    <button class="btn sm" id="tpExport"><i class="fa-solid fa-file-export"></i>Export</button>
    <button class="btn sm ${TOPO.spread ? "on" : ""}" id="tpSpread" title="Give every device its own line you can drag. Off groups them in boxes."><i class="fa-solid fa-diagram-successor"></i>Spread</button>
    ${Object.keys(TOPO.pos).length ? '<button class="btn sm" id="tpResetPos" title="Put dragged devices back"><i class="fa-solid fa-rotate-left"></i>Reset</button>' : ""}
    <button class="btn sm" id="tpZoomOut" title="Zoom out"><i class="fa-solid fa-magnifying-glass-minus"></i></button>
    <button class="btn sm" id="tpZoomIn" title="Zoom in"><i class="fa-solid fa-magnifying-glass-plus"></i></button>
    <button class="btn sm" id="tpFit" title="Fit to screen"><i class="fa-solid fa-expand"></i></button>
    <button class="btn sm" id="tpRefresh" title="Refresh from the router"><i class="fa-solid fa-rotate"></i></button>
    ${TOPO.traffic && topoTraffic(d).rates ? '<span class="tp-src ok" title="Live speeds reported by your UniFi gateway, refreshed about every 30 seconds. Cables and bars use a log scale so one busy device doesn\'t hide the rest."><i class="fa-solid fa-gauge-high"></i>Live throughput from UniFi</span>' : ""}
    ${TOPO.traffic && !topoTraffic(d).rates && !TOPO.talkers.size ? '<span class="tp-src bad" title="LanPulse builds this from your router\'s connection logs. Point the router\'s syslog at LanPulse (Settings > Threats) and it fills in within a minute or two."><i class="fa-solid fa-circle-info"></i>No traffic logged yet. Needs router logs</span>' : ""}
    <span class="tp-spacer"></span>
    ${wifi ? `<span class="tp-chipinfo"><i class="fa-solid fa-wifi"></i>${wifi} on Wi-Fi${weak.length ? ` · <b class="warn">${weak.length} weak</b>` : ""}</span>` : ""}
    ${src}${snmpChip}`;
  $("tpColor").onchange = (e) => { TOPO.color = e.target.value; try { localStorage.setItem("nm_topo_color", TOPO.color); } catch (_) {} renderTopology(); };
  if ($("tpZone")) $("tpZone").onchange = (e) => { TOPO.zone = e.target.value; TOPO.fit = true; renderTopology(); };
  $("tpTraffic").onclick = () => { TOPO.traffic = !TOPO.traffic; if (TOPO.traffic) loadTopoTraffic(); else renderTopology(); };
  $("tpFit").onclick = topoFitView;
  $("tpSpread").onclick = () => { TOPO.spread = !TOPO.spread; try { localStorage.setItem("nm_topo_spread", TOPO.spread ? "1" : "0"); } catch (_) {} TOPO.fit = true; renderTopology(); };
  if ($("tpResetPos")) $("tpResetPos").onclick = () => { TOPO.pos = {}; topoSavePos(); TOPO.fit = true; renderTopology(); };
  $("tpZoomIn").onclick = () => topoZoomBy(1.4);
  $("tpZoomOut").onclick = () => topoZoomBy(1 / 1.4);
  $("tpRefresh").onclick = async () => { toast("Refreshing…"); await loadTopology(true); };
  $("tpChanges").onclick = () => topoPop("changes");
  $("tpZones").onclick = () => topoPop("zones");
  $("tpExport").onclick = () => topoPop("export");
}

/* ------------------------------------------------------------ inspector */
function topoSelect(id) {
  TOPO.sel = id;
  renderTopology();
  renderTopoInfo();
}

function renderTopoInfo() {
  const d = TOPO.data, n = d && d.nodes.find((x) => x.id === TOPO.sel), box = $("topoInfo");
  if (!n) { box.classList.add("hidden"); return; }
  const l = n.link || {}, e = n.extra || {}, par = d.nodes.find((x) => x.id === n.parent),
    t = n.kind === "ap" ? TYPES.ap : n.kind === "switch" ? TYPES.switch : n.kind === "gateway" ? TYPES.router : TYPES[n.type] || TYPES.unknown;
  const rows = [];
  rows.push(["Address", [n.ip, n.mac].filter(Boolean).join(" · ")]);
  if (n.model) rows.push(["Model", n.model + (e.version ? ` · v${e.version}` : "")]);
  if (n.zone) { const z = d.zones.find((x) => x.name === n.zone); rows.push(["Zone", `${n.zone}${z && z.vlan ? ` (VLAN ${z.vlan})` : ""}`]); }
  if (par && n.kind !== "gateway") rows.push(["Connected to", `${par.name}${n.source === "manual" ? " (set by you)" : n.source === "unifi" ? "" : n.source === "snmp" ? " (via SNMP)" : " (assumed)"}`]);
  if (l.medium === "wired") rows.push(["Link", ["Wired", l.port ? `port ${l.port}` : "", l.speed ? `${l.speed} Mbps` : ""].filter(Boolean).join(" · ")]);
  if (l.medium === "wifi") {
    const wf = [l.ssid, l.band, l.channel ? `ch ${l.channel}` : ""].filter(Boolean).join(" · ") || (l.mesh ? "Wireless uplink" : "");
    rows.push(["Link", wf || "Wi-Fi (set by you)"]);
    if (l.signal != null) rows.push(["Signal", `${l.signal} dBm · <b style="color:${SIGNAL_CLR[l.quality] || "inherit"}">${l.quality || ""}</b>`]);
    if (l.tx || l.rx) rows.push(["Speed", [l.tx ? `↑ ${fmtRate(l.tx)}` : "", l.rx ? `↓ ${fmtRate(l.rx)}` : ""].filter(Boolean).join("  ")]);
  }
  if (n.kind === "ap") {
    (e.radios || []).forEach((r) => rows.push([r.band, `ch ${r.channel ?? "?"} · ${r.clients ?? 0} clients${r.satisfaction != null ? ` · ${r.satisfaction}% satisfied` : ""}`]));
    if ((e.ssids || []).length) rows.push(["SSIDs", e.ssids.join(", ")]);
    const kids = d.nodes.filter((x) => x.parent === n.id && x.link && x.link.quality);
    const q = (k) => kids.filter((x) => x.link.quality === k).length;
    if (kids.length) rows.push(["Client signal", `<span style="color:${SIGNAL_CLR.good}">${q("good")} good</span> · <span style="color:${SIGNAL_CLR.fair}">${q("fair")} fair</span> · <span style="color:${SIGNAL_CLR.poor}">${q("poor")} weak</span>`]);
  }
  if (n.kind === "switch" && e.ports_total) rows.push(["Ports", `${e.ports_up} of ${e.ports_total} up${e.poe_watts ? ` · ${e.poe_watts} W PoE` : ""}`]);
  if (n.kind !== "client" || e.clients) rows.push(["Connected devices", String(e.clients || 0)]);
  if (e.uptime) rows.push(["Uptime", fmtUp(e.uptime)]);
  if (TOPO.traffic) {
    const T2 = topoTraffic(d), c = n.kind === "client" ? T2.own.get(n.id) : T2.sub.get(n.id);
    if (T2.rates) rows.push([n.kind === "client" ? "Throughput now" : "Throughput below", c ? topoBps(c) : "idle"]);
    const k = n.kind === "client" ? TOPO.talkers.get(n.id) : [...TOPO.talkers].filter(([id]) => { for (let cur = d.nodes.find((x) => x.id === id), i = 0; cur && i < 20; i++, cur = d.nodes.find((x) => x.id === cur.parent)) if (cur.id === n.id) return true; return false; }).reduce((a, [, v]) => a + v, 0);
    if (!T2.rates || k) rows.push(["Connections (1h)", k ? k.toLocaleString() : "none logged"]);
  }
  rows.push(["Status", n.online ? '<span style="color:#22c55e">online</span>' : "offline"]);
  const real = devices.has(n.id);
  const opts = d.nodes.filter((x) => x.id !== n.id && (TOPO_INFRA.has(x.kind) || x.kind === "client" && false)).sort((a, b) => a.name.localeCompare(b.name));
  box.classList.remove("hidden");
  box.innerHTML = `<div class="ti-head"><span class="ic" style="color:${t.color}"><i class="${faClass(t)}"></i></span>
      <div><b>${esc(n.name)}</b><span class="muted">${esc(t.label)}${n.kind !== "client" ? ` · ${n.kind === "ap" ? "access point" : n.kind}` : ""}</span></div>
      <button class="x" id="tiClose" title="Close"><i class="fa-solid fa-xmark"></i></button></div>
    <div class="ti-rows">${rows.map(([k, v]) => `<div><span>${esc(k)}</span><span>${k === "Status" || k === "Signal" || k === "Client signal" ? v : esc(v)}</span></div>`).join("")}</div>
    ${real && n.kind !== "gateway" ? `<details class="ti-edit"><summary><i class="fa-solid fa-diagram-project"></i> Set connection</summary>
      <label>Connected to<select id="tiParent"><option value="">Automatic</option>${opts.map((o) => `<option value="${esc(o.id)}" ${(n.source === "manual" && n.parent === o.id) ? "selected" : ""}>${esc(o.name)} (${o.kind === "ap" ? "access point" : o.kind})</option>`).join("")}</select></label>
      <label>Role<select id="tiRole">${[["auto", "Automatic"], ["client", "Device"], ["ap", "Access point"], ["switch", "Switch"]].map(([v, nme]) => `<option value="${v}">${nme}</option>`).join("")}</select></label>
      <label>Connection<select id="tiMedium">${[["auto", "Automatic"], ["wired", "Wired"], ["wifi", "Wi-Fi"]].map(([v, nme]) => `<option value="${v}">${nme}</option>`).join("")}</select></label>
      <div class="btns"><button class="btn sm primary" id="tiSave">Save</button><button class="btn sm" id="tiReset">Reset to automatic</button></div></details>` : ""}
    <div class="btns" style="margin-top:8px">${real ? '<button class="btn sm" id="tiOpen"><i class="fa-solid fa-circle-info"></i>Open device</button>' : ""}
      <button class="btn sm" id="tiFocus"><i class="fa-solid fa-route"></i>Path to internet</button></div>`;
  $("tiClose").onclick = () => { TOPO.sel = null; box.classList.add("hidden"); renderTopology(); };
  if ($("tiOpen")) $("tiOpen").onclick = () => openPanel(n.id);
  $("tiFocus").onclick = () => toast(`${n.name}: ${topoPathText(n)}`);
  if ($("tiSave")) {
    const man = (TOPO.data.sources.manual_map || {})[n.id] || {};
    $("tiRole").value = man.role || "auto"; $("tiMedium").value = man.medium || "auto";
    $("tiSave").onclick = () => topoSaveDevice(n.id, {parent: $("tiParent").value, role: $("tiRole").value, medium: $("tiMedium").value});
    $("tiReset").onclick = () => topoSaveDevice(n.id, {parent: "", role: "auto", medium: "auto"});
  }
}

function topoPathText(n) {
  const byId = new Map(TOPO.data.nodes.map((x) => [x.id, x])), path = [];
  for (let c = n, i = 0; c && i < 20; i++) { path.push(c.name); c = byId.get(c.parent); }
  return [...path, "Internet"].join(" → ");
}

async function topoSaveDevice(id, body) {
  const r = await api(`/api/topology/device/${encodeURIComponent(id)}`, "POST", body);
  if (r) { TOPO.data = r; toast("Connection saved"); renderTopology(); }
}

/* ------------------------------------------------------------ popovers: changes, zones, export */
function topoPop(kind) {
  const box = $("topoPop");
  if (TOPO.pop === kind) { TOPO.pop = ""; box.classList.add("hidden"); return; }
  TOPO.pop = kind; box.classList.remove("hidden");
  const d = TOPO.data;
  if (kind === "changes") {
    const ICON = {new: ["fa-circle-plus", "#22c55e"], gone: ["fa-circle-minus", "#94a3b8"], moved: ["fa-arrows-left-right", "#f59e0b"], roamed: ["fa-wifi", "#38bdf8"]};
    box.innerHTML = `<h4>Changes <span class="muted">last 24 hours (moves: 7 days)</span></h4>` + (d.changes.length ? d.changes.map((c) => {
      const [ic, col] = ICON[c.kind] || ICON.moved;
      return `<button class="tp-ch" data-id="${esc(c.id)}"><i class="fa-solid ${ic}" style="color:${col}"></i><span>${esc(c.text)}</span><span class="muted">${ago(c.t)}</span></button>`;
    }).join("") : `<div class="muted" style="padding:8px 0">Nothing changed. Devices that join, leave or move to another access point or port will show here.</div>`);
    box.querySelectorAll(".tp-ch").forEach((b) => b.onclick = () => { topoSelect(b.dataset.id); });
  } else if (kind === "zones") {
    const rows = (d.custom_zones || []).slice();
    box.innerHTML = `<h4>Zones <span class="muted">group devices by VLAN or subnet</span></h4>
      <p class="hint" style="margin:0 0 8px">${d.sources.unifi.ok ? "UniFi networks are used automatically. " : ""}Add your own for any router: a network range and a name.</p>
      <div id="tpZoneRows">${rows.map((z, i) => zoneRow(z, i)).join("")}</div>
      <div class="btns"><button class="btn sm" id="tpZoneAdd"><i class="fa-solid fa-plus"></i>Add zone</button><button class="btn sm primary" id="tpZoneSave">Save</button></div>`;
    $("tpZoneAdd").onclick = () => $("tpZoneRows").insertAdjacentHTML("beforeend", zoneRow({cidr: "", name: ""}, Date.now()));
    $("tpZoneSave").onclick = async () => {
      const zs = [...box.querySelectorAll(".tp-zrow")].map((r) => ({cidr: r.querySelector(".zc").value, name: r.querySelector(".zn").value}));
      const r = await api("/api/topology/zones", "POST", {zones: zs});
      if (r) { TOPO.data = r; toast("Zones saved"); TOPO.pop = ""; box.classList.add("hidden"); renderTopology(); }
    };
    box.onclick = (e) => { const x = e.target.closest(".zx"); if (x) x.closest(".tp-zrow").remove(); };
  } else if (kind === "export") {
    box.innerHTML = `<h4>Export</h4>
      <button class="tp-ch" data-ex="svg"><i class="fa-solid fa-file-image"></i><span>SVG picture</span><span class="muted">sharp at any size</span></button>
      <button class="tp-ch" data-ex="png"><i class="fa-solid fa-image"></i><span>PNG image</span><span class="muted">for documents</span></button>
      <button class="tp-ch" data-ex="drawio"><i class="fa-solid fa-diagram-project"></i><span>draw.io diagram</span><span class="muted">editable</span></button>
      <button class="tp-ch" data-ex="csv"><i class="fa-solid fa-file-csv"></i><span>Inventory CSV</span><span class="muted">with connections</span></button>`;
    box.querySelectorAll("[data-ex]").forEach((b) => b.onclick = () => { topoExport(b.dataset.ex); TOPO.pop = ""; box.classList.add("hidden"); });
  }
}
const zoneRow = (z, i) => `<div class="tp-zrow" data-i="${i}"><input class="zc" placeholder="192.168.10.0/24" value="${esc(z.cidr)}"><input class="zn" placeholder="Name (IoT, Guest…)" value="${esc(z.name)}"><button class="zx" title="Remove"><i class="fa-solid fa-xmark"></i></button></div>`;

/* ------------------------------------------------------------ export */
function topoDownload(name, blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

function topoStandaloneSvg() {
  const L = TOPO.layout, T = topoTheme(), b = L.bounds, pad = 30;
  const w = b.x1 - b.x0 + pad * 2, h = b.y1 - b.y0 + pad * 2;
  const body = topoSvg(L, T, {export: true});
  return {w, h, svg: `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="${b.x0 - pad} ${-pad} ${w} ${h}" font-family="Inter,Segoe UI,Arial,sans-serif">
    <rect x="${b.x0 - pad}" y="${-pad}" width="${w}" height="${h}" fill="${T.bg}"/>${body}</svg>`};
}

function topoExport(kind) {
  const d = TOPO.data, L = TOPO.layout;
  if (!d || !L) return;
  const stamp = new Date().toISOString().slice(0, 10);
  if (kind === "svg") { topoDownload(`lanpulse-topology-${stamp}.svg`, new Blob([topoStandaloneSvg().svg], {type: "image/svg+xml"})); }
  else if (kind === "png") {
    const {w, h, svg} = topoStandaloneSvg(), img = new Image();
    img.onload = () => { const c = document.createElement("canvas"); c.width = w * 2; c.height = h * 2; const x = c.getContext("2d"); x.scale(2, 2); x.drawImage(img, 0, 0, w, h);
      c.toBlob((bl) => topoDownload(`lanpulse-topology-${stamp}.png`, bl)); };
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  } else if (kind === "csv") {
    const byId = new Map(d.nodes.map((n) => [n.id, n])), q = (v) => { let t = String(v ?? ""); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
    const head = ["name", "ip", "mac", "role", "vendor", "model", "zone", "connected_to", "connection", "port", "ssid", "band", "channel", "signal_dbm", "status"];
    const rows = d.nodes.map((n) => { const l = n.link || {}, p = byId.get(n.parent);
      return [n.name, n.ip, n.mac, n.kind, n.vendor, n.model, n.zone, p ? p.name : "Internet", l.medium || "", l.port || "", l.ssid || "", l.band || "", l.channel || "", l.signal ?? "", n.online ? "online" : "offline"].map(q).join(","); });
    topoDownload(`lanpulse-inventory-${stamp}.csv`, new Blob([[head.join(","), ...rows].join("\n")], {type: "text/csv"}));
  } else if (kind === "drawio") {
    const S = TOPO_SIZE, cells = [], T = topoTheme(), esx = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;"}[c]));
    const idOf = (id) => "n" + id.replace(/[^A-Za-z0-9]/g, "");
    const vtx = (id, label, x, y, w, h, fill, stroke) => `<mxCell id="${idOf(id)}" value="${esx(label)}" style="rounded=1;whiteSpace=wrap;html=1;fillColor=${fill};strokeColor=${stroke};fontColor=#e5e9f2;" vertex="1" parent="1"><mxGeometry x="${Math.round(x)}" y="${Math.round(y)}" width="${w}" height="${h}" as="geometry"/></mxCell>`;
    cells.push(vtx("__internet", "Internet", L.inet.x, L.inet.y, L.inet.w, L.inet.h, "#0c4a6e", "#38bdf8"));
    L.headers.forEach((h) => cells.push(vtx(h.node.id, `${h.node.name}\n${h.node.model || h.node.ip}`, h.x, h.y, S.hw, S.hh, "#1f2937", h.node.kind === "ap" ? "#fbbf24" : "#f59e0b")));
    L.chips.forEach((c) => cells.push(vtx(c.node.id, `${c.node.name}\n${c.node.ip}`, c.x, c.y, S.cw, S.ch, "#111827", topoNodeColor(c.node, T))));
    const edge = (a, b, wifi, i) => `<mxCell id="e${i}" style="endArrow=none;${wifi ? "dashed=1;" : ""}strokeColor=#64748b;" edge="1" parent="1" source="${idOf(a)}" target="${idOf(b)}"><mxGeometry relative="1" as="geometry"/></mxCell>`;
    cells.push(edge("__internet", L.tree.node.id, false, 0));
    L.links.forEach((l, i) => cells.push(edge(l.from.node.id, l.to.node.id, (l.to.node.link || {}).medium === "wifi", i + 1)));
    L.chips.forEach((c, i) => cells.push(edge(c.parent.node.id, c.node.id, (c.node.link || {}).medium === "wifi", 1000 + i)));
    const xml = `<mxfile><diagram name="LanPulse topology"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join("")}</root></mxGraphModel></diagram></mxfile>`;
    topoDownload(`lanpulse-topology-${stamp}.drawio`, new Blob([xml], {type: "application/xml"}));
  }
}

/* ------------------------------------------------------------ hooks */
startTopoTimer();
document.addEventListener("click", (e) => {
  if (TOPO.pop && !e.target.closest("#topoPop, #tpChanges, #tpZones, #tpExport")) { TOPO.pop = ""; const b = $("topoPop"); if (b) b.classList.add("hidden"); }
});
