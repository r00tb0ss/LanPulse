// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* LanPulse left menu: what needs your attention, network health, and a filterable activity timeline.
   Device search lives on the map (mapFind). Loaded last. */

let activity = [];
let evFilter = (() => { try { return localStorage.getItem("lp_evf") || "all"; } catch (_) { return "all"; } })();
let busiest = null, busiestAt = 0;
const hiddenAlerts = new Set((() => { try { return JSON.parse(localStorage.getItem("lp_hidden_alerts") || "[]"); } catch (_) { return []; } })());
const EV_GROUP = {new: "devices", online: "devices", offline: "devices", ip: "changes", port: "changes", security: "security", traffic: "security"};
const ATTN_NEW_SHOWN = 4;

function pickDevice(id) {
  if (!devices.has(id)) return;
  openPanel(id);
  try { if ($("altView").classList.contains("hidden")) network.focus(id, {scale: 1.2, animation: {duration: 500}}); } catch (_) {}
  if (window.matchMedia("(max-width: 900px)").matches) $("sidebar").classList.remove("open");
}
const devApi = (id, path = "") => `/api/devices/${encodeURIComponent(id)}${path}`;

/* ------------------------------------------------------------ needs attention */
function attentionItems() {
  const items = [];
  const now = Date.now() / 1000;
  const devs = [...devices.values()];
  const seen = new Set();
  for (const e of activity.slice().reverse()) {          // newest first
    const key = `traffic|${e.id}`;
    if (e.kind !== "traffic" || now - e.t > 86400 || seen.has(e.id) || !devices.has(e.id) || hiddenAlerts.has(`${key}|${Math.floor(e.t)}`)) continue;
    seen.add(e.id);
    items.push({kind: "attacker", rank: 0, d: devices.get(e.id), e, hideKey: `${key}|${Math.floor(e.t)}`});
  }
  for (const d of devs) {
    for (const f of d.findings || []) {
      if (f.dismissed || (f.level !== "high" && f.level !== "medium")) continue;
      items.push({kind: "risk", rank: f.level === "high" ? 1 : 3, d, f});
    }
    if (d.watched && !d.online) items.push({kind: "offline", rank: 2, d});
  }
  const fresh = devs.filter((d) => !d.trusted).sort((a, b) => (b.first_seen || 0) - (a.first_seen || 0));
  fresh.forEach((d) => items.push({kind: "new", rank: 4, d}));
  return items.sort((a, b) => a.rank - b.rank);
}

function attnRow(it) {
  const d = it.d, nm = esc(nameOf(d)), id = esc(d.id);
  const open = `<button class="btn sm ghost" data-act="open" data-id="${id}">Open</button>`;
  if (it.kind === "attacker") return `<div class="att bad" data-id="${id}">
      <div class="att-ic"><i class="fa-solid fa-skull-crossbones"></i></div>
      <div class="att-body"><div class="att-t">${nm} contacted an attacker</div>
        <div class="att-s">${esc(it.e.text)} · ${ago(it.e.t)}</div>
        <div class="att-act">${open}<button class="btn sm ghost" data-act="hide" data-key="${esc(it.hideKey)}">Dismiss</button></div></div></div>`;
  if (it.kind === "risk") return `<div class="att ${it.f.level}" data-id="${id}">
      <div class="att-ic"><i class="fa-solid fa-triangle-exclamation"></i></div>
      <div class="att-body"><div class="att-t"><span class="sev ${it.f.level}">${it.f.level}</span> ${nm}</div>
        <div class="att-s">${esc(it.f.text)}</div>
        <div class="att-act">${open}<button class="btn sm ghost" data-act="dismiss" data-id="${id}" data-text="${esc(it.f.text)}"
          title="Accept this risk (a lab machine, say). It stays listed in the device's details.">Dismiss</button></div></div></div>`;
  if (it.kind === "offline") return `<div class="att off" data-id="${id}">
      <div class="att-ic"><i class="fa-solid fa-plug-circle-xmark"></i></div>
      <div class="att-body"><div class="att-t">${nm} is offline</div>
        <div class="att-s">Watched · last seen ${ago(d.last_seen)}</div>
        <div class="att-act">${open}${d.mac && !d.is_gateway ? `<button class="btn sm ghost" data-act="wake" data-id="${id}">Wake</button>` : ""}</div></div></div>`;
  return `<div class="att new" data-id="${id}">
      <div class="att-ic"><i class="fa-solid fa-user-secret"></i></div>
      <div class="att-body"><div class="att-t">New device: ${nm}</div>
        <div class="att-s">${esc([d.vendor, d.ip].filter(Boolean).join(" · "))} · first seen ${ago(d.first_seen)}</div>
        <div class="att-act"><button class="btn sm" data-act="trust" data-id="${id}"><i class="fa-solid fa-check"></i>Trust</button>${open}</div></div></div>`;
}

function renderAttention() {
  const items = attentionItems();
  const news = items.filter((i) => i.kind === "new");
  const rest = items.filter((i) => i.kind !== "new");
  $("attnCount").textContent = items.length ? String(items.length) : "";
  $("attnCount").classList.toggle("hot", rest.some((i) => i.rank <= 1));
  if (!items.length) {
    $("attn").innerHTML = `<div class="all-clear"><i class="fa-solid fa-circle-check"></i><div><b>All clear</b><span>Nothing needs you right now.</span></div></div>`;
    return;
  }
  const more = news.length - ATTN_NEW_SHOWN;
  $("attn").innerHTML = rest.map(attnRow).join("") + news.slice(0, ATTN_NEW_SHOWN).map(attnRow).join("") +
    (more > 0 ? `<div class="att-more"><span>+${more} more new device${more > 1 ? "s" : ""}</span>
      <button class="btn sm ghost" data-act="shownew">Show</button><button class="btn sm" data-act="trustall">Trust all ${news.length}</button></div>` : "");
}

/* ------------------------------------------------------------ health */
async function loadBusiest() {
  if (Date.now() - busiestAt < 60000) return;
  busiestAt = Date.now();
  const r = await api("/api/flows?hours=1", "GET");
  if (r) { busiest = r; renderHealth(); }
}

function healthRow(state, icon, label, value, sub = "") {
  return `<div class="hrow"><span class="hdot ${state}"></span><i class="fa-solid ${icon}"></i>
    <span class="hl">${label}</span><span class="hv">${value}${sub ? `<small>${sub}</small>` : ""}</span></div>`;
}

function renderHealth() {
  const devs = [...devices.values()];
  const gwIp = meta.gateway || "";
  const gw = devs.find((d) => d.is_gateway) || (gwIp ? devs.find((d) => d.ip === gwIp) : null);
  const on = devs.filter((d) => d.online).length;
  const s = typeof tSummary !== "undefined" && tSummary ? tSummary : null;
  const src = s?.sources || {};
  const sweepAge = meta.last_sweep ? Date.now() / 1000 - meta.last_sweep : Infinity;
  const rows = [
    healthRow(!gwIp && !gw ? "warn" : !gw ? "dim" : gw.online ? (gw.rtt_ms > 20 ? "warn" : "ok") : "bad", "fa-route", "Gateway",
      gw ? `${esc(gw.ip)}` : gwIp ? esc(gwIp) : "not detected",
      gw ? (gw.online ? (gw.rtt_ms != null ? `${gw.rtt_ms} ms` : "up") : "offline") : gwIp ? "not seen in scans" : ""),
    healthRow(s?.public_ip ? "ok" : "dim", "fa-globe", "Internet", s?.public_ip ? esc(s.public_ip) : "unknown",
      s?.home?.city ? esc(s.home.city) : ""),
    healthRow(src.syslog === false ? "bad" : (src.rejected || []).length && !src.last_event ? "warn" : src.last_event ? "ok" : "dim",
      "fa-file-lines", "Router logs",
      src.syslog === false ? "not listening" : src.last_event ? ago(src.last_event)
        : (src.rejected || []).length ? `from ${esc(src.rejected[0].ip)} ignored` : "none yet",
      src.syslog_port ? `UDP ${esc(src.syslog_port)}` : ""),
    healthRow(sweepAge < 300 ? "ok" : "warn", "fa-satellite-dish", "Scanner", meta.last_sweep ? ago(meta.last_sweep) : "starting",
      meta.sweep_ms ? `${meta.sweep_ms} ms sweep` : ""),
    healthRow("ok", "fa-laptop", "Online", `${on} of ${devs.length}`),
  ];
  const talk = (busiest?.talkers || []).slice(0, 3);
  const tmax = Math.max(1, ...talk.map((t) => t.count));
  $("health").innerHTML = rows.join("") + (talk.length ? `<div class="h-busy"><div class="h-sub">Busiest in the last hour</div>
    ${talk.map((t) => `<button class="busy" data-id="${esc(t.id)}"><span class="nm">${esc(t.name)}</span><span class="ct">${fmtN(t.count)}</span>
      <i style="width:${(100 * t.count / tmax).toFixed(0)}%"></i></button>`).join("")}</div>` : "");
}

/* ------------------------------------------------------------ activity */
function setActivity(events) {
  activity = events || [];
  renderActivity();
  renderAttention();
}

function dayLabel(ts) {
  const d = new Date(ts * 1000), today = new Date();
  const y = new Date(); y.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], {weekday: "short", month: "short", day: "numeric"});
}

function renderActivity() {
  document.querySelectorAll("#evFilter button").forEach((b) => {
    b.classList.toggle("on", b.dataset.f === evFilter);
    b.setAttribute("aria-pressed", String(b.dataset.f === evFilter));
  });
  const list = activity.slice().reverse().filter((e) => evFilter === "all" || EV_GROUP[e.kind] === evFilter).slice(0, 100);
  let lastDay = "";
  $("events").innerHTML = list.map((e) => {
    const day = dayLabel(e.t);
    const head = day !== lastDay ? `<div class="ev-day">${day}</div>` : "";
    lastDay = day;
    return `${head}<div class="ev ${esc(e.kind)}" data-id="${esc(e.id)}" title="${esc(full(e.t))}"><time>${clock(e.t)}</time>
      <i class="fa-solid ${EV_ICON[e.kind] || "fa-circle-info"}"></i><span>${esc(e.text)}</span></div>`;
  }).join("") || `<div class="muted" style="padding:6px 0">${evFilter === "all" ? "No activity yet." : "Nothing of this kind yet."}</div>`;
}

/* ------------------------------------------------------------ map search */
function renderFindResults() {
  const q = $("q").value.trim();
  const box = $("findRes");
  if (!q) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const hits = [...devices.values()].filter(matches).sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
  box.classList.remove("hidden");
  box.innerHTML = hits.slice(0, 8).map((d, i) => { const t = typeOf(d); return `<button class="fr ${i === 0 ? "first" : ""}" role="option" data-id="${esc(d.id)}" style="--c:${t.color}">
      <i class="${faClass(t)}"></i><span class="nm">${esc(nameOf(d))}</span><span class="ip">${esc(d.ip)}</span>
      <span class="dot ${d.online ? "on" : "off"}"></span></button>`; }).join("")
    + (hits.length > 8 ? `<div class="fr-more">${hits.length - 8} more match. Keep typing, or use the Table view.</div>` : "")
    + (hits.length ? "" : `<div class="fr-more">No devices match.</div>`);
}

/* ------------------------------------------------------------ hide / show the left menu (desktop) */
const SB_KEY = "lp_sb_collapsed";
const sbIsMobile = () => window.matchMedia("(max-width: 900px)").matches;

function sbRefit() {      // the map just got more (or less) room: let the layout settle, then tell it
  setTimeout(() => {
    try { window.dispatchEvent(new Event("resize")); } catch (_) {}
    try { if (typeof network !== "undefined" && network) network.redraw(); } catch (_) {}
    try { if (typeof topoFitView === "function" && $("topoSvg") && $("topoSvg").clientWidth > 0) topoFitView(); } catch (_) {}
  }, 60);
}

function setSidebarCollapsed(on, save = true) {
  $("netView").classList.toggle("sb-collapsed", on);
  const b = $("btnSidebar");
  b.title = on ? "Show the side menu" : "Hide the side menu";
  b.setAttribute("aria-pressed", String(!on));
  if (save) { try { localStorage.setItem(SB_KEY, on ? "1" : "0"); } catch (_) {} }
  sbRefit();
}

function toggleSidebar() {
  if (sbIsMobile()) { $("sidebar").classList.toggle("open"); return; }   // phones: slide-over menu, as before
  setSidebarCollapsed(!$("netView").classList.contains("sb-collapsed"));
}

function restoreSidebarState() {
  let on = false;
  try { on = localStorage.getItem(SB_KEY) === "1"; } catch (_) {}
  if (on && !sbIsMobile()) setSidebarCollapsed(true, false);
  else if (!sbIsMobile()) $("btnSidebar").title = "Hide the side menu";
}

/* ------------------------------------------------------------ render + wiring */
function renderSidebar() {
  renderAttention();
  renderHealth();
  if (document.activeElement === $("q")) renderFindResults();
}

(function initSidebar() {
  $("attn").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]");
    const row = e.target.closest(".att");
    if (!b) { if (row) pickDevice(row.dataset.id); return; }
    const id = b.dataset.id;
    b.disabled = true;
    switch (b.dataset.act) {
      case "open": pickDevice(id); break;
      case "trust": if (await api(devApi(id), "POST", {trusted: true})) toast(`${nameOf(devices.get(id) || {ip: id})} is now trusted`); break;
      case "dismiss": if (await api(devApi(id), "POST", {dismiss: b.dataset.text})) toast("Dismissed. You can undo it in the device's details."); break;
      case "wake": if (await api(devApi(id, "/wake"), "POST")) toast("Wake-on-LAN packet sent"); break;
      case "hide":
        hiddenAlerts.add(b.dataset.key);
        try { localStorage.setItem("lp_hidden_alerts", JSON.stringify([...hiddenAlerts].slice(-200))); } catch (_) {}
        renderAttention(); break;
      case "shownew": statFilter = "__untrusted";
        document.querySelectorAll(".stat").forEach((s) => s.classList.toggle("active", s.dataset.filter === statFilter));
        syncMap(JSON.parse(layoutKey || "{}")); renderList(); toast("The map now shows only new devices. Click New again to clear."); break;
      case "trustall": if (await api("/api/trust-all", "POST")) toast("All devices trusted"); break;
    }
    b.disabled = false;
  });
  $("health").addEventListener("click", (e) => { const b = e.target.closest(".busy"); if (b && b.dataset.id) pickDevice(b.dataset.id); });
  $("events").addEventListener("click", (e) => { const r = e.target.closest(".ev"); if (r) pickDevice(r.dataset.id); });
  $("evFilter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    evFilter = b.dataset.f;
    try { localStorage.setItem("lp_evf", evFilter); } catch (_) {}
    renderActivity();
  });
  // device panel: dismiss / undo a risk (delegated, because the panel re-renders on every update)
  $("panel").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-dismiss],[data-undismiss]");
    if (!b || !selected) return;
    const body = b.dataset.dismiss != null ? {dismiss: b.dataset.dismiss} : {undismiss: b.dataset.undismiss};
    if (await api(devApi(selected), "POST", body)) toast(body.dismiss ? "Risk accepted" : "Warning turned back on");
  });
  // map search
  const q = $("q");
  q.addEventListener("input", renderFindResults);
  q.addEventListener("focus", renderFindResults);
  q.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { const f = $("findRes").querySelector(".fr"); if (f) { pickDevice(f.dataset.id); $("findRes").classList.add("hidden"); } }
    else if (e.key === "Escape") { q.value = ""; q.dispatchEvent(new Event("input")); q.blur(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); $("findRes").querySelector(".fr")?.focus(); }
  });
  $("findRes").addEventListener("click", (e) => { const f = e.target.closest(".fr"); if (f) { pickDevice(f.dataset.id); $("findRes").classList.add("hidden"); } });
  $("findRes").addEventListener("keydown", (e) => {
    const f = e.target.closest(".fr"); if (!f) return;
    if (e.key === "ArrowDown") { e.preventDefault(); (f.nextElementSibling?.classList.contains("fr") ? f.nextElementSibling : f).focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); (f.previousElementSibling || q).focus(); }
  });
  document.addEventListener("click", (e) => { if (!e.target.closest("#mapFind")) $("findRes").classList.add("hidden"); });
  setInterval(() => { if (view === "net") { renderHealth(); loadBusiest(); } }, 15000);
  setTimeout(loadBusiest, 1500);
  renderSidebar();
  restoreSidebarState();
})();
