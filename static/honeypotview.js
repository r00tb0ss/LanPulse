// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Honeypot view: built-in low-interaction decoy services. Every hit is high-signal; a hit from a device on
   your own network is a strong sign it's compromised or scanning the LAN. */

let potData = null;

async function loadHoneypot() {
  const r = await api("/api/honeypot", "GET");
  if (!r || view !== "honeypot") return;
  potData = r;
  renderHoneypot();
}

const devByIp = (ip) => [...devices.values()].find((d) => d.ip === ip);
function potServiceChip(svc) {                       // small label for a decoy service
  const cat = (potData && potData.catalog && potData.catalog[svc]) || null;
  return cat ? cat.label : svc;
}

function renderHoneypot() {
  const s = potData;
  if (!s || !$("potKpis")) return;
  const t = s.totals;

  // status banner (off / running)
  const live = Object.values(s.listeners || {}).filter((l) => l.state === "listening").length;
  const note = $("potStatus");
  if (!s.enabled) {
    note.className = "v-note";
    note.classList.remove("hidden");
    note.innerHTML = `<i class="fa-solid fa-circle-info"></i> The honeypot is off. Turn it on in
      <button class="linkbtn" id="potOnLink">Settings</button> to start catching probes and brute-force attempts.`;
  } else {
    note.classList.add("hidden");
  }

  $("potKpis").innerHTML = `
    <div class="kpi"><span class="k-lbl">Hits</span><span class="k-num">${t.hits}</span><span class="k-sub">last ${Math.round(s.hours / 24) || 1}d &middot; ${t.all_time} all time</span></div>
    <div class="kpi ${t.internal ? "danger" : ""}"><span class="k-lbl">From your network</span><span class="k-num">${t.internal}</span><span class="k-sub">${t.internal ? "possible compromise" : "none — good"}</span></div>
    <div class="kpi"><span class="k-lbl">Unique sources</span><span class="k-num">${t.attackers}</span><span class="k-sub">${t.external} external hits</span></div>
    <div class="kpi"><span class="k-lbl">Logins tried</span><span class="k-num">${t.creds}</span><span class="k-sub">captured credentials</span></div>`;

  // listener status strip
  $("potListeners").innerHTML = Object.entries(s.listeners || {}).map(([k, l]) => {
    const label = potServiceChip(k);
    const title = l.state === "error" ? esc(l.error || "could not start") :
      l.state === "listening" ? "listening for connections" : "turned off";
    return `<span class="pot-listener ${l.state}" title="${title}">
      <i class="fa-solid fa-circle"></i>${esc(label)}<span class="pot-port">:${l.port}</span>
      ${l.state === "error" ? `<span class="pot-lerr">${esc(l.error || "error")}</span>` : ""}</span>`;
  }).join("");

  // recent hits
  $("potHits").innerHTML = s.recent.length ? s.recent.map((h) => `
    <div class="pot-hit ${h.internal ? "internal" : ""} ${h.internal && !devByIp(h.ip) ? "" : "click"}" data-ip="${esc(h.ip)}" data-ext="${h.internal ? "" : "1"}" title="${h.internal ? "Open this device" : "Look up this IP"}">
      <span class="pot-when" title="${esc(full(h.t))}">${ago(h.t)}</span>
      <span class="pot-svc">${esc(potServiceChip(h.service))}<span class="pot-port">:${h.port}</span></span>
      <span class="pot-ip mono">${esc(h.ip)}</span>
      ${h.internal ? `<span class="tagchip bad" title="A device on your own network hit the honeypot">internal</span>`
                   : (h.sensor ? `<span class="tagchip">${esc(h.sensor)}</span>` : "")}
      ${h.creds ? `<span class="pot-creds" title="login attempted"><i class="fa-solid fa-key"></i>${esc(h.creds)}</span>` : ""}
      ${!h.creds && h.data ? `<span class="pot-data mono">${esc(h.data)}</span>` : ""}
    </div>`).join("") : `<div class="muted">No hits yet. Once the decoys are on, anything that connects shows up here.</div>`;

  // attackers (internal ones tappable if we know the device)
  $("potAttackers").innerHTML = s.attackers.length ? s.attackers.map((a) => {
    const dev = [...devices.values()].find((d) => d.ip === a.ip);
    return `<div class="pot-att ${a.internal ? "internal" : ""}" ${dev ? `data-dev-ip="${esc(a.ip)}"` : (!a.internal ? `data-ext-ip="${esc(a.ip)}"` : "")}>
      <div class="pot-att-ip"><span class="mono">${esc(a.ip)}</span>
        ${a.internal ? `<span class="tagchip bad">internal</span>` : ""}
        ${dev ? `<span class="muted">${esc(nmLabel(dev))}</span>` : ""}</div>
      <div class="pot-att-meta"><span class="pot-hitn">${a.hits}</span>
        <span class="muted">${a.services.map(potServiceChip).map(esc).join(", ")}</span></div>
    </div>`;
  }).join("") : `<div class="muted">Nobody yet.</div>`;

  // services breakdown
  const maxSvc = Math.max(1, ...s.by_service.map((x) => x.count));
  $("potServices").innerHTML = s.by_service.length ? s.by_service.map((x) => `
    <div class="pot-bar"><span class="pot-bar-l">${esc(x.label)}</span>
      <span class="pot-bar-track"><span class="pot-bar-fill" style="width:${Math.round(x.count / maxSvc * 100)}%"></span></span>
      <span class="pot-bar-n">${x.count}</span></div>`).join("") : `<div class="muted">No decoy has been touched yet.</div>`;

  // credentials tried
  $("potCreds").innerHTML = s.creds.length ? s.creds.map((c) => `
    <div class="pot-cred"><span class="mono">${esc(c.cred)}</span><span class="pot-cred-n">${c.count}&times;</span></div>`).join("")
    : `<div class="muted">No login attempts captured yet. Telnet, FTP and HTTP decoys record these.</div>`;

  if ($("potOnLink")) $("potOnLink").onclick = () => showPotSetup(true);
  potBadge();
}

function nmLabel(d) {
  return d.name || d.friendly || d.hostname || d.vendor || d.ip;
}

function potBadge() {
  const b = $("potBadge");
  if (!b || !potData) return;
  const n = potData.totals.internal;             // internal hits are the ones worth a badge
  b.textContent = n;
  b.classList.toggle("hidden", !n);
}

/* ---- settings card (enable, per-service decoys, bind, ingest key) */
async function showPotSetup(force) {
  const box = $("potSetup");
  if (!force && !box.classList.contains("hidden")) { box.classList.add("hidden"); return; }
  const set = await api("/api/settings", "GET");
  if (!set) return;
  const c = set.honeypot || {};
  const cat = (potData && potData.catalog) || {};
  const svcOn = c.services || {};
  const lst = (potData && potData.listeners) || {};
  const rows = Object.keys(cat).length ? Object.entries(cat) :
    Object.entries(svcOn).map(([k]) => [k, {port: (lst[k] || {}).port || 0, label: k, note: ""}]);
  box.classList.remove("hidden");
  box.innerHTML = `<div class="t-card"><h4><span><i class="fa-solid fa-jar"></i> Honeypot settings</span></h4>
    <p class="hint">Turn on decoy services. Pick ports your LanPulse host doesn't already use — a decoy can't share a port
      with a real service. If a decoy can't start, you'll see why in its row.</p>
    <label class="full chk-line"><input type="checkbox" id="potEnabled" ${c.enabled ? "checked" : ""}> <b>Run the honeypot</b></label>
    <div class="pot-svc-grid">
      ${rows.map(([k, v]) => {
        const l = lst[k] || {};
        const err = l.state === "error" ? `<span class="pot-lerr">${esc(l.error || "can't start")}</span>` : "";
        return `<label class="pot-svc-opt"><input type="checkbox" data-pot-svc="${esc(k)}" ${svcOn[k] ? "checked" : ""}>
          <span class="pot-svc-h">${esc(v.label)} <span class="pot-port">:${v.port}</span>${err}</span>
          <span class="pot-svc-note">${esc(v.note || "")}</span></label>`;
      }).join("")}
    </div>
    <div class="chan-fields" style="padding:8px 0 0">
      <label class="full">Listen on<input id="potBind" value="${esc(c.bind || "0.0.0.0")}" placeholder="0.0.0.0 (all interfaces)"></label>
      <label class="full">External-sensor key (optional)<input id="potKey" type="password" value="${esc(c.ingest_key || "")}" autocomplete="off"
        placeholder="set a key to let an ESP32 / other sensor POST hits"></label>
    </div>
    <p class="hint" style="font-size:12px">A sensor sends hits to <span class="mono">POST /api/honeypot/ingest</span> with header
      <span class="mono">X-LanPulse-Key</span> and a JSON body like <span class="mono">{"ip":"1.2.3.4","service":"ssh","port":22,"creds":"root / x"}</span>.</p>
    <div class="modal-foot" style="position:static;padding:10px 0 0"><span class="test-res" id="potRes"></span>
      <button class="btn primary" id="potSave"><i class="fa-solid fa-floppy-disk"></i>Save</button></div></div>`;
  $("potSave").onclick = async () => {
    const services = {};
    box.querySelectorAll("[data-pot-svc]").forEach((el) => { services[el.dataset.potSvc] = el.checked; });
    const body = {honeypot: {enabled: $("potEnabled").checked, bind: $("potBind").value.trim() || "0.0.0.0",
      ingest_key: $("potKey").value.trim(), services}};
    if (await api("/api/settings", "POST", body)) {
      toast($("potEnabled").checked ? "Honeypot settings saved — decoys start within a few seconds." : "Honeypot turned off.");
      box.classList.add("hidden");
      setTimeout(loadHoneypot, 1200);
    }
  };
}

(function initHoneypot() {
  viewHooks.honeypot = loadHoneypot;
  const cfg = $("potCfgBtn");
  if (cfg) cfg.onclick = () => showPotSetup();
  const hits = $("potHits");
  const goIp = (ip, ext) => { const d = devByIp(ip); if (d) openPanel(d.id); else if (ext && typeof openIp === "function") openIp(ip); };
  if (hits) hits.addEventListener("click", (e) => { const r = e.target.closest("[data-ip]"); if (r) goIp(r.dataset.ip, !!r.dataset.ext); });
  const att = $("potAttackers");
  if (att) att.addEventListener("click", (e) => {
    const x = e.target.closest("[data-ext-ip]");
    if (x) return goIp(x.dataset.extIp, true);
    const r = e.target.closest("[data-dev-ip]");
    if (!r) return;
    const d = [...devices.values()].find((x) => x.ip === r.dataset.devIp);
    if (d) openPanel(d.id);
  });
  // keep the tab badge live-ish even when another view is open
  setInterval(() => { if (view !== "honeypot") api("/api/honeypot?hours=24", "GET").then((r) => { if (r) { potData = potData || r; const b = $("potBadge"); if (b) { b.textContent = r.totals.internal; b.classList.toggle("hidden", !r.totals.internal); } } }); }, 60000);
})();
