// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Honeypot view: built-in low-interaction decoy services. Every hit is high-signal; a hit from a device on
   your own network is a strong sign it's compromised or scanning the LAN. */

let potData = null;
let potHours = 168;
let potAttackType = "all";
let potSelectedService = "";
let potSection = (() => { try { return localStorage.getItem("lp_pot_section") === "analysis" ? "analysis" : "overview"; } catch (_) { return "overview"; } })();

function setPotSection(section, persist = true) {
  potSection = section === "analysis" ? "analysis" : "overview";
  const analysis = potSection === "analysis";
  const tabs = $("potSectionTabs");
  if (tabs) tabs.querySelectorAll("[data-pot-section]").forEach((b) => {
    const active = b.dataset.potSection === potSection;
    b.classList.toggle("on", active);
    b.setAttribute("aria-selected", String(active));
    b.tabIndex = active ? 0 : -1;
  });
  $("potOverviewPane")?.classList.toggle("hidden", analysis);
  $("potAnalysisPane")?.classList.toggle("hidden", !analysis);
  if (persist) { try { localStorage.setItem("lp_pot_section", potSection); } catch (_) {} }
  if (analysis && typeof loadMalware === "function") loadMalware();
}

async function loadHoneypot() {
  const r = await api("/api/honeypot?hours=" + potHours, "GET");
  if (!r || view !== "honeypot") return;
  potData = r;
  renderHoneypot();
  if (potSelectedService) loadPotServiceDetail(potSelectedService, false);
  if (typeof loadMalware === "function") loadMalware();      // captured attacks and malware card (static/malwareview.js)
}

const devByIp = (ip) => [...devices.values()].find((d) => d.ip === ip);
function potServiceChip(svc) {                       // small label for a decoy service
  const cat = (potData && potData.catalog && potData.catalog[svc]) || null;
  return cat ? cat.label : svc;
}

let potAttackersExpanded = false;

// Categories describe the evidence captured by the decoy; they do not claim attribution or intent.
function potAttackKind(hit) {
  if (hit.creds) return "credentials";
  if (hit.data) return "probe";
  return "connection";
}
function potAttackKindLabel(kind) {
  return ({credentials: "Credential attempts", probe: "Protocol / request probes",
    connection: "Connections only"})[kind] || kind;
}
function renderPotRecent() {
  const hits = (potData && potData.recent) || [];
  const filtered = hits.filter((h) => (!potSelectedService || h.service === potSelectedService) &&
    (potAttackType === "all" || potAttackKind(h) === potAttackType));
  $("potHits").innerHTML = filtered.length ? filtered.map((h) => `
    <div class="pot-hit click ${h.internal ? "internal" : ""}" data-ip="${esc(h.ip)}" title="Show everything this address did">
      <span class="pot-when" title="${esc(full(h.t))}">${ago(h.t)}</span>
      <span class="pot-svc">${esc(potServiceChip(h.service))}<span class="pot-port">:${h.port}</span></span>
      <span class="pot-ip mono">${esc(h.ip)}</span>
      ${h.iso ? `<span class="pot-geo" title="${esc([h.city, h.country].filter(Boolean).join(", "))}">${flagHtml(h.iso)} ${esc(h.country || h.iso)}</span>` : ""}
      ${h.internal ? `<span class="tagchip bad" title="A device on your own network hit the honeypot">internal</span>`
                   : (h.sensor ? `<span class="tagchip">${esc(h.sensor)}</span>` : "")}
      ${h.creds ? `<span class="pot-creds" title="login attempted"><i class="fa-solid fa-key"></i>${esc(h.creds)}</span>` : ""}
      ${h.data ? `<span class="pot-data mono">${esc(h.data)}</span>` : ""}
    </div>`).join("") : `<div class="muted">No recent hits match these filters.</div>`;
  const serviceLabel = potSelectedService ? potServiceChip(potSelectedService) : "All services";
  $("potFilterSummary").textContent = serviceLabel + " · " +
    (potAttackType === "all" ? "All attack evidence" : potAttackKindLabel(potAttackType)) +
    ` · ${filtered.length} of ${hits.length} recent hits`;
}
async function loadPotServiceDetail(service, scroll = true) {
  potSelectedService = service || "";
  renderPotRecent();
  $("potServices").querySelectorAll("[data-pot-service]").forEach((el) => {
    const active = el.dataset.potService === potSelectedService;
    el.classList.toggle("selected", active);
    el.setAttribute("aria-pressed", String(active));
  });
  const box = $("potServiceDetail");
  if (!potSelectedService) { box.classList.add("hidden"); box.innerHTML = ""; renderHoneypot(); return; }
  box.classList.remove("hidden");
  box.innerHTML = `<div class="muted">Loading ${esc(potServiceChip(service))} hosts…</div>`;
  if (scroll) box.scrollIntoView({behavior: "smooth", block: "nearest"});
  const r = await api("/api/honeypot/service?service=" + encodeURIComponent(service) +
    "&hours=" + potHours, "GET");
  if (!r || potSelectedService !== service) {
    if (!r && potSelectedService === service) box.innerHTML = `<div class="muted">Couldn't load hosts for this service.</div>`;
    return;
  }
  const hosts = r.hosts || [];
  box.innerHTML = `
    <h4><span>${esc(r.label)} hosts <span class="muted">· ${r.total} hits from ${r.host_count} hosts</span></span>
      <button class="btn sm ghost" id="potServiceClear">Show all services <i class="fa-solid fa-xmark"></i></button></h4>
    ${hosts.length ? `<div class="pot-service-hosts">${hosts.map((h) => {
      const dev = devByIp(h.ip);
      const where = [h.city, h.country].filter(Boolean).join(", ");
      return `<div class="pot-service-host click" data-pot-ip="${esc(h.ip)}">
        <div class="pot-service-host-main"><b class="mono">${esc(h.ip)}</b>
          ${h.internal ? `<span class="tagchip bad">internal</span>` : ""}
          ${dev ? `<span class="muted">${esc(nmLabel(dev))}</span>` : ""}
          <span class="pot-hitn">${h.hits} hits</span></div>
        <div class="pot-service-host-meta">
          <span>${h.iso ? flagHtml(h.iso) + " " : ""}${esc(where || "Location unavailable")}</span>
          <span>${esc(h.org || "Network unknown")}${h.asn ? " · AS" + esc(h.asn) : ""}</span>
          <span>Ports: ${esc((h.ports || []).join(", ") || "—")}</span>
          <span>${h.credential_hits} credential attempts</span>
          <span>First: ${esc(ago(h.first))}</span>
          <span>Last: ${esc(ago(h.last))}</span>
          ${h.sensor ? `<span class="tagchip">${esc(h.sensor)}</span>` : ""}
        </div>
      </div>`;
    }).join("")}</div>` : `<div class="muted">No hosts hit this service in the selected time range.</div>`}
    ${r.truncated ? `<p class="muted">Showing the 200 most active hosts.</p>` : ""}
    <p class="muted">Select a host to inspect its full event history and captured details.</p>`;
  $("potServiceClear").onclick = () => loadPotServiceDetail("");
  box.querySelectorAll("[data-pot-ip]").forEach((el) => el.addEventListener("click", () => showPotDetail(el.dataset.potIp)));
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

  // Recent hits are filtered by captured evidence and selected decoy.
  renderPotRecent();

  // attackers (internal ones tappable if we know the device)
  const attackerRows = s.attackers || [];
  const visibleAttackers = potAttackersExpanded ? attackerRows : attackerRows.slice(0, 10);
  $("potAttackers").innerHTML = attackerRows.length ? `
    <div class="pot-expand-list ${potAttackersExpanded ? "expanded" : ""}">${visibleAttackers.map((a) => {
      const dev = [...devices.values()].find((d) => d.ip === a.ip);
      return `<div class="pot-att ${a.internal ? "internal" : ""}" data-pot-ip="${esc(a.ip)}">
        <div class="pot-att-ip"><span class="mono">${esc(a.ip)}</span>
          ${a.internal ? `<span class="tagchip bad">internal</span>` : ""}
          ${dev ? `<span class="muted">${esc(nmLabel(dev))}</span>` : ""}</div>
        <div class="pot-att-meta"><span class="pot-hitn">${a.hits}</span>
          <span class="muted">${a.services.map(potServiceChip).map(esc).join(", ")}</span></div>
        ${a.iso || a.org ? `<div class="pot-att-geo muted">${a.iso ? flagHtml(a.iso) + " " + esc([a.city, a.country].filter(Boolean).join(", ")) : ""}${a.org ? ` &middot; ${esc(a.org)}` : ""}</div>` : ""}
        <div class="pot-att-geo muted">first ${ago(a.first)} &middot; last ${ago(a.last)}</div>
      </div>`;
    }).join("")}</div>
    ${attackerRows.length > 10 ? `<button class="btn sm ghost pot-expand-toggle" data-expand-attackers>${potAttackersExpanded ? "Show less" : `View all (${attackerRows.length})`}</button>` : ""}` : `<div class="muted">Nobody yet.</div>`;

  // Services are buttons: selecting one opens the hosts that hit that decoy.
  const maxSvc = Math.max(1, ...s.by_service.map((x) => x.count));
  $("potServices").innerHTML = s.by_service.length ? s.by_service.map((x) => `
    <button type="button" class="pot-bar pot-service-row ${potSelectedService === x.service ? "selected" : ""}"
      data-pot-service="${esc(x.service)}" aria-pressed="${potSelectedService === x.service}">
      <span class="pot-bar-l">${esc(x.label)}</span>
      <span class="pot-bar-track"><span class="pot-bar-fill" style="width:${Math.round(x.count / maxSvc * 100)}%"></span></span>
      <span class="pot-bar-n">${x.count}</span><i class="fa-solid fa-chevron-right"></i></button>`).join("")
    : `<div class="muted">No decoy has been touched yet.</div>`;

  // credentials tried
  $("potCreds").innerHTML = s.creds.length ? s.creds.map((c) => `
    <div class="pot-cred"><span class="mono">${esc(c.cred)}</span><span class="pot-cred-n">${c.count}&times;</span></div>`).join("")
    : `<div class="muted">No login attempts captured yet. Telnet, FTP and HTTP decoys record these.</div>`;

  // activity over the chosen window
  const hmax = Math.max(1, ...s.hist), n = s.hist.length, span = s.hours / n;
  const slice = (i) => { const h = span * (n - i); return h >= 24 ? Math.round(h / 24) + "d" : Math.round(h) + "h"; };
  $("potTimeline").innerHTML = `<h4><span>Activity</span><span class="muted">hits over the last ${s.hours >= 48 ? Math.round(s.hours / 24) + " days" : s.hours + " hours"}</span></h4>
    <div class="hbars">${s.hist.map((c, i) => `<span style="height:${Math.max(2, 100 * c / hmax)}%" title="${c} hits, ${slice(i)} ago"></span>`).join("")}</div>
    <div class="spark-cap"><span>${s.hours >= 48 ? Math.round(s.hours / 24) + " days ago" : s.hours + "h ago"}</span><span>now</span></div>`;

  const bars = (rows, label, sub) => rows.length ? rows.map((x) => `
    <div class="pot-bar"><span class="pot-bar-l pot-bar-w">${label(x)}</span>
      <span class="pot-bar-track"><span class="pot-bar-fill" style="width:${Math.round(x[sub] / Math.max(1, rows[0][sub]) * 100)}%"></span></span>
      <span class="pot-bar-n">${x[sub]}</span></div>`).join("") : "";
  $("potCountries").innerHTML = bars(s.countries || [], (c) => `${flagHtml(c.iso)} ${esc(c.country)}<span class="muted"> &middot; ${c.ips} IP${c.ips === 1 ? "" : "s"}</span>`, "hits")
    || `<div class="muted">No outside visitors yet (or the GeoIP database isn't installed).</div>`;
  $("potUsers").innerHTML = bars(s.usernames || [], (x) => `<span class="mono">${esc(x.v)}</span>`, "count") || `<div class="muted">No logins captured yet.</div>`;
  $("potPasswords").innerHTML = bars(s.passwords || [], (x) => `<span class="mono">${esc(x.v)}</span>`, "count") || `<div class="muted">No logins captured yet.</div>`;
  if ($("potHours")) $("potHours").value = String(potHours);

  if ($("potOnLink")) $("potOnLink").onclick = () => showPotSetup(true);
  potBadge();
}

async function showPotDetail(ip) {
  const box = $("potDetail");
  box.classList.remove("hidden");
  box.innerHTML = `<div class="muted">Loading ${esc(ip)}&hellip;</div>`;
  box.scrollIntoView({behavior: "smooth", block: "nearest"});
  const r = await api("/api/honeypot/ip?ip=" + encodeURIComponent(ip), "GET");
  if (!r) { box.innerHTML = `<div class="muted">Couldn't load this address.</div>`; return; }
  const dev = devByIp(ip);
  const where = [r.city, r.country].filter(Boolean).join(", ");
  box.innerHTML = `
    <h4><span class="pot-d-title"><span class="mono">${esc(r.ip)}</span>
        ${r.internal ? `<span class="tagchip bad">internal</span>` : ""}${dev ? ` <span class="muted">${esc(nmLabel(dev))}</span>` : ""}</span>
      <button class="btn sm ghost" id="potDetailClose" title="Close"><i class="fa-solid fa-xmark"></i></button></h4>
    <div class="pot-d-facts">
      <div><span class="k-lbl">Hits</span><b>${r.total}</b></div>
      <div><span class="k-lbl">First seen</span><b>${r.first ? esc(full(r.first)) : "—"}</b></div>
      <div><span class="k-lbl">Last seen</span><b>${r.last ? esc(full(r.last)) : "—"}</b></div>
      <div><span class="k-lbl">Location</span><b>${r.iso ? flagHtml(r.iso) + " " : ""}${esc(where || "—")}</b></div>
      <div><span class="k-lbl">Network</span><b>${esc(r.org || "—")}${r.asn ? ` <span class="muted">AS${r.asn}</span>` : ""}</b></div>
      <div><span class="k-lbl">Decoys touched</span><b>${r.services.map((x) => `${esc(x.label)} ×${x.count}`).join(", ") || "—"}</b></div>
    </div>
    ${r.creds.length ? `<h5>Logins tried</h5><div class="pot-d-creds">${r.creds.map((c) => `<span class="pot-cred-chip mono">${esc(c.cred)}${c.count > 1 ? ` <i>×${c.count}</i>` : ""}</span>`).join("")}</div>` : ""}
    <h5>Everything it sent <span class="muted">(newest first, up to 500)</span></h5>
    <div class="pot-hits pot-d-hits">${r.hits.map((h) => `
      <div class="pot-hit"><span class="pot-when" title="${esc(full(h.t))}">${esc(full(h.t))}</span>
        <span class="pot-svc">${esc(potServiceChip(h.service))}<span class="pot-port">:${h.port}</span></span>
        ${h.sensor ? `<span class="tagchip">${esc(h.sensor)}</span>` : ""}
        ${h.creds ? `<span class="pot-creds"><i class="fa-solid fa-key"></i>${esc(h.creds)}</span>` : ""}
        ${h.data ? `<span class="pot-data pot-data-full mono">${esc(h.data)}</span>` : ""}</div>`).join("")}</div>
    <div class="pot-d-actions">
      ${r.internal ? (dev ? `<button class="btn sm" id="potDetailDev"><i class="fa-solid fa-laptop"></i>Open device</button>` : "")
                   : `<button class="btn sm" id="potDetailIntel"><i class="fa-solid fa-magnifying-glass"></i>Full IP intelligence &amp; block</button>`}
    </div>`;
  $("potDetailClose").onclick = () => box.classList.add("hidden");
  if ($("potDetailIntel")) $("potDetailIntel").onclick = () => { if (typeof openIp === "function") openIp(ip); };
  if ($("potDetailDev")) $("potDetailDev").onclick = () => openPanel(dev.id);
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
  const bn = c.banners || {};
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
        const dp = v.default_port || v.port;
        return `<div class="pot-svc-opt"><input type="checkbox" data-pot-svc="${esc(k)}" ${svcOn[k] ? "checked" : ""} aria-label="${esc(v.label)}">
          <span class="pot-svc-h">${esc(v.label)} <span class="pot-port">port <input class="pot-port-in" type="number" min="1" max="65535" data-pot-port="${esc(k)}" value="${(c.ports || {})[k] || dp}" title="default ${dp}"></span>${err}</span>
          <span class="pot-svc-note">${esc(v.note || "")}</span></div>`;
      }).join("")}
    </div>
    <details class="pot-adv"><summary>Customize how the decoys look and behave</summary>
      <div class="pot-adv-grid">
        <label>SSH banner<input id="potBnSsh" maxlength="80" value="${esc(bn.ssh || "")}" placeholder="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"></label>
        <label>Telnet greeting<input id="potBnTel" maxlength="80" value="${esc(bn.telnet || "")}" placeholder="Ubuntu 22.04.3 LTS"></label>
        <label>FTP banner<input id="potBnFtp" maxlength="80" value="${esc(bn.ftp || "")}" placeholder="(vsFTPd 3.0.5)"></label>
        <label>Web server name<input id="potBnSrv" maxlength="80" value="${esc(bn.http_server || "")}" placeholder="lighttpd/1.4.69"></label>
        <label>Web page title<input id="potBnTitle" maxlength="80" value="${esc(bn.http_title || "")}" placeholder="Router Admin"></label>
        <label>Slow scanners down (ms per reply)<input id="potDelay" type="number" min="0" max="5000" value="${c.delay_ms ?? 0}"></label>
        <label>Keep hits for (days)<input id="potKeep" type="number" min="1" max="365" value="${c.retention_days ?? 90}"></label>
        <label>Alert and map at most (hits per address)<input id="potFloodMax" type="number" min="1" max="500" value="${c.flood_max ?? 12}"></label>
        <label>...within (minutes)<input id="potFloodMin" type="number" min="1" max="120" value="${c.flood_minutes ?? 10}"></label>
      </div>
      <label class="chk-line"><input type="checkbox" id="potAlertExt" ${c.alert_external === false ? "" : "checked"}> Send an alert when something from the internet hits a decoy (hits from your own network always alert)</label>
      <label class="full">Never log these addresses (one per line, IPs or ranges like 10.0.0.0/24)
        <textarea id="potIgnore" rows="3" placeholder="e.g. a monitoring server, your own scanner">${esc(c.ignore || "")}</textarea></label>
      <p class="hint" style="font-size:12px">Banners are what a scanner sees when it connects. Changing a port restarts that decoy within a few seconds.
        Ports below 1024 need LanPulse to run with permission for them.</p>
    </details>
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
    const ports = {};
    box.querySelectorAll("[data-pot-port]").forEach((el) => { if (el.value) ports[el.dataset.potPort] = parseInt(el.value, 10); });
    const banners = {ssh: $("potBnSsh").value, telnet: $("potBnTel").value, ftp: $("potBnFtp").value,
      http_server: $("potBnSrv").value, http_title: $("potBnTitle").value};
    const body = {honeypot: {enabled: $("potEnabled").checked, bind: $("potBind").value.trim() || "0.0.0.0",
      ingest_key: $("potKey").value.trim(), services, ports, banners,
      delay_ms: $("potDelay").value, retention_days: $("potKeep").value, flood_max: $("potFloodMax").value,
      flood_minutes: $("potFloodMin").value, alert_external: $("potAlertExt").checked, ignore: $("potIgnore").value}};
    if (await api("/api/settings", "POST", body)) {
      toast($("potEnabled").checked ? "Honeypot settings saved — decoys start within a few seconds." : "Honeypot turned off.");
      box.classList.add("hidden");
      setTimeout(loadHoneypot, 1200);
    }
  };
}

(function initHoneypot() {
  viewHooks.honeypot = loadHoneypot;
  const sectionTabs = $("potSectionTabs");
  if (sectionTabs) {
    sectionTabs.addEventListener("click", (e) => {
      const tab = e.target.closest("[data-pot-section]");
      if (tab) setPotSection(tab.dataset.potSection);
    });
    sectionTabs.addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      const tabs = [...sectionTabs.querySelectorAll("[data-pot-section]")];
      const current = tabs.indexOf(document.activeElement);
      if (current < 0) return;
      e.preventDefault();
      const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 :
        (current + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
      tabs[next].focus();
      setPotSection(tabs[next].dataset.potSection);
    });
    setPotSection(potSection, false);
  }
  const cfg = $("potCfgBtn");
  if (cfg) cfg.onclick = () => showPotSetup();
  const svc = $("potServices");
  if (svc) svc.addEventListener("click", (e) => {
    const row = e.target.closest("[data-pot-service]");
    if (row) loadPotServiceDetail(row.dataset.potService);
  });
  const attackType = $("potAttackType");
  if (attackType) attackType.onchange = () => { potAttackType = attackType.value; renderPotRecent(); };
  const hits = $("potHits");
  if (hits) hits.addEventListener("click", (e) => { const r = e.target.closest("[data-ip]"); if (r) showPotDetail(r.dataset.ip); });
  const att = $("potAttackers");
  if (att) att.addEventListener("click", (e) => {
    if (e.target.closest("[data-expand-attackers]")) { potAttackersExpanded = !potAttackersExpanded; renderHoneypot(); return; }
    const r = e.target.closest("[data-pot-ip]"); if (r) showPotDetail(r.dataset.potIp);
  });
  const hrs = $("potHours");
  if (hrs) hrs.onchange = () => { potHours = parseInt(hrs.value, 10) || 168; loadHoneypot(); };
  // keep the tab badge live-ish even when another view is open
  setInterval(() => { if (view !== "honeypot") api("/api/honeypot?hours=24", "GET").then((r) => { if (r) { potData = potData || r; const b = $("potBadge"); if (b) { b.textContent = r.totals.internal; b.classList.toggle("hidden", !r.totals.internal); } } }); }, 60000);
})();
