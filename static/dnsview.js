// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* DNS tab: what every device looks up, from Pi-hole. */

let dnsData = null, dnsHours = 24, dnsDev = "", dnsLoadedAt = 0, dnsMalSeen = 0;

async function loadDns() {
  const r = await api(`/api/dns?hours=${dnsHours}${dnsDev ? `&device=${encodeURIComponent(dnsDev)}` : ""}`, "GET");
  if (!r) return;
  dnsData = r; dnsLoadedAt = Date.now();
  renderDns();
}

function renderDns() {
  const s = dnsData;
  if (!s) return;
  const st = s.status || {};
  const configured = s.enabled;
  $("dnsBody").classList.toggle("hidden", !configured);
  if (!configured) {
    $("dnsSub").textContent = "connect your Pi-hole to see what each device looks up";
    if ($("dnsSetup").classList.contains("hidden")) showDnsSetup(true);
    return;
  }
  if (!$("dnsSetup").dataset.open) $("dnsSetup").classList.add("hidden");
  $("dnsSub").innerHTML = st.state === "error" ? `<span style="color:#fca5a5"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(st.error)}</span>`
    : st.last_poll ? `from your Pi-hole${st.version ? ` (v${esc(st.version)})` : ""} · updated ${ago(st.last_poll)}` : "connecting to Pi-hole…";
  const pct = s.total ? Math.round(100 * s.blocked / s.total) : 0;
  const mal = s.malware || [];
  $("dnsKpis").innerHTML = `
    <div class="kpi"><span class="k-lbl">Lookups</span><span class="k-num">${fmtN(s.total)}</span><span class="k-sub">last ${s.hours === 168 ? "7 days" : s.hours + "h"}</span></div>
    <div class="kpi"><span class="k-lbl">Blocked</span><span class="k-num">${pct}%</span><span class="k-sub">${fmtN(s.blocked)} lookups</span></div>
    <div class="kpi"><span class="k-lbl">Domains</span><span class="k-num">${fmtN(s.domains)}</span><span class="k-sub">different names</span></div>
    <div class="kpi"><span class="k-lbl">Devices</span><span class="k-num">${fmtN(s.clients.length)}</span><span class="k-sub">${dnsDev ? "filtered" : "making lookups"}</span></div>
    <div class="kpi ${mal.length ? "danger" : ""}"><span class="k-lbl">Malware lookups</span><span class="k-num">${mal.length}</span>
      <span class="k-sub">${mal.length ? esc(mal[0].name) : s.malware_list ? `checked against ${fmtN(s.malware_list)} domains`
        : s.malware_status?.error ? "list couldn't download" : "loading the list…"}</span></div>`;
  const ms = s.malware_status || {};
  $("dnsListNote").classList.toggle("hidden", !!s.malware_list || !ms.error);
  if (!s.malware_list && ms.error) $("dnsListNote").innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i><div>
    <b>The malware domain list couldn't download,</b> so lookups aren't being checked yet. LanPulse retries every 15 minutes.
    <div class="muted" style="font-size:12px;margin-top:4px">${esc(ms.error)}</div>
    <div class="btns" style="margin-top:8px"><button class="btn sm" id="dnsListRetry"><i class="fa-solid fa-rotate"></i>Retry now</button></div></div>`;
  if ($("dnsListRetry")) $("dnsListRetry").onclick = async (e) => {
    e.currentTarget.disabled = true; e.currentTarget.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>Downloading…';
    const r = await api("/api/dns/malware-refresh", "POST");
    if (r) { toast(r.count ? `Malware list loaded: ${fmtN(r.count)} domains` : "Still couldn't download the list"); loadDns(); }
  };
  $("dnsRouterNote").classList.toggle("hidden", !s.router_only);
  if (s.router_only) $("dnsRouterNote").innerHTML = `<i class="fa-solid fa-circle-info"></i><div><b>Almost every lookup comes from your router,</b>
    so Pi-hole can't tell devices apart. Hand out Pi-hole as the DNS server directly: on a UDM, Settings &gt; Networks &gt; your LAN &gt;
    DHCP Service Management &gt; DNS Server, set it to your Pi-hole's IP. Devices pick it up as their leases renew.</div>`;
  $("dnsMalCard").classList.toggle("hidden", !mal.length);
  $("dnsMal").innerHTML = mal.map((m) => `<button class="mal-row" data-dev-id="${esc(m.id)}">
      <i class="fa-solid fa-skull-crossbones"></i><span class="nm">${esc(m.name)}</span><span class="dom">${esc(m.domain)}</span>
      <span class="muted">${fmtN(m.count)}× · ${ago(m.last)}</span></button>`).join("");
  const rankRows = (rows, color, key = "domain") => {
    const max = Math.max(1, ...rows.map((r) => r.count));
    return rows.map((r) => `<div class="rk ${r.bad ? "hot" : ""}" title="${esc(r[key])}"><span class="ico"><i class="fa-solid ${r.bad ? "fa-skull-crossbones" : "fa-globe"}" style="color:${r.bad ? "#f43f5e" : "#5b6b88"}"></i></span>
      <span class="nm">${esc(r[key])}</span><span class="ct">${fmtN(r.count)}</span><div class="bar"><i style="width:${(100 * r.count / max).toFixed(1)}%;background:${color}"></i></div></div>`).join("")
      || `<div class="muted">Nothing yet.</div>`;
  };
  $("dnsTop").innerHTML = rankRows(s.top, "#2dd4bf");
  $("dnsBlocked").innerHTML = rankRows(s.top_blocked, "#f43f5e");
  const cmax = Math.max(1, ...s.clients.map((c) => c.count));
  $("dnsClients").innerHTML = s.clients.map((c) => { const t = TYPES[c.type] || TYPES.unknown; return `<div class="rk click ${dnsDev === c.ip ? "sel" : ""}" data-ip="${esc(c.ip)}">
      <span class="ico"><i class="${faClass(t)}" style="color:${t.color}"></i></span><span class="nm">${esc(c.name)}</span>
      <span class="ct">${fmtN(c.count)}${c.blocked ? ` <span style="color:#fca5a5">· ${fmtN(c.blocked)} blocked</span>` : ""}</span>
      <div class="bar"><i style="width:${(100 * c.count / cmax).toFixed(1)}%;background:var(--accent2)"></i></div></div>`; }).join("") || `<div class="muted">No lookups yet.</div>`;
  const hmax = Math.max(1, ...s.hist.map((h) => h[0]));
  $("dnsHist").innerHTML = s.hist.map(([n, b]) => `<span title="${fmtN(n)} lookups, ${fmtN(b)} blocked" style="height:${Math.max(2, 100 * n / hmax)}%">
      <i style="height:${n ? (100 * b / n).toFixed(1) : 0}%"></i></span>`).join("");
  $("dnsHistAxis").innerHTML = `<span>${s.hours === 168 ? "7 days ago" : s.hours + "h ago"}</span><span>now</span>`;
  if ($("dnsLive").querySelectorAll(".dl").length < 10) $("dnsLive").innerHTML = (s.recent || []).slice(0, 40).map(dnsRow).join("")
    || `<div class="muted">Waiting for lookups…</div>`;
  $("dnsLiveNote").textContent = dnsDev ? "this device" : "all devices";
  // device picker
  const sel = $("dnsDevice");
  const opts = s.clients.map((c) => [c.ip, c.name]);
  if (dnsDev && !opts.some(([ip]) => ip === dnsDev)) opts.unshift([dnsDev, dnsDev]);
  sel.innerHTML = `<option value="">All devices</option>` + opts.map(([ip, nm]) => `<option value="${esc(ip)}" ${ip === dnsDev ? "selected" : ""}>${esc(nm)}</option>`).join("");
  updateDnsBadge();
}

function dnsRow(e) {
  return `<div class="dl ${e.blocked ? "blk" : ""} ${e.bad ? "bad" : ""}"><time>${clock(e.t)}</time>
    <span class="who">${esc(e.name || e.client)}</span><span class="dom">${esc(e.domain)}</span>
    ${e.bad ? '<span class="tagchip bad">malware</span>' : e.blocked ? '<span class="tagchip">blocked</span>' : ""}</div>`;
}

function onDnsLive(msg) {
  const items = (msg.items || []).filter((e) => !dnsDev || e.client === dnsDev);
  if (items.some((e) => e.bad)) { dnsMalSeen += items.filter((e) => e.bad).length; updateDnsBadge(); }
  if (view !== "dns" || !items.length) return;
  const list = $("dnsLive");
  if (!list.querySelector(".dl")) list.innerHTML = "";
  list.insertAdjacentHTML("afterbegin", items.slice(-15).reverse().map(dnsRow).join(""));
  while (list.childElementCount > 60) list.lastElementChild.remove();
  if (Date.now() - dnsLoadedAt > 30000) loadDns();
}

function updateDnsBadge() {
  const b = $("dnsBadge");
  if (b) { b.textContent = String(dnsMalSeen); b.classList.toggle("hidden", !dnsMalSeen || view === "dns"); }
}

/* ---- Pi-hole setup */
async function showDnsSetup(force) {
  const box = $("dnsSetup");
  if (!force && !box.classList.contains("hidden")) { box.classList.add("hidden"); delete box.dataset.open; return; }
  const set = await api("/api/settings", "GET");
  if (!set) return;
  const c = set.dns || {};
  box.dataset.open = force && !dnsData?.enabled ? "" : "1";
  box.classList.remove("hidden");
  box.innerHTML = `<div class="t-card"><h4><span><i class="fa-solid fa-plug"></i> Connect your Pi-hole</span></h4>
    <p class="hint">LanPulse reads Pi-hole's query log to show what each device looks up, and warns you when one looks up a known
      malware domain. Works with Pi-hole v6 (and v5).</p>
    <div class="chan-fields" style="padding:0">
      <label class="full">Pi-hole address<input id="dnsUrl" value="${esc(c.url || "")}" placeholder="http://192.168.0.138"></label>
      <label class="full">Password<input id="dnsPw" type="password" value="${esc(c.password || "")}" autocomplete="off"
        placeholder="web interface password, or an app password"></label>
      <label class="full chk-line"><input type="checkbox" id="dnsMalOn" ${c.malware !== false ? "checked" : ""}> Check lookups against the abuse.ch URLhaus malware list</label>
      <label class="full">abuse.ch Auth-Key (optional, free at auth.abuse.ch)<input id="dnsAbuseKey" type="password" value="${esc(c.abuse_key || "")}" autocomplete="off"
        placeholder="not needed: LanPulse falls back to a mirror of the same list"></label>
      <label class="full chk-line"><input type="checkbox" id="dnsTls" ${c.verify_tls ? "checked" : ""}> Verify Pi-hole's HTTPS certificate</label>
    </div>
    <p class="hint" style="font-size:12px">Tip: in Pi-hole, Settings &gt; Web interface / API &gt; <b>App password</b> creates a separate password just for LanPulse.
      For Pi-hole v5, paste the API token instead.</p>
    <div class="modal-foot" style="position:static;padding:10px 0 0"><span class="test-res" id="dnsRes"></span>
      ${c.enabled ? `<button class="btn danger" id="dnsOff">Disconnect</button>` : ""}
      <button class="btn" id="dnsTest"><i class="fa-solid fa-vial"></i>Test</button>
      <button class="btn primary" id="dnsSave"><i class="fa-solid fa-floppy-disk"></i>Save and connect</button></div></div>`;
  const form = (enabled) => ({url: $("dnsUrl").value.trim(), password: $("dnsPw").value, malware: $("dnsMalOn").checked, abuse_key: $("dnsAbuseKey").value.trim(),
    verify_tls: $("dnsTls").checked, enabled});
  $("dnsTest").onclick = async () => {
    $("dnsRes").className = "test-res"; $("dnsRes").textContent = "Testing…";
    const r = await api("/api/dns/test", "POST", form(true), true);
    $("dnsRes").className = `test-res ${r && r.ok ? "ok" : "bad"}`;
    $("dnsRes").textContent = r && r.ok ? `Connected to Pi-hole v${r.version}. ${r.recent} lookups in the last 10 minutes.` : (r?.error || "No response");
  };
  $("dnsSave").onclick = async () => {
    if (!$("dnsUrl").value.trim()) { $("dnsRes").className = "test-res bad"; $("dnsRes").textContent = "Enter your Pi-hole's address."; return; }
    if (await api("/api/settings", "POST", {dns: form(true)})) {
      toast("Pi-hole connected. Lookups appear within a minute.");
      if (!dnsData?.malware_list) api("/api/dns/malware-refresh", "POST").then(() => loadDns());
      box.classList.add("hidden"); delete box.dataset.open;
      setTimeout(loadDns, 1500);
    }
  };
  if ($("dnsOff")) $("dnsOff").onclick = async () => { if (await api("/api/settings", "POST", {dns: {enabled: false}})) { toast("Pi-hole disconnected"); loadDns(); } };
}

/* ---- device panel: what it looks up */
async function loadDeviceDns(id) {
  const d = devices.get(id);
  if (!d) return;
  const s = await api(`/api/dns?hours=24&device=${encodeURIComponent(d.ip)}`, "GET");
  const box = $("dnsBox");
  if (!s || selected !== id || !box) return;
  if (!s.enabled || !s.total) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  box.classList.remove("hidden");
  const max = Math.max(1, ...s.top.map((t) => t.count));
  box.innerHTML = `<h4>What it looks up · last 24h</h4>
    <div class="muted" style="font-size:12px;margin-bottom:6px">${fmtN(s.total)} lookups · ${fmtN(s.blocked)} blocked by Pi-hole · ${fmtN(s.domains)} domains</div>
    ${(s.malware || []).length ? `<div class="finding"><span class="sev high">malware</span><span>Looked up ${s.malware.map((m) => esc(m.domain)).slice(0, 3).join(", ")}</span></div>` : ""}
    <div class="rank">${s.top.slice(0, 6).map((t) => `<div class="rk"><span class="ico"><i class="fa-solid fa-globe" style="color:#5b6b88"></i></span>
      <span class="nm">${esc(t.domain)}</span><span class="ct">${fmtN(t.count)}</span><div class="bar"><i style="width:${(100 * t.count / max).toFixed(1)}%;background:#2dd4bf"></i></div></div>`).join("")}</div>
    <div class="btns" style="margin-top:10px"><button class="btn" data-dns-ip="${esc(d.ip)}"><i class="fa-solid fa-globe"></i>Open in DNS tab</button></div>`;
}

(function initDns() {
  viewHooks.dns = () => { dnsMalSeen = 0; updateDnsBadge(); loadDns(); };
  $("dnsRange").onchange = (e) => { dnsHours = +e.target.value; $("dnsLive").innerHTML = ""; loadDns(); };
  $("dnsDevice").onchange = (e) => { dnsDev = e.target.value; $("dnsLive").innerHTML = ""; loadDns(); };
  $("dnsCfgBtn").onclick = () => showDnsSetup(false);
  $("dnsClients").addEventListener("click", (e) => {
    const r = e.target.closest("[data-ip]"); if (!r) return;
    dnsDev = dnsDev === r.dataset.ip ? "" : r.dataset.ip; $("dnsLive").innerHTML = ""; loadDns();
  });
  $("dnsMal").addEventListener("click", (e) => { const r = e.target.closest("[data-dev-id]"); if (r && r.dataset.devId) goDevice(r.dataset.devId); });
  $("panel").addEventListener("click", (e) => {
    const b = e.target.closest("[data-dns-ip]"); if (!b) return;
    dnsDev = b.dataset.dnsIp; $("dnsLive").innerHTML = ""; setView("dns");
  });
  setInterval(() => { if (view === "dns" && Date.now() - dnsLoadedAt > 60000) loadDns(); }, 15000);
})();
