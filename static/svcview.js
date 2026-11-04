// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Services tab: up/down board with uptime history; add, edit, test and remove checks. */

let svcData = null, svcEditing = null;

async function loadServices() {
  const r = await api("/api/services", "GET");
  if (!r) return;
  svcData = r;
  renderServices();
}

function svcState(c) {
  if (!c.enabled) return ["paused", "Paused"];
  if (c.up === true) return ["up", "Up"];
  if (c.up === false) return ["down", "Down"];
  return ["wait", "Checking…"];
}

function renderServices() {
  const s = svcData;
  if (!s) return;
  const ups = s.checks.filter((c) => c.up24 != null);
  const avg = ups.length ? ups.reduce((a, c) => a + c.up24, 0) / ups.length : null;
  $("svcKpis").innerHTML = `
    <div class="kpi"><span class="k-lbl">Up</span><span class="k-num" style="color:#86efac">${s.up}</span><span class="k-sub">of ${s.total} checks</span></div>
    <div class="kpi ${s.down ? "danger" : ""}"><span class="k-lbl">Down</span><span class="k-num">${s.down}</span>
      <span class="k-sub">${s.down ? esc(s.checks.filter((c) => c.up === false).map((c) => c.name).join(", ")) : "everything's answering"}</span></div>
    <div class="kpi"><span class="k-lbl">Uptime</span><span class="k-num">${avg == null ? "—" : avg.toFixed(avg >= 99.95 ? 0 : 2) + "%"}</span><span class="k-sub">average, last 24h</span></div>
    <div class="kpi"><span class="k-lbl">Incidents</span><span class="k-num">${s.checks.reduce((a, c) => a + (c.incidents || []).filter((i) => Date.now() / 1000 - i.down < 7 * 86400).length, 0)}</span><span class="k-sub">last 7 days</span></div>`;
  const sg = s.suggestions || [];
  $("svcSugg").classList.toggle("hidden", !sg.length);
  $("svcSugg").innerHTML = sg.length ? `<span class="muted"><i class="fa-solid fa-wand-magic-sparkles"></i> Found on your network:</span>
    ${sg.map((g, i) => `<button class="sugg" data-sugg="${i}"><i class="fa-solid fa-plus"></i>${esc(g.name)}</button>`).join("")}` : "";
  $("svcBoard").innerHTML = s.checks.length ? s.checks.map(svcCard).join("") :
    `<div class="t-card svc-empty"><i class="fa-solid fa-heart-pulse"></i><b>No checks yet</b>
      <span>Add the things you care about: Plex, Pi-hole, your router, a web server. LanPulse checks them every minute and alerts you when one goes down.</span>
      <button class="btn primary" id="svcAddEmpty"><i class="fa-solid fa-plus"></i>Add a check</button></div>`;
  if ($("svcAddEmpty")) $("svcAddEmpty").onclick = () => editService(null);
  const badge = $("svcBadge");
  if (badge) { badge.textContent = String(s.down); badge.classList.toggle("hidden", !s.down || view === "svc"); }
}

function svcCard(c) {
  const [cls, label] = svcState(c);
  const tgt = c.type === "tcp" ? `${c.target}:${c.port}` : c.target;
  const last = (c.incidents || [])[0];
  const bars = (c.bars || []).map((b) => `<i class="${b == null ? "nd" : b >= 0.999 ? "ok" : b >= 0.9 ? "warn" : "bad"}"
      title="${b == null ? "no data" : Math.round(b * 100) + "% of checks OK"}"></i>`).join("");
  return `<div class="t-card svc-card ${cls}" data-id="${esc(c.id)}">
    <div class="svc-top"><span class="svc-dot ${cls}"></span>
      <div class="svc-name"><b>${esc(c.name)}</b><span class="muted">${esc(c.type.toUpperCase())} · ${esc(tgt)}</span></div>
      <span class="svc-state ${cls}">${label}${c.since && c.enabled && c.up != null ? ` <span class="muted">for ${esc(sinceText(c.since))}</span>` : ""}</span></div>
    ${c.up === false && c.err ? `<div class="svc-err"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(c.err)}</div>` : ""}
    <div class="svc-bars" aria-label="Last 24 hours">${bars}</div>
    <div class="svc-axis"><span>24h ago</span><span>now</span></div>
    <div class="svc-stats">
      <span><b>${c.up24 == null ? "—" : c.up24 + "%"}</b> 24h</span><span><b>${c.up7 == null ? "—" : c.up7 + "%"}</b> 7 days</span>
      <span><b>${c.ms != null ? c.ms + " ms" : "—"}</b> now</span><span><b>${c.avg_ms != null ? c.avg_ms + " ms" : "—"}</b> avg</span></div>
    ${last ? `<div class="svc-inc muted"><i class="fa-solid fa-clock-rotate-left"></i> Last outage ${ago(last.down)}${last.up ? `, lasted ${esc(durText(last.up - last.down))}` : ", still down"}${last.err ? ` (${esc(last.err)})` : ""}</div>` : ""}
    <div class="svc-act"><button class="btn sm ghost" data-act="test"><i class="fa-solid fa-vial"></i>Test</button>
      <button class="btn sm ghost" data-act="edit"><i class="fa-solid fa-pen"></i>Edit</button>
      <button class="btn sm ghost" data-act="pause">${c.enabled ? '<i class="fa-solid fa-pause"></i>Pause' : '<i class="fa-solid fa-play"></i>Resume'}</button></div>
  </div>`;
}

function sinceText(t) { return durText(Date.now() / 1000 - t); }
function durText(s) {
  s = Math.max(0, Math.round(s));
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} days`;
}

function onServicesLive(msg) {
  if (!svcData) { svcData = {...msg, suggestions: []}; }
  else {
    const byId = new Map(msg.checks.map((c) => [c.id, c]));
    svcData.checks = svcData.checks.map((c) => byId.has(c.id) ? {...c, ...pick(byId.get(c.id), ["up", "since", "ms", "err", "fails", "enabled"])} : c);
    Object.assign(svcData, {up: msg.up, down: msg.down, total: msg.total});
  }
  if (view === "svc" && !svcEditing) renderServices();
  else { const b = $("svcBadge"); if (b) { b.textContent = String(msg.down); b.classList.toggle("hidden", !msg.down || view === "svc"); } }
}
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => k in o).map((k) => [k, o[k]]));

async function saveChecks(checks) {
  const r = await api("/api/services", "POST", {checks});
  if (r) { svcData = r; renderServices(); }
  return r;
}

function editService(c, preset) {
  svcEditing = c ? c.id : "new";
  const v = c || preset || {type: "http", target: "", port: 0, interval: 60, name: ""};
  const box = $("svcForm");
  box.classList.remove("hidden");
  box.innerHTML = `<div class="t-card"><h4><span>${c ? "Edit check" : "Add a check"}</span></h4>
    <div class="chan-fields" style="padding:0">
      <label>Name<input id="svName" value="${esc(v.name)}" placeholder="e.g. Plex"></label>
      <label>Type<select id="svType">${[["http", "Web page (HTTP/HTTPS)"], ["tcp", "Port is open (TCP)"], ["ping", "Answers ping"]]
        .map(([k, l]) => `<option value="${k}" ${v.type === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      <label class="full" id="svTargetL">Address<input id="svTarget" value="${esc(v.target)}" autocomplete="off"></label>
      <label id="svPortL">Port<input id="svPort" type="number" min="1" max="65535" value="${v.port || ""}"></label>
      <label>Check every<select id="svInt">${[[30, "30 seconds"], [60, "minute"], [300, "5 minutes"], [900, "15 minutes"]]
        .map(([k, l]) => `<option value="${k}" ${+v.interval === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      <label class="full chk-line" id="svTlsL"><input type="checkbox" id="svTls" ${v.verify_tls ? "checked" : ""}> Require a trusted HTTPS certificate</label>
    </div>
    <div class="modal-foot" style="position:static;padding:10px 0 0"><span class="test-res" id="svRes"></span>
      ${c ? `<button class="btn danger" id="svDel"><i class="fa-solid fa-trash"></i>Remove</button>` : ""}
      <button class="btn ghost" id="svCancel">Cancel</button>
      <button class="btn" id="svTest"><i class="fa-solid fa-vial"></i>Test</button>
      <button class="btn primary" id="svSave"><i class="fa-solid fa-floppy-disk"></i>Save</button></div></div>`;
  const sync = () => {
    const t = $("svType").value;
    $("svPortL").classList.toggle("hidden", t !== "tcp");
    $("svTlsL").classList.toggle("hidden", t !== "http");
    $("svTarget").placeholder = t === "http" ? "http://192.168.0.81:32400/web" : "192.168.0.1 or pi.hole";
    $("svTargetL").firstChild.textContent = t === "http" ? "Web address" : "Host or IP";
  };
  $("svType").onchange = sync; sync();
  const read = () => {
    let target = $("svTarget").value.trim();
    const type = $("svType").value;
    if (type === "http" && target && !/^https?:\/\//i.test(target)) target = "http://" + target;
    return {id: c?.id || "", name: $("svName").value.trim() || target, type, target, port: +$("svPort").value || 0,
      interval: +$("svInt").value, verify_tls: $("svTls").checked, enabled: c ? c.enabled : true, device: v.device || ""};
  };
  $("svTest").onclick = async () => {
    $("svRes").className = "test-res"; $("svRes").textContent = "Testing…";
    const r = await api("/api/services/test", "POST", read(), true);
    $("svRes").className = `test-res ${r && r.ok ? "ok" : "bad"}`;
    $("svRes").textContent = r?.ok ? `Up · ${r.ms} ms` : r?.error ? `Down: ${r.error}` : "No response";
  };
  $("svSave").onclick = async () => {
    const n = read();
    if (!n.target) { $("svRes").className = "test-res bad"; $("svRes").textContent = "Enter an address."; return; }
    const checks = (svcData?.checks || []).map(stripCheck);
    const i = checks.findIndex((x) => x.id === n.id);
    if (i >= 0) checks[i] = n; else checks.push(n);
    const before = checks.length;
    const r = await saveChecks(checks);
    if (!r) return;
    if (r.checks.length < before) { $("svRes").className = "test-res bad"; $("svRes").textContent = "That address or port isn't valid."; return; }
    closeSvcForm(); toast(c ? "Check updated" : "Check added. First result in a few seconds.");
  };
  $("svCancel").onclick = closeSvcForm;
  if ($("svDel")) $("svDel").onclick = async () => {
    if (!confirm(`Remove the check "${c.name}" and its history?`)) return;
    if (await saveChecks(svcData.checks.filter((x) => x.id !== c.id).map(stripCheck))) { closeSvcForm(); toast("Check removed"); }
  };
  box.scrollIntoView({behavior: "smooth", block: "nearest"});
  $("svName").focus();
}
const stripCheck = (c) => pick(c, ["id", "name", "type", "target", "port", "interval", "verify_tls", "enabled", "device"]);
function closeSvcForm() { svcEditing = null; $("svcForm").classList.add("hidden"); $("svcForm").innerHTML = ""; renderServices(); }

(function initServices() {
  viewHooks.svc = loadServices;
  $("svcAdd").onclick = () => editService(null);
  $("svcSugg").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-sugg]"); if (!b) return;
    const g = svcData.suggestions[+b.dataset.sugg];
    const checks = svcData.checks.map(stripCheck);
    checks.push({...g, interval: 60, enabled: true});
    if (await saveChecks(checks)) toast(`Watching ${g.name}`);
  });
  $("svcBoard").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const c = svcData.checks.find((x) => x.id === b.closest("[data-id]").dataset.id); if (!c) return;
    if (b.dataset.act === "edit") editService(c);
    else if (b.dataset.act === "pause") saveChecks(svcData.checks.map((x) => stripCheck(x.id === c.id ? {...x, enabled: !x.enabled} : x)));
    else if (b.dataset.act === "test") {
      b.disabled = true;
      const r = await api("/api/services/test", "POST", stripCheck(c), true);
      b.disabled = false;
      toast(r?.ok ? `${c.name}: up · ${r.ms} ms` : `${c.name}: ${r?.error || "no response"}`);
    }
  });
  setInterval(() => { if (view === "svc" && !svcEditing) loadServices(); }, 60000);
  setTimeout(async () => { const r = await api("/api/services", "GET"); if (r) { svcData = r; renderServices(); } }, 3000);
})();
