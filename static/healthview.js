// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Health board, at the top of the Services tab: is each part LanPulse relies on alive, and when did it last report? */

let healthData = null;
const H_PILL = {ok: "Working", warn: "Check", bad: "Problem", off: "Not set up"};

async function loadHealth() {
  const r = await api("/api/health", "GET");
  if (!r) return;
  healthData = r;
  renderHealth();
}

function healthTile(i) {
  return `<div class="h-tile ${i.state}">
    <div class="h-ic"><i class="fa-solid ${esc(i.icon)}"></i></div>
    <div class="h-body">
      <div class="h-row"><b>${esc(i.name)}</b><span class="h-pill ${i.state}">${H_PILL[i.state]}</span></div>
      <div class="h-detail">${esc(i.detail)}</div>
      ${i.hint && i.state !== "ok" ? `<div class="h-hint">${esc(i.hint)}</div>` : ""}
      ${i.last ? `<div class="h-last">Last report ${ago(i.last)}</div>` : ""}
    </div></div>`;
}

function renderHealth() {
  const h = healthData, box = $("healthCard");
  if (!h || !box) return;
  const live = h.items.filter((i) => i.state !== "off"), off = h.items.filter((i) => i.state === "off");
  const [cls, icon, msg] = h.bad ? ["bad", "fa-circle-exclamation", `${h.bad} ${h.bad === 1 ? "part needs" : "parts need"} attention`]
    : h.warn ? ["warn", "fa-triangle-exclamation", `${h.warn} to check`]
    : live.length ? ["ok", "fa-circle-check", "Everything is reporting"] : ["off", "fa-circle-info", "Nothing connected yet"];
  box.innerHTML = `<div class="h-head"><div><h3>LanPulse health</h3>
      <span class="muted">Whether each source and sensor is alive, and when it last reported</span></div>
      <span class="h-overall ${cls}"><i class="fa-solid ${icon}"></i>${msg}</span></div>
    ${live.length ? `<div class="h-grid">${live.map(healthTile).join("")}</div>` : ""}
    ${off.length ? `<div class="h-off"><span class="muted">Not set up:</span>${off.map((i) => `<span class="h-chip" title="${esc(i.hint)}"><i class="fa-solid ${esc(i.icon)}"></i>${esc(i.name)}</span>`).join("")}</div>` : ""}`;
  const dot = $("svcBadge");
  if (dot && h.bad && view !== "svc") { dot.textContent = String(Math.max(+dot.textContent || 0, h.bad)); dot.classList.remove("hidden"); }
}

(function initHealth() {
  const open = viewHooks.svc;
  viewHooks.svc = () => { if (open) open(); loadHealth(); };
  setInterval(() => { if (view === "svc") loadHealth(); }, 30000);
  setTimeout(loadHealth, 3500);
})();
