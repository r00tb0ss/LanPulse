// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Device timeline: everything LanPulse noticed about one device, newest first, grouped by day. */

const TL_FILTERS = [
  ["important", "Important"], ["security", "Security"], ["ports", "Ports"], ["network", "Network"],
  ["presence", "Online/offline"], ["you", "Your changes"], ["all", "All"],
];
const TL_ICONS = {
  new: "fa-circle-plus", online: "fa-plug-circle-check", offline: "fa-plug-circle-xmark", ip: "fa-right-left",
  port: "fa-door-open", port_closed: "fa-door-closed", software: "fa-code-compare", scan: "fa-magnifying-glass",
  security: "fa-triangle-exclamation", vuln: "fa-bug", vuln_gone: "fa-circle-check", threat: "fa-user-secret",
  you: "fa-user-pen",
};
let tlFilter = "important";
let tlData = null;          // {id, items}
let tlDays = 30;

async function loadDeviceTimeline(id, keep) {
  if (!keep) { tlData = null; tlDays = 30; }
  const r = await api(`/api/devices/${encodeURIComponent(id)}/timeline?days=${tlDays}`, "GET");
  if (!r || id !== selected) return;
  tlData = {id, items: r.items || []};
  drawTimeline();
}

function tlShown(items) {
  if (tlFilter === "all") return items;
  if (tlFilter === "important") return items.filter((x) => x.group !== "presence");
  return items.filter((x) => x.group === tlFilter);
}

function tlDay(ts) {
  const d = new Date(ts * 1000), today = new Date();
  const y = new Date(); y.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], {weekday: "short", month: "short", day: "numeric"});
}

function drawTimeline() {
  const box = $("tlBox");
  if (!box || !tlData || tlData.id !== selected) return;
  const all = tlData.items;
  const items = tlShown(all);
  const count = (k) => k === "all" ? all.length : k === "important" ? all.filter((x) => x.group !== "presence").length
    : all.filter((x) => x.group === k).length;
  const counts = Object.fromEntries(TL_FILTERS.map(([k]) => [k, count(k)]));
  let lastDay = "";
  const rows = items.slice(0, 150).map((x) => {
    const day = tlDay(x.t);
    const head = day !== lastDay ? `<div class="tl-day">${esc(day)}</div>` : "";
    lastDay = day;
    return `${head}<div class="tl-row ${esc(x.level)}"><i class="fa-solid ${TL_ICONS[x.kind] || "fa-circle"}"></i>
      <span class="tl-time">${esc(clock(x.t))}</span><span class="tl-text">${esc(x.text)}</span></div>`;
  }).join("");
  box.innerHTML = `
    <div class="tl-chips">${TL_FILTERS.filter(([k]) => counts[k] || k === "important" || k === tlFilter)
      .map(([k, label]) => `<button class="tl-chip ${k === tlFilter ? "on" : ""}" data-tl="${k}">${esc(label)}<span>${counts[k]}</span></button>`).join("")}</div>
    ${rows || `<div class="muted">${all.length ? "Nothing of this kind in the last " + tlDays + " days." : "Nothing recorded yet. Changes show up here from now on."}</div>`}
    ${items.length > 150 ? `<div class="muted" style="margin-top:6px">Showing the latest 150.</div>` : ""}
    ${tlDays < 90 && all.length ? `<button class="linkbtn" id="tlMore" style="margin-top:8px">Show up to 90 days</button>` : ""}`;
  box.querySelectorAll("[data-tl]").forEach((b) => b.onclick = () => { tlFilter = b.dataset.tl; drawTimeline(); });
  const more = $("tlMore");
  if (more) more.onclick = () => { tlDays = 90; loadDeviceTimeline(tlData.id, true); };
}
