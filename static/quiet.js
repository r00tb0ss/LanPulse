// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Quiet mode: mute alert messages for a while. LanPulse keeps watching and recording; only the messages are held back. */

let quietData = {active: false, until: 0, muted: 0};
const qTime = (t) => new Date(t * 1000).toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});

async function loadQuiet() {
  const r = await api("/api/quiet", "GET");
  if (r) { quietData = r; renderQuiet(); }
}

function quietMenu() {
  const q = quietData;
  const body = q.active
    ? `<div class="q-title"><i class="fa-solid fa-bell-slash"></i>Alerts are muted</div>
       <p class="q-sub">Until <b>${qTime(q.until)}</b>. ${q.muted ? `${q.muted} held back so far.` : "Nothing has been held back yet."}</p>
       <button class="btn primary q-wide" data-q="off"><i class="fa-solid fa-bell"></i>Turn alerts back on</button>
       <div class="q-or">or change it</div>`
    : `<div class="q-title"><i class="fa-solid fa-bell"></i>Mute alerts</div>
       <p class="q-sub">Pause messages while you work on the network.</p>`;
  return `${body}<div class="q-opts">
      <button class="btn" data-q="60">1 hour</button><button class="btn" data-q="240">4 hours</button>
      <button class="btn" data-q="morning">Until 8 AM</button></div>
    <p class="q-note">LanPulse keeps watching and recording while muted. The daily summary still goes out.</p>`;
}

function renderQuiet() {
  const b = $("btnQuiet");
  if (!b) return;
  b.classList.toggle("quiet-on", !!quietData.active);
  b.innerHTML = `<i class="fa-solid ${quietData.active ? "fa-bell-slash" : "fa-bell"}"></i>`;
  b.title = quietData.active ? `Alerts muted until ${qTime(quietData.until)}` : "Mute alerts for a while";
  const pop = $("quietPop");
  if (pop && !pop.classList.contains("hidden")) pop.innerHTML = quietMenu();
}

(function initQuiet() {
  const pop = $("quietPop"), btn = $("btnQuiet");
  if (!pop || !btn) return;
  btn.onclick = (e) => {
    e.stopPropagation();
    pop.classList.toggle("hidden");
    if (!pop.classList.contains("hidden")) { pop.innerHTML = quietMenu(); loadQuiet(); }
  };
  pop.addEventListener("click", async (e) => {
    e.stopPropagation();
    const b = e.target.closest("[data-q]");
    if (!b) return;
    const v = b.dataset.q;
    const r = await api("/api/quiet", "POST", v === "off" ? {off: true} : v === "morning" ? {morning: true} : {minutes: +v});
    if (!r) return;
    quietData = r; renderQuiet();
    pop.classList.add("hidden");
    toast(r.active ? `Alerts muted until ${qTime(r.until)}` : "Alerts are back on");
  });
  document.addEventListener("click", () => pop.classList.add("hidden"));
  setInterval(() => { if (quietData.active && quietData.until * 1000 < Date.now()) loadQuiet(); }, 15000);
  setInterval(loadQuiet, 120000);
  setTimeout(loadQuiet, 2500);
})();
