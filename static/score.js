// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Network Security Score: one A-F grade for the whole network, its 30-day trend, and the top things to fix. */

let postureData = null;

const GRADE_COLOR = {A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444"};

async function loadPosture() {
  const r = await api("/api/posture?days=30", "GET");
  if (!r) return;
  postureData = r;
  renderPostureBar();
}

function postureTrendSvg(hist, w = 160, h = 34) {
  if (!hist || hist.length < 2) return "";
  const xs = hist.map((_, i) => i / (hist.length - 1) * (w - 4) + 2);
  const ys = hist.map((p) => h - 3 - (p.score / 100) * (h - 6));
  const pts = xs.map((x, i) => `${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
  const last = hist[hist.length - 1];
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-label="30-day score trend">
    <polyline fill="none" stroke="${GRADE_COLOR[last.grade] || "#38bdf8"}" stroke-width="1.6" points="${pts}"/>
    <circle cx="${xs[xs.length - 1].toFixed(1)}" cy="${ys[ys.length - 1].toFixed(1)}" r="2.5" fill="${GRADE_COLOR[last.grade] || "#38bdf8"}"/>
  </svg>`;
}

function renderPostureBar(elId = "postureBar") {
  const el = $(elId);
  if (!el || !postureData) return;
  const p = postureData;
  const col = GRADE_COLOR[p.grade] || "#38bdf8";
  const hist = p.history || [];
  const first = hist.length > 1 ? hist[0].score : null;
  const delta = first != null ? p.score - first : 0;
  const trendTxt = first == null ? "" : delta > 0 ? `<span style="color:#86efac">▲ +${delta} in ${hist.length}d</span>`
    : delta < 0 ? `<span style="color:#fca5a5">▼ ${delta} in ${hist.length}d</span>` : `<span class="muted">no change</span>`;
  el.innerHTML = `
    <div class="ps-grade" style="--gc:${col}"><span class="ps-letter">${esc(p.grade)}</span><span class="ps-num">${p.score}<small>/100</small></span></div>
    <div class="ps-mid">
      <div class="ps-title">Risk Profile <span class="muted">· ${p.devices} device${p.devices === 1 ? "" : "s"}</span></div>
      <div class="ps-bars">${(p.breakdown || []).slice(0, 6).map((b) =>
        `<span class="ps-chip" title="−${b.points} points: ${esc(b.count)} ${esc(b.label)}">−${b.points} ${esc(b.label)}</span>`).join("")
        || '<span class="ps-chip ok">No deductions — nothing to fix</span>'}</div>
    </div>
    <div class="ps-trend">${postureTrendSvg(hist)}<div class="ps-trend-lbl">${trendTxt}</div></div>
    ${p.fixes && p.fixes.length ? `<button class="btn sm" id="psFixes"><i class="fa-solid fa-list-check"></i>Fix list</button>` : ""}`;
  // inline, collapsible fix list under the bar
  let fl = $("postureFixes");
  if (!fl) { fl = document.createElement("div"); fl.id = "postureFixes"; fl.className = "ps-fixlist hidden"; el.after(fl); }
  fl.innerHTML = (p.fixes || []).map((f) => `<div class="ps-fix"><span class="ps-fix-pts">+${f.points}</span><span>${esc(f.text)}</span></div>`).join("");
  const fb = $("psFixes");
  if (fb) fb.onclick = () => { fl.classList.toggle("hidden"); };
}

(function initScore() {
  viewHooks.redteam = (function (prev) {
    return function () { if (typeof prev === "function") prev(); loadPosture(); };
  })(viewHooks.redteam);
})();
