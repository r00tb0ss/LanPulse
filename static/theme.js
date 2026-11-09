// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Theme switching. Themes are CSS custom-property sets selected by body[data-theme]; the choice is remembered
   per browser in localStorage. The world map (canvas, not CSS) is re-coloured from the active theme's tokens. */

const THEMES = [
  {id: "dark", name: "Midnight (default)", sub: "the original dark navy", sw: ["#0a0f1c", "#38bdf8", "#22c55e"]},
  {id: "light", name: "Enterprise Light", sub: "clean white, for the office", sw: ["#ffffff", "#0284c7", "#16a34a"]},
  {id: "hacker", name: "80s Hacker", sub: "green phosphor on black", sw: ["#000700", "#39ff14", "#157a32"]},
  {id: "synthwave", name: "Midnight Synthwave", sub: "neon magenta & cyan", sw: ["#140a2e", "#ff4fd8", "#2dd4bf"]},
  {id: "ember", name: "Ember", sub: "warm black, copper glow", sw: ["#0c0a09", "#ff8a4c", "#f5c542"]},
  {id: "ocean", name: "Deep Ocean", sub: "sea-green depths, aqua", sw: ["#041a1f", "#22d3c5", "#4ade80"]},
  {id: "frost", name: "Frost", sub: "cool slate, ice blue", sw: ["#242933", "#88c0d0", "#a3be8c"]},
  {id: "sand", name: "Sand", sub: "warm paper, terracotta", sw: ["#f4efe6", "#c2562a", "#3f8a4f"]},
  {id: "noir", name: "Crimson Noir", sub: "pure black, one red accent", sw: ["#0a0a0b", "#ff3b4e", "#f2f2f3"]},
];

function currentTheme() {
  try { return localStorage.getItem("lp_theme") || "dark"; } catch (_) { return "dark"; }
}

function applyTheme(id) {
  const t = THEMES.find((x) => x.id === id) ? id : "dark";
  if (t === "dark") document.body.removeAttribute("data-theme");
  else document.body.setAttribute("data-theme", t);
  try { localStorage.setItem("lp_theme", t); } catch (_) {}
  // Re-colour the world map, which draws on canvas and doesn't inherit CSS variables.
  // Wrapped in try/catch: tChart may not be declared yet at first load (it lives in another script).
  try {
    if (tChart) {
      const css = getComputedStyle(document.body);
      tChart.setOption({geo: {itemStyle: {areaColor: css.getPropertyValue("--map-area").trim() || "#16243f",
        borderColor: css.getPropertyValue("--map-border").trim() || "#2b4170"}}});
    }
  } catch (_) {}
}

// cssVar: read a theme token (used by the map code so it follows the theme).
function cssVar(name, fallback) {
  try { return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback; } catch (_) { return fallback; }
}

function renderAppearance(body) {
  const cur = currentTheme();
  body.innerHTML = `<p class="hint">Pick a look for this dashboard. The choice is saved in this browser.</p>
    <div class="theme-grid">${THEMES.map((t) => `
      <button class="theme-card ${t.id === cur ? "on" : ""}" data-theme-id="${t.id}">
        <div class="sw">${t.sw.map((c) => `<span style="background:${c}"></span>`).join("")}</div>
        <b>${esc(t.name)}</b><small>${esc(t.sub)}</small>
      </button>`).join("")}</div>`;
  body.querySelectorAll("[data-theme-id]").forEach((b) => b.onclick = () => {
    applyTheme(b.dataset.themeId);
    renderAppearance(body);
  });
}

// Apply the saved theme as early as possible.
applyTheme(currentTheme());
