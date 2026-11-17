// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";

/* Dedicated YARA view. Captured samples are fetched as metadata and scanned results;
   file bytes are never executed or exposed by this view. */
let yaraStatus = null;
let yaraSamples = [];

async function loadYaraView() {
  const notice = $("yaraNotice");
  if (notice) notice.textContent = "Checking YARA engine and captured-file results…";
  const [status, samples] = await Promise.all([
    api("/api/honeypot/yara/status", "GET"),
    api("/api/honeypot/samples?limit=200", "GET")
  ]);
  if (view !== "honeypot" || potSection !== "yara") return;
  yaraStatus = status || {};
  const rows = (samples && samples.samples) || [];
  const details = await Promise.all(rows.slice(0, 40).map(async (row) => {
    const detail = await api("/api/honeypot/sample?sha=" + encodeURIComponent(row.sha256), "GET");
    return {row, detail: detail || {}};
  }));
  if (view !== "honeypot" || potSection !== "yara") return;
  yaraSamples = details;
  renderYaraView(samples && samples.total || rows.length);
}

function formatYaraPackageDate(value) {
  if (value === null || value === undefined || value === "") return "Not reported";
  const raw = typeof value === "number" || /^\\d+(?:\\.\\d+)?$/.test(String(value).trim())
    ? Number(value) * (Number(value) < 1e12 ? 1000 : 1)
    : value;
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? "Not reported" : date.toLocaleString();
}

function renderYaraView(total = yaraSamples.length) {
  const s = yaraStatus || {}, managed = s.managed || {};
  const ready = !!s.available && Number(s.loaded || 0) > 0 && !(s.errors || []).length;
  $("yaraNotice").className = "v-note " + (ready ? "" : "warn");
  $("yaraNotice").innerHTML = ready
    ? '<i class="fa-solid fa-circle-check"></i> YARA engine ready — managed rules are loaded and available for captured-file analysis.'
    : '<i class="fa-solid fa-triangle-exclamation"></i> YARA is not fully ready. Check the engine and package details below.';
  $("yaraKpis").innerHTML = [
    ["Engine", s.available ? "Available" : "Unavailable", s.available ? "yara-python detected" : "Install or repair yara-python"],
    ["Rule files loaded", Number(s.loaded || 0).toLocaleString(), Number(s.files || 0) + " rule files found"],
    ["Detection rules", Number(managed.rule_count || 0).toLocaleString(), managed.package || "Managed rules"],
    ["Captured files", Number(total || 0).toLocaleString(), "available for review"]
  ].map(([label,value,note]) => `<div class="kpi"><span class="k-lbl">${label}</span><span class="k-num">${value}</span><span class="k-sub">${esc(note)}</span></div>`).join("");
  $("yaraPackage").innerHTML = `
    <div class="pot-hash-summary"><b>${esc(managed.package || "YARA Forge Core")}</b><br>
      Version: <b>${esc(managed.version || "Not reported")}</b><br>
      Status: <b>${esc(managed.status || "Unknown")}</b><br>
      Managed files: ${Number(s.managed_files || 0)} · Custom files: ${Number(s.custom_files || 0)}<br>
      Loaded groups: ${Number(s.groups || 0)}<br>
      Updated: ${esc(formatYaraPackageDate(managed.updated_at))}<br>
      Last checked: ${esc(formatYaraPackageDate(managed.checked_at))}
    </div>
    ${managed.last_error ? `<div class="v-note warn">${esc(managed.last_error)}</div>` : ""}
    ${(s.errors || []).length ? `<ul class="pot-notes">${s.errors.map(e => `<li>${esc(e)}</li>`).join("")}</ul>` : '<div class="muted">No YARA loading errors reported.</div>'}
    <p class="muted">Managed Forge Core updates are handled by the weekly systemd updater.</p>`;
  $("yaraFilesMeta").textContent = `Showing ${yaraSamples.length} of ${Number(total || 0)} captured files`;
  const rows = yaraSamples || [];
  $("yaraResults").innerHTML = rows.length ? `<div class="pot-hash-list">${rows.map(({row,detail}) => {
    const y = detail.yara || {};
    const matches = y.matches || [];
    const name = (detail.names || []).join(", ") || row.name || row.sha256;
    const hasMatch = matches.length > 0;
    return `<details class="pot-hash-row yara-result-row">
      <summary class="pot-hash-main">
        <b>${esc(name)}</b>
        <span class="muted mono">${esc(row.sha256)}</span>
        <span class="muted">${esc(row.kind || row.type || "file")} · ${Number(row.size || 0).toLocaleString()} bytes · score ${Number(row.score || 0)}/100</span>
        <span class="pot-hash-meta">${hasMatch ? `<span class="tagchip bad">${matches.length} YARA match${matches.length === 1 ? "" : "es"}</span>` :
          y.scan_status === "complete" ? '<span class="tagchip">Scanned · no match</span>' :
          y.scan_status === "partial" ? '<span class="tagchip warn">Partial scan</span>' :
          y.scan_status === "no_rules" ? '<span class="tagchip">No rules loaded</span>' :
          y.scan_status === "unavailable" ? '<span class="tagchip warn">Engine unavailable</span>' : '<span class="tagchip">Scan pending</span>'}</span>
      </summary>
      <div class="yara-result-detail">
        <div><b>SHA-256</b><div class="mono">${esc(row.sha256)}</div></div>
        <div><b>File</b><div>${esc(name)}</div></div>
        <div><b>Type and size</b><div>${esc(row.kind || row.type || "file")} · ${Number(row.size || 0).toLocaleString()} bytes</div></div>
        <div><b>Honeypot score</b><div>${Number(row.score || 0)}/100</div></div>
        <div><b>YARA scan status</b><div>${esc(y.scan_status || "pending")}${y.scanned_at ? " · " + esc(full(y.scanned_at)) : ""}</div></div>
        <div><b>YARA rule files scanned</b><div>${Number(y.files || 0).toLocaleString()}</div></div>
        <div><b>YARA matches</b><div>${hasMatch ? matches.map(m => `<div class="yara-rule-detail"><b class="mono">${esc(m.rule)}</b><div>${esc(m.file || "Rule file")}${(m.tags || []).length ? " · Tags: " + esc(m.tags.join(", ")) : ""}</div>${m.description ? `<p>${esc(m.description)}</p>` : ""}</div>`).join("") : "No matching rules were reported for this file."}</div></div>
      </div>
    </details>`;
  }).join("")}</div>` : '<div class="muted">No captured files yet. Files dropped during honeypot sessions will appear here after LanPulse records them.</div>';
}

document.addEventListener("click", (e) => {
  if (e.target.closest("#yaraRefresh")) loadYaraView();
  if (e.target.closest("#yaraArtifacts")) {
    if (typeof setPotSection === "function") setPotSection("artifacts");
  }
});

