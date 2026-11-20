// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";

/* YARA summary-first view. Full static details and fresh scans load only when a sample is opened. */
let yaraStatus = null;
let yaraSamples = [];
const yaraDetailCache = new Map();

async function loadYaraView() {
  const notice = $("yaraNotice");
  if (notice) notice.textContent = "Checking YARA engine and stored scan summaries…";
  const [status, samples] = await Promise.all([
    api("/api/honeypot/yara/status", "GET"),
    api("/api/honeypot/samples?limit=200", "GET")
  ]);
  if (view !== "honeypot" || potSection !== "yara") return;
  yaraStatus = status || {};
  yaraSamples = (samples && samples.samples) || [];
  renderYaraView(samples && samples.total || yaraSamples.length);
}

function formatYaraPackageDate(value) {
  if (value === null || value === undefined || value === "") return "Not reported";
  const raw = typeof value === "number" || /^\d+(?:\.\d+)?$/.test(String(value).trim())
    ? Number(value) * (Number(value) < 1e12 ? 1000 : 1) : value;
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? "Not reported" : date.toLocaleString();
}

function yaraStatusLabel(status, count) {
  if (count > 0) return "match";
  return ({complete:"no-match",partial:"partial",no_rules:"no-rules",unavailable:"unavailable",pending:"pending"})[status] || "pending";
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
  ].map(([label,value,note]) => \`<div class="kpi"><span class="k-lbl">\${label}</span><span class="k-num">\${value}</span><span class="k-sub">\${esc(note)}</span></div>\`).join("");
  $("yaraPackage").innerHTML = \`
    <div class="pot-hash-summary"><b>\${esc(managed.package || "YARA Forge Core")}</b><br>
      Version: <b>\${esc(managed.version || "Not reported")}</b><br>
      Status: <b>\${esc(managed.status || "Unknown")}</b><br>
      Managed files: \${Number(s.managed_files || 0)} · Custom files: \${Number(s.custom_files || 0)}<br>
      Loaded groups: \${Number(s.groups || 0)}<br>
      Updated: \${esc(formatYaraPackageDate(managed.updated_at))}<br>
      Last checked: \${esc(formatYaraPackageDate(managed.checked_at))}
    </div>
    \${managed.last_error ? \`<div class="v-note warn">\${esc(managed.last_error)}</div>\` : ""}
    \${(s.errors || []).length ? \`<ul class="pot-notes">\${s.errors.map(e => \`<li>\${esc(e)}</li>\`).join("")}</ul>\` : '<div class="muted">No YARA loading errors reported.</div>'}
    <p class="muted">Managed Forge Core updates are handled by the weekly systemd updater.</p>\`;
  $("yaraFilesMeta").textContent = \`Showing \${yaraSamples.length} of \${Number(total || 0)} captured files · details load when opened\`;
  const controls = \`
    <div class="yara-filters">
      <input id="yaraSearch" type="search" placeholder="Search hash, family, tag, or file type" aria-label="Search YARA results">
      <select id="yaraFilter" aria-label="Filter YARA scan status">
        <option value="all">All scan results</option><option value="match">Matches</option>
        <option value="no-match">Scanned · no match</option><option value="partial">Partial scans</option>
        <option value="pending">Pending scans</option><option value="unavailable">Unavailable</option><option value="no-rules">No rules loaded</option>
      </select>
      <select id="yaraScoreFilter" aria-label="Filter honeypot score">
        <option value="0">All scores</option><option value="25">Score 25+</option>
        <option value="50">Score 50+</option><option value="75">Score 75+</option>
      </select>
    </div><div id="yaraResultRows"></div>\`;
  $("yaraResults").innerHTML = controls;
  renderYaraRows();
  $("yaraSearch").addEventListener("input", renderYaraRows);
  $("yaraFilter").addEventListener("change", renderYaraRows);
  $("yaraScoreFilter").addEventListener("change", renderYaraRows);
}

function renderYaraRows() {
  const host = $("yaraResultRows");
  if (!host) return;
  const query = ($("yaraSearch")?.value || "").trim().toLowerCase();
  const statusFilter = $("yaraFilter")?.value || "all";
  const minScore = Number($("yaraScoreFilter")?.value || 0);
  const filtered = yaraSamples.filter(row => {
    const status = yaraStatusLabel(row.yara_status, Number(row.yara_match_count || 0));
    const haystack = [row.sha256,row.kind,row.type,...(row.families || []),...(row.tags || [])].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) && (statusFilter === "all" || status === statusFilter) &&
      Number(row.score || 0) >= minScore;
  });
  host.innerHTML = filtered.length ? \`<div class="pot-hash-list">\${filtered.map(row => {
    const count = Number(row.yara_match_count || 0), status = yaraStatusLabel(row.yara_status, count);
    const badge = count ? \`<span class="tagchip bad">\${count} YARA match\${count === 1 ? "" : "es"}</span>\` :
      status === "no-match" ? '<span class="tagchip">Scanned · no match</span>' :
      status === "partial" ? '<span class="tagchip warn">Partial scan</span>' :
      status === "no-rules" ? '<span class="tagchip">No rules loaded</span>' :
      status === "unavailable" ? '<span class="tagchip warn">Engine unavailable</span>' : '<span class="tagchip">Scan pending</span>';
    const cached = yaraDetailCache.get(row.sha256);
    const title = cached ? ((cached.names || []).join(", ") || row.sha256) : row.sha256;
    return \`<details class="pot-hash-row yara-result-row" data-yara-sha="\${esc(row.sha256)}">
      <summary class="pot-hash-main">
        <b>\${esc(title)}</b><span class="muted mono">\${esc(row.sha256)}</span>
        <span class="muted">\${esc(row.kind || row.type || "file")} · \${Number(row.size || 0).toLocaleString()} bytes · score \${Number(row.score || 0)}/100</span>
        <span class="pot-hash-meta">\${badge}</span>
      </summary><div class="yara-result-detail">\${cached ? yaraDetailMarkup(row,cached) : '<span class="muted">Open to load full static analysis and YARA rule evidence…</span>'}</div>
    </details>\`;
  }).join("")}</div>\` : '<div class="muted">No captured files match these filters.</div>';
  host.querySelectorAll("details[data-yara-sha]").forEach(details => details.addEventListener("toggle", async () => {
    if (!details.open || details.dataset.loaded === "1") return;
    details.dataset.loaded = "1";
    const sha = details.dataset.yaraSha;
    const body = details.querySelector(".yara-result-detail");
    body.innerHTML = '<span class="muted">Loading sample details and checking stored YARA results…</span>';
    let detail = yaraDetailCache.get(sha);
    if (!detail) {
      detail = await api("/api/honeypot/sample?sha=" + encodeURIComponent(sha), "GET");
      if (!detail) {
        details.dataset.loaded = "0";
        body.innerHTML = '<span class="muted">Could not load details. Close and reopen to retry.</span>';
        return;
      }
      yaraDetailCache.set(sha, detail);
    }
    const row = yaraSamples.find(item => item.sha256 === sha);
    body.innerHTML = row ? yaraDetailMarkup(row,detail) : '<span class="muted">Sample summary is no longer available.</span>';
    const summaryName = details.querySelector("summary b");
    if (summaryName) summaryName.textContent = (detail.names || []).join(", ") || sha;
  }));
}

function yaraDetailMarkup(row, detail) {
  const y = detail.yara || {}, matches = y.matches || [], hasMatch = matches.length > 0;
  return \`
    <div><b>SHA-256</b><div class="mono">\${esc(row.sha256)}</div></div>
    <div><b>File</b><div>\${esc((detail.names || []).join(", ") || row.sha256)}</div></div>
    <div><b>Type and size</b><div>\${esc(row.kind || row.type || "file")} · \${Number(row.size || 0).toLocaleString()} bytes</div></div>
    <div><b>Honeypot score</b><div>\${Number(row.score || 0)}/100</div></div>
    <div><b>Families and tags</b><div>\${esc([...(detail.families || row.families || []),...(detail.tags || row.tags || [])].join(", ") || "No family or tag labels")}</div></div>
    <div><b>YARA scan status</b><div>\${esc(y.scan_status || "pending")}\${y.scanned_at ? " · " + esc(full(y.scanned_at)) : ""}</div></div>
    <div><b>YARA rule files scanned</b><div>\${Number(y.files || 0).toLocaleString()}</div></div>
    <div><b>YARA matches</b><div>\${hasMatch ? matches.map(m => \`<div class="yara-rule-detail"><b class="mono">\${esc(m.rule)}</b><div>\${esc(m.file || "Rule file")}\${(m.tags || []).length ? " · Tags: " + esc(m.tags.join(", ")) : ""}</div>\${m.description ? \`<p>\${esc(m.description)}</p>\` : ""}</div>\`).join("") : "No matching rules were reported for this file."}</div></div>
    \${y.report_note ? \`<p class="muted">\${esc(y.report_note)}</p>\` : ""}\`;
}

document.addEventListener("click", (e) => {
  if (e.target.closest("#yaraRefresh")) { yaraDetailCache.clear(); loadYaraView(); }
  if (e.target.closest("#yaraArtifacts") && typeof setPotSection === "function") setPotSection("artifacts");
});
