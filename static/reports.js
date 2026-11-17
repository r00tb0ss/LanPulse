// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Reports: a menu on every tab for the print-ready HTML report (and PDF when the server can make one). */

let reportInfo = null, reportPop = null;
const REPORT_TABS = [
  ["network", "Network", ["executive", "network"]], ["threats", "Threats", ["threats"]], ["dns", "DNS", ["dns"]],
  ["vulns", "Vulnerabilities", ["vulns"]], ["services", "Services", ["services"]], ["redteam", "Red Team", ["redteam"]],
  ["honeypot", "Honeypot", ["honeypot", "honeypot-sessions", "honeypot-attackers", "honeypot-campaigns", "honeypot-malware", "honeypot-sensors"]],
];
const POT_KIND = {overview: "honeypot", activity: "honeypot", sessions: "honeypot-sessions", profiles: "honeypot-attackers",
  campaigns: "honeypot-campaigns", artifacts: "honeypot-malware", yara: "honeypot-malware", sensors: "honeypot-sensors"};
const REPORT_VIEWS = [["threatView", "threats", "tRange"], ["dnsView", "dns", "dnsRange"], ["vulnView", "vulns"], ["svcView", "services"],
  ["redView", "redteam"], ["potView", "honeypot", "potHours"]];

function reportCurrent() {
  for (const [id, tab] of REPORT_VIEWS) {
    const el = document.getElementById(id);
    if (el && !el.classList.contains("hidden")) {
      if (tab === "honeypot") {
        const on = document.querySelector("#potSectionTabs [data-pot-section].on");
        return {tab, kind: POT_KIND[on ? on.dataset.potSection : "overview"] || "honeypot"};
      }
      return {tab, kind: tab};
    }
  }
  return {tab: "network", kind: "network"};
}

function reportHours(tab) {
  const v = REPORT_VIEWS.find((x) => x[1] === tab);
  const sel = v && v[2] ? document.getElementById(v[2]) : null;
  return sel && sel.value ? Number(sel.value) : 168;
}

function reportUrl(kind, fmt, tab) {
  const meta = reportInfo && reportInfo.kinds[kind];
  return `/api/report/${kind}.${fmt}` + (meta && meta.hours ? `?hours=${reportHours(tab || (meta && meta.tab))}` : "");
}

function reportRow(kind) {
  const m = reportInfo.kinds[kind];
  if (!m) return "";
  return `<div class="r-row"><span>${esc(m.title)}</span><span class="r-acts">
    <a class="btn sm ghost" href="${reportUrl(kind, "html")}" target="_blank" rel="noopener" title="Open the report; use Print to save a PDF">View</a>
    ${reportInfo.pdf ? `<a class="btn sm ghost" href="${reportUrl(kind, "pdf")}" download title="Download as a PDF file">PDF</a>` : ""}</span></div>`;
}

function renderReportMenu() {
  const cur = reportCurrent(), title = (REPORT_TABS.find((t) => t[0] === cur.tab) || [])[1] || "this tab";
  return `<div class="q-title"><i class="fa-solid fa-file-lines"></i>Reports</div>
    <div class="r-sec">For this tab: ${esc(title)}</div>${reportRow(cur.kind)}
    ${cur.kind !== "executive" ? `<div class="r-sec">Everything at a glance</div>${reportRow("executive")}` : ""}
    <details class="r-all"><summary>All reports</summary>${REPORT_TABS.map(([, label, kinds]) =>
      `<div class="r-sec">${esc(label)}</div>${kinds.map(reportRow).join("")}`).join("")}</details>
    ${reportInfo.pdf ? "" : `<p class="q-note">PDF needs the reportlab package on the LanPulse box. Reports open as pages you can save as PDF from the print dialog.</p>`}
    <p class="q-note">Made from data LanPulse already holds. Nothing is scanned or run.</p>`;
}

async function toggleReportMenu() {
  if (!reportPop) return;
  if (!reportPop.classList.contains("hidden")) { reportPop.classList.add("hidden"); return; }
  if (!reportInfo) { reportInfo = await api("/api/report/info", "GET"); if (!reportInfo) return; }
  reportPop.innerHTML = renderReportMenu();
  reportPop.classList.remove("hidden");
}

(function initReports() {
  reportPop = document.createElement("div");
  reportPop.className = "q-pop r-pop hidden";
  reportPop.setAttribute("role", "dialog");
  reportPop.setAttribute("aria-label", "Reports");
  document.body.appendChild(reportPop);
  const top = document.getElementById("btnExport");
  if (top) {
    const b = document.createElement("button");
    b.className = "icon-btn"; b.id = "btnReports"; b.title = "Reports for every tab";
    b.setAttribute("aria-haspopup", "true");
    b.innerHTML = '<i class="fa-solid fa-file-lines"></i>';
    top.parentNode.insertBefore(b, top);
    b.addEventListener("click", (e) => { e.stopPropagation(); toggleReportMenu(); });
  }
  for (const [id, , sel] of REPORT_VIEWS) {
    const view = document.getElementById(id);
    if (!view || id === "redView") continue;
    const tools = view.querySelector(".v-tools") || (sel && document.getElementById(sel) && document.getElementById(sel).parentElement);
    if (!tools) continue;
    const b = document.createElement("button");
    b.className = "btn sm ghost"; b.type = "button"; b.title = "Reports for this tab";
    b.innerHTML = '<i class="fa-solid fa-file-lines"></i>Report';
    b.addEventListener("click", (e) => { e.stopPropagation(); toggleReportMenu(); });
    tools.appendChild(b);
  }
  document.addEventListener("click", (e) => { if (!reportPop.contains(e.target)) reportPop.classList.add("hidden"); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") reportPop.classList.add("hidden"); });
})();
