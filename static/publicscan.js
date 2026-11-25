/* Authorized public-target scanning (Nmap / OpenVAS). Lives on the "Public scan" sub-tab of Threats, separate from attacker investigation. */

let publicScanPoll = null;
async function refreshAuthorizedPublicScans() {
  const box = $("publicScanStatus");
  if (!box) { if (publicScanPoll) clearInterval(publicScanPoll); publicScanPoll = null; return; }
  const data = await api("/api/scans/authorized-public", "GET");
  if (!data) {
    box.innerHTML = '<div class="finding"><span>Could not refresh scan status. LanPulse will retry automatically.</span></div>';
    if (!publicScanPoll) publicScanPoll = setInterval(refreshAuthorizedPublicScans, 5000);
    return;
  }
  const rows = [...(data.nmap || []), ...(data.openvas || [])]
    .sort((a, b) => (b.started || 0) - (a.started || 0)).slice(0, 30);
  if (!rows.length) {
    box.textContent = "No authorized public scans yet.";
    if (publicScanPoll) clearInterval(publicScanPoll);
    publicScanPoll = null;
    return;
  }
  const active = rows.some((s) => ["Requested","Queued","Running","New"].includes(s.status));
  if (active && !publicScanPoll) publicScanPoll = setInterval(refreshAuthorizedPublicScans, 3000);
  if (!active && publicScanPoll) { clearInterval(publicScanPoll); publicScanPoll = null; }
  box.innerHTML = rows.map((s) => {
    const key = s.scanner === "nmap" ? s.id : (s.target || s.ip);
    const scanner = (s.scanner || "openvas").toUpperCase();
    const terminal = ["Done","Failed","Interrupted"].includes(s.status);
    const progress = Math.max(0, Math.min(100, Number(s.progress) || 0));
    const findings = s.scanner === "openvas" ? (s.count || 0) + " findings" :
      (s.host_state === "down" ? "target did not respond" : ((s.ports || []).length + " open TCP ports"));
    const error = s.error ? '<div style="color:var(--red);margin-top:6px;overflow-wrap:anywhere">' + esc(s.error) + '</div>' : "";
    const ports = (s.ports || []);
    const details = s.status === "Done" && s.scanner === "nmap"
      ? (ports.length
        ? '<div style="margin-top:8px"><b>Open ports and detected services</b><ul style="margin:5px 0 0;padding-left:19px">' +
          ports.map((p) => '<li><code>' + esc(p.port + "/" + p.protocol) + '</code> · ' + esc(p.service || "unknown service") +
            (p.product ? ' · ' + esc(p.product) : "") + (p.version ? ' ' + esc(p.version) : "") + '</li>').join("") +
          '</ul></div>'
        : (s.host_state === "down"
          ? '<div class="finding" style="margin-top:7px">Nmap could not confirm that the target was reachable. No port findings can be reported for this scan.</div>'
          : s.host_state === "up"
            ? '<div class="ok-line" style="margin-top:7px">Target responded. No open TCP ports were found in the top 1,000 scanned ports.</div>'
            : '<div class="finding" style="margin-top:7px">Scan finished, but target reachability was not confirmed. No open TCP ports were reported.</div>'))
      : s.status === "Done" && s.results?.length
        ? '<div class="muted" style="padding:7px 0">' + s.results.slice(0, 8).map((f) =>
            esc(f.name + " · severity " + f.severity + (f.cve?.length ? " · " + f.cve.join(", ") : ""))).join("<br>") + '</div>'
        : "";
    const phase = s.phase || (s.status === "Requested" || s.status === "Queued" ? "Waiting for the scan worker" :
      s.status === "Running" ? "Scanning target and identifying services" : "");
    const state = terminal ? esc(s.status) : esc(s.status || "Queued");
    const progressHtml = !terminal
      ? '<div style="height:6px;background:var(--line);border-radius:99px;overflow:hidden;margin:7px 0 5px">' +
        '<div style="height:100%;width:' + (progress || (s.status === "Requested" ? 4 : 8)) +
        '%;background:var(--accent);border-radius:99px;transition:width .3s"></div></div>' +
        '<div class="muted" style="font-size:11px">' + (progress ? progress + "% · " : "") + esc(phase) + '</div>'
      : "";
    const started = s.started ? new Date(s.started * 1000).toLocaleString() : "";
    return '<div style="padding:11px 0;border-top:1px solid var(--line)"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b>' +
      esc(s.target || s.ip || "Unknown target") + '</b><span class="badge">' + scanner + '</span>' + (terminal ? '<button class="btn sm ghost ps-del" data-scanner="' + esc(s.scanner || "openvas") +
      '" data-key="' + esc(key || "") + '" title="Delete this scan from history" aria-label="Delete this scan"><i class="fa-solid fa-trash"></i></button>' : "") + '</div>' +
      '<div class="muted" style="font-size:11px;margin:4px 0">' + state +
      (terminal && s.status === "Done" ? ' · ' + esc(findings) : "") + (started ? ' · ' + esc(started) : "") + '</div>' +
      progressHtml + (s.summary ? '<div class="muted" style="margin-top:6px">' + esc(s.summary) + '</div>' : "") +
      error + details + '</div>';
  }).join("");
}

(function initPublicScan() {
  if (!$("bPublicScan")) return;
  $("bPublicScan").onclick = async () => {
    const target = $("publicScanTarget").value.trim();
    const scanner = $("publicScanEngine").value;
    const authorized = $("publicScanAuthorized").checked;
    if (!authorized) { toast("Confirm ownership or explicit authorization first"); return; }
    const label = scanner === "nmap" ? "Nmap top-1,000-port scan" : "OpenVAS Full and Fast assessment";
    if (!window.confirm("Start " + label + " against " + target + "? This sends active scan traffic to that public IP. Only proceed if you are authorized to test it.")) return;
    const button = $("bPublicScan");
    button.disabled = true; button.textContent = "Starting scan…";
    const result = await api("/api/scans/authorized-public", "POST", {target, scanner, authorized: true});
    button.disabled = false; button.innerHTML = '<i class="fa-solid fa-radar"></i> Start authorized scan';
    if (result && result.ok) {
      toast(label + " started for " + target);
      $("publicScanStatus").textContent = "Scan accepted for " + target + ". Waiting for Nmap to start…";
      refreshAuthorizedPublicScans();
      if (!publicScanPoll) publicScanPoll = setInterval(refreshAuthorizedPublicScans, 3000);
    } else toast(result?.error || "The scan could not be started");
  };
  const pane = $("threatView");
  const showSub = (sub) => {
    const wasScan = pane.classList.contains("ps-mode");
    if (sub === "scan" && !wasScan) {
      // Same housekeeping as leaving the tab: a chart left in a hidden box comes back blank in some browsers.
      if (typeof mapIsFull === "function" && mapIsFull()) toggleMapFull(false);
      if (typeof tChart !== "undefined" && tChart) {
        try { pendingGeoView = geoView(); } catch (_) { pendingGeoView = null; }
        try { tChart.dispose(); } catch (_) {}
        tChart = null;
        $("worldMap").innerHTML = "";
      }
    }
    pane.classList.toggle("ps-mode", sub === "scan");
    document.querySelectorAll("#threatSubTabs [data-tsub]").forEach((b) => {
      b.classList.toggle("on", b.dataset.tsub === sub); b.setAttribute("aria-selected", String(b.dataset.tsub === sub));
    });
    if (sub === "scan") refreshAuthorizedPublicScans();
    else if (wasScan) setView("threats");          // rebuild the map exactly as when the Threats tab is opened
  };
  $("threatSubTabs").onclick = (e) => { const b = e.target.closest("[data-tsub]"); if (b) showSub(b.dataset.tsub); };
  const remove = async (payload, what) => {
    if (!window.confirm("Delete " + what + " from the public scan history? Running scans are never deleted.")) return;
    const r = await api("/api/scans/authorized-public/delete", "POST", payload);
    if (r && r.ok) { toast(r.removed + " scan" + (r.removed === 1 ? "" : "s") + " deleted"); refreshAuthorizedPublicScans(); }
    else toast(r?.error || "Could not delete");
  };
  $("publicScanStatus").addEventListener("click", (e) => {
    const b = e.target.closest(".ps-del"); if (!b) return;
    remove({items: [{scanner: b.dataset.scanner, key: b.dataset.key}]}, "this scan");
  });
  $("bPublicScanClear").onclick = () => remove({all_finished: true}, "all finished scans");
  const prev = viewHooks.threats;
  viewHooks.threats = () => { if (pane.classList.contains("ps-mode")) showSub("attacks"); if (prev) prev(); };   // opening Threats always starts on the map
})();
