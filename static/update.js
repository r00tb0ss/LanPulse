// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 The LanPulse authors
"use strict";
/* Settings > Update: upload a LanPulse release (.zip), check it, install it, follow progress. */

let updPoll = null;
let updTarget = "";

function updOpen() { return !$("settings").classList.contains("hidden") && setTab === "update"; }

async function renderUpdate(body) {
  clearInterval(updPoll);
  body.innerHTML = `<div class="loading-line"><i class="fa-solid fa-spinner fa-spin"></i>Checking…</div>`;
  const u = await api("/api/update", "GET");
  if (!updOpen()) return;
  if (!u) { body.innerHTML = `<p class="hint">Updates aren't available here.</p>`; return; }
  drawUpdate(body, u);
  if (u.state === "installing" || u.state === "queued") startUpdatePoll(body);
}

function drawUpdate(body, u, staged = u.staged, note = "") {
  const busy = u.state === "installing" || u.state === "queued";
  const blocked = !u.updater ? "updater" : !u.login ? "login" : "";
  const recentDone = u.state === "done" && Date.now() / 1000 - (u.state_t || 0) < 600;
  const kind = staged ? (staged.kind || (verCmp(staged.version, u.current) > 0 ? "newer" : verCmp(staged.version, u.current) < 0 ? "older" : "same")) : "";
  body.innerHTML = `
    <div class="upd-head"><i class="fa-solid fa-wave-square"></i><div><b>LanPulse v${esc(u.current)}</b>
      <span>is running on this server</span></div></div>
    ${blocked === "updater" ? `<div class="upd-note warn"><i class="fa-solid fa-circle-info"></i><div>
      <b>One more terminal install first.</b> The updater ships with this version, so install it once from the Ubuntu box:
      <code>unzip -o lanpulse.zip -d ~ &amp;&amp; cd ~/lanpulse &amp;&amp; sudo ./install.sh</code>
      After that, updates work from here.</div></div>` : ""}
    ${blocked === "login" ? `<div class="upd-note warn"><i class="fa-solid fa-lock"></i><div>
      <b>Set a login first.</b> An update runs with administrator rights, so LanPulse only allows it when the dashboard is
      password protected. <button class="linkbtn" id="updToLogin">Go to Login</button></div></div>` : ""}
    ${busy ? `<div class="upd-note busy"><i class="fa-solid fa-spinner fa-spin"></i><div><b>${esc(u.message || "Installing…")}</b>
      <span>The dashboard will disconnect while LanPulse restarts, then reload by itself.</span>
      <div class="btns" style="margin-top:8px"><button class="btn sm" onclick="location.reload()"><i class="fa-solid fa-rotate"></i>Reload page</button></div></div></div>` : ""}
    ${u.state === "failed" ? `<div class="upd-note bad"><i class="fa-solid fa-triangle-exclamation"></i><div><b>${esc(u.message)}</b></div></div>` : ""}
    ${recentDone ? `<div class="upd-note ok"><i class="fa-solid fa-circle-check"></i><div><b>${esc(u.message)}</b>
      <span>You're on v${esc(u.current)}.</span></div></div>` : ""}
    ${note ? `<div class="upd-note bad"><i class="fa-solid fa-triangle-exclamation"></i><div>${esc(note)}</div></div>` : ""}
    ${staged && !busy ? `<div class="upd-staged">
        <div><span class="muted">Ready to install</span><b>v${esc(staged.version)}</b>
          <span class="upd-kind ${kind}">${kind === "newer" ? "newer" : kind === "older" ? "older than yours" : "same version (reinstall)"}</span></div>
        <div class="btns"><button class="btn" id="updDiscard">Remove</button>
          <button class="btn primary" id="updApply" ${blocked ? "disabled" : ""}><i class="fa-solid fa-download"></i>Install v${esc(staged.version)}</button></div>
      </div>` : ""}
    ${!busy ? `<label class="upd-drop ${blocked ? "off" : ""}" id="updDrop">
        <input type="file" id="updFile" accept=".zip,application/zip" ${blocked ? "disabled" : ""}>
        <i class="fa-solid fa-file-zipper"></i>
        <b>${staged ? "Choose a different file" : "Choose the update file"}</b>
        <span>the <code>lanpulse.zip</code> you were given, or drop it here</span>
      </label>
      <p class="hint" style="margin-top:10px">Your devices, history, settings and login are kept. The current version is backed up first,
        and if anything goes wrong it's restored automatically. Only install files from a source you trust.</p>` : ""}
    ${u.log ? `<details class="upd-log" ${busy || u.state === "failed" ? "open" : ""}><summary>Update log</summary><pre>${esc(u.log)}</pre></details>` : ""}`;

  $("updToLogin")?.addEventListener("click", () => { setTab = "account"; renderSettings(); });
  $("updDiscard")?.addEventListener("click", async () => { const r = await api("/api/update/discard", "POST"); if (r) drawUpdate(body, r, null); });
  $("updApply")?.addEventListener("click", async (e) => {
    if (!confirm(`Install LanPulse v${staged.version}? The dashboard will restart.`)) return;
    e.currentTarget.disabled = true;
    updTarget = staged.version !== u.current ? staged.version : "";
    const r = await api("/api/update/apply", "POST");
    if (r) { drawUpdate(body, r); startUpdatePoll(body); }
  });
  const file = $("updFile"), drop = $("updDrop");
  if (file) file.addEventListener("change", () => file.files[0] && uploadUpdate(body, u, file.files[0]));
  if (drop && !blocked) {
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); const f = e.dataTransfer.files[0]; if (f) uploadUpdate(body, u, f); });
  }
}

async function uploadUpdate(body, u, f) {
  const drop = $("updDrop");
  if (drop) drop.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i><b>Uploading and checking ${esc(f.name)}…</b>`;
  try {
    const r = await fetch("/api/update/upload", {method: "POST", body: f, headers: {"Content-Type": "application/zip"}});
    if (r.status === 401) { location.href = "/login"; return; }
    const j = await r.json().catch(() => ({error: `Upload failed (${r.status})`}));
    if (!updOpen()) return;
    if (!r.ok) { drawUpdate(body, u, u.staged, j.error || "Upload failed."); return; }
    drawUpdate(body, {...u, state: "", message: ""}, j);
  } catch (_) {
    drawUpdate(body, u, u.staged, "Couldn't upload the file. Check your connection and try again.");
  }
}

function startUpdatePoll(body) {
  clearInterval(updPoll);
  let misses = 0, finishedSeen = 0;
  const startVersion = (typeof meta !== "undefined" && meta.version) || "";
  updPoll = setInterval(async () => {
    let u = null;
    try { const r = await fetch("/api/update"); if (r.ok) u = await r.json(); } catch (_) {}
    if (!u) {                                  // LanPulse is restarting
      misses++;
      const b = document.querySelector(".upd-note.busy b");
      if (b) b.textContent = "LanPulse is restarting…";
      if (misses > 300) clearInterval(updPoll);
      return;
    }
    if (u.state === "done" || (updTarget && u.current === updTarget)) {
      clearInterval(updPoll);
      toast(`Updated to v${u.current}. Reloading…`);
      setTimeout(() => location.reload(), 1500);
      return;
    }
    if (u.state === "failed") { clearInterval(updPoll); if (updOpen()) drawUpdate(body, u); return; }
    if (updOpen()) {
      const pre = document.querySelector(".upd-log pre");
      if (pre && u.log) { pre.textContent = u.log; pre.scrollTop = pre.scrollHeight; }
    }
    // The installer printed its last line: it's done even if the status file hasn't caught up.
    if (u.state === "installing" && /LanPulse is running\./.test(u.log || "")) {
      finishedSeen = finishedSeen || Date.now();
      if (Date.now() - finishedSeen > 15000 || u.current !== startVersion) {
        clearInterval(updPoll);
        toast(`Update finished (v${u.current}). Reloading…`);
        setTimeout(() => location.reload(), 1500);
      }
    }
  }, 2000);
}

function verCmp(a, b) {
  const p = (v) => String(v || "0").split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const x = p(a), y = p(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0) ? 1 : -1;
  return 0;
}

// Shown when the server was updated (from here or the terminal) while this page was open.
function showUpdatedBar(version) {
  if ($("updatedBar") || updPoll) return;
  const bar = document.createElement("div");
  bar.id = "updatedBar";
  bar.className = "updated-bar";
  bar.innerHTML = `<i class="fa-solid fa-circle-arrow-up"></i><span>LanPulse was updated to v${esc(version)}.</span>
    <button class="btn sm primary">Reload</button>`;
  bar.querySelector("button").onclick = () => location.reload();
  document.body.appendChild(bar);
}
