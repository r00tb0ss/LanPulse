# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Network security posture: a single 0-100 score and an A-F grade for the whole network, rolled up from everything
LanPulse already knows (compromised devices, vulnerabilities, exposed services, end-of-life OS, default credentials,
cleartext protocols, untrusted devices, whether a login is set). A daily history is kept so you can see it improve
as you fix things. The score is a prioritisation aid, not a certification.
"""
from __future__ import annotations

import sqlite3
import threading
import time

# (key, points each, cap for this category, label)
WEIGHTS = {
    "compromised": (30, 60, "device talking to a known botnet C2"),
    "confirmed": (20, 50, "flaw confirmed by an active check"),
    "kev": (12, 48, "actively exploited vulnerability"),
    "exploit": (6, 30, "vulnerability with a public exploit"),
    "eol_os": (10, 30, "end-of-life operating system"),
    "default_cred": (4, 20, "service with likely default credentials"),
    "cleartext": (2, 16, "service sending credentials in the clear"),
    "risky_port": (3, 18, "risky exposed service (telnet, RDP, VNC, SMB)"),
    "untrusted": (3, 15, "untrusted device online"),
    "no_login": (10, 10, "dashboard has no login set"),
}
RISKY = {23, 3389, 5900, 5901, 445, 139, 512, 513, 514, 1524}


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def compute(nm) -> dict:
    """Score the current state. Returns the score, grade, per-category breakdown and the top things to fix."""
    import redteam, vulns
    results = getattr(nm.vulns, "results", {}) or {}
    try:
        comp = nm.flows.summary(24).get("compromised", [])
    except Exception:
        comp = []
    counts = {k: 0 for k in WEIGHTS}
    findings = []            # (category, points, text) for the fix-list
    devs = [d for d in nm.devices.values() if not d.get("is_self")]

    comp_ips = {c["ip"] for c in comp}
    for c in comp:
        counts["compromised"] += 1
        findings.append(("compromised", WEIGHTS["compromised"][0],
                         f"{c['name']} is connecting to a known botnet C2 — likely compromised"))

    for d in devs:
        dv = results.get(d["id"], [])
        confirmed = sum(1 for f in dv if f.get("confidence") == "confirmed")
        if confirmed:
            counts["confirmed"] += 1
            findings.append(("confirmed", WEIGHTS["confirmed"][0],
                             f"{nm.label(d)} has {confirmed} flaw{'s' if confirmed > 1 else ''} confirmed by an active check"))
        kev = sum(1 for f in dv if f.get("kev"))
        msf = sum(1 for f in dv if f.get("msf") and not f.get("kev"))
        if kev:
            counts["kev"] += 1
            findings.append(("kev", WEIGHTS["kev"][0], f"{nm.label(d)} runs software with an actively exploited flaw ({kev} CVE{'s' if kev > 1 else ''})"))
        elif msf:
            counts["exploit"] += 1
            findings.append(("exploit", WEIGHTS["exploit"][0], f"{nm.label(d)} has {msf} vulnerabilit{'ies' if msf > 1 else 'y'} with a public exploit"))
        if vulns.windows_version(d):
            counts["eol_os"] += 1
            findings.append(("eol_os", WEIGHTS["eol_os"][0], f"{nm.label(d)} runs an end-of-life Windows"))
        dc = redteam.default_cred_services(d)
        if dc:
            counts["default_cred"] += 1
            findings.append(("default_cred", WEIGHTS["default_cred"][0], f"{nm.label(d)} exposes {dc[0]['service']} (often ships with a default login)"))
        ct = redteam.cleartext_exposures(d)
        if ct:
            counts["cleartext"] += 1
            findings.append(("cleartext", WEIGHTS["cleartext"][0], f"{nm.label(d)} runs {ct[0]['proto']} (sends data unencrypted)"))
        if any(p.get("port") in RISKY for p in d.get("ports", [])):
            counts["risky_port"] += 1
        if d.get("online") and not d.get("trusted") and d["ip"] not in comp_ips:
            counts["untrusted"] += 1

    if not nm.auth.enabled:
        counts["no_login"] = 1
        findings.append(("no_login", WEIGHTS["no_login"][0], "The dashboard has no login — anyone on your network can open it"))

    breakdown, deduction = [], 0
    for key, (pts, cap, label) in WEIGHTS.items():
        lost = min(cap, counts[key] * pts)
        if lost:
            breakdown.append({"key": key, "label": label, "count": counts[key], "points": lost})
            deduction += lost
    score = max(0, 100 - deduction)
    breakdown.sort(key=lambda b: -b["points"])
    # worst-costing fixes first, de-duplicated by text
    seen, fixes = set(), []
    for cat, pts, text in sorted(findings, key=lambda f: -f[1]):
        if text not in seen:
            seen.add(text)
            fixes.append({"category": cat, "points": pts, "text": text})
    return {"score": score, "grade": grade(score), "breakdown": breakdown, "fixes": fixes[:8],
            "devices": len(devs), "t": time.time()}


class PostureHistory:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS posture (day TEXT PRIMARY KEY, score INT, grade TEXT, t REAL)")
        self.db.commit()
        self.lock = threading.Lock()

    _last = (None, None)      # (day, score) last written, to avoid rewriting the same row repeatedly (SD-card friendly)

    def record(self, score: int, grade: str):
        day = time.strftime("%Y-%m-%d")
        if self._last == (day, score):
            return
        self._last = (day, score)
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO posture VALUES (?,?,?,?)", (day, score, grade, time.time()))
            self.db.execute("DELETE FROM posture WHERE day < ?", (time.strftime("%Y-%m-%d", time.localtime(time.time() - 365 * 86400)),))
            self.db.commit()

    def history(self, days: int = 30) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT day, score, grade FROM posture ORDER BY day DESC LIMIT ?", (max(1, min(days, 365)),)).fetchall()
        return [{"day": d, "score": s, "grade": g} for d, s, g in reversed(rows)]
