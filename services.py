# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Services: an up/down board for the things you care about (Plex, Pi-hole, the router, your own servers).

Each check is an HTTP(S) request, a TCP connection or a ping, run on its own interval. Results are kept for
30 days in SQLite. After a check fails twice in a row the service counts as down and an alert goes out;
another goes out when it recovers, with how long it was down.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("lanpulse.services")
KEEP_DAYS = 30
FAIL_AFTER = 2


class _WebOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to other web pages (never ftp:// or anything else)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith(("http://", "https://")):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def run_check(c: dict) -> tuple[bool, float | None, str]:
    """Run one check now. Returns (ok, milliseconds, error text)."""
    t0 = time.perf_counter()
    ms = lambda: round((time.perf_counter() - t0) * 1000, 1)
    try:
        if c["type"] == "http":
            ctx = ssl.create_default_context()
            if not c.get("verify_tls"):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(c["target"], headers={"User-Agent": "LanPulse uptime check"})
            try:
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _WebOnlyRedirects)
                with opener.open(req, timeout=10) as r:
                    r.read(65536)
                    return True, ms(), ""
            except urllib.error.HTTPError as e:
                # 401/403 still prove the service is up and answering (it just wants a login)
                if e.code in (401, 403):
                    return True, ms(), ""
                return False, ms(), f"HTTP {e.code}"
        if c["type"] == "tcp":
            with socket.create_connection((c["target"].strip("[]"), int(c["port"])), timeout=5):
                return True, ms(), ""
        if c["type"] == "ping":
            host = c["target"].strip("[]")
            out = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=6)
            if out.returncode == 0:
                m = re.search(r"time[=<]([\d.]+)", out.stdout)
                return True, float(m.group(1)) if m else ms(), ""
            return False, None, "No reply"
        return False, None, "Unknown check type"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        return False, None, _short(reason)
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return False, None, _short(e)


def _short(e) -> str:
    text = str(getattr(e, "strerror", None) or e)
    if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in text:
        return "Timed out"
    if "refused" in text.lower():
        return "Connection refused"
    if "Name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
        return "Name not found"
    if "unreachable" in text.lower():
        return "Host unreachable"
    if "CERTIFICATE_VERIFY_FAILED" in text:
        return "Certificate not trusted"
    return text[:120]


class ServiceMonitor:
    def __init__(self, nm):
        self.nm = nm
        self.db = sqlite3.connect(str(Path(nm.data_dir) / ("demo-services.db" if nm.args.demo else "services.db")),
                                  check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS hist (t REAL, id TEXT, ok INT, ms REAL, err TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS hist_id ON hist (id, t)")
        self.db.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT, down REAL, up REAL, err TEXT)")
        self.db.commit()
        self.lock = threading.Lock()
        self.state: dict[str, dict] = {}
        self.running: set[str] = set()
        self.dirty = True

    @property
    def checks(self) -> list[dict]:
        return self.nm.settings.get("services", {}).get("checks", [])

    # ---- loop
    async def run(self):
        last_purge = 0.0
        while True:
            now = time.time()
            for c in list(self.checks):
                if not c.get("enabled", True) or c["id"] in self.running:
                    continue
                st = self.state.setdefault(c["id"], {"up": None, "fails": 0, "since": now, "last": 0, "ms": None, "err": ""})
                if now - st["last"] >= c.get("interval", 60):
                    st["last"] = now
                    self.running.add(c["id"])
                    asyncio.create_task(self._check(c))
            if now - last_purge > 3600:
                last_purge = now
                with self.lock:
                    self.db.execute("DELETE FROM hist WHERE t < ?", (now - KEEP_DAYS * 86400,))
                    self.db.execute("DELETE FROM incidents WHERE down < ?", (now - KEEP_DAYS * 86400,))
                    self.db.commit()
            if self.dirty:
                self.dirty = False
                try:
                    await self.nm.broadcast({"type": "services", **self.summary(brief=True)})
                except Exception:
                    log.exception("services broadcast failed")
            await asyncio.sleep(2)

    async def _check(self, c: dict):
        try:
            if self.nm.args.demo:
                ok, ms, err = self._demo_result(c)
            else:
                ok, ms, err = await asyncio.to_thread(run_check, c)
            self.record(c, ok, ms, err)
        finally:
            self.running.discard(c["id"])

    def record(self, c: dict, ok: bool, ms, err: str, t: float | None = None):
        t = t or time.time()
        with self.lock:
            self.db.execute("INSERT INTO hist VALUES (?,?,?,?,?)", (t, c["id"], int(ok), ms, err[:120]))
            self.db.commit()
        st = self.state.setdefault(c["id"], {"up": None, "fails": 0, "since": t, "last": t, "ms": None, "err": ""})
        st["ms"], st["err"] = ms, err
        if ok:
            was_down = st["up"] is False
            st["fails"] = 0
            if st["up"] is not True:
                if was_down:
                    took = t - st["since"]
                    with self.lock:
                        self.db.execute("UPDATE incidents SET up = ? WHERE id = ? AND up IS NULL", (t, c["id"]))
                        self.db.commit()
                    self.nm.notify_plain("services", c["id"], f"{c['name']} is back up",
                                         f"{c['name']} ({describe(c)}) is responding again after {duration(took)}.", 3)
                st["up"], st["since"] = True, t
                self.dirty = True
        else:
            st["fails"] += 1
            if st["fails"] >= FAIL_AFTER and st["up"] is not False:
                st["up"], st["since"] = False, t
                with self.lock:
                    self.db.execute("INSERT INTO incidents VALUES (?,?,?,?)", (c["id"], t, None, err[:120]))
                    self.db.commit()
                self.nm.notify_plain("services", c["id"], f"{c['name']} is down",
                                     f"{c['name']} ({describe(c)}) stopped responding: {err or 'no answer'}.", 4)
                self.dirty = True
        self.dirty = True

    # ---- views
    def summary(self, brief: bool = False) -> dict:
        now = time.time()
        out = []
        with self.lock:
            for c in self.checks:
                st = self.state.get(c["id"], {})
                row = {**c, "up": st.get("up"), "since": st.get("since"), "ms": st.get("ms"), "err": st.get("err", ""),
                       "fails": st.get("fails", 0)}
                if not brief:
                    for label, secs in (("up24", 86400), ("up7", 7 * 86400)):
                        n, good = self.db.execute("SELECT COUNT(*), SUM(ok) FROM hist WHERE id = ? AND t > ?",
                                                  (c["id"], now - secs)).fetchone()
                        row[label] = round(100 * (good or 0) / n, 2) if n else None
                    avg = self.db.execute("SELECT AVG(ms) FROM hist WHERE id = ? AND t > ? AND ok = 1",
                                          (c["id"], now - 86400)).fetchone()[0]
                    row["avg_ms"] = round(avg, 1) if avg is not None else None
                    # 48 half-hour buckets for the last 24 h: share of successful checks (None = no data)
                    bins = [None] * 48
                    for b, n, good in self.db.execute(
                            "SELECT CAST((? - t) / 1800 AS INT) AS b, COUNT(*), SUM(ok) FROM hist "
                            "WHERE id = ? AND t > ? GROUP BY b", (now, c["id"], now - 86400)):
                        if 0 <= b < 48:
                            bins[47 - b] = round((good or 0) / n, 3)
                    row["bars"] = bins
                    row["incidents"] = [{"down": d, "up": u, "err": e} for d, u, e in self.db.execute(
                        "SELECT down, up, err FROM incidents WHERE id = ? ORDER BY down DESC LIMIT 5", (c["id"],))]
                out.append(row)
        ups = sum(1 for r in out if r["up"] is True)
        downs = sum(1 for r in out if r["up"] is False)
        return {"checks": out, "up": ups, "down": downs, "total": len(out), "t": now}

    def history(self, cid: str, hours: int = 24) -> list:
        with self.lock:
            return [{"t": t, "ok": bool(ok), "ms": ms} for t, ok, ms in self.db.execute(
                "SELECT t, ok, ms FROM hist WHERE id = ? AND t > ? ORDER BY t", (cid, time.time() - hours * 3600))]

    def suggestions(self) -> list[dict]:
        """Checks worth adding, based on what the scanner found."""
        have = {(c["type"], c["target"], c.get("port", 0)) for c in self.checks}
        have_targets = {c["target"] for c in self.checks}
        out = []

        def add(name, kind, target, port=0, device=""):
            if (kind, target, port) not in have and not any(target in t for t in have_targets if kind == "http"):
                out.append({"name": name, "type": kind, "target": target, "port": port, "device": device})

        for d in self.nm.devices.values():
            if d.get("is_self"):
                continue
            ports = {p["port"]: p for p in d.get("ports", [])}
            label = self.nm.label(d)
            ip = d["ip"]
            if d.get("is_gateway"):
                add(f"{label} (router)", "ping", ip, device=d["id"])
            if 32400 in ports:
                add(f"Plex on {label}", "http", f"http://{ip}:32400/identity", device=d["id"])
            name = f"{d.get('hostname', '')} {d.get('name', '')} {label}".lower()
            if "pihole" in name or "pi.hole" in name or "pi-hole" in name:
                add(f"Pi-hole on {label}", "http", f"http://{ip}/admin/", device=d["id"])
                if 53 in ports:
                    add(f"Pi-hole DNS on {label}", "tcp", ip, 53, d["id"])
            for port, svc in ((8006, "Proxmox"), (5000, "DSM"), (5001, "DSM"), (3000, "Open WebUI"), (8080, "Open WebUI"),
                              (11434, "Ollama"), (8123, "Home Assistant"), (9000, "Portainer")):
                if port in ports and (svc.lower().split()[0] in (ports[port].get("product") or "").lower()
                                      or svc.lower().split()[0] in name or port in (8006, 11434, 8123)):
                    scheme = "https" if port in (8006, 5001) else "http"
                    add(f"{svc} on {label}", "http", f"{scheme}://{ip}:{port}/", device=d["id"])
        return out[:12]

    # ---- demo
    def _demo_result(self, c):
        import random
        if "flaky" in c["name"].lower():
            return (random.random() > 0.35, round(random.uniform(20, 90), 1), "Timed out")
        return (True, round(random.uniform(1, 40), 1), "")


def describe(c: dict) -> str:
    return f"{c['target']}:{c['port']}" if c["type"] == "tcp" else c["target"]


def duration(s: float) -> str:
    s = int(s)
    if s < 90:
        return f"{s} seconds"
    if s < 5400:
        return f"{round(s / 60)} minutes"
    if s < 172800:
        return f"{s / 3600:.1f} hours"
    return f"{s / 86400:.1f} days"
