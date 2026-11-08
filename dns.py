# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
DNS: what every device looks up, from your Pi-hole's query log.

Works with Pi-hole v6 (REST API: POST /api/auth, GET /api/queries) and falls back to the v5 api.php. Lookups are
stored as per-minute totals per (device, domain, blocked) for 7 days. Domains are checked against the abuse.ch
URLhaus malware host list (public domain, refreshed daily); a device looking one up raises an alert.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import re
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

log = logging.getLogger("lanpulse.dns")
KEEP_DAYS = 7
URLHAUS = "https://urlhaus.abuse.ch/downloads/hostfile/"
# Same URLhaus data, republished by the malware-filter project (CC0) with no key needed.
MALWARE_SOURCES = [("abuse.ch URLhaus", URLHAUS),
                   ("malware-filter (URLhaus mirror)", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"),
                   ("malware-filter mirror 2", "https://curbengh.github.io/malware-filter/urlhaus-filter-hosts.txt")]


def parse_host_list(text: str) -> set:
    """Domains from a hosts file ('127.0.0.1 bad.example') or a plain one-domain-per-line list."""
    hosts = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("<", "{", "!")):
            continue
        parts = line.split()
        d = clean_domain(parts[1] if len(parts) >= 2 else parts[0])
        if d and "." in d and not re.match(r"^\d+\.\d+\.\d+\.\d+$", d) and d not in ("localhost", "localhost.localdomain"):
            hosts.add(d)
    return hosts
_DOMAIN_OK = re.compile(r"^[a-z0-9_.-]{1,253}$")
# Pi-hole v5 numeric statuses that mean "blocked"
V5_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16}


def is_blocked_status(status) -> bool:
    if isinstance(status, int) or (isinstance(status, str) and status.isdigit()):
        return int(status) in V5_BLOCKED
    s = str(status or "").upper()
    return any(w in s for w in ("GRAVITY", "REGEX", "DENYLIST", "BLACKLIST", "BLOCKED", "SPECIAL_DOMAIN"))


def clean_name(v) -> str:
    """Client names come from devices themselves (via DHCP): drop control and invisible characters."""
    import unicodedata
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else "" if unicodedata.category(ch) in ("Cf", "Cs", "Co")
                else ch for ch in str(v or ""))
    return " ".join(s.split())[:80]


def clean_domain(d) -> str:
    d = str(d or "").strip().lower().rstrip(".")
    return d if _DOMAIN_OK.match(d) else ""


class PiHoleError(Exception):
    pass


class PiHole:
    """Minimal client for Pi-hole v6, with a v5 fallback."""

    def __init__(self, cfg: dict):
        self.url = (cfg.get("url") or "").rstrip("/")
        self.password = cfg.get("password") or ""
        self.ctx = ssl.create_default_context()
        if not cfg.get("verify_tls"):
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.sid = None
        self.version = None

    def _req(self, method: str, path: str, body: dict | None = None, timeout: int = 15):
        headers = {"Accept": "application/json", "User-Agent": "LanPulse"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.sid:
            headers["X-FTL-SID"] = self.sid
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                return r.status, json.loads(r.read(20_000_000) or b"{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read(65536) or b"{}")
            except ValueError:
                payload = {}
            return e.code, payload
        except urllib.error.URLError as e:
            raise PiHoleError(f"Can't reach Pi-hole at {self.url}: {getattr(e, 'reason', e)}")
        except ValueError:
            raise PiHoleError("Pi-hole answered with something that isn't JSON. Check the address.")

    def login(self):
        if not self.url:
            raise PiHoleError("Pi-hole address isn't set.")
        code, data = self._req("POST", "/api/auth", {"password": self.password})
        if code == 404:                         # no v6 API here: try Pi-hole v5
            self.version = 5
            return
        if code in (400, 401):
            raise PiHoleError("Pi-hole rejected the password. Use the web interface password or an app password "
                              "(Pi-hole Settings > Web interface / API > App password).")
        if code == 429:
            raise PiHoleError("Pi-hole is rate-limiting logins. Wait a minute and try again.")
        if code != 200:
            raise PiHoleError(f"Pi-hole login failed (HTTP {code}).")
        sess = data.get("session") or {}
        if not sess.get("valid"):
            raise PiHoleError("Pi-hole didn't accept the login.")
        self.sid = sess.get("sid")             # None when Pi-hole has no password
        self.version = 6

    def queries(self, since: float, until: float) -> list[dict]:
        """Lookups between two times, oldest first: {id, t, client, client_name, domain, blocked}."""
        if self.version is None:
            self.login()
        if self.version == 6:
            q = urllib.parse.urlencode({"from": int(since), "until": int(until) + 1, "length": 20000})
            code, data = self._req("GET", f"/api/queries?{q}", timeout=30)
            if code == 401:
                self.sid = None
                self.login()
                code, data = self._req("GET", f"/api/queries?{q}", timeout=30)
            if code != 200:
                raise PiHoleError(f"Pi-hole query log request failed (HTTP {code}).")
            out = []
            for x in data.get("queries", []):
                client = x.get("client") or {}
                out.append({"id": x.get("id"), "t": float(x.get("time") or 0), "client": str(client.get("ip") or ""),
                            "client_name": str(client.get("name") or ""), "domain": clean_domain(x.get("domain")),
                            "blocked": is_blocked_status(x.get("status"))})
            out.sort(key=lambda r: (r["t"], r["id"] or 0))
            return out
        # Pi-hole v5
        q = urllib.parse.urlencode({"getAllQueries": "", "from": int(since), "until": int(until) + 1,
                                    "auth": self.password})
        code, data = self._req("GET", f"/admin/api.php?{q}", timeout=30)
        if code != 200 or not isinstance(data, dict) or "data" not in data:
            raise PiHoleError("Pi-hole v5 didn't return its query log. Use the API token from "
                              "Settings > API / Web interface > Show API token as the password.")
        out = []
        for row in data["data"]:
            try:
                out.append({"id": None, "t": float(row[0]), "client": str(row[3]).split("|")[0], "client_name": "",
                            "domain": clean_domain(row[2]), "blocked": is_blocked_status(row[4])})
            except (IndexError, ValueError, TypeError):
                continue
        out.sort(key=lambda r: r["t"])
        return out

    def logout(self):
        if self.version == 6 and self.sid:
            try:
                self._req("DELETE", "/api/auth", timeout=5)
            except PiHoleError:
                pass
        self.sid = None


class DnsMonitor:
    POLL = 30

    def __init__(self, nm):
        self.nm = nm
        self.data_dir = Path(nm.data_dir)
        self.db = sqlite3.connect(str(self.data_dir / ("demo-dns.db" if nm.args.demo else "dns.db")), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS q (m INTEGER, client TEXT, domain TEXT, blocked INT, n INT,"
                        " PRIMARY KEY (m, client, domain, blocked)) WITHOUT ROWID")
        self.db.execute("CREATE INDEX IF NOT EXISTS q_client ON q (client, m)")
        self.db.execute("CREATE TABLE IF NOT EXISTS hits (t REAL, client TEXT, domain TEXT)")
        self.db.commit()
        self.lock = threading.Lock()
        self.client: PiHole | None = None
        self.cfg_sig = None
        self.last_t = 0.0
        self.last_id = -1
        self.names: dict[str, str] = {}
        self.recent: collections.deque = collections.deque(maxlen=120)
        self.status = {"state": "off", "error": "", "last_poll": 0, "version": None}
        self.malware: set[str] = set()
        self.malware_loaded = 0.0
        self.malware_status = {"source": "", "error": "", "t": 0}
        self.alerted: dict[str, float] = {}

    @property
    def cfg(self) -> dict:
        return self.nm.settings.get("dns", {})

    # ---- malware list (abuse.ch URLhaus, public domain)
    def _malware_path(self) -> Path:
        return self.data_dir / "urlhaus-hosts.txt"

    def refresh_malware(self, force: bool = False):
        """Load the malware domain list. Tries abuse.ch URLhaus first (with your Auth-Key if you set one), then the
        malware-filter project's mirror of the same URLhaus data, which needs no key. A download is only kept if it
        really contains domains, so an error page can't replace a good list."""
        p = self._malware_path()
        fresh = p.exists() and time.time() - p.stat().st_mtime < 86400 and self.malware
        if force or not fresh:
            errors = []
            key = (self.cfg.get("abuse_key") or "").strip()
            for name, url in MALWARE_SOURCES:
                headers = {"User-Agent": "LanPulse"}
                if key and name.startswith("abuse.ch"):
                    headers["Auth-Key"] = key
                try:
                    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                        data = r.read(40_000_000)
                    hosts = parse_host_list(data.decode("utf-8", "replace"))
                    if len(hosts) < 100:
                        errors.append(f"{name}: no domain list in the response")
                        continue
                    tmp = p.with_suffix(".tmp")
                    tmp.write_bytes(data)
                    tmp.replace(p)
                    self.malware, self.malware_loaded = hosts, p.stat().st_mtime
                    self.malware_status = {"source": name, "error": "", "t": time.time()}
                    log.info("Malware domain list: %d domains from %s", len(hosts), name)
                    return
                except urllib.error.HTTPError as e:
                    errors.append(f"{name}: HTTP {e.code}" + (" (needs an abuse.ch Auth-Key)" if e.code in (401, 403) and name.startswith("abuse.ch") else ""))
                except (OSError, urllib.error.URLError, ValueError) as e:
                    errors.append(f"{name}: {getattr(e, 'reason', e)}")
            self.malware_status = {"source": self.malware_status.get("source", ""), "error": "; ".join(errors)[:300], "t": time.time()}
            log.warning("Couldn't download a malware domain list: %s", self.malware_status["error"])
        # fall back to whatever good copy is on disk
        try:
            if not self.malware and p.exists():
                hosts = parse_host_list(p.read_text(errors="replace"))
                if len(hosts) >= 100:
                    self.malware, self.malware_loaded = hosts, p.stat().st_mtime
        except OSError:
            pass

    def is_malware(self, domain: str) -> bool:
        if not domain or not self.malware or not self.cfg.get("malware", True):
            return False
        parts = domain.split(".")
        return any(".".join(parts[i:]) in self.malware for i in range(len(parts) - 1))

    # ---- polling
    async def run(self):
        last_purge = last_list = 0.0
        while True:
            try:
                if self.nm.args.demo:
                    self._demo_tick()
                elif self.cfg.get("enabled") and self.cfg.get("url"):
                    if time.time() - last_list > (3600 if self.malware else 900):    # retry sooner while missing
                        last_list = time.time()
                        await asyncio.to_thread(self.refresh_malware)
                    rows = await asyncio.to_thread(self.fetch_new)
                    if rows:
                        self.ingest(rows)
                else:
                    self.status.update(state="off", error="")
                if time.time() - last_purge > 3600:
                    last_purge = time.time()
                    with self.lock:
                        cut = time.time() - KEEP_DAYS * 86400
                        self.db.execute("DELETE FROM q WHERE m < ?", (int(cut // 60),))
                        self.db.execute("DELETE FROM hits WHERE t < ?", (cut,))
                        self.db.commit()
            except Exception:
                log.exception("DNS poll failed")
            await asyncio.sleep(self.POLL)

    def fetch_new(self) -> list[dict]:
        sig = (self.cfg.get("url"), self.cfg.get("password"), self.cfg.get("verify_tls"))
        if sig != self.cfg_sig or self.client is None:
            if self.client:
                self.client.logout()
            self.client = PiHole(self.cfg)
            self.cfg_sig = sig
        now = time.time()
        since = self.last_t or now - 3600
        try:
            rows = self.client.queries(since, now)
        except PiHoleError as e:
            self.status.update(state="error", error=str(e), last_poll=now)
            self.client.sid = None
            self.client.version = None
            return []
        self.status.update(state="ok", error="", last_poll=now, version=self.client.version)
        return rows

    def ingest(self, rows: list[dict]):
        acc: dict[tuple, int] = collections.Counter()
        fresh = []
        for r in rows:
            if not r["domain"] or not r["client"]:
                continue
            if r["t"] < self.last_t or (r["t"] == self.last_t and r["id"] is not None and r["id"] <= self.last_id):
                continue
            if r["id"] is None and r["t"] <= self.last_t:
                continue
            acc[(int(r["t"] // 60), r["client"], r["domain"], int(r["blocked"]))] += 1
            if r["client_name"]:
                self.names[r["client"]] = clean_name(r["client_name"])
            bad = self.is_malware(r["domain"])
            ev = {"t": r["t"], "client": r["client"], "domain": r["domain"], "blocked": r["blocked"], "bad": bad}
            fresh.append(ev)
            if bad:
                self._malware_hit(ev)
        if rows:
            last = rows[-1]
            self.last_t = max(self.last_t, last["t"])
            if last["id"] is not None:
                self.last_id = max([r["id"] for r in rows if r["t"] == self.last_t and r["id"] is not None] or [-1])
        if acc:
            with self.lock:
                self.db.executemany("INSERT INTO q VALUES (?,?,?,?,?) ON CONFLICT(m, client, domain, blocked) "
                                    "DO UPDATE SET n = n + excluded.n", [(*k, n) for k, n in acc.items()])
                self.db.commit()
        for ev in fresh[-60:]:
            self.recent.appendleft(self.decorate(ev))
        if fresh:
            try:
                asyncio.get_running_loop().create_task(
                    self.nm.broadcast({"type": "dns", "items": [self.decorate(e) for e in fresh[-25:]]}))
            except RuntimeError:
                pass                # no event loop (tests)

    def _malware_hit(self, ev):
        with self.lock:
            self.db.execute("INSERT INTO hits VALUES (?,?,?)", (ev["t"], ev["client"], ev["domain"]))
            self.db.commit()
        key = f"{ev['client']}|{ev['domain']}"
        if time.time() - self.alerted.get(key, 0) < 86400:
            return
        self.alerted[key] = time.time()
        dev = self.device(ev["client"])
        msg = (f"{self.name(ev['client'])} looked up {ev['domain']}, which is on the abuse.ch URLhaus malware list"
               f"{' (Pi-hole blocked it)' if ev['blocked'] else ' and it was NOT blocked'}.")
        try:
            if dev:
                self.nm.notify("dns_threats", dev, f"Malware domain lookup: {self.nm.label(dev)}", msg, 5)
            else:
                self.nm.notify_plain("dns_threats", key, "Malware domain lookup", msg, 5)
        except RuntimeError:
            pass                    # no event loop (tests)

    # ---- helpers
    def device(self, ip: str):
        return next((d for d in list(self.nm.devices.values()) if d["ip"] == ip), None)      # a copy: summary() runs in a worker thread

    def name(self, ip: str) -> str:
        d = self.device(ip)
        return self.nm.label(d) if d else self.names.get(ip) or ip

    def decorate(self, e: dict) -> dict:
        d = self.device(e["client"])
        return {**e, "name": self.nm.label(d) if d else self.names.get(e["client"]) or e["client"],
                "id": d["id"] if d else "", "type": d["type"] if d else "unknown"}

    # ---- views
    def summary(self, hours: int = 24, device_ip: str = "") -> dict:
        m0 = int((time.time() - hours * 3600) // 60)
        w, a = ("m >= ? AND client = ?", (m0, device_ip)) if device_ip else ("m >= ?", (m0,))
        with self.lock:
            total, blocked = self.db.execute(f"SELECT SUM(n), SUM(n * blocked) FROM q WHERE {w}", a).fetchone()
            top = self.db.execute(f"SELECT domain, SUM(n) c, COUNT(DISTINCT client) FROM q WHERE {w} AND blocked = 0 "
                                  "GROUP BY domain ORDER BY c DESC LIMIT 15", a).fetchall()
            topb = self.db.execute(f"SELECT domain, SUM(n) c, COUNT(DISTINCT client) FROM q WHERE {w} AND blocked = 1 "
                                   "GROUP BY domain ORDER BY c DESC LIMIT 15", a).fetchall()
            clients = self.db.execute(f"SELECT client, SUM(n) c, SUM(n * blocked), COUNT(DISTINCT domain) FROM q WHERE {w} "
                                      "GROUP BY client ORDER BY c DESC LIMIT 15", a).fetchall()
            uniq = self.db.execute(f"SELECT COUNT(DISTINCT domain) FROM q WHERE {w}", a).fetchone()[0]
            hw, ha = ("t >= ? AND client = ?", (m0 * 60, device_ip)) if device_ip else ("t >= ?", (m0 * 60,))
            hits = self.db.execute(f"SELECT client, domain, COUNT(*), MAX(t) FROM hits WHERE {hw} "
                                   "GROUP BY client, domain ORDER BY MAX(t) DESC LIMIT 25", ha).fetchall()
            hist = self.db.execute(f"SELECT (m - ?) * 60 / ?, SUM(n), SUM(n * blocked) FROM q WHERE {w} GROUP BY 1",
                                   (m0, hours * 3600 // 48 or 1, *a)).fetchall()
        bins = [[0, 0] for _ in range(48)]
        for b, n, nb in hist:
            if 0 <= int(b) < 48:
                bins[int(b)] = [n or 0, nb or 0]
        gw = self.nm.net.get("gateway")
        total = total or 0
        router_only = bool(not device_ip and clients and clients[0][0] == gw and clients[0][1] > 0.7 * total and total > 100)
        recent = [e for e in list(self.recent) if not device_ip or e["client"] == device_ip][:40]      # the poller adds to it meanwhile
        return {
            "type": "dns_summary", "hours": hours, "device": device_ip,
            "enabled": bool(self.cfg.get("enabled")) or self.nm.args.demo, "status": self.status,
            "total": total, "blocked": blocked or 0, "domains": uniq or 0,
            "top": [{"domain": d, "count": c, "clients": u, "bad": self.is_malware(d)} for d, c, u in top],
            "top_blocked": [{"domain": d, "count": c, "clients": u} for d, c, u in topb],
            "clients": [{"ip": ip, "name": self.name(ip), "id": (self.device(ip) or {}).get("id", ""),
                         "type": (self.device(ip) or {}).get("type", "unknown"), "count": c, "blocked": b or 0, "domains": u}
                        for ip, c, b, u in clients],
            "malware": [{"ip": ip, "name": self.name(ip), "id": (self.device(ip) or {}).get("id", ""), "domain": d,
                         "count": n, "last": lt} for ip, d, n, lt in hits],
            "malware_list": len(self.malware), "malware_status": self.malware_status, "hist": bins, "recent": recent, "router_only": router_only,
        }

    def test(self, cfg: dict) -> dict:
        c = PiHole(cfg)
        try:
            rows = c.queries(time.time() - 600, time.time())
            return {"ok": True, "version": c.version, "recent": len(rows)}
        except PiHoleError as e:
            return {"ok": False, "error": str(e)}
        finally:
            c.logout()

    # ---- demo
    def _demo_tick(self):
        import random
        self.status.update(state="ok", error="", last_poll=time.time(), version=6)
        if not self.malware:
            self.malware = {"evil-update.example", "c2.badhost.example"}
        devs = [d for d in self.nm.devices.values() if d.get("online")]
        if not devs:
            return
        common = ["www.google.com", "api.apple.com", "netflix.com", "graph.microsoft.com", "time.cloudflare.com",
                  "youtube.com", "spclient.wg.spotify.com", "connectivitycheck.gstatic.com", "github.com"]
        ads = ["doubleclick.net", "ads.tiktok.com", "app-measurement.com", "telemetry.example-tv.com"]
        now = time.time()
        rows = []
        for i in range(random.randint(8, 20)):
            d = random.choice(devs)
            r = random.random()
            dom = random.choice(ads) if r < 0.2 else ("c2.badhost.example" if r < 0.215 else random.choice(common))
            rows.append({"id": None, "t": now - random.uniform(0, 25), "client": d["ip"], "client_name": "",
                         "domain": dom, "blocked": dom in ads or dom.endswith(".example")})
        rows.sort(key=lambda x: x["t"])
        self.last_t = min(self.last_t, rows[0]["t"] - 1) if self.last_t else 0
        self.ingest(rows)

