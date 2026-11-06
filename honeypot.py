# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Built-in honeypot: low-interaction decoy services that no legitimate device should ever touch.

LanPulse opens fake SSH, Telnet, FTP, HTTP, SMB, RDP and MySQL listeners. They present a realistic banner,
record everything a client sends (including any username/password it tries), and never grant access or run
anything. Because nobody has a reason to connect to these ports, every hit is high-signal:

  * a hit from a device ON your own network almost always means that device is compromised or is scanning
    the LAN - the classic sign of an attacker who already has a foothold and is moving sideways;
  * a hit from outside is an attacker probing your perimeter.

This is a LOW-interaction honeypot on purpose: it captures who is probing and what they try, without ever
giving an attacker a real shell or a real file share. It also ingests events from an external sensor (an
ESP32 honeypot, say) so hardware and software decoys share one dashboard.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sqlite3
import threading
import subprocess
import time

log = logging.getLogger("lanpulse.honeypot")

MAX_READ = 2048          # never read more than this from a client (a decoy, not a file server)
IO_TIMEOUT = 20.0        # seconds to wait on a slow/idle client before dropping it
HIT_RETENTION_DAYS = 90
FLOOD_WINDOW = 600       # one scanner shouldn't be able to flood the log or the alerts
FLOOD_MAX = 12           # at most this many logged hits per source IP per FLOOD_WINDOW

# key -> (default port, display label, handler name, one-line note shown in the UI)
SERVICES = {
    "ssh":    (22,   "SSH",    "ssh",    "Fake OpenSSH login"),
    "telnet": (23,   "Telnet", "telnet", "Fake Telnet login (captures username + password)"),
    "ftp":    (21,   "FTP",    "ftp",    "Fake FTP server (captures username + password)"),
    "http":   (80,   "HTTP",   "http",   "Fake admin web login (captures Basic-Auth credentials)"),
    "smb":    (445,  "SMB",    "smb",    "Fake Windows file sharing (the EternalBlue target port)"),
    "rdp":    (3389, "RDP",    "rdp",    "Fake Remote Desktop"),
    "mysql":  (3306, "MySQL",  "mysql",  "Fake MySQL database"),
}
# Services safe to turn on by default: the LanPulse host almost never runs these itself, so they won't
# collide with a real service. SSH (22) and HTTP (80) are left off by default because the box often does.
DEFAULT_ON = {"telnet", "ftp", "smb", "rdp", "mysql"}


def default_config() -> dict:
    return {"enabled": False, "bind": "0.0.0.0", "ingest_key": "",
            "services": {k: (k in DEFAULT_ON) for k in SERVICES}}


class Honeypot:
    def __init__(self, nm):
        self.nm = nm
        self.demo = bool(getattr(nm.args, "demo", False))
        self.db = sqlite3.connect(str(nm.data_dir / ("demo-honeypot.db" if self.demo else "honeypot.db")),
                                  check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL, ip TEXT, service TEXT, port INTEGER,
            internal INTEGER, creds TEXT, data TEXT, sensor TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS hits_t ON hits(t)")
        self.db.execute("CREATE INDEX IF NOT EXISTS hits_ip ON hits(ip)")
        self.db.commit()
        self.lock = threading.Lock()
        self.servers: dict[str, asyncio.AbstractServer] = {}
        self.listeners: dict[str, dict] = {}          # service key -> {port, state, error}
        self._sig = None                              # last applied config signature
        self._flood: dict[str, list[float]] = {}
        self._prune()
        self._local = (0.0, set(), [])
        try:
            self._purge_self()
        except Exception:
            log.debug("honeypot self-purge skipped", exc_info=True)

    # ------------------------------------------------------------------ config
    @property
    def cfg(self) -> dict:
        c = self.nm.settings.get("honeypot") or {}
        base = default_config()
        base.update({k: c[k] for k in ("enabled", "bind", "ingest_key") if k in c})
        svc = c.get("services") or {}
        base["services"] = {k: bool(svc.get(k, base["services"][k])) for k in SERVICES}
        return base

    def _config_sig(self):
        c = self.cfg
        return (c["enabled"], c["bind"], tuple(sorted(k for k, v in c["services"].items() if v)))

    # ------------------------------------------------------------------ helpers
    def _local_nets(self):
        """This server's own addresses plus the networks of its Docker/bridge interfaces. Connections from these are
        LanPulse's own scans (nmap, OpenVAS) touching the decoys, not attackers, so they are never logged."""
        now = time.time()
        if now - self._local[0] < 60:
            return self._local[1], self._local[2]
        ips, nets = set(), []
        my = (getattr(self.nm, "net", None) or {}).get("my_ip")
        if my:
            ips.add(my)
        try:
            out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=3).stdout
            for itf in json.loads(out or "[]"):
                name = itf.get("ifname", "")
                for a in itf.get("addr_info", []):
                    if a.get("family") != "inet":
                        continue
                    ips.add(a["local"])
                    if name.startswith(("docker", "br-", "veth", "virbr", "lxc", "cni", "flannel")):
                        nets.append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
        except Exception:
            pass
        self._local = (now, ips, nets)
        return ips, nets

    def _is_self(self, ip: str) -> bool:
        ips, nets = self._local_nets()
        if ip in ips or ip.startswith("127."):
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def _purge_self(self):
        with self.lock:
            rows = self.db.execute("SELECT DISTINCT ip FROM hits").fetchall()
            bad = [r[0] for r in rows if self._is_self(r[0])]
            for ip in bad:
                self.db.execute("DELETE FROM hits WHERE ip=? AND sensor=''", (ip,))
            if bad:
                self.db.commit()

    def _internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return False
        net = self.nm.net.get("subnet") if getattr(self.nm, "net", None) else None
        if net:
            try:
                return addr in ipaddress.ip_network(net, strict=False)
            except ValueError:
                pass
        return addr.is_private

    def _device_for(self, ip: str):
        for d in list(self.nm.devices.values()):
            if d.get("ip") == ip:
                return d
        return None

    def _flooding(self, ip: str) -> bool:
        now = time.time()
        q = [t for t in self._flood.get(ip, []) if now - t < FLOOD_WINDOW]
        q.append(now)
        self._flood[ip] = q
        return len(q) > FLOOD_MAX

    # ------------------------------------------------------------------ recording
    def record(self, ip: str, service: str, port: int, creds: str = "", data: str = "", sensor: str = ""):
        if not sensor and self._is_self(ip):
            return                                    # LanPulse scanning itself (nmap/OpenVAS), not an attacker
        internal = self._internal(ip)
        with self.lock:
            self.db.execute("INSERT INTO hits (t, ip, service, port, internal, creds, data, sensor) "
                            "VALUES (?,?,?,?,?,?,?,?)",
                            (time.time(), ip, service, int(port), 1 if internal else 0,
                             creds[:120], data[:400], sensor[:40]))
            self.db.commit()
        if self._flooding(ip):
            return                                    # keep logging to the DB, but stop alerting on a flood
        if not internal:
            self._to_map(ip, service, port, creds, sensor)
        label = SERVICES.get(service, (0, service))[1]
        where = f"{sensor} honeypot" if sensor else "the honeypot"
        try:
            if internal:
                d = self._device_for(ip)
                detail = f"{ip} connected to {where}'s fake {label} service (port {port})" \
                         + (f" and tried the login {creds}" if creds else "") \
                         + ". A device on your own network has no reason to do this - it is very likely compromised" \
                           " or scanning the LAN."
                if d:
                    self.nm.event("honeypot", d, detail, "bad")
                    self.nm.notify("local_threats", d, f"{self.nm.label(d)} hit the honeypot", detail, 4)
                else:
                    self.nm.notify_plain("local_threats", f"pot-{ip}",
                                         f"Unknown device {ip} hit the honeypot", detail, 4)
            else:
                self.nm.notify_plain("local_threats", f"pot-{ip}",
                                     f"Honeypot probe from {ip}",
                                     f"{ip} connected to {where}'s fake {label} service (port {port})"
                                     + (f" and tried the login {creds}" if creds else "") + ".", 3)
        except Exception:
            log.exception("honeypot alert failed")

    def _to_map(self, ip: str, service: str, port: int, creds: str, sensor: str):
        """Show an outside visitor on the Threats map and feed ("logged" = hit a decoy, never reached a real device)."""
        th = getattr(self.nm, "threats", None)
        if not th:
            return
        label = SERVICES.get(service, (0, service))[1]
        try:
            th.ingest({"src": ip, "dst": self.nm.net.get("my_ip") or "", "dport": int(port), "proto": "tcp",
                       "action": "logged", "service": label, "sensor": sensor or "Honeypot",
                       "detail": f"Honeypot {label} decoy" + (f" - tried login {creds}" if creds else "")})
        except Exception:
            log.exception("honeypot map feed failed")

    def ingest(self, payload: dict, key: str) -> tuple[bool, str]:
        """Accept a hit from an external sensor (POST /api/honeypot/ingest). Requires the configured key."""
        want = self.cfg.get("ingest_key")
        if not want or key != want:
            return False, "bad key"
        ip = str(payload.get("ip") or "").strip()[:45]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, "bad ip"
        service = str(payload.get("service") or "other")[:20]
        try:
            port = int(payload.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        self.record(ip, service, port, str(payload.get("creds") or "")[:120],
                    str(payload.get("data") or "")[:400], str(payload.get("sensor") or "sensor")[:40])
        return True, "ok"

    # ------------------------------------------------------------------ protocol handlers
    async def _recv_line(self, reader, limit=MAX_READ) -> str:
        try:
            raw = await asyncio.wait_for(reader.readline(), IO_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return ""
        return raw[:limit].decode("latin-1", "replace").strip()

    async def _h_ssh(self, r, w, ip):
        w.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await w.drain()
        client = await self._recv_line(r, 120)       # the client's own SSH version string often names the tool
        self.record(ip, "ssh", 22, "", f"client={client}" if client else "")

    async def _h_telnet(self, r, w, ip):
        w.write(b"\r\nUbuntu 22.04.3 LTS\r\n\r\nlogin: ")
        await w.drain()
        user = await self._recv_line(r, 64)
        w.write(b"Password: ")
        await w.drain()
        pw = await self._recv_line(r, 64)
        w.write(b"\r\nLogin incorrect\r\n")
        await w.drain()
        self.record(ip, "telnet", 23, f"{user} / {pw}" if (user or pw) else "")

    async def _h_ftp(self, r, w, ip):
        w.write(b"220 (vsFTPd 3.0.5)\r\n")
        await w.drain()
        user = pw = ""
        for _ in range(4):
            line = await self._recv_line(r, 128)
            if not line:
                break
            up = line.upper()
            if up.startswith("USER"):
                user = line[4:].strip()[:64]
                w.write(b"331 Please specify the password.\r\n")
            elif up.startswith("PASS"):
                pw = line[4:].strip()[:64]
                w.write(b"530 Login incorrect.\r\n")
                await w.drain()
                break
            else:
                w.write(b"530 Please login with USER and PASS.\r\n")
            await w.drain()
        self.record(ip, "ftp", 21, f"{user} / {pw}" if (user or pw) else "")

    async def _h_http(self, r, w, ip):
        import base64
        req, creds = "", ""
        for i in range(20):
            line = await self._recv_line(r, 512)
            if i == 0:
                req = line[:200]
            if not line:
                break
            if line.lower().startswith("authorization: basic "):
                try:
                    creds = base64.b64decode(line.split(None, 2)[2]).decode("latin-1", "replace")[:120]
                except Exception:
                    creds = ""
        body = b"<html><head><title>Router Admin</title></head><body><h3>Authentication required</h3></body></html>"
        w.write(b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4.69\r\n"
                b"WWW-Authenticate: Basic realm=\"Admin\"\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await w.drain()
        self.record(ip, "http", 80, creds, req)

    async def _h_raw(self, r, w, ip, service, port):
        """SMB / RDP / MySQL: binary protocols. The connection attempt itself is the signal; log a short
        hex preview of whatever the client sends first."""
        if service == "mysql":
            # a plausible MySQL greeting makes a scanner think it found a real server and keep talking
            w.write(bytes.fromhex("4a0000000a382e302e3335000a00000001020304050607000000000000000000000000"
                                  "15000000000000000000006162636465666768696a6b6c00"))
            try:
                await w.drain()
            except OSError:
                pass
        try:
            data = await asyncio.wait_for(r.read(MAX_READ), IO_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            data = b""
        preview = data[:64].hex()
        self.record(ip, service, port, "", f"hex={preview}" if preview else "")

    HANDLERS = {"ssh": "_h_ssh", "telnet": "_h_telnet", "ftp": "_h_ftp", "http": "_h_http"}

    def _make_handler(self, service: str, port: int):
        async def handle(reader, writer):
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else "?"
            try:
                name = self.HANDLERS.get(service)
                if name:
                    await getattr(self, name)(reader, writer, ip)
                else:
                    await self._h_raw(reader, writer, ip, service, port)
            except Exception:
                log.debug("honeypot %s handler error", service, exc_info=True)
            finally:
                try:
                    writer.close()
                except Exception:
                    pass
        return handle

    # ------------------------------------------------------------------ server lifecycle
    async def _open(self):
        c = self.cfg
        bind = c["bind"] or "0.0.0.0"
        self.listeners = {}
        for key, on in c["services"].items():
            port = SERVICES[key][0]
            if not on:
                self.listeners[key] = {"port": port, "state": "off", "error": ""}
                continue
            try:
                srv = await asyncio.start_server(self._make_handler(key, port), bind, port)
                self.servers[key] = srv
                self.listeners[key] = {"port": port, "state": "listening", "error": ""}
                log.info("honeypot %s listening on %s:%d", key, bind, port)
            except OSError as e:
                msg = "port already in use" if getattr(e, "errno", 0) in (98, 48) else \
                      ("permission denied (needs a privileged port)" if getattr(e, "errno", 0) == 13 else str(e))
                self.listeners[key] = {"port": port, "state": "error", "error": msg[:120]}
                log.info("honeypot %s could not bind %s:%d: %s", key, bind, port, msg)

    async def _close(self):
        for srv in self.servers.values():
            try:
                srv.close()
            except Exception:
                pass
        for srv in list(self.servers.values()):
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self.servers = {}

    async def run(self):
        await asyncio.sleep(5)
        last_prune = time.time()
        while True:
            try:
                sig = self._config_sig()
                if sig != self._sig:
                    await self._close()
                    if self.cfg["enabled"]:
                        await self._open()
                    else:
                        self.listeners = {k: {"port": SERVICES[k][0], "state": "off", "error": ""} for k in SERVICES}
                    self._sig = sig
                if time.time() - last_prune > 3600:
                    await asyncio.to_thread(self._prune)
                    last_prune = time.time()
            except Exception:
                log.exception("honeypot supervisor error")
            await asyncio.sleep(3)

    def _prune(self):
        try:
            with self.lock:
                self.db.execute("DELETE FROM hits WHERE t < ?", (time.time() - HIT_RETENTION_DAYS * 86400,))
                self.db.commit()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ views
    def summary(self, hours: int = 168) -> dict:
        since = time.time() - hours * 3600
        with self.lock:
            rows = self.db.execute("SELECT t, ip, service, port, internal, creds, data, sensor "
                                   "FROM hits WHERE t >= ? ORDER BY t DESC LIMIT 2000", (since,)).fetchall()
            total_all = self.db.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        hits = [{"t": t, "ip": ip, "service": svc, "port": port, "internal": bool(internal),
                 "creds": creds, "data": data, "sensor": sensor}
                for t, ip, svc, port, internal, creds, data, sensor in rows]
        by_service: dict[str, int] = {}
        by_ip: dict[str, dict] = {}
        by_cred: dict[str, int] = {}
        internal_hits = 0
        for h in hits:
            by_service[h["service"]] = by_service.get(h["service"], 0) + 1
            if h["internal"]:
                internal_hits += 1
            a = by_ip.setdefault(h["ip"], {"ip": h["ip"], "hits": 0, "internal": h["internal"],
                                           "services": set(), "last": h["t"]})
            a["hits"] += 1
            a["services"].add(h["service"])
            a["last"] = max(a["last"], h["t"])
            if h["creds"]:
                by_cred[h["creds"]] = by_cred.get(h["creds"], 0) + 1
        attackers = sorted(by_ip.values(), key=lambda a: -a["hits"])
        for a in attackers:
            a["services"] = sorted(a["services"])
        return {
            "type": "honeypot_summary",
            "enabled": self.cfg["enabled"],
            "bind": self.cfg["bind"],
            "has_ingest_key": bool(self.cfg["ingest_key"]),
            "services_on": self.cfg["services"],
            "catalog": {k: {"port": v[0], "label": v[1], "note": v[3]} for k, v in SERVICES.items()},
            "listeners": self.listeners or {k: {"port": SERVICES[k][0], "state": "off", "error": ""} for k in SERVICES},
            "totals": {"hits": len(hits), "all_time": total_all, "attackers": len(by_ip),
                       "internal": internal_hits, "external": len(hits) - internal_hits,
                       "creds": sum(by_cred.values())},
            "by_service": sorted(({"service": k, "label": SERVICES.get(k, (0, k))[1], "count": v}
                                  for k, v in by_service.items()), key=lambda x: -x["count"]),
            "attackers": attackers[:40],
            "creds": sorted(({"cred": k, "count": v} for k, v in by_cred.items()), key=lambda x: -x["count"])[:20],
            "recent": hits[:60],
            "hours": hours,
        }

    def for_device(self, ip: str, hours: int = 720) -> list:
        since = time.time() - hours * 3600
        with self.lock:
            rows = self.db.execute("SELECT t, service, port, creds, data FROM hits WHERE ip = ? AND t >= ? "
                                   "ORDER BY t DESC LIMIT 100", (ip, since)).fetchall()
        return [{"t": t, "service": svc, "port": port, "creds": creds, "data": data}
                for t, svc, port, creds, data in rows]

    # ------------------------------------------------------------------ demo
    def seed_demo(self):
        """Populate plausible hits so the preview and demo mode show a lively honeypot."""
        with self.lock:
            if self.db.execute("SELECT COUNT(*) FROM hits").fetchone()[0]:
                return
        now = time.time()
        sample = [
            ("45.9.148.37", "ssh", 22, "", "client=libssh2_1.9.0", 2.0),
            ("45.9.148.37", "telnet", 23, "root / admin", "", 2.1),
            ("45.9.148.37", "telnet", 23, "admin / 1234", "", 2.2),
            ("193.32.162.44", "ftp", 21, "anonymous / anonymous", "", 5.0),
            ("193.32.162.44", "http", 80, "admin / admin", "GET /admin HTTP/1.1", 5.1),
            ("61.177.172.13", "ssh", 22, "", "client=Go", 9.0),
            ("61.177.172.13", "smb", 445, "", "hex=00000085ff534d42", 9.1),
            ("192.168.0.104", "smb", 445, "", "hex=00000054ff534d4272", 0.4),
            ("192.168.0.104", "rdp", 3389, "", "hex=030000132ee000000000", 0.3),
            ("192.168.0.104", "mysql", 3306, "root / (blank)", "", 0.2),
            ("141.98.11.29", "mysql", 3306, "root / root", "", 14.0),
            ("141.98.11.29", "telnet", 23, "admin / admin", "", 14.2),
        ]
        with self.lock:
            for ip, svc, port, creds, data, hrs in sample:
                internal = 1 if ip.startswith("192.168.") else 0
                sensor = "ESP32" if ip == "141.98.11.29" else ""
                self.db.execute("INSERT INTO hits (t, ip, service, port, internal, creds, data, sensor) "
                                "VALUES (?,?,?,?,?,?,?,?)",
                                (now - hrs * 3600, ip, svc, port, internal, creds, data, sensor))
            self.db.commit()
