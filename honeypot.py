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
import re
import ipaddress
import json
import secrets
import logging
import sqlite3
import threading
import subprocess
import time

log = logging.getLogger("lanpulse.honeypot")

MAX_READ = 2048          # never read more than this from a client (a decoy, not a file server)
MAX_CONNS = 300          # open decoy connections at once, all services together
MAX_PER_IP = 8           # ...and from any one address
IO_TIMEOUT = 20.0        # seconds to wait on a slow/idle client before dropping it
HIT_RETENTION_DAYS = 90
FLOOD_WINDOW = 600       # one scanner shouldn't be able to flood the log or the alerts
FLOOD_MAX = 12           # at most this many logged hits per source IP per FLOOD_WINDOW

_IAC = re.compile(rb"\xff[\xfb-\xfe][\x00-\xff]|\xff\xfa.*?\xff\xf0|\xff[\xf0-\xfa]", re.S)


def _printable(raw: bytes, limit: int = 120) -> str:
    """Text of what a client sent, with control and telnet-negotiation bytes removed."""
    raw = _IAC.sub(b"", raw)
    return "".join(c if 32 <= ord(c) < 127 else "." for c in raw[:limit].decode("latin-1")).strip()


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
        self._open_conns = 0
        self._cap: dict[str, list[float]] = {}
        self._per_ip: dict[str, int] = {}
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
        base["ports"] = {k: int((c.get("ports") or {}).get(k) or SERVICES[k][0]) for k in SERVICES}
        base["banners"] = dict(c.get("banners") or {})
        for k, d in (("retention_days", HIT_RETENTION_DAYS), ("flood_max", FLOOD_MAX), ("flood_minutes", FLOOD_WINDOW // 60),
                     ("delay_ms", 0)):
            base[k] = c.get(k, d)
        base["alert_external"] = bool(c.get("alert_external", True))
        base["ignore"] = str(c.get("ignore") or "")
        return base

    def _config_sig(self):
        c = self.cfg
        return (c["enabled"], c["bind"], tuple(sorted((k, c["ports"][k]) for k, v in c["services"].items() if v)))

    def _port(self, service: str) -> int:
        return self.cfg["ports"].get(service) or SERVICES.get(service, (0,))[0]

    def _ignored(self, ip: str) -> bool:
        """Addresses the owner chose not to log (their own scanners, a monitoring box, a friend's VPN...)."""
        raw = self.cfg["ignore"]
        if not raw:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for tok in raw.split():
            try:
                if addr in ipaddress.ip_network(tok, strict=False):
                    return True
            except ValueError:
                continue
        return False

    async def _pause(self):
        ms = int(self.cfg["delay_ms"] or 0)
        if ms:
            await asyncio.sleep(ms / 1000)                 # slows scanners down: a very small tarpit

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

    def _over_cap(self, ip: str) -> bool:
        """Hard limit on stored hits per address per window: far above the alert threshold, so real detail is kept."""
        now = time.time()
        window = int(self.cfg["flood_minutes"]) * 60
        cap = max(200, int(self.cfg["flood_max"]) * 20)
        q = [t for t in self._cap.get(ip, []) if now - t < window]
        if len(q) >= cap:
            self._cap[ip] = q
            return True
        q.append(now)
        self._cap[ip] = q
        if len(self._cap) > 5000:
            self._cap.clear()
        return False

    def _flooding(self, ip: str) -> bool:
        now = time.time()
        window = int(self.cfg["flood_minutes"]) * 60
        q = [t for t in self._flood.get(ip, []) if now - t < window]
        q.append(now)
        self._flood[ip] = q
        if len(self._flood) > 5000:
            self._flood.clear()                       # bounded: unique scanners are many, memory isn't
        return len(q) > int(self.cfg["flood_max"])

    # ------------------------------------------------------------------ recording
    def record(self, ip: str, service: str, port: int, creds: str = "", data: str = "", sensor: str = ""):
        if not sensor and self._is_self(ip):
            return                                    # LanPulse scanning itself (nmap/OpenVAS), not an attacker
        if self._ignored(ip):
            return                                    # on the owner's ignore list
        internal = self._internal(ip)
        if self._over_cap(ip):
            return                                    # a scanner hammering the decoys can't fill the disk
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
            elif self.cfg["alert_external"]:
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
        if not want or not secrets.compare_digest(str(key).encode(), str(want).encode()):
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
    async def _recv_raw(self, reader, limit=MAX_READ) -> bytes:
        try:
            raw = await asyncio.wait_for(reader.readline(), IO_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return b""
        return raw[:limit + 64]

    @staticmethod
    def _text(raw: bytes, limit: int) -> str:
        raw = _IAC.sub(b"", raw)                      # telnet option negotiation is not part of the username
        return raw[:limit].decode("latin-1", "replace").replace("\x00", "").strip()

    async def _recv_line(self, reader, limit=MAX_READ) -> str:
        return self._text(await self._recv_raw(reader, limit), limit)

    async def _h_ssh(self, r, w, ip):
        await self._pause()
        ban = self.cfg["banners"].get("ssh") or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        w.write(ban.encode("ascii", "ignore") + b"\r\n")
        await w.drain()
        client = await self._recv_line(r, 120)       # the client's own SSH version string often names the tool
        self.record(ip, "ssh", self._port("ssh"), "", f"client={client}" if client else "")

    async def _h_telnet(self, r, w, ip):
        await self._pause()
        ban = self.cfg["banners"].get("telnet") or "Ubuntu 22.04.3 LTS"
        # Real telnet daemons open with option negotiation (DO NAWS, DO TERMINAL-TYPE, WILL SUPPRESS-GO-AHEAD). Many
        # bots wait for it before they start sending logins, so a silent decoy never gets a username out of them.
        w.write(b"\xff\xfd\x1f\xff\xfd\x18\xff\xfb\x03" + b"\r\n" + ban.encode("ascii", "ignore") + b"\r\n\r\nlogin: ")
        await w.drain()
        tried, port = 0, self._port("telnet")
        for _ in range(3):                            # bots usually try a few logins per connection
            raw = await self._recv_raw(r, 64)
            user = self._text(raw, 64)
            if not user:
                if not tried:
                    # Connected but never sent a username: say what it did instead of leaving the hit blank
                    note = ("only answered the telnet option negotiation" if b"\xff" in raw
                            else "connected and sent nothing before the timeout")
                    self.record(ip, "telnet", port, "", note)
                    return
                break
            await self._pause()
            w.write(b"Password: ")
            await w.drain()
            pw = await self._recv_line(r, 64)
            await self._pause()
            w.write(b"\r\nLogin incorrect\r\n")
            tried += 1
            self.record(ip, "telnet", port, f"{user} / {pw}")
            w.write(b"login: ")
            try:
                await w.drain()
            except OSError:
                break

    async def _h_ftp(self, r, w, ip):
        await self._pause()
        ban = self.cfg["banners"].get("ftp") or "(vsFTPd 3.0.5)"
        w.write(b"220 " + ban.encode("ascii", "ignore") + b"\r\n")
        await w.drain()
        user, tries, other = "", 0, []
        for _ in range(12):
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
                self.record(ip, "ftp", self._port("ftp"), f"{user} / {pw}" if (user or pw) else "")
                tries, user = tries + 1, ""
                if tries >= 3:
                    await w.drain()
                    break
            else:
                other.append(_printable(line.encode("latin-1", "replace"), 40))
                w.write(b"530 Please login with USER and PASS.\r\n")
            await w.drain()
        if not tries:
            self.record(ip, "ftp", self._port("ftp"), f"{user} / " if user else "",
                        ("commands: " + ", ".join(other[:6])) if other else "")

    async def _h_http(self, r, w, ip):
        import base64
        from urllib.parse import parse_qsl
        req, creds, hdr = "", "", {}
        for i in range(30):
            line = await self._recv_line(r, 512)
            if i == 0:
                req = line[:200]
            elif not line:
                break
            elif ":" in line:
                k, _, v = line.partition(":")
                hdr[k.strip().lower()] = v.strip()
        auth = hdr.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                creds = base64.b64decode(auth.split(None, 1)[1]).decode("latin-1", "replace")[:120].replace(":", " / ", 1)
            except Exception:
                creds = ""
        body = ""
        try:
            n = max(0, min(int(hdr.get("content-length", "0") or 0), MAX_READ))
        except ValueError:
            n = 0
        if n:
            try:
                body = (await asyncio.wait_for(r.readexactly(n), IO_TIMEOUT)).decode("latin-1", "replace")
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
                body = ""
        if body and not creds:
            f = {k.lower(): v for k, v in parse_qsl(body, keep_blank_values=True)}
            u = next((f[k] for k in ("username", "user", "login", "email", "uname", "log", "usr") if k in f), "")
            pw = next((f[k] for k in ("password", "pass", "pwd", "passwd", "pw") if k in f), "")
            if u or pw:
                creds = f"{u} / {pw}"[:120]
        parts = [req]
        if hdr.get("user-agent"):
            parts.append("UA: " + _printable(hdr["user-agent"].encode("latin-1", "replace"), 80))
        if hdr.get("host"):
            parts.append("Host: " + _printable(hdr["host"].encode("latin-1", "replace"), 40))
        if body and not creds:
            parts.append("body: " + _printable(body.encode("latin-1", "replace"), 80))
        await self._pause()
        bn = self.cfg["banners"]
        title = (bn.get("http_title") or "Router Admin").replace("<", "").replace(">", "")
        server = (bn.get("http_server") or "lighttpd/1.4.69").encode("ascii", "ignore")
        page = f"<html><head><title>{title}</title></head><body><h3>Authentication required</h3></body></html>".encode()
        w.write(b"HTTP/1.1 401 Unauthorized\r\nServer: " + server + b"\r\n"
                b"WWW-Authenticate: Basic realm=\"Admin\"\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(page)).encode() + b"\r\nConnection: close\r\n\r\n" + page)
        await w.drain()
        self.record(ip, "http", self._port("http"), creds, " | ".join(parts)[:400])

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
        self.record(ip, service, port, "", self._describe(service, data))

    @staticmethod
    def _describe(service: str, data: bytes) -> str:
        """What a scanner's first bytes say: tool or user names where the protocol carries them, else a preview."""
        if not data:
            return ""
        note = ""
        try:
            if service == "rdp":
                m = re.search(rb"Cookie: mstshash=([^\r\n]{1,64})", data)
                if m:
                    note = "RDP login name: " + _printable(m.group(1), 64)
                elif data[:1] == b"\x03":
                    note = "RDP connection request"
            elif service == "smb":
                if b"\xffSMB" in data[:8]:
                    dia = [d.decode("latin-1") for d in re.findall(rb"\x02([ -~]{3,30})\x00", data[36:])][:5]
                    note = "SMBv1 negotiate" + (": " + ", ".join(dia) if dia else "")
                elif b"\xfeSMB" in data[:8]:
                    note = "SMBv2/3 negotiate"
            elif service == "mysql" and len(data) > 37:
                end = data.find(b"\x00", 36)
                if end > 36:
                    note = "MySQL login name: " + _printable(data[36:end], 64)
        except Exception:
            note = ""
        tail = f"hex={data[:48].hex()}"
        return (note + " | " + tail)[:400] if note else tail

    HANDLERS = {"ssh": "_h_ssh", "telnet": "_h_telnet", "ftp": "_h_ftp", "http": "_h_http"}

    def _make_handler(self, service: str, port: int):
        async def handle(reader, writer):
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else "?"
            if self._open_conns >= MAX_CONNS or self._per_ip.get(ip, 0) >= MAX_PER_IP:
                writer.close()                         # one scanner can't use up every socket
                return
            self._open_conns += 1
            self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
            try:
                name = self.HANDLERS.get(service)
                if name:
                    await getattr(self, name)(reader, writer, ip)
                else:
                    await self._h_raw(reader, writer, ip, service, port)
            except Exception:
                log.debug("honeypot %s handler error", service, exc_info=True)
            finally:
                self._open_conns -= 1
                n = self._per_ip.get(ip, 1) - 1
                if n > 0:
                    self._per_ip[ip] = n
                else:
                    self._per_ip.pop(ip, None)
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
            port = c["ports"][key]
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
                        self.listeners = {k: {"port": self._port(k), "state": "off", "error": ""} for k in SERVICES}
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
                self.db.execute("DELETE FROM hits WHERE t < ?", (time.time() - int(self.cfg["retention_days"]) * 86400,))
                self.db.commit()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ views
    def summary(self, hours: int = 168) -> dict:
        since = time.time() - hours * 3600
        nb = 24                                       # activity chart: 24 equal slices of the window
        span = hours * 3600 / nb
        # Totals are counted in the database over the whole window; only the "recent" feed is limited to a few rows
        with self.lock:
            q = self.db.execute
            rows = q("SELECT t, ip, service, port, internal, creds, data, sensor "
                     "FROM hits WHERE t >= ? ORDER BY t DESC LIMIT 60", (since,)).fetchall()
            total_all = q("SELECT COUNT(*) FROM hits").fetchone()[0]
            n_hits, internal_hits = q("SELECT COUNT(*), COALESCE(SUM(internal != 0), 0) FROM hits WHERE t >= ?", (since,)).fetchone()
            svc_rows = q("SELECT service, COUNT(*) FROM hits WHERE t >= ? GROUP BY service", (since,)).fetchall()
            ip_rows = q("SELECT ip, COUNT(*), MAX(internal), group_concat(DISTINCT service), MAX(t), MIN(t) "
                        "FROM hits WHERE t >= ? GROUP BY ip", (since,)).fetchall()
            cred_rows = q("SELECT creds, COUNT(*) FROM hits WHERE t >= ? AND creds != '' AND creds IS NOT NULL GROUP BY creds",
                          (since,)).fetchall()
            hist_rows = q("SELECT CAST((t - ?) / ? AS INTEGER), COUNT(*) FROM hits WHERE t >= ? GROUP BY 1",
                          (since, span, since)).fetchall()
        hits = [{"t": t, "ip": ip, "service": svc, "port": port, "internal": bool(internal),
                 "creds": creds, "data": data, "sensor": sensor}
                for t, ip, svc, port, internal, creds, data, sensor in rows]
        by_service = {svc: n for svc, n in svc_rows}
        by_ip = {ip: {"ip": ip, "hits": n, "internal": bool(internal), "services": set((svcs or "").split(",")),
                      "last": last, "first": first}
                 for ip, n, internal, svcs, last, first in ip_rows}
        by_cred = {c: n for c, n in cred_rows}
        attackers = sorted(by_ip.values(), key=lambda a: -a["hits"])
        for a in attackers:
            a["services"] = sorted(a["services"])
        users: dict[str, int] = {}
        passwords: dict[str, int] = {}
        for c, n in by_cred.items():
            u, sep, pw = c.partition(" / ")
            users[u or "(blank)"] = users.get(u or "(blank)", 0) + n
            passwords[(pw if sep else "") or "(blank)"] = passwords.get((pw if sep else "") or "(blank)", 0) + n
        top = lambda d: [{"v": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:12]]
        hist = [0] * nb
        for b, n in hist_rows:
            hist[min(nb - 1, max(0, int(b)))] += n
        countries: dict[str, dict] = {}
        for a in attackers:
            g = self._geo(a["ip"])
            a.update(g)
            if not a["internal"] and g["iso"]:
                c = countries.setdefault(g["iso"], {"iso": g["iso"], "country": g["country"], "hits": 0, "ips": 0})
                c["hits"] += a["hits"]
                c["ips"] += 1
        for h in hits[:60]:
            h.update({k: v for k, v in self._geo(h["ip"]).items() if k in ("iso", "country", "city")})
        return {
            "type": "honeypot_summary",
            "enabled": self.cfg["enabled"],
            "bind": self.cfg["bind"],
            "has_ingest_key": bool(self.cfg["ingest_key"]),
            "services_on": self.cfg["services"],
            "catalog": {k: {"port": self._port(k), "default_port": v[0], "label": v[1], "note": v[3]} for k, v in SERVICES.items()},
            "listeners": self.listeners or {k: {"port": self._port(k), "state": "off", "error": ""} for k in SERVICES},
            "totals": {"hits": n_hits, "all_time": total_all, "attackers": len(by_ip),
                       "internal": internal_hits, "external": n_hits - internal_hits,
                       "creds": sum(by_cred.values())},
            "by_service": sorted(({"service": k, "label": SERVICES.get(k, (0, k))[1], "count": v}
                                  for k, v in by_service.items()), key=lambda x: -x["count"]),
            "attackers": attackers[:40],
            "creds": sorted(({"cred": k, "count": v} for k, v in by_cred.items()), key=lambda x: -x["count"])[:20],
            "recent": hits[:60],
            "hours": hours,
            "hist": hist,
            "countries": sorted(countries.values(), key=lambda c: -c["hits"])[:10],
            "usernames": top(users),
            "passwords": top(passwords),
        }

    def service_detail(self, service: str, hours: int = 168) -> dict | None:
        """Hosts that touched one decoy, with counts and offline GeoIP context."""
        if service not in SERVICES:
            return None
        since = time.time() - hours * 3600
        with self.lock:
            total, host_count = self.db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT ip) FROM hits WHERE service = ? AND t >= ?",
                (service, since)).fetchone()
            rows = self.db.execute(
                "SELECT ip, COUNT(*), MAX(internal), MIN(t), MAX(t), "
                "GROUP_CONCAT(DISTINCT port), SUM(CASE WHEN creds != '' AND creds IS NOT NULL THEN 1 ELSE 0 END), "
                "MAX(sensor) FROM hits WHERE service = ? AND t >= ? GROUP BY ip "
                "ORDER BY COUNT(*) DESC, MAX(t) DESC LIMIT 200", (service, since)).fetchall()
        hosts = []
        for ip, count, internal, first, last, ports, credential_hits, sensor in rows:
            hosts.append({"ip": ip, "hits": count, "internal": bool(internal), "first": first, "last": last,
                          "ports": sorted(int(p) for p in (ports or "").split(",") if p.isdigit()),
                          "credential_hits": credential_hits or 0, "sensor": sensor or "", **self._geo(ip)})
        return {"service": service, "label": SERVICES[service][1], "hours": hours, "total": total,
                "host_count": host_count, "hosts": hosts, "truncated": host_count > len(hosts)}

    def _geo(self, ip: str) -> dict:
        """Country / city / network owner for an IP, from the offline GeoIP databases (blank for LAN addresses)."""
        out = {"iso": "", "country": "", "city": "", "org": "", "asn": None}
        if self._internal(ip):
            return out
        geo = getattr(getattr(self.nm, "threats", None), "geo", None)
        if not geo:
            return out
        try:
            g, a = geo.lookup(ip), geo.asn(ip)
            out.update(iso=g.get("iso", ""), country=g.get("country", ""), city=g.get("city", ""),
                       org=a.get("org", ""), asn=a.get("asn"))
        except Exception:
            pass
        return out

    def detail(self, ip: str, hours: int = 2160) -> dict:
        """Everything this one address did to the decoys: totals, every login tried, every request."""
        since = time.time() - hours * 3600
        with self.lock:
            rows = self.db.execute("SELECT t, service, port, creds, data, sensor FROM hits WHERE ip = ? AND t >= ? "
                                   "ORDER BY t DESC LIMIT 500", (ip, since)).fetchall()
        hits = [{"t": t, "service": svc, "port": port, "creds": c, "data": d, "sensor": sn}
                for t, svc, port, c, d, sn in rows]
        by_svc: dict[str, int] = {}
        creds: dict[str, int] = {}
        for h in hits:
            by_svc[h["service"]] = by_svc.get(h["service"], 0) + 1
            if h["creds"]:
                creds[h["creds"]] = creds.get(h["creds"], 0) + 1
        return {"ip": ip, "internal": self._internal(ip), "hits": hits, "total": len(hits),
                "first": hits[-1]["t"] if hits else None, "last": hits[0]["t"] if hits else None,
                "services": sorted(({"service": k, "label": SERVICES.get(k, (0, k))[1], "count": v}
                                    for k, v in by_svc.items()), key=lambda x: -x["count"]),
                "creds": sorted(({"cred": k, "count": v} for k, v in creds.items()), key=lambda x: -x["count"])[:30],
                **self._geo(ip)}

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
