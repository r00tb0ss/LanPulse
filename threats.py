# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Threat monitor for LanPulse.

Inputs (any combination):
  * Firewall logs sent by your router over syslog (UDP, default port 514):
      - Linux netfilter / iptables / nftables / UFW / OpenWrt / UniFi  ("SRC=... DST=... DPT=...")
      - pfSense / OPNsense filterlog (CSV)
      - MikroTik RouterOS firewall log; Fortinet / SonicWall / Sophos style key=value logs
  * JSON events POSTed to /api/threats/ingest (honeypots, scripts, IDS), header X-API-Key: <key>
      {"src": "1.2.3.4", "dst_port": 23, "proto": "tcp", "service": "telnet",
       "detail": "login admin/admin", "sensor": "esp32-honeypot", "lan_ip": "192.168.1.121"}

Each attack is geolocated (offline DB-IP database) and stored for 30 days in SQLite.
"""
from __future__ import annotations

import asyncio
import collections
import ipaddress
import json
import logging
import random
import re
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from scanners import ScannerTagger
import mmdb

log = logging.getLogger("lanpulse.threats")
KEEP_DAYS = 30

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 1080: "SOCKS", 1433: "MSSQL", 1723: "PPTP VPN", 1883: "MQTT",
    1900: "UPnP", 2222: "SSH", 2323: "Telnet", 3306: "MySQL", 3389: "RDP", 4444: "Backdoor", 5060: "SIP",
    5432: "PostgreSQL", 5555: "Android ADB", 5900: "VNC", 6379: "Redis", 6667: "IRC", 6697: "IRC",
    7547: "TR-069", 8000: "HTTP", 8080: "HTTP", 8081: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9200: "Elasticsearch",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB", 37215: "Huawei exploit", 49152: "UPnP",
    52869: "UPnP exploit", 60001: "IoT exploit",
}


def service_for(port: int | None, proto: str = "tcp") -> str:
    if proto == "icmp":
        return "Ping (ICMP)"
    return SERVICES.get(port or 0, f"Port {port}" if port else proto.upper())


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- log parsing
KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|IN|OUT)=(\S*)")
TCP_FLAGS = re.compile(r"\b(SYN|ACK|RST|FIN|PSH|URG)\b")
ICMP_TYPE = re.compile(r"\bTYPE=(\d+)")

# Well-known server ports. A packet *from* one of these to a high port on your side is almost always
# a late reply to a connection one of your devices opened, not someone knocking on your door.
REPLY_TCP = {80, 443, 853, 993, 995, 465, 587, 5223, 5228, 8443}
REPLY_UDP = {53, 123, 443, 500, 3478, 3479, 4500, 19302, 19303, 19305}


def noise_reason(raw: dict, forwarded_ports=()) -> str:
    """Why a blocked inbound packet isn't an attack (empty string if it may be one).
    Router logs are full of these: the connection already closed, so the router drops the leftover packets."""
    if raw.get("detail") or "ips" in str(raw.get("sensor") or "").lower():
        return ""                                   # IPS signatures are always real detections
    proto = str(raw.get("proto") or "").lower()
    sport, dport = raw.get("sport"), raw.get("dport")
    if dport in forwarded_ports:
        return ""                                   # traffic aimed at something you expose: keep it
    if proto == "tcp":
        flags = raw.get("flags")
        if flags and "SYN" not in flags:
            return "late reply"                     # ACK/RST/FIN with no SYN: leftovers of a closed connection
        if flags and "SYN" in flags and "ACK" in flags:
            return "late reply"                     # SYN-ACK: a server answering your device
        if not flags and sport in REPLY_TCP and (dport or 0) >= 1024:
            return "late reply"
    elif proto == "udp":
        if sport in REPLY_UDP and (dport or 0) >= 1024:
            return "late reply"
    elif proto in ("icmp", "ipv6-icmp", "icmpv6"):
        if raw.get("icmp_type") in (0, 3, 11, 12):
            return "network message"                # echo reply, unreachable, time exceeded: routine
    return ""
ALLOW_WORDS = re.compile(r"\b(ACCEPT|ALLOW|PASS)", re.I)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


UNIFI_ACCEPT = re.compile(r"\[[^\]]*-A-[^\]]*\]")       # UniFi rule prefixes: -A- accept, -D- drop, -R- reject


def parse_netfilter(line: str) -> dict | None:
    m = dict(KV.findall(line))
    if "SRC" not in m or "DST" not in m:
        return None
    allowed = ALLOW_WORDS.search(line) or UNIFI_ACCEPT.search(line)
    out = {"src": m["SRC"], "dst": m["DST"], "sport": _int(m.get("SPT")), "dport": _int(m.get("DPT")),
           "proto": (m.get("PROTO") or "tcp").lower(), "action": "allowed" if allowed else "blocked"}
    tail = line[line.find("PROTO="):] if "PROTO=" in line else ""
    if out["proto"] == "tcp":
        out["flags"] = sorted(set(TCP_FLAGS.findall(tail.split("DPT=", 1)[-1])))
    elif out["proto"].startswith("icmp"):
        t = ICMP_TYPE.search(tail)
        out["icmp_type"] = int(t.group(1)) if t else None
    return out


CEF_KV = re.compile(r"(\w+)=((?:\\.|[^\\])*?)(?=\s+\w+=|\s*$)")


def parse_cef(line: str) -> dict | None:
    """CEF events, e.g. UniFi CyberSecure (IDS/IPS) threat detections."""
    i = line.find("CEF:")
    if i < 0:
        return None
    parts = line[i:].split("|", 7)
    if len(parts) < 8:
        return None
    ext = {k: v.replace("\\=", "=").replace("\\\\", "\\") for k, v in CEF_KV.findall(parts[7])}
    src = ext.get("src") or ext.get("UNIFIsrcIp") or ext.get("sourceAddress")
    if not src:
        return None
    name = parts[5].strip()
    text = (name + " " + ext.get("act", "") + " " + ext.get("msg", "")).lower()
    blocked = any(w in text for w in ("block", "drop", "deny", "reject", "prevent"))
    sig = ext.get("UNIFIipsSignature") or ext.get("cs1") or ext.get("msg") or name
    return {"src": src, "dst": ext.get("dst", ""), "sport": _int(ext.get("spt")), "dport": _int(ext.get("dpt")),
            "proto": (ext.get("proto") or "tcp").lower(), "action": "blocked" if blocked else "allowed",
            "detail": sig[:300], "sensor": f"{parts[2].strip()} IPS"[:40]}


def parse_filterlog(line: str) -> dict | None:
    i = line.find("filterlog")
    if i < 0:
        return None
    f = line[line.find(":", i) + 1:].strip().split(",")
    try:
        if f[8] != "4" or f[7] != "in":
            return None
        proto = f[16].lower()
        sport = _int(f[20]) if proto in ("tcp", "udp") and len(f) > 21 else None
        dport = _int(f[21]) if proto in ("tcp", "udp") and len(f) > 21 else None
        return {"src": f[18], "dst": f[19], "sport": sport, "dport": dport, "proto": proto,
                "action": "blocked" if f[6] in ("block", "reject") else "allowed"}
    except IndexError:
        return None


def parse_json(obj: dict, default_action: str | None = "logged") -> dict | None:
    """A JSON event. From the ingest API (honeypots, scripts) a missing action means "logged" (a honeypot hit).
    Inside router logs, JSON lines are only events if they say what happened or that they come from a honeypot."""
    g = lambda *keys: next((obj[k] for k in keys if obj.get(k) not in (None, "")), None)
    src = g("src", "src_ip", "source_ip", "remote_ip", "ip")
    if not src:
        return None
    sensor = str(g("sensor", "source", "honeypot") or "")
    action = g("action")
    if action is None:
        if default_action is None and "honey" not in sensor.lower() and not obj.get("honeypot"):
            return None
        action = default_action or "logged"
    return {"src": str(src), "dst": str(g("dst", "dst_ip", "dest_ip") or ""), "sport": _int(g("sport", "src_port")),
            "dport": _int(g("dport", "dst_port", "port")), "proto": str(g("proto", "protocol") or "tcp").lower(),
            "action": str(action).lower(), "service": g("service"),
            "detail": str(g("detail", "message", "payload", "credentials") or "")[:300],
            "sensor": str(g("sensor", "source", "honeypot") or "")[:40], "lan_ip": g("lan_ip", "target_ip")}


def _ip_or_blank(v) -> str:
    try:
        return str(ipaddress.ip_address(str(v).strip())) if v not in (None, "") else ""
    except ValueError:
        return ""


def _port(v):
    return v if isinstance(v, int) and 0 <= v <= 65535 else None


def is_self_redirect(raw: dict) -> bool:
    for k in ("dst", "lan_ip"):
        v = raw.get(k)
        if v:
            try:
                ip = ipaddress.ip_address(v)
                if ip.is_loopback or ip.is_unspecified:
                    return True
            except ValueError:
                pass
    return False


def sanitize_event(raw: dict) -> dict | None:
    """Everything here comes from the network (syslog, honeypots, the ingest API). Keep only well-formed values."""
    if not isinstance(raw, dict):
        return None
    src = _ip_or_blank(raw.get("src"))
    if not src:
        return None
    out = dict(raw)
    out["src"] = src
    out["dst"] = _ip_or_blank(raw.get("dst"))
    if raw.get("lan_ip") not in (None, ""):
        out["lan_ip"] = _ip_or_blank(raw.get("lan_ip"))
    out["sport"], out["dport"] = _port(raw.get("sport")), _port(raw.get("dport"))
    out["proto"] = re.sub(r"[^a-z0-9-]", "", str(raw.get("proto") or "tcp").lower())[:12] or "tcp"
    action = str(raw.get("action") or "blocked").lower()
    out["action"] = action if action in ("blocked", "allowed", "logged") else "logged"
    for k, n in (("service", 40), ("sensor", 40), ("detail", 300)):
        if raw.get(k) not in (None, ""):
            out[k] = " ".join("".join(ch for ch in str(raw[k]) if ch.isprintable()).split())[:n]
    return out


def lan_noise_reason(raw: dict) -> str:
    """Router drops between two of your own devices that aren't blocked connections: leftover packets of a connection
    that already finished (or arrived out of order), which the router discards as "invalid". Traffic inside one
    subnet normally doesn't pass the router at all, so these are what usually shows up."""
    if raw.get("detail") or any(w in str(raw.get("sensor") or "").lower() for w in ("ips", "honey")):
        return ""
    if raw.get("action") != "blocked":
        return ""
    proto = str(raw.get("proto") or "").lower()
    flags = raw.get("flags")
    if proto == "tcp" and flags and ("SYN" not in flags or "ACK" in flags):
        return "leftover packet"            # ACK/RST/FIN/PSH, or SYN-ACK: part of a connection that already exists
    if proto == "udp" and raw.get("sport") in REPLY_UDP and (raw.get("dport") or 0) >= 1024:
        return "leftover packet"
    return ""


MIKROTIK = re.compile(r"(?:(?P<chain>[\w.-]+):\s*)?in:(?P<in>\S+).*?proto (?P<proto>[A-Za-z0-9_]+)(?: \((?P<flags>[^)]*)\))?,\s*"
                      r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<sport>\d+))?->(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dport>\d+))?")
KV_GENERIC = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_mikrotik(line: str) -> dict | None:
    """MikroTik RouterOS firewall log action=log, e.g.
    'forward: in:ether1 out:bridge, proto TCP (SYN), 1.2.3.4:5555->192.168.88.10:22, len 60'.
    Add a log prefix containing 'drop' or 'block' on drop rules, or 'accept' on accept rules (RouterOS does not log the action)."""
    m = MIKROTIK.search(line)
    if not m:
        return None
    proto = m.group("proto").lower()
    low = line.lower()
    allowed = bool(re.search(r"accept|allow|permit", low)) and not re.search(r"drop|block|reject|deny", low)
    out = {"src": m.group("src"), "dst": m.group("dst"), "sport": _int(m.group("sport")), "dport": _int(m.group("dport")),
           "proto": proto, "action": "allowed" if allowed else "blocked"}
    if proto == "tcp" and m.group("flags"):
        out["flags"] = sorted(set(TCP_FLAGS.findall(m.group("flags").replace(",", " "))))
    return out


def parse_keyvalue(line: str) -> dict | None:
    """Fortinet, SonicWall, Sophos, WatchGuard and similar key=value firewall logs
    (srcip/dstip/dstport/action or src/dst/dpt)."""
    kv = {k.lower(): (a or b) for k, a, b in KV_GENERIC.findall(line)}
    src = kv.get("srcip") or kv.get("src") or kv.get("src_ip")
    dst = kv.get("dstip") or kv.get("dst") or kv.get("dst_ip")
    if not src or not dst or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", src):
        return None
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dst):
        return None
    act = (kv.get("action") or kv.get("status") or kv.get("fw_action") or "").lower()
    proto = (kv.get("proto") or kv.get("protocol") or "tcp").lower()
    proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto)
    allowed = act in ("accept", "allow", "allowed", "pass", "permit", "close", "start")
    return {"src": src, "dst": dst, "sport": _int(kv.get("srcport") or kv.get("spt") or kv.get("src_port")),
            "dport": _int(kv.get("dstport") or kv.get("dpt") or kv.get("dst_port")),
            "proto": proto, "action": "allowed" if allowed else "blocked"}


def parse_line(line: str) -> dict | None:
    line = line.strip()
    j = line.find("{")
    if j >= 0:
        try:
            return parse_json(json.loads(line[j:]), default_action=None)
        except ValueError:
            pass
    return (parse_cef(line) or parse_filterlog(line) or parse_netfilter(line)
            or parse_mikrotik(line) or parse_keyvalue(line))


# --------------------------------------------------------------------------- GeoIP
class Geo:
    """Offline IP geolocation from a DB-IP / MaxMind .mmdb file (city level)."""

    def __init__(self, data_dir: Path):
        self.reader = None
        for name in ("dbip-city-lite.mmdb", "GeoLite2-City.mmdb"):
            p = Path(data_dir) / name
            if p.exists():
                try:
                    self.reader = mmdb.open_database(str(p))
                    log.info("GeoIP database: %s", p.name)
                except Exception as e:
                    log.warning("Could not open %s: %s", p, e)
                break
        if not self.reader:
            log.warning("No GeoIP database found; attacks won't be placed on the map. Re-run install.sh.")
        self.cache: dict[str, dict] = {}
        self.asn_reader = None
        self.asn_cache: dict[str, dict] = {}
        for name in ("dbip-asn-lite.mmdb", "GeoLite2-ASN.mmdb"):
            p = Path(data_dir) / name
            if p.exists():
                try:
                    self.asn_reader = mmdb.open_database(str(p))
                except Exception as e:
                    log.warning("Could not open %s: %s", p, e)
                break

    def asn(self, ip: str) -> dict:
        """Who owns an IP: {"asn": 15169, "org": "Google LLC"} (offline, DB-IP ASN Lite)."""
        if ip in self.asn_cache:
            return self.asn_cache[ip]
        out = {"asn": None, "org": ""}
        if self.asn_reader:
            try:
                r = self.asn_reader.get(ip) or {}
                out = {"asn": r.get("autonomous_system_number"), "org": r.get("autonomous_system_organization", "")}
            except Exception:
                pass
        if len(self.asn_cache) > 20000:
            self.asn_cache.clear()
        self.asn_cache[ip] = out
        return out

    def lookup(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]
        out = {"country": "", "iso": "", "city": "", "region": "", "lat": None, "lon": None}
        if self.reader:
            try:
                r = self.reader.get(ip) or {}
                out["country"] = r.get("country", {}).get("names", {}).get("en", "")
                out["iso"] = r.get("country", {}).get("iso_code", "")
                out["city"] = r.get("city", {}).get("names", {}).get("en", "")
                subs = r.get("subdivisions") or [{}]
                out["region"] = subs[0].get("names", {}).get("en", "")
                loc = r.get("location", {})
                out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
            except Exception:
                pass
        if len(self.cache) > 20000:
            self.cache.clear()
        self.cache[ip] = out
        return out


def _get_json(url: str, headers: dict | None = None, timeout: int = 8):
    req = urllib.request.Request(url, headers={"User-Agent": "LanPulse", "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(4_000_000).decode())


def _post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 8):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "LanPulse", "Accept": "application/json",
                                          "Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(4_000_000).decode())


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
TOR_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"
FEODO_C2_LIST = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"   # active botnet C2 IPs, no key needed


# --------------------------------------------------------------------------- demo data
# Documentation-only IP ranges (RFC 5737) so the demo never names a real address.
DEMO_ATTACKERS = [
    ("203.0.113.14", "China", "CN", "Shanghai", 31.23, 121.47), ("203.0.113.77", "Russia", "RU", "Moscow", 55.75, 37.62),
    ("198.51.100.23", "Brazil", "BR", "São Paulo", -23.55, -46.63), ("198.51.100.91", "Netherlands", "NL", "Amsterdam", 52.37, 4.9),
    ("192.0.2.45", "Vietnam", "VN", "Hanoi", 21.03, 105.85), ("192.0.2.130", "India", "IN", "Mumbai", 19.08, 72.88),
    ("203.0.113.201", "United States", "US", "Ashburn", 39.04, -77.49), ("198.51.100.150", "Germany", "DE", "Frankfurt", 50.11, 8.68),
    ("192.0.2.66", "Iran", "IR", "Tehran", 35.69, 51.39), ("203.0.113.180", "South Korea", "KR", "Seoul", 37.57, 126.98),
    ("198.51.100.7", "Romania", "RO", "Bucharest", 44.43, 26.1), ("192.0.2.211", "Indonesia", "ID", "Jakarta", -6.21, 106.85),
    ("203.0.113.99", "Ukraine", "UA", "Kyiv", 50.45, 30.52), ("198.51.100.240", "Singapore", "SG", "Singapore", 1.35, 103.82),
    ("192.0.2.18", "Hong Kong", "HK", "Hong Kong", 22.32, 114.17), ("203.0.113.55", "Bulgaria", "BG", "Sofia", 42.7, 23.32),
]
DEMO_SCANNERS = {"198.51.100.150": "Censys", "203.0.113.201": "Shodan"}
DEMO_SIGS = {23: ["ET SCAN Mirai Variant Telnet Brute Force", "ET TELNET busybox MIRAI hackers - Possible Brute Force Attack"],
             22: ["ET SCAN Potential SSH Scan"], 445: ["ET SCAN Suspicious inbound to SMB (Possible EternalBlue)"],
             3389: ["ET SCAN Behavioral Unusual Port 3389 traffic Potential Scan or Infection"],
             37215: ["ET EXPLOIT Huawei HG532 Remote Code Execution (CVE-2017-17215)"],
             8080: ["ET EXPLOIT TP-Link Archer AX21 Command Injection (CVE-2023-1389)", "ET SCAN Tomcat Manager Login Brute Force"],
             7547: ["ET EXPLOIT TR-069 SOAP Command Injection (Mirai)"], 6379: ["ET SCAN Redis Unauthenticated CONFIG SET"],
             5555: ["ET EXPLOIT Android ADB Debug Command Execution"]}
DEMO_PORTS = [(23, 30), (22, 25), (80, 10), (445, 8), (3389, 7), (8080, 6), (2323, 5), (5555, 3), (7547, 3),
              (6379, 2), (37215, 2), (21, 3), (25, 2), (5900, 2)]
DEMO_DETAILS = {23: ["login root/xc3511", "login admin/admin", "login root/vizxv", "busybox wget payload"],
                22: ["login root/123456", "login ubuntu/ubuntu", "login pi/raspberry"],
                80: ["GET /cgi-bin/luci", "GET /.env", "POST /boaform/admin/formLogin"], 21: ["login anonymous"],
                25: ["EHLO probe"], 8080: ["GET /manager/html"]}


# --------------------------------------------------------------------------- monitor
class ThreatMonitor:
    def __init__(self, nm):
        self.nm = nm
        self.data_dir = Path(nm.data_dir)
        self.db = sqlite3.connect(str(self.data_dir / ("demo-threats.db" if nm.args.demo else "threats.db")),
                                  check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS attacks (t REAL, src TEXT, sport INT, dst TEXT, dport INT, proto TEXT,"
                        " action TEXT, lan TEXT, service TEXT, sensor TEXT, detail TEXT, country TEXT, iso TEXT,"
                        " city TEXT, lat REAL, lon REAL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS attacks_t ON attacks (t)")
        self.db.execute("CREATE INDEX IF NOT EXISTS attacks_src ON attacks (src, t)")
        self.db.commit()
        self.lock = threading.Lock()
        self.geo = Geo(self.data_dir)
        self.intel_cache: dict[str, tuple[float, dict]] = {}
        self.tor_exits: set[str] = set()
        self.tor_loaded = 0.0
        self.c2_ips: set[str] = set()
        self.c2_loaded = 0.0
        self.burst: dict[str, collections.deque] = {}
        self.public_ip = ""
        self.home = {"lat": None, "lon": None, "city": "", "country": ""}
        self.syslog_ok = None
        self.syslog_error = ""
        self.last_event = 0.0
        self.dirty = True
        row = self.db.execute("SELECT MAX(t) FROM attacks").fetchone()
        self.last_event = row[0] or 0.0                     # survive restarts
        self.noise = {"total": 0, "since": time.time(), "reasons": {}, "orgs": {}}
        self.syslog_rejected: dict[str, dict] = {}
        self.uncommitted, self.last_commit = 0, time.time()
        self.syslog_dropped = 0
        self._rate_sec, self._rate_n = 0, 0
        self.clean_noise()
        self.tags = ScannerTagger(self.db, self.lock, demo=nm.args.demo)
        self.tags.on_tag = lambda ip, info: setattr(self, "dirty", True)
        if nm.args.demo:
            self.public_ip = "198.51.100.1"
            self.home = {"lat": 40.71, "lon": -74.0, "city": "New York", "country": "United States"}
            for ip, label in DEMO_SCANNERS.items():
                self.tags.cache[ip] = {"tag": "scanner", "label": label, "host": f"scan-{ip.split('.')[-1]}.example"}

    @property
    def cfg(self) -> dict:
        return self.nm.settings["threats"]

    def forwarded_ports(self) -> set:
        return {fw.get("port") for fw in self.cfg.get("forwards", []) if fw.get("port")}

    def clean_noise(self):
        """Remove late replies that were stored as attacks before LanPulse learned to tell them apart."""
        if not self.cfg.get("ignore_noise", True):
            return
        fw = sorted(p for p in self.forwarded_ports() if isinstance(p, int)) or [-1]
        q = ",".join("?" * len(fw))
        tcp, udp = sorted(REPLY_TCP), sorted(REPLY_UDP)
        with self.lock:
            cur = self.db.execute(
                f"DELETE FROM attacks WHERE COALESCE(detail,'') = '' AND LOWER(COALESCE(sensor,'')) NOT LIKE '%ips%'"
                f" AND dport >= 1024 AND dport NOT IN ({q}) AND ("
                f" (proto = 'tcp' AND sport IN ({','.join('?' * len(tcp))})) OR"
                f" (proto = 'udp' AND sport IN ({','.join('?' * len(udp))})))",
                (*fw, *tcp, *udp))
            self.db.commit()
        if cur.rowcount:
            log.info("Removed %d stored late-reply packets that were not attacks", cur.rowcount)
            row = self.db.execute("SELECT MAX(t) FROM attacks").fetchone()
            self.last_event = row[0] or 0.0
            self.dirty = True

    # ---- who may send router logs
    SYSLOG_MAX_PER_SEC = 400

    def syslog_allowed(self, ip: str) -> bool:
        """Router logs arrive over plain UDP with no password. Only take them from the gateway and addresses you
        allowed, so another device on the network can't feed in fake attacks. Also cap the rate so a flood
        can't fill the disk."""
        now = time.time()
        gateway = self.nm.net.get("gateway")
        # If the gateway couldn't be detected, don't silently drop the router's logs: accept them as before.
        allowed = self.cfg.get("syslog_any") or not gateway or ip in ("127.0.0.1", "::1") or ip == gateway \
            or ip in (self.cfg.get("syslog_from") or [])
        if not allowed:
            r = self.syslog_rejected.get(ip)
            if r is None:
                if len(self.syslog_rejected) >= 50:
                    self.syslog_rejected.pop(min(self.syslog_rejected, key=lambda k: self.syslog_rejected[k]["last"]))
                r = self.syslog_rejected[ip] = {"count": 0, "first": now, "last": 0.0}
                log.warning("Ignoring router logs from %s (not the gateway). Allow it in Settings > Threats if it's yours.", ip)
                self.dirty = True
            r["count"] += 1
            r["last"] = now
            return False
        sec = int(now)
        if sec != self._rate_sec:
            self._rate_sec, self._rate_n = sec, 0
        self._rate_n += 1
        if self._rate_n > self.SYSLOG_MAX_PER_SEC:
            self.syslog_dropped += 1
            return False
        return True

    # ---- lifecycle
    async def start(self):
        tasks = [asyncio.create_task(self.housekeeping()), asyncio.create_task(self.committer())]
        if self.nm.args.demo:
            self.seed_demo()
            tasks.append(asyncio.create_task(self.demo_loop()))
        elif self.cfg.get("enabled", True):
            await self.start_syslog()
        return tasks

    async def start_syslog(self):
        port = int(self.cfg.get("syslog_port", 514))
        loop = asyncio.get_running_loop()
        monitor = self

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not monitor.syslog_allowed(addr[0]):
                    return
                for line in data.decode("utf-8", "replace").splitlines()[:50]:
                    ev = parse_line(line)
                    if ev:
                        monitor.ingest(ev, sensor=f"syslog {addr[0]}")

        try:
            await loop.create_datagram_endpoint(Proto, local_addr=("0.0.0.0", port))
            self.syslog_ok = True
            log.info("Listening for firewall logs on UDP %d", port)
        except OSError as e:
            self.syslog_ok = False
            self.syslog_error = f"UDP port {port}: {e.strerror or e}"
            log.warning("Syslog listener failed on UDP %d: %s", port, e)

    def flush(self):
        with self.lock:
            if self.uncommitted:
                self.db.commit()
                self.uncommitted, self.last_commit = 0, time.time()

    async def committer(self):
        while True:
            await asyncio.sleep(1.5)
            self.flush()

    async def housekeeping(self):
        while True:
            if not self.nm.args.demo:
                try:
                    ip = (await asyncio.to_thread(_get_json, "https://api.ipify.org?format=json"))["ip"]
                    if ip != self.public_ip:
                        self.public_ip = ip
                        with self.lock:            # drop loopback "traffic" recorded before we knew our own address
                            self.db.execute("DELETE FROM flows WHERE dst = ?", (ip,))
                            self.db.commit()
                        g = self.geo.lookup(ip)
                        self.home = {"lat": g["lat"], "lon": g["lon"], "city": g["city"], "country": g["country"]}
                        self.dirty = True
                except Exception as e:
                    log.debug("Public IP lookup failed: %s", e)
            with self.lock:
                self.db.execute("DELETE FROM attacks WHERE t < ?", (time.time() - KEEP_DAYS * 86400,))
                self.db.commit()
            if getattr(self.nm, "local", None):
                self.nm.local.prune(KEEP_DAYS)
            if not self.nm.args.demo:
                try:
                    await asyncio.to_thread(self.refresh_c2)
                except Exception as e:
                    log.debug("C2 refresh failed: %s", e)
                if self.cfg.get("auto_intel", True):
                    try:
                        await self.enrich_top_attackers()
                    except Exception as e:
                        log.debug("Auto-enrich failed: %s", e)
            await asyncio.sleep(1800)

    async def enrich_top_attackers(self, limit: int = 8):
        """Warm the OSINT cache for the worst recent attackers, so their intel is ready when you look. Each lookup
        is skipped if already cached (6 h), and runs off the event loop. Only addresses that reached the LAN or
        hammered you are enriched, to keep outbound lookups modest."""
        now = time.time()
        with self.lock:
            rows = self.db.execute(
                "SELECT src, COUNT(*) c, SUM(action='allowed') reached FROM attacks WHERE t > ? "
                "GROUP BY src ORDER BY reached DESC, c DESC LIMIT ?", (now - 86400, limit)).fetchall()
        for src, cnt, reached in rows:
            if not is_public(src):
                continue
            hit = self.intel_cache.get(src)
            if hit and now - hit[0] < 6 * 3600:
                continue
            await asyncio.to_thread(self.intel, src)
            await asyncio.sleep(1.5)        # be gentle to the free OSINT services

    # ---- intake
    def find_target(self, ev: dict) -> str:
        if ev.get("lan_ip") and not is_public(str(ev["lan_ip"])):
            return str(ev["lan_ip"])
        dst = ev.get("dst") or ""
        if dst and not is_public(dst):
            try:
                if ipaddress.ip_address(dst) in ipaddress.ip_network(self.nm.net["subnet"], strict=False):
                    return dst
            except ValueError:
                pass
        for fw in self.cfg.get("forwards", []):
            if ev.get("dport") == fw.get("port") and fw.get("proto", "tcp") in (ev.get("proto"), "both"):
                return fw.get("lan_ip", "")
        return ""

    def ingest(self, raw: dict, sensor: str = "", t: float | None = None, geo: dict | None = None) -> dict | None:
        raw = sanitize_event(raw)
        if not raw:
            return None
        if is_self_redirect(raw):
            # Aimed at localhost: no device can reach another machine's 127.0.0.1, so this is the router redirecting
            # traffic to itself (UniFi DNS shield / ad blocking sends port 53 to its own resolver, for example).
            self.noise["total"] += 1
            self.noise["reasons"]["router redirect"] = self.noise["reasons"].get("router redirect", 0) + 1
            return None
        src = raw.get("src", "")
        if not self.is_external(src):
            if src == self.nm.net.get("my_ip"):
                return None
            dst = str(raw.get("dst") or "")
            if dst and (dst == self.public_ip or dst == src):
                return None             # NAT loopback (e.g. Plex checking itself via the public IP): not traffic, not a threat
            s = (raw.get("sensor") or sensor or "").lower()
            if dst and self.is_external(dst) and "honey" not in s and "ips" not in s:
                flows = getattr(self.nm, "flows", None)       # a LAN device talking to the internet
                if flows:
                    flows.add(src, dst, raw.get("dport"), raw.get("proto", "tcp"), raw.get("action") == "blocked")
                return None
            fl = raw.get("flags") or []
            if getattr(self.nm, "local", None) and dst and (not fl or ("SYN" in fl and "ACK" not in fl)):
                self.nm.local.observe_lan(src, dst, raw.get("dport"))      # lateral-movement tracking (LAN to LAN)
            if self.cfg.get("ignore_noise", True) and lan_noise_reason(raw):
                n = self.noise
                n["total"] += 1
                n["reasons"]["leftover between devices"] = n["reasons"].get("leftover between devices", 0) + 1
                return None
            if getattr(self.nm, "local", None):
                return self.nm.local.from_sensor(raw, sensor)   # LAN to LAN: a local threat
            return None
        if self.cfg.get("ignore_noise", True):
            why = noise_reason(raw, self.forwarded_ports())
            if why:
                n = self.noise
                n["total"] += 1
                n["reasons"][why] = n["reasons"].get(why, 0) + 1
                return None
        t = t or time.time()
        lan = self.find_target(raw)
        dev = next((d for d in self.nm.devices.values() if d["ip"] == lan), None) if lan else None
        g = geo or self.geo.lookup(src)
        ev = {"t": t, "src": src, "sport": raw.get("sport"), "dst": raw.get("dst") or self.public_ip,
              "dport": raw.get("dport"), "proto": raw.get("proto", "tcp"),
              "action": raw.get("action", "blocked"), "lan": lan, "lan_id": dev["id"] if dev else "",
              "lan_name": self.nm.label(dev) if dev else "",
              "service": raw.get("service") or service_for(raw.get("dport"), raw.get("proto", "tcp")),
              "sensor": raw.get("sensor") or sensor, "detail": raw.get("detail", ""),
              "country": g["country"], "iso": g["iso"], "city": g["city"], "lat": g["lat"], "lon": g["lon"],
              "tag": self.tags.get(src)}
        with self.lock:
            self.db.execute("INSERT INTO attacks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (t, src, ev["sport"], ev["dst"], ev["dport"], ev["proto"], ev["action"], lan,
                             ev["service"], ev["sensor"], ev["detail"], ev["country"], ev["iso"], ev["city"],
                             ev["lat"], ev["lon"]))
            self.uncommitted += 1
            if self.uncommitted >= 500 or time.time() - self.last_commit > 1.0:
                self.db.commit()                    # batch disk writes; a busy router log would otherwise stall
                self.uncommitted, self.last_commit = 0, time.time()
        self.last_event = t
        self.dirty = True
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.nm.broadcast({"type": "threat", "event": ev}))
            self.check_alerts(ev, dev)
        except RuntimeError:
            pass                    # no running loop (seeding)
        return ev

    def is_external(self, ip: str) -> bool:
        if is_public(ip):
            return True
        # the demo uses documentation-only ranges (RFC 5737) for its attackers
        return self.nm.args.demo and ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))

    def check_alerts(self, ev: dict, dev: dict | None):
        if ev.get("tag"):
            return                  # known research scanners don't alert
        if ev["action"] == "allowed" and dev:       # honeypot hits ("logged") are expected, so they don't alert
            self.nm.notify("attacks", dev, f"Attack reached {self.nm.label(dev)}",
                           f"{ev['src']} ({ev['country'] or 'unknown'}) hit {ev['service']} on port {ev['dport']}"
                           f" and was not blocked.", 5)
        q = self.burst.setdefault(ev["src"], collections.deque(maxlen=500))
        q.append(ev["t"])
        limit = int(self.cfg.get("burst_threshold", 25))
        while q and ev["t"] - q[0] > 300:
            q.popleft()
        if len(q) >= limit:
            fake = {"id": f"ip:{ev['src']}", "ip": ev["src"], "mac": "", "vendor": ev["country"], "type": "attacker"}
            self.nm.notify("attacks", fake, f"Attack burst from {ev['src']}",
                           f"{len(q)} attempts in 5 minutes from {ev['city'] or ''} {ev['country']}".strip(), 4)
        if len(self.burst) > 5000:
            self.burst.clear()

    # ---- reporting
    def summary(self, hours: int = 24) -> dict:
        since = time.time() - hours * 3600
        q = lambda sql, *a: self.db.execute(sql, (since, *a)).fetchall()
        with self.lock:
            total, uniq, blocked = q("SELECT COUNT(*), COUNT(DISTINCT src), SUM(action='blocked') FROM attacks WHERE t >= ?")[0]
            countries = q("SELECT iso, country, COUNT(*) c FROM attacks WHERE t >= ? AND iso != '' GROUP BY iso ORDER BY c DESC LIMIT 8")
            ncountries = q("SELECT COUNT(DISTINCT iso) FROM attacks WHERE t >= ? AND iso != ''")[0][0]
            ports = q("SELECT dport, service, COUNT(*) c FROM attacks WHERE t >= ? GROUP BY dport ORDER BY c DESC LIMIT 8")
            targets = q("SELECT lan, COUNT(*) c, SUM(action!='blocked') FROM attacks WHERE t >= ? AND lan != '' "
                        "GROUP BY lan ORDER BY c DESC LIMIT 6")
            attackers = q("SELECT src, COUNT(*) c, MAX(t), iso, country, city, lat, lon, GROUP_CONCAT(DISTINCT service) "
                          "FROM attacks WHERE t >= ? GROUP BY src ORDER BY c DESC LIMIT 150")
            hist = q("SELECT CAST((t - ?) / 3600 AS INT) h, COUNT(*) FROM attacks WHERE t >= ? GROUP BY h", since)
            recent = self.db.execute("SELECT t, src, dport, proto, action, lan, service, sensor, detail, iso, country, city "
                                     "FROM attacks ORDER BY t DESC LIMIT 60").fetchall()
            sigs = q("SELECT detail, COUNT(*) c, COUNT(DISTINCT src), MAX(t) FROM attacks WHERE t >= ? "
                     "AND sensor LIKE '%IPS%' AND detail != '' GROUP BY detail ORDER BY c DESC LIMIT 10")
        hbins = [0] * hours
        for h, c in hist:
            if 0 <= h < hours:
                hbins[h] = c
        by_ip = {d["ip"]: d for d in self.nm.devices.values()}
        ev_keys = ("t", "src", "dport", "proto", "action", "lan", "service", "sensor", "detail", "iso", "country", "city")
        recent_ev = []
        for r in recent:
            e = dict(zip(ev_keys, r))
            d = by_ip.get(e["lan"])
            e["lan_id"], e["lan_name"] = (d["id"], self.nm.label(d)) if d else ("", "")
            e["tag"] = self.tags.cache.get(e["src"])
            recent_ev.append(e)
        return {
            "type": "threat_summary", "hours": hours, "total": total or 0, "unique": uniq or 0,
            "blocked": blocked or 0, "countries_n": ncountries or 0,
            "countries": [{"iso": i, "country": c, "count": n} for i, c, n in countries],
            "ports": [{"port": p, "service": s, "count": n} for p, s, n in ports],
            "targets": [{"lan": ip, "count": n, "allowed": a or 0, "id": by_ip.get(ip, {}).get("id", ""),
                         "name": self.nm.label(by_ip[ip]) if ip in by_ip else ip,
                         "type": by_ip.get(ip, {}).get("type", "unknown")} for ip, n, a in targets],
            "attackers": [{"ip": ip, "count": n, "last": lt, "iso": iso, "country": c, "city": city, "lat": la,
                           "lon": lo, "services": (sv or "").split(",")[:4], "tag": self.tags.get(ip)}
                          for ip, n, lt, iso, c, city, la, lo, sv in attackers],
            "signatures": [{"name": n, "count": c, "ips": u, "last": lt} for n, c, u, lt in sigs],
            "hist": hbins, "recent": recent_ev, "public_ip": self.public_ip, "home": self.home,
            "sources": {"syslog": self.syslog_ok, "syslog_error": self.syslog_error,
                        "syslog_port": self.cfg.get("syslog_port", 514), "geoip": self.geo.reader is not None,
                        "last_event": self.last_event,
                        "rejected": [{"ip": ip, **r} for ip, r in sorted(self.syslog_rejected.items(),
                                                                          key=lambda kv: -kv[1]["last"])][:5],
                        "dropped": self.syslog_dropped, "gateway": self.nm.net.get("gateway", ""),
                        "ignored": {"total": self.noise["total"], "since": self.noise["since"],
                                    "reasons": self.noise["reasons"], "on": self.cfg.get("ignore_noise", True)}},
        }

    def investigate(self, ip: str) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT t, dport, proto, action, lan, service, sensor, detail FROM attacks "
                                   "WHERE src = ? ORDER BY t DESC LIMIT 2000", (ip,)).fetchall()
        by_ip = {d["ip"]: d for d in self.nm.devices.values()}
        ports, targets, sensors = collections.Counter(), collections.Counter(), collections.Counter()
        svc = {}
        blocked = 0
        hourly = [0] * 24
        now = time.time()
        for t, dport, proto, action, lan, service, sensor, detail in rows:
            ports[dport] += 1
            svc[dport] = service
            blocked += action == "blocked"
            if lan:
                targets[lan] += 1
            if sensor:
                sensors[sensor] += 1
            h = int((now - t) // 3600)
            if h < 24:
                hourly[23 - h] += 1
        keys = ("t", "dport", "proto", "action", "lan", "service", "sensor", "detail")
        recent = [dict(zip(keys, r)) for r in rows[:40]]
        for e in recent:
            d = by_ip.get(e["lan"])
            e["lan_id"], e["lan_name"] = (d["id"], self.nm.label(d)) if d else ("", "")
        out = {
            "ip": ip, "geo": self.geo.lookup(ip), "count": len(rows), "blocked": blocked,
            "first": rows[-1][0] if rows else None, "last": rows[0][0] if rows else None,
            "ports": [{"port": p, "service": svc[p], "count": n} for p, n in ports.most_common(12)],
            "targets": [{"lan": l, "count": n, "id": by_ip.get(l, {}).get("id", ""),
                         "name": self.nm.label(by_ip[l]) if l in by_ip else l,
                         "type": by_ip.get(l, {}).get("type", "unknown")} for l, n in targets.most_common(8)],
            "sensors": [{"name": s, "count": n} for s, n in sensors.most_common(5)],
            "hourly": hourly, "recent": recent, "credentials": [], "intel": self.intel(ip),
            "tag": self.tags.cache.get(ip),
            "signatures": [{"name": n, "count": c} for n, c in collections.Counter(
                r[7] for r in rows if r[7] and "IPS" in (r[6] or "")).most_common(8)],
        }
        creds = collections.Counter(e[7] for e in rows if e[7] and "IPS" not in (e[6] or ""))
        out["credentials"] = [{"text": c, "count": n} for c, n in creds.most_common(10)]
        return out

    def reached_ips(self, hours: int = 168) -> set:
        with self.lock:
            rows = self.db.execute("SELECT DISTINCT src FROM attacks WHERE action = 'allowed' AND t > ?",
                                   (time.time() - hours * 3600,)).fetchall()
        return {r[0] for r in rows}

    def intel(self, ip: str) -> dict:
        hit = self.intel_cache.get(ip)
        if hit and time.time() - hit[0] < 6 * 3600:
            return hit[1]
        if self.nm.args.demo:
            r = random.Random(ip)
            info = {"rdns": f"host-{ip.replace('.', '-')}.example.net", "isp": r.choice(["Example Hosting Ltd", "Demo Cloud Inc", "Sample Telecom"]),
                    "org": "Example VPS customer", "asn": f"AS{r.randint(64496, 64511)}", "as_name": "EXAMPLE-AS",
                    "hosting": r.random() > 0.3, "proxy": r.random() > 0.8, "mobile": False,
                    "abuse": {"score": r.choice([100, 100, 87, 64, 33]), "reports": r.randint(40, 4000),
                              "usage": "Data Center/Web Hosting/Transit", "tor": False, "domain": "example.net"},
                    "shodan": {"ports": sorted(r.sample([22, 23, 80, 443, 2222, 7547, 8080, 8443], 3)),
                               "vulns": r.sample(["CVE-2018-10562", "CVE-2017-17215", "CVE-2023-1389"], r.randint(0, 2)),
                               "tags": r.sample(["compromised", "scanner", "self-signed", "iot"], 2), "hostnames": []},
                    "greynoise": ({"classification": "benign", "name": DEMO_SCANNERS[ip], "noise": True, "riot": False}
                                  if ip in DEMO_SCANNERS else {"classification": "malicious", "name": "unknown", "noise": True, "riot": False}),
                    "threatfox": ({"found": True, "count": r.randint(1, 6), "malware": r.sample(["Mirai", "Cobalt Strike", "RedLine Stealer", "Gafgyt"], 2), "types": ["botnet_cc"]}
                                  if ip not in DEMO_SCANNERS and r.random() > 0.5 else {"found": False}),
                    "tor": ip not in DEMO_SCANNERS and r.random() > 0.85,
                    "errors": {}}
            self.intel_cache[ip] = (time.time(), info)
            return info
        info = {"rdns": "", "isp": "", "org": "", "asn": "", "as_name": "", "hosting": None, "proxy": None,
                "mobile": None, "abuse": None, "shodan": None, "errors": {}}
        try:
            info["rdns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        try:
            r = _get_json(f"http://ip-api.com/json/{ip}?fields=status,message,isp,org,as,asname,mobile,proxy,hosting")
            if r.get("status") == "success":
                info.update({"isp": r.get("isp", ""), "org": r.get("org", ""), "asn": (r.get("as") or "").split(" ")[0],
                             "as_name": r.get("asname", ""), "hosting": r.get("hosting"), "proxy": r.get("proxy"),
                             "mobile": r.get("mobile")})
        except Exception as e:
            info["errors"]["ip-api"] = str(e)
        try:
            s = _get_json(f"https://internetdb.shodan.io/{ip}")
            info["shodan"] = {"ports": s.get("ports", []), "vulns": s.get("vulns", [])[:12], "tags": s.get("tags", []),
                              "hostnames": s.get("hostnames", [])[:5]}
        except urllib.error.HTTPError as e:
            info["shodan"] = {"ports": [], "vulns": [], "tags": [], "hostnames": []} if e.code == 404 else None
        except Exception as e:
            info["errors"]["shodan"] = str(e)
        key = self.cfg.get("abuseipdb_key")
        if key:
            try:
                a = _get_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                              {"Key": key})["data"]
                info["abuse"] = {"score": a.get("abuseConfidenceScore"), "reports": a.get("totalReports"),
                                 "usage": a.get("usageType", ""), "tor": a.get("isTor"), "domain": a.get("domain", "")}
            except Exception as e:
                info["errors"]["abuseipdb"] = str(e)
        try:
            gn = _get_json(f"https://api.greynoise.io/v3/community/{ip}")
            info["greynoise"] = {"classification": gn.get("classification", ""), "name": gn.get("name", ""),
                                 "noise": gn.get("noise"), "riot": gn.get("riot"), "last_seen": gn.get("last_seen", "")}
            if gn.get("classification") == "benign" and gn.get("name") and not self.tags.cache.get(ip):
                self.tags.set(ip, {"tag": "scanner", "label": gn["name"], "host": "GreyNoise"})
        except urllib.error.HTTPError as e:
            info["greynoise"] = {"classification": "unknown", "name": "", "noise": False, "riot": False} if e.code == 404 else None
        except Exception as e:
            info["errors"]["greynoise"] = str(e)
        # abuse.ch ThreatFox: is this IP a known malware command-and-control / botnet address?
        # ThreatFox now requires a free abuse.ch Auth-Key (the same one the malware list uses, Settings > DNS).
        tf_key = (self.nm.settings.get("dns", {}).get("abuse_key") or self.cfg.get("abuse_key") or "").strip()
        if not tf_key:
            info["threatfox"] = {"found": False, "need_key": True}
        else:
            try:
                tf = _post_json(THREATFOX_API, {"query": "search_ioc", "search_term": ip}, {"Auth-Key": tf_key})
                if tf.get("query_status") == "ok" and tf.get("data"):
                    rows = tf["data"][:5]
                    info["threatfox"] = {"found": True, "count": len(tf["data"]),
                                         "malware": sorted({r.get("malware_printable") or r.get("malware") or "" for r in rows if r.get("malware_printable") or r.get("malware")})[:5],
                                         "types": sorted({r.get("threat_type") or "" for r in rows if r.get("threat_type")})[:4]}
                else:
                    info["threatfox"] = {"found": False}
            except urllib.error.HTTPError as e:
                info["threatfox"] = {"found": False, "need_key": True} if e.code in (401, 403) else None
                if e.code not in (401, 403):
                    info["errors"]["threatfox"] = f"HTTP {e.code}"
            except Exception as e:
                info["errors"]["threatfox"] = str(e)[:120]
        # Tor exit node?
        self.refresh_tor()
        if self.tor_exits:
            info["tor"] = ip in self.tor_exits
        self.intel_cache[ip] = (time.time(), info)
        return info

    def known_c2(self, ip: str) -> bool:
        return ip in self.c2_ips

    def refresh_c2(self):
        """Keep a daily copy of abuse.ch Feodo Tracker's botnet command-and-control IP list, so an outbound
        connection from one of your own devices to a known C2 can be caught (a sign that device is compromised)."""
        p = self.data_dir / "c2-ips.txt"
        try:
            if not p.exists() or time.time() - p.stat().st_mtime > 86400:
                req = urllib.request.Request(FEODO_C2_LIST, headers={"User-Agent": "LanPulse"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    data = r.read(5_000_000).decode("utf-8", "replace")
                ips = {ln.strip() for ln in data.splitlines() if ln.strip() and not ln.startswith("#")}
                if len(ips) > 10:
                    tmp = p.with_suffix(".tmp")
                    tmp.write_text("\n".join(sorted(ips)))
                    tmp.replace(p)
        except Exception as e:
            log.debug("C2 list refresh failed: %s", e)
        try:
            if p.exists() and p.stat().st_mtime != self.c2_loaded:
                self.c2_ips = {ln.strip() for ln in p.read_text().splitlines() if ln.strip()}
                self.c2_loaded = p.stat().st_mtime
        except OSError:
            pass

    def refresh_tor(self):
        """Keep a daily copy of the Tor exit-node list, so an attacker IP can be flagged as coming through Tor."""
        p = self.data_dir / "tor-exits.txt"
        try:
            if not p.exists() or time.time() - p.stat().st_mtime > 86400:
                req = urllib.request.Request(TOR_EXIT_LIST, headers={"User-Agent": "LanPulse"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    data = r.read(5_000_000).decode("utf-8", "replace")
                ips = {ln.strip() for ln in data.splitlines() if ln.strip() and not ln.startswith("#")}
                if len(ips) > 100:                       # sanity: the real list has thousands
                    tmp = p.with_suffix(".tmp")
                    tmp.write_text("\n".join(sorted(ips)))
                    tmp.replace(p)
        except Exception as e:
            log.debug("Tor exit list refresh failed: %s", e)
        try:
            if p.exists() and p.stat().st_mtime != self.tor_loaded:
                self.tor_exits = {ln.strip() for ln in p.read_text().splitlines() if ln.strip()}
                self.tor_loaded = p.stat().st_mtime
        except OSError:
            pass

    # ---- demo
    def _demo_event(self, t: float):
        a = random.choices(DEMO_ATTACKERS, weights=[9, 7, 4, 5, 6, 4, 3, 3, 3, 4, 2, 3, 2, 2, 3, 2])[0]
        port = random.choices([p for p, _ in DEMO_PORTS], weights=[w for _, w in DEMO_PORTS])[0]
        geo = {"country": a[1], "iso": a[2], "city": a[3], "lat": a[4], "lon": a[5]}
        lan_ip = {23: "192.168.1.121", 22: "192.168.1.140", 80: "192.168.1.120", 8080: "192.168.1.20"}.get(port, "")
        allowed = lan_ip and random.random() < 0.6
        raw = {"src": a[0], "dport": port, "proto": "tcp", "action": "allowed" if allowed else "blocked",
               "lan_ip": lan_ip if allowed else "", "detail": random.choice(DEMO_DETAILS.get(port, [""])) if allowed else "",
               "sensor": "esp32-honeypot" if port in (21, 22, 23, 25) and allowed else "router firewall"}
        if not allowed and port in DEMO_SIGS and random.random() < 0.35:
            raw.update(sensor="UniFi Network IPS", detail=random.choice(DEMO_SIGS[port]))
        return self.ingest(raw, t=t, geo=geo)

    def seed_demo(self):
        with self.lock:
            n = self.db.execute("SELECT COUNT(*) FROM attacks WHERE t > ?", (time.time() - 86400,)).fetchone()[0]
        if n > 100:
            return
        now = time.time()
        for _ in range(1400):
            self._demo_event(now - random.random() ** 0.8 * 86400)

    async def demo_loop(self):
        while True:
            await asyncio.sleep(random.uniform(0.4, 2.2))
            self._demo_event(time.time())
