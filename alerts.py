# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Alert delivery for LanPulse: ntfy, Telegram, webhook (Discord/Slack/generic), email and IRC."""
from __future__ import annotations

import copy
import datetime
import ipaddress
import json
import logging
import re
import smtplib
import socket
import ssl
import time
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("lanpulse.alerts")

MASK = "••••••"
SECRET_FIELDS = {"token", "bot_token", "password", "key"}

DEFAULT_SETTINGS = {
    "rules": {
        "new_device": True,        # an untrusted device joins the network
        "watched_offline": True,   # a watched device goes offline or comes back
        "new_port": True,          # a device opens a port it didn't have before
        "security": True,          # a new high-severity security warning appears
        "attacks": True,           # an attack gets through to a LAN device, or one IP hammers you
        "local_threats": True,     # a LAN device scans, spoofs the router or touches a honeypot
        "compromise": True,        # a LAN device connects out to a known botnet C2 (likely infected)
        "anomaly": True,           # a device behaves unusually (new outbound region, traffic spike)
        "dns_threats": True,       # a device looks up a known malware domain
        "vulns": True,             # a device runs software with an actively exploited vulnerability
        "services": True,          # a watched service goes down or comes back
    },
    "channels": {
        "ntfy": {"enabled": False, "min_level": 1, "max_per_hour": 0, "url": "https://ntfy.sh/my-lanpulse", "token": ""},
        "telegram": {"enabled": False, "min_level": 1, "max_per_hour": 0, "bot_token": "", "chat_id": ""},
        "webhook": {"enabled": False, "min_level": 1, "max_per_hour": 0, "url": ""},
        "email": {"enabled": False, "min_level": 1, "max_per_hour": 0, "host": "", "port": 587, "starttls": True, "user": "", "password": "",
                  "from": "", "to": ""},
        "irc": {"enabled": False, "min_level": 1, "max_per_hour": 0, "host": "", "port": 6697, "tls": True, "tls_verify": False,
                "nick": "lanpulse", "channel": "#alerts", "key": ""},
    },
    "threats": {"enabled": True, "syslog_port": 514, "burst_threshold": 25, "abuseipdb_key": "",
                "ingest_key": "", "forwards": [], "ignore_noise": True,
                "syslog_from": [], "syslog_any": False, "auto_intel": True},
    "local": {"enabled": True, "sweep_threshold": 40, "scan_threshold": 15, "lateral_threshold": 5, "ignore": [],
              "dhcp_check": True, "dhcp_probe": False, "dhcp_servers": [], "gateway_mac": ""},
    "summary": {"enabled": False, "time": "08:00", "last_sent": ""},
    "unifi": {"host": "", "api_key": "", "username": "", "password": "", "site": "default",
              "group": "LanPulse Blocklist", "verify_tls": False},
    "snmp": {"enabled": False, "community": "", "hosts": []},
    "notify": {"repeat_minutes": 10},   # the same alert is sent at most this often
    "quiet": {"until": 0},         # quiet mode: no alert messages are sent until this time (epoch seconds)
    "layout": {},
    "dns": {"enabled": False, "provider": "pihole", "url": "", "username": "", "password": "", "verify_tls": False, "malware": True, "abuse_key": ""},
    "vulns": {"enabled": True, "nvd_key": ""},
    "honeypot": {"enabled": False, "bind": "0.0.0.0", "ingest_key": "",
                 "services": {"ssh": False, "telnet": True, "ftp": True, "http": False,
                              "smb": True, "rdp": True, "mysql": True},
                 "ports": {}, "banners": {}, "retention_days": 90, "flood_max": 12, "flood_minutes": 10,
                 "alert_external": True, "ignore": "", "delay_ms": 0},
    "openvas": {"enabled": False, "auto": False, "username": "admin", "password": ""},
    "wizard": {"done": False},
    "ai": {"enabled": False, "provider": "ollama", "base_url": "", "model": "", "api_key": ""},
    "keys": {"abuseipdb": "", "abusech": "", "nvd": "", "ai": "", "unifi": ""},
    "services": {"checks": []},
    "system": {"iface": "", "subnet": "", "interval": 10, "offline_after": 0, "rescan": 60, "top_ports": 1000,
               "deep": True, "workers": 2, "port": 8080, "https": False, "host": "0.0.0.0", "allow_hosts": []},
}

# System settings that only take effect after LanPulse restarts
SYSTEM_RESTART = ("iface", "subnet", "workers", "port", "https", "host")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$")


def clean_system(incoming: dict, current: dict) -> tuple[dict, list[str]]:
    """Validate Settings > System. Returns the new values and a list of problems (fields left unchanged)."""
    out, bad = dict(current), []

    def num(key, lo, hi, cast=int):
        if key not in incoming:
            return
        try:
            v = cast(incoming[key])
            if not lo <= v <= hi:
                raise ValueError
            out[key] = v
        except (TypeError, ValueError):
            bad.append(f"{key} must be between {lo} and {hi}")

    if "iface" in incoming:
        v = str(incoming["iface"] or "").strip()
        if v and not re.match(r"^[\w.:-]{1,32}$", v):
            bad.append("interface name isn't valid")
        else:
            out["iface"] = v
    if "subnet" in incoming:
        v = str(incoming["subnet"] or "").strip()
        if v:
            try:
                net = ipaddress.ip_network(v, strict=False)
                if net.version != 4 or not 16 <= net.prefixlen <= 30:
                    raise ValueError
                v = str(net)
            except ValueError:
                bad.append("subnet must look like 192.168.0.0/24 (between /16 and /30)")
                v = None
        if v is not None:
            out["subnet"] = v
    num("interval", 3, 300, float)
    num("offline_after", 0, 86400, float)
    num("rescan", 5, 10080, float)
    num("top_ports", 20, 65535)
    num("workers", 1, 4)
    num("port", 1, 65535)
    for k in ("deep", "https"):
        if k in incoming:
            out[k] = bool(incoming[k])
    if "host" in incoming:
        if incoming["host"] in ("0.0.0.0", "127.0.0.1", "::"):
            out["host"] = incoming["host"]
        else:
            bad.append("listen address must be all addresses or this machine only")
    if "allow_hosts" in incoming and isinstance(incoming["allow_hosts"], list):
        hosts = [str(h).strip().lower() for h in incoming["allow_hosts"][:20] if str(h).strip()]
        if all(_HOSTNAME.match(h) for h in hosts):
            out["allow_hosts"] = hosts
        else:
            bad.append("extra host names must be plain names like lanpulse.example.com")
    return out, bad


def with_defaults(s: dict | None) -> dict:
    out = copy.deepcopy(DEFAULT_SETTINGS)
    for k, v in (s or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            for k2, v2 in v.items():
                if isinstance(v2, dict) and isinstance(out[k].get(k2), dict):
                    out[k][k2].update(v2)
                else:
                    out[k][k2] = v2
        else:
            out[k] = v
    # Compatibility: migrate the temporary MalwareBazaar-only field to the shared abuse.ch key.
    legacy_mb_key = out.get("threats", {}).pop("malwarebazaar_key", "")
    if legacy_mb_key and not out.get("dns", {}).get("abuse_key"):
        out["dns"]["abuse_key"] = re.sub(r"[\r\n\x00-\x1f\x7f]", "", str(legacy_mb_key)).strip()[:100]
    # Central API-key vault: migrate existing credentials without asking the user to re-enter them.
    keys = out.setdefault("keys", {})
    legacy = {
        "abuseipdb": out.get("threats", {}).get("abuseipdb_key", ""),
        "abusech": out.get("dns", {}).get("abuse_key", ""),
        "nvd": out.get("vulns", {}).get("nvd_key", ""),
        "ai": out.get("ai", {}).get("api_key", ""),
        "unifi": out.get("unifi", {}).get("api_key", ""),
    }
    for name, value in legacy.items():
        if name == "abusech":
            value = "".join(ch for ch in str(keys.get(name) or value or "").strip() if 33 <= ord(ch) <= 126)[:100]
        else:
            value = keys.get(name) or value
        if value and not keys.get(name):
            keys[name] = value
        elif name == "abusech":
            keys[name] = value
        if keys.get(name):
            target = {"abuseipdb": ("threats", "abuseipdb_key"), "abusech": ("dns", "abuse_key"),
                      "nvd": ("vulns", "nvd_key"), "ai": ("ai", "api_key"), "unifi": ("unifi", "api_key")}[name]
            out[target[0]][target[1]] = keys[name]
    return out


def masked(s: dict) -> dict:
    out = copy.deepcopy(s)
    out.pop("layout", None)
    for name in ("abuseipdb", "abusech", "nvd", "ai", "unifi"):
        if out.get("keys", {}).get(name):
            out["keys"][name] = MASK
    for ch in out["channels"].values():
        for f in SECRET_FIELDS:
            if ch.get(f):
                ch[f] = MASK
    for f in ("abuseipdb_key",):
        if out["threats"].get(f):
            out["threats"][f] = MASK
    if out.get("dns", {}).get("password"):
        out["dns"]["password"] = MASK
    if out.get("dns", {}).get("abuse_key"):
        out["dns"]["abuse_key"] = MASK
    if out.get("vulns", {}).get("nvd_key"):
        out["vulns"]["nvd_key"] = MASK
    if out.get("honeypot", {}).get("ingest_key"):
        out["honeypot"]["ingest_key"] = MASK
    if out.get("openvas", {}).get("password"):
        out["openvas"]["password"] = MASK
    if out.get("ai", {}).get("api_key"):
        out["ai"]["api_key"] = MASK
    for f in ("api_key", "password"):
        if out["unifi"].get(f):
            out["unifi"][f] = MASK
    if out.get("snmp", {}).get("community"):
        out["snmp"]["community"] = MASK
    return out


# Where each saved secret is sent. If one of these addresses changes and the secret was not typed in again, the secret
# is forgotten: otherwise changing only the address would send a stored key or password to a new place.
_SECRET_TARGETS = (
    (("channels", "ntfy"), ("url",), ("token",)),
    (("channels", "email"), ("host",), ("password",)),
    (("channels", "irc"), ("host",), ("key",)),
    (("unifi",), ("host",), ("api_key", "password")),
    (("dns",), ("url", "provider", "username"), ("password",)),
    (("ai",), ("provider", "base_url"), ("api_key",)),
)


def _drop_moved_secrets(current: dict, new: dict, incoming: dict) -> None:
    for path, where, secret_fields in _SECRET_TARGETS:
        cur, nw, inc = current, new, incoming
        for p in path:
            cur = (cur.get(p) if isinstance(cur, dict) else None) or {}
            nw = (nw.get(p) if isinstance(nw, dict) else None) or {}
            inc = (inc.get(p) if isinstance(inc, dict) else None) or {}
        if not isinstance(nw, dict) or all(cur.get(w) == nw.get(w) for w in where):
            continue
        for s in secret_fields:
            retyped = isinstance(inc, dict) and inc.get(s) not in (None, "", MASK)
            if cur.get(s) and not retyped:
                nw[s] = ""


def apply_update(current: dict, incoming: dict) -> dict:
    new = copy.deepcopy(current)
    for k, v in (incoming.get("rules") or {}).items():
        if k in new["rules"]:
            new["rules"][k] = bool(v)
    for name, fields in (incoming.get("channels") or {}).items():
        if name not in new["channels"]:
            continue
        ch = new["channels"][name]
        for f, v in fields.items():
            if f not in ch or (f in SECRET_FIELDS and v == MASK):
                continue
            default = DEFAULT_SETTINGS["channels"][name][f]
            if isinstance(default, bool):
                v = bool(v)
            elif isinstance(default, int):
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    v = default
            else:
                v = str(v).strip()
                if f == "url" and v and not v.lower().startswith(("http://", "https://")):
                    v = ""                          # alerts only ever go to web addresses
            ch[f] = v
        ch["min_level"] = ch.get("min_level") if ch.get("min_level") in LEVELS else 1
        ch["max_per_hour"] = max(0, min(int(ch.get("max_per_hour") or 0), 1000))
    nt = incoming.get("notify")
    if isinstance(nt, dict):
        try:
            minutes = int(nt.get("repeat_minutes"))
        except (TypeError, ValueError):
            minutes = new["notify"].get("repeat_minutes", 10)
        new["notify"]["repeat_minutes"] = max(1, min(minutes, 1440))
    t = incoming.get("threats")
    if isinstance(t, dict):
        cur = new["threats"]
        if "enabled" in t:
            cur["enabled"] = bool(t["enabled"])
        if "ignore_noise" in t:
            cur["ignore_noise"] = bool(t["ignore_noise"])
        if "syslog_any" in t:
            cur["syslog_any"] = bool(t["syslog_any"])
        if isinstance(t.get("syslog_from"), list):
            ok = []
            for x in t["syslog_from"][:20]:
                try:
                    ok.append(str(ipaddress.ip_address(str(x).strip())))
                except ValueError:
                    pass
            cur["syslog_from"] = sorted(set(ok))
        for f, lo, hi in (("syslog_port", 1, 65535), ("burst_threshold", 3, 10000)):
            if f in t:
                try:
                    cur[f] = max(lo, min(hi, int(t[f])))
                except (TypeError, ValueError):
                    pass
        if "abuseipdb_key" in t and t["abuseipdb_key"] != MASK:
            cur["abuseipdb_key"] = str(t["abuseipdb_key"]).strip()[:200]
        if "auto_intel" in t:
            cur["auto_intel"] = bool(t["auto_intel"])
        if isinstance(t.get("forwards"), list):
            fw = []
            for r in t["forwards"][:50]:
                try:
                    port = int(r.get("port"))
                except (TypeError, ValueError, AttributeError):
                    continue
                proto = r.get("proto") if r.get("proto") in ("tcp", "udp", "both") else "tcp"
                if 0 < port < 65536 and r.get("lan_ip"):
                    fw.append({"port": port, "proto": proto, "lan_ip": str(r["lan_ip"]).strip()[:45]})
            cur["forwards"] = fw
    lc = incoming.get("local")
    if isinstance(lc, dict):
        cur = new["local"]
        if "enabled" in lc:
            cur["enabled"] = bool(lc["enabled"])
        for f, lo, hi in (("sweep_threshold", 10, 1000), ("scan_threshold", 5, 1000), ("lateral_threshold", 3, 100)):
            if f in lc:
                try:
                    cur[f] = max(lo, min(hi, int(lc[f])))
                except (TypeError, ValueError):
                    pass
        if isinstance(lc.get("ignore"), list):
            cur["ignore"] = [str(x).strip()[:45] for x in lc["ignore"] if str(x).strip()][:100]
        if "dhcp_check" in lc:
            cur["dhcp_check"] = bool(lc["dhcp_check"])
        if "dhcp_probe" in lc:
            cur["dhcp_probe"] = bool(lc["dhcp_probe"])
        if isinstance(lc.get("dhcp_servers"), list):
            ok = []
            for x in lc["dhcp_servers"][:20]:
                try:
                    ok.append(str(ipaddress.ip_address(str(x).strip())))
                except ValueError:
                    pass
            cur["dhcp_servers"] = ok
        if lc.get("reset_gateway"):             # learn the router's hardware address again (after replacing it)
            cur["gateway_mac"] = ""
        # gateway_mac itself is only ever learned by LanPulse, never set from the browser
    sm = incoming.get("summary")
    if isinstance(sm, dict):
        cur = new["summary"]
        if "enabled" in sm:
            cur["enabled"] = bool(sm["enabled"])
        t = str(sm.get("time", cur["time"]))
        if len(t) == 5 and t[2] == ":" and t[:2].isdigit() and t[3:].isdigit() and int(t[:2]) < 24 and int(t[3:]) < 60:
            cur["time"] = t
    uf = incoming.get("unifi")
    if isinstance(uf, dict):
        cur = new["unifi"]
        for f in ("host", "api_key", "username", "password", "site", "group"):
            if f in uf and not (f in ("api_key", "password") and uf[f] == MASK):
                cur[f] = str(uf[f]).strip()[:200]
        if "verify_tls" in uf:
            cur["verify_tls"] = bool(uf["verify_tls"])
        if not re.fullmatch(r"[A-Za-z0-9._-]+(:\d{1,5})?|\[[0-9A-Fa-f:]+\](:\d{1,5})?", cur["host"] or "x"):
            cur["host"] = ""                     # a bare host or IP (optionally :port); no paths, no user@, no spaces
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", cur["site"] or "default"):
            cur["site"] = "default"              # goes into a URL path
        cur["site"] = cur["site"] or "default"
        cur["group"] = cur["group"] or "LanPulse Blocklist"
    sn = incoming.get("snmp")
    if isinstance(sn, dict):
        cur = new["snmp"]
        if "enabled" in sn:
            cur["enabled"] = bool(sn["enabled"])
        if "community" in sn and sn["community"] != MASK:
            cur["community"] = re.sub(r"[^\x21-\x7e]", "", str(sn["community"]))[:64]
        if "hosts" in sn:
            raw = sn["hosts"] if isinstance(sn["hosts"], list) else re.split(r"[\s,;]+", str(sn["hosts"]))
            from snmpdisc import valid_host
            cur["hosts"] = list(dict.fromkeys(h for h in (valid_host(x) for x in raw) if h))[:20]
    dn = incoming.get("dns")
    if isinstance(dn, dict):
        cur = new["dns"]
        for f in ("enabled", "verify_tls", "malware"):
            if f in dn:
                cur[f] = bool(dn[f])
        if str(dn.get("provider")) in ("pihole", "adguard"):
            cur["provider"] = str(dn["provider"])
        if "username" in dn:
            cur["username"] = re.sub(r"[\x00-\x1f\x7f:]", "", str(dn["username"]))[:100]
        if "url" in dn:
            u = str(dn["url"]).strip().rstrip("/")[:200]
            if u and not u.startswith(("http://", "https://")):
                u = "http://" + u
            cur["url"] = u.removesuffix("/admin")
        if "password" in dn and dn["password"] != MASK:
            cur["password"] = str(dn["password"])[:200]
        if "abuse_key" in dn and dn["abuse_key"] != MASK:
            cur["abuse_key"] = re.sub(r"[\r\n\x00-\x1f\x7f]", "", str(dn["abuse_key"])).strip()[:100]
    vu = incoming.get("vulns")
    if isinstance(vu, dict):
        cur = new["vulns"]
        if "enabled" in vu:
            cur["enabled"] = bool(vu["enabled"])
        if "nvd_key" in vu and vu["nvd_key"] != MASK:
            cur["nvd_key"] = re.sub(r"[^A-Za-z0-9-]", "", str(vu["nvd_key"]))[:64]
    hp = incoming.get("honeypot")
    if isinstance(hp, dict):
        cur = new["honeypot"]
        if "enabled" in hp:
            cur["enabled"] = bool(hp["enabled"])
        if "bind" in hp:
            b = str(hp["bind"]).strip()
            if b in ("0.0.0.0", "::", ""):
                cur["bind"] = b or "0.0.0.0"
            else:
                try:
                    cur["bind"] = str(ipaddress.ip_address(b))
                except ValueError:
                    pass
        if "ingest_key" in hp and hp["ingest_key"] != MASK:
            cur["ingest_key"] = re.sub(r"[^A-Za-z0-9_-]", "", str(hp["ingest_key"]))[:64]
        if isinstance(hp.get("services"), dict):
            for k in list(cur["services"]):
                if k in hp["services"]:
                    cur["services"][k] = bool(hp["services"][k])
        if isinstance(hp.get("ports"), dict):
            ports = {}
            for k in cur["services"]:
                try:
                    n = int(hp["ports"].get(k))
                except (TypeError, ValueError):
                    continue
                if 1 <= n <= 65535:
                    ports[k] = n
            cur["ports"] = ports                      # a missing key means "use the default port"
        if isinstance(hp.get("banners"), dict):
            keep = ("ssh", "telnet", "ftp", "http_server", "http_title")
            cur["banners"] = {k: " ".join("".join(c for c in str(hp["banners"][k]) if 32 <= ord(c) < 127).split())[:80]
                              for k in keep if str(hp["banners"].get(k) or "").strip()}
        for k, lo, hi in (("retention_days", 1, 365), ("flood_max", 1, 500), ("flood_minutes", 1, 120), ("delay_ms", 0, 5000)):
            if k in hp:
                try:
                    cur[k] = max(lo, min(hi, int(hp[k])))
                except (TypeError, ValueError):
                    pass
        if "alert_external" in hp:
            cur["alert_external"] = bool(hp["alert_external"])
        if "ignore" in hp:
            ok = []
            for tok in re.split(r"[\s,;]+", str(hp["ignore"])):
                try:
                    ok.append(str(ipaddress.ip_network(tok, strict=False)) if "/" in tok else str(ipaddress.ip_address(tok)))
                except ValueError:
                    continue
            cur["ignore"] = "\n".join(ok[:100])
    ov = incoming.get("openvas")
    if isinstance(ov, dict):
        cur = new["openvas"]
        for f in ("enabled", "auto"):
            if f in ov:
                cur[f] = bool(ov[f])
        if "username" in ov:
            cur["username"] = re.sub(r"[^\w.@\-]", "", str(ov["username"]))[:64] or "admin"
        if "password" in ov and ov["password"] != MASK:
            cur["password"] = re.sub(r"[^\x21-\x7e]", "", str(ov["password"]))[:128]
    wz = incoming.get("wizard")
    if isinstance(wz, dict) and "done" in wz:
        new["wizard"]["done"] = bool(wz["done"])
    ai = incoming.get("ai")
    if isinstance(ai, dict):
        cur = new["ai"]
        if "enabled" in ai:
            cur["enabled"] = bool(ai["enabled"])
        if ai.get("provider") in ("ollama", "openai", "anthropic"):
            cur["provider"] = ai["provider"]
        if "base_url" in ai:
            u = str(ai["base_url"]).strip()[:300]
            if not u or re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+(:\d+)?(/[\w./\-~%]*)?$", u):
                cur["base_url"] = u.rstrip("/")
        if "model" in ai:
            cur["model"] = re.sub(r"[^\w.:/\-@]", "", str(ai["model"]))[:120]
        if "api_key" in ai and ai["api_key"] != MASK:
            cur["api_key"] = re.sub(r"[^\x21-\x7e]", "", str(ai["api_key"]))[:300]
    sv = incoming.get("services")
    if isinstance(sv, dict) and isinstance(sv.get("checks"), list):
        new["services"]["checks"] = [c for c in (clean_check(x) for x in sv["checks"][:50]) if c]
    # API credentials are edited only in Settings > Keys. Keep legacy storage fields synchronized
    # so existing service code and older settings backups remain compatible.
    key_input = incoming.get("keys")
    key_targets = {"abuseipdb": ("threats", "abuseipdb_key"), "abusech": ("dns", "abuse_key"),
                   "nvd": ("vulns", "nvd_key"), "ai": ("ai", "api_key"), "unifi": ("unifi", "api_key")}
    if isinstance(key_input, dict):
        for name, (section, field) in key_targets.items():
            if name in key_input and key_input[name] != MASK:
                raw = str(key_input[name] or "").strip()
                limits = {"abuseipdb": 200, "abusech": 100, "nvd": 64, "ai": 300, "unifi": 200}
                if name in ("abuseipdb", "abusech", "unifi"):
                    raw = "".join(ch for ch in raw if 33 <= ord(ch) <= 126)
                elif name == "nvd":
                    raw = re.sub(r"[^A-Za-z0-9-]", "", raw)
                elif name == "ai":
                    raw = re.sub(r"[^\x21-\x7e]", "", raw)
                new["keys"][name] = raw[:limits[name]]
                new[section][field] = new["keys"][name]
    else:
        # Accept legacy clients and synchronize their edits into the central key store.
        legacy_inputs = (("threats", "abuseipdb_key", "abuseipdb"), ("dns", "abuse_key", "abusech"),
                         ("vulns", "nvd_key", "nvd"), ("ai", "api_key", "ai"), ("unifi", "api_key", "unifi"))
        for section, field, name in legacy_inputs:
            part = incoming.get(section)
            if isinstance(part, dict) and field in part and part[field] != MASK:
                new["keys"][name] = new[section][field]
    _drop_moved_secrets(current, new, incoming)
    # Keep the vault aligned when a provider/host change deliberately invalidates a credential.
    for name, (section, field) in key_targets.items():
        new["keys"][name] = new[section].get(field, "")
    return new


CHECK_TYPES = ("http", "tcp", "ping")
_HOST_RE = re.compile(r"^[A-Za-z0-9\[][A-Za-z0-9._:\-\[\]]{0,252}$")    # never starts with "-" (would be read as an option)


def clean_check(c) -> dict | None:
    """Validate one Services check from the dashboard."""
    if not isinstance(c, dict):
        return None
    kind = c.get("type") if c.get("type") in CHECK_TYPES else "http"
    target = str(c.get("target") or "").strip()[:300]
    if kind == "http":
        if not re.match(r"^https?://[^\s/$.?#][^\s]*$", target):
            return None
    elif not _HOST_RE.match(target):
        return None
    try:
        port = int(c.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if kind == "tcp" and not 0 < port < 65536:
        return None
    try:
        interval = max(15, min(3600, int(c.get("interval") or 60)))
    except (TypeError, ValueError):
        interval = 60
    cid = re.sub(r"[^a-z0-9]", "", str(c.get("id") or ""))[:16] or secrets_token()
    return {"id": cid, "name": " ".join(str(c.get("name") or target).split())[:60], "type": kind, "target": target,
            "port": port if kind == "tcp" else 0, "interval": interval, "verify_tls": bool(c.get("verify_tls")),
            "enabled": c.get("enabled", True) is not False, "device": str(c.get("device") or "")[:40]}


def secrets_token() -> str:
    import secrets
    return secrets.token_hex(5)


# --------------------------------------------------------------------------- channels
def _post(url: str, data: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "LanPulse", **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=12) as r:
        r.read()


def send_ntfy(c, title, msg, priority):
    headers = {"Title": title.encode("ascii", "ignore").decode(), "Tags": "satellite",
               "Priority": "high" if priority >= 4 else "default"}
    if c.get("token"):
        headers["Authorization"] = f"Bearer {c['token']}"
    _post(c["url"], msg.encode(), headers)


def send_telegram(c, title, msg, priority):
    url = f"https://api.telegram.org/bot{c['bot_token']}/sendMessage"
    _post(url, json.dumps({"chat_id": c["chat_id"], "text": f"{title}\n{msg}"}).encode(),
          {"Content-Type": "application/json"})


def send_webhook(c, title, msg, priority, event=None):
    text = f"**{title}**\n{msg}"
    body = {"title": title, "message": msg, "priority": priority, "event": event or {},
            "content": text, "text": text}       # Discord uses "content", Slack uses "text"
    _post(c["url"], json.dumps(body).encode(), {"Content-Type": "application/json"})


def send_email(c, title, msg, priority):
    m = EmailMessage()
    m["Subject"] = f"[LanPulse] {title}"
    m["From"] = c["from"] or c["user"]
    m["To"] = c["to"]
    m.set_content(msg)
    port = int(c["port"])
    if port == 465:
        s = smtplib.SMTP_SSL(c["host"], port, timeout=15, context=ssl.create_default_context())
    else:
        s = smtplib.SMTP(c["host"], port, timeout=15)
        if c.get("starttls"):
            s.starttls(context=ssl.create_default_context())
    try:
        if c.get("user"):
            s.login(c["user"], c["password"])
        s.send_message(m)
    finally:
        s.quit()


def send_irc(c, title, msg, priority):
    raw = socket.create_connection((c["host"], int(c["port"])), timeout=20)
    if c.get("tls"):
        ctx = ssl.create_default_context()
        if not c.get("tls_verify"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=c["host"])
    nick = c.get("nick") or "lanpulse"
    buf = b""

    def send(line: str):
        raw.sendall((line + "\r\n").encode("utf-8", "replace"))

    send(f"NICK {nick}")
    send(f"USER {nick} 0 * :LanPulse alerts")
    deadline = time.time() + 25
    registered = False
    try:
        while time.time() < deadline and not registered:
            chunk = raw.recv(4096)
            if not chunk:
                raise ConnectionError("IRC server closed the connection")
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                text = line.decode("utf-8", "replace")
                parts = text.split()
                if text.startswith("PING"):
                    send("PONG " + text[5:])
                elif len(parts) > 1 and parts[1] == "001":
                    registered = True
                elif len(parts) > 1 and parts[1] == "433":
                    nick += "_"
                    send(f"NICK {nick}")
        if not registered:
            raise TimeoutError("IRC registration timed out")
        chan = c["channel"]
        send(f"JOIN {chan} {c['key']}".strip())
        time.sleep(1.0)
        for line in f"{title}: {msg}".splitlines():
            send(f"PRIVMSG {chan} :{line[:400]}")
        send("QUIT :bye")
        time.sleep(0.5)
    finally:
        raw.close()


SENDERS = {"ntfy": send_ntfy, "telegram": send_telegram, "webhook": send_webhook,
           "email": send_email, "irc": send_irc}


def send_one(settings: dict, name: str, title: str, msg: str, priority: int = 3, event=None) -> str | None:
    """Send through one channel. Returns None on success or an error message."""
    c = settings["channels"][name]
    try:
        if name == "webhook":
            send_webhook(c, title, msg, priority, event)
        else:
            SENDERS[name](c, title, msg, priority)
        return None
    except Exception as e:
        log.warning("Alert via %s failed: %s", name, e)
        return str(e) or e.__class__.__name__


MUTED = {"count": 0}            # alerts held back since quiet mode was last changed


def quiet_left(settings: dict, now: float | None = None) -> float:
    """Seconds of quiet mode left, 0 when alerts are on."""
    try:
        until = float((settings.get("quiet") or {}).get("until") or 0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, until - (now if now is not None else time.time()))


def quiet_until(body: dict, now: float, max_minutes: int = 7 * 1440) -> float:
    """Turn a request from the dashboard into an end time. {off: true} ends quiet mode, {morning: true} lasts until the
    next 8 AM, {minutes: n} lasts n minutes (at most a week)."""
    if body.get("off"):
        return 0.0
    if body.get("morning"):
        t = datetime.datetime.fromtimestamp(now)
        nxt = t.replace(hour=8, minute=0, second=0, microsecond=0)
        if nxt <= t:
            nxt += datetime.timedelta(days=1)
        return nxt.timestamp()
    try:
        minutes = int(body.get("minutes"))
    except (TypeError, ValueError):
        return 0.0
    return now + max(1, min(minutes, max_minutes)) * 60


# How important each kind of alert is, 1 (routine) to 5 (act now). A channel can be set to hear only 4 and up, or 5 only.
LEVELS = (1, 4, 5)
RULE_LEVEL = {"compromise": 5, "dns_threats": 5, "vulns": 4, "security": 4, "local_threats": 4, "services": 4}
HELD = {"filtered": 0, "capped": 0}      # alerts a channel's importance or hourly limit kept back, since start
_HOURLY: dict[str, dict] = {}            # channel -> {"start": window start, "sent": n, "held": n}


def alert_level(event, priority: int) -> int:
    return max(int(priority or 3), RULE_LEVEL.get((event or {}).get("rule"), 0))


def channel_gate(name: str, c: dict, level: int, now: float | None = None) -> tuple[str, str]:
    """Decide whether one channel gets this alert. Returns ("send"|"skip"|"limit", note). "limit" means this is the first
    alert held back in the hour, so a single notice goes out in its place; the note is added to a message that follows
    a limited hour. Daily summaries never come through here."""
    now = now if now is not None else time.time()
    if level < int(c.get("min_level") or 1):
        HELD["filtered"] += 1
        return "skip", ""
    cap = int(c.get("max_per_hour") or 0)
    if not cap:
        return "send", ""
    w = _HOURLY.get(name)
    if not w or now - w["start"] >= 3600:
        carried = w["held"] if w else 0
        _HOURLY[name] = {"start": now, "sent": 1, "held": 0, "notified": False}
        return "send", (f"{carried} more alert{'s' if carried != 1 else ''} were held back during the last hour by this "
                        f"channel's hourly limit." if carried else "")
    if w["sent"] < cap:
        w["sent"] += 1
        return "send", ""
    w["held"] += 1
    HELD["capped"] += 1
    if not w["notified"]:
        w["notified"] = True
        return "limit", f"Hourly limit of {cap} alerts reached. Further alerts on this channel are held until the hour ends."
    return "skip", ""


def send_all(settings: dict, title: str, msg: str, priority: int = 3, event=None) -> dict:
    # Quiet mode holds alerts back. The daily summary is not an alert, so it still goes out.
    is_summary = (event or {}).get("rule") == "summary"
    if quiet_left(settings) > 0 and not is_summary:
        MUTED["count"] += 1
        return {}
    level = alert_level(event, priority)
    out = {}
    for name, c in settings["channels"].items():
        if not c.get("enabled"):
            continue
        t, m = title, msg
        if not is_summary:
            verdict, note = channel_gate(name, c, level)
            if verdict == "skip":
                continue
            if verdict == "limit":
                t, m = "LanPulse alert limit reached", note
            elif note:
                m = f"{msg}\n\n{note}"
        out[name] = send_one(settings, name, t, m, priority, event)
    return out
