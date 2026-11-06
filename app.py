#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
LanPulse - real-time visual LAN mapper with a web dashboard.

Run as root (ARP sweeps and nmap OS detection need raw sockets):
    sudo /opt/lanpulse/venv/bin/python app.py --set-password   # first time
    sudo /opt/lanpulse/venv/bin/python app.py --host 0.0.0.0 --port 8080
Try it without scanning anything:
    python app.py --demo
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import csv
import getpass
import io
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

import alerts
from auth import Auth
from history import History
from timeline import Timeline
import posture
from threats import ThreatMonitor
from localwatch import LocalWatch
from flows import FlowStore
from dns import DnsMonitor
from vulns import VulnScanner
import redteam
import analyst
from openvas import OpenVAS
from services import ServiceMonitor
from honeypot import Honeypot
from discovery import Discovery, classify_from_hints
from unifi import UniFi, UniFiError

VERSION = "1.24.0"
STARTED = time.time()   # when this process started (used to spot an update status that never finished)
BASE = Path(__file__).resolve().parent
log = logging.getLogger("lanpulse")

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore
    scapy_conf.verb = 0
    HAVE_SCAPY = True
except Exception:  # pragma: no cover
    HAVE_SCAPY = False

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
HAVE_NMAP = shutil.which("nmap") is not None


# --------------------------------------------------------------------------- helpers
def clean_text(v, limit: int = 80) -> str:
    """Names that devices announce about themselves (DHCP, mDNS, UPnP, NetBIOS) are untrusted. Drop control and
    invisible formatting characters (line breaks, right-to-left overrides, zero-width marks) and cap the length."""
    import unicodedata
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else "" if unicodedata.category(ch) in ("Cf", "Cs", "Co")
                else ch for ch in str(v or ""))
    return " ".join(s.split())[:limit]


def csv_safe(v) -> str:
    """Stop spreadsheet formula injection: a cell starting with = + - @ would run as a formula in Excel."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain")


def host_name(value: str) -> str:
    h = (value or "").strip().lower()
    if h.startswith("["):                           # [ipv6]:port
        return h[1:h.find("]")] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def host_allowed(host_header: str, extra=()) -> bool:
    """Without a login, only answer to IP addresses and local names. This blocks DNS rebinding, where a web page
    you visit points its own domain at LanPulse to read it. Real domains can be added with --allow-host."""
    h = host_name(host_header)
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    return h == "localhost" or "." not in h or h.endswith(LOCAL_SUFFIXES) or h in extra


def origin_allowed(origin: str | None, host_header: str, extra=()) -> bool:
    """Browsers send Origin on cross-site requests. Refuse changes that come from another web site (CSRF)."""
    if not origin:
        return True                                 # not from a web page (curl, scripts, honeypots)
    if origin == "null":
        return False
    o = urllib.parse.urlsplit(origin)
    return (o.netloc or "").lower() == (host_header or "").strip().lower() or (o.hostname or "") in extra


UPDATE_MAX_BYTES = 40 * 1024 * 1024


def check_update_zip(path) -> dict:
    """Make sure an uploaded file is a LanPulse release before the root-only updater will install it."""
    import zipfile
    if not zipfile.is_zipfile(path):
        raise ValueError("That isn't a .zip file.")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        total = 0
        for info in z.infolist():
            n = info.filename
            if n.startswith(("/", "\\")) or "\\" in n or ".." in n.split("/") or ":" in n.split("/")[0]:
                raise ValueError("The zip contains unsafe file paths.")
            if not n.startswith("lanpulse/"):
                raise ValueError("This doesn't look like a LanPulse update (everything should be inside a lanpulse folder).")
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in (0, 0o100000, 0o040000):         # only plain files and folders: no links or device files
                raise ValueError("The zip contains links or special files, which LanPulse updates never do.")
            total += info.file_size
        if total > 200 * 1024 * 1024:
            raise ValueError("The zip unpacks to more than 200 MB.")
        if "lanpulse/app.py" not in names or "lanpulse/install.sh" not in names:
            raise ValueError("This doesn't look like a LanPulse update (app.py or install.sh is missing).")
        m = re.search(r'^VERSION = "([^"]+)"', z.read("lanpulse/app.py").decode("utf-8", "replace"), re.M)
    if not m:
        raise ValueError("Couldn't find a version number in this update.")
    return {"version": m.group(1), "files": len(names)}


def version_tuple(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v or "0"))


def sh(cmd: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def default_gateway_from_proc(iface: str | None = None) -> str | None:
    """Backup gateway lookup that reads the kernel routing table directly (no `ip` command needed)."""
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[1] == "00000000" and (not iface or p[0] == iface):
                    return str(ipaddress.IPv4Address(int(p[2], 16).to_bytes(4, "little")))
    except (OSError, ValueError, StopIteration):
        pass
    return None


def detect_network(iface: str | None, subnet: str | None) -> dict:
    gw = None
    m = re.search(r"default via (\S+) dev (\S+)", sh(["ip", "-4", "route", "show", "default"]))
    if m:
        gw = m.group(1)
        iface = iface or m.group(2)
    if not gw:
        gw = default_gateway_from_proc(iface)
    if not iface:
        raise SystemExit("Could not find a network interface. Choose one in Settings > System, or run once with --iface eth0 --import-args.")
    m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", sh(["ip", "-4", "-o", "addr", "show", "dev", iface]))
    if not m2:
        raise SystemExit(f"Interface {iface} has no IPv4 address.")
    ipif = ipaddress.ip_interface(m2.group(1))
    net = ipaddress.ip_network(subnet, strict=False) if subnet else ipif.network
    if net.num_addresses > 4096 and not subnet:
        log.warning("Subnet %s is large; scanning only %s/24. Change it in Settings > System.", net, ipif.ip)
        net = ipaddress.ip_network(f"{ipif.ip}/24", strict=False)
    try:
        my_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().upper()
    except Exception:
        my_mac = ""
    return {"iface": iface, "my_ip": str(ipif.ip), "my_mac": my_mac, "gateway": gw, "subnet": str(net)}


# MAC vendor database: nmap ships one, so no extra download is needed.
VENDORS: dict[str, str] = {}


IEEE: dict[str, str] = {}


def load_ieee(data_dir: str) -> None:
    """IEEE registries (MA-L, MA-M, MA-S) are more complete and current than nmap's list."""
    import csv
    for name in ("oui.csv", "mam.csv", "oui36.csv"):
        p = Path(data_dir) / name
        if not p.exists():
            continue
        try:
            with p.open(newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and row[0] != "Registry":
                        IEEE[row[1].strip().upper()] = row[2].strip()
        except Exception as e:
            log.warning("Could not read %s: %s", p, e)
    if IEEE:
        log.info("Loaded %d IEEE vendor prefixes", len(IEEE))


def load_vendors() -> None:
    for path in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes"):
        p = Path(path)
        if p.exists():
            for line in p.read_text(errors="ignore").splitlines():
                if line and not line.startswith("#"):
                    pre, _, name = line.partition(" ")
                    VENDORS[pre.upper()] = name.strip()
            log.info("Loaded %d MAC vendor prefixes", len(VENDORS))
            return
    log.warning("nmap-mac-prefixes not found; vendor names unavailable (install nmap)")


def is_random_mac(mac: str) -> bool:
    return bool(mac) and mac[1].upper() in "26AE"


def lookup_vendor(mac: str) -> str:
    if not mac:
        return ""
    if is_random_mac(mac):
        return "Private (randomized MAC)"
    hexmac = mac.replace(":", "").replace("-", "").upper()
    for n in (9, 7):                                      # MA-S and MA-M blocks are more specific
        if hexmac[:n] in IEEE:
            return IEEE[hexmac[:n]]
    return VENDORS.get(hexmac[:6]) or IEEE.get(hexmac[:6], "")


def resolve_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    if shutil.which("avahi-resolve-address"):
        parts = sh(["avahi-resolve-address", ip], timeout=3).split()
        if len(parts) >= 2:
            return parts[1]
    if shutil.which("nmblookup"):
        m = re.search(r"^\s+(\S+)\s+<00>\s+-\s+(?!<GROUP>)", sh(["nmblookup", "-A", ip], timeout=4), re.M)
        if m:
            return m.group(1)
    return ""


# --------------------------------------------------------------------------- scanning
def arp_sweep(subnet: str, iface: str, gateway: str = "") -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """Return ({key: {mac, ip, rtt}} for every host that answers, [every (MAC, IP) answer]). A device that answers
    for more than one address (an impersonator answering for the router as well as itself) keeps its own."""
    found: dict[str, dict] = {}
    pairs: list[tuple[str, str]] = []
    if HAVE_SCAPY and IS_ROOT:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), iface=iface,
                     timeout=2, retry=1, inter=0.002)
        for snd, rcv in ans:
            mac = rcv.hwsrc.upper()
            rtt = round((rcv.time - snd.sent_time) * 1000, 1) if getattr(snd, "sent_time", None) else None
            pairs.append((mac, rcv.psrc))
            if mac in found and rcv.psrc == gateway:
                continue
            found[mac] = {"mac": mac, "ip": rcv.psrc, "rtt": rtt}
        return found, pairs
    # Fallback: nmap ping sweep (MACs only available when root)
    out = sh(["nmap", "-sn", "-n", "-oX", "-", subnet], timeout=180)
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return found
    for host in root.findall("host"):
        ip = mac = ""
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr", "").upper()
        if ip:
            key = mac or f"IP-{ip}"
            if mac:
                pairs.append((mac, ip))
            if key in found and ip == gateway:
                continue
            found[key] = {"mac": mac, "ip": ip, "rtt": None}
    return found, pairs


# Safe NSE scripts run on a thorough scan. These actively TEST for a flaw instead of guessing from a version
# number, so they catch patch-level holes a banner can't see (SMB doesn't advertise its patch level). None of
# these exploit or crash the target: smb-vuln-ms17-010 is a safe check, and smb-os-discovery pins the exact
# Windows version (which also sharpens ordinary CVE matching). Intrusive/DoS checks (ms08-067, ms12-020) are
# deliberately left out so LanPulse is safe to run against any home device.
SAFE_NSE = ("smb-os-discovery,smb-security-mode,smb2-security-mode,smb2-capabilities,"
            "smb-vuln-ms17-010,rdp-ntlm-info,ssl-heartbleed,ssl-poodle,vulners")
# vulners looks up each detected service version (its CPE only) at vulners.com; keep just serious or exploitable ones
NSE_ARGS = "vulners.mincvss=7.0"
# Fallback CVE for a script that reports VULNERABLE without a machine-readable CVE in its output.
SCRIPT_CVE = {"smb-vuln-ms17-010": "CVE-2017-0143", "smb-vuln-ms08-067": "CVE-2008-4250",
              "smb-vuln-cve-2017-7494": "CVE-2017-7494", "rdp-vuln-ms12-020": "CVE-2012-0002",
              "ssl-heartbleed": "CVE-2014-0160", "ssl-poodle": "CVE-2014-3566",
              "smb-vuln-cve2009-3103": "CVE-2009-3103", "http-shellshock": "CVE-2014-6271"}
SCRIPT_TITLE = {"smb-vuln-ms17-010": "SMBv1 remote code execution (EternalBlue, MS17-010)",
                "ssl-heartbleed": "OpenSSL Heartbleed memory disclosure",
                "ssl-poodle": "SSLv3 POODLE information disclosure"}


def nmap_deep(ip: str, top_ports: int, thorough: bool = False) -> dict | None:
    """Port + version scan. A thorough scan checks all 65,535 ports with nmap's strongest version detection
    (slower, a few minutes per device) and runs a set of safe NSE checks that actively test for well-known
    holes (EternalBlue, weak SMB signing, Heartbleed) rather than only matching version numbers."""
    if not HAVE_NMAP:
        return None
    if thorough:
        cmd = ["nmap", "-Pn", "-T4", "-p-", "-sV", "--version-all", "--script", SAFE_NSE, "--script-args", NSE_ARGS, "-oX", "-", ip]
    else:
        cmd = ["nmap", "-Pn", "-T4", "--top-ports", str(top_ports), "-sV", "--version-light", "-oX", "-", ip]
    if IS_ROOT:
        cmd[1:1] = ["-O", "--osscan-guess"]
    out = sh(cmd, timeout=2400 if thorough else 300)
    try:
        host = ET.fromstring(out).find("host")
    except ET.ParseError:
        return None
    if host is None:
        return None
    info = {"ports": [], "os": "", "os_accuracy": 0, "os_type": "", "os_family": "", "hostname": "", "vendor": ""}
    hn = host.find("hostnames/hostname")
    if hn is not None:
        info["hostname"] = hn.get("name", "")
    for a in host.findall("address"):
        if a.get("addrtype") == "mac" and a.get("vendor"):
            info["vendor"] = a.get("vendor")
    for p in host.findall("ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = p.find("service")
        product = ""
        name = ""
        cpes, sw, ver = [], "", ""
        if svc is not None:
            # banners come from the scanned device: strip control characters before they reach alerts or the page
            sw, ver = clean_text(svc.get("product", ""), 80), clean_text(svc.get("version", ""), 60)
            name = clean_text(svc.get("name", ""), 40)
            product = " ".join(x for x in (sw, ver) if x)
            if svc.get("tunnel") == "ssl" and name == "http":
                name = "https"
            cpes = [c.text.strip() for c in svc.findall("cpe") if c.text and c.text.startswith("cpe:/a:")][:3]
        info["ports"].append({"port": int(p.get("portid", 0)), "proto": p.get("protocol", "tcp"),
                              "service": name, "product": product, "sw": sw[:80], "ver": ver[:60], "cpe": cpes})
    om = host.find("os/osmatch")
    if om is not None:
        info["os"] = om.get("name", "")
        info["os_accuracy"] = int(om.get("accuracy", 0) or 0)
        oc = om.find("osclass")
        if oc is not None:
            info["os_type"] = oc.get("type", "")
            info["os_family"] = oc.get("osfamily", "")
        info["os_cpe"] = [c.text.strip() for c in om.findall("osclass/cpe") if c.text][:6]
    # Windows reports its own version through SMB/RPC services ("Microsoft Windows XP microsoft-ds")
    hints = {x.get("product", "") for x in host.findall("ports/port/service")
             if x.get("ostype") == "Windows" or "windows" in x.get("product", "").lower()}
    info["probes"], smb_os = parse_scripts(host)
    info["vulners"] = list(getattr(parse_scripts, "vulners", []))
    if smb_os:                       # smb-os-discovery names the exact Windows version; feed it to CVE matching
        hints.add(smb_os)
    info["os_hint"] = " | ".join(sorted(x for x in hints if x))[:300]
    return info


def parse_vulners(scr, port: int) -> list[dict]:
    """CVEs the vulners script lists for one service: [{cve, cvss, exploit, port}] (version-based, not confirmed)."""
    out = []
    for tbl in scr.iter("table"):
        el = {e.get("key"): (e.text or "") for e in tbl.findall("elem")}
        cid = el.get("id", "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cid):
            continue
        try:
            cvss = float(el.get("cvss", "") or 0)
        except ValueError:
            cvss = 0.0
        out.append({"cve": cid, "cvss": round(min(max(cvss, 0.0), 10.0), 1),
                    "exploit": el.get("is_exploit", "").lower() == "true", "port": port})
    return out


def parse_scripts(host) -> tuple[list[dict], str]:
    """Pull confirmed-vulnerable results and the SMB-reported OS from NSE script output.

    A finding counts as confirmed only when a vuln script reports state VULNERABLE (not "LIKELY" or "NOT").
    Returns (probes, smb_os_string)."""
    probes, seen, smb_os = [], set(), ""
    vul, vseen = [], set()
    # (script element, port it ran on) for host scripts and per-port scripts
    pairs = [(s, 0) for s in host.findall("hostscript/script")]
    for p in host.findall("ports/port"):
        port = int(p.get("portid", 0) or 0)
        pairs += [(s, port) for s in p.findall("script")]
    for scr, port in pairs:
        sid = scr.get("id", "")
        if sid == "smb-os-discovery":
            for e in scr.iter("elem"):
                if e.get("key") == "os" and (e.text or "").strip():
                    smb_os = clean_text(e.text, 120)
                    break
            if not smb_os:
                m = re.search(r"OS:\s*([^\n]+)", scr.get("output", ""))
                if m:
                    smb_os = clean_text(m.group(1), 120)
            continue
        if sid == "vulners":
            for v in parse_vulners(scr, port):
                if (v["cve"], v["port"]) not in vseen:
                    vseen.add((v["cve"], v["port"]))
                    vul.append(v)
            continue
        if "vuln" not in sid and sid not in SCRIPT_CVE and sid not in SCRIPT_TITLE:
            continue
        found_table = False
        for tbl in scr.iter("table"):
            state = title = ""
            for e in tbl.findall("elem"):
                if e.get("key") == "state":
                    state = (e.text or "")
                elif e.get("key") == "title":
                    title = (e.text or "")
            st = state.upper()
            if "VULNERABLE" not in st or "NOT VULNERABLE" in st or "LIKELY" in st or st.strip().startswith("UNKNOWN"):
                continue                               # only a definite VULNERABLE counts as confirmed
            found_table = True
            blob = ET.tostring(tbl, encoding="unicode")
            m = re.search(r"CVE-\d{4}-\d{4,7}", tbl.get("key", "") + " " + blob, re.I)
            cve = m.group(0).upper() if m else SCRIPT_CVE.get(sid, "")
            key = (sid, cve, port)
            if key in seen:
                continue
            seen.add(key)
            probes.append({"id": sid, "cve": cve, "port": port,
                           "title": SCRIPT_TITLE.get(sid) or clean_text(title, 160) or sid})
        # Fallback: older output format carries only the "output" text
        if not found_table and "State: VULNERABLE" in scr.get("output", "") and "NOT VULNERABLE" not in scr.get("output", ""):
            m = re.search(r"CVE-\d{4}-\d{4,7}", scr.get("output", ""), re.I)
            cve = (m.group(0).upper() if m else SCRIPT_CVE.get(sid, ""))
            key = (sid, cve, port)
            if key not in seen:
                seen.add(key)
                probes.append({"id": sid, "cve": cve, "port": port, "title": SCRIPT_TITLE.get(sid, sid)})
    parse_scripts.vulners = vul[:80]          # read right after the call by nmap_deep
    return probes[:40], smb_os


# --------------------------------------------------------------------------- classification
def classify(d: dict) -> str:
    if d.get("is_self"):
        return "scanner"
    if d.get("is_gateway"):
        return "router"
    hinted = classify_from_hints(d)          # what the device says about itself beats guessing
    if hinted:
        return hinted
    v = (d.get("vendor") or "").lower()
    h = f'{d.get("hostname") or ""} {d.get("friendly") or ""} {d.get("model") or ""}'.lower().strip()
    os_ = (d.get("os") or "").lower()
    ot = (d.get("os_type") or "").lower()
    ports = {p["port"] for p in d.get("ports", [])}
    vh = f"{v} {h}"
    tok = set(re.split(r"[^a-z0-9]+", vh))

    def any_in(text: str, words) -> bool:
        return any(w in text for w in words)

    if "printer" in ot or ports & {631, 9100, 515} or any_in(vh, (
            "printer", "laserjet", "officejet", "deskjet", "epson", "brother", "canon", "kyocera",
            "xerox", "lexmark", "ricoh")):
        return "printer"
    if "storage" in ot or tok & {"nas"} or any_in(vh, (
            "synology", "qnap", "asustor", "terramaster", "truenas", "unraid", "diskstation", "readynas")):
        return "nas"
    windows = ("windows" in os_ or "microsoft" in h or "windows" in h or bool(ports & {135, 139, 3389})
               or (445 in ports and 554 in ports))
    if "webcam" in ot or any_in(vh, ("hikvision", "dahua", "axis comm", "reolink", "amcrest", "foscam",
                                     "camera", "ipcam", "lorex", "uniview", "cam-")) or tok & {"cam"} \
            or (554 in ports and not windows and len(ports) <= 6):
        return "camera"
    if "raspberry" in vh:
        return "raspberrypi"
    if "ipad" in h or tok & {"kindle", "tablet"}:
        return "tablet"
    if any_in(h, ("iphone", "android", "galaxy", "pixel", "oneplus", "sm-", "moto", "redmi", "huawei")) \
            or "phone" in ot or "ios" in os_.split() or "android" in os_:
        return "phone"
    if "game console" in ot or any_in(vh, ("nintendo", "xbox", "playstation", "sony interactive",
                                           "ps4", "ps5", "steamdeck", "steam-deck")):
        return "game"
    if "media device" in ot or tok & {"tv"} or ports & {8008, 8009, 8060} or any_in(vh, (
            "roku", "vizio", "hisense", "chromecast", "firetv", "fire-tv", "appletv", "apple-tv",
            "bravia", "webos", "tizen", "androidtv", "shield", "smart-tv")):
        return "tv"
    if any_in(vh, ("sonos", "echo", "alexa", "google-home", "googlehome", "nest-audio", "nest-mini",
                   "homepod", "bose", "denon", "harman")):
        return "speaker"
    if tok & {"ring", "hue", "wiz", "nest", "kasa", "plug"} or any_in(vh, (
            "espressif", "tuya", "shelly", "philips lighting", "signify", "ecobee", "lifx", "wemo", "belkin",
            "ikea", "yeelight", "sonoff", "itead", "meross", "govee", "smartthings", "myq", "chamberlain",
            "rachio", "tasmota", "esp32", "esp8266", "esp_", "arduino", "particle", "silicon lab", "murata")):
        return "iot"
    if ot in ("wap",) or any_in(vh, ("unifi", "u6-", "uap", "aruba", "ruckus", "meraki", "eero", "orbi",
                                    "deco", "access point", "mesh")) or tok & {"ap"}:
        return "ap"
    if ot in ("switch", "router", "bridge") or tok & {"switch", "sw"} or any_in(v, (
            "ubiquiti", "cisco", "juniper", "zyxel", "netgear", "d-link", "linksys", "mikrotik", "routerboard")):
        return "switch"
    if "tp-link" in v:
        return "ap" if ports & {80, 443} else "iot"
    if windows:
        return "desktop"
    if "apple" in v or "mac os" in os_ or "macos" in os_ or any_in(h, ("macbook", "imac", "mac-mini",
                                                                       "macmini", "mbp")):
        if not ports and "apple" in v and not any_in(h, ("mac", "imac")):
            return "phone"           # most portless Apple devices on a LAN are iPhones
        return "laptop"
    if any_in(h, ("laptop", "notebook", "thinkpad", "xps", "latitude", "elitebook", "zenbook")):
        return "laptop"
    if any_in(vh, ("vmware", "qemu", "proxmox", "xensource", "super micro", "supermicro")) or \
            any_in(os_, ("linux", "freebsd", "esxi")) and (22 in ports or len(ports) >= 3):
        return "server"
    if tok & {"desktop", "pc"} or any_in(v, ("dell", "lenovo", "asustek", "micro-star", "gigabyte",
                                             "asrock", "acer", "framework", "realtek")):
        return "desktop"
    if "intel" in v:
        return "laptop"
    if d.get("randomized_mac"):
        return "phone"
    return "unknown"


# --------------------------------------------------------------------------- demo data
PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 135: "msrpc",
              139: "netbios-ssn", 443: "https", 445: "microsoft-ds", 554: "rtsp", 631: "ipp", 1400: "sonos",
              3128: "http-proxy", 3389: "ms-wbt-server", 5000: "http", 5001: "https", 7000: "airplay",
              8006: "https", 8008: "http", 8009: "castv2", 8060: "roku-ecp", 9100: "jetdirect", 62078: "iphone-sync"}
DEMO = [
    # mac, ip, vendor, hostname, ports, os
    ("B0:BE:76:11:22:01", "192.168.1.1", "TP-LINK Technologies", "router.lan", [53, 80, 443], "Linux 4.X"),
    ("24:5A:4C:11:22:02", "192.168.1.2", "Ubiquiti Networks", "U6-Lite", [22], "Linux 4.X"),
    ("F4:8E:38:11:22:10", "192.168.1.10", "Dell", "lanpulse", [22, 8080], "Linux 6.X"),
    ("00:11:32:11:22:20", "192.168.1.20", "Synology Incorporated", "DiskStation", [22, 80, 443, 445, 5000, 5001], "Linux 5.X"),
    ("3C:52:82:11:22:30", "192.168.1.30", "Hewlett Packard", "HP-LaserJet-M404", [80, 443, 631, 9100], "HP printer"),
    ("F0:18:98:11:22:65", "192.168.1.101", "Apple", "Johns-iPhone", [62078], "Apple iOS 17"),
    ("A4:83:E7:11:22:66", "192.168.1.102", "Apple", "MacBook-Pro", [22, 5000, 7000], "Apple macOS 14"),
    ("D8:BB:C1:11:22:67", "192.168.1.103", "Micro-Star INTL", "GAMING-PC", [135, 139, 445, 3389], "Microsoft Windows 11"),
    ("DA:A1:19:11:22:68", "192.168.1.104", "Private (randomized MAC)", "Galaxy-S24", [], "Android 14"),
    ("F0:18:98:11:22:69", "192.168.1.105", "Apple", "Sarahs-iPad", [62078], "Apple iPadOS 17"),
    ("8C:8D:28:11:22:6A", "192.168.1.106", "Intel Corporate", "thinkpad-x1", [], ""),
    ("D8:31:34:11:22:6E", "192.168.1.110", "Roku", "Roku-Ultra", [8060], "Linux"),
    ("F4:F5:D8:11:22:6F", "192.168.1.111", "Google", "Chromecast", [8008, 8009], "Linux"),
    ("48:A6:B8:11:22:70", "192.168.1.112", "Sonos", "Sonos-Kitchen", [1400], "Linux"),
    ("C0:56:E3:11:22:78", "192.168.1.120", "Hangzhou Hikvision Digital Technology", "cam-driveway", [80, 554], "Linux"),
    ("24:0A:C4:11:22:79", "192.168.1.121", "Espressif", "esp32-sensor", [23, 80], ""),
    ("00:17:88:11:22:7A", "192.168.1.122", "Philips Lighting BV", "Philips-hue", [80, 443], ""),
    ("00:D9:D1:11:22:82", "192.168.1.130", "Sony Interactive Entertainment", "PS5-Living", [], ""),
    ("DC:A6:32:11:22:8C", "192.168.1.140", "Raspberry Pi Trading", "pihole", [22, 53, 80], "Linux 6.X"),
    ("AC:1F:6B:11:22:96", "192.168.1.150", "Super Micro Computer", "proxmox", [22, 3128, 8006], "Linux 6.X"),
]

# --------------------------------------------------------------------------- security checks
RISKY_PORTS = {
    23: ("high", "Telnet is open. It sends logins in plain text."),
    5900: ("high", "VNC remote control is open."),
    5901: ("high", "VNC remote control is open."),
    2375: ("high", "Docker API is open without TLS. Anyone on the LAN can control containers."),
    21: ("medium", "FTP is open. It sends passwords in plain text."),
    3389: ("medium", "Remote Desktop (RDP) is open."),
    1433: ("medium", "SQL Server database port is reachable."),
    3306: ("medium", "MySQL/MariaDB database port is reachable."),
    5432: ("medium", "PostgreSQL database port is reachable."),
    6379: ("medium", "Redis is reachable. It often has no password."),
    9200: ("medium", "Elasticsearch is reachable. It often has no password."),
    11211: ("medium", "Memcached is reachable."),
    27017: ("medium", "MongoDB is reachable."),
    1883: ("low", "MQTT broker without TLS."),
    69: ("low", "TFTP is open."),
    1524: ("high", "Port 1524 (ingreslock) is open. On many systems this is a backdoor root shell."),
    3632: ("high", "distccd is open. Old versions let anyone run commands."),
    512: ("high", "rexec is open. It sends logins in plain text."),
    513: ("high", "rlogin is open. It sends logins in plain text and often trusts hosts without a password."),
    514: ("high", "rsh is open. It often trusts hosts without a password."),
    6000: ("medium", "X11 display server is open to the network."),
    2049: ("medium", "NFS file sharing is open. Check what it exports."),
}
# Ports that legitimate home devices almost never open; a new one is a classic sign of a backdoor or remote shell
UNUSUAL_PORTS = {
    4444: "Port 4444 is Metasploit's default for reverse shells.",
    1337: "Port 1337 is a common backdoor port.",
    31337: "Port 31337 is a classic backdoor port.",
    6666: "Ports 6666-6669 are often used by botnets (IRC).",
    6667: "Ports 6666-6669 are often used by botnets (IRC).",
    12345: "Port 12345 is a well-known trojan port.",
    5555: "Port 5555 is Android debugging (ADB), which gives full control of the device.",
    4899: "Port 4899 is Radmin remote control.",
    1080: "Port 1080 is a SOCKS proxy, which can be used to relay attacks.",
}
ADMIN_TYPES = {"router", "ap", "switch", "camera", "nas", "printer"}


def findings(d: dict) -> list[dict]:
    out = []
    ports = {p["port"]: p for p in d.get("ports", [])}
    for port, (level, text) in RISKY_PORTS.items():
        if port in ports:
            out.append({"level": level, "port": port, "text": text})
    if 445 in ports:
        normal = d.get("type") in ("nas", "desktop", "server", "laptop")
        out.append({"level": "low" if normal else "medium", "port": 445,
                    "text": "Windows file sharing (SMB) is open."})
    for p in ports.values():
        m = re.search(r"OpenSSH[ _](\d+)\.(\d+)", p.get("product", ""))
        if m and (int(m.group(1)), int(m.group(2))) < (8, 0):
            out.append({"level": "medium", "port": p["port"], "text": f"Old SSH server ({p['product']}). Update it."})
    if d.get("type") in ADMIN_TYPES and 80 in ports and not ({443, 8443} & ports.keys()):
        out.append({"level": "low", "port": 80, "text": "Admin web page only offers unencrypted HTTP."})
    os_l = (d.get("os") or "").lower()
    eol = next((n for n in ("windows xp", "windows vista", "windows 7", "windows 8", "server 2003", "server 2008")
                if n in os_l), None)
    if eol:
        out.append({"level": "high", "port": 0,
                    "text": f"{eol.title()} no longer gets security updates. Keep it off the internet or upgrade it."})
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda f: order[f["level"]])


def wake_on_lan(mac: str, broadcast: str):
    payload = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "").replace("-", "")) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for addr in {broadcast, "255.255.255.255"}:
            s.sendto(payload, (addr, 9))


# --------------------------------------------------------------------------- core
DEVICE_DEFAULTS = {"name": "", "notes": "", "type_override": "", "trusted": False, "watched": False,
                   "findings": [], "ports": [], "ip_history": [], "os": "", "os_accuracy": 0, "os_type": "",
                   "os_family": "", "deep_scanned_at": 0, "scanning": False, "hostname": "", "vendor": "",
                   "hints": {}, "evidence": [], "model": "", "friendly": "", "services": [], "probes": [], "vulners": [], "openvas": []}


class LanPulse:
    def __init__(self, args):
        self.args = args
        self.devices: dict[str, dict] = {}
        self.events: list[dict] = []
        self.clients: set[WebSocket] = set()
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.queued: set[str] = set()
        self.data_dir = Path(args.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.data_file = self.data_dir / ("demo.json" if args.demo else "devices.json")
        self.settings_file = self.data_dir / "settings.json"
        self.history = History(str(self.data_dir / ("demo-history.db" if args.demo else "history.db")))
        self.timeline = Timeline(str(self.data_dir / ("demo-timeline.db" if args.demo else "timeline.db")))
        self.posture = posture.PostureHistory(str(self.data_dir / ("demo-posture.db" if args.demo else "posture.db")))
        self.auth = Auth(self.data_dir / "auth.json")
        self.alert_sent: dict[tuple, float] = {}
        if args.demo:
            self.net = {"iface": "demo0", "my_ip": "192.168.1.10", "my_mac": "F4:8E:38:11:22:10",
                        "gateway": "192.168.1.1", "subnet": "192.168.1.0/24"}
            self.demo_offline: set[str] = {"8C:8D:28:11:22:6A"}
        else:
            self.net = detect_network(args.iface, args.subnet)
        self.broadcast_addr = str(ipaddress.ip_network(self.net["subnet"], strict=False).broadcast_address)
        self.meta = {"version": VERSION, "demo": args.demo, "interval": args.interval, "last_sweep": 0,
                     "sweep_ms": 0, "scapy": HAVE_SCAPY, "nmap": HAVE_NMAP, "root": IS_ROOT,
                     "auth": self.auth.enabled, "https": bool(args.cert), **self.net}
        self.load()
        if not self.settings["threats"].get("ingest_key"):
            self.settings["threats"]["ingest_key"] = secrets.token_urlsafe(18)
            self.save_settings()
        self.threats = ThreatMonitor(self)
        self.local = LocalWatch(self)
        self.flows = FlowStore(self)
        self.dns = DnsMonitor(self)
        self.vulns = VulnScanner(self)
        self.services = ServiceMonitor(self)
        self.honeypot = Honeypot(self)
        self.openvas = OpenVAS(self)
        if args.demo:
            self.honeypot.seed_demo()
        self.discovery = Discovery(self)
        self.blocked_cache: tuple[float, list[str]] = (0.0, [])
        self.demo_blocked: list[str] = ["203.0.113.77"] if args.demo else []
        # Baseline: on a fresh install, devices found in the first sweeps are trusted and don't alert.
        self.baseline_sweeps = 3 if not self.devices else 0

    # ---- persistence
    def load(self):
        try:
            data = json.loads(self.data_file.read_text())
            self.devices = data.get("devices", {})
            self.events = data.get("events", [])[-300:]
            for d in self.devices.values():
                for k, v in DEVICE_DEFAULTS.items():
                    d.setdefault(k, copy.deepcopy(v))
                d["online"] = False
                d["scanning"] = False
            log.info("Loaded %d known devices", len(self.devices))
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("Could not load %s: %s", self.data_file, e)
        try:
            raw = json.loads(self.settings_file.read_text())
            if isinstance(raw, dict) and "wizard" not in raw:
                raw["wizard"] = {"done": True}          # an existing install: don't greet it with the first-run guide
            self.settings = alerts.with_defaults(raw)
        except FileNotFoundError:
            self.settings = alerts.with_defaults(None)
        except Exception as e:
            log.warning("Could not load settings: %s", e)
            self.settings = alerts.with_defaults(None)

    def _atomic(self, path: Path, obj, private=False):
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(obj))
        if private:
            os.chmod(tmp, 0o600)
        tmp.replace(path)

    def save(self):
        try:
            self._atomic(self.data_file, {"devices": self.devices, "events": self.events[-300:]})
        except Exception as e:
            log.warning("Save failed: %s", e)

    def save_settings(self):
        self._atomic(self.settings_file, self.settings, private=True)

    # ---- state helpers
    EVENT_LEVEL = {"new": "warn", "online": "good", "offline": "info", "ip": "info", "port": "warn",
                   "port_closed": "info", "software": "info", "security": "bad", "scan": "info"}

    def event(self, kind: str, d: dict, text: str, level: str = "", feed: bool = True):
        """Something happened to a device: goes on its timeline, and (feed=True) in the live activity feed."""
        try:
            self.timeline.add(d["id"], kind, text, level or self.EVENT_LEVEL.get(kind, "info"))
        except Exception:
            log.exception("timeline write failed")
        if not feed:
            return
        ev = {"t": time.time(), "kind": kind, "id": d["id"], "text": text}
        self.events.append(ev)
        self.events = self.events[-300:]
        log.info("%s: %s", kind, text)

    def label(self, d: dict) -> str:
        return d.get("name") or d.get("friendly") or d.get("hostname") or d.get("vendor") or d["ip"]

    def apply_hints(self, d: dict):
        h = d.get("hints") or {}
        md, up, dh = h.get("mdns", {}), h.get("upnp", {}), h.get("dhcp", {})
        if dh.get("hostname") and not d.get("hostname"):
            d["hostname"] = dh["hostname"]
        friendly = md.get("friendly") or up.get("friendly") or d.get("friendly", "")
        m = re.match(r"^([^:]{1,40}):\s*[^:]*:?$", friendly)   # Windows Media sharing uses "PC-NAME: user:"
        if m and "microsoft" in (up.get("manufacturer", "") + up.get("model", "")).lower():
            friendly = m.group(1).strip()
        d["friendly"] = friendly
        up_model = " ".join(x for x in (up.get("manufacturer"), up.get("model")) if x)
        d["model"] = md.get("model") or up_model or d.get("model", "")
        from discovery import SERVICE_NAMES
        d["services"] = sorted({SERVICE_NAMES.get(x, x.strip("_")) for x in md.get("services", [])
                                if x not in ("_device-info", "_services")})[:10]
        self.reclassify(d)

    def reclassify(self, d: dict):
        for k in ("hostname", "friendly", "model", "vendor", "os"):
            if d.get(k):
                d[k] = clean_text(d[k], 120 if k == "os" else 80)
        for k in ("services", "evidence"):
            if isinstance(d.get(k), list):
                d[k] = [clean_text(x, 160) for x in d[k][:20] if clean_text(x, 160)]
        d["is_gateway"] = d["ip"] == self.net.get("gateway")
        d["is_self"] = bool(d.get("mac")) and d["mac"] == self.net.get("my_mac")
        if d["is_self"] or d["is_gateway"]:
            d["trusted"] = True
        d["type_auto"] = classify(d)
        d["type"] = d.get("type_override") or d["type_auto"]
        d["findings"] = findings(d)
        dismissed = set(d.get("dismissed", []))
        for f in d["findings"]:                 # risks the owner accepted (a lab machine, say) stay listed but stop nagging
            f["dismissed"] = f["text"] in dismissed

    def snapshot(self) -> dict:
        self.meta["auth"] = self.auth.enabled
        return {"type": "snapshot", "meta": self.meta, "devices": list(self.devices.values()),
                "events": self.events[-100:], "layout": self.settings.get("layout", {})}

    async def broadcast(self, msg: dict | None = None):
        data = json.dumps(msg or self.snapshot())
        for ws in list(self.clients):
            try:
                await ws.send_text(data)
            except Exception:
                self.clients.discard(ws)

    def enqueue(self, key: str):
        if key not in self.queued:
            self.queued.add(key)
            self.queue.put_nowait(key)

    # ---- alerts
    def notify(self, rule: str, d: dict, title: str, msg: str, priority: int = 3):
        if not self.settings["rules"].get(rule):
            return
        key = (rule, d["id"], title)
        now = time.time()
        if now - self.alert_sent.get(key, 0) < 600:       # same alert at most every 10 minutes
            return
        self.alert_sent[key] = now
        if not any(c.get("enabled") for c in self.settings["channels"].values()):
            return
        detail = (f"{msg}\nIP {d['ip']}  MAC {d.get('mac') or '-'}\nVendor: {d.get('vendor') or 'unknown'}"
                  f"  Type: {d.get('type')}")
        ev = {"rule": rule, "device": {k: d.get(k) for k in ("id", "ip", "mac", "vendor", "hostname", "type")}}
        task = asyncio.create_task(asyncio.to_thread(alerts.send_all, self.settings, title, detail, priority, ev))
        task.add_done_callback(lambda t: t.exception())   # errors are already logged by send_all

    def notify_plain(self, rule: str, key: str, title: str, msg: str, priority: int = 3, gap: int = 600):
        """Alert that isn't about one device (a service going down, for example)."""
        if not self.settings["rules"].get(rule):
            return
        k = (rule, key, title)
        now = time.time()
        if now - self.alert_sent.get(k, 0) < gap:
            return
        self.alert_sent[k] = now
        if not any(c.get("enabled") for c in self.settings["channels"].values()):
            return
        task = asyncio.create_task(asyncio.to_thread(alerts.send_all, self.settings, title, msg, priority,
                                                     {"rule": rule, "key": key}))
        task.add_done_callback(lambda t: t.exception())

    # ---- daily summary
    def daily_text(self) -> str:
        now = time.time()
        s = self.threats.summary(24)
        loc = self.local.summary(24)
        devs = list(self.devices.values())
        online = sum(d["online"] for d in devs)
        new = [d for d in devs if d.get("first_seen", 0) > now - 86400]
        watched_off = [d for d in devs if d.get("watched") and not d["online"]]
        risky = [d for d in devs if any(f["level"] == "high" and not f.get("dismissed") for f in d.get("findings", []))]
        names = lambda ds: ", ".join(self.label(d) for d in ds[:5]) + (f" +{len(ds) - 5} more" if len(ds) > 5 else "")
        lines = [time.strftime("LanPulse daily summary · %a %b %d", time.localtime(now))]
        lines.append(f"Devices: {online} of {len(devs)} online" + (f" · new: {names(new)}" if new else " · no new devices"))
        if watched_off:
            lines.append(f"Watched and offline: {names(watched_off)}")
        if risky:
            lines.append(f"High-risk services: {names(risky)}")
        total = s["total"]
        if total:
            pct = round(100 * s["blocked"] / total)
            scanners = sum(1 for a in s["attackers"] if a.get("tag"))
            lines.append(f"Internet attacks: {total:,} from {s['unique']:,} IPs in {s['countries_n']} countries · "
                         f"{pct}% blocked · {total - s['blocked']:,} reached your LAN"
                         + (f" · {scanners} research scanners" if scanners else ""))
            if s["countries"]:
                lines.append("Top countries: " + ", ".join(f"{c['country']} {c['count']:,}" for c in s["countries"][:4]))
            if s["ports"]:
                lines.append("Most targeted: " + ", ".join(f"{p['service']} {p['count']:,}" for p in s["ports"][:4]))
            if s.get("signatures"):
                lines.append("Top IPS detections: " + "; ".join(f"{g['name']} ({g['count']})" for g in s["signatures"][:3]))
        else:
            lines.append("Internet attacks: none recorded")
        if loc["count"]:
            seen, items = set(), []
            for e in loc["events"]:
                k = (e["kind"], e["src"] or e["mac"])
                if k not in seen:
                    seen.add(k)
                    items.append(f"{e['title']} from {e['src_name'] or e['src'] or e['mac']}")
            lines.append(f"Inside your network: {loc['count']} events · " + "; ".join(items[:3]))
        else:
            lines.append("Inside your network: nothing suspicious")
        return "\n".join(lines)

    async def summary_loop(self):
        while True:
            await asyncio.sleep(30)
            cfg = self.settings["summary"]
            if not cfg.get("enabled"):
                continue
            lt = time.localtime()
            today = time.strftime("%Y-%m-%d", lt)
            hh, mm = (int(x) for x in cfg.get("time", "08:00").split(":"))
            late = (lt.tm_hour * 60 + lt.tm_min) - (hh * 60 + mm)
            if cfg.get("last_sent") == today or not 0 <= late < 60:
                continue
            cfg["last_sent"] = today
            self.save_settings()
            try:
                text = await asyncio.to_thread(self.daily_text)
                if not self.args.demo:
                    await asyncio.to_thread(alerts.send_all, self.settings, "LanPulse daily summary", text, 3,
                                            {"rule": "summary"})
                log.info("Daily summary sent")
            except Exception:
                log.exception("Daily summary failed")

    # ---- sweeping
    def demo_sweep(self) -> dict[str, dict]:
        if random.random() < 0.15:
            mac = random.choice(DEMO[5:])[0]
            self.demo_offline ^= {mac}
        return {m: {"mac": m, "ip": ip, "rtt": round(random.uniform(0.6, 25), 1), "vendor": v, "hostname": h}
                for m, ip, v, h, *_ in DEMO if m not in self.demo_offline}

    def merge(self, found: dict[str, dict], now: float):
        baseline = self.baseline_sweeps > 0
        for key, f in found.items():
            d = self.devices.get(key)
            if d is None:
                d = {**copy.deepcopy(DEVICE_DEFAULTS), "id": key, "mac": f["mac"], "ip": f["ip"],
                     "vendor": f.get("vendor") or lookup_vendor(f["mac"]), "hostname": f.get("hostname", ""),
                     "type": "unknown", "type_auto": "unknown", "online": True, "first_seen": now,
                     "last_seen": now, "rtt_ms": f["rtt"], "is_gateway": False, "is_self": False,
                     "randomized_mac": is_random_mac(f["mac"]), "ip_history": [f["ip"]], "trusted": baseline}
                self.devices[key] = d
                self.reclassify(d)
                self.discovery.adopt(d)
                self.event("new", d, f"New device {self.label(d)} ({f['ip']})")
                if not d["trusted"]:
                    self.notify("new_device", d, f"New device: {self.label(d)}",
                                "An untrusted device joined your network.", 4)
                asyncio.create_task(self.enrich(key))
            else:
                if not d["online"]:
                    self.event("online", d, f"{self.label(d)} came online ({f['ip']})")
                    if d.get("watched"):
                        self.notify("watched_offline", d, f"Back online: {self.label(d)}", "Watched device is back.")
                if d["ip"] != f["ip"]:
                    self.event("ip", d, f"{self.label(d)} changed IP {d['ip']} -> {f['ip']}")
                    d["ip"] = f["ip"]
                    d.setdefault("ip_history", []).append(f["ip"])
                    d["ip_history"] = d["ip_history"][-10:]
                d["online"] = True
                d["last_seen"] = now
                d["rtt_ms"] = f["rtt"]
                self.reclassify(d)
            self.history.record(key, f["rtt"], now)
            if now - d.get("deep_scanned_at", 0) > self.args.rescan * 60:
                self.enqueue(key)
        if self.baseline_sweeps:
            self.baseline_sweeps -= 1

    async def sweep_loop(self):
        while True:
            t0 = time.time()
            try:
                if self.args.demo:
                    found = self.demo_sweep()
                else:
                    gw = self.net.get("gateway") or ""
                    found, pairs = await asyncio.to_thread(arp_sweep, self.net["subnet"], self.net["iface"], gw)
                    # Router impersonation: anyone else answering for the router's IP is reported and never
                    # recorded as the router (it would otherwise take over the router's place on the map).
                    imposters = self.local.check_sweep(pairs, time.time())
                    for mac in imposters:
                        if found.get(mac, {}).get("ip") == gw:
                            found.pop(mac, None)
                    if self.net["my_mac"]:
                        found[self.net["my_mac"]] = {"mac": self.net["my_mac"], "ip": self.net["my_ip"], "rtt": 0.0}
                now = time.time()
                self.merge(found, now)
                offline_after = self.args.offline_after or self.args.interval * 3 + 5
                for d in self.devices.values():
                    if self.args.demo and d["id"] not in found and d["online"]:
                        d["last_seen"] = min(d["last_seen"], now - offline_after - 1)
                    if d["online"] and now - d["last_seen"] > offline_after:
                        d["online"] = False
                        d["rtt_ms"] = None
                        self.event("offline", d, f"{self.label(d)} went offline")
                        if d.get("watched"):
                            self.notify("watched_offline", d, f"Offline: {self.label(d)}",
                                        "A watched device stopped responding.", 4)
                self.history.flush(now)
                if self.threats.dirty:
                    self.threats.dirty = False
                    await self.broadcast(await asyncio.to_thread(self.threats.summary))   # SQL off the main loop
                self.meta["last_sweep"] = now
                self.meta["sweep_ms"] = int((time.time() - t0) * 1000)
                await self.broadcast()
                self.save()
            except Exception:
                log.exception("Sweep failed")
            await asyncio.sleep(max(1.0, self.args.interval - (time.time() - t0)))

    async def enrich(self, key: str):
        d = self.devices.get(key)
        if not d or d.get("hostname") or self.args.demo:
            return
        name = await asyncio.to_thread(resolve_name, d["ip"])
        if name and not d.get("hostname"):
            d["hostname"] = name
            self.reclassify(d)
            await self.broadcast()

    def port_changes(self, d: dict, before: dict, before_ports: set, first_scan: bool, same_kind: bool, kind_now: str):
        """Compare a finished port scan with the previous one: alert on newly opened ports, note closed ports and
        software that changed version."""
        now_ports = {p["port"]: p for p in d["ports"]}
        name = self.label(d)
        desc = lambda p: f"{p['port']} ({p.get('product') or p.get('service') or 'unknown service'})"
        if first_scan:
            self.event("scan", d, f"First port scan: {len(now_ports)} open port{'s' if len(now_ports) != 1 else ''}"
                       + (f" ({', '.join(str(x) for x in sorted(now_ports)[:12])})" if now_ports else ""), feed=False)
            return
        opened = [now_ports[x] for x in sorted(set(now_ports) - before_ports)]
        closed = [before[x] for x in sorted(before_ports - set(now_ports))]
        if not same_kind:
            # quick <-> thorough covers a different set of ports: differences are expected, not news
            self.event("scan", d, f"{'Thorough' if kind_now == 'thorough' else 'Quick'} scan: {len(now_ports)} open ports"
                       + (f", {len(opened)} more than the quick scan sees" if opened and kind_now == "thorough" else ""),
                       feed=False)
            return
        if opened:
            risky = [p for p in opened if p["port"] in RISKY_PORTS or p["port"] in UNUSUAL_PORTS]
            txt = ", ".join(desc(p) for p in opened[:8]) + (f" and {len(opened) - 8} more" if len(opened) > 8 else "")
            self.event("port", d, f"{name} opened port{'s' if len(opened) > 1 else ''} {txt}", "bad" if risky else "warn")
            extra = ""
            if risky:
                extra = "\n" + "; ".join(RISKY_PORTS.get(p["port"], ("", UNUSUAL_PORTS.get(p["port"], "")))[1]
                                         for p in risky[:3])
            self.notify("new_port", d, f"New open port on {name}",
                        f"Newly open since the last scan: {txt}.{extra}", 4 if risky else 3)
        if closed:
            txt = ", ".join(desc(p) for p in closed[:8]) + (f" and {len(closed) - 8} more" if len(closed) > 8 else "")
            self.event("port_closed", d, f"{name} closed port{'s' if len(closed) > 1 else ''} {txt}", feed=False)
        for port, p in now_ports.items():
            old = before.get(port)
            if old and old.get("product") and p.get("product") and old["product"] != p["product"]:
                self.event("software", d, f"Port {port} changed from {old['product']} to {p['product']}", feed=False)

    async def deep_worker(self):
        while True:
            key = await self.queue.get()
            self.queued.discard(key)
            d = self.devices.get(key)
            if not d or not d["online"]:
                continue
            d["scanning"] = True
            await self.broadcast()
            try:
                if self.args.demo:
                    await asyncio.sleep(random.uniform(1, 4))
                    row = next(r for r in DEMO if r[0] == key)
                    info = {"hostname": row[3], "vendor": row[2], "os": row[5],
                            "os_accuracy": 95 if row[5] else 0, "os_type": "", "os_family": "",
                            "ports": [{"port": p, "proto": "tcp", "service": PORT_NAMES.get(p, ""),
                                       "product": ""} for p in row[4]]}
                elif self.args.no_deep:
                    info = None
                else:
                    kind = "thorough (all ports)" if d.get("thorough") else f"quick (top {self.args.top_ports} ports)"
                    log.info("Port scan started: %s %s", d["ip"], kind)
                    t_scan = time.time()
                    info = await asyncio.to_thread(nmap_deep, d["ip"], self.args.top_ports, bool(d.get("thorough")))
                    if info:
                        log.info("Port scan finished: %s in %ds, %d open ports", d["ip"], time.time() - t_scan,
                                 len(info["ports"]))
                    else:
                        log.warning("Port scan of %s gave no result after %ds (nmap missing, timed out, or host "
                                    "stopped answering)", d["ip"], time.time() - t_scan)
                kind_now = "thorough" if d.get("thorough") else "quick"
                if info and not info["ports"] and d.get("ports") and d.get("empty_scans", 0) < 1 and not self.args.demo:
                    # Every port vanished at once: usually the device's firewall woke up or the scan was cut short.
                    # Keep the last result and believe it only if the next scan agrees.
                    d["empty_scans"] = d.get("empty_scans", 0) + 1
                    log.info("Port scan of %s found no open ports (had %d); waiting for the next scan to confirm",
                             d["ip"], len(d["ports"]))
                    info = None
                if info:
                    d["empty_scans"] = 0
                    before = {p["port"]: p for p in d.get("ports", [])}
                    before_ports = set(before)
                    before_high = {f["text"] for f in d.get("findings", []) if f["level"] == "high"}
                    first_scan = not d.get("deep_scanned_at")
                    same_kind = d.get("scan_kind", kind_now) == kind_now
                    d["scan_kind"] = kind_now
                    d["ports"] = info["ports"]
                    for k in ("os", "os_accuracy", "os_type", "os_family"):
                        if info[k] or k == "os_accuracy":
                            d[k] = info[k]
                    for k in ("os_cpe", "os_hint"):
                        if info.get(k):
                            d[k] = info[k]
                    if "vulners" in info:
                        d["vulners"] = info["vulners"]
                    if "probes" in info:                 # confirmed-vulnerable results from NSE checks (thorough scans)
                        d["probes"] = info["probes"]
                    if info["hostname"] and not d.get("hostname"):
                        d["hostname"] = info["hostname"]
                    if info["vendor"] and (not d.get("vendor") or d["vendor"].startswith("Private")):
                        d["vendor"] = info["vendor"]
                    self.reclassify(d)
                    self.port_changes(d, before, before_ports, first_scan, same_kind, kind_now)
                    for f in d["findings"]:
                        if f["level"] == "high" and f["text"] not in before_high and not f.get("dismissed"):
                            self.event("security", d, f"{self.label(d)}: {f['text']}")
                            self.notify("security", d, f"Security warning: {self.label(d)}", f["text"], 4)
                d["deep_scanned_at"] = time.time()
                self.reclassify(d)
            except Exception:
                log.exception("Deep scan of %s failed", d["ip"])
            finally:
                d["scanning"] = False
            await self.broadcast()
            self.save()
            self.vulns.wake.set()           # new software versions: re-check vulnerabilities


# --------------------------------------------------------------------------- web app
LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>LanPulse · Sign in</title>
<link rel="icon" href="/static/icons/icon.svg" type="image/svg+xml">
<link rel="icon" href="/static/icons/icon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<link rel="manifest" href="/static/manifest.webmanifest">
<meta name="theme-color" content="#0e1527">
<style>*{box-sizing:border-box}body{background:radial-gradient(circle at 50% 30%,#13203d,#0a0f1c 70%);color:#e2e8f0;
font:14px system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px}
form{background:#111a2e;padding:32px;border-radius:16px;border:1px solid #1f2a44;display:grid;gap:12px;width:100%;max-width:320px;
box-shadow:0 20px 50px rgba(0,0,0,.4)}h1{margin:0 0 4px;font-size:22px}h1 b{color:#38bdf8}p{margin:0 0 8px;color:#8b9bb6}
label{font-size:12px;color:#8b9bb6}input{padding:10px 12px;border-radius:9px;border:1px solid #1f2a44;background:#0a0f1c;color:#e2e8f0;
font:inherit;width:100%}input:focus{outline:none;border-color:#0ea5e9}button{margin-top:6px;padding:11px;background:#0ea5e9;border:0;
border-radius:9px;color:#fff;font:600 14px inherit;cursor:pointer}.err{color:#fca5a5;background:#2a0a0a;border:1px solid #7f1d1d;
padding:8px 10px;border-radius:8px}</style></head><body><form method="post" action="/login">
<h1>Lan<b>Pulse</b></h1><p>Sign in to view your network.</p>__ERROR__
<label for="u">Username</label><input id="u" name="user" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form></body></html>"""


def build_app(nm: LanPulse) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        tasks = [asyncio.create_task(nm.sweep_loop())]
        tasks += [asyncio.create_task(nm.deep_worker()) for _ in range(nm.args.workers)]
        tasks += await nm.threats.start()
        tasks += await nm.local.start()
        if not nm.args.demo:
            tasks.append(asyncio.create_task(nm.discovery.run()))
        tasks.append(asyncio.create_task(nm.summary_loop()))
        tasks.append(asyncio.create_task(nm.flows.pump()))
        tasks.append(asyncio.create_task(nm.dns.run()))
        tasks.append(asyncio.create_task(nm.vulns.run()))
        tasks.append(asyncio.create_task(nm.services.run()))
        tasks.append(asyncio.create_task(nm.honeypot.run()))
        tasks.append(asyncio.create_task(nm.openvas.run()))
        if nm.args.demo:
            tasks.append(asyncio.create_task(nm.flows.demo_loop()))
        yield
        for t in tasks:
            t.cancel()
        nm.history.flush(time.time() + 60)
        nm.flows.flush(force=True)
        nm.threats.flush()
        if nm.dns.client:
            nm.dns.client.logout()
        nm.save()

    app = FastAPI(title="LanPulse", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None)
    secure_cookie = bool(nm.args.cert)
    public = ("/login", "/static/", "/api/threats/ingest", "/api/honeypot/ingest", "/favicon.ico")
    def extra_hosts() -> set:          # read live, so changes in Settings > System apply straight away
        return {h.strip().lower() for h in (nm.settings.get("system", {}).get("allow_hosts")
                                           or getattr(nm.args, "allow_host", None) or []) if h.strip()}
    host_ok = lambda headers: host_allowed(headers.get("host", ""), extra_hosts())
    origin_ok = lambda headers: origin_allowed(headers.get("origin"), headers.get("host", ""), extra_hosts())

    def login_page(error: str = "", status: int = 200):
        html = LOGIN_HTML.replace("__ERROR__", f'<div class="err">{error}</div>' if error else "")
        return HTMLResponse(html, status_code=status)

    @app.middleware("http")
    async def auth_guard(request: Request, call_next):
        path = request.url.path
        if not nm.auth.enabled and not host_ok(request.headers):
            return Response("LanPulse only answers to IP addresses and local names when no login is set. "
                            "Set a login, or add this name under Settings > System > Extra host names", 403, media_type="text/plain")
        if request.method not in ("GET", "HEAD", "OPTIONS") and path not in ("/api/threats/ingest", "/api/honeypot/ingest") and not origin_ok(request.headers):
            return JSONResponse({"error": "Request from another web site refused"}, 403)
        if not nm.auth.enabled or path.startswith(public) or nm.auth.verify(request.cookies.get("nm_session")):
            resp = await call_next(request)
        elif path.startswith("/api/"):
            resp = JSONResponse({"error": "Sign in required"}, 401)
        else:
            resp = RedirectResponse("/login", 303)
        if path == "/" or path.startswith("/static/") and not path.startswith("/static/vendor/"):
            resp.headers["Cache-Control"] = "no-cache"      # always check for a newer version after upgrades
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    @app.get("/login")
    async def login_form():
        if not nm.auth.enabled:
            return RedirectResponse("/", 303)
        return login_page()

    @app.post("/login")
    async def login(request: Request):
        ip = request.client.host if request.client else "?"
        if nm.auth.throttled(ip):
            return login_page("Too many attempts. Wait 5 minutes and try again.", 429)
        form = urllib.parse.parse_qs((await request.body()).decode())
        user = form.get("user", [""])[0]
        pw = form.get("password", [""])[0]
        if not nm.auth.check(user, pw):
            nm.auth.failed(ip)
            await asyncio.sleep(1)
            return login_page("Wrong username or password.", 401)
        resp = RedirectResponse("/", 303)
        resp.set_cookie("nm_session", nm.auth.make_session(user), httponly=True, samesite="strict",
                        secure=secure_cookie, max_age=14 * 86400)
        return resp

    @app.get("/logout")
    async def logout():
        resp = RedirectResponse("/login" if nm.auth.enabled else "/", 303)
        resp.delete_cookie("nm_session")
        return resp

    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

    @app.get("/favicon.ico")
    async def favicon():
        return FileResponse(BASE / "static" / "icons" / "favicon.ico", media_type="image/x-icon",
                            headers={"Cache-Control": "max-age=604800"})

    @app.get("/")
    async def index():
        # Version-stamp our own files so a browser never mixes cached files from an older release.
        html = (BASE / "static" / "index.html").read_text()
        html = re.sub(r'(/static/(?!vendor/)[\w./-]+\.(?:css|js))(")', rf'\1?v={VERSION}\2', html)
        return HTMLResponse(html, headers={"Cache-Control": "no-cache"})

    @app.get("/api/devices")
    async def devices():
        return nm.snapshot()

    def get_dev(key: str):
        return nm.devices.get(key)

    @app.post("/api/devices/{key}")
    async def update_device(key: str, request: Request):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return JSONResponse({"error": "Expected a JSON object"}, 400)
        said = []                               # what you changed, for the device's timeline
        if "name" in body and clean_text(str(body["name"]), 64) != d.get("name", ""):
            d["name"] = clean_text(str(body["name"]), 64)
            said.append(f"renamed it to \"{d['name']}\"" if d["name"] else "cleared its display name")
        if "notes" in body:
            d["notes"] = str(body["notes"])[:2000]
        if "type" in body:
            t = str(body["type"])[:32] if body["type"] != "auto" else ""
            if t and not re.fullmatch(r"[a-z0-9_-]{1,32}", t):
                return JSONResponse({"error": "Unknown device type"}, 400)
            if t != d.get("type_override", ""):
                said.append(f"set its type to {t}" if t else "set its type back to auto-detect")
            d["type_override"] = t
        words = {"trusted": ("marked it trusted", "marked it not trusted"), "watched": ("started watching it", "stopped watching it"),
                 "scans_ok": ("allowed it to scan the network", "stopped allowing it to scan"),
                 "thorough": ("turned on thorough scans", "turned off thorough scans")}
        for flag in ("trusted", "watched", "scans_ok", "thorough"):
            if flag in body:
                if bool(body[flag]) != bool(d.get(flag)):
                    said.append(words[flag][0 if body[flag] else 1])
                d[flag] = bool(body[flag])
        if body.get("thorough"):
            nm.enqueue(key)                     # run the thorough scan now
        if "dismiss" in body:
            d["dismissed"] = sorted(set(d.get("dismissed", [])) | {str(body["dismiss"])[:300]})[:50]
            said.append(f"accepted the risk: {str(body['dismiss'])[:120]}")
        if "undismiss" in body:
            d["dismissed"] = [x for x in d.get("dismissed", []) if x != str(body["undismiss"])]
            said.append(f"asked to be warned again: {str(body['undismiss'])[:120]}")
        if said:
            nm.event("you", d, "You " + "; ".join(said), feed=False)
        nm.reclassify(d)
        nm.save()
        await nm.broadcast()
        return d

    @app.post("/api/devices/{key}/rescan")
    async def rescan(key: str):
        if not get_dev(key):
            return JSONResponse({"error": "Device not found"}, 404)
        nm.enqueue(key)
        return {"queued": True}

    @app.post("/api/devices/{key}/wake")
    async def wake(key: str):
        d = get_dev(key)
        if not d or not d.get("mac"):
            return JSONResponse({"error": "This device has no MAC address to wake"}, 400)
        if not nm.args.demo:
            await asyncio.to_thread(wake_on_lan, d["mac"], nm.broadcast_addr)
        return {"sent": True}

    @app.get("/api/devices/{key}/history")
    async def history(key: str, hours: int = 24):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        hours = max(1, min(hours, 168))
        return await asyncio.to_thread(nm.history.query, key, d["first_seen"], hours, 96)

    @app.get("/api/devices/{key}/timeline")
    async def device_timeline(key: str, days: int = 30, limit: int = 300):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        days = max(1, min(days, 90))
        limit = max(10, min(limit, 1000))

        def build():
            items = nm.timeline.query(key, days, limit)
            # threats seen inside the network (ARP spoofing, scans, honeypot hits...) live in their own table
            since = time.time() - days * 86400
            for ev in nm.local.for_device(d["ip"], d.get("mac", "")):
                if ev["t"] < since:
                    continue
                role = "from" if ev.get("src_id") == key or (ev.get("mac") and ev["mac"] == d.get("mac")) else "against"
                items.append({"t": ev["t"], "kind": "threat", "group": "security",
                              "level": "bad" if ev["severity"] == "high" else "warn",
                              "text": f"{ev['title']} ({role} this device): {ev['detail']}"[:400]})
            items.sort(key=lambda x: -x["t"])
            return {"items": items[:limit], "days": days, "first_seen": d.get("first_seen")}
        return await asyncio.to_thread(build)

    @app.delete("/api/devices/{key}")
    async def forget(key: str):
        nm.devices.pop(key, None)
        nm.history.forget(key)
        nm.timeline.forget(key)
        nm.save()
        await nm.broadcast()
        return {"deleted": True}

    @app.post("/api/trust-all")
    async def trust_all():
        for d in nm.devices.values():
            d["trusted"] = True
        nm.save()
        await nm.broadcast()
        return {"trusted": len(nm.devices)}

    @app.post("/api/layout")
    async def save_layout(request: Request):
        body = await request.json()
        pos = body.get("positions") or {}
        nm.settings["layout"] = {str(k): {"x": float(v["x"]), "y": float(v["y"])} for k, v in pos.items()}
        nm.save_settings()
        await nm.broadcast()
        return {"saved": len(nm.settings["layout"])}

    @app.get("/api/settings")
    async def get_settings():
        return alerts.masked(nm.settings)

    @app.post("/api/settings")
    async def set_settings(request: Request):
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return JSONResponse({"error": "Expected a JSON object"}, 400)
        nm.settings = {**alerts.apply_update(nm.settings, body),
                       "layout": nm.settings.get("layout", {})}
        nm.save_settings()
        await asyncio.to_thread(nm.threats.clean_noise)     # drop stored late replies if the filter is on
        return alerts.masked(nm.settings)

    @app.post("/api/settings/test/{channel}")
    async def test_channel(channel: str):
        if channel not in nm.settings["channels"]:
            return JSONResponse({"error": "Unknown channel"}, 404)
        if nm.args.demo:
            return {"ok": True}
        err = await asyncio.to_thread(alerts.send_one, nm.settings, channel, "Test alert",
                                      "LanPulse alerts are working.", 3, {"rule": "test"})
        return {"ok": err is None, "error": err}

    @app.post("/api/account")
    async def account(request: Request):
        body = await request.json()
        user = str(body.get("user", "")).strip()
        new = str(body.get("new_password", ""))
        if nm.auth.enabled and not nm.auth.check(nm.auth.user, str(body.get("current_password", ""))):
            return JSONResponse({"error": "Current password is wrong."}, 403)
        if not user or len(new) < 8:
            return JSONResponse({"error": "Enter a username and a password of at least 8 characters."}, 400)
        nm.auth.set_password(user, new)
        resp = JSONResponse({"ok": True})
        resp.set_cookie("nm_session", nm.auth.make_session(user), httponly=True, samesite="strict",
                        secure=secure_cookie, max_age=14 * 86400)
        await nm.broadcast()
        return resp

    @app.get("/api/export.csv")
    async def export_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["name", "type", "ip", "mac", "vendor", "hostname", "online", "trusted", "watched", "os",
                    "open_ports", "warnings", "first_seen", "last_seen", "notes"])
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""
        for d in sorted(nm.devices.values(), key=lambda d: tuple(int(x) for x in d["ip"].split("."))):
            w.writerow([csv_safe(x) for x in (
                nm.label(d), d["type"], d["ip"], d.get("mac", ""), d.get("vendor", ""), d.get("hostname", ""),
                d["online"], d.get("trusted"), d.get("watched"), d.get("os", ""),
                " ".join(str(p["port"]) for p in d.get("ports", [])),
                " | ".join(f["text"] for f in d.get("findings", [])),
                fmt(d["first_seen"]), fmt(d["last_seen"]), d.get("notes", ""))])
        name = time.strftime("lanpulse-%Y%m%d-%H%M.csv")
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/threats/summary")
    async def threat_summary(hours: int = 24):
        return await asyncio.to_thread(nm.threats.summary, max(1, min(hours, 720)))

    @app.get("/api/threats/ip/{ip}")
    async def threat_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return JSONResponse({"error": "Not a valid IP address"}, 400)
        return await asyncio.to_thread(nm.threats.investigate, ip)

    @app.get("/api/export/iocs.txt")
    async def export_iocs(reached: int = 0, hours: int = 168):
        """The attacker IPs as a plain block list (one per line). reached=1 limits it to IPs that got through to a
        LAN device. For your own firewall or to share as indicators of compromise."""
        def build():
            s = nm.threats.summary(max(1, min(hours, 720)))
            reached_set = nm.threats.reached_ips(hours) if reached else set()
            ips = []
            for a in s.get("attackers", []):
                ip = a.get("ip", "")
                try:
                    ipaddress.ip_address(ip)       # only real addresses in the block list
                except ValueError:
                    continue
                if not reached or ip in reached_set:
                    ips.append(ip)
            header = [f"# LanPulse attacker IPs — {time.strftime('%Y-%m-%d %H:%M')}",
                      f"# {'reached a LAN device' if reached else 'all sources'}, last {min(hours,720)}h, {len(ips)} addresses", ""]
            return "\n".join(header + ips) + "\n"
        return _download(await asyncio.to_thread(build), "text/plain", "lanpulse-iocs.txt")

    # ---- updates (Settings > Update). The sandboxed web app only stages the file; a root-only helper installs it.
    upd_dir = Path(nm.data_dir) / "update"
    updater_unit = Path("/etc/systemd/system/lanpulse-update.path")

    def update_state() -> dict:
        out = {"current": VERSION, "updater": updater_unit.exists() and not nm.args.demo, "login": nm.auth.enabled,
               "state": "", "message": "", "staged": None, "log": ""}
        try:
            st = json.loads((upd_dir / "status.json").read_text())
            out["state"], out["message"], out["state_t"] = st.get("state", ""), st.get("message", ""), st.get("t", 0)
        except (OSError, ValueError):
            pass
        # The updater writes "installing", then "done" once LanPulse is back. If "done" never arrived (older
        # updaters could lose their last step), work it out here instead of showing "Installing" forever.
        if out["state"] in ("installing", "queued") and not (upd_dir / "request").exists():
            began = out.get("state_t") or 0
            fixed = None
            if out["state"] == "installing" and STARTED > began:
                if time.time() - STARTED > 90:                 # we restarted after it began and have been up a while
                    fixed = ("done", "Update installed.")
            elif time.time() - began > 25 * 60:
                fixed = ("failed", "The updater stopped without reporting back. Check the log below.")
            if fixed:
                out["state"], out["message"] = fixed
                try:
                    tmp = upd_dir / "status.json.tmp"
                    tmp.write_text(json.dumps({"state": fixed[0], "message": fixed[1], "t": int(time.time())}))
                    tmp.replace(upd_dir / "status.json")
                    out["state_t"] = int(time.time())
                except OSError:
                    pass
        if (upd_dir / "request").exists() and out["state"] not in ("installing",):
            out["state"], out["message"] = "queued", "Waiting for the updater to start…"
        z = upd_dir / "incoming.zip"
        if z.exists() and out["state"] not in ("installing", "queued"):
            try:
                out["staged"] = check_update_zip(z)
            except ValueError:
                out["staged"] = None
        try:
            out["log"] = "\n".join((upd_dir / "log.txt").read_text(errors="replace").splitlines()[-40:])
        except OSError:
            pass
        return out

    def update_refusal():
        if nm.args.demo:
            return JSONResponse({"error": "Updates are turned off in demo mode."}, 400)
        if not nm.auth.enabled:
            return JSONResponse({"error": "Set a login first (Login tab). Updates run with administrator rights, "
                                          "so LanPulse only allows them when the dashboard is password protected."}, 403)
        if not updater_unit.exists():
            return JSONResponse({"error": "The updater isn't installed yet. Install this version once from the "
                                          "terminal with install.sh; after that, updates work from here."}, 400)
        return None

    @app.get("/api/update")
    async def update_status():
        return update_state()

    @app.post("/api/update/upload")
    async def update_upload(request: Request):
        if (r := update_refusal()):
            return r
        upd_dir.mkdir(parents=True, exist_ok=True)
        tmp = upd_dir / "upload.part"
        size = 0
        with open(tmp, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > UPDATE_MAX_BYTES:
                    f.close()
                    tmp.unlink(missing_ok=True)
                    return JSONResponse({"error": "That file is too big for a LanPulse update."}, 413)
                f.write(chunk)
        try:
            info = await asyncio.to_thread(check_update_zip, tmp)
        except ValueError as e:
            tmp.unlink(missing_ok=True)
            return JSONResponse({"error": str(e)}, 400)
        tmp.replace(upd_dir / "incoming.zip")
        (upd_dir / "status.json").unlink(missing_ok=True)
        cmp = (version_tuple(info["version"]) > version_tuple(VERSION)) - (version_tuple(info["version"]) < version_tuple(VERSION))
        return {**info, "current": VERSION, "kind": {1: "newer", 0: "same", -1: "older"}[cmp]}

    @app.get("/api/update/check")
    async def update_check(force: bool = False):
        import releases
        return await asyncio.to_thread(releases.latest, VERSION, force)

    @app.post("/api/update/fetch")
    async def update_fetch():
        """Download the newest GitHub release into the same staging slot an upload uses; installing still needs a click."""
        import releases
        if (r := update_refusal()):
            return r
        rel = await asyncio.to_thread(releases.latest, VERSION, True)
        if rel.get("error"):
            return JSONResponse({"error": rel["error"]}, 502)
        if not rel.get("asset_url"):
            return JSONResponse({"error": "The latest release has no lanpulse.zip attached."}, 404)
        upd_dir.mkdir(parents=True, exist_ok=True)
        tmp = upd_dir / "upload.part"
        try:
            await asyncio.to_thread(releases.download, rel["asset_url"], tmp, UPDATE_MAX_BYTES)
            info = await asyncio.to_thread(check_update_zip, tmp)
        except ValueError as e:
            tmp.unlink(missing_ok=True)
            return JSONResponse({"error": str(e)}, 400)
        except Exception as e:
            tmp.unlink(missing_ok=True)
            return JSONResponse({"error": f"Couldn't download the release ({e.__class__.__name__})."}, 502)
        tmp.replace(upd_dir / "incoming.zip")
        (upd_dir / "status.json").unlink(missing_ok=True)
        return update_state()

    @app.post("/api/update/apply")
    async def update_apply():
        if (r := update_refusal()):
            return r
        if not (upd_dir / "incoming.zip").exists():
            return JSONResponse({"error": "Upload an update file first."}, 400)
        (upd_dir / "status.json").write_text(json.dumps({"state": "queued", "message": "Starting the updater…",
                                                         "t": time.time()}))
        (upd_dir / "request").write_text(json.dumps({"t": time.time()}))
        log.info("Update requested from the dashboard")
        return update_state()

    @app.post("/api/update/discard")
    async def update_discard():
        for n in ("incoming.zip", "upload.part"):
            (upd_dir / n).unlink(missing_ok=True)
        return update_state()

    # ---- DNS (Pi-hole)
    @app.get("/api/dns")
    async def dns_summary(hours: int = 24, device: str = ""):
        hours = max(1, min(168, hours))
        return await asyncio.to_thread(nm.dns.summary, hours, device[:45])

    @app.post("/api/dns/malware-refresh")
    async def dns_malware_refresh():
        await asyncio.to_thread(nm.dns.refresh_malware, True)
        return {"count": len(nm.dns.malware), "status": nm.dns.malware_status}

    @app.post("/api/dns/test")
    async def dns_test(request: Request):
        body = await request.json()
        cfg = alerts.apply_update(nm.settings, {"dns": body})["dns"]
        return await asyncio.to_thread(nm.dns.test, cfg)

    # ---- vulnerabilities
    @app.get("/api/vulns")
    async def vulns_summary():
        return nm.vulns.summary()

    @app.get("/api/vulns/device/{key}")
    async def vulns_device(key: str):
        return {"items": nm.vulns.for_device(key), "status": nm.vulns.status}

    @app.post("/api/vulns/refresh")
    async def vulns_refresh():
        nm.vulns.wake.set()
        return {"ok": True}

    # ---- Red Team: ATT&CK mapping, Metasploit hand-off and exports (all built from data already scanned -
    # no new connections to any device). LanPulse generates commands; it never runs an exploit.
    posture_cache: dict = {"t": 0.0, "data": None}

    @app.get("/api/posture")
    async def posture_get(days: int = 30):
        def build():
            now = time.time()
            if posture_cache["data"] and now - posture_cache["t"] < 60:    # recompute at most once a minute
                cur = dict(posture_cache["data"])
            else:
                cur = posture.compute(nm)
                nm.posture.record(cur["score"], cur["grade"])
                posture_cache.update(t=now, data=cur)
            cur["history"] = nm.posture.history(days)
            return cur
        return await asyncio.to_thread(build)

    # ---- AI analyst (read-only; explains what LanPulse already knows, never acts)
    @app.get("/api/ai")
    async def ai_status():
        return analyst.status(nm)

    @app.post("/api/ai/ask")
    async def ai_ask(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = None
        q = str(body.get("question", ""))[:1000] if isinstance(body, dict) else ""
        return await asyncio.to_thread(analyst.ask, nm, q)

    @app.post("/api/ai/test")
    async def ai_test(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = None
        cfg = analyst._cfg(nm)
        if isinstance(body, dict):              # test unsaved values from the form, keeping a saved (masked) key
            for k in ("provider", "base_url", "model", "api_key"):
                v = str(body.get(k) or "").strip()
                if v and v != alerts.MASK:
                    cfg[k] = v
            if cfg["provider"] not in analyst.PROVIDERS:
                return JSONResponse({"error": "Unknown provider"}, 400)
            base, model = analyst.DEFAULTS[cfg["provider"]]
            cfg["base_url"] = (cfg["base_url"] or base).rstrip("/")
            cfg["model"] = cfg["model"] or model
        ok, msg = await asyncio.to_thread(analyst.test, cfg)
        return {"ok": ok, "message": msg}

    @app.get("/api/redteam")
    async def redteam_summary():
        def build():
            return redteam.attack_rows(list(nm.devices.values()), nm.vulns.results, nm.vulns.kev)
        return await asyncio.to_thread(build)

    @app.get("/api/redteam/device/{key}")
    async def redteam_device(key: str):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        findings = nm.vulns.for_device(key)
        score, band = redteam.exploitability(findings, d)
        return {"ip": d["ip"], "name": nm.label(d),
                "techniques": redteam._techs_for_device(d, findings),
                "default_creds": redteam.default_cred_services(d),
                "cleartext": redteam.cleartext_exposures(d),
                "score": score, "band": band,
                "targets": redteam.device_targets(d, findings)}

    def _download(text: str, media: str, filename: str) -> Response:
        safe = re.sub(r"[^A-Za-z0-9._-]", "", filename)[:60] or "lanpulse.txt"
        return Response(text, media_type=media, headers={"Content-Disposition": f'attachment; filename="{safe}"'})

    @app.get("/api/export/nmap.xml")
    async def export_nmap(device: str = ""):
        devs = [get_dev(device)] if device else list(nm.devices.values())
        if device and not devs[0]:
            return JSONResponse({"error": "Device not found"}, 404)
        xml = await asyncio.to_thread(redteam.nmap_xml, [d for d in devs if d])
        return _download(xml, "text/xml", "lanpulse-scan.xml")

    @app.get("/api/export/metasploit.rc")
    async def export_msf(device: str = ""):
        devs = [get_dev(device)] if device else [d for d in nm.devices.values() if not d.get("is_self")]
        if device and not devs[0]:
            return JSONResponse({"error": "Device not found"}, 404)
        pairs = [(d, redteam.device_targets(d, nm.vulns.for_device(d["id"]))) for d in devs if d]
        rc = await asyncio.to_thread(redteam.resource_script, pairs)
        return _download(rc, "text/plain", "lanpulse.rc")

    @app.get("/api/export/report.html")
    async def export_report():
        def build():
            return redteam.report_html(nm, nm.vulns.results, nm.vulns.kev)
        return HTMLResponse(await asyncio.to_thread(build))

    @app.get("/api/export/attack-layer.json")
    async def export_attack_layer():
        def build():
            return json.dumps(redteam.attack_layer(list(nm.devices.values()), nm.vulns.results), indent=2)
        return _download(await asyncio.to_thread(build), "application/json", "lanpulse-attack-layer.json")

    # ---- services (uptime)
    @app.get("/api/services")
    async def services_summary():
        out = await asyncio.to_thread(nm.services.summary)
        out["suggestions"] = nm.services.suggestions()
        return out

    @app.post("/api/services")
    async def services_save(request: Request):
        body = await request.json()
        nm.settings = alerts.apply_update(nm.settings, {"services": {"checks": body.get("checks", [])}})
        nm.save_settings()
        keep = {c["id"] for c in nm.settings["services"]["checks"]}
        for cid in list(nm.services.state):
            if cid not in keep:
                nm.services.state.pop(cid, None)
        nm.services.dirty = True
        out = await asyncio.to_thread(nm.services.summary)
        out["suggestions"] = nm.services.suggestions()
        return out

    @app.post("/api/services/test")
    async def services_test(request: Request):
        c = alerts.clean_check(await request.json())
        if not c:
            return JSONResponse({"error": "That check isn't valid. Check the address or port."}, 400)
        if nm.args.demo:
            return {"ok": True, "ms": 12.3, "error": ""}
        from services import run_check
        ok, ms, err = await asyncio.to_thread(run_check, c)
        return {"ok": ok, "ms": ms, "error": err}

    @app.get("/api/services/{cid}/history")
    async def services_history(cid: str, hours: int = 24):
        return await asyncio.to_thread(nm.services.history, cid[:16], max(1, min(720, hours)))

    # ---- Settings > System (network, scanning, web server)
    def running_system() -> dict:
        return {"iface": nm.net.get("iface", ""), "subnet": nm.net.get("subnet", ""), "my_ip": nm.net.get("my_ip", ""),
                "gateway": nm.net.get("gateway", ""), "port": nm.args.port, "https": bool(nm.args.cert),
                "host": nm.args.host, "workers": nm.args.workers}

    def system_view() -> dict:
        sysset = nm.settings["system"]
        run = running_system()
        pending = []
        for k in alerts.SYSTEM_RESTART:
            want = sysset.get(k)
            if k in ("iface", "subnet"):
                if want and want != run[k]:
                    pending.append(k)
            elif want != run[k]:
                pending.append(k)
        try:
            ifaces = sorted(n for n in os.listdir("/sys/class/net") if n != "lo")
        except OSError:
            ifaces = []
        try:
            ufw = "ENABLED=yes" in Path("/etc/ufw/ufw.conf").read_text()
        except OSError:
            ufw = False
        return {"system": {k: v for k, v in sysset.items() if not k.startswith("_") and k not in ("cert", "key")},
                "running": run, "pending": pending, "interfaces": ifaces, "ufw": ufw, "demo": nm.args.demo,
                "version": VERSION}

    @app.get("/api/system")
    async def system_get():
        return system_view()

    @app.post("/api/system")
    async def system_set(request: Request):
        body = await request.json()
        new, problems = alerts.clean_system(body if isinstance(body, dict) else {}, nm.settings["system"])
        if problems:
            return JSONResponse({"error": "; ".join(problems).capitalize() + "."}, 400)
        risky = [k for k in (*alerts.SYSTEM_RESTART, "allow_hosts") if new.get(k) != nm.settings["system"].get(k)]
        if risky and not nm.auth.enabled:
            return JSONResponse({"error": "Set a login first (Login tab). Without one, anyone on your network could change "
                                          "the web server or network settings and lock everyone out."}, 403)
        if (new["port"], new["host"]) != (nm.args.port, nm.args.host) and not nm.args.demo:
            in_use = await asyncio.to_thread(port_in_use, new["host"], new["port"])
            if in_use:
                return JSONResponse({"error": f"Port {new['port']} is already used by another program on this machine. "
                                              "Pick a different port."}, 400)
        nm.settings["system"] = {**nm.settings["system"], **new}
        nm.save_settings()
        # these apply immediately
        for k in ("interval", "offline_after", "rescan", "top_ports"):
            setattr(nm.args, k, new[k])
        nm.args.no_deep = not new["deep"]
        return system_view()

    @app.post("/api/system/restart")
    async def system_restart():
        if nm.args.demo:
            return JSONResponse({"error": "Restart is turned off in demo mode."}, 400)
        if not nm.auth.enabled:
            return JSONResponse({"error": "Set a login first (Login tab) to restart LanPulse from the dashboard."}, 403)
        log.info("Restart requested from the dashboard")

        def stop():
            try:
                nm.history.flush(time.time() + 60)
                nm.flows.flush(force=True)
                nm.threats.flush()
                nm.save()
            finally:
                os._exit(75)            # systemd starts LanPulse again (Restart=on-failure)
        asyncio.get_running_loop().call_later(1.0, stop)
        return {"ok": True, "url_hint": {"port": nm.settings["system"]["port"], "https": nm.settings["system"]["https"]}}

    @app.post("/api/threats/syslog-allow")
    async def syslog_allow(request: Request):
        ip = str((await request.json()).get("ip", "")).strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return JSONResponse({"error": "Not an IP address"}, 400)
        t = nm.settings["threats"]
        t["syslog_from"] = sorted(set(t.get("syslog_from", [])) | {ip})
        nm.threats.syslog_rejected.pop(ip, None)
        nm.save_settings()
        nm.threats.dirty = True
        return {"syslog_from": t["syslog_from"]}

    @app.post("/api/threats/ingest")
    async def threat_ingest(request: Request):
        key = request.headers.get("x-api-key") or request.query_params.get("key") or ""
        if not secrets.compare_digest(key, nm.settings["threats"]["ingest_key"]):
            return JSONResponse({"error": "Wrong or missing X-API-Key"}, 401)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Body must be JSON"}, 400)
        items = body if isinstance(body, list) else [body]
        from threats import parse_json
        accepted = 0
        for item in items[:500]:
            ev = parse_json(item) if isinstance(item, dict) else None
            if ev and nm.threats.ingest(ev, sensor=ev.get("sensor") or "api"):
                accepted += 1
        return {"accepted": accepted}

    # ---- outbound traffic
    @app.get("/api/flows")
    async def flow_summary(hours: int = 24, device: str = ""):
        return await asyncio.to_thread(nm.flows.summary, max(1, min(hours, 168)), device)

    @app.get("/api/devices/{key}/flows")
    async def device_flows(key: str, hours: int = 24):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        return await asyncio.to_thread(nm.flows.summary, max(1, min(hours, 168)), d["ip"])

    # ---- OpenVAS / Greenbone (Settings > Scanner). The sandboxed web app only writes a request file; a root-only
    # helper (lanpulse-openvas) installs Docker and the Greenbone containers.
    ov_dir = Path(nm.data_dir) / "openvas"
    ov_unit = Path("/etc/systemd/system/lanpulse-openvas.path")

    @app.get("/api/openvas")
    async def openvas_status():
        st = await asyncio.to_thread(nm.openvas.status)
        st["helper_installed"] = ov_unit.exists() and not nm.args.demo
        st["login"] = nm.auth.enabled
        return st

    @app.post("/api/openvas/install")
    async def openvas_install(request: Request):
        body = await request.json()
        action = body.get("action") if isinstance(body, dict) else ""
        if action not in ("install", "remove"):
            return JSONResponse({"error": "Unknown action."}, 400)
        if nm.args.demo:
            return JSONResponse({"error": "Not available in demo mode."}, 400)
        if not nm.auth.enabled:
            return JSONResponse({"error": "Set a login first (Login tab). Installing OpenVAS runs with administrator "
                                          "rights, so LanPulse only allows it when the dashboard is password protected."}, 403)
        if not ov_unit.exists():
            return JSONResponse({"error": "The OpenVAS installer helper isn't set up yet. Re-run install.sh from the "
                                          "terminal once (sudo ./install.sh --upgrade); after that it works from here."}, 400)
        cur = nm.openvas.helper_state()
        if cur.get("state") in ("installing", "queued") and (ov_dir / "request").exists():
            return JSONResponse({"error": "An OpenVAS install is already in progress."}, 409)
        ov_dir.mkdir(parents=True, exist_ok=True)
        (ov_dir / "status.json").write_text(json.dumps({"state": "queued", "message": "Starting…", "t": time.time()}))
        (ov_dir / "request").write_text(json.dumps({"action": action, "t": time.time()}))
        log.info("OpenVAS %s requested from the dashboard", action)
        return {"ok": True}

    @app.post("/api/openvas/scan")
    async def openvas_scan(request: Request):
        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse({"error": "Bad request."}, 400)
        ips = [d["ip"] for d in nm.devices.values() if d.get("ip") and d.get("online") and not d.get("is_self")] \
            if body.get("all") else [str(body.get("ip", ""))]
        if not nm.openvas.cfg()["enabled"]:
            return JSONResponse({"error": "Turn on OpenVAS in Settings > Scanner first."}, 400)
        started, err = 0, ""
        for ip in ips[:60]:
            e = await asyncio.to_thread(nm.openvas.start_scan, ip)
            if e:
                err = e
                if not body.get("all"):
                    break
            else:
                started += 1
        if not started and err:
            return JSONResponse({"error": err}, 400)
        return {"started": started}

    # ---- honeypot (built-in low-interaction decoy services)
    @app.get("/api/honeypot")
    async def honeypot_summary(hours: int = 168):
        return await asyncio.to_thread(nm.honeypot.summary, max(1, min(hours, 2160)))

    @app.post("/api/honeypot/ingest")
    async def honeypot_ingest(request: Request):
        key = request.headers.get("X-LanPulse-Key", "") or request.query_params.get("key", "")
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "Expected a JSON object"}, 400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "Expected a JSON object"}, 400)
        ok, msg = await asyncio.to_thread(nm.honeypot.ingest, payload, key)
        return JSONResponse({"ok": True}) if ok else JSONResponse({"error": msg}, 403)

    # ---- local threats
    @app.get("/api/local")
    async def local_summary(hours: int = 24):
        return await asyncio.to_thread(nm.local.summary, max(1, min(hours, 720)))

    @app.get("/api/devices/{key}/local")
    async def device_local(key: str):
        d = get_dev(key)
        if not d:
            return JSONResponse({"error": "Device not found"}, 404)
        return await asyncio.to_thread(nm.local.for_device, d["ip"], d.get("mac", ""))

    # ---- blocking on the UniFi gateway
    def unifi_client():
        return UniFi(nm.settings["unifi"], nm.net.get("gateway"))

    async def blocked_list(force: bool = False) -> list[str]:
        if nm.args.demo:
            return list(nm.demo_blocked)
        t, ips = nm.blocked_cache
        if force or time.time() - t > 60:
            c = unifi_client()
            ips = await asyncio.to_thread(c.blocked) if c.configured else []
            nm.blocked_cache = (time.time(), ips)
        return ips

    @app.get("/api/unifi/blocked")
    async def unifi_blocked():
        c = unifi_client()
        if not (c.configured or nm.args.demo):
            return {"configured": False, "blocked": []}
        try:
            return {"configured": True, "blocked": await blocked_list()}
        except UniFiError as e:
            return {"configured": True, "blocked": [], "error": str(e)}

    @app.post("/api/unifi/test")
    async def unifi_test():
        if nm.args.demo:
            return {"ok": True, "ms": 42, "groups": 3, "group_exists": True, "blocked": len(nm.demo_blocked)}
        c = unifi_client()
        if not c.configured:
            return JSONResponse({"ok": False, "error": "Enter the gateway address and an API key or local account."}, 400)
        try:
            return await asyncio.to_thread(c.test)
        except UniFiError as e:
            return JSONResponse({"ok": False, "error": str(e)}, 502)

    async def change_block(request: Request, block: bool):
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return JSONResponse({"error": "Not a valid IP address"}, 400)
        if block and (a.is_private or ip == nm.threats.public_ip):
            return JSONResponse({"error": "That's one of your own addresses; LanPulse won't block it."}, 400)
        if nm.args.demo:
            if block and ip not in nm.demo_blocked:
                nm.demo_blocked.append(ip)
            if not block and ip in nm.demo_blocked:
                nm.demo_blocked.remove(ip)
            return {"blocked": nm.demo_blocked}
        c = unifi_client()
        if not c.configured:
            return JSONResponse({"error": "Connect your UniFi gateway in Settings > UniFi first."}, 400)
        try:
            ips = await asyncio.to_thread(c.block if block else c.unblock, ip)
        except UniFiError as e:
            return JSONResponse({"error": str(e)}, 502)
        nm.blocked_cache = (time.time(), ips)
        return {"blocked": ips}

    @app.post("/api/threats/block")
    async def block_ip(request: Request):
        return await change_block(request, True)

    @app.post("/api/threats/unblock")
    async def unblock_ip(request: Request):
        return await change_block(request, False)

    # ---- daily summary
    @app.get("/api/summary/preview")
    async def summary_preview():
        return {"text": await asyncio.to_thread(nm.daily_text)}

    @app.post("/api/summary/send")
    async def summary_send():
        text = await asyncio.to_thread(nm.daily_text)
        if nm.args.demo:
            return {"ok": True, "text": text, "results": {}}
        if not any(c.get("enabled") for c in nm.settings["channels"].values()):
            return JSONResponse({"ok": False, "error": "Turn on an alert channel under 'Where to send' first."}, 400)
        res = await asyncio.to_thread(alerts.send_all, nm.settings, "LanPulse daily summary", text, 3, {"rule": "summary"})
        errors = {k: v for k, v in res.items() if v}
        return {"ok": not errors, "text": text, "errors": errors}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        if not origin_ok(websocket.headers) or (not nm.auth.enabled and not host_ok(websocket.headers)):
            await websocket.close(code=4403)        # another web site trying to read the live feed
            return
        if nm.auth.enabled and not nm.auth.verify(websocket.cookies.get("nm_session")):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        nm.clients.add(websocket)
        try:
            await websocket.send_text(json.dumps(nm.snapshot()))
            await websocket.send_text(json.dumps(await asyncio.to_thread(nm.threats.summary)))
            await websocket.send_text(json.dumps({"type": "local_summary", **(await asyncio.to_thread(nm.local.summary))}))
            while True:
                await websocket.receive_text()   # keep-alive pings from the browser
        except WebSocketDisconnect:
            pass
        finally:
            nm.clients.discard(websocket)

    return app


def set_password_cli(data_dir: str):
    auth = Auth(Path(data_dir) / "auth.json")
    print("Set the LanPulse dashboard login.")
    user = input(f"Username [{auth.user or 'admin'}]: ").strip() or auth.user or "admin"
    while True:
        pw = getpass.getpass("Password (8+ characters): ")
        if len(pw) < 8:
            print("Too short.")
        elif pw != getpass.getpass("Repeat password: "):
            print("Passwords don't match.")
        else:
            break
    auth.set_password(user, pw)
    print(f"Saved. Restart LanPulse if it's running: sudo systemctl restart lanpulse")


def port_in_use(host: str, port: int) -> bool:
    """Would LanPulse fail to start on this port because another program already listens there?"""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return False
        except OSError:
            return True


def ensure_cert(data_dir: Path, ip: str) -> tuple[str, str] | None:
    """Self-signed certificate for HTTPS (made once, kept in the data folder)."""
    cert, key = data_dir / "cert.pem", data_dir / "key.pem"
    if cert.exists() and key.exists():
        return str(cert), str(key)
    host = socket.gethostname()
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", "/CN=lanpulse",
                        "-addext", f"subjectAltName=IP:{ip},DNS:{host},DNS:localhost",
                        "-keyout", str(key), "-out", str(cert)], capture_output=True, timeout=60, check=True)
        os.chmod(key, 0o600)
        log.info("Created a self-signed HTTPS certificate in %s", data_dir)
        return str(cert), str(key)
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("Couldn't create an HTTPS certificate (%s); serving plain HTTP.", e)
        return None


# Command-line options that now live in Settings > System. They're read once (moved into settings) and after that
# the dashboard is where they're changed.
CLI_SYSTEM = ("host", "port", "iface", "subnet", "interval", "offline_after", "rescan", "top_ports", "workers")


def load_system_settings(args) -> dict:
    """Merge Settings > System with any command-line options, moving the options into settings the first time."""
    path = Path(args.data_dir) / "settings.json"
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError):
        raw = {}
    settings = alerts.with_defaults(raw)
    system = settings["system"]
    given = {k: getattr(args, k) for k in CLI_SYSTEM if getattr(args, k) is not None}
    if args.no_deep:
        given["deep"] = False
    if args.cert:
        given["https"] = True
    if args.allow_host:
        given["allow_hosts"] = args.allow_host
    first = not system.get("_imported")
    if given and (first or args.import_args):
        system, problems = alerts.clean_system(given, system)
        for p in problems:
            log.warning("Ignored command-line option: %s", p)
        if args.cert and args.key:
            system["cert"], system["key"] = args.cert, args.key
        log.info("Moved command-line options into Settings > System: %s", ", ".join(sorted(given)))
    elif given and not args.demo:
        log.warning("Command-line options %s are ignored: these are set in Settings > System now. "
                    "(Run with --import-args to copy them in again.)", ", ".join(sorted(given)))
    if first or (given and args.import_args):
        system["_imported"] = True
        settings["system"] = system
        if not args.demo:
            Path(args.data_dir).mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(settings, indent=1))
            os.chmod(tmp, 0o600)
            tmp.replace(path)
    return system


def main():
    ap = argparse.ArgumentParser(description="LanPulse - real-time visual network mapper. Network, scanning and web "
                                             "server options are set in the dashboard (Settings > System).")
    ap.add_argument("--data-dir", default=str(BASE / "data"))
    ap.add_argument("--set-password", action="store_true", help="set the dashboard login and exit")
    ap.add_argument("--reset-web", action="store_true",
                    help="locked out? reset the web server to port 8080, plain HTTP, all addresses, and exit")
    ap.add_argument("--import-args", action="store_true", help="copy the options below into Settings > System and exit")
    ap.add_argument("--demo", action="store_true", help="simulated network, no scanning")
    ap.add_argument("--verbose", action="store_true")
    old = ap.add_argument_group("options now set in Settings > System (read once, then ignored)")
    old.add_argument("--host")
    old.add_argument("--port", type=int)
    old.add_argument("--iface")
    old.add_argument("--subnet")
    old.add_argument("--interval", type=float)
    old.add_argument("--offline-after", type=float)
    old.add_argument("--rescan", type=float)
    old.add_argument("--top-ports", type=int)
    old.add_argument("--workers", type=int)
    old.add_argument("--no-deep", action="store_true")
    old.add_argument("--cert")
    old.add_argument("--key")
    old.add_argument("--allow-host", action="append", metavar="NAME")
    args = ap.parse_args()

    if args.set_password:
        set_password_cli(args.data_dir)
        return
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.reset_web:
        path = Path(args.data_dir) / "settings.json"
        settings = alerts.with_defaults(json.loads(path.read_text()) if path.exists() else {})
        settings["system"].update(port=8080, https=False, host="0.0.0.0", _imported=True)
        path.write_text(json.dumps(settings, indent=1))
        os.chmod(path, 0o600)
        print("Web server reset to http://<this-ip>:8080. Now run: sudo systemctl restart lanpulse")
        return
    system = load_system_settings(args)
    if args.import_args:
        print("Saved to Settings > System:", json.dumps({k: v for k, v in system.items() if not k.startswith("_")}))
        return
    # the effective options for this run
    for k in ("host", "port", "interval", "offline_after", "rescan", "top_ports", "workers"):
        setattr(args, k, system[k])
    args.iface, args.subnet = system["iface"] or None, system["subnet"] or None
    args.no_deep = not system["deep"]
    args.allow_host = list(system.get("allow_hosts") or [])
    args.cert = args.key = None

    if not args.demo and not IS_ROOT:
        log.warning("Not running as root: ARP sweeps, MAC addresses and OS detection will be limited.")
    if not args.demo and not HAVE_NMAP:
        log.warning("nmap not found: install it with 'sudo apt install nmap' for port/OS details.")
    load_vendors()
    load_ieee(args.data_dir)
    nm = LanPulse(args)
    if system.get("https"):
        if system.get("cert") and system.get("key") and Path(system["cert"]).exists() and Path(system["key"]).exists():
            args.cert, args.key = system["cert"], system["key"]
        else:
            pair = ensure_cert(Path(args.data_dir), nm.net.get("my_ip", "127.0.0.1"))
            if pair:
                args.cert, args.key = pair
    if not nm.auth.enabled:
        log.warning("No login set. Anyone on your network can open the dashboard. Run: app.py --set-password")
    scheme = "https" if args.cert else "http"
    log.info("Scanning %s on %s every %ss | open %s://<this-ip>:%d", nm.net["subnet"], nm.net["iface"],
             args.interval, scheme, args.port)
    uvicorn.run(build_app(nm), host=args.host, port=args.port, log_level="warning",
                ssl_certfile=args.cert, ssl_keyfile=args.key)


if __name__ == "__main__":
    main()
