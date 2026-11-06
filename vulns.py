# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Vulnerabilities: known security flaws (CVEs) in the software your devices run.

The port scan (nmap -sV) names each service and its version as a CPE, e.g. cpe:/a:openbsd:openssh:7.9p1.
For each product LanPulse fetches every CVE that NVD (the US National Vulnerability Database) lists for it, once
a week, and checks the exact version against each CVE's affected versions itself. CVEs on CISA's Known Exploited
Vulnerabilities list (attackers are using them right now) are flagged and ranked first.

Version matching can't see patches your OS vendor back-ported (Ubuntu and Debian often fix a flaw without changing
the upstream version number), so results for distribution packages are marked as "may be patched".
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import signatures

log = logging.getLogger("lanpulse.vulns")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DAYS = 7
MSF_META = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
UNRELIABLE_VERSION = re.compile(r"^distccd", re.I)
WILDCARD_VER = re.compile(r"(\d\.x\b|\bx\.|\s-\s|\bor later\b)", re.I)     # "3.X - 4.X": not an exact version

# nmap's product IDs sometimes use a different vendor name than NVD does
CPE_ALIASES = {
    ("vsftpd", "vsftpd"): [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")],
    ("mysql", "mysql"): [("mysql", "mysql"), ("oracle", "mysql")],
    ("igor_sysoev", "nginx"): [("f5", "nginx"), ("nginx", "nginx")],
    ("nginx", "nginx"): [("f5", "nginx"), ("nginx", "nginx")],
    ("microsoft", "iis"): [("microsoft", "internet_information_services")],
    ("microsoft", "internet_information_server"): [("microsoft", "internet_information_services")],
    ("apache", "coyote_http_connector"): [],
    ("samba", "samba"): [("samba", "samba")],
    ("php", "php"): [("php", "php")],
    ("mariadb", "mariadb"): [("mariadb", "mariadb")],
    ("unrealircd", "unrealircd"): [("unrealircd", "unrealircd")],
}

# Recognise server software by the name nmap reports when it gives no product ID (NVD vendor:product names)
NAME_MAP = [(re.compile(rx, re.I), prods) for rx, prods in [
    (r"^vsftpd", [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")]),
    (r"^openssh", [("openbsd", "openssh")]),
    (r"^dropbear", [("dropbear_ssh_project", "dropbear_ssh")]),
    (r"^apache httpd", [("apache", "http_server")]),
    (r"^apache tomcat(?!/coyote)", [("apache", "tomcat")]),
    (r"^samba smbd", [("samba", "samba")]),
    (r"^proftpd", [("proftpd", "proftpd")]),
    (r"^pure-?ftpd", [("pureftpd", "pure-ftpd")]),
    (r"^mysql", [("mysql", "mysql"), ("oracle", "mysql")]),
    (r"^mariadb", [("mariadb", "mariadb")]),
    (r"^postgresql", [("postgresql", "postgresql")]),
    (r"^unrealircd", [("unrealircd", "unrealircd")]),
    (r"^distccd", [("samba", "distcc")]),       # nmap reports distcc's protocol version, not the software version
    (r"^postfix", [("postfix", "postfix")]),
    (r"^exim", [("exim", "exim")]),
    (r"^dovecot", [("dovecot", "dovecot")]),
    (r"^isc bind", [("isc", "bind")]),
    (r"^dnsmasq", [("thekelleys", "dnsmasq")]),
    (r"^nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    (r"^lighttpd", [("lighttpd", "lighttpd")]),
    (r"^microsoft iis", [("microsoft", "internet_information_services")]),
    (r"^squid", [("squid-cache", "squid")]),
    (r"^jetty", [("eclipse", "jetty")]),
    (r"^werkzeug", [("palletsprojects", "werkzeug")]),
    (r"^miniupnpd", [("miniupnp_project", "miniupnpd")]),
    (r"^cups", [("apple", "cups"), ("openprinting", "cups")]),
    (r"^redis", [("redis", "redis")]),
    (r"^mongodb", [("mongodb", "mongodb")]),
    (r"^elasticsearch", [("elastic", "elasticsearch")]),
    (r"^memcached", [("memcached", "memcached")]),
    (r"^openssl", [("openssl", "openssl")]),
    (r"^webmin|^miniserv", [("webmin", "webmin")]),
    (r"^php", [("php", "php")]),
    (r"^wing ftp", [("wftpserver", "wing_ftp_server")]),
    (r"^filezilla ftpd", [("filezilla-project", "filezilla_server")]),
    (r"^microsoft sql server", []),
]]

# Windows itself (not a service on a port): nmap's OS guess and the version Windows announces over SMB/RPC.
# NVD files older CVEs under some legacy product names, so a few versions have two.
WINDOWS = [   # (pattern, label, NVD products) - most specific first
    (r"server[ _]2008[ _]?r2|windows_server_2008:r2", "Windows Server 2008 R2", ["windows_server_2008"]),
    (r"server[ _]2008|windows_server_2008", "Windows Server 2008", ["windows_server_2008"]),
    (r"server[ _]2003|windows[ _]2003|windows_2003_server", "Windows Server 2003", ["windows_server_2003", "windows_2003_server"]),
    (r"windows[ _]xp", "Windows XP", ["windows_xp"]),
    (r"windows[ _]2000", "Windows 2000", ["windows_2000"]),
    (r"windows[ _]nt|windows_nt", "Windows NT", ["windows_nt"]),
    (r"windows[ _]vista", "Windows Vista", ["windows_vista"]),
    (r"windows[ _]7\b", "Windows 7", ["windows_7"]),
]
WINDOWS = [(re.compile(rx, re.I), label, prods) for rx, label, prods in WINDOWS]
OS_PRODUCTS = {("microsoft", p) for _, _, prods in WINDOWS for p in prods}
# "Windows 2003 or 2008", "XP SP2 or Windows Server 2003": don't guess between versions ("SP1 or SP2" is fine)
AMBIGUOUS = re.compile(r"\bor\s+(?:microsoft\s+)?(?:windows\s+)?(?:server\s+)?(?:20\d\d|xp|vista|7|8|10|11|nt)\b"
                       r"|\d\s+-\s+\d", re.I)


def windows_version(d: dict):
    """(label, NVD products) for an old Windows the scan identified, or None. Newer Windows (8, 10, 11,
    Server 2012+) is left out: it gets monthly patches, and a scan can't tell which ones are installed."""
    sources = [" | ".join(d.get("os_cpe") or []), d.get("os", "") if (d.get("os_accuracy") or 0) >= 85 else "",
               d.get("os_hint", "")]
    for text in sources:
        if not text or "windows" not in text.lower():
            continue
        for part in text.split("|"):                       # one service or OS class at a time
            if AMBIGUOUS.search(part):
                continue
            found = [(label, prods) for rx, label, prods in WINDOWS if rx.search(part)]
            if len({f[0].replace(" R2", "") for f in found}) == 1:
                return found[0]
    return None


def rank_key(f: dict):
    """Worst first: confirmed by an active check, then actively exploited, then a Metasploit module exists (exact
    version before unknown), then a public exploit, then severity."""
    return (f.get("confidence") != "confirmed", not f["kev"], not f.get("msf"),
            bool(f.get("unverified")), not f.get("edb"), -(f["score"] or 0))
DISTRO = re.compile(r"(ubuntu|debian|deb\d|\+deb|el\d|\.el|rhel|centos|fedora|suse|raspbian|alpine)", re.I)
PRE = {"alpha": -4, "a": -4, "beta": -3, "b": -3, "pre": -2, "rc": -2, "dev": -5}


# --------------------------------------------------------------------------- versions
@functools.lru_cache(maxsize=20000)
def vparts(v: str) -> tuple:
    """'7.9p1' -> [7, 9, 'p', 1]; pre-release words sort before the release ('1.0rc1' < '1.0')."""
    out = []
    for tok in re.findall(r"\d+|[a-z]+", (v or "").lower()):
        if tok.isdigit():
            out.append(int(tok))
        elif tok in PRE:
            out.append(PRE[tok])
        else:
            out.append(tok)
    return tuple(out)


def vcmp(a: str, b: str) -> int:
    x, y = vparts(a), vparts(b)
    for i in range(max(len(x), len(y))):
        p = x[i] if i < len(x) else None
        q = y[i] if i < len(y) else None
        if p == q:
            continue
        if p is None:                       # '7.9' vs '7.9p1': shorter is older, unless the rest is a pre-release
            return 1 if isinstance(q, int) and q < 0 else -1
        if q is None:
            return -1 if isinstance(p, int) and p < 0 else 1
        if isinstance(p, int) and isinstance(q, int):
            return 1 if p > q else -1
        if isinstance(p, str) and isinstance(q, str):
            return 1 if p > q else -1
        return 1 if isinstance(p, int) else -1     # a number beats letters ('1.0.1' > '1.0.a')
    return 0


def clean_version(v: str) -> str:
    """'7.9p1 Debian 10+deb10u2' -> '7.9p1'; '3.0.20-Debian' -> '3.0.20'; keeps '1.0-rc1'."""
    m = re.match(r"\s*v?(\d[\w.\-+~]*)", v or "")
    if not m:
        return ""
    out = m.group(1).split("+")[0].split("~")[0]
    out = re.sub(r"[-_](?!(?:rc|beta|alpha|pre|p)\d*\b)[a-z][\w.-]*$", "", out, flags=re.I)
    out = re.sub(r"-\d+(?:ubuntu|debian|deb|build|el|fc|bpo)[\w.~+-]*$", "", out, flags=re.I)   # distro package revision
    return out.rstrip(".-")


def parse_cpe22(cpe: str):
    """cpe:/a:openbsd:openssh:7.9p1 -> ('openbsd', 'openssh', '7.9p1')."""
    p = cpe.split(":")
    if len(p) < 4 or p[1] != "/a":
        return None
    return p[2].lower(), p[3].lower(), (p[4] if len(p) > 4 else "")


def version_matches(ver: str, m: dict) -> bool:
    """Does this exact version fall inside one NVD cpeMatch entry?"""
    crit = m["c"].split(":")
    cv = crit[5] if len(crit) > 5 else "*"
    cu = crit[6] if len(crit) > 6 else "*"
    if cv not in ("*", "-", ""):
        target = cv + (cu if cu not in ("*", "-", "") else "")
        return vcmp(ver, target) == 0 or (cu in ("*", "-", "") and vcmp(ver, cv) == 0)
    if not any(m.get(k) for k in ("si", "se", "ei", "ee")):
        return False                        # "all versions" entries are too vague to report
    if m.get("si") and vcmp(ver, m["si"]) < 0:
        return False
    if m.get("se") and vcmp(ver, m["se"]) <= 0:
        return False
    if m.get("ei") and vcmp(ver, m["ei"]) > 0:
        return False
    if m.get("ee") and vcmp(ver, m["ee"]) >= 0:
        return False
    return True


def score_of(metrics: dict) -> tuple[float | None, str]:
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for m in metrics.get(k) or []:
            d = m.get("cvssData") or {}
            s = d.get("baseScore")
            if s is not None:
                return float(s), (d.get("baseSeverity") or m.get("baseSeverity") or "").upper()
    return None, ""


def severity(score) -> str:
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def compact_nvd(vendor: str, product: str, items: list, part: str = "a") -> list:
    """Keep only what's needed from NVD's (large) CVE records."""
    out = []
    want = f"cpe:2.3:{part}:{vendor}:{product}:"
    for it in items:
        c = it.get("cve") or {}
        if c.get("vulnStatus") in ("Rejected",):
            continue
        matches = []
        for conf in c.get("configurations") or []:
            for node in conf.get("nodes") or []:
                if node.get("negate"):
                    continue
                for cm in node.get("cpeMatch") or []:
                    if cm.get("vulnerable") and str(cm.get("criteria", "")).lower().startswith(want):
                        matches.append({k2: cm.get(k1) for k1, k2 in (
                            ("criteria", "c"), ("versionStartIncluding", "si"), ("versionStartExcluding", "se"),
                            ("versionEndIncluding", "ei"), ("versionEndExcluding", "ee")) if cm.get(k1)})
        if not matches:
            continue
        score, sev = score_of(c.get("metrics") or {})
        desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
        out.append({"id": c.get("id"), "score": score, "desc": " ".join(desc.split())[:400],
                    "pub": (c.get("published") or "")[:10], "m": matches})
    return out


# --------------------------------------------------------------------------- scanner

def _msf_pairs(sig: dict) -> list:
    """A signature's Metasploit module in the same [module, title, rank] shape the exploit index uses."""
    return [[m, sig.get("title", "")[:160], 0] for m in (sig.get("msf") or []) if isinstance(m, str)]

class VulnScanner:
    def __init__(self, nm):
        self.nm = nm
        self.data_dir = Path(nm.data_dir)
        self.db = sqlite3.connect(str(self.data_dir / ("demo-vulns.db" if nm.args.demo else "vulns.db")),
                                  check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS cache (product TEXT PRIMARY KEY, fetched REAL, data TEXT)")
        self.db.commit()
        self.lock = threading.Lock()
        self.kev: dict[str, dict] = {}
        self.kev_loaded = 0.0
        self.parsed: dict[str, tuple] = {}          # product -> (fetched, parsed CVE list)
        self.match_memo: dict[tuple, set] = {}      # (vendor, product, version, fetched) -> matching CVE ids
        self.exploits: dict[str, dict] = {}         # CVE -> {"m": Metasploit modules, "e": Exploit-DB entries}
        self.exploits_loaded = 0.0
        self.exploit_error = ""
        self.results: dict[str, list] = {}          # device id -> findings
        self.status = {"state": "idle", "error": "", "last_run": 0, "pending": 0, "products": 0, "no_cpe": 0}
        self.alerted: set[str] = set()
        self.wake = asyncio.Event()
        self.last_nvd = 0.0

    @property
    def cfg(self) -> dict:
        return self.nm.settings.get("vulns", {})

    # ---- data sources
    def refresh_kev(self, force: bool = False):
        p = self.data_dir / "kev.json"
        try:
            if force or not p.exists() or time.time() - p.stat().st_mtime > 86400:
                req = urllib.request.Request(KEV, headers={"User-Agent": "LanPulse"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = r.read(20_000_000)
                json.loads(data)
                tmp = p.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(p)
        except (OSError, ValueError, urllib.error.URLError) as e:
            log.info("Couldn't refresh the CISA KEV list: %s", e)
        try:
            if p.exists() and p.stat().st_mtime != self.kev_loaded:
                raw = json.loads(p.read_text())
                self.kev = {v["cveID"]: {"name": v.get("vulnerabilityName", ""), "added": v.get("dateAdded", ""),
                                         "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                                         "action": v.get("requiredAction", "")}
                            for v in raw.get("vulnerabilities", []) if v.get("cveID")}
                self.kev_loaded = p.stat().st_mtime
        except (OSError, ValueError):
            pass

    def refresh_exploits(self, force: bool = False):
        """Which CVEs have a public exploit: Metasploit modules (rapid7/metasploit-framework module metadata, BSD-3)
        and Exploit-DB entries (files_exploits.csv). Downloaded weekly and boiled down to a small CVE index."""
        p = self.data_dir / "exploits.json"
        try:
            if force or not p.exists() or time.time() - p.stat().st_mtime > 7 * 86400:
                index: dict[str, dict] = {}
                errors = []
                try:
                    with urllib.request.urlopen(urllib.request.Request(MSF_META, headers={"User-Agent": "LanPulse"}), timeout=120) as r:
                        meta = json.loads(r.read(80_000_000))
                    for mod in meta.values():
                        if mod.get("type") != "exploit":
                            continue
                        refs = [x for x in mod.get("references") or [] if isinstance(x, str) and x.startswith("CVE-")]
                        for ref in refs:
                            index.setdefault(ref, {}).setdefault("m", []).append(
                                [str(mod.get("fullname", ""))[:120], str(mod.get("name", ""))[:160], int(mod.get("rank") or 0)])
                    del meta
                except (OSError, ValueError, MemoryError, urllib.error.URLError) as e:
                    errors.append(f"Metasploit list: {getattr(e, 'reason', e)}")
                try:
                    import csv
                    import io
                    with urllib.request.urlopen(urllib.request.Request(EDB_CSV, headers={"User-Agent": "LanPulse"}), timeout=120) as r:
                        text = r.read(60_000_000).decode("utf-8", "replace")
                    for row in csv.DictReader(io.StringIO(text)):
                        for code in (row.get("codes") or "").split(";"):
                            code = code.strip()
                            if code.startswith("CVE-"):
                                index.setdefault(code, {}).setdefault("e", []).append(
                                    [str(row.get("id", "")), (row.get("description") or "")[:160], row.get("verified") == "1"])
                except (OSError, ValueError, urllib.error.URLError) as e:
                    errors.append(f"Exploit-DB list: {getattr(e, 'reason', e)}")
                if len(index) > 1000:
                    for v in index.values():
                        if "m" in v:
                            v["m"].sort(key=lambda m: -m[2])
                    tmp = p.with_suffix(".tmp")
                    tmp.write_text(json.dumps(index, separators=(",", ":")))
                    tmp.replace(p)
                self.exploit_error = "; ".join(errors)[:300]
        except OSError as e:
            self.exploit_error = str(e)[:200]
        try:
            if p.exists() and p.stat().st_mtime != self.exploits_loaded:
                self.exploits = json.loads(p.read_text())
                self.exploits_loaded = p.stat().st_mtime
        except (OSError, ValueError):
            pass

    def cached(self, key: str):
        """(fetched time, CVE list) for one product. Parsed lists are kept in memory; the database is only
        read again when NVD data for that product was refreshed."""
        hit = self.parsed.get(key)
        with self.lock:
            row = self.db.execute("SELECT fetched FROM cache WHERE product = ?", (key,)).fetchone()
            if not row:
                return 0, None
            if hit and hit[0] == row[0]:
                return hit
            data = self.db.execute("SELECT data FROM cache WHERE product = ?", (key,)).fetchone()[0]
        val = (row[0], json.loads(data))
        self.parsed[key] = val
        return val

    def fetch_nvd(self, vendor: str, product: str) -> list:
        """Every CVE NVD lists for vendor:product (paged). Respects NVD's rate limit."""
        key = self.cfg.get("nvd_key", "")
        part = "o" if (vendor, product) in OS_PRODUCTS else "a"      # operating system or application
        gap = 0.8 if key else 6.5
        items, start = [], 0
        while True:
            wait = self.last_nvd + gap - time.time()
            if wait > 0:
                time.sleep(wait)
            q = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:{part}:{vendor}:{product}",
                                        "resultsPerPage": 2000, "startIndex": start})
            headers = {"User-Agent": "LanPulse", "Accept": "application/json"}
            if key:
                headers["apiKey"] = key
            self.last_nvd = time.time()
            with urllib.request.urlopen(urllib.request.Request(f"{NVD}?{q}", headers=headers), timeout=60) as r:
                data = json.loads(r.read(120_000_000))
            items += data.get("vulnerabilities") or []
            start += data.get("resultsPerPage") or 0
            if start >= (data.get("totalResults") or 0) or not data.get("resultsPerPage"):
                break
        return compact_nvd(vendor, product, items, part)

    # ---- inventory
    def inventory(self) -> list[dict]:
        """Every scanned service whose software and version LanPulse can name, with the NVD product names to check.
        Uses nmap's product ID (CPE) when there is one, translated to NVD's vendor names, and otherwise recognises
        common server software by the name nmap reports."""
        out, no_cpe = [], 0
        for d in list(self.nm.devices.values()):          # a copy: this runs in a worker thread
            for p in list(d.get("ports", [])):
                sw, raw_ver = p.get("sw") or "", p.get("ver") or ""
                if not sw and p.get("product"):            # scans from older versions only kept "Name 1.2.3"
                    m = re.match(r"^(.*?)\s+v?(\d[\w.\-+~]*.*)$", p["product"])
                    sw, raw_ver = (m.group(1), m.group(2)) if m else (p["product"], "")
                products, cver = [], ""
                for c in p.get("cpe") or []:
                    parsed = parse_cpe22(c)
                    if parsed:
                        vendor, product, cver = parsed
                        products += CPE_ALIASES.get((vendor, product), [(vendor, product)])
                        break
                for rx, prods in NAME_MAP:
                    if rx.search(sw):
                        products += [x for x in prods if x not in products]
                        break
                exact = not WILDCARD_VER.search(raw_ver) and not UNRELIABLE_VERSION.search(sw)
                ver = (clean_version(raw_ver) or clean_version(cver)) if exact else ""
                if not products:
                    if p.get("product"):
                        no_cpe += 1
                    continue
                # Software recognised but no exact version: only exploit-backed flaws are listed, marked "version unknown"
                out.append({"dev": d["id"], "port": p["port"], "products": products, "ver": ver, "unknown": not ver,
                            "label": p.get("product") or sw,
                            "distro": bool(DISTRO.search(f"{raw_ver} {p.get('product', '')}"))})
            win = windows_version(d)
            if win:
                # Shown against the port Windows exposes these flaws through (file sharing first)
                open_ports = [p["port"] for p in d.get("ports", [])]
                port = next((x for x in (445, 139, 135, 3389) if x in open_ports), open_ports[0] if open_ports else 0)
                out.append({"dev": d["id"], "port": port, "products": [("microsoft", x) for x in win[1]], "ver": "",
                            "unknown": True, "os": True, "label": f"{win[0]} (operating system)", "distro": False})
        self.status["no_cpe"] = no_cpe
        return out

    # ---- matching
    def evaluate(self, alert: bool = True):
        inv = self.inventory()
        results: dict[str, list] = {}
        exact_products = {(it["dev"], vp) for it in inv if not it["unknown"] for vp in it["products"]}
        for it in inv:
            seen_cve = set()
            for vendor, product in it["products"]:
                if it["unknown"] and (it["dev"], (vendor, product)) in exact_products:
                    continue                # another port on this device already gave the exact version
                fetched, cves = self.cached(f"{vendor}:{product}")
                # many devices run the same software version: match each (product, version) once
                mkey = (vendor, product, it["ver"], fetched)
                hits = self.match_memo.get(mkey)
                if hits is None:
                    hits = {c["id"] for c in cves or [] if it["unknown"] or any(version_matches(it["ver"], m) for m in c["m"])}
                    self.match_memo[mkey] = hits
                for cve in cves or []:
                    if cve["id"] in seen_cve or cve["id"] not in hits:
                        continue
                    if it["unknown"] and not ((self.exploits.get(cve["id"]) or {}).get("m") or cve["id"] in self.kev):
                        continue
                    seen_cve.add(cve["id"])
                    k = self.kev.get(cve["id"])
                    x = self.exploits.get(cve["id"]) or {}
                    results.setdefault(it["dev"], []).append({
                        "cve": cve["id"], "score": cve["score"], "sev": severity(cve["score"]), "desc": cve["desc"],
                        "pub": cve["pub"], "port": it["port"], "software": it["label"], "product": product,
                        "ver": it["ver"], "kev": bool(k), "kev_name": (k or {}).get("name", ""),
                        "ransomware": bool(k and k["ransomware"]), "distro": it["distro"],
                        "msf": x.get("m", [])[:5], "edb": x.get("e", [])[:5], "unverified": it["unknown"],
                        "os": it.get("os", False),
                        "confidence": "os-guess" if it.get("os") else "version"})
        # vulners.com lookups (thorough scans): CVEs for the detected service version. Version-based, so they rank
        # as "version" findings; only added when the NVD match above did not already list the CVE on that device.
        for d in list(self.nm.devices.values()):
            have = {f["cve"] for f in results.get(d["id"], [])}
            ports = {p["port"]: p for p in d.get("ports", [])}
            for vf in d.get("vulners", []):
                cve = vf.get("cve", "")
                if not cve or cve in have:
                    continue
                have.add(cve)
                k = self.kev.get(cve)
                x = self.exploits.get(cve) or {}
                p = ports.get(vf.get("port"), {})
                results.setdefault(d["id"], []).append({
                    "cve": cve, "score": vf.get("cvss") or None, "sev": severity(vf.get("cvss") or None),
                    "desc": "Listed by vulners.com for this service's detected version (not independently verified).",
                    "pub": "", "port": vf.get("port") or 0, "software": (p.get("product") or p.get("service") or "service"),
                    "product": "vulners", "ver": "", "kev": bool(k), "kev_name": (k or {}).get("name", ""),
                    "ransomware": bool(k and k.get("ransomware")), "distro": False,
                    "msf": x.get("m", [])[:5], "edb": x.get("e", [])[:5], "unverified": False,
                    "os": False, "confidence": "version"})
        # OpenVAS results: real vulnerability tests. QoD >= 80 means the test exercised the flaw or fingerprinted the
        # exact version, so those rank as Confirmed; weaker detections stay "version".
        for d in list(self.nm.devices.values()):
            for ov in d.get("openvas", []):
                conf = "confirmed" if ov.get("qod", 0) >= 80 else "version"
                for cve in [str(c).strip().upper() for c in (ov.get("cve") or [])] or [""]:
                    cid = cve or ("OPENVAS-" + (ov.get("oid", "").split(".")[-1] or "result"))
                    k = self.kev.get(cve) if cve else None
                    x = (self.exploits.get(cve) or {}) if cve else {}
                    results.setdefault(d["id"], []).append({
                        "cve": cid, "score": ov.get("severity"), "sev": severity(ov.get("severity")),
                        "desc": ov.get("desc") or ov.get("name", ""), "pub": "", "port": ov.get("port") or 0,
                        "software": ov.get("name", "")[:80], "product": "openvas", "ver": "", "kev": bool(k),
                        "kev_name": (k or {}).get("name", ""), "ransomware": bool(k and k.get("ransomware")),
                        "distro": False, "msf": x.get("m", [])[:5], "edb": x.get("e", [])[:5], "unverified": False,
                        "os": False, "confidence": conf, "probe": "openvas"})
        # Curated signatures for classic exploitable services nmap can't give a product ID for (see signatures.py)
        for d in list(self.nm.devices.values()):
            have = {(f["cve"], f["port"]) for f in results.get(d["id"], [])}
            for port, sig in signatures.match_device(d):
                if (sig["cve"], port) in have:
                    # Another source (OpenVAS, vulners) already reported it: keep that entry but borrow the
                    # signature's Metasploit module if the exploit index had none for this CVE.
                    for f in results.get(d["id"], []):
                        if f["cve"] == sig["cve"] and f["port"] == port and not f.get("msf") and sig["msf"]:
                            f["msf"] = _msf_pairs(sig)
                    continue
                have.add((sig["cve"], port))
                real = sig["cve"] if sig["cve"].startswith("CVE-") else ""
                k = self.kev.get(real) if real else None
                x = (self.exploits.get(real) or {}) if real else {}
                results.setdefault(d["id"], []).append({
                    "cve": sig["cve"], "score": sig["score"], "sev": severity(sig["score"]), "desc": sig["desc"],
                    "pub": "", "port": port, "software": sig["title"], "product": "signature", "ver": "",
                    "kev": bool(k), "kev_name": (k or {}).get("name", ""), "ransomware": bool(k and k.get("ransomware")),
                    "distro": False, "msf": (x.get("m") or _msf_pairs(sig))[:5], "edb": x.get("e", [])[:5],
                    "unverified": False, "os": False, "confidence": "version"})
        # Confirmed findings: NSE checks that actively TESTED a flaw and reported VULNERABLE (thorough scans).
        # These don't depend on a version string, so they catch patch-level holes banner-matching misses.
        for d in list(self.nm.devices.values()):
            open_ports = [p["port"] for p in d.get("ports", [])]
            # host-level scripts carry no port: show them against the port Windows exposes them through
            host_port = next((x for x in (445, 139, 135, 3389) if x in open_ports), open_ports[0] if open_ports else 0)
            for pr in d.get("probes", []):
                cve = (pr.get("cve") or "").upper()
                k = self.kev.get(cve) if cve else None
                x = (self.exploits.get(cve) or {}) if cve else {}
                results.setdefault(d["id"], []).append({
                    "cve": cve or pr.get("id", "probe").upper(), "score": None, "sev": "unknown",
                    "desc": pr.get("title") or f"Confirmed vulnerable by {pr.get('id', 'an active check')}", "pub": "",
                    "port": pr.get("port") or host_port, "software": pr.get("title") or pr.get("id", ""),
                    "product": pr.get("id", ""), "ver": "", "kev": bool(k), "kev_name": (k or {}).get("name", ""),
                    "ransomware": bool(k and k.get("ransomware")), "distro": False,
                    "msf": x.get("m", [])[:5], "edb": x.get("e", [])[:5], "unverified": False,
                    "os": False, "confidence": "confirmed", "probe": pr.get("id", "")})
        for dev_id, items in results.items():
            seen, uniq = set(), []
            for f in sorted(items, key=rank_key):
                if (f["cve"], f["port"]) not in seen:
                    seen.add((f["cve"], f["port"]))
                    uniq.append(f)
            results[dev_id] = uniq[:300]
        self.results = results
        if alert:
            self._alert_new_kev()

    def _alert_new_kev(self):
        for dev_id, items in self.results.items():
            d = self.nm.devices.get(dev_id)
            if not d:
                continue
            new = [f for f in items if f["kev"] and f"{dev_id}|{f['cve']}" not in self.alerted]
            for f in new:
                self.alerted.add(f"{dev_id}|{f['cve']}")
            if new and self.status["last_run"]:          # stay quiet on the very first run after starting
                top = new[0]
                try:
                    self.nm.notify("vulns", d, f"Actively exploited flaw on {self.nm.label(d)}",
                                   f"{top['software']} on port {top['port']} has {top['cve']} ({top['kev_name'] or 'known exploited'})"
                                   + (f" and {len(new) - 1} more" if len(new) > 1 else "") + ". Attackers are using it now.", 4)
                except RuntimeError:
                    pass

    # ---- loop
    async def run(self):
        await asyncio.sleep(20)
        while True:
            try:
                if self.cfg.get("enabled", True):
                    await self.run_once()
            except Exception as e:
                log.exception("Vulnerability check failed")
                self.status.update(state="error", error=str(e)[:200])
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=1800)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()

    async def run_once(self):
        if self.nm.args.demo:
            self._demo()
            return
        await asyncio.to_thread(self.refresh_kev)
        inv = self.inventory()
        await asyncio.to_thread(self.refresh_exploits)
        products = sorted({vp for i in inv for vp in i["products"]})
        stale = [p for p in products if time.time() - self.cached(f"{p[0]}:{p[1]}")[0] > CACHE_DAYS * 86400]
        self.status.update(products=len(products), pending=len(stale), state="checking" if stale else "idle", error="")
        for vendor, product in stale:
            try:
                cves = await asyncio.to_thread(self.fetch_nvd, vendor, product)
                with self.lock:
                    self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?)",
                                    (f"{vendor}:{product}", time.time(), json.dumps(cves, separators=(",", ":"))))
                    self.db.commit()
            except urllib.error.HTTPError as e:
                self.status["error"] = ("NVD is rate-limiting LanPulse. It will keep trying; a free NVD API key "
                                        "(Settings > Vulnerabilities) makes checks faster.") if e.code in (403, 429) \
                    else f"NVD returned HTTP {e.code} for {product}."
                await asyncio.sleep(30)
            except (OSError, ValueError) as e:
                self.status["error"] = f"Couldn't reach NVD: {e}"[:200]
                break
            self.status["pending"] -= 1
            await self.evaluate_async()
        await self.evaluate_async()
        self.status.update(state="idle", last_run=time.time())
        # Timeline: only compare after a complete check (every product's NVD list cached, exploit lists loaded),
        # so a failed download never looks like "vulnerabilities fixed".
        complete = all(time.time() - self.cached(f"{p[0]}:{p[1]}")[0] <= CACHE_DAYS * 86400 for p in products)
        if complete and not self.status.get("error") and self.exploits:
            try:
                await asyncio.to_thread(self.record_changes)
            except Exception:
                log.exception("Couldn't record vulnerability changes")

    def record_changes(self):
        current = {dev: {f["cve"]: f for f in items} for dev, items in self.results.items()}
        changes = self.nm.timeline.vuln_changes(current, set(self.nm.devices))
        for dev_id, (new, gone) in changes.items():
            d = self.nm.devices.get(dev_id)
            if not d:
                continue
            if new:
                new.sort(key=rank_key)
                sw = sorted({f["software"] for f in new})
                kev = sum(f["kev"] for f in new)
                msf = sum(1 for f in new if f.get("msf"))
                ids = ", ".join(f["cve"] for f in new[:5]) + (f" and {len(new) - 5} more" if len(new) > 5 else "")
                notes = [x for x in (f"{kev} actively exploited" if kev else "",
                                     f"{msf} with a Metasploit module" if msf else "") if x]
                self.nm.event("vuln", d, f"{len(new)} vulnerabilit{'y' if len(new) == 1 else 'ies'} found in "
                              f"{', '.join(sw[:3])}: {ids}" + (f" ({', '.join(notes)})" if notes else ""),
                              "bad" if kev or msf else "warn", feed=False)
            if gone:
                ids = ", ".join(gone[:5]) + (f" and {len(gone) - 5} more" if len(gone) > 5 else "")
                self.nm.event("vuln_gone", d, f"{len(gone)} vulnerabilit{'y' if len(gone) == 1 else 'ies'} no longer "
                              f"found: {ids} (software updated or removed, or the port closed)", "good", feed=False)

    async def evaluate_async(self):
        await asyncio.to_thread(self.evaluate, False)       # heavy matching off the main loop
        self._alert_new_kev()

    # ---- views
    def summary(self) -> dict:
        devs = self.nm.devices
        rows = []
        for dev_id, items in self.results.items():
            d = devs.get(dev_id)
            if not d:
                continue
            rows.append({"id": dev_id, "ip": d["ip"], "name": self.nm.label(d), "type": d.get("type", "unknown"),
                         "count": len(items), "kev": sum(f["kev"] for f in items),
                         "exploits": sum(1 for f in items if f.get("msf") or f.get("edb")),
                         "confirmed": sum(1 for f in items if f.get("confidence") == "confirmed"),
                         "critical": sum(f["sev"] == "critical" for f in items),
                         "high": sum(f["sev"] == "high" for f in items),
                         "max": max((f["score"] or 0) for f in items) if items else 0,
                         "software": sorted({f["software"] for f in items})[:4]})
        rows.sort(key=lambda r: (-r["confirmed"], -r["kev"], -r["exploits"], -r["max"], -r["count"]))
        # "fix first": one line per device + software, worst first
        groups: dict[tuple, dict] = {}
        for dev_id, items in self.results.items():
            d = devs.get(dev_id)
            if not d:
                continue
            for f in items:
                g = groups.setdefault((dev_id, f["software"], f["port"]), {
                    "id": dev_id, "name": self.nm.label(d), "ip": d["ip"], "software": f["software"], "port": f["port"],
                    "count": 0, "kev": 0, "max": 0, "top": f, "distro": f["distro"], "unverified": f.get("unverified", False),
                    "os": f.get("os", False), "confirmed": 0, "confidence": f.get("confidence", "version")})
                g["count"] += 1
                g["cves"] = g.get("cves", 0) + bool(re.match(r"CVE-\d{4}-\d+$", f["cve"] or ""))   # others are scanner-test ids
                g["kev"] += f["kev"]
                g["confirmed"] += f.get("confidence") == "confirmed"
                g["msf"] = g.get("msf", 0) + bool(f.get("msf"))
                g["edb"] = g.get("edb", 0) + bool(f.get("edb") and not f.get("msf"))
                g["max"] = max(g["max"], f["score"] or 0)
                if f.get("confidence") == "confirmed":       # a confirmed hit heads the group
                    g["top"], g["confidence"] = f, "confirmed"
        fix = sorted(groups.values(), key=lambda g: (-g["confirmed"], -g["kev"], -g.get("msf", 0), g["unverified"], -g.get("edb", 0), -g["max"], -g["count"]))[:40]
        # LanPulse's own checks (risky services, end-of-life Windows) belong on this page too
        config = [{"id": d["id"], "name": self.nm.label(d), "ip": d["ip"], "level": f["level"], "text": f["text"],
                   "port": f.get("port")}
                  for d in devs.values() for f in d.get("findings", []) if f["level"] in ("high", "medium") and not f.get("dismissed")]
        all_f = [f for items in self.results.values() for f in items]
        return {"type": "vuln_summary", "status": self.status, "enabled": self.cfg.get("enabled", True),
                "devices": rows, "fix": fix, "config": config[:40],
                "totals": {"cves": len({f["cve"] for f in all_f}), "kev": len({f["cve"] for f in all_f if f["kev"]}),
                           "exploits": len({f["cve"] for f in all_f if f.get("msf") or f.get("edb")}),
                           "msf": len({f["cve"] for f in all_f if f.get("msf")}),
                           "confirmed": sum(1 for f in all_f if f.get("confidence") == "confirmed"),
                           "critical": len({f["cve"] for f in all_f if f["sev"] == "critical"}),
                           "devices": len(rows), "scanned": sum(1 for d in devs.values() if d.get("deep_scanned_at"))},
                "kev_list": len(self.kev), "has_key": bool(self.cfg.get("nvd_key")),
                "exploit_db": {"cves": len(self.exploits), "error": self.exploit_error}}

    def for_device(self, dev_id: str) -> list:
        return self.results.get(dev_id, [])

    # ---- demo
    def _demo(self):
        devs = list(self.nm.devices.values())
        demo = {"OpenSSH 7.9p1": [("CVE-2023-38408", 9.8, True, "PKCS#11 feature in ssh-agent allows remote code execution"),
                                  ("CVE-2021-41617", 7.0, False, "sshd privilege escalation with certain configurations")],
                "Hikvision RTSP": [("CVE-2021-36260", 9.8, True, "Command injection in the web server of some Hikvision products")],
                "nginx 1.24": [("CVE-2023-44487", 7.5, True, "HTTP/2 Rapid Reset denial of service")]}
        self.results = {}
        for d in devs:
            for p in d.get("ports", []):
                for sw, cves in demo.items():
                    if sw.lower().split()[0] in (p.get("product") or "").lower():
                        for cid, score, kev, desc in cves:
                            self.results.setdefault(d["id"], []).append({
                                "cve": cid, "score": score, "sev": severity(score), "desc": desc, "pub": "2023-07-20",
                                "port": p["port"], "software": p.get("product") or sw, "product": sw.split()[0].lower(),
                                "ver": "", "kev": kev, "kev_name": desc if kev else "", "ransomware": False, "distro": False})
        self.kev = self.kev or {"x": {}}
        self.status.update(state="idle", last_run=time.time(), products=len(demo), pending=0)
