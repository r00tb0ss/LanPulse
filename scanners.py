# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Recognise well-known internet research scanners (Shodan, Censys, Shadowserver, ...).

They scan the whole internet constantly and are usually harmless, so LanPulse shows them in grey.
Identification uses forward-confirmed reverse DNS: the IP's hostname must end in a known scanner domain
AND that hostname must resolve back to the same IP, so an attacker can't fake it with a PTR record.
"""
from __future__ import annotations

import logging
import queue
import socket
import sqlite3
import threading
import time

log = logging.getLogger("lanpulse.scanners")

SCANNER_DOMAINS = {
    "shodan.io": "Shodan", "censys-scanner.com": "Censys", "censys.io": "Censys",
    "shadowserver.org": "Shadowserver", "binaryedge.ninja": "BinaryEdge", "binaryedge.io": "BinaryEdge",
    "sonar.labs.rapid7.com": "Rapid7 Project Sonar", "rapid7.com": "Rapid7", "stretchoid.com": "Stretchoid",
    "internet-measurement.com": "Internet Measurement", "onyphe.net": "ONYPHE", "leakix.net": "LeakIX",
    "internet-census.org": "Internet Census", "alphastrike.io": "Alpha Strike Labs", "recyber.net": "ReCyber",
    "netsystemsresearch.com": "Net Systems Research", "ipip.net": "IPIP.net", "criminalip.com": "Criminal IP",
    "expanseinc.com": "Palo Alto Xpanse", "paloaltonetworks.com": "Palo Alto Xpanse", "modat.io": "Modat",
    "hadrian.io": "Hadrian", "bitsight.com": "BitSight", "cyberresilience.io": "CyberResilience",
    "academyforinternetresearch.org": "Academy for Internet Research", "openportstats.com": "OpenPortStats",
    "scanner.ipinfo.io": "IPinfo", "probe.driftnet.io": "Driftnet", "driftnet.io": "Driftnet",
    "security.ipip.net": "IPIP.net", "netscout.com": "NETSCOUT", "projectdiscovery.io": "ProjectDiscovery",
    "internettl.org": "InternetTL", "scan.cypex.ai": "Cypex", "censys.com": "Censys",
}


def match_domain(host: str) -> str | None:
    host = (host or "").lower().rstrip(".")
    for dom, name in SCANNER_DOMAINS.items():
        if host == dom or host.endswith("." + dom):
            return name
    return None


def classify(ip: str) -> dict | None:
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    name = match_domain(host)
    if not name:
        return None
    try:
        confirmed = ip in socket.gethostbyname_ex(host)[2]
    except Exception:
        confirmed = False
    return {"tag": "scanner", "label": name, "host": host} if confirmed else None


class ScannerTagger:
    """Looks up each new attacker once, in the background, and remembers the answer."""

    def __init__(self, db: sqlite3.Connection, lock: threading.Lock, demo: bool = False):
        self.db, self.lock, self.demo = db, lock, demo
        with lock:
            db.execute("CREATE TABLE IF NOT EXISTS ip_tags (ip TEXT PRIMARY KEY, tag TEXT, label TEXT, host TEXT, t REAL)")
            db.commit()
            rows = db.execute("SELECT ip, tag, label, host FROM ip_tags").fetchall()
        self.cache: dict[str, dict | None] = {ip: ({"tag": t, "label": l, "host": h} if t else None) for ip, t, l, h in rows}
        self.q: queue.Queue[str] = queue.Queue(maxsize=5000)
        self.pending: set[str] = set()
        self.on_tag = None
        threading.Thread(target=self.worker, daemon=True, name="scanner-tagger").start()

    def get(self, ip: str) -> dict | None:
        if ip in self.cache:
            return self.cache[ip]
        if ip not in self.pending:
            self.pending.add(ip)
            try:
                self.q.put_nowait(ip)
            except queue.Full:
                self.pending.discard(ip)
        return None

    def set(self, ip: str, info: dict | None):
        self.cache[ip] = info
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO ip_tags VALUES (?,?,?,?,?)",
                            (ip, (info or {}).get("tag", ""), (info or {}).get("label", ""), (info or {}).get("host", ""),
                             time.time()))
            self.db.commit()

    def worker(self):
        while True:
            ip = self.q.get()
            info = None if self.demo else classify(ip)
            self.set(ip, info)
            self.pending.discard(ip)
            if info and self.on_tag:
                try:
                    self.on_tag(ip, info)
                except Exception:
                    pass
