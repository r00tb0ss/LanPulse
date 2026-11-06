# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Outbound traffic: where your devices connect to on the internet.

Source: your router's firewall log for outbound connections (for a UDM, an Internal -> External
"Allow" policy with Syslog Logging on). Each line is aggregated per minute by
(device, destination, port) in SQLite and kept 7 days. Destinations are enriched offline with
location (DB-IP City Lite) and owner (DB-IP ASN Lite), and flagged when they have attacked you.
"""
from __future__ import annotations

import asyncio
import collections
import random
import sqlite3
import threading
import time

KEEP_DAYS = 7


class FlowStore:
    def __init__(self, nm):
        self.nm = nm
        self.db: sqlite3.Connection = nm.threats.db
        self.lock: threading.Lock = nm.threats.lock
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS flows (m INTEGER, src TEXT, dst TEXT, dport INT, proto TEXT,"
                            " n INT, nb INT, PRIMARY KEY (m, src, dst, dport, proto)) WITHOUT ROWID")
            self.db.execute("CREATE INDEX IF NOT EXISTS flows_src ON flows (src, m)")
            # per-device baseline: which countries each device normally talks to, and since when (for anomaly alerts)
            self.db.execute("CREATE TABLE IF NOT EXISTS dev_geo (src TEXT, iso TEXT, first REAL, PRIMARY KEY (src, iso)) WITHOUT ROWID")
            self.db.commit()
        self.geo_seen: dict[str, set] = {}       # src -> set of ISO country codes seen (in memory)
        self.geo_since: dict[str, float] = {}     # src -> when we first saw this device do any outbound
        with self.lock:
            for src, iso, first in self.db.execute("SELECT src, iso, first FROM dev_geo"):
                self.geo_seen.setdefault(src, set()).add(iso)
                self.geo_since[src] = min(self.geo_since.get(src, first), first)
        self.acc: dict[tuple, list[int]] = {}
        self.live: list[dict] = []
        self.recent: collections.deque = collections.deque(maxlen=80)
        self.bad_ips: set[str] = set()
        self.bad_loaded = 0.0
        self.alerted: dict[str, float] = {}
        self.last_flow = 0.0
        with self.lock:
            row = self.db.execute("SELECT MAX(m) FROM flows").fetchone()
        self.last_flow = (row[0] or 0) * 60.0

    # ---- intake (event loop thread)
    def add(self, src: str, dst: str, dport, proto: str, blocked: bool, t: float | None = None):
        t = t or time.time()
        key = (int(t // 60), src, dst, int(dport or 0), (proto or "tcp").lower())
        a = self.acc.setdefault(key, [0, 0])
        a[0] += 1
        a[1] += 1 if blocked else 0
        self.last_flow = t
        c2 = not blocked and self.nm.threats.known_c2(dst)      # our device reaching a known botnet C2 = likely infected
        bad = c2 or self.is_bad(dst)
        ev = self.decorate({"t": t, "src": src, "dst": dst, "dport": key[3], "proto": key[4], "blocked": blocked,
                            "bad": bad, "c2": c2})
        self.recent.appendleft(ev)
        self.live.append(ev)
        if c2:
            self.alert_c2(ev)
        elif bad:
            self.alert_bad(ev)
        if not blocked and ev.get("iso"):
            self.check_new_region(ev)

    def decorate(self, e: dict) -> dict:
        g = self.nm.threats.geo.lookup(e["dst"])
        a = self.nm.threats.geo.asn(e["dst"])
        d = next((x for x in self.nm.devices.values() if x["ip"] == e["src"]), None)
        e.update({"iso": g["iso"], "country": g["country"], "city": g["city"], "lat": g["lat"], "lon": g["lon"],
                  "org": a.get("org", ""), "asn": a.get("asn"),
                  "src_id": d["id"] if d else "", "src_name": self.nm.label(d) if d else e["src"]})
        return e

    def is_bad(self, ip: str) -> bool:
        if time.time() - self.bad_loaded > 300:
            with self.lock:
                rows = self.db.execute("SELECT DISTINCT src FROM attacks WHERE t > ?", (time.time() - 30 * 86400,)).fetchall()
            tags = self.nm.threats.tags.cache
            self.bad_ips = {r[0] for r in rows if not tags.get(r[0])}       # research scanners aren't "bad"
            self.bad_loaded = time.time()
        return ip in self.bad_ips

    def alert_bad(self, e: dict):
        key = f"{e['src']}>{e['dst']}"
        if time.time() - self.alerted.get(key, 0) < 3600:
            return
        self.alerted[key] = time.time()
        d = next((x for x in self.nm.devices.values() if x["ip"] == e["src"]), None)
        subject = d or {"id": f"flow:{e['src']}", "ip": e["src"], "mac": "", "vendor": "", "type": "unknown"}
        self.nm.event("traffic", subject, f"{e['src_name']} connected to {e['dst']}, an IP that attacked you")
        self.nm.notify("local_threats", subject, f"{e['src_name']} is talking to an attacker",
                       f"Outbound connection to {e['dst']} port {e['dport']} ({e['org'] or 'unknown network'}, "
                       f"{e['country'] or 'unknown country'}). That IP attacked your network recently.", 5)

    def check_new_region(self, e: dict):
        """Behavior baseline: alert the first time a device connects to a country it has never talked to — but only
        after a 24h learning window and once the device has an established pattern, so it isn't noisy."""
        src, iso = e["src"], e["iso"]
        seen = self.geo_seen.setdefault(src, set())
        if iso in seen:
            return
        now = time.time()
        first = self.geo_since.get(src)
        if first is None:
            self.geo_since[src] = now
            first = now
        is_new_region = iso not in seen
        seen.add(iso)
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO dev_geo VALUES (?,?,?)", (src, iso, now))
            self.db.commit()
        # learn silently for the first 24h and until the device has a few known regions
        established = (now - first > 86400) and len(seen) > 2
        if not is_new_region or not established or e.get("c2") or e.get("bad"):
            return
        d = next((x for x in self.nm.devices.values() if x["ip"] == src), None)
        subject = d or {"id": f"flow:{src}", "ip": src, "mac": "", "vendor": "", "type": "unknown"}
        key = f"region:{src}:{iso}"
        if now - self.alerted.get(key, 0) < 86400:
            return
        self.alerted[key] = now
        where = e.get("country") or iso
        if d:
            self.nm.event("traffic", d, f"{e['src_name']} connected to a new country for it: {where} ({e.get('org') or e['dst']})", "warn")
        self.nm.notify("anomaly", subject, f"{e['src_name']}: new outbound region",
                       f"{e['src_name']} ({src}) connected to {where} for the first time ({e.get('org') or 'unknown network'}, "
                       f"{e['dst']}). It normally talks to {len(seen) - 1} other region(s). Unexpected for this device, "
                       f"this could be worth a look.", 3)

    def alert_c2(self, e: dict):
        """A LAN device connected OUT to a known botnet command-and-control server. This is the strongest sign in
        LanPulse that a device may be compromised."""
        key = f"c2:{e['src']}>{e['dst']}"
        if time.time() - self.alerted.get(key, 0) < 3600:
            return
        self.alerted[key] = time.time()
        d = next((x for x in self.nm.devices.values() if x["ip"] == e["src"]), None)
        subject = d or {"id": f"flow:{e['src']}", "ip": e["src"], "mac": "", "vendor": "", "type": "unknown"}
        self.nm.event("security", subject, f"{e['src_name']} connected to a known botnet C2 ({e['dst']}) — possible compromise", "bad")
        self.nm.notify("compromise", subject, f"⚠ {e['src_name']} may be compromised",
                       f"{e['src_name']} ({e['src']}) connected OUT to {e['dst']} port {e['dport']} "
                       f"({e['org'] or 'unknown network'}, {e['country'] or 'unknown country'}), a known malware "
                       f"command-and-control server (abuse.ch Feodo Tracker). This device may be infected — "
                       f"investigate it and consider taking it offline.", 5)

    async def pump(self):
        """Every 2 s: send new connections to browsers (sampled) and save finished minutes."""
        last_spike = 0.0
        while True:
            await asyncio.sleep(2)
            if self.live:
                batch, self.live = self.live, []
                bad = [e for e in batch if e["bad"]]
                rest = [e for e in batch if not e["bad"]]
                if len(rest) > 40:
                    rest = random.sample(rest, 40)
                await self.nm.broadcast({"type": "flows", "items": bad + rest, "total": len(batch)})
            self.flush()
            if not self.nm.args.demo and time.time() - last_spike > 600:
                last_spike = time.time()
                try:
                    await asyncio.to_thread(self.check_volume_spikes)
                except Exception:
                    pass

    def check_volume_spikes(self):
        """Behavior baseline: flag a device whose outbound connection volume in the last hour is far above its own
        7-day norm — a possible sign of exfiltration, a new heavy service or malware beaconing."""
        now = int(time.time() // 60)
        with self.lock:
            # last hour vs the prior 7 days, per device
            rows = self.db.execute(
                "SELECT src, SUM(CASE WHEN m > ? THEN n ELSE 0 END) recent, "
                "SUM(CASE WHEN m <= ? AND m > ? THEN n ELSE 0 END) base "
                "FROM flows WHERE m > ? GROUP BY src", (now - 60, now - 60, now - 7 * 1440, now - 7 * 1440)).fetchall()
        for src, recent, base in rows:
            if not recent or recent < 300:            # ignore quiet hours
                continue
            base = base or 0
            if base < 50:                             # not enough 7-day history to judge this device yet
                continue
            hourly_avg = base / (7 * 24)
            if recent < max(hourly_avg * 5, 300):
                continue
            d = next((x for x in self.nm.devices.values() if x["ip"] == src), None)
            subject = d or {"id": f"flow:{src}", "ip": src, "mac": "", "vendor": "", "type": "unknown"}
            name = self.nm.label(d) if d else src
            key = f"spike:{src}"
            if time.time() - self.alerted.get(key, 0) < 6 * 3600:
                continue
            self.alerted[key] = time.time()
            self.nm.notify("anomaly", subject, f"{name}: unusual traffic volume",
                           f"{name} ({src}) made {recent:,} outbound connections in the last hour — about "
                           f"{recent / max(1, hourly_avg):.0f}x its normal hourly rate. Could be a new service, a large "
                           f"transfer, or something worth checking.", 3)

    def flush(self, force: bool = False):
        cur = int(time.time() // 60)
        done = [k for k in self.acc if force or k[0] < cur]
        if not done:
            return
        rows = [(*k, *self.acc.pop(k)) for k in done]
        with self.lock:
            self.db.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?) ON CONFLICT(m, src, dst, dport, proto) "
                                "DO UPDATE SET n = n + excluded.n, nb = nb + excluded.nb", rows)
            self.db.execute("DELETE FROM flows WHERE m < ?", (cur - KEEP_DAYS * 1440,))
            self.db.commit()

    # ---- reporting
    def summary(self, hours: int = 24, device_ip: str = "", talkers: int = 12) -> dict:
        self.flush(force=True)
        since = int(time.time() // 60) - hours * 60
        where, args = "m >= ?", [since]
        if device_ip:
            where += " AND src = ?"
            args.append(device_ip)
        with self.lock:
            dests = self.db.execute(f"SELECT dst, SUM(n), SUM(nb), COUNT(DISTINCT src), GROUP_CONCAT(DISTINCT src), "
                                    f"GROUP_CONCAT(DISTINCT dport) FROM flows WHERE {where} GROUP BY dst "
                                    f"ORDER BY SUM(n) DESC LIMIT 400", args).fetchall()
            talkers = self.db.execute(f"SELECT src, SUM(n), COUNT(DISTINCT dst) FROM flows WHERE {where} "
                                      f"GROUP BY src ORDER BY SUM(n) DESC LIMIT {max(1, min(int(talkers), 1000))}", args).fetchall()
            total, uniq = self.db.execute(f"SELECT SUM(n), COUNT(DISTINCT dst) FROM flows WHERE {where}", args).fetchone()
        self.is_bad("")
        by_ip = {d["ip"]: d for d in self.nm.devices.values()}
        orgs, countries = collections.Counter(), collections.Counter()
        dest_rows = []
        for dst, n, nb, ndev, srcs, ports in dests:
            g, a = self.nm.threats.geo.lookup(dst), self.nm.threats.geo.asn(dst)
            org = a.get("org", "") or "Unknown network"
            orgs[org] += n
            if g["iso"]:
                countries[(g["iso"], g["country"])] += n
            dest_rows.append({"ip": dst, "count": n, "blocked": nb or 0, "devices": ndev, "org": org, "asn": a.get("asn"),
                              "iso": g["iso"], "country": g["country"], "city": g["city"], "lat": g["lat"], "lon": g["lon"],
                              "bad": dst in self.bad_ips or self.nm.threats.known_c2(dst),
                              "c2": self.nm.threats.known_c2(dst),
                              "srcs": [{"ip": s, "id": by_ip.get(s, {}).get("id", ""),
                                        "name": self.nm.label(by_ip[s]) if s in by_ip else s} for s in (srcs or "").split(",")[:6]],
                              "ports": sorted({int(p) for p in (ports or "").split(",") if p.isdigit()})[:8]})
        return {
            "type": "flow_summary", "hours": hours, "device": device_ip, "total": total or 0, "destinations": uniq or 0,
            "dests": dest_rows,
            "talkers": [{"ip": s, "count": n, "dests": u, "id": by_ip.get(s, {}).get("id", ""),
                         "name": self.nm.label(by_ip[s]) if s in by_ip else s,
                         "type": by_ip.get(s, {}).get("type", "unknown")} for s, n, u in talkers],
            "orgs": [{"org": o, "count": n} for o, n in orgs.most_common(10)],
            "countries": [{"iso": i, "country": c, "count": n} for (i, c), n in countries.most_common(10)],
            "bad": [r for r in dest_rows if r["bad"]][:20],
            "compromised": self._compromised(dest_rows),
            "recent": [r for r in self.recent if not device_ip or r["src"] == device_ip][:40],
            "last_flow": self.last_flow,
        }

    def _compromised(self, dest_rows: list) -> list:
        """Devices that connected OUT to a known botnet C2 — the strongest sign of compromise. One row per device."""
        by_dev: dict[str, dict] = {}
        for r in dest_rows:
            if not r.get("c2"):
                continue
            for s in r["srcs"]:
                g = by_dev.setdefault(s["ip"], {"ip": s["ip"], "id": s["id"], "name": s["name"], "c2s": [], "count": 0})
                g["c2s"].append({"ip": r["ip"], "org": r["org"], "country": r["country"], "ports": r["ports"]})
                g["count"] += r["count"]
        return sorted(by_dev.values(), key=lambda g: -g["count"])

    # ---- demo
    DEMO_DESTS = [  # documentation IPs with realistic owners and locations
        ("192.0.2.170", "Google LLC", "United States", "US", "Mountain View", 37.39, -122.08),
        ("192.0.2.171", "Netflix Streaming Services", "United States", "US", "Los Gatos", 37.24, -121.96),
        ("192.0.2.172", "Apple Inc.", "United States", "US", "Cupertino", 37.32, -122.03),
        ("192.0.2.173", "Amazon.com, Inc.", "United States", "US", "Ashburn", 39.04, -77.49),
        ("192.0.2.174", "Cloudflare, Inc.", "United States", "US", "San Francisco", 37.77, -122.42),
        ("192.0.2.175", "Microsoft Corporation", "United States", "US", "Redmond", 47.67, -122.12),
        ("192.0.2.176", "Spotify AB", "Sweden", "SE", "Stockholm", 59.33, 18.07),
        ("192.0.2.177", "Meta Platforms, Inc.", "United States", "US", "Menlo Park", 37.45, -122.18),
        ("192.0.2.178", "Akamai Technologies", "Germany", "DE", "Frankfurt", 50.11, 8.68),
        ("192.0.2.179", "Valve Corporation", "United States", "US", "Seattle", 47.61, -122.33),
        ("192.0.2.180", "Sony Interactive Entertainment", "Japan", "JP", "Tokyo", 35.68, 139.69),
        ("192.0.2.181", "Tuya Global", "China", "CN", "Hangzhou", 30.27, 120.15),
        ("192.0.2.182", "Ubiquiti Inc.", "United States", "US", "New York", 40.71, -74.0),
        ("192.0.2.183", "Hetzner Online GmbH", "Germany", "DE", "Falkenstein", 50.48, 12.37),
    ]
    DEMO_PLAN = {  # device ip -> [(dest index, weight, port)]
        "192.168.1.101": [(2, 6, 443), (0, 4, 443), (7, 3, 443), (6, 2, 443)],
        "192.168.1.102": [(2, 5, 443), (0, 4, 443), (4, 2, 443), (5, 2, 443), (13, 1, 22)],
        "192.168.1.103": [(9, 5, 443), (5, 4, 443), (0, 3, 443), (8, 3, 443)],
        "192.168.1.104": [(0, 6, 443), (7, 4, 443), (6, 2, 443)],
        "192.168.1.110": [(1, 8, 443), (3, 3, 443)],
        "192.168.1.111": [(0, 6, 443), (1, 4, 443)],
        "192.168.1.130": [(10, 5, 443), (3, 2, 443)],
        "192.168.1.150": [(13, 3, 443), (4, 2, 443)],
        "192.168.1.187": [(11, 4, 1883)],
        "192.168.1.2": [(12, 2, 443)],
    }

    def demo_geo(self):
        from threats import DEMO_ATTACKERS
        for ip, country, iso, city, lat, lon in DEMO_ATTACKERS:
            self.nm.threats.geo.cache[ip] = {"country": country, "iso": iso, "city": city, "region": "", "lat": lat, "lon": lon}
            self.nm.threats.geo.asn_cache[ip] = {"asn": 64511, "org": "Example VPS Hosting"}
        for ip, org, country, iso, city, lat, lon in self.DEMO_DESTS:
            self.nm.threats.geo.cache[ip] = {"country": country, "iso": iso, "city": city, "region": "", "lat": lat, "lon": lon}
            self.nm.threats.geo.asn_cache[ip] = {"asn": 64500 + int(ip.split(".")[-1]), "org": org}

    def demo_event(self, t: float):
        src = random.choices(list(self.DEMO_PLAN), weights=[4, 4, 4, 3, 5, 3, 2, 2, 1, 1])[0]
        plan = self.DEMO_PLAN[src]
        di, _, port = random.choices(plan, weights=[w for _, w, _ in plan])[0]
        dst = self.DEMO_DESTS[di][0]
        if src == "192.168.1.187" and random.random() < 0.25:
            dst, port = "203.0.113.14", 23          # the compromised plug phoning an attacker
        self.add(src, dst, port, "tcp", False, t)

    async def seed_demo(self):
        self.demo_geo()
        await asyncio.sleep(1.5)                  # let the first device sweep finish so names resolve
        now = time.time()
        for _ in range(2500):
            self.demo_event(now - random.random() * 86400)
        self.flush(force=True)
        self.live.clear()

    async def demo_loop(self):
        await self.seed_demo()
        while True:
            await asyncio.sleep(random.uniform(0.15, 0.6))
            self.demo_event(time.time())
