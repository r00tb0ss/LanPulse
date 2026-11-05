# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Local threat detection: things happening *inside* your network.

  * ARP sweeps     - a device asking for many addresses quickly (nmap -sn, Fing, malware looking around)
  * ARP spoofing   - a device claiming to be your router (man-in-the-middle setup), or IP conflicts. The router's
                     real hardware address is learned from LanPulse's own sweeps and checked on every sweep, in
                     ARP traffic LanPulse overhears, and in this server's own ARP table.
  * Rogue DHCP     - any device other than your router handing out IP addresses (it could send your devices to a
                     fake router or DNS server). LanPulse watches the DHCP replies it overhears; optionally it also
                     asks for an address every 15 minutes, under its own made-up hardware address (never the server's:
                     a request from the server's real address can make UniFi lose track of the server's IP).
  * Port scans     - many ports probed on this LanPulse server
  * Sensor events  - honeypot hits or UDM IPS / inter-VLAN drops whose source is a LAN address
                     (anything touching a honeypot on your LAN is suspicious by definition)
"""
from __future__ import annotations

import asyncio
import collections
import ipaddress
import logging
import os
import random
import re
import socket
import struct
import time

log = logging.getLogger("lanpulse.local")

KINDS = {
    "arp_sweep": ("Network sweep", "medium"),
    "arp_spoof": ("Router impersonation (ARP spoofing)", "high"),
    "rogue_dhcp": ("Unknown DHCP server", "high"),
    "router_changed": ("Router hardware changed", "medium"),
    "ip_conflict": ("IP address conflict", "medium"),
    "port_scan": ("Port scan against LanPulse", "high"),
    "lateral": ("Possible lateral movement", "high"),
    "honeypot": ("Touched the honeypot", "high"),
    "ips": ("IPS detection inside the LAN", "high"),
    "firewall": ("Blocked between networks", "low"),
}


# Ports an intruder uses to move from one machine to the next: SSH, Telnet, RPC, NetBIOS, SMB, RDP, WinRM, VNC,
# SQL Server, MySQL, PostgreSQL, NFS. One device reaching many *different* machines on these is the classic sign.
LATERAL_PORTS = {22, 23, 111, 135, 139, 445, 1433, 2049, 3306, 3389, 5432, 5900, 5985, 5986}
LATERAL_WINDOW = 600


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


class LocalWatch:
    def __init__(self, nm):
        self.nm = nm
        self.db = nm.threats.db
        self.lock = nm.threats.lock
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS local_events (t REAL, src TEXT, mac TEXT, kind TEXT, target TEXT,"
                            " dport INT, severity TEXT, detail TEXT, sensor TEXT)")
            self.db.execute("CREATE INDEX IF NOT EXISTS local_t ON local_events (t)")
            # clean up loopback entries saved by earlier versions
            self.db.execute("DELETE FROM local_events WHERE kind = 'firewall' AND src = target")
            # traffic "to" localhost is the router redirecting to itself, never a real connection or honeypot hit
            self.db.execute("DELETE FROM local_events WHERE target LIKE '127.%' OR target IN ('::1', '0.0.0.0')")
            # Older versions recorded every router drop between two devices on the same subnet as "blocked". Those were
            # almost all leftover packets of finished connections (same-subnet traffic doesn't pass the router), and they
            # were stored without the detail needed to tell, so clear them out once.
            try:
                net = ipaddress.ip_network(nm.net["subnet"], strict=False)
                old = self.db.execute("SELECT rowid, src, target FROM local_events WHERE kind = 'firewall' "
                                      "AND detail LIKE 'Connected to port%'").fetchall()
                same = [(rid,) for rid, a, b in old if _in(a, net) and _in(b, net)]
                if same:
                    self.db.executemany("DELETE FROM local_events WHERE rowid = ?", same)
                    log.info("Removed %d old same-subnet router drops that weren't real blocks", len(same))
            except (KeyError, ValueError):
                pass
            self.db.commit()
        self.arp_req: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.syn: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.ip_mac: dict[str, tuple[str, float]] = {}
        self.last_flag: dict[tuple, float] = {}
        self.kind_times: dict[str, collections.deque] = {}
        self.fw_seen: dict[tuple, list] = {}            # (src, dst, port) -> [last shown, repeats hidden]
        self.lateral: dict[str, dict] = {}            # src -> {dst: {ports}} within the window
        self.lateral_t: dict[str, dict] = {}          # src -> {dst: last time}
        self.gw_seen = time.time()           # when the router's known MAC last answered a sweep
        self.dhcp_servers: dict[str, dict] = {}     # server IP -> what it handed out, seen recently
        self.dlock = __import__("threading").Lock()
        self.dhcp_probe_xid = 0
        self.loop: asyncio.AbstractEventLoop | None = None
        self.sniffer = None
        self.running = False
        self.error = ""

    @property
    def cfg(self) -> dict:
        return self.nm.settings["local"]

    # ---- lifecycle
    async def start(self) -> list:
        self.loop = asyncio.get_running_loop()
        if self.nm.args.demo:
            self.running = True
            self.seed_demo()
            return [asyncio.create_task(self.demo_loop())]
        if not self.cfg.get("enabled", True):
            self.error = "turned off in settings"
            return []
        try:
            from scapy.all import AsyncSniffer
        except Exception:
            self.error = "scapy is not installed"
            return []
        if os.geteuid() != 0:
            self.error = "LanPulse must run as root to watch the network"
            return []
        my = self.nm.net["my_ip"]
        lports = " or ".join(f"dst port {p}" for p in sorted(LATERAL_PORTS))
        flt = (f"arp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and (dst host {my} or ({lports})))"
               " or (udp and (port 67 or port 68 or port 5353))")
        try:
            self.sniffer = AsyncSniffer(iface=self.nm.net["iface"], filter=flt, prn=self.on_packet, store=False)
            self.sniffer.start()
            self.running = True
            log.info("Watching for local threats on %s", self.nm.net["iface"])
        except Exception as e:
            self.error = str(e)
            log.warning("Local threat watcher failed: %s", e)
            return []
        try:
            await asyncio.to_thread(self.announce_self)
        except Exception as e:
            log.debug("Couldn't announce this server's address: %s", e)
        return [asyncio.create_task(self.dhcp_probe_loop())]

    def announce_self(self):
        """Gratuitous ARP: tell every device and access point "192.168.x.y is at this server's hardware address", which
        repairs stale address tables (as left behind by 1.15.0's DHCP check, which used the server's own address)."""
        from scapy.all import ARP, Ether, sendp
        ip, mac = self.nm.net.get("my_ip"), (self.nm.net.get("my_mac") or "").lower()
        if not ip or not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
            return
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=ip)
        sendp(pkt, iface=self.nm.net["iface"], count=3, inter=0.5, verbose=False)

    def ignored(self, ip: str, mac: str = "") -> bool:
        if ip in (self.nm.net.get("my_ip"),) or (mac and mac == self.nm.net.get("my_mac")):
            return True
        if ip in self.cfg.get("ignore", []):
            return True
        d = self.device_by_ip(ip)
        return bool(d and d.get("scans_ok"))

    def device_by_ip(self, ip: str) -> dict | None:
        return next((d for d in self.nm.devices.values() if d["ip"] == ip), None)

    # ---- packet handlers (sniffer thread)
    def on_packet(self, pkt):
        try:
            from scapy.all import ARP, IP, TCP, UDP
            now = time.time()
            if UDP in pkt and IP in pkt:
                disc = getattr(self.nm, "discovery", None)
                if disc and self.loop:
                    u = pkt[UDP]
                    payload = bytes(u.payload)
                    if u.sport == 67 and u.dport == 68:
                        info = parse_dhcp_reply(payload)
                        if info:
                            self.on_dhcp_reply(info, pkt[IP].src, pkt.src.upper() if hasattr(pkt, "src") else "", now)
                    elif u.dport == 67 or u.sport == 68:
                        from discovery import parse_dhcp
                        info = parse_dhcp(payload)
                        if info:
                            self.loop.call_soon_threadsafe(disc.on_dhcp, info, pkt[IP].src)
                    elif u.sport == 5353 or u.dport == 5353:
                        if pkt[IP].src != self.nm.net.get("my_ip"):
                            self.loop.call_soon_threadsafe(disc.on_mdns, payload, pkt[IP].src)
                return
            if ARP in pkt:
                self.on_arp(pkt[ARP], now)
            elif IP in pkt and TCP in pkt:
                dport = int(pkt[TCP].dport)
                if pkt[IP].dst == self.nm.net.get("my_ip"):
                    self.on_syn(pkt[IP].src, dport, pkt.src.upper() if hasattr(pkt, "src") else "", now)
                self.observe_lan(pkt[IP].src, pkt[IP].dst, dport, now)
        except Exception as e:
            log.debug("packet error: %s", e)

    # ---- the router's real hardware address
    @property
    def gw_pinned(self) -> str:
        """The router's MAC as learned from LanPulse's own sweeps (never from overheard traffic, which an attacker
        could send first)."""
        return self.cfg.get("gateway_mac", "")

    def spoof_text(self, mac: str, gw: str) -> str:
        who = next((d for d in self.nm.devices.values() if d.get("mac") == mac and not d.get("is_gateway")), None)
        name = f"{self.nm.label(who)} ({who['ip']}, {mac})" if who else mac
        return (f"{name} claims to be your router {gw}. The router's real hardware address is {self.gw_pinned}. "
                f"Devices that believe it send their traffic through it (man-in-the-middle).")

    def check_sweep(self, pairs: list[tuple[str, str]], now: float) -> set[str]:
        """Called after every ARP sweep (event loop) with every (MAC, IP) answer. Learns the router's MAC the first
        time, then flags any other MAC answering for the router's IP. Returns MACs that must not be taken as the
        router."""
        gw = self.nm.net.get("gateway")
        if not gw or not self.cfg.get("enabled", True):
            return set()
        gw_macs = {m for m, ip in pairs if ip == gw and m}
        pinned = self.gw_pinned
        if not pinned:
            # Upgrading from a version that didn't pin it: the router LanPulse already knew wins if it still answers
            known = next((d.get("mac") for d in list(self.nm.devices.values()) if d.get("is_gateway") and d.get("mac")), "")
            if known and known in gw_macs:
                self.cfg["gateway_mac"] = known
                self.nm.save_settings()
                return self.check_sweep(pairs, now)
            if len(gw_macs) == 1:
                self.cfg["gateway_mac"] = next(iter(gw_macs))
                self.nm.save_settings()
                log.info("Router %s has hardware address %s", gw, self.cfg["gateway_mac"])
            elif len(gw_macs) > 1:
                self.flag("arp_spoof", "", ",".join(sorted(gw_macs)), gw, None,
                          f"{len(gw_macs)} devices answer as your router {gw}: {', '.join(sorted(gw_macs))}. "
                          "One of them is impersonating it. LanPulse won't learn the router's address until only one answers.")
            return set()
        if pinned in gw_macs:
            self.gw_seen = now
        imposters = gw_macs - {pinned}
        if imposters and pinned not in gw_macs and len(gw_macs) == 1 and now - self.gw_seen > 3600:
            # The known router hasn't answered for an hour and exactly one new device answers: a replaced router.
            new = next(iter(imposters))
            self.flag("router_changed", "", new, gw, None,
                      f"Your router {gw} now has hardware address {new} (it was {pinned}, which hasn't answered for an "
                      "hour). If you didn't replace or reset your router, check your network.")
            self.cfg["gateway_mac"] = new
            self.nm.save_settings()
            self.gw_seen = now
            return set()
        for mac in imposters:
            self.flag("arp_spoof", "", mac, gw, None, self.spoof_text(mac, gw))
        self.check_own_arp(gw, pinned)
        return imposters

    def check_own_arp(self, gw: str, pinned: str):
        """Is this server itself being fooled? Its own ARP table should point the router's IP at the router."""
        try:
            with open("/proc/net/arp") as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4 and cols[0] == gw and cols[2] == "0x2":
                        mac = cols[3].upper()
                        if mac != pinned and mac != "00:00:00:00:00:00":
                            self.flag("arp_spoof", "", mac, gw, None,
                                      f"This LanPulse server's own ARP table says the router {gw} is {mac}, but the router "
                                      f"is {pinned}. Its traffic is being intercepted.")
        except (OSError, StopIteration):
            pass

    def on_arp(self, a, now: float):
        mac, ip = a.hwsrc.upper(), a.psrc
        if mac == self.nm.net.get("my_mac"):
            return
        gw = self.nm.net.get("gateway")
        if ip and ip != "0.0.0.0":
            if ip == gw:
                if self.gw_pinned and mac != self.gw_pinned:
                    self.flag("arp_spoof", "", mac, gw, None, self.spoof_text(mac, gw))
            else:
                prev = self.ip_mac.get(ip)
                if prev and prev[0] != mac and now - prev[1] < 120:
                    self.flag("ip_conflict", ip, mac, ip, None, f"Two devices are using {ip}: {prev[0]} and {mac}.")
                self.ip_mac[ip] = (mac, now)
        if a.op == 1 and a.pdst and ip != gw and not self.ignored(ip, mac):
            q = self.arp_req[mac]
            q.append((now, a.pdst))
            while q and now - q[0][0] > 30:
                q.popleft()
            targets = {t for _, t in q}
            if len(targets) >= int(self.cfg.get("sweep_threshold", 40)):
                self.flag("arp_sweep", ip, mac, "", None,
                          f"Looked up {len(targets)} addresses on your network in 30 seconds (network scan).")
                q.clear()

    def on_syn(self, src: str, dport: int, mac: str, now: float):
        if not is_private(src) or self.ignored(src, mac):
            return
        q = self.syn[src]
        q.append((now, dport))
        while q and now - q[0][0] > 60:
            q.popleft()
        ports = {p for _, p in q}
        if len(ports) >= int(self.cfg.get("scan_threshold", 15)):
            sample = ", ".join(str(p) for p in sorted(ports)[:8])
            self.flag("port_scan", src, mac, self.nm.net["my_ip"], None,
                      f"Probed {len(ports)} ports on this server in 60 seconds ({sample}…).")
            q.clear()

    # ---- lateral movement: one device reaching for many other machines on admin ports
    def observe_lan(self, src: str, dst: str, dport, now: float | None = None):
        """Called for every LAN-to-LAN connection attempt LanPulse can see (router logs between networks, and any
        traffic that reaches this server's network card, e.g. through a mirror port)."""
        try:
            port = int(dport or 0)
        except (TypeError, ValueError):
            return
        if port not in LATERAL_PORTS or not is_private(src) or not is_private(dst) or src == dst:
            return
        if dst in (self.nm.net.get("my_ip"),) or self.ignored(src):
            return
        now = now or time.time()
        with self.dlock:
            seen = self.lateral.setdefault(src, {})
            seen.setdefault(dst, set()).add(port)
            self.lateral_t.setdefault(src, {})[dst] = now
            for d, t in list(self.lateral_t[src].items()):
                if now - t > LATERAL_WINDOW:
                    del self.lateral_t[src][d]
                    seen.pop(d, None)
            if len(self.lateral) > 500:                       # bound memory on a big or hostile network
                for k in list(self.lateral)[:100]:
                    self.lateral.pop(k, None)
                    self.lateral_t.pop(k, None)
            targets = list(seen)
            ports = sorted({p for v in seen.values() for p in v})
        need = int(self.cfg.get("lateral_threshold", 5))
        if len(targets) >= need:
            names = []
            for ip in targets[:5]:
                d = self.device_by_ip(ip)
                names.append(self.nm.label(d) if d else ip)
            self.flag("lateral", src, "", targets[0], ports[0] if ports else None,
                      f"Tried to connect to {len(targets)} different devices in 10 minutes on admin ports "
                      f"({', '.join(str(p) for p in ports[:6])}): {', '.join(names)}{'…' if len(targets) > 5 else ''}. "
                      "This is how an intruder spreads from one machine to others.")
            with self.dlock:
                self.lateral.pop(src, None)
                self.lateral_t.pop(src, None)

    # ---- rogue DHCP servers
    def dhcp_allowed(self, server_ip: str, mac: str) -> bool:
        if server_ip == self.nm.net.get("gateway") or (mac and self.gw_pinned and mac == self.gw_pinned):
            return True
        return server_ip in self.cfg.get("dhcp_servers", [])

    def on_dhcp_reply(self, info: dict, src_ip: str, mac: str, now: float):
        """A DHCP server answered someone (sniffer thread)."""
        if info["type"] not in (2, 5):                 # OFFER or ACK: the server is handing out an address
            return
        server = info.get("server_id") or src_ip
        if not server or server == "0.0.0.0":
            return
        rec = {"ip": server, "mac": mac, "t": now, "offered": info.get("yiaddr", ""), "router": info.get("router", ""),
               "dns": info.get("dns", ""), "allowed": self.dhcp_allowed(server, mac), "probe": info["xid"] == self.dhcp_probe_xid}
        with self.dlock:
            self.dhcp_servers[server] = rec
            if len(self.dhcp_servers) > 20:             # forged replies can't grow this without limit
                oldest = min(self.dhcp_servers, key=lambda k: self.dhcp_servers[k]["t"])
                self.dhcp_servers.pop(oldest, None)
        if rec["allowed"] or not self.cfg.get("dhcp_check", True):
            return
        who = next((d for d in self.nm.devices.values() if d.get("mac") == mac and mac), None)
        name = f"{self.nm.label(who)} ({server})" if who else f"{server} ({mac or 'unknown hardware address'})"
        hands = ", ".join(x for x in (f"address {rec['offered']}" if rec["offered"] else "",
                                       f"router {rec['router']}" if rec["router"] else "",
                                       f"DNS {rec['dns']}" if rec["dns"] else "") if x)
        self.flag("rogue_dhcp", server if is_private(server) else "", mac, rec["offered"], 67,
                  f"{name} is handing out IP addresses" + (f" ({hands})" if hands else "") + ". Only your router should. "
                  "A rogue DHCP server can send devices to a fake router or DNS server. If this is a DHCP server you run on "
                  "purpose, add it under Settings > Threats > Allowed DHCP servers.")

    async def dhcp_probe_loop(self):
        """Every 15 minutes, ask "who hands out addresses here?" (a DHCP DISCOVER, never followed by a request, so
        no address is taken) and let the sniffer catch every server that answers."""
        await asyncio.sleep(60)
        while True:
            if self.cfg.get("enabled", True) and self.cfg.get("dhcp_check", True) and self.cfg.get("dhcp_probe", False):
                try:
                    await asyncio.to_thread(self.send_discover)
                except Exception as e:
                    log.debug("DHCP check failed: %s", e)
            await asyncio.sleep(900)

    def send_discover(self):
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, sendp
        real = self.nm.net.get("my_mac") or ""
        if not re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", real):
            return
        # A made-up, fixed "locally administered" address (02:4C:50 = "LP"), never the server's own: a DHCP request
        # from the server's real address makes the router offer it an address and UniFi's tracking of which device
        # has which IP can then point the server's IP elsewhere, cutting Wi-Fi devices off from LanPulse.
        mac = "02:4C:50:" + real[9:]
        self.dhcp_probe_xid = random.getrandbits(32)
        raw = bytes.fromhex(mac.replace(":", ""))
        pkt = (Ether(src=mac.lower(), dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
               UDP(sport=68, dport=67) / BOOTP(chaddr=raw + b"\0" * 10, xid=self.dhcp_probe_xid, flags=0x8000) /
               DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 54]), "end"]))
        sendp(pkt, iface=self.nm.net["iface"], verbose=False)

    def dhcp_status(self) -> list[dict]:
        cutoff = time.time() - 3 * 3600
        with self.dlock:
            servers = list(self.dhcp_servers.values())
        return [dict(r, name=self.nm.label(d) if (d := next((x for x in self.nm.devices.values()
                                                               if r["mac"] and x.get("mac") == r["mac"]), None)) else "")
                for r in sorted(servers, key=lambda r: -r["t"]) if r["t"] > cutoff]

    def flag(self, kind: str, src: str, mac: str, target: str, dport, detail: str, sensor: str = "LanPulse"):
        key = (kind, src or mac or target)
        now = time.time()
        if now - self.last_flag.get(key, 0) < 600:          # one event per source and kind every 10 minutes
            return
        # Forged packets can use a new fake address every time: cap each kind at 10 events per 10 minutes overall,
        # and keep the dedupe table from growing without limit.
        recent = self.kind_times.setdefault(kind, collections.deque())
        while recent and now - recent[0] > 600:
            recent.popleft()
        if len(recent) >= 10:
            return
        recent.append(now)
        if len(self.last_flag) > 2000:
            self.last_flag = {k: v for k, v in self.last_flag.items() if now - v < 600}
        self.last_flag[key] = now
        ev = {"t": now, "src": src, "mac": mac, "kind": kind, "target": target, "dport": dport,
              "severity": KINDS[kind][1], "detail": detail, "sensor": sensor}
        if self.loop:
            self.loop.call_soon_threadsafe(self.record, ev)

    # ---- intake from sensors (event loop thread)
    def from_sensor(self, raw: dict, sensor: str):
        src = raw.get("src", "")
        if not is_private(src) or self.ignored(src):
            return None
        s = (raw.get("sensor") or sensor or "").lower()
        kind = "honeypot" if "honey" in s or raw.get("action") == "logged" else "ips" if "ips" in s else "firewall"
        target = str(raw.get("lan_ip") or raw.get("dst") or "")
        if target and (target == src or target == self.nm.threats.public_ip):
            return None                 # a device reaching itself through NAT loopback
        port = raw.get("dport")
        flags = " ".join(raw.get("flags") or [])
        if raw.get("detail"):
            detail = raw["detail"]
        elif kind == "firewall" and raw.get("action") == "blocked":
            detail = (f"Router blocked a new connection to port {port}" if "SYN" in flags else
                      f"Router dropped traffic to port {port}") if port else "Router dropped traffic"
        else:
            detail = f"Connected to port {port}" if port else ""
        if kind == "firewall":
            # The same blocked attempt repeats constantly (a VPN client retrying, a chatty app). Show it once per
            # 10 minutes with a count instead of one row per packet.
            now = time.time()
            key = (src, target, port)
            seen = self.fw_seen.get(key)
            if seen and now - seen[0] < 600:
                seen[1] += 1
                return None
            repeats = seen[1] if seen else 0
            if len(self.fw_seen) > 2000:
                self.fw_seen = {k: v for k, v in self.fw_seen.items() if now - v[0] < 600}
            self.fw_seen[key] = [now, 0]
            if repeats:
                detail = f"{detail} (repeated {repeats} more time{'s' if repeats != 1 else ''} since the last alert)"
        ev = {"t": time.time(), "src": src, "mac": "", "kind": kind, "target": target, "dport": port,
              "severity": KINDS[kind][1], "detail": detail[:300], "sensor": raw.get("sensor") or sensor}
        return self.record(ev)

    def record(self, ev: dict) -> dict:
        with self.lock:
            self.db.execute("INSERT INTO local_events VALUES (?,?,?,?,?,?,?,?,?)",
                            (ev["t"], ev["src"], ev["mac"], ev["kind"], ev["target"], ev["dport"], ev["severity"],
                             ev["detail"], ev["sensor"]))
            self.db.commit()
        self.decorate(ev)
        log.info("Local threat: %s from %s: %s", ev["kind"], ev["src"] or ev["mac"], ev["detail"])
        try:
            asyncio.get_running_loop().create_task(self.nm.broadcast({"type": "local_threat", "event": ev}))
            dev = self.device_by_ip(ev["src"]) if ev["src"] else None
            subject = dev or {"id": f"local:{ev['src'] or ev['mac']}", "ip": ev["src"] or "?", "mac": ev["mac"],
                              "vendor": "", "type": "unknown"}
            if ev["severity"] != "low":
                self.nm.notify("local_threats", subject, f"{KINDS[ev['kind']][0]}: {ev['src_name'] or ev['src'] or ev['mac']}",
                               ev["detail"], 5 if ev["severity"] == "high" else 4)
        except RuntimeError:
            pass
        return ev

    def decorate(self, ev: dict):
        s = self.device_by_ip(ev["src"]) if ev.get("src") else None
        if not s and ev.get("mac"):
            s = next((d for d in self.nm.devices.values() if d.get("mac") == ev["mac"]), None)
        t = self.device_by_ip(ev["target"]) if ev.get("target") else None
        ev["src_id"], ev["src_name"] = (s["id"], self.nm.label(s)) if s else ("", "")
        ev["target_id"], ev["target_name"] = (t["id"], self.nm.label(t)) if t else ("", "")
        ev["title"] = KINDS.get(ev["kind"], (ev["kind"], ""))[0]
        return ev

    # ---- reporting
    def summary(self, hours: int = 24) -> dict:
        since = time.time() - hours * 3600
        keys = ("t", "src", "mac", "kind", "target", "dport", "severity", "detail", "sensor")
        with self.lock:
            rows = self.db.execute("SELECT t, src, mac, kind, target, dport, severity, detail, sensor FROM local_events "
                                   "WHERE t >= ? ORDER BY t DESC LIMIT 200", (since,)).fetchall()
        events = [self.decorate(dict(zip(keys, r))) for r in rows]
        by_src = collections.Counter(e["src_id"] or e["src"] or e["mac"] for e in events)
        return {"events": events[:60], "count": len(events), "sources": len(by_src),
                "high": sum(e["severity"] == "high" for e in events),
                "status": {"running": self.running, "error": self.error, "gateway_mac": self.gw_pinned,
                           "dhcp_check": self.cfg.get("dhcp_check", True), "dhcp_servers": self.dhcp_status()}}

    def for_device(self, ip: str, mac: str) -> list[dict]:
        keys = ("t", "src", "mac", "kind", "target", "dport", "severity", "detail", "sensor")
        with self.lock:
            rows = self.db.execute("SELECT t, src, mac, kind, target, dport, severity, detail, sensor FROM local_events "
                                   "WHERE src = ? OR target = ? OR (mac != '' AND mac = ?) ORDER BY t DESC LIMIT 30",
                                   (ip, ip, mac or "-")).fetchall()
        return [self.decorate(dict(zip(keys, r))) for r in rows]

    def prune(self, keep_days: int = 30):
        with self.lock:
            self.db.execute("DELETE FROM local_events WHERE t < ?", (time.time() - keep_days * 86400,))
            self.db.commit()

    # ---- demo
    DEMO = [
        ("honeypot", "192.168.1.187", "D8:1F:12:4E:90:B7", "192.168.1.121", 23, "login root/xc3511 · busybox wget payload", "esp32-honeypot"),
        ("arp_sweep", "192.168.1.104", "DA:A1:19:11:22:68", "", None, "Looked up 254 addresses on your network in 30 seconds (network scan).", "LanPulse"),
        ("port_scan", "192.168.1.103", "D8:BB:C1:11:22:67", "192.168.1.10", None, "Probed 1000 ports on this server in 60 seconds (21, 22, 23, 25, 53, 80, 110, 135…).", "LanPulse"),
        ("honeypot", "192.168.1.187", "D8:1F:12:4E:90:B7", "192.168.1.121", 22, "login admin/admin", "esp32-honeypot"),
    ]

    def seed_demo(self):
        with self.lock:
            n = self.db.execute("SELECT COUNT(*) FROM local_events").fetchone()[0]
        if n:
            return
        now = time.time()
        for i, (kind, src, mac, tgt, port, detail, sensor) in enumerate(self.DEMO):
            with self.lock:
                self.db.execute("INSERT INTO local_events VALUES (?,?,?,?,?,?,?,?,?)",
                                (now - (i + 1) * 2700, src, mac, kind, tgt, port, KINDS[kind][1], detail, sensor))
                self.db.commit()

    async def demo_loop(self):
        while True:
            await asyncio.sleep(random.uniform(40, 80))
            kind, src, mac, tgt, port, detail, sensor = random.choice(self.DEMO)
            self.last_flag.clear()
            self.record({"t": time.time(), "src": src, "mac": mac, "kind": kind, "target": tgt, "dport": port,
                         "severity": KINDS[kind][1], "detail": detail, "sensor": sensor})


def _in(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def parse_dhcp_reply(payload: bytes) -> dict | None:
    """A DHCP server's reply: {type, xid, yiaddr, server_id, router, dns}. Untrusted input: lengths are checked."""
    if len(payload) < 240 or payload[0] != 2 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    out = {"type": 0, "xid": struct.unpack("!I", payload[4:8])[0], "yiaddr": socket.inet_ntoa(payload[16:20]),
           "server_id": "", "router": "", "dns": ""}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        ln = payload[i + 1]
        val = payload[i + 2:i + 2 + ln]
        if len(val) < ln:
            break
        if code == 53 and ln >= 1:
            out["type"] = val[0]
        elif code == 54 and ln == 4:
            out["server_id"] = socket.inet_ntoa(val)
        elif code == 3 and ln >= 4:
            out["router"] = socket.inet_ntoa(val[:4])
        elif code == 6 and ln >= 4:
            out["dns"] = ", ".join(socket.inet_ntoa(val[j:j + 4]) for j in range(0, min(ln, 12) - 3, 4))
        i += 2 + ln
    if out["yiaddr"] == "0.0.0.0":
        out["yiaddr"] = ""
    return out
