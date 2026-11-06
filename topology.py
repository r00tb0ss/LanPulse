# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Network topology: who is connected to what.

LanPulse can see every device's address but not, by itself, which switch port or access point it hangs off. This module
builds that picture from the best source available, in this order:
  1. a manual choice you made for a device (works with any router or switch),
  2. UniFi, when a gateway is configured: it reports each client's access point or switch port, Wi-Fi details,
     VLANs, and each switch's and access point's uplink,
  3. a sensible default: everything hangs off the gateway.
Devices are also grouped into zones (VLANs or subnets). Nothing here changes anything on your network.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import threading
import time
from pathlib import Path

log = logging.getLogger("lanpulse.topology")

ZONE_COLORS = ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#f472b6", "#fb923c", "#2dd4bf", "#f87171", "#60a5fa", "#c084fc"]
RADIO_BAND = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ax": "6 GHz"}
INFRA_KINDS = ("gateway", "switch", "ap")
ROLES = ("auto", "gateway", "switch", "ap", "client")
MEDIA = ("auto", "wired", "wifi")


def norm_mac(m) -> str:
    return (m or "").strip().upper().replace("-", ":")


def _color_for(name: str) -> str:
    return ZONE_COLORS[int(hashlib.md5(name.encode()).hexdigest(), 16) % len(ZONE_COLORS)]


def _signal_quality(dbm) -> str:
    if dbm is None:
        return ""
    return "good" if dbm >= -60 else "fair" if dbm >= -70 else "poor"


class Topology:
    def __init__(self, nm, path: Path):
        self.nm = nm
        self.path = Path(path)
        self.lock = threading.Lock()
        self.state = {"manual": {}, "zones": [], "log": [], "last_parent": {}}
        self.unifi: dict = {}
        self.unifi_status: dict = {"configured": False, "ok": False, "error": "", "t": 0}
        try:
            self.state.update(json.loads(self.path.read_text()))
        except Exception:
            pass

    # ------------------------------------------------------------------ persistence
    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.path)
        except Exception:
            log.exception("could not save topology")

    def set_manual(self, dev_id: str, parent: str = "", role: str = "auto", medium: str = "auto", zone: str = ""):
        if role not in ROLES or medium not in MEDIA:
            raise ValueError("Unknown role or connection type.")
        with self.lock:
            if parent == dev_id:
                raise ValueError("A device can't connect to itself.")
            if (parent or "") in ("", "auto") and role == "auto" and medium == "auto" and not zone:
                self.state["manual"].pop(dev_id, None)
            else:
                self.state["manual"][dev_id] = {"parent": "" if parent == "auto" else parent, "role": role,
                                                "medium": medium, "zone": zone}
            self._save()

    def set_zones(self, zones: list):
        out = []
        for z in zones[:40]:
            name = str(z.get("name", "")).strip()[:40]
            try:
                net = str(ipaddress.ip_network(str(z.get("cidr", "")).strip(), strict=False))
            except ValueError:
                continue
            if name:
                out.append({"cidr": net, "name": name, "color": z.get("color") or _color_for(name)})
        with self.lock:
            self.state["zones"] = out
            self._save()

    def set_unifi(self, data: dict | None, error: str = "", configured: bool = True):
        with self.lock:
            if data is not None:
                self.unifi = data
            self.unifi_status = {"configured": configured, "ok": data is not None and not error, "error": error, "t": time.time(),
                                 "devices": len((data or {}).get("devices", [])), "clients": len((data or {}).get("clients", []))}

    # ------------------------------------------------------------------ build
    def build(self) -> dict:
        devs = {d["id"]: d for d in self.nm.devices.values()}
        by_mac = {norm_mac(d.get("mac")): d["id"] for d in devs.values() if d.get("mac")}
        u = self.unifi or {}
        ud = {norm_mac(x.get("mac")): x for x in u.get("devices", []) if x.get("mac")}
        uc = {norm_mac(x.get("mac")): x for x in u.get("clients", []) if x.get("mac")}
        nets = u.get("networks", [])
        manual = self.state.get("manual", {})

        gateway = next((d["id"] for d in devs.values() if d.get("is_gateway")), None)
        nodes: dict[str, dict] = {}

        def zone_of(d, uclient):
            m = manual.get(d["id"], {}).get("zone")
            if m:
                return m
            if uclient:
                nm_ = uclient.get("network") or ""
                if nm_:
                    return nm_
            try:
                ip = ipaddress.ip_address(d.get("ip", ""))
            except ValueError:
                return ""
            for z in self.state.get("zones", []):
                if ip in ipaddress.ip_network(z["cidr"]):
                    return z["name"]
            for n in nets:
                try:
                    if ip in ipaddress.ip_network(n.get("ip_subnet", ""), strict=False):
                        return n.get("name", "")
                except ValueError:
                    continue
            return ""

        for d in devs.values():
            mac = norm_mac(d.get("mac"))
            uinfra, uclient = ud.get(mac), uc.get(mac)
            role = manual.get(d["id"], {}).get("role", "auto")
            if role != "auto":
                kind = role
            elif d.get("id") == gateway:
                kind = "gateway"
            elif uinfra:
                t = str(uinfra.get("type", ""))
                kind = "ap" if t == "uap" else "switch" if t == "usw" else "gateway" if t in ("ugw", "udm", "uxg", "udr") else "client"
            elif d.get("type") == "ap":
                kind = "ap"
            elif d.get("type") == "switch":
                kind = "switch"
            elif d.get("type") == "router":
                kind = "gateway" if not gateway else "client"
            else:
                kind = "client"
            if uinfra and uinfra.get("name") and not d.get("name"):
                d = {**d, "name": uinfra["name"]}      # the alias set in UniFi beats a vendor name
            nodes[d["id"]] = {"id": d["id"], "kind": kind, "name": self.nm.label(d), "ip": d.get("ip", ""), "mac": d.get("mac", ""),
                              "vendor": d.get("vendor", ""), "type": d.get("type", "unknown"), "online": (uinfra.get("state", 1) == 1) if uinfra else bool(d.get("online")),
                              "model": (uinfra or {}).get("model", "") or d.get("model", ""), "zone": zone_of(d, uclient),
                              "parent": None, "link": {}, "extra": {}, "source": "inferred", "first_seen": d.get("first_seen", 0),
                              "last_seen": d.get("last_seen", 0)}

        # UniFi infrastructure that LanPulse hasn't discovered itself still belongs on the map
        for mac, x in ud.items():
            if mac in by_mac:
                continue
            gid = "u:" + mac
            t = str(x.get("type", ""))
            kind = "ap" if t == "uap" else "switch" if t == "usw" else "gateway" if t in ("ugw", "udm", "uxg", "udr") else "client"
            nodes[gid] = {"id": gid, "kind": kind, "name": x.get("name") or x.get("model") or mac, "ip": x.get("ip", ""), "mac": mac,
                          "vendor": "Ubiquiti", "type": "ap" if kind == "ap" else "switch" if kind == "switch" else "router",
                          "online": x.get("state", 1) == 1, "model": x.get("model", ""), "zone": "", "parent": None, "link": {},
                          "extra": {}, "source": "unifi", "first_seen": 0, "last_seen": 0, "ghost": True}
            by_mac[mac] = gid

        # No gateway flagged by LanPulse's scan? Find it another way so the map always has a root.
        if gateway is None or gateway not in nodes:
            gw_ip = ""
            try:
                gw_ip = str((getattr(self.nm, "net", None) or {}).get("gateway") or "")
            except Exception:
                pass
            pick = (next((i for i, n in nodes.items() if gw_ip and n["ip"] == gw_ip), None)
                    or next((i for i, n in nodes.items() if n["kind"] == "gateway"), None)
                    or next((i for i, n in nodes.items() if n["type"] == "router"), None))
            if pick is None and nodes:
                pick = "u:gateway"
                nodes[pick] = {"id": pick, "kind": "gateway", "name": "Gateway", "ip": gw_ip, "mac": "", "vendor": "", "type": "router",
                               "online": True, "model": "", "zone": "", "parent": None, "link": {}, "extra": {}, "source": "inferred",
                               "first_seen": 0, "last_seen": 0, "ghost": True}
            gateway = pick
            if gateway in nodes:
                nodes[gateway]["kind"] = "gateway"

        # ---- parents and links
        for nid, n in nodes.items():
            mac = norm_mac(n["mac"])
            man = manual.get(nid, {})
            uinfra, uclient = ud.get(mac), uc.get(mac)
            if n["kind"] == "gateway" and nid == gateway:
                n["parent"] = "__internet"
                continue
            parent = None
            if man.get("parent"):
                parent = man["parent"] if man["parent"] in nodes else None
                n["source"] = "manual"
            if parent is None and uclient:
                pm = norm_mac(uclient.get("ap_mac") if not uclient.get("is_wired") else uclient.get("sw_mac"))
                if pm in by_mac:
                    parent = by_mac[pm]
                    n["source"] = "unifi"
                wired = bool(uclient.get("is_wired"))
                if wired:
                    sw = ud.get(pm) or {}
                    port = uclient.get("sw_port")
                    speed = None
                    for p in sw.get("port_table", []) or []:
                        if p.get("port_idx") == port:
                            speed = p.get("speed")
                    n["link"] = {"medium": "wired", "port": port, "speed": speed or uclient.get("wired_rate_mbps")}
                else:
                    sig = uclient.get("signal") if uclient.get("signal") is not None else uclient.get("rssi")
                    n["link"] = {"medium": "wifi", "ssid": uclient.get("essid", ""), "band": RADIO_BAND.get(uclient.get("radio", ""), ""),
                                 "channel": uclient.get("channel"), "signal": sig, "quality": _signal_quality(sig),
                                 "tx": uclient.get("tx_rate"), "rx": uclient.get("rx_rate"), "uptime": uclient.get("uptime")}
            if parent is None and uinfra:
                up = uinfra.get("uplink") or {}
                pm = norm_mac(up.get("uplink_mac"))
                if pm in by_mac:
                    parent = by_mac[pm]
                    n["source"] = "unifi"
                    wireless = up.get("type") == "wireless"
                    n["link"] = {"medium": "wifi" if wireless else "wired", "port": up.get("uplink_remote_port") or up.get("port_idx"),
                                 "speed": up.get("speed"), "mesh": wireless}
            if man.get("medium") in ("wired", "wifi"):
                n["link"] = {**n["link"], "medium": man["medium"]}
            if parent is None or parent == nid:
                parent = gateway or "__internet"
            n["parent"] = parent

        # break cycles: anything that doesn't reach the gateway is re-parented to it
        for nid, n in nodes.items():
            seen, cur = {nid}, n.get("parent")
            while cur in nodes:
                if cur in seen:
                    n["parent"] = gateway or "__internet"
                    break
                seen.add(cur)
                cur = nodes[cur].get("parent")

        # ---- infrastructure details
        kids: dict[str, int] = {}
        for n in nodes.values():
            kids[n["parent"]] = kids.get(n["parent"], 0) + 1
        for nid, n in nodes.items():
            mac = norm_mac(n["mac"])
            x = ud.get(mac)
            ex = {"clients": kids.get(nid, 0)}
            if x:
                ex.update(version=x.get("version", ""), uptime=x.get("uptime"), satisfaction=x.get("satisfaction"))
                if n["kind"] == "ap":
                    ex["radios"] = [{"band": RADIO_BAND.get(r.get("radio", ""), r.get("radio", "")), "channel": r.get("channel"),
                                     "clients": r.get("num_sta"), "power": r.get("tx_power"), "satisfaction": r.get("satisfaction")}
                                    for r in (x.get("radio_table_stats") or [])]
                    ex["ssids"] = sorted({v.get("essid") for v in (x.get("vap_table") or []) if v.get("essid")})
                if n["kind"] == "switch":
                    ports = x.get("port_table") or []
                    ex["ports_total"] = len(ports)
                    ex["ports_up"] = sum(1 for p in ports if p.get("up"))
                    ex["poe_watts"] = round(sum(float(p.get("poe_power") or 0) for p in ports), 1)
            n["extra"] = ex

        # ---- zones
        zone_names = sorted({n["zone"] for n in nodes.values() if n["zone"]})
        zones = []
        for i, name in enumerate(zone_names):
            custom = next((z for z in self.state.get("zones", []) if z["name"] == name), None)
            vlan = next((nn.get("vlan") for nn in nets if nn.get("name") == name), None)
            zones.append({"name": name, "color": (custom or {}).get("color") or ZONE_COLORS[i % len(ZONE_COLORS)], "vlan": vlan,
                          "count": sum(1 for n in nodes.values() if n["zone"] == name)})

        # ---- change log: record when a device's parent differs from the last time we looked
        now = time.time()
        with self.lock:
            last = self.state.setdefault("last_parent", {})
            lg = self.state.setdefault("log", [])
            changed = False
            for nid, n in nodes.items():
                if n.get("ghost"):
                    continue
                prev = last.get(nid)
                old = prev.get("p") if isinstance(prev, dict) else prev
                old_src = prev.get("s") if isinstance(prev, dict) else "inferred"
                # only real moves are news: both the old and new attachment must come from UniFi, not a guess or a manual edit
                if old is not None and old != n["parent"] and n["online"] and old_src == "unifi" and n["source"] == "unifi":
                    po = nodes.get(old, {}).get("name", "?")
                    pn = nodes.get(n["parent"], {}).get("name", "the gateway")
                    roam = nodes.get(old, {}).get("kind") == "ap" and nodes.get(n["parent"], {}).get("kind") == "ap"
                    lg.append({"t": now, "kind": "roamed" if roam else "moved", "id": nid, "name": n["name"],
                               "text": f"{n['name']} {'roamed' if roam else 'moved'} from {po} to {pn}"})
                    changed = True
                if old != n["parent"] or old_src != n["source"]:
                    last[nid] = {"p": n["parent"], "s": n["source"]}
                    changed = True
            if len(lg) > 200:
                del lg[:-200]
            if changed:
                self._save()
            log_out = list(lg[-60:])

        day = now - 86400
        changes = sorted(
            [{"t": n["first_seen"], "kind": "new", "id": n["id"], "name": n["name"], "text": f"{n['name']} joined the network"}
             for n in nodes.values() if n["first_seen"] > day and not n.get("ghost")] +
            [{"t": n["last_seen"], "kind": "gone", "id": n["id"], "name": n["name"], "text": f"{n['name']} went offline"}
             for n in nodes.values() if not n["online"] and n["last_seen"] > day and not n.get("ghost")] +
            [e for e in log_out if e["t"] > now - 7 * 86400],
            key=lambda e: -e["t"])[:80]

        return {"nodes": list(nodes.values()), "zones": zones, "changes": changes, "gateway": gateway,
                "sources": {"unifi": self.unifi_status, "manual": len(manual)},
                "custom_zones": self.state.get("zones", [])}


def demo_unifi(devices) -> dict:
    """Believable UniFi data for demo mode: one access point, one PoE switch, Wi-Fi and wired clients."""
    devs = list(devices)
    ap = next((d for d in devs if "u6" in (d.get("hostname", "") or "").lower() or d.get("type") == "ap"), None)
    sw_mac = "24:5A:4C:AA:BB:01"
    out_d = [{"mac": sw_mac, "type": "usw", "name": "Switch 8 PoE", "model": "USW-8-POE", "ip": "192.168.1.3", "version": "7.1.26",
              "uptime": 1209600, "uplink": {"uplink_mac": next((d["mac"] for d in devs if d.get("is_gateway")), ""), "uplink_remote_port": 5, "speed": 2500},
              "port_table": [{"port_idx": i, "up": i in (1, 2, 3, 4, 6, 7), "speed": 1000 if i != 8 else 2500,
                              "poe_power": "6.5" if i in (1, 2) else "0"} for i in range(1, 9)]}]
    if ap:
        out_d.append({"mac": ap["mac"], "type": "uap", "model": "U6-Lite", "version": "6.6.77", "uptime": 864000, "satisfaction": 96,
                      "uplink": {"uplink_mac": sw_mac, "uplink_remote_port": 1, "speed": 1000, "type": "wire"},
                      "radio_table_stats": [{"radio": "ng", "channel": 6, "num_sta": 5, "tx_power": 17, "satisfaction": 91},
                                            {"radio": "na", "channel": 44, "num_sta": 7, "tx_power": 20, "satisfaction": 97}],
                      "vap_table": [{"essid": "Home"}, {"essid": "Home-IoT"}]})
    clients, port, sig = [], 2, [-48, -57, -61, -66, -72, -54, -69, -78, -59, -64]
    wifi_types = {"phone", "tablet", "laptop", "tv", "speaker", "game", "iot", "camera"}
    for i, d in enumerate(devs):
        if d.get("is_gateway") or d["mac"] in (sw_mac, (ap or {}).get("mac")):
            continue
        if d.get("type") in wifi_types and ap:
            iot = d.get("type") in ("iot", "speaker", "camera")
            clients.append({"mac": d["mac"], "is_wired": False, "ap_mac": ap["mac"], "essid": "Home-IoT" if iot else "Home",
                            "radio": "ng" if iot or d.get("type") == "tv" else "na", "channel": 6 if iot else 44, "signal": sig[i % len(sig)],
                            "tx_rate": 866000 if not iot else 72000, "rx_rate": 780000 if not iot else 65000, "uptime": 3600 * (i + 2),
                            "network": "IoT" if iot else "LAN"})
        else:
            clients.append({"mac": d["mac"], "is_wired": True, "sw_mac": sw_mac, "sw_port": min(8, port), "network": "LAN"})
            port += 1
    return {"devices": out_d, "clients": clients, "networks": [{"name": "LAN", "vlan": 1, "ip_subnet": "192.168.1.1/24"},
            {"name": "IoT", "vlan": 20, "ip_subnet": "192.168.1.1/24"}]}
