# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Smarter device identification from what devices announce about themselves.

  * DHCP     - hostname (option 12) and vendor class (option 60, e.g. "android-dhcp-14", "MSFT 5.0")
  * mDNS     - Bonjour services (_googlecast, _airplay, _ipp, _hap...) and TXT records with exact
               models ("model=MacBookPro18,3", "md=Chromecast", "ty=HP LaserJet") and friendly names
  * UPnP     - SSDP discovery, then the device description: friendlyName, manufacturer, modelName

Passive parts ride on LocalWatch's packet sniffer. Active mDNS and SSDP queries run every 10 minutes.
Results are stored per device in d["hints"] and used by classify() as strong evidence.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ET

log = logging.getLogger("lanpulse.discovery")

MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353
SSDP_ADDR, SSDP_PORT = "239.255.255.250", 1900
MDNS_SERVICES = ["_services._dns-sd._udp.local", "_device-info._tcp.local", "_googlecast._tcp.local",
                 "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local", "_ipp._tcp.local",
                 "_printer._tcp.local", "_hap._tcp.local", "_sonos._tcp.local", "_spotify-connect._tcp.local",
                 "_smb._tcp.local", "_workstation._tcp.local", "_amzn-wplay._tcp.local", "_androidtvremote2._tcp.local",
                 "_esphomelib._tcp.local", "_home-assistant._tcp.local", "_matter._tcp.local", "_rfb._tcp.local"]

SERVICE_NAMES = {
    "_googlecast": "Google Cast", "_airplay": "AirPlay", "_raop": "AirPlay audio", "_companion-link": "Apple device",
    "_ipp": "Printer (IPP)", "_ipps": "Printer (IPP)", "_printer": "Printer", "_pdl-datastream": "Printer",
    "_scanner": "Scanner", "_uscan": "Scanner", "_hap": "HomeKit", "_sonos": "Sonos", "_spotify-connect": "Spotify Connect",
    "_smb": "File sharing", "_afpovertcp": "File sharing (AFP)", "_workstation": "Linux workstation", "_ssh": "SSH",
    "_sftp-ssh": "SFTP", "_rfb": "Screen sharing", "_amzn-wplay": "Fire TV", "_androidtvremote2": "Android TV",
    "_nvstream": "NVIDIA GameStream", "_esphomelib": "ESPHome", "_home-assistant": "Home Assistant", "_matter": "Matter",
    "_matterc": "Matter", "_meshcop": "Thread border router", "_hue": "Philips Hue", "_elg": "Elgato",
    "_http": "Web page", "_https": "Web page", "_device-info": "Device info", "_airport": "AirPort",
    "_adisk": "Time Machine", "_rdlink": "Apple device", "_touch-able": "Apple TV remote", "_mediaremotetv": "Apple TV",
    "_daap": "iTunes sharing", "_plexmediasvr": "Plex", "_octoprint": "OctoPrint", "_wled": "WLED",
}


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# --------------------------------------------------------------------------- DHCP
def parse_dhcp(payload: bytes) -> dict | None:
    """Return {mac, hostname, vendor_class, requested_ip} from a BOOTP/DHCP client packet."""
    if len(payload) < 240 or payload[0] != 1 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    mac = ":".join(f"{b:02X}" for b in payload[28:34])
    out = {"mac": mac, "hostname": "", "vendor_class": "", "requested_ip": "", "params": ""}
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
        if code == 12:
            out["hostname"] = val.decode("utf-8", "replace").strip("\x00 ")[:64]
        elif code == 60:
            out["vendor_class"] = val.decode("utf-8", "replace").strip("\x00 ")[:80]
        elif code == 50 and ln == 4:
            out["requested_ip"] = socket.inet_ntoa(val)
        elif code == 55:
            out["params"] = ",".join(str(b) for b in val)
        i += 2 + ln
    return out


# --------------------------------------------------------------------------- mDNS (minimal DNS parser)
def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while off < len(data) and depth < 20:
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def parse_mdns(data: bytes) -> list[dict]:
    """Return resource records [{name, type, value}] from an mDNS packet (answers + additionals)."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    off = 12
    try:
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        records = []
        for _ in range(an + ns + ar):
            name, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            if rtype == 12:                                   # PTR
                val, _ = _read_name(data, off)
            elif rtype == 16:                                 # TXT
                val, j = [], 0
                while j < len(rdata):
                    ln = rdata[j]
                    val.append(rdata[j + 1:j + 1 + ln].decode("utf-8", "replace"))
                    j += 1 + ln
            elif rtype == 1 and rdlen == 4:                   # A
                val = socket.inet_ntoa(rdata)
            elif rtype == 33:                                 # SRV
                val, _ = _read_name(data, off + 6)
            else:
                val = None
            if val is not None:
                records.append({"name": name, "type": rtype, "value": val})
            off += rdlen
        return records
    except Exception:
        return []


def mdns_query_packet(names: list[str]) -> bytes:
    pkt = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    for n in names:
        for label in n.split("."):
            b = label.encode()
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack("!HH", 12, 0x8001)       # PTR, QU (ask for unicast reply)
    return pkt


def service_of(name: str) -> str:
    """'Living Room._googlecast._tcp.local' -> '_googlecast'"""
    m = re.search(r"(_[a-z0-9-]+)\._(?:tcp|udp)\.local", name.lower())
    return m.group(1) if m else ""


def instance_of(name: str) -> str:
    m = re.match(r"(.+?)\._[a-z0-9-]+\._(?:tcp|udp)\.local", name, re.I)
    return m.group(1).replace("\\032", " ").replace("\\.", ".") if m else ""


def txt_dict(items) -> dict:
    out = {}
    for it in items if isinstance(items, list) else []:
        k, _, v = it.partition("=")
        if k and k.lower() not in out:
            out[k.lower()] = v
    return out


# --------------------------------------------------------------------------- UPnP
def parse_upnp_xml(text: str) -> dict:
    root = ET.fromstring(text)
    dev = None
    for el in root.iter():
        if el.tag.endswith("device"):
            dev = el
            break
    if dev is None:
        return {}
    get = lambda tag: next((c.text or "" for c in dev if c.tag.endswith(tag)), "").strip()[:100]
    return {"friendly": get("friendlyName"), "manufacturer": get("manufacturer"), "model": get("modelName"),
            "model_number": get("modelNumber"), "device_type": get("deviceType").split(":")[-2] if get("deviceType").count(":") >= 2 else get("deviceType")}


# --------------------------------------------------------------------------- the engine
class Discovery:
    def __init__(self, nm):
        self.nm = nm
        self.pending: dict[str, list] = {}            # MAC -> hints seen before ARP found the device
        self.loop: asyncio.AbstractEventLoop | None = None

    def device_for(self, ip: str = "", mac: str = "") -> dict | None:
        mac = (mac or "").upper()
        if mac and mac in self.nm.devices:
            return self.nm.devices[mac]
        return next((d for d in self.nm.devices.values() if ip and d["ip"] == ip), None)

    def adopt(self, d: dict):
        for section, data, evidence in self.pending.pop(d.get("mac", ""), []):
            self._update(d, section, data, evidence)

    def _update(self, d: dict | None, section: str, data: dict, evidence: str, mac: str = ""):
        if not d:
            if mac and mac != "00:00:00:00:00:00":
                q = self.pending.setdefault(mac.upper(), [])
                q.append((section, data, evidence))
                del q[:-5]
                if len(self.pending) > 500:
                    self.pending.pop(next(iter(self.pending)))
            return
        hints = d.setdefault("hints", {})
        cur = hints.setdefault(section, {})
        changed = False
        for k, v in data.items():
            if v in (None, "", [], {}):
                continue
            if isinstance(v, list):
                merged = sorted(set(cur.get(k, [])) | set(v))
                if merged != cur.get(k):
                    cur[k], changed = merged, True
            elif cur.get(k) != v:
                cur[k], changed = v, True
        if changed:
            ev = d.setdefault("evidence", [])
            if evidence and evidence not in ev:
                ev.append(evidence)
                d["evidence"] = ev[-12:]
            self.nm.apply_hints(d)

    # ---- passive (called from the sniffer thread via call_soon_threadsafe)
    def on_dhcp(self, info: dict, src_ip: str):
        d = self.device_for(info.get("requested_ip") or src_ip, info["mac"])
        bits = [x for x in (info.get("vendor_class"), info.get("hostname")) if x]
        self._update(d, "dhcp", {"hostname": info.get("hostname"), "vendor_class": info.get("vendor_class"),
                                 "params": info.get("params")}, "DHCP: " + " · ".join(bits) if bits else "", mac=info["mac"])

    def on_mdns(self, data: bytes, src_ip: str):
        if not _private(src_ip):
            return
        recs = parse_mdns(data)
        if not recs:
            return
        d = self.device_for(src_ip)
        services, names, txt, model = set(), set(), {}, ""
        for r in recs:
            svc = service_of(r["name"]) or (service_of(r["value"]) if isinstance(r["value"], str) else "")
            if r["type"] == 12 and isinstance(r["value"], str):
                if svc:
                    services.add(svc)
                inst = instance_of(r["value"])
                if inst and svc not in ("_device-info",):
                    names.add(inst)
            elif r["type"] == 16:
                t = txt_dict(r["value"])
                if service_of(r["name"]):
                    services.add(service_of(r["name"]))
                txt.update({k: v for k, v in t.items() if k in ("model", "md", "ty", "fn", "am", "manufacturer", "product", "usb_mdl", "mn", "rpmd")})
                inst = instance_of(r["name"])
                if inst:
                    names.add(inst)
        model = txt.get("model") or txt.get("md") or txt.get("ty") or txt.get("am") or txt.get("rpmd") or txt.get("usb_mdl") or ""
        friendly = txt.get("fn") or next(iter(sorted(names, key=len)), "")
        if not (services or model or friendly):
            return
        label = ", ".join(SERVICE_NAMES.get(s, s.strip("_")) for s in sorted(services)[:4])
        self._update(d, "mdns", {"services": sorted(services), "model": model[:80], "friendly": friendly[:64],
                                 "names": sorted(names)[:6]},
                     f"mDNS: {model or label}" + (f" · {friendly}" if friendly and friendly != model else ""))

    # ---- active
    async def run(self):
        self.loop = asyncio.get_running_loop()
        await asyncio.sleep(20)
        while True:
            try:
                await asyncio.to_thread(self.mdns_probe)
                results = await asyncio.to_thread(self.ssdp_probe)
                for ip, info in results.items():
                    d = self.device_for(ip)
                    bits = [x for x in (info.get("manufacturer"), info.get("model")) if x]
                    self._update(d, "upnp", info, "UPnP: " + " ".join(bits) + (f" · {info['friendly']}" if info.get("friendly") else ""))
            except Exception:
                log.exception("Discovery round failed")
            await asyncio.sleep(600)

    def mdns_probe(self):
        """Ask everyone what they offer. Replies are multicast and caught by the sniffer."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.nm.net["my_ip"]))
            except OSError:
                pass
            for i in range(0, len(MDNS_SERVICES), 6):
                s.sendto(mdns_query_packet(MDNS_SERVICES[i:i + 6]), (MDNS_ADDR, MDNS_PORT))
                time.sleep(0.2)
            # Unicast replies (QU bit) come back to this socket, so read them here too.
            s.settimeout(0.6)
            end = time.time() + 3
            while time.time() < end:
                try:
                    data, addr = s.recvfrom(9000)
                except socket.timeout:
                    continue
                if self.loop:
                    self.loop.call_soon_threadsafe(self.on_mdns, data, addr[0])
            s.close()
        except OSError as e:
            log.debug("mDNS probe failed: %s", e)

    def ssdp_probe(self) -> dict:
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").encode()
        locations: dict[str, str] = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.5)
            s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
            end = time.time() + 4
            while time.time() < end:
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    continue
                m = re.search(rb"(?im)^location:\s*(\S+)", data)
                if m and _private(addr[0]) and addr[0] not in locations:
                    locations[addr[0]] = m.group(1).decode("utf-8", "replace")
            s.close()
        except OSError as e:
            log.debug("SSDP probe failed: %s", e)
        out = {}
        for ip, url in locations.items():
            try:
                host = re.match(r"https?://([^:/]+)", url)
                if not host or host.group(1) != ip:          # only fetch from the device that answered
                    continue
                with _NO_REDIRECTS.open(urllib.request.Request(url, headers={"User-Agent": "LanPulse"}), timeout=3) as r:
                    text = r.read(65536).decode("utf-8", "replace")
                info = parse_upnp_xml(text)
                if info:
                    out[ip] = info
            except Exception:
                continue
        return out


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None                     # a device's description must come from that device, not wherever it points


_NO_REDIRECTS = urllib.request.build_opener(_RefuseRedirect)


# --------------------------------------------------------------------------- hint-based classification
def classify_from_hints(d: dict) -> str | None:
    h = d.get("hints") or {}
    md = h.get("mdns", {})
    up = h.get("upnp", {})
    dh = h.get("dhcp", {})
    svcs = set(md.get("services", []))
    model = (md.get("model", "") + " " + up.get("model", "") + " " + up.get("manufacturer", "") + " "
             + up.get("friendly", "") + " " + md.get("friendly", "")).lower()
    dtype = up.get("device_type", "").lower()
    vc = dh.get("vendor_class", "").lower()

    apple = re.search(r"\b(iphone|ipad|ipod|macbook|imac|macmini|macpro|mac\d|appletv|audioaccessory|homepod)", model)
    if apple:
        w = apple.group(1)
        return {"iphone": "phone", "ipod": "phone", "ipad": "tablet", "macbook": "laptop", "imac": "desktop",
                "macmini": "desktop", "macpro": "desktop", "mac": "laptop", "appletv": "tv",
                "audioaccessory": "speaker", "homepod": "speaker"}.get(re.sub(r"\d", "", w), "laptop")
    if svcs & {"_ipp", "_ipps", "_printer", "_pdl-datastream", "_uscan", "_scanner"} or "printer" in dtype:
        return "printer"
    if svcs & {"_sonos"} or "sonos" in model:
        return "speaker"
    if "_googlecast" in svcs:
        return "speaker" if re.search(r"google home|nest (audio|mini)|home mini|speaker", model) else "tv"
    if svcs & {"_amzn-wplay", "_androidtvremote2", "_nvstream", "_mediaremotetv", "_touch-able"}:
        return "tv"
    if re.search(r"xbox|playstation|nintendo", model):
        return "game"
    if re.search(r"windows media player|microsoft corporation windows|windows media", model) or vc.startswith("msft"):
        return "desktop"
    if re.search(r"\b(tv|bravia|roku|webos|tizen|vizio|shield|fire ?tv|chromecast|hdhomerun)\b", model) or "mediarenderer" in dtype:
        return "tv" if "speaker" not in model else "speaker"
    if re.search(r"synology|diskstation|qnap|truenas|readynas|unraid|my cloud", model):
        return "nas"
    if "internetgatewaydevice" in dtype or "wandevice" in dtype:
        return None                       # leave routers to the gateway logic
    if svcs & {"_hap", "_matter", "_matterc", "_esphomelib", "_hue", "_wled", "_meshcop"}:
        return "iot"
    if "_home-assistant" in svcs or "_octoprint" in svcs:
        return "server"
    if "_raop" in svcs and not svcs & {"_companion-link", "_rdlink"}:
        return "speaker"
    if vc.startswith("android-dhcp"):
        return "phone"
    if vc.startswith("msft"):
        return "desktop"
    return None
