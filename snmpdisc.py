"""Optional SNMP/LLDP discovery for routers and switches that are not UniFi.

LanPulse speaks just enough SNMPv2c (GET-BULK over UDP, read-only) to read a few tables:
  * LLDP-MIB remote table  - which device sits at the far end of which port
  * Q-BRIDGE / BRIDGE-MIB forwarding table - which MAC addresses were learned on which port
No extra Python package is needed.  Nothing is ever written to the device (there is no SET).
"""
from __future__ import annotations

import ipaddress
import logging
import random
import socket
import time

log = logging.getLogger("lanpulse.snmp")

# ---- OIDs
SYS_DESCR = "1.3.6.1.2.1.1.1"
SYS_NAME = "1.3.6.1.2.1.1.5"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"      # index: vlan.mac(6)
D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"          # index: mac(6)
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"   # bridge port -> ifIndex

MAX_ROWS = 6000


class SnmpError(Exception):
    pass


# ---------------------------------------------------------------- BER encoding
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(v: int) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return _tlv(0x02, v.to_bytes(n, "big", signed=True))


def _oid(s: str) -> bytes:
    p = [int(x) for x in s.split(".")]
    out = bytearray([p[0] * 40 + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def encode_getbulk(community: str, req_id: int, oid: str, max_rep: int = 20) -> bytes:
    vb = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(0xA5, _int(req_id) + _int(0) + _int(max_rep) + _tlv(0x30, vb))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode("utf-8")) + pdu)      # version 1 = SNMPv2c


# ---------------------------------------------------------------- BER decoding
def _read(buf: bytes, i: int):
    if i + 2 > len(buf):
        raise SnmpError("truncated")
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        k = ln & 0x7F
        if k == 0 or k > 4 or i + k > len(buf):
            raise SnmpError("bad length")
        ln = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + ln > len(buf):
        raise SnmpError("truncated")
    return tag, buf[i:i + ln], i + ln


def _dec_oid(b: bytes) -> str:
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _dec_value(tag: int, body: bytes):
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(body, "big")
    if tag == 0x04:
        return bytes(body)
    if tag == 0x06:
        return _dec_oid(body)
    if tag == 0x40 and len(body) == 4:
        return ".".join(str(x) for x in body)
    if tag in (0x80, 0x81, 0x82):
        return None                                  # noSuchObject / noSuchInstance / endOfMibView
    return None


def decode_response(data: bytes, req_id: int):
    """-> list of (oid, value) or None for end-of-MIB.  Raises SnmpError on anything unexpected."""
    tag, body, _ = _read(data, 0)
    if tag != 0x30:
        raise SnmpError("not an SNMP message")
    t, _v, i = _read(body, 0)
    t, _c, i = _read(body, i)
    t, pdu, i = _read(body, i)
    if t != 0xA2:
        raise SnmpError("not a response")
    t, rid, j = _read(pdu, 0)
    if int.from_bytes(rid, "big", signed=True) != req_id:
        raise SnmpError("stale reply")
    t, err, j = _read(pdu, j)
    if int.from_bytes(err, "big"):
        raise SnmpError(f"device returned SNMP error {int.from_bytes(err, 'big')}")
    t, _ei, j = _read(pdu, j)
    t, vbs, j = _read(pdu, j)
    out, k, end = [], 0, False
    while k < len(vbs):
        t, vb, k = _read(vbs, k)
        t, ob, m = _read(vb, 0)
        vt, vv, _ = _read(vb, m)
        if vt == 0x82:
            end = True
            continue
        out.append((_dec_oid(ob), _dec_value(vt, vv)))
    return out, end


# ---------------------------------------------------------------- client
class Client:
    def __init__(self, host: str, community: str, timeout: float = 2.0):
        self.host, self.community, self.timeout = host, community, timeout
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.port = 161

    def close(self):
        self.sock.close()

    def _ask(self, oid: str):
        rid = random.randint(1, 0x7FFFFFF)
        pkt = encode_getbulk(self.community, rid, oid)
        last = None
        for _ in range(2):                                         # one retry; UDP is lossy
            try:
                self.sock.sendto(pkt, (self.host, self.port))
                while True:
                    data, addr = self.sock.recvfrom(65535)
                    if addr[0] != self.host:
                        continue
                    try:
                        return decode_response(data, rid)
                    except SnmpError as e:
                        if str(e) == "stale reply":
                            continue
                        raise
            except socket.timeout:
                last = SnmpError("no answer (wrong address, SNMP off, or the community string is wrong)")
        raise last

    def walk(self, prefix: str, limit: int = MAX_ROWS):
        rows, cur = [], prefix
        pre = prefix + "."
        while len(rows) < limit:
            vbs, end = self._ask(cur)
            progressed = False
            for oid, val in vbs:
                if not oid.startswith(pre):
                    return rows
                rows.append((oid[len(pre):], val))
                cur = oid
                progressed = True
            if end or not progressed:
                break
        return rows

    def get(self, oid: str):
        for k, v in self.walk(oid, 1):
            return v
        return None


# ---------------------------------------------------------------- helpers
def _mac(b) -> str:
    return ":".join(f"{x:02x}" for x in b) if isinstance(b, (bytes, bytearray)) and len(b) == 6 else ""


def _txt(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace").replace("\x00", "").strip()[:120]
    return "" if v is None else str(v)[:120]


def valid_host(h: str) -> str:
    """A private/link-local unicast IP address, or ''.  SNMP is only ever sent to your own network."""
    try:
        ip = ipaddress.ip_address(str(h).strip())
    except ValueError:
        return ""
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return ""
    return str(ip) if (ip.is_private or ip.is_link_local) else ""


def poll_host(host: str, community: str, timeout: float = 2.0) -> dict:
    c = Client(host, community, timeout)
    try:
        out = {"ip": host, "name": _txt(c.get(SYS_NAME)), "descr": _txt(c.get(SYS_DESCR)), "lldp": [], "fdb": []}
        names = {}
        for idx, v in c.walk(IF_NAME):
            names[idx] = _txt(v)
        if not names:
            for idx, v in c.walk(IF_DESCR):
                names[idx] = _txt(v)
        locp = {idx: _txt(v) for idx, v in c.walk(LLDP_LOC_PORT_DESC)}
        chassis = {idx: v for idx, v in c.walk(LLDP_REM_CHASSIS)}
        sub = {idx: v for idx, v in c.walk(LLDP_REM_CHASSIS_SUBTYPE)}
        rport = {idx: _txt(v) for idx, v in c.walk(LLDP_REM_PORT)}
        rname = {idx: _txt(v) for idx, v in c.walk(LLDP_REM_SYSNAME)}
        for idx, ch in chassis.items():
            parts = idx.split(".")                                 # timeMark.localPort.remIndex
            lp = parts[1] if len(parts) >= 3 else ""
            out["lldp"].append({"local_port": locp.get(lp) or names.get(lp) or f"port {lp}",
                                "chassis_mac": _mac(ch) if sub.get(idx) in (4, None) else "",
                                "port_id": rport.get(idx, ""), "sys_name": rname.get(idx, "")})
        # bridge port -> interface name
        bp = {idx: names.get(str(v), f"port {idx}") for idx, v in c.walk(BASE_PORT_IFINDEX)}
        fdb = c.walk(Q_FDB_PORT)
        legacy = False
        if not fdb:
            fdb, legacy = c.walk(D_FDB_PORT), True
        for idx, port in fdb:
            p = idx.split(".")
            try:
                mac = _mac(bytes(int(x) for x in (p[-6:] if len(p) >= 6 else [])))
            except ValueError:
                continue
            if mac and isinstance(port, int) and port > 0:
                out["fdb"].append({"mac": mac, "port": bp.get(str(port)) or f"port {port}"})
        return out
    finally:
        c.close()


# IF-MIB high-capacity counters and interface metadata.
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
_VIRTUAL_IFACE = ("lo", "vmbr", "br-", "docker", "veth", "virbr", "vnet", "tap",
                  "tun", "wg", "vmk", "vswitch", "vSwitch", "bond", "team", "vlan")


def _interface_rates(rows: dict, previous: dict, elapsed: float) -> dict:
    """Calculate physical Ethernet interface rates from two IF-MIB counter samples."""
    if elapsed <= 0 or elapsed > 300:
        return {}
    selected = []
    for idx, cur in rows.items():
        name = str(cur.get("name") or "").strip()
        if not name or any(name.lower().startswith(x.lower()) for x in _VIRTUAL_IFACE):
            continue
        if cur.get("type") != 6 or cur.get("oper") != 1:
            continue
        old = previous.get(idx) or {}
        incoming, outgoing = cur.get("in"), cur.get("out")
        old_in, old_out = old.get("in"), old.get("out")
        if not all(isinstance(v, int) and v >= 0 for v in (incoming, outgoing, old_in, old_out)):
            continue
        if incoming < old_in or outgoing < old_out:
            continue
        rx, tx = (incoming - old_in) / elapsed, (outgoing - old_out) / elapsed
        selected.append({"name": name, "if_index": idx, "rx_bps": rx, "tx_bps": tx,
                         "speed_mbps": cur.get("speed") or None})
    if not selected:
        return {}
    return {"rx_bps": sum(x["rx_bps"] for x in selected),
            "tx_bps": sum(x["tx_bps"] for x in selected),
            "rate_bps": sum(x["rx_bps"] + x["tx_bps"] for x in selected),
            "interfaces": selected, "sampled": time.time()}


def poll_rate_counters(host: str, community: str, timeout: float = 2.0) -> dict:
    """Read only IF-MIB 64-bit counters; no SNMP SET operations are used."""
    c = Client(host, community, timeout)
    try:
        names = {idx: _txt(v) for idx, v in c.walk(IF_NAME)}
        if not names:
            names = {idx: _txt(v) for idx, v in c.walk(IF_DESCR)}
        types = dict(c.walk(IF_TYPE))
        ops = dict(c.walk(IF_OPER_STATUS))
        speeds = dict(c.walk(IF_HIGH_SPEED))
        incoming = dict(c.walk(IF_HC_IN_OCTETS))
        outgoing = dict(c.walk(IF_HC_OUT_OCTETS))
        rows = {}
        for idx, name in names.items():
            if name:
                rows[idx] = {"name": name, "type": types.get(idx), "oper": ops.get(idx),
                             "speed": speeds.get(idx), "in": incoming.get(idx), "out": outgoing.get(idx)}
        return rows
    finally:
        c.close()


class SnmpDiscovery:
    """Holds the latest poll results; the topology builder reads them."""
    def __init__(self):
        self.data: dict[str, dict] = {}
        self.status = {"configured": False, "ok": False, "error": "", "t": 0, "hosts": 0, "links": 0}
        self.rate_data: dict[str, dict] = {}
        self._rate_previous: dict[str, dict] = {}
        self._rate_sampled: dict[str, float] = {}
        self.rate_status = {"configured": False, "ok": False, "error": "", "t": 0, "hosts": 0}

    def refresh_rates(self, cfg: dict):
        """Poll configured SNMP hosts for physical-interface throughput. First poll establishes a baseline."""
        hosts = [h for h in (valid_host(x) for x in (cfg.get("hosts") or [])) if h][:20]
        if not cfg.get("enabled") or not hosts:
            self.rate_data = {}
            self._rate_previous = {}
            self._rate_sampled = {}
            self.rate_status = {"configured": False, "ok": False, "error": "", "t": time.time(), "hosts": 0}
            return
        community = str(cfg.get("community") or "public")
        now = time.time()
        data, errors = {}, []
        for host in hosts:
            try:
                rows = poll_rate_counters(host, community)
                previous, sampled = self._rate_previous.get(host), self._rate_sampled.get(host)
                if previous is not None and sampled is not None:
                    rates = _interface_rates(rows, previous, now - sampled)
                    if rates:
                        data[host] = rates
                self._rate_previous[host], self._rate_sampled[host] = rows, now
            except (SnmpError, OSError) as exc:
                errors.append(f"{host}: {exc}")
        self.rate_data = data
        self.rate_status = {"configured": True, "ok": bool(data), "error": "; ".join(errors)[:300],
                            "t": now, "hosts": len(data)}

    def refresh(self, cfg: dict):
        hosts = [h for h in (valid_host(x) for x in (cfg.get("hosts") or [])) if h][:20]
        if not cfg.get("enabled") or not hosts:
            self.data = {}
            self.status = {"configured": False, "ok": False, "error": "", "t": time.time(), "hosts": 0, "links": 0}
            return
        community = str(cfg.get("community") or "public")
        data, errs = {}, []
        for h in hosts:
            try:
                data[h] = poll_host(h, community)
            except (SnmpError, OSError) as e:
                errs.append(f"{h}: {e}")
        self.data = data
        links = sum(len(v["lldp"]) for v in data.values())
        self.status = {"configured": True, "ok": bool(data), "error": "; ".join(errs)[:300], "t": time.time(),
                       "hosts": len(data), "links": links}
