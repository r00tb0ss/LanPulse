#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Passive runtime telemetry forwarder for an isolated malware-analysis VM.

This agent observes outbound DNS, TCP/UDP connection attempts, TLS SNI and HTTP
Host headers. It does not execute samples, modify traffic, save packet captures,
or collect request bodies, credentials, or arbitrary payloads.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import logging
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SENSOR_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
RUN_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HTTP_METHOD = re.compile(rb"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s", re.I)
HOST_HEADER = re.compile(rb"(?im)^Host:\s*([^\r\n]+)")


def normalize_hostname(value) -> str:
    """Return a validated DNS hostname, stripping an optional HTTP port."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    host = str(value or "").strip().rstrip(".").lower()
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    if not host or len(host) > 253:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    labels = host.split(".")
    if not labels or any(not HOST_LABEL.fullmatch(label) for label in labels):
        return ""
    return host


def parse_http_host(payload: bytes) -> str:
    """Read only the Host header from an HTTP request header block."""
    if not payload:
        return ""
    header = bytes(payload[:8192]).split(b"\r\n\r\n", 1)[0]
    if not HTTP_METHOD.match(header):
        return ""
    match = HOST_HEADER.search(header)
    return normalize_hostname(match.group(1)) if match else ""


def parse_tls_sni(payload: bytes) -> str:
    """Extract the server_name from a complete TLS ClientHello record, if present."""
    data = bytes(payload or b"")
    if len(data) < 9 or data[0] != 22:  # handshake record
        return ""
    record_len = int.from_bytes(data[3:5], "big")
    if record_len > len(data) - 5:
        return ""
    record = data[5:5 + record_len]
    if len(record) < 4 or record[0] != 1:  # ClientHello
        return ""
    hello_len = int.from_bytes(record[1:4], "big")
    body = record[4:4 + hello_len]
    pos = 2 + 32  # legacy_version + random
    if len(body) <= pos:
        return ""
    session_len = body[pos]
    pos += 1 + session_len
    if len(body) < pos + 2:
        return ""
    cipher_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2 + cipher_len
    if len(body) <= pos:
        return ""
    compression_len = body[pos]
    pos += 1 + compression_len
    if len(body) < pos + 2:
        return ""
    extensions_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    end = min(len(body), pos + extensions_len)
    while pos + 4 <= end:
        ext_type = int.from_bytes(body[pos:pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
        pos += 4
        ext_end = pos + ext_len
        if ext_end > end:
            return ""
        if ext_type == 0:  # server_name
            ext = body[pos:ext_end]
            if len(ext) < 5:
                return ""
            names_len = int.from_bytes(ext[:2], "big")
            npos = 2
            nend = min(len(ext), 2 + names_len)
            while npos + 3 <= nend:
                name_type = ext[npos]
                name_len = int.from_bytes(ext[npos + 1:npos + 3], "big")
                npos += 3
                if npos + name_len > nend:
                    return ""
                if name_type == 0:
                    return normalize_hostname(ext[npos:npos + name_len])
                npos += name_len
            return ""
        pos = ext_end
    return ""


def validate_server_url(value: str, allow_http: bool = False) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if parsed.scheme not in (("https", "http") if allow_http else ("https",)):
        raise ValueError("Use an HTTPS LanPulse URL. HTTP requires the explicit --allow-http option.")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Server URL must contain only a scheme, host, optional port, and optional trailing slash.")
    if parsed.path not in ("", "/"):
        raise ValueError("Provide the LanPulse base URL without an extra path.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Server URL contains an invalid port.") from exc
    return value.strip().rstrip("/")


def read_token_file(path: str) -> str:
    """Read a token from a regular file that is not accessible to group/other users."""
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Token path must be a regular file.")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Token file permissions are too open; run chmod 600 on the file.")
    token = open(path, "r", encoding="utf-8").read().strip()
    if not token or len(token) > 200 or any(ord(ch) < 33 or ord(ch) > 126 for ch in token):
        raise ValueError("Token file is empty or contains an invalid token.")
    return token


class RuntimeSensor:
    def __init__(self, server_url, sensor_id, token, sample_sha256, run_id,
                 interface=None, ca_cert=None, batch_size=50, flush_interval=5, timeout=8):
        self.server_url = validate_server_url(server_url, allow_http=server_url.startswith("http://"))
        if not SENSOR_ID.fullmatch(str(sensor_id or "")):
            raise ValueError("Sensor ID may contain only letters, numbers, dots, underscores, and hyphens.")
        self.sensor_id = sensor_id
        self.token = token
        self.sample_sha256 = str(sample_sha256 or "").lower()
        if not HEX64.fullmatch(self.sample_sha256):
            raise ValueError("A valid sample SHA-256 is required.")
        if not RUN_ID.fullmatch(str(run_id or "")):
            raise ValueError("Run ID may contain only letters, numbers, dots, underscores, colons, and hyphens.")
        self.run_id = run_id
        self.interface = interface
        self.batch_size = max(1, min(int(batch_size), 100))
        self.flush_interval = max(1, min(int(flush_interval), 60))
        self.timeout = max(2, min(int(timeout), 30))
        self.ssl_context = ssl.create_default_context(cafile=ca_cert) if self.server_url.startswith("https://") else None
        self.local_addresses = set()
        self.events = collections.deque(maxlen=10000)
        self.recent = {}
        self.last_flush = time.monotonic()

    def _event(self, kind, timestamp, hostname="", destination_ip="", port=None, protocol=""):
        event = {
            "sample_sha256": self.sample_sha256, "run_id": self.run_id,
            "timestamp": float(timestamp), "type": kind,
            "hostname": hostname, "destination_ip": destination_ip,
            "port": port, "protocol": protocol
        }
        key = (kind, hostname, destination_ip, port, protocol)
        now = time.monotonic()
        if now - self.recent.get(key, 0) < 2:
            return
        self.recent[key] = now
        if len(self.recent) > 4096:
            self.recent = {k: t for k, t in self.recent.items() if now - t < 10}
        if len(self.events) == self.events.maxlen:
            logging.warning("Telemetry queue full; dropping the oldest buffered event.")
        self.events.append(event)

    def handle_packet(self, packet):
        """Convert a captured outbound packet into metadata-only events."""
        try:
            if packet.haslayer("IP"):
                net = packet["IP"]
            elif packet.haslayer("IPv6"):
                net = packet["IPv6"]
            else:
                return
            source, destination = str(net.src), str(net.dst)
            if source not in self.local_addresses:
                return
            stamp = float(getattr(packet, "time", time.time()))

            if packet.haslayer("DNS") and packet.haslayer("DNSQR"):
                dns = packet["DNS"]
                if int(dns.qr or 0) == 0:
                    name = normalize_hostname(packet["DNSQR"].qname)
                    if name:
                        proto = "tcp" if packet.haslayer("TCP") else "udp" if packet.haslayer("UDP") else ""
                        port = int(packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport) if proto else None
                        self._event("dns_query", stamp, hostname=name, destination_ip=destination,
                                    port=port, protocol=proto)

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                port = int(tcp.dport)
                flags = int(tcp.flags)
                if flags & 0x02 and not flags & 0x10:  # outbound SYN, not SYN/ACK
                    self._event("connect", stamp, destination_ip=destination, port=port, protocol="tcp")
                payload = bytes(tcp.payload)
                if payload:
                    sni = parse_tls_sni(payload)
                    if sni:
                        self._event("tls_sni", stamp, hostname=sni, destination_ip=destination,
                                    port=port, protocol="tcp")
                    host = parse_http_host(payload)
                    if host:
                        self._event("http_host", stamp, hostname=host, destination_ip=destination,
                                    port=port, protocol="tcp")
            elif packet.haslayer("UDP"):
                udp = packet["UDP"]
                port = int(udp.dport)
                if port != 53:
                    self._event("connect", stamp, destination_ip=destination, port=port, protocol="udp")
        except Exception:
            logging.debug("Skipped an unreadable packet.", exc_info=True)

    def flush(self):
        if not self.events:
            return True
        batch = list(self.events)[:self.batch_size]
        request = urllib.request.Request(
            self.server_url + "/api/runtime/ingest",
            data=json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-LanPulse-Sensor": self.sensor_id,
                "X-LanPulse-Token": self.token,
                "User-Agent": "LanPulse-runtime-sensor/1.0"
            })
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                result = json.loads(response.read(65536).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", "replace")
            if exc.code == 429 or exc.code >= 500:
                logging.warning("LanPulse temporarily refused telemetry (HTTP %s); will retry.", exc.code)
                return False
            raise RuntimeError(f"LanPulse rejected telemetry (HTTP {exc.code}): {detail[:300]}") from exc
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            logging.warning("Could not reach LanPulse; telemetry remains queued: %s", exc)
            return False
        if not isinstance(result, dict) or result.get("ok") is not True:
            logging.warning("LanPulse returned an unexpected response; telemetry remains queued.")
            return False
        for _ in batch:
            if self.events:
                self.events.popleft()
        logging.info("Sent %d telemetry events (%d accepted, %d duplicates).",
                     len(batch), int(result.get("accepted", 0)), int(result.get("duplicates", 0)))
        return True

    def capture(self):
        try:
            from scapy.all import conf, get_if_addr, get_if_addr6, sniff
        except ImportError as exc:
            raise RuntimeError("Scapy is required. Install the LanPulse requirements in this isolated VM.") from exc
        iface = self.interface or conf.iface
        try:
            ipv4 = get_if_addr(iface)
            if ipv4 and ipv4 != "0.0.0.0":
                self.local_addresses.add(ipv4)
        except Exception:
            pass
        try:
            ipv6 = get_if_addr6(iface)
            if ipv6:
                self.local_addresses.add(str(ipv6).split("%", 1)[0])
        except Exception:
            pass
        if not self.local_addresses:
            raise RuntimeError(f"Could not determine an IP address for interface {iface!r}.")
        logging.info("Monitoring outbound metadata on %s for sample %s (run %s).",
                     iface, self.sample_sha256, self.run_id)
        logging.info("No packet captures or payloads are saved. Press Ctrl+C to stop.")
        while True:
            sniff(iface=iface, filter="ip or ip6", prn=self.handle_packet, store=False, timeout=1)
            now = time.monotonic()
            if self.events and (len(self.events) >= self.batch_size or now - self.last_flush >= self.flush_interval):
                self.flush()
                self.last_flush = now


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-url", required=True, help="LanPulse base URL, e.g. https://192.0.2.10:8080")
    parser.add_argument("--sensor-id", required=True, help="ID created under Honeypot > C2 Intelligence")
    parser.add_argument("--token-file", required=True, help="file containing the one-time sensor token (chmod 600)")
    parser.add_argument("--sample-sha256", required=True, help="SHA-256 of a sample already stored in LanPulse")
    parser.add_argument("--run-id", required=True, help="unique identifier for this isolated sample run")
    parser.add_argument("--interface", help="sandbox network interface (default: Scapy's default interface)")
    parser.add_argument("--ca-cert", help="CA/certificate PEM used to validate a self-signed LanPulse HTTPS certificate")
    parser.add_argument("--allow-http", action="store_true", help="allow unencrypted HTTP only on a trusted isolated management network")
    parser.add_argument("--batch-size", type=int, default=50, help="events per request, 1–100 (default: 50)")
    parser.add_argument("--flush-interval", type=int, default=5, help="seconds between batch flushes (default: 5)")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds (default: 8)")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    args = parser.parse_args(argv)
    args.server_url = validate_server_url(args.server_url, allow_http=args.allow_http)
    return args


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        token = read_token_file(args.token_file)
        if args.server_url.startswith("http://") and not args.allow_http:
            raise ValueError("HTTP requires --allow-http.")
        sensor = RuntimeSensor(args.server_url, args.sensor_id, token, args.sample_sha256,
                               args.run_id, args.interface, args.ca_cert, args.batch_size,
                               args.flush_interval, args.timeout)
        try:
            sensor.capture()
        except KeyboardInterrupt:
            logging.info("Stopping capture; flushing buffered telemetry.")
            sensor.flush()
            if sensor.events:
                logging.warning("%d events remain queued and were not sent.", len(sensor.events))
    except (OSError, ValueError, RuntimeError) as exc:
        logging.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
