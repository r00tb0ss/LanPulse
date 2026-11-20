# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Unit tests for the passive isolated-sandbox runtime telemetry forwarder."""
import os
import pathlib
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import runtime_sensor as rs


def client_hello(hostname):
    name = hostname.encode("ascii")
    server_name = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" +
            len(extension).to_bytes(2, "big") + extension)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class HostParsing(unittest.TestCase):
    def test_normalizes_dns_names_and_ports(self):
        self.assertEqual(rs.normalize_hostname(b"C2.Example.NET."), "c2.example.net")
        self.assertEqual(rs.normalize_hostname("c2.example.net:8443"), "c2.example.net")
        self.assertEqual(rs.normalize_hostname("[2001:db8::1]:443"), "")

    def test_rejects_invalid_hostnames_and_ip_literals(self):
        for value in ("", "bad host", "-bad.example", "bad..example", "127.0.0.1", "a" * 254):
            with self.subTest(value=value):
                self.assertEqual(rs.normalize_hostname(value), "")

    def test_reads_only_http_host_header(self):
        request = (b"GET /path HTTP/1.1\r\nHost: C2.Example.NET:8080\r\n"
                   b"User-Agent: test\r\n\r\nignored-body")
        self.assertEqual(rs.parse_http_host(request), "c2.example.net")
        self.assertEqual(rs.parse_http_host(b"HTTP/1.1 200 OK\r\nHost: server.example\r\n"), "")
        self.assertEqual(rs.parse_http_host(b"GET / HTTP/1.1\r\nHost: bad host\r\n"), "")

    def test_extracts_tls_client_hello_sni(self):
        self.assertEqual(rs.parse_tls_sni(client_hello("c2.example.net")), "c2.example.net")

    def test_malformed_or_non_handshake_tls_is_ignored(self):
        self.assertEqual(rs.parse_tls_sni(b"\x16\x03\x01\x00\x20short"), "")
        self.assertEqual(rs.parse_tls_sni(b"\x17\x03\x03\x00\x04data"), "")


class SensorConfiguration(unittest.TestCase):
    def test_https_is_required_unless_http_is_explicitly_allowed(self):
        self.assertEqual(rs.validate_server_url("https://lanpulse.example/"), "https://lanpulse.example")
        with self.assertRaises(ValueError):
            rs.validate_server_url("http://lanpulse.example")
        self.assertEqual(rs.validate_server_url("http://192.0.2.10:8080", allow_http=True),
                         "http://192.0.2.10:8080")

    def test_rejects_ambiguous_or_unsafe_server_urls(self):
        for value in ("https://user:pass@example.com", "https://example.com/path",
                      "https://example.com/?token=secret", "https://example.com/#fragment",
                      "ftp://example.com", "https:///missing-host"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rs.validate_server_url(value, allow_http=True)

    def test_token_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "token"
            path.write_text("test-token\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(path, 0o644)
                with self.assertRaisesRegex(ValueError, "permissions"):
                    rs.read_token_file(str(path))
                os.chmod(path, 0o600)
            self.assertEqual(rs.read_token_file(str(path)), "test-token")

    def test_sensor_requires_valid_credentials_and_sample(self):
        with self.assertRaises(ValueError):
            rs.RuntimeSensor("https://lanpulse.example", "bad sensor", "token", "a" * 64, "run-1")
        with self.assertRaises(ValueError):
            rs.RuntimeSensor("https://lanpulse.example", "lab-01", "", "a" * 64, "run-1")
        with self.assertRaises(ValueError):
            rs.RuntimeSensor("https://lanpulse.example", "lab-01", "token", "not-a-hash", "run-1")
        with self.assertRaises(ValueError):
            rs.RuntimeSensor("http://lanpulse.example", "lab-01", "token", "a" * 64, "run-1")
        sensor = rs.RuntimeSensor("http://192.0.2.10:8080", "lab-01", "token",
                                  "a" * 64, "run-1", allow_http=True)
        self.assertEqual(sensor.sensor_id, "lab-01")

    def test_event_buffer_deduplicates_repeated_packet_metadata(self):
        sensor = rs.RuntimeSensor("https://lanpulse.example", "lab-01", "token",
                                  "a" * 64, "run-1")
        now = time.time()
        sensor._event("connect", now, destination_ip="203.0.113.20", port=443, protocol="tcp")
        sensor._event("connect", now, destination_ip="203.0.113.20", port=443, protocol="tcp")
        self.assertEqual(len(sensor.events), 1)
        self.assertEqual(sensor.events[0]["sample_sha256"], "a" * 64)
        self.assertEqual(sensor.events[0]["run_id"], "run-1")

    def test_dns_answer_correlates_query_name_with_resolved_ip(self):
        from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

        sensor = rs.RuntimeSensor("https://lanpulse.example", "lab-01", "token",
                                  "a" * 64, "run-1")
        sensor.local_addresses.add("192.0.2.50")
        query = (IP(src="192.0.2.50", dst="192.0.2.1") /
                 UDP(sport=53000, dport=53) /
                 DNS(id=7, qr=0, qd=DNSQR(qname="C2.Example.NET.")))
        response = (IP(src="192.0.2.1", dst="192.0.2.50") /
                    UDP(sport=53, dport=53000) /
                    DNS(id=7, qr=1, qd=DNSQR(qname="C2.Example.NET."),
                        an=DNSRR(rrname="C2.Example.NET.", type="A", rdata="203.0.113.77"),
                        ancount=1))
        sensor.handle_packet(query)
        sensor.handle_packet(response)
        rows = list(sensor.events)
        self.assertEqual([row["type"] for row in rows], ["dns_query", "dns_answer"])
        self.assertEqual(rows[1]["hostname"], "c2.example.net")
        self.assertEqual(rows[1]["destination_ip"], "203.0.113.77")
        self.assertEqual(rows[1]["port"], 53)

    def test_dns_answer_records_ipv4_and_ipv6_and_ignores_unrelated_packets(self):
        from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

        sensor = rs.RuntimeSensor("https://lanpulse.example", "lab-01", "token",
                                  "a" * 64, "run-1")
        sensor.local_addresses.add("192.0.2.50")
        response = (IP(src="192.0.2.1", dst="192.0.2.50") /
                    UDP(sport=53, dport=53000) /
                    DNS(id=8, qr=1, qd=DNSQR(qname="dual.example.net"),
                        an=DNSRR(rrname="dual.example.net", type="A", rdata="203.0.113.88") /
                           DNSRR(rrname="dual.example.net", type="AAAA", rdata="2001:db8::88"),
                        ancount=2))
        unrelated = IP(src="198.51.100.4", dst="192.0.2.50") / UDP(sport=9999, dport=9999)
        sensor.handle_packet(unrelated)
        sensor.handle_packet(response)
        rows = list(sensor.events)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["destination_ip"] for row in rows},
                         {"203.0.113.88", "2001:db8::88"})
        self.assertTrue(all(row["type"] == "dns_answer" for row in rows))


if __name__ == "__main__":
    unittest.main()
