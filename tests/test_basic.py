# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Small checks for logic that has broken before. Run: python -m unittest discover -s tests -v"""
import os
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import honeypot  # noqa: E402
import openvas  # noqa: E402
import signatures  # noqa: E402
import releases  # noqa: E402
import snmpdisc  # noqa: E402
import topology  # noqa: E402


class Signatures(unittest.TestCase):
    def test_msf_by_cve(self):
        self.assertEqual(signatures.msf_for_cve("CVE-2004-2687")[0][0], "exploit/unix/misc/distcc_exec")
        self.assertEqual(signatures.msf_for_cve("cve-2020-1938")[0][0], "auxiliary/admin/http/tomcat_ghostcat")
        self.assertEqual(signatures.msf_for_cve(""), [])
        self.assertEqual(signatures.msf_for_cve("CVE-1-1"), [])


class OpenVASResults(unittest.TestCase):
    @staticmethod
    def _xml(*hosts):
        return ET.fromstring("<r>" + "".join(
            f'<result><name>n{i}</name><host>{h}</host><severity>9</severity><qod><value>99</value></qod>'
            f'<port>80/tcp</port><nvt oid="1.{i}"/></result>' for i, h in enumerate(hosts)) + "</r>")

    def test_foreign_hosts_dropped(self):
        root = self._xml("192.168.0.11", "192.168.0.198", "")
        self.assertEqual([i["name"] for i in openvas.parse_results(root, "192.168.0.198")], ["n1", "n2"])
        self.assertEqual(len(openvas.parse_results(root)), 3)


class HoneypotParsing(unittest.TestCase):
    def test_telnet_negotiation_stripped(self):
        self.assertEqual(honeypot._printable(b"\xff\xfb\x1f\xff\xfd\x01root"), "root")

    def test_describe(self):
        d = honeypot.Honeypot._describe
        self.assertIn("Administrator", d("rdp", b"\x03\x00\x00\x2bCookie: mstshash=Administrator\r\n"))
        self.assertIn("SMBv1", d("smb", b"\x00\x00\x00\x2f\xffSMB\x72" + b"\x00" * 28 + b"\x02NT LM 0.12\x00"))
        self.assertEqual(d("smb", b""), "")


class ReleaseSources(unittest.TestCase):
    def test_gitlab_release_is_parsed(self):
        d = releases._parse("gitlab", {"tag_name": "v1.26.0", "name": "LanPulse 1.26.0", "description": "notes",
                                       "released_at": "2026-11-08T00:00:00Z", "_links": {"self": "https://gitlab.com/x/-/releases/v1.26.0"},
                                       "assets": {"links": [{"name": "lanpulse.zip", "url": "https://gitlab.com/-/project/1/uploads/abc/lanpulse.zip",
                                                             "direct_asset_url": "https://gitlab.com/-/project/1/uploads/abc/lanpulse.zip"}]}})
        self.assertEqual((d["version"], d["asset_url"]), ("1.26.0", "https://gitlab.com/-/project/1/uploads/abc/lanpulse.zip"))

    def test_github_release_is_parsed(self):
        d = releases._parse("github", {"tag_name": "v1.25.36", "body": "n", "html_url": "u", "published_at": "p",
                                       "assets": [{"name": "lanpulse.zip", "browser_download_url": "https://github.com/a/b.zip", "size": 5}]})
        self.assertEqual((d["version"], d["asset_url"], d["size"]), ("1.25.36", "https://github.com/a/b.zip", 5))

    def test_newest_source_wins_and_failures_fall_back(self):
        calls = []

        def fake_open(url, timeout):
            import io
            import json
            calls.append(url)
            if "gitlab" in url:
                raise OSError("offline")
            if url.endswith(".zip.sha256"):
                return io.BytesIO(("a" * 64 + "  lanpulse.zip\n").encode())
            return io.BytesIO(json.dumps({"tag_name": "v1.25.36", "assets": [
                {"name": "lanpulse.zip", "browser_download_url": "https://github.com/a/b.zip"},
                {"name": "lanpulse.zip.sha256", "browser_download_url": "https://github.com/a/b.zip.sha256"}]}).encode())

        orig = releases._open
        releases._open = fake_open
        releases._cache.update(t=0.0, data=None)
        try:
            r = releases.latest("1.25.30", force=True)
        finally:
            releases._open = orig
            releases._cache.update(t=0.0, data=None)
        self.assertEqual((r["version"], r["source"], r["newer"]), ("1.25.36", "GitHub", True))
        self.assertEqual(len(calls), 4)   # Pages, GitLab API, GitHub release and its checksum

    def test_pages_answer_skips_the_api(self):
        calls = []

        def fake_open(url, timeout):
            import io
            import json
            calls.append(url)
            return io.BytesIO(json.dumps({"tag": "v1.25.37", "version": "1.25.37",
                                          "asset_url": "https://gitlab.com/-/project/1/uploads/abc/lanpulse.zip",
                                          "sha256": "b" * 64,
                                          "url": "https://gitlab.com/r00tb0ss/lanpulse/-/releases/v1.25.37"}).encode())

        orig = releases._open
        releases._open = fake_open
        releases._cache.update(t=0.0, data=None)
        try:
            r = releases.latest("1.25.30", force=True)
        finally:
            releases._open = orig
            releases._cache.update(t=0.0, data=None)
        self.assertEqual((r["version"], r["source"], r["newer"]), ("1.25.37", "GitLab Pages", True))
        self.assertEqual(len(calls), 1)

    def test_only_release_hosts_are_allowed(self):
        with self.assertRaises(Exception):
            releases._open("https://example.com/lanpulse.zip", 5)


class HoneypotSummary(unittest.TestCase):
    def test_counts_are_not_capped_at_2000(self):
        import tempfile
        import time
        from pathlib import Path
        from types import SimpleNamespace

        class Pot(honeypot.Honeypot):
            cfg = {"enabled": False, "bind": "0.0.0.0", "ingest_key": "", "services": {}, "ports": {}, "banners": {}, "retention_days": 90}

            def _geo(self, ip):
                return {"iso": "", "country": "", "city": "", "org": "", "asn": None}

        d = tempfile.mkdtemp()
        pot = Pot(SimpleNamespace(args=SimpleNamespace(demo=False), data_dir=Path(d), settings={}, threats=None))
        now = time.time()
        rows = [(now - i, "203.0.113.%d" % (i % 50 + 1), "telnet" if i % 2 else "ftp", 23, 0,
                 "root / x%d" % (i % 7) if i % 3 == 0 else "", "", "") for i in range(5000)]
        pot.db.executemany("INSERT INTO hits (t, ip, service, port, internal, creds, data, sensor) VALUES (?,?,?,?,?,?,?,?)", rows)
        pot.db.commit()
        s = pot.summary(24)
        self.assertEqual(s["totals"]["hits"], 5000)
        self.assertEqual(s["totals"]["attackers"], 50)
        self.assertEqual(sum(x["count"] for x in s["by_service"]), 5000)
        self.assertEqual(s["totals"]["creds"], len([r for r in rows if r[5]]))
        self.assertEqual(sum(s["hist"]), 5000)
        self.assertEqual(len(s["recent"]), 60)
        self.assertEqual(s["attackers"][0]["hits"], 100)


    def test_service_detail_groups_hosts_and_credentials(self):
        import tempfile
        import time
        from pathlib import Path
        from types import SimpleNamespace

        class Pot(honeypot.Honeypot):
            cfg = {"enabled": False, "bind": "0.0.0.0", "ingest_key": "", "services": {}, "ports": {},
                   "banners": {}, "retention_days": 90}
            def _geo(self, ip):
                return {"iso": "US", "country": "United States", "city": "Test City", "org": "Test ISP", "asn": 64500}

        pot = Pot(SimpleNamespace(args=SimpleNamespace(demo=False), data_dir=Path(tempfile.mkdtemp()),
                                  settings={}, threats=None))
        now = time.time()
        pot.db.executemany(
            "INSERT INTO hits (t, ip, service, port, internal, creds, data, sensor) VALUES (?,?,?,?,?,?,?,?)",
            [(now - 20, "203.0.113.10", "ftp", 21, 0, "root / x", "", ""),
             (now - 10, "203.0.113.10", "ftp", 21, 0, "", "commands: SYST", ""),
             (now - 5, "203.0.113.11", "ftp", 2121, 1, "admin / test", "", ""),
             (now - 2, "203.0.113.10", "ssh", 22, 0, "", "client=ssh", "")])
        pot.db.commit()
        result = pot.service_detail("ftp", 24)
        self.assertEqual((result["total"], result["host_count"]), (3, 2))
        self.assertEqual(result["hosts"][0]["ip"], "203.0.113.10")
        self.assertEqual(result["hosts"][0]["hits"], 2)
        self.assertEqual(result["hosts"][0]["credential_hits"], 1)
        self.assertEqual(result["hosts"][0]["ports"], [21])
        self.assertEqual(result["hosts"][1]["ip"], "203.0.113.11")
        self.assertTrue(result["hosts"][1]["internal"])
        self.assertIsNone(pot.service_detail("not-a-service", 24))


class TopologyRates(unittest.TestCase):
    def test_client_rate(self):
        self.assertEqual(topology._client_rate({"bytes-r": 1500}), 1500.0)
        self.assertEqual(topology._client_rate({"tx_bytes-r": 1, "rx_bytes-r": 2}), 3.0)
        self.assertIsNone(topology._client_rate({}))
        self.assertIsNone(topology._client_rate({"bytes-r": "x"}))

    def test_wired_client_rates(self):
        c = {"wired-tx_bytes-r": 6693.7, "wired-rx_bytes-r": 1799.3}      # what UniFi sends for a wired client
        self.assertEqual(topology._client_dirs(c), (6693.7, 1799.3))
        self.assertAlmostEqual(topology._client_rate(c), 8493.0)
        self.assertEqual(topology._client_dirs({"tx_bytes-r": 4, "rx_bytes-r": 5}), (4.0, 5.0))      # a Wi-Fi client

    def test_client_dirs(self):
        self.assertEqual(topology._client_dirs({"tx_bytes-r": 1, "rx_bytes-r": 2}), (1.0, 2.0))
        self.assertEqual(topology._client_dirs({"tx_bytes-r": 5}), (5.0, None))
        self.assertEqual(topology._client_dirs({"bytes-r": 9}), (None, None))
        self.assertEqual(topology._client_dirs({"tx_bytes-r": "x", "rx_bytes-r": -3}), (None, 0.0))
        self.assertEqual(topology._client_dirs({}), (None, None))


class FakeAgent:
    """A tiny SNMP agent: answers GET-BULK from a sorted OID table. Shares the module's own BER code,
    so it proves the tables are read correctly, not that real devices agree on the encoding."""
    def __init__(self, mib):
        import socket
        import threading
        self.rows = sorted(((tuple(int(x) for x in o.split(".")), v) for o, v in mib.items()))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        s = snmpdisc
        while True:
            data, addr = self.sock.recvfrom(65535)
            _t, body, _ = s._read(data, 0)
            _t, _v, i = s._read(body, 0)
            _t, _c, i = s._read(body, i)
            _t, pdu, _ = s._read(body, i)
            _t, rid, j = s._read(pdu, 0)
            _t, _ns, j = s._read(pdu, j)
            _t, mr, j = s._read(pdu, j)
            _t, vbs, _ = s._read(pdu, j)
            _t, vb, _ = s._read(vbs, 0)
            _t, ob, _ = s._read(vb, 0)
            cur = tuple(int(x) for x in s._dec_oid(ob).split("."))
            out = b""
            n = 0
            for o, v in self.rows:
                if o > cur and n < int.from_bytes(mr, "big"):
                    val = s._tlv(0x04, v) if isinstance(v, bytes) else s._int(v)
                    out += s._tlv(0x30, s._oid(".".join(map(str, o))) + val)
                    n += 1
            if n == 0:
                out = s._tlv(0x30, s._oid(".".join(map(str, cur))) + bytes([0x82, 0]))
            resp = s._tlv(0x30, s._int(1) + s._tlv(0x04, b"public") + s._tlv(
                0xA2, s._tlv(0x02, rid) + s._int(0) + s._int(0) + s._tlv(0x30, out)))
            self.sock.sendto(resp, addr)


class SnmpDiscovery(unittest.TestCase):
    def test_encoding_matches_the_standard(self):
        self.assertEqual(snmpdisc._oid("1.3.6.1.2.1.1.1").hex(), "06072b060102010101")
        self.assertEqual(snmpdisc._oid("1.0.8802.1.1.2.1.4.1.1.5").hex(), "060b28c4620101020104010105")
        self.assertEqual(snmpdisc._int(128).hex(), "02020080")
        self.assertEqual(snmpdisc.encode_getbulk("public", 1, "1.3.6.1.2.1.1.1", 20).hex(),
                         "302502010104067075626c6963a518020101020100020114300d300b06072b0601020101010500")

    def test_poll_reads_lldp_and_fdb(self):
        ch = snmpdisc.LLDP_REM_CHASSIS
        mib = {
            snmpdisc.SYS_NAME + ".0": b"core-sw", snmpdisc.SYS_DESCR + ".0": b"Fake Switch",
            snmpdisc.IF_NAME + ".1": b"Gi1/0/1", snmpdisc.IF_NAME + ".2": b"Gi1/0/2",
            ch + ".0.1.1": bytes.fromhex("aabbccddee01"), snmpdisc.LLDP_REM_CHASSIS_SUBTYPE + ".0.1.1": 4,
            snmpdisc.LLDP_REM_PORT + ".0.1.1": b"uplink", snmpdisc.LLDP_REM_SYSNAME + ".0.1.1": b"edge-ap",
            snmpdisc.BASE_PORT_IFINDEX + ".1": 1, snmpdisc.BASE_PORT_IFINDEX + ".2": 2,
            snmpdisc.Q_FDB_PORT + ".1.17.34.51.68.85.102": 2,
        }
        a = FakeAgent(mib)
        orig = snmpdisc.Client.__init__

        def init(self, host, community, timeout=2.0):
            orig(self, host, community, 1.0)
            self.port = a.port
        snmpdisc.Client.__init__ = init
        try:
            r = snmpdisc.poll_host("127.0.0.1", "public")
        finally:
            snmpdisc.Client.__init__ = orig
        self.assertEqual(r["name"], "core-sw")
        self.assertEqual(r["lldp"][0]["chassis_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(r["lldp"][0]["sys_name"], "edge-ap")
        self.assertEqual(r["fdb"], [{"mac": "11:22:33:44:55:66", "port": "Gi1/0/2"}])

    def test_only_private_hosts(self):
        self.assertEqual(snmpdisc.valid_host("192.168.1.2"), "192.168.1.2")
        for bad in ("8.8.8.8", "127.0.0.1", "224.0.0.1", "example.com", "0.0.0.0", ""):
            self.assertEqual(snmpdisc.valid_host(bad), "", bad)

    def test_topology_uses_lldp_and_fdb(self):
        T = topology.Topology
        nodes = {"gw": {"ip": "10.0.0.1", "kind": "gateway"}, "sw": {"ip": "10.0.0.2", "kind": "switch"},
                 "ap": {"ip": "10.0.0.3", "kind": "ap"}, "pc": {"ip": "10.0.0.9", "kind": "client"}}
        by_mac = {"AA:AA:AA:AA:AA:01": "gw", "AA:AA:AA:AA:AA:02": "sw", "AA:AA:AA:AA:AA:03": "ap", "AA:AA:AA:AA:AA:09": "pc"}
        t = T.__new__(T)
        t.snmp = {"10.0.0.1": {"lldp": [{"local_port": "p1", "chassis_mac": "aa:aa:aa:aa:aa:02", "port_id": "up"}], "fdb": []},
                  "10.0.0.2": {"lldp": [{"local_port": "g1", "chassis_mac": "aa:aa:aa:aa:aa:01", "port_id": "p1"},
                                        {"local_port": "g2", "chassis_mac": "aa:aa:aa:aa:aa:03", "port_id": "eth0"}],
                               "fdb": [{"mac": "aa:aa:aa:aa:aa:09", "port": "g5"}, {"mac": "aa:aa:aa:aa:aa:03", "port": "g2"}]}}
        p = t._snmp_parents(nodes, by_mac, "gw")
        self.assertEqual(p["sw"][0], "gw")
        self.assertEqual(p["ap"][0], "sw")
        self.assertEqual(p["pc"], ("sw", {"medium": "wired", "port": "g5"}))


if __name__ == "__main__":
    unittest.main()
