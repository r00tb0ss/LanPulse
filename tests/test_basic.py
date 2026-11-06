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


class TopologyRates(unittest.TestCase):
    def test_client_rate(self):
        self.assertEqual(topology._client_rate({"bytes-r": 1500}), 1500.0)
        self.assertEqual(topology._client_rate({"tx_bytes-r": 1, "rx_bytes-r": 2}), 3.0)
        self.assertIsNone(topology._client_rate({}))
        self.assertIsNone(topology._client_rate({"bytes-r": "x"}))


if __name__ == "__main__":
    unittest.main()
