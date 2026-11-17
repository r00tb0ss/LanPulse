# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""A labelled set of real-world cases for vulnerability matching: version order, banner cleaning, product recognition,
NVD range matching, and the whole path from a scanned port to a finding. Each case states the right answer, so a change
that makes LanPulse less accurate fails here."""
import asyncio
import json
import pathlib
import tempfile
import time
import types
import unittest

import vulns as v

ORDER = [   # (a, b, sign of a compared with b)
    ("1.0", "1.0.0", 0), ("1.0.0", "1.0", 0), ("1.2.3", "1.2.3.0", 0), ("8.1", "8.1.0", 0), ("4.18.0", "4.18", 0),
    ("2.4.49", "2.4.50", -1), ("2.4.9", "2.4.10", -1), ("1.10", "1.9", 1), ("10.0", "9.9.9", 1), ("2.7.18", "2.7.9", 1),
    ("7.9p1", "7.9", 1), ("7.9p1", "7.9p2", -1), ("9.8p1", "9.8", 1), ("6.6.1p1", "6.6.1", 1),
    ("1.0.2k", "1.0.2", 1), ("1.0.2zf", "1.0.2k", 1), ("1.0.2z", "1.0.2za", -1), ("1.1.1w", "1.1.1", 1),
    ("1.0.1a", "1.0.1", 1), ("1.0.1b", "1.0.1a", 1), ("3.0.20a", "3.0.20", 1), ("3.0.20", "3.0.20a", -1),
    ("2.0-rc1", "2.0", -1), ("2.0", "2.0.0-rc1", 1), ("5.0.0-beta2", "5.0.0", -1), ("1.0.0-alpha", "1.0.0", -1),
    ("2.0b1", "2.0", -1), ("2.0a2", "2.0b1", -1), ("2.0", "2.0b1", 1),
]

CLEAN = [
    ("7.9p1 Debian 10+deb10u2", "7.9p1"), ("3.0.20-Debian", "3.0.20"), ("1.0-rc1", "1.0-rc1"), ("2.4.41 ((Ubuntu))", "2.4.41"),
    ("5.7.33-0ubuntu0.18.04.1", "5.7.33"), ("1.18.0 (Ubuntu)", "1.18.0"), ("OpenSSH_8.2p1", "8.2p1"), ("Apache/2.4.41", "2.4.41"),
    ("v2.3.4", "2.3.4"), ("9.18.12-1~deb12u1-Debian", "9.18.12"), ("4.9.5-Debian", "4.9.5"), ("1.0.2k-fips", "1.0.2k"),
    ("8.0.33-0ubuntu0.22.04.2", "8.0.33"), ("10.5.18-MariaDB", "10.5.18"), ("", ""), ("unknown", ""),
]

NAMES = [   # (what nmap reports, expected NVD vendor:product or None for "not this software")
    ("OpenSSH", "openbsd:openssh"), ("Dropbear sshd", "dropbear_ssh_project:dropbear_ssh"), ("Apache httpd", "apache:http_server"),
    ("Apache Tomcat", "apache:tomcat"), ("Apache Tomcat/Coyote JSP engine", None), ("nginx", "f5:nginx"), ("lighttpd", "lighttpd:lighttpd"),
    ("PHP", "php:php"), ("PHP cli server", "php:php"), ("phpMyAdmin", None), ("MySQL", "mysql:mysql"), ("MySQL Router", None),
    ("Exim smtpd", "exim:exim"), ("Eximon", None), ("Redis key-value store", "redis:redis"), ("RediSearch", None),
    ("Squid http proxy", "squid-cache:squid"), ("Squid Cache Manager", None), ("Postfix smtpd", "postfix:postfix"),
    ("ISC BIND", "isc:bind"), ("dnsmasq", "thekelleys:dnsmasq"), ("OpenSSL", "openssl:openssl"), ("Jetty", "eclipse:jetty"),
    ("Samba smbd", "samba:samba"), ("vsFTPd", "vsftpd_project:vsftpd"), ("nginx-ui", "f5:nginx"),
]

def cm(**k):
    return {"c": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", **k}

RANGES = [   # (version, cpeMatch entry, vulnerable?)  - shapes taken from NVD records
    ("1.0.1", cm(si="1.0.1", ei="1.0.1f"), True), ("1.0.1a", cm(si="1.0.1", ei="1.0.1f"), True), ("1.0.1e", cm(si="1.0.1", ei="1.0.1f"), True),
    ("1.0.1f", cm(si="1.0.1", ei="1.0.1f"), True), ("1.0.1g", cm(si="1.0.1", ei="1.0.1f"), False), ("1.0.0", cm(si="1.0.1", ei="1.0.1f"), False),
    ("1.0.2", cm(si="1.0.1", ei="1.0.1f"), False),
    ("8.4p1", cm(si="8.5p1", ee="9.8p1"), False), ("8.5p1", cm(si="8.5p1", ee="9.8p1"), True), ("9.7p1", cm(si="8.5p1", ee="9.8p1"), True),
    ("9.8p1", cm(si="8.5p1", ee="9.8p1"), False), ("9.9p1", cm(si="8.5p1", ee="9.8p1"), False),
    ("2.4.49", {"c": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, True), ("2.4.50", {"c": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, False),
    ("7.9p1", {"c": "cpe:2.3:a:openbsd:openssh:7.9:p1:*:*:*:*:*:*"}, True), ("7.9p2", {"c": "cpe:2.3:a:openbsd:openssh:7.9:p1:*:*:*:*:*:*"}, False),
    ("4.6.3", cm(si="3.5.0", ee="4.6.4"), True), ("4.6.4", cm(si="3.5.0", ee="4.6.4"), False), ("3.4.9", cm(si="3.5.0", ee="4.6.4"), False),
    ("3.5.0", cm(si="3.5.0", ee="4.6.4"), True),
    ("2.0", cm(se="2.0", ei="2.5"), False), ("2.0.1", cm(se="2.0", ei="2.5"), True), ("2.5", cm(se="2.0", ei="2.5"), True), ("2.5.1", cm(se="2.0", ei="2.5"), False),
    ("2.0-rc1", cm(ee="2.0"), True), ("2.0", cm(ee="2.0"), False), ("2.0.0", cm(ee="2.0"), False), ("1.9.9", cm(ee="2.0"), True),
    ("1.2.3", cm(ee="1.2.3.0"), False), ("10.5.18", cm(ee="10.5.19"), True), ("10.5.19", cm(ee="10.5.19"), False),
    ("9.9.9", cm(), False),      # "all versions" entries are too vague to report
]


class Pure(unittest.TestCase):
    def test_version_order(self):
        for a, b, want in ORDER:
            with self.subTest(a=a, b=b):
                self.assertEqual(v.vcmp(a, b), want)
                self.assertEqual(v.vcmp(b, a), -want)

    def test_banner_cleaning(self):
        for raw, want in CLEAN:
            with self.subTest(raw=raw):
                self.assertEqual(v.clean_version(raw), want)

    def test_product_recognition(self):
        for name, want in NAMES:
            got = next(((prods[0][0] + ":" + prods[0][1]) if prods else None for rx, prods in v.NAME_MAP if rx.search(name)), None)
            with self.subTest(name=name):
                self.assertEqual(got, want)

    def test_nvd_ranges(self):
        for ver, entry, want in RANGES:
            with self.subTest(ver=ver, entry=entry):
                self.assertEqual(v.version_matches(ver, entry), want)


def nvd(cve, score, matches):
    return {"id": cve, "score": score, "desc": cve, "pub": "2024-01-01", "m": matches}


class EndToEnd(unittest.TestCase):
    """From a scanned port to a finding, with a stand-in NVD cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        devs = {
            "a": {"id": "a", "ip": "192.168.0.10", "ports": [{"port": 443, "sw": "OpenSSL", "ver": "1.0.1a", "product": "OpenSSL 1.0.1a"}]},
            "b": {"id": "b", "ip": "192.168.0.11", "ports": [{"port": 80, "sw": "phpMyAdmin", "ver": "5.2.1", "product": "phpMyAdmin 5.2.1"}]},
            "c": {"id": "c", "ip": "192.168.0.12", "ports": [{"port": 22, "sw": "OpenSSH", "ver": "7.9p1 Debian 10+deb10u2", "product": "OpenSSH 7.9p1 Debian 10+deb10u2"}]},
            "d": {"id": "d", "ip": "192.168.0.13", "ports": [{"port": 22, "sw": "OpenSSH", "ver": "9.8p1", "product": "OpenSSH 9.8p1"}]},
            "e": {"id": "e", "ip": "192.168.0.14", "ports": [{"port": 80, "sw": "Apache httpd", "ver": "2.4.x", "product": "Apache httpd 2.4.x"}]},
        }
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name), devices=devs, settings={"vulns": {}},
                                   openvas=types.SimpleNamespace(items_for=lambda d: []), label=lambda d: d["ip"])
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.vs = v.VulnScanner(nm)
        data = {
            "openssl:openssl": [nvd("CVE-2014-0160", 7.5, [cm(si="1.0.1", ei="1.0.1f")])],
            "php:php": [nvd("CVE-PHP-1", 9.8, [cm(si="5.0", ee="8.3")])],
            "openbsd:openssh": [nvd("CVE-2024-6387", 8.1, [cm(si="8.5p1", ee="9.8p1")]), nvd("CVE-2019-6111", 5.9, [cm(ee="8.0")])],
            "apache:http_server": [nvd("CVE-APACHE-1", 7.5, [cm(si="2.4.0", ee="2.4.60")])],
        }
        with self.vs.lock:
            for key, cves in data.items():
                self.vs.db.execute("INSERT INTO cache VALUES (?,?,?)", (key, time.time(), json.dumps(cves)))
            self.vs.db.commit()
        self.vs.kev = {"CVE-2014-0160": {"name": "Heartbleed", "ransomware": False}}
        self.vs.evaluate(alert=False)

    def tearDown(self):
        self.tmp.cleanup()

    def cves(self, dev):
        return {f["cve"] for f in self.vs.results.get(dev, [])}

    def test_openssl_1_0_1a_is_flagged_for_heartbleed_and_marked_actively_exploited(self):
        self.assertIn("CVE-2014-0160", self.cves("a"))
        self.assertTrue(next(f for f in self.vs.results["a"] if f["cve"] == "CVE-2014-0160")["kev"])

    def test_phpmyadmin_is_not_matched_to_php_flaws(self):
        self.assertEqual(self.cves("b"), set())

    def test_debian_openssh_is_flagged_but_marked_as_possibly_patched(self):
        f = next(f for f in self.vs.results["c"] if f["cve"] == "CVE-2019-6111")
        self.assertTrue(f["distro"])                                # Debian may have patched it without changing the version
        self.assertEqual(self.cves("c"), {"CVE-2019-6111"})         # 7.9p1 is older than the 8.5p1 start of CVE-2024-6387's range

    def test_fixed_openssh_has_no_findings(self):
        self.assertEqual(self.cves("d"), set())

    def test_a_wildcard_version_never_produces_a_version_based_finding(self):
        self.assertEqual(self.cves("e"), set())


if __name__ == "__main__":
    unittest.main()
