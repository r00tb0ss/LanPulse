# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""The authorized public scan has its own card on the Vulns tab; the attacker panel stays about the attacker."""
import pathlib
import re
import unittest

STATIC = pathlib.Path(__file__).resolve().parent.parent / "static"


class PublicScanPlacement(unittest.TestCase):
    def test_threat_panel_has_no_scan_controls(self):
        js = (STATIC / "threats.js").read_text()
        for name in ("publicScan", "bPublicScan", "public-scan", "authorized/public", "authorized-public"):
            self.assertNotIn(name, js)

    def test_vulns_tab_hosts_the_scan_card_once(self):
        html = (STATIC / "index.html").read_text()
        vuln = html[html.index('id="vulnView"'):]
        vuln = vuln[:vuln.index("</section>")]
        for ident in ("publicScanTarget", "publicScanEngine", "publicScanAuthorized", "bPublicScan", "publicScanStatus"):
            self.assertEqual(len(re.findall(r'id="%s"' % ident, html)), 1, ident)
            self.assertIn('id="%s"' % ident, vuln)
        self.assertIn("/static/publicscan.js", html)

    def test_scan_script_keeps_the_authorization_guards(self):
        js = (STATIC / "publicscan.js").read_text()
        self.assertIn("publicScanAuthorized", js)
        self.assertIn("window.confirm", js)
        self.assertIn('"/api/scans/authorized-public", "POST"', js)
        self.assertIn("authorized: true", js)


if __name__ == "__main__":
    unittest.main()
