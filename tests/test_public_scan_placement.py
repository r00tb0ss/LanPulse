# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""The authorized public scan is a "Public scan" sub-tab of Threats; the attacker panel stays about the attacker."""
import pathlib
import re
import unittest

STATIC = pathlib.Path(__file__).resolve().parent.parent / "static"


def section(html, view_id):
    part = html[html.index('id="%s"' % view_id):]
    return part[:part.index("</section>")]


class PublicScanPlacement(unittest.TestCase):
    def test_attacker_side_panel_has_no_scan_controls(self):
        js = (STATIC / "threats.js").read_text()
        for name in ("publicScan", "bPublicScan", "public-scan", "authorized/public", "authorized-public"):
            self.assertNotIn(name, js)

    def test_threats_has_a_public_scan_sub_tab_and_vulns_does_not(self):
        html = (STATIC / "index.html").read_text()
        threats, vulns = section(html, "threatView"), section(html, "vulnView")
        self.assertIn('data-tsub="scan"', threats)
        self.assertIn('data-tsub="attacks"', threats)
        for ident in ("publicScanTarget", "publicScanEngine", "publicScanAuthorized", "bPublicScan",
                      "publicScanStatus", "bPublicScanClear"):
            self.assertEqual(len(re.findall(r'id="%s"' % ident, html)), 1, ident)
            self.assertIn('id="%s"' % ident, threats)
            self.assertNotIn(ident, vulns)
        self.assertIn("/static/publicscan.js", html)

    def test_scan_script_keeps_the_authorization_guards_and_can_delete_history(self):
        js = (STATIC / "publicscan.js").read_text()
        for needle in ("publicScanAuthorized", "window.confirm", '"/api/scans/authorized-public", "POST"',
                       "authorized: true", "/api/scans/authorized-public/delete", "ps-del"):
            self.assertIn(needle, js)


if __name__ == "__main__":
    unittest.main()
