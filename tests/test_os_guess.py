# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""A device with no open ports must not get old-Windows CVEs from a stale or weak OS guess."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vulns  # noqa: E402

XP = {"os": "Microsoft Windows XP SP3", "os_accuracy": 92, "os_cpe": ["cpe:/o:microsoft:windows_xp::sp3"], "os_hint": "Microsoft Windows XP microsoft-ds"}


class NoPortsNoWindowsGuess(unittest.TestCase):
    def test_stale_guess_without_ports_is_ignored(self):
        self.assertIsNone(vulns.windows_version({**XP, "ports": []}))
        self.assertIsNone(vulns.windows_version(dict(XP)))

    def test_real_old_windows_with_ports_still_matches(self):
        d = {**XP, "ports": [{"port": 445, "proto": "tcp", "service": "microsoft-ds"}]}
        self.assertEqual(vulns.windows_version(d)[0], "Windows XP")


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PickedOs(unittest.TestCase):
    def test_a_picked_old_windows_is_honoured_even_without_ports(self):
        d = {"os": "Windows XP", "os_accuracy": 100, "os_hint": "Windows XP", "os_override": "Windows XP", "ports": []}
        self.assertEqual(vulns.windows_version(d)[0], "Windows XP")

    def test_a_picked_new_windows_gets_no_old_windows_cves(self):
        d = {"os": "Windows 11", "os_accuracy": 100, "os_hint": "Windows 11", "os_override": "Windows 11", "ports": [{"port": 445}]}
        self.assertIsNone(vulns.windows_version(d))

    def test_page_and_server_offer_the_same_systems(self):
        import ast
        app_src = open(os.path.join(ROOT, "app.py")).read()
        start = app_src.index("OS_GROUPS = ") + len("OS_GROUPS = ")
        groups = ast.literal_eval(app_src[start:app_src.index("\n", start)])
        js = open(os.path.join(ROOT, "static", "app.js")).read()
        for labels in groups.values():
            for label in labels:
                self.assertIn(json_quote(label), js, label)


def json_quote(s):
    import json
    return json.dumps(s)


class SilentHostGetsNoGuess(unittest.TestCase):
    def test_nmap_deep_drops_the_guess_when_no_port_answers(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")).read()
        self.assertIn('if not info["ports"]:            # nmap fingerprints', src)
        self.assertIn('"DESKTOP-", "LAPTOP-"', src)


if __name__ == "__main__":
    unittest.main()
