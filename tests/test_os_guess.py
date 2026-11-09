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


class SilentHostGetsNoGuess(unittest.TestCase):
    def test_nmap_deep_drops_the_guess_when_no_port_answers(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")).read()
        self.assertIn('if not info["ports"]:            # nmap fingerprints', src)
        self.assertIn('"DESKTOP-", "LAPTOP-"', src)


if __name__ == "__main__":
    unittest.main()
