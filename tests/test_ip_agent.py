# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for passive IP-agent evidence handling."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyst


class PassiveIpEvidence(unittest.TestCase):
    def test_evidence_omits_credentials_and_raw_event_details(self):
        data = {
            "count": 3, "blocked": 2, "reached": 1,
            "credentials": [{"text": "root / do-not-send-this-password", "count": 1}],
            "recent": [{"service": "ssh", "detail": "do-not-send-this-command"}],
            "ports": [{"port": 22, "service": "SSH", "count": 3}],
        }
        evidence = analyst.format_ip_evidence("198.51.100.7", data)
        self.assertIn("SSH", evidence)
        self.assertNotIn("do-not-send-this-password", evidence)
        self.assertNotIn("do-not-send-this-command", evidence)

    def test_decoy_activity_is_explicit_and_no_yara_match_is_invented(self):
        data = {"count": 0, "blocked": 0, "reached": 0}
        context = {"honeypot": {"total": 2, "logged_in": True, "commands": 4,
                                "samples": [{"sha256": "a" * 64, "name": "payload"}]}}
        evidence = analyst.format_ip_evidence("198.51.100.8", data, context)
        self.assertIn("Honeypot decoy activity", evidence)
        self.assertIn("No YARA result is attached", evidence)
        self.assertNotIn("confirmed compromise", evidence.lower())

    def test_c2_match_is_explicitly_gated(self):
        data = {"count": 1, "blocked": 0, "reached": 1}
        no_match = analyst.format_ip_evidence("198.51.100.9", data, known_c2=False)
        match = analyst.format_ip_evidence("198.51.100.9", data, known_c2=True)
        self.assertIn("NO / not listed", no_match)
        self.assertIn("exact-match: YES", match)


if __name__ == "__main__":
    unittest.main()
