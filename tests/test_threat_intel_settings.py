# SPDX-License-Identifier: GPL-2.0-or-later
"""Settings regression tests for optional threat-intelligence credentials."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import alerts  # noqa: E402


class ThreatIntelSettings(unittest.TestCase):
    def test_malwarebazaar_key_is_masked_and_mask_round_trips(self):
        current = alerts.with_defaults(None)
        current["threats"]["malwarebazaar_key"] = "secret-api-key"
        public = alerts.masked(current)
        self.assertEqual(public["threats"]["malwarebazaar_key"], alerts.MASK)
        updated = alerts.apply_update(current, {"threats": {"malwarebazaar_key": alerts.MASK}})
        self.assertEqual(updated["threats"]["malwarebazaar_key"], "secret-api-key")

    def test_malwarebazaar_key_is_saved_separately_from_abuseipdb(self):
        current = alerts.with_defaults(None)
        updated = alerts.apply_update(current, {"threats": {
            "abuseipdb_key": "abuse-key-123",
            "malwarebazaar_key": "mb-key-456"
        }})
        self.assertEqual(updated["threats"]["abuseipdb_key"], "abuse-key-123")
        self.assertEqual(updated["threats"]["malwarebazaar_key"], "mbkey456")


if __name__ == "__main__":
    unittest.main()
