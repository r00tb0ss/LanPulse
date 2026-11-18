# SPDX-License-Identifier: GPL-2.0-or-later
"""Settings regression tests for shared abuse.ch credentials."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import alerts  # noqa: E402


class ThreatIntelSettings(unittest.TestCase):
    def test_abuse_ch_key_is_masked_and_mask_round_trips(self):
        current = alerts.with_defaults(None)
        current["dns"]["abuse_key"] = "abc-123_Xy.z+!/=:"
        public = alerts.masked(current)
        self.assertEqual(public["dns"]["abuse_key"], alerts.MASK)
        updated = alerts.apply_update(current, {"dns": {"abuse_key": alerts.MASK}})
        self.assertEqual(updated["dns"]["abuse_key"], "abc-123_Xy.z+!/=:" )

    def test_malwarebazaar_legacy_key_migrates_to_shared_abuse_ch_key(self):
        legacy = {
            "dns": {"abuse_key": ""},
            "threats": {"malwarebazaar_key": "legacy-MB_key.123+/"}
        }
        migrated = alerts.with_defaults(legacy)
        self.assertEqual(migrated["dns"]["abuse_key"], "legacy-MB_key.123+/")
        self.assertNotIn("malwarebazaar_key", migrated["threats"])

    def test_existing_abuse_ch_key_wins_over_legacy_key(self):
        legacy = {
            "dns": {"abuse_key": "existing-shared-key.+/"},
            "threats": {"malwarebazaar_key": "old-separate-key"}
        }
        migrated = alerts.with_defaults(legacy)
        self.assertEqual(migrated["dns"]["abuse_key"], "existing-shared-key.+/")


if __name__ == "__main__":
    unittest.main()

    def test_realistic_mixed_case_key_is_not_altered(self):
        key = "aB3dEf9GhIjKlMnOpQrStUvWxYz0123456789AbC"
        updated = alerts.apply_update(alerts.with_defaults({}), {"dns": {"abuse_key": key}})
        self.assertEqual(updated["dns"]["abuse_key"], key)
        updated = alerts.apply_update(updated, {"dns": {"abuse_key": " " + key + "\n"}})
        self.assertEqual(updated["dns"]["abuse_key"], key)
