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


    def test_existing_provider_keys_migrate_into_masked_central_vault(self):
        legacy = {
            "threats": {"abuseipdb_key": "abuse-key"},
            "dns": {"abuse_key": "abusech-key"},
            "vulns": {"nvd_key": "nvd-key"},
            "ai": {"api_key": "ai-key"},
            "unifi": {"api_key": "unifi-key"},
        }
        migrated = alerts.with_defaults(legacy)
        self.assertEqual(migrated["keys"], {
            "abuseipdb": "abuse-key", "abusech": "abusech-key", "nvd": "nvd-key",
            "ai": "ai-key", "unifi": "unifi-key",
        })
        public = alerts.masked(migrated)
        self.assertTrue(all(value == alerts.MASK for value in public["keys"].values()))

    def test_central_key_update_keeps_legacy_consumers_in_sync(self):
        current = alerts.with_defaults(None)
        key = "aB3dEf9GhIjKlMnOpQrStUvWxYz0123456789AbC"
        updated = alerts.apply_update(current, {"keys": {"abusech": key, "abuseipdb": "ipdb-key"}})
        self.assertEqual(updated["keys"]["abusech"], key)
        self.assertEqual(updated["dns"]["abuse_key"], key)
        self.assertEqual(updated["threats"]["abuseipdb_key"], "ipdb-key")
        round_trip = alerts.apply_update(updated, {"keys": {"abusech": alerts.MASK}})
        self.assertEqual(round_trip["keys"]["abusech"], key)

    def test_changing_ai_provider_clears_centralized_provider_key(self):
        current = alerts.with_defaults({"ai": {"provider": "openai", "api_key": "secret-key"}})
        updated = alerts.apply_update(current, {"ai": {"provider": "anthropic"}})
        self.assertEqual(updated["ai"]["api_key"], "")
        self.assertEqual(updated["keys"]["ai"], "")

    def test_abuse_ch_key_is_sanitized_to_printable_ascii(self):
        current = alerts.with_defaults(None)
        updated = alerts.apply_update(current, {"keys": {"abusech": "abc-123\u200b_Xy.z+!/="}})
        self.assertEqual(updated["dns"]["abuse_key"], "abc-123_Xy.z+!/=")


if __name__ == "__main__":
    unittest.main()

    def test_realistic_mixed_case_key_is_not_altered(self):
        key = "aB3dEf9GhIjKlMnOpQrStUvWxYz0123456789AbC"
        updated = alerts.apply_update(alerts.with_defaults({}), {"dns": {"abuse_key": key}})
        self.assertEqual(updated["dns"]["abuse_key"], key)
        updated = alerts.apply_update(updated, {"dns": {"abuse_key": " " + key + "\n"}})
        self.assertEqual(updated["dns"]["abuse_key"], key)
