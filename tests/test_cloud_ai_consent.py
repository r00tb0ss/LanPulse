import types
import unittest
from unittest.mock import patch

import alerts
import analyst


class CloudEvidenceConsent(unittest.TestCase):
    def remote_nm(self, provider="openai", base_url="https://api.openai.com/v1"):
        return types.SimpleNamespace(settings={
            "ai": {"enabled": True, "provider": provider, "base_url": base_url}
        })

    def test_global_question_is_blocked_before_collecting_or_sending_evidence(self):
        nm = self.remote_nm()
        with patch.object(analyst, "build_context", side_effect=AssertionError("must not collect evidence")):
            result = analyst.ask(nm, "Summarize my network")
        self.assertTrue(result.get("consent_required"))
        self.assertIn("No evidence was sent", result["error"])

    def test_focused_ip_is_blocked_before_collecting_evidence(self):
        nm = self.remote_nm("anthropic", "https://api.anthropic.com")
        result = analyst.investigate_ip(nm, "203.0.113.8", "Investigate this source")
        self.assertTrue(result.get("consent_required"))

    def test_sample_is_blocked_before_collecting_evidence(self):
        nm = self.remote_nm("anthropic", "https://api.anthropic.com")
        nm.honeyan = types.SimpleNamespace(
            sample_evidence=lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not collect sample"))
        )
        result = analyst.investigate_sample(nm, "a" * 64)
        self.assertTrue(result.get("consent_required"))

    def test_local_openai_compatible_server_does_not_need_cloud_consent(self):
        cfg = {"provider": "openai", "base_url": "http://192.168.1.20:1234/v1",
               "cloud_evidence_consent": False}
        self.assertFalse(analyst.cloud_evidence_consent_required(cfg))

    def test_consent_setting_defaults_off_and_can_be_granted_or_revoked(self):
        self.assertFalse(alerts.DEFAULT_SETTINGS["ai"]["cloud_evidence_consent"])
        granted = alerts.apply_update(alerts.DEFAULT_SETTINGS, {"ai": {"cloud_evidence_consent": True}})
        self.assertTrue(granted["ai"]["cloud_evidence_consent"])
        revoked = alerts.apply_update(granted, {"ai": {"cloud_evidence_consent": False}})
        self.assertFalse(revoked["ai"]["cloud_evidence_consent"])

    def test_changing_cloud_provider_endpoint_revokes_previous_consent(self):
        approved = alerts.apply_update(alerts.DEFAULT_SETTINGS, {
            "ai": {"provider": "openai", "base_url": "https://api.openai.com/v1",
                   "cloud_evidence_consent": True}
        })
        changed = alerts.apply_update(approved, {"ai": {"provider": "anthropic"}})
        self.assertFalse(changed["ai"]["cloud_evidence_consent"])


if __name__ == "__main__":
    unittest.main()
