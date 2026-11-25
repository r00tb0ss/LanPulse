# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Choosing a model per request: only models the AI server really offers are accepted, and nothing is saved."""
import io
import json
import types
import unittest
from unittest.mock import patch

import analyst


def tags(*names):
    return io.BytesIO(json.dumps({"models": [{"name": n} for n in names]}).encode())


class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


class ModelPicker(unittest.TestCase):
    def setUp(self):
        analyst._models_cache.clear()
        self.nm = types.SimpleNamespace(settings={"ai": {"enabled": True, "provider": "ollama",
                                                         "base_url": "http://192.168.0.50:11434", "model": "qwen2.5-coder:32b"}})

    def test_lists_installed_ollama_models_sorted(self):
        with patch("urllib.request.urlopen", return_value=FakeResp(tags("qwen2.5-coder:32b", "llama3.1:8b").getvalue())):
            self.assertEqual(analyst.list_models(analyst._cfg(self.nm)), ["llama3.1:8b", "qwen2.5-coder:32b"])

    def test_chosen_model_is_used_for_that_request_only(self):
        with patch("urllib.request.urlopen", return_value=FakeResp(tags("qwen2.5-coder:32b", "llama3.1:8b").getvalue())):
            self.assertEqual(analyst._cfg(self.nm, "llama3.1:8b")["model"], "llama3.1:8b")
            self.assertEqual(analyst._cfg(self.nm)["model"], "qwen2.5-coder:32b")
        self.assertEqual(self.nm.settings["ai"]["model"], "qwen2.5-coder:32b")

    def test_model_the_server_does_not_have_is_ignored(self):
        with patch("urllib.request.urlopen", return_value=FakeResp(tags("llama3.1:8b").getvalue())):
            self.assertEqual(analyst._cfg(self.nm, "evil/../model")["model"], "qwen2.5-coder:32b")

    def test_unreachable_server_falls_back_to_the_configured_model(self):
        with patch("urllib.request.urlopen", side_effect=OSError("down")):
            self.assertEqual(analyst.list_models(analyst._cfg(self.nm)), [])
            self.assertEqual(analyst._cfg(self.nm, "llama3.1:8b")["model"], "qwen2.5-coder:32b")

    def test_hosted_anthropic_has_no_model_list(self):
        self.assertEqual(analyst.list_models({"provider": "anthropic", "base_url": "https://api.anthropic.com"}), [])


class TodaysDate(unittest.TestCase):
    def test_model_is_told_todays_date_and_not_to_distrust_newer_data(self):
        import datetime
        note = analyst.date_note(datetime.date(2026, 11, 25))
        self.assertIn("2026-11-25", note)
        self.assertIn("never call a date on or before today 'future'", note)
        seen = {}
        def fake(url, payload, headers, timeout):
            seen["system"] = payload["messages"][0]["content"]
            return {"message": {"content": "ok"}}
        cfg = {"provider": "ollama", "base_url": "http://localhost:11434", "model": "m"}
        with patch.object(analyst, "_http_json", side_effect=fake):
            analyst.call_model(cfg, "base system prompt", "question")
        self.assertTrue(seen["system"].startswith("base system prompt"))
        self.assertIn("Today's date is", seen["system"])


if __name__ == "__main__":
    unittest.main()
