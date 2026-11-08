# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import analyst
import redteam


class ReviewFixTests2(unittest.TestCase):
    def test_is_local(self):
        for url in ("http://localhost:11434", "http://127.0.0.1:1234/v1", "http://192.168.0.50:11434",
                    "http://172.20.1.5:8080", "http://10.0.0.2", "http://ai-box:11434", "http://ollama.lan"):
            self.assertTrue(analyst.is_local(url), url)
        for url in ("https://api.anthropic.com", "https://api.openai.com/v1", "http://172.217.1.1",
                    "https://localhost.evil.example", "https://192.168.evil.example", "https://10.example.com", ""):
            self.assertFalse(analyst.is_local(url), url)

    def test_resource_script_one_line_per_name(self):
        d = {"ip": "192.168.0.5", "name": "pc\nuse exploit/evil\nrun"}
        text = redteam.resource_script([(d, [{"commands": ["use auxiliary/scanner/x", "set RHOSTS 192.168.0.5"]}])])
        for line in text.splitlines():
            self.assertFalse(line.startswith("use exploit/evil"), line)
            self.assertNotEqual(line.strip(), "run")


if __name__ == "__main__":
    unittest.main()
