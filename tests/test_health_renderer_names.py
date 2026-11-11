# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import unittest
from pathlib import Path


class HealthRendererNameTests(unittest.TestCase):
    def test_network_and_services_health_renderers_are_distinct(self):
        root = Path(__file__).resolve().parent.parent
        sidebar = (root / "static" / "sidebar.js").read_text()
        services = (root / "static" / "healthview.js").read_text()

        self.assertIn("function renderHealth() {", sidebar)
        self.assertIn("function renderServiceHealth() {", services)
        self.assertNotIn("function renderHealth() {", services)
        self.assertIn("healthData = r;\n  renderServiceHealth();", services)


if __name__ == "__main__":
    unittest.main()
