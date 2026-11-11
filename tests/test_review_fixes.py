# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth
import history
import topology


class ReviewFixTests(unittest.TestCase):
    def test_wired_rate_reads_wired_fields_first(self):
        c = {"tx_bytes-r": 0, "rx_bytes-r": 0, "wired-tx_bytes-r": 100.0, "wired-rx_bytes-r": 50.0}
        self.assertEqual(topology._client_rate(c), 150.0)
        self.assertEqual(topology._client_dirs(c), (100.0, 50.0))

    def test_plain_rate_still_works(self):
        self.assertEqual(topology._client_rate({"tx_bytes-r": 30, "rx_bytes-r": 20}), 50.0)
        self.assertEqual(topology._client_rate({"bytes-r": 7}), 7.0)
        self.assertIsNone(topology._client_rate({}))

    @unittest.skipIf(os.name == "nt", "file modes are not meaningful on Windows")
    def test_login_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            a = auth.Auth(path)
            a.set_password("admin", "secret")
            self.assertEqual(os.stat(path).st_mode & 0o077, 0)
            self.assertTrue(a.check("admin", "secret"))
            self.assertFalse(a.check("admin", "wrong"))

    def test_network_health_refreshes_on_live_data(self):
        root = Path(__file__).resolve().parent.parent
        app = (root / "static" / "app.js").read_text()
        threats = (root / "static" / "threats.js").read_text()

        helper = app.split("function refreshNetworkHealth() {", 1)[1].split(chr(10) + "}", 1)[0]
        self.assertIn('typeof renderHealth === "function"', helper)
        self.assertIn("catch (e)", helper)

        snapshot = app.split("function applySnapshot(s) {", 1)[1].split(chr(10) + "}", 1)[0]
        self.assertIn("refreshNetworkHealth();", snapshot)

        summary = threats.split("function renderThreats(s, full) {", 1)[1].split(chr(10) + "}", 1)[0]
        self.assertIn("refreshNetworkHealth();", summary)
        self.assertLess(summary.index("refreshNetworkHealth();"), summary.index('if (view !== "threats") return;'))

    def test_history_query_while_recording(self):
        with tempfile.TemporaryDirectory() as d:
            h = history.History(str(Path(d) / "h.db"))
            stop = threading.Event()

            def writer():
                i = 0
                while not stop.is_set():
                    h.record(f"dev{i % 5000}", 1.0, time.time())
                    i += 1

            t = threading.Thread(target=writer)
            t.start()
            try:
                for _ in range(300):
                    h.query("dev1", time.time() - 60, 1, 96)
            finally:
                stop.set()
                t.join()


if __name__ == "__main__":
    unittest.main()
