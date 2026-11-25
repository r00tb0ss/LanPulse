# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Deleting public-scan history never removes a running scan and never resets the scan rate limits."""
import tempfile
import types
import unittest
from unittest.mock import patch

from public_scans import PublicScans


def rec(i, target, status, started):
    return {"id": i, "target": target, "scanner": "nmap", "status": status, "started": started, "finished": started}


class NmapHistoryDelete(unittest.TestCase):
    def make(self, tmp, rows):
        scans = PublicScans(tmp)
        scans.scans = {r["id"]: r for r in rows}
        return scans

    def test_deletes_only_finished_scans_and_selected_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.make(tmp, [rec("a", "8.8.8.8", "Done", 1), rec("b", "1.1.1.1", "Failed", 2), rec("c", "9.9.9.9", "Running", 3)])
            self.assertEqual(s.delete({"a", "c"}), 1)          # c is running: kept
            self.assertEqual(set(s.scans), {"b", "c"})
            self.assertEqual(s.delete(None), 1)                # clear all finished: running one still stays
            self.assertEqual(set(s.scans), {"c"})
            s.pool.shutdown(wait=False)

    def test_deleting_history_does_not_reset_the_cooldowns(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = 1_800_000_000
            s = self.make(tmp, [rec("a", "8.8.8.8", "Done", now - 30)])
            with patch("public_scans.time.time", return_value=now):
                s.delete(None)
                self.assertEqual(s.scans, {})
            with patch("public_scans.shutil.which", return_value="/usr/bin/nmap"), \
                    patch("public_scans.time.time", return_value=now + 5), patch.object(s.pool, "submit"):
                record, error = s.start_nmap("8.8.4.4")
                self.assertIsNone(record)
                self.assertIn("recently", error)               # global cooldown still applies
            with patch("public_scans.shutil.which", return_value="/usr/bin/nmap"), \
                    patch("public_scans.time.time", return_value=now + 120), patch.object(s.pool, "submit"):
                record, error = s.start_nmap("8.8.8.8")
                self.assertIsNone(record)
                self.assertIn("scanned recently", error)       # same target: per-target cooldown still applies
                record, error = s.start_nmap("1.0.0.1")
                self.assertEqual(error, "")                    # a different target is allowed after the global wait
            s.pool.shutdown(wait=False)

    def test_old_deleted_scans_leave_no_cooldown_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = 1_800_000_000
            s = self.make(tmp, [rec("a", "8.8.8.8", "Done", now - 86400)])
            with patch("public_scans.time.time", return_value=now):
                s.delete(None)
            self.assertEqual(s._cooldown_memory, {})
            s.pool.shutdown(wait=False)


class OpenVasHistoryDelete(unittest.TestCase):
    def test_public_only_finished_and_cooldown_kept(self):
        import openvas
        ov = openvas.OpenVAS.__new__(openvas.OpenVAS)
        now = 1_800_000_000
        ov.scans = {"8.8.8.8": {"public": True, "status": "Done", "started": now - 10},
                    "1.1.1.1": {"public": True, "status": "Running", "started": now - 5},
                    "192.168.0.9": {"status": "Done", "started": now - 10}}     # a LAN scan is not public history
        ov._public_cooldown_memory = {}
        ov._save = lambda: None
        with patch("openvas.time.time", return_value=now):
            self.assertEqual(ov.delete_public(None), 1)
        self.assertEqual(set(ov.scans), {"1.1.1.1", "192.168.0.9"})
        self.assertEqual(ov._public_cooldown_memory, {"8.8.8.8": now - 10})


if __name__ == "__main__":
    unittest.main()
