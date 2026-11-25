import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from public_scans import PublicScans, validate_public_ipv4


class PublicTargetValidation(unittest.TestCase):
    def test_accepts_global_ipv4(self):
        self.assertEqual(validate_public_ipv4("8.8.8.8"), "8.8.8.8")

    def test_rejects_private_reserved_and_invalid_targets(self):
        for value in ("192.168.1.1", "127.0.0.1", "169.254.1.2", "224.0.0.1",
                      "0.0.0.0", "255.255.255.255", "2001:4860:4860::8888", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_public_ipv4(value)


class PublicScanQueue(unittest.TestCase):
    def test_scan_is_queued_once_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = PublicScans(tmp)
            try:
                with patch("public_scans.shutil.which", return_value="/usr/bin/nmap"):
                    with patch.object(scans.pool, "submit") as submit:
                        record, error = scans.start_nmap("8.8.8.8")
                        self.assertFalse(error)
                        self.assertEqual(record["status"], "Requested")
                        self.assertEqual(record["scope"], "top-1000-tcp-ports")
                        self.assertEqual(submit.call_count, 1)
                        duplicate, error = scans.start_nmap("1.1.1.1")
                        self.assertIsNone(duplicate)
                        self.assertIn("already queued or running", error)
                saved = json.loads((Path(tmp) / "authorized-public-scans.json").read_text())
                self.assertEqual(len(saved), 1)
                self.assertEqual(next(iter(saved.values()))["target"], "8.8.8.8")
            finally:
                scans.close()

    def test_nmap_progress_and_phase_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = PublicScans(tmp)
            try:
                scans.scans["scan1"] = {"id": "scan1", "status": "Running", "progress": 0}
                scans._update_progress("scan1",
                    "Stats: 0:00:10 elapsed; 0 hosts completed, 1 undergoing SYN Stealth Scan; About 42.50% done")
                row = scans.list()[0]
                self.assertEqual(row["progress"], 42)
                self.assertEqual(row["phase"], "SYN Stealth Scan")
            finally:
                scans.close()

    def test_nmap_progress_parser_persists_carriage_return_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = PublicScans(tmp)
            try:
                scans.scans["abc"] = {"id": "abc", "status": "Running", "progress": 0}
                scans._update_progress("abc", "About 42.50% done; ETC: 00:01:30")
                row = scans.scans["abc"]
                self.assertEqual(row["progress"], 42)
                self.assertTrue(row["phase"])
                self.assertIn("updated", row)
            finally:
                scans.close()

    def test_nmap_progress_is_persisted_for_the_status_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = PublicScans(tmp)
            try:
                with scans.lock:
                    scans.scans["abc"] = {"id": "abc", "target": "8.8.8.8",
                                          "status": "Running", "progress": 0}
                scans._update_progress("abc", "About 42.50% done; ETC: 00:03:12")
                row = scans.list()[0]
                self.assertEqual(row["progress"], 42)
                self.assertIn("updated", row)
                self.assertEqual(row["status"], "Running")
            finally:
                scans.close()

    def test_nmap_progress_does_not_change_terminal_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = PublicScans(tmp)
            try:
                with scans.lock:
                    scans.scans["abc"] = {"id": "abc", "target": "8.8.8.8",
                                          "status": "Done", "progress": 100}
                scans._update_progress("abc", "About 75% done")
                row = scans.list()[0]
                self.assertEqual(row["progress"], 100)
                self.assertEqual(row["status"], "Done")
            finally:
                scans.close()

    def test_inflight_scan_is_marked_interrupted_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authorized-public-scans.json"
            path.write_text(json.dumps({"abc": {"id": "abc", "target": "8.8.8.8",
                                                  "status": "Running", "started": 1}}))
            scans = PublicScans(tmp)
            try:
                row = scans.list()[0]
                self.assertEqual(row["status"], "Interrupted")
                self.assertIn("restarted", row["error"])
            finally:
                scans.close()


if __name__ == "__main__":
    unittest.main()
