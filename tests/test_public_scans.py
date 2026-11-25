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
