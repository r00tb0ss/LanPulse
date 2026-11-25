import unittest
from unittest.mock import Mock, patch

from openvas import OpenVAS


class OpenVASPublicLimits(unittest.TestCase):
    def make_scanner(self):
        scanner = OpenVAS.__new__(OpenVAS)
        scanner.scans = {}
        scanner._save = Mock()
        return scanner

    def test_public_target_has_one_hour_cooldown(self):
        scanner = self.make_scanner()
        now = 1_800_000_000
        scanner.scans["8.8.8.8"] = {
            "public": True, "status": "Done", "started": now - 60
        }
        with patch("openvas.time.time", return_value=now):
            error = scanner.start_scan("8.8.8.8", authorized_public=True)
        self.assertIn("public target was scanned recently", error)

    def test_public_openvas_has_global_cooldown_between_targets(self):
        scanner = self.make_scanner()
        now = 1_800_000_000
        scanner.scans["1.1.1.1"] = {
            "public": True, "status": "Done", "started": now - 10
        }
        with patch("openvas.time.time", return_value=now):
            error = scanner.start_scan("8.8.8.8", authorized_public=True)
        self.assertIn("public OpenVAS scan was started recently", error)

    def test_history_pruning_keeps_newest_hundred_and_active_tasks(self):
        scanner = self.make_scanner()
        now = 1_800_000_000
        scanner.scans = {
            str(i): {"status": "Done", "started": now - i}
            for i in range(scanner.MAX_HISTORY + 25)
        }
        scanner.scans["active"] = {"status": "Running", "started": now}
        scanner._prune_history()
        self.assertEqual(len(scanner.scans), scanner.MAX_HISTORY + 1)
        self.assertIn("active", scanner.scans)
        self.assertIn("0", scanner.scans)
        self.assertNotIn(str(scanner.MAX_HISTORY + 24), scanner.scans)
        scanner._save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
