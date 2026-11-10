# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_ui


class BackupSettingsHelpers(unittest.TestCase):
    def test_lists_only_regular_lanpulse_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = root / "lanpulse-20261110T182337123456Z.tar.gz"
            good.write_bytes(b"backup")
            (root / "other.tar.gz").write_bytes(b"not a LanPulse backup")
            (root / "lanpulse-20261110T182337123456Z.txt").write_bytes(b"not an archive")
            try:
                (root / "lanpulse-20261110T182337654321Z.tar.gz").symlink_to(good)
            except OSError:
                pass

            backups = backup_ui.list_backup_archives(root)
            self.assertEqual([item["name"] for item in backups], [good.name])
            self.assertEqual(backups[0]["size"], 6)
            self.assertTrue(backups[0]["created"])

    def test_download_path_accepts_only_generated_backup_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = root / "lanpulse-20261110T182337123456Z.tar.gz"
            good.write_bytes(b"backup")
            self.assertEqual(backup_ui.backup_archive_path(good.name, root), good)
            for invalid in ("../secret.tar.gz", "other.tar.gz", good.name + "/.."):
                with self.assertRaises(ValueError):
                    app.backup_archive_path(invalid, root)

    def test_download_path_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "private"
            target.write_bytes(b"secret")
            link = root / "lanpulse-20261110T182337123456Z.tar.gz"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("Symlinks are unavailable on this platform")
            with self.assertRaises(ValueError):
                app.backup_archive_path(link.name, root)


if __name__ == "__main__":
    unittest.main()
