# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_ui


class BackupSettingsHelpers(unittest.TestCase):
    def test_backup_directory_can_be_configured_with_absolute_path(self):
        configured = backup_ui.configured_backup_dir({"LANPULSE_BACKUP_DIR": "/mnt/private/backups"})
        self.assertEqual(configured, Path("/mnt/private/backups"))

    def test_backup_directory_rejects_relative_environment_path(self):
        with self.assertRaises(ValueError):
            backup_ui.configured_backup_dir({"LANPULSE_BACKUP_DIR": "relative/backups"})

    def test_backup_directory_keeps_default_when_unset(self):
        self.assertEqual(
            backup_ui.configured_backup_dir({}),
            Path("/var/backups/lanpulse"),
        )

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
                    backup_ui.backup_archive_path(invalid, root)

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
                backup_ui.backup_archive_path(link.name, root)

class BackupDeletion(unittest.TestCase):
    NAMES = [f"lanpulse-2026111{d}T120000000000Z.tar.gz" for d in range(1, 6)]

    def make(self, root):
        for n in self.NAMES:
            (root / n).write_bytes(b"x")
        (root / "notes.txt").write_text("not a backup")
        (root / "lanpulse-latest.tar.gz").write_bytes(b"not a generated name")

    def test_deletes_exactly_one_named_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); self.make(root)
            backup_ui.delete_backup_archive(self.NAMES[0], root)
            self.assertFalse((root / self.NAMES[0]).exists())
            self.assertEqual(len(backup_ui.list_backup_archives(root)), 4)

    def test_refuses_names_that_are_not_generated_backups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); self.make(root)
            for bad in ("notes.txt", "../notes.txt", "lanpulse-latest.tar.gz", "/etc/passwd", ""):
                with self.assertRaises(ValueError):
                    backup_ui.delete_backup_archive(bad, root)
            self.assertTrue((root / "notes.txt").exists() and (root / "lanpulse-latest.tar.gz").exists())

    def test_prune_keeps_the_newest_and_touches_nothing_else(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); self.make(root)
            removed = backup_ui.prune_backups(2, root)
            self.assertEqual(sorted(removed), sorted(self.NAMES[:3]))
            self.assertEqual([b["name"] for b in backup_ui.list_backup_archives(root)], [self.NAMES[4], self.NAMES[3]])
            self.assertTrue((root / "notes.txt").exists() and (root / "lanpulse-latest.tar.gz").exists())

    def test_prune_zero_or_larger_than_count_removes_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); self.make(root)
            self.assertEqual(backup_ui.prune_backups(0, root), [])
            self.assertEqual(backup_ui.prune_backups(50, root), [])
            self.assertEqual(len(backup_ui.list_backup_archives(root)), 5)

    def test_a_symlink_named_like_a_backup_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp); target = Path(outside) / "precious"; target.write_text("keep me")
            link = root / "lanpulse-20261101T120000000000Z.tar.gz"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                backup_ui.delete_backup_archive(link.name, root)
            self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
