# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for safe YARA Forge package extraction and validation."""
import pathlib
import tempfile
import types
import unittest
import zipfile
from unittest.mock import patch

import yara_manager


class YaraManagerTests(unittest.TestCase):
    def test_extracts_only_rule_files_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            archive, stage = root / "rules.zip", root / "stage"
            stage.mkdir()
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("packages/core/malware/test.yar", "rule test { condition: true }")
                z.writestr("README.md", "not a rule")
            files, total = yara_manager._safe_extract_rules(archive, stage)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].relative_to(stage).as_posix(), "malware/test.yar")
            self.assertEqual(total, len("rule test { condition: true }"))

            bad = root / "bad.zip"
            with zipfile.ZipFile(bad, "w") as z:
                z.writestr("../escape.yar", "rule escape { condition: true }")
            with self.assertRaises(yara_manager.UpdateError):
                yara_manager._safe_extract_rules(bad, root / "bad-stage")

    def test_accepts_rule_file_larger_than_old_two_mib_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            archive, stage = root / "large.zip", root / "stage"
            stage.mkdir()
            payload = b"x" * (2 * 1024 * 1024 + 1)
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as z:
                z.writestr("packages/core/large.yar", payload)
            files, total = yara_manager._safe_extract_rules(archive, stage)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_size, len(payload))
            self.assertEqual(total, len(payload))

    def test_empty_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            archive, stage = root / "empty.zip", root / "stage"
            stage.mkdir()
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("readme.txt", "no rules")
            with self.assertRaises(yara_manager.UpdateError):
                yara_manager._safe_extract_rules(archive, stage)

    def test_release_digest_is_required(self):
        release = {"tag_name": "20261115", "draft": False, "prerelease": False,
                   "assets": [{"name": yara_manager.ASSET, "size": 100,
                               "browser_download_url": "https://github.com/YARAHQ/yara-forge/releases/download/20261115/rules.zip"}]}
        response = types.SimpleNamespace(read=lambda n: __import__("json").dumps(release).encode(),
                                         __enter__=lambda self: self, __exit__=lambda *a: None)
        with patch.object(yara_manager, "_request", return_value=response):
            with self.assertRaises(yara_manager.UpdateError):
                yara_manager._release()

    def test_validation_compiles_entire_package_with_includes_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = pathlib.Path(tmp) / "a.yar"
            f.write_text("rule a { condition: true }")
            seen = {}
            class Compiled:
                def match(self, data=None, timeout=None):
                    seen["timeout"] = timeout
                    return []
            def compile_rules(filepaths=None, includes=True):
                seen["filepaths"] = filepaths
                seen["includes"] = includes
                return Compiled()
            fake = types.SimpleNamespace(compile=compile_rules)
            with patch.dict("sys.modules", {"yara": fake}):
                yara_manager._validate([f])
            self.assertFalse(seen["includes"])
            self.assertEqual(len(seen["filepaths"]), 1)
            self.assertEqual(seen["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
