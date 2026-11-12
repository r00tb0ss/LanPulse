# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Release metadata and download integrity checks."""
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import releases


class ReleaseChecksumTests(unittest.TestCase):
    def test_pages_metadata_requires_and_preserves_sha256(self):
        digest = "a" * 64
        parsed = releases._parse("pages", {
            "tag": "v1.2.3", "version": "1.2.3",
            "asset_url": "https://gitlab.com/example/lanpulse.zip",
            "sha256": digest,
        })
        self.assertEqual(parsed["sha256"], digest)
        self.assertEqual(parsed["version"], "1.2.3")

    def test_gitlab_release_finds_exact_zip_and_checksum_assets(self):
        parsed = releases._parse("gitlab", {
            "tag_name": "v1.2.3",
            "assets": {"links": [
                {"name": "source.zip", "url": "https://gitlab.com/source.zip"},
                {"name": "lanpulse.zip", "url": "https://gitlab.com/lanpulse.zip"},
                {"name": "lanpulse.zip.sha256", "url": "https://gitlab.com/lanpulse.zip.sha256"},
            ]},
        })
        self.assertEqual(parsed["asset_url"], "https://gitlab.com/lanpulse.zip")
        self.assertEqual(parsed["checksum_url"], "https://gitlab.com/lanpulse.zip.sha256")

    def test_download_accepts_matching_checksum(self):
        payload = b"trusted release archive"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "lanpulse.zip"
            with patch.object(releases, "_open", return_value=io.BytesIO(payload)):
                size = releases.download("https://gitlab.com/lanpulse.zip", target, 1024, digest)
            self.assertEqual(size, len(payload))
            self.assertEqual(target.read_bytes(), payload)

    def test_download_rejects_modified_release_and_removes_partial_file(self):
        payload = b"modified release archive"
        expected = hashlib.sha256(b"original release archive").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "lanpulse.zip"
            with patch.object(releases, "_open", return_value=io.BytesIO(payload)):
                with self.assertRaisesRegex(ValueError, "SHA-256 verification"):
                    releases.download("https://gitlab.com/lanpulse.zip", target, 1024, expected)
            self.assertFalse(target.exists())

    def test_download_refuses_missing_or_malformed_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "lanpulse.zip"
            with self.assertRaisesRegex(ValueError, "valid SHA-256 checksum"):
                releases.download("https://gitlab.com/lanpulse.zip", target, 1024, "not-a-checksum")
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
