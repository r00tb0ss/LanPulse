# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Release metadata and download integrity checks."""
import hashlib
import io
import json
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

    SUM_URL = "https://github.com/lanpulse.zip.sha256"

    def tearDown(self):
        releases._cache.update(t=0.0, data=None)

    def _sources(self, answers):
        """Make latest() see the given answer per source; an Exception stands for a source that can't be reached."""
        asked = []

        def fake_open(url, timeout):
            if url == self.SUM_URL:
                return io.BytesIO(b"b" * 64 + b"  lanpulse.zip\n")
            kind = next(k for _l, k, u in releases.SOURCES if u == url)
            asked.append(kind)
            if isinstance(answers[kind], Exception):
                raise answers[kind]
            return io.BytesIO(json.dumps(answers[kind]).encode())
        return asked, patch.object(releases, "_open", side_effect=fake_open)

    @staticmethod
    def _pages(v):
        return {"tag": "v" + v, "version": v, "asset_url": "https://gitlab.com/lanpulse.zip", "sha256": "a" * 64}

    def _github(self, v):
        return {"tag_name": "v" + v, "assets": [
            {"name": "lanpulse.zip", "browser_download_url": "https://github.com/lanpulse.zip"},
            {"name": "lanpulse.zip.sha256", "browser_download_url": self.SUM_URL}]}

    def test_a_newer_release_on_github_is_found_when_gitlab_is_behind(self):
        asked, opened = self._sources({"pages": self._pages("1.35.0"), "github": self._github("1.35.2")})
        with opened:
            r = releases.latest("1.35.0", force=True)
        self.assertEqual((r["version"], r["source"], r["newer"], r["sha256"]), ("1.35.2", "GitHub", True, "b" * 64))
        self.assertEqual(asked, ["pages", "github"])               # GitLab's API is not asked again after Pages answers

    def test_gitlab_is_kept_when_github_has_the_same_or_older_or_is_down(self):
        for github in (self._github("1.35.2"), self._github("1.35.0"), OSError("down")):
            asked, opened = self._sources({"pages": self._pages("1.35.2"), "github": github})
            with opened:
                r = releases.latest("1.35.0", force=True)
            self.assertEqual((r["version"], r["source"], r["sha256"]), ("1.35.2", "GitLab Pages", "a" * 64))

    def test_github_alone_is_enough_when_gitlab_cannot_be_reached(self):
        asked, opened = self._sources({"pages": OSError("down"), "gitlab": OSError("down"), "github": self._github("1.35.2")})
        with opened:
            r = releases.latest("1.35.1", force=True)
        self.assertEqual((r["version"], r["source"], asked), ("1.35.2", "GitHub", ["pages", "gitlab", "github"]))

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
