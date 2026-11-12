# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Regression tests for session invalidation when dashboard credentials change."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth


class PasswordChangeSessions(unittest.TestCase):
    def test_password_change_invalidates_old_sessions_and_preserves_new_one(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            manager = auth.Auth(path)
            manager.set_password("admin", "old-password")
            old_cookie = manager.make_session("admin")
            old_secret = manager.data["secret"]

            self.assertEqual(manager.verify(old_cookie), "admin")

            manager.set_password("admin", "new-password")
            self.assertNotEqual(manager.data["secret"], old_secret)
            self.assertIsNone(manager.verify(old_cookie))
            self.assertFalse(manager.check("admin", "old-password"))
            self.assertTrue(manager.check("admin", "new-password"))

            new_cookie = manager.make_session("admin")
            self.assertEqual(manager.verify(new_cookie), "admin")

            # A restarted process must also reject the old cookie and accept
            # the new one using the persisted signing secret.
            restarted = auth.Auth(path)
            self.assertIsNone(restarted.verify(old_cookie))
            self.assertEqual(restarted.verify(new_cookie), "admin")


if ( __name__ == "__main__" ):
    unittest.main()
