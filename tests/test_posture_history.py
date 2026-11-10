# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from posture import PostureHistory


class PostureHistoryTests(unittest.TestCase):
    def test_failed_write_can_be_retried_for_same_score(self):
        with tempfile.TemporaryDirectory() as d:
            h = PostureHistory(str(Path(d) / "posture.db"))
            h.db.execute("""
                CREATE TRIGGER reject_cleanup BEFORE DELETE ON posture
                BEGIN SELECT RAISE(ABORT, 'temporary write failure'); END
            """)
            h.db.commit()

            with self.assertRaises(sqlite3.IntegrityError):
                h.record(82, "B")

            # Simulate recovery from the failed transaction before retrying.
            h.db.rollback()
            h.db.execute("DROP TRIGGER reject_cleanup")
            h.db.commit()
            h.record(82, "B")

            rows = h.history()
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["score"], rows[0]["grade"]), (82, "B"))
            h.db.close()

    def test_last_score_is_tracked_per_database_instance(self):
        with tempfile.TemporaryDirectory() as d:
            first = PostureHistory(str(Path(d) / "first.db"))
            second = PostureHistory(str(Path(d) / "second.db"))

            first.record(82, "B")
            second.record(82, "B")

            self.assertEqual(len(first.history()), 1)
            self.assertEqual(len(second.history()), 1)
            first.db.close()
            second.db.close()


if __name__ == "__main__":
    unittest.main()
