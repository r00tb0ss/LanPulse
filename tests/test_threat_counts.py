# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threats import merge_counted


class MergeCounted(unittest.TestCase):
    def test_identical_lines_become_one_row(self):
        rows = [{"text": "connected and sent nothing before the timeout", "count": 1} for _ in range(16)]
        self.assertEqual(merge_counted(rows), [{"text": "connected and sent nothing before the timeout", "count": 16}])

    def test_counts_add_up_and_order_is_kept(self):
        rows = [{"text": "root / admin", "count": 3}, {"text": "GET /", "count": 1}, {"text": "root / admin", "count": 2},
                {"text": "GET /", "count": 1}]
        self.assertEqual(merge_counted(rows), [{"text": "root / admin", "count": 5}, {"text": "GET /", "count": 2}])

    def test_limit(self):
        rows = [{"text": f"line {i}", "count": 1} for i in range(40)]
        self.assertEqual(len(merge_counted(rows)), 20)
        self.assertEqual(len(merge_counted(rows, limit=5)), 5)


if __name__ == "__main__":
    unittest.main()
