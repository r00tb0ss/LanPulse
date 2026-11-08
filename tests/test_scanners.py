# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanners


class ScannerLookupTests(unittest.TestCase):
    def test_dns_hiccup_is_not_an_answer(self):
        with mock.patch("socket.gethostbyaddr", side_effect=socket.herror(2, "try again")):
            with self.assertRaises(LookupError):
                scanners.classify("198.51.100.5")

    def test_address_without_a_name_is_not_a_scanner(self):
        with mock.patch("socket.gethostbyaddr", side_effect=socket.herror(1, "not found")):
            self.assertIsNone(scanners.classify("198.51.100.5"))

    def test_confirmed_scanner(self):
        with mock.patch("socket.gethostbyaddr", return_value=("scan-1.shodan.io", [], ["198.51.100.5"])), \
                mock.patch("socket.gethostbyname_ex", return_value=("scan-1.shodan.io", [], ["198.51.100.5"])):
            self.assertEqual(scanners.classify("198.51.100.5")["label"], "Shodan")


if __name__ == "__main__":
    unittest.main()
