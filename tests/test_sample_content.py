# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Reading a whole captured file in the dashboard, and keeping long commands."""
import importlib.util
import os
import pathlib
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import honeyanalysis as ha

spec = importlib.util.spec_from_file_location("fwd_content", os.path.join(ROOT, "tools", "pi-honeypot", "lanpulse-forwarder.py"))
fwd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fwd)


class FakeHp:
    cfg = {}

    def _geo(self, ip):
        return {"iso": "", "country": "", "city": "", "org": "", "asn": None}

    def record(self, *a, **k):
        pass


class WholeFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name),
                                   notify_plain=lambda *a: None)
        self.h = ha.HoneyAnalysis(nm, FakeHp())

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_script_is_returned_whole_across_pages(self):
        data = b"#!/bin/sh\n" + b"".join(b"echo line %06d of the dropper\n" % i for i in range(20000))
        self.assertGreater(len(data), ha.VIEW_TEXT)
        ok, sha = self.h.add_sample(data, {"ip": "198.51.100.7"}, quiet=True)
        self.assertTrue(ok)
        text, offset, pages = "", 0, 0
        while offset is not None:
            r = self.h.sample_content(sha, offset)
            self.assertEqual((r["mode"], r["size"], r["stored"]), ("text", len(data), True))
            self.assertTrue(r["text"].endswith("\n"))               # pages end on a line break
            text, offset, pages = text + r["text"], r["next"], pages + 1
        self.assertGreater(pages, 1)
        self.assertEqual(text.encode(), data)
        self.assertTrue(r["path"].endswith(sha))

    def test_binaries_get_a_hex_listing_and_text_is_made_inert(self):
        ok, sha = self.h.add_sample(b"\x7fELF" + bytes(range(256)) * 4, {}, quiet=True)
        r = self.h.sample_content(sha)
        self.assertEqual(r["mode"], "hex")
        self.assertTrue(r["text"].startswith("00000000  7f 45 4c 46"))
        self.assertIn("|.ELF", r["text"])
        self.assertEqual(self.h.sample_content(sha, 16, "hex")["text"][:8], "00000010")
        shown = ha.inert_text(b"a\x1b[2Jb\xe2\x80\xaec\r\n<script>\x00")
        self.assertEqual(shown, "a�[2Jb�c\n<script>�")

    def test_missing_removed_and_bad_names(self):
        for bad in ("../../etc/passwd", "zz", "", "a" * 64):
            self.assertIsNone(self.h.sample_content(bad))
        ok, sha = self.h.add_sample(b"#!/bin/sh\necho gone\n", {}, quiet=True)
        (pathlib.Path(self.tmp.name) / "honeypot-samples" / sha).unlink()
        self.assertFalse(self.h.sample_content(sha)["stored"])
        self.assertEqual(self.h.sample_content(sha, "x")["stored"], False)

    def test_long_commands_are_kept_within_a_session_budget(self):
        long = "echo " + "A" * 20000
        self.h.add_session({"session": "long1", "ip": "198.51.100.7", "commands": [long] * 60}, quiet=True)
        cmds = [c["cmd"] for c in self.h.session("long1")["commands"]]
        self.assertEqual(len(cmds[0]), ha.MAX_CMD_LEN)
        self.assertEqual(len(cmds[-1]), 200)                        # past the budget, commands are cut short
        self.assertLessEqual(sum(map(len, cmds)), ha.MAX_CMD_TOTAL + ha.MAX_CMD_LEN + 200 * len(cmds))


class ForwarderKeepsLongCommands(unittest.TestCase):
    def test_commands_are_kept_up_to_the_new_limit(self):
        s = fwd.Sessions("pi")
        s.feed({"eventid": "cowrie.session.connect", "session": "abc", "src_ip": "198.51.100.7", "timestamp": "2026-11-15T00:00:00Z"})
        for _ in range(50):
            s.feed({"eventid": "cowrie.command.input", "session": "abc", "input": "x" * 20000})
        done = s.feed({"eventid": "cowrie.session.closed", "session": "abc"})
        self.assertEqual(len(done["commands"][0]), fwd.MAX_CMD)
        self.assertEqual(len(done["commands"][-1]), 200)
        self.assertNotIn("_cmd_chars", fwd.public_session(done))
        self.assertLess(len(__import__("json").dumps(fwd.public_session(done))), 1_900_000)
        self.assertEqual(fwd.MAX_FILE, ha.MAX_SAMPLE)


if __name__ == "__main__":
    unittest.main()
