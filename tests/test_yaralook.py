# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Optional YARA matching. The yara package may not be installed, so the scanner is replaced by a stand-in here;
the real package is exercised by the same calls in production."""
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

import honeyanalysis as ha
import yaralook


class FakeMatch:
    def __init__(self, rule, tags=(), meta=None, strings=()):
        self.rule, self.tags, self.meta, self.strings = rule, list(tags), meta or {}, list(strings)


class FakeRules:
    def __init__(self, path):
        self.path = path

    calls = 0

    def match(self, data=None, timeout=None):
        type(self).calls += 1
        if b"BAD" in pathlib.Path(self.path).read_bytes():
            raise RuntimeError("scan blew up")
        return [FakeMatch("Mirai_like", ["botnet"], {"description": "needs\x1b review"}, [1, 2])] if b"botnet" in data else []


def fake_compile(filepath=None, includes=True):
    assert includes is False                                   # a rule must not be able to include other files
    if "broken" in filepath:
        raise SyntaxError("line 3: unexpected token")
    return FakeRules(filepath)


FAKE = types.SimpleNamespace(compile=fake_compile)


class Rules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_nothing_happens_without_the_package_or_rules(self):
        with patch.object(yaralook, "yara", None):
            (self.dir / "a.yar").write_text("rule a { condition: true }")
            s = yaralook.YaraRules(self.dir).scan(b"x")
        self.assertEqual((s["available"], s["files"], s["loaded"], s["matches"]), (False, 1, 0, []))
        with patch.object(yaralook, "yara", FAKE):
            s = yaralook.YaraRules(self.dir / "missing").scan(b"x")
        self.assertEqual((s["files"], s["matches"]), (0, []))

    def test_matches_are_reported_and_a_broken_file_does_not_hide_the_rest(self):
        (self.dir / "good.yar").write_text("rule ok { condition: true }")
        (self.dir / "broken.yar").write_text("rule {")
        (self.dir / "notes.txt").write_text("not a rule file")
        with patch.object(yaralook, "yara", FAKE):
            r = yaralook.YaraRules(self.dir)
            s = r.scan(b"a botnet sample")
            self.assertEqual((s["files"], s["loaded"]), (2, 1))
            self.assertEqual([m["rule"] for m in s["matches"]], ["Mirai_like"])
            self.assertEqual(s["matches"][0]["description"], "needs review")      # the control character is dropped
            self.assertTrue(s["matches"][0]["description"].isprintable())
            self.assertTrue(any("broken.yar" in e for e in s["errors"]))
            self.assertEqual(r.scan(b"clean")["matches"], [])

    def test_a_failing_scan_is_reported_and_other_rules_still_run(self):
        (self.dir / "a.yar").write_text("BAD")
        (self.dir / "b.yar").write_text("rule b { condition: true }")
        with patch.object(yaralook, "yara", FAKE):
            s = yaralook.YaraRules(self.dir).scan(b"botnet")
        self.assertEqual([m["file"] for m in s["matches"]], ["b.yar"])
        self.assertTrue(any("a.yar: scan stopped" in e for e in s["errors"]))

    def test_changed_files_are_picked_up_and_the_rest_are_cached(self):
        (self.dir / "a.yar").write_text("rule a { condition: true }")
        with patch.object(yaralook, "yara", FAKE):
            r = yaralook.YaraRules(self.dir)
            r.scan(b"x")
            first = r._rules
            r.scan(b"x")
            self.assertIs(r._rules, first)                       # nothing changed: not compiled again
            (self.dir / "b.yar").write_text("rule b { condition: true }")
            self.assertEqual(r.status()["loaded"], 2)

    def test_rule_file_larger_than_old_two_megabyte_limit_is_loaded(self):
        (self.dir / "large.yar").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        with patch.object(yaralook, "yara", FAKE):
            s = yaralook.YaraRules(self.dir).status()
        self.assertEqual((s["files"], s["loaded"]), (1, 1))
        self.assertEqual(s["errors"], [])

    def test_oversized_and_linked_rule_files_are_skipped(self):
        (self.dir / "big.yar").write_bytes(b"x" * (yaralook.MAX_RULE_BYTES + 1))
        (self.dir / "real.txt").write_text("x")
        (self.dir / "link.yar").symlink_to(self.dir / "real.txt")
        with patch.object(yaralook, "yara", FAKE):
            s = yaralook.YaraRules(self.dir).status()
        self.assertEqual((s["files"], s["loaded"]), (1, 0))
        self.assertTrue(any("big.yar: skipped" in e for e in s["errors"]))

    def test_staging_and_previous_package_folders_are_not_rules_in_use(self):
        for sub in (".yara-update-abc/managed", ".managed-previous"):
            (self.dir / sub).mkdir(parents=True)
            (self.dir / sub / "old.yar").write_text("rule old { condition: true }")
        (self.dir / "managed").mkdir()
        (self.dir / "managed" / "forge.yar").write_text("rule f { condition: true }")
        (self.dir / "mine.yar").write_text("rule m { condition: true }")
        with patch.object(yaralook, "yara", FAKE):
            s = yaralook.YaraRules(self.dir).status()
        self.assertEqual((s["managed_files"], s["custom_files"]), (1, 1))

    def test_scans_from_several_threads_during_reloads_always_find_the_match(self):
        import threading
        (self.dir / "bot.yar").write_text("rule x { condition: true }")
        misses, stop = [], threading.Event()
        with patch.object(yaralook, "yara", FAKE):
            rules = yaralook.YaraRules(self.dir)

            def scan():
                while not stop.is_set():
                    if not rules.scan(b"botnet")["matches"]:
                        misses.append(1)

            threads = [threading.Thread(target=scan) for _ in range(4)]
            [t.start() for t in threads]
            for i in range(40):
                tmp = self.dir / "bot.tmp"
                tmp.write_text("rule x%d { condition: true }" % i)
                tmp.replace(self.dir / "bot.yar")          # swapped in whole, like the rule updater does
            stop.set()
            [t.join() for t in threads]
        self.assertEqual(misses, [])


class FakeHp:
    cfg = {}

    def _geo(self, ip):
        return {"iso": "", "country": "", "city": "", "org": "", "asn": None}

    def record(self, *a, **k):
        pass


class InTheFileView(unittest.TestCase):
    def test_file_view_gets_yara_only_when_rule_files_exist(self):
        with tempfile.TemporaryDirectory() as t, patch.object(yaralook, "yara", FAKE):
            nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(t), notify_plain=lambda *a: None)
            h = ha.HoneyAnalysis(nm, FakeHp())
            ok, sha = h.add_sample(b"#!/bin/sh\necho botnet\n", {"ip": "198.51.100.7"}, quiet=True)
            self.assertEqual(h.sample(sha)["yara"]["scan_status"], "no_rules")
            (pathlib.Path(t) / "yara-rules").mkdir()
            (pathlib.Path(t) / "yara-rules" / "bot.yar").write_text("rule x { condition: true }")
            first = h.sample(sha)["yara"]
            self.assertEqual([m["rule"] for m in first["matches"]], ["Mirai_like"])
            self.assertEqual(first["scan_status"], "complete")
            self.assertTrue(first["rules_fingerprint"])
            calls = FakeRules.calls
            cached = h.sample(sha)["yara"]
            self.assertEqual(cached["rules_fingerprint"], first["rules_fingerprint"])
            self.assertEqual(FakeRules.calls, calls)
            (pathlib.Path(t) / "yara-rules" / "bot.yar").write_text("rule changed { condition: true }")
            refreshed = h.sample(sha)["yara"]
            self.assertNotEqual(refreshed["rules_fingerprint"], first["rules_fingerprint"])
            self.assertGreater(FakeRules.calls, calls)

    def test_big_uploads_are_not_scanned_during_ingest_but_small_ones_are(self):
        with tempfile.TemporaryDirectory() as t, patch.object(yaralook, "yara", FAKE):
            nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(t), notify_plain=lambda *a: None)
            h = ha.HoneyAnalysis(nm, FakeHp())
            ok, small = h.add_sample(b"#!/bin/sh\necho botnet\n", {"ip": "198.51.100.7"}, quiet=True)
            ok, big = h.add_sample(b"#!/bin/sh\n" + b"# pad\n" * (ha.YARA_INGEST_MAX // 6 + 10), {"ip": "198.51.100.7"}, quiet=True)
            rows = {r["sha256"]: r for r in h.samples()["samples"]}
            self.assertEqual(rows[small]["yara_status"], "no_rules")
            self.assertEqual(rows[big]["yara_status"], "pending")
            self.assertEqual(h.sample(big)["yara"]["scan_status"], "no_rules")      # scanned the first time it is opened

    def test_scores_come_with_the_evidence_behind_them(self):
        a = ha.analyze_sample(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 200)
        self.assertEqual(a["score"], sum(e["points"] for e in a["score_evidence"]))
        self.assertTrue(a["score_evidence"])
        self.assertIn("not a probability", a["score_explanation"])


class RootHelper(unittest.TestCase):
    def test_planted_links_are_not_followed(self):
        import subprocess, os
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            d, victim = t / "yara", t / "victim.txt"
            d.mkdir()
            victim.write_text("keep me")
            for name in ("log.txt", "status.json.tmp"):
                (d / name).symlink_to(victim)
            (d / "request").write_text('{"action": "bogus"}')
            helper = pathlib.Path(__file__).resolve().parent.parent / "yara-helper.sh"
            subprocess.run(["bash", str(helper)], env={**os.environ, "LANPULSE_YARA_DIR": str(d)}, capture_output=True, timeout=30)
            self.assertEqual(victim.read_text(), "keep me")
            self.assertFalse((d / "log.txt").is_symlink())
            self.assertIn("Unknown YARA", (d / "status.json").read_text())
            link = t / "linked"
            link.symlink_to(d)
            r = subprocess.run(["bash", str(helper)], env={**os.environ, "LANPULSE_YARA_DIR": str(link)}, capture_output=True, timeout=30)
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
