# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""AdGuard Home as a DNS source: login, paged query log, blocked reasons, timestamps and settings."""
import base64
import http.server
import json
import threading
import time
import unittest
import urllib.parse

import alerts
import dns


def stamp(t, tz="-05:00"):
    import datetime
    d = datetime.datetime.fromtimestamp(t, datetime.timezone(datetime.timedelta(hours=-5)))
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123" + tz


class Fake(http.server.BaseHTTPRequestHandler):
    entries: list = []
    calls: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        want = "Basic " + base64.b64encode(b"admin:secret").decode()
        if self.headers.get("Authorization") != want:
            self.send_response(401)
            self.end_headers()
            return
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        Fake.calls.append(self.path)
        if u.path == "/control/status":
            body = {"version": "v0.107.52", "running": True}
        elif u.path == "/control/querylog":
            limit = int(q.get("limit", ["500"])[0])
            rows = Fake.entries
            if "older_than" in q:
                cut = q["older_than"][0]
                rows = [r for r in rows if r["time"] < cut]
            page = rows[:limit]
            body = {"data": page, "oldest": page[-1]["time"] if page else ""}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def cfg(self, **k):
        return {"provider": "adguard", "url": self.url, "username": "admin", "password": "secret", **k}

    def setUp(self):
        now = time.time()
        Fake.calls = []
        Fake.entries = sorted([
            {"time": stamp(now - i), "client": "192.168.0.20", "client_info": {"name": "cam"}, "question": {"name": f"Host{i}.Example.com.", "type": "A"},
             "reason": ("FilteredBlackList" if i % 3 == 0 else "FilteredSafeSearch" if i == 1 else "NotFilteredNotFound")} for i in range(7)],
            key=lambda r: r["time"], reverse=True)

    def test_factory_picks_the_source(self):
        self.assertIsInstance(dns.make_client(self.cfg()), dns.AdGuardHome)
        self.assertIsInstance(dns.make_client({"url": "x"}), dns.PiHole)
        self.assertIsInstance(dns.make_client({"provider": "pihole"}), dns.PiHole)

    def test_reads_lookups_and_marks_blocks(self):
        c = dns.make_client(self.cfg())
        rows = c.queries(time.time() - 600, time.time())
        self.assertEqual(c.version, "0.107.52")
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[0]["domain"], "host6.example.com")            # oldest first, names lower-cased, no trailing dot
        self.assertEqual({r["client"] for r in rows}, {"192.168.0.20"})
        self.assertEqual(rows[0]["client_name"], "cam")
        self.assertEqual(sum(r["blocked"] for r in rows), 3)                # i = 0, 3, 6; safe-search is a rewrite, not a block

    def test_pages_through_a_busy_log_and_stops_at_the_start_of_the_window(self):
        now = time.time()
        Fake.entries = [{"time": stamp(now - i * 0.01), "client": "10.0.0.5", "question": {"name": "a.example"}, "reason": "NotFilteredNotFound"} for i in range(1200)]
        Fake.entries.sort(key=lambda r: r["time"], reverse=True)
        c = dns.make_client(self.cfg())
        rows = c.queries(now - 600, now)
        self.assertEqual(len(rows), 1200)
        self.assertEqual(len([p for p in Fake.calls if "querylog" in p]), 3)
        self.assertTrue(any("older_than" in p for p in Fake.calls))

    def test_reports_when_the_pagination_safety_limit_is_reached(self):
        now = time.time()
        Fake.entries = [{"time": stamp(now - i * 0.01), "client": "10.0.0.5", "question": {"name": "a.example"}, "reason": "NotFilteredNotFound"} for i in range(1200)]
        Fake.entries.sort(key=lambda r: r["time"], reverse=True)
        c = dns.make_client(self.cfg())
        c.MAX_PAGES = 2
        rows = c.queries(now - 600, now)
        self.assertEqual(rows, [])  # don't advance the monitor watermark with a partial window
        self.assertTrue(c.pagination_truncated)
        rows = c.queries(now - 600, now)
        self.assertEqual(len(rows), 1200)
        self.assertFalse(c.pagination_truncated)
        self.assertEqual(len({r["domain"] for r in rows}), 1)

    def test_old_entries_are_left_out(self):
        Fake.entries.append({"time": stamp(time.time() - 7200), "client": "1.1.1.1", "question": {"name": "old.example"}, "reason": ""})
        rows = dns.make_client(self.cfg()).queries(time.time() - 600, time.time())
        self.assertNotIn("old.example", [r["domain"] for r in rows])

    def test_wrong_password_and_unreachable_are_plain_errors(self):
        with self.assertRaises(dns.AdGuardError) as e:
            dns.make_client(self.cfg(password="nope")).queries(0, time.time())
        self.assertIn("username or password", str(e.exception))
        with self.assertRaises(dns.DnsSourceError):
            dns.make_client(self.cfg(url="http://127.0.0.1:1")).queries(0, time.time())

    def test_timestamps(self):
        self.assertAlmostEqual(dns.parse_rfc3339("2026-11-17T10:00:01.5Z"), dns.parse_rfc3339("2026-11-17T05:00:01.5-05:00"), places=3)
        self.assertAlmostEqual(dns.parse_rfc3339("2026-11-17T10:00:01.123456789+00:00") % 1, 0.123456, places=5)
        self.assertEqual(dns.parse_rfc3339("garbage"), 0.0)
        self.assertEqual(dns.parse_rfc3339(None), 0.0)

    def test_the_settings_test_button_reports_the_source(self):
        mon = dns.DnsMonitor.__new__(dns.DnsMonitor)
        r = dns.DnsMonitor.test(mon, self.cfg())
        self.assertTrue(r["ok"])
        self.assertEqual((r["source"], r["version"], r["recent"]), ("AdGuard Home", "0.107.52", 7))
        bad = dns.DnsMonitor.test(mon, self.cfg(password="x"))
        self.assertFalse(bad["ok"])


class Settings(unittest.TestCase):
    def base(self):
        import copy
        return copy.deepcopy(alerts.DEFAULT_SETTINGS) if True else None

    def test_provider_and_username_are_saved_and_cleaned(self):
        cur = self.base()
        if cur is None:
            self.skipTest("no DEFAULTS")
        new = alerts.apply_update(cur, {"dns": {"provider": "adguard", "username": "ad\x00:min", "url": "192.168.0.5:3000", "password": "pw"}})["dns"]
        self.assertEqual((new["provider"], new["username"], new["url"]), ("adguard", "admin", "http://192.168.0.5:3000"))
        new = alerts.apply_update(cur, {"dns": {"provider": "evil"}})["dns"]
        self.assertEqual(new["provider"], "pihole")

    def test_switching_source_forgets_the_saved_password(self):
        cur = self.base()
        if cur is None:
            self.skipTest("no DEFAULTS")
        cur["dns"].update(provider="pihole", url="http://192.168.0.5", password="pihole-secret")
        new = alerts.apply_update(cur, {"dns": {"provider": "adguard", "password": alerts.MASK}})["dns"]
        self.assertEqual(new["password"], "")


if __name__ == "__main__":
    unittest.main()
