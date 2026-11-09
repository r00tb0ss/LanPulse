#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
LanPulse forwarder for a Cowrie honeypot (runs on the Raspberry Pi, Python 3 standard library only).

It follows Cowrie's JSON log, groups the events into one record per attacker session (logins tried, every command
typed, files downloaded or uploaded) and sends each finished session to LanPulse. It also uploads the captured files
so LanPulse can analyse them. It only ever sends data OUT to your LanPulse server; it opens no ports and never runs
anything it captured.

Settings come from environment variables (the installer writes /etc/lanpulse-forwarder.env):
  LANPULSE_URL          e.g. https://192.168.0.208:8080
  LANPULSE_KEY          the sensor key from LanPulse > Honeypot > Add sensor
  LANPULSE_FINGERPRINT  optional SHA-256 of the server certificate to trust (LanPulse uses a self-signed one)
  LANPULSE_INSECURE     set to 1 to skip certificate checks (only on a network you trust)
  COWRIE_HOME           default /home/cowrie/cowrie
  SENSOR_NAME           default the Pi's host name
  STATE_FILE            default /var/lib/lanpulse-forwarder/state.json
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE = 5 * 1024 * 1024
IDLE_FLUSH = 600            # send a session that never got a "closed" event after this many quiet seconds
HELLO_EVERY = 60            # seconds between 'I am alive' messages
MAX_OPEN = 2000
MAX_OUTBOX = 3000


def parse_ts(s: str) -> float:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except (ValueError, TypeError):
        return time.time()


class Sessions:
    """Turns Cowrie events into finished session records."""

    def __init__(self, sensor: str):
        self.sensor = sensor
        self.open: dict[str, dict] = {}

    def feed(self, ev: dict):
        """Returns a finished session dict when this event closes one, else None."""
        eid, sid = ev.get("eventid", ""), ev.get("session")
        if not sid or not isinstance(sid, str):
            return None
        s = self.open.get(sid)
        if eid == "cowrie.session.connect":
            if len(self.open) >= MAX_OPEN:
                self.open.pop(next(iter(self.open)))
            self.open[sid] = s = {"session": sid, "sensor": self.sensor, "ip": ev.get("src_ip", ""),
                                  "port": ev.get("dst_port", 0), "proto": "telnet" if ev.get("protocol") == "telnet" else "ssh",
                                  "start": parse_ts(ev.get("timestamp")), "end": parse_ts(ev.get("timestamp")),
                                  "client": "", "hassh": "", "logins": [], "commands": [], "files": [], "_seen": time.time()}
            return None
        if s is None:
            return None
        s["_seen"] = time.time()
        s["end"] = max(s["end"], parse_ts(ev.get("timestamp")))
        if eid == "cowrie.client.version":
            s["client"] = str(ev.get("version", ""))[:120]
        elif eid == "cowrie.client.kex":
            s["hassh"] = str(ev.get("hassh", ""))[:40]
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            s["logins"].append({"u": str(ev.get("username", ""))[:64], "p": str(ev.get("password", ev.get("fingerprint", "")))[:64],
                                "ok": eid.endswith("success")})
        elif eid == "cowrie.command.input":
            s["commands"].append(str(ev.get("input", ""))[:1000])
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = str(ev.get("shasum", "")).lower()
            if HEX64.match(sha):
                s["files"].append({"sha256": sha, "url": str(ev.get("url", ""))[:300], "outfile": str(ev.get("outfile", ""))[:300],
                                   "name": os.path.basename(str(ev.get("destfile") or ev.get("filename") or ""))[:120],
                                   "dir": "upload" if eid.endswith("upload") else "download"})
        elif eid == "cowrie.session.closed":
            ms = ev.get("duration_ms")
            if isinstance(ms, (int, float)):
                s["end"] = max(s["end"], s["start"] + ms / 1000.0)
            return self.open.pop(sid, None)
        return None

    def idle(self, now: float | None = None) -> list[dict]:
        now = now or time.time()
        done = [k for k, v in self.open.items() if now - v["_seen"] > IDLE_FLUSH]
        return [self.open.pop(k) for k in done]


def public_session(s: dict) -> dict:
    return {k: v for k, v in s.items() if not k.startswith("_")}


def find_file(cowrie_home: str, f: dict) -> str | None:
    """Where Cowrie saved a captured file. Cowrie names the file after its SHA-256."""
    cands = []
    if f.get("outfile"):
        cands.append(os.path.join(cowrie_home, f["outfile"]))
    cands += [os.path.join(cowrie_home, "var/lib/cowrie/downloads", f["sha256"]),
              os.path.join(cowrie_home, "downloads", f["sha256"])]
    for c in cands:
        real = os.path.realpath(c)
        if real.startswith(os.path.realpath(cowrie_home) + os.sep) and os.path.isfile(real):
            return real
    return None


class Client:
    def __init__(self, url: str, key: str, fingerprint: str = "", insecure: bool = False, timeout: float = 30):
        u = urllib.parse.urlparse(url)
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname or "", u.port or (443 if self.https else 80)
        self.base = u.path.rstrip("/")
        self.key, self.fp, self.timeout = key, fingerprint.lower().replace(":", ""), timeout
        self.ctx = None
        if self.https:
            self.ctx = ssl.create_default_context()
            if self.fp or insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def post(self, path: str, body: bytes, headers: dict) -> tuple[int, bytes]:
        conn = (http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx) if self.https
                else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout))
        try:
            conn.connect()
            if self.https and self.fp:
                der = conn.sock.getpeercert(binary_form=True)
                if hashlib.sha256(der).hexdigest() != self.fp:
                    raise ssl.SSLError("server certificate does not match LANPULSE_FINGERPRINT")
            conn.request("POST", self.base + path, body=body, headers={"X-LanPulse-Key": self.key, **headers})
            r = conn.getresponse()
            return r.status, r.read(2000)
        finally:
            conn.close()

    def send_session(self, s: dict) -> int:
        status, _ = self.post("/api/honeypot/ingest/session", json.dumps(public_session(s)).encode(),
                              {"Content-Type": "application/json"})
        return status

    def hello(self, sensor: str) -> int:
        """Tells LanPulse this sensor is alive (so the Add sensor card turns green before the first attack)."""
        status, _ = self.post("/api/honeypot/ingest/hello", json.dumps({"sensor": sensor, "v": 1}).encode(),
                              {"Content-Type": "application/json"})
        return status

    def send_file(self, path: str, ip: str, f: dict) -> int:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
        if not data or len(data) > MAX_FILE:
            return 400                                    # nothing to send, or too big for LanPulse: don't retry forever
        q = urllib.parse.quote
        status, _ = self.post("/api/honeypot/ingest/sample", data,
                              {"Content-Type": "application/octet-stream", "X-Src-Ip": ip, "X-Url": q(f.get("url", "")),
                               "X-Name": q(f.get("name", "")), "X-Sha256": f["sha256"]})
        return status


class State:
    """Remembers how far into the log we are and what is still waiting to be sent, across restarts."""

    def __init__(self, path: str):
        self.path = path
        self.d = {"inode": 0, "offset": 0, "outbox": [], "sent_files": []}
        try:
            with open(path) as fh:
                self.d.update(json.load(fh))
        except (OSError, ValueError):
            pass

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.d, fh)
            os.replace(tmp, self.path)
        except OSError as e:
            print("could not save state:", e, file=sys.stderr)


def read_new(log_path: str, st: State, max_bytes: int = 4_000_000) -> list[dict]:
    """New complete JSON lines since last time. Follows the log if it is rotated or truncated."""
    try:
        fs = os.stat(log_path)
    except OSError:
        return []
    if fs.st_ino != st.d["inode"] or fs.st_size < st.d["offset"]:
        if st.d["inode"] and fs.st_ino != st.d["inode"]:
            st.d["offset"] = 0                           # a new file after rotation: read it from the start
        elif fs.st_size < st.d["offset"]:
            st.d["offset"] = 0
        st.d["inode"] = fs.st_ino
    out = []
    with open(log_path, "rb") as fh:
        fh.seek(st.d["offset"])
        chunk = fh.read(max_bytes)
    end = chunk.rfind(b"\n")
    if end < 0:
        return []
    st.d["offset"] += end + 1
    for line in chunk[:end].split(b"\n"):
        try:
            ev = json.loads(line)
            if isinstance(ev, dict):
                out.append(ev)
        except ValueError:
            continue
    return out


def _settled(status: int) -> bool:
    """True when LanPulse answered for good: accepted, or refused in a way that retrying cannot fix."""
    return status == 200 or (400 <= status < 500 and status not in (401, 403, 408, 429))


def flush_outbox(client: Client, st: State, cowrie_home: str) -> None:
    keep = []
    sent = set(st.d["sent_files"])
    items = st.d["outbox"]
    for n, item in enumerate(items):
        try:
            if item["type"] == "session":
                done = _settled(client.send_session(item["data"]))
            else:
                f = item["data"]
                if f["sha256"] in sent:
                    continue
                path = find_file(cowrie_home, f)
                if not path:
                    if time.time() - item.get("t", 0) <= 600:
                        keep.append(item)               # Cowrie may still be writing it
                    continue
                done = _settled(client.send_file(path, item["ip"], f))
                if done:
                    sent.add(f["sha256"])
            if not done:
                keep.append(item)
        except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as e:
            print("LanPulse not reachable, will retry:", e, file=sys.stderr)
            keep.extend(items[n:])
            break
    st.d["outbox"] = keep[-MAX_OUTBOX:]
    st.d["sent_files"] = list(sent)[-5000:]


def queue_session(st: State, s: dict) -> None:
    now = time.time()
    for f in s["files"]:                                  # files first, so LanPulse knows them when the session arrives
        st.d["outbox"].append({"type": "file", "t": now, "ip": s["ip"], "data": f})
    st.d["outbox"].append({"type": "session", "t": now, "data": public_session(s)})


def main() -> int:
    url, key = os.environ.get("LANPULSE_URL", ""), os.environ.get("LANPULSE_KEY", "")
    if not url or not key:
        print("Set LANPULSE_URL and LANPULSE_KEY (see /etc/lanpulse-forwarder.env)", file=sys.stderr)
        return 2
    home = os.environ.get("COWRIE_HOME", "/home/cowrie/cowrie")
    log_path = os.path.join(home, "var/log/cowrie/cowrie.json")
    st = State(os.environ.get("STATE_FILE", "/var/lib/lanpulse-forwarder/state.json"))
    client = Client(url, key, os.environ.get("LANPULSE_FINGERPRINT", ""), os.environ.get("LANPULSE_INSECURE") == "1")
    sessions = Sessions(os.environ.get("SENSOR_NAME") or socket.gethostname())
    print(f"forwarding {log_path} to {url}", flush=True)
    last_save, last_hello = 0.0, 0.0
    while True:
        try:
            if time.time() - last_hello > HELLO_EVERY:
                last_hello = time.time()
                try:
                    client.hello(sessions.sensor)
                except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as e:
                    print("LanPulse not reachable:", e, file=sys.stderr, flush=True)
            for ev in read_new(log_path, st):
                done = sessions.feed(ev)
                if done:
                    queue_session(st, done)
            for s in sessions.idle():
                queue_session(st, s)
            if st.d["outbox"]:
                flush_outbox(client, st, home)
            if time.time() - last_save > 5:
                st.save()
                last_save = time.time()
        except Exception as e:                            # never die: a honeypot sensor should keep running
            print("forwarder error:", repr(e), file=sys.stderr, flush=True)
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
