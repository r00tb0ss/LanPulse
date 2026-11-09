#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
LanPulse trap: small FTP and web decoys for a honeypot sensor (Python 3 standard library only).

Cowrie covers SSH and Telnet. This program adds two more doors so you can see what attackers upload:
  * an FTP server that accepts any login and keeps every file that is uploaded;
  * a web server that logs exploit attempts and login forms and keeps uploaded files (PUT, POST, multipart forms).

It writes what it sees in the same JSON format Cowrie uses, so the LanPulse forwarder picks it up and sends it to LanPulse,
where the sessions and the static file analysis show up next to the Cowrie ones. It never runs, opens or serves anything
an attacker sends: files are only written to disk under their SHA-256 name (mode 0600). It never connects out (FTP active
mode PORT/EPRT is refused), and it only listens on the ports you give it, all above 1023 so it can run without root.

Settings come from environment variables (the installer writes /etc/lanpulse-trap.env):
  TRAP_HOME               default /home/cowrie/cowrie   (logs go to var/log/trap, files to var/lib/trap/downloads)
  TRAP_FTP_PORT           0 = off (default). The passive data ports are the next 20 ports (TRAP_PASV_COUNT).
  TRAP_HTTP_PORT          0 = off (default)
  TRAP_BIND               default 0.0.0.0
  TRAP_FTP_BANNER         default "(vsFTPd 3.0.3)"
  TRAP_MAX_FILE_MB        default 5 (LanPulse stores nothing larger)
  TRAP_MAX_STORE_MB       default 500: stop keeping files when the folder is this big
  TRAP_MAX_SESSIONS_PER_MIN  default 30: most sessions written per minute, so a flood cannot drown LanPulse
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

MB = 1024 * 1024
LOG_ROTATE = 20 * MB
SESSION_TIMEOUT = 120          # seconds one connection may last
HTTP_LIMIT = 90                # hard limit for a whole web connection, so trickled bytes can't hold a slot
FTP_LIMIT = 300                # the same for a whole FTP connection
MAX_COMMANDS = 200
MEM_BODY = 1 * MB              # request bodies up to this size are looked into (multipart forms); bigger ones go to disk whole
SUSPICIOUS = re.compile(r"(\.\./|;|\||\$\(|\$\{|`|wget|curl|tftp|/bin/|cmd=|exec|eval\(|passwd|jndi|\.php|\.cgi|cgi-bin|\.env|\.git|"
                        r"phpmyadmin|wp-|boaform|hnap|setup\.cgi|shell|\.asp|actuator|manager/html)", re.I)
USER_KEYS = ("user", "username", "login", "log", "email", "uname", "usr")
PASS_KEYS = ("pass", "password", "pwd", "passwd", "pw")
INDEX = b"<html><head><title>It works!</title></head><body><h1>It works!</h1><p>This is the default web page for this server.</p></body></html>\n"


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def watchdog(sock, seconds: float) -> threading.Timer:
    """Cut the connection after `seconds` however slowly the other side trickles bytes (the socket timeout only covers one read)."""
    def kill():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    t = threading.Timer(seconds, kill)
    t.daemon = True
    t.start()
    return t


def printable(s: str, limit: int) -> str:
    return "".join(c if c.isprintable() else "?" for c in s)[:limit]


def safe_name(s: str) -> str:
    return printable(os.path.basename(str(s).replace("\\", "/")), 120)


class Store:
    """Where the events and the captured files go, plus the limits that keep a flood from filling the disk."""

    def __init__(self, home: str, max_file_mb: float = 5, max_store_mb: float = 500, per_minute: int = 30):
        self.home = os.path.realpath(home)
        self.log_path = os.path.join(self.home, "var/log/trap/trap.json")
        self.dl_dir = os.path.join(self.home, "var/lib/trap/downloads")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        os.makedirs(self.dl_dir, mode=0o700, exist_ok=True)
        self.max_file, self.max_store, self.per_min = int(max_file_mb * MB), int(max_store_mb * MB), per_minute
        self.lock = threading.Lock()
        self.recent: list[float] = []
        self.size_at, self.size = 0.0, 0
        self.dropped = 0

    def allow(self) -> bool:
        now = time.time()
        with self.lock:
            self.recent = [t for t in self.recent if now - t < 60]
            if len(self.recent) >= self.per_min:
                return False
            self.recent.append(now)
            return True

    def write(self, events: list[dict]) -> None:
        data = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events).encode()
        with self.lock:
            try:
                if os.path.getsize(self.log_path) > LOG_ROTATE:
                    os.replace(self.log_path, self.log_path + ".1")
            except OSError:
                pass
            fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)

    def store_size(self) -> int:
        if time.time() - self.size_at > 30:
            total = 0
            try:
                for e in os.scandir(self.dl_dir):
                    if e.is_file(follow_symlinks=False):
                        total += e.stat(follow_symlinks=False).st_size
            except OSError:
                pass
            self.size, self.size_at = total, time.time()
        return self.size

    def rel(self, sha: str) -> str:
        return os.path.relpath(os.path.join(self.dl_dir, sha), self.home)


class Spool:
    """Receives one file on disk (never in memory), hashing as it goes. Refuses what is too big or when the folder is full."""

    def __init__(self, store: Store):
        self.store, self.h, self.n = store, hashlib.sha256(), 0
        self.ok = store.store_size() < store.max_store
        self.path = os.path.join(store.dl_dir, ".tmp-" + secrets.token_hex(8))
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) if self.ok else None

    def write(self, b: bytes) -> bool:
        if not self.ok:
            return False
        if self.n + len(b) > self.store.max_file:
            self.discard()
            return False
        os.write(self.fd, b)
        self.h.update(b)
        self.n += len(b)
        return True

    def discard(self) -> None:
        self.ok = False
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def finish(self):
        """(sha256, size) of the saved file, or None when nothing was kept."""
        if not self.ok or self.fd is None:
            return None
        os.close(self.fd)
        self.fd = None
        if self.n == 0:
            os.unlink(self.path)
            return None
        sha = self.h.hexdigest()
        dest = os.path.join(self.store.dl_dir, sha)
        if os.path.exists(dest):
            os.unlink(self.path)
        else:
            os.replace(self.path, dest)
        self.ok = False
        self.store.size_at = 0
        return sha, self.n


class Session:
    """The events of one connection. Written out when it ends, and only if it was worth keeping."""

    def __init__(self, store: Store, proto: str, ip: str, port: int):
        self.store, self.proto, self.t0 = store, proto, time.time()
        self.sid = ("ftp" if proto == "ftp" else "web") + secrets.token_hex(5)
        self.events: list[dict] = []
        self.ncmd = self.nfiles = self.nlogins = 0
        self.add("cowrie.session.connect", src_ip=ip, dst_port=port, protocol=proto)

    def add(self, eid: str, **kw) -> None:
        self.events.append({"eventid": eid, "session": self.sid, "timestamp": iso_now(), **kw})

    def client(self, v: str) -> None:
        self.add("cowrie.client.version", version=printable(v, 120))

    def login(self, user: str, pw: str, ok: bool) -> None:
        self.nlogins += 1
        self.add("cowrie.login.success" if ok else "cowrie.login.failed", username=printable(user, 64), password=printable(pw, 64))

    def command(self, text: str) -> None:
        if self.ncmd < MAX_COMMANDS:
            self.ncmd += 1
            self.add("cowrie.command.input", input=printable(text, 1000))

    def upload(self, sha: str, size: int, name: str, url: str = "") -> None:
        self.nfiles += 1
        self.add("cowrie.session.file_upload", shasum=sha, filename=safe_name(name), outfile=self.store.rel(sha), url=url[:300], size=size)

    def close(self, keep: bool = True) -> None:
        if keep and self.store.allow():
            self.add("cowrie.session.closed", duration_ms=int((time.time() - self.t0) * 1000))
            self.store.write(self.events)
        else:
            self.store.dropped += 1


class Gate:
    """Most connections at once, in total and from one address."""

    def __init__(self, total: int = 40, per_ip: int = 5):
        self.total, self.per_ip, self.n, self.by_ip = total, per_ip, 0, {}
        self.lock = threading.Lock()

    def enter(self, ip: str) -> bool:
        with self.lock:
            if self.n >= self.total or self.by_ip.get(ip, 0) >= self.per_ip:
                return False
            self.n += 1
            self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
            return True

    def leave(self, ip: str) -> None:
        with self.lock:
            self.n -= 1
            self.by_ip[ip] = self.by_ip.get(ip, 1) - 1
            if self.by_ip[ip] <= 0:
                self.by_ip.pop(ip, None)


# ------------------------------------------------------------------ FTP
FAKE_LIST = (b"drwxr-xr-x    2 ftp      ftp          4096 Mar 02  2023 backup\r\n"
             b"drwxr-xr-x    4 ftp      ftp          4096 Jun 11  2023 public_html\r\n"
             b"-rw-r--r--    1 ftp      ftp          1743 Jun 11  2023 index.html\r\n")


class FtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, addr, store: Store, gate: Gate, pasv_ports, banner: str = "(vsFTPd 3.0.3)", pasv_ip: str = ""):
        self.store, self.gate, self.banner, self.pasv_ip = store, gate, banner, pasv_ip
        self.bind_host = addr[0]
        self.pasv_free = list(pasv_ports)
        self.pasv_lock = threading.Lock()
        super().__init__(addr, FtpHandler)


class FtpHandler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
        ip = self.client_address[0]
        if not self.server.gate.enter(ip):
            return
        self.pasv = None
        wd = watchdog(self.request, FTP_LIMIT)
        try:
            self.run(ip)
        except (OSError, ValueError):
            pass
        finally:
            wd.cancel()
            self.close_pasv()
            self.server.gate.leave(ip)

    def reply(self, text: str) -> None:
        self.wfile.write((text + "\r\n").encode("latin-1", "replace"))
        self.wfile.flush()

    def open_pasv(self):
        self.close_pasv()
        srv = self.server
        with srv.pasv_lock:
            port = srv.pasv_free.pop() if srv.pasv_free else None
        if port is None:
            return None
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((srv.bind_host, port))
            ls.listen(1)
        except OSError:
            ls.close()
            with srv.pasv_lock:
                srv.pasv_free.append(port)
            return None
        self.pasv = (ls, port)
        return port

    def close_pasv(self) -> None:
        if self.pasv:
            ls, port = self.pasv
            self.pasv = None
            ls.close()
            with self.server.pasv_lock:
                self.server.pasv_free.append(port)

    def accept_data(self, ip: str):
        """The data connection, but only from the same address as the control connection."""
        if not self.pasv:
            return None
        ls, _ = self.pasv
        end = time.time() + 20
        try:
            while time.time() < end:
                ls.settimeout(max(0.5, end - time.time()))
                c, addr = ls.accept()
                if addr[0] == ip:
                    c.settimeout(20)
                    return c
                c.close()
        except OSError:
            pass
        finally:
            self.close_pasv()
        return None

    def run(self, ip: str) -> None:
        srv = self.server
        s = Session(srv.store, "ftp", ip, srv.server_address[1])
        user, authed, deadline = "", False, time.time() + SESSION_TIMEOUT
        try:
            self.reply("220 " + srv.banner)
            while time.time() < deadline and s.ncmd < MAX_COMMANDS:
                raw = self.rfile.readline(512)
                if not raw:
                    break
                line = raw.decode("latin-1").strip()
                if not line:
                    continue
                verb, _, arg = line.partition(" ")
                verb = verb.upper()
                if verb != "PASS":
                    s.command(line)
                if verb == "QUIT":
                    self.reply("221 Goodbye.")
                    break
                if verb == "USER":
                    user = arg[:64]
                    self.reply("331 Please specify the password.")
                elif verb == "PASS":
                    s.login(user, arg, True)
                    authed = True
                    self.reply("230 Login successful.")
                elif verb in ("NOOP", "TYPE", "MODE", "STRU", "OPTS"):
                    self.reply("200 OK.")
                elif verb == "SYST":
                    self.reply("215 UNIX Type: L8")
                elif verb == "FEAT":
                    self.reply("211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End")
                elif not authed:
                    self.reply("530 Please login with USER and PASS.")
                elif verb in ("PWD", "XPWD"):
                    self.reply('257 "/" is the current directory')
                elif verb in ("CWD", "CDUP", "DELE", "RMD", "XRMD", "RNTO"):
                    self.reply("250 Requested file action okay, completed.")
                elif verb in ("MKD", "XMKD"):
                    self.reply('257 "/%s" created' % printable(arg, 60).lstrip("/"))
                elif verb == "RNFR":
                    self.reply("350 Ready for RNTO.")
                elif verb in ("SIZE", "MDTM", "RETR"):
                    self.reply("550 Failed to open file.")
                elif verb == "PASV":
                    port = self.open_pasv()
                    if port is None:
                        self.reply("425 Can't open data connection.")
                    else:
                        host = srv.pasv_ip or self.request.getsockname()[0]
                        self.reply("227 Entering Passive Mode (%s,%d,%d)" % (host.replace(".", ","), port >> 8, port & 255))
                elif verb == "EPSV":
                    port = self.open_pasv()
                    self.reply("425 Can't open data connection." if port is None else "229 Entering Extended Passive Mode (|||%d|)" % port)
                elif verb in ("PORT", "EPRT"):
                    self.reply("502 Active mode is not available, use passive.")      # never connect out to an address an attacker names
                elif verb in ("LIST", "NLST", "MLSD"):
                    c = self.accept_data(ip)
                    if c is None:
                        self.reply("425 Use PASV first.")
                    else:
                        self.reply("150 Here comes the directory listing.")
                        try:
                            c.sendall(FAKE_LIST)
                        except OSError:
                            pass
                        c.close()
                        self.reply("226 Directory send OK.")
                elif verb in ("STOR", "APPE", "STOU"):
                    c = self.accept_data(ip)
                    if c is None:
                        self.reply("425 Use PASV first.")
                        continue
                    self.reply("150 Ok to send data.")
                    sp, t_end = Spool(srv.store), time.time() + 60
                    while sp.ok and time.time() < t_end:
                        try:
                            b = c.recv(65536)
                        except OSError:
                            break
                        if not b or not sp.write(b):
                            break
                    c.close()
                    res = sp.finish()
                    if res:
                        s.upload(res[0], res[1], arg or "upload", "ftp://" + ip + "/" + arg.lstrip("/"))
                        self.reply("226 Transfer complete.")
                    else:
                        sp.discard()
                        self.reply("552 Requested file action aborted.")
                else:
                    self.reply("502 Command not implemented.")
        finally:
            s.close(keep=s.ncmd > 0 or s.nlogins > 0)


# ------------------------------------------------------------------ HTTP
def parse_multipart(body: bytes, boundary: str, max_parts: int = 20) -> list[tuple[str, str, bytes]]:
    """[(field name, file name or '', content)] from a multipart/form-data body."""
    out = []
    delim = b"--" + boundary.encode("latin-1", "replace")
    for chunk in body.split(delim)[1:max_parts + 1]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        h = head.decode("latin-1")
        name = re.search(r'[; ]name="([^"]*)"', h)
        fn = re.search(r'filename="([^"]*)"', h)
        out.append((name.group(1) if name else "", fn.group(1) if fn else "", data))
    return out


class HttpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, addr, store: Store, gate: Gate):
        self.store, self.gate = store, gate
        super().__init__(addr, HttpHandler)


class HttpHandler(socketserver.StreamRequestHandler):
    timeout = 20

    def handle(self):
        ip = self.client_address[0]
        if not self.server.gate.enter(ip):
            return
        wd = watchdog(self.request, HTTP_LIMIT)
        try:
            self.run(ip)
        except (OSError, ValueError):
            pass
        finally:
            wd.cancel()
            self.server.gate.leave(ip)

    def respond(self, code: int, text: str, body: bytes = b"", head_only: bool = False) -> None:
        hdr = (f"HTTP/1.1 {code} {text}\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        self.wfile.write(hdr + (b"" if head_only else body))
        self.wfile.flush()

    def read_body(self, headers: dict, store: Store):
        """(bytes held in memory or None, (sha, size) when it went to disk, too_big). Streams big bodies to a file."""
        if headers.get("expect", "").lower().startswith("100"):
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.wfile.flush()
        mem, sp, total = bytearray(), None, 0
        chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        cl = headers.get("content-length", "")
        if not chunked and not (cl.isdigit() and int(cl) > 0):
            return None, None, False
        deadline = time.time() + 60

        def take(data: bytes) -> bool:
            nonlocal sp, total
            total += len(data)
            if sp is None and total <= MEM_BODY:
                mem.extend(data)
                return True
            if sp is None:
                sp = Spool(store)
                if not sp.write(bytes(mem)):
                    return False
                mem.clear()
            return sp.write(data)

        def pieces():
            if chunked:
                while True:
                    try:
                        n = int(self.rfile.readline(64).split(b";")[0].strip(), 16)
                    except ValueError:
                        return
                    if n == 0:
                        return
                    left = n
                    while left > 0:
                        d = self.rfile.read(min(left, 65536))
                        if not d:
                            return
                        left -= len(d)
                        yield d
                    self.rfile.readline(4)              # the CRLF after each chunk
            else:
                left = int(cl)
                while left > 0:
                    d = self.rfile.read(min(left, 65536))
                    if not d:
                        return
                    left -= len(d)
                    yield d

        for d in pieces():
            if time.time() > deadline:
                break
            if not take(d):
                if sp:
                    sp.discard()
                return None, None, True
        if sp:
            return None, sp.finish(), False
        return bytes(mem), None, False

    def run(self, ip: str) -> None:
        srv = self.server
        s = Session(srv.store, "http", ip, srv.server_address[1])
        keep = False
        try:
            line = self.rfile.readline(8192).decode("latin-1").strip()
            parts = line.split()
            if len(parts) < 2 or not parts[0].isalpha():
                return
            method, target = parts[0].upper(), parts[1][:2000]
            decoded = urllib.parse.unquote_plus(target)
            headers: dict[str, str] = {}
            for _ in range(64):
                h = self.rfile.readline(4096).decode("latin-1").rstrip("\r\n")
                if not h:
                    break
                k, _, v = h.partition(":")
                headers[k.strip().lower()] = v.strip()
            if headers.get("user-agent"):
                s.client(headers["user-agent"])
            s.command(f"{method} {decoded}")
            notes = SUSPICIOUS.search(decoded) is not None
            for k, v in headers.items():                 # exploit payloads often ride in headers (Log4Shell, Shellshock)
                if k not in ("host", "accept", "connection", "content-length") and SUSPICIOUS.search(v):
                    s.command(f"HEADER {k}: {v}")
                    notes = True
            auth = headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    u, _, p = base64.b64decode(auth[6:], validate=False).decode("latin-1").partition(":")
                    s.login(u, p, False)
                except ValueError:
                    pass
            body, saved, too_big = (None, None, False)
            if method in ("POST", "PUT", "PATCH"):
                body, saved, too_big = self.read_body(headers, srv.store)
            name = safe_name(urllib.parse.urlsplit(decoded).path) or "body"
            ctype = headers.get("content-type", "")
            url = "http://" + ip + decoded[:200]
            if saved:
                s.upload(saved[0], saved[1], name, url)
            elif body:
                self.handle_body(s, method, ctype, body, name, url)
            keep = (method not in ("GET", "HEAD", "OPTIONS") or notes or s.nlogins > 0 or s.nfiles > 0)
            if too_big:
                self.respond(413, "Payload Too Large")
            elif method in ("POST", "PUT", "PATCH"):
                self.respond(200, "OK", b"OK\n")
            else:
                self.respond(200, "OK", INDEX, head_only=(method == "HEAD"))
        finally:
            s.close(keep=keep)

    def handle_body(self, s: Session, method: str, ctype: str, body: bytes, name: str, url: str) -> None:
        low = ctype.lower()
        m = re.search(r'boundary="?([^";]+)"?', ctype, re.I)
        if "multipart/form-data" in low and m:
            for field, fname, data in parse_multipart(body, m.group(1)):
                if fname and data:
                    sp = Spool(self.server.store)
                    if sp.write(data):
                        res = sp.finish()
                        if res:
                            s.upload(res[0], res[1], fname, url)
                    else:
                        sp.discard()
                elif field and data:
                    s.command(f"FIELD {field}={data[:200].decode('latin-1')}")
            return
        if "application/x-www-form-urlencoded" in low:
            try:
                fields = urllib.parse.parse_qsl(body[:65536].decode("latin-1"), max_num_fields=50)
            except ValueError:
                fields = []
            u = next((v for k, v in fields if k.lower() in USER_KEYS), None)
            p = next((v for k, v in fields if k.lower() in PASS_KEYS), None)
            if u is not None and p is not None:
                s.login(u, p, False)
            s.command("BODY " + urllib.parse.unquote_plus(body[:500].decode("latin-1")))
            return
        text = body[:2000]
        if method != "PUT" and len(body) <= 2000 and b"\x00" not in text:
            s.command("BODY " + text.decode("latin-1"))                  # a JSON or text payload: the log line is the evidence
            return
        sp = Spool(self.server.store)
        if sp.write(body):
            res = sp.finish()
            if res:
                s.upload(res[0], res[1], name, url)
        else:
            sp.discard()


# ------------------------------------------------------------------ main
def serve(server) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def main() -> int:
    env = os.environ.get
    ftp_port, http_port = int(env("TRAP_FTP_PORT", "0") or 0), int(env("TRAP_HTTP_PORT", "0") or 0)
    if not ftp_port and not http_port:
        print("Set TRAP_FTP_PORT and/or TRAP_HTTP_PORT (see /etc/lanpulse-trap.env)", file=sys.stderr)
        return 2
    bind = env("TRAP_BIND", "0.0.0.0")
    store = Store(env("TRAP_HOME", "/home/cowrie/cowrie"), float(env("TRAP_MAX_FILE_MB", "5")), float(env("TRAP_MAX_STORE_MB", "500")),
                  int(env("TRAP_MAX_SESSIONS_PER_MIN", "30")))
    gate = Gate()
    threads = []
    if ftp_port:
        count = int(env("TRAP_PASV_COUNT", "20"))
        srv = FtpServer((bind, ftp_port), store, gate, range(ftp_port + 1, ftp_port + 1 + count), env("TRAP_FTP_BANNER", "(vsFTPd 3.0.3)"),
                        env("TRAP_PASV_IP", ""))
        threads.append(serve(srv))
        print(f"FTP decoy on {bind}:{ftp_port}, passive ports {ftp_port + 1}-{ftp_port + count}", flush=True)
    if http_port:
        threads.append(serve(HttpServer((bind, http_port), store, gate)))
        print(f"web decoy on {bind}:{http_port}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
