# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Login for the LanPulse dashboard: PBKDF2 password hash + HMAC-signed session cookie."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

ITERATIONS = 240_000
SESSION_DAYS = 14


class Auth:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data: dict = {}
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        self.failures: dict[str, list[float]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.data.get("hash"))

    @property
    def user(self) -> str:
        return self.data.get("user", "")

    def _hash(self, pw: str, salt: bytes, iterations: int) -> str:
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations).hex()

    def set_password(self, user: str, pw: str):
        salt = os.urandom(16)
        self.data = {"user": user, "salt": salt.hex(), "iter": ITERATIONS, "hash": self._hash(pw, salt, ITERATIONS),
                     "secret": secrets.token_hex(32)}       # new secret signs everyone out
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def check(self, user: str, pw: str) -> bool:
        if not self.enabled:
            return False
        good_hash = self._hash(pw, bytes.fromhex(self.data["salt"]), self.data.get("iter", ITERATIONS))
        return hmac.compare_digest(user.encode(), self.user.encode()) & hmac.compare_digest(good_hash, self.data["hash"])

    def throttled(self, ip: str) -> bool:
        now = time.time()
        recent = [t for t in self.failures.get(ip, []) if now - t < 300]
        self.failures[ip] = recent
        return len(recent) >= 8

    def failed(self, ip: str):
        if len(self.failures) > 5000:           # don't let failed logins from many addresses grow memory forever
            now = time.time()
            self.failures = {k: v for k, v in self.failures.items() if v and now - v[-1] < 300}
        self.failures.setdefault(ip, []).append(time.time())

    def make_session(self, user: str) -> str:
        payload = f"{user}|{int(time.time()) + SESSION_DAYS * 86400}"
        sig = hmac.new(bytes.fromhex(self.data["secret"]), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}|{sig}"

    def verify(self, cookie: str | None) -> str | None:
        if not self.enabled or not cookie:
            return None
        try:
            user, exp, sig = cookie.rsplit("|", 2)
        except ValueError:
            return None
        good = hmac.new(bytes.fromhex(self.data["secret"]), f"{user}|{exp}".encode(), hashlib.sha256).hexdigest()
        try:
            if hmac.compare_digest(sig.encode(), good.encode()) and int(exp) > time.time() and user == self.user:
                return user
        except ValueError:          # a tampered or garbled cookie
            pass
        return None
