# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Device timeline: one history per device of everything LanPulse noticed about it (joined the network, online and
offline, IP changes, ports opened or closed, software changes, vulnerabilities found or gone, security warnings,
and changes you made). Kept for 90 days in SQLite.
"""
from __future__ import annotations

import sqlite3
import threading
import time

KEEP_DAYS = 90
MAX_PER_DEVICE = 3000
# kind -> group shown in the filter chips
GROUPS = {
    "new": "network", "ip": "network", "online": "presence", "offline": "presence",
    "port": "ports", "port_closed": "ports", "software": "ports", "scan": "ports",
    "security": "security", "vuln": "security", "vuln_gone": "security", "threat": "security",
    "you": "you",
}
LEVELS = ("info", "good", "warn", "bad")


class Timeline:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS tl (t REAL, dev TEXT, kind TEXT, level TEXT, text TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS tl_dev ON tl (dev, t)")
        # vulnerabilities already reported per device, so only changes go on the timeline
        self.db.execute("CREATE TABLE IF NOT EXISTS vuln_known (dev TEXT, cve TEXT, PRIMARY KEY (dev, cve)) WITHOUT ROWID")
        self.db.commit()
        self.lock = threading.Lock()
        self.last_prune = 0.0

    def add(self, dev: str, kind: str, text: str, level: str = "info", t: float | None = None):
        if not dev or kind not in GROUPS:
            return
        level = level if level in LEVELS else "info"
        with self.lock:
            self.db.execute("INSERT INTO tl VALUES (?,?,?,?,?)", (t or time.time(), dev[:64], kind, level, str(text)[:400]))
            self.db.commit()
        self.prune()

    def query(self, dev: str, days: int = 30, limit: int = 200) -> list[dict]:
        days = max(1, min(int(days), KEEP_DAYS))
        limit = max(10, min(int(limit), 1000))
        with self.lock:
            rows = self.db.execute("SELECT t, kind, level, text FROM tl WHERE dev = ? AND t > ? ORDER BY t DESC LIMIT ?",
                                   (dev, time.time() - days * 86400, limit)).fetchall()
        return [{"t": t, "kind": k, "group": GROUPS.get(k, "network"), "level": lv, "text": tx} for t, k, lv, tx in rows]

    def forget(self, dev: str):
        with self.lock:
            self.db.execute("DELETE FROM tl WHERE dev = ?", (dev,))
            self.db.execute("DELETE FROM vuln_known WHERE dev = ?", (dev,))
            self.db.commit()

    def prune(self, force: bool = False):
        now = time.time()
        if not force and now - self.last_prune < 3600:
            return
        self.last_prune = now
        with self.lock:
            self.db.execute("DELETE FROM tl WHERE t < ?", (now - KEEP_DAYS * 86400,))
            # a device that flaps online/offline all day can't grow without limit
            for (dev,) in self.db.execute("SELECT dev FROM tl GROUP BY dev HAVING COUNT(*) > ?", (MAX_PER_DEVICE,)).fetchall():
                self.db.execute("DELETE FROM tl WHERE dev = ? AND t < (SELECT t FROM tl WHERE dev = ? ORDER BY t DESC "
                                "LIMIT 1 OFFSET ?)", (dev, dev, MAX_PER_DEVICE - 1))
            self.db.commit()

    # ---- vulnerabilities: report only what changed
    def vuln_changes(self, current: dict[str, dict[str, dict]], devices: set[str]) -> dict[str, tuple[list, list]]:
        """current: device -> {cve: finding}. Returns device -> (new findings, CVE ids no longer found) and
        remembers the new state. Devices not in `devices` (forgotten) are cleared."""
        out = {}
        with self.lock:
            known: dict[str, set] = {}
            for dev, cve in self.db.execute("SELECT dev, cve FROM vuln_known"):
                known.setdefault(dev, set()).add(cve)
            for dev in set(known) | set(current):
                if dev not in devices:
                    self.db.execute("DELETE FROM vuln_known WHERE dev = ?", (dev,))
                    continue
                now_set = set(current.get(dev, {}))
                was = known.get(dev, set())
                new, gone = now_set - was, was - now_set
                if new:
                    self.db.executemany("INSERT OR IGNORE INTO vuln_known VALUES (?,?)", [(dev, c) for c in new])
                if gone:
                    self.db.executemany("DELETE FROM vuln_known WHERE dev = ? AND cve = ?", [(dev, c) for c in gone])
                if new or gone:
                    out[dev] = ([current[dev][c] for c in new], sorted(gone))
            self.db.commit()
        return out
