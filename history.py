# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Per-device presence and latency history, stored per minute in SQLite (kept 7 days)."""
from __future__ import annotations

import sqlite3
import threading
import time

KEEP_DAYS = 7


class History:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS samples (id TEXT, m INTEGER, rtt REAL, "
                        "PRIMARY KEY (id, m)) WITHOUT ROWID")
        self.db.commit()
        self.lock = threading.Lock()
        self.acc: dict[tuple[str, int], list] = {}   # (id, minute) -> [rtt_sum, rtt_count]
        self.last_prune = 0.0

    def record(self, dev_id: str, rtt: float | None, now: float):
        a = self.acc.setdefault((dev_id, int(now // 60)), [0.0, 0])
        if rtt is not None:
            a[0] += rtt
            a[1] += 1

    def flush(self, now: float):
        cur = int(now // 60)
        done = [k for k in self.acc if k[1] < cur]
        if done:
            rows = [(k[0], k[1], round(self.acc[k][0] / self.acc[k][1], 2) if self.acc[k][1] else None) for k in done]
            with self.lock:
                self.db.executemany("INSERT OR REPLACE INTO samples VALUES (?, ?, ?)", rows)
                self.db.commit()
            for k in done:
                del self.acc[k]
        if now - self.last_prune > 3600:
            with self.lock:
                self.db.execute("DELETE FROM samples WHERE m < ?", (cur - KEEP_DAYS * 1440,))
                self.db.commit()
            self.last_prune = now

    def forget(self, dev_id: str):
        with self.lock:
            self.db.execute("DELETE FROM samples WHERE id = ?", (dev_id,))
            self.db.commit()
        for k in [k for k in self.acc if k[0] == dev_id]:
            del self.acc[k]

    def query(self, dev_id: str, first_seen: float, hours: int = 24, buckets: int = 96) -> dict:
        now = time.time()
        cur = int(now // 60)
        start = cur - hours * 60 + 1
        with self.lock:
            rows = self.db.execute("SELECT m, rtt FROM samples WHERE id = ? AND m >= ? ORDER BY m",
                                   (dev_id, start)).fetchall()
        data = dict(rows)
        for (i, m), (s, n) in list(self.acc.items()):      # a copy: the event loop keeps adding to it while this runs in a worker thread
            if i == dev_id and m >= start:
                data[m] = round(s / n, 2) if n else None
        first_m = int(first_seen // 60)
        size = hours * 60 // buckets
        presence = []
        for b in range(buckets):
            lo = start + b * size
            hi = min(lo + size, cur + 1)
            lo_t = max(lo, first_m)
            if hi <= lo_t:
                presence.append(None)        # before we knew about the device / in the future
                continue
            present = sum(1 for m in range(lo_t, hi) if m in data)
            presence.append(round(present / (hi - lo_t), 3))
        tracked = cur + 1 - max(start, first_m)
        uptime = round(100 * sum(1 for m in data if m >= first_m) / tracked, 1) if tracked > 0 else None
        rtt = [[m * 60, v] for m, v in sorted(data.items()) if v is not None]
        vals = [v for _, v in rtt]
        return {"hours": hours, "start": start * 60, "bucket_minutes": size, "presence": presence,
                "uptime_pct": uptime, "rtt": rtt,
                "rtt_avg": round(sum(vals) / len(vals), 1) if vals else None,
                "rtt_max": max(vals) if vals else None}
