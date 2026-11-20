# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Bounded storage and validation for authenticated malware-sandbox runtime telemetry.

This module does not execute samples or open network listeners. The API layer must
authenticate a sensor with authenticate_sensor() before calling ingest().
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
EVENT_TYPES = {"dns_query", "connect", "tls_sni", "http_host"}
MAX_BATCH = 100
MAX_TEXT = 253
MAX_AGE_SECONDS = 7 * 86400


def _text(value, limit=MAX_TEXT):
    value = str(value or "").strip()
    if not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid telemetry text field.")
    return value


def _hostname(value):
    value = _text(value).rstrip(".").lower()
    if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", value):
        raise ValueError("Invalid hostname.")
    return value


class RuntimeTelemetry:
    """SQLite event store. Sensor secrets are random and only SHA-256 hashes are persisted."""

    def __init__(self, db_path):
        self.path = str(db_path)
        self.lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runtime_sensors (
                sensor_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                created REAL NOT NULL, revoked REAL
            );
            CREATE TABLE IF NOT EXISTS runtime_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE, sensor_id TEXT NOT NULL,
                sample_sha256 TEXT NOT NULL, run_id TEXT NOT NULL,
                observed_at REAL NOT NULL, event_type TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT '', destination_ip TEXT NOT NULL DEFAULT '',
                port INTEGER, protocol TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(sensor_id) REFERENCES runtime_sensors(sensor_id)
            );
            CREATE INDEX IF NOT EXISTS runtime_events_sample_time
                ON runtime_events(sample_sha256, observed_at DESC);
            CREATE INDEX IF NOT EXISTS runtime_events_run
                ON runtime_events(run_id, observed_at DESC);
        """)
        self.db.commit()

    def register_sensor(self, sensor_id):
        """Create a sensor credential. Return the secret once; callers must display it securely."""
        sensor_id = _text(sensor_id, 64)
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.lock:
            self.db.execute(
                "INSERT INTO runtime_sensors(sensor_id,token_hash,created,revoked) VALUES(?,?,?,NULL)",
                (sensor_id, digest, time.time()))
            self.db.commit()
        return token

    def revoke_sensor(self, sensor_id):
        with self.lock:
            cur = self.db.execute("UPDATE runtime_sensors SET revoked=? WHERE sensor_id=? AND revoked IS NULL",
                                  (time.time(), str(sensor_id)))
            self.db.commit()
            return cur.rowcount == 1

    def authenticate_sensor(self, sensor_id, token):
        if not isinstance(token, str) or not token or len(token) > 200:
            return False
        with self.lock:
            row = self.db.execute(
                "SELECT token_hash FROM runtime_sensors WHERE sensor_id=? AND revoked IS NULL",
                (str(sensor_id),)).fetchone()
        if not row:
            return False
        supplied = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(row["token_hash"], supplied)

    @staticmethod
    def validate_event(event, now=None):
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object.")
        sha = str(event.get("sample_sha256", "")).lower()
        if not HEX64.fullmatch(sha):
            raise ValueError("A valid sample SHA-256 is required.")
        run_id = _text(event.get("run_id"), 96)
        kind = _text(event.get("type"), 24)
        if kind not in EVENT_TYPES:
            raise ValueError("Unsupported telemetry event type.")
        stamp = event.get("timestamp")
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            raise ValueError("Event timestamp must be numeric Unix time.")
        stamp = float(stamp)
        now = time.time() if now is None else float(now)
        if not (now - MAX_AGE_SECONDS <= stamp <= now + 300):
            raise ValueError("Event timestamp is outside the accepted time window.")
        host = _hostname(event["hostname"]) if event.get("hostname") else ""
        dest = ""
        if event.get("destination_ip"):
            try:
                dest = str(ipaddress.ip_address(str(event["destination_ip"])))
            except ValueError:
                raise ValueError("Invalid destination IP address.")
        port = event.get("port")
        if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535.")
        proto = str(event.get("protocol", "")).lower()
        if proto not in ("", "tcp", "udp", "icmp", "other"):
            raise ValueError("Unsupported network protocol.")
        if kind == "dns_query" and not host:
            raise ValueError("DNS events require a hostname.")
        if kind == "connect" and not (dest or host):
            raise ValueError("Connection events require a destination IP or hostname.")
        if kind in ("tls_sni", "http_host") and not host:
            raise ValueError("TLS/HTTP host events require a hostname.")
        return {"sample_sha256": sha, "run_id": run_id, "timestamp": stamp, "type": kind,
                "hostname": host, "destination_ip": dest, "port": port, "protocol": proto}

    def ingest(self, sensor_id, events):
        """Persist a bounded batch after caller-side sensor authentication."""
        sensor_id = _text(sensor_id, 64)
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH:
            raise ValueError(f"Submit between 1 and {MAX_BATCH} events.")
        now = time.time()
        cleaned = [self.validate_event(event, now) for event in events]
        inserted = 0
        with self.lock:
            sensor = self.db.execute(
                "SELECT 1 FROM runtime_sensors WHERE sensor_id=? AND revoked IS NULL",
                (sensor_id,)).fetchone()
            if not sensor:
                raise PermissionError("Unknown or revoked telemetry sensor.")
            for event in cleaned:
                canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
                event_key = hashlib.sha256((sensor_id + "\\0" + canonical).encode()).hexdigest()
                cur = self.db.execute("""
                    INSERT OR IGNORE INTO runtime_events
                    (event_key,sensor_id,sample_sha256,run_id,observed_at,event_type,hostname,destination_ip,port,protocol)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                """, (event_key, sensor_id, event["sample_sha256"], event["run_id"],
                      event["timestamp"], event["type"], event["hostname"], event["destination_ip"],
                      event["port"], event["protocol"]))
                inserted += cur.rowcount
            self.db.commit()
        return {"accepted": inserted, "duplicates": len(cleaned) - inserted}

    def events_for_sample(self, sample_sha256, limit=200):
        sha = str(sample_sha256 or "").lower()
        if not HEX64.fullmatch(sha):
            raise ValueError("Invalid sample SHA-256.")
        limit = max(1, min(int(limit), 500))
        with self.lock:
            rows = self.db.execute("""
                SELECT sensor_id,run_id,observed_at,event_type AS type,hostname,destination_ip,port,protocol
                FROM runtime_events WHERE sample_sha256=? ORDER BY observed_at DESC LIMIT ?
            """, (sha, limit)).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        with self.lock:
            self.db.close()
