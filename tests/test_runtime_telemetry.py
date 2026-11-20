# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for authenticated, bounded sandbox runtime telemetry storage."""
import pathlib
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from runtime_telemetry import RuntimeTelemetry


class RuntimeTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = RuntimeTelemetry(pathlib.Path(self.tmp.name) / "telemetry.db")
        self.token = self.store.register_sensor("isolated-lab-01")
        self.sha = "a" * 64

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def event(self, **overrides):
        item = {"sample_sha256": self.sha, "run_id": "run-2026-001",
                "timestamp": time.time(), "type": "connect",
                "destination_ip": "203.0.113.20", "port": 443, "protocol": "tcp"}
        item.update(overrides)
        return item

    def test_sensor_secret_is_hashed_and_authenticates(self):
        row = self.store.db.execute(
            "SELECT token_hash FROM runtime_sensors WHERE sensor_id=?",
            ("isolated-lab-01",)).fetchone()
        self.assertNotEqual(row["token_hash"], self.token)
        self.assertTrue(self.store.authenticate_sensor("isolated-lab-01", self.token))
        self.assertFalse(self.store.authenticate_sensor("isolated-lab-01", "wrong"))

    def test_ingest_and_deduplicate(self):
        event = self.event()
        first = self.store.ingest("isolated-lab-01", [event])
        second = self.store.ingest("isolated-lab-01", [event])
        self.assertEqual(first, {"accepted": 1, "duplicates": 0})
        self.assertEqual(second, {"accepted": 0, "duplicates": 1})
        self.assertEqual(len(self.store.events_for_sample(self.sha)), 1)

    def test_rejects_bad_hash_and_unknown_event(self):
        with self.assertRaises(ValueError):
            self.store.validate_event(self.event(sample_sha256="not-a-hash"))
        with self.assertRaises(ValueError):
            self.store.validate_event(self.event(type="process_exec"))

    def test_rejects_invalid_host_ip_port_and_stale_time(self):
        for change in ({"hostname": "bad host"}, {"destination_ip": "999.1.1.1"},
                       {"port": 70000}, {"timestamp": time.time() - 8 * 86400}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.validate_event(self.event(**change))

    def test_dns_requires_hostname(self):
        with self.assertRaises(ValueError):
            self.store.validate_event(self.event(type="dns_query", destination_ip=""))

    def test_batch_limit_and_sensor_revocation(self):
        with self.assertRaises(ValueError):
            self.store.ingest("isolated-lab-01", [self.event()] * 101)
        self.assertTrue(self.store.revoke_sensor("isolated-lab-01"))
        self.assertFalse(self.store.authenticate_sensor("isolated-lab-01", self.token))
        with self.assertRaises(PermissionError):
            self.store.ingest("isolated-lab-01", [self.event()])

    def test_sample_events_are_scoped_by_hash(self):
        self.store.ingest("isolated-lab-01", [self.event()])
        self.assertEqual(len(self.store.events_for_sample(self.sha)), 1)
        self.assertEqual(self.store.events_for_sample("b" * 64), [])

    def test_sensor_inventory_and_revocation_state(self):
        self.assertEqual(self.store.sensors(), [
            {"id": "isolated-lab-01", "created": self.store.sensors()[0]["created"],
             "revoked": None, "state": "active"}
        ])
        self.assertTrue(self.store.revoke_sensor("isolated-lab-01"))
        self.assertEqual(self.store.sensors()[0]["state"], "revoked")

    def test_request_rate_limit(self):
        self.assertTrue(self.store.allow_request("isolated-lab-01", now=100, limit=2, window=60))
        self.assertTrue(self.store.allow_request("isolated-lab-01", now=101, limit=2, window=60))
        self.assertFalse(self.store.allow_request("isolated-lab-01", now=102, limit=2, window=60))
        self.assertTrue(self.store.allow_request("isolated-lab-01", now=161, limit=2, window=60))

    def test_events_since_returns_sample_linked_observations(self):
        event = self.event(type="dns_query", hostname="c2.example.net", destination_ip="")
        self.store.ingest("isolated-lab-01", [event])
        rows = self.store.events_since(time.time() - 60)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sample_sha256"], self.sha)
        self.assertEqual(rows[0]["type"], "dns_query")
        self.assertEqual(rows[0]["hostname"], "c2.example.net")


if __name__ == "__main__":
    unittest.main()
