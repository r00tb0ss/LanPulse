# SPDX-License-Identifier: GPL-2.0-or-later
"""HTTP security and behavior tests for runtime telemetry routes."""
import pathlib
import sys
import tempfile
import time
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from auth import Auth
from runtime_telemetry import RuntimeTelemetry
from runtime_telemetry_api import build_router


class RuntimeTelemetryApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.store = RuntimeTelemetry(root / "runtime.db")
        self.token = self.store.register_sensor("lab-sensor-01")
        self.auth = Auth(root / "auth.json")
        self.auth.set_password("admin", "test-password")
        self.cookie = self.auth.make_session("admin")
        app = FastAPI()
        app.include_router(build_router(self.store, self.auth))
        self.client = TestClient(app)
        self.sha = "a" * 64

    def tearDown(self):
        self.client.close()
        self.store.close()
        self.tmp.cleanup()

    def event(self):
        return {"sample_sha256": self.sha, "run_id": "run-01", "timestamp": time.time(),
                "type": "connect", "destination_ip": "203.0.113.20", "port": 443, "protocol": "tcp"}

    def dashboard(self):
        return {"Cookie": "nm_session=" + self.cookie}

    def sensor(self, token=None):
        return {"X-LanPulse-Sensor": "lab-sensor-01", "X-LanPulse-Key": token or self.token}

    def test_sensor_ingest_and_dashboard_retrieval(self):
        response = self.client.post("/api/runtime/ingest", headers=self.sensor(),
                                    json={"events": [self.event()]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"accepted": 1, "duplicates": 0})
        response = self.client.get("/api/runtime/events", params={"sha256": self.sha},
                                   headers=self.dashboard())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["events"]), 1)

    def test_bad_sensor_token_and_revoked_sensor_are_rejected(self):
        response = self.client.post("/api/runtime/ingest", headers=self.sensor("wrong"),
                                    json={"events": [self.event()]})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(self.store.revoke_sensor("lab-sensor-01"))
        response = self.client.post("/api/runtime/ingest", headers=self.sensor(),
                                    json={"events": [self.event()]})
        self.assertEqual(response.status_code, 403)

    def test_management_and_reads_require_dashboard_session(self):
        self.assertEqual(self.client.get("/api/runtime/sensors").status_code, 401)
        self.assertEqual(self.client.post("/api/runtime/sensors", json={"id": "new-sensor"}).status_code, 401)
        self.assertEqual(self.client.get("/api/runtime/events", params={"sha256": self.sha}).status_code, 401)
        self.assertEqual(self.client.get("/api/runtime/sensors", headers=self.dashboard()).status_code, 200)

    def test_sensor_registration_shows_secret_once_and_revocation_works(self):
        response = self.client.post("/api/runtime/sensors", headers=self.dashboard(),
                                    json={"id": "new-sensor"})
        self.assertEqual(response.status_code, 200)
        token = response.json()["token"]
        self.assertTrue(self.store.authenticate_sensor("new-sensor", token))
        listed = self.client.get("/api/runtime/sensors", headers=self.dashboard()).json()
        self.assertNotIn("token", str(listed))
        revoked = self.client.post("/api/runtime/sensors/new-sensor/revoke", headers=self.dashboard())
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(self.store.authenticate_sensor("new-sensor", token))

    def test_malformed_payloads_and_unknown_fields_are_rejected(self):
        headers = self.sensor()
        self.assertEqual(self.client.post("/api/runtime/ingest", headers=headers, json=[]).status_code, 400)
        self.assertEqual(self.client.post("/api/runtime/ingest", headers=headers,
                                          json={"events": [self.event()], "extra": True}).status_code, 400)
        bad = self.event()
        bad["type"] = "process_exec"
        self.assertEqual(self.client.post("/api/runtime/ingest", headers=headers,
                                          json={"events": [bad]}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
