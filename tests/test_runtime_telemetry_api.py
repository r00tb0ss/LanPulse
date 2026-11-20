# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""API security tests for runtime telemetry routes; no live server or sandbox is started."""
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as lanpulse_app  # noqa: E402
from runtime_telemetry import RuntimeTelemetry  # noqa: E402


class FakeAuth:
    enabled = True

    @staticmethod
    def verify(cookie):
        return "admin" if cookie == "test-session" else None


async def asgi_request(app, method, path, payload=None, headers=None, session=True):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    raw_headers = [(b"host", b"127.0.0.1")]
    if payload is not None:
        raw_headers.append((b"content-type", b"application/json"))
        raw_headers.append((b"content-length", str(len(body)).encode("ascii")))
    if session:
        raw_headers.append((b"cookie", b"nm_session=test-session"))
    raw_headers.extend(headers or [])
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 80),
    }
    messages = []
    sent_request = False

    async def receive():
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(message.get("body", b"") for message in messages
                             if message["type"] == "http.response.body")
    try:
        data = json.loads(response_body) if response_body else None
    except ValueError:
        data = response_body.decode("utf-8", "replace")
    return start["status"], data


class RuntimeTelemetryAPISecurity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.sample_sha = "c" * 64
        self.store = RuntimeTelemetry(pathlib.Path(self.temp.name) / "runtime" / "events.db")
        nm = SimpleNamespace(
            args=SimpleNamespace(demo=False, cert=None, allow_host=[]),
            settings={"system": {"allow_hosts": []}},
            auth=FakeAuth(),
            runtime_telemetry=self.store,
            honeyan=SimpleNamespace(sample_exists=lambda sha: sha == self.sample_sha),
        )
        self.app = lanpulse_app.build_app(nm)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    async def request(self, method, path, payload=None, session=True, headers=None):
        return await asgi_request(self.app, method, path, payload, headers, session)

    def event(self, sample_sha=None):
        import time
        return {
            "sample_sha256": sample_sha or self.sample_sha,
            "run_id": "isolated-run-001",
            "timestamp": time.time(),
            "type": "connect",
            "destination_ip": "203.0.113.77",
            "port": 443,
            "protocol": "tcp",
        }

    async def test_management_and_event_review_require_dashboard_login(self):
        for method, path, payload in (
            ("GET", "/api/runtime/sensors", None),
            ("GET", "/api/runtime/events", None),
            ("POST", "/api/runtime/sensors", {"id": "lab-api-01"}),
            ("POST", "/api/runtime/sensors/revoke", {"id": "lab-api-01"}),
        ):
            with self.subTest(method=method, path=path):
                status, body = await self.request(method, path, payload, session=False)
                self.assertEqual(status, 401, body)

    async def test_sensor_token_is_shown_once_ingest_is_publicly_authenticated_and_revocation_works(self):
        status, created = await self.request("POST", "/api/runtime/sensors", {"id": "lab-api-01"})
        self.assertEqual(status, 200, created)
        token = created["token"]
        self.assertTrue(token)

        status, inventory = await self.request("GET", "/api/runtime/sensors")
        self.assertEqual(status, 200, inventory)
        self.assertEqual(inventory["sensors"][0]["id"], "lab-api-01")
        self.assertNotIn("token", inventory["sensors"][0])
        self.assertNotIn(token, json.dumps(inventory))

        auth_headers = [(b"x-lanpulse-sensor", b"lab-api-01"),
                        (b"x-lanpulse-token", token.encode("ascii"))]
        status, result = await self.request(
            "POST", "/api/runtime/ingest", {"events": [self.event()]},
            session=False, headers=auth_headers)
        self.assertEqual(status, 200, result)
        self.assertEqual((result["accepted"], result["duplicates"]), (1, 0))

        status, reviewed = await self.request("GET", "/api/runtime/events", session=False)
        self.assertEqual(status, 401, reviewed)
        status, reviewed = await self.request("GET", "/api/runtime/events")
        self.assertEqual(status, 200, reviewed)
        self.assertEqual(reviewed["count"], 1)
        self.assertEqual(reviewed["events"][0]["sample_sha256"], self.sample_sha)

        status, denied = await self.request(
            "POST", "/api/runtime/ingest", {"events": [self.event()]},
            session=False,
            headers=[(b"x-lanpulse-sensor", b"lab-api-01"),
                     (b"x-lanpulse-token", b"not-the-token")])
        self.assertEqual(status, 403, denied)

        status, revoked = await self.request(
            "POST", "/api/runtime/sensors/revoke", {"id": "lab-api-01"})
        self.assertEqual(status, 200, revoked)
        status, denied = await self.request(
            "POST", "/api/runtime/ingest", {"events": [self.event()]},
            session=False, headers=auth_headers)
        self.assertEqual(status, 403, denied)

    async def test_unknown_sample_is_rejected_before_storage(self):
        status, created = await self.request("POST", "/api/runtime/sensors", {"id": "lab-api-02"})
        self.assertEqual(status, 200, created)
        status, result = await self.request(
            "POST", "/api/runtime/ingest", {"events": [self.event("d" * 64)]},
            session=False,
            headers=[(b"x-lanpulse-sensor", b"lab-api-02"),
                     (b"x-lanpulse-token", created["token"].encode("ascii"))])
        self.assertEqual(status, 400, result)
        self.assertEqual(self.store.events_since(0), [])

    async def test_management_is_denied_when_dashboard_login_is_disabled(self):
        self.app = lanpulse_app.build_app(SimpleNamespace(
            args=SimpleNamespace(demo=False, cert=None, allow_host=[]),
            settings={"system": {"allow_hosts": []}},
            auth=SimpleNamespace(enabled=False, verify=lambda _cookie: None),
            runtime_telemetry=self.store,
            honeyan=SimpleNamespace(sample_exists=lambda _sha: True),
        ))
        status, result = await self.request("POST", "/api/runtime/sensors", {"id": "no-login"})
        self.assertEqual(status, 403, result)
        self.assertIn("Enable a LanPulse dashboard login", result["error"])


if __name__ == "__main__":
    unittest.main()
