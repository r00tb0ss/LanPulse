# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Authenticated HTTP API for isolated malware-sandbox runtime telemetry."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

MAX_BODY = 128 * 1024


async def _read_capped(request: Request, limit: int = MAX_BODY):
    try:
        if int(request.headers.get("content-length") or 0) > limit:
            return None
    except ValueError:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            return None
    return bytes(body)


def build_router(store, auth):
    """Build routes around the app's shared telemetry store and dashboard auth."""
    router = APIRouter(prefix="/api/runtime", tags=["runtime-telemetry"])

    def dashboard_user(request: Request):
        # Runtime sensor administration and event reads are never anonymous,
        # even when the dashboard's optional-login mode is enabled.
        if not auth.enabled:
            return None
        return auth.verify(request.cookies.get("nm_session"))

    @router.post("/ingest")
    async def ingest(request: Request):
        sensor_id = request.headers.get("X-LanPulse-Sensor", "")
        token = request.headers.get("X-LanPulse-Key", "")
        if not sensor_id or not await asyncio.to_thread(store.authenticate_sensor, sensor_id, token):
            return JSONResponse({"error": "Invalid runtime sensor credentials"}, 403)
        if not await asyncio.to_thread(store.allow_request, sensor_id):
            return JSONResponse({"error": "Sensor request rate limit exceeded"}, 429)
        raw = await _read_capped(request)
        if raw is None:
            return JSONResponse({"error": "Request too large"}, 413)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return JSONResponse({"error": "Body must be valid JSON"}, 400)
        if not isinstance(payload, dict) or set(payload) != {"events"}:
            return JSONResponse({"error": "Expected an object containing only events"}, 400)
        try:
            result = await asyncio.to_thread(store.ingest, sensor_id, payload["events"])
        except PermissionError:
            return JSONResponse({"error": "Unknown or revoked runtime sensor"}, 403)
        except (TypeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, 400)
        return result

    @router.get("/sensors")
    async def sensors(request: Request):
        if not dashboard_user(request):
            return JSONResponse({"error": "Dashboard sign-in required"}, 401)
        return {"sensors": await asyncio.to_thread(store.sensors)}

    @router.post("/sensors")
    async def register_sensor(request: Request):
        if not dashboard_user(request):
            return JSONResponse({"error": "Dashboard sign-in required"}, 401)
        try:
            body = await request.json()
        except (ValueError, UnicodeDecodeError):
            body = None
        if not isinstance(body, dict) or set(body) != {"id"}:
            return JSONResponse({"error": "Expected a JSON object containing only id"}, 400)
        try:
            sensor_id = body["id"]
            token = await asyncio.to_thread(store.register_sensor, sensor_id)
        except (TypeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, 400)
        return {"sensor": {"id": sensor_id, "state": "active"}, "token": token}

    @router.post("/sensors/{sensor_id}/revoke")
    async def revoke_sensor(sensor_id: str, request: Request):
        if not dashboard_user(request):
            return JSONResponse({"error": "Dashboard sign-in required"}, 401)
        revoked = await asyncio.to_thread(store.revoke_sensor, sensor_id)
        if not revoked:
            return JSONResponse({"error": "Active sensor not found"}, 404)
        return {"ok": True}

    @router.get("/events")
    async def sample_events(request: Request, sha256: str, limit: int = 200):
        if not dashboard_user(request):
            return JSONResponse({"error": "Dashboard sign-in required"}, 401)
        try:
            events = await asyncio.to_thread(store.events_for_sample, sha256, limit)
        except (TypeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, 400)
        return {"sample_sha256": sha256.lower(), "events": events}

    return router
