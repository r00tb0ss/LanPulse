# SPDX-License-Identifier: GPL-2.0-or-later
"""User-approved scans of explicitly entered public IPv4 targets.

This is intentionally separate from threat-source investigation: no attacker IP is
ever copied into a scan request automatically.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("lanpulse.public_scans")


def validate_public_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        raise ValueError("Enter a valid public IPv4 address.") from None
    if address.version != 4 or not address.is_global:
        raise ValueError("The target must be a globally routable public IPv4 address.")
    return str(address)


class PublicScans:
    """Small persistent queue for bounded Nmap scans of manually approved public IPs."""

    ACTIVE = {"Requested", "Running"}

    def __init__(self, data_dir: str | Path):
        self.path = Path(data_dir) / "authorized-public-scans.json"
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="lanpulse-public-scan")
        try:
            raw = json.loads(self.path.read_text())
            self.scans = raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            self.scans = {}
        # A process restart cannot resume an in-flight subprocess; make that explicit.
        for scan in self.scans.values():
            if scan.get("status") in self.ACTIVE:
                scan.update({"status": "Interrupted", "finished": int(time.time()),
                             "error": "LanPulse restarted before this scan finished."})
        self._save()

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.scans, separators=(",", ":")))
            tmp.replace(self.path)
        except OSError:
            log.exception("Could not persist authorized public scan history")

    def list(self) -> list[dict]:
        with self.lock:
            rows = [dict(v) for v in self.scans.values()]
        return sorted(rows, key=lambda x: x.get("started", 0), reverse=True)[:30]

    def start_nmap(self, target: str) -> tuple[dict | None, str]:
        try:
            target = validate_public_ipv4(target)
        except ValueError as exc:
            return None, str(exc)
        if not shutil.which("nmap"):
            return None, "Nmap is not installed on this LanPulse server."
        with self.lock:
            if any(s.get("status") in self.ACTIVE for s in self.scans.values()):
                return None, "A public IP scan is already queued or running. Wait for it to finish first."
            scan_id = uuid.uuid4().hex[:12]
            record = {"id": scan_id, "target": target, "scanner": "nmap", "scope": "top-1000-tcp-ports",
                      "status": "Requested", "progress": 0, "started": int(time.time()),
                      "finished": 0, "ports": [], "error": "", "authorized": True}
            self.scans[scan_id] = record
            self._save()
        self.pool.submit(self._run_nmap, scan_id, target)
        return dict(record), ""

    def _run_nmap(self, scan_id: str, target: str):
        with self.lock:
            if scan_id not in self.scans:
                return
            self.scans[scan_id]["status"] = "Running"
            self._save()
        cmd = ["nmap", "-Pn", "-n", "-T3", "--top-ports", "1000", "-sV",
               "--version-light", "--reason", "-oX", "-", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
            if result.returncode not in (0, 1):
                raise RuntimeError((result.stderr or "Nmap exited with an error").strip()[:300])
            root = ET.fromstring(result.stdout or "")
            host = root.find("host")
            ports = []
            if host is not None:
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    svc = port.find("service")
                    ports.append({
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": (svc.get("name", "") if svc is not None else "")[:60],
                        "product": (svc.get("product", "") if svc is not None else "")[:100],
                        "version": (svc.get("version", "") if svc is not None else "")[:80],
                        "tunnel": (svc.get("tunnel", "") if svc is not None else "")[:20],
                    })
            state = root.find("runstats/finished")
            summary = (state.get("summary", "") if state is not None else "")[:300]
            with self.lock:
                rec = self.scans.get(scan_id)
                if rec is not None:
                    rec.update({"status": "Done", "progress": 100, "finished": int(time.time()),
                                "ports": ports, "summary": summary})
                    self._save()
        except subprocess.TimeoutExpired:
            self._finish_error(scan_id, "Nmap timed out after 15 minutes.")
        except Exception as exc:
            self._finish_error(scan_id, str(exc)[:300])

    def _finish_error(self, scan_id: str, message: str):
        with self.lock:
            rec = self.scans.get(scan_id)
            if rec is not None:
                rec.update({"status": "Failed", "finished": int(time.time()), "error": message})
                self._save()

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)
