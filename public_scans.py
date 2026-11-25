# SPDX-License-Identifier: GPL-2.0-or-later
"""User-approved scans of explicitly entered public IPv4 targets.

This is intentionally separate from threat-source investigation: no attacker IP is
ever copied into a scan request automatically.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import selectors
import shutil
import subprocess
import tempfile
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
    if (address.version != 4 or not address.is_global or address.is_multicast or
            address.is_unspecified or address.is_loopback or address.is_link_local or address.is_reserved):
        raise ValueError("The target must be a globally routable public IPv4 address, not a reserved or multicast address.")
    return str(address)


class PublicScans:
    """Small persistent queue for bounded Nmap scans of manually approved public IPs."""

    ACTIVE = {"Requested", "Running"}
    MAX_HISTORY = 100
    TARGET_COOLDOWN_SECONDS = 3600
    GLOBAL_COOLDOWN_SECONDS = 60

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

    def _prune_history_locked(self, now: int):
        """Bound persisted history while never pruning a queued or running scan."""
        terminal = sorted(
            ((key, row) for key, row in self.scans.items() if row.get("status") not in self.ACTIVE),
            key=lambda item: item[1].get("started", 0), reverse=True,
        )
        keep = {key for key, _ in terminal[:self.MAX_HISTORY]}
        keep.update(key for key, row in self.scans.items() if row.get("status") in self.ACTIVE)
        if len(keep) != len(self.scans):
            self.scans = {key: row for key, row in self.scans.items() if key in keep}
            self._save()

    def list(self) -> list[dict]:
        with self.lock:
            rows = [dict(v) for v in self.scans.values()]
        return sorted(rows, key=lambda x: x.get("started", 0), reverse=True)[:30]

    def start_nmap(self, target: str, authorized_by: str = "dashboard-admin") -> tuple[dict | None, str]:
        try:
            target = validate_public_ipv4(target)
        except ValueError as exc:
            return None, str(exc)
        if not shutil.which("nmap"):
            return None, "Nmap is not installed on this LanPulse server."
        with self.lock:
            now = int(time.time())
            self._prune_history_locked(now)
            if any(s.get("status") in self.ACTIVE for s in self.scans.values()):
                return None, "A public IP scan is already queued or running. Wait for it to finish first."
            previous_global = max((int(s.get("started") or 0) for s in self.scans.values()), default=0)
            global_wait = self.GLOBAL_COOLDOWN_SECONDS - (now - previous_global)
            if previous_global and global_wait > 0:
                return None, f"A public Nmap scan was started recently. Wait about {global_wait} second(s) before another scan."
            previous = max((s.get("started", 0) for s in self.scans.values()
                            if s.get("target") == target), default=0)
            wait = self.TARGET_COOLDOWN_SECONDS - (now - previous)
            if previous and wait > 0:
                return None, f"This target was scanned recently. Try again in about {max(1, (wait + 59) // 60)} minute(s)."
            scan_id = uuid.uuid4().hex[:12]
            record = {"id": scan_id, "target": target, "scanner": "nmap", "scope": "top-1000-tcp-ports",
                      "status": "Requested", "progress": 0, "started": now,
                      "finished": 0, "ports": [], "host_state": "unknown", "error": "", "authorized": True,
                      "authorized_by": str(authorized_by or "dashboard-admin")[:80], "authorized_at": now,
                      "authorization_attestation": "User confirmed ownership or explicit authorization in dashboard"}
            self.scans[scan_id] = record
            self._prune_history_locked(now)
            self._save()
        self.pool.submit(self._run_nmap, scan_id, target)
        return dict(record), ""

    def _run_nmap(self, scan_id: str, target: str):
        with self.lock:
            if scan_id not in self.scans:
                return
            self.scans[scan_id]["status"] = "Running"
            self._save()
        try:
            # Write XML to a temporary file so stderr can be streamed independently for live
            # progress without mixing Nmap's progress messages into the XML document.
            with tempfile.TemporaryDirectory(prefix="lanpulse-nmap-") as tmp:
                xml_path = Path(tmp) / "scan.xml"
                cmd = ["nmap", "-Pn", "-n", "-T3", "--top-ports", "1000", "-sV",
                       "--version-light", "--reason", "--stats-every", "5s",
                       "-oX", str(xml_path), target]
                with subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                      text=False, bufsize=0) as proc:
                    started = time.monotonic()
                    pending = b""
                    with selectors.DefaultSelector() as selector:
                        selector.register(proc.stderr, selectors.EVENT_READ)
                        while True:
                            if time.monotonic() - started > 900:
                                proc.kill()
                                proc.wait()
                                raise subprocess.TimeoutExpired(cmd, 900)
                            ready = selector.select(timeout=1)
                            if ready:
                                # Nmap writes live progress with carriage returns, not necessarily
                                # newline-terminated lines. readline() can therefore block until the
                                # scan ends and leave the UI stuck at "started". Read available bytes
                                # and split on either line ending so progress is persisted live.
                                chunk = os.read(proc.stderr.fileno(), 4096)
                                if chunk:
                                    pending += chunk
                                    while True:
                                        cuts = [p for p in (pending.find(b"\\r"), pending.find(b"\\n")) if p >= 0]
                                        if not cuts:
                                            break
                                        cut = min(cuts)
                                        line = pending[:cut]
                                        pending = pending[cut + 1:]
                                        if line.strip():
                                            self._update_progress(scan_id, line.decode("utf-8", "replace"))
                                else:
                                    break
                            elif proc.poll() is not None:
                                break
                        if pending.strip():
                            self._update_progress(scan_id, pending.decode("utf-8", "replace"))
                        returncode = proc.wait(timeout=5)
                if returncode not in (0, 1):
                    raise RuntimeError("Nmap exited with status " + str(returncode))
                if not xml_path.exists():
                    raise RuntimeError("Nmap finished without producing scan results.")
                root = ET.parse(xml_path).getroot()
            host = root.find("host")
            host_status = host.find("status") if host is not None else None
            host_state = host_status.get("state", "unknown") if host_status is not None else "unknown"
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
                                "ports": ports, "host_state": host_state, "summary": summary})
                    self._save()
        except subprocess.TimeoutExpired:
            self._finish_error(scan_id, "Nmap timed out after 15 minutes.")
        except Exception as exc:
            self._finish_error(scan_id, str(exc)[:300])

    def _update_progress(self, scan_id: str, line: str):
        """Persist Nmap's periodic progress without exposing raw command output to the UI."""
        match = re.search(r"(?:About\s+)?([0-9]+(?:\.[0-9]+)?)%\s+done", line, re.I)
        phase = re.search(r"undergoing\s+([^;]+)", line, re.I)
        with self.lock:
            rec = self.scans.get(scan_id)
            if rec is None or rec.get("status") != "Running":
                return
            if match:
                rec["progress"] = max(1, min(99, int(float(match.group(1)))))
            rec["phase"] = (phase.group(1).strip()[:100] if phase else
                            ("Nmap is scanning ports and identifying services" if not rec.get("phase") else rec["phase"]))
            rec["updated"] = int(time.time())
            self._save()

    def _finish_error(self, scan_id: str, message: str):
        with self.lock:
            rec = self.scans.get(scan_id)
            if rec is not None:
                rec.update({"status": "Failed", "finished": int(time.time()), "error": message})
                self._save()

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)
