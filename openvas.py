# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
OpenVAS / Greenbone integration.

nmap can only guess at vulnerabilities from banners and a few safe probes. OpenVAS (Greenbone Community Edition) runs
tens of thousands of real vulnerability tests, so it is the accurate source. LanPulse:

  * installs it for you (Settings > Scanner runs a root-only helper that sets up Docker + the Greenbone containers),
  * talks to its management daemon (gvmd) with the Greenbone Management Protocol (GMP, plain XML over a unix socket),
  * starts one scan per device, and
  * imports the results into the Vulnerabilities view. Results with a high "quality of detection" (the test actually
    exercised the flaw or fingerprinted the exact version) are shown as Confirmed.

LanPulse never exploits anything here: it asks OpenVAS to run its normal (non-destructive) "Full and fast" scan.
There is no extra Python dependency: GMP is a small XML protocol, spoken directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("lanpulse.openvas")

SOCKET_NAME = "gvmd/gvmd.sock"           # inside <data>/openvas, bind-mounted into the gvmd container by the helper
CONFIG_NAME = "Full and fast"
PORTLIST_NAME = "All IANA assigned TCP"
SCANNER_NAME = "OpenVAS Default"
CONFIRMED_QOD = 80                       # remote_vul / remote_app and better: the test exercised the flaw
MIN_QOD = 70                             # below this OpenVAS itself treats a result as a weak guess
MAX_RESULTS = 200
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class GmpError(Exception):
    pass


class Gmp:
    """Minimal GMP client: one XML command in, one XML response out."""

    def __init__(self, path: str, timeout: float = 30):
        self.path, self.timeout = path, timeout
        self.s: socket.socket | None = None

    def __enter__(self):
        if self.s is not None:                # already connected (and possibly logged in): keep that connection
            return self
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(self.timeout)
        try:
            self.s.connect(self.path)
        except OSError as e:
            self.s.close()
            raise GmpError(f"can't reach the OpenVAS service ({e.strerror or e})") from None
        return self

    def __exit__(self, *a):
        try:
            self.s.close()
        except Exception:
            pass

    def cmd(self, xml: str) -> ET.Element:
        self.s.sendall(xml.encode())
        buf = b""
        while True:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                raise GmpError("OpenVAS took too long to answer") from None
            if not chunk:
                raise GmpError("OpenVAS closed the connection")
            buf += chunk
            if len(buf) > 40_000_000:
                raise GmpError("OpenVAS reply was too large")
            try:
                root = ET.fromstring(buf)
            except ET.ParseError:
                continue                    # reply not complete yet
            status = root.get("status", "")
            if status and not status.startswith("2"):
                raise GmpError(root.get("status_text") or f"OpenVAS error {status}")
            return root

    def auth(self, user: str, password: str):
        esc = lambda t: (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.cmd(f"<authenticate><credentials><username>{esc(user)}</username><password>{esc(password)}</password>"
                 f"</credentials></authenticate>")

    def find_id(self, command: str, tag: str, name: str) -> str:
        root = self.cmd(f"<{command} filter=\"rows=-1\"/>")
        for el in root.findall(tag):
            if (el.findtext("name") or "").strip().lower() == name.lower():
                return el.get("id", "")
        for el in root.findall(tag):        # prefix match, e.g. "Full and fast" vs "Full and fast ultimate"
            if (el.findtext("name") or "").lower().startswith(name.lower()):
                return el.get("id", "")
        raise GmpError(f"OpenVAS doesn't have \"{name}\" yet. It is probably still loading its vulnerability feed.")


def parse_results(root: ET.Element) -> list[dict]:
    """GMP <get_results_response> -> [{name, cve, port, severity, qod, desc, oid}] (worst first, capped)."""
    out, seen = [], set()
    for r in root.iter("result"):
        try:
            sev = float(r.findtext("severity") or 0)
            qod = int(float(r.findtext("qod/value") or 0))
        except ValueError:
            continue
        if sev <= 0:
            continue                         # log/info results are not vulnerabilities
        nvt = r.find("nvt")
        oid = (nvt.get("oid") if nvt is not None else "") or ""
        name = (r.findtext("name") or (nvt.findtext("name") if nvt is not None else "") or "")[:160]
        cves = []
        if nvt is not None:
            for ref in nvt.iter("ref"):
                if ref.get("type", "").lower() == "cve" and CVE_RE.fullmatch(ref.get("id", "") or ""):
                    cves.append(ref.get("id").upper())
            for m in CVE_RE.findall(nvt.findtext("cve") or ""):
                cves.append(m.upper())
        cves = sorted(set(cves))
        port = 0
        m = re.match(r"(\d+)/", r.findtext("port") or "")
        if m:
            port = int(m.group(1))
        key = (oid or name, port)
        if key in seen:
            continue
        seen.add(key)
        desc = re.sub(r"\s+", " ", (r.findtext("description") or "")).strip()[:300]
        out.append({"oid": oid[:80], "name": name, "cve": cves[:12], "port": port, "severity": round(sev, 1),
                    "qod": qod, "desc": desc, "host": (r.findtext("host") or "").strip()[:45]})
    out.sort(key=lambda x: (-x["severity"], -x["qod"]))
    return out[:MAX_RESULTS]


class OpenVAS:
    def __init__(self, nm):
        self.nm = nm
        self.dir = Path(nm.data_dir) / "openvas"
        self.state_file = self.dir / "scans.json"
        self.scans: dict[str, dict] = {}     # ip -> {task, status, progress, started, finished, error}
        self.ready_cache = (0.0, None)
        self.wake = asyncio.Event()
        try:
            self.scans = json.loads(self.state_file.read_text())
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------------ config
    def cfg(self) -> dict:
        c = {"enabled": False, "auto": False, "username": "admin", "password": ""}
        c.update({k: v for k, v in (self.nm.settings.get("openvas") or {}).items() if k in c})
        if not c["password"]:               # the installer stores the admin password it generated
            try:
                c["password"] = (self.dir / "admin.pw").read_text().strip()
            except OSError:
                pass
        return c

    def sock_path(self) -> str:
        return str(self.dir / SOCKET_NAME)

    def installed(self) -> bool:
        return Path(self.sock_path()).exists()

    def _open(self) -> Gmp:
        c = self.cfg()
        g = Gmp(self.sock_path()).__enter__()
        try:
            g.auth(c["username"], c["password"])
        except Exception:
            g.__exit__()
            raise
        return g

    def _save(self):
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.scans))
            tmp.replace(self.state_file)
        except OSError:
            log.exception("couldn't save OpenVAS scan state")

    # ------------------------------------------------------------------ status
    def check(self) -> tuple[bool, str]:
        """Is OpenVAS reachable, logged in and finished loading its feed? Returns (ready, message)."""
        if not self.installed():
            return False, "OpenVAS isn't installed yet."
        try:
            with self._open() as g:
                g.find_id("get_configs", "config", CONFIG_NAME)
                g.find_id("get_scanners", "scanner", SCANNER_NAME)
            return True, "Ready."
        except GmpError as e:
            if "auth" in str(e).lower():
                return False, ("LanPulse can reach OpenVAS but its admin login doesn't match, so the installer's password "
                               "step didn't finish. Press Install OpenVAS again to finish it.")
            return False, str(e)
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"[:200]

    def status(self) -> dict:
        helper = self.helper_state()
        ready, msg = (False, helper.get("message", "")) if not self.installed() else self.cached_check()
        devs = {d["ip"]: d for d in self.nm.devices.values() if d.get("ip")}
        scans = []
        for ip, s in self.scans.items():
            d = devs.get(ip)
            scans.append({"ip": ip, "name": self.nm.label(d) if d else ip, **{k: s.get(k) for k in
                          ("status", "progress", "started", "finished", "error", "count")}})
        c = self.cfg()
        try:
            log_tail = "\n".join((self.dir / "log.txt").read_text(errors="replace").splitlines()[-30:])
        except OSError:
            log_tail = ""
        return {"installed": self.installed(), "ready": ready, "message": msg, "enabled": c["enabled"],
                "auto": c["auto"], "helper": helper, "scans": scans, "log": log_tail}

    def cached_check(self) -> tuple[bool, str]:
        t, res = self.ready_cache
        if res is not None and time.time() - t < 20:
            return res
        res = self.check()
        self.ready_cache = (time.time(), res)
        return res

    def helper_state(self) -> dict:
        try:
            st = json.loads((self.dir / "status.json").read_text())
        except (OSError, ValueError):
            return {}
        # The installer updates this file at every step. If it says "installing" but nothing has touched it for a
        # long while and no request is pending, the installer died (server restart, full disk): don't hang forever.
        if st.get("state") in ("installing", "queued") and not (self.dir / "request").exists():
            try:
                age = time.time() - (self.dir / "status.json").stat().st_mtime
            except OSError:
                age = 0
            if age > 45 * 60:
                return {"state": "failed", "message": "The installer stopped before it finished (the server may have "
                        "restarted or run out of disk space). Press Install to continue where it left off."}
        return st

    # ------------------------------------------------------------------ scanning
    def start_scan(self, ip: str) -> str:
        """Create a target + task for one device and start it. Returns '' or an error message."""
        if not IP_RE.match(ip or ""):
            return "That isn't a valid address."
        if not any(d.get("ip") == ip for d in self.nm.devices.values()):
            return "That device isn't on your network map."
        cur = self.scans.get(ip)
        if cur and cur.get("status") in ("Requested", "Queued", "Running", "New"):
            return "A scan of this device is already running."
        clash = self.nm.local.conflict_for(ip)
        if clash:
            return (f"{ip} is being answered by more than one device ({', '.join(clash)}), so a scan could land on either "
                    "one. Give one of them another address, then scan again.")
        try:
            with self._open() as g:
                cfg = g.find_id("get_configs", "config", CONFIG_NAME)
                scanner = g.find_id("get_scanners", "scanner", SCANNER_NAME)
                plist = g.find_id("get_port_lists", "port_list", PORTLIST_NAME)
                stamp = time.strftime("%Y%m%d-%H%M%S")
                t = g.cmd(f"<create_target><name>LanPulse {ip} {stamp}</name><hosts>{ip}</hosts>"
                          f"<port_list id=\"{plist}\"/></create_target>")
                task = g.cmd(f"<create_task><name>LanPulse {ip} {stamp}</name><config id=\"{cfg}\"/>"
                             f"<target id=\"{t.get('id')}\"/><scanner id=\"{scanner}\"/></create_task>")
                tid = task.get("id", "")
                g.cmd(f"<start_task task_id=\"{tid}\"/>")
        except GmpError as e:
            return str(e)
        except Exception as e:
            return f"{type(e).__name__}: {e}"[:200]
        dev = next((d for d in self.nm.devices.values() if d.get("ip") == ip), {})
        self.scans[ip] = {"task": tid, "status": "Requested", "progress": 0, "started": int(time.time()),
                          "finished": 0, "error": "", "count": 0, "mac": str(dev.get("mac") or "").lower()}
        self._save()
        self.wake.set()
        return ""

    def poll(self):
        """Update running scans; import results of finished ones."""
        active = {ip: s for ip, s in self.scans.items() if s.get("status") in ("Requested", "Queued", "Running", "New")}
        if not active:
            return
        try:
            g = self._open()
        except Exception as e:
            log.info("OpenVAS poll skipped: %s", e)
            return
        with g:
            for ip, s in active.items():
                try:
                    root = g.cmd(f"<get_tasks task_id=\"{s['task']}\"/>")
                    task = root.find("task")
                    if task is None:
                        s["status"], s["error"] = "Failed", "OpenVAS no longer has this scan."
                        continue
                    s["status"] = (task.findtext("status") or "").strip() or s["status"]
                    try:
                        s["progress"] = max(0, int(float(task.findtext("progress") or 0)))
                    except ValueError:
                        pass
                    if s["status"] == "Done":
                        res = g.cmd(f"<get_results task_id=\"{s['task']}\" filter=\"min_qod={MIN_QOD} rows={MAX_RESULTS} "
                                    f"sort-reverse=severity\" details=\"1\"/>")
                        items = parse_results(res)
                        # Each result names the host OpenVAS found it on. Anything that isn't the address we asked
                        # it to scan belongs to another machine and is dropped.
                        foreign = {i["host"] for i in items if i.get("host") and i["host"] != ip}
                        if foreign:
                            items = [i for i in items if not i.get("host") or i["host"] == ip]
                            log.warning("OpenVAS scan of %s also returned results for %s; ignored", ip, ", ".join(sorted(foreign)))
                        s["finished"], s["count"], s["progress"] = int(time.time()), len(items), 100
                        clash = self.nm.local.conflict_for(ip, since=s.get("started", 0))
                        if clash:
                            # Don't attach findings that may belong to the other machine
                            s["error"] = (f"{ip} was answered by more than one device ({', '.join(clash)}) during the scan, "
                                          "so the results can't be trusted and were not saved. Fix the address conflict and scan again.")
                            s["count"] = 0
                        else:
                            self._import(ip, items)
                    elif s["status"] in ("Stopped", "Interrupted", "Failed"):
                        s["error"] = f"The scan {s['status'].lower()}."
                except GmpError as e:
                    s["error"] = str(e)
        self._save()

    def items_for(self, d: dict) -> list:
        """OpenVAS findings that really belong to this device. Scans are requested by IP address, and addresses get
        reused (DHCP, swapped VMs), so findings are tied to the machine's MAC and ignored if the device differs."""
        items = d.get("openvas") or []
        if not items:
            return []
        f = d.get("openvas_for") or {}
        mac = str(d.get("mac") or "").lower()
        if f.get("mac"):
            return items if f["mac"] == mac else []
        # Older results with no record of which machine was scanned: a scan that finished before this device first
        # appeared can't be about it
        fin = (self.scans.get(d.get("ip")) or {}).get("finished") or 0
        if fin and d.get("first_seen") and fin < d["first_seen"]:
            return []
        return items

    def _import(self, ip: str, items: list[dict]):
        mac = str((self.scans.get(ip) or {}).get("mac") or "").lower()
        for d in self.nm.devices.values():
            if (mac and str(d.get("mac") or "").lower() == mac) or (not mac and d.get("ip") == ip):
                d["openvas"] = items
                d["openvas_for"] = {"ip": ip, "mac": mac or str(d.get("mac") or "").lower()}
                crit = sum(1 for i in items if i["severity"] >= 9)
                self.nm.event("openvas", d, f"OpenVAS scan finished: {len(items)} findings"
                              + (f", {crit} critical" if crit else ""), "bad" if crit else "info", feed=False)
                self.nm.save()
                try:
                    self.nm.vulns.evaluate()
                except Exception:
                    log.exception("re-evaluating vulnerabilities failed")
                return

    async def run(self):
        while True:
            try:
                c = self.cfg()
                if c["enabled"] and self.installed():
                    await asyncio.to_thread(self.poll)
                    if c["auto"]:
                        await asyncio.to_thread(self.auto_scan)
            except Exception:
                log.exception("OpenVAS loop failed")
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()

    def auto_scan(self):
        """Weekly rescan of online devices, one at a time (OpenVAS is heavy)."""
        if any(s.get("status") in ("Requested", "Queued", "Running", "New") for s in self.scans.values()):
            return
        week = 7 * 86400
        def mine(d):    # a scan record only counts for the machine that was scanned, not whoever holds the IP now
            s = self.scans.get(d["ip"], {})
            return s if not s.get("mac") or s["mac"] == str(d.get("mac") or "").lower() else {}
        due = [d for d in self.nm.devices.values() if d.get("online") and d.get("ip") and not d.get("is_self")
               and time.time() - mine(d).get("finished", 0) > week
               and time.time() - mine(d).get("started", 0) > week]
        if due:
            self.start_scan(due[0]["ip"])
