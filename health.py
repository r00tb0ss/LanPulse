# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Health board: is each part LanPulse relies on alive, and when did it last report?

Nothing new is collected here. This reads the status each part already keeps (UniFi, SNMP, Pi-hole, the firewall log
listener, the vulnerability checker and the honeypot sensors) and turns it into one list for the dashboard.
A part that was never set up is reported as "off", not as a problem.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("lanpulse.health")

STALE_LIVE = 10 * 60         # UniFi, SNMP and Pi-hole are polled often; older than this means polling stopped
STALE_LOGS = 24 * 3600       # a quiet network can go a while without a firewall event, but not a day


def _item(key: str, name: str, icon: str, state: str, detail: str, last: float | None = None, hint: str = "") -> dict:
    return {"key": key, "name": name, "icon": icon, "state": state, "detail": detail,
            "last": last or None, "hint": hint}


def _span(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} seconds"
    if seconds < 5400:
        return f"{round(seconds / 60)} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def _polled(key, name, icon, st: dict, now: float, what: str, hint: str) -> dict:
    """Shared logic for UniFi and SNMP, which both report {configured, ok, error, t}."""
    if not st.get("configured"):
        return _item(key, name, icon, "off", "Not connected", None, hint)
    t = st.get("t") or 0
    if not st.get("ok"):
        return _item(key, name, icon, "bad", st.get("error") or "The last refresh failed", t, "Check the address and login in Settings.")
    if t and now - t > STALE_LIVE:
        return _item(key, name, icon, "warn", f"No refresh for {_span(now - t)}", t)
    return _item(key, name, icon, "ok", what, t)


def build(nm, now: float | None = None) -> dict:
    now = now or time.time()
    items: list[dict] = []

    def safe(fn):
        try:
            fn()
        except Exception:                       # one broken part must never hide the others
            log.exception("health check failed")

    def logs():
        th, cfg = nm.threats, nm.settings.get("threats", {})
        if not cfg.get("enabled", True):
            items.append(_item("logs", "Firewall logs", "fa-shield-halved", "off", "Turned off", None,
                               "Settings > Threats turns this on."))
        elif th.syslog_ok is False:
            items.append(_item("logs", "Firewall logs", "fa-shield-halved", "bad", th.syslog_error or "The listener could not start",
                               None, "Another program may be using the port."))
        elif not th.last_event:
            items.append(_item("logs", "Firewall logs", "fa-shield-halved", "warn",
                               f"Listening on UDP {cfg.get('syslog_port', 514)}, nothing received yet", None,
                               "Point your router's syslog at this machine."))
        elif now - th.last_event > STALE_LOGS:
            items.append(_item("logs", "Firewall logs", "fa-shield-halved", "warn",
                               f"Nothing received for {_span(now - th.last_event)}", th.last_event,
                               "Check that your router still sends logs."))
        else:
            items.append(_item("logs", "Firewall logs", "fa-shield-halved", "ok", "Receiving events from your router", th.last_event))

    def unifi():
        items.append(_polled("unifi", "UniFi", "fa-wifi", nm.topology.unifi_status, now,
                             "{} devices and {} clients".format(nm.topology.unifi_status.get("devices", 0),
                                                                nm.topology.unifi_status.get("clients", 0)),
                             "Settings > UniFi adds the map details and one-click blocking."))

    def snmp():
        st = nm.snmp.status
        items.append(_polled("snmp", "SNMP", "fa-network-wired", st, now,
                             f"{st.get('hosts', 0)} switches answering", "Settings > SNMP adds switch ports to the map."))

    def dns():
        cfg, st = nm.settings.get("dns", {}), nm.dns.status
        last = st.get("last_poll") or 0
        if not cfg.get("enabled"):
            items.append(_item("dns", "Pi-hole DNS", "fa-globe", "off", "Not connected", None, "Settings > DNS shows what devices look up."))
        elif st.get("state") == "error":
            items.append(_item("dns", "Pi-hole DNS", "fa-globe", "bad", st.get("error") or "The last poll failed", last,
                               "Check the address and password in Settings."))
        elif last and now - last > STALE_LIVE:
            items.append(_item("dns", "Pi-hole DNS", "fa-globe", "warn", f"No poll for {_span(now - last)}", last))
        else:
            items.append(_item("dns", "Pi-hole DNS", "fa-globe", "ok", "Reading the query log", last))

    def vulns():
        cfg, st = nm.settings.get("vulns", {}), nm.vulns.status
        last = st.get("last_run") or 0
        if not cfg.get("enabled", True):
            items.append(_item("vulns", "Vulnerability data", "fa-bug", "off", "Turned off", None))
        elif st.get("error"):
            items.append(_item("vulns", "Vulnerability data", "fa-bug", "warn", st["error"], last))
        elif st.get("state") == "checking":
            items.append(_item("vulns", "Vulnerability data", "fa-bug", "ok",
                               f"Checking {st.get('pending', 0)} of {st.get('products', 0)} products", last))
        elif last:
            items.append(_item("vulns", "Vulnerability data", "fa-bug", "ok", f"{st.get('products', 0)} products matched", last))
        else:
            items.append(_item("vulns", "Vulnerability data", "fa-bug", "warn", "First check has not finished yet", None))

    def sensors():
        for s in nm.honeyan.sensors():
            where = f" at {s['last_ip']}" if s.get("last_ip") else ""
            last = s.get("last_seen") or 0
            if s["state"] == "connected":
                items.append(_item("sensor:" + s["id"], s["name"], "fa-jar", "ok", f"Connected{where}", last))
            elif s["state"] == "waiting":
                items.append(_item("sensor:" + s["id"], s["name"], "fa-jar", "warn", "Added, but it has not reported yet", None,
                                   "Run the install command on the sensor."))
            else:
                items.append(_item("sensor:" + s["id"], s["name"], "fa-jar", "bad", f"Silent for {_span(now - last)}", last,
                                   "Check that the sensor is powered and can reach this machine."))

    for fn in (logs, unifi, snmp, dns, vulns, sensors):
        safe(fn)
    live = [i for i in items if i["state"] != "off"]
    return {"items": items, "now": now,
            "bad": sum(i["state"] == "bad" for i in live), "warn": sum(i["state"] == "warn" for i in live),
            "ok": sum(i["state"] == "ok" for i in live), "off": sum(i["state"] == "off" for i in items)}
