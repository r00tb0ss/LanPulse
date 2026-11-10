import os
import sys
import unittest
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import health

NOW = 1_000_000.0


def fake(**kw):
    base = dict(
        threats=NS(syslog_ok=True, syslog_error="", last_event=NOW - 30),
        topology=NS(unifi_status={"configured": True, "ok": True, "error": "", "t": NOW - 5, "devices": 4, "clients": 30}),
        snmp=NS(status={"configured": False, "ok": False, "error": "", "t": 0, "hosts": 0}),
        dns=NS(status={"state": "ok", "error": "", "last_poll": NOW - 20}),
        vulns=NS(status={"state": "idle", "error": "", "last_run": NOW - 60, "pending": 0, "products": 12}),
        honeyan=NS(sensors=lambda: []),
        settings={"threats": {"enabled": True}, "dns": {"enabled": True}, "vulns": {"enabled": True}},
    )
    base.update(kw)
    return NS(**base)


def states(out):
    return {i["key"]: i["state"] for i in out["items"]}


class HealthTests(unittest.TestCase):
    def test_healthy_system(self):
        out = health.build(fake(), NOW)
        self.assertEqual(states(out), {"logs": "ok", "unifi": "ok", "snmp": "off", "dns": "ok", "vulns": "ok"})
        self.assertEqual((out["bad"], out["warn"], out["ok"], out["off"]), (0, 0, 4, 1))

    def test_unset_parts_are_off_not_problems(self):
        nm = fake(settings={"threats": {"enabled": False}, "dns": {"enabled": False}, "vulns": {"enabled": False}},
                  topology=NS(unifi_status={"configured": False, "ok": False, "error": "", "t": 0}))
        out = health.build(nm, NOW)
        self.assertEqual(set(states(out).values()), {"off"})
        self.assertEqual(out["bad"] + out["warn"], 0)

    def test_unifi_error_and_stale(self):
        nm = fake(topology=NS(unifi_status={"configured": True, "ok": False, "error": "Login failed", "t": NOW - 5}))
        item = [i for i in health.build(nm, NOW)["items"] if i["key"] == "unifi"][0]
        self.assertEqual((item["state"], item["detail"]), ("bad", "Login failed"))
        nm = fake(topology=NS(unifi_status={"configured": True, "ok": True, "error": "", "t": NOW - 3600, "devices": 1, "clients": 1}))
        self.assertEqual(states(health.build(nm, NOW))["unifi"], "warn")

    def test_firewall_log_states(self):
        self.assertEqual(states(health.build(fake(threats=NS(syslog_ok=False, syslog_error="UDP port 514: in use", last_event=0)), NOW))["logs"], "bad")
        self.assertEqual(states(health.build(fake(threats=NS(syslog_ok=True, syslog_error="", last_event=0)), NOW))["logs"], "warn")
        self.assertEqual(states(health.build(fake(threats=NS(syslog_ok=True, syslog_error="", last_event=NOW - 3 * 86400)), NOW))["logs"], "warn")

    def test_sensors(self):
        sensors = [{"id": "a", "name": "pi-one", "state": "connected", "last_seen": NOW - 10, "last_ip": "192.168.0.50"},
                   {"id": "b", "name": "pi-two", "state": "waiting", "last_seen": 0, "last_ip": ""},
                   {"id": "c", "name": "pi-three", "state": "silent", "last_seen": NOW - 7200, "last_ip": ""}]
        out = health.build(fake(honeyan=NS(sensors=lambda: sensors)), NOW)
        s = states(out)
        self.assertEqual((s["sensor:a"], s["sensor:b"], s["sensor:c"]), ("ok", "warn", "bad"))
        self.assertIn("2.0 hours", [i for i in out["items"] if i["key"] == "sensor:c"][0]["detail"])

    def test_one_broken_part_does_not_hide_the_rest(self):
        def boom():
            raise RuntimeError("db locked")
        out = health.build(fake(honeyan=NS(sensors=boom)), NOW)
        self.assertIn("unifi", states(out))


if __name__ == "__main__":
    unittest.main()
