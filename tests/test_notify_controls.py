# SPDX-License-Identifier: GPL-2.0-or-later
"""Per-channel importance filter, hourly limit and repeat setting for alerts."""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import alerts  # noqa: E402


def settings(**chan):
    s = alerts.with_defaults({})
    for name, fields in chan.items():
        s["channels"][name].update({"enabled": True, **fields})
    return s


class ChannelControls(unittest.TestCase):
    def setUp(self):
        alerts._HOURLY.clear()
        alerts.MUTED["count"] = 0

    def sent(self, s, title, priority=3, rule="new_device"):
        calls = []
        with patch.object(alerts, "send_one", side_effect=lambda st, n, t, m, p, e=None: calls.append((n, t, m)) or None):
            alerts.send_all(s, title, "body", priority, {"rule": rule})
        return calls

    def test_defaults_send_everything(self):
        self.assertEqual(len(self.sent(settings(irc={}), "x")), 1)

    def test_important_only_drops_routine_alerts_but_keeps_serious_ones(self):
        s = settings(webhook={"min_level": 4}, irc={})
        self.assertEqual([c[0] for c in self.sent(s, "new device")], ["irc"])
        self.assertEqual({c[0] for c in self.sent(s, "malware", 3, "compromise")}, {"webhook", "irc"})
        self.assertEqual({c[0] for c in self.sent(s, "service", 3, "services")}, {"webhook", "irc"})

    def test_critical_only(self):
        s = settings(email={"min_level": 5})
        self.assertEqual(self.sent(s, "honeypot hit", 4, "local_threats"), [])
        self.assertEqual(len(self.sent(s, "dns", 5, "dns_threats")), 1)

    def test_hourly_limit_sends_one_notice_then_holds_the_rest(self):
        s = settings(irc={"max_per_hour": 2})
        titles = [t for i in range(6) for (_, t, _) in self.sent(s, f"a{i}")]
        self.assertEqual(titles, ["a0", "a1", "LanPulse alert limit reached"])

    def test_next_hour_reports_how_many_were_held(self):
        s = settings(irc={"max_per_hour": 1})
        for i in range(4):
            self.sent(s, f"a{i}")
        alerts._HOURLY["irc"]["start"] -= 3601
        out = self.sent(s, "later")
        self.assertEqual(len(out), 1)
        self.assertIn("held back", out[0][2])

    def test_daily_summary_ignores_the_controls(self):
        s = settings(irc={"min_level": 5, "max_per_hour": 1})
        for _ in range(3):
            self.assertEqual(len(self.sent(s, "summary", 3, "summary")), 1)

    def test_settings_are_validated(self):
        cur = alerts.with_defaults({})
        new = alerts.apply_update(cur, {"channels": {"irc": {"min_level": "7", "max_per_hour": "-4"}},
                                        "notify": {"repeat_minutes": "99999"}})
        self.assertEqual(new["channels"]["irc"]["min_level"], 1)
        self.assertEqual(new["channels"]["irc"]["max_per_hour"], 0)
        self.assertEqual(new["notify"]["repeat_minutes"], 1440)
        new = alerts.apply_update(new, {"channels": {"irc": {"min_level": 4, "max_per_hour": 20}}, "notify": {"repeat_minutes": 60}})
        self.assertEqual((new["channels"]["irc"]["min_level"], new["channels"]["irc"]["max_per_hour"], new["notify"]["repeat_minutes"]), (4, 20, 60))


if __name__ == "__main__":
    unittest.main()
