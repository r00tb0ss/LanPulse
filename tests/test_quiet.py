import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import alerts

NOW = datetime.datetime(2026, 11, 10, 14, 30).timestamp()


class QuietTests(unittest.TestCase):
    def test_minutes(self):
        self.assertEqual(alerts.quiet_until({"minutes": 60}, NOW), NOW + 3600)
        self.assertEqual(alerts.quiet_until({"minutes": 10 ** 9}, NOW), NOW + 7 * 86400)     # capped at a week
        self.assertEqual(alerts.quiet_until({"minutes": "soon"}, NOW), 0.0)

    def test_off(self):
        self.assertEqual(alerts.quiet_until({"off": True, "minutes": 60}, NOW), 0.0)

    def test_until_morning_is_the_next_8am(self):
        until = datetime.datetime.fromtimestamp(alerts.quiet_until({"morning": True}, NOW))
        self.assertEqual((until.day, until.hour, until.minute), (11, 8, 0))
        early = datetime.datetime(2026, 11, 10, 6, 0).timestamp()          # before 8 AM: the same morning
        self.assertEqual(datetime.datetime.fromtimestamp(alerts.quiet_until({"morning": True}, early)).day, 10)

    def test_quiet_left(self):
        self.assertEqual(alerts.quiet_left({"quiet": {"until": NOW + 100}}, NOW), 100)
        self.assertEqual(alerts.quiet_left({"quiet": {"until": NOW - 5}}, NOW), 0.0)
        self.assertEqual(alerts.quiet_left({}, NOW), 0.0)
        self.assertEqual(alerts.quiet_left({"quiet": {"until": "junk"}}, NOW), 0.0)

    def test_send_all_is_held_back_while_quiet(self):
        settings = {"channels": {"ntfy": {"enabled": True}}, "quiet": {"until": 4_000_000_000}}
        alerts.MUTED["count"] = 0
        with mock.patch.object(alerts, "send_one", return_value=None) as send:
            self.assertEqual(alerts.send_all(settings, "t", "m", 3, {"rule": "new_device"}), {})
            send.assert_not_called()
            self.assertEqual(alerts.MUTED["count"], 1)
            # the daily summary is not an alert, so it still goes out
            alerts.send_all(settings, "t", "m", 3, {"rule": "summary"})
            send.assert_called_once()

    def test_send_all_works_normally_when_not_quiet(self):
        settings = {"channels": {"ntfy": {"enabled": True}}, "quiet": {"until": 0}}
        with mock.patch.object(alerts, "send_one", return_value=None) as send:
            self.assertEqual(alerts.send_all(settings, "t", "m", 3, {"rule": "new_device"}), {"ntfy": None})
            send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
