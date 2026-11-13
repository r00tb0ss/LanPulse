# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Regression tests for the 1.34.19 hardening changes."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import alerts
import auth
import discovery

NOW = 1_800_000_000.0


def settings(**sections):
    s = alerts.with_defaults({})
    for name, fields in sections.items():
        s[name].update(fields)
    return s


class MovedSecrets(unittest.TestCase):
    def test_changing_the_unifi_address_forgets_the_saved_key(self):
        cur = settings(unifi={"host": "192.168.1.1", "api_key": "real-key"})
        new = alerts.apply_update(cur, {"unifi": {"host": "203.0.113.9", "api_key": alerts.MASK}})
        self.assertEqual(new["unifi"]["host"], "203.0.113.9")
        self.assertEqual(new["unifi"]["api_key"], "")

    def test_typing_the_key_again_keeps_it(self):
        cur = settings(unifi={"host": "192.168.1.1", "api_key": "real-key"})
        new = alerts.apply_update(cur, {"unifi": {"host": "192.168.1.2", "api_key": "new-key"}})
        self.assertEqual(new["unifi"]["api_key"], "new-key")

    def test_saving_without_moving_the_address_keeps_the_secret(self):
        cur = settings(unifi={"host": "192.168.1.1", "api_key": "real-key"},
                       dns={"url": "http://192.168.1.2", "password": "pw"})
        new = alerts.apply_update(cur, {"unifi": {"host": "192.168.1.1", "api_key": alerts.MASK, "site": "default"},
                                        "dns": {"url": "http://192.168.1.2", "password": alerts.MASK}})
        self.assertEqual(new["unifi"]["api_key"], "real-key")
        self.assertEqual(new["dns"]["password"], "pw")

    def test_other_saved_secrets_follow_the_same_rule(self):
        cur = settings(dns={"url": "http://192.168.1.2", "password": "pw"},
                       ai={"provider": "openai", "base_url": "http://192.168.1.3:1234/v1", "api_key": "sk"})
        cur["channels"]["email"].update(host="smtp.example.com", password="mail-pw")
        cur["channels"]["ntfy"].update(url="https://ntfy.example.com/t", token="tok")
        new = alerts.apply_update(cur, {
            "dns": {"url": "http://203.0.113.9", "password": alerts.MASK},
            "ai": {"base_url": "http://203.0.113.9/v1", "api_key": alerts.MASK},
            "channels": {"email": {"host": "203.0.113.9", "password": alerts.MASK},
                         "ntfy": {"url": "https://203.0.113.9/t", "token": alerts.MASK}}})
        self.assertEqual(new["dns"]["password"], "")
        self.assertEqual(new["ai"]["api_key"], "")
        self.assertEqual(new["channels"]["email"]["password"], "")
        self.assertEqual(new["channels"]["ntfy"]["token"], "")

    def test_the_stored_settings_are_not_changed_in_place(self):
        cur = settings(unifi={"host": "192.168.1.1", "api_key": "real-key"})
        before = copy.deepcopy(cur)
        alerts.apply_update(cur, {"unifi": {"host": "203.0.113.9"}})
        self.assertEqual(cur, before)


class AlertAddresses(unittest.TestCase):
    def test_alert_urls_must_be_web_addresses(self):
        cur = settings()
        new = alerts.apply_update(cur, {"channels": {"webhook": {"url": "file:///etc/passwd"},
                                                     "ntfy": {"url": "https://ntfy.sh/topic"}}})
        self.assertEqual(new["channels"]["webhook"]["url"], "")
        self.assertEqual(new["channels"]["ntfy"]["url"], "https://ntfy.sh/topic")


class QuietCap(unittest.TestCase):
    def test_quiet_mode_can_be_capped_lower(self):
        self.assertEqual(alerts.quiet_until({"minutes": 10 ** 6}, NOW, 1440), NOW + 86400)
        self.assertEqual(alerts.quiet_until({"minutes": 10 ** 6}, NOW), NOW + 7 * 86400)


class UpnpAddress(unittest.TestCase):
    def test_only_the_announcing_device_is_fetched(self):
        ok = discovery.upnp_url_ok
        self.assertTrue(ok("http://192.168.1.5:49152/desc.xml", "192.168.1.5"))
        self.assertTrue(ok("https://192.168.1.5/desc.xml", "192.168.1.5"))
        self.assertFalse(ok("http://192.168.1.5:80@127.0.0.1:9000/desc.xml", "192.168.1.5"))
        self.assertFalse(ok("http://192.168.1.5@evil.example/desc.xml", "192.168.1.5"))
        self.assertFalse(ok("http://192.168.1.6/desc.xml", "192.168.1.5"))
        self.assertFalse(ok("ftp://192.168.1.5/desc.xml", "192.168.1.5"))
        self.assertFalse(ok("http://192.168.1.5:notaport/", "192.168.1.5"))


class SignOut(unittest.TestCase):
    def test_signing_out_everywhere_ends_existing_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            a = auth.Auth(path)
            a.sign_out_everywhere()                     # no login set: nothing to do, nothing written
            self.assertFalse(path.exists())
            a.set_password("admin", "long-password")
            cookie = a.make_session("admin")
            self.assertEqual(a.verify(cookie), "admin")
            a.sign_out_everywhere()
            self.assertIsNone(a.verify(cookie))
            self.assertTrue(a.check("admin", "long-password"))      # the login itself is unchanged
            self.assertIsNone(auth.Auth(path).verify(cookie))       # and it survives a restart
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
