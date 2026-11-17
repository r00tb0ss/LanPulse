# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Dashboard checks: the default-login check and the security score must not flag ordinary devices."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import posture  # noqa: E402
import redteam  # noqa: E402


def P(*a):
    return [{"port": p, "service": s, "product": pr} for p, s, pr in a]


class DefaultLogins(unittest.TestCase):
    def flagged(self, **d):
        return bool(redteam.default_cred_services(d))

    def test_ordinary_services_are_not_flagged(self):
        self.assertFalse(self.flagged(vendor="Dell", os="Linux", ports=P((22, "ssh", "OpenSSH"), (2222, "sftp", ""))))
        self.assertFalse(self.flagged(vendor="Milo Devices", os="Linux 5.X", ports=P((80, "http", "nginx"))))
        self.assertFalse(self.flagged(vendor="", os="Pilot OS", ports=P((443, "https", ""))))
        self.assertFalse(self.flagged(vendor="Dell", os="Linux 5.X", ports=P((80, "http", "nginx"), (443, "https", "nginx"))))

    def test_known_default_login_services_are_flagged(self):
        for name, ports in {"ilo": P((443, "https", "HPE iLO")), "grafana": P((3000, "http", "Grafana")),
                            "vsftpd": P((21, "ftp", "vsftpd")), "telnet": P((23, "telnet", "")),
                            "idrac": P((443, "https", "Dell iDRAC"))}.items():
            self.assertTrue(self.flagged(vendor="", os="Linux", ports=ports), name)
        self.assertTrue(self.flagged(vendor="Hikvision", os="", ports=P((554, "rtsp", ""))))


class Score(unittest.TestCase):
    def nm(self, devices, results=None):
        return types.SimpleNamespace(
            vulns=types.SimpleNamespace(results=results or {}),
            flows=types.SimpleNamespace(summary=lambda h: {"compromised": []}),
            devices={d["id"]: d for d in devices}, label=lambda d: d["id"],
            auth=types.SimpleNamespace(enabled=True))

    def dev(self, i, ports, **kw):
        return {"id": i, "ip": "192.168.1.%d" % i, "online": True, "trusted": True, "ports": ports,
                "vendor": "Dell", "os": "Linux 5.X", **kw}

    def test_web_servers_do_not_cost_score(self):
        ds = [self.dev(i, P((80, "http", "nginx"), (443, "https", "nginx"))) for i in range(1, 9)]
        self.assertEqual(posture.compute(self.nm(ds))["score"], 100)

    def test_patchable_distro_matches_do_not_cost_score_but_real_ones_do(self):
        d = self.dev(1, P((22, "ssh", "OpenSSH")))
        distro = {1: [{"kev": True, "distro": True}]}
        real = {1: [{"kev": True, "distro": False}]}
        self.assertEqual(posture.compute(self.nm([d], distro))["score"], 100)
        self.assertEqual(posture.compute(self.nm([d], real))["score"], 100 - posture.WEIGHTS["kev"][0])

    def test_real_cleartext_still_costs_score(self):
        d = self.dev(1, P((23, "telnet", "")))
        self.assertLess(posture.compute(self.nm([d]))["score"], 100)


if __name__ == "__main__":
    unittest.main()
