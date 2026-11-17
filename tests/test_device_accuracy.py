# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Labelled real-world devices: classify() must name each one correctly.

Loads classify() straight from app.py so the test runs without the web stack installed.
"""
import ast
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import discovery  # noqa: E402


def _load():
    tree = ast.parse(open(os.path.join(ROOT, "app.py"), encoding="utf-8").read())
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"is_random_mac", "lookup_vendor", "classify"}]
    ns = {"re": re, "classify_from_hints": discovery.classify_from_hints}
    exec(compile(ast.Module(body=body, type_ignores=[]), "app", "exec"), ns)
    return ns["classify"]


classify = _load()
P = lambda *ps: [{"port": p} for p in ps]  # noqa: E731
CASES = [
("Echo hostname", dict(vendor="Amazon Technologies",hostname="echo-dot-4",ports=[]),"speaker"),
("Amazon fire tablet", dict(vendor="Amazon Technologies",hostname="Fire-HD-10",ports=[]),"tablet"),
("Ring doorbell", dict(vendor="Ring LLC",hostname="Front Door Ring",ports=[]),"iot"),
("Windows PC named Ringo", dict(vendor="Dell",hostname="DESKTOP-RINGO1",ports=P(135,445)),"desktop"),
("Deco mesh", dict(vendor="TP-Link",hostname="Deco-M5",ports=P(80)),"ap"),
("Decorator laptop", dict(vendor="Intel",hostname="decorator-laptop",ports=[]),"laptop"),
("Canon printer by vendor", dict(vendor="Canon Inc.",hostname="",ports=[]),"printer"),
("Canon camera", dict(vendor="Canon Inc.",hostname="EOS-R6",ports=[]),"camera"),
("Brother printer", dict(vendor="Brother Industries",hostname="BRW1234",ports=P(9100,80)),"printer"),
("Hostname Brotherton PC", dict(vendor="Dell",hostname="brotherton-pc",ports=P(445,135)),"desktop"),
("Epson printer", dict(vendor="Seiko Epson",hostname="EPSON123",ports=P(631)),"printer"),
("Samsung Galaxy", dict(vendor="Samsung",hostname="Galaxy-S23",ports=[]),"phone"),
("Samsung TV", dict(vendor="Samsung",hostname="Samsung-TV",ports=P(8001)),"tv"),
("Pixel", dict(vendor="Google",hostname="Pixel-7",ports=[]),"phone"),
("Nest thermostat", dict(vendor="Nest Labs",hostname="Nest-Thermostat",ports=[]),"iot"),
("Nest Audio", dict(vendor="Google",hostname="Nest-Audio",ports=[]),"speaker"),
("Raspberry Pi", dict(vendor="Raspberry Pi Trading",hostname="raspberrypi",ports=P(22)),"raspberrypi"),
("Pi-hole on Pi", dict(vendor="Raspberry Pi Trading",hostname="pihole",ports=P(22,53,80)),"raspberrypi"),
("MacBook", dict(vendor="Apple",hostname="Johns-MacBook-Pro",ports=P(22)),"laptop"),
("Mac mini no ports", dict(vendor="Apple",hostname="Mac-mini",ports=[]),"desktop"),
("iPhone portless", dict(vendor="Apple",hostname="",ports=[]),"phone"),
("iPad", dict(vendor="Apple",hostname="Sarahs-iPad",ports=[]),"tablet"),
("Apple TV", dict(vendor="Apple",hostname="Living-Room-Apple-TV",ports=P(7000)),"tv"),
("Windows server w/ domain", dict(vendor="Dell",hostname="dc01",os="Microsoft Windows Server 2019",ports=P(53,135,389,445,3389)),"server"),
("Linux server ssh", dict(vendor="Super Micro",hostname="node1",os="Linux 5.X",ports=P(22,80)),"server"),
("ESXi host", dict(vendor="HP",hostname="esxi01",os="VMware ESXi",ports=P(443,902)),"server"),
("Proxmox VM", dict(vendor="QEMU",hostname="vm100",ports=P(22)),"server"),
("Hikvision cam", dict(vendor="Hikvision",hostname="",ports=P(80,554)),"camera"),
("Windows w/ 554 open", dict(vendor="Dell",hostname="PC1",os="Windows 10",ports=P(135,445,554)),"desktop"),
("Plex server on Linux", dict(vendor="Intel",hostname="plex",os="Linux 5.X",ports=P(22,32400)),"server"),
("PS5", dict(vendor="Sony Interactive Entertainment",hostname="PS5-123",ports=[]),"game"),
("Xbox", dict(vendor="Microsoft",hostname="Xbox",ports=[]),"game"),
("Roku", dict(vendor="Roku",hostname="Roku-Ultra",ports=P(8060)),"tv"),
("Chromecast", dict(vendor="Google",hostname="Chromecast",ports=P(8008,8009)),"tv"),
("Sonos", dict(vendor="Sonos",hostname="Sonos-Play1",ports=P(1400)),"speaker"),
("Philips Hue bridge", dict(vendor="Philips Lighting",hostname="Philips-hue",ports=P(80,443)),"iot"),
("ESP32 device", dict(vendor="Espressif",hostname="esp32-abc",ports=P(80)),"iot"),
("Shelly", dict(vendor="Shelly",hostname="shelly1pm",ports=P(80)),"iot"),
("UniFi AP", dict(vendor="Ubiquiti",hostname="U6-Pro",ports=P(22)),"ap"),
("UniFi switch", dict(vendor="Ubiquiti",hostname="USW-24-PoE",ports=P(22)),"switch"),
("Cisco switch", dict(vendor="Cisco",hostname="sw-core",ports=P(22,23)),"switch"),
("Netgear router non-gw", dict(vendor="Netgear",hostname="Netgear-GS108",ports=P(80)),"switch"),
("TP-Link plug", dict(vendor="TP-Link",hostname="HS103",ports=[]),"iot"),
("Dell laptop hostname", dict(vendor="Dell",hostname="LAPTOP-9ABC",ports=P(445)),"laptop"),
("Lenovo thinkpad", dict(vendor="Lenovo",hostname="thinkpad-x1",ports=[]),"laptop"),
("Dell desktop win", dict(vendor="Dell",hostname="DESKTOP-FED6KG4",os="Windows 10",ports=P(135,445)),"desktop"),
("Random MAC unknown", dict(vendor="",hostname="",ports=[],randomized_mac=True),"phone"),
("Random MAC with 445 open", dict(vendor="",hostname="DESKTOP-X1",ports=P(445,135),randomized_mac=True),"desktop"),
("Random MAC Linux ssh", dict(vendor="",hostname="ubuntu",os="Linux 5.X",ports=P(22),randomized_mac=True),"server"),
("Intel NIC Linux ssh/http", dict(vendor="Intel",hostname="docker1",os="Linux 5.X",ports=P(22,80,443)),"server"),
("Intel NIC no data", dict(vendor="Intel",hostname="",ports=[]),"unknown"),
("Nothing at all", dict(vendor="",hostname="",ports=[]),"unknown"),
("Realtek NIC Windows", dict(vendor="Realtek",hostname="",os="Windows 11",ports=P(135,445)),"desktop"),
("Home Assistant", dict(vendor="Raspberry Pi",hostname="homeassistant",ports=P(8123,22)),"server"),
("Ubiquiti NVR", dict(vendor="Ubiquiti",hostname="UNVR",ports=P(22,443,7442)),"nas"),
("Synology", dict(vendor="Synology",hostname="DS920",ports=P(5000,445)),"nas"),
("Printer HP by port", dict(vendor="HP",hostname="NPI123",ports=P(9100,631)),"printer"),
("HP laptop", dict(vendor="HP",hostname="HP-Envy",ports=P(445,135)),"desktop"),
("Smart TV LG", dict(vendor="LG Electronics",hostname="LGwebOSTV",ports=[]),"tv"),
("Hisense", dict(vendor="Hisense",hostname="",ports=[]),"tv"),
("Bose speaker", dict(vendor="Bose",hostname="Bose-SoundTouch",ports=[]),"speaker"),
("Xiaomi phone redmi", dict(vendor="Xiaomi",hostname="Redmi-Note-9",ports=[]),"phone"),
("Kindle", dict(vendor="Amazon",hostname="Kindle",ports=[]),"tablet"),
("Ecobee", dict(vendor="ecobee",hostname="ecobee",ports=[]),"iot"),
("Tuya", dict(vendor="Tuya Smart",hostname="",ports=[]),"iot"),
("Steam Deck", dict(vendor="Valve",hostname="steamdeck",ports=[]),"game"),
("Motorola phone", dict(vendor="Motorola",hostname="moto-g",ports=[]),"phone"),
("Mother's PC (moto in name)", dict(vendor="Dell",hostname="motorhead-pc",os="Windows 10",ports=P(135,445)),"desktop"),
("Apple w/ SSH & mac hostname", dict(vendor="Apple",hostname="studio",ports=P(22,5900)),"laptop"),
]

class DeviceAccuracy(unittest.TestCase):
    def test_labelled_devices(self):
        wrong = []
        for name, d, exp in CASES:
            d = dict(d)
            d.setdefault("os", ""); d.setdefault("friendly", ""); d.setdefault("model", "")
            got = classify(d)
            if got != exp:
                wrong.append(f"{name}: expected {exp}, got {got}")
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
