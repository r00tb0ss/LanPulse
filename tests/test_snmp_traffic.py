# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for read-only SNMP interface traffic calculations."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import snmpdisc


class SnmpTrafficRates(unittest.TestCase):
    def test_rates_use_only_up_physical_ethernet_interfaces(self):
        previous = {
            "1": {"in": 1000, "out": 2000},
            "2": {"in": 500, "out": 500},
            "3": {"in": 100, "out": 100},
            "4": {"in": 100, "out": 100},
        }
        current = {
            "1": {"name": "vmnic0", "type": 6, "oper": 1, "speed": 1000, "in": 5000, "out": 8000},
            "2": {"name": "vmbr0", "type": 6, "oper": 1, "speed": 1000, "in": 9000, "out": 9000},
            "3": {"name": "lo", "type": 24, "oper": 1, "speed": 0, "in": 900, "out": 900},
            "4": {"name": "eno2", "type": 6, "oper": 2, "speed": 1000, "in": 900, "out": 900},
        }
        rates = snmpdisc._interface_rates(current, previous, 2.0)
        self.assertEqual(rates["rx_bps"], 2000)
        self.assertEqual(rates["tx_bps"], 3000)
        self.assertEqual(rates["rate_bps"], 5000)
        self.assertEqual([x["name"] for x in rates["interfaces"]], ["vmnic0"])

    def test_first_sample_and_counter_reset_do_not_create_rates(self):
        current = {"1": {"name": "eno1", "type": 6, "oper": 1, "in": 50, "out": 80}}
        self.assertEqual(snmpdisc._interface_rates(current, {}, 5), {})
        previous = {"1": {"in": 100, "out": 100}}
        self.assertEqual(snmpdisc._interface_rates(current, previous, 5), {})

    def test_stale_or_invalid_elapsed_window_is_rejected(self):
        current = {"1": {"name": "eno1", "type": 6, "oper": 1, "in": 200, "out": 200}}
        previous = {"1": {"in": 100, "out": 100}}
        self.assertEqual(snmpdisc._interface_rates(current, previous, 0), {})
        self.assertEqual(snmpdisc._interface_rates(current, previous, 301), {})
