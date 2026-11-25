import json
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import analyst
import honeyanalysis
import honeypot
import openvas
import threats


class OpenVASPublicScanLimits(unittest.TestCase):
    def test_public_scan_target_cooldown_blocks_repeat(self):
        obj = openvas.OpenVAS.__new__(openvas.OpenVAS)
        obj.scans = {"8.8.8.8": {"public": True, "started": 1_800_000_000, "status": "Done"}}
        with patch("openvas.time.time", return_value=1_800_000_030):
            error = obj.start_scan("8.8.8.8", authorized_public=True)
        self.assertIn("public target was scanned recently", error)

    def test_public_scan_global_cooldown_blocks_another_target(self):
        obj = openvas.OpenVAS.__new__(openvas.OpenVAS)
        obj.scans = {"8.8.8.8": {"public": True, "started": 1_800_000_000, "status": "Done"}}
        with patch("openvas.time.time", return_value=1_800_000_030):
            error = obj.start_scan("1.1.1.1", authorized_public=True)
        self.assertIn("public OpenVAS scan was started recently", error)

    def test_openvas_history_pruning_keeps_newest_terminal_and_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            state = Path(tmp) / "openvas"
            state.mkdir()
            scans = {f"192.0.2.{i}": {"status": "Done", "started": 1_800_000_000 - i}
                     for i in range(1, 126)}
            scans["active"] = {"status": "Running", "started": 1_800_000_000}
            (state / "scans.json").write_text(json.dumps(scans))
            nm = types.SimpleNamespace(data_dir=tmp)
            obj = openvas.OpenVAS(nm)
            self.assertEqual(len(obj.scans), obj.MAX_HISTORY + 1)
            self.assertIn("active", obj.scans)
            self.assertIn("192.0.2.1", obj.scans)
            self.assertNotIn("192.0.2.125", obj.scans)


class EvidenceSizeQueries(unittest.TestCase):
    def test_threat_event_size_uses_aggregate_query(self):
        obj = threats.ThreatMonitor.__new__(threats.ThreatMonitor)
        obj.lock = threading.Lock()
        obj.db = sqlite3.connect(":memory:")
        obj.db.execute("CREATE TABLE attacks (t REAL, src TEXT, dport INTEGER, proto TEXT, action TEXT, lan TEXT, service TEXT, sensor TEXT, detail TEXT)")
        obj.db.execute("INSERT INTO attacks VALUES (1,'198.51.100.1',22,'tcp','blocked','','ssh','','raw-detail')")
        result = obj.evidence_size()
        self.assertEqual(result["records"], 1)
        self.assertGreater(result["estimated_bytes"], len("raw-detail"))

    def test_builtin_honeypot_size_uses_aggregate_query(self):
        obj = honeypot.Honeypot.__new__(honeypot.Honeypot)
        obj.lock = threading.Lock()
        obj.db = sqlite3.connect(":memory:")
        obj.db.execute("CREATE TABLE hits (t REAL, ip TEXT, service TEXT, port INTEGER, internal INTEGER, creds TEXT, data TEXT, sensor TEXT)")
        obj.db.execute("INSERT INTO hits VALUES (1,'198.51.100.2','ssh',22,0,'root / attempted','raw-data','sensor-1')")
        result = obj.evidence_size()
        self.assertEqual(result["records"], 1)
        self.assertGreater(result["estimated_bytes"], len("attempted") + len("raw-data"))

    def test_cowrie_size_uses_aggregate_queries(self):
        obj = honeyanalysis.HoneyAnalysis.__new__(honeyanalysis.HoneyAnalysis)
        obj.lock = threading.Lock()
        obj.db = sqlite3.connect(":memory:")
        obj.db.execute("CREATE TABLE sessions (id TEXT, logins TEXT, commands TEXT, files TEXT, tags TEXT, client TEXT)")
        obj.db.execute("CREATE TABLE samples (analysis TEXT, ips TEXT, urls TEXT, names TEXT)")
        obj.db.execute("INSERT INTO sessions VALUES ('s1','[{}]','[\"uname\"]','[]','[]','ssh-client')")
        obj.db.execute("INSERT INTO samples VALUES ('{\"yara\":{}}','[]','[]','[]')")
        result = obj.evidence_size()
        self.assertEqual(result["sessions"], 1)
        self.assertEqual(result["samples"], 1)
        self.assertGreater(result["estimated_bytes"], 0)

    def test_oversized_combined_pack_fails_before_evidence_rows_are_loaded(self):
        nm = types.SimpleNamespace(
            threats=types.SimpleNamespace(evidence_size=lambda: {"records": 10, "estimated_bytes": 700}),
            honeypot=types.SimpleNamespace(evidence_size=lambda: {"records": 10, "estimated_bytes": 200}),
            honeyan=types.SimpleNamespace(evidence_size=lambda: {"sessions": 10, "estimated_bytes": 200}),
        )
        with patch.object(analyst, "MAX_AI_RAW_EVIDENCE_BYTES", 1000):
            with self.assertRaisesRegex(analyst.EvidenceBudgetExceeded, "No records were omitted or sent"):
                analyst._preflight_raw_evidence(nm, ["threats", "honeypot"])

    def test_small_complete_pack_passes_preflight(self):
        nm = types.SimpleNamespace(
            threats=types.SimpleNamespace(evidence_size=lambda: {"records": 1, "estimated_bytes": 100}),
            honeypot=types.SimpleNamespace(evidence_size=lambda: {"records": 1, "estimated_bytes": 100}),
            honeyan=types.SimpleNamespace(evidence_size=lambda: {"sessions": 1, "estimated_bytes": 100}),
        )
        with patch.object(analyst, "MAX_AI_RAW_EVIDENCE_BYTES", 1000):
            analyst._preflight_raw_evidence(nm, ["threats", "honeypot"])


if __name__ == "__main__":
    unittest.main()
