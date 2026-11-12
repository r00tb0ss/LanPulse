import sys
import fcntl
import tarfile
import tempfile
import sqlite3
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import lanpulse_backup as backup

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.destination = self.root / "backups"
        (self.data / "settings.json").write_text('{"port":8080}\n')
        with sqlite3.connect(self.data / "history.db") as db:
            db.execute("CREATE TABLE devices (id TEXT PRIMARY KEY)")
            db.execute("INSERT INTO devices VALUES ('device-1')")

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trip_preserves_previous_data(self):
        archive = backup.create_backup(self.data, self.destination)
        (self.data / "settings.json").write_text('{"port":9999}\n')
        with patch.object(backup, "service_active", return_value=False):
            previous = backup.restore_backup(archive, self.data)
        self.assertIn("8080", (self.data / "settings.json").read_text())
        self.assertIn("9999", (previous / "settings.json").read_text())
        with sqlite3.connect(self.data / "history.db") as db:
            self.assertEqual(db.execute("SELECT id FROM devices").fetchone()[0], "device-1")

    def test_restore_preserves_restricted_directory_permissions(self):
        private = self.data / "private"
        private.mkdir()
        (private / "secret.txt").write_text("sensitive")
        private.chmod(0o700)
        archive = backup.create_backup(self.data, self.destination)
        private.chmod(0o755)
        with patch.object(backup, "service_active", return_value=False):
            backup.restore_backup(archive, self.data)
        self.assertEqual((self.data / "private").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.data / "private" / "secret.txt").read_text(), "sensitive")

    def test_refuses_restore_while_service_is_active(self):
        archive = backup.create_backup(self.data, self.destination)
        with patch.object(backup, "service_active", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "Stop it first"):
                backup.restore_backup(archive, self.data)
        self.assertIn("8080", (self.data / "settings.json").read_text())

    def test_rejects_tampered_backup(self):
        archive = backup.create_backup(self.data, self.destination)
        with tempfile.TemporaryDirectory() as temp:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(temp)
            payload = Path(temp) / "lanpulse-data" / "settings.json"
            payload.write_text('{"tampered":true}\n')
            corrupt = self.destination / "corrupt.tar.gz"
            with tarfile.open(corrupt, "w:gz") as tar:
                tar.add(Path(temp) / "lanpulse-data", arcname="lanpulse-data")
        with patch.object(backup, "service_active", return_value=False):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                backup.restore_backup(corrupt, self.data)
        self.assertIn("8080", (self.data / "settings.json").read_text())

    def test_backup_skips_openvas_runtime_pid_and_socket(self):
        runtime_dir = self.data / "openvas" / "gvmd"
        runtime_dir.mkdir(parents=True)
        pid_file = runtime_dir / "gvmd.pid"
        pid_file.write_text("1234\\n")
        pid_file.chmod(0o600)
        socket_file = runtime_dir / "gvmd.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as runtime_socket:
            runtime_socket.bind(str(socket_file))
        persistent = runtime_dir / "config.txt"
        persistent.write_text("persistent scanner configuration")

        archive = backup.create_backup(self.data, self.destination)
        with tarfile.open(archive, "r:gz") as tar:
            names = set(tar.getnames())

        self.assertNotIn("lanpulse-data/openvas/gvmd/gvmd.pid", names)
        self.assertNotIn("lanpulse-data/openvas/gvmd/gvmd.sock", names)
        self.assertIn("lanpulse-data/openvas/gvmd/config.txt", names)

    def test_refuses_a_second_backup_while_one_is_running(self):
        archive_dir = self.destination
        archive_dir.mkdir(mode=0o700)
        lock_fd = __import__("os").open(archive_dir / ".lanpulse-backup.lock",
                                        __import__("os").O_CREAT | __import__("os").O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "already in progress"):
                backup.create_backup(self.data, archive_dir)
        finally:
            __import__("os").close(lock_fd)

    def test_backup_must_be_outside_data(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            backup.create_backup(self.data, self.data / "backups")

if __name__ == "__main__":
    unittest.main()
