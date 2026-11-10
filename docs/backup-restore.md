## Manual data backup and restore

LanPulse's updater rollback protects application files; it is not a backup of the live data directory. The optional helper at `tools/lanpulse_backup.py` creates a separate, verified archive of `/opt/lanpulse/data` without changing the running installation.

Create a backup:

```bash
sudo python3 tools/lanpulse_backup.py backup
```

By default, archives are written to `/var/backups/lanpulse` with directory mode `0700` and archive mode `0600`. To choose another destination:

```bash
sudo python3 tools/lanpulse_backup.py backup --backup-dir /path/to/private/backups
```

Restore during a maintenance window:

```bash
sudo systemctl stop lanpulse
sudo python3 tools/lanpulse_backup.py restore /var/backups/lanpulse/lanpulse-TIMESTAMP.tar.gz
sudo systemctl start lanpulse
```

Restore refuses to run while the LanPulse systemd service is active. It verifies archive contents and SHA-256 hashes before replacing anything. Existing data is renamed to a timestamped `.pre-restore-*` directory, not deleted. If the final directory swap fails, the helper attempts to put the previous data directory back.

SQLite databases are copied with SQLite's online backup API so committed WAL data is included consistently. Symbolic links and unsupported file types are rejected. Backups contain credentials, API keys, certificates and network history: keep them private, encrypted and preferably off-device. This is a manual utility; it adds no dashboard page, schedule, or installer/updater changes.
