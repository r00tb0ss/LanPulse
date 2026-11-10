## Manual data backup and restore

LanPulse's updater rollback protects application files; it is not a backup of the live data directory. The optional helper at `tools/lanpulse_backup.py` creates a separate, verified archive of `/opt/lanpulse/data` without changing the running installation.

Create a backup from **Settings → Backup → Create backup now**, or from the command line:

```bash
sudo python3 tools/lanpulse_backup.py backup
```

By default, archives are written to `/var/backups/lanpulse` with directory mode `0700` and archive mode `0600`. The installer creates this directory and explicitly grants the hardened systemd service write access to it. To choose another destination:

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

SQLite databases are copied with SQLite's online backup API so committed WAL data is included consistently. Symbolic links and unsupported file types are rejected. Backups contain credentials, API keys, certificates and network history: keep them private, encrypted and preferably off-device. The Settings → Backup tab can start a backup and list/download completed archives. Restore remains a maintenance operation performed from the command line; no automatic schedule is configured.


### Choosing another backup location

The backup directory can be changed with the `LANPULSE_BACKUP_DIR` environment variable. Use an absolute path. The Settings → Backup page displays the active location.

For a direct systemd installation, create a service drop-in and grant the service write access to the new directory as well:

```bash
sudo mkdir -p /srv/lanpulse-backups
sudo chmod 700 /srv/lanpulse-backups
sudo systemctl edit lanpulse
```

Add:

```ini
[Service]
Environment=LANPULSE_BACKUP_DIR=/srv/lanpulse-backups
ReadWritePaths=/srv/lanpulse-backups
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart lanpulse`.

For a container, mount a persistent writable host directory and set the same variable inside the container. For example, with Docker:

```bash
docker run ... \
  -e LANPULSE_BACKUP_DIR=/backups \
  -v /path/on/host/lanpulse-backups:/backups \
  ...
```

The mounted directory must be writable by the LanPulse process. Keep it private: backup archives contain credentials, API keys, certificates and network history. This environment-variable support does not assume or require a particular Docker image or compose layout.
