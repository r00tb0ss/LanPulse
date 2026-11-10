# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Safe listing and filename validation for Settings > Backup."""
from pathlib import Path
import re
import time

BACKUP_DIR = Path("/var/backups/lanpulse")
BACKUP_NAME_RE = re.compile(r"lanpulse-\\d{8}T\\d{12}Z\\.tar\\.gz\\Z")


def list_backup_archives(directory: Path = BACKUP_DIR) -> list[dict]:
    """List only regular LanPulse backup archives; never follow symlinks."""
    try:
        entries = list(Path(directory).iterdir())
    except FileNotFoundError:
        return []
    backups = []
    for path in entries:
        if not BACKUP_NAME_RE.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        backups.append({"name": path.name, "size": stat.st_size,
                        "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))})
    return sorted(backups, key=lambda item: item["name"], reverse=True)


def backup_archive_path(name: str, directory: Path = BACKUP_DIR) -> Path:
    """Resolve a backup download by its generated filename only."""
    if not BACKUP_NAME_RE.fullmatch(str(name)):
        raise ValueError("Invalid backup filename")
    root = Path(directory).resolve()
    path = root / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
        raise ValueError("Backup not found")
    return path
