#!/usr/bin/env python3
"""Manual, verified backup and restore for LanPulse's data directory."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote

DEFAULT_DATA_DIR = Path("/opt/lanpulse/data")
DEFAULT_BACKUP_DIR = Path("/var/backups/lanpulse")
FORMAT_VERSION = 1

def stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sqlite_snapshot(source, target):
    uri = "file:" + quote(str(source.resolve())) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=30) as src:
        with sqlite3.connect(str(target)) as dst:
            src.backup(dst, pages=256, sleep=0.05)

def copy_tree(data_dir, snapshot):
    records = []
    for source in sorted(data_dir.rglob("*")):
        rel = source.relative_to(data_dir)
        target = snapshot / rel
        info = source.lstat()
        if source.is_symlink():
            raise ValueError(f"Refusing symbolic link: {rel}")
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, info.st_mode & 0o777)
            continue
        if not source.is_file():
            raise ValueError(f"Refusing non-regular file: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.suffix.lower() == ".db":
            sqlite_snapshot(source, target)
        else:
            shutil.copyfile(source, target)
        os.chmod(target, info.st_mode & 0o777)
        records.append({"path": rel.as_posix(), "size": target.stat().st_size,
                        "sha256": sha256(target), "mode": info.st_mode & 0o777})
    return records

def create_backup(data_dir, backup_dir):
    data_dir = Path(data_dir).resolve()
    backup_dir = Path(backup_dir).resolve()
    if not data_dir.is_dir():
        raise ValueError(f"Data directory does not exist: {data_dir}")
    if backup_dir == data_dir or data_dir in backup_dir.parents:
        raise ValueError("Backup directory must be outside the data directory")
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    created = stamp()
    archive = backup_dir / f"lanpulse-{created}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="lanpulse-backup-") as temp:
        root = Path(temp) / "lanpulse-data"
        root.mkdir(mode=0o700)
        records = copy_tree(data_dir, root)
        manifest = {"format_version": FORMAT_VERSION, "created_utc": created,
                    "source_data_dir": str(data_dir), "files": records}
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(root / "manifest.json", 0o600)
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(root, arcname="lanpulse-data", recursive=True)
    os.chmod(archive, 0o600)
    return archive

def service_active():
    try:
        result = subprocess.run(["systemctl", "is-active", "--quiet", "lanpulse"],
                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise RuntimeError(f"Cannot verify LanPulse service state: {exc}") from exc
    return result.returncode == 0

def safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or path.parts[0] != "lanpulse-data" or ".." in path.parts:
        raise ValueError(f"Unsafe archive path: {name}")
    return path

def restore_backup(archive, data_dir):
    archive, data_dir = Path(archive).resolve(), Path(data_dir).resolve()
    if not archive.is_file():
        raise ValueError(f"Backup not found: {archive}")
    if service_active():
        raise RuntimeError("LanPulse is running. Stop it first: sudo systemctl stop lanpulse")
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lanpulse-restore-", dir=data_dir.parent) as temp:
        stage = Path(temp) / "lanpulse-data"
        stage.mkdir(mode=0o700)
        with tarfile.open(archive, "r:gz") as tar:
            seen = set()
            for member in tar.getmembers():
                rel = safe_member(member.name)
                if member.name in seen:
                    raise ValueError(f"Duplicate archive path: {member.name}")
                seen.add(member.name)
                if not (member.isdir() or member.isfile()) or member.issym() or member.islnk():
                    raise ValueError(f"Unsupported archive entry: {member.name}")
                if member.isfile():
                    dest = stage.joinpath(*rel.parts[1:])
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src = tar.extractfile(member)
                    if src is None:
                        raise ValueError(f"Cannot read archive entry: {member.name}")
                    with src, dest.open("xb") as out:
                        shutil.copyfileobj(src, out)
                    os.chmod(dest, member.mode & 0o777)
                elif rel.parts[1:]:
                    stage.joinpath(*rel.parts[1:]).mkdir(parents=True, exist_ok=True)
        manifest_path = stage / "manifest.json"
        if not manifest_path.is_file():
            raise ValueError("Backup has no manifest")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        records = manifest.get("files") if manifest.get("format_version") == FORMAT_VERSION else None
        if not isinstance(records, list):
            raise ValueError("Unsupported or invalid backup format")
        expected = {item["path"]: item for item in records}
        actual = {p.relative_to(stage).as_posix() for p in stage.rglob("*")
                  if p.is_file() and p != manifest_path}
        if actual != set(expected):
            raise ValueError("Archive contents do not match manifest")
        for relative, item in expected.items():
            rel = PurePosixPath(relative)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"Unsafe manifest path: {relative}")
            path = stage.joinpath(*rel.parts)
            if path.stat().st_size != item.get("size") or sha256(path) != item.get("sha256"):
                raise ValueError(f"Backup verification failed: {relative}")
            os.chmod(path, int(item.get("mode", 0o600)) & 0o777)
        previous = data_dir.with_name(data_dir.name + ".pre-restore-" + stamp())
        had_previous = data_dir.exists()
        if had_previous:
            if not data_dir.is_dir() or data_dir.is_symlink():
                raise ValueError(f"Refusing to replace non-directory: {data_dir}")
            data_dir.rename(previous)
        try:
            stage.rename(data_dir)
        except Exception:
            if had_previous and previous.exists() and not data_dir.exists():
                previous.rename(data_dir)
            raise
        return previous if had_previous else data_dir

def main(argv=None):
    parser = argparse.ArgumentParser(description="Safely back up or restore LanPulse data.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup", help="Create a verified backup")
    backup.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    restore = sub.add_parser("restore", help="Restore a verified backup; service must be stopped")
    restore.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            result = create_backup(args.data_dir, args.backup_dir)
            print(f"Backup created: {result}")
            print("Contains sensitive settings and credentials; keep it private.")
        else:
            result = restore_backup(args.archive, args.data_dir)
            print("Restore completed.")
            if result != args.data_dir.resolve():
                print(f"Previous data preserved at: {result}")
            print("Review the installation, then start LanPulse: sudo systemctl start lanpulse")
        return 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(f"LanPulse backup/restore failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
