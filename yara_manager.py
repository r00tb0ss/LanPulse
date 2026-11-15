# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Fetch, verify and atomically activate the curated YARA Forge Core rule package.

This helper runs as root from a systemd oneshot service. It downloads only the
named release asset, verifies GitHub's published SHA-256 digest, rejects unsafe
or oversized ZIP contents, compiles the complete staged rule set with includes
disabled, then atomically swaps only data/yara-rules/managed. Owner rules in
data/yara-rules/ and the last known-good managed package are never overwritten
by a failed update.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

LOG = logging.getLogger("lanpulse.yara_manager")
API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
ASSET = "yara-forge-rules-core.zip"
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_EXPANDED = 50 * 1024 * 1024
MAX_RULE_FILES = 6000
MAX_RULE_FILE = 2 * 1024 * 1024
USER_AGENT = "LanPulse-YARA-Manager"


class UpdateError(Exception):
    pass


def _request(url: str, accept: str = "application/octet-stream"):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    return urllib.request.urlopen(req, timeout=45)


def _read_status(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_status(path: Path, update: dict) -> None:
    old = _read_status(path)
    old.update(update)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(old, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _release() -> tuple[dict, dict]:
    try:
        with _request(API, "application/vnd.github+json") as response:
            release = json.loads(response.read(2 * 1024 * 1024 + 1))
    except Exception as exc:
        raise UpdateError(f"could not read YARA Forge release metadata: {exc}") from exc
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        raise UpdateError("YARA Forge did not return a stable release")
    tag = str(release.get("tag_name") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", tag):
        raise UpdateError("YARA Forge release tag is invalid")
    asset = next((x for x in release.get("assets", []) if x.get("name") == ASSET), None)
    if not asset:
        raise UpdateError(f"YARA Forge release is missing {ASSET}")
    digest = str(asset.get("digest") or "")
    match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", digest)
    if not match:
        raise UpdateError("GitHub did not publish a SHA-256 digest for the rule package")
    size = int(asset.get("size") or 0)
    if size <= 0 or size > MAX_ARCHIVE:
        raise UpdateError("YARA Forge rule archive exceeds the allowed download size")
    url = str(asset.get("browser_download_url") or "")
    if not url.startswith("https://github.com/YARAHQ/yara-forge/releases/download/"):
        raise UpdateError("YARA Forge asset URL is not an expected GitHub release URL")
    body = str(release.get("body") or "")
    rules = re.search(r"\|\s*core\s*\|\s*([\d,]+)\s*\|", body, re.I)
    info = {"package": "YARA Forge Core", "version": tag,
            "rule_count": int(rules.group(1).replace(",", "")) if rules else None}
    return {**asset, "digest": match.group(1).lower(), "url": url}, info


def _download(asset: dict, target: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with _request(asset["url"]) as response, target.open("wb") as out:
            while True:
                chunk = response.read(128 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    raise UpdateError("download exceeded the archive size limit")
                digest.update(chunk)
                out.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    actual = digest.hexdigest()
    if total != int(asset["size"]) or actual != asset["digest"]:
        target.unlink(missing_ok=True)
        raise UpdateError("YARA Forge archive failed its published size or SHA-256 check")
    return actual


def _safe_extract_rules(archive: Path, stage: Path) -> tuple[list[Path], int]:
    files: list[Path] = []
    total = 0
    seen = set()
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > 20000:
            raise UpdateError("YARA Forge archive contains too many entries")
        for info in infos:
            raw = info.filename.replace("\\", "/")
            p = PurePosixPath(raw)
            if p.is_absolute() or not p.parts or any(part in ("", ".", "..") for part in p.parts):
                if info.is_dir() and not p.is_absolute():
                    continue
                raise UpdateError("YARA Forge archive contains an unsafe path")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise UpdateError("YARA Forge archive contains a symbolic link")
            if info.is_dir() or p.suffix.lower() not in (".yar", ".yara"):
                continue
            if info.file_size <= 0 or info.file_size > MAX_RULE_FILE:
                raise UpdateError(f"rule file exceeds the per-file size limit: {p.name[:100]}")
            total += info.file_size
            if total > MAX_EXPANDED:
                raise UpdateError("YARA Forge rules exceed the total expanded size limit")
            if len(files) >= MAX_RULE_FILES:
                raise UpdateError("YARA Forge contains more rule files than LanPulse allows")
            parts = list(p.parts)
            if len(parts) >= 2 and parts[0] == "packages" and parts[1] == "core":
                parts = parts[2:]
            elif parts[0] == "core":
                parts = parts[1:]
            if not parts:
                raise UpdateError("rule file has no usable path")
            rel = PurePosixPath(*parts)
            key = str(rel).casefold()
            if key in seen:
                raise UpdateError("YARA Forge archive contains duplicate rule paths")
            seen.add(key)
            dest = stage.joinpath(*rel.parts)
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = zf.read(info)
            if len(data) != info.file_size:
                raise UpdateError("rule file size changed while extracting")
            dest.write_bytes(data)
            os.chmod(dest, 0o600)
            files.append(dest)
    if not files:
        raise UpdateError("YARA Forge archive contains no .yar or .yara files")
    return files, total


def _validate(files: list[Path]) -> None:
    try:
        import yara
    except Exception as exc:
        raise UpdateError(f"yara-python is unavailable: {exc}") from exc
    filepaths = {f"rule_{i:05d}": str(path) for i, path in enumerate(files)}
    try:
        compiled = yara.compile(filepaths=filepaths, includes=False)
        compiled.match(data=b"", timeout=10)
    except Exception as exc:
        raise UpdateError(f"YARA Forge package failed compilation/validation: {exc}") from exc


def update(data_dir: Path) -> dict:
    data_dir = data_dir.resolve()
    root = data_dir / "yara-rules"
    managed = root / "managed"
    status_path = data_dir / "yara-status.json"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = _read_status(status_path)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    work = Path(tempfile.mkdtemp(prefix=".yara-update-", dir=str(root)))
    archive = work / "rules.zip"
    stage = work / "managed"
    stage.mkdir(mode=0o700)
    try:
        asset, info = _release()
        if status.get("version") == info["version"] and status.get("sha256") == asset["digest"] and managed.is_dir():
            status.update({"checked_at": now, "last_error": ""})
            _write_status(status_path, status)
            return status
        sha = _download(asset, archive)
        files, total = _safe_extract_rules(archive, stage)
        _validate(files)
        backup = root / ".managed-previous"
        if backup.exists():
            shutil.rmtree(backup)
        if managed.exists():
            os.replace(managed, backup)
        try:
            os.replace(stage, managed)
        except Exception:
            if backup.exists() and not managed.exists():
                os.replace(backup, managed)
            raise
        if backup.exists():
            shutil.rmtree(backup)
        status = {**info, "status": "active", "rule_files": len(files), "bytes": total,
                  "sha256": sha, "updated_at": now, "checked_at": now, "last_error": ""}
        _write_status(status_path, status)
        LOG.info("Installed %s %s: %s rules in %s files", info["package"], info["version"],
                 info["rule_count"] or "unknown", len(files))
        return status
    except Exception as exc:
        previous = _read_status(status_path)
        previous.update({"checked_at": now, "last_error": str(exc)[:500]})
        if not previous.get("status"):
            previous["status"] = "unavailable"
        _write_status(status_path, previous)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Update LanPulse's managed YARA Forge Core rules")
    parser.add_argument("--data-dir", default="/opt/lanpulse/data")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        result = update(Path(args.data_dir))
        print(f"{result.get('package', 'YARA Forge Core')} {result.get('version', '')}: "
              f"{result.get('rule_count') or result.get('rule_files', 0)} rules; "
              f"{result.get('rule_files', 0)} files")
        return 0
    except Exception as exc:
        LOG.error("YARA rule update failed: %s", exc)
        print(f"YARA rule update failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
