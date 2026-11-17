# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Bounded, static YARA matching for captured honeypot files.

Managed YARA Forge rules live under yara-rules/managed and are compiled as a
single package so cross-file rule dependencies work. Owner-created rules remain
outside that folder and are compiled independently. Captured files are bytes;
they are never executed. Rule includes are disabled.
"""
from __future__ import annotations

import hashlib
import json
import logging
import pathlib

log = logging.getLogger("lanpulse.yaralook")

MAX_RULE_FILES = 6000
MAX_RULE_BYTES = 8 * 1024 * 1024
MAX_RULE_TOTAL = 50_000_000
SCAN_SECONDS = 10
MAX_MATCHES = 100

try:
    import yara
except Exception:
    yara = None


def _short(v, n: int = 200) -> str:
    return "".join(c for c in str(v) if c.isprintable())[:n]


class YaraRules:
    """Load and cache managed and custom rules, refreshing when their files change."""

    def __init__(self, folder: pathlib.Path):
        self.folder = pathlib.Path(folder)
        self._sig = None
        self._rules: list = []
        self._errors: list[str] = []
        self._managed_files = 0
        self._custom_files = 0
        self._loaded_files = 0

    def _files(self):
        managed, custom = [], []
        try:
            paths = sorted(self.folder.rglob("*"))
        except OSError:
            return managed, custom
        for p in paths:
            try:
                if p.is_symlink() or not p.is_file() or p.suffix.lower() not in (".yar", ".yara"):
                    continue
                rel = p.relative_to(self.folder)
                (managed if rel.parts and rel.parts[0] == "managed" else custom).append(p)
            except (OSError, ValueError):
                continue
        return managed[:MAX_RULE_FILES], custom[:MAX_RULE_FILES]

    def _compile_group(self, files, label, total):
        if not files:
            return total
        if len(files) > MAX_RULE_FILES:
            self._errors.append(f"{label}: too many rule files")
            return total
        paths = {}
        for i, p in enumerate(files):
            try:
                size = p.stat().st_size
                if size <= 0 or size > MAX_RULE_BYTES or total + size > MAX_RULE_TOTAL:
                    self._errors.append(f"{p.name}: skipped, too large or package limit reached")
                    continue
                total += size
                paths[f"lp_{i:05d}"] = str(p)
            except OSError:
                self._errors.append(f"{p.name}: cannot read rule file")
        if not paths:
            return total
        if label == "YARA Forge Core":
            try:
                self._rules.append((label, yara.compile(filepaths=paths, includes=False)))
                self._loaded_files += len(paths)
            except Exception as e:
                self._errors.append(f"{label}: {_short(e, 180)}")
            return total
        for name, path in paths.items():
            try:
                self._rules.append((pathlib.Path(path).name, yara.compile(filepath=path, includes=False)))
                self._loaded_files += 1
            except Exception as e:
                self._errors.append(f"{pathlib.Path(path).name}: {_short(e, 160)}")
        return total

    def _load(self):
        managed, custom = self._files()
        all_files = managed + custom
        try:
            sig = tuple((str(p.relative_to(self.folder)), p.stat().st_mtime_ns, p.stat().st_size) for p in all_files)
        except OSError:
            sig = ()
        if sig == self._sig:
            return
        self._sig, self._rules, self._errors = sig, [], []
        self._managed_files, self._custom_files = len(managed), len(custom)
        self._loaded_files = 0
        if yara is None:
            return
        total = self._compile_group(managed, "YARA Forge Core", 0)
        self._compile_group(custom, "custom rule", total)

    def status(self) -> dict:
        self._load()
        meta = {}
        try:
            p = self.folder.parent / "yara-status.json"
            obj = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                meta = {k: obj.get(k) for k in ("package", "version", "status", "rule_count", "rule_files",
                                                   "updated_at", "checked_at", "last_error") if obj.get(k) is not None}
        except (OSError, ValueError):
            pass
        return {"available": yara is not None, "files": self._managed_files + self._custom_files,
                "managed_files": self._managed_files, "custom_files": self._custom_files,
                "loaded": self._loaded_files, "groups": len(self._rules), "errors": self._errors[:20], "managed": meta,
                "fingerprint": hashlib.sha256(repr(self._sig).encode("utf-8")).hexdigest()}

    def scan(self, data: bytes) -> dict:
        out = self.status()
        out["matches"] = []
        if yara is None or not self._rules:
            return out
        for name, rules in self._rules:
            try:
                found = rules.match(data=data, timeout=SCAN_SECONDS)
            except Exception as e:
                out["errors"].append(f"{name}: scan stopped ({_short(e, 80)})")
                continue
            for m in found:
                meta = getattr(m, "meta", {}) or {}
                out["matches"].append({
                    "rule": _short(m.rule, 80), "file": name,
                    "tags": [_short(t, 30) for t in (getattr(m, "tags", []) or [])][:8],
                    "description": _short(meta.get("description", ""), 200),
                    "hits": len(getattr(m, "strings", []) or [])})
                if len(out["matches"]) >= MAX_MATCHES:
                    return out
        return out
