# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Optional YARA rule matching for captured honeypot files.

Off unless two things are true: the `yara-python` package is installed, and there are rule files in the
`yara-rules` folder inside LanPulse's data folder. LanPulse never downloads rules and never takes a rule from a
capture; only files the owner put in that folder are used.

SAFETY: a captured file is only ever handed to the YARA scanner as bytes. Nothing is executed. Rule files are read
with `include` directives disabled, so a rule cannot pull in other files from the disk, and every scan has a time limit.
"""
from __future__ import annotations

import logging
import pathlib

log = logging.getLogger("lanpulse.yaralook")

MAX_RULE_FILES = 200
MAX_RULE_BYTES = 1_000_000      # one rule file
MAX_RULE_TOTAL = 20_000_000     # all rule files together
SCAN_SECONDS = 10
MAX_MATCHES = 25

try:                            # the package is optional
    import yara
except Exception:               # not installed, or it failed to load
    yara = None


def _short(v, n: int = 200) -> str:
    return "".join(c for c in str(v) if c.isprintable())[:n]


class YaraRules:
    """Loads rule files from one folder, compiles each separately (so one broken file cannot hide the rest) and caches
    the result until a file in the folder changes."""

    def __init__(self, folder: pathlib.Path):
        self.folder = pathlib.Path(folder)
        self._sig = None
        self._rules: list = []          # [(file name, compiled rules)]
        self._errors: list[str] = []

    def _files(self) -> list[pathlib.Path]:
        try:
            found = [p for p in sorted(self.folder.iterdir())
                     if p.suffix.lower() in (".yar", ".yara") and p.is_file() and not p.is_symlink()]
        except OSError:
            return []
        return found[:MAX_RULE_FILES]

    def _load(self):
        files = self._files()
        try:
            sig = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        except OSError:
            sig = ()
        if sig == self._sig:
            return
        self._sig, self._rules, self._errors = sig, [], []
        if yara is None:
            return
        total = 0
        for p in files:
            size = p.stat().st_size
            total += size
            if size > MAX_RULE_BYTES or total > MAX_RULE_TOTAL:
                self._errors.append(f"{p.name}: skipped, too large")
                continue
            try:
                self._rules.append((p.name, yara.compile(filepath=str(p), includes=False)))
            except Exception as e:                  # a syntax error in one file
                self._errors.append(f"{p.name}: {_short(e, 160)}")

    def status(self) -> dict:
        self._load()
        return {"available": yara is not None, "files": len(self._sig or ()), "loaded": len(self._rules),
                "errors": self._errors[:10]}

    def scan(self, data: bytes) -> dict:
        """Rules matched by `data`: {available, files, loaded, errors, matches:[{rule, file, tags, description, hits}]}.
        An empty result when YARA or the rules are not there."""
        out = self.status()
        out["matches"] = []
        if yara is None or not self._rules:
            return out
        for name, rules in self._rules:
            try:
                found = rules.match(data=data, timeout=SCAN_SECONDS)
            except Exception as e:                  # timeout or a scanner error: report, keep going
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
