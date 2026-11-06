# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Find and download the newest LanPulse release from GitHub (used by Settings > Update).

Only the repository's own releases are used, over HTTPS, and every redirect must stay on GitHub's hosts. The downloaded
file goes through the same checks as a manually uploaded zip before anything is installed."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "r00tb0ss/LanPulse"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
ALLOWED_HOSTS = ("github.com", "api.github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com", "github-releases.githubusercontent.com")
_cache: dict = {"t": 0.0, "data": None}


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise urllib.error.URLError("Redirected away from GitHub; refusing to follow.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, timeout: int):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise urllib.error.URLError("Only GitHub release downloads are allowed.")
    opener = urllib.request.build_opener(_Redirects())
    return opener.open(urllib.request.Request(url, headers={"User-Agent": "LanPulse-updater",
                                                            "Accept": "application/vnd.github+json"}), timeout=timeout)


def latest(current: str, force: bool = False) -> dict:
    """Newest published release: {tag, version, notes, newer, asset_url, size, error}."""
    if not force and _cache["data"] and time.time() - _cache["t"] < 600:
        return {**_cache["data"], "newer": version_tuple(_cache["data"]["version"]) > version_tuple(current)}
    try:
        with _open(API, 15) as r:
            j = json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        return {"error": "No release is published on GitHub yet." if e.code == 404 else f"GitHub answered {e.code}."}
    except Exception as e:
        return {"error": f"Couldn't reach GitHub ({e.__class__.__name__}). Check this server's internet access."}
    tag = j.get("tag_name") or ""
    assets = [a for a in j.get("assets", []) if str(a.get("name", "")).lower().endswith(".zip")]
    asset = next((a for a in assets if a["name"].lower() == "lanpulse.zip"), assets[0] if assets else None)
    data = {"tag": tag, "version": tag.lstrip("vV"), "name": j.get("name") or tag, "notes": (j.get("body") or "")[:4000],
            "url": j.get("html_url", ""), "asset_url": asset["browser_download_url"] if asset else "",
            "size": asset.get("size", 0) if asset else 0, "published": j.get("published_at", "")}
    _cache.update(t=time.time(), data=data)
    return {**data, "newer": version_tuple(data["version"]) > version_tuple(current)}


def download(url: str, dest: Path, max_bytes: int) -> int:
    """Stream the release zip to dest. Raises ValueError when it's too big, URLError when GitHub can't be reached."""
    size = 0
    with _open(url, 120) as r, open(dest, "wb") as f:
        while chunk := r.read(1 << 16):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("That release is too big for a LanPulse update.")
            f.write(chunk)
    return size
