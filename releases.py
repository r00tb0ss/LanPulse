# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Find and download the newest LanPulse release (used by Settings > Update).

Releases are looked up on GitLab first and on GitHub as a fallback. Only the project's own releases are used, over HTTPS,
and every redirect must stay on those hosts. The downloaded file goes through the same checks as a manually uploaded zip
before anything is installed."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GITLAB_PROJECT = "r00tb0ss/lanpulse"
GITHUB_REPO = "r00tb0ss/LanPulse"
PAGES_URL = "https://r00tb0ss.gitlab.io/lanpulse/latest.json"   # written by the pages job in .gitlab-ci.yml
SOURCES = (
    ("GitLab Pages", "pages", PAGES_URL),   # not rate-limited like the API, so it goes first
    ("GitLab", "gitlab", f"https://gitlab.com/api/v4/projects/{urllib.parse.quote(GITLAB_PROJECT, safe='')}/releases/permalink/latest"),
    ("GitHub", "github", f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"),
)
ALLOWED_HOSTS = ("gitlab.com", "r00tb0ss.gitlab.io", "github.com", "api.github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com", "github-releases.githubusercontent.com")
_cache: dict = {"t": 0.0, "data": None}


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise urllib.error.URLError("Redirected away from the release host; refusing to follow.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, timeout: int):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise urllib.error.URLError("Only LanPulse release downloads are allowed.")
    opener = urllib.request.build_opener(_Redirects())
    return opener.open(urllib.request.Request(url, headers={"User-Agent": "LanPulse-updater",
                                                            "Accept": "application/json"}), timeout=timeout)


def _parse(kind: str, j: dict) -> dict:
    if kind == "pages":
        tag = j.get("tag") or ""
        ver = str(j.get("version") or tag.lstrip("vV"))
        return {"tag": tag, "version": ver, "name": f"LanPulse {ver}", "notes": "", "url": j.get("url", ""),
                "asset_url": j.get("asset_url", ""), "size": 0, "published": ""}
    tag = j.get("tag_name") or ""
    if kind == "gitlab":
        links = [a for a in (j.get("assets") or {}).get("links", []) if str(a.get("name", "")).lower().endswith(".zip")]
        asset = next((a for a in links if a["name"].lower() == "lanpulse.zip"), links[0] if links else None)
        return {"tag": tag, "version": tag.lstrip("vV"), "name": j.get("name") or tag,
                "notes": (j.get("description") or "")[:4000], "url": (j.get("_links") or {}).get("self", ""),
                "asset_url": (asset.get("direct_asset_url") or asset.get("url") or "") if asset else "", "size": 0,
                "published": j.get("released_at", "")}
    assets = [a for a in j.get("assets", []) if str(a.get("name", "")).lower().endswith(".zip")]
    asset = next((a for a in assets if a["name"].lower() == "lanpulse.zip"), assets[0] if assets else None)
    return {"tag": tag, "version": tag.lstrip("vV"), "name": j.get("name") or tag, "notes": (j.get("body") or "")[:4000],
            "url": j.get("html_url", ""), "asset_url": asset["browser_download_url"] if asset else "",
            "size": asset.get("size", 0) if asset else 0, "published": j.get("published_at", "")}


def latest(current: str, force: bool = False) -> dict:
    """Newest published release: {tag, version, notes, newer, asset_url, size, source, error}. Tries each source in turn;
    the newest version found wins."""
    if not force and _cache["data"] and time.time() - _cache["t"] < 600:
        return {**_cache["data"], "newer": version_tuple(_cache["data"]["version"]) > version_tuple(current)}
    best, errors, limited = None, [], False
    for label, kind, api in SOURCES:
        try:
            with _open(api, 15) as r:
                d = _parse(kind, json.loads(r.read(2_000_000)))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                limited = True
                errors.append(f"{label}: rate limited, try again in a minute")
            else:
                errors.append(f"{label}: no release published yet" if e.code == 404 else f"{label} answered {e.code}")
            continue
        except Exception as e:
            errors.append(f"{label}: couldn't reach it ({e.__class__.__name__})")
            continue
        if not d["version"] or not d["asset_url"]:
            errors.append(f"{label}: release has no lanpulse.zip")
            continue
        d["source"] = label
        if best is None or version_tuple(d["version"]) > version_tuple(best["version"]):
            best = d
        if kind == "pages":
            break   # Pages answered; don't spend the rate-limited API
    if best is None and limited and _cache["data"]:
        return {**_cache["data"], "newer": version_tuple(_cache["data"]["version"]) > version_tuple(current)}
    if best is None:
        return {"error": "No release found. " + "; ".join(errors) + ". Check this server's internet access, or choose a file yourself."}
    _cache.update(t=time.time(), data=best)
    return {**best, "newer": version_tuple(best["version"]) > version_tuple(current)}


def download(url: str, dest: Path, max_bytes: int) -> int:
    """Stream the release zip to dest. Raises ValueError when it's too big, URLError when the release host can't be reached."""
    size = 0
    with _open(url, 120) as r, open(dest, "wb") as f:
        while chunk := r.read(1 << 16):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("That release is too big for a LanPulse update.")
            f.write(chunk)
    return size
