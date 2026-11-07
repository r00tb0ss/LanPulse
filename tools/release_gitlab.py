#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Publish the current VERSION as a GitLab release with lanpulse.zip attached (Settings > Update reads these).

Run from the repository root after the version change is committed and pushed:
    GITLAB_TOKEN=glpat-... python3 tools/release_gitlab.py
The token needs the `api` scope. It is read from the environment and never written anywhere."""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROJECT = os.environ.get("GITLAB_PROJECT", "r00tb0ss/lanpulse")
HOST = "https://gitlab.com"
API = f"{HOST}/api/v4/projects/{urllib.parse.quote(PROJECT, safe='')}"


def call(req):
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"GitLab answered {e.code}: {e.read()[:300].decode('utf-8', 'replace')}")


def main():
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        sys.exit("Set GITLAB_TOKEN (a personal access token with the api scope).")
    ver = re.search(r'^VERSION = "([^"]+)"', open("app.py").read(), re.M).group(1)
    tag = f"v{ver}"
    notes_file = f"docs/releases/{ver}.md"
    notes = open(notes_file).read() if os.path.exists(notes_file) else f"LanPulse {ver}"
    zpath = os.path.join(tempfile.mkdtemp(), "lanpulse.zip")
    subprocess.run(["git", "archive", "--prefix=lanpulse/", "HEAD", "-o", zpath, "--format=zip"], check=True)
    # 1. upload the zip (GitLab serves it from the project's uploads)
    b = uuid.uuid4().hex
    data = open(zpath, "rb").read()
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="lanpulse.zip"\r\n'
            f'Content-Type: application/zip\r\n\r\n').encode() + data + f"\r\n--{b}--\r\n".encode()
    up = call(urllib.request.Request(f"{API}/uploads", data=body, method="POST", headers={
        "PRIVATE-TOKEN": token, "Content-Type": f"multipart/form-data; boundary={b}"}))
    url = HOST + up["full_path"]          # e.g. https://gitlab.com/-/project/123/uploads/<hash>/lanpulse.zip
    # 2. create the release pointing at that file
    rel = {"tag_name": tag, "ref": "HEAD", "name": f"LanPulse {ver}", "description": notes,
           "assets": {"links": [{"name": "lanpulse.zip", "url": url, "link_type": "package"}]}}
    rel["ref"] = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    out = call(urllib.request.Request(f"{API}/releases", data=json.dumps(rel).encode(), method="POST", headers={
        "PRIVATE-TOKEN": token, "Content-Type": "application/json"}))
    print("Published", out.get("_links", {}).get("self", tag))


if __name__ == "__main__":
    main()
