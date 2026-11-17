# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Open every main view of a demo-mode LanPulse in a real browser and fail on script errors or failed requests.

Run by the "Browser check" CI job (not by the unit tests, because it needs Playwright and a browser):
    pip install playwright && playwright install chromium && python tests/browser_check.py
"""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8080
BASE = f"http://127.0.0.1:{PORT}"
VIEWS = ["vNet", "vThreat", "vDns", "vVuln", "vSvc", "vRed", "vPot"]


def wait_up(proc, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise SystemExit("LanPulse exited early with code %s" % proc.returncode)
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
            return
        except Exception:
            time.sleep(1)
    raise SystemExit("LanPulse did not start within %ss" % seconds)


def check_delivery(problems):
    """Pages and data must be compressed, and a version-stamped file must be cacheable for a long time."""
    import re
    html = urllib.request.urlopen(BASE + "/").read().decode()
    stamped = re.search(r'(/static/app\.js\?v=[^"]+)', html)
    if not stamped:
        problems.append("[delivery] the page does not stamp its script URLs with the release number")
        return
    for path in (stamped.group(1), "/api/devices"):
        req = urllib.request.Request(BASE + path, headers={"Accept-Encoding": "gzip"})
        resp = urllib.request.urlopen(req)
        if resp.headers.get("Content-Encoding") != "gzip":
            problems.append(f"[delivery] {path} was not compressed")
    cache = urllib.request.urlopen(BASE + stamped.group(1)).headers.get("Cache-Control", "")
    if "immutable" not in cache:
        problems.append(f"[delivery] a version-stamped file should be cached long-term, got {cache!r}")


def main() -> int:
    from playwright.sync_api import sync_playwright
    problems = []
    with tempfile.TemporaryDirectory() as data:
        with open(os.path.join(data, "settings.json"), "w") as fh:
            fh.write('{"wizard": {"done": true}}')          # skip the first-run guide, which covers the page
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "app.py"), "--demo", "--data-dir", data], cwd=ROOT)
        try:
            wait_up(proc)
            check_delivery(problems)
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1400, "height": 900})
                current = {"view": "load"}
                page.on("pageerror", lambda e: problems.append(f"[{current['view']}] script error: {e}"))
                page.on("response", lambda r: problems.append(f"[{current['view']}] HTTP {r.status} {r.url}")
                        if r.url.startswith(BASE) and r.status >= 400 and not r.url.endswith("favicon.ico") and "/static/vendor/" not in r.url else None)   # vendor libraries come from the installer; the page falls back to a CDN
                page.goto(BASE, wait_until="domcontentloaded")
                page.wait_for_selector("#vNet", timeout=20000)
                page.wait_for_timeout(2500)
                if page.is_visible("#wizSkipAll"):
                    page.click("#wizSkipAll")
                    page.wait_for_timeout(500)
                for vid in VIEWS:
                    current["view"] = vid
                    page.click("#" + vid)
                    page.wait_for_timeout(2500)
                    if page.get_attribute("#" + vid, "aria-selected") != "true":
                        problems.append(f"[{vid}] the tab did not become selected")
                    shown = page.evaluate("document.body.innerText.trim().length")
                    if shown < 200:
                        problems.append(f"[{vid}] the page looks blank ({shown} characters of text)")
                    page.screenshot(path=os.path.join(ROOT, f"browser-{vid}.png"))
                browser.close()
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except Exception:
                proc.kill()
    for line in problems:
        print("FAIL", line)
    print("browser check:", "failed" if problems else "all views loaded cleanly", f"({len(VIEWS)} views)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
