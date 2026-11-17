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
                # Phone layout: a device card with many tags must keep a readable name column (it once became one letter wide).
                page.set_viewport_size({"width": 390, "height": 800})
                current["view"] = "phone vulns"
                page.goto(BASE, wait_until="domcontentloaded")
                page.wait_for_selector("#vVuln", timeout=20000)
                page.evaluate("document.getElementById('vVuln').click()")
                page.wait_for_timeout(1500)
                widths = page.evaluate("""() => {
                  const host = document.getElementById('vulnFix'); const dev = document.getElementById('vulnDevs');
                  host.innerHTML = `<div class="fixdev open"><button class="fixdev-head"><span class="score-chip">10.0</span>
                    <span class="fix-main"><b>METASPLOITABLE</b> <span class="muted mono">192.168.0.11</span><br><span class="fix-dev">69 services with flaws</span></span>
                    <span class="fix-tags"><span class="tagchip confirmed">56 confirmed</span><span class="tagchip msf">12 Metasploit</span><span class="tagchip">7 CVEs + 64 other</span></span>
                    <i class="fa-solid fa-chevron-down chev"></i></button></div>`;
                  dev.innerHTML = `<div class="rk click vd"><span class="ico"></span><span class="nm">METASPLOITABLE</span><span class="ct">71 findings</span>
                    <div class="vd-meta"><span class="vd-facts">56 confirmed · 10 Metasploit modules · 12 with public code</span>
                    <span class="vd-acts"><button class="btn sm">OpenVAS scan</button><button class="btn sm">Attack view</button></span></div><div class="bar"><i style="width:50%"></i></div></div>`;
                  return {main: host.querySelector('.fix-main').getBoundingClientRect().width,
                          name: dev.querySelector('.nm').getBoundingClientRect().width};
                }""")
                if widths["main"] < 120:
                    problems.append(f"[phone vulns] the device name column is only {widths['main']:.0f}px wide")
                if widths["name"] < 100:
                    problems.append(f"[phone vulns] the device list name is only {widths['name']:.0f}px wide")
                page.screenshot(path=os.path.join(ROOT, "browser-phone-vulns.png"))
                # Tablet layout: Topology must sit right under the view buttons and clear of the bottom search bar.
                page.set_viewport_size({"width": 840, "height": 900})
                current["view"] = "tablet topology"
                page.goto(BASE, wait_until="domcontentloaded")
                page.wait_for_selector("#vNet", timeout=20000)
                page.wait_for_timeout(1500)
                geo = page.evaluate("""async () => {
                  for (const b of document.querySelectorAll('#layoutPick button')) {
                    b.click(); await new Promise(r => setTimeout(r, 700));
                    if (document.querySelector('.topo-bar')) break;
                  }
                  const bar = document.querySelector('.topo-bar'), pick = document.getElementById('layoutPick'),
                        stage = document.querySelector('.topo-stage'), find = document.getElementById('mapFind');
                  if (!bar) return null;
                  return {gap: bar.getBoundingClientRect().top - pick.getBoundingClientRect().bottom,
                          overlap: stage.getBoundingClientRect().bottom - find.getBoundingClientRect().top};
                }""")
                if geo is None:
                    problems.append("[tablet topology] the topology view did not open")
                else:
                    if geo["gap"] > 40:
                        problems.append(f"[tablet topology] {geo['gap']:.0f}px of empty space above the toolbar")
                    if geo["overlap"] > 4:
                        problems.append(f"[tablet topology] the search bar covers the bottom {geo['overlap']:.0f}px of the diagram")
                page.screenshot(path=os.path.join(ROOT, "browser-tablet-topology.png"))
                # The side panel keeps its normal size on a tablet and gets wider only when asked.
                widths = page.evaluate("""() => {
                  const p = document.getElementById('panel'); p.classList.add('open');
                  const normal = p.getBoundingClientRect().width;
                  document.getElementById('btnExpand').click();
                  const wide = p.getBoundingClientRect().width;
                  document.getElementById('btnExpand').click(); p.classList.remove('open');
                  return {normal, wide, vw: window.innerWidth};
                }""")
                if widths["normal"] > widths["vw"] * 0.7:
                    problems.append(f"[tablet panel] the side panel covers {widths['normal']:.0f}px of a {widths['vw']}px screen by default")
                if widths["wide"] <= widths["normal"] + 100:
                    problems.append("[tablet panel] the wider-panel button did not make the panel wider")
                # Phone layout: no tab may be wider than the screen (the page would scroll sideways).
                page.set_viewport_size({"width": 390, "height": 1400})
                page.goto(BASE, wait_until="domcontentloaded")
                page.wait_for_selector("#vNet", timeout=20000)
                page.wait_for_timeout(1500)
                for vid in VIEWS:
                    current["view"] = f"phone {vid}"
                    page.evaluate("id => document.getElementById(id).click()", vid)
                    page.wait_for_timeout(1800)
                    over = page.evaluate("""() => {
                      const w = window.innerWidth, wide = [];
                      for (const el of document.querySelectorAll('body *')) {
                        const r = el.getBoundingClientRect();
                        if (r.width > 0 && r.right > w + 2 && getComputedStyle(el).position !== 'fixed' && !el.closest('.vis-network,canvas,svg,.topo-stage,.t-map,#map,.scroll-x,.table-wrap,.atk-table,pre,.tabs,.views')) {
                          wide.push((el.id ? '#' + el.id : el.tagName.toLowerCase() + '.' + String(el.className).split(' ')[0]) + ' ' + Math.round(r.right - w) + 'px');
                          if (wide.length >= 4) break;
                        }
                      }
                      return {scroll: document.documentElement.scrollWidth - w, wide};
                    }""")
                    if over["scroll"] > 2:
                        problems.append(f"[phone {vid}] the page scrolls sideways by {over['scroll']}px")
                    if over["wide"]:
                        problems.append(f"[phone {vid}] wider than the screen: {', '.join(over['wide'])}")
                    page.screenshot(path=os.path.join(ROOT, f"browser-phone-{vid}.png"))
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
