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

CONTRAST_JS = """() => {
  const hex = (h) => { h = h.trim().replace('#', ''); if (h.length === 3) h = [...h].map((x) => x + x).join(''); return h.length === 6 ? {r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: 1} : null; };
  const parse = (c) => { if (!c) return null; c = c.trim(); if (c[0] === '#') return hex(c); const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null;
    const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(parseFloat); return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1}; };
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  const over = (top, bot) => ({r: top.r * top.a + bot.r * (1 - top.a), g: top.g * top.a + bot.g * (1 - top.a), b: top.b * top.a + bot.b * (1 - top.a), a: 1});
  const mapArea = parse(getComputedStyle(document.body).getPropertyValue('--map-area')) || {r: 26, g: 39, b: 66, a: 1};
  const bgOf = (el) => {
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e), c = parse(cs.backgroundColor);
      if (e.classList && (e.classList.contains('t-mapcard') || e.classList.contains('mapwrap'))) { layers.push(mapArea); break; }
      if (cs.backgroundImage !== 'none' && (!c || c.a < 1)) return null;          // a gradient or picture: cannot be judged
      if (c && c.a > 0) { layers.push(c); if (c.a >= 1) break; }
    }
    let out = {r: 255, g: 255, b: 255, a: 1};
    const bodyBg = parse(getComputedStyle(document.body).backgroundColor); if (bodyBg && bodyBg.a > 0) out = over(bodyBg, out);
    for (const l of layers.reverse()) out = over(l, out);
    return out;
  };
  const seen = new Set(), bad = [];
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('svg,canvas,script,style,#panel:not(.open)') || el.disabled || el.closest(':disabled')) continue;
    const own = [...el.childNodes].filter((n) => n.nodeType === 3 && n.textContent.trim().length > 1).map((n) => n.textContent.trim()).join(' ');
    if (!own) continue;
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (r.width < 2 || r.height < 2 || cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) continue;
    if (r.bottom < 0 || r.top > innerHeight * 3) continue;
    const fg = parse(cs.color), bg = bgOf(el);
    if (!fg || !bg) continue;
    const f = fg.a < 1 ? over(fg, bg) : fg, l1 = lum(f), l2 = lum(bg), ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    if (ratio < 3) {
      const name = (el.id ? '#' + el.id : el.tagName.toLowerCase()) + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\\s+/).slice(0, 2).join('.') : '');
      const key = name + own.slice(0, 20);
      if (!seen.has(key)) { seen.add(key); bad.push(name + ' "' + own.slice(0, 32) + '" ' + ratio.toFixed(1) + ':1'); }
    }
  }
  return bad.slice(0, 14);
}"""


def check_contrast(page, problems):
    """Light themes keep a few dark areas (the map). Text must stay readable everywhere, in every tab and settings page."""
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(BASE, wait_until="domcontentloaded")
    page.wait_for_selector("#vNet", timeout=20000)
    page.wait_for_timeout(1500)
    for theme in ("light", "sand"):
        page.evaluate("t => document.body.setAttribute('data-theme', t)", theme)
        for vid in VIEWS:
            page.evaluate("id => document.getElementById(id).click()", vid)
            page.wait_for_timeout(1200)
            for item in page.evaluate(CONTRAST_JS):
                problems.append(f"[{theme} {vid}] hard to read: {item}")
        page.evaluate("() => document.getElementById('btnSettings').click()")
        page.wait_for_timeout(600)
        for tab in page.evaluate("() => [...document.querySelectorAll('#setTabs button')].map((b) => b.dataset.tab)"):
            page.evaluate("t => document.querySelector(`#setTabs button[data-tab=\"${t}\"]`).click()", tab)
            page.wait_for_timeout(700)
            for item in page.evaluate(CONTRAST_JS):
                problems.append(f"[{theme} settings {tab}] hard to read: {item}")
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)
        # The side panels: the attacker IP box and a device
        page.evaluate("() => document.getElementById('vThreat').click()")
        page.wait_for_timeout(800)
        page.evaluate("() => openIp('198.51.100.7')")
        page.wait_for_timeout(2500)
        for item in page.evaluate(CONTRAST_JS):
            problems.append(f"[{theme} IP box] hard to read: {item}")
        page.evaluate("() => { const d = [...devices.values()][0]; if (d && typeof openPanel === 'function') openPanel(d.id); }")
        page.wait_for_timeout(1500)
        for item in page.evaluate(CONTRAST_JS):
            problems.append(f"[{theme} device panel] hard to read: {item}")
        page.evaluate("() => document.getElementById('btnClose').click()")
    page.evaluate("() => document.body.removeAttribute('data-theme')")


def check_arcs(page, problems):
    """Traffic arcs must stay on the map: a long route to the southern hemisphere used to swing below the bottom edge."""
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(BASE, wait_until="domcontentloaded")
    page.wait_for_selector("#vNet", timeout=20000)
    page.evaluate("() => document.getElementById('vThreat').click()")
    page.wait_for_timeout(3000)
    worst = page.evaluate("""() => {
      if (typeof tChart === 'undefined' || !tChart || typeof homeCoord !== 'function' || !homeCoord()) return null;
      const home = homeCoord(), h = tChart.getHeight();
      const far = [[151, -33], [-70, -50], [20, -34], [139, 35], [-5, 50], [175, -41], [-58, -34]];
      let over = -1e9;
      for (const p of far) for (const route of [[home, p], [p, home]]) for (const coords of arcSegments(route)) {
        const a = tChart.convertToPixel('geo', coords[0]), b = tChart.convertToPixel('geo', coords[1]);
        if (!a || !b) continue;
        if (Math.abs(coords[1][0] - coords[0][0]) > 180) return -2;               // a piece still runs more than half the world
        const c = arcCurve(coords), cy = (a[1] + b[1]) / 2 - (b[0] - a[0]) * c;
        over = Math.max(over, (0.25 * a[1] + 0.5 * cy + 0.25 * b[1]) - h);       // how far the arc's middle sags below the map
      }
      return over;
    }""")
    if worst is None:
        problems.append("[map arcs] the live map did not start, so the arc check could not run")
    elif worst == -2:
        problems.append("[map arcs] an arc still runs the long way across the whole map instead of over the date line")
    elif worst > 0:
        problems.append(f"[map arcs] an arc to a far southern place swings {worst:.0f}px below the bottom of the map")


def check_colours_and_ips(page, problems):
    """Map colours: attackers red, known scanners yellow, device data blue, all named in the legend. IPs never wrap."""
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(BASE, wait_until="domcontentloaded")
    page.wait_for_selector("#vNet", timeout=20000)
    page.evaluate("() => document.getElementById('vThreat').click()")
    page.wait_for_timeout(1500)
    got = page.evaluate("""() => ({scanner: typeof SCANNER_COLOR === 'undefined' ? '' : SCANNER_COLOR,
      attack: typeof ATTACK_COLOR === 'undefined' ? '' : ATTACK_COLOR,
      legend: (document.querySelector('.map-legend') || {}).textContent || ''})""")
    if got["scanner"].lower() != "#facc15" or got["attack"].lower() != "#f43f5e":
        problems.append(f"[map colours] scanners should be yellow and attackers red, got {got['scanner']} / {got['attack']}")
    for word in ("Attacker", "Suspicious", "data", "Your network"):
        if word not in got["legend"]:
            problems.append(f"[map colours] the legend does not name '{word}'")
    page.set_viewport_size({"width": 390, "height": 800})
    page.evaluate("() => { const b = document.getElementById('vPot') || document.getElementById('vHoney'); if (b) b.click(); }")
    page.wait_for_timeout(1500)
    wrapped = page.evaluate("""() => [...document.querySelectorAll('#potView .pot-ip')].filter((el) => el.offsetParent
      && el.offsetHeight > 1.8 * parseFloat(getComputedStyle(el).lineHeight || 18)).length""")
    if wrapped:
        problems.append(f"[honeypot phone] {wrapped} IP address(es) are split across lines")


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
                        if (r.width > 0 && r.right > w + 2 && getComputedStyle(el).position !== 'fixed' && !el.closest('#panel,.vis-network,canvas,svg,.topo-stage,.t-map,#map,.scroll-x,.table-wrap,.atk-table,pre,.tabs,.views')) {
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
                check_arcs(page, problems)
                check_colours_and_ips(page, problems)
                check_contrast(page, problems)
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
