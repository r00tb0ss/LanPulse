# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Professional reports for every tab, as print-ready HTML and (optionally) PDF.

Each report is first built as a small document model (title, headline numbers, then headings, paragraphs and
tables). One renderer turns that model into a self-contained HTML page and another into a PDF, so every tab gets
the same look and the two formats always agree. Nothing here opens a connection or runs a scan: every report is
made from data LanPulse already holds. Captured malware is never run; reports list static findings only, and
indicators are shown defanged.

The PDF renderer needs the optional `reportlab` package. Without it only the HTML report is offered; the HTML
page has a Print button, and "Save as PDF" in any browser gives the same layout.
"""
from __future__ import annotations

import html
import io
import re
import time

MAX_ROWS = 400                      # rows printed per table; the report says how many more exist
MAX_SAMPLE_DETAILS = 25             # malware samples described in full
MAX_SESSION_DETAILS = 8             # sessions with their attack timeline
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# kind -> (menu title, which tab it belongs to, uses a time range)
KINDS = {
    "executive": ("Executive security report", "network", True),
    "network": ("Network and devices", "network", False),
    "threats": ("Threats at the router", "threats", True),
    "dns": ("DNS activity", "dns", True),
    "vulns": ("Vulnerabilities", "vulns", False),
    "services": ("Services and uptime", "services", False),
    "redteam": ("Red Team findings", "redteam", False),
    "honeypot": ("Honeypot attacks", "honeypot", True),
    "honeypot-sessions": ("Captured sessions", "honeypot", True),
    "honeypot-attackers": ("Attacker profiles", "honeypot", True),
    "honeypot-campaigns": ("Campaigns and shared evidence", "honeypot", True),
    "honeypot-malware": ("Malware samples and YARA", "honeypot", True),
    "honeypot-sensors": ("Honeypot sensors", "honeypot", False),
}


def clean(v, n: int = 300) -> str:
    """Printable text only, so a hostile string from the network can't break a report."""
    return _CTRL.sub("", str(v if v is not None else ""))[:n]


_URL = re.compile(r"\b(https?|ftp)://([^\s/'\"<>]+)", re.I)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def inert(v, n: int = 300) -> str:
    """Text an attacker controlled (commands, URLs, tried logins), made harmless to read and copy: hxxp://host[.]example"""
    t = clean(v, n)
    t = _URL.sub(lambda m: m.group(1).replace("t", "x", 2) + "://" + m.group(2).replace(".", "[.]"), t)
    return _IPV4.sub(r"\1[.]\2[.]\3[.]\4", t)


def when(t) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t))) if t else "-"
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def span(seconds) -> str:
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "-"
    if s < 90:
        return f"{round(s)} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} days"


def hours_label(h: int) -> str:
    return "last hour" if h == 1 else f"last {h} hours" if h < 48 else f"last {round(h / 24)} days"


class Doc:
    """The report model: a title, a row of headline numbers, then blocks in reading order."""

    def __init__(self, title: str, subtitle: str = ""):
        self.title, self.subtitle = clean(title, 160), clean(subtitle, 600)
        self.kpis: list[dict] = []
        self.blocks: list[dict] = []

    def kpi(self, label, value, tone: str = ""):
        self.kpis.append({"label": clean(label, 60), "value": clean(value, 40), "tone": tone})
        return self

    def h(self, text):
        self.blocks.append({"t": "h", "text": clean(text, 160)})
        return self

    def p(self, text):
        self.blocks.append({"t": "p", "text": clean(text, 1200)})
        return self

    def note(self, text):
        self.blocks.append({"t": "note", "text": clean(text, 1200)})
        return self

    def bullets(self, items):
        items = [clean(i, 500) for i in items if i]
        if items:
            self.blocks.append({"t": "list", "items": items})
        return self

    def kv(self, pairs):
        pairs = [(clean(k, 60), clean(v, 600)) for k, v in pairs if v not in (None, "")]
        if pairs:
            self.blocks.append({"t": "kv", "pairs": pairs})
        return self

    def table(self, cols, rows, weights=None, empty: str = "Nothing to report for this period."):
        rows = [[clean(c, 400) for c in r] for r in rows]
        if not rows:
            return self.p(empty)
        shown = rows[:MAX_ROWS]
        self.blocks.append({"t": "table", "cols": [clean(c, 60) for c in cols], "rows": shown,
                            "weights": weights or [1] * len(cols),
                            "more": len(rows) - len(shown)})
        return self


# ---------------------------------------------------------------- renderers

def render_html(doc: Doc, meta: dict) -> str:
    e = html.escape
    out = []
    for b in doc.blocks:
        t = b["t"]
        if t == "h":
            out.append(f"<h2>{e(b['text'])}</h2>")
        elif t == "p":
            out.append(f"<p>{e(b['text'])}</p>")
        elif t == "note":
            out.append(f"<p class='note'>{e(b['text'])}</p>")
        elif t == "list":
            out.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in b["items"]) + "</ul>")
        elif t == "kv":
            out.append("<dl>" + "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in b["pairs"]) + "</dl>")
        elif t == "table":
            total = sum(b["weights"]) or 1
            cols = "".join(f"<col style='width:{100 * w / total:.1f}%'>" for w in b["weights"])
            head = "".join(f"<th>{e(c)}</th>" for c in b["cols"])
            body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in b["rows"])
            more = f"<p class='note'>Showing the first {len(b['rows'])}; {b['more']} more are in LanPulse.</p>" if b["more"] else ""
            out.append(f"<table><colgroup>{cols}</colgroup><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}")
    kpis = "".join(f"<div class='kpi {e(k['tone'])}'><b>{e(k['value'])}</b><span>{e(k['label'])}</span></div>" for k in doc.kpis)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(doc.title)} - LanPulse</title><style>{_CSS}</style></head><body>
<div class="bar noprint"><button onclick="window.print()">Print or save as PDF</button></div>
<header><div class="brand">LanPulse</div><h1>{e(doc.title)}</h1>
<p class="sub">{e(doc.subtitle)}</p>
<p class="meta">Generated {e(meta.get('generated', ''))} &middot; LanPulse {e(meta.get('version', ''))} &middot; {e(meta.get('network', ''))}</p></header>
{f'<div class="kpis">{kpis}</div>' if kpis else ''}
{''.join(out)}
<footer>{e(FOOTER)}</footer></body></html>"""


FOOTER = ("Internal use. This report contains real IP addresses, device names and indicators from your own network. "
          "It was made by LanPulse from data it already held. Captured files were analysed statically and never run, "
          "and indicators are defanged. Scores and matches are triage evidence, not verdicts, and a missing match does "
          "not prove a file is safe.")

_CSS = """
@page{size:A4;margin:14mm 12mm}
*{box-sizing:border-box}
body{font:13px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111827;max-width:1000px;margin:0 auto;padding:24px}
.bar{text-align:right;margin-bottom:8px}.bar button{font:inherit;padding:6px 12px;border:1px solid #0ea5e9;background:#0ea5e9;color:#fff;border-radius:6px;cursor:pointer}
header{border-bottom:3px solid #0ea5e9;padding-bottom:10px;margin-bottom:16px}
.brand{font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#0369a1;font-size:11px}
h1{margin:2px 0 4px;font-size:24px}.sub{margin:0;color:#334155}.meta{margin:4px 0 0;color:#64748b;font-size:11px}
h2{margin:24px 0 8px;font-size:16px;color:#0b4a6e;border-bottom:1px solid #e2e8f0;padding-bottom:4px;break-after:avoid}
p{margin:6px 0}.note{color:#64748b;font-size:11px}
ul{margin:6px 0 6px 18px;padding:0}li{margin:2px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:8px 0;font-size:12px}dt{color:#64748b}dd{margin:0;word-break:break-all}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 8px}
.kpi{flex:1 1 120px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;text-align:center;break-inside:avoid}
.kpi b{display:block;font-size:22px;color:#0b4a6e}.kpi span{font-size:11px;color:#64748b}
.kpi.bad b{color:#b91c1c}.kpi.warn b{color:#c2410c}.kpi.good b{color:#15803d}
table{border-collapse:collapse;width:100%;table-layout:fixed;margin:8px 0;font-size:11px}
th,td{border:1px solid #cbd5e1;padding:4px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f1f5f9}thead{display:table-header-group}tr{break-inside:avoid}tbody tr:nth-child(even) td{background:#fafcff}
footer{margin-top:32px;border-top:1px solid #e2e8f0;padding-top:10px;color:#64748b;font-size:10.5px}
@media print{body{padding:0;max-width:none}.noprint{display:none}}
"""


def pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


def _pdf_text(v) -> str:
    """The built-in PDF fonts cover Windows Latin-1 only; anything else prints as '?' rather than as a box."""
    return html.escape(clean(v, 1500).encode("cp1252", "replace").decode("cp1252"), quote=False)


def render_pdf(doc: Doc, meta: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    base = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=base["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#64748b"))
    cell = ParagraphStyle("c", parent=body, fontSize=7.5, leading=9.5)
    head = ParagraphStyle("hc", parent=cell, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=base["Title"], fontSize=20, leading=24, alignment=0, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, textColor=colors.HexColor("#0b4a6e"), spaceBefore=12, spaceAfter=4)
    width = A4[0] - 24 * mm
    story = [Paragraph("LANPULSE", ParagraphStyle("br", parent=small, textColor=colors.HexColor("#0369a1"), fontName="Helvetica-Bold")),
             Paragraph(_pdf_text(doc.title), h1), Paragraph(_pdf_text(doc.subtitle), body),
             Paragraph(_pdf_text(f"Generated {meta.get('generated', '')} | LanPulse {meta.get('version', '')} | {meta.get('network', '')}"), small),
             Spacer(1, 8)]
    if doc.kpis:
        per = min(len(doc.kpis), 4)
        rows = []
        for i in range(0, len(doc.kpis), per):
            chunk = doc.kpis[i:i + per]
            rows.append([[Paragraph(f"<b><font size=15>{_pdf_text(k['value'])}</font></b>", ParagraphStyle("kv", parent=body, alignment=1)),
                          Paragraph(_pdf_text(k["label"]), ParagraphStyle("kl", parent=small, alignment=1))] for k in chunk]
                        + [""] * (per - len(chunk)))
        t = Table(rows, colWidths=[width / per] * per)
        t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                               ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                               ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story += [t, Spacer(1, 6)]
    for b in doc.blocks:
        k = b["t"]
        if k == "h":
            story.append(Paragraph(_pdf_text(b["text"]), h2))
        elif k == "p":
            story.append(Paragraph(_pdf_text(b["text"]), body))
        elif k == "note":
            story.append(Paragraph(_pdf_text(b["text"]), small))
        elif k == "list":
            for i in b["items"]:
                story.append(Paragraph("&bull; " + _pdf_text(i), body))
        elif k == "kv":
            t = Table([[Paragraph(_pdf_text(a), small), Paragraph(_pdf_text(v), cell)] for a, v in b["pairs"]],
                      colWidths=[width * 0.22, width * 0.78])
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 1),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
            story.append(t)
        elif k == "table":
            total = sum(b["weights"]) or 1
            data = [[Paragraph(_pdf_text(c), head) for c in b["cols"]]] + [[Paragraph(_pdf_text(c), cell) for c in r] for r in b["rows"]]
            t = Table(data, colWidths=[width * w / total for w in b["weights"]], repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                                   ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafcff")]),
                                   ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
            story.append(t)
            if b["more"]:
                story.append(Paragraph(_pdf_text(f"Showing the first {len(b['rows'])}; {b['more']} more are in LanPulse."), small))
    story += [Spacer(1, 14), Paragraph(_pdf_text(FOOTER), small)]

    def frame(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(12 * mm, 8 * mm, _pdf_plain(f"LanPulse | {doc.title}"))
        canvas.drawRightString(A4[0] - 12 * mm, 8 * mm, f"Page {d.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm, bottomMargin=14 * mm,
                      title=_pdf_plain(doc.title), author="LanPulse").build(story, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()


def _pdf_plain(v) -> str:
    return clean(v, 200).encode("cp1252", "replace").decode("cp1252")


# ---------------------------------------------------------------- collectors (plain dicts in, Doc out)

def _pct(a, b) -> str:
    return f"{round(100 * a / b)}%" if b else "0%"


def _countries(rows, key="country"):
    return [[r.get(key) or r.get("iso") or "?", f"{r.get('count', r.get('hits', 0)):,}"] for r in rows]


def _tone(n, bad=1, warn=0):
    return "bad" if n >= bad else "warn" if n > warn else "good"


def build_network(snap: dict, posture: dict, health: dict | None = None) -> Doc:
    devs = [d for d in snap.get("devices", []) if not d.get("is_self")] or list(snap.get("devices", []))
    online = sum(1 for d in devs if d.get("online"))
    now = time.time()
    new = [d for d in devs if (d.get("first_seen") or 0) > now - 86400]
    untrusted = [d for d in devs if d.get("online") and not d.get("trusted")]
    doc = Doc("Network and devices", "Everything LanPulse has discovered on the network, with its security score.")
    doc.kpi("Security score", f"{posture.get('score', '-')} ({posture.get('grade', '-')})",
            "good" if posture.get("score", 0) >= 80 else "warn" if posture.get("score", 0) >= 60 else "bad")
    doc.kpi("Devices", len(devs)).kpi("Online", online, "good").kpi("Offline", len(devs) - online)
    doc.kpi("New in 24 h", len(new), _tone(len(new), 99, 0)).kpi("Untrusted online", len(untrusted), _tone(len(untrusted), 99, 0))
    if posture.get("breakdown"):
        doc.h("What lowers the security score")
        doc.table(["Issue", "Devices or items", "Points lost"],
                  [[b.get("label"), b.get("count"), f"-{b.get('points')}"] for b in posture["breakdown"]], [5, 2, 2])
    if posture.get("fixes"):
        doc.h("Biggest fixes")
        doc.bullets(f"{f.get('text')} (+{f.get('points')} points)" for f in posture["fixes"])
    if health and health.get("items"):
        doc.h("LanPulse data sources")
        doc.table(["Source", "State", "Detail"], [[i.get("name"), i.get("state"), i.get("detail")] for i in health["items"]], [2, 1, 6])
    types: dict = {}
    for d in devs:
        types[d.get("type") or "unknown"] = types.get(d.get("type") or "unknown", 0) + 1
    doc.h("Device types")
    doc.table(["Type", "Devices"], [[k, v] for k, v in sorted(types.items(), key=lambda kv: -kv[1])], [3, 1])
    if new:
        doc.h("New devices in the last 24 hours")
        doc.table(["Name", "IP", "MAC", "Vendor", "First seen"],
                  [[d.get("name") or d.get("hostname") or d.get("vendor") or d.get("ip"), d.get("ip"), d.get("mac"),
                    d.get("vendor"), when(d.get("first_seen"))] for d in new], [3, 2, 3, 3, 2])
    doc.h("Device inventory")
    rows = []
    for d in sorted(devs, key=lambda d: (not d.get("online"), str(d.get("ip")))):
        ports = d.get("ports") or []
        rows.append([d.get("name") or d.get("friendly") or d.get("hostname") or d.get("vendor") or d.get("ip"), d.get("ip"),
                     d.get("mac"), d.get("vendor"), d.get("type"), d.get("os"), "online" if d.get("online") else "offline",
                     ", ".join(str(p.get("port")) for p in ports[:12])])
    doc.table(["Name", "IP", "MAC", "Vendor", "Type", "OS guess", "Status", "Open ports"], rows, [3, 2, 3, 3, 2, 3, 1.5, 3])
    return doc


def build_threats(s: dict, local: dict | None, hours: int) -> Doc:
    doc = Doc("Threats at the router", f"Attacks from the internet seen at your router, {hours_label(hours)}.")
    total, blocked = s.get("total", 0), s.get("blocked", 0)
    doc.kpi("Attacks", f"{total:,}").kpi("Attacking IPs", f"{s.get('unique', 0):,}").kpi("Countries", s.get("countries_n", 0))
    doc.kpi("Blocked at router", _pct(blocked, total), "good").kpi("Reached your network", f"{max(0, total - blocked):,}", _tone(total - blocked, 1, 0))
    doc.h("Where attacks came from")
    doc.table(["Country", "Attacks"], _countries(s.get("countries", [])[:15]), [4, 1])
    doc.h("Most targeted ports")
    doc.table(["Port", "Service", "Attacks"], [[p.get("port"), p.get("service"), f"{p.get('count', 0):,}"] for p in s.get("ports", [])[:15]], [1, 3, 1])
    reached = [t for t in s.get("targets", []) if t.get("allowed")]
    doc.h("Devices that were reached")
    doc.table(["Device", "Address", "Type", "Attempts", "Allowed through"],
              [[t.get("name"), t.get("lan"), t.get("type"), t.get("count"), t.get("allowed")] for t in s.get("targets", [])[:25]], [3, 2, 2, 1, 1],
              empty="No attacks were aimed at devices on your network.")
    if reached:
        doc.note("Attempts that were allowed through the router deserve a look: check that those devices are patched and need to be reachable.")
    doc.h("Top attacking addresses")
    doc.table(["Address", "Country", "City", "Attempts", "Services", "Note"],
              [[a.get("ip"), a.get("country"), a.get("city"), f"{a.get('count', 0):,}", ", ".join(a.get("services") or []),
                (a.get("tag") or {}).get("label", "") if isinstance(a.get("tag"), dict) else ""] for a in s.get("attackers", [])[:40]],
              [2.5, 2, 2, 1.2, 3, 2.5])
    doc.h("Attack signatures")
    doc.table(["Signature", "Hits", "Sources"], [[g.get("name"), g.get("count"), g.get("ips")] for g in s.get("signatures", [])[:25]], [6, 1, 1],
              empty="No signature matches were recorded.")
    ev = (local or {}).get("events") or []
    doc.h("Alerts from inside the network")
    doc.table(["When", "Source", "Kind", "Severity", "Target", "Detail"],
              [[when(e.get("t")), e.get("src"), e.get("kind"), e.get("severity"), e.get("target"), e.get("detail")] for e in ev[:60]],
              [2, 2, 2, 1, 2, 4], empty="No local network alerts were recorded.")
    return doc


def build_dns(s: dict, hours: int) -> Doc:
    doc = Doc("DNS activity", f"What devices looked up, {hours_label(hours)}.")
    if not s.get("enabled", True):
        doc.p("DNS monitoring is not set up, so there is nothing to report. Connect a DNS source from the DNS tab.")
        return doc
    total, blocked = s.get("total", 0), s.get("blocked", 0)
    doc.kpi("Lookups", f"{total:,}").kpi("Blocked", _pct(blocked, total), "good").kpi("Distinct domains", f"{s.get('domains', 0):,}")
    doc.kpi("Known-malware lookups", len(s.get("malware", [])), _tone(len(s.get("malware", [])), 1, 0))
    if s.get("malware"):
        doc.h("Devices that looked up known-malicious domains")
        doc.table(["Device", "Address", "Domain", "Lookups", "Last seen"],
                  [[m.get("name"), m.get("ip"), inert(m.get("domain")), m.get("count"), when(m.get("last"))] for m in s["malware"]], [3, 2, 4, 1, 2])
        doc.note("A device that asks for a known-malicious domain may be infected, or may have been tricked into a link. Check it first.")
    doc.h("Busiest clients")
    doc.table(["Device", "Address", "Lookups", "Blocked", "Domains"],
              [[c.get("name"), c.get("ip"), f"{c.get('count', 0):,}", c.get("blocked"), c.get("domains")] for c in s.get("clients", [])[:30]], [3, 2, 1, 1, 1])
    doc.h("Most requested domains")
    doc.table(["Domain", "Lookups", "Clients", "Flag"], [[d.get("domain"), f"{d.get('count', 0):,}", d.get("clients"), "malware list" if d.get("bad") else ""]
                                                         for d in s.get("top", [])[:30]], [6, 1, 1, 2])
    doc.h("Most blocked domains")
    doc.table(["Domain", "Blocked", "Clients"], [[d.get("domain"), f"{d.get('count', 0):,}", d.get("clients")] for d in s.get("top_blocked", [])[:30]], [6, 1, 1])
    return doc


def build_vulns(s: dict) -> Doc:
    t = s.get("totals", {})
    doc = Doc("Vulnerabilities", "Known flaws in the software LanPulse found on your devices (NVD, CISA KEV, Metasploit, Exploit-DB).")
    doc.kpi("Distinct CVEs", t.get("cves", 0)).kpi("Critical", t.get("critical", 0), _tone(t.get("critical", 0), 1, 0))
    doc.kpi("Actively exploited", t.get("kev", 0), _tone(t.get("kev", 0), 1, 0)).kpi("With public exploit", t.get("exploits", 0), _tone(t.get("exploits", 0), 99, 0))
    doc.kpi("Confirmed by a safe check", t.get("confirmed", 0)).kpi("Devices scanned", f"{t.get('scanned', 0)} of {t.get('devices', 0)}")
    doc.p("Matching is by version number. Software that your operating system patched without changing the version can still be listed.")
    doc.h("Fix these first")
    rows = []
    for f in s.get("fix", [])[:40]:
        top = f.get("top") or {}
        rows.append([f.get("name"), f.get("ip"), f"{f.get('software')}:{f.get('port')}", f.get("count"), f.get("max"),
                     "yes" if f.get("kev") else "", top.get("cve"), top.get("desc")])
    doc.table(["Device", "IP", "Software", "CVEs", "Worst CVSS", "Exploited", "Top CVE", "Description"], rows, [2.5, 2, 3, 1, 1.2, 1.3, 2.3, 6],
              empty="No vulnerabilities were matched.")
    doc.h("Devices ranked by risk")
    doc.table(["Device", "IP", "Type", "CVEs", "Critical", "High", "Exploited", "Exploits", "Confirmed"],
              [[d.get("name"), d.get("ip"), d.get("type"), d.get("count"), d.get("critical"), d.get("high"), d.get("kev"), d.get("exploits"), d.get("confirmed")]
               for d in sorted(s.get("devices", []), key=lambda d: (-(d.get("kev") or 0), -(d.get("critical") or 0), -(d.get("count") or 0)))],
              [3, 2, 2, 1, 1, 1, 1.2, 1.2, 1.3], empty="No devices have been scanned for vulnerabilities yet.")
    if s.get("config"):
        doc.h("Configuration findings")
        doc.table(["Device", "IP", "Level", "Finding"], [[c.get("name"), c.get("ip"), c.get("level"), c.get("text")] for c in s["config"]], [3, 2, 1, 8])
    return doc


def build_services(s: dict, suggestions: list | None = None) -> Doc:
    doc = Doc("Services and uptime", "Availability checks for the services you asked LanPulse to watch.")
    doc.kpi("Checks", s.get("total", 0)).kpi("Up", s.get("up", 0), "good").kpi("Down", s.get("down", 0), _tone(s.get("down", 0), 1, 0))
    rows = []
    for c in s.get("checks", []):
        target = f"{c.get('target')}:{c.get('port')}" if c.get("type") == "tcp" else c.get("target")
        rows.append([c.get("name"), c.get("type"), target, "up" if c.get("up") is True else "DOWN" if c.get("up") is False else "unknown",
                     f"{c['up24']}%" if c.get("up24") is not None else "-", f"{c['up7']}%" if c.get("up7") is not None else "-",
                     f"{c['avg_ms']} ms" if c.get("avg_ms") is not None else "-", c.get("err")])
    doc.h("Service status")
    doc.table(["Service", "Type", "Target", "Now", "Uptime 24 h", "Uptime 7 d", "Avg latency", "Last error"], rows, [3, 1, 3, 1, 1.4, 1.4, 1.4, 3],
              empty="No service checks are configured.")
    inc = [[c.get("name"), when(i.get("down")), when(i.get("up")) if i.get("up") else "still down", span((i.get("up") or time.time()) - (i.get("down") or 0)), i.get("err")]
           for c in s.get("checks", []) for i in (c.get("incidents") or [])]
    if inc:
        doc.h("Recent incidents")
        doc.table(["Service", "Went down", "Recovered", "Duration", "Error"], inc, [3, 2, 2, 1.5, 4])
    if suggestions:
        doc.h("Suggested checks")
        doc.bullets(f"{x.get('name')}: {x.get('type')} {x.get('target')}" + (f":{x['port']}" if x.get("port") else "") for x in suggestions)
    return doc


def build_redteam(devices: list[dict], results: dict, helpers) -> Doc:
    """helpers is the redteam module (default_cred_services, _techs_for_device) so this stays testable."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    doc = Doc("Red Team findings", "An attacker's-eye view built from LanPulse's own scan data. LanPulse runs no exploits.")
    allf = [(d, f) for d in devices for f in results.get(d.get("id"), [])]
    cves = {f.get("cve") for _, f in allf}
    doc.kpi("Hosts with findings", sum(1 for d in devices if results.get(d.get("id")) or d.get("ports")))
    doc.kpi("Vulnerabilities", len(cves)).kpi("Actively exploited", len({f["cve"] for _, f in allf if f.get("kev")}), "bad" if any(f.get("kev") for _, f in allf) else "good")
    doc.kpi("With a Metasploit module", len({f["cve"] for _, f in allf if f.get("msf")}), "warn" if any(f.get("msf") for _, f in allf) else "good")
    rows, techs = [], {}
    for d in devices:
        fs = results.get(d.get("id"), [])
        try:
            dc = helpers.default_cred_services(d)
            tl = helpers._techs_for_device(d, fs)
        except Exception:
            dc, tl = [], []
        for t in tl:
            key = (t.get("id"), t.get("name"), t.get("tactic"))
            techs.setdefault(key, []).append(d.get("name") or d.get("ip"))
        if fs or dc:
            rows.append([d.get("name") or d.get("hostname") or d.get("ip"), d.get("ip"), d.get("type"), len(d.get("ports") or []), len(fs),
                         sum(1 for f in fs if f.get("sev") in ("critical", "high")), sum(1 for f in fs if f.get("kev")),
                         ", ".join(x.get("service", "") for x in dc)])
    doc.h("Hosts")
    doc.table(["Host", "IP", "Type", "Open ports", "CVEs", "Critical/High", "Exploited", "Default-login services"], rows, [3, 2, 2, 1, 1, 1.4, 1.3, 3],
              empty="No findings. Run port and vulnerability scans first.")
    doc.h("Top vulnerabilities")
    top = sorted(allf, key=lambda df: (not df[1].get("kev"), order.get(df[1].get("sev"), 4), -(df[1].get("score") or 0)))[:100]
    doc.table(["CVE", "CVSS", "Severity", "Host", "Software", "Flags", "Description"],
              [[f.get("cve"), f.get("score") or "-", f.get("sev"), d.get("name") or d.get("ip"), f"{f.get('software')}:{f.get('port')}",
                " ".join(x for x, on in (("KEV", f.get("kev")), ("MSF", f.get("msf")), ("EDB", f.get("edb"))) if on), (f.get("desc") or "")[:220]] for d, f in top],
              [2, 1, 1.3, 2.5, 3, 1.3, 7], empty="No vulnerabilities were matched.")
    doc.h("MITRE ATT&CK techniques that apply")
    doc.table(["Technique", "Name", "Tactic", "Hosts"], [[k[0], k[1], k[2], ", ".join(sorted(set(map(str, v)))[:6])] for k, v in sorted(techs.items(), key=lambda kv: (str(kv[0][2]), str(kv[0][0])))],
              [1.5, 4, 2, 5], empty="No techniques map to the current findings.")
    doc.note("ATT&CK is a trademark of The MITRE Corporation. Use this report only for authorised testing of your own network.")
    return doc


def _intro_hp(doc: Doc, hours: int, extra: str = ""):
    doc.subtitle = f"{doc.subtitle} Period: {hours_label(hours)}. {extra}".strip()


def build_honeypot(s: dict, hours: int) -> Doc:
    doc = Doc("Honeypot attacks", "Hits on the decoy services. No real device should ever touch them, so each hit is a warning sign.")
    _intro_hp(doc, hours)
    t = s.get("totals", {})
    doc.kpi("Hits", f"{t.get('hits', 0):,}").kpi("Attacking addresses", t.get("attackers", 0)).kpi("From inside the LAN", t.get("internal", 0), _tone(t.get("internal", 0), 1, 0))
    doc.kpi("From the internet", t.get("external", 0)).kpi("Credentials tried", t.get("creds", 0))
    if t.get("internal"):
        doc.h("Needs attention: hits from inside your network")
        doc.p("A device on your own network touched a decoy. That usually means it is infected or someone is scanning from inside. These sources:")
        doc.table(["Address", "Hits", "Services", "First", "Last"],
                  [[a.get("ip"), a.get("hits"), ", ".join(sorted(x for x in a.get("services", []) if x)), when(a.get("first")), when(a.get("last"))]
                   for a in s.get("attackers", []) if a.get("internal")], [2, 1, 4, 2, 2])
    doc.h("Hits by service")
    doc.table(["Service", "Hits"], [[b.get("label") or b.get("service"), f"{b.get('count', 0):,}"] for b in s.get("by_service", [])], [4, 1])
    doc.h("Where attackers came from")
    doc.table(["Country", "Hits", "Addresses"], [[c.get("country") or c.get("iso"), c.get("hits"), c.get("ips")] for c in s.get("countries", [])], [4, 1, 1])
    doc.h("Most active attackers")
    doc.table(["Address", "Hits", "Internal", "Services", "First seen", "Last seen"],
              [[a.get("ip"), a.get("hits"), "yes" if a.get("internal") else "", ", ".join(sorted(x for x in a.get("services", []) if x)), when(a.get("first")), when(a.get("last"))]
               for a in s.get("attackers", [])], [2, 1, 1, 4, 2, 2])
    doc.h("Credentials attackers tried")
    doc.table(["Login attempted", "Times"], [[inert(c.get("cred")), c.get("count")] for c in s.get("creds", [])], [5, 1])
    doc.h("Most tried usernames and passwords")
    doc.table(["Username", "Times"], [[inert(u.get("v")), u.get("count")] for u in s.get("usernames", [])], [5, 1])
    doc.table(["Password", "Times"], [[inert(u.get("v")), u.get("count")] for u in s.get("passwords", [])], [5, 1])
    doc.h("Most recent hits")
    doc.table(["When", "Source", "Service", "Port", "Internal", "Detail"],
              [[when(h.get("t")), h.get("ip"), h.get("service"), h.get("port"), "yes" if h.get("internal") else "", inert(h.get("creds") or h.get("data") or "", 120)] for h in s.get("recent", [])],
              [2, 2, 1.5, 1, 1, 5])
    return doc


def build_sessions(sess: dict, hours: int, detail=None) -> Doc:
    rows = sess.get("sessions", [])
    doc = Doc("Captured sessions", "Attacker sessions recorded by Cowrie sensors.")
    _intro_hp(doc, hours)
    doc.kpi("Sessions", f"{sess.get('total', len(rows)):,}").kpi("Logged in", sum(1 for r in rows if r.get("logged_in")), _tone(sum(1 for r in rows if r.get("logged_in")), 99, 0))
    doc.kpi("Ran commands", sum(1 for r in rows if r.get("commands"))).kpi("Dropped files", sum(1 for r in rows if r.get("files")), _tone(sum(1 for r in rows if r.get("files")), 99, 0))
    doc.kpi("Highest score", max((r.get("score", 0) for r in rows), default=0))
    doc.h("Sessions")
    doc.table(["Started", "Source", "Country", "Sensor", "Service", "Length", "Logins", "Cmds", "Files", "Score", "Behaviour"],
              [[when(r.get("start")), r.get("ip"), r.get("country"), r.get("sensor"), f"{r.get('proto')}:{r.get('port')}", span(r.get("duration")),
                ("success" if r.get("logged_in") else r.get("logins")), r.get("commands"), r.get("files"), r.get("score"), ", ".join(r.get("tags") or [])] for r in rows],
              [2, 2, 1.6, 1.6, 1.4, 1.1, 1, 0.8, 0.8, 0.9, 4])
    if detail:
        top = sorted(rows, key=lambda r: -(r.get("score") or 0))[:MAX_SESSION_DETAILS]
        for r in top:
            d = detail(r.get("id")) or {}
            tl = d.get("timeline") or []
            if not tl:
                continue
            doc.h(f"Attack timeline: {r.get('ip')} at {when(r.get('start'))} (score {r.get('score')})")
            doc.table(["Stage", "What happened", "Evidence"], [[x.get("stage"), inert(x.get("summary")), inert(x.get("evidence") or "", 160)] for x in tl[:40]], [2, 5, 5])
    doc.note("Command evidence is shown as text only. Nothing an attacker sent was run.")
    return doc


def build_attackers(p: dict, hours: int) -> Doc:
    rows = p.get("profiles") or p.get("attackers") or []
    doc = Doc("Attacker profiles", "Behaviour per source address. This groups by address; it does not identify a person.")
    _intro_hp(doc, hours)
    doc.kpi("Source addresses", len(rows)).kpi("Logged in", sum(1 for r in rows if r.get("successful_logins")), _tone(sum(1 for r in rows if r.get("successful_logins")), 99, 0))
    doc.kpi("Dropped files", sum(1 for r in rows if r.get("files"))).kpi("Highest score", max((r.get("max_score", 0) for r in rows), default=0))
    doc.h("Profiles, highest risk first")
    doc.table(["Address", "Country", "Network", "Sessions", "Logins ok", "Commands", "Files", "Max score", "Behaviour", "First", "Last"],
              [[r.get("ip"), r.get("country"), r.get("org"), r.get("sessions"), r.get("successful_logins"), r.get("commands"), r.get("files"), r.get("max_score"),
                ", ".join(t.get("name", "") for t in (r.get("tags") or [])[:4]), when(r.get("first_seen")), when(r.get("last_seen"))] for r in rows],
              [2, 1.5, 2.5, 1, 1, 1.2, 0.8, 1, 3.5, 2, 2])
    return doc


def build_campaigns(c: dict, hours: int) -> Doc:
    rows = c.get("campaigns") or []
    doc = Doc("Campaigns and shared evidence", "Indicators seen from more than one source. Shared evidence suggests common tools or infrastructure; it does not prove one operator.")
    _intro_hp(doc, hours)
    doc.kpi("Shared indicators", len(rows)).kpi("High confidence", sum(1 for r in rows if r.get("confidence") == "high"), _tone(sum(1 for r in rows if r.get("confidence") == "high"), 99, 0))
    doc.kpi("Sources involved", len({ip for r in rows for ip in r.get("source_ips", [])}))
    doc.h("Shared indicators")
    doc.table(["Kind", "Value", "Confidence", "Sources", "Sensors", "Sessions", "Samples", "First", "Last"],
              [[r.get("kind"), inert(r.get("value")), r.get("confidence"), r.get("sources"), ", ".join(r.get("sensors") or []), r.get("sessions"), r.get("samples"),
                when(r.get("first_seen")), when(r.get("last_seen"))] for r in rows], [2.5, 5, 1.4, 1, 2, 1, 1, 2, 2], empty="No cross-source indicators were found in this period.")
    top = [r for r in rows if r.get("source_ips")][:15]
    if top:
        doc.h("Sources behind the strongest indicators")
        doc.table(["Indicator", "Source addresses"], [[f"{r.get('kind')}: {inert(r.get('value'), 60)}", ", ".join(r.get("source_ips", [])[:12])] for r in top], [4, 7])
    return doc


def build_malware(samples: dict, details: list[dict], yara: dict | None, hours: int) -> Doc:
    rows = samples.get("samples", [])
    doc = Doc("Malware samples and YARA", "Files attackers uploaded to the honeypot, analysed statically. None was run.")
    doc.kpi("Samples", f"{samples.get('total', len(rows)):,}").kpi("High score (60+)", sum(1 for r in rows if (r.get("score") or 0) >= 60), _tone(sum(1 for r in rows if (r.get("score") or 0) >= 60), 99, 0))
    doc.kpi("YARA matches", sum(1 for r in rows if r.get("yara_match_count")), _tone(sum(1 for r in rows if r.get("yara_match_count")), 99, 0))
    doc.kpi("Seen more than once", sum(1 for r in rows if (r.get("seen") or 0) > 1))
    if yara:
        doc.h("YARA engine")
        doc.kv([("Engine installed", "yes" if yara.get("available") else "no"), ("Rule files loaded", f"{yara.get('loaded', 0)} of {yara.get('files', 0)}"),
                ("Rule groups", yara.get("groups")), ("Package", (yara.get("managed") or {}).get("package")), ("Version", (yara.get("managed") or {}).get("version")),
                ("Rules updated", (yara.get("managed") or {}).get("updated_at"))])
        if yara.get("errors"):
            doc.bullets(yara["errors"][:10])
    doc.h("All captured samples")
    doc.table(["SHA-256", "Type", "Size", "Score", "Looks like", "YARA", "Seen", "First", "Last"],
              [[r.get("sha256"), r.get("type"), f"{(r.get('size') or 0):,}", r.get("score"), ", ".join(r.get("families") or []),
                (f"{r.get('yara_match_count')} match" + ("es" if r.get("yara_match_count") != 1 else "")) if r.get("yara_match_count") else r.get("yara_status"),
                r.get("seen"), when(r.get("first_seen")), when(r.get("last_seen"))] for r in rows],
              [6, 3, 1.4, 1.3, 3, 2.2, 1.2, 2.2, 2.2])
    for a in details:
        sha = a.get("sha256", "")
        doc.h(f"Sample {sha[:16]}  (score {a.get('score', 0)})")
        y = a.get("yara") or {}
        doc.kv([("SHA-256", sha), ("File type", a.get("type")), ("Size", f"{(a.get('size') or 0):,} bytes"), ("Entropy", a.get("entropy")),
                ("First / last seen", f"{when(a.get('first_seen'))} / {when(a.get('last_seen'))}"), ("Times captured", a.get("seen")),
                ("Saved as", inert(", ".join(a.get("names") or []))), ("Source addresses", ", ".join(a.get("ips") or [])[:300]),
                ("Looks like", ", ".join(a.get("families") or [])), ("Behaviour tags", ", ".join(a.get("tags") or []))])
        if a.get("score_evidence"):
            doc.table(["Why this score", "Points", "Source", "Explanation"], [[e.get("label"), f"+{e.get('points')}", e.get("source"), e.get("explanation")] for e in a["score_evidence"]], [3, 1, 2, 6])
        beh = (a.get("script_analysis") or {}).get("behaviors") or []
        if beh:
            doc.table(["Behaviour", "ATT&CK", "Confidence", "Example"], [[b.get("label"), b.get("attack"), b.get("confidence"),
                      inert((b.get("evidence") or [{}])[0].get("text") or "", 140)] for b in beh], [4, 2, 1.4, 6])
        iocs = a.get("iocs") or {}
        ind = [x.get("defanged") or x.get("value") for k in ("urls", "ips", "domains") for x in (iocs.get(k) or []) if isinstance(x, dict)]
        ind += [x if isinstance(x, str) else str(x) for k in ("irc_servers", "irc_channels", "emails", "wallets") for x in (iocs.get(k) or [])]
        if ind:
            doc.p("Indicators found inside it (defanged): " + ", ".join(ind[:30]))
        if y.get("matches"):
            doc.table(["YARA rule", "Rule file", "Tags", "Description"], [[m.get("rule"), m.get("file"), ", ".join(m.get("tags") or []), m.get("description")] for m in y["matches"][:20]], [3, 3, 2, 6])
        elif y.get("scan_status"):
            doc.note(f"YARA scan status: {y.get('scan_status')}; no rule matched. No match does not prove the file is safe.")
        for n in (a.get("notes") or [])[:4]:
            doc.note(n)
    if samples.get("total", 0) > len(details):
        doc.note(f"Full detail is shown for the {len(details)} highest-scoring samples. The rest are in the table above and in LanPulse.")
    return doc


def build_sensors(sensors: list[dict]) -> Doc:
    doc = Doc("Honeypot sensors", "Cowrie honeypot sensors enrolled with this LanPulse.")
    doc.kpi("Sensors", len(sensors)).kpi("Connected", sum(1 for s in sensors if s.get("state") == "connected"), "good")
    doc.kpi("Silent", sum(1 for s in sensors if s.get("state") == "silent"), _tone(sum(1 for s in sensors if s.get("state") == "silent"), 1, 0))
    doc.table(["Name", "Kind", "State", "Created", "Last heard", "Last address", "Sessions", "Files"],
              [[s.get("name"), s.get("kind"), s.get("state"), when(s.get("created")), when(s.get("last_seen")), s.get("last_ip"), s.get("sessions"), s.get("files")] for s in sensors],
              [2, 1.5, 1.2, 2, 2, 2, 1, 1], empty="No sensors are enrolled yet.")
    return doc


def build_executive(parts: dict, hours: int) -> Doc:
    """One page of what matters, drawn from the other tabs' data."""
    posture, vs, th, dn, sv, hp = (parts.get(k) or {} for k in ("posture", "vulns", "threats", "dns", "services", "honeypot"))
    snap, ses, smp = parts.get("snapshot") or {}, parts.get("sessions") or {}, parts.get("samples") or {}
    doc = Doc("Executive security report", f"A summary of the network's security across every LanPulse tab. Period: {hours_label(hours)}.")
    score = posture.get("score")
    doc.kpi("Security score", f"{score} ({posture.get('grade')})" if score is not None else "-", "good" if (score or 0) >= 80 else "warn" if (score or 0) >= 60 else "bad")
    devs = [d for d in snap.get("devices", []) if not d.get("is_self")]
    doc.kpi("Devices", f"{sum(1 for d in devs if d.get('online'))} online of {len(devs)}")
    t = vs.get("totals", {})
    doc.kpi("Actively exploited flaws", t.get("kev", 0), _tone(t.get("kev", 0), 1, 0))
    doc.kpi("Attacks at the router", f"{th.get('total', 0):,}").kpi("Honeypot hits", f"{(hp.get('totals') or {}).get('hits', 0):,}")
    doc.kpi("Malware samples", smp.get("total", 0))
    att = []
    if (hp.get("totals") or {}).get("internal"):
        att.append(f"{hp['totals']['internal']} honeypot hit(s) came from inside the network: a device may be compromised.")
    if dn.get("malware"):
        att.append(f"{len(dn['malware'])} device lookup(s) of known-malicious domains were seen in DNS.")
    if t.get("kev"):
        att.append(f"{t['kev']} actively exploited vulnerability(ies) were found on your devices.")
    if t.get("critical"):
        att.append(f"{t['critical']} critical vulnerability(ies) are open.")
    if sv.get("down"):
        att.append(f"{sv['down']} watched service(s) are down.")
    reached = sum(x.get("allowed", 0) for x in th.get("targets", []))
    if reached:
        att.append(f"{reached} attack attempt(s) were allowed through the router to devices.")
    if sum(1 for r in ses.get("sessions", []) if r.get("logged_in")):
        att.append("Attackers logged in to a honeypot sensor; review the captured sessions.")
    doc.h("Needs attention")
    if att:
        doc.bullets(att)
    else:
        doc.p("Nothing urgent was found in the data LanPulse holds for this period.")
    if posture.get("fixes"):
        doc.h("Biggest fixes")
        doc.bullets(f"{f.get('text')} (+{f.get('points')} points)" for f in posture["fixes"][:6])
    doc.h("Threat summary")
    doc.kv([("Attacks at the router", f"{th.get('total', 0):,} from {th.get('unique', 0):,} addresses in {th.get('countries_n', 0)} countries"),
            ("Blocked at the router", _pct(th.get("blocked", 0), th.get("total", 0))),
            ("DNS", f"{dn.get('total', 0):,} lookups, {_pct(dn.get('blocked', 0), dn.get('total', 0))} blocked, {len(dn.get('malware', []))} malicious-domain lookup(s)" if dn.get("enabled", True) else "not set up"),
            ("Services", f"{sv.get('up', 0)} up, {sv.get('down', 0)} down of {sv.get('total', 0)}")])
    if th.get("countries"):
        doc.table(["Top attack origins", "Attacks"], _countries(th["countries"][:6]), [4, 1])
    doc.h("Honeypot summary")
    ht = hp.get("totals") or {}
    doc.kv([("Decoy hits", f"{ht.get('hits', 0):,} from {ht.get('attackers', 0)} addresses ({ht.get('internal', 0)} internal)"),
            ("Captured sessions", f"{ses.get('total', 0):,}"), ("Malware samples", f"{smp.get('total', 0):,}, {sum(1 for r in smp.get('samples', []) if (r.get('score') or 0) >= 60)} scoring 60 or more")])
    doc.h("Vulnerability summary")
    doc.kv([("Distinct CVEs", t.get("cves", 0)), ("Critical", t.get("critical", 0)), ("With a public exploit", t.get("exploits", 0)),
            ("Devices scanned", f"{t.get('scanned', 0)} of {t.get('devices', 0)}")])
    doc.note("The other reports (one per tab) hold the detail behind each line.")
    return doc


# ---------------------------------------------------------------- gathering from the running app

def _safe(fn, *a, default=None, **k):
    try:
        return fn(*a, **k)
    except Exception:
        return {} if default is None else default


def gather(nm, kind: str, hours: int = 168) -> Doc:
    """Build one report from the live objects. Each source is read in its own try, so a broken source leaves a gap, not a failure."""
    import health as health_mod
    import posture as posture_mod
    import redteam
    if kind not in KINDS:
        raise KeyError(kind)
    hours = max(1, min(int(hours), 2160))
    day = max(1, min(hours, 720))
    ha = nm.honeyan
    if kind == "network":
        return build_network(nm.snapshot(), _safe(posture_mod.compute, nm), _safe(health_mod.build, nm))
    if kind == "threats":
        return build_threats(nm.threats.summary(day), _safe(nm.local.summary, day), day)
    if kind == "dns":
        return build_dns(nm.dns.summary(max(1, min(168, hours)), ""), max(1, min(168, hours)))
    if kind == "vulns":
        return build_vulns(nm.vulns.summary())
    if kind == "services":
        return build_services(nm.services.summary(), _safe(nm.services.suggestions, default=[]))
    if kind == "redteam":
        devs = [d for d in nm.devices.values() if not d.get("is_self")]
        return build_redteam(devs, nm.vulns.results, redteam)
    if kind == "honeypot":
        return build_honeypot(nm.honeypot.summary(hours), hours)
    if kind == "honeypot-sessions":
        return build_sessions(ha.sessions(hours, 400), hours, ha.session)
    if kind == "honeypot-attackers":
        return build_attackers(ha.attacker_profiles(hours, 400), hours)
    if kind == "honeypot-campaigns":
        return build_campaigns(ha.campaigns(hours), hours)
    if kind == "honeypot-malware":
        samples = ha.samples(2000)
        ranked = sorted(samples.get("samples", []), key=lambda r: (-(r.get("score") or 0), -(r.get("last_seen") or 0)))[:MAX_SAMPLE_DETAILS]
        details = [d for d in (_safe(ha.sample, r["sha256"], default=None) for r in ranked) if d]
        return build_malware(samples, details, _safe(ha.yara.status), hours)
    if kind == "honeypot-sensors":
        return build_sensors(ha.sensors())
    # executive
    return build_executive({
        "posture": _safe(posture_mod.compute, nm), "snapshot": nm.snapshot(), "vulns": _safe(nm.vulns.summary),
        "threats": _safe(nm.threats.summary, day), "dns": _safe(nm.dns.summary, max(1, min(168, hours)), ""),
        "services": _safe(nm.services.summary), "honeypot": _safe(nm.honeypot.summary, hours),
        "sessions": _safe(ha.sessions, hours, 400), "samples": _safe(ha.samples, 2000)}, hours)


def meta_for(nm, version: str) -> dict:
    net = getattr(nm, "net", {}) or {}
    return {"generated": time.strftime("%Y-%m-%d %H:%M %Z"), "version": version,
            "network": f"network {net.get('subnet', '')}".strip()}
