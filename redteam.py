# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Red-team / offensive-recon helpers. This module turns what LanPulse already discovered (open ports, service
versions, OS guesses, vulnerabilities) into the things a tester needs next:

  * MITRE ATT&CK mapping  - which techniques each exposure maps to, grouped by tactic.
  * Metasploit hand-off   - the `use` / `set RHOSTS` / `set RPORT` lines, and a resource script (.rc) you run
                            yourself in your own msfconsole. LanPulse never runs an exploit; it only writes the
                            commands, from module names it already identified (NVD/CISA/Metasploit metadata).
  * Nmap XML export       - the stored scan as an nmap XML file, to `db_import` into Metasploit or another tool.
  * Engagement report     - an HTML report of findings per host (exposures, ATT&CK, vulnerabilities, remediation).

Everything here is built from data already in memory. It opens no new connections to any device, so it adds no
scanning load and no new attack surface against the targets.
"""
from __future__ import annotations

import html
import ipaddress
import re
import time
from xml.sax.saxutils import escape as xml_escape, quoteattr

# ATT&CK technique -> (id, name, tactic). One source of truth so the report and the view agree.
T = {
    "pubapp": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "extremote": ("T1133", "External Remote Services", "Initial Access"),
    "rdp": ("T1021.001", "Remote Services: RDP", "Lateral Movement"),
    "smb": ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "ssh": ("T1021.004", "Remote Services: SSH", "Lateral Movement"),
    "vnc": ("T1021.005", "Remote Services: VNC", "Lateral Movement"),
    "sniff": ("T1040", "Network Sniffing", "Credential Access"),
    "brute": ("T1110", "Brute Force", "Credential Access"),
    "defcred": ("T1078.001", "Valid Accounts: Default Accounts", "Initial Access"),
    "netshare": ("T1135", "Network Share Discovery", "Discovery"),
    "remsvcdisc": ("T1046", "Network Service Discovery", "Discovery"),
    "db": ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "web": ("T1505.003", "Server Software Component: Web Shell", "Persistence"),
    "unpatched": ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
}

# Short, offline summaries for each technique LanPulse maps (so the detail panel works without internet).
# These are condensed from MITRE ATT&CK; the technique links go to attack.mitre.org for the full text.
TECH_INFO = {
    "T1190": ("Adversaries exploit a weakness in an internet- or network-facing application to run code or gain access.",
              "Watch for unusual requests, new processes spawned by the service, and crashes in exposed apps.",
              "Patch promptly, put exposed services behind a WAF/reverse proxy, and segment them from the rest of the network."),
    "T1133": ("Adversaries use external-facing remote services (VPN, RDP, SSH gateways) to access or persist on a network.",
              "Review remote-access logs for logins from new locations, times or failed-then-success patterns.",
              "Require MFA, limit which addresses can reach remote services, and disable services you don't use."),
    "T1021.001": ("Adversaries use RDP to move to and control other hosts with valid credentials.",
                  "Alert on RDP logins between internal hosts and on new accounts using RDP.",
                  "Restrict RDP to a jump host, require MFA, and never expose RDP to the internet."),
    "T1021.002": ("Adversaries use SMB and Windows admin shares (C$, ADMIN$) to move between Windows hosts.",
                  "Watch for access to admin shares and remote service creation across hosts.",
                  "Require SMB signing, limit admin-share access, and segment Windows hosts."),
    "T1021.004": ("Adversaries use SSH to move to and control other hosts, often with stolen keys or passwords.",
                  "Alert on SSH logins between internal hosts and on new or unusual key use.",
                  "Use key-based auth with passphrases, restrict source addresses, and rotate keys."),
    "T1021.005": ("Adversaries use VNC to remotely view and control a host's desktop.",
                  "Watch for VNC connections, especially unencrypted ones or from new sources.",
                  "Disable VNC where unneeded, require strong auth and a tunnel, and restrict source addresses."),
    "T1040": ("Adversaries capture network traffic to harvest credentials and information, easiest on plaintext protocols.",
              "Hard to detect passively; look for interfaces in promiscuous mode and rogue devices.",
              "Use encrypted protocols (SSH, HTTPS) instead of telnet/FTP/HTTP, and segment the network."),
    "T1110": ("Adversaries guess passwords by trying many combinations (brute force, spraying, credential stuffing).",
              "Alert on bursts of failed logins and on one source trying many accounts.",
              "Enforce lockouts, strong passwords and MFA, and rate-limit authentication."),
    "T1078.001": ("Adversaries use default accounts and factory credentials that were never changed.",
                  "Check for logins using known default usernames and for devices still on factory settings.",
                  "Change every default credential, disable unused default accounts, and audit regularly."),
    "T1135": ("Adversaries enumerate network shares to find data and places to move to.",
              "Watch for one host querying many shares or SMB/NFS enumeration in a short window.",
              "Limit share permissions, require authentication, and monitor share access."),
    "T1046": ("Adversaries scan for listening services to find what can be attacked.",
              "Detect port scans: one source touching many ports or hosts quickly (LanPulse already flags these).",
              "Reduce exposed services, segment the network, and alert on scanning."),
    "T1210": ("Adversaries exploit a vulnerability in a remote service to run code or move laterally.",
              "Watch for exploit signatures, service crashes and unexpected child processes.",
              "Patch known-vulnerable services, segment them, and remove ones you don't need."),
    "T1505.003": ("Adversaries install a web shell on a web server to keep access and run commands.",
                  "Look for new or modified files in web roots and web processes spawning shells.",
                  "Patch web apps, restrict write access to web roots, and monitor for new files."),
}

# Open port -> technique keys. Plaintext protocols also expose credentials to sniffing.
PORT_TECH = {
    21: ["sniff", "brute"], 23: ["sniff", "brute"], 25: ["remsvcdisc"], 3389: ["rdp", "brute"],
    445: ["smb", "netshare"], 139: ["smb", "netshare"], 135: ["smb"], 5900: ["vnc", "brute"], 5901: ["vnc"],
    22: ["ssh", "brute"], 512: ["extremote"], 513: ["extremote"], 514: ["extremote"], 1524: ["extremote"],
    3306: ["db", "brute"], 5432: ["db", "brute"], 1433: ["db", "brute"], 27017: ["db"], 6379: ["db"],
    80: ["web"], 443: ["web"], 8080: ["web"], 8443: ["web"], 2049: ["netshare"], 111: ["remsvcdisc"],
    161: ["remsvcdisc"], 69: ["sniff"], 110: ["sniff", "brute"], 143: ["sniff", "brute"],
}

# Services that commonly ship with known default credentials (flagged only - never tried).
DEFAULT_CRED_HINTS = re.compile(
    r"tomcat|jboss|jenkins|grafana|pi-?hole|phpmyadmin|webmin|router|camera|hikvision|dahua|ipcam|printer|"
    r"ilo|idrac|ipmi|mongodb|redis|elasticsearch|memcached|vnc|telnet|ftp", re.I)

MODULE_RE = re.compile(r"^(?:auxiliary|exploit|post|encoder|nop|payload)/[\w./-]{1,160}$")


PROTO_NAMES = {21: "FTP", 23: "Telnet", 25: "SMTP", 3389: "RDP", 445: "SMB", 139: "NetBIOS", 135: "MSRPC",
               5900: "VNC", 5901: "VNC", 22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
               27017: "MongoDB", 6379: "Redis", 80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
               2049: "NFS", 111: "RPC", 161: "SNMP", 110: "POP3", 143: "IMAP", 69: "TFTP",
               512: "rexec", 513: "rlogin", 514: "rsh", 1524: "shell"}


def _techs_for_device(d: dict, findings: list[dict] | None = None) -> list[dict]:
    """Techniques this device's exposures map to, each with the evidence that triggered it (why)."""
    findings = findings if findings is not None else d.get("findings_vuln") or []
    reasons: dict[str, list[str]] = {}

    def add(key, why):
        tid = T.get(key)
        if tid:
            reasons.setdefault(tid[0], [])
            if why and why not in reasons[tid[0]]:
                reasons[tid[0]].append(why)

    for p in d.get("ports", []):
        port = p.get("port")
        label = f"{port}/tcp {PROTO_NAMES.get(port, p.get('service') or 'service')}"
        for key in PORT_TECH.get(port, []):
            add(key, f"{label} open")
    for f in d.get("findings", []):
        txt = (f.get("text") or "").lower()
        if "telnet" in txt or "plain text" in txt:
            add("sniff", "plaintext service exposes credentials"); add("brute", "plaintext login service")
        if "vnc" in txt:
            add("vnc", "VNC remote control open")
        if "windows" in txt and ("end of" in txt or "no longer" in txt or "unsupported" in txt):
            add("unpatched", "end-of-life Windows")
    for f in findings:
        if f.get("kev"):
            add("pubapp", f"{f.get('cve')} is actively exploited (CISA KEV)"); add("unpatched", f"{f.get('cve')} (KEV)")
        elif f.get("msf"):
            add("pubapp", f"{f.get('cve')} has a Metasploit module"); add("unpatched", f"{f.get('cve')} (exploit available)")
    if default_cred_services(d):
        add("defcred", "service commonly ships with default credentials")
    out = []
    for tid, why in reasons.items():
        info = next((v for v in T.values() if v[0] == tid), None)
        if info:
            out.append({"id": tid, "name": info[1], "tactic": info[2], "why": why[:4],
                        "desc": (TECH_INFO.get(tid) or ("", "", ""))[0],
                        "detect": (TECH_INFO.get(tid) or ("", "", ""))[1],
                        "mitigate": (TECH_INFO.get(tid) or ("", "", ""))[2]})
    return out


CLEARTEXT = {21: "FTP", 23: "Telnet", 80: "HTTP (if it serves a login)", 110: "POP3", 143: "IMAP",
             161: "SNMP", 69: "TFTP", 512: "rexec", 513: "rlogin", 514: "rsh"}


def cleartext_exposures(d: dict) -> list[dict]:
    """Open services that send credentials or data in the clear, so a sniffer on the path could read them."""
    out = []
    for p in d.get("ports", []):
        if p.get("port") in CLEARTEXT:
            out.append({"port": p["port"], "proto": CLEARTEXT[p["port"]], "note": "credentials/data sent unencrypted"})
    return out


def exploitability(findings: list[dict], d: dict) -> tuple[int, str]:
    """A 0-100 'how easy to break in' score and a one-word band, from exploit availability and exposure.
    A planning aid, not a measurement."""
    kev = sum(1 for f in findings if f.get("kev"))
    msf = sum(1 for f in findings if f.get("msf"))
    score = min(60, kev * 30 + msf * 15)
    score += min(20, 10 * len(cleartext_exposures(d)))
    score += min(10, 5 * len(default_cred_services(d)))
    if any(p.get("port") in (23, 445, 3389, 5900) for p in d.get("ports", [])):
        score += 10
    score = min(100, score)
    band = "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 15 else "low"
    return score, band


def default_cred_services(d: dict) -> list[dict]:
    """Services on this device that commonly ship with default logins. Flagged for manual checking - LanPulse
    never attempts a login."""
    out = []
    for p in d.get("ports", []):
        label = f"{p.get('product', '')} {p.get('service', '')}".strip()
        if DEFAULT_CRED_HINTS.search(f"{label} {d.get('vendor', '')} {d.get('os', '')}"):
            out.append({"port": p.get("port"), "service": label or "unknown"})
    return out[:12]


def msf_lines(ip: str, port, module: str) -> list[str] | None:
    """The msfconsole commands for one module against one target. Returns None if anything doesn't validate -
    device-reported text never becomes a command."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not isinstance(module, str) or not MODULE_RE.match(module):
        return None
    lines = [f"use {module}", f"set RHOSTS {ip}"]
    try:
        if port and 0 < int(port) < 65536:
            lines.append(f"set RPORT {int(port)}")
    except (TypeError, ValueError):
        pass
    return lines


def device_targets(d: dict, findings: list[dict]) -> list[dict]:
    """Per-device Metasploit targets: each vulnerability finding that has a module, with ready-to-run commands."""
    ip = d.get("ip", "")
    out = []
    for f in findings:
        for mod in (f.get("msf") or [])[:3]:
            module = mod[0] if isinstance(mod, (list, tuple)) else mod
            lines = msf_lines(ip, f.get("port"), module)
            if lines:
                out.append({"cve": f.get("cve"), "software": f.get("software"), "port": f.get("port"),
                            "module": module, "name": mod[1] if isinstance(mod, (list, tuple)) and len(mod) > 1 else "",
                            "kev": bool(f.get("kev")), "commands": lines})
    # one row per module, worst (KEV) first
    seen, uniq = set(), []
    for t in sorted(out, key=lambda x: (not x["kev"], x["module"])):
        if t["module"] not in seen:
            seen.add(t["module"])
            uniq.append(t)
    return uniq[:60]


def resource_script(targets_by_device: list[tuple[dict, list[dict]]]) -> str:
    """A Metasploit resource script. Each target is set up in its own workspace block; the exploit line is left
    commented out, so running the script configures modules but never fires until you uncomment and run them."""
    out = ["# LanPulse Metasploit resource script",
           f"# Generated {time.strftime('%Y-%m-%d %H:%M')}. Run with:  msfconsole -r lanpulse.rc",
           "# LanPulse did not run anything. Each module below is pre-configured; the 'run' line is commented out.",
           "# Review every command, confirm the target is yours and in scope, then uncomment 'run' to fire it.",
           "# Only use this against systems you own or are explicitly authorised to test.", ""]
    n = 0
    for d, targets in targets_by_device:
        if not targets:
            continue
        out.append(f"# ===== {d.get('ip', '?')}  {d.get('name', '')} =====")
        for t in targets:
            out += t["commands"]
            out.append("# run")        # intentionally commented - you uncomment to execute
            out.append("")
            n += 1
    out.append(f"# {n} module(s) configured.")
    return "\n".join(out)


def _xml_port(p: dict) -> str:
    svc = p.get("service") or ""
    prod = p.get("sw") or ""
    ver = p.get("ver") or ""
    attrs = f'name={quoteattr(svc[:40])}'
    if prod:
        attrs += f' product={quoteattr(prod[:80])}'
    if ver:
        attrs += f' version={quoteattr(ver[:60])}'
    cpe = "".join(f"<cpe>{xml_escape(c)}</cpe>" for c in (p.get("cpe") or [])[:3] if isinstance(c, str))
    proto = p.get("proto") if p.get("proto") in ("tcp", "udp") else "tcp"
    try:
        portid = int(p.get("port"))
    except (TypeError, ValueError):
        return ""
    return (f'<port protocol="{proto}" portid="{portid}"><state state="open"/>'
            f'<service {attrs}>{cpe}</service></port>')


def nmap_xml(devices: list[dict]) -> str:
    """Rebuild the stored scan results as an nmap XML document (importable with Metasploit's db_import)."""
    now = int(time.time())
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<!DOCTYPE nmaprun>',
             f'<nmaprun scanner="nmap" args="LanPulse export" start="{now}" version="7.94" xmloutputversion="1.05">',
             '<scaninfo type="syn" protocol="tcp"/>']
    for d in devices:
        ip = d.get("ip", "")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        ports = "".join(x for x in (_xml_port(p) for p in d.get("ports", [])) if x)
        addr = f'<address addr={quoteattr(ip)} addrtype="ipv4"/>'
        if d.get("mac") and re.match(r"^[0-9A-Fa-f:]{17}$", d["mac"]):
            vendor = f' vendor={quoteattr((d.get("vendor") or "")[:60])}' if d.get("vendor") else ""
            addr += f'<address addr={quoteattr(d["mac"])} addrtype="mac"{vendor}/>'
        host = d.get("hostname") or d.get("name") or ""
        names = f'<hostnames><hostname name={quoteattr(host[:80])} type="user"/></hostnames>' if host else "<hostnames/>"
        osx = ""
        if d.get("os"):
            acc = int(d.get("os_accuracy") or 0)
            osx = f'<os><osmatch name={quoteattr(d["os"][:120])} accuracy="{acc}"/></os>'
        parts.append(f'<host><status state="up" reason="arp-response"/>{addr}{names}'
                     f'<ports>{ports}</ports>{osx}</host>')
    parts.append(f'<runstats><finished time="{now}" elapsed="0"/></runstats></nmaprun>')
    return "\n".join(parts)


def attack_rows(devices: list[dict], results: dict, kev: dict) -> dict:
    """Summary for the Red Team view: ATT&CK techniques across the network, grouped by tactic, plus per-device rows."""
    TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Discovery",
                    "Lateral Movement", "Credential Access"]
    by_tactic: dict[str, dict[str, dict]] = {}
    device_rows = []
    for d in devices:
        if d.get("is_self"):
            continue
        findings = results.get(d["id"], [])
        dc = default_cred_services(d)
        clear = cleartext_exposures(d)
        techs = _techs_for_device(d, findings)
        if not techs and not findings and not dc and not clear:
            continue
        targets = device_targets(d, findings)
        score, band = exploitability(findings, d)
        for t in techs:
            slot = by_tactic.setdefault(t["tactic"], {}).setdefault(t["id"], {
                "id": t["id"], "name": t["name"], "devices": 0, "desc": t["desc"], "detect": t["detect"],
                "mitigate": t["mitigate"], "hosts": [], "why": []})
            slot["devices"] += 1
            if d.get("name") or d.get("ip"):
                slot["hosts"].append(d.get("name") or d.get("ip"))
            for w in t["why"]:
                if w not in slot["why"]:
                    slot["why"].append(w)
        device_rows.append({"id": d["id"], "ip": d.get("ip"), "name": d.get("name") or d.get("hostname") or d.get("ip"),
                            "type": d.get("type", "unknown"), "techniques": techs, "modules": len(targets),
                            "exploitable": sum(1 for f in findings if f.get("msf")),
                            "kev": sum(1 for f in findings if f.get("kev")), "default_creds": len(dc),
                            "cleartext": len(clear), "score": score, "band": band})
    tactics = []
    for name in TACTIC_ORDER:
        if name in by_tactic:
            for slot in by_tactic[name].values():
                slot["hosts"] = sorted(set(slot["hosts"]))[:12]
                slot["why"] = slot["why"][:6]
            tactics.append({"tactic": name, "techniques": sorted(by_tactic[name].values(), key=lambda x: x["id"])})
    device_rows.sort(key=lambda r: (-r["score"], -r["kev"], -r["modules"]))
    return {"tactics": tactics, "devices": device_rows,
            "totals": {"techniques": sum(len(t["techniques"]) for t in tactics),
                       "targets": len(device_rows), "modules": sum(r["modules"] for r in device_rows)}}


def attack_layer(devices: list[dict], results: dict) -> dict:
    """A MITRE ATT&CK Navigator layer (v4.5). Load it at mitre-attack.github.io/attack-navigator to see your
    findings as the classic technique heatmap. Each technique is scored by how many hosts it maps to."""
    counts: dict[str, int] = {}
    comments: dict[str, set] = {}
    for d in devices:
        if d.get("is_self"):
            continue
        for t in _techs_for_device(d, results.get(d["id"], [])):
            counts[t["id"]] = counts.get(t["id"], 0) + 1
            comments.setdefault(t["id"], set()).add(d.get("name") or d.get("ip", "?"))
    mx = max(counts.values()) if counts else 1
    techniques = [{"techniqueID": tid, "score": n, "enabled": True,
                   "comment": f"{n} host(s): " + ", ".join(sorted(comments[tid])[:8])}
                  for tid, n in sorted(counts.items())]
    return {"name": "LanPulse findings", "domain": "enterprise-attack",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "description": "Techniques inferred by LanPulse from open ports, services and vulnerabilities on the local network.",
            "techniques": techniques,
            "gradient": {"colors": ["#fef3c7", "#f97316", "#b91c1c"], "minValue": 0, "maxValue": mx},
            "legendItems": [], "showTacticRowBackground": True, "tacticRowBackground": "#1f2a44",
            "selectTechniquesAcrossTactics": True, "sorting": 3}


def report_html(nm, results: dict, kev: dict, generated: str = "") -> str:
    """A self-contained engagement report of everything found, per host."""
    esc = html.escape
    devs = [d for d in nm.devices.values() if not d.get("is_self")]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    total_vulns = sum(len(v) for v in results.values())
    total_kev = len({f["cve"] for v in results.values() for f in v if f.get("kev")})
    exploitable = len({f["cve"] for v in results.values() for f in v if f.get("msf")})
    rows = []
    for d in sorted(devs, key=lambda d: ipaddress.ip_address(d["ip"]) if _isip(d["ip"]) else ipaddress.ip_address("255.255.255.255")):
        findings = sorted(results.get(d["id"], []), key=lambda f: sev_order.get(f.get("sev"), 4))
        dc = default_cred_services(d)
        techs = _techs_for_device(d, findings)
        ports = sorted(d.get("ports", []), key=lambda p: p.get("port", 0))
        if not findings and not ports and not dc:
            continue
        port_rows = "".join(f"<tr><td>{esc(str(p.get('port','')))}/{esc(p.get('proto','tcp'))}</td>"
                            f"<td>{esc(p.get('service') or '')}</td><td>{esc(p.get('product') or '')}</td></tr>" for p in ports)
        vuln_rows = "".join(
            f"<tr class='{esc(f.get('sev',''))}'><td>{esc(f.get('cve',''))}</td><td>{f.get('score') or '—'}</td>"
            f"<td>{esc(f.get('sev',''))}</td><td>{esc(f.get('software') or '')}:{esc(str(f.get('port','')))}</td>"
            f"<td>{'KEV ' if f.get('kev') else ''}{'MSF ' if f.get('msf') else ''}{'EDB' if f.get('edb') else ''}</td>"
            f"<td>{esc((f.get('desc') or '')[:200])}</td></tr>" for f in findings[:100])
        tech_tags = "".join(f"<span class='tag'>{esc(t['id'])} {esc(t['name'])}</span>" for t in techs)
        dc_html = ("<p><b>Default-credential services to check:</b> "
                   + ", ".join(f"{esc(x['service'])} (:{x['port']})" for x in dc) + "</p>") if dc else ""
        rows.append(f"""<section class="host"><h2>{esc(nm.label(d))} <span class="ip">{esc(d['ip'])}</span></h2>
          <p class="meta">Type: {esc(d.get('type','unknown'))} · MAC: {esc(d.get('mac') or '—')} · Vendor: {esc(d.get('vendor') or '—')} · OS: {esc(d.get('os') or '—')}</p>
          {f'<p class="techs">{tech_tags}</p>' if tech_tags else ''}
          {dc_html}
          {f'<h3>Open ports ({len(ports)})</h3><table><tr><th>Port</th><th>Service</th><th>Product</th></tr>{port_rows}</table>' if ports else ''}
          {f'<h3>Vulnerabilities ({len(findings)})</h3><table><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Where</th><th>Exploit</th><th>Description</th></tr>{vuln_rows}</table>' if findings else ''}
        </section>""")
    css = """body{font:14px -apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;margin:0 auto;padding:24px;color:#111;background:#fff}
      h1{border-bottom:3px solid #0ea5e9;padding-bottom:8px}h2{margin-top:32px;color:#0b4a6e}.ip{color:#64748b;font-weight:normal;font-size:.8em}
      .meta{color:#475569;font-size:12px}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}
      th,td{border:1px solid #cbd5e1;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9}
      tr.critical td:nth-child(3){color:#b91c1c;font-weight:bold}tr.high td:nth-child(3){color:#c2410c;font-weight:bold}
      .tag{display:inline-block;background:#eef2ff;border:1px solid #c7d2fe;color:#3730a3;border-radius:4px;padding:1px 6px;margin:2px;font-size:11px}
      .summary{display:flex;gap:24px;flex-wrap:wrap;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:16px 0}
      .summary div{text-align:center}.summary b{display:block;font-size:24px;color:#0b4a6e}.disc{color:#64748b;font-size:11px;margin-top:40px;border-top:1px solid #e2e8f0;padding-top:12px}"""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>LanPulse engagement report</title><style>{css}</style></head>
    <body><h1>LanPulse Engagement Report</h1>
    <p class="meta">Network {esc(nm.net.get('subnet',''))} · generated {esc(generated or time.strftime('%Y-%m-%d %H:%M'))}</p>
    <div class="summary"><div><b>{len([r for r in rows])}</b>hosts with findings</div><div><b>{total_vulns}</b>vulnerabilities</div>
      <div><b>{total_kev}</b>actively exploited</div><div><b>{exploitable}</b>with a Metasploit module</div></div>
    {''.join(rows) or '<p>No findings. Run port and vulnerability scans first.</p>'}
    <p class="disc">Generated by LanPulse from its own scan data. Vulnerability matching is by version number and may include
    issues already patched by your OS. This report is for authorised testing of your own network only. Data: NVD, CISA KEV,
    Metasploit metadata, Exploit-DB. MITRE ATT&CK® is a trademark of The MITRE Corporation.</p></body></html>"""


def _isip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
