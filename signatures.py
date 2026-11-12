# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Curated signatures for classic, trivially exploitable services.

NVD matching works from a product's CPE, and nmap often can't produce one for old or unusual software (distccd, a
bindshell, a backdoored FTP build), so these get missed. Each signature here is a well-known flaw that has a public
Metasploit module, matched on what nmap reports (service name, product, version). They are shown as "version match"
findings (the banner says so; nothing was exploited). OpenVAS is the accurate source; this is a safety net.

Signature: (id, service-name regex, product regex, version regex or None, port or None, cve, score, title, desc, msf module)
"""
from __future__ import annotations

import re

# (key, service regex, product regex, version regex, cve, score, title, description, metasploit module)
SIGNATURES = [
    ("vsftpd-234", r"ftp", r"vsftpd", r"^2\.3\.4$", "CVE-2011-2523", 10.0,
     "vsftpd 2.3.4 backdoor",
     "This vsftpd release shipped with a backdoor: logging in with a username ending in :) opens a root shell on port 6200.",
     "exploit/unix/ftp/vsftpd_234_backdoor"),
    ("unrealircd", r"irc", r"unreal", r"^3\.2\.8\.1$", "CVE-2010-2075", 10.0,
     "UnrealIRCd 3.2.8.1 backdoor",
     "This UnrealIRCd release contains a remote-command backdoor ('AB;' command) in the official download.",
     "exploit/unix/irc/unreal_ircd_3281_backdoor"),
    ("distccd", r"distcc", r"", None, "CVE-2004-2687", 9.3,
     "distccd allows remote command execution",
     "An exposed distcc daemon runs commands sent by anyone who can reach it.",
     "exploit/unix/misc/distcc_exec"),
    ("samba-usermap", r"netbios-ssn|microsoft-ds|smb", r"samba", r"^3\.0\.([0-9]|1[0-9]|2[0-4])($|[^0-9])", "CVE-2007-2447", 10.0,
     "Samba 'username map script' command execution",
     "Samba 3.0.0 through 3.0.25rc3 runs shell metacharacters in a username when 'username map script' is set.",
     "exploit/multi/samba/usermap_script"),
    ("proftpd-133c", r"ftp", r"proftpd", r"^1\.3\.3c$", "CVE-2010-20103", 10.0,
     "ProFTPD 1.3.3c backdoor",
     "The ProFTPD 1.3.3c source download was backdoored with a remote command execution.",
     "exploit/unix/ftp/proftpd_133c_backdoor"),
    ("java-rmi", r"java-rmi|rmiregistry", r"", None, "CVE-2011-3556", 10.0,
     "Java RMI registry with remote class loading",
     "A default-configured Java RMI registry/server lets a remote client load and run its own code.",
     "exploit/multi/misc/java_rmi_server"),
    ("bindshell", r"bindshell|ingreslock", r"", None, "", 10.0,
     "Open remote shell (bindshell)",
     "A service on this port hands out a command shell without a login: anyone who connects has control of the machine.",
     ""),
    ("drb", r"drb", r"", None, "", 9.0,
     "Ruby DRb service exposed",
     "An exposed Ruby DRb (distributed Ruby) service accepts remote method calls and can be made to run commands.",
     "exploit/linux/misc/drb_remote_codeexec"),
    ("rservices", r"exec|login|shell", r"rexecd|rlogind|rshd|netkit-rsh", None, "", 7.5,
     "r-services (rsh/rlogin/rexec) exposed",
     "These legacy services send passwords and commands unencrypted and trust the connecting host's name.",
     ""),
]
_COMPILED = [(k, re.compile(sv, re.I), re.compile(pr, re.I), re.compile(vr) if vr else None, cve, score, title, desc, msf)
             for k, sv, pr, vr, cve, score, title, desc, msf in SIGNATURES]

# Well-known CVEs with a Metasploit module, so a finding from any source (OpenVAS, vulners, an NSE check) gets its
# badge even when the exploit index hasn't downloaded yet or doesn't list it. The signatures above add theirs.
_EXTRA_MSF = {
    "CVE-2020-1938": ("auxiliary/admin/http/tomcat_ghostcat", "Apache Tomcat AJP file read (Ghostcat)"),
    "CVE-2017-0143": ("exploit/windows/smb/ms17_010_eternalblue", "MS17-010 EternalBlue SMB remote code execution"),
    "CVE-2008-4250": ("exploit/windows/smb/ms08_067_netapi", "MS08-067 Server service remote code execution"),
    "CVE-2012-1823": ("exploit/multi/http/php_cgi_arg_injection", "PHP CGI argument injection"),
}
MSF_BY_CVE = {**{cve: (msf, title) for _, _, _, _, cve, _, title, _, msf in SIGNATURES if msf and cve.startswith("CVE-")},
              **_EXTRA_MSF}


def msf_for_cve(cve: str) -> list:
    """Metasploit module for a CVE as [[module, title, rank]] (the exploit index's shape), or []."""
    m = MSF_BY_CVE.get((cve or "").upper())
    return [[m[0], m[1][:160], 0]] if m else []


def match_port(p: dict) -> list[dict]:
    """Signatures that fit one port entry from nmap ({service, product, ver, ...})."""
    svc = str(p.get("service") or p.get("name") or "")
    prod = str(p.get("product") or p.get("sw") or "")
    ver = str(p.get("ver") or "").strip()
    out = []
    for key, rs, rp, rv, cve, score, title, desc, msf in _COMPILED:
        if not rs.search(svc) and not (prod and rs.search(prod)):
            continue
        if rp.pattern and not rp.search(prod + " " + svc):
            continue
        if rv is not None and not rv.search(ver):
            continue
        out.append({"key": key, "cve": cve or f"LANPULSE-{key.upper()}", "score": score, "title": title, "desc": desc,
                    "msf": [msf] if msf else []})
    return out


def match_device(d: dict) -> list[tuple[int, dict]]:
    """[(port, signature)] for a device: per-port matches, plus Samba versions only visible in the SMB OS string
    (nmap often reports just 'Samba smbd 3.X - 4.X' for the service, while smb-os-discovery gives 'Samba 3.0.20-Debian')."""
    out = []
    for p in d.get("ports", []):
        for m in match_port(p):
            out.append((p.get("port") or 0, m))
    if not any(m["key"] == "samba-usermap" for _, m in out):
        hint = f"{d.get('os_hint', '')} {d.get('os', '')}"
        m = re.search(r"Samba (3\.0\.\d+)", hint)
        if m:
            for sig in match_port({"service": "netbios-ssn", "product": "Samba", "ver": m.group(1)}):
                port = next((p.get("port") for p in d.get("ports", []) if p.get("port") in (445, 139)), 445)
                out.append((port, sig))
    return out


# Specific OpenVAS findings without CVE references; caller restricts these to confirmed results.
_FINDING_MSF = [
    (re.compile(r"\bghostcat\b", re.I), "auxiliary/admin/http/tomcat_ghostcat", "Apache Tomcat AJP file read (Ghostcat)"),
    (re.compile(r"distributed ruby|\bd[r]?b\b", re.I), "exploit/linux/misc/drb_remote_codeexec", "Distributed Ruby remote code execution"),
    (re.compile(r"php.*cgi|cgi.*php", re.I), "exploit/multi/http/php_cgi_arg_injection", "PHP CGI argument injection"),
    (re.compile(r"postgresql default credentials", re.I), "auxiliary/scanner/postgres/postgres_login", "PostgreSQL Login Utility"),
    (re.compile(r"vnc brute force login", re.I), "auxiliary/scanner/vnc/vnc_login", "VNC Authentication Scanner"),
    (re.compile(r"ftp brute force logins", re.I), "auxiliary/scanner/ftp/ftp_login", "FTP Authentication Scanner"),
    (re.compile(r"anonymous ftp login", re.I), "auxiliary/scanner/ftp/ftp_anonymous", "FTP Anonymous Access Scanner"),
    (re.compile(r"rlogin passwordless login", re.I), "auxiliary/scanner/rservices/rlogin_login", "rlogin Authentication Scanner"),
]


def msf_for_finding(name: str, desc: str = "") -> list:
    """Known modules for specifically named, confirmed scanner findings."""
    text = f"{name or ''} {desc or ''}"
    for pattern, module, title in _FINDING_MSF:
        if pattern.search(text):
            return [[module, title, 0]]
    return []
