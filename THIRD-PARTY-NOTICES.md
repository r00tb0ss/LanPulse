# Third-party notices

LanPulse itself is licensed under the **GNU General Public License v2.0 or later** (see `LICENSE`).

LanPulse does not ship copies of the projects below. The installer downloads or installs them on your machine, or LanPulse
runs them as separate programs or calls them as online services. Each keeps its own license.

## Python packages (installed by `install.sh` with pip)

| Package | Used for | License |
|---|---|---|
| [Scapy](https://scapy.net) | Live ARP/DHCP/mDNS listening, ARP sweeps | GPL-2.0-only |
| [FastAPI](https://fastapi.tiangolo.com) | Web server and API | MIT |
| [Uvicorn](https://www.uvicorn.org) | HTTP/WebSocket server | BSD-3-Clause |

The GeoIP database reader (`mmdb.py`) is LanPulse's own code, written from the public
[MaxMind DB format specification](https://maxmind.github.io/MaxMind-DB/).

## Programs LanPulse runs

| Program | Used for | License |
|---|---|---|
| [Nmap](https://nmap.org) | Port scans and OS detection (run as a separate program; also reads its `nmap-mac-prefixes` vendor list) | Nmap Public Source License (NPSL) |

Nmap is installed from your operating system's packages. If you redistribute LanPulse bundled with Nmap,
read the NPSL first: it places conditions on redistribution.

## Browser libraries (downloaded into `static/vendor` by `install.sh`, with a CDN fallback)

| Library | Used for | License |
|---|---|---|
| [vis-network](https://visjs.github.io/vis-network/) 9.1.9 | Device map | Apache-2.0 OR MIT |
| [Apache ECharts](https://echarts.apache.org) 5.4.3 | World attack map and charts | Apache-2.0 |
| ECharts world map (`world.js`, from ECharts 4.9.0) | Country outlines | Apache-2.0 |
| [Font Awesome Free](https://fontawesome.com) 6.5.1 | Icons | Icons CC BY 4.0, fonts SIL OFL 1.1, code MIT |
| [Inter](https://rsms.me/inter/) and [JetBrains Mono](https://www.jetbrains.com/lp/mono/) (Google Fonts) | Typefaces | SIL OFL 1.1 |

## Data

| Data | Used for | License / terms |
|---|---|---|
| [DB-IP](https://db-ip.com) IP to City Lite and IP to ASN Lite | Placing IPs on the map, naming networks | CC BY 4.0. Attribution: **IP Geolocation by DB-IP** |
| [IEEE](https://standards.ieee.org/products-programs/regauth/) MA-L / MA-M / MA-S registries | Device manufacturer names | Public registry listings from the IEEE |
| [NVD](https://nvd.nist.gov) (US National Vulnerability Database) CVE API | Vulnerabilities tab | US government data. **This product uses the NVD API but is not endorsed or certified by the NVD.** |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Flagging actively exploited flaws | US government work, public domain |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch) host file | Malware domain lookups in the DNS tab | CC0 (public domain) |
| [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) URLhaus mirror | Fallback copy of the URLhaus list | CC0 |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) module metadata (`modules_metadata_base.json`) | Which CVEs have a Metasploit module | BSD-3-Clause |
| [Exploit-DB](https://www.exploit-db.com) `files_exploits.csv` | Which CVEs have public exploit code | Exploit-DB / OffSec terms |

LanPulse reads your own [Pi-hole](https://pi-hole.net)'s query log through its API (DNS tab); nothing of Pi-hole is included.

## Online services (used only when you investigate an IP or turn on a feature)

| Service | Used for | Terms |
|---|---|---|
| [abuse.ch ThreatFox](https://threatfox.abuse.ch) | Flagging attacker IPs that are known malware C2/botnet | Free, CC0 |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) | Detecting devices that connect out to known botnet C2 | Free, CC0 |
| [Tor Project exit list](https://check.torproject.org/torbulkexitlist) | Flagging attackers coming through Tor | Public list |

| Service | Used for | Terms |
|---|---|---|
| [ip-api.com](https://ip-api.com) | IP details | Free for non-commercial use |
| [Shodan InternetDB](https://internetdb.shodan.io) | Open ports and known issues for an IP | Free, non-commercial |
| [GreyNoise Community API](https://www.greynoise.io) | Whether an IP is a known internet scanner | GreyNoise community terms |
| [AbuseIPDB](https://www.abuseipdb.com) | IP reputation (optional, your own key) | AbuseIPDB terms |
| [ipify](https://www.ipify.org) | Finding your public IP | Free |

If you sell or run LanPulse commercially, check the terms of the online services above. Some are free for non-commercial use only.

## Trademarks

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. LanPulse references ATT&CK technique names and IDs for
educational mapping only and is not affiliated with or endorsed by MITRE. Metasploit® is a trademark of Rapid7, Inc.
