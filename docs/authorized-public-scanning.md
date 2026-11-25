# Authorized public IP scanning

LanPulse keeps public-target scanning separate from Threat Map attacker investigation. An attacker IP is never copied into a scan target automatically.

## Requirements and approval

- Sign in to LanPulse with dashboard authentication enabled.
- Enter a public IPv4 address manually in the Threat Map investigation panel.
- Confirm that you own the address or have explicit permission to test it.
- Confirm the browser prompt before the scan starts.
- Only globally routable public IPv4 addresses are accepted. Private, loopback, link-local, multicast, reserved, and IPv6 targets are rejected in this initial implementation.
- One public scan may be queued or running at a time.

The authorization checkbox is an operator attestation, not independent proof of ownership. Do not scan systems unless you are authorized to test them.

## Scan profiles

### Nmap
Runs a bounded service-discovery scan against the 1,000 most common TCP ports using light version detection and a conservative timing template. It does not run exploit scripts, brute-force logins, or attempt exploitation. A scan is limited to 15 minutes.

### OpenVAS
Uses the Greenbone **Full and Fast** vulnerability assessment profile and the configured IANA TCP port list. OpenVAS must already be installed, ready, and enabled in Settings > Scanner. Results remain attached to the public scan record and are not imported as findings for a LAN device.

## Results and AI

Scan status and results are retained under the LanPulse data directory. The AI Threat Analyst can receive the saved public Nmap and OpenVAS results alongside retained threat events when a threat investigation is requested. Results are evidence, not proof that a vulnerability is exploitable; interpret service banners and scanner confidence accordingly.

## Operational notes

- Public scans require the LanPulse dashboard login and are disabled in demo mode.
- Nmap scan history is persisted. If LanPulse restarts during a scan, that record is marked Interrupted; it is not silently resumed.
- This initial workflow accepts IPv4 addresses only. Hostnames and automatic scans of attacker IPs are intentionally unsupported.
