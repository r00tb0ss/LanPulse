# Honeypot sensor for LanPulse (Raspberry Pi, Linux box or container)

A sensor (a Raspberry Pi, or any Linux machine, with or without containers) runs [Cowrie](https://github.com/cowrie/cowrie), a honeypot that looks like an SSH and Telnet server.
Attackers log in, type commands and download malware, and Cowrie records all of it inside a fake system. A small
forwarder (`lanpulse-forwarder.py`, Python standard library only) sends each session and every captured file to
LanPulse, where **Honeypot > Captured attacks and malware** explains what the attacker did and what the malware is.

This is an optional extra. LanPulse's built-in light honeypot keeps working on its own, with or without a sensor.

LanPulse only ever **reads** captured files as bytes (hashes, file type, strings, addresses inside). It never runs
them, and it never offers them for download.

## 1. Put the sensor on its own network first

The honeypot is *meant* to be attacked. Treat the sensor as already compromised.

- Best: a separate VLAN or the UDM's DMZ/"Guest"-style network with **no access to your LAN**.
- Add a firewall rule that lets the sensor talk only to LanPulse (TCP 8080) and the internet, and blocks everything
  else to your LAN. Cowrie's fake shell cannot touch the machine, but a real break-in through a bug in Cowrie could.
- Do not reuse passwords or SSH keys from the sensor anywhere else. On a Pi, use a spare SD card.
- A container is a fence, not a vault: it shares the host's kernel. Prefer a separate small machine over running the
  container on the LanPulse server itself.

## 2. Install

**Easiest: the Add sensor button.** In LanPulse open **Honeypot > Captured attacks and malware > Sensors > Add sensor**,
name it, choose Raspberry Pi / Linux or container, and copy the one-line command to a terminal on the sensor. The sensor
gets its own key (you can remove it later without touching other sensors), the command carries a checksum of the
installer so a swapped script is refused, and the page turns green when the sensor reports in. Nothing about the sensor
(no password, no SSH key) is ever given to LanPulse. The manual routes below do the same thing step by step.

Manual: **A** installs straight onto a Raspberry Pi; **B** runs in containers on a Pi or any other Linux host.

### A. Raspberry Pi (no containers)

1. In LanPulse use **Add sensor** and copy the sensor key it shows (it is shown once).
2. On the Pi (Raspberry Pi OS or Ubuntu, network access to GitHub and your LanPulse box):

   ```
   git clone https://gitlab.com/r00tb0ss/lanpulse
   cd lanpulse/tools/pi-honeypot
   sudo ./install-pi.sh https://<lanpulse-ip>:8080 <sensor-key>
   ```

   The script installs Cowrie for a new `cowrie` user, listens on ports **2222** (SSH) and **2223** (Telnet), installs
   the forwarder, and pins LanPulse's self-signed certificate (it prints the fingerprint so you can compare).
   Your Pi's own SSH on port 22 is not touched.

3. Test from another computer: `ssh -p 2222 root@<pi-ip>` with any password, run a few commands such as `uname -a`,
   then log out. The session should appear in **Honeypot > Captured attacks and malware > Sessions** in a few seconds.

### B. Containers (Docker or Podman)

Needs Docker with the Compose plugin (or `podman-compose`) and network access to Docker Hub. It runs the official
`cowrie/cowrie` image plus the forwarder in a stock `python` image, so nothing is built and nothing is installed on
the host. Check that `docker pull cowrie/cowrie` works on your CPU first (64-bit Raspberry Pi OS and x86 are the
usual cases).

1. In LanPulse use **Add sensor** and copy the sensor key it shows (it is shown once).
2. On the sensor machine:

   ```
   git clone https://gitlab.com/r00tb0ss/lanpulse
   cd lanpulse/tools/pi-honeypot/docker
   cp .env.example .env
   nano .env            # LanPulse address, the sensor key, and the certificate fingerprint (the file shows how to get it)
   docker compose up -d
   ```

3. Test it as in step 3 above (`ssh -p 2222 root@<machine-ip>`). Logs: `docker compose logs -f`.

Cowrie and the forwarder share one volume. The forwarder mounts it **read-only**, drops all Linux capabilities except
the one that lets it read Cowrie's files, and talks only to your LanPulse server. Stop with `docker compose down`
(add `-v` to also delete the captured data on the sensor). Update with `docker compose pull && docker compose up -d`.

(The Add sensor command for containers does the same thing in `/opt/lanpulse-sensor`.)

## 3. Let the internet in

On your router, forward **TCP 22 to the sensor's port 2222** and **TCP 23 to its port 2223**. (Move your own
router's or server's real SSH off 22 if it is exposed, and never forward 22 to a machine you really use.)

## What you get in LanPulse

- **Sessions:** every connection with the logins tried, a command-by-command replay, and plain-language tags
  (downloads a file, plants an SSH key, erases its tracks, probes for IoT shells, and so on) mapped to MITRE ATT&CK.
- **Samples:** every captured file with SHA-256, file type (including CPU type for Linux ELF files), entropy,
  strings, URLs/IPs/domains/wallets inside it, family hints (Mirai-style, miner, ...), where it came from, and a link
  to look the hash up on VirusTotal. URLs and IPs are shown defanged (`hxxp://evil[.]com`).
- **Sensors:** each sensor with a connected / waiting / silent light, last contact, and how much it has sent.
- Alerts when a **new** sample is captured, and the headline hit shows on the normal Honeypot and Threats views.

## Troubleshooting

On a Pi: `journalctl -u cowrie -n 50` and `journalctl -u lanpulse-forwarder -n 50`.
In containers: `docker compose logs --tail 50 cowrie forwarder`.

- *The sensor stays on "Waiting"*: the sensor cannot reach LanPulse. Check the address and port, and any firewall rule
  between the sensor and LanPulse. Nothing is lost; the forwarder keeps a queue and sends it when LanPulse answers.
- *403 in the forwarder log*: the sensor key is wrong or the sensor was removed in LanPulse. Add the sensor again, then fix
  `LANPULSE_KEY` (on a Pi in `/etc/lanpulse-forwarder.env`, then `sudo systemctl restart lanpulse-forwarder`; in containers in `.env`, then `docker compose up -d`).
- *The install command says the checksum does not match*: LanPulse was updated after the command was made, or something
  between the sensor and LanPulse changed the file. Create the sensor again to get a fresh command.
- On a Pi, captured files older than 30 days are deleted daily (`/etc/cron.daily/cowrie-clean`). In containers they stay in the volume until you remove it.
- A session that is still open when the forwarder restarts is not sent; finished sessions are never lost.

## Updating Cowrie (Pi install)

```
sudo systemctl stop cowrie
sudo -u cowrie bash -c 'cd ~/cowrie && git pull && . cowrie-env/bin/activate && python -m pip install --upgrade -e .'
sudo systemctl start cowrie
```
