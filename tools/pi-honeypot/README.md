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

1. In LanPulse open **Honeypot > Settings**, set an **External-sensor key**, and save. (This shared key is what the manual
   routes use; sensors made with Add sensor each get their own key instead.)
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

1. In LanPulse open **Honeypot > Settings**, set an **External-sensor key**, and save.
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

## Customizing a sensor

In **Honeypot > Captured attacks and malware > Sensors > Add sensor**, open **Customize (optional)** before you click
Create. Whatever you set is written into the one-line command as `setting=value` words, so there is nothing else to
do on the sensor. Leave a box empty to keep its default. If you install by hand, put the same words after the key
and certificate fingerprint (use `''` for the fingerprint if you do not pin one):
`sudo bash install-pi.sh https://192.168.0.208:8080 <key> '' ssh_port=2200 hostname=web01`.

| Setting | What it does | Default |
|---|---|---|
| `ssh=off`, `telnet=off` | Turn one of the two decoys off (one must stay on). | both on |
| `ssh_port=N`, `telnet_port=N` | Ports to listen on, 1024-65535. Forward 22 and 23 to these on your router. | 2222, 2223 |
| `ftp=on`, `ftp_port=N` | Also run the FTP decoy (see below). It uses `ftp_port` and the 20 ports after it. | off, 2121 |
| `http=on`, `http_port=N` | Also run the web decoy (see below). | off, 2180 |
| `hostname=NAME` | The name in the attacker's shell prompt and `uname -a`. | `svr04` |
| `profile=debian12` / `debian11` / `ubuntu2204` | Makes the SSH banner and `uname` claim that system. | Cowrie's own (old Debian) |
| `login=any` | Every username and password gets in (most sessions, most captured malware). | Cowrie's default (almost any login) |
| `login=random` | Logins fail for the first 2 to 5 tries, then work. Looks more like a real machine. | |
| `login=weak` | Only common default logins work (`root/root`, `admin/admin`, `pi/raspberry`, ...). | |
| `file_mb=N` | Biggest file kept, 1 to 5 MB (LanPulse stores nothing larger). | Cowrie's limit |
| `mem_mb=N`, `cpu_pct=N` | Cap Cowrie's memory (64-4096 MB) and CPU (10-100 %). Useful on a small Pi. | no cap |
| `keep_days=N` | Delete captured files, replay logs and old logs after N days (Pi install). | 30 |
| `disk_mb=N` | Keep captures under N MB by deleting the oldest first (Pi install; checked every hour). | no cap |

Run the command again with different settings to change them. The Pi install rewrites `cowrie.cfg` when you pass
settings (a file you edited by hand is kept as `cowrie.cfg.bak`) and restarts Cowrie. On a container sensor the
captures live in Docker volumes, so `keep_days` and `disk_mb` do not apply there.

The hostname and system are only what the attacker is told. They do not make the sensor safer or more dangerous;
the advice in section 1 stays the same.

## FTP and web decoys (optional)

Cowrie covers SSH and Telnet. Turn on **FTP decoy** and/or **Web decoy** in Add sensor > Customize (or add `ftp=on` and
`http=on` to the command) to also see what attackers upload over those protocols. They are one small Python program
(`lanpulse-trap.py`, standard library only) that runs next to Cowrie as its own service (`lanpulse-trap`) or container.
It writes its events in Cowrie's format, so sessions and captured files show up in the same place in LanPulse and get the
same static analysis.

- **FTP:** accepts any login, shows a small fake folder listing, and keeps every file that is uploaded. Active mode
  (`PORT`/`EPRT`) is refused, so the sensor never connects out to an address an attacker names.
- **Web:** answers every request with a plain "It works!" page, logs exploit attempts (paths, suspicious headers, login
  forms, Basic auth) and keeps files sent with `PUT`, `POST` or a multipart upload form. Plain page loads from scanners are
  answered but not recorded, so the list stays about real attacks.

Safety limits: files are saved only under their SHA-256 name with mode 0600 and are never run, opened or served back;
files above the size limit (5 MB at most) are refused; the decoys stop keeping files when their folder reaches 500 MB;
the number of connections is capped, in total and per address; and at most 30 sessions per minute are reported. Ports
below 1024 are not used, so nothing runs as root.

On your router forward the same way as for SSH and Telnet:

| Internet | To the sensor |
|---|---|
| TCP 21 (FTP) | port 2121, **and** 2122-2141 to the same port numbers (FTP uploads use them) |
| TCP 80 (web) | port 2180 |

If you chose other ports, forward to those (FTP: your port plus the 20 after it). A sensor needs SSH or Telnet on as
well; FTP-only or web-only sensors are not supported.

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
