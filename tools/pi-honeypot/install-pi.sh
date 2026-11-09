#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
#
# Sets up a Cowrie SSH/Telnet honeypot on a Raspberry Pi (Raspberry Pi OS / Debian / Ubuntu) and a small forwarder
# that sends every attacker session and captured file to your LanPulse server.
#
#   sudo ./install-pi.sh https://192.168.0.208:8080 <sensor-key> [server-certificate-sha256]
#
# The easy way is LanPulse > Honeypot > Add sensor, which gives you a ready-made one-line command with its own key.
# To run this by hand use the key under LanPulse > Honeypot > Settings > "External-sensor key".
# Cowrie listens on ports 2222 (SSH) and 2223 (Telnet). Your Pi's own SSH on port 22 is NOT touched; forward the
# internet-facing ports 22/23 to 2222/2223 on your router instead (see README.md).
set -euo pipefail

# LanPulse fills this in when it serves this script (Honeypot > Add sensor); empty when run from a git checkout.
FORWARDER_B64=""

URL="${1:-}"; KEY="${2:-}"; FP="${3:-}"
[ "$(id -u)" = 0 ] || { echo "Run this with sudo." >&2; exit 1; }
[ -n "$URL" ] && [ -n "$KEY" ] || { echo "Usage: sudo $0 https://<lanpulse-ip>:8080 <sensor-key> [cert-sha256]" >&2; exit 2; }
case "$URL" in http://*|https://*) ;; *) echo "The LanPulse address must start with http:// or https://" >&2; exit 2;; esac
URL="${URL%/}"
HERE="$(cd "$(dirname "$0")" && pwd)"
COWRIE_USER=cowrie
HOME_DIR="/home/$COWRIE_USER"
COWRIE_DIR="$HOME_DIR/cowrie"

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3-venv python3-pip libssl-dev libffi-dev build-essential libpython3-dev openssl >/dev/null

echo "==> Creating the '$COWRIE_USER' user (no login, no password)"
id "$COWRIE_USER" >/dev/null 2>&1 || adduser --disabled-password --gecos "Cowrie honeypot" "$COWRIE_USER" >/dev/null

echo "==> Installing Cowrie"
if [ ! -d "$COWRIE_DIR/.git" ]; then
  sudo -u "$COWRIE_USER" git clone --quiet https://github.com/cowrie/cowrie "$COWRIE_DIR"
fi
sudo -u "$COWRIE_USER" bash -c "cd '$COWRIE_DIR' && python3 -m venv cowrie-env && . cowrie-env/bin/activate \
  && python -m pip install --quiet --upgrade pip && python -m pip install --quiet -e ."

if [ ! -f "$COWRIE_DIR/etc/cowrie.cfg" ]; then
  echo "==> Writing Cowrie settings"
  cat > "$COWRIE_DIR/etc/cowrie.cfg" <<'CFG'
# Only the settings that differ from Cowrie's defaults.
[honeypot]
hostname = svr04

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
CFG
  chown "$COWRIE_USER:$COWRIE_USER" "$COWRIE_DIR/etc/cowrie.cfg"
fi

if [ -z "$FP" ] && [ "${URL#https://}" != "$URL" ]; then
  HOSTPORT="${URL#https://}"; HOSTPORT="${HOSTPORT%%/*}"
  case "$HOSTPORT" in *:*) ;; *) HOSTPORT="$HOSTPORT:443";; esac
  FP="$(openssl s_client -connect "$HOSTPORT" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' || true)"
  if [ -n "$FP" ]; then
    echo "==> Trusting the LanPulse certificate with fingerprint:"
    echo "    $FP"
    echo "    (Compare it with the one your browser shows for LanPulse if you want to be sure.)"
  else
    echo "!! Could not read LanPulse's certificate. Check the address and that LanPulse is running." >&2
  fi
fi

echo "==> Installing the forwarder"
install -d -m 0755 /usr/local/lib/lanpulse-forwarder
if [ -n "$FORWARDER_B64" ]; then          # embedded copy wins, so a stray file next to the script is never used
  printf '%s' "$FORWARDER_B64" | base64 -d > /usr/local/lib/lanpulse-forwarder/lanpulse-forwarder.py
  chmod 755 /usr/local/lib/lanpulse-forwarder/lanpulse-forwarder.py
elif [ -f "$HERE/lanpulse-forwarder.py" ]; then
  install -m 0755 "$HERE/lanpulse-forwarder.py" /usr/local/lib/lanpulse-forwarder/lanpulse-forwarder.py
else
  echo "lanpulse-forwarder.py not found next to this script." >&2; exit 1
fi
umask 077
cat > /etc/lanpulse-forwarder.env <<ENV
LANPULSE_URL=$URL
LANPULSE_KEY=$KEY
LANPULSE_FINGERPRINT=$FP
COWRIE_HOME=$COWRIE_DIR
SENSOR_NAME=$(hostname)
ENV
chmod 600 /etc/lanpulse-forwarder.env
umask 022

cat > /etc/systemd/system/cowrie.service <<UNIT
[Unit]
Description=Cowrie SSH/Telnet honeypot
After=network.target

[Service]
Type=forking
User=$COWRIE_USER
WorkingDirectory=$COWRIE_DIR
PIDFile=$COWRIE_DIR/var/run/cowrie.pid
ExecStart=$COWRIE_DIR/cowrie-env/bin/cowrie start
ExecStop=$COWRIE_DIR/cowrie-env/bin/cowrie stop
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/lanpulse-forwarder.service <<UNIT
[Unit]
Description=Send Cowrie honeypot sessions and captured files to LanPulse
After=network-online.target cowrie.service
Wants=network-online.target

[Service]
User=$COWRIE_USER
EnvironmentFile=/etc/lanpulse-forwarder.env
ExecStart=/usr/bin/python3 /usr/local/lib/lanpulse-forwarder/lanpulse-forwarder.py
Restart=always
RestartSec=5
StateDirectory=lanpulse-forwarder
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
UNIT

# Captured files pile up on the SD card; keep a month.
cat > /etc/cron.daily/cowrie-clean <<CRON
#!/bin/sh
find "$COWRIE_DIR/var/lib/cowrie/downloads" -type f -mtime +30 -delete 2>/dev/null
exit 0
CRON
chmod 755 /etc/cron.daily/cowrie-clean

echo "==> Starting"
systemctl daemon-reload
systemctl enable --now cowrie.service lanpulse-forwarder.service
sleep 3
systemctl --no-pager --lines=0 status cowrie.service lanpulse-forwarder.service || true

cat <<DONE

Done. Test the honeypot from another computer:   ssh -p 2222 root@$(hostname -I | awk '{print $1}')   (any password)
Then open LanPulse > Honeypot > Sessions: the session should appear within a few seconds.
If it does not, look at:   journalctl -u lanpulse-forwarder -n 30    and    journalctl -u cowrie -n 30
Next: forward ports 22 and 23 from the internet to this Pi's 2222 and 2223 on your router, and read README.md first
(the Pi should sit on its own network so a break-in cannot reach the rest of your LAN).
DONE
