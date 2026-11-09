#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
#
# Runs a Cowrie SSH/Telnet honeypot and the LanPulse forwarder as containers (Docker or Podman with compose).
#
#   sudo ./install-container.sh https://192.168.0.208:8080 <sensor-key> [server-certificate-sha256]
#
# Everything goes in /opt/lanpulse-sensor. Cowrie listens on host ports 2222 (SSH) and 2223 (Telnet).
set -euo pipefail

# LanPulse fills these in when it serves this script (Honeypot > Add sensor); empty when run from a git checkout.
FORWARDER_B64=""

URL="${1:-}"; KEY="${2:-}"; FP="${3:-}"
[ "$(id -u)" = 0 ] || { echo "Run this with sudo." >&2; exit 1; }
[ -n "$URL" ] && [ -n "$KEY" ] || { echo "Usage: sudo $0 https://<lanpulse-ip>:8080 <sensor-key> [cert-sha256]" >&2; exit 2; }
case "$URL" in http://*|https://*) ;; *) echo "The LanPulse address must start with http:// or https://" >&2; exit 2;; esac
URL="${URL%/}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/lanpulse-sensor

if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then COMPOSE="podman-compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else echo "Docker (with the Compose plugin) or podman-compose is required." >&2; exit 1; fi

if [ -z "$FP" ] && [ "${URL#https://}" != "$URL" ]; then
  HOSTPORT="${URL#https://}"; HOSTPORT="${HOSTPORT%%/*}"
  case "$HOSTPORT" in *:*) ;; *) HOSTPORT="$HOSTPORT:443";; esac
  FP="$(openssl s_client -connect "$HOSTPORT" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' || true)"
  [ -n "$FP" ] && echo "==> Trusting the LanPulse certificate with fingerprint: $FP"
fi

install -d -m 0755 "$DIR"
if [ -n "$FORWARDER_B64" ]; then
  printf '%s' "$FORWARDER_B64" | base64 -d > "$DIR/lanpulse-forwarder.py"
elif [ -f "$HERE/lanpulse-forwarder.py" ]; then
  cp "$HERE/lanpulse-forwarder.py" "$DIR/lanpulse-forwarder.py"
else
  echo "lanpulse-forwarder.py not found next to this script." >&2; exit 1
fi
chmod 644 "$DIR/lanpulse-forwarder.py"

umask 077
cat > "$DIR/.env" <<ENV
LANPULSE_URL=$URL
LANPULSE_KEY=$KEY
LANPULSE_FINGERPRINT=$FP
SENSOR_NAME=$(hostname)
ENV
umask 022

cat > "$DIR/docker-compose.yml" <<'YML'
services:
  cowrie:
    image: cowrie/cowrie:latest
    restart: unless-stopped
    ports:
      - "2222:2222"
      - "2223:2223"
    environment:
      COWRIE_TELNET_ENABLED: "yes"
      COWRIE_OUTPUT_JSONLOG_ENABLED: "yes"
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var
    security_opt:
      - no-new-privileges:true

  forwarder:
    image: python:3.12-slim
    restart: unless-stopped
    depends_on:
      - cowrie
    command: ["python", "-u", "/app/lanpulse-forwarder.py"]
    env_file: .env
    environment:
      COWRIE_HOME: /cowrie/cowrie-git
      STATE_FILE: /state/state.json
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var:ro
      - forwarder-state:/state
      - ./lanpulse-forwarder.py:/app/lanpulse-forwarder.py:ro
    cap_drop:
      - ALL
    cap_add:
      - DAC_READ_SEARCH
    security_opt:
      - no-new-privileges:true

volumes:
  cowrie-var:
  forwarder-state:
YML

echo "==> Starting the containers"
cd "$DIR"
$COMPOSE up -d

cat <<DONE

Done. Test from another computer:   ssh -p 2222 root@$(hostname -I | awk '{print $1}')   (any password)
Logs:   cd $DIR && $COMPOSE logs -f        Stop:   cd $DIR && $COMPOSE down
Next: forward ports 22 and 23 from the internet to this machine's 2222 and 2223 on your router, and keep this machine
off your main LAN (a container shares the host's kernel).
DONE
