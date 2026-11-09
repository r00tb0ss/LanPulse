#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
#
# Runs a Cowrie SSH/Telnet honeypot and the LanPulse forwarder as containers (Docker or Podman with compose).
#
#   sudo ./install-container.sh https://192.168.0.208:8080 <sensor-key> [server-certificate-sha256] [setting=value ...]
#
# Everything goes in /opt/lanpulse-sensor. Cowrie listens on host ports 2222 (SSH) and 2223 (Telnet).
#
# Optional settings (the Customize section of Add sensor writes these into the command; all have a default):
#   ssh=off  telnet=off            turn one of the decoys off
#   ssh_port=N  telnet_port=N      host ports to listen on, 1024-65535 (default 2222 and 2223)
#   ftp=on  ftp_port=N             also run the FTP decoy that keeps uploaded files (default off; port 2121 and the 20 after it)
#   http=on  http_port=N           also run the web decoy that logs exploit attempts and keeps uploads (default off; port 2180)
#   hostname=NAME                  name the attacker sees in the shell prompt (default svr04)
#   profile=debian12|debian11|ubuntu2204   what uname and the SSH banner claim (default: Cowrie's own)
#   login=any|random|weak          any = every login works; random = works after 2-5 tries; weak = only common passwords
#   file_mb=N                      biggest file to keep, 1-5 MB
#   mem_mb=N  cpu_pct=N            cap Cowrie's memory (64-4096 MB) and CPU (10-100 %)
# Running the command again with different settings changes them.
set -euo pipefail

# LanPulse fills these in when it serves this script (Honeypot > Add sensor); empty when run from a git checkout.
FORWARDER_B64=""
TRAP_B64=""

URL="${1:-}"; KEY="${2:-}"; FP="${3:-}"
[ "$(id -u)" = 0 ] || { echo "Run this with sudo." >&2; exit 1; }
[ -n "$URL" ] && [ -n "$KEY" ] || { echo "Usage: sudo $0 https://<lanpulse-ip>:8080 <sensor-key> [cert-sha256] [setting=value ...]" >&2; exit 2; }
case "$URL" in http://*|https://*) ;; *) echo "The LanPulse address must start with http:// or https://" >&2; exit 2;; esac
URL="${URL%/}"
if [ "$#" -ge 3 ]; then shift 3; else shift "$#"; fi

# ---- settings
SSH_ON=yes; TELNET_ON=yes; SSH_PORT=2222; TELNET_PORT=2223; FAKE_HOST=svr04; PROFILE=default; LOGIN=default
FTP_ON=no; HTTP_ON=no; FTP_PORT=2121; HTTP_PORT=2180
FILE_MB=""; MEM_MB=""; CPU_PCT=""
bad() { echo "Unknown or invalid setting: $1" >&2; exit 2; }
num() {                                   # name value min max: digits only, within range
  case "$2" in ''|*[!0-9]*) bad "$1=$2";; esac
  if [ "${#2}" -gt 6 ] || [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then bad "$1=$2 (use $3 to $4)"; fi
}
for kv in "$@"; do
  k="${kv%%=*}"; v="${kv#*=}"
  case "$k" in
    ssh)         case "$v" in on) SSH_ON=yes;; off) SSH_ON=no;; *) bad "$kv";; esac;;
    telnet)      case "$v" in on) TELNET_ON=yes;; off) TELNET_ON=no;; *) bad "$kv";; esac;;
    ftp)         case "$v" in on) FTP_ON=yes;; off) FTP_ON=no;; *) bad "$kv";; esac;;
    http)        case "$v" in on) HTTP_ON=yes;; off) HTTP_ON=no;; *) bad "$kv";; esac;;
    ftp_port)    num "$k" "$v" 1024 65515; FTP_PORT="$v";;
    http_port)   num "$k" "$v" 1024 65535; HTTP_PORT="$v";;
    ssh_port)    num "$k" "$v" 1024 65535; SSH_PORT="$v";;
    telnet_port) num "$k" "$v" 1024 65535; TELNET_PORT="$v";;
    hostname)    case "$v" in ''|-*|*-|[0-9]*|*[!a-z0-9-]*) bad "$kv";; esac
                 [ "${#v}" -le 32 ] || bad "$kv"; FAKE_HOST="$v";;
    profile)     case "$v" in default|debian12|debian11|ubuntu2204) PROFILE="$v";; *) bad "$kv";; esac;;
    login)       case "$v" in default|any|random|weak) LOGIN="$v";; *) bad "$kv";; esac;;
    file_mb)     num "$k" "$v" 1 5; FILE_MB="$v";;
    mem_mb)      num "$k" "$v" 64 4096; MEM_MB="$v";;
    cpu_pct)     num "$k" "$v" 10 100; CPU_PCT="$v";;
    keep_days|disk_mb) ;;                 # captures live in Docker volumes; clean those up with docker if you need to
    *)           bad "$kv";;
  esac
done
if [ "$SSH_ON" = no ] && [ "$TELNET_ON" = no ]; then bad "ssh=off telnet=off (leave one on)"; fi
NAMES=(); LOS=(); HIS=()                  # no two decoys may share a port (FTP also uses the 20 ports after its own)
if [ "$SSH_ON" = yes ]; then NAMES+=(SSH); LOS+=("$SSH_PORT"); HIS+=("$SSH_PORT"); fi
if [ "$TELNET_ON" = yes ]; then NAMES+=(Telnet); LOS+=("$TELNET_PORT"); HIS+=("$TELNET_PORT"); fi
if [ "$FTP_ON" = yes ]; then NAMES+=(FTP); LOS+=("$FTP_PORT"); HIS+=("$((FTP_PORT + 20))"); fi
if [ "$HTTP_ON" = yes ]; then NAMES+=(web); LOS+=("$HTTP_PORT"); HIS+=("$HTTP_PORT"); fi
for ((i = 0; i < ${#NAMES[@]}; i++)); do
  for ((j = i + 1; j < ${#NAMES[@]}; j++)); do
    if [ "${LOS[i]}" -le "${HIS[j]}" ] && [ "${LOS[j]}" -le "${HIS[i]}" ]; then bad "the ${NAMES[i]} and ${NAMES[j]} ports overlap"; fi
  done
done

case "$PROFILE" in
  debian12)   SSHV="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"; KERNEL="6.1.0-18-amd64"; BUILD="#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)";;
  debian11)   SSHV="SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"; KERNEL="5.10.0-28-amd64"; BUILD="#1 SMP Debian 5.10.209-2 (2024-01-31)";;
  ubuntu2204) SSHV="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"; KERNEL="5.15.0-91-generic"; BUILD="#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";;
  *)          SSHV=""; KERNEL=""; BUILD="";;
esac

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
  if [ -n "$FP" ]; then echo "==> Trusting the LanPulse certificate with fingerprint: $FP"; fi
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
if [ "$FTP_ON" = yes ] || [ "$HTTP_ON" = yes ]; then
  if [ -n "$TRAP_B64" ]; then
    printf '%s' "$TRAP_B64" | base64 -d > "$DIR/lanpulse-trap.py"
  elif [ -f "$HERE/lanpulse-trap.py" ]; then
    cp "$HERE/lanpulse-trap.py" "$DIR/lanpulse-trap.py"
  else
    echo "lanpulse-trap.py not found next to this script." >&2; exit 1
  fi
  chmod 644 "$DIR/lanpulse-trap.py"
fi

umask 077
cat > "$DIR/.env" <<ENV
LANPULSE_URL=$URL
LANPULSE_KEY=$KEY
LANPULSE_FINGERPRINT=$FP
SENSOR_NAME=$(hostname)
ENV
umask 022

# Pieces of the compose file that depend on the settings.
NL=$'\n'
PORTS=""; COWENV=""; COWVOL=""; LIMITS=""; TRAPSVC=""; FWDVOL=""; FWDENV=""; FWDDEP=""; TRAPVOL=""
if [ "$SSH_ON" = yes ]; then PORTS="${PORTS}      - \"$SSH_PORT:2222\"$NL"; fi
if [ "$TELNET_ON" = yes ]; then PORTS="${PORTS}      - \"$TELNET_PORT:2223\"$NL"; fi
COWENV="${COWENV}      COWRIE_SSH_ENABLED: \"$SSH_ON\"$NL      COWRIE_TELNET_ENABLED: \"$TELNET_ON\"$NL"
COWENV="${COWENV}      COWRIE_HONEYPOT_HOSTNAME: \"$FAKE_HOST\"$NL"
if [ -n "$FILE_MB" ]; then COWENV="${COWENV}      COWRIE_HONEYPOT_DOWNLOAD_LIMIT_SIZE: \"$((FILE_MB * 1048576))\"$NL"; fi
if [ "$LOGIN" = random ]; then
  COWENV="${COWENV}      COWRIE_HONEYPOT_AUTH_CLASS: \"AuthRandom\"$NL      COWRIE_HONEYPOT_AUTH_CLASS_PARAMETERS: \"2, 5, 10\"$NL"
fi
if [ -n "$KERNEL" ]; then
  COWENV="${COWENV}      COWRIE_SHELL_KERNEL_VERSION: \"$KERNEL\"$NL      COWRIE_SHELL_KERNEL_BUILD_STRING: \"$BUILD\"$NL"
  COWENV="${COWENV}      COWRIE_SHELL_HARDWARE_PLATFORM: \"x86_64\"$NL      COWRIE_SHELL_OPERATING_SYSTEM: \"GNU/Linux\"$NL"
  COWENV="${COWENV}      COWRIE_SSH_VERSION: \"$SSHV\"$NL"
fi
if [ -n "$MEM_MB" ]; then LIMITS="${LIMITS}    mem_limit: ${MEM_MB}m$NL"; fi
if [ -n "$CPU_PCT" ]; then LIMITS="${LIMITS}    cpus: \"$((CPU_PCT / 100)).$(printf '%02d' $((CPU_PCT % 100)))\"$NL"; fi

if [ "$FTP_ON" = yes ] || [ "$HTTP_ON" = yes ]; then
  TRAPENV="      PYTHONDONTWRITEBYTECODE: \"1\"$NL      TRAP_HOME: \"/trap\"$NL"
  TRAPPORTS=""
  if [ "$FTP_ON" = yes ]; then
    TRAPENV="${TRAPENV}      TRAP_FTP_PORT: \"$FTP_PORT\"$NL"
    TRAPPORTS="${TRAPPORTS}      - \"$FTP_PORT:$FTP_PORT\"$NL      - \"$((FTP_PORT + 1))-$((FTP_PORT + 20)):$((FTP_PORT + 1))-$((FTP_PORT + 20))\"$NL"
  fi
  if [ "$HTTP_ON" = yes ]; then
    TRAPENV="${TRAPENV}      TRAP_HTTP_PORT: \"$HTTP_PORT\"$NL"
    TRAPPORTS="${TRAPPORTS}      - \"$HTTP_PORT:$HTTP_PORT\"$NL"
  fi
  if [ -n "$FILE_MB" ]; then TRAPENV="${TRAPENV}      TRAP_MAX_FILE_MB: \"$FILE_MB\"$NL"; fi
  TRAPSVC="  trap:${NL}    image: python:3.12-slim${NL}    restart: unless-stopped${NL}    command: [\"python\", \"-u\", \"/app/lanpulse-trap.py\"]${NL}    ports:${NL}${TRAPPORTS}    environment:${NL}${TRAPENV}    volumes:${NL}      - trap-var:/trap/var${NL}      - ./lanpulse-trap.py:/app/lanpulse-trap.py:ro${NL}    read_only: true${NL}    cap_drop:${NL}      - ALL${NL}    security_opt:${NL}      - no-new-privileges:true${NL}    mem_limit: 192m${NL}${NL}"
  FWDVOL="      - trap-var:/trap/var:ro$NL"
  FWDENV="      TRAP_HOME: /trap$NL"
  FWDDEP="      - trap$NL"
  TRAPVOL="  trap-var:$NL"
fi

# Which logins work: Cowrie reads etc/userdb.txt ("name:x:password", * matches anything).
rm -f "$DIR/userdb.txt"
case "$LOGIN" in
  any)  printf '# LanPulse: every login works\n*:x:*\n' > "$DIR/userdb.txt";;
  weak) { echo "# LanPulse: only common default logins work"
          printf '%s\n' root:x:root root:x:admin root:x:password root:x:123456 root:x:toor admin:x:admin admin:x:password admin:x:1234 \
            user:x:user pi:x:raspberry ubnt:x:ubnt support:x:support guest:x:guest test:x:test ubuntu:x:ubuntu
        } > "$DIR/userdb.txt";;
esac
if [ -f "$DIR/userdb.txt" ]; then
  chmod 644 "$DIR/userdb.txt"
  COWVOL="      - ./userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro$NL"
fi

cat > "$DIR/docker-compose.yml" <<YML
services:
  cowrie:
    image: cowrie/cowrie:latest
    restart: unless-stopped
    ports:
${PORTS}    environment:
${COWENV}      COWRIE_OUTPUT_JSONLOG_ENABLED: "yes"
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var
${COWVOL}    security_opt:
      - no-new-privileges:true
${LIMITS}
${TRAPSVC}  forwarder:
    image: python:3.12-slim
    restart: unless-stopped
    depends_on:
      - cowrie
${FWDDEP}    command: ["python", "-u", "/app/lanpulse-forwarder.py"]
    env_file: .env
    environment:
      COWRIE_HOME: /cowrie/cowrie-git
${FWDENV}      STATE_FILE: /state/state.json
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var:ro
${FWDVOL}      - forwarder-state:/state
      - ./lanpulse-forwarder.py:/app/lanpulse-forwarder.py:ro
    cap_drop:
      - ALL
    cap_add:
      - DAC_READ_SEARCH
    security_opt:
      - no-new-privileges:true

volumes:
  cowrie-var:
${TRAPVOL}  forwarder-state:
YML

echo "==> Starting the containers"
cd "$DIR"
$COMPOSE up -d

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Done. This sensor looks like '$FAKE_HOST' and listens on:"
if [ "$SSH_ON" = yes ]; then echo "  SSH    port $SSH_PORT    (test: ssh -p $SSH_PORT root@$IP)"; else echo "  SSH    off"; fi
if [ "$TELNET_ON" = yes ]; then echo "  Telnet port $TELNET_PORT    (test: telnet $IP $TELNET_PORT)"; else echo "  Telnet off"; fi
if [ "$FTP_ON" = yes ]; then echo "  FTP    port $FTP_PORT, uploads use $((FTP_PORT + 1))-$((FTP_PORT + 20))    (test: ftp $IP $FTP_PORT)"; fi
if [ "$HTTP_ON" = yes ]; then echo "  Web    port $HTTP_PORT    (test: curl http://$IP:$HTTP_PORT/)"; fi
cat <<DONE
Logs:   cd $DIR && $COMPOSE logs -f        Stop:   cd $DIR && $COMPOSE down
Next: forward ports 22 and 23 from the internet to the ports above on your router, and keep this machine
off your main LAN (a container shares the host's kernel).
DONE
