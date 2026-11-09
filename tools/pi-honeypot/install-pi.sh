#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
#
# Sets up a Cowrie SSH/Telnet honeypot on a Raspberry Pi (Raspberry Pi OS / Debian / Ubuntu) and a small forwarder
# that sends every attacker session and captured file to your LanPulse server.
#
#   sudo ./install-pi.sh https://192.168.0.208:8080 <sensor-key> [server-certificate-sha256] [setting=value ...]
#
# The sensor key comes from LanPulse > Honeypot > Add sensor (which also gives you a ready-made one-line command).
# Cowrie listens on ports 2222 (SSH) and 2223 (Telnet). Your Pi's own SSH on port 22 is NOT touched; forward the
# internet-facing ports 22/23 to 2222/2223 on your router instead (see README.md).
#
# Optional settings (the Customize section of Add sensor writes these into the command; all have a default):
#   ssh=off  telnet=off            turn one of the decoys off
#   ssh_port=N  telnet_port=N      ports to listen on, 1024-65535 (default 2222 and 2223)
#   ftp=on  ftp_port=N             also run the FTP decoy that keeps uploaded files (default off; port 2121 and the 20 after it)
#   http=on  http_port=N           also run the web decoy that logs exploit attempts and keeps uploads (default off; port 2180)
#   hostname=NAME                  name the attacker sees in the shell prompt (default svr04)
#   profile=debian12|debian11|ubuntu2204   what uname and the SSH banner claim (default: Cowrie's own)
#   login=any|random|weak          any = every login works; random = works after 2-5 tries; weak = only common passwords
#   file_mb=N                      biggest file to keep, 1-5 MB
#   mem_mb=N  cpu_pct=N            cap Cowrie's memory (64-4096 MB) and CPU (10-100 %)
#   keep_days=N  disk_mb=N         delete captures older than N days (default 30); keep the captures under N MB
# Running the command again with different settings changes them.
set -euo pipefail

# LanPulse fills this in when it serves this script (Honeypot > Add sensor); empty when run from a git checkout.
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
FILE_MB=""; MEM_MB=""; CPU_PCT=""; KEEP_DAYS=30; DISK_MB=""; OPTS_GIVEN=0
bad() { echo "Unknown or invalid setting: $1" >&2; exit 2; }
num() {                                   # name value min max: digits only, within range
  case "$2" in ''|*[!0-9]*) bad "$1=$2";; esac
  if [ "${#2}" -gt 6 ] || [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then bad "$1=$2 (use $3 to $4)"; fi
}
for kv in "$@"; do
  OPTS_GIVEN=1
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
    keep_days)   num "$k" "$v" 1 365; KEEP_DAYS="$v";;
    disk_mb)     num "$k" "$v" 100 100000; DISK_MB="$v";;
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
COWRIE_USER=cowrie
HOME_DIR="/home/$COWRIE_USER"
COWRIE_DIR="$HOME_DIR/cowrie"
CFG="$COWRIE_DIR/etc/cowrie.cfg"
UDB="$COWRIE_DIR/etc/userdb.txt"
MARK="# Written by the LanPulse installer"

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

# The settings file is rewritten when it is missing, when we wrote it, or when you passed settings. A file you edited by
# hand is kept as cowrie.cfg.bak first.
REWRITE=0
if [ ! -f "$CFG" ] || [ "$OPTS_GIVEN" = 1 ] || grep -q "^$MARK" "$CFG"; then REWRITE=1; fi
if [ "$REWRITE" = 1 ]; then
  echo "==> Writing Cowrie settings"
  if [ -f "$CFG" ] && ! grep -q "^$MARK" "$CFG"; then cp -p "$CFG" "$CFG.bak"; fi
  {
    echo "$MARK. Running the Add sensor command again rewrites this file."
    echo "[honeypot]"
    echo "hostname = $FAKE_HOST"
    if [ -n "$FILE_MB" ]; then echo "download_limit_size = $((FILE_MB * 1048576))"; fi
    if [ "$LOGIN" = random ]; then echo "auth_class = AuthRandom"; echo "auth_class_parameters = 2, 5, 10"; fi
    if [ -n "$KERNEL" ]; then
      echo "[shell]"
      echo "kernel_version = $KERNEL"
      echo "kernel_build_string = $BUILD"
      echo "hardware_platform = x86_64"
      echo "operating_system = GNU/Linux"
    fi
    echo "[ssh]"
    echo "enabled = $SSH_ON"
    if [ -n "$SSHV" ]; then echo "version = $SSHV"; fi
    echo "listen_endpoints = tcp:$SSH_PORT:interface=0.0.0.0"
    echo "[telnet]"
    echo "enabled = $TELNET_ON"
    echo "listen_endpoints = tcp:$TELNET_PORT:interface=0.0.0.0"
    echo "[output_jsonlog]"
    echo "enabled = true"
  } > "$CFG"
  chown "$COWRIE_USER:$COWRIE_USER" "$CFG"

  # Which logins work: Cowrie reads etc/userdb.txt ("name:x:password", * matches anything, ! says no).
  if [ -f "$UDB" ] && ! grep -q '^# LanPulse' "$UDB"; then cp -p "$UDB" "$UDB.bak"; fi
  case "$LOGIN" in
    any)  printf '# LanPulse: every login works\n*:x:*\n' > "$UDB";;
    weak) cat > "$UDB" <<'USERS'
# LanPulse: only common default logins work
root:x:root
root:x:admin
root:x:password
root:x:123456
root:x:toor
admin:x:admin
admin:x:password
admin:x:1234
user:x:user
pi:x:raspberry
ubnt:x:ubnt
support:x:support
guest:x:guest
test:x:test
ubuntu:x:ubuntu
USERS
          ;;
    *)    if [ -f "$UDB" ] && grep -q '^# LanPulse' "$UDB"; then rm -f "$UDB"; fi;;
  esac
  if [ -f "$UDB" ]; then chown "$COWRIE_USER:$COWRIE_USER" "$UDB"; fi
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
TRAP_ON=no; TRAP_ENV_LINE=""
if [ "$FTP_ON" = yes ] || [ "$HTTP_ON" = yes ]; then TRAP_ON=yes; TRAP_ENV_LINE="TRAP_HOME=$COWRIE_DIR"; fi
umask 077
cat > /etc/lanpulse-forwarder.env <<ENV
LANPULSE_URL=$URL
LANPULSE_KEY=$KEY
LANPULSE_FINGERPRINT=$FP
COWRIE_HOME=$COWRIE_DIR
SENSOR_NAME=$(hostname)
${TRAP_ENV_LINE}
ENV
chmod 600 /etc/lanpulse-forwarder.env
umask 022

if [ "$TRAP_ON" = yes ]; then
  echo "==> Installing the FTP/web decoys"
  if [ -n "$TRAP_B64" ]; then
    printf '%s' "$TRAP_B64" | base64 -d > /usr/local/lib/lanpulse-forwarder/lanpulse-trap.py
  elif [ -f "$HERE/lanpulse-trap.py" ]; then
    cp "$HERE/lanpulse-trap.py" /usr/local/lib/lanpulse-forwarder/lanpulse-trap.py
  else
    echo "lanpulse-trap.py not found next to this script." >&2; exit 1
  fi
  chmod 755 /usr/local/lib/lanpulse-forwarder/lanpulse-trap.py
  FTP_P=0; HTTP_P=0
  if [ "$FTP_ON" = yes ]; then FTP_P="$FTP_PORT"; fi
  if [ "$HTTP_ON" = yes ]; then HTTP_P="$HTTP_PORT"; fi
  cat > /etc/lanpulse-trap.env <<TENV
TRAP_HOME=$COWRIE_DIR
TRAP_FTP_PORT=$FTP_P
TRAP_HTTP_PORT=$HTTP_P
${FILE_MB:+TRAP_MAX_FILE_MB=$FILE_MB}
TENV
  cat > /etc/systemd/system/lanpulse-trap.service <<UNIT
[Unit]
Description=LanPulse FTP and web decoys
After=network.target

[Service]
User=$COWRIE_USER
EnvironmentFile=/etc/lanpulse-trap.env
ExecStart=/usr/bin/python3 /usr/local/lib/lanpulse-forwarder/lanpulse-trap.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$COWRIE_DIR/var
MemoryMax=192M
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT
else
  systemctl disable --now lanpulse-trap.service >/dev/null 2>&1 || true      # turned off again: stop and remove it
  rm -f /etc/systemd/system/lanpulse-trap.service /etc/lanpulse-trap.env
fi

LIMITS=""
if [ -n "$MEM_MB" ]; then LIMITS="${LIMITS}MemoryMax=${MEM_MB}M"$'\n'; fi
if [ -n "$CPU_PCT" ]; then LIMITS="${LIMITS}CPUQuota=${CPU_PCT}%"$'\n'; fi

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
${LIMITS}
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

# Captured files and logs pile up on the SD card: delete old ones every hour, and the oldest first when over the size limit.
rm -f /etc/cron.daily/cowrie-clean            # what older versions of this installer used
cat > /etc/lanpulse-cleanup.conf <<CONF
COWRIE_VAR=$COWRIE_DIR/var
KEEP_DAYS=$KEEP_DAYS
CAP_MB=${DISK_MB:-0}
CONF
chmod 644 /etc/lanpulse-cleanup.conf
cat > /usr/local/lib/lanpulse-forwarder/cowrie-clean.sh <<'CLEAN'
#!/bin/sh
# Deletes old Cowrie captures. Settings: /etc/lanpulse-cleanup.conf
. /etc/lanpulse-cleanup.conf
V="$COWRIE_VAR"
[ -d "$V" ] || exit 0
for d in "$V/lib/cowrie/downloads" "$V/lib/cowrie/tty" "$V/lib/trap/downloads"; do
  [ -d "$d" ] && find "$d" -type f -mtime +"$KEEP_DAYS" -delete
done
for d in "$V/log/cowrie" "$V/log/trap"; do
  [ -d "$d" ] && find "$d" -type f \( -name 'cowrie.json.*' -o -name 'cowrie.log.*' -o -name 'trap.json.*' \) -mtime +"$KEEP_DAYS" -delete
done
if [ "${CAP_MB:-0}" -gt 0 ]; then
  n=0
  while [ "$(du -sm "$V" | cut -f1)" -gt "$CAP_MB" ] && [ "$n" -lt 5000 ]; do
    f=$(find "$V/lib/cowrie/downloads" "$V/lib/cowrie/tty" "$V/lib/trap/downloads" "$V/log/cowrie" "$V/log/trap" -type f \
          \( -path '*/downloads/*' -o -path '*/tty/*' -o -name 'cowrie.json.*' -o -name 'cowrie.log.*' -o -name 'trap.json.*' \) \
          -printf '%T@ %p\n' 2>/dev/null | sort -n | head -n 1 | cut -d' ' -f2-)
    [ -n "$f" ] || break
    rm -f -- "$f"; n=$((n + 1))
  done
fi
exit 0
CLEAN
chmod 755 /usr/local/lib/lanpulse-forwarder/cowrie-clean.sh
cat > /etc/systemd/system/cowrie-clean.service <<UNIT
[Unit]
Description=Delete old Cowrie honeypot captures

[Service]
Type=oneshot
User=$COWRIE_USER
ExecStart=/bin/sh /usr/local/lib/lanpulse-forwarder/cowrie-clean.sh
NoNewPrivileges=yes
UNIT
cat > /etc/systemd/system/cowrie-clean.timer <<UNIT
[Unit]
Description=Delete old Cowrie honeypot captures every hour

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
UNIT

echo "==> Starting"
systemctl daemon-reload
systemctl enable cowrie.service lanpulse-forwarder.service cowrie-clean.timer >/dev/null 2>&1
if [ "$TRAP_ON" = yes ]; then
  systemctl enable lanpulse-trap.service >/dev/null 2>&1
  systemctl restart lanpulse-trap.service
fi
systemctl restart cowrie.service lanpulse-forwarder.service
systemctl start cowrie-clean.timer
sleep 3
systemctl --no-pager --lines=0 status cowrie.service lanpulse-forwarder.service || true

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Done. This sensor looks like '$FAKE_HOST' and listens on:"
if [ "$SSH_ON" = yes ]; then echo "  SSH    port $SSH_PORT    (test: ssh -p $SSH_PORT root@$IP)"; else echo "  SSH    off"; fi
if [ "$TELNET_ON" = yes ]; then echo "  Telnet port $TELNET_PORT    (test: telnet $IP $TELNET_PORT)"; else echo "  Telnet off"; fi
if [ "$FTP_ON" = yes ]; then echo "  FTP    port $FTP_PORT, uploads use $((FTP_PORT + 1))-$((FTP_PORT + 20))    (test: ftp $IP $FTP_PORT)"; fi
if [ "$HTTP_ON" = yes ]; then echo "  Web    port $HTTP_PORT    (test: curl http://$IP:$HTTP_PORT/)"; fi
cat <<DONE
Then open LanPulse > Honeypot > Captured attacks and malware: the session should appear within a few seconds.
If it does not, look at:   journalctl -u lanpulse-forwarder -n 30    and    journalctl -u cowrie -n 30
Next: forward ports 22 and 23 from the internet to the ports above on your router, and read README.md first
(the Pi should sit on its own network so a break-in cannot reach the rest of your LAN).
DONE
