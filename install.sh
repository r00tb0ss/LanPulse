#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
# LanPulse installer for Ubuntu / Debian.
# Usage:  sudo ./install.sh            (installs to /opt/lanpulse, runs on port 8080)
#         sudo PORT=9000 ./install.sh  (custom port)
# Re-running it upgrades an existing install and keeps your devices, history and settings.
#         sudo ./install.sh --upgrade  (no questions; used by Settings > Update in the dashboard)
set -euo pipefail

UPGRADE=""
[[ "${1:-}" == "--upgrade" ]] && UPGRADE=1

if [[ $EUID -ne 0 ]]; then echo "Please run with sudo: sudo ./install.sh"; exit 1; fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST=/opt/lanpulse
PORT="${PORT:-8080}"
if [[ -f /etc/default/lanpulse ]]; then           # keep the port an existing install already uses
  P=$(grep -oE -- '--port [0-9]+' /etc/default/lanpulse | awk '{print $2}' | head -1 || true)
  [[ -n "${P:-}" ]] && PORT=$P
fi
VIS_VER=9.1.9
FA_VER=6.5.1
CDN=https://cdnjs.cloudflare.com/ajax/libs

echo "==> Installing system packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip nmap avahi-utils \
  samba-common-bin curl openssl unzip >/dev/null

# ---- upgrade from the old NetMapper name: keep devices, history, settings, login and certificates
if [[ -d /opt/netmapper/data && ! -d "$DEST/data" ]]; then
  echo "==> Moving your NetMapper data to LanPulse"
  systemctl stop netmapper 2>/dev/null || true
  mkdir -p "$DEST"
  cp -a /opt/netmapper/data "$DEST/"
  if [[ -f /etc/default/netmapper && ! -f /etc/default/lanpulse ]]; then
    sed -e 's#/opt/netmapper#/opt/lanpulse#g' -e 's/NETMAPPER_ARGS/LANPULSE_ARGS/g' /etc/default/netmapper > /etc/default/lanpulse
  fi
fi
# fix settings files migrated by version 1.5/1.6, which kept the old variable name
if [[ -f /etc/default/lanpulse ]] && grep -q NETMAPPER_ARGS /etc/default/lanpulse; then
  sed -i 's/NETMAPPER_ARGS/LANPULSE_ARGS/g' /etc/default/lanpulse
fi
if [[ -f /etc/systemd/system/netmapper.service ]]; then
  echo "==> Removing the old NetMapper service"
  systemctl disable --now netmapper >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/netmapper.service /etc/cron.monthly/netmapper-geoip \
        /usr/local/sbin/netmapper-geoip /usr/local/sbin/netmapper-vendors
  systemctl daemon-reload
fi

echo "==> Copying files to $DEST"
mkdir -p "$DEST/data"
chmod 700 "$DEST/data"
if [[ "$SRC" != "$DEST" ]]; then
  cp -r "$SRC"/*.py "$SRC"/*.sh "$SRC"/requirements.txt "$SRC"/LICENSE "$SRC"/THIRD-PARTY-NOTICES.md "$SRC"/static "$DEST"/
  if [[ -f "$SRC/tools/lanpulse_backup.py" ]]; then
    mkdir -p "$DEST/tools"
    cp "$SRC/tools/lanpulse_backup.py" "$DEST/tools/"
  fi
  if [[ -d "$SRC/tools/pi-honeypot" ]]; then        # the honeypot sensor installers that Honeypot > Add sensor hands out
    mkdir -p "$DEST/tools"
    rm -rf "$DEST/tools/pi-honeypot"
    cp -r "$SRC/tools/pi-honeypot" "$DEST/tools/"
  fi
fi

echo "==> Downloading map and icon libraries (so the dashboard works without internet)"
V="$DEST/static/vendor"
mkdir -p "$V/fontawesome/css" "$V/fontawesome/webfonts"
fetch() { curl -fsSL --retry 2 "$1" -o "$2" || echo "    warning: couldn't download $(basename "$2"); the browser will use the CDN instead"; }
fetch "$CDN/vis-network/$VIS_VER/standalone/umd/vis-network.min.js" "$V/vis-network.min.js"
fetch "$CDN/echarts/5.4.3/echarts.min.js" "$V/echarts.min.js"
fetch "https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/js/world.js" "$V/world.js"
fetch "$CDN/font-awesome/$FA_VER/css/all.min.css" "$V/fontawesome/css/all.min.css"
for f in fa-solid-900 fa-regular-400 fa-brands-400 fa-v4compatibility; do
  for ext in woff2 ttf; do fetch "$CDN/font-awesome/$FA_VER/webfonts/$f.$ext" "$V/fontawesome/webfonts/$f.$ext"; done
done

echo "==> Downloading the GeoIP database (DB-IP City Lite, CC BY 4.0) for the attack map"
cat > /usr/local/sbin/lanpulse-geoip <<'GEO'
#!/usr/bin/env bash
# Refreshes LanPulse's offline GeoIP database (DB-IP City Lite, updated monthly).
set -u
ASN=/opt/lanpulse/data/dbip-asn-lite.mmdb
for m in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m)"; do
  if curl -fsSL --retry 2 "https://download.db-ip.com/free/dbip-asn-lite-$m.mmdb.gz" -o "$ASN.gz.tmp"; then
    gunzip -c "$ASN.gz.tmp" > "$ASN.tmp" && mv "$ASN.tmp" "$ASN" && rm -f "$ASN.gz.tmp" && echo "ASN database $m installed" && break
  fi
done
rm -f "$ASN.gz.tmp" "$ASN.tmp"
OUT=/opt/lanpulse/data/dbip-city-lite.mmdb
for m in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m)"; do
  if curl -fsSL --retry 2 "https://download.db-ip.com/free/dbip-city-lite-$m.mmdb.gz" -o "$OUT.gz.tmp"; then
    gunzip -c "$OUT.gz.tmp" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT" && rm -f "$OUT.gz.tmp" && echo "GeoIP database $m installed" && exit 0
  fi
done
rm -f "$OUT.gz.tmp" "$OUT.tmp"
echo "warning: couldn't download the GeoIP database; attacks won't be placed on the map"
GEO
# The GeoIP script exits early on success, so vendor lists get their own script.
cat > /usr/local/sbin/lanpulse-vendors <<'OUI'
#!/usr/bin/env bash
# Refreshes the IEEE MAC vendor registries LanPulse uses to name device makers.
D=/opt/lanpulse/data
for f in oui mam oui36; do
  curl -fsSL --retry 2 -A "Mozilla/5.0 (LanPulse)" "https://standards-oui.ieee.org/$( [ $f = oui ] && echo oui/oui.csv || echo $( [ $f = mam ] && echo oui28/mam.csv || echo oui36/oui36.csv ) )" -o "$D/$f.csv.tmp" \
    && mv "$D/$f.csv.tmp" "$D/$f.csv" || { rm -f "$D/$f.csv.tmp"; echo "warning: couldn't download IEEE $f list"; }
done
OUI
chmod +x /usr/local/sbin/lanpulse-vendors
echo "==> Downloading the IEEE MAC vendor lists"
/usr/local/sbin/lanpulse-vendors
chmod +x /usr/local/sbin/lanpulse-geoip
/usr/local/sbin/lanpulse-geoip
cat > /etc/cron.monthly/lanpulse-geoip <<'CRON'
#!/bin/sh
/usr/local/sbin/lanpulse-vendors >/dev/null 2>&1
/usr/local/sbin/lanpulse-geoip >/dev/null 2>&1 && systemctl restart lanpulse
CRON
chmod +x /etc/cron.monthly/lanpulse-geoip

echo "==> Creating Python environment"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

# ---- login
if [[ ! -f "$DEST/data/auth.json" && -z "$UPGRADE" ]]; then
  echo
  echo "==> Dashboard login"
  read -r -p "Require a username and password for the dashboard? [Y/n] " ans
  if [[ ! "$ans" =~ ^[Nn] ]]; then
    "$DEST/venv/bin/python" "$DEST/app.py" --data-dir "$DEST/data" --set-password
  else
    echo "    Skipped. You can set one later in the dashboard (gear icon > Login)."
  fi
fi

# ---- HTTPS (asked on a new install; after that it's a switch in Settings > System)
HTTPS_ARGS=""
if [[ ! -f /etc/default/lanpulse && ! -f "$DEST/data/settings.json" && -z "$UPGRADE" ]]; then
  echo
  read -r -p "Serve the dashboard over HTTPS with a self-signed certificate? [y/N] " ans
  if [[ "$ans" =~ ^[Yy] ]]; then
    IP=$(hostname -I | awk '{print $1}')
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=lanpulse" \
      -addext "subjectAltName=IP:$IP,DNS:$(hostname),DNS:localhost" \
      -keyout "$DEST/data/key.pem" -out "$DEST/data/cert.pem" 2>/dev/null
    chmod 600 "$DEST/data/key.pem"
    HTTPS_ARGS="--cert $DEST/data/cert.pem --key $DEST/data/key.pem"
    echo "    Your browser will warn about the certificate the first time; choose to continue."
  fi
fi

# ---- options live in the dashboard now (Settings > System). Move any from /etc/default/lanpulse into it once.
echo "==> Installing systemd service"
OLD_ARGS=""
FROM_FILE=""
if [[ -f /etc/default/lanpulse ]]; then
  OLD_ARGS=$(bash -c 'source /etc/default/lanpulse >/dev/null 2>&1; echo "${LANPULSE_ARGS:-}"')
  FROM_FILE=1
elif [[ ! -f "$DEST/data/settings.json" ]]; then
  OLD_ARGS="--host 0.0.0.0 --port $PORT $HTTPS_ARGS"
fi
IMPORT_ARGS=$(echo " $OLD_ARGS " | sed -E 's/ --data-dir +[^ ]+//g' | xargs || true)
if [[ -n "$IMPORT_ARGS" ]]; then
  [[ -n "$FROM_FILE" ]] && echo "    Moving your options from /etc/default/lanpulse into Settings > System"
  # shellcheck disable=SC2086
  "$DEST/venv/bin/python" "$DEST/app.py" --data-dir "$DEST/data" $IMPORT_ARGS --import-args >/dev/null \
    || echo "    warning: couldn't move the options; set them in Settings > System"
fi
cat > /etc/default/lanpulse <<EOF
# LanPulse's network, scanning and web server options are set in the dashboard: Settings > System.
# Locked out after changing the port or HTTPS? Run:
#   sudo $DEST/venv/bin/python $DEST/app.py --data-dir $DEST/data --reset-web && sudo systemctl restart lanpulse
LANPULSE_ARGS="--data-dir $DEST/data"
EOF
read -r PORT SCHEME < <("$DEST/venv/bin/python" - "$DEST/data/settings.json" <<'PY'
import json, sys
try:
    s = json.load(open(sys.argv[1])).get("system", {})
except Exception:
    s = {}
print(s.get("port", 8080), "https" if s.get("https") else "http")
PY
)
cat > /etc/systemd/system/lanpulse.service <<EOF
[Unit]
Description=LanPulse - real-time network mapper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DEST
EnvironmentFile=-/etc/default/lanpulse
ExecStart=$DEST/venv/bin/python $DEST/app.py \$LANPULSE_ARGS
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# ---- sandbox: LanPulse needs root-level network access (raw packets, port 514, OS detection), but nothing else.
# This keeps the rest of the system read-only to it and drops every other root power.
mkdir -p /etc/systemd/system/lanpulse.service.d "$DEST/data/home" /var/backups/lanpulse
chmod 700 /var/backups/lanpulse
cat > /etc/systemd/system/lanpulse.service.d/hardening.conf <<HARDEN
[Service]
Environment=HOME=$DEST/data/home
Environment=LANPULSE_BACKUP_DIR=/var/backups/lanpulse
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DEST/data /var/backups/lanpulse -/var/lib/samba -/var/cache/samba -/run/samba
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK AF_UNIX
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
HARDEN

systemctl daemon-reload
systemctl enable lanpulse.service >/dev/null 2>&1
if ! systemctl restart lanpulse.service; then
  echo "ERROR: LanPulse failed to start with systemd hardening enabled."
  echo "       The hardening configuration has been preserved."
  echo "       Inspect: sudo journalctl -u lanpulse -n 50"
  exit 1
fi
sleep 6
if ! systemctl is-active --quiet lanpulse.service; then
  echo "ERROR: LanPulse is not active with systemd hardening enabled."
  echo "       The hardening configuration has been preserved."
  echo "       Inspect: sudo journalctl -u lanpulse -n 50"
  exit 1
fi

# ---- in-dashboard updates (Settings > Update)
# The web app is sandboxed and can't change its own files. When you click Install, it drops a request file in its
# data folder; this separate root-only helper notices it, backs up the current version, installs the uploaded
# update, and rolls back automatically if anything fails.
mkdir -p "$DEST/data/update"
# A terminal install replaces whatever the dashboard was doing, so clear a leftover "Installing…" status.
if [[ -z "$UPGRADE" ]] && grep -qE '"state": "(installing|queued)"' "$DEST/data/update/status.json" 2>/dev/null; then
  rm -f "$DEST/data/update/status.json" "$DEST/data/update/request"
fi
# Written to a new file and moved into place: this install may be running FROM the old updater, and bash reads
# a script as it goes, so overwriting it in place would cut the updater off before it reports "done".
cat > /usr/local/sbin/lanpulse-update.new <<UPD
#!/usr/bin/env bash
# LanPulse updater: installs $DEST/data/update/incoming.zip (uploaded in Settings > Update).
# Everything is inside main() so bash reads the whole script before running any of it.
main() {
set -u
D=$DEST/data/update
LOG=\$D/log.txt
state() { printf '{"state": "%s", "message": "%s", "t": %s}\\n' "\$1" "\$2" "\$(date +%s)" > "\$D/status.json"; }
rm -f "\$D/request"
# Off switch only root can flip: sudo mv /etc/lanpulse/web-updates /etc/lanpulse/web-updates.off  (terminal installs still work)
[[ -f /etc/lanpulse/web-updates ]] || { state failed "Updates from the dashboard are turned off on this machine (/etc/lanpulse/web-updates is missing)."; exit 1; }
[[ -f "\$D/incoming.zip" ]] || { state failed "No update file was uploaded."; exit 1; }
[[ -f "\$D/incoming.zip.sha256" ]] || { state failed "The update has no SHA-256 verification file; it wasn't installed."; exit 1; }
if ! (cd "\$D" && sha256sum -c incoming.zip.sha256) >> "\$LOG" 2>&1; then
  state failed "The update failed SHA-256 verification and wasn't installed."; exit 1
fi
# Check again here, as root, before unpacking: only plain files under lanpulse/, no links or special files
if zipinfo "\$D/incoming.zip" 2>/dev/null | awk 'NR>2 && /^[-dlbcps?]/ {print substr(\$0,1,1)}' | grep -qv '^[-d]\$'; then
  state failed "The update contains links or special files, so it wasn't installed."; exit 1
fi
if unzip -Z1 "\$D/incoming.zip" 2>/dev/null | grep -qvE '^lanpulse/' || unzip -Z1 "\$D/incoming.zip" | grep -qE '(^|/)\.\.(/|\$)'; then
  state failed "The update has files outside the lanpulse folder, so it wasn't installed."; exit 1
fi
W=\$(mktemp -d)
trap 'rm -rf "\$W"' EXIT
state installing "Installing the update. LanPulse will restart in a minute or two."
(
  set -e
  echo "== LanPulse update \$(date) =="
# Create the rollback archive separately and verify it before replacing the
# last known-good archive or touching the installed application.
PREVIOUS_TMP="\$D/previous.tgz.tmp.\$\$"
rm -f "\$PREVIOUS_TMP"
echo "-- creating and verifying the rollback archive"
if ! tar -czf "\$PREVIOUS_TMP" -C / --exclude=opt/lanpulse/data opt/lanpulse etc/default/lanpulse etc/systemd/system/lanpulse.service etc/systemd/system/lanpulse.service.d >> "\$LOG" 2>&1 \
  || ! tar -tzf "\$PREVIOUS_TMP" >/dev/null 2>> "\$LOG" \
  || ! tar -tzf "\$PREVIOUS_TMP" 2>> "\$LOG" | grep -qx 'opt/lanpulse/app.py' \
  || ! tar -tzf "\$PREVIOUS_TMP" 2>> "\$LOG" | grep -q '^opt/lanpulse/venv/' \
  || ! tar -tzf "\$PREVIOUS_TMP" 2>> "\$LOG" | grep -qx 'etc/default/lanpulse' \
  || ! tar -tzf "\$PREVIOUS_TMP" 2>> "\$LOG" | grep -qx 'etc/systemd/system/lanpulse.service' \
  || ! tar -tzf "\$PREVIOUS_TMP" 2>> "\$LOG" | grep -qx 'etc/systemd/system/lanpulse.service.d/hardening.conf'; then
  rm -f "\$PREVIOUS_TMP"
  state failed "Could not create and verify the rollback archive. No application files were changed."
  exit 1
fi
if ! mv -f "\$PREVIOUS_TMP" "\$D/previous.tgz"; then
  rm -f "\$PREVIOUS_TMP"
  state failed "Could not save the verified rollback archive. No application files were changed."
  exit 1
fi
if (
  set -e
  echo "-- unpacking"
  unzip -q "\$D/incoming.zip" -d "\$W"
  test -f "\$W/lanpulse/install.sh"
  test -f "\$W/lanpulse/app.py"
  echo "-- installing"
  cd "\$W/lanpulse"
  bash ./install.sh --upgrade
) > "\$LOG" 2>&1 && systemctl is-active --quiet lanpulse; then
  rm -f "\$D/incoming.zip" "\$D/incoming.zip.sha256"
  state done "Update installed."
else
  echo "-- update failed: restoring the previous version" >> "\$LOG"
  if tar -xzf "\$D/previous.tgz" -C / >> "\$LOG" 2>&1 \
    && tar -dzf "\$D/previous.tgz" -C / >> "\$LOG" 2>&1 \
    && systemctl daemon-reload >> "\$LOG" 2>&1 \
    && systemctl restart lanpulse >> "\$LOG" 2>&1 \
    && systemctl is-active --quiet lanpulse; then
    state failed "The update failed. The previous version was restored and verified; see the log below."
  else
    state failed "The update failed and automatic rollback could not be verified. LanPulse may be unavailable; inspect the log and service status."
  fi
fi
)
}
main "\$@"; exit
UPD
if ! bash -n /usr/local/sbin/lanpulse-update.new; then
  echo "ERROR: generated LanPulse updater has invalid shell syntax; keeping the existing updater unchanged." >&2
  rm -f /usr/local/sbin/lanpulse-update.new
  exit 1
fi
chmod 755 /usr/local/sbin/lanpulse-update.new
mv -f /usr/local/sbin/lanpulse-update.new /usr/local/sbin/lanpulse-update
mkdir -p /etc/lanpulse
[[ -f /etc/lanpulse/web-updates.off ]] || touch /etc/lanpulse/web-updates   # leave it off if you turned it off
cat > /etc/systemd/system/lanpulse-update.service <<UNIT
[Unit]
Description=LanPulse updater (started from Settings > Update)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lanpulse-update
TimeoutStartSec=20min
UNIT
cat > /etc/systemd/system/lanpulse-update.path <<UNIT
[Unit]
Description=Watch for LanPulse update requests

[Path]
PathExists=$DEST/data/update/request
Unit=lanpulse-update.service

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now lanpulse-update.path >/dev/null 2>&1 || true

# ---- OpenVAS installer (Settings > Scanner): same pattern as the updater. Root-only helper + a path unit that fires
# when the dashboard writes a request file. It does nothing unless you press Install in Settings.
mkdir -p "$DEST/data/openvas"
sed "s#@DEST@#$DEST#g" "$DEST/openvas-helper.sh" > /usr/local/sbin/lanpulse-openvas.new
chmod 755 /usr/local/sbin/lanpulse-openvas.new
mv -f /usr/local/sbin/lanpulse-openvas.new /usr/local/sbin/lanpulse-openvas
cat > /etc/systemd/system/lanpulse-openvas.service <<UNIT
[Unit]
Description=LanPulse OpenVAS installer (started from Settings > Scanner)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lanpulse-openvas
TimeoutStartSec=60min
UNIT
cat > /etc/systemd/system/lanpulse-openvas.path <<UNIT
[Unit]
Description=Watch for LanPulse OpenVAS install requests

[Path]
PathExists=$DEST/data/openvas/request
Unit=lanpulse-openvas.service

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now lanpulse-openvas.path >/dev/null 2>&1 || true

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "==> Opening port $PORT in ufw (local networks only)"
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    ufw allow from "$net" to any port "$PORT" proto tcp >/dev/null
    ufw allow from "$net" to any port 514 proto udp >/dev/null      # router firewall logs
  done
fi

IP=$(hostname -I | awk '{print $1}')
echo
echo "LanPulse is running."
echo "  Open from any computer on your network:  $SCHEME://$IP:$PORT"
echo "  Logs:            sudo journalctl -u lanpulse -f"
echo "  Change login:    sudo $DEST/venv/bin/python $DEST/app.py --data-dir $DEST/data --set-password"
echo "  Settings:        in the dashboard, Settings > System"
echo
echo "Attack map: send your router's firewall log to $IP UDP port 514 (remote syslog),"
echo "  and/or POST honeypot events to /api/threats/ingest. Details in the Threats tab."
echo
echo "Devices found in the first scan are trusted automatically. Anything that joins later"
echo "shows a red dashed ring and can alert you. Set up alerts under the gear icon."
