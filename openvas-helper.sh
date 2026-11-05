#!/bin/bash
# LanPulse OpenVAS installer (root-only). Started by lanpulse-openvas.path when the dashboard writes a request file
# (Settings > Scanner). Installs Docker (if missing) and the official Greenbone Community Edition containers, or removes them.
set -u
D=@DEST@/data/openvas
LOG=$D/log.txt
COMPOSE=$D/compose.yaml
PROJECT=greenbone-community-edition
URL=https://greenbone.github.io/docs/latest/_static/compose.yaml

state() {  # state <installing|done|failed> <message>
  printf '{"state": "%s", "message": "%s", "t": %s}\n' "$1" "$2" "$(date +%s)" > "$D/status.json.tmp" && mv -f "$D/status.json.tmp" "$D/status.json"
}
fail() { echo "!! $1" >> "$LOG"; state failed "$1 See the log below."; exit 1; }
dc() { docker compose -f "$COMPOSE" -p "$PROJECT" "$@"; }

[[ -f "$D/request" ]] || exit 0
ACTION=$(sed -n 's/.*"action": *"\([a-z]*\)".*/\1/p' "$D/request")
rm -f "$D/request"
: > "$LOG"; chmod 600 "$LOG"
exec >> "$LOG" 2>&1
echo "== OpenVAS $ACTION $(date) =="

if [[ "$ACTION" == "remove" ]]; then
  state installing "Removing OpenVAS…"
  [[ -f "$COMPOSE" ]] && dc down -v
  rm -rf "$D/gvmd" "$COMPOSE" "$D/admin.pw"
  state done "OpenVAS was removed."
  exit 0
fi
[[ "$ACTION" == "install" ]] || fail "Unknown request."

state installing "Checking this machine…"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
(( mem_mb >= 3500 )) || fail "OpenVAS needs about 4 GB of RAM and this machine has ${mem_mb} MB."
mkdir -p "$D"
free_gb=$(df -BG --output=avail /var/lib 2>/dev/null | tail -1 | tr -dc 0-9)
(( ${free_gb:-0} >= 15 )) || fail "OpenVAS needs about 15 GB of free disk space and this machine has ${free_gb:-0} GB."

if ! docker compose version >/dev/null 2>&1; then
  state installing "Installing Docker…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || fail "apt-get update failed."
  apt-get install -y -qq docker.io docker-compose-v2 || apt-get install -y -qq docker.io docker-compose-plugin \
    || fail "Couldn't install Docker with Compose from your package sources."
  systemctl enable --now docker || fail "Docker didn't start."
fi
docker compose version >/dev/null 2>&1 || fail "Docker Compose isn't available."

state installing "Downloading the Greenbone configuration…"
mkdir -p "$D/gvmd"
chmod 755 "$D/gvmd"
curl -fsSL --max-time 60 "$URL" -o "$COMPOSE.new" || fail "Couldn't download the Greenbone compose file from greenbone.github.io."
grep -q 'gvmd_socket_vol:/run/gvmd' "$COMPOSE.new" \
  || fail "Greenbone changed its compose file layout, so LanPulse can't connect it safely. Please report this."
# Put the gvmd control socket where LanPulse can reach it (the web UI stays on 127.0.0.1 only).
sed -i "s#gvmd_socket_vol:/run/gvmd#$D/gvmd:/run/gvmd#g" "$COMPOSE.new"
mv -f "$COMPOSE.new" "$COMPOSE"
chmod 600 "$COMPOSE"

state installing "Downloading and starting OpenVAS (several GB, this takes a while)…"
# Large downloads often fail once on a slow or flaky route to the registry; layers already fetched are kept, so retry.
pulled=""
for i in 1 2 3 4 5 6; do
  state installing "Downloading OpenVAS containers (attempt $i of 6; several GB, this takes a while)…"
  if dc pull; then pulled=1; break; fi
  echo "-- download attempt $i failed; retrying in 60 seconds"
  sleep 60
done
[[ -n "$pulled" ]] || fail "Downloading the Greenbone containers kept failing (the connection to registry.community.greenbone.net timed out). Check this server's internet access, DNS and IPv6, then press Install again; progress is kept."
dc up -d || fail "Starting the Greenbone containers failed."

state installing "Creating the admin login…"
PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
ok=""
for i in $(seq 1 60); do
  if dc exec -T -u gvmd gvmd gvmd --user=admin --new-password="$PW" >/dev/null 2>&1; then ok=1; break; fi
  sleep 10
done
[[ -n "$ok" ]] || fail "OpenVAS started but its admin account couldn't be set up."
umask 077
printf '%s' "$PW" > "$D/admin.pw"

state done "Installed. OpenVAS is now downloading its vulnerability feed, which takes 30 to 90 minutes the first time. Scans become available when it says Ready."
echo "== done =="
