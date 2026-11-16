#!/usr/bin/env bash
# LanPulse YARA setup helper. Invoked only by the root-owned systemd path unit.
set -euo pipefail
D=/opt/lanpulse/data/yara
LOG=$D/log.txt
STATUS=$D/status.json
mkdir -p "$D"
chmod 700 "$D"
state() { printf '{"state":"%s","message":"%s","t":%s}\n' "$1" "$2" "$(date +%s)" > "$STATUS.tmp"; chmod 600 "$STATUS.tmp"; mv -f "$STATUS.tmp" "$STATUS"; }
fail() { echo "!! $1" >> "$LOG"; state failed "$1"; exit 1; }
[[ -f "$D/request" ]] || exit 0
ACTION=$(python3 - "$D/request" <<'PY'
import json,sys
try:
 d=json.load(open(sys.argv[1])); print(d.get('action','') if isinstance(d,dict) else '')
except Exception: print('')
PY
)
rm -f "$D/request"
: > "$LOG"; chmod 600 "$LOG"
exec >> "$LOG" 2>&1
echo "== LanPulse YARA $ACTION $(date) =="
case "$ACTION" in
  install|repair)
    state installing "Installing or repairing YARA engine and managed rules…"
    /opt/lanpulse/venv/bin/pip install --disable-pip-version-check -q 'yara-python>=4.5.1' || fail "Could not install yara-python. Check Python build dependencies and internet access."
    /usr/local/sbin/lanpulse-yara-update || fail "YARA engine is installed, but rules could not be downloaded or validated. Check internet/DNS and retry."
    systemctl enable --now lanpulse-yara-update.timer || fail "Rules installed, but weekly update timer could not be enabled."
    state done "YARA engine and managed rules are installed and validated. Weekly updates are enabled."
    ;;
  update)
    state installing "Downloading and validating the latest YARA Forge Core rules…"
    /usr/local/sbin/lanpulse-yara-update || fail "YARA rule update failed. Last known-good rules were preserved; check the log and retry."
    state done "YARA Forge Core rules updated and validated."
    ;;
  schedule_on) systemctl enable --now lanpulse-yara-update.timer || fail "Could not enable weekly YARA updates."; state done "Weekly YARA rule updates are enabled." ;;
  schedule_off) systemctl disable --now lanpulse-yara-update.timer || fail "Could not disable weekly YARA updates."; state done "Weekly YARA rule updates are disabled. Manual updates remain available." ;;
  *) fail "Unknown YARA setup request." ;;
esac
