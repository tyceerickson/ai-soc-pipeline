#!/usr/bin/env bash
#
# sync_dionaea.sh — pull Dionaea data from the VPS, then parse it for Wazuh.
# Run on the home server by the dionaea-sync systemd timer (every 15 min).
#
# 1. rsync the Dionaea SQLite DB + captured binaries from the VPS (key auth)
# 2. run parse_dionaea.py (which emits Wazuh events + archives new samples)
#
# All output goes to journald via the .service unit.
#
# Author: Tyce Erickson · CMU MSISPM Portfolio · Project 4
#
# NOTE: Host, port, and key path are read from the environment so no
# infrastructure details are committed. Set them in the systemd unit
# (config/dionaea-sync.service) or a local env file:
#   VPS_HOST=user@<vps-host-or-tailscale-name>
#   VPS_PORT=<ssh-port>
#   SSH_KEY=/path/to/private_key

set -uo pipefail

VPS_HOST="${VPS_HOST:-user@vps-host.example}"
VPS_PORT="${VPS_PORT:-22}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vps_sync}"
SSH_OPTS="-p ${VPS_PORT} -i ${SSH_KEY} -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

VPS_SQLITE="${VPS_SQLITE:-/opt/cowrie/dionaea-data/dionaea.sqlite}"
VPS_BINARIES="${VPS_BINARIES:-/opt/cowrie/dionaea-data/binaries/}"

LOCAL_DIR="/opt/cowrie-logs/dionaea"
LOCAL_BINARIES="${LOCAL_DIR}/binaries/"
PARSER="/opt/cowrie-tools/pipeline/parse_dionaea.py"

mkdir -p "${LOCAL_DIR}" "${LOCAL_BINARIES}"

echo "[$(date -Is)] sync start"

# 1a. SQLite DB (small, changes every run)
rsync -az --timeout=60 -e "ssh ${SSH_OPTS}" \
    "${VPS_HOST}:${VPS_SQLITE}" "${LOCAL_DIR}/dionaea.sqlite"
rc_db=$?
if [ $rc_db -ne 0 ]; then
    echo "[$(date -Is)] WARN: sqlite rsync failed (rc=${rc_db}) — will parse existing copy"
fi

# 1b. Captured binaries (append-only set; --ignore-existing keeps it cheap and
# never re-pulls a sample we already have)
rsync -az --timeout=120 --ignore-existing -e "ssh ${SSH_OPTS}" \
    "${VPS_HOST}:${VPS_BINARIES}" "${LOCAL_BINARIES}"
rc_bin=$?
if [ $rc_bin -ne 0 ]; then
    echo "[$(date -Is)] WARN: binaries rsync failed (rc=${rc_bin}) — parser will fall back to md5 for unsynced files"
fi

# 2. Parse -> Wazuh feed (+ archive). VT_API_KEY (if set in the .service) is inherited.
/usr/bin/python3 "${PARSER}"
rc_parse=$?

echo "[$(date -Is)] sync done (db=${rc_db} bin=${rc_bin} parse=${rc_parse})"
exit 0
