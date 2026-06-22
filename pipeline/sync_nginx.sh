#!/usr/bin/env bash
# sync_nginx.sh — pull nginx access log from VPS, then parse for Wazuh.
# Mirrors the cowrie-sync pattern: rotation guard, --append to preserve inode
# so Wazuh logcollector tail is not disrupted. Runs via nginx-sync.timer every 5 min.
#
# Safety: if the VPS is unreachable or reports size 0, we skip entirely —
# the local access.log is left untouched and the next cron picks up where it left off.
#
# Author: Tyce Erickson · CMU MSISPM Portfolio · Project 4

set -uo pipefail

VPS_HOST="<sync-user>@<vps-host>"
VPS_PORT="2222"
SSH_KEY="/home/terickson/.ssh/vps_sync"
SSH_OPTS="-p ${VPS_PORT} -i ${SSH_KEY} -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

VPS_NGINX_DIR="/opt/cowrie/nginx-logs"
VPS_ACCESS_LOG="${VPS_NGINX_DIR}/access.log"

LOCAL_NGINX_DIR="/opt/cowrie-logs/nginx"
LOCAL_ACCESS_LOG="${LOCAL_NGINX_DIR}/access.log"

PARSER="/opt/cowrie-tools/pipeline/parse_nginx.py"

mkdir -p "${LOCAL_NGINX_DIR}"

echo "[$(date -Is)] nginx sync start"

# ── Reachability guard ────────────────────────────────────────────────────────
# If the VPS is unreachable or returns size 0, skip this run entirely.
# Never truncate the local file on a failed SSH — same guard as sync_cowrie.sh.
remote_size=$(ssh ${SSH_OPTS} "${VPS_HOST}" "stat -c%s '${VPS_ACCESS_LOG}' 2>/dev/null" || echo 0)

if [ -z "${remote_size}" ] || [ "${remote_size}" -eq 0 ]; then
    echo "[$(date -Is)] remote unreachable or empty (size=${remote_size}) — skipping run, NOT touching local"
    exit 0
fi

# ── Rotation guard ────────────────────────────────────────────────────────────
# If remote access.log is smaller than local, logrotate ran on the VPS.
# Truncate local (same inode preserved) and do a full re-pull of the active log.
local_size=$(stat -c%s "${LOCAL_ACCESS_LOG}" 2>/dev/null || echo 0)

if [ "${remote_size}" -lt "${local_size}" ]; then
    echo "[$(date -Is)] rotation detected (remote ${remote_size} < local ${local_size}) — truncating local and re-pulling"
    : > "${LOCAL_ACCESS_LOG}"
fi

# ── Sync active access.log (append-only, inode preserved) ────────────────────
rsync --append --timeout=60 -e "ssh ${SSH_OPTS}" \
    "${VPS_HOST}:${VPS_ACCESS_LOG}" "${LOCAL_ACCESS_LOG}"
rc_access=$?

if [ $rc_access -ne 0 ]; then
    echo "[$(date -Is)] WARN: access.log rsync failed (rc=${rc_access}) — parsing existing copy"
fi

# ── Sync rotated files (static once rotated; --ignore-existing = no re-pull) ──
# Covers access.log.1 and access.log.*.gz needed for parse_nginx.py's 25h lookback.
rsync -az --ignore-existing --exclude="access.log" --exclude="error.log" \
    --timeout=60 -e "ssh ${SSH_OPTS}" \
    "${VPS_HOST}:${VPS_NGINX_DIR}/" "${LOCAL_NGINX_DIR}/"
rc_rot=$?

echo "[$(date -Is)] nginx sync done (access=${rc_access} rotated=${rc_rot}, remote=${remote_size}, local_was=${local_size})"

# ── Parse → Wazuh feed ───────────────────────────────────────────────────────
/usr/bin/python3 "${PARSER}"
rc_parse=$?

echo "[$(date -Is)] nginx parse done (rc=${rc_parse})"
exit 0
