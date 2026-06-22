#!/usr/bin/env bash
# sync_cowrie.sh — append Cowrie's new JSON log lines from the VPS so Wazuh's
# logcollector (which tails the local file by inode) sees continuous growth.
# Using rsync --append preserves the inode; a full replace (rsync -az) would
# swap the inode and silently break the tail.
set -uo pipefail
VPS_HOST="<sync-user>@<vps-host>"
VPS_PORT="2222"
SSH_KEY="/home/terickson/.ssh/vps_sync"
SSH_OPTS="-p ${VPS_PORT} -i ${SSH_KEY} -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
VPS_LOG="/opt/cowrie/logs/cowrie.json"
LOCAL_LOG="/opt/cowrie-logs/cowrie.json"

echo "[$(date -Is)] cowrie sync start"

# Sizes to detect daily rotation (remote smaller than local = rotated)
remote_size=$(ssh ${SSH_OPTS} "${VPS_HOST}" "stat -c%s '${VPS_LOG}' 2>/dev/null" || echo 0)
local_size=$(stat -c%s "${LOCAL_LOG}" 2>/dev/null || echo 0)

if [ -z "${remote_size}" ] || [ "${remote_size}" -eq 0 ]; then
    echo "[$(date -Is)] remote unreachable or empty (size=${remote_size}) — skipping run, NOT truncating local"
    exit 0
fi
if [ "${remote_size}" -lt "${local_size}" ]; then
    # Rotation happened on the VPS — the remote file restarted smaller.
    # Truncate local and pull fresh so we don't append onto stale data.
    echo "[$(date -Is)] rotation detected (remote ${remote_size} < local ${local_size}) — full re-pull"
    : > "${LOCAL_LOG}"
fi

# --append: transfer only the bytes beyond the current local size, appended in
# place (inode preserved -> Wazuh tail keeps working). No -z (append + compress
# don't mix reliably).
rsync --append --timeout=60 -e "ssh ${SSH_OPTS}" "${VPS_HOST}:${VPS_LOG}" "${LOCAL_LOG}"
rc=$?
echo "[$(date -Is)] cowrie sync done (rsync=${rc}, remote=${remote_size}, local_was=${local_size})"
/usr/bin/python3 /opt/cowrie-tools/pipeline/forward_cowrie.py
echo "[$(date -Is)] cowrie forward done"
exit 0
