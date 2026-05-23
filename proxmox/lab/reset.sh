#!/usr/bin/env bash
# Roll the lab honeypot VM back to the named snapshot. Use this between
# attacker sessions so each study starts from an identical clean state.
#
# Usage:
#     sudo ./reset.sh <vmid> [snapshot-name]
#
# Default snapshot name is "clean". This stops the VM, restores from the
# snapshot, then starts the VM again. ALL changes since the snapshot are
# DISCARDED — including captured credentials, audit log, threat history.
# If you want to preserve them, run backup.sh from the parent directory
# first.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <vmid> [snapshot-name]" >&2
    exit 64
fi

VMID="$1"
SNAPNAME="${2:-clean}"

if ! command -v qm >/dev/null 2>&1; then
    echo "error: qm not on PATH — run on the Proxmox host" >&2
    exit 1
fi

if ! qm status "$VMID" >/dev/null 2>&1; then
    echo "error: VM $VMID does not exist" >&2
    exit 1
fi

if ! qm listsnapshot "$VMID" | awk '{print $1}' | grep -Fxq "$SNAPNAME"; then
    echo "error: snapshot '$SNAPNAME' does not exist on VM $VMID" >&2
    echo "available snapshots:" >&2
    qm listsnapshot "$VMID" >&2
    exit 1
fi

read -r -p "[lab] roll VM $VMID back to '$SNAPNAME'? This DISCARDS all changes. [y/N] " ack
if [[ "$ack" != "y" && "$ack" != "Y" ]]; then
    echo "[lab] aborted"
    exit 0
fi

if [[ "$(qm status "$VMID" | awk '{print $2}')" == "running" ]]; then
    echo "[lab] stopping VM $VMID"
    qm stop "$VMID"
fi

echo "[lab] rolling back VM $VMID to '$SNAPNAME'"
qm rollback "$VMID" "$SNAPNAME"

echo "[lab] starting VM $VMID"
qm start "$VMID"

echo "[lab] done. VM $VMID is back at the '$SNAPNAME' state."
