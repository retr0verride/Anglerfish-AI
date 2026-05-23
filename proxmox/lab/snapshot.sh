#!/usr/bin/env bash
# Take a "clean" snapshot of the lab honeypot VM. Pair with reset.sh to
# roll back to this state between attacker sessions.
#
# Usage:
#     sudo ./snapshot.sh <vmid> [snapshot-name]
#
# Default snapshot name is "clean". If a snapshot of that name already
# exists, it's deleted first so the new one always reflects current state.
#
# Requires LVM-thin / ZFS / qcow2 storage. raw on directory storage does
# not support qm snapshot.

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

if qm listsnapshot "$VMID" | awk '{print $1}' | grep -Fxq "$SNAPNAME"; then
    echo "[lab] deleting existing snapshot '$SNAPNAME' on VM $VMID"
    qm delsnapshot "$VMID" "$SNAPNAME"
fi

echo "[lab] taking snapshot '$SNAPNAME' on VM $VMID"
qm snapshot "$VMID" "$SNAPNAME" --description "Anglerfish lab clean state $(date -Iseconds)"
echo "[lab] done. roll back with: sudo ./reset.sh $VMID $SNAPNAME"
