#!/usr/bin/env bash
#
# Anglerfish AI — restore a backup tarball onto a fresh honeypot VM.
#
# Run on a host with SSH access to the (already-installed) VM. The
# remote VM must already have the package layout — i.e. it has booted,
# the wizard has run once (so /etc/anglerfish/ exists). This script
# overlays the backup files; it does NOT install the package.
#
# Restored files:
#   * /etc/anglerfish/anglerfish.env       — restored verbatim, 0600 root:root
#   * /etc/anglerfish/wizard.json          — restored verbatim, 0600 root:root
#   * /var/lib/anglerfish/credentials.db   — restored verbatim, 0600 anglerfish:anglerfish
#   * /var/lib/anglerfish/sessions.jsonl   — restored verbatim, 0600 anglerfish:anglerfish
#   * /var/log/anglerfish/audit.jsonl      — restored verbatim, 0640 anglerfish:anglerfish
#
# After restore the script restarts anglerfish-bridge + anglerfish-
# dashboard so they pick up the restored encryption key.
#
# Usage:
#     ./proxmox/restore.sh \
#         --host anglerfish-ops@10.0.0.42 \
#         --in   ./backups/anglerfish-2026-05-22.tar.gz \
#         [--gpg]

set -euo pipefail

HOST=""
IN=""
DECRYPT=0
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=yes"

usage() {
    sed -n '3,27p' "$0"
    exit "${1:-64}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)      HOST="$2"; shift 2 ;;
        --in)        IN="$2"; shift 2 ;;
        --gpg)       DECRYPT=1; shift ;;
        --ssh-opts)  SSH_OPTS="$2"; shift 2 ;;
        -h|--help)   usage 0 ;;
        *)           echo "unknown flag: $1" >&2; usage 64 ;;
    esac
done

[[ -z "${HOST}" ]] && { echo "--host is required" >&2; usage 64; }
[[ -z "${IN}" ]]   && { echo "--in is required"   >&2; usage 64; }
[[ ! -f "${IN}" ]] && { echo "input not found: ${IN}" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [[ "${DECRYPT}" -eq 1 ]]; then
    command -v gpg >/dev/null 2>&1 || { echo "gpg required for --gpg" >&2; exit 1; }
    gpg --batch --yes --output "${WORK}/anglerfish.tar.gz" --decrypt "${IN}"
    PAYLOAD="${WORK}/anglerfish.tar.gz"
else
    PAYLOAD="${IN}"
fi

if ! tar -tzf "${PAYLOAD}" | grep -q "anglerfish/anglerfish.env$"; then
    echo "[anglerfish-restore] WARNING: anglerfish.env not present in backup" >&2
fi

# The ssh command argument is a small bash script that reads the
# tarball from its own stdin (which is the local PAYLOAD streamed in
# via ssh's stdin). One round trip, single stdin source.
REMOTE_SCRIPT=$(cat <<'REMOTE'
set -euo pipefail
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
cat > "$TMP"
sudo systemctl stop anglerfish-bridge.service anglerfish-dashboard.service || true
sudo tar -xzf "$TMP" -C /
if [ -f /etc/anglerfish/anglerfish.env ]; then
    sudo chmod 0600 /etc/anglerfish/anglerfish.env
    sudo chown root:root /etc/anglerfish/anglerfish.env
fi
if [ -f /etc/anglerfish/wizard.json ]; then
    sudo chmod 0600 /etc/anglerfish/wizard.json
    sudo chown root:root /etc/anglerfish/wizard.json
fi
if [ -f /var/lib/anglerfish/credentials.db ]; then
    sudo chmod 0600 /var/lib/anglerfish/credentials.db
    sudo chown anglerfish:anglerfish /var/lib/anglerfish/credentials.db
fi
if [ -f /var/lib/anglerfish/sessions.jsonl ]; then
    sudo chmod 0600 /var/lib/anglerfish/sessions.jsonl
    sudo chown anglerfish:anglerfish /var/lib/anglerfish/sessions.jsonl
fi
if [ -f /var/log/anglerfish/audit.jsonl ]; then
    sudo chmod 0640 /var/log/anglerfish/audit.jsonl
    sudo chown anglerfish:anglerfish /var/log/anglerfish/audit.jsonl
fi
sudo systemctl start anglerfish-bridge.service anglerfish-dashboard.service
REMOTE
)

# The script is passed as ssh's command argument so the remote shell
# parses it; the payload (tarball) is streamed via ssh's stdin and
# captured inside the script with `cat > "$TMP"`. One round trip, one
# stdin source — no redirection conflict.
# shellcheck disable=SC2086  # SSH_OPTS is intentionally word-split
ssh ${SSH_OPTS} "${HOST}" "${REMOTE_SCRIPT}" < "${PAYLOAD}"

echo "[anglerfish-restore] restore complete; bridge + dashboard restarted on ${HOST}"
