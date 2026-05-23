#!/usr/bin/env bash
#
# Anglerfish AI — pull operational state off a running honeypot VM.
#
# Run on a host that has SSH access to the honeypot VM's service NIC.
# This is NOT the Proxmox host backup workflow (use vzdump for full-VM
# snapshots); this script pulls only the small files an operator would
# replay after a rebuild:
#
#   * /etc/anglerfish/anglerfish.env       (mode 0600)
#   * /etc/anglerfish/wizard.json          (operator answers)
#   * /var/lib/anglerfish/credentials.db   (AES-GCM encrypted at rest)
#   * /var/lib/anglerfish/sessions.jsonl   (session capture)
#   * /var/log/anglerfish/audit.jsonl      (audit trail)
#
# Output: a single tarball, GPG-encrypted to the operator's pubkey if
# one is supplied. SSHs with an operator key — never the bait NIC.
#
# Usage:
#     ./proxmox/backup.sh \
#         --host anglerfish-ops@10.0.0.42 \
#         --out  ./backups/anglerfish-2026-05-22.tar.gz \
#         [--gpg-recipient ops@example.com]
#
# Designed for pve-cron / Linux cron / systemd-timer.

set -euo pipefail

HOST=""
OUT=""
GPG_RECIPIENT=""
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=30"

usage() {
    sed -n '3,28p' "$0"
    exit "${1:-64}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)          HOST="$2"; shift 2 ;;
        --out)           OUT="$2"; shift 2 ;;
        --gpg-recipient) GPG_RECIPIENT="$2"; shift 2 ;;
        --ssh-opts)      SSH_OPTS="$2"; shift 2 ;;
        -h|--help)       usage 0 ;;
        *)               echo "unknown flag: $1" >&2; usage 64 ;;
    esac
done

[[ -z "${HOST}" ]] && { echo "--host is required" >&2; usage 64; }
[[ -z "${OUT}" ]]  && { echo "--out  is required" >&2; usage 64; }

if ! command -v ssh >/dev/null 2>&1; then
    echo "ssh is required" >&2; exit 1
fi
if [[ -n "${GPG_RECIPIENT}" ]] && ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required for --gpg-recipient" >&2; exit 1
fi

mkdir -p "$(dirname "${OUT}")"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

REMOTE_PATHS=(
    /etc/anglerfish/anglerfish.env
    /etc/anglerfish/wizard.json
    /var/lib/anglerfish/credentials.db
    /var/lib/anglerfish/sessions.jsonl
    /var/log/anglerfish/audit.jsonl
)

# Build a small tar on the remote side, then stream it back. Using
# ssh+tar instead of rsync keeps the dependency surface minimal and
# survives operators who have not enabled rsync on the VM.
# shellcheck disable=SC2029  # we intentionally interpolate the path list
ssh ${SSH_OPTS} "${HOST}" "sudo tar -czf - --ignore-failed-read ${REMOTE_PATHS[*]}" \
    > "${WORK}/anglerfish.tar.gz"

# Inspect what we got — fail loudly if the encrypted credentials DB
# isn't present, since silent-empty backups are the worst outcome.
if ! tar -tzf "${WORK}/anglerfish.tar.gz" | grep -q "anglerfish/credentials.db$"; then
    echo "[anglerfish-backup] WARNING: credentials.db not present in backup" >&2
fi

if [[ -n "${GPG_RECIPIENT}" ]]; then
    gpg --batch --yes --output "${OUT}.gpg" \
        --encrypt --recipient "${GPG_RECIPIENT}" "${WORK}/anglerfish.tar.gz"
    rm -f "${WORK}/anglerfish.tar.gz"
    echo "[anglerfish-backup] wrote ${OUT}.gpg"
else
    mv "${WORK}/anglerfish.tar.gz" "${OUT}"
    chmod 0600 "${OUT}"
    echo "[anglerfish-backup] wrote ${OUT}"
fi
