#!/usr/bin/env bash
#
# Boot the Anglerfish AI ISO in QEMU for an interactive smoke test.
#
# What this gives you:
#   * Two virtual NICs — a "bait" NIC reachable from the host on
#     localhost:2222 (Cowrie's SSH listener) and a "service" NIC
#     reachable on localhost:8420 (the dashboard).
#   * Serial console multiplexed onto your tty so you can drive the
#     first-boot wizard.
#   * A persistent 20 GB qcow2 disk so the wizard's answers survive
#     reboots.
#
# Usage:
#     ./iso/smoke.sh path/to/anglerfish-ai-<version>.iso [--memory 4G] [--cpus 4]
#
# After boot:
#   1. Run the wizard on the serial console (tty mux into ./serial.log).
#   2. `ssh -p 2222 root@127.0.0.1` to drive the bait NIC.
#   3. `curl http://127.0.0.1:8420/api/health` to hit the dashboard.
#   4. `Ctrl-A x` to terminate QEMU cleanly.

set -euo pipefail

usage() {
    sed -n '3,21p' "$0"
    exit "${1:-64}"
}

if [[ $# -lt 1 ]]; then
    usage
fi

ISO="$1"
shift

MEMORY="4G"
CPUS="4"
SSH_HOST_PORT="2222"
DASHBOARD_HOST_PORT="8420"
DISK_SIZE="20G"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --memory)              MEMORY="$2"; shift 2 ;;
        --cpus)                CPUS="$2"; shift 2 ;;
        --ssh-port)            SSH_HOST_PORT="$2"; shift 2 ;;
        --dashboard-port)      DASHBOARD_HOST_PORT="$2"; shift 2 ;;
        --disk-size)           DISK_SIZE="$2"; shift 2 ;;
        -h|--help)             usage 0 ;;
        *)                     echo "unknown flag: $1" >&2; usage 64 ;;
    esac
done

if [[ ! -f "${ISO}" ]]; then
    echo "ISO not found: ${ISO}" >&2
    exit 1
fi

for tool in qemu-system-x86_64 qemu-img; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "missing required tool: ${tool}" >&2
        echo "On Debian/Ubuntu: apt install qemu-system-x86 qemu-utils" >&2
        exit 1
    fi
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_DIR="${HERE}/smoke"
DISK="${SMOKE_DIR}/anglerfish.qcow2"
SERIAL_LOG="${SMOKE_DIR}/serial.log"

mkdir -p "${SMOKE_DIR}"

if [[ ! -f "${DISK}" ]]; then
    qemu-img create -f qcow2 "${DISK}" "${DISK_SIZE}"
fi

cat <<EOF
[anglerfish-smoke] booting ${ISO}
[anglerfish-smoke] disk:           ${DISK} (${DISK_SIZE})
[anglerfish-smoke] memory / cpus:  ${MEMORY} / ${CPUS}
[anglerfish-smoke] bait NIC (ssh): host ${SSH_HOST_PORT} -> guest 2222
[anglerfish-smoke] service NIC:    host ${DASHBOARD_HOST_PORT} -> guest 8420
[anglerfish-smoke] serial log:     ${SERIAL_LOG}
[anglerfish-smoke] exit with: Ctrl-A x
EOF

# Two user-mode networking stacks — one per NIC. The bait NIC publishes
# Cowrie's SSH listener (host port 2222 → guest 2222); the service NIC
# publishes the dashboard (host port 8420 → guest 8420). Both stacks are
# isolated from each other and from the host's LAN, which matches the
# production split.
exec qemu-system-x86_64 \
    -name "anglerfish-smoke" \
    -machine type=q35,accel=kvm:hvf:tcg \
    -m "${MEMORY}" \
    -smp "cpus=${CPUS}" \
    -drive "file=${DISK},if=virtio,format=qcow2" \
    -cdrom "${ISO}" \
    -boot order=dc \
    -netdev "user,id=bait,hostfwd=tcp:127.0.0.1:${SSH_HOST_PORT}-:2222" \
    -device "virtio-net-pci,netdev=bait,mac=52:54:00:ba:17:01" \
    -netdev "user,id=service,hostfwd=tcp:127.0.0.1:${DASHBOARD_HOST_PORT}-:8420,net=10.0.2.0/24" \
    -device "virtio-net-pci,netdev=service,mac=52:54:00:5e:01:01" \
    -nographic \
    -serial "mon:stdio" \
    -chardev "file,id=seriallog,path=${SERIAL_LOG}" \
    -serial "chardev:seriallog"
