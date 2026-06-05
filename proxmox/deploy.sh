#!/usr/bin/env bash
#
# Anglerfish AI — Proxmox VM provisioning.
#
# Run this on a Proxmox host (not inside the honeypot VM). It will:
#
#   1. Ensure two Linux bridges exist: vmbr-bait and vmbr-service.
#      They MUST be backed by physical NICs that the operator has
#      already wired into ``/etc/network/interfaces`` — this script
#      refuses to add the bridges if the operator has not configured
#      them, because attaching a bridge to the wrong NIC could expose
#      the management plane to attacker traffic.
#
#   2. Upload the Anglerfish ISO to the Proxmox `local` storage if it
#      isn't already there.
#
#   3. Create a VM with `qm create` using the topology in
#      ./anglerfish.json (or whatever --template points at).
#
#   4. Print next-step instructions: start the VM, open the console,
#      complete the wizard.
#
# Usage:
#     sudo ./proxmox/deploy.sh \
#         --iso ./anglerfish-ai-0.1.0.iso \
#         --vmid 9000 \
#         --name anglerfish-honeypot
#
# Optional flags:
#     --template PATH      Override the VM template (default: ./anglerfish.json).
#     --storage NAME       Override the ISO storage (default from template).
#     --disk-storage NAME  Override the VM disk storage (default from template).
#     --memory MIB         Override memory.
#     --cores N            Override CPU cores.
#     --dry-run            Print the qm-create command without running it.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${HERE}/anglerfish.json"

VMID=""
NAME="anglerfish-honeypot"
ISO=""
DRY_RUN=0
STORAGE_OVERRIDE=""
DISK_STORAGE_OVERRIDE=""
MEMORY_OVERRIDE=""
CORES_OVERRIDE=""

usage() {
    sed -n '3,38p' "$0"
    exit "${1:-64}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso)           ISO="$2"; shift 2 ;;
        --vmid)          VMID="$2"; shift 2 ;;
        --name)          NAME="$2"; shift 2 ;;
        --template)      TEMPLATE="$2"; shift 2 ;;
        --storage)       STORAGE_OVERRIDE="$2"; shift 2 ;;
        --disk-storage)  DISK_STORAGE_OVERRIDE="$2"; shift 2 ;;
        --memory)        MEMORY_OVERRIDE="$2"; shift 2 ;;
        --cores)         CORES_OVERRIDE="$2"; shift 2 ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage 0 ;;
        *)               echo "unknown flag: $1" >&2; usage 64 ;;
    esac
done

if [[ -z "${ISO}" ]]; then echo "--iso is required" >&2; usage 64; fi
if [[ -z "${VMID}" ]]; then echo "--vmid is required" >&2; usage 64; fi
if [[ "$(id -u)" -ne 0 ]]; then echo "deploy.sh must run as root on a Proxmox host" >&2; exit 1; fi

for tool in qm pvesm jq awk; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "missing required tool: ${tool}" >&2
        echo "Install: apt install proxmox-ve jq gawk" >&2
        exit 1
    fi
done

if [[ ! -f "${TEMPLATE}" ]]; then
    echo "VM template not found: ${TEMPLATE}" >&2; exit 1
fi
if [[ ! -f "${ISO}" ]]; then
    echo "ISO not found: ${ISO}" >&2; exit 1
fi

# Lift defaults from the template, allow CLI overrides.
MEMORY="$(jq -r '.vm.memory_mib' "${TEMPLATE}")"
CORES="$(jq -r '.vm.cores' "${TEMPLATE}")"
SOCKETS="$(jq -r '.vm.sockets' "${TEMPLATE}")"
CPU="$(jq -r '.vm.cpu' "${TEMPLATE}")"
DISK_GIB="$(jq -r '.vm.disk_gib' "${TEMPLATE}")"
DISK_STORAGE="$(jq -r '.vm.disk_storage' "${TEMPLATE}")"
OSTYPE="$(jq -r '.vm.ostype' "${TEMPLATE}")"
SCSIHW="$(jq -r '.vm.scsihw' "${TEMPLATE}")"
MACHINE="$(jq -r '.vm.machine' "${TEMPLATE}")"
BOOT="$(jq -r '.vm.boot' "${TEMPLATE}")"
AGENT="$(jq -r '.vm.agent' "${TEMPLATE}")"
ONBOOT="$(jq -r '.vm.onboot' "${TEMPLATE}")"
BALLOON="$(jq -r '.vm.balloon' "${TEMPLATE}")"

BAIT_BRIDGE="$(jq -r '.network.bait_bridge' "${TEMPLATE}")"
SERVICE_BRIDGE="$(jq -r '.network.service_bridge' "${TEMPLATE}")"
BAIT_MODEL="$(jq -r '.network.bait_model' "${TEMPLATE}")"
SERVICE_MODEL="$(jq -r '.network.service_model' "${TEMPLATE}")"

ISO_STORAGE="$(jq -r '.iso.storage' "${TEMPLATE}")"

[[ -n "${MEMORY_OVERRIDE}" ]]       && MEMORY="${MEMORY_OVERRIDE}"
[[ -n "${CORES_OVERRIDE}" ]]        && CORES="${CORES_OVERRIDE}"
[[ -n "${STORAGE_OVERRIDE}" ]]      && ISO_STORAGE="${STORAGE_OVERRIDE}"
[[ -n "${DISK_STORAGE_OVERRIDE}" ]] && DISK_STORAGE="${DISK_STORAGE_OVERRIDE}"

# --- 1. Bridges --------------------------------------------------------
for bridge in "${BAIT_BRIDGE}" "${SERVICE_BRIDGE}"; do
    if ! ip link show "${bridge}" >/dev/null 2>&1; then
        cat >&2 <<EOF
[anglerfish-deploy] missing Linux bridge: ${bridge}

This deploy script refuses to auto-create bridges because attaching the
wrong physical NIC to the bait bridge could expose the Proxmox
management plane to attacker traffic. Add the bridge yourself in
/etc/network/interfaces and ifup it, then re-run.

Example /etc/network/interfaces entry:

    auto ${bridge}
    iface ${bridge} inet manual
        bridge-ports <physical-nic>
        bridge-stp off
        bridge-fd 0
EOF
        exit 2
    fi
done

# --- 2. ISO upload -----------------------------------------------------
ISO_BASENAME="$(basename "${ISO}")"
if ! pvesm list "${ISO_STORAGE}" | awk '{print $1}' | grep -q ":iso/${ISO_BASENAME}$"; then
    echo "[anglerfish-deploy] uploading ISO to ${ISO_STORAGE}..."
    if [[ "${DRY_RUN}" -eq 0 ]]; then
        pvesm upload "${ISO_STORAGE}" "${ISO}" --content iso
    fi
fi
ISO_VOLID="${ISO_STORAGE}:iso/${ISO_BASENAME}"

# --- 3. VM creation ----------------------------------------------------
qm_args=(
    "${VMID}"
    --name "${NAME}"
    --memory "${MEMORY}"
    --cores "${CORES}"
    --sockets "${SOCKETS}"
    --cpu "${CPU}"
    --ostype "${OSTYPE}"
    --scsihw "${SCSIHW}"
    --machine "${MACHINE}"
    --agent "${AGENT}"
    --onboot "${ONBOOT}"
    --balloon "${BALLOON}"
    --scsi0 "${DISK_STORAGE}:${DISK_GIB},format=raw"
    --ide2 "${ISO_VOLID},media=cdrom"
    --boot "${BOOT}"
    --net0 "${BAIT_MODEL},bridge=${BAIT_BRIDGE},firewall=0"
    --net1 "${SERVICE_MODEL},bridge=${SERVICE_BRIDGE},firewall=0"
)

echo "[anglerfish-deploy] qm create ${qm_args[*]}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[anglerfish-deploy] --dry-run set; skipping qm create"
    exit 0
fi

qm create "${qm_args[@]}"

cat <<EOF

[anglerfish-deploy] VM ${VMID} (${NAME}) created.

Next steps:
  1. Start the VM:   qm start ${VMID}
  2. Open console:   qm terminal ${VMID}   # or via the Proxmox web UI
  3. Walk through the first-boot wizard.
  4. Once the wizard finishes:
       * SSH to the service NIC for ops.
       * The native SSH lure listens on the bait NIC (default port 2222);
         run "anglerfish lure serve" if it is not already up (TODO-3).
  5. To make the VM autostart at host boot: qm set ${VMID} --onboot 1
EOF
