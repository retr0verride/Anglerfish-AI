#!/usr/bin/env bash
#
# Full-appliance smoke: boot the real ISO under QEMU/KVM with the two-NIC
# Proxmox topology, drive the first-boot wizard over QMP, then prove the
# lure (:2222) and dashboard (:8420) are reachable and the honeypot loop
# answers. Runs INSIDE the iso/Dockerfile builder container (needs qemu +
# /dev/kvm). Results + screendumps land in /out for inspection.
#
# Exit status: 0 only if BOTH the dashboard health check and the lure
# honeypot loop succeed. Any failure (no KVM, apt install failure, dead
# dashboard, dead lure) exits non-zero so a caller or CI job can gate on it.
#
# Usage (via docker run, see the host invocation):
#   smoke-appliance.sh <iso_path> [skip-wizard]
set -uo pipefail

ISO="${1:?usage: smoke-appliance.sh <iso_path> [skip-wizard]}"
WIZ="${2:-}"  # "skip-wizard" for a pre-seeded image (no interactive wizard)
OUT="/out"
QMP="/tmp/anglerfish-qmp.sock"
DISK="/tmp/anglerfish-smoke.qcow2"
RESULT="${OUT}/smoke-result.txt"

log() { echo "[smoke] $*" | tee -a "${RESULT}"; }

: > "${RESULT}"
log "iso: ${ISO}"

# KVM is required. The timings below assume hardware virtualisation; a TCG
# fallback would boot a full Debian live + LLM far too slowly for the waits
# to hold. Fail fast and clearly rather than time out cryptically later.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    log "kvm: present"
else
    log "kvm: MISSING - this smoke needs /dev/kvm (run with: docker run --device /dev/kvm ...)"
    exit 1
fi

# Tools the checks need. The builder image ships none of these (it carries
# only the live-build toolchain), so install whatever is absent. python3
# drives the wizard over QMP and must be present.
need=()
command -v qemu-system-x86_64 >/dev/null || need+=(qemu-system-x86 qemu-utils)
command -v python3 >/dev/null || need+=(python3)
command -v ssh >/dev/null || need+=(openssh-client)
command -v sshpass >/dev/null || need+=(sshpass)
command -v curl >/dev/null || need+=(curl)
command -v pnmtopng >/dev/null || need+=(netpbm)
if [ "${#need[@]}" -gt 0 ]; then
    log "installing: ${need[*]}"
    # noninteractive + no-recommends keeps apt from stopping on a debconf
    # prompt (which would hang forever) or dragging in interactive packages.
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update -qq; then
        log "FATAL: apt-get update failed"
        exit 1
    fi
    if ! apt-get install -y -qq --no-install-recommends "${need[@]}"; then
        log "FATAL: apt install failed: ${need[*]}"
        exit 1
    fi
fi

qemu-img create -f qcow2 "${DISK}" 20G >/dev/null

log "booting QEMU (headless, QMP-driven, two NICs)"
# bait NIC -> host :2222 (lure); service NIC -> host :8420 (dashboard).
# Distinct SLIRP subnets so the two guest NICs get distinct DHCP leases.
qemu-system-x86_64 \
    -name anglerfish-smoke \
    -machine type=q35,accel=kvm \
    -cpu host -m 4G -smp 4 \
    -drive "file=${DISK},if=virtio,format=qcow2" \
    -cdrom "${ISO}" \
    -boot order=dc \
    -netdev "user,id=bait,net=10.0.2.0/24,hostfwd=tcp:127.0.0.1:2222-:2222" \
    -device "virtio-net-pci,netdev=bait,mac=52:54:00:ba:17:01" \
    -netdev "user,id=service,net=10.0.3.0/24,hostfwd=tcp:127.0.0.1:8420-:8420" \
    -device "virtio-net-pci,netdev=service,mac=52:54:00:5e:01:01" \
    -vga std -display none \
    -qmp "unix:${QMP},server,nowait" \
    -serial "file:${OUT}/smoke-serial.log" \
    &
QEMU_PID=$!
log "qemu pid ${QEMU_PID}"

# Drive the wizard. menu_wait boot_wait svc_wait tuned for KVM. svc_wait is
# generous because the dashboard is After=bridge and the bridge waits for
# model-pull (the tinyllama fetch) before it starts.
python3 /work/iso/test/qmp_wizard_smoke.py "${QMP}" "${OUT}" 12 130 300 "${WIZ}" 2>&1 | tee -a "${RESULT}"

# Convert screendumps to PNG for easy viewing (best-effort).
for ppm in "${OUT}"/smoke-*.ppm; do
    [ -e "${ppm}" ] || continue
    command -v pnmtopng >/dev/null 2>&1 && pnmtopng "${ppm}" > "${ppm%.ppm}.png" 2>/dev/null
done

dash_ok=0
log "=== dashboard health (:8420) ==="
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    # The dashboard serves plain HTTP (uvicorn, no ssl_*). Try http, then
    # https -k in case an operator fronted it with TLS.
    body="$(curl -s --max-time 10 http://127.0.0.1:8420/api/health 2>/dev/null)"
    [ -z "${body}" ] && body="$(curl -k -s --max-time 10 https://127.0.0.1:8420/api/health 2>/dev/null)"
    log "attempt ${attempt}: ${body:-<no response>}"
    case "${body}" in *'"status"'*'ok'*) dash_ok=1; break ;; esac
    sleep 15
done

lure_ok=0
log "=== lure SSH (:2222) + honeypot loop ==="
SSH_OPTS="-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
-o PreferredAuthentications=password -o PubkeyAuthentication=no \
-o ConnectTimeout=10 -o NumberOfPasswordPrompts=1"
for attempt in 1 2 3; do
    out="$(sshpass -p 'hunter2' ssh ${SSH_OPTS} root@127.0.0.1 'whoami; uname -r; id' 2>&1)"
    log "attempt ${attempt}:"
    printf '%s\n' "${out}" | sed 's/^/[lure] /' | tee -a "${RESULT}"
    case "${out}" in *root*) lure_ok=1; break ;; esac
    sleep 20
done

log "=== teardown ==="
kill "${QEMU_PID}" 2>/dev/null
sleep 2
kill -9 "${QEMU_PID}" 2>/dev/null
wait "${QEMU_PID}" 2>/dev/null

# Report and gate. The script previously always exited 0, so a boot that
# never brought up the dashboard or lure still "passed". Account for both.
rc=0
[ "${dash_ok}" -eq 1 ] || { log "FAIL: dashboard never returned status ok on :8420"; rc=1; }
[ "${lure_ok}" -eq 1 ] || { log "FAIL: lure honeypot loop never answered on :2222"; rc=1; }
if [ "${rc}" -eq 0 ]; then
    log "PASS: dashboard + lure both healthy"
fi
log "smoke complete; artifacts in ${OUT}"
exit "${rc}"
