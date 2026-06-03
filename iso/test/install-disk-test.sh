#!/bin/bash
#
# install-disk-test.sh -- end-to-end verification of anglerfish-install.
#
# Exercises the full install-to-disk lifecycle against the built ISO using a
# loopback disk and QEMU/KVM, with no real hardware:
#
#   A. fresh install      -> 4-partition layout, state relocated onto the
#                            anglerfish-data partition, fstab bind mounts
#   B. boot (BIOS)         -> the installed disk reaches the first-boot wizard
#   C. preserve-reimage    -> a second install keeps the data partition
#                            (accumulated intel survives) and reimages the OS
#   D. --wipe-data         -> the data partition is purged
#
# This is a privileged integration test, not a CI unit test: it needs
# --privileged, /dev/kvm, devtmpfs, and loopback partitions. Run it inside
# the pinned build container (which already has the live-build toolchain):
#
#   docker run --rm --privileged --device /dev/kvm \
#     -v "$PWD/output:/keep" \
#     -v "$PWD/iso/config/includes.chroot/usr/local/sbin/anglerfish-install:/installer:ro" \
#     -v "$PWD/iso/test:/test:ro" \
#     anglerfish-iso-builder:<tag> \
#     bash /test/install-disk-test.sh /keep/anglerfish-ai-0.1.0.iso
#
# Screenshots land in /keep (the mounted output/ dir). Exit code is nonzero
# if any stage assertion fails.

set -uo pipefail

ISO="${1:-/keep/anglerfish-ai-0.1.0.iso}"
INSTALLER="${INSTALLER:-/installer}"
HELPER="${HELPER:-/test/qmp_screendump.py}"
OUT="${OUT:-/keep}"
fails=0
note() { echo "  $1"; }
# check "<description>" <command...>; the command runs now (after the
# relevant mount), so arguments expand at call time.
check() {
    local desc="$1"
    shift
    if "$@"; then note "PASS: ${desc}"; else note "FAIL: ${desc}"; fails=$((fails + 1)); fi
}

mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y squashfs-tools qemu-system-x86 qemu-utils netpbm python3 >/dev/null 2>&1

echo "== unsquash the live appliance rootfs =="
xorriso -osirrox on -indev "${ISO}" -extract /live/filesystem.squashfs /tmp/fs.squashfs 2>/dev/null
unsquashfs -q -d /srcroot /tmp/fs.squashfs >/dev/null 2>&1
cp "${INSTALLER}" /srcroot/usr/local/sbin/anglerfish-install
chmod +x /srcroot/usr/local/sbin/anglerfish-install

echo "== plant simulated config + intel in the live state dirs =="
mkdir -p /srcroot/etc/anglerfish /srcroot/var/lib/anglerfish /srcroot/var/log/anglerfish
echo baseline > /srcroot/etc/anglerfish/marker
echo baseline > /srcroot/var/lib/anglerfish/marker
echo baseline > /srcroot/var/log/anglerfish/marker

truncate -s 12G /tmp/disk.img
loop=$(losetup --find --show -P /tmp/disk.img)
P3="${loop}p3"; P4="${loop}p4"
bind_dev() { for d in dev proc sys; do mount --bind "/$d" "/srcroot/$d"; done; }
unbind_dev() { for d in dev/pts dev proc sys; do umount "/srcroot/$d" 2>/dev/null || true; done; }
run_installer() { bind_dev; chroot /srcroot /usr/local/sbin/anglerfish-install "$@" "$loop"; rc=$?; unbind_dev; return $rc; }

echo; echo "#### STAGE A: FRESH INSTALL ####"
run_installer --yes --root-size 4G >/tmp/a.log 2>&1
note "installer exit: $?"
check "data partition labelled anglerfish-data" \
    test "$(blkid -s LABEL -o value "$P4")" = anglerfish-data
mkdir -p /m3 /m4; mount "$P4" /m4
check "state relocated to /data/etc" test "$(cat /m4/etc/marker 2>/dev/null)" = baseline
check "state relocated to /data/lib" test "$(cat /m4/lib/marker 2>/dev/null)" = baseline
check "state relocated to /data/log" test "$(cat /m4/log/marker 2>/dev/null)" = baseline
umount /m4; mount "$P3" /m3
check "/etc/anglerfish is an empty bind target" test -z "$(ls -A /m3/etc/anglerfish 2>/dev/null)"
check "fstab has the data bind mounts" grep -q "/var/lib/anglerfish  none  bind" /m3/etc/fstab
echo canary > /m3/REIMAGE-CANARY
umount /m3
cp /tmp/disk.img "${OUT}/disk-datapart.img"

echo; echo "#### STAGE B: BOOT (BIOS) ####"
qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 -drive file=/tmp/disk.img,format=raw,if=virtio \
  -display none -vga std -qmp unix:/tmp/qmp.sock,server,nowait & qpid=$!
sleep 70
python3 "${HELPER}" /tmp/qmp.sock /tmp/shot.ppm || true
kill $qpid 2>/dev/null || true
if pnmtopng /tmp/shot.ppm > "${OUT}/boot-datapart.png" 2>/dev/null; then
    note "boot screenshot saved to ${OUT}/boot-datapart.png (inspect for the wizard)"
fi

echo; echo "#### STAGE C: PRESERVE-REIMAGE ####"
mount "$P4" /m4; echo intel-v2 > /m4/lib/accumulated; umount /m4
run_installer --yes --root-size 4G >/tmp/c.log 2>&1
check "preserve mode was selected" grep -qi preserved /tmp/c.log
mount "$P4" /m4
check "accumulated intel survives reimage" test "$(cat /m4/lib/accumulated 2>/dev/null)" = intel-v2
umount /m4; mount "$P3" /m3
check "OS root was reimaged (canary gone)" test ! -f /m3/REIMAGE-CANARY
umount /m3

echo; echo "#### STAGE D: --wipe-data ####"
run_installer --yes --wipe-data --root-size 4G >/tmp/d.log 2>&1
mount "$P4" /m4
check "accumulated intel purged by --wipe-data" test ! -f /m4/lib/accumulated
umount /m4
losetup -d "$loop" 2>/dev/null || true

echo; echo "#### RESULT ####"
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "${fails} CHECK(S) FAILED"; fi
exit "$fails"
