# Anglerfish-AI ISO build environment.
#
# The single source of truth for the live-build toolchain: the host
# orchestrator (./build.sh) and CI both build the ISO inside THIS image, so
# the build no longer depends on whatever live-build the host (WSL trixie,
# the Ubuntu CI runner, a fresh VM) happens to ship. Debian bookworm's
# live-build 1:20230502 accepts the --bootloaders/--image-name options the
# Ubuntu fork rejected.
#
# Pinned to a dated Debian bookworm tag AND its content digest so the base
# is immutable across machines and over time. To refresh the pin:
#   docker buildx imagetools inspect debian:bookworm-slim
# then update the dated tag and the @sha256 digest below together (see
# iso/README.md "Refreshing the pins").
FROM debian:bookworm-20260518-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# Non-interactive, deterministic locale/timezone for reproducible output.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC

# live-build plus every tool it shells out to for a BIOS+UEFI hybrid ISO:
#   debootstrap                  - bootstrap the Debian chroot
#   squashfs-tools               - mksquashfs the live filesystem
#   xorriso                      - author the ISO 9660 / El Torito image
#   isolinux + syslinux-common   - BIOS bootloader (isohdpfx.bin hybrid MBR)
#   grub-efi-amd64-bin           - UEFI bootloader
#   grub-pc-bin                  - BIOS grub bits (kept available; the
#                                  recipe uses syslinux for BIOS by default)
#   mtools + dosfstools          - build the FAT EFI System Partition
#   debian-archive-keyring       - verify the bootstrap against Debian's keys
#   ca-certificates              - HTTPS to the mirrors
# Recommends are kept for live-build so its runtime helpers (rsync, cpio,
# gnupg, ...) are present; this is a build container, not the shipped image.
RUN set -eux; \
    apt-get update; \
    apt-get install -y \
        live-build \
        debootstrap \
        squashfs-tools \
        xorriso \
        isolinux \
        syslinux-common \
        grub-pc-bin \
        grub-efi-amd64-bin \
        mtools \
        dosfstools \
        debian-archive-keyring \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    lb config --help >/dev/null

# The orchestrator bind-mounts the repo here and runs iso/build.sh.
WORKDIR /work
