#!/usr/bin/env bash
#
# Anglerfish AI live-build ISO builder.
#
# Produces a bootable Debian 12 (bookworm) ISO that:
#   * boots to a text console
#   * runs the first-boot wizard on tty1
#   * comes up with the bridge + the dashboard enabled (the native
#     SSH lure ships in this tree but has no auto-start unit yet;
#     operators run `anglerfish lure serve` themselves — see TODO-3)
#
# Run as root inside a Debian/Ubuntu host with `live-build` installed.
#
# Usage:
#     sudo ./iso/build.sh [--clean] [--sign]
#
# --sign  Signs the ISO with cosign keyless. Requires `cosign` on
#         PATH and a workload identity capable of obtaining an OIDC
#         token (Github Actions, gcloud, etc). When absent the signing
#         step is skipped silently.
#
# The ISO is written to ./build/anglerfish-ai-<version>.iso.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
BUILD_DIR="${HERE}/build"
VERSION="$(grep -E '^version' "${ROOT}/pyproject.toml" | head -1 | sed -E 's/version = "(.+)"/\1/')"

WANT_SIGN=0
WANT_CLEAN=0
for arg in "$@"; do
    case "${arg}" in
        --clean) WANT_CLEAN=1 ;;
        --sign)  WANT_SIGN=1 ;;
        *)
            echo "unknown flag: ${arg}" >&2
            exit 64
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "build.sh must run as root (live-build needs chroot)." >&2
    exit 1
fi

for tool in lb dpkg-deb sha256sum; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "missing required tool: ${tool}" >&2
        echo "On Debian/Ubuntu: apt install live-build debootstrap squashfs-tools xorriso isolinux syslinux-common" >&2
        exit 1
    fi
done

if [[ "${WANT_SIGN}" -eq 1 ]] && ! command -v cosign >/dev/null 2>&1; then
    echo "--sign requested but cosign is not on PATH" >&2
    exit 1
fi

if [[ "${WANT_CLEAN}" -eq 1 ]]; then
    rm -rf "${BUILD_DIR}"
fi

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Stage live-build configuration.
cp -r "${HERE}/auto" auto
cp -r "${HERE}/config" config

echo "[anglerfish-iso] live-build config in $(pwd)"
echo "[anglerfish-iso] version: ${VERSION}"

lb clean --purge
lb config
lb build

# Locate and rename the resulting ISO.
shopt -s nullglob
artefacts=(live-image-amd64.hybrid.iso)
shopt -u nullglob
if [[ ${#artefacts[@]} -eq 0 ]]; then
    echo "[anglerfish-iso] live-build produced no ISO" >&2
    exit 2
fi
out="anglerfish-ai-${VERSION}.iso"
mv "${artefacts[0]}" "${out}"
sha256sum "${out}" > "${out}.sha256"
echo "[anglerfish-iso] built: $(pwd)/${out}"

if [[ "${WANT_SIGN}" -eq 1 ]]; then
    echo "[anglerfish-iso] signing ${out} with cosign (keyless)"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
        --output-signature "${out}.sig" \
        --output-certificate "${out}.pem" \
        "${out}"
    echo "[anglerfish-iso] signature: $(pwd)/${out}.sig"
    echo "[anglerfish-iso] certificate: $(pwd)/${out}.pem"
fi
