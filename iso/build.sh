#!/usr/bin/env bash
#
# Anglerfish-AI in-container live-build ISO builder.
#
# Runs INSIDE the pinned iso/Dockerfile container (invoked by ./build.sh,
# the host orchestrator). Bootstraps a Debian 12 (bookworm) chroot,
# installs the app from the staged source tree, and produces a BIOS+UEFI
# bootable hybrid ISO that:
#   * boots to a text console
#   * runs the first-boot wizard on tty1 (anglerfish-firstboot.service)
#   * comes up with the bridge, dashboard, and SSH lure enabled
#
# The repo is bind-mounted at /work. live-build's large, root-owned work
# tree is built in a container-local path (BUILD_DIR), NOT under the bind
# mount, so the build is fast and loop/overlay-safe regardless of the host
# filesystem. The finished ISO is copied to OUTPUT_DIR (./output on the
# host).
#
# Do not run this directly on a host; use ./build.sh. Running it outside
# the pinned container reintroduces the live-build version drift the
# container exists to eliminate.
#
# Usage (via ./build.sh):
#     iso/build.sh [--clean] [--sign] [--with-ollama|--without-ollama]
#
# --with-ollama / --without-ollama
#         Whether to install Ollama on-host inside the image (the 0060
#         chroot hook). Default is --without-ollama (the trusted-remote
#         design: the bridge points at a separate GPU box). --with-ollama
#         adds ~5 GB. Wired through the ANGLERFISH_INSTALL_OLLAMA build env.
#
# --clean Discard the container-local work dir before building (forces a
#         fresh debootstrap).
#
# --sign  Sign the ISO with cosign keyless. Requires cosign on PATH and an
#         OIDC-capable workload identity (GitHub Actions, gcloud, ...).
#
# Env: OUTPUT_DIR (default ${ROOT}/output), BUILD_DIR (default
# /var/tmp/anglerfish-lb).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT}/output}"
BUILD_DIR="${BUILD_DIR:-/var/tmp/anglerfish-lb}"
VERSION="$(grep -E '^version' "${ROOT}/pyproject.toml" | head -1 | sed -E 's/version = "(.+)"/\1/')"

WANT_SIGN=0
WANT_CLEAN=0
WANT_OLLAMA=0
for arg in "$@"; do
    case "${arg}" in
        --clean)          WANT_CLEAN=1 ;;
        --sign)           WANT_SIGN=1 ;;
        --with-ollama)    WANT_OLLAMA=1 ;;
        --without-ollama) WANT_OLLAMA=0 ;;
        *)
            echo "unknown flag: ${arg}" >&2
            exit 64
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "iso/build.sh must run as root (live-build needs chroot); use ./build.sh." >&2
    exit 1
fi

for tool in lb dpkg-deb sha256sum; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "missing required tool: ${tool}" >&2
        echo "Run inside the iso/Dockerfile container via ./build.sh." >&2
        exit 1
    fi
done

if [[ "${WANT_SIGN}" -eq 1 ]] && ! command -v cosign >/dev/null 2>&1; then
    echo "--sign requested but cosign is not on PATH" >&2
    exit 1
fi

# Always start from a clean work tree: lb config is not idempotent across
# option changes, and a fresh dir is the simplest reproducible state.
# --clean is implied; the flag remains for explicitness and CI clarity.
if [[ "${WANT_CLEAN}" -eq 1 ]]; then
    echo "[anglerfish-iso] --clean: discarding ${BUILD_DIR}"
fi
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Stage the live-build configuration.
cp -a "${HERE}/auto" auto
cp -a "${HERE}/config" config

# Stage the app source tree into the image via includes.chroot. live-build
# copies config/includes.chroot/* into the chroot root before the normal/
# hooks run AND into the booted image, so the app is present at boot with
# zero network. Allowlist only what pip + the systemd units need: this
# keeps the ISO small and never recurses into iso/.
app_dest="config/includes.chroot/opt/anglerfish/src"
mkdir -p "${app_dest}"
for item in src systemd pyproject.toml README.md LICENSE uv.lock; do
    if [[ -e "${ROOT}/${item}" ]]; then
        cp -a "${ROOT}/${item}" "${app_dest}/"
    fi
done

echo "[anglerfish-iso] live-build work dir: $(pwd)"
echo "[anglerfish-iso] version: ${VERSION}"
echo "[anglerfish-iso] on-host Ollama: ${WANT_OLLAMA} (1=install, 0=trusted-remote)"

# The 0060 chroot hook reads ANGLERFISH_INSTALL_OLLAMA from the build env.
export ANGLERFISH_INSTALL_OLLAMA="${WANT_OLLAMA}"

lb config
lb build

# Locate the produced ISO. With --image-name anglerfish-ai (auto/config),
# live-build emits anglerfish-ai-<arch>.hybrid.iso in the work dir.
shopt -s nullglob
artefacts=(anglerfish-ai-*.hybrid.iso)
shopt -u nullglob
if [[ ${#artefacts[@]} -eq 0 ]]; then
    echo "[anglerfish-iso] live-build produced no ISO" >&2
    exit 2
fi

mkdir -p "${OUTPUT_DIR}"
out="anglerfish-ai-${VERSION}.iso"
cp "${artefacts[0]}" "${OUTPUT_DIR}/${out}"
( cd "${OUTPUT_DIR}" && sha256sum "${out}" > "${out}.sha256" )
echo "[anglerfish-iso] built: ${OUTPUT_DIR}/${out}"

if [[ "${WANT_SIGN}" -eq 1 ]]; then
    echo "[anglerfish-iso] signing ${out} with cosign (keyless)"
    ( cd "${OUTPUT_DIR}" && cosign sign-blob --yes \
        --output-signature "${out}.sig" \
        --output-certificate "${out}.pem" \
        "${out}" )
    echo "[anglerfish-iso] signature:   ${OUTPUT_DIR}/${out}.sig"
    echo "[anglerfish-iso] certificate: ${OUTPUT_DIR}/${out}.pem"
fi

# The container runs as root, so the output is root-owned on the host bind
# mount. When the orchestrator passes the invoking user's ids, hand the
# files back so a normal user can read/delete them without sudo. CI leaves
# HOST_UID unset (root-owned is fine there).
if [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
    chown -R "${HOST_UID}:${HOST_GID}" "${OUTPUT_DIR}"
fi
