#!/usr/bin/env bash
#
# Anglerfish-AI ISO build orchestrator (host entry point).
#
# Builds the pinned Debian bookworm build container (iso/Dockerfile) and
# runs the live-build ISO build inside it. Because the toolchain lives in a
# digest-pinned container, the result is the same whether you run this from
# WSL, CI, or a fresh Debian VM - the host's own live-build (if any) is
# never used.
#
# The finished ISO + checksum land in ./output/, owned by the invoking user.
#
# Usage:
#     ./build.sh [--with-ollama | --without-ollama] [--sign] [--clean]
#
# Defaults to --without-ollama (trusted-remote; the bridge points at a
# separate Ollama box). --with-ollama bundles Ollama in the image (~5 GB).
#
# Requirements: Docker with privileged-container support (live-build needs
# loop devices + chroot). On Docker Desktop, enable WSL integration for this
# distro; on Linux, add your user to the 'docker' group.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_REPO="anglerfish-iso-builder"
OUTPUT_DIR="${REPO}/output"

ollama_flag="--without-ollama"
passthru=()
for arg in "$@"; do
    case "${arg}" in
        --with-ollama)    ollama_flag="--with-ollama" ;;
        --without-ollama) ollama_flag="--without-ollama" ;;
        --sign|--clean)   passthru+=("${arg}") ;;
        *)
            echo "usage: ./build.sh [--with-ollama|--without-ollama] [--sign] [--clean]" >&2
            exit 64
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found. Install Docker; on Docker Desktop enable WSL integration." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "cannot reach the Docker daemon." >&2
    echo "Linux: add your user to the 'docker' group and re-login." >&2
    echo "Docker Desktop: enable WSL integration for this distro." >&2
    exit 1
fi

# Tag the builder image by the Dockerfile's content hash: a changed recipe
# forces a rebuild, an unchanged one reuses the cache. --pull keeps the
# digest-pinned base layer current.
dockerfile_hash="$(sha256sum "${REPO}/iso/Dockerfile" | cut -c1-12)"
image="${IMAGE_REPO}:${dockerfile_hash}"

echo "==> building builder image ${image}"
docker build --pull -t "${image}" "${REPO}/iso"

mkdir -p "${OUTPUT_DIR}"
# Reproducibility (TODO-18): pin SOURCE_DATE_EPOCH to the HEAD commit time so
# the build's mtimes are deterministic, and pass through an optional
# snapshot.debian.org timestamp for a byte-stable package set.
source_date_epoch="$(git -C "${REPO}" log -1 --format=%ct 2>/dev/null || echo 1704067200)"
echo "==> building ISO (${ollama_flag}) inside the container"
docker run --rm --privileged \
    -v "${REPO}:/work" \
    -v "${OUTPUT_DIR}:/work/output" \
    -w /work \
    -e OUTPUT_DIR=/work/output \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -e SOURCE_DATE_EPOCH="${source_date_epoch}" \
    -e ANGLERFISH_DEBIAN_SNAPSHOT="${ANGLERFISH_DEBIAN_SNAPSHOT:-}" \
    -e ANGLERFISH_SMOKE_SEED="${ANGLERFISH_SMOKE_SEED:-}" \
    "${image}" \
    iso/build.sh "${ollama_flag}" "${passthru[@]}"

echo "==> done. Artifacts in ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}"
