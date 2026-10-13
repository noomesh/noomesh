#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Build the hardened llama.cpp image for a specific architecture and tag it
# pai-assistant/llamacpp:<arch>, matching what the Go node-agent reaches for
# (StartBackendSDK: pai-assistant/llamacpp:${GOARCH}) — see
# docs/models/backends.md and docker/Dockerfile.llamacpp.
#
# This hardened build ships with the stack (docker/README-llamacpp.md); the
# release workflow publishes the same Dockerfile as ghcr.io/noomesh/llamacpp.
# This script is the local/controller build of it.
#
# Why build on the CONTROLLER (not on the edge node): the Dockerfile builds
# llama.cpp from source on a DHI base (dhi.io/…) that needs the controller's
# DHI auth + mirroring; edge devices have neither. So we buildx here (native
# for amd64, qemu-emulated for a foreign arch), then `noo cluster sync-images`
# ships the resulting arch-matched image to the node.
#
# Usage:
#   scripts/build-hardened-llamacpp.sh [amd64|arm64]     # default: host arch
#   LLAMACPP_REF=b9628 scripts/build-hardened-llamacpp.sh arm64
#
# Cross-arch (foreign platform) auto-registers qemu/binfmt via tonistiigi/binfmt.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root (this script lives at scripts/)

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
esac

ARCH="${1:-$HOST_ARCH}"
case "$ARCH" in amd64|arm64) ;; *) echo "unsupported arch: $ARCH (want amd64|arm64)"; exit 2 ;; esac

PLATFORM="linux/${ARCH}"
IMAGE="pai-assistant/llamacpp:${ARCH}"
# Must match the Dockerfile's ARG default, and must be an immutable tag —
# the Dockerfile refuses a moving ref (§3f R30). Keep the two in step;
# tests/test_llamacpp_ref_is_pinned.py fails if they drift.
LLAMACPP_REF="${LLAMACPP_REF:-b9628}"

echo "[build-llamacpp] arch=${ARCH} platform=${PLATFORM} ref=${LLAMACPP_REF}"

# Foreign arch → ensure qemu/binfmt is registered (idempotent).
if [ "$ARCH" != "$HOST_ARCH" ]; then
  if ! docker run --rm --platform "$PLATFORM" busybox true >/dev/null 2>&1; then
    echo "[build-llamacpp] registering qemu/binfmt for ${ARCH} (needs --privileged)…"
    docker run --privileged --rm tonistiigi/binfmt --install "$ARCH"
  fi
fi

# A docker-container builder supports --platform cross-builds with --load.
# Create it if missing, but DO NOT `--use` it / `docker buildx use` it — that
# would switch the GLOBAL default builder, and the docker-container driver
# can't see the host's local image store, which breaks `docker compose build`
# (e.g. `FROM pai-assistant/deps-base:latest` → tries to pull from a registry
# and fails). We reference it explicitly via --builder for THIS build only.
docker buildx inspect noo-multiarch >/dev/null 2>&1 \
  || docker buildx create --name noo-multiarch --driver docker-container >/dev/null

docker buildx build \
  --builder noo-multiarch \
  --platform "$PLATFORM" \
  --build-arg "LLAMACPP_REF=${LLAMACPP_REF}" \
  -f docker/Dockerfile.llamacpp \
  -t "$IMAGE" \
  --load \
  .

# The controller's OWN compose service uses :latest; keep it pointing at the
# native build so a host-arch build stays the default local image too.
if [ "$ARCH" = "$HOST_ARCH" ]; then
  docker tag "$IMAGE" pai-assistant/llamacpp:latest
  echo "[build-llamacpp] also tagged :latest (host arch)"
fi

echo "[build-llamacpp] OK → ${IMAGE}"
docker image inspect "$IMAGE" --format '  {{.Id}}  {{.Architecture}}  {{.Size}} bytes' 2>/dev/null || true
echo "[build-llamacpp] ship to an ${ARCH} node with: noo cluster sync-images <node> --image ${IMAGE}"
