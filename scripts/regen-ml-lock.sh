#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Regenerate docker/ml-lock/requirements.txt, the hash-locked install set for
# docker/Dockerfile.deps-base. Needs uv >= 0.13 and network.
#
#   scripts/regen-ml-lock.sh [TRELLION_DIR [TRELLION_PROTOCOLS_DIR]]
#
# TRELLION_DIR is the trellion checkout the image will be built from (default
# ../trellion): its dependencies are part of the resolution, so lock against
# the commit the release builds (images-release.yml: release-line's
# trellion_sha). A trellion whose dependencies moved since needs a regenerate;
# the image build fails loudly (`uv pip check`) rather than ship a gap.
# To take a newer release of one package: UV_ARGS="--upgrade-package <name>".
set -euo pipefail
cd "$(dirname "$0")/.."
trellion="$(cd "${1:-../trellion}" && pwd)"
protocols="$(cd "${2:-../trellion-protocols}" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The local packages the image installs --no-deps from its build contexts; the
# overrides replace pyproject.toml's git URL for trellion (no credentials, no
# network) exactly as Dockerfile.deps-base's do.
printf 'trellion[transport,video] @ file://%s\nnoo-gateway-client @ file://%s\ntrellion-protocols @ file://%s\n' \
  "$trellion" "$PWD/packages/noo-gateway-client" "$protocols" > "$work/overrides.txt"
# Their dependencies, and the build backends they are built with (the image
# builds them --no-build-isolation, so no backend resolves unhashed).
printf 'trellion[transport,video] @ file://%s\nnoo-gateway-client @ file://%s\nhatchling>=1.27\nsetuptools>=77\n' \
  "$trellion" "$PWD/packages/noo-gateway-client" > "$work/in.txt"

# shellcheck disable=SC2086
uv pip compile pyproject.toml "$work/in.txt" --universal --python-version 3.12 \
  --extra trellion --extra web --extra cache --extra feedback --extra pgvector \
  --extra mcp --extra rag --extra voice \
  --overrides "$work/overrides.txt" --constraints docker/core-lock/requirements.txt \
  --extra-index-url https://download.pytorch.org/whl/cpu --index-strategy unsafe-best-match \
  --no-emit-package trellion --no-emit-package trellion-protocols \
  --no-emit-package noo-gateway-client --no-emit-package noomesh \
  --generate-hashes --no-header ${UV_ARGS:-} -o "$work/out.txt" >&2

{
  cat <<'HDR'
# Hash-locked install set for docker/Dockerfile.deps-base (the ML tier: the
# trellion, rag and voice extras on top of deps-core's), resolved for Python
# 3.12 (.python-version) on every platform. The image installs this with
# --require-hashes, so a PyPI release published after this file was written
# cannot reach a build. Packages that deps-core's lock already pins are held at
# those versions (--constraints), so installing this over deps-core changes
# nothing in the layer below.
#
# Not in here, by design: trellion, trellion-protocols and noo-gateway-client.
# They come from the build contexts (trellion at the commit the release
# resolved, trellion-protocols at the commit trellion pins, checked by
# scripts/check-protocols-pin.py) and are installed --no-deps; their own
# dependencies are in this file, and the image build runs `uv pip check` so a
# trellion whose dependencies moved since this was generated fails the build.
#
# torch is resolved from https://download.pytorch.org/whl/cpu (the CPU wheel
# the image has always wanted) when something in the tree asks for it; the
# current tree asks for none, so no torch, nvidia-* or triton pin is here and
# tests/test_python_lock_guard.py fails if one appears without a +cpu version.
#
# Regenerate after changing pyproject.toml dependencies, on a version bump, or
# when trellion's dependencies change (uv >= 0.13):
#   scripts/regen-ml-lock.sh ../trellion ../trellion-protocols
# tests/test_python_lock_guard.py fails if the Dockerfile installs without this
# file, if a pin loses its hashes, or if a pin disagrees with core-lock.
HDR
  cat "$work/out.txt"
} > docker/ml-lock/requirements.txt
