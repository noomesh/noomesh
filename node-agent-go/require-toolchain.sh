#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Refuse to build with a Go older than go.mod's `toolchain` line.
#
# Both release builds (docker/Dockerfile.node-agent-go and build-cross.sh)
# run with GOTOOLCHAIN=local on the floating golang:1.26 image, so they use
# whatever 1.26.x that image holds and never read the `toolchain` line. The
# line is where a security patch release is named (govulncheck gates CI on
# it), so a stale image would ship a binary without the fix, silently:
# 0.6.8-rc.1's darwin agent was built with go1.26.9 after GO-2026-6809 was
# fixed in 1.26.10. Run from node-agent-go/ (the directory holding go.mod).
set -eu

want="$(sed -n 's/^toolchain go//p' go.mod)"
have="$(go env GOVERSION)"
have="${have#go}"
echo "[require-toolchain] go ${have}; go.mod toolchain ${want:-none}"
[ -n "$want" ] || { echo "[require-toolchain] go.mod has no toolchain line" >&2; exit 1; }
lowest="$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)"
if [ "$lowest" != "$want" ]; then
  echo "[require-toolchain] go ${have} is older than go.mod's toolchain ${want}: refresh the golang image (mirror-images.yml) before building" >&2
  exit 1
fi
