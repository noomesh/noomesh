#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Refuse to build with a Go older than go.mod's `toolchain` line, and say
# which Go builds.
#
# Both release builds (docker/Dockerfile.node-agent-go and build-cross.sh)
# run on the floating golang:1.26 image with GOTOOLCHAIN=auto: Go uses the
# image's own toolchain when it satisfies the `toolchain` line, and otherwise
# downloads that release from the module proxy, verified against the checksum
# database (sum.golang.org). The line is where a security patch release is
# named (govulncheck gates CI on it): 0.6.8-rc.1's darwin agent was built with
# go1.26.9 after GO-2026-6809 was fixed in 1.26.10, because the builds then
# ran GOTOOLCHAIN=local on a stale image.
#
# This runs AFTER toolchain selection: `go env GOVERSION` inside the module
# answers with the Go that `go build` will use. It is the final gate either
# way, and a download with checksum verification switched off is refused.
# Run from node-agent-go/ (the directory holding go.mod).
set -eu

want="$(sed -n 's/^toolchain go//p' go.mod)"
have="$(go env GOVERSION)"
have="${have#go}"
image="$(GOTOOLCHAIN=local go env GOVERSION)"
image="${image#go}"
echo "[require-toolchain] go ${have}; go.mod toolchain ${want:-none}"
[ -n "$want" ] || { echo "[require-toolchain] go.mod has no toolchain line" >&2; exit 1; }
lowest="$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)"
if [ "$lowest" != "$want" ]; then
  echo "[require-toolchain] go ${have} is older than go.mod's toolchain ${want}: build with GOTOOLCHAIN=auto, or refresh the golang image (mirror-images.yml)" >&2
  exit 1
fi
if [ "$have" = "$image" ]; then
  echo "toolchain: local DHI go${have}"
  exit 0
fi
# Downloaded: only with the checksum database on.
sumdb="$(go env GOSUMDB)"
case "$sumdb" in
  off|"") echo "[require-toolchain] go${have} was downloaded with GOSUMDB=${sumdb:-empty}: refusing an unverified toolchain" >&2; exit 1 ;;
esac
for v in GONOSUMDB GONOSUMCHECK GOINSECURE; do
  if [ -n "$(go env "$v")" ]; then
    echo "[require-toolchain] go${have} was downloaded with ${v} set: refusing a toolchain the checksum database may not have verified" >&2
    exit 1
  fi
done
case " $(go env GOFLAGS) " in
  *" -insecure "*) echo "[require-toolchain] GOFLAGS has -insecure: refusing a downloaded toolchain" >&2; exit 1 ;;
esac
echo "toolchain: downloaded go${have} (sumdb-verified, ${sumdb})"
