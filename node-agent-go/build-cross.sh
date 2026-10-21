#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Cross-compile noo-node-agent for any GOARCH using the DHI golang image.
#
# Usage:
#   ./build-cross.sh                    # default: arm64 (Pi/Jetson/RK)
#   ./build-cross.sh arm64
#   ./build-cross.sh amd64              # for testing
#   ./build-cross.sh arm                # 32-bit ARM (Pi 3, older boards)
#
# Output: ./noo-node-agent-${GOARCH}
#
# Why a script (not inline in Ansible):
#   - Reusable from CLI for one-off builds
#   - Single place to bump Go toolchain version
#   - Lets the playbook stay readable
#
# Why DHI golang (not public golang:alpine):
#   - Controller has DHI auth + mirroring already set up
#   - Same hardened toolchain as the existing Dockerfile.node-agent-go uses
#   - Reproducible builds across the fleet (controller + all targets use
#     the same compiler version with the same patches)
#
# Why no Pi-side compile:
#   - Go cross-compilation is host-arch native (no qemu needed)
#   - Pi 4 takes ~3-5 min to compile; HOST3 takes ~10 sec for the same arch
#   - Edge devices stay light (no Go toolchain installed)

set -e

# Accepts "<goarch>" (GOOS defaults to linux) or "<goos>/<goarch>"
# (e.g. darwin/arm64 for a Mac node). Pure Go — cross-compiles from the
# linux DHI builder to any GOOS/GOARCH.
TARGET="${1:-arm64}"
case "$TARGET" in
  */*) GOOS="${TARGET%/*}"; GOARCH="${TARGET#*/}" ;;
  *)   GOOS="linux";        GOARCH="$TARGET" ;;
esac
IMAGE="${BUILD_IMAGE:-dhi.io/golang:1.26-debian13-dev}"

# Which binary. This module ships two: noo-node-agent (workers — listens on
# :8081 with mTLS) and noo-hostd (controller — no network surface at all).
# Separate binaries by design; see cmd/noo-hostd/main.go for why that
# distinction is a security property rather than a packaging preference.
#
#   ./build-cross.sh amd64                     # noo-node-agent (default)
#   BINARY=noo-hostd ./build-cross.sh amd64    # noo-hostd
BINARY="${BINARY:-noo-node-agent}"
case "$BINARY" in
  noo-node-agent) CMD_PKG="./cmd/node-agent/" ;;
  noo-hostd)      CMD_PKG="./cmd/noo-hostd/" ;;
  *) echo "[build-cross] unknown BINARY=$BINARY (want noo-node-agent or noo-hostd)" >&2; exit 2 ;;
esac

# Backward-compatible output name for the linux case (sync-images and the
# Pi playbook expect ./noo-node-agent-<arch>); non-linux gets the GOOS
# prefix so the two don't collide.
if [ "$GOOS" = "linux" ]; then
  OUT="${BINARY}-${GOARCH}"
else
  OUT="${BINARY}-${GOOS}-${GOARCH}"
fi

# Run from the directory containing this script (node-agent-go/)
cd "$(dirname "$0")"

# Stamp the binary with its build version so each node reports which
# node-agent it's running (heartbeat app_version → controller). Computed
# on the host (git is here, not necessarily in the builder image).
VERSION="${NODE_AGENT_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
VPKG="github.com/noomesh/noomesh/node-agent-go/internal/version"
LDFLAGS="-s -w -X ${VPKG}.Version=${VERSION} -X ${VPKG}.Commit=${COMMIT}"

echo "[build-cross] binary: ${BINARY}  target: ${GOOS}/${GOARCH}  image: ${IMAGE}  version: ${VERSION}+${COMMIT}"

# --user is not optional. Without it the container runs as root and every
# artifact it writes into the mounted tree — the binary, and the Go build and
# module caches — is root-owned. The first thing that breaks is
# `git worktree remove`, which fails with "Permission denied" and leaves the
# tree behind; with no passwordless sudo on the controller, recovery needs
# another container just to delete the files. scripts/cargo-docker.sh carries
# the same flag for the same reason (CLAUDE.md documents that incident).
#
# GOCACHE/GOMODCACHE/GOPATH must move too: as a non-root uid the default
# /.cache and /go are unwritable, and `go build` fails outright rather than
# degrading. GOPATH holds the checksum database's cache (pkg/sumdb), which a
# toolchain download needs to verify against sum.golang.org.
#
# GOTOOLCHAIN=auto (the image says local): the image's Go builds when it
# satisfies go.mod's `toolchain` line; otherwise Go downloads that release
# from proxy.golang.org, verified by sum.golang.org (GOSUMDB left at its
# default; -mod=mod does not touch verification). require-toolchain.sh runs
# after that selection and prints which one builds.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd):/build" -w /build \
  -e GOOS="${GOOS}" \
  -e GOARCH="${GOARCH}" \
  -e CGO_ENABLED=0 \
  -e GOTOOLCHAIN=auto \
  -e GOFLAGS=-mod=mod \
  -e GOCACHE=/tmp/.gocache \
  -e GOMODCACHE=/tmp/.gomodcache \
  -e GOPATH=/tmp/.gopath \
  "${IMAGE}" \
  /bin/sh -c "sh ./require-toolchain.sh && go mod download && go build -ldflags='${LDFLAGS}' -o ${OUT} ${CMD_PKG}"

ls -lh "${OUT}"
echo "[build-cross] OK → ${OUT}"
