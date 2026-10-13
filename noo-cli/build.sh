#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Build the static musl `pai` binary in docker (no host Rust toolchain needed)
# and install it as the front door at ~/.local/bin/noo.
#
# The binary is static-pie (musl): it runs even when the Python venv is
# broken, which is the point — it's the recovery-safe control plane.
set -euo pipefail
cd "$(dirname "$0")"

docker run --rm \
  -v "$PWD":/build \
  -v noo-cli-cargo-cache:/usr/local/cargo/registry \
  -w /build rust:1-alpine \
  sh -c "apk add -q musl-dev && cargo build --release"

install -m 755 target/release/noo ~/.local/bin/noo
echo "installed: $(command -v pai)"
~/.local/bin/noo health
