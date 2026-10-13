#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Free disk on a GitHub-hosted runner before a large image build.
#
# A hosted ubuntu runner has ~14 GB free of its ~72 GB disk; the torch / rust
# release builds need more than that. These toolchains ship preinstalled and no
# image build here uses them. Absent paths are fine (rm -f); a failure to
# delete one must not fail the job (the build then fails on its own if the disk
# really was too small, and says so).
set -uo pipefail
echo "--- disk before"; df -h / | tail -1
sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup \
  /opt/hostedtoolcache/CodeQL /usr/local/share/boost /usr/share/swift /opt/az \
  2>/dev/null || echo "::warning::could not remove some preinstalled toolchains"
sudo docker image prune -af >/dev/null 2>&1 || true
echo "--- disk after"; df -h / | tail -1
