#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# install-noo.sh — install the standalone `noo` binary from GitHub Releases.
#
# Thin, safe entry point that delegates to the canonical installer at
# noo-cli/install.sh (single source of truth — kept there because the release
# workflow attaches it to every `noo-cli-v*` release). This wrapper:
#   1. uses the repo-local copy when run from a checkout (no network needed);
#   2. otherwise downloads install.sh to a TEMP FILE, sanity-checks it, and
#      runs it — never pipes curl straight into sh.
#
# The installer itself detects OS/arch, downloads the matching static musl
# `noo` binary, verifies its SHA-256 against the published checksum, and
# installs to ~/.local/bin (or a root-owned dir like /usr/local/bin via sudo).
#
# Usage:
#   scripts/install-noo.sh                        # from a repo checkout
#   NOO_INSTALL_DIR=/usr/local/bin scripts/install-noo.sh
#
# Env passthrough (see noo-cli/install.sh): NOO_CLI_VERSION, NOO_INSTALL_DIR,
# NOO_CLI_BASE_URL.
set -euo pipefail

# Declared home of the release repo (pinned equal to noo-cli/install.sh and
# noo-cli/src/registry.rs::RELEASE_REPO by tests/test_release_repo_declarations.py).
REPO="${NOO_CLI_REPO:-noomesh/noomesh}"
INSTALLER_URL="https://raw.githubusercontent.com/${REPO}/main/noo-cli/install.sh"

# 1. Repo checkout? Use the local canonical installer directly.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
local_installer="${script_dir}/../noo-cli/install.sh"
if [[ -f "$local_installer" ]]; then
    exec sh "$local_installer"
fi

# 2. Standalone: download the installer to a temp file, check it, run it.
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT HUP TERM
installer="${tmpdir}/install.sh"

echo "Fetching installer: ${INSTALLER_URL}" >&2
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$installer" "$INSTALLER_URL"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$installer" "$INSTALLER_URL"
else
    echo "error: need 'curl' or 'wget' to download the installer" >&2
    exit 1
fi

# Sanity check: non-empty and actually a shell script (a raw.githubusercontent
# error page or truncated download must not reach `sh`).
if [[ ! -s "$installer" ]] || ! head -n1 "$installer" | grep -q '^#!/bin/sh'; then
    echo "error: downloaded installer looks wrong (empty or not a shell script) — refusing to run it" >&2
    exit 1
fi

exec sh "$installer"
