#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
# Parse-check docker/apparmor-noo-sandbox with the AppArmor 4.0 parser
# Ubuntu 24.04 ships, inside a throwaway container, so a host without
# AppArmor (WSL2) or with an older parser (22.04: no `userns,` rule) can
# still prove the profile loads where it is meant to. Needs docker and
# network for the apt install; nothing is loaded into any kernel (-Q).
#
#   bash scripts/check-apparmor-profile.sh            # exit 0 = parses
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="$ROOT/docker/apparmor-noo-sandbox"
IMAGE="${NOO_APPARMOR_CHECK_IMAGE:-ubuntu:24.04}"
[ -f "$PROFILE" ] || { echo "missing: $PROFILE" >&2; exit 2; }
docker run --rm -v "$PROFILE:/p/noo-sandbox:ro" "$IMAGE" sh -c '
  apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor >/dev/null 2>&1
  v="$(apparmor_parser --version | head -1)"
  case "$v" in *" 4."*|*" 5."*) ;; *) echo "parser too old for userns rules: $v" >&2; exit 3 ;; esac
  apparmor_parser -Q -K --skip-cache /p/noo-sandbox && echo "ok: noo-sandbox parses with $v"
'
