#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Build the deployable console into apps/web/dist/.
#
# This used to `cp -rL src dist` — packaging the legacy vanilla console, which
# the gateway retired (docker/Dockerfile.gateway-rust: "One UI, every build").
# Anyone following the old README to "produce the deployable artifact" got the
# console that is no longer shipped, and got it silently.
#
# NOTE: this is for local inspection, NOT the release path. The console ships
# inside the stack, not on its own tag: pushing a `stack-vX` tag runs
# .github/workflows/publish-web.yml, which builds apps/web and pushes
# ghcr.io/<org>/noomesh/mesh-ui-web:stack-vX; images-release.yml then builds
# the gateway with --build-arg UI_IMAGE=.../mesh-ui-web:stack-vX automatically
# — there is no separate UI tag and no hand-bumped pin.
#
# Building here does not publish anything and does not update any gateway.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-full}"
case "$MODE" in
  full) npm run build -w @metis/web ;;
  core) npm run build -w @metis/web -- --mode core ;;
  *) echo "usage: $0 [full|core]" >&2; exit 2 ;;
esac

echo "apps/web/dist/ ready — $MODE edition ($(find apps/web/dist -type f | wc -l) files)"
echo "This is a local build. The released artifact comes from a v* tag; see the header."
