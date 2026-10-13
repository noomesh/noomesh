#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Tear the box down and stand it back up from scratch.
#
# This is the "pretend this is a brand-new customer machine" button. It runs
# the same three steps a real first-time install does, back to back:
#
#   1. noo stack clean --deep   — stop everything; remove volumes, images,
#                                 PKI, secrets; untrust the cluster CA
#   2. noo onboard              — the setup wizard (--ci for unattended)
#   3. noo stack start [--dist] — bring the stack up
#
# With --dist, step 3 runs from the published GHCR images (a true
# distribution install). Without it, step 3 builds from the local source
# tree — useful for verifying that a from-scratch DEV install still works.
#
# DESTRUCTIVE: every conversation, document, embedding, certificate and
# generated secret on this box is deleted. Requires an explicit confirmation
# unless -y/--yes is passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DIST=false
DIST_TAG=""
ASSUME_YES=false
ONBOARD_CI=false
KEEP_ENV=false

while [ $# -gt 0 ]; do
    case "$1" in
        --dist)      DIST=true; shift ;;
        --tag)       DIST_TAG="$2"; shift 2 ;;
        --tag=*)     DIST_TAG="${1#*=}"; shift ;;
        -y|--yes)    ASSUME_YES=true; shift ;;
        --ci)        ONBOARD_CI=true; shift ;;
        --keep-env)  KEEP_ENV=true; shift ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: noo stack reset [--dist] [--tag vX.Y.Z] [--ci] [--keep-env] [-y]" >&2
            exit 1
            ;;
    esac
done

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"
MODE_DESC="local source build"
if [ "$DIST" = true ]; then
    MODE_DESC="published GHCR images${DIST_TAG:+ (tag $DIST_TAG)}"
fi

ui_phase "Reset"
ui_warned "$(ui_bad "Full reset — this destroys all local Mesh state")"
ui_kv "Deletes" "Docker volumes AND the bind-mounted data directories under NOO_DATA_ROOT"
ui_kv "" "(Postgres database, Redis, NATS), built images, PKI/certificates,"
ui_kv "" "generated secrets; untrusts the cluster CA from the OS trust store"
ui_kv "Keeps" "your source tree, and .env only if --keep-env is passed"
ui_kv "Rebuilt as" "${MODE_DESC}"
echo ""

if [ "$ASSUME_YES" != true ]; then
    read -r -p "Type 'reset' to confirm: " _confirm
    if [ "$_confirm" != "reset" ]; then
        echo "Aborted."
        exit 1
    fi
fi

# ── .env preservation ──────────────────────────────────────────────────
# A deep clean removes generated secrets. Keeping .env makes the re-onboard
# non-interactive-friendly, but means you are NOT testing the true
# zero-to-one path (where the wizard generates everything fresh).
ENV_BACKUP=""
if [ "$KEEP_ENV" = true ] && [ -f .env ]; then
    ENV_BACKUP="$(mktemp)"
    cp .env "$ENV_BACKUP"
    ui_warned "Preserving .env (--keep-env) — not a true zero-to-one test"
fi

ui_phase "Deep Clean"
bash "$SCRIPT_DIR/noomesh-clean.sh" --deep -y

if [ -n "$ENV_BACKUP" ]; then
    cp "$ENV_BACKUP" .env
    rm -f "$ENV_BACKUP"
    ui_done "Restored .env"
fi

ui_phase "Onboarding"
ONBOARD_ARGS=()
if [ "$ONBOARD_CI" = true ]; then
    ONBOARD_ARGS+=(--ci)
fi
# Services are started explicitly in step 3 (so --dist is honoured); let the
# wizard handle everything else.
if ! noo onboard --skip-services "${ONBOARD_ARGS[@]+"${ONBOARD_ARGS[@]}"}"; then
    ui_close_failed "Onboarding failed — stopping before service start"
    exit 1
fi

ui_phase "Stack"
ui_step "Starting services (${MODE_DESC})"
START_ARGS=()
if [ "$DIST" = true ]; then
    START_ARGS+=(--dist)
    if [ -n "$DIST_TAG" ]; then
        START_ARGS+=(--tag "$DIST_TAG")
    fi
fi
bash "$SCRIPT_DIR/noomesh-start.sh" "${START_ARGS[@]+"${START_ARGS[@]}"}"

ui_close_done "Reset complete — stack is running from ${MODE_DESC}"
ui_rule
ui_guide_cmd "noo stack status" "every service should be Running"
ui_guide_cmd "docker inspect --format '{{.Config.Image}}' noo-gateway" "confirms which image the gateway came from"
if [ "$DIST" = true ]; then
    ui_guide_cmd "noo stack start" "flip back to live-source dev"
else
    ui_guide_cmd "noo stack start --dist" "flip to distribution images"
fi
