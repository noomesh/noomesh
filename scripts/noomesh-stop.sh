#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Stop Mesh cluster services

set -e


# fu 46: derive the per-instance namespace (project, container prefix,
# network, ports) before any compose invocation — stop/status/logs must
# address the same project start created.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-instance.sh"


# Auto-include override file if it exists (user directory mounts)
# The file list has ONE home: this now composes the
# add-on overlays too, so an add-on container is stopped/cleaned/logged as
# part of its own stack rather than treated as an orphan of it.
. "$(dirname "$0")/lib-compose.sh"
COMPOSE_FILES="$(compose_file_args .)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"

ui_phase "Stack"

# Parse arguments
PROFILE=""
SERVICES=()
REMOVE_VOLUMES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        -v|--volumes)
            REMOVE_VOLUMES=true
            shift
            ;;
        *)
            SERVICES+=("$1")
            shift
            ;;
    esac
done

# Determine what to stop
if [ ${#SERVICES[@]} -eq 0 ]; then
    # Stop all services
    ui_step "Stopping all services"
    echo ""

    # Volumes are only removed if explicitly requested via -v/--volumes flag.
    # Use 'noo stack clean --volumes' for interactive volume removal.

    # Build profile flags — when no specific profile given, discover ALL profiles
    # from the compose file so nothing gets orphaned.
    if [ -n "$PROFILE" ]; then
        PROFILE_FLAGS="--profile $PROFILE"
    else
        PROFILE_FLAGS=""
        for p in $(docker compose $COMPOSE_FILES config --profiles 2>/dev/null); do
            PROFILE_FLAGS="$PROFILE_FLAGS --profile $p"
        done
        # Fallback if discovery failed
        if [ -z "$PROFILE_FLAGS" ]; then
            PROFILE_FLAGS="--profile controller --profile standalone"
        fi
    fi

    # Stop backend containers spawned by the node-agent (outside compose)
    for name in noo-vllm noo-llamacpp noo-ollama; do
        if docker ps -q --filter "name=^${name}$" 2>/dev/null | grep -q .; then
            ui_step "Stopping spawned backend ${name}"
            docker stop "$name" && docker rm "$name" 2>/dev/null || true
        fi
    done

    # Stop with or without volumes
    if [ "$REMOVE_VOLUMES" = true ]; then
        docker compose $COMPOSE_FILES $PROFILE_FLAGS down -v --remove-orphans
        ui_warned "Volumes removed — data is gone"
    else
        docker compose $COMPOSE_FILES $PROFILE_FLAGS down --remove-orphans
        ui_done "Volumes preserved (data intact)"
    fi
else
    # Stop specific services, and remove their containers (i301 a.4). A
    # container left exited is one boot-restore starts again after a reboot
    # (it starts every stopped core service, hostd boot.go), so a plain
    # `compose stop` did not survive one. With no container, boot-restore
    # (which never recreates) leaves it down until `noo stack start`.
    ui_step "Stopping ${SERVICES[*]}"

    if [ -n "$PROFILE" ]; then
        docker compose $COMPOSE_FILES --profile "$PROFILE" rm --stop --force "${SERVICES[@]}"
    else
        docker compose $COMPOSE_FILES rm --stop --force "${SERVICES[@]}"
    fi
fi

ui_close_done "Services stopped"
ui_note "noo stack status shows anything still running"

echo ""
ui_rule
ui_guide_cmd "noo stack start" "bring the stack back on the existing images"
ui_guide_cmd "noo stack rebuild" "rebuild the custom images first, then start"


# fu76: materialized file credentials live only while the stack runs.
rm -rf secrets/.runtime 2>/dev/null || true
# The RAM copies the containers' `secrets:` bind (lib-secrets.sh
# write_secret_files). Only on a full stop: stopping one service leaves the
# rest running, and a restart policy re-resolves their bind sources. The
# next `noo stack start` writes them again before compose creates anything.
if [ ${#SERVICES[@]} -eq 0 ]; then
    # shellcheck source=lib-secrets.sh
    . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-secrets.sh" 2>/dev/null && remove_secret_files || true
fi
