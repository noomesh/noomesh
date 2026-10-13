#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Show status of Mesh services


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

DEFAULT_PROFILE="controller"

PROFILE=""

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
        *)
            shift
            ;;
    esac
done

if [ -z "$PROFILE" ]; then
    PROFILE="$DEFAULT_PROFILE"
fi

docker compose $COMPOSE_FILES --profile "$PROFILE" ps

# Show backend containers spawned by the node-agent (not part of compose)
COMPOSE_NAMES=$(docker compose $COMPOSE_FILES --profile "$PROFILE" ps --format '{{.Name}}' 2>/dev/null)
BACKEND_CONTAINERS=$(docker ps --filter "name=noo-vllm" --filter "name=noo-llamacpp" --filter "name=noo-ollama" --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | while IFS=$'\t' read -r name image status ports; do
    # Skip containers already shown by compose (e.g. noo-ollama-embed)
    if echo "$COMPOSE_NAMES" | grep -qx "$name" 2>/dev/null; then
        continue
    fi
    echo "$name|$image|$status|$ports"
done)

if [ -n "$BACKEND_CONTAINERS" ]; then
    echo ""
    echo "Spawned backends (managed by node-agent):"
    printf "%-22s %-45s %-30s %s\n" "NAME" "IMAGE" "STATUS" "PORTS"
    echo "$BACKEND_CONTAINERS" | while IFS='|' read -r name image status ports; do
        printf "%-22s %-45s %-30s %s\n" "$name" "$image" "$status" "$ports"
    done
fi
