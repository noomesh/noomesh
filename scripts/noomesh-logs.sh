#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# View logs for Mesh services


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

FOLLOW=false
TAIL=50
PROFILE=""
SERVICES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --follow|-f)
            FOLLOW=true
            shift
            ;;
        --tail)
            TAIL="$2"
            shift 2
            ;;
        --tail=*)
            TAIL="${1#*=}"
            shift
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        *)
            SERVICES+=("$1")
            shift
            ;;
    esac
done

if [ -z "$PROFILE" ]; then
    PROFILE="$DEFAULT_PROFILE"
fi

COMPOSE_CMD="docker compose $COMPOSE_FILES --profile $PROFILE"

if [ "$FOLLOW" = true ]; then
    $COMPOSE_CMD logs -f --tail="$TAIL" ${SERVICES[@]}
else
    $COMPOSE_CMD logs --tail="$TAIL" ${SERVICES[@]}
fi
