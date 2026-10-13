#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-created-guard.sh — self-heal for the stuck-in-Created recreate wedge.
#
# The defect (intermittent, still undiagnosed): `docker compose up -d
# --force-recreate` RETURNS SUCCESS with the freshly created container
# sitting in the Created state, never transitioning to Running. On
# 2026-08-20 that took the gateway down for 74 minutes (18:29→19:43Z)
# because nothing was watching — `up` said fine, `ps` showed Created,
# and no health check runs on a container that never started.
#
# This guard runs AFTER a compose `up` invocation returns (that timing is
# the wedge shape — do not anchor the window on a Starting event that may
# never come). Containers still in Created past the window are:
#   1. captured — docker events + inspect + compose version to a
#      diagnostics file, the evidence the eventual diagnosis needs;
#   2. healed with `docker start` — strictly safer than leaving the
#      service down: it is the exact container compose just created and
#      intended to start, and starting it in place avoids re-entering
#      compose ownership (the 08-02 incident recovery recipe).
#
# Usage: noo_created_guard <container-id-or-name>...
#   (typically: noo_created_guard $(docker compose ... ps -aq [SERVICES]))
# Returns 0 whether or not a heal was needed — a successful heal must not
# fail the launcher. Window: NOO_CREATED_GUARD_WAIT seconds (default 18).
#
# `docker compose ... ps -aq` (no SERVICES given) can return a container
# that belongs to a service NOT among the profiles/services this
# invocation asked compose to manage — e.g. a `noo-ollama` left Created by
# an earlier `noo models switch` bug while the active profile is
# `standalone` (whose Ollama is `ollama-embed`, a different service).
# `docker start`-ing such a container is wrong: it is not a recreate
# wedge, it is a stale leftover, and it can fail for reasons (missing GPU
# runtime, etc.) that have nothing to do with this launch — yet it prints
# "manual intervention needed" for a service nobody asked to run
# (2026-09-29 newcomer upgrade rehearsal).
#
# Callers that know the exact service set this invocation manages should
# set NOO_CREATED_GUARD_SERVICES to a space-separated list of those
# service names (e.g. from `docker compose ... config --services`) before
# calling. When set, a stuck container whose `com.docker.compose.service`
# label is NOT in that list is treated as stale/out-of-profile: reported
# and removed with `docker rm -f` (safe — Created means it never started,
# so it holds no data of its own) instead of started. When unset, every
# stuck container is treated as in-scope — the original, unfiltered
# behavior — so callers that pass no service set are unaffected.

noo_created_guard() {
    local wait_secs="${NOO_CREATED_GUARD_WAIT:-18}"
    local ids=("$@")
    [ ${#ids[@]} -eq 0 ] && return 0

    local deadline=$((SECONDS + wait_secs))
    local stuck=()
    while :; do
        stuck=()
        local id status
        for id in "${ids[@]}"; do
            status=$(docker inspect --format '{{.State.Status}}' "$id" 2>/dev/null || echo gone)
            [ "$status" = "created" ] && stuck+=("$id")
        done
        [ ${#stuck[@]} -eq 0 ] && return 0
        [ $SECONDS -ge $deadline ] && break
        sleep 2
    done

    # Out-of-profile containers are stale leftovers, not a wedge: remove
    # them and leave the real wedge self-heal below untouched for the rest.
    if [ -n "${NOO_CREATED_GUARD_SERVICES+x}" ]; then
        local managed=() id svc cname
        for id in "${stuck[@]}"; do
            svc=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' "$id" 2>/dev/null)
            if [ -n "$svc" ] && ! printf '%s\n' "$NOO_CREATED_GUARD_SERVICES" | tr ' ' '\n' | grep -qx "$svc"; then
                cname=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null | tr -d '/')
                if declare -F ui_warned >/dev/null; then
                    ui_warned "created-guard: ${cname:-$id} is not a service of this profile (stale, still Created — left by an earlier run) — removing it" >&2
                else
                    echo "! created-guard: ${cname:-$id} is not a service of this profile (stale, still Created — left by an earlier run) — removing it" >&2
                fi
                docker rm -f "$id" >/dev/null 2>&1 \
                    || echo "! created-guard: docker rm -f ${cname:-$id} failed — remove manually: docker rm -f ${cname:-$id}" >&2
                continue
            fi
            managed+=("$id")
        done
        stuck=("${managed[@]}")
        [ ${#stuck[@]} -eq 0 ] && return 0
    fi

    # Still Created past the window — capture evidence, then heal.
    local diag="${TMPDIR:-/tmp}/noo-created-guard-$(date -u +%Y%m%d-%H%M%S).log"
    {
        echo "== noo_created_guard: containers stuck in Created after ${wait_secs}s =="
        date -u
        for id in "${stuck[@]}"; do
            docker inspect --format '{{.Name}} state={{json .State}}' "$id" 2>&1
        done
        echo "== versions =="
        docker --version 2>&1
        docker compose version 2>&1
        echo "== docker events (last 5m) =="
        docker events --since 5m --until 0s 2>&1
        echo "== full inspect =="
        for id in "${stuck[@]}"; do
            docker inspect "$id" 2>&1
        done
    } > "$diag" 2>&1

    local names
    names=$(docker inspect --format '{{.Name}}' "${stuck[@]}" 2>/dev/null | tr -d '/' | tr '\n' ' ')
    if declare -F ui_warned >/dev/null; then
        ui_warned "created-guard: ${names}never left Created after ${wait_secs}s — applying docker start (recreate-wedge self-heal)" >&2
        ui_note "diagnostics: $diag" >&2
    else
        echo "! created-guard: ${names}never left Created after ${wait_secs}s — applying docker start (recreate-wedge self-heal). Diagnostics: $diag" >&2
    fi

    for id in "${stuck[@]}"; do
        if ! docker start "$id" >/dev/null 2>>"$diag"; then
            if declare -F ui_failed >/dev/null; then
                ui_failed "created-guard: docker start ${id} FAILED — service is DOWN, manual intervention needed (see $diag)"
            else
                echo "x created-guard: docker start ${id} FAILED — service is DOWN, manual intervention needed. See $diag" >&2
            fi
        fi
    done
    return 0
}
