#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-stuck-container.sh — one unkillable container must not take the whole
# stack down.
#
# The incident (controller pop-os, 2026-10-20, rolling 0.6.6 -> 0.6.7):
# `noo-ollama-embed`'s process survived `kill -9` and a docker restart (stuck
# in the kernel; only a reboot clears it). `docker compose up --force-recreate`
# tried to stop it, got
#     cannot stop container: <id>: tried to kill container, but did not
#     receive an exit event
# and ABORTED, leaving EVERY service Created and the gateway, postgres and
# redis down. `docker rename` did not help: compose finds the container by
# its labels and tries to remove it again.
#
# noo_compose_up_isolating_stuck runs the stack `up` and, only for that
# failure, names the stuck container's service and brings up every OTHER
# service (explicit list from `config --services`, --no-deps so a service
# that depends on the stuck one cannot drag compose back into it).
#
# Exit code (documented; noo-cli/src/commands/upgrade.rs reads it):
#   75  NOO_EXIT_STACK_PARTIAL — the stack is up EXCEPT one stuck service;
#       a reboot of this host clears it. If NOO_STUCK_REPORT names a file,
#       the service name and container id are written there (one per line).
# Any other non-zero status is compose's own, unchanged. The generic
# "retry once in 5s" for transient registry errors stays with the caller and
# is NOT used for 75: a reboot is the only remedy, a retry cannot help.
#
# Never `docker rename`, never kills a host process.

NOO_EXIT_STACK_PARTIAL=75

# _stuck_failure_ids <compose-output-file> — the container id(s) compose
# blamed, one per line. Empty when the failure is not the stuck-process shape.
_stuck_failure_ids() {
    grep -qE 'did not receive an exit event|could not kill container|cannot stop container' "$1" 2>/dev/null || return 0
    grep -oE 'cannot stop container: [0-9a-f]{12,64}' "$1" | awk '{print $NF}' | sort -u
}

# noo_compose_up_isolating_stuck <docker compose args ... up [flags]>
# Pass exactly the args that follow `docker`, e.g.
#   noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate
noo_compose_up_isolating_stuck() {
    local errf rc
    errf="$(mktemp)" || { docker "$@"; return $?; }
    docker "$@" 2>&1 | tee "$errf"
    rc="${PIPESTATUS[0]}"
    if [ "$rc" -eq 0 ]; then rm -f "$errf"; return 0; fi

    local ids id
    ids="$(_stuck_failure_ids "$errf")"
    rm -f "$errf"
    [ -n "$ids" ] || return "$rc"

    # Split the args at `up`: base = compose + files + profiles.
    local -a base=() upflags=()
    local seen_up=0 a
    for a in "$@"; do
        if [ "$seen_up" = 0 ]; then
            if [ "$a" = up ]; then seen_up=1; else base+=("$a"); fi
        else
            upflags+=("$a")
        fi
    done
    [ "$seen_up" = 1 ] || return "$rc"

    local stuck_svcs="" name svc
    for id in $ids; do
        name="$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null)"; name="${name#/}"
        svc="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.service" }}' "$id" 2>/dev/null)"
        [ -n "$svc" ] || return "$rc"   # not a compose container: not ours to isolate
        ui_failed "${name:-$id} ($svc) is stuck: its process will not exit (kill -9 and docker restart cannot clear it); a reboot of this host clears it. Starting everything else."
        stuck_svcs="$stuck_svcs $svc"
        if [ -n "${NOO_STUCK_REPORT:-}" ]; then
            printf '%s\n%s\n' "$svc" "$id" >> "$NOO_STUCK_REPORT" 2>/dev/null || true
        fi
    done

    local all others=()
    if ! all="$(docker "${base[@]}" config --services 2>/dev/null)"; then
        return "$rc"
    fi
    for svc in $all; do
        case " $stuck_svcs " in *" $svc "*) continue ;; esac
        others+=("$svc")
    done
    [ "${#others[@]}" -gt 0 ] || return "$NOO_EXIT_STACK_PARTIAL"

    docker "${base[@]}" up --no-deps "${upflags[@]}" "${others[@]}" || return $?
    return "$NOO_EXIT_STACK_PARTIAL"
}
