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
# The second shape (controller pop-os, 2026-10-28, i277e): the GPU did not
# answer when a GPU service's container started —
#     error getting device handle for index '0': Unknown Error
# (CDI / nvidia-container-cli). compose aborted the same way and the gateway,
# evolve, grafana and the embed doors stayed Created until a reboot. A GPU
# service is never part of the core: the services whose container recorded a
# GPU device error (docker inspect .State.Error) are held by name and every
# other service is started, exactly as for a stuck one. The CPU embedder
# (profile embed-cpu) is a peer embed endpoint of the gateway and takes the
# embeddings while the GPU one is held.
#
# Exit code (documented; noo-cli/src/commands/upgrade.rs reads it):
#   75  NOO_EXIT_STACK_PARTIAL — the stack is up EXCEPT the named service(s);
#       a reboot of this host clears it. If NOO_STUCK_REPORT names a file,
#       the service name and container id are written there (one per line;
#       the id line of a GPU-held service ends in " gpu").
# NOO_ISOLATED_SERVICES (space-separated) names the services left out, so
# the caller's Created guard does not `docker start` them again.
# Any other non-zero status is compose's own, unchanged. The generic
# "retry once in 5s" for transient registry errors stays with the caller and
# is NOT used for 75: a reboot is the only remedy, a retry cannot help.
#
# Never `docker rename`, never kills a host process.

NOO_EXIT_STACK_PARTIAL=75
NOO_ISOLATED_SERVICES=""

# The daemon's words for a GPU that did not answer at container start.
_NOO_GPU_START_ERROR='error getting device handle|failed to inject CDI devices|unresolvable CDI devices|nvidia-container-cli|could not select device driver "nvidia"|NVML|nvidia-container-runtime'

# _stuck_failure_ids <compose-output-file> — the container id(s) compose
# blamed, one per line. Empty when the failure is not the stuck-process shape.
_stuck_failure_ids() {
    grep -qE 'did not receive an exit event|could not kill container|cannot stop container' "$1" 2>/dev/null || return 0
    grep -oE 'cannot stop container: [0-9a-f]{12,64}' "$1" | awk '{print $NF}' | sort -u
}

# _gpu_failure_ids <docker compose args before `up`> — the project's
# containers that never started because the GPU did not answer: still
# Created, with a GPU device error in .State.Error. Empty when none is.
_gpu_failure_ids() {
    local id st
    for id in $(docker "$@" ps -aq 2>/dev/null); do
        st="$(docker inspect -f '{{.State.Status}} {{.State.Error}}' "$id" 2>/dev/null)"
        case "$st" in created\ *|exited\ *) ;; *) continue ;; esac
        printf '%s\n' "$st" | grep -qE "$_NOO_GPU_START_ERROR" && printf '%s\n' "$id"
    done
    return 0
}

# noo_compose_up_isolating_stuck <docker compose args ... up [flags]>
# Pass exactly the args that follow `docker`, e.g.
#   noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate
noo_compose_up_isolating_stuck() {
    local errf rc
    NOO_ISOLATED_SERVICES=""
    errf="$(mktemp)" || { docker "$@"; return $?; }

    # Split the args at `up`: base = compose + files + profiles.
    local -a base=() upflags=() argv=("$@") others=()
    local seen_up=0 a
    for a in "$@"; do
        if [ "$seen_up" = 0 ]; then
            if [ "$a" = up ]; then seen_up=1; else base+=("$a"); fi
        else
            upflags+=("$a")
        fi
    done

    # One round per failure: a second GPU service (the exporter, a second
    # backend) can fail the retry the same way. Bounded: the services held
    # by name only grow.
    local isolated="" round ids id gpu name svc why all
    for round in 1 2 3 4; do
        : > "$errf"
        docker "${argv[@]}" 2>&1 | tee "$errf"
        rc="${PIPESTATUS[0]}"
        if [ "$rc" -eq 0 ]; then
            rm -f "$errf"
            [ -z "$isolated" ] && return 0
            return "$NOO_EXIT_STACK_PARTIAL"
        fi
        [ "$seen_up" = 1 ] && [ "$round" -lt 4 ] || { rm -f "$errf"; return "$rc"; }

        gpu=0
        ids="$(_stuck_failure_ids "$errf")"
        if [ -z "$ids" ] && grep -qE "$_NOO_GPU_START_ERROR" "$errf" 2>/dev/null; then
            ids="$(_gpu_failure_ids "${base[@]}")"
            gpu=1
        fi
        [ -n "$ids" ] || { rm -f "$errf"; return "$rc"; }

        for id in $ids; do
            name="$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null)"; name="${name#/}"
            svc="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.service" }}' "$id" 2>/dev/null)"
            [ -n "$svc" ] || { rm -f "$errf"; return "$rc"; }   # not a compose container: not ours to isolate
            case " $isolated " in *" $svc "*) continue ;; esac
            if [ "$gpu" = 1 ]; then
                why="$(docker inspect -f '{{.State.Error}}' "$id" 2>/dev/null | grep -oE "($_NOO_GPU_START_ERROR)[^;:]*" | head -1)"
                ui_failed "${name:-$id} ($svc) is held: the GPU did not answer when it started (${why:-GPU device error}); a reboot of this host usually clears it. Starting everything else."
            else
                ui_failed "${name:-$id} ($svc) is stuck: its process will not exit (kill -9 and docker restart cannot clear it); a reboot of this host clears it. Starting everything else."
            fi
            isolated="${isolated:+$isolated }$svc"
            if [ -n "${NOO_STUCK_REPORT:-}" ]; then
                if [ "$gpu" = 1 ]; then
                    printf '%s\n%s gpu\n' "$svc" "$id" >> "$NOO_STUCK_REPORT" 2>/dev/null || true
                else
                    printf '%s\n%s\n' "$svc" "$id" >> "$NOO_STUCK_REPORT" 2>/dev/null || true
                fi
            fi
        done
        NOO_ISOLATED_SERVICES="$isolated"

        all="$(docker "${base[@]}" config --services 2>/dev/null)" || { rm -f "$errf"; return "$rc"; }
        others=()
        for svc in $all; do
            case " $isolated " in *" $svc "*) continue ;; esac
            others+=("$svc")
        done
        [ "${#others[@]}" -gt 0 ] || { rm -f "$errf"; return "$NOO_EXIT_STACK_PARTIAL"; }
        # The embed fallback: a held GPU embedder leaves embeddings to the
        # CPU one when this install runs it (a peer endpoint of the gateway).
        case " $isolated " in *" ollama-embed "*|*" ollama "*)
            case " ${others[*]} " in *" ollama-embed-cpu "*)
                ui_note "the CPU embedder (ollama-embed-cpu) takes the embeddings while the GPU one is held" ;; esac ;;
        esac
        argv=("${base[@]}" up --no-deps "${upflags[@]}" "${others[@]}")
    done
    rm -f "$errf"
    return "$rc"
}
