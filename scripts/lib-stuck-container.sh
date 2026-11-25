#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-stuck-container.sh — one unkillable container must not take the whole
# stack down.
#
# The incident (controller ctrl, 2026-10-20, rolling 0.6.6 -> 0.6.7):
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
# The second shape (controller ctrl, 2026-10-28, i277e): the GPU did not
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
# The third shape (controller ctrl, 2026-11-25, release 0.6.30): the GPU
# embedder's process survived SIGKILL and containerd could not delete the
# task ("cannot delete running task ... failed precondition"). From then on
# EVERY docker call that touched that one container hung forever, `docker
# inspect` included, so there was no compose error text to read: `noo stack
# restart` sat at "25 of 26 up" for 30 minutes and a later `noo stack start`
# hung before starting what it had recreated. So the launcher no longer waits
# to be told: before it brings anything up or restarts it, it asks Docker
# about each of the stack's containers with a BOUNDED `docker inspect`
# (NOO_DOCKER_PROBE_SECS, default 10). One that does not answer in time is
# stuck: it is named once (the container, what it was, what stops working,
# that only a reboot of this host removes it) and everything else is started
# without it, core services first, exactly as for the other two shapes.
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
# Seconds one probe of one container may take before it counts as stuck.
NOO_DOCKER_PROBE_SECS="${NOO_DOCKER_PROBE_SECS:-10}"

# _noo_bounded <secs> cmd args... — run cmd with a deadline that HOLDS (the
# same shape as _noo_nvidia_smi_bounded in lib-compose.sh: the child runs in
# the background with its output in a file, nothing waits on it past the
# deadline). Prints cmd's output and returns its status; 124 = no answer in
# time (the child is sent KILL and left; it may never die).
_noo_bounded() {
    local secs="$1" d ticks rc child sub
    shift
    d="$(mktemp -d "${TMPDIR:-/tmp}/noo-bounded.XXXXXX" 2>/dev/null)" || { "$@"; return $?; }
    (
        "$@" >"$d/out" 2>&1 </dev/null &
        child=$!
        echo "$child" >"$d/pid"
        wait "$child"
        echo "$?" >"$d/rc.tmp" && mv "$d/rc.tmp" "$d/rc"
    ) >/dev/null 2>&1 </dev/null &
    sub=$!
    ticks=$((secs * 10))
    while [ ! -f "$d/rc" ] && [ "$ticks" -gt 0 ]; do
        sleep 0.1 2>/dev/null || sleep 1
        ticks=$((ticks - 1))
    done
    if [ -f "$d/rc" ]; then
        rc="$(cat "$d/rc")"
        cat "$d/out" 2>/dev/null
        rm -rf "$d"
        wait "$sub" 2>/dev/null
        return "$rc"
    fi
    child="$(cat "$d/pid" 2>/dev/null)"
    [ -n "$child" ] && kill -KILL "$child" 2>/dev/null
    kill -KILL "$sub" 2>/dev/null
    rm -rf "$d"
    return 124
}

# What stops working while a service is down, in the operator's words.
_noo_service_role() {
    case "$1" in
        ollama-embed|ollama) echo "GPU embeddings stop (the CPU embedder takes them when this install runs it)" ;;
        ollama-embed-cpu) echo "CPU embeddings stop" ;;
        postgres) echo "the database is down, so the gateway cannot work" ;;
        redis) echo "the cache and queues are down" ;;
        nats) echo "messaging is down" ;;
        gateway) echo "the API and every client door are down" ;;
        loki) echo "log search stops" ;;
        prometheus) echo "metrics stop" ;;
        grafana) echo "dashboards stop" ;;
        *) echo "$1 stays down" ;;
    esac
}

# _noo_core_first <services...> — one per line: the data stores the gateway
# needs first, then the rest in the order given.
_noo_core_first() {
    local s c
    for c in postgres redis nats; do
        for s in "$@"; do [ "$s" = "$c" ] && printf '%s\n' "$s"; done
    done
    for s in "$@"; do
        case "$s" in postgres|redis|nats) ;; *) printf '%s\n' "$s" ;; esac
    done
}

# _noo_hung_services <docker compose args before up> — "service id name" per
# stack container that exists and whose `docker inspect` gets no answer within
# the bound. Empty when every container answers. Listing uses `docker ps`
# (which does not touch each container); if even that does not answer, say so
# and probe nothing: compose will meet the same wall and there is no name to give.
_noo_hung_services() {
    local all rows id name svc st rc project=()
    all="$(docker "$@" config --services 2>/dev/null)" || return 0
    [ -n "${COMPOSE_PROJECT_NAME:-}" ] && project=(--filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
    rows="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker ps -a --filter label=com.docker.compose.service \
        ${project[@]+"${project[@]}"} --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.service"}}')"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        ui_failed "Docker does not list containers within ${NOO_DOCKER_PROBE_SECS}s: it is not answering; nothing here can start the stack until it does." >&2
        return 0
    fi
    printf '%s\n' "$rows" | while read -r id name svc; do
        [ -n "$id" ] && [ -n "$svc" ] || continue
        printf '%s\n' "$all" | grep -qx "$svc" || continue
        st="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker inspect -f '{{.State.Status}}' "$id")"
        [ "$?" -eq 124 ] && printf '%s %s %s\n' "$svc" "$id" "$name"
    done
    return 0
}

# _noo_report_hung <service> <container id> <container name> — the one plain
# statement, and the report file line the callers read.
_noo_report_hung() {
    ui_failed "$3 ($1) is stuck: its process did not exit and Docker cannot remove it (docker inspect gets no answer in ${NOO_DOCKER_PROBE_SECS}s). Starting the rest of the stack without it; $(_noo_service_role "$1") until then. Only a reboot of this host removes it."
    if [ -n "${NOO_STUCK_REPORT:-}" ]; then
        printf '%s\n%s\n' "$1" "$2" >> "$NOO_STUCK_REPORT" 2>/dev/null || true
    fi
}

# noo_hold_hung "<services>" <docker compose args before up> — probe the stack
# (or only the services named, space-separated; "" = all), report each stuck
# one, and put them in NOO_ISOLATED_SERVICES. For callers that do not go
# through noo_compose_up_isolating_stuck (restart, named services).
noo_hold_hung() {
    local only="$1" svc id name held=""
    shift
    NOO_ISOLATED_SERVICES=""
    while read -r svc id name; do
        [ -n "$svc" ] || continue
        if [ -n "$only" ]; then case " $only " in *" $svc "*) ;; *) continue ;; esac; fi
        case " $held " in *" $svc "*) continue ;; esac
        _noo_report_hung "$svc" "$id" "$name"
        held="${held:+$held }$svc"
    done <<EOF_HUNG
$(_noo_hung_services "$@")
EOF_HUNG
    NOO_ISOLATED_SERVICES="$held"
    return 0
}

# noo_stack_ps_ids [service...] — the container ids for noo_created_guard,
# never asking Docker about a service held above (a compose `ps` that meets
# the stuck container hangs with it). Uses $COMPOSE_FILES and $PROFILE_ARGS.
noo_stack_ps_ids() {
    local svcs="$*" s keep=""
    if [ -z "${NOO_ISOLATED_SERVICES:-}" ]; then
        # shellcheck disable=SC2086
        docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq $svcs
        return 0
    fi
    # shellcheck disable=SC2086
    [ -n "$svcs" ] || svcs="$(docker compose $COMPOSE_FILES $PROFILE_ARGS config --services 2>/dev/null)"
    for s in $svcs; do
        case " $NOO_ISOLATED_SERVICES " in *" $s "*) continue ;; esac
        keep="${keep:+$keep }$s"
    done
    [ -n "$keep" ] || return 0
    # shellcheck disable=SC2086
    _noo_bounded "$NOO_DOCKER_PROBE_SECS" docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq $keep
}

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
    local isolated="" round ids id gpu name svc why all hid hname
    if [ "$seen_up" = 1 ]; then
        # Ask about every container first (the 2026-11-25 shape: no error to
        # read, Docker simply never answers about one of them).
        while read -r svc hid hname; do
            [ -n "$svc" ] || continue
            case " $isolated " in *" $svc "*) continue ;; esac
            _noo_report_hung "$svc" "$hid" "$hname"
            isolated="${isolated:+$isolated }$svc"
        done <<EOF_HUNG
$(_noo_hung_services "${base[@]}")
EOF_HUNG
        if [ -n "$isolated" ]; then
            NOO_ISOLATED_SERVICES="$isolated"
            all="$(docker "${base[@]}" config --services 2>/dev/null)" || all=""
            others=()
            for svc in $(_noo_core_first $all); do
                case " $isolated " in *" $svc "*) continue ;; esac
                others+=("$svc")
            done
            [ "${#others[@]}" -gt 0 ] || { rm -f "$errf"; return "$NOO_EXIT_STACK_PARTIAL"; }
            argv=("${base[@]}" up --no-deps "${upflags[@]}" "${others[@]}")
        fi
    fi
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
                if [ "${NOO_GPU_LOST:-}" = 1 ]; then
                    # compose_gpu_notice already named the lost GPU and the reboot.
                    ui_failed "${name:-$id} ($svc) is held: it needs the GPU (lost, above). Starting everything else."
                else
                    ui_failed "${name:-$id} ($svc) is held: the GPU did not answer when it started (${why:-GPU device error}); a reboot of this host usually clears it. Starting everything else."
                fi
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
        for svc in $(_noo_core_first $all); do
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
