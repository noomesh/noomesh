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
# Seconds one probe of one container may take before it is asked again, and
# how long the second, longer probe waits (a slow Docker is not a stuck one).
NOO_DOCKER_PROBE_SECS="${NOO_DOCKER_PROBE_SECS:-10}"
NOO_DOCKER_REPROBE_SECS="${NOO_DOCKER_REPROBE_SECS:-30}"
# How long a start stage waits for its services to be healthy/running.
NOO_STAGE_WAIT_SECS="${NOO_STAGE_WAIT_SECS:-120}"
# The data stores and the bus: started and waited for before everything else.
NOO_STACK_CORE_SERVICES="${NOO_STACK_CORE_SERVICES:-postgres redis nats}"
# What the probe found (set by noo_hold_hung; the snapshot, the guard and the
# add-on helpers read them so no call of theirs names a held container):
NOO_HELD_IDS=""            # container ids Docker did not answer for
NOO_HELD_NAMES=""          # their names
NOO_EXCLUDED_SERVICES=""   # services compose would touch the held one through
NOO_PROBE_DONE=""          # 1 once noo_hold_hung ran for this launch
_NOO_CFG_JSON=""

# _noo_bounded <secs> cmd args... — run cmd with a deadline that HOLDS (the
# same shape as _noo_nvidia_smi_bounded in lib-compose.sh: the child runs in
# the background with its output in files, nothing waits on it past the
# deadline). Prints cmd's stdout, its stderr on stderr, and returns its
# status; 124 = no answer in time (the child's whole group is sent KILL and
# left; it may never die). The temp dir is removed on every path, and on
# INT/TERM while waiting.
_noo_bounded() {
    local secs="$1" d ticks rc child sub oldint oldterm
    shift
    # Fail closed: without a temp dir the call cannot be bounded, and an
    # unbounded call is the defect this library exists to remove.
    d="$(mktemp -d "${TMPDIR:-/tmp}/noo-bounded.XXXXXX" 2>/dev/null)" || { echo "noo: no temp dir for a bounded call to docker (TMPDIR=${TMPDIR:-/tmp}); not running it unbounded" >&2; return 125; }
    oldint="$(trap -p INT)"; oldterm="$(trap -p TERM)"
    # shellcheck disable=SC2064
    trap "rm -rf '$d'; exit 143" INT TERM
    (
        if command -v setsid >/dev/null 2>&1; then
            setsid "$@" >"$d/out" 2>"$d/err" </dev/null &
        else
            "$@" >"$d/out" 2>"$d/err" </dev/null &
        fi
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
        cat "$d/err" >&2 2>/dev/null
        rc="${rc:-1}"
    else
        child="$(cat "$d/pid" 2>/dev/null)"
        if [ -n "$child" ]; then
            kill -KILL -- "-$child" 2>/dev/null
            kill -KILL "$child" 2>/dev/null
        fi
        kill -KILL "$sub" 2>/dev/null
        rc=124
    fi
    rm -rf "$d"
    trap - INT TERM
    [ -n "$oldint" ] && eval "$oldint"
    [ -n "$oldterm" ] && eval "$oldterm"
    [ "$rc" -eq 124 ] || wait "$sub" 2>/dev/null
    return "$rc"
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

# _noo_core_first <services...> — one per line: the data stores and the bus
# first, then the rest in the order given.
_noo_core_first() {
    local s c
    for c in $NOO_STACK_CORE_SERVICES; do
        for s in "$@"; do [ "$s" = "$c" ] && printf '%s\n' "$s"; done
    done
    for s in "$@"; do
        case " $NOO_STACK_CORE_SERVICES " in *" $s "*) ;; *) printf '%s\n' "$s" ;; esac
    done
}

# _noo_rel <mode> args... — the compose relations, read from the rendered
# config (never a list of names): `excluded <held...>` prints "service<TAB>why"
# for each service compose would touch the held one through: a service that
# shares a held service's network namespace (network_mode: service:<held>),
# the door a held service joins, and the services a held one depends on with
# `restart: true` (compose restarts the held one with them). `closure
# <svc...>` prints the services and everything they depend_on. `layers
# <svc...>` prints the services as dependency layers, one per line.
# Without python3 or a readable config it prints nothing, and the callers
# degrade (no exclusion, one layer) and say so.
_noo_rel() {
    [ -n "$_NOO_CFG_JSON" ] && command -v python3 >/dev/null 2>&1 || return 1
    printf '%s' "$_NOO_CFG_JSON" | python3 -c '
import json, sys
try:
    cfg = json.load(sys.stdin)
except Exception:
    sys.exit(1)
svcs = cfg.get("services", {}) or {}
mode, args = sys.argv[1], sys.argv[2:]
def deps(s):
    d = (svcs.get(s) or {}).get("depends_on") or {}
    if isinstance(d, list):
        return {x: {} for x in d}
    return d
def netdep(s):
    n = (svcs.get(s) or {}).get("network_mode") or ""
    return n[8:] if n.startswith("service:") else ""
if mode == "excluded":
    held = set(args)
    out = {}
    for s in svcs:
        if s not in held and netdep(s) in held:
            out[s] = "it shares the network namespace of " + netdep(s)
    for h in held:
        nd = netdep(h)
        if nd and nd not in held:
            out.setdefault(nd, h + " joins its network namespace")
        for d, c in deps(h).items():
            if isinstance(c, dict) and c.get("restart") and d not in held:
                out.setdefault(d, "compose restarts " + h + " with it")
    for k in sorted(out):
        print(k + "\t" + out[k])
elif mode == "closure":
    seen, todo = [], list(args)
    while todo:
        s = todo.pop(0)
        if s in seen or s not in svcs:
            continue
        seen.append(s)
        todo.extend(sorted(deps(s)))
    print(" ".join(seen))
elif mode == "layers":
    sel, done, left = list(args), set(), list(args)
    while left:
        layer = [s for s in left if all(d in done or d not in sel for d in deps(s))] or list(left)
        print(" ".join(layer))
        done |= set(layer)
        left = [s for s in left if s not in done]
' "$@"
}

# _noo_project — the compose project this launch belongs to.
_noo_project() { printf '%s' "${COMPOSE_PROJECT_NAME:-noomesh}"; }

# noo_name_is_held <container name or id> — true for a held container.
noo_name_is_held() {
    local h
    for h in ${NOO_HELD_NAMES:-}; do [ "$h" = "${1#/}" ] && return 0; done
    for h in ${NOO_HELD_IDS:-}; do
        case "$1" in "$h"*) return 0 ;; esac
        case "$h" in "$1"*) [ -n "$1" ] && return 0 ;; esac
    done
    return 1
}

# _noo_hung_services — "service id name" per container of this project (every
# container, whatever profiles are active) whose `docker inspect` got no
# answer within the bound, asked a second time with the longer one
# (NOO_DOCKER_REPROBE_SECS). Listing uses `docker ps` (which does not touch
# each container); the probes run NOO_PROBE_FANOUT (6) at a time. Returns 3
# when the listing itself got no answer or failed: nothing was probed, and the
# caller must not run compose.
_noo_hung_services() {
    local rows id name svc rc d n=0 running=0 i proj
    proj="$(_noo_project)"
    rows="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker ps -a --filter "label=com.docker.compose.project=$proj" \
        --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.service"}}')"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        ui_failed "Docker did not list containers within ${NOO_DOCKER_PROBE_SECS}s: it is not answering. Nothing was started or restarted; try again once Docker answers (systemctl status docker)." >&2
        return 3
    fi
    if [ "$rc" -ne 0 ]; then
        ui_failed "Could not list the containers of project $proj (docker ps exited $rc), so none was probed. Nothing was started or restarted; try again once Docker answers (systemctl status docker)." >&2
        return 3
    fi
    d="$(mktemp -d "${TMPDIR:-/tmp}/noo-probe.XXXXXX" 2>/dev/null)" || { ui_failed "No temp dir to probe the containers with: nothing was started or restarted." >&2; return 3; }
    while read -r id name svc; do
        [ -n "$id" ] && [ -n "$svc" ] || continue
        n=$((n + 1))
        (
            _noo_bounded "$NOO_DOCKER_PROBE_SECS" docker inspect -f '{{.State.Status}}' "$id" >/dev/null 2>&1
            [ "$?" -eq 124 ] || exit 0
            # Slow is not stuck: one more try, with the longer bound.
            _noo_bounded "$NOO_DOCKER_REPROBE_SECS" docker inspect -f '{{.State.Status}}' "$id" >/dev/null 2>&1
            [ "$?" -eq 124 ] && printf '%s %s %s\n' "$svc" "$id" "$name" > "$d/$n"
            exit 0
        ) </dev/null &
        running=$((running + 1))
        if [ "$running" -ge "${NOO_PROBE_FANOUT:-6}" ]; then wait; running=0; fi
    done <<EOF_ROWS
$rows
EOF_ROWS
    wait
    i=1
    while [ "$i" -le "$n" ]; do
        [ -f "$d/$i" ] && cat "$d/$i"
        i=$((i + 1))
    done
    rm -rf "$d"
    return 0
}

# _noo_report_hung <service> <container id> <container name> — the one plain
# statement per held container, worded as what is known, and the report line.
_noo_report_hung() {
    local what
    what="$(_noo_service_role "$1")"
    case "$1" in
        gateway|postgres)
            ui_failed "THE CONTROLLER IS NOT UP: $3 ($1) is held, and $what." ;;
    esac
    ui_failed "Docker did not answer for $3 ($1) in ${NOO_DOCKER_PROBE_SECS}s, and not again in ${NOO_DOCKER_REPROBE_SECS}s. If it still does not answer, its process most likely did not exit and Docker cannot remove it; only a reboot of this host removes it. Starting the rest of the stack without it; $what until then."
    if [ -n "${NOO_STUCK_REPORT:-}" ]; then
        printf '%s\n%s\n' "$1" "$2" >> "$NOO_STUCK_REPORT" 2>/dev/null || true
    fi
}

# noo_hold_hung "<ignored>" <docker compose args before up> — probe EVERY
# stack container first (before anything inspects them), report each held one,
# then work out which other services compose would touch it through. Sets
# NOO_ISOLATED_SERVICES (held), NOO_HELD_IDS, NOO_HELD_NAMES,
# NOO_EXCLUDED_SERVICES and NOO_PROBE_DONE. Returns 3 when Docker does not
# list containers at all (the caller stops), else 0.
noo_hold_hung() {
    local svc id name held="" rows rc svcname why
    shift
    NOO_ISOLATED_SERVICES=""; NOO_HELD_IDS=""; NOO_HELD_NAMES=""
    NOO_EXCLUDED_SERVICES=""; NOO_PROBE_DONE=1; _NOO_CFG_JSON=""
    rows="$(_noo_hung_services "$@")"
    rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    while read -r svc id name; do
        [ -n "$svc" ] || continue
        _noo_report_hung "$svc" "$id" "$name"
        case " $held " in *" $svc "*) ;; *) held="${held:+$held }$svc" ;; esac
        NOO_HELD_IDS="${NOO_HELD_IDS:+$NOO_HELD_IDS }$id"
        NOO_HELD_NAMES="${NOO_HELD_NAMES:+$NOO_HELD_NAMES }${name#/}"
    done <<EOF_HUNG
$rows
EOF_HUNG
    NOO_ISOLATED_SERVICES="$held"
    [ -n "$held" ] || return 0
    _NOO_CFG_JSON="$(_noo_bounded 30 docker "$@" config --format json 2>/dev/null)" || _NOO_CFG_JSON=""
    # shellcheck disable=SC2046
    rows="$(_noo_rel excluded $held)" || rows=""
    if [ -z "$_NOO_CFG_JSON" ] || ! command -v python3 >/dev/null 2>&1; then
        ui_warned "could not read the compose relations (no python3 or no config): services linked to $held cannot be told apart, so none are left out"
    fi
    while IFS="$(printf '\t')" read -r svcname why; do
        [ -n "$svcname" ] || continue
        ui_warned "not touching $svcname ($why): compose would act on the held container"
        NOO_EXCLUDED_SERVICES="${NOO_EXCLUDED_SERVICES:+$NOO_EXCLUDED_SERVICES }$svcname"
    done <<EOF_EXC
$rows
EOF_EXC
    return 0
}

# noo_service_is_left_out <service> — held, or linked to a held one.
noo_service_is_left_out() {
    case " ${NOO_ISOLATED_SERVICES:-} ${NOO_EXCLUDED_SERVICES:-} " in *" $1 "*) return 0 ;; esac
    return 1
}

# noo_depends_on_held <service> — true when the service needs (depends_on, any
# depth) a held one: starting it alone would only make it fail.
noo_depends_on_held() {
    local c h
    c="$(_noo_rel closure "$1")" || return 1
    for h in ${NOO_ISOLATED_SERVICES:-}; do
        [ "$h" = "$1" ] && continue
        case " $c " in *" $h "*) return 0 ;; esac
    done
    return 1
}

# noo_not_held_ids — stdin: container ids (short or full), one per line; stdout:
# those that are not held. The snapshot and the add-on helpers filter through
# it so no `docker inspect` they run names a held container.
noo_not_held_ids() {
    local id h keep
    while read -r id; do
        [ -n "$id" ] || continue
        keep=1
        for h in ${NOO_HELD_IDS:-}; do
            case "$id" in "$h"*) keep=0 ;; esac
            case "$h" in "$id"*) keep=0 ;; esac
        done
        [ "$keep" = 1 ] && printf '%s\n' "$id"
    done
    return 0
}

# noo_stack_ps_ids [service...] — the container ids for noo_created_guard,
# never asking Docker about a service left out above (a compose `ps` that
# meets the held container hangs with it). Uses $COMPOSE_FILES and $PROFILE_ARGS.
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
        noo_service_is_left_out "$s" && continue
        keep="${keep:+$keep }$s"
    done
    [ -n "$keep" ] || return 0
    # shellcheck disable=SC2086
    _noo_bounded "$NOO_DOCKER_PROBE_SECS" docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq $keep | noo_not_held_ids
}

# _noo_wait_ready <seconds> <compose args...> -- <service>... — wait, bounded
# (one deadline for the whole stage), for each service's container to be
# healthy (when it has a healthcheck) or running. A service with no container
# (scaled to 0, never created) is not waited for. One not ready in time is
# said and the start goes on.
_noo_wait_ready() {
    local secs="$1" cargs=() s id st deadline
    shift
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do cargs+=("$1"); shift; done
    shift
    deadline=$((SECONDS + secs))
    for s in "$@"; do
        while :; do
            id="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker "${cargs[@]}" ps -aq "$s" 2>/dev/null | head -1)"
            [ -n "$id" ] || break
            st="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null)"
            case "$st" in healthy|running) break ;; esac
            if [ "$SECONDS" -ge "$deadline" ]; then
                ui_warned "$s was not ready within ${secs}s (${st:-unknown}); continuing with the rest"
                break
            fi
            sleep 2
        done
    done
}

# _noo_sweep_created <service>... — after the last stage: a container of THIS
# project, of one of the named services (the ones this start brought up: never
# an out-of-profile or scaled-out leftover, which noo_created_guard removes),
# still in Created, is started by name, bounded, and said. A held container or
# one linked to it is never started.
_noo_sweep_created() {
    local rows id name svc
    rows="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker ps -a --filter status=created \
        --filter "label=com.docker.compose.project=$(_noo_project)" \
        --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.service"}}')" || return 0
    printf '%s\n' "$rows" | while read -r id name svc; do
        [ -n "$id" ] && [ -n "$svc" ] || continue
        case " $* " in *" $svc "*) ;; *) continue ;; esac
        noo_service_is_left_out "$svc" && continue
        noo_name_is_held "$id" && continue
        if _noo_bounded "$NOO_DOCKER_PROBE_SECS" docker start "$name" >/dev/null 2>&1; then
            ui_warned "$name ($svc) was left in Created by the start: started it"
        else
            ui_failed "$name ($svc) was left in Created and docker start did not bring it up: start it with: docker start $name"
        fi
    done
    return 0
}

# _noo_not_up <compose args...> -- <service>... — the named services whose
# container is missing, or neither running nor a one-shot that finished
# cleanly, one per line. Bounded.
_noo_not_up() {
    local cargs=() s id st
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do cargs+=("$1"); shift; done
    shift
    for s in "$@"; do
        id="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker "${cargs[@]}" ps -aq "$s" 2>/dev/null | head -1)"
        [ -n "$id" ] || { printf '%s\n' "$s"; continue; }
        st="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$id" 2>/dev/null)"
        case "$st" in running\ *|"exited 0") ;; *) printf '%s\n' "$s" ;; esac
    done
}

# _noo_scaled_out <up flags...> — the services `--scale <svc>=0` asked to keep out.
_noo_scaled_out() {
    local prev="" a
    for a in "$@"; do
        case "$prev" in
            --scale) case "$a" in *=0) printf '%s\n' "${a%=0}" ;; esac ;;
        esac
        case "$a" in --scale=*=0) a="${a#--scale=}"; printf '%s\n' "${a%=0}" ;; esac
        prev="$a"
    done
}

# _noo_staged_up <docker compose args before up> -- <up flags> -- <service>... —
# the services (and, for a named start, everything they depend on that is not
# held or left out) are brought up in explicit stages, each its own
# `up --no-deps` call, so the answer to "does compose order services under
# --no-deps" does not matter: (1) the data stores and the bus, then a bounded
# wait for them; (2..) the rest in dependency layers read from the compose
# config, each followed by the same wait; then the Created sweep. Services
# scaled to 0 and, when NOO_STACK_ACTIVE_SERVICES is set, services outside it
# are not part of this start. Returns 0 when everything this start brought up
# is up (whatever a stage's own exit code said); else the failing stage's
# status (1 if none).
_noo_staged_up() {
    local base=() flags=() want=() sel=() s rc=0 r core="" rest=() layers layer closure out failed
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do base+=("$1"); shift; done
    shift
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do flags+=("$1"); shift; done
    shift
    want=("$@")
    if closure="$(_noo_rel closure "${want[@]}")" && [ -n "$closure" ]; then
        # shellcheck disable=SC2206
        want=($closure)
    fi
    out="$(_noo_scaled_out "${flags[@]}")"
    for s in "${want[@]}"; do
        noo_service_is_left_out "$s" && continue
        case " $(printf '%s' "$out" | tr '\n' ' ') " in *" $s "*) continue ;; esac
        if [ -n "${NOO_STACK_ACTIVE_SERVICES:-}" ]; then
            printf '%s\n' "$NOO_STACK_ACTIVE_SERVICES" | tr ' ' '\n' | grep -qx "$s" || continue
        fi
        sel+=("$s")
    done
    [ "${#sel[@]}" -gt 0 ] || return 0
    for s in "${sel[@]}"; do
        case " $NOO_STACK_CORE_SERVICES " in *" $s "*) core="${core:+$core }$s" ;; *) rest+=("$s") ;; esac
    done
    if [ -n "$core" ]; then
        # shellcheck disable=SC2086
        docker "${base[@]}" up --no-deps "${flags[@]}" $core || { r=$?; [ "$r" -gt "$rc" ] && rc=$r; }
        # shellcheck disable=SC2086
        _noo_wait_ready "$NOO_STAGE_WAIT_SECS" "${base[@]}" -- $core
    fi
    if [ "${#rest[@]}" -gt 0 ]; then
        layers="$(_noo_rel layers "${rest[@]}")" || layers="${rest[*]}"
        while IFS= read -r layer; do
            [ -n "$layer" ] || continue
            # shellcheck disable=SC2086
            docker "${base[@]}" up --no-deps "${flags[@]}" $layer || { r=$?; [ "$r" -gt "$rc" ] && rc=$r; }
            # shellcheck disable=SC2086
            _noo_wait_ready "$NOO_STAGE_WAIT_SECS" "${base[@]}" -- $layer
        done <<EOF_LAYERS
$layers
EOF_LAYERS
    fi
    _noo_sweep_created "${sel[@]}"
    failed="$(_noo_not_up "${base[@]}" -- "${sel[@]}" | tr '\n' ' ')"
    if [ -n "${failed// /}" ]; then
        ui_failed "did not come up: ${failed% }"
        [ "$rc" -ne 0 ] || rc=1
        return "$rc"
    fi
    return 0
}

# noo_staged_up <up flags...> -- <service>... — the same, for the launchers'
# named starts (uses $COMPOSE_FILES and $PROFILE_ARGS).
noo_staged_up() {
    local flags=(-d)
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do flags+=("$1"); shift; done
    shift
    # shellcheck disable=SC2086
    _noo_staged_up compose $COMPOSE_FILES $PROFILE_ARGS -- "${flags[@]}" -- "$@"
}

# noo_staged_restart <service>... — `compose restart`, by stage, for the
# services that are not held or left out and have a container (the whole-stack
# restart with a held container). Uses $COMPOSE_FILES and $PROFILE_ARGS.
# Returns 0 when each is up afterwards, else compose's failing status (1).
noo_staged_restart() {
    local sel=() s layers layer rc=0 r core="" rest=() failed id
    for s in "$@"; do
        noo_service_is_left_out "$s" && continue
        # shellcheck disable=SC2086
        id="$(_noo_bounded "$NOO_DOCKER_PROBE_SECS" docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq "$s" 2>/dev/null | head -1)"
        [ -n "$id" ] || continue
        sel+=("$s")
    done
    [ "${#sel[@]}" -gt 0 ] || return 0
    for s in "${sel[@]}"; do
        case " $NOO_STACK_CORE_SERVICES " in *" $s "*) core="${core:+$core }$s" ;; *) rest+=("$s") ;; esac
    done
    if [ -n "$core" ]; then
        # shellcheck disable=SC2086
        docker compose $COMPOSE_FILES $PROFILE_ARGS restart $core || { r=$?; [ "$r" -gt "$rc" ] && rc=$r; }
        # shellcheck disable=SC2086
        _noo_wait_ready "$NOO_STAGE_WAIT_SECS" compose $COMPOSE_FILES $PROFILE_ARGS -- $core
    fi
    if [ "${#rest[@]}" -gt 0 ]; then
        layers="$(_noo_rel layers "${rest[@]}")" || layers="${rest[*]}"
        while IFS= read -r layer; do
            [ -n "$layer" ] || continue
            # shellcheck disable=SC2086
            docker compose $COMPOSE_FILES $PROFILE_ARGS restart $layer || { r=$?; [ "$r" -gt "$rc" ] && rc=$r; }
            # shellcheck disable=SC2086
            _noo_wait_ready "$NOO_STAGE_WAIT_SECS" compose $COMPOSE_FILES $PROFILE_ARGS -- $layer
        done <<EOF_LAYERS
$layers
EOF_LAYERS
    fi
    # shellcheck disable=SC2086
    failed="$(_noo_not_up compose $COMPOSE_FILES $PROFILE_ARGS -- "${sel[@]}" | tr '\n' ' ')"
    if [ -n "${failed// /}" ]; then
        ui_failed "not running after the restart: ${failed% }"
        [ "$rc" -ne 0 ] || rc=1
        return "$rc"
    fi
    return 0
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
    [ "${NOO_PROBE_DONE:-}" = 1 ] || NOO_ISOLATED_SERVICES=""
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
    if [ "$seen_up" = 1 ]; then
        # Ask about every container first (the 2026-11-25 shape: no error to
        # read, Docker simply never answers about one of them). A caller that
        # already probed (start_inputs_full_up, before its snapshot) is not
        # asked to again.
        if [ "${NOO_PROBE_DONE:-}" != 1 ]; then
            noo_hold_hung "" "${base[@]}" || { rm -f "$errf"; return 1; }
        fi
        isolated="$NOO_ISOLATED_SERVICES"
        if [ -n "$isolated" ]; then
            all="$(docker "${base[@]}" config --services 2>/dev/null)" || all=""
            others=()
            for svc in $(_noo_core_first $all); do
                noo_service_is_left_out "$svc" || others+=("$svc")
            done
            rm -f "$errf"
            NOO_PROBE_DONE=""
            [ "${#others[@]}" -gt 0 ] || return "$NOO_EXIT_STACK_PARTIAL"
            rc=0
            _noo_staged_up "${base[@]}" -- "${upflags[@]}" -- "${others[@]}" || rc=$?
            [ "$rc" -eq 0 ] || return "$rc"
            return "$NOO_EXIT_STACK_PARTIAL"
        fi
        NOO_PROBE_DONE=""
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
