#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-compose.sh — the ONE answer to "which compose files make up this install".
#
# an earlier change. Eight scripts used to build COMPOSE_FILES by hand from
# literals — cluster-init, host-watcher, clean, logs, rebuild, start, restart,
# stop — and no two agreed. start.sh composed the GPU overlay; restart never
# did, so `restart --force` recreated ollama-embed without its GPU
# reservation. restart put the dist overlay before the evolve overlay;
# start put it after. stop/clean/logs never composed the evolve overlay at
# all, so `down --remove-orphans` removed noo-evolve as an ORPHAN of its own
# stack. A hand-mirrored copy of a decision is a copy that drifts (#247 said
# this about profiles; this is the same sentence about files).
#
# Contract:
#   compose_file_list [root]   one path per line, in merge order
#   compose_file_args [root]   the same as "-f a -f b …", for unquoted expansion
#
# Merge order is load-bearing and is start.sh's historical order:
#   1. docker-compose.cluster.yml         the base — the minimal install
#   2. docker-compose.gpu-embed.yml       when present AND a GPU is visible
#                                         (NOO_COMPOSE_GPU=1|0 overrides the
#                                         probe, for tests and headless boxes)
#   3. docker-compose.override.yml        when present
#   4. every enabled add-on overlay       addon_compose_overlay_args (lib-addons)
#   5. the dist overlay                   LAST, so pinned image refs win —
#                                         only when the caller resolved dist
#                                         mode (DIST_MODE=1 + DIST_COMPOSE_FILE,
#                                         from lib-dist's apply_dist_mode)
#
# This file decides the LIST. It does not decide dist mode (lib-dist does) or
# which add-ons are on (lib-addons does); it composes their answers.
[ -n "${_NOO_LIB_COMPOSE_LOADED:-}" ] && return 0
_NOO_LIB_COMPOSE_LOADED=1

_lib_compose_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
# When sourced (not executed) $0 is the caller; find ourselves by BASH_SOURCE
# where bash provides it, else fall back to the caller's scripts/ dir.
if [ -n "${BASH_SOURCE:-}" ]; then
    _lib_compose_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
[ -n "${_NOO_LIB_ADDONS_LOADED:-}" ] || . "$_lib_compose_dir/lib-addons.sh"
[ -n "${_NOO_LIB_DIST_LOADED:-}" ]   || . "$_lib_compose_dir/lib-dist.sh"

# What the NVIDIA GPU is doing: "ok" (answers a per-device query), "lost"
# (the driver is installed and cannot read the card: i277e, Xid 79/154, "GPU
# has fallen off the bus"), or "none" (no NVIDIA driver). `nvidia-smi -L` alone
# is not enough: it can list the card while the device-handle call the
# container runtime makes fails. The query asks only for the index, which every
# GPU answers: memory.total is "[N/A]" on a unified-memory GPU (GB10, Jetson),
# and that GPU is not lost. A card with no driver installed is "none": a box
# set up without the NVIDIA stack, not a fault. NOO_COMPOSE_GPU=1|0 overrides
# (tests, headless boxes); 0 reads "none", the operator's choice of CPU.
_compose_gpu_state() {
    case "${NOO_COMPOSE_GPU:-}" in
        1) echo ok; return 0 ;;
        0) echo none; return 0 ;;
    esac
    if command -v nvidia-smi >/dev/null 2>&1; then
        if nvidia-smi -L >/dev/null 2>&1 \
            && _noo_gpu_q="$(nvidia-smi --query-gpu=index --format=csv,noheader 2>&1)" \
            && ! printf '%s\n' "$_noo_gpu_q" | grep -qiE 'unknown error|unable to determine'; then
            echo ok
        else
            echo lost
        fi
        return 0
    fi
    echo none
}

# A GPU the base can hand to ollama-embed? Probe, unless told.
_compose_gpu_visible() {
    [ "$(_compose_gpu_state)" = ok ]
}

# One line when the driver lost the GPU, naming the cause and the choice.
# The overlay is then NOT requested (_compose_gpu_visible is false), so the
# embedder starts on CPU and the core never waits on a device that cannot
# answer. Silent otherwise. Launchers call it once, after the file list.
# NOO_GPU_LOST=1 tells lib-stuck-container.sh the cause is already said, so a
# GPU backend held on the same start names itself without repeating it.
compose_gpu_notice() {
    [ "$(_compose_gpu_state)" = lost ] || return 0
    NOO_GPU_LOST=1; export NOO_GPU_LOST
    echo "  the NVIDIA driver lost the GPU (nvidia-smi cannot read it): the embedder starts on CPU; reboot to get the GPU back" >&2
}

compose_file_list() {
    _cfl_root="${1:-.}"
    printf '%s\n' "$_cfl_root/docker-compose.cluster.yml"
    if [ -f "$_cfl_root/docker-compose.gpu-embed.yml" ] && _compose_gpu_visible; then
        printf '%s\n' "$_cfl_root/docker-compose.gpu-embed.yml"
    fi
    if [ -f "$_cfl_root/docker-compose.override.yml" ]; then
        printf '%s\n' "$_cfl_root/docker-compose.override.yml"
    fi
    # Add-on overlays: lib-addons echoes "-f <path>" pairs; keep the paths.
    _cfl_addons="$(addon_compose_overlay_args)"
    if [ -n "$_cfl_addons" ]; then
        set -- $_cfl_addons
        while [ $# -gt 0 ]; do
            [ "$1" = "-f" ] && shift
            [ $# -gt 0 ] && printf '%s\n' "$1" && shift
        done
    fi
    if [ "${DIST_MODE:-0}" = 1 ] && [ -n "${DIST_COMPOSE_FILE:-}" ]; then
        printf '%s\n' "$DIST_COMPOSE_FILE"
    fi
}

compose_file_args() {
    _cfa=""
    for _f in $(compose_file_list "${1:-.}"); do
        _cfa="$_cfa -f $_f"
    done
    printf '%s' "${_cfa# }"
}

# The compose project of this install: COMPOSE_PROJECT_NAME, else the cluster
# file's name:, else noomesh. ONE answer for the report and the removal below.
_compose_project_name() {
    _cpn="${COMPOSE_PROJECT_NAME:-}"
    if [ -z "$_cpn" ]; then
        _cpn="$(sed -n 's/^name:[[:space:]]*//p' "${1:-.}/docker-compose.cluster.yml" 2>/dev/null | head -n1)"
        _cpn="${_cpn:-noomesh}"
    fi
    printf '%s' "$_cpn"
}

# ── Remove containers of RETIRED services, and only those (186b step 4) ────
#
# config/retired-services.txt (<service>  <YYYY-MM-DD>  <PR>, whole-line `#`
# comments) lists compose services the repo removed on purpose; `up` leaves
# their container running (noo-cluster-executor ran two days after #98, root,
# with ~/.ssh mounted). Before the whole-stack `up` the launcher removes every
# container, running OR stopped, of THIS install's project whose
# com.docker.compose.service label is on that list, one line each:
#
#   - removed <name>: service <svc> was retired on <date> (<PR>)
#
# This is the only automatic removal and it is safe by declaration. It never
# removes a container whose service is not on the list, one with no service
# label (agent-managed backends), or one of another project. Exit status is
# unchanged: a failed rm prints a line and the loop goes on; a list or a
# docker call it cannot read is said, never read as "nothing retired".
# $1 is the install root (the dir holding config/ and the compose files).
compose_remove_retired() {
    _crr_list="${1:-.}/config/retired-services.txt"
    if [ ! -r "$_crr_list" ]; then
        echo "! could not read $_crr_list, so retired services were NOT checked (not a pass): noo doctor orphans" >&2
        return 0
    fi
    _crr_proj="$(_compose_project_name "${1:-.}")"
    if ! _crr_run="$(docker ps -a --filter "label=com.docker.compose.project=$_crr_proj" \
            --format '{{.Label "com.docker.compose.service"}} {{.Names}}' 2>/dev/null)"; then
        echo "! could not list the containers of project $_crr_proj, so retired services were NOT checked (not a pass): noo doctor orphans" >&2
        return 0
    fi
    printf '%s\n' "$_crr_run" | while read -r _crr_svc _crr_name; do
        [ -n "$_crr_svc" ] && [ -n "$_crr_name" ] || continue
        # "L <date> <PR…>" when the service is on the list; "L" alone is still a hit.
        _crr_meta="$(awk -v s="$_crr_svc" '$1 == s { r = "L"; for (i = 2; i <= NF; i++) r = r " " $i; print r; exit }' "$_crr_list")"
        [ -n "$_crr_meta" ] || continue
        set -f
        set -- $_crr_meta
        shift
        _crr_date="${1:-}"
        [ $# -gt 0 ] && shift
        _crr_pr="$*"
        if docker rm -f "$_crr_name" >/dev/null 2>&1; then
            echo "- removed $_crr_name: service $_crr_svc was retired on $_crr_date ($_crr_pr)"
        else
            echo "! could not remove $_crr_name (service $_crr_svc was retired on $_crr_date ($_crr_pr)): docker rm -f $_crr_name" >&2
        fi
    done
    return 0
}

# ── Report (never reap) containers no compose file of this install declares ─
#
# `up` does not stop a container whose service was deleted from the compose
# files (noo-cluster-executor ran two days after #98), and `up --remove-orphans`
# is NEVER the answer: compose computes orphans against the services and
# profiles of THAT invocation, and every call shape we have hands it a partial
# picture (targeted services, profile set, add-on overlays that come and go).
# So after a whole-stack `up` the launcher only SAYS what is left over:
#
#   ! <name> is not declared by any compose file of this install: docker rm -f <name>
#
# Declared = a service in $COMPOSE_FILES evaluated with --profile '*' (every
# profile counts). Project = COMPOSE_PROJECT_NAME, else the cluster file's
# name:, else noomesh (the pattern bootRestoreScript uses). Containers with
# no com.docker.compose.service label (agent-managed backends) are never
# candidates. Exit status is unchanged: this always returns 0, and when it
# cannot compare it says so rather than reading as clean.
compose_report_undeclared() {
    _cru_proj="$(_compose_project_name "${1:-.}")"
    # shellcheck disable=SC2086
    if ! _cru_decl="$(docker compose $COMPOSE_FILES --profile '*' config --services 2>/dev/null)" || [ -z "$_cru_decl" ]; then
        echo "! could not read the compose services of this install, so running containers were NOT compared with them (not a pass): noo doctor orphans" >&2
        return 0
    fi
    if ! _cru_run="$(docker ps --filter "label=com.docker.compose.project=$_cru_proj" \
            --format '{{.Label "com.docker.compose.service"}} {{.Names}}' 2>/dev/null)"; then
        echo "! could not list the running containers of project $_cru_proj, so they were NOT compared with the compose files (not a pass): noo doctor orphans" >&2
        return 0
    fi
    printf '%s\n' "$_cru_run" | while read -r _cru_svc _cru_name; do
        [ -n "$_cru_svc" ] && [ -n "$_cru_name" ] || continue
        printf '%s\n' "$_cru_decl" | grep -qxF -- "$_cru_svc" && continue
        echo "! $_cru_name is not declared by any compose file of this install: docker rm -f $_cru_name" >&2
    done
    return 0
}

# ── Compose v2 is a prerequisite, and a pull failure says WHY ─────────────
#
# Ubuntu's `docker.io` ships WITHOUT the compose v2 plugin (separate
# `docker-compose-v2` package; Docker's own apt repo calls it
# `docker-compose-plugin`). Without it `docker compose …` is the v1-less
# shim: "unknown shorthand flag: 'f' in -f", exit 125 — and the pull retry
# loop used to read that as a network failure. Semantics, same as the
# onboard prerequisites step (noo-cli/src/onboard/steps.rs):
#   compose ABSENT                 -> require_compose_v2 fails, names the package
#   compose OLD (v1 binary only)   -> the same failure: `docker compose` is the
#                                     v2 plugin; the v1 `docker-compose` is not used
#   compose present, pull fails    -> the pull loop shows compose's real last line

# The package that supplies the plugin. NOO_OS_RELEASE lets a test point at a
# fake os-release; docker-ce (dpkg) means Docker's own apt repository.
compose_v2_package() {
    _osr="${NOO_OS_RELEASE:-/etc/os-release}"
    _id="$(sed -n 's/^ID=//p' "$_osr" 2>/dev/null | tr -d '"' | head -n1)"
    _like="$(sed -n 's/^ID_LIKE=//p' "$_osr" 2>/dev/null | tr -d '"' | head -n1)"
    case " $_id $_like " in
        *" ubuntu "*|*" debian "*)
            if dpkg-query -W docker-ce >/dev/null 2>&1; then
                echo docker-compose-plugin
            else
                echo docker-compose-v2
            fi ;;
        *) echo "" ;;
    esac
}

# 0 when the v2 plugin answers; otherwise one stderr line naming the missing
# plugin and the package, return 1 (callers exit; never enter the retry loop).
require_compose_v2() {
    docker compose version >/dev/null 2>&1 && return 0
    _pkg="$(compose_v2_package)"
    if [ -n "$_pkg" ]; then
        _msg="the Docker Compose v2 plugin is missing — sudo apt install $_pkg (the old docker-compose does not count)"
    else
        _msg="the Docker Compose v2 plugin is missing — install it (the old docker-compose does not count): https://docs.docker.com/compose/install/linux/"
    fi
    if command -v ui_failed >/dev/null 2>&1; then ui_failed "$_msg"; else echo "ERROR: $_msg" >&2; fi
    return 1
}

# compose_pull ERRFILE ARGS... - one attempt of the dist pull; ARGS are the
# compose arguments up to and including `pull` and its services.
#
# On a real terminal (fd 2 is a tty, TERM is not dumb) compose writes straight
# to it and draws its in-place display, like `up` does; ERRFILE is left empty
# and the failure reason is whatever compose printed on screen. Anywhere else
# (a log, CI, a pipe) the output is teed into ERRFILE so a failed attempt can
# quote its LAST line, and compose prints plain progress, which is what a log
# wants.
#
# The output must not be piped on a terminal. A piped compose cannot query
# the console, so even with `--progress tty` it draws every frame below the
# last instead of over it: dozens of repeated "Pulling" blocks per image
# (seen live on the v0.2.95 roll). Returns compose's own exit status.
compose_pull() {
    _cp_err="$1"; shift
    : > "$_cp_err"
    if [ -t 2 ] && [ "${TERM:-dumb}" != dumb ]; then
        docker compose "$@" >&2
        return $?
    fi
    docker compose "$@" 2>&1 | tee "$_cp_err" >&2
    return "${PIPESTATUS[0]}"
}

# Last non-empty line of a captured stderr file, ANSI and carriage returns
# stripped (compose redraws progress with \r).
last_error_line() {
    [ -s "${1:-}" ] || return 0
    tr '\r' '\n' < "$1" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' | grep -v '^[[:space:]]*$' | tail -n 1
}
