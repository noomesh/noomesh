#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-start-inputs.sh — a full `noo stack start` recreates only the containers
# whose inputs changed, decided from the files, not from who called it.
#
# Compose's config hash covers the resolved compose config but NOT the
# contents of bind-mounted files or of `secrets: file:` sources, so the
# launcher used to pass --force-recreate on every full start: right after
# `noo onboard` had started the stack, `noo stack start` recreated all 13
# containers (25-32 s, in every install-matrix cell, config-less containers
# included) and dropped the node agent's NATS link and tunnel.
#
# Now each service carries the label `noo.inputs`: ONE keyed digest of its
# secret files and mounted config (scripts/noo-start-inputs.py says exactly
# which mounts count). The label sits in a generated override
# ($START_INPUTS_OVERRIDE) that the start's `up` includes, so compose's own
# hash changes exactly when an input did: a rotated secret, an edited config
# file or a new PKI leaf recreates its services, and nothing else moves.
#
# --force-recreate stays for:
#   - `noo stack start --recreate` / NOO_START_RECREATE=1 (the explicit force;
#     `noo upgrade` and onboard's own start pass the env form, which an older
#     launcher ignores instead of reading it as a service name);
#   - a host where the fingerprint cannot be computed (no python3, an
#     unrenderable config): today's behaviour, said.
# A key that exists but cannot be read REFUSES the start (exit 1): there is no
# unkeyed fallback, because the label is readable by anyone with docker read
# access.
#
# The state file ($START_INPUTS_STATE, 0600) only serves the message ("recreated
# gateway: its inputs changed (secret noo_jwt_secret)"); it holds per-file
# KEYED values, never a raw digest. The label is the mechanism.
[ -n "${_NOO_LIB_START_INPUTS_LOADED:-}" ] && return 0
_NOO_LIB_START_INPUTS_LOADED=1

_START_INPUTS_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/noo-start-inputs.py"
START_INPUTS_OVERRIDE="${NOO_START_INPUTS_OVERRIDE:-./.noo-start-inputs.yml}"
START_INPUTS_STATE="${NOO_START_INPUTS_STATE:-./.noo-start-inputs.json}"
# The keyed secret digests the launcher writes beside the secret files
# (write_secret_files), before the files go to their containers' uids.
START_INPUTS_SECRET_CACHE_NAME=".noo-inputs"
START_UP_FORCE=""

# The per-install HMAC key: 32 random bytes, 0600, in the operator's private
# config dir beside the age key's home. Only its PATH is ever passed on.
start_inputs_key_file() {
    printf '%s' "${NOO_START_INPUTS_KEY_FILE:-$HOME/.config/noo/start-inputs.key}"
}

_start_inputs_usable() {
    command -v python3 >/dev/null 2>&1 && [ -f "$_START_INPUTS_PY" ]
}

# start_inputs_secret_digests <rundir> <NAME=TMPNAME>... — called by
# write_secret_files while the temp files are still ours to read. A failure
# only drops the cache: fingerprint then cannot read those secrets and
# recreates their services (the old behaviour), and says so.
start_inputs_secret_digests() {
    local d="$1"; shift
    rm -f "$d/$START_INPUTS_SECRET_CACHE_NAME" 2>/dev/null
    _start_inputs_usable || return 0
    python3 "$_START_INPUTS_PY" secret-digests --key-file "$(start_inputs_key_file)" \
        --dir "$d" --out "$d/$START_INPUTS_SECRET_CACHE_NAME" "$@" 2>/dev/null \
        || rm -f "$d/$START_INPUTS_SECRET_CACHE_NAME" 2>/dev/null
    return 0
}

# start_inputs_prepare — before an `up`, with $COMPOSE_FILES and $PROFILE_ARGS
# final. Sets START_UP_FORCE ("" or --force-recreate) and, when the labels
# were computed, appends the override to $COMPOSE_FILES. 1 = refused (the key
# cannot be read); the caller exits before `up`.
start_inputs_prepare() {
    local _json _rc _dd _v
    START_UP_FORCE=""
    if [ "${START_RECREATE:-false}" = true ]; then
        START_UP_FORCE="--force-recreate"
        ui_note "--recreate: every container is recreated"
    fi
    if ! _start_inputs_usable; then
        START_UP_FORCE="--force-recreate"
        ui_note "no python3: changed secret and config files cannot be detected, so every container is recreated"
        return 0
    fi
    # shellcheck disable=SC2086  # word lists by design
    if ! _json="$(docker compose $COMPOSE_FILES $PROFILE_ARGS config --format json 2>/dev/null)"; then
        START_UP_FORCE="--force-recreate"
        ui_note "could not render the compose config to fingerprint its inputs, so every container is recreated"
        return 0
    fi
    _dd=()
    for _v in NOO_DATA_ROOT NOO_STATE_ROOT MODELS_DIR IMAGES_DIR HF_CACHE_DIR OLLAMA_DATA_DIR; do
        _v="$(_start_inputs_env "$_v")"
        [ -n "$_v" ] && _dd+=(--data-dir "$(_start_inputs_abs "$_v")")
    done
    _rc=0
    printf '%s' "$_json" | python3 "$_START_INPUTS_PY" fingerprint \
        --key-file "$(start_inputs_key_file)" --root "$PWD" \
        --pki-dir "$(_start_inputs_abs "$(_start_inputs_env NOO_PKI_DIR)")" \
        "${_dd[@]+"${_dd[@]}"}" \
        --secret-digests "${NOO_SECRET_RUNDIR:-/nonexistent}/$START_INPUTS_SECRET_CACHE_NAME" \
        --old-state "$START_INPUTS_STATE" \
        --override-out "$START_INPUTS_OVERRIDE" --state-out "$START_INPUTS_STATE.new" || _rc=$?
    case "$_rc" in
        0) COMPOSE_FILES="$COMPOSE_FILES -f $START_INPUTS_OVERRIDE" ;;
        3) echo "       Nothing was started. The key only lets the start tell which secret and config files changed." >&2
           echo "       Fix its owner/mode (chmod 600 $(start_inputs_key_file)), or remove it: the next start makes a new one and recreates every container once." >&2
           return 1 ;;
        *) START_UP_FORCE="--force-recreate"
           ui_note "could not fingerprint the services' inputs (exit $_rc), so every container is recreated" ;;
    esac
    return 0
}

_start_inputs_env() {  # environment first, then the last KEY= line in .env
    local _x="${!1:-}"
    if [ -z "$_x" ] && [ -f .env ]; then
        _x="$(grep -E "^[[:space:]]*$1=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    printf '%s' "$_x"
}

_start_inputs_abs() {
    case "$1" in
        "") ;;
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$PWD" "${1#./}" ;;
    esac
}

# start_inputs_snapshot <file> — "service id status" for every container of
# this install's compose project, before and after the `up`.
start_inputs_snapshot() {
    local _proj
    _proj="$(_compose_project_name . 2>/dev/null || true)"
    : > "$1"
    [ -n "$_proj" ] || return 0
    docker ps -aq --filter "label=com.docker.compose.project=$_proj" 2>/dev/null \
        | xargs -r docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{.Id}} {{.State.Status}}' \
        >> "$1" 2>/dev/null || true
}

# start_inputs_report <before> <after> — say what the start did ("13 running,
# 0 recreated", or which services were recreated and which of their files
# changed), then keep this start's state for the next message.
start_inputs_report() {
    local _line _first=1
    _start_inputs_usable || return 0
    while IFS= read -r _line; do
        if [ "$_first" = 1 ]; then ui_kv "Containers" "$_line"; _first=0; else ui_note "$_line"; fi
    done < <(python3 "$_START_INPUTS_PY" report --before "$1" --after "$2" \
        --old-state "$START_INPUTS_STATE" --new-state "$START_INPUTS_STATE.new" \
        --root "$PWD" --secret-dir "${NOO_SECRET_RUNDIR:-}" 2>/dev/null)
    if [ -f "$START_INPUTS_STATE.new" ]; then
        mv -f "$START_INPUTS_STATE.new" "$START_INPUTS_STATE" 2>/dev/null || true
    fi
    rm -f "$1" "$2" 2>/dev/null
    return 0
}
