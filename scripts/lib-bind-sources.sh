#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-bind-sources.sh — refuse a `compose up` whose bind-mount sources are
# missing or the wrong type, BEFORE compose touches anything.
#
# Docker does not refuse a bind mount whose host source is missing: it
# creates it, as an empty ROOT-OWNED DIRECTORY, even where the container
# expects a file. stack-v0.2.78 on host8 (2026-09-29): grafana died on
# `read /app/pki/sso/grafana.pub: is a directory`, and a root-owned empty
# `pki/services/model-cache` from an earlier start made the cert reconcile
# hit EACCES. Compose's `bind: create_host_path: false` refuses only one
# container at a time, mid-`up` (with --force-recreate the earlier ones are
# already recreated), and never notices a ghost directory that already
# sits where a file belongs.
#
# The same check refuses a bind-mounted NATS users.conf that names a `$VAR`
# its service is not handed — the OTHER half of the v0.2.78
# roll, where an older CLI's users.conf still said `user: $NATS_USER` after
# the compose stopped handing nats the variable, and NATS would not start.
# Its remedy line names `noo cluster nats-users render`.
#
# The check itself lives in the `noo` binary (`noo config launch-check
# bind-sources`, noo-cli/src/commands/bind_sources.rs) — the same code the
# onboard wizard calls before its own `up`s. This file only feeds it the
# EFFECTIVE config: the caller's own $COMPOSE_FILES and $PROFILE_ARGS, after
# secrets and compose_env are loaded, so interpolation matches the `up`.
#
# Contract:
#   check_bind_sources [--no-deps] [--skip SERVICE]... [SERVICE...]
#     0  every bind source of those services (all, when none are named)
#        (minus each --skip: a service the `up` scales to zero)
#        exists and has the right type — or the check could not run (said
#        loudly on stderr; an older `noo` must not block a start)
#     1  refused: one line per offending source is on stderr; the caller
#        must `exit 1` before `up`
#
# Every launcher `docker compose … up` is preceded by
#   check_bind_sources … || exit 1
# (tests/test_launcher_bind_sources.py holds each launcher to it).
#
# The other pre-start refusal lives here too, because it is the same kind of
# check through the same hidden verb:
#   check_system_credentials
#     0  every system noomesh.yaml declares enabled (evolve, trellion…) has
#        its credentials in this launcher's environment (or .env) — or the
#        check could not run (said loudly; an older `noo` must not block)
#     1  refused: an enabled system lacks a credential the gateway will not
#        start without, and the fix (`noo systems enable <name>`) is on
#        stderr. Without this the gateway crash-looped instead (stack-v0.2.80
#        rehearsal: evolve switched on, NOO_EVOLVE_DDL_PASSWORD never minted).
# Each launcher calls it once, after load_secrets, before its first compose
# command (tests/test_launcher_system_credentials.py holds them to it).
[ -n "${_NOO_LIB_BIND_SOURCES_LOADED:-}" ] && return 0
_NOO_LIB_BIND_SOURCES_LOADED=1

# The launcher's OWN scratch mounts: the dist/dev-overlay neutralisers point
# these variables at `./.<name>-placeholder` directories nothing else makes.
# They are declared by the launcher, so the launcher creates them — as the
# operator, not as Docker's root. Anything else missing is refused.
_bind_sources_make_placeholders() {
    local _v _p
    for _v in NOO_SRC_OVERLAY NOO_UI_STATIC_OVERLAY NOO_UI_INDEX_OVERLAY TRELLION_SRC; do
        _p="${!_v:-}"
        case "$_p" in
            ./.*-placeholder) mkdir -p "$_p" 2>/dev/null || true ;;
        esac
    done
}

check_bind_sources() {
    local _nb _json _rc _root
    _bind_sources_make_placeholders
    if ! command -v noo_bin >/dev/null 2>&1 || ! _nb="$(noo_bin 2>/dev/null)"; then
        echo "WARNING: no noo binary found — bind-mount sources NOT checked before start" >&2
        return 0
    fi
    # shellcheck disable=SC2086  # COMPOSE_FILES / PROFILE_ARGS are word lists by design
    if ! _json="$(docker compose $COMPOSE_FILES $PROFILE_ARGS config --format json 2>/dev/null)"; then
        # `up` renders the same config and will print compose's own error.
        echo "WARNING: could not render the compose config — bind-mount sources NOT checked" >&2
        return 0
    fi
    _root="${NOO_DATA_ROOT:-$(grep -E '^[[:space:]]*NOO_DATA_ROOT=' .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' \t\r"')}"
    _rc=0
    printf '%s' "$_json" | "$_nb" config launch-check bind-sources \
        --data-root "${_root:-/var/lib/noo}" "$@" || _rc=$?
    case "$_rc" in
        0) return 0 ;;
        3) return 1 ;;
        *)
            echo "WARNING: '$_nb config launch-check bind-sources' could not run (exit $_rc; an older noo?) — bind-mount sources NOT checked" >&2
            return 0 ;;
    esac
}

check_system_credentials() {
    local _nb _rc
    if ! command -v noo_bin >/dev/null 2>&1 || ! _nb="$(noo_bin 2>/dev/null)"; then
        echo "WARNING: no noo binary found — enabled systems' credentials NOT checked before start" >&2
        return 0
    fi
    _rc=0
    "$_nb" config launch-check system-credentials noomesh.yaml || _rc=$?
    case "$_rc" in
        0) return 0 ;;
        3) return 1 ;;
        *)
            echo "WARNING: '$_nb config launch-check system-credentials' could not run (exit $_rc; an older noo?) — enabled systems' credentials NOT checked" >&2
            return 0 ;;
    esac
}
