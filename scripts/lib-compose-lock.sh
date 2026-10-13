#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Single-flight for every compose-mutating entry point.
#
# The 2026-07-31 fleet outage was two recreate paths interleaving: a second
# `noo stack start` issued before the first settled left the whole stack in
# `Created` with rename orphans (`<hex>_noo-<name>`) blocking recreation.
# The watcher's stack-rebuild already has its own single-flight
# (*.rebuild.running); this extends the same guarantee across ALL the
# launcher-family scripts AND the watcher's per-service compose calls, with
# one shared lock file.
#
# Usage (source, then call once before the first compose mutation):
#   source "$(dirname "$0")/lib-compose-lock.sh"
#   acquire_compose_lock || exit 1
#
# Blocking with a visible notice, not refusing: the operator's instinct in
# an incident is to re-run the command, and queueing that harmlessly is
# strictly better than either racing (the outage) or erroring (which invites
# a third, angrier attempt). The lock dies with the process (flock on an
# inherited fd), so no stale-lock cleanup is ever needed.

COMPOSE_LOCK_FILE="${COMPOSE_LOCK_FILE:-${TMPDIR:-/tmp}/noo-compose.lock}"
COMPOSE_LOCK_WAIT="${COMPOSE_LOCK_WAIT:-600}"

# Name whoever holds the lock (finding #100: a stray compose child that
# survived a Ctrl+C held it invisibly, and "if you are CERTAIN nothing is
# running" is unanswerable when the holder is anonymous). Best-effort —
# fuser (psmisc) or lsof; silence when neither exists.
_compose_lock_holder() {
    local pids=""
    if command -v fuser >/dev/null 2>&1; then
        pids="$(fuser "$COMPOSE_LOCK_FILE" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' || true)"
    elif command -v lsof >/dev/null 2>&1; then
        pids="$(lsof -t "$COMPOSE_LOCK_FILE" 2>/dev/null || true)"
    fi
    [ -n "$pids" ] || return 0
    echo "       lock holder(s):" >&2
    local p
    for p in $pids; do
        ps -o pid=,etime=,cmd= -p "$p" 2>/dev/null | sed 's/^/         /' >&2 || true
    done
}

acquire_compose_lock() {
    exec 9>>"$COMPOSE_LOCK_FILE" || {
        echo "WARN: cannot open compose lock $COMPOSE_LOCK_FILE — continuing UNLOCKED" >&2
        return 0
    }
    if flock -n 9; then
        return 0
    fi
    echo "Another stack start/restart/rebuild is in progress — waiting for it" \
         "to finish (up to ${COMPOSE_LOCK_WAIT}s; Ctrl+C to give up)..."
    _compose_lock_holder
    if flock -w "$COMPOSE_LOCK_WAIT" 9; then
        echo "Lock acquired — continuing."
        return 0
    fi
    echo "ERROR: gave up waiting for the compose lock after ${COMPOSE_LOCK_WAIT}s." >&2
    _compose_lock_holder
    echo "       A holder above that is a stray/leftover (e.g. an interrupted pull):" >&2
    echo "         kill <pid>   then retry — the lock frees the moment its holder dies." >&2
    echo "       No holder shown and nothing running?  rm -f $COMPOSE_LOCK_FILE  and retry." >&2
    return 1
}
