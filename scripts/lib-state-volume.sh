#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# check_state_volume_open — refuse to START the stack when this install's
# state root (NOO_STATE_ROOT) is the encrypted, TPM-unlocked state volume
# (i10a) and that volume is not open and mounted. Started anyway, postgres,
# redis, nats and the rest would find an empty directory where their data
# belongs (the mountpoint is `chattr +i`, so they could not even write
# there — they would crash-loop instead). Every launcher calls it once,
# beside check_secrets_at_rest, before its first compose command:
#   check_state_volume_open || exit 1
#     0  no encrypted volume recorded, the state root is not on it (the
#        install was not switched yet), or it is open and mounted — or the
#        check could not run (said loudly; an older `noo` without the verb
#        must not block a start)
#     1  refused: the reason and the recovery pointers are on stderr
# hostd's boot restore (node-agent-go/internal/hostd/boot.go) calls it too,
# so a reboot whose TPM unlock failed does not `docker start` the stack.
# The criterion is NOT restated here: it is `noo config launch-check
# state-root` (noo-cli/src/commands/at_rest_volume.rs), the same reading
# `noo cluster verify --controller` uses for its "at-rest volume" row.
# tests/test_launcher_state_volume.py holds each launcher to the call.
check_state_volume_open() {
    local _nb="" _rc _c
    if command -v noo_bin >/dev/null 2>&1; then
        _nb="$(noo_bin 2>/dev/null || true)"
    fi
    if [ -z "$_nb" ] && [ -n "${NOO_CLI_BIN:-}" ] && [ -x "${NOO_CLI_BIN}" ]; then
        _nb="$NOO_CLI_BIN"
    fi
    if [ -z "$_nb" ]; then
        _nb="$(command -v noo 2>/dev/null || true)"
    fi
    # hostd's boot restore runs from a user unit whose PATH may not hold
    # the operator's ~/.local/bin.
    if [ -z "$_nb" ]; then
        for _c in "${HOME:-/nonexistent}/.local/bin/noo"; do
            if [ -x "$_c" ]; then _nb="$_c"; break; fi
        done
    fi
    if [ -z "$_nb" ]; then
        echo "WARNING: no noo binary found — the encrypted state volume was NOT checked before start" >&2
        return 0
    fi
    _rc=0
    "$_nb" config launch-check state-root . || _rc=$?
    case "$_rc" in
        0) return 0 ;;
        3) return 1 ;;
        *)
            echo "WARNING: '$_nb config launch-check state-root' could not run (exit $_rc; an older noo?) — the encrypted state volume was NOT checked" >&2
            return 0 ;;
    esac
}
