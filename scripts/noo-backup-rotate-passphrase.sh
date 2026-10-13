#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Rotate a backup encryption passphrase.
#
# THIS IS A WRAPPER. The rotation lives in `noo security secrets rotate`, and
# this script only translates its old flags and execs it.
#
#   --age     -> noo security secrets rotate NOO_AGE_BACKUP_PASSPHRASE
#   --pg      -> noo security secrets rotate NOO_BACKUP_PASSPHRASE
#   --both    -> both keys in one invocation
#   --dry-run -> --dry-run
#   --generate is the DEFAULT now (the verb always generates); it is accepted
#              and ignored so existing runbooks and cron lines keep working.
#   --stdout  -> --stdout   (let the generated value reach a non-terminal)
#
# ── Why this file no longer implements anything ──────────────────────────
#
# It used to, and what it implemented was an outage. It treated `.env` as the
# plaintext source of truth and re-encrypted `secrets/env.sops` FROM it:
#
#     sops -e --filename-override secrets/env.sops --input-type dotenv \
#          --output-type dotenv .env > secrets/env.sops
#
# That is a full REPLACE, not a merge. On a sops-first install — the default
# since 2026-08-02 — `.env` holds two bootstrap flags and the store holds
# ~30 secrets, so one run would have reduced the store to those two flags and
# taken the whole cluster down, while also writing both passphrases into
# `.env` in plaintext via `env_set`. CLAUDE.md has a rule with this exact
# name ("Never re-encrypt env.sops from .env") and this script was the thing
# it was written about. Caught in dry-run on the live controller on
# 2026-09-12 before it ever ran; tracker R42.
#
# The fix was not to repair the store write here. `noo security secrets
# rotate` already wrote the store correctly — decrypt, edit only the named
# keys, re-encrypt, diff the KEY SET and refuse on any loss, round-trip
# verify, install by atomic rename, plaintext only ever on a pipe — and it
# already had the phased prepare/verify/commit model. What it lacked was the
# one thing this script did right: re-encrypting the existing backup files
# old → new so they stay openable. That moved into the verb
# (`Class::BackupPassphrase`), which is now the single implementation.
#
# Two implementations of "rotate a passphrase" is how one of them ends up
# wrong and nobody notices. This one was the wrong one.
#
# Use the verb directly; it has better output and a real --dry-run:
#     noo security secrets rotate NOO_AGE_BACKUP_PASSPHRASE
#     noo security secrets rotate NOO_BACKUP_PASSPHRASE NOO_AGE_BACKUP_PASSPHRASE

set -euo pipefail

KEYS=()
PASS=()
for arg in "$@"; do
    case "$arg" in
        --age)  KEYS+=("NOO_AGE_BACKUP_PASSPHRASE") ;;
        --pg)   KEYS+=("NOO_BACKUP_PASSPHRASE") ;;
        --both) KEYS+=("NOO_BACKUP_PASSPHRASE" "NOO_AGE_BACKUP_PASSPHRASE") ;;
        --dry-run) PASS+=("--dry-run") ;;
        --stdout)  PASS+=("--stdout") ;;
        # Accepted and ignored: the verb always mints the value itself. Kept
        # so a runbook or cron line carrying the old flag does not fail.
        --generate) ;;
        -h|--help) sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg (see --help)" >&2; exit 1 ;;
    esac
done

if [ "${#KEYS[@]}" -eq 0 ]; then
    echo "Nothing to do. Pass --age, --pg, or --both (see --help)." >&2
    exit 1
fi

# Deduplicate while preserving order (`--pg --both` is not an error).
declare -A _seen=()
UNIQ=()
for k in "${KEYS[@]}"; do
    [ -n "${_seen[$k]:-}" ] && continue
    _seen[$k]=1
    UNIQ+=("$k")
done

# `noo` is the front door and is on PATH after install. Say so plainly if it
# is not, rather than failing with "command not found" from inside a wrapper
# whose whole job is to delegate.
if ! command -v noo >/dev/null 2>&1; then
    echo "ERROR: this script now delegates to \`noo security secrets rotate\`, and \`noo\` is not on PATH." >&2
    echo "       Install it (scripts/install-noo.sh) or run the verb from wherever the binary lives." >&2
    exit 1
fi

echo "note: this script is a wrapper; running" >&2
echo "      noo security secrets rotate ${UNIQ[*]} ${PASS[*]:-}" >&2
exec noo security secrets rotate "${UNIQ[@]}" ${PASS[@]+"${PASS[@]}"}
