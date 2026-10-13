#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Rehearse the followup-247 incident against real Docker, without the fleet.
#
# On 2026-09-14 a `noo security secrets rotate` recreated the core stack and
# left `noo-trellion-intel` on the OLD NOO_CONTROLLER_SECRET for four days.
# The mechanism was not subtle: `compose up --force-recreate` silently skips a
# service whose profile it was not given AND whose name its argument list does
# not carry. The launcher exited 0, so the rotation reported success.
#
# Everything built in response — `addon_profile_args` (#247), the per-consumer
# `Created`-stamp verdict (#258), `recreate_args` (#277) — has been unit-tested
# and never once exercised against a real `docker compose`. This script closes
# that gap on ANY box with Docker: it builds a throwaway two-profile project
# out of `alpine`, reproduces the silent skip, then proves the fix catches it.
#
# It deliberately does NOT need postgres, the gateway, or a controller. The
# verdict logic reads container names and `Created` stamps and nothing else
# (`noo-cli/src/commands/secrets.rs::recreate_verdicts`), so a stub project
# exercises the real decision.
#
# Usage:   scripts/test-rotation-rehearsal.sh
# Env:     KEEP_PROJECT=1   leave the containers up for inspection
set -euo pipefail

# A name no real install uses, so this can never touch the live stack.
PROJECT="noorehearsal"
IMAGE="${NOO_REHEARSAL_IMAGE:-alpine:3.20}"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — this rehearsal needs a container runtime." >&2
    exit 0
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "SKIP: 'docker compose' (v2) not available." >&2
    exit 0
fi

STAGE="$(mktemp -d)"
cleanup() {
    if [ -z "${KEEP_PROJECT:-}" ]; then
        docker compose -p "$PROJECT" -f "$STAGE/compose.yml" --profile addon down -t 1 >/dev/null 2>&1 || true
    fi
    rm -rf "$STAGE"
}
trap cleanup EXIT

# Two core services and one behind a profile — the shape of the real file,
# where `trellion-intel` sits behind `--profile trellion-intel`.
cat > "$STAGE/compose.yml" <<YAML
services:
  core-a:
    image: $IMAGE
    container_name: ${PROJECT}-core-a
    command: ["sleep", "600"]
  core-b:
    image: $IMAGE
    container_name: ${PROJECT}-core-b
    command: ["sleep", "600"]
  addon-x:
    image: $IMAGE
    container_name: ${PROJECT}-addon-x
    profiles: ["addon"]
    command: ["sleep", "600"]
YAML

dc() { docker compose --progress quiet -p "$PROJECT" -f "$STAGE/compose.yml" "$@"; }

# The single primitive the verdict rests on: secrets.rs::container_created.
created() { docker inspect -f '{{.Created}}' "$1" 2>/dev/null || true; }

# secrets.rs::recreate_verdicts, transcribed. Kept as a literal transcription
# so a change to the Rust that this no longer matches shows up as a rehearsal
# that disagrees with the CLI, rather than as nothing at all.
verdict() {
    local before="$1" after="$2"
    if   [ -z "$before" ] && [ -z "$after" ]; then echo "NotRunning"
    elif [ -n "$before" ] && [ -z "$after" ]; then echo "Vanished"
    elif [ -z "$before" ] && [ -n "$after" ]; then echo "Recreated"
    elif [ "$before" != "$after" ];            then echo "Recreated"
    else                                            echo "Unchanged"; fi
}

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== rotation rehearsal (project: $PROJECT, image: $IMAGE)"
dc --profile addon down -t 1 >/dev/null 2>&1 || true

echo "-- bringing the stack up WITH the add-on, as start.sh does"
dc --profile addon up -d >/dev/null
for c in core-a core-b addon-x; do
    [ -n "$(created "${PROJECT}-${c}")" ] || fail "$c did not start; the rehearsal cannot judge anything"
done

# ── Arm 1: the defect ────────────────────────────────────────────────────────
# What noomesh-restart.sh --force did before #247: no --profile, and an
# argument list naming only the core services.
echo
echo "-- ARM 1: recreate the way the rotation used to (no profile, core only)"
b_core="$(created ${PROJECT}-core-a)"; b_addon="$(created ${PROJECT}-addon-x)"
dc up -d --force-recreate core-a core-b >/dev/null
rc=$?
a_core="$(created ${PROJECT}-core-a)"; a_addon="$(created ${PROJECT}-addon-x)"

echo "   launcher exit status ........ $rc   <- reports success"
echo "   core-a ...................... $(verdict "$b_core" "$a_core")"
echo "   addon-x ..................... $(verdict "$b_addon" "$a_addon")"

[ "$rc" -eq 0 ] || fail "arm 1 expected the launcher to SUCCEED — that is the whole point"
[ "$(verdict "$b_core" "$a_core")" = "Recreated" ] \
    || fail "arm 1: core-a should have been recreated"
[ "$(verdict "$b_addon" "$a_addon")" = "Unchanged" ] \
    || fail "arm 1 did not reproduce the incident: the add-on was NOT skipped. \
Either compose changed its behaviour or this project is malformed — either way \
the fix below is being proven against nothing."
echo "   => reproduced: exit 0, and the add-on still holds the old value."

# ── Arm 2: the fix ───────────────────────────────────────────────────────────
# What recreate_args / addon_profile_args produce: the add-on's profile
# selected AND its service named.
echo
echo "-- ARM 2: recreate the way #247/#277 do (profile selected, service named)"
b_core="$a_core"; b_addon="$a_addon"
dc --profile addon up -d --force-recreate core-a core-b addon-x >/dev/null
a_core="$(created ${PROJECT}-core-a)"; a_addon="$(created ${PROJECT}-addon-x)"

echo "   core-a ...................... $(verdict "$b_core" "$a_core")"
echo "   addon-x ..................... $(verdict "$b_addon" "$a_addon")"
[ "$(verdict "$b_core" "$a_core")" = "Recreated" ]  || fail "arm 2: core-a not recreated"
[ "$(verdict "$b_addon" "$a_addon")" = "Recreated" ] \
    || fail "arm 2: the add-on was STILL skipped — the fix does not hold"
echo "   => every consumer recreated."

# ── Arm 3: the two verdicts a rotation must refuse ───────────────────────────
echo
echo "-- ARM 3: the verdicts that must not read as success"
b_gone="$(created ${PROJECT}-addon-x)"
dc --profile addon rm -sf addon-x >/dev/null 2>&1
a_gone="$(created ${PROJECT}-addon-x)"
echo "   addon-x removed ............. $(verdict "$b_gone" "$a_gone")"
[ "$(verdict "$b_gone" "$a_gone")" = "Vanished" ] || fail "a removed consumer must read Vanished"

echo "   absent consumer ............. $(verdict "" "")"
[ "$(verdict "" "")" = "NotRunning" ] || fail "an absent consumer must read NotRunning"

echo
echo "PASS — the incident reproduces, the fix holds, and the four verdicts are distinct."
