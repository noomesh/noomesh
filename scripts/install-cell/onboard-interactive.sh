#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# onboard-interactive.sh: the install matrix's `onboard: interactive` hook
# (i677). It runs the README's `noo onboard`, with no flags, through a pty, as a
# stranger would. The pass comes from the cell name:
#   *-literal  Enter at every prompt (where it stops is the result)
#   otherwise  attentive: Enter wherever a default moves forward, typing only
#              what a prompt forces (see onboard_pty.py)
# Every prompt is printed as `PROMPT: <text>` with its `ANSWER:`, so run.sh
# counts them. A loop, a stuck prompt or too many prompts fail the step; they
# never hang to the job limit.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/install-cell/lib.sh
. "$HERE/lib.sh"

case "$CELL" in
    *-literal) PASS=literal ;;
    *)         PASS=attentive ;;
esac
meta pass "$PASS"
meta limits "sudo is passwordless on the runner: a stranger may also meet sudo password prompts"
meta limits "no TPM, no GPU, no tailnet: the at-rest, GPU and tailnet prompts take their no-hardware branch"

# Not a checkout: the README says to run it from any directory that is not one.
cd "$HOME" || exit 1
step_tty onboard-"$PASS" 3600 -- python3 "$HERE/onboard_pty.py" --pass "$PASS" -- noo onboard
