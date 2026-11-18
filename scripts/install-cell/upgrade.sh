#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The UPGRADE cell of .github/workflows/install-matrix.yml: the first roll a
# real fleet makes. A box on the PREVIOUS final (its generation-1 applier)
# takes the release under test with `noo upgrade --all`, then a same-tag
# `noo upgrade --stack`, on a hosted runner where systemd is PID 1, the one
# thing the rehearsal's dind cannot give (its self node never collects or
# applies a bundle, so i908's release check, i907 1b's netns unit, the
# agent's filesystem hold and the hf-hub re-own were proven end to end by
# nothing).
#
#   OUT=<dir> CELL=upgrade-24.04 RUNNER=<label> CLI_TAG=noo-cli-vX.Y.Z[-rc.N] \
#   scripts/install-cell/upgrade.sh
#
# GITHUB-HOSTED, EPHEMERAL RUNNERS ONLY: it installs with sudo. The operator
# is the runner user (non-root, passwordless sudo).
#
# Every judged assert prints exactly one line, `UPGRADE <id> PASS|FAIL|NOT
# REACHED: <why>`, quoting the product's own line on a FAIL. The asserts are
# 97's spec (A1-A6 after `--all`, B1-B3 after the same-tag `--stack`) and
# general's (G1-G5: the verify rows, the journal, a chat answer after).
set -uo pipefail
: "${OUT:?}" "${CELL:=upgrade-24.04}" "${RUNNER:=?}" "${CLI_TAG:=latest}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT" "$OUT/stranger-cwd"
# shellcheck source=scripts/install-cell/lib.sh
. "$HERE/lib.sh"
export PATH="$HOME/.local/bin:$PATH"
J="$OUT/judge"; mkdir -p "$J"

meta cell "$CELL"
meta runner "$RUNNER"
meta modes "upgrade: previous final -> $CLI_TAG (noo upgrade --all, then a same-tag --stack); model=default"
meta limits "the operator is the runner user with passwordless sudo: sudo password prompts are never seen"
meta limits "no GPU on hosted runners: CPU inference only"
meta systemd "$(systemctl --version 2>/dev/null | head -n 1)"
meta openssl "$(openssl version 2>/dev/null)"
meta operator_user "$(id -un) (uid $(id -u))"

finish() {
    python3 "$CELL_PY" summary "$OUT"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
    if ! python3 "$CELL_PY" scan "$OUT"; then
        echo "::error::$CELL: secret-shaped text in the cell's output; the artifact is withheld"
        rm -rf "$OUT/logs" "$OUT/judge"
        exit 3
    fi
    python3 - "$OUT/summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
sys.exit(0 if s["result"] in ("pass", "not run") else 1)
PY
    exit $?
}

# ── 1. the previous final, from the releases API ────────────────────────────
# The newest noo-cli-vX.Y.Z FINAL (no prerelease) strictly below the release
# under test's X.Y.Z. CLI_TAG=latest: the newest final, and the one before.
step resolve-previous 60 -- python3 "$HERE/upgrade_judge.py" resolve "$CLI_TAG" "$J/prev" "$J/target" || finish
PREV="$(cat "$J/prev")"; TARGET="$(cat "$J/target")"
meta upgrade "$PREV -> $TARGET"

# ── 2. install the previous final the README's way, onboard ─────────────────
README="$HERE/../../README.md"
LINE="$(grep -m1 -E '^[^#]*releases/latest/download/install\.sh' "$README" 2>/dev/null)"
[ -n "$LINE" ] || { step install 10 -- sh -c 'echo "upgrade-cell: no install line in README.md"; exit 1'; finish; }
LINE="$(printf '%s' "$LINE" | sed "s#releases/latest/download/#releases/download/$PREV/#")"
export NOO_CLI_VERSION="$PREV"
step install-previous 600 -- sh -c "cd '$OUT/stranger-cwd' && $LINE" || finish
step version-previous 30 -- noo --version || finish
if noo onboard --help 2>&1 | grep -q -- '--root-ok'; then
    step onboard 3600 -- noo onboard --ci --root-ok || finish
else
    step onboard 3600 -- noo onboard --ci || finish
fi
step stack-start 1800 -- noo stack start || finish
SELF="$(hostname)"

# What the box looks like on the previous final, before the roll: whether the
# self node took a rail apply (an onboard-installed agent does not, #991),
# its applier's journal, and the fetch timer.
step before-roll 120 -- bash -c '
  echo "self node: $1"
  echo "noo-fetch.timer: $(systemctl is-active noo-fetch.timer 2>/dev/null || echo absent)"
  n="$(sudo -n journalctl -t noo-apply --no-pager 2>/dev/null | grep -c "applied:")"
  echo "apply reports in the journal before the roll: ${n:-0}"
  sudo -n journalctl -t noo-apply --no-pager 2>/dev/null | grep -E "release-check:|applied:" | tail -n 3 | cut -c1-300
  noo --json cluster verify > "$2/verify-before.json" 2>/dev/null
  python3 "$3" before "$2/verify-before.json" "$1"
' before "$SELF" "$J" "$HERE/upgrade_judge.py"

# ── 3. the roll: --all to the release under test ────────────────────────────
ROLL_T0="$(date +%s)"
step upgrade-all 3600 -- noo upgrade --all --version "$TARGET" --yes
ROLL_RC=$?
echo "$ROLL_RC" > "$J/roll.rc"
noo --json cluster verify > "$J/verify-after.json" 2>/dev/null
# The --all window ONLY, captured before the same-tag --stack can apply
# anything: A2 judges whether --all installed the generation-2 applier, and a
# release-check line from the later --stack must not stand in for it (97).
# The applier's `release-check: generation=…` is noo-apply's stdout under
# noo-fetch.service, so journald files it as `noo-fetch`, NOT `-t noo-apply`
# (only its `logger -t noo-apply` refusals land there): keep both.
sudo -n journalctl --no-pager --since "@$ROLL_T0" 2>/dev/null | grep -E "noo-apply|noo-fetch|noo-node-agent" \
  | python3 "$CELL_PY" redact > "$J/roll-window.journal"

# ── 4. the same-tag --stack (1b's Stage route on a node whose applier is new) ─
# 0.6.26's onboard already installed noo-netns-restore.service (its own sudo
# tee), so a --stack would find it current and print nothing: remove it first,
# so the --stack must recreate it through the self node's applier, with no
# sudo, which is the one real-systemd proof of 1b's Stage route (97).
step remove-netns-unit 60 -- sh -c 'echo "unit before: $(ls -l /etc/systemd/system/noo-netns-restore.service 2>&1)"
  sudo -n rm -f /etc/systemd/system/noo-netns-restore.service && sudo -n systemctl daemon-reload; echo "__rm=$?"
  echo "unit after: $(ls /etc/systemd/system/noo-netns-restore.service 2>&1)"'
STACK_T0="$(date +%s)"
step upgrade-stack-same-tag 2400 -- noo upgrade --stack --version "$TARGET" --yes
echo "$?" > "$J/stack.rc"
STACK_T1="$(date +%s)"

# ── 5. a chat answer after both ────────────────────────────────────────────
step chat-after 900 -- noo chat --message "Reply with the single word ok."

# ── 6. the judges: one line per assert ─────────────────────────────────────
noo --json cluster verify > "$J/verify-final.json" 2>/dev/null
# Every journal goes through the cell's redactor before it is kept: the
# artifacts are PUBLIC, and these files are not written by step().
sudo -n journalctl -t noo-apply --no-pager --since "@$ROLL_T0" 2>/dev/null | python3 "$CELL_PY" redact > "$J/apply.journal"
sudo -n journalctl --no-pager --since "@$ROLL_T0" 2>/dev/null | grep -E "noo-apply|noo-fetch|noo-node-agent" \
  | python3 "$CELL_PY" redact > "$J/node.journal"
sudo -n journalctl _COMM=sudo --no-pager --since "@$STACK_T0" --until "@$STACK_T1" 2>/dev/null | python3 "$CELL_PY" redact > "$J/sudo-stack.journal"
export J SELF ROLL_T0 OUT
step judge 120 -- python3 "$HERE/upgrade_judge.py" judge
finish
