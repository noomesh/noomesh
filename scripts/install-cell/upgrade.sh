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
#   [PREV_TAG=noo-cli-vX.Y.Z] scripts/install-cell/upgrade.sh
#
# PREV_TAG (the dispatch input `prev_tag`) chooses the final the box starts
# on; empty, it is the newest final below the release under test. A chosen
# start must be exactly noo-cli-vX.Y.Z, strictly below the release under
# test and a published, non-prerelease release, or the resolve step refuses
# naming the rule and nothing installs (upgrade_judge.py resolve).
#
# GITHUB-HOSTED, EPHEMERAL RUNNERS ONLY: it installs with sudo. The operator
# is the runner user (non-root, passwordless sudo).
#
# Every judged assert prints exactly one line, `UPGRADE <id> PASS|FAIL|NOT
# REACHED: <why>`, quoting the product's own line on a FAIL. The asserts are
# 97's spec (A1-A7 after `--all`, B1-B4 after the same-tag `--stack`) and
# general's (G1-G5: the verify rows, the journal, a chat answer after).
set -uo pipefail
: "${OUT:?}" "${CELL:=upgrade-24.04}" "${RUNNER:=?}" "${CLI_TAG:=latest}" "${PREV_TAG:=}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# CLI_TAG and PREV_TAG are free-text dispatch inputs: hold both to the rule
# before ANY use, on their own (the workflow refuses them first, resolve
# again). Exit 2: not run.
# shellcheck source=scripts/install-cell/validate_tag.sh
. "$HERE/validate_tag.sh"
require_cli_tag "$CLI_TAG" || exit 2
require_prev_tag "$PREV_TAG" || exit 2
# ── end of the dispatch-input check ──
if [ -n "$PREV_TAG" ]; then START_KIND="chosen"; else START_KIND="previous final"; fi
mkdir -p "$OUT" "$OUT/stranger-cwd"
# shellcheck source=scripts/install-cell/lib.sh
. "$HERE/lib.sh"
export PATH="$HOME/.local/bin:$PATH"
J="$OUT/judge"; mkdir -p "$J"

meta cell "$CELL"
meta runner "$RUNNER"
meta modes "upgrade: ${PREV_TAG:-previous final} ($START_KIND) -> $CLI_TAG (noo upgrade --all, then a same-tag --stack); model=default"
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
# PREV_TAG set: that final instead, once resolve has held it to the rules.
# The repo is the one the README's install line downloads from (never typed
# here: the release repo has one declared home).
README="$HERE/../../README.md"
LINE="$(grep -m1 -E '^[^#]*releases/latest/download/install\.sh' "$README" 2>/dev/null)"
REPO="$(printf '%s' "$LINE" | sed -nE 's#.*github\.com/([^/]+/[^/]+)/releases/.*#\1#p')"
[ -n "$REPO" ] || { step resolve-previous 10 -- sh -c 'echo "upgrade-cell: no install line naming a github repo in README.md"; exit 1'; finish; }
step resolve-previous 60 -- python3 "$HERE/upgrade_judge.py" resolve "$REPO" "$CLI_TAG" "$J/prev" "$J/target" "$PREV_TAG" || finish
PREV="$(cat "$J/prev")"; TARGET="$(cat "$J/target")"
meta upgrade "$PREV ($START_KIND) -> $TARGET"

# ── 2. install the previous final the README's way, onboard ─────────────────
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

# The Docker daemon's own record of the new version's roll: image + container
# events from here to the end of the plain start after the upgrade (UPGRADE
# NO-DOCKERHUB judges them: no Docker Hub pull, no Docker Hub container).
# ONLY those six fields (time type action id image name), never `{{json .}}`:
# a full event carries every container label and `KEY=value` string, which the
# upload scan refuses (and then withholds ALL evidence, run 44798146312).
# Started AFTER the previous final's onboard and start (which may pull
# alpine), stopped by PID, never by pattern. When the operator is not in the
# docker group yet, the watcher is sudo's, and so is its stop.
DOCKER="docker"; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
mkdir -p "$OUT/logs"
$DOCKER events --format '{"time":{{json .Time}},"type":{{json .Type}},"action":{{json .Action}},"id":{{json .Actor.ID}},"image":{{json (index .Actor.Attributes "image")}},"name":{{json (index .Actor.Attributes "name")}}}' --filter type=image --filter type=container \
    > "$OUT/logs/docker-events-upgrade.jsonl" 2> "$OUT/logs/docker-events-upgrade.err" < /dev/null &
EVENTS_PID=$!
echo "$EVENTS_PID" > "$J/docker-events.pid"
sleep 1

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

# The node agent's own record of the roll (the fresh cells' agent-state-after-*
# dump, run.sh agent_dump): its unit status, its journal from ROLL_T0 and the
# self node as the controller sees it. A step, so it passes the redactor, lands
# in logs/ (uploaded, then scanned) and a failure of it never fails the cell
# (cell.py skips agent-state-after-*). Before the --stack's sleep + STACK_T0,
# so its sudos are outside B3's window.
step agent-state-after-roll 120 -- sh -c '
  echo "== systemctl status noo-node-agent"; sudo -n systemctl status noo-node-agent --no-pager -l 2>&1 | head -40
  echo "== journalctl -u noo-node-agent (since the roll, last 300)"
  sudo -n journalctl -u noo-node-agent --no-pager --since "@$1" -n 300 2>&1
  echo "== noo --json cluster show $2"
  timeout 60 noo --json cluster show "$2" 2>&1 | head -c 20000; echo' _ "$ROLL_T0" "$SELF" || true

# ── 4. the same-tag --stack (1b's Stage route on a node whose applier is new) ─
# 0.6.26's onboard already installed noo-netns-restore.service (its own sudo
# tee), so a --stack would find it current and print nothing: remove it first,
# so the --stack must recreate it through the self node's applier, with no
# sudo, which is the one real-systemd proof of 1b's Stage route (97).
step remove-netns-unit 60 -- sh -c 'echo "unit before: $(ls -l /etc/systemd/system/noo-netns-restore.service 2>&1)"
  sudo -n rm -f /etc/systemd/system/noo-netns-restore.service && sudo -n systemctl daemon-reload; echo "__rm=$?"
  echo "unit after: $(ls /etc/systemd/system/noo-netns-restore.service 2>&1)"'
# B3 reads the sudo journal from STACK_T0 at whole-second resolution: the
# cell's own sudos just above (the roll-window journalctl, the rm, the
# daemon-reload) landed in STACK_T0's second and counted as the --stack's
# (0.6.26 -> rc.1, run 44706791256: "3 sudo command(s) during the --stack").
# One second apart, they are strictly earlier; B3 also ignores exactly those
# commands, arguments included (upgrade_judge.py own_sudo_commands).
sleep 1
STACK_T0="$(date +%s)"
step upgrade-stack-same-tag 2400 -- noo upgrade --stack --version "$TARGET" --yes
echo "$?" > "$J/stack.rc"
STACK_T1="$(date +%s)"

# ── 4b. a plain start after the upgrade recreates nothing (B4) ─────────────
# Every container the upgrade made must carry the start-inputs labels, or the
# operator's next plain `noo stack start` recreates it (the release lead).
# Snapshots before and after with recreated.py, the parser run.sh's
# start-idempotent uses; the step's own exit is the start's. Here, before
# chat-after: the start is judged on the stack exactly as the upgrade left it
# (nothing between could move a container), and G5's chat then proves the
# stack still answers after it. After STACK_T1, so recreated.py's `sudo -n
# docker` fallback is outside B3's window.
step start-after-upgrade 1800 -- sh -c 'python3 "$1" snap "$2/start-after.before" || exit 1
  noo stack start; rc=$?
  python3 "$1" snap "$2/start-after.after"
  exit $rc' _ "$HERE/recreated.py" "$J"

# The window ends here: `noo upgrade --all`, the same-tag `--stack` (with the
# cell's remove-netns-unit step between them) and the plain start. Not chat-after.
sleep 1
if [ "$DOCKER" = "docker" ]; then kill "$EVENTS_PID" 2>/dev/null; else sudo -n kill "$EVENTS_PID" 2>/dev/null; fi
wait "$EVENTS_PID" 2>/dev/null

# ── 5. a chat answer after both ────────────────────────────────────────────
step chat-after 900 -- noo chat --message "Reply with the single word ok."

# ── 6. the judges: one line per assert ─────────────────────────────────────
noo --json cluster verify > "$J/verify-final.json" 2>/dev/null
# G2 must not judge one snapshot (a node agent restarted moments before has no
# ollama_verify for ~30-60 s): while the row is absent or "not yet checked",
# verify again every 30 s up to 6 min. Each try is kept as verify-g2-<n>.json
# in judge/ and logs/ (uploaded); the wait is in judge/g2.wait.
python3 "$HERE/upgrade_judge.py" g2wait "$OUT" "$J" "$SELF" 30 360
# Every journal goes through the cell's redactor before it is kept: the
# artifacts are PUBLIC, and these files are not written by step().
sudo -n journalctl -t noo-apply --no-pager --since "@$ROLL_T0" 2>/dev/null | python3 "$CELL_PY" redact > "$J/apply.journal"
sudo -n journalctl --no-pager --since "@$ROLL_T0" 2>/dev/null | grep -E "noo-apply|noo-fetch|noo-node-agent" \
  | python3 "$CELL_PY" redact > "$J/node.journal"
sudo -n journalctl _COMM=sudo --no-pager --since "@$STACK_T0" --until "@$STACK_T1" 2>/dev/null | python3 "$CELL_PY" redact > "$J/sudo-stack.journal"
export J SELF ROLL_T0 STACK_T0 STACK_T1 OUT
step judge 120 -- python3 "$HERE/upgrade_judge.py" judge
finish
