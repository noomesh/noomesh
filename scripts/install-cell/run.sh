#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# One cell of .github/workflows/install-matrix.yml: what a stranger does
# from the README on a machine we have never seen, timed step by step.
#
#   OUT=<dir> CELL=<name> RUNNER=<label> DOCKER=preinstalled|none \
#   ONBOARD=ci|interactive MODEL=default|tiny SCOPE=full|node-partial \
#   CLI_TAG=latest|noo-cli-vX.Y.Z  scripts/install-cell/run.sh
#
# GITHUB-HOSTED, EPHEMERAL RUNNERS ONLY. This pipes our released install.sh
# into sh, installs with sudo and then offboards the box. Never point it at a
# machine someone owns or shares.
#
# The stranger is the runner user (non-root, PASSWORDLESS sudo): a real
# stranger may meet sudo password prompts this run never shows.
#
# Steps stop at the first failure, except that a cell that got as far as
# onboarding always tears down and checks for leftovers, and every cell
# ends with the secret scan (exit 3 on a hit) and its summary.
set -uo pipefail
: "${OUT:?}" "${CELL:?}" "${RUNNER:=?}" "${DOCKER:=preinstalled}" "${ONBOARD:=ci}" \
  "${MODEL:=default}" "${SCOPE:=full}" "${CLI_TAG:=latest}"
TINY_MODEL="${TINY_MODEL:-qwen2.5:0.5b}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
# shellcheck source=scripts/install-cell/lib.sh
. "$HERE/lib.sh"
export PATH="$HOME/.local/bin:$PATH"
CELL_START=$(date +%s)

meta cell "$CELL"
meta runner "$RUNNER"
meta modes "docker=$DOCKER onboard=$ONBOARD model=$MODEL scope=$SCOPE cli_tag=$CLI_TAG"
meta limits "the stranger is the runner user with passwordless sudo: sudo password prompts are never seen"
meta limits "no GPU on hosted runners: CPU inference only"

# Peak disk: sample `df` every 5 s for the whole cell.
( while :; do df -Pk / | awk 'NR==2{print $3}' >> "$OUT/disk.samples"; sleep 5; done ) &
SAMPLER=$!

finish() {
    kill "$SAMPLER" 2>/dev/null
    if [ -s "$OUT/disk.samples" ]; then
        meta peak_disk_used_gb "$(sort -n "$OUT/disk.samples" | tail -1 | awk '{printf "%.1f", $1/1048576}')"
    fi
    python3 "$CELL_PY" summary "$OUT"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
    # Last gate before anything is uploaded: this repo's artifacts are public.
    if ! python3 "$CELL_PY" scan "$OUT"; then
        echo "::error::$CELL: secret-shaped text in the cell's output; the artifact is withheld"
        rm -rf "$OUT/logs"
        exit 3
    fi
    python3 - "$OUT/summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
sys.exit(0 if s["result"] in ("pass", "not run") else 1)
PY
    exit $?   # finish ENDS the cell (run 1, 2026-11-12: without this every later step still ran)
}

hook() {  # a mode's steps written by another owner (see the workflow)
    local f="$HERE/$1"
    if [ ! -x "$f" ]; then
        meta limits "$1 not written yet: this cell's mode is not run"
        meta not_run "$1 not written yet"
        echo "::notice::$CELL: $1 is not written yet; the cell stops here"
        finish
    fi
    "$f"
}

# ── 1. the box ──────────────────────────────────────────────────────────
step box 120 -- sh -c 'uname -a; cat /etc/os-release 2>/dev/null | head -3; sw_vers 2>/dev/null;
  nproc 2>/dev/null || sysctl -n hw.ncpu; free -m 2>/dev/null || sysctl -n hw.memsize; df -h /;
  docker version --format "docker {{.Server.Version}}" 2>&1 | head -1; docker compose version 2>&1 | head -1'
if [ "$DOCKER" = none ]; then
    hook prep-no-docker.sh || finish
fi

# ── 2. the install line, read from the README and run VERBATIM ──────────
# The cell runs exactly what a stranger copies, so README and test cannot
# drift: the first line of README.md that downloads install.sh. A tag only
# swaps releases/latest/download for releases/download/<tag> in it.
README="$HERE/../../README.md"
LINE="$(grep -m1 -E '^[^#]*releases/latest/download/install\.sh' "$README" 2>/dev/null)"
if [ -z "$LINE" ]; then
    meta limits "README.md has no install line this harness can find"
    step install 10 -- sh -c 'echo "install-cell: no install line in README.md"; exit 1'
    finish
fi
if [ "$CLI_TAG" != latest ]; then
    LINE="$(printf '%s' "$LINE" | sed "s#releases/latest/download/#releases/download/$CLI_TAG/#")"
    export NOO_CLI_VERSION="$CLI_TAG"
fi
meta install_line "$LINE"
mkdir -p "$OUT/stranger-cwd"
step install 600 -- sh -c "cd '$OUT/stranger-cwd' && $LINE" || finish
step version 30 -- noo --version || finish
meta installed_version "$(noo --version 2>/dev/null | head -1)"

if [ "$SCOPE" = node-partial ]; then
    # macOS is a NODE: it needs a controller this hosted runner cannot reach,
    # and hosted Apple-silicon runners have no Docker. Install + CLI only.
    meta limits "macOS node path stops before join: no reachable controller from a hosted runner, no Docker on hosted Apple silicon"
    step cli-help 60 -- noo --help
    finish
fi

# ── 3. onboard ──────────────────────────────────────────────────────────
TORN_DOWN=0
teardown() {
    [ "$TORN_DOWN" = 1 ] && return 0
    TORN_DOWN=1
    # Never offboard a box this user cannot see the containers of: without
    # docker access offboard read "already clean" with 16 containers running
    # and removed the storage root from under them (fa, run 43157286042; the
    # product fix is fa's). The runner is thrown away anyway.
    # A probe that failed altered the box (on releases without #1059 the
    # offboard probe wipes it, and the box then reads as a node, so the real
    # uninstall refuses, run 4): its state is no longer the install's, and
    # the runner is thrown away anyway.
    if [ "${PROBE_ALTERED:-0}" = 1 ]; then
        meta limits "cleanup skipped: a failed probe altered the box"
        echo "::notice::$CELL: cleanup skipped, a failed probe altered the box"
        return 0
    fi
    if ! docker info >/dev/null 2>&1; then
        meta limits "cleanup skipped: docker unreachable as $(id -un)"
        echo "::notice::$CELL: cleanup skipped, docker is unreachable as $(id -un)"
        return 0
    fi
    # What the install put on the disk, before it goes: images by name,
    # volumes, build cache, the data root and the install home.
    step disk-breakdown 300 -- sh -c 'df -h /; docker system df -v 2>&1 | head -80
      sudo du -sh /var/lib/noo /var/lib/noo/* "$HOME/.noo" 2>/dev/null | sort -h | tail -25'
    # ONE offboard: `offboard -y` then `offboard --uninstall -y` failed, as
    # the first left the box looking like a node and the second refused
    # ("runs on the controller", run 3). The leftover verdict is ours:
    # `offboard --check` misses noomesh_* volumes and needs the removed CLI.
    step uninstall 900 -- noo offboard --uninstall -y
    # Our own verdict, not offboard --check's: its audit looks for `noo_*`
    # volumes while the compose project names them `noomesh_*` (fa, 11-12),
    # so it reads clean over leftover stack volumes.
    step leftover-docker 60 -- sh -c 'left=0
      for what in "ps -a" "volume ls" "image ls"; do
        n=$(docker $what -q 2>/dev/null | wc -l); echo "docker $what: $n"; done
      L=label=com.docker.compose.project=noomesh
      { docker ps -a --filter "$L" --format "LEFTOVER container {{.Names}}"
        docker volume ls --filter "$L" --format "LEFTOVER volume {{.Name}}"
        docker network ls --filter "$L" --format "LEFTOVER network {{.Name}}"
        docker volume ls --format "{{.Name}}" 2>/dev/null | grep -E "^(noomesh|noo)_" | sed "s/^/LEFTOVER volume /"
        docker network ls --format "{{.Name}}" 2>/dev/null | grep -vxE "bridge|host|none" | sed "s/^/LEFTOVER network /"
      } | sort -u | grep . && left=1
      docker image ls --format "image {{.Repository}}:{{.Tag}} {{.Size}}" 2>/dev/null
      for f in "$HOME/.local/bin/noo" /usr/local/bin/noo; do [ -e "$f" ] && { echo "LEFTOVER $f"; left=1; }; done
      exit $left'
}
fail_onboarded() { teardown; finish; }

if [ "$ONBOARD" = interactive ]; then
    hook onboard-interactive.sh || fail_onboarded
elif [ "$MODEL" = tiny ]; then
    # --ci takes the declared OLLAMA_MODEL, which onboard reads from the
    # install's .env only (not the process env): onboard everything but the
    # model, declare the tiny one there, then run the model section alone.
    step onboard 2700 -- noo onboard --ci --skip-model || fail_onboarded
    envf="$(find "$HOME" -maxdepth 4 -name .noo-standalone -print -quit 2>/dev/null)"
    envf="${envf%/.noo-standalone}/.env"
    step declare-tiny-model 30 -- sh -c "test -f '$envf' && { grep -v '^OLLAMA_MODEL=' '$envf' > '$envf.tmp'; echo 'OLLAMA_MODEL=$TINY_MODEL' >> '$envf.tmp'; mv '$envf.tmp' '$envf'; echo \"OLLAMA_MODEL=$TINY_MODEL in $envf\"; }" \
        || fail_onboarded
    step onboard-model 1800 -- noo onboard --ci --only model || fail_onboarded
else
    step onboard 3600 -- noo onboard --ci || fail_onboarded
fi

# ── 4. up, verified, answering ──────────────────────────────────────────
step stack-start 1800 -- noo stack start || fail_onboarded
step health 600 -- sh -c 'for i in $(seq 1 40); do noo health >/dev/null 2>&1 && break; sleep 15; done; noo health' \
    || fail_onboarded
# Not in the README's path (it is `stack start && health`, then chat): a red
# verify is recorded with every row, and the stranger still asks the question.
if [ "$MODEL" = tiny ]; then
    # The declared OLLAMA_MODEL is pulled, but the default chat model stays the
    # product default (run 3: "model 'gemma4:e2b' is not served by any node");
    # the error's own remedy makes the tiny one the default.
    step switch-to-tiny-model 300 -- noo models switch "$TINY_MODEL" --backend ollama --yes || fail_onboarded
fi
step verify 900 -- noo cluster verify --wait
# The single-turn line docs/getting-started/first-chat.md gives, verbatim.
step first-answer 1800 -- sh -c 'out="$(noo chat --message "in two lines, what can you do on this machine?")"; rc=$?
  printf "%s\n" "$out"; [ $rc = 0 ] && [ -n "$(printf "%s" "$out" | tr -d "[:space:]")" ]' || fail_onboarded
meta first_answer_s "$(( $(date +%s) - CELL_START ))"

# PROBE (fa, i677 finding 20; fix #1059): `noo offboard` run by a shell that
# cannot reach docker (no supplementary groups, as for a stranger whose
# shell lacks the docker group) must refuse and remove NOTHING. A probe is
# reported on its own and never becomes the cell's failed step; on releases
# without #1059 it is expected to fail (it wiped the box).
step probe-offboard-without-docker 600 -- sh -c '
  out="$(sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups --reset-env \
         env HOME="$HOME" PATH="$PATH" noo offboard -y 2>&1)"; rc=$?
  printf "%s\n" "$out"; ok=1
  [ "$rc" != 0 ] || { echo "PROBE FAIL: offboard without docker exited 0"; ok=0; }
  printf "%s" "$out" | grep -q "cannot reach docker" || { echo "PROBE FAIL: it did not say it cannot reach docker"; ok=0; }
  printf "%s" "$out" | grep -q "nothing was removed" || { echo "PROBE FAIL: it did not say nothing was removed"; ok=0; }
  docker ps -q --filter name=noo-gateway | grep -q . || { echo "PROBE FAIL: the gateway container is gone"; ok=0; }
  [ -d "$HOME/.noo" ] || { echo "PROBE FAIL: ~/.noo is gone"; ok=0; }
  [ -d /var/lib/noo ] || { echo "PROBE FAIL: /var/lib/noo is gone"; ok=0; }
  noo health >/dev/null 2>&1 || { echo "PROBE FAIL: noo health is not ok afterwards"; ok=0; }
  [ "$ok" = 1 ]' || PROBE_ALTERED=1

# ── 5. clean uninstall ──────────────────────────────────────────────────
teardown
finish
