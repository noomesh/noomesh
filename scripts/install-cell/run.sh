#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# One cell of .github/workflows/install-matrix.yml: what a stranger does
# from the README on a machine we have never seen, timed step by step.
#
#   OUT=<dir> CELL=<name> RUNNER=<label> DOCKER=preinstalled|none|distro \
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

# PROBE (connections forensics, 2026-11-14): Postgres connections held by
# the stack (pg_stat_activity, grouped; pg_conns.py) against max_connections,
# which the stack leaves at Postgres's default (100). The default cell only.
# Points: idle after verify (+ os.cpu_count() inside worker/trellion), idle
# after the 40 min series, the MAXIMUM during first-answer and during the
# RAG ingest probe (a 1 s background sampler around the step), and right
# after each. Writes $OUT/pg-conns.json. Probes: never the failed step.
PG_CONNS_CELL=ubuntu-24.04-amd64-default
PG_WATCH_PID=""; PG_WATCH_POINT=""
pg_sample() {  # POINT [--cpus]
    [ "$CELL" = "$PG_CONNS_CELL" ] || return 0
    step "probe-pg-conns-$1" 180 -- python3 "$HERE/pg_conns.py" sample --out "$OUT/pg-conns.json" \
        --cell "$CELL" --point "$@"
}
pg_watch_start() {  # POINT CAP_S: sample every 1 s until pg_watch_stop
    [ "$CELL" = "$PG_CONNS_CELL" ] || return 0
    PG_WATCH_POINT="$1"; rm -f "$OUT/pg-watch.stop"
    python3 "$HERE/pg_conns.py" watch --samples "$OUT/pg-watch-$1.jsonl" --stop "$OUT/pg-watch.stop" \
        --interval 1 --max-seconds "$2" --parent $$ >> "$OUT/logs/pg-watch-$1.log" 2>&1 &
    PG_WATCH_PID=$!
}
pg_watch_stop() {  # the step's maximum becomes one point (also from finish)
    [ -n "$PG_WATCH_PID" ] || return 0
    touch "$OUT/pg-watch.stop"; wait "$PG_WATCH_PID" 2>/dev/null; PG_WATCH_PID=""
    step "probe-pg-conns-$PG_WATCH_POINT" 120 -- python3 "$HERE/pg_conns.py" fold \
        --samples "$OUT/pg-watch-$PG_WATCH_POINT.jsonl" --point "$PG_WATCH_POINT" --out "$OUT/pg-conns.json" --cell "$CELL"
}

finish() {
    pg_watch_stop   # a step that failed mid-watch still folds its samples
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

# DIAGNOSTIC (fa, rc.3 matrix run 2: the WSL2 cell placed a model and its
# node read "no lanes" two minutes later, with no agent log to say why): on
# EVERY failed step or probe, the node agent's status and its last 200 log
# lines, as a step of its own, so the same redactor and upload scan apply.
# Also after the model step SUCCEEDS (agent-state-after-model): the
# placement is made there, so a passing cell (22.04) and a failing one
# (WSL2) can be read side by side: does a reconcile follow the place within
# seconds, is the backend native/adopted or managed, did the gateway log
# reconcile_nudged for the node. Each dump also carries `noo --json cluster
# show <this node>` and the gateway's reconcile_nudge*/placement lines.
# systemd hosts: systemctl status + journalctl. Without systemd: the agent
# process (if any), launchd's view on macOS and the log file the plist names.
# Never the env file (it holds the agent's token). At most 5 dumps per cell.
AGENT_DUMPS=0
agent_dump() {
    [ "$AGENT_DUMPS" -lt 5 ] || return 0
    AGENT_DUMPS=$((AGENT_DUMPS + 1))
    step "agent-state-after-$1" 120 -- sh -c '
      if command -v systemctl >/dev/null 2>&1 && [ -d "${CELL_SYSTEMD_DIR:-/run/systemd/system}" ]; then
        echo "== systemctl status noo-node-agent"; sudo -n systemctl status noo-node-agent --no-pager -l 2>&1 | head -40
        echo "== journalctl -u noo-node-agent (last 200)"; sudo -n journalctl -u noo-node-agent --no-pager -n 200 2>&1
      else
        echo "== no systemd on this host: the agent process"
        ps -eo pid,etime,args 2>/dev/null | grep -E "[n]oo-node-agent|[n]oomesh-agent" || echo "(no noo-node-agent process)"
        if command -v launchctl >/dev/null 2>&1; then
          echo "== launchctl list (noo*)"; launchctl list 2>/dev/null | grep -i noo || echo "(no noo launchd job)"
        fi
        for f in /tmp/noomesh-agent.log /var/log/noo-node-agent.log; do
          [ -f "$f" ] && { echo "== $f (last 200)"; tail -n 200 "$f"; }
        done
      fi
      if command -v noo >/dev/null 2>&1; then
        echo "== noo --json cluster show $(hostname) (this node: lanes, placements, backends)"
        timeout 60 noo --json cluster show "$(hostname)" 2>&1 | head -c 20000; echo
      fi
      if docker inspect noo-gateway >/dev/null 2>&1; then
        echo "== noo-gateway: nudges and placements (last 15 min)"
        docker logs --since 15m noo-gateway 2>&1 | grep -E "reconcile_nudge|placement" | tail -n 40
      fi
      true'
    return 0
}
ON_STEP_FAIL=agent_dump
# The mode hooks (prep-no-docker.sh, onboard-interactive.sh) are child bash
# processes that source lib.sh: they inherit the hook this way. Their dump
# count starts at 0 again, so a hook adds at most 5 of its own.
export ON_STEP_FAIL AGENT_DUMPS
export -f agent_dump

# ── 1. the box ──────────────────────────────────────────────────────────
step box 120 -- sh -c 'uname -a; cat /etc/os-release 2>/dev/null | head -3; sw_vers 2>/dev/null;
  nproc 2>/dev/null || sysctl -n hw.ncpu; free -m 2>/dev/null || sysctl -n hw.memsize; df -h /;
  docker version --format "docker {{.Server.Version}}" 2>&1 | head -1; docker compose version 2>&1 | head -1'
if [ "$DOCKER" = none ]; then
    hook prep-no-docker.sh || finish
fi
# DOCKER=distro: the engine a stranger gets from `apt install docker.io`, not
# the runner image's docker-ce/moby. #1108's restore was only ever proven on
# the image's engine, and Docker versions word a failed namespace join
# differently (27 vs 28: noomesh#1128). The first run (2026-11-13) found
# 22.04's docker.io at 29.1.3, so this cell covers the distro engine; Docker
# 27 itself is the rehearsal's dind (27.5.1). The image's engine packages are removed,
# Ubuntu's own docker.io + docker-compose-v2 installed, and the step FAILs by
# name unless the engine now running is the docker.io package's.
if [ "$DOCKER" = distro ]; then
    step distro-docker 900 -- sudo bash -c '
      set -u
      systemctl stop docker.socket docker.service containerd.service 2>/dev/null
      engines="$(dpkg-query -W -f "\${Package}\n" "docker-ce*" "docker-buildx-plugin" "docker-compose-plugin" "containerd.io" "moby-*" 2>/dev/null | sort -u | tr "\n" " ")"
      echo "image engine packages: ${engines:-none}"
      [ -z "${engines// /}" ] || DEBIAN_FRONTEND=noninteractive apt-get remove -y -q $engines >/dev/null || { echo "could not remove the image engine"; exit 1; }
      apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 >/dev/null || { echo "apt could not install docker.io docker-compose-v2"; exit 1; }
      systemctl enable --now docker.service >/dev/null 2>&1
      usermod -aG docker "${SUDO_USER:-runner}" 2>/dev/null
      t=0; until docker info >/dev/null 2>&1 || [ $t -ge 60 ]; do sleep 2; t=$((t+2)); done
      pkg="$(dpkg-query -W -f "\${Version}" docker.io 2>/dev/null)"
      # What the archive offers (the first run, 2026-11-13, found 29.1.3 on
      # 22.04, not the 27.x assumed): a future pin can only pick from these.
      apt-cache madison docker.io 2>/dev/null | head -6 | sed "s/^/available: /"
      echo "docker.io package: ${pkg:-NOT INSTALLED}"
      docker version 2>&1 | sed -n "/^Server/,\$p" | head -8
      docker compose version 2>&1 | head -1
      left="$(dpkg-query -W -f "\${Package} \${Status}\n" "docker-ce" "moby-engine" 2>/dev/null | grep -c " installed$")"
      srv="$(docker version --format "{{.Server.Version}}" 2>/dev/null)"
      echo "engine: server ${srv:-none}, from docker.io ${pkg:-none}, image engines still installed: $left"
      [ -n "$pkg" ] && [ -n "$srv" ] && [ "$left" = 0 ] || { echo "DISTRO-DOCKER FAIL: the engine running is not Ubuntu docker.io"; exit 1; }
    ' || finish
    meta docker_engine "$(docker version --format '{{.Server.Version}}' 2>/dev/null) (Ubuntu docker.io)"
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

# An arm64 cell EXPECTS the controller refusal (the matrix says expect:
# refusal): a controller needs Linux on x86_64 today (noo-cli onboard/upfront.rs
# platform_refusal; noomesh-internal i781 scopes lifting it). The cell passes
# when the refusal is clean, so the matrix has no permanent red: onboard exits
# non-zero, names the reason and the way on (join as a node), and creates no
# stack container. Anything else fails it by name.
if [ "${EXPECT:-}" = refusal ]; then
    step onboard-refuses 600 -- sh -c '
      out="$(noo onboard --ci 2>&1)"; rc=$?
      printf "%s\n" "$out" | tail -n 20
      why=""
      [ "$rc" != 0 ] || why="onboard exited 0 on a machine it must refuse"
      printf "%s" "$out" | grep -q "a controller needs Linux on x86_64 (amd64)" || why="${why:-the refusal does not name the reason (a controller needs Linux on x86_64)}"
      printf "%s" "$out" | grep -q "can join an amd64 controller as a node instead" || why="${why:-the refusal does not name the way on (join as a node)}"
      n="$(docker ps -aq --filter name=noo- 2>/dev/null | wc -l)"
      [ "$n" = 0 ] || why="${why:-the refused onboard left $n noo- container(s)}"
      if [ -n "$why" ]; then echo "REFUSAL FAIL: $why"; exit 1; fi
      echo "REFUSAL OK: onboard refused this $(uname -m) machine, named the reason and the node alternative, and started nothing"'
    teardown
    finish
fi

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
# The model was placed above: the agent's view on success too (see agent_dump).
agent_dump model

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
# verify runs as the stranger's NEXT terminal would: a fresh login session
# (sudo -i reads /etc/group again). On a docker=none cell the install added
# the runner user to the docker group, which the cell's own shell, started
# before that, does not hold (rc.3/rc.4: every docker row "permission
# denied"). The probe after the JSON one keeps the old shell, so the
# "not judged" rows (#1119) stay covered.
NOO_BIN="$(command -v noo)"
fresh() { if [ "$DOCKER" = none ]; then sudo -iu "$(id -un)" -- "$NOO_BIN" "$@"; else "$NOO_BIN" "$@"; fi; }
export -f fresh; export NOO_BIN DOCKER
step verify 900 -- bash -c 'fresh cluster verify --wait'
# PROBE (cf, #1069): the verify table above shows only failing rows' detail;
# the JSON keeps every row, so a PASSING row's text (e.g. the sandbox
# executor's "profile: 3.x form") is readable from the cell's artifacts. Same
# redactor and upload scan as every log. Never the failed step.
step probe-verify-json 300 -- bash -c 'fresh --json cluster verify'
# PROBE (general, rc.4): the same JSON from the cell's OLD shell, which lacks
# the docker group: the rows that need docker must say "not judged" with the
# docker-access remedy (#1119), never "no running container". docker=none
# cells only (elsewhere the old shell has the group from the start).
if [ "$DOCKER" = none ]; then
    step probe-verify-old-shell 300 -- sh -c '
  out="$(noo --json cluster verify 2>&1)"; printf "%s\n" "$out"
  printf "%s" "$out" | python3 -c "
import json, sys
t = sys.stdin.read(); d = json.loads(t[t.find(\"{\"):t.rfind(\"}\") + 1])
rows = [c for c in d[\"controller\"][\"checks\"] if c[\"name\"] == \"shared secrets\"]
r = rows[0] if rows else {}
ok = (r.get(\"detail\") or \"\").startswith(\"not judged\") and \"permission denied\" in (r.get(\"detail\") or \"\") and \"docker\" in (r.get(\"remedy\") or \"\")
print(\"OLD-SHELL PROBE: shared secrets\", r.get(\"verdict\"), \"not-judged-with-docker-remedy=\" + (\"yes\" if ok else \"no\"))
sys.exit(0 if ok else 1)"'
fi
# DIAGNOSTIC (fa, i677 finding 17: the box's own node reads "online: status
# unknown" and holds no live tunnel): the self-agent's own log, the URLs and
# id it was given (ONLY those keys: the env file also holds the agent's
# token), and how the controller sees it. A probe: never the failed step.
step probe-self-agent-diagnostics 120 -- sh -c '
  echo "== journalctl -u noo-node-agent (last 300)"; sudo journalctl -u noo-node-agent --no-pager -n 300 2>&1
  echo "== /etc/noo-node-agent.env (URLs and id only)"
  sudo grep -E "^(NATS_URL|NOO_GATEWAY_URL|CONTROLLER_URL|NODE_ID)=" /etc/noo-node-agent.env 2>&1
  echo "== noo --json cluster show $(hostname)"; noo --json cluster show "$(hostname)" 2>&1
  true'
# PROBE (operator 2026-11-14): the whole stack's memory at idle after
# onboard, MEASURED, tracked per release by the size job. Here: after health
# and the verify probes, BEFORE first-answer, so no chat has loaded a chat
# model yet. Per container docker stats + cgroup v2 anon/file/memory.current,
# the noo-* host units' systemd MemoryCurrent/MemoryPeak + VmRSS, totals,
# and the controller / node split (memory_baseline.py). Writes
# $OUT/memory.json (uploaded with the cell, through the upload scan). docker
# and unreadable files go through sudo, so the docker=none cells work too.
# Two cells only, to keep matrix minutes down. A probe: never the failed step.
pg_sample idle-after-verify --cpus
MEMORY_SETTLE_S="${MEMORY_SETTLE_S:-60}"
case "$CELL" in
    ubuntu-24.04-amd64-default|ubuntu-22.04-amd64)
        step probe-memory-baseline 600 -- python3 "$HERE/memory_baseline.py" measure --out "$OUT/memory.json" \
            --cell "$CELL" --model "$MODEL" --settle "$MEMORY_SETTLE_S" ;;
esac
# PROBE (operator 2026-11-14): is the chat model resident at idle FOREVER,
# or only warm after install? Two more samples of the same memory.json shape
# (memory-idle-t10.json, memory-idle-t40.json) at t0 + 10 min and t0 + 40
# min, t0 being the sample above: past ollama's 5 min default keep_alive and
# our 30 min embed keep_alive. NOTHING uses the stack in between (no step
# runs while a sample waits). Each records `ollama ps` per ollama*
# container with every model's SIZE and UNTIL, raw lines kept. The default
# cell only: ~41 min of its 120 min budget (it ran 13-18 min, 2026-11-13/14).
# A probe: never the failed step.
IDLE_SERIES_CELL=ubuntu-24.04-amd64-default
if [ "$CELL" = "$IDLE_SERIES_CELL" ]; then
    IDLE_T0="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["meta"]["epoch"])' "$OUT/memory.json" 2>/dev/null || date +%s)"
    for IDLE_MIN in 10 40; do
        step "probe-idle-t$IDLE_MIN" $(( IDLE_MIN * 60 + 300 )) -- python3 "$HERE/memory_baseline.py" measure \
            --out "$OUT/memory-idle-t$IDLE_MIN.json" --cell "$CELL" --model "$MODEL" \
            --sample "t$IDLE_MIN" --t0 "$IDLE_T0" --until $(( IDLE_T0 + IDLE_MIN * 60 ))
    done
    # JUDGED, not a probe (general 2026-11-14): on a build whose node agent
    # carries #1191's /backend-alive route, the chat model must be unloaded
    # at +40 min with nobody chatting, or this cell FAILs here. An older
    # build prints "unjudged" and passes. idle_judge.py says which.
    step idle-chat-unloaded 60 -- python3 "$HERE/idle_judge.py" \
        --t40 "$OUT/memory-idle-t40.json" --agent-bin "$(command -v noo-node-agent || echo /usr/local/bin/noo-node-agent)"
fi
pg_sample idle-after-series
# The single-turn line docs/getting-started/first-chat.md gives, read from the
# doc itself (its first `noo chat --message "…"` line), so the page and the
# test cannot drift. The answer must be an answer: a model that asks for more
# input or refuses FAILs by name (rc.4-rc.6: the old prompt "what can you do
# on this machine?" got "Please provide an image or description of the
# machine you are referring to." from gemma4:e2b, the first thing a stranger
# saw the product say).
FIRST_CHAT_DOC="$HERE/../../docs/getting-started/first-chat.md"
FIRST_PROMPT="$(sed -n 's/^noo chat --message "\(.*\)"$/\1/p' "$FIRST_CHAT_DOC" 2>/dev/null | head -n 1)"
# A refusal or a request for more input, in the shapes small models use.
FIRST_ANSWER_NOT_AN_ANSWER='please (provide|specify|clarify|share|tell me)|could you (please )?(provide|specify|clarify|share|tell me)|can you (please )?(provide|specify|clarify|share)|i (can.?t|cannot|am unable to|am not able to) (help|answer|assist|see|access)|i don.?t have (access|enough (information|context))|(what|which) (machine|computer|device|system) (are|do) you|more (details|information|context) (about|on|is needed)'
# A deflection ("How can I help you?") counts only when the answer gives no
# list item at all: a real answer may end with that line after its tips.
FIRST_ANSWER_DEFLECTION='how can i help you|do you have any (specific )?(questions|topics)|what would you like (to (know|discuss|talk about)|me to)'
# The named FAIL is for the product's default model only (MODEL=default: what
# a stranger gets). A tiny-model cell (MODEL=tiny, a 0.5B test model) prints
# the answer and a NOTE and never fails on it: its mood is not the product's
# (rc.6 branch run: qwen2.5:0.5b answered "How can I help you …?" on one cell
# and gave the tips on another; general 11-13).
export FIRST_PROMPT FIRST_ANSWER_NOT_AN_ANSWER FIRST_ANSWER_DEFLECTION MODEL TINY_MODEL
meta first_prompt "${FIRST_PROMPT:-none}"
pg_watch_start during-first-answer 1860
step first-answer 1800 -- sh -c '
  [ -n "$FIRST_PROMPT" ] || { echo "FIRST-ANSWER FAIL: docs/getting-started/first-chat.md has no noo chat --message line"; exit 1; }
  echo "prompt: $FIRST_PROMPT"
  out="$(noo chat --message "$FIRST_PROMPT")"; rc=$?
  printf "%s\n" "$out"
  [ $rc = 0 ] && [ -n "$(printf "%s" "$out" | tr -d "[:space:]")" ] || exit 1
  listed="$(printf "%s\n" "$out" | grep -cE "^[[:space:]]*([0-9]+[.)]|[-*]|•)[[:space:]]")"
  if printf "%s" "$out" | grep -qiE "$FIRST_ANSWER_NOT_AN_ANSWER" \
     || { [ "$listed" = 0 ] && printf "%s" "$out" | grep -qiE "$FIRST_ANSWER_DEFLECTION"; }; then
    if [ "$MODEL" = default ]; then
      echo "FIRST-ANSWER FAIL: the model asked for more input or refused instead of answering"; exit 1
    fi
    echo "FIRST-ANSWER NOTE: the tiny test model ($TINY_MODEL) did not answer the prompt; this cell runs MODEL=$MODEL, not the product default, so this is not a product verdict"
  fi' || fail_onboarded
meta first_answer_s "$(( $(date +%s) - CELL_START ))"
pg_watch_stop
pg_sample after-first-answer

# PROBE (operator 2026-11-14): cold-load delays, AFTER first-answer so the
# idle series above is untouched. coldload.py stops every model ollama ps
# lists (docker exec <c> ollama stop), then times ONE embed through the
# gateway (POST /api/external/embeddings with a service key it mints, never
# prints and revokes) and ONE `noo chat --message "$FIRST_PROMPT"` from
# cold, then both again warm. Writes $OUT/coldload.json. The default cell
# only (the idle-series cell). A probe: never the failed step.
if [ "$CELL" = "$IDLE_SERIES_CELL" ]; then
    step probe-coldload 3000 -- python3 "$HERE/coldload.py" --out "$OUT/coldload.json" --cell "$CELL" \
        --prompt "$FIRST_PROMPT"
fi

# PROBE (fa, general 11-13): where does a chat get an ingested document back?
# first-chat.md ingests ~/notes/anything.md and proves it with `noo rag query`
# (that line is read from the page). The same question is then asked on the
# three chat paths a person can reach with no more setup: `noo chat` (POST
# /api/inference/stream), `noo inference agent` (POST /api/agent/run, what the
# MCP tool noo_agentic_inference calls) and the console's chat (/ws/coordinator,
# via ws_chat.py with the CLI's stored login). rc.6 (run 43487245793): the
# query returned the fact, `noo chat` did not. If the page shows a chat line
# about anything.md again, that line is the one asked. Read, never judged;
# never the cell's failed step.
RAG_DOC_PAGE="$HERE/../../docs/getting-started/first-chat.md"
RAG_QUERY_LINE="$(sed -n 's/^noo rag query "\(.*anything\.md.*\)"$/\1/p' "$RAG_DOC_PAGE" 2>/dev/null | head -n 1)"
RAG_CHAT_LINE="$(sed -n 's/^noo chat --message "\(.*anything\.md.*\)"$/\1/p' "$RAG_DOC_PAGE" 2>/dev/null | head -n 1)"
RAG_CHAT_LINE="${RAG_CHAT_LINE:-summarise what you know from anything.md}"
RAG_WS_CHAT="$HERE/ws_chat.py"
RAG_VERDICT="$OUT/rag-chat.verdict"
export RAG_QUERY_LINE RAG_CHAT_LINE RAG_WS_CHAT RAG_VERDICT
pg_watch_start during-rag-ingest 1560
step probe-rag-chat 1500 -- sh -c '
  [ -n "$RAG_QUERY_LINE" ] || { echo "RAG PROBE: first-chat.md has no noo rag query line about anything.md"; exit 0; }
  fact="14(th)? (of )?march|ZIRCON-4471|kestrel"
  mkdir -p "$HOME/notes"
  printf "%s\n" "# Project notes" "" "The delivery deadline for the Kestrel project is the 14th of March, and the project codeword is ZIRCON-4471." > "$HOME/notes/anything.md"
  echo "== noo rag ingest ~/notes/anything.md"
  noo rag ingest "$HOME/notes/anything.md" 2>&1 | tail -n 5
  echo "== waiting for the index (the page'"'"'s noo rag query line)"
  t=0; indexed=no
  while [ "$t" -lt 300 ]; do
    if noo rag query "$RAG_QUERY_LINE" 2>&1 | grep -qiE "$fact"; then indexed=yes; break; fi
    sleep 10; t=$((t + 10))
  done
  echo "RAG PROBE: indexed (rag query returns the fact)=$indexed after ${t}s"
  noo rag status 2>&1 | head -n 8
  for path in chat agent console; do
    echo "== $path: \"$RAG_CHAT_LINE\""
    case "$path" in
      chat) out="$(noo chat --message "$RAG_CHAT_LINE" 2>&1)" ;;
      agent) out="$(timeout 300 noo inference agent "$RAG_CHAT_LINE" 2>&1)" ;;
      console) out="$(timeout 330 python3 -I "$RAG_WS_CHAT" "$RAG_CHAT_LINE" 2>&1)" ;;
    esac
    printf "%s\n" "$out" | head -n 30
    if printf "%s" "$out" | grep -qiE "$fact"; then got=yes; else got=no; fi
    echo "RAG PROBE: $path returned the fact=$got (index ready=$indexed)"
    [ "$path" = chat ] && echo "got=$got indexed=$indexed" > "$RAG_VERDICT"
  done
  true'
pg_watch_stop
pg_sample after-rag-ingest

# JUDGED (general 11-14, for 0.6.25): from noomesh#1164 on, `noo chat` runs the
# coordinator turn over POST /api/inference/chat and retrieves the caller's
# documents, so the page's chat line about anything.md must bring the fact
# back. Judged only when the build under test has that route (the installed
# noo names it AND the gateway answers it with anything but 404) and the cell
# runs the default model; a tiny-model cell prints a NOTE (as first-answer
# does), and an older build is "not judged", so an earlier rc never goes red.
RAG_CHAT_ROUTE=no
if grep -qa "/api/inference/chat" "$(command -v noo 2>/dev/null)" 2>/dev/null; then
  code="$(python3 -I "$RAG_WS_CHAT" --probe-route /api/inference/chat 2>/dev/null)"
  case "$code" in [1-5][0-9][0-9]) [ "$code" != 404 ] && RAG_CHAT_ROUTE=yes ;; esac
fi
export RAG_CHAT_ROUTE
step rag-chat 60 -- sh -c '
  v="$(cat "$RAG_VERDICT" 2>/dev/null)"
  if [ "$RAG_CHAT_ROUTE" != yes ]; then
    echo "RAG-CHAT: not judged: this build has no POST /api/inference/chat (noo chat is the raw model stream before 0.6.25)"; exit 0
  fi
  case "$v" in *"indexed=yes"*) ;; *) echo "RAG-CHAT: not judged: the index never returned the fact (${v:-no verdict})"; exit 0 ;; esac
  case "$v" in *"got=yes"*) echo "RAG-CHAT PASS: noo chat returned the ingested document'"'"'s fact"; exit 0 ;; esac
  if [ "$MODEL" = default ]; then
    echo "RAG-CHAT FAIL: noo chat (the coordinator route) did not return the fact the index holds"; exit 1
  fi
  echo "RAG-CHAT NOTE: the tiny test model ($TINY_MODEL) did not return the fact; this cell runs MODEL=$MODEL, not the product default, so this is not a product verdict"' || fail_onboarded

# PROBE (fa, rc.1 rehearsal A-reboot.status, i677): a container that joins
# another's network namespace (network_mode: service:<door>; noo-ollama-embed
# joins noo-stunnel-ollama-embed) must be running after EVERY dockerd start.
# rc.2 on a real dockerd: one start in five left it exited 128 ("cannot join
# network namespace of a non running container") with nothing restarting it.
# The fix is noo-netns-restore.service (onboard installs it; After=/PartOf=/
# WantedBy=docker.service). Twenty restarts of dockerd (its restore is the
# path a reboot takes), each read back and followed by a chat. BEFORE the
# offboard probe, which can take the install down (rc.3 run 1: it did, and every
# chat here then failed). A probe: read, never the cell's failed step.
# 20 restarts on ubuntu-22.04-amd64, where the race was first seen; 5 on every
# other cell (rc.3/rc.4: 20 took 37-42 min of each cell's runner).
NETNS_RESTARTS=5; [ "$CELL" = ubuntu-22.04-amd64 ] && NETNS_RESTARTS=20
export NETNS_RESTARTS
step probe-docker-restart-namespace-joiners 2700 -- sh -c '
  echo "PROBE SCOPE: ${NETNS_RESTARTS}x systemctl restart docker on this throwaway hosted runner (the dockerd restore path a reboot takes). It does NOT cover noo-hostd boot-restore, which runs only at a real boot."
  if [ -f /etc/systemd/system/noo-netns-restore.service ]; then echo "noo-netns-restore.service: installed"; else echo "noo-netns-restore.service: NOT installed (a release without the fix)"; fi
  left=0; chats=0
  for i in $(seq 1 "$NETNS_RESTARTS"); do
    sudo systemctl restart docker
    t=0; while [ $t -lt 90 ]; do docker info >/dev/null 2>&1 && break; sleep 2; t=$((t+2)); done
    sleep 20
    for c in noo-stunnel-ollama-embed noo-ollama-embed noo-stunnel-ollama-embed-cpu noo-ollama-embed-cpu; do
      line="$(docker inspect -f "{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}" "$c" 2>/dev/null)" || continue
      echo "restart $i: $line"
      case "$line" in *status=running*) ;; *) left=$((left+1)) ;; esac
    done
    out="$(timeout 300 noo chat --message "reply with the word ok" 2>&1)" && chats=$((chats+1)) || echo "restart $i: chat FAILED: $(printf "%s" "$out" | tail -n 1 | cut -c1-160)"
  done
  sudo journalctl -u noo-netns-restore.service --no-pager 2>/dev/null | grep -F "noo-netns-restore:" | tail -n 20
  docker --version
  echo "NETNS PROBE: containers left not running after a restart=$left, chats answered=$chats of $NETNS_RESTARTS"
  true'

# PROBE (fa, i677 finding 20; fix #1059): `noo offboard` run by a shell that
# cannot reach docker (no supplementary groups, as for a stranger whose
# shell lacks the docker group) must refuse and remove NOTHING: not even the
# self-heal daemons (rc.2: the gate trusted an exit 0 with no version and
# offboard stopped them first; the fix reads the version). A probe is
# reported on its own and never becomes the cell's failed step; on releases
# without #1059 it is expected to fail (it wiped the box).
# A cell running as ROOT (the WSL2 cell's distro user) cannot be "a shell
# without the docker group": root reaches the socket by uid, so offboard
# rightly proceeds and -y wipes the box (rc.5 matrix run 1, WSL2). There the
# probe is not run and says why, by name.
if [ "$(id -u)" = 0 ]; then
step probe-offboard-without-docker 30 -- sh -c 'echo "PROBE SKIPPED: this cell runs as root (uid 0), which reaches docker without the docker group; a shell without docker access cannot be made here"; true'
else
step probe-offboard-without-docker 600 -- sh -c '
  # What THIS docker answers in that shell (rc.2: Docker 28.0.4 let the gate
  # pass; is it "exit 0, empty version"?): read, never judged.
  sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups --reset-env \
       env HOME="$HOME" PATH="$PATH" docker info --format "{{.ServerVersion}}" >/tmp/noo-di.out 2>/tmp/noo-di.err; di_rc=$?
  echo "DOCKER-INFO without the docker group: exit=$di_rc stdout-bytes=$(tr -d "[:space:]" </tmp/noo-di.out | wc -c) stderr1=$(grep -m1 -v "^[[:space:]]*$" /tmp/noo-di.err | cut -c1-200)"
  rm -f /tmp/noo-di.out /tmp/noo-di.err
  # NOO_DOCKER_GROUP_RELAUNCHED=1: the docker-group relaunch (#1064) is
  # spent, as for a user who is NOT in the docker group. The runner user is
  # in it (/etc/group), so without the marker `sg docker` relaunches the
  # offboard WITH docker and -y removes the install, which is what -y asks
  # (rc.3 run 1); the refusal this probe tests is then never reached.
  out="$(sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups --reset-env \
         env HOME="$HOME" PATH="$PATH" NOO_DOCKER_GROUP_RELAUNCHED=1 noo offboard -y 2>&1)"; rc=$?
  printf "%s\n" "$out"; ok=1
  [ "$rc" != 0 ] || { echo "PROBE FAIL: offboard without docker exited 0"; ok=0; }
  # Case-insensitive: the failure line is printed capitalised ("x Cannot reach
  # docker (…): nothing was removed"; rc.3 run 43351232102).
  printf "%s" "$out" | grep -qi "cannot reach docker" || { echo "PROBE FAIL: it did not say it cannot reach docker"; ok=0; }
  printf "%s" "$out" | grep -qi "nothing was removed" || { echo "PROBE FAIL: it did not say nothing was removed"; ok=0; }
  # sudo: this shell may lack the docker group too (rc.4: a groupless
  # `docker ps` answered permission denied and read as "gone").
  sudo docker ps -q --filter name=noo-gateway | grep -q . || { echo "PROBE FAIL: the gateway container is gone"; ok=0; }
  [ -d "$HOME/.noo" ] || { echo "PROBE FAIL: ~/.noo is gone"; ok=0; }
  [ -d /var/lib/noo ] || { echo "PROBE FAIL: /var/lib/noo is gone"; ok=0; }
  noo health >/dev/null 2>&1 || { echo "PROBE FAIL: noo health is not ok afterwards"; ok=0; }
  [ "$ok" = 1 ]' || PROBE_ALTERED=1
fi


# ── 5. clean uninstall ──────────────────────────────────────────────────
teardown
finish
