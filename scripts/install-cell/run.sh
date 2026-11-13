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
# The single-turn line docs/getting-started/first-chat.md gives, verbatim.
step first-answer 1800 -- sh -c 'out="$(noo chat --message "in two lines, what can you do on this machine?")"; rc=$?
  printf "%s\n" "$out"; [ $rc = 0 ] && [ -n "$(printf "%s" "$out" | tr -d "[:space:]")" ]' || fail_onboarded
meta first_answer_s "$(( $(date +%s) - CELL_START ))"

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


# ── 5. clean uninstall ──────────────────────────────────────────────────
teardown
finish
