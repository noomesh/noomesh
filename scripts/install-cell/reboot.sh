#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The REBOOT cell of .github/workflows/install-matrix.yml: does the stack come
# back after a reboot with NO command?
#
# The stance (release lead): after a reboot the stack comes back by itself.
# noo-hostd's BootRestore (node-agent-go/internal/hostd/boot.go) rewrites the
# RAM-backed secret files and starts the stopped containers; `noo stack start`
# is only the remedy when it did not. This cell JUDGES that.
#
# A hosted runner cannot be rebooted, so the box is a QEMU/KVM guest (Ubuntu
# 24.04 cloud image) the cell installs into exactly as run.sh does (the README
# line, `noo onboard --ci` with the tiny model, `noo health`, one chat), then
# reboots with `systemctl reboot`. From T0 (the host's clock when ssh stops
# answering) it polls with READ-ONLY commands only (no `noo stack`, `start`,
# `upgrade` or `onboard`), each under a hard budget. Only after the judge file
# is written may `noo stack start` run, as extra evidence.
#
#   OUT=<dir> CELL=reboot-24.04 RUNNER=<label> CLI_TAG=latest|noo-cli-vX.Y.Z[-rc.N] \
#   scripts/install-cell/reboot.sh
#
# GITHUB-HOSTED, EPHEMERAL RUNNERS ONLY: it uses sudo and /dev/kvm. No /dev/kvm
# (the workflow's udev step did not give it): `REBOOT kvm SKIP ...`, exit 0. A
# SKIP is neither a PASS nor a FAIL.
#
# One line per assert in $OUT/judge/reboot.txt: REBOOT <id> PASS|FAIL|SKIP <s> <why>
set -uo pipefail
: "${OUT:?}" "${CELL:=reboot-24.04}" "${RUNNER:=?}" "${CLI_TAG:=latest}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# CLI_TAG is a free-text dispatch input spliced into the install line below,
# which the guest runs with `sh -c`: hold it to the rule before ANY use, on its
# own (the workflow refuses it first). Exit 2: not run.
# shellcheck source=scripts/install-cell/validate_tag.sh
. "$HERE/validate_tag.sh"
require_cli_tag "$CLI_TAG" || exit 2
# ── end of the dispatch-input check ──
TINY_MODEL="${TINY_MODEL:-qwen2.5:0.5b}"
mkdir -p "$OUT"
# shellcheck source=scripts/install-cell/lib.sh
. "$HERE/lib.sh"
export PATH="$HOME/.local/bin:$PATH"
J="$OUT/judge"; mkdir -p "$J"
JUDGE_PY="$HERE/reboot_judge.py"; export JUDGE_PY
ROWS="$J/rows.tsv"; : > "$ROWS"

meta cell "$CELL"
meta runner "$RUNNER"
meta modes "reboot: a QEMU/KVM Ubuntu 24.04 guest installs cli_tag=$CLI_TAG (README line, onboard --ci, tiny model $TINY_MODEL), reboots, and must come back with NO command"
meta limits "the guest's user is non-root with passwordless sudo: sudo password prompts are never seen"
meta limits "no GPU: CPU inference only; the guest has 10 GB RAM and 4 vCPUs"
meta limits "the reboot is the guest's (systemctl reboot under QEMU), not a power cut: a crash-reboot (journal and Docker unclean shutdown) is not covered"

# row ID STATUS SECONDS DETAIL: one assert's result (judged by reboot_judge.py).
row() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$ROWS"; }

QEMU_PID=""
finish() {
    # The guest dies with the cell: by recorded PID, never by pattern.
    if [ -n "$QEMU_PID" ] && [ -r "/proc/$QEMU_PID/cmdline" ] && tr '\0' ' ' < "/proc/$QEMU_PID/cmdline" | grep -q qemu-system; then
        kill "$QEMU_PID" 2>/dev/null; sleep 2; kill -9 "$QEMU_PID" 2>/dev/null
    fi
    # The serial console, through the redactor (the artifacts are PUBLIC).
    if [ -s "${SERIAL:-/nonexistent}" ]; then
        tail -c 2000000 "$SERIAL" | python3 "$CELL_PY" redact > "$OUT/logs/guest-serial.log"
    fi
    python3 "$CELL_PY" summary "$OUT"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && {
        [ -s "$J/reboot.md" ] && cat "$J/reboot.md" >> "$GITHUB_STEP_SUMMARY"
        cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"; }
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

# ── 0. KVM, or a clean SKIP ──────────────────────────────────────────────────
if [ ! -c /dev/kvm ] || [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    row kvm SKIP - "no /dev/kvm on this runner"
    python3 "$JUDGE_PY" judge "$ROWS" "$J"
    meta not_run "no /dev/kvm on this runner: the reboot cell was not run (SKIP, not a pass)"
    echo "::notice::$CELL: no /dev/kvm on this runner; nothing was judged"
    finish
fi
step prereqs 30 -- bash -c 'for b in qemu-system-x86_64 qemu-img cloud-localds ssh ssh-keygen curl sha256sum; do
    command -v "$b" >/dev/null || { echo "missing: $b (the workflow'"'"'s KVM step installs qemu-system-x86 qemu-utils cloud-image-utils)"; exit 1; }; done; ls -l /dev/kvm' || finish

# ── 1. the guest: Ubuntu 24.04 cloud image, an overlay, a cloud-init seed ───
# /mnt is the hosted runner's larger disk; the cell falls back to the temp dir.
WORK=/mnt/reboot-cell
if ! { sudo mkdir -p "$WORK" && sudo chown "$(id -u):$(id -g)" "$WORK"; } 2>/dev/null || [ "$(df -Pk /mnt | awk 'NR==2{print $4}')" -lt 41943040 ]; then
    WORK="${RUNNER_TEMP:-/tmp}/reboot-cell"; mkdir -p "$WORK"
fi
meta guest_workdir "$WORK ($(df -Pk "$WORK" | awk 'NR==2{printf "%.0f", $4/1048576}') GB free)"
BASE_URL="https://cloud-images.ubuntu.com/noble/current"
IMG="noble-server-cloudimg-amd64.img"
KEY="$WORK/id_ed25519"; SERIAL="$WORK/serial.raw"; export KEY
SSH_PORT=2222; export SSH_PORT
GUEST_USER=noocell; export GUEST_USER

# Download, then verify the SHA256 against the published SHA256SUMS (same host).
step guest-image 900 -- bash -c '
  set -eu; cd "$1"
  curl -fsSL --retry 3 -o SHA256SUMS "$2/SHA256SUMS"
  curl -fsSL --retry 3 -o "$3" "$2/$3"
  want="$(awk -v f="*$3" "\$2==f || \$2==substr(f,2) {print \$1; exit}" SHA256SUMS)"
  [ -n "$want" ] || { echo "SHA256SUMS has no line for $3"; exit 1; }
  got="$(sha256sum "$3" | cut -d" " -f1)"
  echo "published sha256: $want"; echo "downloaded sha256: $got"
  [ "$want" = "$got" ] || { echo "SHA256 MISMATCH for $3"; exit 1; }
  echo "sha256 verified"' _ "$WORK" "$BASE_URL" "$IMG" || finish

step guest-disk 120 -- bash -c '
  set -eu; cd "$1"
  qemu-img create -f qcow2 -b "$2" -F qcow2 overlay.qcow2 40G
  rm -f "$3" "$3.pub"; ssh-keygen -q -t ed25519 -N "" -C reboot-cell -f "$3"
  printf "instance-id: reboot-cell\nlocal-hostname: noocell\n" > meta-data
  cat > user-data <<EOF
#cloud-config
users:
  - name: $4
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$3.pub")
ssh_pwauth: false
package_update: true
packages: [curl, ca-certificates, git, python3]
EOF
  cloud-localds seed.img user-data meta-data
  ls -l overlay.qcow2 seed.img' _ "$WORK" "$IMG" "$KEY" "$GUEST_USER" || finish

# gssh CMD: one command in the guest, over the forwarded port. PATH carries the
# installer's ~/.local/bin. Exported: the steps below run it in `bash -c`.
gssh() {
    ssh -i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=6 -o LogLevel=ERROR "$GUEST_USER@127.0.0.1" \
        "export PATH=\"\$HOME/.local/bin:\$PATH\"; $*"
}
export -f gssh
# gs NAME TIMEOUT CMD: a step whose command runs in the guest (cell.py run
# starts a program, not a shell function, so the step goes through bash).
gs() { local n="$1" t="$2" c="$3"; step "$n" "$t" -- bash -c 'gssh "$1"' _ "$c"; }
export J CELL_PY

echo "::group::boot the guest"
: > "$SERIAL"
nohup qemu-system-x86_64 -enable-kvm -cpu host -m 10G -smp 4 -nographic -monitor none \
    -serial "file:$SERIAL" \
    -drive "file=$WORK/overlay.qcow2,if=virtio,format=qcow2" -drive "file=$WORK/seed.img,if=virtio,format=raw" \
    -nic "user,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" > "$WORK/qemu.out" 2>&1 < /dev/null &
QEMU_PID=$!
echo "qemu pid $QEMU_PID"
echo "::endgroup::"
# A bound on the first boot (cloud-init installs packages before it is done).
step guest-ssh 600 -- bash -c 'until gssh true >/dev/null 2>&1; do kill -0 "$1" 2>/dev/null || { echo "qemu exited"; cat "$2"; exit 1; }; sleep 5; done; gssh "uname -a; cat /proc/sys/kernel/random/boot_id"' _ "$QEMU_PID" "$WORK/qemu.out" || finish
gs guest-cloud-init 600 'sudo cloud-init status --wait --long; sudo cloud-init status | grep -q "status: done"' || finish
gs box 120 'cat /etc/os-release | head -3; nproc; free -m; df -h /; git --version'

# ── 2. install, onboard, health, one chat: exactly run.sh's path ────────────
# Docker is what `noo onboard` offers to install on a bare box (get.docker.com,
# install.md); a --ci onboard cannot answer that prompt, so the cell installs
# it the same way first, in its own step.
gs guest-docker 900 'curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker "$(id -un)" && sudo systemctl enable --now docker && sudo docker compose version' || finish

README="$HERE/../../README.md"
LINE="$(grep -m1 -E '^[^#]*releases/latest/download/install\.sh' "$README" 2>/dev/null)"
if [ -z "$LINE" ]; then
    step install 10 -- sh -c 'echo "install-cell: no install line in README.md"; exit 1'; finish
fi
NOO_ENV=""
if [ "$CLI_TAG" != latest ]; then
    LINE="$(printf '%s' "$LINE" | sed "s#releases/latest/download/#releases/download/$CLI_TAG/#")"
    NOO_ENV="export NOO_CLI_VERSION=$CLI_TAG;"
fi
meta install_line "$LINE"
gs install 900 "$NOO_ENV cd \"\$HOME\" && $LINE" || finish
gs version 60 'noo --version' || finish
meta installed_version "$(gssh 'noo --version' 2>/dev/null | head -1)"

# run.sh's tiny-model ci path: onboard everything but the model, declare the
# tiny one in the install's .env, run the model section alone, then switch to it.
if ! gssh 'noo onboard --help 2>&1 | grep -q -- "--root-ok"'; then
    meta limits "the installed CLI predates onboard --root-ok (0.6.27-rc.1): dispatch with a newer cli_tag"
    meta not_run "the installed CLI predates the harness's onboard flags (--root-ok)"
    row kvm PASS - "the guest booted (KVM present)"
    row onboard SKIP - "the installed CLI has no onboard --root-ok"
    python3 "$JUDGE_PY" judge "$ROWS" "$J"
    finish
fi
gs onboard 2700 'noo onboard --ci --root-ok --skip-model' || finish
gs declare-tiny-model 60 "envf=\"\$(find \"\$HOME\" -maxdepth 4 -name .noo-standalone -print -quit 2>/dev/null)\"; envf=\"\${envf%/.noo-standalone}/.env\"; test -f \"\$envf\" && { grep -v '^OLLAMA_MODEL=' \"\$envf\" > \"\$envf.tmp\"; echo 'OLLAMA_MODEL=$TINY_MODEL' >> \"\$envf.tmp\"; mv \"\$envf.tmp\" \"\$envf\"; echo \"OLLAMA_MODEL=$TINY_MODEL in \$envf\"; }" || finish
gs onboard-model 1800 'noo onboard --ci --only model' || finish
gs health 600 'for i in $(seq 1 40); do noo health >/dev/null 2>&1 && break; sleep 15; done; noo health' || finish
gs switch-to-tiny-model 300 "noo models switch '$TINY_MODEL' --backend ollama --yes" || finish
# The switch restarts the gateway and returns before it answers again (the
# shake-out's chat 0.3 s later read "not reachable"); run.sh has other probes
# in between. Wait for health as run.sh's health step does.
gs health-after-switch 600 'for i in $(seq 1 40); do noo health >/dev/null 2>&1 && break; sleep 15; done; noo health' || finish
CHAT_MSG="Reply with the single word ok."
export CHAT_MSG
gs chat-before 900 "noo chat --message '$CHAT_MSG'" || finish

# ── 3. evidence before: verify, and the hostd unit's kind and Linger ────────
gssh 'noo --json cluster verify' 2>/dev/null | python3 "$CELL_PY" redact > "$J/verify-before.json"
SELF="$(gssh hostname 2>/dev/null | tr -d '\r')"
export SELF

# linger-at-install. onboard installs noo-hostd as a systemd USER unit in
# controller mode (noo-cli onboard/steps.rs hostd_install_args: no --system) and
# never enables linger: noo-hostd's installer only PRINTS the hint (install.go).
# Without Linger the user manager, and so hostd, does not start at boot until
# someone logs in.
hostd_kind() { gssh 'if systemctl --user is-enabled noo-hostd >/dev/null 2>&1; then echo user; elif systemctl is-enabled noo-hostd >/dev/null 2>&1; then echo system; else echo none; fi' 2>/dev/null | tr -d '\r'; }
HOSTD_KIND="$(hostd_kind)"
LINGER="$(gssh 'loginctl show-user "$(id -un)" -p Linger --value' 2>/dev/null | tr -d '\r')"
LV="$(python3 "$JUDGE_PY" linger "$HOSTD_KIND" "$LINGER" "$GUEST_USER")"
row linger-at-install "${LV%%$'\t'*}" - "${LV#*$'\t'}"
meta hostd_unit "$HOSTD_KIND (Linger=${LINGER:-?})"

# ── 4. the shared pass: reboot, then read-only polls ─────────────────────────
# reboot_pass PREFIX: `systemctl reboot`, T0 = the host's clock when ssh stops
# answering, then the polls. Budgets are the B_* variables. Rows are PREFIXid.
# Only read-only commands run after T0 (ssh, cat, docker info, noo health, noo
# --json cluster verify|show, noo chat, systemctl is-active, journalctl, docker ps).
since() { echo $(( $(date +%s) - T0 )); }
last_line() { tail -n 1 "$OUT/logs/${STEPP}$1.log" | cut -c1-240; }
STEPP=rb-   # pass two sets probe-: its steps are diagnostic and never fail the cell
# trow ID BUDGET OK_DETAIL -- CMD...: one step with a hard budget, its result as
# a row (seconds since T0 at its end). 124 is the budget expiring.
trow() {
    local id="$1" budget="$2" okd="$3"; shift 4
    step "${STEPP}$id" "$budget" -- "$@"
    local rc=$? secs; secs="$(since)"
    if [ "$rc" = 0 ]; then row "$id" PASS "$secs" "$okd: $(last_line "$id")"
    elif [ "$rc" = 124 ]; then row "$id" FAIL "$secs" "not within the ${budget}s budget: $(last_line "$id")"
    else row "$id" FAIL "$secs" "rc=$rc: $(last_line "$id")"; fi
    return "$rc"
}

reboot_pass() {
    local P="$1" bid gt0 i
    bid="$(gssh 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r')"
    gt0="$(gssh 'date +%s' 2>/dev/null | tr -d '\r')"
    case "$gt0" in ''|*[!0-9]*) row "${P}reboot-initiated" FAIL - "could not read the guest clock before the reboot"; return 1 ;; esac
    export BOOT_ID_BEFORE="$bid" GUEST_T0="$gt0"
    gs "${STEPP}${P}reboot-command" 60 'sudo systemctl reboot' || true
    T0=""
    for i in $(seq 1 60); do
        if ! gssh true >/dev/null 2>&1; then T0="$(date +%s)"; break; fi
        sleep 2
    done
    export T0
    if [ -z "$T0" ]; then
        row "${P}reboot-initiated" FAIL - "ssh still answered 120 s after systemctl reboot: the guest never went down"
        return 1
    fi
    row "${P}reboot-initiated" PASS 0 "ssh stopped answering; T0 on the host clock"
    if [ -n "$P" ]; then
        # No login yet: only the sshd banner (no PAM session, so no user manager).
        # Then a headless wait, so a user unit that needs a login has had its chance.
        step "${STEPP}${P}banner" "$B_SSH" -- bash -c 'until timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$SSH_PORT && head -c 4 <&3 | grep -q SSH-"; do sleep 3; done'
        sleep "$HEADLESS_WAIT"
        row "${P}headless-wait" INFO "$(since)" "waited ${HEADLESS_WAIT}s after the sshd banner with no login before the first session"
    fi
    # ssh-up: answering on a NEW boot (boot_id changed), not the old guest.
    trow "${P}ssh-up" "$B_SSH" "ssh answers on a new boot" -- bash -c '
      until [ "$(gssh "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d "\r")" ] && \
            [ "$(gssh "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d "\r")" != "$BOOT_ID_BEFORE" ]; do
        sleep 3; done; echo "boot id changed; guest uptime: $(gssh "uptime -p")"' || {
        for i in docker-up gateway-healthy verify chat agent-registered units boot-restore; do
            row "${P}$i" SKIP - "not reached: ssh did not come back (see logs/guest-serial.log)"
        done
        row "${P}no-command" PASS "$(since)" "by construction: from T0 on the cell ran only read-only commands; nothing started the stack"
        return 0
    }
    trow "${P}docker-up" "$B_DOCKER" "docker info answers" -- bash -c '
      until gssh "docker info >/dev/null 2>&1 || sudo -n docker info >/dev/null 2>&1"; do sleep 5; done; gssh "docker info 2>&1 | head -5 || true"'
    trow "${P}gateway-healthy" "$B_HEALTH" "noo health is ok" -- bash -c '
      until gssh "noo health" >/dev/null 2>&1; do sleep 10; done; gssh "noo health"'
    # verify: no FAIL row, by ratchet.py's rule. A row may FAIL while the agent is
    # still reconnecting, so it is retried within the budget; the last JSON is kept.
    ONBOARD_LOGS=(--onboard-log "$OUT/logs/onboard.log" --onboard-log "$OUT/logs/onboard-model.log")
    export VERIFY_JSON="$J/${P}verify-after.json"
    trow "${P}verify" "$B_VERIFY" "no FAIL rows" -- bash -c '
      while :; do
        gssh "noo --json cluster verify" 2>/dev/null | python3 "$1" redact > "$VERIFY_JSON"
        python3 "$JUDGE_PY" verify "$VERIFY_JSON" "${@:2}" && break
        sleep 20
      done' _ "$CELL_PY" "${ONBOARD_LOGS[@]}"
    trow "${P}chat" "$B_CHAT" "answered after the reboot" -- bash -c '
      out=""
      until out="$(gssh "noo chat --message \"$CHAT_MSG\"" 2>&1)" && [ -n "$(printf "%s" "$out" | tr -d "[:space:]")" ]; do sleep 10; done
      printf "%s\n" "$out"'
    # agent-registered: the node agent re-registered after the reboot. Source 1:
    # `noo --json cluster show <node>`: last_heartbeat later than the guest's clock
    # at the reboot command. Source 2 (only if that field is unreadable): the agent's
    # "registered with controller" line in `journalctl -u noo-node-agent -b`.
    export AGENT_SHOW="$J/${P}cluster-show-after.json" AGENT_JOURNAL="$J/${P}agent-boot.journal"
    trow "${P}agent-registered" "$B_AGENT" "the node agent beat after the reboot" -- bash -c '
      while :; do
        gssh "timeout 60 noo --json cluster show $SELF" 2>/dev/null | python3 "$CELL_PY" redact > "$AGENT_SHOW"
        gssh "sudo -n journalctl -u noo-node-agent -b --no-pager" 2>/dev/null | python3 "$CELL_PY" redact > "$AGENT_JOURNAL"
        python3 "$JUDGE_PY" agent "$AGENT_SHOW" "$GUEST_T0" --journal "$AGENT_JOURNAL" && break
        sleep 10
      done'
    # What the boot did, read-only: unit states, noo-hostd's boot journal (the
    # BOOT-RESTORE lines), every container's status, failed units, and when the
    # first login session began against when hostd's first line was logged.
    gssh 'for u in noo-hostd noo-node-agent noo-netns-restore; do echo "$u system=$(systemctl is-active $u 2>&1) user=$(systemctl --user is-active $u 2>&1)"; done' 2>&1 | python3 "$CELL_PY" redact > "$J/${P}units.txt"
    gssh 'sudo -n journalctl -b -u noo-hostd --no-pager 2>&1; journalctl --user -b -u noo-hostd --no-pager 2>&1' 2>&1 | python3 "$CELL_PY" redact > "$J/${P}hostd-boot.journal"
    gssh 'docker ps -a --format "{{.Names}}\t{{.Status}}" 2>&1 || sudo -n docker ps -a --format "{{.Names}}\t{{.Status}}"' 2>&1 | python3 "$CELL_PY" redact > "$J/${P}docker-ps.txt"
    gssh 'systemctl --failed --no-pager 2>&1; echo "== first sessions"; sudo -n journalctl -b -u systemd-logind --no-pager 2>&1 | grep -m2 "New session"; echo "== hostd first line"; journalctl --user -b -u noo-hostd --no-pager -o short-iso 2>&1 | sed -n 2p' 2>&1 | python3 "$CELL_PY" redact > "$J/${P}boot-evidence.txt"
    UV="$(python3 "$JUDGE_PY" units "$J/${P}units.txt")"; urc=$?
    row "${P}units" "$([ $urc = 0 ] && echo PASS || echo FAIL)" "$(since)" "$UV"
    BV="$(python3 "$JUDGE_PY" bootrestore "$J/${P}hostd-boot.journal")"
    row "${P}boot-restore" "${BV%%$'\t'*}" "$(since)" "${BV#*$'\t'}"
    row "${P}no-command" PASS "$(since)" "by construction: from T0 on the cell ran only read-only commands (listed above); nothing started the stack"
}

# ── 5. pass one: the reboot with the install's own Linger ───────────────────
B_SSH=300 B_DOCKER=300 B_HEALTH=600 B_VERIFY=600 B_CHAT=300 B_AGENT=300 HEADLESS_WAIT=0
reboot_pass "" || { step judge 120 -- python3 "$JUDGE_PY" judge "$ROWS" "$J"; finish; }

# ── 6. pass two (diagnostic): what a stranger who skipped linger gets ───────
# After pass one's rows are written and BEFORE any remedy. Bounded to ~15 min.
if [ "$HOSTD_KIND" = user ]; then
    if gs probe-disable-linger 60 'sudo loginctl disable-linger "$(id -un)"; loginctl show-user "$(id -un)" -p Linger --value'; then
        B_SSH=180 B_DOCKER=120 B_HEALTH=240 B_VERIFY=120 B_CHAT=120 B_AGENT=120 HEADLESS_WAIT=90
        STEPP=probe-
        reboot_pass "nolinger-" || true
        STEPP=rb-
    else
        row nolinger SKIP - "could not disable linger"
    fi
else
    row nolinger SKIP - "hostd is a ${HOSTD_KIND} unit"
fi

# ── 7. the judge, written before any `noo stack start` ──────────────────────
step judge 120 -- python3 "$JUDGE_PY" judge "$ROWS" "$J"
JUDGE_RC=$?

# ── 8. the remedy, as extra evidence only (after the judge file exists) ─────
# Run when a judged row failed: does `noo stack start` bring it back? Not a
# verdict: the line is appended and the judge re-run to render it.
if [ "$JUDGE_RC" != 0 ] && [ -s "$J/reboot.txt" ] && gssh true >/dev/null 2>&1; then
    # linger back on first so the remedy runs in the install's own conditions
    gssh 'sudo loginctl enable-linger "$(id -un)"' >/dev/null 2>&1
    R0="$(date +%s)"
    step probe-remedy-stack-start 1800 -- bash -c 'gssh "noo stack start"'
    RRC=$?
    row remedy-stack-start "$([ $RRC = 0 ] && echo PASS || echo FAIL)" "$(( $(date +%s) - R0 ))" "noo stack start after the failed asserts: rc=$RRC"
    python3 "$JUDGE_PY" judge "$ROWS" "$J" > /dev/null
fi
finish
