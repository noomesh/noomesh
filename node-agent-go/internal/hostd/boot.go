// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// The reboot path for RAM-backed secret files.
//
// The gateway, worker and trellion bind-mount their secrets from files under a
// tmpfs directory (scripts/lib-secrets.sh write_secret_files). A reboot empties
// the tmpfs while dockerd, at boot, starts every container whose restart policy
// says so. A container whose bind source is missing fails to start, and dockerd
// does not retry it (the restart policy governs a container that STARTED and
// exited, not one that could not be created for the daemon-boot start): it sits
// in `Created`/`Exited` until something starts it. Before the files moved to
// tmpfs the values lived in each container's layer and the stack came back by
// itself, so this daemon, which the controller already runs at boot, restores
// that: once, when it starts and finds the secret directory gone, it rewrites
// the files from the store with the age key already on disk (load_secrets) and
// `docker start`s the stopped containers that bind from that directory AND the
// stopped controller core services (i301 a): dockerd's own restore skipped
// noo-nats on 2026-10-28 and, with NATS down, the gateway crash-looped and the
// whole controller stayed down until `noo stack start`. The core set is the
// services whose compose profiles include "controller", derived from the
// compose files (not a list); a container labelled noo.managed-by (an
// agent-managed backend) or with restart: "no" (a one-shot) is not started.
// The script ends by naming what is STILL down (stderr, exit 4), which
// BootRestore logs as a WARN.
//
// Not a launcher: nothing is pulled, built or recreated, and any other
// container is never touched. When the install's state lives
// on the encrypted volume (i10a) and that volume did not open, nothing is
// started (lib-state-volume.sh check_state_volume_open). A directory that EXISTS means
// the files are there (a hostd restart, not a reboot) and the step does nothing,
// so a service an operator stopped by hand stays stopped.
//
// The data root. With restart: unless-stopped, dockerd starts the containers at
// boot WITHOUT a launcher, so a data disk that did not come back leaves postgres
// binding an empty directory on the root disk and initialising a NEW EMPTY
// database there (the 2026-10-24 near miss). The step therefore runs
// lib-data-root-mount.sh data_root_mount_boot_guard FIRST, whether or not the
// secret directory is populated: when the data root is missing, unreadable or
// not on the filesystem recorded in .noo-data-root-id, it stops the stack's
// containers (postgres first), writes why to .noo-data-root-refused, starts
// nothing and fails the attempt (retried: a slow disk may yet mount). It never
// starts a container on that path. On Linux a host without findmnt
// (util-linux) is refused the same way, since the filesystem cannot be
// checked; the reason says retrying will not help (the binary does not appear
// by waiting), and the bounded loop below only repeats the harmless stop. The race is real (dockerd is up before
// this daemon), so the stop is a backstop; the launchers' check is the gate.
// Hardening for later: a controller-only docker drop-in RequiresMountsFor=<data
// root> would keep dockerd from starting at all, at the price of docker (and
// everything on it) staying down while the disk is absent.

const bootRestoreScript = `_noo_lib=%s
_noo_t_list=%d _noo_t_inspect=%d _noo_t_start=%d _noo_t_netns=%d _noo_t_listwindow=%d _noo_t_listwait=%d _noo_budget=%d
. "$_noo_lib" 2>/dev/null || { echo "boot-restore: cannot source lib-secrets.sh" >&2; exit 2; }
if . "$(dirname "$_noo_lib")/lib-data-root-mount.sh" 2>/dev/null; then
  data_root_mount_boot_guard || { echo "boot-restore: the data-root guard refused (the data root is not on its recorded filesystem, or it cannot be checked) — stateful containers stopped, nothing started (reason above, and in .noo-data-root-refused)" >&2; exit 3; }
fi
d="$(secret_rundir)"
if [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
  echo "boot-restore: $d is populated; nothing to do"
  exit 0
fi
if . "$(dirname "$_noo_lib")/lib-state-volume.sh" 2>/dev/null; then
  check_state_volume_open || { echo "boot-restore: the encrypted state volume is not open — not starting the stack (reason above)" >&2; exit 3; }
fi
load_secrets >/dev/null || { echo "boot-restore: could not write the secret files (reason above)" >&2; exit 1; }
d="$(secret_rundir)"
root="$(cd "$(dirname "$_noo_lib")/.." && pwd)"
# The compose project the launcher used: COMPOSE_PROJECT_NAME if set, else the
# instance's (lib-instance.sh noo_instance_env: NOO_INSTANCE in .env gives
# noo-<instance>), else the cluster file's name:, else noomesh. If the instance
# cannot be resolved (its data-root guard refused), no core service is started:
# guessing the default project would start another instance's containers.
proj="${COMPOSE_PROJECT_NAME:-}"
if [ -z "$proj" ] && [ -f "$(dirname "$_noo_lib")/lib-instance.sh" ]; then
  if ! proj="$(cd "$root" && . "$(dirname "$_noo_lib")/lib-instance.sh" && noo_instance_env >/dev/null 2>&1 && echo "${COMPOSE_PROJECT_NAME:-}")"; then
    proj=""; noproj=1
    echo "boot-restore: could not resolve this instance's compose project; only the secret-binding containers are started" >&2
  fi
fi
if [ -z "$proj" ] && [ -z "${noproj:-}" ]; then
  proj="$(sed -n 's/^name:[[:space:]]*//p' "$root/docker-compose.cluster.yml" 2>/dev/null | head -1)"
  proj="${proj:-noomesh}"
fi
# The controller core set, derived from the compose files (the same way
# lib-addons.sh addon_core_services derives its set, never a list): every
# service whose profiles include "controller". The agent-managed backends and
# the one-shots sit in other profiles or carry restart: "no" (skipped below).
core=" $(awk 'FNR==1 { s=0; svc="" }
  /^services:[ \t]*$/ { s=1; next }
  /^[^ \t#]/ { s=0 }
  s && /^  [A-Za-z0-9][A-Za-z0-9_.-]*:/ { svc=$1; sub(/:.*/, "", svc) }
  s && svc != "" && /^    profiles:.*"controller"/ { print svc }' "$root"/docker-compose*.yml 2>/dev/null | sort -u | tr '\n' ' ')"
n=0
down=""
skipped=""
# Every docker call below is bounded (_noo_dk <seconds> <docker args>): a
# container Docker never answers for (a process that survived SIGKILL) would
# otherwise hang this script while it holds the compose lock. A timeout is
# 124 (or 137 after the follow-up KILL); any other failure keeps the old
# meaning (an empty answer). timeout(1) is probed ONCE: GNU form first, then a
# plain "timeout <n>" (BusyBox), else the calls are unbounded and only the
# overall deadline (Go side) applies, said once.
if timeout --foreground -k 1 1 true >/dev/null 2>&1; then _noo_tm=gnu
elif timeout 1 true >/dev/null 2>&1; then _noo_tm=plain
else _noo_tm=none; echo "boot-restore: timeout(1) is not usable here; Docker calls are not individually bounded (the overall deadline of ${_noo_budget}s still applies)" >&2; fi
_noo_wedged() { [ "$1" = 124 ] || [ "$1" = 137 ]; }
_noo_bound() {
  _noo_s="$1"; shift
  case "$_noo_tm" in
    gnu) timeout --foreground -k 3 "$_noo_s" "$@" ;;
    plain) timeout "$_noo_s" "$@" ;;
    *) "$@" ;;
  esac
}
# Every call is also clamped to what is left of the script budget (at least
# 1 s), so a container reached late cannot run the script past its budget: the
# script always ends itself, with its summary, before the Go deadline.
_noo_dk() {
  _noo_s2="$1"; shift
  _noo_rem=$((_noo_budget - SECONDS))
  [ "$_noo_rem" -lt "$_noo_s2" ] && _noo_s2="$_noo_rem"
  [ "$_noo_s2" -lt 1 ] && _noo_s2=1
  _noo_bound "$_noo_s2" docker "$@"
}
_noo_skip() {
  echo "boot-restore: Docker did not answer for container $1 within ${2}s ($3); it was left alone" >&2
  skipped="${skipped:+$skipped, }$1"
}
# docker start, bounded. A start that times out may only be slow (a large
# image, a cold disk): ask once what the container is doing. Running counts as
# started; not running gets one more bounded start. Returns 0 started, 1 start
# failed (as before), 9 Docker did not answer (left alone).
_noo_running() { _noo_rs="$(_noo_dk "$_noo_t_inspect" inspect -f '{{.State.Running}}' "$1" 2>/dev/null)"; _noo_rr=$?; }
_noo_start() {
  _noo_dk "$_noo_t_start" start "$1" >/dev/null; _noo_sr=$?
  if ! _noo_wedged "$_noo_sr"; then [ "$_noo_sr" = 0 ]; return; fi
  _noo_running "$1"
  _noo_wedged "$_noo_rr" && return 9
  if [ "$_noo_rs" = true ]; then echo "boot-restore: container $1 was slow to start (over ${_noo_t_start}s) and is running" >&2; return 0; fi
  _noo_dk "$_noo_t_start" start "$1" >/dev/null; _noo_sr=$?
  if ! _noo_wedged "$_noo_sr"; then [ "$_noo_sr" = 0 ]; return; fi
  _noo_running "$1"
  if ! _noo_wedged "$_noo_rr" && [ "$_noo_rs" = true ]; then echo "boot-restore: container $1 was slow to start (over ${_noo_t_start}s) and is running" >&2; return 0; fi
  return 9
}
# The list. dockerd may still be starting after a power cut (it then refuses
# the connection at once), so ANY failure of the list, a timeout or a fast
# error, means "Docker did not answer yet" and is retried, bounded each time,
# for the list window. Only a zero status with an empty answer means "no
# containers". Giving up is NOT a success and is not retried by the caller (the
# secret files are written by now, so a second pass would say "nothing to
# do"): it exits 4, the WARN path.
_noo_try=1
while :; do
  ids="$(_noo_dk "$_noo_t_list" ps -aq --filter status=created --filter status=exited)"; rc=$?
  [ "$rc" = 0 ] && break
  if [ "$SECONDS" -ge "$_noo_t_listwindow" ] || [ "$SECONDS" -ge "$_noo_budget" ]; then
    echo "boot-restore: Docker did not answer the container list (exit $rc, $_noo_try tries over ${SECONDS}s); the secret files are written but NO container was started" >&2
    exit 4
  fi
  echo "boot-restore: Docker did not answer the container list (exit $rc, try $_noo_try, ${SECONDS}s of ${_noo_t_listwindow}s); retrying" >&2
  sleep "$_noo_t_listwait"; _noo_try=$((_noo_try+1))
done
for id in $ids; do
  if [ "$SECONDS" -ge "$((_noo_budget - 5))" ]; then
    echo "boot-restore: out of time ($SECONDS s of ${_noo_budget}s); containers from $id on were not handled" >&2
    skipped="${skipped:+$skipped, }$id and the rest (out of time)"
    break
  fi
  want=""
  mounts="$(_noo_dk "$_noo_t_inspect" inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2>/dev/null)"; rc=$?
  if _noo_wedged "$rc"; then _noo_skip "$id" "$_noo_t_inspect" "docker inspect"; continue; fi
  if printf '%%s\n' "$mounts" | grep -q "^$d/"; then
    want=1
  else
    meta="$(_noo_dk "$_noo_t_inspect" inspect -f '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "noo.managed-by"}}|{{.HostConfig.RestartPolicy.Name}}' "$id" 2>/dev/null)"; rc=$?
    if _noo_wedged "$rc"; then _noo_skip "$id" "$_noo_t_inspect" "docker inspect"; continue; fi
    p="$(echo "$meta" | cut -d'|' -f1)"; svc="$(echo "$meta" | cut -d'|' -f2)"
    mby="$(echo "$meta" | cut -d'|' -f3)"; rp="$(echo "$meta" | cut -d'|' -f4)"
    if [ -n "$proj" ] && [ "$p" = "$proj" ] && [ -z "$mby" ] && [ -n "$svc" ] && [ "$rp" != "no" ] && [ -n "$rp" ]; then
      case "$core" in *" $svc "*) want=1 ;; esac
    fi
  fi
  [ -n "$want" ] || continue
  _noo_start "$id"; rc=$?
  if [ "$rc" = 9 ]; then _noo_skip "$id" "$_noo_t_start" "docker start"; continue; fi
  [ "$rc" = 0 ] && n=$((n+1))
  run="$(_noo_dk "$_noo_t_inspect" inspect -f '{{.State.Running}}' "$id" 2>/dev/null)"; rc=$?
  if _noo_wedged "$rc"; then _noo_skip "$id" "$_noo_t_inspect" "docker inspect"; continue; fi
  if [ "$run" != "true" ]; then
    st="$(_noo_dk "$_noo_t_inspect" inspect -f '{{.Name}}|{{.State.Status}} {{.State.ExitCode}} {{.State.FinishedAt}}' "$id" 2>/dev/null)"; rc=$?
    if _noo_wedged "$rc"; then _noo_skip "$id" "$_noo_t_inspect" "docker inspect"; continue; fi
    nm="$(echo "$st" | cut -d'|' -f1)"; nm="${nm#/}"; info="$(echo "$st" | cut -d'|' -f2)"
    hhmm="$(echo "${info##*T}" | cut -c1-5)"
    info="$(echo "$info" | cut -d' ' -f1,2)"
    down="${down:+$down, }${nm:-$id} ($info${hhmm:+ $hhmm})"
  fi
done
# The containers that join another's network namespace (noo-ollama-embed
# joins noo-stunnel-ollama-embed): dockerd's restore may start them before
# their door and never retries them. The same script noo-netns-restore.service
# runs at every dockerd start; here it covers a host without systemd.
if [ -f "$root/scripts/noo-netns-restore.sh" ]; then
  # Bound: its own, or what is left of the script budget, so the pass ends
  # before the overall deadline in every path (no orphan outlives it).
  _noo_nbound="$_noo_t_netns"; _noo_left=$((_noo_budget - SECONDS))
  [ "$_noo_left" -lt "$_noo_nbound" ] && _noo_nbound="$_noo_left"
  if [ "$_noo_nbound" -lt 1 ]; then
    echo "boot-restore: no time left for the namespace restore; it was not run" >&2
    skipped="${skipped:+$skipped, }the namespace restore (out of time)"
  else
    _noo_bound "$_noo_nbound" bash "$root/scripts/noo-netns-restore.sh" || echo "boot-restore: the namespace restore reported a problem (above)" >&2
  fi
fi
echo "boot-restore: wrote the secret files and started $n container(s)"
if [ -n "$down" ] || [ -n "$skipped" ]; then
  echo "boot-restore: started $n${down:+; still down: $down}${skipped:+; not handled (left alone): $skipped}" >&2
  exit 4
fi
`

// The bounds on boot-restore's Docker calls. Variables, not constants, only so
// a test can shrink them; nothing reads them from the environment.
var (
	// bootListBound: one `docker ps` (the container list). Docker answers it in
	// milliseconds when healthy.
	bootListBound = 20 * time.Second
	// bootListWindow / bootListWait: dockerd may need minutes after a power cut
	// (and BootRestore runs once, with no timer), so a list that fails or does
	// not answer is retried every bootListWait for about ten minutes before the
	// run gives up (exit 4, a WARN, not a success).
	bootListWindow = 10 * time.Minute
	bootListWait   = 15 * time.Second
	// bootInspectBound: one `docker inspect`, per container. A miss skips that
	// container (named in the log) and the rest are still handled.
	bootInspectBound = 15 * time.Second
	// bootStartBound: one `docker start`. A healthy start can be slow (GPU
	// runtime init, a large image, a cold disk), so this is generous; a start
	// that times out is followed by a bounded look at whether it is running.
	bootStartBound = 180 * time.Second
	// bootNetnsBound: the namespace-restore pass (it waits up to 60 s for docker
	// and 60 s per door by its own design). Capped at what is left of the
	// script budget, so it always ends before bootOverall.
	bootNetnsBound = 150 * time.Second
	// bootOverall: the Go-side backstop for the whole run, held under the
	// compose lock: the 10 min list window plus 15 min for the container pass
	// (the pass has its full time after a long wait) = 25 min. The script
	// keeps its own budget (scriptBudget: 60 s less), clamps every call to what
	// is left of it and stops starting containers near it, so it ends itself,
	// with its summary, before this fires. On expiry the shell is killed (not a
	// process group; each child carries its own bound) and the lock released.
	bootOverall = 25 * time.Minute
)

// scriptBudget is the part of the overall deadline the script may spend:
// 60 s less (at least half). Every call is clamped to the budget that is left
// (at least 1 s), so after the budget only the few 1 s calls of the container
// in hand and the summary remain, which fit in the 60 s.
func scriptBudget(overall time.Duration) int {
	b := overall - 60*time.Second
	if b < overall/2 {
		b = overall / 2
	}
	return secs(b)
}

func secs(d time.Duration) int { return int(d / time.Second) }

// BootRestore runs the step once, retrying while docker is not up yet (this
// unit is ordered after docker.service, but on WSL2 and SysV hosts that is
// best-effort). Controller mode only.
func (e *Engine) BootRestore(ctx context.Context) {
	if e.Mode == ModeWorker {
		return
	}
	// i10a: the script also sources lib-state-volume.sh beside lib-secrets.sh:
	// a reboot whose TPM unlock failed leaves the state volume closed, and
	// starting the stack then would run it on an empty directory.
	//
	// `exec 1>&2` first: the Runner keeps only stderr, and the script's stdout
	// (`started N container(s)`, `populated; nothing to do`) is what says what
	// it did, so it must reach the log too (i301 a).
	script := "exec 1>&2\n" + fmt.Sprintf(bootRestoreScript, shellQuote(filepath.Join(e.Root, "scripts", "lib-secrets.sh")),
		secs(bootListBound), secs(bootInspectBound), secs(bootStartBound), secs(bootNetnsBound),
		secs(bootListWindow), secs(bootListWait), scriptBudget(bootOverall))
	for attempt := 1; attempt <= 12; attempt++ {
		unlock, err := acquireComposeLock(ctx)
		if err != nil {
			return
		}
		runCtx, cancel := context.WithTimeout(ctx, bootOverall)
		rc, stderr := e.Runner.Run(runCtx, e.Root, nil, "bash", "-c", script)
		timedOut := runCtx.Err() == context.DeadlineExceeded
		cancel()
		unlock()
		if timedOut {
			// Not retried: the secret files may already be written, so another
			// pass would say "nothing to do" and hide the containers not started.
			e.logf("BOOT-RESTORE WARN: the run did not finish within %s and was stopped (the compose lock is released; Docker may be wedged on a container): %s (run `noo stack restart` to bring the controller up; `noo stack start` if that does not)", bootOverall, strings.TrimSpace(stderr))
			return
		}
		if rc == 0 {
			e.logf("boot-restore: done")
			if w := strings.TrimSpace(stderr); w != "" {
				e.logf("%s", w)
			}
			return
		}
		if rc == 4 {
			// Done, but a core service is still down. Not retried: the secret
			// files now exist, so another pass would report "nothing to do".
			// i1184: restart first. It rewrites the secret files and starts
			// the stopped containers without contacting a registry, so it
			// works while the network is still coming up; start second.
			e.logf("BOOT-RESTORE WARN: %s (run `noo stack restart` to bring the controller up; `noo stack start` if that does not)", strings.TrimSpace(stderr))
			return
		}
		e.logf("BOOT-RESTORE attempt %d failed (exit %d): %s", attempt, rc, strings.TrimSpace(stderr))
		if rc == 2 {
			return // no launcher library in this tree: nothing to restore with
		}
		sleepCtx(ctx, 10*time.Second)
	}
	// A key sealed to the TPM (i10a) that did not unseal fails every attempt
	// the same way; lib-secrets.sh names the unit in the stderr above.
	e.logf("BOOT-RESTORE gave up: run `noo stack restart` to rewrite the secret files, `noo stack start` if that does not (age key sealed to the TPM? systemctl status noo-unseal.service; a data-root refusal says why in .noo-data-root-refused)")
}
