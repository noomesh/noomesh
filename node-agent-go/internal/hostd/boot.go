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
for id in $(docker ps -aq --filter status=created --filter status=exited); do
  want=""
  if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2>/dev/null | grep -q "^$d/"; then
    want=1
  else
    meta="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "noo.managed-by"}}|{{.HostConfig.RestartPolicy.Name}}' "$id" 2>/dev/null)"
    p="$(echo "$meta" | cut -d'|' -f1)"; svc="$(echo "$meta" | cut -d'|' -f2)"
    mby="$(echo "$meta" | cut -d'|' -f3)"; rp="$(echo "$meta" | cut -d'|' -f4)"
    if [ -n "$proj" ] && [ "$p" = "$proj" ] && [ -z "$mby" ] && [ -n "$svc" ] && [ "$rp" != "no" ] && [ -n "$rp" ]; then
      case "$core" in *" $svc "*) want=1 ;; esac
    fi
  fi
  [ -n "$want" ] || continue
  docker start "$id" >/dev/null && n=$((n+1))
  if [ "$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null)" != "true" ]; then
    st="$(docker inspect -f '{{.Name}}|{{.State.Status}} {{.State.ExitCode}} {{.State.FinishedAt}}' "$id" 2>/dev/null)"
    nm="$(echo "$st" | cut -d'|' -f1)"; nm="${nm#/}"; info="$(echo "$st" | cut -d'|' -f2)"
    hhmm="$(echo "${info##*T}" | cut -c1-5)"
    info="$(echo "$info" | cut -d' ' -f1,2)"
    down="${down:+$down, }${nm:-$id} ($info${hhmm:+ $hhmm})"
  fi
done
echo "boot-restore: wrote the secret files and started $n container(s)"
if [ -n "$down" ]; then
  echo "boot-restore: started $n; still down: $down" >&2
  exit 4
fi
`

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
	script := "exec 1>&2\n" + fmt.Sprintf(bootRestoreScript, shellQuote(filepath.Join(e.Root, "scripts", "lib-secrets.sh")))
	for attempt := 1; attempt <= 12; attempt++ {
		unlock, err := acquireComposeLock(ctx)
		if err != nil {
			return
		}
		rc, stderr := e.Runner.Run(ctx, e.Root, nil, "bash", "-c", script)
		unlock()
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
			e.logf("BOOT-RESTORE WARN: %s (run `noo stack start` to bring the controller up)", strings.TrimSpace(stderr))
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
	e.logf("BOOT-RESTORE gave up: run `noo stack start` to rewrite the secret files (age key sealed to the TPM? systemctl status noo-unseal.service; a data-root refusal says why in .noo-data-root-refused)")
}
