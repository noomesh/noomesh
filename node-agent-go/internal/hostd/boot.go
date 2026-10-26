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
// `docker start`s exactly the stopped containers that bind from that directory.
//
// Not a launcher: nothing is pulled, built or recreated, and a container that
// does not bind a secret file is never touched. When the install's state lives
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
n=0
for id in $(docker ps -aq --filter status=created --filter status=exited); do
  docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2>/dev/null | grep -q "^$d/" || continue
  docker start "$id" >/dev/null && n=$((n+1))
done
echo "boot-restore: wrote the secret files and started $n container(s)"
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
	script := fmt.Sprintf(bootRestoreScript, shellQuote(filepath.Join(e.Root, "scripts", "lib-secrets.sh")))
	for attempt := 1; attempt <= 12; attempt++ {
		unlock, err := acquireComposeLock(ctx)
		if err != nil {
			return
		}
		rc, stderr := e.Runner.Run(ctx, e.Root, nil, "bash", "-c", script)
		unlock()
		if rc == 0 {
			e.logf("boot-restore: done")
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
