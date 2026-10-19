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
// does not bind a secret file is never touched. A directory that EXISTS means
// the files are there (a hostd restart, not a reboot) and the step does nothing,
// so a service an operator stopped by hand stays stopped.

const bootRestoreScript = `. %s 2>/dev/null || { echo "boot-restore: cannot source lib-secrets.sh" >&2; exit 2; }
d="$(secret_rundir)"
if [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
  echo "boot-restore: $d is populated; nothing to do"
  exit 0
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
	e.logf("BOOT-RESTORE gave up: run `noo stack start` to rewrite the secret files")
}
