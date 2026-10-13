// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// executeFetchBundle collects the bundle the controller staged, now, instead
// of waiting for the node's 60s noo-fetch timer.
//
// This is the node half of "stage and poke", the shape that
// replaces controller→node SSH. It rides the ordinary job rail
// (`tasks.dispatch.<node>`) rather than an inbound HTTP call, and that choice
// is the whole point:
//
//   - JetStream HOLDS the job while a node is offline. An inbound poke to a
//     node that is down is simply lost, and "down" is a normal state during
//     the reboots a config change causes.
//   - The node's NATS connection is OUTBOUND. It crosses NAT and survives a
//     tailnet flap, where a gateway → node:8081 dial does not.
//   - Retry, backoff and the reaper already exist here. An HTTP poke would
//     have had none of them.
//
// TIMING CROSSES THE WIRE, NEVER CONTENT. The payload is ignored — deliberately
// and completely. The bundle is already staged at the gateway and signed by
// the cluster CA; noo-apply verifies that signature and refuses anything else.
// A URL or a digest taken from this job would be content arriving from the
// network side, which is the one thing this design does not accept. That is
// also why the hostd op takes no arguments.
//
// The privileged half is noo-hostd's `fetch-bundle` op: this process is
// unprivileged and cannot run the fetch itself, so it
// stages a spool command for the root daemon's fixed op table.
//
// A failure here is a SLOWER delivery, not a lost one — the 60s timer is the
// real delivery mechanism and it is unaffected. Every return path says so,
// because "failed" for a bundle that lands 40 seconds later is the false
// negative that gets a real one ignored.
func (e *Executor) executeFetchBundle() (any, error) {
	const timerNote = "the 60s noo-fetch timer will still collect the staged bundle"

	// Refuse BEFORE queueing when no daemon would claim it: a command file
	// nothing consumes leaves the caller believing a fetch is coming. Same
	// guard, same reason, as the (retired) swap-agent producer had.
	hb, err := hostd.ReadHeartbeat(hostd.WorkerSpoolDir)
	if err != nil {
		return map[string]string{"status": "skipped", "reason": "no worker hostd heartbeat", "note": timerNote}, nil
	}
	if hb.Stale(time.Now().UTC()) {
		return map[string]string{"status": "skipped", "reason": "worker hostd heartbeat is stale", "note": timerNote}, nil
	}
	if !hb.Supports("fetch-bundle") {
		return map[string]string{
			"status": "skipped",
			"reason": fmt.Sprintf("hostd does not support fetch-bundle (ops: %s)", strings.Join(hb.Ops, ", ")),
			"note":   timerNote,
		}, nil
	}

	// Timestamped so serial fetches never collide on result files — the
	// daemon claims by rename, and a duplicate name would shadow an earlier
	// result (the same reason the retired swap-agent stamped its name).
	name := fmt.Sprintf("fetch-%d", time.Now().UTC().Unix())
	cmd := hostd.Command{
		Op:          "fetch-bundle",
		Service:     "noo-node-agent",
		RequestedBy: "node-agent:job/fetch_bundle",
	}
	if err := hostd.WriteCommand(hostd.WorkerSpoolDir, name, cmd); err != nil {
		slog.Error("fetch_bundle: could not queue the fetch", "error", err)
		return nil, fmt.Errorf("could not queue a fetch (%s): %w", timerNote, err)
	}
	slog.Info("fetch-bundle queued", "command", name, "spool", hostd.WorkerSpoolDir)
	return map[string]string{"status": "queued", "command": name}, nil
}
