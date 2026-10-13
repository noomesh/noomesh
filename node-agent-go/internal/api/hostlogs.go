// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Host-service logs, for services that are NOT containers.
//
// `noo cluster logs <node> <name>` reaches a container through the agent.
// Two things on a node are not containers: the agent itself, which serves
// its own recent lines from an in-memory ring, and the HARNESS, whose output only the platform's log system holds.
//
// The harness is the case the ring cannot cover, for two reasons found the
// hard way on 2026-09-19. A ring inside a process dies with it, and the
// harness was crash-looping — the very failure you want the log for erases
// it. And the leading suspect was the dynamic linker, where the process
// dies before any of our code runs, so nothing the harness itself could
// buffer would ever exist.
//
// So the capture has to happen outside the process, which is what the
// platform already does:
//
//   - Linux: journald has it. Reading a system unit's journal needs
//     privilege the agent deliberately does not have,
//     and the access group covers every journal on the box rather than one
//     unit, so widening the agent is the wrong trade. It asks noo-hostd —
//     already root, already a closed op table — for the `unit-logs` op,
//     which names its unit from a fixed allowlist.
//   - darwin: the harness is a LaunchAgent whose plist already writes
//     stdout and stderr to a file, owned by the same user the agent runs
//     as. No daemon, no privilege, just read it.
//
// Nothing about journald is reimplemented. It already captures at the fd
// level, rotates and caps; a second log system of our own would do all
// three worse.
package api

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// HostServiceUnits maps the name a caller asks for to the unit behind it.
// The harness is the one that matters today; the others are here because
// an operator debugging a node reaches for them in the same breath.
var HostServiceUnits = map[string]string{
	"noo-harness":    "noo-harness",
	"noo-fetch":      "noo-fetch",
	"noo-hostd":      "noo-hostd",
	"noo-node-agent": "noo-node-agent",
}

// darwinLogFile is where a host service's plist sends stdout and stderr.
// Only the harness has one today; anything else returns "no file".
func darwinLogFile(name string) string {
	if name == "noo-harness" {
		return "/tmp/noomesh-harness.log"
	}
	return ""
}

// HostServiceLogs returns the last `tail` lines for a host service, and
// the source it came from, so a reader can tell a journal answer from a
// file answer without guessing.
func HostServiceLogs(ctx context.Context, name string, tail int) (lines []string, source string, err error) {
	unit, ok := HostServiceUnits[name]
	if !ok {
		return nil, "", fmt.Errorf("%q is not a host service this agent serves logs for", name)
	}
	if tail <= 0 {
		tail = 200
	}
	if runtime.GOOS == "darwin" {
		p := darwinLogFile(name)
		if p == "" {
			return nil, "", fmt.Errorf("no log file is configured for %s on darwin", name)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil, "", fmt.Errorf("cannot read %s: %w", p, rerr)
		}
		return lastLines(string(b), tail), "launchd stdout/stderr file " + p, nil
	}
	out, herr := logsViaHostd(ctx, unit, tail)
	if herr != nil {
		return nil, "", herr
	}
	return lastLines(out, tail), "journal via noo-hostd (unit " + unit + ")", nil
}

// logsViaHostd queues the read-only `unit-logs` op and waits for it.
//
// A daemon that is dead or too old is named as such rather than reported
// as "no logs": those are different facts and only one of them means the
// service has been quiet.
func logsViaHostd(ctx context.Context, unit string, tail int) (string, error) {
	hb, err := hostd.ReadHeartbeat(hostd.WorkerSpoolDir)
	if err != nil {
		return "", fmt.Errorf("the node's privileged helper (noo-hostd) is not running, so its journal cannot be read: %w", err)
	}
	if hb.Stale(time.Now().UTC()) {
		return "", fmt.Errorf("noo-hostd's heartbeat is stale (published %s) — logs cannot be read", hb.TS)
	}
	if !hb.Supports("unit-logs") {
		return "", fmt.Errorf("this node's noo-hostd predates the unit-logs op (serves [%s]); run `noo upgrade --nodes`",
			strings.Join(hb.Ops, " "))
	}
	name := fmt.Sprintf("unit-logs-%d", time.Now().UTC().UnixNano())
	if err := hostd.WriteCommand(hostd.WorkerSpoolDir, name, hostd.Command{
		Op:          "unit-logs",
		Service:     unit,
		Args:        []string{fmt.Sprintf("lines=%d", tail)},
		RequestedBy: "node-agent:api/host-logs",
	}); err != nil {
		return "", fmt.Errorf("could not queue the log read: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		res, rerr := hostd.ReadResult(hostd.WorkerSpoolDir, name)
		if rerr == nil {
			if res.RC != 0 {
				return "", fmt.Errorf("noo-hostd refused the log read: %s", strings.TrimSpace(res.Stderr))
			}
			return hostd.ReadLogOut(hostd.WorkerSpoolDir, name)
		}
		if !os.IsNotExist(rerr) {
			return "", fmt.Errorf("log result unreadable: %w", rerr)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("noo-hostd did not answer the log read within 30s")
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// lastLines keeps the final n non-empty-trailing lines.
func lastLines(s string, n int) []string {
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		return []string{}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}
