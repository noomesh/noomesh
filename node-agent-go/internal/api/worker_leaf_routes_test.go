// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"testing"
)

// noo-worker presents its own service leaf (CN=worker,
// O=Mesh Cluster Service), no longer the controller's gateway leaf. These
// are the node-agent routes the worker's Python ever named — the disk-scan
// detectors (/cleanup/*, heartbeat.py) and the sandbox/browser container
// runners (/api/skills/run, /api/containers/*). All are ControllerOnly: the
// worker's leaf is refused with a 403 (and a WARN naming cert_cn=worker on
// the node), never served, and the controller's leaf — the gateway, which
// runs disk_cleanup natively — still reaches each one. No node-agent change
// ships with this: nothing here needs `upgrade-agents`.

var workerNamedRoutes = []struct{ method, path string }{
	{"POST", "/cleanup/images"},
	{"POST", "/cleanup/logs"},
	{"POST", "/api/skills/run"},
	{"POST", "/api/containers/start"},
	{"POST", "/api/containers/stop"},
}

func TestTheWorkerLeafIsRefusedEveryRouteItNamed(t *testing.T) {
	h := identifyingMux(t)
	worker := testLeaf(t, "worker", "Mesh Cluster Service")
	for _, c := range workerNamedRoutes {
		if got := callAs(t, h, c.method, c.path, worker); got != http.StatusForbidden {
			t.Errorf("%s %s: the worker's own leaf must be refused loudly (403), got %d", c.method, c.path, got)
		}
	}
	// And it gets no /metrics either: only the scraper's service leaf does.
	if got := callAs(t, h, "GET", "/metrics", worker); got != http.StatusForbidden {
		t.Errorf("GET /metrics: a non-scraper service leaf must be refused, got %d", got)
	}
}

func TestTheControllerLeafStillReachesTheScanRoutes(t *testing.T) {
	h := identifyingMux(t)
	ctrl := testLeaf(t, "host8", "Mesh Cluster Gateway")
	for _, c := range workerNamedRoutes {
		// No Docker in this harness: the handler fails on its own terms or
		// panics (reported as `reached`). 403 is the one wrong answer.
		if got := callAs(t, h, c.method, c.path, ctrl); got == http.StatusForbidden {
			t.Errorf("%s %s: the controller (the gateway's disk_cleanup) must reach it", c.method, c.path)
		}
	}
}
