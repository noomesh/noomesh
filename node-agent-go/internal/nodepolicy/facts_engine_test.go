// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"reflect"
	"testing"
)

// i1058: the docker_engine fact rides the heartbeat's node facts as the probe
// gave it, each state as itself; an unwired probe (no Docker client built)
// sends no key, which the controller reads as an agent that predates it.
func TestReportCarriesDockerEngine(t *testing.T) {
	for _, eng := range []map[string]any{
		{"state": "ok", "version": "27.5.1", "kind": "dockerd"},
		{"state": "none"},
		{"state": "unreadable", "error": "Cannot connect to the Docker daemon"},
	} {
		f := &Facts{Mode: ModeNone, DockerEngine: func(context.Context) map[string]any { return eng }}
		got, ok := f.Report(context.Background())["docker_engine"]
		if !ok || !reflect.DeepEqual(got, eng) {
			t.Errorf("docker_engine = %v (sent %v), want %v", got, ok, eng)
		}
	}
	if _, ok := (&Facts{Mode: ModeNone}).Report(context.Background())["docker_engine"]; ok {
		t.Error("an unwired probe sent docker_engine")
	}
}
