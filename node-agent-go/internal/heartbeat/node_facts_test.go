// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"runtime"
	"testing"
)

// i300 F5b: `os` is always reported; every other node-workload key comes from
// the provider and is omitted when the provider does not return it.
func TestHeartbeatReportsOSAlwaysAndOmitsUnknownNodeFacts(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	node := []string{"gpu_compute_cap", "nvidia_runtime", "nvidia_driver_caps_ok", "controller_host",
		"data_root_free_gb", "addon_workloads_policy", "addon_workloads_approvals", "node_workloads"}

	// Not wired: os is there, nothing else is.
	r.SendHeartbeat()
	beat := cap.last(&cap.beats)
	if beat["os"] != runtime.GOOS {
		t.Fatalf("os = %v, want %s", beat["os"], runtime.GOOS)
	}
	for _, k := range node {
		if _, ok := beat[k]; ok {
			t.Errorf("an unwired reporter sent %s", k)
		}
	}

	// Wired, and the provider knows only some of it.
	r.SetNodeFacts(func() map[string]any {
		return map[string]any{"addon_workloads_policy": "none", "controller_host": false}
	})
	r.SendHeartbeat()
	beat = cap.last(&cap.beats)
	if beat["addon_workloads_policy"] != "none" || beat["controller_host"] != false || beat["os"] != runtime.GOOS {
		t.Fatalf("beat = %v", beat)
	}
	for _, k := range []string{"gpu_compute_cap", "nvidia_runtime", "nvidia_driver_caps_ok", "data_root_free_gb", "addon_workloads_approvals", "node_workloads"} {
		if _, ok := beat[k]; ok {
			t.Errorf("%s was sent although the provider did not know it", k)
		}
	}

	// A provider that knows nothing: os alone.
	r.SetNodeFacts(func() map[string]any { return nil })
	r.SendHeartbeat()
	beat = cap.last(&cap.beats)
	if beat["os"] != runtime.GOOS {
		t.Fatalf("os missing when the provider knows nothing: %v", beat)
	}
	if _, ok := beat["addon_workloads_policy"]; ok {
		t.Fatal("policy lingered after the provider stopped returning it")
	}
}

// The rows ride with the contract's exact key names and shapes.
func TestHeartbeatNodeWorkloadRowShape(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })
	type row struct {
		Addon       string `json:"addon"`
		Name        string `json:"name"`
		State       string `json:"state"`
		Ready       bool   `json:"ready"`
		Model       string `json:"model,omitempty"`
		DoorPort    int    `json:"door_port"`
		Reservation string `json:"reservation,omitempty"`
		Reason      string `json:"reason,omitempty"`
	}
	r.SetNodeFacts(func() map[string]any {
		return map[string]any{"node_workloads": []row{
			{Addon: "rhaddon", Name: "worker", State: "running", Ready: true, Model: "rh-s2s-7b", DoorPort: 8443, Reservation: "0b1f5f0e-6a3e-4a54-9d3c-0a4e5b9c7d21"},
			{Addon: "rhaddon", Name: "echo", State: "provisioned", DoorPort: 8443},
		}}
	})
	r.SendHeartbeat()
	rows, _ := cap.last(&cap.beats)["node_workloads"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	b := rows[1].(map[string]any)
	if len(b) != 5 || b["ready"] != false || b["door_port"] != float64(8443) {
		t.Fatalf("echo row = %v (model, slots, reservation and reason must be omitted, ready and door_port always present)", b)
	}
}
