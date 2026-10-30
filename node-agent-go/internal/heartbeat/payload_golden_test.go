// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// capturePayloads runs one heartbeat and one registration against a bare
// reporter and returns the JSON object each one put on the wire.
func capturePayloads(t *testing.T) (beat, reg map[string]any) {
	t.Helper()
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = nil
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer server.Close()
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	t.Setenv("NOO_BIND_ADDR", "")
	t.Setenv("NODE_LOCATION", "")
	r := newTestReporter(t, server.URL, nil)
	r.Register(hardware.Capabilities{CPUCores: 1}, "192.168.1.10")
	reg = got
	r.SendHeartbeat()
	beat = got
	return beat, reg
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		// stunnel_image is process-global with no reset hook and is pinned by
		// its own test; whether an earlier test set it must not matter here.
		if k == "stunnel_image" {
			continue
		}
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// The wire contract, frozen: the exact key set of a bare reporter's
// heartbeat and registration. Sections moved from one hand-built map into a
// shared list; this fails if a key appears, vanishes or is renamed.
func TestPayloadGolden_KeySets(t *testing.T) {
	beat, reg := capturePayloads(t)
	wantBeat := []string{"active_jobs", "active_sensors", "app_version", "available_models", "backend_leaves", "battery_pct", "bind_addr", "capabilities", "control_transports", "controller_leaf_only", "cpu_cores", "cpu_load", "data_roots", "gpu_model", "image_source_mode", "is_charging", "legacy_lanes", "load", "location", "mem_used_gb", "model_presence", "network_type", "peer_identity_enforced", "power_source", "ram_gb", "reconcile_refusals", "running_backends", "self_node", "thermal_state", "tier", "vram_gb", "vram_used_gb"}
	wantReg := []string{"agent_url", "app_version", "backend_leaves", "capabilities", "control_transports", "controller_leaf_only", "data_roots", "hostname", "image_source_mode", "ip_address", "legacy_lanes", "model_presence", "node_id", "peer_identity_enforced"}
	if got := sortedKeys(beat); !reflect.DeepEqual(got, wantBeat) {
		t.Errorf("heartbeat keys changed:\n got %v\nwant %v", got, wantBeat)
	}
	if got := sortedKeys(reg); !reflect.DeepEqual(got, wantReg) {
		t.Errorf("registration keys changed:\n got %v\nwant %v", got, wantReg)
	}
}

// Keys that are ALWAYS sent keep their zero shapes: absence reads as "an
// agent too old to report" to the gateway, so an empty value must stay an
// empty value, never an omitted key.
func TestPayloadGolden_ZeroShapes(t *testing.T) {
	beat, reg := capturePayloads(t)
	for name, p := range map[string]map[string]any{"heartbeat": beat, "registration": reg} {
		for _, k := range []string{"backend_leaves", "data_roots", "model_presence", "legacy_lanes", "control_transports"} {
			if _, ok := p[k].(map[string]any); !ok {
				t.Errorf("%s: %s must be a JSON object, got %#v", name, k, p[k])
			}
		}
		for _, k := range []string{"peer_identity_enforced", "controller_leaf_only"} {
			if _, ok := p[k].(bool); !ok {
				t.Errorf("%s: %s must be a bool, got %#v", name, k, p[k])
			}
		}
	}
	rr, ok := beat["reconcile_refusals"].([]any)
	if !ok || len(rr) != 0 {
		t.Errorf("reconcile_refusals must be an EMPTY LIST, always sent: %#v", beat["reconcile_refusals"])
	}
	ll := beat["legacy_lanes"].(map[string]any)
	// whois_non_controller (a constant 0 reported as a measurement since
	// GET /tailnet/whois went behind ControllerOnly) and cluster_hmac_v1 (the
	// deleted v1 admission lane) are GONE from the shape on purpose: a lane
	// that cannot move is not evidence. cluster_hmac_v1_refused is the one
	// v1 signal, kept for one release so a stale caller is visible.
	if ll["static_token"] != float64(0) || ll["cluster_hmac_v1_refused"] != float64(0) {
		t.Errorf("legacy_lanes zero shape changed: %#v", ll)
	}
	for _, gone := range []string{"whois_non_controller", "cluster_hmac_v1"} {
		if _, ok := ll[gone]; ok {
			t.Errorf("legacy_lanes still reports the deleted lane %q: %#v", gone, ll)
		}
	}
	if _, ok := reg["reconcile_refusals"]; ok {
		t.Errorf("registration must not carry reconcile_refusals")
	}
}
