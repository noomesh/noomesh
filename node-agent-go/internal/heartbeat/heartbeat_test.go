// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/sidecarimage"
)

func newTestReporter(t *testing.T, serverURL string, cfg *config.Config) *Reporter {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{
			NodeID:        "test-node",
			ControllerURL: serverURL,
			Tier:          3,
		}
	} else {
		cfg.ControllerURL = serverURL
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := metrics.NewCollector(gpu)
	return NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() map[string]string { return map[string]string{} },
		func() int { return 0 },
	)
}

func TestReporter_Register(t *testing.T) {
	var registered atomic.Bool
	var receivedBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/register" && r.Method == "POST" {
			registered.Store(true)
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, &config.Config{
		NodeID: "test-node",
		Tier:   2,
	})

	caps := hardware.Capabilities{CPUCores: 8, RAMGB: 32, Tier: 2}
	ok := rpt.Register(caps, "192.168.1.10")

	if !ok {
		t.Error("registration should succeed")
	}
	if !registered.Load() {
		t.Error("server should have received registration")
	}
	if _, ok := receivedBody["backend_leaves"].(map[string]any); !ok {
		t.Errorf("registration must carry backend_leaves (a map, {} when none): %#v", receivedBody["backend_leaves"])
	}
	if receivedBody["node_id"] != "test-node" {
		t.Errorf("expected node_id 'test-node', got %v", receivedBody["node_id"])
	}
}

func TestReporter_Heartbeat(t *testing.T) {
	var heartbeatCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/test-node/heartbeat" {
			heartbeatCount.Add(1)
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SendHeartbeat()

	if heartbeatCount.Load() != 1 {
		t.Errorf("expected 1 heartbeat, got %d", heartbeatCount.Load())
	}
}

func TestReporter_Heartbeat404_ReRegisters(t *testing.T) {
	var registerCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/cluster/nodes/test-node/heartbeat":
			w.WriteHeader(404) // node not found → triggers re-registration
		case r.URL.Path == "/api/cluster/nodes/register":
			registerCalls.Add(1)
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SendHeartbeat()

	if registerCalls.Load() != 1 {
		t.Errorf("expected 1 re-registration after 404, got %d", registerCalls.Load())
	}
}

func TestReporter_HeartbeatPayload(t *testing.T) {
	var payload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/test-node/heartbeat" {
			json.NewDecoder(r.Body).Decode(&payload)
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	cfg := &config.Config{
		NodeID:   "test-node",
		Tier:     2,
		VRAMGB:   24.0,
		GPUModel: "RTX 4090",
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := metrics.NewCollector(gpu)
	rpt := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() map[string]string { return map[string]string{"vllm": "Qwen/Qwen3-8B"} },
		func() int { return 3 },
	)
	rpt.cfg.ControllerURL = server.URL

	rpt.SendHeartbeat()

	if payload["tier"] != float64(2) {
		t.Errorf("expected tier 2, got %v", payload["tier"])
	}
	if payload["active_jobs"] != float64(3) {
		t.Errorf("expected 3 active jobs, got %v", payload["active_jobs"])
	}
	if payload["gpu_model"] != "RTX 4090" {
		t.Errorf("expected gpu_model 'RTX 4090', got %v", payload["gpu_model"])
	}
	if payload["vram_gb"] != float64(24.0) {
		t.Errorf("expected vram_gb 24.0, got %v", payload["vram_gb"])
	}

	backends, ok := payload["running_backends"].(map[string]any)
	if !ok {
		t.Errorf("running_backends should be a map, got %T", payload["running_backends"])
	} else if backends["vllm"] != "Qwen/Qwen3-8B" {
		t.Errorf("expected vllm backend, got %v", backends)
	}

	load, ok := payload["load"].(float64)
	if !ok {
		t.Error("load should be a float64")
	} else if load < 0 || load > 1 {
		t.Errorf("load should be 0-1, got %f", load)
	}
}

func TestReporter_AuthHeader(t *testing.T) {
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &config.Config{
		NodeID:        "test-node",
		ClusterSecret: "my-secret",
		Tier:          3,
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := metrics.NewCollector(gpu)
	rpt := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() map[string]string { return map[string]string{} },
		func() int { return 0 },
	)
	rpt.cfg.ControllerURL = server.URL

	rpt.SendHeartbeat()

	if authHeader == "" {
		t.Error("expected Authorization header when cluster secret is set")
	}
	if len(authHeader) < 20 {
		t.Errorf("auth header seems too short: %q", authHeader)
	}
}

func TestDetectHostIP_FromEnv(t *testing.T) {
	cfg := &config.Config{NodeIP: "10.0.0.42"}
	got := DetectHostIP(cfg)
	if got != "10.0.0.42" {
		t.Errorf("expected NODE_IP value, got %q", got)
	}
}

// The contract used to be "never empty", which is what forced a loopback
// out when nothing better existed. It is now "never undialable": empty is
// the honest answer when the host cannot be reached at anything, and the
// caller omits the field so the controller keeps the last good address.
func TestDetectHostIP_Fallback_NeverReturnsAnUndialableAddress(t *testing.T) {
	cfg := &config.Config{
		NodeIP:        "",
		ControllerURL: "https://unreachable-host:8080",
	}
	got := DetectHostIP(cfg)
	if got == "" {
		return // no dialable address on this box: correct, and what host3 should have said
	}
	ip := net.ParseIP(got)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		t.Errorf("DetectHostIP returned an address the controller cannot dial: %q", got)
	}
}

func TestUsableHostIP(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"debian hostname line only", []string{"127.0.1.1"}, ""},
		{"loopback then tailnet", []string{"127.0.1.1", "100.64.0.1"}, "100.64.0.1"},
		{"link-local skipped", []string{"169.254.1.2", "192.0.2.10"}, "192.0.2.10"},
		{"unspecified skipped", []string{"0.0.0.0", "::", "10.0.0.42"}, "10.0.0.42"},
		{"garbage is not an address", []string{"HOST3", "not-an-ip"}, ""},
		{"nothing", nil, ""},
		{"v6 loopback then routable", []string{"::1", "2001:db8::1"}, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := usableHostIP(c.in); got != c.want {
			t.Errorf("%s: usableHostIP(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestAgentURL_IsEmptyWhenNoAddressIsDialable(t *testing.T) {
	cfg := &config.Config{NodeIP: "", ControllerURL: "https://unreachable-host:8080", AgentPort: 8081}
	if ip := DetectHostIP(cfg); ip == "" {
		if u := agentURL(cfg); u != "" {
			t.Errorf("no address, yet agentURL = %q — that would register https://:8081", u)
		}
	}
}

func TestReporter_RunCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &config.Config{
		NodeID:            "test-node",
		ControllerURL:     server.URL,
		HeartbeatInterval: 1,
		Tier:              3,
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := metrics.NewCollector(gpu)
	rpt := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() map[string]string { return map[string]string{} },
		func() int { return 0 },
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rpt.Run(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run exited cleanly after cancel
	case <-time.After(3 * time.Second):
		t.Error("Run did not exit after context cancellation")
	}
}

// A node that is HTTP-alive but bus-deaf used to be indistinguishable from a
// healthy one: the heartbeat kept last_seen fresh while jobs dispatched over
// NATS stranded. The heartbeat now carries the node's own view
// of its bus.
func TestReporter_HeartbeatCarriesNATSStatus(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SetBusStatus(func() any {
		return map[string]any{
			"state":              "reconnecting",
			"connected":          false,
			"job_dispatch_bound": false,
		}
	})
	rpt.SendHeartbeat()

	bus, ok := payload["nats_status"].(map[string]any)
	if !ok {
		t.Fatalf("nats_status missing from heartbeat: %v", payload["nats_status"])
	}
	if bus["state"] != "reconnecting" {
		t.Errorf("state = %v, want reconnecting", bus["state"])
	}
	if bus["connected"] != false {
		t.Errorf("connected = %v, want false", bus["connected"])
	}
}

// An agent with no messaging subsystem — or an older agent binary — must
// OMIT the field. "Not reported" is a different answer from "reported as
// down", and the gateway must be able to tell them apart.
func TestReporter_HeartbeatOmitsNATSStatusWhenUnreported(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	newTestReporter(t, server.URL, nil).SendHeartbeat()

	if _, present := payload["nats_status"]; present {
		t.Errorf("nats_status must be absent, not null: got %v", payload["nats_status"])
	}
}

// An agent that does not report backend runtimes must OMIT the key, so the
// controller cannot read absence as "every backend is container-managed".
//
// That distinction is the whole point of the field. A docker-managed backend
// and a natively-adopted one look identical in running_backends — one word,
// two relationships — and only one of them can ever converge to a placement.
// Defaulting absence to "docker" would tell an operator their Mac placement
// is being reconciled when nothing is reconciling it.
func TestReporter_HeartbeatOmitsBackendRuntimesWhenUnreported(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	newTestReporter(t, server.URL, nil).SendHeartbeat()

	if _, present := payload["backend_runtimes"]; present {
		t.Errorf("backend_runtimes must be absent, not empty: got %v", payload["backend_runtimes"])
	}
}

// And an EMPTY map is absence too: a node running nothing has no runtimes to
// report, and sending {} would be a claim where there is no fact.
func TestReporter_HeartbeatOmitsEmptyBackendRuntimes(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	r := newTestReporter(t, server.URL, nil)
	r.SetBackendRuntimes(func() map[string]string { return map[string]string{} })
	r.SendHeartbeat()

	if _, present := payload["backend_runtimes"]; present {
		t.Errorf("an empty runtime map must be omitted: got %v", payload["backend_runtimes"])
	}
}

// When it IS reported it travels verbatim, so the controller can distinguish
// a backend it can converge from one it can only observe.
func TestReporter_HeartbeatCarriesBackendRuntimes(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	r := newTestReporter(t, server.URL, nil)
	r.SetBackendRuntimes(func() map[string]string {
		return map[string]string{"ollama": "native", "llamacpp": "docker"}
	})
	r.SendHeartbeat()

	rt, ok := payload["backend_runtimes"].(map[string]any)
	if !ok {
		t.Fatalf("backend_runtimes missing: %v", payload["backend_runtimes"])
	}
	if rt["ollama"] != "native" {
		t.Errorf("ollama runtime = %v, want native", rt["ollama"])
	}
	if rt["llamacpp"] != "docker" {
		t.Errorf("llamacpp runtime = %v, want docker", rt["llamacpp"])
	}
}

// A beat the controller refuses is a beat the controller did not get, and
// the agent must count it that way: the streak grows on every miss, and
// the first delivery afterwards clears it. Before this the failure path
// logged at DEBUG only — an agent could go silent for hours with nothing
// in its own log to say so.
func TestReporter_TracksDeliveryStreak(t *testing.T) {
	var refuse atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/nodes/test-node/heartbeat" {
			w.WriteHeader(404)
			return
		}
		if refuse.Load() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SendHeartbeat()
	if rpt.failStreak != 0 || !rpt.silentSince.IsZero() {
		t.Fatalf("delivered beat: streak=%d silentSince=%v, want clean", rpt.failStreak, rpt.silentSince)
	}

	refuse.Store(true)
	rpt.SendHeartbeat()
	rpt.SendHeartbeat()
	if rpt.failStreak != 2 || rpt.silentSince.IsZero() {
		t.Fatalf("two refused beats: streak=%d silentSince=%v", rpt.failStreak, rpt.silentSince)
	}

	// An unreachable controller is the same outage as a refusing one.
	server.Close()
	rpt.SendHeartbeat()
	if rpt.failStreak != 3 {
		t.Fatalf("connection refused: streak=%d, want 3", rpt.failStreak)
	}

	restored := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer restored.Close()
	rpt.cfg.ControllerURL = restored.URL
	rpt.SendHeartbeat()
	if rpt.failStreak != 0 || !rpt.silentSince.IsZero() {
		t.Fatalf("recovery: streak=%d silentSince=%v, want cleared", rpt.failStreak, rpt.silentSince)
	}
}

// The clock names the stage that spent the time — the only fact about a
// slow beat that the controller cannot see.
func TestStageClockNamesTheSlowestStage(t *testing.T) {
	clk := newStageClock()
	clk.mark("metrics")
	time.Sleep(30 * time.Millisecond)
	clk.mark("gpu_identity")
	clk.mark("post")
	if clk.slowest != "gpu_identity" {
		t.Fatalf("slowest=%q, want gpu_identity", clk.slowest)
	}
	if clk.slowestTook < 30*time.Millisecond || clk.total() < clk.slowestTook {
		t.Fatalf("slowestTook=%v total=%v", clk.slowestTook, clk.total())
	}
}

// The payload is what the controller believes. With no dialable address the
// fields must be ABSENT — not "", not a loopback — so the controller keeps the
// address it already has.
func TestSetDialableAddress(t *testing.T) {
	mk := func() map[string]any { return map[string]any{"ip_address": "stale", "agent_url": "stale", "load": 0.1} }

	p := mk()
	setDialableAddress(p, "", "")
	if _, ok := p["ip_address"]; ok {
		t.Error("no address known, yet ip_address was sent")
	}
	if _, ok := p["agent_url"]; ok {
		t.Error("no address known, yet agent_url was sent")
	}
	if _, ok := p["load"]; !ok {
		t.Error("unrelated fields must survive")
	}

	p = mk()
	setDialableAddress(p, "127.0.1.1", "https://127.0.1.1:8081")
	if _, ok := p["ip_address"]; ok {
		t.Error("a loopback reached the payload — the exact 2026-09-22 failure")
	}

	p = mk()
	setDialableAddress(p, "100.64.0.1", "https://100.64.0.1:8081")
	if p["ip_address"] != "100.64.0.1" || p["agent_url"] != "https://100.64.0.1:8081" {
		t.Errorf("a routable address must be sent as-is, got %v", p)
	}
}

// what an adopted server has loaded travels beside — never instead
// of — what it is placed to serve, and is omitted when nothing is loaded.
func TestReporter_HeartbeatCarriesLoadedModelsWhenReported(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/test-node/heartbeat" {
			json.NewDecoder(r.Body).Decode(&got)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SendHeartbeat()
	if _, present := got["loaded_models"]; present {
		t.Fatal("no reporter installed → key omitted")
	}

	rpt.SetLoadedModels(func() map[string]string { return map[string]string{} })
	rpt.SendHeartbeat()
	if _, present := got["loaded_models"]; present {
		t.Fatal("nothing loaded → key omitted, not an empty map")
	}

	rpt.SetLoadedModels(func() map[string]string { return map[string]string{"ollama": "harrier:latest"} })
	rpt.SendHeartbeat()
	lm, _ := got["loaded_models"].(map[string]any)
	if lm["ollama"] != "harrier:latest" {
		t.Fatalf("loaded_models must carry the loaded model, got %v", got["loaded_models"])
	}
}

// Every beat AND the registration carry `legacy_lanes`:
// every lane present, zeros included, plus the window it was counted over.
func TestReporter_HeartbeatCarriesLegacyLanes(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	r := newTestReporter(t, server.URL, nil)
	for _, send := range []func(){func() { r.SendHeartbeat() }, func() { r.Register(hardware.Capabilities{CPUCores: 1}, "192.168.1.10") }} {
		payload = nil
		send()
		ll, ok := payload["legacy_lanes"].(map[string]any)
		if !ok {
			t.Fatalf("legacy_lanes missing or not a map: %#v", payload["legacy_lanes"])
		}
		for _, k := range []string{"since_unix", "static_token", "cluster_hmac_v1_refused"} {
			if _, ok := ll[k].(float64); !ok {
				t.Fatalf("legacy_lanes.%s missing or not a number: %#v", k, ll)
			}
		}
	}
}

// Every beat AND the registration carry `controller_leaf_only`: the capability the gateway reads before it stops sending the
// static bearer to this node. A test reporter has no TLS material, so it
// reports false — the agent never claims a leaf check it cannot make.
func TestReporter_HeartbeatCarriesControllerLeafOnly(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	r := newTestReporter(t, server.URL, nil)
	for _, send := range []func(){func() { r.SendHeartbeat() }, func() { r.Register(hardware.Capabilities{CPUCores: 1}, "192.168.1.10") }} {
		payload = nil
		send()
		v, ok := payload["controller_leaf_only"].(bool)
		if !ok {
			t.Fatalf("controller_leaf_only missing or not a bool: %#v", payload["controller_leaf_only"])
		}
		if v != (r.cfg.TLSCert != "" && r.cfg.TLSKey != "" && r.cfg.TLSCA != "") {
			t.Fatalf("controller_leaf_only=%v does not match the agent's TLS posture", v)
		}
	}
}

// Every beat AND the registration carry `control_transports`: the HTTPS
// listener is on, the node-initiated transports are reserved and off.
func TestReporter_HeartbeatCarriesControlTransports(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	r := newTestReporter(t, server.URL, nil)
	for _, send := range []func(){func() { r.SendHeartbeat() }, func() { r.Register(hardware.Capabilities{CPUCores: 1}, "192.168.1.10") }} {
		payload = nil
		send()
		ct, ok := payload["control_transports"].(map[string]any)
		if !ok {
			t.Fatalf("control_transports missing or not an object: %#v", payload["control_transports"])
		}
		want := map[string]bool{"https_listener": true, "nats_rpc": false, "tunnel": false}
		if len(ct) != len(want) {
			t.Fatalf("control_transports has unexpected keys: %#v", ct)
		}
		for k, v := range want {
			if got, ok := ct[k].(bool); !ok || got != v {
				t.Fatalf("control_transports[%q]=%#v, want %v", k, ct[k], v)
			}
		}
	}
}

// Every beat carries `backend_leaves`, the map the CLI's
// `backend doors` row reads: present leaves with their SANs and expiry,
// and `{}` — never absent — when the node holds none.
func TestReporter_HeartbeatCarriesBackendLeaves(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	// Holds none: the key is there, and empty.
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	r := newTestReporter(t, server.URL, nil)
	r.SendHeartbeat()
	bl, ok := payload["backend_leaves"].(map[string]any)
	if !ok {
		t.Fatalf("backend_leaves missing or not a map: %#v", payload["backend_leaves"])
	}
	if len(bl) != 0 {
		t.Fatalf("backend_leaves = %v, want {} for a PKI dir with no services/", bl)
	}

	// Holds a vllm leaf: reported with the fields the CLI reads.
	dir := t.TempDir()
	notAfter := writeTestLeaf(t, dir, "vllm", []string{"vllm", "noo-vllm"})
	t.Setenv("NOO_PKI_DIR", dir)
	payload = nil
	r.SendHeartbeat()
	v, ok := payload["backend_leaves"].(map[string]any)["vllm"].(map[string]any)
	if !ok {
		t.Fatalf("backend_leaves.vllm missing: %#v", payload["backend_leaves"])
	}
	if dns, _ := v["dns"].([]any); len(dns) != 2 || dns[1] != "noo-vllm" {
		t.Errorf("backend_leaves.vllm.dns = %v", v["dns"])
	}
	if na, _ := v["not_after"].(float64); int64(na) != notAfter {
		t.Errorf("backend_leaves.vllm.not_after = %v, want %d", v["not_after"], notAfter)
	}
}

// `stunnel_image`: absent until a sidecar image has been
// chosen, then the LAST choice — "published" or "fallback-alpine" — on
// every beat and on registration.
func TestReporter_HeartbeatCarriesStunnelImage(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload = nil
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()
	r := newTestReporter(t, server.URL, nil)

	r.SendHeartbeat()
	if v, ok := payload["stunnel_image"]; ok {
		t.Fatalf("stunnel_image = %v before any sidecar start, want the key omitted", v)
	}

	sidecarimage.Chose("noomesh/stunnel:latest", false, nil)
	r.SendHeartbeat()
	if got := payload["stunnel_image"]; got != sidecarimage.Published {
		t.Errorf("heartbeat stunnel_image = %v, want %q", got, sidecarimage.Published)
	}

	sidecarimage.Chose("alpine:3.20", true, []string{"ghcr.io/x/stunnel:v1: not found"})
	r.SendHeartbeat()
	if got := payload["stunnel_image"]; got != sidecarimage.FallbackAlpine {
		t.Errorf("heartbeat stunnel_image = %v, want %q", got, sidecarimage.FallbackAlpine)
	}
	r.Register(hardware.Capabilities{CPUCores: 1, Tier: 2}, "192.168.1.10")
	if got := payload["stunnel_image"]; got != sidecarimage.FallbackAlpine {
		t.Errorf("registration stunnel_image = %v, want %q", got, sidecarimage.FallbackAlpine)
	}
}

// writeTestLeaf plants a self-signed services/<svc>/service.crt and returns
// its NotAfter (unix seconds). The heartbeat reports, it does not verify the
// chain, so a self-signed leaf is enough here; the CA-signed shapes are
// internal/backendleaves' tests.
func writeTestLeaf(t *testing.T, dir, svc string, dns []string) int64 {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: svc},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(dir, "services", svc)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "service.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return notAfter.Unix()
}

// on the controller's own node localhost:11434 is the
// stunnel-ollama-embed door (verify = 2), which the old bare probe cannot
// pass. With an adopted lane installed the inventory comes from the lane
// (dialled with the node leaf) and the bare loopback probe is not used.
func TestAvailableModelsAsksTheAdoptedLane(t *testing.T) {
	t.Setenv("MODELS_DIR", "")
	var bareProbed bool
	r := &Reporter{}
	r.SetAdoptedModels(func() []string { return []string{"harrier:latest", "gemma4:12b"} })
	r.SetOllamaDoor(func() string { bareProbed = true; return "" })
	got := r.availableModels()
	if len(got) != 2 || got[0] != "harrier:latest" || got[1] != "gemma4:12b" {
		t.Fatalf("inventory = %v, want the lane's models", got)
	}
	if !bareProbed {
		t.Fatal("the container door resolver must still be consulted")
	}
}

// `backend_containers` rides every beat and the
// registration when the provider is installed; the CLI's `backend doors`
// row reads a door miss on a fresh, health=starting container as
// `starting` only from it. Absent when not installed or unlistable.
func TestReporter_CarriesBackendContainers(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload = nil
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	r := newTestReporter(t, server.URL, nil)
	r.SendHeartbeat()
	if _, present := payload["backend_containers"]; present {
		t.Errorf("no provider: backend_containers must be absent, got %v", payload["backend_containers"])
	}
	r.SetBackendContainers(func() map[string]any { return nil })
	r.SendHeartbeat()
	if _, present := payload["backend_containers"]; present {
		t.Errorf("unlistable docker: backend_containers must be absent, got %v", payload["backend_containers"])
	}

	r.SetBackendContainers(func() map[string]any {
		return map[string]any{"vllm": map[string]any{"running": true, "started_at": int64(1_790_000_000), "health": "starting"}}
	})
	for _, send := range []func(){
		r.SendHeartbeat,
		func() { r.Register(hardware.Capabilities{Tier: 3}, "192.168.1.10") },
	} {
		send()
		v, ok := payload["backend_containers"].(map[string]any)["vllm"].(map[string]any)
		if !ok {
			t.Fatalf("backend_containers.vllm missing: %#v", payload["backend_containers"])
		}
		if v["started_at"] != float64(1_790_000_000) || v["health"] != "starting" {
			t.Errorf("backend_containers.vllm = %v", v)
		}
	}

	// `{}` is a report (nothing running), not an omission.
	r.SetBackendContainers(func() map[string]any { return map[string]any{} })
	r.SendHeartbeat()
	if bc, ok := payload["backend_containers"].(map[string]any); !ok || len(bc) != 0 {
		t.Errorf("an empty report must be sent as {}: %#v", payload["backend_containers"])
	}
}

// Every beat carries `model_presence`: `{}` when nothing was
// checked (the key's presence says "this agent reports it"), and the
// reconcile tick's per-backend verdict otherwise.
func TestReporter_HeartbeatCarriesModelPresence(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()
	modelpresence.Reset()
	t.Cleanup(modelpresence.Reset)

	r := newTestReporter(t, server.URL, nil)
	r.SendHeartbeat()
	if mp, ok := payload["model_presence"].(map[string]any); !ok || len(mp) != 0 {
		t.Fatalf("model_presence = %#v, want {}", payload["model_presence"])
	}
	modelpresence.Set("ollama", modelpresence.Entry{Model: "harrier", Role: "embed", Present: false, ImportOnly: true})
	payload = nil
	r.SendHeartbeat()
	e, ok := payload["model_presence"].(map[string]any)["ollama"].(map[string]any)
	if !ok || e["present"] != false || e["model"] != "harrier" || e["role"] != "embed" {
		t.Fatalf("model_presence.ollama = %#v", payload["model_presence"])
	}
}

// The shared-GPU yield's report rides every beat as `gpu_contention`, so a
// yielded node stays online and says why its GPU backend is gone.
func TestReporter_HeartbeatCarriesGPUContention(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer server.Close()

	rpt := newTestReporter(t, server.URL, nil)
	rpt.SendHeartbeat()
	if _, has := payload["gpu_contention"]; has {
		t.Fatal("no yield wired: gpu_contention must be omitted, not faked")
	}
	rpt.SetGPUContention(func() any {
		return map[string]any{"state": "yielded", "foreign_mb": 11468, "method": "memory-accounting", "paused_backends": []string{"vllm"}}
	})
	rpt.SendHeartbeat()
	gc, ok := payload["gpu_contention"].(map[string]any)
	if !ok || gc["state"] != "yielded" || gc["method"] != "memory-accounting" {
		t.Fatalf("gpu_contention missing or wrong: %#v", payload["gpu_contention"])
	}
}

// nats_rpc follows the probe the agent installs: false until control over the
// bus is live, true while it is, false again when it is taken back.
func TestControlTransportsFollowTheBusProbe(t *testing.T) {
	r := &Reporter{}
	if r.controlTransports()["nats_rpc"] {
		t.Fatal("no probe installed: nats_rpc must be false (an old controller NATS file, or no CA)")
	}
	live := false
	r.SetNatsRPC(func() bool { return live })
	if r.controlTransports()["nats_rpc"] {
		t.Fatal("probe says not live")
	}
	live = true
	ct := r.controlTransports()
	if !ct["nats_rpc"] || !ct["https_listener"] || ct["tunnel"] {
		t.Fatalf("live probe: %v", ct)
	}
}

// model_bench rides every heartbeat beside host_services once a bench has
// run, and is absent before (a nil answer, or no provider).
func TestHeartbeatCarriesModelBenchOnlyOnceOneHasRun(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/test-node/heartbeat" {
			payload = nil
			_ = json.NewDecoder(r.Body).Decode(&payload)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	rpt := newTestReporter(t, server.URL, nil)
	rpt.SetHostState(func() map[string]any { return map[string]any{"harness": map[string]any{"state": "running"}} })

	rpt.SendHeartbeat()
	if _, ok := payload["model_bench"]; ok {
		t.Fatalf("no provider: model_bench must be absent: %v", payload["model_bench"])
	}
	var bench any
	rpt.SetModelBench(func() any { return bench })
	rpt.SendHeartbeat()
	if _, ok := payload["model_bench"]; ok {
		t.Fatalf("no bench yet: model_bench must be absent")
	}
	bench = map[string]any{"model": "gemma4:12b", "backend": "ollama", "load_secs": 4.2, "prefill_tps": 210.5,
		"decode_tps": 18.3, "prompt_tokens": 8192, "at": "2026-10-19T17:00:00Z"}
	rpt.SendHeartbeat()
	mb, ok := payload["model_bench"].(map[string]any)
	if !ok || mb["model"] != "gemma4:12b" || mb["prefill_tps"] != 210.5 {
		t.Fatalf("model_bench: %v", payload["model_bench"])
	}
	if _, ok := payload["host_services"]; !ok {
		t.Error("host_services still sent beside it")
	}
}

func TestControlTransportsAdvertiseTheTunnelOnlyWhileItIsUp(t *testing.T) {
	r := &Reporter{}
	if r.controlTransports()["tunnel"] {
		t.Fatal("no tunnel provider: must not advertise")
	}
	up := false
	r.SetTunnel(func() bool { return up })
	if r.controlTransports()["tunnel"] {
		t.Fatal("tunnel down: must not advertise")
	}
	up = true
	if !r.controlTransports()["tunnel"] {
		t.Fatal("tunnel up: must advertise")
	}
	if !r.controlTransports()["https_listener"] {
		t.Fatal("the HTTPS listener is always offered")
	}
}
