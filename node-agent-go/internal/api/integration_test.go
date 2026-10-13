// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Integration tests for the Go node-agent HTTP API.
//
// These tests start a real HTTP server with mocked Docker/GPU dependencies
// and exercise every endpoint. No running cluster needed.
//
// Run: go test -v ./internal/api/ -run TestIntegration
package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// testServer creates a Server with mocked dependencies and returns an httptest.Server.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()

	cfg := &config.Config{
		NodeID:         "integration-test-node",
		Tier:           2,
		GPUModel:       "Test GPU",
		VRAMGB:         8.0,
		NodeAgentToken: "test-token",
		TLSCA:          "ca.pem",
	}

	// No real Docker — backend start/stop will fail gracefully.
	// For a full integration test with Docker, set NOO_NODE_AGENT_URL
	// and test against the running container.
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := metrics.NewCollector(gpu)

	srv := NewServer(cfg, nil, gpu, coll)
	return httptest.NewServer(asController(t, srv.mux))
}

// asController puts the request in the state a REAL controller call arrives
// in: a verified client leaf carrying O="Mesh Cluster Gateway", on an agent
// that has a cluster CA configured (cfg.TLSCA above).
//
// Without it every controller-only route now answers 503 ("this node cannot
// identify its callers"), which is the correct production behaviour and
// makes these handler tests untestable. The GATE itself is exercised
// separately and adversarially in principal_routes_test.go — including the
// 503 this harness is standing in for — so faking it here tests the handler
// without hiding the decision.
func asController(t *testing.T, h http.Handler) http.Handler {
	t.Helper()
	leaf := testLeaf(t, "host8", "Mesh Cluster Gateway")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		// A test that means "a caller with no controller leaf" says so: the
		// controller's leaf alone now earns /health's detail.
		if r.Header.Get(noLeafHeader) != "" {
			r.TLS = &tls.ConnectionState{}
		}
		h.ServeHTTP(w, r)
	})
}

// noLeafHeader asks asController to present no client leaf.
const noLeafHeader = "X-Test-No-Controller-Leaf"

func authReq(method, url string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, url, body)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// --- Health endpoint (no auth) ---

func TestIntegration_Health(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	anon, _ := http.NewRequest("GET", ts.URL+"/health", nil)
	anon.Header.Set(noLeafHeader, "1")
	resp, err := http.DefaultClient.Do(anon)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	if body["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", body["status"])
	}
	// ANONYMOUS: liveness and build, nothing about the node. The node id,
	// the NATS URL + username and the host's disk layout used to be free to
	// anything that could open a socket to :8081.
	if _, present := body["node_id"]; present {
		t.Errorf("unauthenticated /health must not disclose node_id: %v", body)
	}
	for _, k := range []string{"nats", "disk"} {
		if _, present := body[k]; present {
			t.Errorf("unauthenticated /health must not disclose %q: %v", k, body)
		}
	}
	if body["version"] == nil || body["version"] == "" {
		t.Errorf("unauthenticated /health must still say which build it is: %v", body)
	}

	// AUTHENTICATED: the full picture, which is what the gateway's
	// reachability probe and disk-watermark evaluator both read.
	resp2, err := http.DefaultClient.Do(authReq("GET", ts.URL+"/health", nil))
	if err != nil {
		t.Fatalf("GET /health (auth): %v", err)
	}
	defer resp2.Body.Close()
	var full map[string]any
	json.NewDecoder(resp2.Body).Decode(&full)
	if full["node_id"] != "integration-test-node" {
		t.Errorf("expected node_id 'integration-test-node', got %v", full["node_id"])
	}
	if full["nats"] == nil {
		t.Errorf("authenticated /health must carry the bus state: %v", full)
	}
	if full["disk"] == nil {
		t.Errorf("authenticated /health must carry disk usage: %v", full)
	}
}

// --- Auth enforcement ---

func TestIntegration_AuthRequired(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	endpoints := []struct {
		method string
		path   string
	}{
		{"POST", "/start"},
		{"POST", "/stop"},
		{"POST", "/restart"},
		{"POST", "/pull"},
		{"POST", "/clean"},
		{"GET", "/gpu"},
		{"GET", "/metrics"},
		{"GET", "/logs/containers"},
		{"GET", "/logs/test-container"},
		{"GET", "/stats/containers"},
		{"POST", "/api/device/camera_capture"},
		{"POST", "/api/device/location"},
		{"POST", "/api/device/clipboard"},
		{"POST", "/api/device/screenshot"},
		{"POST", "/api/device/ambient_audio"},
		{"POST", "/api/device/battery_status"},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequest(ep.method, ts.URL+ep.path, nil)
		// No Authorization header, and no controller leaf — the leaf alone
		// is a credential on these routes now.
		req.Header.Set(noLeafHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("%s %s: %v", ep.method, ep.path, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d", ep.method, ep.path, resp.StatusCode)
		}
	}
}

// --- GPU metrics ---

func TestIntegration_GPUMetrics(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authReq("GET", ts.URL+"/gpu", nil))
	if err != nil {
		t.Fatalf("GET /gpu: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	// No real GPU in test — should report unavailable
	if body["available"] != false {
		t.Logf("GPU metrics available: %v (may vary by test environment)", body["available"])
	}
}

// --- Prometheus metrics ---

// metricsMuxAndLeaf builds the agent in the state it actually ships in —
// a cluster CA configured, so the listener asks callers for a certificate
// — plus the scraper's own service leaf.
//
// The old version of this test ran against a PLAINTEXT httptest server and
// asserted 200, which is exactly the posture /metrics no longer serves
// Asserting the content through the real gate means the
// test fails if the gate is ever wired to refuse the scraper.
func metricsMuxAndLeaf(t *testing.T) (http.Handler, *x509.Certificate) {
	t.Helper()
	cfg := &config.Config{
		NodeID:         "integration-test-node",
		Tier:           2,
		GPUModel:       "Test GPU",
		VRAMGB:         8.0,
		NodeAgentToken: "test-token",
		TLSCA:          "ca.pem",
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	srv := NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
	return srv.mux, testLeaf(t, "prometheus", "Mesh Cluster Service")
}

// A plaintext agent cannot tell the scraper from a peer holding the same
// fleet secret, so it refuses and names the missing config rather than
// serving and hoping. Without this case the 503 path is never executed.
//
// It must build its OWN server: `testServer` sets TLSCA and wraps the mux in
// `asController`, so every request through it arrives already carrying the
// controller's leaf. Running this case against that harness passed for the
// wrong reason — 200, because the caller WAS the controller.
func TestIntegration_PrometheusMetricsRefusedWithoutPeerIdentity(t *testing.T) {
	// No TLSCA, no injected peer certificate: the real plaintext posture.
	cfg := &config.Config{
		NodeID:         "integration-test-node",
		NodeAgentToken: "test-token",
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	srv := NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authReq("GET", ts.URL+"/metrics", nil))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a plaintext agent must refuse /metrics, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "NOO_TLS_CA") {
		t.Errorf("the refusal must name the config that fixes it, got %q", string(body))
	}
}

func TestIntegration_PrometheusMetrics(t *testing.T) {
	mux, svc := metricsMuxAndLeaf(t)

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{svc}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	resp := rec.Result()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content-type, got %q", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Verify required metric families exist
	required := []string{
		"noo_node_info",
		"noo_node_load",
	}
	for _, metric := range required {
		if !strings.Contains(text, metric) {
			t.Errorf("missing metric %q in Prometheus output", metric)
		}
	}

	// Verify HELP and TYPE lines exist
	if !strings.Contains(text, "# HELP noo_node_info") {
		t.Error("missing HELP line for noo_node_info")
	}
	if !strings.Contains(text, "# TYPE noo_node_info gauge") {
		t.Error("missing TYPE line for noo_node_info")
	}

	// Verify node_id label is present
	if !strings.Contains(text, `node_id="integration-test-node"`) {
		t.Error("missing node_id label in metrics")
	}
}

// --- Device sensor endpoints (real data or explicit errors, never mocks) ---

// battery_status and location are the two endpoints that can return real
// data on any Linux host, so they are asserted concretely. The rest must
// fail loudly rather than return fiction — that is the whole point of the
// rewrite, so it is pinned by a test.

func TestIntegration_DeviceBatteryIsReal(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+"/api/device/battery_status",
		jsonBody(map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("battery_status: expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	// battery_pct is deliberately null on a mains host — assert the key is
	// PRESENT rather than truthy, so a fabricated percentage would fail.
	if _, ok := body["battery_pct"]; !ok {
		t.Errorf("missing battery_pct key: %v", body)
	}
	for _, k := range []string{"power_source", "thermal_state", "network_type", "cpu_load"} {
		if _, ok := body[k]; !ok {
			t.Errorf("missing %q in %v", k, body)
		}
	}
	// Vocabulary must match CompanionPolicy (node.py:102), or the gate
	// silently never matches.
	switch body["thermal_state"] {
	case "nominal", "fair", "serious", "critical":
	default:
		t.Errorf("thermal_state %v outside CompanionPolicy vocabulary", body["thermal_state"])
	}
	switch body["power_source"] {
	case "mains", "battery":
	default:
		t.Errorf("unexpected power_source %v", body["power_source"])
	}
}

func TestIntegration_DeviceLocationRequiresConfig(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	// Unconfigured: must refuse rather than invent coordinates.
	resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+"/api/device/location",
		jsonBody(map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("unconfigured location: expected 501, got %d (%v)", resp.StatusCode, body)
	}
	if _, ok := body["lat"]; ok {
		t.Error("unconfigured location must NOT return coordinates")
	}

	// Configured: real, with an explicit source so no caller mistakes it
	// for a GPS fix.
	t.Setenv("NOO_DEVICE_LAT", "27.9506")
	t.Setenv("NOO_DEVICE_LON", "-82.4572")
	resp, err = http.DefaultClient.Do(authReq("POST", ts.URL+"/api/device/location",
		jsonBody(map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("configured location: expected 200, got %d", resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["lat"] != 27.9506 || body["lon"] != -82.4572 {
		t.Errorf("coordinates not echoed: %v", body)
	}
	if body["source"] != "configured" {
		t.Errorf("source = %v, want \"configured\"", body["source"])
	}
}

func TestIntegration_DeviceLocationRejectsBadCoordinates(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	t.Setenv("NOO_DEVICE_LAT", "999")
	t.Setenv("NOO_DEVICE_LON", "-82.4572")
	resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+"/api/device/location",
		jsonBody(map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("out-of-range latitude: expected 500, got %d", resp.StatusCode)
	}
}

// Sensors with no hardware (CI runners, and host9 today) must return a
// non-2xx with available=false. A 200 carrying invented data is precisely
// the regression this guards.
func TestIntegration_AbsentSensorsFailLoudly(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	for _, path := range []string{
		"/api/device/camera_capture",
		"/api/device/ambient_audio",
		"/api/device/clipboard",
		"/api/device/screenshot",
	} {
		resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+path, jsonBody(map[string]any{})))
		if err != nil {
			t.Errorf("POST %s: %v", path, err)
			continue
		}
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			t.Errorf("POST %s returned 200 with %v; unavailable sensors must not return data", path, body)
			continue
		}
		if resp.StatusCode != 501 && resp.StatusCode != 503 {
			t.Errorf("POST %s: expected 501 or 503, got %d", path, resp.StatusCode)
		}
		if body["available"] != false {
			t.Errorf("POST %s: expected available=false, got %v", path, body)
		}
		if _, ok := body["error"]; !ok {
			t.Errorf("POST %s: missing error explanation: %v", path, body)
		}
	}
}

// --- Backend start/stop (will fail without Docker, but tests error handling) ---

func TestIntegration_StartBackend_NoDocker(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+"/start",
		jsonBody(map[string]string{"backend": "ollama", "model": "qwen3:8b"})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// 503 — Docker client is nil in test
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without Docker, got %d", resp.StatusCode)
	}
}

func TestIntegration_StopBackend_NoDocker(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authReq("POST", ts.URL+"/stop",
		jsonBody(map[string]string{"backend": "ollama"})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without Docker, got %d", resp.StatusCode)
	}
}

// /health must report the NATS bus as its own fact. `status: healthy`
// deliberately describes only the control API (the Docker healthcheck hangs
// off it), so the bus needs a field of its own — otherwise a bus-deaf node
// is byte-for-byte identical to a healthy one, which is exactly how the
// 2026-08-02 outage stayed invisible for two days.
func TestIntegration_HealthReportsNATSState(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	get := func() map[string]any {
		// Authenticated: the bus state is node detail, behind the bearer.
		resp, err := http.DefaultClient.Do(authReq("GET", ts.URL+"/health", nil))
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		return body
	}

	// No provider wired: honest "unavailable", never a benign default.
	bus, ok := get()["nats"].(map[string]any)
	if !ok {
		t.Fatal("/health must always include a `nats` object")
	}
	if bus["state"] != "unavailable" {
		t.Errorf("state = %v, want 'unavailable' when no messaging exists", bus["state"])
	}
	if bus["connected"] != false {
		t.Errorf("connected = %v, want false", bus["connected"])
	}
	if bus["last_connected_at"] != nil {
		t.Errorf("last_connected_at = %v, want null (never)", bus["last_connected_at"])
	}

	// Provider wired and reporting an outage.
	srv := NewServer(&config.Config{NodeID: "n"}, nil, nil, nil)
	srv.SetBusStatus(func() BusStatus {
		return BusStatus{State: "reconnecting", Connected: false, Detail: "d"}
	})
	if got := srv.BusStatusOrUnavailable(); got.State != "reconnecting" || got.Connected {
		t.Errorf("BusStatusOrUnavailable = %+v, want the provider's value", got)
	}
}
