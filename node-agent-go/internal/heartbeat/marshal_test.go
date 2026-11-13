// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestMarshalPayload_NaNKeyDroppedAndNamed(t *testing.T) {
	logs := captureLog(t)
	body, err := marshalPayload(map[string]any{
		"load":        0.5,
		"cpu_load":    math.NaN(),
		"mem_used_gb": map[string]any{"nested": math.Inf(1)},
		"tier":        3,
	})
	if err != nil {
		t.Fatalf("marshal failed, the beat would be dropped: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["load"] != 0.5 || got["tier"] != float64(3) {
		t.Errorf("good keys lost: %v", got)
	}
	if _, ok := got["cpu_load"]; ok {
		t.Error("cpu_load (NaN) must be omitted")
	}
	if _, ok := got["mem_used_gb"]; ok {
		t.Error("mem_used_gb (nested Inf) must be omitted")
	}
	for _, k := range []string{`key=cpu_load`, `key=mem_used_gb`} {
		if !strings.Contains(logs.String(), k) {
			t.Errorf("log does not name %s:\n%s", k, logs)
		}
	}
}

func TestMarshalPayload_CleanPayloadUntouched(t *testing.T) {
	logs := captureLog(t)
	body, err := marshalPayload(map[string]any{"load": 0.5})
	if err != nil || string(body) != `{"load":0.5}` || logs.Len() != 0 {
		t.Errorf("body=%s err=%v log=%q", body, err, logs)
	}
}

// The real SendHeartbeat with a machine whose memory read gives a zero total
// (the 1 - 0/0 = NaN case): the beat must arrive.
func TestSendHeartbeat_ZeroTotalMemoryStillDelivers(t *testing.T) {
	var mu sync.Mutex
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{NodeID: "test-node", ControllerURL: srv.URL, Tier: 3}
	gpu := hardware.NewGPUDetector()
	coll := metrics.NewCollectorWithSources(gpu,
		func() (float64, bool) { return 0.3, true },
		func() hardware.MemoryInfo { return hardware.MemoryInfo{} })
	rpt := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() (map[string]string, error) { return map[string]string{}, nil },
		func() int { return 0 })
	rpt.SendHeartbeat()

	mu.Lock()
	defer mu.Unlock()
	if payload == nil {
		t.Fatal("no heartbeat arrived")
	}
	if payload["load"] != 0.3 {
		t.Errorf("load = %v, want 0.3 (CPU only)", payload["load"])
	}
	if payload["cpu_load"] != 0.3 {
		t.Errorf("cpu_load = %v, want 0.3", payload["cpu_load"])
	}
	if _, ok := payload["mem_used_gb"]; ok {
		t.Errorf("mem_used_gb = %v, want omitted", payload["mem_used_gb"])
	}
}

// A CPU that cannot be read: the beat arrives with neither load nor cpu_load
// (not 0, not null), even though memory is known.
func TestSendHeartbeat_UnknownCPUOmitsLoadKeys(t *testing.T) {
	var mu sync.Mutex
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{NodeID: "test-node", ControllerURL: srv.URL, Tier: 3}
	gpu := hardware.NewGPUDetector()
	coll := metrics.NewCollectorWithSources(gpu,
		func() (float64, bool) { return 0, false },
		func() hardware.MemoryInfo {
			return hardware.MemoryInfo{TotalKB: 16 << 20, AvailableKB: 4 << 20, AvailableKnown: true}
		})
	rpt := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, coll, gpu,
		func() (map[string]string, error) { return map[string]string{}, nil },
		func() int { return 0 })
	rpt.SendHeartbeat()

	mu.Lock()
	defer mu.Unlock()
	if raw == nil {
		t.Fatal("no heartbeat arrived")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for _, k := range []string{"load", "cpu_load"} {
		if v, ok := payload[k]; ok {
			t.Errorf("%s present (%s), want the key absent", k, v)
		}
	}
	if string(payload["mem_used_gb"]) != "12" {
		t.Errorf("mem_used_gb = %s, want 12", payload["mem_used_gb"])
	}
}
