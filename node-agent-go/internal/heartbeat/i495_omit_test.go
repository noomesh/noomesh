// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// Followup i495 (noomesh-internal), items 1 and 2: a probe that failed is
// omitted from the beat (the gateway stores an omitted running_backends as {}
// and keeps an omitted gpu_model / vram_gb), never reported as an empty fact.

type scriptedGPU struct {
	mu    sync.Mutex
	model string
	vram  float64
	count int
	err   error
}

func (g *scriptedGPU) set(model string, vram float64, count int, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.model, g.vram, g.count, g.err = model, vram, count, err
}
func (g *scriptedGPU) DetectModel() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.model, g.err
}
func (g *scriptedGPU) DetectVRAM() (float64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.vram, g.err
}
func (g *scriptedGPU) DetectCount() (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count, g.err
}

type capture struct {
	mu        sync.Mutex
	beats     []map[string]any
	registers []map[string]any
}

func (c *capture) last(list *[]map[string]any) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(*list) == 0 {
		return nil
	}
	return (*list)[len(*list)-1]
}

func captureServer(t *testing.T) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.mu.Lock()
		if r.URL.Path == "/api/cluster/nodes/register" {
			c.registers = append(c.registers, body)
		} else {
			c.beats = append(c.beats, body)
		}
		c.mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func newReporterWith(srvURL string, gpu hardware.GPUProbe, backends func() (map[string]string, error)) *Reporter {
	cfg := &config.Config{NodeID: "n1", Tier: 2, ControllerURL: srvURL}
	return NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, metrics.NewCollector(hardware.NewGPUDetector(nil, "http")), gpu,
		backends, func() int { return 0 })
}

func TestHeartbeatOmitsRunningBackendsWhenDockerCannotBeAsked(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	var dockerErr error
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) {
		if dockerErr != nil {
			return nil, dockerErr
		}
		return map[string]string{"vllm": "google/gemma"}, nil
	})

	r.SendHeartbeat()
	if got, _ := cap.last(&cap.beats)["running_backends"].(map[string]any); got["vllm"] != "google/gemma" {
		t.Fatalf("healthy beat: running_backends = %v", cap.last(&cap.beats)["running_backends"])
	}

	dockerErr = errors.New("listing containers: context deadline exceeded")
	r.SendHeartbeat()
	beat := cap.last(&cap.beats)
	if _, present := beat["running_backends"]; present {
		t.Fatalf("a docker list error must OMIT running_backends, not send %v", beat["running_backends"])
	}
	// The rest of the beat is unaffected.
	if beat["tier"] != float64(2) || beat["lanes"] == nil {
		t.Fatalf("the beat must still carry its other fields: tier=%v lanes=%v", beat["tier"], beat["lanes"])
	}
}

func TestHeartbeatOmitsGPUIdentityWhenTheProbeFails(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	beat := cap.last(&cap.beats)
	if beat["gpu_model"] != "RTX 4090" || beat["vram_gb"] != float64(24) {
		t.Fatalf("healthy probe: gpu_model=%v vram_gb=%v", beat["gpu_model"], beat["vram_gb"])
	}

	gpu.set("", 0, 0, errors.New("nvidia-smi name: context deadline exceeded"))
	r.SendHeartbeat()
	beat = cap.last(&cap.beats)
	if _, ok := beat["gpu_model"]; ok {
		t.Fatalf("a failed probe must omit gpu_model, got %v", beat["gpu_model"])
	}
	if _, ok := beat["vram_gb"]; ok {
		t.Fatalf("a failed probe must omit vram_gb, got %v", beat["vram_gb"])
	}

	// A host with no GPU at all is a clean answer and is still reported.
	gpu.set("", 0, 0, nil)
	r.SendHeartbeat()
	beat = cap.last(&cap.beats)
	if m, ok := beat["gpu_model"]; !ok || m != "" {
		t.Fatalf("no GPU (clean) must still be reported as empty, got %v present=%v", m, ok)
	}
	if v, ok := beat["vram_gb"]; !ok || v != float64(0) {
		t.Fatalf("no GPU (clean) vram_gb = %v present=%v", v, ok)
	}
}

// Registered during a failed probe: the capabilities keep vllm, and when the
// probe answers on a later beat the node re-registers with the detected ones.
func TestFailedProbeAtRegistrationKeepsVLLMThenReRegisters(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{err: errors.New("nvidia-smi name: context deadline exceeded")}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })
	r.cfg.GPUModel = "RTX 4090" // configured: survives the failed probe

	caps, err := hardware.Detect(r.cfg, gpu, nil)
	if err == nil || !caps.ProbeIncomplete {
		t.Fatalf("Detect must report the failed probe: err=%v incomplete=%v", err, caps.ProbeIncomplete)
	}
	if !contains(caps.Backends, "vllm") || !contains(caps.Backends, "airllm") {
		t.Fatalf("a failed probe must not drop vllm/airllm: %v", caps.Backends)
	}
	if !r.Register(caps, "10.0.0.1") {
		t.Fatal("register failed")
	}

	// Still failing: no re-register.
	r.SendHeartbeat()
	if n := len(cap.registers); n != 1 {
		t.Fatalf("expected 1 registration while the probe still fails, got %d", n)
	}

	// The probe answers with real values: re-register with them.
	gpu.set("RTX 4090", 24, 2, nil)
	r.SendHeartbeat()
	if n := len(cap.registers); n != 2 {
		t.Fatalf("expected a re-registration once the probe recovered, got %d registrations", n)
	}
	got, _ := cap.last(&cap.registers)["capabilities"].(map[string]any)
	if got["gpu_count"] != float64(2) || got["vram_gb"] != float64(24) {
		t.Fatalf("re-registered capabilities = %v", got)
	}
	if r.caps.ProbeIncomplete {
		t.Fatal("capabilities still marked incomplete after a good probe")
	}
	// And it does not keep re-registering.
	r.SendHeartbeat()
	if n := len(cap.registers); n != 2 {
		t.Fatalf("re-registered again with nothing to fix: %d", n)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
