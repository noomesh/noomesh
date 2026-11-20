package heartbeat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// A Kick sends a heartbeat now, not at the next tick: a node workload's row
// that changed after its door leaf landed reaches the controller at once
// (0.6.25-rc.1 rehearsal, A-nodewl.reserve).
func TestKickSendsAHeartbeatBeforeTheTick(t *testing.T) {
	srv, cap := captureServer(t)
	cfg := &config.Config{NodeID: "n1", Tier: 2, ControllerURL: srv.URL, HeartbeatInterval: 3600}
	r := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, metrics.NewCollector(hardware.NewGPUDetector()),
		&scriptedGPU{}, func() (map[string]string, error) { return map[string]string{}, nil }, func() int { return 0 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	r.Kick()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cap.mu.Lock()
		n := len(cap.beats)
		cap.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a Kick sent no heartbeat within 5 s (the tick is an hour away)")
}

// Kicks never block and coalesce: a burst of converges is one extra beat.
func TestKicksCoalesceAndNeverBlock(t *testing.T) {
	r := &Reporter{}
	for i := 0; i < 5; i++ {
		r.Kick()
	}
	if got := len(r.kickCh()); got != 1 {
		t.Fatalf("pending kicks = %d, want 1", got)
	}
}

// A successful registration is followed by a beat at once, not an interval
// later: a registration carries no lanes, so until the first beat the
// controller cannot route to the node (every agent restart's ~30 s of 503s).
// The boot registration happens before Run starts; the kick must survive it.
func TestRegisterKicksABeatBeforeTheTick(t *testing.T) {
	srv, cap := captureServer(t)
	cfg := &config.Config{NodeID: "n1", Tier: 2, ControllerURL: srv.URL, HeartbeatInterval: 3600}
	r := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, metrics.NewCollector(hardware.NewGPUDetector()),
		&scriptedGPU{}, func() (map[string]string, error) { return map[string]string{}, nil }, func() int { return 0 })
	if !r.Register(hardware.Capabilities{CPUCores: 4, RAMGB: 8, Tier: 2}, "100.64.0.2") {
		t.Fatal("registration failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cap.mu.Lock()
		n := len(cap.beats)
		cap.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no heartbeat within 5 s of a successful registration (the tick is an hour away)")
}

// A beat's 404 re-registers WITHOUT a kick: a controller that keeps
// answering the beat 404 must not get a tight register/beat loop.
func TestHeartbeat404ReRegisterDoesNotKick(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/nodes/register" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	cfg := &config.Config{NodeID: "n1", Tier: 2, ControllerURL: server.URL, HeartbeatInterval: 3600}
	r := NewReporter(cfg, &http.Client{Timeout: 5 * time.Second}, metrics.NewCollector(hardware.NewGPUDetector()),
		&scriptedGPU{}, func() (map[string]string, error) { return map[string]string{}, nil }, func() int { return 0 })
	r.SendHeartbeat()
	if got := len(r.kickCh()); got != 0 {
		t.Fatalf("pending kicks after a 404 re-register = %d, want 0", got)
	}
}
