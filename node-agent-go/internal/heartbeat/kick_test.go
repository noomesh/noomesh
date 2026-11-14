package heartbeat

import (
	"context"
	"net/http"
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
