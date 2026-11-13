// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// GPU detection asks no resolver anything (noomesh#1129 follow-up, general
// 2026-11-13). Metrics() used to fall back to GET
// https://nvidia-exporter:9400/metrics, a compose name with no container
// behind it on a host agent, so on every host without nvidia-smi the agent
// asked the host's resolver for `nvidia-exporter.<search domain>` once per
// start. docs/security/telemetry.md says nothing of ours asks a resolver for
// our own container names; this holds the agent's half of that.

// dnsRecorder replaces net.DefaultResolver (which every net.Dialer without
// its own Resolver uses, the agent's transport and containerdial's fallback
// dialer included) with one that records each DNS connection it would open
// and opens none.
type dnsRecorder struct {
	mu   sync.Mutex
	dial []string
}

func (r *dnsRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dial...)
}

func (r *dnsRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dial = nil
}

func recordDNS(t *testing.T) *dnsRecorder {
	t.Helper()
	r := &dnsRecorder{}
	orig := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			r.mu.Lock()
			r.dial = append(r.dial, network+" "+address)
			r.mu.Unlock()
			return nil, errors.New("this test allows no DNS")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = orig })
	return r
}

func TestGPUDetectionResolvesNoNameWithoutNvidiaSmi(t *testing.T) {
	pinSmi(t, filepath.Join(t.TempDir(), "nvidia-smi")) // no nvidia-smi on this host
	rec := recordDNS(t)

	// The recorder sees exactly the request the old fallback made, so a
	// clean result below is not a recorder that sees nothing.
	// No proxy (a runner's HTTP_PROXY would dial the proxy, not resolve the
	// name) and a plain net.Dialer: the path the agent's own transport takes.
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}}
	if resp, err := c.Get("https://nvidia-exporter:9400/metrics"); err == nil {
		resp.Body.Close()
		t.Fatal("nvidia-exporter answered with DNS disabled: the recorder is not in the path")
	}
	if len(rec.seen()) == 0 {
		t.Fatal("canary: an HTTP GET of nvidia-exporter:9400 opened no DNS connection; the recorder cannot prove anything")
	}
	rec.reset()

	g := NewGPUDetector()
	for i := 0; i < 3; i++ {
		if m := g.Metrics(); m != nil {
			t.Fatalf("Metrics() = %+v with no nvidia-smi", m)
		}
	}
	_, _ = g.DetectCount()
	_, _ = g.DetectModel()
	_, _ = g.DetectVRAM()
	_, _ = g.DetectComputeCaps()
	_ = g.DetectVRAMUsed()
	_ = g.ComputeApps()

	if got := rec.seen(); len(got) != 0 {
		t.Fatalf("GPU detection on a host without nvidia-smi asked a resolver %d time(s) (%v): "+
			"the host agent must not look up a compose name such as nvidia-exporter", len(got), got)
	}
}
