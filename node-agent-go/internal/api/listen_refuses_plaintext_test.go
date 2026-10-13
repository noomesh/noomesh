// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// freePort asks the kernel for an unused TCP port and releases it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// listenOutcome runs ListenAndServe on cfg and reports what happened within
// the deadline: the error it returned, or nil if it is still serving. A
// still-serving agent with no TLS material is exactly the plaintext
// listener this test exists to keep out.
func listenOutcome(t *testing.T, cfg *config.Config) error {
	t.Helper()
	gpu := hardware.NewGPUDetector(nil, "http")
	srv := NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		return nil
	}
}

// An agent with no certificate does not listen at all — there is no
// plaintext fallback. The refusal is returned before a socket is bound
// (nothing answers on the port afterwards), and it names the command that
// delivers the material. Plant: restore the `server.ListenAndServe()`
// branch in ListenAndServe and this fails twice — no error arrives, and
// the dial below succeeds.
func TestListenAndServeRefusesWithoutTLSMaterial(t *testing.T) {
	port := freePort(t)
	cfg := &config.Config{NodeID: "plain-node", AgentPort: port, NodeAgentToken: "tok"}

	err := listenOutcome(t, cfg)
	if err == nil {
		t.Fatalf("an agent with no TLS material is serving on :%d — the plaintext listener is back", port)
	}
	for _, needle := range []string{"refusing to start", "noo cluster provision <node>", "no plaintext fallback", fmt.Sprintf(":%d", port)} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("refusal must say %q, got: %v", needle, err)
		}
	}
	// Nothing may STAY listening. The first dials can reach freePort's own
	// just-closed probe socket, which lingers for a few milliseconds on some
	// hosts (WSL2 mirrored networking: 7 runs in 20 failed on a dev box while
	// the agent bound nothing). A real plaintext listener would still be
	// there after the grace period; the probe's ghost is not.
	var dialErr error
	for deadline := time.Now().Add(time.Second); ; {
		var conn net.Conn
		conn, dialErr = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if dialErr != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("something is listening on :%d after the refusal — the refusal must come before any bind", port)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var opErr *net.OpError
	if !errors.As(dialErr, &opErr) {
		t.Fatalf("expected a connection refusal, got %v", dialErr)
	}
}

// NOO_MTLS_NODES=false used to relax the handshake and, without a cert,
// serve plaintext. It now refuses the start outright, naming the line to
// remove — a stale env file is loud rather than silently ignored.
func TestListenAndServeRefusesTheRetiredDowngrade(t *testing.T) {
	port := freePort(t)
	cfg := &config.Config{NodeID: "downgraded", AgentPort: port, MTLSDowngradeAsked: "false"}
	err := listenOutcome(t, cfg)
	if err == nil {
		t.Fatalf("NOO_MTLS_NODES=false must refuse the start, but the agent is serving on :%d", port)
	}
	if !strings.Contains(err.Error(), "NOO_MTLS_NODES") || !strings.Contains(err.Error(), "mTLS-only") {
		t.Errorf("refusal must name NOO_MTLS_NODES and the mTLS-only contract, got: %v", err)
	}
}
