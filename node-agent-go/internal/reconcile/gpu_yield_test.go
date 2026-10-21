// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
)

type heldProbe struct{}

func (heldProbe) Read(context.Context) gpuyield.Reading {
	return gpuyield.Reading{Measured: true, TotalMB: 16384, UsedMB: 11000}
}

type heldDocker struct{ starts int }

func (*heldDocker) GPUBackendContainers(context.Context) ([]docker.GPUBackend, error) {
	return []docker.GPUBackend{{Backend: "vllm", ID: "x", Running: true}}, nil
}
func (*heldDocker) NoomeshContainers(context.Context) ([]docker.NoomeshContainer, error) {
	return nil, nil
}
func (*heldDocker) StopContainerGraceful(context.Context, string, int) error { return nil }
func (d *heldDocker) StartContainer(context.Context, string) error           { d.starts++; return nil }

// A backend the shared-GPU yield has paused is not started by the reconciler:
// the decision says hold, and the running branch consults it before the
// start path (pinned on the source — Once needs a live docker daemon).
func TestReconcileDoesNotStartAPausedGPUBackend(t *testing.T) {
	d := &heldDocker{}
	c := gpuyield.New(gpuyield.ConfigFromEnv(func(string) string { return "" }), heldProbe{}, d, "")
	gpuyield.SetDefault(c)
	t.Cleanup(func() { gpuyield.SetDefault(nil) })
	gpuyield.PublishPlacements(gpuPlacements([]placement{
		{Backend: "vllm", DesiredState: "running"},
		{Backend: "ollama", DesiredState: "running", Target: "cpu"},
	}))
	if gpuHeld(placement{Backend: "vllm"}) {
		t.Fatal("nothing paused yet: vllm must start")
	}
	c.Hold(context.Background(), gpuyield.HoldRequest{Reason: "voice", OperationID: "op-1"})
	if !gpuHeld(placement{Backend: "vllm"}) {
		t.Fatal("held: reconcile must not start vllm")
	}
	if gpuHeld(placement{Backend: "ollama", Target: "cpu"}) {
		t.Fatal("a CPU backend is never held by the GPU yield")
	}

	src, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	running := s[strings.Index(s, `case "running":`):]
	hold := strings.Index(running, "if gpuHeld(p) {")
	start := strings.Index(running, "r.docker.StartBackend(")
	if hold < 0 || start < 0 || hold > start {
		t.Fatal("the running branch must check gpuHeld before StartBackend")
	}
}
