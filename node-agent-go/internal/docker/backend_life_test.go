// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

// The heartbeat's `backend_containers` entry: the start
// time the CLI measures the warm-up window from, and the health it
// requires to be `starting`.
func TestContainerLifeReportsStartTimeAndHealth(t *testing.T) {
	started := time.Date(2026, 9, 30, 12, 0, 5, 123456789, time.UTC)
	life := containerLife(&container.State{
		Running:   true,
		StartedAt: started.Format(time.RFC3339Nano),
		Health:    &container.Health{Status: container.Starting},
	})
	if life == nil {
		t.Fatal("a running container with a start time must be reported")
	}
	if life["started_at"] != started.Unix() {
		t.Errorf("started_at = %v, want %d", life["started_at"], started.Unix())
	}
	if life["health"] != "starting" {
		t.Errorf("health = %v, want starting", life["health"])
	}
	if life["running"] != true {
		t.Errorf("running = %v", life["running"])
	}

	// No healthcheck: the key is omitted, never reported as "starting".
	for _, h := range []*container.Health{nil, {Status: container.NoHealthcheck}, {Status: ""}} {
		l := containerLife(&container.State{Running: true, StartedAt: started.Format(time.RFC3339Nano), Health: h})
		if _, present := l["health"]; present {
			t.Errorf("health %+v must be omitted, got %v", h, l["health"])
		}
	}
	healthy := containerLife(&container.State{Running: true, StartedAt: started.Format(time.RFC3339Nano),
		Health: &container.Health{Status: container.Healthy}})
	if healthy["health"] != "healthy" {
		t.Errorf("health = %v, want healthy", healthy["health"])
	}
}

// No parseable start time, no entry: a guessed start would widen the
// warm-up window, and the CLI reads a missing entry as "not reported".
func TestContainerLifeWithoutAStartTimeIsNotReported(t *testing.T) {
	for _, st := range []*container.State{
		nil,
		{Running: true, StartedAt: ""},
		{Running: true, StartedAt: "garbage"},
		{Running: false, StartedAt: "0001-01-01T00:00:00Z"},
	} {
		if l := containerLife(st); l != nil {
			t.Errorf("%+v: want nil, got %v", st, l)
		}
	}
}

// A client with no daemon reports nothing (the heartbeat omits the key).
func TestBackendContainersWithoutDockerIsNil(t *testing.T) {
	var c *Client
	if c.BackendContainers() != nil {
		t.Error("nil client must report nil")
	}
	if (&Client{}).BackendContainers() != nil {
		t.Error("client without docker must report nil")
	}
}

// A docker container beside an adopted backend is nobody's: flagged orphan
// with its name and its sidecar. A backend the adopted lane does not serve
// is untouched.
func TestMarkOrphansFlagsDockerBesideAdopted(t *testing.T) {
	out := map[string]any{
		"ollama": map[string]any{"running": true, "container": "noo-ollama"},
		"vllm":   map[string]any{"running": true, "container": "noo-vllm"},
	}
	sc := map[string][]string{"ollama": {"noo-stunnel-ollama"}, "vllm": {"noo-stunnel-vllm"}}
	markOrphans(out, sc, map[string]bool{"ollama": true})
	o := out["ollama"].(map[string]any)
	if o["orphan"] != true || o["container"] != "noo-ollama" {
		t.Fatalf("ollama not flagged orphan: %v", o)
	}
	if got, _ := o["sidecars"].([]string); len(got) != 1 || got[0] != "noo-stunnel-ollama" {
		t.Fatalf("sidecars = %v", o["sidecars"])
	}
	v := out["vllm"].(map[string]any)
	if _, bad := v["orphan"]; bad {
		t.Fatalf("vllm is not adopted, must not be flagged: %v", v)
	}
	if _, bad := v["sidecars"]; bad {
		t.Fatalf("vllm sidecars leaked: %v", v)
	}
}

func TestStunnelBackendKey(t *testing.T) {
	for name, want := range map[string]string{
		"noo-stunnel-ollama":       "ollama",
		"noo-stunnel-llamacpp":     "llamacpp",
		"noo-stunnel-ollama-embed": "",
		"noo-ollama":               "",
	} {
		if got := stunnelBackendKey(name); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

// A container an older agent created from `vllm/vllm-openai:latest` (awolf,
// 2026-10-20, before the floating-ref refusal) is reported as floating; a
// pinned, versioned or rail-own ref is not.
func TestImageFactsFlagsAFloatingThirdPartyRef(t *testing.T) {
	cases := map[string]bool{
		"vllm/vllm-openai:latest":  true,
		"ollama/ollama":            true,
		"vllm/vllm-openai:v0.29.0": false,
		"vllm/vllm-openai:latest@sha256:" + strings.Repeat("a", 64): false,
		"pai-assistant/llamacpp:latest":                             false, // our own local build: rail-only, exempt
	}
	for img, want := range cases {
		ref, floating := imageFacts(img)
		if ref != img || floating != want {
			t.Errorf("imageFacts(%q) = (%q, %v), want floating=%v", img, ref, floating, want)
		}
	}
}
