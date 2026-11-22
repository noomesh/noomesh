// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
)

func has(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// `embed` drives mesh routing: the gateway picks an embedding node by this
// capability. Keying it on container names was wrong in both directions --
// it missed the real embedder and advertised stray ones.
func TestEmbedCapabilityFollowsDeclaredRole(t *testing.T) {
	d := &RuntimeCapabilityDetector{
		GetRunningBackends: func() map[string]string { return map[string]string{} },
		ListContainers:     func() []string { return nil },
	}

	t.Run("no declared embedder means no embed capability", func(t *testing.T) {
		embedtarget.Set(embedtarget.Target{})
		if caps := d.Detect(); has(caps, "embed") {
			t.Errorf("advertised embed with no declared embedder: %v", caps)
		}
	})

	t.Run("declared ollama embedder advertises embed", func(t *testing.T) {
		embedtarget.Set(embedtarget.Target{
			BaseURL: "http://noo-ollama:11434", Backend: "ollama", Model: "harrier",
		})
		caps := d.Detect()
		if !has(caps, "embed") {
			t.Errorf("harrier-on-ollama did not advertise embed: %v", caps)
		}
		if !has(caps, "embedding") {
			t.Errorf("harrier-on-ollama did not advertise embedding: %v", caps)
		}
	})

	// A container is present but desired state declares no embedder here, so
	// this node must NOT draw mesh embed traffic (a leftover noo-tei did).
	t.Run("undeclared tei container does not advertise embed", func(t *testing.T) {
		embedtarget.Set(embedtarget.Target{})
		d2 := &RuntimeCapabilityDetector{
			GetRunningBackends: func() map[string]string { return map[string]string{} },
			ListContainers:     func() []string { return []string{"noo-tei"} },
		}
		if caps := d2.Detect(); has(caps, "embed") {
			t.Errorf("stray noo-tei still advertised embed: %v", caps)
		}
	})

	t.Run("a declared embedder advertises embed", func(t *testing.T) {
		embedtarget.Set(embedtarget.Target{
			BaseURL: "https://noo-stunnel-llamacpp:8085", Backend: "llamacpp", Model: "embed.gguf",
		})
		if caps := d.Detect(); !has(caps, "embed") {
			t.Errorf("a declared embedder did not advertise embed: %v", caps)
		}
	})
}
