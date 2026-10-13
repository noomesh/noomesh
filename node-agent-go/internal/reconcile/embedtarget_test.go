// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
)

// The bug this guards: /embed was hardcoded to noo-tei, so a node whose
// DECLARED embedder was harrier-on-ollama still answered from a stray TEI
// container with 768-dim bge vectors instead of harrier's 1024. Nothing
// errored — retrieval just silently used the wrong vector space.
func TestResolveEmbedTarget(t *testing.T) {
	tests := []struct {
		name  string
		given []placement
		want  embedtarget.Target
	}{
		{
			name: "ollama declared embed wins over a co-resident tei",
			given: []placement{
				{Backend: "llamacpp", Role: "chat", DesiredState: "running"},
				{Backend: "ollama", Role: "embed", DesiredState: "running", Model: "harrier"},
				{Backend: "embedding", Role: "chat", DesiredState: "running"},
			},
			want: embedtarget.Target{BaseURL: "https://stunnel-ollama:11434", Backend: "ollama", Model: "harrier"},
		},
		{
			name:  "tei declared embed resolves to the tei door",
			given: []placement{{Backend: "embedding", Role: "embed", DesiredState: "running", Model: "BAAI/bge-base-en-v1.5"}},
			want:  embedtarget.Target{BaseURL: "https://stunnel-tei:443", Backend: "embedding", Model: "BAAI/bge-base-en-v1.5"},
		},
		{
			// ollama serving CHAT must never be picked as the embedder --
			// this is the exact ambiguity that put harrier in the chat pool.
			name:  "ollama serving chat is not an embed target",
			given: []placement{{Backend: "ollama", Role: "chat", DesiredState: "running"}},
			want:  embedtarget.Target{},
		},
		{
			name:  "stopped embed placement is ignored",
			given: []placement{{Backend: "ollama", Role: "embed", DesiredState: "stopped"}},
			want:  embedtarget.Target{},
		},
		{
			// A pre-role gateway omits `role` entirely; everything reads as
			// chat and the proxy keeps its historical noo-tei default.
			name:  "missing role field yields no target",
			given: []placement{{Backend: "embedding", DesiredState: "running"}},
			want:  embedtarget.Target{},
		},
		{
			name:  "no placements at all",
			given: nil,
			want:  embedtarget.Target{},
		},
		{
			name:  "unmapped backend is skipped rather than guessed at",
			given: []placement{{Backend: "some-future-embedder", Role: "embed", DesiredState: "running"}},
			want:  embedtarget.Target{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveEmbedTarget(tt.given); got != tt.want {
				t.Errorf("resolveEmbedTarget() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
