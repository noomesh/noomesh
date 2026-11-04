// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package lanes

import (
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

func healthy() map[string]any {
	return map[string]any{"running": true, "started_at": int64(1790000000), "health": "healthy"}
}

func TestBuild_States(t *testing.T) {
	docker := map[string]string{"vllm": "docker", "reranker": "docker", "llamacpp": "docker", "embedding": "docker"}
	tests := []struct {
		name string
		in   Inputs
		want []Lane
		// unnamed: running backends with no placement and no model name.
		unnamed []string
	}{
		{
			name: "missing: presence says not on disk",
			in: Inputs{
				Placed:   []Placed{{"ollama", "gemma4:12b", "chat"}},
				Presence: map[string]modelpresence.Entry{"ollama": {Model: "gemma4:12b", Role: "chat", Present: false}},
				Running:  map[string]string{"ollama": "gemma4:12b"},
			},
			want: []Lane{{"ollama", "gemma4:12b", "chat", StateMissing, ReasonNotOnDisk}},
		},
		{
			name: "missing beats a mismatching runtime",
			in: Inputs{
				Placed:   []Placed{{"llamacpp", "b.gguf", ""}},
				Presence: map[string]modelpresence.Entry{"llamacpp": {Model: "b.gguf", Role: "chat", Present: false}},
				Running:  map[string]string{"llamacpp": "a.gguf"}, Runtimes: docker,
			},
			want: []Lane{{"llamacpp", "b.gguf", "", StateMissing, ReasonNotOnDisk}},
		},
		{
			name: "mismatch: loading, reconciling, no lane for the old model",
			in: Inputs{
				Placed:     []Placed{{"vllm", "org/new", "chat"}},
				Running:    map[string]string{"vllm": "org/old"},
				Runtimes:   docker,
				Containers: map[string]any{"vllm": healthy()},
			},
			want: []Lane{{"vllm", "org/new", "chat", StateLoading, "reconciling: runtime runs org/old"}},
		},
		{
			name: "health starting: loading",
			in: Inputs{
				Placed:   []Placed{{"vllm", "org/m", "chat"}},
				Running:  map[string]string{"vllm": "org/m"},
				Runtimes: docker,
				Containers: map[string]any{"vllm": map[string]any{
					"running": true, "health": "starting"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateLoading, ReasonStarting}},
		},
		{
			name: "warmup running without a healthcheck: loading, warming",
			in: Inputs{
				Placed:   []Placed{{"vllm", "org/m", "chat"}},
				Running:  map[string]string{"vllm": "org/m"},
				Runtimes: docker,
				Containers: map[string]any{"vllm": map[string]any{
					"running": true, "warmup": "running"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateLoading, ReasonWarming}},
		},
		{
			name: "not serving with a warmup reason: loading, warming",
			in: Inputs{
				Placed:   []Placed{{"vllm", "org/m", "chat"}},
				Running:  map[string]string{"vllm": "org/m"},
				Runtimes: docker,
				Containers: map[string]any{"vllm": map[string]any{
					"running": true, "health": "healthy", "serving": false, "serving_reason": "engine warming up"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateLoading, ReasonWarming}},
		},
		{
			name: "docker serving: model equal after trim, healthy",
			in: Inputs{
				Placed:     []Placed{{"vllm", "org/m", "chat"}},
				Running:    map[string]string{"vllm": " org/m\n"},
				Runtimes:   docker,
				Containers: map[string]any{"vllm": healthy()},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateServing, ReasonNone}},
		},
		{
			name: "docker non-chat role is emitted verbatim",
			in: Inputs{
				Placed:     []Placed{{"reranker", "bge-rerank.gguf", "rerank"}},
				Running:    map[string]string{"reranker": "bge-rerank.gguf"},
				Runtimes:   docker,
				Containers: map[string]any{"reranker": healthy()},
			},
			want: []Lane{{"reranker", "bge-rerank.gguf", "rerank", StateServing, ReasonNone}},
		},
		{
			name: "docker same model but unhealthy: down, unhealthy",
			in: Inputs{
				Placed:   []Placed{{"vllm", "org/m", "chat"}},
				Running:  map[string]string{"vllm": "org/m"},
				Runtimes: docker,
				Containers: map[string]any{"vllm": map[string]any{
					"running": true, "health": "unhealthy"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateDown, ReasonUnhealthy}},
		},
		{
			name: "docker not serving for a non-warmup reason: down, unhealthy",
			in: Inputs{
				Placed:   []Placed{{"vllm", "org/m", "chat"}},
				Running:  map[string]string{"vllm": "org/m"},
				Runtimes: docker,
				Containers: map[string]any{"vllm": map[string]any{
					"running": true, "health": "healthy", "serving": false, "serving_reason": "probe timed out"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateDown, ReasonUnhealthy}},
		},
		{
			name: "docker placed but not running: down, not running",
			in:   Inputs{Placed: []Placed{{"vllm", "org/m", "chat"}}},
			want: []Lane{{"vllm", "org/m", "chat", StateDown, ReasonNotRunning}},
		},
		{
			name: "llamacpp placed path vs reported basename is the same model (reconciler rule)",
			in: Inputs{
				Placed:     []Placed{{"llamacpp", "/models/x.gguf", "chat"}},
				Running:    map[string]string{"llamacpp": "x.gguf"},
				Runtimes:   docker,
				Containers: map[string]any{"llamacpp": healthy()},
			},
			want: []Lane{{"llamacpp", "/models/x.gguf", "chat", StateServing, ReasonNone}},
		},
		{
			name: "native non-ollama runs another model: down, not running",
			in: Inputs{
				Placed:   []Placed{{"llamacpp", "b.gguf", "chat"}},
				Running:  map[string]string{"llamacpp": "a.gguf"},
				Runtimes: map[string]string{"llamacpp": "native"},
			},
			want: []Lane{{"llamacpp", "b.gguf", "chat", StateDown, ReasonNotRunning}},
		},
		{
			name: "docker runtime names no model: down, unnamed backend",
			in: Inputs{
				Placed:     []Placed{{"embedding", "BAAI/bge", "embed"}},
				Running:    map[string]string{"embedding": "tei"},
				Runtimes:   docker,
				Containers: map[string]any{"embedding": healthy()},
			},
			want: []Lane{{"embedding", "BAAI/bge", "embed", StateDown, ReasonUnnamedBackend}},
		},
		{
			name: "two placed ollama models give two lanes: serving and on_demand",
			in: Inputs{
				Placed: []Placed{{"ollama", "gemma4:12b", "chat"}, {"ollama", "harrier", "embed"}},
				Presence: map[string]modelpresence.Entry{
					"ollama":       {Model: "gemma4:12b", Role: "chat", Present: true},
					"ollama#embed": {Model: "harrier", Role: "embed", Present: true},
				},
				Running: map[string]string{"ollama": "gemma4:12b"},
				Ollama: Ollama{Known: true,
					OnDisk: map[string]bool{"gemma4:12b": true, "harrier:latest": true},
					Loaded: map[string]bool{"gemma4:12b": true}},
			},
			want: []Lane{
				{"ollama", "gemma4:12b", "chat", StateServing, ReasonNone},
				{"ollama", "harrier", "embed", StateOnDemand, ReasonNotLoaded},
			},
		},
		{
			name: "ollama on_demand from the held set",
			in: Inputs{
				Placed:  []Placed{{"ollama", "gemma4:12b", ""}},
				Running: map[string]string{"ollama": "gemma4:12b"},
				Ollama:  Ollama{Held: map[string]bool{"gemma4:12b": true}},
			},
			want: []Lane{{"ollama", "gemma4:12b", "", StateOnDemand, ReasonNotLoaded}},
		},
		{
			name: "ollama with nothing known and no presence: unknown, no presence yet",
			in: Inputs{
				Placed:  []Placed{{"ollama", "gemma4:12b", "chat"}},
				Running: map[string]string{"ollama": "gemma4:12b"},
			},
			want: []Lane{{"ollama", "gemma4:12b", "chat", StateUnknown, ReasonNoPresenceYet}},
		},
		{
			name: "ollama not running: down, not running",
			in:   Inputs{Placed: []Placed{{"ollama", "gemma4:12b", "chat"}}},
			want: []Lane{{"ollama", "gemma4:12b", "chat", StateDown, ReasonNotRunning}},
		},
		{
			name: "bare placed name with :latest loaded is serving",
			in: Inputs{
				Placed:  []Placed{{"ollama", "harrier", "embed"}},
				Running: map[string]string{"ollama": "gemma4:12b"},
				Ollama:  Ollama{Known: true, Loaded: map[string]bool{"harrier:latest": true}},
			},
			want: []Lane{{"ollama", "harrier", "embed", StateServing, ReasonNone}},
		},
		{
			name: "placed :latest with the bare name on disk is on_demand",
			in: Inputs{
				Placed:  []Placed{{"ollama", "harrier:latest", "embed"}},
				Running: map[string]string{"ollama": "gemma4:12b"},
				Ollama:  Ollama{Known: true, OnDisk: map[string]bool{"harrier": true}},
			},
			want: []Lane{{"ollama", "harrier:latest", "embed", StateOnDemand, ReasonNotLoaded}},
		},
		{
			name: "other tags are not :latest",
			in: Inputs{
				Placed:  []Placed{{"ollama", "gemma4", "chat"}},
				Running: map[string]string{"ollama": "gemma4:12b"},
				Ollama:  Ollama{Known: true, Loaded: map[string]bool{"gemma4:12b": true}},
			},
			want: []Lane{{"ollama", "gemma4", "chat", StateUnknown, ReasonNoPresenceYet}},
		},
		{
			name: "ollama health starting: loading",
			in: Inputs{
				Placed:     []Placed{{"ollama", "gemma4:12b", "chat"}},
				Running:    map[string]string{"ollama": "gemma4:12b"},
				Containers: map[string]any{"ollama": map[string]any{"running": true, "health": "starting"}},
			},
			want: []Lane{{"ollama", "gemma4:12b", "chat", StateLoading, ReasonStarting}},
		},
		{
			name: "unplaced running backend that names its model",
			in: Inputs{
				Running:  map[string]string{"llamacpp": "native.gguf", "embedding": "BAAI/bge"},
				Runtimes: docker,
			},
			want: []Lane{
				{"embedding", "BAAI/bge", "embed", StateUnplaced, ReasonNone},
				{"llamacpp", "native.gguf", "", StateUnplaced, ReasonNone},
			},
		},
		{
			name: "unnamed unplaced backends give no lane; the harness is not a lane",
			in: Inputs{
				Running:  map[string]string{"vllm": "", "ollama": "ollama", "harness": "auto"},
				Runtimes: docker,
			},
			want:    []Lane{},
			unnamed: []string{"ollama", "vllm"},
		},
		{
			name: "placed rows with no model and harness rows are skipped; duplicates collapse",
			in: Inputs{
				Placed: []Placed{{"vllm", " ", "chat"}, {"harness", "x", ""}, {"vllm", "org/m", "chat"}, {"vllm", "org/m", "chat"}},
			},
			want: []Lane{{"vllm", "org/m", "chat", StateDown, ReasonNotRunning}},
		},
		{
			name: "no placements and nothing running: an empty slice, not nil",
			in:   Inputs{},
			want: []Lane{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, unnamed := Build(tc.in)
			if got == nil || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lanes:\n got %#v\nwant %#v", got, tc.want)
			}
			if !reflect.DeepEqual(unnamed, tc.unnamed) {
				t.Errorf("unnamed: got %v want %v", unnamed, tc.unnamed)
			}
			for _, l := range got {
				if l.Model == "" {
					t.Errorf("a lane has no model: %#v", l)
				}
			}
		})
	}
}

func TestBuild_ModelIsPlacedStringVerbatim(t *testing.T) {
	got, _ := Build(Inputs{
		Placed:     []Placed{{"vllm", "Org/Model-A ", "chat"}},
		Running:    map[string]string{"vllm": "Org/Model-A"},
		Runtimes:   map[string]string{"vllm": "docker"},
		Containers: map[string]any{"vllm": healthy()},
	})
	if len(got) != 1 || got[0].Model != "Org/Model-A " || got[0].State != StateServing {
		t.Errorf("got %#v", got)
	}
}

func TestPlacedRoundTrip(t *testing.T) {
	SetPlaced([]Placed{{"ollama", "m", "chat"}})
	if got := PlacedNow(); !reflect.DeepEqual(got, []Placed{{"ollama", "m", "chat"}}) {
		t.Errorf("got %#v", got)
	}
	SetPlaced(nil)
	if got := PlacedNow(); len(got) != 0 {
		t.Errorf("got %#v", got)
	}
}
