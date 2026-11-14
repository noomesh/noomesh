// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/keepwarm"
)

// The flag rides desired-config as `keep_warm`; absent (a gateway that
// predates it) is false.
func TestKeepWarmDecodesFromDesiredConfigAndDefaultsOff(t *testing.T) {
	var d desiredConfig
	if err := json.Unmarshal([]byte(`{"placements":[
		{"backend":"ollama","model":"gemma4:12b","desired_state":"running","keep_warm":true},
		{"backend":"ollama","model":"harrier","role":"embed","desired_state":"running"}]}`), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Placements[0].KeepWarm || d.Placements[1].KeepWarm {
		t.Fatalf("keep_warm: %+v", d.Placements)
	}
}

// Only running ollama placements that declare it; the embedder beside them
// and a stopped row are not warm.
func TestPublishKeepWarmNamesOnlyDeclaredRunningOllamaModels(t *testing.T) {
	t.Cleanup(func() { keepwarm.Set(nil) })
	publishKeepWarm([]placement{
		{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running", KeepWarm: true, Target: "gpu"},
		{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"},
		{Backend: "ollama", Model: "gemma4:e2b", DesiredState: "stopped", KeepWarm: true},
		{Backend: "vllm", Model: "org/m", DesiredState: "running", KeepWarm: true},
	})
	want := []keepwarm.Warm{{Model: "gemma4:12b", Target: "gpu"}}
	if got := keepwarm.All(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	// The flag cleared: the set empties on the next pass.
	publishKeepWarm([]placement{{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running"}})
	if got := keepwarm.All(); len(got) != 0 {
		t.Fatalf("cleared flag still warm: %#v", got)
	}
}

// keep_warm changes no container: the spec hash ignores it, so turning it on
// never recreates the ollama.
func TestKeepWarmIsNotInTheSpecHash(t *testing.T) {
	p := placement{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running"}
	q := p
	q.KeepWarm = true
	if specHash(p) != specHash(q) {
		t.Fatal("keep_warm must not recreate the container")
	}
}
