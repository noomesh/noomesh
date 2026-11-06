// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/lanes"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

// fixtureInputs hold one lane of every state, a non-chat lane, and a
// running_backends entry for the loading lane's backend that names the OLD
// model: the gateway must ignore running_backends when lanes is present.
func fixtureInputs() (lanes.Inputs, map[string]string) {
	running := map[string]string{
		"vllm":      "org/old-model",
		"ollama":    "gemma4:12b",
		"llamacpp":  "m.gguf",
		"airllm":    "org/air-model",
		"embedding": "BAAI/bge-small",
	}
	return lanes.Inputs{
		Placed: []lanes.Placed{
			{Backend: "vllm", Model: "org/new-model", Role: "chat"},
			{Backend: "ollama", Model: "gemma4:12b", Role: "chat"},
			{Backend: "ollama", Model: "qwen3:4b", Role: "chat"},
			{Backend: "ollama", Model: "harrier", Role: "embed"},
			{Backend: "ollama", Model: "mystery:7b", Role: "chat"},
			{Backend: "llamacpp", Model: "m.gguf", Role: ""},
			{Backend: "reranker", Model: "bge-rerank.gguf", Role: "rerank"},
			{Backend: "airllm", Model: "org/air-model", Role: "chat"},
		},
		Presence: map[string]modelpresence.Entry{
			"ollama":       {Model: "gemma4:12b", Role: "chat", Present: true},
			"ollama#embed": {Model: "harrier", Role: "embed", Present: false},
		},
		Running:  running,
		Runtimes: map[string]string{"vllm": "docker", "ollama": "docker", "llamacpp": "docker", "embedding": "docker", "airllm": "docker"},
		// airllm runs but has NO entry: no health report, so down, never
		// serving (i495 item 4).
		Containers: map[string]any{
			"vllm":     map[string]any{"running": true, "health": "healthy"},
			"llamacpp": map[string]any{"running": true, "health": "healthy"},
		},
		Ollama: lanes.Ollama{Known: true,
			OnDisk: map[string]bool{"gemma4:12b": true, "qwen3:4b": true},
			Loaded: map[string]bool{"gemma4:12b": true}},
	}, running
}

func fixturePayload() map[string]any {
	in, running := fixtureInputs()
	ls, _ := lanes.Build(in)
	return map[string]any{"lanes": ls, "running_backends": running}
}

// The gateway session copies testdata/lanes_fixture.json; the builder's
// output must equal it, so the two halves cannot drift apart.
func TestLanesFixtureMatchesBuilder(t *testing.T) {
	raw, err := os.ReadFile("testdata/lanes_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(fixturePayload())
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("builder output differs from the fixture:\n got %s\nwant %s", b, raw)
	}
	// The fixture must keep covering what the gateway tests lean on.
	states := map[string]string{}
	for _, l := range want["lanes"].([]any) {
		m := l.(map[string]any)
		states[m["state"].(string)] = m["reason"].(string)
	}
	for _, s := range []string{"serving", "on_demand", "loading", "missing", "unplaced", "unknown", "down"} {
		if _, ok := states[s]; !ok {
			t.Errorf("fixture has no %s lane", s)
		}
	}
	hasNoReport := false
	for _, l := range want["lanes"].([]any) {
		if m := l.(map[string]any); m["backend"] == "airllm" && m["state"] == "down" && m["reason"] == "no health report" {
			hasNoReport = true
		}
	}
	if !hasNoReport {
		t.Error("fixture has no down / no health report lane")
	}
	if states["unknown"] != "no presence yet" {
		t.Errorf("unknown reason = %q", states["unknown"])
	}
	if states["loading"] != "reconciling: runtime runs org/old-model" {
		t.Errorf("loading reason = %q", states["loading"])
	}
	if want["running_backends"].(map[string]any)["vllm"] != "org/old-model" {
		t.Errorf("fixture lost the stale running_backends entry: %v", want["running_backends"])
	}
	hasEmbed := false
	for _, l := range want["lanes"].([]any) {
		if l.(map[string]any)["role"] == "embed" {
			hasEmbed = true
		}
	}
	if !hasEmbed {
		t.Error("fixture has no non-chat lane")
	}
}

// A bare reporter's heartbeat always carries `lanes`, as an empty list.
func TestHeartbeatAlwaysCarriesLanes(t *testing.T) {
	lanes.SetPlaced(nil)
	beat, _ := capturePayloads(t)
	got, ok := beat["lanes"].([]any)
	if !ok || len(got) != 0 {
		t.Errorf("lanes must be an EMPTY LIST, always sent: %#v", beat["lanes"])
	}
}

// The reporter feeds Build from the payload sections and the registries.
func TestReporterLanesReportReadsPayloadAndPlacements(t *testing.T) {
	modelpresence.Reset()
	t.Cleanup(func() { modelpresence.Reset(); lanes.SetPlaced(nil) })
	lanes.SetPlaced([]lanes.Placed{
		{Backend: "ollama", Model: "gemma4:12b", Role: "chat"},
		{Backend: "ollama", Model: "qwen3:4b", Role: "chat"},
	})
	r := &Reporter{}
	r.SetHeldModels(func() []string { return []string{"qwen3:4b"} })
	got := r.lanesReport(map[string]any{
		"running_backends": map[string]string{"ollama": "gemma4:12b"},
		"model_stats":      []ModelStat{{Name: "gemma4:12b", Loaded: true}},
	})
	want := []lanes.Lane{
		{Backend: "ollama", Model: "gemma4:12b", Role: "chat", State: "serving"},
		{Backend: "ollama", Model: "qwen3:4b", Role: "chat", State: "on_demand", Reason: "not loaded"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}
