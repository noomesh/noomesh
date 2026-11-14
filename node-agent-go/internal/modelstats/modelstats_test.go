// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelstats

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Real-shaped ollama bodies (trimmed): /api/tags `size` is the weights on
// disk; /api/ps `size` is the resident footprint and `size_vram` the part
// of it in GPU memory.
const tagsBody = `{"models":[
 {"name":"gemma4:26b-a4b-it-qat","model":"gemma4:26b-a4b-it-qat","modified_at":"2026-10-01T10:00:00Z","size":15800000000,"digest":"abc","details":{"family":"gemma4"}},
 {"name":"harrier:latest","model":"harrier:latest","size":1200000000,"digest":"def"}
]}`

const psBody = `{"models":[
 {"name":"harrier:latest","model":"harrier:latest","size":1900000000,"digest":"def","expires_at":"0001-01-01T00:00:00Z","size_vram":1900000000},
 {"name":"orphan:1b","model":"orphan:1b","size":900000000,"size_vram":0}
]}`

func TestParse(t *testing.T) {
	cases := []struct {
		name     string
		tags, ps string
		want     []ModelStat
	}{
		{"tags and ps merged", tagsBody, psBody, []ModelStat{
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000, digest: "abc"},
			{Name: "harrier:latest", SizeBytes: 1200000000, digest: "def", ResidentBytes: 1900000000, VRAMBytes: 1900000000, Loaded: true},
			{Name: "orphan:1b", ResidentBytes: 900000000, Loaded: true},
		}},
		{"nothing loaded", tagsBody, `{"models":[]}`, []ModelStat{
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000, digest: "abc"},
			{Name: "harrier:latest", SizeBytes: 1200000000, digest: "def"},
		}},
		{"ps unreachable", tagsBody, ``, []ModelStat{
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000, digest: "abc"},
			{Name: "harrier:latest", SizeBytes: 1200000000, digest: "def"},
		}},
		{"garbage", `x`, `y`, nil},
	}
	for _, c := range cases {
		got := Parse([]byte(c.tags), []byte(c.ps))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

// An /api/show body (trimmed): model_info mirrors the GGUF's keys under the
// architecture's prefix. 262144 is gemma4:12b's, read from its GGUF on awolf.
const showBody = `{"modelfile":"…","details":{"family":"gemma4"},"model_info":{
 "general.architecture":"gemma4","gemma4.block_count":48,"gemma4.context_length":262144,
 "gemma4.attention.head_count_kv":[8,8]}}`

func TestShowContextLengthReadsTheArchitecturesKey(t *testing.T) {
	if got := ShowContextLength([]byte(showBody)); got != 262144 {
		t.Fatalf("ShowContextLength = %d, want 262144", got)
	}
	for _, b := range []string{``, `{}`, `{"model_info":{"gemma4.context_length":8192}}`, `{"model_info":{"general.architecture":"llama"}}`, `not json`} {
		if got := ShowContextLength([]byte(b)); got != 0 {
			t.Errorf("ShowContextLength(%q) = %d, want 0", b, got)
		}
	}
}

// i285: each model's ceiling is asked once per digest, at most showBudget
// new models per beat, and a failed call is asked again next beat.
func TestCeilingsAskOncePerModelWithinTheBudget(t *testing.T) {
	var c Ceilings
	asked := map[string]int{}
	fail := map[string]bool{"harrier:latest": true}
	show := func(name string) ([]byte, error) {
		asked[name]++
		if fail[name] {
			return nil, errTest
		}
		return []byte(showBody), nil
	}
	stats := Parse([]byte(tagsBody), nil)
	c.Fill(stats, show)
	if stats[0].Name != "gemma4:26b-a4b-it-qat" || stats[0].ContextLength != 262144 {
		t.Fatalf("first beat: %+v", stats[0])
	}
	if stats[1].ContextLength != 0 {
		t.Fatalf("a failed show leaves it unknown: %+v", stats[1])
	}
	fail["harrier:latest"] = false
	stats = Parse([]byte(tagsBody), nil)
	c.Fill(stats, show)
	if asked["gemma4:26b-a4b-it-qat"] != 1 || asked["harrier:latest"] != 2 {
		t.Fatalf("asked %v: once for a known model, again after a failure", asked)
	}
	if stats[0].ContextLength != 262144 || stats[1].ContextLength != 262144 {
		t.Fatalf("second beat: %+v", stats)
	}

	many := make([]ModelStat, showBudget+3)
	for i := range many {
		many[i] = ModelStat{Name: string(rune('a' + i)), digest: "d"}
	}
	before := len(asked)
	c.Fill(many, show)
	if got := len(asked) - before; got != showBudget {
		t.Fatalf("asked %d new models in one beat, want %d", got, showBudget)
	}
}

func TestCeilingsKeyOnTheDigest(t *testing.T) {
	var c Ceilings
	n := 0
	show := func(string) ([]byte, error) { n++; return []byte(showBody), nil }
	c.Fill([]ModelStat{{Name: "m:1", digest: "a"}}, show)
	c.Fill([]ModelStat{{Name: "m:1", digest: "a"}}, show)
	c.Fill([]ModelStat{{Name: "m:1", digest: "b"}}, show)
	if n != 2 {
		t.Fatalf("show called %d times, want 2: a re-pulled tag is asked again", n)
	}
}

func TestContextLengthIsOmittedWhileUnknown(t *testing.T) {
	b, _ := json.Marshal(ModelStat{Name: "m"})
	if strings.Contains(string(b), "context_length") || strings.Contains(string(b), "digest") {
		t.Fatalf("wire: %s", b)
	}
	b, _ = json.Marshal(ModelStat{Name: "m", ContextLength: 8192})
	if !strings.Contains(string(b), `"context_length":8192`) {
		t.Fatalf("wire: %s", b)
	}
}

var errTest = errors.New("test: show failed")

func TestHFConfigContextLengthReadsTextConfigFirst(t *testing.T) {
	cases := map[string]int64{
		// Gemma 4 (trimmed): the language model's window is in text_config.
		`{"architectures":["Gemma4ForConditionalGeneration"],"text_config":{"max_position_embeddings":262144},"vision_config":{"max_position_embeddings":4096}}`: 262144,
		`{"max_position_embeddings":40960}`:                                                       40960,
		`{"max_position_embeddings":32768,"rope_scaling":{"type":"yarn","factor":4.0}}`:           0,
		`{"text_config":{"max_position_embeddings":8192,"rope_scaling":{"rope_type":"default"}}}`: 8192,
		`{"rope_scaling":null,"max_position_embeddings":4096}`:                                    4096,
		`{}`:       0,
		`not json`: 0,
		``:         0,
	}
	for body, want := range cases {
		if got := HFConfigContextLength([]byte(body)); got != want {
			t.Errorf("%s: %d, want %d", body, got, want)
		}
	}
}

func TestLlamaTrainContextPicksTheServedModel(t *testing.T) {
	body := []byte(`{"object":"list","data":[
 {"id":"other.gguf","meta":{"n_ctx_train":4096,"size":100}},
 {"id":"gemma-4-12b-it-Q4_K_M.gguf","object":"model","meta":{"vocab_type":1,"n_vocab":262144,"n_ctx_train":262144,"n_embd":3840,"n_params":11766034688,"size":7300000000}}]}`)
	if c, s := LlamaTrainContext(body, "gemma-4-12b-it-Q4_K_M.gguf"); c != 262144 || s != 7300000000 {
		t.Errorf("served: ctx %d size %d", c, s)
	}
	if c, _ := LlamaTrainContext(body, "unknown"); c != 4096 {
		t.Errorf("no match falls back to the first entry: ctx %d", c)
	}
	if c, s := LlamaTrainContext([]byte(`{"data":[]}`), "x"); c != 0 || s != 0 {
		t.Errorf("empty list: %d %d", c, s)
	}
}

func TestMergeFillsAndAppends(t *testing.T) {
	stats := []ModelStat{{Name: "b", SizeBytes: 5}, {Name: "a", ContextLength: 100}}
	got := Merge(stats, []ModelStat{{Name: "a", ContextLength: 999}, {Name: "b", ContextLength: 200}, {Name: "c", ContextLength: 300, Loaded: true}})
	want := []ModelStat{{Name: "a", ContextLength: 100}, {Name: "b", SizeBytes: 5, ContextLength: 200}, {Name: "c", ContextLength: 300, Loaded: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if got := Merge(nil, nil); got != nil {
		t.Errorf("nothing merged into nothing: %+v", got)
	}
}

// i495 item 4: a failed /api/ps is "loaded unknown", never "not loaded".
func TestParseCheckedFailedPsIsUnknownNotUnloaded(t *testing.T) {
	got := ParseChecked([]byte(tagsBody), nil, false)
	if len(got) != 2 {
		t.Fatalf("models = %+v, want the two on disk", got)
	}
	for _, s := range got {
		if !s.LoadedUnknown || s.Loaded || s.ResidentBytes != 0 || s.VRAMBytes != 0 {
			t.Errorf("%s = %+v, want LoadedUnknown with nothing claimed", s.Name, s)
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		for _, k := range []string{"loaded", "resident_bytes", "vram_bytes"} {
			if _, ok := m[k]; ok {
				t.Errorf("%s: wire shape carries %q while unknown: %s", s.Name, k, b)
			}
		}
		if m["name"] != s.Name || m["size_bytes"] == nil {
			t.Errorf("%s: name and size_bytes must still ride: %s", s.Name, b)
		}
	}
	// A ps that ANSWERED with nothing loaded is a fact: loaded:false, 0 bytes.
	known := ParseChecked([]byte(tagsBody), []byte(`{"models":[]}`), true)
	b, _ := json.Marshal(known[0])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if v, ok := m["loaded"]; !ok || v != false || m["resident_bytes"] != float64(0) {
		t.Errorf("answered-empty ps must report loaded:false and 0 bytes, got %s", b)
	}
}

// i802: /api/ps's context_length is what the loaded model RUNS at (4096 on a
// stock CPU ollama), reported as running_context beside the ceiling, never in
// place of it; absent while not loaded or while ps is unknown.
func TestRunningContextComesFromPsBesideTheCeiling(t *testing.T) {
	tags := `{"models":[{"name":"gemma4:e2b","size":4600000000},{"name":"harrier:latest","size":396705831}]}`
	ps := `{"models":[{"name":"gemma4:e2b","size":1300000000,"size_vram":0,"context_length":4096}]}`
	got := ParseChecked([]byte(tags), []byte(ps), true)
	byName := map[string]ModelStat{}
	for _, s := range got {
		byName[s.Name] = s
	}
	g := byName["gemma4:e2b"]
	g.ContextLength = 131072 // the ceiling, filled from /api/show elsewhere
	b, _ := json.Marshal(g)
	if !strings.Contains(string(b), `"running_context":4096`) || !strings.Contains(string(b), `"context_length":131072`) {
		t.Fatalf("want both the running context and the ceiling: %s", b)
	}
	if h, _ := json.Marshal(byName["harrier:latest"]); strings.Contains(string(h), "running_context") {
		t.Errorf("a model not loaded has no running context: %s", h)
	}
	unknown := ParseChecked([]byte(tags), []byte(ps), false)
	for _, s := range unknown {
		if b, _ := json.Marshal(s); strings.Contains(string(b), "running_context") {
			t.Errorf("ps unknown: no running context claimed: %s", b)
		}
	}
}
