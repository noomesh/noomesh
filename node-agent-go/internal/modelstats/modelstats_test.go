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
