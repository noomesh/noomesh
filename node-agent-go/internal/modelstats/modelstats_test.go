// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelstats

import (
	"reflect"
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
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000},
			{Name: "harrier:latest", SizeBytes: 1200000000, ResidentBytes: 1900000000, VRAMBytes: 1900000000, Loaded: true},
			{Name: "orphan:1b", ResidentBytes: 900000000, Loaded: true},
		}},
		{"nothing loaded", tagsBody, `{"models":[]}`, []ModelStat{
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000},
			{Name: "harrier:latest", SizeBytes: 1200000000},
		}},
		{"ps unreachable", tagsBody, ``, []ModelStat{
			{Name: "gemma4:26b-a4b-it-qat", SizeBytes: 15800000000},
			{Name: "harrier:latest", SizeBytes: 1200000000},
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
