// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package modelstats turns an ollama's /api/tags and /api/ps bodies into the
// heartbeat's `model_stats`: MEASURED sizes, so the controller's memory-fit
// check for multi-role placements judges real bytes, not a guess from the tag.
package modelstats

import (
	"encoding/json"
	"sort"
	"strings"
)

// ModelStat is one model the ollama holds. Wire shape (heartbeat
// `model_stats` is a JSON list of these):
//
//	{"name","size_bytes","resident_bytes","vram_bytes","loaded"}
//
// size_bytes is the weights (/api/tags size); resident_bytes and vram_bytes
// are /api/ps size and size_vram, and are 0 unless loaded.
type ModelStat struct {
	Name          string `json:"name"`
	SizeBytes     int64  `json:"size_bytes"`
	ResidentBytes int64  `json:"resident_bytes"`
	VRAMBytes     int64  `json:"vram_bytes"`
	Loaded        bool   `json:"loaded"`
}

type entry struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	Size     int64  `json:"size"`
	SizeVRAM int64  `json:"size_vram"`
}

func (e entry) key() string {
	if n := strings.TrimSpace(e.Name); n != "" {
		return n
	}
	return strings.TrimSpace(e.Model)
}

func decode(b []byte) []entry {
	var v struct {
		Models []entry `json:"models"`
	}
	if len(b) == 0 || json.Unmarshal(b, &v) != nil {
		return nil
	}
	return v.Models
}

// Parse merges /api/tags (every model held) with /api/ps (what is loaded).
// A loaded model absent from tags is still listed. Sorted by name; nil when
// neither body yields a model.
func Parse(tags, ps []byte) []ModelStat {
	byName := map[string]*ModelStat{}
	for _, e := range decode(tags) {
		if k := e.key(); k != "" {
			byName[k] = &ModelStat{Name: k, SizeBytes: e.Size}
		}
	}
	for _, e := range decode(ps) {
		k := e.key()
		if k == "" {
			continue
		}
		s := byName[k]
		if s == nil {
			s = &ModelStat{Name: k}
			byName[k] = s
		}
		s.ResidentBytes, s.VRAMBytes, s.Loaded = e.Size, e.SizeVRAM, true
	}
	if len(byName) == 0 {
		return nil
	}
	out := make([]ModelStat, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
