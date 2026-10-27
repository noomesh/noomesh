// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package modelstats turns an ollama's /api/tags and /api/ps bodies into the
// heartbeat's `model_stats`: MEASURED sizes, so the controller's memory-fit
// check for multi-role placements judges real bytes, not a guess from the tag.
// [Ceilings] adds each model's own context ceiling from /api/show, so the
// controller caps a harness window by what the weights declare rather than a
// table in core (noomesh-internal i285).
package modelstats

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// ModelStat is one model the ollama holds. Wire shape (heartbeat
// `model_stats` is a JSON list of these):
//
//	{"name","size_bytes","resident_bytes","vram_bytes","loaded","context_length"}
//
// size_bytes is the weights (/api/tags size); resident_bytes and vram_bytes
// are /api/ps size and size_vram, and are 0 unless loaded. context_length is
// the model's own context ceiling (/api/show `<arch>.context_length`),
// omitted while not known.
type ModelStat struct {
	Name          string `json:"name"`
	SizeBytes     int64  `json:"size_bytes"`
	ResidentBytes int64  `json:"resident_bytes"`
	VRAMBytes     int64  `json:"vram_bytes"`
	Loaded        bool   `json:"loaded"`
	ContextLength int64  `json:"context_length,omitempty"`
	// digest is /api/tags' digest: a re-pulled tag is a different model.
	digest string
}

type entry struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	Size     int64  `json:"size"`
	SizeVRAM int64  `json:"size_vram"`
	Digest   string `json:"digest"`
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
			byName[k] = &ModelStat{Name: k, SizeBytes: e.Size, digest: e.Digest}
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

// ShowContextLength is the model's own context ceiling from an /api/show
// body: model_info's `<general.architecture>.context_length`. 0 when the
// body does not say.
func ShowContextLength(body []byte) int64 {
	var v struct {
		ModelInfo map[string]any `json:"model_info"`
	}
	if len(body) == 0 || json.Unmarshal(body, &v) != nil {
		return 0
	}
	arch, _ := v.ModelInfo["general.architecture"].(string)
	if arch == "" {
		return 0
	}
	n, _ := v.ModelInfo[arch+".context_length"].(float64)
	if n <= 0 {
		return 0
	}
	return int64(n)
}

// showBudget bounds the /api/show calls one heartbeat makes: a node that
// holds many models learns their ceilings over a few beats instead of
// stalling one.
const showBudget = 2

// Ceilings remembers each model's context ceiling by name and digest, so
// /api/show runs once per model, not once per heartbeat. The zero value is
// ready to use.
type Ceilings struct {
	mu    sync.Mutex
	known map[string]int64
}

// Fill sets ContextLength on stats from what is remembered, asking `show`
// (an /api/show for one model name) for at most [showBudget] models it does
// not know yet. A failed call is not remembered: the next beat asks again.
func (c *Ceilings) Fill(stats []ModelStat, show func(name string) ([]byte, error)) {
	if c == nil || show == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.known == nil {
		c.known = map[string]int64{}
	}
	asked := 0
	for i := range stats {
		key := stats[i].Name + "@" + stats[i].digest
		n, ok := c.known[key]
		if !ok {
			if asked >= showBudget {
				continue
			}
			asked++
			body, err := show(stats[i].Name)
			if err != nil {
				continue
			}
			n = ShowContextLength(body)
			c.known[key] = n
		}
		stats[i].ContextLength = n
	}
}
