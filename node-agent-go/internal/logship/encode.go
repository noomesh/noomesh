// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
)

const (
	// BodyCapBytes is the gateway's cap, on the wire and decoded (413
	// beyond it). Never sent.
	BodyCapBytes = 4 << 20
	// SplitBelowBytes is what we actually stay under: a batch whose JSON
	// exceeds it is halved until every piece fits, so a burst of long
	// lines cannot produce a 413 that would then be dropped.
	SplitBelowBytes = 3 << 20
	// MaxStreams / MaxValues are the gateway's per-push counts (400
	// beyond them); a piece is halved past either.
	MaxStreams = 64
	MaxValues  = 20_000
)

// wireStream is one Loki stream: a label map and [ts, line] pairs.
type wireStream struct {
	Labels map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type wireBody struct {
	Streams []wireStream `json:"streams"`
}

// encode renders entries as the push body, grouped into streams by label
// set in first-seen order. Entries within a stream keep arrival order.
func encode(node string, entries []Entry) []byte {
	b, _ := json.Marshal(build(node, entries))
	return b
}

func build(node string, entries []Entry) wireBody {
	idx := map[string]int{}
	body := wireBody{Streams: []wireStream{}}
	for _, e := range entries {
		k := e.Labels.key()
		i, ok := idx[k]
		if !ok {
			i = len(body.Streams)
			idx[k] = i
			body.Streams = append(body.Streams, wireStream{Labels: e.Labels.wire(node)})
		}
		body.Streams[i].Values = append(body.Streams[i].Values, [2]string{nsString(e.TS), e.Line})
	}
	return body
}

// fits reports whether entries make one acceptable push.
func fits(node string, entries []Entry, capBytes int) bool {
	if len(entries) > MaxValues {
		return false
	}
	body := build(node, entries)
	if len(body.Streams) > MaxStreams {
		return false
	}
	b, _ := json.Marshal(body)
	return len(b) <= capBytes
}

// splitEntries halves entries until each piece fits (bytes, streams,
// values). A single entry that is itself over the cap goes alone — the
// gateway's 413 then drops that one line, loudly, not the batch around it.
func splitEntries(node string, entries []Entry, capBytes int) [][]Entry {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) == 1 || fits(node, entries, capBytes) {
		return [][]Entry{entries}
	}
	mid := len(entries) / 2
	return append(splitEntries(node, entries[:mid], capBytes), splitEntries(node, entries[mid:], capBytes)...)
}

// splitBelowCap is splitEntries, encoded.
func splitBelowCap(node string, entries []Entry, capBytes int) [][]byte {
	var out [][]byte
	for _, p := range splitEntries(node, entries, capBytes) {
		out = append(out, encode(node, p))
	}
	return out
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
