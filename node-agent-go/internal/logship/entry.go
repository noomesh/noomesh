// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package logship ships this node's logs to the controller.
//
// The unprivileged node agent is the shipper (fleet logging plan:
// it already dials the controller with the node leaf and the cluster
// token, already holds the docker socket, and already tails files. What it
// cannot read — the journal — noo-hostd follows into a spool file for it
// (hostd `journal-follow`; hostd has no network, the agent has no journal
// group, and each half keeps the privilege it had).
//
// Push path: POST {controller}/api/cluster/nodes/{self}/logs, gzip JSON,
// authenticated exactly as the heartbeat is. The gateway verifies the node
// (cert + cluster token, `{self}` binding), overwrites the `node` label with
// the verified id and forwards to Loki. Nothing here ever dials Loki, and
// nothing here ever speaks plaintext: an http:// controller is refused at
// construction.
//
// Wire body (the Loki push shape the gateway accepts):
//
//	{"streams":[{"stream":{"source":"journal"|"docker"|"file","name":…,
//	  "stream":"stdout"|"stderr"|"journal","level":"debug"|"info"|"warn"|"error"|"unknown",
//	  "compose_service":…},"values":[["<ts_ns>","<line>"],…]}]}
//
// Status contract (gateway phase 2): 204 accepted. 400/413 = the batch is
// malformed or too large — drop it, say so once per reason per 5 min.
// 401/403 = a credential problem — KEEP the batch, back off. 429 = keep,
// wait Retry-After. 503 = Loki away — keep, retry with backoff (1 s → 60 s,
// jitter). 404 = an older gateway — keep, re-probe every 10 min. A refusal
// body carries {"error","reason","retry"}; `retry` is believed when present.
package logship

import "strconv"

// Sources.
const (
	SourceDocker  = "docker"
	SourceJournal = "journal"
	SourceFile    = "file"
)

// Streams.
const (
	StreamStdout  = "stdout"
	StreamStderr  = "stderr"
	StreamJournal = "journal"
)

// LevelUnknown is what a line with no recognisable level carries — the
// gateway's contract names it, and an empty label is not the same thing.
const LevelUnknown = "unknown"

// maxLabelValue is the gateway's per-value cap (400 beyond it). Names are
// truncated here rather than refused there: a long container name must
// not silence the whole batch it rides in.
const maxLabelValue = 128

// Labels is the FIXED label set. Every key is low-cardinality by
// construction — a free-text field promoted to a label is a cardinality
// bomb on Loki's index, which is why promtail's `module`/`event` regex
// labels are not carried over. `node` is not here: the gateway sets it
// from the verified identity and would overwrite anything we sent.
type Labels struct {
	Source         string
	Name           string
	Stream         string
	Level          string // debug|info|warn|error|unknown — see ExtractLevel
	ComposeService string // compose label when present, else ""
}

// key groups entries into streams.
func (l Labels) key() string {
	return l.Source + "\x00" + l.Name + "\x00" + l.Stream + "\x00" + l.Level + "\x00" + l.ComposeService
}

// flowKey is where an entry came from, without its level (a PEM body and
// its last line may be read at different levels): the context RedactAfter
// is carried across.
func (l Labels) flowKey() string { return l.Source + "\x00" + l.Name + "\x00" + l.Stream }

func clip(s string) string {
	if len(s) > maxLabelValue {
		return s[:maxLabelValue]
	}
	return s
}

// wire renders the label map the gateway expects. `node` is sent for
// readability only (the gateway overwrites it); compose_service is omitted
// when empty so a worker's streams carry exactly the five fixed keys.
func (l Labels) wire(node string) map[string]string {
	level := l.Level
	if level == "" {
		level = LevelUnknown
	}
	m := map[string]string{
		"node":   clip(node),
		"source": clip(l.Source),
		"name":   clip(l.Name),
		"stream": clip(l.Stream),
		"level":  level,
	}
	if l.ComposeService != "" {
		m["compose_service"] = clip(l.ComposeService)
	}
	return m
}

// Entry is one log line with its labels. TS is unix nanoseconds.
type Entry struct {
	TS     int64  `json:"ts"`
	Line   string `json:"line"`
	Labels Labels `json:"labels"`
	// Redacted counts the credential shapes scrubbed out of Line at intake
	// (redact.go). Carried through the spill so the per-batch debug line
	// stays right across a restart; never on the wire.
	Redacted int `json:"redacted,omitempty"`
}

func (e Entry) size() int { return len(e.Line) + 64 }

func nsString(ts int64) string { return strconv.FormatInt(ts, 10) }
