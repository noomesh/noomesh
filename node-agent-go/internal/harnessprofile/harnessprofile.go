// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package harnessprofile holds this node's resolved harness profile: the
// per-node defaults the controller resolves (tier default, refined by a
// per-node override and by a measured model speed) and serves in
// desired-config as `harness_profile`.
//
// The controller owns the resolution; this package only holds the last good
// answer. The reconciler stores it on every successful desired-config fetch
// (Set), and the parts of the agent that apply a field read it (Current):
// the inference proxy's first-byte wait, the ollama context default, the
// foreign-kind refusal and GET /harness/placement.
//
// A fetch that FAILS keeps the last good profile (the reconciler never calls
// Set on a failed fetch). A fetch that answers without one clears it: no
// profile is today's behaviour, everywhere it is read.
package harnessprofile

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
)

// Profile is the resolved shape (the contract's section 4). Raw is the object
// exactly as the controller sent it, so GET /harness/placement passes it to
// the harness without dropping a field this agent does not model.
type Profile struct {
	Tier           int               `json:"tier"`
	FirstByteSecs  int               `json:"first_byte_secs"`
	StreamIdleSecs int               `json:"stream_idle_secs"`
	Thinking       string            `json:"thinking"`
	OllamaContext  int               `json:"ollama_context"`
	ClaudePrompt   string            `json:"claude_prompt"`
	ForeignKinds   []string          `json:"foreign_kinds"`
	Sources        map[string]string `json:"sources"`
	Bench          json.RawMessage   `json:"bench"`

	Raw json.RawMessage `json:"-"`
}

// Offers says whether the profile lists a foreign harness kind.
func (p *Profile) Offers(kind string) bool {
	for _, k := range p.ForeignKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Parse reads desired-config's `harness_profile`. Absent or JSON null is
// (nil, nil): no profile. Anything else must be an object that decodes into
// the shape; numbers that are not positive are dropped to 0 (field unset)
// rather than applied, so a bad value can never remove a bound.
func Parse(raw json.RawMessage) (*Profile, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("harness_profile: %w", err)
	}
	if p.FirstByteSecs < 0 {
		p.FirstByteSecs = 0
	}
	if p.StreamIdleSecs < 0 {
		p.StreamIdleSecs = 0
	}
	if p.OllamaContext < 0 {
		p.OllamaContext = 0
	}
	p.Raw = append(json.RawMessage(nil), raw...)
	return &p, nil
}

var current atomic.Pointer[Profile]

// Set installs the profile (nil clears it). Readers see the change on their
// next Current call: there is no restart and no lock on the hot path.
func Set(p *Profile) { current.Store(p) }

// Current is the last profile the controller sent, nil when none.
func Current() *Profile { return current.Load() }
