// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

// Send-on-change for the heartbeat's static sections (i675 F11).
//
// A static section is sent in full only when its content hash differs from
// the one the gateway last acknowledged; otherwise the beat carries just its
// hash in `section_hashes` and the gateway restores the section from its own
// copy. The agent omits nothing unless the gateway's LAST 200 reply said it
// keeps those copies (`section_cache` = sectionCacheVersion). A gateway that
// never says so gets a full beat every time, exactly as before.
//
// Resync rules (any one means the next beat is full):
//   - any failed beat: transport error, non-200, 404/re-register;
//   - a reply without `section_cache` (an older gateway; the beat is re-sent
//     in full at once when it omitted anything);
//   - a reply with a non-empty `resync` (the gateway lacks a section or holds
//     another hash; the beat is re-sent in full at once);
//   - every fullBeatEvery-th beat, as anti-entropy.

// sectionCacheVersion is the `section_cache` value this agent understands.
const sectionCacheVersion = 1

// fullBeatEvery forces a full beat every N beats (10 min at 30 s).
const fullBeatEvery = 20

// staticSection names a heartbeat section the agent may omit and the keys it
// owns. Only sections whose keys an older gateway KEEPS when a beat omits
// them belong here (carry_reported or `if let Some`): if a gateway is
// downgraded between two beats, one omitted beat must not change the node
// record. Posture is left out on purpose: the gateway rewrites
// controller_leaf_only and control_transports from every beat, absent
// included. Node facts too: carry_i300 removes absent keys.
type staticSection struct {
	name string
	keys []string
}

var staticSections = []staticSection{
	{name: "capabilities", keys: []string{"capabilities"}},
	{name: "backend_leaves", keys: []string{"backend_leaves"}},
	{name: "data_roots", keys: []string{"data_roots"}},
	{name: "image_provenance", keys: []string{"image_sources", "image_source_mode"}},
	{name: "legacy_lanes", keys: []string{"legacy_lanes"}},
	{name: "app_version", keys: []string{"app_version"}},
}

// sectionHashesKey is the beat key that carries the hashes.
const sectionHashesKey = "section_hashes"

// beatReply is what the agent reads from a 200 heartbeat reply.
type beatReply struct {
	Status       string   `json:"status"`
	SectionCache int      `json:"section_cache"`
	Resync       []string `json:"resync"`
}

// readBeatReply decodes a heartbeat reply. An unreadable or non-JSON body
// is a reply without `section_cache`: the safe reading, full beats.
func readBeatReply(body io.Reader) beatReply {
	var rep beatReply
	_ = json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&rep)
	return rep
}

// sectionCache is the agent's half. Touched only from the Run loop's
// goroutine, like the delivery bookkeeping.
type sectionCache struct {
	// enabled: the last 200 reply advertised sectionCacheVersion.
	enabled bool
	// acked: section -> hash the gateway confirmed holding.
	acked map[string]string
	beats int
}

// sectionHash is the hash of a section's keys as present in the payload,
// or "" when it cannot be marshalled (a section that cannot be hashed is
// never omitted).
func sectionHash(s staticSection, payload map[string]any) string {
	sub := make(map[string]any, len(s.keys))
	for _, k := range s.keys {
		if v, ok := payload[k]; ok {
			sub[k] = v
		}
	}
	b, err := json.Marshal(sub) // map keys are sorted: stable bytes
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// prepare returns the payload to send, the full payload (every section, and
// the hashes, for an immediate resend), the hashes of the static sections,
// and whether send omits any of them. Neither payload shares a map with the
// input. With the cache off it returns the input unchanged and nil hashes.
func (c *sectionCache) prepare(payload map[string]any) (send, full map[string]any, hashes map[string]string, didOmit bool) {
	c.beats++
	if !c.enabled {
		return payload, payload, nil, false
	}
	hashes = make(map[string]string, len(staticSections))
	for _, s := range staticSections {
		if h := sectionHash(s, payload); h != "" {
			hashes[s.name] = h
		}
	}
	full = make(map[string]any, len(payload)+1)
	for k, v := range payload {
		full[k] = v
	}
	full[sectionHashesKey] = hashes
	if c.beats%fullBeatEvery == 0 || len(c.acked) == 0 {
		return full, full, hashes, false
	}
	send = make(map[string]any, len(full))
	for k, v := range full {
		send[k] = v
	}
	for _, s := range staticSections {
		h, ok := hashes[s.name]
		if !ok || c.acked[s.name] != h {
			continue
		}
		for _, k := range s.keys {
			if _, present := send[k]; present {
				delete(send, k)
				didOmit = true
			}
		}
	}
	return send, full, hashes, didOmit
}

// settle records a 200 reply to a beat. hashes is what that beat carried
// (nil = the cache was off, nothing hashed); didOmit says whether it left
// out any static section. It returns true when the gateway cannot restore
// what was omitted, so the caller re-sends the full beat now: the reply has
// no `section_cache` (an older gateway), or it asks for a resync.
//
// On a cached reply with no resync every hashed section is acknowledged:
// one sent in full is now held at its hash, and one omitted was omitted
// only because the gateway already held that hash.
func (c *sectionCache) settle(rep beatReply, hashes map[string]string, didOmit bool) (resendFull bool) {
	c.acked = nil
	if rep.SectionCache != sectionCacheVersion {
		c.enabled = false
		return didOmit
	}
	c.enabled = true
	if len(rep.Resync) > 0 {
		return didOmit
	}
	if hashes != nil {
		c.acked = make(map[string]string, len(hashes))
		for k, v := range hashes {
			c.acked[k] = v
		}
	}
	return false
}

// reset forgets every acknowledgement: the next beat is full.
func (c *sectionCache) reset() { c.acked = nil }
