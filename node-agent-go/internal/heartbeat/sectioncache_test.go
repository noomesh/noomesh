// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// scriptedGateway answers each heartbeat with the next scripted reply (the
// last one repeats) and records every body it was sent.
type scriptedGateway struct {
	mu      sync.Mutex
	replies []scriptedReply
	bodies  []map[string]any
}

type scriptedReply struct {
	status int
	body   string
}

var (
	oldGateway   = scriptedReply{200, `{"status":"ok"}`}
	cacheGateway = scriptedReply{200, `{"status":"ok","section_cache":1}`}
)

func (g *scriptedGateway) script(rs ...scriptedReply) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.replies = rs
}

func (g *scriptedGateway) take() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.bodies
	g.bodies = nil
	return out
}

func newScriptedGateway(t *testing.T) (*scriptedGateway, *Reporter) {
	t.Helper()
	g := &scriptedGateway{replies: []scriptedReply{oldGateway}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		g.mu.Lock()
		g.bodies = append(g.bodies, b)
		rep := g.replies[0]
		if len(g.replies) > 1 {
			g.replies = g.replies[1:]
		}
		g.mu.Unlock()
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	t.Setenv("MODELS_DIR", "")
	r := newTestReporter(t, srv.URL, &config.Config{NodeID: "test-node", Tier: 3, NodeIP: "192.168.1.10"})
	r.caps = &hardware.Capabilities{CPUCores: 4, Backends: []string{"ollama"}}
	return g, r
}

// beat sends one heartbeat and returns the bodies it put on the wire.
func beat(t *testing.T, g *scriptedGateway, r *Reporter) []map[string]any {
	t.Helper()
	r.SendHeartbeat()
	return g.take()
}

func staticKeys() []string {
	var ks []string
	for _, s := range staticSections {
		for _, k := range s.keys {
			if k == "image_sources" { // omitted until a container start
				continue
			}
			ks = append(ks, k)
		}
	}
	return ks
}

func requireFull(t *testing.T, what string, b map[string]any) {
	t.Helper()
	for _, k := range staticKeys() {
		if _, ok := b[k]; !ok {
			t.Errorf("%s: static key %q missing from a beat that must be full", what, k)
		}
	}
}

func requireOmitted(t *testing.T, what string, b map[string]any, except ...string) {
	t.Helper()
	keep := map[string]bool{}
	for _, k := range except {
		keep[k] = true
	}
	for _, k := range staticKeys() {
		_, ok := b[k]
		if keep[k] && !ok {
			t.Errorf("%s: changed key %q must be sent", what, k)
		}
		if !keep[k] && ok {
			t.Errorf("%s: unchanged key %q should be omitted", what, k)
		}
	}
	// What the gateway rewrites from every beat is never omitted.
	for _, k := range []string{"controller_leaf_only", "control_transports", "peer_identity_enforced", "os", "lanes", "model_presence", "running_backends"} {
		if _, ok := b[k]; !ok {
			t.Errorf("%s: non-static key %q must be in every beat", what, k)
		}
	}
	if _, ok := b[sectionHashesKey].(map[string]any); !ok {
		t.Errorf("%s: an omitting beat must carry %s, got %#v", what, sectionHashesKey, b[sectionHashesKey])
	}
}

// An older gateway never advertises the cache: every beat stays full and
// carries no new key, byte-for-byte the shape it always received.
func TestSectionCache_OldGatewayGetsFullBeatsAndNoNewKey(t *testing.T) {
	g, r := newScriptedGateway(t)
	for i := 0; i < 4; i++ {
		bs := beat(t, g, r)
		if len(bs) != 1 {
			t.Fatalf("beat %d: %d posts, want 1", i, len(bs))
		}
		requireFull(t, "old gateway", bs[0])
		if _, ok := bs[0][sectionHashesKey]; ok {
			t.Fatalf("beat %d: %s sent to a gateway that never advertised the cache", i, sectionHashesKey)
		}
	}
}

func TestSectionCache_OmitsOnlyWhatTheGatewayHolds(t *testing.T) {
	g, r := newScriptedGateway(t)
	g.script(cacheGateway)

	b1 := beat(t, g, r)[0]
	requireFull(t, "first beat", b1)
	if _, ok := b1[sectionHashesKey]; ok {
		t.Fatal("first beat: the cache is not advertised yet, no hashes")
	}
	b2 := beat(t, g, r)[0]
	requireFull(t, "second beat (gateway has nothing yet)", b2)
	h2, ok := b2[sectionHashesKey].(map[string]any)
	if !ok || len(h2) != len(staticSections) {
		t.Fatalf("second beat: want a hash per static section, got %#v", b2[sectionHashesKey])
	}
	b3 := beat(t, g, r)[0]
	requireOmitted(t, "third beat", b3)
	if h3 := b3[sectionHashesKey].(map[string]any); h3["capabilities"] != h2["capabilities"] {
		t.Errorf("unchanged section changed hash: %v vs %v", h3["capabilities"], h2["capabilities"])
	}

	// A capability change is sent at once, and only that section.
	r.caps = &hardware.Capabilities{CPUCores: 4, Backends: []string{"ollama", "llamacpp"}}
	b4 := beat(t, g, r)[0]
	requireOmitted(t, "after a capability change", b4, "capabilities")
	if b4[sectionHashesKey].(map[string]any)["capabilities"] == h2["capabilities"] {
		t.Error("a changed section kept its hash")
	}
	requireOmitted(t, "next beat", beat(t, g, r)[0])
}

// The gateway lacks a section or holds another hash (it restarted on an
// empty store, or its copy was lost): the same beat is re-sent whole at
// once, never left a beat behind.
func TestSectionCache_ResyncResendsTheBeatWholeAtOnce(t *testing.T) {
	g, r := newScriptedGateway(t)
	g.script(cacheGateway)
	beat(t, g, r)
	beat(t, g, r)
	g.script(scriptedReply{200, `{"status":"ok","section_cache":1,"resync":["capabilities"]}`}, cacheGateway)
	bs := beat(t, g, r)
	if len(bs) != 2 {
		t.Fatalf("resync: %d posts, want the omitting beat and its full resend", len(bs))
	}
	requireOmitted(t, "beat answered with resync", bs[0])
	requireFull(t, "resend", bs[1])
	if _, ok := bs[1][sectionHashesKey]; !ok {
		t.Error("resend to a caching gateway must carry the hashes it stores")
	}
	requireOmitted(t, "beat after the resend was acknowledged", beat(t, g, r)[0])
}

// Any failed beat makes the next one full: the gateway may not hold what
// that beat carried.
func TestSectionCache_FailedBeatMakesTheNextFull(t *testing.T) {
	for _, fail := range []scriptedReply{{500, ""}, {503, `{"section_cache":1}`}} {
		g, r := newScriptedGateway(t)
		g.script(cacheGateway)
		beat(t, g, r)
		beat(t, g, r)
		g.script(fail, cacheGateway)
		if bs := beat(t, g, r); len(bs) != 1 {
			t.Fatalf("HTTP %d: %d posts, want 1 (no resend on a failure)", fail.status, len(bs))
		}
		requireFull(t, "beat after a failure", beat(t, g, r)[0])
		requireOmitted(t, "beat after recovery", beat(t, g, r)[0])
	}
}

// A 404 re-registers; the next beat is full.
func TestSectionCache_ReRegisterMakesTheNextFull(t *testing.T) {
	g, r := newScriptedGateway(t)
	g.script(cacheGateway)
	beat(t, g, r)
	beat(t, g, r)
	g.script(scriptedReply{404, ""}, scriptedReply{200, `{"status":"registered"}`}, cacheGateway)
	beat(t, g, r)
	requireFull(t, "beat after re-registration", beat(t, g, r)[0])
}

// The gateway is downgraded between two beats: the omitting beat's reply
// has no section_cache, so the beat is re-sent whole, without the new key,
// and the cache stays off.
func TestSectionCache_DowngradedGatewayGetsTheBeatWhole(t *testing.T) {
	g, r := newScriptedGateway(t)
	g.script(cacheGateway)
	beat(t, g, r)
	beat(t, g, r)
	g.script(oldGateway)
	bs := beat(t, g, r)
	if len(bs) != 2 {
		t.Fatalf("downgrade: %d posts, want the omitting beat and its full resend", len(bs))
	}
	requireFull(t, "resend to an older gateway", bs[1])
	if _, ok := bs[1][sectionHashesKey]; ok {
		t.Error("resend to an older gateway must not carry the new key")
	}
	next := beat(t, g, r)
	requireFull(t, "beat after the downgrade", next[0])
	if _, ok := next[0][sectionHashesKey]; ok {
		t.Error("the cache must stay off until the gateway advertises it again")
	}
}

// Every fullBeatEvery-th beat is full whatever the gateway holds.
func TestSectionCache_PeriodicFullBeat(t *testing.T) {
	g, r := newScriptedGateway(t)
	g.script(cacheGateway)
	beat(t, g, r)
	beat(t, g, r)
	r.sections.beats = fullBeatEvery - 1
	requireFull(t, "periodic beat", beat(t, g, r)[0])
	requireOmitted(t, "beat after the periodic one", beat(t, g, r)[0])
}

func TestSectionHashIsStableAndKeyed(t *testing.T) {
	s := staticSection{name: "x", keys: []string{"a", "b"}}
	p1 := map[string]any{"a": map[string]any{"z": 1, "y": 2}, "b": "v", "other": 1}
	p2 := map[string]any{"b": "v", "a": map[string]any{"y": 2, "z": 1}, "other": 2}
	if sectionHash(s, p1) != sectionHash(s, p2) {
		t.Error("hash depends on map order or on keys outside the section")
	}
	if sectionHash(s, p1) == sectionHash(s, map[string]any{"a": p1["a"]}) {
		t.Error("a key that vanished must change the hash")
	}
	if len(sectionHash(s, p1)) != 16 {
		t.Errorf("hash length = %d, want 16 hex chars", len(sectionHash(s, p1)))
	}
}

// The gateway half copies testdata/static_sections.json (section names, the
// keys each owns, the version and the request key); the agent's table must
// equal it, so the two halves cannot drift apart.
func TestStaticSectionsMatchTheFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/static_sections.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		SectionCache int    `json:"section_cache"`
		RequestKey   string `json:"request_key"`
		Sections     []struct {
			Name string   `json:"name"`
			Keys []string `json:"keys"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if fx.SectionCache != sectionCacheVersion || fx.RequestKey != sectionHashesKey {
		t.Errorf("fixture version/key %d/%q, agent %d/%q", fx.SectionCache, fx.RequestKey, sectionCacheVersion, sectionHashesKey)
	}
	if len(fx.Sections) != len(staticSections) {
		t.Fatalf("fixture has %d sections, agent %d", len(fx.Sections), len(staticSections))
	}
	for i, s := range staticSections {
		if fx.Sections[i].Name != s.name || !reflect.DeepEqual(fx.Sections[i].Keys, s.keys) {
			t.Errorf("section %d: fixture %v, agent %v", i, fx.Sections[i], s)
		}
	}
}
