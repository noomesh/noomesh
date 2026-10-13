// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package messaging

import "testing"

func sampleBackends() map[string]BackendInfo {
	return map[string]BackendInfo{
		"vllm": {Model: "Qwen/Qwen3-8B-AWQ", URL: "http://noo-vllm:8000", APIFormat: "openai"},
	}
}

func TestMeshDiscoverSubjectMatchesGateway(t *testing.T) {
	// The Rust gateway (mesh/router.rs) and Python mesh_router.py both
	// publish discovery on this subject. Regression guard for the
	// "mesh.discover" mismatch that made Go agents undiscoverable.
	if meshDiscoverSubject != "mesh.inference.discover" {
		t.Fatalf("discover subject diverged from gateway: %q", meshDiscoverSubject)
	}
}

func TestBuildOffer_CanonicalShape(t *testing.T) {
	offer := buildOffer("node-1", sampleBackends(), 0.3, discoverRequest{})
	if offer == nil {
		t.Fatal("expected an offer")
	}
	// Fields the Rust BackendOffer struct requires to deserialize.
	for _, k := range []string{"node_id", "backend_type", "model", "url", "load"} {
		if _, ok := offer[k]; !ok {
			t.Errorf("offer missing required field %q", k)
		}
	}
	if offer["type"] != "offer" {
		t.Errorf("expected type=offer, got %v", offer["type"])
	}
	if offer["backend_type"] != "vllm" {
		t.Errorf("expected backend_type=vllm, got %v", offer["backend_type"])
	}
	if offer["api_format"] != "openai" {
		t.Errorf("expected api_format=openai, got %v", offer["api_format"])
	}
}

func TestBuildOffer_ModelFilter(t *testing.T) {
	if offer := buildOffer("n", sampleBackends(), 0.1, discoverRequest{Model: "other-model"}); offer != nil {
		t.Error("expected no offer for non-matching model")
	}
	if offer := buildOffer("n", sampleBackends(), 0.1, discoverRequest{Model: "Qwen/Qwen3-8B-AWQ"}); offer == nil {
		t.Error("expected offer for matching model")
	}
}

func TestBuildOffer_BackendTypeFilter(t *testing.T) {
	if offer := buildOffer("n", sampleBackends(), 0.1, discoverRequest{BackendType: "ollama"}); offer != nil {
		t.Error("expected no offer for non-matching backend_type")
	}
}

func TestBuildOffer_LoadShedding(t *testing.T) {
	if offer := buildOffer("n", sampleBackends(), 0.96, discoverRequest{}); offer != nil {
		t.Error("expected no offer when load > 0.95")
	}
}

func TestBuildOffer_EmptyBackendsOrURL(t *testing.T) {
	if offer := buildOffer("n", nil, 0.1, discoverRequest{}); offer != nil {
		t.Error("expected no offer with no backends")
	}
	b := map[string]BackendInfo{"vllm": {Model: "m", URL: ""}}
	if offer := buildOffer("n", b, 0.1, discoverRequest{}); offer != nil {
		t.Error("expected no offer when backend has no URL")
	}
}

func TestBuildOffer_DefaultAPIFormat(t *testing.T) {
	b := map[string]BackendInfo{"llamacpp": {Model: "m", URL: "http://x:8085"}}
	offer := buildOffer("n", b, 0.1, discoverRequest{})
	if offer == nil {
		t.Fatal("expected an offer")
	}
	if offer["api_format"] != "openai" {
		t.Errorf("expected default api_format=openai, got %v", offer["api_format"])
	}
}

// The subject must match the per-principal credential's grant EXACTLY.
//
// The credential (noo-cli/src/commands/nats_users.rs) grants a node
// `mesh.gossip.announce.{id}` and nothing wider. The agent published the bare
// `mesh.gossip.announce`, which the server refused — and because NATS reports
// permission violations asynchronously, Publish returned nil and nothing was
// logged. Gossip stopped silently, the gateway marked the node `unknown`, and
// has_capacity (which requires Online) made it undispatchable while it still
// heartbeat and reported a connected bus. host3 + host9, 2026-09-05.
//
// There is no runtime signal for this mismatch, which is exactly why it needs
// a test rather than an integration check.
func TestGossipAnnounceSubjectIsNodeScoped(t *testing.T) {
	got := gossipAnnounceSubject("host9")
	if want := "mesh.gossip.announce.host9"; got != want {
		t.Errorf("gossipAnnounceSubject = %q, want %q", got, want)
	}
	// The bare subject is what the credential refuses. Publishing it is the
	// bug; assert we never produce it again.
	if got == "mesh.gossip.announce" {
		t.Error("published the unscoped subject — the node credential forbids it")
	}
}

// The id goes in raw: the grant is rendered from the same raw id, and the
// gateway matches a SINGLE wildcard token against it. Transforming the id here
// would silently stop matching both.
func TestGossipAnnounceSubjectUsesTheIdVerbatim(t *testing.T) {
	for _, id := range []string{"host8", "host3", "host6", "node_1"} {
		if got, want := gossipAnnounceSubject(id), "mesh.gossip.announce."+id; got != want {
			t.Errorf("gossipAnnounceSubject(%q) = %q, want %q", id, got, want)
		}
	}
}
