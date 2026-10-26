// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

func chatGemma() placement {
	return placement{Backend: "ollama", Model: "gemma4:26b-a4b-it-qat", Role: "chat", DesiredState: "running",
		Image: "ollama/ollama:0.9", Port: 11434, Env: map[string]string{"OLLAMA_NUM_PARALLEL": "1", "LOG_LEVEL": "info"}}
}

func embedHarrier() placement {
	return placement{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running",
		Image: "other", Port: 9999, Env: map[string]string{"OLLAMA_NUM_PARALLEL": "4", "LOG_LEVEL": "debug"}}
}

// (a) two roles on one backend collapse into ONE placement for the container
// lifecycle: chat's model/image/port, and room for both models.
func TestEffectivePlacements_TwoOllamaRolesMergeIntoOne(t *testing.T) {
	// embed listed first on purpose: order in the wire list must not matter.
	eff, _ := effectivePlacements([]placement{embedHarrier(), chatGemma()})
	if len(eff) != 1 {
		t.Fatalf("want one effective placement, got %d: %+v", len(eff), eff)
	}
	m := eff[0]
	if m.Model != "gemma4:26b-a4b-it-qat" || m.Image != "ollama/ollama:0.9" || m.Port != 11434 || m.Role != "chat" {
		t.Fatalf("merged = %+v, want the chat placement's model/image/port", m)
	}
	if got := m.Env["OLLAMA_MAX_LOADED_MODELS"]; got != "2" {
		t.Fatalf("OLLAMA_MAX_LOADED_MODELS = %q, want 2", got)
	}
	if m.Env["OLLAMA_KEEP_ALIVE"] != "-1" {
		t.Fatalf("OLLAMA_KEEP_ALIVE = %q, want -1 (warm)", m.Env["OLLAMA_KEEP_ALIVE"])
	}
}

// (b)
func TestMergeOllamaEnv_MaxForParallelChatWinsRest(t *testing.T) {
	env, warns := mergeOllamaEnv([]placement{embedHarrier(), chatGemma()})
	if env["OLLAMA_NUM_PARALLEL"] != "4" {
		t.Errorf("NUM_PARALLEL = %q, want 4 (max)", env["OLLAMA_NUM_PARALLEL"])
	}
	if env["LOG_LEVEL"] != "info" {
		t.Errorf("LOG_LEVEL = %q, want chat's info", env["LOG_LEVEL"])
	}
	want := []string{
		"LOG_LEVEL: chat=info embed=debug -> info (chat)",
		"OLLAMA_NUM_PARALLEL: chat=1 embed=4 -> 4 (max)",
	}
	if !reflect.DeepEqual(warns, want) {
		t.Errorf("warnings = %q, want %q", warns, want)
	}
}

func TestMergeOllamaEnv_UnionMaxLoadedAndNonIntegerFallback(t *testing.T) {
	chat := placement{Backend: "ollama", Role: "chat", Env: map[string]string{"OLLAMA_MAX_LOADED_MODELS": "x", "A": "1"}}
	embed := placement{Backend: "ollama", Role: "embed", Env: map[string]string{"OLLAMA_MAX_LOADED_MODELS": "3", "B": "2", "OLLAMA_KEEP_ALIVE": "5m"}}
	rerank := placement{Backend: "ollama", Role: "rerank"}
	env, _ := mergeOllamaEnv([]placement{rerank, embed, chat})
	if env["A"] != "1" || env["B"] != "2" {
		t.Errorf("union lost keys: %v", env)
	}
	// non-integer chat value falls back to priority (chat wins: "x"), which
	// is then not an integer, so n (3) applies.
	if env["OLLAMA_MAX_LOADED_MODELS"] != "3" {
		t.Errorf("MAX_LOADED = %q, want 3", env["OLLAMA_MAX_LOADED_MODELS"])
	}
	if env["OLLAMA_KEEP_ALIVE"] != "5m" {
		t.Errorf("an explicit KEEP_ALIVE must survive, got %q", env["OLLAMA_KEEP_ALIVE"])
	}
}

func TestPrimaryPlacementOrdering(t *testing.T) {
	rr := placement{Backend: "ollama", Role: "rerank", Model: "r"}
	em := placement{Backend: "ollama", Role: "embed", Model: "e"}
	zz := placement{Backend: "ollama", Role: "zzz", Model: "z"}
	aa := placement{Backend: "ollama", Role: "aaa", Model: "a"}
	ch := placement{Backend: "ollama", Model: "c"} // empty role = chat
	got := []string{}
	for _, p := range orderPlacements([]placement{zz, rr, aa, em, ch}) {
		got = append(got, p.Model)
	}
	if !reflect.DeepEqual(got, []string{"c", "e", "r", "a", "z"}) {
		t.Errorf("order = %v", got)
	}
	if primaryPlacement([]placement{em, rr}).Model != "e" {
		t.Error("with no chat, the first by role order is primary")
	}
}

// (e) a backend with one placement is untouched: same spec hash, no env.
func TestEffectivePlacements_SingleBackendHashUnchanged(t *testing.T) {
	one := chatGemma()
	vl := placement{Backend: "vllm", Model: "m", Role: "chat", DesiredState: "running", Env: map[string]string{"VLLM_X": "1"}}
	stopped := placement{Backend: "ollama", Model: "old", Role: "embed", DesiredState: "stopped"}
	eff, _ := effectivePlacements([]placement{one, vl, stopped})
	if len(eff) != 2 {
		t.Fatalf("eff = %+v", eff)
	}
	if specHash(eff[0]) != specHash(one) || specHash(eff[1]) != specHash(vl) {
		t.Fatal("spec hash changed for a single running placement")
	}
	if _, injected := eff[0].Env["OLLAMA_MAX_LOADED_MODELS"]; injected {
		t.Fatal("env injected into a single placement")
	}
}

func TestEffectivePlacements_AllStoppedStops(t *testing.T) {
	a, b := chatGemma(), embedHarrier()
	a.DesiredState, b.DesiredState = "stopped", "stopped"
	eff, _ := effectivePlacements([]placement{a, b})
	if len(eff) != 1 || eff[0].DesiredState != "stopped" {
		t.Fatalf("eff = %+v", eff)
	}
}

// (c) both models are ensured and both roles are advertised.
func TestEnsureOllamaModels_BothRolesReported(t *testing.T) {
	r := presenceFixture(t, false)
	asked := map[string]bool{}
	has := func(_ context.Context, m string) (bool, error) { asked[m] = true; return true, nil }
	pull := func(context.Context, string) (string, error) { return "", nil }
	keep := r.ensureOllamaModels(context.Background(), "host6", []placement{embedHarrier(), chatGemma()}, has, pull)
	if !asked["gemma4:26b-a4b-it-qat"] || !asked["harrier"] {
		t.Fatalf("ensure asked %v, want both models", asked)
	}
	rep := modelpresence.Report()
	if g := rep["ollama"]; g.Model != "gemma4:26b-a4b-it-qat" || g.Role != "chat" || !g.Present {
		t.Errorf("ollama = %+v", g)
	}
	if h := rep["ollama#embed"]; h.Model != "harrier" || h.Role != "embed" || !h.Present {
		t.Errorf("ollama#embed = %+v", h)
	}
	if !keep["ollama"] || !keep["ollama#embed"] || len(keep) != 2 {
		t.Errorf("keep = %v", keep)
	}
	modelpresence.Retain(keep)
	if len(modelpresence.Report()) != 2 {
		t.Error("Retain dropped a #role key")
	}
}

func TestPresenceKey(t *testing.T) {
	all := []placement{chatGemma(), embedHarrier()}
	if presenceKey("ollama", embedHarrier(), chatGemma(), all) != "ollama#embed" ||
		presenceKey("ollama", chatGemma(), chatGemma(), all) != "ollama" {
		t.Error("presence keys wrong")
	}
}

func embedNomicCode() placement {
	return placement{Backend: "ollama", Model: "nomic-embed-code", Role: "embed", DesiredState: "running",
		Image: "other", Port: 9999}
}

// A node serving two embedding spaces: every running row has its OWN key,
// the first embed keeps "ollama#embed", and Retain keeps all of them.
func TestPresenceKey_UniquePerEmbedModel(t *testing.T) {
	rows := runningOllama([]placement{embedNomicCode(), chatGemma(), embedHarrier()})
	primary := rows[0]
	got := map[string]string{}
	for _, p := range rows {
		k := presenceKey(p.Backend, p, primary, rows)
		if prev, dup := got[k]; dup {
			t.Fatalf("key %q shared by %s and %s", k, prev, p.Model)
		}
		got[k] = p.Model
	}
	want := map[string]string{
		"ollama":                        "gemma4:26b-a4b-it-qat",
		"ollama#embed":                  "harrier",
		"ollama#embed@nomic-embed-code": "nomic-embed-code",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

// Two embed rows and no chat: the primary (first by model) is the bare
// backend; the other still gets a distinct key.
func TestPresenceKey_TwoEmbedsNoChat(t *testing.T) {
	rows := runningOllama([]placement{embedNomicCode(), embedHarrier()})
	keys := map[string]bool{}
	for _, p := range rows {
		keys[presenceKey(p.Backend, p, rows[0], rows)] = true
	}
	if len(keys) != 2 || !keys["ollama"] {
		t.Errorf("keys = %v, want two distinct, primary bare", keys)
	}
}

// Two embed placements on one node are BOTH published as targets, primary
// (first by model) first.
func TestResolveEmbedTargets_TwoEmbeds(t *testing.T) {
	got := resolveEmbedTargets([]placement{chatGemma(), embedNomicCode(), embedHarrier()})
	if len(got) != 2 || got[0].Model != "harrier" || got[1].Model != "nomic-embed-code" {
		t.Fatalf("targets = %+v, want harrier then nomic-embed-code", got)
	}
	stopped := embedNomicCode()
	stopped.DesiredState = "stopped"
	if got := resolveEmbedTargets([]placement{embedHarrier(), stopped}); len(got) != 1 {
		t.Errorf("a stopped embed row must not be a target: %+v", got)
	}
}

// host6, live: the embed placement was replaced by chat and the node kept
// advertising `embed`, because the empty-desired-state early return never
// cleared the embed target (nor presence, nor the plist tuning).
func TestOnce_EmptyDesiredClearsStaleState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"node":null,"placements":[]}`))
	}))
	defer srv.Close()
	embedtarget.Set(embedtarget.Target{BaseURL: "https://stunnel-ollama:11434", Backend: "ollama", Model: "harrier"})
	modelpresence.Reset()
	modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "harrier", Role: "embed", Present: true})
	backendrt.SetOllamaTuning(map[string]string{"OLLAMA_NUM_PARALLEL": "4"})
	t.Cleanup(func() {
		embedtarget.Set(embedtarget.Target{})
		modelpresence.Reset()
		backendrt.SetOllamaTuning(nil)
	})
	r := &Reconciler{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "host6"}, client: srv.Client()}
	r.Once(context.Background())
	if got := embedtarget.Get(); got != (embedtarget.Target{}) {
		t.Errorf("embed target survived an empty desired state: %+v", got)
	}
	if len(modelpresence.Report()) != 0 {
		t.Errorf("presence survived: %v", modelpresence.Report())
	}
	if len(backendrt.OllamaTuning()) != 0 {
		t.Errorf("tuning survived: %v", backendrt.OllamaTuning())
	}
}

// A chat row beside an embed row on the SAME backend: only the embed row is
// the embedder; with only the chat row there is no target.
func TestResolveEmbedTarget_MultiRole(t *testing.T) {
	got := resolveEmbedTarget([]placement{chatGemma(), embedHarrier()})
	if got.Model != "harrier" || got.Backend != "ollama" {
		t.Errorf("got %+v, want the embed row", got)
	}
	if got := resolveEmbedTarget([]placement{chatGemma()}); got != (embedtarget.Target{}) {
		t.Errorf("chat-only yielded %+v", got)
	}
}
