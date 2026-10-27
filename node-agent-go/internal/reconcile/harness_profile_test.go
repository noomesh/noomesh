// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/harnessprofile"
)

func profileT(t *testing.T, p *harnessprofile.Profile) {
	t.Helper()
	harnessprofile.Set(p)
	t.Cleanup(func() { harnessprofile.Set(nil) })
}

// The profile arrives in desired-config; a failed fetch keeps the last good
// one, a malformed one keeps it too, and an answer without one clears it.
func TestOnceKeepsTheLastGoodProfileAndClearsOnAbsence(t *testing.T) {
	profileT(t, nil)
	var body atomic.Value
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	r := &Reconciler{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "mcmini"}, client: srv.Client()}

	body.Store(`{"node":null,"placements":[],"harness_profile":{"tier":2,"first_byte_secs":600,"ollama_context":32768,"foreign_kinds":["codex"]}}`)
	r.Once(context.Background())
	if p := harnessprofile.Current(); p == nil || p.FirstByteSecs != 600 || p.Tier != 2 {
		t.Fatalf("profile not installed: %+v", p)
	}

	fail.Store(true)
	r.Once(context.Background())
	if p := harnessprofile.Current(); p == nil || p.FirstByteSecs != 600 {
		t.Fatalf("a failed fetch must keep the last good profile: %+v", p)
	}
	fail.Store(false)

	body.Store(`{"node":null,"placements":[],"harness_profile":{"first_byte_secs":"later"}}`)
	r.Once(context.Background())
	if p := harnessprofile.Current(); p == nil || p.FirstByteSecs != 600 {
		t.Fatalf("a malformed profile must keep the last good one: %+v", p)
	}

	body.Store(`{"node":null,"placements":[]}`)
	r.Once(context.Background())
	if p := harnessprofile.Current(); p != nil {
		t.Fatalf("no harness_profile in desired-config means no profile: %+v", p)
	}
}

func TestProfileRefusesAForeignKindItDoesNotOffer(t *testing.T) {
	prof := &harnessprofile.Profile{Tier: 3, ForeignKinds: []string{"codex", "copilot"}}
	got := profileKindRefusal("claude-code", prof, "host7")
	want := "harness kind \"claude-code\": this node's profile (tier 3) does not offer it; set it with `noo cluster profile host7 --set foreign_kinds=…`"
	if got != want {
		t.Fatalf("refusal\n got: %s\nwant: %s", got, want)
	}
	if got := profileKindRefusal("codex", prof, "host7"); got != "" {
		t.Errorf("a listed kind must not be refused: %s", got)
	}
	if got := profileKindRefusal("noo", &harnessprofile.Profile{Tier: 4}, "host7"); got != "" {
		t.Errorf("noo is always allowed: %s", got)
	}
	if got := profileKindRefusal("claude-code", nil, "host7"); got != "" {
		t.Errorf("no profile, no new refusal: %s", got)
	}
	if got := profileKindRefusal("claude-code", &harnessprofile.Profile{Tier: 4, ForeignKinds: []string{}}, ""); got !=
		"harness kind \"claude-code\": this node's profile (tier 4) does not offer it; set it with `noo cluster profile <node> --set foreign_kinds=…`" {
		t.Errorf("an empty list refuses every foreign kind, and an unknown node reads <node>: %s", got)
	}
}

// Through harnessKindRefusalProfiled: the existing checks come first (an
// unknown kind is still "unknown"), and the profile refusal follows them.
func TestHarnessKindRefusalProfiledRunsAfterTheExistingChecks(t *testing.T) {
	chat := []placement{{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running"}}
	h := func(kind string) placement {
		return placement{Backend: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": kind}}
	}
	present := func(string) bool { return true }
	prof := &harnessprofile.Profile{Tier: 4, ForeignKinds: []string{}}
	if got := harnessKindRefusalProfiled(h("bogus"), chat, present, present, prof, "n"); got == "" || got[:22] != "unknown harness kind \"" {
		t.Errorf("unknown kind must keep its own refusal: %q", got)
	}
	if got := harnessKindRefusalProfiled(h("claude-code"), chat, present, func(string) bool { return false }, prof, "n"); got == "" ||
		got == profileKindRefusal("claude-code", prof, "n") {
		t.Errorf("a missing CLI is refused for that first: %q", got)
	}
	if got := harnessKindRefusalProfiled(h("copilot"), chat, present, present, prof, "n"); got != profileKindRefusal("copilot", prof, "n") || got == "" {
		t.Errorf("profile refusal expected: %q", got)
	}
	if got := harnessKindRefusalProfiled(h("copilot"), chat, present, present, nil, "n"); got != "" {
		t.Errorf("no profile must not refuse: %q", got)
	}
	if got := harnessKindRefusalProfiled(h("noo"), chat, present, present, prof, "n"); got != "" {
		t.Errorf("noo must not be refused: %q", got)
	}
}

func TestProfileOllamaContextJoinsTheSpecOnlyWhenThePlacementDoesNotSetIt(t *testing.T) {
	bare := placement{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running", Env: map[string]string{"OLLAMA_NUM_PARALLEL": "2"}}
	own := placement{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running", Env: map[string]string{"OLLAMA_CONTEXT_LENGTH": "8192"}}
	// an engine with no window key stays untouched (vLLM now gets one: see
	// TestTheProfileContextReachesEveryChatEngineThatDoesNotSetItsOwn)
	other := placement{Backend: "tei", Model: "m", DesiredState: "running"}

	p32 := &harnessprofile.Profile{Context: 32768}
	out := withProfileContext([]placement{bare, own, other}, p32)
	if out[0].Env["OLLAMA_CONTEXT_LENGTH"] != "32768" || out[0].Env["OLLAMA_NUM_PARALLEL"] != "2" {
		t.Errorf("default not injected: %v", out[0].Env)
	}
	if _, mutated := bare.Env["OLLAMA_CONTEXT_LENGTH"]; mutated {
		t.Error("the controller's placement env must not be mutated")
	}
	if out[1].Env["OLLAMA_CONTEXT_LENGTH"] != "8192" {
		t.Errorf("a placement that sets the key must be left alone: %v", out[1].Env)
	}
	if specHash(out[1]) != specHash(own) || specHash(out[2]) != specHash(other) {
		t.Error("an untouched placement's spec hash must not change")
	}
	if got := buildPlacementEnv(out[0]); got["OLLAMA_CONTEXT_LENGTH"] != "32768" {
		t.Errorf("the default must reach the container env: %v", got)
	}

	// No profile: today's spec. A changed default: a new spec (recreate).
	none := withProfileContext([]placement{bare}, nil)
	if specHash(none[0]) != specHash(bare) {
		t.Error("no profile must leave the spec hash as it was")
	}
	p16 := withProfileContext([]placement{bare}, &harnessprofile.Profile{Context: 16384})
	if specHash(p16[0]) == specHash(out[0]) || specHash(p16[0]) == specHash(bare) {
		t.Error("a changed profile context must change the spec hash so the container is recreated")
	}
	stopped := bare
	stopped.DesiredState = "stopped"
	if s := withProfileContext([]placement{stopped}, p32); s[0].Env["OLLAMA_CONTEXT_LENGTH"] != "" {
		t.Error("a stopped placement is not tuned")
	}
}

// One profile value, every chat engine: vLLM gets VLLM_MAX_MODEL_LEN and
// llama.cpp N_CTX from the same default Ollama always got, when the
// placement does not decide the window itself (awolf ran vLLM at the image
// default 16384 beside Ollama's 32768 at the same tier, 2026-10-24).
func TestTheProfileContextReachesEveryChatEngineThatDoesNotSetItsOwn(t *testing.T) {
	p32 := &harnessprofile.Profile{Context: 32768}
	vllm := placement{Backend: "vllm", Model: "google/gemma-4-12B", DesiredState: "running", Env: map[string]string{"VLLM_MAX_NUM_SEQS": "8"}}
	vllmOwn := placement{Backend: "vllm", Model: "m", DesiredState: "running", Env: map[string]string{"VLLM_MAX_MODEL_LEN": "8192"}}
	secondary := placement{Backend: "vllm-secondary", Model: "m2", DesiredState: "running"}
	llama := placement{Backend: "llamacpp", Model: "x.gguf", DesiredState: "running"}
	llamaArg := placement{Backend: "llamacpp", Model: "y.gguf", DesiredState: "running", Env: map[string]string{"LLAMA_ARG_CTX_SIZE": "4096"}}
	embed := placement{Backend: "tei", Model: "e", DesiredState: "running"}
	out := withProfileContext([]placement{vllm, vllmOwn, secondary, llama, llamaArg, embed}, p32)
	if out[0].Env["VLLM_MAX_MODEL_LEN"] != "32768" || out[0].Env["VLLM_MAX_NUM_SEQS"] != "8" {
		t.Errorf("vllm: %v", out[0].Env)
	}
	if out[1].Env["VLLM_MAX_MODEL_LEN"] != "8192" || specHash(out[1]) != specHash(vllmOwn) {
		t.Errorf("a vllm placement that sets the window is left alone: %v", out[1].Env)
	}
	if out[2].Env["VLLM_MAX_MODEL_LEN"] != "32768" {
		t.Errorf("vllm-secondary: %v", out[2].Env)
	}
	if out[3].Env["N_CTX"] != "32768" {
		t.Errorf("llamacpp: %v", out[3].Env)
	}
	if _, set := out[4].Env["N_CTX"]; set || specHash(out[4]) != specHash(llamaArg) {
		t.Errorf("a llama.cpp placement with LLAMA_ARG_CTX_SIZE decided its window: %v", out[4].Env)
	}
	if len(out[5].Env) != 0 {
		t.Errorf("an engine without a window key is untouched: %v", out[5].Env)
	}
	if _, mutated := vllm.Env["VLLM_MAX_MODEL_LEN"]; mutated {
		t.Error("the controller's placement env must not be mutated")
	}
	// the default must survive the env allow-list on its way to the container
	if got := buildPlacementEnv(out[0]); got["VLLM_MAX_MODEL_LEN"] != "32768" {
		t.Errorf("VLLM_MAX_MODEL_LEN must reach the container env: %v", got)
	}
	if got := buildPlacementEnv(out[3]); got["N_CTX"] != "32768" {
		t.Errorf("N_CTX must reach the container env: %v", got)
	}
}

func TestNativeOllamaTuningCarriesTheProfileContextToThePlist(t *testing.T) {
	p32 := &harnessprofile.Profile{Context: 32768}
	lone := []placement{{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running"}}
	if got := nativeOllamaTuning(lone, nil); got != nil {
		t.Errorf("a lone placement with no profile keeps no tuning, as before: %v", got)
	}
	if got := nativeOllamaTuning(lone, p32); len(got) != 1 || got["OLLAMA_CONTEXT_LENGTH"] != "32768" {
		t.Errorf("lone placement + profile: %v", got)
	}
	set := []placement{{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running", Env: map[string]string{"OLLAMA_CONTEXT_LENGTH": "8192"}}}
	if got := nativeOllamaTuning(set, p32); len(got) != 1 || got["OLLAMA_CONTEXT_LENGTH"] != "8192" {
		t.Errorf("a lone placement that sets the key keeps its own value: %v", got)
	}
	// A lone native ollama's own tuning reaches its plist too (the only way
	// `--env OLLAMA_FLASH_ATTENTION=1` can reach a daemon that is not a
	// container); keys outside the allow-list do not.
	tuned := []placement{{Backend: "ollama", Model: "gemma4:12b", DesiredState: "running",
		Env: map[string]string{"OLLAMA_FLASH_ATTENTION": "1", "OLLAMA_KV_CACHE_TYPE": "q8_0", "NOO_SECRET": "x"}}}
	got := nativeOllamaTuning(tuned, p32)
	if got["OLLAMA_FLASH_ATTENTION"] != "1" || got["OLLAMA_KV_CACHE_TYPE"] != "q8_0" || got["OLLAMA_CONTEXT_LENGTH"] != "32768" {
		t.Errorf("lone placement carries its allow-listed env plus the profile default: %v", got)
	}
	if _, leaked := got["NOO_SECRET"]; leaked {
		t.Errorf("allow-list not applied to a lone placement: %v", got)
	}
	multi := []placement{chatGemma(), embedHarrier()}
	got = nativeOllamaTuning(multi, p32)
	if got["OLLAMA_CONTEXT_LENGTH"] != "32768" || got["OLLAMA_MAX_LOADED_MODELS"] == "" {
		t.Errorf("multi-role: merged env plus the default: %v", got)
	}
	if got := nativeOllamaTuning(nil, p32); got != nil {
		t.Errorf("no rows, no tuning: %v", got)
	}
}

func TestChatPlacementOfPicksTheRunningChatEngine(t *testing.T) {
	all := []placement{
		{Backend: "harness", DesiredState: "running"},
		{Backend: "reranker", Model: "bge.gguf", DesiredState: "running"},
		{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"},
		{Backend: "vllm", Model: "old", DesiredState: "stopped"},
		{Backend: "ollama", Model: "gemma4:12b", Role: "chat", DesiredState: "running"},
	}
	p, ok := chatPlacementOf(all)
	if !ok || p.Backend != "ollama" || p.Model != "gemma4:12b" {
		t.Fatalf("got %+v %v", p, ok)
	}
	if _, ok := chatPlacementOf(all[:4]); ok {
		t.Error("no running chat engine, no chat placement")
	}
	r := &Reconciler{}
	r.recordChatPlacement(all)
	if b, m, ok := r.ChatPlacement(); !ok || b != "ollama" || m != "gemma4:12b" {
		t.Errorf("ChatPlacement = %s %s %v", b, m, ok)
	}
	r.recordChatPlacement(nil)
	if _, _, ok := r.ChatPlacement(); ok {
		t.Error("cleared")
	}
}

// Every running chat placement, not only the first: the controller's
// harness fit takes the smallest window across them (i285).
func TestChatModelsListsEveryRunningChatPlacement(t *testing.T) {
	all := []placement{
		{Backend: "vllm", Model: "org/gemma-4-12B", DesiredState: "running"},
		{Backend: "reranker", Model: "bge.gguf", DesiredState: "running"},
		{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"},
		{Backend: "llamacpp", Model: "small.gguf", Role: "chat", DesiredState: "running"},
		{Backend: "ollama", Model: "old", DesiredState: "stopped"},
	}
	r := &Reconciler{}
	r.recordChatPlacement(all)
	want := []ChatModel{{"vllm", "org/gemma-4-12B"}, {"llamacpp", "small.gguf"}}
	if got := r.ChatModels(); !reflect.DeepEqual(got, want) {
		t.Errorf("ChatModels = %+v, want %+v", got, want)
	}
	r.recordChatPlacement(nil)
	if got := r.ChatModels(); len(got) != 0 {
		t.Errorf("cleared: %+v", got)
	}
}

// The harness tells Claude Code its model's real window from this (i147):
// the chat ollama's own OLLAMA_CONTEXT_LENGTH, else the profile's default,
// else 0; never a window for a chat backend that is not ollama.
func TestChatContextWindowIsTheOllamaContextTheAgentSets(t *testing.T) {
	prof := &harnessprofile.Profile{Context: 32768}
	chat := placement{Backend: "ollama", Model: "gemma4:12b", Role: "chat", DesiredState: "running"}
	r := &Reconciler{}

	r.recordChatPlacement([]placement{chat})
	if got := r.ChatContextWindow(prof); got != 32768 {
		t.Errorf("profile default: got %d", got)
	}
	if got := r.ChatContextWindow(nil); got != 0 {
		t.Errorf("no profile, no placement value: got %d", got)
	}

	own := chat
	own.Env = map[string]string{"OLLAMA_CONTEXT_LENGTH": " 65536 "}
	r.recordChatPlacement([]placement{own})
	if got := r.ChatContextWindow(prof); got != 65536 {
		t.Errorf("the placement's own value wins: got %d", got)
	}

	// Several ollama roles share one daemon: the merged env decides.
	embed := placement{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running",
		Env: map[string]string{"OLLAMA_CONTEXT_LENGTH": "16384"}}
	r.recordChatPlacement([]placement{chat, embed})
	if got := r.ChatContextWindow(prof); got != 16384 {
		t.Errorf("another role's value reaches the shared daemon: got %d", got)
	}

	bad := chat
	bad.Env = map[string]string{"OLLAMA_CONTEXT_LENGTH": "lots"}
	r.recordChatPlacement([]placement{bad})
	if got := r.ChatContextWindow(prof); got != 0 {
		t.Errorf("an unreadable value is not a window: got %d", got)
	}

	r.recordChatPlacement([]placement{{Backend: "vllm", Model: "gemma", DesiredState: "running"}})
	if got := r.ChatContextWindow(prof); got != 0 {
		t.Errorf("vllm: the ollama default is not its window: got %d", got)
	}
	r.recordChatPlacement(nil)
	if got := r.ChatContextWindow(prof); got != 0 {
		t.Errorf("no chat placement: got %d", got)
	}
}
