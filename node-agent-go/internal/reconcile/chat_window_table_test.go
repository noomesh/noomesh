// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"testing"
)

// desired-config's `chat_windows` (i1411) reaches ChatWindows: names as
// placed, zero and blank dropped, a copy handed out, and a body without the
// key (an older gateway) clears what was held.
func TestChatWindowsReadDesiredConfigChatWindows(t *testing.T) {
	var d desiredConfig
	raw := `{"placements": [], "chat_windows": {"Llama-3.2-3B-Instruct-Q4_K_M.gguf": 4096, " org/vllm-model ": 8192, "zero": 0, "": 2048}}`
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{}
	if r.ChatWindows() != nil {
		t.Fatal("before any desired-config: no table")
	}
	r.recordChatWindows(d.ChatWindows)
	got := r.ChatWindows()
	if len(got) != 2 || got["Llama-3.2-3B-Instruct-Q4_K_M.gguf"] != 4096 || got["org/vllm-model"] != 8192 {
		t.Fatalf("ChatWindows() = %v", got)
	}
	got["org/vllm-model"] = 1
	if r.ChatWindows()["org/vllm-model"] != 8192 {
		t.Fatal("ChatWindows() must hand out a copy")
	}

	var older desiredConfig
	if err := json.Unmarshal([]byte(`{"placements": []}`), &older); err != nil {
		t.Fatal(err)
	}
	r.recordChatWindows(older.ChatWindows)
	if r.ChatWindows() != nil {
		t.Errorf("an older gateway's body clears the table: got %v", r.ChatWindows())
	}
}

// The shipped harness is pinned to the model "auto" (the proxy substitutes
// the real one), so /harness/placement states the window under that name:
// the smallest known across the running chat placements, an engine window or
// an Ollama decided context alike. Named entries stay.
func TestPlacementStatesTheWindowOfAuto(t *testing.T) {
	r := &Reconciler{}
	r.chatModels = []ChatModel{{"llamacpp", "Llama-3.2-3B-Instruct-Q4_K_M.gguf"}, {"vllm", "org/big"}, {"ollama", "gemma4:e2b"}}
	r.recordChatWindows(map[string]int{"Llama-3.2-3B-Instruct-Q4_K_M.gguf": 4096, "org/big": 16384})
	r.recordChatContexts(map[string]int{"gemma4:e2b": 32768})

	w := r.ChatWindows()
	if w["auto"] != 4096 || w["Llama-3.2-3B-Instruct-Q4_K_M.gguf"] != 4096 || w["org/big"] != 16384 || len(w) != 3 {
		t.Fatalf("ChatWindows() = %v", w)
	}
	c := r.ChatContexts()
	if c["auto:latest"] != 4096 || c["gemma4:e2b"] != 32768 || len(c) != 2 {
		t.Fatalf("ChatContexts() = %v (auto is the smallest across engines, under the key the harness looks up)", c)
	}

	// The stored tables are untouched by the copies.
	if r.ChatWindows()["auto"] != 4096 || r.chatWindows["auto"] != 0 {
		t.Fatal("auto must be added to the copy only")
	}

	// A lone Ollama: its decided context is auto's; no engine table, no auto window.
	o := &Reconciler{}
	o.chatModels = []ChatModel{{"ollama", "gemma4:e2b"}}
	o.recordChatContexts(map[string]int{"gemma4:e2b": 8192})
	if got := o.ChatContexts(); got["auto:latest"] != 8192 {
		t.Fatalf("lone ollama: %v", got)
	}
	if o.ChatWindows() != nil {
		t.Fatalf("no engine window: no table, got %v", o.ChatWindows())
	}

	// Nothing known: nothing stated for auto.
	n := &Reconciler{}
	n.chatModels = []ChatModel{{"llamacpp", "x.gguf"}}
	if n.ChatWindows() != nil || n.ChatContexts() != nil {
		t.Fatal("nothing known: no auto entry")
	}
}

// A placement whose window is unknown is ignored by `auto`: never 0, never
// the reason the key is absent when another placement's window is known.
func TestAutoIgnoresAPlacementWithNoKnownWindow(t *testing.T) {
	r := &Reconciler{}
	r.chatModels = []ChatModel{{"vllm", "org/known"}, {"llamacpp", "unknown.gguf"}, {"ollama", "nodecided:1b"}}
	r.recordChatWindows(map[string]int{"org/known": 8192})
	w := r.ChatWindows()
	if w["auto"] != 8192 {
		t.Fatalf("auto must be the known window, got %v", w)
	}
	if _, ok := w["unknown.gguf"]; ok || len(w) != 2 {
		t.Fatalf("the unknown model stays unstated: %v", w)
	}
	if got := autoWindow(r.chatModels, r.chatWindows, nil); got != 8192 {
		t.Fatalf("autoWindow = %d, want 8192", got)
	}
}
