// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"testing"
)

// desired-config's `chat_contexts` (i802) reaches ChatContext: a bare tag and
// its `:latest` are one model, an unknown model is 0, and a body without the
// key (an older gateway) clears what was held.
func TestChatContextReadsDesiredConfigChatContexts(t *testing.T) {
	var d desiredConfig
	raw := `{"placements": [], "chat_contexts": {"gemma4:e2b": 16384, "qwen3": 8192, "bad": 0}}`
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{}
	if got := r.ChatContext("gemma4:e2b"); got != 0 {
		t.Fatalf("before any desired-config: want 0, got %d", got)
	}
	r.recordChatContexts(d.ChatContexts)
	for model, want := range map[string]int{"gemma4:e2b": 16384, "qwen3": 8192, "qwen3:latest": 8192, "bad": 0, "other:7b": 0, "": 0} {
		if got := r.ChatContext(model); got != want {
			t.Errorf("ChatContext(%q) = %d, want %d", model, got, want)
		}
	}

	var older desiredConfig
	if err := json.Unmarshal([]byte(`{"placements": []}`), &older); err != nil {
		t.Fatal(err)
	}
	r.recordChatContexts(older.ChatContexts)
	if got := r.ChatContext("gemma4:e2b"); got != 0 {
		t.Errorf("an older gateway's body clears the table: got %d", got)
	}
}
