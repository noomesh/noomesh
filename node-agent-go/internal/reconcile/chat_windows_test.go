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
