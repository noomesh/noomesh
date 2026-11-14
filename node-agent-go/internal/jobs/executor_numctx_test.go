// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"encoding/json"
	"strings"
	"testing"
)

// A native Ollama job carries the controller's decided chat context for its
// model as options.num_ctx (i802), so it never reloads the chat runner at
// another context; with none known it sends no options, as before.
func TestOllamaGenerateBodyCarriesTheDecidedContextOnlyWhenKnown(t *testing.T) {
	e := NewExecutor(nil, nil, nil, "http", "http://127.0.0.1:1", "node-1")
	if got := e.decidedContext("gemma4:e2b"); got != 0 {
		t.Fatalf("no lookup installed: want 0, got %d", got)
	}
	e.SetChatContext(func(model string) int {
		if model == "gemma4:e2b" {
			return 16384
		}
		return 0
	})

	raw, err := json.Marshal(ollamaGenerateBody("gemma4:e2b", "hi", e.decidedContext("gemma4:e2b")))
	if err != nil {
		t.Fatal(err)
	}
	var known map[string]any
	if err := json.Unmarshal(raw, &known); err != nil {
		t.Fatal(err)
	}
	opts, ok := known["options"].(map[string]any)
	if !ok || opts["num_ctx"] != float64(16384) {
		t.Fatalf("decided model: want options.num_ctx 16384, got %s", raw)
	}
	if known["stream"] != false || known["prompt"] != "hi" || known["model"] != "gemma4:e2b" {
		t.Fatalf("the rest of the body changed: %s", raw)
	}

	raw, err = json.Marshal(ollamaGenerateBody("other:7b", "hi", e.decidedContext("other:7b")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "options") || strings.Contains(string(raw), "num_ctx") {
		t.Fatalf("unknown model: want no options, got %s", raw)
	}
}
