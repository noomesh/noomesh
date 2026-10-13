// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"testing"
)

// ollama rejects an embeddings request with no `model`, and the proxy
// forwarded that bare 404 to the caller — it read as "the node-agent has no
// /embed route" when in fact routing was correct and the body was short a
// field TEI never needed.
func TestEnsureEmbedModel(t *testing.T) {
	modelOf := func(b []byte) string {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return "<not json>"
		}
		s, _ := m["model"].(string)
		return s
	}

	t.Run("injects the declared model when absent", func(t *testing.T) {
		got := ensureEmbedModel([]byte(`{"input":"hi"}`), "harrier")
		if modelOf(got) != "harrier" {
			t.Errorf("model = %q, want harrier", modelOf(got))
		}
	})

	t.Run("preserves input while injecting", func(t *testing.T) {
		var m map[string]any
		_ = json.Unmarshal(ensureEmbedModel([]byte(`{"input":"hi"}`), "harrier"), &m)
		if m["input"] != "hi" {
			t.Errorf("input = %v, want hi", m["input"])
		}
	})

	t.Run("caller's explicit model wins", func(t *testing.T) {
		got := ensureEmbedModel([]byte(`{"input":"hi","model":"explicit"}`), "harrier")
		if modelOf(got) != "explicit" {
			t.Errorf("model = %q, want explicit", modelOf(got))
		}
	})

	t.Run("empty declared model leaves body untouched", func(t *testing.T) {
		in := []byte(`{"input":"hi"}`)
		if got := ensureEmbedModel(in, ""); string(got) != string(in) {
			t.Errorf("body = %s, want unchanged", got)
		}
	})

	t.Run("blank model field is treated as absent", func(t *testing.T) {
		got := ensureEmbedModel([]byte(`{"input":"hi","model":"  "}`), "harrier")
		if modelOf(got) != "harrier" {
			t.Errorf("model = %q, want harrier", modelOf(got))
		}
	})

	t.Run("non-JSON body passes through rather than erroring", func(t *testing.T) {
		in := []byte(`not json`)
		if got := ensureEmbedModel(in, "harrier"); string(got) != string(in) {
			t.Errorf("body = %s, want unchanged", got)
		}
	})
}
