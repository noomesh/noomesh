// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"context"
	"net/http"
	"testing"
)

// An unreadable /api/tags is "could not ask", never "model absent": absent
// makes the reconciler start an ollama pull.
func TestTagsHave(t *testing.T) {
	const tags = `{"models":[{"name":"harrier:latest","model":"harrier:latest"},{"name":"llama3.2:3b","model":"llama3.2:3b"}]}`
	cases := []struct {
		label   string
		body    string
		name    string
		want    bool
		wantErr bool
	}{
		{"valid present", tags, "llama3.2:3b", true, false},
		{"valid absent", tags, "gemma4:12b", false, false},
		{"bare name defaults to :latest", tags, "harrier", true, false},
		{"bare name misses a non-latest tag", tags, "llama3.2", false, false},
		{"empty model list is absent", `{"models":[]}`, "harrier", false, false},
		{"non-JSON", `<html>bad gateway</html>`, "harrier", false, true},
		{"empty body", ``, "harrier", false, true},
		{"truncated JSON", `{"models":[{"name":"harrier:lat`, "harrier", false, true},
	}
	for _, c := range cases {
		got, err := tagsHave([]byte(c.body), c.name)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: tagsHave = %v, %v; want %v, err=%v", c.label, got, err, c.want, c.wantErr)
		}
	}
}

// HasModel carries that through: a 200 with an unreadable body is an error,
// and a 500 (send turns non-2xx into an error) is an error too.
func TestHasModelUnreadableAnswerIsAnError(t *testing.T) {
	for label, h := range map[string]http.HandlerFunc{
		"non-JSON 200": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not json")) },
		"truncated":    func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"models":[{"na`)) },
		"500 json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		},
	} {
		n := stub(t, h)
		has, err := n.HasModel(context.Background(), "harrier")
		if err == nil || has {
			t.Errorf("%s: HasModel = %v, %v; want false with an error", label, has, err)
		}
	}
}
