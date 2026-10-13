// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each engine's native encode/decode must round-trip to the SAME
// OpenAI-shaped result, because /embed's contract is identical regardless
// of which engine served it. A dialect that encodes correctly but decodes
// into the wrong shape is the silent-wrong-answer case.
func TestEmbedDialects(t *testing.T) {
	t.Run("every dialect has a path, encode and decode", func(t *testing.T) {
		for name, d := range embedDialects {
			if d.path == "" || d.encode == nil || d.decode == nil {
				t.Errorf("dialect %q is incomplete: path=%q encode=%v decode=%v",
					name, d.path, d.encode != nil, d.decode != nil)
			}
		}
	})

	t.Run("tei encodes to inputs and decodes a bare matrix", func(t *testing.T) {
		b, err := embedDialects[backendTEI].encode([]string{"a", "b"}, "ignored", nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if _, ok := m["inputs"]; !ok {
			t.Errorf("tei body missing 'inputs': %s", b)
		}
		v, err := embedDialects[backendTEI].decode([]byte(`[[1.0,2.0],[3.0,4.0]]`))
		if err != nil || len(v) != 2 || v[1][1] != 4.0 {
			t.Errorf("tei decode = %v, err=%v", v, err)
		}
	})

	t.Run("ollama encodes model+input and decodes embeddings", func(t *testing.T) {
		b, err := embedDialects[backendOllama].encode([]string{"a"}, "harrier", nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if m["model"] != "harrier" {
			t.Errorf("ollama body model = %v, want harrier", m["model"])
		}
		v, err := embedDialects[backendOllama].decode([]byte(`{"embeddings":[[1.0,2.0]]}`))
		if err != nil || len(v) != 1 || v[0][0] != 1.0 {
			t.Errorf("ollama decode = %v, err=%v", v, err)
		}
	})

	// The original bug, now a hard error at encode time instead of a
	// confusing 404 from the engine.
	t.Run("ollama refuses to encode without a model", func(t *testing.T) {
		if _, err := embedDialects[backendOllama].encode([]string{"a"}, "", nil); err == nil {
			t.Error("expected an error when no model is available, got nil")
		}
	})

	t.Run("garbage decodes to an error, never silent empty", func(t *testing.T) {
		for name, d := range embedDialects {
			if _, err := d.decode([]byte(`"nonsense"`)); err == nil {
				t.Errorf("dialect %q decoded garbage without error", name)
			}
		}
	})
}

// The gateway sends `options.num_ctx` on every embed so ollama allocates a
// small window per slot instead of its 8192 default. Two things must hold
// or that is a no-op: the options reach ollama's NATIVE body, and the proxy
// takes the native route (ollama's /v1/embeddings drops `options`).
func TestOllamaEmbedCarriesOptionsToTheNativeBody(t *testing.T) {
	opts := embedOptions([]byte(`{"input":["a"],"options":{"num_ctx":1024}}`))
	b, err := embedDialects[backendOllama].encode([]string{"a"}, "harrier", opts)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got struct {
		Options map[string]any `json:"options"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Options["num_ctx"] != float64(1024) {
		t.Errorf("native body options = %v, want num_ctx 1024 (body %s)", got.Options, b)
	}
	// No options -> no options key (TEI and old callers unchanged).
	b, _ = embedDialects[backendOllama].encode([]string{"a"}, "harrier", nil)
	if strings.Contains(string(b), "options") {
		t.Errorf("no options expected, got %s", b)
	}
}

func TestEmbedNativeFirstOnlyForOllamaWithOptions(t *testing.T) {
	with := []byte(`{"input":["a"],"options":{"num_ctx":1024}}`)
	without := []byte(`{"input":["a"]}`)
	if !embedNativeFirst(backendOllama, with) {
		t.Error("ollama + options must go native first (the v1 route drops options)")
	}
	if embedNativeFirst(backendOllama, without) {
		t.Error("ollama without options keeps the OpenAI route")
	}
	if embedNativeFirst(backendTEI, with) {
		t.Error("TEI keeps the OpenAI route")
	}
}

func TestStripEmbedOptionsForNonOllamaEngines(t *testing.T) {
	got := stripEmbedOptions([]byte(`{"input":["a"],"options":{"num_ctx":1024}}`))
	if strings.Contains(string(got), "options") || !strings.Contains(string(got), `"input"`) {
		t.Errorf("options must go, input must stay: %s", got)
	}
	in := []byte(`not json`)
	if string(stripEmbedOptions(in)) != string(in) {
		t.Error("non-JSON passes through")
	}
}

// The gateway pins the embed model with `keep_alive` on every ollama embed
// so it is not unloaded after ollama's 5 idle minutes. Like `options`, it
// only survives on ollama's native /api/embed body, so the proxy must go
// native for it and carry it across.
func TestOllamaEmbedBodyCarriesKeepAlive(t *testing.T) {
	in := []byte(`{"input":["a"],"keep_alive":"30m"}`)
	if !embedNativeFirst(backendOllama, in) {
		t.Fatal("ollama + keep_alive must go native first (the v1 route drops it)")
	}
	native, err := embedDialects[backendOllama].encode([]string{"a"}, "harrier", embedOptions(in))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	native = withEmbedKeepAlive(native, embedKeepAlive(in))
	var got struct {
		KeepAlive string `json:"keep_alive"`
		Model     string `json:"model"`
	}
	if err := json.Unmarshal(native, &got); err != nil {
		t.Fatal(err)
	}
	if got.KeepAlive != "30m" || got.Model != "harrier" {
		t.Errorf("native /api/embed body = %s, want keep_alive 30m and model harrier", native)
	}
	// Absent keep_alive: body unchanged.
	plain, _ := embedDialects[backendOllama].encode([]string{"a"}, "harrier", nil)
	if string(withEmbedKeepAlive(plain, embedKeepAlive([]byte(`{"input":["a"]}`)))) != string(plain) {
		t.Error("no keep_alive must leave the native body untouched")
	}
}

func TestStripEmbedKeepAliveForNonOllamaEngines(t *testing.T) {
	got := stripEmbedKeepAlive([]byte(`{"input":["a"],"keep_alive":"30m"}`))
	if strings.Contains(string(got), "keep_alive") || !strings.Contains(string(got), `"input"`) {
		t.Errorf("keep_alive must go, input must stay: %s", got)
	}
}
