// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"strings"
	"testing"
	"time"
)

// Table-driven test for the inference-routing rules in pickInferenceBackend.
// Rules (in order):
//  1. honour X-Noo-Backend header if backend is locally running
//  2. exact-match request body's `model` field against running backends
//  3. preference-order fallback (vllm > llamacpp > ollama)
//  4. else "" (caller responds 503)
func TestPickInferenceBackend(t *testing.T) {
	cases := []struct {
		name        string
		running     map[string]string // backendType → modelName
		headerHint  string
		body        []byte
		wantBackend string
	}{
		{
			name:        "header hint matches running backend → wins",
			running:     map[string]string{"vllm": "gemma-4-E4B-it", "llamacpp": "Qwen3.5-0.8B-GGUF"},
			headerHint:  "llamacpp",
			body:        []byte(`{"model":"gemma-4-E4B-it"}`),
			wantBackend: "llamacpp",
		},
		{
			name:        "header hint missing locally → fall through to model match",
			running:     map[string]string{"vllm": "gemma-4-E4B-it"},
			headerHint:  "llamacpp",
			body:        []byte(`{"model":"gemma-4-E4B-it"}`),
			wantBackend: "vllm",
		},
		{
			name:        "no hint → exact body model match",
			running:     map[string]string{"vllm": "gemma-4-E4B-it", "llamacpp": "Qwen3.5-0.8B-GGUF"},
			headerHint:  "",
			body:        []byte(`{"model":"Qwen3.5-0.8B-GGUF"}`),
			wantBackend: "llamacpp",
		},
		{
			name:        "no hint, no model match → preference order: vllm wins",
			running:     map[string]string{"vllm": "gemma-4", "ollama": "llama3"},
			headerHint:  "",
			body:        []byte(`{"model":"unknown"}`),
			wantBackend: "vllm",
		},
		{
			name:        "no hint, no model match, no vllm → llamacpp wins",
			running:     map[string]string{"llamacpp": "Qwen3", "ollama": "llama3"},
			headerHint:  "",
			body:        []byte(`{"model":"unknown"}`),
			wantBackend: "llamacpp",
		},
		{
			name:        "no hint, no model match, no vllm/llamacpp → ollama",
			running:     map[string]string{"ollama": "llama3"},
			headerHint:  "",
			body:        []byte(`{}`),
			wantBackend: "ollama",
		},
		{
			name:        "nothing running → empty (caller will 503)",
			running:     map[string]string{},
			headerHint:  "vllm",
			body:        []byte(`{"model":"gemma-4"}`),
			wantBackend: "",
		},
		{
			name:        "non-JSON body → falls through to preference",
			running:     map[string]string{"vllm": "gemma-4"},
			headerHint:  "",
			body:        []byte("not json"),
			wantBackend: "vllm",
		},
		{
			name:        "empty body → preference order",
			running:     map[string]string{"vllm": "gemma-4"},
			headerHint:  "",
			body:        nil,
			wantBackend: "vllm",
		},
		{
			name:        "header hint trumps body model match",
			running:     map[string]string{"vllm": "gemma-4", "llamacpp": "Qwen3"},
			headerHint:  "vllm",
			body:        []byte(`{"model":"Qwen3"}`),
			wantBackend: "vllm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := pickInferenceBackend(tc.running, tc.headerHint, tc.body)
			if got != tc.wantBackend {
				t.Errorf("pickInferenceBackend() = %q, want %q", got, tc.wantBackend)
			}
		})
	}
}

func TestFilterBodyForBackend(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		backendType string
		mustNotHave []string // keys expected to be stripped
		mustHave    []string // keys expected to be preserved
	}{
		// vLLM-target: keep its vendor extras
		{
			name:        "vllm keeps chat_template_kwargs",
			in:          `{"model":"x","messages":[],"chat_template_kwargs":{"enable_thinking":true}}`,
			backendType: "vllm",
			mustHave:    []string{"chat_template_kwargs", "model"},
		},
		// llamacpp-target: strip vllm extras, keep llamacpp extras
		{
			name:        "llamacpp strips guided_json",
			in:          `{"model":"x","messages":[],"guided_json":{}}`,
			backendType: "llamacpp",
			mustNotHave: []string{"guided_json"},
			mustHave:    []string{"model", "messages"},
		},
		// The harness's thinking-off (disable_on_wire) reaches every engine
		// behind the agent: each keeps the field it reads.
		{
			name:        "vllm keeps the chat template's thinking switch",
			in:          `{"model":"x","messages":[],"chat_template_kwargs":{"enable_thinking":false},"reasoning":{"effort":"none"},"think":false}`,
			backendType: "vllm",
			mustHave:    []string{"chat_template_kwargs"},
			mustNotHave: []string{"think"},
		},
		{
			name:        "llamacpp keeps the chat template's thinking switch",
			in:          `{"model":"x","messages":[],"chat_template_kwargs":{"enable_thinking":false},"reasoning":{"effort":"none"},"think":false}`,
			backendType: "llamacpp",
			mustHave:    []string{"chat_template_kwargs"},
			mustNotHave: []string{"think"},
		},
		{
			name:        "ollama keeps its reasoning fields",
			in:          `{"model":"x","messages":[],"chat_template_kwargs":{"enable_thinking":false},"reasoning":{"effort":"none"},"reasoning_effort":"low","think":false}`,
			backendType: "ollama",
			// chat_template_kwargs too: the /api/chat translator reads it
			// (i183); it is consumed there, never sent to ollama.
			mustHave: []string{"reasoning", "reasoning_effort", "think", "chat_template_kwargs"},
		},
		{
			name:        "llamacpp keeps n_predict",
			in:          `{"model":"x","prompt":"hi","n_predict":256}`,
			backendType: "llamacpp",
			mustHave:    []string{"n_predict", "prompt"},
		},
		// ollama-target: strip vllm + llamacpp extras, keep ollama extras
		{
			name:        "ollama strips n_predict, keeps keep_alive",
			in:          `{"model":"x","messages":[],"n_predict":256,"keep_alive":"5m"}`,
			backendType: "ollama",
			mustNotHave: []string{"n_predict"},
			mustHave:    []string{"keep_alive", "model"},
		},
		// stream_options is portable: the translator's usage chunk
		// depends on it reaching every backend (i147).
		{
			name:        "ollama keeps stream_options",
			in:          `{"model":"x","messages":[],"stream":true,"stream_options":{"include_usage":true}}`,
			backendType: "ollama",
			mustHave:    []string{"stream_options"},
		},
		{
			name:        "llamacpp keeps stream_options",
			in:          `{"model":"x","messages":[],"stream":true,"stream_options":{"include_usage":true}}`,
			backendType: "llamacpp",
			mustHave:    []string{"stream_options"},
		},
		// A Responses reasoning.effort of low|medium|high (i153).
		{
			name:        "vllm keeps reasoning_effort",
			in:          `{"model":"x","messages":[],"reasoning_effort":"high"}`,
			backendType: "vllm",
			mustHave:    []string{"reasoning_effort"},
		},
		// Unknown backend: pass through
		{
			name:        "unknown backend passes body through unchanged",
			in:          `{"model":"x","custom_vendor_key":42}`,
			backendType: "future_backend",
			mustHave:    []string{"custom_vendor_key", "model"},
		},
		// Portable keys always kept
		{
			name:        "portable keys kept across all backends (vllm)",
			in:          `{"model":"x","messages":[],"temperature":0.5,"tools":[]}`,
			backendType: "vllm",
			mustHave:    []string{"model", "messages", "temperature", "tools"},
		},
		{
			name:        "portable keys kept across all backends (llamacpp)",
			in:          `{"model":"x","messages":[],"temperature":0.5,"tools":[]}`,
			backendType: "llamacpp",
			mustHave:    []string{"model", "messages", "temperature", "tools"},
		},
		// Invalid JSON: pass through
		{
			name:        "invalid JSON returns input unchanged",
			in:          `not json`,
			backendType: "vllm",
			mustHave:    nil,
		},
		// Unknown vendor key on KNOWN backend → stripped (allowlist semantics)
		{
			name:        "unknown vendor key stripped from known backend",
			in:          `{"model":"x","messages":[],"some_brand_new_vllm_extension":true}`,
			backendType: "vllm",
			mustNotHave: []string{"some_brand_new_vllm_extension"},
			mustHave:    []string{"model"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filterBodyForBackend([]byte(tc.in), tc.backendType)
			for _, k := range tc.mustNotHave {
				if contains(out, []byte(`"`+k+`"`)) {
					t.Errorf("expected key %q to be stripped, still present: %s", k, out)
				}
			}
			for _, k := range tc.mustHave {
				if !contains(out, []byte(`"`+k+`"`)) {
					t.Errorf("expected key %q to be preserved, missing: %s", k, out)
				}
			}
		})
	}
}

// Tiny indexOf — avoid pulling in `bytes` just for testing.
func contains(haystack, needle []byte) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestFirstByteTimeoutOutlastsAColdModelLoad(t *testing.T) {
	// A cold gemma4:12b load exceeded 60 s on a laptop GPU; the gateway
	// gives a backend call 300 s, and the proxy must not be the one to give
	// up first.
	if d := backendFirstByteTimeout(); d < 240*time.Second || d >= 300*time.Second {
		t.Fatalf("backendFirstByteTimeout = %s; want a bound that outlasts a cold load and stays inside the gateway's 300 s", d)
	}
}

// A first-byte-timeout override is an operator knob on the inference hot
// path, so the parse must fail SAFE: a typo keeps the bound rather than
// removing it. "0" is the one that matters — a zero ResponseHeaderTimeout
// means "wait forever" to net/http, which is exactly the pinned-connection
// bug the bound exists to prevent.
func TestResolveBackendFirstByteTimeout(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", defaultBackendFirstByteTimeout},
		{"   ", defaultBackendFirstByteTimeout},
		{"900", 900 * time.Second},
		{" 900 ", 900 * time.Second},
		{"0", defaultBackendFirstByteTimeout},
		{"-30", defaultBackendFirstByteTimeout},
		{"10m", defaultBackendFirstByteTimeout},
		{"abc", defaultBackendFirstByteTimeout},
	}
	for _, c := range cases {
		if got := resolveBackendFirstByteTimeout(c.raw); got != c.want {
			t.Errorf("resolveBackendFirstByteTimeout(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// a harness placed as `auto` asks its own agent for
// "the model", and the backends validate the name — so `auto` (or no
// model) becomes the served name at the pick, and a named model is left
// for the backend to accept or refuse honestly.
func TestSubstituteAutoModel(t *testing.T) {
	cases := []struct {
		name, body, served, want string
	}{
		{"auto becomes served", `{"model":"auto","messages":[]}`, "gemma4:12b", `"model":"gemma4:12b"`},
		{"absent becomes served", `{"messages":[]}`, "gemma4:12b", `"model":"gemma4:12b"`},
		{"empty becomes served", `{"model":"","messages":[]}`, "gemma4:12b", `"model":"gemma4:12b"`},
		{"named is untouched", `{"model":"llama3.2:3b","messages":[]}`, "gemma4:12b", `"model":"llama3.2:3b"`},
		{"no served name: untouched", `{"model":"auto"}`, "", `"model":"auto"`},
		{"unparseable: untouched", `not json`, "gemma4:12b", `not json`},
	}
	for _, c := range cases {
		got := string(substituteAutoModel([]byte(c.body), c.served))
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %s, want it to contain %s", c.name, got, c.want)
		}
	}
	// The rest of the body survives the rewrite.
	got := string(substituteAutoModel([]byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}],"stream":true}`), "m"))
	for _, keep := range []string{`"messages"`, `"content":"hi"`, `"stream":true`} {
		if !strings.Contains(got, keep) {
			t.Errorf("rewrite dropped %s: %s", keep, got)
		}
	}
}

// What the allowlist removed is named on the answer (i183): sorted, only
// when something was removed, and never for a backend the list does not
// know.
func TestDroppedKeysAreNamedSorted(t *testing.T) {
	body := []byte(`{"model":"x","messages":[],"guided_json":{},"chat_template_kwargs":{},"n_predict":1}`)
	_, dropped := filterBodyForBackendDropped(body, "ollama")
	if got := strings.Join(dropped, ","); got != "guided_json,n_predict" {
		t.Fatalf("ollama dropped %q, want guided_json,n_predict", got)
	}
	if _, dropped := filterBodyForBackendDropped([]byte(`{"model":"x","think":false}`), "ollama"); dropped != nil {
		t.Fatalf("nothing to drop must report nothing, got %v", dropped)
	}
	if _, dropped := filterBodyForBackendDropped(body, "something-new"); dropped != nil {
		t.Fatalf("an unknown backend passes everything through, got %v", dropped)
	}
}
