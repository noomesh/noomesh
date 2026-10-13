// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Embedding dialects.
//
// The node-agent's /embed contract is OpenAI-shaped in BOTH directions:
// callers send `{input, model?}` and get back `{object:"list", data:[...]}`
// no matter which engine actually served the request. Engines disagree
// about the native route and payload underneath, though, and /embed was
// written when TEI was the only embedder — so it hardcoded TEI's route and
// TEI's response shape.
//
// That was invisible until a node served embeddings from something else.
// host8 runs harrier on ollama; /embed dutifully posted TEI's
// `POST /embed {inputs}` at it, ollama does not serve that route, and its
// bare "404 page not found" went back to the caller looking like the
// node-agent had no such endpoint. The routing was right; the dialect was
// wrong.
//
// So dialects live in a table keyed by backend type (which the role=embed
// placement tells us), not in a chain of per-engine branches. Adding an
// engine is an entry here plus its two translation funcs — no edits to the
// proxy's control flow.
//
// The OpenAI-compatible path is still tried FIRST for every engine; these
// are the fallback for engines that don't serve /v1/embeddings (or serve it
// only in newer versions).
//
// Only engines actually verified against a running server belong here. An
// entry written from documentation alone is worse than no entry: an unknown
// backend falls back to TEI's dialect and fails loudly, whereas a WRONG
// decoder can take the wrong slice of a valid response and return vectors
// that are silently in the wrong space -- the exact failure this whole
// change exists to prevent. llama.cpp can serve embeddings (it is the same
// BERT machinery as the --reranking cross-encoder already in the fleet),
// but its /embedding response shape varies with --pooling, so it gets an
// entry when someone places a gguf embedder and probes it, not before.

const (
	backendTEI    = "embedding" // TEI — the `embedding` backend type
	backendOllama = "ollama"
)

// embedDialect describes one engine's native embeddings API.
type embedDialect struct {
	// path is appended to the backend base URL, e.g. "/api/embed".
	path string
	// encode builds the native request body from OpenAI-shaped inputs.
	//
	// options is the caller's engine tuning object (`{"num_ctx":1024}`),
	// verbatim, or nil. Only ollama's native API honours it: its
	// /v1/embeddings compatibility route drops `options` (the OpenAI
	// middleware rebuilds the request from model/input/dimensions only),
	// which is why ollama is spoken to natively first (see
	// embedNativeFirst).
	encode func(inputs []string, model string, options json.RawMessage) ([]byte, error)
	// decode extracts vectors from the native response body.
	decode func(raw []byte) ([][]float64, error)
}

var embedDialects = map[string]embedDialect{
	// TEI native: POST /embed {inputs:[...]} -> [[...], ...]
	// TEI serves exactly one model and ignores any model field.
	backendTEI: {
		path: "/embed",
		encode: func(inputs []string, _ string, _ json.RawMessage) ([]byte, error) {
			return json.Marshal(map[string]any{"inputs": inputs, "truncate": true})
		},
		decode: func(raw []byte) ([][]float64, error) {
			var v [][]float64
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("unexpected TEI /embed response shape: %w", err)
			}
			return v, nil
		},
	},

	// ollama native: POST /api/embed {model, input:[...]}
	//             -> {"embeddings": [[...], ...]}
	// REQUIRES model — a request without one is rejected, which is the
	// failure that started all this.
	backendOllama: {
		path: "/api/embed",
		encode: func(inputs []string, model string, options json.RawMessage) ([]byte, error) {
			if model == "" {
				return nil, fmt.Errorf("ollama embeddings require a model; " +
					"none in the request and none declared by the role=embed placement")
			}
			body := map[string]any{"model": model, "input": inputs}
			if len(options) > 0 && string(options) != "null" {
				body["options"] = options
			}
			return json.Marshal(body)
		},
		decode: func(raw []byte) ([][]float64, error) {
			var d struct {
				Embeddings [][]float64 `json:"embeddings"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return nil, fmt.Errorf("unexpected ollama /api/embed response shape: %w", err)
			}
			return d.Embeddings, nil
		},
	},
}

// embedNativeFirst reports whether /embed should skip the OpenAI-compatible
// route and speak the engine's native API straight away. True for ollama
// when the caller sent engine `options`: ollama's /v1/embeddings silently
// drops them, so an OpenAI-route passthrough would answer 200 with the
// context window the caller asked to shrink never applied (the model then
// loads at ollama's default 8192-token window, ~2.6 GB for harrier). Every
// other engine keeps the OpenAI route first, unchanged.
func embedNativeFirst(backend string, body []byte) bool {
	if backend != backendOllama {
		return false
	}
	return len(embedOptions(body)) > 0 || len(embedKeepAlive(body)) > 0
}

// embedKeepAlive extracts the `keep_alive` value (a duration string such as
// "30m", or a number) from an /embed request body, or nil when absent. It is
// ollama's per-model residency knob: the gateway pins the embed model so it
// is not unloaded after ollama's 5 idle minutes. Like `options`, ollama's
// /v1/embeddings route drops it, so only the native API honours it.
func embedKeepAlive(body []byte) json.RawMessage {
	var in struct {
		KeepAlive json.RawMessage `json:"keep_alive"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil
	}
	k := bytes.TrimSpace(in.KeepAlive)
	if len(k) == 0 || string(k) == "null" {
		return nil
	}
	return k
}

// withEmbedKeepAlive adds `keep_alive` to an already-encoded native ollama
// body. A nil keepAlive, or a body that is not a JSON object, passes through.
func withEmbedKeepAlive(native []byte, keepAlive json.RawMessage) []byte {
	if len(keepAlive) == 0 {
		return native
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(native, &obj); err != nil {
		return native
	}
	obj["keep_alive"] = keepAlive
	out, err := json.Marshal(obj)
	if err != nil {
		return native
	}
	return out
}

// embedOptions extracts the `options` object from an /embed request body,
// or nil when absent / not an object.
func embedOptions(body []byte) json.RawMessage {
	var in struct {
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil
	}
	o := bytes.TrimSpace(in.Options)
	if len(o) == 0 || o[0] != '{' {
		return nil
	}
	return o
}
