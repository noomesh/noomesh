// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"testing"
)

// i802: the translated /api/chat body carries the controller's decided chat
// context when nobody set one; a stamped or caller-set value stands, and an
// unknown context (0) leaves the body untouched.
func TestWithDecidedNumCtxFillsOnlyWhenAbsent(t *testing.T) {
	read := func(b []byte) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("not JSON: %s", b)
		}
		return m
	}
	got := read(withDecidedNumCtx([]byte(`{"model":"gemma4:e2b","options":{"num_predict":512}}`), 16384))
	opts := got["options"].(map[string]any)
	if opts["num_ctx"] != float64(16384) || opts["num_predict"] != float64(512) {
		t.Fatalf("want num_ctx 16384 beside num_predict: %v", opts)
	}
	got = read(withDecidedNumCtx([]byte(`{"model":"m"}`), 8192))
	if got["options"].(map[string]any)["num_ctx"] != float64(8192) {
		t.Fatalf("no options yet: want them created: %v", got)
	}
	kept := read(withDecidedNumCtx([]byte(`{"model":"m","options":{"num_ctx":2048}}`), 16384))
	if kept["options"].(map[string]any)["num_ctx"] != float64(2048) {
		t.Fatalf("a set num_ctx stands: %v", kept)
	}
	in := []byte(`{"model":"m"}`)
	if string(withDecidedNumCtx(in, 0)) != string(in) {
		t.Fatal("unknown context: unchanged")
	}
	if string(withDecidedNumCtx([]byte(`not json`), 4096)) != "not json" {
		t.Fatal("not JSON: unchanged")
	}
}
