// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteMediaPartRefusesEveryNonDataMediaURL(t *testing.T) {
	refused := []struct {
		name, body, partType string
	}{
		{"http image_url", `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"http://192.0.2.10/a.png"}}]}]}`, "image_url"},
		{"https bare string image_url", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":"https://example.com/a.png"}]}]}`, "image_url"},
		{"file scheme", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"file:///etc/passwd"}}]}]}`, "image_url"},
		{"anthropic url source", `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.com/a.png"}}]}]}`, "image"},
		{"audio_url", `{"messages":[{"role":"user","content":[{"type":"audio_url","audio_url":{"url":"https://example.com/a.wav"}}]}]}`, "audio_url"},
		{"video_url", `{"messages":[{"role":"user","content":[{"type":"video_url","video_url":{"url":"https://example.com/a.mp4"}}]}]}`, "video_url"},
		{"input_audio url", `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"url":"https://example.com/a.wav"}}]}]}`, "input_audio"},
		{"file part url", `{"messages":[{"role":"user","content":[{"type":"file","file":{"url":"https://example.com/a.pdf"}}]}]}`, "file"},
		{"unknown part url", `{"messages":[{"role":"user","content":[{"type":"brand_new","url":"http://100.64.0.1:8081/x"}]}]}`, "brand_new"},
		{"nested tool_result", `{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"image","source":{"type":"url","url":"http://192.0.2.1/x"}}]}]}]}`, "image"},
	}
	for _, c := range refused {
		got, ok := remoteMediaPart([]byte(c.body))
		if !ok || got != c.partType {
			t.Errorf("%s: remoteMediaPart = (%q, %v), want (%q, true)", c.name, got, ok, c.partType)
		}
	}
}

func TestRemoteMediaPartPassesDataURLsTextAndUnknownParts(t *testing.T) {
	passed := []struct{ name, body string }{
		{"data png", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]}`},
		{"upper-case DATA", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"DATA:image/png;base64,iVBORw0KGgo="}}]}]}`},
		{"text only", `{"messages":[{"role":"system","content":"see https://example.com"},{"role":"user","content":"fetch http://192.0.2.1/"}]}`},
		{"text part holding a link", `{"messages":[{"role":"user","content":[{"type":"text","text":"https://example.com/a.png"}]}]}`},
		{"unknown part without a url", `{"messages":[{"role":"user","content":[{"type":"brand_new","payload":{"x":1}},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`},
		{"tool call arguments", `{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"url\":\"https://example.com\"}"}}]}]}`},
		{"embeddings input", `{"input":["https://example.com"]}`},
		{"not json", `not json`},
	}
	for _, c := range passed {
		if got, ok := remoteMediaPart([]byte(c.body)); ok {
			t.Errorf("%s: refused as %q, want passed", c.name, got)
		}
	}
}

func TestCleanPartTypeBoundsCallerInput(t *testing.T) {
	if got := cleanPartType("image_url\n<script>"); got != "image_urlscript" {
		t.Errorf("cleanPartType = %q", got)
	}
	if got := cleanPartType(""); got != "untyped" {
		t.Errorf("cleanPartType(\"\") = %q", got)
	}
	long := cleanPartType("abcdefghijklmnopqrstuvwxyzabcdefghijklmnop")
	if len(long) != 32 {
		t.Errorf("len = %d", len(long))
	}
}

// The proxy refuses before it picks a backend: a zero Server (no Docker)
// answers 400 with the code, and the answer never echoes the URL.
func TestInferenceProxyRefusesRemoteMediaBeforePickingABackend(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://192.0.2.10/a.png"}}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	w := httptest.NewRecorder()
	(&Server{}).handleInferenceProxy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body)
	}
	var got struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != RemoteMediaURLRefused || !strings.Contains(got.Error.Message, "data: URL") {
		t.Fatalf("error = %+v", got.Error)
	}
	if strings.Contains(w.Body.String(), "192.0.2.10") {
		t.Fatalf("the answer echoes the URL: %s", w.Body)
	}
}
