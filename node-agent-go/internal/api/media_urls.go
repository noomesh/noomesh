// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"strings"
)

// Remote media URLs in chat content parts: the second wall (0.6.29).
//
// vLLM fetches an http(s) media URL in a content part itself (image_url,
// audio_url, video_url), from the backend's network; llama-server can too.
// The gateway refuses every media URL that is not an inline data: URL
// (gateway-rust/src/inline_media.rs, which also checks the type, size and
// bytes of inline media). This is the same rule as a scheme check only, on
// the body the inference proxy is about to forward, so a request that
// reached the agent some other way is refused here as well.

// RemoteMediaURLRefused is the error code of the refusal, the same code the
// gateway answers with.
const RemoteMediaURLRefused = "remote_media_url_refused"

// remoteMediaPart reports the type of the first content part that names a
// media URL other than an inline data: URL, walking messages[*].content
// (and a part's own nested content or output). A body that is not JSON, or
// has no such part, reports false. The URL itself is never returned.
func remoteMediaPart(body []byte) (string, bool) {
	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return "", false
	}
	for _, m := range req.Messages {
		if t, ok := remoteInItem(m); ok {
			return t, true
		}
	}
	return "", false
}

// remoteInItem checks one message or part, then the parts it holds.
func remoteInItem(raw json.RawMessage) (string, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return "", false // a string, null, or a number: not a part
	}
	var typ string
	_ = json.Unmarshal(obj["type"], &typ)
	for k, v := range obj {
		urlField := k == "url" || strings.HasSuffix(k, "_url")
		// The object named by the part's type (file: {url}) and an Anthropic
		// source carry the URL inside; their string form is not a URL
		// (text: "...").
		objectField := k == "source" || (typ != "" && k == typ)
		if !urlField && !objectField {
			continue
		}
		if u, ok := mediaURLOf(v, urlField); ok && isRemoteMediaURL(u) {
			return cleanPartType(typ), true
		}
	}
	for _, key := range []string{"content", "output"} {
		v, ok := obj[key]
		if !ok {
			continue
		}
		var parts []json.RawMessage
		if json.Unmarshal(v, &parts) == nil {
			for _, p := range parts {
				if t, ok := remoteInItem(p); ok {
					return t, true
				}
			}
			continue
		}
		if t, ok := remoteInItem(v); ok {
			return t, true
		}
	}
	return "", false
}

// mediaURLOf is the link a field holds: the string itself (when the field is
// a link field), or the link field of an object such as image_url or an
// Anthropic source.
func mediaURLOf(v json.RawMessage, stringIsURL bool) (string, bool) {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s, stringIsURL
	}
	var o struct {
		URL *string `json:"url"`
	}
	if json.Unmarshal(v, &o) == nil && o.URL != nil {
		return *o.URL, true
	}
	return "", false
}

// isRemoteMediaURL is true for any non-empty URL that is not data:.
func isRemoteMediaURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	return len(u) < 5 || !strings.EqualFold(u[:5], "data:")
}

// cleanPartType is a part type as it may appear in a log line or a message:
// the caller's own input, cut to 32 characters of [A-Za-z0-9_-].
func cleanPartType(raw string) string {
	var b strings.Builder
	for _, c := range raw {
		if b.Len() >= 32 {
			break
		}
		if c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "untyped"
	}
	return b.String()
}
