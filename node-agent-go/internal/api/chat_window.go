// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// chatWindowTimeout bounds the live window read: GET /harness/placement must
// answer the harness even when its chat backend does not.
const chatWindowTimeout = 2 * time.Second

// liveChatContext is the context window, in tokens, the running chat backend
// reports for itself, for `model_context` when the agent sets none (vLLM and
// llama.cpp: the agent's env is one of five sources of their window, so only
// the backend knows; noomesh-internal i147). It dials the backend exactly as
// the bench does (resolveBenchTarget). vLLM answers GET /v1/models with
// max_model_len; llama-server answers GET /props with the per-slot n_ctx, the
// window one request gets. 0 = not known (another backend, not running, or no
// usable answer).
func (s *Server) liveChatContext(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, chatWindowTimeout)
	defer cancel()
	resolve := s.resolveBenchTarget
	if s.windowResolve != nil {
		resolve = s.windowResolve
	}
	t, err := resolve(ctx)
	if err != nil {
		return 0
	}
	var path string
	var parse func([]byte, string) int
	switch t.backend {
	case "vllm":
		path, parse = "/v1/models", vllmMaxModelLen
	case "llamacpp":
		path, parse = "/props", llamaSlotContext
	default:
		return 0
	}
	base := strings.TrimSuffix(t.url, "/v1/chat/completions")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0
	}
	return parse(body, t.served)
}

// vllmMaxModelLen is max_model_len from vLLM's /v1/models: the served
// model's entry, else the first entry that has one.
func vllmMaxModelLen(body []byte, served string) int {
	var out struct {
		Data []struct {
			ID          string `json:"id"`
			MaxModelLen int    `json:"max_model_len"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &out) != nil {
		return 0
	}
	first := 0
	for _, m := range out.Data {
		if m.MaxModelLen <= 0 {
			continue
		}
		if m.ID == served {
			return m.MaxModelLen
		}
		if first == 0 {
			first = m.MaxModelLen
		}
	}
	return first
}

// llamaSlotContext is the per-slot n_ctx from llama-server's /props
// (default_generation_settings.n_ctx: --ctx-size divided across
// --parallel slots), else an older build's top-level n_ctx.
func llamaSlotContext(body []byte, _ string) int {
	var out struct {
		Default struct {
			NCtx int `json:"n_ctx"`
		} `json:"default_generation_settings"`
		NCtx int `json:"n_ctx"`
	}
	if json.Unmarshal(body, &out) != nil {
		return 0
	}
	if out.Default.NCtx > 0 {
		return out.Default.NCtx
	}
	if out.NCtx > 0 {
		return out.NCtx
	}
	return 0
}
