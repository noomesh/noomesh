// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// OpenAI chat over Ollama's NATIVE /api/chat.
//
// Ollama's OpenAI-compatible layer does not stream a request that carries
// `tools`: it holds every chunk until the whole answer exists, so the first
// byte arrives when the answer is complete. Measured on mcmini (Ollama
// 0.33.3, gemma4:12b, the same short prompt, 2026-10-21): /v1 with one tool
// 84 s to the first byte, every chunk at once; /v1 without tools 4 s;
// /api/chat with the same tool 2 s, one token per ~0.33 s. Every call the
// native harness makes carries the mesh tools, so through /v1 each one sat
// silent past the harness's stream idle bound and was cut (noomesh-internal
// i159).
//
// So a chat request bound for an ollama is translated here to /api/chat and
// its reply translated back to OpenAI chat — streamed as SSE chunks line by
// line, or folded into one chat.completion. One place covers every caller:
// the gateway's routing, the native harness and the foreign-kind translator
// all speak OpenAI chat to this proxy. The shapes mirror the gateway's
// harness translator (`harness/translator.rs`, mod ollama), plus reasoning:
// Ollama's `message.thinking` comes back as `reasoning`, the field its own
// /v1 layer uses and the gateway reads, and the request's reasoning control
// (`reasoning.effort`, `reasoning_effort`, `chat_template_kwargs.
// enable_thinking`, or `think` itself) becomes `think`.

// ollamaChatRequest is an OpenAI chat body as Ollama's /api/chat takes it,
// and what the reply needs to know about the request.
type ollamaChatRequest struct {
	body         []byte
	model        string
	stream       bool
	includeUsage bool
}

// openAIToOllamaChat translates an OpenAI chat-completions body. Ollama takes
// OpenAI's message and tool shapes except that a tool call's `arguments` is
// an object, not a string; sampling options live under `options`; an
// image is a base64 string under `images`; and reasoning is `think`.
func openAIToOllamaChat(body []byte) (ollamaChatRequest, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(body, &in); err != nil {
		return ollamaChatRequest{}, fmt.Errorf("chat body is not a JSON object: %w", err)
	}
	req := ollamaChatRequest{}
	out := map[string]any{}

	var model string
	_ = json.Unmarshal(in["model"], &model)
	req.model = model
	out["model"] = model

	_ = json.Unmarshal(in["stream"], &req.stream)
	out["stream"] = req.stream
	if raw, ok := in["stream_options"]; ok {
		var so struct {
			IncludeUsage bool `json:"include_usage"`
		}
		_ = json.Unmarshal(raw, &so)
		req.includeUsage = so.IncludeUsage
	}

	var msgs []map[string]json.RawMessage
	_ = json.Unmarshal(in["messages"], &msgs)
	messages := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		messages = append(messages, ollamaMessage(m))
	}
	out["messages"] = messages

	// tool_choice "none" means the model may not call a tool: send none.
	var toolChoice string
	_ = json.Unmarshal(in["tool_choice"], &toolChoice)
	if raw, ok := in["tools"]; ok && toolChoice != "none" {
		var tools []any
		if json.Unmarshal(raw, &tools) == nil && len(tools) > 0 {
			out["tools"] = tools
		}
	}

	if think, ok := ollamaThink(in); ok {
		out["think"] = think
	}

	options := map[string]any{}
	// A caller's own `options` (an Ollama extra the allowlist keeps) is the
	// base; the OpenAI fields map onto it.
	if raw, ok := in["options"]; ok {
		_ = json.Unmarshal(raw, &options)
	}
	for from, to := range map[string]string{
		"max_tokens": "num_predict", "max_completion_tokens": "num_predict",
		"temperature": "temperature", "top_p": "top_p", "seed": "seed",
		"presence_penalty": "presence_penalty", "frequency_penalty": "frequency_penalty",
	} {
		raw, ok := in[from]
		if !ok || string(raw) == "null" {
			continue
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			options[to] = v
		}
	}
	if raw, ok := in["stop"]; ok && string(raw) != "null" {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			options["stop"] = []string{one}
		case json.Unmarshal(raw, &many) == nil:
			options["stop"] = many
		}
	}
	if len(options) > 0 {
		out["options"] = options
	}

	// JSON mode: OpenAI's response_format onto Ollama's `format`.
	if raw, ok := in["response_format"]; ok {
		var rf struct {
			Type       string          `json:"type"`
			JSONSchema json.RawMessage `json:"json_schema"`
		}
		if json.Unmarshal(raw, &rf) == nil {
			switch rf.Type {
			case "json_object":
				out["format"] = "json"
			case "json_schema":
				var js struct {
					Schema json.RawMessage `json:"schema"`
				}
				if json.Unmarshal(rf.JSONSchema, &js) == nil && len(js.Schema) > 0 {
					out["format"] = json.RawMessage(js.Schema)
				}
			}
		}
	}
	for _, k := range []string{"format", "keep_alive"} {
		if raw, ok := in[k]; ok && string(raw) != "null" {
			if _, already := out[k]; !already {
				out[k] = json.RawMessage(raw)
			}
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return ollamaChatRequest{}, err
	}
	req.body = b
	return req, nil
}

// ollamaMessage is one OpenAI chat message in Ollama's shape: text content
// joined from parts, data-URL images lifted to `images`, a tool call's
// string arguments parsed to an object, a tool result's `name` as
// `tool_name`.
func ollamaMessage(m map[string]json.RawMessage) map[string]any {
	out := map[string]any{"role": "user"}
	var role string
	if json.Unmarshal(m["role"], &role) == nil && role != "" {
		out["role"] = role
	}
	text, images := openAIContent(m["content"])
	out["content"] = text
	if len(images) > 0 {
		out["images"] = images
	}
	if raw, ok := m["tool_calls"]; ok {
		var calls []map[string]json.RawMessage
		if json.Unmarshal(raw, &calls) == nil && len(calls) > 0 {
			tc := make([]map[string]any, 0, len(calls))
			for _, c := range calls {
				f := c
				if inner, ok := c["function"]; ok {
					var fn map[string]json.RawMessage
					if json.Unmarshal(inner, &fn) == nil {
						f = fn
					}
				}
				var name string
				_ = json.Unmarshal(f["name"], &name)
				args := map[string]any{}
				var asString string
				if json.Unmarshal(f["arguments"], &asString) == nil {
					var parsed map[string]any
					if json.Unmarshal([]byte(asString), &parsed) == nil {
						args = parsed
					}
				} else {
					var parsed map[string]any
					if json.Unmarshal(f["arguments"], &parsed) == nil {
						args = parsed
					}
				}
				tc = append(tc, map[string]any{"function": map[string]any{"name": name, "arguments": args}})
			}
			out["tool_calls"] = tc
		}
	}
	if raw, ok := m["tool_call_id"]; ok {
		out["tool_call_id"] = json.RawMessage(raw)
	}
	if raw, ok := m["name"]; ok {
		out["tool_name"] = json.RawMessage(raw)
	}
	return out
}

// openAIContent is a message's content as text, plus any data-URL images:
// a string as is, or the text parts of a parts array joined.
func openAIContent(raw json.RawMessage) (string, []string) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) != nil {
		return "", nil
	}
	var text strings.Builder
	var images []string
	for _, p := range parts {
		var t string
		if json.Unmarshal(p["text"], &t) == nil && t != "" {
			text.WriteString(t)
		}
		var img struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(p["image_url"], &img) == nil && strings.HasPrefix(img.URL, "data:") {
			if i := strings.Index(img.URL, ","); i > 0 {
				images = append(images, img.URL[i+1:])
			}
		}
	}
	return text.String(), images
}

// ollamaThink is the request's reasoning control as /api/chat's `think`:
// `think` itself when the caller sent one (the harness's thinking-off sends
// it); else `reasoning.effort` / `reasoning_effort` none|minimal → false,
// low|medium|high → true; else `chat_template_kwargs.enable_thinking`.
// Nothing → unset, the model's own default.
func ollamaThink(in map[string]json.RawMessage) (bool, bool) {
	if raw, ok := in["think"]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b, true
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return !strings.EqualFold(s, "false") && !strings.EqualFold(s, "none"), true
		}
	}
	effort := ""
	if raw, ok := in["reasoning"]; ok {
		var r struct {
			Effort string `json:"effort"`
		}
		_ = json.Unmarshal(raw, &r)
		effort = r.Effort
	}
	if effort == "" {
		_ = json.Unmarshal(in["reasoning_effort"], &effort)
	}
	switch strings.ToLower(effort) {
	case "none", "minimal":
		return false, true
	case "low", "medium", "high":
		return true, true
	}
	if raw, ok := in["chat_template_kwargs"]; ok {
		var kw struct {
			EnableThinking *bool `json:"enable_thinking"`
		}
		if json.Unmarshal(raw, &kw) == nil && kw.EnableThinking != nil {
			return *kw.EnableThinking, true
		}
	}
	return false, false
}

// ollamaReply is one /api/chat object: a streamed line or the whole reply.
type ollamaReply struct {
	Model   string `json:"model"`
	Message struct {
		Role      string            `json:"role"`
		Content   string            `json:"content"`
		Thinking  string            `json:"thinking"`
		ToolCalls []json.RawMessage `json:"tool_calls"`
	} `json:"message"`
	Done            bool   `json:"done"`
	DoneReason      string `json:"done_reason"`
	PromptEvalCount *int64 `json:"prompt_eval_count"`
	EvalCount       *int64 `json:"eval_count"`
	Error           string `json:"error"`
}

// openAIToolCalls lifts Ollama's tool calls (object arguments, no id) to
// OpenAI's (string arguments, an id, an index from firstIndex).
func openAIToolCalls(calls []json.RawMessage, firstIndex int, withIndex bool) []map[string]any {
	out := make([]map[string]any, 0, len(calls))
	for i, raw := range calls {
		var c map[string]json.RawMessage
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		f := c
		if inner, ok := c["function"]; ok {
			var fn map[string]json.RawMessage
			if json.Unmarshal(inner, &fn) == nil {
				f = fn
			}
		}
		var name string
		_ = json.Unmarshal(f["name"], &name)
		args := "{}"
		if raw, ok := f["arguments"]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				args = s
			} else {
				args = string(raw)
			}
		}
		id := ""
		_ = json.Unmarshal(c["id"], &id)
		if id == "" {
			id = fmt.Sprintf("call_%d", firstIndex+i)
		}
		tc := map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": args}}
		if withIndex {
			tc["index"] = firstIndex + i
		}
		out = append(out, tc)
	}
	return out
}

func ollamaUsage(r *ollamaReply) map[string]any {
	if r.PromptEvalCount == nil && r.EvalCount == nil {
		return nil
	}
	var p, c int64
	if r.PromptEvalCount != nil {
		p = *r.PromptEvalCount
	}
	if r.EvalCount != nil {
		c = *r.EvalCount
	}
	return map[string]any{"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}
}

func ollamaFinish(r *ollamaReply, hadTools bool) string {
	switch {
	case hadTools:
		return "tool_calls"
	case r.DoneReason == "length":
		return "length"
	default:
		return "stop"
	}
}

// ollamaToOpenAIResponse folds one whole /api/chat reply into an OpenAI
// chat.completion.
func ollamaToOpenAIResponse(r *ollamaReply, model string, id string, created int64) map[string]any {
	message := map[string]any{"role": "assistant", "content": r.Message.Content}
	if r.Message.Thinking != "" {
		message["reasoning"] = r.Message.Thinking
	}
	if len(r.Message.ToolCalls) > 0 {
		message["tool_calls"] = openAIToolCalls(r.Message.ToolCalls, 0, false)
	}
	if r.Model != "" {
		model = r.Model
	}
	out := map[string]any{
		"id": id, "object": "chat.completion", "created": created, "model": model,
		"choices": []map[string]any{{"index": 0, "message": message, "finish_reason": ollamaFinish(r, len(r.Message.ToolCalls) > 0)}},
	}
	if u := ollamaUsage(r); u != nil {
		out["usage"] = u
	}
	return out
}

// ollamaChunker turns streamed /api/chat lines into OpenAI chunks.
type ollamaChunker struct {
	id           string
	model        string
	created      int64
	includeUsage bool
	tools        int
	sentRole     bool
}

func (c *ollamaChunker) chunk(choices []map[string]any) map[string]any {
	return map[string]any{"id": c.id, "object": "chat.completion.chunk", "created": c.created, "model": c.model, "choices": choices}
}

func (c *ollamaChunker) delta(d map[string]any) map[string]any {
	if !c.sentRole {
		d["role"] = "assistant"
		c.sentRole = true
	}
	return c.chunk([]map[string]any{{"index": 0, "delta": d, "finish_reason": nil}})
}

// chunks is one NDJSON object → zero or more OpenAI chunks. Content and
// thinking stream as they arrive; a tool call arrives whole; the closing
// `done` object becomes the finish chunk and the usage (a chunk of its own
// when the caller asked with stream_options.include_usage, as OpenAI sends
// it; else on the finish chunk, so a client that did not ask never sees a
// chunk with no choices).
func (c *ollamaChunker) chunks(r *ollamaReply) []map[string]any {
	var out []map[string]any
	if r.Model != "" {
		c.model = r.Model // the served name, as the whole-reply path reports it
	}
	if r.Message.Thinking != "" {
		out = append(out, c.delta(map[string]any{"reasoning": r.Message.Thinking}))
	}
	if r.Message.Content != "" {
		out = append(out, c.delta(map[string]any{"content": r.Message.Content}))
	}
	if len(r.Message.ToolCalls) > 0 {
		tc := openAIToolCalls(r.Message.ToolCalls, c.tools, true)
		c.tools += len(r.Message.ToolCalls)
		out = append(out, c.delta(map[string]any{"tool_calls": tc}))
	}
	if r.Done {
		fin := c.chunk([]map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": ollamaFinish(r, c.tools > 0)}})
		u := ollamaUsage(r)
		if u != nil && !c.includeUsage {
			fin["usage"] = u
		}
		out = append(out, fin)
		if u != nil && c.includeUsage {
			uc := c.chunk([]map[string]any{})
			uc["usage"] = u
			out = append(out, uc)
		}
	}
	return out
}

// proxyOllamaChat answers an OpenAI chat request from the ollama at
// targetURL over its native /api/chat. `body` is the request as the proxy
// would have forwarded it (model substituted, keys filtered).
func (s *Server) proxyOllamaChat(w http.ResponseWriter, r *http.Request, body []byte, targetURL, scheme string, firstByte time.Duration) {
	req, err := openAIToOllamaChat(body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad_chat_body", err.Error())
		return
	}
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(targetURL, "/")+"/api/chat", bytes.NewReader(req.body))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "bad_backend_url", err.Error())
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("X-Forwarded-By", "noo-node-agent-inference-proxy")
	// No whole-request timeout: a stream lives while bytes arrive. The
	// transport's ResponseHeaderTimeout (firstByte) still bounds the wait
	// for headers — on /api/chat those come with the first token.
	client := &http.Client{Transport: s.inferenceTransport(scheme, firstByte)}
	resp, err := client.Do(upstream)
	if err != nil {
		slog.Warn("inference proxy could not complete the upstream request",
			"backend", "ollama", "target", targetURL, "error", err,
			"first_byte_timeout_seconds", int(firstByte.Seconds()), "wire", "api/chat")
		jsonError(w, http.StatusBadGateway, "backend_unreachable", err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Ollama's error body is {"error": "..."}: name it in OpenAI's shape.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		jsonError(w, resp.StatusCode, "backend_error", msg)
		return
	}
	id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	if !req.stream {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			jsonError(w, http.StatusBadGateway, "backend_unreachable", err.Error())
			return
		}
		var reply ollamaReply
		if err := json.Unmarshal(raw, &reply); err != nil {
			jsonError(w, http.StatusBadGateway, "backend_error", "ollama answered something other than a chat reply: "+err.Error())
			return
		}
		if reply.Error != "" {
			jsonError(w, http.StatusBadGateway, "backend_error", reply.Error)
			return
		}
		if len(reply.Message.ToolCalls) == 0 && reservedTokensOnly(reply.Message.Content) {
			slog.Warn("inference proxy: the model answered with reserved tokens only", "backend", "ollama", "model", req.model, "chars", len(reply.Message.Content))
			jsonError(w, http.StatusBadGateway, "bad_output", badOutputMessage)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ollamaToOpenAIResponse(&reply, req.model, id, created))
		return
	}
	streamOllamaChat(r.Context(), w, resp.Body, &ollamaChunker{id: id, model: req.model, created: created, includeUsage: req.includeUsage})
}

// A reply made of nothing but the model's reserved vocabulary (gemma's
// `<unusedN>` ids) is not text: a broken sample, never an answer. Returned
// as a backend error so the caller retries or fails loudly instead of
// posting it as a result (noomesh-internal i174, mcmini 2026-10-22).
var reservedTokenRe = regexp.MustCompile(`^(\s*<unused\d+>)+\s*$`)

const badOutputMessage = "the model answered with reserved tokens only (<unusedN>); not an answer — check the backend's KV cache / quantisation settings"

// reservedTokensOnly: non-empty content that is reserved tokens throughout.
func reservedTokensOnly(content string) bool {
	return strings.TrimSpace(content) != "" && reservedTokenRe.MatchString(content)
}

// reservedTokenGuard watches a stream's content: it trips once
// reservedTokenTripAfter reserved tokens have arrived with no real text in
// front of them, or when the stream ends having carried reserved tokens
// and nothing else.
type reservedTokenGuard struct {
	tokens int
	text   bool
}

const reservedTokenTripAfter = 8

var reservedTokenFindRe = regexp.MustCompile(`<unused\d+>`)

// feed records one content delta; true = tripped (stop the stream).
func (g *reservedTokenGuard) feed(content string, done bool) bool {
	if g.text {
		return false
	}
	rest := strings.TrimSpace(reservedTokenFindRe.ReplaceAllString(content, ""))
	if rest != "" {
		g.text = true
		return false
	}
	g.tokens += len(reservedTokenFindRe.FindAllStringIndex(content, -1))
	if g.tokens >= reservedTokenTripAfter {
		return true
	}
	return done && g.tokens > 0
}

// streamOllamaChat relays an /api/chat NDJSON stream as OpenAI SSE, one
// flush per line, so the first token reaches the caller when Ollama emits
// it. The stream ends with `data: [DONE]`.
func streamOllamaChat(ctx context.Context, w http.ResponseWriter, body io.Reader, c *ollamaChunker) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	flush()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	var guard reservedTokenGuard
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var reply ollamaReply
		if err := json.Unmarshal(line, &reply); err != nil {
			slog.Warn("inference proxy: unreadable /api/chat line", "error", err)
			continue
		}
		if reply.Error != "" {
			e, _ := json.Marshal(map[string]any{"error": map[string]any{"message": reply.Error, "type": "node_agent_proxy_error", "code": "backend_error"}})
			fmt.Fprintf(w, "data: %s\n\n", e)
			flush()
			break
		}
		if len(reply.Message.ToolCalls) == 0 && guard.feed(reply.Message.Content, reply.Done) {
			slog.Warn("inference proxy: the model is emitting reserved tokens only; cutting the stream", "backend", "ollama", "model", c.model, "tokens", guard.tokens)
			e, _ := json.Marshal(map[string]any{"error": map[string]any{"message": badOutputMessage, "type": "node_agent_proxy_error", "code": "bad_output", "status": 502}})
			fmt.Fprintf(w, "data: %s\n\n", e)
			flush()
			break
		}
		for _, ch := range c.chunks(&reply) {
			b, err := json.Marshal(ch)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		flush()
		if reply.Done {
			break
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		slog.Warn("inference proxy: /api/chat stream ended early", "error", err)
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	flush()
}
