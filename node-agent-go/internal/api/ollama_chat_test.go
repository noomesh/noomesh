// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return v
}

func TestOpenAIChatBecomesOllamaApiChat(t *testing.T) {
	in := `{"model":"gemma4:12b","stream":true,"stream_options":{"include_usage":true},
	  "messages":[
	    {"role":"system","content":"be brief"},
	    {"role":"user","content":[{"type":"text","text":"look: "},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]},
	    {"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"noo_cluster_status","arguments":"{\"detail\":true}"}}]},
	    {"role":"tool","tool_call_id":"call_1","name":"noo_cluster_status","content":"5 nodes"}],
	  "tools":[{"type":"function","function":{"name":"noo_cluster_status","parameters":{"type":"object"}}}],
	  "reasoning_effort":"none","chat_template_kwargs":{"enable_thinking":false},
	  "max_tokens":64,"temperature":0.2,"stop":"END","options":{"num_ctx":32768},"keep_alive":"-1"}`
	req, err := openAIToOllamaChat([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !req.stream || !req.includeUsage || req.model != "gemma4:12b" {
		t.Fatalf("request facts: %+v", req)
	}
	out := decode(t, req.body)
	if out["model"] != "gemma4:12b" || out["stream"] != true || out["think"] != false {
		t.Fatalf("model/stream/think: %v", out)
	}
	msgs := out["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("messages: %v", msgs)
	}
	user := msgs[1].(map[string]any)
	if user["content"] != "look: " || user["images"].([]any)[0] != "AAAA" {
		t.Fatalf("parts content + image: %v", user)
	}
	// A tool call's arguments is a string on OpenAI's wire and must be an object on Ollama's.
	call := msgs[2].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if call["name"] != "noo_cluster_status" || call["arguments"].(map[string]any)["detail"] != true {
		t.Fatalf("tool call: %v", call)
	}
	tool := msgs[3].(map[string]any)
	if tool["role"] != "tool" || tool["tool_name"] != "noo_cluster_status" || tool["tool_call_id"] != "call_1" {
		t.Fatalf("tool result: %v", tool)
	}
	if len(out["tools"].([]any)) != 1 {
		t.Fatalf("tools: %v", out["tools"])
	}
	opts := out["options"].(map[string]any)
	if opts["num_predict"] != 64.0 || opts["temperature"] != 0.2 || opts["num_ctx"] != 32768.0 || opts["stop"].([]any)[0] != "END" {
		t.Fatalf("options: %v", opts)
	}
	if out["keep_alive"] != "-1" {
		t.Fatalf("keep_alive: %v", out["keep_alive"])
	}
}

func TestOllamaThinkFollowsEveryReasoningField(t *testing.T) {
	cases := []struct {
		body string
		want string // "true", "false" or "unset"
	}{
		{`{"think":false}`, "false"},
		{`{"think":true,"reasoning_effort":"none"}`, "true"},
		{`{"reasoning":{"effort":"none"}}`, "false"},
		{`{"reasoning_effort":"minimal"}`, "false"},
		{`{"reasoning_effort":"high"}`, "true"},
		{`{"chat_template_kwargs":{"enable_thinking":false}}`, "false"},
		{`{"chat_template_kwargs":{"enable_thinking":true}}`, "true"},
		{`{"messages":[]}`, "unset"},
		{`{"tool_choice":"none","tools":[{"type":"function","function":{"name":"x"}}]}`, "unset"},
	}
	for _, c := range cases {
		req, err := openAIToOllamaChat([]byte(c.body))
		if err != nil {
			t.Fatal(err)
		}
		out := decode(t, req.body)
		got := "unset"
		if v, ok := out["think"]; ok {
			got = fmt.Sprint(v)
		}
		if got != c.want {
			t.Errorf("%s: think=%s, want %s", c.body, got, c.want)
		}
		if strings.Contains(c.body, `"tool_choice":"none"`) {
			if _, ok := out["tools"]; ok {
				t.Errorf("tool_choice none must send no tools: %v", out)
			}
		}
	}
}

func TestOllamaWholeReplyBecomesChatCompletion(t *testing.T) {
	raw := `{"model":"gemma4:12b","message":{"role":"assistant","content":"","thinking":"I should list them.",
	  "tool_calls":[{"function":{"name":"noo_cluster_status","arguments":{"detail":true}}}]},
	  "done":true,"done_reason":"stop","prompt_eval_count":20,"eval_count":7}`
	var r ollamaReply
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	out := ollamaToOpenAIResponse(&r, "auto", "chatcmpl-x", 1)
	choice := out["choices"].([]map[string]any)[0]
	msg := choice["message"].(map[string]any)
	if choice["finish_reason"] != "tool_calls" || msg["reasoning"] != "I should list them." || out["model"] != "gemma4:12b" {
		t.Fatalf("choice: %v", out)
	}
	tc := msg["tool_calls"].([]map[string]any)[0]
	if tc["id"] != "call_0" || tc["type"] != "function" {
		t.Fatalf("tool call id/type: %v", tc)
	}
	// Arguments are a JSON string on OpenAI's wire.
	args := tc["function"].(map[string]any)["arguments"].(string)
	if decode(t, []byte(args))["detail"] != true {
		t.Fatalf("arguments: %q", args)
	}
	if _, has := tc["index"]; has {
		t.Fatalf("a whole reply's tool call carries no index: %v", tc)
	}
	u := out["usage"].(map[string]any)
	if u["prompt_tokens"] != int64(20) || u["completion_tokens"] != int64(7) || u["total_tokens"] != int64(27) {
		t.Fatalf("usage: %v", u)
	}
}

// Ollama's NDJSON lines, as gemma4 streams them: thinking first, then
// content, a tool call whole, then the closing object with the counts.
const ollamaLines = `{"model":"gemma4:12b","message":{"role":"assistant","content":"","thinking":"Let me "},"done":false}
{"model":"gemma4:12b","message":{"role":"assistant","content":"","thinking":"think."},"done":false}
{"model":"gemma4:12b","message":{"role":"assistant","content":"ok"},"done":false}
{"model":"gemma4:12b","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"noo_task_done","arguments":{"result":"ok"}}}]},"done":false}
{"model":"gemma4:12b","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":30,"eval_count":9}
`

func sseData(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		out = append(out, decode(t, []byte(strings.TrimPrefix(line, "data: "))))
	}
	return out
}

func TestOllamaStreamBecomesOpenAIChunks(t *testing.T) {
	c := &ollamaChunker{id: "chatcmpl-x", model: "auto", created: 1, includeUsage: true}
	rec := httptest.NewRecorder()
	streamOllamaChat(t.Context(), rec, strings.NewReader(ollamaLines), c)
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type: %s", ct)
	}
	body := rec.Body.String()
	if !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("no [DONE]: %q", body)
	}
	chunks := sseData(t, body)
	// reasoning, reasoning, content, tool call, finish, usage
	if len(chunks) != 6 {
		t.Fatalf("want 6 chunks, got %d: %v", len(chunks), chunks)
	}
	delta := func(i int) map[string]any {
		return chunks[i]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	}
	if delta(0)["reasoning"] != "Let me " || delta(0)["role"] != "assistant" || delta(1)["reasoning"] != "think." {
		t.Fatalf("reasoning deltas: %v %v", delta(0), delta(1))
	}
	if _, again := delta(1)["role"]; again {
		t.Fatalf("role is sent once: %v", delta(1))
	}
	if delta(2)["content"] != "ok" {
		t.Fatalf("content delta: %v", delta(2))
	}
	tc := delta(3)["tool_calls"].([]any)[0].(map[string]any)
	if tc["index"] != 0.0 || tc["id"] != "call_0" || tc["function"].(map[string]any)["name"] != "noo_task_done" {
		t.Fatalf("tool call delta: %v", tc)
	}
	if decode(t, []byte(tc["function"].(map[string]any)["arguments"].(string)))["result"] != "ok" {
		t.Fatalf("tool call arguments: %v", tc)
	}
	fin := chunks[4]["choices"].([]any)[0].(map[string]any)
	if fin["finish_reason"] != "tool_calls" {
		t.Fatalf("finish: %v", fin)
	}
	if _, onFinish := chunks[4]["usage"]; onFinish {
		t.Fatalf("with include_usage the usage is its own chunk: %v", chunks[4])
	}
	if len(chunks[5]["choices"].([]any)) != 0 || chunks[5]["usage"].(map[string]any)["total_tokens"] != 39.0 {
		t.Fatalf("usage chunk: %v", chunks[5])
	}
	for _, ch := range chunks {
		if ch["model"] != "gemma4:12b" || ch["object"] != "chat.completion.chunk" {
			t.Fatalf("chunk envelope: %v", ch)
		}
	}
}

func TestOllamaStreamUsageRidesTheFinishChunkWhenNotAskedFor(t *testing.T) {
	c := &ollamaChunker{id: "chatcmpl-x", model: "auto", created: 1}
	rec := httptest.NewRecorder()
	streamOllamaChat(t.Context(), rec, strings.NewReader(ollamaLines), c)
	chunks := sseData(t, rec.Body.String())
	if len(chunks) != 5 {
		t.Fatalf("want 5 chunks, got %d", len(chunks))
	}
	last := chunks[4]
	if last["choices"].([]any)[0].(map[string]any)["finish_reason"] != "tool_calls" || last["usage"].(map[string]any)["prompt_tokens"] != 30.0 {
		t.Fatalf("finish chunk carries the usage: %v", last)
	}
}

// The point of the whole file: the first chunk reaches the caller while
// Ollama is still generating, tools or not.
func TestOllamaChatStreamsTheFirstTokenBeforeTheAnswerIsComplete(t *testing.T) {
	release := make(chan struct{})
	var seenBody []byte
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.Error(w, "wrong path "+r.URL.Path, 404)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		seenBody, _ = json.Marshal(in)
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		fmt.Fprintln(w, `{"model":"gemma4:12b","message":{"role":"assistant","content":"first"},"done":false}`)
		f.Flush()
		<-release // the rest only once the test has seen the first chunk
		fmt.Fprintln(w, `{"model":"gemma4:12b","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"noop","arguments":{}}}]},"done":false}`)
		fmt.Fprintln(w, `{"model":"gemma4:12b","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":5,"eval_count":2}`)
		f.Flush()
	}))
	defer mock.Close()

	s := &Server{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`{"model":"gemma4:12b","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"noop","parameters":{"type":"object"}}}]}`)
		s.proxyOllamaChat(w, r, body, mock.URL, "http", 5*time.Second)
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d, type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	rd := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				first <- "EOF: " + err.Error()
				return
			}
			if strings.HasPrefix(line, "data: ") {
				first <- line
				return
			}
		}
	}()
	select {
	case line := <-first:
		if !strings.Contains(line, `"content":"first"`) {
			t.Fatalf("first chunk: %s", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no chunk arrived while the upstream was still generating: the stream is buffered")
	}
	close(release)
	rest, _ := readAllLines(rd)
	if !strings.Contains(rest, `"finish_reason":"tool_calls"`) || !strings.Contains(rest, "data: [DONE]") {
		t.Fatalf("tail: %s", rest)
	}
	if !strings.Contains(string(seenBody), `"tools":[`) || !strings.Contains(string(seenBody), `"stream":true`) {
		t.Fatalf("upstream body: %s", seenBody)
	}
}

func readAllLines(rd *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := rd.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String(), err
		}
	}
}

func TestOllamaChatWholeReplyAndErrorsKeepOpenAIShape(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["model"] == "missing" {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"model 'missing' not found"}`)
			return
		}
		fmt.Fprint(w, `{"model":"gemma4:12b","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":"stop","prompt_eval_count":3,"eval_count":1}`)
	}))
	defer mock.Close()
	s := &Server{}
	call := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		s.proxyOllamaChat(rec, req, []byte(body), mock.URL, "http", 5*time.Second)
		return rec
	}
	rec := call(`{"model":"gemma4:12b","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	out := decode(t, rec.Body.Bytes())
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if out["object"] != "chat.completion" || msg["content"] != "ok" || out["usage"].(map[string]any)["total_tokens"] != 4.0 {
		t.Fatalf("completion: %v", out)
	}
	rec = call(`{"model":"missing","messages":[]}`)
	if rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
	e := decode(t, rec.Body.Bytes())["error"].(map[string]any)
	if e["message"] != "model 'missing' not found" || e["code"] != "backend_error" {
		t.Fatalf("error shape: %v", e)
	}
	rec = call(`not json`)
	if rec.Code != 400 {
		t.Fatalf("bad body status %d", rec.Code)
	}
}

// noomesh-internal i174: a reply made of reserved tokens only is a backend
// error, never an answer; a stream of them is cut with an error event.
func TestReservedTokensOnlyIsABackendErrorNotAnAnswer(t *testing.T) {
	for s, want := range map[string]bool{
		"<unused49><unused49><unused49>": true,
		" <unused0> \n<unused12>":        true,
		"ok":                             false,
		"":                               false,
		"<unused49> and a word":          false,
		"the <unused3> token":            false,
	} {
		if got := reservedTokensOnly(s); got != want {
			t.Fatalf("reservedTokensOnly(%q) = %v", s, got)
		}
	}
	var g reservedTokenGuard
	for i := 0; i < reservedTokenTripAfter-1; i++ {
		if g.feed("<unused49>", false) {
			t.Fatalf("tripped at %d tokens", i+1)
		}
	}
	if !g.feed("<unused49>", false) {
		t.Fatal("trips at the limit")
	}
	g = reservedTokenGuard{}
	if g.feed("<unused49><unused49>", false) || !g.feed("", true) {
		t.Fatal("a stream that ends with only reserved tokens trips at done")
	}
	g = reservedTokenGuard{}
	if g.feed("Sure", false) || g.feed("<unused49>", false) || g.feed("<unused49><unused49><unused49><unused49><unused49><unused49><unused49><unused49>", true) {
		t.Fatal("real text first: never tripped")
	}
}

func TestProxyRefusesAReservedTokenReplyAndCutsAReservedTokenStream(t *testing.T) {
	garbage := strings.Repeat("<unused49>", 20)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream bool `json:"stream"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		if !req.Stream {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"model":"m","message":{"role":"assistant","content":%q},"done":true,"done_reason":"stop"}`, garbage)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for i := 0; i < 20; i++ {
			fmt.Fprint(w, `{"model":"m","message":{"role":"assistant","content":"<unused49>"},"done":false}`+"\n")
		}
		fmt.Fprint(w, `{"model":"m","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop"}`+"\n")
	}))
	defer mock.Close()
	s := &Server{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.proxyOllamaChat(w, r, body, mock.URL, "http", time.Second)
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 502 || !strings.Contains(string(body), `"bad_output"`) || strings.Contains(string(body), "<unused49><unused49>") {
		t.Fatalf("whole reply: %d %s", resp.StatusCode, body)
	}

	resp, err = http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(body)
	if resp.StatusCode != 200 || !strings.Contains(out, `"bad_output"`) || !strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]") {
		t.Fatalf("stream: %d %s", resp.StatusCode, out)
	}
	if n := strings.Count(out, "<unused49>"); n >= 20 {
		t.Fatalf("the stream was cut, not relayed whole: %d tokens reached the caller", n)
	}
}
