// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

// A proxied handler the tests drive: admission, then a reverse proxy to
// `upstream`, as handleInferenceProxy does after it picked the backend.
func admittedProxy(t *testing.T, upstream string, stream bool, bound, keepAlive, earlyAfter time.Duration) http.Handler {
	t.Helper()
	target, _ := url.Parse(upstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// As handleInferenceProxy: the body is read before admission and
		// restored after (net/http closes the original once the response
		// starts, which a queued stream's headers do).
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		adm := admitWith(w, r, "ollama", stream, bound, keepAlive, earlyAfter)
		if adm == nil {
			return
		}
		defer adm.done()
		p := httputil.NewSingleHostReverseProxy(target)
		p.FlushInterval = -1
		p.ServeHTTP(adm.w, r)
	})
}

// readUntil reads SSE lines until one contains `want` (or the body ends).
func readUntil(t *testing.T, body io.Reader, want string, within time.Duration) []string {
	t.Helper()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var seen []string
	deadline := time.After(within)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				return seen
			}
			seen = append(seen, l)
			if strings.Contains(l, want) {
				return seen
			}
		case <-deadline:
			t.Fatalf("no line with %q within %s; saw %q", want, within, seen)
		}
	}
}

// waitReleased: the slot is released by the handler's deferred done() AFTER
// the response is written, so a client that has read the whole body can
// observe in_flight 1 for a moment; the contract is "released once the
// handler returns", not "before the last byte". Wait for it, briefly.
func waitReleased(t *testing.T, backend string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e := occupancy.Report()[backend]
		if e.InFlight == 0 && e.Queued == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not released after the response: %+v", e)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestAFullBackendQueuesAStreamWithKeepAlivesThenServesIt(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 1})

	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	srv := httptest.NewServer(admittedProxy(t, upstream.URL, true, 5*time.Second, 30*time.Millisecond, 0))
	defer srv.Close()

	// First request holds the only slot.
	hold, _ := occupancy.Admit(context.Background(), "ollama")
	go func() {
		<-release
		hold()
	}()

	start := time.Now()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("a queued stream gets its headers at once: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Noo-In-Flight") != "1" || resp.Header.Get("X-Noo-Slots") != "1" {
		t.Fatalf("occupancy headers: %v", resp.Header)
	}
	seen := readUntil(t, resp.Body, ": keep-alive", 2*time.Second)
	if seen[0] != ": queued ahead=0" {
		t.Fatalf("first line names the queue: %q", seen)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("keep-alives must flow while the slot is held")
	}
	close(release)
	seen = readUntil(t, resp.Body, "[DONE]", 2*time.Second)
	joined := strings.Join(seen, "\n")
	if !strings.Contains(joined, `"content":"hi"`) {
		t.Fatalf("after the slot frees the answer flows through the same stream: %q", seen)
	}
}

func TestAFullBackendRejectsWhenTheCallerAsks(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 1})
	hold, _ := occupancy.Admit(context.Background(), "ollama")
	defer hold()

	srv := httptest.NewServer(admittedProxy(t, "http://127.0.0.1:1", false, time.Second, time.Second, 0))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/embeddings", strings.NewReader(`{}`))
	req.Header.Set("X-Noo-Busy", "reject")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" || resp.Header.Get("X-Noo-Queue") != "0" ||
		resp.Header.Get("X-Noo-In-Flight") != "1" || resp.Header.Get("X-Noo-Slots") != "1" {
		t.Fatalf("busy headers: %v", resp.Header)
	}
	if !strings.Contains(string(body), `"backend_busy"`) || strings.Contains(string(body), "wedged") {
		t.Fatalf("busy is named busy: %s", body)
	}
	if e := occupancy.Report()["ollama"]; e.InFlight != 1 || e.Queued != 0 {
		t.Fatalf("a rejected request never counted: %+v", e)
	}
}

func TestAWaitThatOutlastsTheBoundIs503(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 1})
	hold, _ := occupancy.Admit(context.Background(), "ollama")
	defer hold()

	srv := httptest.NewServer(admittedProxy(t, "http://127.0.0.1:1", false, 50*time.Millisecond, time.Second, 0))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/embeddings", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "stayed taken") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if e := occupancy.Report()["ollama"]; e.Queued != 0 {
		t.Fatalf("the waiter left the queue: %+v", e)
	}
}

func TestASilentPrefillGetsHeadersAndKeepAlivesBeforeTheFirstToken(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)

	firstToken := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-firstToken // the engine says nothing, not even headers, while it prefills
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"tok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	srv := httptest.NewServer(admittedProxy(t, upstream.URL, true, 5*time.Second, 30*time.Millisecond, 20*time.Millisecond))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("early headers: %d", resp.StatusCode)
	}
	readUntil(t, resp.Body, ": keep-alive", 2*time.Second)
	close(firstToken)
	seen := readUntil(t, resp.Body, "[DONE]", 2*time.Second)
	if !strings.Contains(strings.Join(seen, "\n"), `"content":"tok"`) {
		t.Fatalf("the engine's bytes follow the keep-alives: %q", seen)
	}
}

func TestAQuickEngineRefusalKeepsItsOwnStatus(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":{"message":"model not found"}}`)
	}))
	defer upstream.Close()
	srv := httptest.NewServer(admittedProxy(t, upstream.URL, true, 5*time.Second, time.Second, time.Second))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("an engine that answers before earlyHeadersAfter keeps its status: %d", resp.StatusCode)
	}
	waitReleased(t, "ollama")
}

func TestARefusalAfterEarlyHeadersIsAnSSEErrorEvent(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		fmt.Fprint(w, `{"error":{"message":"engine fell over"}}`)
	}))
	defer upstream.Close()
	srv := httptest.NewServer(admittedProxy(t, upstream.URL, true, 5*time.Second, time.Second, 10*time.Millisecond))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if resp.StatusCode != 200 || !strings.Contains(text, `"engine fell over"`) || !strings.Contains(text, `"status":502`) || !strings.HasSuffix(strings.TrimSpace(text), "data: [DONE]") {
		t.Fatalf("%d %q", resp.StatusCode, text)
	}
}

func TestANonStreamingRequestPassesThroughUntouched(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer upstream.Close()
	srv := httptest.NewServer(admittedProxy(t, upstream.URL, false, 5*time.Second, 10*time.Millisecond, 10*time.Millisecond))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/embeddings", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != `{"data":[]}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("no early headers, no comments on a JSON reply: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp.Header.Get("X-Noo-Slots") != "0" {
		t.Fatalf("slots unknown is reported as 0: %v", resp.Header)
	}
}

func TestOllamaChatGoesThroughAdmissionToo(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 1})
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprint(w, "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"ok\"},\"done\":true,\"done_reason\":\"stop\"}\n")
	}))
	defer mock.Close()
	s := &Server{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		adm := s.admit(w, r, "ollama", body, time.Second)
		if adm == nil {
			return
		}
		defer adm.done()
		s.proxyOllamaChat(adm.w, r, body, mock.URL, "http", time.Second)
	}))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"content":"ok"`) || resp.Header.Get("X-Noo-In-Flight") != "1" {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
	waitReleased(t, "ollama")
}

// A GPU hold's drain (internal/gpuyield, mode drain) closes admission: a
// new request is refused at once with 503 backend_draining and
// `X-Noo-Busy: draining`, whether or not it asked to be rejected; nothing
// is queued, so in_flight only falls.
func TestADrainingBackendRefusesNewRequestsAtOnce(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	hold, _ := occupancy.Admit(context.Background(), "ollama")
	defer hold()
	occupancy.SetDraining([]string{"ollama"}, true)

	srv := httptest.NewServer(admittedProxy(t, "http://127.0.0.1:1", true, time.Second, time.Second, 0))
	defer srv.Close()
	started := time.Now()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"backend_draining"`) {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Noo-Busy") != "draining" || resp.Header.Get("Retry-After") == "" || resp.Header.Get("X-Noo-In-Flight") != "1" {
		t.Fatalf("draining headers: %v", resp.Header)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("refused at once, not after the bound")
	}
	if e := occupancy.Report()["ollama"]; e.InFlight != 1 || e.Queued != 0 {
		t.Fatalf("a refused request never counted: %+v", e)
	}
	occupancy.SetDraining([]string{"ollama"}, false)
	resp2, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("reopened: the request reaches the backend (and fails on the dead upstream, not on admission)")
	}
}
