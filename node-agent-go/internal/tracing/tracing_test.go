// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tracing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestAWellFormedTraceparentIsContinuedAndAnythingElseMakesNoSpan(t *testing.T) {
	s := Start("agent inference", tp)
	if s == nil || s.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || s.ParentID != "00f067aa0ba902b7" {
		t.Fatalf("not continued: %+v", s)
	}
	if s.SpanID == s.ParentID || len(s.SpanID) != 16 {
		t.Fatalf("the node's span is its own: %q", s.SpanID)
	}
	tid, pid, ok := ParseTraceparent(s.Traceparent())
	if !ok || tid != s.TraceID || pid != s.SpanID {
		t.Fatalf("the next hop continues from this span: %q", s.Traceparent())
	}
	for _, bad := range []string{"", "garbage", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"} {
		if Start("x", bad) != nil {
			t.Errorf("%q started a span: a node never starts a trace", bad)
		}
	}
}

func TestANilSpanIsSafeEverywhere(t *testing.T) {
	var s *Span
	s.SetStr("k", "v")
	s.SetInt("k", 1)
	s.End(200)
	if s.Traceparent() != "" {
		t.Fatal("a nil span has no traceparent")
	}
}

func TestTheBodyIsTheGatewaysOtlpShape(t *testing.T) {
	s := Start("agent inference", tp)
	s.SetStr("noo.backend", "vllm")
	s.SetInt("n", 3)
	s.EndTime = s.StartTime.Add(time.Millisecond)
	s.Error = true
	raw, err := Body([]*Span{s})
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []map[string]any `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sp := v.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if sp["parentSpanId"] != "00f067aa0ba902b7" || sp["traceId"] != s.TraceID {
		t.Fatalf("ids: %v", sp)
	}
	if _, isStr := sp["startTimeUnixNano"].(string); !isStr {
		t.Fatalf("OTLP JSON times are strings: %v", sp["startTimeUnixNano"])
	}
	if sp["status"].(map[string]any)["code"] != float64(2) {
		t.Fatalf("an error span: %v", sp["status"])
	}
	if !strings.Contains(string(raw), `{"key":"n","value":{"intValue":"3"}}`) {
		t.Fatalf("an int attribute is a string intValue: %s", raw)
	}
}

func TestTheExporterRefusesPlaintext(t *testing.T) {
	if _, err := NewExporter("http://ctl:8080", "host3", http.DefaultClient, nil); err == nil || !strings.Contains(err.Error(), "TLS only") {
		t.Fatalf("a plaintext controller URL must be refused: %v", err)
	}
}

func TestSpansGoToTheNodeRouteWithTheCredentialAndA429IsWaitedOut(t *testing.T) {
	var got atomic.Value
	var status atomic.Int32
	status.Store(204)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store([]string{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(b)})
		if status.Load() == 429 {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	e, err := NewExporter(srv.URL, "host3", srv.Client(), func(r *http.Request) error {
		r.Header.Set("Authorization", "Bearer node-token")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := Start("agent inference", tp)
	s.EndTime = time.Now()
	if wait := e.Push(context.Background(), []*Span{s}); wait != 0 {
		t.Fatalf("a 204 needs no wait: %v", wait)
	}
	req := got.Load().([]string)
	if req[0] != "POST" || req[1] != "/api/cluster/nodes/host3/traces" || req[2] != "Bearer node-token" || !strings.Contains(req[3], s.SpanID) {
		t.Fatalf("request: %v", req)
	}
	status.Store(429)
	if wait := e.Push(context.Background(), []*Span{s}); wait != 7*time.Second {
		t.Fatalf("Retry-After is honoured: %v", wait)
	}
	if st := e.State(); st["sent"] != int64(1) || st["dropped"] != int64(1) {
		t.Fatalf("counts: %v", st)
	}
}

func TestAFullQueueDropsAndCounts(t *testing.T) {
	e, err := NewExporter("https://ctl:8080", "host3", http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := Start("x", tp)
	for i := 0; i < queueCap+3; i++ {
		e.Record(s)
	}
	if e.dropped.Load() != 3 {
		t.Fatalf("dropped %d, want 3", e.dropped.Load())
	}
}

func TestEndHandsTheSpanToTheDefaultExporterOnce(t *testing.T) {
	e, err := NewExporter("https://ctl:8080", "host3", http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	SetDefault(e)
	defer SetDefault(nil)
	s := Start("x", tp)
	s.End(502)
	s.End(200)
	if len(e.ch) != 1 {
		t.Fatalf("queued %d, want exactly 1", len(e.ch))
	}
	if !s.Error {
		t.Fatal("a 5xx is an error span")
	}
}
