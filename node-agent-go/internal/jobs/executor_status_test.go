package jobs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// truncated answers 200 with a Content-Length larger than what it writes,
// then drops the connection, so the client's body read fails.
func truncated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "100")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`{"choices":[`))
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	_ = buf.Flush()
	_ = conn.Close()
}

func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestPostInferenceOutcomes(t *testing.T) {
	cases := []struct {
		name       string
		handler    http.HandlerFunc
		wantErr    []string // substrings; empty = no error
		wantResult any
		wantEvent  string
	}{
		{"valid 200", reply(200, `{"ok":true}`), nil, map[string]any{"ok": true}, "complete"},
		{"truncated body", truncated, []string{"HTTP 200", "reading response body"}, nil, "failed"},
		{"non-JSON 200", reply(200, "<html>proxy says hi</html>"), []string{"HTTP 200", "not JSON", "<html>proxy says hi</html>"}, nil, "failed"},
		{"500", reply(500, `{"error":"boom"}`), []string{"HTTP 500", `{"error":"boom"}`}, nil, "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("{}"))
			got, err := postInference(srv.Client(), req, "vllm")
			checkOutcome(t, got, err, tc.wantErr, tc.wantResult, tc.wantEvent)
		})
	}
}

func TestPostInferenceNonJSONSnippetIsBounded(t *testing.T) {
	srv := httptest.NewServer(reply(200, strings.Repeat("x", 1000)))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	_, err := postInference(srv.Client(), req, "vllm")
	if err == nil || strings.Count(err.Error(), "x") < 200 || strings.Count(err.Error(), "x") > 210 {
		t.Fatalf("want an error carrying ~200 body bytes, got %v", err)
	}
}

func checkOutcome(t *testing.T, got any, err error, wantErr []string, wantResult any, wantEvent string) {
	t.Helper()
	if len(wantErr) == 0 && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range wantErr {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("error %v does not contain %q", err, s)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(wantResult) {
		t.Fatalf("result = %v, want %v", got, wantResult)
	}
	if ev := jobEventKind(err); ev != wantEvent {
		t.Fatalf("job recorded as %q, want %q", ev, wantEvent)
	}
}

func controllerExec(url string, h http.HandlerFunc) (*Executor, func()) {
	srv := httptest.NewServer(h)
	e := NewExecutor(&messaging.Client{}, nil, srv.Client(), "http", srv.URL, "node-1")
	return e, srv.Close
}

func TestBackgroundJobsByControllerStatus(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantErr    []string
		wantStatus string // result["status"]
		wantEvent  string
	}{
		{"200", 200, nil, "completed", "complete"},
		{"404 endpoint absent is skipped", 404, nil, "skipped", "complete"},
		{"401", 401, []string{"HTTP 401", "denied"}, "", "failed"},
		{"500", 500, []string{"HTTP 500", "denied"}, "", "failed"},
	}
	for _, tc := range cases {
		h := reply(tc.status, "denied")
		t.Run("graph/"+tc.name, func(t *testing.T) {
			e, done := controllerExec("", h)
			defer done()
			got, err := e.executeBackgroundGraph(context.Background(), map[string]any{"scope": "extract"})
			checkStatus(t, got, err, tc.wantErr, tc.wantStatus, tc.wantEvent)
		})
		t.Run("cache/"+tc.name, func(t *testing.T) {
			e, done := controllerExec("", h)
			defer done()
			got, err := e.executeBackgroundCache(context.Background(), map[string]any{})
			checkStatus(t, got, err, tc.wantErr, tc.wantStatus, tc.wantEvent)
		})
	}
}

func checkStatus(t *testing.T, got any, err error, wantErr []string, wantStatus, wantEvent string) {
	t.Helper()
	if len(wantErr) == 0 && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range wantErr {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("error %v does not contain %q", err, s)
		}
	}
	status := ""
	switch m := got.(type) {
	case map[string]string:
		status = m["status"]
	case map[string]any:
		status, _ = m["status"].(string)
	}
	if status != wantStatus {
		t.Fatalf("result status = %q (%v), want %q", status, got, wantStatus)
	}
	if ev := jobEventKind(err); ev != wantEvent {
		t.Fatalf("job recorded as %q, want %q", ev, wantEvent)
	}
}
