// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Followup i495 (noomesh-internal), item 1: a docker list or inspect error is
// an error, never "nothing is running" and never a silently dropped backend.

var listInspectPath = regexp.MustCompile(`/containers/([^/]+)/json$`)

// listFakeDaemon is a docker API on a loopback port. listStatus/inspectStatus
// choose the answer; listFailures, when > 0, fails only that many list calls
// before answering normally (a transient timeout).
type listFakeDaemon struct {
	mu            sync.Mutex
	calls         []string
	listBody      string
	listStatus    int
	inspectStatus map[string]int // container id -> status; absent = 200
	inspectBody   map[string]string
}

func (f *listFakeDaemon) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newFakeDaemon(t *testing.T, f *listFakeDaemon) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/containers/json") {
			w.WriteHeader(f.listStatus)
			_, _ = w.Write([]byte(f.listBody))
			return
		}
		if m := listInspectPath.FindStringSubmatch(r.URL.Path); m != nil {
			if st := f.inspectStatus[m[1]]; st != 0 {
				w.WriteHeader(st)
				_, _ = w.Write([]byte(`{"message":"inspect broke"}`))
				return
			}
			_, _ = w.Write([]byte(f.inspectBody[m[1]]))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"unexpected"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const twoBackends = `[
 {"Id":"aaa","Names":["/noo-llamacpp"],"Image":"ghcr.io/x/llama:latest","Labels":{"noo.spec-hash":"h1"}},
 {"Id":"bbb","Names":["/noo-vllm"],"Image":"vllm/vllm-openai:v0.25.0","Labels":{}}
]`

func healthyListDaemon() *listFakeDaemon {
	return &listFakeDaemon{
		listStatus: 200,
		listBody:   twoBackends,
		inspectBody: map[string]string{
			"aaa": `{"Id":"aaa","Config":{"Env":["MODEL_PATH=/models/qwen.gguf"]}}`,
			"bbb": `{"Id":"bbb","Config":{"Env":["MODEL_NAME=google/gemma"]}}`,
		},
	}
}

func TestRunningBackendsHealthy(t *testing.T) {
	c := newFakeDaemon(t, healthyListDaemon())
	got, err := c.RunningBackends(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["llamacpp"] != "qwen.gguf" || got["vllm"] != "google/gemma" {
		t.Fatalf("got %v", got)
	}
}

func TestRunningBackendsListErrorIsAnError(t *testing.T) {
	f := healthyListDaemon()
	f.listStatus = 500
	f.listBody = `{"message":"daemon busy"}`
	c := newFakeDaemon(t, f)
	got, err := c.RunningBackends(t.Context())
	if err == nil {
		t.Fatalf("a list error must be an error, got map %v", got)
	}
	if got != nil {
		t.Fatalf("on error the map must be nil (not an empty 'nothing runs'), got %v", got)
	}
	if !strings.Contains(err.Error(), "listing containers") || !strings.Contains(err.Error(), "daemon busy") {
		t.Fatalf("error does not say what failed: %v", err)
	}
}

func TestRunningBackendsInspectErrorFailsTheWholeCall(t *testing.T) {
	f := healthyListDaemon()
	f.inspectStatus = map[string]int{"bbb": 500}
	c := newFakeDaemon(t, f)
	got, err := c.RunningBackends(t.Context())
	if err == nil {
		t.Fatalf("an inspect error must not silently drop the backend; got %v", got)
	}
	if got != nil {
		t.Fatalf("a partial map must not be returned with an error: %v", got)
	}
	if !strings.Contains(err.Error(), "inspecting container noo-vllm") {
		t.Fatalf("error must name the container: %v", err)
	}
}

func TestBackendLabelsAndFloatingImagesListErrorIsAnError(t *testing.T) {
	f := healthyListDaemon()
	f.listStatus = 500
	f.listBody = `{"message":"daemon busy"}`
	c := newFakeDaemon(t, f)
	if got, err := c.BackendLabels(t.Context(), SpecHashLabel); err == nil || got != nil {
		t.Fatalf("BackendLabels: want (nil, error), got (%v, %v)", got, err)
	}
	if got, err := c.FloatingBackendImages(t.Context()); err == nil || got != nil {
		t.Fatalf("FloatingBackendImages: want (nil, error), got (%v, %v)", got, err)
	}
}

func TestBackendLabelsAndFloatingImagesHealthy(t *testing.T) {
	c := newFakeDaemon(t, healthyListDaemon())
	labels, err := c.BackendLabels(t.Context(), "noo.spec-hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 2 || labels["llamacpp"] != "h1" || labels["vllm"] != "" {
		t.Fatalf("labels = %v", labels)
	}
	floating, err := c.FloatingBackendImages(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// llama:latest floats; the pinned vllm tag does not.
	if len(floating) != 1 || floating["llamacpp"] == "" {
		t.Fatalf("floating = %v", floating)
	}
}

func TestDockerAbsentOnlyOnADarwinHostWithNoAnswer(t *testing.T) {
	down := errors.New("dial unix /var/run/docker.sock: no such file")
	for _, c := range []struct {
		goos string
		ping error
		want bool
	}{
		{"darwin", down, true}, // a Mac with no Docker: nothing runs in it
		{"darwin", nil, false}, // the daemon answers: the list error is real
		{"linux", down, false}, // a Linux outage is an outage, not an absence
		{"linux", nil, false},
	} {
		if got := dockerAbsent(c.goos, c.ping); got != c.want {
			t.Errorf("dockerAbsent(%s, %v) = %v, want %v", c.goos, c.ping, got, c.want)
		}
	}
}
