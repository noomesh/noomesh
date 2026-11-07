// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// Followup i495 (noomesh-internal), item 1: a docker list error is "could not
// ask", not "nothing is running". The tick is skipped: no start, recreate or
// stop reaches the daemon.

// listDaemon is a docker API on loopback that records every call and fails
// the list calls whose 1-based ordinal is in failList (a transient error).
type listDaemon struct {
	mu       sync.Mutex
	calls    []string
	lists    int
	failList map[int]bool
}

func (d *listDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

// writes are the calls that change the node: anything but a GET.
func (d *listDaemon) writes() []string {
	var w []string
	for _, c := range d.seen() {
		if !strings.HasPrefix(c, "GET ") {
			w = append(w, c)
		}
	}
	return w
}

func tickFixture(t *testing.T, d *listDaemon) *Reconciler {
	t.Helper()
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		d.mu.Lock()
		d.calls = append(d.calls, r.Method+" "+r.URL.Path)
		isList := strings.HasSuffix(r.URL.Path, "/containers/json")
		if isList {
			d.lists++
		}
		fail := isList && d.failList[d.lists]
		d.mu.Unlock()
		if fail {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"message":"context deadline exceeded"}`))
			return
		}
		if isList {
			_, _ = w.Write([]byte("[]")) // nothing running
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	t.Cleanup(daemon.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(daemon.URL, "http://"))
	dc, err := dockerpkg.NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}

	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"placements":[{"backend":"vllm","model":"google/gemma","image":"vllm/vllm-openai:v0.25.0","port":8000,"desired_state":"running"}]}`))
	}))
	t.Cleanup(ctl.Close)
	// The image manifest probe reads the controller URL from CONTROLLER_URL
	// (ctrlenv), not from cfg; point it at the same fake so no test here
	// needs the network or DNS (the default is https://gateway:8080).
	t.Setenv("CONTROLLER_URL", ctl.URL)

	r := New(&config.Config{ControllerURL: ctl.URL, NodeID: "n1", StateDir: t.TempDir()}, dc, ctl.Client(), nil)
	return r
}

// The three reads, in tick order: RunningBackends, BackendLabels,
// FloatingBackendImages. A failure in any one must skip the pass.
func TestTickSkippedWhenDockerListFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail int // which list call fails
	}{
		{"RunningBackends", 1},
		{"BackendLabels", 2},
		{"FloatingBackendImages", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &listDaemon{failList: map[int]bool{tc.fail: true}}
			r := tickFixture(t, d)
			r.Once(t.Context())

			if w := d.writes(); len(w) != 0 {
				t.Fatalf("a failed docker list must skip the tick, but the daemon was asked to change things: %v", w)
			}
			// It got as far as the failing read and not past it.
			var lists int
			for _, c := range d.seen() {
				if strings.HasSuffix(c, "/containers/json") {
					lists++
				}
			}
			if lists != tc.fail {
				t.Fatalf("expected the pass to stop at list call %d, saw %d list calls: %v", tc.fail, lists, d.seen())
			}
		})
	}
}

// The control: with the lists healthy and nothing running, the same desired
// state does reach the daemon (an image check or a create). Without it the
// test above could pass because nothing ever acts.
func TestTickActsWhenDockerListsAreHealthy(t *testing.T) {
	d := &listDaemon{}
	r := tickFixture(t, d)
	r.Once(t.Context())
	var acted bool
	for _, c := range d.seen() {
		if !strings.HasSuffix(c, "/containers/json") {
			acted = true
		}
	}
	if !acted {
		t.Fatalf("healthy lists + a placement with nothing running should reach the daemon beyond listing; saw %v", d.seen())
	}
}
