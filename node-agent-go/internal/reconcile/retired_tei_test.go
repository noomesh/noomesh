// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// The TEI engine is gone from core (0.6.30, i1182a). What an upgraded node
// does about it:
//   - an `embedding` placement left in desired state is REFUSED with the
//     replacement (backend_start), never silently skipped, and starts nothing;
//   - the containers the old agent made for it (noo-tei(-gpu), their
//     noo-stunnel-tei(-gpu) doors, a TEI-image noo-reranker) are stopped and
//     removed, by exact name, only when this agent's label is on them.

func embeddingRefusal() string {
	for _, r := range refusals.List() {
		if r.Scope == "backend_start" && r.Target == "embedding" {
			return r.Reason
		}
	}
	return ""
}

// An `embedding` placement in desired state: refused with the replacement
// text, and no start is attempted.
func TestAnEmbeddingPlacementIsRefusedWithTheReplacementAndStartsNothing(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	starts := 0
	r := &Reconciler{
		cfg:            &config.Config{NodeID: "node-a"},
		driftRecreated: map[string]string{},
		startBackendFn: func(context.Context, string, string, int, dockerpkg.StartOverrides) error {
			starts++
			return nil
		},
	}
	tk := &tick{
		desired: &desiredConfig{}, running: map[string]string{}, native: map[string]string{},
		specLabels: map[string]string{}, floating: map[string]string{},
	}
	p := placement{Backend: "embedding", Model: "BAAI/bge-base-en-v1.5", Role: "embed", DesiredState: "running"}
	r.convergeContainer(context.Background(), tk, p)
	if starts != 0 {
		t.Fatalf("%d start(s) attempted for the removed TEI backend", starts)
	}
	got := embeddingRefusal()
	for _, want := range []string{"TEI embedding engine was removed in 0.6.30", "nothing was started",
		"noo cluster place node-a ollama <model> --role embed"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal %q lacks %q", got, want)
		}
	}
	// Unplaced (no running embedding placement any more): the refusal clears.
	clearUnplacedRetiredRefusals(nil)
	if embeddingRefusal() != "" {
		t.Error("the refusal outlived its placement")
	}
}

// The reranker is always llama.cpp: a .gguf reranker placement starts the
// llama.cpp spec, and no RERANK_ENGINE reaches the start (it is read nowhere).
func TestAGGUFRerankerStartsWithNoEngineSwitch(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	t.Setenv("MODELS_DIR", t.TempDir())
	t.Setenv("RERANK_ENGINE", "tei") // retired: must change nothing
	var gotBackend, gotModel string
	var gotEnv map[string]string
	r := &Reconciler{
		cfg:            &config.Config{NodeID: "node-a"},
		driftRecreated: map[string]string{},
		ggufMissing:    map[string]string{},
		ggufExists:     func(context.Context, string, string) (bool, error) { return true, nil },
		startBackendFn: func(_ context.Context, backend, model string, _ int, o dockerpkg.StartOverrides) error {
			gotBackend, gotModel, gotEnv = backend, model, o.ExtraEnv
			return nil
		},
	}
	tk := &tick{
		desired: &desiredConfig{}, running: map[string]string{}, native: map[string]string{},
		specLabels: map[string]string{}, floating: map[string]string{},
	}
	r.convergeContainer(context.Background(), tk, placement{Backend: "reranker", Model: "bge-reranker-v2-m3-Q8_0.gguf", DesiredState: "running"})
	if gotBackend != "reranker" || gotModel != "bge-reranker-v2-m3-Q8_0.gguf" {
		t.Fatalf("start = %q %q, want the reranker on its gguf", gotBackend, gotModel)
	}
	if _, ok := gotEnv["RERANK_ENGINE"]; ok {
		t.Errorf("RERANK_ENGINE reached the start env: %v", gotEnv)
	}
	if !dockerpkg.ExpectsGGUFModel("reranker") {
		t.Error("the reranker must expect a gguf whatever RERANK_ENGINE says")
	}
}

// A reranker placed with a HuggingFace repo id (what ran on TEI) is refused
// with the GGUF replacement in the refusal `noo cluster show` prints, not only
// in the log, and nothing is started.
func TestARerankerWithARepoIDIsRefusedWithTheGGUFReplacement(t *testing.T) {
	r, d := teiHostFixture(t, `[]`, `{"backend":"reranker","model":"BAAI/bge-reranker-base","desired_state":"running"}`)
	r.Once(t.Context())
	got := ""
	for _, ref := range refusals.List() {
		if ref.Scope == "backend_start" && ref.Target == "reranker" {
			got = ref.Reason
		}
	}
	for _, want := range []string{"TEI reranker was removed in 0.6.30", "noo cluster place node-a reranker <file>.gguf", "BAAI/bge-reranker-base"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal %q lacks %q", got, want)
		}
	}
	if c := d.creates(); len(c) != 0 {
		t.Fatalf("a container was created: %v", c)
	}
}

// fakeTEIHost is a docker daemon that lists the given containers and records
// every call, answering stop and remove with 204.
type fakeTEIHost struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeTEIHost) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeTEIHost) removed() string {
	var ids []string
	for _, c := range f.seen() {
		if rest, ok := strings.CutPrefix(c, "DELETE "); ok {
			ids = append(ids, rest[strings.LastIndex(rest, "/")+1:])
		}
	}
	return strings.Join(ids, ",")
}

func (f *fakeTEIHost) creates() []string {
	var out []string
	for _, c := range f.seen() {
		if strings.HasPrefix(c, "POST ") && strings.Contains(c, "/containers/create") {
			out = append(out, c)
		}
	}
	return out
}

// teiHostFixture runs a whole reconcile pass (New + Once) against a daemon
// that lists `containers` (a docker list body) and a controller whose desired
// state places an embedding backend (or the given placements).
func teiHostFixture(t *testing.T, containers string, placements ...string) (*Reconciler, *fakeTEIHost) {
	t.Helper()
	f := &fakeTEIHost{}
	desired := placements
	if len(desired) == 0 {
		desired = []string{`{"backend":"embedding","model":"BAAI/bge-base-en-v1.5","role":"embed","desired_state":"running"}`}
	}
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = w.Write([]byte(containers))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/stop"),
			r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/containers/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	t.Cleanup(daemon.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(daemon.URL, "http://"))
	dc, err := dockerpkg.NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"placements":[` + strings.Join(desired, ",") + `]}`))
	}))
	t.Cleanup(ctl.Close)
	t.Setenv("CONTROLLER_URL", ctl.URL)
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	r := New(&config.Config{ControllerURL: ctl.URL, NodeID: "node-a", StateDir: t.TempDir()}, dc, ctl.Client(), nil)
	return r, f
}

const agentLabelJSON = `"noo.managed-by":"node-agent-go"`

// The upgrade: a node whose old agent ran noo-tei behind noo-stunnel-tei, and
// whose desired state still places `embedding`. One pass stops and removes
// both (they are this agent's), refuses the placement with the replacement,
// and creates nothing.
func TestUpgradeStopsAndRemovesTheTEIContainerAndItsDoor(t *testing.T) {
	r, d := teiHostFixture(t, `[
 {"Id":"tei1","Names":["/noo-tei"],"Image":"ghcr.io/huggingface/text-embeddings-inference:cpu-1.9.4","Labels":{`+agentLabelJSON+`}},
 {"Id":"door1","Names":["/noo-stunnel-tei"],"Image":"x/stunnel:1","Labels":{`+agentLabelJSON+`}},
 {"Id":"gpu1","Names":["/noo-tei-gpu"],"Image":"ghcr.io/huggingface/text-embeddings-inference:1.6","Labels":{`+agentLabelJSON+`}}
]`)
	r.Once(t.Context())
	if got := d.removed(); got != "tei1,door1,gpu1" {
		t.Fatalf("removed %q, want the TEI containers and their door (calls %v)", got, d.seen())
	}
	if c := d.creates(); len(c) != 0 {
		t.Fatalf("a container was created for the removed engine: %v", c)
	}
	if got := embeddingRefusal(); !strings.Contains(got, "noo cluster place node-a ollama <model> --role embed") {
		t.Fatalf("no replacement refusal for the placement: %q", got)
	}
	if !r.retiredTEIDone {
		t.Error("the leftover check did not record that it ran clean")
	}
	// A second pass does not list for leftovers again.
	before := len(d.seen())
	r.Once(t.Context())
	for _, c := range d.seen()[before:] {
		if strings.HasPrefix(c, "DELETE ") {
			t.Fatalf("a second pass removed again: %s", c)
		}
	}
}

// A container that merely carries the name but not this agent's label is NOT
// removed: it is compose-run, or someone else's.
func TestUpgradeLeavesAForeignNooTEIAlone(t *testing.T) {
	r, d := teiHostFixture(t, `[
 {"Id":"foreign1","Names":["/noo-tei"],"Image":"ghcr.io/huggingface/text-embeddings-inference:1.6","Labels":{"com.docker.compose.project":"noomesh"}},
 {"Id":"foreign2","Names":["/noo-stunnel-tei"],"Image":"x/stunnel:1","Labels":{}}
]`)
	r.Once(t.Context())
	if got := d.removed(); got != "" {
		t.Fatalf("removed %q: a container without this agent's label was removed", got)
	}
	for _, c := range d.seen() {
		if strings.HasSuffix(c, "/stop") {
			t.Fatalf("a foreign container was stopped: %s", c)
		}
	}
	// The placement is still refused: the engine is gone either way.
	if embeddingRefusal() == "" {
		t.Error("the placement was not refused")
	}
}

// The seam: a removal is logged once per container, a docker error is retried
// on the next pass (not marked done), and a clean pass is not repeated.
func TestRemoveRetiredTEIPhaseRunsOnceCleanAndRetriesAnError(t *testing.T) {
	calls := 0
	var fail error
	r := &Reconciler{
		cfg: &config.Config{NodeID: "node-a"},
		removeRetiredTEIFn: func(context.Context) ([]dockerpkg.RetiredTEI, error) {
			calls++
			if fail != nil {
				return nil, fail
			}
			return []dockerpkg.RetiredTEI{{Name: "noo-tei"}, {Name: "noo-reranker", Reranker: true}}, nil
		},
	}
	fail = errors.New("docker busy")
	r.removeRetiredTEI(t.Context(), &tick{})
	if r.retiredTEIDone || calls != 1 {
		t.Fatalf("an error must be retried: done=%v calls=%d", r.retiredTEIDone, calls)
	}
	fail = nil
	r.removeRetiredTEI(t.Context(), &tick{})
	r.removeRetiredTEI(t.Context(), &tick{})
	if !r.retiredTEIDone || calls != 2 {
		t.Fatalf("a clean pass must not repeat: done=%v calls=%d", r.retiredTEIDone, calls)
	}
}

// The one line per removal says what was removed, why, and the replacement.
func TestRetiredTEIRemovalLines(t *testing.T) {
	for _, tc := range []struct {
		rc   dockerpkg.RetiredTEI
		want []string
	}{
		{dockerpkg.RetiredTEI{Name: "noo-tei"}, []string{"removed noo-tei: the TEI engine was removed in 0.6.30; replace the placement:", "noo cluster place node-a ollama <model> --role embed"}},
		{dockerpkg.RetiredTEI{Name: "noo-stunnel-tei"}, []string{"removed noo-stunnel-tei: the door of the TEI engine, which was removed in 0.6.30"}},
		{dockerpkg.RetiredTEI{Name: "noo-reranker", Reranker: true}, []string{"removed noo-reranker: it ran the TEI engine", "noo cluster place node-a reranker <file>.gguf"}},
	} {
		line := retiredTEIRemovalLine(tc.rc, "node-a")
		for _, w := range tc.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s: line %q lacks %q", tc.rc.Name, line, w)
			}
		}
	}
}
