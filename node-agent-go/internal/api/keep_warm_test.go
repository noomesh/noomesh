// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/keepwarm"
)

func onlyGemma(m string) bool { return keepwarm.SameModel(m, "gemma4:12b") }

func keepAliveOf(t *testing.T, body []byte) (json.RawMessage, bool) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	v, ok := m["keep_alive"]
	return v, ok
}

// The named warm model gets keep_alive -1; another model, the embedder and a
// body with no model are untouched.
func TestKeepWarmPinsOnlyTheNamedModel(t *testing.T) {
	got := withKeepWarm([]byte(`{"model":"gemma4:12b","messages":[]}`), onlyGemma)
	if v, ok := keepAliveOf(t, got); !ok || string(v) != "-1" {
		t.Fatalf("warm model not pinned: %s", got)
	}
	for _, body := range []string{
		`{"model":"gemma4:e2b","messages":[]}`,
		`{"model":"harrier","input":"x"}`,
		`{"messages":[]}`,
		`not json`,
	} {
		if out := withKeepWarm([]byte(body), onlyGemma); string(out) != body {
			t.Errorf("%s changed to %s", body, out)
		}
	}
}

// A caller's explicit keep_alive is theirs: a duration, 0 (unload now) and an
// explicit null all pass through unchanged.
func TestKeepWarmKeepsTheCallersKeepAlive(t *testing.T) {
	for _, ka := range []string{`"10m"`, `0`, `null`, `"-1"`} {
		body := fmt.Sprintf(`{"model":"gemma4:12b","keep_alive":%s}`, ka)
		if out := withKeepWarm([]byte(body), onlyGemma); string(out) != body {
			t.Errorf("keep_alive %s overridden: %s", ka, out)
		}
	}
}

// Default off: nothing declared, nothing pinned (the published set is empty
// until a placement says keep_warm).
func TestKeepWarmIsOffUntilDeclared(t *testing.T) {
	t.Cleanup(func() { keepwarm.Set(nil) })
	keepwarm.Set(nil)
	body := `{"model":"gemma4:12b","messages":[]}`
	if out := keepWarmBody([]byte(body), "ollama", "/v1/chat/completions"); string(out) != body {
		t.Fatalf("pinned with nothing declared: %s", out)
	}
	keepwarm.Set([]keepwarm.Warm{{Model: "gemma4:12b"}})
	if v, ok := keepAliveOf(t, keepWarmBody([]byte(body), "ollama", "/v1/chat/completions")); !ok || string(v) != "-1" {
		t.Fatal("declared warm, not pinned")
	}
	// Only ollama, and only the paths that become a generation.
	for _, c := range [][2]string{{"vllm", "/v1/chat/completions"}, {"llamacpp", "/v1/completions"}, {"ollama", "/v1/embeddings"}} {
		if out := keepWarmBody([]byte(body), c[0], c[1]); string(out) != body {
			t.Errorf("%s %s: pinned: %s", c[0], c[1], out)
		}
	}
}

// The pin survives the allowlist and the /api/chat translation, so it reaches
// the ollama a chat is relayed to — the adopted stack lane's included (the
// translator is runtime-agnostic; the lane differs only in its URL).
func TestKeepWarmReachesOllamaApiChat(t *testing.T) {
	t.Cleanup(func() { keepwarm.Set(nil) })
	keepwarm.Set([]keepwarm.Warm{{Model: "gemma4:12b"}})
	var seen map[string]any
	lane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"model":"gemma4:12b","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":"stop"}`)
	}))
	defer lane.Close()
	body := keepWarmBody([]byte(`{"model":"gemma4:12b","messages":[{"role":"user","content":"hi"}]}`), "ollama", "/v1/chat/completions")
	body = filterBodyForBackend(body, "ollama")
	s := &Server{native: backendrt.NewStackAt(lane.URL)}
	w := httptest.NewRecorder()
	s.proxyOllamaChat(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), body, lane.URL, "http", 5*time.Second)
	if w.Code != 200 {
		t.Fatalf("relay: %d %s", w.Code, w.Body)
	}
	if seen["keep_alive"] != float64(-1) {
		t.Fatalf("ollama /api/chat body has keep_alive %v, want -1: %v", seen["keep_alive"], seen)
	}
}

// The proxy pins before it splits Docker from a native or adopted lane, so
// every ollama runtime gets it.
func TestKeepWarmRunsBeforeTheRuntimeSplit(t *testing.T) {
	src, err := os.ReadFile("inference_proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "func (s *Server) handleInferenceProxy(")
	end := strings.Index(s, "\nfunc (s *Server) inferenceTarget(")
	if start < 0 || end < start {
		t.Fatal("handleInferenceProxy not found")
	}
	fn := s[start:end]
	pin := strings.Index(fn, "body = keepWarmBody(body, backendType, r.URL.Path)")
	split := strings.Index(fn, "s.inferenceTarget(")
	if pin < 0 || split < 0 || pin > split {
		t.Fatalf("keepWarmBody must run before inferenceTarget (pin at %d, split at %d)", pin, split)
	}
}

// fakeOllama is a stack-lane ollama: /api/tags, /api/ps from its loaded set,
// /api/generate recorded and applied (keep_alive -1 pins, 0 unloads, absent
// resets to 5 minutes).
type fakeOllama struct {
	mu     sync.Mutex
	loaded map[string]time.Time // model -> expires_at
	gens   []map[string]any
	srv    *httptest.Server
}

func newFakeOllama(t *testing.T, loaded map[string]time.Time) *fakeOllama {
	f := &fakeOllama{loaded: loaded}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/api/tags":
			fmt.Fprint(w, `{"models":[]}`)
		case "/api/ps":
			var ms []map[string]any
			for m, exp := range f.loaded {
				ms = append(ms, map[string]any{"name": m, "model": m, "expires_at": exp})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": ms})
		case "/api/generate":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.gens = append(f.gens, in)
			m, _ := in["model"].(string)
			switch ka, set := in["keep_alive"]; {
			case !set:
				f.loaded[m] = time.Now().Add(5 * time.Minute)
			case ka == float64(0):
				delete(f.loaded, m)
			default:
				f.loaded[m] = time.Date(2318, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			fmt.Fprint(w, `{"done":true}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOllama) generations() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.gens...)
}

// stackKeeper: a keeper dialling a stack-lane ollama through the Server's own
// resolution (runningAndNative + inferenceTarget), as on the controller's
// self-node, where the agent never configures the daemon.
func stackKeeper(f *fakeOllama, warm []keepwarm.Warm, freed *bool) *warmKeeper {
	s := &Server{cfg: &config.Config{}, native: backendrt.NewStackAt(f.srv.URL)}
	k := newWarmKeeper(s.ollamaDial)
	k.warm = func() []keepwarm.Warm { return warm }
	k.freed = func() bool { return *freed }
	return k
}

// On the adopted stack lane: the warm model is preloaded with keep_alive -1
// and no prompt; the embedder loaded beside it is never touched; a pinned
// model is not preloaded again.
func TestKeeperPreloadsTheWarmModelOnTheStackLane(t *testing.T) {
	f := newFakeOllama(t, map[string]time.Time{"harrier:latest": time.Now().Add(4 * time.Minute)})
	freed := false
	k := stackKeeper(f, []keepwarm.Warm{{Model: "gemma4:12b"}}, &freed)
	k.Pass(context.Background())
	g := f.generations()
	if len(g) != 1 || g[0]["model"] != "gemma4:12b" || g[0]["keep_alive"] != float64(-1) {
		t.Fatalf("preload: %v", g)
	}
	if _, prompt := g[0]["prompt"]; prompt {
		t.Fatalf("a preload sends no prompt: %v", g[0])
	}
	k.Pass(context.Background())
	if n := len(f.generations()); n != 1 {
		t.Fatalf("a pinned model is not preloaded again: %d generations", n)
	}
	// A request without keep_alive reset it to the default: re-pinned.
	f.mu.Lock()
	f.loaded["gemma4:12b"] = time.Now().Add(5 * time.Minute)
	f.mu.Unlock()
	k.Pass(context.Background())
	if g := f.generations(); len(g) != 2 || g[1]["keep_alive"] != float64(-1) {
		t.Fatalf("re-pin: %v", g)
	}
	for _, x := range f.generations() {
		if x["model"] != "gemma4:12b" {
			t.Fatalf("only the warm model is touched: %v", x)
		}
	}
}

// Turning the flag off hands the model back to the daemon's expiry (no
// keep_alive), once; it is never unloaded for it.
func TestKeeperReleasesAClearedModelToTheDaemonsExpiry(t *testing.T) {
	f := newFakeOllama(t, map[string]time.Time{})
	freed := false
	warm := []keepwarm.Warm{{Model: "gemma4:12b"}}
	k := stackKeeper(f, warm, &freed)
	k.Pass(context.Background())
	k.warm = func() []keepwarm.Warm { return nil }
	k.Pass(context.Background())
	k.Pass(context.Background())
	g := f.generations()
	if len(g) != 2 {
		t.Fatalf("want preload then one release: %v", g)
	}
	if _, set := g[1]["keep_alive"]; set || g[1]["model"] != "gemma4:12b" {
		t.Fatalf("release must carry no keep_alive (the daemon's own expiry), not 0: %v", g[1])
	}
	if _, still := f.loaded["gemma4:12b"]; !still {
		t.Fatal("turning the flag off must not unload the model")
	}
}

// A GPU yield or hold unloads each warm GPU model with keep_alive 0 — on the
// stack lane too, which no container stop reaches — and leaves a cpu one; while
// the GPU is given back the keeper pins nothing on it.
func TestYieldUnloadsTheWarmGPUModel(t *testing.T) {
	f := newFakeOllama(t, map[string]time.Time{})
	freed := false
	k := stackKeeper(f, []keepwarm.Warm{{Model: "gemma4:12b", Target: "gpu"}, {Model: "qwen3:0.6b", Target: "cpu"}}, &freed)
	k.Pass(context.Background())
	if n := len(f.generations()); n != 2 {
		t.Fatalf("both preloaded: %v", f.generations())
	}
	freed = true
	k.Unload(context.Background(), "voice")
	g := f.generations()
	if len(g) != 3 || g[2]["model"] != "gemma4:12b" || g[2]["keep_alive"] != float64(0) {
		t.Fatalf("unload: %v", g)
	}
	if _, loaded := f.loaded["gemma4:12b"]; loaded {
		t.Fatal("the warm GPU model is still loaded")
	}
	if _, loaded := f.loaded["qwen3:0.6b"]; !loaded {
		t.Fatal("a cpu model holds no GPU: left alone")
	}
	k.Pass(context.Background())
	if n := len(f.generations()); n != 3 {
		t.Fatalf("nothing is pinned on a GPU given back: %v", f.generations())
	}
	freed = false
	k.Pass(context.Background())
	if g := f.generations(); len(g) != 4 || g[3]["model"] != "gemma4:12b" || g[3]["keep_alive"] != float64(-1) {
		t.Fatalf("after the resume the keeper warms it again: %v", g)
	}
}

// A yield that lands while the preload runs: what was loaded is given back.
func TestAPreloadThatRacesAYieldIsUnloaded(t *testing.T) {
	f := newFakeOllama(t, map[string]time.Time{})
	freed := false
	k := stackKeeper(f, []keepwarm.Warm{{Model: "gemma4:12b"}}, &freed)
	calls := 0
	k.freed = func() bool { calls++; return calls > 1 } // free at the check, held after the load
	k.Pass(context.Background())
	g := f.generations()
	if len(g) != 2 || g[1]["keep_alive"] != float64(0) {
		t.Fatalf("want preload then unload: %v", g)
	}
}
