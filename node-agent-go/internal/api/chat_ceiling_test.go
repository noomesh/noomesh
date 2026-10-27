// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// hfSnapshot writes config.json into a fake HF cache for repo at revision
// rev, with refs/main pointing at it.
func hfSnapshot(t *testing.T, hf, repo, rev, config string) {
	t.Helper()
	dir := filepath.Join(hf, "hub", preseed.RepoCacheDir(repo))
	snap := filepath.Join(dir, "snapshots", rev)
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refs", "main"), []byte(rev+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, "config.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ceilingServer is a Server whose running chat placements are `targets`,
// each {backend, model} served by srv under the model's name.
func ceilingServer(srv *httptest.Server, targets ...[2]string) *Server {
	s := &Server{}
	s.ceilingTargets = func(context.Context) []benchTarget {
		var out []benchTarget
		for _, t := range targets {
			out = append(out, benchTarget{
				backend: t[0], model: t[1], served: t[1],
				url:    srv.URL + "/" + t[0] + "/v1/chat/completions",
				client: &http.Client{Transport: s.inferenceTransport("http", benchBudget)},
			})
		}
		return out
	}
	return s
}

func TestChatModelStatsReadsVLLMsConfigOnce(t *testing.T) {
	hf := t.TempDir()
	hfSnapshot(t, hf, "org/gemma-4-12B", "abc123", `{"text_config":{"max_position_embeddings":262144}}`)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// --served-model-name m: the id hides the repo, root names it.
		_, _ = w.Write([]byte(`{"data":[{"id":"m","root":"org/gemma-4-12B","max_model_len":16384}]}`))
	}))
	defer srv.Close()
	s := ceilingServer(srv, [2]string{"vllm", "m"})
	s.hfCacheDir = func() string { return hf }
	want := []modelstats.ModelStat{{Name: "m", Loaded: true, ContextLength: 262144}}
	for i := 0; i < 3; i++ {
		got := s.ChatModelStats(context.Background())
		if len(got) != 1 || got[0] != want[0] {
			t.Fatalf("beat %d: %+v, want %+v", i, got, want)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the backend was asked %d times, want once", n)
	}
}

func TestChatModelStatsVLLMPathUnderTheMount(t *testing.T) {
	hf := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hf, "local", "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hf, "local", "m", "config.json"), []byte(`{"max_position_embeddings":40960}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := hfConfig(hf, "/root/.cache/huggingface/local/m"); modelstats.HFConfigContextLength(got) != 40960 {
		t.Errorf("a path under the mount: %q", got)
	}
	if got := hfConfig(hf, "/models/m"); got != nil {
		t.Errorf("a path outside the mount must not be read: %q", got)
	}
	if got := hfConfig(hf, "/root/.cache/huggingface/../../etc"); got != nil {
		t.Errorf("a path escaping the mount must not be read: %q", got)
	}
}

func TestChatModelStatsReportsEveryChatPlacement(t *testing.T) {
	hf := t.TempDir()
	hfSnapshot(t, hf, "org/big", "r1", `{"max_position_embeddings":131072}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vllm/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"org/big","root":"org/big"}]}`))
		case "/llamacpp/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"small.gguf","meta":{"n_ctx_train":32768,"size":4200000000}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	// vLLM and llama-server side by side, and an ollama chat placement that
	// reports through /api/show instead.
	s := ceilingServer(srv, [2]string{"vllm", "org/big"}, [2]string{"llamacpp", "small.gguf"}, [2]string{"ollama", "gemma4:12b"})
	s.hfCacheDir = func() string { return hf }
	want := []modelstats.ModelStat{
		{Name: "org/big", Loaded: true, ContextLength: 131072},
		{Name: "small.gguf", Loaded: true, ContextLength: 32768, SizeBytes: 4200000000},
	}
	if got := s.ChatModelStats(context.Background()); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if len(s.ceilings) != 2 {
		t.Errorf("remembered %d, want 2", len(s.ceilings))
	}
	// The vLLM placement is removed: its ceiling is forgotten.
	s2 := ceilingServer(srv, [2]string{"llamacpp", "small.gguf"})
	s.ceilingTargets = s2.ceilingTargets
	if got := s.ChatModelStats(context.Background()); len(got) != 1 || len(s.ceilings) != 1 {
		t.Errorf("after the vLLM placement left: %+v, remembered %d", got, len(s.ceilings))
	}
}

func TestChatModelStatsUnknowns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	defer srv.Close()
	// vLLM with the repo missing from the cache, llama-server without meta:
	// unknown, nothing remembered, asked again next beat.
	s := ceilingServer(srv, [2]string{"vllm", "m"}, [2]string{"llamacpp", "m"})
	s.hfCacheDir = t.TempDir
	if got := s.ChatModelStats(context.Background()); got != nil || len(s.ceilings) != 0 {
		t.Errorf("unknown ceilings: %+v, remembered %d", got, len(s.ceilings))
	}
	if got := (&Server{}).ChatModelStats(context.Background()); got != nil {
		t.Errorf("no chat placements: %+v", got)
	}
}
