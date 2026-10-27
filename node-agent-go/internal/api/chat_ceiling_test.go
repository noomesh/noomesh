// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	s := windowServer("vllm", srv)
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

func TestChatModelStatsLlamaServerAndUnknowns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"m","meta":{"n_ctx_train":131072,"size":4200000000}}]}`))
	}))
	defer srv.Close()
	got := windowServer("llamacpp", srv).ChatModelStats(context.Background())
	if want := (modelstats.ModelStat{Name: "m", Loaded: true, ContextLength: 131072, SizeBytes: 4200000000}); len(got) != 1 || got[0] != want {
		t.Errorf("llama-server: %+v, want %+v", got, want)
	}
	if got := windowServer("ollama", srv).ChatModelStats(context.Background()); got != nil {
		t.Errorf("ollama reports through /api/show, not here: %+v", got)
	}
	// vLLM with the repo missing from the cache: unknown, and asked again.
	s := windowServer("vllm", srv)
	s.hfCacheDir = t.TempDir
	if got := s.ChatModelStats(context.Background()); got != nil {
		t.Errorf("model not in the cache: %+v", got)
	}
}
