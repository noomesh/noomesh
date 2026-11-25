// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"testing"
)

func TestBuildRerankRequest_LlamacppTranslate(t *testing.T) {
	body := []byte(`{"query":"q","texts":["a","b"],"return_text":false}`)
	out, path, err := buildRerankRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/v1/rerank" {
		t.Errorf("path = %q, want /v1/rerank", path)
	}
	var got struct {
		Model     string   `json:"model"`
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
		TopN      int      `json:"top_n"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("bad translated body: %v", err)
	}
	if got.Query != "q" || len(got.Documents) != 2 || got.Documents[1] != "b" || got.TopN != 2 {
		t.Errorf("bad translation: %+v", got)
	}
}

func TestBuildRerankRequest_LlamacppRejectsEmpty(t *testing.T) {
	if _, _, err := buildRerankRequest([]byte(`{"texts":[]}`)); err == nil {
		t.Error("expected error for empty query/texts")
	}
}

func TestNormalizeRerankResponse_Llamacpp(t *testing.T) {
	raw := []byte(`{"model":"m","object":"list","results":[{"index":0,"relevance_score":-1.5},{"index":2,"relevance_score":3.25}],"usage":{"total_tokens":9}}`)
	out, err := normalizeRerankResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var rows []struct {
		Index int     `json:"index"`
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("bad normalized body: %v", err)
	}
	if len(rows) != 2 || rows[0].Index != 2 || rows[0].Score != 3.25 || rows[1].Index != 0 {
		t.Errorf("bad llamacpp normalization: %+v", rows)
	}
	// Gateway contract: TOP-LEVEL array of {index, score} only.
	var generic []map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("normalized response must be a bare array: %v", err)
	}
	for _, row := range generic {
		if len(row) != 2 {
			t.Errorf("row must carry exactly index+score, got %v", row)
		}
	}
}

func TestNormalizeRerankResponse_ShapeMismatch(t *testing.T) {
	// The old TEI bare array is not llama-server's answer: it must error, not
	// be passed on as scores.
	if _, err := normalizeRerankResponse([]byte(`[{"index":0,"score":1}]`)); err == nil {
		t.Error("llamacpp parser accepted a bare TEI-style array")
	}
}

// There is one candidate: llama-server, on the door the container declares.
func TestLocalRerankTargets_OnlyLlamacpp(t *testing.T) {
	t.Setenv("NOO_LOCAL_RERANK_URL", "")
	rerankTargetMu.Lock()
	rerankTargetCached = nil
	rerankTargetMu.Unlock()
	// The sidecar door (the default, and what a running noo-stunnel-reranker
	// declares).
	targets := localRerankTargets("https://noo-stunnel-reranker:443")
	if len(targets) != 1 || targets[0].base != "https://noo-stunnel-reranker:443" {
		t.Fatalf("sidecar door: %+v", targets)
	}
	// A pre-door container (plain, recorded as a refusal by the docker
	// package): llama-server's port on the container itself. No :80 TEI probe.
	targets = localRerankTargets("http://noo-reranker:8085")
	if len(targets) != 1 || targets[0].base != "http://noo-reranker:8085" {
		t.Errorf("pre-door: %+v", targets)
	}
}

func TestLocalRerankTargets_CachePromotion(t *testing.T) {
	t.Setenv("NOO_LOCAL_RERANK_URL", "")
	cacheRerankTarget(rerankTarget{"http://other-reranker:8085"})
	defer func() {
		rerankTargetMu.Lock()
		rerankTargetCached = nil
		rerankTargetMu.Unlock()
	}()
	targets := localRerankTargets("http://noo-reranker:8085")
	if targets[0].base != "http://other-reranker:8085" {
		t.Errorf("cached target should be probed first, got %+v", targets)
	}
	if len(targets) != 2 {
		t.Errorf("cache promotion must not drop candidates: %+v", targets)
	}
}

func TestLocalRerankTargets_EnvOverride(t *testing.T) {
	t.Setenv("NOO_LOCAL_RERANK_URL", "http://custom:9999/")
	rerankTargetMu.Lock()
	rerankTargetCached = nil
	rerankTargetMu.Unlock()
	targets := localRerankTargets("https://noo-stunnel-reranker:443")
	if len(targets) != 1 || targets[0].base != "http://custom:9999" {
		t.Errorf("env override not honoured: %+v", targets)
	}
}
