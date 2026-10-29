// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// ChatModelStats is the heartbeat's `model_stats` entries for the models
// the node's vLLM and llama-server chat placements serve, each with the
// model's own context ceiling, so the controller caps a harness window by
// the weights rather than a table in core (noomesh-internal i285). Every
// running chat placement is read: the controller's fit takes the smallest
// window across all of them. An ollama's models report theirs through
// /api/show (modelstats.Ceilings). A ceiling once found is remembered for
// the backend, model and served name, so each backend is asked once per
// model; one not found yet is left out and asked again next beat.
func (s *Server) ChatModelStats(ctx context.Context) []modelstats.ModelStat {
	ctx, cancel := context.WithTimeout(ctx, chatWindowTimeout)
	defer cancel()
	s.ceilingMu.Lock()
	defer s.ceilingMu.Unlock()
	known := map[string]modelstats.ModelStat{}
	var out []modelstats.ModelStat
	for _, t := range s.chatTargets(ctx) {
		if t.backend != "vllm" && t.backend != "llamacpp" {
			continue
		}
		key := t.backend + "\x00" + t.model + "\x00" + t.served
		st, ok := s.ceilings[key]
		if !ok {
			if st = s.chatCeiling(ctx, t); st.ContextLength == 0 {
				continue
			}
		}
		known[key] = st
		out = append(out, st)
	}
	// Only the placements running now are remembered.
	s.ceilings = known
	return out
}

// chatTargets dials every running chat placement whose backend is up.
func (s *Server) chatTargets(ctx context.Context) []benchTarget {
	if s.ceilingTargets != nil {
		return s.ceilingTargets(ctx)
	}
	if s.chatPlacements == nil {
		return nil
	}
	cps := s.chatPlacements()
	if len(cps) == 0 {
		return nil
	}
	running, native := s.runningAndNative(ctx)
	var out []benchTarget
	for _, cp := range cps {
		if t, err := s.chatTarget(ctx, cp, running, native); err == nil {
			out = append(out, t)
		}
	}
	return out
}

// chatCeiling reads the served model's ceiling. vLLM: max_position_embeddings
// from the model's config.json in the node's HF cache (vLLM's /v1/models
// gives only the window it was started with, max_model_len). llama-server:
// the GGUF's n_ctx_train and size from /v1/models.
func (s *Server) chatCeiling(ctx context.Context, t benchTarget) modelstats.ModelStat {
	st := modelstats.ModelStat{Name: t.model, Loaded: true}
	body := backendGet(ctx, t, "/v1/models")
	switch t.backend {
	case "vllm":
		root := vllmRoot(body, t.served)
		if root == "" {
			root = t.model
		}
		hf := dockerpkg.HFCacheHost
		if s.hfCacheDir != nil {
			hf = s.hfCacheDir
		}
		st.ContextLength = modelstats.HFConfigContextLength(hfConfig(hf(), root))
	case "llamacpp":
		st.ContextLength, st.SizeBytes = modelstats.LlamaTrainContext(body, t.served)
	}
	return st
}

// vllmRoot is the `root` of the served model's /v1/models entry: the HF repo
// id or path vLLM loaded, which --served-model-name may hide behind another
// id. "" when the body does not say.
func vllmRoot(body []byte, served string) string {
	var out struct {
		Data []struct {
			ID   string `json:"id"`
			Root string `json:"root"`
		} `json:"data"`
	}
	if len(body) == 0 || json.Unmarshal(body, &out) != nil {
		return ""
	}
	for _, m := range out.Data {
		if m.ID == served {
			return m.Root
		}
	}
	return ""
}

// hfConfig is the config.json of the model vLLM loaded from `root`, read
// from the host's HF cache `hfHost`: a repo id resolves through
// hub/models--org--name/refs/main (or the only snapshot), a path under the
// container's mount (dockerpkg.HFCacheTarget) maps to the host. Nil for a
// path outside the mount or a model not in the cache.
func hfConfig(hfHost, root string) []byte {
	if hfHost == "" || root == "" {
		return nil
	}
	var dir string
	if strings.HasPrefix(root, "/") {
		rel, ok := strings.CutPrefix(filepath.Clean(root), dockerpkg.HFCacheTarget+"/")
		if !ok {
			return nil
		}
		dir = filepath.Join(hfHost, rel)
	} else {
		snaps := filepath.Join(hfHost, "hub", preseed.RepoCacheDir(root), "snapshots")
		rev := ""
		if b, err := os.ReadFile(filepath.Join(snaps, "..", "refs", "main")); err == nil {
			rev = strings.TrimSpace(string(b))
		} else if entries, err := os.ReadDir(snaps); err == nil && len(entries) == 1 {
			rev = entries[0].Name()
		}
		if rev == "" || strings.ContainsAny(rev, `/\`) || rev == ".." {
			return nil
		}
		dir = filepath.Join(snaps, rev)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil
	}
	return b
}
