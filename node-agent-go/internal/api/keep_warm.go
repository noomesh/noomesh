// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

// Declared keep-warm (`noo cluster place … --keep-warm`, internal/keepwarm).
//
// An ollama unloads an idle model after its keep_alive (5 minutes by
// default) and loads it again, cold, on the next request. A placement that
// declares keep_warm is kept loaded by the AGENT, on whichever ollama serves
// it — agent-run Docker, brew, Ollama.app, or the controller's adopted stack
// lane, which the agent never configures or restarts — because all of them
// take a per-request keep_alive:
//
//   - the inference proxy adds `keep_alive: -1` to a chat or completion
//     request for a warm model, unless the caller set keep_alive itself
//     (keepWarmBody). Only that model: the embedder or another chat model on
//     the same daemon keeps the daemon's own expiry;
//   - the warm keeper (RunKeepWarm, every keepWarmEvery) reads /api/ps and
//     PRELOADS a warm model that is not loaded or not pinned (`/api/generate
//     {model, keep_alive: -1}`, no prompt), so it is warm after a daemon
//     (re)start, a flag turned on or a GPU resume without waiting for a first
//     request — and re-pins one a request without keep_alive reset to the
//     default (ollama's OpenAI /v1/completions layer drops keep_alive);
//   - a flag turned OFF stops the pinning and hands the model back to the
//     daemon's own expiry (`/api/generate {model}` with no keep_alive, sent
//     only if it is loaded): it then expires naturally. Never keep_alive 0
//     there — turning the flag off is not "unload now";
//   - a GPU yield or hold UNLOADS each warm GPU model (`keep_alive: 0`,
//     UnloadWarm, the gpuyield pause hook) before the GPU backends stop: the
//     adopted stack lane is never stopped, so a stop would not free it. While
//     the GPU is given back nothing pins a GPU model (a request still loads
//     it on demand, with the daemon's expiry). A `--on cpu` model holds no
//     GPU and is left alone.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
	"github.com/noomesh/noomesh/node-agent-go/internal/keepwarm"
)

const (
	// keepWarmEvery is how often the keeper checks the warm models.
	keepWarmEvery = 30 * time.Second
	// keepWarmLoadTimeout bounds one preload: a cold load of a large model
	// takes over a minute on a laptop GPU (backendFirstByteTimeout's note).
	keepWarmLoadTimeout = 10 * time.Minute
	// pinnedHorizon: an /api/ps expiry further out than this is a pin
	// (keep_alive -1 reads as year 2318), not a countdown.
	pinnedHorizon = 365 * 24 * time.Hour
)

// keepWarmPaths are the proxied paths that become an ollama generation.
var keepWarmPaths = map[string]bool{"/v1/chat/completions": true, "/v1/completions": true}

// keepWarmBody adds keep_alive -1 to an ollama chat/completion body whose
// model is declared warm on this node. Runtime-agnostic: it runs before the
// proxy splits Docker from a native or adopted lane.
func keepWarmBody(body []byte, backendType, path string) []byte {
	if backendType != "ollama" || !keepWarmPaths[path] {
		return body
	}
	return withKeepWarm(body, keepWarmPinsNow)
}

// keepWarmPinsNow: model is declared warm, and the GPU is not being given
// back (a GPU model is not pinned during a yield or hold).
func keepWarmPinsNow(model string) bool {
	w, ok := keepwarm.Lookup(model)
	if !ok {
		return false
	}
	return !(w.OnGPU() && gpuyield.GPUFreed())
}

// withKeepWarm sets keep_alive -1 on body when pin(model) and the caller sent
// no keep_alive. Anything unparseable passes through unchanged.
func withKeepWarm(body []byte, pin func(model string) bool) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if _, set := m["keep_alive"]; set {
		return body // the caller's own keep_alive wins, null included
	}
	var model string
	if json.Unmarshal(m["model"], &model) != nil || !pin(model) {
		return body
	}
	m["keep_alive"] = json.RawMessage("-1")
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// errNoOllama: no ollama runs on this node right now (nothing to keep warm).
var errNoOllama = errors.New("no ollama is running on this node")

// ollamaDialer resolves this node's ollama: its base URL and a client.
type ollamaDialer func(ctx context.Context) (string, *http.Client, error)

// warmKeeper preloads, re-pins, releases and unloads the declared-warm
// models on this node's ollama.
type warmKeeper struct {
	dial  ollamaDialer
	warm  func() []keepwarm.Warm
	freed func() bool
	now   func() time.Time

	pass sync.Mutex // one keeper pass at a time

	mu sync.Mutex
	// pinned: the models this agent pinned (canonical -> name as placed), so
	// a cleared flag is handed back to the daemon's expiry once.
	pinned map[string]string
	// lastErr: the last failure per model, so a model not pulled yet is
	// logged once per cause, not every pass.
	lastErr map[string]string
}

func newWarmKeeper(dial ollamaDialer) *warmKeeper {
	return &warmKeeper{
		dial: dial, warm: keepwarm.All, freed: gpuyield.GPUFreed, now: time.Now,
		pinned: map[string]string{}, lastErr: map[string]string{},
	}
}

// psEntry is one /api/ps model: when it expires.
type psEntry struct {
	expires time.Time
}

// loaded reads /api/ps: canonical model name -> entry.
func (k *warmKeeper) loaded(ctx context.Context, base string, client *http.Client) (map[string]psEntry, error) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, base+"/api/ps", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/api/ps: status %d", resp.StatusCode)
	}
	var ps struct {
		Models []struct {
			Name      string    `json:"name"`
			Model     string    `json:"model"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ps); err != nil {
		return nil, fmt.Errorf("/api/ps: %w", err)
	}
	out := map[string]psEntry{}
	for _, m := range ps.Models {
		for _, n := range []string{m.Name, m.Model} {
			if c := keepwarm.Canonical(n); c != "" {
				out[c] = psEntry{expires: m.ExpiresAt}
			}
		}
	}
	return out, nil
}

// generate sends ollama's no-prompt `/api/generate`: keep_alive -1 loads and
// pins, 0 unloads, and nil (absent) resets the model to the daemon's own
// expiry.
func (k *warmKeeper) generate(ctx context.Context, base string, client *http.Client, model string, keepAlive *int) error {
	body := map[string]any{"model": model, "stream": false}
	if keepAlive != nil {
		body["keep_alive"] = *keepAlive
	}
	b, _ := json.Marshal(body)
	rctx, cancel := context.WithTimeout(ctx, keepWarmLoadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, base+"/api/generate", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/api/generate: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func intp(n int) *int { return &n }

// noteErr logs a model's failure once per distinct cause.
func (k *warmKeeper) noteErr(model, what string, err error) {
	k.mu.Lock()
	same := k.lastErr[model] == err.Error()
	k.lastErr[model] = err.Error()
	k.mu.Unlock()
	if !same {
		slog.Warn("keep-warm: "+what+" failed; retrying each pass", "model", model, "error", err)
	}
}

func (k *warmKeeper) clearErr(model string) {
	k.mu.Lock()
	delete(k.lastErr, model)
	k.mu.Unlock()
}

// Pass is one keeper round (see the file comment).
func (k *warmKeeper) Pass(ctx context.Context) {
	k.pass.Lock()
	defer k.pass.Unlock()
	ws := k.warm()
	k.mu.Lock()
	idle := len(ws) == 0 && len(k.pinned) == 0
	k.mu.Unlock()
	if idle {
		return
	}
	base, client, err := k.dial(ctx)
	if err != nil {
		return // no ollama now: nothing is loaded to keep or release
	}
	loaded, err := k.loaded(ctx, base, client)
	if err != nil {
		slog.Debug("keep-warm: /api/ps unreadable; skipping this pass", "error", err)
		return
	}
	want := map[string]bool{}
	for _, w := range ws {
		c := keepwarm.Canonical(w.Model)
		want[c] = true
		if w.OnGPU() && k.freed() {
			continue // the GPU is given back: pin nothing on it
		}
		e, isLoaded := loaded[c]
		if isLoaded && e.expires.After(k.now().Add(pinnedHorizon)) {
			k.mu.Lock()
			k.pinned[c] = w.Model
			k.mu.Unlock()
			continue
		}
		start := k.now()
		if err := k.generate(ctx, base, client, w.Model, intp(-1)); err != nil {
			k.noteErr(w.Model, "preload", err)
			continue
		}
		k.clearErr(w.Model)
		k.mu.Lock()
		k.pinned[c] = w.Model
		k.mu.Unlock()
		slog.Info("keep-warm: model pinned (declared warm)", "model", w.Model,
			"was_loaded", isLoaded, "took", k.now().Sub(start).Round(time.Millisecond))
		// A yield or hold that landed while it loaded: give it back now.
		if w.OnGPU() && k.freed() {
			k.unloadOne(ctx, base, client, w.Model, "GPU given back while it loaded")
		}
	}
	k.mu.Lock()
	var released []string
	for c, m := range k.pinned {
		if !want[c] {
			delete(k.pinned, c)
			if _, isLoaded := loaded[c]; isLoaded {
				released = append(released, m)
			}
		}
	}
	k.mu.Unlock()
	for _, m := range released {
		// No keep_alive: the daemon's own expiry. Not 0 — off is not unload.
		if err := k.generate(ctx, base, client, m, nil); err != nil {
			slog.Warn("keep-warm: could not hand a model back to the daemon's expiry; it stays loaded until a request resets it",
				"model", m, "error", err)
			continue
		}
		slog.Info("keep-warm: flag cleared; model back on the daemon's own expiry", "model", m)
	}
}

// unloadOne sends keep_alive 0 for model.
func (k *warmKeeper) unloadOne(ctx context.Context, base string, client *http.Client, model, why string) {
	if err := k.generate(ctx, base, client, model, intp(0)); err != nil {
		slog.Error("keep-warm: unloading a warm model failed; it may still hold the GPU", "model", model, "why", why, "error", err)
		return
	}
	k.mu.Lock()
	delete(k.pinned, keepwarm.Canonical(model))
	k.mu.Unlock()
	slog.Warn("keep-warm: warm model unloaded to free the GPU", "model", model, "why", why)
}

// Unload sends keep_alive 0 for every warm GPU model (the gpuyield pause
// hook). It does not wait for a pass in progress: that pass re-checks the
// GPU after its preload and unloads what it loaded.
func (k *warmKeeper) Unload(ctx context.Context, why string) {
	var gpu []string
	for _, w := range k.warm() {
		if w.OnGPU() {
			gpu = append(gpu, w.Model)
		}
	}
	if len(gpu) == 0 {
		return
	}
	base, client, err := k.dial(ctx)
	if err != nil {
		if !errors.Is(err, errNoOllama) {
			slog.Warn("keep-warm: cannot reach ollama to unload the warm models for the GPU", "error", err)
		}
		return
	}
	for _, m := range gpu {
		k.unloadOne(ctx, base, client, m, why)
	}
}

// ollamaDial reaches this node's ollama exactly as the inference proxy does
// (inferenceTarget + inferenceTransport): the agent-run container, a native
// install, or the adopted stack lane's door with the node leaf.
func (s *Server) ollamaDial(ctx context.Context) (string, *http.Client, error) {
	running, native, err := s.runningAndNative(ctx)
	if err != nil {
		return "", nil, err
	}
	if _, up := running["ollama"]; !up {
		return "", nil, errNoOllama
	}
	base, scheme := s.inferenceTarget(ctx, "ollama", dockerpkg.BackendPorts["ollama"], native)
	return strings.TrimRight(base, "/"), &http.Client{Transport: s.inferenceTransport(scheme, keepWarmLoadTimeout)}, nil
}

func (s *Server) warmKeeper() *warmKeeper {
	s.keeperOnce.Do(func() {
		if s.keeper == nil {
			s.keeper = newWarmKeeper(s.ollamaDial)
		}
	})
	return s.keeper
}

// RunKeepWarm keeps the declared-warm models loaded until ctx ends.
func (s *Server) RunKeepWarm(ctx context.Context) {
	k := s.warmKeeper()
	t := time.NewTicker(keepWarmEvery)
	defer t.Stop()
	for {
		k.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// UnloadWarm is the GPU yield/hold pause hook (gpuyield.OnPause).
func (s *Server) UnloadWarm(ctx context.Context, why string) {
	s.warmKeeper().Unload(ctx, why)
}
