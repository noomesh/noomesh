// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/harnessprofile"
)

// ollamaContextKey is the placement env key the profile's context
// defaults (placementEnvExact and backendrt.OllamaTuningKeys allow it).
const ollamaContextKey = "OLLAMA_CONTEXT_LENGTH"

// applyHarnessProfile installs desired-config's `harness_profile` as the
// node's current profile. Called only on a SUCCESSFUL fetch, so a failed one
// keeps the last good profile. Absent clears it (today's behaviour). A
// malformed one is logged and the last good profile kept: a controller bug
// must not take a node's bounds back to defaults mid-flight.
func applyHarnessProfile(raw json.RawMessage) {
	p, err := harnessprofile.Parse(raw)
	if err != nil {
		slog.Warn("reconcile.harness_profile_unreadable",
			"error", err, "effect", "keeping the last good profile")
		return
	}
	harnessprofile.Set(p)
}

// profileOllamaContext is the value to default OLLAMA_CONTEXT_LENGTH to for
// an ollama whose env is env, or "" when nothing is injected: no profile, no
// context in it, or the placement already sets the key (the
// placement's own value is never touched).
func profileOllamaContext(env map[string]string, prof *harnessprofile.Profile) string {
	if prof == nil || prof.Context <= 0 {
		return ""
	}
	if v, ok := env[ollamaContextKey]; ok && strings.TrimSpace(v) != "" {
		return ""
	}
	return strconv.Itoa(prof.Context)
}

// contextKeys is, per chat engine, the placement env key that sets its
// context window and every key whose presence means the placement already
// decided it (so the profile default stays out). One profile value, rendered
// per engine: until 2026-10-24 only Ollama read it, and a vLLM node ran at
// the image default (16384) while the same tier's Ollama ran at 32768, which
// no vendor CLI's prompt fit (noomesh-internal i225, proposal i226 phase A).
var contextKeys = map[string]struct {
	set    string
	decide []string
}{
	"ollama":         {ollamaContextKey, []string{ollamaContextKey}},
	"vllm":           {"VLLM_MAX_MODEL_LEN", []string{"VLLM_MAX_MODEL_LEN"}},
	"vllm-secondary": {"VLLM_MAX_MODEL_LEN", []string{"VLLM_MAX_MODEL_LEN"}},
	// llama-server takes --ctx-size from N_CTX (the noo image) or
	// LLAMA_ARG_CTX_SIZE (upstream image, mirrored from N_CTX); either one
	// set by the placement is its decision. Note the window is shared across
	// the server's parallel slots.
	"llamacpp": {"N_CTX", []string{"N_CTX", "LLAMA_ARG_CTX_SIZE"}},
}

// profileContext is the (key, value) the profile's context default adds to a
// placement of backend with env, or ("", "") when nothing is injected: no
// profile, no context in it, an engine without a window key, or a placement
// that already decides the window (its own value is never touched).
func profileContext(backend string, env map[string]string, prof *harnessprofile.Profile) (string, string) {
	if prof == nil || prof.Context <= 0 {
		return "", ""
	}
	k, ok := contextKeys[backend]
	if !ok {
		return "", ""
	}
	for _, d := range k.decide {
		if v, set := env[d]; set && strings.TrimSpace(v) != "" {
			return "", ""
		}
	}
	return k.set, strconv.Itoa(prof.Context)
}

// withProfileContext returns the effective placements with the profile's
// context default added to each RUNNING chat-engine placement whose env does
// not decide its window ([`contextKeys`]). The env map is copied, never
// mutated: the placement rows are the controller's. Applied before specHash,
// so the default is part of the container's spec and a change recreates it.
func withProfileContext(ps []placement, prof *harnessprofile.Profile) []placement {
	out := make([]placement, len(ps))
	copy(out, ps)
	for i, p := range out {
		if p.DesiredState != "running" {
			continue
		}
		key, v := profileContext(p.Backend, p.Env, prof)
		if v == "" {
			continue
		}
		env := make(map[string]string, len(p.Env)+1)
		for k, val := range p.Env {
			env[k] = val
		}
		env[key] = v
		out[i].Env = env
	}
	return out
}

// nativeOllamaTuning is what the macOS guard writes into a brew-managed
// ollama's plist (backendrt.SetOllamaTuning). Several roles in one daemon:
// the merged env, as before, plus the profile's context default when no role
// sets it. A lone placement's env is left as it always was, EXCEPT that the
// profile's context default reaches the plist when the placement does not
// set the key. No rows, no tuning.
func nativeOllamaTuning(rows []placement, prof *harnessprofile.Profile) map[string]string {
	switch {
	case len(rows) > 1:
		env, _ := mergeOllamaEnv(rows)
		if v := profileOllamaContext(env, prof); v != "" {
			env[ollamaContextKey] = v
		}
		return buildPlacementEnv(placement{Backend: "ollama", Env: env})
	case len(rows) == 1:
		env := buildPlacementEnv(rows[0])
		if v := profileOllamaContext(rows[0].Env, prof); v != "" {
			env[ollamaContextKey] = v
		}
		if len(env) == 0 {
			return nil
		}
		return env
	}
	return nil
}

// chatPlacementOf is the placement this node serves chat from: the first
// RUNNING placement whose role is chat (or unset) on a chat engine (a
// backend `noo` speaks, harness_kinds.json), in desired order. ok=false
// when there is none.
func chatPlacementOf(all []placement) (placement, bool) {
	for _, p := range all {
		if p.Backend == "harness" || p.DesiredState != "running" || (p.Role != "" && p.Role != "chat") {
			continue
		}
		for _, b := range harnessKinds["noo"] {
			if b == p.Backend {
				return p, true
			}
		}
	}
	return placement{}, false
}

// ChatModel is one running chat placement's backend and model.
type ChatModel struct{ Backend, Model string }

// chatModelsOf is every RUNNING chat placement on a chat engine, in desired
// order: chatPlacementOf's first and the ones after it.
func chatModelsOf(all []placement) []ChatModel {
	var out []ChatModel
	for _, p := range all {
		if p.Backend == "harness" || p.DesiredState != "running" || (p.Role != "" && p.Role != "chat") {
			continue
		}
		if slices.Contains(harnessKinds["noo"], p.Backend) {
			out = append(out, ChatModel{p.Backend, p.Model})
		}
	}
	return out
}

// ChatModels is every running chat placement's backend and model: the
// controller's harness fit takes the smallest window across all of them,
// so each one's context ceiling is reported (i285).
func (r *Reconciler) ChatModels() []ChatModel {
	r.harnessMu.RLock()
	defer r.harnessMu.RUnlock()
	return slices.Clone(r.chatModels)
}

// recordChatPlacement remembers the desired chat placement for ChatPlacement.
func (r *Reconciler) recordChatPlacement(all []placement) {
	p, ok := chatPlacementOf(all)
	models := chatModelsOf(all)
	r.harnessMu.Lock()
	defer r.harnessMu.Unlock()
	r.chatModels = models
	if !ok {
		r.chatDesired = nil
		r.chatOllamaEnv = nil
		return
	}
	r.chatDesired = &p
	r.chatOllamaEnv = nil
	if p.Backend == "ollama" {
		r.chatOllamaEnv = map[string]string{}
		for k, v := range p.Env {
			r.chatOllamaEnv[k] = v
		}
		if rows := runningOllama(all); len(rows) > 1 {
			r.chatOllamaEnv, _ = mergeOllamaEnv(rows)
		}
	}
}

// ChatContextWindow is the context window, in tokens, that the node's chat
// backend runs with as far as the agent sets it, for GET /harness/placement
// (`model_context`): the harness tells a foreign CLI its model's real window
// (noomesh-internal i147). Today that is Ollama's OLLAMA_CONTEXT_LENGTH: the
// placement's own value, else the profile's context default the agent
// injects. 0 = not known (another backend, or nothing sets it).
func (r *Reconciler) ChatContextWindow(prof *harnessprofile.Profile) int {
	r.harnessMu.RLock()
	defer r.harnessMu.RUnlock()
	return ollamaContextOf(r.chatOllamaEnv, prof)
}

// ollamaContextOf is the OLLAMA_CONTEXT_LENGTH an ollama with env runs
// with: its own value, else the profile's default; 0 when neither is a
// positive whole number or env is nil (chat is not on ollama).
func ollamaContextOf(env map[string]string, prof *harnessprofile.Profile) int {
	if env == nil {
		return 0
	}
	v := strings.TrimSpace(env[ollamaContextKey])
	if v == "" {
		v = profileOllamaContext(env, prof)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// ChatPlacement is the desired chat placement's backend and model, for
// POST /bench. ok=false when the controller places no running chat model.
func (r *Reconciler) ChatPlacement() (backend, model string, ok bool) {
	r.harnessMu.RLock()
	defer r.harnessMu.RUnlock()
	if r.chatDesired == nil {
		return "", "", false
	}
	return r.chatDesired.Backend, r.chatDesired.Model, true
}
