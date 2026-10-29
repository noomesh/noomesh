// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
)

// POST /bench measures this node's running CHAT model: how long it takes to
// answer at all (load_secs), how fast it reads a long prompt (prefill_tps)
// and how fast it writes (decode_tps). The controller folds the result into
// the node's harness profile (a measured first_byte_secs); the agent keeps
// the last result in memory and reports it on every heartbeat as
// `model_bench`.
//
// Controller-only (ctrlMW, the class of /restart and /gpu/hold): a bench
// occupies the GPU for up to benchBudget, so it is a command, not a read.

// ModelBench is the heartbeat's `model_bench` and the route's answer.
type ModelBench struct {
	Model        string  `json:"model"`
	Backend      string  `json:"backend"`
	LoadSecs     float64 `json:"load_secs"`
	PrefillTPS   float64 `json:"prefill_tps"`
	DecodeTPS    float64 `json:"decode_tps"`
	PromptTokens int     `json:"prompt_tokens"`
	At           string  `json:"at"`
}

// ChatPlacement is the chat placement the controller asks this node to run.
type ChatPlacement struct {
	Backend string
	Model   string
}

// benchBudget bounds the whole bench (both requests).
const benchBudget = 600 * time.Second

// benchPromptChars is the synthetic prompt's size: ~8192 tokens at the
// chars/4 estimate used when the backend does not report usage.
const benchPromptChars = 8192 * 4

// benchTarget is how the bench reaches the chat backend.
type benchTarget struct {
	backend string // backend type (ollama, vllm, llamacpp, ...)
	model   string // the placement's model: what the controller compares
	served  string // the name the backend serves, sent as `model`
	url     string // the backend's /v1/chat/completions
	client  *http.Client
}

var (
	errNoChatBackend = errors.New("no chat backend")
	errBenchBusy     = errors.New("a bench is already running on this node")
)

// SetChatPlacements installs the provider of every running chat placement
// (ChatModelStats).
func (s *Server) SetChatPlacements(f func() []ChatPlacement) { s.chatPlacements = f }

// SetChatPlacement installs the provider of the node's desired chat
// placement (the reconciler's last desired-config). nil = none, and
// POST /bench answers 409.
func (s *Server) SetChatPlacement(f func() (ChatPlacement, bool)) { s.chatPlacement = f }

// LastBench is the last completed bench, nil before one has run.
func (s *Server) LastBench() *ModelBench {
	s.benchMu.Lock()
	defer s.benchMu.Unlock()
	if s.benchLast == nil {
		return nil
	}
	cp := *s.benchLast
	return &cp
}

func (s *Server) benchClock() time.Time {
	if s.benchNow != nil {
		return s.benchNow()
	}
	return time.Now()
}

// handleBench runs one bench and answers it (200), or 409 when there is no
// running chat backend or a bench is already running, 504 when the budget ran
// out, 502 when the backend failed.
func (s *Server) handleBench(w http.ResponseWriter, r *http.Request) {
	s.benchMu.Lock()
	if s.benchRunning {
		s.benchMu.Unlock()
		jsonError(w, http.StatusConflict, "bench_busy", errBenchBusy.Error())
		return
	}
	s.benchRunning = true
	s.benchMu.Unlock()
	defer func() {
		s.benchMu.Lock()
		s.benchRunning = false
		s.benchMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), benchBudget)
	defer cancel()
	resolve := s.benchResolve
	if resolve == nil {
		resolve = s.resolveBenchTarget
	}
	t, err := resolve(ctx)
	if err != nil {
		jsonError(w, http.StatusConflict, "no_chat_backend", err.Error())
		return
	}
	b, err := s.runBench(ctx, t)
	if err != nil {
		status, code := http.StatusBadGateway, "bench_failed"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status, code = http.StatusGatewayTimeout, "bench_timeout"
		}
		slog.Warn("bench failed", "backend", t.backend, "model", t.model, "error", err)
		jsonError(w, status, code, err.Error())
		return
	}
	s.benchMu.Lock()
	s.benchLast = b
	s.benchMu.Unlock()
	slog.Info("bench done", "backend", b.Backend, "model", b.Model, "load_secs", b.LoadSecs,
		"prefill_tps", b.PrefillTPS, "decode_tps", b.DecodeTPS, "prompt_tokens", b.PromptTokens)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}

// resolveBenchTarget finds the running chat backend and dials it exactly as
// the inference proxy would (inferenceTarget, inferenceTransport): the same
// door, the same TLS and client certificate, the same bridge dialer. The
// response-header bound is the bench budget, not the proxy's first-byte
// bound: the bench measures what that bound should be, so it must not be cut
// off by it.
func (s *Server) resolveBenchTarget(ctx context.Context) (benchTarget, error) {
	if s.chatPlacement == nil {
		return benchTarget{}, fmt.Errorf("%w: this node has no chat placement", errNoChatBackend)
	}
	cp, ok := s.chatPlacement()
	if !ok {
		return benchTarget{}, fmt.Errorf("%w: this node has no running chat placement", errNoChatBackend)
	}
	running, native := s.runningAndNative(ctx)
	return s.chatTarget(ctx, cp, running, native)
}

// runningAndNative is every running backend (docker, then native ones docker
// does not run) with its served model, and the native ones alone.
func (s *Server) runningAndNative(ctx context.Context) (running, native map[string]string) {
	running = map[string]string{}
	if s.docker != nil {
		running = s.docker.RunningBackends(ctx)
	}
	native = s.nativeBackends(ctx)
	for b, m := range native {
		if _, taken := running[b]; !taken {
			running[b] = m
		}
	}
	return running, native
}

// chatTarget dials placement cp's backend, which must be running.
func (s *Server) chatTarget(ctx context.Context, cp ChatPlacement, running, native map[string]string) (benchTarget, error) {
	served, up := running[cp.Backend]
	if !up {
		return benchTarget{}, fmt.Errorf("%w: the chat placement's backend %s is not running", errNoChatBackend, cp.Backend)
	}
	port := dockerpkg.BackendPorts[cp.Backend]
	base, scheme := s.inferenceTarget(ctx, cp.Backend, port, native)
	if served == "" {
		served = cp.Model
	}
	return benchTarget{
		backend: cp.Backend,
		model:   cp.Model,
		served:  served,
		url:     strings.TrimRight(base, "/") + "/v1/chat/completions",
		client:  &http.Client{Transport: s.inferenceTransport(scheme, benchBudget)},
	}, nil
}

// streamResult is one streamed completion, timed.
type streamResult struct {
	start, first, end time.Time
	// tokenChunks counts chunks that carried output text: the completion
	// token count when the backend reports no usage.
	tokenChunks      int
	promptTokens     int
	completionTokens int
	usage            bool
}

// runBench: (a) a one-token completion, timed to its first token: load_secs,
// measured AS FOUND (a model already loaded gives a warm number; one that is
// not gives the cold load), then (b) a ~8192-token prompt with max_tokens 64.
func (s *Server) runBench(ctx context.Context, t benchTarget) (*ModelBench, error) {
	load, err := s.benchStream(ctx, t, "Reply with the single word OK.", 1)
	if err != nil {
		return nil, fmt.Errorf("load probe: %w", err)
	}
	prompt := benchPrompt(s.benchClock().UnixNano())
	long, err := s.benchStream(ctx, t, prompt, 64)
	if err != nil {
		return nil, fmt.Errorf("prefill/decode run: %w", err)
	}
	promptTokens := long.promptTokens
	if promptTokens <= 0 {
		// The backend reported no usage: estimate at chars/4.
		promptTokens = len(prompt) / 4
	}
	completion := long.completionTokens
	if completion <= 0 {
		completion = long.tokenChunks
	}
	prefill, decode := benchRates(promptTokens, completion, long.first.Sub(long.start), long.end.Sub(long.start))
	return &ModelBench{
		Model:        t.model,
		Backend:      t.backend,
		LoadSecs:     round2(load.first.Sub(load.start).Seconds()),
		PrefillTPS:   round2(prefill),
		DecodeTPS:    round2(decode),
		PromptTokens: promptTokens,
		At:           s.benchClock().UTC().Format(time.RFC3339),
	}, nil
}

// benchRates is the arithmetic: prefill = prompt tokens / time to first
// token; decode = the tokens after the first / the time after the first.
// A zero or negative interval gives 0, never Inf.
func benchRates(promptTokens, completionTokens int, ttft, total time.Duration) (prefill, decode float64) {
	if ttft > 0 {
		prefill = float64(promptTokens) / ttft.Seconds()
	}
	if after := total - ttft; after > 0 && completionTokens > 1 {
		decode = float64(completionTokens-1) / after.Seconds()
	}
	return prefill, decode
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// benchPrompt is the synthetic long prompt: deterministic text of
// benchPromptChars characters after one nonce line. The nonce leads the
// prompt so a backend's prefix cache (vLLM, llama.cpp, ollama) cannot answer
// a second bench from the first one's KV and report an impossible prefill.
func benchPrompt(nonce int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Benchmark run %d. Read the numbered notes below, then answer.\n", nonce)
	words := []string{"river", "lantern", "copper", "meadow", "signal", "harbor", "orchard", "granite", "violet", "compass", "thunder", "ledger"}
	for i := 0; b.Len() < benchPromptChars; i++ {
		fmt.Fprintf(&b, "Note %d: the %s near the %s keeps a %s beside the %s. ",
			i, words[i%12], words[(i*5+3)%12], words[(i*7+1)%12], words[(i*11+2)%12])
	}
	b.WriteString("\nIn one sentence, what do the notes describe?")
	return b.String()
}

// benchStream sends one streamed chat completion (OpenAI wire, which ollama
// serves on /v1 too) with usage requested, and times it. The body is the
// bench's own and is sent as is: the proxy's per-backend key filter would
// strip stream_options for ollama, and usage is what the token counts come
// from.
func (s *Server) benchStream(ctx context.Context, t benchTarget, prompt string, maxTokens int) (streamResult, error) {
	body, _ := json.Marshal(map[string]any{
		"model":          t.served,
		"messages":       []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens":     maxTokens,
		"temperature":    0,
		"stream":         true,
		"stream_options": map[string]any{"include_usage": true},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return streamResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-By", "noo-node-agent-bench")
	res := streamResult{start: s.benchClock()}
	resp, err := t.client.Do(req)
	if err != nil {
		return res, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return res, fmt.Errorf("backend answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					Reasoning        string `json:"reasoning"`
				} `json:"delta"`
				Text string `json:"text"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		for _, c := range chunk.Choices {
			if c.Delta.Content != "" || c.Delta.ReasoningContent != "" || c.Delta.Reasoning != "" || c.Text != "" {
				if res.first.IsZero() {
					res.first = s.benchClock()
				}
				res.tokenChunks++
				break
			}
		}
		if chunk.Usage != nil {
			res.usage = true
			res.promptTokens = chunk.Usage.PromptTokens
			res.completionTokens = chunk.Usage.CompletionTokens
		}
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	res.end = s.benchClock()
	if res.first.IsZero() {
		// No output text at all (max_tokens 1 spent on a role or an empty
		// token): the stream's end is the first byte we can time.
		res.first = res.end
	}
	return res, nil
}

// benchState is the Server's bench bookkeeping (embedded).
type benchState struct {
	benchMu      sync.Mutex
	benchRunning bool
	benchLast    *ModelBench
	// chatPlacement reports the desired chat placement (reconciler).
	chatPlacement func() (ChatPlacement, bool)
	// benchResolve overrides resolveBenchTarget (tests).
	benchResolve func(context.Context) (benchTarget, error)
	// windowResolve overrides resolveBenchTarget for liveChatContext (tests).
	windowResolve func(context.Context) (benchTarget, error)
	// benchNow overrides time.Now (tests).
	benchNow func() time.Time
	// chatPlacements reports every running chat placement (reconciler).
	chatPlacements func() []ChatPlacement
	// ceilings remembers each chat model's ceiling once found
	// (ChatModelStats), keyed by backend, model and served name.
	ceilingMu sync.Mutex
	ceilings  map[string]modelstats.ModelStat
	// ceilingTargets overrides the chat targets ChatModelStats reads (tests).
	ceilingTargets func(context.Context) []benchTarget
	// hfCacheDir overrides dockerpkg.HFCacheHost (tests).
	hfCacheDir func() string
}
