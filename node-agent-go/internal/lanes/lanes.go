// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package lanes derives the heartbeat's `lanes`: one entry per (backend,
// placed model) with a state, built from what the controller PLACED, what
// the model server HOLDS (modelpresence), and what the runtime is doing
// (running_backends, backend_containers, ollama /api/ps and /api/tags).
// Proposal i403 (noomesh-internal), Phase 1.
//
// The gateway used to route on the model string a backend self-reports in
// `running_backends`; an empty or stale string made a lane vanish. A lane
// names the PLACED model verbatim and says what state it is in, so the
// gateway never has to guess a model. `running_backends` is unchanged.
//
// The key is ALWAYS sent: `[]` means "no lanes", an absent key means an
// agent too old to report.
package lanes

import (
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

// Lane states. First match wins in Build; see the table in the PR.
const (
	StateServing  = "serving"
	StateOnDemand = "on_demand"
	StateLoading  = "loading"
	StateMissing  = "missing"
	StateUnplaced = "unplaced"
	StateUnknown  = "unknown"
)

// Reasons. The vocabulary is fixed; free text is allowed only after the
// colon of ReasonReconciling.
const (
	ReasonNone           = ""
	ReasonWarming        = "warming"
	ReasonStarting       = "starting"
	ReasonReconciling    = "reconciling: "
	ReasonNotOnDisk      = "not on disk"
	ReasonNoPresenceYet  = "no presence yet"
	ReasonNotLoaded      = "not loaded"
	ReasonUnnamedBackend = "unnamed backend"
)

// Lane is one entry of the heartbeat's `lanes`.
type Lane struct {
	Backend string `json:"backend"`
	Model   string `json:"model"`
	Role    string `json:"role"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
}

// Placed is one running placement, as the reconciler received it.
type Placed struct {
	Backend string
	Model   string
	Role    string
}

var (
	placedMu sync.Mutex
	placed   []Placed
)

// SetPlaced records the node's running placements (the reconciler calls it
// each pass with the controller's desired state). A package singleton for the
// reason modelpresence is one: producer (reconcile) and consumer (heartbeat)
// are wired at different points in startup.
func SetPlaced(ps []Placed) {
	placedMu.Lock()
	defer placedMu.Unlock()
	placed = append([]Placed(nil), ps...)
}

// PlacedNow is the last recorded set.
func PlacedNow() []Placed {
	placedMu.Lock()
	defer placedMu.Unlock()
	return append([]Placed(nil), placed...)
}

// Ollama is what the ollama server says. Known is false when neither
// /api/tags nor /api/ps could be read.
type Ollama struct {
	Known  bool
	OnDisk map[string]bool // /api/tags
	Loaded map[string]bool // /api/ps
	Held   map[string]bool // the agent's held set
}

// Inputs is everything Build reads. All of it is already in the heartbeat
// payload or the reconciler; Build does no I/O.
type Inputs struct {
	Placed []Placed
	// Presence is modelpresence.Report(): keys are "backend", "backend#role"
	// or "backend#embed@model"; matched here by (backend, model, role).
	Presence map[string]modelpresence.Entry
	// Running is `running_backends`; Runtimes is `backend_runtimes`
	// ("docker" | "native" | ...), nil when unreported.
	Running  map[string]string
	Runtimes map[string]string
	// Containers is `backend_containers`.
	Containers map[string]any
	Ollama     Ollama
}

// Same is the model comparison: exact equality after trimming whitespace.
func Same(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) }

func roleOf(r string) string {
	if r = strings.TrimSpace(r); r != "" {
		return r
	}
	return "chat"
}

// placeholders are the stand-ins docker.RunningBackends reports when a
// container names no model; they are not claims about a model.
var placeholders = map[string]string{"ollama": "ollama", "embedding": "tei", "harness": "auto"}

// runtimeModel is what running_backends says the backend runs, "" when it
// names none.
func runtimeModel(backend, m string) string {
	m = strings.TrimSpace(m)
	if m == placeholders[backend] {
		return ""
	}
	return m
}

func presenceFor(in Inputs, p Placed) (modelpresence.Entry, bool) {
	for k, e := range in.Presence {
		b, _, _ := strings.Cut(k, "#")
		if b == p.Backend && Same(e.Model, p.Model) && roleOf(e.Role) == roleOf(p.Role) {
			return e, true
		}
	}
	return modelpresence.Entry{}, false
}

// Build derives the lanes, plus the unplaced backends that name no model
// (no lane is emitted for those; the caller logs them via NoteUnnamed).
func Build(in Inputs) (lanes []Lane, unnamed []string) {
	lanes = []Lane{}
	placedBackends := map[string]bool{}
	seen := map[string]bool{}
	for _, p := range in.Placed {
		if p.Backend == "harness" || strings.TrimSpace(p.Model) == "" {
			continue
		}
		placedBackends[p.Backend] = true
		key := p.Backend + "\x00" + strings.TrimSpace(p.Model) + "\x00" + roleOf(p.Role)
		if seen[key] {
			continue
		}
		seen[key] = true
		state, reason := derive(in, p)
		lanes = append(lanes, Lane{Backend: p.Backend, Model: p.Model, Role: p.Role, State: state, Reason: reason})
	}
	var rest []string
	for b := range in.Running {
		if b != "harness" && !placedBackends[b] {
			rest = append(rest, b)
		}
	}
	sort.Strings(rest)
	for _, b := range rest {
		m := runtimeModel(b, in.Running[b])
		if m == "" {
			unnamed = append(unnamed, b)
			continue
		}
		role := ""
		switch b {
		case "embedding":
			role = "embed"
		case "reranker":
			role = "rerank"
		}
		lanes = append(lanes, Lane{Backend: b, Model: m, Role: role, State: StateUnplaced, Reason: ReasonNone})
	}
	return lanes, unnamed
}

func derive(in Inputs, p Placed) (string, string) {
	pres, havePres := presenceFor(in, p)
	// 1. The model server does not hold the placed model.
	if havePres && !pres.Present {
		return StateMissing, ReasonNotOnDisk
	}
	isOllama := p.Backend == "ollama"
	// A docker backend other than ollama (which hosts several models) runs
	// exactly one model, named by its env or args.
	runs := ""
	if !isOllama && in.Runtimes[p.Backend] == "docker" {
		runs = runtimeModel(p.Backend, in.Running[p.Backend])
	}
	// 2. The runtime runs a different model: the reconciler is replacing it.
	if runs != "" && !Same(runs, p.Model) {
		return StateLoading, ReasonReconciling + "runtime runs " + runs
	}
	life, _ := in.Containers[p.Backend].(map[string]any)
	health, _ := life["health"].(string)
	warmup, _ := life["warmup"].(string)
	servingOff := false
	if v, ok := life["serving"].(bool); ok && !v {
		servingOff = true
	}
	reason, _ := life["serving_reason"].(string)
	// 3. Starting or warming.
	if health == "starting" {
		return StateLoading, ReasonStarting
	}
	if warmup == "running" || (servingOff && strings.Contains(strings.ToLower(reason), "warm")) {
		return StateLoading, ReasonWarming
	}
	_, running := in.Running[p.Backend]
	// 4 and 5.
	if isOllama {
		if !running {
			return StateUnknown, ReasonNone
		}
		o := in.Ollama
		if o.Loaded[p.Model] || o.Loaded[strings.TrimSpace(p.Model)] {
			return StateServing, ReasonNone
		}
		onDisk := o.OnDisk[strings.TrimSpace(p.Model)] || o.Held[strings.TrimSpace(p.Model)] || (havePres && pres.Present)
		if onDisk {
			return StateOnDemand, ReasonNotLoaded
		}
		if !havePres {
			return StateUnknown, ReasonNoPresenceYet
		}
		return StateUnknown, ReasonNone
	}
	if runs != "" && life != nil && !servingOff && (health == "" || health == "healthy") {
		if r, _ := life["running"].(bool); r {
			return StateServing, ReasonNone
		}
	}
	return StateUnknown, ReasonNone
}

var (
	noteMu   sync.Mutex
	lastNote string
)

// NoteUnnamed logs the running backends that no placement explains and that
// name no model, once per change of the set (not every heartbeat).
func NoteUnnamed(unnamed []string) {
	key := strings.Join(unnamed, ",")
	noteMu.Lock()
	changed := key != lastNote
	lastNote = key
	noteMu.Unlock()
	if changed && key != "" {
		slog.Warn("lanes.unnamed_backend", "backends", unnamed, "reason", ReasonUnnamedBackend,
			"detail", "running with no placement and no model name; no lane is reported for it")
	}
}
