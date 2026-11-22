// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// An agent refuses calls addressed to another node (i1174).
//
// The gateway names the node every call is meant for in TargetNodeHeader.
// This agent answers only calls that name ITSELF: a call naming another node
// is refused with 421 Misdirected Request and {"code":"wrong_node"}, whoever
// sent it. The refusal is recorded for the heartbeat (verify's
// `target-node check` row on this node) only when the controller sent it: a
// misaddressed controller call is a controller or routing problem. A peer's
// misaddressed call (a node or service leaf) is refused and logged, once per
// caller per misaddressedWindow, and reported against the CALLER
// (MisaddressedFromField), never as this node's failure.
//
// A call that names no node is accepted while the controller has not said
// otherwise. The controller turns strictness on PER NODE through the
// authenticated desired-config it already serves (`require_target_node`),
// and only once this agent reported it checks the header
// (ChecksTargetNodeField on every heartbeat). From then on a controller call
// (the gateway's leaf) with no header is refused too. An older controller
// sends no field, which reads as false: the agent goes tolerant again, so a
// one-step-back controller keeps working, and a controller-first roll never
// strands a node that has not upgraded yet.
//
// Only the HTTPS listener is wrapped. The node-held tunnel and the bus
// reach this agent by its own node id (the controller picks the tunnel or
// the subject by node), so nothing on them is addressed to another node.
// GET /health and GET /metrics stay open to a header-less caller: they
// change nothing, and the controller's startup probe and the scraper read
// them.

// TargetNodeHeader names the node a call is meant for.
const TargetNodeHeader = "X-Noo-Node"

// ChecksTargetNodeField is the heartbeat field saying this agent checks
// TargetNodeHeader.
const ChecksTargetNodeField = "checks_target_node"

// RequiresTargetNodeField is the heartbeat field saying whether this agent
// refuses a header-less controller call right now (the desired-config flag
// it last applied).
const RequiresTargetNodeField = "requires_target_node"

// WrongNodeCode is the refusal's machine-readable code.
const WrongNodeCode = "wrong_node"

// startsStrict is the flag before the first desired-config read: tolerant
// until told. The HTTPS listener comes up first in the agent's start
// (agent.Run step 1), then registration (step 3), the tunnel and the
// heartbeat (step 4), and only then the reconcile loop's first fetch (step
// 4b), which applies `require_target_node`. In that window the controller
// can already call this agent: after an agent restart its record (and the
// address book entry) outlive the restart, so routed inference
// (`/v1/chat/completions`) and the per-node polls (`GET /gpu`) arrive before
// the first fetch. Tolerant is the safe direction for that window: a call
// whose X-Noo-Node names ANOTHER node is refused from the first second
// regardless of this flag; only a header-LESS controller call is accepted
// until the first fetch, which is what an older controller sends anyway.
// Starting strict instead would refuse an older controller's every call
// until the fetch told the agent otherwise.
const startsStrict = false

var requireTargetNode atomic.Bool

func init() { requireTargetNode.Store(startsStrict) }

// WrongNodeRefusedField is the heartbeat field carrying the latest refusal
// (LastWrongNode), for verify's `target-node check` row.
const WrongNodeRefusedField = "wrong_node_refused"

// wrongNodeReportFor is how long a refusal is reported after it happened.
const wrongNodeReportFor = 10 * time.Minute

type wrongNodeRefusal struct {
	target, path, detail string
	at                   time.Time
}

var lastWrongNode atomic.Pointer[wrongNodeRefusal]

// noteWrongNode keeps the refusal for the heartbeat.
func noteWrongNode(r *http.Request, why string) {
	lastWrongNode.Store(&wrongNodeRefusal{
		target: strings.TrimSpace(r.Header.Get(TargetNodeHeader)),
		path:   r.URL.Path,
		detail: why,
		at:     time.Now(),
	})
}

// LastWrongNode is the latest refusal within wrongNodeReportFor, as the
// heartbeat's WrongNodeRefusedField ({target, path, detail, at}; target ""
// for a header-less controller call), or nil when there was none.
func LastWrongNode() map[string]any {
	w := lastWrongNode.Load()
	if w == nil || time.Since(w.at) > wrongNodeReportFor {
		return nil
	}
	return map[string]any{"target": w.target, "path": w.path, "detail": w.detail, "at": w.at.Unix()}
}

// MisaddressedFromField is the heartbeat field listing the peers (not the
// controller) whose calls this agent refused as addressed to another node in
// the last misaddressedWindow: [{caller, count, last_at}]. It is this node's
// report on the caller, for an operator alert on the caller.
const MisaddressedFromField = "misaddressed_from"

// misaddressedWindow is both the log rate limit (one line per caller per
// window) and how long a caller stays in MisaddressedFromField.
const misaddressedWindow = 10 * time.Minute

// misaddressedCallersMax bounds the callers tracked; the one seen longest ago
// is evicted first.
const misaddressedCallersMax = 64

type misaddressedCaller struct {
	count        int // calls since the last log line
	logged, last time.Time
}

var (
	misaddressedMu sync.Mutex
	misaddressed   = map[string]*misaddressedCaller{}
	// Seams for the tests: the clock and the log line.
	misaddressedNow = time.Now
	misaddressedLog = func(caller, target, path string, earlier int) {
		slog.Warn("misaddressed_call_refused", "caller", caller, "target", target, "path", path,
			"earlier_calls", earlier, "note", "a peer's call naming another node; logged once per caller per 10m")
	}
)

// callerName is the verified leaf's common name (a node id or a service
// name), never more of the certificate.
func callerName(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "unknown"
	}
	cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
	if cn == "" {
		return "unknown"
	}
	if len(cn) > 64 {
		cn = cn[:64]
	}
	return cn
}

// noteMisaddressed counts a peer's misaddressed call and logs it at most
// once per caller per misaddressedWindow.
func noteMisaddressed(caller string, r *http.Request) {
	now := misaddressedNow()
	misaddressedMu.Lock()
	e := misaddressed[caller]
	if e == nil {
		if len(misaddressed) >= misaddressedCallersMax {
			oldest := ""
			for k, v := range misaddressed {
				if oldest == "" || v.last.Before(misaddressed[oldest].last) {
					oldest = k
				}
			}
			delete(misaddressed, oldest)
		}
		e = &misaddressedCaller{}
		misaddressed[caller] = e
	}
	e.last = now
	logIt := true
	earlier := e.count
	if logIt {
		e.logged, e.count = now, 1
	} else {
		e.count++
	}
	misaddressedMu.Unlock()
	if logIt {
		misaddressedLog(caller, strings.TrimSpace(r.Header.Get(TargetNodeHeader)), r.URL.Path, earlier)
	}
}

// MisaddressedFrom is the heartbeat's MisaddressedFromField: the callers
// refused within misaddressedWindow, the latest first, or nil when there
// were none.
func MisaddressedFrom() []map[string]any {
	now := misaddressedNow()
	misaddressedMu.Lock()
	defer misaddressedMu.Unlock()
	var out []map[string]any
	for caller, e := range misaddressed {
		if now.Sub(e.last) <= misaddressedWindow {
			out = append(out, map[string]any{"caller": caller, "count": e.count, "last_at": e.last.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["last_at"].(int64) > out[j]["last_at"].(int64) })
	return out
}

// SetRequireTargetNode applies desired-config's `require_target_node`
// (absent = false).
func SetRequireTargetNode(v bool) {
	if requireTargetNode.Swap(v) != v {
		slog.Info("target_node_strictness", "require_target_node", v)
	}
}

// RequiresTargetNode reports whether a header-less controller call is
// refused now.
func RequiresTargetNode() bool { return requireTargetNode.Load() }

// TargetNode wraps the agent's HTTPS listener with the target check.
func TargetNode(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if why := TargetNodeRefusal(cfg, r); why != "" {
				if r.TLS != nil && isController(r.TLS.PeerCertificates) {
					slog.Warn("wrong_node", "path", r.URL.Path, "target", r.Header.Get(TargetNodeHeader), "detail", why)
					noteWrongNode(r, why)
				} else {
					noteMisaddressed(callerName(r), r)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusMisdirectedRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": WrongNodeCode, "detail": why})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TargetNodeRefusal is why the call is refused, or "" when it is not.
func TargetNodeRefusal(cfg *config.Config, r *http.Request) string {
	self := ""
	if cfg != nil {
		self = strings.TrimSpace(cfg.NodeID)
	}
	if want := strings.TrimSpace(r.Header.Get(TargetNodeHeader)); want != "" {
		if self != "" && !strings.EqualFold(want, self) {
			return "this call is addressed to node " + want + "; this agent is " + self
		}
		return ""
	}
	if !RequiresTargetNode() || targetNodeExempt(r) {
		return ""
	}
	if r.TLS != nil && isController(r.TLS.PeerCertificates) {
		return "a controller call must name the node it is meant for (" + TargetNodeHeader + ")"
	}
	return ""
}

func targetNodeExempt(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/health" || r.URL.Path == "/metrics")
}
