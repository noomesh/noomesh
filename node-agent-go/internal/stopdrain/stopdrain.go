// Package stopdrain lets the node agent stop without cutting answers that
// a caller is already reading (option B of the 0.6.26 roll's chat 502,
// 2026-11-17T17:01:09Z; the gateway half is noomesh#1294).
//
// On SIGTERM the agent drains before it exits:
//   - streams this node's controller marked `X-Noo-Resend: whole` are cut
//     at once: the gateway re-sends them whole, nothing of them has reached
//     a caller;
//   - every other inference stream (a caller is reading its bytes) may
//     finish, up to Bound;
//   - a NEW inference call is refused with 503 node_restarting and a
//     Retry-After covering the rest of the drain and the restart, but only
//     when the controller advertised it understands that answer
//     (desired-config gateway_features). Otherwise a new call is served as
//     before the drain existed: an older gateway would read the refusal as
//     a final error.
//
// The marker is honoured only from the controller: a verified controller
// leaf on the mTLS control API, or a stream over this node's own tunnel.
// From anyone else it is ignored (the stream is drained) and it is never
// passed on to the backend.
package stopdrain

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Bound is the longest a stop waits for streams a caller is reading:
	// above p99 (13.9 s) and short of the longest seen (40.2 s) of the
	// fleet's streamed answers (7 days to 2026-11-17, 33,041 streamed).
	// The unit's TimeoutStopSec is this plus 20 s
	// (cmd/node-agent TestUnitStopTimeoutOutlastsTheDrain), so systemd's
	// SIGKILL never lands inside the drain.
	Bound = 30 * time.Second
	// RestartAllowance is added to the remaining drain in Retry-After: the
	// agent's own restart (0.7-3.5 s on the 0.6.26 roll).
	RestartAllowance = 3 * time.Second
	// Code is the refusal's error code; Feature is the desired-config
	// gateway feature that allows it.
	Code    = "node_restarting"
	Feature = "node_restarting"
	// ResendHeader / ResendWhole: the controller's marker on a call it
	// re-sends whole if it is cut.
	ResendHeader = "X-Noo-Resend"
	ResendWhole  = "whole"
)

// RecordFile is the last drain's record in the agent's state dir; the next
// start reports it once in a heartbeat (heartbeat's last_stop) and removes it.
const RecordFile = "last-stop.json"

// Result is what a drain did, for the log and the next start's report.
type Result struct {
	// Drained: streams that finished on their own during the drain.
	Drained int `json:"drained"`
	// CutMarked: marked streams cut at once (re-sent by the gateway).
	CutMarked int `json:"cut_marked"`
	// CutAtBound: streams still open when Bound passed, cut.
	CutAtBound int `json:"cut_at_bound"`
	// OldestAgeSecs: the oldest stream cut at the bound, seconds old.
	OldestAgeSecs int     `json:"oldest_age_secs"`
	BoundHit      bool    `json:"bound_hit"`
	DrainSecs     float64 `json:"drain_secs"`
	At            string  `json:"at"`
	// AtUnix: when the stop began, seconds since the epoch: the roll keeps
	// only stops that happened during itself.
	AtUnix int64 `json:"at_unix"`
}

type stream struct {
	marked  bool
	cancel  context.CancelFunc
	started time.Time
}

// Gate tracks this agent's inference streams and drains them on stop.
type Gate struct {
	isController func(*http.Request) bool
	now          func() time.Time
	feature      atomic.Bool

	mu        sync.Mutex
	draining  bool
	drainEnds time.Time
	next      uint64
	live      map[uint64]*stream
}

// New makes a gate. isController says whether a request is the verified
// controller (the only source whose marker counts).
func New(isController func(*http.Request) bool) *Gate {
	return &Gate{isController: isController, now: time.Now, live: map[uint64]*stream{}}
}

// SetFeatures takes the controller's gateway_features (desired-config).
// nil or absent (an older gateway): new calls are never refused.
func (g *Gate) SetFeatures(features []string) {
	g.feature.Store(slices.Contains(features, Feature))
}

// Wrap guards an inference handler.
func (g *Gate) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marked := r.Header.Get(ResendHeader) == ResendWhole && g.isController(r)
		r.Header.Del(ResendHeader)
		g.mu.Lock()
		if g.draining {
			ends := g.drainEnds
			g.mu.Unlock()
			if g.feature.Load() {
				refuse(w, ends.Sub(g.now())+RestartAllowance)
				return
			}
			// The controller cannot read the refusal: serve it as before the
			// drain existed (it ends with the process, as every call did).
			h.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		id := g.next
		g.next++
		g.live[id] = &stream{marked: marked, cancel: cancel, started: g.now()}
		g.mu.Unlock()
		defer func() {
			g.mu.Lock()
			delete(g.live, id)
			g.mu.Unlock()
			cancel()
		}()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func refuse(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", itoa(secs))
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code":    Code,
		"message": "this node's agent is restarting; send the request again after Retry-After",
	}})
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Drain starts the stop: cuts the marked streams, waits for the rest up to
// bound (polling every step), cuts what is left, and says what it did.
func (g *Gate) Drain(bound, step time.Duration) Result {
	start := g.now()
	g.mu.Lock()
	g.draining = true
	g.drainEnds = start.Add(bound)
	res := Result{At: start.UTC().Format(time.RFC3339), AtUnix: start.Unix()}
	waiting := 0
	for _, s := range g.live {
		if s.marked {
			s.cancel()
			res.CutMarked++
		} else {
			waiting++
		}
	}
	g.mu.Unlock()
	for {
		g.mu.Lock()
		open := 0
		for _, s := range g.live {
			if !s.marked {
				open++
			}
		}
		if open == 0 {
			g.mu.Unlock()
			res.Drained = waiting
			break
		}
		if !g.now().Before(g.drainEnds) {
			res.BoundHit = true
			res.CutAtBound = open
			res.Drained = waiting - open
			for _, s := range g.live {
				if !s.marked {
					if age := int(g.now().Sub(s.started).Seconds()); age > res.OldestAgeSecs {
						res.OldestAgeSecs = age
					}
					s.cancel()
				}
			}
			g.mu.Unlock()
			break
		}
		g.mu.Unlock()
		time.Sleep(step)
	}
	res.DrainSecs = math.Round(g.now().Sub(start).Seconds()*10) / 10
	return res
}
