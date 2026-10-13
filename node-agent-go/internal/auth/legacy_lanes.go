// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Legacy credential lanes on the node side, OBSERVED.
//
// Nothing here refuses anything. It counts two admissions that are kept
// only until a week of evidence says nobody uses them:
//
//   - LaneStaticToken: a request admitted by the static NOO_NODE_AGENT_TOKEN
//     rather than the HMAC cluster token. The token carries no name; the
//     leaf beside it is the only identity.
//   - LaneWhoisNonController: GET /tailnet/whois served to a caller whose
//     leaf is NOT the controller's (a peer node, or no leaf at all). The
//     route is authMW-gated only, so any fleet-secret holder reaches it.
//
// The counts ride every heartbeat as `legacy_lanes` (see Snapshot) and are
// exposed on this agent's /metrics as noo_node_legacy_lane_uses_total. The
// controller's `noo cluster verify --controller` reads the heartbeat copy.
const (
	LaneStaticToken         = "static_token"
	LaneWhoisNonController  = "whois_non_controller"
	legacyLaneLogEvery      = time.Hour
	legacyLaneLogMaxEntries = 256
)

var (
	laneStaticToken        atomic.Uint64
	laneWhoisNonController atomic.Uint64
	lanesSince             = time.Now()

	laneLogMu   sync.Mutex
	laneLogSeen = map[string]time.Time{}
)

// LegacyLaneSnapshot is the heartbeat's `legacy_lanes`: each lane's count
// since this process started, and when that was. Every lane is ALWAYS
// present, including at zero — absence is what an agent too old to report
// looks like, and the verify row must not read that as "0 uses".
func LegacyLaneSnapshot() map[string]any {
	return map[string]any{
		"since_unix":           lanesSince.Unix(),
		LaneStaticToken:        laneStaticToken.Load(),
		LaneWhoisNonController: laneWhoisNonController.Load(),
	}
}

// LegacyLaneCounts is the same numbers for /metrics.
func LegacyLaneCounts() map[string]uint64 {
	return map[string]uint64{
		LaneStaticToken:        laneStaticToken.Load(),
		LaneWhoisNonController: laneWhoisNonController.Load(),
	}
}

// laneLogDue is true at most once per legacyLaneLogEvery per key. The key
// is a lane plus a certificate CN — the CA issued those, so the space is
// the fleet's size, and the map is cleared past a hard cap regardless.
func laneLogDue(key string) bool {
	laneLogMu.Lock()
	defer laneLogMu.Unlock()
	now := time.Now()
	if len(laneLogSeen) > legacyLaneLogMaxEntries {
		laneLogSeen = map[string]time.Time{}
	}
	if last, ok := laneLogSeen[key]; ok && now.Sub(last) < legacyLaneLogEvery {
		return false
	}
	laneLogSeen[key] = now
	return true
}

// noteStaticToken counts one admission by the static token. The principal
// is the one serveAs is about to attach; its leaf is the caller's name.
func noteStaticToken(p Principal, r *http.Request) {
	laneStaticToken.Add(1)
	if laneLogDue(LaneStaticToken + "|" + p.CertCN) {
		slog.Info("node agent: legacy lane — request admitted by the static NOO_NODE_AGENT_TOKEN "+
			"(once per caller per hour, the count rides the heartbeat as legacy_lanes)",
			"path", r.URL.Path,
			"cert_cn", p.CertCN,
			"cert_org", p.CertOrg,
			"controller", p.Controller,
		)
	}
}

// CountNonControllerWhois wraps GET /tailnet/whois (INSIDE Middleware, like
// ControllerOnly) and counts every request it serves to a caller that is not
// the controller. It never refuses: this is the evidence for putting the
// route behind ControllerOnly, not the change itself.
func CountNonControllerWhois(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := FromContext(r.Context()); !ok || !p.Controller {
			laneWhoisNonController.Add(1)
			if laneLogDue(LaneWhoisNonController + "|" + p.CertCN) {
				slog.Warn("node agent: legacy lane — /tailnet/whois served to a caller that is not the controller "+
					"",
					"cert_cn", p.CertCN,
					"cert_org", p.CertOrg,
					"actor", p.Actor,
				)
			}
		}
		next.ServeHTTP(w, r)
	})
}
