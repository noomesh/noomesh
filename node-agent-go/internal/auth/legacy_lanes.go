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
//   - LaneWhoisNonController: RETIRED. GET /tailnet/whois is now behind
//     ControllerOnly, so a non-controller caller is refused rather than
//     counted. The key stays in the heartbeat shape at zero so a gateway or
//     `noo cluster verify` that expects it keeps reading a number.
//
// The counts ride every heartbeat as `legacy_lanes` (see Snapshot) and are
// exposed on this agent's /metrics as noo_node_legacy_lane_uses_total. The
// controller's `noo cluster verify --controller` reads the heartbeat copy.
const (
	LaneStaticToken        = "static_token"
	LaneWhoisNonController = "whois_non_controller"
	// LaneHMACv1: a request admitted on a v1 cluster token (HMAC over actor
	// and time only, not bound to the request, replayable for the window).
	LaneHMACv1 = "cluster_hmac_v1"
	// LaneHMACv1Refused: a v1 cluster token REFUSED because this node's
	// NOO_CLUSTER_TOKEN_V1=0 closed the gate. Counted apart from LaneHMACv1,
	// which is admissions only: a refusal is a caller whose calls all fail,
	// not a use of the lane.
	LaneHMACv1Refused       = "cluster_hmac_v1_refused"
	legacyLaneLogEvery      = time.Hour
	legacyLaneLogMaxEntries = 256
)

var (
	laneStaticToken        atomic.Uint64
	laneWhoisNonController atomic.Uint64
	laneHMACv1             atomic.Uint64
	laneHMACv1Refused      atomic.Uint64
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
		LaneHMACv1:             laneHMACv1.Load(),
		LaneHMACv1Refused:      laneHMACv1Refused.Load(),
	}
}

// LegacyLaneCounts is the same numbers for /metrics.
func LegacyLaneCounts() map[string]uint64 {
	return map[string]uint64{
		LaneStaticToken:        laneStaticToken.Load(),
		LaneWhoisNonController: laneWhoisNonController.Load(),
		LaneHMACv1:             laneHMACv1.Load(),
		LaneHMACv1Refused:      laneHMACv1Refused.Load(),
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

// noteHMACv1 counts one admission on a v1 cluster token, by caller.
func noteHMACv1(actor string, r *http.Request) {
	laneHMACv1.Add(1)
	if laneLogDue(LaneHMACv1 + "|" + actor) {
		slog.Info("node agent: legacy lane — request admitted on a v1 cluster token "+
			"(once per caller per hour; the count rides the heartbeat as legacy_lanes)",
			"actor", actor, "path", r.URL.Path)
	}
}

// noteHMACv1Refused is the closed-gate twin: counted under its own lane, so
// a caller that still signs v1 after the gate closed is visible without
// reading as an admission.
func noteHMACv1Refused(actor string, r *http.Request) {
	laneHMACv1Refused.Add(1)
	if laneLogDue(LaneHMACv1 + "|refused|" + actor) {
		slog.Warn("node agent: v1 cluster token REFUSED (NOO_CLUSTER_TOKEN_V1=0) — the caller must upgrade",
			"actor", actor, "path", r.URL.Path)
	}
}
