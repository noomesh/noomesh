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
// It counts one admission that is kept only until a week of evidence says
// nobody uses it, and one refusal:
//
//   - LaneStaticToken: a request admitted by the static NOO_NODE_AGENT_TOKEN
//     rather than the HMAC cluster token. The token carries no name; the
//     leaf beside it is the only identity.
//   - LaneHMACv1Refused: a v1 cluster token refused (the v1 admission lane
//     and the NOO_CLUSTER_TOKEN_V1 gate are deleted), so a stale caller is
//     visible for one release.
//
// (`whois_non_controller` is gone from the shape: it was a constant 0 once
// GET /tailnet/whois went behind ControllerOnly, reported as if measured.)
//
// The counts ride every heartbeat as `legacy_lanes` (see Snapshot) and are
// exposed on this agent's /metrics as noo_node_legacy_lane_uses_total. The
// controller's `noo cluster verify --controller` reads the heartbeat copy.
const (
	LaneStaticToken = "static_token"
	// LaneHMACv1Refused: a v1 cluster token (HMAC over actor and time only,
	// not bound to the request, replayable for the window) REFUSED. A caller
	// whose calls all fail until it signs v2.
	LaneHMACv1Refused       = "cluster_hmac_v1_refused"
	legacyLaneLogEvery      = time.Hour
	legacyLaneLogMaxEntries = 256
)

var (
	laneStaticToken   atomic.Uint64
	laneHMACv1Refused atomic.Uint64
	lanesSince        = time.Now()

	laneLogMu   sync.Mutex
	laneLogSeen = map[string]time.Time{}
)

// LegacyLaneSnapshot is the heartbeat's `legacy_lanes`: each lane's count
// since this process started, and when that was. Every lane is ALWAYS
// present, including at zero — absence is what an agent too old to report
// looks like, and the verify row must not read that as "0 uses".
func LegacyLaneSnapshot() map[string]any {
	return map[string]any{
		"since_unix":      lanesSince.Unix(),
		LaneStaticToken:   laneStaticToken.Load(),
		LaneHMACv1Refused: laneHMACv1Refused.Load(),
	}
}

// LegacyLaneCounts is the same numbers for /metrics.
func LegacyLaneCounts() map[string]uint64 {
	return map[string]uint64{
		LaneStaticToken:   laneStaticToken.Load(),
		LaneHMACv1Refused: laneHMACv1Refused.Load(),
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

// noteHMACv1Refused counts one refused v1 cluster token, by caller, so a node
// that still signs v1 is visible.
func noteHMACv1Refused(actor string, r *http.Request) {
	laneHMACv1Refused.Add(1)
	if laneLogDue(LaneHMACv1Refused + "|" + actor) {
		slog.Warn("node agent: v1 cluster token REFUSED — the caller must upgrade",
			"actor", actor, "path", r.URL.Path)
	}
}
