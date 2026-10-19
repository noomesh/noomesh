// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package auth provides HTTP middleware for node-agent authentication.
//
// Two modes, matching Python node_agent_auth.py:
//  1. NOO_NODE_AGENT_TOKEN → static bearer token (constant-time compare)
//  2. NOO_CLUSTER_SECRET   → HMAC cluster token verification
//
// At least one must be configured; requests are rejected 503 otherwise.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// Middleware returns an HTTP middleware that enforces node-agent auth.
func Middleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A stream the controller opened on this node's own tunnel has
			// already been authenticated by the tunnel handshake (see
			// tunnel.go); there is no bearer to check and none is needed.
			// Every other front door (ControllerLeafOrToken,
			// ServiceLeafOrToken, OwnHarnessLeafOrToken) falls through to this
			// function, so this is the one place the marker is read.
			if IsTunnelController(r) {
				serveAs(next, w, r, cfg, "")
				return
			}
			if !cfg.HasAuth() {
				http.Error(w, `{"detail":"Node agent auth not configured — set NOO_NODE_AGENT_TOKEN or NOO_CLUSTER_SECRET"}`, http.StatusServiceUnavailable)
				return
			}

			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"detail":"Missing node agent auth token"}`, http.StatusUnauthorized)
				return
			}
			token := auth[7:]

			// Mode 1: static bearer token (constant-time compare).
			// The token carries no name, so the actor is whatever the
			// certificate says — see principal.go.
			if cfg.NodeAgentToken != "" {
				if hmac.Equal([]byte(token), []byte(cfg.NodeAgentToken)) {
					// Counted, never refused: the
					// evidence for retiring this lane.
					noteStaticToken(classify(cfg, r, ""), r)
					serveAs(next, w, r, cfg, "")
					return
				}
			}

			// Mode 2: HMAC cluster token. The node id inside it is a claim
			// signed with a secret every node holds — recorded, never
			// trusted for authorization.
			if cfg.ClusterSecret != "" {
				valid, actor, refusal := checkClusterToken(token, cfg.ClusterSecret, r)
				if refusal != "" {
					http.Error(w, `{"detail":"`+refusal+`"}`, http.StatusForbidden)
					return
				}
				if valid {
					if IsCLIActor(actor) {
						// No CLI signs with the fleet secret any more (the
						// Python passthrough's `cli` fallback was removed,
						// and the Rust CLI never calls a node). A token
						// claiming to be one is a stale CLI or someone
						// spending the shared secret under its name.
						http.Error(w, `{"detail":"a CLI does not call node routes with the shared secret; use the noo CLI with your own login, through the controller"}`, http.StatusForbidden)
						return
					}
					serveAs(next, w, r, cfg, actor)
					return
				}
			}

			http.Error(w, `{"detail":"Invalid node agent auth token"}`, http.StatusForbidden)
		})
	}
}

// ServiceLeafOrToken admits a verified cluster SERVICE leaf with no bearer,
// and sends every other request through Middleware. It exists for /metrics
// and nothing else. The controller's leaf is admitted the
// same way.
//
// Prometheus authenticates by its leaf (CN=prometheus, O="Mesh Cluster
// Service"), not a token. Its scrape config used to send
// `${NOO_NODE_AGENT_TOKEN}` as a bearer, but Prometheus does not expand
// environment variables in its config, so the literal string arrived, the
// token check refused it, and this job never scraped. The leaf is the
// credential; MetricsReader, which wraps the handler, still decides what it
// may read.
//
// Only when this agent can identify peers at all (TLS with the cluster CA):
// without it no certificate was verified, so none is believed.
func ServiceLeafOrToken(cfg *config.Config) func(http.Handler) http.Handler {
	tokenMW := Middleware(cfg)
	return func(next http.Handler) http.Handler {
		viaToken := tokenMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsControllerLeafWithoutBearer(cfg, r) || (r.Header.Get("Authorization") == "" &&
				canIdentifyPeers(cfg, r) && r.TLS != nil && isService(r.TLS.PeerCertificates)) {
				serveAs(next, w, r, cfg, "")
				return
			}
			viaToken.ServeHTTP(w, r)
		})
	}
}

// ControllerLeafOrToken admits the CONTROLLER's verified leaf with no bearer,
// and sends every other request through Middleware.
//
// Every route the gateway calls here is wrapped in ControllerOnly (or
// ControllerOrOwnHarness), which serves only a caller whose verified leaf
// carries the controller organization. On those routes the bearer adds
// nothing: the token is a FLEET secret every node holds, so it never told
// the controller from a peer — the certificate did, and still does. The
// gateway nevertheless sent NOO_NODE_AGENT_TOKEN on every call (7,900 uses
// in 27 minutes on host8, mostly /gpu polls), which kept the static-token
// lane alive for no security it bought.
//
// So a request with NO Authorization header and the controller's leaf is
// served as the controller. Anything else — a bearer present (valid or
// not), no leaf, a node or service leaf — goes through Middleware exactly as
// before, so a stale token still 403s and an old gateway that keeps sending
// the static token is still counted. A peer node gains nothing: its leaf is
// not the controller's, and without a bearer Middleware refuses it.
//
// Only when this agent can identify peers at all (TLS with the cluster CA).
// The gateway learns that this agent accepts the leaf alone from the
// heartbeat (ControllerLeafOnly) and stops sending the bearer per node.
func ControllerLeafOrToken(cfg *config.Config) func(http.Handler) http.Handler {
	tokenMW := Middleware(cfg)
	return func(next http.Handler) http.Handler {
		viaToken := tokenMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsControllerLeafWithoutBearer(cfg, r) {
				serveAs(next, w, r, cfg, "")
				return
			}
			viaToken.ServeHTTP(w, r)
		})
	}
}

// IsControllerLeafWithoutBearer is the one condition ControllerLeafOrToken
// admits on: no Authorization header, an agent that verifies client
// certificates, and a verified leaf carrying the controller organization.
// /health reads it too, to give the controller its full detail.
func IsControllerLeafWithoutBearer(cfg *config.Config, r *http.Request) bool {
	return cfg != nil && r.Header.Get("Authorization") == "" && canIdentifyPeers(cfg, r) &&
		r.TLS != nil && isController(r.TLS.PeerCertificates)
}

// OwnHarnessLeafOrToken is ControllerLeafOrToken plus ONE more caller admitted
// with no bearer: this node's own harness, presenting this
// node's leaf over loopback. It wraps exactly the route the
// harness calls, POST /v1/chat/completions, and nothing else.
//
// The harness used to send NOO_NODE_AGENT_TOKEN beside its leaf. That token
// is a fleet secret; the leaf + loopback pair is what ControllerOrOwnHarness
// already decided on, so the bearer added nothing. The harness gets no
// heartbeat feed (the gateway's controller_leaf_only flag never reaches
// it), so it reads this capability from /health instead
// (OwnHarnessLeafOnlyField), sent only to the caller this door admits.
//
// A peer node's leaf, this node's leaf from off-box, a service leaf, or any
// request that carries a bearer goes through ControllerLeafOrToken exactly
// as before.
func OwnHarnessLeafOrToken(cfg *config.Config) func(http.Handler) http.Handler {
	ctrl := ControllerLeafOrToken(cfg)
	return func(next http.Handler) http.Handler {
		viaCtrl := ctrl(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsOwnHarnessLeafWithoutBearer(cfg, r) {
				serveAs(next, w, r, cfg, "")
				return
			}
			viaCtrl.ServeHTTP(w, r)
		})
	}
}

// IsOwnHarnessLeafWithoutBearer is the one condition OwnHarnessLeafOrToken
// adds: no Authorization header, an agent that verifies client
// certificates, THIS node's own leaf (node organization, CN = this node's
// id), and a loopback socket. /health reads it to tell the harness the door
// is open.
func IsOwnHarnessLeafWithoutBearer(cfg *config.Config, r *http.Request) bool {
	return cfg != nil && r.Header.Get("Authorization") == "" && canIdentifyPeers(cfg, r) &&
		r.TLS != nil && isOwnNode(cfg, r.TLS.PeerCertificates) && isLoopback(r.RemoteAddr)
}

// OwnHarnessLeafOnlyField is the /health field that tells this node's harness
// it may drop the bearer. The gateway binary's harness reads it
// (node_agent_auth::OWN_HARNESS_CAPABILITY); an agent too old to write it
// keeps receiving the bearer, so the two roll in either order.
const OwnHarnessLeafOnlyField = "own_harness_leaf_only"

// ControllerLeafOnly reports, on registration and every heartbeat, that this
// agent admits the controller's leaf without a bearer (ControllerLeafOrToken).
// The gateway stops sending NOO_NODE_AGENT_TOKEN to a node only once it says
// so; an agent too old to report it keeps receiving the bearer. Same
// predicate as PeerIdentityEnforced: the leaf is only believed when this
// agent verifies client certificates.
func ControllerLeafOnly(cfg *config.Config) bool {
	return PeerIdentityEnforced(cfg)
}

// HasValidToken reports whether a request carries a bearer this agent
// accepts, WITHOUT writing a response. For the one route that is public but
// should not say everything to everyone: /health answers a bare liveness
// shape to an anonymous caller and the full node detail to an authenticated
// one (api/handlers.go).
//
// It is deliberately not a middleware: a middleware that "attaches a
// principal but never refuses" is one refactor away from being mistaken for
// a gate.
func HasValidToken(cfg *config.Config, r *http.Request) bool {
	if cfg == nil || !cfg.HasAuth() {
		return false
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return false
	}
	token := authz[7:]
	if cfg.NodeAgentToken != "" && hmac.Equal([]byte(token), []byte(cfg.NodeAgentToken)) {
		return true
	}
	if cfg.ClusterSecret != "" {
		if ok, _, refusal := checkClusterToken(token, cfg.ClusterSecret, r); ok && refusal == "" {
			return true
		}
	}
	return false
}

// checkClusterToken is the one door for a bearer that might be a cluster
// token, v1 or v2. A v2 token is verified against THIS request (method,
// target, body) and its nonce is spent; a v1 token is accepted and counted
// (LaneHMACv1) until NOO_CLUSTER_TOKEN_V1=0 closes it, when it is refused with
// a reason that names the fix. refusal is non-empty only for an explained
// refusal; an ordinary bad token is (false, "", "").
func checkClusterToken(token, secret string, r *http.Request) (bool, string, string) {
	if IsV2Token(token) {
		body, err := bufferBody(r)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				return false, "", "request body too large to verify against a v2 cluster token"
			}
			return false, "", ""
		}
		ok, actor := verifyClusterTokenV2(token, secret, r, body)
		return ok, actor, ""
	}
	ok, actor := verifyClusterToken(token, secret)
	if !ok {
		return false, "", ""
	}
	if !V1Allowed() {
		noteHMACv1Refused(actor, r)
		return false, "", "v1 cluster tokens are refused here (NOO_CLUSTER_TOKEN_V1=0); upgrade the calling node so it signs v2 (`noo update`), or set NOO_CLUSTER_TOKEN_V1=1 on this node while the fleet rolls"
	}
	noteHMACv1(actor, r)
	return true, actor, ""
}

// verifyClusterToken verifies a v1 HMAC cluster token (not request-bound;
// see clustertoken_v2.go for the bound form).
//
// Token format: "<node_id>:<timestamp>:<hex_signature>"
// The signature is HMAC-SHA256 over "node_id:timestamp" with the cluster secret.
// Tokens older than 5 minutes are rejected.
func verifyClusterToken(token, secret string) (bool, string) {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		return false, ""
	}

	nodeID, tsStr, sigHex := parts[0], parts[1], parts[2]

	// Check timestamp freshness (5 min window)
	ts, err := parseTimestamp(tsStr)
	if err != nil {
		return false, ""
	}
	if time.Since(ts).Abs() > 5*time.Minute {
		return false, ""
	}

	// Verify HMAC signature
	message := fmt.Sprintf("%s:%s", nodeID, tsStr)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHex), []byte(expectedSig)) {
		return false, ""
	}

	return true, nodeID
}

// IsCLIActor reports whether an HMAC actor names the noo CLI: `cli` (the
// retired Python fallback) or `cli-<purpose>` (`cli-break-glass`,
// `cli-onboard`, `cli-posture`). None of them has any business on a node
// route; the node refuses them even with a valid signature.
func IsCLIActor(actor string) bool {
	return actor == "cli" || strings.HasPrefix(actor, "cli-")
}

// CreateClusterToken generates an HMAC cluster token for outbound requests.
//
// Matches Python cluster_auth.create_cluster_token().
func CreateClusterToken(nodeID, secret string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	message := fmt.Sprintf("%s:%s", nodeID, ts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s:%s:%s", nodeID, ts, sig)
}

func parseTimestamp(s string) (time.Time, error) {
	// Unix timestamp (seconds)
	var ts int64
	_, err := fmt.Sscanf(s, "%d", &ts)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}

// serveAs attaches the caller's principal and continues. Every route sees
// it; only the ones wrapped in ControllerOnly act on it.
func serveAs(next http.Handler, w http.ResponseWriter, r *http.Request, cfg *config.Config, actor string) {
	p := classify(cfg, r, actor)
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
}
