// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// Who is allowed to command this node.
//
// # The problem
//
// Every route below /health is gated by a bearer token that is either the
// static NOO_NODE_AGENT_TOKEN or an HMAC signed with NOO_CLUSTER_SECRET.
// Both of those are FLEET secrets: every node holds them, because every
// node needs them to talk to the controller. The HMAC token names its
// caller, but that name is a claim signed with a key the caller shares
// with everyone else, so it proves nothing about which node sent it.
//
// The consequence is that one compromised node can drive the whole fleet:
// stop another node's backends, pull and start images on it, wipe its
// disk, restart its agent, and read any container's logs. Nothing in the
// mesh is meant to work that way — work flows controller → node, never
// node → node.
//
// # The fix
//
// The identity already exists and was never read on this rail: the cluster
// CA stamps a different Organization on each kind of leaf.
//
//	O="Mesh Cluster Gateway"  the gateway — the only service that mounts
//	                          gateway.crt
//	O="Mesh Cluster Node"     a node agent
//	O="Mesh Cluster Service"  a service leaf (the worker, trellion,
//	                          trellion-intel, evolve), a sidecar (exporters, Grafana, Loki — and
//	                          Prometheus, which reads GET /metrics with it
//	                          and reaches nothing else; see MetricsReader)
//
// A node cannot obtain a gateway leaf: issuing one needs the CA key, which
// lives on the controller. So the client certificate — not the token —
// answers "is this the controller?", and revocation stays the PKI's job.
// This mirrors what the gateway now does in the other direction
// (gateway-rust/src/node_identity.rs) and what the hostd manifest rail
// does for swap manifests (internal/hostd/manifest.go).
//
// # When it is enforced
//
// Only when this agent can actually identify its peers: TLS is on AND a
// cluster CA is configured, which is what makes the server ask for a
// client certificate in the first place (see config.TLSServerConfig).
// A plaintext agent — the local-executor path, a dev box — cannot tell
// callers apart, so it keeps its old behaviour and says so in the log
// rather than pretending to a guarantee it has no way to make.
//
// There is deliberately no flag. An operator who turns TLS on gets the
// restriction with it, because at that point the fleet has everything the
// check needs.

// controllerOrg is the leaf Organization the cluster CA stamps on the
// controller's own services. A node's leaf carries "Mesh Cluster Node" and
// must never satisfy this.
const controllerOrg = "Mesh Cluster Gateway"

// serviceOrg is the leaf Organization the cluster CA stamps on a SIDECAR —
// an exporter, Grafana, Loki, and (as) Prometheus. It is a
// strictly weaker principal than the controller: it opens exactly one route
// on this agent, GET /metrics, and nothing else.
//
// Before 96a, Prometheus scraped every node agent holding gateway.crt AND
// gateway.key, because that was the only leaf the scrape config named. So
// the monitoring container — a process whose whole job is to issue GETs at
// a metrics path — carried a credential that satisfied /start, /stop,
// /clean, /pull, /api/skills/run and /logs/{container} on every node in the
// fleet. The gateway key is the sole basis on which a node decides a caller
// is the controller; a copy of it in a service that does not command
// anything is a copy too many.
const serviceOrg = "Mesh Cluster Service"

// The node organization: what the cluster CA stamps on every node leaf
// (noo-cli/src/pki.rs: CN=<id>, O=Mesh Cluster Node). Read for ONE
// purpose — recognising this node's OWN certificate when it arrives over
// loopback, which is the harness. It never widens
// what a node may do to a peer: a node leaf from anywhere but 127.0.0.1,
// or naming any other node, stays a peer and is refused as before.
const nodeOrg = "Mesh Cluster Node"

// RetiredOrgOverrides are the env vars that once let an operator RENAME the
// three organizations above, for a PKI that predated the convention. Every
// leaf the cluster CA issues carries the fixed names (noo-cli/src/pki.rs),
// nothing in any template or compose file set them, and an override is the
// one knob that could widen "is this the controller?" to an org a node leaf
// also carries. So the orgs are hard-coded, and a value still set is a
// REFUSAL TO START naming the variable (RetiredOrgOverrideRefusal), never
// silently ignored.
var RetiredOrgOverrides = []string{
	"NOO_CONTROLLER_CERT_ORG",
	"NOO_SERVICE_CERT_ORG",
	"NOO_NODE_CERT_ORG",
}

// RetiredOrgOverrideRefusal is non-empty when any retired org override is
// set (non-blank) in the environment `getenv` reads; the agent exits on it.
func RetiredOrgOverrideRefusal(getenv func(string) string) string {
	var set []string
	for _, name := range RetiredOrgOverrides {
		if strings.TrimSpace(getenv(name)) != "" {
			set = append(set, name)
		}
	}
	if len(set) == 0 {
		return ""
	}
	return "retired certificate-organization override(s) set: " + strings.Join(set, ", ") +
		` — the node agent recognises only the organizations the cluster CA issues ("` +
		controllerOrg + `", "` + serviceOrg + `", "` + nodeOrg + `"). Remove the variable(s) and restart.`
}

// Principal is what the agent concluded about a caller.
type Principal struct {
	// Actor is the name the token claims. A claim, not a proof — kept for
	// logs so an operator can see who said what.
	Actor string
	// CertCN / CertOrg come from a client certificate the cluster CA
	// signed. Empty when none was presented.
	CertCN  string
	CertOrg string
	// Identified is true when this agent was in a position to tell callers
	// apart: TLS with a cluster CA, so the handshake asked for a cert.
	Identified bool
	// Controller is true only when a verified leaf carries the controller
	// organization.
	Controller bool
	// Service is true only when a verified leaf carries the SERVICE
	// organization — a sidecar. It is never implied by Controller: the two
	// orgs are disjoint, and the routes that accept a service say so by
	// accepting both explicitly (see MetricsReader).
	Service bool
	// OwnHarness is true only when a verified leaf is THIS node's own
	// certificate (node org, CN = this node's id) AND the connection came
	// over loopback. That is the harness the design runs beside this
	// agent, asking for a model. Nothing else satisfies both halves: a
	// peer node's leaf names a different id, and this node's leaf used from
	// another box is not on loopback.
	OwnHarness bool
	// Tunnel is true when Controller was established by the node's own
	// tunnel rather than by a TLS peer certificate.
	Tunnel bool
}

type principalKey struct{}

// FromContext returns the principal the middleware attached, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// isController reports whether a verified peer chain names the controller.
func isController(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	want := controllerOrg
	for _, o := range chain[0].Subject.Organization {
		if strings.EqualFold(strings.TrimSpace(o), want) {
			return true
		}
	}
	return false
}

// isService reports whether a verified peer chain names a sidecar.
func isService(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	want := serviceOrg
	for _, o := range chain[0].Subject.Organization {
		if strings.EqualFold(strings.TrimSpace(o), want) {
			return true
		}
	}
	return false
}

// classify builds the principal for a request that has already passed the
// token check.
//
// r.TLS.PeerCertificates is only populated for a chain the server VERIFIED
// against ClientCAs — Go rejects the handshake outright otherwise — so
// reaching here with a certificate means the cluster CA signed it.
func classify(cfg *config.Config, r *http.Request, actor string) Principal {
	p := Principal{Actor: actor, Identified: canIdentifyPeers(cfg, r)}
	if IsTunnelController(r) {
		// The controller, over this node's own authenticated tunnel: as if
		// the TLS leaf carried the controller organization. There is no
		// certificate on this request, and none is claimed.
		p.Identified = true
		p.Controller = true
		p.Tunnel = true
		return p
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		p.CertCN = leaf.Subject.CommonName
		p.CertOrg = strings.Join(leaf.Subject.Organization, ",")
		p.Controller = isController(r.TLS.PeerCertificates)
		p.Service = isService(r.TLS.PeerCertificates)
		p.OwnHarness = isOwnNode(cfg, r.TLS.PeerCertificates) && isLoopback(r.RemoteAddr)
	}
	return p
}

// isOwnNode reports whether a verified peer chain is THIS node's leaf:
// the node organization and this node's id as CN. A different id is a
// peer, however genuine its certificate.
func isOwnNode(cfg *config.Config, chain []*x509.Certificate) bool {
	if len(chain) == 0 || cfg == nil || strings.TrimSpace(cfg.NodeID) == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(chain[0].Subject.CommonName), strings.TrimSpace(cfg.NodeID)) {
		return false
	}
	want := nodeOrg
	for _, o := range chain[0].Subject.Organization {
		if strings.EqualFold(strings.TrimSpace(o), want) {
			return true
		}
	}
	return false
}

// isLoopback reports whether a request's RemoteAddr is this host talking
// to itself. Unparseable is false: an unknown origin is not loopback.
func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		host = strings.TrimSpace(remote)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// ControllerOrOwnHarness is ControllerOnly for the INFERENCE routes plus
// one more admitted caller: this node's own harness, over loopback, with
// this node's own certificate. The harness asks its
// own node for a model and never any other node — "same node only" is
// enforced here by identity (the leaf must be this node's) and by origin
// (the socket must be loopback), not by configuration. Everything a
// peer or an unidentified caller got from ControllerOnly, it still gets.
func ControllerOrOwnHarness(cfg *config.Config) func(http.Handler) http.Handler {
	ctrl := ControllerOnly(cfg)
	return func(next http.Handler) http.Handler {
		refuse := ctrl(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := FromContext(r.Context()); ok && p.Identified && p.OwnHarness {
				next.ServeHTTP(w, r)
				return
			}
			refuse.ServeHTTP(w, r)
		})
	}
}

// canIdentifyPeers reports whether this particular connection asked the
// caller for a certificate.
//
// Two things must hold. The connection has to be TLS, and a cluster CA has
// to be configured — that is exactly the condition under which
// config.TLSServerConfig sets ClientAuth, so a cert was requested and any
// cert that arrived was verified. Without a CA there is nothing to verify
// against and client auth stays off, so every caller looks alike and
// enforcing would only refuse the controller along with everyone else.
func canIdentifyPeers(cfg *config.Config, r *http.Request) bool {
	return r.TLS != nil && cfg.TLSCA != ""
}

// PeerIdentityEnforced reports whether THIS AGENT is configured to tell the
// controller from a peer at all, independent of any one request.
//
// canIdentifyPeers answers the same question per-connection, which is right
// for gating but useless to anyone else: the one place the answer surfaced
// was a warning line in the node's own journal, so a node quietly serving
// fleet-command routes to any holder of the shared fleet secret looked,
// from the controller, exactly like a node that is not. This is the same
// predicate minus the request, reported at registration and on every
// heartbeat.
//
// Since the control API became mTLS-only (config.TLSServerConfig refuses
// to start without all three files), a RUNNING agent always reports true.
// The predicate is kept rather than hardcoded so that an agent is never
// asserting a posture it did not compute — and `noo cluster verify` reads
// a false (an older agent still on the plaintext build) as a failure whose
// fix is to provision and upgrade the node.
func PeerIdentityEnforced(cfg *config.Config) bool {
	return cfg.TLSCert != "" && cfg.TLSKey != "" && cfg.TLSCA != ""
}

// ControllerOnly gates a route on the caller being the controller.
//
// Wrap it INSIDE Middleware — it reads the principal that one attaches:
//
//	s.mux.Handle("POST /start", authMW(auth.ControllerOnly(cfg)(h)))
func ControllerOnly(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				// Middleware did not run. Fail closed: a privileged route
				// with no principal is a wiring bug, and guessing here is
				// how a gate silently becomes decorative.
				http.Error(w, `{"detail":"node agent: no principal on this request"}`, http.StatusForbidden)
				return
			}
			if p.Controller {
				next.ServeHTTP(w, r)
				return
			}
			if !p.Identified {
				// Plaintext, or TLS with no cluster CA: this agent cannot
				// tell the controller from a peer.
				//
				// It used to SERVE here, with a rate-limited warning — so
				// the gate was decorative on exactly the nodes that needed
				// it, and the only trace was a line in the node's own
				// journal. Any holder of the fleet secret (that is: every
				// other node) could start, stop, pull, clean, run a skill
				// or read a container's logs on such a box.
				//
				// Now it refuses. A privileged route whose precondition is
				// missing is a 503 naming the missing config, not a
				// best-effort serve: the node is not broken, it is not
				// configured to make the guarantee this route needs.
				warnUnidentified(r)
				http.Error(w,
					`{"detail":"this node cannot identify its callers, so it will not serve `+
						`controller-only routes: set NOO_TLS_CA, NOO_TLS_CERT and NOO_TLS_KEY `+
						`on this agent (re-run host prep to install its PKI material)"}`,
					http.StatusServiceUnavailable)
				return
			}
			slog.Warn("node agent: refused a fleet-command route to a non-controller caller",
				"path", r.URL.Path,
				"actor", p.Actor,
				"cert_cn", p.CertCN,
				"cert_org", p.CertOrg,
			)
			http.Error(w,
				`{"detail":"this route is the controller's: the caller presented no client certificate carrying the controller organization"}`,
				http.StatusForbidden)
		})
	}
}

// One line a minute per path, not one per request — an inference proxy
// under load would otherwise bury the log it is trying to write.
var (
	warnMu   sync.Mutex
	warnSeen = map[string]time.Time{}
)

func warnUnidentified(r *http.Request) {
	warnMu.Lock()
	last, seen := warnSeen[r.URL.Path]
	now := time.Now()
	if seen && now.Sub(last) < time.Minute {
		warnMu.Unlock()
		return
	}
	warnSeen[r.URL.Path] = now
	warnMu.Unlock()
	slog.Error("node agent: REFUSING a fleet-command route — this listener has no TLS client "+
		"identity, so the controller cannot be told from a peer node "+
		"(set NOO_TLS_CA, NOO_TLS_CERT and NOO_TLS_KEY on this agent)",
		"path", r.URL.Path)
}

// MetricsScraperCN is the one service leaf MetricsReader admits: Prometheus's
// (`noo security pki issue-service prometheus`). Mirrors the gateway's
// METRICS_SCRAPER_SERVICE.
const MetricsScraperCN = "prometheus"

// MetricsReader gates a route on the caller being either the controller or
// the metrics scraper (a service leaf with CN=prometheus) — and is used for exactly one route, GET /metrics.
//
// # Why a second principal exists at all
//
// Every other privileged route on this agent is the controller's, and
// ControllerOnly says so. /metrics is different in one respect that matters:
// its caller is Prometheus, which is not the controller and has no business
// being able to impersonate it. Under ControllerOnly the only way to keep
// the scrape working is to hand the monitoring container gateway.key — which
// is what the fleet did, and what the design is about. The scrape then
// carried, in a process whose entire behaviour is "GET the URLs in my own
// config file", a credential good for /start, /stop, /clean, /pull,
// /api/skills/run and /logs/{container} on every node.
//
// So the fix is not to relax /metrics: it is to give Prometheus a leaf that
// opens /metrics and closes everything else. "Mesh Cluster Service" is that
// leaf, and this is the only middleware that accepts it.
//
// # What a service leaf can do here
//
// Read this node's Prometheus text: node id, load, GPU model/utilisation/
// memory/temperature/power, and backend state. No command verb, no logs, no
// container stats, no inference. Widening this set means widening it
// deliberately, at a second call site — which is the point of naming the
// principal rather than adding a boolean to ControllerOnly.
//
// Wrap it INSIDE Middleware, like ControllerOnly:
//
//	s.mux.Handle("GET /metrics", authMW(auth.MetricsReader(cfg)(h)))
func MetricsReader(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				// Same rule as ControllerOnly: a gated route with no
				// principal is a wiring bug, and serving on a guess is how
				// the gate stops being one.
				http.Error(w, `{"detail":"node agent: no principal on this request"}`, http.StatusForbidden)
				return
			}
			// A service leaf opens /metrics only when it is the SCRAPER's
			// (CN=prometheus, the gateway's METRICS_SCRAPER_SERVICE). Since
			// every node holds its own backend-door leaves (vllm, llamacpp,
			// ollama, tei, reranker — all O=Mesh Cluster Service), "any
			// service leaf" would let one compromised node read every other
			// node's metrics.
			if p.Controller || (p.Service && p.CertCN == MetricsScraperCN) {
				next.ServeHTTP(w, r)
				return
			}
			if !p.Identified {
				// This agent cannot tell a scraper from a peer node, so it
				// cannot make the guarantee this route now rests on. Refuse
				// and name the missing config, exactly as the fleet-command
				// routes do — a metrics route that quietly serves any holder
				// of the shared fleet secret is the decorative gate again,
				// just with a smaller blast radius.
				warnUnidentified(r)
				http.Error(w,
					`{"detail":"this node cannot identify its callers, so it will not serve `+
						`/metrics: set NOO_TLS_CA, NOO_TLS_CERT and NOO_TLS_KEY on this agent `+
						`(re-run host prep to install its PKI material)"}`,
					http.StatusServiceUnavailable)
				return
			}
			slog.Warn("node agent: refused /metrics to a caller that is neither the controller nor a cluster service",
				"path", r.URL.Path,
				"actor", p.Actor,
				"cert_cn", p.CertCN,
				"cert_org", p.CertOrg,
			)
			http.Error(w,
				`{"detail":"/metrics is for the controller and the cluster's monitoring service: the caller presented no client certificate carrying either organization"}`,
				http.StatusForbidden)
		})
	}
}
