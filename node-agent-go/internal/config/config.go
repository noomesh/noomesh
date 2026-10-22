// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package config provides environment-based configuration for the node agent.
//
// All settings are read from environment variables at startup, matching the
// Python node_agent.py contract so either implementation can be swapped in.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Config holds all node-agent configuration derived from environment variables.
type Config struct {
	// Node identity
	NodeID   string
	Tier     int
	GPUModel string
	// SelfNode: this node runs on the controller's own device
	// (NOO_SELF_NODE=1, written by `noo cluster provision`). Advertised in
	// the heartbeat so the fleet views and every node verb can branch on
	// it without the operator having to know there is a difference.
	SelfNode bool
	VRAMGB   float64

	// Port the control API listens on. Configurable so a host can run more
	// than one agent — e.g. a tier-3 worker on 8081 alongside a tier-5
	// sensor companion on 8082, each with its own node identity and its own
	// blast radius (the sensor agent gets no Docker socket).
	//
	// Three things must agree on this value or a second agent is silently
	// broken: the listener, the -healthcheck subcommand, and the agent_url
	// reported to the gateway (which otherwise falls back to :8081 and
	// proxies sensor calls to the wrong process).
	AgentPort int

	// AgentBind is NODE_AGENT_BIND: where the control API listens. Empty =
	// the address the controller reaches this node on (NODE_IP, else the
	// source address of the route to the controller) plus loopback; `all`
	// (or 0.0.0.0) = every interface; otherwise a comma list of IPs. See
	// api.BindPlan.
	AgentBind string

	// Controller (gateway) connection
	ControllerURL     string
	HeartbeatInterval int // seconds

	// NATS messaging
	NATSURL string

	// Auth — read through Secret (secretenv.go): NAME_FILE, NOO_SECRET_NAME,
	// then NAME. One that cannot be resolved reads as unset here; agent.New
	// refuses to start on it first (CheckSecrets).
	NodeAgentToken string
	ClusterSecret  string

	// TLS / mTLS
	TLSCA   string // CA cert path
	TLSCert string // Node cert path
	TLSKey  string // Node key path
	// BackendTLSDowngradeAsked is the `NAME=value` of a per-backend TLS
	// flag (BackendTLSFlags) that asks for a plaintext backend door. Every
	// agent-started backend serves TLS with a required client certificate;
	// a line asking for less is a startup REFUSAL, never a silently ignored
	// one — see TLSServerConfig.
	BackendTLSDowngradeAsked string
	// MTLSDowngradeAsked is the raw NOO_MTLS_NODES value when it names the
	// retired downgrade (false/0/no/off), "" otherwise. The control API is
	// mTLS-only; a line asking for less is a startup REFUSAL, never a
	// silently ignored one — see TLSServerConfig.
	MTLSDowngradeAsked string

	// Node IP override (set by provisioner)
	NodeIP string

	// Compose project name used to scope container stats / listings to this
	// stack. Containers started by other compose projects on the same Docker
	// host (e.g. noo-meshsec) are excluded from the dashboard.
	ComposeProject string

	// Log shipping (fleet logging phase 3). LogShip is the operator's
	// switch: NOO_LOG_SHIP=0|false|no|off disables; anything else (and
	// unset) leaves it on — the agent still ships only when it has TLS
	// material, see LogShipEnabled. LogShipUnits overrides the journal
	// allowlist the agent asks hostd to follow (NOO_LOG_SHIP_UNITS,
	// comma-separated; hostd enforces its own allowlist regardless).
	LogShip bool
	// EmbedPull: claim bulk embedding jobs from the WORK_EMBED stream
	// (proposal i179). On by default; NOO_EMBED_PULL=0 turns the worker off.
	EmbedPull    bool
	LogShipUnits []string

	// StateDir is the agent's writable state directory (NOO_AGENT_STATE;
	// default /var/lib/noo-node-agent, the spool's parent). The shipper's
	// disk spill and tail offsets live under it.
	StateDir string
}

// LogShipEnabled reports whether the shipper should run: the operator has
// not switched it off AND this agent has a client certificate to present.
// Without TLS material the push would be refused at the door anyway; the
// heartbeat says why (`log_ship.last_error`).
func (c *Config) LogShipEnabled() (bool, string) {
	if !c.LogShip {
		return false, "disabled by NOO_LOG_SHIP"
	}
	if !c.HasTLS() {
		return false, "no TLS material (NOO_TLS_CERT/NOO_TLS_KEY) — nothing to present to the controller"
	}
	return true, ""
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	c := &Config{
		NodeID:            envOr("NODE_ID", "auto"),
		Tier:              envInt("NODE_TIER", 3),
		AgentPort:         envInt("NODE_AGENT_PORT", 8081),
		AgentBind:         strings.TrimSpace(os.Getenv("NODE_AGENT_BIND")),
		GPUModel:          os.Getenv("GPU_MODEL"),
		SelfNode:          envBool("NOO_SELF_NODE"),
		VRAMGB:            envFloat("VRAM_GB", 0.0),
		ControllerURL:     envOr("CONTROLLER_URL", "https://gateway:8080"),
		HeartbeatInterval: envInt("HEARTBEAT_INTERVAL", 30),
		NATSURL:           envOr("NATS_URL", "tls://nats:4222"),
		NodeAgentToken:    secretOrEmpty("NOO_NODE_AGENT_TOKEN"),
		ClusterSecret:     secretOrEmpty("NOO_CLUSTER_SECRET"),
		TLSCA:             os.Getenv("NOO_TLS_CA"),
		TLSCert:           os.Getenv("NOO_TLS_CERT"),
		TLSKey:            os.Getenv("NOO_TLS_KEY"),
		NodeIP:            os.Getenv("NODE_IP"),
		ComposeProject:    envOr("NOO_COMPOSE_PROJECT", "pai-assistant"),
		LogShip:           !envOff("NOO_LOG_SHIP"),
		EmbedPull:         !envOff("NOO_EMBED_PULL"),
		LogShipUnits:      envList("NOO_LOG_SHIP_UNITS"),
		StateDir:          envOr("NOO_AGENT_STATE", "/var/lib/noo-node-agent"),
	}

	c.MTLSDowngradeAsked = mtlsDowngradeAsked()
	c.BackendTLSDowngradeAsked = backendTLSDowngradeAsked()

	return c
}

// BackendTLSFlags is the ONE declaration of the per-backend TLS switches:
// backend key (the reconciler's / placement's name) → the env variable
// provision renders into /etc/noo-node-agent.env. The docker package reads
// this map for SchemeFor; the refusal below reads it for a downgrade.
//
// These variables no longer switch anything. Since 2026-09-29 every backend
// the agent starts serves TLS with a REQUIRED cluster-CA client certificate
// at the door a caller reaches — vLLM by its own listener (`--ssl-cert-reqs
// 2`), llama.cpp, ollama, TEI and the reranker behind a stunnel sidecar
// (`verify = 2`) the agent runs beside them. The one thing a flag can still
// do is refuse the start: a node whose env says NOO_LLAMACPP_TLS=false is a
// node someone once downgraded on purpose, and silently ignoring the line
// would hide that the downgrade no longer exists. Any other value (true, 1,
// empty, unset — provision renders them empty) is accepted and means
// nothing.
var BackendTLSFlags = map[string]string{
	"vllm":      "NOO_VLLM_TLS",
	"llamacpp":  "NOO_LLAMACPP_TLS",
	"ollama":    "NOO_OLLAMA_TLS",
	"embedding": "NOO_TEI_TLS",
	"reranker":  "NOO_RERANKER_TLS",
}

// backendTLSDowngradeAsked returns the first `NAME=value` among
// BackendTLSFlags whose value asks for plaintext (false/0/no/off), or "".
// Sorted so the refusal names the same line every start.
func backendTLSDowngradeAsked() string {
	names := make([]string, 0, len(BackendTLSFlags))
	for _, env := range BackendTLSFlags {
		names = append(names, env)
	}
	sort.Strings(names)
	for _, env := range names {
		raw := os.Getenv(env)
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "false", "0", "no", "off":
			return env + "=" + raw
		}
	}
	return ""
}

// mtlsDowngradeAsked reads NOO_MTLS_NODES for the RETIRED downgrade.
//
// History, because the variable has flipped meaning twice and a stale line
// in an env file outlives every one of them: it began as an opt-IN (unset
// meant tls.VerifyClientCertIfGiven, and the provisioning rail rendered it
// EMPTY, so the whole fleet ran the weak handshake while the docs said
// "true"). It then became an opt-OUT (#96): unset required a certificate,
// false/0/no/off restored "verify if given", and with no certificate at
// all the agent still served PLAINTEXT on :8081.
//
// Now there is nothing to opt out of. The control API is mTLS-only, and
// the one thing this variable can still do is refuse the start: a node
// whose env still says NOO_MTLS_NODES=false is a node someone once
// downgraded on purpose, and silently ignoring the line would hide that
// the downgrade no longer exists. Any other value (true, 1, empty, unset)
// is accepted and means nothing.
func mtlsDowngradeAsked() string {
	raw := os.Getenv("NOO_MTLS_NODES")
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "false", "0", "no", "off":
		return raw
	default:
		return ""
	}
}

// HasTLS returns true if both cert and key are configured and exist on disk.
func (c *Config) HasTLS() bool {
	if c.TLSCert == "" || c.TLSKey == "" {
		return false
	}
	if _, err := os.Stat(c.TLSCert); err != nil {
		return false
	}
	if _, err := os.Stat(c.TLSKey); err != nil {
		return false
	}
	return true
}

// HasAuth returns true if at least one auth mechanism is configured.
func (c *Config) HasAuth() bool {
	return c.NodeAgentToken != "" || c.ClusterSecret != ""
}

// TLSServerConfig builds the *tls.Config the control API listens with.
//
// There is no plaintext listener and no weaker handshake. The agent either
// has the cluster CA, its node certificate and key — and then it REQUIRES
// a CA-signed client certificate from every caller — or it does not start.
// Every error here names the fix, because the symptom on the controller
// ("node UNREACHABLE") reads as a network fault and sends the operator
// debugging the wrong layer.
//
// `noo cluster provision <node>` delivers all three files (Linux:
// /etc/noo/pki, macOS: ~/noomesh/pki) and the env lines that point at
// them; a node that was never provisioned — or a Mac that only ran
// `noo enroll` — has the CA anchor and nothing else, and this is the
// error it sees.
func (c *Config) TLSServerConfig() (*tls.Config, error) {
	if c.MTLSDowngradeAsked != "" {
		return nil, fmt.Errorf(
			"NOO_MTLS_NODES=%q asks for a client-certificate downgrade that no longer exists: "+
				"the control API on :%d is mTLS-only. Remove the NOO_MTLS_NODES line from this "+
				"node's env (/etc/noo-node-agent.env, or the controller's .env for a containerised "+
				"agent) and restart the agent", c.MTLSDowngradeAsked, c.portOrDefault())
	}
	// Same door, same reason: a line asking for a plaintext BACKEND door.
	// Checked here because this is where the agent decides whether it may
	// start at all, and a backend flag that means "serve plaintext" is as
	// retired as the control-API one.
	if c.BackendTLSDowngradeAsked != "" {
		name, _, _ := strings.Cut(c.BackendTLSDowngradeAsked, "=")
		return nil, fmt.Errorf(
			"%s asks for a plaintext backend door that no longer exists: every backend this "+
				"agent starts serves TLS with a required cluster-CA client certificate (vLLM "+
				"natively, the others behind a stunnel sidecar). Remove the %s line from this "+
				"node's env: `sudo sed -i '/^%s=/d' /etc/noo-node-agent.env` (macOS: delete it "+
				"from ~/noomesh/agent.env; a containerised agent: from the controller's .env, "+
				"or run `noo onboard --only env`), then restart the agent "+
				"(`noo cluster restart-agent <node>`). `noo cluster provision <node>` re-renders "+
				"the node env without these switches",
			c.BackendTLSDowngradeAsked, name, name)
	}
	var missing []string
	if c.TLSCA == "" {
		missing = append(missing, "NOO_TLS_CA")
	}
	if c.TLSCert == "" {
		missing = append(missing, "NOO_TLS_CERT")
	}
	if c.TLSKey == "" {
		missing = append(missing, "NOO_TLS_KEY")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"refusing to start: %s not set — the control API on :%d serves mTLS only and "+
				"there is no plaintext fallback. Provision this node's PKI material from the "+
				"controller: `noo cluster provision <node>` (a node that only ran `noo enroll` "+
				"has the CA anchor and no node certificate yet). Re-enroll with `noo enroll` "+
				"first if the controller no longer lists it",
			strings.Join(missing, ", "), c.portOrDefault())
	}
	for _, f := range []struct{ name, path string }{{"NOO_TLS_CA", c.TLSCA}, {"NOO_TLS_CERT", c.TLSCert}, {"NOO_TLS_KEY", c.TLSKey}} {
		if _, err := os.Stat(f.path); err != nil {
			return nil, fmt.Errorf(
				"refusing to start: %s=%q is not readable (%v) — the control API on :%d serves "+
					"mTLS only. Re-run `noo cluster provision <node>` to reissue and deliver this "+
					"node's PKI material", f.name, f.path, err, c.portOrDefault())
		}
	}

	cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading server cert NOO_TLS_CERT=%q / NOO_TLS_KEY=%q: %w — "+
			"re-run `noo cluster provision <node>` to reissue them", c.TLSCert, c.TLSKey, err)
	}
	caPEM, err := os.ReadFile(c.TLSCA)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert NOO_TLS_CA=%q: %w", c.TLSCA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("NOO_TLS_CA=%q contains no usable PEM certificate — "+
			"re-run `noo cluster provision <node>` to deliver the cluster CA", c.TLSCA)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    pool,
		// Prove who you are at the handshake or do not get a connection.
		// This is not configurable: auth.ControllerOnly reads the
		// certificate, and every legitimate caller (the gateway,
		// Prometheus, the agent's own -healthcheck) presents one.
		ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}

// portOrDefault is the control API port as ListenAndServe binds it.
func (c *Config) portOrDefault() int {
	if c.AgentPort == 0 {
		return 8081
	}
	return c.AgentPort
}

// HTTPTransport builds an *http.Transport for outbound requests with TLS/mTLS.
func (c *Config) HTTPTransport() (*http.Transport, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA cert for verifying server certificates.
	//
	// A CONFIGURED-BUT-UNREADABLE file is an error, not a shrug. This used to
	// os.Stat and silently skip on failure, so NOO_TLS_CA pointing at a path
	// that did not exist quietly degraded to the system trust store — and
	// because the cluster CA is private, every controller call then failed
	// with
	//
	//   x509: certificate signed by unknown authority
	//
	// which reads as a certificate problem rather than "your CA path is
	// wrong". It cost real time in the 2026-08-14 node-agent cutover on
	// host8: the agent ran eight minutes emitting x509 errors before anyone
	// spotted that the env file had not been written yet.
	//
	// An EMPTY value still means "no custom CA, use the system pool" — that is
	// the documented off switch and compose depends on it
	// (NOO_TLS_CA=${NOO_TLS_CA:+/app/pki/ca.crt} yields "" when unset). Only a
	// non-empty path that cannot be used is fatal.
	if c.TLSCA != "" {
		caPEM, err := os.ReadFile(c.TLSCA)
		if err != nil {
			return nil, fmt.Errorf(
				"NOO_TLS_CA is set to %q but cannot be read (%w) — verification would "+
					"silently fall back to the system trust store and every controller "+
					"call would fail with \"certificate signed by unknown authority\". "+
					"Fix the path, or unset NOO_TLS_CA to use the system pool on purpose",
				c.TLSCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("NOO_TLS_CA %q contains no usable PEM certificate", c.TLSCA)
		}
		tlsCfg.RootCAs = pool
	}

	// Client cert for mTLS — same rule, and a nastier silent failure: without
	// a client certificate the handshake still SUCCEEDS, and the server
	// rejects the request afterwards as unauthenticated. The client sees a
	// bare 401 and nothing at all about certificates.
	if c.TLSCert != "" && c.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, fmt.Errorf(
				"NOO_TLS_CERT=%q / NOO_TLS_KEY=%q are set but cannot be loaded (%w) — "+
					"the agent would connect WITHOUT a client certificate and be "+
					"rejected as unauthenticated (HTTP 401) with no clue why. Fix the "+
					"paths, or unset both", c.TLSCert, c.TLSKey, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Transport{
		TLSClientConfig: tlsCfg,
	}, nil
}

// Scheme always returns "https". All PAI cluster communication uses TLS.
// Plain HTTP is not supported — if TLS isn't configured, connections will
// fail loudly rather than silently falling back to unencrypted.
func (c *Config) Scheme() string {
	return "https"
}

// helpers

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool reads a yes/no flag: "1", "true" or "yes" (any case) is true.
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// envOff reads an explicit OFF switch: only "0", "false", "no" or "off"
// (any case) is off; unset and anything else leaves the feature on.
func envOff(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// envList reads a comma-separated list, trimmed, empties dropped.
func envList(key string) []string {
	var out []string
	for _, s := range strings.Split(os.Getenv(key), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}
