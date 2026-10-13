// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear env vars to test defaults
	for _, key := range []string{"NODE_ID", "CONTROLLER_URL", "NATS_URL", "NODE_TIER", "HEARTBEAT_INTERVAL"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.NodeID != "auto" {
		t.Errorf("expected NodeID 'auto', got %q", cfg.NodeID)
	}
	if cfg.ControllerURL != "https://gateway:8080" {
		t.Errorf("expected default controller URL, got %q", cfg.ControllerURL)
	}
	if cfg.NATSURL != "tls://nats:4222" {
		t.Errorf("expected the TLS default NATS URL (the bus is mTLS-only), got %q", cfg.NATSURL)
	}
	if cfg.Tier != 3 {
		t.Errorf("expected tier 3, got %d", cfg.Tier)
	}
	if cfg.HeartbeatInterval != 30 {
		t.Errorf("expected 30s heartbeat, got %d", cfg.HeartbeatInterval)
	}
}

func TestLoad_FromEnv(t *testing.T) {
	os.Setenv("NODE_ID", "gpu-worker-1")
	os.Setenv("NODE_TIER", "1")
	os.Setenv("VRAM_GB", "24.0")
	os.Setenv("GPU_MODEL", "RTX 4090")
	os.Setenv("HEARTBEAT_INTERVAL", "10")
	defer func() {
		os.Unsetenv("NODE_ID")
		os.Unsetenv("NODE_TIER")
		os.Unsetenv("VRAM_GB")
		os.Unsetenv("GPU_MODEL")
		os.Unsetenv("HEARTBEAT_INTERVAL")
	}()

	cfg := Load()

	if cfg.NodeID != "gpu-worker-1" {
		t.Errorf("expected NodeID 'gpu-worker-1', got %q", cfg.NodeID)
	}
	if cfg.Tier != 1 {
		t.Errorf("expected tier 1, got %d", cfg.Tier)
	}
	if cfg.VRAMGB != 24.0 {
		t.Errorf("expected 24.0 VRAM, got %f", cfg.VRAMGB)
	}
	if cfg.GPUModel != "RTX 4090" {
		t.Errorf("expected GPU model 'RTX 4090', got %q", cfg.GPUModel)
	}
	if cfg.HeartbeatInterval != 10 {
		t.Errorf("expected 10s heartbeat, got %d", cfg.HeartbeatInterval)
	}
}

func TestHasAuth(t *testing.T) {
	cases := []struct {
		token  string
		secret string
		want   bool
	}{
		{"", "", false},
		{"tok", "", true},
		{"", "sec", true},
		{"tok", "sec", true},
	}

	for _, tc := range cases {
		cfg := &Config{NodeAgentToken: tc.token, ClusterSecret: tc.secret}
		if cfg.HasAuth() != tc.want {
			t.Errorf("HasAuth(token=%q, secret=%q) = %v, want %v", tc.token, tc.secret, cfg.HasAuth(), tc.want)
		}
	}
}

func TestScheme_AlwaysHTTPS(t *testing.T) {
	cfg := &Config{TLSCA: ""}
	if cfg.Scheme() != "https" {
		t.Errorf("expected https always, got %q", cfg.Scheme())
	}

	cfg.TLSCA = "/some/ca.crt"
	if cfg.Scheme() != "https" {
		t.Errorf("expected https, got %q", cfg.Scheme())
	}
}

func TestHasTLS_MissingFiles(t *testing.T) {
	cfg := &Config{
		TLSCert: "/nonexistent/cert.pem",
		TLSKey:  "/nonexistent/key.pem",
	}
	if cfg.HasTLS() {
		t.Error("HasTLS should be false when files don't exist")
	}
}

func TestHasTLS_EmptyPaths(t *testing.T) {
	cfg := &Config{TLSCert: "", TLSKey: ""}
	if cfg.HasTLS() {
		t.Error("HasTLS should be false with empty paths")
	}
}

// NOO_MTLS_NODES cannot downgrade anything any more. A value that names
// the retired downgrade is recorded so the server refuses to start on it
// (a stale env line must be loud, not silently ignored); every other
// value, including unset and the empty string the provisioner renders, is
// accepted and means nothing.
func TestMTLSDowngradeIsRecordedOnlyForDowngradeValues(t *testing.T) {
	for _, val := range []string{"", "true", "1", "yes", "anything-else"} {
		os.Setenv("NOO_MTLS_NODES", val)
		if cfg := Load(); cfg.MTLSDowngradeAsked != "" {
			t.Errorf("NOO_MTLS_NODES=%q is not a downgrade and must not be recorded as one", val)
		}
	}
	for _, val := range []string{"false", "0", "no", "off", "FALSE", " false "} {
		os.Setenv("NOO_MTLS_NODES", val)
		if cfg := Load(); cfg.MTLSDowngradeAsked != val {
			t.Errorf("NOO_MTLS_NODES=%q must be recorded verbatim as the retired downgrade, got %q", val, cfg.MTLSDowngradeAsked)
		}
	}
	os.Unsetenv("NOO_MTLS_NODES")
	if cfg := Load(); cfg.MTLSDowngradeAsked != "" {
		t.Error("an unset NOO_MTLS_NODES must not read as a downgrade")
	}
}

// A per-backend TLS flag asking for plaintext (false/0/no/off) REFUSES the
// start, naming the line; every other value is inert. There is no plaintext
// backend door to switch to.
func TestBackendTLSDowngradeRefusesTheStart(t *testing.T) {
	for _, env := range []string{"NOO_VLLM_TLS", "NOO_LLAMACPP_TLS", "NOO_OLLAMA_TLS", "NOO_TEI_TLS", "NOO_RERANKER_TLS"} {
		os.Unsetenv(env)
	}
	defer os.Unsetenv("NOO_LLAMACPP_TLS")
	for _, val := range []string{"", "true", "1", "yes"} {
		os.Setenv("NOO_LLAMACPP_TLS", val)
		if cfg := Load(); cfg.BackendTLSDowngradeAsked != "" {
			t.Errorf("NOO_LLAMACPP_TLS=%q is not a downgrade: %q", val, cfg.BackendTLSDowngradeAsked)
		}
	}
	for _, val := range []string{"false", "0", "no", "off", " FALSE "} {
		os.Setenv("NOO_LLAMACPP_TLS", val)
		if cfg := Load(); cfg.BackendTLSDowngradeAsked != "NOO_LLAMACPP_TLS="+val {
			t.Errorf("NOO_LLAMACPP_TLS=%q must be recorded as the downgrade, got %q", val, cfg.BackendTLSDowngradeAsked)
		}
	}
	dir := t.TempDir()
	ca, cert, key := writeSelfSignedPair(t, dir)
	cfg := &Config{TLSCA: ca, TLSCert: cert, TLSKey: key, BackendTLSDowngradeAsked: "NOO_LLAMACPP_TLS=false"}
	if _, err := cfg.TLSServerConfig(); err == nil {
		t.Fatal("NOO_LLAMACPP_TLS=false must refuse the start")
	} else {
		for _, needle := range []string{"NOO_LLAMACPP_TLS=false", "plaintext backend door", "Remove the NOO_LLAMACPP_TLS line", "sed -i '/^NOO_LLAMACPP_TLS=/d' /etc/noo-node-agent.env", "noo cluster restart-agent"} {
			if !strings.Contains(err.Error(), needle) {
				t.Errorf("refusal must say %q, got: %v", needle, err)
			}
		}
	}
	// The flag table names every fronted backend, once.
	want := map[string]string{"vllm": "NOO_VLLM_TLS", "llamacpp": "NOO_LLAMACPP_TLS", "ollama": "NOO_OLLAMA_TLS", "embedding": "NOO_TEI_TLS", "reranker": "NOO_RERANKER_TLS"}
	if len(BackendTLSFlags) != len(want) {
		t.Fatalf("BackendTLSFlags = %v", BackendTLSFlags)
	}
	for b, env := range want {
		if BackendTLSFlags[b] != env {
			t.Errorf("BackendTLSFlags[%s] = %q, want %q", b, BackendTLSFlags[b], env)
		}
	}
}

// A downgrade line REFUSES the start. The old behaviour (VerifyClientCertIfGiven)
// is gone; the only trace of the variable is this error, which names the fix.
func TestTLSServerConfigRefusesTheRetiredDowngrade(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key := writeSelfSignedPair(t, dir)
	cfg := &Config{TLSCA: ca, TLSCert: cert, TLSKey: key, MTLSDowngradeAsked: "false"}
	tc, err := cfg.TLSServerConfig()
	if err == nil {
		t.Fatalf("NOO_MTLS_NODES=false must refuse the start, got ClientAuth=%v", tc.ClientAuth)
	}
	for _, needle := range []string{"NOO_MTLS_NODES", "mTLS-only", "Remove the NOO_MTLS_NODES line"} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("refusal must say %q, got: %v", needle, err)
		}
	}
}

// With the material present the handshake REQUIRES a verified client
// certificate — there is no configuration that yields anything weaker.
func TestTLSServerConfigClientAuthMode(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key := writeSelfSignedPair(t, dir)

	cfg := &Config{TLSCA: ca, TLSCert: cert, TLSKey: key}
	tc, err := cfg.TLSServerConfig()
	if err != nil {
		t.Fatalf("TLSServerConfig: %v", err)
	}
	if tc.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("with a cluster CA the handshake must be RequireAndVerifyClientCert, got %v", tc.ClientAuth)
	}
	if tc.ClientCAs == nil {
		t.Error("ClientCAs must be the cluster CA pool")
	}
}

// No material, no listener. Each missing piece is named, and so is the
// command that delivers it — the symptom on the controller is "node
// UNREACHABLE", which reads as a network fault.
func TestTLSServerConfigRefusesWithoutMaterial(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key := writeSelfSignedPair(t, dir)

	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		{"nothing", Config{}, []string{"NOO_TLS_CA, NOO_TLS_CERT, NOO_TLS_KEY", "noo cluster provision <node>", "no plaintext fallback"}},
		{"no ca", Config{TLSCert: cert, TLSKey: key}, []string{"NOO_TLS_CA not set", "noo cluster provision <node>"}},
		{"no cert", Config{TLSCA: ca, TLSKey: key}, []string{"NOO_TLS_CERT not set"}},
		{"no key", Config{TLSCA: ca, TLSCert: cert}, []string{"NOO_TLS_KEY not set"}},
		{"ca path missing", Config{TLSCA: filepath.Join(dir, "nope.crt"), TLSCert: cert, TLSKey: key}, []string{"NOO_TLS_CA=", "not readable", "noo cluster provision <node>"}},
		{"cert path missing", Config{TLSCA: ca, TLSCert: filepath.Join(dir, "nope.crt"), TLSKey: key}, []string{"NOO_TLS_CERT=", "not readable"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc, err := c.cfg.TLSServerConfig()
			if err == nil {
				t.Fatalf("must refuse, got a config (ClientAuth=%v)", tc.ClientAuth)
			}
			if tc != nil {
				t.Errorf("a refusal must not also hand back a config")
			}
			for _, needle := range c.want {
				if !strings.Contains(err.Error(), needle) {
					t.Errorf("refusal must say %q, got: %v", needle, err)
				}
			}
		})
	}
}

// A CA file that holds no certificate is as good as none: the pool would
// verify nobody, and RequireAndVerifyClientCert would refuse the controller.
func TestTLSServerConfigRefusesAnEmptyCA(t *testing.T) {
	dir := t.TempDir()
	_, cert, key := writeSelfSignedPair(t, dir)
	junk := filepath.Join(dir, "junk.crt")
	if err := os.WriteFile(junk, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{TLSCA: junk, TLSCert: cert, TLSKey: key}
	if _, err := cfg.TLSServerConfig(); err == nil || !strings.Contains(err.Error(), "no usable PEM certificate") {
		t.Fatalf("a CA with no certificate must refuse, got %v", err)
	}
}

// writeSelfSignedPair writes a usable CA/cert/key trio into dir and returns
// their paths. Self-signed is fine here: the assertion is about ClientAuth,
// not about the chain.
func writeSelfSignedPair(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test", Organization: []string{"Mesh Cluster Node"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	for p, b := range map[string][]byte{caPath: certPEM, certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return caPath, certPath, keyPath
}

func TestEnvHelpers(t *testing.T) {
	if envOr("DEFINITELY_NOT_SET_12345", "fallback") != "fallback" {
		t.Error("envOr should return fallback for unset var")
	}

	if envInt("DEFINITELY_NOT_SET_12345", 42) != 42 {
		t.Error("envInt should return fallback for unset var")
	}

	if envFloat("DEFINITELY_NOT_SET_12345", 3.14) != 3.14 {
		t.Error("envFloat should return fallback for unset var")
	}
}

// A host may run more than one agent (worker on 8081, sensor companion on
// 8082). The port must come from the environment or the second agent
// collides with the first.
func TestAgentPortConfigurable(t *testing.T) {
	for _, key := range []string{"NODE_AGENT_PORT"} {
		os.Unsetenv(key)
	}
	if got := Load().AgentPort; got != 8081 {
		t.Errorf("default AgentPort = %d, want 8081", got)
	}

	os.Setenv("NODE_AGENT_PORT", "8082")
	defer os.Unsetenv("NODE_AGENT_PORT")
	if got := Load().AgentPort; got != 8082 {
		t.Errorf("AgentPort = %d, want 8082", got)
	}

	// Garbage must not silently produce port 0 (which would bind a random
	// ephemeral port and make the node unreachable).
	os.Setenv("NODE_AGENT_PORT", "not-a-port")
	if got := Load().AgentPort; got != 8081 {
		t.Errorf("invalid AgentPort = %d, want fallback 8081", got)
	}
}

// A misconfigured TLS path must fail LOUDLY at construction.
//
// These exist because the silent version cost eight minutes of a live cutover
// on 2026-08-14: NOO_TLS_CA pointed at a file that did not exist yet, the
// transport quietly used the system trust store, and the operator saw
// "x509: certificate signed by unknown authority" — which points at
// certificates, not at a path typo.
func TestConfiguredButUnreadableCAIsFatalNotSilent(t *testing.T) {
	c := &Config{TLSCA: filepath.Join(t.TempDir(), "nope.crt")}
	_, err := c.HTTPTransport()
	if err == nil {
		t.Fatal("a NOO_TLS_CA pointing at a missing file was accepted — it would " +
			"silently fall back to the system pool")
	}
	// The message has to name the variable and the consequence, or it just
	// relocates the confusion.
	for _, want := range []string{"NOO_TLS_CA", "unknown authority"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestGarbageCAContentIsFatal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, []byte("this is not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Config{TLSCA: p}).HTTPTransport(); err == nil {
		t.Fatal("a CA file with no PEM in it was accepted")
	}
}

// The off switch must keep working: compose renders NOO_TLS_CA as "" when the
// operator has not configured PKI, and that has to mean "system pool", not
// "fail to start".
func TestEmptyCAStillMeansSystemPool(t *testing.T) {
	tr, err := (&Config{}).HTTPTransport()
	if err != nil {
		t.Fatalf("empty TLS config must be valid, got: %v", err)
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Error("no CA configured should leave RootCAs nil (system pool)")
	}
}

// Missing client cert/key is the worse one: the handshake SUCCEEDS without a
// certificate and the server 401s afterwards, so the client log says nothing
// about certificates at all.
func TestConfiguredButUnreadableClientCertIsFatal(t *testing.T) {
	d := t.TempDir()
	c := &Config{
		TLSCert: filepath.Join(d, "node.crt"),
		TLSKey:  filepath.Join(d, "node.key"),
	}
	_, err := c.HTTPTransport()
	if err == nil {
		t.Fatal("missing client cert/key was accepted — the agent would connect " +
			"anonymously and be 401'd with no explanation")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should name the symptom the operator will actually see, got: %v", err)
	}
}
