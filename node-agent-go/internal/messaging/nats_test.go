// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package messaging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// applyOptions resolves the option funcs into a concrete nats.Options so the
// resilience settings can be asserted without a server.
func applyOptions(t *testing.T, c *Client) nats.Options {
	t.Helper()
	// Credentials are fail-closed stage 1; these tests
	// assert the resilience settings, not the credential, so opt in to the
	// anonymous path explicitly.
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")
	o := nats.GetDefaultOptions()
	opts, err := c.buildOptions()
	if err != nil {
		t.Fatalf("buildOptions: %v", err)
	}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			t.Fatalf("option failed: %v", err)
		}
	}
	return o
}

// The inbox prefix must be this node's alone — the shared "_INBOX." cannot
// be granted to one principal without granting it to all of them.
func TestCustomInboxPrefixIsNodeScoped(t *testing.T) {
	c := &Client{nodeID: "host8", url: "nats://nats:4222"}
	o := applyOptions(t, c)
	if o.InboxPrefix != "_INBOX_node_host8" {
		t.Errorf("InboxPrefix = %q, want _INBOX_node_host8", o.InboxPrefix)
	}
}

// The incident these assertions guard: two nodes lost the bus when the
// controller's NATS container was recreated and never came back, while
// still heartbeating over HTTPS so they looked healthy.
func TestConnectOptionsReconnectForever(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222"}
	o := applyOptions(t, c)

	if o.MaxReconnect != -1 {
		t.Errorf("MaxReconnect = %d, want -1 (unlimited)", o.MaxReconnect)
	}
	if o.ReconnectWait != 2*time.Second {
		t.Errorf("ReconnectWait = %v, want 2s", o.ReconnectWait)
	}
	if o.ReconnectJitter <= 0 {
		t.Error("ReconnectJitter must be set so a restarting fleet does not synchronise its retries")
	}
	if !o.RetryOnFailedConnect {
		t.Error("RetryOnFailedConnect must be on: an agent that starts while NATS is down " +
			"used to run deaf for the rest of its lifetime")
	}
	if !o.IgnoreAuthErrorAbort {
		t.Error("IgnoreAuthErrorAbort must be on: nats.go otherwise CLOSES the connection " +
			"permanently after two auth errors, ignoring MaxReconnects")
	}
	if o.ReconnectBufSize <= 0 {
		t.Error("ReconnectBufSize must be set so publishes during an outage are flushed, not dropped")
	}
}

// A black-holed link (common over the tailnet, where the peer sends no RST)
// is only detected by pings. nats.go's default takes ~4 minutes.
func TestConnectOptionsDetectDeadLinkQuickly(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222"}
	o := applyOptions(t, c)

	if o.PingInterval > 30*time.Second {
		t.Errorf("PingInterval = %v, want <= 30s", o.PingInterval)
	}
	deadAfter := time.Duration(o.MaxPingsOut) * o.PingInterval
	if deadAfter > 2*time.Minute {
		t.Errorf("dead-link detection takes %v, want <= 2m", deadAfter)
	}
}

// The worst property of the incident was silence: nothing in the agent logs
// marked the disconnect, so a two-day outage left no trace at all.
func TestConnectOptionsWireAllHandlers(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222"}
	o := applyOptions(t, c)

	if o.DisconnectedErrCB == nil {
		t.Error("DisconnectErrHandler must be wired")
	}
	if o.ReconnectedCB == nil {
		t.Error("ReconnectHandler must be wired")
	}
	if o.ClosedCB == nil {
		t.Error("ClosedHandler must be wired — CLOSED is terminal for nats.go and must be loud")
	}
	if o.AsyncErrorCB == nil {
		t.Error("ErrorHandler must be wired")
	}
}

// The old handler only logged when err != nil, and a clean server-side close
// (exactly what a container recreate produces) passes nil.
func TestDisconnectHandlerRecordsStateOnNilError(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222", state: StateConnected}
	o := applyOptions(t, c)

	o.DisconnectedErrCB(nil, nil)

	st := c.Status()
	if st.State != StateReconnecting {
		t.Errorf("state = %q after a nil-error disconnect, want %q", st.State, StateReconnecting)
	}
	if st.LastDisconnectedAt == nil {
		t.Error("LastDisconnectedAt must be recorded even when the close was clean")
	}
}

func TestReconnectHandlerFiresHooks(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222", state: StateReconnecting}

	var wg sync.WaitGroup
	wg.Add(2)
	var mu sync.Mutex
	fired := []string{}
	for _, name := range []string{"dispatch", "mesh"} {
		n := name
		c.OnReconnect(func() {
			mu.Lock()
			fired = append(fired, n)
			mu.Unlock()
			wg.Done()
		})
	}

	c.fireHooks()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect hooks did not fire")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 2 {
		t.Errorf("fired = %v, want both hooks", fired)
	}
}

// Honest status: a node with no messaging must never render as connected.
func TestStatusOfNilClientIsUnavailable(t *testing.T) {
	var c *Client
	st := c.Status()
	if st.State != StateUnavailable {
		t.Errorf("state = %q, want %q", st.State, StateUnavailable)
	}
	if st.Connected {
		t.Error("a nil client must not report Connected")
	}
	if st.LastConnectedAt != nil {
		t.Error("LastConnectedAt must be nil (unknown), not a zero timestamp")
	}
}

func TestStatusNeverConnectedLeavesTimestampsNil(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222", state: StateConnecting}
	st := c.Status()

	if st.State != StateConnecting {
		t.Errorf("state = %q, want %q", st.State, StateConnecting)
	}
	if st.LastConnectedAt != nil || st.LastDisconnectedAt != nil {
		t.Error("timestamps must stay nil until something actually happened")
	}
	if st.Connects != 0 {
		t.Errorf("Connects = %d, want 0", st.Connects)
	}
}

func TestStatusReportsOutageDuration(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222"}
	c.markConnected()
	time.Sleep(10 * time.Millisecond)
	c.markDisconnected()

	st := c.Status()
	if st.Connected {
		t.Error("must not report Connected while disconnected")
	}
	if st.DisconnectedForSec == nil {
		t.Fatal("DisconnectedForSec must be reported during an outage")
	}
	if st.LastConnectedAt == nil {
		t.Error("LastConnectedAt must survive the disconnect")
	}
	if st.Connects != 1 {
		t.Errorf("Connects = %d, want 1", st.Connects)
	}
}

func TestPublishEventWithoutConnectionReportsFailure(t *testing.T) {
	c := &Client{nodeID: "test-node", url: "nats://nats:4222"}
	// No underlying connection: the caller must learn the event did not go
	// out rather than assume success.
	if err := c.PublishEvent("job.failed", map[string]any{"job_id": "x"}); err == nil {
		t.Fatal("expected an error when there is no connection")
	}
}

// The three credential shapes must each say something, because the retry loop
// alone says nothing useful. host9 cut over on 2026-08-14 with NATS_URL set
// and no user/password: the agent connected anonymously, was rejected, and
// logged "nats not yet connected — retrying" for twelve minutes while DNS,
// TCP and TLS all looked fine.
func TestMissingNATSCredentialsAreAnnounced(t *testing.T) {
	cases := []struct {
		name, user, pass, want string
	}{
		{"user without password", "u", "", "NATS_NODE_PASSWORD is empty"},
		{"password without user", "", "p", "NATS_NODE_USER is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The half-set pair is the node's OWN pair: the shared one is
			// retired and never consulted.
			t.Setenv("NATS_NODE_USER", tc.user)
			t.Setenv("NATS_NODE_PASSWORD", tc.pass)
			t.Setenv("NATS_USER", "")
			t.Setenv("NATS_PASSWORD", "")
			t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			c := &Client{nodeID: "testnode", url: "tls://x:4222"}
			_, _ = c.buildOptions()

			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("expected a warning containing %q, got: %s", tc.want, buf.String())
			}
		})
	}
}

// Both absent is no longer a warning but a refusal: an empty NATS_USER means
// the client connects anonymously AND the server accepts it, so a blank in
// the secret store silently removed bus authentication.
func TestNoCredentialRefusesToConnect(t *testing.T) {
	t.Setenv("NATS_USER", "")
	t.Setenv("NATS_PASSWORD", "")
	t.Setenv("NATS_NODE_USER", "")
	t.Setenv("NATS_NODE_PASSWORD", "")
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "")

	c := &Client{nodeID: "testnode", url: "tls://x:4222"}
	_, err := c.buildOptions()
	if err == nil {
		t.Fatal("expected a refusal when no NATS credential is configured")
	}
	for _, want := range []string{"NATS_NODE_USER", "NATS_NODE_PASSWORD", "NOO_NATS_ALLOW_ANONYMOUS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %s, got: %v", want, err)
		}
	}
}

// The shared fleet credential is retired and so is its bridge.
// An agent whose own pair has not been delivered must stop, naming the verb
// that delivers it, whatever the retired bridge variable says — never
// present the one credential users.conf could only grant ">"/">".
func TestSharedCredentialIsRefusedEvenWithTheRetiredBridge(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	for _, bridge := range []string{"", "0", "1", "true"} {
		shared := map[string]string{
			"NATS_USER": "noo", "NATS_PASSWORD": "fleet-secret",
			"NOO_NATS_LEGACY_SHARED_CREDS": bridge,
		}
		cred, err := resolveNATSCredential(env(shared), "host9", "tls://x:4222")
		if err == nil {
			t.Fatalf("bridge=%q: the retired shared pair must be refused, got %+v", bridge, cred)
		}
		for _, want := range []string{"RETIRED", "NATS_NODE_USER", "nats-creds rotate host9", "cluster provision host9"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("bridge=%q: the refusal must name %s, got: %v", bridge, want, err)
			}
		}
		if strings.Contains(err.Error(), "NOO_NATS_LEGACY_SHARED_CREDS") {
			t.Errorf("the refusal must not offer the retired bridge: %v", err)
		}
	}
}

func TestAnonymousEscapeHatch(t *testing.T) {
	t.Setenv("NATS_USER", "")
	t.Setenv("NATS_PASSWORD", "")
	t.Setenv("NATS_NODE_USER", "")
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")

	c := &Client{nodeID: "testnode", url: "tls://x:4222"}
	if _, err := c.buildOptions(); err != nil {
		t.Fatalf("the escape hatch must allow an anonymous connection: %v", err)
	}
}

func TestCredentialPrecedence(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	cred, err := resolveNATSCredential(env(map[string]string{
		"NATS_NODE_USER":     "node-host9",
		"NATS_NODE_PASSWORD": "node-secret",
		"NATS_USER":          "noo",
		"NATS_PASSWORD":      "fleet-secret",
	}), "host9", "tls://x:4222")
	if err != nil || cred == nil {
		t.Fatalf("expected the node pair, got %v / %v", cred, err)
	}
	if cred.User != "node-host9" || cred.Password != "node-secret" || cred.Source != "node" {
		t.Errorf("the role pair must win: %+v", cred)
	}

	// A rendered env file with a blank per-node line must NOT fall through to
	// the retired shared pair, bridge variable or not.
	cred, err = resolveNATSCredential(env(map[string]string{
		"NATS_NODE_USER":               "   ",
		"NATS_USER":                    "noo",
		"NATS_PASSWORD":                "fleet-secret",
		"NOO_NATS_LEGACY_SHARED_CREDS": "1",
	}), "host9", "tls://x:4222")
	if err == nil {
		t.Fatalf("a blank role user must not fall through to the shared pair, got %+v", cred)
	}
}

func TestSubjectTokenSanitisation(t *testing.T) {
	cases := map[string]string{
		"host9":  "host9",
		"host8":  "host8",
		"node_1":  "node_1",
		"a.b":     "a_b",   // a dot would create a subject hierarchy
		"a.b.c":   "a_b_c", // ... and widen any permission rule written against it
		"node id": "node_id",
		"node>":   "node_",
		"node*":   "node_",
		"$sys":    "_sys",
		"":        "unknown",
	}
	for in, want := range cases {
		if got := SubjectToken(in); got != want {
			t.Errorf("SubjectToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNodeInboxPrefixIsOneToken(t *testing.T) {
	got := NodeInboxPrefix("some.node")
	if got != "_INBOX_node_some_node" {
		t.Errorf("NodeInboxPrefix = %q", got)
	}
	if strings.Contains(got, ".") {
		t.Errorf("the inbox prefix must be a single subject token: %q", got)
	}
}

// A fully-configured agent must stay quiet — a warning that fires on the happy
// path is noise, and noise is what stops warnings being read.
func TestCompleteNATSCredentialsWarnNothing(t *testing.T) {
	// "Complete" now means this node's OWN pair — the happy path after
	// `noo cluster nats-creds rotate <node>` has delivered it.
	t.Setenv("NATS_NODE_USER", "node-testnode")
	t.Setenv("NATS_NODE_PASSWORD", "p")
	t.Setenv("NATS_USER", "")
	t.Setenv("NATS_PASSWORD", "")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	c := &Client{nodeID: "testnode", url: "tls://x:4222"}
	if _, err := c.buildOptions(); err != nil {
		t.Fatalf("complete credentials must connect: %v", err)
	}

	if strings.Contains(buf.String(), "NATS_USER") || strings.Contains(buf.String(), "ANONYMOUSLY") {
		t.Errorf("complete credentials should produce no credential warning, got: %s", buf.String())
	}
}

// The reported principal must be the USERNAME and never the password.
//
// This field exists so an operator can tell a node deliberately on the shared
// pair from one whose per-principal credential never arrived — both report
// `connected: true` and were, until this, indistinguishable. That diagnostic
// value is worthless if shipping it also ships the secret, so the absence of
// the password is asserted, not assumed.
func TestStatusReportsThePrincipalAndNeverThePassword(t *testing.T) {
	const secret = "s3cr3t-do-not-report"
	c := &Client{}
	c.stateMu.Lock()
	c.credUser, c.credRole = "node-host9", "node"
	c.state = StateConnected
	c.stateMu.Unlock()

	st := c.Status()
	if st.User != "node-host9" {
		t.Errorf("User = %q, want the username", st.User)
	}
	if st.Role != "node" {
		t.Errorf("Role = %q, want \"node\"", st.Role)
	}
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatal("the serialised bus status contains a password")
	}
	// There is no password field at all — the strongest form of the claim.
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range m {
		if strings.Contains(strings.ToLower(k), "pass") {
			t.Errorf("bus status carries a password-ish field %q", k)
		}
	}
}

// An agent that never resolved a credential must report ABSENCE, not
// "anonymous". Absence means "this build does not report it"; claiming
// anonymous would accuse a perfectly normal older node of running unauthenticated.
func TestUnreportedPrincipalIsOmittedNotAnonymous(t *testing.T) {
	c := &Client{}
	c.stateMu.Lock()
	c.state = StateConnected
	c.stateMu.Unlock()
	blob, _ := json.Marshal(c.Status())
	var m map[string]any
	_ = json.Unmarshal(blob, &m)
	if _, present := m["role"]; present {
		t.Errorf("role must be omitted when unknown, got %v", m["role"])
	}
	if _, present := m["user"]; present {
		t.Errorf("user must be omitted when unknown, got %v", m["user"])
	}
}

// A tls:// URL whose TLS configuration cannot be built must REFUSE, not
// connect in the clear.
//
// The old code warned and carried on. Against the TLS profile that produced
// "nats not yet connected — retrying" with the real cause one WARN above the
// noise; against the plain profile it SUCCEEDED, and every job dispatch and
// prompt went out unencrypted while NATS_URL said tls://.
func TestUnbuildableTLSRefusesRatherThanDowngrading(t *testing.T) {
	t.Setenv("NOO_TLS_CA", filepath.Join(t.TempDir(), "there-is-no-ca-here.crt"))
	t.Setenv("NATS_NODE_USER", "node-testnode")
	t.Setenv("NATS_NODE_PASSWORD", "p")

	c := &Client{nodeID: "testnode", url: "tls://nats:4222"}
	_, err := c.buildOptions()
	if err == nil {
		t.Fatal("a tls:// URL with an unreadable CA must refuse to connect")
	}
	for _, want := range []string{"tls://nats:4222", "refusing to connect in the clear", "NOO_TLS_CA"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q, got: %v", want, err)
		}
	}

	// The guard must not fire on the plain profile, or it would refuse
	// every no-PKI install rather than the downgrade it is aimed at.
	c = &Client{nodeID: "testnode", url: "nats://nats:4222"}
	if _, err := c.buildOptions(); err != nil {
		t.Fatalf("a nats:// URL needs no TLS config: %v", err)
	}
}

// The counterpart dev's test does not have: a USABLE TLS config must still
// produce a Secure() option, and must never skip verification. Without this,
// "refuse when TLS cannot be built" is satisfied just as well by refusing
// always, or by building a config that verifies nothing — two ways to pass
// the guard above while breaking or hollowing out every TLS connection.
func TestTLSSchemeStillConfiguresTLSWhenUsable(t *testing.T) {
	t.Setenv("NOO_TLS_CA", "")
	t.Setenv("NOO_TLS_CERT", "")
	t.Setenv("NOO_TLS_KEY", "")
	t.Setenv("NATS_NODE_USER", "node-testnode")
	t.Setenv("NATS_NODE_PASSWORD", "p")

	c := &Client{nodeID: "testnode", url: "tls://bus.example:4222"}
	opts, err := c.buildOptions()
	if err != nil {
		t.Fatalf("buildOptions with no CA configured: %v", err)
	}
	o := nats.GetDefaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			t.Fatalf("option failed: %v", err)
		}
	}
	if o.TLSConfig == nil {
		t.Fatal("a tls:// URL must install a TLS config")
	}
	if o.TLSConfig.InsecureSkipVerify {
		t.Fatal("the NATS TLS config must never skip verification")
	}
}
