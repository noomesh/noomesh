// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/harnessprofile"
)

// Precedence: the env on the box > the profile's first_byte_secs > 290 s.
func TestFirstByteTimeoutPrecedence(t *testing.T) {
	p600 := &harnessprofile.Profile{FirstByteSecs: 600}
	cases := []struct {
		name   string
		envD   time.Duration
		envSet bool
		prof   *harnessprofile.Profile
		want   time.Duration
	}{
		{"nothing set", 0, false, nil, defaultBackendFirstByteTimeout},
		{"profile only", 0, false, p600, 600 * time.Second},
		{"env beats profile", 900 * time.Second, true, p600, 900 * time.Second},
		{"env only", 120 * time.Second, true, nil, 120 * time.Second},
		{"profile without the field", 0, false, &harnessprofile.Profile{Tier: 2}, defaultBackendFirstByteTimeout},
	}
	for _, c := range cases {
		if got := firstByteTimeoutFor(c.envD, c.envSet, c.prof); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// An unusable env value is not an override: the profile applies.
	d, set := parseFirstByteOverride("0")
	if got := firstByteTimeoutFor(d, set, p600); got != 600*time.Second {
		t.Errorf("unusable env must fall through to the profile: %v", got)
	}
}

// The bound in force is read per call, so a profile change is seen by the
// next request with no restart.
func TestFirstByteTimeoutFollowsTheProfileLive(t *testing.T) {
	if os.Getenv(backendFirstByteTimeoutEnv) != "" {
		t.Skip("the box's env override wins over the profile by design")
	}
	t.Cleanup(func() { harnessprofile.Set(nil) })
	harnessprofile.Set(nil)
	if got := backendFirstByteTimeout(); got != defaultBackendFirstByteTimeout {
		t.Fatalf("no profile: %v", got)
	}
	harnessprofile.Set(&harnessprofile.Profile{FirstByteSecs: 900})
	if got := backendFirstByteTimeout(); got != 900*time.Second {
		t.Fatalf("profile 900: %v", got)
	}
	harnessprofile.Set(nil)
	if got := backendFirstByteTimeout(); got != defaultBackendFirstByteTimeout {
		t.Fatalf("profile cleared: %v", got)
	}
}

// End to end through the proxy's own transport: a backend that takes 1.5 s
// to send headers fails under a 1 s profile bound, and the SAME agent
// (no restart, no rebuilt server) serves it once the profile says 3 s.
func TestInferenceTransportAppliesAProfileChangeToTheNextRequest(t *testing.T) {
	if os.Getenv(backendFirstByteTimeoutEnv) != "" {
		t.Skip("the box's env override wins over the profile by design")
	}
	t.Cleanup(func() { harnessprofile.Set(nil) })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	s := &Server{}
	get := func() error {
		c := &http.Client{Transport: s.inferenceTransport("http", backendFirstByteTimeout())}
		resp, err := c.Get(backend.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}

	harnessprofile.Set(&harnessprofile.Profile{FirstByteSecs: 1})
	if err := get(); err == nil || !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Fatalf("1 s bound against a 1.5 s backend: want a header timeout, got %v", err)
	}
	harnessprofile.Set(&harnessprofile.Profile{FirstByteSecs: 3})
	if err := get(); err != nil {
		t.Fatalf("after the profile moved to 3 s: %v", err)
	}
}
