// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// fakeVersionDaemon answers /version (any API prefix) with body, as a daemon would.
func fakeVersionDaemon(t *testing.T, status int, body string) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/version") && !strings.HasSuffix(r.URL.Path, "/_ping") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Api-Version", "1.47")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	dc, err := client.NewClientWithOpts(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithVersion("1.47"))
	if err != nil {
		t.Fatal(err)
	}
	return dc
}

func engineOf(t *testing.T, dc *client.Client) map[string]any {
	t.Helper()
	c := &Client{docker: dc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.EngineReport(ctx)
}

// i1058: a reply from each engine kind is reported with its version and kind.
func TestEngineReportNamesVersionAndKind(t *testing.T) {
	for _, tc := range []struct{ name, body, version, kind string }{
		{"dockerd", `{"Platform":{"Name":"Docker Engine - Community"},"Version":"27.5.1","ApiVersion":"1.47",
			"Components":[{"Name":"Engine","Version":"27.5.1"},{"Name":"containerd","Version":"1.7.24"}]}`, "27.5.1", EngineKindDockerd},
		{"desktop", `{"Platform":{"Name":"Docker Desktop 4.49.0 (208003)"},"Version":"28.5.1","ApiVersion":"1.51",
			"Components":[{"Name":"Engine","Version":"28.5.1"}]}`, "28.5.1", EngineKindDesktop},
		{"podman", `{"Platform":{"Name":"linux/amd64/fedora-40"},"Version":"5.2.2","ApiVersion":"1.41",
			"Components":[{"Name":"Podman Engine","Version":"5.2.2"}]}`, "5.2.2", EngineKindPodman},
	} {
		got := engineOf(t, fakeVersionDaemon(t, 200, tc.body))
		if got["state"] != EngineStateOK || got["version"] != tc.version || got["kind"] != tc.kind || len(got) != 3 {
			t.Errorf("%s: docker_engine = %v, want ok %s %s", tc.name, got, tc.version, tc.kind)
		}
	}
}

// No Docker at all (the daemon's socket does not exist): "none", explicitly.
func TestEngineReportNoneWithoutDocker(t *testing.T) {
	dc, err := client.NewClientWithOpts(client.WithHost("unix://" + filepath.Join(t.TempDir(), "no-such", "docker.sock")))
	if err != nil {
		t.Fatal(err)
	}
	got := engineOf(t, dc)
	if got["state"] != EngineStateNone || len(got) != 1 {
		t.Fatalf("docker_engine = %v, want {state: none}", got)
	}
}

// Docker is there but its version cannot be read: "unreadable" with the
// error, never "none" (that would hide the node from the verify row).
func TestEngineReportUnreadableIsNotNone(t *testing.T) {
	// A socket path that exists but answers nothing: a connection failure
	// that is not "no Docker".
	sock := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dc, err := client.NewClientWithOpts(client.WithHost("unix://" + sock))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]map[string]any{
		"socket refuses": engineOf(t, dc),
		"daemon 500":     engineOf(t, fakeVersionDaemon(t, 500, `{"message":"boom"}`)),
		"no Version":     engineOf(t, fakeVersionDaemon(t, 200, `{"Platform":{"Name":"x"}}`)),
	} {
		e, _ := got["error"].(string)
		if got["state"] != EngineStateUnreadable || e == "" || len(e) > maxEngineErrLen {
			t.Errorf("%s: docker_engine = %v, want unreadable with an error", name, got)
		}
	}
}

// The daemon is asked once per TTL, not on every heartbeat.
func TestEngineReportIsCached(t *testing.T) {
	calls := 0
	now := time.Unix(1000, 0)
	p := &engineProbe{
		version: func(context.Context) (client.ServerVersionResult, error) {
			calls++
			return client.ServerVersionResult{Version: "27.0.3"}, nil
		},
		now: func() time.Time { return now },
	}
	for i := 0; i < 5; i++ {
		p.Report(context.Background())
	}
	if calls != 1 {
		t.Fatalf("version asked %d times within the TTL", calls)
	}
	now = now.Add(engineOKTTL + time.Second)
	if p.Report(context.Background())["version"] != "27.0.3" || calls != 2 {
		t.Fatalf("not refreshed after the TTL: %d calls", calls)
	}
}
