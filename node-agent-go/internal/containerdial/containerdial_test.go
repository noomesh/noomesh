// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package containerdial

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	ips   map[string]string
	calls int
}

func (f *fakeResolver) ContainerDialAddr(_ context.Context, name, port string) (string, error) {
	f.calls++
	if ip, ok := f.ips[name]; ok {
		return net.JoinHostPort(ip, port), nil
	}
	return "", errors.New("no such container")
}

// recordingDial records the addresses dialed and fails those listed in fail.
func recordingDial(dialed *[]string, fail map[string]bool) dialFn {
	return func(_ context.Context, _ string, addr string) (net.Conn, error) {
		*dialed = append(*dialed, addr)
		if fail[addr] {
			return nil, errors.New("refused")
		}
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
}

func TestHostMode(t *testing.T) {
	envOf := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	cases := []struct {
		name            string
		env             map[string]string
		dockerenvExists bool
		wantHost        bool
	}{
		{
			name:            "no override, no systemd, no dockerenv: bare host process",
			env:             map[string]string{},
			dockerenvExists: false,
			wantHost:        true,
		},
		{
			name:            "no override, no systemd, dockerenv present: in-compose container",
			env:             map[string]string{},
			dockerenvExists: true,
			wantHost:        false,
		},
		{
			name:            "systemd unit, box is itself a container (the newcomer rehearsal case)",
			env:             map[string]string{"INVOCATION_ID": "abc123"},
			dockerenvExists: true,
			wantHost:        true,
		},
		{
			name:            "systemd unit, ordinary bare-metal host",
			env:             map[string]string{"INVOCATION_ID": "abc123"},
			dockerenvExists: false,
			wantHost:        true,
		},
		{
			name:            "override wins over systemd: force container mode",
			env:             map[string]string{"NOO_AGENT_HOST_MODE": "0", "INVOCATION_ID": "abc123"},
			dockerenvExists: false,
			wantHost:        false,
		},
		{
			name:            "override wins over dockerenv: force host mode",
			env:             map[string]string{"NOO_AGENT_HOST_MODE": "1"},
			dockerenvExists: true,
			wantHost:        true,
		},
		{
			name:            "unrecognized override value falls through to heuristics",
			env:             map[string]string{"NOO_AGENT_HOST_MODE": "yes"},
			dockerenvExists: true,
			wantHost:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := hostMode(envOf(tc.env), tc.dockerenvExists)
			if got != tc.wantHost {
				t.Errorf("hostMode() = %v (%s), want host=%v", got, reason, tc.wantHost)
			}
			if reason == "" {
				t.Error("hostMode() returned an empty reason")
			}
		})
	}
}

func TestCandidateNames(t *testing.T) {
	// The discriminator that keeps docker OUT of ordinary dials: only bare
	// single-label non-address names are candidates.
	for host, want := range map[string]bool{
		"noo-reranker":   true,
		"noo-ollama":     true,
		"noo-controller": true, // candidate — but resolve fails on a worker, so /etc/hosts still wins via fallback
		"localhost":      false,
		"127.0.0.1":      false,
		"100.64.0.17":    false,
		"example.com":    false,
		"host8.ts.net":  false,
		"::1":            false,
		"fe80::1":        false,
		"":               false,
	} {
		if got := candidateName(host); got != want {
			t.Errorf("candidateName(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestContainerNameDialsBridgeIP(t *testing.T) {
	fr := &fakeResolver{ips: map[string]string{"noo-reranker": "172.20.0.5"}}
	var dialed []string
	d := New(fr).WrapDialContext(recordingDial(&dialed, nil))
	if _, err := d(context.Background(), "tcp", "noo-reranker:8085"); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 1 || dialed[0] != "172.20.0.5:8085" {
		t.Fatalf("dialed %v, want the bridge IP", dialed)
	}
}

func TestUnknownNameFallsBackToOrdinaryDial(t *testing.T) {
	// noo-controller on a worker: single-label (candidate), NOT a container
	// — the /etc/hosts path must proceed exactly as before.
	fr := &fakeResolver{ips: map[string]string{}}
	var dialed []string
	d := New(fr).WrapDialContext(recordingDial(&dialed, nil))
	if _, err := d(context.Background(), "tcp", "noo-controller:8080"); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 1 || dialed[0] != "noo-controller:8080" {
		t.Fatalf("dialed %v, want the original addr untouched", dialed)
	}
}

func TestAddressesNeverTouchDocker(t *testing.T) {
	fr := &fakeResolver{ips: map[string]string{}}
	var dialed []string
	d := New(fr).WrapDialContext(recordingDial(&dialed, nil))
	for _, addr := range []string{"127.0.0.1:11434", "100.64.0.17:8080", "example.com:443"} {
		if _, err := d(context.Background(), "tcp", addr); err != nil {
			t.Fatal(err)
		}
	}
	if fr.calls != 0 {
		t.Fatalf("docker consulted %d times for plain addresses", fr.calls)
	}
}

func TestStaleIPReinspectsOnce(t *testing.T) {
	// A cached bridge IP goes stale the moment the container is recreated.
	// The failed dial re-inspects NOW (not after TTL) and dials the fresh IP.
	fr := &fakeResolver{ips: map[string]string{"noo-ollama": "172.20.0.9"}}
	var dialed []string
	r := New(fr)
	d := r.WrapDialContext(recordingDial(&dialed, map[string]bool{"172.20.0.9:11434": true}))
	_ = r.resolve(context.Background(), "noo-ollama", "11434") // cache the soon-stale IP
	fr.ips["noo-ollama"] = "172.20.0.10"                       // container recreated
	if _, err := d(context.Background(), "tcp", "noo-ollama:11434"); err != nil {
		t.Fatalf("fresh IP after re-inspect should connect: %v", err)
	}
	if len(dialed) != 2 || dialed[0] != "172.20.0.9:11434" || dialed[1] != "172.20.0.10:11434" {
		t.Fatalf("dialed %v, want stale IP then the fresh one", dialed)
	}
}

// TestContainerDialFailureNeverFallsBackToDNS is the host3 2026-09-29
// regression: a vLLM still loading refuses on its bridge IP, and the dialer
// used to fall back to the ORDINARY dial of "noo-vllm:8000" — a system DNS
// lookup — so every request of a cold load read "lookup noo-vllm on
// 100.100.100.100:53: no such host". A name that IS a container is never
// handed to the ordinary dialer; the error names the container and the
// address that refused.
func TestContainerDialFailureNeverFallsBackToDNS(t *testing.T) {
	fr := &fakeResolver{ips: map[string]string{"noo-vllm": "172.18.0.2"}}
	var dialed []string
	d := New(fr).WrapDialContext(recordingDial(&dialed, map[string]bool{"172.18.0.2:8000": true}))
	_, err := d(context.Background(), "tcp", "noo-vllm:8000")
	if err == nil {
		t.Fatal("a refusing container must fail the dial")
	}
	for _, a := range dialed {
		if a == "noo-vllm:8000" {
			t.Fatalf("dialed %v: the container NAME reached the ordinary (DNS) dialer", dialed)
		}
	}
	if !strings.Contains(err.Error(), "noo-vllm") || !strings.Contains(err.Error(), "172.18.0.2:8000") ||
		!strings.Contains(err.Error(), "refused") {
		t.Fatalf("error %q should name the container, the address dialled and the cause", err)
	}
}

func TestCachePreventsInspectPerDial(t *testing.T) {
	fr := &fakeResolver{ips: map[string]string{"noo-reranker": "172.20.0.5"}}
	var dialed []string
	r := New(fr)
	d := r.WrapDialContext(recordingDial(&dialed, nil))
	for i := 0; i < 5; i++ {
		if _, err := d(context.Background(), "tcp", "noo-reranker:8085"); err != nil {
			t.Fatal(err)
		}
	}
	if fr.calls != 1 {
		t.Fatalf("resolver called %d times for 5 dials — cache not working", fr.calls)
	}
}

func TestNegativeCacheExpiresFasterThanPositive(t *testing.T) {
	fr := &fakeResolver{ips: map[string]string{}}
	r := New(fr)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }

	if ip := r.resolve(context.Background(), "noo-llamacpp", "8085"); ip != "" {
		t.Fatal("expected miss")
	}
	// Backend starts a moment later.
	fr.ips["noo-llamacpp"] = "172.20.0.7"

	// Within the negative window: still cached as a miss.
	now = now.Add(r.ttl / 8)
	if ip := r.resolve(context.Background(), "noo-llamacpp", "8085"); ip != "" {
		t.Fatal("negative entry expired too early")
	}
	// After the negative window (ttl/4) but well before the positive ttl.
	now = now.Add(r.ttl / 4)
	if ip := r.resolve(context.Background(), "noo-llamacpp", "8085"); ip != "172.20.0.7:8085" {
		t.Fatalf("late-starting backend not found after negative window, got %q", ip)
	}
}
