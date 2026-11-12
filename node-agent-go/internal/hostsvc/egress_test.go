// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const goodBinds = "/etc/noo/harness-net/resolv.conf:/etc/resolv.conf /etc/noo/harness-net/hosts:/etc/hosts /etc/noo/harness-net/nsswitch.conf:/etc/nsswitch.conf"

func show(pid, deny, allow, binds string) string {
	return fmt.Sprintf("MainPID=%s\nIPAddressDeny=%s\nIPAddressAllow=%s\nBindReadOnlyPaths=%s\nInaccessiblePaths=\n", pid, deny, allow, binds)
}

const hostsFile = "# Rendered by noo-apply at 2026-11-12T00:00:00Z\n# names: ctl.example\n127.0.0.1 localhost\n10.0.0.5 ctl.example\n"

func selfTest(pid int, enforced bool) string {
	return fmt.Sprintf(`{"version":1,"pid":%d,"started_at":1,"lookup":{"name":"example.com","result":"failed"},"connect":{"addr":"192.0.2.1:9","result":"denied"},"enforced":%v}`, pid, enforced)
}

func TestEgressReader(t *testing.T) {
	good := show("4242", "0.0.0.0/0 ::/0", "localhost 10.0.0.0/8", goodBinds)
	cases := []struct {
		name       string
		showOut    string
		showErr    error
		files      map[string]string
		resolve    map[string][]string
		wantState  string
		wantReason string
		wantStale  []string
		wantPID    bool
		wantRes    string
	}{
		{"enforced", good, nil, map[string]string{"st": selfTest(4242, true), "h": hostsFile}, map[string][]string{"ctl.example": {"10.0.0.5"}}, "enforced", "confirms", nil, true, "unit"},
		{"deny spelled any", show("4242", "any", "localhost", goodBinds), nil, map[string]string{"st": selfTest(4242, true), "h": hostsFile}, nil, "enforced", "", nil, true, "unit"},
		{"unenforced from self-test", good, nil, map[string]string{"st": selfTest(4242, false), "h": hostsFile}, nil, "unenforced", "self-test says not enforced", nil, true, "unit"},
		{"pid mismatch is unknown", good, nil, map[string]string{"st": selfTest(1, true), "h": hostsFile}, nil, "unknown", "not the running harness", nil, false, "unit"},
		{"self-test absent is unknown", good, nil, map[string]string{"h": hostsFile}, nil, "unknown", "has not written", nil, false, "unit"},
		{"self-test garbage is unknown", good, nil, map[string]string{"st": "{", "h": hostsFile}, nil, "unknown", "not a version 1", nil, false, "unit"},
		{"self-test without enforced is unknown", good, nil, map[string]string{"st": `{"version":1,"pid":4242}`}, nil, "unknown", "not a version 1", nil, false, "unit"},
		{"systemctl failing is unknown", "", errors.New("exec: systemctl: not found"), nil, nil, "unknown", "systemctl show failed", nil, false, "none"},
		{"unit not running is unknown", show("0", "0.0.0.0/0 ::/0", "", goodBinds), nil, map[string]string{"st": selfTest(4242, true)}, nil, "unknown", "not running", nil, false, "unit"},
		{"running, no deny is unenforced", show("4242", "", "", goodBinds), nil, map[string]string{"st": selfTest(4242, true)}, nil, "unenforced", "no IPAddressDeny", nil, false, "unit"},
		{"v4-only deny is unenforced", show("4242", "0.0.0.0/0", "", goodBinds), nil, map[string]string{"st": selfTest(4242, true)}, nil, "unenforced", "no IPAddressDeny", nil, false, "unit"},
		{"resolver none is unenforced", show("4242", "0.0.0.0/0 ::/0", "", ""), nil, map[string]string{"st": selfTest(4242, true)}, nil, "unenforced", "resolv.conf", nil, false, "none"},
		{"a stale host", good, nil, map[string]string{"st": selfTest(4242, true), "h": hostsFile}, map[string][]string{"ctl.example": {"10.0.0.5", "10.0.0.6"}}, "enforced", "", []string{"ctl.example"}, true, "unit"},
		{"unresolvable name is not stale", good, nil, map[string]string{"st": selfTest(4242, true), "h": hostsFile}, map[string][]string{}, "enforced", "", nil, true, "unit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &EgressReader{
				SelfTestPath: "st", HostsPath: "h",
				Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
					if name != "systemctl" || args[0] != "show" || args[1] != UnitName {
						t.Fatalf("unexpected command %s %v", name, args)
					}
					return []byte(c.showOut), c.showErr
				},
				ReadFile: func(p string) ([]byte, error) {
					if v, ok := c.files[p]; ok {
						return []byte(v), nil
					}
					return nil, errors.New("absent")
				},
				Resolve: func(_ context.Context, n string) ([]string, error) {
					if a, ok := c.resolve[n]; ok && len(a) > 0 {
						return a, nil
					}
					return nil, errors.New("no such host")
				},
			}
			got := r.Read(context.Background())
			if got.State != c.wantState {
				t.Fatalf("state = %q (%s), want %q", got.State, got.Reason, c.wantState)
			}
			if !strings.Contains(got.Reason, c.wantReason) || got.Reason == "" {
				t.Fatalf("reason %q lacks %q", got.Reason, c.wantReason)
			}
			if got.PIDMatch != c.wantPID || got.Resolver != c.wantRes {
				t.Fatalf("pid_match=%v resolver=%q", got.PIDMatch, got.Resolver)
			}
			want := c.wantStale
			if want == nil {
				want = []string{}
			}
			// A stale list is computed only for a running unit.
			if c.name == "systemctl failing is unknown" || c.name == "unit not running is unknown" {
				want = []string{}
			}
			if !reflect.DeepEqual(got.StaleHosts, want) {
				t.Fatalf("stale_hosts = %v, want %v", got.StaleHosts, want)
			}
		})
	}
}

func TestEgressMapKeysAreTheWireNames(t *testing.T) {
	m := Egress{State: EgressUnknown}.Map()
	for _, k := range []string{"state", "reason", "ip_deny", "ip_allow", "resolver", "pid_match", "lookup", "connect", "stale_hosts"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %v", k, m)
		}
	}
	if s, ok := m["stale_hosts"].([]string); !ok || s == nil {
		t.Fatalf("stale_hosts must be a non-nil list: %#v", m["stale_hosts"])
	}
}

// On Ubuntu /etc/resolv.conf is a symlink and the applier binds over its
// target (/run/systemd/resolve/stub-resolv.conf): still the unit's resolver.
func TestResolverIsRecognisedOnTheSymlinkTarget(t *testing.T) {
	stub := "/etc/noo/harness-net/resolv.conf:/run/systemd/resolve/stub-resolv.conf:rbind /etc/noo/harness-net/hosts:/etc/hosts:rbind"
	if got := resolverFromBinds(stub); got != "unit" {
		t.Fatalf("stub target: got %q", got)
	}
	if got := resolverFromBinds("/somewhere/else/resolv.conf:/etc/resolv.conf"); got != "none" {
		t.Fatalf("a resolv.conf that is not the harness's: got %q", got)
	}
}
