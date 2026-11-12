// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Where the harness's egress hold-off is recorded. Named by meaning:
// EgressSelfTestPath is the file the harness writes about itself inside its
// own namespace; HarnessNetHostsPath is the hosts file the applier renders
// for the harness (its `# names:` line lists the controller names in it);
// HarnessNetDir is where the applier keeps every file it binds over the
// harness's /etc/resolv.conf, /etc/hosts and /etc/nsswitch.conf.
const (
	EgressSelfTestPath  = "/run/noo-harness/egress.json"
	HarnessNetDir       = "/etc/noo/harness-net/"
	HarnessNetHostsPath = "/etc/noo/harness-net/hosts"
)

// Egress states. Only EgressEnforced is a pass; EgressUnknown is never one.
const (
	EgressEnforced   = "enforced"
	EgressUnenforced = "unenforced"
	EgressUnknown    = "unknown"
)

// Egress is the heartbeat's host_services.harness.egress object. The json
// tags are the wire names; every key is always present.
type Egress struct {
	State      string   `json:"state"`
	Reason     string   `json:"reason"`
	IPDeny     string   `json:"ip_deny"`
	IPAllow    string   `json:"ip_allow"`
	Resolver   string   `json:"resolver"` // "unit" | "none"
	PIDMatch   bool     `json:"pid_match"`
	Lookup     string   `json:"lookup"`
	Connect    string   `json:"connect"`
	StaleHosts []string `json:"stale_hosts"`
}

// Map is the heartbeat form (the payload is map[string]any).
func (e Egress) Map() map[string]any {
	stale := e.StaleHosts
	if stale == nil {
		stale = []string{}
	}
	return map[string]any{
		"state": e.State, "reason": e.Reason, "ip_deny": e.IPDeny, "ip_allow": e.IPAllow,
		"resolver": e.Resolver, "pid_match": e.PIDMatch, "lookup": e.Lookup,
		"connect": e.Connect, "stale_hosts": stale,
	}
}

// EgressReader holds every outside input of the egress reading so tests use
// fakes: the command runner, the two file paths, the file reader and the
// resolver.
type EgressReader struct {
	// Run runs a command and returns its stdout.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// ReadFile reads a file.
	ReadFile func(path string) ([]byte, error)
	// Resolve looks a name up with THIS agent's own resolver.
	Resolve func(ctx context.Context, name string) ([]string, error)
	// SelfTestPath and HostsPath default to the constants above.
	SelfTestPath string
	HostsPath    string
}

// DefaultEgressReader reads the real host.
func DefaultEgressReader() *EgressReader {
	return &EgressReader{
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
		ReadFile: os.ReadFile,
		Resolve: func(ctx context.Context, name string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, name)
		},
		SelfTestPath: EgressSelfTestPath,
		HostsPath:    HarnessNetHostsPath,
	}
}

type selfTestRecord struct {
	Version int   `json:"version"`
	PID     int64 `json:"pid"`
	Lookup  struct {
		Result string `json:"result"`
	} `json:"lookup"`
	Connect struct {
		Result string `json:"result"`
	} `json:"connect"`
	Enforced *bool `json:"enforced"`
}

// Read builds the egress object. Every absent, old or failing input yields
// state "unknown" with a reason; "enforced" needs every check to pass.
func (r *EgressReader) Read(ctx context.Context) Egress {
	e := Egress{State: EgressUnknown, Resolver: "none", StaleHosts: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	out, err := r.Run(ctx, "systemctl", "show", UnitName, "-p", "MainPID", "-p", "IPAddressDeny",
		"-p", "IPAddressAllow", "-p", "BindReadOnlyPaths", "-p", "InaccessiblePaths")
	if err != nil {
		e.Reason = "could not read the harness unit's properties (systemctl show failed: " + shortErr(err) + ")"
		return e
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = strings.TrimSpace(v)
		}
	}
	e.IPDeny, e.IPAllow = props["IPAddressDeny"], props["IPAddressAllow"]
	e.Resolver = resolverFromBinds(props["BindReadOnlyPaths"])
	var mainPID int64
	if _, perr := fmt.Sscanf(props["MainPID"], "%d", &mainPID); perr != nil {
		e.Reason = "the harness unit's MainPID could not be read"
		return e
	}
	if mainPID <= 0 {
		e.Reason = "the harness unit is not running"
		return e
	}
	e.StaleHosts = r.staleHosts(ctx)

	// A running unit without the deny or the resolver is held off nothing,
	// whatever the self-test file says (or does not).
	if !denyCoversAny(e.IPDeny) {
		e.State = EgressUnenforced
		e.Reason = "the harness unit has no IPAddressDeny=any"
		return e
	}
	if e.Resolver != "unit" {
		e.State = EgressUnenforced
		e.Reason = "the harness unit does not use the harness-only resolv.conf"
		return e
	}

	raw, err := r.ReadFile(r.SelfTestPath)
	if err != nil {
		e.Reason = "the harness has not written its egress self-test (" + r.SelfTestPath + " unreadable)"
		return e
	}
	var st selfTestRecord
	if err := json.Unmarshal(raw, &st); err != nil || st.Version != 1 || st.Enforced == nil {
		e.Reason = "the harness's egress self-test file is not a version 1 record"
		return e
	}
	e.Lookup, e.Connect = st.Lookup.Result, st.Connect.Result
	e.PIDMatch = st.PID == mainPID
	if !e.PIDMatch {
		e.Reason = fmt.Sprintf("the egress self-test is from pid %d, not the running harness (pid %d)", st.PID, mainPID)
		return e
	}
	if !*st.Enforced {
		e.State = EgressUnenforced
		e.Reason = fmt.Sprintf("the harness's own self-test says not enforced (lookup %s, connect %s)", st.Lookup.Result, st.Connect.Result)
		return e
	}
	e.State = EgressEnforced
	e.Reason = "the unit denies all but local and tailnet addresses and the harness's own self-test confirms it"
	return e
}

func shortErr(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// denyCoversAny reports whether systemd's IPAddressDeny value denies every
// address: the keyword `any`, or both whole families.
func denyCoversAny(v string) bool {
	var v4, v6 bool
	for _, f := range strings.Fields(v) {
		switch f {
		case "any":
			return true
		case "0.0.0.0/0":
			v4 = true
		case "::/0":
			v6 = true
		}
	}
	return v4 && v6
}

// resolverFromBinds is "unit" when BindReadOnlyPaths maps /etc/resolv.conf
// from the harness-net directory.
func resolverFromBinds(v string) string {
	for _, f := range strings.Fields(v) {
		parts := strings.Split(strings.TrimLeft(f, "-+"), ":")
		if len(parts) >= 2 && parts[1] == "/etc/resolv.conf" && strings.HasPrefix(parts[0], HarnessNetDir) {
			return "unit"
		}
	}
	return "none"
}

// staleHosts names each controller name in the rendered hosts file whose
// addresses, resolved NOW by this agent, are not all in the file. A name this
// agent cannot resolve is not evidence of anything and is not listed.
func (r *EgressReader) staleHosts(ctx context.Context) []string {
	stale := []string{}
	raw, err := r.ReadFile(r.HostsPath)
	if err != nil {
		return stale
	}
	var names []string
	inFile := map[string]map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "# names:"); ok {
			names = strings.Fields(rest)
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		ip := net.ParseIP(f[0])
		if ip == nil {
			continue
		}
		for _, n := range f[1:] {
			if inFile[n] == nil {
				inFile[n] = map[string]bool{}
			}
			inFile[n][ip.String()] = true
		}
	}
	for _, n := range names {
		addrs, err := r.Resolve(ctx, n)
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			a, _, _ = strings.Cut(a, "%")
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if !inFile[n][ip.String()] {
				stale = append(stale, n)
				break
			}
		}
	}
	return stale
}
