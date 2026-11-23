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
	// EgressStale: held, but the harness cannot reach the gateway from inside
	// its hold: the allow list names an address the controller no longer has.
	// Not a leak (fail closed); a re-apply renders the current addresses.
	EgressStale = "stale"
)

// SelfTestMaxAge: the harness re-runs its self-test every 60 s; a record
// older than three intervals no longer says anything about now.
const SelfTestMaxAge = 180 * time.Second

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
	// From a harness that re-checks (absent from an older one): how old its
	// latest self-test is, and whether its private resolv.conf still holds.
	CheckedAgeSecs *int64 `json:"checked_age_secs,omitempty"`
	ResolvHeld     *bool  `json:"resolv_held,omitempty"`
}

// Map is the heartbeat form (the payload is map[string]any).
func (e Egress) Map() map[string]any {
	stale := e.StaleHosts
	if stale == nil {
		stale = []string{}
	}
	m := map[string]any{
		"state": e.State, "reason": e.Reason, "ip_deny": e.IPDeny, "ip_allow": e.IPAllow,
		"resolver": e.Resolver, "pid_match": e.PIDMatch, "lookup": e.Lookup,
		"connect": e.Connect, "stale_hosts": stale,
	}
	if e.CheckedAgeSecs != nil {
		m["checked_age_secs"] = *e.CheckedAgeSecs
	}
	if e.ResolvHeld != nil {
		m["resolv_held"] = *e.ResolvHeld
	}
	return m
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
	// Now is the clock the self-test's age is read against (time.Now if nil).
	Now func() time.Time
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
	// From a harness that re-checks every minute (absent from an older one).
	CheckedAt    *int64   `json:"checked_at"`
	ResolvHeld   *bool    `json:"resolv_held"`
	DNSReachable []string `json:"dns_reachable"`
	AllowFile    string   `json:"allow_file"`
	Gateway      *struct {
		Addr   string `json:"addr"`
		Result string `json:"result"`
	} `json:"gateway"`
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
	// Every allowed entry must be one host: a range (an older applier wrote
	// private, tailnet and link-local ranges) lets the unit reach whatever
	// answers in it, a resolver included, whatever the self-test says.
	if wide := wideAllowEntries(e.IPAllow); len(wide) > 0 {
		e.State = EgressUnenforced
		e.Reason = fmt.Sprintf("the harness's allow list still includes %s (an older applier wrote it): re-apply", strings.Join(wide, " "))
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
	// A harness that re-checks: its latest check must be recent. An older
	// harness (no checked_at) is read as before, from its start-time check.
	if st.CheckedAt != nil {
		now := time.Now
		if r.Now != nil {
			now = r.Now
		}
		age := now().Unix() - *st.CheckedAt
		if age < 0 {
			age = 0
		}
		e.CheckedAgeSecs = &age
		e.ResolvHeld = st.ResolvHeld
		if time.Duration(age)*time.Second > SelfTestMaxAge {
			e.Reason = fmt.Sprintf("the harness's egress self-test is %ds old (it re-checks every 60 s); nothing says the hold holds now", age)
			return e
		}
	}
	if !*st.Enforced {
		e.State = EgressUnenforced
		e.Reason = fmt.Sprintf("the harness's own self-test says not enforced (lookup %s, connect %s)", st.Lookup.Result, st.Connect.Result)
		if len(st.DNSReachable) > 0 {
			e.Reason += fmt.Sprintf("; a resolver answered at %s", strings.Join(st.DNSReachable, ", "))
		}
		if st.AllowFile == "missing" {
			e.Reason += "; no allow file beside the drop-in (an older applier): re-apply"
		}
		return e
	}
	if st.Gateway != nil && st.Gateway.Result == "failed" {
		e.State = EgressStale
		e.Reason = fmt.Sprintf("held, but the harness cannot reach the gateway at %s from inside its hold (the allow list may be stale): re-apply", st.Gateway.Addr)
		return e
	}
	e.State = EgressEnforced
	e.Reason = fmt.Sprintf("the unit allows only %s and the harness's own self-test confirms it", e.IPAllow)
	return e
}

// wideAllowEntries returns the entries of systemd's IPAddressAllow value that
// are not a single host (/32 or /128). An empty value allows nothing.
func wideAllowEntries(v string) []string {
	var wide []string
	for _, f := range strings.Fields(v) {
		_, pfx, ok := strings.Cut(f, "/")
		switch {
		case ok && strings.Contains(f, ":") && pfx == "128":
		case ok && !strings.Contains(f, ":") && pfx == "32":
		default:
			wide = append(wide, f)
		}
	}
	return wide
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

// resolverFromBinds is "unit" when BindReadOnlyPaths maps the harness-net
// resolv.conf over the file resolvers read: /etc/resolv.conf itself, or, on a
// host where that is a symlink (Ubuntu: into /run/systemd/resolve/), the
// link's target, which is where the applier binds it.
func resolverFromBinds(v string) string {
	for _, f := range strings.Fields(v) {
		parts := strings.Split(strings.TrimLeft(f, "-+"), ":")
		if len(parts) >= 2 && parts[0] == strings.TrimSuffix(HarnessNetDir, "/")+"/resolv.conf" && strings.HasSuffix(parts[1], "resolv.conf") {
			return "unit"
		}
		// A resolver file outside /etc is held by binding the harness-net
		// directory over its parent (a file bind would detach on the host's
		// next rewrite of it).
		if len(parts) >= 2 && parts[0] == strings.TrimSuffix(HarnessNetDir, "/")+"/resolvdir" && parts[1] != "" && parts[1] != "/etc" {
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
