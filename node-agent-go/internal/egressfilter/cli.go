// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// MaxObserve is the longest --observe accepted.
const MaxObserve = 24 * time.Hour

// AcctPath is the one host setting plan mode may change, and only while
// observing.
const AcctPath = "/proc/sys/net/netfilter/nf_conntrack_acct"

// Env is everything Main touches. Tests fill it with fakes.
type Env struct {
	Out, Err io.Writer
	Runner   Runner
	Stream   Streamer
	Sysctl   Sysctl
	Now      func() time.Time
	IsRoot   func() bool
	Getenv   func(string) string
}

// Usage is the help text.
const Usage = `  noo-hostd egress-filter plan [--observe DURATION] [--json]
        READ-ONLY. Measure this node's noomesh Docker networks and firewall and
        print the rules a later step WOULD install. Nothing is installed.
        --observe 30m (max 24h; root + conntrack-tools; Ctrl-C ends early)
        also watches the connection tracker and lists which flows those rules
        WOULD have dropped. The only host change is net.netfilter.nf_conntrack_acct
        = 1 while observing, restored when it ends. Hostnames are not looked up;
        use docs/security/egress-capture.sh for names.
`

// Main runs `egress-filter <args>` against the real host.
func Main(args []string, out, errw io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, args, ProdEnv(out, errw))
}

// ProdEnv wires the real host, with every command behind the read-only guard.
func ProdEnv(out, errw io.Writer) Env {
	return Env{
		Out: out, Err: errw,
		Runner: GuardRunner{Inner: hostd.ExecRunner{}},
		Stream: GuardStreamer(execStream),
		Sysctl: fileSysctl{AcctPath},
		Now:    time.Now,
		IsRoot: func() bool { return os.Geteuid() == 0 },
		Getenv: os.Getenv,
	}
}

type fileSysctl struct{ path string }

func (f fileSysctl) Get() (string, error) {
	b, err := os.ReadFile(f.path)
	return string(b), err
}

func (f fileSysctl) Set(v string) error { return os.WriteFile(f.path, []byte(v+"\n"), 0o644) }

func execStream(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, func() string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	return out, cmd.Wait, func() string { return errBuf.String() }, nil
}

// Report is the --json document.
type Report struct {
	Plan        *Plan        `json:"plan"`
	Observation *Observation `json:"observation,omitempty"`
}

// Run executes `plan`.
func Run(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || args[0] != "plan" {
		fmt.Fprint(env.Err, "usage:\n"+Usage)
		return errors.New("egress-filter: the only subcommand is 'plan'")
	}
	fs := flag.NewFlagSet("egress-filter plan", flag.ContinueOnError)
	fs.SetOutput(env.Err)
	observe := fs.String("observe", "", "watch the connection tracker for this long (e.g. 30m, max 24h)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var dur time.Duration
	if *observe != "" {
		d, err := time.ParseDuration(*observe)
		if err != nil || d <= 0 {
			return fmt.Errorf("--observe %q: want a duration like 30m", *observe)
		}
		if d > MaxObserve {
			return fmt.Errorf("--observe %s is over the 24h limit", *observe)
		}
		if !env.IsRoot() {
			return errors.New("--observe needs root (the connection tracker and the sysctl are root-only): re-run with sudo, or drop --observe for the plan alone")
		}
		dur = d
	}

	cfg := Config{ClusterNetwork: env.Getenv("NOO_CLUSTER_NETWORK"), ComposeProject: env.Getenv("NOO_COMPOSE_PROJECT")}
	plan := BuildPlan(ctx, env.Runner, cfg)
	rep := Report{Plan: plan}

	var obsErr error
	if dur > 0 {
		obsErr = observeInto(ctx, env, cfg, plan, dur, &rep)
	}

	if *asJSON {
		enc := json.NewEncoder(env.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		WriteText(env.Out, rep)
	}
	return obsErr
}

func observeInto(ctx context.Context, env Env, cfg Config, plan *Plan, dur time.Duration, rep *Report) error {
	if len(plan.NotApplicable) > 0 {
		return nil // already printed as "not applicable"; there is no filter to rehearse
	}
	if len(plan.Networks) == 0 {
		rep.Observation = &Observation{Requested: dur.String(), Failure: "no noomesh networks were measured, so there is nothing to classify flows against"}
		return errors.New(rep.Observation.Failure)
	}
	if rc, _ := env.Runner.Capture(ctx, "", "conntrack", "--version"); rc != 0 {
		why := "conntrack failed to run"
		if rc == 127 {
			why = "conntrack is not installed"
		}
		rep.Observation = &Observation{Requested: dur.String(), Failure: why + ": --observe needs conntrack-tools (Debian/Ubuntu: apt install conntrack; Alpine: apk add conntrack-tools). The plan above is complete; no flows were observed."}
		return errors.New(rep.Observation.Failure)
	}
	refresh := func(c context.Context) ([]Network, error) { return CollectNetworks(c, env.Runner, cfg) }
	obs, err := Observe(ctx, dur, plan.Networks, env.Stream, env.Sysctl, env.Now, refresh)
	rep.Observation = obs
	return err
}

// WriteText prints the human report.
func WriteText(w io.Writer, rep Report) {
	p := rep.Plan
	fmt.Fprintln(w, "noo-hostd egress-filter plan (READ-ONLY: nothing is installed or changed)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== What was detected")
	d := p.Detection
	fmt.Fprintf(w, "  firewall backend:   %s\n", d.Backend)
	fmt.Fprintf(w, "  DOCKER-USER (v4):   %s    (v6): %s\n", d.DockerUserV4, d.DockerUserV6)
	fmt.Fprintf(w, "  FORWARD policy:     %s (information only; the plan never changes it)\n", orDash(d.ForwardPolicy))
	fmt.Fprintf(w, "  docker engine:      %s (rootless: %v)\n", orDash(d.EngineOS), d.EngineRootless)
	for _, r := range d.OtherRulesV4 {
		fmt.Fprintf(w, "  already in DOCKER-USER (v4, never touched): %s\n", r)
	}
	for _, r := range d.OtherRulesV6 {
		fmt.Fprintf(w, "  already in DOCKER-USER (v6, never touched): %s\n", r)
	}
	if d.JumpPresentV4 || d.JumpPresentV6 {
		fmt.Fprintf(w, "  jump to %s already present: v4=%v v6=%v\n", Chain, d.JumpPresentV4, d.JumpPresentV6)
	}
	for _, u := range p.Unknown {
		fmt.Fprintf(w, "  COULD NOT MEASURE:  %s\n", u)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "== noomesh networks")
	if len(p.Networks) == 0 {
		fmt.Fprintln(w, "  (none measured)")
	}
	for _, n := range p.Networks {
		fmt.Fprintf(w, "  %s  internal=%v  v4=%s  v6=%s\n", n.Name, n.Internal, orDash(strings.Join(n.Subnets4, ",")), orDash(strings.Join(n.Subnets6, ",")))
		for _, c := range n.Containers {
			fmt.Fprintf(w, "      %s  %s\n", c.Name, strings.Join(append(append([]string{}, c.IPv4...), c.IPv6...), " "))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== Egress class (allowed to reach the internet)")
	any := false
	for _, c := range p.Containers {
		if c.EgressClass {
			any = true
			fmt.Fprintf(w, "  %s  %s\n", c.Name, strings.Join(append(append([]string{}, c.IPv4...), c.IPv6...), " "))
		}
	}
	if !any {
		fmt.Fprintln(w, "  (no egress-class container is running)")
	}
	fmt.Fprintln(w, "  The future design puts these on their own noo-egress network; that network is NOT created yet.")

	fmt.Fprintln(w)
	if len(p.NotApplicable) > 0 {
		for _, n := range p.NotApplicable {
			fmt.Fprintf(w, "not applicable: %s\n", n)
		}
	} else if p.Rules.RestoreV4 == "" && p.Rules.NFT == "" {
		fmt.Fprintln(w, "== Rules: none rendered (see COULD NOT MEASURE above)")
	} else {
		fmt.Fprintln(w, "== Rules that WOULD be installed (nothing below has been run)")
		for _, n := range p.Rules.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
		if p.Rules.RestoreV4 != "" {
			fmt.Fprintf(w, "\n-- iptables: iptables-restore --noflush <<'EOF'\n%sEOF\n   then, only when absent:\n   %s\n", p.Rules.RestoreV4, p.Rules.JumpV4)
		}
		if p.Rules.RestoreV6 != "" {
			fmt.Fprintf(w, "\n-- ip6tables: ip6tables-restore --noflush <<'EOF'\n%sEOF\n   then, only when absent:\n   %s\n", p.Rules.RestoreV6, p.Rules.JumpV6)
		}
		if p.Rules.NFT != "" {
			fmt.Fprintf(w, "\n-- nftables (for a Docker that uses nftables): nft -f - <<'EOF'\n%sEOF\n", p.Rules.NFT)
		}
	}

	if rep.Observation != nil {
		writeObservation(w, rep.Observation)
	}
}

func writeObservation(w io.Writer, o *Observation) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== Observation")
	if o.Failure != "" && o.Events == 0 && len(o.Rows) == 0 {
		fmt.Fprintf(w, "  NOT OBSERVED: %s\n", o.Failure)
		return
	}
	state := "complete"
	if o.EndedEarly {
		state = "ended early (Ctrl-C) after " + (time.Duration(o.ElapsedSeconds) * time.Second).String()
	}
	if !o.Complete {
		state = "INCOMPLETE: " + o.Failure
	}
	fmt.Fprintf(w, "  requested %s; %s; %d conntrack events (%d not understood); IP map refresh failures: %d\n",
		o.Requested, state, o.Events, o.Unparsed, o.RefreshFailures)
	if !o.BytesCounted {
		fmt.Fprintln(w, "  bytes: NOT counted (nf_conntrack_acct could not be read or set); byte columns are 0, not zero traffic")
	}
	if o.OpenFlows > 0 {
		fmt.Fprintf(w, "  %d flow(s) were still open at the end; their bytes are not counted\n", o.OpenFlows)
	}
	if o.AcctRestored != "" {
		fmt.Fprintf(w, "  nf_conntrack_acct restored to %s\n", o.AcctRestored)
	}
	fmt.Fprintln(w, "  Hostnames are not looked up here; use docs/security/egress-capture.sh for names.")
	if !o.Complete {
		fmt.Fprintln(w, "  The table below is PARTIAL; do not read an absent row as 'would not drop'.")
	}
	if len(o.Rows) == 0 {
		if o.Complete {
			fmt.Fprintln(w, "  No flow from a noomesh subnet to a non-private destination was seen in this window.")
			fmt.Fprintln(w, "  That says nothing about traffic outside the window.")
		}
		return
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  VERDICT\tCONTAINER\tDESTINATION\tPORT/PROTO\tFLOWS\tBYTES OUT\tBYTES IN\tFIRST\tLAST")
	for _, r := range o.Rows {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s/%s\t%d\t%d\t%d\t%s\t%s\n", r.Verdict, r.Container, r.Dst, r.Port, r.Proto,
			r.Flows, r.BytesOut, r.BytesIn, r.First.UTC().Format("15:04:05"), r.Last.UTC().Format("15:04:05"))
	}
	_ = tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
