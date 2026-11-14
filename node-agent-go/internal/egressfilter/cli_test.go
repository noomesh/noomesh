// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCheckReadOnlyTable(t *testing.T) {
	cases := []struct {
		name string
		args []string
		ok   bool
	}{
		{"iptables", []string{"-V"}, true},
		{"iptables", []string{"-S"}, true},
		{"iptables", []string{"-C", "DOCKER-USER", "-j", "X"}, true},
		{"iptables", []string{"-L", "-n"}, true},
		{"/usr/sbin/ip6tables", []string{"-S"}, true},
		{"iptables", []string{"-A", "DOCKER-USER", "-j", "NOO-EGRESS"}, false},
		{"iptables", []string{"-I", "DOCKER-USER", "1", "-j", "NOO-EGRESS"}, false},
		{"iptables", []string{"-N", "NOO-EGRESS"}, false},
		{"iptables", []string{"-F"}, false},
		{"iptables", []string{"-X", "NOO-EGRESS"}, false},
		{"iptables", []string{"-D", "FORWARD", "1"}, false},
		{"iptables", []string{"-P", "FORWARD", "ACCEPT"}, false},
		{"iptables", []string{"-Z"}, false},
		{"ip6tables", []string{"--append", "X"}, false},
		{"iptables-restore", []string{"--noflush"}, false},
		{"ip6tables-restore", nil, false},
		{"nft", []string{"list", "ruleset"}, true},
		{"nft", []string{"add", "table", "inet", "x"}, false},
		{"nft", []string{"delete", "table", "inet", "x"}, false},
		{"nft", []string{"flush", "ruleset"}, false},
		{"nft", []string{"-f", "x.nft"}, false},
		{"nft", []string{"list", "ruleset", "-f", "x"}, false},
		{"nft", []string{"foo"}, false},
		{"docker", []string{"info", "--format=json"}, true},
		{"docker", []string{"network", "ls", "--format=json"}, true},
		{"docker", []string{"network", "inspect", "a", "b"}, true},
		{"docker", []string{"network", "create", "noo-egress"}, false},
		{"docker", []string{"network", "connect", "a", "b"}, false},
		{"docker", []string{"network", "rm", "a"}, false},
		{"docker", []string{"run", "x"}, false},
		{"docker", []string{"rm", "-f", "x"}, false},
		{"conntrack", []string{"-E", "-e", "NEW,DESTROY", "-o", "timestamp,extended,id"}, true},
		{"conntrack", []string{"--version"}, true},
		{"conntrack", []string{"-F"}, false},
		{"conntrack", []string{"-D", "-s", "1.1.1.1"}, false},
		{"sysctl", []string{"-w", "net.netfilter.nf_conntrack_acct=1"}, false},
		{"bash", []string{"-c", "true"}, false},
	}
	for _, tc := range cases {
		err := CheckReadOnly(tc.name, tc.args)
		if (err == nil) != tc.ok {
			t.Errorf("%s %v: err=%v want ok=%v", tc.name, tc.args, err, tc.ok)
		}
	}
}

func TestGuardRunnerRefusesBeforeTheInnerRunner(t *testing.T) {
	inner := newFake(t, nil)
	g := GuardRunner{Inner: inner}
	rc, out := g.Capture(context.Background(), "", "iptables", "-A", "DOCKER-USER", "-j", "ACCEPT")
	if rc == 0 || !strings.Contains(out, "refused") || len(inner.calls) != 0 {
		t.Fatalf("rc=%d out=%q inner calls=%v", rc, out, inner.calls)
	}
	if _, _, _, err := GuardStreamer(feedStream(nil, nil, false))(context.Background(), "nft", "flush", "ruleset"); err == nil {
		t.Fatal("stream guard let a write through")
	}
}

type testEnv struct {
	env    Env
	out    *bytes.Buffer
	errw   *bytes.Buffer
	runner *fakeRunner
	sysctl *memSysctl
}

func newEnv(t *testing.T, mut func(map[string]fakeAns), root bool, st Streamer) *testEnv {
	m := baseTable()
	m["conntrack --version"] = fakeAns{0, "conntrack v1.4.8"}
	if mut != nil {
		mut(m)
	}
	te := &testEnv{out: &bytes.Buffer{}, errw: &bytes.Buffer{}, runner: newFake(t, m), sysctl: &memSysctl{val: "0", orig: "0"}}
	clk := &clock{t: time.Unix(1700000000, 0)}
	if st == nil {
		st = feedStream(obsLines(), nil, false)
	}
	te.env = Env{Out: te.out, Err: te.errw, Runner: GuardRunner{Inner: te.runner}, Stream: GuardStreamer(st), Sysctl: te.sysctl,
		Now: clk.Now, IsRoot: func() bool { return root }, Getenv: func(string) string { return "" }}
	return te
}

func TestPlanTextWithoutObserve(t *testing.T) {
	te := newEnv(t, nil, false, nil)
	if err := Run(context.Background(), []string{"plan"}, te.env); err != nil {
		t.Fatal(err)
	}
	o := te.out.String()
	for _, want := range []string{"READ-ONLY", "iptables-legacy", "NOO-EGRESS", "noo-gateway", "noo-egress network; that network is NOT created yet", "already in DOCKER-USER (v4, never touched): -A DOCKER-USER -s 203.0.113.0/24 -j DROP", "FORWARD policy:     DROP"} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q in:\n%s", want, o)
		}
	}
	if strings.Contains(o, "== Observation") {
		t.Error("no observation was asked for")
	}
	if len(te.sysctl.sets) != 0 {
		t.Errorf("plan without --observe wrote the sysctl: %v", te.sysctl.sets)
	}
	for _, c := range te.runner.calls {
		if strings.HasPrefix(c, "conntrack") {
			t.Errorf("plan without --observe ran %s", c)
		}
	}
}

func TestPlanJSON(t *testing.T) {
	te := newEnv(t, nil, false, nil)
	if err := Run(context.Background(), []string{"plan", "--json"}, te.env); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(te.out.Bytes(), &rep); err != nil {
		t.Fatalf("%v\n%s", err, te.out.String())
	}
	if rep.Plan.Rules.RestoreV4 != goldenV4 || rep.Observation != nil {
		t.Errorf("%+v", rep)
	}
}

func TestNotApplicableText(t *testing.T) {
	te := newEnv(t, func(m map[string]fakeAns) {
		m["docker info --format=json"] = fakeAns{0, `{"OperatingSystem":"Docker Desktop","SecurityOptions":[]}`}
	}, false, nil)
	if err := Run(context.Background(), []string{"plan"}, te.env); err != nil {
		t.Fatal(err)
	}
	o := te.out.String()
	if !strings.Contains(o, "not applicable: Docker Desktop; no filter can be applied here") || strings.Contains(o, "iptables-restore") {
		t.Errorf("%s", o)
	}
	te = newEnv(t, func(m map[string]fakeAns) {
		m["docker network inspect"] = fakeAns{0, `[{"Name":"noo-cluster","Labels":{},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]},"Containers":{}}]`}
	}, false, nil)
	_ = Run(context.Background(), []string{"plan"}, te.env)
	if !strings.Contains(te.out.String(), "not applicable: no noomesh containers on this node") {
		t.Errorf("%s", te.out.String())
	}
}

func TestUnknownIsNeverPrintedAsNothingToDo(t *testing.T) {
	te := newEnv(t, func(m map[string]fakeAns) { delete(m, "docker info --format=json") }, false, nil)
	_ = Run(context.Background(), []string{"plan"}, te.env)
	o := te.out.String()
	if !strings.Contains(o, "COULD NOT MEASURE") || strings.Contains(o, "no noomesh containers") || strings.Contains(o, "not applicable") {
		t.Errorf("a failed measurement must not read as 'nothing to do':\n%s", o)
	}
}

func TestObserveRefusesWithoutRoot(t *testing.T) {
	te := newEnv(t, nil, false, nil)
	err := Run(context.Background(), []string{"plan", "--observe", "1m"}, te.env)
	if err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("%v", err)
	}
	if len(te.runner.calls) != 0 || len(te.sysctl.sets) != 0 {
		t.Errorf("a refused observe must do nothing: calls=%v sets=%v", te.runner.calls, te.sysctl.sets)
	}
}

func TestObserveDurationBounds(t *testing.T) {
	for _, d := range []string{"0s", "-5m", "25h", "soon"} {
		te := newEnv(t, nil, true, nil)
		if err := Run(context.Background(), []string{"plan", "--observe", d}, te.env); err == nil {
			t.Errorf("--observe %s accepted", d)
		}
		if len(te.sysctl.sets) != 0 {
			t.Errorf("--observe %s touched the sysctl", d)
		}
	}
}

func TestObserveWithoutConntrackPrintsPlanAndSaysSo(t *testing.T) {
	te := newEnv(t, func(m map[string]fakeAns) { delete(m, "conntrack --version") }, true, nil)
	err := Run(context.Background(), []string{"plan", "--observe", "1m"}, te.env)
	if err == nil || !strings.Contains(err.Error(), "needs conntrack-tools") {
		t.Fatalf("%v", err)
	}
	o := te.out.String()
	if !strings.Contains(o, "-A NOO-EGRESS") || !strings.Contains(o, "NOT OBSERVED") || strings.Contains(o, "No flow from") {
		t.Errorf("plan must print, observation must say it did not happen:\n%s", o)
	}
	if len(te.sysctl.sets) != 0 {
		t.Errorf("sysctl touched without conntrack: %v", te.sysctl.sets)
	}
}

func TestObserveEndToEnd(t *testing.T) {
	te := newEnv(t, nil, true, feedStream([]string{
		newLine(1700000001, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 1),
		destroyLine(1700000003, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 10, 20, 1),
		newLine(1700000001, "ipv4", "tcp", "172.19.0.5", "93.184.216.34", 2, 443, 2),
	}, nil, false))
	if err := Run(context.Background(), []string{"plan", "--observe", "50ms"}, te.env); err != nil {
		t.Fatal(err)
	}
	o := te.out.String()
	for _, want := range []string{"== Observation", "WOULD DROP", "noo-postgres", "8.8.8.8", "443/tcp", "would pass (egress class)", "noo-gateway", "restored to 0", "egress-capture.sh"} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q:\n%s", want, o)
		}
	}
	if strings.Join(te.sysctl.sets, ",") != "1,0" {
		t.Errorf("sets=%v", te.sysctl.sets)
	}
	// Every command the whole run issued (the fake already failed the test on a
	// write verb); also the guard agrees.
	for _, c := range te.runner.calls {
		f := strings.Fields(c)
		if err := CheckReadOnly(f[0], f[1:]); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}

func TestObserveStreamFailureIsAnErrorWithPlanStillPrinted(t *testing.T) {
	te := newEnv(t, nil, true, feedStream(nil, errors.New("permission denied"), false))
	err := Run(context.Background(), []string{"plan", "--observe", "50ms"}, te.env)
	if err == nil {
		t.Fatal("expected failure")
	}
	if !strings.Contains(te.out.String(), "-A NOO-EGRESS") || !strings.Contains(te.out.String(), "NOT OBSERVED") || te.sysctl.val != "0" {
		t.Errorf("sysctl=%s\n%s", te.sysctl.val, te.out.String())
	}
}

func TestUsageForUnknownSubcommand(t *testing.T) {
	te := newEnv(t, nil, false, nil)
	if err := Run(context.Background(), []string{"install"}, te.env); err == nil {
		t.Fatal("only plan exists")
	}
	if len(te.runner.calls) != 0 {
		t.Errorf("ran %v", te.runner.calls)
	}
}
