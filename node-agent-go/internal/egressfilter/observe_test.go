// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func newLine(ts int, family, proto, src, dst string, sport, dport int, id int) string {
	return fmt.Sprintf("[%d.100000]\t    [NEW] %s     2 %s      6 120 SYN_SENT src=%s dst=%s sport=%d dport=%d [UNREPLIED] src=%s dst=%s sport=%d dport=%d id=%d",
		ts, family, proto, src, dst, sport, dport, dst, src, dport, sport, id)
}

func destroyLine(ts int, family, proto, src, dst string, sport, dport int, out, in uint64, id int) string {
	return fmt.Sprintf("[%d.200000]\t    [DESTROY] %s     2 %s      6 src=%s dst=%s sport=%d dport=%d packets=10 bytes=%d src=%s dst=%s sport=%d dport=%d packets=12 bytes=%d [ASSURED] id=%d",
		ts, family, proto, src, dst, sport, dport, out, dst, src, dport, sport, in, id)
}

func TestParseEvent(t *testing.T) {
	ev, ok := ParseEvent(newLine(1700000000, "ipv4", "tcp", "172.19.0.5", "93.184.216.34", 40000, 443, 111))
	if !ok || ev.Kind != "NEW" || ev.Proto != "tcp" || ev.Src.String() != "172.19.0.5" || ev.Dst.String() != "93.184.216.34" || ev.Dport != "443" || ev.ID != "111" || ev.HasBytes {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
	ev, ok = ParseEvent(destroyLine(1700000010, "ipv4", "udp", "172.19.0.5", "1.1.1.1", 5000, 53, 1500, 9000, 7))
	if !ok || ev.Kind != "DESTROY" || ev.Proto != "udp" || ev.BytesOut != 1500 || ev.BytesIn != 9000 || !ev.HasBytes || ev.ID != "7" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
	// IPv6, and ICMP with its own id= inside the tuple: the LAST id= is conntrack's.
	ev, ok = ParseEvent(`[1700000000.5]	    [NEW] ipv6     10 icmpv6   58 30 src=fd00:19::5 dst=2606:4700::1111 type=128 code=0 id=4242 [UNREPLIED] src=2606:4700::1111 dst=fd00:19::5 type=129 code=0 id=4242 id=999`)
	if !ok || ev.Proto != "icmpv6" || ev.Dst.String() != "2606:4700::1111" || ev.Dport != "0" || ev.ID != "999" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
	for _, bad := range []string{"", "garbage", "[1.0] [NEW]", "[1700000000.1] [UPDATE] ipv4 2 tcp 6 src=1.1.1.1 dst=2.2.2.2", "[1700000000.1] [NEW] ipv4 2 tcp 6 src=nope dst=2.2.2.2"} {
		if _, ok := ParseEvent(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

// observerNets: noo-cluster v4+v6 with a gateway container, a postgres and
// browser, and a workload container.
func observerNets() []Network {
	return []Network{{
		Name: "noo-cluster", Subnets4: []string{"172.19.0.0/16"}, Subnets6: []string{"fd00:19::/64"}, Gateways: []string{"172.19.0.1"},
		Containers: []Attached{
			{Name: "noo-gateway", IPv4: []string{"172.19.0.5"}, IPv6: []string{"fd00:19::5"}},
			{Name: "noo-postgres", IPv4: []string{"172.19.0.2"}},
		},
	}}
}

func TestObserverClassification(t *testing.T) {
	clk := &clock{t: time.Unix(1700000000, 0)}
	o := NewObserver(observerNets(), clk.Now, nil)
	ctx := context.Background()
	feed := func(lines ...string) {
		for _, l := range lines {
			ev, ok := ParseEvent(l)
			if !ok {
				t.Fatalf("unparsed %q", l)
			}
			o.Handle(ctx, ev)
		}
	}
	feed(
		// egress class, with bytes from DESTROY
		newLine(1700000001, "ipv4", "tcp", "172.19.0.5", "93.184.216.34", 40000, 443, 1),
		destroyLine(1700000009, "ipv4", "tcp", "172.19.0.5", "93.184.216.34", 40000, 443, 1500, 9000, 1),
		// non-egress container
		newLine(1700000002, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 41000, 443, 2),
		destroyLine(1700000005, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 41000, 443, 100, 200, 2),
		// a noomesh address no container owns
		newLine(1700000003, "ipv4", "udp", "172.19.0.77", "1.1.1.1", 5000, 53, 3),
		// private destination: ignored
		newLine(1700000003, "ipv4", "tcp", "172.19.0.2", "10.1.2.3", 41001, 5432, 4),
		// public destination but source is NOT a noomesh subnet: ignored
		newLine(1700000003, "ipv4", "tcp", "192.168.1.9", "8.8.8.8", 41002, 443, 5),
		// the bridge gateway (host traffic): ignored
		newLine(1700000003, "ipv4", "tcp", "172.19.0.1", "8.8.8.8", 41003, 443, 6),
		// v6 egress class, then v6 from a non-egress unowned address
		newLine(1700000004, "ipv6", "tcp", "fd00:19::5", "2606:4700::1111", 42000, 443, 7),
		newLine(1700000004, "ipv6", "tcp", "fd00:19::9", "2606:4700::1111", 42001, 443, 8),
	)
	rows := o.Rows()
	if len(rows) != 5 {
		t.Fatalf("rows=%d: %+v", len(rows), rows)
	}
	// Order: WOULD DROP, unattributed, pass.
	want := []struct {
		verdict, container, dst, port, proto string
		flows                                int
		out, in                              uint64
	}{
		{VerdictDrop, "noo-postgres", "8.8.8.8", "443", "tcp", 1, 100, 200},
		{VerdictDropUnattrib, "(unattributed 172.19.0.77)", "1.1.1.1", "53", "udp", 1, 0, 0},
		{VerdictDropUnattrib, "(unattributed fd00:19::9)", "2606:4700::1111", "443", "tcp", 1, 0, 0},
		{VerdictPass, "noo-gateway", "93.184.216.34", "443", "tcp", 1, 1500, 9000},
	}
	got := map[string]Row{}
	for _, r := range rows {
		got[r.Container+"|"+r.Dst] = r
	}
	for _, w := range want[:2] {
		r, ok := got[w.container+"|"+w.dst]
		if !ok || r.Verdict != w.verdict || r.Port != w.port || r.Proto != w.proto || r.Flows != w.flows || r.BytesOut != w.out || r.BytesIn != w.in {
			t.Errorf("row %v: %+v", w, r)
		}
	}
	if r := got["noo-gateway|93.184.216.34"]; r.Verdict != VerdictPass || r.BytesOut != 1500 || r.BytesIn != 9000 {
		t.Errorf("egress class row: %+v", r)
	}
	if r := got["noo-gateway|2606:4700::1111"]; r.Verdict != VerdictPass {
		t.Errorf("v6 egress class row: %+v", r)
	}
	if r := got["(unattributed fd00:19::9)|2606:4700::1111"]; r.Verdict != VerdictDropUnattrib {
		t.Errorf("v6 unattributed row: %+v", r)
	}
	// Sorted: every WOULD DROP before every pass.
	seenPass := false
	for _, r := range rows {
		if r.Verdict == VerdictPass {
			seenPass = true
		} else if seenPass {
			t.Errorf("a drop row after a pass row: %+v", rows)
		}
	}
	// Flows 7 and 8 never saw a DESTROY.
	if o.OpenFlows() != 3 {
		t.Errorf("open flows=%d want 3 (ids 3,7,8)", o.OpenFlows())
	}
}

func TestDestroyWithoutNewIsAttributedAtDestroy(t *testing.T) {
	clk := &clock{t: time.Unix(1700000000, 0)}
	o := NewObserver(observerNets(), clk.Now, nil)
	ev, _ := ParseEvent(destroyLine(1700000100, "ipv4", "tcp", "172.19.0.2", "9.9.9.9", 1, 443, 50, 60, 77))
	o.Handle(context.Background(), ev)
	rows := o.Rows()
	if len(rows) != 1 || rows[0].Verdict != VerdictDrop || rows[0].Flows != 1 || rows[0].BytesOut != 50 {
		t.Fatalf("%+v", rows)
	}
}

func TestIPMapChangesBetweenTwoFlows(t *testing.T) {
	clk := &clock{t: time.Unix(1700000000, 0)}
	calls := 0
	refresh := func(context.Context) ([]Network, error) {
		calls++
		// After recreate, 172.19.0.2 belongs to noo-worker (egress class) and
		// noo-postgres moved to .8.
		n := observerNets()
		n[0].Containers = []Attached{
			{Name: "noo-worker", IPv4: []string{"172.19.0.2"}},
			{Name: "noo-postgres", IPv4: []string{"172.19.0.8"}},
		}
		return []Network{n[0]}, nil
	}
	o := NewObserver(observerNets(), clk.Now, refresh)
	ctx := context.Background()
	first, _ := ParseEvent(newLine(1700000001, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 1))
	o.Handle(ctx, first)
	if calls != 0 {
		t.Fatal("refreshed before 10s")
	}
	clk.t = clk.t.Add(11 * time.Second)
	second, _ := ParseEvent(newLine(1700000012, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 2, 443, 2))
	o.Handle(ctx, second)
	if calls != 1 {
		t.Fatalf("refresh calls=%d", calls)
	}
	var drop, pass bool
	for _, r := range o.Rows() {
		if r.Container == "noo-postgres" && r.Verdict == VerdictDrop {
			drop = true
		}
		if r.Container == "noo-worker" && r.Verdict == VerdictPass {
			pass = true
		}
	}
	if !drop || !pass {
		t.Fatalf("the same IP must be attributed to whoever owned it at the time: %+v", o.Rows())
	}
}

func TestRefreshFailureKeepsOldMapAndIsCounted(t *testing.T) {
	clk := &clock{t: time.Unix(1700000000, 0)}
	o := NewObserver(observerNets(), clk.Now, func(context.Context) ([]Network, error) { return nil, errors.New("docker down") })
	clk.t = clk.t.Add(30 * time.Second)
	ev, _ := ParseEvent(newLine(1700000030, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 1))
	o.Handle(context.Background(), ev)
	if o.RefreshFailures != 1 || o.Rows()[0].Container != "noo-postgres" {
		t.Fatalf("failures=%d rows=%+v", o.RefreshFailures, o.Rows())
	}
}

func obsLines() []string {
	return []string{
		newLine(1700000001, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 1),
		destroyLine(1700000003, "ipv4", "tcp", "172.19.0.2", "8.8.8.8", 1, 443, 10, 20, 1),
	}
}

func runObserve(t *testing.T, st Streamer, sc Sysctl, d time.Duration, ctx context.Context) (*Observation, error) {
	clk := &clock{t: time.Unix(1700000000, 0)}
	return Observe(ctx, d, observerNets(), st, sc, clk.Now, nil)
}

func TestObserveSetsAcctAndRestoresIt(t *testing.T) {
	sc := &memSysctl{val: "0", orig: "0"}
	obs, err := runObserve(t, feedStream(obsLines(), nil, false), sc, 50*time.Millisecond, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sc.sets, ",") != "1,0" || sc.val != "0" || obs.AcctRestored != "0" || !obs.BytesCounted {
		t.Fatalf("sets=%v val=%s obs=%+v", sc.sets, sc.val, obs)
	}
	if !obs.Complete || len(obs.Rows) != 1 || obs.Rows[0].BytesOut != 10 {
		t.Fatalf("%+v", obs)
	}
}

func TestObserveLeavesAcctAloneWhenAlreadyOne(t *testing.T) {
	sc := &memSysctl{val: "1", orig: "1"}
	if _, err := runObserve(t, feedStream(obsLines(), nil, false), sc, 30*time.Millisecond, context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sc.sets) != 0 {
		t.Fatalf("wrote %v though it was already 1", sc.sets)
	}
}

func TestObserveRestoresOnEveryErrorPath(t *testing.T) {
	cases := []struct {
		name string
		st   Streamer
		cut  bool
	}{
		{"start fails", feedStream(nil, errors.New("exec: conntrack: not found"), false), false},
		{"conntrack dies early", feedStream(obsLines(), nil, true), false},
		{"no events at all", feedStream(nil, nil, false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := &memSysctl{val: "0", orig: "0"}
			obs, err := runObserve(t, tc.st, sc, 30*time.Millisecond, context.Background())
			if err == nil {
				t.Fatal("must be an error: nothing trustworthy was observed")
			}
			if sc.val != "0" || strings.Join(sc.sets, ",") != "1,0" {
				t.Fatalf("acct not restored: sets=%v val=%s", sc.sets, sc.val)
			}
			if obs.Failure == "" || obs.Complete {
				t.Fatalf("a failed observation must say so: %+v", obs)
			}
		})
	}
}

func TestObserveRestoreRunsOnPanic(t *testing.T) {
	sc := &memSysctl{val: "0", orig: "0"}
	st := func(ctx context.Context, name string, args ...string) (r io.ReadCloser, w func() error, e func() string, err error) {
		panic("boom")
	}
	func() {
		defer func() { _ = recover() }()
		clk := &clock{t: time.Unix(1700000000, 0)}
		_, _ = Observe(context.Background(), time.Second, observerNets(), Streamer(st), sc, clk.Now, nil)
	}()
	if sc.val != "0" {
		t.Fatalf("acct left at %s after a panic", sc.val)
	}
}

func TestObserveReportsRestoreFailure(t *testing.T) {
	sc := &memSysctl{val: "0", orig: "0", restErr: errors.New("read-only")}
	_, err := runObserve(t, feedStream(obsLines(), nil, false), sc, 30*time.Millisecond, context.Background())
	if err == nil || !strings.Contains(err.Error(), "could not restore nf_conntrack_acct") {
		t.Fatalf("a failed restore must be loud: %v", err)
	}
}

func TestObserveCtrlCEndsEarlyButIsComplete(t *testing.T) {
	sc := &memSysctl{val: "0", orig: "0"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	obs, err := runObserve(t, feedStream(obsLines(), nil, false), sc, time.Hour, ctx)
	if err != nil || !obs.EndedEarly || !obs.Complete || sc.val != "0" {
		t.Fatalf("err=%v obs=%+v val=%s", err, obs, sc.val)
	}
}

func TestObserveWithoutAcctSaysBytesNotCounted(t *testing.T) {
	sc := &memSysctl{val: "0", orig: "0", setErr: errors.New("EROFS")}
	obs, err := runObserve(t, feedStream(obsLines(), nil, false), sc, 30*time.Millisecond, context.Background())
	if err != nil || obs.BytesCounted {
		t.Fatalf("err=%v obs=%+v", err, obs)
	}
	var b strings.Builder
	writeObservation(&b, obs)
	if !strings.Contains(b.String(), "NOT counted") {
		t.Errorf("text must say bytes were not counted:\n%s", b.String())
	}
}

func TestNothingObservedNeverPrintsWouldDropNothing(t *testing.T) {
	var b strings.Builder
	writeObservation(&b, &Observation{Requested: "1m", Failure: "conntrack is not installed"})
	if strings.Contains(b.String(), "No flow") || !strings.Contains(b.String(), "NOT OBSERVED") {
		t.Errorf("%s", b.String())
	}
	b.Reset()
	writeObservation(&b, &Observation{Requested: "1m", Complete: true, Events: 40})
	if !strings.Contains(b.String(), "No flow from a noomesh subnet") {
		t.Errorf("a complete empty window should say what it covers:\n%s", b.String())
	}
}
