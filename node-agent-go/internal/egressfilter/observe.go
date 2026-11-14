// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Verdicts.
const (
	VerdictPass         = "would pass (egress class)"
	VerdictDrop         = "WOULD DROP"
	VerdictDropUnattrib = "WOULD DROP (unattributed)"
)

// RefreshEvery is how often the container-IP map is re-read from docker. IPs
// reorder when a container is recreated, so a map read once would misname
// flows.
const RefreshEvery = 10 * time.Second

// Event is one parsed conntrack line.
type Event struct {
	Time     time.Time
	Kind     string // NEW | DESTROY
	Proto    string
	Src, Dst netip.Addr
	Sport    string
	Dport    string
	BytesOut uint64
	BytesIn  uint64
	HasBytes bool
	ID       string
}

var (
	tsRe   = regexp.MustCompile(`^\s*\[(\d+)\.(\d+)\]`)
	kindRe = regexp.MustCompile(`\[(NEW|DESTROY)\]`)
)

// ParseEvent parses a line of `conntrack -E -o timestamp,extended,id`. The
// ORIGINAL direction is the first src/dst/sport/dport group; the first bytes=
// is bytes out, the second bytes in. ok is false for anything it does not
// understand; the caller counts those instead of dropping them silently.
func ParseEvent(line string) (Event, bool) {
	var ev Event
	m := tsRe.FindStringSubmatch(line)
	if m == nil {
		return ev, false
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	ev.Time = time.Unix(sec, 0)
	k := kindRe.FindStringSubmatch(line)
	if k == nil {
		return ev, false
	}
	ev.Kind = k[1]
	fields := strings.Fields(line)
	for i, f := range fields {
		if (f == "ipv4" || f == "ipv6") && i+2 < len(fields) {
			ev.Proto = fields[i+2]
			break
		}
	}
	if ev.Proto == "" {
		return ev, false
	}
	var haveSrc, haveDst bool
	var bytes []uint64
	for _, f := range fields {
		key, val, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch key {
		case "src":
			if !haveSrc {
				a, err := netip.ParseAddr(val)
				if err != nil {
					return ev, false
				}
				ev.Src, haveSrc = a.Unmap(), true
			}
		case "dst":
			if !haveDst {
				a, err := netip.ParseAddr(val)
				if err != nil {
					return ev, false
				}
				ev.Dst, haveDst = a.Unmap(), true
			}
		case "sport":
			if ev.Sport == "" {
				ev.Sport = val
			}
		case "dport":
			if ev.Dport == "" {
				ev.Dport = val
			}
		case "bytes":
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				bytes = append(bytes, n)
			}
		case "id":
			ev.ID = val // last one wins: ICMP has its own id= inside the tuple
		}
	}
	if !haveSrc || !haveDst {
		return ev, false
	}
	if ev.Dport == "" {
		ev.Dport = "0"
	}
	if len(bytes) >= 2 {
		ev.BytesOut, ev.BytesIn, ev.HasBytes = bytes[0], bytes[1], true
	}
	return ev, true
}

// Row is one line of the observation table.
type Row struct {
	Verdict   string    `json:"verdict"`
	Container string    `json:"container"`
	Dst       string    `json:"dst"`
	Port      string    `json:"port"`
	Proto     string    `json:"proto"`
	Flows     int       `json:"flows"`
	BytesOut  uint64    `json:"bytes_out"`
	BytesIn   uint64    `json:"bytes_in"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

type rowKey struct{ verdict, container, dst, port, proto string }

type openFlow struct{ row *Row }

// Observer classifies events against the current network and container maps.
type Observer struct {
	Now     func() time.Time
	Refresh func(context.Context) ([]Network, error)

	subnets []netip.Prefix
	gateway map[netip.Addr]bool
	owner   map[netip.Addr]string
	private []netip.Prefix

	lastRefresh time.Time
	rows        map[rowKey]*Row
	open        map[string]openFlow

	Events          int
	Unparsed        int
	RefreshFailures int
	RefreshCount    int
}

// NewObserver seeds the maps from an already-measured network list.
func NewObserver(nets []Network, now func() time.Time, refresh func(context.Context) ([]Network, error)) *Observer {
	o := &Observer{Now: now, Refresh: refresh, rows: map[rowKey]*Row{}, open: map[string]openFlow{}}
	for _, s := range append(append([]string{}, PrivateV4...), PrivateV6...) {
		o.private = append(o.private, netip.MustParsePrefix(s))
	}
	o.setMaps(nets)
	o.lastRefresh = now()
	return o
}

func (o *Observer) setMaps(nets []Network) {
	o.subnets = nil
	o.gateway = map[netip.Addr]bool{}
	o.owner = map[netip.Addr]string{}
	for _, n := range nets {
		for _, s := range append(append([]string{}, n.Subnets4...), n.Subnets6...) {
			if p, err := netip.ParsePrefix(s); err == nil {
				o.subnets = append(o.subnets, p)
			}
		}
		for _, g := range n.Gateways {
			if a, err := netip.ParseAddr(g); err == nil {
				o.gateway[a] = true
			}
		}
		for _, c := range n.Containers {
			for _, a := range append(append([]string{}, c.IPv4...), c.IPv6...) {
				if ip, err := netip.ParseAddr(a); err == nil {
					o.owner[ip] = c.Name
				}
			}
		}
	}
}

func (o *Observer) maybeRefresh(ctx context.Context) {
	if o.Refresh == nil || o.Now().Sub(o.lastRefresh) < RefreshEvery {
		return
	}
	o.lastRefresh = o.Now()
	nets, err := o.Refresh(ctx)
	if err != nil {
		o.RefreshFailures++ // keep the old map; the count is reported
		return
	}
	o.RefreshCount++
	o.setMaps(nets)
}

func (o *Observer) inNoomesh(a netip.Addr) bool {
	for _, p := range o.subnets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (o *Observer) isPrivate(a netip.Addr) bool {
	if a.IsUnspecified() {
		return true
	}
	for _, p := range o.private {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// classify returns the verdict and container for a flow, or ok=false when the
// flow is not one the filter would see (source outside the noomesh subnets,
// the bridge gateway itself, or a private/local destination).
func (o *Observer) classify(ev Event) (verdict, container string, ok bool) {
	if !o.inNoomesh(ev.Src) || o.gateway[ev.Src] || o.isPrivate(ev.Dst) {
		return "", "", false
	}
	name, owned := o.owner[ev.Src]
	switch {
	case !owned:
		return VerdictDropUnattrib, "(unattributed " + ev.Src.String() + ")", true
	case IsEgressClass(name):
		return VerdictPass, name, true
	}
	return VerdictDrop, name, true
}

func flowKey(ev Event) string {
	if ev.ID != "" {
		return ev.ID
	}
	return strings.Join([]string{ev.Proto, ev.Src.String(), ev.Sport, ev.Dst.String(), ev.Dport}, "|")
}

func (o *Observer) row(verdict, container string, ev Event) *Row {
	k := rowKey{verdict, container, ev.Dst.String(), ev.Dport, ev.Proto}
	r := o.rows[k]
	if r == nil {
		r = &Row{Verdict: verdict, Container: container, Dst: k.dst, Port: k.port, Proto: k.proto, First: ev.Time, Last: ev.Time}
		o.rows[k] = r
	}
	if ev.Time.Before(r.First) {
		r.First = ev.Time
	}
	if ev.Time.After(r.Last) {
		r.Last = ev.Time
	}
	return r
}

// Handle consumes one parsed event.
func (o *Observer) Handle(ctx context.Context, ev Event) {
	o.Events++
	o.maybeRefresh(ctx)
	key := flowKey(ev)
	switch ev.Kind {
	case "NEW":
		v, c, ok := o.classify(ev)
		if !ok {
			return
		}
		r := o.row(v, c, ev)
		r.Flows++
		o.open[key] = openFlow{row: r}
	case "DESTROY":
		f, known := o.open[key]
		if known {
			delete(o.open, key)
			if f.row.Last.Before(ev.Time) {
				f.row.Last = ev.Time
			}
		} else {
			// Started before the observation: attribute it now.
			v, c, ok := o.classify(ev)
			if !ok {
				return
			}
			f = openFlow{row: o.row(v, c, ev)}
			f.row.Flows++
		}
		if ev.HasBytes {
			f.row.BytesOut += ev.BytesOut
			f.row.BytesIn += ev.BytesIn
		}
	}
}

// OpenFlows is how many flows were still open (no DESTROY seen) at the end;
// their bytes are not counted.
func (o *Observer) OpenFlows() int { return len(o.open) }

// Rows returns the table, WOULD DROP first, then by bytes out.
func (o *Observer) Rows() []Row {
	rank := map[string]int{VerdictDrop: 0, VerdictDropUnattrib: 1, VerdictPass: 2}
	out := make([]Row, 0, len(o.rows))
	for _, r := range o.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Verdict] != rank[b.Verdict] {
			return rank[a.Verdict] < rank[b.Verdict]
		}
		if a.BytesOut != b.BytesOut {
			return a.BytesOut > b.BytesOut
		}
		return a.Container+a.Dst < b.Container+b.Dst
	})
	return out
}

// Observation is the outcome of an --observe run.
type Observation struct {
	Requested       string `json:"requested"`
	ElapsedSeconds  int    `json:"elapsed_seconds"`
	EndedEarly      bool   `json:"ended_early"`
	Complete        bool   `json:"complete"` // false: the tracker stream died; the rows are partial
	Failure         string `json:"failure,omitempty"`
	Events          int    `json:"conntrack_events"`
	Unparsed        int    `json:"unparsed_events"`
	OpenFlows       int    `json:"open_flows_bytes_not_counted"`
	RefreshFailures int    `json:"ip_map_refresh_failures"`
	BytesCounted    bool   `json:"bytes_counted"`
	AcctRestored    string `json:"acct_restored_to,omitempty"`
	Rows            []Row  `json:"rows"`
}

// Observe runs the conntrack stream for d (or until ctx is cancelled, which is
// Ctrl-C), counting bytes via nf_conntrack_acct. It sets the sysctl to 1 and
// restores it on EVERY return path, including a panic. The error is non-nil
// when nothing trustworthy could be observed.
func Observe(ctx context.Context, d time.Duration, nets []Network, stream Streamer, sc Sysctl, now func() time.Time, refreshNets func(context.Context) ([]Network, error)) (obs *Observation, err error) {
	obs = &Observation{Requested: d.String()}
	prev, gerr := sc.Get()
	if gerr == nil {
		prev = strings.TrimSpace(prev)
		if prev != "1" {
			if serr := sc.Set("1"); serr == nil {
				obs.BytesCounted = true
				defer func() {
					if rerr := sc.Set(prev); rerr != nil {
						err = errors.Join(err, fmt.Errorf("could not restore nf_conntrack_acct to %s: %v", prev, rerr))
					} else {
						obs.AcctRestored = prev
					}
				}()
			}
		} else {
			obs.BytesCounted = true
		}
	}

	start := now()
	defer func() { obs.ElapsedSeconds = int(now().Sub(start).Seconds()) }()

	runCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	out, wait, stderr, serr := stream(runCtx, "conntrack", "-E", "-e", "NEW,DESTROY", "-o", "timestamp,extended,id")
	if serr != nil {
		obs.Failure = "could not start conntrack: " + serr.Error()
		return obs, errors.New(obs.Failure)
	}
	o := NewObserver(nets, now, refreshNets)
	sc2 := bufio.NewScanner(out)
	sc2.Buffer(make([]byte, 64*1024), 1<<20)
	for sc2.Scan() {
		ev, ok := ParseEvent(sc2.Text())
		if !ok {
			o.Events++
			o.Unparsed++
			continue
		}
		o.Handle(runCtx, ev)
	}
	_ = out.Close()
	werr := wait()

	obs.Events, obs.Unparsed, obs.OpenFlows, obs.RefreshFailures = o.Events, o.Unparsed, o.OpenFlows(), o.RefreshFailures
	obs.Rows = o.Rows()
	switch {
	case ctx.Err() != nil:
		obs.EndedEarly, obs.Complete = true, true // Ctrl-C: what was seen is complete up to now
	case runCtx.Err() != nil:
		obs.Complete = true // the full duration elapsed
	default:
		msg := strings.TrimSpace(stderr())
		if msg == "" && werr != nil {
			msg = werr.Error()
		}
		obs.Failure = "conntrack exited before the duration ended: " + msg
		return obs, errors.New(obs.Failure)
	}
	if obs.Events == 0 {
		obs.Failure = "the connection tracker reported no events at all in this time; nothing was observed (is this the host's network namespace, and is traffic flowing?)"
		obs.Complete = false
		return obs, errors.New(obs.Failure)
	}
	return obs, nil
}
