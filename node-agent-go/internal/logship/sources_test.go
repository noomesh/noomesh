// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// ── tailer ───────────────────────────────────────────────────────────────

func TestTailerStartsAtTheEndThenFollowsAndSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "journal.follow")
	if err := os.WriteFile(p, []byte("old-1\nold-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	emit := func(l string) { got = append(got, l) }
	tl := newTailer(p, filepath.Join(dir, "offset"))
	tl.readOnce(emit)
	if len(got) != 0 {
		t.Fatalf("first sight must not ship history, got %v", got)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("new-1\npartial")
	f.Close()
	tl.readOnce(emit)
	if strings.Join(got, ",") != "new-1" {
		t.Fatalf("after append: %v", got)
	}
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("-done\n")
	f.Close()
	tl.readOnce(emit)
	if strings.Join(got, ",") != "new-1,partial-done" {
		t.Fatalf("partial line must complete: %v", got)
	}

	// Rotate: rename to .1, write a fresh file; the tail of .1 is read first.
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("tail-of-old\n")
	f.Close()
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("fresh-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tl.readOnce(emit)
	if strings.Join(got, ",") != "new-1,partial-done,tail-of-old,fresh-1" {
		t.Fatalf("after rotation: %v", got)
	}

	// The offset persists: a new tailer over the same offset file resumes.
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("fresh-2\n")
	f.Close()
	var got2 []string
	tl2 := newTailer(p, filepath.Join(dir, "offset"))
	tl2.readOnce(func(l string) { got2 = append(got2, l) })
	if strings.Join(got2, ",") != "fresh-2" {
		t.Fatalf("resume from persisted offset: %v", got2)
	}

	// Truncation restarts at 0.
	if err := os.WriteFile(p, []byte("after-truncate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got2 = nil
	tl2.readOnce(func(l string) { got2 = append(got2, l) })
	if strings.Join(got2, ",") != "after-truncate" {
		t.Fatalf("after truncation: %v", got2)
	}
}

// ── journal records ──────────────────────────────────────────────────────

func TestParseJournalLine(t *testing.T) {
	e, ok := ParseJournalLine(`{"__CURSOR":"s=1","__REALTIME_TIMESTAMP":"1700000000123456","_SYSTEMD_UNIT":"docker.service","PRIORITY":"3","MESSAGE":"GPU has fallen off the bus"}`)
	if !ok {
		t.Fatal("record not parsed")
	}
	if e.Labels != (Labels{Source: SourceJournal, Name: "docker", Stream: StreamJournal, Level: "error"}) {
		t.Fatalf("labels = %+v", e.Labels)
	}
	if e.TS != 1700000000123456000 || e.Line != "GPU has fallen off the bus" {
		t.Fatalf("entry = %+v", e)
	}
	// A level word in the MESSAGE wins over PRIORITY.
	e, _ = ParseJournalLine(`{"__REALTIME_TIMESTAMP":"1","_SYSTEMD_UNIT":"noo-node-agent.service","PRIORITY":"6","MESSAGE":"{\"level\":\"WARN\",\"msg\":\"x\"}"}`)
	if e.Labels.Level != "warn" || e.Labels.Name != "noo-node-agent" {
		t.Fatalf("labels = %+v", e.Labels)
	}
	// Byte-array MESSAGE (non-UTF-8) is decoded; no MESSAGE is skipped.
	e, ok = ParseJournalLine(`{"_SYSTEMD_UNIT":"noo-hostd.service","MESSAGE":[104,105]}`)
	if !ok || e.Line != "hi" {
		t.Fatalf("byte-array message: %v %+v", ok, e)
	}
	if _, ok := ParseJournalLine(`{"_SYSTEMD_UNIT":"noo-hostd.service"}`); ok {
		t.Fatal("a record without MESSAGE must be skipped")
	}
	if _, ok := ParseJournalLine(`not json`); ok {
		t.Fatal("junk must be skipped")
	}
}

// With no units configured the agent names none, so hostd follows its OWN
// allowlist: an agent newer than hostd must not ask for a unit the older
// daemon does not know (it refuses the whole op and nothing ships).
func TestJournalSourceWithNoUnitsLetsHostdChoose(t *testing.T) {
	spool := t.TempDir()
	j := NewJournalSource(spool, t.TempDir(), nil)
	hb := hostd.Heartbeat{TS: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Interval: 15, Ops: []string{"journal-follow"}}
	b, _ := json.Marshal(hb)
	if err := os.WriteFile(filepath.Join(spool, hostd.HeartbeatFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	j.check(context.Background())
	cmds, _ := filepath.Glob(filepath.Join(spool, "journal-follow-*.cmd.json"))
	if len(cmds) != 1 {
		t.Fatalf("expected one queued command, got %v", cmds)
	}
	raw, _ := os.ReadFile(cmds[0])
	c, err := hostd.ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Args) != 0 {
		t.Fatalf("no configured units must send no units= arg, got %v", c.Args)
	}
	// And hostd reads "no units" as its whole allowlist.
	if units, err := hostd.ParseFollowUnitsForTest(c.Args); err != nil || len(units) == 0 {
		t.Fatalf("hostd default units = %v, %v", units, err)
	}
}

// The journal source asks hostd for the op exactly as hostd's allowlist
// expects, and only when the heartbeat says nothing is following.
func TestJournalSourceRequestsTheFollowerFromHostd(t *testing.T) {
	spool := t.TempDir()
	j := NewJournalSource(spool, t.TempDir(), []string{"noo-hostd", "docker"})
	ctx := context.Background()

	j.check(ctx)
	if !strings.Contains(j.Status(), "no hostd heartbeat") {
		t.Fatalf("status = %q", j.Status())
	}
	writeHB := func(ops []string, jf *hostd.JournalFollowState) {
		hb := hostd.Heartbeat{TS: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Interval: 15, Ops: ops, JournalFollow: jf}
		b, _ := json.Marshal(hb)
		if err := os.WriteFile(filepath.Join(spool, hostd.HeartbeatFile), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeHB([]string{"unit-logs"}, nil)
	j.check(ctx)
	if !strings.Contains(j.Status(), "predates journal-follow") {
		t.Fatalf("status = %q", j.Status())
	}
	if m, _ := filepath.Glob(filepath.Join(spool, "*.cmd.json")); len(m) != 0 {
		t.Fatal("must not queue an op an old daemon cannot run")
	}

	writeHB([]string{"unit-logs", "journal-follow"}, nil)
	j.check(ctx)
	cmds, _ := filepath.Glob(filepath.Join(spool, "journal-follow-*.cmd.json"))
	if len(cmds) != 1 {
		t.Fatalf("expected one queued command, got %v", cmds)
	}
	b, _ := os.ReadFile(cmds[0])
	c, err := hostd.ParseCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Op != "journal-follow" || c.Service != "noo-node-agent" || strings.Join(c.Args, " ") != "units=noo-hostd,docker" {
		t.Fatalf("command = %+v", c)
	}
	if j.Status() != "requested" {
		t.Fatalf("status = %q", j.Status())
	}
	// Rate-limited: a second check within a minute queues nothing more.
	j.check(ctx)
	if cmds, _ := filepath.Glob(filepath.Join(spool, "journal-follow-*.cmd.json")); len(cmds) != 1 {
		t.Fatalf("re-request within a minute: %v", cmds)
	}
	// Running: content.
	writeHB([]string{"journal-follow"}, &hostd.JournalFollowState{Running: true})
	j.check(ctx)
	if j.Status() != "running" {
		t.Fatalf("status = %q", j.Status())
	}
}

// ── docker source ────────────────────────────────────────────────────────

// frame builds one stdcopy frame.
func frame(stream byte, s string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(s)))
	return append(hdr, s...)
}

type fakeDocker struct {
	mu      sync.Mutex
	targets []ContainerTarget
	streams map[string][]byte
	sinces  map[string][]string
	tty     bool
}

func (f *fakeDocker) LogTargets(context.Context) ([]ContainerTarget, error) { return f.targets, nil }
func (f *fakeDocker) FollowLogs(ctx context.Context, name, since string) (io.ReadCloser, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sinces == nil {
		f.sinces = map[string][]string{}
	}
	f.sinces[name] = append(f.sinces[name], since)
	b, ok := f.streams[name]
	if !ok {
		return nil, false, errors.New("no such container")
	}
	return io.NopCloser(bytes.NewReader(b)), f.tty, nil
}
func (f *fakeDocker) ContainerStarts(ctx context.Context) (<-chan ContainerTarget, <-chan error) {
	out := make(chan ContainerTarget)
	errs := make(chan error, 1)
	go func() { <-ctx.Done() }()
	return out, errs
}

func TestDockerSourceDemuxesStreamsAndStripsTimestamps(t *testing.T) {
	var stream []byte
	stream = append(stream, frame(1, "2026-09-28T10:00:00.000000001Z INFO started\n")...)
	stream = append(stream, frame(2, "2026-09-28T10:00:01.000000002Z ERROR boom\n")...)
	stream = append(stream, frame(1, "no timestamp here\n")...)
	fd := &fakeDocker{
		targets: []ContainerTarget{{Name: "noo-gateway", ComposeService: "gateway"}},
		streams: map[string][]byte{"noo-gateway": stream},
	}
	src := NewDockerSource(fd)
	var mu sync.Mutex
	var got []Entry
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.attachAll(ctx, func(e Entry) { mu.Lock(); got = append(got, e); mu.Unlock() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	byLine := map[string]Entry{}
	for _, e := range got {
		byLine[e.Line] = e
	}
	a := byLine["INFO started"]
	if a.Labels != (Labels{Source: SourceDocker, Name: "noo-gateway", Stream: StreamStdout, Level: "info", ComposeService: "gateway"}) || a.TS != time.Date(2026, 9, 28, 10, 0, 0, 1, time.UTC).UnixNano() {
		t.Fatalf("stdout entry = %+v", a)
	}
	b := byLine["ERROR boom"]
	if b.Labels.Stream != StreamStderr || b.Labels.Level != "error" {
		t.Fatalf("stderr entry = %+v", b)
	}
	if c, ok := byLine["no timestamp here"]; !ok || c.TS == 0 {
		t.Fatalf("untimestamped line = %+v", c)
	}
	// The first attach began at now-minus-a-window, not at the beginning of time.
	since, err := time.Parse(time.RFC3339Nano, fd.sinces["noo-gateway"][0])
	if err != nil || time.Since(since) > time.Minute || time.Since(since) < 20*time.Second {
		t.Fatalf("first since = %q (%v)", fd.sinces["noo-gateway"][0], err)
	}
	// The stream ended (container stopped): a re-attach resumes after the
	// last timestamp seen, so nothing is shipped twice.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		src.mu.Lock()
		att := src.attached["noo-gateway"]
		src.mu.Unlock()
		if !att {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	src.attachAll(ctx, func(Entry) {})
	// The untimestamped line was stamped at read time, so the last seen
	// timestamp is "a moment ago" — the re-attach resumes just after it,
	// not from the 30 s window again.
	s := fd.sinces["noo-gateway"]
	if len(s) != 2 {
		t.Fatalf("re-attach since = %v", s)
	}
	since2, err := time.Parse(time.RFC3339Nano, s[1])
	if err != nil || !since2.After(since.Add(20*time.Second)) || time.Since(since2) > 5*time.Second {
		t.Fatalf("re-attach must resume after the last seen timestamp: first %s, second %s (%v)", s[0], s[1], err)
	}
}

func TestSplitDockerTimestamp(t *testing.T) {
	ts, line := splitDockerTimestamp("2026-09-28T10:00:00.5Z  two spaces\r")
	if line != "two spaces" || ts.Nanosecond() != 500_000_000 {
		t.Fatalf("%v %q", ts, line)
	}
	if _, line := splitDockerTimestamp("plain"); line != "plain" {
		t.Fatalf("%q", line)
	}
}

func TestScanLinesCapsAnOverlongLine(t *testing.T) {
	long := strings.Repeat("a", (1<<20)+100)
	var got []string
	scanLines(strings.NewReader("short\n"+long+"\nafter\n"), func(l string) { got = append(got, l) })
	if len(got) != 3 || got[0] != "short" || len(got[1]) != 1<<20 || got[2] != "after" {
		t.Fatalf("got %d lines; lens %v", len(got), func() []int {
			var o []int
			for _, g := range got {
				o = append(o, len(g))
			}
			return o
		}())
	}
}
