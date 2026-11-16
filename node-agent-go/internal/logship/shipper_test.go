// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── test server: records decoded bodies, answers a scripted status ──────

type ingest struct {
	mu       sync.Mutex
	bodies   []wireBody
	statuses []int // consumed in order; the last one repeats
	hits     int32
	headers  []http.Header
	retryAft string
}

func (s *ingest) status() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return 204
	}
	st := s.statuses[0]
	if len(s.statuses) > 1 {
		s.statuses = s.statuses[1:]
	}
	return st
}

func (s *ingest) handler(t *testing.T, node string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		if r.URL.Path != "/api/cluster/nodes/"+node+"/logs" {
			http.Error(w, "wrong path "+r.URL.Path, 404)
			return
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "not gzip", 400)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "bad gzip", 400)
			return
		}
		raw, _ := io.ReadAll(zr)
		var body wireBody
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		st := s.status()
		s.mu.Lock()
		s.headers = append(s.headers, r.Header.Clone())
		if st < 300 {
			s.bodies = append(s.bodies, body)
		}
		s.mu.Unlock()
		if s.retryAft != "" && (st == 429 || st >= 500) {
			w.Header().Set("Retry-After", s.retryAft)
		}
		w.WriteHeader(st)
	}
}

func (s *ingest) lines() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.bodies {
		for _, st := range b.Streams {
			n += len(st.Values)
		}
	}
	return n
}

func newShipper(t *testing.T, srv *httptest.Server, node string, tune func(*Config)) *Shipper {
	t.Helper()
	cfg := Config{
		NodeID:        node,
		ControllerURL: srv.URL,
		Client:        srv.Client(),
		Auth:          func(r *http.Request) error { r.Header.Set("Authorization", "Bearer test-token"); return nil },
		StateDir:      t.TempDir(),
		FlushEvery:    50 * time.Millisecond,
		FlushLines:    1000,
		RouteRetry:    100 * time.Millisecond,
		PushTimeout:   2 * time.Second,
	}
	if tune != nil {
		tune(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// runUntilCleanup runs s until the test ends, and the test does not end
// until Run has returned. On shutdown Run spills its in-flight batch into
// StateDir, and t.TempDir removes that directory in its own cleanup: a Run
// still writing then fails the test with "TempDir RemoveAll cleanup:
// unlinkat …/logship: directory not empty" (flaky go-node-agent, run
// 42230233221). Cleanups run last-registered first, so this one (registered
// after newShipper's t.TempDir) cancels and waits before the directory goes.
func runUntilCleanup(t *testing.T, s *Shipper) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("the shipper did not stop within 10s of its context ending")
		}
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func entry(name, line string) Entry {
	return Entry{TS: time.Now().UnixNano(), Line: line, Labels: Labels{Source: SourceDocker, Name: name, Stream: StreamStdout, Level: ExtractLevel(line)}}
}

// ── plaintext ────────────────────────────────────────────────────────────

func TestAnHTTPControllerIsRefused(t *testing.T) {
	_, err := New(Config{NodeID: "n1", ControllerURL: "http://controller:8080", Client: &http.Client{}, StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("http:// controller must be refused, got %v", err)
	}
	if _, err := New(Config{NodeID: "n1", ControllerURL: "https://controller:8080", Client: &http.Client{}, StateDir: t.TempDir()}); err != nil {
		t.Fatalf("https:// must be accepted: %v", err)
	}
}

// ── label set ────────────────────────────────────────────────────────────

func TestWireLabelsAreExactlyTheFixedKeys(t *testing.T) {
	es := []Entry{
		{TS: 1, Line: "a", Labels: Labels{Source: SourceJournal, Name: "noo-hostd", Stream: StreamJournal, Level: "info"}},
		{TS: 2, Line: "b", Labels: Labels{Source: SourceDocker, Name: "noo-gateway", Stream: StreamStderr, Level: "", ComposeService: "gateway"}},
	}
	var body wireBody
	if err := json.Unmarshal(encode("host3", es), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Streams) != 2 {
		t.Fatalf("two label sets must be two streams, got %d", len(body.Streams))
	}
	keys := func(m map[string]string) string {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	if got := keys(body.Streams[0].Labels); got != "level,name,node,source,stream" {
		t.Fatalf("journal stream keys = %s", got)
	}
	if got := keys(body.Streams[1].Labels); got != "compose_service,level,name,node,source,stream" {
		t.Fatalf("docker stream keys = %s", got)
	}
	if body.Streams[0].Labels["node"] != "host3" || body.Streams[1].Labels["level"] != "unknown" {
		t.Fatalf("labels = %v", body.Streams)
	}
	if body.Streams[0].Values[0] != [2]string{"1", "a"} {
		t.Fatalf("values = %v", body.Streams[0].Values)
	}
	// The Loki push shape: "stream" holds the labels, "values" the pairs.
	raw := string(encode("host3", es))
	if !strings.Contains(raw, `"stream":{`) || !strings.Contains(raw, `"values":[[`) || strings.Contains(raw, `"entries"`) {
		t.Fatalf("not the Loki push shape: %s", raw)
	}
	// A label value is clipped to the gateway's 128-byte cap, not refused.
	long := encode("n", []Entry{{TS: 1, Line: "x", Labels: Labels{Source: "docker", Name: strings.Repeat("n", 300), Stream: "stdout"}}})
	var lb wireBody
	_ = json.Unmarshal(long, &lb)
	if len(lb.Streams[0].Labels["name"]) != 128 {
		t.Fatalf("name not clipped: %d bytes", len(lb.Streams[0].Labels["name"]))
	}
}

// ── level table ──────────────────────────────────────────────────────────

func TestExtractLevelTable(t *testing.T) {
	cases := map[string]string{
		`{"time":"2026-09-28T10:00:00Z","level":"WARN","msg":"heartbeat not delivered"}`: "warn",
		`{"level":"error","event":"backend_failed"}`:                                     "error",
		`ts=2026-09-28 level=info msg="started"`:                                         "info",
		`level=debug cursor=1`:                                                           "debug",
		`2026-09-28T10:00:00.123456Z  INFO gateway::routes: request`:                     "info",
		`2026-09-28T10:00:00.123456Z ERROR gateway::embed: no backend`:                   "error",
		`INFO 09-28 10:00:00 [engine.py:120] Loading model`:                              "info",
		`WARNING 09-28 10:00:00 [config.py:12] deprecated`:                               "warn",
		`warn: llama.cpp: context shift`:                                                 "warn",
		`[warning  ] structlog line`:                                                     "warn",
		`2026-09-28 10:00:00,123 - noomesh.worker - CRITICAL - boom`:                     "unknown",
		`Traceback (most recent call last):`:                                             "unknown",
		`plain line with the word information in it`:                                     "unknown",
		``: "unknown",
	}
	for line, want := range cases {
		if got := ExtractLevel(line); got != want {
			t.Errorf("ExtractLevel(%q) = %q, want %q", line, got, want)
		}
	}
	for p, want := range map[string]string{"3": "error", "4": "warn", "6": "info", "7": "debug", "": "unknown"} {
		if got := levelFromPriority(p); got != want {
			t.Errorf("levelFromPriority(%q) = %q, want %q", p, got, want)
		}
	}
}

// ── batching, split, gzip ────────────────────────────────────────────────

func TestSplitStaysBelowTheCap(t *testing.T) {
	var es []Entry
	for i := 0; i < 200; i++ {
		es = append(es, entry("c", fmt.Sprintf("%03d %s", i, strings.Repeat("x", 100))))
	}
	whole := encode("n", es)
	capBytes := len(whole)/4 + 1
	pieces := splitEntries("n", es, capBytes)
	if len(pieces) < 4 {
		t.Fatalf("expected at least 4 pieces under a quarter cap, got %d", len(pieces))
	}
	total := 0
	for _, p := range pieces {
		if b := encode("n", p); len(b) > capBytes {
			t.Fatalf("piece of %d entries encodes to %d bytes, over the cap %d", len(p), len(b), capBytes)
		}
		total += len(p)
	}
	if total != len(es) {
		t.Fatalf("split lost entries: %d != %d", total, len(es))
	}
	// Order is preserved across pieces.
	if !strings.HasPrefix(pieces[0][0].Line, "000") || !strings.HasPrefix(pieces[len(pieces)-1][len(pieces[len(pieces)-1])-1].Line, "199") {
		t.Fatal("split reordered entries")
	}
	// splitBelowCap is the same boundaries, encoded.
	if bodies := splitBelowCap("n", es, capBytes); len(bodies) != len(pieces) {
		t.Fatalf("splitBelowCap %d bodies vs splitEntries %d pieces", len(bodies), len(pieces))
	}
	// One oversize entry goes alone rather than looping forever.
	huge := []Entry{entry("c", strings.Repeat("y", 1000))}
	if got := splitBelowCap("n", huge, 10); len(got) != 1 {
		t.Fatalf("single oversize entry must be one body, got %d", len(got))
	}
	// The gateway's counts: never more than 64 streams or 20 000 values.
	var many []Entry
	for i := 0; i < 130; i++ {
		many = append(many, entry(fmt.Sprintf("c%03d", i), "x"))
	}
	for _, p := range splitEntries("n", many, SplitBelowBytes) {
		if n := len(build("n", p).Streams); n > MaxStreams {
			t.Fatalf("a piece carries %d streams, over %d", n, MaxStreams)
		}
	}
	var dense []Entry
	for i := 0; i < 45_000; i++ {
		dense = append(dense, Entry{TS: int64(i), Line: "y", Labels: Labels{Source: "docker", Name: "c", Stream: "stdout"}})
	}
	for _, p := range splitEntries("n", dense, SplitBelowBytes) {
		if len(p) > MaxValues {
			t.Fatalf("a piece carries %d values, over %d", len(p), MaxValues)
		}
	}
}

func TestGzipRoundTrip(t *testing.T) {
	body := encode("n", []Entry{entry("c", "hello"), entry("c", "world")})
	gz, err := gzipBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(gz) == 0 || bytes.Equal(gz, body) {
		t.Fatal("body was not compressed")
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(zr)
	if !bytes.Equal(back, body) {
		t.Fatal("gzip round trip differs")
	}
}

// ── status contract ──────────────────────────────────────────────────────

func TestAcceptedBatchesCountAndCarryAuth(t *testing.T) {
	ig := &ingest{}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	for i := 0; i < 5; i++ {
		s.Offer(entry("noo-vllm", fmt.Sprintf("INFO line %d", i)))
	}
	// Wait on the CLIENT's count: the server records a body before it
	// answers, so its line count leads shipped_total by one round trip.
	waitFor(t, "5 lines accepted", func() bool { return s.State()["shipped_total"].(int64) == 5 })
	if ig.lines() != 5 {
		t.Fatalf("server holds %d lines, want 5", ig.lines())
	}
	st := s.State()
	if st["shipped_total"].(int64) != 5 || st["last_accepted_unix"].(int64) == 0 || st["last_error"] != "" || st["enabled"] != true {
		t.Fatalf("state = %v", st)
	}
	ig.mu.Lock()
	h := ig.headers[len(ig.headers)-1]
	ig.mu.Unlock()
	if h.Get("Authorization") != "Bearer test-token" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", h)
	}
}

// 4xx: the batch is dropped, counted, NOT retried.
func TestA4xxDropsTheBatchWithoutRetry(t *testing.T) {
	ig := &ingest{statuses: []int{200 /* probe */, 400, 204}}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	s.Offer(entry("c", "first"))
	waitFor(t, "first batch answered", func() bool { return atomic.LoadInt32(&ig.hits) >= 2 })
	// The drop is counted client-side once the 400 is classified; then
	// give a would-be retry every chance to show up.
	waitFor(t, "drop counted", func() bool { return s.State()["dropped_total"].(int64) == 1 })
	time.Sleep(300 * time.Millisecond)
	if atomic.LoadInt32(&ig.hits) != 2 {
		t.Fatalf("a 4xx must not be retried; hits=%d", ig.hits)
	}
	st := s.State()
	if st["dropped_total"].(int64) != 1 || !strings.Contains(st["last_error"].(string), "http 400") {
		t.Fatalf("state after 4xx = %v", st)
	}
	// Later batches are unaffected.
	s.Offer(entry("c", "second"))
	s.Offer(entry("c", "third"))
	waitFor(t, "recovery after 4xx", func() bool { return ig.lines() == 2 })
}

// 5xx: kept and retried until accepted; nothing lost.
func TestA5xxIsRetriedUntilAccepted(t *testing.T) {
	ig := &ingest{statuses: []int{200 /* probe */, 503, 500, 204}}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	s.Offer(entry("c", "keep me"))
	waitFor(t, "line accepted after two 5xx", func() bool { return s.State()["shipped_total"].(int64) == 1 })
	if ig.lines() != 1 {
		t.Fatalf("server holds %d lines, want 1", ig.lines())
	}
	if atomic.LoadInt32(&ig.hits) != 4 {
		t.Fatalf("expected probe + 2 failures + 1 success = 4 hits, got %d", ig.hits)
	}
	if st := s.State(); st["dropped_total"].(int64) != 0 || st["shipped_total"].(int64) != 1 {
		t.Fatalf("state = %v", st)
	}
}

// 429 honours Retry-After (as a wait, not a drop).
func TestA429WaitsRetryAfterThenRetries(t *testing.T) {
	ig := &ingest{statuses: []int{200, 429, 204}, retryAft: "1"}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	s.Offer(entry("c", "rate limited"))
	waitFor(t, "429 answered", func() bool { return atomic.LoadInt32(&ig.hits) >= 2 })
	t0 := time.Now()
	waitFor(t, "retry after the 429", func() bool { return ig.lines() == 1 })
	if el := time.Since(t0); el < 800*time.Millisecond {
		t.Fatalf("retry came after %s; Retry-After: 1 was not honoured", el)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("7"); d != 7*time.Second {
		t.Fatalf("seconds: %s", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Fatalf("empty: %s", d)
	}
	if d := parseRetryAfter("junk"); d != 0 {
		t.Fatalf("junk: %s", d)
	}
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(future); d < 25*time.Second || d > 31*time.Second {
		t.Fatalf("http date: %s", d)
	}
}

func TestBackoffGrowsToTheCapWithJitter(t *testing.T) {
	b := newBackoff(time.Second, 60*time.Second)
	prev := time.Duration(0)
	for i := 0; i < 10; i++ {
		d := b.next(0)
		if d < 750*time.Millisecond || d > 75*time.Second {
			t.Fatalf("step %d out of range: %s", i, d)
		}
		if i > 0 && i < 6 && d < prev {
			// Doubling with ±25 % jitter never goes down between consecutive
			// steps below the cap (2x·0.75 > 1.25).
			t.Fatalf("step %d (%s) below step %d (%s)", i, d, i-1, prev)
		}
		prev = d
	}
	if b.cur != 60*time.Second {
		t.Fatalf("cap not reached: %s", b.cur)
	}
	if d := b.next(5 * time.Second); d != 5*time.Second {
		t.Fatalf("Retry-After hint must win: %s", d)
	}
}

// A transport failure (the controller away) is a retry: nothing is
// dropped, and the batch lands once the controller is back.
func TestControllerAwayKeepsTheBatch(t *testing.T) {
	ig := &ingest{}
	// "Away" is the server cutting every connection before it answers, so
	// the pusher sees a transport error. The switch is an atomic the
	// handler reads: the test never writes the shipper's own fields while
	// Run reads them (it used to swap s.push.url, a data race under -race).
	var away atomic.Bool
	live := ig.handler(t, "n1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if away.Load() {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					_ = c.Close()
					return
				}
			}
			panic(http.ErrAbortHandler)
		}
		live(w, r)
	}))
	defer srv.Close()

	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	// Go away, offer, then come back.
	away.Store(true)
	s.Offer(entry("c", "while away"))
	waitFor(t, "a transport error recorded", func() bool {
		e, _ := s.State()["last_error"].(string)
		return strings.Contains(e, "transport")
	})
	if st := s.State(); st["dropped_total"].(int64) != 0 || ig.lines() != 0 {
		t.Fatalf("state while away = %v, server lines %d", st, ig.lines())
	}
	away.Store(false)
	waitFor(t, "batch delivered after return", func() bool { return ig.lines() == 1 })
}

// ── roll safety ──────────────────────────────────────────────────────────

// An older gateway (404 on the route): no source starts, the probe
// repeats after RouteRetry, and shipping begins once the route appears.
func TestSourcesStartOnlyOnceTheRouteExists(t *testing.T) {
	ig := &ingest{}
	var routeUp atomic.Bool
	srv := httptest.NewTLSServer(func() http.HandlerFunc {
		h := ig.handler(t, "n1")
		return func(w http.ResponseWriter, r *http.Request) {
			if !routeUp.Load() {
				atomic.AddInt32(&ig.hits, 1)
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}())
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	src := &fakeSource{}
	s.AddSource(src)
	runUntilCleanup(t, s)
	waitFor(t, "two 404 probes", func() bool { return atomic.LoadInt32(&ig.hits) >= 2 })
	if src.started.Load() {
		t.Fatal("a source started while the route answered 404")
	}
	if st := s.State(); st["route_ready"] != false || !strings.Contains(st["last_error"].(string), "404") {
		t.Fatalf("state = %v", st)
	}
	routeUp.Store(true)
	waitFor(t, "source started after the route appeared", func() bool { return src.started.Load() })
	waitFor(t, "source line shipped", func() bool { return ig.lines() == 1 })
}

type fakeSource struct{ started atomic.Bool }

func (f *fakeSource) Name() string { return "fake" }
func (f *fakeSource) Run(ctx context.Context, emit func(Entry)) {
	f.started.Store(true)
	emit(entry("fake", "hello from a source"))
	<-ctx.Done()
}

// ── spill and recovery ───────────────────────────────────────────────────

func TestOverflowSpillsToDiskAndRecovers(t *testing.T) {
	ig := &ingest{}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", func(c *Config) {
		c.MemMaxLines = 10
		c.FlushLines = 5
		c.FlushEvery = time.Hour // only explicit flushes
	})
	// No Run yet: the queue fills, then spills.
	for i := 0; i < 25; i++ {
		s.Offer(entry("c", fmt.Sprintf("line %02d", i)))
	}
	if st := s.State(); st["queued"].(int) != 10 || st["spill_pending"] != true {
		t.Fatalf("state before run = %v", st)
	}
	spillDir := filepath.Join(s.cfg.StateDir, "logship")
	if fi, err := os.Stat(filepath.Join(spillDir, "spill.ndjson")); err != nil || fi.Size() == 0 {
		t.Fatalf("spill file missing or empty: %v", err)
	}
	runUntilCleanup(t, s)
	waitFor(t, "shipper ready", func() bool { return s.State()["route_ready"] == true })
	for i := 0; i < 6; i++ { // kick until memory and spill are drained
		s.kick()
		time.Sleep(50 * time.Millisecond)
	}
	waitFor(t, "all 25 lines delivered (memory + spill)", func() bool { return ig.lines() == 25 })
	if s.spill.pending() {
		t.Fatal("spill should be empty after recovery")
	}
	// Every line exactly once.
	seen := map[string]int{}
	ig.mu.Lock()
	for _, b := range ig.bodies {
		for _, st := range b.Streams {
			for _, e := range st.Values {
				seen[e[1]]++
			}
		}
	}
	ig.mu.Unlock()
	for i := 0; i < 25; i++ {
		if seen[fmt.Sprintf("line %02d", i)] != 1 {
			t.Fatalf("line %02d seen %d times", i, seen[fmt.Sprintf("line %02d", i)])
		}
	}
}

// Shutdown mid-retry keeps the batch on disk for the next start.
func TestShutdownSpillsTheInFlightBatch(t *testing.T) {
	ig := &ingest{statuses: []int{200, 503}}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	s.Offer(entry("c", "in flight"))
	waitFor(t, "503 received", func() bool { return atomic.LoadInt32(&ig.hits) >= 2 })
	cancel()
	<-done
	if !s.spill.pending() {
		t.Fatal("the undelivered batch must be spilled on shutdown")
	}
	// A fresh shipper over the same state dir delivers it.
	ig2 := &ingest{}
	srv2 := httptest.NewTLSServer(ig2.handler(t, "n1"))
	defer srv2.Close()
	s2 := newShipper(t, srv2, "n1", func(c *Config) { c.StateDir = s.cfg.StateDir })
	runUntilCleanup(t, s2)
	waitFor(t, "spilled batch delivered by the next start", func() bool { return ig2.lines() == 1 })
}

// The spill is bounded: the OLDEST lines go, and they are counted.
func TestSpillDropsOldestPastItsCap(t *testing.T) {
	var dropped int64
	sp, err := newSpill(t.TempDir(), 2000, func(n int64) { dropped += n })
	if err != nil {
		t.Fatal(err)
	}
	var es []Entry
	for i := 0; i < 100; i++ {
		es = append(es, Entry{TS: int64(i), Line: fmt.Sprintf("%03d-%s", i, strings.Repeat("z", 60)), Labels: Labels{Source: "docker", Name: "c", Stream: "stdout"}})
	}
	if err := sp.write(es); err != nil {
		t.Fatal(err)
	}
	if dropped == 0 {
		t.Fatal("writing 100 long lines into a 2000-byte spill must drop some")
	}
	var got []Entry
	for {
		batch, err := sp.drain(7)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) == 0 {
			break
		}
		got = append(got, batch...)
	}
	if len(got)+int(dropped) != 100 {
		t.Fatalf("kept %d + dropped %d != 100", len(got), dropped)
	}
	// What survived is the newest, in order.
	for i := 1; i < len(got); i++ {
		if got[i].TS != got[i-1].TS+1 {
			t.Fatalf("order broken at %d: %d after %d", i, got[i].TS, got[i-1].TS)
		}
	}
	if got[len(got)-1].TS != 99 {
		t.Fatalf("newest line lost: last TS %d", got[len(got)-1].TS)
	}
}

// ── self-loop guard ──────────────────────────────────────────────────────

func TestOwnIngestRequestLinesAreNotShipped(t *testing.T) {
	s, err := New(Config{NodeID: "host8", ControllerURL: "https://c", Client: &http.Client{}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Offer(entry("noo-gateway", `INFO request POST /api/cluster/nodes/host8/logs 204`))
	s.Offer(entry("noo-gateway", `INFO request POST /api/cluster/nodes/host8/heartbeat 200`))
	if q := s.State()["queued"].(int); q != 1 {
		t.Fatalf("queued %d, want 1 (the ingest line must be suppressed)", q)
	}
}

// ── the gateway's refusal bodies ─────────────────────────────────────────

func TestClassifyFollowsTheGatewayContract(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   outcome
	}{
		{204, "", outcomeAccepted},
		{400, `{"error":"bad label","reason":"malformed","retry":false}`, outcomeDropped},
		{413, `{"error":"too big","reason":"too_large","retry":false}`, outcomeDropped},
		{400, `{"error":"loki said no","reason":"loki_refused","retry":false}`, outcomeDropped},
		{401, `{"error":"bad token","reason":"not_this_node","retry":true}`, outcomeRetry},
		{403, ``, outcomeRetry},
		{429, `{"error":"slow down","reason":"bytes_per_min","retry":true}`, outcomeRetry},
		{503, `{"error":"loki down","reason":"loki_down","retry":true}`, outcomeRetry},
		{410, `{"error":"log search is off on this controller by choice","reason":"loki_off","retry":false}`, outcomeLokiOff},
		{500, ``, outcomeRetry},
		{404, ``, outcomeRetry},
		// `retry` is believed over the status class, both ways.
		{400, `{"error":"transient","retry":true}`, outcomeRetry},
		{503, `{"error":"permanent","retry":false}`, outcomeDropped},
	}
	for _, c := range cases {
		got := classify(c.status, "", []byte(c.body))
		if got.outcome != c.want {
			t.Errorf("classify(%d, %q) = %v, want %v", c.status, c.body, got.outcome, c.want)
		}
		if c.status == 404 && got.err != errRouteAbsent {
			t.Errorf("404 must be named as the absent route")
		}
	}
	r := classify(429, "17", []byte(`{"error":"x","reason":"requests_per_min","retry":true}`))
	if r.retryAfter != 17*time.Second || !strings.Contains(r.reason, "requests_per_min") {
		t.Fatalf("429 result = %+v", r)
	}
}

// 401/403 keep the batch: a credential problem is fixed elsewhere and the
// lines are still good.
func TestACredentialRefusalKeepsTheBatch(t *testing.T) {
	ig := &ingest{statuses: []int{200, 403, 204}}
	srv := httptest.NewTLSServer(ig.handler(t, "n1"))
	defer srv.Close()
	s := newShipper(t, srv, "n1", nil)
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&ig.hits) >= 1 })
	s.Offer(entry("c", "still good"))
	waitFor(t, "delivered after the 403", func() bool { return s.State()["shipped_total"].(int64) == 1 })
	if st := s.State(); st["dropped_total"].(int64) != 0 || ig.lines() != 1 {
		t.Fatalf("a 403 must not drop: %v", st)
	}
}

// 410 loki_off (the controller declared cluster.monitoring: lean and runs
// no Loki): the batch is dropped, not retried; shipping pauses for
// RouteRetry with intake discarded; the heartbeat says enabled:false with
// the reason; and once the controller accepts again, it is enabled again.
func TestLokiOffPausesOnTheLongCadenceAndReportsDisabled(t *testing.T) {
	var hits, off int32
	atomic.StoreInt32(&off, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 { // the route probe
			w.WriteHeader(400)
			return
		}
		if atomic.LoadInt32(&off) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"log search is off on this controller by choice (noo stack monitoring on)","reason":"loki_off","retry":false}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	s := newShipper(t, srv, "n1", func(c *Config) { c.RouteRetry = 400 * time.Millisecond })
	runUntilCleanup(t, s)
	waitFor(t, "route probe", func() bool { return atomic.LoadInt32(&hits) >= 1 })
	s.Offer(entry("c", "first"))
	waitFor(t, "loki_off answered", func() bool { return atomic.LoadInt32(&hits) >= 2 })
	waitFor(t, "drop counted", func() bool { return s.State()["dropped_total"].(int64) == 1 })
	st := s.State()
	if st["enabled"] != false || st["reason"] != "loki_off" || !strings.Contains(st["last_error"].(string), "off on this controller by choice") {
		t.Fatalf("state after loki_off = %v", st)
	}
	// Paused: intake is discarded and nothing is sent until RouteRetry.
	s.Offer(entry("c", "during the pause"))
	time.Sleep(150 * time.Millisecond)
	if h := atomic.LoadInt32(&hits); h != 2 {
		t.Fatalf("a loki_off must pause, not retry; hits=%d", h)
	}
	if q := s.State()["queued"].(int); q != 0 {
		t.Fatalf("intake during the pause must be discarded, queued=%d", q)
	}
	// Turned on at the controller: after the pause the next line lands.
	atomic.StoreInt32(&off, 0)
	waitFor(t, "pause over", func() bool { return !s.offPaused.Load() })
	s.Offer(entry("c", "after"))
	waitFor(t, "shipped after the pause", func() bool { return s.State()["shipped_total"].(int64) == 1 })
	if st := s.State(); st["enabled"] != true {
		t.Fatalf("an accepted push must clear loki_off: %v", st)
	}
}
