// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// corpusPath is the shared vector, relative to this package: the Rust twin
// loads the same file with include_str!, and the Python parity test holds
// the two tables' kinds equal. Move the file and both unit tests fail.
const corpusPath = "../../../tests/fixtures/redaction_corpus.json"

type corpusCase struct {
	Name     string `json:"name"`
	Line     string `json:"line"`
	Expected string `json:"expected"`
}

func loadCorpus(t testing.TB) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(corpusPath))
	if err != nil {
		t.Fatalf("shared corpus missing: %v", err)
	}
	var doc struct {
		Cases []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corpus is not the expected JSON: %v", err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("corpus holds %d cases; the parse found too little to be the real file", len(doc.Cases))
	}
	return doc.Cases
}

// TestRedactMatchesTheSharedCorpus is the Go half of the parity contract.
// Planted 2026-09-28: the `service-key` row removed from `shapes` → the
// "service key as issued" case fails here and nowhere else.
func TestRedactMatchesTheSharedCorpus(t *testing.T) {
	cases := loadCorpus(t)
	secrets, clean := 0, 0
	for _, c := range cases {
		got, n := Redact(c.Line)
		if got != c.Expected {
			t.Errorf("%s:\n  line     %q\n  want     %q\n  got      %q", c.Name, c.Line, c.Expected, got)
		}
		if c.Expected == c.Line {
			clean++
			if n != 0 {
				t.Errorf("%s: a must-not-touch line counted %d redactions", c.Name, n)
			}
		} else {
			secrets++
			if n == 0 {
				t.Errorf("%s: the line changed but the count is zero", c.Name)
			}
		}
	}
	if secrets < 10 || clean < 8 {
		t.Fatalf("corpus is thin: %d secret cases, %d must-not-touch cases", secrets, clean)
	}
}

// Idempotence is what lets the gateway run the same table a second time
// without the count going up or a placeholder being wrapped twice.
func TestRedactIsIdempotent(t *testing.T) {
	for _, c := range loadCorpus(t) {
		once, _ := Redact(c.Line)
		twice, n := Redact(once)
		if twice != once {
			t.Errorf("%s: second pass changed the line:\n  %q\n  %q", c.Name, once, twice)
		}
		if n != 0 {
			t.Errorf("%s: second pass counted %d redactions", c.Name, n)
		}
	}
}

// A line with no secret comes back as the same string — no copy — and the
// gates keep the regex engine out of the common case.
func TestRedactLeavesACleanLineUntouched(t *testing.T) {
	line := `2026-09-28T10:14:02Z level=info msg="heartbeat ok" node=host3 took=12ms`
	got, n := Redact(line)
	if n != 0 || got != line {
		t.Fatalf("clean line changed: %q (%d)", got, n)
	}
	if !strings.HasPrefix(line, got) || len(got) != len(line) {
		t.Fatal("expected the identical string back")
	}
}

// Every gate must be a superset of its regex: a gate that refuses a line
// the regex would match is a silent hole. Proved on the corpus: for every
// case, running the regexes WITHOUT their gates gives the same answer.
func TestGatesNeverHideAMatch(t *testing.T) {
	for _, c := range loadCorpus(t) {
		line := c.Line
		p := newProbe(line, nil)
		for i := range shapes {
			sh := &shapes[i]
			gated := sh.gate == nil || sh.gate(p)
			if !gated && sh.re.MatchString(line) {
				t.Errorf("%s: the %q gate hid a match on %q", c.Name, sh.kind, line)
			}
			line, _ = redactOne(sh, line)
		}
	}
}

// redactOne applies a single shape (test helper mirroring Redact's loop).
func redactOne(sh *shape, line string) (string, int) {
	idx := sh.re.FindAllStringSubmatchIndex(line, -1)
	if idx == nil {
		return line, 0
	}
	b := make([]byte, 0, len(line))
	last := 0
	for _, m := range idx {
		b = append(b, line[last:m[0]]...)
		if sh.accept != nil && !sh.accept(line, m[0], m[1]) {
			b = append(b, line[m[0]:m[1]]...)
		} else {
			b = sh.re.ExpandString(b, sh.repl, line, m)
		}
		last = m[1]
	}
	b = append(b, line[last:]...)
	return string(b), len(idx)
}

func TestShapeKindsAreUniqueAndLabelled(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range ShapeKinds() {
		if k == "" || seen[k] {
			t.Fatalf("kind %q empty or repeated", k)
		}
		seen[k] = true
	}
	for _, sh := range shapes {
		if !strings.Contains(sh.repl, "<redacted:"+sh.kind+">") {
			t.Errorf("shape %q does not label its replacement with its own kind: %q", sh.kind, sh.repl)
		}
	}
}

// ── cost ──────────────────────────────────────────────────────────────

// A realistic mix: what a node's containers print. ~95 % clean lines of
// the shapes the fleet actually emits, ~5 % holding a credential.
func benchLines() []string {
	clean := []string{
		`2026-09-28T10:14:02.123456789Z level=info msg="heartbeat ok" node=host3 took=12ms`,
		`{"level":"info","ts":1727512345.12,"msg":"placement reconciled","node":"host8","backend":"vllm","model":"gemma-4-12B-it-qat-w4a16-ct"}`,
		`INFO 09-28 10:14:02 [engine.py:123] Avg prompt throughput: 12.3 tokens/s, Avg generation throughput: 45.6 tokens/s, Running: 1 reqs`,
		`GET /api/cluster/nodes/host3/logs 204 12ms caller=host3`,
		`pulled ghcr.io/noomesh/noo-gateway@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`,
		`level=warn msg="log push failed; retrying with backoff" reason="http-503" wait=4s`,
		`Sep 28 10:14:02 host8 noo-hostd[1234]: journal-follow: rotated /var/lib/noo-node-agent/spool/journal.follow (16 MB)`,
		`postgres  | 2026-09-28 10:14:02.123 UTC [77] LOG:  checkpoint complete: wrote 1234 buffers (7.5%); 0 WAL file(s) added`,
		`redis     | 1:M 28 Sep 2026 10:14:02.123 * Background saving terminated with success`,
		`nats      | [1] 2026/09/28 10:14:02.123456 [INF] 172.19.0.4:51234 - cid:12 - Client connection closed: Client Closed`,
		`dial tcp [fe80::1%eth0]:8081: connect: connection refused`,
		`token_count=512 max_tokens=1024 prompt_tokens=7 secret_name=db-password`,
		`node=host8 id=8f14e45f-ceea-467a-9575-62c0f2b0d1a9 online=true`,
		`{"level":"debug","msg":"embedding batch","items":32,"dims":1024,"took_ms":41}`,
		`ok`,
		`level=info msg="rotating the cluster secret" reason=scheduled`,
		`container 3f2a9c1e8b7d started`,
		`NOO_LOG_SHIP=0 NOO_LOG_SHIP_UNITS=noo-hostd,docker NOO_AGENT_STATE=/var/lib/noo-node-agent`,
		`vllm      | INFO:     172.19.0.2:41234 - "POST /v1/chat/completions HTTP/1.1" 200 OK`,
	}
	secret := []string{
		`heartbeat auth failed for host3:1727512345:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`,
		`error sending request for url (https://api.telegram.org/bot1234567890:AAFsomeSecretBodyHereXXXXXXXXXXXXXX/getUpdates)`,
		`DATABASE_URL=postgres://noo:hunter2@postgres:5432/noo`,
		`Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MX0.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWc`, // leak-ok: fabricated JWT fixture for the redactor test
		`{"NOO_CLUSTER_SECRET": "abc123", "level": "info"}`,
	}
	var out []string
	for i := 0; i < 100; i++ {
		out = append(out, clean...)
		out = append(out, secret[i%len(secret)])
	}
	return out
}

// BenchmarkRedact reports ns per line over the realistic mix.
func BenchmarkRedact(b *testing.B) {
	lines := benchLines()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Redact(lines[i%len(lines)])
	}
}

// BenchmarkRedactClean is the common case alone: a line with nothing in it.
func BenchmarkRedactClean(b *testing.B) {
	line := `{"level":"info","ts":1727512345.12,"msg":"placement reconciled","node":"host8","backend":"vllm","model":"gemma-4-12B-it-qat-w4a16-ct"}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Redact(line)
	}
}

// BenchmarkRedactSecret is the worst realistic case: a line that trips a
// gate and matches.
func BenchmarkRedactSecret(b *testing.B) {
	line := `Authorization: Bearer host3:1727512345:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 password=hunter2`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Redact(line)
	}
}

// ── the shipper applies it before the spill ──────────────────────────

// The spill is a 0640 file that outlives the process; the memory queue
// feeds the wire. Both sit behind Offer, so Offer is where the scrub
// happens: with the memory cap at one line the second entry goes straight
// to disk, and neither the disk nor the wire may hold the secret.
func TestOfferScrubsBeforeTheSpillAndTheWire(t *testing.T) {
	srv := &ingest{}
	ts := httptest.NewTLSServer(srv.handler(t, "host3"))
	defer ts.Close()
	s := newShipper(t, ts, "host3", func(c *Config) {
		c.MemMaxLines = 1
		c.FlushEvery = time.Hour // hold everything until we look
	})
	const secret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	s.Offer(entry("gateway", "auth failed for host3:1727512345:"+secret))
	s.Offer(entry("gateway", "DATABASE_URL=postgres://noo:hunter2@postgres:5432/noo"))
	s.Offer(entry("gateway", "level=info msg=\"heartbeat ok\""))

	spilled, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "logship", "spill.ndjson"))
	if err != nil {
		t.Fatalf("expected a spill file: %v", err)
	}
	if strings.Contains(string(spilled), secret) || strings.Contains(string(spilled), "hunter2") {
		t.Fatalf("the spill holds a secret:\n%s", spilled)
	}
	// (json.Marshal writes `<` as \u003c in the spill, so match the label.)
	if !strings.Contains(string(spilled), "redacted:dsn") {
		t.Fatalf("the spilled DSN line was not scrubbed:\n%s", spilled)
	}
	s.mu.Lock()
	inMem := s.mem[0].Line
	s.mu.Unlock()
	if strings.Contains(inMem, secret) || !strings.Contains(inMem, "<redacted:cluster-token>") {
		t.Fatalf("the queued line was not scrubbed: %q", inMem)
	}
	if got := s.State()["redacted_total"]; got != int64(2) {
		t.Fatalf("redacted_total = %v, want 2", got)
	}

	// And nothing reaches the wire: ship everything, read what the
	// controller received.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.kick() // the wake channel is buffered; the loop drains memory, then the spill
	waitFor(t, "3 lines accepted", func() bool { return srv.lines() == 3 })
	for _, b := range srv.bodies {
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "hunter2") {
			t.Fatalf("a secret reached the wire: %s", raw)
		}
	}
}

// ── a PEM body's short last line, across entries ─────

// Planted 2026-10-02: the pem-tail row removed → this and the corpus
// cases fail.
func TestRedactAfterCatchesThePemTail(t *testing.T) {
	body, _ := Redact("r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g")
	if body != pemBodyPlaceholder {
		t.Fatalf("body line: %q", body)
	}
	if got, n := RedactAfter(body, "Qw3rTy+Uio=="); got != "<redacted:pem-tail>" || n != 1 {
		t.Fatalf("tail after a body line: %q (%d)", got, n)
	}
	if got, n := RedactAfter("level=info", "Qw3rTy+Uio=="); got != "Qw3rTy+Uio==" || n != 0 {
		t.Fatalf("the same line without the context: %q (%d)", got, n)
	}
	if got, n := RedactAfter(body, "done"); got != "done" || n != 0 {
		t.Fatalf("a word after a body line: %q (%d)", got, n)
	}
	if got, n := RedactAfter(body, "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g"); got != pemBodyPlaceholder || n != 1 {
		t.Fatalf("a body line after a body line: %q (%d)", got, n)
	}
}

// The shipper carries the context per flow: a key printed one line per
// entry loses its last line, a second container's lines interleaved with
// it do not borrow the context, and a level change does not drop it.
func TestOfferCarriesThePemContextPerFlow(t *testing.T) {
	srv := &ingest{}
	ts := httptest.NewTLSServer(srv.handler(t, "host3"))
	defer ts.Close()
	s := newShipper(t, ts, "host3", func(c *Config) { c.FlushEvery = time.Hour })
	s.Offer(entry("a", "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g"))
	s.Offer(entry("b", "Qw3rTy+Uio=="))
	s.Offer(entry("a", "cFH/X3aYjOOuafKrMDCg63ZAt76NozQ5v1bfUr5Lu0WTf92P1rxM2u8qnA+yF9cm"))
	s.Offer(entry("a", "Qw3rTy+Uio=="))
	s.Offer(entry("a", "Qw3rTy+Uio=="))
	s.Offer(entry("b", "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g"))
	s.Offer(entry("b", "done"))
	s.mu.Lock()
	got := make([]string, 0, len(s.mem))
	for _, e := range s.mem {
		got = append(got, e.Labels.Name+" "+e.Line)
	}
	s.mu.Unlock()
	s.pemMu.Lock()
	flows := len(s.pemFlows)
	s.pemMu.Unlock()
	want := []string{
		"a <redacted:pem-body>",
		"b Qw3rTy+Uio==",
		"a <redacted:pem-body>",
		"a <redacted:pem-tail>",
		"a Qw3rTy+Uio==",
		"b <redacted:pem-body>",
		"b done",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("queued:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if flows != 0 {
		t.Fatalf("%d flows still marked after their bodies ended", flows)
	}
}
