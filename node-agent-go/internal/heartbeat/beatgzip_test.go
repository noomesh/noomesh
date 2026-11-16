// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// gzGateway answers each beat with the next scripted reply (the last one
// repeats) and records what arrived on the wire.
type gzGateway struct {
	mu      sync.Mutex
	replies []gzReply
	posts   []gzPost
}

type gzReply struct {
	status int
	body   string
}

type gzPost struct {
	encoding string
	raw      []byte // as received
	json     map[string]any
	bodySHA  string
	token    string
}

var (
	plainOK = gzReply{200, `{"status":"ok"}`}
	gzipOK  = gzReply{200, `{"status":"ok","accept_encoding":["gzip"]}`}
)

func (g *gzGateway) script(rs ...gzReply) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.replies = rs
}

func (g *gzGateway) take() []gzPost {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.posts
	g.posts = nil
	return out
}

func newGzGateway(t *testing.T) (*gzGateway, *Reporter) {
	t.Helper()
	g := &gzGateway{replies: []gzReply{plainOK}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p := gzPost{encoding: r.Header.Get("Content-Encoding"), raw: raw,
			bodySHA: r.Header.Get(auth.BodySHAHeader), token: r.Header.Get("Authorization")}
		plain := raw
		if p.encoding == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Errorf("a gzip beat that does not decode: %v", err)
			} else {
				plain, _ = io.ReadAll(zr)
			}
		}
		_ = json.Unmarshal(plain, &p.json)
		g.mu.Lock()
		g.posts = append(g.posts, p)
		rep := g.replies[0]
		if len(g.replies) > 1 {
			g.replies = g.replies[1:]
		}
		g.mu.Unlock()
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("NOO_PKI_DIR", t.TempDir())
	t.Setenv("MODELS_DIR", "")
	r := newTestReporter(t, srv.URL, &config.Config{NodeID: "test-node", Tier: 3, NodeIP: "192.168.1.10",
		ClusterSecret: "fleet-secret-for-tests"})
	return g, r
}

func gzBeat(t *testing.T, g *gzGateway, r *Reporter) []gzPost {
	t.Helper()
	r.SendHeartbeat()
	return g.take()
}

func requirePlain(t *testing.T, what string, p gzPost) {
	t.Helper()
	if p.encoding != "" {
		t.Errorf("%s: Content-Encoding %q, want a plain beat", what, p.encoding)
	}
	if len(p.raw) == 0 || p.raw[0] != '{' {
		t.Errorf("%s: the wire body is not plain JSON", what)
	}
	if p.json["node_id"] == nil && p.json["app_version"] == nil {
		t.Errorf("%s: the beat did not parse as a heartbeat", what)
	}
}

func requireGzip(t *testing.T, what string, p gzPost) {
	t.Helper()
	if p.encoding != "gzip" {
		t.Fatalf("%s: Content-Encoding %q, want gzip", what, p.encoding)
	}
	if len(p.raw) < 2 || p.raw[0] != 0x1f || p.raw[1] != 0x8b {
		t.Errorf("%s: the wire body is not a gzip stream", what)
	}
	if p.json["app_version"] == nil {
		t.Errorf("%s: the decoded beat is not a heartbeat", what)
	}
}

// An older gateway never advertises gzip: every beat is plain JSON, as it
// always was.
func TestGzip_PlainUntilAdvertised(t *testing.T) {
	g, r := newGzGateway(t)
	for i := 0; i < 3; i++ {
		ps := gzBeat(t, g, r)
		if len(ps) != 1 {
			t.Fatalf("beat %d: %d posts, want 1", i, len(ps))
		}
		requirePlain(t, "gateway without the advertisement", ps[0])
	}
}

func TestGzip_AfterTheAdvertisement(t *testing.T) {
	g, r := newGzGateway(t)
	g.script(gzipOK)
	requirePlain(t, "first beat (nothing advertised yet)", gzBeat(t, g, r)[0])
	p := gzBeat(t, g, r)[0]
	requireGzip(t, "beat after the advertisement", p)

	// The v2 token and the body-hash header describe the bytes AS SENT:
	// the compressed body the gateway verifies before it decodes.
	sum := sha256.Sum256(p.raw)
	if p.bodySHA != hex.EncodeToString(sum[:]) {
		t.Errorf("body hash header %q is not the sha256 of the compressed wire bytes", p.bodySHA)
	}
	if !strings.HasPrefix(p.token, "Bearer v2:") {
		t.Errorf("gzip beat not signed v2: %q", p.token)
	}

	// The gateway stops advertising (rolled back): the next beat is plain.
	g.script(plainOK)
	gzBeat(t, g, r)
	requirePlain(t, "beat after the advertisement stopped", gzBeat(t, g, r)[0])
}

// A gzip beat the gateway refuses is re-sent plain at once, and gzip stays
// off for the process even if later replies advertise it again.
func TestGzip_RefusalFallsBackToPlainForGood(t *testing.T) {
	for _, status := range []int{400, 413, 415} {
		g, r := newGzGateway(t)
		g.script(gzipOK)
		gzBeat(t, g, r)
		g.script(gzReply{status, `{"error":"no"}`}, gzipOK)
		ps := gzBeat(t, g, r)
		if len(ps) != 2 {
			t.Fatalf("HTTP %d: %d posts, want the gzip beat and its plain resend", status, len(ps))
		}
		requireGzip(t, "refused beat", ps[0])
		requirePlain(t, "resend", ps[1])
		if r.failStreak != 0 {
			t.Errorf("HTTP %d: the plain resend was delivered, but the beat counted as failed", status)
		}
		for i := 0; i < 2; i++ {
			requirePlain(t, "beat after a refusal (still advertised)", gzBeat(t, g, r)[0])
		}
	}
}

// A failure that is not an encoding refusal is not answered with a resend,
// and does not turn gzip off.
func TestGzip_OtherFailuresAreNotRefusals(t *testing.T) {
	g, r := newGzGateway(t)
	g.script(gzipOK)
	gzBeat(t, g, r)
	g.script(gzReply{503, ""}, gzipOK)
	if ps := gzBeat(t, g, r); len(ps) != 1 {
		t.Fatalf("503: %d posts, want 1", len(ps))
	}
	requireGzip(t, "beat after a 503", gzBeat(t, g, r)[0])
}

func TestReadBeatReply(t *testing.T) {
	for body, want := range map[string]bool{
		`{"status":"ok"}`: false,
		`{"status":"ok","accept_encoding":["gzip"]}`: true,
		`{"status":"ok","accept_encoding":["br"]}`:   false,
		`{"status":"ok","accept_encoding":"gzip"}`:   false,
		`not json`: false,
		``:         false,
		`{"accept_encoding":["identity","gzip"],"x":1}`: true,
	} {
		if got := readBeatReply(strings.NewReader(body)).acceptsGzip(); got != want {
			t.Errorf("%q: acceptsGzip = %v, want %v", body, got, want)
		}
	}
}
