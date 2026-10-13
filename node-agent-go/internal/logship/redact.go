// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
)

// Secret scrubbing, BEFORE a line is queued, spilled or shipped.
//
// Any service on a node can print a credential — a reqwest error renders
// the URL it failed on (the Telegram token lived in one, 2026-09-12), a
// startup banner echoes its environment, a curl in a heartbeat action
// prints the header it sent. Once the shipper exists, such a line is no
// longer one `docker logs` away: it sits in the spill file on disk and in
// Loki for `NOO_LOKI_RETENTION`, readable by every operator. So the
// shipper scrubs at intake ([Shipper.Offer]), which is the only place the
// spill and the wire both sit behind; the gateway repeats the same table
// on ingest (`gateway-rust/src/redact.rs`) as the belt to this brace.
//
// SHAPE-based, by construction: a scrubber that compares against known
// values would need every secret in memory and would miss a rotated one.
// The cost of that choice is the caveat operators are told: a secret in a
// shape this table does not name ships. Add the shape, not a value.
//
// The Go and Rust tables cannot share source. They share a vector:
// tests/fixtures/redaction_corpus.json is loaded by both unit tests, and
// tests/test_log_redaction_parity.py holds the KINDS in both tables, the
// corpus and the operator doc equal. The table is ORDERED and the order
// is part of the contract (pem before the key=value pair, so a
// `private_key=-----BEGIN…` is not half-eaten; the generic header/pair
// shapes before the specific ones so a placeholder is never re-wrapped).
//
// Nothing of a secret survives: the replacement is `<redacted:KIND>` and
// the rest of the line is untouched. Cost is bounded — every regex is
// compiled once, each has a cheap byte-scan gate so a line that cannot
// hold that shape never enters the regex engine, and a line with no match
// is returned without a copy. See BenchmarkRedact for the ns/line.

// shape is one row of the table.
type shape struct {
	kind string
	// gate answers "could this line hold the shape" from a substring scan
	// over the probe (the line, and an ASCII-lower-cased copy made once);
	// nil means always try. It must be a SUPERSET of what re matches.
	gate func(probe) bool
	re   *regexp.Regexp
	repl string
	// accept, when set, is asked about every match (the whole line and
	// the match's byte range) and a false keeps the match as it is. It is
	// how a bare, prefixless shape states what a regex cannot without
	// look-around: "exactly 43, with an upper, a lower and a digit, and no
	// base64 neighbour". The Rust twin carries the same predicate under
	// the same kind (tests/test_log_redaction_parity.py holds the set).
	accept func(line string, start, end int) bool
}

// Character classes shared by the patterns. ASCII on purpose: Go's \s and
// \b are ASCII already; the Rust twin says (?-u:\b) and [ \t] so the two
// engines agree on non-ASCII neighbours.
const (
	// A "value" for the generic shapes: runs to whitespace, a quote, an
	// angle bracket (so an existing `<redacted:…>` is never re-wrapped), or
	// a separator.
	valueClass = `[^ \t"'<>,;]+`
	// Same, for a key=value pair, which also stops at & } ] (query strings
	// and JSON).
	pairValueClass = `[^ \t"'<>,;&}\]]+`
)

// shapes is the table. Kinds are the operator-facing label; the parity
// test reads them from this file by the `kind:` literal.
var shapes = []shape{
	{
		kind: "pem",
		gate: func(p probe) bool { return p.has("-----BEGIN ") },
		// The body between the markers on one line (escaped newlines are
		// how a block reaches a single log line); without an END marker,
		// the rest of the line.
		re:   regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----)(?:.*?(-----END [A-Z ]*PRIVATE KEY-----)|.*)`),
		repl: `${1}<redacted:pem>${2}`,
	},
	{
		kind: "pem-body",
		gate: func(p probe) bool {
			n := len(strings.Trim(p.s, " \t\r"))
			return n == 64 || n == 70 || strings.IndexByte(p.s, '\n') >= 0 && hasRun(p.s, isB64Std, 64)
		},
		// A PEM body printed one base64 line per log line (`cat key.pem`),
		// or one per line of a multi-line string: a line that is NOTHING
		// but 64 base64 characters (RFC 7468's width; 70 is OpenSSH's).
		// The width and the whole-line anchor are what say it sits between
		// the markers. A bare 64-hex digest on a line of its own is the
		// decoy: accept wants a character hex has not.
		re:     regexp.MustCompile(`(?m)^[ \t]*(?:[A-Za-z0-9+/]{70}|[A-Za-z0-9+/]{64})[ \t\r]*$`),
		repl:   `<redacted:pem-body>`,
		accept: func(line string, start, end int) bool { return hasNonHex(strings.Trim(line[start:end], " \t\r")) },
	},
	{
		kind: "pem-tail",
		gate: func(p probe) bool {
			return strings.IndexByte(p.s, '\n') >= 0 && (p.has(pemBodyPlaceholder) || hasRun(p.s, isB64Std, 64))
		},
		// The body's short LAST line, by context:
		// the line right after a full-width body line, which the row above
		// has already turned into its placeholder. Within one string that
		// is the next line; across log entries RedactAfter carries the
		// context (the shipper keeps one bit per stream). accept wants
		// what a word does not have — `=` padding, a digit, `+` or `/` —
		// or an `-----END ` marker as the next line. A plain word after a
		// key body (`done`) is left alone; the price is a letters-only
		// unpadded tail with no END in sight, about 0.8^len of tails.
		re:     regexp.MustCompile(`(?m)^(<redacted:pem-body>\r?\n)[ \t]*[A-Za-z0-9+/]{1,69}={0,2}[ \t\r]*$`),
		repl:   `${1}<redacted:pem-tail>`,
		accept: acceptPemTail,
	},
	{
		kind: "age-key",
		gate: func(p probe) bool { return p.has("AGE-SECRET-KEY-1") }, // leak-ok: redactor gate string, not a key
		re:   regexp.MustCompile(`AGE-SECRET-KEY-1[A-Z0-9]{20,}`),     // leak-ok: redactor regex, not a key
		repl: `<redacted:age-key>`,
	},
	{
		kind: "authorization",
		gate: func(p probe) bool { return p.hasFold(bAuthorization) },
		// The header name, then an optional scheme word, then the
		// credential. A scheme followed by a placeholder is matched as a
		// whole and rewritten to itself (idempotent, not counted), which is
		// what stops the engine from falling back to "the scheme word IS
		// the value" on an already-scrubbed line.
		re:   regexp.MustCompile(`(?i)\b(authorization["']?[ \t]*[:=][ \t]*["']?)(?:((?:bearer|basic|token|digest)[ \t]+)(?:<redacted:[a-z-]+>|` + valueClass + `)|` + valueClass + `)`),
		repl: `${1}${2}<redacted:authorization>`,
	},
	{
		kind: "bearer",
		gate: func(p probe) bool { return p.hasFold(bBearer) },
		// 16+ chars: every bearer this system mints is far longer, and
		// "bearer of bad news" in prose is not one.
		re:   regexp.MustCompile(`(?i)\b(bearer[ \t]+)[^ \t"'<>,;]{16,}`),
		repl: `${1}<redacted:bearer>`,
	},
	{
		kind: "cookie",
		gate: func(p probe) bool { return p.hasFold(bCookie) },
		// `Cookie:` / `Set-Cookie:` — the refresh token rides in one. The
		// value is one or more `name=value` pairs joined by `;` (and a
		// Set-Cookie's bare attributes); it stops at whitespace that is not
		// after a `;`, so the log fields after the header survive. A
		// `name=` is required: "cookie: missing" in prose is not a value.
		re:   regexp.MustCompile(`(?i)\b((?:set-)?cookie["']?[ \t]*[:=][ \t]*["']?)[^ \t"'<>;=]+=[^ \t"'<>;]*(?:;[ \t]*[^ \t"'<>;=]+(?:=[^ \t"'<>;]*)?)*`),
		repl: `${1}<redacted:cookie>`,
	},
	{
		kind: "kv",
		gate: func(p probe) bool { return strings.ContainsAny(p.s, ":=") && p.stemThenSeparator() },
		// A key ENDING in a secret-ish stem (`NOO_CLUSTER_SECRET`,
		// `refresh_token`, `X-Api-Key`), then `=value` (no whitespace: a
		// `password= ` with nothing after it must not eat the next word)
		// or `: value` (a header, YAML or JSON), optional quotes. The stem
		// must be the end of the key: `tokens=`, `token_count=`,
		// `secret_name=`, `password_reset=` are not matched.
		// `key = value` (TOML/INI) is taken when there is whitespace BEFORE
		// the `=` — `password= next` still is not. A `NOO_…_KEY` (the
		// entitlement, audit, gateway, service and age keys) is taken as
		// well; a plain `key=`, `cache_key=`, `sort_key=` is not.
		re:   regexp.MustCompile(`(?i)\b((?:[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key)|noo_[a-z0-9_]*key)(?:=["']?|[ \t]+=[ \t]*["']?|["']?[ \t]*:[ \t]*["']?))` + pairValueClass),
		repl: `${1}<redacted:kv>`,
	},
	{
		kind: "dsn",
		gate: func(p probe) bool {
			i := strings.Index(p.s, "://")
			return i >= 0 && strings.IndexByte(p.s[i+3:], '@') >= 0
		},
		// scheme://user:PASSWORD@host — the user is kept, the password is
		// not. A password may not hold `/` (a URL-encoded one never does),
		// which is what keeps `https://host:8080/x@y` out.
		re:   regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://[^ \t:/@"'<>]+:)[^ \t@"'/<>]+@`),
		repl: `${1}<redacted:dsn>@`,
	},
	{
		kind: "userinfo",
		gate: func(p probe) bool { return strings.IndexByte(p.s, '@') > 0 && strings.IndexByte(p.s, ':') >= 0 },
		// `user:PASSWORD@host` with no scheme (a proxy setting, a
		// `redis-cli -u` without its `redis://`). The user is kept. The
		// decoy is an image reference pinned by tag AND digest,
		// `noo-gateway:v0.2.77@sha256:…`, which has the same spine: accept
		// refuses a "host" that is a digest algorithm.
		re:     regexp.MustCompile(`\b([A-Za-z0-9._~%-]+:)[^ \t@"'/<>:]+@([A-Za-z0-9][A-Za-z0-9.-]*)`),
		repl:   `${1}<redacted:userinfo>@${2}`,
		accept: acceptUserinfo,
	},
	{
		kind: "pgpass",
		gate: func(p probe) bool { return strings.Count(p.s, ":") >= 4 },
		// A ~/.pgpass line, `host:port:db:user:PASSWORD`, alone on its line
		// (a `cat`, an entrypoint echo). The port field must be digits or
		// `*`, and every field non-empty, so a MAC address or an IPv6
		// literal does not qualify.
		re:   regexp.MustCompile(`^([ \t]*[^: \t]+:(?:[0-9]+|\*):[^: \t]+:[^: \t]+:)(?:[^ \t\r:\\]|\\.)+[ \t\r]*$`),
		repl: `${1}<redacted:pgpass>`,
	},
	{
		kind: "redis-auth",
		gate: func(p probe) bool {
			return p.has("AUTH") || p.has("requirepass") || p.has("masterauth") || p.has("redis-cli")
		},
		// Redis passwords where redis itself shows them: an `AUTH` typed at
		// a prompt or starting the line (one or two arguments: ACL `AUTH
		// user pass`), the quoted MONITOR form `"AUTH" "…"`, `requirepass`
		// / `masterauth` as a config line, a `--flag` or `CONFIG SET`, and
		// `redis-cli -a` / `--pass`. Case-sensitive AUTH, and requirepass
		// only in those positions, because the entrypoint's own warning
		// says "An empty requirepass disables …" in prose.
		re: regexp.MustCompile(`((?:^[ \t]*|>[ \t]*)AUTH[ \t]+)` + valueClass + `(?:[ \t]+` + valueClass + `)?` +
			`|("AUTH"[ \t]+")[^"<]+(?:"[ \t]+"[^"<]+)?` +
			`|((?:^[ \t]*|--|(?i:config[ \t]+set[ \t]+))(?:requirepass|masterauth)[ \t]+["']?)` + valueClass +
			`|(\bredis-cli(?:[ \t]+[^ \t]+)*?[ \t]+(?:-a|--pass)[ \t]+["']?)` + valueClass),
		repl: `${1}${2}${3}${4}<redacted:redis-auth>`,
	},
	{
		kind: "cluster-token",
		gate: func(p probe) bool { return len(p.s) >= 1+1+10+1+32 && hasColonTenDigitsColon(p.s) },
		// `<actor>:<unix ts>:<hmac hex>`, 64 hex from every minter, 32 also
		// accepted by the gateway (auth.rs verify_cluster_token).
		re:   regexp.MustCompile(`\b[A-Za-z0-9_.-]+:[0-9]{10}:(?:[0-9a-f]{64}|[0-9a-f]{32})\b`),
		repl: `<redacted:cluster-token>`,
	},
	{
		kind: "service-key",
		gate: func(p probe) bool { return p.has("noo-sk-") },
		// routes/users.rs new_raw_key: "noo-sk-" + 43 base64url chars.
		re:   regexp.MustCompile(`\bnoo-sk-[A-Za-z0-9_-]{20,}`),
		repl: `<redacted:service-key>`,
	},
	{
		kind: "addon-key",
		gate: func(p probe) bool { return p.has("noo-ak-") },
		// gateway addon_auth.rs mint: "noo-ak-" + 64 hex.
		// Bare, the same 64 hex is an image digest and is left alone.
		re:   regexp.MustCompile(`\bnoo-ak-[0-9a-fA-F]{20,}`),
		repl: `<redacted:addon-key>`,
	},
	{
		kind: "bootstrap-token",
		gate: func(p probe) bool { return p.has("noo-bt-") },
		// gateway auth_refresh.rs generate_bootstrap_token: "noo-bt-" + 43
		// base64url. One minted before the prefix is bare
		// and only the opaque-token heuristic below can see it.
		re:   regexp.MustCompile(`\bnoo-bt-[A-Za-z0-9_-]{20,}`),
		repl: `<redacted:bootstrap-token>`,
	},
	{
		kind: "refresh-token",
		gate: func(p probe) bool { return p.has("noo-rt-") },
		// gateway auth_refresh.rs generate_raw_token: "noo-rt-" + 43
		// base64url, the noo_refresh cookie's value.
		re:   regexp.MustCompile(`\bnoo-rt-[A-Za-z0-9_-]{20,}`),
		repl: `<redacted:refresh-token>`,
	},
	{
		kind: "jwt",
		gate: func(p probe) bool { return p.has("eyJ") },
		re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		repl: `<redacted:jwt>`,
	},
	{
		kind: "telegram-token",
		gate: func(p probe) bool { return hasDigitRunThenColon(p.s, 8) },
		// `<8-10 digits>:<35 chars>`; no leading \b because the URL form is
		// `/bot<token>/`. The delimiter after it is kept.
		re:   regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}([^A-Za-z0-9_-]|$)`),
		repl: `<redacted:telegram-token>${1}`,
	},
	{
		kind: "api-key",
		gate: func(p probe) bool { return p.has("sk-") },
		re:   regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
		repl: `<redacted:api-key>`,
	},
	{
		kind: "tailscale-key",
		gate: func(p probe) bool { return p.has("tskey-") },
		re:   regexp.MustCompile(`\btskey-[A-Za-z0-9_-]{10,}`),
		repl: `<redacted:tailscale-key>`,
	},
	{
		// tailscaled logs a one-time login URL when the node must
		// (re-)authenticate; whoever opens it first attaches the node to
		// their tailnet. Shipped once tailscaled's journal is followed.
		kind: "tailscale-login-url",
		gate: func(p probe) bool { return p.has("login.tailscale.com/a/") },
		re:   regexp.MustCompile(`\bhttps://login\.tailscale\.com/a/[A-Za-z0-9]{6,}`),
		repl: `<redacted:tailscale-login-url>`,
	},
	{
		kind: "github-token",
		gate: func(p probe) bool {
			return p.has("ghp_") || p.has("gho_") || p.has("ghu_") || p.has("ghs_") ||
				p.has("ghr_") || p.has("github_pat_")
		},
		re:   regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`),
		repl: `<redacted:github-token>`,
	},
	{
		kind: "aws-key",
		gate: func(p probe) bool { return p.has("AKIA") || p.has("ASIA") },
		re:   regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		repl: `<redacted:aws-key>`,
	},
	{
		kind: "bcrypt",
		gate: func(p probe) bool { return p.has("$2") },
		// A bcrypt digest (`$2a$11$` + 53): what NATS's users.conf holds
		// for every principal. Not a secret, but a verifier: whoever holds
		// it can guess offline, at leisure, against a password that is
		// still live. It has no business in a store every operator reads.
		re:   regexp.MustCompile(`\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}`),
		repl: `<redacted:bcrypt>`,
	},
	{
		kind: "aws-secret",
		gate: func(p probe) bool { return hasRun(p.s, isB64Std, 40) },
		// A bare AWS secret access key: exactly 40 standard-base64
		// characters. A git SHA is 40 too, so accept wants an upper, a
		// lower, a digit and a character hex has not, with no base64
		// neighbour on either side.
		re:     regexp.MustCompile(`[A-Za-z0-9+/]{40,}`),
		repl:   `<redacted:aws-secret>`,
		accept: func(line string, start, end int) bool { return acceptBare(line, start, end, 40, "-_=") },
	},
	{
		kind: "opaque-token",
		gate: func(p probe) bool { return hasRun(p.s, isB64URL, 43) },
		// 32 CSPRNG bytes as unpadded base64url — exactly 43 characters:
		// the bootstrap and refresh tokens (auth_refresh.rs
		// generate_raw_token), and Python's token_urlsafe(32). Same accept
		// as above; a padded (`=`) run is a standard-base64 digest.
		re:     regexp.MustCompile(`[A-Za-z0-9_-]{43,}`),
		repl:   `<redacted:opaque-token>`,
		accept: func(line string, start, end int) bool { return acceptBare(line, start, end, 43, "+=") },
	},
}

// pemBodyPlaceholder is what a full-width PEM body line becomes.
const pemBodyPlaceholder = "<redacted:pem-body>"

// RedactAfter is Redact with the previous entry of the same stream as
// context: prev is that entry AS REDACTED. When its last line was a PEM
// body line (now the pem-body placeholder), line is scrubbed as the line
// that follows it, so a key printed one line per entry loses its short
// last line too (pem-tail). Otherwise it is Redact. The Rust twin is
// redact::scrub_secrets_after.
func RedactAfter(prev, line string) (string, int) {
	if prev[strings.LastIndexByte(prev, '\n')+1:] != pemBodyPlaceholder || line == "" {
		return Redact(line)
	}
	out, n := Redact(pemBodyPlaceholder + "\n" + line)
	if n == 0 {
		return line, 0
	}
	return out[len(pemBodyPlaceholder)+1:], n
}

// minRedactable is the shortest line that can hold any shape (`pwd=a`).
const minRedactable = 5

// Redact scrubs every credential shape out of line. Returns the line and
// the number of replacements that CHANGED it (an idempotent rewrite of an
// existing placeholder is not a redaction). A line with nothing to scrub
// comes back as the same string, no copy.
func Redact(line string) (string, int) {
	if len(line) < minRedactable {
		return line, 0
	}
	bp := probePool.Get().(*[]byte)
	p := newProbe(line, (*bp)[:0])
	n := 0
	for i := range shapes {
		sh := &shapes[i]
		if sh.gate != nil && !sh.gate(p) {
			continue
		}
		idx := sh.re.FindAllStringSubmatchIndex(line, -1)
		if idx == nil {
			continue
		}
		b := make([]byte, 0, len(line))
		last := 0
		for _, m := range idx {
			b = append(b, line[last:m[0]]...)
			start := len(b)
			if sh.accept != nil && !sh.accept(line, m[0], m[1]) {
				b = append(b, line[m[0]:m[1]]...)
				last = m[1]
				continue
			}
			b = sh.re.ExpandString(b, sh.repl, line, m)
			if string(b[start:]) != line[m[0]:m[1]] {
				n++
			}
			last = m[1]
		}
		b = append(b, line[last:]...)
		line = string(b)
		// The gates read the ORIGINAL line; a placeholder introduces no
		// new shape, so the probe stays valid for the rows that follow.
	}
	if cap(p.lower) <= 64<<10 {
		*bp = p.lower[:0]
		probePool.Put(bp)
	}
	return line, n
}

// probePool recycles the lower-cased copy: a 1 KB buffer covers nearly
// every line, and a longer line's buffer is kept unless it grew past 64 KB.
var probePool = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}

// ShapeKinds lists the table's kinds in order (for tests and the parity
// guard).
func ShapeKinds() []string {
	out := make([]string, 0, len(shapes))
	for _, sh := range shapes {
		out = append(out, sh.kind)
	}
	return out
}

// probe is the line plus one ASCII-lower-cased copy, made once per line
// so the case-insensitive gates are a bytes.Index (SIMD) rather than a
// byte loop each. Passed by value so nothing escapes to the heap.
type probe struct {
	s     string
	lower []byte
}

func newProbe(s string, buf []byte) probe {
	if cap(buf) < len(s) {
		buf = make([]byte, 0, len(s))
	}
	buf = buf[:len(s)]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return probe{s: s, lower: buf}
}

func (p probe) has(sub string) bool     { return strings.Contains(p.s, sub) }
func (p probe) hasFold(sub []byte) bool { return bytes.Contains(p.lower, sub) }

var (
	bAuthorization = []byte("authorization")
	bBearer        = []byte("bearer")
	bCookie        = []byte("cookie")
	// pairStems are the ENDINGS of the kv regex's key alternatives
	// (`api_key` ends in `key`, and so on), lower-case.
	pairStems = [][]byte{[]byte("password"), []byte("passwd"), []byte("pwd"), []byte("secret"), []byte("token"), []byte("key")}
)

// stemThenSeparator: one of the pair shape's key stems, immediately
// followed by a separator (`=`, `:`, a quote, or the space before a `:`).
// A superset of what the kv regex matches, and tight enough that vLLM's
// `tokens/s` or a `max_tokens=` never wakes the engine.
func (p probe) stemThenSeparator() bool {
	for _, stem := range pairStems {
		rest := p.lower
		for {
			i := bytes.Index(rest, stem)
			if i < 0 {
				break
			}
			j := i + len(stem)
			if j < len(rest) {
				switch rest[j] {
				case '=', ':', '"', '\'', ' ', '\t':
					return true
				}
			}
			rest = rest[i+1:]
		}
	}
	return false
}

// hasColonTenDigitsColon: `:` + exactly ten digits + `:` somewhere in s
// (the cluster token's `:<unix ts>:` spine).
func hasColonTenDigitsColon(s string) bool {
	for i := 0; i+12 <= len(s); i++ {
		if s[i] != ':' || s[i+11] != ':' {
			continue
		}
		ok := true
		for j := i + 1; j <= i+10; j++ {
			if s[j] < '0' || s[j] > '9' {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// hasDigitRunThenColon: a run of at least min digits directly before a `:`.
func hasDigitRunThenColon(s string, min int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			run++
		case c == ':' && run >= min:
			return true
		default:
			run = 0
		}
	}
	return false
}

// ── the bare shapes' predicates ──────────────────────────────────────

func isB64Std(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/'
}

func isB64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// hasRun: a maximal run of at least min bytes of class somewhere in s.
func hasRun(s string, class func(byte) bool, min int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		if class(s[i]) {
			run++
			if run >= min {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// hasNonHex: a byte outside [0-9A-Fa-f] — what a digest never has.
func hasNonHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return true
		}
	}
	return false
}

// acceptBare: the (maximal) run is exactly n long, holds an upper, a
// lower, a digit and a non-hex byte, and neither neighbour is in notNear —
// the other alphabet's extra bytes and padding, so a slice of a longer
// blob in the other alphabet is not taken. A `/` beside a base64url token
// is a URL path separator and is allowed.
func acceptBare(line string, start, end, n int, notNear string) bool {
	// A run that opens with `/` is an absolute path (`/api/…/Node1/…`
	// can be 40 long); a secret opening with one is 1 in 64, and missed.
	if end-start != n || line[start] == '/' {
		return false
	}
	near := func(c byte) bool { return strings.IndexByte(notNear, c) >= 0 }
	if start > 0 && near(line[start-1]) || end < len(line) && near(line[end]) {
		return false
	}
	var up, lo, dig bool
	for i := start; i < end; i++ {
		c := line[i]
		switch {
		case 'A' <= c && c <= 'Z':
			up = true
		case 'a' <= c && c <= 'z':
			lo = true
		case '0' <= c && c <= '9':
			dig = true
		}
	}
	return up && lo && dig && hasNonHex(line[start:end])
}

// acceptPemTail: the matched tail (after the placeholder line) carries
// padding, a digit, `+` or `/`, or the next line is an `-----END ` marker.
func acceptPemTail(line string, start, end int) bool {
	m := line[start:end]
	tail := strings.Trim(m[strings.LastIndexByte(m, '\n')+1:], " \t\r")
	if strings.HasSuffix(tail, "=") || strings.ContainsAny(tail, "0123456789+/") {
		return true
	}
	rest, ok := strings.CutPrefix(line[end:], "\n")
	return ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), "-----END ")
}

// acceptUserinfo refuses `name:tag@sha256:…`, an image pinned by digest.
func acceptUserinfo(line string, start, end int) bool {
	m := line[start:end]
	host := m[strings.LastIndexByte(m, '@')+1:]
	switch strings.ToLower(host) {
	case "sha256", "sha384", "sha512":
		return false
	}
	return true
}
