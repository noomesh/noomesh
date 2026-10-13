// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Scrubbing secrets out of strings that are about to be LOGGED.
//!
//! The Telegram bot token lives in the request PATH
//! (`https://api.telegram.org/bot<token>/getUpdates`), and a `reqwest` error
//! renders the URL it failed on. So every place that stringified such an error
//! wrote the token into the journal in full — `telegram_poll_error` did it on
//! every failed poll, and a 502 from Telegram is routine, so the token was in
//! the log many times over (observed on the live controller, 2026-09-12).
//!
//! That token is the bot's password: anyone holding it can read the chat and
//! post as the bot. A log is not the place for it, and `docker logs` is read
//! and pasted freely during an incident, which is exactly when this would be
//! handed to someone.
//!
//! The fix is to scrub at the LOGGING boundary rather than to avoid building
//! the URL, because the URL is what the API takes and the error is what renders
//! it. One function, used by every site that turns such an error into text.

/// Replace any `bot<id>:<secret>` path segment with `bot<redacted>`.
///
/// Shape-based rather than value-based on purpose: it does not need the token
/// to compare against, so it keeps working for a rotated token, a second bot,
/// and a token this process never held.
pub fn scrub(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A token segment starts at "bot" followed by digits and a colon.
        if bytes[i..].starts_with(b"bot") && looks_like_token(&s[i + 3..]) {
            out.push_str("bot<redacted>");
            i += 3;
            // Consume the token itself: digits, colon, then the secret body.
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            continue;
        }
        let ch = s[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `<digits>:<something>` — the Telegram token shape. Requiring the colon is
/// what keeps the word "bot" in ordinary prose from being mangled.
fn looks_like_token(rest: &str) -> bool {
    let mut seen_digit = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            seen_digit = true;
            continue;
        }
        return c == ':' && seen_digit;
    }
    false
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-'
}

// ── Every credential shape, for lines about to be STORED ─────────────
//
// The log shipper (node-agent-go/internal/logship/redact.go) scrubs every
// line at intake, before its spill file and before the wire. The gateway
// repeats the SAME table on ingest (`routes/logs_ingest.rs::prepare_push`)
// as defence in depth: an agent older than the scrubber, or a line that
// reached the route some other way, still meets it before Loki.
//
// Shape-based, like [`scrub`] above and for the same reason: no value to
// compare against, so a rotated or foreign secret is caught too, and the
// cost of that is the caveat operators are told — a secret in a shape this
// table does not name ships. Add the shape, not a value.
//
// The Go and Rust tables cannot share source. They share a vector:
// `tests/fixtures/redaction_corpus.json` is loaded by both unit tests
// (here with `include_str!`), and `tests/test_log_redaction_parity.py`
// holds the KINDS in both tables, the corpus and the operator doc equal.
// The table is ORDERED and the order is part of the contract — see the Go
// twin for why each row sits where it does.
//
// Pattern dialect: ASCII boundaries `(?-u:\b)` and explicit `[ \t]`
// rather than `\s`, so this engine agrees with Go's RE2 (whose `\b` and
// `\s` are ASCII) on non-ASCII neighbours.

use regex::{Captures, Regex};
use std::borrow::Cow;
use std::sync::LazyLock;

/// One row of the table.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    pub kind: &'static str,
    pattern: &'static str,
    replacement: &'static str,
}

const VALUE: &str = r#"[^ \t"'<>,;]+"#;
const PAIR_VALUE: &str = r#"[^ \t"'<>,;&}\]]+"#;

/// The table. Kinds are the operator-facing label; the parity test reads
/// them from this file by the `kind: "…"` literal.
pub static SHAPES: LazyLock<Vec<Shape>> = LazyLock::new(|| {
    vec![
        Shape {
            kind: "pem",
            pattern: r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(?:.*?(-----END [A-Z ]*PRIVATE KEY-----)|.*)",
            replacement: "${1}<redacted:pem>${2}",
        },
        // A PEM body one base64 line per log line, or per line of a
        // multi-line string; see the Go twin. Accept: `has_non_hex` (a bare
        // 64-hex digest line is the decoy).
        Shape {
            kind: "pem-body",
            pattern: r"(?m)^[ \t]*(?:[A-Za-z0-9+/]{70}|[A-Za-z0-9+/]{64})[ \t\r]*$",
            replacement: "<redacted:pem-body>",
        },
        // The body's short LAST line, by context: the line right after a
        // full-width body line (already a placeholder, the row above runs
        // first). Across log entries the context is carried by
        // [`scrub_secrets_after`]. Accept: `accept_pem_tail` (padding, a
        // digit, `+` or `/`, or an END marker next — a plain word is not
        // a tail). .
        Shape {
            kind: "pem-tail",
            pattern: r"(?m)^(<redacted:pem-body>\r?\n)[ \t]*[A-Za-z0-9+/]{1,69}={0,2}[ \t\r]*$",
            replacement: "${1}<redacted:pem-tail>",
        },
        Shape { kind: "age-key", pattern: r"AGE-SECRET-KEY-1[A-Z0-9]{20,}", replacement: "<redacted:age-key>" }, // leak-ok: the pattern for the shape, not a key
        Shape {
            kind: "authorization",
            pattern: Box::leak(
                format!(
                    r#"(?i)(?-u:\b)(authorization["']?[ \t]*[:=][ \t]*["']?)(?:((?:bearer|basic|token|digest)[ \t]+)(?:<redacted:[a-z-]+>|{VALUE})|{VALUE})"#
                )
                .into_boxed_str(),
            ),
            replacement: "${1}${2}<redacted:authorization>",
        },
        Shape {
            kind: "bearer",
            pattern: r#"(?i)(?-u:\b)(bearer[ \t]+)[^ \t"'<>,;]{16,}"#,
            replacement: "${1}<redacted:bearer>",
        },
        Shape {
            kind: "cookie",
            pattern: r#"(?i)(?-u:\b)((?:set-)?cookie["']?[ \t]*[:=][ \t]*["']?)[^ \t"'<>;=]+=[^ \t"'<>;]*(?:;[ \t]*[^ \t"'<>;=]+(?:=[^ \t"'<>;]*)?)*"#,
            replacement: "${1}<redacted:cookie>",
        },
        Shape {
            kind: "kv",
            pattern: Box::leak(
                format!(
                    r#"(?i)(?-u:\b)((?:[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key)|noo_[a-z0-9_]*key)(?:=["']?|[ \t]+=[ \t]*["']?|["']?[ \t]*:[ \t]*["']?)){PAIR_VALUE}"#
                )
                .into_boxed_str(),
            ),
            replacement: "${1}<redacted:kv>",
        },
        Shape {
            kind: "dsn",
            pattern: r#"(?-u:\b)([a-zA-Z][a-zA-Z0-9+.-]*://[^ \t:/@"'<>]+:)[^ \t@"'/<>]+@"#,
            replacement: "${1}<redacted:dsn>@",
        },
        // Accept: `accept_userinfo` (an image `name:tag@sha256:` is not one).
        Shape {
            kind: "userinfo",
            pattern: r#"(?-u:\b)([A-Za-z0-9._~%-]+:)[^ \t@"'/<>:]+@([A-Za-z0-9][A-Za-z0-9.-]*)"#,
            replacement: "${1}<redacted:userinfo>@${2}",
        },
        Shape {
            kind: "pgpass",
            pattern: r"^([ \t]*[^: \t]+:(?:[0-9]+|\*):[^: \t]+:[^: \t]+:)(?:[^ \t\r:\\]|\\.)+[ \t\r]*$",
            replacement: "${1}<redacted:pgpass>",
        },
        Shape {
            kind: "redis-auth",
            pattern: Box::leak(
                format!(
                    r#"((?:^[ \t]*|>[ \t]*)AUTH[ \t]+){VALUE}(?:[ \t]+{VALUE})?|("AUTH"[ \t]+")[^"<]+(?:"[ \t]+"[^"<]+)?|((?:^[ \t]*|--|(?i:config[ \t]+set[ \t]+))(?:requirepass|masterauth)[ \t]+["']?){VALUE}|((?-u:\b)redis-cli(?:[ \t]+[^ \t]+)*?[ \t]+(?:-a|--pass)[ \t]+["']?){VALUE}"#
                )
                .into_boxed_str(),
            ),
            replacement: "${1}${2}${3}${4}<redacted:redis-auth>",
        },
        Shape {
            kind: "cluster-token",
            pattern: r"(?-u:\b)[A-Za-z0-9_.-]+:[0-9]{10}:(?:[0-9a-f]{64}|[0-9a-f]{32})(?-u:\b)",
            replacement: "<redacted:cluster-token>",
        },
        Shape {
            kind: "service-key",
            pattern: r"(?-u:\b)noo-sk-[A-Za-z0-9_-]{20,}",
            replacement: "<redacted:service-key>",
        },
        // addon_auth.rs mint: "noo-ak-" + 64 hex. The prefix
        // is the whole point: bare, the same 64 hex is an image digest.
        Shape {
            kind: "addon-key",
            pattern: r"(?-u:\b)noo-ak-[0-9a-fA-F]{20,}",
            replacement: "<redacted:addon-key>",
        },
        // auth_refresh.rs: "noo-bt-" / "noo-rt-" + 43 base64url. A token minted before the prefix is bare; only the
        // opaque-token heuristic below sees that one.
        Shape {
            kind: "bootstrap-token",
            pattern: r"(?-u:\b)noo-bt-[A-Za-z0-9_-]{20,}",
            replacement: "<redacted:bootstrap-token>",
        },
        Shape {
            kind: "refresh-token",
            pattern: r"(?-u:\b)noo-rt-[A-Za-z0-9_-]{20,}",
            replacement: "<redacted:refresh-token>",
        },
        Shape {
            kind: "jwt",
            pattern: r"(?-u:\b)eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            replacement: "<redacted:jwt>",
        },
        Shape {
            kind: "telegram-token",
            pattern: r"[0-9]{8,10}:[A-Za-z0-9_-]{35}([^A-Za-z0-9_-]|$)",
            replacement: "<redacted:telegram-token>${1}",
        },
        Shape { kind: "api-key", pattern: r"(?-u:\b)sk-[A-Za-z0-9_-]{20,}", replacement: "<redacted:api-key>" },
        Shape {
            kind: "tailscale-key",
            pattern: r"(?-u:\b)tskey-[A-Za-z0-9_-]{10,}",
            replacement: "<redacted:tailscale-key>",
        },
        Shape {
            kind: "tailscale-login-url",
            pattern: r"(?-u:\b)https://login\.tailscale\.com/a/[A-Za-z0-9]{6,}",
            replacement: "<redacted:tailscale-login-url>",
        },
        Shape {
            kind: "github-token",
            pattern: r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
            replacement: "<redacted:github-token>",
        },
        Shape { kind: "aws-key", pattern: r"(?-u:\b)(?:AKIA|ASIA)[A-Z0-9]{16}(?-u:\b)", replacement: "<redacted:aws-key>" },
        Shape { kind: "bcrypt", pattern: r"\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}", replacement: "<redacted:bcrypt>" },
        // The two bare shapes; accept: `accept_bare` (exact length, an
        // upper, a lower, a digit, a non-hex byte, no foreign neighbour).
        Shape { kind: "aws-secret", pattern: r"[A-Za-z0-9+/]{40,}", replacement: "<redacted:aws-secret>" },
        Shape { kind: "opaque-token", pattern: r"[A-Za-z0-9_-]{43,}", replacement: "<redacted:opaque-token>" },
    ]
});

/// A match predicate: the whole line and the match's byte range; `false`
/// keeps the match as it is.
type Accept = fn(&str, usize, usize) -> bool;

/// The rows whose regex cannot say everything (no look-around in either
/// engine). The Go twin carries the same predicate as the row's `accept`
/// field; `tests/test_log_redaction_parity.py` holds the two sets equal.
fn accept_for(kind: &str) -> Option<Accept> {
    match kind {
        "pem-body" => Some(|line, s, e| has_non_hex(line[s..e].trim_matches([' ', '\t', '\r']))),
        "pem-tail" => Some(accept_pem_tail),
        "userinfo" => Some(accept_userinfo),
        "aws-secret" => Some(|line, s, e| accept_bare(line, s, e, 40, b"-_=")),
        "opaque-token" => Some(|line, s, e| accept_bare(line, s, e, 43, b"+=")),
        _ => None,
    }
}

fn has_non_hex(s: &str) -> bool {
    s.bytes().any(|c| !c.is_ascii_hexdigit())
}

/// The (maximal) run is exactly `n` long, holds an upper, a lower, a digit
/// and a non-hex byte, and neither neighbour is in `not_near` (the other
/// base64 alphabet's extra bytes and padding). See the Go twin.
fn accept_bare(line: &str, start: usize, end: usize, n: usize, not_near: &[u8]) -> bool {
    let b = line.as_bytes();
    // A run opening with `/` is an absolute path, not a key (Go twin).
    if end - start != n || b[start] == b'/' {
        return false;
    }
    if (start > 0 && not_near.contains(&b[start - 1])) || (end < b.len() && not_near.contains(&b[end])) {
        return false;
    }
    let run = &b[start..end];
    run.iter().any(u8::is_ascii_uppercase)
        && run.iter().any(u8::is_ascii_lowercase)
        && run.iter().any(u8::is_ascii_digit)
        && has_non_hex(&line[start..end])
}

/// The line after a full-width PEM body line is the body's last line when
/// it carries what a word does not: `=` padding, a digit, `+` or `/` — or
/// when an `-----END ` marker is the next line, whatever it holds. A plain
/// word (`done`, `Finished`) after a key body is left alone; a tail of
/// letters only, unpadded and with no END marker in sight, is missed (see
/// the Go twin for the odds).
fn accept_pem_tail(line: &str, start: usize, end: usize) -> bool {
    let m = &line[start..end];
    let tail = m[m.rfind('\n').map_or(0, |i| i + 1)..].trim_matches([' ', '\t', '\r']);
    if tail.ends_with('=') || tail.bytes().any(|c| c.is_ascii_digit() || c == b'+' || c == b'/') {
        return true;
    }
    line[end..]
        .strip_prefix('\n')
        .is_some_and(|rest| rest.trim_start_matches([' ', '\t']).starts_with("-----END "))
}

/// `name:tag@sha256:…` is an image pinned by digest, not a password.
fn accept_userinfo(line: &str, start: usize, end: usize) -> bool {
    let m = &line[start..end];
    let host = &m[m.rfind('@').map_or(0, |i| i + 1)..];
    !matches!(host.to_ascii_lowercase().as_str(), "sha256" | "sha384" | "sha512")
}

type Compiled = (&'static str, Regex, &'static str, Option<Accept>);

static COMPILED: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    SHAPES
        .iter()
        .map(|s| {
            (
                s.kind,
                Regex::new(s.pattern).unwrap_or_else(|e| panic!("redaction shape {}: {e}", s.kind)),
                s.replacement,
                accept_for(s.kind),
            )
        })
        .collect()
});

/// The two BARE rows: a guess from length and alphabet alone, with no
/// prefix or context. Right for a log line (a missed secret is stored for
/// `NOO_LOKI_RETENTION`, read by every operator); wrong for a reply a
/// person reads, where a 40/43-character mixed-case identifier the user
/// asked about would come back as `<redacted:…>`. The channel path
/// ([`scrub_secrets_for_channel`]) skips these; every prefixed and
/// structured row still runs there. .
pub const BARE_HEURISTIC_KINDS: &[&str] = &["aws-secret", "opaque-token"];

/// Scrub every credential shape out of `line`. Returns the line and the
/// number of replacements that CHANGED it (rewriting an existing
/// placeholder to itself is not a redaction, so a second pass over a line
/// the shipper already scrubbed counts nothing). A line with nothing to
/// scrub is returned borrowed.
pub fn scrub_secrets(line: &str) -> (Cow<'_, str>, u64) {
    scrub_with(line, &[])
}

/// [`scrub_secrets`] for text bound for a CHANNEL (`egress.rs`): the whole
/// table except [`BARE_HEURISTIC_KINDS`]. Logs keep the full table.
pub fn scrub_secrets_for_channel(line: &str) -> (Cow<'_, str>, u64) {
    scrub_with(line, BARE_HEURISTIC_KINDS)
}

/// The placeholder a full-width PEM body line becomes.
pub const PEM_BODY_PLACEHOLDER: &str = "<redacted:pem-body>";

/// [`scrub_secrets`] with the previous entry of the same stream as context:
/// `prev` is that entry AS SCRUBBED. When its last line was a PEM body line
/// (now the `pem-body` placeholder), `line` is scrubbed as the line that
/// follows it, so a key printed one line per entry loses its short last
/// line too (`pem-tail`). Otherwise this is [`scrub_secrets`]. The Go
/// shipper's `RedactAfter` is the twin.
pub fn scrub_secrets_after<'a>(prev: &str, line: &'a str) -> (Cow<'a, str>, u64) {
    let last = &prev[prev.rfind('\n').map_or(0, |i| i + 1)..];
    if last != PEM_BODY_PLACEHOLDER || line.is_empty() {
        return scrub_secrets(line);
    }
    let joined = format!("{PEM_BODY_PLACEHOLDER}\n{line}");
    let (out, n) = scrub_secrets(&joined);
    if n == 0 {
        return (Cow::Borrowed(line), 0);
    }
    (Cow::Owned(out[PEM_BODY_PLACEHOLDER.len() + 1..].to_string()), n)
}

fn scrub_with<'a>(line: &'a str, skip: &[&str]) -> (Cow<'a, str>, u64) {
    let mut cur: Cow<'a, str> = Cow::Borrowed(line);
    let mut count = 0u64;
    for (kind, re, repl, accept) in COMPILED.iter() {
        if skip.contains(kind) || !re.is_match(&cur) {
            continue;
        }
        let before = count;
        let replaced = re.replace_all(&cur, |caps: &Captures| {
            let m = caps.get(0).expect("group 0 is the match");
            if let Some(ok) = accept {
                if !ok(&cur, m.start(), m.end()) {
                    return m.as_str().to_string();
                }
            }
            let mut out = String::new();
            caps.expand(repl, &mut out);
            if out != caps[0] {
                count += 1;
            }
            out
        });
        // A match that rewrote itself (a placeholder behind a scheme word)
        // changed nothing: keep the borrow rather than the identical copy.
        if count == before {
            continue;
        }
        if let Cow::Owned(s) = replaced {
            cur = Cow::Owned(s);
        }
    }
    (cur, count)
}

/// A URL with its userinfo (`user:password@`) removed, for LOG LINES that
/// name where a client connected: `rediss://:hunter2@redis:6379/0` →
/// `rediss://redis:6379/0`. An operator who puts the password in
/// `REDIS_URL` or `NATS_URL` (both accept it) had it written to the journal
/// in full at every connect (`cache.rs`, `state.rs`, `bus.rs`, 2026-09-29).
///
/// Structural, not a regex over the whole line: it takes the URL itself,
/// finds the authority (between `://` and the next `/`, `?` or `#`) and
/// drops everything up to and including its LAST `@`. A string with no
/// scheme or no `@` in the authority comes back unchanged, so a bare
/// `host:port` is still readable. The username goes too: it is half of the
/// credential, and the host is what the line is for.
pub fn scrub_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let auth_start = scheme_end + 3;
    let rest = &url[auth_start..];
    let auth_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_len];
    match authority.rfind('@') {
        Some(at) => format!("{}{}{}", &url[..auth_start], &authority[at + 1..], &rest[auth_len..]),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod url_userinfo_tests {
    use super::scrub_url_userinfo;

    #[test]
    fn a_password_in_the_url_does_not_reach_the_log() {
        let out = scrub_url_userinfo("rediss://:hunter2@redis:6379/0");
        assert_eq!(out, "rediss://redis:6379/0");
        let out = scrub_url_userinfo("tls://noo:s3cret@nats:4222");
        assert_eq!(out, "tls://nats:4222", "the username is half the credential and goes too");
    }

    #[test]
    fn a_url_without_userinfo_is_unchanged() {
        for u in ["rediss://redis:6379", "tls://nats:4222", "https://h/p?q=1#f", "redis:6379", ""] {
            assert_eq!(scrub_url_userinfo(u), u);
        }
    }

    #[test]
    fn an_at_sign_past_the_authority_is_not_userinfo() {
        // `@` in a path or query is data, not a credential boundary.
        assert_eq!(scrub_url_userinfo("https://h:1/x@y?u=a@b"), "https://h:1/x@y?u=a@b");
        // And a password that itself contains `@` is cut at the LAST one.
        assert_eq!(scrub_url_userinfo("rediss://u:p@ss@redis:6379"), "rediss://redis:6379");
    }
}

#[cfg(test)]
mod secret_shape_tests {
    use super::{
        scrub_secrets, scrub_secrets_after, scrub_secrets_for_channel, BARE_HEURISTIC_KINDS, PEM_BODY_PLACEHOLDER,
        SHAPES,
    };
    use std::borrow::Cow;
    use serde_json::Value;

    /// The shared vector. Move the file and this and the Go test both fail.
    const CORPUS: &str = include_str!("../../tests/fixtures/redaction_corpus.json");

    fn cases() -> Vec<(String, String, String)> {
        let doc: Value = serde_json::from_str(CORPUS).expect("corpus is JSON");
        let cases = doc["cases"].as_array().expect("corpus has cases");
        assert!(cases.len() >= 20, "corpus holds {} cases; too thin to be the real file", cases.len());
        cases
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap().to_string(),
                    c["line"].as_str().unwrap().to_string(),
                    c["expected"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// The Rust half of the parity contract. Planted 2026-09-28: the
    /// `service-key` row removed from `SHAPES` → the "service key as
    /// issued" case fails here and nowhere else.
    #[test]
    fn scrub_secrets_matches_the_shared_corpus() {
        let (mut secrets, mut clean) = (0, 0);
        for (name, line, expected) in cases() {
            let (got, n) = scrub_secrets(&line);
            assert_eq!(got.as_ref(), expected, "{name}\n  line {line:?}");
            if expected == line {
                clean += 1;
                assert_eq!(n, 0, "{name}: a must-not-touch line counted {n}");
                assert!(matches!(got, std::borrow::Cow::Borrowed(_)), "{name}: a clean line must come back borrowed");
            } else {
                secrets += 1;
                assert!(n > 0, "{name}: the line changed but the count is zero");
            }
        }
        assert!(secrets >= 10 && clean >= 8, "corpus is thin: {secrets} secret, {clean} clean");
    }

    #[test]
    fn a_second_pass_changes_nothing_and_counts_nothing() {
        for (name, line, _) in cases() {
            let (once, _) = scrub_secrets(&line);
            let (twice, n) = scrub_secrets(&once);
            assert_eq!(twice, once, "{name}");
            assert_eq!(n, 0, "{name}");
        }
    }

    /// across entries: the previous entry as
    /// scrubbed is the context. Planted 2026-10-02: the `pem-tail` row
    /// removed → this and the corpus cases fail.
    #[test]
    fn a_pem_body_s_short_last_line_is_caught_after_a_body_line() {
        let (body, _) = scrub_secrets("r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g");
        assert_eq!(body, PEM_BODY_PLACEHOLDER);
        let (tail, n) = scrub_secrets_after(&body, "Qw3rTy+Uio==");
        assert_eq!((tail.as_ref(), n), ("<redacted:pem-tail>", 1));
        // Without the context the same line is ordinary text.
        let (alone, n) = scrub_secrets_after("level=info", "Qw3rTy+Uio==");
        assert_eq!((alone.as_ref(), n), ("Qw3rTy+Uio==", 0));
        assert!(matches!(alone, Cow::Borrowed(_)));
        // A word after a body line is not a tail, and comes back borrowed.
        let (word, n) = scrub_secrets_after(&body, "done");
        assert_eq!((word.as_ref(), n), ("done", 0));
        assert!(matches!(word, Cow::Borrowed(_)));
        // Another body line after a body line is a body line.
        let (next, n) = scrub_secrets_after(&body, "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g");
        assert_eq!((next.as_ref(), n), (PEM_BODY_PLACEHOLDER, 1));
    }

    /// the channel variant skips exactly the bare rows.
    #[test]
    fn the_channel_table_skips_only_the_bare_guesses() {
        let bare = "id RQm-sKtAHXH6SlzZSlXJp08TMyd2rkAZxb_EwgBRV_8 and wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let (out, n) = scrub_secrets_for_channel(bare);
        assert_eq!((out.as_ref(), n), (bare, 0));
        let (out, n) = scrub_secrets(bare);
        assert_eq!(n, 2, "{out}");
        for k in BARE_HEURISTIC_KINDS {
            assert!(SHAPES.iter().any(|s| s.kind == *k), "{k} is not a row");
        }
        // Every other row still runs on the channel path: the corpus,
        // less the cases only a bare row changes, reads the same.
        for (name, line, expected) in cases() {
            if BARE_HEURISTIC_KINDS.iter().any(|k| expected.contains(&format!("<redacted:{k}>"))) {
                continue;
            }
            assert_eq!(scrub_secrets_for_channel(&line).0.as_ref(), expected, "{name}");
        }
    }

    #[test]
    fn every_shape_labels_its_replacement_with_its_own_kind() {
        let mut seen = std::collections::HashSet::new();
        for s in SHAPES.iter() {
            assert!(seen.insert(s.kind), "kind {} repeated", s.kind);
            assert!(s.replacement.contains(&format!("<redacted:{}>", s.kind)), "{}: {}", s.kind, s.replacement);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scrub;

    /// The exact line the live gateway wrote, with the token replaced by one of
    /// the same shape. This is the string the fix exists for.
    #[test]
    fn the_poll_error_url_loses_its_token() {
        let line = "error sending request for url \
                    (https://api.telegram.org/bot1234567890:AAFsomeSecretBodyHere-x/getUpdates)";
        let out = scrub(line);
        assert!(!out.contains("AAFsomeSecretBodyHere"), "{out}");
        assert!(!out.contains("1234567890:"), "the id half is part of the credential: {out}");
        assert!(out.contains("bot<redacted>/getUpdates"), "the rest must stay readable: {out}");
    }

    #[test]
    fn every_send_path_shape_is_covered() {
        for verb in ["getUpdates", "sendMessage", "getMe"] {
            let out = scrub(&format!("failed: https://api.telegram.org/bot999:SEKRIT/{verb}"));
            assert!(!out.contains("SEKRIT"), "{out}");
            assert!(out.contains(verb), "{out}");
        }
    }

    #[test]
    fn ordinary_prose_about_bots_is_left_alone() {
        // The guard against an over-eager scrubber: a message that merely says
        // "bot" must survive, or operators lose readable errors to a redactor.
        for s in [
            "another bot instance or a registered webhook is consuming updates",
            "bot",
            "robot: starting",
            "bots:",
        ] {
            assert_eq!(scrub(s), s, "prose must not be mangled: {s}");
        }
    }

    #[test]
    fn more_than_one_token_in_one_string_all_go() {
        let out = scrub("a=https://x/bot11:AAA/getMe b=https://y/bot22:BBB/sendMessage");
        assert!(!out.contains("AAA") && !out.contains("BBB"), "{out}");
        assert_eq!(out.matches("bot<redacted>").count(), 2, "{out}");
    }

    #[test]
    fn non_ascii_text_does_not_panic_or_corrupt() {
        let s = "échec: https://api.telegram.org/bot7:ZZZ/getUpdates — réessai";
        let out = scrub(s);
        assert!(!out.contains("ZZZ"), "{out}");
        assert!(out.contains("échec") && out.contains("réessai"), "{out}");
    }
}
