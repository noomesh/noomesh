// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The staged bootstrap bundle's ETag (0.6.24-rc.2).
//!
//! A node's fetcher (scripts/noo-fetch.sh, `noo node fetch`) polls
//! `GET /bootstrap/bundle/<node>` every few minutes, and the answer is
//! nearly always "the bundle you already applied". Before this, finding that
//! out cost the WHOLE bundle (a few hundred MB: the node's binaries and its
//! vendor CLIs) on every poll, ~150 GiB a day per node, and the controller
//! paid twice more: the fetch receipt and the status route hashed the blob in
//! Postgres (`sha256(blob)`) each time.
//!
//! Now the bundle carries `ETag: "<sha256 of the ciphertext>"`, and a fetcher
//! that sends `If-None-Match` with the sha it last applied gets `304 Not
//! Modified` with no body. The blob is not even read for a 304.
//!
//! The sha is kept in a process cache per node, keyed by the staged row's
//! `(created_at, byte length)`. Every stage rewrites `created_at` (the upsert
//! sets `now()`, microsecond precision), so a re-stage, even of the same
//! length within the same second, is a new key and is never answered with
//! the old sha. A 304 is sent ONLY when the cache holds an entry for the
//! row's CURRENT key and that entry's sha is what the node sent: a stale
//! entry, a missing entry or an older sha all fall through to a full 200.
//! Anything doubtful downloads. Verification is unchanged: the node still
//! decrypts and CA-verifies whatever it applies.
//!
//! The route is public, so the cache and the counters only ever hold nodes
//! that HAVE a staged row: a caller spraying names grows neither.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Which staged row a cached sha belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// `created_at` of the row, in microseconds since the epoch.
    pub created_at_micros: i64,
    /// `octet_length(blob)`.
    pub len: i64,
}

static CACHE: LazyLock<Mutex<HashMap<String, (Key, String)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Per node: (304s, 200s, bytes not sent).
static COUNTS: LazyLock<Mutex<HashMap<String, (u64, u64, u64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The cached sha for `node`, only if it was computed for exactly `key`.
pub fn cached_sha(node: &str, key: Key) -> Option<String> {
    let c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.get(node).filter(|(k, _)| *k == key).map(|(_, sha)| sha.clone())
}

/// Record the sha of the row `key` for `node` (replacing any older entry).
pub fn remember(node: &str, key: Key, sha: &str) {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.insert(node.to_string(), (key, sha.to_string()));
}

/// Forget `node` (its bundle was deleted).
pub fn forget(node: &str) {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).remove(node);
}

/// Whether an `If-None-Match` value names `sha`: a strong, quoted
/// `"<64 lowercase hex>"` equal to it, alone or in a comma-separated list.
/// A weak tag (`W/`), `*`, an unquoted value or anything else is "no": the
/// fetcher then downloads, which is always safe.
pub fn not_modified(if_none_match: Option<&str>, sha: &str) -> bool {
    let Some(v) = if_none_match else { return false };
    if !is_sha(sha) {
        return false;
    }
    v.split(',').map(str::trim).any(|tag| {
        tag.strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .is_some_and(|t| is_sha(t))
    })
}

fn is_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The decision for one GET: `Some(sha)` when a 304 may be sent, i.e. the
/// cache holds the CURRENT row's sha and the caller named exactly it.
pub fn decide_304(node: &str, current: Key, if_none_match: Option<&str>) -> Option<String> {
    let sha = cached_sha(node, current)?;
    not_modified(if_none_match, &sha).then_some(sha)
}

/// Count one answer for a node that has a staged bundle.
pub fn count(node: &str, not_modified: bool, bytes: u64) {
    let mut c = COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    let e = c.entry(node.to_string()).or_insert((0, 0, 0));
    if not_modified {
        e.0 += 1;
        e.2 += bytes;
    } else {
        e.1 += 1;
    }
}

/// `noo_bootstrap_bundle_responses_total{node,code}` and
/// `noo_bootstrap_bundle_bytes_not_sent_total{node}`: what the ETag saved.
pub fn metrics_text() -> String {
    let c = COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    if c.is_empty() {
        return String::new();
    }
    let mut nodes: Vec<_> = c.iter().collect();
    nodes.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::from(
        "# HELP noo_bootstrap_bundle_responses_total Bundle GETs answered, per node: 304 (unchanged, no body) or 200 (the bundle).\n\
         # TYPE noo_bootstrap_bundle_responses_total counter\n",
    );
    for (n, (nm, ok, _)) in &nodes {
        out.push_str(&format!("noo_bootstrap_bundle_responses_total{{node=\"{n}\",code=\"304\"}} {nm}\n"));
        out.push_str(&format!("noo_bootstrap_bundle_responses_total{{node=\"{n}\",code=\"200\"}} {ok}\n"));
    }
    out.push_str(
        "# HELP noo_bootstrap_bundle_bytes_not_sent_total Bundle bytes a 304 did not send, per node.\n\
         # TYPE noo_bootstrap_bundle_bytes_not_sent_total counter\n",
    );
    for (n, (_, _, b)) in &nodes {
        out.push_str(&format!("noo_bootstrap_bundle_bytes_not_sent_total{{node=\"{n}\"}} {b}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn quoted(s: &str) -> String {
        format!("\"{s}\"")
    }

    #[test]
    fn only_an_exact_strong_quoted_sha_is_not_modified() {
        assert!(not_modified(Some(&quoted(A)), A));
        assert!(not_modified(Some(&format!("{}, {}", quoted(B), quoted(A))), A), "a list containing it");
        for bad in [A.to_string(), format!("W/{}", quoted(A)), "*".to_string(), quoted(B), quoted(&A.to_uppercase()), String::new(), "\"\"".into()] {
            assert!(!not_modified(Some(&bad), A), "{bad:?}");
        }
        assert!(!not_modified(None, A));
        assert!(!not_modified(Some(&quoted("x")), "x"), "a sha that is not 64 hex never matches");
    }

    #[test]
    fn a_304_needs_the_cache_entry_for_the_current_row() {
        let node = "etag-current";
        let k1 = Key { created_at_micros: 1_000_000, len: 400 };
        assert_eq!(decide_304(node, k1, Some(&quoted(A))), None, "no entry: never a 304");
        remember(node, k1, A);
        assert_eq!(decide_304(node, k1, Some(&quoted(A))).as_deref(), Some(A));
        assert_eq!(decide_304(node, k1, Some(&quoted(B))), None, "another sha: a 200");
        assert_eq!(decide_304(node, k1, None), None, "no header: a 200");
    }

    #[test]
    fn a_restage_of_the_same_length_within_the_same_second_is_never_a_304() {
        let node = "etag-restage";
        // Same byte length; created_at differs by one microsecond (the same
        // second): the key differs, so the old sha is never answered.
        let old = Key { created_at_micros: 5_000_000, len: 1234 };
        let new = Key { created_at_micros: 5_000_001, len: 1234 };
        remember(node, old, A);
        assert_eq!(decide_304(node, new, Some(&quoted(A))), None, "the node's old sha against a re-staged row");
        // Even when the old sha is still cached and the node sends it.
        assert_eq!(cached_sha(node, new), None);
        // Once the new row is served and remembered, its own sha is 304-able
        // and the old one is not.
        remember(node, new, B);
        assert_eq!(decide_304(node, new, Some(&quoted(A))), None);
        assert_eq!(decide_304(node, new, Some(&quoted(B))).as_deref(), Some(B));
    }

    #[test]
    fn a_restage_of_another_length_is_never_a_304() {
        let node = "etag-relen";
        remember(node, Key { created_at_micros: 9, len: 10 }, A);
        assert_eq!(decide_304(node, Key { created_at_micros: 9, len: 11 }, Some(&quoted(A))), None);
    }

    #[test]
    fn a_forgotten_node_is_never_a_304() {
        let node = "etag-forget";
        let k = Key { created_at_micros: 1, len: 1 };
        remember(node, k, A);
        forget(node);
        assert_eq!(decide_304(node, k, Some(&quoted(A))), None);
    }

    #[test]
    fn the_counters_say_what_was_saved() {
        count("etag-metrics", true, 400);
        count("etag-metrics", true, 400);
        count("etag-metrics", false, 0);
        let m = metrics_text();
        assert!(m.contains("noo_bootstrap_bundle_responses_total{node=\"etag-metrics\",code=\"304\"} 2"), "{m}");
        assert!(m.contains("noo_bootstrap_bundle_responses_total{node=\"etag-metrics\",code=\"200\"} 1"), "{m}");
        assert!(m.contains("noo_bootstrap_bundle_bytes_not_sent_total{node=\"etag-metrics\"} 800"), "{m}");
    }
}
