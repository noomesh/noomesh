// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster token v2: an HMAC that authenticates the REQUEST.
//!
//! v1 signs `<actor>:<ts>` and nothing else, so one captured Authorization
//! header is a bearer for any method, path and body for five minutes. v2
//! signs
//!
//! ```text
//! v2 \n METHOD \n path?query \n hex(sha256(body)) \n actor \n ts \n nonce
//! ```
//!
//! and travels as `v2:<actor>:<ts>:<nonce>:<hex hmac>`. The nonce is 128
//! random bits (32 hex); a verifier remembers each nonce it accepted for the
//! window and refuses a second use ([`claim`]: Redis `SET NX EX`, process-local
//! when Redis is absent or erroring, like the rate limiter). The Go node agent
//! (`node-agent-go/internal/auth/clustertoken_v2.go`) and `scripts/noo-fetch.sh`
//! sign the same message; the shared test vector pins all three.
//!
//! Rollout: every verifier accepts v1 AND v2 (v1 is counted under the
//! `cluster_hmac_v1` legacy lane); signers send v2. Once `noo cluster verify`
//! shows no v1 callers, the posture bridge `NOO_CLUSTER_TOKEN_V1=0` refuses
//! v1 ([`v1_allowed`]).

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

type HmacSha256 = Hmac<Sha256>;

pub const PREFIX: &str = "v2:";
/// Freshness window, both directions of clock skew (same as v1).
pub const WINDOW_SECS: u64 = 300;
/// The header signers send with the body's sha256, so the rate limiter (which
/// runs before the body is read) can check a node's signature without
/// buffering. The auth middleware hashes the real body itself and never
/// trusts this value.
pub const BODY_SHA_HEADER: &str = "x-noo-content-sha256";
/// What the auth middleware will buffer to hash. Larger bodies are refused
/// (413), never admitted unbound.
pub const MAX_SIGNED_BODY: usize = 64 * 1024 * 1024;
/// Replay memory bound. Only a token that already verified under the fleet
/// secret reaches the set; at the cap new tokens are refused (closed).
const NONCE_CAP: usize = 200_000;
/// A token stamped up to WINDOW in the future stays valid WINDOW after that,
/// so its nonce is kept for twice the window.
const NONCE_TTL_SECS: u64 = 2 * WINDOW_SECS + 1;

pub fn is_v2(token: &str) -> bool {
    token.starts_with(PREFIX)
}

pub struct Parsed<'a> {
    pub actor: &'a str,
    pub ts: u64,
    pub nonce: &'a str,
    pub sig: &'a str,
}

pub fn parse(token: &str) -> Option<Parsed<'_>> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 5 || parts[0] != "v2" {
        return None;
    }
    let (actor, ts, nonce, sig) = (parts[1], parts[2], parts[3], parts[4]);
    if actor.is_empty() || nonce.len() != 32 || sig.len() != 64 {
        return None;
    }
    if !nonce.bytes().all(|b| b.is_ascii_hexdigit()) || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(Parsed { actor, ts: ts.parse().ok()?, nonce, sig })
}

pub fn body_sha_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

fn message(method: &str, request_uri: &str, body_sha: &str, actor: &str, ts: u64, nonce: &str) -> String {
    format!("v2\n{}\n{request_uri}\n{body_sha}\n{actor}\n{ts}\n{nonce}", method.to_ascii_uppercase())
}

/// Sign one request. Tests and Rust callers; production signers are the node
/// agent and the shell fetcher.
#[cfg_attr(not(test), allow(dead_code))]
pub fn sign(secret: &str, method: &str, request_uri: &str, body: &[u8], actor: &str, ts: u64, nonce: &str) -> Option<String> {
    if secret.is_empty() || actor.is_empty() || actor.contains(':') || actor.contains('\n') {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message(method, request_uri, &body_sha_hex(body), actor, ts, nonce).as_bytes());
    Some(format!("v2:{actor}:{ts}:{nonce}:{}", hex::encode(mac.finalize().into_bytes())))
}

/// Signature, window and request binding — NOT replay (see [`claim`]).
/// `body_sha` is the hex sha256 of the body the caller will actually serve.
/// Returns `(actor, nonce)`.
pub fn verify_signature<'a>(
    token: &'a str,
    secret: &str,
    method: &str,
    request_uri: &str,
    body_sha: &str,
    now: u64,
) -> Option<(&'a str, &'a str)> {
    if secret.is_empty() {
        return None;
    }
    let p = parse(token)?;
    if now.abs_diff(p.ts) > WINDOW_SECS {
        return None;
    }
    let sig = hex::decode(p.sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message(method, request_uri, body_sha, p.actor, p.ts, p.nonce).as_bytes());
    // `verify_slice` compares in constant time.
    mac.verify_slice(&sig).ok()?;
    Some((p.actor, p.nonce))
}

/// Is the legacy v1 token still accepted? Unset (the rollout default) and
/// anything but an explicit closing value: yes.
pub fn v1_allowed() -> bool {
    v1_allowed_value(&std::env::var("NOO_CLUSTER_TOKEN_V1").unwrap_or_default())
}

pub fn v1_allowed_value(v: &str) -> bool {
    !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off" | "closed")
}

/// Nonce -> expiry, bounded. The process-local half of the replay memory.
#[derive(Default)]
pub struct NonceSet {
    seen: HashMap<String, u64>,
    next_sweep: u64,
}

impl NonceSet {
    /// Record `key`; false when it was already used inside the window or the
    /// set is full (fail closed).
    pub fn claim(&mut self, key: &str, now: u64) -> bool {
        if now >= self.next_sweep || self.seen.len() >= NONCE_CAP {
            self.seen.retain(|_, exp| *exp > now);
            self.next_sweep = now + 30;
        }
        if self.seen.get(key).is_some_and(|exp| *exp > now) {
            return false;
        }
        if self.seen.len() >= NONCE_CAP {
            return false;
        }
        self.seen.insert(key.to_string(), now + NONCE_TTL_SECS);
        true
    }
}

static LOCAL: LazyLock<Mutex<NonceSet>> = LazyLock::new(Default::default);

fn claim_local(key: &str, now: u64) -> bool {
    match LOCAL.lock() {
        Ok(mut g) => g.claim(key, now),
        Err(p) => p.into_inner().claim(key, now),
    }
}

/// Spend a verified token's nonce. Redis when connected (shared across
/// gateway replicas and restarts); the process-local set when Redis is absent
/// or errors, so "no Redis" narrows the guarantee to one process rather than
/// removing it. false = replay (or the set is full): refuse.
pub async fn claim(redis: Option<&crate::cache::RedisCache>, actor: &str, nonce: &str, now: u64) -> bool {
    let key = format!("noo:hmac2:{actor}:{nonce}");
    if let Some(r) = redis {
        if let Some(fresh) = r.claim_once(&key, NONCE_TTL_SECS as i64).await {
            return fresh;
        }
    }
    claim_local(&key, now)
}

/// The whole check for one request: signature, window, request binding, then
/// the nonce is spent. `Some(actor)` only if all hold; a request that fails an
/// earlier check never burns a nonce, and a replay of a good one stops here.
pub async fn verify_and_spend(
    redis: Option<&crate::cache::RedisCache>,
    secret: &str,
    token: &str,
    method: &str,
    request_uri: &str,
    body: &[u8],
    now: u64,
) -> Option<String> {
    let (actor, nonce) = verify_signature(token, secret, method, request_uri, &body_sha_hex(body), now)?;
    if !claim(redis, actor, nonce, now).await {
        return None;
    }
    Some(actor.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cret";
    const NONCE: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn shared_vector_matches_go_and_shell() {
        let t = sign(SECRET, "POST", "/bootstrap/bundle/host1/applied", br#"{"a":1}"#, "host1", 1_700_000_000, NONCE).unwrap();
        assert_eq!(
            t,
            "v2:host1:1700000000:00112233445566778899aabbccddeeff:3aee59b3fc968f448b71de5aeb463044b25a26a3ef8ccdff6fc3d53cbbe59540",
            "the wire vector drifted: node-agent-go clustertoken_v2_test.go and scripts/noo-fetch.sh pin the same value"
        );
    }

    fn ok(t: &str, m: &str, uri: &str, body: &[u8], now: u64) -> bool {
        verify_signature(t, SECRET, m, uri, &body_sha_hex(body), now).is_some()
    }

    #[test]
    fn a_signed_request_verifies_and_names_its_actor() {
        let t = sign(SECRET, "POST", "/api/cluster/nodes/host2/heartbeat", b"{}", "host2", 1000, NONCE).unwrap();
        let (actor, nonce) = verify_signature(&t, SECRET, "post", "/api/cluster/nodes/host2/heartbeat", &body_sha_hex(b"{}"), 1100).unwrap();
        assert_eq!((actor, nonce), ("host2", NONCE));
    }

    #[test]
    fn body_path_query_method_and_secret_tamper_are_refused() {
        let t = sign(SECRET, "POST", "/a?x=1", b"{}", "host2", 1000, NONCE).unwrap();
        assert!(ok(&t, "POST", "/a?x=1", b"{}", 1000));
        assert!(!ok(&t, "POST", "/a?x=1", b"{\"evil\":1}", 1000), "body");
        assert!(!ok(&t, "POST", "/b?x=1", b"{}", 1000), "path");
        assert!(!ok(&t, "POST", "/a?x=2", b"{}", 1000), "query");
        assert!(!ok(&t, "DELETE", "/a?x=1", b"{}", 1000), "method");
        assert!(verify_signature(&t, "other", "POST", "/a?x=1", &body_sha_hex(b"{}"), 1000).is_none(), "secret");
        assert!(verify_signature(&t, "", "POST", "/a?x=1", &body_sha_hex(b"{}"), 1000).is_none(), "empty secret");
    }

    #[test]
    fn the_window_is_symmetric_and_a_v1_token_is_not_a_v2_token() {
        let t = sign(SECRET, "GET", "/x", b"", "host2", 1000, NONCE).unwrap();
        assert!(ok(&t, "GET", "/x", b"", 1000 + 300));
        assert!(ok(&t, "GET", "/x", b"", 700));
        assert!(!ok(&t, "GET", "/x", b"", 1000 + 301));
        assert!(verify_signature(&t, SECRET, "GET", "/x", &body_sha_hex(b""), 1000 - 0).is_some());
        // ts 1000 vs now 699 is 301 s of skew the other way
        assert!(!ok(&t, "GET", "/x", b"", 699));
        let v1 = crate::routes::cluster::mint_cluster_token("host2", SECRET, 1000).unwrap();
        assert!(!is_v2(&v1) && parse(&v1).is_none());
    }

    #[test]
    fn malformed_tokens_do_not_parse() {
        for bad in ["v2:", "v2:a:1:n:s", "v2::1:00112233445566778899aabbccddeeff:00", "v2:a:x:00112233445566778899aabbccddeeff:3aee59b3fc968f448b71de5aeb463044b25a26a3ef8ccdff6fc3d53cbbe59540",
                    "v2:a:1:zz112233445566778899aabbccddeeff:3aee59b3fc968f448b71de5aeb463044b25a26a3ef8ccdff6fc3d53cbbe59540"] {
            assert!(parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_nonce_is_spent_once_and_the_set_is_bounded() {
        let mut s = NonceSet::default();
        assert!(s.claim("a|1", 100));
        assert!(!s.claim("a|1", 101), "replay inside the window");
        assert!(s.claim("a|2", 101));
        assert!(s.claim("a|1", 100 + NONCE_TTL_SECS + 1), "after expiry the key is free again");
        let mut full = NonceSet::default();
        for i in 0..NONCE_CAP {
            full.seen.insert(format!("k{i}"), 10_000);
        }
        assert!(!full.claim("new", 100), "a full set must refuse, not admit unchecked");
        assert!(full.claim("new", 20_000), "expired entries are swept so the set recovers");
    }

    /// The property the finding is about, end to end through the same entry
    /// point the middleware calls: a captured request replays NOWHERE, and the
    /// same signature cannot be moved to another body, path or method.
    #[tokio::test]
    async fn a_captured_request_cannot_be_replayed_or_repurposed() {
        async fn go(t: &str, m: &str, uri: &str, body: &[u8]) -> Option<String> {
            verify_and_spend(None, SECRET, t, m, uri, body, 7001).await
        }
        let mk = |n: &str| sign(SECRET, "POST", "/api/cluster/nodes/host2/logs", b"[1,2]", "host2", 7000, n).unwrap();
        let t = mk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
        // Repurposing attempts first: none of them may burn the nonce either.
        assert_eq!(go(&t, "POST", "/api/cluster/nodes/host2/heartbeat", b"[1,2]").await, None, "path");
        assert_eq!(go(&t, "POST", "/api/cluster/nodes/host2/logs", br#"{"agent_url":"https://evil"}"#).await, None, "body");
        assert_eq!(go(&t, "PUT", "/api/cluster/nodes/host2/logs", b"[1,2]").await, None, "method");
        // The genuine request is still good (the failures above spent nothing)...
        assert_eq!(go(&t, "POST", "/api/cluster/nodes/host2/logs", b"[1,2]").await.as_deref(), Some("host2"));
        // ...exactly once.
        assert_eq!(go(&t, "POST", "/api/cluster/nodes/host2/logs", b"[1,2]").await, None, "replay");
    }

    #[tokio::test]
    async fn claim_without_redis_uses_the_local_set() {
        let n = "ffeeddccbbaa99887766554433221100";
        assert!(claim(None, "hostx", n, 5000).await);
        assert!(!claim(None, "hostx", n, 5001).await, "replay refused with no Redis at all");
    }

    #[test]
    fn the_v1_gate_closes_only_on_an_explicit_value() {
        for open in ["", "1", "true", "open", "anything", " "] {
            assert!(v1_allowed_value(open), "{open:?}");
        }
        for closed in ["0", "false", "NO", "off", " closed "] {
            assert!(!v1_allowed_value(closed), "{closed:?}");
        }
    }
}
