// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Sealing and signing for agent messages.
//!
//! Operator decision: as much coverage as possible, as long
//! as review in the CLI and dashboard still works. So:
//!
//! - every body is sealed before it touches the bus — a fresh per-message
//!   ChaCha20-Poly1305 key, wrapped (X25519 + AEAD) to each recipient:
//!   the controller's **review key** always, plus the addressed agent's
//!   key when it has registered one (phase 4 gives node-local agents
//!   their own keys; until then that wrap is absent and the message is
//!   "gateway-sealed": ciphertext on the bus and in the table, plaintext
//!   only inside the gateway for an authorised reader);
//! - every envelope is signed (Ed25519) by whoever sealed it — the
//!   controller for HTTP/MCP/WS-ingested messages — over its identifying
//!   fields, so "who said this" is verifiable, not trusted from a
//!   credential;
//! - the gateway unseals with the review key for operators (CLI review,
//!   dashboard) and for the addressed recipient reading through the
//!   gateway. Metadata (from, to, kind, thread, ts, identities) stays in
//!   the clear for indexing.
//!
//! One secret drives it: `NOO_AGENT_REVIEW_KEY` (any string ≥ 32 bytes of
//! entropy; minted by the secrets registry). Both key pairs derive from it
//! (SHA-256 with a domain label), so there is one thing to back up and
//! rotating it is the one operation that makes OLD sealed bodies
//! unreadable — the registry says so. Absent → messages travel and are
//! stored in plaintext with `enc: none` (the pre-2b behaviour), and the
//! boot log says which.

use std::sync::OnceLock;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const ENV_KEY: &str = "NOO_AGENT_REVIEW_KEY";
/// Optional second secret: when set, the SIGNING key derives from this and
/// the review key becomes decrypt-only. Absent → both
/// derive from `NOO_AGENT_REVIEW_KEY`, as before.
pub const SIGN_ENV_KEY: &str = "NOO_AGENT_SIGNING_KEY";
/// v1 sealing: body AAD is the algorithm string alone, wrap KDF binds only
/// the shared secret and the label. Still opened — the table holds v1 rows.
pub const ALG: &str = "x25519-chacha20poly1305-v1";
/// v2 sealing: the body AEAD is bound to the envelope
/// it belongs to, and the wrap KDF binds the ephemeral and recipient keys.
/// A ciphertext lifted out of its envelope no longer opens anywhere else.
pub const ALG_V2: &str = "x25519-chacha20poly1305-v2";
/// Wrap label for the controller's review key inside `enc_meta.wraps`.
pub const REVIEW_WRAP: &str = "review";
/// NATS KV bucket holding agents' public keys (phase 4 fills it).
pub const KEYS_BUCKET: &str = "agent_msg_keys";

pub struct KeySet {
    pub seal: StaticSecret,
    pub sign: SigningKey,
}

impl KeySet {
    /// Derive the sealing pair from `seal_secret` and the signing pair from
    /// `sign_secret`. Passing the same string for both is [`from_secret`].
    pub fn from_secrets(seal_secret: &str, sign_secret: &str) -> Option<Self> {
        let (a, b) = (seal_secret.trim(), sign_secret.trim());
        if a.len() < 32 || b.len() < 32 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"noomesh-agent-msg/x25519/v1:");
        h.update(a.as_bytes());
        let seal = StaticSecret::from(<[u8; 32]>::from(h.finalize()));
        let mut h = Sha256::new();
        h.update(b"noomesh-agent-msg/ed25519/v1:");
        h.update(b.as_bytes());
        let sign = SigningKey::from_bytes(&<[u8; 32]>::from(h.finalize()));
        Some(KeySet { seal, sign })
    }

    /// Derive both key pairs from one secret string.
    pub fn from_secret(secret: &str) -> Option<Self> {
        let s = secret.trim();
        if s.len() < 32 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"noomesh-agent-msg/x25519/v1:");
        h.update(s.as_bytes());
        let seal = StaticSecret::from(<[u8; 32]>::from(h.finalize()));
        let mut h = Sha256::new();
        h.update(b"noomesh-agent-msg/ed25519/v1:");
        h.update(s.as_bytes());
        let sign = SigningKey::from_bytes(&<[u8; 32]>::from(h.finalize()));
        Some(KeySet { seal, sign })
    }
    pub fn seal_public(&self) -> PublicKey {
        PublicKey::from(&self.seal)
    }
    pub fn sign_public(&self) -> VerifyingKey {
        self.sign.verifying_key()
    }
    /// What an agent publishes to the key registry.
    pub fn public_record(&self) -> Value {
        json!({
            "x25519": b64(self.seal_public().as_bytes()),
            "ed25519": b64(self.sign_public().as_bytes()),
            "alg": ALG,
        })
    }
}

/// The controller's keys, from `NOO_AGENT_REVIEW_KEY` (process-constant).
pub fn controller_keys() -> Option<&'static KeySet> {
    static KEYS: OnceLock<Option<KeySet>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let raw = crate::config::secret_env::secret_or_empty(ENV_KEY);
        // A separate signing secret makes the review key decrypt-only:
        // whoever holds it can read history but cannot forge controller
        // signatures. Absent → one secret, as before.
        let sign_raw = crate::config::secret_env::secret_opt(SIGN_ENV_KEY).filter(|v| v.trim().len() >= 32);
        let ks = match &sign_raw {
            Some(sk) => KeySet::from_secrets(&raw, sk),
            None => KeySet::from_secret(&raw),
        };
        if ks.is_none() {
            tracing::warn!(
                "agent messaging: {ENV_KEY} is not set (or too short) — messages are NOT sealed; \
                 mint it with `noo security secrets rotate {ENV_KEY}` / the onboarding secrets step"
            );
        }
        ks
    })
    .as_ref()
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("bad base64: {e}"))
}
fn arr32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// A recipient to wrap the message key to: a label (as stored in
/// `enc_meta.wraps`) and its X25519 public key.
pub struct Recipient<'a> {
    pub label: &'a str,
    pub key: PublicKey,
}

/// The sealed body + the metadata a reader needs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
    /// Base64 ciphertext of the JSON body.
    pub ct: String,
    pub meta: Value,
}

fn wrap_key_for(epk_secret: &StaticSecret, recipient: &PublicKey, label: &str) -> Key {
    let shared = epk_secret.diffie_hellman(recipient);
    let mut h = Sha256::new();
    h.update(b"noomesh-agent-msg/wrap/v1:");
    h.update(shared.as_bytes());
    h.update(label.as_bytes());
    Key::from(<[u8; 32]>::from(h.finalize()))
}

/// v2 wrap key: the KDF binds the ephemeral and recipient public keys as
/// well as the shared secret, and a non-contributory exchange (a low-order
/// `epk`, which makes the shared secret a public constant) is refused.
/// `own_secret` × `dh_peer` is the exchange; `epk` and `recipient` are the
/// two public keys the KDF binds, whichever side is deriving. Sealing:
/// (epk_secret, recipient_pub). Opening: (recipient_secret, epk).
fn wrap_key_v2(
    own_secret: &StaticSecret,
    dh_peer: &PublicKey,
    epk: &PublicKey,
    recipient: &PublicKey,
    label: &str,
) -> Result<Key, String> {
    let shared = own_secret.diffie_hellman(dh_peer);
    if !shared.was_contributory() {
        return Err("non-contributory key exchange (low-order point)".into());
    }
    let mut h = Sha256::new();
    h.update(b"noomesh-agent-msg/wrap/v2:");
    h.update(shared.as_bytes());
    h.update(epk.as_bytes());
    h.update(recipient.as_bytes());
    h.update(label.as_bytes());
    Ok(Key::from(<[u8; 32]>::from(h.finalize())))
}

/// Seal `body` to every recipient (v2). `aad` binds the ciphertext to the
/// envelope it belongs to — see [`crate::agent_messages::envelope_aad`] —
/// so a body lifted into a different envelope no longer authenticates.
pub fn seal(body: &Value, recipients: &[Recipient<'_>], aad: &[u8]) -> Result<Sealed, String> {
    if recipients.is_empty() {
        return Err("no recipients to seal to".into());
    }
    let mut msg_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), msg_key.as_mut_slice());
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let plaintext = Zeroizing::new(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let ct = ChaCha20Poly1305::new(&Key::from(*msg_key))
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext.as_slice(), aad })
        .map_err(|_| "encrypt failed".to_string())?;
    // One ephemeral X25519 key per message; each recipient gets the message
    // key wrapped under ECDH(ephemeral, recipient) — the v2 KDF binds both
    // public keys and the label, so wraps are distinct and non-replayable.
    let epk_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let epk = PublicKey::from(&epk_secret);
    let mut wraps = serde_json::Map::new();
    for r in recipients {
        let wk = wrap_key_v2(&epk_secret, &r.key, &epk, &r.key, r.label)?;
        let wrapped = ChaCha20Poly1305::new(&wk)
            .encrypt(&Nonce::from([0u8; 12]), Payload { msg: msg_key.as_slice(), aad: r.label.as_bytes() })
            .map_err(|_| "wrap failed".to_string())?;
        wraps.insert(r.label.to_string(), Value::String(b64(&wrapped)));
    }
    Ok(Sealed {
        ct: b64(&ct),
        meta: json!({ "alg": ALG_V2, "epk": b64(epk.as_bytes()), "nonce": b64(&nonce), "wraps": Value::Object(wraps) }),
    })
}

/// Open a sealed body as `label` with `secret`. `aad` is the envelope
/// binding for v2 bodies; v1 bodies (rows sealed before wave B) ignore it
/// and authenticate against the algorithm string, as they were sealed.
pub fn open(sealed: &Sealed, label: &str, secret: &StaticSecret, aad: &[u8]) -> Result<Value, String> {
    let alg = sealed.meta["alg"].as_str().unwrap_or_default();
    let v2 = match alg {
        a if a == ALG_V2 => true,
        a if a == ALG => false,
        _ => return Err(format!("unknown sealing algorithm {:?}", sealed.meta["alg"])),
    };
    let body_aad: &[u8] = if v2 { aad } else { ALG.as_bytes() };
    let epk = PublicKey::from(arr32(&b64d(sealed.meta["epk"].as_str().ok_or("missing epk")?)?)?);
    let wrapped = b64d(sealed.meta["wraps"][label].as_str().ok_or_else(|| format!("no wrap for '{label}'"))?)?;
    let wk = if v2 {
        wrap_key_v2(secret, &epk, &epk, &PublicKey::from(secret), label)?
    } else {
        wrap_key_for(secret, &epk, label)
    };
    let msg_key = ChaCha20Poly1305::new(&wk)
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: &wrapped, aad: label.as_bytes() })
        .map_err(|_| "wrap does not open with this key".to_string())?;
    // Anyone can mint a wrap under the public review key, so a short key or
    // nonce must be an Err, never a panic: convert with `try_from`.
    let msg_key = Zeroizing::new(msg_key);
    let key = Key::try_from(msg_key.as_slice()).map_err(|_| "wrapped key has the wrong length".to_string())?;
    let nonce = b64d(sealed.meta["nonce"].as_str().ok_or("missing nonce")?)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| "nonce has the wrong length".to_string())?;
    let ct = b64d(&sealed.ct)?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new(&key)
            .decrypt(&nonce, Payload { msg: &ct, aad: body_aad })
            .map_err(|_| "ciphertext does not authenticate".to_string())?,
    );
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

/// The bytes a signature covers: the identifying fields plus the body as
/// it travels (ciphertext when sealed), so a re-sealed or re-addressed
/// copy does not verify.
pub fn signing_input(id: &str, thread_id: &str, from: &str, to: &str, kind: &str, ts: &str, body: &Value) -> Vec<u8> {
    let mut v = Vec::new();
    for part in [id, thread_id, from, to, kind, ts] {
        v.extend_from_slice(part.as_bytes());
        v.push(0);
    }
    v.extend_from_slice(&serde_json::to_vec(body).unwrap_or_default());
    v
}

/// The bytes a v2 signature covers: the WHOLE envelope minus `sig`, in
/// canonical JSON (keys sorted, no whitespace). Nothing an attacker can
/// edit — recipient wraps, `enc`, `refs`, the structured identities — sits
/// outside the signature any more.
pub fn signing_input_v2(envelope: &Value) -> Result<Vec<u8>, String> {
    let mut v = envelope.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    } else {
        return Err("envelope is not an object".into());
    }
    let mut out = b"noomesh-agent-msg/env/v2:".to_vec();
    // serde_json::Map is a BTreeMap here (no `preserve_order` feature), so
    // this is key-sorted; Python mirrors it with sort_keys=True.
    out.extend_from_slice(&serde_json::to_vec(&v).map_err(|e| e.to_string())?);
    Ok(out)
}

/// The bytes an AUTHOR's own signature covers
/// closing.
///
/// Deliberately NOT [`signing_input_v2`]. That covers the whole envelope
/// including `id` and `ts`, which the gateway assigns — an author cannot
/// sign fields that do not exist until after it has sent the message. So
/// this covers exactly what the author chose: who it is from, who it is
/// to, the kind, the thread, and the body.
///
/// What that means, stated plainly because a signature's value is
/// entirely in what it does NOT cover: an author signature proves the
/// author wrote this content for this recipient. It does not bind the
/// message to a time or an id, so the gateway's own v2 signature still
/// does that job, and the two answer different questions. The controller
/// signature says "this came through the gateway"; this one says "the
/// named agent wrote it", which is the thing a compromised controller
/// cannot forge.
///
/// Domain-separated from the envelope signature so a blob signed for one
/// purpose can never verify as the other.
pub fn author_signing_input(
    from: &str,
    to: &str,
    kind: &str,
    thread_id: &str,
    body: &Value,
) -> Vec<u8> {
    let mut out = b"noomesh-agent-msg/author/v1:".to_vec();
    for part in [from, to, kind, thread_id] {
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out.extend_from_slice(&serde_json::to_vec(body).unwrap_or_default());
    out
}

pub fn sign(keys: &KeySet, input: &[u8]) -> String {
    b64(&keys.sign.sign(input).to_bytes())
}

pub fn verify(pubkey: &VerifyingKey, input: &[u8], sig_b64: &str) -> bool {
    let Ok(bytes) = b64d(sig_b64) else { return false };
    let Ok(sig) = Signature::from_slice(&bytes) else { return false };
    pubkey.verify(input, &sig).is_ok()
}

/// The bytes a key-registry record's `sig` covers: the agent id the record
/// is for plus both public keys — so a record proves possession of its
/// Ed25519 key and cannot be replayed under another agent's name.
pub fn key_record_input(agent: &str, x25519_b64: &str, ed25519_b64: &str) -> Vec<u8> {
    let mut v = b"noomesh-agent-msg/keyreg/v1:".to_vec();
    for part in [agent, x25519_b64, ed25519_b64] {
        v.extend_from_slice(part.as_bytes());
        v.push(0);
    }
    v
}

impl KeySet {
    /// A self-signed registry record for `agent` (what `PUT /api/agents/keys`
    /// and the WS `register_key` expect). `prev` = the key set being
    /// replaced, when this agent already registered a different one.
    pub fn signed_record(&self, agent: &str, prev: Option<&KeySet>) -> Value {
        let mut rec = self.public_record();
        let x = rec["x25519"].as_str().unwrap_or_default().to_string();
        let e = rec["ed25519"].as_str().unwrap_or_default().to_string();
        let input = key_record_input(agent, &x, &e);
        rec["sig"] = Value::String(sign(self, &input));
        if let Some(p) = prev {
            rec["prev_sig"] = Value::String(sign(p, &input));
        }
        rec
    }
}

/// Check a registry record's self-signature for `agent`. Records without
/// a valid `sig` are not keys anyone proved they hold — never trust them.
pub fn verify_key_record(agent: &str, record: &Value) -> Result<(PublicKey, VerifyingKey), String> {
    let (x, e) = parse_public_record(record).ok_or("record must carry base64 x25519 and ed25519 public keys")?;
    let sig = record["sig"].as_str().ok_or("record must be self-signed (missing sig)")?;
    let input = key_record_input(agent, record["x25519"].as_str().unwrap_or(""), record["ed25519"].as_str().unwrap_or(""));
    if !verify(&e, &input, sig) {
        return Err("record self-signature does not verify".into());
    }
    Ok((x, e))
}

/// Look an agent's registered public keys up (phase 4). `None` when the
/// agent never registered, or when the stored record fails its own
/// signature check (a tampered registry must not redirect wraps) — the
/// message is then gateway-sealed only.
pub async fn registered_keys(js: &async_nats::jetstream::Context, agent: &str) -> Option<(PublicKey, VerifyingKey)> {
    let kv = js.get_key_value(KEYS_BUCKET).await.ok()?;
    let raw = kv.get(crate::agent_messages::subject_token(agent)).await.ok().flatten()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    match verify_key_record(agent, &v) {
        Ok(keys) => Some(keys),
        Err(e) => {
            tracing::warn!(agent, error = %e, "agent_crypto: stored key record rejected — treating agent as unregistered");
            None
        }
    }
}

/// Store an agent's public keys. The record must be self-signed (proof of
/// possession). Replacing a DIFFERENT registered key additionally needs
/// `prev_sig` — the same input signed by the key being replaced — unless
/// `privileged` (an operator rotating a lost key; audited by the caller).
/// `registered_by` names the credential that wrote it.
pub async fn register_keys(
    js: &async_nats::jetstream::Context,
    agent: &str,
    record: &Value,
    registered_by: &str,
    privileged: bool,
) -> Result<(), String> {
    let (_, new_ed) = verify_key_record(agent, record)?;
    let kv = js.get_key_value(KEYS_BUCKET).await.map_err(|e| format!("key registry unavailable: {e}"))?;
    let key = crate::agent_messages::subject_token(agent);
    if let Ok(Some(raw)) = kv.get(&key).await {
        if let Some((_, old_ed)) = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| parse_public_record(&v)) {
            if old_ed != new_ed && !privileged {
                let input = key_record_input(agent, record["x25519"].as_str().unwrap_or(""), record["ed25519"].as_str().unwrap_or(""));
                let ok = record["prev_sig"].as_str().map(|s| verify(&old_ed, &input, s)).unwrap_or(false);
                if !ok {
                    return Err(format!(
                        "'{agent}' already has a different key registered — sign the new record with the previous key (prev_sig) or ask an operator to rotate it"
                    ));
                }
            }
        }
    }
    let mut stored = json!({
        "x25519": record["x25519"],
        "ed25519": record["ed25519"],
        "alg": record["alg"].as_str().unwrap_or(ALG),
        "sig": record["sig"],
        "registered_at": chrono::Utc::now().to_rfc3339(),
        "registered_by": registered_by,
    });
    if let Some(p) = record.get("prev_sig") {
        stored["prev_sig"] = p.clone();
    }
    kv.put(key, serde_json::to_vec(&stored).map_err(|e| e.to_string())?.into())
        .await
        .map_err(|e| format!("key registry write failed: {e}"))?;
    Ok(())
}

/// Parse a registry record (`KeySet::public_record` shape).
pub fn parse_public_record(v: &Value) -> Option<(PublicKey, VerifyingKey)> {
    let x = arr32(&b64d(v["x25519"].as_str()?).ok()?).ok()?;
    let e = arr32(&b64d(v["ed25519"].as_str()?).ok()?).ok()?;
    Some((PublicKey::from(x), VerifyingKey::from_bytes(&e).ok()?))
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Phase D: an author signature proves the named agent wrote this
    /// content, and is domain-separated from the envelope signature so
    /// one can never be replayed as the other.
    #[test]
    fn an_author_signature_is_its_own_domain() {
        let keys = KeySet::from_secret("author-test-secret-with-enough-entropy-0123456").unwrap();
        let body = serde_json::json!({"text": "run the deploy"});
        let input = author_signing_input("owner/s1", "owner/worker", "message", "", &body);
        let sig = sign(&keys, &input);
        assert!(verify(&keys.sign_public(), &input, &sig));

        // Every covered field changes the signature. Asserted one at a
        // time, because a signing input that silently ignored a field
        // would still round-trip and look correct.
        for altered in [
            author_signing_input("owner/s2", "owner/worker", "message", "", &body),
            author_signing_input("owner/s1", "someone/else", "message", "", &body),
            author_signing_input("owner/s1", "owner/worker", "task", "", &body),
            author_signing_input("owner/s1", "owner/worker", "message", "t-1", &body),
            author_signing_input("owner/s1", "owner/worker", "message", "", &serde_json::json!({"text": "rm -rf"})),
        ] {
            assert!(!verify(&keys.sign_public(), &altered, &sig), "a covered field was not covered");
        }

        // And a DIFFERENT agent's key does not verify it — the whole point.
        let other = KeySet::from_secret("a-different-author-secret-with-entropy-98765432").unwrap();
        assert!(!verify(&other.sign_public(), &input, &sig));

        // Domain separation: the same bytes signed as an envelope must
        // not verify as an author signature.
        let env = serde_json::json!({"from": "owner/s1", "to": "owner/worker"});
        let env_input = signing_input_v2(&env).unwrap();
        assert_ne!(env_input, input);
        assert!(!verify(&keys.sign_public(), &env_input, &sig));
    }

    #[test]
    fn open_rejects_short_key_and_nonce_instead_of_panicking() {
        let ctrl = KeySet::from_secret("controller-review-secret-with-enough-entropy-0123").unwrap();
        let body = json!({"text": "x"});
        let aad = b"aad";
        let sealed = seal(&body, &[Recipient { label: REVIEW_WRAP, key: ctrl.seal_public() }], aad).unwrap();
        // Short nonce.
        let mut bad = sealed.clone();
        bad.meta["nonce"] = Value::String(b64(&[1u8; 5]));
        assert!(open(&bad, REVIEW_WRAP, &ctrl.seal, aad).unwrap_err().contains("nonce"));
        // A wrap that authenticates but carries a 5-byte "key": anyone can
        // mint one, since the review public key is public.
        let epk_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let epk = PublicKey::from(&epk_secret);
        let wk = wrap_key_v2(&epk_secret, &ctrl.seal_public(), &epk, &ctrl.seal_public(), REVIEW_WRAP).unwrap();
        let wrapped = ChaCha20Poly1305::new(&wk)
            .encrypt(&Nonce::from([0u8; 12]), Payload { msg: &[7u8; 5], aad: REVIEW_WRAP.as_bytes() })
            .unwrap();
        let mut bad = sealed.clone();
        bad.meta["epk"] = Value::String(b64(epk.as_bytes()));
        bad.meta["wraps"][REVIEW_WRAP] = Value::String(b64(&wrapped));
        assert!(open(&bad, REVIEW_WRAP, &ctrl.seal, aad).unwrap_err().contains("length"));
    }

    #[test]
    fn opens_and_verifies_the_python_generated_v2_vector() {
        // The cross-language contract for wave B: Python sealed this with the
        // envelope-bound AAD and signed the canonical whole envelope with a
        // SEPARATE signing secret. Rust must agree on all three.
        let v: Value = serde_json::from_str(include_str!("fixtures/agent_seal_vector_v2.json")).unwrap();
        let ctrl = KeySet::from_secret(v["controller_secret"].as_str().unwrap()).unwrap();
        let agent = KeySet::from_secret(v["agent_secret"].as_str().unwrap()).unwrap();
        let signer = KeySet::from_secret(v["signing_secret"].as_str().unwrap()).unwrap();
        let e = &v["envelope"];
        let env: crate::agent_messages::Envelope = serde_json::from_value(e.clone()).unwrap();
        assert_eq!(env.v, 2);
        let aad = env.aad();
        let sealed = Sealed {
            ct: e["body"]["ct"].as_str().unwrap().to_string(),
            meta: e["enc_meta"].clone(),
        };
        assert_eq!(sealed.meta["alg"].as_str(), Some(ALG_V2));
        assert_eq!(open(&sealed, REVIEW_WRAP, &ctrl.seal, &aad).unwrap(), v["plaintext"]);
        assert_eq!(open(&sealed, "node-a/claude-code-1", &agent.seal, &aad).unwrap(), v["plaintext"]);
        // Signature covers the canonical envelope minus `sig`.
        let mut signed = e.clone();
        signed.as_object_mut().unwrap().insert("sig".into(), v["sig"].clone());
        let input = signing_input_v2(&signed).unwrap();
        assert!(verify(&signer.sign_public(), &input, v["sig"].as_str().unwrap()));
        // The review key is NOT the signing key here — that is the point of
        // the second secret.
        assert!(!verify(&ctrl.sign_public(), &input, v["sig"].as_str().unwrap()));
        // Editing anything outside the old six-field signature is now caught:
        // strip the recipient wrap (a silent e2e downgrade).
        let mut downgraded = signed.clone();
        downgraded["enc_meta"]["wraps"].as_object_mut().unwrap().remove("node-a/claude-code-1");
        let bad = signing_input_v2(&downgraded).unwrap();
        assert!(!verify(&signer.sign_public(), &bad, v["sig"].as_str().unwrap()));
    }

    #[test]
    fn a_second_secret_separates_reading_from_signing() {
        let one = KeySet::from_secret("controller-review-secret-with-enough-entropy-0123").unwrap();
        let split = KeySet::from_secrets(
            "controller-review-secret-with-enough-entropy-0123",
            "controller-signing-secret-with-enough-entropy-9876",
        )
        .unwrap();
        // Same sealing key (history stays readable), different signing key.
        assert_eq!(one.seal_public().as_bytes(), split.seal_public().as_bytes());
        assert_ne!(one.sign_public().as_bytes(), split.sign_public().as_bytes());
        // Too-short halves are refused, like the single-secret path.
        assert!(KeySet::from_secrets("short", "controller-signing-secret-with-enough-entropy-9876").is_none());
        assert!(KeySet::from_secrets("controller-review-secret-with-enough-entropy-0123", "short").is_none());
    }

    #[test]
    fn key_records_prove_possession_and_bind_the_agent_id() {
        let a = KeySet::from_secret("agent-secret-with-enough-entropy-abcdefghijklmn").unwrap();
        let rec = a.signed_record("node-a/claude-code-1", None);
        assert!(verify_key_record("node-a/claude-code-1", &rec).is_ok());
        assert!(verify_key_record("node-a/claude-code-2", &rec).is_err(), "replayed under another id");
        let mut tampered = rec.clone();
        tampered["x25519"] = Value::String(b64(&[9u8; 32]));
        assert!(verify_key_record("node-a/claude-code-1", &tampered).is_err(), "swapped sealing key");
        let unsigned = a.public_record();
        assert!(verify_key_record("node-a/claude-code-1", &unsigned).unwrap_err().contains("sig"));
        // Rotation carries prev_sig under the old key.
        let b = KeySet::from_secret("some-other-agent-secret-with-enough-entropy-xyz").unwrap();
        let rotated = b.signed_record("node-a/claude-code-1", Some(&a));
        let input = key_record_input("node-a/claude-code-1", rotated["x25519"].as_str().unwrap(), rotated["ed25519"].as_str().unwrap());
        assert!(verify(&a.sign_public(), &input, rotated["prev_sig"].as_str().unwrap()));
    }

    #[test]
    fn seal_opens_for_each_recipient_and_no_one_else() {
        let ctrl = KeySet::from_secret("controller-review-secret-with-enough-entropy-0123").unwrap();
        let agent = KeySet::from_secret("agent-secret-with-enough-entropy-abcdefghijklmn").unwrap();
        let other = KeySet::from_secret("some-other-agent-secret-with-enough-entropy-xyz").unwrap();
        let body = json!({"text": "meet at the graph", "n": 3});
        let aad = b"envelope-binding";
        let sealed = seal(&body, &[
            Recipient { label: REVIEW_WRAP, key: ctrl.seal_public() },
            Recipient { label: "node-a/claude-code-1", key: agent.seal_public() },
        ], aad).unwrap();
        assert_ne!(sealed.ct, "");
        assert_eq!(open(&sealed, REVIEW_WRAP, &ctrl.seal, aad).unwrap(), body);
        assert_eq!(open(&sealed, "node-a/claude-code-1", &agent.seal, aad).unwrap(), body);
        assert!(open(&sealed, REVIEW_WRAP, &other.seal, aad).is_err());
        assert!(open(&sealed, "nobody", &ctrl.seal, aad).unwrap_err().contains("no wrap"));
        // The whole point of v2: the same ciphertext under a different
        // envelope binding does not authenticate.
        assert!(open(&sealed, REVIEW_WRAP, &ctrl.seal, b"another-envelope")
            .unwrap_err()
            .contains("authenticate"));
        // Round-trips through JSON (what the table stores).
        let back: Sealed = serde_json::from_str(&serde_json::to_string(&sealed).unwrap()).unwrap();
        assert_eq!(open(&back, REVIEW_WRAP, &ctrl.seal, aad).unwrap(), body);
    }

    #[test]
    fn signatures_bind_the_fields() {
        let ks = KeySet::from_secret("controller-review-secret-with-enough-entropy-0123").unwrap();
        let body = json!({"ct": "abc"});
        let input = signing_input("msg_1", "thr_1", "a", "b", "message", "2026-09-03T00:00:00Z", &body);
        let sig = sign(&ks, &input);
        assert!(verify(&ks.sign_public(), &input, &sig));
        let tampered = signing_input("msg_1", "thr_1", "a", "c", "message", "2026-09-03T00:00:00Z", &body);
        assert!(!verify(&ks.sign_public(), &tampered, &sig));
        let (_, vk) = parse_public_record(&ks.public_record()).unwrap();
        assert_eq!(vk, ks.sign_public());
    }

    /// The Python client (`noomesh.agents.messaging`) produced this fixture;
    /// both sides opening it is what keeps the two implementations agreeing.
    #[test]
    fn opens_the_python_generated_vector() {
        let v: Value = serde_json::from_str(include_str!("fixtures/agent_seal_vector.json")).unwrap();
        let ctrl = KeySet::from_secret(v["controller_secret"].as_str().unwrap()).unwrap();
        let agent = KeySet::from_secret(v["agent_secret"].as_str().unwrap()).unwrap();
        let sealed = Sealed { ct: v["envelope"]["body"]["ct"].as_str().unwrap().to_string(), meta: v["enc_meta"].clone() };
        // v1 vector: sealed before wave B, so it opens with any aad.
        assert_eq!(open(&sealed, REVIEW_WRAP, &ctrl.seal, b"ignored").unwrap(), v["plaintext"]);
        assert_eq!(open(&sealed, "node-a/claude-code-1", &agent.seal, b"ignored").unwrap(), v["plaintext"]);
        let e = &v["envelope"];
        let input = signing_input(e["id"].as_str().unwrap(), e["thread_id"].as_str().unwrap(), e["from"].as_str().unwrap(),
                                  e["to"].as_str().unwrap(), e["kind"].as_str().unwrap(), e["ts"].as_str().unwrap(), &e["body"]);
        assert!(verify(&ctrl.sign_public(), &input, v["sig"].as_str().unwrap()));
    }

    #[test]
    fn short_secrets_are_refused() {
        assert!(KeySet::from_secret("short").is_none());
    }
}
