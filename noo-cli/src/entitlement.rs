// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Entitlement tokens, the CLI half (verify / install / show). Mirrors
//! `gateway-rust/src/entitlement.rs`: same format
//! (`noo-ent1.<b64url payload>.<b64url ed25519 sig>`), same baked public
//! key (`PUBKEY_HEX`; tests/test_entitlement_pubkey_parity.py pins the two
//! constants equal).

use base64::Engine as _;
#[cfg(has_entitlement_signer)]
use ed25519_dalek::{Signer, SigningKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Mirrors the gateway's `PUBKEYS_HEX` (current first), so `verify` and
/// `install` agree with what a gateway accepts.
pub const PUBKEY_HEX: &str = "e1a9a8e707a8b15245193f8a37148e937ba879a49774137a48551e0c12bfdc81";
pub const PUBKEYS_HEX: &[&str] = &[PUBKEY_HEX];
/// Every feature a token can grant, with the add-on it unlocks.
pub const KNOWN_FEATURES: &[(&str, &str)] = &[
    ("trellion_intel", "Intelligent tier (trellion-intel container)"),
    ("evolve", "evolve add-on (prompt-skill evolution)"),
];

pub const TOKEN_PREFIX: &str = "noo-ent1.";
pub const STORE_KEY: &str = "NOO_ENTITLEMENT";
#[cfg(any(test, has_entitlement_signer))]
pub const TIER_INTELLIGENT: &str = "intelligent";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entitlement {
    pub v: u32,
    pub sub: String,
    pub tier: String,
    #[serde(default)]
    pub features: Vec<String>,
    pub iat: i64,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u32>,
    /// The add-on terms version accepted at issue (`addon-1.0`). Absent =
    /// issued before terms existed; never affects what the token unlocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<String>,
}

impl Entitlement {
    /// Features are the only authority; `tier` is a bundle label.
    pub fn grants(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
    pub fn expired_at(&self, now: i64) -> bool {
        self.exp > 0 && now >= self.exp
    }
}

fn hex_bytes(hex: &str) -> Result<[u8; 32], String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "key is not hex".to_string())?;
    bytes.try_into().map_err(|_| "key must be 32 bytes (64 hex chars)".to_string())
}

pub fn pubkey_from_hex(hex: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&hex_bytes(hex.trim())?).map_err(|e| format!("invalid ed25519 public key: {e}"))
}

#[cfg(has_entitlement_signer)]
pub fn signing_key_from_hex(hex: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&hex_bytes(hex.trim())?))
}

#[cfg(any(test, has_entitlement_signer))]
fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("bad base64url segment: {e}"))
}

#[cfg(has_entitlement_signer)]
pub fn sign(ent: &Entitlement, key: &SigningKey) -> String {
    let payload = serde_json::to_vec(ent).expect("entitlement serialises");
    let sig = key.sign(&payload);
    format!("{TOKEN_PREFIX}{}.{}", b64(&payload), b64(&sig.to_bytes()))
}

pub fn verify_with(token: &str, key: &VerifyingKey) -> Result<Entitlement, String> {
    let body = token
        .trim()
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| format!("not an entitlement token (expected the {TOKEN_PREFIX} prefix)"))?;
    let (payload_b64, sig_b64) = body
        .split_once('.')
        .ok_or_else(|| "malformed token: missing signature segment".to_string())?;
    let payload = b64d(payload_b64)?;
    let sig = Signature::from_slice(&b64d(sig_b64)?).map_err(|e| format!("bad signature encoding: {e}"))?;
    key.verify(&payload, &sig)
        .map_err(|_| "signature does not verify against this build's entitlement key".to_string())?;
    let ent: Entitlement =
        serde_json::from_slice(&payload).map_err(|e| format!("payload is not an entitlement: {e}"))?;
    if ent.v != 1 {
        return Err(format!("unsupported entitlement version {}", ent.v));
    }
    Ok(ent)
}

pub fn verify(token: &str) -> Result<Entitlement, String> {
    let mut first_err: Option<String> = None;
    for hex in PUBKEYS_HEX {
        match verify_with(token, &pubkey_from_hex(hex)?) {
            Ok(e) => return Ok(e),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| "no entitlement keys baked in".into()))
}

/// Full check as the gateway applies it before any feature question:
/// signature and expiry.
pub fn check(token: &str, now: i64) -> Result<Entitlement, String> {
    let ent = verify(token)?;
    if ent.expired_at(now) {
        return Err(format!("entitlement for '{}' expired", ent.sub));
    }
    Ok(ent)
}

/// `check` plus "does it grant this feature" — what a licensed add-on asks.
pub fn check_feature(token: &str, now: i64, feature: &str) -> Result<Entitlement, String> {
    let ent = check(token, now)?;
    if !ent.grants(feature) {
        return Err(format!("entitlement for '{}' grants [{}], not '{feature}'", ent.sub, ent.features.join(", ")));
    }
    Ok(ent)
}

/// The installed token, checked for `feature` — the one call the wizard and
/// `noo systems enable` need.
pub fn installed_grants(feature: &str, now: i64) -> Result<Entitlement, String> {
    let token = installed_token().ok_or_else(|| "no entitlement installed".to_string())?;
    check_feature(&token, now, feature)
}

/// The token installed on this controller, if any: the sops store when
/// that backend is active, else `.env`. Values never leave the process.
pub fn installed_token() -> Option<String> {
    let root = crate::envfile::repo_root();
    if crate::envfile::sops_backend_active() {
        let store = crate::commands::secrets::SecretStore::load_sops(&root.join("secrets/env.sops")).ok()?;
        return store.get(STORE_KEY).map(str::to_string).filter(|s| !s.trim().is_empty());
    }
    let v = crate::onboard::env::read_env_key(&root.join(".env"), STORE_KEY);
    if v.trim().is_empty() { None } else { Some(v) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(ent: &Entitlement, key: &SigningKey) -> String {
        let payload = serde_json::to_vec(ent).unwrap();
        format!("{TOKEN_PREFIX}{}.{}", b64(&payload), b64(&key.sign(&payload).to_bytes()))
    }

    fn ent() -> Entitlement {
        Entitlement { v: 1, sub: "acme".into(), tier: TIER_INTELLIGENT.into(), features: vec!["trellion_intel".into()], iat: 1_700_000_000, exp: 0, id: "t-1".into(), bound: None, max_nodes: None, terms: None }
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let tok = sign(&ent(), &sk);
        assert!(tok.starts_with(TOKEN_PREFIX));
        assert_eq!(verify_with(&tok, &sk.verifying_key()).unwrap(), ent());
        let other = SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        assert!(verify_with(&tok, &other).is_err());
    }

    #[test]
    fn terms_round_trip_and_are_omitted_when_absent() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let with = Entitlement { terms: Some("addon-1.0".into()), ..ent() };
        let back = verify_with(&sign(&with, &sk), &sk.verifying_key()).unwrap();
        assert_eq!(back.terms.as_deref(), Some("addon-1.0"));
        assert!(!serde_json::to_string(&ent()).unwrap().contains("terms"), "absent terms must not serialise");
    }

    #[test]
    fn token_issued_before_terms_still_verifies_and_unlocks_the_same() {
        // Exactly the payload shape signed before the field existed.
        let old = br#"{"v":1,"sub":"acme","tier":"intelligent","features":["trellion_intel"],"iat":1700000000,"exp":0,"id":"t-1"}"#;
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let sig = ed25519_dalek::Signer::sign(&sk, old);
        let tok = format!("{TOKEN_PREFIX}{}.{}", b64(old), b64(&sig.to_bytes()));
        let e = verify_with(&tok, &sk.verifying_key()).unwrap();
        assert_eq!(e.terms, None);
        assert!(e.grants("trellion_intel") && !e.grants("evolve"));
    }

    #[test]
    fn features_are_the_authority() {
        let e = ent();
        assert!(e.grants("trellion_intel") && !e.grants("evolve"));
        let label_only = Entitlement { features: vec![], ..ent() };
        assert!(!label_only.grants("trellion_intel"), "a tier label grants nothing by itself");
    }

    #[test]
    fn hex_round_trip_and_baked_key() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let hex: String = sk.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(pubkey_from_hex(&hex).unwrap(), sk.verifying_key());
        assert!(pubkey_from_hex(PUBKEY_HEX).is_ok());
        assert!(pubkey_from_hex("zz").is_err());
    }
}
