// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Entitlement tokens, the CLI half (verify / install / show). Mirrors
//! `gateway-rust/src/entitlement.rs`: same format
//! (`noo-ent1.<b64url payload>.<b64url ed25519 sig>`), same baked public
//! key (`PUBKEY_HEX`; tests/test_entitlement_pubkey_parity.py pins the two
//! constants equal).

use std::collections::BTreeMap;

use base64::Engine as _;
#[cfg(has_entitlement_signer)]
use ed25519_dalek::{Signer, SigningKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::addon_lock::{valid_registry_root, TrustAnchor};

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
    /// Per add-on trust anchor: whose key signs that add-on's lock (current
    /// key first) and the registry root its images sit under, keyed by the
    /// `ADDON_ROWS` name. Additive and optional: a token issued without it
    /// still verifies, and CLIs and gateways that predate it ignore it (no
    /// struct here denies unknown fields). The public tree therefore names
    /// no add-on key and no add-on registry; the licence does.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addons: BTreeMap<String, TrustAnchor>,
}

impl Entitlement {
    /// Features are the only authority; `tier` is a bundle label.
    pub fn grants(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
    pub fn expired_at(&self, now: i64) -> bool {
        self.exp > 0 && now >= self.exp
    }
    /// The trust anchor this licence names for `addon`, if any.
    pub fn addon_anchor(&self, addon: &str) -> Option<&TrustAnchor> {
        self.addons.get(addon)
    }
}

/// Shape rules for the `addons` block, applied to every token this build
/// verifies: each anchor names at least one key, every key is an ed25519
/// public key in hex, and the registry is a root (`host/path`, no tag,
/// digest or scheme). A block that breaks them refuses the whole token: it
/// was signed by the issuer, so a bad one is an issuing bug to fix there,
/// not a value to half-trust here.
pub fn validate_addons(addons: &BTreeMap<String, TrustAnchor>) -> Result<(), String> {
    for (name, anchor) in addons {
        if name.trim().is_empty() {
            return Err("add-on trust block has an empty add-on name".into());
        }
        if anchor.keys.is_empty() {
            return Err(format!("add-on trust block for {name} names no signing key"));
        }
        for (i, k) in anchor.keys.iter().enumerate() {
            pubkey_from_hex(k).map_err(|e| format!("add-on trust block for {name}: key #{i} {e}"))?;
        }
        if !valid_registry_root(anchor.registry.trim()) {
            return Err(format!(
                "add-on trust block for {name}: registry {:?} is not a registry root (host/path)",
                anchor.registry
            ));
        }
    }
    Ok(())
}

/// The first 16 hex characters of a key: enough to tell keys apart in a
/// listing, never enough to be mistaken for the key.
pub fn short_key_id(hex: &str) -> String {
    let h = hex.trim();
    format!("{}…", h.get(..16).unwrap_or(h))
}

/// Parse one issuer `--addon <name>=<registry>:<key>[,<key>]` value (current
/// key first). The registry root holds no `:` (see `valid_registry_root`),
/// so the last `:` splits it from the keys.
#[cfg(any(test, has_entitlement_signer))]
pub fn parse_addon_flag(v: &str) -> Result<(String, TrustAnchor), String> {
    let bad = || format!("--addon {v}: expected <name>=<registry>:<key>[,<key>]");
    let (name, rest) = v.split_once('=').ok_or_else(bad)?;
    let (registry, keys) = rest.rsplit_once(':').ok_or_else(bad)?;
    let name = name.trim().to_string();
    let anchor = TrustAnchor {
        keys: keys.split(',').map(str::trim).filter(|k| !k.is_empty()).map(String::from).collect(),
        registry: registry.trim().to_string(),
    };
    if name.is_empty() {
        return Err(bad());
    }
    let one = BTreeMap::from([(name.clone(), anchor)]);
    validate_addons(&one)?;
    let (name, anchor) = one.into_iter().next().expect("one entry");
    Ok((name, anchor))
}

/// Issue-time pairing rule: every licensed add-on feature the token grants
/// carries its trust block, and no block names an add-on the token does not
/// grant. A token that unlocks an add-on without naming its signer would
/// leave the controller nothing to verify that add-on's lock against.
#[cfg(any(test, has_entitlement_signer))]
pub fn check_issue_addons(features: &[String], addons: &BTreeMap<String, TrustAnchor>) -> Result<(), String> {
    validate_addons(addons)?;
    if let Some(name) = addons.keys().find(|n| !features.iter().any(|f| f == *n)) {
        return Err(format!("--addon {name} names an add-on the token does not grant; add it to --features or drop the block"));
    }
    if let Some(f) = features.iter().find(|f| KNOWN_FEATURES.iter().any(|(k, _)| k == f) && !addons.contains_key(f.as_str())) {
        return Err(format!("feature {f} has no --addon block naming its signing key and registry"));
    }
    Ok(())
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
    validate_addons(&ent.addons)?;
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
        Entitlement { v: 1, sub: "acme".into(), tier: TIER_INTELLIGENT.into(), features: vec!["trellion_intel".into()], iat: 1_700_000_000, exp: 0, id: "t-1".into(), bound: None, max_nodes: None, terms: None, addons: BTreeMap::new() }
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

    fn key_hex(seed: u8) -> String {
        SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn with_addons() -> Entitlement {
        let a = TrustAnchor { keys: vec![key_hex(7), key_hex(8)], registry: "ghcr.io/example/intel".into() };
        Entitlement { addons: BTreeMap::from([("trellion_intel".to_string(), a)]), ..ent() }
    }

    /// Sign raw payload bytes, so a test can put anything in a token.
    fn sign_raw(payload: &[u8], sk: &SigningKey) -> String {
        format!("{TOKEN_PREFIX}{}.{}", b64(payload), b64(&sk.sign(payload).to_bytes()))
    }

    #[test]
    fn addon_block_round_trips_and_is_omitted_when_absent() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let e = with_addons();
        let back = verify_with(&sign(&e, &sk), &sk.verifying_key()).unwrap();
        assert_eq!(back, e);
        let a = back.addon_anchor("trellion_intel").expect("the block survives the round trip");
        assert_eq!(a.keys, [key_hex(7), key_hex(8)], "key order (current first) is kept");
        assert_eq!(a.registry, "ghcr.io/example/intel");
        assert!(back.addon_anchor("evolve").is_none());
        assert!(!serde_json::to_string(&ent()).unwrap().contains("addons"), "an empty block must not serialise");
    }

    #[test]
    fn token_without_addon_block_still_verifies() {
        let old = br#"{"v":1,"sub":"acme","tier":"intelligent","features":["trellion_intel"],"iat":1,"exp":0,"id":"t","terms":"addon-1.0"}"#;
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let e = verify_with(&sign_raw(old, &sk), &sk.verifying_key()).unwrap();
        assert!(e.addons.is_empty());
        assert!(e.addon_anchor("trellion_intel").is_none());
        assert!(e.grants("trellion_intel"));
    }

    #[test]
    fn unknown_fields_inside_and_beside_the_block_are_ignored() {
        // A later issuer may add fields; this build must still read the token.
        let k = key_hex(7);
        let payload = format!(
            r#"{{"v":1,"sub":"a","tier":"t","features":["evolve"],"iat":1,"exp":0,"id":"t","later":1,"addons":{{"evolve":{{"keys":["{k}"],"registry":"ghcr.io/example/evolve","note":"x"}}}}}}"#
        );
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let e = verify_with(&sign_raw(payload.as_bytes(), &sk), &sk.verifying_key()).unwrap();
        assert_eq!(e.addon_anchor("evolve").unwrap().keys, [k]);
    }

    #[test]
    fn malformed_addon_block_refuses_the_token() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let k = key_hex(7);
        let cases = [
            (r#""addons":{"evolve":{"keys":"abc","registry":"ghcr.io/x/y"}}"#.to_string(), "payload is not an entitlement"),
            (r#""addons":{"evolve":{"registry":"ghcr.io/x/y"}}"#.to_string(), "payload is not an entitlement"),
            (r#""addons":["evolve"]"#.to_string(), "payload is not an entitlement"),
            (r#""addons":{"evolve":{"keys":[],"registry":"ghcr.io/x/y"}}"#.to_string(), "names no signing key"),
            (r#""addons":{"evolve":{"keys":["zz"],"registry":"ghcr.io/x/y"}}"#.to_string(), "key #0"),
            (format!(r#""addons":{{"evolve":{{"keys":["{k}"],"registry":"https://ghcr.io/x"}}}}"#), "not a registry root"),
            (format!(r#""addons":{{"evolve":{{"keys":["{k}"],"registry":"ghcr.io/x:latest"}}}}"#), "not a registry root"),
        ];
        for (block, want) in cases {
            let payload = format!(r#"{{"v":1,"sub":"a","tier":"t","features":["evolve"],"iat":1,"exp":0,"id":"t",{block}}}"#);
            let err = verify_with(&sign_raw(payload.as_bytes(), &sk), &sk.verifying_key()).unwrap_err();
            assert!(err.contains(want), "{block}: {err}");
        }
    }

    #[test]
    fn issuer_addon_flag_parses_and_pairs_with_features() {
        let (k1, k2) = (key_hex(7), key_hex(8));
        let (name, a) = parse_addon_flag(&format!("trellion_intel=ghcr.io/example/intel:{k1},{k2}")).unwrap();
        assert_eq!(name, "trellion_intel");
        assert_eq!(a, TrustAnchor { keys: vec![k1.clone(), k2], registry: "ghcr.io/example/intel".into() });
        for bad in ["trellion_intel", "=ghcr.io/x/y:aa", &format!("x=ghcr.io/x/y:{k1},zz"), &format!("x=ghcr.io:{k1}"), "x=ghcr.io/x/y:"] {
            assert!(parse_addon_flag(bad).is_err(), "{bad} must be refused");
        }
        let blocks = BTreeMap::from([(name, a)]);
        assert!(check_issue_addons(&["trellion_intel".into()], &blocks).is_ok());
        let e = check_issue_addons(&["trellion_intel".into(), "evolve".into()], &blocks).unwrap_err();
        assert!(e.contains("evolve") && e.contains("--addon"), "{e}");
        let e = check_issue_addons(&[], &blocks).unwrap_err();
        assert!(e.contains("does not grant"), "{e}");
        assert!(check_issue_addons(&[], &BTreeMap::new()).is_ok());
    }

    #[test]
    fn short_key_id_is_a_prefix() {
        assert_eq!(short_key_id(&"ab".repeat(32)), format!("{}…", "ab".repeat(8)));
        assert_eq!(short_key_id("abc"), "abc…");
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
