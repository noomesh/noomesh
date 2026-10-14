// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Entitlement tokens: an offline-verifiable, signed licence.
//!
//! Format: `noo-ent1.<base64url(payload JSON)>.<base64url(ed25519 sig)>`.
//! The signature covers the raw payload bytes. Verification needs only the
//! public key baked into this binary (`PUBKEY_HEX`): no network, no
//! licence server. The token is stored in the secret store as
//! `NOO_ENTITLEMENT` and the launcher passes it to this process.
//!
//! [`crate::addons::trellion_intel_enabled`] is "flag on AND entitlement
//! valid". Without a valid entitlement the intel surfaces refuse the way a
//! disabled add-on does (an explained 503, "skipped" run records), with a
//! message that says *licensed* rather than *disabled*.
//!
//! The verification key is not overridable by env. Tests use
//! [`verify_with`] with an ephemeral key.

use std::sync::OnceLock;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The entitlement-signing public key (ed25519, raw 32 bytes, hex).
pub const PUBKEY_HEX: &str = "e1a9a8e707a8b15245193f8a37148e937ba879a49774137a48551e0c12bfdc81";

/// Every key a token may be signed with, current first.
pub const PUBKEYS_HEX: &[&str] = &[PUBKEY_HEX];

pub const TOKEN_PREFIX: &str = "noo-ent1.";
pub const ENV_KEY: &str = "NOO_ENTITLEMENT";
pub const TIER_INTELLIGENT: &str = "intelligent";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entitlement {
    /// Format version — 1.
    pub v: u32,
    /// Who it was issued to (customer / org label). Informational.
    pub sub: String,
    /// The bundle label (`intelligent`); informational.
    pub tier: String,
    /// Feature flags the token carries; these are what the gateway gates on.
    #[serde(default)]
    pub features: Vec<String>,
    /// Issued at / expires at, Unix seconds. `exp` = 0 means no expiry.
    pub iat: i64,
    #[serde(default)]
    pub exp: i64,
    /// Issuer-assigned id.
    #[serde(default)]
    pub id: String,
    /// Controller binding (mesh CA fingerprint). Parsed so tokens carrying
    /// it verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    /// Seat limit. Parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u32>,
    /// The add-on terms version the holder accepted at issue (e.g.
    /// `addon-1.0`). Absent = issued before terms existed; it never changes
    /// what the token unlocks. Parsed so signed payloads round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<String>,
}

impl Entitlement {
    /// Features are the only authority; `tier` is a label this binary never
    /// consults.
    pub fn grants(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
    pub fn expired_at(&self, now: i64) -> bool {
        self.exp > 0 && now >= self.exp
    }
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("bad base64url segment: {e}"))
}

pub fn pubkey_from_hex(hex: &str) -> Result<VerifyingKey, String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "public key is not hex".to_string())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 public key: {e}"))
}

/// Parse + verify a token against `key`. Pure: no clock, no env — expiry is
/// the caller's check ([`Entitlement::expired_at`]) so tests can pin time.
pub fn verify_with(token: &str, key: &VerifyingKey) -> Result<Entitlement, String> {
    let body = token
        .trim()
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| format!("not an entitlement token (expected the {TOKEN_PREFIX} prefix)"))?;
    let (payload_b64, sig_b64) = body
        .split_once('.')
        .ok_or_else(|| "malformed token: missing signature segment".to_string())?;
    let payload = b64d(payload_b64)?;
    let sig_bytes = b64d(sig_b64)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("bad signature encoding: {e}"))?;
    key.verify(&payload, &sig)
        .map_err(|_| "signature does not verify against this build's entitlement key".to_string())?;
    let ent: Entitlement =
        serde_json::from_slice(&payload).map_err(|e| format!("payload is not an entitlement: {e}"))?;
    if ent.v != 1 {
        return Err(format!("unsupported entitlement version {}", ent.v));
    }
    Ok(ent)
}

/// Verify against the baked key(s): the first that verifies wins; the
/// error reported is the current key's.
pub fn verify(token: &str) -> Result<Entitlement, String> {
    let mut first_err: Option<String> = None;
    for hex in PUBKEYS_HEX {
        let key = pubkey_from_hex(hex).map_err(|e| format!("built-in key broken: {e}"))?;
        match verify_with(token, &key) {
            Ok(e) => return Ok(e),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| "no entitlement keys baked in".into()))
}

/// The entitlement this process was started with, verified once. `Err`
/// carries the operator-facing reason (absent / invalid / expired / wrong
/// tier), cached because env does not change under a running process.
pub fn installed() -> Result<&'static Entitlement, &'static str> {
    static CACHE: OnceLock<Result<Entitlement, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let raw = crate::config::secret_env::secret_or_empty(ENV_KEY);
            if raw.trim().is_empty() {
                return Err("no entitlement installed".to_string());
            }
            let ent = verify(&raw).map_err(|e| format!("entitlement rejected: {e}"))?;
            let now = chrono::Utc::now().timestamp();
            if ent.expired_at(now) {
                return Err(format!("entitlement for '{}' expired", ent.sub));
            }
            Ok(ent)
        })
        .as_ref()
        .map_err(|e| e.as_str())
}

/// Does the installed entitlement grant `feature`? `Err` = the operator-
/// facing reason (none installed / rejected / expired / not granted).
pub fn licensed(feature: &str) -> Result<(), String> {
    let ent = installed().map_err(|e| e.to_string())?;
    if ent.grants(feature) {
        Ok(())
    } else {
        Err(format!(
            "entitlement for '{}' grants [{}], not '{feature}'",
            ent.sub,
            ent.features.join(", ")
        ))
    }
}

#[cfg(test)]
pub mod testing {
    //! Ephemeral-key helpers shared by the tests here and in `addons.rs`.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    pub fn token(ent: &Entitlement) -> String {
        let payload = serde_json::to_vec(ent).unwrap();
        let sig = key().sign(&payload);
        format!(
            "{TOKEN_PREFIX}{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }
    pub fn intel(sub: &str, exp: i64) -> Entitlement {
        Entitlement {
            v: 1,
            sub: sub.into(),
            tier: TIER_INTELLIGENT.into(),
            features: vec!["trellion_intel".into()],
            iat: 1_700_000_000,
            exp,
            id: "t-1".into(),
            bound: None,
            max_nodes: None,
            terms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_tampering() {
        let ent = testing::intel("acme", 0);
        let tok = testing::token(&ent);
        let vk = testing::key().verifying_key();
        assert_eq!(verify_with(&tok, &vk).unwrap(), ent);
        // Flip a payload byte: signature no longer matches.
        let mut bad = tok.clone();
        let i = TOKEN_PREFIX.len() + 3;
        let c = if &bad[i..i + 1] == "A" { "B" } else { "A" };
        bad.replace_range(i..i + 1, c);
        assert!(verify_with(&bad, &vk).is_err());
        // A different key does not verify.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(verify_with(&tok, &other).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn prefix_version_and_expiry_rules() {
        let vk = testing::key().verifying_key();
        assert!(verify_with("garbage", &vk).unwrap_err().contains("prefix"));
        let ent = testing::intel("acme", 1_800_000_000);
        assert!(!ent.expired_at(1_799_999_999));
        assert!(ent.expired_at(1_800_000_000));
        // Features are the authority: a tier label alone grants nothing, and
        // a token may carry more than one feature.
        let label_only = Entitlement { features: vec![], ..testing::intel("x", 0) };
        assert!(!label_only.grants("trellion_intel"));
        let both = Entitlement { features: vec!["trellion_intel".into(), "evolve".into()], ..testing::intel("x", 0) };
        assert!(both.grants("evolve") && both.grants("trellion_intel") && !both.grants("other"));
        // Binding and seat fields parse and round-trip.
        let bound = Entitlement { bound: Some("sha256:abc".into()), max_nodes: Some(5), ..testing::intel("x", 0) };
        let tok = testing::token(&bound);
        assert_eq!(verify_with(&tok, &testing::key().verifying_key()).unwrap(), bound);
    }

    #[test]
    fn terms_round_trip_and_old_tokens_still_verify() {
        let vk = testing::key().verifying_key();
        let with = Entitlement { terms: Some("addon-1.0".into()), ..testing::intel("x", 0) };
        assert_eq!(verify_with(&testing::token(&with), &vk).unwrap(), with);
        assert!(!serde_json::to_string(&testing::intel("x", 0)).unwrap().contains("terms"));
        // A payload signed before the field existed.
        let old = br#"{"v":1,"sub":"acme","tier":"intelligent","features":["trellion_intel"],"iat":1,"exp":0,"id":"t"}"#;
        let sig = ed25519_dalek::Signer::sign(&testing::key(), old);
        let tok = format!(
            "{TOKEN_PREFIX}{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(old),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let e = verify_with(&tok, &vk).unwrap();
        assert_eq!(e.terms, None);
        assert!(e.grants("trellion_intel"));
    }

    /// The CLI's entitlement gained an `addons` trust block (i33). The
    /// gateway does not read it; a token carrying it must still verify here
    /// and unlock exactly what its features say, so this struct must keep
    /// tolerating unknown fields.
    #[test]
    fn token_with_addon_trust_block_still_verifies() {
        let vk = testing::key().verifying_key();
        let k = "ab".repeat(32);
        let payload = format!(
            r#"{{"v":1,"sub":"acme","tier":"intelligent","features":["evolve"],"iat":1,"exp":0,"id":"t","addons":{{"evolve":{{"keys":["{k}"],"registry":"ghcr.io/example/evolve"}}}}}}"#
        );
        let sig = ed25519_dalek::Signer::sign(&testing::key(), payload.as_bytes());
        let tok = format!(
            "{TOKEN_PREFIX}{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let e = verify_with(&tok, &vk).unwrap();
        assert!(e.grants("evolve") && !e.grants("trellion_intel"));
    }

    #[test]
    fn baked_key_is_a_valid_ed25519_point() {
        pubkey_from_hex(PUBKEY_HEX).expect("PUBKEY_HEX must decode");
        assert_eq!(PUBKEY_HEX.len(), 64);
    }
}
