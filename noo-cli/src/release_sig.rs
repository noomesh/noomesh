// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Release-artifact signatures.
//!
//! The release workflow signs `sha256sums.txt` with an Ed25519 key whose
//! seed lives ONLY in the `NOO_RELEASE_SIGNING_SEED` Actions secret and an
//! off-repo operator copy (`~/.config/noo/release-signing.seed`). The
//! verifying half is baked here, so `noo upgrade` proves a release came
//! from the pipeline whether it fetched from GitHub or a controller mirror —
//! a mirror (or the gateway database behind it) gains nothing by being
//! compromised. This is a DIFFERENT key from the entitlement key: different
//! trust domain, different rotation story. Rotation: prepend the new public
//! key, ship a CLI, then swap the secret; old releases keep verifying.
//!
//! Format: `noo-sig1.<base64url, unpadded, 64-byte ed25519 signature>` over
//! the exact file bytes.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Current key first.
pub const RELEASE_PUBKEYS_HEX: &[&str] = &["13be2244d5b91b1d5c29dfffd94a3817cb774c906785cf700e10a86d7be62d43"];
pub const SIG_PREFIX: &str = "noo-sig1.";
/// The manifest every release publishes and signs.
pub const MANIFEST: &str = "sha256sums.txt";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .map_err(|e| format!("bad base64url in signature: {e}"))
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let h = hex.trim();
    if !h.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..h.len()).step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

pub fn signing_key_from_seed_hex(seed_hex: &str) -> Result<SigningKey, String> {
    let bytes = hex_to_bytes(seed_hex)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "seed must be 32 bytes (64 hex chars)".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn pubkey_hex(key: &SigningKey) -> String {
    key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign `data`; the caller decides where the text goes (`<file>.sig`).
pub fn sign(key: &SigningKey, data: &[u8]) -> String {
    format!("{SIG_PREFIX}{}", b64(&key.sign(data).to_bytes()))
}

/// Verify against the baked key list; Ok(index of the key that matched).
pub fn verify(data: &[u8], sig_text: &str) -> Result<usize, String> {
    verify_with_keys(data, sig_text, RELEASE_PUBKEYS_HEX)
}

pub fn verify_with_keys(data: &[u8], sig_text: &str, keys_hex: &[&str]) -> Result<usize, String> {
    let body = sig_text.trim().strip_prefix(SIG_PREFIX)
        .ok_or_else(|| format!("not a release signature (expected the {SIG_PREFIX} prefix)"))?;
    let sig = Signature::from_slice(&b64d(body)?).map_err(|e| format!("bad signature encoding: {e}"))?;
    for (i, k) in keys_hex.iter().enumerate() {
        let kb: [u8; 32] = hex_to_bytes(k)?.try_into().map_err(|_| "baked key is not 32 bytes".to_string())?;
        let vk = VerifyingKey::from_bytes(&kb).map_err(|e| format!("baked key invalid: {e}"))?;
        if vk.verify(data, &sig).is_ok() {
            return Ok(i);
        }
    }
    Err("signature does not verify against any release key baked into this build".into())
}

/// The sha256 a signed `sha256sums.txt` states for `asset` (`<hex>  <name>` lines).
pub fn manifest_sha_for(manifest: &str, asset: &str) -> Option<String> {
    manifest.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let (sum, name) = (it.next()?, it.next()?);
        let name = name.trim_start_matches('*').rsplit('/').next().unwrap_or(name);
        (name == asset).then(|| sum.to_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let key = signing_key_from_seed_hex(&"ab".repeat(32)).unwrap();
        let pk = pubkey_hex(&key);
        let data = b"deadbeef  noo-x86_64-unknown-linux-musl\n";
        let sig = sign(&key, data);
        assert!(sig.starts_with(SIG_PREFIX));
        assert_eq!(verify_with_keys(data, &sig, &[pk.as_str()]).unwrap(), 0);
        assert!(verify_with_keys(b"deadbeef  noo-evil\n", &sig, &[pk.as_str()]).is_err());
        assert!(verify_with_keys(data, &sig, &["00".repeat(32).as_str()]).is_err());
        // rotation: an older key later in the list still verifies
        assert_eq!(verify_with_keys(data, &sig, &["00".repeat(32).as_str(), pk.as_str()]).unwrap(), 1);
    }

    #[test]
    fn manifest_lookup() {
        let m = "aa  noo-a\nbb  ./noo-b\ncc *noo-c\n";
        assert_eq!(manifest_sha_for(m, "noo-b").as_deref(), Some("bb"));
        assert_eq!(manifest_sha_for(m, "noo-c").as_deref(), Some("cc"));
        assert!(manifest_sha_for(m, "noo-z").is_none());
    }

    #[test]
    fn baked_keys_are_well_formed() {
        for k in RELEASE_PUBKEYS_HEX {
            assert_eq!(hex_to_bytes(k).unwrap().len(), 32);
        }
    }
}
