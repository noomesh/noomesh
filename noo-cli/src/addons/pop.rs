// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Proof of possession for the vendor's add-on registry proxy.
//!
//! An entitlement may be bound to one controller (`cnf.ed25519`, RFC 7800
//! style). The proxy then answers the first token request with
//! `401` + `WWW-Authenticate: Noo-PoP realm="…",nonce="<n>"`, and the
//! controller repeats it with `Noo-PoP-Nonce: <n>` and `Noo-PoP-Signature:
//! <base64url ed25519 signature>` over [`message`]. A copied entitlement is
//! then no use on another controller.
//!
//! # Which key
//!
//! The controller's identity is its mesh CA: the entitlement's existing
//! `bound` field already names the CA fingerprint, the CA lives exactly as
//! long as the cluster (3650 days; the bundle-signing key rotates on its own
//! and the self node's birth key is re-minted on re-enrollment), and only this
//! CLI reads `ca.key`. None of the cluster's keys is ed25519 (the CA and
//! `signing.key` are P-384, birth keys RSA-4096), and the proxy speaks
//! ed25519, so the PoP key is DERIVED from the CA private key, one way and
//! domain-separated: `seed = SHA-256("noo-addon-pop/1 controller key\0" ||
//! CA private scalar)`. Nothing new is stored; the same CA always yields the
//! same key; the derived key reveals nothing about the CA key. The public
//! half is what `noo security entitlement pubkey` prints for the vendor to
//! bind at issue (`--bind-key`). A CA rotation changes it, and the
//! entitlement is then reissued for the new key.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::Digest as _;

/// Signed-message domain; matches the proxy's `pop::DOMAIN`.
pub const DOMAIN: &str = "noo-addon-pop/1";
pub const NONCE_HEADER: &str = "Noo-PoP-Nonce";
pub const SIGNATURE_HEADER: &str = "Noo-PoP-Signature";
/// The derivation label (domain separation from every other use of the CA key).
const DERIVE_LABEL: &[u8] = b"noo-addon-pop/1 controller key\0";

/// The exact bytes the controller signs.
pub fn message(service: &str, ent_id: &str, nonce: &str) -> Vec<u8> {
    format!("{DOMAIN}\n{service}\n{ent_id}\n{nonce}").into_bytes()
}

/// The signature header value: 64 bytes, base64url without padding.
pub fn sign(key: &SigningKey, service: &str, ent_id: &str, nonce: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(&message(service, ent_id, nonce)).to_bytes())
}

pub fn pubkey_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// `Noo-PoP realm="…",nonce="…"` → the nonce.
pub fn challenge_nonce(h: &str) -> Option<String> {
    let rest = h.trim();
    let rest = rest.get(..8).filter(|p| p.eq_ignore_ascii_case("noo-pop ")).map(|_| &rest[8..])?;
    crate::addons::lock_fetch::parse_auth_params(rest)?
        .into_iter()
        .find(|(k, _)| k == "nonce")
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// The PoP key derived from a CA private key PEM (PKCS#8 `PRIVATE KEY`, or
/// SEC1 `EC PRIVATE KEY`).
pub fn derive_from_ca_pem(pem: &str) -> Result<SigningKey, String> {
    let scalar = ec_private_scalar(pem)?;
    let mut h = sha2::Sha256::new();
    h.update(DERIVE_LABEL);
    h.update(&scalar);
    let d = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&d[..32]);
    Ok(SigningKey::from_bytes(&seed))
}

/// This controller's PoP key, from the cluster CA under the PKI directory.
pub fn controller_key() -> Result<SigningKey, String> {
    let ca = crate::pki::ClusterCa { dir: crate::pki::pki_dir() };
    let path = ca.ca_key_path();
    let pem = std::fs::read_to_string(&path).map_err(|e| {
        format!("the controller's add-on key is derived from the cluster CA, and {} could not be read ({e})", path.display())
    })?;
    derive_from_ca_pem(&pem).map_err(|e| format!("{}: {e}", path.display()))
}

/// The private scalar of an EC key: the bytes that ARE the key, whatever
/// optional members (curve, public point) the encoder added around them.
fn ec_private_scalar(pem: &str) -> Result<Vec<u8>, String> {
    let (label, der) = pem_body(pem)?;
    let sec1 = match label.as_str() {
        "PRIVATE KEY" => {
            // PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING, … }
            let mut seq = Der::new(Der::new(&der).expect_tlv(0x30)?);
            seq.expect_tlv(0x02)?;
            seq.expect_tlv(0x30)?;
            seq.expect_tlv(0x04)?.to_vec()
        }
        "EC PRIVATE KEY" => der,
        other => return Err(format!("the CA key is a {other:?} PEM, not an EC private key")),
    };
    // ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING, … }
    let mut ec = Der::new(Der::new(&sec1).expect_tlv(0x30)?);
    ec.expect_tlv(0x02)?;
    let scalar = ec.expect_tlv(0x04)?;
    if scalar.len() < 32 {
        return Err("the CA key's private scalar is shorter than 32 bytes".into());
    }
    Ok(scalar.to_vec())
}

fn pem_body(pem: &str) -> Result<(String, Vec<u8>), String> {
    let begin = pem.find("-----BEGIN ").ok_or("not a PEM file")?;
    let rest = &pem[begin + 11..];
    let label_end = rest.find("-----").ok_or("not a PEM file")?;
    let label = rest[..label_end].to_string();
    let body_start = label_end + 5;
    let end = rest.find("-----END ").ok_or("PEM has no END line")?;
    let b64: String = rest[body_start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("PEM body is not base64: {e}"))?;
    Ok((label, der))
}

/// A minimal DER reader: tag, definite length, contents.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self {
        Der(b)
    }

    fn expect_tlv(&mut self, tag: u8) -> Result<&'a [u8], String> {
        let b = self.0;
        let bad = || format!("the CA key is not DER this reader understands (expected tag {tag:#04x})");
        if b.first() != Some(&tag) {
            return Err(bad());
        }
        let (len, hdr) = match *b.get(1).ok_or_else(bad)? {
            l if l < 0x80 => (l as usize, 2),
            0x81 => (*b.get(2).ok_or_else(bad)? as usize, 3),
            0x82 => (((*b.get(2).ok_or_else(bad)? as usize) << 8) | *b.get(3).ok_or_else(bad)? as usize, 4),
            _ => return Err(bad()),
        };
        let body = b.get(hdr..hdr + len).ok_or_else(bad)?;
        self.0 = &b[hdr + len..];
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    fn p384_pem() -> String {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap().serialize_pem()
    }

    #[test]
    fn the_message_is_the_proxy_wire_format() {
        assert_eq!(message("addons.noomesh.ai", "ent-1", "N"), b"noo-addon-pop/1\naddons.noomesh.ai\nent-1\nN".to_vec());
    }

    #[test]
    fn a_signature_verifies_over_the_message_only() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let sig = sign(&k, "addons.noomesh.ai", "ent-1", "N");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&sig).unwrap();
        assert_eq!(raw.len(), 64);
        let s = ed25519_dalek::Signature::from_slice(&raw).unwrap();
        assert!(k.verifying_key().verify(&message("addons.noomesh.ai", "ent-1", "N"), &s).is_ok());
        assert!(k.verifying_key().verify(&message("addons.noomesh.ai", "ent-2", "N"), &s).is_err());
        assert!(!sig.contains('=') && !sig.contains('+') && !sig.contains('/'), "base64url, no padding: {sig}");
    }

    #[test]
    fn the_derived_key_is_stable_per_ca_and_differs_between_cas() {
        let a = p384_pem();
        let b = p384_pem();
        let ka = derive_from_ca_pem(&a).unwrap();
        assert_eq!(pubkey_hex(&ka), pubkey_hex(&derive_from_ca_pem(&a).unwrap()), "same CA, same key");
        assert_ne!(pubkey_hex(&ka), pubkey_hex(&derive_from_ca_pem(&b).unwrap()));
        assert_eq!(pubkey_hex(&ka).len(), 64);
    }

    #[test]
    fn the_derivation_reads_the_scalar_not_the_encoding() {
        // The same key as SEC1 and as PKCS#8 (what python-cryptography and
        // rcgen write) derives the same PoP key.
        let pem = p384_pem();
        let scalar = ec_private_scalar(&pem).unwrap();
        assert_eq!(scalar.len(), 48, "P-384");
        let (_, der) = pem_body(&pem).unwrap();
        let mut seq = Der::new(Der::new(&der).expect_tlv(0x30).unwrap());
        seq.expect_tlv(0x02).unwrap();
        seq.expect_tlv(0x30).unwrap();
        let sec1 = seq.expect_tlv(0x04).unwrap();
        let sec1_pem = format!(
            "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(sec1)
        );
        assert_eq!(pubkey_hex(&derive_from_ca_pem(&sec1_pem).unwrap()), pubkey_hex(&derive_from_ca_pem(&pem).unwrap()));
        assert!(derive_from_ca_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
        assert!(derive_from_ca_pem("nonsense").is_err());
    }

    #[test]
    fn challenge_nonce_parsing() {
        assert_eq!(challenge_nonce(r#"Noo-PoP realm="https://addons.noomesh.ai/token",nonce="abc.def""#).as_deref(), Some("abc.def"));
        assert_eq!(challenge_nonce(r#"noo-pop nonce="n1""#).as_deref(), Some("n1"));
        assert_eq!(challenge_nonce(r#"Bearer realm="x",nonce="n""#), None);
        assert_eq!(challenge_nonce(r#"Noo-PoP realm="x""#), None);
    }
}
