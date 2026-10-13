// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Asymmetric signing for exchanged tokens, and the public key set
//!
//!
//! ## Why only exchanged tokens
//!
//! Every other JWT the gateway mints is HS256 against `NOO_JWT_SECRET`:
//! one shared secret that both signs and verifies, which means verifying
//! and forging are the same capability. That is fine for a token whose
//! only audience is this gateway — a login token has no third-party
//! verifier and no reason to grow one — and it keeps login cheap.
//!
//! An exchanged token is different. It is handed to an integrator who may
//! reasonably want to verify it in their own backend, or hand it to a
//! partner service, without a round trip here and without holding a secret
//! that would let them mint a token for any user in the system. That needs
//! a key pair: the gateway signs with the private half, anyone verifies
//! with the public half at [`JWKS_PATH`].
//!
//! So the split is deliberate and narrow. Turning this on changes the
//! signature of agent tokens and nothing else — no dual-accept window on
//! the login path, no migration for existing sessions.
//!
//! ## Algorithm confusion
//!
//! The classic attack on a deployment that publishes a public key: take
//! the published key, sign an HS256 token using it as the HMAC secret, and
//! hand it to a verifier that picks its key by algorithm name. This module
//! closes that by construction — [`crate::auth::verify_token`] reads the
//! header's `alg` and picks the key for THAT algorithm only, with
//! `Validation::new(alg)` restricting the accepted set to one. An ES256
//! token is never checked against the HMAC secret and an HS256 token is
//! never checked against the public key. A token claiming ES256 when no
//! signing key is configured is refused rather than falling back.
//!
//! ## Operating it
//!
//! `NOO_JWT_SIGNING_KEY` holds a PEM-encoded P-256 private key. Absent, the
//! exchange mints HS256 exactly as before — this is opt-in, and an install
//! that never sets it is unaffected.

use std::sync::OnceLock;

use base64::Engine as _;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Where the public key set is served. Public: a JWKS is public by
/// definition, and a verifier fetches it before it has any credential.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// The env key holding the PEM private key.
pub const SIGNING_KEY_ENV: &str = "NOO_JWT_SIGNING_KEY";

/// The one algorithm this module signs with. P-256 rather than RSA: the
/// keys and signatures are a fraction of the size, which matters for a
/// token minted per turn.
pub const ALG: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::ES256;

pub struct SigningKey {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    /// `kid`, so a verifier can pick the right key across a rotation.
    pub kid: String,
    /// The public half as a JWK, ready to serve.
    pub jwk: Value,
}

static KEY: OnceLock<Option<SigningKey>> = OnceLock::new();

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Read the PEM through `secret_env` — the same precedence every tier-1
/// secret uses: `NOO_JWT_SIGNING_KEY_FILE` first, then `NOO_SECRET_*`,
/// then the plain variable.
///
/// The `_FILE` tier is the way out of the contortion below: a file holds
/// a real multi-line PEM, so once compose delivers `/run/secrets/…` the
/// operator writes the key as `openssl` printed it and none of the three
/// env encodings is needed. [`normalise_pem`] still runs on the file's
/// content, so a base64 or `\n`-escaped file is accepted too.
fn pem_from_env() -> Option<String> {
    crate::config::secret_env::secret_opt(SIGNING_KEY_ENV)
        .map(|s| normalise_pem(&s))
        .filter(|s| !s.is_empty())
}

/// Accept the three shapes a PEM can arrive in through an environment
/// variable, because **a dotenv file cannot hold a multi-line value.**
///
/// This was nearly shipped as "paste the PEM into `env.sops`", which
/// cannot work: `env.sops` is dotenv-shaped, docker's `env_file` stops at
/// the first newline, and every other PEM in this codebase arrives as a
/// FILE for exactly that reason. The operator would have stored a key,
/// restarted, and seen `{"keys": []}` with no clue why.
///
///   1. a real multi-line PEM — `export` from a shell, or a compose
///      block scalar;
///   2. a PEM with literal `\n` two-character sequences — what you get
///      when you put one on a single dotenv line;
///   3. base64 of the whole PEM — the shape that survives every
///      transport without escaping, and the one to prefer.
///
/// Normalising here rather than asking the operator to pick means the
/// thing they tried first works.
pub fn normalise_pem(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.contains("-----BEGIN") {
        // Shape 1 or 2. Unescaping is safe on a real PEM: base64 and the
        // armour never contain a backslash, so there is no `\n` to
        // corrupt.
        return t.replace("\\n", "\n");
    }
    // Shape 3, or something unusable. Decoding failure returns the input
    // so `parse` reports "not a usable PEM" against what was actually
    // configured, rather than an empty string that reads as "unset".
    match base64::engine::general_purpose::STANDARD.decode(t.as_bytes()) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| t.to_string()),
        Err(_) => t.to_string(),
    }
}

/// Parse a PEM P-256 private key into everything the gateway needs from
/// it. `None` — with a loud log — when it is set but unusable: a
/// misconfigured key must not read as "asymmetric signing is off", which
/// would silently downgrade every token to HS256.
pub fn parse(pem: &str) -> Option<SigningKey> {
    let kp = match rcgen::KeyPair::from_pem(pem) {
        Ok(kp) => kp,
        Err(e) => {
            tracing::error!(error = %e, "{SIGNING_KEY_ENV} is set but is not a usable PEM key pair");
            return None;
        }
    };
    // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
    let raw = kp.public_key_raw();
    if raw.len() != 65 || raw[0] != 0x04 {
        tracing::error!(
            len = raw.len(),
            "{SIGNING_KEY_ENV} is not a P-256 key (expected a 65-byte uncompressed point)"
        );
        return None;
    }
    let (x, y) = (&raw[1..33], &raw[33..65]);
    let encoding = match EncodingKey::from_ec_pem(pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "{SIGNING_KEY_ENV} could not be loaded as an ES256 signing key");
            return None;
        }
    };
    let (x_b64, y_b64) = (b64(x), b64(y));
    // Derived from the key, not configured: a rotation changes the kid
    // without anyone having to remember to change it, and two gateways
    // holding the same key agree on it.
    let kid = b64(&Sha256::digest(raw)[..16]);
    Some(SigningKey {
        encoding,
        decoding: DecodingKey::from_ec_components(&x_b64, &y_b64).ok()?,
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
        }),
        kid: kid.clone(),
    })
}

/// The configured signing key, parsed once. `None` = HS256 everywhere, as
/// before.
pub fn signing_key() -> Option<&'static SigningKey> {
    KEY.get_or_init(|| pem_from_env().as_deref().and_then(parse)).as_ref()
}

/// The JWKS document. An empty `keys` array when nothing is configured —
/// a valid JWKS that says "this issuer publishes no keys", which is the
/// truthful answer and lets a client tell it apart from a 404.
pub fn jwks_document() -> Value {
    match signing_key() {
        Some(k) => json!({ "keys": [k.jwk] }),
        None => json!({ "keys": [] }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated key round-trips: sign with the private half, verify
    /// with the public components the JWKS publishes. If this passes, a
    /// third party holding only the JWKS can verify our tokens — which is
    /// the entire point of the feature.
    #[test]
    fn a_third_party_can_verify_with_only_the_published_key() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key = parse(&kp.serialize_pem()).expect("a generated P-256 key must parse");

        let claims = json!({
            "sub": "persona", "iss": crate::auth::JWT_ISSUER,
            "aud": crate::auth::JWT_AUDIENCE,
            "exp": 4_102_444_800i64,
        });
        let mut header = jsonwebtoken::Header::new(ALG);
        header.kid = Some(key.kid.clone());
        let token = jsonwebtoken::encode(&header, &claims, &key.encoding).unwrap();

        // Verify using ONLY what the JWKS exposes.
        let published = &key.jwk;
        let rebuilt = DecodingKey::from_ec_components(
            published["x"].as_str().unwrap(),
            published["y"].as_str().unwrap(),
        )
        .unwrap();
        let mut v = jsonwebtoken::Validation::new(ALG);
        v.set_issuer(&[crate::auth::JWT_ISSUER]);
        v.set_audience(&[crate::auth::JWT_AUDIENCE]);
        jsonwebtoken::decode::<serde_json::Value>(&token, &rebuilt, &v)
            .expect("the published key must verify what the private half signed");
    }

    /// The dual-accept rules, exercised through the PRODUCTION verifier.
    ///
    /// An earlier version of this test asserted against
    /// `jsonwebtoken::decode` directly and passed for the wrong reason —
    /// an EC `DecodingKey` cannot do HMAC at all, so it rejected the
    /// forgery whatever the validation allowed. Loosening the algorithm
    /// list did not fail it, which is how the vacuity showed up. It now
    /// goes through `verify_token_with`, which is the code that actually
    /// runs.
    ///
    /// **What each assertion is worth**, measured by planting the bug it
    /// describes and watching this fail:
    ///
    /// - the HS256-with-a-signing-key-present case is load-bearing. Make
    ///   the HS256 branch prefer the EC key and it fails — which is
    ///   exactly the regression that would break every login the day
    ///   asymmetric signing is switched on.
    /// - the wrong-`kid` case is load-bearing. The token is signed by the
    ///   real key and its signature is valid; only the label is wrong.
    ///   Relax the match to "any kid" and it verifies. This is the one
    ///   that matters at rotation, when the difference between a current
    ///   key and a retired one is exactly this label.
    /// - the ES256-refusal and forged-token cases do NOT fail when the
    ///   branch is broken, because `jsonwebtoken` binds key TYPE to
    ///   algorithm family and rejects an HMAC key for ES256 (and an EC
    ///   key for HS256) on its own. They are kept as a statement of
    ///   intent and a guard against a future library that is laxer, but
    ///   the honest reading is that the library, not this branch, is what
    ///   structurally prevents algorithm confusion here. The branch buys
    ///   an explained error instead of a signature failure.
    #[test]
    fn the_verifier_picks_its_key_from_the_tokens_own_algorithm() {
        use crate::auth::verify_token_with;
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key = parse(&kp.serialize_pem()).expect("a generated P-256 key must parse");
        let secret = "the-gateways-hmac-secret-not-a-real-key";
        let claims = json!({
            "sub": "persona", "role": "user", "scopes": ["read"],
            "iss": crate::auth::JWT_ISSUER, "aud": crate::auth::JWT_AUDIENCE,
            "exp": 4_102_444_800i64,
        });

        // An ES256 token verifies with the signing key, and ONLY then.
        let mut header = jsonwebtoken::Header::new(ALG);
        header.kid = Some(key.kid.clone());
        let es = jsonwebtoken::encode(&header, &claims, &key.encoding).unwrap();
        assert!(verify_token_with(&es, secret, Some(&key)).is_ok());
        assert!(
            verify_token_with(&es, secret, None).is_err(),
            "ES256 with no signing key configured must be REFUSED, never fall back to the secret"
        );

        // An HS256 token keeps working whether or not a signing key
        // exists — login is unaffected by turning this on.
        let hs = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        assert!(verify_token_with(&hs, secret, Some(&key)).is_ok());
        assert!(verify_token_with(&hs, secret, None).is_ok());

        // The alg-confusion attack: the attacker takes the published
        // public key and signs an HS256 token using it as the HMAC
        // secret. It fails because the HS256 branch uses the gateway's
        // secret and nothing else — the public key is never a key for
        // symmetric verification.
        // One spelling of the attack: the JWK's `x` coordinate. The
        // canonical version tries whatever encoding the server might
        // treat as the public key — the PEM, the DER, the full point.
        // Every variant fails for the same structural reason (the HS256
        // branch never touches public key material at all), so this is a
        // sample of the family rather than a weaker claim.
        let published = key.jwk["x"].as_str().unwrap().to_string();
        let forged = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"sub": "admin", "role": "admin", "scopes": ["admin"],
                    "iss": crate::auth::JWT_ISSUER, "aud": crate::auth::JWT_AUDIENCE,
                    "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(published.as_bytes()),
        )
        .unwrap();
        assert!(
            verify_token_with(&forged, secret, Some(&key)).is_err(),
            "a token signed with the PUBLISHED key must never verify"
        );

        // `kid` must MATCH, not merely be present. This assertion is
        // load-bearing in a way the two above are not: the token is
        // signed by the real key and its signature is perfectly valid —
        // only the `kid` is wrong. Drop the check and it verifies. That
        // is the rotation hazard in miniature: a verifier that ignores
        // `kid` cannot tell a retired key from a current one.
        let mut wrong_kid = jsonwebtoken::Header::new(ALG);
        wrong_kid.kid = Some("a-key-this-gateway-does-not-hold".into());
        let mislabelled = jsonwebtoken::encode(&wrong_kid, &claims, &key.encoding).unwrap();
        assert!(
            verify_token_with(&mislabelled, secret, Some(&key)).is_err(),
            "a validly-signed token naming an unknown kid must be refused"
        );

        // And an ES256 token with no kid at all.
        let no_kid = jsonwebtoken::encode(&jsonwebtoken::Header::new(ALG), &claims, &key.encoding).unwrap();
        assert!(verify_token_with(&no_kid, secret, Some(&key)).is_err());

        // And an algorithm we do not sign with is refused outright rather
        // than reaching a key-selection branch at all.
        let none_alg = format!(
            "{}.{}.",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        assert!(verify_token_with(&none_alg, secret, Some(&key)).is_err());
    }

    /// A dotenv file cannot hold a multi-line value, so a PEM reaches
    /// this process escaped or encoded. All three shapes must parse to
    /// the same key, or the operator stores a key, restarts, and sees an
    /// empty JWKS with nothing to explain it.
    #[test]
    fn a_pem_survives_every_shape_an_env_var_can_carry() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = kp.serialize_pem();

        // 1. A real multi-line PEM.
        let a = parse(&normalise_pem(&pem)).expect("multi-line PEM");
        // 2. Escaped onto one line, as a dotenv file forces.
        let escaped = pem.replace('\n', "\\n");
        assert!(!escaped.contains('\n'), "the escaped form must be single-line");
        let b = parse(&normalise_pem(&escaped)).expect("escaped PEM");
        // 3. base64 of the whole thing.
        let encoded = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
        let c = parse(&normalise_pem(&encoded)).expect("base64 PEM");

        // Same key all three ways — compared on the published material,
        // which is what a verifier would actually use.
        assert_eq!(a.jwk["x"], b.jwk["x"]);
        assert_eq!(a.jwk["x"], c.jwk["x"]);
        assert_eq!(a.kid, b.kid);
        assert_eq!(a.kid, c.kid);
    }

    /// Garbage must report against what was configured, not vanish. An
    /// empty string reads as "unset", and "unset" is the one diagnosis
    /// that sends an operator looking in the wrong place.
    #[test]
    fn an_unusable_value_is_reported_not_erased() {
        assert_eq!(normalise_pem("   "), "");
        assert_eq!(normalise_pem("not-a-key"), "not-a-key");
        assert!(parse(&normalise_pem("not-a-key")).is_none());
    }

    #[test]
    fn a_key_that_is_set_but_broken_is_not_silently_off() {
        assert!(parse("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----").is_none()); // leak-ok: the literal string "not a key" inside PEM armour, which is the point of the test
        assert!(parse("").is_none());
    }

    #[test]
    fn no_key_configured_publishes_an_empty_set_not_an_error() {
        // Shape, not state: `jwks_document` must always be a valid JWKS.
        let doc = jwks_document();
        assert!(doc.get("keys").and_then(|k| k.as_array()).is_some());
    }
}
