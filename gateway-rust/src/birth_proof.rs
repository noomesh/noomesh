// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Birth-key proof of possession for the provisioning pull lane.
//!
//! # The hole this closes
//!
//! `GET /bootstrap/bundle/{node}` is public, and it has to be: the node holds
//! no fleet credential at that moment — `NOO_CLUSTER_SECRET` is rendered into
//! the `agent-env` member of the very bundle being fetched — and the blob is
//! CMS ciphertext encrypted to the node's birth cert, so a stranger who fetches
//! it gets bytes they cannot decrypt. Leaving the READ open is evidenced.
//!
//! What was not evidenced is that the same request **wrote** `fetched_at`. Any
//! anonymous caller could stamp it, so it meant "somebody collected this
//! ciphertext", never "the node did" — and a stranger could make
//! `noo cluster provision --wait` believe the applier phase had completed and
//! drive it on to stage the full bundle early.
//!
//! # The credential
//!
//! The one thing the node DOES hold at fetch time is its birth key: an
//! RSA-4096 private key written at enrollment (`/etc/noo/birth.key`, root
//! 0600, installed by `scripts/prep-host.sh`; `<base>/birth.key` on a Mac).
//! The controller holds the matching certificate in
//! `noo_bootstrap_tokens.birth_cert`, recorded at enrollment. That is the same
//! pair CMS encryption already uses, so this adds no key material and no new
//! ceremony — it uses the one that is provably already on both sides.
//!
//! # The proof
//!
//! The node signs, with RSA PKCS#1 v1.5 over SHA-256:
//!
//! ```text
//! noo-bundle-<purpose>:<node>:<bundle_sha>:<unix_ts>
//! ```
//!
//! and presents `<ts>.<base64 signature>`. The gateway verifies it against the
//! stored certificate, requires the timestamp within ±300 s, and requires the
//! sha to be the sha of the blob currently staged for that node.
//!
//! Three things are bound in deliberately:
//!
//! - **`node`** — so a node that legitimately holds a birth key cannot stamp
//!   its neighbour's row. A signature is otherwise transferable.
//! - **`bundle_sha`** — so `fetched_at` means "the node collected exactly this
//!   blob", which is stronger than the header-on-the-GET shape could be: at
//!   the moment of the GET the node has not yet seen the bytes, so it cannot
//!   sign them. The fetch receipt is therefore a separate, later call.
//! - **`purpose`** — domain separation, so a captured fetch receipt is not
//!   also an apply report.
//!
//! Replay is bounded by the freshness window plus the sha binding: a captured
//! proof is worth nothing once 300 s have passed, and worth nothing against a
//! different bundle even inside it.
//!
//! # What this module deliberately does not do
//!
//! It does not mint, sign or validate certificate CHAINS. The birth cert is
//! self-signed by construction (`noo enroll` generates it, as the retired `bootstrap-enroll.sh` did, with
//! `openssl req -x509`), and its authority here is that the controller
//! recorded THIS cert for THIS node at enrollment — not that some CA vouches
//! for it. Verifying a chain would be a different, weaker claim.

use base64::Engine as _;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
// rsa 0.9 is built on digest 0.10 (its digest-0.11 line, 0.10, is still a
// release candidate), so the hash it is parameterised by must be the sha2
// 0.10 it re-exports, not the crate's own sha2 0.11.
use rsa::sha2::Sha256;

/// How far a node's clock may be from the controller's. The same ±300 s the
/// cluster HMAC rail already allows, for the same reason: a node whose NTP has
/// drifted a few minutes is a normal node, and a window wider than that starts
/// buying an attacker replay time for nothing.
pub const MAX_SKEW_SECS: i64 = 300;

/// What the proof is FOR. Domain separation, so a receipt captured off one
/// route cannot be replayed onto the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// "I collected this bundle" — stamps `fetched_at`.
    Fetch,
    /// "I applied this bundle, with this result" — stamps `applied_at`.
    Apply,
    // ── Kiosk SEATS (i77) ──
    //
    // A seat signs with its own birth key, recorded in `noo_seats` — never in
    // `noo_bootstrap_tokens`, so no node route can find a seat's cert. The
    // seat purposes ALSO sign a different message prefix (`noo-seat-…`, see
    // [`signed_message`]): a seat proof is not a node proof even for a seat
    // and a node that share a name, and a node proof is not a seat proof.
    /// The seat collects its staged bundle (the GET itself is signed, over
    /// no sha: the seat is fully enrolled before it ever fetches).
    SeatGet,
    /// The seat's receipt for the blob it collected.
    SeatFetch,
    /// The seat's apply report.
    SeatApply,
    /// The seat's heartbeat; the sha is that of the JSON body.
    SeatHeartbeat,
}

impl Purpose {
    fn tag(self) -> &'static str {
        match self {
            Purpose::Fetch => "fetch",
            Purpose::Apply => "apply",
            Purpose::SeatGet => "get",
            Purpose::SeatFetch => "fetch",
            Purpose::SeatApply => "apply",
            Purpose::SeatHeartbeat => "heartbeat",
        }
    }

    /// The domain a proof belongs to: `noo-bundle` for a node, `noo-seat`
    /// for a seat. Part of the signed bytes.
    pub fn is_seat(self) -> bool {
        matches!(self, Purpose::SeatGet | Purpose::SeatFetch | Purpose::SeatApply | Purpose::SeatHeartbeat)
    }
}

/// Why a proof was refused. Separate from the message the caller sees so the
/// handler decides how much to disclose; every variant is a refusal, never a
/// "probably fine".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The header is absent. The caller offered no proof at all.
    Missing,
    /// Present but not `<ts>.<base64>`.
    Malformed(&'static str),
    /// Outside the ±MAX_SKEW_SECS window. Includes the replay of an old,
    /// otherwise-valid proof.
    Stale,
    /// This node has no birth cert recorded — enrolled before the birth
    /// keypair existed, or enrolled on a host with no openssl.
    NoBirthCert,
    /// The recorded cert did not parse.
    BadBirthCert(String),
    /// The signature did not verify against the recorded cert. This is the
    /// "wrong node's key" case as well as the forged one.
    BadSignature,
}

impl ProofError {
    /// The operator-facing text. It names the fix, because a node that cannot
    /// prove itself is usually a node running an old `noo-fetch`.
    pub fn message(&self, node: &str) -> String {
        match self {
            ProofError::Missing => format!(
                "this write needs a birth-key proof: node '{node}' must sign \
                 \"noo-bundle-<purpose>:<node>:<sha>:<ts>\" with /etc/noo/birth.key and send it as \
                 X-Noo-Birth-Proof: <ts>.<base64 sig>. An old `noo-fetch` does not — get \
                 scripts/noo-fetch.sh onto this node (`noo cluster provision {node}`)"
            ),
            ProofError::Malformed(why) => {
                format!("birth-key proof is malformed ({why}): expected <ts>.<base64 signature>")
            }
            ProofError::Stale => format!(
                "birth-key proof is outside the ±{MAX_SKEW_SECS}s freshness window — \
                 check this node's clock, or it is a replayed proof"
            ),
            ProofError::NoBirthCert => format!(
                "no birth certificate is recorded for node '{node}', so its proof cannot be \
                 checked. It enrolled before the birth keypair existed (or without openssl); \
                 re-enroll it to arm the pull lane"
            ),
            ProofError::BadBirthCert(e) => {
                format!("the birth certificate recorded for node '{node}' does not parse: {e}")
            }
            ProofError::BadSignature => format!(
                "birth-key proof does not verify against the certificate recorded for node \
                 '{node}'"
            ),
        }
    }
}

/// The exact bytes both sides sign. Public so the shell and Mac signers can be
/// tested against the same string the gateway builds, rather than against a
/// second copy of the format that is free to drift.
pub fn signed_message(purpose: Purpose, node: &str, sha: &str, ts: i64) -> String {
    let domain = if purpose.is_seat() { "noo-seat" } else { "noo-bundle" };
    format!("{domain}-{}:{}:{}:{}", purpose.tag(), node, sha, ts)
}

/// Split `<ts>.<base64 signature>`.
fn split_header(raw: &str) -> Result<(i64, Vec<u8>), ProofError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ProofError::Missing);
    }
    let (ts, sig_b64) = raw
        .split_once('.')
        .ok_or(ProofError::Malformed("no '.' separating the timestamp"))?;
    let ts: i64 = ts
        .trim()
        .parse()
        .map_err(|_| ProofError::Malformed("the timestamp is not an integer"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| ProofError::Malformed("the signature is not base64"))?;
    if sig.is_empty() || sig.len() > 1024 {
        return Err(ProofError::Malformed("implausible signature length"));
    }
    Ok((ts, sig))
}

/// Pull the RSA public key out of a PEM certificate.
///
/// `x509-cert` is already a direct dependency (the cert-expiry heartbeat
/// parses `notAfter` with it), so this adds no parser to the trust boundary —
/// only the `rsa` verifier, which was already in the lock graph.
fn public_key(cert_pem: &str) -> Result<RsaPublicKey, ProofError> {
    use x509_cert::der::{Decode as _, Encode as _};
    use x509_cert::Certificate;

    let pem = cert_pem.trim();
    if !pem.contains("BEGIN CERTIFICATE") {
        return Err(ProofError::BadBirthCert("not a PEM certificate".into()));
    }
    // Decode the PEM body ourselves rather than through a feature-gated
    // helper: the body is standard base64 between the two armour lines.
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| ProofError::BadBirthCert(format!("PEM body is not base64: {e}")))?;
    let cert = Certificate::from_der(&der)
        .map_err(|e| ProofError::BadBirthCert(format!("DER: {e}")))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| ProofError::BadBirthCert(format!("SPKI: {e}")))?;
    RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| ProofError::BadBirthCert(format!("not an RSA public key: {e}")))
}

/// Is this PEM a birth certificate a proof could ever be checked against?
/// A seat's enrolment refuses one that is not (i77): a seat recorded with an
/// unusable cert could never sign anything, and the failure would surface
/// minutes later as a refused heartbeat instead of at the enrolment that
/// caused it.
pub fn usable_birth_cert(cert_pem: &str) -> bool {
    public_key(cert_pem).is_ok()
}

/// Verify a proof. `now` is passed in rather than read here so the freshness
/// window is testable without sleeping — and so a test can prove the REPLAY
/// case rather than assert the happy path twice.
///
/// Returns `Ok(())` only when the signature verifies against the recorded
/// certificate, over exactly `(purpose, node, sha, ts)`, inside the window.
pub fn verify(
    header: Option<&str>,
    purpose: Purpose,
    node: &str,
    sha: &str,
    birth_cert_pem: Option<&str>,
    now: i64,
) -> Result<(), ProofError> {
    let raw = header.map(str::trim).filter(|h| !h.is_empty()).ok_or(ProofError::Missing)?;
    let (ts, sig) = split_header(raw)?;
    if (now - ts).abs() > MAX_SKEW_SECS {
        return Err(ProofError::Stale);
    }
    let pem = birth_cert_pem
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or(ProofError::NoBirthCert)?;
    let key = public_key(pem)?;
    let verifying: VerifyingKey<Sha256> = VerifyingKey::new(key);
    let signature = Signature::try_from(sig.as_slice()).map_err(|_| ProofError::BadSignature)?;
    verifying
        .verify(signed_message(purpose, node, sha, ts).as_bytes(), &signature)
        .map_err(|_| ProofError::BadSignature)
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    // Two real birth keypairs, generated once with the same openssl invocation
    // `noo enroll` uses (RSA, self-signed, /CN=noo-birth-<host>) and
    // committed as fixtures. Minting a 4096-bit key per test run would add
    // seconds to every `cargo test`; the SHAPE is what is under test, and 2048
    // is the same shape.
    //
    // They are named `*.testkey.pem`, not `*.key`. `.gitignore` ignores `*.key`
    // — for good reasons — so a fixture with that extension would pass here
    // and never be committed, and CI would fail to COMPILE this module on a
    // file that exists only on the author's machine. These keys are test
    // material and protect nothing; a real birth key is generated per node at
    // enrollment and never leaves it.
    const CERT_A: &str = include_str!("fixtures/birth_node_a.testcert.pem");
    const KEY_A: &str = include_str!("fixtures/birth_node_a.testkey.pem");
    const CERT_B: &str = include_str!("fixtures/birth_node_b.testcert.pem");
    const KEY_B: &str = include_str!("fixtures/birth_node_b.testkey.pem");

    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// Sign exactly the way `noo-fetch.sh` does: `openssl dgst -sha256 -sign`
    /// is RSA PKCS#1 v1.5 over SHA-256, which is what this builds.
    fn proof(key_pem: &str, purpose: Purpose, node: &str, sha: &str, ts: i64) -> String {
        let key = RsaPrivateKey::from_pkcs8_pem(key_pem).expect("fixture key");
        let signing: SigningKey<Sha256> = SigningKey::new(key);
        let sig = signing.sign(signed_message(purpose, node, sha, ts).as_bytes());
        format!(
            "{ts}.{}",
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        )
    }

    #[test]
    fn a_node_signed_proof_is_accepted() {
        let now = 1_757_000_000;
        let p = proof(KEY_A, Purpose::Fetch, "host9", SHA, now);
        verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), now).expect("must verify");
    }

    /// The hole, stated as a test: no proof is not a pass. This function has
    /// no "accept anyway" branch, and neither does its only caller.
    #[test]
    fn no_proof_is_refused_here_always() {
        for header in [None, Some(""), Some("   ")] {
            assert_eq!(
                verify(header, Purpose::Fetch, "host9", SHA, Some(CERT_A), 1_757_000_000),
                Err(ProofError::Missing)
            );
        }
    }

    /// A node that legitimately holds a birth key must not be able to stamp
    /// its neighbour's row — which is why the node name is signed, not just
    /// sent.
    #[test]
    fn another_nodes_key_is_refused() {
        let now = 1_757_000_000;
        let p = proof(KEY_B, Purpose::Fetch, "host9", SHA, now);
        assert_eq!(
            verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), now),
            Err(ProofError::BadSignature)
        );
        // And its own name against someone else's cert fares no better.
        let p = proof(KEY_B, Purpose::Fetch, "host3", SHA, now);
        assert_eq!(
            verify(Some(&p), Purpose::Fetch, "host3", SHA, Some(CERT_A), now),
            Err(ProofError::BadSignature)
        );
        // The same signature under B's own cert is fine — proving the refusal
        // above is about WHOSE key it is, not a broken fixture.
        verify(Some(&p), Purpose::Fetch, "host3", SHA, Some(CERT_B), now).expect("B verifies as B");
    }

    /// Replay: a proof that was valid twenty minutes ago is not valid now.
    #[test]
    fn an_old_proof_is_refused() {
        let then = 1_757_000_000;
        let p = proof(KEY_A, Purpose::Fetch, "host9", SHA, then);
        // Valid at the time it was made...
        verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), then).expect("fresh");
        // ...and at the edge of the window...
        verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), then + MAX_SKEW_SECS)
            .expect("edge of the window");
        // ...but not one second past it, nor twenty minutes later.
        for now in [then + MAX_SKEW_SECS + 1, then + 1200] {
            assert_eq!(
                verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), now),
                Err(ProofError::Stale),
                "a proof from {}s ago must be refused",
                now - then
            );
        }
        // A clock ahead of the controller is refused the same way.
        assert_eq!(
            verify(Some(&p), Purpose::Fetch, "host9", SHA, Some(CERT_A), then - 1200),
            Err(ProofError::Stale)
        );
    }

    /// A proof is for ONE bundle and ONE route. Either binding, cut, and the
    /// signature stops verifying.
    #[test]
    fn the_sha_and_the_purpose_are_both_bound() {
        let now = 1_757_000_000;
        let p = proof(KEY_A, Purpose::Fetch, "host9", SHA, now);
        let other_sha = "0".repeat(64);
        assert_eq!(
            verify(Some(&p), Purpose::Fetch, "host9", &other_sha, Some(CERT_A), now),
            Err(ProofError::BadSignature),
            "a fetch receipt must not carry over to a different bundle"
        );
        assert_eq!(
            verify(Some(&p), Purpose::Apply, "host9", SHA, Some(CERT_A), now),
            Err(ProofError::BadSignature),
            "a fetch receipt must not double as an apply report"
        );
    }

    #[test]
    fn a_node_with_no_recorded_cert_cannot_be_checked() {
        let now = 1_757_000_000;
        let p = proof(KEY_A, Purpose::Fetch, "host9", SHA, now);
        for cert in [None, Some(""), Some("  \n ")] {
            assert_eq!(
                verify(Some(&p), Purpose::Fetch, "host9", SHA, cert, now),
                Err(ProofError::NoBirthCert)
            );
        }
        assert!(matches!(
            verify(Some(&p), Purpose::Fetch, "host9", SHA, Some("not a cert"), now),
            Err(ProofError::BadBirthCert(_))
        ));
    }

    #[test]
    fn a_malformed_header_is_named_not_guessed() {
        let now = 1_757_000_000;
        for bad in ["abc", "123.@@@@", ".", "notanint.YWJj"] {
            assert!(
                matches!(
                    verify(Some(bad), Purpose::Fetch, "host9", SHA, Some(CERT_A), now),
                    Err(ProofError::Malformed(_))
                ),
                "{bad:?} must be refused as malformed"
            );
        }
    }

    /// Absence and every kind of wrong are all failures of `verify` — there
    /// is no window any more (`NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` is
    /// retired), so the route turns every one of them into a 403.
    #[test]
    fn only_a_good_proof_verifies() {
        let now = 1_757_000_000;
        assert!(verify(Some(&proof(KEY_A, Purpose::Fetch, "host9", SHA, now)),
                       Purpose::Fetch, "host9", SHA, Some(CERT_A), now).is_ok());
        let missing = verify(None, Purpose::Fetch, "host9", SHA, Some(CERT_A), now);
        let no_cert = verify(Some(&proof(KEY_A, Purpose::Fetch, "host9", SHA, now)),
                             Purpose::Fetch, "host9", SHA, None, now);
        let wrong_node = verify(Some(&proof(KEY_B, Purpose::Fetch, "host9", SHA, now)),
                                Purpose::Fetch, "host9", SHA, Some(CERT_A), now);
        let replayed = verify(Some(&proof(KEY_A, Purpose::Fetch, "host9", SHA, now - 1200)),
                              Purpose::Fetch, "host9", SHA, Some(CERT_A), now);
        let wrong_bundle = verify(Some(&proof(KEY_A, Purpose::Fetch, "host9", &"0".repeat(64), now)),
                                  Purpose::Fetch, "host9", SHA, Some(CERT_A), now);
        let garbage = verify(Some("nonsense"), Purpose::Fetch, "host9", SHA, Some(CERT_A), now);
        assert_eq!(missing, Err(ProofError::Missing));
        assert_eq!(no_cert, Err(ProofError::NoBirthCert));
        for (what, r) in [("wrong node", wrong_node), ("replay", replayed),
                          ("wrong bundle", wrong_bundle), ("garbage", garbage)] {
            assert!(r.is_err(), "{what} must not verify");
        }
    }

    /// The node signs with `openssl dgst -sha256 -sign`, not with this crate.
    /// The tests above all sign with `rsa`, so on their own they only prove
    /// this module agrees with itself — a real node could still be refused by
    /// a gateway that passes every one of them.
    ///
    /// So: a signature produced by OPENSSL, over the exact string
    /// `scripts/noo-fetch.sh` builds, committed as a fixture. Regenerate with
    ///
    /// ```sh
    /// printf 'noo-bundle-fetch:fixture-node:<sha>:<ts>' \
    ///   | openssl dgst -sha256 -sign src/fixtures/birth_node_a.testkey.pem \
    ///   | openssl base64 -A
    /// ```
    ///
    /// The node id is the neutral `fixture-node`, never a fleet host name:
    /// the public sync rewrites host names in the staged tree, and a
    /// signature over text cannot survive a rewrite of that text. The
    /// fixture is a throwaway test vector signed with the committed test key.
    #[test]
    fn an_openssl_signature_verifies() {
        let proof = include_str!("fixtures/birth_openssl_proof.txt").trim();
        let (ts, _) = proof.split_once('.').expect("fixture shape");
        let ts: i64 = ts.parse().unwrap();
        verify(Some(proof), Purpose::Fetch, "fixture-node", SHA, Some(CERT_A), ts)
            .expect("what a real node produces must verify");
        // And the fixture is not accidentally accepted by a broken verifier:
        // the same bytes against the other node's cert must fail.
        assert_eq!(
            verify(Some(proof), Purpose::Fetch, "fixture-node", SHA, Some(CERT_B), ts),
            Err(ProofError::BadSignature)
        );
    }

    /// The signed string is a WIRE FORMAT: three signers build it (this crate,
    /// `scripts/noo-fetch.sh`, `noo node fetch`). Pin it, so a change here is
    /// a change someone has to make on purpose.
    #[test]
    fn the_signed_message_is_pinned() {
        assert_eq!(
            signed_message(Purpose::Fetch, "host9", "deadbeef", 1_757_000_000),
            "noo-bundle-fetch:host9:deadbeef:1757000000"
        );
        assert_eq!(
            signed_message(Purpose::Apply, "host9", "deadbeef", 1_757_000_000),
            "noo-bundle-apply:host9:deadbeef:1757000000"
        );
        // The seat domain (i77): a different prefix, so neither side's proof
        // is ever the other's message. `noo kiosk seat-sync` builds these.
        assert_eq!(
            signed_message(Purpose::SeatHeartbeat, "lobby", "deadbeef", 1_757_000_000),
            "noo-seat-heartbeat:lobby:deadbeef:1757000000"
        );
        assert_eq!(
            signed_message(Purpose::SeatFetch, "lobby", "deadbeef", 1_757_000_000),
            "noo-seat-fetch:lobby:deadbeef:1757000000"
        );
    }

    /// A seat's proof never verifies as a node's, nor a node's as a seat's,
    /// even under one name and one key: the domain is part of the signed
    /// bytes. This is what makes a name collision between a seat and a node
    /// worthless to either.
    #[test]
    fn seat_and_node_proofs_never_cross() {
        let now = 1_757_000_000;
        for (seat, node) in [(Purpose::SeatFetch, Purpose::Fetch), (Purpose::SeatApply, Purpose::Apply)] {
            let sp = proof(KEY_A, seat, "lobby", SHA, now);
            assert_eq!(verify(Some(&sp), node, "lobby", SHA, Some(CERT_A), now), Err(ProofError::BadSignature));
            verify(Some(&sp), seat, "lobby", SHA, Some(CERT_A), now).expect("a seat proof verifies as the seat");
            let np = proof(KEY_A, node, "lobby", SHA, now);
            assert_eq!(verify(Some(&np), seat, "lobby", SHA, Some(CERT_A), now), Err(ProofError::BadSignature));
        }
    }
}
