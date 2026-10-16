// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Who may write security POSTURE.
//!
//! `POST /api/security/posture` and `/api/security/posture/profile` refuse
//! an app login by design: an app admin must not be able to weaken posture.
//! the only credential they admitted was the
//! controller's shared secret, which names no person and cannot be revoked
//! for one.
//!
//! The credential that replaces it has two halves, and BOTH are required:
//!
//! 1. an **operator client certificate** on the connection: a leaf the
//!    cluster CA issued with `O=Mesh Cluster Operator`, `CN=operator:<account>`
//!    (`noo security pki issue-client <account>`), registered with this
//!    gateway and not revoked (`noo_operator_certs`);
//! 2. an **Admin token bound to that certificate**: `cnf.x5t#S256` equal to
//!    the presented leaf's thumbprint (RFC 8705), minted by
//!    `POST /api/security/operator-token` over that same connection, for the
//!    account the certificate names.
//!
//! A browser session can hold neither: it presents no client certificate,
//! and its token carries no `cnf`. A stolen bound token is useless without
//! the key, and the key is useless without the operator's login.
//!
//! The shared secret is NOT admitted here, in any form by design (no break glass: the
//! operator sees the same login path end users do). There
//! was a `cli-break-glass` actor and a bootstrap `cli-onboard` window; both
//! are gone. A controller-secret HMAC signed by the CLI (`cli`, `cli-*`)
//! never reaches this module — the middleware refuses it on every route,
//! naming the upgrade ([`OLD_CLI_REFUSAL`]) — and any other shared-secret
//! actor that reaches a posture write is refused here.
//!
//! Recovery without the secret is the ordinary path: a lost admin password
//! is replaced on the controller host (`noo security admin-password reset`,
//! which logs in with a one-time host ticket when no login is held), and a
//! lost operator certificate is re-issued after that login
//! (`noo security pki issue-client <you>`, then `revoke-client <you>
//! --others`).

use crate::auth::Role;

/// What a `noo` CLI that still signs with the controller's shared secret is
/// told — by the middleware on every route (`auth::require_any_auth`) and
/// here on the posture writes. The CLI stopped signing with it in the
/// change that removed `--break-glass`; there is no grace path.
pub const OLD_CLI_REFUSAL: &str = "this `noo` CLI signs with the controller's shared secret, which the gateway no \
longer accepts from the CLI (no break-glass, no onboard bootstrap). Upgrade the CLI and the stack \
together: noo upgrade --all — then log in (`noo auth login`); posture writes take your operator \
certificate (`noo security pki issue-client <you>`)";

/// The upgrade command [`OLD_CLI_REFUSAL`] names, as its own field for a
/// client that renders hints.
pub const OLD_CLI_UPGRADE: &str = "noo upgrade --all";

/// Is this HMAC actor the `noo` CLI? Every actor the CLI ever signed with:
/// a bare `cli` (before the actor split), `cli-posture`
/// `cli-onboard` and `cli-break-glass` (before
/// their removal). A claim, not a proof — but the CLI is the only caller
/// that ever used these names, so refusing them refuses the CLI and
/// nothing else.
pub fn is_cli_actor(actor: &str) -> bool {
    actor == "cli" || actor.starts_with("cli-")
}

/// How long an operator's bound token lives. The CLI mints one per
/// posture command; five minutes covers a slow `apply-profile`.
pub const OPERATOR_TOKEN_TTL_SECS: u64 = 300;

/// The credential a posture write arrived with, as the middleware left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureCred<'a> {
    /// A JWT. `bound` is the thumbprint its `cnf` named, present only when
    /// the middleware verified the binding held (`auth::CertBoundToken`).
    Jwt { sub: &'a str, role: Role, bound: Option<&'a str> },
    /// A controller-secret HMAC (`ClusterKind::Internal`), by actor. Never
    /// admitted on a posture write.
    SharedSecret { actor: &'a str },
    /// Nothing the middleware recognised (cannot reach a handler today).
    None,
}

/// The certificate on the connection, as the TLS acceptor verified it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnCert<'a> {
    /// `x5t#S256` of the presented leaf.
    pub thumbprint: Option<&'a str>,
    /// The account an operator leaf names (`node_identity::VerifiedOperator`).
    pub operator: Option<&'a str>,
}

/// What the registry says about the presented thumbprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Registered to this account and not revoked.
    Active,
    /// Registered and revoked.
    Revoked,
    /// Never registered.
    Unknown,
}

/// Why a posture write was admitted: there is one way, and it names the
/// operator the audit row blames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Operator certificate + bound Admin token.
    Operator { account: String, thumbprint: String },
}

impl Admission {
    /// The `actor` of the audit row.
    pub fn audit_actor(&self) -> String {
        match self {
            Admission::Operator { account, .. } => format!("operator:{account}"),
        }
    }
}

/// The posture-write decision. Pure: the handler gathers the facts
/// (extensions + two registry reads) and this says yes or why not.
///
/// `registration` is about `conn.thumbprint` FOR `conn.operator`.
pub fn admit_posture_write(
    cred: &PostureCred<'_>,
    conn: ConnCert<'_>,
    registration: Registration,
) -> Result<Admission, String> {
    match cred {
        PostureCred::Jwt { sub, role, bound } => {
            let Some(operator) = conn.operator else {
                return Err(
                    "security posture is operator-only: a login alone is refused, so an app admin \
                     cannot weaken posture. Present your operator client certificate with a token \
                     bound to it — `noo security posture …` does this once `noo security pki \
                     issue-client <you>` has run"
                        .into(),
                );
            };
            let Some(tp) = conn.thumbprint else {
                return Err("no client certificate thumbprint on this connection".into());
            };
            let Some(bound) = bound else {
                return Err(
                    "this token is not bound to your operator certificate — mint one with \
                     POST /api/security/operator-token over the same connection (the CLI does)"
                        .into(),
                );
            };
            if *bound != tp {
                // The middleware already refuses a mismatched binding; this
                // is the second wall, so a change there cannot open this.
                return Err("the token is bound to a different certificate".into());
            }
            if *role != Role::Admin {
                return Err(format!("posture writes need an Admin account; '{sub}' is {}", role.as_str()));
            }
            if operator != *sub {
                return Err(format!(
                    "the certificate names operator '{operator}' but the token is for '{sub}'"
                ));
            }
            match registration {
                Registration::Active => Ok(Admission::Operator {
                    account: (*sub).to_string(),
                    thumbprint: tp.to_string(),
                }),
                Registration::Revoked => Err(format!(
                    "operator certificate {} for '{operator}' is REVOKED — issue a new one: \
                     noo security pki issue-client {operator}",
                    short(tp)
                )),
                Registration::Unknown => Err(format!(
                    "operator certificate {} for '{operator}' is not registered with this gateway — \
                     noo security pki issue-client {operator} registers it",
                    short(tp)
                )),
            }
        }
        // No shared secret writes posture: not as break-glass, not before
        // the first operator certificate. The CLI's own actors are refused
        // by the middleware before they get here; this is the second wall.
        PostureCred::SharedSecret { actor } if is_cli_actor(actor) => Err(OLD_CLI_REFUSAL.to_string()),
        PostureCred::SharedSecret { actor } => Err(format!(
            "security posture is operator-only: the shared secret ('{actor}') does not write it. \
             Present your operator client certificate with a token bound to it \
             (`noo security pki issue-client <you>`)"
        )),
        PostureCred::None => Err("no credential".into()),
    }
}

/// The certificate-registration decision (`POST
/// /api/security/operator-certs/register`): the presented operator leaf is
/// registered for the account it names, by that account's own Admin login.
/// The CA's signature (checked at the handshake) is what proves the leaf
/// was issued on the controller; the login is what proves the person.
pub fn admit_registration(sub: &str, role: Role, conn: ConnCert<'_>, registration: Registration) -> Result<(), String> {
    let Some(operator) = conn.operator else {
        return Err(
            "present the operator client certificate you are registering (no operator leaf on this \
             connection — the gateway reads client certificates unless NOO_MTLS_GATEWAY=false switched mTLS off)"
                .into(),
        );
    };
    if conn.thumbprint.is_none() {
        return Err("no client certificate thumbprint on this connection".into());
    }
    if role != Role::Admin {
        return Err(format!("registering an operator certificate needs an Admin account; '{sub}' is {}", role.as_str()));
    }
    if operator != sub {
        return Err(format!("the certificate names operator '{operator}', but you are logged in as '{sub}'"));
    }
    if registration == Registration::Revoked {
        return Err("this certificate was revoked and cannot be registered again — issue a new one".into());
    }
    Ok(())
}

/// The bound-token mint decision (`POST /api/security/operator-token`):
/// a registered, live operator leaf on the connection and the Admin login
/// of the account it names. The token minted is bound to that leaf.
pub fn admit_token_mint(sub: &str, role: Role, conn: ConnCert<'_>, registration: Registration) -> Result<String, String> {
    admit_registration(sub, role, conn, registration)?;
    match registration {
        Registration::Active => Ok(conn.thumbprint.unwrap_or_default().to_string()),
        Registration::Revoked => Err("this operator certificate is revoked".into()),
        Registration::Unknown => Err(
            "this operator certificate is not registered — noo security pki issue-client <you> registers it".into(),
        ),
    }
}

fn short(tp: &str) -> String {
    tp.chars().take(12).collect()
}

/// The registry's answer for one thumbprint and account.
pub async fn registration_of(db: &sqlx::PgPool, thumbprint: &str, account: &str) -> Result<Registration, sqlx::Error> {
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT operator, revoked_at IS NOT NULL FROM noo_operator_certs WHERE thumbprint = $1",
    )
    .bind(thumbprint)
    .fetch_optional(db)
    .await?;
    Ok(match row {
        None => Registration::Unknown,
        // Registered to someone else: not this account's certificate.
        Some((op, _)) if op != account => Registration::Unknown,
        Some((_, true)) => Registration::Revoked,
        Some((_, false)) => Registration::Active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TP: &str = "tp-alice";
    fn cert() -> ConnCert<'static> {
        ConnCert { thumbprint: Some(TP), operator: Some("alice") }
    }
    fn admin_bound(b: Option<&'static str>) -> PostureCred<'static> {
        PostureCred::Jwt { sub: "alice", role: Role::Admin, bound: b }
    }

    #[test]
    fn cert_plus_bound_admin_token_is_accepted() {
        let a = admit_posture_write(&admin_bound(Some(TP)), cert(), Registration::Active).unwrap();
        assert_eq!(a, Admission::Operator { account: "alice".into(), thumbprint: TP.into() });
        assert_eq!(a.audit_actor(), "operator:alice");
    }

    #[test]
    fn a_jwt_alone_is_refused() {
        // The rule the route always had: no certificate, no posture write,
        // whatever the token says — bound or not, Admin or not.
        for b in [None, Some(TP)] {
            let e = admit_posture_write(&admin_bound(b), ConnCert::default(), Registration::Unknown).unwrap_err();
            assert!(e.contains("operator-only"), "{e}");
        }
    }

    #[test]
    fn a_cert_with_an_unbound_token_is_refused() {
        // The operator's ordinary login over the operator's certificate is
        // still not enough: the token must be bound to the leaf.
        let e = admit_posture_write(&admin_bound(None), cert(), Registration::Active).unwrap_err();
        assert!(e.contains("not bound"), "{e}");
    }

    #[test]
    fn a_cert_alone_is_refused() {
        // A certificate with the shared secret as the bearer is the HMAC
        // path, judged by the HMAC rule; with no credential, nothing.
        assert!(admit_posture_write(&PostureCred::None, cert(), Registration::Active).is_err());
        let e = admit_posture_write(&PostureCred::SharedSecret { actor: "cli-posture" }, cert(), Registration::Active)
            .unwrap_err();
        assert!(e.contains("noo upgrade --all"), "{e}");
    }

    #[test]
    fn a_token_bound_to_a_different_cert_is_refused() {
        let e = admit_posture_write(&admin_bound(Some("tp-mallory")), cert(), Registration::Active).unwrap_err();
        assert!(e.contains("different certificate"), "{e}");
    }

    #[test]
    fn the_certificate_and_the_token_must_name_the_same_admin() {
        let bob = PostureCred::Jwt { sub: "bob", role: Role::Admin, bound: Some(TP) };
        assert!(admit_posture_write(&bob, cert(), Registration::Active).unwrap_err().contains("'alice'"));
        let op = PostureCred::Jwt { sub: "alice", role: Role::Operator, bound: Some(TP) };
        assert!(admit_posture_write(&op, cert(), Registration::Active).unwrap_err().contains("Admin"));
    }

    #[test]
    fn a_revoked_or_unregistered_cert_is_refused() {
        let e = admit_posture_write(&admin_bound(Some(TP)), cert(), Registration::Revoked).unwrap_err();
        assert!(e.contains("REVOKED"), "{e}");
        let e = admit_posture_write(&admin_bound(Some(TP)), cert(), Registration::Unknown).unwrap_err();
        assert!(e.contains("not registered"), "{e}");
    }

    /// By design there is no break-glass and no onboard bootstrap.
    /// The shared secret never writes posture — not before the first
    /// operator certificate, not as `cli-break-glass`, not as anything.
    #[test]
    fn the_shared_secret_never_writes_posture() {
        for actor in ["cli", "cli-posture", "cli-onboard", "cli-break-glass"] {
            for reg in [Registration::Unknown, Registration::Active] {
                for conn in [ConnCert::default(), cert()] {
                    let e = admit_posture_write(&PostureCred::SharedSecret { actor }, conn, reg).unwrap_err();
                    assert!(e.contains("noo upgrade --all"), "{actor}: an old CLI is told to upgrade: {e}");
                    assert!(!e.contains("--break-glass"), "no refusal may point at a removed flag: {e}");
                }
            }
        }
        // A non-CLI holder of the secret (an add-on on its fallback) is
        // refused too, and told what the operator path is.
        let e = admit_posture_write(&PostureCred::SharedSecret { actor: "trellion" }, ConnCert::default(), Registration::Unknown)
            .unwrap_err();
        assert!(e.contains("operator-only") && e.contains("issue-client"), "{e}");
    }

    #[test]
    fn every_actor_the_cli_ever_signed_with_is_a_cli_actor() {
        for a in ["cli", "cli-posture", "cli-onboard", "cli-break-glass", "cli-anything"] {
            assert!(is_cli_actor(a), "{a}");
        }
        for a in ["trellion", "pai-evolve", "gateway", "client", "clinic", "", "heartbeat"] {
            assert!(!is_cli_actor(a), "{a}");
        }
    }

    #[test]
    fn registration_needs_the_named_admin_and_a_live_cert() {
        assert!(admit_registration("alice", Role::Admin, cert(), Registration::Unknown).is_ok());
        assert!(admit_registration("alice", Role::Admin, cert(), Registration::Active).is_ok(), "idempotent");
        assert!(admit_registration("alice", Role::Admin, cert(), Registration::Revoked).is_err(), "revoked stays revoked");
        assert!(admit_registration("bob", Role::Admin, cert(), Registration::Unknown).is_err());
        assert!(admit_registration("alice", Role::Operator, cert(), Registration::Unknown).is_err());
        assert!(admit_registration("alice", Role::Admin, ConnCert::default(), Registration::Unknown).is_err());
    }

    #[test]
    fn the_mint_binds_to_the_presented_registered_cert_only() {
        assert_eq!(admit_token_mint("alice", Role::Admin, cert(), Registration::Active).unwrap(), TP);
        assert!(admit_token_mint("alice", Role::Admin, cert(), Registration::Unknown).is_err());
        assert!(admit_token_mint("alice", Role::Admin, cert(), Registration::Revoked).is_err());
        assert!(admit_token_mint("alice", Role::Admin, ConnCert::default(), Registration::Active).is_err());
    }
}
