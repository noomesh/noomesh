// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The add-on delegated token (ADT): how an add-on acts for a PRESENT person
//! through tasks (i143).
//!
//! The add-on proxy mints one per proxied request that opts in
//! (`receives_delegation` on the route, the manifest's `delegate: "tasks"`, and
//! the operator's switch) and SETS it in [`HEADER`]. The add-on keeps it in
//! memory for the request and presents it back to this gateway to create and
//! steer tasks for that person.
//!
//! * `sub` — the ACCOUNT (`account_of`); `role`, `scopes` — as the gateway
//!   resolved them for the request, nothing the add-on chose;
//! * `iss`/`aud` — this gateway's, so the ordinary verifier
//!   (`auth::verify_token`) accepts it; there is no second verifier;
//! * `act: {sub: "addon:<name>"}` — RFC 8693. Because it carries `act`, the
//!   auth layer re-checks the account on every request (a disabled account is
//!   refused within the cache bound);
//! * `jti` — unique per mint; `exp` — [`TTL_SECS`], so the add-on's authority
//!   tracks the person's presence: five minutes after the last proxied
//!   request it can start nothing new.
//!
//! The claims carry no `conn` (the connection): `auth::Claims` has no field
//! for it, and nothing downstream needs it, since ownership is the account.
//!
//! It is a bearer, so it is NEVER persisted or logged. The auth layer confines
//! it ([`confine`]) to the task routes in [`route_allowed`], requires the
//! add-on to be registered with delegation on, and holds the token's role to
//! the account's live role. Handlers see an [`AddonDelegation`] extension and
//! then show the token only the tasks its own add-on created for that person.

use axum::http::StatusCode;
use serde_json::{json, Value};

use crate::auth::{Claims, RequesterCtx};

/// Prefix of the actor an add-on delegated token names (`addon:<name>`). Also
/// the `created_via` a task it creates records.
pub const ACTOR_PREFIX: &str = "addon:";

/// The header the proxy sets on the upstream request. A client's copy is never
/// forwarded: the upstream request is built from nothing.
pub const HEADER: &str = "x-noo-delegation";

/// How long one lives. Five minutes is the design's ceiling; a longer one
/// fails the build.
pub const TTL_SECS: u64 = 300;
const _: () = assert!(TTL_SECS <= 300);

/// Inserted by the auth layer on a request carrying a valid ADT: which add-on
/// is acting. Handlers key their isolation on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddonDelegation {
    pub addon: String,
}

impl AddonDelegation {
    /// What a task this add-on creates records in `created_via`.
    pub fn via(&self) -> String {
        format!("{ACTOR_PREFIX}{}", self.addon)
    }
}

/// The add-on an ADT names, or `None` for any other token.
pub fn addon_of(claims: &Claims) -> Option<&str> {
    claims.act.as_ref().and_then(|a| a.sub.strip_prefix(ACTOR_PREFIX)).filter(|n| !n.is_empty())
}

/// The claims, unsigned. `None` when the secret is insecure (the same
/// judgement every mint makes, in `auth::scoped_claims`).
///
/// `feature`: the add-on feature of the route the token was minted for, in a
/// manifest with features (f99). The auth layer holds every use to it.
pub(crate) fn claims(requester: &RequesterCtx, addon: &str, feature: Option<&str>, secret: &str) -> Option<Value> {
    let mut c = crate::auth::scoped_claims(crate::auth::account_of(&requester.sub), requester.role.as_str(), &requester.scopes, TTL_SECS, secret)?;
    c["act"] = json!({ "sub": format!("{ACTOR_PREFIX}{addon}") });
    if let Some(f) = feature {
        c["act"]["feature"] = json!(f);
    }
    c["jti"] = json!(uuid::Uuid::new_v4().to_string());
    Some(c)
}

/// [`mint`] with the keys passed in (tests).
pub(crate) fn mint_with(
    requester: &RequesterCtx,
    addon: &str,
    feature: Option<&str>,
    secret: &str,
    signing: Option<&crate::jwks::SigningKey>,
) -> Option<String> {
    crate::worker_delegation::sign(&claims(requester, addon, feature, secret)?, secret, signing)
}

/// Mint for one proxied request with the gateway's own keys: ES256 under
/// `NOO_JWT_SIGNING_KEY` when configured, HS256 otherwise. `None` when the
/// gateway has no usable secret; the add-on then gets no token and fails
/// closed.
pub fn mint(requester: &RequesterCtx, addon: &str, feature: Option<&str>) -> Option<String> {
    let secret = crate::auth::configured_jwt_secret()?;
    mint_with(requester, addon, feature, &secret, crate::jwks::signing_key())
}

/// Does a token minted under `feature` still act for `account` (f99)? A
/// manifest without features: nothing to hold (`Ok`). With features: the
/// token must name one, and the account (at its `live` role) must still
/// hold it, so turning the feature off stops the add-on at the next call.
pub(crate) fn feature_still_held(
    has_features: bool,
    feature: Option<&str>,
    addon: &str,
    account: &str,
    live: Option<crate::auth::Role>,
) -> Result<(), String> {
    if !has_features {
        return Ok(());
    }
    let Some(feature) = feature else {
        return Err("the token names no feature, and the add-on declares features".into());
    };
    let Some(role) = live else {
        return Err("the account is disabled or absent".into());
    };
    let d = crate::addon_access::feature_allows(addon, feature, account, role);
    if d.allowed {
        Ok(())
    } else {
        Err(format!("feature {feature:?} is off for {account} ({})", d.decided_by))
    }
}

/// Every `(METHOD, path template)` an ADT may call. Nothing else: not
/// `resubmit` (it spends the owner's tokens), not `/mcp/*`, not the harness
/// rail, not the identity or service-key routes, not an add-on's routes.
const ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/tasks"),
    ("GET", "/api/tasks"),
    ("GET", "/api/tasks/{id}"),
    ("POST", "/api/tasks/{id}/stop"),
    ("POST", "/api/tasks/{id}/ask"),
    ("POST", "/api/tasks/{id}/answer"),
    ("POST", "/api/tasks/{id}/context"),
    ("GET", "/api/tasks/{id}/events"),
    ("POST", "/api/tasks/stop"),
];

/// May an ADT be used for `method path`?
pub fn route_allowed(method: &str, path: &str) -> bool {
    ROUTES
        .iter()
        .any(|(m, t)| m.eq_ignore_ascii_case(method) && crate::worker_delegation::template_matches(t, path))
}

/// The auth layer's rule: an ADT off [`route_allowed`] is refused (403). Any
/// other token is unaffected.
pub fn confine(claims: &Claims, method: &str, path: &str) -> Result<(), StatusCode> {
    let Some(addon) = addon_of(claims) else { return Ok(()) };
    if route_allowed(method, path) {
        return Ok(());
    }
    tracing::warn!(sub = %claims.sub, addon, method, path, "add-on delegated token refused: not a task route");
    Err(StatusCode::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{verify_token_with, Role};

    /// f99: the token names the feature of the route it was minted for, and
    /// only when there is one; it parses back into `Actor::feature`.
    #[test]
    fn a_token_carries_its_feature_only_when_minted_under_one() {
        let c = claims(&alice(), "voice", Some("converse"), SECRET).expect("claims");
        assert_eq!(c["act"]["feature"], "converse");
        assert_eq!(c["act"]["sub"], "addon:voice");
        let plain = claims(&alice(), "voice", None, SECRET).expect("claims");
        assert!(plain["act"].get("feature").is_none(), "{plain}");
        let tok = mint_with(&alice(), "voice", Some("converse"), SECRET, None).unwrap();
        let back = verify_token_with(&tok, SECRET, None).expect("verifies");
        assert_eq!(back.act.and_then(|a| a.feature).as_deref(), Some("converse"));
    }

    /// The rule the auth layer applies on every use.
    #[test]
    fn a_features_addon_token_must_name_a_feature_the_account_still_holds() {
        assert_eq!(feature_still_held(false, None, "voice", "alice", Some(Role::User)), Ok(()), "no features: nothing to hold");
        assert!(feature_still_held(true, None, "voice", "alice", Some(Role::User)).unwrap_err().contains("names no feature"));
        assert!(feature_still_held(true, Some("converse"), "voice", "alice", None).unwrap_err().contains("disabled"));
        // The unit tests never load the settings, so a feature is refused
        // (fail closed): the token stops acting.
        let e = feature_still_held(true, Some("converse"), "voice", "alice", Some(Role::Admin)).unwrap_err();
        assert!(e.contains("\"converse\" is off for alice") && e.contains("not loaded"), "{e}");
    }

    const SECRET: &str = "addon-delegation-test-secret-not-a-real-one";

    fn alice() -> RequesterCtx {
        RequesterCtx {
            sub: "alice/laptop".into(),
            scopes: vec!["read".into()],
            role: Role::User,
            harness: None,
            act: None,
        }
    }

    fn es256() -> crate::jwks::SigningKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        crate::jwks::parse(&kp.serialize_pem()).expect("a generated P-256 key parses")
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn the_allowlist_is_exactly_the_task_routes() {
        let id = "3f1c2d4e-0000-4000-8000-000000000000";
        for (m, p) in [
            ("POST", "/api/tasks".to_string()),
            ("GET", "/api/tasks".to_string()),
            ("GET", format!("/api/tasks/{id}")),
            ("POST", format!("/api/tasks/{id}/stop")),
            ("POST", format!("/api/tasks/{id}/ask")),
            ("POST", format!("/api/tasks/{id}/answer")),
            ("POST", format!("/api/tasks/{id}/context")),
            ("GET", format!("/api/tasks/{id}/events")),
            ("POST", "/api/tasks/stop".to_string()),
            ("post", "/api/tasks".to_string()),
        ] {
            assert!(route_allowed(m, &p), "{m} {p}");
        }
        for (m, p) in [
            ("POST", "/api/tasks/".to_string()),
            ("DELETE", "/api/tasks".to_string()),
            ("PUT", format!("/api/tasks/{id}")),
            ("GET", format!("/api/tasks/{id}/stop")),
            ("POST", format!("/api/tasks/{id}/resubmit")),
            ("POST", format!("/api/tasks/{id}/events")),
            ("POST", format!("/api/tasks/{id}/extra/more")),
            ("POST", "/mcp/user".to_string()),
            ("GET", "/mcp/user".to_string()),
            ("POST", "/api/harness/call".to_string()),
            ("GET", "/api/security/service-keys/self".to_string()),
            ("POST", "/api/security/service-keys/self".to_string()),
            ("POST", "/api/identity/token".to_string()),
            ("POST", "/api/addon/token".to_string()),
            ("GET", "/api/addons/some/route".to_string()),
            ("POST", "/api/some-addon/notes".to_string()),
            ("GET", "/api/jobs".to_string()),
        ] {
            assert!(!route_allowed(m, &p), "{m} {p} must be refused");
        }
    }

    #[test]
    fn mint_then_verify_names_the_addon_and_expires_within_five_minutes() {
        let key = es256();
        let tok = mint_with(&alice(), "voice", None, SECRET, Some(&key)).expect("mints");
        assert_eq!(jsonwebtoken::decode_header(&tok).unwrap().alg, jsonwebtoken::Algorithm::ES256);
        let claims = verify_token_with(&tok, SECRET, Some(&key)).expect("the ordinary verifier accepts it");
        assert_eq!(addon_of(&claims), Some("voice"));
        assert_eq!(claims.sub, "alice", "the account, not the connection");
        assert_eq!(claims.resolved_role(), Role::User);
        assert!((claims.exp as u64) <= now() + TTL_SECS);
        assert!(claims.harness.is_none() && claims.conv.is_none());

        // Two mints are two tokens.
        let again = mint_with(&alice(), "voice", None, SECRET, Some(&key)).unwrap();
        assert_ne!(tok, again);
    }

    #[test]
    fn without_a_signing_key_it_is_hs256_and_an_insecure_secret_mints_nothing() {
        let tok = mint_with(&alice(), "voice", None, SECRET, None).unwrap();
        assert_eq!(jsonwebtoken::decode_header(&tok).unwrap().alg, jsonwebtoken::Algorithm::HS256);
        assert!(verify_token_with(&tok, SECRET, None).is_ok());
        assert!(mint_with(&alice(), "voice", None, crate::auth::INSECURE_DEFAULT_JWT_SECRET, None).is_none());
    }

    #[test]
    fn only_an_addon_actor_is_an_adt() {
        let tok = mint_with(&alice(), "voice", None, SECRET, None).unwrap();
        let mut claims = verify_token_with(&tok, SECRET, None).unwrap();
        assert_eq!(confine(&claims, "POST", "/api/tasks"), Ok(()));
        assert_eq!(confine(&claims, "POST", "/mcp/user"), Err(StatusCode::FORBIDDEN));
        assert_eq!(confine(&claims, "POST", "/api/tasks/x/resubmit"), Err(StatusCode::FORBIDDEN));
        // A worker-delegated or ordinary token is none of this module's business.
        claims.act = Some(crate::auth::Actor { sub: "svc:worker".into(), iss_user: None, task: None, feature: None });
        assert_eq!(addon_of(&claims), None);
        assert_eq!(confine(&claims, "POST", "/mcp/user"), Ok(()));
        claims.act = Some(crate::auth::Actor { sub: ACTOR_PREFIX.into(), iss_user: None, task: None, feature: None });
        assert_eq!(addon_of(&claims), None, "an empty add-on name is no add-on");
        claims.act = None;
        assert_eq!(confine(&claims, "POST", "/mcp/user"), Ok(()));
    }

    #[test]
    fn the_extension_names_the_via_a_task_records() {
        assert_eq!(AddonDelegation { addon: "voice".into() }.via(), "addon:voice");
    }
}
