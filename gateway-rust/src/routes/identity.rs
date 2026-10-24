// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `/api/identity/*` — the agent identity exchange.
//!
//! One provisioning credential in, a short-lived token for one account out.
//!
//! ## The problem it replaces
//!
//! An integrator running a hundred agent personas against this mesh has had
//! two options, and both are bad at that scale. Mint a long-lived bound
//! service key per persona and you are storing a hundred standing
//! credentials and rotating them forever. Share one key and pass the persona
//! in the request body and you have a shared secret that can name any
//! subject — which is precisely the "unattributed operator" the service-key
//! module refuses to become (`service_keys.rs`, `Consumer::user`), and why
//! [`crate::routes::inference::bind_identity`] drops a `user_id` delegated
//! by an unbound key.
//!
//! The exchange is the third option: one provisioning key, and a token per
//! turn that expires on its own.
//!
//! ## The shape (RFC 8693)
//!
//! This is OAuth 2.0 Token Exchange in its administrative-issuance profile.
//! The provisioning key is the **actor**, presented as the bearer. The
//! **subject** is a mesh account named by `subject_token`, with the
//! noomesh-defined token type [`SUBJECT_TOKEN_TYPE_ACCOUNT`] — RFC 8693
//! types are URIs precisely so a deployment can define its own, and "the
//! subject does not present a credential, the issuer asserts it" is a case
//! the RFC covers.
//!
//! What comes back is an ordinary user JWT for that account, so every
//! downstream handler, scope check and usage row treats it as that person.
//! **There is no new trust class.** That is the design's whole economy: the
//! JWT branch of the auth middleware already does the right thing, and the
//! only addition to the credential is a signed `act` claim (RFC 8693
//! naming the key and the account behind it.
//!
//! ## What holds it closed
//!
//! Five independent barriers, in the order they run:
//!
//! 1. the add-on gate — licensed feature, off by default ([`crate::addons`]);
//! 2. the door — the middleware admits an `identity`-scoped key on this one
//!    path and no other, so no other credential class reaches the handler
//!    ([`crate::auth::exchange_scope_for`]);
//! 3. the binding — an unbound machine key is refused, at issue time and
//!    again here, because a credential with no account behind it has no
//!    tier to clamp against;
//! 4. `may_manage` — the same clamp that governs password resets: the bound
//!    account may not mint for an account at or above its own tier;
//! 5. the role clamp — the minted token carries the LOWER of the subject's
//!    live tier and the issuer's, so a permitted pairing still cannot hand
//!    out more than the issuer holds.
//!
//! Barriers 4 and 5 overlap deliberately. 4 decides whether the mint may
//! happen; 5 decides what it is worth if the tier table changes under it.
//!
//! ## What it does not do
//!
//! A minted token cannot be *recalled* — nothing hands it back. But it is
//! not unstoppable either: because it carries `act`, the auth layer
//! re-checks the subject account on every request it makes
//! ([`crate::auth::delegated_subject_enabled`], 10s cache), so disabling
//! the account kills tokens already in flight, not merely the next mint.
//! Revoking the provisioning key stops all future mints. Together those
//! are the kill switch, and
//! `POST /api/security/service-keys/{consumer}/revoke-and-disable` does
//! both in one transaction.
//!
//! That per-request check is deliberately scoped to delegated tokens. An
//! ordinary user JWT stays stateless, which is the property that keeps
//! login cheap; an exchanged token is minted on demand for an account
//! somebody else controls, and has to be answerable to it.

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::Role;
use crate::service_keys::Consumer;
use crate::state::AppState;

use super::{AppError, AppResult};

/// RFC 8693 grant type. Accepted verbatim; also accepted absent, because a
/// single-purpose endpoint naming its own grant adds nothing.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The token type of what comes back.
pub const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

/// noomesh's own subject-token type: the `subject_token` is a mesh account
/// name, asserted by the issuer rather than presented by the subject.
///
/// A local URI rather than a reused IANA one on purpose. Calling a bare
/// username an `id_token` or an `access_token` would be a lie in a field
/// whose entire job is to say what the bytes are.
pub const SUBJECT_TOKEN_TYPE_ACCOUNT: &str = "urn:noomesh:params:oauth:token-type:account";

/// Every subject-token type this exchange accepts.
///
/// A table rather than a literal because a second type is already
/// foreseen: the design wants a CONNECTION subject
/// (`sub = "<owner>/<connection>"`), entitled by owning the prefix rather
/// than by `may_manage` over an account. The barriers and the mint are
/// the same; only "who may name this subject" differs, which is one
/// function.
///
/// Adding a type means adding a row here AND an arm wherever entitlement
/// is decided — never a row alone. The two are separate on purpose: a new
/// subject type that inherits the account rule by default would be a
/// silent authorization change.
/// A CONNECTION subject: one live session of an account
/// (`owner/laptop`). Entitled by the issuer
/// OWNING the name — `auth::owns_name` — and explicitly **not** by
/// `may_manage`, which asks a different question.
pub const SUBJECT_TOKEN_TYPE_CONNECTION: &str = "urn:noomesh:params:oauth:token-type:connection";

pub const SUBJECT_TOKEN_TYPES: &[&str] =
    &[SUBJECT_TOKEN_TYPE_ACCOUNT, SUBJECT_TOKEN_TYPE_CONNECTION];

/// Which kind of subject an exchange is for. The entitlement rule differs
/// per kind and that is the whole reason this is an enum rather than a
/// string compared in two places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Account,
    Connection,
}

/// Resolve the requested subject type. Absent means the account type,
/// which is what every caller predating the design sends.
fn subject_kind(token_type: Option<&str>) -> Result<SubjectKind, AppError> {
    match token_type.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(SubjectKind::Account),
        Some(t) if t == SUBJECT_TOKEN_TYPE_ACCOUNT => Ok(SubjectKind::Account),
        Some(t) if t == SUBJECT_TOKEN_TYPE_CONNECTION => Ok(SubjectKind::Connection),
        Some(t) => Err(AppError::BadRequest(format!(
            "unsupported subject_token_type '{t}' — this exchange accepts {SUBJECT_TOKEN_TYPES:?}"
        ))),
    }
}

/// A CONNECTION subject is `<issuer>/<label>`, and the issuer must own it.
///
/// The entitlement rule for this kind, kept deliberately separate from the
/// account kind's `may_manage`. `owns_name` asks "is this name mine";
/// `may_manage` asks "may I act for someone else". A connection type that
/// inherited the second would be an authorization change disguised as a
/// list edit.
///
/// **A connection credential may not mint another connection.** A
/// connection is a LEAF. Without this, `owner/laptop` could present
/// itself and ask for `owner/claude-s1` — a sibling it may not act as, it
/// could nonetheless become, and the asymmetry in `owns_name` would have
/// been defeated one layer below the predicate while the predicate stayed
/// correct. A client that needs another connection re-authenticates with
/// the provisioning credential, which is the only thing that credential is
/// for.
///
/// Today this is belt-and-braces: the exchange is reachable only with an
/// `identity`-scoped service key, whose bound `user_id` is a `noo_users`
/// username, and migration 072 forbids `/` there — so the issuer cannot be
/// compound. That is three facts in a chain, each true for its own reason,
/// and "inert given an invariant nothing states here" is precisely the
/// reasoning that has been wrong twice in this file. The check is written
/// down.
fn connection_subject<'a>(subject: &'a str, issuer: &str) -> Result<&'a str, AppError> {
    if issuer.contains(crate::auth::CONNECTION_SEP) {
        return Err(AppError::Forbidden(format!(
            "'{issuer}' is a connection, and a connection may not mint another —              re-authenticate with the provisioning credential"
        )));
    }
    let Some((owner, label)) = subject.split_once(crate::auth::CONNECTION_SEP) else {
        return Err(AppError::BadRequest(format!(
            "'{subject}' is not a connection name — expected '<account>{}<label>'",
            crate::auth::CONNECTION_SEP
        )));
    };
    // BOTH halves obey the same character class. The account half was
    // already constrained twice; leaving the label half at "non-empty"
    // would mean `owner/ session`, a trailing non-breaking space and a
    // Cyrillic lookalike each mint a distinct identity from the name they
    // resemble — and connection names are precisely what a trust list and
    // a presence registry will name.
    if !crate::auth::valid_name_segment(owner) || !crate::auth::valid_name_segment(label) {
        return Err(AppError::BadRequest(format!(
            "'{subject}' is not a connection name — expected '<account>{}<label>', each \
             1-128 characters of [A-Za-z0-9._-]",
            crate::auth::CONNECTION_SEP
        )));
    }
    // A minted connection must also be a usable AGENT ID, because that is
    // what it will be the moment it sends a message: `Envelope::validate`
    // runs `agent_messages::check_id` on `from` and `to`.
    //
    // The two rules are not the same and cannot be made the same.
    // `valid_name_segment` allows `.` because usernames always have
    // (`first.last`); `is_valid_id` forbids it because `/` maps to `.` to
    // build the NATS subject, and permitting both would make that mapping
    // ambiguous — `owner/my.laptop` and `owner/my/laptop` would land on one
    // subject, and the injectivity that keeps two agents out of each
    // other's inbox would be gone.
    //
    // So the connection name takes the INTERSECTION: valid segments AND a
    // valid id. Minting an identity that cannot send a message would be a
    // credential that works right up until it is used.
    crate::agent_messages::check_id("subject_token", subject).map_err(AppError::BadRequest)?;
    if !crate::auth::owns_name(issuer, subject) {
        return Err(AppError::Forbidden(format!(
            "'{issuer}' does not own '{subject}' — a connection is minted under its own account"
        )));
    }
    Ok(subject)
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Literal, not `auth::IDENTITY_TOKEN_PATH`: the OpenAPI generator
        // reads route strings. `identity_door_path_matches_route` pins the
        // two equal, the same way the kiosk door is pinned.
        .route("/api/identity/token", post(token))
        // RFC 8414 metadata. Public — `/.well-known/` is in
        // `auth::PUBLIC_PATH_PREFIXES` — and that is the point: a client
        // reads it BEFORE it holds a credential, which is what discovery
        // is for.
        .route("/.well-known/oauth-authorization-server", get(metadata))
        // The public key set. Served whenever the add-on is on, even with
        // no key configured — then it is an empty `keys` array, which is a
        // valid JWKS meaning "this issuer publishes none". A 404 would be
        // indistinguishable from a misrouted request.
        // Literal, not `jwks::JWKS_PATH`: the OpenAPI generator reads
        // route strings, and a constant here is invisible to it — the
        // path lands in the spec as a "phantom" with no route. Same rule
        // as the two above; `the_jwks_path_matches_the_route` pins them
        // equal.
        .route("/.well-known/jwks.json", get(jwks))
}

/// `GET /.well-known/jwks.json` — the public half of the exchange's
/// signing key.
///
/// Public by definition: a verifier fetches this before it holds any
/// credential, and everything in it is safe to hand to anyone. Gated on
/// the add-on for the same reason discovery is — an install without the
/// exchange has no keys to talk about.
async fn jwks() -> Response {
    if !crate::addons::identity_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(crate::jwks::jwks_document()).into_response()
}

/// `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
///
/// **404 when the add-on is off**, rather than a document describing a door
/// that is not there. Discovery answers "does this exist"; a 503 would say
/// "it exists and is unwell", which is a different and wrong answer, and an
/// install that never bought the add-on should not advertise it at all.
///
/// The `issuer` is derived from the request's `Host`, because a self-hosted
/// controller does not know its own external name — it sits behind a
/// tailnet name, a reverse proxy, or both. Only the host is reflected,
/// never a path or a query, so the worst a forged `Host` produces is a
/// document the forger sent to themselves.
async fn metadata(uri: axum::http::Uri, headers: HeaderMap) -> Response {
    if !crate::addons::identity_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = issuer_from(&uri, &headers);
    Json(json!({
        "issuer": base,
        "token_endpoint": format!("{base}{}", crate::auth::IDENTITY_TOKEN_PATH),
        "grant_types_supported": [GRANT_TYPE],
        // RFC 8414 requires the field. Empty is the honest value: there is
        // no authorization endpoint, because there is no human to redirect
        // and nothing to consent to — the issuer's authority over the
        // subject is what stands in for consent here.
        "response_types_supported": [],
        // Not one of RFC 8414's registered values, and deliberately named
        // rather than approximated: the credential is a noomesh service key
        // in the `Authorization` header, which is neither
        // `client_secret_basic` nor `client_secret_post`.
        "token_endpoint_auth_methods_supported": ["noomesh_service_key"],
        "subject_token_types_supported": SUBJECT_TOKEN_TYPES,
        "jwks_uri": format!("{base}{}", crate::jwks::JWKS_PATH),
        // Exchanged tokens are ES256 when a signing key is configured and
        // HS256 otherwise. Advertising both is honest: a verifier must be
        // prepared for what this install actually mints.
        "id_token_signing_alg_values_supported": ["ES256", "HS256"],
        "scopes_supported": ["read", "write", "admin"],
        "service_documentation": "https://github.com/noomesh/noomesh/blob/dev/docs/cli/agents-and-channels.md",
    }))
    .into_response()
}

/// The `issuer` value: scheme + authority of the request, no trailing
/// slash. `X-Forwarded-Proto` wins when present, because the controller
/// commonly terminates TLS upstream and would otherwise advertise `http`
/// for a deployment that only speaks `https`.
///
/// **Three sources, in this order, and the order is the bug fix.** The
/// first version read only the `Host` header and shipped advertising
/// `https://localhost:8080` to a client that had asked over the tailnet
/// name — because **HTTP/2 has no `Host` header**. It carries the
/// `:authority` pseudo-header instead, which lands in the request URI,
/// and TLS with ALPN negotiates h2 with any modern client. So the header
/// was simply absent and the fallback answered.
///
/// A discovery document naming an unreachable `token_endpoint` is worse
/// than no discovery document: the client does not fail at discovery, it
/// fails at the endpoint, pointed at the wrong host by the server's own
/// answer. Unit tests could not see it — the bug lived entirely in which
/// protocol version the connection negotiated.
///
///   1. `X-Forwarded-Host`, for a reverse proxy that rewrote the rest;
///   2. the request URI's authority — HTTP/2's `:authority`;
///   3. the `Host` header — HTTP/1.1.
fn issuer_from(uri: &axum::http::Uri, headers: &HeaderMap) -> String {
    let from_header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
    };
    let host = from_header("x-forwarded-host")
        .or_else(|| uri.authority().map(|a| a.to_string()))
        .or_else(|| from_header("host"))
        // Nothing said where it is. Better a value a reader recognises
        // as a fallback than a plausible-looking wrong one.
        .unwrap_or_else(|| "localhost:8080".to_string());
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("https");
    format!("{scheme}://{host}")
}

#[derive(Deserialize)]
struct ExchangeBody {
    /// RFC 8693 `grant_type`. Optional; refused if present and wrong.
    #[serde(default)]
    grant_type: Option<String>,
    /// The account to mint for.
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    /// Requested lifetime in seconds; clamped by [`crate::auth::clamp_agent_ttl`].
    #[serde(default)]
    expires_in: Option<u64>,
}

/// An ACCOUNT subject is a bare `noo_users` username and nothing else.
///
/// Closed deliberately, before the connection subject type that will make
/// compound names legal. Today a caller could pass
/// `owner/anything` here: it matches no account row, so `may_manage` sees
/// no tier and waves it through, the mint succeeds, and every later call
/// attributes to a username that does not exist — usage resolves
/// `user_uuid` by username and quietly stores NULL. Nothing errors. See
/// the warning on `auth::effective_user_id`.
///
/// Rejecting `/` here means the connection type will be the ONLY way to
/// obtain a compound subject: one door, one rule, and a new subject type
/// cannot arrive by accident through the old one.
///
/// Returns the validated name rather than `()` so the handler's
/// `subject` comes out of this function and there is no un-validated
/// binding to reach for by mistake. That is a nudge, **not** an
/// enforcement — the call can still be deleted and the file still
/// compiles, which I checked rather than assumed. What pins it is
/// `the_handler_validates_the_subject`, because a pure-function test
/// stays green whether or not anything calls the function.
fn account_subject(subject: &str) -> Result<&str, AppError> {
    let bad = subject
        .chars()
        .find(|c| *c == '/' || *c == '\\' || c.is_whitespace() || c.is_control());
    match bad {
        None => Ok(subject),
        Some('/') => Err(AppError::BadRequest(format!(
            "subject_token '{subject}' is not an account name — a '/' names a connection, and              that subject type is not served here"
        ))),
        Some(_) => Err(AppError::BadRequest(format!(
            "subject_token '{subject}' is not a valid account name"
        ))),
    }
}

/// Reject a grant type that is present and not ours, rather than ignoring
/// it. A caller that sent `client_credentials` believes something about
/// what it is getting back, and silence would confirm it.
fn check_grant_type(grant_type: Option<&str>) -> Result<(), AppError> {
    match grant_type.map(str::trim).filter(|g| !g.is_empty()) {
        None => Ok(()),
        Some(g) if g == GRANT_TYPE => Ok(()),
        Some(g) => Err(AppError::BadRequest(format!(
            "unsupported grant_type '{g}' — this endpoint implements {GRANT_TYPE}"
        ))),
    }
}

/// `POST /api/identity/token` — exchange a provisioning key for a
/// short-lived token acting as one account.
///
/// The `Consumer` is inserted by the middleware door, which has already
/// established that the bearer is an `identity`-scoped service key and
/// charged it against its per-minute quota. Nothing else can arrive here.
async fn token(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    // RFC 8705: present only when the exchange was called over a
    // connection carrying a client certificate. `Option<Option<_>>`
    // because the extension itself is absent without mTLS.
    peer: Option<Extension<Option<crate::node_identity::PeerThumbprint>>>,
    Json(body): Json<ExchangeBody>,
) -> AppResult {
    if !crate::addons::identity_enabled() {
        return Err(AppError::Unavailable(crate::addons::refusal_msg("identity")));
    }
    check_grant_type(body.grant_type.as_deref())?;
    let kind = subject_kind(body.subject_token_type.as_deref())?;

    let requested = body
        .subject_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "subject_token is required — the mesh identity this token should act as".into(),
            )
        })?;

    // Barrier 3. Also enforced at issue time; re-checked because a key
    // predating that check, or one whose account was erased, must not slip
    // through on the strength of a validation that ran in the past.
    let (issuer_user, issuer_role) = match (&consumer.user, consumer.user_role) {
        (Some(u), Some(r)) => (u.clone(), r),
        _ => {
            return Err(AppError::Forbidden(format!(
                "service key '{}' is not bound to an account, so it cannot mint for one — \
                 reissue it with `--user <account>`",
                consumer.name
            )))
        }
    };

    // Barrier 3.5 — the subject, validated FOR ITS KIND, and the two
    // rules kept in separate functions on purpose. `account_subject` +
    // `may_manage` asks "may I act for someone else"; `connection_subject`
    // + `owns_name` asks "is this name mine". Collapsing them would be an
    // authorization change wearing a naming change's clothes — the shape
    // this design has now produced five times.
    let subject = match kind {
        SubjectKind::Account => account_subject(requested)?,
        SubjectKind::Connection => connection_subject(requested, &issuer_user)?,
    };
    // The ACCOUNT behind the subject is what `noo_users` holds: a
    // connection has no row of its own and must not have one — one
    // person, one account, however many sessions.
    let account = crate::auth::account_of(subject);

    // The account must exist and be usable. A disabled one is refused
    // explicitly: minting a working token for an account someone has just
    // switched off is the exact failure this endpoint would be blamed for.
    let row: Option<(String, serde_json::Value, bool)> =
        sqlx::query_as("SELECT role, scopes, COALESCE(disabled, false) FROM noo_users WHERE username = $1")
            .bind(account)
            .fetch_optional(&state.db)
            .await?;
    let Some((role_col, scopes_col, disabled)) = row else {
        return Err(AppError::NotFound(format!("account '{account}' not found")));
    };
    if disabled {
        return Err(AppError::Forbidden(format!("account '{account}' is disabled")));
    }
    // Same resolution as `users::effective_tier`: an unparseable role column
    // reads as Admin, never as User — the low-protection answer must not be
    // the one a corrupt row produces.
    let subject_role = {
        let from_col: Role = role_col.trim().parse().unwrap_or(Role::Admin);
        let list: Vec<String> = serde_json::from_value(scopes_col).unwrap_or_default();
        from_col.max(Role::from_scopes(&list))
    };

    // Barrier 4 — for an ACCOUNT subject, the password-reset clamp,
    // unchanged. A CONNECTION subject does not take it: its entitlement
    // was settled by ownership above, and asking `may_manage` whether an
    // account may manage ITSELF is a different question that happens to
    // answer yes. Relying on that would be relying on a coincidence.
    if kind == SubjectKind::Account {
        crate::auth::may_manage(issuer_role, &issuer_user, subject_role, subject)
            .map_err(AppError::Forbidden)?;
    }

    // Barrier 5.
    let minted_role = crate::auth::agent_token_role(subject_role, issuer_role);
    let ttl = crate::auth::clamp_agent_ttl(body.expires_in);

    // Bind the token to the certificate that asked for it, when there was
    // one. Nothing to configure: a client that presents a certificate gets
    // a bound token, one that does not gets a bearer token, and the
    // difference is visible in the response so the caller knows which it
    // holds.
    let thumbprint = peer.and_then(|Extension(p)| p).map(|p| p.0);
    let Some(access_token) = crate::auth::mint_agent_jwt(
        subject,
        minted_role,
        &consumer.name,
        Some(&issuer_user),
        ttl,
        thumbprint.as_deref(),
    ) else {
        return Err(AppError::Unavailable(
            "the gateway has no usable NOO_JWT_SECRET; agent tokens cannot be minted".into(),
        ));
    };

    tracing::info!(
        subject = %subject,
        consumer = %consumer.name,
        issuer = %issuer_user,
        role = %minted_role.as_str(),
        ttl,
        cert_bound = thumbprint.is_some(),
        "agent_token_minted"
    );
    // One audit row per mint. This is where the delegation becomes a fact
    // an operator can read months later: who was minted for, by which key,
    // on whose authority.
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::IdentityTokenIssue, &format!("key:{}", consumer.name), subject)
            .details(json!({
            "issuer_user": issuer_user,
            "role": minted_role.as_str(),
            "expires_in": ttl,
            "cert_bound": thumbprint.is_some(),
            "kind": format!("{kind:?}").to_lowercase(),
            "account": account,
        })),
    )
    .await;

    Ok(Json(json!({
        "access_token": access_token,
        "issued_token_type": TOKEN_TYPE_ACCESS,
        "token_type": "Bearer",
        "expires_in": ttl,
        "subject": subject,
        // The account behind the subject, so a caller never parses the
        // name to learn whose it is.
        "account": account,
        "scope": minted_role.legacy_scopes().join(" "),
        "act": { "sub": format!("key:{}", consumer.name), "iss_user": issuer_user },
        // RFC 8705 Absent when the caller presented no client
        // certificate — then this is an ordinary bearer token.
        "cnf": thumbprint.as_ref().map(|t| json!({ "x5t#S256": t })),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_door_path_matches_the_route() {
        // The middleware admits the provisioning key by path string; the
        // router mounts by path string. A typo in either is an endpoint
        // that 401s forever, which is a slow thing to debug.
        let src = include_str!("identity.rs");
        assert!(
            src.contains(&format!("\"{}\"", crate::auth::IDENTITY_TOKEN_PATH)),
            "the mounted route must equal auth::IDENTITY_TOKEN_PATH"
        );
    }

    #[test]
    fn the_jwks_path_matches_the_route() {
        let src = include_str!("identity.rs");
        assert!(
            src.contains(&format!("\"{}\"", crate::jwks::JWKS_PATH)),
            "the mounted route must equal jwks::JWKS_PATH — they drift into a 404 otherwise"
        );
    }

    #[test]
    fn the_door_opens_for_identity_and_nothing_else() {
        use axum::http::Method;
        assert_eq!(
            crate::auth::exchange_scope_for(crate::auth::IDENTITY_TOKEN_PATH, &Method::POST),
            Some(crate::auth::IDENTITY_SCOPE)
        );
        // A GET on the same path is not the exchange.
        assert_eq!(
            crate::auth::exchange_scope_for(crate::auth::IDENTITY_TOKEN_PATH, &Method::GET),
            None
        );
        // And the scope buys nothing anywhere else.
        assert_eq!(
            crate::auth::exchange_scope_for("/api/security/users", &Method::POST),
            None
        );
    }

    #[test]
    fn grant_and_subject_types_are_checked_not_ignored() {
        assert!(check_grant_type(None).is_ok());
        assert!(check_grant_type(Some(GRANT_TYPE)).is_ok());
        let err = check_grant_type(Some("client_credentials")).unwrap_err();
        assert!(format!("{err:?}").contains("client_credentials"));

        assert_eq!(subject_kind(None).unwrap(), SubjectKind::Account);
        assert_eq!(subject_kind(Some(SUBJECT_TOKEN_TYPE_ACCOUNT)).unwrap(), SubjectKind::Account);
        assert_eq!(
            subject_kind(Some(SUBJECT_TOKEN_TYPE_CONNECTION)).unwrap(),
            SubjectKind::Connection
        );
        assert!(subject_kind(Some("urn:ietf:params:oauth:token-type:id_token")).is_err());
    }

    /// The hazard this closes is silent, which is why it is closed on the
    /// way in: a compound subject matches no `noo_users` row, so
    /// `may_manage` finds no tier to refuse, the mint succeeds, and
    /// attribution goes NULL with no error anywhere.
    #[test]
    fn an_account_subject_may_not_be_a_compound_name() {
        assert!(account_subject("persona-alice").is_ok());
        assert!(account_subject("alice.b_c-1").is_ok());

        let err = account_subject("owner/laptop").unwrap_err();
        assert!(
            format!("{err:?}").contains("connection"),
            "the refusal should name what a '/' means, so the next person asks for the right type"
        );
        assert!(account_subject("alice bob").is_err());
        assert!(account_subject("alice\nbob").is_err());
    }

    /// The trap raised in review, and the reason `connection_subject`
    /// takes the issuer rather than trusting the predicate alone.
    ///
    /// `owns_name` correctly says a connection owns only itself. But the
    /// exchange takes a CALLER and a requested subject, so if the caller
    /// could be a connection, `owner/laptop` could present itself
    /// and ask for `owner/claude-s1` — a sibling it may not act as, it
    /// could nonetheless become. The predicate would have stayed correct
    /// while the property it exists to protect died one layer below it.
    #[test]
    fn a_connection_may_not_mint_another_connection() {
        // The ordinary case: an account mints under itself.
        assert_eq!(
            connection_subject("owner/laptop", "owner").unwrap(),
            "owner/laptop"
        );

        // The trap: a connection issuer, minting a sibling.
        let err = connection_subject("owner/claude-s1", "owner/laptop").unwrap_err();
        assert!(
            format!("{err:?}").contains("may not mint another"),
            "a connection is a leaf; it re-authenticates rather than minting"
        );
        // …and it may not even re-mint itself through this path.
        assert!(connection_subject("owner/laptop", "owner/laptop").is_err());
    }

    #[test]
    fn a_connection_is_minted_only_under_its_own_account() {
        // Somebody else's namespace.
        assert!(connection_subject("other/session", "owner").is_err());
        // Shapes that are not a connection name at all.
        assert!(connection_subject("owner", "owner").is_err());
        assert!(connection_subject("owner/", "owner").is_err());
        assert!(connection_subject("/session", "owner").is_err());
        assert!(connection_subject("owner/a/b", "owner").is_err());
        // A prefix that merely looks similar.
        assert!(connection_subject("ownerx/session", "owner").is_err());
    }

    /// Both halves of a connection name obey one character class.
    ///
    /// Found in review: the account half was constrained twice and the
    /// LABEL half only for "non-empty, no separator" — and the label half
    /// is the one that ends up in a trust list and a presence listing,
    /// where two entries that look identical are worth something.
    #[test]
    fn a_connection_label_cannot_be_a_lookalike() {
        assert!(connection_subject("owner/laptop", "owner").is_ok());
        assert!(connection_subject("owner/claude_s1-2", "owner").is_ok());
        // A dot is legal in a name SEGMENT and illegal in an agent id, so
        // the intersection refuses it. See
        // `a_connection_name_is_also_a_valid_agent_id` for why.
        assert!(connection_subject("owner/claude_s1.2", "owner").is_err());

        // A space, which reads as the name beside it in any listing.
        assert!(connection_subject("owner/ session", "owner").is_err());
        assert!(connection_subject("owner/session ", "owner").is_err());
        // A non-breaking space, which reads as NOTHING at all.
        assert!(connection_subject("owner/session\u{a0}", "owner").is_err());
        // Cyrillic 'е' in what looks like "session".
        assert!(connection_subject("owner/s\u{435}ssion", "owner").is_err());
        // Control characters, and an over-long label.
        assert!(connection_subject("owner/ses\nsion", "owner").is_err());
        assert!(connection_subject(&format!("owner/{}", "a".repeat(129)), "owner").is_err());

        // The account half keeps its own rule through the same function.
        assert!(connection_subject("own er/session", "own er").is_err());
    }

    /// A minted connection must be a usable agent id, or it is a
    /// credential that works until it is used.
    ///
    /// `valid_name_segment` allows `.` (usernames always have); the
    /// messaging id rule forbids it, because `/` becomes `.` when the NATS
    /// subject is built and allowing both would collapse `owner/my.laptop`
    /// and `owner/my/laptop` onto one inbox. The connection name takes the
    /// intersection rather than either side.
    #[test]
    fn a_connection_name_is_also_a_valid_agent_id() {
        assert!(connection_subject("owner/laptop", "owner").is_ok());
        // Legal as a name segment, illegal as an agent id — refused HERE,
        // rather than minting a token that fails at first send.
        assert!(connection_subject("owner/my.laptop", "owner").is_err());
        assert!(crate::agent_messages::check_id("x", "owner/my.laptop").is_err());
    }

    /// The two kinds must not share an entitlement rule. Pinned as source
    /// because the alternative — asserting the handler's behaviour —
    /// needs a database, and the thing worth protecting is that the
    /// `may_manage` call stays inside the Account arm.
    #[test]
    fn the_two_subject_kinds_keep_separate_entitlement_rules() {
        let src = include_str!("identity.rs");
        let body = src.split("async fn token(").nth(1).expect("the handler must exist");
        let head = &body[..body.find("\n}").expect("the handler must have a body")];
        assert!(
            head.contains("SubjectKind::Account => account_subject("),
            "the account kind is entitled by account_subject + may_manage"
        );
        assert!(
            head.contains("SubjectKind::Connection => connection_subject("),
            "the connection kind is entitled by ownership, not may_manage"
        );
        assert!(
            head.contains("if kind == SubjectKind::Account {"),
            "may_manage must stay inside the Account arm — a connection that inherited it \
             would be an authorization change disguised as a list edit"
        );
    }

    /// Pins that the handler actually CALLS the validator. Without this,
    /// `account_subject` could be dead code and the test above would
    /// still pass — which is what the first attempt did.
    #[test]
    fn the_handler_validates_the_subject() {
        let src = include_str!("identity.rs");
        let body = src
            .split("async fn token(")
            .nth(1)
            .expect("the exchange handler must exist");
        let head = &body[..body.find("\n}").expect("the handler must have a body")];
        assert!(
            head.contains("account_subject("),
            "the exchange must validate its subject; an unchecked compound name mints a token \
             that attributes to nobody, silently"
        );
    }

    /// The live bug, pinned.
    ///
    /// Shipped advertising `https://localhost:8080` to a client that had
    /// asked over the tailnet name, because HTTP/2 carries `:authority`
    /// in the URI and has no `Host` header at all. Found by running the
    /// verification script against the real gateway minutes after the
    /// deploy; no unit test could have seen it, because the bug lived in
    /// which protocol version the connection negotiated.
    #[test]
    fn the_issuer_survives_http2_where_there_is_no_host_header() {
        use axum::http::{HeaderMap, HeaderValue, Uri};
        fn h(pairs: &[(&str, &str)]) -> HeaderMap {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(
                    axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            m
        }

        // HTTP/2: no Host header, authority in the URI. THE case.
        let u: Uri = "https://mesh.example:8080/.well-known/oauth-authorization-server"
            .parse()
            .unwrap();
        assert_eq!(issuer_from(&u, &h(&[])), "https://mesh.example:8080");

        // HTTP/1.1: origin-form URI, authority only in the header.
        let u1: Uri = "/.well-known/oauth-authorization-server".parse().unwrap();
        assert_eq!(issuer_from(&u1, &h(&[("host", "mesh.example:8080")])), "https://mesh.example:8080");

        // A proxy that rewrote the rest wins over both.
        assert_eq!(
            issuer_from(&u, &h(&[("x-forwarded-host", "public.example")])),
            "https://public.example"
        );
        // …and it decides the scheme too, for a proxy terminating TLS.
        assert_eq!(
            issuer_from(&u1, &h(&[("host", "mesh.example"), ("x-forwarded-proto", "http")])),
            "http://mesh.example"
        );

        // Nothing said where it is: a fallback a reader recognises AS
        // one, rather than a plausible-looking wrong answer.
        assert_eq!(issuer_from(&u1, &h(&[])), "https://localhost:8080");
    }

    #[test]
    fn ttl_is_clamped_at_both_ends() {
        use crate::auth::{clamp_agent_ttl, AGENT_TOKEN_MAX_TTL_SECS, AGENT_TOKEN_TTL_SECS};
        assert_eq!(clamp_agent_ttl(None), AGENT_TOKEN_TTL_SECS);
        assert_eq!(clamp_agent_ttl(Some(600)), 600);
        assert_eq!(clamp_agent_ttl(Some(999_999)), AGENT_TOKEN_MAX_TTL_SECS);
        // The units mistake: 1 second is a token that expires in flight.
        assert_eq!(clamp_agent_ttl(Some(1)), 60);
    }

    #[test]
    fn an_issuer_never_mints_above_its_own_tier() {
        use crate::auth::agent_token_role;
        // The ordinary case: a persona is a user, the issuer an operator.
        assert_eq!(agent_token_role(Role::User, Role::Operator), Role::User);
        // The escalation attempt: an operator-bound key naming an admin
        // persona. `may_manage` refuses this pairing first; if the tier
        // table changes under a permitted one, the clamp still holds.
        assert_eq!(agent_token_role(Role::Admin, Role::Operator), Role::Operator);
        assert_eq!(agent_token_role(Role::Admin, Role::Admin), Role::Admin);
    }

    /// A token from the exchange must not be able to buy a standing one.
    /// Guarded in `users::self_requester`; pinned here because the reason
    /// lives in this module and a refactor over there would not know it.
    #[test]
    fn a_delegated_token_cannot_mint_a_standing_key() {
        let src = include_str!("users.rs");
        let guard = src
            .split("fn self_requester(")
            .nth(1)
            .expect("users::self_requester must exist — it is the self-service key gate");
        let body = &guard[..guard.find("\n}").expect("self_requester must have a body")];
        assert!(
            body.contains("r.act.is_some()"),
            "self_requester must refuse a delegated token; without it an exchanged \
             token can mint an MCP key that outlives revoking the provisioning key"
        );
    }

    #[test]
    fn a_cert_bound_token_is_useless_without_the_cert() {
        use crate::auth::{cert_binding_holds, Cnf};
        let bound = Cnf { x5t_s256: "abc123".into() };

        // The ordinary token: no binding, nothing changes.
        assert!(cert_binding_holds(None, None));
        assert!(cert_binding_holds(None, Some("abc123")));

        // The bound token, used correctly.
        assert!(cert_binding_holds(Some(&bound), Some("abc123")));

        // Stolen and replayed from another client.
        assert!(!cert_binding_holds(Some(&bound), Some("someone-else")));

        // The case that matters most: a bound token presented over a
        // connection with NO certificate at all. If this passed, turning
        // mTLS off would silently downgrade every bound token to a plain
        // bearer — the failure would look like nothing at all.
        assert!(!cert_binding_holds(Some(&bound), None));
    }

    /// The mint, not the comparison. Clippy caught this exact gap once:
    /// `bind_to_cert` was threaded all the way through the signature and
    /// never written into the claims, so every token would have been
    /// unbound while the pure-function test above went on passing.
    #[test]
    fn the_mint_actually_writes_the_binding() {
        use crate::auth::{mint_agent_jwt_with, verify_token_with, Claims};

        // No env mutation: both keys are passed in, so this test cannot
        // disturb — or be disturbed by — anything else in the binary.
        let secret = "identity-exchange-mint-test-secret-not-a-real-key";
        let mint = |tp: Option<&str>| {
            mint_agent_jwt_with("persona", Role::User, "k", Some("boss"), 300, tp, secret, None)
                .expect("a mint with a usable secret must produce a token")
        };
        let claims = |t: &str| -> Claims {
            verify_token_with(t, secret, None).expect("the token this mint produced must verify")
        };

        let c = claims(&mint(Some("THUMB")));
        assert_eq!(
            c.cnf.as_ref().map(|c| c.x5t_s256.as_str()),
            Some("THUMB"),
            "a token minted over a client certificate must carry cnf"
        );
        assert_eq!(c.sub, "persona");
        assert_eq!(
            c.act.as_ref().map(|a| a.sub.as_str()),
            Some("key:k"),
            "every exchanged token records its actor"
        );
        assert!(
            claims(&mint(None)).cnf.is_none(),
            "no client certificate means no binding — not an empty one"
        );
    }

    #[test]
    fn discovery_is_only_advertised_when_the_addon_is_on() {
        // `metadata` returns 404 rather than a document when the add-on is
        // off. Pinned as source rather than executed: `identity_enabled`
        // reads process-wide config, and a test that mutated it would race
        // every other test in the binary.
        let src = include_str!("identity.rs");
        let body = src
            .split("async fn metadata(")
            .nth(1)
            .expect("the metadata handler must exist");
        let head = &body[..body.find("\n}").expect("metadata must have a body")];
        assert!(
            head.contains("identity_enabled()") && head.contains("NOT_FOUND"),
            "discovery must 404 when the add-on is off, not describe a door that is not there"
        );
    }

    /// The rule this whole module exists to preserve. If someone ever adds
    /// a body field naming the subject to the inference surface, the
    /// exchange stops being the only way to act as another account.
    #[test]
    fn an_unbound_key_still_cannot_delegate_on_the_inference_surface() {
        let machine = Consumer {
            name: "personifai".into(),
            scopes: vec!["chat".into()],
            rpm_limit: None,
            user: None,
            user_scopes: vec![],
            user_role: None,
        };
        let (uid, _actor) =
            crate::routes::inference::bind_identity(None, None, Some(&machine), Some("alice"), "v1");
        assert_eq!(uid, None, "an unbound key must not be able to name a subject");
    }
}
