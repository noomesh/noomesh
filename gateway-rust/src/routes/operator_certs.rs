// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Operator client certificates on the gateway.
//!
//! The decisions live in `crate::operator_auth` (pure, tested there); this
//! module gathers the facts a request carries and serves three routes:
//!
//! | route | admits | does |
//! |---|---|---|
//! | `POST /api/security/operator-certs/register` | the operator leaf being registered + the Admin login of the account it names | records the leaf's thumbprint in `noo_operator_certs` |
//! | `POST /api/security/operator-token` | a registered operator leaf + the Admin login of its account | mints an Admin token BOUND to that leaf (`cnf`, 5 min) |
//! | `POST /api/security/operator-certs/revoke` | the posture-write rule (operator leaf + bound token; nothing else) | marks rows revoked |
//!
//! and [`posture_admission`], which the posture write routes call.

use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{CertBoundToken, ClusterKind, ClusterNode, RequesterCtx};
use crate::node_identity::{PeerThumbprint, VerifiedOperator};
use crate::operator_auth::{self, Admission, ConnCert, PostureCred, Registration};
use crate::state::AppState;

use super::{AppError, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/security/operator-certs/register", post(register))
        .route("/api/security/operator-certs/revoke", post(revoke))
        .route("/api/security/operator-token", post(operator_token))
}

/// Everything the middleware and the TLS acceptor attached that bears on
/// operator authority. Never rejects: a missing fact is `None`, and the
/// decision functions say what was missing.
#[derive(Debug, Default, Clone)]
pub(crate) struct CallerFacts {
    pub requester: Option<RequesterCtx>,
    pub bound: Option<String>,
    pub thumbprint: Option<String>,
    pub operator: Option<String>,
    pub cluster: Option<ClusterNode>,
}

impl<S: Send + Sync> FromRequestParts<S> for CallerFacts {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ext = &parts.extensions;
        Ok(CallerFacts {
            requester: ext.get::<RequesterCtx>().cloned(),
            bound: ext.get::<CertBoundToken>().map(|b| b.0.clone()),
            thumbprint: ext.get::<Option<PeerThumbprint>>().and_then(|t| t.as_ref()).map(|t| t.0.clone()),
            operator: ext.get::<Option<VerifiedOperator>>().and_then(|o| o.as_ref()).map(|o| o.0.clone()),
            cluster: ext.get::<ClusterNode>().cloned(),
        })
    }
}

impl CallerFacts {
    fn conn(&self) -> ConnCert<'_> {
        ConnCert { thumbprint: self.thumbprint.as_deref(), operator: self.operator.as_deref() }
    }

    fn cred(&self) -> PostureCred<'_> {
        if let Some(r) = &self.requester {
            return PostureCred::Jwt { sub: &r.sub, role: r.role, bound: self.bound.as_deref() };
        }
        match &self.cluster {
            // Only the CONTROLLER secret. A node token never reaches these
            // routes (`node_route_allowed`), and if one did it is not the
            // operator.
            Some(ClusterNode(actor, ClusterKind::Internal)) => PostureCred::SharedSecret { actor },
            _ => PostureCred::None,
        }
    }

    async fn registration(&self, db: &sqlx::PgPool) -> Result<Registration, AppError> {
        match (&self.thumbprint, &self.operator) {
            (Some(tp), Some(op)) => operator_auth::registration_of(db, tp, op)
                .await
                .map_err(|e| AppError::Internal(format!("cannot read the operator certificate registry: {e}"))),
            _ => Ok(Registration::Unknown),
        }
    }
}

/// The posture-write gate: admits or refuses with the reason, and counts
/// the operator-certificate comparator lane on success.
pub(crate) async fn posture_admission(state: &AppState, facts: &CallerFacts, path: &str) -> Result<Admission, AppError> {
    let registration = facts.registration(&state.db).await?;
    let admission = operator_auth::admit_posture_write(&facts.cred(), facts.conn(), registration)
        .map_err(AppError::Forbidden)?;
    let Admission::Operator { account, .. } = &admission;
    let u = crate::legacy_lanes::operator_cert_use(account, path);
    crate::legacy_lanes::observe(&state.metrics, &[u], &crate::legacy_lanes::PeerFacts::default()).await;
    Ok(admission)
}

fn login_of(facts: &CallerFacts) -> Result<&RequesterCtx, AppError> {
    facts.requester.as_ref().ok_or_else(|| {
        AppError::Forbidden("log in first (`noo auth login`) — this route takes your own Admin login".into())
    })
}

/// `POST /api/security/operator-certs/register` — register the operator
/// leaf presented on this connection for the account it names. Idempotent
/// for a live registration; a revoked thumbprint stays revoked.
async fn register(State(state): State<Arc<AppState>>, facts: CallerFacts) -> AppResult {
    let who = login_of(&facts)?;
    let registration = facts.registration(&state.db).await?;
    operator_auth::admit_registration(&who.sub, who.role, facts.conn(), registration).map_err(AppError::Forbidden)?;
    let tp = facts.thumbprint.clone().unwrap_or_default();
    // ON CONFLICT DO NOTHING: a thumbprint registered to ANOTHER account is
    // impossible (the CN is in the hashed DER), and one registered to this
    // account is already what we want.
    sqlx::query("INSERT INTO noo_operator_certs (thumbprint, operator) VALUES ($1, $2) ON CONFLICT (thumbprint) DO NOTHING")
        .bind(&tp)
        .bind(&who.sub)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("cannot register the operator certificate: {e}")))?;
    crate::routes::core::audit_event(
        &state.db,
        "operator_cert_registered",
        "warning",
        &format!("operator:{}", who.sub),
        &tp,
        "ok",
        json!({ "operator": who.sub, "thumbprint": tp }),
    )
    .await;
    Ok(Json(json!({
        "status": "registered",
        "operator": who.sub,
        "thumbprint": tp,
        "already": registration == Registration::Active,
    })))
}

/// `POST /api/security/operator-token` — an Admin token bound to the
/// operator leaf on this connection. The ONLY minter of `cnf` on a login
/// subject; the token is refused from any connection without that leaf.
async fn operator_token(State(state): State<Arc<AppState>>, facts: CallerFacts) -> AppResult {
    let who = login_of(&facts)?;
    let registration = facts.registration(&state.db).await?;
    let tp = operator_auth::admit_token_mint(&who.sub, who.role, facts.conn(), registration)
        .map_err(AppError::Forbidden)?;
    let token = crate::auth::mint_operator_jwt(&who.sub, &tp, operator_auth::OPERATOR_TOKEN_TTL_SECS)
        .ok_or_else(|| AppError::Unavailable("no JWT secret is configured, so no token can be minted".into()))?;
    Ok(Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": operator_auth::OPERATOR_TOKEN_TTL_SECS,
        "cnf": { "x5t#S256": tp },
    })))
}

#[derive(Debug, Deserialize)]
struct RevokeBody {
    /// One certificate, by `x5t#S256`.
    #[serde(default)]
    thumbprint: Option<String>,
    /// Every live certificate of one account.
    #[serde(default)]
    operator: Option<String>,
    /// With `operator`: keep this one (`x5t#S256`) — "revoke every other
    /// certificate of this account", the recovery after a lost leaf
    /// (`noo security pki revoke-client <you> --others`, run with the newly
    /// issued one).
    #[serde(default)]
    keep: Option<String>,
}

/// `POST /api/security/operator-certs/revoke` — revoke by thumbprint, or
/// every certificate of an account (optionally all but one: `keep`).
/// Admitted exactly as a posture write is: revocation is posture.
async fn revoke(State(state): State<Arc<AppState>>, facts: CallerFacts, Json(body): Json<RevokeBody>) -> AppResult {
    let admission = posture_admission(&state, &facts, "/api/security/operator-certs/revoke").await?;
    let by = admission.audit_actor();
    let tp = body.thumbprint.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let op = body.operator.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let keep = body.keep.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let rows = match (tp, op) {
        (Some(tp), _) => sqlx::query(
            "UPDATE noo_operator_certs SET revoked_at = now(), revoked_by = $2 \
             WHERE thumbprint = $1 AND revoked_at IS NULL",
        )
        .bind(tp)
        .bind(&by)
        .execute(&state.db)
        .await,
        (None, Some(op)) => sqlx::query(
            "UPDATE noo_operator_certs SET revoked_at = now(), revoked_by = $2 \
             WHERE operator = $1 AND revoked_at IS NULL AND ($3::text IS NULL OR thumbprint <> $3)",
        )
        .bind(op)
        .bind(&by)
        .bind(keep)
        .execute(&state.db)
        .await,
        (None, None) => return Err(AppError::BadRequest("name a `thumbprint` or an `operator` to revoke".into())),
    }
    .map_err(|e| AppError::Internal(format!("cannot revoke: {e}")))?
    .rows_affected();
    crate::routes::core::audit_event(
        &state.db,
        "operator_cert_revoked",
        "warning",
        &by,
        tp.or(op).unwrap_or(""),
        "ok",
        json!({ "thumbprint": tp, "operator": op, "kept": keep, "revoked": rows }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "revoked": rows })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;

    fn requester(sub: &str, role: Role) -> RequesterCtx {
        RequesterCtx { sub: sub.into(), scopes: vec![], role, harness: None, act: None }
    }

    /// The facts → credential mapping the handlers rely on. A JWT always
    /// wins over a cluster extension (the middleware never sets both), and
    /// only the CONTROLLER secret maps to the shared-secret case.
    #[test]
    fn facts_map_to_the_credential_the_decision_judges() {
        let jwt = CallerFacts { requester: Some(requester("alice", Role::Admin)), bound: Some("tp".into()), ..Default::default() };
        assert_eq!(jwt.cred(), PostureCred::Jwt { sub: "alice", role: Role::Admin, bound: Some("tp") });

        let hmac = CallerFacts { cluster: Some(ClusterNode("cli-posture".into(), ClusterKind::Internal)), ..Default::default() };
        assert_eq!(hmac.cred(), PostureCred::SharedSecret { actor: "cli-posture" });

        let node = CallerFacts { cluster: Some(ClusterNode("host3".into(), ClusterKind::Node)), ..Default::default() };
        assert_eq!(node.cred(), PostureCred::None, "a node token is never the operator");
    }

    /// End to end over the pure parts: what a request carrying each
    /// combination gets. The posture handlers call exactly this.
    #[test]
    fn the_four_combinations_the_followup_names() {
        let conn = |op: bool| CallerFacts {
            thumbprint: op.then(|| "tp-a".to_string()),
            operator: op.then(|| "alice".to_string()),
            ..Default::default()
        };
        let decide = |f: &CallerFacts| {
            operator_auth::admit_posture_write(&f.cred(), f.conn(), Registration::Active)
        };
        // cert + bound JWT: accepted.
        let mut f = conn(true);
        f.requester = Some(requester("alice", Role::Admin));
        f.bound = Some("tp-a".into());
        assert!(decide(&f).is_ok());
        // JWT alone (even bound): refused.
        let mut f = conn(false);
        f.requester = Some(requester("alice", Role::Admin));
        f.bound = Some("tp-a".into());
        assert!(decide(&f).is_err());
        // cert alone: refused.
        assert!(decide(&conn(true)).is_err());
        // cert + JWT bound to a different cert: refused.
        let mut f = conn(true);
        f.requester = Some(requester("alice", Role::Admin));
        f.bound = Some("tp-b".into());
        assert!(decide(&f).is_err());
        // The controller secret, with or without the operator's leaf, as
        // any actor the CLI ever used: refused (no break-glass, no onboard
        // bootstrap — by design).
        for actor in ["cli", "cli-posture", "cli-onboard", "cli-break-glass"] {
            for leaf in [false, true] {
                let mut f = conn(leaf);
                f.cluster = Some(ClusterNode(actor.into(), ClusterKind::Internal));
                let e = decide(&f).unwrap_err();
                assert!(e.contains("noo upgrade --all"), "{actor}: {e}");
            }
        }
    }
}
