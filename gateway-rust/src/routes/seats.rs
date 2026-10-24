// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Kiosk SEATS (proposal i77, followup i66): a display enrolled with the
//! controller so its `noo` CLI and kiosk assets ride the artifact rail like a
//! node's — without ever becoming a node.
//!
//! # The rule
//!
//! A seat can NEVER obtain node credentials. Not a NATS principal, not a
//! backend door leaf, not the fleet secret, not the node-agent control API,
//! not a harness. Reusing the node lanes with a `role` flag was rejected: a
//! flag on a node credential is one bug away from a seat holding a node's
//! powers. So everything here is separate by construction:
//!
//! | what | node | seat |
//! |---|---|---|
//! | enrolment token | `noo_bootstrap_tokens`, `noo-bt-` | `noo_seat_tokens`, `noo-st-`, `role = 'seat'` CHECK |
//! | redeemed at | `POST /api/cluster/bootstrap` | `POST /api/cluster/seat-enroll` |
//! | registry | the node registry + its token row | `noo_seats` (no node query reads it) |
//! | staged bundle | `noo_provision_bundles` | `noo_seat_bundles` |
//! | proof domain | `noo-bundle-<purpose>:…` | `noo-seat-<purpose>:…` |
//! | rail routes | `/bootstrap/bundle/{node}…` | `/bootstrap/seat/{seat}…` |
//!
//! A seat holds its birth key and nothing else, so the only routes it can
//! call are the four `/bootstrap/seat/{seat}/…` routes, and every one of them
//! refuses anything but a `noo-seat-*` proof verified against the cert in
//! `noo_seats` (`auth::seat_cannot_reach_node_routes` walks the rest).
//!
//! # Surfaces
//!
//! - operator (>= Operator JWT or the controller's own cluster HMAC; a node's
//!   fleet token is refused here as everywhere off its allow-list):
//!   `POST|GET /api/cluster/seat-tokens`, `POST …/{id}/revoke`,
//!   `GET /api/cluster/seats`, `POST /api/cluster/seats/{seat}/bundle`,
//!   `GET /api/cluster/seats/{seat}/status`;
//! - public, token in the body: `POST /api/cluster/seat-enroll`;
//! - the seat's rail, birth-proof only: `GET /bootstrap/seat/{seat}/bundle`,
//!   `POST …/fetched`, `POST …/applied`, `POST …/heartbeat`.
//!
//! The bundle is CMS ciphertext encrypted to the seat's birth cert and,
//! inside, signed with the fleet signing key (`noo kiosk` seat staging) — the
//! gateway never sees plaintext, exactly like a node bundle.

use crate::audit::{AuditEvent, AuditKind};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::bootstrap::{
    cluster_ca_candidates, cluster_ca_fingerprint_from, controller_url,
    enroll_url, valid_node_name, validate_ttl, BIRTH_PROOF_HEADER,
};
use super::{AppError, AppResult};
use crate::auth::ClusterNode;
use crate::authz::OperatorOrInternal;
use crate::auth_refresh::{generate_seat_token, hash_token};
use crate::birth_proof::Purpose;
use crate::state::AppState;

/// A seat bundle is the CLI for one platform (~10-20 MB, gzipped) plus four
/// scripts and four units. 256 MB is far above that and far below the
/// node rail's cap.
const MAX_SEAT_BODY: usize = 256 * 1024 * 1024;

/// A heartbeat is a handful of fields. Anything bigger is not a heartbeat.
const MAX_HEARTBEAT_BYTES: usize = 16 * 1024;

/// The one body every failed seat redemption gets: unknown, expired, used,
/// revoked and wrong-name tokens are indistinguishable to the caller.
const DENIED_MSG: &str = "seat token rejected";

/// The sha a `SeatGet` proof signs: the seat has not seen the bytes yet.
pub const SEAT_GET_SHA: &str = "-";

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Operator surface ──
        .route("/api/cluster/seat-tokens", get(seat_tokens_list).post(seat_token_create))
        .route("/api/cluster/seat-tokens/{id}/revoke", post(seat_token_revoke))
        .route("/api/cluster/seats", get(seats_list))
        .route("/api/cluster/seats/{seat}/bundle",
            post(seat_bundle_put).layer(DefaultBodyLimit::max(MAX_SEAT_BODY)))
        .route("/api/cluster/seats/{seat}/status", get(seat_bundle_status))
        // ── Public enrolment (PUBLIC_PATHS_EXACT): the token is the credential ──
        .route("/api/cluster/seat-enroll", post(seat_enroll))
        // ── The seat's rail (HANDLER_AUTHENTICATED_PATHS): birth proof only ──
        .route("/bootstrap/seat/{seat}/bundle", get(seat_bundle_get))
        .route("/bootstrap/seat/{seat}/fetched", post(seat_fetch_receipt))
        .route("/bootstrap/seat/{seat}/applied", post(seat_apply_report))
        .route("/bootstrap/seat/{seat}/heartbeat", post(seat_heartbeat))
}

// ═══════════════════════════════════════════════════════════════
// Guards
// ═══════════════════════════════════════════════════════════════

/// >= Operator, or the controller's own cluster HMAC — never a node.
///
/// The `OperatorOrInternal` extractor already refuses a sub-operator JWT; the extra arm
/// refuses a `Node`-kind cluster token even if the middleware's allow-list
/// were ever to let one past. A node has no business minting, listing or
/// staging seats.
fn seat_admin_guard(
    op: &OperatorOrInternal,
    cluster: &Option<Extension<ClusterNode>>,
) -> Result<String, AppError> {
    if let Some(Extension(c)) = cluster {
        if !c.is_internal() {
            return Err(AppError::Forbidden(format!("node '{}' may not manage kiosk seats", c.0)));
        }
    }
    Ok(op.actor("cluster-cli"))
}

/// Does an enrolled NODE hold this name? A seat may not take it: the two
/// registries are separate, and a shared name would make every log line,
/// audit row and operator command ambiguous about which of them it meant.
async fn name_held_by_node(db: &sqlx::PgPool, name: &str) -> Result<bool, AppError> {
    if crate::self_node::is_self_node(name) {
        return Ok(true);
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM noo_bootstrap_tokens \
         WHERE lower(node_name) = lower($1) AND used_at IS NOT NULL AND NOT revoked",
    )
    .bind(name)
    .fetch_one(db)
    .await?;
    Ok(n > 0)
}

// ═══════════════════════════════════════════════════════════════
// Mint / list / revoke
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSeatTokenBody {
    seat_name: String,
    ttl_seconds: Option<i64>,
}

/// One minted token: the raw value exists here and in the response, nowhere
/// else.
#[derive(Debug)]
pub(crate) struct MintedSeatToken {
    pub id: uuid::Uuid,
    pub raw: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Insert a single-use seat token. `role` is written explicitly and pinned by
/// the table's CHECK, so the claim is part of the row, not an assumption.
pub(crate) async fn mint_seat_token(
    db: &sqlx::PgPool,
    seat: &str,
    ttl_secs: i64,
    by: &str,
) -> Result<MintedSeatToken, sqlx::Error> {
    let raw = generate_seat_token();
    let (id, expires_at): (uuid::Uuid, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "INSERT INTO noo_seat_tokens (token_hash, role, seat_name, created_by, expires_at) \
         VALUES ($1, 'seat', $2, $3, now() + make_interval(secs => $4)) \
         RETURNING id, expires_at",
    )
    .bind(hash_token(&raw))
    .bind(seat)
    .bind(by)
    .bind(ttl_secs as f64)
    .fetch_one(db)
    .await?;
    Ok(MintedSeatToken { id, raw, expires_at })
}

/// POST /api/cluster/seat-tokens — mint a one-time seat enrolment token.
///
/// The response carries what the controller's `noo kiosk seat-token` needs to
/// compose the paste (`noo kiosk enroll noo-seat1.<blob>`): the raw token,
/// the controller URL a seat can reach, and the cluster CA pin. The fleet
/// signing PUBLIC key goes into the blob from the controller's own PKI —
/// the gateway does not hold it.
async fn seat_token_create(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
    Json(body): Json<CreateSeatTokenBody>,
) -> AppResult {
    let by = seat_admin_guard(&op, &cluster)?;
    let seat = body.seat_name.trim().to_string();
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("seat_name must be <= 64 chars of [a-zA-Z0-9._-]".into()));
    }
    let ttl = validate_ttl(body.ttl_seconds).map_err(AppError::BadRequest)?;
    if name_held_by_node(&state.db, &seat).await? {
        return Err(AppError::Conflict(format!(
            "'{seat}' is an enrolled NODE's name — a seat is never a node and may not share its name; \
             pick another seat name"
        )));
    }
    // Settled before the token exists: a token minted into a failing
    // response is a live credential nobody holds.
    let gateway = enroll_url(&controller_url()).map_err(AppError::Unavailable)?;
    let ca_sha256 = cluster_ca_fingerprint_from(&cluster_ca_candidates()).map_err(AppError::Unavailable)?;
    let t = mint_seat_token(&state.db, &seat, ttl, &by).await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SeatTokenCreate, &by, &format!("seat-token:{}", t.id))
            .details(json!({ "token_id": t.id.to_string(), "seat": seat, "ttl_seconds": ttl, "role": "seat" })),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "id": t.id.to_string(),
        "role": "seat",
        "seat_name": seat,
        "token": t.raw,
        "expires_at": t.expires_at.to_rfc3339(),
        "controller_url": gateway,
        "ca_sha256": ca_sha256,
        "note": "single-use; enrolls a kiosk SEAT, never a node — it expires, burns on first use, \
                 and can be revoked by id",
    })))
}

/// GET /api/cluster/seat-tokens — issuance metadata, never hashes.
async fn seat_tokens_list(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    let _ = seat_admin_guard(&op, &cluster)?;
    type Row = (uuid::Uuid, String, String, String, chrono::DateTime<chrono::Utc>,
                chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, role, seat_name, created_by, created_at, expires_at, used_at, used_by_ip, revoked \
         FROM noo_seat_tokens ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;
    let now = chrono::Utc::now();
    let tokens: Vec<Value> = rows
        .into_iter()
        .map(|(id, role, seat, by, created, expires, used, ip, revoked)| {
            json!({
                "id": id.to_string(),
                "role": role,
                "seat_name": seat,
                "status": token_status(revoked, used.is_some(), expires <= now),
                "created_by": by,
                "created_at": created.to_rfc3339(),
                "expires_at": expires.to_rfc3339(),
                "used_at": used.map(|t| t.to_rfc3339()),
                "used_by_ip": ip,
            })
        })
        .collect();
    Ok(Json(json!({ "tokens": tokens, "count": tokens.len() })))
}

fn token_status(revoked: bool, used: bool, expired: bool) -> &'static str {
    if revoked {
        "revoked"
    } else if used {
        "used"
    } else if expired {
        "expired"
    } else {
        "active"
    }
}

/// POST /api/cluster/seat-tokens/{id}/revoke — idempotent.
async fn seat_token_revoke(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    let by = seat_admin_guard(&op, &cluster)?;
    let id: uuid::Uuid = id.parse().map_err(|_| AppError::BadRequest("invalid token id (expected a UUID)".into()))?;
    let updated = sqlx::query("UPDATE noo_seat_tokens SET revoked = true WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("seat token {id} not found")));
    }
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SeatTokenRevoke, &by, &format!("seat-token:{id}"))
            .details(json!({ "token_id": id.to_string() })),
    ).await;
    Ok(Json(json!({ "status": "ok", "id": id.to_string(), "revoked": true })))
}

// ═══════════════════════════════════════════════════════════════
// Enrolment (public; the token is the credential)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct SeatEnrollBody {
    token: String,
    /// The name the seat believes it was minted for. Must equal the token's
    /// bound name; a mismatch is refused BEFORE the burn.
    seat_name: String,
    /// PEM of the seat's self-signed BIRTH certificate (RSA). Bundles are
    /// encrypted to it, and every seat proof verifies against it.
    birth_cert: String,
    /// arch, os, cli_user, cli_path, kiosk_user — what staging needs.
    facts: Option<Value>,
    enroll_user: Option<String>,
}

/// Why a seat redemption was refused — the audit row's word; the caller
/// always gets the uniform [`DENIED_MSG`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeatDeny {
    Unknown,
    Revoked,
    AlreadyUsed,
    Expired,
    /// The token was minted for another seat name.
    WrongSeat,
    /// The row's claim is not `seat` (impossible under the CHECK; refused
    /// anyway, so the claim is checked rather than assumed).
    NotASeatClaim,
    LostRace,
}

impl SeatDeny {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SeatDeny::Unknown => "unknown_token",
            SeatDeny::Revoked => "revoked",
            SeatDeny::AlreadyUsed => "already_used",
            SeatDeny::Expired => "expired",
            SeatDeny::WrongSeat => "wrong_seat",
            SeatDeny::NotASeatClaim => "not_a_seat_claim",
            SeatDeny::LostRace => "lost_race",
        }
    }
}

/// What a redemption decides from the token row, before anything is written.
/// Pure, so single use / expiry / claim / binding are pinned without a DB.
pub(crate) fn judge_seat_token(
    revoked: bool,
    used: bool,
    expired: bool,
    role: &str,
    bound_seat: &str,
    presented_seat: &str,
) -> Result<(), SeatDeny> {
    if role != "seat" {
        return Err(SeatDeny::NotASeatClaim);
    }
    if revoked {
        return Err(SeatDeny::Revoked);
    }
    if used {
        return Err(SeatDeny::AlreadyUsed);
    }
    if expired {
        return Err(SeatDeny::Expired);
    }
    if !bound_seat.eq_ignore_ascii_case(presented_seat.trim()) {
        return Err(SeatDeny::WrongSeat);
    }
    Ok(())
}

/// Spend a seat token: look it up by hash, judge it, then the GUARDED update
/// (every condition re-checked under the row lock, so exactly one concurrent
/// redeemer wins). Returns the token id and the bound seat name.
pub(crate) async fn redeem_seat_token(
    db: &sqlx::PgPool,
    raw: &str,
    presented_seat: &str,
    ip: &str,
) -> Result<Result<(uuid::Uuid, String), (SeatDeny, Option<uuid::Uuid>)>, sqlx::Error> {
    type Row = (uuid::Uuid, String, String, bool, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, role, seat_name, revoked, used_at, expires_at FROM noo_seat_tokens WHERE token_hash = $1",
    )
    .bind(hash_token(raw.trim()))
    .fetch_optional(db)
    .await?;
    let Some((id, role, seat, revoked, used_at, expires_at)) = row else {
        return Ok(Err((SeatDeny::Unknown, None)));
    };
    if let Err(d) = judge_seat_token(revoked, used_at.is_some(), expires_at <= chrono::Utc::now(), &role, &seat, presented_seat) {
        return Ok(Err((d, Some(id))));
    }
    let claimed = sqlx::query(
        "UPDATE noo_seat_tokens SET used_at = now(), used_by_ip = $2 \
         WHERE id = $1 AND role = 'seat' AND used_at IS NULL AND NOT revoked AND expires_at > now()",
    )
    .bind(id)
    .bind(ip)
    .execute(db)
    .await?;
    if claimed.rows_affected() == 0 {
        return Ok(Err((SeatDeny::LostRace, Some(id))));
    }
    Ok(Ok((id, seat)))
}

/// Record the seat (re-enrolment replaces its birth cert and drops any bundle
/// staged for the old one, which it could no longer decrypt).
pub(crate) async fn record_seat(
    db: &sqlx::PgPool,
    seat: &str,
    birth_cert: &str,
    facts: Option<&Value>,
    enroll_user: Option<&str>,
    token_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM noo_seat_bundles WHERE seat_name = $1")
        .bind(seat)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO noo_seats (seat_name, birth_cert, facts, enroll_user, token_id, enrolled_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (seat_name) DO UPDATE SET birth_cert = EXCLUDED.birth_cert, facts = EXCLUDED.facts, \
             enroll_user = EXCLUDED.enroll_user, token_id = EXCLUDED.token_id, enrolled_at = now(), \
             last_seen = NULL, heartbeat = NULL",
    )
    .bind(seat)
    .bind(birth_cert)
    .bind(facts)
    .bind(enroll_user)
    .bind(token_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// POST /api/cluster/seat-enroll — redeem a seat token.
///
/// PUBLIC: the seat holds nothing yet. Refusals are one uniform 403 (the
/// reason goes to the audit row only). On success the seat is in `noo_seats`
/// and the response carries NO credential: no secret, no key, no token. What
/// the seat may do from here is sign `noo-seat-*` proofs with the key it
/// generated itself.
async fn seat_enroll(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SeatEnrollBody>,
) -> AppResult {
    let ip = peer.ip().to_string();
    let deny = |reason: SeatDeny, id: Option<uuid::Uuid>| {
        let db = state.db.clone();
        let ip = ip.clone();
        async move {
            let resource = id.map(|i| format!("seat-token:{i}")).unwrap_or_else(|| "seat-token:unknown".into());
            crate::audit::record(
                &db,
                AuditEvent::new(AuditKind::SeatTokenDenied, "anonymous", &resource)
                    .outcome(crate::audit::Outcome::Denied)
                    .details(json!({ "reason": reason.as_str(), "ip": ip })),
            ).await;
            AppError::Forbidden(DENIED_MSG.into())
        }
    };
    let seat = body.seat_name.trim().to_string();
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("seat_name must be <= 64 chars of [a-zA-Z0-9._-]".into()));
    }
    // Shape AND usability, before the burn: a seat whose cert cannot verify a
    // proof could never fetch, heartbeat or report.
    let cert = body.birth_cert.trim();
    if !(cert.starts_with("-----BEGIN CERTIFICATE-----") && cert.len() < 16_384)
        || !crate::birth_proof::usable_birth_cert(cert)
    {
        return Err(AppError::BadRequest("birth_cert must be a PEM RSA certificate".into()));
    }
    if name_held_by_node(&state.db, &seat).await? {
        return Err(AppError::Conflict(format!(
            "'{seat}' is an enrolled node's name; a seat may not share it. The token was not spent."
        )));
    }
    let facts = body.facts.as_ref().filter(|f| f.is_object() && f.to_string().len() < 8192);
    let enroll_user = body.enroll_user.as_deref().map(str::trim).filter(|u| !u.is_empty() && u.len() <= 64);
    let (id, seat) = match redeem_seat_token(&state.db, &body.token, &seat, &ip).await? {
        Ok(v) => v,
        Err((reason, id)) => return Err(deny(reason, id).await),
    };
    record_seat(&state.db, &seat, cert, facts, enroll_user, id).await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SeatEnrolled, "anonymous", &format!("seat:{seat}"))
            .details(json!({ "token_id": id.to_string(), "seat": seat, "ip": ip })),
    ).await;
    tracing::info!(seat = %seat, ip = %ip, "seat_enrolled");
    Ok(Json(json!({
        "status": "ok",
        "seat_name": seat,
        "role": "seat",
        "controller_url": controller_url(),
        "next_step": "on the controller: `noo upgrade --nodes` (or `--seats`) stages this seat's bundle; \
                      the seat's noo-seat-sync timer collects it",
    })))
}

// ═══════════════════════════════════════════════════════════════
// Operator: registry + staging
// ═══════════════════════════════════════════════════════════════

/// GET /api/cluster/seats — every enrolled seat with its last heartbeat and
/// the state of its staged bundle. What `noo upgrade` and `noo cluster
/// verify` read, and the ONLY place either learns a seat exists.
async fn seats_list(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    let _ = seat_admin_guard(&op, &cluster)?;
    type Row = (String, String, Option<Value>, Option<String>, chrono::DateTime<chrono::Utc>,
                Option<chrono::DateTime<chrono::Utc>>, Option<Value>, Option<String>,
                Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>,
                Option<String>, Option<i32>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.seat_name, s.birth_cert, s.facts, s.enroll_user, s.enrolled_at, s.last_seen, s.heartbeat, \
                encode(sha256(b.blob), 'hex'), b.fetched_at, b.applied_at, b.applied_sha, b.apply_rc, b.apply_msg \
         FROM noo_seats s LEFT JOIN noo_seat_bundles b ON b.seat_name = s.seat_name \
         ORDER BY s.seat_name",
    )
    .fetch_all(&state.db)
    .await?;
    let seats: Vec<Value> = rows
        .into_iter()
        .map(|(name, cert, facts, user, enrolled, seen, hb, sha, fetched, applied, applied_sha, rc, msg)| {
            json!({
                "seat_name": name,
                "role": "seat",
                "birth_cert": cert,
                "facts": facts,
                "enroll_user": user,
                "enrolled_at": enrolled.to_rfc3339(),
                "last_seen": seen.map(|t| t.to_rfc3339()),
                "heartbeat": hb,
                "staged_sha": sha,
                "fetched_at": fetched.map(|t| t.to_rfc3339()),
                "applied_at": applied.map(|t| t.to_rfc3339()),
                "applied_sha": applied_sha,
                "apply_rc": rc,
                "apply_msg": msg,
            })
        })
        .collect();
    Ok(Json(json!({ "seats": seats, "count": seats.len() })))
}

/// POST /api/cluster/seats/{seat}/bundle — stage a seat's bundle: CMS
/// ciphertext to the seat's birth cert, built and signed by the controller's
/// CLI. Upsert; the seat's sync timer collects it.
async fn seat_bundle_put(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
    Path(seat): Path<String>,
    body: Bytes,
) -> AppResult {
    let by = seat_admin_guard(&op, &cluster)?;
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("invalid seat name".into()));
    }
    if body.is_empty() {
        return Err(AppError::BadRequest("empty bundle".into()));
    }
    let r = sqlx::query(
        "INSERT INTO noo_seat_bundles (seat_name, blob, created_at, fetched_at) \
         SELECT seat_name, $2, now(), NULL FROM noo_seats WHERE seat_name = $1 \
         ON CONFLICT (seat_name) DO UPDATE SET blob = EXCLUDED.blob, created_at = now(), fetched_at = NULL",
    )
    .bind(&seat)
    .bind(body.as_ref())
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("no seat named '{seat}' is enrolled")));
    }
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SeatBundleStaged, &by, &format!("seat-bundle:{seat}"))
            .details(json!({ "seat": seat, "bytes": body.len() })),
    ).await;
    Ok(Json(json!({ "status": "staged", "seat": seat, "bytes": body.len() })))
}

/// GET /api/cluster/seats/{seat}/status — the staged bundle and the seat's
/// receipts, the same shape as a node's provision-bundle status so the
/// CLI's combined wait judges both with one function.
async fn seat_bundle_status(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    cluster: Option<Extension<ClusterNode>>,
    Path(seat): Path<String>,
) -> AppResult {
    let _ = seat_admin_guard(&op, &cluster)?;
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("invalid seat name".into()));
    }
    type Row = (chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, i64,
                Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<i32>, Option<String>, String,
                Option<chrono::DateTime<chrono::Utc>>, Option<Value>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT b.created_at, b.fetched_at, octet_length(b.blob)::bigint, b.applied_at, b.applied_sha, \
                b.apply_rc, b.apply_msg, encode(sha256(b.blob), 'hex'), s.last_seen, s.heartbeat \
         FROM noo_seat_bundles b JOIN noo_seats s ON s.seat_name = b.seat_name WHERE b.seat_name = $1",
    )
    .bind(&seat)
    .fetch_optional(&state.db)
    .await?;
    match row {
        Some((staged, fetched, bytes, applied, applied_sha, rc, msg, sha, seen, hb)) => Ok(Json(json!({
            "seat": seat,
            "staged_at": staged.to_rfc3339(),
            "fetched_at": fetched.map(|t| t.to_rfc3339()),
            "bytes": bytes,
            "sha256": sha,
            "applied_at": applied.map(|t| t.to_rfc3339()),
            "applied_sha": applied_sha,
            "apply_rc": rc,
            "apply_msg": msg,
            "last_seen": seen.map(|t| t.to_rfc3339()),
            "heartbeat": hb,
        }))),
        None => Err(AppError::NotFound("no bundle staged".into())),
    }
}

// ═══════════════════════════════════════════════════════════════
// The seat's rail — a `noo-seat-*` birth proof, or nothing
// ═══════════════════════════════════════════════════════════════

/// The birth cert recorded for this SEAT. Reads `noo_seats` and nothing
/// else: a node's cert can never answer for a seat, and the node routes'
/// `birth_cert_for` never reads this table.
async fn seat_cert_for(db: &sqlx::PgPool, seat: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT birth_cert FROM noo_seats WHERE seat_name = $1")
        .bind(seat)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Verify a seat proof, or 403. There is no other credential on these routes:
/// a bearer of any kind is not consulted (and a fleet token never reaches
/// here — the middleware confines it to the node allow-list).
async fn check_seat_proof(
    db: &sqlx::PgPool,
    headers: &HeaderMap,
    purpose: Purpose,
    seat: &str,
    sha: &str,
) -> Result<(), AppError> {
    debug_assert!(purpose.is_seat());
    let header = headers.get(BIRTH_PROOF_HEADER).and_then(|v| v.to_str().ok());
    let cert = seat_cert_for(db, seat).await;
    let now = chrono::Utc::now().timestamp();
    crate::birth_proof::verify(header, purpose, seat, sha, cert.as_deref(), now).map_err(|e| {
        tracing::warn!(seat = %seat, reason = ?e, "seat_proof_rejected");
        AppError::Forbidden(format!("seat proof refused for '{seat}': {e:?} (sign \"noo-seat-<purpose>:<seat>:<sha>:<ts>\" with the seat's birth key)"))
    })
}

async fn staged_seat_sha(db: &sqlx::PgPool, seat: &str) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT encode(sha256(blob), 'hex') FROM noo_seat_bundles WHERE seat_name = $1",
    )
    .bind(seat)
    .fetch_optional(db)
    .await?)
}

fn sha_param(body: &Value) -> Result<String, AppError> {
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("sha must be 64 hex chars".into()));
    }
    Ok(sha)
}

/// GET /bootstrap/seat/{seat}/bundle — the seat collects its ciphertext. The
/// GET is SIGNED (unlike a node's, which happens before the node holds
/// anything): a seat is fully enrolled before it ever fetches.
async fn seat_bundle_get(
    State(state): State<Arc<AppState>>,
    Path(seat): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !valid_node_name(&seat) {
        return (StatusCode::BAD_REQUEST, "invalid seat name").into_response();
    }
    if let Err(e) = check_seat_proof(&state.db, &headers, Purpose::SeatGet, &seat, SEAT_GET_SHA).await {
        return e.into_response();
    }
    let row: Result<Option<(Vec<u8>,)>, _> =
        sqlx::query_as("SELECT blob FROM noo_seat_bundles WHERE seat_name = $1")
            .bind(&seat)
            .fetch_optional(&state.db)
            .await;
    match row {
        Ok(Some((blob,))) => (StatusCode::OK, [("content-type", "application/octet-stream")], blob).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no bundle staged").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bundle lookup failed").into_response(),
    }
}

/// POST /bootstrap/seat/{seat}/fetched — `{sha}`, signed. Stamps fetched_at.
async fn seat_fetch_receipt(
    State(state): State<Arc<AppState>>,
    Path(seat): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult {
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("invalid seat name".into()));
    }
    let sha = sha_param(&body)?;
    match staged_seat_sha(&state.db, &seat).await? {
        None => return Err(AppError::NotFound("no bundle staged for this seat".into())),
        Some(s) if s != sha => return Err(AppError::BadRequest("sha does not match the staged bundle".into())),
        _ => {}
    }
    check_seat_proof(&state.db, &headers, Purpose::SeatFetch, &seat, &sha).await?;
    sqlx::query("UPDATE noo_seat_bundles SET fetched_at = now() WHERE seat_name = $1")
        .bind(&seat)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "recorded": true, "seat": seat })))
}

/// POST /bootstrap/seat/{seat}/applied — `{sha, rc, msg}`, signed.
async fn seat_apply_report(
    State(state): State<Arc<AppState>>,
    Path(seat): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult {
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("invalid seat name".into()));
    }
    let sha = sha_param(&body)?;
    let rc = body.get("rc").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
    let msg: String = body.get("msg").and_then(|v| v.as_str()).unwrap_or("").chars().take(2000).collect();
    match staged_seat_sha(&state.db, &seat).await? {
        None => return Err(AppError::NotFound("no bundle staged for this seat".into())),
        Some(s) if s != sha => return Err(AppError::BadRequest("sha does not match the staged bundle".into())),
        _ => {}
    }
    check_seat_proof(&state.db, &headers, Purpose::SeatApply, &seat, &sha).await?;
    sqlx::query(
        "UPDATE noo_seat_bundles SET applied_at = now(), applied_sha = $2, apply_rc = $3, apply_msg = $4 \
         WHERE seat_name = $1",
    )
    .bind(&seat)
    .bind(&sha)
    .bind(rc)
    .bind(&msg)
    .execute(&state.db)
    .await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SeatBundleApplied, &format!("seat:{seat}"), &format!("seat-bundle:{seat}"))
            .outcome(if rc == 0 { crate::audit::Outcome::Ok } else { crate::audit::Outcome::custom("failed") })
            .severity(if rc == 0 { crate::audit::Severity::Info } else { crate::audit::Severity::Warning })
            .details(json!({ "seat": seat, "rc": rc, "sha": sha, "msg": msg })),
    )
    .await;
    Ok(Json(json!({ "recorded": true, "seat": seat, "rc": rc })))
}

/// POST /bootstrap/seat/{seat}/heartbeat — the seat's state (CLI version,
/// kiosk units, console build), signed over the sha256 of the exact body
/// bytes so a captured proof cannot carry a different body.
async fn seat_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(seat): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult {
    if !valid_node_name(&seat) {
        return Err(AppError::BadRequest("invalid seat name".into()));
    }
    if body.is_empty() || body.len() > MAX_HEARTBEAT_BYTES {
        return Err(AppError::BadRequest(format!("a heartbeat is 1..{MAX_HEARTBEAT_BYTES} bytes of JSON")));
    }
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&body))
    };
    check_seat_proof(&state.db, &headers, Purpose::SeatHeartbeat, &seat, &sha).await?;
    let hb: Value = serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(format!("heartbeat is not JSON: {e}")))?;
    if !hb.is_object() {
        return Err(AppError::BadRequest("heartbeat must be a JSON object".into()));
    }
    sqlx::query("UPDATE noo_seats SET last_seen = now(), heartbeat = $2 WHERE seat_name = $1")
        .bind(&seat)
        .bind(&hb)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "recorded": true, "seat": seat })))
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Single use, expiry, revocation, the claim and the name binding — the
    /// whole redemption decision, judged before any write.
    #[test]
    fn a_seat_token_redeems_once_unexpired_unrevoked_for_its_own_seat() {
        assert_eq!(judge_seat_token(false, false, false, "seat", "lobby", "lobby"), Ok(()));
        assert_eq!(judge_seat_token(false, false, false, "seat", "lobby", "Lobby"), Ok(()));
        assert_eq!(judge_seat_token(false, true, false, "seat", "lobby", "lobby"), Err(SeatDeny::AlreadyUsed));
        assert_eq!(judge_seat_token(false, false, true, "seat", "lobby", "lobby"), Err(SeatDeny::Expired));
        assert_eq!(judge_seat_token(true, false, false, "seat", "lobby", "lobby"), Err(SeatDeny::Revoked));
        assert_eq!(judge_seat_token(false, false, false, "seat", "lobby", "hall"), Err(SeatDeny::WrongSeat));
        // A row whose claim is anything but `seat` mints nothing, whatever
        // else is true of it.
        for role in ["node", "", "SEAT", "seat "] {
            assert_eq!(judge_seat_token(false, false, false, role, "lobby", "lobby"), Err(SeatDeny::NotASeatClaim), "{role:?}");
        }
    }

    /// The guarded UPDATE re-checks every condition, including the claim, so
    /// a concurrent second redeemer gets `rows_affected = 0`.
    #[test]
    fn the_seat_claim_update_is_guarded_for_single_use() {
        let src = include_str!("seats.rs");
        let upd = src.split("UPDATE noo_seat_tokens SET used_at").nth(1).expect("the claim update");
        let guard = &upd[..upd.find(".bind(").expect("the update binds")];
        for clause in ["role = 'seat'", "used_at IS NULL", "NOT revoked", "expires_at > now()"] {
            assert!(guard.contains(clause), "the claim must re-check {clause}");
        }
    }

    /// A seat token and a node token never meet: the seat lane reads only
    /// `noo_seat_tokens`, and the node redemption only `noo_bootstrap_tokens`.
    #[test]
    fn seat_and_node_tokens_live_in_separate_tables() {
        let seats = include_str!("seats.rs");
        let prod = seats.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains("FROM noo_seat_tokens WHERE token_hash"));
        assert!(!prod.contains("FROM noo_bootstrap_tokens WHERE token_hash"), "the seat lane must not redeem node tokens");
        assert!(!prod.contains("UPDATE noo_bootstrap_tokens"), "the seat lane must not write node tokens");
        let boot = include_str!("bootstrap.rs");
        let boot = boot.split("#[cfg(test)]").next().unwrap();
        assert!(!boot.contains("noo_seat_tokens"), "the node redemption must not read seat tokens");
        assert!(!boot.contains("noo_seats"), "node birth certs never come from the seat registry");
        assert!(crate::auth_refresh::generate_seat_token().starts_with("noo-st-"));
        assert_ne!(crate::auth_refresh::SEAT_TOKEN_PREFIX, crate::auth_refresh::BOOTSTRAP_TOKEN_PREFIX);
    }

    /// The seat's rail verifies seat proofs, against the seat registry, and
    /// nothing else — every route, no unsigned branch.
    #[test]
    fn every_seat_rail_route_requires_a_seat_proof() {
        let src = include_str!("seats.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        for (handler, purpose) in [
            ("async fn seat_bundle_get(", "Purpose::SeatGet"),
            ("async fn seat_fetch_receipt(", "Purpose::SeatFetch"),
            ("async fn seat_apply_report(", "Purpose::SeatApply"),
            ("async fn seat_heartbeat(", "Purpose::SeatHeartbeat"),
        ] {
            let body = prod.split(handler).nth(1).expect(handler);
            let body = &body[..body.find("\nasync fn ").or_else(|| body.find("\n// ═")).unwrap_or(body.len())];
            assert!(body.contains("check_seat_proof("), "{handler} must check a seat proof");
            assert!(body.contains(purpose), "{handler} must sign {purpose}");
        }
        let lookup = prod.split("async fn seat_cert_for(").nth(1).unwrap();
        let lookup = &lookup[..lookup.find("\n}").unwrap()];
        assert!(lookup.contains("FROM noo_seats") && !lookup.contains("noo_bootstrap_tokens"));
    }

    /// The enrolment answer carries no credential.
    #[test]
    fn the_enrolment_response_hands_out_nothing() {
        let src = include_str!("seats.rs");
        let body = src.split("async fn seat_enroll(").nth(1).unwrap();
        let body = &body[..body.find("\n}\n").unwrap()];
        let resp = body.split("Ok(Json(json!({").nth(1).unwrap();
        for leak in ["secret", "token\"", "nats", "leaf", "key", "password"] {
            assert!(!resp.to_lowercase().contains(leak), "the seat-enroll response must not carry {leak}");
        }
    }

    /// DB-backed: mint, redeem once, refuse the second, refuse an expired
    /// one, and the CHECK refuses a non-seat claim. Runs where CI provides a
    /// scratch Postgres (`NOO_TEST_DSN`), like the other DSN-gated suites.
    #[tokio::test]
    async fn seat_tokens_round_trip_through_postgres() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — seat token round trip not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let seat = format!("seat-test-{}", std::process::id());

        let t = mint_seat_token(&db, &seat, 3600, "test").await.expect("mint");
        assert!(t.raw.starts_with("noo-st-"));
        let role: String = sqlx::query_scalar("SELECT role FROM noo_seat_tokens WHERE id = $1").bind(t.id).fetch_one(&db).await.unwrap();
        assert_eq!(role, "seat", "the claim is on the row");
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM noo_seat_tokens WHERE id = $1").bind(t.id).fetch_one(&db).await.unwrap();
        assert_ne!(stored, t.raw, "only the hash is stored");

        assert_eq!(redeem_seat_token(&db, &t.raw, "other", "127.0.0.1").await.unwrap().err().map(|e| e.0), Some(SeatDeny::WrongSeat));
        let (id, bound) = redeem_seat_token(&db, &t.raw, &seat, "127.0.0.1").await.unwrap().expect("first redemption");
        assert_eq!((id, bound.as_str()), (t.id, seat.as_str()));
        assert_eq!(redeem_seat_token(&db, &t.raw, &seat, "127.0.0.1").await.unwrap().err().map(|e| e.0), Some(SeatDeny::AlreadyUsed));

        let old = mint_seat_token(&db, &seat, 3600, "test").await.expect("mint");
        sqlx::query("UPDATE noo_seat_tokens SET expires_at = now() - interval '1 second' WHERE id = $1").bind(old.id).execute(&db).await.unwrap();
        assert_eq!(redeem_seat_token(&db, &old.raw, &seat, "127.0.0.1").await.unwrap().err().map(|e| e.0), Some(SeatDeny::Expired));

        let rev = mint_seat_token(&db, &seat, 3600, "test").await.expect("mint");
        sqlx::query("UPDATE noo_seat_tokens SET revoked = true WHERE id = $1").bind(rev.id).execute(&db).await.unwrap();
        assert_eq!(redeem_seat_token(&db, &rev.raw, &seat, "127.0.0.1").await.unwrap().err().map(|e| e.0), Some(SeatDeny::Revoked));

        assert!(sqlx::query("INSERT INTO noo_seat_tokens (token_hash, role, seat_name, created_by, expires_at) VALUES ('x', 'node', 'n', 't', now())")
            .execute(&db).await.is_err(), "the CHECK refuses a non-seat claim");
        // A node bootstrap token is not a seat token.
        assert_eq!(redeem_seat_token(&db, "noo-bt-not-a-seat-token", &seat, "127.0.0.1").await.unwrap().err().map(|e| e.0), Some(SeatDeny::Unknown));

        sqlx::query("DELETE FROM noo_seat_tokens WHERE seat_name = $1").bind(&seat).execute(&db).await.unwrap();
    }
}
