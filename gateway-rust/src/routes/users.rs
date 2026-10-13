// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! User, KB-role-grant, user-proposal, and service-key administration.
//!
//! Native Rust (SQL): ports the direct-DB logic that previously lived ONLY in
//! `security_cli.py` — the CLI opened its own SQLAlchemy engine, hashed
//! passwords locally, and mutated `noo_users` / `noo_kb_role_grants` /
//! `noo_user_proposals` / `noo_service_keys` in-process. Moving it here gives
//! every client (CLI, dashboard, agents) one audited path; the CLI is now a
//! thin caller.
//!
//! Auth: sits behind `require_any_auth` like the rest of the control plane —
//! cluster-HMAC (host operator CLI) or admin/write JWT. Read-scope JWTs can
//! GET (dashboard visibility) but mutations are blocked by `scope_allows`.
//! Attribution: mutations record the `AuthActor` (JWT sub) when present,
//! else "cluster-cli".

use std::sync::Arc;
use axum::{
    Router,
    routing::{delete, get, post, put},
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{AuthActor, RequesterCtx};
use crate::state::AppState;
use super::{AppError, AppResult};

// Python subjects this module has replaced. See `crate::ported`.
crate::ported! {
    POST "/api/users/propose" => "worker.api.users.propose",
}


/// Scopes a service key may carry (external inference contract;
/// "mcp" gates the external MCP hub surface). "kiosk" is NOT here any more:
/// the kiosk key lane was retired on 2026-09-30, the scope is refused at
/// issuance by name (`service_keys::RETIRED_KEY_SCOPES`), and a key that
/// still carries it resolves to nothing on every route.
// `addon` is a plain scope, not in the operator tier: an exchanged add-on
// token carries the key's OTHER scopes minus `addon` (`auth::addon_token_scopes`),
// so it never grants more than the key already holds — unlike `identity`,
// which mints tokens for accounts. PR 343 declared the scope at the DOOR and
// not here, so the door existed and no key the gateway would mint could open
// it; the first live provision was refused with "unknown scope(s): [\"addon\"]".
// `every_exchange_door_scope_is_issuable` holds the two declarations together.
//
// Control scopes (`auth::is_control_scope`: `temporal`, `heartbeat`,
// `config:<section>`, `conversation_stats`, …) are issuable but deliberately NOT here: this list is
// also the DEFAULT for a key issued without scopes, and a default must never
// carry a control-plane write.
const SERVICE_KEY_SCOPES: &[&str] = &[
    "chat", "embeddings", "rerank", "classify", "mcp",
    crate::auth::ADDON_SCOPE,
];

/// What each plain scope opens, for `GET /api/security/service-keys/scopes`
/// (`provision` shows the operator the route beside each
/// word before minting). The handlers enforce these words inline
/// (`consumer.has_scope(..)`), so this is their index, not their authority;
/// `every_issuable_scope_says_what_it_opens` insists every word in
/// `SERVICE_KEY_SCOPES` and `OPERATOR_ONLY_KEY_SCOPES` has exactly one row.
/// The control scopes need no row here: `auth::CONTROL_SCOPE_ROUTES` (writes)
/// and `auth::CONTROL_READ_SCOPE_ROUTES` (reads) ARE what they open, and the
/// listing reads both directly (`auth::control_scope_rows`).
const SCOPE_OPENS: &[(&str, &[&str])] = &[
    ("chat", &["POST /v1/chat/completions", "POST /api/external/chat/completions",
               "POST /api/external/inference (chat)"]),
    ("embeddings", &["POST /api/external/embeddings", "POST /api/external/inference (embeddings)"]),
    ("rerank", &["POST /api/external/rerank", "POST /api/external/inference (rerank)"]),
    ("classify", &["POST /api/external/classify", "POST /api/external/inference (classify)"]),
    ("mcp", &["POST /mcp/user"]),
    (crate::auth::ADDON_SCOPE, &["POST /api/addon/token"]),
    (crate::mcp_local::OPERATOR_SCOPE, &["POST /mcp/operator"]),
    (crate::auth::IDENTITY_SCOPE, &["POST /api/identity/token"]),
];

fn scope_opens(scope: &str) -> Vec<&'static str> {
    SCOPE_OPENS.iter().find(|(s, _)| *s == scope).map(|(_, o)| o.to_vec()).unwrap_or_default()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Users (noo_users) ──
        .route("/api/security/users", get(users_list).post(user_create))
        .route("/api/security/users/{username}/password", put(user_set_password))
        .route("/api/security/users/{username}/disable", post(user_disable))
        // Account role (user/operator/admin) — the coarse
        // permission tier. Admin-only (see scope_mutation_guard: granting
        // privilege requires Admin, never Operator). Distinct from /roles
        // below, which grants KB *roles*, a different axis entirely.
        .route("/api/security/users/{username}/role", post(user_set_role))
        // Auth scopes (read/write/admin/peer) — admin-only, see scope_mutation_guard.
        // DEPRECATED: roles are the grant; this endpoint stays
        // for the dual-accept window and re-derives the role column from the
        // scopes it writes (repo::users::set_scopes). Prefer …/role above.
        // Distinct from /roles below, which grants KB *roles*, a different axis.
        .route("/api/security/users/{username}/scopes", post(user_set_scopes))
        // ── KB provenance rules + team registry ──
        //
        // the design gaps 2 and 3. These reuse the legacy handlers verbatim:
        // both surfaces already call the same repo functions, so there is no
        // second implementation to keep in step — only a second path.
        //
        // Naming is REST-shaped rather than a literal copy. The legacy forms
        // `/api/kb/rule` (singular; upsert or delete depending on a body flag)
        // and `/api/kb/teams/create` put the verb in the path, which nothing
        // else on `/api/security/*` does. `/api/kb/rule` itself is gone
        // (2026-09-27, the design: its only caller was the deleted
        // legacy console); `api_kb_rule` is served here alone.
        .route("/api/security/kb-rules", get(api_kb_rules).post(api_kb_rule))
        .route("/api/security/teams", get(api_kb_teams).post(api_kb_teams_create))
        .route("/api/security/teams/{team}", delete(security_team_delete))
        // ── Security posture (noo_security_posture) — operator-only, restart-to-apply ──
        .route("/api/security/posture", get(posture_list).post(posture_set))
        .route("/api/security/posture/profile", post(posture_apply_profile))
        // RTBF erasure: dry-run by default; archive-then-delete across all
        // user-scoped stores into noo_user_erasure_staging (migration 026).
        .route("/api/security/users/{username}/erase", post(user_erase))
        // What the erase archive holds and how old its oldest copy is
        // (`erasure_archive.rs`): the controller verify row reads it.
        .route("/api/security/erasure-archive", get(erasure_archive_status))
        // ── Orgs (noo_orgs) — the top tenant boundary (PR5) ──
        .route("/api/security/orgs", get(orgs_list).post(org_create))
        .route("/api/security/users/{username}/org", post(user_set_org))
        // ── Channel identity links (noo_user_channel_links) ──
        // Maps an opaque per-channel sender id (Telegram chat_id, Google Chat
        // "users/123", WhatsApp phone) → a canonical noo_users username, so an
        // inbound channel message is scoped to the same identity as that
        // person's terminal/CLI/JWT session (multi-user PR2). Unlink takes the
        // key in the body, not the path, because channel_user_id can contain
        // slashes ("users/123") which would break path parsing.
        .route("/api/security/users/{username}/links", get(user_links_list).post(user_link_create))
        .route("/api/security/channel-links/unlink", post(channel_link_delete))
        // ── Space→team links (noo_channel_team_links) — shared team channels (PR5c) ──
        .route("/api/security/teams/{team}/spaces", get(team_spaces_list).post(team_space_link))
        .route("/api/security/channel-team-links/unlink", post(team_space_unlink))
        // ── KB role grants (noo_kb_role_grants) ──
        .route("/api/security/role-grants", get(role_grants_list))
        .route("/api/security/users/{username}/roles", post(user_grant_roles))
        .route("/api/security/users/{username}/roles/revoke", post(user_revoke_roles))
        // ── User-management proposals (noo_user_proposals) ──
        //
        // the propose/approve workflow is the
        // User→Operator escalation path on this surface. Filing reuses the
        // legacy handler verbatim (one implementation, two paths — the
        // kb-rules/teams precedent); listing and deciding already lived here
        // under `user-proposals`, addressed by path param, so those routes
        // stay rather than growing `/users/proposals` aliases.
        .route("/api/security/users/propose", post(api_users_propose))
        .route("/api/security/user-proposals", get(proposals_list))
        .route("/api/security/user-proposals/{id}", get(proposal_get))
        .route("/api/security/user-proposals/{id}/decide", post(proposal_decide))
        // ── Service keys (noo_service_keys) ──
        .route("/api/security/service-keys", get(service_keys_list).post(service_key_issue))
        // Self-service MCP key (any authenticated account, incl. the User
        // tier — see auth::SELF_SERVICE_KEY_PATHS). Registered BEFORE the
        // `{consumer}` routes below: `self` is a static segment and matchit
        // prefers static over dynamic, but declaring it first keeps the
        // precedence visible to a reader rather than implied by the router.
        .route(
            "/api/security/service-keys/self",
            get(service_key_self_status).post(service_key_self_issue),
        )
        .route(
            "/api/security/service-keys/self/revoke",
            post(service_key_self_revoke),
        )
        // The scope vocabulary and what each word opens (the design phase
        // B). Static segment, registered before the `{consumer}` routes for
        // the same reason `self` is.
        .route("/api/security/service-keys/scopes", get(service_key_scopes))
        .route("/api/security/service-keys/{consumer}/revoke", post(service_key_revoke))
        // the kill switch. One call, one transaction — see
        // `service_key_revoke_and_disable` for why it is not two.
        .route(
            "/api/security/service-keys/{consumer}/revoke-and-disable",
            post(service_key_revoke_and_disable),
        )
        .route("/api/security/service-keys/{consumer}/rotate", post(service_key_rotate))
        .route("/api/security/service-keys/{consumer}/retire", post(service_key_retire))
        .route("/api/security/service-keys/{consumer}/quota", post(service_key_set_quota))
        // ── Mesh-UI contract surface (openapi.json) — native ports of the
        //    Python worker.api.users.* / worker.api.kb.* NATS handlers.
        //    Explicit routes here shadow the /api/{*path} Python catch-all.
        .route("/api/users", get(api_users_list))
        .route("/api/users/disable", post(api_users_disable))
        .route("/api/users/propose", post(api_users_propose))
        .route("/api/users/proposals", get(api_users_proposals))
        .route("/api/kb/grants", get(api_kb_grants))
        .route("/api/kb/rules", get(api_kb_rules))
        .route("/api/kb/teams", get(api_kb_teams))
        .route("/api/kb/teams/create", post(api_kb_teams_create))
        .route("/api/kb/teams/delete", post(api_kb_teams_delete))
}

fn actor(ext: &Option<Extension<AuthActor>>) -> String {
    ext.as_ref()
        .map(|Extension(AuthActor(sub))| sub.clone())
        .unwrap_or_else(|| "cluster-cli".to_string())
}

fn hash_password(pw: &str) -> Result<String, AppError> {
    bcrypt::hash(pw, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("password hash failed: {e}")))
}

// ═══════════════════════════════════════════════════════════════
// Users
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/users
/// GET /api/security/users — the account list.
///
/// Uses `list_with_lock` so `locked_until` is present.
/// Without it this surface showed `disabled` and `failed_login_count` but not
/// the lockout itself, so a temporarily locked-out account was indistinguishable
/// from a healthy one that had simply mistyped its password a few times — and
/// the operator's next question, "is this user locked out right now?", could
/// only be answered on the legacy surface. Purely additive for existing callers.
///
/// Read-guarded like the legacy `api_users_list`:
/// account enumeration is operator-only even on GET;
/// cluster-HMAC/internal callers (no `RequesterCtx`) pass, exactly as on the
/// legacy surface.
async fn users_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = crate::repo::users::list_with_lock(&state.db).await?;

    let users: Vec<Value> = rows
        .into_iter()
        .map(|(username, disabled, scopes, created, last_login, failed, locked_until, role)| {
            json!({
                "username": username,
                "disabled": disabled,
                "scopes": scopes,
                "role": role,
                "created_at": created,
                "last_login_at": last_login,
                "failed_login_count": failed,
                "locked_until": locked_until,
            })
        })
        .collect();
    Ok(Json(json!({ "users": users, "count": users.len() })))
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
}

/// What a new account gets when the caller does not say (operator
/// decision, 2026-09-04): **read only**, i.e. the `User` tier.
///
/// It used to be `["read", "write"]`, which `Role::from_scopes` resolves
/// to **Operator** — so every account made through this endpoint without
/// explicit scopes was an operator, and the User tier the rest of the
/// authorization model is built around barely existed.
/// Existing accounts are unaffected: they carry stored scopes, and this
/// is only the default for new ones. Grant more with
/// `noo security users set-scopes <user> read write`.
fn default_scopes() -> Vec<String> {
    vec!["read".into()]
}

/// POST /api/security/users
///
/// Workflow-gated: sub-operator and cluster-HMAC callers
/// are redirected to `POST /api/security/users/propose` — see
/// `security_users_mutation_guard`.
async fn user_create(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<CreateUserBody>,
) -> AppResult {
    let by = security_users_mutation_guard(&ctx)?.sub.clone();
    // the requested scopes decide the new account's tier
    // (`repo::users::create` derives `role` from them), so an unclamped
    // create was the Operator→Admin escalation in one request.
    require_may_grant(&ctx, &body.scopes)?;
    crate::auth::valid_account_name(body.username.trim()).map_err(AppError::BadRequest)?;
    if body.username.trim().is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }
    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }
    let hashed = hash_password(&body.password)?;
    // disabled/failed_login_count set explicitly for pre-migration-020 schemas.
    let result = crate::repo::users::create(&state.db, &body.username, &hashed, &json!(body.scopes), None)
        .await?;

    if result == 0 {
        return Err(AppError::Conflict(format!(
            "user '{}' already exists",
            body.username
        )));
    }
    tracing::info!(user = %body.username, by = %by, "user_created");
    crate::routes::core::audit_event(
        &state.db,
        "user_create",
        "info",
        &by,
        body.username.trim(),
        "ok",
        json!({ "scopes": body.scopes }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "username": body.username,
        "scopes": body.scopes,
    })))
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

/// PUT /api/security/users/{username}/password
///
/// Workflow-gated — see `security_users_mutation_guard`.
async fn user_set_password(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<PasswordBody>,
) -> AppResult {
    let by = security_users_mutation_guard(&ctx)?.sub.clone();
    // a password reset is a full account takeover — and this statement
    // also clears `locked_until`, so it is the lockout bypass too.
    require_may_manage(&state.db, &ctx, &username).await?;
    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }
    let hashed = hash_password(&body.password)?;
    let result = sqlx::query(
        "UPDATE noo_users SET hashed_password = $1, password_changed_at = NOW(), \
         failed_login_count = 0, locked_until = NULL WHERE username = $2",
    )
    .bind(&hashed)
    .bind(&username)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("user '{username}' not found")));
    }
    tracing::info!(user = %username, by = %by, "password_changed");
    crate::routes::core::audit_event(
        &state.db,
        "user_set_password",
        "info",
        &by,
        username.trim(),
        "ok",
        json!({}),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "username": username })))
}

/// POST /api/security/users/{username}/disable
///
/// Workflow-gated — see `security_users_mutation_guard`.
async fn user_disable(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let by = security_users_mutation_guard(&ctx)?.sub.clone();
    require_may_manage(&state.db, &ctx, &username).await?;
    require_not_last_admin(&state.db, &username, "disable").await?;
    // Same self-lockout rule as `exec_user_set_disabled` (the legacy
    // `/api/users/disable` route): meaningful here now that the guard means
    // `by` is always a named account rather than "cluster-cli".
    if by == username.trim() {
        return Err(AppError::BadRequest(
            "cannot disable your own account".into(),
        ));
    }
    let result = crate::repo::users::set_disabled(&state.db, &username, true).await?;
    if result == 0 {
        return Err(AppError::NotFound(format!("user '{username}' not found")));
    }
    tracing::info!(user = %username, by = %by, "user_disabled");
    crate::routes::core::audit_event(
        &state.db,
        "user_set_disabled",
        "info",
        &by,
        username.trim(),
        "ok",
        json!({ "disabled": true }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "username": username, "disabled": true })))
}

#[derive(Deserialize)]
struct SetScopesBody {
    scopes: Vec<String>,
}

/// POST /api/security/users/{username}/scopes — body {scopes: [..]}.
///
/// The scopes list **replaces** the account's scopes; it does not merge. Send
/// the full intended set (`["read","write"]`, not `["write"]`) or the omitted
/// ones are dropped.
///
/// Closes gap 1 of followups/32: `/api/security/*` had no way to change an
/// account's auth scopes, so the only path was the legacy `/api/users/scopes`
/// (removed 2026-09-27; this route replaced it). Runs through
/// `exec_user_set_scopes`, so the username, unknown-scope and self-lockout
/// checks live in one place. `proposal_decide` applies an approved `scopes`
/// proposal inline and does not repeat the self-lockout check.
async fn user_set_scopes(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<SetScopesBody>,
) -> AppResult {
    let by = scope_mutation_guard(&ctx)?.sub.clone();
    require_may_manage(&state.db, &ctx, &username).await?;
    // Dropping `admin` here demotes the account (repo::users::set_scopes
    // re-derives `role`), so the last-admin guard applies to this path too.
    if crate::auth::Role::from_scopes(&body.scopes) < crate::auth::Role::Admin {
        require_not_last_admin(&state.db, &username, "demote").await?;
    }
    let outcome = exec_user_set_scopes(&state.db, &username, Some(body.scopes), &by)
        .await
        .map_err(AppError::BadRequest)?;
    crate::routes::core::audit_event(
        &state.db,
        "user_set_scopes",
        "info",
        &by,
        username.trim(),
        "ok",
        json!({ "scopes": outcome["scopes"] }),
    )
    .await;
    tracing::info!(user = %username.trim(), by = %by, "user_set_scopes");
    Ok(Json(outcome))
}

#[derive(Deserialize)]
struct SetRoleBody {
    role: String,
}

/// POST /api/security/users/{username}/role — body {role: "user"|"operator"|"admin"}.
///
/// Assigns the account's permission tier. **Admin-only**, via
/// the same guard as the scopes endpoint and for the same reason (the PR#460
/// asymmetry): granting privilege requires `Admin`; an `Operator` that could
/// assign roles could assign itself `admin`, and a ceiling you can edit is
/// not a ceiling. Cluster-HMAC is refused — a role change must name who made
/// it.
///
/// The legacy `scopes` column is re-derived from the new role atomically
/// (`repo::users::set_role`), so dual-accept validators and the Python KB
/// resolver see the change immediately; non-tier scopes (ingest/peer) are
/// preserved.
async fn user_set_role(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<SetRoleBody>,
) -> AppResult {
    let by = scope_mutation_guard(&ctx)?.sub.clone();
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }
    let role: crate::auth::Role = body
        .role
        .trim()
        .parse()
        .map_err(AppError::BadRequest)?;
    // Self-demotion lockout guard, mirroring exec_user_set_scopes: the last
    // admin dropping their own tier strands the identity surface behind an
    // account that can no longer administer it.
    if by == username && role < crate::auth::Role::Admin {
        return Err(AppError::BadRequest(
            "cannot drop your own admin role".into(),
        ));
    }
    require_may_manage(&state.db, &ctx, &username).await?;
    if role < crate::auth::Role::Admin {
        require_not_last_admin(&state.db, &username, "demote").await?;
    }
    let updated = crate::repo::users::set_role(&state.db, &username, role).await?;
    if updated == 0 {
        return Err(AppError::NotFound(format!("user '{username}' not found")));
    }
    // Audited with the username and the new role, NOTHING else.
    crate::routes::core::audit_event(
        &state.db,
        "user_set_role",
        "info",
        &by,
        &username,
        "ok",
        json!({ "role": role.as_str() }),
    )
    .await;
    tracing::info!(user = %username, role = %role.as_str(), by = %by, "user_set_role");
    Ok(Json(json!({ "username": username, "role": role.as_str() })))
}

// ═══════════════════════════════════════════════════════════════
// Security posture (noo_security_posture) — operator-only, restart-to-apply
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/posture — the app-tier security gates: what's running now
/// (from env, set at boot), the desired DB value, and whether a restart is
/// pending. Readable by any authenticated caller (visibility); the app UI shows
/// it read-only.
async fn posture_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    // Which security gates are open is operator information: it tells a
    // prober whether the external MCP door is open.
    users_admin_read_guard(&ctx)?;
    // Previously `.unwrap_or_default()`. On any DB failure every gate then
    // reported `db_value: null, source: "env", pending_restart: false` — i.e.
    // "the running process matches the desired posture, nothing pending". On a
    // SECURITY surface that is the exact wrong answer to give on failure: an
    // operator who had just tightened a gate would be told it was already in
    // effect. Propagate instead; the caller gets a 500, not a false all-clear.
    //
    // A missing table is deliberately NOT special-cased to an empty posture:
    // `noo_security_posture` is created by migration, and its absence means the
    // schema is wrong, not that the operator has set no gates.
    // `opened_at` is the bridge's own clock; `updated_at` is the fallback for a
    // row written before migration 074, and the flag says which one answered so
    // the CLI can present an inferred age as inferred.
    let db_rows = sqlx::query_as::<_, (String, String, Option<f64>, bool)>(
        "SELECT key, value, \
                (EXTRACT(EPOCH FROM (NOW() - COALESCE(opened_at, updated_at))) / 86400.0)::float8, \
                (opened_at IS NULL) \
         FROM noo_security_posture",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        AppError::Internal(format!(
            "cannot read security posture from noo_security_posture: {e}"
        ))
    })?;
    let db_of = |k: &str| db_rows.iter().find(|(key, ..)| key == k).map(|(_, v, ..)| v.clone());
    let age_of = |k: &str| {
        db_rows
            .iter()
            .find(|(key, ..)| key == k)
            .map(|(_, _, age, from_update)| (age.unwrap_or(0.0) as i64, *from_update))
    };

    let gates: Vec<Value> = crate::posture::POSTURE_CATALOG
        .iter()
        .map(|entry| {
            let key = entry.key;
            let running = std::env::var(key).ok();
            let desired = db_of(key);
            // Pending = the DB says one thing but the running process (env set at
            // boot) has another → takes effect on the next restart.
            let pending = desired.is_some() && desired.as_deref() != running.as_deref();
            json!({
                "key": key,
                // Gate or bridge (R43). A bridge is a rollout state the
                // operator holds open on purpose, so `apply-profile` leaves it
                // alone — the listing has to say which is which or an operator
                // cannot tell why a profile did not touch a row.
                "kind": entry.kind.as_str(),
                "why": entry.why,
                "running": running,
                "db_value": desired,
                "source": if db_of(key).is_some() { "db" } else if running.is_some() { "env" } else { "default" },
                // Constant, and correct as a constant — not a per-key lookup.
                // posture::apply_security_posture writes the DB posture into
                // the process env ONCE at boot, before any gate accessor runs,
                // and every key here is a member of POSTURE_KEYS which goes
                // through that path. So "requires a restart to take effect" is
                // a property of the mechanism, true for the whole allow-list by
                // construction. (The noo_security_posture.requires_restart
                // column exists but is written TRUE unconditionally by
                // posture_set / posture_apply_profile below, so reading it back
                // would add a query without adding information.) If a gate is
                // ever made hot-reloadable, this must become per-key.
                "requires_restart": true,
                "pending_restart": pending,
                // A bridge's lifetime. Absent for a gate, and absent for a
                // bridge sitting at its closed value — a closed bridge is not
                // holding anything open and has no clock to report.
                "bridge": desired.as_deref().and_then(|v| {
                    let (days, from_update) = age_of(key)?;
                    let b = crate::posture::bridge_standing(key, v, days, from_update)?;
                    Some(json!({
                        "open_days": b.open_days,
                        "window_days": b.window_days,
                        "overdue_days": b.overdue_days(),
                        "overdue": b.is_overdue(),
                        "dated_from_update": b.dated_from_update,
                    }))
                }),
            })
        })
        .collect();
    // DB rows for keys the catalog no longer has — a retired bridge
    // (`NOO_NATS_LEGACY_SHARED_CREDS`) left behind in the
    // table. Boot skips them, so they change nothing; they are listed so
    // `noo cluster verify --controller` can say one is still set rather
    // than the listing silently hiding it.
    let retired: Vec<Value> = db_rows
        .iter()
        .filter(|(key, ..)| !crate::posture::is_posture_key(key))
        .map(|(key, value, ..)| json!({ "key": key, "value": value }))
        .collect();
    Ok(Json(json!({ "posture": gates, "count": gates.len(), "retired": retired })))
}

#[derive(Deserialize)]
struct PostureSetBody {
    key: String,
    value: String,
}

/// Write one posture row, stamping a bridge's lifetime alongside its value.
///
/// Three rules, and each one is a bug we have already paid for:
///
/// - Closing a bridge CLEARS `opened_at`/`close_by`. A closed bridge owes
///   nobody an account, and a stale open date would keep warning forever.
/// - Re-writing an already-open bridge KEEPS the original `opened_at`
///   (`COALESCE` on the existing row, not `NOW()`). Otherwise every
///   `apply-profile` run, every re-set of the same value, silently restarts
///   the clock — and the bridge touched most often, which is the one in active
///   migration, would be the one that never ages.
/// - A GATE gets NULLs. It has no lifetime; it is a standing property.
async fn posture_write(db: &sqlx::PgPool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    let window: Option<i64> = match crate::posture::kind_of(key) {
        Some(crate::posture::PostureKind::Bridge { closed, window_days }) if value != closed => {
            Some(window_days)
        }
        _ => None,
    };
    sqlx::query(
        "INSERT INTO noo_security_posture \
             (key, value, requires_restart, updated_by, updated_at, opened_at, close_by) \
         VALUES ($1, $2, TRUE, 'operator', NOW(), \
                 CASE WHEN $3::BIGINT IS NULL THEN NULL ELSE NOW() END, \
                 CASE WHEN $3::BIGINT IS NULL THEN NULL \
                      ELSE NOW() + make_interval(days => $3::INT) END) \
         ON CONFLICT (key) DO UPDATE SET \
             value = EXCLUDED.value, updated_by = 'operator', updated_at = NOW(), \
             opened_at = CASE WHEN $3::BIGINT IS NULL THEN NULL \
                              ELSE COALESCE(noo_security_posture.opened_at, NOW()) END, \
             close_by  = CASE WHEN $3::BIGINT IS NULL THEN NULL \
                              ELSE COALESCE(noo_security_posture.opened_at, NOW()) \
                                   + make_interval(days => $3::INT) END",
    )
    .bind(key)
    .bind(value)
    .bind(window)
    .execute(db)
    .await?;
    Ok(())
}


/// POST /api/security/posture — set an app-tier gate. **Operator-only**:
/// an app login is refused, however privileged. Admitted on an operator
/// client certificate plus an Admin token bound to it, and on nothing else
/// — no shared secret (`crate::operator_auth`). The
/// change is DB-authoritative + tamper-evident-audited, and takes effect on the
/// next gateway restart (the gates are read once at boot).
async fn posture_set(
    State(state): State<Arc<AppState>>,
    facts: super::operator_certs::CallerFacts,
    Json(body): Json<PostureSetBody>,
) -> AppResult {
    // App-admin (JWT) must NOT be able to weaken posture from the app. The
    // operator writes posture with an operator client certificate AND an
    // Admin token bound to it, and with nothing else — the shared secret is
    // refused (`crate::operator_auth`). Read-only in the UI.
    let admission = super::operator_certs::posture_admission(&state, &facts, "/api/security/posture").await?;
    let key = body.key.trim();
    let value = body.value.trim();
    // A RETIRED bridge may be written to its closed value and to nothing
    // else: that is the one write the boot refusal
    // (`posture::retired_bridge_refusal`) tells the operator to make, and it
    // must not need SQL.
    if let Some(b) = crate::posture::retired_bridge(key) {
        if b.closed != value {
            return Err(AppError::BadRequest(format!(
                "'{key}' is a RETIRED bridge; {}. The only write accepted is its closed value: \
                 `noo security posture set {key} {}`",
                b.now, b.closed
            )));
        }
    } else if crate::posture::RETIRED_INERT_KEYS.contains(&key) {
        // The same one write for a retired key that never became a
        // RetiredBridge (`NOO_NATS_LEGACY_SHARED_CREDS`): closing a row still
        // held open, so the next boot deletes it (`retired_rows_to_clear`).
        if value != "0" {
            return Err(AppError::BadRequest(format!(
                "'{key}' is RETIRED; the only write accepted is its closed value: \
                 `noo security posture set {key} 0` (the next gateway start then deletes the row)"
            )));
        }
    } else if !crate::posture::is_posture_key(key) {
        return Err(AppError::BadRequest(format!(
            "'{key}' is not an app-tier posture gate (allowed: {:?})",
            crate::posture::posture_keys().collect::<Vec<_>>()
        )));
    }
    posture_write(&state.db, key, value).await?;
    // Tamper-evident audit sink (not the JSONL) — posture changes are high-value.
    // The actor names the operator when an operator certificate admitted the
    // write, and the shared-secret lane otherwise.
    crate::routes::core::audit_event(
        &state.db,
        "security_posture_set",
        "warning",
        &admission.audit_actor(),
        key,
        "ok",
        json!({ "key": key, "value": value, "effect": "next restart" }),
    )
    .await;
    tracing::warn!(gate = %key, value = %value, "security_posture_set (restart to apply)");
    Ok(Json(json!({
        "status": "ok",
        "key": key,
        "value": value,
        // Constant by construction — this handler's own INSERT writes
        // requires_restart = TRUE, and posture is only ever applied at boot.
        // See the note in posture_list.
        "requires_restart": true,
        "note": "takes effect on the next gateway restart",
    })))
}

/// Vetted posture bundles. `hardened` = the customer-distribution default;
/// `dev` = permissive local. Each takes effect on the next restart.
///
/// **GATE keys only.** A bundle describes an environment, so it may only set
/// the keys that ARE properties of an environment. Bridge keys
/// (`posture::PostureKind::Bridge`) are deliberately absent and the parity
/// test refuses to let one back in — see `posture_apply_profile` and
/// for what happened when they were here.
fn posture_profile(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "hardened" => Some(&[
            ("NOO_EXEC_APPROVAL_MODE", "approval"),
            ("NOO_NODE_AGENT_PRIVILEGED", "false"),
            // Closed in BOTH profiles, deliberately — not an oversight that
            // `dev` agrees with `hardened` here. The external MCP door exposes
            // cluster tools to someone else's agent, so OPENING it is a
            // decision about a specific person, never a side effect of
            // applying a bundle. Operators open it with an explicit
            // single-key `posture set`.
            //
            // It stays a GATE rather than joining the bridges: closing a door
            // is the safe direction, and a door left open because a bundle
            // declined to touch it is how "hardened" stops meaning anything.
            // The before/after diff `apply-profile` now prints is what makes
            // the closing visible, which was the real complaint.
            ("NOO_MCP_EXTERNAL_ENABLED", "0"),
            // (NOO_APPROVAL_BREAK_GLASS, closed in both profiles, is RETIRED
            // — `posture::RETIRED_BRIDGES`. No profile names it.)
        ]),
        "dev" => Some(&[
            ("NOO_EXEC_APPROVAL_MODE", "auto"),
            ("NOO_NODE_AGENT_PRIVILEGED", "true"),
            ("NOO_MCP_EXTERNAL_ENABLED", "0"),
        ]),
        _ => None,
    }
}

#[derive(Deserialize)]
struct ProfileBody {
    profile: String,
    /// Also close every BRIDGE key to its safe value. Off by default: a bridge
    /// is open because the operator opened it, and only the operator knows
    /// whether the last node has crossed.
    #[serde(default)]
    include_bridges: bool,
}

/// POST /api/security/posture/profile — apply a vetted posture bundle in one
/// step. **Operator-only** (same as posture_set); each gate is upserted +
/// tamper-evident-audited; takes effect on the next restart.
///
/// Sets GATE keys only. BRIDGE keys are read and REPORTED but not written,
/// unless `include_bridges` is set, in which case each is closed to its
/// catalog `closed` value. The response carries a full before/after diff so
/// the operator can see what moved instead of inferring it from a count:
/// R43 was a bridge being closed silently, and "applied 7 gates" said nothing
/// about which of the seven had actually changed.
async fn posture_apply_profile(
    State(state): State<Arc<AppState>>,
    facts: super::operator_certs::CallerFacts,
    Json(body): Json<ProfileBody>,
) -> AppResult {
    // Same gate as `posture_set`.
    let admission =
        super::operator_certs::posture_admission(&state, &facts, "/api/security/posture/profile").await?;
    let name = body.profile.trim();
    let gates = posture_profile(name).ok_or_else(|| {
        AppError::BadRequest(format!("unknown profile '{name}' (available: hardened, dev)"))
    })?;

    // Read the CURRENT desired posture first, so the diff is a diff. Fails the
    // request rather than reporting an empty "before": a before/after where
    // "before" silently became null would claim every row changed.
    let before = sqlx::query_as::<_, (String, String)>(
        "SELECT key, value FROM noo_security_posture",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        AppError::Internal(format!(
            "cannot read the current posture before applying '{name}': {e}"
        ))
    })?;
    let value_of = |k: &str| before.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());

    // What to write: the profile's gates, plus — only on request — every
    // bridge closed to its own safe value. The closing value lives in the
    // catalog, not in each profile, so a new profile cannot forget one and a
    // bridge cannot be closed to two different values by two profiles.
    let mut writes: Vec<(&str, &str)> = gates.iter().map(|(k, v)| (*k, *v)).collect();
    if body.include_bridges {
        for entry in crate::posture::bridge_keys() {
            if let crate::posture::PostureKind::Bridge { closed, .. } = entry.kind {
                writes.push((entry.key, closed));
            }
        }
    }

    let mut changed: Vec<Value> = Vec::new();
    let mut unchanged: Vec<Value> = Vec::new();
    for (key, value) in &writes {
        let prev = value_of(key);
        posture_write(&state.db, key, value).await?;
        let row = json!({
            "key": key,
            "from": prev,
            "to": value,
            "kind": crate::posture::kind_of(key).map(|k| k.as_str()),
        });
        if prev.as_deref() == Some(*value) {
            unchanged.push(row);
        } else {
            changed.push(row);
        }
    }

    // Bridges the profile did NOT touch, with their current values — the part
    // that makes the omission auditable rather than invisible. `open` flags a
    // bridge that is currently holding something open, which is a weakening
    // the operator should see every time they harden an install.
    let skipped: Vec<Value> = if body.include_bridges {
        Vec::new()
    } else {
        crate::posture::bridge_keys()
            .map(|entry| {
                let current = value_of(entry.key);
                let closed = match entry.kind {
                    crate::posture::PostureKind::Bridge { closed, .. } => closed,
                    crate::posture::PostureKind::Gate => "",
                };
                // "Not closed" = set to something other than the safe value.
                // An UNSET bridge is not open: the key's own code default
                // decides, and that default is the key's business, not ours.
                let open = current.as_deref().is_some_and(|v| v != closed);
                json!({
                    "key": entry.key,
                    "value": current,
                    "closed_value": closed,
                    "open": open,
                    "why": entry.why,
                })
            })
            .collect()
    };
    let bridges_open: Vec<&str> = skipped
        .iter()
        .filter(|b| b["open"] == json!(true))
        .filter_map(|b| b["key"].as_str())
        .collect();

    crate::routes::core::audit_event(
        &state.db,
        "security_posture_profile",
        "warning",
        &admission.audit_actor(),
        name,
        "ok",
        json!({
            "profile": name,
            "gates": writes.len(),
            "changed": changed,
            "include_bridges": body.include_bridges,
            "bridges_left_alone": skipped.iter().filter_map(|b| b["key"].as_str()).collect::<Vec<_>>(),
            "bridges_open": bridges_open,
            "effect": "next restart",
        }),
    )
    .await;
    tracing::warn!(
        profile = %name,
        wrote = writes.len(),
        changed = changed.len(),
        include_bridges = body.include_bridges,
        bridges_open = bridges_open.len(),
        "security_posture_profile_applied"
    );
    Ok(Json(json!({
        "status": "ok",
        "profile": name,
        // `applied` is every key WRITTEN — kept for older clients, which
        // printed it as "applied N gates".
        "applied": writes.len(),
        "changed": changed,
        "unchanged": unchanged,
        "bridges_skipped": skipped,
        "include_bridges": body.include_bridges,
        // Constant by construction — same reasoning as posture_set above.
        "requires_restart": true,
    })))
}

// ═══════════════════════════════════════════════════════════════
// RTBF erasure (noo_user_erasure_staging)
// ═══════════════════════════════════════════════════════════════

/// One store to erase. `where_sql` is a CONSTANT SQL fragment binding `$1` to
/// the username — never user input, so `format!`-ing it into the statement is
/// injection-safe (the username is always a bound parameter).
struct EraseTarget {
    label: &'static str,
    table: &'static str,
    where_sql: &'static str,
}

impl EraseTarget {
    fn count_sql(&self) -> String {
        format!("SELECT COUNT(*) FROM {} WHERE {}", self.table, self.where_sql)
    }

    /// `$1` = username, `$2` = run_id, `$3` = store label.
    fn snapshot_sql(&self) -> String {
        format!(
            "INSERT INTO noo_user_erasure_staging (run_id, username, store, payload) \
             SELECT $2, $1, $3, to_jsonb(x) FROM {} x WHERE {}",
            self.table, self.where_sql
        )
    }

    fn delete_sql(&self) -> String {
        format!("DELETE FROM {} WHERE {}", self.table, self.where_sql)
    }
}

/// Conversation-subtree rows tie to the user only via their conversation.
const CONV_SUBQ: &str =
    "conversation_id IN (SELECT id FROM noo_conversations WHERE user_id = $1)";

/// Episode rows (`trellion_episodes`) carry the private question text
/// (`content_summary`) and an embedding of it, one per captured walk. They
/// are the user's when they say so (`user_id`, written since trellion
/// migration 104) OR when a traversal record of the user's points at them
/// (`video_frame_id`: every episode captured before 104, and the net if an
/// episode's own `user_id` was never set). Must run BEFORE
/// `video_traversals`, or the second branch has nothing left to match on.
const EPISODE_WHERE: &str = "user_id = $1 OR id IN (SELECT video_frame_id \
     FROM trellion_traversal_records WHERE user_id = $1 AND video_frame_id IS NOT NULL)";

/// The same, for a trellion that has not run migration 104 yet: no
/// `trellion_episodes.user_id` column to match, only the frame link. Erasure
/// is a legal obligation; a deploy-order skew must not make it error.
const EPISODE_WHERE_NO_OWNER_COLUMN: &str = "id IN (SELECT video_frame_id \
     FROM trellion_traversal_records WHERE user_id = $1 AND video_frame_id IS NOT NULL)";

/// Which episode predicate applies, given whether the column exists.
fn episode_where(has_user_id_column: bool) -> &'static str {
    if has_user_id_column { EPISODE_WHERE } else { EPISODE_WHERE_NO_OWNER_COLUMN }
}

/// Does `trellion_episodes.user_id` exist in the schema the targets resolve
/// to? Targets are unqualified, so they resolve through the search path;
/// match that with `current_schemas(false)`. A missing TABLE yields false
/// here and then errors on the target like every other store (no table, no
/// erase), which is the existing behaviour.
const EPISODES_OWNER_COLUMN_SQL: &str = "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
     WHERE table_name = 'trellion_episodes' AND column_name = 'user_id' \
     AND table_schema = ANY (current_schemas(false)))";

/// Legacy feedback tables: the user's conversations, the messages in them, the
/// ratings of those messages (or by the user) and the preference pairs built
/// from those messages (their text is the user's prompt and replies).
const LEGACY_FEEDBACK_PREFS: &str = "chosen_message_id IN (SELECT m.id FROM noo_feedback_messages m \
     JOIN noo_feedback_conversations c ON c.id = m.conversation_id WHERE c.user_id = $1) \
     OR rejected_message_id IN (SELECT m.id FROM noo_feedback_messages m \
     JOIN noo_feedback_conversations c ON c.id = m.conversation_id WHERE c.user_id = $1)";
const LEGACY_FEEDBACK_RATINGS: &str = "user_id = $1 OR message_id IN (SELECT m.id FROM noo_feedback_messages m \
     JOIN noo_feedback_conversations c ON c.id = m.conversation_id WHERE c.user_id = $1)";
const LEGACY_FEEDBACK_MSGS: &str = "conversation_id IN (SELECT id FROM noo_feedback_conversations WHERE user_id = $1)";

/// Erase order is FK-safe: conversation children (which reference entries +
/// conversations) first, then entries, then conversations; graph edges before
/// entities (entity delete DB-cascades mentions/embeddings/cluster-members and
/// edges touching the entity — those regenerable internals are cleaned by
/// cascade, not individually snapshotted); temporal edges before typed
/// entities; then the mesh-owned per-user tables; account last.
fn erase_targets(keep_account: bool, episodes_have_user_id: bool) -> Vec<EraseTarget> {
    let mut t = vec![
        // Legacy per-user stores with no live writer (the Python feedback
        // collector and coding-task manager), whose old rows may remain. All
        // run BEFORE `conversations`: the coding history is keyed only by the
        // conversation it ran in, and the feedback children by their parent.
        // Preferences first (they reference the user's messages), then
        // ratings, messages, conversations.
        EraseTarget { label: "legacy_feedback_preferences", table: "noo_feedback_preferences", where_sql: LEGACY_FEEDBACK_PREFS },
        EraseTarget { label: "legacy_feedback_ratings", table: "noo_feedback_ratings", where_sql: LEGACY_FEEDBACK_RATINGS },
        EraseTarget { label: "legacy_feedback_messages", table: "noo_feedback_messages", where_sql: LEGACY_FEEDBACK_MSGS },
        EraseTarget { label: "legacy_feedback_conversations", table: "noo_feedback_conversations", where_sql: "user_id = $1" },
        EraseTarget {
            label: "coding_tasks",
            table: "noo_coding_tasks",
            where_sql: "conversation_id::text IN (SELECT id::text FROM noo_conversations WHERE user_id = $1)",
        },
        EraseTarget { label: "tool_executions", table: "noo_tool_executions", where_sql: CONV_SUBQ },
        EraseTarget { label: "context_retrievals", table: "noo_context_retrievals", where_sql: CONV_SUBQ },
        EraseTarget { label: "feedback", table: "noo_feedback", where_sql: CONV_SUBQ },
        EraseTarget { label: "entries", table: "noo_entries", where_sql: CONV_SUBQ },
        EraseTarget { label: "conversations", table: "noo_conversations", where_sql: "user_id = $1" },
        EraseTarget { label: "kg_edges", table: "edges", where_sql: "user_id = $1" },
        EraseTarget { label: "kg_entities", table: "entities", where_sql: "user_id = $1" },
        EraseTarget { label: "temporal_edges", table: "noo_temporal_edges", where_sql: "user_id = $1" },
        EraseTarget { label: "temporal_entities", table: "noo_entities_typed", where_sql: "user_id = $1" },
        EraseTarget { label: "video_episodes", table: "trellion_episodes", where_sql: episode_where(episodes_have_user_id) },
        EraseTarget { label: "video_traversals", table: "trellion_traversal_records", where_sql: "user_id = $1" },
        EraseTarget { label: "prompt_skills", table: "noo_prompt_skill_stats", where_sql: "user_id = $1" },
        EraseTarget { label: "kb_grants", table: "noo_kb_role_grants", where_sql: "username = $1" },
        EraseTarget { label: "channel_links", table: "noo_user_channel_links", where_sql: "username = $1" },
        // Per-account settings (`walks.save_threads`). Erased with
        // the account, and also under `keep_account`: a wiped user starts from
        // the defaults.
        EraseTarget { label: "user_settings", table: "noo_user_settings", where_sql: "username = $1" },
        // Asynchronous operations the user started (`ops.rs`): the params,
        // progress and RESULT of a navigate, an ingest, an extraction are the
        // user's own content, kept up to a day by default. Keyed by the
        // account's `user_uuid`, never a name, so the subquery is the join.
        EraseTarget {
            label: "ops",
            table: "noo_ops",
            where_sql: "owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = $1)",
        },
        // Agent-to-agent messages the user sent or received.
        // Bodies are sealed at rest; the staging archive carries ciphertext.
        EraseTarget { label: "agent_messages", table: "noo_agent_messages", where_sql: "from_user = $1 OR to_user = $1" },
        // A task is keyed by `owner_uuid` with `ON DELETE SET
        // NULL`, so deleting the account left the objective, notes, result and
        // error behind, ownerless. Must run before the account goes (the
        // subquery reads it); children and parents are the user's own.
        EraseTarget {
            label: "tasks",
            table: "noo_tasks",
            where_sql: "owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = $1)",
        },
        // The gate's `reason` carries up to 400 characters of the tool's arguments.
        EraseTarget { label: "approval_requests", table: "noo_approval_requests", where_sql: "requester = $1" },
        // The user's own saved contacts (name, chat id, notes). `owner IS NULL`
        // is the shared address book and is never touched.
        EraseTarget { label: "channel_recipients", table: "noo_channel_recipients", where_sql: "owner = $1" },
        // IP address and user agent per session; also ends the account's live
        // sessions under `--keep-account`.
        EraseTarget { label: "refresh_tokens", table: "noo_refresh_tokens", where_sql: "user_id = $1" },
        // What the graph prune set aside for the user. Entities carry the owner
        // in their payload, edges in a column (both stamped by `graph_prune.rs`
        // since 084); rows staged before that are unattributable and age out
        // under the prune's own retention. The prune RESTORE route refuses an
        // erased user's rows as well (`erasure_archive::user_is_erased`).
        EraseTarget { label: "graph_prune_entities", table: "graph_prune_staging", where_sql: "payload->>'user_id' = $1" },
        EraseTarget { label: "graph_prune_edges", table: "graph_edge_prune_staging", where_sql: "user_id = $1" },
        // Raw uploads the user sent (the files go after commit, see
        // `uploads_to_remove`).
        EraseTarget { label: "uploads", table: "noo_uploads", where_sql: "owner = $1" },
    ];
    if !keep_account {
        t.push(EraseTarget { label: "account", table: "noo_users", where_sql: "username = $1" });
    }
    t
}

/// Every table an erase touches, for tests that need them to exist.
#[allow(dead_code)]
pub(crate) fn erase_store_tables() -> Vec<&'static str> {
    erase_targets(true, true).iter().map(|t| t.table).collect()
}

#[derive(Deserialize)]
struct EraseBody {
    /// Default TRUE — an erase call with no body only previews.
    #[serde(default = "default_true")]
    dry_run: bool,
    #[serde(default)]
    keep_account: bool,
}

fn default_true() -> bool {
    true
}

/// POST /api/security/users/{username}/erase — right-to-be-forgotten.
///
/// `{dry_run: true}` (the default) returns the per-store row counts and
/// mutates nothing. `{dry_run: false}` snapshots every matched row into
/// `noo_user_erasure_staging` and deletes it, all in one transaction, then
/// writes an audit row. `{keep_account: true}` wipes the data but keeps the
/// `noo_users` login.
async fn user_erase(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    body: Option<Json<EraseBody>>,
) -> AppResult {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }
    // erasure is the most destructive account mutation on this surface
    // and had NO tier check at all — an Operator could erase every Admin.
    // The clamp applies to the dry run too: the plan discloses per-store row
    // counts for the target, which is itself information about that account.
    require_may_manage(&state.db, &ctx, &username).await?;
    let Json(body) = body.unwrap_or(Json(EraseBody { dry_run: true, keep_account: false }));

    let out = match erase_account(&state.db, &username, body.dry_run, body.keep_account).await {
        Ok(v) => v,
        Err(e @ AppError::RetryLater { .. }) => {
            // A refused erase is an event an operator should be able to see. No content.
            if let AppError::RetryLater { retry_after_secs, .. } = &e {
                crate::routes::core::audit_event(
                    &state.db,
                    "user_erase_refused",
                    "warning",
                    &actor(&actor_ext),
                    &username,
                    "refused",
                    json!({ "reason": "write operation in flight", "retry_after_secs": retry_after_secs, "keep_account": body.keep_account }),
                )
                .await;
            }
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    if !body.dry_run {
        let by = actor(&actor_ext);
        crate::routes::core::audit_event(
            &state.db,
            "user_erase",
            "warning",
            &by,
            &username,
            "ok",
            json!({ "run_id": out["run_id"], "keep_account": body.keep_account, "deleted": out["deleted"], "kb": out["kb"] }),
        )
        .await;
        tracing::warn!(user = %username, run_id = %out["run_id"], by = %by, keep_account = body.keep_account, "user_erased");
    }
    Ok(Json(out))
}

/// The erase itself, over the pool alone (the handler's tier checks and audit
/// row are around it), so it can be tested against a real schema.
///
/// Asynchronous operations (`ops.rs`) make this more than a delete: work
/// already handed to a worker finishes regardless of what the gateway does, so
/// an erase must not run while the account has a WRITE-side operation live or
/// within the window its worker run may still be going. It then answers `409`
/// with `Retry-After` (the wait is bounded by the type's run limit) and marks
/// the account erase-PENDING (persisted, with an expiry), after which every new
/// operation start for it is refused: a caller that keeps starting writes
/// cannot starve the erase. The check, the mark and the delete all happen
/// under the account's `noo:ops:<uuid>` advisory lock, the one every start
/// takes, so no start can slip in between.
pub(crate) async fn erase_account(
    db: &sqlx::PgPool,
    username: &str,
    dry_run: bool,
    keep_account: bool,
) -> Result<Value, AppError> {
    let username = username.trim().to_string();
    // Footgun guard: never erase the configured operator/admin identity — that
    // is the deployment's own login, not an offboardable tenant.
    let operator = std::env::var("NOO_OPERATOR_USER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("NOO_ADMIN_USER").ok());
    if operator.as_deref().map(str::trim) == Some(username.as_str()) {
        return Err(AppError::BadRequest(format!(
            "refusing to erase the operator account '{username}' (NOO_ADMIN_USER/NOO_OPERATOR_USER)"
        )));
    }

    // Looked up once per erase and used for count, snapshot and delete alike.
    let episodes_have_user_id: bool =
        sqlx::query_scalar(EPISODES_OWNER_COLUMN_SQL).fetch_one(db).await?;
    let targets = erase_targets(keep_account, episodes_have_user_id);

    // Always compute the plan (row counts per store).
    let mut plan = Vec::with_capacity(targets.len());
    let mut total: i64 = 0;
    for t in &targets {
        let sql = t.count_sql();
        let (n,): (i64,) = sqlx::query_as(&sql).bind(&username).fetch_one(db).await?;
        total += n;
        plan.push(json!({ "store": t.label, "table": t.table, "rows": n }));
    }
    // Knowledge-base documents: not keyed by a user column but by audience
    // (`metadata.roles`). Personal ones go, shared ones are scrubbed
    // (`erase_kb.rs`). Same plan as the erase acts on, so the preview counts
    // are the real ones.
    let kb = {
        let mut conn = db.acquire().await?;
        super::erase_kb::plan(&mut conn, &username, false).await?
    };
    total += kb.total();
    plan.extend(kb.rows());

    if dry_run {
        return Ok(json!({
            "dry_run": true,
            "username": username,
            "keep_account": keep_account,
            "total_rows": total,
            "plan": plan,
            "kb": kb.summary(),
        }));
    }

    if !keep_account {
        require_not_last_admin(db, &username, "erase").await?;
    }

    // Execute: snapshot-then-delete each store inside one transaction so a
    // failure rolls the whole erasure back (nothing half-deleted, unsnapshotted).
    let run_id = uuid::Uuid::new_v4();
    let mut tx = db.begin().await?;
    let owner: Option<uuid::Uuid> = sqlx::query_scalar("SELECT user_uuid FROM noo_users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(owner) = owner {
        // The lock every operation start takes: from here no start for this
        // account can commit until this transaction ends.
        crate::ops::lock_owner(&mut tx, owner).await?;
        if let Some(wait) = super::ops::erase_block(&mut tx, owner).await? {
            crate::ops::mark_erase_pending(&mut tx, owner, super::ops::erase_pending_ttl_secs()).await?;
            // Commit the MARK (and nothing else): refusing must not forget it.
            tx.commit().await?;
            return Err(AppError::RetryLater {
                msg: format!(
                    "erasure is pending: '{username}' has a write operation running, or cancelled but possibly \
                     still running in its worker, and work already handed to a worker finishes regardless. \
                     New operations for this account are refused until the erase succeeds; retry in {wait}s"
                ),
                retry_after_secs: wait,
            });
        }
        // Read-side live operations are stopped here, before their rows go:
        // a detached task outlives its row.
        crate::ops::abort_live_for_account(db, &username)
            .await
            .map_err(|e| AppError::Internal(format!("could not stop the account's live operations: {e}")))?;
        crate::ops::clear_erase_pending(&mut tx, owner).await?;
    }
    // The files behind the user's upload rows, read before the rows go.
    let upload_ids: Vec<String> = sqlx::query_scalar("SELECT file_id FROM noo_uploads WHERE owner = $1")
        .bind(&username)
        .fetch_all(&mut *tx)
        .await?;
    let mut deleted = Vec::with_capacity(targets.len());
    for t in &targets {
        // $1 = username (in where_sql + snapshot SELECT list), $2 = run_id, $3 = store label.
        let snapshot = t.snapshot_sql();
        sqlx::query(&snapshot)
            .bind(&username)
            .bind(run_id)
            .bind(t.label)
            .execute(&mut *tx)
            .await?;
        let del = t.delete_sql();
        let r = sqlx::query(&del).bind(&username).execute(&mut *tx).await?;
        deleted.push(json!({ "store": t.label, "rows": r.rows_affected() }));
    }
    // Re-planned under the transaction, documents locked: what the preview
    // showed may have moved (a retag, an ingest by someone else).
    let kb = super::erase_kb::plan(&mut tx, &username, true).await?;
    deleted.extend(super::erase_kb::apply(&mut tx, &username, run_id, &kb).await?);
    // A file is removed only when nobody else uploaded the same bytes (the
    // name is the content hash, so two accounts can share one file).
    let orphaned_uploads: Vec<String> = sqlx::query_scalar(
        "SELECT f FROM unnest($1::text[]) f WHERE NOT EXISTS (SELECT 1 FROM noo_uploads u WHERE u.file_id = f)",
    )
    .bind(&upload_ids)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    // After the commit: a file cannot be rolled back, and a failure to remove
    // one must not undo the erase (it is logged, and the row is already gone).
    let files_removed = super::ui::remove_upload_files(std::path::Path::new(super::ui::UPLOAD_DIR), &orphaned_uploads).await;
    if files_removed > 0 {
        deleted.push(json!({ "store": "upload_files", "rows": files_removed }));
    }

    Ok(json!({
        "dry_run": false,
        "username": username,
        "keep_account": keep_account,
        "run_id": run_id,
        "deleted": deleted,
        "kb": kb.summary(),
    }))
}

/// GET /api/security/erasure-archive — what the right-to-be-forgotten archive
/// holds: row and run counts, the age of the oldest copy, the 30-day retention
/// window, and whether the daily purge loop is ticking. Counts and ages only;
/// no archived content. Admin read.
async fn erasure_archive_status(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    Ok(Json(crate::erasure_archive::status(&state.db).await?))
}

// ═══════════════════════════════════════════════════════════════
// Orgs (noo_orgs) — top tenant boundary
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/orgs
async fn orgs_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (
        String,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT o.id, o.name, o.description, o.created_at FROM noo_orgs o ORDER BY o.id",
    )
    .fetch_all(&state.db)
    .await?;

    // Member counts per org (small tables; one grouped scan).
    let counts = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT org_id, COUNT(*) FROM noo_users GROUP BY org_id",
    )
    .fetch_all(&state.db)
    .await?;
    let count_of = |id: &str| -> i64 {
        counts.iter().find(|(o, _)| o.as_deref() == Some(id)).map(|(_, n)| *n).unwrap_or(0)
    };

    let orgs: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, description, created_at)| {
            json!({
                "id": id,
                "name": name,
                "description": description,
                "created_at": created_at,
                "members": count_of(&id),
            })
        })
        .collect();
    Ok(Json(json!({ "orgs": orgs, "count": orgs.len() })))
}

#[derive(Deserialize)]
struct CreateOrgBody {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// POST /api/security/orgs — body {id, name?, description?}.
async fn org_create(
    State(state): State<Arc<AppState>>,
    actor_ext: Option<Extension<AuthActor>>,
    Json(body): Json<CreateOrgBody>,
) -> AppResult {
    let id = body.id.trim();
    if id.is_empty() {
        return Err(AppError::BadRequest("org id is required".into()));
    }
    let name = body.name.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(id);
    let result = sqlx::query(
        "INSERT INTO noo_orgs (id, name, description, created_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(name)
    .bind(&body.description)
    .bind(actor(&actor_ext))
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(format!("org '{id}' already exists")));
    }
    tracing::info!(org = %id, by = %actor(&actor_ext), "org_created");
    crate::routes::core::audit_event(
        &state.db,
        "org_create",
        "info",
        &actor(&actor_ext),
        name,
        "ok",
        json!({ "org_id": id }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "id": id, "name": name })))
}

#[derive(Deserialize)]
struct SetOrgBody {
    org_id: String,
}

/// POST /api/security/users/{username}/org — assign a user to an org.
async fn user_set_org(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<SetOrgBody>,
) -> AppResult {
    // the org is the top tenant boundary — moving an account across it
    // changes what that account can see.
    require_may_manage(&state.db, &ctx, &username).await?;
    let org_id = body.org_id.trim();
    if org_id.is_empty() {
        return Err(AppError::BadRequest("org_id is required".into()));
    }
    // The org must exist — never point a user at a phantom tenant.
    let org: Option<(String,)> = sqlx::query_as("SELECT id FROM noo_orgs WHERE id = $1")
        .bind(org_id)
        .fetch_optional(&state.db)
        .await?;
    if org.is_none() {
        return Err(AppError::NotFound(format!(
            "org '{org_id}' not found — create it first (noo security org create)"
        )));
    }
    let result = crate::repo::users::set_org(&state.db, &username, org_id).await?;
    if result == 0 {
        return Err(AppError::NotFound(format!("user '{username}' not found")));
    }
    tracing::info!(user = %username, org = %org_id, by = %actor(&actor_ext), "user_org_set");
    crate::routes::core::audit_event(
        &state.db,
        "user_set_org",
        "info",
        &actor(&actor_ext),
        username.trim(),
        "ok",
        json!({ "org_id": org_id }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "username": username, "org_id": org_id })))
}

// ═══════════════════════════════════════════════════════════════
// Channel identity links (noo_user_channel_links)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct LinkCreateBody {
    channel: String,
    channel_user_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

/// POST /api/security/users/{username}/links
/// Body {channel, channel_user_id, display_name?} — upsert a channel→user link.
async fn user_link_create(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<LinkCreateBody>,
) -> AppResult {
    // a channel link makes an inbound chat identity resolve to this
    // account, so pointing one at an Admin is an impersonation primitive.
    require_may_manage(&state.db, &ctx, &username).await?;
    let channel = body.channel.trim();
    let channel_user_id = body.channel_user_id.trim();
    if username.trim().is_empty() || channel.is_empty() || channel_user_id.is_empty() {
        return Err(AppError::BadRequest(
            "username, channel, and channel_user_id are required".into(),
        ));
    }
    // The link points at a real account — reject before creating a dangling map.
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT username FROM noo_users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(AppError::NotFound(format!(
            "user '{username}' not found — create it first (noo security user create)"
        )));
    }
    // Upsert on the (channel, channel_user_id) PK so re-linking a sender to a
    // different account is a single idempotent call.
    sqlx::query(
        "INSERT INTO noo_user_channel_links (channel, channel_user_id, username, display_name) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (channel, channel_user_id) DO UPDATE \
         SET username = EXCLUDED.username, display_name = EXCLUDED.display_name",
    )
    .bind(channel)
    .bind(channel_user_id)
    .bind(&username)
    .bind(&body.display_name)
    .execute(&state.db)
    .await?;
    tracing::info!(
        user = %username, channel = %channel, channel_user_id = %channel_user_id,
        by = %actor(&actor_ext), "channel_link_created"
    );
    crate::routes::core::audit_event(
        &state.db,
        "user_channel_link",
        "info",
        &actor(&actor_ext),
        username.trim(),
        "ok",
        json!({ "channel": channel, "channel_user_id": channel_user_id }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "username": username,
        "channel": channel,
        "channel_user_id": channel_user_id,
    })))
}

/// GET /api/security/users/{username}/links — all channel links for a user.
async fn user_links_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(username): Path<String>,
) -> AppResult {
    // A user's channel links are an impersonation primitive on the chat
    // surface — operators only.
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (
        String,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT channel, channel_user_id, display_name, linked_at \
         FROM noo_user_channel_links WHERE username = $1 ORDER BY linked_at DESC",
    )
    .bind(&username)
    .fetch_all(&state.db)
    .await?;

    let links: Vec<Value> = rows
        .into_iter()
        .map(|(channel, channel_user_id, display_name, linked_at)| {
            json!({
                "channel": channel,
                "channel_user_id": channel_user_id,
                "display_name": display_name,
                "linked_at": linked_at,
            })
        })
        .collect();
    Ok(Json(json!({ "username": username, "links": links, "count": links.len() })))
}

#[derive(Deserialize)]
struct LinkDeleteBody {
    channel: String,
    channel_user_id: String,
}

/// POST /api/security/channel-links/unlink — remove a (channel, channel_user_id) link.
/// Key is in the body (not the path) because channel_user_id can contain slashes.
async fn channel_link_delete(
    State(state): State<Arc<AppState>>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<LinkDeleteBody>,
) -> AppResult {
    let channel = body.channel.trim();
    let channel_user_id = body.channel_user_id.trim();
    if channel.is_empty() || channel_user_id.is_empty() {
        return Err(AppError::BadRequest(
            "channel and channel_user_id are required".into(),
        ));
    }
    // the target account is not in the body — it is whoever the link
    // currently points at. Resolve it, then clamp. (Unlinking an Admin's
    // channel identity is a denial-of-service on that account's inbound.)
    let linked: Option<(String,)> = sqlx::query_as(
        "SELECT username FROM noo_user_channel_links \
         WHERE channel = $1 AND channel_user_id = $2",
    )
    .bind(channel)
    .bind(channel_user_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((target,)) = &linked {
        require_may_manage(&state.db, &ctx, target).await?;
    }
    let result = sqlx::query(
        "DELETE FROM noo_user_channel_links WHERE channel = $1 AND channel_user_id = $2",
    )
    .bind(channel)
    .bind(channel_user_id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "no link for {channel}/{channel_user_id}"
        )));
    }
    tracing::info!(
        channel = %channel, channel_user_id = %channel_user_id,
        by = %actor(&actor_ext), "channel_link_deleted"
    );
    crate::routes::core::audit_event(
        &state.db,
        "user_channel_unlink",
        "info",
        &actor(&actor_ext),
        channel,
        "ok",
        json!({ "channel_user_id": channel_user_id }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "channel": channel, "channel_user_id": channel_user_id })))
}

// ═══════════════════════════════════════════════════════════════
// Space→team links (noo_channel_team_links) — shared team channels
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct SpaceLinkBody {
    channel: String,
    space_id: String,
}

/// POST /api/security/teams/{team}/spaces — link a channel space to a team.
/// Messages in that space become shared team memory (owned by `team:<team>`).
async fn team_space_link(
    State(state): State<Arc<AppState>>,
    Path(team): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    Json(body): Json<SpaceLinkBody>,
) -> AppResult {
    let team = team.trim();
    let channel = body.channel.trim();
    let space_id = body.space_id.trim();
    if team.is_empty() || channel.is_empty() || space_id.is_empty() {
        return Err(AppError::BadRequest(
            "team, channel, and space_id are required".into(),
        ));
    }
    // The team must be registered — never point a space at a phantom team.
    if !crate::repo::kb_grants::team_exists(&state.db, team).await? {
        return Err(AppError::NotFound(format!(
            "team '{team}' not found — create it first (noo security team create)"
        )));
    }
    sqlx::query(
        "INSERT INTO noo_channel_team_links (channel, channel_space_id, team, created_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (channel, channel_space_id) DO UPDATE SET team = EXCLUDED.team",
    )
    .bind(channel)
    .bind(space_id)
    .bind(team)
    .bind(actor(&actor_ext))
    .execute(&state.db)
    .await?;
    tracing::info!(team = %team, channel = %channel, space = %space_id,
        by = %actor(&actor_ext), "space_team_linked");
    crate::routes::core::audit_event(
        &state.db,
        "team_space_link",
        "info",
        &actor(&actor_ext),
        team,
        "ok",
        json!({ "channel": channel, "space_id": space_id }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "team": team, "channel": channel, "space_id": space_id })))
}

/// GET /api/security/teams/{team}/spaces — all spaces linked to a team.
async fn team_spaces_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(team): Path<String>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (String, String, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT channel, channel_space_id, created_at FROM noo_channel_team_links \
         WHERE team = $1 ORDER BY created_at DESC",
    )
    .bind(&team)
    .fetch_all(&state.db)
    .await?;
    let spaces: Vec<Value> = rows
        .into_iter()
        .map(|(channel, space_id, created_at)| {
            json!({ "channel": channel, "space_id": space_id, "created_at": created_at })
        })
        .collect();
    Ok(Json(json!({ "team": team, "spaces": spaces, "count": spaces.len() })))
}

/// POST /api/security/channel-team-links/unlink — body {channel, space_id}.
async fn team_space_unlink(
    State(state): State<Arc<AppState>>,
    actor_ext: Option<Extension<AuthActor>>,
    Json(body): Json<SpaceLinkBody>,
) -> AppResult {
    let channel = body.channel.trim();
    let space_id = body.space_id.trim();
    if channel.is_empty() || space_id.is_empty() {
        return Err(AppError::BadRequest("channel and space_id are required".into()));
    }
    let result = sqlx::query(
        "DELETE FROM noo_channel_team_links WHERE channel = $1 AND channel_space_id = $2",
    )
    .bind(channel)
    .bind(space_id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("no space link for {channel}/{space_id}")));
    }
    tracing::info!(channel = %channel, space = %space_id,
        by = %actor(&actor_ext), "space_team_unlinked");
    crate::routes::core::audit_event(
        &state.db,
        "team_space_unlink",
        "info",
        &actor(&actor_ext),
        channel,
        "ok",
        json!({ "space_id": space_id }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "channel": channel, "space_id": space_id })))
}

// ═══════════════════════════════════════════════════════════════
// KB role grants
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/role-grants
async fn role_grants_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = crate::repo::kb_grants::list_grants_detailed(&state.db).await?;

    let grants: Vec<Value> = rows
        .into_iter()
        .map(|(username, roles, updated_at, updated_by)| {
            json!({
                "username": username,
                "roles": roles,
                "updated_at": updated_at,
                "updated_by": updated_by,
            })
        })
        .collect();
    Ok(Json(json!({ "grants": grants, "count": grants.len() })))
}

#[derive(Deserialize)]
struct RolesBody {
    roles: Vec<String>,
}

/// Reject grants naming `team:x` roles whose team isn't registered — a typo'd
/// team silently matches no documents, so fail loudly instead.
async fn validate_team_roles(db: &sqlx::PgPool, roles: &[String]) -> Result<(), AppError> {
    let team_names: Vec<String> = roles
        .iter()
        .filter_map(|r| r.strip_prefix("team:").map(|s| s.to_string()))
        .collect();
    if team_names.is_empty() {
        return Ok(());
    }
    let known = crate::repo::kb_grants::existing_team_names(db, &team_names).await?;
    let known: Vec<&str> = known.iter().map(String::as_str).collect();
    let missing: Vec<String> = team_names
        .iter()
        .filter(|n| !known.contains(&n.as_str()))
        .map(|n| format!("team:{n}"))
        .collect();
    if !missing.is_empty() {
        return Err(AppError::BadRequest(format!(
            "unregistered team role(s): {missing:?} — create first with: noo security team create <name>"
        )));
    }
    Ok(())
}

/// POST /api/security/users/{username}/roles — merge-grant extra KB roles.
async fn user_grant_roles(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<RolesBody>,
) -> AppResult {
    // KB roles decide which documents the account can read.
    require_may_manage(&state.db, &ctx, &username).await?;
    let requested: Vec<String> = body
        .roles
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    if requested.is_empty() {
        return Err(AppError::BadRequest("no roles given".into()));
    }
    validate_team_roles(&state.db, &requested).await?;

    let existing = crate::repo::kb_grants::get_roles(&state.db, &username).await?;
    let mut merged: Vec<String> = existing
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
        .unwrap_or_default();
    for r in requested {
        if !merged.contains(&r) {
            merged.push(r);
        }
    }
    merged.sort();

    let by = actor(&actor_ext);
    crate::repo::kb_grants::upsert_roles(&state.db, &username, &json!(merged), &by).await?;
    tracing::info!(user = %username, roles = ?merged, by = %by, "kb_roles_granted");
    crate::routes::core::audit_event(
        &state.db,
        "kb_roles_grant",
        "info",
        &actor(&actor_ext),
        username.trim(),
        "ok",
        json!({ "roles": merged }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "username": username, "roles": merged })))
}

/// POST /api/security/users/{username}/roles/revoke
async fn user_revoke_roles(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<RolesBody>,
) -> AppResult {
    require_may_manage(&state.db, &ctx, &username).await?;
    let existing = crate::repo::kb_grants::get_roles(&state.db, &username).await?;
    let existing: Vec<String> = existing
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
        .unwrap_or_default();
    let revoke: Vec<String> = body.roles.iter().map(|r| r.trim().to_string()).collect();
    let remaining: Vec<String> = existing
        .into_iter()
        .filter(|r| !revoke.contains(r))
        .collect();

    let by = actor(&actor_ext);
    if remaining.is_empty() {
        crate::repo::kb_grants::delete_grant(&state.db, &username).await?;
    } else {
        crate::repo::kb_grants::update_roles(&state.db, &username, &json!(remaining), &by).await?;
    }
    tracing::info!(user = %username, roles = ?remaining, by = %by, "kb_roles_revoked");
    crate::routes::core::audit_event(
        &state.db,
        "kb_roles_revoke",
        "info",
        &actor(&actor_ext),
        username.trim(),
        "ok",
        json!({ "roles": remaining }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "username": username, "roles": remaining })))
}

// ═══════════════════════════════════════════════════════════════
// User-management proposals
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/user-proposals
async fn proposals_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    // Mirrors the legacy listing's `users_admin_read_guard` (the design step
    // 4): the queue carries usernames, requested scopes and requesters, so a
    // sub-operator account must not enumerate it. Cluster-HMAC (None) passes,
    // as it does on the legacy listing.
    users_admin_read_guard(&ctx)?;
    let rows = proposal_rows(&state.db).await?;

    let proposals: Vec<Value> = rows
        .into_iter()
        .map(|(id, action, payload, by, status, created, decided_by)| {
            json!({
                "id": id,
                "action": action,
                "payload": payload.unwrap_or_else(|| json!({})),
                "requested_by": by,
                "status": status,
                "created_at": created,
                "decided_by": decided_by,
            })
        })
        .collect();
    Ok(Json(json!({ "proposals": proposals, "count": proposals.len() })))
}

/// One `noo_user_proposals` row as the security routes answer it.
///
/// `id` is `integer` (INT4, 0001_baseline.sql) — decoding it as `i64` made sqlx refuse every row
/// ("mismatched types … INT8 … INT4"), so both the list and the by-id route answered 500 and no
/// proposal could be seen or decided. `i32` here, pinned by a test against the real column.
pub(crate) type ProposalRow = (
    i32,
    String,
    Option<Value>,
    Option<String>,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
);

pub(crate) async fn proposal_rows(db: &sqlx::PgPool) -> Result<Vec<ProposalRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, action, payload, requested_by, status, created_at, decided_by \
         FROM noo_user_proposals \
         ORDER BY (status = 'pending') DESC, id DESC LIMIT 50",
    )
    .fetch_all(db)
    .await
}

pub(crate) async fn proposal_row(db: &sqlx::PgPool, id: i64) -> Result<Option<ProposalRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, action, payload, requested_by, status, created_at, decided_by FROM noo_user_proposals WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// GET /api/security/user-proposals/{id}
///
/// One proposal by id, whatever its age or status. The list answers only the newest 50 with pending
/// first, so a CLI deciding "is proposal N a task proposal" must not depend on N being in it.
async fn proposal_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let row = proposal_row(&state.db, id).await?;
    let Some((id, action, payload, by, status, created, decided_by)) = row else {
        return Err(AppError::NotFound(format!("proposal {id} not found")));
    };
    Ok(Json(json!({
        "id": id, "action": action, "payload": payload.unwrap_or_else(|| json!({})),
        "requested_by": by, "status": status, "created_at": created, "decided_by": decided_by,
    })))
}

#[derive(Deserialize)]
struct DecideBody {
    approve: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// POST /api/security/user-proposals/{id}/decide
///
/// Approving executes the proposed action (create / scopes / disable /
/// grant_roles) in the same transaction that finalises the proposal row.
/// Approve-create returns a generated password ONCE — it is not stored.
///
/// Requires a **named operator**, via the same
/// `proposal_decider` gate the legacy `/api/users/decide` used: cluster-HMAC
/// callers used to pass here as "cluster-cli", which let the very agent that
/// filed a proposal approve it with the fleet-shared secret — the exact
/// self-approval the queue exists to prevent.
async fn proposal_decide(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    ctx: Option<Extension<RequesterCtx>>,
    cert_bound: Option<Extension<crate::auth::CertBoundToken>>,
    Json(body): Json<DecideBody>,
) -> AppResult {
    let by = proposal_decider(&ctx)?;
    let mut tx = state.db.begin().await?;

    let row: Option<(String, Option<Value>, String)> = sqlx::query_as(
        "SELECT action, payload, status FROM noo_user_proposals WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((action, payload, status)) = row else {
        return Err(AppError::NotFound(format!("proposal {id} not found")));
    };
    if status != "pending" {
        return Err(AppError::Conflict(format!("proposal {id} already {status}")));
    }
    let payload = payload.unwrap_or_else(|| json!({}));
    let username = payload["username"].as_str().unwrap_or_default().to_string();
    // What the audit rows name: the account for a user proposal, the task for a task proposal.
    let subject = if action == crate::task_guard::PROPOSAL_ACTION {
        format!("heartbeat:{}", payload["task"]["id"].as_str().unwrap_or("?"))
    } else {
        username.trim().to_string()
    };

    // A scheduled task that destroys data is a PERSON'S decision: approving one needs a credential
    // with no harness claim and no `act`, holding the role the task needs. The spec is classified
    // again now, not as it was when it was filed.
    let task_origin = if action == crate::task_guard::PROPOSAL_ACTION {
        Some(crate::task_guard::resolve_origin(&state.db, &ctx).await)
    } else {
        None
    };
    if let (true, Some(origin)) = (body.approve, &task_origin) {
        crate::task_guard::check_approver(origin, &payload).map_err(AppError::Forbidden)?;
        // Optional hardening (`NOO_TASK_APPROVE_REQUIRE_CERT_BOUND=1`): approving a scheduled delete
        // needs a token bound to the operator's client certificate, so a password or a stolen login
        // token on a shared shell is not enough. Off by default: not every install issues client certs.
        let require = std::env::var("NOO_TASK_APPROVE_REQUIRE_CERT_BOUND").is_ok_and(|v| v == "1");
        if require && cert_bound.is_none() {
            return Err(AppError::Forbidden(
                "approving a scheduled task needs a certificate-bound operator token on this install \
                 (NOO_TASK_APPROVE_REQUIRE_CERT_BOUND); log in with your client certificate"
                    .into(),
            ));
        }
    }

    // approval executes the proposed action with the DECIDER's authority,
    // so the clamp has to run here too — otherwise "file a proposal, have an
    // Operator approve it" is the escalation path the direct routes refuse.
    // Denial is always allowed: it mutates nothing but the queue.
    if body.approve {
        require_may_grant_value(&ctx, payload.get("scopes"))?;
        if !username.trim().is_empty() {
            require_may_manage(&state.db, &ctx, &username).await?;
            if payload.get("disabled").and_then(Value::as_bool) == Some(true) {
                require_not_last_admin(&state.db, &username, "disable").await?;
            }
        }
    }

    async fn finalise(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: i64,
        by: &str,
        status: &str,
        result: &Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE noo_user_proposals SET status = $2, decided_at = now(), \
             decided_by = $3, result = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .bind(result)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    if !body.approve {
        let result = json!({ "reason": body.reason.as_deref().unwrap_or("denied") });
        finalise(&mut tx, id, &by, "denied", &result).await?;
        tx.commit().await?;
        // Audited after the commit, like kb_team_delete: the row records what
        // actually happened, so it must not exist for a decision that rolled
        // back.
        crate::routes::core::audit_event(
            &state.db,
            "user_proposal_denied",
            "info",
            &by,
            &subject,
            "ok",
            json!({ "proposal_id": id, "action": action, "reason": body.reason }),
        )
        .await;
        return Ok(Json(json!({ "status": "denied", "id": id })));
    }

    // Execute the action; a failure marks the proposal failed (committed)
    // rather than leaving it pending forever.
    let mut generated_password: Option<String> = None;
    let exec: Result<Value, String> = async {
        match action.as_str() {
            "create" => {
                use rand::Rng;
                let pw: String = {
                    let mut rng = rand::thread_rng();
                    (0..16)
                        .map(|_| {
                            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                            chars[rng.gen_range(0..chars.len())] as char
                        })
                        .collect()
                };
                let hashed = bcrypt::hash(&pw, bcrypt::DEFAULT_COST)
                    .map_err(|e| format!("hash failed: {e}"))?;
                let scopes = payload
                    .get("scopes")
                    .cloned()
                    .unwrap_or_else(|| json!(["read"]));
                let r = crate::repo::users::create(&mut *tx, &username, &hashed, &scopes, None)
                .await
                .map_err(|e| e.to_string())?;
                if r == 0 {
                    return Err(format!("user '{username}' already exists"));
                }
                generated_password = Some(pw);
                Ok(json!({ "created": true, "scopes": scopes }))
            }
            "scopes" => {
                let scopes = payload.get("scopes").cloned().unwrap_or_else(|| json!([]));
                let r = crate::repo::users::set_scopes(&mut *tx, &username, &scopes)
                    .await
                    .map_err(|e| e.to_string())?;
                if r == 0 {
                    return Err(format!("user '{username}' not found"));
                }
                Ok(json!({ "scopes": scopes }))
            }
            "disable" => {
                let disabled = payload["disabled"].as_bool().unwrap_or(true);
                let r = crate::repo::users::set_disabled(&mut *tx, &username, disabled)
                    .await
                    .map_err(|e| e.to_string())?;
                if r == 0 {
                    return Err(format!("user '{username}' not found"));
                }
                Ok(json!({ "disabled": disabled }))
            }
            "grant_roles" => {
                let roles: Vec<String> = payload["roles"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let team_names: Vec<String> = roles
                    .iter()
                    .filter_map(|r| r.strip_prefix("team:").map(str::to_string))
                    .collect();
                if !team_names.is_empty() {
                    let known =
                        crate::repo::kb_grants::existing_team_names(&mut *tx, &team_names)
                            .await
                            .map_err(|e| e.to_string())?;
                    let known: Vec<&str> = known.iter().map(String::as_str).collect();
                    let missing: Vec<String> = team_names
                        .iter()
                        .filter(|n| !known.contains(&n.as_str()))
                        .map(|n| format!("team:{n}"))
                        .collect();
                    if !missing.is_empty() {
                        return Err(format!("unregistered team role(s): {missing:?}"));
                    }
                }
                if roles.is_empty() {
                    crate::repo::kb_grants::delete_grant(&mut *tx, &username)
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    crate::repo::kb_grants::upsert_roles(
                        &mut *tx,
                        &username,
                        &json!(roles),
                        "proposal-decide",
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                }
                Ok(json!({ "roles": roles }))
            }
            crate::task_guard::PROPOSAL_ACTION => match &task_origin {
                Some(origin) => crate::task_guard::apply_approved(&mut tx, &payload, origin).await,
                None => Err("no approver".into()),
            },
            other => Err(format!("unknown action '{other}'")),
        }
    }
    .await;

    match exec {
        Ok(result) => {
            finalise(&mut tx, id, &by, "approved", &result).await?;
            tx.commit().await?;
            tracing::info!(id, action = %action, user = %username, by = %by, "proposal_approved");
            // `result` only — never `generated_password`. An approved `create`
            // mints a password and returns it once; putting it in the audit
            // trail would persist a live credential in the one table designed
            // to be kept, exported and read by people who were not the
            // requester.
            crate::routes::core::audit_event(
                &state.db,
                "user_proposal_approved",
                "info",
                &by,
                &subject,
                "ok",
                json!({ "proposal_id": id, "action": action, "result": result }),
            )
            .await;
            let mut resp = json!({
                "status": "approved",
                "id": id,
                "action": action,
                "username": username,
                "result": result,
            });
            if let Some(pw) = generated_password {
                resp["generated_password"] = json!(pw);
            }
            Ok(Json(resp))
        }
        Err(e) => {
            finalise(&mut tx, id, &by, "failed", &json!({ "error": e })).await?;
            tx.commit().await?;
            // Outcome "failed", not "ok". A privileged action that was
            // attempted and did not succeed is exactly what an audit trail is
            // for — recording only the successes would make the record a
            // highlight reel.
            crate::routes::core::audit_event(
                &state.db,
                "user_proposal_failed",
                "warning",
                &by,
                &subject,
                "failed",
                json!({ "proposal_id": id, "action": action, "error": e }),
            )
            .await;
            Err(AppError::BadRequest(format!("proposal {id} failed: {e}")))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Service keys
// ═══════════════════════════════════════════════════════════════

/// GET /api/security/service-keys — never returns raw keys or hashes.
async fn service_keys_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (
        String,
        Value,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        // superseded_at: an unfinished rotation is a state an operator has to
        // be able to SEE. Two live keys for one consumer is correct during a
        // rotation and wrong if it is still true next week.
        "SELECT consumer, scopes, active, created_at, last_used_at, note, rpm_limit, user_id, \
                superseded_at \
         FROM noo_service_keys ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await?;

    let keys: Vec<Value> = rows
        .into_iter()
        .map(|(consumer, scopes, active, created, last_used, note, rpm, user_id, superseded)| {
            // A key carrying a retired scope authenticates nothing now
            // (`service_keys::resolve`); say so on the row so the listing can
            // tell the operator to revoke it rather than leave it looking live.
            let scope_words: Vec<String> = scopes
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let retired = crate::service_keys::retired_scopes_in(&scope_words);
            json!({
                "consumer": consumer,
                "scopes": scopes,
                "retired_scopes": retired,
                "active": active,
                "created_at": created,
                "last_used_at": last_used,
                "note": note,
                "rpm_limit": rpm,
                "user_id": user_id,
                "superseded_at": superseded,
            })
        })
        .collect();
    Ok(Json(json!({ "keys": keys, "count": keys.len() })))
}

/// GET /api/security/service-keys/scopes — every word a key may be issued
/// with and the route each opens.
///
/// Derived, never restated: the plain words are `SERVICE_KEY_SCOPES`, the
/// control words are `auth::CONTROL_SCOPE_ROUTES` row by row, `config:<section>`
/// is `auth::CONFIG_SCOPE_PREFIX` minus `GATED_CONFIG_SECTIONS`, and the
/// operator-only words are `OPERATOR_ONLY_KEY_SCOPES`. `noo security
/// service-key provision` reads it to show the operator what an add-on's
/// declared grant opens, and to refuse a word the issuer would reject BEFORE
/// minting anything. Operator-gated like the listing beside it.
async fn service_key_scopes(ctx: Option<Extension<RequesterCtx>>) -> AppResult {
    users_admin_read_guard(&ctx)?;
    Ok(Json(scope_vocabulary()))
}

fn scope_vocabulary() -> Value {
    let plain: Vec<Value> = SERVICE_KEY_SCOPES
        .iter()
        .map(|s| json!({ "scope": s, "opens": scope_opens(s), "default": true }))
        .collect();
    let mut control: Vec<(String, Vec<String>)> = Vec::new();
    for (scope, method, path) in crate::auth::control_scope_rows() {
        let route = format!("{method} {path}");
        match control.iter_mut().find(|(s, _)| s == scope) {
            Some((_, opens)) => opens.push(route),
            None => control.push((scope.to_string(), vec![route])),
        }
    }
    let control: Vec<Value> = control
        .into_iter()
        .map(|(scope, opens)| json!({ "scope": scope, "opens": opens, "default": false }))
        .collect();
    let operator_only: Vec<Value> = OPERATOR_ONLY_KEY_SCOPES
        .iter()
        .map(|s| json!({ "scope": s, "opens": scope_opens(s), "default": false }))
        .collect();
    json!({
        "plain": plain,
        "control": control,
        "config": {
            "prefix": crate::auth::CONFIG_SCOPE_PREFIX,
            "opens": "PUT /api/config/<section>",
            "gated_sections": crate::routes::settings::GATED_CONFIG_SECTIONS,
        },
        "operator_only": operator_only,
    })
}

#[derive(Deserialize)]
struct IssueKeyBody {
    consumer: String,
    #[serde(default = "default_key_scopes")]
    scopes: Vec<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    rpm: Option<i64>,
    /// Bind the key to a Mesh user. When set, the MCP hub dispatches that
    /// user's tool calls under their own JWT, so their `noo_users` scopes and
    /// KB roles apply. Unset = a machine key that dispatches as the operator.
    #[serde(default)]
    user_id: Option<String>,
}

fn default_key_scopes() -> Vec<String> {
    SERVICE_KEY_SCOPES.iter().map(|s| s.to_string()).collect()
}

/// Scopes an OPERATOR may put on a key beyond [`SERVICE_KEY_SCOPES`].
/// Never a default and never self-issuable: `mcp:operator` opens the
/// operator MCP door with the full tool catalog (`mcp_local::OPERATOR_SCOPE`),
/// so it is granted explicitly, to a named admin, by an operator.
///
/// `identity` joins it for the same reason: a key carrying it
/// can mint a live token for any account its bound user may manage, so it
/// is a provisioning credential, not a client credential.
const OPERATOR_ONLY_KEY_SCOPES: &[&str] =
    &[crate::mcp_local::OPERATOR_SCOPE, crate::auth::IDENTITY_SCOPE];

fn validate_key_scopes(scopes: &[String]) -> Result<(), AppError> {
    // A retired scope gets its own refusal, naming what replaced it — "unknown
    // scope" would read as a typo to someone following an old runbook.
    if let Some((scope, why)) = crate::service_keys::RETIRED_KEY_SCOPES
        .iter()
        .find(|(r, _)| scopes.iter().any(|s| s == r))
    {
        return Err(AppError::BadRequest(format!("scope '{scope}' is retired: {why}")));
    }
    let bad: Vec<&String> = scopes
        .iter()
        .filter(|s| {
            !SERVICE_KEY_SCOPES.contains(&s.as_str())
                && !OPERATOR_ONLY_KEY_SCOPES.contains(&s.as_str())
                && !crate::auth::is_control_scope(s)
        })
        .collect();
    if !bad.is_empty() {
        return Err(AppError::BadRequest(format!(
            "unknown scope(s): {bad:?}. Allowed: {SERVICE_KEY_SCOPES:?}, the control scopes \
             (temporal, heartbeat, activities, channels:send, metrics, config:<section>) \
             (+ {OPERATOR_ONLY_KEY_SCOPES:?}, operator-issued only)"
        )));
    }
    Ok(())
}

/// An `mcp:operator` key must be bound to a user who is an admin NOW. The
/// door re-checks the role live on every call, so this is not the security
/// boundary — it is the early, explained refusal, so an operator does not
/// mint a key that can never work.
async fn validate_operator_key_binding(
    db: &sqlx::PgPool,
    scopes: &[String],
    user_id: &Option<String>,
) -> Result<(), AppError> {
    if !scopes.iter().any(|s| s == crate::mcp_local::OPERATOR_SCOPE) {
        return Ok(());
    }
    let Some(u) = user_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(AppError::BadRequest(format!(
            "an '{}' key must be bound to an admin account (--user)",
            crate::mcp_local::OPERATOR_SCOPE
        )));
    };
    let row: Option<(String,)> = sqlx::query_as("SELECT role FROM noo_users WHERE username = $1")
        .bind(u)
        .fetch_optional(db)
        .await?;
    match row.as_ref().map(|(r,)| r.as_str()) {
        Some("admin") => Ok(()),
        Some(role) => Err(AppError::BadRequest(format!(
            "user '{u}' has role '{role}'; an '{}' key needs an admin",
            crate::mcp_local::OPERATOR_SCOPE
        ))),
        None => Err(AppError::BadRequest(format!("user '{u}' not found"))),
    }
}

/// An `identity` key must be bound to an account.
///
/// Not a convenience check — it is the rule the whole exchange rests on.
/// The subject a mint is permitted to name is decided by `may_manage`
/// against the BOUND account's live tier; an unbound key has no tier, and
/// the clamp would have nothing to compare against. Refusing at issue time
/// means that case never reaches the exchange.
fn validate_identity_key_binding(
    scopes: &[String],
    user_id: &Option<String>,
) -> Result<(), AppError> {
    if !scopes.iter().any(|s| s == crate::auth::IDENTITY_SCOPE) {
        return Ok(());
    }
    let bound = user_id.as_deref().map(str::trim).is_some_and(|s| !s.is_empty());
    if bound {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        "an '{}' key must be bound to an account (--user): the exchange decides which \
         subjects it may mint for from that account's tier, so an unbound key could \
         never mint anything",
        crate::auth::IDENTITY_SCOPE
    )))
}

fn new_raw_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::Engine;
    format!(
        "noo-sk-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn sha256_hex(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw.as_bytes()))
}

async fn insert_key(
    db: &sqlx::PgPool,
    consumer: &str,
    scopes: &[String],
    note: &Option<String>,
    rpm: Option<i64>,
    user_id: &Option<String>,
) -> Result<String, AppError> {
    let raw = new_raw_key();
    sqlx::query(
        "INSERT INTO noo_service_keys (id, consumer, key_hash, scopes, note, rpm_limit, user_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(consumer)
    .bind(sha256_hex(&raw))
    .bind(json!(scopes))
    .bind(note)
    .bind(rpm)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(raw)
}

/// Reject a user-bound key for an account that does not exist or is disabled.
/// The FK would catch the first case at insert time, but as a 500 — and it
/// cannot catch the second at all. Checking here turns both into a 400 that
/// names the problem.
async fn validate_key_user(
    db: &sqlx::PgPool,
    user_id: &Option<String>,
) -> Result<(), AppError> {
    let Some(u) = user_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT disabled FROM noo_users WHERE username = $1")
            .bind(u)
            .fetch_optional(db)
            .await?;
    match row {
        None => Err(AppError::BadRequest(format!("user '{u}' not found"))),
        Some((true,)) => Err(AppError::BadRequest(format!("user '{u}' is disabled"))),
        Some((false,)) => Ok(()),
    }
}

/// POST /api/security/service-keys — returns the raw key ONCE.
async fn service_key_issue(
    State(state): State<Arc<AppState>>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<IssueKeyBody>,
) -> AppResult {
    if body.consumer.trim().is_empty() {
        return Err(AppError::BadRequest("consumer is required".into()));
    }
    validate_key_scopes(&body.scopes)?;
    validate_key_user(&state.db, &body.user_id).await?;
    // a user-bound key is a bearer form of that account — the MCP door
    // dispatches its tool calls under the bound user's own identity. Minting
    // one for an account the caller may not manage is impersonation with a
    // credential, so it takes the same clamp as a password reset.
    if let Some(u) = body.user_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        require_may_manage(&state.db, &ctx, u).await?;
    }
    validate_operator_key_binding(&state.db, &body.scopes, &body.user_id).await?;
    validate_identity_key_binding(&body.scopes, &body.user_id)?;
    let raw = insert_key(
        &state.db,
        &body.consumer,
        &body.scopes,
        &body.note,
        body.rpm,
        &body.user_id,
    )
    .await?;
    tracing::info!(
        consumer = %body.consumer,
        user = %body.user_id.as_deref().unwrap_or("-"),
        by = %actor(&actor_ext),
        "service_key_issued"
    );
    crate::routes::core::audit_event(
        &state.db,
        "service_key_issue",
        "info",
        &actor(&actor_ext),
        &body.consumer,
        "ok",
        json!({ "scopes": body.scopes, "rpm_limit": body.rpm, "user_id": body.user_id }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "consumer": body.consumer,
        "scopes": body.scopes,
        "rpm_limit": body.rpm,
        "user_id": body.user_id,
        "key": raw,
        "note": "shown once — store it now; gateway key cache refreshes within ~60s",
    })))
}

// ── Self-service MCP keys ──────────────────────────────────────────────
//
// The operator-issued key above answers "give consumer X these scopes".
// These answer a different question — "give ME a bearer form of the account
// I already have" — and the difference is why they can be exposed below the
// Operator tier. Every identity field is re-derived from the JWT; the body
// carries nothing but an optional note. A caller cannot name the consumer,
// cannot choose scopes, and cannot bind the key to somebody else.
//
// The key's scope list is `["mcp"]` and nothing more. That is the DOOR
// gate, not the permission set: the external MCP door dispatches a bound
// key's tool calls under the bound user's own JWT, so what the key can
// actually reach is that account's `noo_users` scopes and KB audience,
// resolved per request. Widen the account and the key follows; disable the
// account and the key stops working. This is the "user and org associate
// through the token" property — it holds because the key carries an
// identity rather than a copy of that identity's powers.

/// Consumer name for a self-issued key.
///
/// Namespaced so it can never collide with an operator-issued machine key
/// that happens to share a username — which matters because revoke-by-consumer
/// is a bulk UPDATE, so a collision would make `noo security service-key
/// revoke alice` silently kill Alice's personal key too (or the reverse).
fn self_consumer(username: &str) -> String {
    format!("self:{username}")
}

/// Default rate cap for a self-issued key. Operator-issued keys may be
/// uncapped; a self-service one is not, so a stray client loop is bounded by
/// something other than trust.
const SELF_KEY_DEFAULT_RPM: i64 = 120;

#[derive(Deserialize)]
struct SelfKeyBody {
    /// Free-text label ("laptop", "work desktop") so a user with several
    /// machines can tell issuances apart in the listing.
    #[serde(default)]
    note: Option<String>,
}

/// The caller, or a 400 explaining why an unattributable credential cannot
/// self-issue. Cluster HMAC and machine service keys carry no `RequesterCtx`
/// — there is no "self" for them to issue to, and defaulting to anything
/// would mint a key nobody can be held to.
fn self_requester(ctx: &Option<Extension<RequesterCtx>>) -> Result<&RequesterCtx, AppError> {
    match ctx {
        // A DELEGATED token may not mint a standing credential for the
        // account it is acting as. The exchange's whole
        // premise is that what it hands out expires in minutes; letting
        // one of those tokens buy a long-lived MCP key would convert a
        // bounded delegation into a permanent one that outlives revoking
        // the provisioning key. Not an escalation of authority — the key
        // holder can re-exchange at will — but an escalation of
        // PERSISTENCE, which is the property the short TTL exists to buy.
        Some(Extension(r)) if r.act.is_some() => Err(AppError::Forbidden(
            "this is a delegated token and cannot mint a standing key for \
             the account it is acting as — exchange a fresh token instead, or have an \
             operator issue a bound key"
                .into(),
        )),
        Some(Extension(r)) if !r.sub.trim().is_empty() => Ok(r),
        _ => Err(AppError::BadRequest(
            "self-service keys require a logged-in user — the cluster HMAC and \
             machine service keys are not attributable to an account; run \
             `noo auth login` first"
                .into(),
        )),
    }
}

/// POST /api/security/service-keys/self — mint (or rotate) the caller's own
/// MCP key. Returns the raw key exactly once; only its hash is stored.
async fn service_key_self_issue(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<SelfKeyBody>,
) -> AppResult {
    let username = self_requester(&ctx)?.sub.clone();
    // Catches the disabled-account case the JWT cannot: tokens outlive the
    // `disabled` flag, so a just-disabled user could otherwise mint a fresh
    // credential on the way out.
    validate_key_user(&state.db, &Some(username.clone())).await?;
    let consumer = self_consumer(&username);

    // One active self-key per account: re-issuing ROTATES. Anything else and
    // a user accumulates live credentials they have no way to enumerate,
    // since the raw keys were shown once and never stored.
    let replaced = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE consumer = $1 AND active = true",
    )
    .bind(&consumer)
    .execute(&state.db)
    .await?
    .rows_affected();

    let scopes = vec!["mcp".to_string()];
    let raw = insert_key(
        &state.db,
        &consumer,
        &scopes,
        &body.note,
        Some(SELF_KEY_DEFAULT_RPM),
        &Some(username.clone()),
    )
    .await?;

    tracing::info!(consumer = %consumer, user = %username, replaced, "service_key_self_issued");
    crate::routes::core::audit_event(
        &state.db,
        "service_key_self_issue",
        "info",
        &username,
        &consumer,
        "ok",
        json!({ "replaced_active": replaced, "rpm_limit": SELF_KEY_DEFAULT_RPM }),
    )
    .await;

    Ok(Json(json!({
        "status": "ok",
        "consumer": consumer,
        "user_id": username,
        "scopes": scopes,
        "rpm_limit": SELF_KEY_DEFAULT_RPM,
        "replaced_active": replaced,
        "key": raw,
        "note": "shown once — store it now; gateway key cache refreshes within ~60s",
    })))
}

/// GET /api/security/service-keys/self — whether the caller has an active key,
/// and when it was last used. Never returns the key or its hash: there is no
/// recovery path for a lost key, only re-issue.
async fn service_key_self_status(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let username = self_requester(&ctx)?.sub.clone();
    let consumer = self_consumer(&username);
    let row: Option<(
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT created_at, last_used_at, note, rpm_limit FROM noo_service_keys \
         WHERE consumer = $1 AND active = true ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&consumer)
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(match row {
        Some((created, last_used, note, rpm)) => json!({
            "active": true,
            "consumer": consumer,
            "user_id": username,
            "scopes": ["mcp"],
            "created_at": created,
            "last_used_at": last_used,
            "note": note,
            "rpm_limit": rpm,
        }),
        None => json!({ "active": false, "consumer": consumer, "user_id": username }),
    }))
}

/// POST /api/security/service-keys/self/revoke — kill the caller's own key.
async fn service_key_self_revoke(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let username = self_requester(&ctx)?.sub.clone();
    let consumer = self_consumer(&username);
    let revoked = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE consumer = $1 AND active = true",
    )
    .bind(&consumer)
    .execute(&state.db)
    .await?
    .rows_affected();
    tracing::info!(consumer = %consumer, n = revoked, "service_key_self_revoked");
    crate::routes::core::audit_event(
        &state.db,
        "service_key_self_revoke",
        "info",
        &username,
        &consumer,
        "ok",
        json!({ "revoked": revoked }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "consumer": consumer, "revoked": revoked })))
}

/// POST /api/security/service-keys/{consumer}/revoke
/// The two statements a rotation-with-overlap is made of, named so a test can
/// run the REAL sql rather than a copy of it that can drift.
///
/// Supersede STAMPS and leaves the row active. The moment this becomes
/// `SET active = false` the rotation is an outage again, and no assertion
/// about a pure function can see that — which is why these are tested
/// against a database.
pub(crate) const SUPERSEDE_PREVIOUS_SQL: &str =
    "UPDATE noo_service_keys SET superseded_at = COALESCE(superseded_at, NOW()) \
     WHERE consumer = $1 AND active = true AND key_hash <> $2";

/// Retire deactivates only rows that were superseded — never the current one.
pub(crate) const RETIRE_SUPERSEDED_SQL: &str =
    "UPDATE noo_service_keys SET active = false \
     WHERE consumer = $1 AND active = true AND superseded_at IS NOT NULL";

/// Has the consumer actually presented its NEW key?
///
/// `last_used_at` and `created_at` are on the SAME row, so a null means this
/// key has never authenticated anything. The comparison is not redundant
/// defence: it states the rule the caller is entitled to rely on, which is
/// "used SINCE it was minted", not "this consumer has used something".
///
/// Presenting the OLD key moves the OLD row's stamp, never this one — which
/// is exactly why retiring may not be judged from "I restarted the
/// container". That judgement is an echo of one's own action (#258).
pub(crate) fn rotation_is_complete(
    last_used: Option<chrono::DateTime<chrono::Utc>>,
    created: chrono::DateTime<chrono::Utc>,
) -> bool {
    last_used.is_some_and(|t| t >= created)
}

/// May the superseded keys be retired?
///
/// Yes once the NEW key has been presented — the rotation is complete. And
/// yes when NO superseded key was ever presented either: overlap exists to
/// protect a consumer that is still presenting the old value, and a value
/// nobody ever presented protects nobody. Without this branch a consumer
/// that never calls the gateway over HTTP (the worker on a fleet where every
/// worker path rides NATS, 2026-09-27) can never finish a rotation: its new
/// key stays unused, so `retire` refuses forever, and the superseded row
/// lingers as a credential nothing holds.
pub(crate) fn retire_is_safe(new_key_used: bool, any_superseded_used: bool) -> bool {
    new_key_used || !any_superseded_used
}

/// `POST /api/security/service-keys/{consumer}/retire` — finish a rotation.
///
/// Deactivates the superseded rows, and REFUSES while the new key has not
/// been seen in use. That refusal is the whole point: a rotation is only
/// complete when the consumer is actually presenting the new value, and the
/// only thing that can say so is `last_used_at` moving after the stamp.
/// Judging by "the container was recreated" is judging by an echo — the same
/// mistake #258 took out of `secrets rotate`.
async fn service_key_retire(
    State(state): State<Arc<AppState>>,
    Path(consumer): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    require_may_manage_key_consumer(&state.db, &ctx, &consumer).await?;

    // The current key is the active one that is NOT superseded.
    let current: Option<(Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT last_used_at, created_at FROM noo_service_keys \
             WHERE consumer = $1 AND active = true AND superseded_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&consumer)
        .fetch_optional(&state.db)
        .await?;

    let Some((last_used, created)) = current else {
        return Err(AppError::BadRequest(format!(
            "'{consumer}' has no current key to retire the previous ones in favour of — \
             rotate first"
        )));
    };

    let new_key_used = rotation_is_complete(last_used, created);
    let any_superseded_used: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM noo_service_keys \
         WHERE consumer = $1 AND active = true AND superseded_at IS NOT NULL \
         AND last_used_at IS NOT NULL)",
    )
    .bind(&consumer)
    .fetch_one(&state.db)
    .await?;
    if !retire_is_safe(new_key_used, any_superseded_used) {
        return Err(AppError::BadRequest(format!(
            "'{consumer}' has not presented its new key yet (last_used_at is {}). Retiring now \
             would leave the consumer holding a key that is about to stop working, which is \
             exactly what rotation-with-overlap exists to prevent. Install the new value, \
             recreate the consumer, and retire once it has called.",
            last_used.map(|t| t.to_rfc3339()).unwrap_or_else(|| "never".into())
        )));
    }
    if !new_key_used {
        tracing::info!(
            consumer = %consumer,
            "service key retire: neither the new key nor any superseded key was ever presented — \
             retiring the superseded rows loses nothing"
        );
    }

    let retired = sqlx::query(RETIRE_SUPERSEDED_SQL)
    .bind(&consumer)
    .execute(&state.db)
    .await?
    .rows_affected();

    tracing::info!(consumer = %consumer, by = %actor(&actor_ext), retired, "service_key_retired");
    crate::routes::core::audit_event(
        &state.db,
        "service_key_retire",
        "info",
        &actor(&actor_ext),
        &consumer,
        "ok",
        json!({ "retired": retired }),
    )
    .await;
    Ok(Json(json!({ "consumer": consumer, "retired": retired })))
}

async fn service_key_revoke(
    State(state): State<Arc<AppState>>,
    Path(consumer): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    // revoking an Admin's bound key is a denial of service against that
    // account's MCP/inference access.
    require_may_manage_key_consumer(&state.db, &ctx, &consumer).await?;
    let result = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE consumer = $1 AND active = true",
    )
    .bind(&consumer)
    .execute(&state.db)
    .await?;
    tracing::info!(consumer = %consumer, n = result.rows_affected(), by = %actor(&actor_ext), "service_keys_revoked");
    crate::routes::core::audit_event(
        &state.db,
        "service_key_revoke",
        "info",
        &actor(&actor_ext),
        &consumer,
        "ok",
        json!({ "revoked": result.rows_affected() }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "consumer": consumer,
        "revoked": result.rows_affected(),
    })))
}

#[derive(Deserialize)]
struct RotateBody {
    #[serde(default = "default_key_scopes")]
    scopes: Vec<String>,
    #[serde(default)]
    note: Option<String>,
}

/// POST /api/security/service-keys/{consumer}/revoke-and-disable
///
/// The kill switch for one agent persona: revoke every active
/// key for `consumer` AND disable the account it is bound to, in one
/// transaction.
///
/// **Why this exists rather than two calls from the client.** Revoking the
/// key stops the next mint; it does not touch a token already in flight,
/// which stays valid for up to its TTL. Disabling the account is what makes
/// that outstanding token worthless — every handler resolves the account
/// live. An operator reaching for "stop this agent" wants both, and doing
/// them as two requests has a failure mode with no good half: revoke
/// succeeds and disable fails, and the operator is told "revoked" while a
/// live token keeps working for another five minutes. One transaction has
/// no such state.
///
/// Refuses an unbound (machine) key: there is no account to disable, and
/// silently degrading to a plain revoke would mean the button did half of
/// what its name says. Use `/revoke` for those.
async fn service_key_revoke_and_disable(
    State(state): State<Arc<AppState>>,
    Path(consumer): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let consumer = consumer.trim().to_string();
    let bound: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT user_id FROM noo_service_keys \
         WHERE consumer = $1 AND active = true ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&consumer)
    .fetch_optional(&state.db)
    .await?;
    let Some((Some(username),)) = bound else {
        return Err(AppError::BadRequest(format!(
            "no active key for '{consumer}' is bound to an account, so there is nothing to \
             disable — use /revoke to kill the key alone"
        )));
    };

    // Same two clamps the standalone verbs take. Both, because this does
    // both: managing the account AND not stranding the install without an
    // admin.
    require_may_manage(&state.db, &ctx, &username).await?;
    require_not_last_admin(&state.db, &username, "disable").await?;

    let mut tx = state.db.begin().await?;
    let revoked = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE consumer = $1 AND active = true",
    )
    .bind(&consumer)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let disabled = crate::repo::users::set_disabled(&mut *tx, &username, true).await?;
    if disabled == 0 {
        // The key names an account that is not there. Rolling back is the
        // only honest outcome: committing would revoke the key and report
        // an account disabled that does not exist.
        tx.rollback().await?;
        return Err(AppError::NotFound(format!(
            "key '{consumer}' is bound to '{username}', which is not an account — nothing was changed"
        )));
    }
    tx.commit().await?;

    tracing::warn!(
        consumer = %consumer, user = %username, revoked,
        by = %actor(&actor_ext), "service_key_revoked_and_account_disabled"
    );
    crate::routes::core::audit_event(
        &state.db,
        "service_key_revoke_and_disable",
        "warning",
        &actor(&actor_ext),
        &consumer,
        "ok",
        json!({ "revoked": revoked, "user_id": username }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "consumer": consumer,
        "revoked": revoked,
        "user_id": username,
        "account_disabled": true,
        // The one thing the caller must not assume away. Stated in the
        // response so a UI can render it without having to know the rule.
        "note": "outstanding tokens cannot be recalled, but the disabled account makes them \
                 useless within ~10s: the auth layer re-checks the subject on every request \
                 made with a delegated token",
    })))
}

/// POST /api/security/service-keys/{consumer}/rotate — fresh key, old ones
/// superseded (live until `retire`), quota preserved. Returns the raw key ONCE.
async fn service_key_rotate(
    State(state): State<Arc<AppState>>,
    Path(consumer): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<RotateBody>,
) -> AppResult {
    validate_key_scopes(&body.scopes)?;
    // rotation mints a NEW bearer credential for whoever the key is
    // bound to, so it is an issue by another name.
    require_may_manage_key_consumer(&state.db, &ctx, &consumer).await?;
    // Carry BOTH the quota and the user binding across a rotation. Dropping
    // user_id here would silently turn a rotated user key into an unbound
    // machine key — i.e. quietly promote that user to operator tier on the
    // MCP door, which is the opposite of what rotating a credential should do.
    let prev: Option<(Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT rpm_limit, user_id FROM noo_service_keys \
         WHERE consumer = $1 AND active = true ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&consumer)
    .fetch_optional(&state.db)
    .await?;
    let (prev_rpm, prev_user) = match prev {
        Some((r, u)) => (r, u),
        None => (None, None),
    };
    validate_key_user(&state.db, &prev_user).await?;
    // A rotation may widen scopes; widening INTO mcp:operator gets the same
    // admin-binding rule as a fresh issue.
    validate_operator_key_binding(&state.db, &body.scopes, &prev_user).await?;

    let raw = insert_key(
        &state.db,
        &consumer,
        &body.scopes,
        &body.note,
        prev_rpm,
        &prev_user,
    )
    .await?;
    // SUPERSEDE, do not revoke. The previous rows stay ACTIVE and are
    // stamped; `/retire` deactivates them once the new key has been seen in
    // use. Deactivating here is what made rotating a container's key an
    // outage: the process still presents the old value, which is now dead,
    // and a refused bearer logs nothing.
    //
    // Rows already superseded keep their original stamp — COALESCE — so a
    // second rotation before a retire cannot reset the clock on how long a
    // consumer has had two live keys.
    let superseded = sqlx::query(SUPERSEDE_PREVIOUS_SQL)
    .bind(&consumer)
    .bind(sha256_hex(&raw))
    .execute(&state.db)
    .await?
    .rows_affected();
    tracing::info!(
        consumer = %consumer,
        user = %prev_user.as_deref().unwrap_or("-"),
        by = %actor(&actor_ext),
        superseded,
        "service_key_rotated"
    );
    crate::routes::core::audit_event(
        &state.db,
        "service_key_rotate",
        "info",
        &actor(&actor_ext),
        &consumer,
        "ok",
        json!({ "scopes": body.scopes, "rpm_limit": prev_rpm }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "consumer": consumer,
        "scopes": body.scopes,
        "rpm_limit": prev_rpm,
        "user_id": prev_user,
        "key": raw,
        "note": "previous keys superseded, still live until `retire`; shown once — store it now",
    })))
}

#[derive(Deserialize)]
struct QuotaBody {
    rpm: i64,
}

/// POST /api/security/service-keys/{consumer}/quota — rpm ≤ 0 removes the cap.
async fn service_key_set_quota(
    State(state): State<Arc<AppState>>,
    Path(consumer): Path<String>,
    actor_ext: Option<Extension<AuthActor>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<QuotaBody>,
) -> AppResult {
    // throttling an Admin's key to 1 rpm is the same denial of service
    // as revoking it, one step slower.
    require_may_manage_key_consumer(&state.db, &ctx, &consumer).await?;
    let val: Option<i64> = (body.rpm > 0).then_some(body.rpm);
    let result = sqlx::query(
        "UPDATE noo_service_keys SET rpm_limit = $2 WHERE consumer = $1 AND active = true",
    )
    .bind(&consumer)
    .bind(val)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "no active keys for consumer '{consumer}'"
        )));
    }
    tracing::info!(consumer = %consumer, rpm = ?val, by = %actor(&actor_ext), "service_key_quota_set");
    crate::routes::core::audit_event(
        &state.db,
        "service_key_set_quota",
        "info",
        &actor(&actor_ext),
        &consumer,
        "ok",
        json!({ "rpm_limit": val, "updated_keys": result.rows_affected() }),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "consumer": consumer,
        "rpm_limit": val,
        "updated_keys": result.rows_affected(),
    })))
}

// ═══════════════════════════════════════════════════════════════
// Mesh-UI contract surface: /api/users* + /api/kb* (openapi.json)
//
// Native Rust ports of the Python NATS worker handlers
// [ported from workers/users.py + workers/kb.py 2026-07-18].
// Response/request shapes intentionally match the Python handlers
// byte-for-byte at the field level (the mesh-ui contract at
// noo-mesh-ui/contracts/openapi.json was derived from them).
//
// Error mapping note: behind the Python catch-all, EVERY handler-level
// {"error": ...} came back as HTTP 400 (delegation.rs::worker_ok), so
// these ports use AppError::BadRequest even for not-found / forbidden
// cases — same status + body a contract client saw before the port.
//
// Auth note: the Python side relied on the gateway mutation middleware
// for operator (admin/write) scope on POSTs — the Rust equivalent is
// `auth::scope_allows` in `require_any_auth`, which already 403s
// read-scope JWTs on these paths. The in-handler `_requester` checks
// below (internal-caller redirect to the proposal queue, admin-only
// reads, self-lockout guards) are replicated verbatim on top of it.
// ═══════════════════════════════════════════════════════════════

/// Known account scopes, sorted (mirrors `_KNOWN_SCOPES` in workers/users.py).
// "ingest" is deliberately NOT a tier: `scope_allows` short-circuits on
// admin/write and grants everything, and `_resolve_kb_roles` treats those two
// as unrestricted KB readers. "ingest" does neither — it opens exactly the
// paths in `INGEST_PREFIXES` and leaves every other check unchanged, so a
// read+ingest user still reads only their own audience.
// "graph" is the same shape: it opens exactly `GRAPH_QUERY_PATHS` (the six
// audience-scoped graph query routes) and nothing else, per account.
const KNOWN_USER_SCOPES: &[&str] = &["admin", "peer", "read", "write", "ingest", "graph"];

/// `_USERNAME_RE`: `^[A-Za-z0-9._-]{1,128}$`.
///
/// Delegates to [`crate::auth::valid_name_segment`] so an account name and
/// a connection label obey ONE rule. They are both halves of
/// the same kind of name and were briefly governed by two different
/// standards, with the half that ends up in a trust list being the looser
/// one.
fn valid_username(u: &str) -> bool {
    crate::auth::valid_name_segment(u)
}

/// `_TEAM_NAME_RE`: `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn valid_team_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// Python `str(body.get(k) or "")`: missing/null/empty → "", strings pass
/// through, other JSON scalars are stringified.
fn body_str(body: &Value, key: &str) -> String {
    match body.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(false)) => String::new(),
        Some(v) => v.to_string(),
    }
}

/// Python `body.get(k)` when the handler requires `isinstance(x, list)`:
/// None ⇒ missing or not a list. Entries are stringified like `str(s)`.
fn body_str_list(body: &Value, key: &str) -> Option<Vec<String>> {
    body.get(key)?.as_array().map(|a| {
        a.iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect()
    })
}

/// Trim entries + drop empties (Python `[str(s).strip() for s in xs if str(s).strip()]`).
fn clean_str_list(xs: Vec<String>) -> Vec<String> {
    xs.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn unknown_scopes_error(scopes: &[String]) -> Option<String> {
    let mut unknown: Vec<&String> = scopes
        .iter()
        .filter(|s| !KNOWN_USER_SCOPES.contains(&s.as_str()))
        .collect();
    if unknown.is_empty() {
        return None;
    }
    unknown.sort();
    unknown.dedup();
    Some(format!(
        "unknown scopes: {unknown:?} (known: {KNOWN_USER_SCOPES:?})"
    ))
}

fn is_operator(r: &RequesterCtx) -> bool {
    // Role cascade: Operator and above. `role` is resolved at
    // token validation (dual-accept: role claim AND legacy admin/write
    // scopes both land here), so this is the old check, centralised.
    r.role >= crate::auth::Role::Operator
}

// ── The tier clamp ───────────────────────────────
//
// ONE helper — `require_may_manage` — guards every mutation on this surface
// that names another account. The rule itself is `auth::may_manage`; what
// lives here is the DB lookup that resolves the TARGET's effective tier, so
// there is exactly one place that decides what "Operator" and "Admin" mean
// relative to each other.
//
// Applied at: user_create (via `may_grant_tier` on the requested scopes),
// user_set_password, user_disable / api_users_disable, user_erase,
// user_set_scopes, user_set_role, user_grant_roles, user_revoke_roles,
// user_set_org, user_link_create, service_key_issue / _rotate / _revoke /
// _set_quota (on the bound user), and proposal_decide.

/// The effective tier of an existing account.
///
/// `role` is the source of truth (`repo::users::set_role` /
/// `set_scopes` keep the legacy `scopes` column in sync atomically), but this
/// takes the **max** of the role column and the scope-derived tier. If the
/// two ever disagree — a hand-edited row, a half-applied migration — the
/// account is protected at the HIGHER of the two, never the lower. Failing
/// closed here means an inconsistency cannot be used to strip an admin's
/// protection.
///
/// `Ok(None)` means no such account; callers let the handler produce its own
/// 404 rather than turning "not found" into "forbidden".
async fn effective_tier(
    db: &sqlx::PgPool,
    username: &str,
) -> Result<Option<crate::auth::Role>, AppError> {
    let row: Option<(String, Value)> =
        sqlx::query_as("SELECT role, scopes FROM noo_users WHERE username = $1")
            .bind(username.trim())
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(role, scopes)| {
        // An unparseable role column must not silently read as `User` — that
        // is the low-protection answer. Anything we cannot parse is treated
        // as Admin.
        let from_col: crate::auth::Role = role
            .trim()
            .parse()
            .unwrap_or(crate::auth::Role::Admin);
        let list: Vec<String> = serde_json::from_value(scopes).unwrap_or_default();
        from_col.max(crate::auth::Role::from_scopes(&list))
    }))
}

/// Refuse a mutation whose TARGET account out-ranks the caller.
///
/// `None` ctx = cluster-HMAC / internal: exempt, exactly as today. See
/// `auth::may_manage` for why.
async fn require_may_manage(
    db: &sqlx::PgPool,
    ctx: &Option<Extension<RequesterCtx>>,
    target: &str,
) -> Result<(), AppError> {
    let Some(Extension(caller)) = ctx else {
        return Ok(());
    };
    let Some(tier) = effective_tier(db, target).await? else {
        return Ok(());
    };
    crate::auth::may_manage(caller.role, &caller.sub, tier, target.trim())
        .map_err(AppError::Forbidden)
}

/// `require_may_manage` for the consumer-addressed service-key routes
/// (revoke / rotate / quota), where the target ACCOUNT is not in the request
/// at all — it is whatever the active key for that consumer is bound to.
///
/// An unbound (machine) key has no account behind it, so there is nothing to
/// clamp: those stay plain Operator-gated, as before.
async fn require_may_manage_key_consumer(
    db: &sqlx::PgPool,
    ctx: &Option<Extension<RequesterCtx>>,
    consumer: &str,
) -> Result<(), AppError> {
    let bound: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT user_id FROM noo_service_keys \
         WHERE consumer = $1 AND active = true ORDER BY created_at DESC LIMIT 1",
    )
    .bind(consumer.trim())
    .fetch_optional(db)
    .await?;
    let Some((Some(u),)) = bound else {
        return Ok(());
    };
    require_may_manage(db, ctx, &u).await
}

/// Refuse creating/approving an account at or above the caller's own tier.
fn require_may_grant(
    ctx: &Option<Extension<RequesterCtx>>,
    scopes: &[String],
) -> Result<(), AppError> {
    let Some(Extension(caller)) = ctx else {
        return Ok(());
    };
    let granted = crate::auth::Role::from_scopes(scopes);
    crate::auth::may_grant_tier(caller.role, granted).map_err(AppError::Forbidden)
}

/// `require_may_grant` for the untyped `Value` scope lists the proposal
/// surface carries. A missing/`null`/empty list is the `["read"]` default
/// (what an approved create gets), i.e. the `User` tier.
fn require_may_grant_value(
    ctx: &Option<Extension<RequesterCtx>>,
    scopes: Option<&Value>,
) -> Result<(), AppError> {
    let list: Vec<String> = match scopes {
        Some(Value::Array(a)) if !a.is_empty() => a
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        _ => vec!["read".to_string()],
    };
    require_may_grant(ctx, &list)
}

/// How many enabled `admin` accounts exist right now.
///
/// Counts on BOTH columns for the same fail-closed reason as
/// `effective_tier`: an account that is admin by either measure counts, so a
/// desynced row cannot make the fleet look like it has fewer admins than it
/// does — which would be the direction that lets the guard be bypassed.
async fn enabled_admin_count(db: &sqlx::PgPool) -> Result<i64, AppError> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM noo_users WHERE disabled = false \
         AND (role = 'admin' OR scopes @> '[\"admin\"]'::jsonb)",
    )
    .fetch_one(db)
    .await?;
    Ok(n)
}

/// The last-admin guard: refuse to disable, erase or demote the only enabled
/// admin left.
///
/// Without it, the identity surface can be locked permanently behind an
/// account nobody can administer — the `/role` endpoint has a *self*-demotion
/// guard, but one admin demoting another, or a proposal-approved disable, hit
/// nothing. This is not a privilege check; it runs even for an admin caller
/// and even for cluster-HMAC.
async fn require_not_last_admin(
    db: &sqlx::PgPool,
    username: &str,
    verb: &str,
) -> Result<(), AppError> {
    let username = username.trim();
    if effective_tier(db, username).await? != Some(crate::auth::Role::Admin) {
        return Ok(());
    }
    let disabled: Option<(bool,)> = sqlx::query_as("SELECT disabled FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await?;
    if disabled.map(|(d,)| d).unwrap_or(true) {
        // Already disabled, or gone: it is not one of the live admins, so
        // removing it cannot strand the surface.
        return Ok(());
    }
    if enabled_admin_count(db).await? <= 1 {
        return Err(AppError::Forbidden(format!(
            "refusing to {verb} '{username}': it is the last enabled admin account. \
             Promote another account to admin first (noo security user set-role <user> admin)."
        )));
    }
    Ok(())
}

/// Mirrors `_users_admin_error(body)` for reads: users admin is operator-only
/// even on GETs (a read-scope user must not enumerate accounts); callers with
/// no `RequesterCtx` are internal/cluster-HMAC and pass. An authenticated
/// caller below Operator is `403` (the house convention, as `operator_guard`
/// in mcp_registry.rs); a missing credential is `401` from the auth layer
/// before this runs. It was `400`, which told a client its request was
/// malformed rather than that it lacked the role.
fn users_admin_read_guard(ctx: &Option<Extension<RequesterCtx>>) -> Result<(), AppError> {
    match ctx {
        None => Ok(()),
        Some(Extension(r)) if is_operator(r) => Ok(()),
        Some(_) => Err(AppError::Forbidden("operator role required".into())),
    }
}

/// Mirrors `_users_admin_error(body, internal_ok=False)` for mutations:
/// internal callers are redirected to the proposal queue so the agent cannot
/// create accounts on its own; JWT callers need admin/write.
fn users_admin_mutation_guard(
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<&RequesterCtx, AppError> {
    match ctx {
        None => Err(AppError::BadRequest(
            "direct user mutations require a logged-in operator — \
             file a request via POST /api/users/propose \
             (noo_user_propose) for human approval"
                .into(),
        )),
        Some(Extension(r)) if is_operator(r) => Ok(r),
        Some(_) => Err(AppError::Forbidden("operator role required".into())),
    }
}

/// `users_admin_mutation_guard` for the `/api/security/*`
/// user-CRUD surface. Same workflow gate — the agent (cluster-HMAC, no
/// `RequesterCtx`) and sub-operator accounts do not mutate accounts directly;
/// they file a proposal and a human operator decides — with the redirect
/// pointing at the SECURITY-surface propose path, so consolidating the Admin
/// tab here keeps the approval step instead of silently dropping it.
///
/// One deliberate difference from the legacy guard: a logged-in caller below
/// Operator gets the propose redirect too (legacy said only "admin scope
/// required"). The recorded decision makes propose/approve the User→Operator
/// escalation path, so the rejection must name the path the caller is
/// actually supposed to use.
fn security_users_mutation_guard(
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<&RequesterCtx, AppError> {
    match ctx {
        Some(Extension(r)) if is_operator(r) => Ok(r),
        // None (cluster-HMAC / internal) and Some(< Operator) both land here:
        // identical to the legacy guard for the HMAC case, and the recorded
        // User→Operator escalation path for the sub-operator JWT case.
        _ => Err(AppError::BadRequest(
            "direct user mutations require an operator — \
             file a request via POST /api/security/users/propose \
             (noo_user_propose) for human approval"
                .into(),
        )),
    }
}

/// WHO is deciding a user-management proposal. The gate the legacy
/// `/api/users/decide` used (that route is gone, 2026-09-27): a **named**
/// operator is required — cluster-HMAC callers are refused (the agent must
/// not approve its own proposals, and the fleet-shared secret names nobody),
/// and so is any JWT below Operator.
fn proposal_decider(
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<String, AppError> {
    let Some(Extension(requester)) = ctx else {
        return Err(AppError::BadRequest(
            "decisions require a logged-in operator (admin/write JWT)".into(),
        ));
    };
    if !is_operator(requester) {
        return Err(AppError::BadRequest(
            "decisions require a logged-in operator (admin/write JWT)".into(),
        ));
    }
    Ok(if requester.sub.is_empty() {
        "operator".to_string()
    } else {
        requester.sub.clone()
    })
}

/// Guard for *privilege* mutation (roles and the deprecated scopes surface) —
/// stricter than `users_admin_mutation_guard`, and deliberately not
/// `is_operator`.
///
/// Every other guard in this file treats Operator and Admin as one privilege,
/// because in `scope_allows` they are: either grants the whole API. That parity
/// is fine until the endpoint being guarded is the one that hands out
/// privilege. With `is_operator` here, an Operator account could grant itself
/// Admin, so the two tiers would be not merely equivalent but permanently so —
/// no privilege ceiling exists if the ceiling is self-editable. (The PR#460
/// asymmetry: granting requires Admin, never Operator. It survives the roles
/// cutover by design.)
///
/// Cluster-HMAC (`None`) is refused for the same reason the mutation guard
/// refuses it: the shared cluster secret is not attributable to a person, and
/// a privilege change must name who made it.
fn scope_mutation_guard(
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<&RequesterCtx, AppError> {
    match ctx {
        None => Err(AppError::BadRequest(
            "changing roles/scopes requires a logged-in admin — the cluster HMAC \
             is shared and not attributable; run `noo auth login` first"
                .into(),
        )),
        Some(Extension(r)) if r.role >= crate::auth::Role::Admin => Ok(r),
        Some(_) => Err(AppError::Forbidden(
            "admin role required to change roles/scopes (operator cannot promote itself)"
                .into(),
        )),
    }
}

// ── Shared executors ───────────────────────────────────────────
//
// The direct routes run through these, so the unknown-scope, self-lockout and
// team-registry guards live in one place. (The legacy `/api/users/decide` also
// ran through them; `proposal_decide`, the surviving decide path, applies an
// approved action inline.) Errors are plain strings; callers map them to a
// 400 {"error": ...} body.

/// [ported from workers/users.py::_users_set_scopes 2026-07-18]
async fn exec_user_set_scopes(
    db: &sqlx::PgPool,
    username: &str,
    scopes_in: Option<Vec<String>>,
    requester_sub: &str,
) -> Result<Value, String> {
    let username = username.trim();
    let raw = match scopes_in {
        Some(s) if !s.is_empty() && !username.is_empty() => s,
        _ => return Err("username and scopes (non-empty list) required".into()),
    };
    let scopes = clean_str_list(raw);
    if let Some(err) = unknown_scopes_error(&scopes) {
        return Err(err);
    }
    if requester_sub == username && !scopes.iter().any(|s| s == "admin" || s == "write") {
        return Err("cannot drop your own operator scope".into());
    }
    let result = crate::repo::users::set_scopes(db, username, &json!(scopes))
        .await
        .map_err(|e| format!("Database error: {e}"))?;
    if result == 0 {
        return Err(format!("user '{username}' not found"));
    }
    Ok(json!({ "username": username, "scopes": scopes }))
}

/// [ported from workers/users.py::_users_set_disabled 2026-07-18]
async fn exec_user_set_disabled(
    db: &sqlx::PgPool,
    username: &str,
    disabled: Option<bool>,
    requester_sub: &str,
) -> Result<Value, String> {
    let username = username.trim();
    let Some(disabled) = disabled else {
        return Err("username and disabled (bool) required".into());
    };
    if username.is_empty() {
        return Err("username and disabled (bool) required".into());
    }
    if disabled && requester_sub == username {
        return Err("cannot disable your own account".into());
    }
    let result = crate::repo::users::set_disabled(db, username, disabled)
        .await
        .map_err(|e| format!("Database error: {e}"))?;
    if result == 0 {
        return Err(format!("user '{username}' not found"));
    }
    Ok(json!({ "username": username, "disabled": disabled }))
}

/// The `team:*` entries in `roles` not registered in noo_kb_teams. Non-team
/// roles (company/system/user:*/org:*) pass — only teams have a registry.
/// [ported from workers/kb.py::_unknown_team_roles 2026-07-18]
async fn unknown_team_roles(
    db: &sqlx::PgPool,
    roles: &[String],
) -> Result<Vec<String>, String> {
    let team_names: Vec<String> = roles
        .iter()
        .filter_map(|r| r.strip_prefix("team:").map(str::to_string))
        .collect();
    if team_names.is_empty() {
        return Ok(vec![]);
    }
    let known = crate::repo::kb_grants::existing_team_names(db, &team_names)
        .await
        .map_err(|e| format!("Database error: {e}"))?;
    let known: Vec<&str> = known.iter().map(String::as_str).collect();
    Ok(team_names
        .iter()
        .filter(|n| !known.contains(&n.as_str()))
        .map(|n| format!("team:{n}"))
        .collect())
}

// ── /api/users ─────────────────────────────────────────────────

/// GET /api/users — all accounts, no password hashes.
/// [ported from workers/users.py::_users_list (worker.api.users) 2026-07-18]
async fn api_users_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = crate::repo::users::list_with_lock(&state.db).await?;
    let users: Vec<Value> = rows
        .into_iter()
        .map(|(username, disabled, scopes, created, last_login, failed, locked, role)| {
            json!({
                "username": username,
                "disabled": disabled,
                "scopes": scopes,
                "role": role,
                "created_at": created,
                "last_login_at": last_login,
                "failed_login_count": failed,
                "locked_until": locked,
            })
        })
        .collect();
    Ok(Json(json!({ "users": users })))
}

/// POST /api/users/disable — body {username, disabled: bool}.
/// [ported from workers/users.py::_users_set_disabled (worker.api.users.disable) 2026-07-18]
async fn api_users_disable(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let by = users_admin_mutation_guard(&ctx)?.sub.clone();
    let username = body_str(&body, "username");
    let disabled = body.get("disabled").and_then(Value::as_bool);
    require_may_manage(&state.db, &ctx, &username).await?;
    if disabled == Some(true) {
        require_not_last_admin(&state.db, &username, "disable").await?;
    }
    let outcome = exec_user_set_disabled(&state.db, &username, disabled, &by)
        .await
        .map_err(AppError::BadRequest)?;
    crate::routes::core::audit_event(
        &state.db,
        "user_set_disabled",
        "info",
        &by,
        username.trim(),
        "ok",
        json!({ "disabled": outcome["disabled"] }),
    )
    .await;
    tracing::info!(user = %username.trim(), by = %by, "user_set_disabled (mesh-ui surface)");
    Ok(Json(outcome))
}

// ── Proposal filing (agent proposes, humans decide) ────────────

/// Valid proposal actions, sorted (`_USER_PROPOSAL_ACTIONS`).
const USER_PROPOSAL_ACTIONS: &[&str] = &["create", "disable", "grant_roles", "scopes"];

/// Python-repr a string list — `sorted(unknown)` in an f-string renders as
/// `['a', 'b']` (single quotes, comma-space); kept byte-identical because the
/// error strings are part of the pre-port contract.
fn py_list_repr(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

/// Validate a proposal payload up-front so bad requests fail at propose
/// time, not at approval time. Returns Python's exact error strings.
/// [ported from workers/users.py::_validate_user_an earlier change-07-18]
fn validate_user_proposal(action: &str, payload: &Value) -> Option<String> {
    let username = body_str(payload, "username");
    if !valid_username(username.trim()) {
        return Some("payload.username must be 1-128 chars of [A-Za-z0-9._-]".into());
    }
    if payload.get("password").is_some() {
        return Some(
            "proposals never carry passwords — one is generated at \
             approval time and shown to the approver"
                .into(),
        );
    }
    // Both `create` and `scopes` validate a scopes list; `create` defaults a
    // falsy value (missing/null/empty list) to ["read"], `scopes` requires one.
    let scopes_to_check: Option<Vec<String>> = match action {
        "create" => match payload.get("scopes") {
            None | Some(Value::Null) => None, // defaults to ["read"] at approval
            Some(Value::Array(a)) if a.is_empty() => None,
            Some(Value::Array(_)) => match body_str_list(payload, "scopes") {
                Some(s) => Some(s),
                None => return Some("payload.scopes must be a non-empty list".into()),
            },
            Some(_) => return Some("payload.scopes must be a non-empty list".into()),
        },
        "scopes" => match body_str_list(payload, "scopes") {
            Some(s) if !s.is_empty() => Some(s),
            _ => return Some("payload.scopes must be a non-empty list".into()),
        },
        "disable" => {
            if payload.get("disabled").and_then(Value::as_bool).is_none() {
                return Some("payload.disabled must be a bool".into());
            }
            None
        }
        "grant_roles" => {
            match body_str_list(payload, "roles") {
                // all(str(r).strip()) — every stringified entry must be
                // non-empty after trim (an empty LIST passes: all([]) is True).
                Some(roles) if roles.iter().all(|r| !r.trim().is_empty()) => {}
                _ => {
                    return Some(
                        "payload.roles must be a list of role strings (may be empty to clear)"
                            .into(),
                    );
                }
            }
            None
        }
        _ => None,
    };
    if let Some(scopes) = scopes_to_check {
        let mut unknown: Vec<String> = scopes
            .into_iter()
            .filter(|s| !KNOWN_USER_SCOPES.contains(&s.as_str()))
            .collect();
        if !unknown.is_empty() {
            unknown.sort();
            unknown.dedup();
            return Some(format!("unknown scopes: {}", py_list_repr(&unknown)));
        }
    }
    None
}

/// Best-effort text notification to the approval channels — same env vars as
/// the Python `_notify_user_proposal` (NOO_APPROVAL_GCHAT_SPACE /
/// NOO_APPROVAL_TELEGRAM_CHAT) and same message text; delivery goes through
/// the native channel senders in routes/communication.rs (the Rust
/// equivalent of Python's ChannelManager adapters — Google Chat uses the
/// service-account OAuth2 path, Telegram the bot API). No interactive
/// buttons — deciding happens in the dashboard Admin view or via
/// `noo security user decide`. Returns the list of channels notified.
/// [ported from workers/users.py::_notify_user_an earlier change-07-18]
async fn notify_user_proposal(
    pid: i32,
    action: &str,
    payload: &Value,
    requested_by: &str,
    note: &str,
) -> Vec<String> {
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let note_line = if note.is_empty() {
        String::new()
    } else {
        format!("Note: {note}\n")
    };
    let text = format!(
        "User-management proposal #{pid}: {action} {username}\n\
         Payload: {payload}\n\
         {note_line}Requested by: {requested_by}\n\
         Decide: dashboard Admin view, or \
         noo security user decide {pid} --approve/--deny"
    );

    notify_approval_channels(&text).await
}

/// Send one text to the approval channels (`NOO_APPROVAL_GCHAT_SPACE`, `NOO_APPROVAL_TELEGRAM_CHAT`),
/// best effort. The caller writes the text and owns what is in it: a channel gets general
/// messages only. Returns the channels that took it.
pub(crate) async fn notify_approval_channels(text: &str) -> Vec<String> {
    let mut notified: Vec<String> = Vec::new();
    let gchat_space = std::env::var("NOO_APPROVAL_GCHAT_SPACE")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !gchat_space.is_empty() {
        match crate::routes::communication::send_channel_message(
            "google_chat", &gchat_space, text, None, None, None,
        )
        .await
        {
            Ok(()) => notified.push("google_chat".into()),
            Err(e) => tracing::debug!(error = %e, "notify_user_proposal_gchat_failed"),
        }
    }

    let tg_chat = std::env::var("NOO_APPROVAL_TELEGRAM_CHAT")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !tg_chat.is_empty() {
        match crate::routes::communication::send_channel_message(
            "telegram", &tg_chat, text, None, None, None,
        )
        .await
        {
            Ok(()) => notified.push("telegram".into()),
            Err(e) => tracing::debug!(error = %e, "notify_user_proposal_telegram_failed"),
        }
    }
    notified
}

/// POST /api/users/propose — body {action, payload, note?}.
/// Also served as POST /api/security/users/propose —
/// same handler, two paths, like kb-rules/teams.
/// [ported from workers/users.py::_users_propose (worker.api.users.propose) 2026-07-18]
///
/// File a user-management request for human approval. This is the agent's
/// ONLY path to account changes (the direct mutation routes above reject
/// internal callers), and — on the `/api/security/*` path — the escalation
/// path for sub-operator accounts (`auth::USER_PROPOSAL_ESCALATION_PATH`
/// exempts exactly that path from the tier gate); operators may also use it
/// to leave a reviewable trail. Deliberately NO mutation guard here —
/// filing is the low-privilege half of the workflow; execution happens only
/// at decide time, behind `proposal_decider`.
async fn api_users_propose(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let action = body_str(&body, "action").trim().to_string();
    if !USER_PROPOSAL_ACTIONS.contains(&action.as_str()) {
        return Err(AppError::BadRequest(format!(
            "action must be one of {}",
            py_list_repr(
                &USER_PROPOSAL_ACTIONS
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            )
        )));
    }
    let mut payload = match body.get("payload") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        _ => return Err(AppError::BadRequest("payload (object) required".into())),
    };
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("_requester");
    }
    if let Some(err) = validate_user_proposal(&action, &payload) {
        return Err(AppError::BadRequest(err));
    }
    let note = body_str(&body, "note").trim().to_string();
    // Python: `str((body.get("_requester") or {}).get("sub") or "agent")` —
    // internal/cluster-HMAC callers (no RequesterCtx) file as "agent".
    let requested_by = ctx
        .as_ref()
        .map(|Extension(r)| r.sub.clone())
        .unwrap_or_else(|| "agent".to_string());

    let (pid,): (i32,) = sqlx::query_as(
        "INSERT INTO noo_user_proposals (action, payload, note, requested_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&action)
    .bind(&payload)
    .bind(if note.is_empty() { None } else { Some(note.as_str()) })
    .bind(&requested_by)
    .fetch_one(&state.db)
    .await?;

    let notified = notify_user_proposal(pid, &action, &payload, &requested_by, &note).await;

    let username = payload.get("username").cloned().unwrap_or(Value::Null);
    // Same JSONL self-modify trail row the Python handler wrote (shared
    // file, shared shape) + a noo_security_audit event per the native
    // mutation-audit pattern.
    crate::routes::admin::self_modify_audit(json!({
        "action": "user_proposal_filed", "proposal_id": pid,
        "proposal_action": action, "username": username,
        "by": requested_by, "result": "pending",
    }))
    .await;
    crate::routes::core::audit_event(
        &state.db,
        "user_proposal_filed",
        "info",
        &requested_by,
        username.as_str().unwrap_or("?"),
        "pending",
        json!({ "proposal_id": pid, "proposal_action": action, "notified": notified }),
    )
    .await;

    Ok(Json(json!({
        "proposal_id": pid, "status": "pending", "notified": notified,
        "note": format!(
            "Awaiting operator approval (dashboard Admin view or \
             noo security user decide {pid})."
        ),
    })))
}

/// GET /api/users/proposals — pending first, then recent decisions (≤ 50).
/// [ported from workers/users.py::_users_proposals_list (worker.api.users.proposals) 2026-07-18]
async fn api_users_proposals(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (
        i32,
        String,
        Value,
        Option<String>,
        Option<String>,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<Value>,
    )>(
        "SELECT id, action, payload, note, requested_by, status, \
         created_at, decided_at, decided_by, result FROM noo_user_proposals \
         ORDER BY (status = 'pending') DESC, id DESC LIMIT 50",
    )
    .fetch_all(&state.db)
    .await?;
    let mut pending = 0usize;
    let proposals: Vec<Value> = rows
        .into_iter()
        .map(|(id, action, payload, note, requested_by, status, created, decided, decided_by, result)| {
            if status == "pending" {
                pending += 1;
            }
            json!({
                "id": id,
                "action": action,
                "payload": payload,
                "note": note,
                "requested_by": requested_by,
                "status": status,
                "created_at": created,
                "decided_at": decided,
                "decided_by": decided_by,
                "result": result,
            })
        })
        .collect();
    Ok(Json(json!({ "proposals": proposals, "pending": pending })))
}

// ── /api/kb ────────────────────────────────────────────────────

/// GET /api/kb/grants — username → extra granted KB roles.
/// Errors degrade to an empty map, matching `_kb_grants_map` (the table may
/// not exist yet on old schemas). The Python 30s cache is dropped: this is a
/// direct small-table read.
/// [ported from workers/kb.py::_kb_grants_list (worker.api.kb.grants) 2026-07-18]
async fn api_kb_grants(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    // NOTE: pre-existing behaviour — a database error is swallowed into an
    // empty grant list rather than surfaced. Preserved deliberately so this
    // refactor changes nothing; it is the #247 silent-failure class and worth
    // fixing separately.
    let rows = crate::repo::kb_grants::list_grants(&state.db)
        .await
        .unwrap_or_default();
    let mut grants = serde_json::Map::new();
    for (username, roles) in rows {
        // `roles` is NOT NULL DEFAULT '[]'::jsonb — the previous
        // `unwrap_or_else(|| json!([]))` handled a case the schema forbids.
        // The compile-checked query is what proved it.
        grants.insert(username, roles);
    }
    Ok(Json(json!({ "grants": grants })))
}

/// GET /api/kb/rules — DB-backed provenance→roles rules ordered by priority
/// (YAML kb.source_roles applies as fallback).
/// [ported from workers/kb.py::_kb_rules_list (worker.api.kb.rules) 2026-07-18]
async fn api_kb_rules(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    users_admin_read_guard(&ctx)?;
    let rows = sqlx::query_as::<_, (i32, i32, String, Value, bool)>(
        "SELECT id, priority, match, roles, enabled FROM noo_kb_source_rules \
         ORDER BY priority, id",
    )
    .fetch_all(&state.db)
    .await?;
    let rules: Vec<Value> = rows
        .into_iter()
        .map(|(id, priority, match_, roles, enabled)| {
            json!({
                "id": id,
                "priority": priority,
                "match": match_,
                "roles": roles,
                "enabled": enabled,
            })
        })
        .collect();
    Ok(Json(json!({
        "rules": rules,
        "note": "YAML kb.source_roles applies after these",
    })))
}

/// POST /api/security/kb-rules — upsert a provenance rule.
/// Body {id?, match, roles: [..], priority?, enabled?}; omit id to create;
/// {id, delete: true} removes. Mutation scope via the auth middleware.
/// [ported from workers/kb.py::_kb_rule_set (worker.api.kb.rule) 2026-07-18]
async fn api_kb_rule(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let updated_by = ctx
        .as_ref()
        .map(|Extension(r)| r.sub.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "internal".to_string());

    if body.get("delete").and_then(Value::as_bool) == Some(true) {
        let Some(rule_id) = body.get("id").and_then(Value::as_i64) else {
            return Err(AppError::BadRequest("id (int) required to delete".into()));
        };
        sqlx::query("DELETE FROM noo_kb_source_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&state.db)
            .await?;
        return Ok(Json(json!({ "deleted": rule_id })));
    }

    let match_ = body_str(&body, "match").trim().to_string();
    let roles = body_str_list(&body, "roles");
    let raw = match roles {
        Some(r) if !r.is_empty() && !match_.is_empty() => r,
        _ => {
            return Err(AppError::BadRequest(
                "match and roles (non-empty list) required".into(),
            ))
        }
    };
    let roles = clean_str_list(raw);
    // Python: int(body.get("priority") or 100) — falsy (missing/null/0) → 100.
    let priority: i32 = body
        .get("priority")
        .and_then(Value::as_i64)
        .filter(|p| *p != 0)
        .map(|p| p as i32)
        .unwrap_or(100);
    // Python: bool(body.get("enabled", True)) — missing → true, null → false.
    let enabled = body
        .get("enabled")
        .map(|v| v.as_bool().unwrap_or(false))
        .unwrap_or(true);

    let unknown = unknown_team_roles(&state.db, &roles)
        .await
        .map_err(AppError::Internal)?;
    if !unknown.is_empty() {
        return Err(AppError::BadRequest(format!(
            "unregistered team role(s): {unknown:?} — \
             create the team first (Admin → Teams)"
        )));
    }

    if let Some(rule_id) = body.get("id").and_then(Value::as_i64) {
        // NOTE: like Python, a non-existent id is a silent no-op (no rowcount check).
        sqlx::query(
            "UPDATE noo_kb_source_rules SET match = $1, roles = $2, priority = $3, \
             enabled = $4, updated_at = now(), updated_by = $5 WHERE id = $6",
        )
        .bind(&match_)
        .bind(json!(roles))
        .bind(priority)
        .bind(enabled)
        .bind(&updated_by)
        .bind(rule_id)
        .execute(&state.db)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO noo_kb_source_rules (match, roles, priority, enabled, updated_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&match_)
        .bind(json!(roles))
        .bind(priority)
        .bind(enabled)
        .bind(&updated_by)
        .execute(&state.db)
        .await?;
    }
    crate::routes::core::audit_event(
        &state.db,
        "kb_rule_set",
        "info",
        &updated_by,
        &match_,
        "ok",
        json!({ "roles": roles }),
    )
    .await;
    tracing::info!(rule = %match_, by = %updated_by, "kb_rule_set (mesh-ui surface)");
    Ok(Json(json!({
        "match": match_,
        "roles": roles,
        "priority": priority,
        "enabled": enabled,
    })))
}

/// GET /api/kb/teams — team registry with members + document counts.
/// [ported from workers/kb.py::_kb_teams_list (worker.api.kb.teams) 2026-07-18]
async fn api_kb_teams(State(state): State<Arc<AppState>>) -> AppResult {
    let rows = crate::repo::kb_grants::list_teams(&state.db).await?;
    let grant_rows = crate::repo::kb_grants::list_grants(&state.db).await?;
    let grant_rows: Vec<(String, Vec<String>)> = grant_rows
        .into_iter()
        .map(|(u, roles)| {
            // `roles` is NOT NULL; only the JSON shape can disappoint us.
            let roles = serde_json::from_value::<Vec<String>>(roles).unwrap_or_default();
            (u, roles)
        })
        .collect();

    let mut teams: Vec<Value> = Vec::with_capacity(rows.len());
    for (name, description, created_at, created_by) in rows {
        let role = format!("team:{name}");
        let mut members: Vec<&str> = grant_rows
            .iter()
            .filter(|(_, roles)| roles.contains(&role))
            .map(|(u, _)| u.as_str())
            .collect();
        members.sort();
        let (doc_count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM docs WHERE jsonb_exists(metadata->'roles', $1)",
        )
        .bind(&role)
        .fetch_one(&state.db)
        .await?;
        teams.push(json!({
            "name": name,
            "description": description,
            "created_at": created_at,
            "created_by": created_by,
            "members": members,
            "doc_count": doc_count,
        }));
    }
    Ok(Json(json!({ "teams": teams })))
}

/// POST /api/kb/teams/create — body {name, description?}.
/// [ported from workers/kb.py::_kb_teams_create (worker.api.kb.teams.create) 2026-07-18]
async fn api_kb_teams_create(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let raw_name = body_str(&body, "name");
    let trimmed = raw_name.trim();
    let name = trimmed.strip_prefix("team:").unwrap_or(trimmed).to_string();
    let description = {
        let d = body_str(&body, "description").trim().to_string();
        if d.is_empty() { None } else { Some(d) }
    };
    if !valid_team_name(&name) {
        return Err(AppError::BadRequest(
            "team name must be 1-64 chars of [a-z0-9_-], starting alphanumeric".into(),
        ));
    }
    let by = ctx
        .as_ref()
        .map(|Extension(r)| r.sub.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "internal".to_string());

    // Org (PR5c): a team must carry an org for the org read filter + the
    // space→team trigger to place its data in a tenant. Inherit the creator's
    // org; default to `default` (single-org, or internal caller).
    let mut org_id: Option<String> = None;
    if by != "internal" {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT org_id FROM noo_users WHERE username = $1")
                .bind(&by)
                .fetch_optional(&state.db)
                .await?;
        org_id = row.and_then(|(o,)| o);
    }
    let org_id = org_id.unwrap_or_else(|| "default".to_string());

    let inserted = crate::repo::kb_grants::create_team(
        &state.db,
        &name,
        description.as_deref(),
        &by,
        &org_id,
    )
    .await?;
    if inserted == 0 {
        return Err(AppError::BadRequest(format!("team '{name}' already exists")));
    }
    crate::routes::core::audit_event(
        &state.db,
        "kb_team_create",
        "info",
        &by,
        &name,
        "ok",
        json!({}),
    )
    .await;
    tracing::info!(team = %name, by = %by, "kb_team_create (mesh-ui surface)");
    Ok(Json(json!({ "name": name, "role": format!("team:{name}"), "created": true })))
}

/// POST /api/kb/teams/delete — body {name, force?}.
///
/// Refuses while the team has members or documents unless force, in which
/// case the team role is stripped from every grant. Documents keep their tag:
/// an unregistered tag matches no reader until the team is re-created, which
/// is the safe direction.
/// [ported from workers/kb.py::_kb_teams_delete (worker.api.kb.teams.delete) 2026-07-18]
async fn api_kb_teams_delete(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
    team_delete_inner(&state, &body_str(&body, "name"), force, &ctx).await
}

/// DELETE /api/security/teams/{team}?force=true — the same deletion, addressed
/// by path instead of by a name in a POST body.
///
/// Shares [`team_delete_inner`] with the legacy route rather than
/// reimplementing it: the member-strip and the refuse-unless-force rule are
/// the parts that must not drift between two surfaces that both delete teams.
async fn security_team_delete(
    State(state): State<Arc<AppState>>,
    Path(team): Path<String>,
    axum::extract::Query(q): axum::extract::Query<TeamDeleteQuery>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    team_delete_inner(&state, &team, q.force, &ctx).await
}

#[derive(Deserialize)]
struct TeamDeleteQuery {
    #[serde(default)]
    force: bool,
}

async fn team_delete_inner(
    state: &Arc<AppState>,
    raw_name: &str,
    force: bool,
    ctx: &Option<Extension<RequesterCtx>>,
) -> AppResult {
    let trimmed = raw_name.trim();
    let name = trimmed.strip_prefix("team:").unwrap_or(trimmed).to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    let role = format!("team:{name}");
    let by = ctx
        .as_ref()
        .map(|Extension(r)| r.sub.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "internal".to_string());

    let mut tx = state.db.begin().await?;
    let grant_rows = crate::repo::kb_grants::list_grants(&mut *tx).await?;
    let members: Vec<(String, Vec<String>)> = grant_rows
        .into_iter()
        .filter_map(|(u, roles)| {
            let roles = serde_json::from_value::<Vec<String>>(roles).unwrap_or_default();
            roles.contains(&role).then_some((u, roles))
        })
        .collect();
    let (doc_count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM docs WHERE jsonb_exists(metadata->'roles', $1)",
    )
    .bind(&role)
    .fetch_one(&mut *tx)
    .await?;

    if (!members.is_empty() || doc_count > 0) && !force {
        return Err(AppError::BadRequest(format!(
            "team '{name}' has {} member(s) and {doc_count} document(s) — \
             pass force to delete anyway",
            members.len()
        )));
    }

    for (username, member_roles) in &members {
        let remaining: Vec<&String> = member_roles.iter().filter(|r| **r != role).collect();
        if remaining.is_empty() {
            crate::repo::kb_grants::delete_grant(&mut *tx, username).await?;
        } else {
            crate::repo::kb_grants::update_roles(&mut *tx, username, &json!(remaining), &by).await?;
        }
    }
    let deleted_teams = crate::repo::kb_grants::delete_team(&mut *tx, &name).await?;
    // Python commits before the rowcount check (member strips persist even
    // when the team row was already gone) — same ordering here.
    tx.commit().await?;
    if deleted_teams == 0 {
        return Err(AppError::BadRequest(format!("team '{name}' not found")));
    }
    crate::routes::core::audit_event(
        &state.db,
        "kb_team_delete",
        "info",
        &by,
        &name,
        "ok",
        json!({ "forced": force, "members_stripped": members.len(), "docs_orphaned": doc_count }),
    )
    .await;
    tracing::info!(team = %name, forced = force, by = %by, "kb_team_delete (mesh-ui surface)");
    Ok(Json(json!({
        "deleted": name,
        "members_stripped": members.len(),
        "docs_orphaned": doc_count,
    })))
}

#[cfg(test)]
mod tests {
    /// Security review of #1001: `graph` is a per-account USER scope
    /// (`KNOWN_USER_SCOPES`), not a service-key scope. A service key cannot be
    /// issued it, by itself or beside `read`, so no key can gain the six graph
    /// routes by any path; a future declaration has to add it to the vocabulary
    /// on purpose, in code review.
    #[test]
    fn a_service_key_cannot_be_issued_the_graph_scope() {
        use super::{validate_key_scopes, OPERATOR_ONLY_KEY_SCOPES, SERVICE_KEY_SCOPES};
        assert!(validate_key_scopes(&["graph".to_string()]).is_err());
        assert!(validate_key_scopes(&["read".to_string(), "graph".to_string()]).is_err());
        assert!(!SERVICE_KEY_SCOPES.contains(&"graph"));
        assert!(!OPERATOR_ONLY_KEY_SCOPES.contains(&"graph"));
        // control: a vocabulary scope is still accepted, so the test is not vacuous
        assert!(validate_key_scopes(&["chat".to_string()]).is_ok());
    }

    use axum::response::IntoResponse;

    /// `GET /api/security/erasure-archive` (and every users-admin read) answers an
    /// authenticated caller below Operator `403`, not `400`; an Operator and
    /// an internal (no-ctx) caller pass. 401 for no credential at all is the
    /// auth layer's, before the handler runs.
    #[test]
    fn users_admin_read_guard_is_403_for_a_non_admin_and_open_to_operators() {
        let status = |c| match super::users_admin_read_guard(&c) {
            Ok(()) => axum::http::StatusCode::OK,
            Err(e) => e.into_response().status(),
        };
        assert_eq!(status(role_ctx(crate::auth::Role::User)), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(status(role_ctx(crate::auth::Role::Operator)), axum::http::StatusCode::OK);
        assert_eq!(status(role_ctx(crate::auth::Role::Admin)), axum::http::StatusCode::OK);
        assert_eq!(status(None), axum::http::StatusCode::OK);
    }

    /// The mutation guard refuses a non-admin the same way.
    #[test]
    fn users_admin_mutation_guard_is_403_for_a_non_admin() {
        let c = role_ctx(crate::auth::Role::User);
        let err = super::users_admin_mutation_guard(&c).expect_err("refused");
        assert_eq!(err.into_response().status(), axum::http::StatusCode::FORBIDDEN);
    }

    // ── RTBF: the walk stores ────────────────────────────────────────

    /// The stores a user's walks live in. A user's question is held in TWO
    /// tables per capture (the traversal record and its episode row), and RTBF
    /// listed only the first: the episode's `content_summary` carried the
    /// question and its `embedding` was a vector of it.
    #[test]
    fn rtbf_lists_both_walk_stores_and_the_episode_goes_first() {
        let t = super::erase_targets(true, true);
        let pos = |table: &str| t.iter().position(|x| x.table == table);
        let ep = pos("trellion_episodes").expect("trellion_episodes must be an erase target");
        let tr = pos("trellion_traversal_records").expect("traversal records must be an erase target");
        assert!(ep < tr, "episodes match through the records' video_frame_id: erase them first");
        assert!(t[ep].where_sql.contains("user_id = $1"));
        assert!(t[ep].where_sql.contains("video_frame_id"), "pre-104 episodes have no user_id");
        assert_eq!(t[tr].where_sql, "user_id = $1");
        // Labels are the staging archive's keys: unique, or two stores merge.
        let mut labels: Vec<_> = t.iter().map(|x| x.label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), t.len());
    }

    /// Per-account settings (`walks.save_threads`) are an erase target, and
    /// erased even when the account is kept: a wiped user starts from defaults.
    #[test]
    fn rtbf_lists_the_per_account_settings_store() {
        for keep in [true, false] {
            let t = super::erase_targets(keep, true);
            let s = t.iter().find(|x| x.table == "noo_user_settings").expect("noo_user_settings must be an erase target");
            assert_eq!(s.where_sql, "username = $1");
            assert_eq!(s.label, "user_settings");
        }
    }

    /// Asynchronous operations (`noo_ops`) hold the params and RESULT of a user's
    /// navigate/ingest/extraction: erased with the account, also when the account is kept.
    #[test]
    fn rtbf_lists_the_operations_store_by_owner_uuid() {
        for keep in [true, false] {
            let t = super::erase_targets(keep, true);
            let o = t.iter().find(|x| x.table == "noo_ops").expect("noo_ops must be an erase target");
            assert_eq!(o.label, "ops");
            assert!(o.where_sql.contains("owner_uuid") && o.where_sql.contains("noo_users"), "keyed by user_uuid, never a name");
        }
    }

    /// RTBF against the real `noo_ops`: the user's ops (finished AND live) go and are archived;
    /// another account's, and a machine's, stay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtbf_erases_a_users_ops_and_only_theirs() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("rtbf").await else { return };
        use crate::auth::Role;
        let _ = crate::ops::tests::account(&db, "alice", Role::User).await;
        let _ = crate::ops::tests::account(&db, "bob", Role::User).await;
        for (who, status, result) in [
            (Some("alice"), "succeeded", Some(serde_json::json!({"private": "ALICE-RESULT"}))),
            (Some("alice"), "running", None),
            (Some("bob"), "succeeded", Some(serde_json::json!({"private": "BOB-RESULT"}))),
            (None, "succeeded", Some(serde_json::json!({"private": "MACHINE-RESULT"}))),
        ] {
            sqlx::query(
                "INSERT INTO noo_ops (op_type, status, owner_uuid, result, runner_instance, expires_at) \
                 VALUES ('t', $1, (SELECT user_uuid FROM noo_users WHERE username = $2), $3, 'i', now() + interval '1 day')",
            )
            .bind(status)
            .bind(who)
            .bind(result)
            .execute(&db)
            .await
            .unwrap();
        }
        let run = uuid::Uuid::new_v4();
        for t in super::erase_targets(true, true).iter().filter(|t| t.table == "noo_ops") {
            sqlx::query(&t.snapshot_sql()).bind("alice").bind(run).bind(t.label).execute(&db).await.unwrap();
            sqlx::query(&t.delete_sql()).bind("alice").execute(&db).await.unwrap();
        }
        let left: Vec<String> = sqlx::query_scalar("SELECT COALESCE(result->>'private', 'none') FROM noo_ops ORDER BY 1")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(left, ["BOB-RESULT", "MACHINE-RESULT"], "alice's ops are gone, nobody else's");
        let staged: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_user_erasure_staging WHERE store = 'ops' AND username = 'alice'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(staged, 2, "archived like every other store");
    }

    /// RTBF for the thread walks and the setting, against real tables: the
    /// user's `kind='thread'` rows, their episodes and their `walks.save_threads`
    /// row go; another user's threads and setting, and the shared simulated
    /// rows, stay; the setting lands in the staging archive. Private schema,
    /// skips without a DSN (NOO_KB_AUDIENCE_TEST_DSN or CI's NOO_BROKER_TEST_DSN).
    #[tokio::test]
    async fn rtbf_removes_a_users_threads_and_their_walks_setting_and_only_theirs() {
        let Some(dsn) = ["NOO_KB_AUDIENCE_TEST_DSN", "NOO_BROKER_TEST_DSN"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        else {
            eprintln!("SKIPPED: set NOO_KB_AUDIENCE_TEST_DSN to run the DB-backed RTBF thread test");
            return;
        };
        let schema = format!("rtbf_threads_{}", uuid::Uuid::new_v4().simple());
        let s2 = schema.clone();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |c, _| {
                let s = s2.clone();
                Box::pin(async move {
                    sqlx::query(&format!("SET search_path TO {s}")).execute(&mut *c).await?;
                    Ok(())
                })
            })
            .connect(&dsn)
            .await
            .expect("connect to the DSN under test");
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&db).await.unwrap();
        sqlx::query(&format!("SET search_path TO {schema}")).execute(&db).await.unwrap();
        for ddl in [
            "CREATE TABLE trellion_episodes (id uuid PRIMARY KEY, persona_id text NOT NULL, \
             content_summary text NOT NULL, user_id text)",
            "CREATE TABLE trellion_traversal_records (id uuid PRIMARY KEY, query_text text NOT NULL, \
             user_id text, kind text NOT NULL DEFAULT 'simulated', \
             video_frame_id uuid REFERENCES trellion_episodes(id) ON DELETE SET NULL)",
            "CREATE TABLE noo_user_settings (username text NOT NULL, key text NOT NULL, value jsonb NOT NULL, \
             PRIMARY KEY (username, key))",
            "CREATE TABLE noo_user_erasure_staging (run_id uuid, username text, store text, payload jsonb)",
        ] {
            sqlx::query(ddl).execute(&db).await.unwrap();
        }
        // (question, owner, kind)
        for (q, owner, kind) in [
            ("x-thread-1", Some("xuser"), "thread"),
            ("x-thread-2", Some("xuser"), "thread"),
            ("y-thread", Some("yuser"), "thread"),
            ("shared-rehearsal", None, "simulated"),
        ] {
            let ep = uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO trellion_episodes (id, persona_id, content_summary, user_id) VALUES ($1,'p','thread walk',$2)")
                .bind(ep).bind(owner).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO trellion_traversal_records (id, query_text, user_id, kind, video_frame_id) VALUES ($1,$2,$3,$4,$5)")
                .bind(uuid::Uuid::new_v4()).bind(q).bind(owner).bind(kind).bind(ep).execute(&db).await.unwrap();
        }
        for (u, on) in [("xuser", false), ("yuser", false)] {
            sqlx::query("INSERT INTO noo_user_settings (username, key, value) VALUES ($1, 'walks.save_threads', to_jsonb($2::boolean))")
                .bind(u).bind(on).execute(&db).await.unwrap();
        }

        let run = uuid::Uuid::new_v4();
        let wanted = ["trellion_episodes", "trellion_traversal_records", "noo_user_settings"];
        for t in super::erase_targets(true, true).iter().filter(|t| wanted.contains(&t.table)) {
            sqlx::query(&t.snapshot_sql()).bind("xuser").bind(run).bind(t.label).execute(&db).await.unwrap();
            sqlx::query(&t.delete_sql()).bind("xuser").execute(&db).await.unwrap();
        }

        let left = |sql: &'static str| {
            let db = db.clone();
            async move { sqlx::query_scalar::<_, String>(sql).fetch_all(&db).await.unwrap() }
        };
        assert_eq!(
            left("SELECT query_text FROM trellion_traversal_records ORDER BY 1").await,
            ["shared-rehearsal", "y-thread"],
            "X's threads must be gone, Y's and the shared rehearsal must stay"
        );
        assert_eq!(left("SELECT user_id FROM trellion_episodes WHERE user_id IS NOT NULL").await, ["yuser"]);
        assert_eq!(left("SELECT username FROM noo_user_settings").await, ["yuser"], "X's walks.save_threads row must go");
        assert_eq!(
            left("SELECT store FROM noo_user_erasure_staging WHERE store = 'user_settings'").await,
            ["user_settings"],
            "the setting is archived like every other store"
        );

        drop(db);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    }

    /// Erase user X against real tables: X's traversals AND episodes go (both
    /// the ones stamped with `user_id` and the pre-104 ones reachable only
    /// through the record), Y's and the unattributed heartbeat rows stay, and
    /// the question text lands in the staging archive. Builds the tables it
    /// touches in a private schema; skips without a DSN like the KB audience
    /// tests (NOO_KB_AUDIENCE_TEST_DSN or CI's NOO_BROKER_TEST_DSN).
    #[tokio::test]
    async fn rtbf_clears_one_users_walks_and_episodes_and_leaves_the_rest() {
        rtbf_walks_case(true).await;
    }

    /// The same erase against a trellion that has NOT run migration 104:
    /// `trellion_episodes` has no `user_id`. Erasure must still work, through
    /// the frame link, and the choice is made by the real column probe.
    #[tokio::test]
    async fn rtbf_still_erases_episodes_on_a_trellion_without_the_owner_column() {
        rtbf_walks_case(false).await;
    }

    #[test]
    fn the_episode_predicate_follows_the_owner_column() {
        assert!(super::episode_where(true).contains("user_id = $1 OR id IN"));
        let legacy = super::episode_where(false);
        assert!(legacy.starts_with("id IN (SELECT video_frame_id"), "{legacy}");
        assert!(!legacy.contains("user_id = $1 OR"), "{legacy}");
        assert!(legacy.contains("trellion_traversal_records"));
    }

    async fn rtbf_walks_case(owner_column: bool) {
        let Some(dsn) = ["NOO_KB_AUDIENCE_TEST_DSN", "NOO_BROKER_TEST_DSN"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        else {
            eprintln!("SKIPPED: set NOO_KB_AUDIENCE_TEST_DSN to run the DB-backed RTBF walk test");
            return;
        };
        let schema = format!("rtbf_walks_{}", uuid::Uuid::new_v4().simple());
        let s2 = schema.clone();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |c, _| {
                let s = s2.clone();
                Box::pin(async move {
                    sqlx::query(&format!("SET search_path TO {s}")).execute(&mut *c).await?;
                    Ok(())
                })
            })
            .connect(&dsn)
            .await
            .expect("connect to the DSN under test");
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&db).await.unwrap();
        sqlx::query(&format!("SET search_path TO {schema}")).execute(&db).await.unwrap();
        for ddl in [
            if owner_column {
                "CREATE TABLE trellion_episodes (id uuid PRIMARY KEY, persona_id text NOT NULL, \
                 content_summary text NOT NULL, user_id text)"
            } else {
                "CREATE TABLE trellion_episodes (id uuid PRIMARY KEY, persona_id text NOT NULL, \
                 content_summary text NOT NULL)"
            },
            "CREATE TABLE trellion_traversal_records (id uuid PRIMARY KEY, query_text text NOT NULL, \
             user_id text, video_frame_id uuid REFERENCES trellion_episodes(id) ON DELETE SET NULL)",
            "CREATE TABLE noo_user_erasure_staging (run_id uuid, username text, store text, payload jsonb)",
        ] {
            sqlx::query(ddl).execute(&db).await.unwrap();
        }

        // (question, episode owner, record owner); `None` = NULL.
        let cases: [(&str, Option<&str>, Option<&str>); 5] = [
            ("x-stamped", Some("xuser"), Some("xuser")), // post-104 capture
            ("x-legacy", None, Some("xuser")),           // pre-104: episode unowned, record owned
            ("y-own", Some("yuser"), Some("yuser")),
            ("y-legacy", None, Some("yuser")),
            ("heartbeat", None, None),                   // unattributed rehearsal
        ];
        for (q, ep_owner, rec_owner) in cases {
            let ep = uuid::Uuid::new_v4();
            if owner_column {
                sqlx::query("INSERT INTO trellion_episodes (id, persona_id, content_summary, user_id) VALUES ($1,'p',$2,$3)")
                    .bind(ep).bind(format!("Traversal: {q}")).bind(ep_owner).execute(&db).await.unwrap();
            } else {
                sqlx::query("INSERT INTO trellion_episodes (id, persona_id, content_summary) VALUES ($1,'p',$2)")
                    .bind(ep).bind(format!("Traversal: {q}")).execute(&db).await.unwrap();
            }
            sqlx::query("INSERT INTO trellion_traversal_records (id, query_text, user_id, video_frame_id) VALUES ($1,$2,$3,$4)")
                .bind(uuid::Uuid::new_v4()).bind(q).bind(rec_owner).bind(ep).execute(&db).await.unwrap();
        }

        let run = uuid::Uuid::new_v4();
        let probed: bool =
            sqlx::query_scalar(super::EPISODES_OWNER_COLUMN_SQL).fetch_one(&db).await.unwrap();
        assert_eq!(probed, owner_column, "the probe must see the column iff it exists");
        for t in super::erase_targets(true, probed)
            .iter()
            .filter(|t| t.table == "trellion_episodes" || t.table == "trellion_traversal_records")
        {
            sqlx::query(&t.snapshot_sql()).bind("xuser").bind(run).bind(t.label).execute(&db).await.unwrap();
            sqlx::query(&t.delete_sql()).bind("xuser").execute(&db).await.unwrap();
        }

        let left = |sql: &'static str| {
            let db = db.clone();
            async move { sqlx::query_scalar::<_, String>(sql).fetch_all(&db).await.unwrap() }
        };
        assert_eq!(
            left("SELECT query_text FROM trellion_traversal_records ORDER BY 1").await,
            ["heartbeat", "y-legacy", "y-own"]
        );
        assert_eq!(
            left("SELECT content_summary FROM trellion_episodes ORDER BY 1").await,
            ["Traversal: heartbeat", "Traversal: y-legacy", "Traversal: y-own"],
            "X's episodes (stamped and legacy) must be gone; Y's and the heartbeat's must stay"
        );
        let staged = left("SELECT payload->>'content_summary' FROM noo_user_erasure_staging \
                           WHERE store = 'video_episodes' ORDER BY 1").await;
        assert_eq!(staged, ["Traversal: x-legacy", "Traversal: x-stamped"]);

        drop(db);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    }

    /// Control scopes are issued on purpose, never by default: a key minted
    /// without scopes gets SERVICE_KEY_SCOPES, and until this was split a
    /// default key carried `temporal`, the temporal-graph write.
    #[test]
    fn control_scopes_are_issuable_but_never_a_default() {
        for scope in ["temporal", "heartbeat", "activities", "channels:send", "metrics", "config:self_identity"] {
            assert!(super::validate_key_scopes(&[scope.to_string()]).is_ok(), "{scope}");
            assert!(!super::default_key_scopes().iter().any(|s| s == scope), "{scope} is a default");
        }
        assert!(super::default_key_scopes().iter().all(|s| !crate::auth::is_control_scope(s)));
        assert!(super::validate_key_scopes(&["config:security".to_string()]).is_err());
    }

    /// A scope that opens an exchange door must be one the issuer will put on
    /// a key. The door table (`auth::exchange_scope_for`) and the issuer's
    /// allowlist are two declarations of one fact; PR 343 updated the first
    /// and not the second, and the result was a door nothing could open.
    #[test]
    fn every_exchange_door_scope_is_issuable() {
        use axum::http::Method;
        for path in [
            crate::auth::IDENTITY_TOKEN_PATH,
            crate::auth::ADDON_TOKEN_PATH,
        ] {
            let scope = crate::auth::exchange_scope_for(path, &Method::POST)
                .unwrap_or_else(|| panic!("{path} is no longer an exchange door"));
            assert!(
                super::validate_key_scopes(&[scope.to_string()]).is_ok(),
                "the door at {path} needs scope {scope:?}, which the issuer refuses — \
                 a key that can open it can never be minted"
            );
        }
    }

    /// The retired kiosk scope cannot be issued — alone, mixed, or by
    /// default — and the refusal says it is RETIRED, not unknown.
    #[test]
    fn issuance_refuses_the_retired_kiosk_scope() {
        let k = crate::auth::KIOSK_SCOPE.to_string();
        for scopes in [vec![k.clone()], vec!["chat".to_string(), k.clone()]] {
            match super::validate_key_scopes(&scopes) {
                Err(super::AppError::BadRequest(m)) => {
                    assert!(m.contains("retired") && m.contains("tailnet"), "{m}")
                }
                other => panic!("kiosk scope was not refused as retired: {other:?}"),
            }
        }
        assert!(!super::default_key_scopes().contains(&k), "a default key carries the retired scope");
        assert!(super::SCOPE_OPENS.iter().all(|(s, _)| *s != k), "the vocabulary still advertises kiosk");
    }

    /// Every word the issuer accepts by name says what it opens, so the
    /// request `provision` shows never has a blank route column.
    #[test]
    fn every_issuable_scope_says_what_it_opens() {
        for s in super::SERVICE_KEY_SCOPES.iter().chain(super::OPERATOR_ONLY_KEY_SCOPES) {
            let rows = super::SCOPE_OPENS.iter().filter(|(w, _)| w == s).count();
            assert_eq!(rows, 1, "{s:?} has {rows} SCOPE_OPENS rows");
            assert!(!super::scope_opens(s).is_empty(), "{s:?} opens nothing");
        }
        for (s, _) in super::SCOPE_OPENS {
            assert!(super::validate_key_scopes(&[s.to_string()]).is_ok(), "{s:?} is not issuable");
        }
    }

    /// The listing is DERIVED from the tables the issuer and the middleware
    /// read: every word it lists is issuable, every control row appears, and
    /// no gate-bearing config section is offered.
    #[test]
    fn the_scope_listing_is_the_issuers_vocabulary() {
        let v = super::scope_vocabulary();
        let words: Vec<String> = ["plain", "control", "operator_only"]
            .iter()
            .flat_map(|k| v[*k].as_array().unwrap().iter())
            .map(|r| r["scope"].as_str().unwrap().to_string())
            .collect();
        for w in &words {
            assert!(super::validate_key_scopes(std::slice::from_ref(w)).is_ok(), "{w} listed but refused");
        }
        for (s, m, p) in crate::auth::control_scope_rows() {
            let row = v["control"].as_array().unwrap().iter().find(|r| r["scope"] == *s).unwrap();
            assert!(row["opens"].as_array().unwrap().iter().any(|o| o == format!("{m} {p}").as_str()));
        }
        assert_eq!(v["config"]["prefix"], crate::auth::CONFIG_SCOPE_PREFIX);
        for g in crate::routes::settings::GATED_CONFIG_SECTIONS {
            assert!(v["config"]["gated_sections"].as_array().unwrap().iter().any(|x| x == g));
            assert!(super::validate_key_scopes(&[format!("config:{g}")]).is_err());
        }
        assert!(v["plain"].as_array().unwrap().iter().all(|r| r["default"] == true));
        assert!(v["control"].as_array().unwrap().iter().all(|r| r["default"] == false),
            "a control scope is never a default");
    }

    /// One word, both metric doors: `provision` shows `metrics` opening the
    /// increment AND the gauge route on one row.
    #[test]
    fn metrics_lists_both_of_its_routes_on_one_row() {
        let v = super::scope_vocabulary();
        let rows: Vec<&Value> = v["control"].as_array().unwrap().iter().filter(|r| r["scope"] == "metrics").collect();
        assert_eq!(rows.len(), 1, "one row per word");
        let opens = rows[0]["opens"].as_array().unwrap();
        assert!(opens.iter().any(|o| o == "POST /api/metrics/increment"), "{opens:?}");
        assert!(opens.iter().any(|o| o == "POST /api/metrics/gauge"), "{opens:?}");
    }

    /// The behaviour this whole change exists for, against a real database.
    ///
    /// A pure-function test cannot see it: `rotation_is_complete` stayed
    /// green when `SUPERSEDE_PREVIOUS_SQL` was reverted to
    /// `SET active = false`, which is the outage. So run the real statements.
    ///
    /// Skips silently without NOO_BROKER_TEST_DSN — CI sets it.
    #[tokio::test]
    async fn a_rotation_leaves_the_previous_key_live_until_it_is_retired() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())
        else {
            return;
        };
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("connect");
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS svc_key_overlap_test (FORCE)")
            .execute(&admin)
            .await;
        sqlx::raw_sql("CREATE DATABASE svc_key_overlap_test")
            .execute(&admin)
            .await
            .expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{head}/svc_key_overlap_test"))
            .await
            .expect("connect scratch");

        sqlx::raw_sql(
            "CREATE TABLE noo_service_keys ( \
                 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
                 consumer text NOT NULL, \
                 key_hash text NOT NULL UNIQUE, \
                 scopes jsonb NOT NULL DEFAULT '[]'::jsonb, \
                 active boolean NOT NULL DEFAULT true, \
                 created_at timestamptz NOT NULL DEFAULT NOW(), \
                 last_used_at timestamptz, \
                 superseded_at timestamptz )",
        )
        .execute(&db)
        .await
        .expect("create table");
        for h in ["old-hash", "new-hash"] {
            sqlx::query("INSERT INTO noo_service_keys (consumer, key_hash) VALUES ('svc', $1)")
                .bind(h)
                .execute(&db)
                .await
                .expect("insert");
        }

        // Rotate: supersede everything that is not the new key.
        sqlx::query(super::SUPERSEDE_PREVIOUS_SQL)
            .bind("svc")
            .bind("new-hash")
            .execute(&db)
            .await
            .expect("supersede");

        let (active, stamped): (bool, bool) = sqlx::query_as(
            "SELECT active, superseded_at IS NOT NULL FROM noo_service_keys WHERE key_hash='old-hash'",
        )
        .fetch_one(&db)
        .await
        .expect("read old");
        assert!(active, "the previous key must stay LIVE through a rotation — \
                         deactivating it here is the outage this change removes");
        assert!(stamped, "the previous key must be stamped so an unfinished rotation is visible");

        let (new_active, new_stamped): (bool, bool) = sqlx::query_as(
            "SELECT active, superseded_at IS NOT NULL FROM noo_service_keys WHERE key_hash='new-hash'",
        )
        .fetch_one(&db)
        .await
        .expect("read new");
        assert!(new_active && !new_stamped, "the new key must be active and unstamped");

        // Retire: the superseded one goes, the current one does not.
        sqlx::query(super::RETIRE_SUPERSEDED_SQL)
            .bind("svc")
            .execute(&db)
            .await
            .expect("retire");
        let old_active: bool = sqlx::query_scalar(
            "SELECT active FROM noo_service_keys WHERE key_hash='old-hash'",
        )
        .fetch_one(&db)
        .await
        .expect("read old again");
        let new_active: bool = sqlx::query_scalar(
            "SELECT active FROM noo_service_keys WHERE key_hash='new-hash'",
        )
        .fetch_one(&db)
        .await
        .expect("read new again");
        assert!(!old_active, "retire must deactivate the superseded key");
        assert!(new_active, "retire must NOT touch the key the consumer is using");

        drop(db);
        let _ = sqlx::raw_sql("DROP DATABASE svc_key_overlap_test (FORCE)")
            .execute(&admin)
            .await;
    }

    use chrono::{Duration, Utc};

    /// A rotation is finished when the NEW key has been seen, not when the
    /// operator believes they installed it. Retiring on belief is what makes
    /// a rotation an outage: the consumer keeps presenting the old value,
    /// which is now inactive, and a refused bearer logs nothing.
    #[test]
    fn a_rotation_is_not_complete_until_the_new_key_has_been_used() {
        let created = Utc::now();
        assert!(
            !super::rotation_is_complete(None, created),
            "never used must not read as complete"
        );
        assert!(
            super::rotation_is_complete(Some(created + Duration::seconds(1)), created),
            "used after minting is complete"
        );
        assert!(
            super::rotation_is_complete(Some(created), created),
            "used at the same instant is complete — the stamp is not finer than the mint"
        );
    }

    /// Overlap protects a consumer still presenting the OLD key. When no
    /// superseded key was ever presented there is nothing to protect, and
    /// refusing forever leaves a consumer that never calls over HTTP unable
    /// to finish a rotation (svc:worker, 2026-09-27).
    #[test]
    fn retiring_is_safe_once_the_new_key_is_used_or_when_no_old_key_ever_was() {
        assert!(super::retire_is_safe(true, true), "new key used: complete, whatever the old did");
        assert!(super::retire_is_safe(true, false));
        assert!(super::retire_is_safe(false, false), "nothing was ever presented: nothing to protect");
        assert!(!super::retire_is_safe(false, true), "the old key IS in use and the new one is not: refuse");
    }

    /// A timestamp from BEFORE this key existed cannot be evidence for it.
    /// Rows carry their own stamps, so this should be unreachable — but the
    /// rule is what the caller relies on, and "some stamp exists" is the
    /// weaker rule that would let an old key's activity retire its successor.
    #[test]
    fn activity_predating_the_key_is_not_evidence_for_it() {
        let created = Utc::now();
        assert!(
            !super::rotation_is_complete(Some(created - Duration::seconds(1)), created),
            "a stamp older than the key must not count as the key having been used"
        );
    }
    use super::*;

    // ── Posture profiles: gates only ──────────────────────────

    /// The live bug, as an assertion. `apply-profile hardened` set
    /// `NOO_NATS_LEGACY_SHARED_CREDS` to 0 at runbook step C1, undoing step
    /// and a node that had not been re-provisioned lost the bus. A profile
    /// describes an environment; it must not decide where an operator is in a
    /// migration. FAILS on the old profile table, which listed all three
    /// bridges in both bundles.
    #[test]
    fn no_profile_names_a_bridge_key() {
        for name in ["hardened", "dev"] {
            let gates = posture_profile(name).expect("profile should exist");
            for (key, value) in gates {
                let kind = crate::posture::kind_of(key)
                    .unwrap_or_else(|| panic!("profile '{name}' sets unknown key {key}"));
                assert!(
                    !kind.is_bridge(),
                    "profile '{name}' sets bridge {key}={value} — applying it would move a \
                     compatibility bridge the operator is holding open (R43)"
                );
            }
        }
    }

    /// ...and the other direction: a profile that quietly stopped covering a
    /// gate would leave it at whatever `.env` says, which is how "hardened"
    /// stops meaning anything.
    #[test]
    fn every_profile_covers_every_gate() {
        for name in ["hardened", "dev"] {
            let gates = posture_profile(name).expect("profile should exist");
            for gate in crate::posture::gate_keys() {
                assert!(
                    gates.iter().any(|(k, _)| *k == gate),
                    "profile '{name}' does not set gate {gate}"
                );
            }
        }
    }

    /// `hardened` must actually harden. A profile of all-permissive values
    /// would satisfy both tests above.
    #[test]
    fn hardened_is_stricter_than_dev_where_it_matters() {
        let get = |name: &str, key: &str| {
            posture_profile(name)
                .unwrap()
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("{name} does not set {key}"))
        };
        assert_eq!(get("hardened", "NOO_EXEC_APPROVAL_MODE"), "approval");
        assert_eq!(get("dev", "NOO_EXEC_APPROVAL_MODE"), "auto");
        assert_eq!(get("hardened", "NOO_NODE_AGENT_PRIVILEGED"), "false");
        // Closed in BOTH — opening it is a per-person call.
        for name in ["hardened", "dev"] {
            assert_eq!(get(name, "NOO_MCP_EXTERNAL_ENABLED"), "0");
            // Retired: a profile naming it would write a row boot then deletes.
            assert!(posture_profile(name).unwrap().iter().all(|(k, _)| *k != "NOO_APPROVAL_BREAK_GLASS"),
                "profile '{name}' names the retired NOO_APPROVAL_BREAK_GLASS");
        }
    }

    /// An unknown profile name must not silently apply nothing.
    #[test]
    fn an_unknown_profile_is_none() {
        assert!(posture_profile("hardened-ish").is_none());
        assert!(posture_profile("").is_none());
    }

    fn ctx(scopes: &[&str]) -> Option<Extension<RequesterCtx>> {
        // Role derived from scopes, exactly as `require_any_auth` resolves a
        // legacy scope-only token — so these tests exercise the dual-accept
        // path the guards actually see.
        Some(Extension(RequesterCtx {
            sub: "tester".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role: crate::auth::Role::from_scopes(scopes),
            harness: None,
            act: None,
        }))
    }

    /// A context carrying an explicit role claim (new-style token) with the
    /// dual-emitted legacy scopes alongside.
    fn role_ctx(role: crate::auth::Role) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: "tester".into(),
            scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }))
    }

    /// The role-claim path must gate identically to the legacy scope path:
    /// only Admin may hand out privilege, Operator and below never.
    #[test]
    fn role_claims_gate_privilege_mutation_identically() {
        use crate::auth::Role;
        assert!(scope_mutation_guard(&role_ctx(Role::Admin)).is_ok());
        assert!(scope_mutation_guard(&role_ctx(Role::Operator)).is_err());
        assert!(scope_mutation_guard(&role_ctx(Role::User)).is_err());
        // And the operator guard admits Operator but not User.
        assert!(users_admin_mutation_guard(&role_ctx(Role::Operator)).is_ok());
        assert!(users_admin_mutation_guard(&role_ctx(Role::User)).is_err());
    }

    /// The whole point of the guard: `write` is a grantable tier, so it must
    /// not be able to hand itself `admin`. If this ever passes, `write` and
    /// `admin` are permanently the same privilege — a ceiling you can edit is
    /// not a ceiling.
    #[test]
    fn write_cannot_change_scopes() {
        assert!(scope_mutation_guard(&ctx(&["write"])).is_err());
        assert!(scope_mutation_guard(&ctx(&["read", "write"])).is_err());
    }

    #[test]
    fn admin_can_change_scopes() {
        assert!(scope_mutation_guard(&ctx(&["admin"])).is_ok());
        assert!(scope_mutation_guard(&ctx(&["read", "write", "admin"])).is_ok());
    }

    #[test]
    fn read_cannot_change_scopes() {
        assert!(scope_mutation_guard(&ctx(&["read"])).is_err());
        assert!(scope_mutation_guard(&ctx(&[])).is_err());
    }

    /// Cluster-HMAC callers arrive with no RequesterCtx. Every other mutation
    /// guard in this file refuses them too, but for scopes the reason is
    /// specifically attribution: the cluster secret is shared with every node,
    /// so a scope change made with it names nobody.
    #[test]
    fn cluster_hmac_cannot_change_scopes() {
        assert!(scope_mutation_guard(&None).is_err());
    }

    /// `scope_mutation_guard` is strictly stricter than the guard it replaced
    /// on this path — anything it admits, the old one admitted too. Guards the
    /// direction of the change, so a future "simplification" back to
    /// `is_operator` fails here rather than silently widening the endpoint.
    #[test]
    fn scope_guard_is_stricter_than_the_operator_guard() {
        for scopes in [vec!["write"], vec!["admin"], vec!["read"], vec![]] {
            let c = ctx(&scopes);
            if scope_mutation_guard(&c).is_ok() {
                assert!(
                    users_admin_mutation_guard(&c).is_ok(),
                    "scope guard admitted {scopes:?} that the operator guard rejects"
                );
            }
        }
    }

    /// the design's premise is that `/api/security/*` replaces the legacy
    /// surface. That is only true while it is a superset, and it was not: KB
    /// provenance rules and the team registry existed on `/api/kb/*` alone.
    /// Step 5 has since removed legacy paths (`/api/kb/rule`, 2026-09-27), so
    /// the security surface is now the ONLY door for some of these.
    ///
    /// Asserted against the router source rather than a hand-kept list,
    /// because the failure this guards against is someone deleting a path
    /// whose replacement was never actually added — at which point the
    /// capability disappears and nothing says so.
    #[test]
    fn the_security_surface_covers_every_kb_capability() {
        let src = include_str!("users.rs");
        // (capability, the handler that must be reachable under /api/security)
        for (capability, handler) in [
            ("list KB provenance rules", "api_kb_rules"),
            ("upsert/delete a KB provenance rule", "post(api_kb_rule)"),
            ("list KB teams", "api_kb_teams"),
            ("create a KB team", "api_kb_teams_create"),
        ] {
            let on_security = src
                .lines()
                .filter(|l| l.contains("\"/api/security/"))
                .any(|l| l.contains(handler));
            assert!(
                on_security,
                "{capability} ({handler}) has no /api/security/* route; that \
                 capability would have no door"
            );
        }
        // Deletion is the one that is not a verbatim reuse — it is addressed
        // by path there and by body here — so assert the shared inner fn
        // instead of the handler name.
        assert!(
            src.contains("async fn security_team_delete"),
            "no team deletion on /api/security/*"
        );
        // Assembled at compile time rather than written as one literal.
        // `include_str!` pulls in this test module too, so any literal spelling
        // of the thing being counted also matches ITSELF and the count comes
        // out one too high — which it did, twice, before this was split.
        let needle = concat!("async fn ", "team_delete_inner(");
        assert_eq!(
            src.matches(needle).count(),
            1,
            "team deletion must have exactly one implementation shared by both surfaces"
        );
    }

    /// Every mutating handler on `/api/security/*` must write an audit row.
    ///
    /// This is checked mechanically because the gap it closes was invisible:
    /// sixteen mutations — account creation, credential changes, privilege
    /// grants, API-key issuance — wrote a tracing line and nothing durable,
    /// while the legacy surface audited its equivalents. Nothing failed, no
    /// test went red, and the plan of record was to consolidate ONTO the
    /// unaudited surface. A silent reduction in audit coverage is exactly the
    /// class of regression a person does not spot in review.
    ///
    /// Handlers are found from the router, so a route added tomorrow is
    /// covered without anyone remembering to extend a list.
    #[test]
    fn every_security_mutation_writes_an_audit_row() {
        let src = include_str!("users.rs");

        // Handler names bound to a mutating verb on a /api/security/* route.
        let mut handlers: Vec<String> = Vec::new();
        for line in src.lines() {
            if !line.contains("\"/api/security/") {
                continue;
            }
            for verb in ["post(", "put(", "patch(", "delete("] {
                let mut rest = line;
                while let Some(i) = rest.find(verb) {
                    let after = &rest[i + verb.len()..];
                    let name: String =
                        after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() {
                        handlers.push(name);
                    }
                    rest = after;
                }
            }
        }
        assert!(
            handlers.len() >= 15,
            "expected the security surface to have many mutations, found {}",
            handlers.len()
        );

        // Body of a top-level `async fn`, relying on rustfmt putting the
        // closing brace at column 0.
        let body_of = |name: &str| -> Option<&str> {
            let start = src.find(&format!("async fn {name}("))?;
            let rest = &src[start..];
            let end = rest.find("\n}\n").unwrap_or(rest.len());
            Some(&rest[..end])
        };

        // Audited directly, or via one level of delegation. `security_team_delete`
        // is a thin wrapper over `team_delete_inner` — sharing that inner
        // function is deliberate (the refuse-unless-force rule must not exist
        // twice), so demanding the audit call appear in the wrapper itself
        // would push the code the wrong way to satisfy a test. What matters is
        // that the mutation produces a row, not where the call is written.
        let audited = |name: &str| -> bool {
            let Some(body) = body_of(name) else { return true };
            if body.contains("audit_event") {
                return true;
            }
            body.lines().any(|l| {
                l.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .filter(|w| w.ends_with("_inner"))
                    .any(|w| body_of(w).is_some_and(|b| b.contains("audit_event")))
            })
        };

        let unaudited: Vec<&String> = handlers.iter().filter(|h| !audited(h)).collect();

        assert!(
            unaudited.is_empty(),
            "these /api/security/* mutations write no audit_event row: {unaudited:?}\n\
             The legacy surface audits its equivalents, so leaving these unaudited means \
             converging on /api/security/* REDUCES audit coverage — a security regression \
             wearing a refactor's clothes. See followups/32."
        );
    }

    /// on the security surface, a caller below Operator —
    /// JWT or cluster-HMAC — is not refused with a bare scope error; it is
    /// redirected to the propose path, so the approval workflow survives the
    /// Admin-tab consolidation instead of being silently dropped.
    #[test]
    fn security_surface_redirects_sub_operators_to_the_propose_path() {
        use crate::auth::Role;
        for c in [role_ctx(Role::User), None] {
            let err = security_users_mutation_guard(&c).unwrap_err();
            let AppError::BadRequest(msg) = err else {
                panic!("expected the structured 400 redirect, got another variant");
            };
            assert!(
                msg.contains("POST /api/security/users/propose"),
                "rejection must name the security-surface propose path: {msg}"
            );
        }
        // >= Operator proceeds exactly as before.
        assert!(security_users_mutation_guard(&role_ctx(Role::Operator)).is_ok());
        assert!(security_users_mutation_guard(&role_ctx(Role::Admin)).is_ok());
        // And the legacy-scope path resolves identically (dual-accept).
        assert!(security_users_mutation_guard(&ctx(&["read", "write"])).is_ok());
        assert!(security_users_mutation_guard(&ctx(&["read"])).is_err());
    }

    /// Deciding a proposal executes privileged actions, so it requires a
    /// NAMED operator on both surfaces: no cluster-HMAC (the agent must not
    /// approve its own filings), no sub-operator JWT.
    #[test]
    fn proposal_decisions_require_a_named_operator() {
        use crate::auth::Role;
        assert!(proposal_decider(&None).is_err());
        assert!(proposal_decider(&role_ctx(Role::User)).is_err());
        assert_eq!(proposal_decider(&role_ctx(Role::Operator)).unwrap(), "tester");
        assert_eq!(proposal_decider(&role_ctx(Role::Admin)).unwrap(), "tester");
    }

    /// The consolidation contract itself, checked against the source like the
    /// KB-capability test above: the three legacy-guarded mutations have
    /// guarded twins on `/api/security/*`, the propose path exists there, and
    /// both decide handlers share the one operator gate.
    #[test]
    fn the_approval_workflow_is_mirrored_on_the_security_surface() {
        let src = include_str!("users.rs");
        let body_of = |name: &str| -> &str {
            let start = src
                .find(&format!("async fn {name}("))
                .unwrap_or_else(|| panic!("{name} not found"));
            let rest = &src[start..];
            &rest[..rest.find("\n}\n").unwrap_or(rest.len())]
        };
        // The mirror of what `users_admin_mutation_guard` protects on the
        // legacy side — exactly create/password/disable, per the design.
        for h in ["user_create", "user_set_password", "user_disable"] {
            assert!(
                body_of(h).contains("security_users_mutation_guard"),
                "{h} must run the security-surface workflow guard"
            );
        }
        assert!(
            src.lines().any(|l| l.contains("\"/api/security/users/propose\"")
                && l.contains("api_users_propose")),
            "the propose path must exist on /api/security/* (one handler, two paths)"
        );
        assert!(
            body_of("proposal_decide").contains("proposal_decider(&ctx)"),
            "proposal_decide must gate on proposal_decider"
        );
    }

    /// `GET /api/security/users` must gate reads
    /// exactly like the legacy `api_users_list` — a sub-operator JWT is
    /// refused (account enumeration is operator-only even on GET), Operator
    /// and above pass, and cluster-HMAC/internal callers (no `RequesterCtx`)
    /// pass because the legacy read guard admits them.
    #[test]
    fn security_users_list_is_read_guarded_like_the_legacy_surface() {
        use crate::auth::Role;
        // Guard semantics (shared with the legacy handler, so they cannot drift).
        assert!(users_admin_read_guard(&role_ctx(Role::User)).is_err());
        assert!(users_admin_read_guard(&ctx(&["read"])).is_err());
        assert!(users_admin_read_guard(&role_ctx(Role::Operator)).is_ok());
        assert!(users_admin_read_guard(&role_ctx(Role::Admin)).is_ok());
        assert!(users_admin_read_guard(&None).is_ok());
        // And the handler actually runs it (source check, like the other
        // surface-parity tests in this module).
        let src = include_str!("users.rs");
        let body = src
            .split("async fn users_list(")
            .nth(1)
            .expect("users_list not found");
        let body = &body[..body.find("\n}\n").expect("no close for users_list")];
        assert!(
            body.contains("users_admin_read_guard(&ctx)"),
            "users_list must run the shared read guard"
        );
    }

    /// The lockout state is what an operator actually wants when an account
    /// "cannot log in", and it was visible only on the legacy surface.
    #[test]
    fn the_user_list_exposes_lockout_state() {
        let src = include_str!("users.rs");
        let body = src
            .split("async fn users_list(")
            .nth(1)
            .expect("users_list not found");
        let body = &body[..body.find("\n}\n").expect("no close for users_list")];
        assert!(
            body.contains("list_with_lock"),
            "users_list must use the projection that carries locked_until"
        );
        assert!(
            body.contains("\"locked_until\""),
            "locked_until must reach the response, not just the query"
        );
    }

    // ── User-proposal validation (moved from tests/test_user_proposals.py in
    // the 2026-08-08 reference sweep — the Python body is archived in
    // legacy/python-workers-reference/users.py; this fn is the live one). ──

    #[test]
    fn proposal_validation_rejects_bad_username() {
        let err = validate_user_proposal("create", &json!({"username": "no way!"})).unwrap();
        assert!(err.contains("username"), "{err}");
    }

    #[test]
    fn proposal_validation_rejects_embedded_password() {
        let err = validate_user_proposal(
            "create",
            &json!({"username": "bob", "password": "sneaky-plaintext"}),
        )
        .unwrap();
        assert!(err.contains("password"), "{err}");
    }

    #[test]
    fn proposal_validation_rejects_unknown_scopes() {
        let err =
            validate_user_proposal("create", &json!({"username": "bob", "scopes": ["root"]}))
                .unwrap();
        assert!(err.contains("unknown scopes"), "{err}");
    }

    #[test]
    fn proposal_validation_disable_needs_bool() {
        let err = validate_user_proposal("disable", &json!({"username": "bob"})).unwrap();
        assert!(err.contains("bool"), "{err}");
    }

    #[test]
    fn proposal_validation_good_payloads_pass() {
        assert_eq!(validate_user_proposal("create", &json!({"username": "bob"})), None);
        assert_eq!(
            validate_user_proposal(
                "grant_roles",
                &json!({"username": "bob", "roles": ["team:research"]})
            ),
            None
        );
        assert_eq!(
            validate_user_proposal("disable", &json!({"username": "bob", "disabled": true})),
            None
        );
    }

    /// The propose handler must gate action + payload shape BEFORE any SQL —
    /// the same pure-path property tests/test_user_proposals.py pinned on the
    /// Python body (unknown action → error mentioning "action"; non-object
    /// payload → "payload (object) required").
    #[test]
    fn propose_handler_gates_action_and_payload_before_sql() {
        let src = include_str!("users.rs");
        let start = src.find("async fn api_users_propose(").expect("handler present");
        let body = &src[start..];
        let action_gate = body.find("USER_PROPOSAL_ACTIONS.contains").expect("action gate");
        let payload_gate = body.find("payload (object) required").expect("payload gate");
        let validate = body.find("validate_user_proposal(&action, &payload)").expect("validate");
        let first_sql = body.find("sqlx::query").expect("insert");
        assert!(action_gate < first_sql && payload_gate < first_sql && validate < first_sql,
            "propose must validate before touching the DB");
    }

    // ── The tier clamp ───────────────────────────

    /// An Operator creating an account with `scopes: ["admin"]` — the exact
    /// request in the R1 finding. `repo::users::create` derives
    /// `role = 'admin'` from that list, so this WAS Operator → Admin in one
    /// call. FAILS on the unfixed code (there was no `require_may_grant`).
    #[test]
    fn operator_cannot_create_an_admin_account() {
        let admin_scopes = vec!["read".to_string(), "write".into(), "admin".into()];
        let err = require_may_grant(&role_ctx(crate::auth::Role::Operator), &admin_scopes)
            .expect_err("an Operator must not mint an admin");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "must be a 403, not a 400 — this is an authorization answer, got {err:?}"
        );
        // …and the legacy/proposal surfaces, which carry an untyped list.
        assert!(require_may_grant_value(
            &role_ctx(crate::auth::Role::Operator),
            Some(&json!(["admin"])),
        )
        .is_err());
        assert!(require_may_grant_value(
            &role_ctx(crate::auth::Role::Operator),
            Some(&json!(["read", "write"])),
        )
        .is_err(), "['read','write'] resolves to Operator — a peer, not below");
    }

    /// The same requests an Operator is still supposed to make.
    #[test]
    fn operator_can_still_create_user_tier_accounts() {
        assert!(require_may_grant(&role_ctx(crate::auth::Role::Operator), &["read".to_string()]).is_ok());
        // Missing / null / empty all mean the ["read"] default an approved
        // create gets, i.e. the User tier.
        for scopes in [None, Some(&json!(null)), Some(&json!([]))] {
            assert!(
                require_may_grant_value(&role_ctx(crate::auth::Role::Operator), scopes).is_ok(),
                "the default tier must stay creatable by an Operator"
            );
        }
    }

    /// Admin creates any tier; cluster-HMAC (no RequesterCtx) is the
    /// documented break-glass exemption and is unaffected.
    #[test]
    fn admin_creates_any_tier_and_cluster_hmac_is_exempt() {
        assert!(require_may_grant(&role_ctx(crate::auth::Role::Admin), &["admin".to_string()]).is_ok());
        assert!(require_may_grant(&None, &["admin".to_string()]).is_ok());
        assert!(require_may_grant_value(&None, Some(&json!(["admin"]))).is_ok());
    }

    /// The "21 chances to forget one" guard. Every handler on this surface
    /// that names ANOTHER account by path or body must reach a clamp helper.
    /// A new mutation route that skips it fails here rather than shipping as
    /// a quiet hole — which is exactly how R1 happened.
    #[test]
    fn every_account_naming_mutation_reaches_the_clamp() {
        let src = include_str!("users.rs");
        // (handler, the clamp call that must appear in its body)
        let required: &[(&str, &[&str])] = &[
            ("async fn user_create(", &["require_may_grant("]),
            ("async fn user_set_password(", &["require_may_manage("]),
            ("async fn user_disable(", &["require_may_manage(", "require_not_last_admin("]),
            ("async fn user_set_scopes(", &["require_may_manage(", "require_not_last_admin("]),
            ("async fn user_set_role(", &["require_may_manage(", "require_not_last_admin("]),
            ("async fn user_erase(", &["require_may_manage(", "require_not_last_admin("]),
            ("async fn user_set_org(", &["require_may_manage("]),
            ("async fn user_link_create(", &["require_may_manage("]),
            ("async fn channel_link_delete(", &["require_may_manage("]),
            ("async fn user_grant_roles(", &["require_may_manage("]),
            ("async fn user_revoke_roles(", &["require_may_manage("]),
            ("async fn service_key_issue(", &["require_may_manage("]),
            ("async fn service_key_rotate(", &["require_may_manage_key_consumer("]),
            ("async fn service_key_revoke(", &["require_may_manage_key_consumer("]),
            ("async fn service_key_set_quota(", &["require_may_manage_key_consumer("]),
            ("async fn proposal_decide(", &["require_may_grant_value(", "require_may_manage("]),
            ("async fn api_users_disable(", &["require_may_manage(", "require_not_last_admin("]),
        ];
        // The parse itself must find something — a renamed handler that
        // silently matched nothing would make this test pass while checking
        // nothing at all.
        assert_eq!(required.len(), 17, "keep the list and the count in step");
        for (sig, calls) in required {
            let start = src
                .find(sig)
                .unwrap_or_else(|| panic!("handler {sig} not found — was it renamed?"));
            // Bound the search to this handler: the next `\nasync fn ` after it.
            let rest = &src[start + sig.len()..];
            let end = rest.find("\nasync fn ").unwrap_or(rest.len());
            let body = &rest[..end];
            for call in *calls {
                assert!(
                    body.contains(call),
                    "{sig} does not call {call} — an account-naming mutation without the tier clamp"
                );
            }
        }
    }
}

/// the per-user stores a right-to-be-forgotten erase used to
/// leave behind. Real schema (migrated scratch database); skips without a DSN.
#[cfg(test)]
mod rtbf_residue_tests {
    use serde_json::{json, Value};

    /// Stores whose rows X owns and Y owns: one each (two for the tasks).
    const STORES: &[(&str, &str)] = &[
        ("tasks", "noo_tasks"),
        ("approval_requests", "noo_approval_requests"),
        ("channel_recipients", "noo_channel_recipients"),
        ("refresh_tokens", "noo_refresh_tokens"),
        ("graph_prune_entities", "graph_prune_staging"),
        ("graph_prune_edges", "graph_edge_prune_staging"),
        ("uploads", "noo_uploads"),
        ("legacy_feedback_preferences", "noo_feedback_preferences"),
        ("legacy_feedback_ratings", "noo_feedback_ratings"),
        ("legacy_feedback_messages", "noo_feedback_messages"),
        ("legacy_feedback_conversations", "noo_feedback_conversations"),
        ("coding_tasks", "noo_coding_tasks"),
    ];

    /// Run `sql` with `<u>` replaced by the account name.
    async fn run(db: &sqlx::PgPool, user: &str, sql: &str) {
        sqlx::query(&sql.replace("<u>", user)).execute(db).await.unwrap();
    }

    async fn seed(db: &sqlx::PgPool, user: &str, n_tasks: usize) {
        for _ in 0..n_tasks {
            run(db, user, "INSERT INTO noo_tasks (objective, owner_uuid, conversation_id, thread_id, last_note) \
               VALUES ('<u> objective', (SELECT user_uuid FROM noo_users WHERE username = '<u>'), gen_random_uuid(), 't', 'PRIVATE note')").await;
        }
        run(db, user, "INSERT INTO noo_approval_requests (request_id, tool_name, risk_level, reason, requester) \
           VALUES ('req-<u>', 'python_exec', 'high', 'PRIVATE tool arguments', '<u>')").await;
        run(db, user, "INSERT INTO noo_channel_recipients (id, channel, recipient_id, display_name, notes, owner) \
           VALUES ('rc-<u>', 'telegram', 'chat-<u>', '<u> contact', 'PRIVATE note', '<u>')").await;
        run(db, user, "INSERT INTO noo_refresh_tokens (id, user_id, token_hash, expires_at, user_agent, ip_address) \
           VALUES (gen_random_uuid(), '<u>', 'h-<u>', now() + interval '1 day', 'UA', '10.0.0.9')").await;
        run(db, user, "INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload) \
           VALUES (gen_random_uuid(), '<u> entity', 'x', 'junk', '{\"user_id\": \"<u>\", \"entity\": {}}'::jsonb)").await;
        run(db, user, "INSERT INTO graph_edge_prune_staging (edge_id, src_entity_id, rel_type, dst_entity_id, reason, user_id) \
           VALUES (gen_random_uuid(), gen_random_uuid(), 'RELATED_TO', gen_random_uuid(), 'low_confidence', '<u>')").await;
        run(db, user, "INSERT INTO noo_uploads (file_id, owner, filename) VALUES ('f-<u>', '<u>', 'a.txt')").await;
        // The legacy feedback chain, and the coding task that ran in the user's conversation.
        let (conv, fconv, m1, m2) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        sqlx::query("INSERT INTO noo_conversations (id, user_id) VALUES ($1, $2)").bind(conv).bind(user).execute(db).await.unwrap();
        sqlx::query("INSERT INTO noo_coding_tasks (id, description, conversation_id) VALUES ($1, 'PRIVATE description', $2)")
            .bind(format!("ct-{user}")).bind(conv.to_string()).execute(db).await.unwrap();
        sqlx::query("INSERT INTO noo_feedback_conversations (id, session_id, user_id, started_at) VALUES ($1, $3, $2, now())")
            .bind(fconv).bind(user).bind(format!("s-{user}")).execute(db).await.unwrap();
        for m in [m1, m2] {
            sqlx::query("INSERT INTO noo_feedback_messages (id, conversation_id, role, content, \"timestamp\") VALUES ($1, $2, 'user', 'PRIVATE', now())")
                .bind(m).bind(fconv).execute(db).await.unwrap();
        }
        sqlx::query("INSERT INTO noo_feedback_ratings (id, message_id, user_id, rating, created_at) VALUES (gen_random_uuid(), $1, $2, 1, now())")
            .bind(m1).bind(user).execute(db).await.unwrap();
        sqlx::query("INSERT INTO noo_feedback_preferences (id, prompt, chosen_response, rejected_response, chosen_message_id, rejected_message_id, created_at) \
                     VALUES (gen_random_uuid(), 'PRIVATE', 'a', 'b', $1, $2, now())")
            .bind(m1).bind(m2).execute(db).await.unwrap();
    }

    async fn count(db: &sqlx::PgPool, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}")).fetch_one(db).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_erase_empties_each_residue_store_for_the_user_and_leaves_another_users_alone() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("rtbf_residue").await else { return };
        crate::ops::tests::stub_erase_stores(&db).await;
        use crate::auth::Role;
        let _ = crate::ops::tests::account(&db, "xuser", Role::User).await;
        let _ = crate::ops::tests::account(&db, "yuser", Role::User).await;
        seed(&db, "xuser", 2).await;
        seed(&db, "yuser", 1).await;
        // Rows that are nobody's: the shared address book, a staged row nobody can be named for.
        sqlx::query("INSERT INTO noo_channel_recipients (id, channel, recipient_id, display_name, owner) VALUES ('shared', 'telegram', '1', 'shared', NULL)")
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload) VALUES (gen_random_uuid(), 'legacy', 'x', 'junk', '{\"entity\": {}}'::jsonb)")
            .execute(&db).await.unwrap();

        let before: Vec<i64> = {
            let mut v = Vec::new();
            for (_, t) in STORES {
                v.push(count(&db, t).await);
            }
            v
        };
        let row = |v: &Value, store: &str| {
            v.as_array().unwrap().iter().find(|p| p["store"] == store).map(|p| p["rows"].as_i64().unwrap())
        };

        // The preview counts each new store, and mutates nothing.
        let preview = super::erase_account(&db, "xuser", true, false).await.expect("preview");
        for (label, table) in STORES {
            let want = if matches!(*label, "tasks" | "legacy_feedback_messages") { 2 } else { 1 };
            assert_eq!(row(&preview["plan"], label), Some(want), "the preview counts {label} ({table}): {preview}");
        }
        for ((_, t), b) in STORES.iter().zip(&before) {
            assert_eq!(count(&db, t).await, *b, "a preview deletes nothing from {t}");
        }

        let done = super::erase_account(&db, "xuser", false, false).await.expect("erase");
        for (label, _) in STORES {
            assert_eq!(row(&done["deleted"], label), row(&preview["plan"], label), "the erase does what the preview said for {label}");
        }

        // Y's rows (and the nobody's rows) are all that is left.
        for (label, table) in STORES {
            let extra = match *label {
                "channel_recipients" | "graph_prune_entities" => 1,
                _ => 0,
            };
            let own = if *label == "legacy_feedback_messages" { 2 } else { 1 };
            assert_eq!(count(&db, table).await, own + extra, "{table}: only yuser's rows (and nobody's) remain");
        }
        let x_left: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM noo_tasks WHERE objective LIKE 'xuser%') \
                  + (SELECT count(*) FROM noo_approval_requests WHERE requester = 'xuser') \
                  + (SELECT count(*) FROM noo_channel_recipients WHERE owner = 'xuser') \
                  + (SELECT count(*) FROM noo_refresh_tokens WHERE user_id = 'xuser') \
                  + (SELECT count(*) FROM graph_prune_staging WHERE payload->>'user_id' = 'xuser') \
                  + (SELECT count(*) FROM graph_edge_prune_staging WHERE user_id = 'xuser') \
                  + (SELECT count(*) FROM noo_uploads WHERE owner = 'xuser') \
                  + (SELECT count(*) FROM noo_feedback_conversations WHERE user_id = 'xuser') \
                  + (SELECT count(*) FROM noo_coding_tasks WHERE id = 'ct-xuser')",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(x_left, 0, "nothing of xuser's survives in any residue store");
        assert_eq!(count(&db, "noo_tasks").await, 1, "the task did not just lose its owner: it is gone");

        // Archive-then-delete: every store's content is in the staging archive, under this run.
        let staged: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT store FROM noo_user_erasure_staging WHERE username = 'xuser' ORDER BY 1",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        for (label, _) in STORES {
            assert!(staged.iter().any(|s| s == label), "{label} is archived: {staged:?}");
        }
        let note: Vec<String> = sqlx::query_scalar("SELECT payload->>'last_note' FROM noo_user_erasure_staging WHERE store = 'tasks'")
            .fetch_all(&db).await.unwrap();
        assert_eq!(note, ["PRIVATE note", "PRIVATE note"], "the task's content is recoverable from the archive within its window");
    }

    /// The prune RESTORE route refuses an erased user's rows, and still serves
    /// everyone else's (status "refused" vs anything else).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_prune_restore_refuses_rows_that_belong_to_an_erased_user() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("rtbf_restore").await else { return };
        crate::ops::tests::stub_erase_stores(&db).await;
        use crate::auth::Role;
        let _ = crate::ops::tests::account(&db, "xuser", Role::User).await;
        let _ = crate::ops::tests::account(&db, "yuser", Role::User).await;
        // X is erased: a row staged for them after (a prune racing the erase) or
        // before (one that outlived it) must not come back.
        super::erase_account(&db, "xuser", false, false).await.expect("erase");
        let payload = |u: &str| json!({"user_id": u, "entity": {"entity_id": uuid::Uuid::new_v4().to_string(), "canonical_name": "N", "type": "t"}, "edges": [], "mentions": []});
        let mut ids = std::collections::HashMap::new();
        for u in ["xuser", "yuser"] {
            let sid: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload) \
                 VALUES (gen_random_uuid(), 'N', 't', 'junk', $1) RETURNING staging_id",
            )
            .bind(payload(u)).fetch_one(&db).await.unwrap();
            let esid: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO graph_edge_prune_staging (edge_id, src_entity_id, rel_type, dst_entity_id, reason, user_id) \
                 VALUES (gen_random_uuid(), gen_random_uuid(), 'R', gen_random_uuid(), 'low', $1) RETURNING staging_id",
            )
            .bind(u).fetch_one(&db).await.unwrap();
            ids.insert(u, (sid.to_string(), esid.to_string()));
        }
        let (xs, xe) = &ids["xuser"];
        let r = crate::memory::provider::prune_restore_entity(&db, xs).await;
        assert_eq!(r["status"], "refused", "{r}");
        let r = crate::memory::provider::prune_restore_edge(&db, xe).await;
        assert_eq!(r["status"], "refused", "{r}");
        let restored: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM graph_prune_staging WHERE restored_at IS NOT NULL) \
                  + (SELECT count(*) FROM graph_edge_prune_staging WHERE restored_at IS NOT NULL)",
        )
        .fetch_one(&db).await.unwrap();
        assert_eq!(restored, 0, "a refused restore marks nothing restored");
        // A live user's row is not refused (here it fails later, on the stub tables,
        // which is the point: the refusal is about whose row it is, not about errors).
        let (ys, ye) = &ids["yuser"];
        assert_ne!(crate::memory::provider::prune_restore_entity(&db, ys).await["status"], "refused");
        assert_ne!(crate::memory::provider::prune_restore_edge(&db, ye).await["status"], "refused");
    }

    /// The files behind an erased user's upload rows go; a file another account
    /// also uploaded (same content hash) stays; and a name that merely starts
    /// like the id is not enough.
    #[tokio::test]
    async fn upload_files_are_removed_by_content_hash_prefix() {
        let dir = std::env::temp_dir().join(format!("noo_uploads_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["aaaa_one.txt", "aaaa_two.pdf", "bbbb_keep.txt", "aaaab_other.txt"] {
            std::fs::write(dir.join(f), "x").unwrap();
        }
        let n = crate::routes::ui::remove_upload_files(&dir, &["aaaa".to_string()]).await;
        assert_eq!(n, 2);
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["aaaab_other.txt", "bbbb_keep.txt"]);
        assert_eq!(crate::routes::ui::remove_upload_files(&dir, &[]).await, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
