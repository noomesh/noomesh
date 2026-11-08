// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! "View as" (i538 P1): an operator narrows their OWN session to a
//! perspective — a lower role, add-ons treated as disabled or absent, or no
//! entitlement — and every request of that session answers as the narrower
//! view until the operator goes back.
//!
//! The mechanism (`noomesh-internal/proposals/i538-view-as-perspectives.md`
//! §3) is a signed claim backed by a server-side row:
//!
//! - **The row** (`noo_perspectives`) is written by `POST /api/auth/perspective`
//!   and stamped on the session's live refresh row (`perspective_id`) in the
//!   same transaction. From then on every refresh of that session mints a
//!   perspective token, until the row ends (Back to me, a switch, logout, the
//!   family being revoked, or the unadvertised 12 h cap).
//! - **The token** carries the NARROWED `role` (so every role check in the
//!   gateway is already on the narrower path; nothing new to learn there) and
//!   a signed `prs` claim naming the row.
//! - **The middleware** refuses a `prs` token whose row has ended, belongs to
//!   another account, or is past its cap ([`admit`]), with a cached lookup
//!   like `auth::delegated_subject_enabled`.
//!
//! Two barriers keep a perspective from ever widening anything: the type
//! ([`Perspective`] can only express removals, and [`effective`] is a `min`),
//! and the start/switch validation ([`validate`]), which refuses a role cap at
//! or above the account's LIVE role.
//!
//! P1 does not apply the add-on and licence dimensions to the gateway's
//! process-wide accessors (`addons::state`, `addon_registry`,
//! `entitlement::licensed`); that is P2's task-local. P1 records them,
//! validates them, carries them in the claim, and answers them on
//! `/auth/me`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::audit::{AuditEvent, AuditKind};
use crate::auth::{Claims, Role};

/// The unadvertised safety net (D-2): a perspective row lives at most this
/// long, so an orphaned one cannot narrow a session forever. Never sent to
/// the console.
pub const CAP_HOURS: i32 = 12;

/// 401 on any request whose token names a perspective that is no longer
/// live. The console's refresher then gets a real token, because the session
/// no longer carries the perspective.
pub const ENDED: &str = "perspective_ended";
pub const NEEDS_OPERATOR: &str = "perspective_needs_operator";
pub const CANNOT_WIDEN: &str = "perspective_cannot_widen";
pub const UNKNOWN_ADDON: &str = "perspective_unknown_addon";
pub const NO_CHANGE: &str = "perspective_no_change";
pub const ACTIVE: &str = "perspective_active";
pub const INVALID: &str = "perspective_invalid";
pub const NONE: &str = "perspective_none";
pub const NOT_THIS_SESSION: &str = "perspective_not_this_session";
pub const NEEDS_SESSION: &str = "perspective_needs_session";
pub const UNAVAILABLE: &str = "perspective_unavailable";
/// 403 on a perspective route from anything but a plain person-session
/// token: the set `/auth/refresh` issues, with no `act`, `harness`, `conv` or
/// `cnf` (the cert binding is not checked on this path, so a bound token is
/// refused rather than half-honoured).
pub const NEEDS_PERSON: &str = "perspective_needs_a_person_session";
/// 403 from every credential mint a perspective session may not reach
/// (§4.3): a mint would hand out the real role, or outlive the perspective.
pub const REFUSES_MINT: &str = "perspective_refuses_mint";

/// How an add-on is hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hide {
    /// As if the operator had switched it off.
    Disabled,
    /// As if it had never been installed: not reported at all.
    Absent,
}

/// What a perspective holds. Every field is a REMOVAL — a role cap, add-ons
/// to hide, no entitlement — and there is no field that could mean "add".
/// That is the type-level half of "narrow only" (R1). Unknown fields are
/// refused (a P4 `seat` sent to a P1 gateway is a 422, not ignored).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Perspective {
    #[serde(default, with = "role_opt", skip_serializing_if = "Option::is_none")]
    pub role_cap: Option<Role>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addons: BTreeMap<String, Hide>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub core_only: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Perspective {
    /// No dimension is active: the same as Back to me.
    pub fn is_empty(&self) -> bool {
        self.role_cap.is_none() && self.addons.is_empty() && !self.core_only
    }
}

/// `Role` on the wire as its canonical name; an unknown name is an error.
mod role_opt {
    use crate::auth::Role;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(role: &Option<Role>, s: S) -> Result<S::Ok, S::Error> {
        match role {
            Some(r) => s.serialize_some(r.as_str()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Role>, D::Error> {
        let raw: Option<String> = Option::deserialize(d)?;
        raw.map(|r| r.parse::<Role>().map_err(serde::de::Error::custom)).transpose()
    }
}

/// The signed `prs` claim of a perspective access token: the row, and the
/// dimensions it was started with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrsClaim {
    pub id: String,
    pub dims: Perspective,
}

/// Put on a request by the auth middleware when its token carried a LIVE
/// perspective. Handlers that mint a credential refuse when it is present
/// ([`refuse_mint`]); Grafana takes the lower role ([`clamp`]). Also the
/// SNAPSHOT a chat turn or a task carries ([`current`], `noo_tasks.perspective`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequesterPerspective {
    pub id: String,
    pub dims: Perspective,
}

// ───────────────────────── the snapshot a turn or a task carries ─────────────────────────

tokio::task_local! {
    /// The perspective a chat turn was submitted under. Set by the auth
    /// middleware around the rest of a JWT request, by the console socket
    /// around each turn (from the ticket's verified claims), and by the
    /// in-process task runner from the task's stored snapshot. Read by the
    /// role reads that bypass the token: the node-harness turn token
    /// (`coordinator::dispatch::try_dispatch`, `tasks::start`) and the
    /// external-tool audience (`mcp_bridge::identity`).
    ///
    /// Like `bus_principal`'s own task-local it does NOT cross
    /// `tokio::spawn`. That is why the snapshot also rides inside the bus
    /// `Principal` ([`crate::bus_principal::Principal::narrowed`]), which
    /// detached work re-binds: [`current`] falls back to it.
    static CURRENT: Option<RequesterPerspective>;
}

/// The snapshot in scope: this task-local's, else the one the bus principal
/// in scope carries; `None` outside both (a background loop, a channel bot,
/// a request without a perspective).
pub fn current() -> Option<RequesterPerspective> {
    CURRENT.try_with(|p| p.clone()).ok().flatten().or_else(crate::bus_principal::current_perspective)
}

/// The view a child task may have when it is submitted under one
/// perspective and its parent was under another: the INTERSECTION, so a
/// child is never wider than either. The lower role cap; every add-on
/// either hides (`absent` beats `disabled`); core-only if either is.
pub fn intersect(a: &Perspective, b: &Perspective) -> Perspective {
    let role_cap = match (a.role_cap, b.role_cap) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    let mut addons = a.addons.clone();
    for (name, hide) in &b.addons {
        let merged = match (addons.get(name), hide) {
            (Some(Hide::Absent), _) | (_, Hide::Absent) => Hide::Absent,
            _ => Hide::Disabled,
        };
        addons.insert(name.clone(), merged);
    }
    Perspective { role_cap, addons, core_only: a.core_only || b.core_only }
}

/// The snapshot a new task takes: the request's (or turn's) and its
/// parent task's, intersected when both exist (the id is the request's).
pub fn combine(current: Option<RequesterPerspective>, parent: Option<RequesterPerspective>) -> Option<RequesterPerspective> {
    match (current, parent) {
        (Some(c), Some(p)) => Some(RequesterPerspective { dims: intersect(&c.dims, &p.dims), id: c.id }),
        (c, p) => c.or(p),
    }
}

/// Run `fut` with `p` as the turn's snapshot. A `tokio::spawn` inside `fut`
/// does NOT inherit it: put the scope inside a spawned task, not around the
/// spawn.
pub async fn scope<F: std::future::Future>(p: Option<RequesterPerspective>, fut: F) -> F::Output {
    CURRENT.scope(p, fut).await
}

/// The snapshot rule (i538 P1): a role read from the database for a turn or
/// a task submitted under a perspective is `min(live, snapshot)`, whether or
/// not the perspective's row is still live. It never widens (a min with the
/// LIVE role, so a demotion still wins) and it never strands a turn that
/// outlives Back to me or the cap.
pub fn snapshot_role(live: Role, snapshot: Option<&RequesterPerspective>) -> Role {
    match snapshot {
        Some(p) => narrow_role(live, &p.dims),
        None => live,
    }
}

/// The snapshot a task was submitted under (`noo_tasks.perspective`). A
/// snapshot that cannot be read, or parsed (a newer gateway's dimension),
/// FAILS CLOSED to the narrowest view, a `user` cap: it is a narrowing the
/// task already had, and guessing "none" would widen it.
pub async fn task_snapshot(db: &PgPool, task_id: uuid::Uuid) -> Option<RequesterPerspective> {
    let narrowest = || {
        Some(RequesterPerspective {
            id: String::new(),
            dims: Perspective { role_cap: Some(Role::User), ..Perspective::default() },
        })
    };
    let row: Result<Option<Option<Value>>, sqlx::Error> =
        crate::repo::tasks::perspective(db, task_id).await;
    match row {
        Ok(Some(Some(v))) => match serde_json::from_value::<RequesterPerspective>(v) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(task = %task_id, error = %e, "task perspective unreadable; the task runs as a user view");
                narrowest()
            }
        },
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(task = %task_id, error = %e, "task perspective could not be read; the task runs as a user view");
            narrowest()
        }
    }
}

// ───────────────────────── the narrowing function ─────────────────────────

/// An add-on as a view reports it. "Absent" is not a variant: an absent
/// add-on is simply not in the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonView {
    Enabled,
    Disabled,
    Unlicensed,
}

impl From<&crate::addons::AddonState> for AddonView {
    fn from(s: &crate::addons::AddonState) -> Self {
        match s {
            crate::addons::AddonState::Enabled => AddonView::Enabled,
            crate::addons::AddonState::Disabled => AddonView::Disabled,
            crate::addons::AddonState::Unlicensed(_) => AddonView::Unlicensed,
        }
    }
}

/// What the account really has: its live role, the add-ons as the registry
/// reports them, and whether an entitlement is installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Real {
    pub role: Role,
    pub addons: BTreeMap<String, AddonView>,
    pub licensed: bool,
}

/// The same shape, as the perspective lets the session see it.
pub type Effective = Real;

/// The role rule: a `min`, so it can only go down.
pub fn narrow_role(real: Role, p: &Perspective) -> Role {
    real.min(p.role_cap.unwrap_or(real))
}

/// The add-on rule: `Enabled` becomes `Disabled` or disappears when hidden;
/// any other state passes through unchanged. Nothing here turns anything on.
pub fn narrow_addon(real: AddonView, hide: Option<Hide>) -> Option<AddonView> {
    match (real, hide) {
        (AddonView::Enabled, Some(Hide::Disabled)) => Some(AddonView::Disabled),
        (AddonView::Enabled, Some(Hide::Absent)) => None,
        (other, _) => Some(other),
    }
}

/// §4.1: the view a perspective leaves. Pure, so it is tested exhaustively
/// (`a_perspective_never_widens`). An add-on the real view does not have is
/// never added, whatever the perspective names.
pub fn effective(real: &Real, p: &Perspective) -> Effective {
    let addons = real
        .addons
        .iter()
        .filter_map(|(name, state)| narrow_addon(*state, p.addons.get(name).copied()).map(|v| (name.clone(), v)))
        .collect();
    Effective {
        role: narrow_role(real.role, p),
        addons,
        licensed: real.licensed && !p.core_only,
    }
}

/// Does the perspective change anything about `real`? A perspective that
/// changes nothing would look narrowed while being the real view.
pub fn changes_anything(real: &Real, p: &Perspective) -> bool {
    let e = effective(real, p);
    e.role != real.role || e.licensed != real.licensed || e.addons != real.addons
}

/// Grafana's session role under a perspective: the LOWER of the account's
/// live role and the perspective's (§4.3). `None` stays `None`.
pub fn clamp(live: Option<Role>, p: Option<&RequesterPerspective>) -> Option<Role> {
    match (live, p) {
        (Some(l), Some(p)) => Some(narrow_role(l, &p.dims)),
        (l, _) => l,
    }
}

/// The answer to a request that would mint a credential under a
/// perspective: 403 `perspective_refuses_mint`. `what` names the mint in the
/// log.
pub fn refuse_mint(
    p: Option<&axum::Extension<RequesterPerspective>>,
    what: &'static str,
) -> Result<(), crate::routes::AppError> {
    match p {
        Some(axum::Extension(p)) => {
            tracing::info!(perspective = %p.id, mint = what, "perspective_refuses_mint");
            Err(crate::routes::AppError::Forbidden(REFUSES_MINT.into()))
        }
        None => Ok(()),
    }
}

/// The perspective as `/auth/me` and the start/switch answers show it.
/// Never `cap_at` (D-2: the cap is not advertised).
pub fn view(id: &str, dims: &Perspective, started_at: DateTime<Utc>) -> Value {
    json!({
        "id": id,
        "dims": dims,
        "started_at": started_at.to_rfc3339(),
        "cap_at": (started_at + chrono::Duration::hours(i64::from(CAP_HOURS))).to_rfc3339(),
    })
}

// ───────────────────────── refusals ─────────────────────────

/// A refusal from a perspective route: a status and a machine-readable
/// `detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub status: StatusCode,
    pub detail: &'static str,
}

fn refused(status: StatusCode, detail: &'static str) -> Refused {
    Refused { status, detail }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

/// The request body of a start or a switch. An empty body is the empty
/// perspective; anything that does not parse (an unknown field included) is
/// a 422.
pub fn parse_dims(body: &[u8]) -> Result<Perspective, Refused> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Perspective::default());
    }
    serde_json::from_slice(body).map_err(|e| {
        tracing::info!(error = %e, "perspective body refused");
        refused(StatusCode::UNPROCESSABLE_ENTITY, INVALID)
    })
}

/// A perspective route answers a plain person-session token only (the set
/// `/auth/refresh` issues): no delegation (`act`), no harness, no pinned
/// conversation, no certificate binding.
pub fn plain_session(claims: &Claims) -> Result<(), Refused> {
    if claims.act.is_some() || claims.harness.is_some() || claims.conv.is_some() || claims.cnf.is_some() {
        return Err(refused(StatusCode::FORBIDDEN, NEEDS_PERSON));
    }
    Ok(())
}

// ───────────────────────── liveness (the middleware's lookup) ─────────────────────────

#[derive(Debug, Clone)]
struct Row {
    account: String,
    ended: bool,
    cap_at: DateTime<Utc>,
    started_at: DateTime<Utc>,
}

/// How long a liveness answer is cached. Short, and ending a perspective in
/// this process drops its entry at once ([`forget`]), so Back to me takes
/// effect on the next request.
const LIVENESS_TTL: Duration = Duration::from_secs(3);

type Cache = RwLock<HashMap<String, (Option<Row>, Instant)>>;

static LIVENESS: OnceLock<Cache> = OnceLock::new();

fn cache() -> &'static Cache {
    LIVENESS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn forget(id: &str) {
    if let Ok(mut map) = cache().write() {
        map.remove(id);
    }
}

async fn row(db: &PgPool, id: &str) -> Result<Option<Row>, sqlx::Error> {
    if let Ok(map) = cache().read() {
        if let Some((r, at)) = map.get(id) {
            if at.elapsed() < LIVENESS_TTL {
                return Ok(r.clone());
            }
        }
    }
    let fetched = crate::repo::perspectives::liveness(db, id).await?;
    let r = fetched.map(|(account, ended, cap_at, started_at)| Row { account, ended, cap_at, started_at });
    if let Ok(mut map) = cache().write() {
        if map.len() > 10_000 {
            map.clear();
        }
        map.insert(id.to_string(), (r.clone(), Instant::now()));
    }
    Ok(r)
}

/// Why a `prs` token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No such row (or not a row id at all).
    Unknown,
    /// The row belongs to another account.
    NotOwner,
    /// The row has ended, or reached its cap just now.
    Ended,
    /// The database could not answer. Refused, never read as live.
    Unavailable,
}

/// The middleware's check (§3.1 step 4): the row exists, belongs to `sub`,
/// has not ended and is before `cap_at`. A row found past its cap is ended
/// here, with reason `cap`. `Ok` carries `started_at` for `/auth/me`.
pub async fn admit(db: &PgPool, sub: &str, prs: &PrsClaim) -> Result<DateTime<Utc>, Refusal> {
    if uuid::Uuid::parse_str(&prs.id).is_err() {
        return Err(Refusal::Unknown);
    }
    let row = match row(db, &prs.id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(Refusal::Unknown),
        Err(e) => {
            tracing::warn!(perspective = %prs.id, error = %e, "perspective liveness check failed; refusing");
            return Err(Refusal::Unavailable);
        }
    };
    if row.account != sub {
        return Err(Refusal::NotOwner);
    }
    if row.ended {
        return Err(Refusal::Ended);
    }
    // The app clock here, the database's `now()` in `carried`: the two can
    // disagree by the hosts' clock skew, which only moves the moment a 12 h
    // safety net fires by that skew. Either side ends the row, and an ended
    // row is ended for both.
    if Utc::now() >= row.cap_at {
        if let Err(e) = end(db, &prs.id, EndReason::Cap).await {
            tracing::warn!(perspective = %prs.id, error = %e, "perspective past its cap could not be ended");
        }
        return Err(Refusal::Ended);
    }
    Ok(row.started_at)
}

/// The HTTP answer for a refused `prs` token: 401 `perspective_ended`, or
/// 503 when the database could not say.
pub fn refusal_response(why: Refusal) -> Response {
    match why {
        Refusal::Unavailable => refused(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE).into_response(),
        Refusal::Unknown | Refusal::NotOwner | Refusal::Ended => {
            refused(StatusCode::UNAUTHORIZED, ENDED).into_response()
        }
    }
}

// ───────────────────────── ending ─────────────────────────

/// Why a perspective ended (the `end_reason` column and the audit row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    BackToMe,
    Switched,
    Logout,
    FamilyRevoked,
    Cap,
    /// The row's dimensions cannot be read by this gateway (a newer one wrote
    /// a dimension this one does not know).
    Unreadable,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EndReason::BackToMe => "back_to_me",
            EndReason::Switched => "switched",
            EndReason::Logout => "logout",
            EndReason::FamilyRevoked => "family_revoked",
            EndReason::Cap => "cap",
            EndReason::Unreadable => "unreadable",
        }
    }
}

/// End one perspective: the row, and the stamp on every refresh row carrying
/// it. `PerspectiveEnded` is written only when this call ended it, so it is
/// written once. `Ok(false)`: it had already ended.
pub async fn end(db: &PgPool, id: &str, reason: EndReason) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    let ended = crate::repo::perspectives::mark_ended(&mut *tx, id, reason.as_str()).await?;
    crate::repo::perspectives::unstamp(&mut *tx, id).await?;
    tx.commit().await?;
    forget(id);
    match ended {
        Some(account) => {
            audit_ended(db, &account, id, reason).await;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// End every live perspective of an account (its refresh family was revoked:
/// replay detection, password change, disable). Called from
/// `auth_refresh::revoke_all_for_user`, so no caller can forget it.
pub async fn end_all_for_account(db: &PgPool, account: &str, reason: EndReason) -> Result<u64, sqlx::Error> {
    let mut tx = db.begin().await?;
    let ended = crate::repo::perspectives::mark_all_ended(&mut *tx, account, reason.as_str()).await?;
    crate::repo::perspectives::unstamp_account(&mut *tx, account).await?;
    tx.commit().await?;
    for id in &ended {
        forget(id);
        audit_ended(db, account, id, reason).await;
    }
    Ok(ended.len() as u64)
}

async fn audit_ended(db: &PgPool, account: &str, id: &str, reason: EndReason) {
    crate::audit::record(
        db,
        AuditEvent::new(AuditKind::PerspectiveEnded, account, &format!("perspective:{id}"))
            .outcome(reason.as_str())
            .details(json!({ "id": id, "reason": reason.as_str() })),
    )
    .await;
}

async fn audit_started(db: &PgPool, account: &str, started: &Started, switched_from: Option<&str>) {
    let mut details = json!({ "id": started.id, "dims": started.dims });
    if let Some(old) = switched_from {
        details["switched_from"] = json!(old);
    }
    crate::audit::record(
        db,
        AuditEvent::new(AuditKind::PerspectiveStarted, account, &format!("perspective:{}", started.id)).details(details),
    )
    .await;
}

// ───────────────────────── the session ─────────────────────────

/// The caller's live refresh row, found by the HttpOnly refresh cookie (never
/// by a body field): the session a perspective belongs to.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub perspective_id: Option<String>,
}

/// The live (unrevoked, unexpired) refresh row the cookie names, when it is
/// `account`'s.
pub async fn session_row(db: &PgPool, raw_cookie: &str, account: &str) -> Result<Option<SessionRow>, sqlx::Error> {
    let row = crate::repo::perspectives::session_row(db, &crate::auth_refresh::hash_token(raw_cookie), account).await?;
    Ok(row.map(|(id, perspective_id)| SessionRow { id, perspective_id }))
}

/// A perspective that was just started (or switched to).
#[derive(Debug, Clone)]
pub struct Started {
    pub id: String,
    pub dims: Perspective,
    pub started_at: DateTime<Utc>,
    /// The narrowed role, from the account's LIVE role.
    pub role: Role,
}

impl Started {
    pub fn claim(&self) -> PrsClaim {
        PrsClaim { id: self.id.clone(), dims: self.dims.clone() }
    }

    pub fn view(&self) -> Value {
        view(&self.id, &self.dims, self.started_at)
    }
}

/// Validate a start or a switch against the account's LIVE role, read from
/// the database now (never the token's, which may already be narrowed).
/// The second barrier (§3.3); `Ok` is that live role.
pub async fn validate(db: &PgPool, account: &str, dims: &Perspective) -> Result<Role, Refused> {
    let live = match crate::repo::users::enabled_role(db, account).await {
        // Fail closed to the lowest tier on a role this build cannot read.
        Ok(Some(r)) => r.parse::<Role>().unwrap_or(Role::User),
        Ok(None) => return Err(refused(StatusCode::FORBIDDEN, NEEDS_OPERATOR)),
        Err(e) => {
            tracing::error!(error = %e, "perspective: the account's role could not be read");
            return Err(refused(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE));
        }
    };
    if live < Role::Operator {
        return Err(refused(StatusCode::FORBIDDEN, NEEDS_OPERATOR));
    }
    if let Some(cap) = dims.role_cap {
        if cap >= live {
            return Err(refused(StatusCode::UNPROCESSABLE_ENTITY, CANNOT_WIDEN));
        }
    }
    let mut addons = BTreeMap::new();
    for name in dims.addons.keys() {
        let state = AddonView::from(&crate::addons::state(name));
        if state != AddonView::Enabled {
            return Err(refused(StatusCode::UNPROCESSABLE_ENTITY, UNKNOWN_ADDON));
        }
        addons.insert(name.clone(), state);
    }
    let licensed = crate::entitlement::installed().is_ok();
    if dims.core_only && !licensed {
        return Err(refused(StatusCode::UNPROCESSABLE_ENTITY, NO_CHANGE));
    }
    let real = Real { role: live, addons, licensed };
    if !changes_anything(&real, dims) {
        return Err(refused(StatusCode::UNPROCESSABLE_ENTITY, NO_CHANGE));
    }
    Ok(live)
}

fn db_failed(e: sqlx::Error) -> Refused {
    tracing::error!(error = %e, "perspective: database write failed");
    refused(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE)
}

async fn insert_in(
    conn: &mut sqlx::PgConnection,
    account: &str,
    session: &SessionRow,
    dims: &Perspective,
    live: Role,
    switched_from: Option<&str>,
) -> Result<Started, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let dims_json = serde_json::to_value(dims).unwrap_or_else(|_| json!({}));
    let started_at = crate::repo::perspectives::insert(
        &mut *conn,
        &crate::repo::perspectives::NewPerspective {
            id: &id,
            account,
            refresh_family: &session.id,
            dims: &dims_json,
            cap_hours: CAP_HOURS,
            switched_from,
        },
    )
    .await?;
    Ok(Started { id, dims: dims.clone(), started_at, role: narrow_role(live, dims) })
}

/// Stamp `new_id` on the session's refresh row, only while it is live and
/// still carries `expect`. `false`: the row moved under us.
async fn stamp_in(
    conn: &mut sqlx::PgConnection,
    session: &SessionRow,
    new_id: &str,
    expect: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let n = crate::repo::perspectives::stamp(&mut *conn, &session.id, new_id, expect).await?;
    Ok(n == 1)
}

/// `POST /api/auth/perspective`: start a perspective on this session. Never
/// nested (409 `perspective_active`). One transaction writes the row and
/// stamps the session; `PerspectiveStarted` is written after it commits.
pub async fn begin(db: &PgPool, claims: &Claims, session: &SessionRow, dims: &Perspective) -> Result<Started, Refused> {
    if claims.prs.is_some() || session.perspective_id.is_some() {
        return Err(refused(StatusCode::CONFLICT, ACTIVE));
    }
    let live = validate(db, &claims.sub, dims).await?;
    let mut tx = db.begin().await.map_err(db_failed)?;
    let started = insert_in(&mut tx, &claims.sub, session, dims, live, None).await.map_err(db_failed)?;
    if !stamp_in(&mut tx, session, &started.id, None).await.map_err(db_failed)? {
        // Dropping the transaction rolls the row back.
        return Err(refused(StatusCode::CONFLICT, ACTIVE));
    }
    tx.commit().await.map_err(db_failed)?;
    audit_started(db, &claims.sub, &started, None).await;
    Ok(started)
}

/// Switch and Back to me authorize on the ROW, never on the token's role
/// (which may be `user`): the token's `prs` must be live, the caller's own,
/// and on this very session. `Ok` is the perspective id.
pub async fn authorize_own(db: &PgPool, claims: &Claims, session: &SessionRow) -> Result<String, Refused> {
    let Some(prs) = claims.prs.as_ref() else {
        return Err(refused(StatusCode::CONFLICT, NONE));
    };
    admit(db, &claims.sub, prs).await.map_err(|why| match why {
        Refusal::Unavailable => refused(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE),
        Refusal::Unknown | Refusal::NotOwner | Refusal::Ended => refused(StatusCode::UNAUTHORIZED, ENDED),
    })?;
    if session.perspective_id.as_deref() != Some(prs.id.as_str()) {
        return Err(refused(StatusCode::UNAUTHORIZED, NOT_THIS_SESSION));
    }
    Ok(prs.id.clone())
}

/// `DELETE /api/auth/perspective`: Back to me. Never refused to the
/// perspective's own session for a role reason, or an operator could be
/// stranded in a `user` view (M20).
pub async fn back_to_me(db: &PgPool, claims: &Claims, session: &SessionRow) -> Result<(), Refused> {
    let id = authorize_own(db, claims, session).await?;
    end(db, &id, EndReason::BackToMe).await.map_err(db_failed)?;
    Ok(())
}

/// What a switch did.
#[derive(Debug)]
pub enum Switched {
    /// The new perspective was empty: the same as Back to me.
    Back,
    To(Started),
}

/// `PUT /api/auth/perspective`: end the current perspective and start the
/// new one in ONE transaction, re-stamping the session, so there is no
/// moment with neither (M21). The new one is validated against the LIVE
/// role, exactly like a start (M19).
pub async fn switch(db: &PgPool, claims: &Claims, session: &SessionRow, dims: &Perspective) -> Result<Switched, Refused> {
    let old = authorize_own(db, claims, session).await?;
    if dims.is_empty() {
        end(db, &old, EndReason::BackToMe).await.map_err(db_failed)?;
        return Ok(Switched::Back);
    }
    let live = validate(db, &claims.sub, dims).await?;
    let mut tx = db.begin().await.map_err(db_failed)?;
    let n = crate::repo::perspectives::end_for_switch(&mut *tx, &old, EndReason::Switched.as_str(), &claims.sub)
        .await
        .map_err(db_failed)?;
    if n != 1 {
        return Err(refused(StatusCode::UNAUTHORIZED, ENDED));
    }
    let started = insert_in(&mut tx, &claims.sub, session, dims, live, Some(&old)).await.map_err(db_failed)?;
    if !stamp_in(&mut tx, session, &started.id, Some(&old)).await.map_err(db_failed)? {
        // Dropping the transaction rolls back the end AND the new row: the
        // old perspective is still on.
        return Err(refused(StatusCode::CONFLICT, NOT_THIS_SESSION));
    }
    tx.commit().await.map_err(db_failed)?;
    forget(&old);
    audit_ended(db, &claims.sub, &old, EndReason::Switched).await;
    audit_started(db, &claims.sub, &started, Some(&old)).await;
    Ok(Switched::To(started))
}

// ───────────────────────── refresh ─────────────────────────

/// What a refresh carries forward from the row it just claimed.
#[derive(Debug)]
pub enum Carry {
    /// No perspective (or an ended one): a real token, a clean child row.
    Real,
    /// A live perspective: the child row inherits it and the access token
    /// is the perspective token.
    Live(PrsClaim),
    /// The row must end (it reached its cap, or this gateway cannot read its
    /// dimensions): a real token, and the caller ends the row with this
    /// reason once its transaction is committed, so old `prs` tokens and
    /// `/auth/me` stop honouring it too.
    End(String, EndReason),
}

/// Read the claimed row's perspective on the refresh's OWN connection (the
/// rotation holds a transaction and must not ask the pool for a second
/// connection).
pub async fn carried(
    conn: &mut sqlx::PgConnection,
    perspective_id: Option<&str>,
    account: &str,
) -> Result<Carry, sqlx::Error> {
    let Some(id) = perspective_id else {
        return Ok(Carry::Real);
    };
    let row = crate::repo::perspectives::carried(&mut *conn, id).await?;
    Ok(match row {
        Some((owner, ended, past_cap, dims)) if owner == account && !ended => {
            if past_cap {
                Carry::End(id.to_string(), EndReason::Cap)
            } else {
                match serde_json::from_value::<Perspective>(dims) {
                    Ok(dims) => Carry::Live(PrsClaim { id: id.to_string(), dims }),
                    Err(e) => {
                        tracing::warn!(perspective = %id, error = %e, "perspective dims unreadable; ending it, the refresh is real");
                        Carry::End(id.to_string(), EndReason::Unreadable)
                    }
                }
            }
        }
        _ => Carry::Real,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [Role; 3] = [Role::User, Role::Operator, Role::Admin];

    /// The order an add-on's state is compared in: absent < disabled or
    /// unlicensed < enabled.
    fn rank(v: Option<AddonView>) -> u8 {
        match v {
            None => 0,
            Some(AddonView::Disabled) | Some(AddonView::Unlicensed) => 1,
            Some(AddonView::Enabled) => 2,
        }
    }

    /// M1–M3: every combination of the finite domain (§8), and every output
    /// no wider than its input. The case count is asserted, so a shrunk
    /// domain fails instead of passing vacuously.
    #[test]
    fn a_perspective_never_widens() {
        let caps: [Option<Role>; 4] = [None, Some(Role::User), Some(Role::Operator), Some(Role::Admin)];
        let reals: [Option<AddonView>; 4] =
            [Some(AddonView::Enabled), Some(AddonView::Disabled), Some(AddonView::Unlicensed), None];
        let hides: [Option<Hide>; 3] = [None, Some(Hide::Disabled), Some(Hide::Absent)];
        let mut cases = 0usize;
        for role in ROLES {
            for cap in caps {
                for real_addon in reals {
                    for hide in hides {
                        for licensed in [true, false] {
                            for core_only in [true, false] {
                                cases += 1;
                                let mut addons = BTreeMap::new();
                                if let Some(s) = real_addon {
                                    addons.insert("x".to_string(), s);
                                }
                                let real = Real { role, addons, licensed };
                                let mut p = Perspective { role_cap: cap, core_only, ..Perspective::default() };
                                if let Some(h) = hide {
                                    p.addons.insert("x".to_string(), h);
                                }
                                let e = effective(&real, &p);
                                let case = format!("{role:?} cap={cap:?} addon={real_addon:?} hide={hide:?} licensed={licensed} core_only={core_only}");
                                assert!(e.role <= real.role, "role widened: {case} -> {:?}", e.role);
                                if let Some(c) = cap {
                                    assert!(e.role <= c, "role above the cap: {case}");
                                }
                                let out = e.addons.get("x").copied();
                                assert!(rank(out) <= rank(real_addon), "add-on widened: {case} -> {out:?}");
                                if rank(out) == rank(real_addon) && real_addon.is_some() {
                                    assert_eq!(out, real_addon, "add-on changed kind: {case}");
                                }
                                assert!(!e.licensed || real.licensed, "licence widened: {case}");
                                assert!(e.addons.keys().all(|k| real.addons.contains_key(k)), "an add-on was added: {case}");
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 3 * 4 * 4 * 3 * 2 * 2, "the domain shrank");
        assert_eq!(cases, 576);
    }

    /// The type admits removals only: an unknown field (a P4 `seat`) is
    /// refused, and the wire names are the documented ones.
    #[test]
    fn the_wire_shape_is_removals_only() {
        let body = |v: Value| serde_json::to_vec(&v).expect("json");
        let p = parse_dims(&body(json!({"role_cap": "user", "addons": {"x": "absent", "y": "disabled"}, "core_only": true})))
            .expect("parses");
        assert_eq!(p.role_cap, Some(Role::User));
        assert_eq!(p.addons.get("x"), Some(&Hide::Absent));
        assert_eq!(p.addons.get("y"), Some(&Hide::Disabled));
        assert!(p.core_only);
        let back = serde_json::to_value(&p).expect("serializes");
        assert_eq!(back["role_cap"], "user");
        let seat = parse_dims(&body(json!({"seat": "hall"}))).expect_err("an unknown field");
        assert_eq!(seat, Refused { status: StatusCode::UNPROCESSABLE_ENTITY, detail: INVALID });
        assert!(parse_dims(&body(json!({"role_cap": "root"}))).is_err(), "an unknown role");
        assert!(parse_dims(&body(json!({"addons": {"x": "enabled"}}))).is_err(), "nothing can be turned on");
        assert!(parse_dims(b"").expect("empty").is_empty());
        assert_eq!(serde_json::to_value(Perspective::default()).expect("serializes"), json!({}), "an empty perspective is an empty object");
    }

    /// M13: Grafana opens at the LOWER of the live role and the
    /// perspective's, and the handler takes it before the role function.
    #[test]
    fn grafana_takes_the_lower_role() {
        let user_view = RequesterPerspective {
            id: "p".into(),
            dims: Perspective { role_cap: Some(Role::User), ..Perspective::default() },
        };
        assert_eq!(clamp(Some(Role::Admin), Some(&user_view)), Some(Role::User));
        assert_eq!(clamp(Some(Role::Operator), Some(&user_view)), Some(Role::User));
        assert_eq!(clamp(Some(Role::Admin), None), Some(Role::Admin));
        assert_eq!(clamp(None, Some(&user_view)), None, "no account stays no account");
        let addons_only = RequesterPerspective { id: "p".into(), dims: Perspective { core_only: true, ..Perspective::default() } };
        assert_eq!(clamp(Some(Role::Operator), Some(&addons_only)), Some(Role::Operator));

        let own = crate::test_src::own_code(include_str!("routes/monitoring.rs"));
        let body = crate::test_src::fn_body(&own, "async fn grafana_session(");
        let clamped = body
            .find("let live = crate::perspective::clamp(live, perspective.as_deref());")
            .expect("the Grafana handler must clamp the live role with the perspective");
        let gate = body.find("if live == Some(Role::User)").expect("the viewer gate");
        let role = body.find("grafana_session_role(live, disabled, &viewer)").expect("the role function");
        assert!(clamped < gate && clamped < role, "the clamp must come before the viewer gate and the role function");
    }

    /// The refused mints (§4.3), one case per mint: each handler asks
    /// `refuse_mint` before it mints, and `refuse_mint` refuses with 403
    /// `perspective_refuses_mint` whenever a perspective is on the request.
    #[test]
    fn mints_under_a_perspective_are_refused() {
        let p = axum::Extension(RequesterPerspective { id: "p".into(), dims: Perspective::default() });
        match refuse_mint(Some(&p), "test") {
            Err(crate::routes::AppError::Forbidden(m)) => assert_eq!(m, REFUSES_MINT),
            other => panic!("expected a 403, got {:?}", other),
        }
        assert!(refuse_mint(None, "test").is_ok());

        let cases: &[(&str, &str, &str, &str)] = &[
            ("harness turn token", include_str!("routes/harness.rs"), "async fn harness_call(", "HarnessOp::TaskCheckpoint"),
            ("identity exchange (agent token)", include_str!("routes/identity.rs"), "async fn token(", "mint_agent_jwt("),
            ("add-on token", include_str!("routes/addon_token.rs"), "async fn token(", "mint_addon_jwt("),
            ("operator cert token", include_str!("routes/operator_certs.rs"), "async fn operator_token(", "mint_operator_jwt("),
            ("join key", include_str!("routes/cluster.rs"), "async fn mint_join_key(", "mint_tailscale_auth_key("),
            ("bootstrap token", include_str!("routes/bootstrap.rs"), "async fn bootstrap_token_create(", "generate_bootstrap_token("),
            ("seat token", include_str!("routes/seats.rs"), "async fn seat_token_create(", "mint_seat_token("),
            ("seat bind", include_str!("routes/seats.rs"), "async fn seat_bind(", "bind_tailnet("),
            ("seat revoke", include_str!("routes/seats.rs"), "async fn seat_revoke(", "seats::revoke("),
        ];
        for (what, src, handler, mint) in cases {
            let own = crate::test_src::own_code(src);
            let body = crate::test_src::fn_body(&own, handler);
            let refusal = body
                .find("crate::perspective::refuse_mint(perspective.as_ref(),")
                .unwrap_or_else(|| panic!("{what}: {handler} does not refuse a perspective"));
            let minted = body.find(mint).unwrap_or_else(|| panic!("{what}: {mint} is not in {handler}"));
            assert!(refusal < minted, "{what}: the refusal must come before the mint");
        }
    }

    /// Guard (a): every `pub fn mint_` in auth.rs is classified. A new mint
    /// fails here until someone decides what a perspective does to it.
    /// "aware": carries or clamps the perspective; "refused": every request
    /// handler that reaches it refuses a perspective (see
    /// `mints_under_a_perspective_are_refused`); "no-session": reached only
    /// by a caller that presents no session token, so a perspective cannot
    /// reach it.
    const MINTS: &[(&str, &str)] = &[
        // routes/harness.rs (refused); coordinator::try_dispatch and
        // tasks::start mint for the turn's owner at min(live role, the
        // snapshot the turn or task was submitted under).
        ("mint_harness_jwt", "refused"),
        ("mint_harness_jwt_with", "refused"),
        // routes/addon_token.rs, behind a service key.
        ("mint_addon_jwt", "refused"),
        // routes/identity.rs, behind a service key.
        ("mint_agent_jwt", "refused"),
        ("mint_agent_jwt_with", "refused"),
        // routes/monitoring.rs: perspective::clamp.
        ("mint_grafana_jwt_with", "aware"),
        // routes/kiosk.rs token_tailnet: keyless; the tailnet whois is the
        // credential, and no session token is read.
        ("mint_kiosk_jwt", "no-session"),
        ("mint_kiosk_jwt_with", "no-session"),
        // routes/operator_certs.rs.
        ("mint_operator_jwt", "refused"),
        ("mint_operator_jwt_with", "refused"),
    ];

    #[test]
    fn every_mint_is_classified() {
        let own = crate::test_src::own_code(include_str!("auth.rs"));
        let mut found: Vec<String> = Vec::new();
        for (i, _) in own.match_indices("pub fn mint_") {
            let name: String = own[i + "pub fn ".len()..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            found.push(name);
        }
        assert!(found.len() >= 8, "the scan found {} mints; the scan is broken", found.len());
        for name in &found {
            let row = MINTS.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
                panic!("auth.rs `{name}` is a new mint: classify it in perspective::tests::MINTS (aware / refused / no-session)")
            });
            assert!(matches!(row.1, "aware" | "refused" | "no-session"), "{name}: {}", row.1);
        }
        for (name, _) in MINTS {
            assert!(found.iter().any(|f| f == name), "MINTS names `{name}`, which auth.rs no longer has");
        }
    }

    /// Guard (b): every caller of a live-role read (`repo::users::role_of`,
    /// `coordinator::role_of`) is classified, by file and count. A new
    /// caller fails here until someone decides whether it reads the
    /// caller's role (refuse or clamp under a perspective) or another
    /// account's (unchanged).
    const ROLE_OF_CALLERS: &[(&str, usize, &str)] = &[
        // §4.3: the caller's role, to renew or mint a harness credential;
        // `harness_call` refuses a perspective before either.
        ("routes/harness.rs", 2, "refused"),
        // A chat-channel sender (Telegram, Google Chat) linked to an
        // account: no gateway session, so no perspective can be on it.
        ("channels/approvals.rs", 1, "unchanged: chat sender, not a session"),
        ("routes/addon_access.rs", 1, "unchanged: listed accounts"),
        ("routes/users.rs", 1, "unchanged: the account in the path"),
        // The snapshot rule: min(live role, the perspective the task or the
        // turn was submitted under), live or not.
        ("task_events.rs", 1, "clamped: the task's snapshot"),
        ("tasks.rs", 1, "clamped: the task's snapshot"),
        ("coordinator/dispatch.rs", 1, "clamped: the turn's snapshot"),
        // A certificate's kind from its path, not an account's role.
        ("cert_expiry.rs", 1, "unrelated: certificate kind"),
    ];

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("read src dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    #[test]
    fn every_role_of_caller_is_classified() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rs_files(&root, &mut files);
        assert!(files.len() > 50, "the scan found {} files; the walk is broken", files.len());
        let needle = concat!("role", "_of(");
        let mut found: Vec<(String, usize)> = Vec::new();
        for f in files {
            let rel = f.strip_prefix(&root).expect("under src").to_string_lossy().replace('\\', "/");
            let own = crate::test_src::own_code(&std::fs::read_to_string(&f).expect("read source"));
            let calls = own
                .match_indices(needle)
                .filter(|(i, _)| {
                    let before = &own[..*i];
                    let prev = before.chars().next_back();
                    !prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') && !before.ends_with("fn ")
                })
                .count();
            if calls > 0 {
                found.push((rel, calls));
            }
        }
        for (file, n) in &found {
            let row = ROLE_OF_CALLERS.iter().find(|(f, _, _)| f == file).unwrap_or_else(|| {
                panic!("{file} calls a live-role read and is not classified in perspective::tests::ROLE_OF_CALLERS")
            });
            assert_eq!(row.1, *n, "{file}: {n} live-role reads, {} classified; classify the new one", row.1);
        }
        for (file, _, _) in ROLE_OF_CALLERS {
            assert!(found.iter().any(|(f, _)| f == file), "ROLE_OF_CALLERS names {file}, which no longer reads a role");
        }
    }

    /// M6: the middleware asks `admit` for every `prs` token before anything
    /// else reads the claims, and answers its refusal.
    #[test]
    fn the_middleware_admits_a_perspective_token() {
        let own = crate::test_src::own_code(include_str!("auth.rs"));
        let body = crate::test_src::fn_body(&own, "pub async fn require_any_auth(");
        let floor = body.find("crate::session_floor::refuses(").expect("the floor");
        let admit = body
            .find("crate::perspective::admit(&state.db, &claims.sub, prs).await")
            .expect("the middleware must check a perspective token's row");
        let harness = body.find("harness_turn_for(&claims, &path)").expect("the harness rail");
        assert!(floor < admit && admit < harness, "the perspective check sits right after the floor");
        assert!(body.contains("return Ok(crate::perspective::refusal_response(why));"));
        assert!(body.contains("request.extensions_mut().insert(view.clone());"));
        assert!(
            body.contains("return Ok(crate::perspective::scope(in_view, next.run(request)).await);"),
            "the rest of a perspective request runs under its snapshot"
        );
    }

    /// The database not answering is a refusal (503), never "live": the
    /// middleware answers every `admit` refusal, `Unavailable` included.
    #[tokio::test]
    async fn an_unanswerable_liveness_check_is_refused() {
        let dead = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
            .expect("lazy pool");
        let prs = PrsClaim { id: uuid::Uuid::new_v4().to_string(), dims: Perspective::default() };
        assert_eq!(admit(&dead, "olive", &prs).await, Err(Refusal::Unavailable));
        assert_eq!(refusal_response(Refusal::Unavailable).status(), StatusCode::SERVICE_UNAVAILABLE);
        let own = crate::test_src::own_code(include_str!("auth.rs"));
        let body = crate::test_src::fn_body(&own, "pub async fn require_any_auth(");
        let asked = body.find("crate::perspective::admit(&state.db, &claims.sub, prs).await").expect("the check");
        let answered = body[asked..].find("return Ok(crate::perspective::refusal_response(why));").expect("its answer") + asked;
        assert!(!body[asked..answered].contains("Unavailable"), "every refusal is answered, Unavailable included");
    }

    fn user_view() -> RequesterPerspective {
        RequesterPerspective { id: "p".into(), dims: Perspective { role_cap: Some(Role::User), ..Perspective::default() } }
    }

    fn token_role(token: &str) -> Value {
        use base64::Engine as _;
        let mid = token.split('.').nth(1).expect("a JWT");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mid).expect("base64url");
        let claims: Value = serde_json::from_slice(&raw).expect("json claims");
        claims["role"].clone()
    }

    /// The dispatch clamp: a chat turn submitted under a `user` perspective
    /// by an operator mints its node-harness token at `user`. The snapshot
    /// is visible inside its scope and nowhere else, and both turn-token
    /// mints (a chat turn, a task) take it before minting.
    #[tokio::test]
    async fn a_user_perspective_chat_turn_token_carries_role_user() {
        assert_eq!(current(), None, "no snapshot outside a scope");
        let role = scope(Some(user_view()), async { snapshot_role(Role::Operator, current().as_ref()) }).await;
        assert_eq!(role, Role::User);
        assert_eq!(current(), None, "the scope does not leak");
        assert_eq!(snapshot_role(Role::Operator, None), Role::Operator, "no perspective, the live role");
        let token = crate::auth::mint_harness_jwt_with("olive", role, "node-1", "c1", 60, "a-test-signing-key-not-a-secret-0001")
            .expect("mint");
        assert_eq!(token_role(&token), "user");

        let own = crate::test_src::own_code(include_str!("coordinator/dispatch.rs"));
        let body = crate::test_src::fn_body(&own, "pub async fn try_dispatch<");
        let narrowed = body
            .find("let role = crate::perspective::snapshot_role(live, crate::perspective::current().as_ref());")
            .expect("try_dispatch must narrow the live role to the turn's snapshot");
        let minted = body.find("crate::auth::mint_harness_jwt(user, role,").expect("the mint takes the narrowed role");
        assert!(narrowed < minted);

        let own = crate::test_src::own_code(include_str!("tasks.rs"));
        let body = crate::test_src::fn_body(&own, "pub async fn start(");
        let narrowed = body
            .find("let role = crate::perspective::snapshot_role(live, snapshot.as_ref());")
            .expect("a task's turn token must narrow the live role to the task's snapshot");
        let minted = body.find("crate::auth::mint_harness_jwt(owner, role,").expect("the mint takes the narrowed role");
        assert!(narrowed < minted);
    }

    /// The snapshot rule: the snapshot keeps narrowing after Back to me
    /// (it is not a liveness lookup), and a demotion of the live role below
    /// it still wins (a min).
    #[test]
    fn the_snapshot_narrows_after_the_end_and_a_demotion_wins() {
        let operator_view = RequesterPerspective {
            id: "p".into(),
            dims: Perspective { role_cap: Some(Role::Operator), ..Perspective::default() },
        };
        assert_eq!(snapshot_role(Role::Admin, Some(&operator_view)), Role::Operator);
        assert_eq!(snapshot_role(Role::User, Some(&operator_view)), Role::User, "the demotion wins");
        assert_eq!(snapshot_role(Role::Operator, Some(&user_view())), Role::User);
        for live in ROLES {
            assert!(snapshot_role(live, Some(&user_view())) <= live);
        }
    }

    /// The catalog clamp: the external-tool audience reads the role through
    /// the turn's snapshot.
    #[test]
    fn catalog_for_reads_the_role_through_the_snapshot() {
        let own = crate::test_src::own_code(include_str!("mcp_bridge.rs"));
        let body = crate::test_src::fn_body(&own, "async fn identity(");
        let read = body.find("crate::repo::users::enabled_role(db, u)").expect("the live role");
        let clamped = body
            .find("let role = crate::perspective::clamp(role, crate::perspective::current().as_ref());")
            .expect("identity must clamp the live role with the turn's snapshot");
        assert!(read < clamped);
        let user = clamp(Some(Role::Operator), Some(&user_view()));
        assert!(!crate::mcp_bridge::audience_permits(&[], Some("olive"), user, &[]), "an operators-only server is hidden from a user view");
        assert!(crate::mcp_bridge::audience_permits(&[], Some("olive"), Some(Role::Operator), &[]));
    }

    /// The owner clamp: a task's events are delivered at the owner's live
    /// role min'd with the task's snapshot.
    #[test]
    fn owner_role_reads_the_task_snapshot() {
        let own = crate::test_src::own_code(include_str!("task_events.rs"));
        let body = crate::test_src::fn_body(&own, "async fn task_owner_role(");
        assert!(body.contains("crate::perspective::task_snapshot(db, task_id).await"));
        assert!(body.contains("Ok(crate::perspective::snapshot_role(live, snapshot.as_ref()))"));
        let deliver = crate::test_src::fn_body(&own, "async fn deliver_task(");
        assert!(deliver.contains("task_owner_role(db, d.task_id, &owner).await"));
    }

    /// A child task submitted under one view, with a parent under another,
    /// takes the intersection: the lower cap, every hide (absent beats
    /// disabled), core-only if either. Never just one side.
    #[test]
    fn a_child_task_takes_the_intersection() {
        let mut current = RequesterPerspective {
            id: "c".into(),
            dims: Perspective { role_cap: Some(Role::Operator), ..Perspective::default() },
        };
        current.dims.addons.insert("x".into(), Hide::Disabled);
        let mut parent = RequesterPerspective {
            id: "p".into(),
            dims: Perspective { role_cap: Some(Role::User), core_only: true, ..Perspective::default() },
        };
        parent.dims.addons.insert("x".into(), Hide::Absent);
        parent.dims.addons.insert("y".into(), Hide::Disabled);
        let both = combine(Some(current.clone()), Some(parent.clone())).expect("a snapshot");
        assert_eq!(both.dims.role_cap, Some(Role::User), "the lower cap");
        assert_eq!(both.dims.addons.get("x"), Some(&Hide::Absent), "absent beats disabled");
        assert_eq!(both.dims.addons.get("y"), Some(&Hide::Disabled), "the parent's hide stays");
        assert!(both.dims.core_only, "core-only if either");
        assert_eq!(both.id, "c");
        let reversed = combine(Some(parent.clone()), Some(current.clone())).expect("a snapshot");
        assert_eq!(reversed.dims, both.dims, "the intersection is symmetric");
        assert_eq!(combine(Some(current.clone()), None), Some(current.clone()));
        assert_eq!(combine(None, Some(parent.clone())), Some(parent));
        assert_eq!(combine(None, None), None);
        let own = crate::test_src::own_code(include_str!("tasks.rs"));
        let body = crate::test_src::fn_body(&own, "pub async fn create_task(");
        assert!(body.contains("crate::perspective::combine(crate::perspective::current(), parent_snapshot)"));
    }

    /// A principal narrowed to a `user` view signs as a user: the role and
    /// exactly the scopes that role expands to, carrying the snapshot.
    #[test]
    fn a_narrowed_principal_signs_as_the_view() {
        let real = crate::bus_principal::Principal::user(
            "olive",
            Role::Operator,
            vec!["read".into(), "write".into(), "ingest".into()],
        );
        assert_eq!(real.clone().narrowed(None), real, "no snapshot, no change");
        let p = real.narrowed(Some(user_view()));
        assert_eq!(p.role, "user");
        assert_eq!(p.scopes, vec!["read".to_string()]);
        assert_eq!(p.perspective, Some(user_view()));
        let own = crate::test_src::own_code(include_str!("tasks.rs"));
        let body = crate::test_src::fn_body(&own, "async fn task_principal(");
        assert!(body.contains(".map(|p| p.narrowed(snapshot))"), "the task principal must take the task's snapshot");
        let runner = crate::test_src::fn_body(&own, "fn run_in_process(");
        assert!(runner.contains("task_principal(&st.db, &req.user, snapshot.clone()).await"));
    }

    /// The perspective routes take a plain person-session token only.
    #[test]
    fn perspective_routes_take_a_plain_session_only() {
        let plain = || Claims {
            sub: "olive".into(),
            exp: 4_102_444_800,
            role: "operator".into(),
            scopes: vec!["read".into(), "write".into()],
            harness: None,
            conv: None,
            act: None,
            cnf: None,
            prs: None,
        };
        assert!(plain_session(&plain()).is_ok());
        let refused_as = |c: Claims| plain_session(&c).expect_err("not a plain session").detail;
        assert_eq!(refused_as(Claims { act: Some(crate::auth::Actor { sub: "key:x".into(), iss_user: None, task: None, feature: None }), ..plain() }), NEEDS_PERSON);
        assert_eq!(refused_as(Claims { harness: Some("node:host8".into()), ..plain() }), NEEDS_PERSON);
        assert_eq!(refused_as(Claims { conv: Some("c1".into()), ..plain() }), NEEDS_PERSON);
        assert_eq!(refused_as(Claims { cnf: Some(crate::auth::Cnf { x5t_s256: "t".into() }), ..plain() }), NEEDS_PERSON);
        let own = crate::test_src::own_code(include_str!("routes/core.rs"));
        let body = crate::test_src::fn_body(&own, "async fn perspective_session(");
        assert!(body.contains("crate::perspective::plain_session(&claims)"));
        assert!(body.contains("lookup_user_db(&state.db, &claims.sub)"), "the subject must be a real account");
    }
}
