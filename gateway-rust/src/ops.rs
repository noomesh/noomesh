// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Asynchronous operations: start a long run, get an id at once, poll for it.
//!
//! WHY THIS EXISTS. Recluster holds a request open for up to 900 s;
//! extract-relations, consolidate, navigate and ingest for 120 s or more. An
//! MCP client, a proxy or a CLI gives up first, and the user is told the
//! gateway is "unreachable" while it is working. A request that can last
//! minutes must not BE a request. So the work runs detached, its outcome is
//! captured in a row, and the caller asks for the row.
//!
//! WHAT THIS FILE IS. The engine and the store, independent of any HTTP route
//! and of any one operation: `start` / `get` / `cancel` / `list`, the
//! detached supervisor, restart reconciliation, and the sweeper. The
//! operations themselves (the registry of types, each calling the SAME shared
//! function its synchronous route used to) and the HTTP surface live in
//! `routes/ops.rs`.
//!
//! WHY NOT THE JOBS TABLE. Its lifecycle is scheduler PLACEMENT: a job is
//! queued for a node to claim and reported on by that node. This captures one
//! request/response that the gateway itself runs. the design reached the
//! same conclusion and designed MCP tasks onto a table of exactly this shape;
//! `noo_ops` is that table (`task_id` = `op_id`).
//!
//! THE GUARANTEES, each pinned by a test:
//!   * Identity. An op carries the OWNER's identity from the moment it is
//!     started, and runs under it: the owner's `RequesterCtx` is handed to the
//!     run (so audience resolution is the owner's, never "no caller = the
//!     gateway = unrestricted") and the owner's bus principal is re-bound
//!     around the detached task (task-locals do not cross `tokio::spawn`).
//!     A caller with no account (the controller's own services: heartbeat
//!     ingest, a cluster-HMAC script) owns a NULL-owner op, visible to
//!     admins and to other such callers only, and runs exactly as that route
//!     always ran for it (unrestricted, as an internal principal).
//!   * Visibility. Only the owner (and an admin) can see an op; anyone else
//!     gets "not found", exactly as for an id that never existed. A caller
//!     that came through a harness (an MCP consumer) sees only that
//!     consumer's ops.
//!   * Finality. A terminal write is conditional on the row still being live,
//!     so a cancel that wins the race is never overwritten by a late
//!     "succeeded", and an expiry never resurrects.
//!   * Honesty about cancel. The gateway can stop WAITING; it cannot stop a
//!     worker that is already running. The row says which.
//!   * Orphans. A gateway restart ends its detached tasks. Rows of the
//!     restarted instance are failed at boot; rows of an instance that
//!     simply stopped reporting are failed by the sweeper once their
//!     heartbeat is stale. One gateway never reconciles another's LIVE run:
//!     a live run is touched every sweep, a lost one is not.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::auth::{account_of, RequesterCtx, Role};

pub const QUEUED: &str = "queued";
pub const RUNNING: &str = "running";
pub const SUCCEEDED: &str = "succeeded";
pub const FAILED: &str = "failed";
pub const CANCELLED: &str = "cancelled";
pub const EXPIRED: &str = "expired";

/// A status after which the row never changes again (except to `expired`).
pub fn is_terminal(status: &str) -> bool {
    matches!(status, SUCCEEDED | FAILED | CANCELLED | EXPIRED)
}

/// The longest `?wait=` any poll or route will hold a request for. Short of
/// every proxy timeout in front of the gateway, and the whole point: no
/// request is ever held for a whole run.
pub const MAX_WAIT_SECS: u64 = 25;

/// A result larger than this is not stored: the op FAILS and says so, rather
/// than succeeding with a truncated body nobody can tell is truncated.
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// Stored `params` larger than this are replaced by a marker (the run itself
/// always gets the full params; the row is for display and audit).
pub const MAX_PARAMS_BYTES: usize = 16 * 1024;

/// How often the sweeper runs, and how stale a heartbeat must be (a few
/// sweeps) before the run is declared lost.
pub const SWEEP_INTERVAL_SECS: u64 = 30;
const STALE_HEARTBEAT_SECS: i64 = (SWEEP_INTERVAL_SECS as i64) * 4;

/// How long a result is kept after the op finishes: `NOO_OPS_RESULT_TTL_SECS`
/// (default 24 h, clamped to a minute .. 30 days).
pub fn result_ttl() -> Duration {
    let secs = crate::settings::get("NOO_OPS_RESULT_TTL_SECS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(24 * 3600)
        .clamp(60, 30 * 24 * 3600);
    Duration::from_secs(secs)
}

/// Ops one account may have live at once (`NOO_OPS_MAX_ACTIVE_PER_OWNER`).
pub fn max_active_per_owner() -> i64 {
    crate::settings::get("NOO_OPS_MAX_ACTIVE_PER_OWNER")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(8)
        .clamp(1, 1000)
}

/// Which gateway process owns a run. Stable across a plain restart of the
/// same container (so boot reconciliation can fail its own orphans at once),
/// different between gateways (so one never claims another's live run).
/// `NOO_GATEWAY_INSTANCE` overrides; else the hostname.
pub fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        std::env::var("NOO_GATEWAY_INSTANCE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "gateway".to_string())
    })
}

// ───────────────────────────── the operation seam ─────────────────────────────

/// What a run answers with. `http_status` is what the synchronous route would
/// have answered (the route that waits for its op returns exactly this);
/// `failure` is `Some(reason)` when the op did not succeed.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub http_status: u16,
    pub body: Value,
    pub failure: Option<String>,
}

impl Outcome {
    pub fn done(http_status: u16, body: Value) -> Self {
        Self { http_status, body, failure: None }
    }
    pub fn failed(http_status: u16, body: Value, reason: impl Into<String>) -> Self {
        Self { http_status, body, failure: Some(reason.into()) }
    }
    /// Classify a handler's `(status, body)`: 2xx succeeded, anything else a
    /// failure carrying the body's own `error`.
    pub fn from_http(http_status: u16, body: Value) -> Self {
        if (200..300).contains(&http_status) {
            Self::done(http_status, body)
        } else {
            let reason = body
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("the operation answered HTTP {http_status}"));
            Self::failed(http_status, body, reason)
        }
    }
}

pub type RunFuture = Pin<Box<dyn Future<Output = Outcome> + Send + 'static>>;

/// What an op's run is handed besides its params: its id (for progress) and
/// the OWNER's identity.
#[derive(Clone)]
pub struct OpCtx {
    pub op_id: Uuid,
    /// `None` only for a machine caller that had no account when it started
    /// the op. A user's op is NEVER `None`: that would be read as "no caller",
    /// which the audience resolver treats as unrestricted.
    pub requester: Option<RequesterCtx>,
    db: PgPool,
}

impl OpCtx {
    /// The requester in the shape every shared route function takes
    /// (`Option<Extension<RequesterCtx>>`), captured at start.
    pub fn ctx(&self) -> Option<axum::Extension<RequesterCtx>> {
        self.requester.clone().map(axum::Extension)
    }

    /// Whether this op's ROW still exists and is live. An adapter whose work
    /// WRITES on the owner's behalf asks this immediately before dispatching.
    /// An erase deletes the account's op rows (also with `keep_account`, which
    /// leaves the account itself), so a missing row means "erased, or
    /// cancelled": do not write. Reading the row, not `noo_users`, is what makes
    /// this true for an op queued before the erase and for one on another
    /// gateway instance. A failed lookup answers false: fail closed.
    pub async fn still_live(&self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM noo_ops WHERE op_id = $1 AND status IN ('queued','running'))",
        )
        .bind(self.op_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(false)
    }

    /// Record progress. Best effort: a failed write must not fail the run.
    pub async fn progress(&self, progress: Value) {
        let r = sqlx::query(
            "UPDATE noo_ops SET progress = $2, heartbeat_at = now() WHERE op_id = $1 AND status = 'running'",
        )
        .bind(self.op_id)
        .bind(progress)
        .execute(&self.db)
        .await;
        if let Err(e) = r {
            tracing::warn!(op = %self.op_id, error = %e, "op_progress_write_failed");
        }
    }
}

/// What an operation type declares about itself (data only; the registry in
/// `routes/ops.rs` pairs it with the function that runs it).
pub struct OpSpec {
    pub name: &'static str,
    pub summary: &'static str,
    /// The synchronous route this operation is the body of. It is also the
    /// authorisation question: starting the op asks `auth::requester_allows`
    /// about THIS path, so the rule is the route's own, not a copy.
    pub route: &'static str,
    /// The longest the run may take before the supervisor fails it.
    pub timeout: fn() -> Duration,
    /// How long the route waits for the op before answering 202 when the
    /// caller did not say (`?wait=`). Overridable per type in settings.
    pub default_wait_secs: u64,
    pub poll_interval_ms: u64,
    /// What cancel can and cannot stop, said in the row.
    pub cancel_note: &'static str,
    /// Only one live op of this type at a time, across every gateway (the
    /// worker itself refuses a second concurrent recluster).
    pub exclusive: bool,
    /// Whether re-running after a lost run is harmless.
    pub retry_safe: bool,
    /// Whether the run WRITES data that belongs to the owner (ingested
    /// documents, extracted edges, saved walk threads, snapshots). Such an op
    /// blocks an erase of its owner while live or cancelled-but-possibly-still-
    /// running, and re-checks its row exists immediately before dispatching.
    pub writes_user_data: bool,
    /// Whether starting this type needs the Admin role, on top of whatever the
    /// type's `route` asks at the front door. The front door's tier rule is
    /// "an Operator may do anything"; a destructive maintenance run (the junk
    /// entity cleanup) is held to the stricter one. Checked in
    /// `routes/ops.rs::begin`, so it covers the route AND `POST /api/v1/ops`
    /// with one rule. A caller with no account (a controller-service
    /// credential) is refused too: an admin-only run needs an accountable actor.
    pub admin_only: bool,
    /// Whether an APPLY (`params.apply == true`) must come from a person's own
    /// credential. Any credential minted for a harness (`harness` claim set: the
    /// MCP operator door's `operator:<consumer>`, the user door's `mcp-external:`,
    /// a node-hosted harness `node:`, an agent run `worker:`) may still preview
    /// but is refused an apply with 403; the message names the CLI. Checked in
    /// `routes/ops.rs::begin` and again in the type's shared core. A future
    /// destructive type opts in by setting this flag.
    pub human_only_apply: bool,
    /// The params as stored on the row (the run always gets the real ones).
    pub redact: fn(&Value) -> Value,
}

impl OpSpec {
    /// The `noo_settings` / env key of this type's default wait.
    pub fn wait_key(&self) -> String {
        format!("NOO_OPS_WAIT_{}_SECS", self.name.to_uppercase().replace(['.', '-'], "_"))
    }

    /// The seconds the route waits when `?wait=` is absent: a `noo_settings`
    /// row (hot, within the settings refresh window) -> env -> the type's
    /// default, bounded by [`MAX_WAIT_SECS`].
    pub fn default_wait(&self) -> u64 {
        crate::settings::get(&self.wait_key())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(self.default_wait_secs)
            .min(MAX_WAIT_SECS)
    }
}

/// Default `params` redaction: keep everything, unless it is large.
pub fn redact_default(params: &Value) -> Value {
    cap_params(params.clone())
}

/// Replace over-large params with a marker saying how big they were.
pub fn cap_params(params: Value) -> Value {
    let n = params.to_string().len();
    if n > MAX_PARAMS_BYTES {
        json!({"_omitted": "params too large to store", "bytes": n})
    } else {
        params
    }
}

// ───────────────────────────── rows ─────────────────────────────

#[derive(Debug, Clone)]
pub struct OpRow {
    pub op_id: Uuid,
    pub op_type: String,
    pub status: String,
    pub owner_uuid: Option<Uuid>,
    pub consumer: Option<String>,
    pub params: Value,
    pub progress: Value,
    pub result: Option<Value>,
    pub result_status: Option<i32>,
    pub error: Option<String>,
    pub cancel_note: Option<Value>,
    pub runner_instance: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

const COLS: &str = "op_id, op_type, status, owner_uuid, consumer, params, progress, result, result_status, \
                    error, cancel_note, runner_instance, created_at, started_at, finished_at, expires_at";

impl OpRow {
    fn from_row(r: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            op_id: r.try_get("op_id")?,
            op_type: r.try_get("op_type")?,
            status: r.try_get("status")?,
            owner_uuid: r.try_get("owner_uuid")?,
            consumer: r.try_get("consumer")?,
            params: r.try_get("params")?,
            progress: r.try_get("progress")?,
            result: r.try_get("result")?,
            result_status: r.try_get("result_status")?,
            error: r.try_get("error")?,
            cancel_note: r.try_get("cancel_note")?,
            runner_instance: r.try_get("runner_instance")?,
            created_at: r.try_get("created_at")?,
            started_at: r.try_get("started_at")?,
            finished_at: r.try_get("finished_at")?,
            expires_at: r.try_get("expires_at")?,
        })
    }

    pub fn is_terminal(&self) -> bool {
        is_terminal(&self.status)
    }

    /// The row as the API shows it. `include_result` is false for listings.
    pub fn view(&self, include_result: bool, poll_interval_ms: u64, retry_safe: Option<bool>) -> Value {
        let mut v = json!({
            "op_id": self.op_id,
            "type": self.op_type,
            "status": self.status,
            "poll": format!("/api/v1/ops/{}", self.op_id),
            "poll_interval_ms": poll_interval_ms,
            "progress": self.progress,
            "params": self.params,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "expires_at": self.expires_at,
        });
        if include_result {
            v["result"] = self.result.clone().unwrap_or(Value::Null);
            v["result_status"] = json!(self.result_status);
        }
        if let Some(note) = &self.cancel_note {
            v["cancel"] = note.clone();
        }
        if self.status == FAILED {
            if let Some(safe) = retry_safe {
                v["retry_safe"] = json!(safe);
            }
        }
        if self.status == EXPIRED {
            v["note"] = json!("the result was kept until expires_at and has been removed");
        }
        v
    }
}

// ───────────────────────────── live task registry ─────────────────────────────

fn live() -> &'static Mutex<HashMap<Uuid, tokio::task::AbortHandle>> {
    static LIVE: OnceLock<Mutex<HashMap<Uuid, tokio::task::AbortHandle>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn live_ids() -> Vec<Uuid> {
    live().lock().unwrap_or_else(|p| p.into_inner()).keys().copied().collect()
}

/// Aborts its task when dropped, so aborting the supervisor also stops the
/// run it is awaiting (a dropped `JoinHandle` would only detach it).
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ───────────────────────────── start ─────────────────────────────

#[derive(Debug)]
pub enum StartError {
    /// The requester's account has no `noo_users` row: an op is owned by an
    /// account, and there is none to own it.
    NoAccount,
    /// The account already has the maximum number of live ops.
    TooMany(i64),
    /// Another start for this account holds the per-owner lock right now.
    Contended,
    /// The account is being erased (a refused erase marked it): no starts.
    ErasePending,
    Db(sqlx::Error),
}

pub enum Started {
    /// A new op was created and is running.
    New(OpRow),
    /// The type is exclusive, the same account already has it running, and
    /// this request JOINED that run rather than starting a second.
    Joined(OpRow),
    /// The type is exclusive and ANOTHER account's run is live. Nothing was
    /// started, and the other account's op id is not disclosed.
    Busy,
}

/// The owner's `user_uuid`, from the requester's ACCOUNT (never the
/// connection name).
pub async fn owner_uuid(db: &PgPool, requester: &RequesterCtx) -> Result<Option<Uuid>, sqlx::Error> {
    crate::repo::users::uuid_by_username(db, account_of(&requester.sub)).await
}

/// The advisory-lock key an account's op starts and erase share.
fn owner_lock_key(owner: Option<Uuid>) -> String {
    format!("noo:ops:{}", owner.map(|o| o.to_string()).unwrap_or_else(|| "machine".into()))
}

/// Take the account's op lock for the rest of `tx` (blocking: an erase may wait
/// the few milliseconds a start holds it).
pub async fn lock_owner(tx: &mut sqlx::PgConnection, owner: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(owner_lock_key(Some(owner)))
        .execute(tx)
        .await?;
    Ok(())
}

/// Mark `owner` erase-pending until `ttl_secs` from now (upsert).
pub async fn mark_erase_pending(tx: &mut sqlx::PgConnection, owner: Uuid, ttl_secs: u64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_ops_erase_pending (user_uuid, expires_at) VALUES ($1, now() + make_interval(secs => $2)) \
         ON CONFLICT (user_uuid) DO UPDATE SET marked_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(owner)
    .bind(ttl_secs as f64)
    .execute(tx)
    .await?;
    Ok(())
}

/// Clear the mark (the erase succeeded).
pub async fn clear_erase_pending(tx: &mut sqlx::PgConnection, owner: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM noo_ops_erase_pending WHERE user_uuid = $1").bind(owner).execute(tx).await?;
    Ok(())
}

/// Create the op row and spawn its detached run.
///
/// `runner` is the whole run, already closed over the shared state; it gets
/// the owner's [`OpCtx`] and the real params. `principal` is the caller's bus
/// principal, captured by the route while the request's task-local was still
/// in scope (`bus_principal::current()`); it is re-bound around the run.
pub async fn start(
    db: &PgPool,
    spec: &'static OpSpec,
    requester: Option<&RequesterCtx>,
    principal: crate::bus_principal::Principal,
    params: Value,
    runner: Box<dyn FnOnce(OpCtx, Value) -> RunFuture + Send + 'static>,
) -> Result<Started, StartError> {
    let owner: Option<Uuid> = match requester {
        Some(r) => Some(owner_uuid(db, r).await.map_err(StartError::Db)?.ok_or(StartError::NoAccount)?),
        None => None,
    };
    let consumer: Option<&str> = requester.and_then(|r| r.harness.as_deref());

    // Count and insert in ONE transaction under a per-owner advisory lock, so
    // concurrent starts cannot all read "7 of 8" and all insert.
    let mut tx = db.begin().await.map_err(StartError::Db)?;
    // TRY the lock: a burst of starts from one account must not park pool
    // connections behind it. Losing the race is a 429, which is what an
    // over-cap start would have been anyway.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
        .bind(owner_lock_key(owner))
        .fetch_one(&mut *tx)
        .await
        .map_err(StartError::Db)?;
    if !locked {
        return Err(StartError::Contended);
    }
    if let Some(o) = owner {
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM noo_ops_erase_pending WHERE user_uuid = $1 AND expires_at > now())",
        )
        .bind(o)
        .fetch_one(&mut *tx)
        .await
        .map_err(StartError::Db)?;
        if pending {
            return Err(StartError::ErasePending);
        }
    }
    // A cancelled op still counts while its WORKER run may still be going
    // (`worker_stopped: false`): `cancel` stamps `worker_may_run_until`, the
    // type's own run limit. Otherwise start-then-cancel in a loop would be
    // unbounded worker load.
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM noo_ops WHERE owner_uuid IS NOT DISTINCT FROM $1 AND ( \
             status IN ('queued','running') \
             OR (status = 'cancelled' AND worker_may_run_until > now()) )",
    )
    .bind(owner)
    .fetch_one(&mut *tx)
    .await
    .map_err(StartError::Db)?;
    // The controller's own services share one bucket, so it is wider.
    let cap = if owner.is_some() { max_active_per_owner() } else { max_active_per_owner() * 4 };
    if active >= cap {
        return Err(StartError::TooMany(cap));
    }

    let op_id = Uuid::new_v4();
    let ttl = result_ttl().as_secs() as f64;
    let timeout_secs = (spec.timeout)().as_secs() as i32;
    let inserted = sqlx::query(
        "INSERT INTO noo_ops (op_id, op_type, owner_uuid, consumer, params, exclusive_key, runner_instance, expires_at, worker_limit_secs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8), $9) \
         RETURNING op_id",
    )
    .bind(op_id)
    .bind(spec.name)
    .bind(owner)
    .bind(consumer)
    .bind((spec.redact)(&params))
    .bind(spec.exclusive.then_some(spec.name))
    .bind(instance_id())
    .bind(ttl)
    .bind(timeout_secs)
    .fetch_one(&mut *tx)
    .await;

    match inserted {
        Ok(_) => tx.commit().await.map_err(StartError::Db)?,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() && spec.exclusive => {
            // Leave the aborted transaction before reading.
            drop(tx);
            // The one-live-at-a-time index refused us: someone's run is live.
            let existing = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT {COLS} FROM noo_ops WHERE exclusive_key = $1 AND status IN ('queued','running')"
            )))
            .bind(spec.name)
            .fetch_optional(db)
            .await
            .map_err(StartError::Db)?;
            return match existing {
                Some(r) => {
                    let row = OpRow::from_row(&r).map_err(StartError::Db)?;
                    if row.owner_uuid == owner && (consumer.is_none() || row.consumer.as_deref() == consumer) {
                        Ok(Started::Joined(row))
                    } else {
                        Ok(Started::Busy)
                    }
                }
                // It finished between the refusal and the read: the caller
                // can simply ask again.
                None => Ok(Started::Busy),
            };
        }
        Err(e) => return Err(StartError::Db(e)),
    }

    let ctx = OpCtx { op_id, requester: requester.cloned(), db: db.clone() };
    let timeout = (spec.timeout)();
    let task_db = db.clone();
    let task = tokio::spawn(async move {
        supervise(task_db, op_id, spec, principal, timeout, ctx, params, runner).await;
        live().lock().unwrap_or_else(|p| p.into_inner()).remove(&op_id);
    });
    {
        let mut reg = live().lock().unwrap_or_else(|p| p.into_inner());
        reg.insert(op_id, task.abort_handle());
        if task.is_finished() {
            reg.remove(&op_id);
        }
    }

    let row = get_row(db, op_id).await.map_err(StartError::Db)?.ok_or(StartError::NoAccount)?;
    Ok(Started::New(row))
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    db: PgPool,
    op_id: Uuid,
    spec: &'static OpSpec,
    principal: crate::bus_principal::Principal,
    timeout: Duration,
    ctx: OpCtx,
    params: Value,
    runner: Box<dyn FnOnce(OpCtx, Value) -> RunFuture + Send + 'static>,
) {
    // queued -> running. Zero rows means it was cancelled before it began.
    match sqlx::query(
        "UPDATE noo_ops SET status = 'running', started_at = now(), heartbeat_at = now() \
         WHERE op_id = $1 AND status = 'queued'",
    )
    .bind(op_id)
    .execute(&db)
    .await
    {
        Ok(r) if r.rows_affected() == 0 => return,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(op = %op_id, error = %e, "op_mark_running_failed");
            finish(&db, op_id, FAILED, None, None, Some(format!("could not start: {e}"))).await;
            return;
        }
    }

    // The run is its own task so a panic is a `JoinError` here (reported)
    // rather than a supervisor that dies silently and leaves the row
    // "running" until the sweeper declares it lost. The principal is bound
    // INSIDE it: task-locals do not cross `tokio::spawn`.
    let fut = runner(ctx, params);
    let inner = tokio::spawn(crate::bus_principal::with_principal(
        principal,
        tokio::time::timeout(timeout, fut),
    ));
    let _guard = AbortOnDrop(inner.abort_handle());
    match inner.await {
        Ok(Ok(outcome)) => {
            let body_len = outcome.body.to_string().len();
            if body_len > MAX_RESULT_BYTES {
                finish(
                    &db,
                    op_id,
                    FAILED,
                    None,
                    Some(outcome.http_status as i32),
                    Some(format!(
                        "the result is {body_len} bytes, over the {MAX_RESULT_BYTES}-byte limit for a stored result; \
                         narrow the request"
                    )),
                )
                .await;
            } else if let Some(reason) = outcome.failure {
                finish(&db, op_id, FAILED, Some(outcome.body), Some(outcome.http_status as i32), Some(reason)).await;
            } else {
                finish(&db, op_id, SUCCEEDED, Some(outcome.body), Some(outcome.http_status as i32), None).await;
            }
        }
        Ok(Err(_elapsed)) => {
            let secs = timeout.as_secs();
            finish_held(
                &db,
                op_id,
                FAILED,
                None,
                Some(504),
                Some(format!(
                    "{} did not finish within {secs}s; the gateway stopped waiting ({})",
                    spec.name, spec.cancel_note
                )),
            )
            .await;
        }
        Err(join) if join.is_panic() => {
            tracing::error!(op = %op_id, op_type = spec.name, "op_panicked");
            finish(&db, op_id, FAILED, None, Some(500), Some("the operation panicked; see the gateway log".into())).await;
        }
        Err(_) => {
            // Aborted: a cancel owns the row's final state.
        }
    }
}

/// The one terminal write. Conditional on the row still being live, so it
/// loses to a cancel or an expiry instead of overwriting it.
async fn finish(
    db: &PgPool,
    op_id: Uuid,
    status: &str,
    result: Option<Value>,
    result_status: Option<i32>,
    error: Option<String>,
) {
    finish_inner(db, op_id, status, result, result_status, error, false).await;
}

/// [`finish`] for a run the gateway gave up waiting on (the supervisor
/// timeout): in the SAME statement, stamp the window in which the worker may
/// still be going (`worker_may_run_until` = now + the limit stamped at start: the
/// worker has no deadline of its own, so a full run limit from the moment we
/// stopped listening is the conservative bound) and
/// keep the row at least that long, so an erase still blocks on it.
async fn finish_held(
    db: &PgPool,
    op_id: Uuid,
    status: &str,
    result: Option<Value>,
    result_status: Option<i32>,
    error: Option<String>,
) {
    finish_inner(db, op_id, status, result, result_status, error, true).await;
}

async fn finish_inner(
    db: &PgPool,
    op_id: Uuid,
    status: &str,
    result: Option<Value>,
    result_status: Option<i32>,
    error: Option<String>,
    hold_worker: bool,
) {
    let ttl = result_ttl().as_secs() as f64;
    let r = sqlx::query(
        "UPDATE noo_ops SET status = $2, result = $3, result_status = $4, error = $5, finished_at = now(), \
                worker_may_run_until = CASE WHEN $7 THEN now() + make_interval(secs => COALESCE(worker_limit_secs, 930)) \
                                            ELSE worker_may_run_until END, \
                expires_at = GREATEST(now() + make_interval(secs => $6), \
                    CASE WHEN $7 THEN now() + make_interval(secs => COALESCE(worker_limit_secs, 930)) ELSE now() END) \
         WHERE op_id = $1 AND status IN ('queued','running')",
    )
    .bind(op_id)
    .bind(status)
    .bind(result)
    .bind(result_status)
    .bind(error)
    .bind(ttl)
    .bind(hold_worker)
    .execute(db)
    .await;
    if let Err(e) = r {
        // The row stays `running` and the sweeper will fail it as lost: say so.
        tracing::error!(op = %op_id, error = %e, "op_finish_write_failed");
    }
}

// ───────────────────────────── read ─────────────────────────────

/// An op by id, with no visibility check (internal: the supervisor, waits).
pub async fn get_row(db: &PgPool, op_id: Uuid) -> Result<Option<OpRow>, sqlx::Error> {
    match sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {COLS} FROM noo_ops WHERE op_id = $1"))).bind(op_id).fetch_optional(db).await? {
        Some(r) => Ok(Some(OpRow::from_row(&r)?)),
        None => Ok(None),
    }
}

/// Whether `requester` may see an op at all: its owner, or an admin. A
/// caller that came through a harness sees only that harness's ops.
fn visible_sql(admin: u8, account: u8, consumer: u8) -> String {
    format!(
        "( ${admin}::bool \
           OR ( ( (${account}::text IS NULL AND owner_uuid IS NULL) \
                  OR owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = ${account}) ) \
                AND (${consumer}::text IS NULL OR consumer = ${consumer}) ) )"
    )
}

/// Whether `r` is a worker-delegated agent token.
fn is_delegated(r: &RequesterCtx) -> bool {
    r.act.as_ref().is_some_and(|a| a.sub == crate::worker_delegation::WORKER_ACTOR)
        || r.harness.as_deref().is_some_and(|h| h.starts_with(crate::worker_delegation::HARNESS_PREFIX))
}

/// The three bind values [`visible_sql`] names: admin?, account, consumer.
fn who(requester: Option<&RequesterCtx>) -> (bool, Option<&str>, Option<&str>) {
    match requester {
        // A delegated agent run (worker actor, or a `worker:` harness) is an
        // agent acting for the account, prompt-injectable, so it gets the
        // run-scoped view whatever the account's role: an admin's agent turn
        // must not list every account's ops or cancel other users' ingests.
        Some(r) => (r.role >= Role::Admin && !is_delegated(r), Some(account_of(&r.sub)), r.harness.as_deref()),
        None => (false, None, None),
    }
}

/// An op the requester may see, or `None` — the SAME `None` whether the id
/// is another account's or never existed, so a probe learns nothing.
pub async fn get_visible(db: &PgPool, requester: Option<&RequesterCtx>, op_id: Uuid) -> Result<Option<OpRow>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM noo_ops WHERE op_id = $1 AND {}", visible_sql(2, 3, 4));
    let (admin, account, consumer) = who(requester);
    match sqlx::query(sqlx::AssertSqlSafe(&*sql))
        .bind(op_id)
        .bind(admin)
        .bind(account)
        .bind(consumer)
        .fetch_optional(db)
        .await?
    {
        Some(r) => Ok(Some(OpRow::from_row(&r)?)),
        None => Ok(None),
    }
}

/// The requester's ops, newest first. An admin sees every account's unless
/// `mine`. `status` filters; `limit` is clamped to 1..=100.
pub async fn list(
    db: &PgPool,
    requester: Option<&RequesterCtx>,
    mine: bool,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<OpRow>, sqlx::Error> {
    let (admin, account, consumer) = who(requester);
    let admin_all = admin && !mine;
    let sql = format!(
        "SELECT {COLS} FROM noo_ops WHERE {} AND ($4::text IS NULL OR status = $4) \
         ORDER BY created_at DESC LIMIT $5",
        visible_sql(1, 2, 3)
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(&*sql))
        .bind(admin_all)
        .bind(account)
        .bind(consumer)
        .bind(status)
        .bind(limit.clamp(1, 100))
        .fetch_all(db)
        .await?;
    rows.iter().map(OpRow::from_row).collect()
}

/// Wait up to `wait` for the op to reach a terminal status; the latest row
/// either way. Polls the row: cheap (one tiny row), and it works across
/// gateways, which an in-process notify would not.
pub async fn wait_terminal(db: &PgPool, op_id: Uuid, wait: Duration) -> Result<Option<OpRow>, sqlx::Error> {
    let wait = wait.min(Duration::from_secs(MAX_WAIT_SECS));
    let deadline = tokio::time::Instant::now() + wait;
    let mut step = Duration::from_millis(100);
    loop {
        let row = get_row(db, op_id).await?;
        match &row {
            Some(r) if r.is_terminal() => return Ok(row),
            None => return Ok(None),
            _ => {}
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(row);
        }
        tokio::time::sleep(step.min(deadline - now)).await;
        step = (step * 2).min(Duration::from_millis(500));
    }
}

// ───────────────────────────── cancel ─────────────────────────────

#[derive(Debug)]
pub enum CancelOutcome {
    /// The gateway-side run was stopped and the row says `cancelled`.
    Cancelled(OpRow),
    /// It had already ended; the row as it is.
    AlreadyFinished(OpRow),
    /// The run is another gateway instance's: this one cannot stop it.
    OtherInstance(OpRow),
}

/// Cancel an op the caller may already see. Aborts the gateway-side task and
/// records, in the row, that the WORKER is not stopped (`note`).
pub async fn cancel(db: &PgPool, row: OpRow, note: &str, worker_hold: Duration) -> Result<CancelOutcome, sqlx::Error> {
    if row.is_terminal() {
        return Ok(CancelOutcome::AlreadyFinished(row));
    }
    let local = live().lock().unwrap_or_else(|p| p.into_inner()).remove(&row.op_id);
    if local.is_none() && row.runner_instance != instance_id() {
        return Ok(CancelOutcome::OtherInstance(row));
    }
    let aborted = local.is_some();
    if let Some(h) = local {
        h.abort();
    }
    let may_run_until = chrono::Utc::now() + chrono::Duration::from_std(worker_hold).unwrap_or_default();
    let cancel_note = json!({
        "gateway_aborted": aborted,
        "worker_stopped": false,
        "note": note,
        // Until when the worker run may still be live: the cancelled op keeps
        // counting against the owner's cap until then.
        "worker_may_run_until": may_run_until,
    });
    let ttl = result_ttl().as_secs() as f64;
    sqlx::query(
        "UPDATE noo_ops SET status = 'cancelled', cancel_note = $2, finished_at = now(), \
                error = 'cancelled by the caller', \
                worker_may_run_until = $4::timestamptz, \
                expires_at = GREATEST(now() + make_interval(secs => $3), $4::timestamptz) \
         WHERE op_id = $1 AND status IN ('queued','running')",
    )
    .bind(row.op_id)
    .bind(cancel_note)
    .bind(ttl)
    .bind(may_run_until)
    .execute(db)
    .await?;
    let now = get_row(db, row.op_id).await?.unwrap_or(row);
    if now.status == CANCELLED {
        Ok(CancelOutcome::Cancelled(now))
    } else {
        // It finished between our read and our write; report what it is.
        Ok(CancelOutcome::AlreadyFinished(now))
    }
}

// ───────────────────────────── erasure ─────────────────────────────

/// Right-to-be-forgotten: stop every live run of `username`'s ops BEFORE their
/// rows are deleted. Deleting the row does not stop the detached task; a
/// `docs.ingest` started just before an erasure would otherwise land its
/// document after it. Returns how many tasks were aborted here (runs on
/// another instance are stopped by [`OpCtx::owner_present`] at their next write).
pub async fn abort_live_for_account(db: &PgPool, username: &str) -> Result<usize, sqlx::Error> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT op_id FROM noo_ops WHERE status IN ('queued','running') \
           AND owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = $1)",
    )
    .bind(username)
    .fetch_all(db)
    .await?;
    let mut n = 0;
    let mut reg = live().lock().unwrap_or_else(|p| p.into_inner());
    for id in ids {
        if let Some(h) = reg.remove(&id) {
            h.abort();
            n += 1;
        }
    }
    Ok(n)
}

// ───────────────────────────── reconciliation + sweep ─────────────────────────────

/// Boot: fail every live op of THIS instance. The detached tasks died with
/// the process, so these runs can never report. (Another instance's rows are
/// not touched: its runs are live; if it is gone its heartbeats stop and the
/// sweeper fails them.) Returns how many were failed.
pub async fn reconcile_boot(db: &PgPool, instance: &str) -> Result<u64, sqlx::Error> {
    let ttl = result_ttl().as_secs() as f64;
    let r = sqlx::query(
        "UPDATE noo_ops SET status = 'failed', finished_at = now(), \
                error = 'gateway restarted while the operation was running; its result was lost. Submit it again.', \
                worker_may_run_until = COALESCE(started_at, created_at) + make_interval(secs => COALESCE(worker_limit_secs, 930)), \
                expires_at = GREATEST(now() + make_interval(secs => $2), \
                    COALESCE(started_at, created_at) + make_interval(secs => COALESCE(worker_limit_secs, 930))) \
         WHERE status IN ('queued','running') AND runner_instance = $1",
    )
    .bind(instance)
    .bind(ttl)
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// What one sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub lost: u64,
    pub expired: u64,
    pub purged: u64,
}

/// One sweep: refresh this instance's live heartbeats, fail runs whose
/// heartbeat has gone stale (their runner is gone), expire results past their
/// TTL (clearing the payload, keeping a tombstone so a poll says "expired"
/// rather than "never existed"), and purge tombstones a day old.
pub async fn sweep(db: &PgPool) -> Result<SweepReport, sqlx::Error> {
    let ids = live_ids();
    if !ids.is_empty() {
        sqlx::query("UPDATE noo_ops SET heartbeat_at = now() WHERE op_id = ANY($1) AND status IN ('queued','running')")
            .bind(&ids)
            .execute(db)
            .await?;
    }
    let ttl = result_ttl().as_secs() as f64;
    let lost = sqlx::query(
        "UPDATE noo_ops SET status = 'failed', finished_at = now(), \
                error = 'the gateway running this operation stopped reporting; its result was lost. Submit it again.', \
                worker_may_run_until = COALESCE(started_at, created_at) + make_interval(secs => COALESCE(worker_limit_secs, 930)), \
                expires_at = GREATEST(now() + make_interval(secs => $2), \
                    COALESCE(started_at, created_at) + make_interval(secs => COALESCE(worker_limit_secs, 930))) \
         WHERE status IN ('queued','running') \
           AND heartbeat_at < now() - make_interval(secs => $1)",
    )
    .bind(STALE_HEARTBEAT_SECS as f64)
    .bind(ttl)
    .execute(db)
    .await?
    .rows_affected();
    let expired = sqlx::query(
        "UPDATE noo_ops SET status = 'expired', params = '{}'::jsonb, progress = '{}'::jsonb, \
                result = NULL, error = NULL, cancel_note = NULL \
         WHERE status IN ('succeeded','failed','cancelled') AND expires_at < now()",
    )
    .execute(db)
    .await?
    .rows_affected();
    let purged = sqlx::query("DELETE FROM noo_ops WHERE status = 'expired' AND expires_at < now() - interval '1 day'")
        .execute(db)
        .await?
        .rows_affected();
    Ok(SweepReport { lost, expired, purged })
}

/// Boot wiring: reconcile this instance's orphans, then start the sweeper on
/// the managed-loop primitive (which registers it with `loop_health`, so a
/// dead sweeper pages the operator like every other loop).
pub fn spawn(state: std::sync::Arc<crate::state::AppState>) {
    let st = state.clone();
    tokio::spawn(async move {
        match reconcile_boot(&st.db, instance_id()).await {
            Ok(0) => {}
            Ok(n) => tracing::warn!(failed = n, instance = instance_id(), "ops_boot_reconcile_failed_orphans"),
            Err(e) => tracing::warn!(error = %e, "ops_boot_reconcile_error"),
        }
    });
    crate::managed_loop::spawn_managed_loop("ops_sweep", SWEEP_INTERVAL_SECS, state, |st| async move {
        let report = sweep(&st.db).await?;
        if report != SweepReport::default() {
            tracing::info!(lost = report.lost, expired = report.expired, purged = report.purged, "ops_sweep");
        }
        Ok(())
    });
}

#[cfg(test)]
pub(crate) mod tests;
