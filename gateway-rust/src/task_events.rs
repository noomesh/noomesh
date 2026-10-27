//! Task events for add-on delegated tasks (i143 part D, wire contract v1).
//!
//! A task created through an add-on (`noo_tasks.created_via = 'addon:<name>'`)
//! records every lifecycle event in a per-task outbox (`noo_task_events`,
//! primary key `(task_id, seq)`), and the gateway POSTs them, in order, one
//! at a time, to the add-on's manifest `task_events` route through the add-on
//! proxy (the gateway's caller bearer plus `X-Noo-Requester-*` = the task's
//! OWNER). No user token is needed to receive them, and no token or secret
//! ever appears in an event.
//!
//! `seq` starts at 1 per task and goes up by exactly 1. It is assigned in the
//! same transaction that writes the outbox row: [`emit`] bumps
//! `noo_task_event_delivery.last_seq` (which also serialises concurrent
//! emitters on the row lock) and inserts the event with the value it got.
//!
//! The receiver answers 2xx (applied, or a duplicate), or 409 `{expected: n}`
//! (a gap). A 409 rewinds that task's cursor to `n` when the outbox still has
//! it; when `n` is older than retention the gateway sends ONE `reset` event
//! (not stored) whose `seq` is `earliest_seq - 1` and whose data is
//! `{earliest_seq, task}`, then resumes at `earliest_seq`. Anything else is
//! retried with backoff for up to 7 days, after which the task's delivery is
//! marked `undelivered`.

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;

use crate::state::AppState;

/// The envelope's `v`.
pub const WIRE_VERSION: i64 = 1;
/// How long events (and context) outlive a terminal task, and how long a
/// failing delivery is retried before it is marked undelivered.
const RETENTION_DAYS: i64 = 7;
/// Most events one delivery pass sends for one task before yielding.
const BURST: usize = 25;
/// Most events one pull returns.
const MAX_PAGE: i64 = 500;
/// Most tool calls one `result` event carries.
const MAX_TOOL_CALLS: i64 = 500;

// ── pure pieces ─────────────────────────────────────────────────────────

/// The add-on name in a `created_via`, if it is an add-on's.
pub fn addon_of(created_via: &str) -> Option<&str> {
    created_via.strip_prefix("addon:").filter(|n| !n.is_empty())
}

pub fn is_terminal(state: &str) -> bool {
    matches!(state, "done" | "failed" | "stopped")
}

/// `state` data: `{state, why?, final}`.
pub fn state_data(state: &str, why: Option<&str>) -> Value {
    let mut d = json!({"state": state, "final": is_terminal(state)});
    if let Some(w) = why.filter(|w| !w.trim().is_empty()) {
        d["why"] = json!(w);
    }
    d
}

fn is_final_state(kind: &str, data: &Value) -> bool {
    kind == "state" && data.get("final").and_then(Value::as_bool) == Some(true)
}

/// The wire envelope.
pub fn envelope(task_id: &str, owner: &str, via: &str, seq: i64, kind: &str, at: chrono::DateTime<chrono::Utc>, data: &Value) -> Value {
    json!({
        "v": WIRE_VERSION,
        "task_id": task_id,
        "owner": owner,
        "via": via,
        "seq": seq,
        "kind": kind,
        "at": at.to_rfc3339(),
        "data": data,
    })
}

/// `result` data. `result` is the task's answer on success and `null` on
/// failure (the reason rides the final `state`'s `why`).
pub fn result_data(result: Option<&str>, tool_calls: Vec<Value>) -> Value {
    json!({"result": result, "tool_calls": tool_calls})
}

/// One recorded tool call, as the `result` event lists it.
///
/// `outcome`: `noo_tool_executions.success` true = `ok`, false = `error`,
/// NULL (a row with no verdict yet) = `pending_approval`. `denied` has no
/// source in the record today. `audit_id` has no source either, so it is
/// `null` rather than invented.
pub fn tool_call_json(call_id: &str, tool: &str, success: Option<bool>, at: chrono::DateTime<chrono::Utc>) -> Value {
    let outcome = match success {
        Some(true) => "ok",
        Some(false) => "error",
        None => "pending_approval",
    };
    json!({"call_id": call_id, "tool": tool, "outcome": outcome, "audit_id": Value::Null, "at": at.to_rfc3339()})
}

/// Backoff after `attempts` consecutive failures: `min(5 s x 2^attempts, 300 s)`.
pub fn backoff_secs(attempts: i32) -> i64 {
    let a = attempts.clamp(0, 16) as u32;
    (5i64 * (1i64 << a)).min(300)
}

/// Has a delivery been failing for more than the retention window?
pub fn give_up(first_failure: Option<chrono::DateTime<chrono::Utc>>, now: chrono::DateTime<chrono::Utc>) -> bool {
    first_failure.is_some_and(|t| now - t > chrono::Duration::days(RETENTION_DAYS))
}

/// What to do after a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// 2xx: advance past the event.
    Delivered,
    /// 409 with `expected: n` that the outbox still holds: resend from `n`.
    Rewind(i64),
    /// 409 with `expected: n` older than retention: send the reset event.
    Reset,
    /// Anything else: back off.
    Retry,
}

/// The decision, pure. `sent` is the seq just sent, `earliest` the oldest
/// retained seq, `last_seq` the newest. A 409 whose `expected` is not a
/// number, is ahead of everything we have, or equals what was just sent
/// (the receiver contradicts itself) is a plain failure, never a loop.
pub fn decide(status: Option<u16>, body: Option<&Value>, sent: i64, earliest: i64, last_seq: i64) -> Next {
    match status {
        Some(s) if (200..300).contains(&s) => Next::Delivered,
        Some(409) => match body.and_then(|b| b.get("expected")).and_then(Value::as_i64) {
            Some(n) if n > last_seq || n == sent => Next::Retry,
            Some(n) if n >= earliest => Next::Rewind(n),
            Some(_) => Next::Reset,
            None => Next::Retry,
        },
        _ => Next::Retry,
    }
}

// ── emitting ────────────────────────────────────────────────────────────

/// Record an event for a task. A no-op unless the task was created by an
/// add-on. One transaction: upsert the delivery row (which locks it),
/// `last_seq + 1`, insert the event with that seq. A second final `state`
/// is dropped, so `final` is true exactly once.
pub async fn emit(db: &sqlx::PgPool, task_id: &str, kind: &str, data: Value) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let via: Option<String> = crate::repo::tasks::created_via(db, uuid).await?;
    let Some(addon) = via.as_deref().and_then(addon_of) else { return Ok(()) };
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO noo_task_event_delivery (task_id, addon) VALUES ($1, $2) \
         ON CONFLICT (task_id) DO UPDATE SET addon = EXCLUDED.addon",
    )
    .bind(uuid)
    .bind(addon)
    .execute(&mut *tx)
    .await?;
    if is_final_state(kind, &data) {
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM noo_task_events WHERE task_id = $1 AND kind = 'state' AND data->>'final' = 'true')",
        )
        .bind(uuid)
        .fetch_one(&mut *tx)
        .await?;
        if already {
            tx.rollback().await?;
            return Ok(());
        }
    }
    let seq: i64 = sqlx::query_scalar("UPDATE noo_task_event_delivery SET last_seq = last_seq + 1 WHERE task_id = $1 RETURNING last_seq")
        .bind(uuid)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO noo_task_events (task_id, seq, kind, data) VALUES ($1, $2, $3, $4)")
        .bind(uuid)
        .bind(seq)
        .bind(kind)
        .bind(&data)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// [`emit`] for call sites that must never fail because an event could not
/// be recorded: the failure is logged and swallowed.
pub async fn emit_logged(db: &sqlx::PgPool, task_id: &str, kind: &str, data: Value) {
    if let Err(e) = emit(db, task_id, kind, data).await {
        tracing::warn!(task = task_id, kind, error = %e, "task_events: event not recorded");
    }
}

/// `state {state, why?, final: false}` for a live state.
pub async fn emit_state(db: &sqlx::PgPool, task_id: &str, state: &str, why: Option<&str>) {
    emit_logged(db, task_id, "state", state_data(state, why)).await;
}

/// `revoked {reason}`: `stopped_by_owner` | `background_revoked` | `account_disabled`.
/// Emit it BEFORE the final state.
pub async fn emit_revoked(db: &sqlx::PgPool, task_id: &str, reason: &str) {
    emit_logged(db, task_id, "revoked", json!({"reason": reason})).await;
}

/// The final `state` event, read from the task row as it stands: the
/// caller changed the row to a terminal state, and calls this after. A task
/// that is not terminal (or is gone) emits nothing; a second call emits
/// nothing (`final` is true exactly once).
pub async fn emit_final_state(db: &sqlx::PgPool, task_id: &str, why: Option<&str>) {
    let Ok(uuid) = uuid::Uuid::parse_str(task_id) else { return };
    let state: Option<String> = crate::repo::tasks::state_of(db, uuid).await.ok().flatten();
    if let Some(s) = state.filter(|s| is_terminal(s)) {
        emit_logged(db, task_id, "state", state_data(&s, why)).await;
    }
}

/// The task's recorded tool calls (`result` event), oldest first. The loop's
/// own bookkeeping tools are left out, like the evidence gate leaves them out.
/// A read failure yields an empty list, logged.
pub async fn tool_calls(db: &sqlx::PgPool, task_id: &str) -> Vec<Value> {
    let Ok(uuid) = uuid::Uuid::parse_str(task_id) else { return vec![] };
    let bookkeeping: Vec<String> = crate::tasks::BOOKKEEPING_TOOLS.iter().map(|s| s.to_string()).collect();
    let rows = sqlx::query(
        "SELECT e.id, e.tool_name, e.success, e.created_at FROM noo_tool_executions e \
         JOIN noo_tasks t ON t.conversation_id = e.conversation_id \
         WHERE t.id = $1 AND NOT (e.tool_name = ANY($2)) ORDER BY e.created_at, e.id LIMIT $3",
    )
    .bind(uuid)
    .bind(&bookkeeping)
    .bind(MAX_TOOL_CALLS)
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => rows
            .iter()
            .map(|r| {
                let id = r.try_get::<uuid::Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default();
                let tool: String = r.try_get("tool_name").unwrap_or_default();
                let success = r.try_get::<Option<bool>, _>("success").ok().flatten();
                let at = r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").unwrap_or_else(|_| chrono::Utc::now());
                tool_call_json(&id, &tool, success, at)
            })
            .collect(),
        Err(e) => {
            tracing::warn!(task = task_id, error = %e, "task_events: tool calls not read");
            vec![]
        }
    }
}

/// `result` then the final `state`, for a task that just reached done|failed.
pub async fn emit_finished(db: &sqlx::PgPool, task_id: &str, ok: bool, text: &str) {
    // Cheap exit for the common case (a direct task): emit() would no-op
    // anyway, but the tool-call read should not run for it.
    if !is_addon_task(db, task_id).await {
        return;
    }
    let calls = tool_calls(db, task_id).await;
    emit_logged(db, task_id, "result", result_data(ok.then_some(text), calls)).await;
    emit_final_state(db, task_id, (!ok).then_some(text)).await;
}

async fn is_addon_task(db: &sqlx::PgPool, task_id: &str) -> bool {
    let Ok(uuid) = uuid::Uuid::parse_str(task_id) else { return false };
    crate::repo::tasks::created_via(db, uuid)
        .await
        .ok()
        .flatten()
        .is_some_and(|v| addon_of(&v).is_some())
}

// ── pulling ─────────────────────────────────────────────────────────────

/// `GET /api/tasks/{id}/events` body.
#[derive(Debug, Clone, Serialize)]
pub struct EventsPage {
    pub events: Vec<Value>,
    pub earliest_seq: i64,
    pub last_seq: i64,
}

async fn owner_and_via(db: &sqlx::PgPool, uuid: uuid::Uuid) -> Result<Option<(String, String)>> {
    Ok(sqlx::query_as::<_, (String, String)>(
        "SELECT COALESCE(u.username, ''), COALESCE(t.created_via, '') FROM noo_tasks t \
         LEFT JOIN noo_users u ON u.user_uuid = t.owner_uuid WHERE t.id = $1",
    )
    .bind(uuid)
    .fetch_optional(db)
    .await?)
}

/// Events with `seq > after`, oldest first, as full envelopes.
pub async fn list_after(db: &sqlx::PgPool, task_id: &str, after: i64, limit: i64) -> Result<EventsPage> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let (owner, via) = owner_and_via(db, uuid).await?.ok_or_else(|| anyhow!("task {task_id} not found"))?;
    let rows = sqlx::query("SELECT seq, kind, data, at FROM noo_task_events WHERE task_id = $1 AND seq > $2 ORDER BY seq LIMIT $3")
        .bind(uuid)
        .bind(after.max(0))
        .bind(limit.clamp(1, MAX_PAGE))
        .fetch_all(db)
        .await?;
    let events = rows
        .iter()
        .map(|r| {
            let at = r.try_get::<chrono::DateTime<chrono::Utc>, _>("at").unwrap_or_else(|_| chrono::Utc::now());
            let data: Value = r.try_get("data").unwrap_or(Value::Null);
            envelope(task_id, &owner, &via, r.try_get("seq").unwrap_or(0), &r.try_get::<String, _>("kind").unwrap_or_default(), at, &data)
        })
        .collect();
    let (min, last): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT (SELECT min(seq) FROM noo_task_events WHERE task_id = $1), \
                (SELECT last_seq FROM noo_task_event_delivery WHERE task_id = $1)",
    )
    .bind(uuid)
    .fetch_one(db)
    .await?;
    let last_seq = last.unwrap_or(0);
    Ok(EventsPage { events, earliest_seq: min.unwrap_or(last_seq + 1), last_seq })
}

// ── delivery ────────────────────────────────────────────────────────────

struct Due {
    task_id: uuid::Uuid,
    addon: String,
    next_seq: i64,
    last_seq: i64,
    attempts: i32,
    first_failure_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Start the delivery loop (every ~2 s) and the hourly sweep.
pub fn spawn_delivery(state: Arc<AppState>) {
    let st = state.clone();
    tokio::spawn(async move {
        const INTERVAL_SECS: u64 = 2;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(INTERVAL_SECS)).await;
            crate::loop_health::record_tick("task_event_delivery", INTERVAL_SECS);
            if let Err(e) = deliver_due(&st).await {
                tracing::warn!(error = %e, "task_events: delivery pass failed");
            }
        }
    });
    tokio::spawn(async move {
        const INTERVAL_SECS: u64 = 3600;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(INTERVAL_SECS)).await;
            crate::loop_health::record_tick("task_event_sweep", INTERVAL_SECS);
            sweep(&state.db).await;
        }
    });
}

async fn deliver_due(state: &Arc<AppState>) -> Result<()> {
    let rows = sqlx::query(
        "SELECT task_id, addon, next_seq, last_seq, attempts, first_failure_at FROM noo_task_event_delivery \
         WHERE next_seq <= last_seq AND next_try_at <= now() AND undelivered_at IS NULL \
         ORDER BY next_try_at LIMIT 50",
    )
    .fetch_all(&state.db)
    .await?;
    let due: Vec<Due> = rows
        .iter()
        .filter_map(|r| {
            Some(Due {
                task_id: r.try_get("task_id").ok()?,
                addon: r.try_get("addon").ok()?,
                next_seq: r.try_get("next_seq").ok()?,
                last_seq: r.try_get("last_seq").ok()?,
                attempts: r.try_get("attempts").unwrap_or(0),
                first_failure_at: r.try_get("first_failure_at").ok().flatten(),
            })
        })
        .collect();
    // One in-flight POST per task: each task is one future, and the pass
    // waits for all of them before the next one starts.
    futures::future::join_all(due.into_iter().map(|d| deliver_task(state, d))).await;
    Ok(())
}

async fn record_failure(db: &sqlx::PgPool, d: &Due, why: &str) {
    let attempts = d.attempts.saturating_add(1);
    let now = chrono::Utc::now();
    let first = d.first_failure_at.unwrap_or(now);
    let undelivered = give_up(Some(first), now);
    if undelivered {
        tracing::error!(task = %d.task_id, addon = %d.addon, why, "task_events: delivery abandoned after 7 days; marked undelivered");
    } else {
        tracing::warn!(task = %d.task_id, addon = %d.addon, attempts, why, "task_events: delivery failed; will retry");
    }
    let r = sqlx::query(
        "UPDATE noo_task_event_delivery SET attempts = $2, next_try_at = now() + ($3::float8 * interval '1 second'), \
         first_failure_at = COALESCE(first_failure_at, now()), \
         undelivered_at = CASE WHEN $4 THEN now() ELSE undelivered_at END WHERE task_id = $1",
    )
    .bind(d.task_id)
    .bind(attempts)
    .bind(backoff_secs(attempts) as f64)
    .bind(undelivered)
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::warn!(task = %d.task_id, error = %e, "task_events: failure not recorded");
    }
}

async fn set_cursor(db: &sqlx::PgPool, task_id: uuid::Uuid, next_seq: i64, delivered: bool) -> Result<()> {
    if delivered {
        sqlx::query("UPDATE noo_task_event_delivery SET next_seq = $2, attempts = 0, first_failure_at = NULL WHERE task_id = $1")
    } else {
        sqlx::query("UPDATE noo_task_event_delivery SET next_seq = $2 WHERE task_id = $1")
    }
    .bind(task_id)
    .bind(next_seq)
    .execute(db)
    .await?;
    Ok(())
}

async fn deliver_task(state: &Arc<AppState>, mut d: Due) {
    let db = &state.db;
    let Some(entry) = crate::addon_registry::get(&d.addon) else {
        return record_failure(db, &d, "the add-on is not registered").await;
    };
    let Some(spec) = entry.task_events() else {
        return record_failure(db, &d, "the add-on declares no task_events route").await;
    };
    let task_s = d.task_id.to_string();
    let (owner, via) = match owner_and_via(db, d.task_id).await {
        Ok(Some(x)) => x,
        Ok(None) => return, // the task is gone; the sweep removes the rows
        Err(e) => return record_failure(db, &d, &format!("task not read: {e}")).await,
    };
    // The owner's role and scopes, as the add-on would see them on a request
    // from that person. A disabled owner still gets their events (the
    // revoked + final state ones above all).
    let role = crate::repo::users::role_of(db, &owner)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.parse::<crate::auth::Role>().ok())
        .unwrap_or(crate::auth::Role::User);
    let requester = crate::auth::RequesterCtx {
        sub: owner.clone(),
        scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
        role,
        harness: None,
        act: None,
    };

    let mut rewinds = 0;
    for _ in 0..BURST {
        if d.next_seq > d.last_seq {
            break;
        }
        let row = match sqlx::query("SELECT kind, data, at FROM noo_task_events WHERE task_id = $1 AND seq = $2")
            .bind(d.task_id)
            .bind(d.next_seq)
            .fetch_optional(db)
            .await
        {
            Ok(r) => r,
            Err(e) => return record_failure(db, &d, &format!("event not read: {e}")).await,
        };
        let earliest: Option<i64> = sqlx::query_scalar("SELECT min(seq) FROM noo_task_events WHERE task_id = $1")
            .bind(d.task_id)
            .fetch_one(db)
            .await
            .ok()
            .flatten();
        let Some(row) = row else {
            // The event we owe is gone (swept, or never written). Resume at
            // what is retained with a reset, or past the end if nothing is.
            match earliest {
                Some(e) if e > d.next_seq => match send_reset(state, &entry, spec, &requester, &d, &owner, &via, e).await {
                    Ok(()) => {
                        if set_cursor(db, d.task_id, e, true).await.is_err() {
                            return;
                        }
                        d.next_seq = e;
                        d.attempts = 0;
                        d.first_failure_at = None;
                        continue;
                    }
                    Err(why) => return record_failure(db, &d, &why).await,
                },
                _ => {
                    let _ = set_cursor(db, d.task_id, d.last_seq + 1, true).await;
                    return;
                }
            }
        };
        let earliest = earliest.unwrap_or(d.next_seq);
        let kind: String = row.try_get("kind").unwrap_or_default();
        let data: Value = row.try_get("data").unwrap_or(Value::Null);
        let at = row.try_get::<chrono::DateTime<chrono::Utc>, _>("at").unwrap_or_else(|_| chrono::Utc::now());
        let body = envelope(&task_s, &owner, &via, d.next_seq, &kind, at, &data);
        let out = crate::addon_proxy::post_task_event(&entry, spec, &requester, &body).await;
        match decide(out.status, out.body.as_ref(), d.next_seq, earliest, d.last_seq) {
            Next::Delivered => {
                d.next_seq += 1;
                d.attempts = 0;
                d.first_failure_at = None;
                if let Err(e) = set_cursor(db, d.task_id, d.next_seq, true).await {
                    tracing::warn!(task = %d.task_id, error = %e, "task_events: cursor not advanced");
                    return;
                }
            }
            Next::Rewind(n) => {
                rewinds += 1;
                if rewinds > 3 {
                    return record_failure(db, &d, "the receiver keeps rewinding").await;
                }
                tracing::info!(task = %d.task_id, from = d.next_seq, to = n, "task_events: receiver asked for a rewind");
                if set_cursor(db, d.task_id, n, false).await.is_err() {
                    return;
                }
                d.next_seq = n;
            }
            Next::Reset => match send_reset(state, &entry, spec, &requester, &d, &owner, &via, earliest).await {
                Ok(()) => {
                    if set_cursor(db, d.task_id, earliest, true).await.is_err() {
                        return;
                    }
                    d.next_seq = earliest;
                    d.attempts = 0;
                    d.first_failure_at = None;
                }
                Err(why) => return record_failure(db, &d, &why).await,
            },
            Next::Retry => return record_failure(db, &d, &out.detail).await,
        }
    }
}

/// The one `reset` event: not stored, `seq = earliest_seq - 1`,
/// `data = {earliest_seq, task}` with the task's current JSON.
#[allow(clippy::too_many_arguments)]
async fn send_reset(
    state: &Arc<AppState>,
    entry: &crate::addon_registry::AddonEntry,
    spec: &crate::addon_proxy::TaskEventsSpec,
    requester: &crate::auth::RequesterCtx,
    d: &Due,
    owner: &str,
    via: &str,
    earliest: i64,
) -> std::result::Result<(), String> {
    let task_s = d.task_id.to_string();
    let task = crate::tasks::get(&state.db, &task_s).await.map_err(|e| e.to_string())?.ok_or("task gone")?;
    let task_json = serde_json::to_value(&task).map_err(|e| e.to_string())?;
    let body = envelope(&task_s, owner, via, earliest - 1, "reset", chrono::Utc::now(), &json!({"earliest_seq": earliest, "task": task_json}));
    let out = crate::addon_proxy::post_task_event(entry, spec, requester, &body).await;
    if out.status.is_some_and(|s| (200..300).contains(&s)) {
        Ok(())
    } else {
        Err(format!("reset not accepted: {}", out.detail))
    }
}

/// Hourly: drop what outlived its task. Events, delivery rows and context of
/// tasks terminal for more than 7 days; idempotency keys older than 24 h.
/// Each statement stands alone, so one failing never blocks the others.
pub async fn sweep(db: &sqlx::PgPool) {
    const TERMINAL: &str = "SELECT id FROM noo_tasks WHERE state IN ('done','failed','stopped') AND updated_at < now() - interval '7 days'";
    let stmts: [(&str, String); 4] = [
        ("events", format!("DELETE FROM noo_task_events WHERE task_id IN ({TERMINAL})")),
        ("delivery", format!("DELETE FROM noo_task_event_delivery WHERE task_id IN ({TERMINAL})")),
        ("context", format!("DELETE FROM noo_task_context WHERE task_id IN ({TERMINAL})")),
        ("idempotency", "DELETE FROM noo_task_idempotency WHERE created_at < now() - interval '24 hours'".to_string()),
    ];
    for (what, sql) in stmts {
        match sqlx::query(sqlx::AssertSqlSafe(sql)).execute(db).await {
            Ok(r) if r.rows_affected() > 0 => tracing::info!(what, rows = r.rows_affected(), "task_events: swept"),
            Ok(_) => {}
            Err(e) => tracing::warn!(what, error = %e, "task_events: sweep failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addon_of_reads_only_addon_vias() {
        assert_eq!(addon_of("addon:pai-voice"), Some("pai-voice"));
        assert_eq!(addon_of("addon:"), None);
        assert_eq!(addon_of("direct"), None);
        assert_eq!(addon_of(""), None);
    }

    #[test]
    fn envelope_has_exactly_the_wire_fields() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-19T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let e = envelope("t1", "alice", "addon:pai-voice", 3, "progress", at, &json!({"loop": 1, "note": "n"}));
        let keys: std::collections::BTreeSet<_> = e.as_object().unwrap().keys().cloned().collect();
        let want: std::collections::BTreeSet<_> = ["v", "task_id", "owner", "via", "seq", "kind", "at", "data"].iter().map(|s| s.to_string()).collect();
        assert_eq!(keys, want);
        assert_eq!(e["v"], 1);
        assert_eq!(e["seq"], 3);
        assert_eq!(e["at"], "2026-10-19T12:00:00+00:00");
        assert_eq!(e["data"]["note"], "n");
    }

    #[test]
    fn state_data_marks_final_only_on_terminal_states() {
        for s in ["open", "running", "checkpointed"] {
            assert_eq!(state_data(s, None)["final"], false, "{s}");
        }
        for s in ["done", "failed", "stopped"] {
            assert_eq!(state_data(s, None)["final"], true, "{s}");
        }
        assert!(state_data("done", None).get("why").is_none());
        assert!(state_data("failed", Some("  ")).get("why").is_none());
        assert_eq!(state_data("failed", Some("boom"))["why"], "boom");
        assert!(is_final_state("state", &state_data("done", None)));
        assert!(!is_final_state("state", &state_data("running", None)));
        assert!(!is_final_state("result", &state_data("done", None)));
    }

    #[test]
    fn result_data_shape_and_tool_call_outcomes() {
        let at = chrono::Utc::now();
        let ok = tool_call_json("c1", "web_search", Some(true), at);
        assert_eq!(ok["outcome"], "ok");
        assert_eq!(ok["audit_id"], Value::Null);
        assert_eq!(tool_call_json("c", "t", Some(false), at)["outcome"], "error");
        assert_eq!(tool_call_json("c", "t", None, at)["outcome"], "pending_approval");
        let d = result_data(None, vec![ok]);
        assert_eq!(d["result"], Value::Null);
        assert_eq!(d["tool_calls"].as_array().unwrap().len(), 1);
        assert_eq!(result_data(Some("x"), vec![])["result"], "x");
    }

    #[test]
    fn backoff_is_5s_doubling_capped_at_300s() {
        let got: Vec<i64> = (0..9).map(backoff_secs).collect();
        assert_eq!(got, vec![5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(backoff_secs(i32::MAX), 300);
        assert_eq!(backoff_secs(-3), 5);
    }

    #[test]
    fn delivery_is_abandoned_after_seven_days_of_failing() {
        let now = chrono::Utc::now();
        assert!(!give_up(None, now));
        assert!(!give_up(Some(now - chrono::Duration::days(6)), now));
        assert!(give_up(Some(now - chrono::Duration::days(7) - chrono::Duration::seconds(1)), now));
    }

    #[test]
    fn decide_table() {
        let b = |n: i64| json!({"expected": n});
        // sent 7; retained 3..=9
        assert_eq!(decide(Some(200), None, 7, 3, 9), Next::Delivered);
        assert_eq!(decide(Some(204), None, 7, 3, 9), Next::Delivered);
        assert_eq!(decide(Some(409), Some(&b(5)), 7, 3, 9), Next::Rewind(5));
        assert_eq!(decide(Some(409), Some(&b(3)), 7, 3, 9), Next::Rewind(3), "the earliest retained seq is still there");
        assert_eq!(decide(Some(409), Some(&b(2)), 7, 3, 9), Next::Reset, "older than retention");
        assert_eq!(decide(Some(409), Some(&b(0)), 7, 3, 9), Next::Reset);
        assert_eq!(decide(Some(409), Some(&b(7)), 7, 3, 9), Next::Retry, "expecting what we just sent is a contradiction");
        assert_eq!(decide(Some(409), Some(&b(12)), 7, 3, 9), Next::Retry, "ahead of everything we have");
        assert_eq!(decide(Some(409), Some(&json!({"error": "x"})), 7, 3, 9), Next::Retry);
        assert_eq!(decide(Some(409), None, 7, 3, 9), Next::Retry);
        assert_eq!(decide(Some(500), None, 7, 3, 9), Next::Retry);
        assert_eq!(decide(Some(404), None, 7, 3, 9), Next::Retry);
        assert_eq!(decide(None, None, 7, 3, 9), Next::Retry);
    }
}
