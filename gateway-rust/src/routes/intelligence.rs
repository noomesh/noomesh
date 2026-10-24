// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Intelligence routes — heartbeat scheduler, autonomy engine.
//!
//! Native Rust: heartbeat task CRUD (SQL), history, actions list, status,
//!   artifacts, run_task (coordinator-driven),
//!   autonomy status/audit/locations/toggle/enable/disable (config YAML + Redis)
//!   webhook (reuses run_task — ported 2026-03-31)

use std::sync::Arc;
use std::time::Instant;
use axum::{
    Router,
    routing::{get, post, put, delete},
    extract::{State, Path, Query},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::measured::{put_into, put_keyed_into, Measured};
use crate::state::AppState;
use crate::heartbeat_actions;
use super::{AppJson, AppError, AppResult};
// delegate_post removed — all intelligence routes are now native Rust

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Agent activities (Phase 3 meta-loop) ──
        .route("/api/activities", get(activities_list))
        .route("/api/activities", post(activities_create))
        .route("/api/activities/{id}/progress", post(activities_append_progress))
        .route("/api/activities/{id}/link-task", post(activities_link_task))
        .route("/api/activities/{id}/status", put(activities_set_status))
        .route("/api/activities/{id}/complete", post(activities_complete))

        // ── Heartbeat: Native Rust (SQL) ──
        .route("/api/heartbeat/tasks", get(heartbeat_tasks))
        .route("/api/heartbeat/tasks", post(heartbeat_create_task))
        .route("/api/heartbeat/schedule", post(heartbeat_schedule_task))
        .route("/api/heartbeat/tasks/{task_id}/toggle", put(heartbeat_toggle_task))
        .route("/api/heartbeat/tasks/{task_id}/schedule", put(heartbeat_set_schedule))
        // Tasks and saved recipients that predate the guard: a person reviews them once.
        .route("/api/heartbeat/review-existing", get(heartbeat_review_list))
        .route("/api/heartbeat/review-existing/approve", post(heartbeat_review_approve))
        .route("/api/heartbeat/tasks/{task_id}", delete(heartbeat_delete_task))
        .route("/api/heartbeat/history", get(heartbeat_history))
        .route("/api/heartbeat/actions", get(heartbeat_actions))

        // ── Heartbeat: Native Rust (SQL — scheduler status & artifacts) ──
        .route("/api/heartbeat/status", get(heartbeat_status))
        .route("/api/heartbeat/tasks/{task_id}/artifacts", get(heartbeat_task_artifacts))
        .route("/api/heartbeat/artifacts", get(heartbeat_artifact_content))

        // ── Heartbeat: Native Rust (run_task via coordinator) ──
        .route("/api/heartbeat/tasks/{task_id}/run", post(heartbeat_run_task))

        // ── Heartbeat: reload signal — UI calls this after task save so the
        // running scheduler picks up the new schedule without a gateway
        // restart. Sets a Redis flag the heartbeat_loop checks every 5s. ──
        .route("/api/heartbeat/reload", post(heartbeat_reload))

        // ── Loop liveness: every always-on background loop stamps a tick
        // into loop_health; this exposes the registry so operators (and
        // agent_self_check) can see a dead loop instead of inferring it
        // from missing reports. ──
        .route("/api/agent/loops", get(agent_loops))

        // ── Autonomy: Native Rust (config YAML + Redis — ported 2026-03-31) ──
        .route("/api/autonomy/status", get(autonomy_status))
        .route("/api/autonomy/audit", get(autonomy_audit))
        .route("/api/autonomy/decisions", get(autonomy_decisions))
        .route("/api/autonomy/locations", post(autonomy_add_location))
        .route("/api/autonomy/locations/{name}/toggle", post(autonomy_toggle_location))
        .route("/api/autonomy/enable", post(autonomy_enable))
        .route("/api/autonomy/disable", post(autonomy_disable))
}

// ═══════════════════════════════════════════════════════════════
// Heartbeat task CRUD — native SQL via sqlx
// ═══════════════════════════════════════════════════════════════

/// List all heartbeat tasks.
async fn heartbeat_tasks(State(state): State<Arc<AppState>>) -> AppResult {
    let tasks = sqlx::query_as::<_, (String, String, String, String, Value, Value, Value, bool, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, name, schedule, action, \
                COALESCE(config, '{}'::jsonb), \
                COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), \
                enabled, last_run, next_run, \
                COALESCE(created_by, 'system'), \
                authorised_by, authorised_at \
         FROM noo_heartbeat_tasks \
         ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let tasks: Vec<Value> = tasks.iter().map(|(id, name, schedule, action, config, channels, recipients, enabled, last_run, next_run, created_by, authorised_by, authorised_at)| {
        // `guard`: whether the live spec destroys data, and who authorised it (task_guard.rs).
        let guard = crate::task_guard::listing_view(
            action,
            config,
            authorised_by.as_deref(),
            authorised_at.map(|t| t.to_rfc3339()),
        );
        json!({
            "guard": guard,
            "id": id,
            "name": name,
            "schedule": schedule,
            "action": action,
            "config": config,
            "channels": channels,
            "recipients": recipients,
            "enabled": enabled,
            "last_run": last_run,
            "next_run": next_run,
            "created_by": created_by,
        })
    }).collect();
    // Existing tasks and saved recipients waiting for `noo heartbeat review-existing`.
    let waiting = crate::task_guard::review_count(&state.db).await;
    Ok(Json(json!({"tasks": tasks, "waiting_review": waiting})))
}

/// Create or update a heartbeat task.
///
/// A task that destroys data (`task_guard::classify`) written by an MCP door, an agent run or
/// any credential that is not a person is NOT written: it becomes a proposal in the user-proposal
/// queue, and the answer says so (`proposal: true`, `task_created: false`). A person approves it
/// with `noo heartbeat approve <proposal-id>`. Non-destructive tasks are written directly.
async fn heartbeat_create_task(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // No explicit id → derive it from the name, exactly like
    // `heartbeat_schedule_task` does (2026-08-07: `noo heartbeat add` sent
    // name/schedule/action without an id and this endpoint 400'd — the CLI
    // now sends a derived id too, but name-only payloads must keep working).
    let id = match body.get("id").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
        Some(id) => id.to_string(),
        None => slugify_for_id(name),
    };
    if id.is_empty() {
        return Err(AppError::BadRequest("Missing field: id".into()));
    }
    let schedule = body.get("schedule").and_then(|v| v.as_str()).unwrap_or("");
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");

    if name.is_empty() || schedule.is_empty() || action.is_empty() {
        return Err(AppError::BadRequest("Required fields: id, name, schedule, action".into()));
    }

    let config = body.get("config").cloned().unwrap_or(json!({}));
    // Stored as-is until 2026-09-22: a JSON list sent as a string became a
    // row whose channels no reader could see (`destination_list`).
    let channels = json!(crate::heartbeat_actions::destination_list(
        body.get("channels").unwrap_or(&json!([]))
    ));
    let recipients = json!(crate::heartbeat_actions::destination_list(
        body.get("recipients").unwrap_or(&json!([]))
    ));
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let created_by = body.get("created_by").and_then(|v| v.as_str()).unwrap_or("user");
    crate::entity_cleanup_task::validate_write(action, &config).map_err(AppError::BadRequest)?;

    // The write goes through the decision guard: directly, or as a proposal. The upsert itself
    // (including the next_run reset on schedule change) is `repo::heartbeat::upsert_task`.
    let spec = crate::task_guard::TaskSpec {
        id: id.clone(),
        name: name.to_string(),
        schedule: schedule.to_string(),
        action: action.to_string(),
        config,
        channels,
        recipients,
        enabled,
        created_by: created_by.to_string(),
    };
    let origin = crate::task_guard::resolve_origin(&state.db, &ctx).await;
    match crate::task_guard::write_task(&state.db, &origin, &spec, "create").await? {
        crate::task_guard::Written::Direct { authorised_by } => {
            let mut out = json!({"ok": true, "task_id": id});
            if authorised_by.is_some() {
                out["authorised_by"] = json!(authorised_by);
            }
            Ok(Json(out))
        }
        crate::task_guard::Written::Proposed { proposal_id, why } => Ok(Json(proposal_response(&id, proposal_id, &why))),
    }
}

/// The answer to a caller whose write became a proposal. General wording: what the task does in
/// the operator's terms, never its config.
fn proposal_response(task_id: &str, proposal_id: i32, why: &str) -> Value {
    json!({
        "ok": true,
        "proposal": true,
        "task_created": false,
        "task_id": task_id,
        "proposal_id": proposal_id,
        "status": "pending_approval",
        "message": crate::task_guard::proposal_message(why, proposal_id),
    })
}

/// High-level "create a recurring task" endpoint.
///
/// Designed for agent / chat use: takes natural-language ``name``, ``do``
/// (description of what the task should produce), and ``when`` (cron-like
/// schedule in plain English), and does the translation work the model
/// keeps getting wrong:
///
/// - ``when`` like "daily 8am" / "every Monday 9am" / "every 6 hours"
///   → cron expression
/// - ``do`` like "deep research report on AI agents" → action enum
///   + config block (``action=research_report``, ``config.topic=...``)
/// - id slug from name; defaults enabled=true, created_by=agent
///
/// Then **verifies** by re-SELECTing the row, sets the scheduler reload
/// flag, and returns the canonical row so the caller can confirm what
/// landed. This closes the "agent claimed success but no row exists"
/// gap that the lower-level ``heartbeat_create_task`` endpoint can't
/// catch because it has no opinion on whether the model called it.
async fn heartbeat_schedule_task(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
    let do_text = body
        .get("do")
        .or_else(|| body.get("what"))
        .or_else(|| body.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let when_text = body
        .get("when")
        .or_else(|| body.get("schedule"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if name.is_empty() {
        return Err(AppError::BadRequest("Missing required field: name".into()));
    }
    if do_text.is_empty() {
        return Err(AppError::BadRequest(
            "Missing required field: 'do' (what the task should produce)".into(),
        ));
    }
    if when_text.is_empty() {
        return Err(AppError::BadRequest(
            "Missing required field: 'when' (e.g. 'daily 8am' or '0 8 * * *')".into(),
        ));
    }

    let schedule = match parse_when_to_cron(when_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(AppError::BadRequest(format!(
                "Could not parse 'when'='{when_text}': {e}. Try 'daily 8am', \
                 'every Monday 9am', 'every 6 hours', or a 5-field cron."
            )));
        }
    };

    let (action, mut config) = classify_do_to_action(do_text);

    // Optional depth override for research-style actions.
    if matches!(action.as_str(), "research_report" | "research_and_send") {
        if let Some(depth) = body.get("depth").and_then(|v| v.as_str()) {
            config["depth"] = json!(depth);
        }
    }

    // Channel auto-injection: if caller passed an explicit channel, mirror
    // the inject_coordinator_context behavior so the report lands where the
    // user asked from.
    let mut channels_arr: Vec<Value> = Vec::new();
    if let Some(ch) = body.get("channel").and_then(|v| v.as_str()) {
        if !ch.is_empty() {
            channels_arr.push(json!(ch));
        }
    }
    let channels = json!(channels_arr);
    let recipients = json!(crate::heartbeat_actions::destination_list(
        body.get("recipients").unwrap_or(&json!([]))
    ));

    let id = slugify_for_id(name);
    let created_by = body
        .get("created_by")
        .and_then(|v| v.as_str())
        .unwrap_or("agent")
        .to_string();

    // Collision check: id is derived from the slug of `name`, so two
    // genuinely different tasks with similar names ("AI Research Review"
    // vs "AI Research review") map to the same id. A blind UPSERT would
    // silently overwrite the first task with the second. Same name =
    // intentional re-create (update), different name with same id =
    // probable accident → reject with guidance so the caller can pick a
    // more specific name or use the lower-level tool with an explicit id.
    let existing_name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM noo_heartbeat_tasks WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("db_collision_check_failed: {e}")))?;

    if let Some(existing) = existing_name.as_ref() {
        if existing != name {
            return Err(AppError::BadRequest(format!(
                "Task id '{id}' already exists with a different name \
                 ('{existing}'). Pick a more specific name so the slugified \
                 id is unique, or call noo_heartbeat_create_task with an \
                 explicit id to overwrite intentionally."
            )));
        }
        // Same name — caller is updating an existing task. Proceed.
    }

    // INSERT (or update if id already exists and name matches), through the decision guard: a
    // destructive task (`memory cleanup`, a retention job, ...) from an agent is a proposal.
    let spec = crate::task_guard::TaskSpec {
        id: id.clone(),
        name: name.to_string(),
        schedule: schedule.clone(),
        action: action.clone(),
        config: config.clone(),
        channels: channels.clone(),
        recipients: recipients.clone(),
        enabled: true,
        created_by: created_by.clone(),
    };
    let origin = crate::task_guard::resolve_origin(&state.db, &ctx).await;
    match crate::task_guard::write_task(&state.db, &origin, &spec, "schedule").await {
        Ok(crate::task_guard::Written::Direct { .. }) => {}
        Ok(crate::task_guard::Written::Proposed { proposal_id, why }) => {
            return Ok(Json(proposal_response(&id, proposal_id, &why)));
        }
        Err(e) => return Err(AppError::Internal(format!("db_insert_failed: {e}"))),
    }

    // Verify by re-SELECTing — this is the "claim success only if it
    // actually landed" guarantee the lower-level endpoint can't make.
    let row: Option<(String, String, String, String, bool, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT id, name, schedule, action, enabled, next_run \
             FROM noo_heartbeat_tasks WHERE id = $1",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("db_verify_failed: {e}")))?;

    let row = match row {
        Some(r) => r,
        None => {
            return Err(AppError::Internal(
                "Insert returned OK but row not found on verify — \
                 possible race or trigger rejection."
                    .into(),
            ))
        }
    };

    // Kick the scheduler so the new task fires on the next tick rather
    // than waiting up to 60s for the next poll.
    if let Some(redis) = state.redis.as_ref() {
        redis.set_string("noo:heartbeat:reload_pending", "1").await;
    }

    // Optional: also LAUNCH the task immediately (not just schedule it).
    // "Create" and "launch" are different intents:
    //   - Create only: register the task in the scheduler; it runs at
    //     the next cron tick. Default behavior.
    //   - Create + launch: also kick off a one-shot run right now (the
    //     scheduled future runs still happen on cron).
    // Users often want both ("set up daily research AND give me one
    // now") — the run_immediately flag handles that in one tool call
    // instead of forcing the agent to chain noo_schedule_task →
    // noo_heartbeat_run_task.
    let run_immediately = body
        .get("run_immediately")
        .or_else(|| body.get("launch_now"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut launched_run_id: Option<String> = None;
    if run_immediately {
        // Fire-and-forget — don't block the create response on a long
        // research run. The launched run writes its own noo_heartbeat_runs
        // row when done, queryable via noo_heartbeat_task_history.
        let state_clone = state.clone();
        let id_owned = id.clone();
        let immediate_run_id = uuid::Uuid::new_v4().to_string()[..12].to_string();
        launched_run_id = Some(immediate_run_id.clone());
        tokio::spawn(async move {
            if let Err(e) = crate::heartbeat_loop::execute_task(state_clone, &id_owned).await {
                tracing::warn!(
                    task_id = %id_owned,
                    error = %e,
                    "schedule_task_immediate_launch_failed"
                );
            }
        });
        tracing::info!(task_id = %id, run_id = %immediate_run_id, "schedule_task_launched_immediately");
    }

    Ok(Json(json!({
        "ok": true,
        "task_id": row.0,
        "name": row.1,
        "schedule": row.2,
        "action": row.3,
        "enabled": row.4,
        "next_run": row.5,
        "verified": true,
        "launched_immediately": run_immediately,
        "immediate_run_id": launched_run_id,
        "translation": {
            "when_input": when_text,
            "when_cron": schedule,
            "do_input": do_text,
            "classified_action": action,
        }
    })))
}

/// Convert a stable id slug from a human-readable task name. Lowercases,
/// strips non-alphanumerics, caps at 40 chars. The same name always maps
/// to the same id, so a re-create updates the existing row instead of
/// creating a duplicate.
fn slugify_for_id(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            // Every non-alphanumeric character folds to '_' — separators and
            // anything else alike. The two cases were spelled out separately
            // with identical bodies, which reads as if they differ.
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Collapse repeated underscores, trim leading/trailing.
    let mut out = String::with_capacity(cleaned.len());
    let mut last_underscore = true; // skip leading
    for c in cleaned.chars() {
        if c == '_' {
            if !last_underscore {
                out.push('_');
            }
            last_underscore = true;
        } else {
            out.push(c);
            last_underscore = false;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("task");
    }
    out.chars().take(40).collect()
}

/// Translate a natural-language schedule into a 5-field cron expression.
///
/// Handles the common phrases the agent will produce. If the input
/// already looks like a 5-field cron (5 whitespace-separated tokens),
/// pass it through unchanged. Falls back to error so the caller can
/// retry with a clearer phrase — silently picking "daily 8am" because
/// we didn't recognize the input would hide bugs.
fn parse_when_to_cron(when: &str) -> Result<String, String> {
    let w = when.trim().to_lowercase();

    // Pass-through: already a 5-field cron expression.
    let tokens: Vec<&str> = w.split_whitespace().collect();
    if tokens.len() == 5 {
        return Ok(w);
    }

    // Common phrases.
    match w.as_str() {
        "daily" | "every day" => return Ok("0 8 * * *".into()),
        "weekly" | "every week" => return Ok("0 9 * * 1".into()),
        "monthly" | "every month" => return Ok("0 9 1 * *".into()),
        "hourly" | "every hour" => return Ok("0 * * * *".into()),
        _ => {}
    }

    // "every N hours" / "every N minutes" / "every N days"
    if let Some(rest) = w.strip_prefix("every ") {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(n) = parts[0].parse::<u32>() {
                match parts[1] {
                    "minute" | "minutes" | "min" | "mins" => {
                        if (1..=59).contains(&n) {
                            return Ok(format!("*/{n} * * * *"));
                        }
                    }
                    "hour" | "hours" | "hr" | "hrs" => {
                        if (1..=23).contains(&n) {
                            return Ok(format!("0 */{n} * * *"));
                        }
                    }
                    "day" | "days"
                        if (1..=30).contains(&n) => {
                            return Ok(format!("0 9 */{n} * *"));
                        }
                    _ => {}
                }
            }
        }
        // "every Monday" / "every Mon at 9" / "every Friday 5pm"
        if let Some(dow) = parse_dow(parts[0]) {
            let (hour, min) = extract_time(&parts[1..]).unwrap_or((9, 0));
            return Ok(format!("{min} {hour} * * {dow}"));
        }
    }

    // "daily at HH" / "daily 8am" / "daily 17:30"
    if w.starts_with("daily") || w.starts_with("every day") {
        let rest = w.trim_start_matches("daily").trim_start_matches("every day").trim();
        let rest_tokens: Vec<&str> = rest.split_whitespace().collect();
        if let Some((hour, min)) = extract_time(&rest_tokens) {
            return Ok(format!("{min} {hour} * * *"));
        }
    }

    Err(format!(
        "unrecognized schedule phrase '{when}' — use 'daily 8am', \
         'every Monday 9am', 'every 6 hours', or a 5-field cron"
    ))
}

fn parse_dow(s: &str) -> Option<u8> {
    match s.to_lowercase().trim_end_matches('s').trim_end_matches(',') {
        "mon" | "monday" => Some(1),
        "tue" | "tues" | "tuesday" => Some(2),
        "wed" | "wednesday" => Some(3),
        "thu" | "thurs" | "thursday" => Some(4),
        "fri" | "friday" => Some(5),
        "sat" | "saturday" => Some(6),
        "sun" | "sunday" => Some(0),
        _ => None,
    }
}

/// Best-effort time extraction from tokens like ["at", "8am"], ["9"],
/// ["17:30"], ["8:00", "am"], ["5pm"]. Returns (hour 0-23, minute 0-59).
fn extract_time(tokens: &[&str]) -> Option<(u32, u32)> {
    // Concatenate, drop "at", look for HH[:MM] [am|pm] patterns.
    let joined: String = tokens
        .iter()
        .filter(|t| **t != "at")
        .copied()
        .collect::<Vec<_>>()
        .join("");
    let mut s = joined.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }

    let (is_pm, is_am) = (s.ends_with("pm"), s.ends_with("am"));
    if is_pm || is_am {
        s.truncate(s.len() - 2);
    }

    let (hh_str, mm_str) = if let Some(idx) = s.find(':') {
        (&s[..idx], &s[idx + 1..])
    } else {
        (s.as_str(), "0")
    };

    let mut hour: u32 = hh_str.parse().ok()?;
    let minute: u32 = mm_str.parse().ok()?;

    if is_pm && hour < 12 {
        hour += 12;
    } else if is_am && hour == 12 {
        hour = 0;
    }
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute))
}

/// Map a natural-language "what should this task do" string to an
/// (action, config) tuple. Keyword-based; defaults to ``custom_prompt``
/// with the raw text as the prompt body when nothing else matches —
/// always returns *something* so the model doesn't have to retry.
fn classify_do_to_action(do_text: &str) -> (String, Value) {
    let lower = do_text.to_lowercase();

    // research-style — most common heartbeat use case.
    if lower.contains("research")
        || lower.contains("report on")
        || lower.contains("brief on")
        || lower.contains("dig into")
    {
        // Extract topic by stripping the leading verb phrase if present.
        let topic = lower
            .trim_start_matches("research report on ")
            .trim_start_matches("research report about ")
            .trim_start_matches("research on ")
            .trim_start_matches("research ")
            .trim_start_matches("report on ")
            .trim_start_matches("brief on ")
            .trim_start_matches("dig into ")
            .trim()
            .to_string();
        let topic = if topic.is_empty() { do_text.to_string() } else { topic };
        return (
            "research_and_send".into(),
            json!({"topic": topic, "depth": "standard"}),
        );
    }

    // Specific named system actions.
    if lower.contains("cluster health") || lower.contains("node status") {
        return ("cluster_health".into(), json!({}));
    }
    if lower.contains("daily briefing") || lower.contains("daily summary") {
        return ("daily_briefing".into(), json!({}));
    }
    if lower.contains("cost report") || lower.contains("token usage") || lower.contains("inference cost") {
        return ("cost_report".into(), json!({}));
    }
    if lower.contains("security audit") || lower.contains("auth failures") {
        return ("security_audit".into(), json!({}));
    }
    if lower.contains("memory cleanup") || lower.contains("prune conversations") {
        return ("memory_cleanup".into(), json!({}));
    }
    if lower.contains("self check")
        || lower.contains("self-check")
        || lower.contains("agent digest")
        || lower.contains("meta loop")
        || lower.contains("daily digest")
    {
        return ("agent_self_check".into(), json!({}));
    }

    // Default: treat as a custom prompt the LLM will execute literally.
    (
        "custom_prompt".into(),
        json!({"prompt": do_text}),
    )
}

/// GET /api/heartbeat/review-existing — the existing tasks (full config) and saved recipients that no
/// person has approved: an agent-turn, destructive or delivering task with no `authorised_by`, and a
/// saved recipient with no `created_by`. Until reviewed, the tasks run read-only and their targets
/// are not registered.
async fn heartbeat_review_list(State(state): State<Arc<AppState>>) -> AppResult {
    let (tasks, recipients) = crate::task_guard::pending_review(&state.db).await?;
    Ok(Json(json!({"tasks": tasks, "recipients": recipients, "count": tasks.len() + recipients.len()})))
}

/// POST /api/heartbeat/review-existing/approve — body `{tasks: [id], recipients: [id]}`. A person
/// only (no harness claim, no `act`, an enabled account): each task is recorded as authorised by
/// them and each recipient as created by them. A task that needs a higher role than theirs is
/// skipped and named.
async fn heartbeat_review_approve(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let origin = crate::task_guard::resolve_origin(&state.db, &ctx).await;
    if !matches!(origin, crate::task_guard::Origin::Person { .. }) {
        return Err(AppError::Forbidden(
            "reviewing existing tasks is a person's decision: run `noo heartbeat review-existing` yourself".into(),
        ));
    }
    let ids = |k: &str| -> Vec<String> {
        body.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    let (tasks, recipients, skipped) = crate::task_guard::approve_review(&state.db, &origin, &ids("tasks"), &ids("recipients")).await?;
    Ok(Json(json!({"ok": true, "tasks_approved": tasks, "recipients_approved": recipients, "skipped": skipped})))
}

/// Toggle a heartbeat task enabled/disabled.
/// PUT /api/heartbeat/tasks/{task_id}/toggle
///
/// The body is OPTIONAL: `{"enabled": <bool>}` sets the state, and no body at
/// all flips it. The flip branch below always existed but was unreachable —
/// the extractor was a bare `Json<Value>`, which axum rejects with 415
/// Unsupported Media Type when a request carries no JSON content type. So a
/// caller that relied on the documented flip got 415, and only a caller that
/// sent an explicit value ever worked.
///
/// That is exactly how the two dashboards diverged: `ui/src/static` sends
/// `{"enabled": …}` and works, `ui/apps/web` sends no body and always failed.
/// Found live 2026-09-20 from the console.
async fn heartbeat_toggle_task(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(task_id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult {
    let enabled = body
        .as_ref()
        .and_then(|Json(b)| b.get("enabled"))
        .and_then(|v| v.as_bool());

    // If no explicit value, flip the current state
    let new_enabled = if let Some(e) = enabled {
        e
    } else {
        let current = sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM noo_heartbeat_tasks WHERE id = $1"
        )
        .bind(&task_id)
        .fetch_optional(&state.db)
        .await?;

        match current {
            Some(e) => !e,
            None => return Err(AppError::NotFound(format!("Task not found: {task_id}"))),
        }
    };

    // Switching a task OFF is always safe. Switching a destructive one ON is a proposal unless a
    // person does it.
    let origin = crate::task_guard::resolve_origin(&state.db, &ctx).await;
    match crate::task_guard::set_enabled(&state.db, &origin, &task_id, new_enabled).await? {
        Some(crate::task_guard::Written::Direct { .. }) => {
            Ok(Json(json!({"ok": true, "task_id": task_id, "enabled": new_enabled})))
        }
        Some(crate::task_guard::Written::Proposed { proposal_id, why }) => {
            Ok(Json(proposal_response(&task_id, proposal_id, &why)))
        }
        None => Err(AppError::NotFound(format!("Task not found: {task_id}"))),
    }
}

/// Change ONLY a task's schedule.
/// PUT /api/heartbeat/tasks/{task_id}/schedule  body `{"schedule": "<cron>"}`
///
/// The cron is checked with the parser the scheduler fires from
/// (`heartbeat_actions::parse_cron`), so a schedule this accepts is one the
/// scheduler can run, and a refusal carries the parser's reason. The write is
/// `task_guard::set_schedule`: the `schedule` column and `updated_at` only, and
/// `next_run` is cleared only if the schedule actually changed.
async fn heartbeat_set_schedule(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(task_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let schedule = body.get("schedule").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if schedule.is_empty() {
        return Err(AppError::BadRequest("Required field: schedule (a cron expression)".into()));
    }
    crate::heartbeat_actions::parse_cron(schedule)
        .map_err(|e| AppError::BadRequest(format!("Invalid cron schedule {schedule:?}: {e}")))?;
    let origin = crate::task_guard::resolve_origin(&state.db, &ctx).await;
    let Some(change) = crate::task_guard::set_schedule(&state.db, &origin, &task_id, schedule).await? else {
        return Err(AppError::NotFound(format!("Task not found: {task_id}")));
    };
    match change.written {
        crate::task_guard::Written::Direct { .. } => Ok(Json(json!({
            "ok": true,
            "task_id": task_id,
            "old_schedule": change.old_schedule,
            "schedule": schedule,
            "changed": change.old_schedule != schedule,
            "next_run": change.next_run.map(|t| t.to_rfc3339()),
        }))),
        crate::task_guard::Written::Proposed { proposal_id, why } => {
            let mut out = proposal_response(&task_id, proposal_id, &why);
            out["old_schedule"] = json!(change.old_schedule);
            out["schedule"] = json!(schedule);
            Ok(Json(out))
        }
    }
}

/// Delete a heartbeat task.
async fn heartbeat_delete_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> AppResult {
    let rows = crate::repo::heartbeat::delete_task(&state.db, &task_id).await?;

    if rows > 0 {
        Ok(Json(json!({"ok": true, "task_id": task_id})))
    } else {
        Err(AppError::NotFound(format!("Task not found: {task_id}")))
    }
}

#[derive(Deserialize)]
struct HistoryParams {
    limit: Option<i64>,
    offset: Option<i64>,
    task_id: Option<String>,
    status: Option<String>,
}

/// Get heartbeat run history with pagination and filters.
async fn heartbeat_history(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryParams>,
) -> AppResult {
    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);

    let runs = sqlx::query_as::<_, (String, String, String, String, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, String, Option<String>, Option<String>, i32, Value, Value)>(
        "SELECT run_id, task_id, task_name, action, started_at, completed_at, \
                status, result_text, error, COALESCE(duration_ms, 0), \
                COALESCE(notified_channels, '[]'::jsonb), \
                COALESCE(artifacts, '[]'::jsonb) \
         FROM noo_heartbeat_runs \
         WHERE ($1::text IS NULL OR task_id = $1) \
           AND ($2::text IS NULL OR status = $2) \
         ORDER BY started_at DESC \
         LIMIT $3 OFFSET $4"
    )
    .bind(&params.task_id)
    .bind(&params.status)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total = Measured::from_result_in(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM noo_heartbeat_runs \
             WHERE ($1::text IS NULL OR task_id = $1) \
               AND ($2::text IS NULL OR status = $2)"
        )
        .bind(&params.task_id)
        .bind(&params.status)
        .fetch_one(&state.db)
        .await,
        "cannot count noo_heartbeat_runs",
    );

    let runs: Vec<Value> = runs.iter().map(|(run_id, task_id, task_name, action, started_at, completed_at, status, result_text, error, duration_ms, channels, artifacts)| {
        json!({
            "run_id": run_id,
            "task_id": task_id,
            "task_name": task_name,
            "action": action,
            "started_at": started_at,
            "completed_at": completed_at,
            "status": status,
            "result_text": result_text,
            "error": error,
            "duration_ms": duration_ms,
            "notified_channels": channels,
            "artifacts": artifacts,
        })
    }).collect();
    let mut body = json!({"runs": runs, "offset": offset, "limit": limit});
    put_into(&mut body, "total", total);
    Ok(Json(body))
}

/// List available heartbeat actions with descriptions and config schemas.
async fn heartbeat_actions() -> AppJson {
    let actions = vec![
        // The five below were dispatchable but unlisted, which is not a
        // cosmetic gap: this catalog is what the API, the dashboard and the
        // CLI enumerate, so an action missing from it cannot be discovered
        // or scheduled by anyone who does not already know its name.
        //
        // `agent_self_check` is the one that cost something. It is the ONLY
        // thing that dispatches to the evolve add-on, so with it unlistable
        // the add-on ran enabled, healthy and completely idle — zero
        // requests since boot. `database_backup` and
        // `agent_messages_retention` are scheduled on this install already,
        // which is the proof the omission was an oversight rather than a
        // policy: they work fine, they were just never written down here.
        json!({"name": "agent_self_check", "description": "Scan for failing tasks, repeat offenders and security spikes (drives the evolve meta-loop)", "config_schema": {"fields": [
            {"name": "lookback_hours", "type": "number", "label": "Lookback window (hours)", "default": 24},
            {"name": "stuck_threshold_minutes", "type": "number", "label": "Stuck cycle threshold (minutes)", "default": 30},
            {"name": "security_spike_threshold", "type": "number", "label": "Security events before a spike is reported", "default": 10},
            {"name": "repeat_offender_days", "type": "number", "label": "Repeat-offender window (days)", "default": 7},
        ]}}),
        json!({"name": "database_backup", "description": "Dump the database through the host spool", "config_schema": {"fields": []}}),
        json!({"name": "heartbeat_retention", "description": "Prune old heartbeat run records", "config_schema": {"fields": [
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report, don't delete)", "default": true},
        ]}}),
        json!({"name": "agent_messages_retention", "description": "Archive (sealed), then prune, old agent-to-agent messages", "config_schema": {"fields": [
            {"name": "days", "type": "number", "label": "Keep messages newer than (days)", "default": 90},
            {"name": "archive_dir", "type": "string", "label": "Archive directory", "default": "/data/audit-archive"},
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report, don't delete)", "default": true},
        ]}}),
        json!({"name": "usage_rollup", "description": "Roll raw token-usage rows into monthly totals", "config_schema": {"fields": [
            {"name": "months_raw", "type": "number", "label": "Months of raw rows to keep", "default": 3},
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report, don't roll up)", "default": true},
        ]}}),
        json!({"name": "backup_knowledge", "description": "Export knowledge base to file", "config_schema": {"fields": [
            {"name": "output_dir", "type": "string", "label": "Output directory", "default": "/data/backups"},
            {"name": "include_graph", "type": "boolean", "label": "Include graph", "default": true},
            {"name": "include_conversations", "type": "boolean", "label": "Include conversations", "default": false},
            {"name": "retention_days", "type": "number", "label": "Keep snapshots newer than (days, 1-90)", "default": 30},
        ]}}),
        json!({"name": "cert_auto_rotate", "description": "Auto-rotate expiring TLS certificates", "config_schema": {"fields": [
            {"name": "warn_days", "type": "number", "label": "Warn if expiring within (days)", "default": 30},
            {"name": "new_cert_days", "type": "number", "label": "New cert validity (days)", "default": 90},
            {"name": "pki_dir", "type": "string", "label": "PKI directory"},
        ]}}),
        json!({"name": "cert_rotation_check", "description": "Check for expiring certificates", "config_schema": {"fields": [
            {"name": "warn_days", "type": "number", "label": "Warn if expiring within (days)", "default": 30},
            {"name": "pki_dir", "type": "string", "label": "PKI directory", "placeholder": "Leave empty to use NOO_PKI_DIR env var"},
        ]}}),
        json!({"name": "channel_keepalive", "description": "Send keepalive to registered channels", "config_schema": {"fields": [
            {"name": "channels", "type": "string_list", "label": "Channels to check"},
            {"name": "send_test", "type": "boolean", "label": "Send test message", "default": false},
        ]}}),
        json!({"name": "channel_message", "description": "Send a message to a channel", "config_schema": {"fields": [
            {"name": "channel", "type": "select", "label": "Channel", "required": true, "options": [
                {"value": "google_chat", "label": "Google Chat"},
                {"value": "telegram", "label": "Telegram"},
                {"value": "whatsapp", "label": "WhatsApp"},
            ]},
            {"name": "recipient", "type": "channel_recipient", "label": "Recipient", "required": true, "linked_channel_field": "channel"},
            {"name": "prompt", "type": "text", "label": "Prompt (generates message via AI)"},
            {"name": "message", "type": "text", "label": "Static message (overrides prompt)"},
        ]}}),
        json!({"name": "chat_digest", "description": "Generate digest of recent conversations", "config_schema": {"fields": [
            {"name": "channel", "type": "select", "label": "Channel", "default": "google_chat", "options": [
                {"value": "google_chat", "label": "Google Chat"},
            ]},
            {"name": "recipient", "type": "string", "label": "Space ID", "required": true, "placeholder": "spaces/AAAA..."},
            {"name": "limit", "type": "number", "label": "Max messages", "default": 100},
            {"name": "since", "type": "string", "label": "Since (ISO timestamp)", "placeholder": "2026-03-01T00:00:00Z (optional)"},
            {"name": "prompt", "type": "text", "label": "Custom digest prompt", "placeholder": "Leave empty for default: identify key topics, ideas, action items..."},
        ]}}),
        json!({"name": "cluster_health", "description": "Report cluster node health status", "config_schema": {"fields": [
            {"name": "alert_on_offline", "type": "boolean", "label": "Alert on offline nodes", "default": true},
        ]}}),
        json!({"name": "conversation_summarize", "description": "Summarize recent conversations", "config_schema": {"fields": [
            {"name": "min_age_days", "type": "number", "label": "Min age (days)", "default": 30},
            {"name": "min_messages", "type": "number", "label": "Min messages", "default": 5},
            {"name": "max_conversations", "type": "number", "label": "Max conversations", "default": 10},
        ]}}),
        json!({"name": "cost_report", "description": "Generate inference cost report", "config_schema": {"fields": [
            {"name": "period_days", "type": "number", "label": "Period (days)", "default": 7},
            {"name": "gpu_cost_per_hour", "type": "number", "label": "GPU cost/hour ($)", "default": 0.0},
        ]}}),
        json!({"name": "custom_prompt", "description": "Run arbitrary prompt through coordinator", "config_schema": {"fields": [
            {"name": "prompt", "type": "text", "label": "Prompt", "required": true, "placeholder": "Enter a prompt for the coordinator..."},
            {"name": "tools_enabled", "type": "boolean", "label": "Enable tools", "default": true},
        ]}}),
        json!({"name": "daily_briefing", "description": "Daily cluster + knowledge summary", "config_schema": {"fields": []}}),
        json!({"name": "disk_cleanup", "description": "Clean up temporary files and old data", "config_schema": {"fields": [
            {"name": "targets", "type": "multiselect", "label": "Cleanup targets", "options": [
                {"value": "tmp_noo_files", "label": "Temp PAI files"},
                {"value": "heartbeat_run_records", "label": "Old run records"},
                {"value": "docker_dangling_images", "label": "Docker dangling images"},
                {"value": "container_logs", "label": "Container logs"},
            ]},
        ]}}),
        json!({"name": "goal_review", "description": "Review and track progress on goals", "config_schema": {"fields": [
            {"name": "goals", "type": "json", "label": "Goals (JSON array)", "placeholder": "[{\"name\": \"...\", \"description\": \"...\", \"target_date\": \"...\", \"status\": \"...\"}]"},
            {"name": "review_prompt", "type": "text", "label": "Review prompt"},
        ]}}),
        json!({"name": "graph_clustering", "description": "Run graph clustering algorithm", "config_schema": {"fields": [
            {"name": "min_cluster_size", "type": "number", "label": "Min cluster size", "default": 3},
            {"name": "resolution", "type": "number", "label": "Resolution", "default": 1.0},
        ]}}),
        json!({"name": "entity_cleanup", "description": "Junk-entity cleanup (a, x_t, 0.003): stage-then-delete, 30d restorable. A preview unless a person set apply; an apply task an agent asks for waits for a person's approval", "config_schema": {"fields": [
            {"name": "apply", "type": "boolean", "label": "Apply (stage and delete); off = preview only", "default": false},
            {"name": "max_delete", "type": "number", "label": "Max entities removed per run (cap 5000)", "default": 1000},
            {"name": "examples", "type": "number", "label": "Example entities written to the gateway log (0-200)", "default": 0},
        ]}}),
        json!({"name": "graph_prune", "description": "Graph hygiene: stage-then-delete orphans, junk names, duplicate merges (30d restorable)", "config_schema": {"fields": [
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report, don't stage/delete)", "default": true},
            {"name": "remove_orphans", "type": "boolean", "label": "Remove orphans (no edges, no mentions)", "default": true},
            {"name": "orphan_min_age_days", "type": "number", "label": "Orphan min age (days)", "default": 7},
            {"name": "remove_junk", "type": "boolean", "label": "Remove junk names (too short / no letters; ignores entity type, so it also removes model numbers like 3090; prefer the entity_cleanup task)", "default": crate::graph_prune::REMOVE_JUNK_DEFAULT},
            {"name": "min_name_length", "type": "number", "label": "Min name length (shorter = junk)", "default": 2},
            {"name": "merge_duplicates", "type": "boolean", "label": "Merge near-duplicate names", "default": true},
            {"name": "similarity_threshold", "type": "number", "label": "Duplicate similarity threshold", "default": 0.85},
            {"name": "max_entities", "type": "number", "label": "Duplicate-scan sample size", "default": 200},
            {"name": "max_delete", "type": "number", "label": "Max removals per run", "default": 500},
            {"name": "staging_retention_days", "type": "number", "label": "Staging retention before permanent purge (days)", "default": 30},
            {"name": "dedup_edges", "type": "boolean", "label": "Collapse exact duplicate edges", "default": true},
            {"name": "prune_edges", "type": "boolean", "label": "Snip weak old edges (entity-preserving)", "default": true},
            {"name": "edge_confidence_floor", "type": "number", "label": "Edge confidence floor (snip classified edges below)", "default": 0.15},
            {"name": "edge_min_age_days", "type": "number", "label": "Edge min age before snip (days — reinforcement window)", "default": 14}
        ]}}),
        json!({"name": "graph_signals", "description": "Detect signals in knowledge graph", "config_schema": {"fields": []}}),
        json!({"name": "idle_scaledown", "description": "Stop idle inference backends", "config_schema": {"fields": [
            {"name": "idle_threshold_sec", "type": "number", "label": "Idle threshold (seconds)", "default": 600},
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report what would be stopped)", "default": true},
        ]}}),
        json!({"name": "audit_log_rotate", "description": "Archive expired security-audit months to JSONL, then drop them (signed checkpoint first)", "config_schema": {"fields": [
            {"name": "retention_months", "type": "number", "label": "Keep this many months", "default": 12},
            {"name": "archive_dir", "type": "string", "label": "Archive directory", "default": "/data/audit-archive"},
            {"name": "dry_run", "type": "boolean", "label": "Dry run only (report what would be dropped)", "default": true},
        ]}}),
        json!({"name": "knowledge_refresh", "description": "Refresh knowledge base from sources", "config_schema": {"fields": [
            {"name": "max_docs", "type": "number", "label": "Max docs to check", "default": 20},
            {"name": "timeout_per_doc", "type": "number", "label": "Timeout per doc (sec)", "default": 10},
        ]}}),
        json!({"name": "memory_cleanup", "description": "Prune old conversations", "config_schema": {"fields": [
            {"name": "max_age_days", "type": "number", "label": "Max age (days)", "default": 90, "required": true},
        ]}}),
        json!({"name": "memory_relevance_audit", "description": "Audit memory retrieval relevance", "config_schema": {"fields": [
            {"name": "test_queries", "type": "string_list", "label": "Test queries (one per line)"},
            {"name": "min_expected_score", "type": "number", "label": "Min expected score", "default": 0.3},
        ]}}),
        json!({"name": "model_cache_warm", "description": "Pre-cache frequently used models", "config_schema": {"fields": [
            {"name": "models", "type": "json", "label": "Models (JSON array)", "placeholder": "[{\"model\": \"...\", \"node_id\": \"...\", \"backend\": \"ollama\"}]"},
        ]}}),
        json!({"name": "news_scan", "description": "Scan news sources for relevant updates", "config_schema": {"fields": [
            {"name": "feeds", "type": "string_list", "label": "Feed URLs (one per line)", "required": true, "placeholder": "https://example.com/feed.xml"},
            {"name": "keywords", "type": "string_list", "label": "Keywords (one per line)"},
            {"name": "max_entries", "type": "number", "label": "Max entries", "default": 10},
            {"name": "ingest", "type": "boolean", "label": "Ingest into KB", "default": false},
        ]}}),
        json!({"name": "pipeline", "description": "Run a multi-step pipeline", "config_schema": {"fields": [
            {"name": "steps", "type": "json", "label": "Pipeline steps (JSON)", "required": true, "placeholder": "[{\"action\": \"...\", \"name\": \"step1\", \"config\": {}, \"condition\": \"...\", \"on_error\": \"stop\"}]"},
        ]}}),
        json!({"name": "rag_reindex", "description": "Check the document embedding backlog is draining", "config_schema": {"fields": []}}),
        json!({"name": "research_and_send", "description": "Research topic and send to channel", "config_schema": {"fields": [
            {"name": "topic", "type": "string", "label": "Topic", "required": true},
            {"name": "depth", "type": "select", "label": "Depth", "default": "standard", "options": [
                {"value": "brief", "label": "Brief (~700 words, 2 searches)"},
                {"value": "standard", "label": "Standard (~1500 words, 3 searches)"},
                {"value": "deep", "label": "Deep (~3000 words, 4 searches, 4-6 subsections)"},
                {"value": "exhaustive", "label": "Exhaustive (5000+ words, 6 searches, white-paper)"},
            ]},
            {"name": "channel", "type": "select", "label": "Channel", "required": true, "options": [
                {"value": "google_chat", "label": "Google Chat"},
                {"value": "telegram", "label": "Telegram"},
                {"value": "whatsapp", "label": "WhatsApp"},
            ]},
            {"name": "recipient", "type": "channel_recipient", "label": "Recipient", "required": true, "linked_channel_field": "channel"},
            {"name": "instructions", "type": "text", "label": "Additional instructions"},
            {"name": "save_to_file", "type": "boolean", "label": "Force file attachment (always on for *report actions)", "default": true},
            {"name": "drive_folder_id", "type": "string", "label": "Drive folder ID (override; defaults to NOO_REPORTS_DRIVE_FOLDER_ID env)", "placeholder": "leave blank to use default"},
        ]}}),
        json!({"name": "research_report", "description": "Generate a research report", "config_schema": {"fields": [
            {"name": "topic", "type": "string", "label": "Topic", "required": true, "placeholder": "AI developments this week"},
            {"name": "depth", "type": "select", "label": "Depth", "default": "standard", "options": [
                {"value": "brief", "label": "Brief (~700 words, 2 searches)"},
                {"value": "standard", "label": "Standard (~1500 words, 3 searches)"},
                {"value": "deep", "label": "Deep (~3000 words, 4 searches, 4-6 subsections)"},
                {"value": "exhaustive", "label": "Exhaustive (5000+ words, 6 searches, white-paper)"},
            ]},
            {"name": "instructions", "type": "text", "label": "Additional instructions"},
            {"name": "save_to_file", "type": "boolean", "label": "Force file attachment (always on for *report actions)", "default": true},
            {"name": "drive_folder_id", "type": "string", "label": "Drive folder ID (override; defaults to NOO_REPORTS_DRIVE_FOLDER_ID env)", "placeholder": "leave blank to use default"},
        ]}}),
        json!({"name": "security_audit", "description": "Run security violation scan", "config_schema": {"fields": [
            {"name": "period_hours", "type": "number", "label": "Period (hours)", "default": 24},
            {"name": "alert_threshold", "type": "number", "label": "Alert threshold", "default": 5},
        ]}}),
        json!({"name": "self_benchmark", "description": "Benchmark inference performance", "config_schema": {"fields": [
            {"name": "test_prompts", "type": "json", "label": "Test prompts (JSON array)"},
            {"name": "timeout", "type": "number", "label": "Timeout (seconds)", "default": 30},
        ]}}),
        json!({"name": "thought_experiment", "description": "Run a thought experiment prompt", "config_schema": {"fields": [
            {"name": "num_queries", "type": "number", "label": "Synthetic queries per run", "default": 5},
            {"name": "min_entities", "type": "number", "label": "Min entities needed to run", "default": 3},
            {"name": "intent_types", "type": "string_list", "label": "Intent types to practice (blank = all)", "placeholder": "causal, definitional, procedural, comparative, exploratory"},
            {"name": "pair_revisit_days", "type": "number", "label": "Days before re-rehearsing an entity pair (0 = allow repeats)", "default": 7},
        ]}}),
        json!({"name": "write_log", "description": "Write a log entry", "config_schema": {"fields": [
            {"name": "sections", "type": "multiselect", "label": "Sections", "options": [
                {"value": "cluster", "label": "Cluster"},
                {"value": "rag", "label": "RAG"},
                {"value": "jobs", "label": "Jobs"},
                {"value": "memory", "label": "Memory"},
                {"value": "errors", "label": "Errors"},
                {"value": "backends", "label": "Backends"},
            ]},
            {"name": "filename", "type": "string", "label": "Filename template", "default": "heartbeat-{date}.md"},
        ]}}),
    ];
    let count = actions.len();
    Json(json!({
        "actions": actions,
        "count": count,
    }))
}

// ═══════════════════════════════════════════════════════════════
// Heartbeat status — native SQL (replaces NATS delegation)
// ═══════════════════════════════════════════════════════════════

/// GET /api/heartbeat/status — scheduler status with task summaries.
///
/// Returns task count, per-task next_run/last_run/enabled, and aggregate
/// run statistics. `running` reflects the actual scheduler loop tick from
/// loop_health when available (falls back to the legacy inference from
/// future next_run rows before the loop's first tick after boot).
pub(super) async fn heartbeat_status(State(state): State<Arc<AppState>>) -> AppResult {
    // Fetch all tasks (lightweight — same query the tasks list uses).
    let tasks = sqlx::query_as::<_, (
        String, String, String, String,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT id, name, schedule, action, enabled, last_run, next_run \
         FROM noo_heartbeat_tasks \
         ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let task_count = tasks.len();
    let enabled_count = tasks.iter().filter(|t| t.4).count();
    let now = chrono::Utc::now();
    let has_future_runs = tasks.iter().any(|t| t.4 && t.6.is_some_and(|nr| nr > now));

    let task_summaries: Vec<Value> = tasks.iter().map(|(id, name, schedule, action, enabled, last_run, next_run)| {
        json!({
            "id": id,
            "name": name,
            "schedule": schedule,
            "action": action,
            "enabled": enabled,
            "last_run": last_run,
            "next_run": next_run,
        })
    }).collect();

    // Count recent runs (last 24h) for a quick pulse.
    let recent_runs = Measured::from_result_in(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM noo_heartbeat_runs \
             WHERE started_at > NOW() - INTERVAL '24 hours'"
        )
        .fetch_one(&state.db)
        .await,
        "cannot read noo_heartbeat_runs",
    );
    let any_recent_runs = recent_runs.value.is_some_and(|n| n > 0);

    // Real loop liveness — present once the scheduler loop has ticked.
    let hb_snapshot = crate::loop_health::snapshot();
    let hb_loop = hb_snapshot.iter().find(|l| l.name == "heartbeat_scheduler");
    let (hb_running, hb_running_detail) =
        crate::loop_health::describe("heartbeat_scheduler", hb_loop);

    // Only the loop registry knows whether the scheduler is running; absent a
    // tick record the answer is unknown (null), not "running".
    //
    // Cron parsing happens in the Python worker_pool subprocess, which this
    // process cannot introspect. What IS observable is whether it demonstrably
    // worked: a task with a future `next_run` was scheduled by a working
    // croniter. Report that evidence, and null when there is none.
    let mut body = json!({
        "loop_last_tick_age_secs": hb_loop.map(|l| l.age_secs),
        "enabled": enabled_count > 0,
        "task_count": task_count,
        "enabled_count": enabled_count,
        "tasks": task_summaries,
        "scheduler_initialized": has_future_runs || any_recent_runs,
        "waiting_review": crate::task_guard::review_count(&state.db).await,
    });
    put_into(&mut body, "running", Measured::noted(hb_running, hb_running_detail));
    put_into(&mut body, "recent_runs_24h", recent_runs);
    put_into(&mut body, "croniter_available", Measured::noted(
        if has_future_runs { Some(true) } else { None },
        if has_future_runs {
            "at least one task has a computed next_run, so cron parsing works"
        } else {
            "unknown — cron parsing runs in the Python worker pool and no task \
             currently has a computed next_run to prove it works"
        },
    ));
    Ok(Json(body))
}

/// GET /api/agent/loops — liveness of every always-on background loop
/// (heartbeat scheduler, autonomy engine, ingest, recall archive, DLQ
/// drain, session eviction, the monitor itself). A loop is `stale` when
/// it hasn't ticked within 3× its interval — the same condition that
/// triggers an operator alert from loop_health::spawn_monitor.
async fn agent_loops() -> AppResult {
    let loops = crate::loop_health::snapshot();
    let any_stale = loops.iter().any(|l| l.stale);
    Ok(Json(json!({
        "loops": loops,
        "any_stale": any_stale,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Heartbeat task artifacts — native SQL (replaces NATS delegation)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ArtifactParams {
    limit: Option<i64>,
    status: Option<String>,
}

/// GET /api/heartbeat/tasks/{task_id}/artifacts — artifacts from runs of a specific task.
///
/// Returns runs that have non-empty artifacts arrays, newest first.
async fn heartbeat_task_artifacts(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
    Query(params): Query<ArtifactParams>,
) -> AppResult {
    let limit = params.limit.unwrap_or(50).min(200);

    // Verify the task exists.
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM noo_heartbeat_tasks WHERE id = $1)"
    )
    .bind(&task_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !exists {
        return Err(AppError::NotFound(format!("Task not found: {task_id}")));
    }

    let runs = sqlx::query_as::<_, (
        String,                                // run_id
        String,                                // task_name
        String,                                // action
        chrono::DateTime<chrono::Utc>,         // started_at
        Option<chrono::DateTime<chrono::Utc>>, // completed_at
        String,                                // status
        Option<String>,                        // result_text
        i32,                                   // duration_ms
        Value,                                 // artifacts
    )>(
        "SELECT run_id, task_name, action, started_at, completed_at, \
                status, result_text, COALESCE(duration_ms, 0), \
                COALESCE(artifacts, '[]'::jsonb) \
         FROM noo_heartbeat_runs \
         WHERE task_id = $1 \
           AND ($2::text IS NULL OR status = $2) \
           AND artifacts IS NOT NULL AND artifacts != '[]'::jsonb \
         ORDER BY started_at DESC \
         LIMIT $3"
    )
    .bind(&task_id)
    .bind(&params.status)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let artifacts: Vec<Value> = runs.iter().map(|(
        run_id, task_name, action, started_at, completed_at,
        status, result_text, duration_ms, artifacts_val,
    )| {
        json!({
            "run_id": run_id,
            "task_id": task_id,
            "task_name": task_name,
            "action": action,
            "started_at": started_at,
            "completed_at": completed_at,
            "status": status,
            "result_text": result_text,
            "duration_ms": duration_ms,
            "artifacts": artifacts_val,
        })
    }).collect();

    Ok(Json(json!({
        "task_id": task_id,
        "runs_with_artifacts": artifacts,
        "count": artifacts.len(),
    })))
}

#[derive(serde::Deserialize)]
struct ArtifactContentParams {
    path: String,
}

/// GET /api/heartbeat/artifacts?path=… — read one artifact file's content.
///
/// Path-traversal safe by construction: the exact path must appear in some
/// run's recorded `artifacts` array (a DB-backed allowlist) — arbitrary
/// filesystem paths are rejected before any disk access.
async fn heartbeat_artifact_content(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ArtifactContentParams>,
) -> AppResult {
    const MAX_BYTES: usize = 2 * 1024 * 1024;

    let recorded = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM noo_heartbeat_runs \
         WHERE artifacts @> to_jsonb($1::text))"
    )
    .bind(&params.path)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !recorded {
        return Err(AppError::NotFound(
            "Path is not a recorded heartbeat artifact".into(),
        ));
    }

    match tokio::fs::read(&params.path).await {
        Ok(bytes) => {
            let truncated = bytes.len() > MAX_BYTES;
            let slice = if truncated { &bytes[..MAX_BYTES] } else { &bytes[..] };
            let content = String::from_utf8_lossy(slice).into_owned();
            Ok(Json(json!({
                "path": params.path,
                "content": content,
                "truncated": truncated,
                "size_bytes": bytes.len(),
            })))
        }
        Err(e) => Err(AppError::NotFound(format!(
            "Artifact file unreadable ({e}) — it may have been rotated out"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════
// Heartbeat run_task — native Rust (SQL + coordinator)
// ═══════════════════════════════════════════════════════════════

/// POST /api/heartbeat/tasks/{task_id}/run — execute a heartbeat task immediately.
///
/// 1. Look up the task from noo_heartbeat_tasks
/// 2. Build a prompt based on the task action
/// 3. Call the Rust coordinator for AI-generated content
/// 4. Record the run in noo_heartbeat_runs
/// 5. Return the run record
async fn heartbeat_run_task(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(task_id): Path<String>,
) -> AppResult {
    // 1. Look up the task
    let task = sqlx::query_as::<_, (
        String, String, String, String,
        Value, Value, Value, bool,
    )>(
        "SELECT id, name, schedule, action, \
                COALESCE(config, '{}'::jsonb), \
                COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), \
                enabled \
         FROM noo_heartbeat_tasks WHERE id = $1"
    )
    .bind(&task_id)
    .fetch_optional(&state.db)
    .await?;

    let (_, task_name, _schedule, action, config, channels, recipients, _enabled) =
        match task {
            Some(t) => t,
            None => return Err(AppError::NotFound(format!("Task not found: {task_id}"))),
        };

    // A task that destroys data runs on its schedule, or when a person asks: not on an agent's say-so.
    crate::task_guard::may_run_now(&crate::task_guard::resolve_origin(&state.db, &ctx).await, &action, &config)
        .map_err(AppError::Forbidden)?;

    // Three dispatch paths matching the cron-tick loop in heartbeat_loop.rs:
    //   - RustLlm:        build prompt → coordinator::run (LLM)
    //   - RustNative:     pure data/orchestration handler in Rust
    //   - PythonDelegate: ML-touching actions still in Python (NATS)
    //
    // Previously this endpoint used the old is_llm_driven_action() check,
    // which sent EVERYTHING non-LLM to Python — including the Rust-native
    // actions (cluster_health, agent_self_check, etc.) we ported.
    // Result: "Unknown action: agent_self_check" because Python's
    // _dispatch doesn't know about them.
    let run_id = uuid::Uuid::new_v4().to_string()[..12].to_string();
    let started_at = chrono::Utc::now();
    let action_path = heartbeat_actions::action_path(&action);

    // Delegated tasks dispatch fire-and-forget, matching the cron path.
    //
    // This used a synchronous NATS request, so NOO_WORKER_TIMEOUT_SECS (120s)
    // was an effective deadline on the task. graph_signals legitimately runs
    // ~392s, so "Run now" on it always failed while the task itself succeeded
    // — the same defect fixed for scheduled runs, left behind here because
    // that fix only touched heartbeat_loop.
    //
    // No run_id is returned. Python generates its own
    // (`str(uuid.uuid4())[:12]` in `_execute_task`) when it writes the run
    // row, so any id invented here would never match the record the caller
    // then polls for. `dispatched_at` is the correlator instead — the same
    // (task_id, started_at >= dispatched_at) key heartbeat_reconcile uses.
    if matches!(action_path, heartbeat_actions::ActionPath::PythonDelegate) {
        // Surface routing, same rule as the cron path in
        // heartbeat_loop::dispatch_python_delegate — this branch was the
        // second dispatch site and originally missed the routing: a manual
        // "Run now" on an ML action landed on the core worker and errored.
        let subject = if heartbeat_actions::is_trellion_action(&action) {
            if !crate::addons::trellion_intel_enabled() {
                // Deliberately-off add-on: refuse synchronously and record
                // an honest skipped run — no dispatch ledger, no
                // abandonment alert, matching the cron path.
                let now = chrono::Utc::now();
                let empty = json!([]);
                let skipped = format!(
                    "Skipped: '{action}' requires the trellion-intel add-on, which \
                     is not available on this install ({})",
                    crate::addons::intel_refusal_msg()
                );
                let _ = crate::repo::heartbeat::record_run(
                    &state.db,
                    &crate::repo::heartbeat::RunRecord {
                        run_id: &run_id,
                        task_id: &task_id,
                        task_name: &task_name,
                        action: &action,
                        started_at: now,
                        completed_at: now,
                        status: "skipped",
                        result_text: &skipped,
                        error: None,
                        duration_ms: 0,
                        notified_channels: &empty,
                        artifacts: &empty,
                    },
                )
                .await;
                return Ok(Json(json!({
                    "status": "skipped",
                    "task_id": task_id,
                    "task_name": task_name,
                    "action": action,
                    "message": skipped,
                })));
            }
            "worker.api.heartbeat.run_ml"
        } else {
            "worker.api.heartbeat.run"
        };

        // One run per task, delegates included: claimed here, released by
        // the reconciler on the terminal verdict.
        if let Err(existing) = heartbeat_actions::try_begin_delegate_run(&task_id, &run_id) {
            return Ok(Json(json!({
                "status": "already_running",
                "task_id": task_id,
                "task_name": task_name,
                "action": action,
                "run_id": existing,
                "poll": format!("/api/heartbeat/history?task_id={task_id}"),
                "message": "A run of this task is already in flight — poll the \
                            history endpoint for its outcome.",
            })));
        }
        let dispatch = crate::heartbeat_reconcile::Dispatch {
            task_id: task_id.clone(),
            task_name: task_name.clone(),
            action: action.clone(),
            dispatched_at: started_at.timestamp(),
        };
        // Ledger before publish, so a task that dies is still reconciled.
        crate::heartbeat_reconcile::record_dispatch(&state, &dispatch).await;
        // Start row: the worker updates this same row via the run_id in
        // the payload, so callers poll ONE id across all action paths.
        if let Err(e) = crate::repo::heartbeat::record_run_start(
            &state.db, &run_id, &task_id, &task_name, &action, started_at,
        )
        .await
        {
            tracing::warn!(task_id = %task_id, error = %e, "heartbeat_run_start_row_failed");
        }
        crate::worker_client::publish_fire_and_forget(
            state.nats.clone(),
            state.db.clone(),
            subject,
            crate::heartbeat_reconcile::dispatch_payload(&task_id, &run_id),
        );
        tracing::info!(
            task_id = %task_id, action = %action, subject = %subject, run_id = %run_id,
            "heartbeat_manual_delegate_dispatched"
        );
        return Ok(Json(json!({
            "status": "queued",
            "task_id": task_id,
            "task_name": task_name,
            "action": action,
            "run_id": run_id,
            "dispatched_at": started_at.to_rfc3339(),
            "poll": format!("/api/heartbeat/history?task_id={task_id}"),
            "message": "Dispatched to the Python worker. The outcome is written \
                        to noo_heartbeat_runs when it completes — poll the history \
                        endpoint for a run with started_at at or after \
                        dispatched_at. Failures alert via heartbeat.task_failed.",
        })));
    }

    // Run the task in a SPAWNED future. The handler future is dropped by
    // axum when the client disconnects — before this split, a research run
    // triggered from a client with a request timeout (noo CLI: ~120s
    // global) was CANCELLED mid-flight with no run row, which read exactly
    // like "the run never happened" (observed live 2026-08-20, three
    // vanished runs). tokio::spawn decouples the work either way.
    //
    // LLM actions (research pipelines, custom prompts) run for MINUTES —
    // awaiting them here just re-created the old failure shape one layer
    // up: the CLI's global timeout expired and reported "cannot reach
    // gateway" while the run continued fine server-side (observed live
    // 2026-08-28). They now detach and answer "queued" with the run_id,
    // exactly like the Python-delegate branch. The sub-second RustNative
    // data actions keep the synchronous result the dashboard's Run-now
    // expects.
    // One run per task at a time — a second Run-now (or a race with the
    // cron tick) answers with the live run instead of double-executing.
    let in_flight = match heartbeat_actions::try_begin_run(&task_id, &run_id) {
        Ok(g) => g,
        Err(existing) => {
            return Ok(Json(json!({
                "status": "already_running",
                "task_id": task_id,
                "task_name": task_name,
                "action": action,
                "run_id": existing,
                "poll": format!("/api/heartbeat/history?task_id={task_id}"),
                "message": "A run of this task is already in flight — poll the                             history endpoint for its outcome.",
            })));
        }
    };
    // Start row: in-flight runs are visible in history, not only in logs.
    if let Err(e) = crate::repo::heartbeat::record_run_start(
        &state.db, &run_id, &task_id, &task_name, &action, started_at,
    )
    .await
    {
        tracing::warn!(task_id = %task_id, error = %e, "heartbeat_run_start_row_failed");
    }
    let run = tokio::spawn({
        let fut = execute_manual_run(
            state.clone(),
            task_id.clone(),
            task_name.clone(),
            action.clone(),
            config,
            channels,
            recipients,
            run_id.clone(),
            started_at,
        );
        async move {
            let _in_flight = in_flight; // released when the run finishes
            fut.await
        }
    });
    if matches!(action_path, heartbeat_actions::ActionPath::RustLlm) {
        drop(run); // detached — the spawned task owns the run to completion
        tracing::info!(
            task_id = %task_id, action = %action, run_id = %run_id,
            "heartbeat_manual_llm_detached"
        );
        return Ok(Json(json!({
            "status": "queued",
            "task_id": task_id,
            "task_name": task_name,
            "action": action,
            "run_id": run_id,
            "dispatched_at": started_at.to_rfc3339(),
            "poll": format!("/api/heartbeat/history?task_id={task_id}"),
            "message": "Running in the gateway. LLM actions take minutes — the                         outcome is written to noo_heartbeat_runs when it                         completes; poll the history endpoint for this run_id.                         Failures alert via heartbeat.task_failed.",
        })));
    }
    match run.await {
        Ok(result) => result,
        Err(e) => Err(AppError::Internal(format!("manual task run panicked: {e}"))),
    }
}

/// The body of a manual "run now": LLM/native execution, channel dispatch,
/// quality reclassification, and the noo_heartbeat_runs row. Owns all its
/// inputs so it can outlive the HTTP request that started it (see the
/// tokio::spawn split in `heartbeat_run_task`).
#[allow(clippy::too_many_arguments)]
async fn execute_manual_run(
    state: Arc<AppState>,
    task_id: String,
    task_name: String,
    action: String,
    config: Value,
    channels: Value,
    recipients: Value,
    run_id: String,
    started_at: chrono::DateTime<chrono::Utc>,
) -> AppResult {
    let start_instant = Instant::now();
    // Same per-task max_iterations override as the cron-tick path
    // (heartbeat_loop.rs). Default 15 — research/report tasks need
    // headroom; old default of 5 truncated mid-plan.
    let max_iterations: u32 = config
        .get("max_iterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(15);

    let action_path = heartbeat_actions::action_path(&action);
    // A system action's channel lines (heartbeat_actions::SystemReport).
    let mut native_system: Option<(String, bool)> = None;
    let (mut status, result_text, mut error_text) = match action_path {
        heartbeat_actions::ActionPath::RustNative => {
            match heartbeat_actions::run_rust_native_task(&state, &task_id, &action, &config).await {
                // The manual-trigger path reports result text only; the
                // artifact path it wrote is already named in that text.
                Ok(outcome) => {
                    // Queued, not done (database_backup): park the run as
                    // `running` for its completion hook; do not record success.
                    if outcome.pending {
                        if matches!(crate::backup_completion::park_run(&state.db, &run_id, &outcome.text).await, Ok(true)) {
                            crate::repo::heartbeat::set_last_run(&state.db, &task_id, started_at).await?;
                            return Ok(Json(json!({
                                "run_id": run_id,
                                "task_id": task_id,
                                "task_name": task_name,
                                "action": action,
                                "started_at": started_at.to_rfc3339(),
                                "completed_at": Value::Null,
                                "status": "running",
                                "result_text": outcome.text,
                                "error": "",
                                "duration_ms": start_instant.elapsed().as_millis() as i64,
                                "notified_channels": [],
                                "artifacts": [],
                            })));
                        }
                        tracing::error!(task_id = %task_id, run_id = %run_id, "database_backup_park_failed");
                        (
                            "error".to_string(),
                            String::new(),
                            "Database backup was queued, but its pending state could not be recorded, \
                             so nothing will confirm it. Look for the result file in the host spool."
                                .to_string(),
                        )
                    } else {
                        native_system = outcome.channel.map(|c| (c, outcome.has_detail));
                        ("success".to_string(), outcome.text, String::new())
                    }
                }
                Err(e) => {
                    tracing::warn!(task_id = %task_id, action = %action, error = %e, "rust_native_run_task_failed");
                    ("error".to_string(), String::new(), e)
                }
            }
        }
        // Same two `channel_message` guards as the cron-tick path: a
        // misconfigured task is an error (not a success carrying a
        // complaint), and a literal `config.message` skips the model.
        heartbeat_actions::ActionPath::RustLlm
            if heartbeat_actions::channel_message_config_error(
                &action, &config, &channels,
            )
            .is_some() =>
        {
            let reason = heartbeat_actions::channel_message_config_error(
                &action, &config, &channels,
            )
            .unwrap_or_default();
            ("error".to_string(), String::new(), reason)
        }
        heartbeat_actions::ActionPath::RustLlm
            if heartbeat_actions::literal_channel_message(&action, &config).is_some() =>
        {
            (
                "success".to_string(),
                heartbeat_actions::literal_channel_message(&action, &config)
                    .unwrap_or_default(),
                String::new(),
            )
        }
        heartbeat_actions::ActionPath::RustLlm => {
            let prompt = heartbeat_actions::build_action_prompt(&action, &task_name, &config);
            let conversation_id =
                heartbeat_actions::build_conversation_id(&task_id, &run_id, &action, &config);
            // Shared with the cron-tick path (heartbeat_loop) — model
            // resolution, phased research pipeline + fallback, usage
            // recording and corrective retry all live in run_llm_action.
            match heartbeat_actions::run_llm_action(
                &state,
                &action,
                &task_id,
                &config,
                &prompt,
                &conversation_id,
                max_iterations,
            )
            .await
            {
                Ok(text) => ("success".to_string(), text, String::new()),
                Err(e) => {
                    tracing::error!(task_id = %task_id, error = %e, "heartbeat_run_task_error");
                    ("error".to_string(), String::new(), e.to_string())
                }
            }
        }
        heartbeat_actions::ActionPath::PythonDelegate => unreachable!(
            "PythonDelegate is handled before this match",
        ),
    };

    // Dispatch result to configured channels — same path the cron-tick
    // loop uses. Long results are sent as `.md` attachments where the
    // adapter supports uploads (Google Chat).
    let (notified, artifacts, delivery_failed) = if status == "success" && !result_text.is_empty() {
        heartbeat_actions::notify_channels(
            &task_id,
            &task_name,
            &action,
            &config,
            &channels,
            &recipients,
            &result_text,
            native_system.as_ref().map(|(c, d)| (c.as_str(), *d)),
        ).await
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    // Same delivery-failure surfacing as the cron-tick path
    // (heartbeat_loop.rs::execute_task): record failed channels in the
    // run's error column and alert the operator.
    if !delivery_failed.is_empty() {
        let note = format!("delivery_failed: {}", delivery_failed.join(", "));
        if error_text.is_empty() {
            error_text = note;
        } else {
            error_text = format!("{error_text}; {note}");
        }
        crate::operator_alert::send_operator_alert_with(
            &state,
            crate::operator_alert::OperatorAlert::new(
                "heartbeat.delivery_failed",
                &task_id,
                format!(
                    "📭 Heartbeat task '{task_name}' completed but its result was \
                     not delivered. The result is kept in task history."
                ),
            )
            .detail(format!(
                "action {action}, run {run_id}; delivery failed for: {}",
                delivery_failed.join(", ")
            ))
            .investigate(format!("noo heartbeat history --task-id {task_id} --limit 5")),
            3600,
        )
        .await;
    }

    // Quality reclassification — same rule as the cron-tick path
    // (heartbeat_loop.rs::execute_task): unusable LLM output is recorded
    // as error so it never feeds prior-research history and the meta
    // loop sees it as a failure.
    if status == "success"
        && matches!(
            heartbeat_actions::action_path(&action),
            heartbeat_actions::ActionPath::RustLlm
        )
    {
        let depth = config.get("depth").and_then(|v| v.as_str());
        let quality = crate::verify::response::classify_response_quality(
            &result_text,
            crate::verify::response::min_chars_for_action_depth(&action, depth),
        );
        if !quality.is_usable() {
            status = "error".to_string();
            let note = format!("unusable output: {}", quality.reason());
            error_text = if error_text.is_empty() {
                note
            } else {
                format!("{error_text}; {note}")
            };
        }
    }

    let duration_ms = start_instant.elapsed().as_millis() as i32;
    let completed_at = chrono::Utc::now();

    // 4. Record the run in noo_heartbeat_runs. Unlike the scheduler path this
    //    one propagates — a manual trigger reports its own failure to the caller.
    let notified_json = json!(notified);
    let artifacts_json = json!(artifacts);
    crate::repo::heartbeat::complete_run(
        &state.db,
        &crate::repo::heartbeat::RunRecord {
            run_id: &run_id,
            task_id: &task_id,
            task_name: &task_name,
            action: &action,
            started_at,
            completed_at,
            status: &status,
            result_text: &result_text,
            error: if error_text.is_empty() { None } else { Some(&error_text) },
            duration_ms,
            notified_channels: &notified_json,
            artifacts: &artifacts_json,
        },
    )
    .await?;

    // Update last_run on the task
    crate::repo::heartbeat::set_last_run(&state.db, &task_id, started_at).await?;

    // 5. Return the run record (matching Python's TaskRunRecord.to_dict() shape)
    let truncated_result = if result_text.len() > 2000 {
        // Find last char boundary at or before 2000 to avoid panicking on multi-byte
        let mut end = 2000;
        while end > 0 && !result_text.is_char_boundary(end) {
            end -= 1;
        }
        &result_text[..end]
    } else {
        &result_text
    };

    Ok(Json(json!({
        "run_id": run_id,
        "task_id": task_id,
        "task_name": task_name,
        "action": action,
        "started_at": started_at.to_rfc3339(),
        "completed_at": completed_at.to_rfc3339(),
        "status": status,
        "result_text": truncated_result,
        "error": error_text,
        "duration_ms": duration_ms,
        "notified_channels": notified,
        "artifacts": artifacts,
    })))
}

// `build_action_prompt` lives in `crate::heartbeat_actions` so the loop
// and the run-now route share one source of truth (they had drifted as
// separate copies).

/// POST /api/heartbeat/reload — signal the heartbeat scheduler to reseat
/// `next_run` for every enabled task using the current cron + TZ.
///
/// The UI calls this after a task save so schedule edits take effect
/// without a gateway restart. The scheduler picks up the flag within
/// the reload-check interval (5s by default) and recomputes `next_run`
/// without firing tasks. Idempotent: a flurry of saves results in one
/// reload pass.
async fn heartbeat_reload(State(state): State<Arc<AppState>>) -> AppResult {
    if let Some(redis) = state.redis.as_ref() {
        redis.set_string("noo:heartbeat:reload_pending", "1").await;
        Ok(Json(json!({"ok": true, "queued": true})))
    } else {
        // No Redis — without the flag store, the loop already polls every
        // 60s, so the worst-case delay is one tick. Tell the caller it's a
        // no-op rather than failing.
        Ok(Json(json!({"ok": true, "queued": false, "reason": "redis_not_configured"})))
    }
}

// ═══════════════════════════════════════════════════════════════
// Autonomy engine — native Rust (config YAML + Redis)
//
// The Python AutonomyEngine holds its state in-process (locations list,
// audit log, running flag).  The Rust gateway mirrors this by reading
// the `autonomy` section of noomesh.yaml for location definitions and
// using Redis for the global enabled flag.  The audit log is stored in
// the `noo_autonomy_audit` table when available, falling back to an
// empty list.
//
// Redis keys:
//   noo:autonomy:enabled — "1" or "0"
//
// Config YAML path: autonomy.locations[]
// ═══════════════════════════════════════════════════════════════

/// GET /api/autonomy/status — read autonomy state from config YAML + Redis.
///
/// Returns the global running flag (from Redis) and the list of configured
/// locations with their enabled/interval/conditions/actions metadata.
async fn autonomy_status(State(state): State<Arc<AppState>>) -> AppResult {
    // Two DIFFERENT facts that were being reported as one. The Redis flag says
    // whether the engine is *allowed* to act; only the loop registry says
    // whether it is actually ticking. The old code answered "running: true"
    // from the flag alone — including when Redis was absent — which is exactly
    // the "the loop died and nobody noticed" case loop_health exists to catch.
    //
    // The flag is read through autonomy_loop::is_enabled so status and the loop
    // cannot disagree about what the key means (this handler used `!= "0"`,
    // the loop uses `== "1" || == "true"` — "off" split them).
    let enabled = crate::autonomy_loop::is_enabled(&state).await;
    let (running, running_detail) = crate::loop_health::liveness("autonomy_engine");

    // Read locations from cached config YAML
    let config = state.config_yaml.read().await;
    let locations = config
        .get("autonomy")
        .and_then(|a| a.get("locations"))
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();

    // Real last-evaluation times from the loop's in-memory map. Empty before
    // the engine's first tick; a location missing from it reports null, which
    // the CLI renders as unknown rather than "never ran".
    let last_checks = crate::autonomy_loop::last_checks().await;
    // Durable half: when each location last FIRED, from the audit table. A
    // read failure yields an empty map, so every location reports null and
    // the CLI shows unknown — the same shape as before the table existed.
    // It must never render as "has never fired", which is a claim.
    let last_fired: std::collections::HashMap<String, String> =
        crate::autonomy_audit::last_fired(&state)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(loc, at)| (loc, at.to_rfc3339()))
            .collect();
    let fired = |name: &str| -> Value {
        last_fired.get(name).map(|t| json!(t)).unwrap_or(Value::Null)
    };
    let checked = |name: &str| -> Value {
        last_checks
            .get(name)
            .map(|t| json!(t.to_rfc3339()))
            .unwrap_or(Value::Null)
    };
    // `armed` / `dry_run` are OMITTED for a location with no gate. Sending
    // false would assert "its gate is off" for something that has no gate —
    // a different fact, and the one an operator uses to decide what is safe
    // to arm. Absence is not a negative.
    let gate = |name: &str, config: &Value, out: &mut serde_json::Map<String, Value>| {
        if let Some((armed, dry_run)) = crate::autonomy_loop::gate_of(name, config) {
            out.insert("armed".into(), json!(armed));
            out.insert("dry_run".into(), json!(dry_run));
        }
    };

    // Build location summaries matching Python AutonomyEngine.get_status()
    let mut location_summaries: Vec<Value> = locations.iter().map(|loc| {
        let conditions = loc.get("conditions").and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0);
        let actions = loc.get("actions").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0);
        let name = loc.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let mut o = serde_json::Map::new();
        o.insert("name".into(), json!(name));
        o.insert("type".into(), json!(loc.get("type").and_then(|t| t.as_str()).unwrap_or("custom")));
        o.insert("enabled".into(), json!(loc.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true)));
        o.insert("interval".into(), json!(loc.get("check_interval_seconds").and_then(|i| i.as_i64()).unwrap_or(60)));
        o.insert("cooldown".into(), json!(loc.get("cooldown_seconds").and_then(|c| c.as_i64()).unwrap_or(300)));
        o.insert("last_check".into(), checked(name));
        o.insert("last_fired".into(), fired(name));
        o.insert("conditions".into(), json!(conditions));
        o.insert("actions".into(), json!(actions));
        o.insert("source".into(), json!("config"));
        gate(name, loc.get("config").unwrap_or(&Value::Null), &mut o);
        Value::Object(o)
    }).collect();

    // DB-defined custom locations (single writable store) — these WIN
    // over a YAML entry with the same name (the AUTONOMY-LOCATIONS API
    // never writes YAML — noomesh.yaml is only its seed; note the file
    // itself IS runtime-writable elsewhere via the settings/config routes,
    // through settings::mutate_config).
    let db_customs: Vec<(String, Value, bool)> = sqlx::query_as(
        "SELECT name, definition, enabled FROM noo_autonomy_locations",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (name, definition, enabled) in db_customs {
        let conditions = definition.get("conditions").and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0);
        let actions = definition.get("actions").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0);
        let mut o = serde_json::Map::new();
        o.insert("name".into(), json!(name));
        o.insert("type".into(), json!(definition.get("type").and_then(|t| t.as_str()).unwrap_or("custom")));
        o.insert("enabled".into(), json!(enabled));
        o.insert("interval".into(), json!(definition.get("check_interval_seconds").and_then(|i| i.as_i64()).unwrap_or(60)));
        o.insert("cooldown".into(), json!(definition.get("cooldown_seconds").and_then(|c| c.as_i64()).unwrap_or(300)));
        o.insert("last_check".into(), checked(&name));
        o.insert("last_fired".into(), fired(&name));
        o.insert("conditions".into(), json!(conditions));
        o.insert("actions".into(), json!(actions));
        o.insert("source".into(), json!("db"));
        gate(&name, definition.get("config").unwrap_or(&Value::Null), &mut o);
        let summary = Value::Object(o);
        if let Some(existing) = location_summaries.iter_mut().find(|l| {
            l.get("name").and_then(|n| n.as_str()) == summary.get("name").and_then(|n| n.as_str())
        }) {
            *existing = summary;
        } else {
            location_summaries.push(summary);
        }
    }

    // The autonomy loop ALSO runs a hard-coded builtin patrol
    // (autonomy_loop::default_locations) that never appears in the YAML.
    // Status must show it too — before this, `noo autonomy status` listed
    // only custom locations and the patrol looked dead ("1/1 enabled"
    // while 17 builtins were actually evaluating).
    let custom_names: std::collections::HashSet<String> = location_summaries.iter()
        .filter_map(|l| l.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    for b in crate::autonomy_loop::load_locations(&state).await {
        if custom_names.contains(&b.name) {
            continue; // a config entry with the same name wins the listing
        }
        let mut o = serde_json::Map::new();
        o.insert("name".into(), json!(b.name));
        o.insert("type".into(), json!("builtin"));
        o.insert("enabled".into(), json!(b.enabled));
        o.insert("interval".into(), json!(b.interval_seconds));
        o.insert("cooldown".into(), json!(b.interval_seconds));
        o.insert("last_check".into(), checked(&b.name));
        o.insert("last_fired".into(), fired(&b.name));
        o.insert("conditions".into(), json!(1));
        o.insert("actions".into(), json!(1));
        o.insert("action".into(), json!(b.action));
        o.insert("source".into(), json!("builtin"));
        gate(&b.name, &b.config, &mut o);
        location_summaries.push(Value::Object(o));
    }

    let locations_total = location_summaries.len();
    let locations_enabled = location_summaries.iter()
        .filter(|l| l.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true))
        .count();

    // `noo_autonomy_audit` has no migration and no writer in this repo, so an
    // unreadable store is "not tracked", never "0 actions taken".
    let audit = match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM noo_autonomy_audit")
        .fetch_one(&state.db)
        .await
    {
        Ok(n) => Measured::of(n),
        Err(e) => Measured::unmeasured(format!(
            "not tracked — no autonomy audit store is readable {}; fired \
             actions are visible in the gateway logs only",
            crate::measured::ref_note(&e)
        )),
    };

    let mut body = json!({
        "enabled": enabled,
        "locations_total": locations_total,
        "locations_enabled": locations_enabled,
        "locations": location_summaries,
    });
    put_into(&mut body, "running", Measured::noted(running, running_detail));
    put_keyed_into(&mut body, "audit_entries", "audit_detail", audit);
    Ok(Json(body))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    location: Option<String>,
}

#[derive(serde::Deserialize)]
struct DecisionsQuery {
    limit: Option<i64>,
    location: Option<String>,
    /// `would` (default), `fired`, `error`, or `all`.
    outcome: Option<String>,
}

/// GET /api/autonomy/audit — what the engine actually DID.
///
/// Reads `noo_autonomy_audit` through `autonomy_audit::recent`. Until
/// migration 058 that table did not exist and this route had never once
/// succeeded, while reporting a confident empty list.
async fn autonomy_audit(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQuery>,
) -> AppResult {
    let limit = params.limit.unwrap_or(50);
    audit_rows(&state, limit, params.location.as_deref(), None, "entries").await
}

/// GET /api/autonomy/decisions — what the DISARMED locations WOULD have done.
///
/// Defaults to `outcome = 'would'`, because that is the question this view
/// exists to answer: an operator deciding whether to arm an action needs the
/// decisions it did not take. `?outcome=fired|error|all` reaches the rest
/// without falling back to the audit route.
async fn autonomy_decisions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DecisionsQuery>,
) -> AppResult {
    let limit = params.limit.unwrap_or(20);
    let outcome = match params.outcome.as_deref() {
        None => Some("would"),
        Some("all") => None,
        Some(o) => Some(o),
    };
    audit_rows(&state, limit, params.location.as_deref(), outcome, "decisions").await
}

/// Shared body of both audit views.
///
/// A read error returns the store-unreadable envelope, NEVER an empty list.
/// An empty list says "autonomy has never acted", which is a claim; a failed
/// read is the absence of a measurement. Conflating them is the exact defect
/// that hid a missing table from everyone for months, so it stays explicit
/// even though it costs a branch on every call.
async fn audit_rows(
    state: &AppState,
    limit: i64,
    location: Option<&str>,
    outcome: Option<&str>,
    key: &str,
) -> AppResult {
    let rows = match crate::autonomy_audit::recent(state, limit, location, outcome).await {
        Ok(rows) => rows,
        Err(e) => {
            return Ok(Json(json!({
                key: Value::Null,
                "count": Value::Null,
                "error": format!("autonomy audit log is not available: {e}"),
                "detail": "no noo_autonomy_audit store is readable; fired actions \
                           appear in the gateway logs only",
            })));
        }
    };
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "at": r.at.to_rfc3339(),
                "location": r.location,
                "action": r.action,
                "outcome": r.outcome,
                "target": r.target,
                "detail": r.detail,
                // armed/dry_run are Option and stay null for a location with
                // no gate — the schema's half of "absence is not a negative".
                "armed": r.armed,
                "dry_run": r.dry_run,
                "metrics": r.metrics,
            })
        })
        .collect();
    let count = entries.len();
    Ok(Json(json!({ key: entries, "count": count })))
}

/// POST /api/autonomy/locations — add a new location to config YAML.
///
/// Accepts a JSON body with location fields (name, type, config,
/// check_interval_seconds, conditions, actions, enabled, cooldown_seconds).
/// Appends to the `autonomy.locations` array in noomesh.yaml and
/// refreshes the in-memory cache.
async fn autonomy_add_location(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    let name = body.get("name").and_then(|n| n.as_str()).unwrap_or("");
    if name.is_empty() {
        return Err(AppError::BadRequest("Missing field: name".into()));
    }

    // Build the location entry
    let location = json!({
        "name": name,
        "type": body.get("type").and_then(|t| t.as_str()).unwrap_or("endpoint"),
        "config": body.get("config").cloned().unwrap_or(json!({})),
        "check_interval_seconds": body.get("check_interval_seconds").and_then(|i| i.as_i64()).unwrap_or(60),
        "conditions": body.get("conditions").cloned().unwrap_or(json!([])),
        "actions": body.get("actions").cloned().unwrap_or(json!([])),
        "enabled": body.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true),
        "cooldown_seconds": body.get("cooldown_seconds").and_then(|c| c.as_i64()).unwrap_or(300),
    });

    // Custom definitions live in the runtime-editable DB tier — the
    // autonomy-locations API never writes YAML (for locations the file is
    // just the seed). Other routes DO write noomesh.yaml (settings/config/
    // user-dirs/proactive-rules), always via settings::mutate_config.
    let enabled = location.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
    sqlx::query(
        "INSERT INTO noo_autonomy_locations (name, definition, enabled, updated_by) \
         VALUES ($1, $2, $3, 'api') \
         ON CONFLICT (name) DO UPDATE SET definition = $2, enabled = $3, \
           updated_at = now(), updated_by = 'api'",
    )
    .bind(name)
    .bind(&location)
    .bind(enabled)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("autonomy location upsert: {e}")))?;

    Ok(Json(json!({"status": "ok", "name": name, "store": "db"})))
}

/// POST /api/autonomy/locations/{name}/toggle — toggle a location's enabled flag.
///
/// Reads the location from config YAML, flips (or sets) the `enabled` field,
/// writes back, and refreshes the cache.
async fn autonomy_toggle_location(
    State(state): State<Arc<AppState>>,
    actor: Option<axum::Extension<crate::auth::AuthActor>>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let enabled = body.get("enabled").and_then(|e| e.as_bool());
    let enabled = match enabled {
        Some(e) => e,
        None => return Err(AppError::BadRequest("Missing 'enabled' field".into())),
    };

    let updated_by = actor
        .as_ref()
        .map(|axum::Extension(a)| a.0.clone())
        .unwrap_or_else(|| "api".to_string());

    // Builtins: persist to noo_autonomy_overrides (runtime tier — wins
    // over YAML in autonomy_loop::load_locations).
    let is_builtin = crate::autonomy_loop::default_locations()
        .iter()
        .any(|l| l.name == name);
    if is_builtin {
        // Optional `config` object: this is how a built-in's per-location
        // action gate is armed without editing noomesh.yaml and restarting —
        // `{"enabled": true, "config": {"enabled_action": true}}`. Omitting it
        // leaves any stored config untouched, so a plain enable/disable never
        // silently disarms an action the operator opted into.
        let config = body.get("config").filter(|c| c.is_object()).cloned();
        sqlx::query(
            "INSERT INTO noo_autonomy_overrides (name, enabled, config, updated_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (name) DO UPDATE SET enabled = $2, \
               config = COALESCE($3, noo_autonomy_overrides.config), \
               updated_at = now(), updated_by = $4",
        )
        .bind(&name)
        .bind(enabled)
        .bind(&config)
        .bind(&updated_by)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("autonomy override upsert: {e}")))?;
        return Ok(Json(
            json!({"name": name, "enabled": enabled, "config": config, "store": "db"}),
        ));
    }

    // Customs: single writable store is noo_autonomy_locations. A custom
    // still defined only in the YAML seed is LAZILY MIGRATED here on its
    // first toggle (definition copied, enabled set) — no API path writes
    // YAML anymore.
    let in_db: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM noo_autonomy_locations WHERE name = $1",
    )
    .bind(&name)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("autonomy location query: {e}")))?;

    if in_db.is_some() {
        sqlx::query(
            "UPDATE noo_autonomy_locations SET enabled = $2, \
             updated_at = now(), updated_by = $3 WHERE name = $1",
        )
        .bind(&name)
        .bind(enabled)
        .bind(&updated_by)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("autonomy location update: {e}")))?;
        return Ok(Json(json!({"name": name, "enabled": enabled, "store": "db"})));
    }

    let yaml_def = {
        let config = state.config_yaml.read().await;
        config
            .get("autonomy")
            .and_then(|a| a.get("locations"))
            .and_then(|l| l.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|l| l.get("name").and_then(|n| n.as_str()) == Some(&name))
                    .cloned()
            })
    };
    let Some(mut definition) = yaml_def else {
        return Err(AppError::NotFound(format!("Location '{name}' not found")));
    };
    if let Some(obj) = definition.as_object_mut() {
        obj.insert("enabled".to_string(), json!(enabled));
    }
    sqlx::query(
        "INSERT INTO noo_autonomy_locations (name, definition, enabled, updated_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&name)
    .bind(&definition)
    .bind(enabled)
    .bind(&updated_by)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("autonomy location migrate: {e}")))?;
    Ok(Json(json!({"name": name, "enabled": enabled, "store": "db",
                   "migrated_from_yaml": true})))
}

/// Write the global autonomy flag; 503 when the write did not happen.
async fn set_autonomy_flag(state: &AppState, value: &str) -> Result<(), AppError> {
    match state.redis.as_ref() {
        Some(redis) => {
            if redis.set_string("noo:autonomy:enabled", value).await {
                Ok(())
            } else {
                Err(AppError::Unavailable("the autonomy flag could not be written to Redis; nothing changed".into()))
            }
        }
        None => Err(AppError::Unavailable(
            "Redis is not configured, so the autonomy flag cannot be set; nothing changed".into(),
        )),
    }
}

/// POST /api/autonomy/enable — enable the autonomy engine globally.
///
/// Sets the Redis flag `noo:autonomy:enabled` to "1" and toggles all
/// locations to enabled in config YAML.
async fn autonomy_enable(State(state): State<Arc<AppState>>) -> AppResult {
    // The flag is the only switch. Without Redis (or a failed write) nothing
    // changed, so say so instead of answering "enabled".
    set_autonomy_flag(&state, "1").await?;

    // The Redis flag alone gates the loop (autonomy_loop::is_enabled).
    // The old behavior ALSO force-flipped every location's individual
    // enabled in the YAML — destroying per-location choices and writing
    // to the git-owned seed file. Global on/off is now just the flag.
    Ok(Json(json!({"status": "enabled"})))
}

/// POST /api/autonomy/disable — disable the autonomy engine globally.
///
/// Clears the Redis flag `noo:autonomy:enabled` to "0" and toggles all
/// locations to disabled in config YAML.
async fn autonomy_disable(State(state): State<Arc<AppState>>) -> AppResult {
    set_autonomy_flag(&state, "0").await?;

    // Redis flag only — see autonomy_enable for rationale.
    Ok(Json(json!({"status": "disabled"})))
}


// ═══════════════════════════════════════════════════════════════
// Agent activities — long-running pursuits (Phase 3 meta-loop)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ActivityListQuery {
    status: Option<String>,
    kind: Option<String>,
    limit: Option<i64>,
}

/// GET /api/activities — list agent activities (long-running pursuits).
///
/// Query params: `status` (active|paused|completed|abandoned), `kind`, and
/// `limit` (default 50, capped at 500). Returns `{activities, count}`.
/// Activities are the meta-loop's cross-run pursuit tracker (migration
/// 008_agent_activities); the `noo_activity_list` MCP tool calls this.
async fn activities_list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ActivityListQuery>,
) -> AppResult {
    let limit = q.limit.unwrap_or(50).min(500);
    let activities = crate::agent_activities::list_activities(
        &state.db,
        q.status.as_deref(),
        q.kind.as_deref(),
        limit,
    )
    .await
    .map_err(AppError::Internal)?;
    Ok(Json(json!({"activities": activities, "count": activities.len()})))
}

/// POST /api/activities — create an agent activity.
///
/// Body: `name` (required), `kind` (default "other"), `description`,
/// `success_when` (optional completion criterion), `created_by` (default
/// "user"). Returns `{ok, activity_id}`. Lifecycle: create → progress
/// updates → complete or abandon; linked heartbeat tasks bump
/// `last_activity_at` automatically when they fire.
async fn activities_create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing field: name".into()))?;
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("other");
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let success_when = body.get("success_when").and_then(|v| v.as_str());
    let created_by = body
        .get("created_by")
        .and_then(|v| v.as_str())
        .unwrap_or("user");

    let id = crate::agent_activities::create_activity(
        &state.db,
        name,
        kind,
        description,
        success_when,
        created_by,
    )
    .await
    .map_err(AppError::BadRequest)?;

    Ok(Json(json!({"ok": true, "activity_id": id.to_string()})))
}

/// POST /api/activities/{id}/progress — append a progress entry.
///
/// The JSON body is stored verbatim as one entry in the activity's
/// progress log and refreshes `last_activity_at`. 400 on a non-UUID id.
async fn activities_append_progress(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let activity_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest("invalid activity id".into()))?;
    crate::agent_activities::append_progress(&state.db, activity_id, body)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({"ok": true})))
}

/// POST /api/activities/{id}/link-task — link a heartbeat task.
///
/// Body: `task_id` (required). A linked task bumps the activity's
/// `last_activity_at` on every run, so the pursuit reads as alive for as
/// long as its automation fires. 400 on a non-UUID id.
async fn activities_link_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let activity_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest("invalid activity id".into()))?;
    let task_id = body
        .get("task_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing field: task_id".into()))?;
    crate::agent_activities::link_task(&state.db, activity_id, task_id)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({"ok": true})))
}

/// PUT /api/activities/{id}/status — pause or resume an activity.
///
/// Body: `status` — only the active↔paused transition lives here;
/// terminal states go through /complete instead, which is why an invalid
/// status is a 400 rather than a silent write.
async fn activities_set_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let activity_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest("invalid activity id".into()))?;
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing field: status".into()))?;
    crate::agent_activities::pause_or_resume(&state.db, activity_id, status)
        .await
        .map_err(AppError::BadRequest)?;
    Ok(Json(json!({"ok": true})))
}

/// POST /api/activities/{id}/complete — close an activity.
///
/// Body: `final_status` ("completed" default, or "abandoned") and an
/// optional `note`. Terminal: a closed activity stops appearing in the
/// default active listing and no longer accepts progress.
async fn activities_complete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let activity_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest("invalid activity id".into()))?;
    let final_status = body
        .get("final_status")
        .and_then(|v| v.as_str())
        .unwrap_or("completed");
    let final_note = body.get("note").and_then(|v| v.as_str());
    crate::agent_activities::complete_activity(
        &state.db,
        activity_id,
        final_status,
        final_note,
    )
    .await
    .map_err(AppError::BadRequest)?;
    Ok(Json(json!({"ok": true})))
}

#[cfg(test)]
mod toggle_body_tests {
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::{header, Request};
    use axum::Json;
    use serde_json::Value;

    /// The toggle handler takes `Option<Json<Value>>` so that a request with
    /// no body flips the task's state, which is what the OpenAPI spec has
    /// always promised ("Omit to flip current state") and what `ui/apps/web`
    /// sends. A bare `Json<Value>` rejected those with 415 before the caller
    /// ever reached the handler, so the flip branch was dead code.
    #[tokio::test]
    async fn a_request_with_no_body_extracts_as_none() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let got = Option::<Json<Value>>::from_request(req, &()).await;
        assert!(
            matches!(got, Ok(None)),
            "a bodyless toggle must extract as None, not reject with 415"
        );
    }

    #[tokio::test]
    async fn an_explicit_value_still_extracts() {
        let req = Request::builder()
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"enabled":true}"#))
            .unwrap();
        let got = Option::<Json<Value>>::from_request(req, &()).await;
        let Ok(Some(Json(v))) = got else {
            panic!("an explicit body must still extract")
        };
        assert_eq!(v.get("enabled").and_then(|e| e.as_bool()), Some(true));
    }
}

#[cfg(test)]
mod heartbeat_catalog_tests {
    /// Every Rust-native heartbeat action must appear in the catalog
    /// `GET /api/heartbeat/actions` serves.
    ///
    /// The two lists are hand-maintained in different files —
    /// `RUST_NATIVE_ACTIONS` decides what the dispatcher will RUN, this
    /// catalog decides what the API, the dashboard and the CLI will OFFER —
    /// and nothing bound them. Five actions were runnable and unlistable,
    /// so the only way to schedule one was to already know its name.
    ///
    /// `agent_self_check` is why that mattered: it is the sole dispatcher
    /// into the evolve add-on, so while it was unlistable the add-on ran
    /// enabled and healthy and served zero requests.
    ///
    /// One direction only. The catalog is deliberately WIDER than this list,
    /// because actions delegated to the Python worker (`thought_experiment`,
    /// `graph_signals`, …) belong in it too and are not Rust-native.
    #[test]
    fn every_native_action_is_offered() {
        let dispatcher = include_str!("../heartbeat_actions.rs");
        let catalog = include_str!("intelligence.rs");

        let block = dispatcher
            .split_once("const RUST_NATIVE_ACTIONS")
            .expect("RUST_NATIVE_ACTIONS is gone; this guard is stale")
            .1;
        let block = block.split_once("];").expect("unterminated list").0;

        let listed: Vec<&str> = catalog
            .match_indices(r#"json!({"name": ""#)
            .map(|(i, m)| {
                let rest = &catalog[i + m.len()..];
                &rest[..rest.find('"').unwrap_or(0)]
            })
            .collect();

        let missing: Vec<&str> = block
            .match_indices('"')
            .map(|(i, _)| &block[i + 1..])
            .filter_map(|rest| rest.find('"').map(|e| &rest[..e]))
            .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()))
            .filter(|n| !listed.contains(n))
            .collect();

        assert!(
            missing.is_empty(),
            "dispatchable but not offered by GET /api/heartbeat/actions — \
             nobody can schedule these without already knowing the name: {missing:?}"
        );
    }
}
