// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Heartbeat scheduler — cron-tick poll loop.
//!
//! Polls `noo_heartbeat_tasks` for tasks whose `next_run <= NOW()` and
//! enabled = true, fires them via the same coordinator path the manual
//! `/api/heartbeat/tasks/{id}/run` route uses, then advances `next_run`
//! using the task's cron schedule (interpreted in the configured TZ —
//! see `heartbeat_actions::resolve_tz`).
//!
//! Design note (keep harness boundary in mind):
//! Heartbeat tasks like `daily_briefing`, `custom_prompt`, `research_report`
//! require an LLM and are HARNESS-side concerns. We dispatch them through
//! `coordinator::run`, which is the existing Rust agentic loop that calls
//! out to the harness's tool implementations via NATS workers. MESH owns
//! the *firing* (cron tick), HARNESS owns the *execution* (LLM + tools).
//!
//! Reload signaling: `/api/heartbeat/reload` (in `routes/intelligence.rs`)
//! sets the Redis key `noo:heartbeat:reload_pending`. Each tick checks
//! the flag and, if set, recomputes `next_run` for every enabled task
//! WITHOUT firing them — picking up schedule edits made via the UI
//! without waiting for a gateway restart. The actual firing logic is
//! unchanged; only `next_run` is reseated based on the new cron + TZ.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use serde_json::{json, Value};
use sqlx::Row;
use tokio::time::{interval, Duration};

use crate::heartbeat_actions;
use crate::state::AppState;

/// Poll interval for the heartbeat scheduler. The scheduler can fire
/// tasks no more granularly than this — finer-grained schedules will
/// still be rounded up to the next tick. 60s matches the Python
/// `HeartbeatScheduler` default.
const POLL_INTERVAL_SECS: u64 = 60;

/// Faster cadence for the reload check. Lets schedule edits made via
/// the UI take effect quickly without paying the full 60s poll latency.
/// The reload check itself is cheap (one Redis GET + at most one
/// pass over enabled tasks to recompute `next_run`).
const RELOAD_CHECK_SECS: u64 = 5;

/// Redis key set by `/api/heartbeat/reload` after a UI save. The loop
/// clears it once a reload pass completes.
const RELOAD_FLAG_KEY: &str = "noo:heartbeat:reload_pending";

/// Spawn the heartbeat scheduler loop. Call after `AppState::new()` in
/// `main.rs`. The loop runs for the lifetime of the process.
pub fn spawn(state: Arc<AppState>) {
    let tz = heartbeat_actions::resolve_tz();
    tracing::info!(
        interval_s = POLL_INTERVAL_SECS,
        reload_check_s = RELOAD_CHECK_SECS,
        timezone = %tz,
        "heartbeat_loop_spawned"
    );
    tokio::spawn(run_loop(state));
}

// NOTE: deliberately NOT on `managed_loop::spawn_managed_loop` — this loop
// multiplexes two cadences (60s task poll + 5s reload check) in ONE task
// via `select!`, so the registered "heartbeat_scheduler" liveness tick
// also guards the reload check's liveness. Splitting into two managed
// loops would either leave the reload check unmonitored or introduce a
// new loop_health tick name. `record_tick` therefore stays manual here.
async fn run_loop(state: Arc<AppState>) {
    // Sweep orphaned `running` rows FIRST: rows inserted at dispatch by a
    // previous gateway process cannot still be executing (LLM/native runs
    // live in gateway memory; the in-flight registry died with it). Left
    // alone they read as "running" forever — the exact silent state the
    // start-row change exists to eliminate. Delegate rows are left for the
    // reconciler's deadline (the Python worker may genuinely still be
    // working), except ones already older than the abandonment deadline.
    sweep_orphaned_runs(&state).await;

    // Boot grace: dispatching LLM/delegate work seconds after boot burns
    // the run against an empty cluster (observed 2026-08-28: research
    // tasks fired 68s after start into alive_nodes=0 — every completion
    // call 502'd). Hold the first poll until a node heartbeat lands, or a
    // bounded grace expires.
    wait_for_cluster_warm(&state).await;

    // A critical task (the database backup) whose newest success is older than
    // its schedule allows is told to the operator NOW, before the first poll
    // fires the catch-up: the scheduler cannot report its own outage while it
    // is down, so the moment it is back is the earliest it can speak.
    crate::backup_overdue::check(&state).await;

    let mut tick = interval(Duration::from_secs(POLL_INTERVAL_SECS));
    let mut reload_tick = interval(Duration::from_secs(RELOAD_CHECK_SECS));
    // Skip the first immediate tick on both timers — we want a full
    // delay before the first poll so the gateway has time to finish
    // initialisation.
    tick.tick().await;
    reload_tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                crate::loop_health::record_tick("heartbeat_scheduler", POLL_INTERVAL_SECS);
                crate::backup_overdue::check(&state).await;
                if let Err(e) = poll_and_dispatch(state.clone()).await {
                    tracing::warn!(error = %e, "heartbeat_loop_poll_error");
                }
            }
            _ = reload_tick.tick() => {
                if let Err(e) = check_reload(state.clone()).await {
                    tracing::warn!(error = %e, "heartbeat_loop_reload_error");
                }
            }
        }
    }
}

/// If the reload flag is set, recompute `next_run` for every enabled
/// task using the current cron + TZ. Does NOT fire tasks — just reseats
/// the schedule so UI edits take effect without a restart.
async fn check_reload(state: Arc<AppState>) -> Result<(), sqlx::Error> {
    let Some(redis) = state.redis.as_ref() else { return Ok(()); };
    let flag = redis.get_string(RELOAD_FLAG_KEY).await;
    if flag.as_deref() != Some("1") {
        return Ok(());
    }
    redis.set_string(RELOAD_FLAG_KEY, "0").await;

    let tz = heartbeat_actions::resolve_tz();
    let now = Utc::now();

    let rows = sqlx::query(
        "SELECT id, schedule \
         FROM noo_heartbeat_tasks \
         WHERE enabled = true"
    )
    .fetch_all(&state.db)
    .await?;

    let mut updated = 0usize;
    for row in rows {
        let task_id: String = row.try_get("id")?;
        let schedule: String = row.try_get("schedule")?;
        let next_run = match heartbeat_actions::compute_next_run(&schedule, now, tz) {
            Some(ts) => ts,
            None => continue,
        };
        let _ = crate::repo::heartbeat::set_next_run(&state.db, &task_id, next_run).await;
        updated += 1;
    }
    tracing::info!(reseated = updated, tz = %tz, "heartbeat_loop_reload_applied");
    Ok(())
}

async fn poll_and_dispatch(state: Arc<AppState>) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let tz = heartbeat_actions::resolve_tz();

    // SELECT tasks that are due. A task is due when:
    //   enabled = true
    //   AND (next_run IS NULL OR next_run <= NOW())
    //
    // NULL next_run handles freshly-created tasks that haven't been
    // scheduled yet — we'll compute their next run from `now` after firing.
    let rows = sqlx::query(
        "SELECT id, schedule \
         FROM noo_heartbeat_tasks \
         WHERE enabled = true \
           AND (next_run IS NULL OR next_run <= $1) \
         ORDER BY next_run NULLS FIRST \
         LIMIT 50"
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    tracing::info!(due_count = rows.len(), "heartbeat_loop_tick");

    // Two-phase dispatch so cron tasks at the same tick run in parallel
    // instead of queuing behind each other:
    //
    //   Phase 1 (synchronous, per row): update next_run / disable broken
    //     cron BEFORE spawning execution. If we waited until after
    //     execute_task to update next_run, the next tick (60s later) could
    //     re-pick a still-running task because next_run hadn't advanced yet.
    //
    //   Phase 2 (concurrent): spawn execute_task as a background task.
    //     Each task writes its own noo_heartbeat_runs row, so the runs
    //     are isolated. poll_and_dispatch returns immediately — long
    //     tasks don't block the next 60s tick.
    //
    // Errors inside the spawned task are logged but never propagated;
    // execute_task records status="error" in the runs table so it's
    // visible to the operator without crashing the loop.
    let mut spawned = 0usize;
    for row in rows {
        let task_id: String = row.try_get("id")?;
        let schedule: String = row.try_get("schedule")?;

        let next_run_at = heartbeat_actions::compute_next_run(&schedule, now, tz);

        match next_run_at {
            Some(ts) => {
                if let Err(e) =
                    crate::repo::heartbeat::set_next_run(&state.db, &task_id, ts).await
                {
                    tracing::warn!(task_id = %task_id, error = %e, "heartbeat_next_run_update_failed");
                    continue;
                }
            }
            None => {
                tracing::error!(
                    task_id = %task_id,
                    schedule = %schedule,
                    "heartbeat_invalid_cron_disabling_task"
                );
                let _ = crate::repo::heartbeat::set_enabled(&state.db, &task_id, false).await;
                continue;
            }
        }

        let state_clone = state.clone();
        let task_id_owned = task_id.clone();
        tokio::spawn(async move {
            if let Err(e) = execute_task(state_clone, &task_id_owned).await {
                tracing::warn!(
                    task_id = %task_id_owned,
                    error = %e,
                    "heartbeat_task_execute_failed"
                );
            }
        });
        spawned += 1;
    }

    if spawned > 0 {
        tracing::info!(spawned, "heartbeat_loop_dispatched_parallel");
    }

    Ok(())
}

/// Mark Rust-path `running` rows from a previous gateway process as
/// errored (they cannot have survived the restart), and delegate rows
/// already past the abandonment deadline (their reconcile ledger may have
/// died with redis). Recent delegate rows are left for the reconciler.
async fn sweep_orphaned_runs(state: &Arc<AppState>) {
    // A queued database_backup is `running` BY DESIGN: hostd is still dumping,
    // possibly across this restart, and backup_completion settles it from the
    // result file (or fails it at its own deadline). Sweeping it here would
    // record "gateway restarted mid-run" for a dump that is fine.
    let rows: Vec<(String, String, String)> = match sqlx::query_as(
        "SELECT run_id, task_id, action FROM noo_heartbeat_runs          WHERE status = 'running'          AND COALESCE(result_text, '') NOT LIKE $1",
    )
    .bind(format!("{}%", crate::backup_completion::PENDING_MARKER))
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "heartbeat_orphan_sweep_query_failed");
            return;
        }
    };
    let deadline = chrono::Utc::now()
        - chrono::Duration::seconds(crate::heartbeat_reconcile::deadline_secs());
    let mut swept = 0usize;
    for (run_id, task_id, action) in rows {
        let is_delegate = matches!(
            heartbeat_actions::action_path(&action),
            heartbeat_actions::ActionPath::PythonDelegate
        );
        let clause = if is_delegate {
            // only if already past the abandonment deadline
            "UPDATE noo_heartbeat_runs SET status='error', completed_at=NOW(),              error='abandoned: dispatched before a gateway restart and never              reported an outcome'              WHERE run_id = $1 AND status='running' AND started_at < $2"
        } else {
            "UPDATE noo_heartbeat_runs SET status='error', completed_at=NOW(),              error='gateway restarted mid-run'              WHERE run_id = $1 AND status='running' AND started_at < $2"
        };
        let cutoff = if is_delegate { deadline } else { chrono::Utc::now() };
        match sqlx::query(clause).bind(&run_id).bind(cutoff).execute(&state.db).await {
            Ok(r) if r.rows_affected() > 0 => {
                swept += 1;
                tracing::warn!(run_id = %run_id, task_id = %task_id, action = %action,
                    "heartbeat_orphaned_run_swept");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(run_id = %run_id, error = %e,
                "heartbeat_orphan_sweep_update_failed"),
        }
    }
    if swept > 0 {
        tracing::info!(swept, "heartbeat_orphan_sweep_complete");
    }
}

/// Hold scheduling until the cluster can actually serve work: a node with
/// a fresh heartbeat, or the grace ceiling (NOO_HEARTBEAT_BOOT_GRACE_SECS,
/// default 180) — whichever first. Tasks due during the hold fire on the
/// first poll after it lifts instead of burning their run against an
/// empty cluster.
async fn wait_for_cluster_warm(state: &Arc<AppState>) {
    let grace = std::env::var("NOO_HEARTBEAT_BOOT_GRACE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(180);
    let start = Instant::now();
    loop {
        let alive: Option<i64> = sqlx::query_scalar(
            "SELECT count(*) FROM cluster_nodes              WHERE last_heartbeat > NOW() - INTERVAL '90 seconds'",
        )
        .fetch_one(&state.db)
        .await
        .ok();
        if alive.unwrap_or(0) > 0 {
            tracing::info!(
                waited_s = start.elapsed().as_secs(),
                "heartbeat_boot_grace_lifted_cluster_warm"
            );
            return;
        }
        if start.elapsed().as_secs() >= grace {
            tracing::warn!(
                grace_s = grace,
                "heartbeat_boot_grace_expired_no_nodes — scheduling anyway"
            );
            return;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Execute a single heartbeat task by ID. Records the run in
/// `noo_heartbeat_runs`, updates `last_run` on the task, and dispatches
/// the result to any `(channel, recipient)` pairs configured on the
/// task. Long results are sent as `.md` attachments where the adapter
/// supports file uploads (Google Chat) so the full report doesn't get
/// truncated by per-message char limits.
pub async fn execute_task(state: Arc<AppState>, task_id: &str) -> Result<(), String> {
    let task = sqlx::query_as::<_, (
        String, String, String, String, Value, Value, Value, bool,
    )>(
        "SELECT id, name, schedule, action, \
                COALESCE(config, '{}'::jsonb), \
                COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), \
                enabled \
         FROM noo_heartbeat_tasks WHERE id = $1"
    )
    .bind(task_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("db_lookup_failed: {e}"))?;

    let (_, task_name, _schedule, action, config, channels, recipients, _enabled) =
        match task {
            Some(t) => t,
            None => return Err(format!("task_not_found: {task_id}")),
        };

    let run_id = uuid::Uuid::new_v4().to_string()[..12].to_string();
    let started_at = Utc::now();
    let start_instant = Instant::now();

    // One run per task at a time: skip this tick when a run is live
    // (typically a manual run, or the previous tick of a long task).
    let _in_flight = match heartbeat_actions::try_begin_run(task_id, &run_id) {
        Ok(g) => g,
        Err(existing) => {
            tracing::info!(
                task_id = %task_id, running_run_id = %existing,
                "heartbeat_tick_skipped_task_already_running"
            );
            return Ok(());
        }
    };

    // Start row: in-flight runs are visible in history, not only in logs.
    // Python delegates update this same row via the run_id in their
    // dispatch payload; the Rust paths complete it below.
    if let Err(e) = crate::repo::heartbeat::record_run_start(
        &state.db, &run_id, task_id, &task_name, &action, started_at,
    )
    .await
    {
        tracing::warn!(task_id = %task_id, error = %e, "heartbeat_run_start_row_failed");
    }

    let prompt = heartbeat_actions::build_action_prompt(&action, &task_name, &config);
    // For research_report / research_and_send, append summaries of recent
    // prior runs so the model targets novel angles instead of rehashing
    // earlier reports. No-op for other actions.
    let prompt = heartbeat_actions::enrich_research_prompt_with_history(
        prompt,
        &state.db,
        &action,
        task_id,
    )
    .await;

    // Summaries are written from the record of what the operator was told
    // and what is still open, not from the model's guess at "no errors".
    let prompt = crate::alert_digest::enrich_prompt(prompt, &state, &action, &config).await;

    let conversation_id =
        heartbeat_actions::build_conversation_id(task_id, &run_id, &action, &config);
    // Per-task max_iterations override via task.config.max_iterations.
    // Default 15 — research/report tasks need RAG + 2-3 web searches + a
    // synthesis pass, and pre-synthesis planning often eats 1-2 iterations
    // before the real work starts. The old default of 5 cut off long-form
    // tasks mid-plan with only the planning text in the response.
    let max_iterations: u32 = config
        .get("max_iterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(15);

    // Three action paths (see heartbeat_actions::action_path):
    //   - RustLlm:        build prompt → coordinator::run (LLM loop)
    //   - RustNative:     pure data/orchestration handler in Rust
    //   - PythonDelegate: ML-touching actions still in Python (NATS)
    //
    // PythonDelegate early-returns because Python writes its own
    // noo_heartbeat_runs row; for the other two paths we own the row.
    // Artifacts written by the action itself (as opposed to attachments
    // generated from long result text in notify_channels).
    let mut native_artifacts: Vec<String> = Vec::new();
    // A system action's channel lines (heartbeat_actions::SystemReport).
    let mut native_system: Option<(String, bool)> = None;
    let (mut status, result_text, mut error_text) = match heartbeat_actions::action_path(&action) {
        heartbeat_actions::ActionPath::PythonDelegate => {
            // Degradation contract: the only
            // delegated actions left are the trellion pack's ML pair —
            // on a trellion-less install they record an honest error
            // (never a timeout that rots as "running").
            if !crate::addons::trellion_intel_enabled() {
                (
                    "error".to_string(),
                    String::new(),
                    format!("action '{action}' requires the trellion-intel add-on: {}", crate::addons::intel_refusal_msg()),
                )
            } else {
                // Convert the RAII claim into a delegate claim: the run
                // finishes in the Python worker, so the reconciler releases
                // it on the terminal verdict — dropping the guard here
                // would free the task while it is still executing remotely.
                std::mem::forget(_in_flight);
                delegate_to_python(&state, task_id, &task_name, &action, &run_id).await;
                return Ok(());
            }
        }
        heartbeat_actions::ActionPath::RustNative => {
            match heartbeat_actions::run_rust_native_task(&state, task_id, &action, &config).await {
                Ok(outcome) => {
                    // Queued, not done (database_backup): leave the run
                    // `running` for its completion hook and return. Recording
                    // success here is the silent-success bug.
                    if outcome.pending {
                        if matches!(
                            crate::backup_completion::park_run(&state.db, &run_id, &outcome.text).await,
                            Ok(true)
                        ) {
                            if let Err(e) = crate::repo::heartbeat::set_last_run(&state.db, task_id, started_at).await {
                                tracing::warn!(task_id = %task_id, error = %e, "heartbeat_last_run_update_failed");
                            }
                            tracing::info!(task_id = %task_id, run_id = %run_id, action = %action, "heartbeat_run_queued_pending_completion");
                            return Ok(());
                        }
                        // The pending marker is the only thing the hook finds
                        // the run by. Without it the run would sit `running`
                        // until the next restart: fail it loudly instead.
                        tracing::error!(task_id = %task_id, run_id = %run_id, "database_backup_park_failed");
                        (
                            "error".to_string(),
                            String::new(),
                            "Database backup was queued, but its pending state could not be recorded, \
                             so nothing will confirm it. Look for the result file in the host spool."
                                .to_string(),
                        )
                    } else {
                        // Files the action wrote itself (write_log). Merged with
                        // the generated attachments from notify_channels below —
                        // Python tracks these separately on _current_artifacts.
                        native_artifacts = outcome.artifacts;
                        native_system = outcome.channel.map(|c| (c, outcome.has_detail));
                        ("success".to_string(), outcome.text, String::new())
                    }
                }
                Err(e) => {
                    tracing::warn!(task_id = %task_id, action = %action, error = %e, "rust_native_action_failed");
                    ("error".to_string(), String::new(), e)
                }
            }
        }
        // A misconfigured `channel_message` is a failed run, not a success
        // carrying a complaint (the defect that hid daily_digest_gchat's
        // 401s behind `status=success` for days).
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
            tracing::warn!(task_id = %task_id, reason = %reason, "channel_message_misconfigured");
            ("error".to_string(), String::new(), reason)
        }
        // `goal_review` with no goals needs no model — Python returned the
        // plain text without an LLM call (success, not error: an empty goal
        // list is a valid configuration, just nothing to review).
        heartbeat_actions::ActionPath::RustLlm
            if heartbeat_actions::goal_review_no_goals(&action, &config).is_some() =>
        {
            (
                "success".to_string(),
                heartbeat_actions::goal_review_no_goals(&action, &config)
                    .unwrap_or_default(),
                String::new(),
            )
        }
        // A `channel_message` carrying a literal `config.message` needs no
        // model — the configured text is itself the payload.
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
        // run_llm_action owns model resolution (config.model), the phased
        // research pipeline with single-shot fallback, usage recording and
        // the corrective retry — shared with routes::intelligence so the
        // cron tick and "run now" cannot drift.
        heartbeat_actions::ActionPath::RustLlm => match heartbeat_actions::run_llm_action(
            &state,
            &action,
            task_id,
            &config,
            &prompt,
            &conversation_id,
            max_iterations,
        )
        .await
        {
            Ok(text) => ("success".to_string(), text, String::new()),
            Err(e) => {
                tracing::warn!(task_id = %task_id, error = %e, "heartbeat_loop_coordinator_error");
                ("error".to_string(), String::new(), e.to_string())
            }
        },
    };

    // Dispatch to configured channels. We do this on success only —
    // sending an empty/error body to a channel is noisier than useful.
    let (notified, mut artifacts, delivery_failed) = if status == "success" && !result_text.is_empty() {
        // Ingest the finished report into the local KB so future runs
        // (and `noo_rag_query` callers) can see it. Best-effort and
        // a no-op for non-research actions.
        heartbeat_actions::ingest_report_to_kb(
            &state,
            task_id,
            &task_name,
            &action,
            &run_id,
            &result_text,
        ).await;
        heartbeat_actions::notify_channels(
            task_id,
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

    // Files the action wrote itself are recorded regardless of whether
    // channel delivery ran — write_log's output is the point of the task,
    // so it must land in noo_heartbeat_runs.artifacts even with no channels
    // configured (the branch above yields empty vectors in that case).
    artifacts.extend(native_artifacts);

    // Surface delivery failures. The run still counts as success (the
    // artifact exists in result_text and the KB), but a generated-and-
    // never-delivered report must not be silent: record the failed
    // channels in the run's error column and alert the operator
    // (cooldown-deduplicated per task; the alert channel may differ
    // from the failing task channel, so this often still gets through).
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
                task_id,
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

    // Quality reclassification: an LLM action whose output failed the
    // usability gate (stub, stall narration, too short) is a FAILED run,
    // not a success — record it as error so (a) the prior-research
    // enrichment (filters status='success') never feeds stubs back into
    // future prompts as "prior research", and (b) the meta loop's
    // failure queries (status='error') see it for Phase 2a retry /
    // Phase 2b escalation. Runs after notify_channels, which has already
    // dispatched the inline "unusable output" note to channels.
    // RustNative actions are exempt — their short outputs (e.g. 55-char
    // cluster_health lines) are legitimately terse.
    // An operator-authored literal `channel_message` is likewise exempt —
    // a deliberate one-line notice is not a failed report.
    if status == "success"
        && heartbeat_actions::literal_channel_message(&action, &config).is_none()
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
    let completed_at = Utc::now();

    // Both writes remain non-fatal: the task has ALREADY run, and its side
    // effects (a backup taken, a report sent) are done. Aborting here would
    // not undo them, so failing the run is the wrong response.
    //
    // But non-fatal must not mean unobserved. These were `let _ =`, so a failed
    // run-record write left NO trace: the runs table is the only durable record
    // that a scheduled task executed, and losing it silently makes a task that
    // ran look identical to one that never fired. That is the #247 shape — a
    // failure that reports as nothing at all.
    //
    // The task_failed alert above works off in-memory `status`, so it still
    // fires when the database is unreachable. The run record does not, which is
    // exactly why its loss needs its own alarm rather than sharing that one.
    let notified_json = json!(notified);
    let artifacts_json = json!(artifacts);
    let record_res = crate::repo::heartbeat::complete_run(
        &state.db,
        &crate::repo::heartbeat::RunRecord {
            run_id: &run_id,
            task_id,
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
    .await;

    if let Err(e) = record_res {
        tracing::error!(
            task_id = %task_id,
            task_name = %task_name,
            action = %action,
            run_id = %run_id,
            status = %status,
            error = %e,
            "heartbeat_run_record_write_failed"
        );
        // Deduped per task on the same 1h cooldown as task_failed: a database
        // outage would otherwise alert once per task per tick.
        crate::operator_alert::send_operator_alert_with(
            &state,
            crate::operator_alert::OperatorAlert::new(
                "heartbeat.run_record_lost",
                task_id,
                format!(
                    "⚠️ Heartbeat task '{task_name}' ({action}) RAN (status={status}) but its \
                     run record could not be written (run `{run_id}`). The runs table \
                     is missing this execution — it will look as though the task never fired."
                ),
            )
            .detail(e.to_string())
            .investigate("noo stack status"),
            3600,
        )
        .await;
    }

    if let Err(e) = crate::repo::heartbeat::set_last_run(&state.db, task_id, started_at).await {
        // Lower severity: next_run was already advanced in phase 1, so a missed
        // last_run stamp skews operator-facing "when did this last run" display
        // without causing a re-fire.
        tracing::warn!(
            task_id = %task_id,
            error = %e,
            "heartbeat_last_run_update_failed"
        );
    }

    tracing::info!(
        task_id = %task_id,
        task_name = %task_name,
        action = %action,
        status = %status,
        duration_ms = duration_ms,
        notified = ?notified,
        artifacts = artifacts.len(),
        "heartbeat_loop_task_complete"
    );

    // A task that FAILED must reach a human. Until now the only operator alert
    // in this loop fired for delivery failures, so a task failing outright — a
    // backup that never ran, an audit rotation that didn't rotate, retention
    // that didn't prune — produced just a log line and a runs-table row nobody
    // reads. That is how database_backup stayed broken for weeks. Cooldown-
    // deduped per task, so a persistently broken task alerts hourly, not every run.
    if status == "error" {
        let detail: String = if error_text.is_empty() {
            "no error detail recorded".to_string()
        } else {
            error_text.chars().take(300).collect()
        };
        // The failure text is evidence for the log, not the channel: it is
        // whatever the action's error was — an upstream body, a path, a DSN.
        crate::operator_alert::send_operator_alert_with(
            &state,
            crate::operator_alert::OperatorAlert::new(
                "heartbeat.task_failed",
                task_id,
                format!("❌ Heartbeat task '{task_name}' ({action}) FAILED (run `{run_id}`)."),
            )
            .detail(detail)
            .investigate(format!("noo heartbeat history --task-id {task_id} --limit 5")),
            3600,
        )
        .await;
    }

    // Phase B activity linkage: if the task's config carries an
    // `activity_id`, append a progress entry to that activity so it
    // accumulates state across runs. No-op when the field is missing.
    if let Some(activity_id_str) = config.get("activity_id").and_then(|v| v.as_str()) {
        if let Ok(activity_uuid) = uuid::Uuid::parse_str(activity_id_str) {
            let entry = serde_json::json!({
                "at": Utc::now().to_rfc3339(),
                "kind": if status == "success" { "task_completed" } else { "task_failed" },
                "summary": format!(
                    "Task '{}' ({}) {} in {}ms",
                    task_name, action, status, duration_ms
                ),
                "task_id": task_id,
                "run_id": run_id,
                "result_chars": result_text.chars().count(),
            });
            if let Err(e) = crate::agent_activities::append_progress(
                &state.db, activity_uuid, entry,
            ).await {
                tracing::debug!(
                    activity_id = %activity_id_str,
                    error = %e,
                    "activity_progress_append_failed"
                );
            }
        }
    }

    Ok(())
}

/// Delegate a heartbeat task to the Python worker via NATS. Used for
/// system actions (graph_signals, thought_experiment, cluster_health,
/// cost_report, security_audit, etc.) that have real Python
/// implementations in `noomesh.gateway.heartbeat._dispatch`.
///
/// Python's `_heartbeat_run_task` calls `HeartbeatScheduler.run_task_now`
/// which executes the action handler and writes a `noo_heartbeat_runs`
/// row. We don't insert another row here — Python already did, and the caller
/// early-returns, so notify_channels + DB-insert are skipped (Python handles
/// dispatch + persistence end-to-end).
///
/// Because the caller early-returns, this function owns failure alerting for
/// the delegate path: nothing downstream ever sees the result.
/// Dispatch a Python-delegated task and return immediately.
///
/// This used to be a synchronous NATS `request`, which made
/// `NOO_WORKER_TIMEOUT_SECS` (120s) an effective deadline on the task itself.
/// Real work exceeds it routinely — `graph_signals` at 392s and
/// `structured_research` at 135s both SUCCEEDED and both were reported as
/// failures, paging the operator for healthy tasks.
///
/// The outcome is no longer read from the NATS reply. Python is the writer of
/// record (`store.save_run`), so `heartbeat_reconcile` resolves each dispatch
/// against `noo_heartbeat_runs` instead. That module carries the full
/// rationale, including why a Redis ledger is required rather than just
/// querying the table (a worker that dies mid-task writes no row at all).
async fn delegate_to_python(
    state: &Arc<AppState>,
    task_id: &str,
    task_name: &str,
    action: &str,
    run_id: &str,
) {
    // Surface routing: ML actions go to the trellion-gated subject
    // so they land on the container that has the ML tree — the core
    // dispatch shell would answer them with a success-shaped "not
    // available" no-op. When the add-on is deliberately OFF, record an
    // honest skipped run and return WITHOUT a ledger entry: an operator
    // who turned trellion off must not receive "worker may have died"
    // abandonment alerts for work that cannot exist.
    let subject = if crate::heartbeat_actions::is_trellion_action(action) {
        if !crate::addons::trellion_intel_enabled() {
            let now = chrono::Utc::now();
            let run_id = uuid::Uuid::new_v4().to_string()[..12].to_string();
            let empty = serde_json::json!([]);
            let skipped = format!(
                "Skipped: '{action}' requires the trellion-intel add-on, which is \
                 not available on this install ({})",
                crate::addons::intel_refusal_msg()
            );
            if let Err(e) = crate::repo::heartbeat::record_run(
                &state.db,
                &crate::repo::heartbeat::RunRecord {
                    run_id: &run_id,
                    task_id,
                    task_name,
                    action,
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
            .await
            {
                tracing::error!(
                    task_id = %task_id, action = %action, error = %e,
                    "heartbeat_skip_record_write_failed"
                );
            }
            tracing::info!(
                task_id = %task_id, action = %action,
                "heartbeat_ml_action_skipped_addon_disabled"
            );
            return;
        }
        "worker.api.heartbeat.run_ml"
    } else {
        "worker.api.heartbeat.run"
    };

    // Ledger BEFORE publishing. Ordering matters: if we published first and
    // then failed to record, a task that died would have no ledger entry and
    // would go unnoticed — the failure mode this whole change is meant to
    // preserve coverage of. A ledger entry with no dispatch is merely a
    // spurious "abandoned" alert, which is the safer way to be wrong.
    let dispatch = crate::heartbeat_reconcile::Dispatch {
        task_id: task_id.to_string(),
        task_name: task_name.to_string(),
        action: action.to_string(),
        dispatched_at: chrono::Utc::now().timestamp(),
    };
    crate::heartbeat_reconcile::record_dispatch(state, &dispatch).await;

    // publish_fire_and_forget already retries and DLQs on exhaustion, so a
    // NATS blip does not silently drop the task.
    // The heartbeat is an internal actor, and it is the one that needs the
    // whole knowledge base (research/reindex actions run over every tier),
    // so it is one of the two places `kb:unrestricted` is granted. It is
    // still NOT an admin: it cannot manage users, keys or posture.
    //
    // `with_internal` wraps the call rather than the spawn because
    // `publish_fire_and_forget` captures the principal synchronously,
    // before it spawns — see `worker_client::publish_fire_and_forget_inner`.
    crate::bus_principal::with_internal(
        "heartbeat",
        &["read", "write", crate::bus_principal::SCOPE_KB_UNRESTRICTED],
        async {
            crate::worker_client::publish_fire_and_forget(
                state.nats.clone(),
                state.db.clone(),
                subject,
                crate::heartbeat_reconcile::dispatch_payload(task_id, run_id),
            );
        },
    )
    .await;

    tracing::info!(
        task_id = %task_id, action = %action, subject = %subject, run_id = %run_id,
        "heartbeat_python_delegate_dispatched"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_run_in_et_matches_local_8am() {
        // 8 AM ET on a fixed day — verify the cron evaluator returns the
        // matching UTC instant rather than 8 AM UTC.
        let tz: chrono_tz::Tz = "America/New_York".parse().unwrap();
        // Pick a moment just before 8 AM ET in winter (EST = UTC-5).
        let from = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = heartbeat_actions::compute_next_run("0 8 * * *", from, tz)
            .expect("next run resolves");
        // 8 AM EST on 2026-01-15 = 13:00 UTC.
        let expected = chrono::DateTime::parse_from_rfc3339("2026-01-15T13:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(next, expected);
    }
}
