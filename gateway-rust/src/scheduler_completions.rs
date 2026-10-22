// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Job lifecycle consumer — `events.job.ack|complete|failed` in Rust.
//!
//! Part of the scheduler port. The Go node-agent publishes
//! these three events (`internal/jobs/executor.go`); until now only Python
//! consumed them, via the JetStream durables `scheduler_job_ack`,
//! `scheduler_job_complete`, `scheduler_job_failed`.
//!
//! # One consumer, not two
//!
//! This module uses its OWN durable, [`DURABLE`], rather than binding the
//! Python names. During phase 6 that mattered because both consumers could
//! exist: two durables on the same subject each receive a full copy of
//! every message, so single-ownership came from the engine flag, not from
//! NATS. Phase 7 removed Python's `listen_completions()` entirely, so this
//! is now the only consumer of the job lifecycle.
//!
//! The durable name stays as-is. Renaming it to the Python one would take
//! over a consumer with a stale stream position and replay whatever it had
//! not seen; and two clients on one durable split messages arbitrarily,
//! which turns any future mistake into *half-working* completion handling
//! rather than an obvious duplicate.
//!
//! # Deliver policy
//!
//! `DeliverPolicy::New`. `EVENTS` retains 24h, so a durable created with
//! the default (`All`) would replay a day of completions on first flip —
//! rewriting job hashes that already settled and inserting a day of
//! `noo_job_runs` rows. The terminal script would reject most of them, but
//! "mostly rejected" is not a thing to rely on at cutover.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::scheduler_engine::{self, num, JOB_KEY_PREFIX};
use crate::state::AppState;

/// Rust-side durable. Deliberately distinct from Python's
/// `scheduler_job_{ack,complete,failed}` — see module docs.
pub const DURABLE: &str = "rust_scheduler_jobs";
const STREAM: &str = "EVENTS";
/// One consumer for the three lifecycle subjects. `events.job.cancel` also
/// matches and is acked-and-ignored: it is a scheduler→node instruction,
/// not a report about a job we own.
///
/// A multi-token `>` rather than the old single-token `*` because node
/// agents now report on `events.job.<kind>.<node_id>`
/// and a mixed fleet publishes BOTH shapes: the fleet upgrades node by
/// node, and a node still on the old build must keep being heard. See
/// [`parse_subject`].
const FILTER_SUBJECT: &str = "events.job.>";

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run(state.clone()).await {
                tracing::warn!(error = %e, "scheduler_completions.consumer_failed — retrying in 30s");
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

async fn run(state: Arc<AppState>) -> anyhow::Result<()> {
    use async_nats::jetstream::consumer::{pull::Config, AckPolicy, DeliverPolicy};
    use futures::StreamExt;

    let stream = state.js.get_stream(STREAM).await?;
    let config = Config {
        durable_name: Some(DURABLE.to_string()),
        filter_subject: FILTER_SUBJECT.to_string(),
        deliver_policy: DeliverPolicy::New,
        ack_policy: AckPolicy::Explicit,
        ..Default::default()
    };
    // The durable already exists on every live controller with the older
    // `events.job.*` filter. Servers that accept a filter-subject update
    // take the first path; one that refuses the change would otherwise
    // leave the gateway permanently blind to the node-scoped subjects, so
    // delete and recreate. That is cheap here and only here: the deliver
    // policy is `New`, so a fresh consumer starts at the head of the
    // stream rather than replaying a day of settled completions.
    let consumer = match stream.get_or_create_consumer(DURABLE, config.clone()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                durable = DURABLE,
                "scheduler_completions: recreating the durable to widen its filter subject"
            );
            let _ = stream.delete_consumer(DURABLE).await;
            stream.get_or_create_consumer(DURABLE, config).await?
        }
    };
    tracing::info!(durable = DURABLE, "scheduler_completions: consuming job lifecycle events");

    let mut messages = consumer.messages().await?;
    while let Some(msg) = messages.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "scheduler_completions.message_error");
                continue;
            }
        };
        let subject = msg.subject.to_string();
        let event: Value = serde_json::from_slice(&msg.payload).unwrap_or(Value::Null);
        // Ack first: these handlers are idempotent (the terminal script is
        // exactly-once by state, the ack handler is a plain HSET), so a
        // redelivery loop on a poisoned payload would cost more than a
        // dropped event.
        let _ = msg.ack().await;

        if let Err(e) = handle(&state, &subject, &event).await {
            tracing::warn!(subject = %subject, error = %e, "scheduler_completions.handler_failed");
        }
    }
    Ok(())
}

/// Split `events.job.<kind>[.<node_id>]` into its kind and the publishing
/// node, if the publisher named itself.
///
/// `None` for anything that is not one of those two shapes. A subject with
/// MORE tokens than expected is refused rather than read leniently: node
/// ids are sanitised to one token before publishing, so a deeper subject is
/// either a bug or someone trying to smuggle an origin past the check.
fn parse_subject(subject: &str) -> Option<(&str, Option<&str>)> {
    let rest = subject.strip_prefix("events.job.")?;
    match rest.split_once('.') {
        None if !rest.is_empty() => Some((rest, None)),
        Some((kind, node)) if !kind.is_empty() && !node.is_empty() && !node.contains('.') => {
            Some((kind, Some(node)))
        }
        _ => None,
    }
}

/// Whether a lifecycle event may act on this job.
///
/// The bus credential is shared today, so any holder of it can publish
/// `events.job.complete` for ANY job id and terminalise it, or
/// `events.job.failed` to burn its retry budget. Once the publisher names
/// itself in the subject, an event about a job dispatched somewhere else
/// can be refused.
///
/// Two cases are deliberately accepted:
///   * `origin: None` — the node still runs a older agent and
///     publishes the unsuffixed subject. The fleet upgrades node by node;
///     refusing here would strand every job on every un-upgraded node.
///   * the job has no `node_id` recorded — a requeue clears it, and a late
///     but honest completion from the node that had it must still land.
fn origin_matches(assigned_node: &str, origin: &str) -> bool {
    assigned_node.is_empty() || assigned_node == origin
}

async fn handle(state: &AppState, subject: &str, event: &Value) -> anyhow::Result<()> {
    let Some((kind, origin)) = parse_subject(subject) else {
        tracing::warn!(subject = %subject, "scheduler_completions.unparseable_subject");
        return Ok(());
    };
    let Some(job_id) = event.get("job_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
    else {
        return Ok(());
    };

    // `cancel` is a gateway→node instruction on this stream, not a report
    // about a job we own; it never carries an origin and is ignored below.
    if matches!(kind, "ack" | "complete" | "failed") {
        match origin {
            None => tracing::debug!(
                subject = %subject,
                job_id,
                "scheduler_completions.origin_unknown — node agent predates node-scoped job events"
            ),
            Some(origin) => {
                let assigned = assigned_node(state, job_id).await;
                if !origin_matches(&assigned, origin) {
                    tracing::warn!(
                        job_id,
                        event_node = %origin,
                        assigned_node = %assigned,
                        kind,
                        "scheduler_completions.origin_mismatch — refusing a job event from a node the job was not dispatched to"
                    );
                    return Ok(());
                }
            }
        }
    }

    match kind {
        "ack" => on_ack(state, job_id, origin).await,
        "complete" => on_complete(state, job_id, event, origin).await,
        "failed" => on_failed(state, job_id, event).await,
        _ => Ok(()), // cancel and anything else: not ours
    }
}

/// The node this job was dispatched to, or "" when nothing is recorded
/// (no Redis, unknown job, or a requeue that cleared the field).
///
/// A pulled job (`path=pull`, i179) was dispatched to nobody: any node that
/// serves the model may claim it, and JetStream may redeliver it to a
/// different one after the first acked. Its `node_id` only records the last
/// node to report, so it is never an assignment to enforce.
async fn assigned_node(state: &AppState, job_id: &str) -> String {
    let Some(redis) = state.redis.as_ref() else {
        return String::new();
    };
    let hash: HashMap<String, String> =
        redis.hgetall(&format!("{JOB_KEY_PREFIX}{job_id}")).await.unwrap_or_default();
    if hash.get("path").map(String::as_str) == Some("pull") {
        return String::new();
    }
    hash.get("node_id").cloned().unwrap_or_default()
}

/// Node acknowledged receipt and started working.
///
/// Also stamps `started_at`, which Python never wrote — `noo_job_runs`
/// needs a start instant to report `duration_ms`, and `dispatched_at`
/// (the fallback) includes queue-to-node latency.
async fn on_ack(state: &AppState, job_id: &str, origin: Option<&str>) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        return Ok(());
    };
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    if hash.is_empty() {
        return Ok(());
    }
    let status = hash.get("status").map(|s| s.as_str()).unwrap_or("");
    if scheduler_engine::TERMINAL_STATES.contains(&status) {
        // A late ack must not resurrect a job the reaper already killed.
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut fields: Vec<(&str, &str)> = vec![("status", "running"), ("updated_at", now.as_str())];
    if hash.get("started_at").map(|s| s.is_empty()).unwrap_or(true) {
        fields.push(("started_at", now.as_str()));
    }
    // A pulled job has no assignment until a worker claims it: record which
    // node did (the last one, if JetStream redelivers).
    if hash.get("path").map(String::as_str) == Some("pull") {
        if let Some(node) = origin {
            fields.push(("node_id", node));
        }
    }
    redis.hset(&key, &fields).await;
    tracing::debug!(job_id, "scheduler_completions.job_running");
    Ok(())
}

async fn on_complete(
    state: &AppState,
    job_id: &str,
    event: &Value,
    origin: Option<&str>,
) -> anyhow::Result<()> {
    // An embed_batch completion carries vectors: they move to a side key and
    // only a summary reaches the 24 h job hash (see `embed_jobs`).
    if let Some(redis) = state.redis.as_ref() {
        let hash: HashMap<String, String> =
            redis.hgetall(&format!("{JOB_KEY_PREFIX}{job_id}")).await.unwrap_or_default();
        if crate::embed_jobs::is_embed_job(&hash) {
            return crate::embed_jobs::on_complete(state, job_id, &hash, event, origin).await;
        }
    }
    let result = match event.get("result") {
        Some(Value::String(s)) => s.clone(),
        Some(v) if !v.is_null() => v.to_string(),
        _ => String::new(),
    };
    if scheduler_engine::terminalize(state, job_id, "completed", &result, "").await {
        tracing::info!(job_id, "scheduler_completions.job_completed");
    }
    Ok(())
}

/// Node reported failure — retry until `max_retries`, then dead.
///
/// `node_id` comes from the job hash, not the event: the Go agent publishes
/// only `{job_id, error}`, and without the node the retry cannot steer away
/// from the machine that just failed.
/// Whether a `job.failed` event should be retried on another node.
///
/// Absent = retryable: older node-agents publish only `{job_id, error}`,
/// and the pre-existing behaviour for those is the retry budget.
fn is_retryable(event: &Value) -> bool {
    event
        .get("retryable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

async fn on_failed(state: &AppState, job_id: &str, event: &Value) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        return Ok(());
    };
    let error = event
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown error")
        .to_string();
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    if hash.is_empty() {
        return Ok(());
    }
    // A pulled job's retry budget is the work queue's `max_deliver`, not
    // `max_retries`: requeueing here would put it on the node dispatch queue.
    if crate::embed_jobs::is_embed_job(&hash) {
        return crate::embed_jobs::on_failed(state, job_id, &hash, event).await;
    }
    let retries = num(&hash, "retries", 0);
    let max_retries = num(&hash, "max_retries", 2);
    let node_id = event
        .get("node_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| hash.get("node_id").cloned().unwrap_or_default());

    // A node that cannot execute the job type at all publishes
    // `retryable: false` (node-agent-go `internal/jobs/types.go`). Retrying
    // that is pure latency: every node runs the same executor, so the next
    // one rejects it too and the job only reaches a terminal state after
    // the whole retry budget. Fail it now, with the node's reason.
    if !is_retryable(event) {
        scheduler_engine::terminalize(state, job_id, "dead", "", &error).await;
        tracing::error!(job_id, error = %error, "scheduler_completions.job_dead_not_retryable");
        return Ok(());
    }

    if retries < max_retries {
        let msg = format!("{error} (retry {}/{max_retries})", retries + 1);
        scheduler_engine::requeue_for_retry(state, job_id, &node_id, retries + 1, &msg).await;
        tracing::warn!(job_id, retry = retries + 1, error = %error, "scheduler_completions.job_failed_retry");
    } else {
        let msg = format!("{error} (max retries exhausted)");
        scheduler_engine::terminalize(state, job_id, "dead", "", &msg).await;
        tracing::error!(job_id, error = %error, "scheduler_completions.job_dead");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_differs_from_python_durables() {
        // Python: scheduler_job_ack / scheduler_job_complete /
        // scheduler_job_failed (cluster/scheduler.py::listen_completions).
        // Colliding with any of them would split messages between the two
        // engines instead of giving each a full copy.
        for py in ["scheduler_job_ack", "scheduler_job_complete", "scheduler_job_failed"] {
            assert_ne!(DURABLE, py);
        }
    }

    #[test]
    fn filter_covers_both_subject_shapes() {
        // `>` and not `*`: the old single-token wildcard cannot match a
        // node-scoped subject, and a mixed fleet publishes both.
        assert_eq!(FILTER_SUBJECT, "events.job.>");
        for subject in [
            "events.job.ack",
            "events.job.complete",
            "events.job.failed",
            "events.job.complete.host9",
        ] {
            assert!(parse_subject(subject).is_some(), "{subject}");
        }
    }

    #[test]
    fn subject_kind_extraction() {
        assert_eq!(parse_subject("events.job.ack"), Some(("ack", None)));
        assert_eq!(parse_subject("events.job.complete"), Some(("complete", None)));
        assert_eq!(parse_subject("events.job.failed"), Some(("failed", None)));
        assert_eq!(parse_subject("events.job.cancel"), Some(("cancel", None)));
    }

    #[test]
    fn node_scoped_subject_yields_the_origin() {
        assert_eq!(parse_subject("events.job.complete.host9"), Some(("complete", Some("host9"))));
        assert_eq!(parse_subject("events.job.ack.host8"), Some(("ack", Some("host8"))));
        assert_eq!(parse_subject("events.job.failed.node_1"), Some(("failed", Some("node_1"))));
    }

    #[test]
    fn malformed_subjects_are_refused_not_guessed() {
        assert_eq!(parse_subject("events.job."), None);
        assert_eq!(parse_subject("events.job.complete."), None);
        // Deeper than the shape allows: a sanitised node id is one token, so
        // reading only the last one here would let an origin be smuggled in.
        assert_eq!(parse_subject("events.job.complete.a.b"), None);
        assert_eq!(parse_subject("events.node.registered"), None);
    }

    #[test]
    fn matching_node_is_accepted() {
        assert!(origin_matches("host9", "host9"));
    }

    #[test]
    fn mismatched_node_is_refused() {
        // The attack this closes: any holder of the shared bus credential
        // completing (or failing) a job dispatched to another machine.
        assert!(!origin_matches("host9", "attacker"));
        assert!(!origin_matches("host9", "HOST9"));
    }

    #[test]
    fn unrecorded_assignment_is_accepted() {
        // A requeue clears node_id; a late-but-honest completion from the
        // node that had the job must still be able to land.
        assert!(origin_matches("", "host9"));
    }

    #[test]
    fn retryable_defaults_to_true_when_absent() {
        // Older node-agents publish only {job_id, error}; those must keep
        // the retry budget they have always had.
        assert!(is_retryable(&serde_json::json!({"job_id": "x", "error": "boom"})));
    }

    #[test]
    fn explicit_false_disables_retry() {
        // What the node-agent sends when it has no executor for the type —
        // retrying it can only be rejected by the next node too.
        assert!(!is_retryable(&serde_json::json!({
            "job_id": "x",
            "error": "node host9 cannot execute job type \"test_run\"",
            "retryable": false,
        })));
    }

    #[test]
    fn explicit_true_keeps_retry() {
        assert!(is_retryable(&serde_json::json!({"retryable": true})));
    }

    #[test]
    fn non_bool_retryable_is_ignored() {
        assert!(is_retryable(&serde_json::json!({"retryable": "false"})));
    }
}
