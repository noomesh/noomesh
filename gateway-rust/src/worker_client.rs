// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! NATS-based worker delegation client with capability-aware fallback.
//!
//! Sends requests to Python worker pool via NATS request/reply.
//! Workers subscribe to `worker.{service}.{method}` subjects.
//!
//! Fallback chain for capability-based requests:
//!   1. Primary NATS subject (designated worker)
//!   2. Gossip peers with the capability (sorted by load)
//!   3. Local fallback subject (controller spins up service)
//!
//! Fire-and-forget publishes use `publish_fire_and_forget` which retries
//! transient failures and writes to a Postgres DLQ on exhaustion. The
//! Python `dlq_drain.py` worker recovers DLQ rows when NATS is back.

use anyhow::Result;
use serde_json::Value;
use std::time::Duration;


/// Backoffs applied between in-process retry attempts. Total worst-case
/// budget: ~21s (1 + 4 + 16). Beyond this we give up and DLQ to Postgres.
const PUBLISH_RETRY_BACKOFFS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(4),
    Duration::from_secs(16),
];

/// Worker timeout. Reads NOO_WORKER_TIMEOUT_SECS from env, defaults to 120s.
/// RAG queries can take 30-60s so this must be generous.
pub(crate) fn worker_timeout() -> Duration {
    static TIMEOUT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        let secs: u64 = crate::config::env_or_yaml_u64(
            "NOO_WORKER_TIMEOUT_SECS",
            |c| c.worker.timeout_secs,
            120,
        );
        Duration::from_secs(secs)
    })
}
const FAST_TIMEOUT: Duration = Duration::from_secs(5);

/// Send a request to a Python worker via NATS and await the response.
pub async fn request(
    nats: &async_nats::Client,
    subject: &str,
    payload: &Value,
) -> Result<Value> {
    request_with_timeout(nats, subject, payload, worker_timeout()).await
}

/// Send a request with a custom timeout.
pub async fn request_with_timeout(
    nats: &async_nats::Client,
    subject: &str,
    payload: &Value,
    timeout: Duration,
) -> Result<Value> {
    // Degradation contract: a knowledge-pack subject
    // on a trellion-less install refuses INSTANTLY here — the one choke
    // point every caller (routes, facades, coordinator recall, tools,
    // conversation tracking) already handles as an Err — instead of
    // burning the full NATS timeout and presenting as an outage.
    if crate::addons::is_trellion_subject(subject) && !crate::addons::trellion_enabled() {
        anyhow::bail!("{}: {subject}", crate::addons::DISABLED_MARKER);
    }
    if crate::addons::is_trellion_intel_subject(subject)
        && !crate::addons::trellion_intel_enabled()
    {
        anyhow::bail!("{}: {subject}", crate::addons::INTEL_DISABLED_MARKER);
    }
    let data = serde_json::to_vec(payload)?;

    // Every `worker.*` message carries the caller. See
    // `crate::bus_principal`. This module is the only place a worker message
    // leaves the gateway, and `tests/bus_principal_sites.rs` fails the build
    // if a publish appears anywhere else.
    let headers = crate::bus_principal::headers_for(subject);

    // The reply comes back on the SERVING principal's own inbox prefix, the
    // one its static publish grant names (i69/i70): a NATS config reload
    // wipes `allow_responses`, so a reply on the gateway's shared default
    // inbox would be refused whenever the request straddles a SIGHUP. The
    // worker's prefix for core subjects, an add-on's own for its subjects.
    let mut request = async_nats::Request::new()
        .payload(data.into())
        .inbox(crate::nats_credentials::scoped_inbox(nats, crate::nats_credentials::reply_prefix_for(subject)));
    if let Some(h) = headers {
        request = request.headers(h);
    }
    let response = tokio::time::timeout(timeout, nats.send_request(subject.to_string(), request))
    .await
    .map_err(|_| anyhow::anyhow!("Worker timeout on {subject}"))?
    .map_err(|e| anyhow::anyhow!("NATS request failed: {e}"))?;

    let value: Value = serde_json::from_slice(&response.payload)?;

    reply_result(subject, value)
}

/// A worker refused the request on purpose: a policy or request-validity
/// decision, not an outage. Carried as the `Err` payload so a route can
/// answer a 4xx (retrying will never help) instead of the 503 that means
/// "try again later". Only a worker that sends the structured `error_kind`
/// field produces this; an older worker sends none and keeps today's 503.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRefusal {
    pub kind: RefusalKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// `policy_refusal`: the request is not permitted (path confinement).
    Policy,
    /// `invalid_request`: the request is malformed or names something absent.
    Invalid,
}

impl RefusalKind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "policy_refusal" => Some(Self::Policy),
            "invalid_request" => Some(Self::Invalid),
            _ => None,
        }
    }
}

impl std::fmt::Display for WorkerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WorkerRefusal {}

/// Turn a decoded worker reply into the caller's `Result`. Split from
/// [`request_with_timeout`] so the success:false contract is testable without
/// a bus.
pub(crate) fn reply_result(subject: &str, value: Value) -> Result<Value> {
    // Check for worker-level errors. The worker pool's catch-all fallback
    // reports failures as {"success": false, "data": {"error": ...}} — the
    // error nested under `data` — so any success:false reply is an error,
    // whether the message sits at the top level or inside the envelope.
    // (Previously only top-level `error` was checked, which made unhandled
    // subjects look like successes and silently broke their features.)
    if value.get("success") == Some(&Value::Bool(false)) {
        let err = value
            .get("error")
            .and_then(|e| e.as_str())
            .or_else(|| value.get("data").and_then(|d| d.get("error")).and_then(|e| e.as_str()))
            .unwrap_or("worker reported success=false with no error message");
        let message = format!("Worker error on {subject}: {err}");
        // A structured kind (never message text) marks a deliberate refusal.
        let kind = value
            .get("error_kind")
            .or_else(|| value.get("data").and_then(|d| d.get("error_kind")))
            .and_then(|k| k.as_str())
            .and_then(RefusalKind::parse);
        if let Some(kind) = kind {
            return Err(anyhow::Error::new(WorkerRefusal { kind, message }));
        }
        return Err(anyhow::anyhow!(message));
    }

    Ok(value)
}

// `request_with_fallback` was removed. It was the only route to the
// `worker.{capability}.local` subjects (embedding/whisper capability-router
// fallbacks), and it had no callers — the compiler reported it as dead for
// some time. Its handlers are deleted too, so nothing is left to fall back
// to and nothing calls it.
pub fn publish_fire_and_forget(
    nats: async_nats::Client,
    db: sqlx::PgPool,
    subject: impl Into<String>,
    payload: Value,
) {
    publish_fire_and_forget_inner(nats, db, subject.into(), payload, None)
}

/// Variant used by call sites that have access to `MetricsState` so we can
/// count retry exhaustions and DLQ insert failures. Equivalent semantics
/// to `publish_fire_and_forget` otherwise.
pub fn publish_fire_and_forget_metered(
    nats: async_nats::Client,
    db: sqlx::PgPool,
    subject: impl Into<String>,
    payload: Value,
    metrics: std::sync::Arc<crate::metrics::MetricsState>,
) {
    publish_fire_and_forget_inner(nats, db, subject.into(), payload, Some(metrics))
}

fn publish_fire_and_forget_inner(
    nats: async_nats::Client,
    db: sqlx::PgPool,
    subject: String,
    payload: Value,
    metrics: Option<std::sync::Arc<crate::metrics::MetricsState>>,
) {
    // Captured HERE, not inside the spawn: a tokio task-local does not cross
    // `tokio::spawn`, so reading it on the other side would silently yield
    // the unattributed principal for every fire-and-forget publish in the
    // gateway. This one line is the difference between "the heartbeat is the
    // caller" and "nobody is".
    let principal = crate::bus_principal::current();
    // Same degradation contract as `request_with_timeout`: an add-on-owned
    // subject on an install without that add-on is refused HERE, counted,
    // and never reaches NATS. A publish has no reply, so without this the
    // message would be accepted by the server, delivered to nobody, and look
    // exactly like success — the shape `worker.retrieval.feedback` had for
    // months.
    if let Some(addon) = addon_refusing(&subject) {
        tracing::debug!(subject = %subject, addon, "publish refused: add-on not enabled");
        if let Some(m) = metrics.clone() {
            let mut labels = std::collections::HashMap::new();
            labels.insert("subject".to_string(), subject.clone());
            labels.insert("addon".to_string(), addon.to_string());
            tokio::spawn(async move {
                m.inc_counter("nats_publish_refused_addon_total", Some(&labels), 1).await;
            });
        }
        return;
    }
    tokio::spawn(async move {
        match publish_with_retry(&nats, &subject, &payload, &principal).await {
            Ok(()) => {}
            Err(retry_err) => {
                if let Some(m) = &metrics {
                    let mut labels = std::collections::HashMap::new();
                    labels.insert("subject".to_string(), subject.clone());
                    m.inc_counter("nats_publish_retry_exhausted_total", Some(&labels), 1)
                        .await;
                }
                if let Err(db_err) =
                    insert_dlq(&db, &subject, &payload, &retry_err.to_string(), &principal).await
                {
                    if let Some(m) = &metrics {
                        m.inc_counter("nats_dlq_insert_failed_total", None, 1).await;
                    }
                    tracing::error!(
                        subject = %subject,
                        nats_error = %retry_err,
                        db_error = %db_err,
                        "publish + DLQ both failed — message lost"
                    );
                } else {
                    tracing::warn!(
                        subject = %subject,
                        error = %retry_err,
                        "publish exhausted retries, written to DLQ"
                    );
                }
            }
        }
    });
}

/// The add-on that owns `subject` and is not enabled, if any — the reason a
/// publish is refused before it leaves the gateway.
fn addon_refusing(subject: &str) -> Option<&'static str> {
    if crate::addons::is_trellion_subject(subject) && !crate::addons::trellion_enabled() {
        return Some("trellion");
    }
    if crate::addons::is_trellion_intel_subject(subject)
        && !crate::addons::trellion_intel_enabled()
    {
        return Some("trellion_intel");
    }
    None
}

/// In-process retry loop. Returns Ok on first successful publish, or the
/// last error after all attempts have failed.
async fn publish_with_retry(
    nats: &async_nats::Client,
    subject: &str,
    payload: &Value,
    principal: &crate::bus_principal::Principal,
) -> Result<()> {
    let bytes = serde_json::to_vec(payload)?;
    // Re-signed per attempt on purpose: the backoff ladder runs to ~21s and
    // a principal is only fresh for 60s, so a token minted once up front
    // would arrive stale on the last retry and be refused for a reason that
    // has nothing to do with who is calling.
    let sign = || crate::bus_principal::headers_for_principal(principal, subject);
    // Attempt 0 — immediate, no backoff
    if let Ok(()) = publish_once(nats, subject, bytes.clone(), sign()).await {
        return Ok(());
    }
    // Attempts 1..=3 — exp backoff
    let mut last_err: Option<async_nats::PublishError> = None;
    for backoff in PUBLISH_RETRY_BACKOFFS {
        tokio::time::sleep(backoff).await;
        match publish_once(nats, subject, bytes.clone(), sign()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!(
                    subject,
                    backoff_secs = backoff.as_secs(),
                    error = %e,
                    "publish retry failed"
                );
                last_err = Some(e);
            }
        }
    }
    match last_err {
        Some(e) => Err(anyhow::anyhow!("publish exhausted retries: {e}")),
        None => Err(anyhow::anyhow!("publish exhausted retries (no recorded error)")),
    }
}

/// One publish, with the principal header when this process can sign.
async fn publish_once(
    nats: &async_nats::Client,
    subject: &str,
    bytes: Vec<u8>,
    headers: Option<async_nats::HeaderMap>,
) -> std::result::Result<(), async_nats::PublishError> {
    match headers {
        Some(h) => {
            nats.publish_with_headers(subject.to_string(), h, bytes.into())
                .await
        }
        None => nats.publish(subject.to_string(), bytes.into()).await,
    }
}

async fn insert_dlq(
    db: &sqlx::PgPool,
    subject: &str,
    payload: &Value,
    last_error: &str,
    principal: &crate::bus_principal::Principal,
) -> Result<()> {
    // A DLQ row can be replayed hours later, long after the signed header
    // that would have accompanied it expired. So the row carries the
    // principal's CLAIMS (never the signature — a stored signature is a
    // stored forgery waiting for a clock) under a reserved payload key, and
    // `dlq_drain` re-signs from them and strips the key before publishing.
    // A row without it replays as a scopeless `internal:dlq-drain`.
    let payload = dlq_row_payload(payload, principal);
    let payload = &payload;
    sqlx::query(
        "INSERT INTO noo_nats_dlq (subject, payload, attempt_count, last_error) \
         VALUES ($1, $2::jsonb, 0, $3)",
    )
    .bind(subject)
    .bind(serde_json::to_string(payload)?)
    .bind(crate::text::clip(last_error, 500))
    .execute(db)
    .await?;
    Ok(())
}

/// The payload exactly as a DLQ row stores it: the principal's claims
/// embedded, and the per-dispatch delegated user token
/// REMOVED — a bearer written to Postgres outlives the dispatch it was
/// minted for, and the drain would replay it. Pure, so the guard test pins
/// what reaches the table.
pub(crate) fn dlq_row_payload(payload: &Value, principal: &crate::bus_principal::Principal) -> Value {
    let mut payload = payload.clone();
    crate::worker_delegation::strip(&mut payload);
    crate::bus_principal::embed_for_dlq(&payload, principal)
}

/// Send a request and stream the response (for large results).
/// The worker publishes chunks to a reply subject.
pub async fn request_stream(
    nats: &async_nats::Client,
    subject: &str,
    payload: &Value,
) -> Result<async_nats::Subscriber> {
    // The serving principal's own reply prefix, as `request_with_timeout`.
    let inbox = crate::nats_credentials::scoped_inbox(nats, crate::nats_credentials::reply_prefix_for(subject));
    let sub = nats.subscribe(inbox.clone()).await?;

    let data = serde_json::to_vec(payload)?;
    match crate::bus_principal::headers_for(subject) {
        Some(h) => {
            nats.publish_with_reply_and_headers(subject.to_string(), inbox, h, data.into())
                .await?
        }
        None => nats.publish_with_reply(subject.to_string(), inbox, data.into()).await?,
    }

    Ok(sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the per-dispatch user token is a bearer. A DLQ row is
    /// persisted and replayed later, so the token must never reach it.
    #[test]
    fn a_dlq_row_never_carries_the_delegated_token() {
        let p = crate::bus_principal::Principal::user("alice", crate::auth::Role::User, vec!["read".into()]);
        let payload = serde_json::json!({
            "name": "noo_graph_stats",
            "arguments": {"q": 1},
            crate::worker_delegation::ENVELOPE_KEY: "eyJhbGciOiJFUzI1NiJ9.bearer.sig",
        });
        let row = dlq_row_payload(&payload, &p);
        let text = serde_json::to_string(&row).unwrap();
        assert!(!text.contains("bearer.sig"), "{text}");
        assert!(row.get(crate::worker_delegation::ENVELOPE_KEY).is_none());
        assert_eq!(row["arguments"], serde_json::json!({"q": 1}), "the rest of the payload survives");
    }

    /// And `insert_dlq` builds its row through that function — the pure
    /// test above is only worth something if the writer uses it.
    #[test]
    fn insert_dlq_writes_the_stripped_payload() {
        let src = include_str!("worker_client.rs");
        let body = src.split("async fn insert_dlq(").nth(1).expect("insert_dlq exists");
        let body = &body[..body.find("\n}\n").expect("end of insert_dlq")];
        assert!(body.contains("dlq_row_payload(payload, principal)"), "insert_dlq must store dlq_row_payload(..)");
    }
}
