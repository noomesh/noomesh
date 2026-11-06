// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Unified operator alert dispatch — the single funnel for "a human
//! should hear about this" messages from background loops (autonomy
//! evaluators, agent meta loop, loop-liveness monitor, watchdogs).
//!
//! Behaviors enforced here so every caller is consistent:
//! - **Cooldown/dedup** per (kind, target): Redis `SET NX EX` so a
//!   condition that holds across many evaluation ticks reaches the
//!   operator once per window, not once per tick. Falls back to an
//!   in-process map when Redis is unavailable.
//! - **On change, not on time** for *persisting* conditions
//!   ([`OperatorAlert::persisting`]): one alert at onset, silence while it
//!   holds, reminders at 4 h / 12 h / 24 h and then daily, and one
//!   "recovered" message (with how long it lasted) when the caller reports
//!   the condition clear ([`clear_operator_alert`]).
//! - **Maintenance mute**: alerts targeting a node in maintenance are not
//!   delivered (still logged and published to the stream; see
//!   [`crate::maintenance`]).
//! - **Grouping**: alerts raised within [`GROUP_WINDOW`] of each other are
//!   delivered as ONE message, rendered by `egress::system_group`, the same
//!   renderer a single alert uses, so detail stays out of every shape.
//! - **Delivery** via the channels/send loopback — same dispatch path,
//!   auth, and formatting as normal channel traffic. Channel + recipient
//!   come from `NOO_AGENT_ALERT_CHANNEL` / `NOO_AGENT_ALERT_RECIPIENT`
//!   (defaults: google_chat / broadcast).
//! - **Egress shaping**: an alert is structured data ([`OperatorAlert`]:
//!   summary, detail, one investigation command). The channel gets
//!   `egress::system`'s rendering — scrubbed summary, the command, a
//!   reference id; the detail is logged under that id (`operator_alert`)
//!   and never sent. See `crate::egress` for what may and may not leave.
//! - **Outcome logging** under stable event names
//!   (`operator_alert_sent` / `operator_alert_send_failed` /
//!   `operator_alert_cooldown_suppressed`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::egress::{self, ChannelText};
pub use crate::egress::OperatorAlert;
use crate::state::AppState;

/// Outcome of an alert request. Most callers fire-and-forget; the meta
/// loop records outcomes in `noo_agent_decisions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertOutcome {
    Sent,
    /// Suppressed by the (kind, target) cooldown window.
    Cooldown,
    SendFailed,
    /// Held back: the target node is in maintenance.
    Muted,
}

/// In-process cooldown fallback when Redis is unavailable. Resets on
/// restart — acceptable: worst case is one duplicate alert per restart.
fn local_cooldowns() -> &'static Mutex<HashMap<String, Instant>> {
    static MAP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Redis failed under the alert path (i460). The cooldown and the persisting
/// state fall back to this process's own maps, the ones used when there is no
/// Redis at all. Said here, and counted, because saying it through
/// operator_alert would be circular: `noo_operator_alert_store_errors_total`
/// (label `op`) is what Prometheus and the Redis alerts can see.
static STORE_ERROR_LOG: std::sync::LazyLock<crate::log_gate::LogGate> =
    std::sync::LazyLock::new(|| crate::log_gate::LogGate::new(300));

async fn store_error(metrics: &crate::metrics::MetricsState, op: &'static str, error: &str) {
    let labels = HashMap::from([("op".to_string(), op.to_string())]);
    metrics.inc_counter("noo_operator_alert_store_errors_total", Some(&labels), 1).await;
    if let Some(suppressed) = STORE_ERROR_LOG.should_log(op, unix_now().max(0) as u64) {
        tracing::warn!(op, error, suppressed, "operator_alert_store_unavailable: using this process's cooldown and state until Redis answers");
    }
}

/// Is this alert outside its cooldown? Redis answers when it can. When it
/// cannot (an error) or is absent, this process's own cooldown decides:
/// reading an outage as "cooling down" dropped every cooldown-gated alert for
/// as long as Redis failed, which is exactly when they matter.
fn cooldown_admit(redis: Option<Result<bool, String>>, local: impl FnOnce() -> bool) -> bool {
    match redis {
        Some(Ok(acquired)) => acquired,
        Some(Err(_)) | None => local(),
    }
}

async fn cooldown_acquired(state: &AppState, key: &str, secs: i64) -> bool {
    let redis = match state.redis.as_ref() {
        Some(r) => Some(r.set_nx_ex_checked(key, "1", secs).await),
        None => None,
    };
    if let Some(Err(e)) = &redis {
        store_error(&state.metrics, "cooldown", e).await;
    }
    cooldown_admit(redis, || local_cooldown(key, secs))
}

fn local_cooldown(key: &str, secs: i64) -> bool {
    let mut map = local_cooldowns().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    let acquired = match map.get(key) {
        Some(t) => now.duration_since(*t) >= Duration::from_secs(secs.max(0) as u64),
        None => true,
    };
    if acquired {
        map.insert(key.to_string(), now);
        // Opportunistic cleanup so the fallback map doesn't grow unbounded.
        map.retain(|_, t| now.duration_since(*t) < Duration::from_secs(86_400));
    }
    acquired
}

// Operator-facing alerts are deduplicated per (kind, target). `kind` is a
// stable dotted event name (e.g. `autonomy.node_health`); `target` narrows
// the cooldown scope (node id, task id, or "cluster"). `cooldown_secs <= 0`
// disables dedup here — for callers that manage their own cooldown windows
// (e.g. the meta loop's `noo_agent_decisions`-based checks).
//
// (Also a `///` block with a blank line under it, documenting nothing.)

/// Publish this alert into the replayable `events.ops.<kind>` stream
/// (). The EVENTS JetStream stream (`events.>`, 24h
/// retention) already carries the job lifecycle; ops alerts join it so
/// ANY consumer — dashboard tabs, scripts, a future mobile app — can
/// replay recent operational history without the gateway growing a
/// bespoke endpoint per consumer. Best-effort by design: the stream is
/// an OBSERVER of alerting, never a gate on it. Published for every
/// outcome (including cooldown-suppressed) — the stream records what
/// HAPPENED; per-channel dedup is a delivery concern, not history.
///
/// `message` is the CHANNEL rendering (the same text the channel got), so
/// a consumer that forwards it further is still safe. `detail` rides next
/// to it for consumers inside the trust boundary (the bus is authenticated
/// and internal, the same audience as the logs).
fn ops_event_payload(alert: &OperatorAlert, reference: &str, message: &str, outcome: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": alert.kind,
        "target": alert.target,
        "message": message,
        "detail": alert.detail,
        "ref": reference,
        "outcome": outcome,
        "ts": chrono::Utc::now().to_rfc3339(),
    })
}

async fn publish_ops_event(js: &async_nats::jetstream::Context, alert: &OperatorAlert, reference: &str, message: &str, outcome: &str) {
    let subject = format!("events.ops.{}", alert.kind);
    let payload = ops_event_payload(alert, reference, message, outcome);
    if let Ok(bytes) = serde_json::to_vec(&payload) {
        if let Err(e) = js.publish(subject, bytes.into()).await {
            tracing::debug!(kind = %alert.kind, error = %e, "ops_event_publish_failed");
        }
    }
}

/// Log the alert IN FULL — summary and detail — under its reference id.
/// This line is where the operator's `noo logs search <ref>` lands; the
/// channel only ever sees [`egress::system`]'s rendering.
fn log_alert(alert: &OperatorAlert, reference: &str) {
    tracing::warn!(
        reference = %reference,
        kind = %alert.kind,
        target = %alert.target,
        summary = %alert.summary,
        detail = %alert.detail,
        "operator_alert"
    );
}


// ── Persisting conditions: on change, not on time ───────────────────────

/// Reminders for a condition that keeps holding, as offsets from its onset:
/// the first alert is at onset, then these, then every
/// [`REMINDER_REPEAT_SECS`] after the last one sent.
pub const REMINDER_OFFSETS_SECS: [i64; 3] = [4 * 3600, 12 * 3600, 24 * 3600];
pub const REMINDER_REPEAT_SECS: i64 = 24 * 3600;
/// Alerts raised within this long of the first one waiting are one message.
pub const GROUP_WINDOW: Duration = Duration::from_secs(5);
/// A condition nobody has re-evaluated for this long is forgotten.
const STATE_TTL_SECS: i64 = 35 * 86_400;
const OPEN_SET_KEY: &str = "noo:alerts:open";

/// What is remembered about one open condition, per (kind, target).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistState {
    pub kind: String,
    pub target: String,
    /// The general summary line (already channel-safe), for the daily summary.
    pub summary: String,
    /// Unix seconds the condition was first seen.
    pub onset: i64,
    /// Unix seconds of the last alert actually delivered; 0 = none yet.
    pub last_sent: i64,
    /// Alerts delivered so far (the onset alert counts as one).
    pub count: u32,
    /// A held-back (maintenance) alert has already been recorded for the
    /// current silence, so the stream does not get one per tick.
    #[serde(default)]
    pub muted_noted: bool,
}

/// What one evaluation of a persisting condition should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing to say this tick.
    Quiet,
    /// Deliver. `Some(secs)` = a reminder, the condition is that old.
    Deliver(Option<i64>),
    /// Due, but the node is in maintenance. `true` = first time, record it.
    Muted(bool),
}

/// When the next message for a state is due, as unix seconds.
pub fn next_due(st: &PersistState) -> i64 {
    if st.count == 0 {
        return st.onset;
    }
    match REMINDER_OFFSETS_SECS.get(st.count as usize - 1) {
        Some(off) => st.onset + off,
        None => st.last_sent + REMINDER_REPEAT_SECS,
    }
}

/// The whole schedule, pure: given what we remember and the clock, what now?
pub fn persisting_step(
    prev: Option<PersistState>,
    alert: &OperatorAlert,
    now: i64,
    muted: bool,
) -> (Step, PersistState) {
    let mut st = prev.unwrap_or(PersistState {
        kind: alert.kind.clone(),
        target: alert.target.clone(),
        summary: String::new(),
        onset: now,
        last_sent: 0,
        count: 0,
        muted_noted: false,
    });
    st.summary = alert.summary.clone();
    if now < next_due(&st) {
        return (Step::Quiet, st);
    }
    if muted {
        let first = !st.muted_noted;
        st.muted_noted = true;
        return (Step::Muted(first), st);
    }
    let reminder = (st.count > 0).then(|| now - st.onset);
    st.count += 1;
    st.last_sent = now;
    st.muted_noted = false;
    (Step::Deliver(reminder), st)
}

/// What closing a condition should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearStep {
    /// Never open, or never announced: nothing to recover from.
    Nothing,
    /// Announce recovery; it lasted this many seconds.
    Deliver(i64),
    /// It was announced, but the node is in maintenance: record, don't send.
    Muted(i64),
}

pub fn clear_step(prev: Option<&PersistState>, now: i64, muted: bool) -> ClearStep {
    match prev {
        Some(st) if st.count > 0 => {
            let lasted = (now - st.onset).max(0);
            if muted {
                ClearStep::Muted(lasted)
            } else {
                ClearStep::Deliver(lasted)
            }
        }
        _ => ClearStep::Nothing,
    }
}

fn local_states() -> &'static Mutex<HashMap<String, PersistState>> {
    static MAP: OnceLock<Mutex<HashMap<String, PersistState>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn state_key(kind: &str, target: &str) -> String {
    format!("noo:alerts:state:{kind}:{target}")
}

// The persisting state lives in Redis when Redis takes it. The local map
// holds only what this process saved while Redis could not, until it is
// dropped or superseded by a Redis save; it is read whenever Redis has no
// copy (absent, erroring, or `None`).

async fn load_state(redis: Option<&crate::cache::RedisCache>, metrics: &crate::metrics::MetricsState, key: &str) -> Option<PersistState> {
    let read = match redis {
        Some(r) => Some(r.get_string_checked(key).await),
        None => None,
    };
    if let Some(Err(e)) = &read {
        // An error is not "no prior state": read that way, a persisting
        // alert was re-announced as new on every tick of the outage.
        store_error(metrics, "load_state", e).await;
    }
    let local = local_states().lock().unwrap_or_else(|p| p.into_inner()).get(key).cloned();
    load_choice(read, local)
}

/// Which copy of a persisting state counts, pure. Redis's when it has one;
/// otherwise the one this process saved while Redis could not take it. Read
/// `Ok(None)` as "nothing open" and a condition saved locally during an
/// outage was never cleared, then came back as open in the next outage.
fn load_choice(redis: Option<Result<Option<String>, String>>, local: Option<PersistState>) -> Option<PersistState> {
    match redis {
        Some(Ok(Some(raw))) => serde_json::from_str(&raw).ok().or(local),
        _ => local,
    }
}

async fn save_state(redis: Option<&crate::cache::RedisCache>, metrics: &crate::metrics::MetricsState, key: &str, st: &PersistState) {
    if let Some(r) = redis {
        let Ok(raw) = serde_json::to_string(st) else { return };
        if r.set_string(key, &raw).await {
            r.expire(key, STATE_TTL_SECS).await;
            r.sadd(OPEN_SET_KEY, key).await;
            // Redis holds it now; an older local copy must not outlive it.
            local_states().lock().unwrap_or_else(|p| p.into_inner()).remove(key);
            return;
        }
        store_error(metrics, "save_state", "SET failed").await;
    }
    local_states().lock().unwrap_or_else(|p| p.into_inner()).insert(key.to_string(), st.clone());
}

/// Close a persisting state everywhere it may be. The local copy always
/// goes: it is what [`load_state`] reads while Redis errors, so keeping it
/// (as this did when Redis was configured) sent "recovered" again on every
/// tick of an outage and left it to come back in a later one.
async fn drop_state(redis: Option<&crate::cache::RedisCache>, metrics: &crate::metrics::MetricsState, key: &str) {
    local_states().lock().unwrap_or_else(|p| p.into_inner()).remove(key);
    if let Some(r) = redis {
        if let Err(e) = r.del_key_checked(key).await {
            store_error(metrics, "drop_state", &e).await;
        }
        if let Err(e) = r.srem_checked(OPEN_SET_KEY, key).await {
            store_error(metrics, "drop_state", &e).await;
        }
    }
}

/// The state half of clearing a condition: what was open (if anything),
/// now dropped.
async fn take_state(redis: Option<&crate::cache::RedisCache>, metrics: &crate::metrics::MetricsState, key: &str) -> Option<PersistState> {
    let prev = load_state(redis, metrics, key).await?;
    drop_state(redis, metrics, key).await;
    Some(prev)
}

/// Every persisting condition currently open (announced or held back).
pub async fn open_conditions(state: &AppState) -> Vec<PersistState> {
    let mut out = Vec::new();
    if let Some(r) = state.redis.as_ref() {
        for key in r.smembers(OPEN_SET_KEY).await {
            match load_state(Some(r), &state.metrics, &key).await {
                Some(st) => out.push(st),
                None => {
                    r.srem(OPEN_SET_KEY, &key).await; // expired: the set must not outlive it
                }
            }
        }
    } else {
        out.extend(local_states().lock().unwrap_or_else(|p| p.into_inner()).values().cloned());
    }
    out.sort_by_key(|a| a.onset);
    out
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

async fn target_muted(state: &AppState, target: &str, now: i64) -> bool {
    let windows = crate::maintenance::active(&state.js, now).await;
    crate::maintenance::is_muted(&windows, target, now)
}

// ── Grouping ───────────────────────────────────────────────────────────

/// An alert waiting for its group window to close.
#[derive(Debug, Clone)]
struct Pending {
    alert: OperatorAlert,
    reference: String,
    /// `Some(secs)` = this is a recovery message; the condition lasted this long.
    recovered: Option<i64>,
}

fn group_buffer() -> &'static Mutex<Vec<Pending>> {
    static BUF: OnceLock<Mutex<Vec<Pending>>> = OnceLock::new();
    BUF.get_or_init(|| Mutex::new(Vec::new()))
}

/// Add to a buffer; true when it was empty (the caller starts the timer).
fn push_pending(buf: &Mutex<Vec<Pending>>, p: Pending) -> bool {
    let mut v = buf.lock().unwrap_or_else(|e| e.into_inner());
    v.push(p);
    v.len() == 1
}

fn take_pending(buf: &Mutex<Vec<Pending>>) -> Vec<Pending> {
    std::mem::take(&mut *buf.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The one message a batch becomes.
fn batch_text(batch: &[Pending]) -> ChannelText {
    let items: Vec<(&OperatorAlert, &str, Option<i64>)> =
        batch.iter().map(|p| (&p.alert, p.reference.as_str(), p.recovered)).collect();
    egress::system_group(&items)
}

async fn flush(js: async_nats::jetstream::Context, batch: Vec<Pending>) {
    if batch.is_empty() {
        return;
    }
    let text = batch_text(&batch);
    let outcome = match dispatch_raw(&text).await {
        Ok(()) => "sent",
        Err(e) => {
            tracing::warn!(count = batch.len(), error = %e, "operator_alert_send_failed");
            "send_failed"
        }
    };
    for p in &batch {
        if outcome == "sent" {
            tracing::info!(kind = %p.alert.kind, target = %p.alert.target, reference = %p.reference, grouped = batch.len(), "operator_alert_sent");
        }
        let one = batch_text(std::slice::from_ref(p));
        publish_ops_event(&js, &p.alert, &p.reference, one.as_str(), outcome).await;
    }
}

/// Queue a message for the group window. Never blocks the caller.
fn enqueue(js: &async_nats::jetstream::Context, p: Pending) {
    if push_pending(group_buffer(), p) {
        let js = js.clone();
        tokio::spawn(async move {
            tokio::time::sleep(GROUP_WINDOW).await;
            flush(js, take_pending(group_buffer())).await;
        });
    }
}

// ── The funnels ────────────────────────────────────────────────────────

/// The funnel. Every operator alert reaches a channel through here, and
/// the only text that reaches the channel is [`egress::system`]'s (or, for
/// alerts raised together, `egress::system_group`'s: the same renderer).
///
/// There is no sentence-shaped entry point. One existed
/// (`send_operator_alert(state, kind, target, cooldown, &str)`) and about
/// thirty producers used it; their text was authored by us and scrubbed on
/// the way out, but a future `{e}` added to one of them would have been
/// caught only by the scrubber. Every producer now builds an
/// [`OperatorAlert`]: a general summary, one `investigate` command, and the
/// evidence in `detail` (logged, never sent). `tests/test_channel_egress_guard.py`
/// fails if the sentence API comes back.
///
/// `Sent` means accepted for delivery: the message leaves when the group
/// window closes ([`GROUP_WINDOW`]); a failed send is logged and published
/// to the stream as `send_failed`.
pub async fn send_operator_alert_with(
    state: &AppState,
    alert: OperatorAlert,
    cooldown_secs: i64,
) -> AlertOutcome {
    let reference = egress::new_ref();
    let text = egress::system(&alert, &reference);
    let now = unix_now();
    let mut reminder_age: Option<i64> = None;
    if alert.persisting {
        // On change, not on time: the schedule replaces the cooldown.
        let key = state_key(&alert.kind, &alert.target);
        let muted = target_muted(state, &alert.target, now).await;
        let (step, st) = persisting_step(load_state(state.redis.as_ref(), &state.metrics, &key).await, &alert, now, muted);
        save_state(state.redis.as_ref(), &state.metrics, &key, &st).await;
        match step {
            Step::Quiet => return AlertOutcome::Cooldown,
            Step::Muted(first) => {
                if first {
                    log_alert(&alert, &reference);
                    publish_ops_event(&state.js, &alert, &reference, text.as_str(), "maintenance").await;
                }
                return AlertOutcome::Muted;
            }
            Step::Deliver(age) => reminder_age = age,
        }
    } else {
        if cooldown_secs > 0 {
            let key = format!("noo:alerts:cooldown:{}:{}", alert.kind, alert.target);
            if !cooldown_acquired(state, &key, cooldown_secs).await {
                tracing::debug!(kind = %alert.kind, target = %alert.target, "operator_alert_cooldown_suppressed");
                publish_ops_event(&state.js, &alert, &reference, text.as_str(), "cooldown").await;
                return AlertOutcome::Cooldown;
            }
        }
        if target_muted(state, &alert.target, now).await {
            log_alert(&alert, &reference);
            publish_ops_event(&state.js, &alert, &reference, text.as_str(), "maintenance").await;
            return AlertOutcome::Muted;
        }
    }
    let mut alert = alert;
    if let Some(age) = reminder_age {
        alert.summary = format!("Still unresolved after {}: {}", egress::human_duration(age), alert.summary);
    }
    log_alert(&alert, &reference);
    enqueue(&state.js, Pending { alert, reference, recovered: None });
    AlertOutcome::Sent
}

/// Same admission as [`send_operator_alert_with`], for request-path callers.
/// Both are non-blocking now that delivery is deferred to the group window;
/// this one returns `true` when an alert was queued.
pub async fn send_operator_alert_detached_with(
    state: &AppState,
    alert: OperatorAlert,
    cooldown_secs: i64,
) -> bool {
    send_operator_alert_with(state, alert, cooldown_secs).await == AlertOutcome::Sent
}

/// A persisting condition is fine now. `recovered` carries the general
/// "what is fine again" summary (and the same target/kind as the alert it
/// closes); nothing is sent when that condition was never announced. Cheap
/// when nothing is open, so an evaluator may call it for every healthy
/// target on every tick.
///
/// Returns true when a recovered message was queued.
pub async fn clear_operator_alert(state: &AppState, recovered: OperatorAlert) -> bool {
    let key = state_key(&recovered.kind, &recovered.target);
    let Some(prev) = take_state(state.redis.as_ref(), &state.metrics, &key).await else {
        return false;
    };
    let now = unix_now();
    let muted = target_muted(state, &recovered.target, now).await;
    let step = clear_step(Some(&prev), now, muted);
    let reference = egress::new_ref();
    match step {
        ClearStep::Nothing => false,
        ClearStep::Muted(lasted) => {
            let text = egress::system_recovered(&recovered, &reference, lasted);
            log_alert(&recovered, &reference);
            publish_ops_event(&state.js, &recovered, &reference, text.as_str(), "maintenance").await;
            false
        }
        ClearStep::Deliver(lasted) => {
            log_alert(&recovered, &reference);
            enqueue(&state.js, Pending { alert: recovered, reference, recovered: Some(lasted) });
            true
        }
    }
}

/// Deliver a message through the channel adapter, in process, bypassing
/// cooldown logic. Doesn't need `&AppState` — the channel and recipient
/// come from env vars and the adapter is stateless; this keeps spawn-Send
/// bounds simple for callers inside `Box::pin` recursion (agent meta loop).
///
/// Takes [`ChannelText`], not `&str`: the only way to build one is through
/// `crate::egress`, so nothing un-shaped can be handed to this wire.
pub async fn dispatch_raw(message: &ChannelText) -> Result<(), String> {
    let channel = std::env::var("NOO_AGENT_ALERT_CHANNEL")
        .unwrap_or_else(|_| "google_chat".to_string());
    // No default. `broadcast` used to stand in for an unset recipient, but
    // nothing on the send path ever resolved that word — not the channels
    // route, not either adapter — so it reached Google Chat as a literal and
    // built `https://chat.googleapis.com/v1/broadcast/messages`, a URL that is
    // not a Chat endpoint. Every alert 404'd, and because a failed alert is
    // only reported by an alert, the loss was invisible: on 2026-09-20 an hour
    // of node-quarantine and unreachable-worker warnings went nowhere while the
    // gateway logged each one as merely `operator_alert_send_failed`.
    // Refusing names the unset variable, which is the one thing the reader
    // needs and the 404 never said.
    let recipient = match std::env::var("NOO_AGENT_ALERT_RECIPIENT") {
        Ok(r) if !r.trim().is_empty() => r,
        _ => {
            return Err(
                "NOO_AGENT_ALERT_RECIPIENT is unset — operator alerts have \
                 nowhere to go; set it to a channel address (for google_chat, \
                 a space resource name like `spaces/<id>`)"
                    .to_string(),
            )
        }
    };
    // In process: the adapter call `/api/channels/send`
    // makes, with no HTTPS self-call and no controller HMAC. A refusal
    // carries the same words the route's `{"success": false}` envelope did
    // — an alert that did not arrive must say so, never read as sent.
    let sent = crate::routes::communication::send_channel_message(
        &channel,
        &recipient,
        message.as_str(),
        None,
        None,
        None,
    )
    .await;
    crate::heartbeat_actions::delivery_result(sent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// i460: a Redis error under the cooldown used to read as "cooling down",
    /// so every cooldown-gated alert was dropped while Redis failed.
    #[test]
    fn a_redis_error_falls_back_to_this_process_cooldown() {
        assert!(cooldown_admit(Some(Err("connection refused".into())), || true), "an outage is not a cooldown");
        assert!(!cooldown_admit(Some(Err("connection refused".into())), || false), "the local cooldown still dedupes");
        assert!(cooldown_admit(Some(Ok(true)), || false), "Redis answers when it can");
        assert!(!cooldown_admit(Some(Ok(false)), || true), "a held Redis cooldown wins");
        assert!(cooldown_admit(None, || true));
    }

    #[test]
    fn the_local_cooldown_admits_once_per_window() {
        let key = "noo:alerts:cooldown:test.local_cooldown:t1";
        assert!(local_cooldown(key, 3600));
        assert!(!local_cooldown(key, 3600), "a repeat inside the window is held");
    }

    const H: i64 = 3600;

    fn alert() -> OperatorAlert {
        OperatorAlert::new("autonomy.node_health", "alpha", "Node 'alpha' is offline.").persisting()
    }

    /// Run the schedule every 10 minutes for `hours`, returning the offsets
    /// (seconds since onset) at which a message was delivered.
    fn deliveries(hours: i64, muted: impl Fn(i64) -> bool) -> Vec<i64> {
        let mut st: Option<PersistState> = None;
        let mut out = Vec::new();
        let t0 = 1_000_000;
        let mut t = 0;
        while t <= hours * H {
            let (step, next) = persisting_step(st.take(), &alert(), t0 + t, muted(t));
            if matches!(step, Step::Deliver(_)) {
                out.push(t);
            }
            st = Some(next);
            t += 600;
        }
        out
    }

    #[test]
    fn a_persisting_key_alerts_at_onset_then_at_4h_12h_24h_then_daily() {
        assert_eq!(
            deliveries(80, |_| false),
            vec![0, 4 * H, 12 * H, 24 * H, 48 * H, 72 * H],
        );
    }

    #[test]
    fn a_persisting_key_is_silent_between_the_scheduled_messages() {
        let mut st = None;
        let (first, next) = persisting_step(st.take(), &alert(), 0, false);
        assert_eq!(first, Step::Deliver(None));
        st = Some(next);
        for t in [60, H, 3 * H, 4 * H - 1] {
            let (step, next) = persisting_step(st.take(), &alert(), t, false);
            assert_eq!(step, Step::Quiet, "t={t}");
            st = Some(next);
        }
        let (step, _) = persisting_step(st.take(), &alert(), 4 * H, false);
        assert_eq!(step, Step::Deliver(Some(4 * H)));
    }

    #[test]
    fn clearing_sends_one_recovered_message_with_the_duration_and_reonset_alerts_again() {
        let (_, st) = persisting_step(None, &alert(), 0, false);
        assert_eq!(clear_step(Some(&st), 2 * H + 300, false), ClearStep::Deliver(2 * H + 300));
        // The state is dropped on clear, so a second clear says nothing...
        assert_eq!(clear_step(None, 3 * H, false), ClearStep::Nothing);
        // ...and a re-onset starts from scratch: an immediate alert.
        let (step, st2) = persisting_step(None, &alert(), 5 * H, false);
        assert_eq!(step, Step::Deliver(None));
        assert_eq!(st2.onset, 5 * H);
    }

    #[test]
    fn a_node_in_maintenance_gets_no_delivery_and_off_restores_it() {
        // Muted for the first 2 h: nothing is delivered, and the stream is
        // told once, not every tick.
        let mut st: Option<PersistState> = None;
        let mut noted = 0;
        for t in (0..=2 * H).step_by(600) {
            let (step, next) = persisting_step(st.take(), &alert(), t, true);
            assert!(!matches!(step, Step::Deliver(_)), "delivered while muted at {t}");
            if step == Step::Muted(true) {
                noted += 1;
            }
            st = Some(next);
        }
        assert_eq!(noted, 1);
        // `off`: the very next evaluation delivers, with the true onset.
        let (step, st) = persisting_step(st.take(), &alert(), 2 * H + 600, false);
        assert_eq!(step, Step::Deliver(None));
        assert_eq!(st.onset, 0);
        // Maintenance windows themselves: on, then off.
        let on = [crate::maintenance::Maintenance {
            node: "alpha".into(), reason: "swap".into(), since: 0, until: None, by: "op".into(),
        }];
        assert!(crate::maintenance::is_muted(&on, "alpha", 10));
        assert!(!crate::maintenance::is_muted(&[], "alpha", 10));
    }

    #[test]
    fn a_recovery_during_maintenance_is_recorded_not_sent() {
        let (_, st) = persisting_step(None, &alert(), 0, false);
        assert_eq!(clear_step(Some(&st), H, true), ClearStep::Muted(H));
        // A condition that was only ever held back has nothing to recover from.
        let (_, held) = persisting_step(None, &alert(), 0, true);
        assert_eq!(clear_step(Some(&held), H, false), ClearStep::Nothing);
    }

    fn pending(target: &str) -> Pending {
        Pending {
            alert: OperatorAlert::new("autonomy.node_health", target, format!("Node '{target}' is offline."))
                .investigate(format!("noo cluster verify {target}")),
            reference: format!("ref-{target}"),
            recovered: None,
        }
    }

    #[test]
    fn two_alerts_in_one_pass_arrive_as_one_grouped_message() {
        let buf = Mutex::new(Vec::new());
        assert!(push_pending(&buf, pending("alpha")), "the first alert starts the window");
        assert!(!push_pending(&buf, pending("beta")), "the second joins it");
        let batch = take_pending(&buf);
        assert_eq!(batch.len(), 2);
        let text = batch_text(&batch);
        let out = text.as_str();
        assert!(out.contains("Node 'alpha' is offline.") && out.contains("Node 'beta' is offline."), "{out}");
        assert!(out.contains("Next: `noo cluster verify alpha`") && out.contains("Next: `noo cluster verify beta`"), "{out}");
        assert!(out.contains("ref-alpha") && out.contains("ref-beta"), "{out}");
        assert_eq!(out.matches("operator alerts:").count(), 1, "one message, one header:\n{out}");
        // The buffer is empty again, so the next alert opens a new window.
        assert!(take_pending(&buf).is_empty());
        assert!(push_pending(&buf, pending("gamma")));
    }

    /// The dead-Redis shape, against a real client whose server never
    /// answers: onset, recover, recover. The first recover finds the onset
    /// (saved locally, since Redis failed) and drops it; the second finds
    /// nothing, so "recovered" is sent once. Before, drop_state returned
    /// after the failing Redis DEL with the local copy still there, and every
    /// later tick (node_reachability's 120 s loop) sent "recovered" again.
    #[tokio::test]
    async fn with_redis_down_a_recovery_is_taken_once() {
        let dead = crate::cache::RedisCache::dead_for_tests();
        let metrics = crate::metrics::MetricsState::new();
        let a = alert();
        let key = format!("{}:dead-redis-test", state_key(&a.kind, &a.target));
        let (_, onset) = persisting_step(None, &a, 0, false);
        save_state(Some(&dead), &metrics, &key, &onset).await;
        let first = take_state(Some(&dead), &metrics, &key).await.expect("the first recover sees the onset");
        assert_eq!(clear_step(Some(&first), 2 * H, false), ClearStep::Deliver(2 * H));
        assert_eq!(take_state(Some(&dead), &metrics, &key).await, None, "the second recover finds nothing to announce");
        assert_eq!(load_state(Some(&dead), &metrics, &key).await, None, "nothing is left to come back in a later outage");
    }

    /// Which copy counts: Redis's when it has one, else this process's,
    /// including when Redis answers "none" (a condition saved during an
    /// outage is cleared once Redis is back, not left to resurface).
    #[test]
    fn the_local_copy_counts_whenever_redis_has_none() {
        let (_, local) = persisting_step(None, &alert(), 0, false);
        let (_, newer) = persisting_step(None, &alert(), 7 * H, false);
        let raw = serde_json::to_string(&newer).unwrap();
        assert_eq!(load_choice(Some(Ok(Some(raw))), Some(local.clone())), Some(newer), "Redis's copy wins");
        assert_eq!(load_choice(Some(Ok(None)), Some(local.clone())), Some(local.clone()), "Redis has none: the local one");
        assert_eq!(load_choice(Some(Err("refused".into())), Some(local.clone())), Some(local.clone()));
        assert_eq!(load_choice(None, Some(local.clone())), Some(local));
        assert_eq!(load_choice(Some(Ok(None)), None), None);
    }
}
