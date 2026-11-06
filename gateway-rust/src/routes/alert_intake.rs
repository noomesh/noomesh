// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `POST /api/alerts/alertmanager` — Alertmanager's critical alerts, raised
//! as the operator's persisting `operator_alert` (i515b).
//!
//! `monitoring/alertmanager/alertmanager.yml` routes `severity="critical"`
//! here (its `gateway` receiver) and everything else to `null`. What this
//! intake decides, and from where:
//!
//! - **who may post**: Alertmanager's own service leaf, and nothing else
//!   (`auth::is_alert_intake`, decided in the auth middleware before any
//!   bearer is read, and again here).
//! - **what it takes**: alerts labelled `severity="critical"` only. A
//!   payload with none is a 400, so the route can never become a generic
//!   channel. Body and alert count are bounded.
//! - **what reaches the channel**: a gateway-owned sentence, "critical alert
//!   <alertname> firing on <target>", and `noo cluster verify`. The alert's
//!   annotations and other labels never do; they are logged (bounded) under
//!   the alert's (kind, target).
//! - **flapping**: an onset is admitted at most once per
//!   [`ONSET_COOLDOWN_SECS`] per (kind, target) ([`flap_guard`]). An onset
//!   the cooldown holds back is never opened, so the "resolved" that follows
//!   finds nothing announced and clears silently.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::node_identity::VerifiedService;
use crate::operator_alert::{self, OperatorAlert};
use crate::state::AppState;

/// The largest webhook body taken. Alertmanager's payloads for a handful of
/// grouped alerts are a few KiB.
const MAX_BODY: usize = 256 * 1024;
/// The most alerts one payload may carry.
const MAX_ALERTS: usize = 100;
/// Longest accepted `alertname`.
const MAX_ALERTNAME: usize = 64;
/// Longest accepted target label value.
const MAX_TARGET: usize = 128;
/// Bound on the logged annotations and labels of one alert.
const MAX_LOGGED_CONTEXT: usize = 4 * 1024;
/// One announced onset per (kind, target) per this window: a TargetDown
/// flapping every few minutes posts one onset and one recovery, not a pair
/// per cycle. A still-firing alert is re-sent by Alertmanager every
/// `repeat_interval` (1 h for criticals), so it is announced after this.
pub const ONSET_COOLDOWN_SECS: i64 = 30 * 60;
/// The labels a target may come from, in order; else `cluster`.
const TARGET_LABELS: [&str; 2] = ["instance", "service"];

pub fn router() -> Router<Arc<AppState>> {
    // A literal path: the OpenAPI generator and the drift checker read
    // route strings. Same value as `auth::ALERT_INTAKE_PATH`.
    Router::new().route(
        "/api/alerts/alertmanager",
        post(alertmanager_intake).layer(DefaultBodyLimit::max(MAX_BODY)),
    )
}

/// Alertmanager's webhook payload (version "4"). Only what is read.
#[derive(Debug, Deserialize)]
struct Webhook {
    #[serde(default)]
    alerts: Vec<WebhookAlert>,
}

#[derive(Debug, Deserialize)]
struct WebhookAlert {
    #[serde(default)]
    status: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    fingerprint: String,
}

/// One alert's state change as Alertmanager reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEvent {
    Firing,
    Resolved,
}

/// A critical alert the intake accepted: its (kind, target) and the event.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Intake {
    alertname: String,
    kind: String,
    target: String,
    event: AlertEvent,
}

/// Why a whole payload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadRefusal {
    TooManyAlerts,
    NoCriticalAlert,
}

fn valid_alertname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ALERTNAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn valid_target(target: &str) -> bool {
    !target.trim().is_empty()
        && target.chars().count() <= MAX_TARGET
        && !target.chars().any(char::is_control)
}

/// The target an alert names: `instance`, else `service`, else `cluster`.
fn alert_target(labels: &BTreeMap<String, String>) -> &str {
    TARGET_LABELS
        .iter()
        .find_map(|l| labels.get(*l).map(String::as_str).filter(|v| !v.is_empty()))
        .unwrap_or("cluster")
}

fn is_critical(a: &WebhookAlert) -> bool {
    a.labels.get("severity").is_some_and(|s| s == "critical")
}

/// One alert, pure: accepted as an [`Intake`], or refused with why.
fn classify(a: &WebhookAlert) -> Result<Intake, &'static str> {
    if !is_critical(a) {
        return Err("not critical");
    }
    let event = match a.status.as_str() {
        "firing" => AlertEvent::Firing,
        "resolved" => AlertEvent::Resolved,
        _ => return Err("status is neither firing nor resolved"),
    };
    let alertname = a.labels.get("alertname").map(String::as_str).unwrap_or("");
    if !valid_alertname(alertname) {
        return Err("alertname must be 1 to 64 of A-Z a-z 0-9 _");
    }
    let target = alert_target(&a.labels);
    if !valid_target(target) {
        return Err("target label is empty, too long or has control characters");
    }
    Ok(Intake {
        alertname: alertname.to_string(),
        kind: format!("prometheus.{alertname}"),
        target: target.to_string(),
        event,
    })
}

/// The whole payload, pure: one result per alert, or the payload refused.
fn plan(w: &Webhook) -> Result<Vec<Result<Intake, &'static str>>, PayloadRefusal> {
    if w.alerts.len() > MAX_ALERTS {
        return Err(PayloadRefusal::TooManyAlerts);
    }
    if !w.alerts.iter().any(is_critical) {
        return Err(PayloadRefusal::NoCriticalAlert);
    }
    Ok(w.alerts.iter().map(classify).collect())
}

/// The channel's words for an alert: the gateway's own sentence, never the
/// alert's annotations or any other label.
fn intake_alert(i: &Intake) -> OperatorAlert {
    let summary = match i.event {
        AlertEvent::Firing => format!("critical alert {} firing on {}", i.alertname, i.target),
        AlertEvent::Resolved => format!("critical alert {} resolved on {}", i.alertname, i.target),
    };
    OperatorAlert::new(&i.kind, &i.target, summary).investigate("noo cluster verify")
}

/// The alert's annotations, other labels and fingerprint, for the log
/// line only, bounded to [`MAX_LOGGED_CONTEXT`] bytes.
fn logged_context(a: &WebhookAlert) -> String {
    let mut out = String::new();
    let pairs = a
        .annotations
        .iter()
        .map(|(k, v)| ("annotation", k, v))
        .chain(a.labels.iter().map(|(k, v)| ("label", k, v)));
    for (what, k, v) in pairs {
        out.push_str(&format!("{what}.{k}={v}; "));
        if out.len() > MAX_LOGGED_CONTEXT {
            break;
        }
    }
    out.push_str(&format!("fingerprint={}", a.fingerprint));
    if out.len() > MAX_LOGGED_CONTEXT {
        let mut end = MAX_LOGGED_CONTEXT;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// What one event does to its (kind, target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeAction {
    /// Raise the persisting condition: an onset, or a re-send of an open
    /// one (the persisting schedule keeps that quiet or makes it a reminder).
    Raise,
    /// An onset the cooldown held back: not opened, not announced.
    Hold,
    /// Clear the condition: "recovered" if it was announced, else nothing.
    Clear,
}

/// Whether this event is an onset, the one case the cooldown is asked.
pub fn needs_onset_gate(event: AlertEvent, open: bool) -> bool {
    event == AlertEvent::Firing && !open
}

/// The flap guard, pure. `open` = a condition is open for the (kind,
/// target); `onset_admitted` = the onset cooldown admitted this one (read
/// only when [`needs_onset_gate`]).
pub fn flap_guard(event: AlertEvent, open: bool, onset_admitted: bool) -> IntakeAction {
    match event {
        AlertEvent::Resolved => IntakeAction::Clear,
        AlertEvent::Firing if open || onset_admitted => IntakeAction::Raise,
        AlertEvent::Firing => IntakeAction::Hold,
    }
}

fn onset_cooldown_key(kind: &str, target: &str) -> String {
    format!("noo:alerts:onset:{kind}:{target}")
}

async fn deliver(state: &AppState, i: &Intake) {
    let open = operator_alert::condition_open(state, &i.kind, &i.target).await;
    let admitted = if needs_onset_gate(i.event, open) {
        let key = onset_cooldown_key(&i.kind, &i.target);
        operator_alert::cooldown_acquired(state, &key, ONSET_COOLDOWN_SECS).await
    } else {
        false
    };
    match flap_guard(i.event, open, admitted) {
        IntakeAction::Raise => {
            operator_alert::send_operator_alert_with(state, intake_alert(i).persisting(), 0).await;
        }
        IntakeAction::Hold => {
            tracing::info!(kind = %i.kind, target = %i.target, "alertmanager_onset_held: inside the onset cooldown, not announced");
        }
        IntakeAction::Clear => {
            operator_alert::clear_operator_alert(state, intake_alert(i)).await;
        }
    }
}

fn refused(status: StatusCode, why: &str) -> Response {
    (status, Json(json!({ "error": why }))).into_response()
}

/// `POST /api/alerts/alertmanager` — Alertmanager's webhook. Alertmanager's
/// service leaf only. Critical alerts only: `firing` raises a persisting
/// operator alert for (`prometheus.<alertname>`, target), `resolved` clears
/// it; onsets are flap-guarded. Answers `{accepted, refused}` counts and
/// never echoes the alert's annotations.
async fn alertmanager_intake(
    State(state): State<Arc<AppState>>,
    svc: Option<Extension<Option<VerifiedService>>>,
    method: Method,
    body: Bytes,
) -> Response {
    let service = svc.and_then(|Extension(s)| s);
    if !crate::auth::is_alert_intake(&method, crate::auth::ALERT_INTAKE_PATH, service.as_ref()) {
        return refused(StatusCode::FORBIDDEN, "answers Alertmanager's own service leaf only");
    }
    let Ok(webhook) = serde_json::from_slice::<Webhook>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "not an Alertmanager webhook payload");
    };
    let items = match plan(&webhook) {
        Ok(items) => items,
        Err(PayloadRefusal::TooManyAlerts) => {
            return refused(StatusCode::BAD_REQUEST, "too many alerts in one payload");
        }
        Err(PayloadRefusal::NoCriticalAlert) => {
            return refused(StatusCode::BAD_REQUEST, "this intake takes severity=critical alerts only");
        }
    };
    let (mut accepted, mut refused_n) = (0u32, 0u32);
    for (a, item) in webhook.alerts.iter().zip(items) {
        match item {
            Ok(i) => {
                tracing::warn!(kind = %i.kind, target = %i.target, status = %a.status, context = %logged_context(a), "alertmanager_alert");
                deliver(&state, &i).await;
                accepted += 1;
            }
            Err(why) => {
                tracing::info!(why, context = %logged_context(a), "alertmanager_alert_refused");
                refused_n += 1;
            }
        }
    }
    Json(json!({ "accepted": accepted, "refused": refused_n })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_alert::{clear_step, persisting_step, ClearStep, PersistState, Step};

    fn webhook(v: serde_json::Value) -> Webhook {
        serde_json::from_value(v).expect("a webhook payload")
    }

    fn one(status: &str, labels: serde_json::Value) -> Webhook {
        webhook(json!({
            "version": "4",
            "status": status,
            "alerts": [{
                "status": status,
                "labels": labels,
                "annotations": {
                    "summary": "SECRET-SUMMARY node 10.1.2.3 is down",
                    "description": "SECRET-DESCRIPTION dial tcp 10.1.2.3:9100 refused"
                },
                "startsAt": "2026-11-05T00:00:00Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "abc123"
            }],
            "groupLabels": {"alertname": "TargetDown"},
            "commonLabels": {"severity": "critical"}
        }))
    }

    #[test]
    fn a_payload_with_no_critical_alert_is_refused() {
        let w = one("firing", json!({"alertname": "HighLatency", "severity": "warning", "service": "alpha"}));
        assert_eq!(plan(&w).unwrap_err(), PayloadRefusal::NoCriticalAlert);
        let w = one("firing", json!({"alertname": "HighLatency", "service": "alpha"}));
        assert_eq!(plan(&w).unwrap_err(), PayloadRefusal::NoCriticalAlert, "no severity is not critical");
        assert_eq!(plan(&webhook(json!({"alerts": []}))).unwrap_err(), PayloadRefusal::NoCriticalAlert);
    }

    #[test]
    fn too_many_alerts_refuse_the_payload() {
        let a = json!({"status": "firing", "labels": {"alertname": "TargetDown", "severity": "critical"}});
        let w = webhook(json!({"alerts": vec![a; MAX_ALERTS + 1]}));
        assert_eq!(plan(&w).unwrap_err(), PayloadRefusal::TooManyAlerts);
    }

    #[test]
    fn a_bad_alertname_is_refused() {
        for bad in ["", "Target Down", "TargetDown`", "a.b", "x\nInjected"] {
            let w = one("firing", json!({"alertname": bad, "severity": "critical", "service": "alpha"}));
            let items = plan(&w).expect("a critical payload is planned");
            assert!(items[0].is_err(), "{bad:?} was accepted");
        }
        let long = "A".repeat(MAX_ALERTNAME + 1);
        let w = one("firing", json!({"alertname": long, "severity": "critical"}));
        assert!(plan(&w).unwrap()[0].is_err());
        let w = one("firing", json!({"alertname": "TargetDown", "severity": "critical", "service": "alpha"}));
        let ok = plan(&w).unwrap().remove(0).expect("a good alert");
        assert_eq!(ok.kind, "prometheus.TargetDown");
        assert_eq!(ok.target, "alpha");
        assert_eq!(ok.event, AlertEvent::Firing);
    }

    #[test]
    fn the_target_is_instance_then_service_then_cluster_and_is_validated() {
        let w = one("resolved", json!({"alertname": "TargetDown", "severity": "critical", "instance": "host3", "service": "alpha"}));
        let i = plan(&w).unwrap().remove(0).unwrap();
        assert_eq!((i.target.as_str(), i.event), ("host3", AlertEvent::Resolved));
        let w = one("firing", json!({"alertname": "TargetDown", "severity": "critical", "job": "ignored"}));
        assert_eq!(plan(&w).unwrap().remove(0).unwrap().target, "cluster");
        let w = one("firing", json!({"alertname": "TargetDown", "severity": "critical", "instance": "a\u{7}b"}));
        assert!(plan(&w).unwrap()[0].is_err(), "a control character in the target");
        let w = one("firing", json!({"alertname": "TargetDown", "severity": "critical", "instance": "h".repeat(MAX_TARGET + 1)}));
        assert!(plan(&w).unwrap()[0].is_err(), "an overlong target");
        let w = one("pending", json!({"alertname": "TargetDown", "severity": "critical"}));
        assert!(plan(&w).unwrap()[0].is_err(), "an unknown status");
    }

    #[test]
    fn annotations_never_reach_the_channel_text() {
        let w = one("firing", json!({"alertname": "TargetDown", "severity": "critical", "service": "alpha", "team": "SECRET-LABEL"}));
        let i = plan(&w).unwrap().remove(0).unwrap();
        let text = crate::egress::system(&intake_alert(&i), "ref-test");
        let out = text.as_str();
        assert!(out.contains("critical alert TargetDown firing on alpha"), "{out}");
        assert!(out.contains("Next: `noo cluster verify`"), "{out}");
        for leak in ["SECRET-SUMMARY", "SECRET-DESCRIPTION", "SECRET-LABEL", "abc123"] {
            assert!(!out.contains(leak), "`{leak}` reached the channel:\n{out}");
        }
        let recovered = crate::egress::system_recovered(&intake_alert(&Intake { event: AlertEvent::Resolved, ..i }), "ref-test", 60);
        assert!(recovered.as_str().contains("critical alert TargetDown resolved on alpha"), "{recovered}");
        assert!(!recovered.as_str().contains("SECRET-"), "{recovered}");
        // They are in the log line, bounded.
        let ctx = logged_context(&w.alerts[0]);
        assert!(ctx.contains("SECRET-SUMMARY") && ctx.contains("fingerprint=abc123"), "{ctx}");
        let mut big = one("firing", json!({"alertname": "TargetDown", "severity": "critical"}));
        big.alerts[0].annotations.insert("description".into(), "é".repeat(10_000));
        assert!(logged_context(&big.alerts[0]).len() <= MAX_LOGGED_CONTEXT);
    }

    /// The model of what the handler does with one (kind, target): the flap
    /// guard, the persisting schedule and a SET NX EX cooldown. Returns how
    /// many onsets and recoveries were delivered.
    fn deliveries(events: &[(i64, AlertEvent)]) -> (u32, u32) {
        let alert = OperatorAlert::new("prometheus.TargetDown", "alpha", "x").persisting();
        let mut st: Option<PersistState> = None;
        let mut cooldown_until = i64::MIN;
        let (mut onsets, mut recovered) = (0, 0);
        for &(t, ev) in events {
            let open = st.is_some();
            let admitted = needs_onset_gate(ev, open) && t >= cooldown_until;
            if admitted {
                cooldown_until = t + ONSET_COOLDOWN_SECS;
            }
            match flap_guard(ev, open, admitted) {
                IntakeAction::Raise => {
                    let (step, next) = persisting_step(st.take(), &alert, t, false);
                    if step == Step::Deliver(None) {
                        onsets += 1;
                    }
                    st = Some(next);
                }
                IntakeAction::Hold => {}
                IntakeAction::Clear => {
                    if let ClearStep::Deliver(_) = clear_step(st.as_ref(), t, false) {
                        recovered += 1;
                    }
                    st = None;
                }
            }
        }
        (onsets, recovered)
    }

    #[test]
    fn a_flapping_target_posts_one_onset_and_one_recovery_per_window() {
        let t0 = 1_000_000;
        let mut events = Vec::new();
        for n in 0..10 {
            events.push((t0 + n * 150, AlertEvent::Firing));
            events.push((t0 + n * 150 + 60, AlertEvent::Resolved));
        }
        assert!(events.last().unwrap().0 - t0 < ONSET_COOLDOWN_SECS);
        assert_eq!(deliveries(&events), (1, 1), "10 flaps inside the window");
        // After the window, a firing is an onset again.
        events.push((t0 + ONSET_COOLDOWN_SECS + 1, AlertEvent::Firing));
        assert_eq!(deliveries(&events), (2, 1));
    }

    #[test]
    fn a_held_onset_still_firing_is_announced_at_the_next_repeat() {
        let t0 = 1_000_000;
        let events = [
            (t0, AlertEvent::Firing),
            (t0 + 60, AlertEvent::Resolved),
            (t0 + 120, AlertEvent::Firing),          // held: inside the window
            (t0 + 120 + 3600, AlertEvent::Firing),   // Alertmanager's 1 h repeat
            (t0 + 120 + 7200, AlertEvent::Firing),   // open: the schedule keeps it quiet
        ];
        assert_eq!(deliveries(&events), (2, 1));
    }

    #[test]
    fn the_flap_guard_decides_from_open_and_the_cooldown() {
        assert_eq!(flap_guard(AlertEvent::Resolved, false, false), IntakeAction::Clear);
        assert_eq!(flap_guard(AlertEvent::Firing, true, false), IntakeAction::Raise);
        assert_eq!(flap_guard(AlertEvent::Firing, false, true), IntakeAction::Raise);
        assert_eq!(flap_guard(AlertEvent::Firing, false, false), IntakeAction::Hold);
        assert!(needs_onset_gate(AlertEvent::Firing, false));
        assert!(!needs_onset_gate(AlertEvent::Firing, true));
        assert!(!needs_onset_gate(AlertEvent::Resolved, false));
    }

    #[test]
    fn the_route_literal_is_the_auth_constant() {
        assert!(include_str!("alert_intake.rs").contains(&format!("\"{}\",", crate::auth::ALERT_INTAKE_PATH)));
    }
}
