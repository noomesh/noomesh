// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The record a summary must be written from.
//!
//! A scheduled summary ("Today's system activity", the daily briefing) is
//! drafted by a model that knows only what its prompt tells it, and the
//! prompt used to tell it nothing about alerts. On 2026-10-09 it reported
//! "no critical errors" on a day a backup failed and two nodes were down.
//!
//! This module reads what the operator was actually told (the `events.ops.>`
//! alert stream, which the EVENTS stream keeps for 24 h), the conditions
//! still open, and the nodes in maintenance, and prepends them to the
//! prompt with an explicit rule: the summary reports them, and never says
//! all is well while the record lists any. When the stream cannot be read,
//! the record says so rather than staying silent (an unread record is not a
//! clean one).
//!
//! Only the channel rendering of each alert is used (its first line), never
//! the alert's `detail`, so the summary cannot carry evidence a channel
//! may not.

use serde_json::Value;

use crate::maintenance::Maintenance;
use crate::operator_alert::PersistState;
use crate::state::AppState;

/// How far back the record reaches. Matches the EVENTS stream's retention.
pub const WINDOW_SECS: i64 = 24 * 3600;
const MAX_EVENTS: usize = 1000;
const MAX_LISTED: usize = 40;

/// One alert event from the stream.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertEvent {
    pub ts: String,
    pub kind: String,
    pub target: String,
    /// First line of the channel text.
    pub headline: String,
    pub outcome: String,
}

pub fn parse_event(payload: &[u8]) -> Option<AlertEvent> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let kind = s("kind");
    if kind.is_empty() {
        return None;
    }
    let headline = s("message").lines().next().unwrap_or("").trim().to_string();
    Some(AlertEvent { ts: s("ts"), kind, target: s("target"), headline, outcome: s("outcome") })
}

fn clip<T>(items: &[T]) -> (&[T], usize) {
    let shown = items.len().min(MAX_LISTED);
    (&items[..shown], items.len() - shown)
}

/// The text prepended to a summary prompt. Pure: every input is explicit.
/// `events` is `None` when the stream could not be read.
pub fn render_record(
    events: Option<&[AlertEvent]>,
    open: &[PersistState],
    maintenance: &[Maintenance],
    now: i64,
) -> String {
    let mut out = String::from(
        "## Operator alert record (authoritative; read this before you write anything)\n\
         This is what the operator was actually told in the last 24 hours, the conditions still \
         open, and the nodes known to be down for maintenance.\n\n",
    );
    match events {
        None => out.push_str(
            "The alert stream could not be read, so the list of alerts sent is UNKNOWN. State that \
             plainly. Do not say there were no errors.\n\n",
        ),
        Some(events) => {
            let sent: Vec<&AlertEvent> = events.iter().filter(|e| e.outcome == "sent").collect();
            let failed: Vec<&AlertEvent> = events.iter().filter(|e| e.outcome == "send_failed").collect();
            let held = events.iter().filter(|e| e.outcome == "maintenance").count();
            if sent.is_empty() {
                out.push_str("Alerts sent to the operator: none.\n");
            } else {
                out.push_str(&format!("Alerts sent to the operator ({}):\n", sent.len()));
                let (shown, more) = clip(&sent);
                for e in shown {
                    out.push_str(&format!("- {} [{}] {}\n", e.ts, e.kind, e.headline));
                }
                if more > 0 {
                    out.push_str(&format!("- ...and {more} more\n"));
                }
            }
            if !failed.is_empty() {
                out.push_str(&format!(
                    "Alerts that FAILED to reach the operator ({}); the operator may not know:\n",
                    failed.len()
                ));
                let (shown, more) = clip(&failed);
                for e in shown {
                    out.push_str(&format!("- {} [{}] {}\n", e.ts, e.kind, e.headline));
                }
                if more > 0 {
                    out.push_str(&format!("- ...and {more} more\n"));
                }
            }
            if held > 0 {
                out.push_str(&format!("Alerts held back because the node is in maintenance: {held}.\n"));
            }
            out.push('\n');
        }
    }
    if open.is_empty() {
        out.push_str("Conditions open right now: none.\n");
    } else {
        out.push_str(&format!("Conditions open right now ({}):\n", open.len()));
        let (shown, more) = clip(open);
        for st in shown {
            out.push_str(&format!(
                "- [{}] {} (open for {})\n",
                st.kind,
                st.summary.lines().next().unwrap_or(""),
                crate::egress::human_duration(now - st.onset),
            ));
        }
        if more > 0 {
            out.push_str(&format!("- ...and {more} more\n"));
        }
    }
    if maintenance.is_empty() {
        out.push_str("Nodes in maintenance: none.\n");
    } else {
        out.push_str(&format!("Nodes in maintenance ({}); list them as down or in maintenance:\n", maintenance.len()));
        for m in maintenance {
            let until = m.until.map_or("until turned off".to_string(), |u| {
                format!("for another {}", crate::egress::human_duration(u - now))
            });
            out.push_str(&format!("- {}: {} ({until})\n", m.node, m.reason));
        }
    }
    out.push_str(
        "\nRules: report every failure, open condition and maintenance node above. Never write \
         that there were no errors, nothing to report, or that everything is healthy while this \
         record lists any alert or open condition. If the record lists none, say only that no \
         alerts were sent in the window.\n\n---\n\n",
    );
    out
}

/// Read the alert stream for the window. `None` = unreadable.
async fn read_events(state: &AppState, now: i64) -> Option<Vec<AlertEvent>> {
    use async_nats::jetstream::consumer::{pull::Config, AckPolicy, DeliverPolicy};
    use tokio_stream::StreamExt;
    let stream = state.js.get_stream("EVENTS").await.ok()?;
    let start = time::OffsetDateTime::from_unix_timestamp(now - WINDOW_SECS).ok()?;
    let consumer = stream
        .create_consumer(Config {
            filter_subject: "events.ops.>".to_string(),
            deliver_policy: DeliverPolicy::ByStartTime { start_time: start },
            ack_policy: AckPolicy::None,
            inactive_threshold: std::time::Duration::from_secs(30),
            ..Default::default()
        })
        .await
        .ok()?;
    let pending = consumer.cached_info().num_pending as usize;
    if pending == 0 {
        return Some(Vec::new());
    }
    let mut batch = consumer
        .fetch()
        .max_messages(pending.min(MAX_EVENTS))
        .expires(std::time::Duration::from_secs(3))
        .messages()
        .await
        .ok()?;
    let mut out = Vec::new();
    while let Some(Ok(msg)) = batch.next().await {
        if let Some(e) = parse_event(&msg.payload) {
            out.push(e);
        }
    }
    Some(out)
}

/// Actions whose output is a summary of how the system has been.
pub fn wants_alert_record(action: &str, config: &Value) -> bool {
    match action {
        "daily_briefing" | "cluster_health" => true,
        "channel_message" => {
            let p = config.get("prompt").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
            ["summar", "activity", "error", "briefing", "digest", "status"].iter().any(|w| p.contains(w))
        }
        _ => false,
    }
}

/// Prepend the alert record to a summary prompt (no-op for other actions).
pub async fn enrich_prompt(prompt: String, state: &AppState, action: &str, config: &Value) -> String {
    if !wants_alert_record(action, config) {
        return prompt;
    }
    let now = chrono::Utc::now().timestamp();
    let events = read_events(state, now).await;
    let open = crate::operator_alert::open_conditions(state).await;
    let maintenance = crate::maintenance::active(&state.js, now).await;
    let record = render_record(events.as_deref(), &open, &maintenance, now);
    format!("{record}{prompt}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(kind: &str, outcome: &str, msg: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "kind": kind, "target": "alpha", "message": msg, "outcome": outcome,
            "ts": "2026-10-09T08:00:00Z", "detail": "dial 10.0.0.9 refused",
        }))
        .unwrap()
    }

    #[test]
    fn the_summary_input_includes_the_windows_sent_alerts() {
        let events = vec![
            parse_event(&event("backup.failed", "sent", "Database backup failed.\nNext: `noo db backup`\nRef: ref-1")).unwrap(),
            parse_event(&event("autonomy.node_health", "sent", "Node 'alpha' is offline.\nRef: ref-2")).unwrap(),
            parse_event(&event("autonomy.node_health", "cooldown", "Node 'alpha' is offline.")).unwrap(),
        ];
        let out = render_record(Some(&events), &[], &[], 0);
        assert!(out.contains("Alerts sent to the operator (2)"), "{out}");
        assert!(out.contains("Database backup failed."), "{out}");
        assert!(out.contains("Node 'alpha' is offline."), "{out}");
        assert!(out.contains("Never write"), "the rule that forbids an all-clear is part of the input");
        // Evidence stays out: only the channel headline is carried.
        assert!(!out.contains("10.0.0.9"), "{out}");
    }

    #[test]
    fn open_conditions_and_maintenance_are_stated() {
        let open = [PersistState {
            kind: "node_unreachable".into(), target: "alpha".into(),
            summary: "Node 'alpha' cannot be reached.".into(), onset: 0, last_sent: 0, count: 1, muted_noted: false,
        }];
        let m = [Maintenance { node: "beta".into(), reason: "disk swap".into(), since: 0, until: None, by: "op".into() }];
        let out = render_record(Some(&[]), &open, &m, 7200);
        assert!(out.contains("Alerts sent to the operator: none."), "{out}");
        assert!(out.contains("Node 'alpha' cannot be reached.") && out.contains("open for 2h 0m"), "{out}");
        assert!(out.contains("beta: disk swap"), "{out}");
    }

    #[test]
    fn an_unreadable_stream_is_not_a_clean_record() {
        let out = render_record(None, &[], &[], 0);
        assert!(out.contains("UNKNOWN"), "{out}");
        assert!(!out.contains("Alerts sent to the operator: none."), "{out}");
    }

    #[test]
    fn failed_deliveries_are_called_out() {
        let events = vec![parse_event(&event("backup.failed", "send_failed", "Backup failed.")).unwrap()];
        let out = render_record(Some(&events), &[], &[], 0);
        assert!(out.contains("FAILED to reach the operator (1)"), "{out}");
    }

    #[test]
    fn only_summary_shaped_actions_get_the_record_and_the_loop_wires_it() {
        let none = json!({});
        assert!(wants_alert_record("daily_briefing", &none));
        assert!(wants_alert_record("channel_message", &json!({"prompt": "Summarize today's system activity"})));
        assert!(!wants_alert_record("channel_message", &json!({"prompt": "say hi"})));
        assert!(!wants_alert_record("database_backup", &none));
        let src = include_str!("heartbeat_loop.rs");
        assert!(src.contains("alert_digest::enrich_prompt("), "the heartbeat loop must feed summaries the alert record");
    }
}
