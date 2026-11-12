// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Is a node's LIVE record there, and if not, why (i604 roll follow-up).
//!
//! `noo cluster provision` reads a node's running CLI version, its derived
//! tier and its data roots off `GET /api/cluster/nodes`. On the 0.6.20 roll
//! the second `noo upgrade --nodes` found awolf and pop-os with none of them
//! and fell back three times in silence: "no CLI version" (so an
//! uncompressed 528 MB bundle), tier from enrollment facts, data-root check
//! skipped. The record it read was the gateway's DATABASE row for a node
//! whose live (NATS KV) entry had expired while its agent restarted, which
//! carries none of those facts; a failed fetch read the same, as nothing.
//!
//! [`classify`] tells the four states apart, [`wait_live`] waits a bounded
//! time for a live record (an agent that just restarted heartbeats within
//! seconds), and [`fallback_line`] is the one line that says why the facts
//! are missing and what the bundle loses. A node that stays down is still
//! upgradeable: the fallback is kept, never silent.

use serde_json::Value;

/// How long provision waits for a node's live record, and how often it asks.
pub(crate) const LIVE_WAIT_SECS: u64 = 60;
pub(crate) const LIVE_POLL_SECS: u64 = 5;

const NODES_PATH: &str = "/api/cluster/nodes";

/// One `GET /api/cluster/nodes`: the status and body, `None` when nothing
/// answered (crate::http::get_raw_opt).
pub(crate) type NodesFetch<'a> = &'a mut dyn FnMut() -> Option<(u16, String)>;

/// What the gateway's node list says about one node.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LiveState {
    /// Heard from on the live bus: its heartbeat facts are on the record.
    Live(Value),
    /// Listed from the gateway's database only: its live entry expired (the
    /// agent is down, or restarting). None of its heartbeat facts are there.
    Offline { since: Option<String>, detail: Option<String> },
    /// The gateway answered and does not list the node at all.
    Absent,
    /// No usable answer: unreachable, an HTTP error, or not JSON.
    Unreachable(String),
}

/// What a live record says the node RUNS, for a wave's "prerequisite met"
/// check (harness's dependency map): the version its applier reports and
/// that version parsed by the one parser (`node_leaves::cli_version_triple`:
/// `noo-cli-v…`, `stack-v…` or `v…`). `applier` is None when the version is
/// absent or unreadable; the caller decides what that means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveFacts {
    pub app_version: String,
    // Read by the dependency map's wave check (harness, i613), not yet on dev.
    #[cfg_attr(not(test), allow(dead_code))]
    pub applier: Option<(u32, u32, u32)>,
}

impl LiveState {
    pub(crate) fn live(&self) -> Option<&Value> {
        match self {
            LiveState::Live(v) => Some(v),
            _ => None,
        }
    }

    /// The node's [`LiveFacts`], when its record is live.
    pub(crate) fn facts(&self) -> Option<LiveFacts> {
        let rec = self.live()?;
        let app_version = rec["app_version"].as_str().unwrap_or("").trim().to_string();
        let applier = super::node_leaves::cli_version_triple(&app_version);
        Some(LiveFacts { app_version, applier })
    }

    /// Why there is no live record, in the words the operator reads.
    pub(crate) fn why(&self) -> String {
        match self {
            LiveState::Live(_) => "live".into(),
            LiveState::Offline { since, detail } => {
                let mut s = match since {
                    Some(t) => format!("listed offline, last heartbeat {t}"),
                    None => "listed offline, no heartbeat on record".into(),
                };
                if let Some(d) = detail.as_deref().filter(|d| !d.is_empty()) {
                    s.push_str(&format!(" ({d})"));
                }
                s
            }
            LiveState::Absent => "not in the gateway's node list: never heard from, e.g. its first provision".into(),
            LiveState::Unreachable(e) => e.clone(),
        }
    }
}

/// Classify `GET /api/cluster/nodes`'s answer (`None`: nothing answered) for
/// `node`. Pure.
pub(crate) fn classify(answer: Option<(u16, &str)>, node: &str) -> LiveState {
    let Some((status, body)) = answer else {
        return LiveState::Unreachable(format!("the gateway did not answer GET {NODES_PATH}"));
    };
    if !(200..=299).contains(&status) {
        return LiveState::Unreachable(format!("GET {NODES_PATH} answered HTTP {status}"));
    }
    let Ok(doc) = serde_json::from_str::<Value>(body) else {
        return LiveState::Unreachable(format!("GET {NODES_PATH} did not answer JSON"));
    };
    let Some(nodes) = doc["nodes"].as_array() else {
        return LiveState::Unreachable(format!("GET {NODES_PATH} answered without a `nodes` list"));
    };
    let Some(rec) = nodes.iter().find(|n| n["id"].as_str() == Some(node)) else {
        return LiveState::Absent;
    };
    // The gateway merges database rows for nodes whose live entry expired
    // and marks them so (routes/cluster.rs: `last_heartbeat_source:
    // "database"`); those rows carry no heartbeat facts.
    let from_db = rec["last_heartbeat_source"].as_str() == Some("database");
    if from_db || rec["status"].as_str() == Some("offline") {
        return LiveState::Offline {
            since: rec["last_heartbeat"].as_str().map(String::from),
            detail: rec["status_detail"].as_str().map(String::from),
        };
    }
    LiveState::Live(rec.clone())
}

/// Ask `fetch` until `node` is live, at most `tries` times, calling `pause`
/// between asks. Returns the last state and how many asks it took. Pure but
/// for its arguments.
///
/// Only a state that can turn live soon is waited on: OFFLINE (a known
/// node whose agent is restarting) and UNREACHABLE (a gateway mid-restart).
/// ABSENT is a node the gateway has never heard from, a first provision
/// before its agent exists, so it is not waited on.
pub(crate) fn wait_live(
    fetch: NodesFetch<'_>,
    node: &str,
    tries: u32,
    pause: &mut dyn FnMut(),
) -> (LiveState, u32) {
    let mut asked = 0;
    loop {
        asked += 1;
        let answer = fetch();
        let state = classify(answer.as_ref().map(|(s, b)| (*s, b.as_str())), node);
        if matches!(state, LiveState::Live(_) | LiveState::Absent) || asked >= tries.max(1) {
            return (state, asked);
        }
        pause();
    }
}

/// The one line a provision prints when it builds without a live record:
/// why, and what the bundle falls back to. `None` when live.
pub(crate) fn fallback_line(node: &str, state: &LiveState, waited_secs: u64) -> Option<String> {
    if state.live().is_some() {
        return None;
    }
    Some(format!(
        "{node} has no live record after {waited_secs}s ({}): its tier comes from the enrollment facts, \
         the bundle is staged uncompressed (no CLI version to prove a gzip-aware fetcher), and the data-root \
         check is skipped",
        state.why()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nodes(list: Value) -> String {
        json!({ "nodes": list }).to_string()
    }

    fn live_awolf() -> Value {
        json!({"id": "awolf", "status": "online", "app_version": "noo-cli-v0.6.20", "derived_tier": 2,
               "data_roots": {"noo_data_root": "/data/noo"}})
    }

    /// The 0.6.20 roll's shape: the gateway's database row for a node whose
    /// live entry expired (routes/cluster.rs merges it as `offline`).
    fn db_row_awolf() -> Value {
        json!({"id": "awolf", "status": "offline", "status_detail": "no heartbeat on the bus",
               "last_heartbeat": "2026-11-09T21:10:04Z", "last_heartbeat_source": "database", "tier": 2})
    }

    #[test]
    fn a_database_row_is_offline_not_a_live_record() {
        let body = nodes(json!([db_row_awolf()]));
        let s = classify(Some((200, &body)), "awolf");
        assert_eq!(s, LiveState::Offline { since: Some("2026-11-09T21:10:04Z".into()), detail: Some("no heartbeat on the bus".into()) });
        assert!(s.live().is_none(), "a database row has no heartbeat facts and must not be read as live");
        let live = nodes(json!([live_awolf()]));
        assert_eq!(classify(Some((200, &live)), "awolf"), LiveState::Live(live_awolf()));
    }

    #[test]
    fn a_failed_fetch_says_why_instead_of_reading_as_nothing() {
        assert!(matches!(classify(None, "awolf"), LiveState::Unreachable(w) if w.contains("did not answer")));
        assert!(matches!(classify(Some((502, "bad gateway")), "awolf"), LiveState::Unreachable(w) if w.contains("HTTP 502")));
        assert!(matches!(classify(Some((200, "<html>")), "awolf"), LiveState::Unreachable(w) if w.contains("JSON")));
        assert_eq!(classify(Some((200, &nodes(json!([live_awolf()])))), "pop-os"), LiveState::Absent);
    }

    #[test]
    fn the_wait_stops_at_the_first_live_record_and_is_bounded() {
        // A just-restarted agent: two asks find the database row, the third
        // its fresh heartbeat.
        let answers = [nodes(json!([db_row_awolf()])), nodes(json!([db_row_awolf()])), nodes(json!([live_awolf()]))];
        let mut i = 0;
        let mut pauses = 0;
        let (s, asked) = wait_live(&mut || { i += 1; Some((200, answers[i - 1].clone())) }, "awolf", 12, &mut || pauses += 1);
        assert_eq!((asked, pauses), (3, 2));
        assert!(s.live().is_some());
        // Never live: exactly `tries` asks, and the last state is returned.
        let mut n = 0;
        let (s, asked) = wait_live(&mut || { n += 1; Some((200, nodes(json!([db_row_awolf()])))) }, "awolf", 4, &mut || {});
        assert_eq!((asked, n), (4, 4));
        assert!(matches!(s, LiveState::Offline { .. }));
    }

    #[test]
    fn a_live_record_gives_the_applier_version_a_wave_checks() {
        // Linux reports its stack tag, a Mac its CLI tag (the 0.6.21 parser).
        let f = LiveState::Live(json!({"id": "aserve", "app_version": "stack-v0.6.21+07ce5047"})).facts().unwrap();
        assert_eq!(f, LiveFacts { app_version: "stack-v0.6.21+07ce5047".into(), applier: Some((0, 6, 21)) });
        let mac = LiveState::Live(json!({"id": "mcmini", "app_version": "noo-cli-v0.6.20"})).facts().unwrap();
        assert_eq!(mac.applier, Some((0, 6, 20)));
        // Live but no version: the facts say so, unparsed.
        let none = LiveState::Live(json!({"id": "x"})).facts().unwrap();
        assert_eq!(none, LiveFacts { app_version: String::new(), applier: None });
        // No live record: no facts at all (never an empty "met").
        assert_eq!(LiveState::Offline { since: None, detail: None }.facts(), None);
        assert_eq!(LiveState::Absent.facts(), None);
    }

    #[test]
    fn a_node_never_heard_from_is_not_waited_on() {
        // A first provision: the agent the bundle installs does not exist yet.
        let mut pauses = 0;
        let (s, asked) = wait_live(&mut || Some((200, nodes(json!([live_awolf()])))), "pop-os", 12, &mut || pauses += 1);
        assert_eq!((s, asked, pauses), (LiveState::Absent, 1, 0));
    }

    #[test]
    fn the_fallback_line_names_why_and_every_fact_it_loses() {
        let line = fallback_line("awolf", &LiveState::Offline { since: Some("2026-11-09T21:10:04Z".into()), detail: None }, 60).unwrap();
        for part in ["awolf has no live record after 60s", "last heartbeat 2026-11-09T21:10:04Z", "enrollment facts",
                     "uncompressed", "data-root check is skipped"] {
            assert!(line.contains(part), "{part:?} missing from {line}");
        }
        let unreachable = fallback_line("awolf", &LiveState::Unreachable("GET /api/cluster/nodes answered HTTP 502".into()), 60).unwrap();
        assert!(unreachable.contains("HTTP 502"), "the swallowed fetch error must be visible: {unreachable}");
        assert_eq!(fallback_line("awolf", &LiveState::Live(live_awolf()), 0), None);
    }
}
