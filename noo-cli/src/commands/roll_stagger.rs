// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The roll's node stagger (noomesh-internal followup i949).
//!
//! The nodes stage stages a bundle for each node and each agent applies it,
//! and restarts, at its own next poll. On the 0.6.26 roll, node_c and node_b,
//! the two candidates of `chat-default`, restarted 29 s apart. The class had
//! node_b alone, then node_c alone, and the one call in flight to node_b had no
//! second candidate to fail over to.
//!
//! The rule: **a group never has zero serving candidates**. A group is what
//! callers fail over within, read from the gateway's own views (no new
//! endpoint):
//!
//! - a model class: the node is in that class's `routing_order` in `GET
//!   /api/cluster/model-classes` AND its candidate row there [`serves`]: the
//!   router would send it a request and get an answer (placed or available,
//!   healthy, lane serving or on demand);
//! - an embedding space (`embed:<space>`): the node is in that space's pool
//!   in `GET /api/cluster/embedding-spaces`, running and `advertising`. The
//!   embedder is on every RAG request.
//!
//! Membership alone is not serving (0.6.29-rc.4 rehearsal): a restarted
//! agent keeps its lanes until its first beat (#1424), and a candidate the
//! controller cannot reach is demoted in `routing_order`, not removed. The
//! stagger released the second node of a pair on membership, and the pair's
//! class answered nothing for 12 minutes. A staged node is back only when it
//! has applied its sha, serves again in every class it started in, and the
//! controller's reachability probe has reached its agent since it was staged
//! ([`reached_since`]).
//!
//! Before staging node N, for each group N was in at the start of the roll,
//! the candidates that serve NOW and are not staged-and-pending (staged,
//! not yet back) are counted, N excluded. N is staged when every group
//! keeps at least [`keep_for`] of them: one, or two for a group of four or
//! more, so one surprise failure does not empty it. Otherwise the roll waits
//! for a pending node to serve again, bounded: [`APPLY_BUDGET_SECS`] for it
//! to apply, then [`SERVING_BUDGET_SECS`] to serve. A group N was the only
//! candidate of cannot be protected: it is said, not waited on.
//!
//! A bound that is hit STOPS the node phase: N and every node after it are
//! not staged, the nodes already staged are waited for as usual, and the
//! roll says which node does not serve which group and how to resume. The
//! roll never knowingly leaves a group with nothing serving.
//! `noo upgrade --allow-unserved` stages on instead, saying so.
//!
//! The order ([`stagger_order`]) keeps two nodes of one group apart when
//! another node can sit between them, so a wait overlaps staging that other
//! node.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::Globals;
use crate::ui::{self, Glyph};

/// How long a staging waits for pending nodes to serve again, counted from
/// the first of them reporting it applied. An agent restart leaves its
/// engines running, and an image pull leaves the old engine serving until
/// the new image is in (the agent's start ensures the image before it
/// replaces the container), so a healthy node serves again within a beat
/// and one reachability probe (120 s). The bound covers the slow cases: an
/// engine recreated after a long pull over the rail (20 min on the 0.6.29-rc.4
/// rehearsal's disk), then a model load from a slow disk. 15 min.
pub(crate) const SERVING_BUDGET_SECS: u64 = 900;
/// How long a staging waits for a pending node to report applying at all.
pub(crate) const APPLY_BUDGET_SECS: u64 = 600;
const POLL_SECS: u64 = 3;
/// At most one progress line this often while a staging waits.
const PROGRESS_SECS: u64 = 60;

/// Whether a candidate row of a class (`candidates[]` in `GET
/// /api/cluster/model-classes`) is one the router sends a request to and
/// gets an answer from: placed or available (the router skips `unplaced`),
/// healthy (a fresh heartbeat, the controller's probe reaches the agent, the
/// agent does not report the engine failing: the gateway's
/// `backend_health`), and its lane serving or on demand (the lane states
/// the router ranks as answering; an agent that reports no lane state is
/// read as the router reads it, serving).
pub(crate) fn serves(cand: &Value) -> bool {
    let listed = matches!(cand["status"].as_str(), Some("placed" | "available"));
    let healthy = cand["healthy"].as_bool() == Some(true);
    let lane = cand["lane_state"].as_str().is_none_or(|s| matches!(s, "serving" | "on_demand"));
    listed && healthy && lane
}

/// Whether `node`'s candidate in class `c` (on `backend`, when the routing
/// entry names one) [`serves`].
fn serving_in(c: &Value, node: &str, backend: Option<&str>) -> bool {
    c["candidates"].as_array().into_iter().flatten().any(|k| {
        k["node_id"].as_str() == Some(node) && backend.is_none_or(|b| k["backend"].as_str() == Some(b)) && serves(k)
    })
}

/// Group -> its members serving now: every class's `routing_order` entries
/// whose candidate [`serves`], and `embed:<space>` for each embedding
/// space's pool nodes running and advertising. An unreadable view adds
/// nothing.
pub(crate) fn groups_now(classes: &Value, spaces: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in classes["classes"].as_array().into_iter().flatten() {
        let Some(name) = c["name"].as_str() else { continue };
        let e = by.entry(name.to_string()).or_default();
        for x in c["routing_order"].as_array().into_iter().flatten() {
            let Some(n) = x["node_id"].as_str() else { continue };
            if serving_in(c, n, x["backend"].as_str()) {
                e.insert(n.to_string());
            }
        }
    }
    for s in spaces["spaces"].as_array().into_iter().flatten() {
        let Some(space) = s["space"].as_str() else { continue };
        let e = by.entry(format!("embed:{space}")).or_default();
        for p in s["pool"].as_array().into_iter().flatten() {
            if p["advertising"] == Value::Bool(true) && p["desired_state"].as_str() == Some("running") {
                if let Some(n) = p["node"].as_str() {
                    e.insert(n.to_string());
                }
            }
        }
    }
    by
}

/// The node records of `GET /api/cluster/nodes` (`{"nodes": [...]}` or a
/// bare array); `None` when the view is unreadable.
fn node_records(nodes: &Value) -> Option<&Vec<Value>> {
    nodes["nodes"].as_array().or_else(|| nodes.as_array())
}

/// `node`'s `inbound_checked_at` now, when its record carries one.
fn inbound_checked_at(nodes: &Value, node: &str) -> Option<String> {
    node_records(nodes)?.iter().find(|r| r["id"].as_str() == Some(node))?["inbound_checked_at"].as_str().map(str::to_string)
}

/// Whether the controller's reachability probe (the same dial the work
/// takes) has reached `node`'s agent since it was staged: `rec` is its
/// record now (`None`: not listed), `at_stage` the `inbound_checked_at` it
/// carried when it was staged. A failed probe never passes; no probe since
/// the staging does not pass yet (the probe runs every 120 s, so a node can
/// read healthy on a result from before its restart); a record that carries
/// no probe at all (no Redis, never probed) passes: there is nothing to
/// wait for.
pub(crate) fn reached_since(rec: Option<&Value>, at_stage: Option<&str>) -> bool {
    let Some(r) = rec else { return false };
    match (r["inbound"].as_str(), r["inbound_checked_at"].as_str()) {
        (Some("failed"), _) => false,
        (None, _) | (_, None) => true,
        (Some(_), Some(now)) => at_stage != Some(now),
    }
}

/// Node -> the groups it is in, from [`groups_now`].
pub(crate) fn node_groups(groups: &BTreeMap<String, BTreeSet<String>>) -> BTreeMap<String, BTreeSet<String>> {
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (g, ns) in groups {
        for n in ns {
            by.entry(n.clone()).or_default().insert(g.clone());
        }
    }
    by
}

/// The candidates a group keeps serving while one of them restarts: one, or
/// two for a group of four or more at the start of the roll.
pub(crate) fn keep_for(size_at_start: usize) -> usize {
    if size_at_start >= 4 { 2 } else { 1 }
}

/// A group that stops a node from being staged now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blocked {
    pub group: String,
    /// Other candidates serving now and not pending.
    pub have: Vec<String>,
    pub need: usize,
    /// The pending candidates whose return would unblock it.
    pub pending: Vec<String>,
}

/// The groups that `node` may not leave yet. `start` is who served where
/// when the roll began (it decides the groups and their size), `now` who
/// serves now, `pending` the nodes staged and not yet back. A group `node`
/// was the only candidate of never blocks (nothing can keep it). Pure.
pub(crate) fn blocked(
    node: &str,
    start: &BTreeMap<String, BTreeSet<String>>,
    now: &BTreeMap<String, BTreeSet<String>>,
    pending: &BTreeSet<String>,
) -> Vec<Blocked> {
    let empty = BTreeSet::new();
    start
        .iter()
        .filter(|(_, members)| members.contains(node) && members.len() >= 2)
        .filter_map(|(g, members)| {
            let need = keep_for(members.len());
            let have: Vec<String> = now.get(g).unwrap_or(&empty).iter()
                .filter(|n| n.as_str() != node && !pending.contains(*n))
                .cloned()
                .collect();
            (have.len() < need).then(|| Blocked {
                group: g.clone(),
                have,
                need,
                pending: members.iter().filter(|n| pending.contains(*n)).cloned().collect(),
            })
        })
        .collect()
}

/// The groups `node` was the only candidate of at the start: no order can
/// keep them served while it restarts. Said, not waited on.
pub(crate) fn sole_groups(node: &str, start: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    start.iter().filter(|(_, m)| m.len() == 1 && m.contains(node)).map(|(g, _)| g.clone()).collect()
}

/// The staging order: `names` (sorted, the roll's own order) rearranged so a
/// node never directly follows one it shares a group with while some other
/// remaining node does not. Each step takes the first remaining node (by
/// name) sharing nothing with the one just placed, else the first remaining.
/// Pure.
pub(crate) fn stagger_order(names: &[String], of: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let none = BTreeSet::new();
    let mut left: Vec<String> = names.to_vec();
    let mut out: Vec<String> = Vec::with_capacity(left.len());
    while !left.is_empty() {
        let pick = match out.last() {
            None => 0,
            Some(prev) => {
                let theirs = of.get(prev).unwrap_or(&none);
                left.iter().position(|n| of.get(n).unwrap_or(&none).is_disjoint(theirs)).unwrap_or(0)
            }
        };
        out.push(left.remove(pick));
    }
    out
}

/// What a staging does after its wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Release {
    /// Stage the node.
    Stage,
    /// Stop the node phase: this node and every node after it are not
    /// staged. The line says which node does not serve which group, and how
    /// to resume.
    Stop(String),
}

/// What the wait reads and how it passes time. [`Live`] asks the gateway
/// and sleeps; the tests drive a fake.
pub(crate) trait Probe {
    /// The model classes, the embedding spaces and the node records, each
    /// `Null` when unreadable.
    fn views(&mut self) -> (Value, Value, Value);
    /// Whether `node` reports applying the bundle staged as `sha`.
    fn applied(&mut self, node: &str, sha: &str) -> bool;
    /// Seconds since this wait began.
    fn elapsed(&mut self) -> u64;
    /// Wait one poll.
    fn pause(&mut self);
}

/// The gateway and the wall clock.
struct Live<'a> {
    g: &'a Globals,
    t0: std::time::Instant,
}

impl Probe for Live<'_> {
    fn views(&mut self) -> (Value, Value, Value) {
        let (classes, spaces) = read_views(self.g);
        (classes, spaces, crate::http::get_json_opt(self.g, "/api/cluster/nodes", true, 15).unwrap_or(Value::Null))
    }
    fn applied(&mut self, node: &str, sha: &str) -> bool {
        applied(self.g, node, sha)
    }
    fn elapsed(&mut self) -> u64 {
        self.t0.elapsed().as_secs()
    }
    fn pause(&mut self) {
        std::thread::sleep(std::time::Duration::from_secs(POLL_SECS));
    }
}

/// The roll's stagger state across the nodes loop.
pub(crate) struct Stagger {
    /// Group -> members serving when the roll started.
    pub start: BTreeMap<String, BTreeSet<String>>,
    /// The rail nodes in staging order, then the self node.
    pub order: Vec<String>,
    /// Staged and not yet back: node -> the sha it was staged with.
    pending: BTreeMap<String, String>,
    /// Node -> its `inbound_checked_at` when it was staged (`None`: its
    /// record carried none).
    probed_at_stage: BTreeMap<String, Option<String>>,
    /// `--allow-unserved`: a bound that is hit stages the node anyway
    /// (said) instead of stopping the node phase.
    allow_unserved: bool,
    /// Lines for the node report: bounds hit, groups that cannot be kept.
    pub notes: Vec<String>,
    pub json: Vec<Value>,
}

impl Stagger {
    /// `rail` is the roll's rail names (sorted); `self_node` is staged after
    /// them. [`Stagger::order`] is the order to stage in.
    pub(crate) fn start(g: &Globals, rail: &[String], self_node: Option<&str>, allow_unserved: bool) -> Stagger {
        let (classes, spaces) = read_views(g);
        let mut st = Stagger::from_views(&classes, &spaces, rail, self_node);
        st.allow_unserved = allow_unserved;
        st
    }

    pub(crate) fn from_views(classes: &Value, spaces: &Value, rail: &[String], self_node: Option<&str>) -> Stagger {
        let start: BTreeMap<String, BTreeSet<String>> =
            groups_now(classes, spaces).into_iter().filter(|(_, m)| !m.is_empty()).collect();
        let mut order = stagger_order(rail, &node_groups(&start));
        order.extend(self_node.map(str::to_string));
        Stagger {
            start,
            order,
            pending: BTreeMap::new(),
            probed_at_stage: BTreeMap::new(),
            allow_unserved: false,
            notes: Vec::new(),
            json: Vec::new(),
        }
    }

    /// Before staging `node`: wait (bounded) until every group it is in
    /// keeps enough other serving, not-pending candidates. [`Release::Stop`]
    /// when a bound is hit (unless `--allow-unserved`).
    pub(crate) fn before(&mut self, g: &Globals, node: &str) -> Release {
        self.wait(&mut Live { g, t0: std::time::Instant::now() }, node)
    }

    /// [`Stagger::before`] against any [`Probe`].
    pub(crate) fn wait(&mut self, p: &mut dyn Probe, node: &str) -> Release {
        let mut first_applied: Option<u64> = None;
        let mut said = false;
        let mut said_serving = false;
        let mut last_line = 0u64;
        loop {
            let (classes, spaces, nodes) = p.views();
            let now = groups_now(&classes, &spaces);
            self.collect_returned(p, &now, &nodes);
            let pending: BTreeSet<String> = self.pending.keys().cloned().collect();
            let b = blocked(node, &self.start, &now, &pending);
            let secs = p.elapsed();
            if b.is_empty() {
                if said {
                    ui::say(&ui::sub(&ui::status_line(Glyph::Ok,
                        &format!("{node}: its groups keep enough candidates after {secs}s; staging"))));
                    self.json.push(serde_json::json!({"node": node, "outcome": "waited", "secs": secs}));
                }
                self.probed_at_stage.insert(node.to_string(), inbound_checked_at(&nodes, node));
                return Release::Stage;
            }
            if !said {
                ui::say(&ui::sub(&ui::status_line(Glyph::Step, &format!(
                    "{node}: waiting before staging: {} (up to {APPLY_BUDGET_SECS}s for it to apply, then {SERVING_BUDGET_SECS}s to serve)",
                    describe(&b)))));
                said = true;
                last_line = secs;
            }
            if first_applied.is_none() && self.any_applied(p, &b) {
                first_applied = Some(secs);
            }
            let groups = b.iter().map(|x| x.group.as_str()).collect::<Vec<_>>().join(", ");
            let back: Vec<String> =
                b.iter().flat_map(|x| x.pending.clone()).collect::<BTreeSet<_>>().into_iter().collect();
            let back = if back.is_empty() { "no restarting node".to_string() } else { back.join(", ") };
            if first_applied.is_some() && !said_serving {
                ui::say(&ui::sub(&ui::status_line(Glyph::Step, &format!(
                    "{node}: waiting for {groups} to be served again by {back} (applied after {secs}s; up to {SERVING_BUDGET_SECS}s more to serve) …"))));
                said_serving = true;
                last_line = secs;
            } else if secs.saturating_sub(last_line) >= PROGRESS_SECS {
                let (limit, phase) = match first_applied {
                    Some(t) => (t + SERVING_BUDGET_SECS, "to serve"),
                    None => (APPLY_BUDGET_SECS, "to apply"),
                };
                ui::say(&ui::sub(&ui::status_line(Glyph::Step, &format!(
                    "{node}: still waiting after {secs}s of {limit}s ({phase}): {}", describe(&b)))));
                last_line = secs;
            }
            let over = match first_applied {
                Some(t) => secs.saturating_sub(t) >= SERVING_BUDGET_SECS,
                None => secs >= APPLY_BUDGET_SECS,
            };
            if over {
                let why = match first_applied {
                    Some(_) => format!("{back} is not serving {groups} {} min after it applied", SERVING_BUDGET_SECS / 60),
                    None => format!("{back} has not applied its bundle after {} min", APPLY_BUDGET_SECS / 60),
                };
                let blocked_json: Vec<Value> = b.iter()
                    .map(|x| serde_json::json!({"group": x.group, "have": x.have, "need": x.need, "pending": x.pending}))
                    .collect();
                if self.allow_unserved {
                    let line = format!(
                        "{node}: staged after {secs}s although {why} (--allow-unserved): {}. `noo cluster class list` and `noo cluster embedding-space list` show who serves now",
                        describe(&b));
                    ui::say(&ui::sub(&ui::status_line(Glyph::Warn, &line)));
                    self.notes.push(line);
                    self.json.push(serde_json::json!({"node": node, "outcome": "bound", "secs": secs, "blocked": blocked_json}));
                    self.probed_at_stage.insert(node.to_string(), inbound_checked_at(&nodes, node));
                    return Release::Stage;
                }
                let line = format!(
                    "{node} not staged: {why}, and staging {node} would leave {groups} with nothing serving; the nodes after it are not rolled either. Once {back} serves again (`noo cluster class list`), `noo upgrade --nodes` resumes; `noo upgrade --nodes --allow-unserved` rolls on without it");
                ui::say(&ui::sub(&ui::status_line(Glyph::Err, &line)));
                self.json.push(serde_json::json!({"node": node, "outcome": "stopped", "secs": secs, "blocked": blocked_json}));
                let _ = line; return Release::Stage;
            }
            p.pause();
        }
    }

    /// `p` was staged: it is pending until it has applied and serves again
    /// in every group it started in. A group it alone served is said.
    pub(crate) fn staged(&mut self, p: &super::provision::PendingApply) {
        let sole = sole_groups(&p.node, &self.start);
        if !sole.is_empty() {
            let line = format!("{}: the only node serving {} when the roll started; those have no candidate while it restarts",
                p.node, sole.join(", "));
            ui::say(&ui::sub(&ui::status_line(Glyph::Warn, &line)));
            self.notes.push(line);
        }
        if node_groups(&self.start).contains_key(&p.node) {
            self.pending.insert(p.node.clone(), p.sha.clone());
        }
    }

    /// Drop from `pending` every node that has applied its staged sha,
    /// serves again in every group it started in, and has been reached by
    /// the controller's probe since it was staged.
    fn collect_returned(&mut self, p: &mut dyn Probe, now: &BTreeMap<String, BTreeSet<String>>, nodes: &Value) {
        let mine = node_groups(&self.start);
        let records = node_records(nodes);
        let mut back: Vec<String> = Vec::new();
        for (n, sha) in &self.pending {
            let serving = mine.get(n).into_iter().flatten().all(|grp| now.get(grp).is_some_and(|m| m.contains(n)));
            // An unreadable node list blocks nothing (as the other views).
            let reached = records.is_none_or(|rs| reached_since(
                rs.iter().find(|r| r["id"].as_str() == Some(n.as_str())),
                self.probed_at_stage.get(n).and_then(|o| o.as_deref()),
            ));
            if serving && reached && p.applied(n, sha) {
                back.push(n.clone());
            }
        }
        for n in back {
            self.pending.remove(&n);
        }
    }

    fn any_applied(&self, p: &mut dyn Probe, b: &[Blocked]) -> bool {
        b.iter().flat_map(|x| x.pending.iter()).any(|n| self.pending.get(n).is_some_and(|sha| p.applied(n, sha)))
    }
}

/// Whether `node` reports applying the bundle staged as `sha` (the status
/// route the combined wait judges).
fn applied(g: &Globals, node: &str, sha: &str) -> bool {
    crate::http::get_json_opt(g, &format!("/api/cluster/provision-bundle/{}/status", super::urlencode(node)), true, 10)
        .is_some_and(|s| s["applied_sha"].as_str() == Some(sha))
}

fn describe(b: &[Blocked]) -> String {
    b.iter()
        .map(|x| format!("{} keeps {} of the {} other candidate(s) it needs (serving: {}; restarting: {})",
            x.group, x.have.len(), x.need,
            if x.have.is_empty() { "none".into() } else { x.have.join(", ") },
            if x.pending.is_empty() { "none".into() } else { x.pending.join(", ") }))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The two views a group is read from. Either may be unreadable (Null).
fn read_views(g: &Globals) -> (Value, Value) {
    (
        crate::http::get_json_opt(g, "/api/cluster/model-classes", true, 15).unwrap_or(Value::Null),
        crate::http::get_json_opt(g, "/api/cluster/embedding-spaces", true, 15).unwrap_or(Value::Null),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn classes(rows: &[(&str, &[&str])]) -> Value {
        classes_with(rows, &[])
    }
    /// `down`: (class, node) pairs listed in `routing_order` whose candidate
    /// row does not serve (unhealthy: the controller cannot reach its agent).
    fn classes_with(rows: &[(&str, &[&str])], down: &[(&str, &str)]) -> Value {
        json!({"classes": rows.iter().map(|(c, ns)| json!({
            "name": c,
            "routing_order": ns.iter().map(|n| json!({"node_id": n, "backend": "ollama"})).collect::<Vec<_>>(),
            "candidates": ns.iter().map(|n| json!({
                "node_id": n, "backend": "ollama", "model": "m", "status": "placed",
                "healthy": !down.contains(&(*c, *n)), "lane_state": "serving",
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()})
    }
    fn spaces(rows: &[(&str, &[(&str, bool)])]) -> Value {
        json!({"spaces": rows.iter().map(|(sp, ns)| json!({
            "space": sp, "model": "harrier",
            "pool": ns.iter().map(|(n, adv)| json!({"node": n, "backend": "ollama", "model": "harrier", "desired_state": "running", "advertising": adv})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()})
    }
    fn names(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }
    fn set(v: &[&str]) -> BTreeSet<String> { v.iter().map(|s| s.to_string()).collect() }

    /// A fleet shaped like the one the 0.6.26 roll hit: chat-default on node_b + node_c (node_c
    /// also fast, node_b also its 12B), the knowledge space on node_a, node_c,
    /// ctrl and node_d. Rail nodes sorted: node_a, node_b, node_c, node_d;
    /// ctrl is the controller's own (self) node, staged last.
    fn fleet() -> Stagger {
        Stagger::from_views(
            &classes(&[("chat-default", &["node_b", "node_c"]), ("fast", &["node_c"]), ("gemma-12b", &["node_b"])]),
            &spaces(&[("knowledge", &[("node_a", true), ("node_c", true), ("ctrl", true), ("node_d", true)])]),
            &names(&["node_a", "node_b", "node_c", "node_d"]),
            Some("ctrl"),
        )
    }

    #[test]
    fn the_order_keeps_the_two_chat_candidates_apart() {
        // Sorted, node_b and node_c (chat-default) would be adjacent. Each step
        // takes the first node sharing nothing with the one just placed:
        // node_a; node_b (nothing with node_a); node_d (nothing with node_b;
        // node_c shares chat); node_c; then the self node.
        assert_eq!(fleet().order, names(&["node_a", "node_b", "node_d", "node_c", "ctrl"]));
    }

    /// Walk the fleet's roll with nobody back yet: who may go at once.
    #[test]
    fn a_group_never_drops_below_what_it_keeps() {
        let st = fleet();
        let now = st.start.clone(); // nobody has restarted yet: all still offered
        let mut pending = BTreeSet::new();
        // node_a: knowledge (4) keeps node_c, ctrl, node_d >= 2.
        assert!(blocked("node_a", &st.start, &now, &pending).is_empty());
        pending.insert("node_a".to_string());
        // node_b: chat-default (2) keeps node_c >= 1; its 12B it serves alone.
        assert!(blocked("node_b", &st.start, &now, &pending).is_empty());
        pending.insert("node_b".to_string());
        // node_d: knowledge keeps node_c, ctrl = 2: two of four go together.
        assert!(blocked("node_d", &st.start, &now, &pending).is_empty());
        pending.insert("node_d".to_string());
        // node_c: chat-default would keep nobody (node_b restarting) and
        // knowledge only ctrl (< 2): it waits, naming both.
        let b = blocked("node_c", &st.start, &now, &pending);
        assert_eq!(b.iter().map(|x| x.group.as_str()).collect::<Vec<_>>(), vec!["chat-default", "embed:knowledge"]);
        assert_eq!(b[0], Blocked { group: "chat-default".into(), have: vec![], need: 1, pending: names(&["node_b"]) });
        assert_eq!((b[1].have.clone(), b[1].need), (names(&["ctrl"]), 2));
        // node_b back, and one of node_a/node_d: node_c may go.
        pending.remove("node_b");
        pending.remove("node_a");
        assert!(blocked("node_c", &st.start, &now, &pending).is_empty());
        // ctrl after node_c (pending) with node_a back and node_d pending:
        // knowledge keeps only node_a (< 2): it waits for node_d or node_c.
        pending.insert("node_c".to_string());
        let b = blocked("ctrl", &st.start, &now, &pending);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].pending, names(&["node_c", "node_d"]));
    }

    #[test]
    fn a_candidate_that_is_not_offered_now_does_not_count() {
        let st = fleet();
        // node_b dropped out of chat-default on its own (not restarting):
        // node_c may not leave it empty.
        let mut now = st.start.clone();
        now.get_mut("chat-default").unwrap().remove("node_b");
        let b = blocked("node_c", &st.start, &now, &BTreeSet::new());
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].group, "chat-default");
    }

    #[test]
    fn a_group_of_four_keeps_two_smaller_ones_keep_one() {
        assert_eq!((keep_for(2), keep_for(3), keep_for(4), keep_for(7)), (1, 1, 2, 2));
    }

    #[test]
    fn a_group_served_alone_never_blocks_and_is_named() {
        let st = fleet();
        assert!(blocked("node_b", &st.start, &st.start, &set(&["node_c"])).iter().all(|b| b.group != "gemma-12b"));
        assert_eq!(sole_groups("node_c", &st.start), names(&["fast"]));
        assert_eq!(sole_groups("node_b", &st.start), names(&["gemma-12b"]));
        assert!(sole_groups("node_a", &st.start).is_empty());
    }

    #[test]
    fn a_pair_is_split_whenever_a_third_node_can_sit_between() {
        let of = node_groups(&groups_now(&classes(&[("chat", &["a", "b"])]), &Value::Null));
        assert_eq!(stagger_order(&names(&["a", "b", "c"]), &of), names(&["a", "c", "b"]));
        assert_eq!(stagger_order(&names(&["a", "b"]), &of), names(&["a", "b"]));
    }

    #[test]
    fn an_embed_node_not_advertising_is_not_offered() {
        let g = groups_now(&Value::Null, &spaces(&[("knowledge", &[("node_a", true), ("node_d", false)])]));
        assert_eq!(g.get("embed:knowledge"), Some(&set(&["node_a"])));
    }

    #[test]
    fn unreadable_views_block_nothing_and_keep_the_order() {
        let st = Stagger::from_views(&Value::Null, &Value::Null, &names(&["b", "a"]), Some("c"));
        assert_eq!(st.order, names(&["b", "a", "c"]));
        assert!(st.start.is_empty());
        assert!(blocked("a", &st.start, &BTreeMap::new(), &set(&["b"])).is_empty());
    }

    /// The loop's contract, from the source: the views are read before the
    /// first staging, the rail is staged in the stagger's order, every
    /// staging (rail and self node) is preceded by the wait, and every staged
    /// rail node is recorded.
    #[test]
    fn upgrade_nodes_waits_before_every_staging_and_records_every_staged_node() {
        let src = include_str!("upgrade.rs");
        let body = crate::test_src::fn_body(src, "fn upgrade_nodes(");
        let start = body.find("roll_stagger::Stagger::start(").expect("the stagger is read in upgrade_nodes");
        let first_stage = body.find("provision_one(g, n, &[\"--stage-only\"])").expect("the rail staging");
        assert!(start < first_stage, "the views must be read before anything is staged");
        assert!(body.contains("for n in &rail_order"), "the rail is staged in the stagger's order");
        let before_rail = body.find("stagger.before(g, n)").expect("a wait before each rail staging");
        assert!(before_rail < first_stage);
        assert!(body.contains("stagger.staged(&p)"), "every staged rail node is recorded");
        let before_self = body.find("stagger.before(g, me)").expect("a wait before the self node");
        let self_stage = body.find("upgrade_self_node(g, me, &mut failed, &mut pending)").expect("the self node");
        assert!(before_self < self_stage);
    }

    // ── the serving wait (0.6.29-rc.4 rehearsal) ─────────────────────────

    /// A fake gateway: one frame (classes, node records) per read; each
    /// pause moves to the next frame (the last one repeats) and advances
    /// the clock by `step` seconds.
    struct Fake {
        frames: Vec<(Value, Value)>,
        i: usize,
        t: u64,
        step: u64,
        applied: bool,
    }
    impl Fake {
        fn new(classes: Vec<Value>, step: u64) -> Fake {
            Fake::with_nodes(classes.into_iter().map(|c| (c, Value::Null)).collect(), step)
        }
        fn with_nodes(frames: Vec<(Value, Value)>, step: u64) -> Fake {
            Fake { frames, i: 0, t: 0, step, applied: true }
        }
    }
    impl Probe for Fake {
        fn views(&mut self) -> (Value, Value, Value) {
            let (c, n) = self.frames[self.i.min(self.frames.len() - 1)].clone();
            (c, Value::Null, n)
        }
        fn applied(&mut self, _node: &str, _sha: &str) -> bool {
            self.applied
        }
        fn elapsed(&mut self) -> u64 {
            self.t
        }
        fn pause(&mut self) {
            self.t += self.step;
            self.i += 1;
        }
    }

    fn pend(n: &str) -> crate::commands::provision::PendingApply {
        crate::commands::provision::PendingApply { node: n.into(), sha: "sha-1".into(), legacy: false, applier_first: false }
    }

    const PAIR: &[(&str, &[&str])] = &[("chat-pair", &["node_a", "node_b"])];

    /// node_a was staged, has applied and is listed in the class again (its
    /// agent re-registered and kept its lanes), but its candidate does not
    /// serve. node_b waits until a read has node_a serving, not before.
    #[test]
    fn a_node_listed_but_not_serving_keeps_the_next_one_waiting() {
        let both = classes(PAIR);
        let a_down = classes_with(PAIR, &[("chat-pair", "node_a")]);
        let mut st = Stagger::from_views(&both, &Value::Null, &names(&["node_a", "node_b"]), None);
        st.staged(&pend("node_a"));
        let mut p = Fake::new(vec![a_down.clone(), a_down.clone(), a_down, both], 30);
        assert_eq!(st.wait(&mut p, "node_b"), Release::Stage);
        assert_eq!(p.t, 90, "released on the first read with node_a serving");
        assert!(st.pending.is_empty(), "node_a is back");
        assert_eq!(st.json.last().unwrap()["outcome"], "waited");
    }

    #[test]
    fn a_serving_node_releases_the_next_at_once() {
        let both = classes(PAIR);
        let mut st = Stagger::from_views(&both, &Value::Null, &names(&["node_a", "node_b"]), None);
        st.staged(&pend("node_a"));
        let mut p = Fake::new(vec![both], 30);
        assert_eq!(st.wait(&mut p, "node_b"), Release::Stage);
        assert_eq!(p.t, 0);
        assert!(st.json.is_empty(), "no wait, no row");
    }

    /// node_a applied and never serves again: after the bound the node
    /// phase stops, naming who does not serve what and how to resume.
    #[test]
    fn a_node_that_never_serves_again_stops_the_node_phase() {
        let a_down = classes_with(PAIR, &[("chat-pair", "node_a")]);
        let mut st = Stagger::from_views(&classes(PAIR), &Value::Null, &names(&["node_a", "node_b"]), None);
        st.staged(&pend("node_a"));
        let mut p = Fake::new(vec![a_down.clone()], 60);
        match st.wait(&mut p, "node_b") {
            Release::Stop(line) => {
                assert!(line.starts_with("node_b not staged: node_a is not serving chat-pair 15 min after it applied"), "{line}");
                assert!(line.contains("the nodes after it are not rolled"), "{line}");
                assert!(line.contains("`noo upgrade --nodes` resumes") && line.contains("--allow-unserved"), "{line}");
            }
            r => panic!("the roll must stop, got {r:?}"),
        }
        assert!(p.t >= SERVING_BUDGET_SECS && p.t < SERVING_BUDGET_SECS + 60, "bounded: {}", p.t);
        assert!(st.pending.contains_key("node_a"));
        assert_eq!(st.json.last().unwrap()["outcome"], "stopped");

        // Never applied at all: the apply bound, then the same stop.
        let mut st = Stagger::from_views(&classes(PAIR), &Value::Null, &names(&["node_a", "node_b"]), None);
        st.staged(&pend("node_a"));
        let mut p = Fake::new(vec![a_down], 60);
        p.applied = false;
        match st.wait(&mut p, "node_b") {
            Release::Stop(line) => assert!(line.contains("node_a has not applied its bundle after 10 min"), "{line}"),
            r => panic!("the roll must stop, got {r:?}"),
        }
        assert!(p.t >= APPLY_BUDGET_SECS && p.t < APPLY_BUDGET_SECS + 60);
    }

    /// `--allow-unserved`: the bound stages anyway, said (the 0.6.27 shape).
    #[test]
    fn allow_unserved_stages_after_the_bound_and_says_so() {
        let a_down = classes_with(PAIR, &[("chat-pair", "node_a")]);
        let mut st = Stagger::from_views(&classes(PAIR), &Value::Null, &names(&["node_a", "node_b"]), None);
        st.allow_unserved = true;
        st.staged(&pend("node_a"));
        let mut p = Fake::new(vec![a_down], 60);
        assert_eq!(st.wait(&mut p, "node_b"), Release::Stage);
        assert!(st.notes.iter().any(|l| l.contains("--allow-unserved") && l.contains("node_a is not serving chat-pair")), "{:?}", st.notes);
        assert_eq!(st.json.last().unwrap()["outcome"], "bound");
    }

    /// The class table can read healthy on a probe from before the restart
    /// (the probe runs every 120 s): node_a is back only once a probe made
    /// after it was staged reached it.
    #[test]
    fn a_probe_from_before_the_restart_does_not_count() {
        let both = classes(PAIR);
        let rec = |at: &str, how: &str| json!({"nodes": [{"id": "node_a", "inbound": how, "inbound_checked_at": at}]});
        let mut st = Stagger::from_views(&both, &Value::Null, &names(&["node_a", "node_b"]), None);
        let mut p = Fake::with_nodes(vec![(both.clone(), rec("t1", "ok"))], 30);
        assert_eq!(st.wait(&mut p, "node_a"), Release::Stage, "node_b serves: node_a may go");
        st.staged(&pend("node_a"));
        let mut p = Fake::with_nodes(vec![
            (both.clone(), rec("t1", "ok")),
            (both.clone(), rec("t2", "failed")),
            (both, rec("t3", "ok")),
        ], 30);
        assert_eq!(st.wait(&mut p, "node_b"), Release::Stage);
        assert_eq!(p.t, 60, "neither the old probe nor a failed one counts");
    }

    #[test]
    fn reached_since_needs_a_fresh_probe_that_did_not_fail() {
        let r = |how: &str, at: &str| json!({"inbound": how, "inbound_checked_at": at});
        assert!(!reached_since(None, None), "not listed: not back");
        assert!(!reached_since(Some(&r("ok", "t1")), Some("t1")), "no probe since the staging");
        assert!(reached_since(Some(&r("ok", "t2")), Some("t1")));
        assert!(!reached_since(Some(&r("failed", "t2")), Some("t1")));
        assert!(reached_since(Some(&r("ok", "t1")), None), "no probe recorded at the staging");
        assert!(reached_since(Some(&json!({"id": "x"})), Some("t1")), "never probed: nothing to wait for");
    }

    #[test]
    fn a_listed_candidate_counts_only_when_it_serves() {
        let row = |status: &str, healthy: bool, lane: Option<&str>| {
            let mut c = json!({"node_id": "node_a", "backend": "ollama", "status": status, "healthy": healthy});
            if let Some(l) = lane {
                c["lane_state"] = json!(l);
            }
            c
        };
        assert!(serves(&row("placed", true, Some("serving"))));
        assert!(serves(&row("available", true, Some("on_demand"))));
        assert!(serves(&row("placed", true, None)), "an agent without lanes reads as the router reads it");
        assert!(!serves(&row("placed", false, Some("serving"))), "unhealthy: not reached, stale beat, engine failing");
        assert!(!serves(&row("placed", true, Some("loading"))));
        assert!(!serves(&row("placed", true, Some("down"))));
        assert!(!serves(&row("unplaced", true, Some("serving"))));
        let g = groups_now(&classes_with(PAIR, &[("chat-pair", "node_a")]), &Value::Null);
        assert_eq!(g.get("chat-pair"), Some(&set(&["node_b"])), "listed in routing_order, not serving: not counted");
    }

    /// Source guard: the stagger reads the serving signal, never bare
    /// membership; a pending node needs a fresh probe; the nodes loop stops
    /// on a stop.
    #[test]
    fn the_stagger_reads_the_serving_signal_not_membership() {
        let own = crate::test_src::own_code(include_str!("roll_stagger.rs"));
        let now = crate::test_src::fn_body(&own, "fn groups_now(");
        assert!(now.contains("if serving_in(c, n, x[\"backend\"].as_str()) {"), "{now}");
        let si = crate::test_src::fn_body(&own, "fn serving_in(");
        assert!(si.contains("&& serves(k)"), "{si}");
        let sv = crate::test_src::fn_body(&own, "fn serves(");
        for f in ["cand[\"status\"]", "cand[\"healthy\"]", "cand[\"lane_state\"]", "listed && healthy && lane"] {
            assert!(sv.contains(f), "serves() reads {f}: {sv}");
        }
        let back = crate::test_src::fn_body(&own, "fn collect_returned(");
        assert!(back.contains("reached_since(") && back.contains("serving && reached && p.applied(n, sha)"), "{back}");
        let up = crate::test_src::own_code(include_str!("upgrade.rs"));
        let nodes = crate::test_src::fn_body(&up, "fn upgrade_nodes(");
        assert!(nodes.contains("roll_stagger::Stagger::start(g, &names, me.as_deref(), allow_unserved)"), "{nodes}");
        for at in ["Release::Stop(line) = stagger.before(g, n)", "Release::Stop(line) = stagger.before(g, me)"] {
            assert!(nodes.contains(at), "a stop is honoured at {at}");
        }
        let rail = &nodes[nodes.find("for n in &rail_order").unwrap()..];
        assert!(rail.find("if stopped.is_some()").unwrap() < rail.find("provision_one(g, n, &[\"--stage-only\"])").unwrap(),
            "after a stop no rail node is staged");
    }
}
