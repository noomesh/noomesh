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
//! The rule: **a group never has zero offered candidates**. A group is what
//! callers fail over within, read from the gateway's own views (no new
//! endpoint):
//!
//! - a model class: the node is in that class's `routing_order` in `GET
//!   /api/cluster/model-classes`;
//! - an embedding space (`embed:<space>`): the node is in that space's pool
//!   in `GET /api/cluster/embedding-spaces`, running and `advertising`. The
//!   embedder is on every RAG request.
//!
//! Before staging node N, for each group N was in at the start of the roll,
//! the candidates that are offered NOW and not staged-and-pending (staged,
//! not yet applied and offered again) are counted, N excluded. N is staged
//! when every group keeps at least [`keep_for`] of them: one, or two for a
//! group of four or more, so one surprise failure does not empty it.
//! Otherwise the roll waits for a pending node to come back, bounded. A group
//! N was the only candidate of cannot be protected: it is said, not waited
//! on.
//!
//! The order ([`stagger_order`]) keeps two nodes of one group apart when
//! another node can sit between them, so a wait overlaps staging that other
//! node. A bound that is hit is said, with what to run, and the roll goes on.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::Globals;
use crate::ui::{self, Glyph};

/// How long a staging waits for pending nodes to come back, counted from the
/// first of them reporting it applied. Observed re-offer times: 30-61 s per
/// chat node on the 0.6.26 roll (i949).
pub(crate) const OFFERED_BUDGET_SECS: u64 = 150;
/// How long a staging waits for a pending node to report applying at all.
const APPLY_BUDGET_SECS: u64 = 600;
const POLL_SECS: u64 = 3;

/// Group -> its members offered now: every class's `routing_order`, and
/// `embed:<space>` for each embedding space's pool nodes running and
/// advertising. An unreadable view adds nothing.
pub(crate) fn groups_now(classes: &Value, spaces: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in classes["classes"].as_array().into_iter().flatten() {
        let Some(name) = c["name"].as_str() else { continue };
        let e = by.entry(name.to_string()).or_default();
        for x in c["routing_order"].as_array().into_iter().flatten() {
            if let Some(n) = x["node_id"].as_str() {
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

/// The candidates a group keeps offered while one of them restarts: one, or
/// two for a group of four or more at the start of the roll.
pub(crate) fn keep_for(size_at_start: usize) -> usize {
    if size_at_start >= 4 { 2 } else { 1 }
}

/// A group that stops a node from being staged now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blocked {
    pub group: String,
    /// Other candidates offered now and not pending.
    pub have: Vec<String>,
    pub need: usize,
    /// The pending candidates whose return would unblock it.
    pub pending: Vec<String>,
}

/// The groups that `node` may not leave yet. `start` is who was offered where
/// when the roll began (it decides the groups and their size), `now` who is
/// offered now, `pending` the nodes staged and not yet back. A group `node`
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
/// keep them offered while it restarts. Said, not waited on.
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

/// The roll's stagger state across the nodes loop.
pub(crate) struct Stagger {
    /// Group -> members offered when the roll started.
    pub start: BTreeMap<String, BTreeSet<String>>,
    /// The rail nodes in staging order, then the self node.
    pub order: Vec<String>,
    /// Staged and not yet back: node -> the sha it was staged with.
    pending: BTreeMap<String, String>,
    /// Lines for the node report: bounds hit, groups that cannot be kept.
    pub notes: Vec<String>,
    pub json: Vec<Value>,
}

impl Stagger {
    /// `rail` is the roll's rail names (sorted); `self_node` is staged after
    /// them. [`Stagger::order`] is the order to stage in.
    pub(crate) fn start(g: &Globals, rail: &[String], self_node: Option<&str>) -> Stagger {
        let (classes, spaces) = read_views(g);
        Stagger::from_views(&classes, &spaces, rail, self_node)
    }

    pub(crate) fn from_views(classes: &Value, spaces: &Value, rail: &[String], self_node: Option<&str>) -> Stagger {
        let start: BTreeMap<String, BTreeSet<String>> =
            groups_now(classes, spaces).into_iter().filter(|(_, m)| !m.is_empty()).collect();
        let mut order = stagger_order(rail, &node_groups(&start));
        order.extend(self_node.map(str::to_string));
        Stagger { start, order, pending: BTreeMap::new(), notes: Vec::new(), json: Vec::new() }
    }

    /// Before staging `node`: wait (bounded) until every group it is in keeps
    /// enough other offered, not-pending candidates.
    pub(crate) fn before(&mut self, g: &Globals, node: &str) {
        let started = std::time::Instant::now();
        let mut first_applied: Option<std::time::Instant> = None;
        let mut said = false;
        loop {
            let (classes, spaces) = read_views(g);
            let now = groups_now(&classes, &spaces);
            self.collect_returned(g, &now);
            let pending: BTreeSet<String> = self.pending.keys().cloned().collect();
            let b = blocked(node, &self.start, &now, &pending);
            if b.is_empty() {
                if said {
                    let secs = started.elapsed().as_secs();
                    ui::say(&ui::sub(&ui::status_line(Glyph::Ok,
                        &format!("{node}: its groups keep enough candidates after {secs}s; staging"))));
                    self.json.push(serde_json::json!({"node": node, "outcome": "waited", "secs": secs}));
                }
                return;
            }
            if !said {
                ui::say(&ui::sub(&ui::status_line(Glyph::Step, &format!("{node}: waiting before staging: {}", describe(&b)))));
                said = true;
            }
            if first_applied.is_none() && self.any_applied(g, &b) {
                first_applied = Some(std::time::Instant::now());
            }
            let over = match first_applied {
                Some(t) => t.elapsed().as_secs() >= OFFERED_BUDGET_SECS,
                None => started.elapsed().as_secs() >= APPLY_BUDGET_SECS,
            };
            if over {
                let secs = started.elapsed().as_secs();
                let back: Vec<String> =
                    b.iter().flat_map(|x| x.pending.clone()).collect::<BTreeSet<_>>().into_iter().collect();
                let line = format!(
                    "{node}: staged after {secs}s without the wait's condition: {} (bound: {OFFERED_BUDGET_SECS}s once a pending node applied, {APPLY_BUDGET_SECS}s if none did). `noo cluster verify --wait` shows whether {} came back; `noo cluster class list` and `noo cluster embedding-space list` show who is offered now",
                    describe(&b),
                    if back.is_empty() { "the pending nodes".to_string() } else { back.join(", ") });
                ui::say(&ui::sub(&ui::status_line(Glyph::Warn, &line)));
                self.notes.push(line);
                self.json.push(serde_json::json!({"node": node, "outcome": "bound", "secs": secs,
                    "blocked": b.iter().map(|x| serde_json::json!({"group": x.group, "have": x.have, "need": x.need, "pending": x.pending})).collect::<Vec<_>>()}));
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(POLL_SECS));
        }
    }

    /// `p` was staged: it is pending until it has applied and is offered
    /// again in every group it started in. A group it alone served is said.
    pub(crate) fn staged(&mut self, p: &super::provision::PendingApply) {
        let sole = sole_groups(&p.node, &self.start);
        if !sole.is_empty() {
            let line = format!("{}: the only node offered for {} when the roll started; those have no candidate while it restarts",
                p.node, sole.join(", "));
            ui::say(&ui::sub(&ui::status_line(Glyph::Warn, &line)));
            self.notes.push(line);
        }
        if node_groups(&self.start).contains_key(&p.node) {
            self.pending.insert(p.node.clone(), p.sha.clone());
        }
    }

    /// Drop from `pending` every node that has applied its staged sha and is
    /// offered again in every group it started in.
    fn collect_returned(&mut self, g: &Globals, now: &BTreeMap<String, BTreeSet<String>>) {
        let mine = node_groups(&self.start);
        let back: Vec<String> = self.pending.iter()
            .filter(|(n, sha)| {
                let all_back = mine.get(*n).into_iter().flatten().all(|grp| now.get(grp).is_some_and(|m| m.contains(*n)));
                all_back && applied(g, n, sha)
            })
            .map(|(n, _)| n.clone())
            .collect();
        for n in back {
            self.pending.remove(&n);
        }
    }

    fn any_applied(&self, g: &Globals, b: &[Blocked]) -> bool {
        b.iter().flat_map(|x| x.pending.iter()).any(|n| self.pending.get(n).is_some_and(|sha| applied(g, n, sha)))
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
        .map(|x| format!("{} keeps {} of the {} other candidate(s) it needs (offered: {}; restarting: {})",
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
        json!({"classes": rows.iter().map(|(c, ns)| json!({
            "name": c,
            "routing_order": ns.iter().map(|n| json!({"node_id": n, "backend": "ollama"})).collect::<Vec<_>>(),
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
}
