// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Model classes and aliases — what an external consumer may ask for, and
//! the ordered list of concrete backends that answer for it
//! phase 1.
//!
//! A *class* is a name a consumer sends as `model` (`chat-default`,
//! `gemma4:12b`, `fast`), resolving to an ORDERED list of candidates — one
//! `(node, backend, model)` each. An *alias* is a second name for a class
//! (`default`, `auto`, an operator-declared spelling of the same model).
//!
//! Two sources, one table:
//!
//! * **Declared** (`noo_model_classes` + `noo_model_aliases`, written by
//!   `noo cluster class set` / `cluster seed`). A declared candidate's
//!   `model` is NULL when it means "whatever the placement on that node
//!   serves" — the table never restates what `noo_backend_placements`
//!   already declares. Only a declared candidate may carry `degraded:
//!   true`, and only a degraded candidate may answer with a different
//!   model than the class's first one.
//! * **Derived** when nothing is declared: one class per distinct served
//!   model, holding only that model's candidates. A request that NAMES a
//!   model goes to that model's nodes first (see "Preferences" below).
//!
//! ## `chat-default` is the whole mesh (operator rule, 2026-10-17)
//!
//! An unpinned request (`model` absent, `default`, `auto`, blank) means
//! "any live chat-capable node", chosen per request. Undeclared,
//! `chat-default` is **dynamic**: every running chat-role candidate on
//! every node, whatever model it serves, ranked by [`rank_key`]. Nodes are
//! multipurpose and come and go — a busy, hot, stalled or offline node
//! drops down or out of the ranking on its own and climbs back the same
//! way; nothing is pinned to one model or one node. The yaml's
//! `cluster.backends.<x>.model` is a PLACEMENT hint (what onboarding put on
//! the local backend), never a routing pin: it does not narrow the default.
//!
//! Three things steer an unpinned request: a concrete model name (its
//! derived class), an explicit node (`node` / `X-Noo-Node`, see
//! [`select`]), or a DECLARED `chat-default` (`noo cluster class set
//! chat-default …`). `noo cluster class list` says which default is live:
//! `dynamic (all live chat nodes)` or `declared`.
//!
//! ## Preferences, not selections (operator rule, 2026-10-19)
//!
//! A model name, an alias, a declared class — all of them say which
//! candidates to try FIRST, never which are the only ones. Behind a class's
//! own candidates [`select`] appends every other live chat candidate in the
//! dynamic ranking (`fallback,` in the rank, `+mesh` in the label), and a
//! model nothing serves resolves to the dynamic default instead of a 404.
//! The mesh heals: when the node a caller preferred is off doing something
//! else, another node answers, slower or smaller, and the served-model
//! header says which. Live failure that day: trellion named awolf's vLLM
//! model while awolf's GPU ran a voice test, and every knowledge answer
//! failed with `model_not_found` although two other nodes served chat.
//! A node pin is a preference too: that node first, then the class's other
//! nodes, then the mesh. Only a STRICT node pin (`X-Noo-Node-Strict` /
//! `node_strict`, for locality or privacy) keeps a request on one node.
//!
//! The dynamic ranking, lowest first ([`rank_key`]): degraded, unhealthy
//! (stale heartbeat, unreachable, quarantined), stalled in the last
//! [`STALL_DEMOTION`] (5 min), thermal `serious`/`critical`, GPU shared
//! with a foreign workload (`gpu_contention.state: shared`; a lane listed in
//! `gpu_contention.paused_backends` is not a candidate at all), engine (vLLM,
//! then a GPU runtime, then CPU), larger model first (parameter estimate,
//! [`quality_of`]), fewest requests in flight from this gateway, heartbeat
//! load. A quarantined node and a thermal-`critical` node are EXCLUDED
//! (`skipped`) unless nothing else is left, and then used with a warning.
//!
//! A declared class may be a **pool** (`noo cluster class set … --pool`):
//! its non-degraded candidates are peers, not a failover order. Each
//! request goes to the healthy one with the fewest requests this gateway
//! has in flight to it, then the lowest heartbeat load, then position —
//! so one class spreads across nodes instead of queueing on the first.
//! Peers may serve different models (the operator declared them
//! interchangeable); failover and `--degraded` work as in any class. A
//! request that names a concrete model or node still goes exactly there.
//!
//! Resolution of a `model` hint: absent / `default` / `auto` → `chat-default`;
//! an alias → its class; a class name → that class; a concrete model name →
//! the derived class of that model, then the rest of the mesh; a name
//! nothing serves → `chat-default`. Candidate order within a class:
//! non-degraded before degraded, healthy before not, declared position,
//! then load.
//!
//! The pure parts (`build_table`, `resolve_hint`, `ordered`) take plain
//! facts and are tested without NATS or Postgres; `load_table` is the thin
//! loader that reads the `mesh_nodes` KV, the placements and the
//! declarations (both cached ~30 s, operator speed, like `non_chat_backends`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::state::AppState;

/// The class every unqualified request resolves to.
pub const CHAT_DEFAULT: &str = "chat-default";

/// Built-in aliases for [`CHAT_DEFAULT`]. `model_hint` already drops them,
/// so they reach the resolver as `None`; they are listed here so the
/// catalogue can show them as ids a consumer may send.
pub const BUILTIN_ALIASES: [&str; 2] = ["default", "auto"];

/// The node agent's heartbeat cadence (node-agent-go `config.HeartbeatInterval`
/// default, seconds). A record older than twice this is a node the gateway
/// is not hearing from; its candidates sort after the ones it is.
pub const HEARTBEAT_INTERVAL_SECS: f64 = 30.0;

/// Backend types that can serve chat (the same set the legacy resolver scans).
const INFERENCE_TYPES: [&str; 4] = ["vllm", "vllm-secondary", "ollama", "llamacpp"];

/// How long a candidate that stalled (connected, then produced nothing in
/// time) or timed out sorts after every candidate that did not. Five
/// minutes: long enough that a wedged engine or a node busy with something
/// else (a GPU in a VR session, a model build) stops taking every new
/// request in its first 30 s window, short enough that it rejoins on its
/// own once it recovers. Process-wide, written by the raw chat failover
/// loop and the agent loop's `send_llm_with_fallback`.
pub const STALL_DEMOTION: Duration = Duration::from_secs(300);

// ── declarations ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeclaredCandidate {
    pub node_id: String,
    pub backend: String,
    /// `None` = the model the placement (or, failing that, the node's
    /// heartbeat) says this backend serves.
    pub model: Option<String>,
    pub degraded: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DeclaredClass {
    pub name: String,
    pub candidates: Vec<DeclaredCandidate>,
    /// Non-degraded candidates share the load instead of failing over in
    /// order (see the module doc).
    pub pool: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declarations {
    pub classes: Vec<DeclaredClass>,
    /// `(alias, class)`.
    pub aliases: Vec<(String, String)>,
}

/// A class or alias name an operator may declare: lowercase-insensitive
/// ASCII letters, digits and `. _ - : /`, 1..=128 chars, and not a built-in
/// alias (those always mean `chat-default`).
pub fn valid_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 128 {
        return Err("a class or alias name is 1-128 characters".into());
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/')) {
        return Err(format!("'{n}' has characters outside [A-Za-z0-9._-:/]"));
    }
    if BUILTIN_ALIASES.iter().any(|b| b.eq_ignore_ascii_case(n)) {
        return Err(format!("'{n}' is a built-in alias of {CHAT_DEFAULT} and cannot be redeclared"));
    }
    Ok(())
}

// ── facts ────────────────────────────────────────────────────────────────

/// What the gateway knows about one node, flattened from its `mesh_nodes`
/// record and the placements table. Built by [`node_facts_from_kv`]; tests
/// build it by hand.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeFacts {
    pub node_id: String,
    pub ip: String,
    /// `(backend, model)` the heartbeat reports running.
    pub running: Vec<(String, String)>,
    /// Model names the node has locally (Ollama tags, GGUFs).
    pub available_models: Vec<String>,
    /// Backends whose `model_presence.present` is `false`.
    pub model_missing: Vec<String>,
    /// Backends whose placement role is not `chat`.
    pub non_chat: Vec<String>,
    /// `(backend, model)` the agent's `model_presence` reports under a role
    /// other than chat (`ollama#embed`). Empty from an agent that predates
    /// the field: the placements and the name registry still apply.
    pub reported_non_chat_models: Vec<(String, String)>,
    pub load: f64,
    pub tier: Option<i64>,
    /// `vram_gb > 0`, or unified memory (Apple silicon).
    pub gpu: bool,
    /// Seconds since the last heartbeat; `None` = no timestamp.
    pub heartbeat_age_secs: Option<f64>,
    /// `false` only when the reachability probe RECORDED a failure.
    pub inbound_ok: bool,
    /// The heartbeat's `thermal_state` (`nominal|fair|serious|critical`).
    pub thermal: Option<String>,
    /// `status: quarantined` (the auto-quarantine evaluator's verdict).
    pub quarantined: bool,
    /// `status: offline`.
    pub offline: bool,
    /// `(model, size_bytes)` from the heartbeat's `model_stats`.
    pub model_sizes: Vec<(String, u64)>,
    /// `gpu_contention.state == "shared"`: something else on the node (a
    /// game, a model build) is using the GPU. Absent = free.
    pub gpu_shared: bool,
    /// `gpu_contention.paused_backends`: lanes the node yielded; never
    /// candidates while listed.
    pub paused_backends: Vec<String>,
}

/// One row of `noo_backend_placements` as the table needs it:
/// `(node_id, backend, model, role)`.
pub type PlacementRow = (String, String, Option<String>, String);

// ── the table ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// The node's heartbeat reports this backend serving this model.
    Placed,
    /// Not running, but the model is in the node's `available_models`; the
    /// node proxy passes a named model through, so it is routable.
    Available,
    /// Neither — skipped at routing, reported by `noo cluster verify`.
    Unplaced,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Candidate {
    pub node_id: String,
    pub backend: String,
    pub model: String,
    /// What the declaration said, when it said anything: `None` = "the
    /// placement's model". Exported by `cluster seed --export` so a seed
    /// file never restates a placement.
    pub declared_model: Option<String>,
    /// Declared position (0 = first). Derived classes number their sort order.
    pub position: usize,
    pub degraded: bool,
    pub status: CandidateStatus,
    pub healthy: bool,
    /// Why not healthy, for the operator surfaces; empty when healthy.
    pub health: String,
    pub load: f64,
    /// The node-agent address work is sent to (`https://<ip>:8081`), or the
    /// controller-local docker URL when the node has no registered address.
    /// Not serialised: no API surface carries a dial address.
    #[serde(skip)]
    pub url: String,
    #[serde(skip)]
    tier: Option<i64>,
    /// `vram_gb > 0` or unified memory on the node.
    pub gpu: bool,
    /// Parameter estimate in billions ([`quality_of`]); `None` = unknown.
    pub params_b: Option<f64>,
    /// The node's `thermal_state`, when it reports one.
    pub thermal: Option<String>,
    pub quarantined: bool,
    /// The node reports its GPU shared with a foreign workload.
    pub gpu_shared: bool,
    /// The class this candidate was selected through, as logs print it
    /// (`chat-default(dynamic)`); set by [`select`].
    #[serde(skip)]
    pub class_label: String,
    /// Why it ranks where it does (`rank=gpu,params=12,load=0.20`); set by
    /// [`select`] for the logs.
    #[serde(skip)]
    pub rank: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Class {
    pub name: String,
    pub declared: bool,
    pub candidates: Vec<Candidate>,
    /// A declared pool: candidates are picked by in-flight requests and load.
    pub pool: bool,
    /// The undeclared `chat-default`: every live chat candidate on every
    /// node, ranked by [`rank_key`].
    pub dynamic: bool,
}

impl Candidate {
    /// A candidate the legacy resolver produced (the static `OLLAMA_URL`
    /// last resort on a standalone controller): routable, assumed healthy,
    /// first and only.
    pub fn synthetic(node_id: String, backend: String, model: String, url: String) -> Candidate {
        Candidate {
            node_id,
            backend,
            model,
            declared_model: None,
            position: 0,
            degraded: false,
            status: CandidateStatus::Placed,
            healthy: true,
            health: String::new(),
            load: 0.0,
            url,
            tier: None,
            gpu: false,
            params_b: None,
            thermal: None,
            quarantined: false,
            gpu_shared: false,
            class_label: String::new(),
            rank: String::new(),
        }
    }

    /// Thermal `critical` or quarantined: out of a dynamic default or a pool
    /// unless nothing else is left. The reason, for the logs.
    pub fn exclusion(&self) -> Option<String> {
        if self.quarantined {
            Some("quarantined".into())
        } else if self.thermal.as_deref() == Some("critical") {
            Some("thermal critical".into())
        } else {
            None
        }
    }
}

impl Class {
    pub fn healthy_count(&self) -> usize {
        self.candidates.iter().filter(|c| c.healthy && c.status != CandidateStatus::Unplaced).count()
    }
    pub fn routable_count(&self) -> usize {
        self.candidates.iter().filter(|c| c.status != CandidateStatus::Unplaced).count()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ClassTable {
    pub classes: Vec<Class>,
    /// `(alias, class)`, built-ins first.
    pub aliases: Vec<(String, String)>,
    /// The dynamic pool of every live chat candidate, kept even when
    /// `chat-default` is declared: a node pin with no model selects from it.
    #[serde(skip)]
    pub all_chat: Option<Class>,
    /// Every node with a heartbeat record, chat-capable or not — so a node
    /// pin can tell "no such node" (422) from "serves no chat" (409).
    #[serde(skip)]
    pub nodes: Vec<String>,
}

impl ClassTable {
    pub fn class(&self, name: &str) -> Option<&Class> {
        self.classes.iter().find(|c| c.name == name)
            .or_else(|| self.classes.iter().find(|c| same_model(&c.name, name)))
    }

    /// Every id a consumer may send as `model`: classes then aliases.
    pub fn ids(&self) -> Vec<String> {
        let mut out: Vec<String> = self.classes.iter().map(|c| c.name.clone()).collect();
        for (a, _) in &self.aliases {
            if !out.iter().any(|x| x == a) {
                out.push(a.clone());
            }
        }
        out
    }
}

/// Ollama reports `name:tag` and treats a missing tag as `:latest`; neither
/// runtime's naming is case-significant. Same rule as `model_matches_pin`.
pub fn norm_model(m: &str) -> String {
    let m = m.trim().to_ascii_lowercase();
    m.strip_suffix(":latest").map(str::to_string).unwrap_or(m)
}

fn same_model(a: &str, b: &str) -> bool {
    norm_model(a) == norm_model(b)
}

/// True for a model name that is an embedding or reranking model, never a
/// chat model: the registry that still works when an old agent sends no role
/// and no placement names the model (the controller's adopted
/// `noo-ollama-embed` hosts the embedder without any embed placement row).
/// Conservative on purpose: a family name or an explicit `embed`/`rerank`
/// token, nothing a chat model is called.
pub fn is_embedding_model_name(model: &str) -> bool {
    let m = norm_model(model);
    let base = m.rsplit('/').next().unwrap_or(&m);
    if base.contains("embed") || base.contains("rerank") {
        return true;
    }
    ["harrier", "bge-", "bge:", "e5-", "gte-", "all-minilm", "minilm", "snowflake"]
        .iter()
        .any(|p| base.starts_with(p))
        || base == "bge"
        || base == "tei"
}

/// What a running `(backend, model)` on this node is for chat: the model to
/// list as the chat candidate, or `None` when the backend is serving a
/// non-chat model with no chat model placed beside it.
///
/// The candidate's model is the model PLACED for the chat role, not "whatever
/// the heartbeat says is loaded": on a shared ollama the loaded model flips
/// between the chat model and the embedder. Evidence the reported model is not
/// chat, in order: an embed/rerank placement row for it, the agent's own
/// `model_presence` role, then the name registry (works for an old agent that
/// sends no role at all, and for an embedder that has no placement row). A
/// model the operator placed as chat is always chat.
fn chat_model_for(n: &NodeFacts, placements: &[PlacementRow], backend: &str, reported: &str) -> Option<String> {
    let rows = || placements.iter().filter(|(node, b, _, _)| node == &n.node_id && b == backend);
    let placed_chat: Vec<&str> = rows().filter(|(_, _, _, r)| r == "chat").filter_map(|(_, _, m, _)| m.as_deref()).collect();
    if placed_chat.iter().any(|m| same_model(m, reported)) {
        return Some(reported.to_string());
    }
    let not_chat = rows().any(|(_, _, m, r)| r != "chat" && m.as_deref().is_some_and(|m| same_model(m, reported)))
        || n.reported_non_chat_models.iter().any(|(b, m)| b == backend && same_model(m, reported))
        || is_embedding_model_name(reported);
    if !not_chat {
        return Some(reported.to_string());
    }
    placed_chat.first().map(|m| m.to_string())
}

/// Lower sorts first: vLLM, then a GPU-backed runtime, then CPU.
fn engine_rank(backend: &str, gpu: bool) -> u8 {
    if backend.starts_with("vllm") {
        0
    } else if gpu {
        1
    } else {
        2
    }
}

fn derive_key(c: &Candidate) -> (u8, i64, i64) {
    (engine_rank(&c.backend, c.gpu), c.tier.unwrap_or(i64::MAX), (c.load * 100.0) as i64)
}

/// The routing order within a class, lowest first: non-degraded, healthy,
/// declared position, load. A function so the ORDER is what gets tested.
pub fn order_key(c: &Candidate) -> (u8, u8, usize, i64) {
    (
        if c.degraded { 1 } else { 0 },
        if c.healthy { 0 } else { 1 },
        c.position,
        (c.load * 100.0) as i64,
    )
}

/// The dynamic default's routing order, lowest first: non-degraded,
/// healthy, not stalled in the last [`STALL_DEMOTION`], not thermally
/// `serious`/`critical`, GPU not shared with a foreign workload
/// (`gpu_contention.state: shared`), engine (vLLM < GPU runtime < CPU), the larger
/// model (`-params`, tenths of a billion), fewest requests in flight from
/// this gateway, heartbeat load, position. A function so the ORDER is what
/// gets tested.
pub fn rank_key(c: &Candidate, in_flight: usize, stalled: bool) -> (u8, u8, u8, u8, u8, u8, i64, usize, i64, usize) {
    (
        if c.degraded { 1 } else { 0 },
        if c.healthy { 0 } else { 1 },
        if stalled { 1 } else { 0 },
        thermal_rank(c.thermal.as_deref()),
        if c.gpu_shared { 1 } else { 0 },
        engine_rank(&c.backend, c.gpu),
        -((c.params_b.unwrap_or(0.0) * 10.0) as i64),
        in_flight,
        (c.load * 100.0) as i64,
        c.position,
    )
}

/// `serious` and `critical` sort after every cooler candidate.
fn thermal_rank(t: Option<&str>) -> u8 {
    match t {
        Some("serious") | Some("critical") => 1,
        _ => 0,
    }
}

/// A candidate's model size in billions of parameters — the quality key of
/// the dynamic default. From the name first (`gemma4:12b`, `gemma4:e2b-it-qat`,
/// `google/gemma-4-12B-it-qat-w4a16-ct`: [`crate::placement_fit::params_b`];
/// a vLLM lane reports no sizes, so its HF name is the only source), then
/// the node's measured `model_stats[].size_bytes`, then the known-weights
/// table, both converted at [`crate::placement_fit::GB_PER_BILLION_PARAMS`].
pub fn quality_of(n: &NodeFacts, model: &str) -> Option<f64> {
    if let Some(p) = crate::placement_fit::params_b(model) {
        return Some(p);
    }
    let gb_to_b = |gb: f64| gb / crate::placement_fit::GB_PER_BILLION_PARAMS;
    if let Some((_, b)) = n.model_sizes.iter().find(|(m, b)| *b > 0 && same_model(m, model)) {
        return Some(gb_to_b(*b as f64 / 1e9));
    }
    crate::placement_fit::KNOWN_WEIGHTS_GB.iter().find(|(m, _)| same_model(m, model)).map(|(_, g)| gb_to_b(*g))
}

/// `rank=gpu,params=12,load=0.20` — why a candidate sits where it does.
pub fn rank_reason(c: &Candidate, in_flight: usize, stalled: bool) -> String {
    let engine = match engine_rank(&c.backend, c.gpu) {
        0 => "vllm",
        1 => "gpu",
        _ => "cpu",
    };
    let mut out = format!("rank={engine}");
    match c.params_b {
        Some(p) => out.push_str(&format!(",params={}", (p * 10.0).round() / 10.0)),
        None => out.push_str(",params=?"),
    }
    out.push_str(&format!(",load={:.2}", c.load));
    if in_flight > 0 {
        out.push_str(&format!(",in_flight={in_flight}"));
    }
    if stalled {
        out.push_str(",stalled");
    }
    if let Some(t) = c.thermal.as_deref().filter(|t| thermal_rank(Some(t)) > 0) {
        out.push_str(&format!(",thermal={t}"));
    }
    if c.gpu_shared {
        out.push_str(",gpu_shared");
    }
    if !c.healthy {
        out.push_str(&format!(",unhealthy={}", c.health));
    }
    if c.degraded {
        out.push_str(",degraded");
    }
    out
}

fn health_of(n: &NodeFacts) -> (bool, String) {
    if n.quarantined {
        return (false, "quarantined".into());
    }
    if n.offline {
        return (false, "status offline".into());
    }
    match n.heartbeat_age_secs {
        None => return (false, "no heartbeat timestamp".into()),
        Some(age) if age > 2.0 * HEARTBEAT_INTERVAL_SECS => {
            return (false, format!("heartbeat {}s old", age as i64));
        }
        _ => {}
    }
    if !n.inbound_ok {
        return (false, "agent not reachable from the controller".into());
    }
    (true, String::new())
}

fn url_for(n: &NodeFacts, backend: &str) -> String {
    if !n.ip.is_empty() {
        crate::node_link::NodeLink::for_ip(&n.ip).base().to_string()
    } else {
        let port = crate::config::backend_port(backend).unwrap_or(0);
        super::backend::local_backend_url(backend, port)
    }
}

fn candidate(n: &NodeFacts, backend: &str, model: &str, position: usize, degraded: bool, status: CandidateStatus) -> Candidate {
    let (healthy, health) = health_of(n);
    Candidate {
        node_id: n.node_id.clone(),
        backend: backend.to_string(),
        model: model.to_string(),
        declared_model: None,
        position,
        degraded,
        status,
        healthy,
        health,
        load: n.load,
        url: url_for(n, backend),
        tier: n.tier,
        gpu: n.gpu,
        params_b: quality_of(n, model),
        thermal: n.thermal.clone(),
        quarantined: n.quarantined,
        gpu_shared: n.gpu_shared,
        class_label: String::new(),
        rank: String::new(),
    }
}

/// Build the class table from facts.
///
/// No configured default model takes part: an undeclared `chat-default` is
/// the dynamic pool of every served chat candidate (see the module doc).
pub fn build_table(nodes: &[NodeFacts], placements: &[PlacementRow], decl: &Declarations) -> ClassTable {
    // Every served chat model, as the heartbeats report it.
    let mut served: Vec<Candidate> = Vec::new();
    for n in nodes {
        for (bt, m) in &n.running {
            if !INFERENCE_TYPES.contains(&bt.as_str()) || m.is_empty() {
                continue;
            }
            if n.non_chat.iter().any(|b| b == bt) || n.model_missing.iter().any(|b| b == bt) || n.paused_backends.iter().any(|b| b == bt) {
                continue;
            }
            let Some(chat_model) = chat_model_for(n, placements, bt, m) else { continue };
            served.push(candidate(n, bt, &chat_model, 0, false, CandidateStatus::Placed));
        }
    }

    // The dynamic default: every served chat candidate, whatever its model,
    // positions in static rank order (in-flight and stalls are live and
    // applied per request by `rank`).
    let all_chat: Option<Class> = if served.is_empty() {
        None
    } else {
        let mut cands = served.clone();
        cands.sort_by_key(|c| rank_key(c, 0, false));
        for (i, c) in cands.iter_mut().enumerate() {
            c.position = i;
        }
        Some(Class { name: CHAT_DEFAULT.into(), declared: false, candidates: cands, pool: false, dynamic: true })
    };

    // Derived: one class per distinct model, candidates in derive order.
    let mut groups: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    let mut spelling: HashMap<String, String> = HashMap::new();
    for c in served {
        let key = norm_model(&c.model);
        spelling.entry(key.clone()).or_insert_with(|| c.model.clone());
        groups.entry(key).or_default().push(c);
    }
    let mut classes: Vec<Class> = Vec::new();
    for (key, mut cands) in groups {
        cands.sort_by_key(derive_key);
        for (i, c) in cands.iter_mut().enumerate() {
            c.position = i;
        }
        classes.push(Class { name: spelling[&key].clone(), declared: false, candidates: cands, pool: false, dynamic: false });
    }

    // Declared classes override a derived class of the same name.
    for d in &decl.classes {
        let mut cands = Vec::with_capacity(d.candidates.len());
        for (i, dc) in d.candidates.iter().enumerate() {
            let placed_model = placements
                .iter()
                .filter(|(n, b, _, _)| n == &dc.node_id && b == &dc.backend)
                // Several roles may share the backend: a chat class names
                // the CHAT row's model, else the first row.
                .min_by_key(|(_, _, _, role)| if role == "chat" { 0 } else { 1 })
                .and_then(|(_, _, m, _)| m.clone());
            let node = nodes.iter().find(|n| n.node_id == dc.node_id);
            // What the backend runs, as a CHAT model: an embedder it reports
            // is never the declared candidate's model (see `chat_model_for`).
            let running_model = node.and_then(|n| {
                n.running.iter().find(|(b, _)| b == &dc.backend).and_then(|(_, m)| chat_model_for(n, placements, &dc.backend, m))
            });
            let model = dc.model.clone().or(placed_model).or_else(|| running_model.clone()).unwrap_or_default();
            let (status, facts) = match node {
                Some(n) => {
                    let placed = running_model.as_deref().is_some_and(|m| same_model(m, &model))
                        && !n.model_missing.iter().any(|b| b == &dc.backend);
                    let available = n.available_models.iter().any(|a| same_model(a, &model));
                    let status = if model.is_empty() {
                        CandidateStatus::Unplaced
                    } else if placed {
                        CandidateStatus::Placed
                    } else if available {
                        CandidateStatus::Available
                    } else {
                        CandidateStatus::Unplaced
                    };
                    (status, n.clone())
                }
                None => (
                    CandidateStatus::Unplaced,
                    NodeFacts { node_id: dc.node_id.clone(), inbound_ok: true, ..Default::default() },
                ),
            };
            let mut c = candidate(&facts, &dc.backend, &model, i, dc.degraded, status);
            c.declared_model = dc.model.clone();
            if node.is_none() {
                c.health = "no heartbeat record".into();
            }
            cands.push(c);
        }
        let class = Class { name: d.name.clone(), declared: true, candidates: cands, pool: d.pool, dynamic: false };
        // Declared names are stored lowercase; a derived class keeps the
        // heartbeat's spelling (`google/gemma-4-12B-…`). Same model, one
        // class — the declaration replaces the derived one.
        if let Some(existing) = classes.iter_mut().find(|c| same_model(&c.name, &d.name)) {
            *existing = class;
        } else {
            classes.push(class);
        }
    }
    if !classes.iter().any(|c| c.name == CHAT_DEFAULT) {
        if let Some(d) = all_chat.clone() {
            classes.insert(0, d);
        }
    } else {
        // Declared chat-default goes first for the catalogue.
        if let Some(i) = classes.iter().position(|c| c.name == CHAT_DEFAULT) {
            let d = classes.remove(i);
            classes.insert(0, d);
        }
    }

    let mut aliases: Vec<(String, String)> = BUILTIN_ALIASES.iter().map(|a| (a.to_string(), CHAT_DEFAULT.to_string())).collect();
    for (a, c) in &decl.aliases {
        if !aliases.iter().any(|(x, _)| x == a) {
            aliases.push((a.clone(), c.clone()));
        }
    }
    let mut node_ids: Vec<String> = nodes.iter().map(|n| n.node_id.clone()).collect();
    node_ids.sort();
    node_ids.dedup();
    ClassTable { classes, aliases, all_chat, nodes: node_ids }
}

/// The class a `model` hint names, if any. `hint` has been through
/// `model_hint` (placeholders and blank are already `None`).
pub fn resolve_hint<'a>(table: &'a ClassTable, hint: Option<&str>) -> Option<&'a Class> {
    let name = match hint {
        None => CHAT_DEFAULT,
        Some(h) => h,
    };
    // A class or a served model by that name wins over an alias: an alias
    // may not shadow a concrete model (PUT refuses one that would), and if
    // a model of that name starts being served after the alias was
    // declared, the exact pin still means the model.
    if let Some(c) = table.class(name) {
        return Some(c);
    }
    let (_, class) = table.aliases.iter().find(|(a, _)| a.eq_ignore_ascii_case(name))?;
    table.class(class)
}

/// What a declared `model` may look like: the charset of an HF id or an
/// Ollama tag (`org/name:tag`, dots, dashes, underscores), 1..=256 chars.
pub fn valid_model(model: &str) -> Result<(), String> {
    let m = model.trim();
    if m.is_empty() || m.len() > 256 {
        return Err("a model name is 1-256 characters".into());
    }
    if !m.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '@' | '+')) {
        return Err(format!("model '{m}' has characters outside [A-Za-z0-9._-:/@+]"));
    }
    Ok(())
}

/// The candidates to try, in order, minus unplaced ones and any that
/// already failed this request. `exclude` holds `(url, backend)` pairs:
/// every backend on a node is dialled at the same node-agent address
/// (`https://<ip>:8081`), so a URL alone would take a node's ollama out
/// with its vLLM. A dynamic default or a pool leaves out quarantined and
/// thermal-`critical` candidates unless nothing else is left ([`rank`]).
pub fn ordered<'a>(class: &'a Class, exclude: &[(String, String)]) -> Vec<&'a Candidate> {
    let ex = |c: &Candidate| exclude.iter().any(|(u, b)| u == &c.url && b == &c.backend);
    rank(class, &ex, &|c| in_flight(&c.url, &c.backend), &|c| recently_stalled(&c.url, &c.backend)).order
}

/// [`ordered`] with the in-flight count supplied and no stall memory, so a
/// pool's order is tested without the process-wide registries.
pub fn ordered_by<'a>(class: &'a Class, exclude: &[(String, String)], busy: &dyn Fn(&Candidate) -> usize) -> Vec<&'a Candidate> {
    let ex = |c: &Candidate| exclude.iter().any(|(u, b)| u == &c.url && b == &c.backend);
    rank(class, &ex, busy, &|_| false).order
}

/// A class's routable candidates, ranked.
#[derive(Debug, Default)]
pub struct Ranked<'a> {
    /// The routing order.
    pub order: Vec<&'a Candidate>,
    /// Left out of a dynamic default or a pool (quarantined, thermal
    /// critical) with the reason. When nothing else was left they are in
    /// `order` instead and `last_resort` is true.
    pub skipped: Vec<(&'a Candidate, String)>,
    pub last_resort: bool,
}

/// Rank a class: drop unplaced and `exclude`d candidates; a dynamic default
/// or a pool sets quarantined / thermal-critical ones aside unless nothing
/// else is left; then sort — the dynamic default by [`rank_key`], a pool by
/// [`pool_key`], any other class by [`order_key`] (declared position).
pub fn rank<'a>(
    class: &'a Class,
    exclude: &dyn Fn(&Candidate) -> bool,
    busy: &dyn Fn(&Candidate) -> usize,
    stalled: &dyn Fn(&Candidate) -> bool,
) -> Ranked<'a> {
    let routable: Vec<&Candidate> = class
        .candidates
        .iter()
        .filter(|c| c.status != CandidateStatus::Unplaced)
        .filter(|c| !exclude(c))
        .collect();
    let mut out = Ranked::default();
    if class.dynamic || class.pool {
        let (mut eligible, set_aside): (Vec<&Candidate>, Vec<&Candidate>) =
            routable.into_iter().partition(|c| c.exclusion().is_none());
        if eligible.is_empty() && !set_aside.is_empty() {
            out.last_resort = true;
            eligible = set_aside;
        } else {
            out.skipped = set_aside.into_iter().map(|c| (c, c.exclusion().unwrap_or_default())).collect();
        }
        if class.dynamic {
            eligible.sort_by_key(|c| rank_key(c, busy(c), stalled(c)));
        } else {
            eligible.sort_by_key(|c| pool_key(c, busy(c), stalled(c)));
        }
        out.order = eligible;
    } else {
        let mut v = routable;
        v.sort_by_key(|c| order_key(c));
        out.order = v;
    }
    out
}

/// A pool's routing order, lowest first: non-degraded, healthy, not
/// recently stalled, not thermally hot, GPU not shared, fewest requests in flight from this
/// gateway, heartbeat load, declared position. No engine or model-size key:
/// declaring a pool says its peers are interchangeable, and a size key
/// would send every request to the biggest peer and never spread.
pub fn pool_key(c: &Candidate, in_flight: usize, stalled: bool) -> (u8, u8, u8, u8, u8, usize, i64, usize) {
    (
        if c.degraded { 1 } else { 0 },
        if c.healthy { 0 } else { 1 },
        if stalled { 1 } else { 0 },
        thermal_rank(c.thermal.as_deref()),
        if c.gpu_shared { 1 } else { 0 },
        in_flight,
        (c.load * 100.0) as i64,
        c.position,
    )
}

// ── selection (one function for raw chat and the agent loop) ────────────

/// The candidates a request goes to, in order, with what the logs need.
#[derive(Clone, Debug)]
pub struct Selection {
    /// The class name a consumer sees (`chat-default`, a model, a class).
    pub class: String,
    /// The same for the logs: `chat-default(dynamic)` / `chat-default(declared)`.
    pub label: String,
    /// In routing order; each carries `class_label` and `rank`.
    pub candidates: Vec<Candidate>,
    /// `node/backend: reason` for every candidate left out or demoted.
    pub skipped: Vec<String>,
    pub last_resort: bool,
}

/// Why a request has no candidate.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// The hint names no class, alias or served model (404).
    UnknownModel(String),
    /// The pinned node has no heartbeat record (422).
    UnknownNode(String),
    /// The pinned node is there and serves no chat model (422, the same
    /// status `/api/inference` gives a node pin with no chat backend).
    NodeServesNoChat(String),
    /// The pinned node serves chat, but not the named model (409).
    NodeCannotServe(String),
    /// The class exists and nothing in it is routable (503).
    NoCandidates(String),
}

impl Refusal {
    pub fn message(&self) -> &str {
        match self {
            Refusal::UnknownModel(m)
            | Refusal::UnknownNode(m)
            | Refusal::NodeServesNoChat(m)
            | Refusal::NodeCannotServe(m)
            | Refusal::NoCandidates(m) => m,
        }
    }
}

/// How the logs name a class.
pub fn class_label(class: &Class) -> String {
    if class.name == CHAT_DEFAULT {
        if class.dynamic {
            format!("{CHAT_DEFAULT}(dynamic)")
        } else {
            format!("{CHAT_DEFAULT}(declared)")
        }
    } else {
        class.name.clone()
    }
}

/// [`select_with`] on the live in-flight and stall registries.
pub fn select(table: &ClassTable, hint: Option<&str>, node: Option<&str>, strict: bool, exclude: &dyn Fn(&Candidate) -> bool) -> Result<Selection, Refusal> {
    select_with(table, hint, node, strict, exclude, &|c| in_flight(&c.url, &c.backend), &|c| recently_stalled(&c.url, &c.backend))
}

/// Resolve a request to its ordered candidates: the class the hint names
/// (absent → `chat-default`), the pinned `node`'s share of it first when
/// one is named. A node pin with no model selects from every live chat
/// candidate on that node (the dynamic pool), even when `chat-default` is
/// declared — the caller named where, and the declaration is about where
/// NOT named.
///
/// Everything named is a preference (operator, 2026-10-19): behind the
/// preferred candidates come the class's other nodes (when a node was
/// pinned), then every other live chat candidate in the dynamic ranking,
/// all with a `fallback,` rank so the answer says it is a fallback. A
/// model nothing serves is answered the same way. `strict` (the caller's
/// `X-Noo-Node-Strict` / `node_strict`) keeps a node pin to that node
/// alone, for locality or privacy: no fallback, and the refusals below. A
/// name that is no node of this mesh is refused either way — a typo must
/// not silently become "any node". Pure but for the two live callbacks, so
/// raw chat and the agent loop share it and a test drives it with facts.
pub fn select_with(
    table: &ClassTable,
    hint: Option<&str>,
    node: Option<&str>,
    strict: bool,
    exclude: &dyn Fn(&Candidate) -> bool,
    busy: &dyn Fn(&Candidate) -> usize,
    stalled: &dyn Fn(&Candidate) -> bool,
) -> Result<Selection, Refusal> {
    let node = node.map(str::trim).filter(|n| !n.is_empty());
    if let Some(n) = node {
        if !table.nodes.iter().any(|x| x.eq_ignore_ascii_case(n)) {
            return Err(node_refusal(table, n, hint));
        }
    }
    let strict_pin = strict && node.is_some();
    let named = resolve_hint(table, hint);
    // Said once, logged with the selection: where the request could not go
    // where it asked and the mesh answered instead.
    let mut notes: Vec<String> = Vec::new();
    // Every candidate stands in for a model the caller named.
    let mut substituted = false;
    let base: &Class = if let (Some(n), None) = (node, hint) {
        match table.all_chat.as_ref() {
            Some(c) => c,
            None => return Err(node_refusal(table, n, None)),
        }
    } else if let Some(c) = named {
        c
    } else if let (Some(h), false, Some(all)) = (hint, strict_pin, table.all_chat.as_ref()) {
        // A model nothing serves is a preference the mesh cannot meet right
        // now (its node is off doing something else): any live chat node
        // answers, and the served-model header says which.
        substituted = true;
        notes.push(format!("model '{h}' is not served by any live node; any live chat node answers"));
        all
    } else {
        return Err(Refusal::UnknownModel(format!(
            "model '{}' is not a class, alias or served model; ids: {}",
            hint.unwrap_or(CHAT_DEFAULT),
            table.ids().join(", ")
        )));
    };
    let filtered: Class;
    let class: &Class = match node {
        Some(n) => {
            let cands: Vec<Candidate> = base.candidates.iter().filter(|c| c.node_id.eq_ignore_ascii_case(n)).cloned().collect();
            if cands.iter().all(|c| c.status == CandidateStatus::Unplaced) {
                let why = node_refusal(table, n, hint);
                if strict {
                    return Err(why);
                }
                notes.push(format!("{}; the mesh answers instead", why.message()));
            }
            filtered = Class { candidates: cands, ..base.clone() };
            &filtered
        }
        None => base,
    };
    let label = class_label(class);
    let ranked = rank(class, exclude, busy, stalled);
    // Behind the preferred candidates: the class's other nodes when a node
    // was pinned, then every other live chat candidate in the dynamic
    // ranking. A strict node pin goes without them — the caller said where
    // and nowhere else.
    let mut fallback: Vec<&Candidate> = Vec::new();
    if !strict_pin {
        let mut tiers: Vec<Vec<&Candidate>> = Vec::new();
        if node.is_some() {
            tiers.push(rank(base, exclude, busy, stalled).order);
        }
        if let Some(all) = table.all_chat.as_ref() {
            if node.is_some() || !class.dynamic {
                tiers.push(rank(all, exclude, busy, stalled).order);
            }
        }
        for f in tiers.into_iter().flatten() {
            let listed = |c: &&Candidate| c.url == f.url && c.backend == f.backend;
            if !ranked.order.iter().any(listed) && !fallback.iter().any(listed) {
                fallback.push(f);
            }
        }
    }
    if ranked.order.is_empty() && !fallback.is_empty() && node.is_none() {
        notes.push(format!("class '{}' has nothing routable right now; any live chat node answers", class.name));
    }
    if ranked.order.is_empty() && fallback.is_empty() {
        let declared = class.candidates.len();
        return Err(Refusal::NoCandidates(if class.declared && declared > 0 {
            format!(
                "class '{}' has {declared} declared candidate(s) and none is placed or available: {}",
                class.name,
                class.candidates.iter().map(|c| format!("{}/{}={} ({})", c.node_id, c.backend, c.model, c.health)).collect::<Vec<_>>().join("; ")
            )
        } else {
            format!("class '{}' has no candidates", class.name)
        }));
    }
    let mut skipped: Vec<String> = notes;
    skipped.extend(ranked.skipped.iter().map(|(c, why)| format!("{}/{}: {why}", c.node_id, c.backend)));
    let mut candidates = Vec::with_capacity(ranked.order.len() + fallback.len());
    for c in &ranked.order {
        let (b, st) = (busy(c), stalled(c));
        let mut c = (*c).clone();
        c.class_label = label.clone();
        c.rank = if substituted { format!("fallback,{}", rank_reason(&c, b, st)) } else { rank_reason(&c, b, st) };
        if st {
            skipped.push(format!("{}/{}: stalled in the last {}s (demoted)", c.node_id, c.backend, STALL_DEMOTION.as_secs()));
        } else if !c.healthy {
            skipped.push(format!("{}/{}: {} (demoted)", c.node_id, c.backend, c.health));
        } else if thermal_rank(c.thermal.as_deref()) > 0 {
            skipped.push(format!("{}/{}: thermal {} (demoted)", c.node_id, c.backend, c.thermal.as_deref().unwrap_or("?")));
        } else if c.gpu_shared {
            skipped.push(format!("{}/{}: GPU shared with another workload (demoted)", c.node_id, c.backend));
        }
        candidates.push(c);
    }
    for f in fallback {
        let mut c = f.clone();
        c.class_label = format!("{label}+mesh");
        c.rank = format!("fallback,{}", rank_reason(&c, busy(f), stalled(f)));
        candidates.push(c);
    }
    Ok(Selection { class: class.name.clone(), label, candidates, skipped, last_resort: ranked.last_resort })
}

/// Why a pinned node cannot take this request: unknown (422), present
/// without a chat backend (422), or without the named model (409).
fn node_refusal(table: &ClassTable, node: &str, hint: Option<&str>) -> Refusal {
    if !table.nodes.iter().any(|x| x.eq_ignore_ascii_case(node)) {
        return Refusal::UnknownNode(format!("node '{node}' is not a node of this mesh (no heartbeat record)"));
    }
    let serves: Vec<String> = table
        .all_chat
        .iter()
        .flat_map(|c| c.candidates.iter())
        .filter(|c| c.node_id.eq_ignore_ascii_case(node))
        .map(|c| format!("{}={}", c.backend, c.model))
        .collect();
    if serves.is_empty() {
        return Refusal::NodeServesNoChat(format!("node '{node}' serves no chat model right now"));
    }
    Refusal::NodeCannotServe(format!(
        "node '{node}' does not serve '{}'; it serves {}",
        hint.unwrap_or(CHAT_DEFAULT),
        serves.join(", ")
    ))
}

// ── stall memory ─────────────────────────────────────────────────────────

/// When each `(node-agent address, backend)` last stalled or timed out. The
/// address is one per node (`https://<ip>:8081`), so this is per node and
/// backend; both callers hold the address, not always the node id.
static STALLS: OnceLock<Mutex<HashMap<(String, String), Instant>>> = OnceLock::new();

fn stalls() -> &'static Mutex<HashMap<(String, String), Instant>> {
    STALLS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a stall/timeout failover of `(url, backend)`: the candidate sorts
/// after every non-stalled one for [`STALL_DEMOTION`].
pub fn note_stall(url: &str, backend: &str) {
    if let Ok(mut m) = stalls().lock() {
        let now = Instant::now();
        m.retain(|_, at| !stall_expired(*at, now));
        m.insert((url.to_string(), backend.to_string()), now);
    }
    tracing::warn!(url, backend, demotion_secs = STALL_DEMOTION.as_secs(), "backend_stall_noted");
}

/// Did `(url, backend)` stall within [`STALL_DEMOTION`]?
pub fn recently_stalled(url: &str, backend: &str) -> bool {
    let now = Instant::now();
    stalls()
        .lock()
        .ok()
        .and_then(|m| m.get(&(url.to_string(), backend.to_string())).copied())
        .is_some_and(|at| !stall_expired(at, now))
}

/// A stall noted at `at` no longer demotes at `now`.
pub fn stall_expired(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) >= STALL_DEMOTION
}

// ── requests in flight ───────────────────────────────────────────────────

/// Requests this gateway has open to each `(url, backend)`. A pool reads it
/// to pick the least busy peer; the heartbeat load alone is up to 30 s old
/// and does not see a burst.
static IN_FLIGHT: OnceLock<Mutex<HashMap<(String, String), usize>>> = OnceLock::new();

fn in_flight_map() -> &'static Mutex<HashMap<(String, String), usize>> {
    IN_FLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Open requests to `(url, backend)` right now.
pub fn in_flight(url: &str, backend: &str) -> usize {
    in_flight_map().lock().map(|m| m.get(&(url.to_string(), backend.to_string())).copied().unwrap_or(0)).unwrap_or(0)
}

/// One open request; dropping it closes it. Held for the whole answer,
/// including a stream the client is still reading.
#[derive(Debug)]
pub struct InFlight((String, String));

impl InFlight {
    pub fn open(url: &str, backend: &str) -> InFlight {
        let key = (url.to_string(), backend.to_string());
        if let Ok(mut m) = in_flight_map().lock() {
            *m.entry(key.clone()).or_insert(0) += 1;
        }
        InFlight(key)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut m) = in_flight_map().lock() {
            if let Some(n) = m.get_mut(&self.0) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.0);
                }
            }
        }
    }
}

// ── loaders ──────────────────────────────────────────────────────────────

/// One node's facts from its `mesh_nodes` record.
pub fn node_facts_from_kv(key: &str, data: &Value, non_chat: &[(String, String)], now_unix: f64) -> NodeFacts {
    let node_id = data.get("id").and_then(Value::as_str).unwrap_or(key).to_string();
    let running = data
        .get("running_backends")
        .or_else(|| data.get("backends"))
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(bt, m)| m.as_str().filter(|s| !s.is_empty()).map(|s| (bt.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let available_models = data
        .get("available_models")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string).or_else(|| v.get("name").and_then(Value::as_str).map(str::to_string)))
                .collect()
        })
        .unwrap_or_default();
    let model_missing = data
        .get("model_presence")
        .and_then(Value::as_object)
        .map(|o| o.keys().filter(|b| crate::model_presence::backend_model_missing(data, b)).cloned().collect())
        .unwrap_or_default();
    let reported_non_chat_models: Vec<(String, String)> = data
        .get("model_presence")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter(|(_, e)| !matches!(e["role"].as_str(), None | Some("") | Some("chat")))
                .filter_map(|(k, e)| Some((k.split('#').next()?.to_string(), e["model"].as_str().filter(|m| !m.is_empty())?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let vram = data.get("vram_gb").and_then(Value::as_f64).unwrap_or(0.0);
    let unified = data
        .pointer("/capabilities/unified_memory")
        .or_else(|| data.pointer("/capabilities/facts/unified_memory"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let last = data.get("last_heartbeat").or_else(|| data.get("ts")).and_then(Value::as_f64);
    NodeFacts {
        ip: data.get("ip_address").and_then(Value::as_str).unwrap_or("").to_string(),
        running,
        available_models,
        model_missing,
        reported_non_chat_models,
        non_chat: non_chat.iter().filter(|(n, _)| n == &node_id).map(|(_, b)| b.clone()).collect(),
        load: data.get("load").and_then(Value::as_f64).map(|l| l.clamp(0.0, 1.0)).unwrap_or(0.0),
        tier: data.get("tier").and_then(Value::as_i64),
        gpu: vram > 0.0 || unified,
        heartbeat_age_secs: last.map(|t| (now_unix - t).max(0.0)),
        inbound_ok: data.get("inbound").and_then(Value::as_str) != Some("failed"),
        thermal: data.get("thermal_state").and_then(Value::as_str).map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()),
        quarantined: data.get("status").and_then(Value::as_str) == Some("quarantined"),
        offline: data.get("status").and_then(Value::as_str) == Some("offline"),
        model_sizes: data
            .get("model_stats")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| Some((s.get("name")?.as_str()?.to_string(), s.get("size_bytes")?.as_u64()?)))
                    .collect()
            })
            .unwrap_or_default(),
        // Read defensively: an older agent sends no `gpu_contention` (= free).
        gpu_shared: data.pointer("/gpu_contention/state").and_then(Value::as_str) == Some("shared"),
        paused_backends: data
            .pointer("/gpu_contention/paused_backends")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        node_id,
    }
}

/// `(node, backend)` pairs that serve NO chat role. Placements are keyed
/// (node, backend, role): one ollama hosting a chat model and an embedder has
/// a chat row, so it stays a chat candidate; only a backend whose every row is
/// non-chat (a dedicated embedder) is excluded. `placements` are the RUNNING
/// rows ([`load_placements`]).
pub fn non_chat_pairs(placements: &[PlacementRow]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = placements
        .iter()
        .filter(|(n, b, _, role)| {
            role != "chat" && !placements.iter().any(|(n2, b2, _, r2)| n2 == n && b2 == b && r2 == "chat")
        })
        .map(|(n, b, _, _)| (n.clone(), b.clone()))
        .collect();
    out.sort();
    out.dedup();
    out
}

async fn kv_node_facts(state: &AppState, placements: &[PlacementRow]) -> Vec<NodeFacts> {
    let non_chat = non_chat_pairs(placements);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let mut out = Vec::new();
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return out };
    let Ok(keys) = kv.keys().await else { return out };
    use tokio_stream::StreamExt;
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect::<Vec<String>>().await;
    for key in keys {
        if key == "gateway" {
            continue;
        }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(mut data) = serde_json::from_slice::<Value>(&entry) else { continue };
        // The reachability probe's verdict lives in Redis, not the KV.
        let inbound = crate::node_reachability::read_inbound(state, &key).await;
        crate::node_reachability::apply_inbound(&mut data, inbound.as_deref());
        out.push(node_facts_from_kv(&key, &data, &non_chat, now));
    }
    out
}

/// Operator-speed cache: declarations and placements change by `noo cluster
/// class set` / `place`, not per request. Stale beats wrong-by-omission (a
/// DB blip must not turn a declared class into a derived one mid-request),
/// so an error serves the last copy and refuses only with none to serve.
struct Cached {
    at: Instant,
    decl: Declarations,
    placements: Vec<PlacementRow>,
}

const CACHE_TTL: Duration = Duration::from_secs(30);
static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();

fn cache() -> &'static Mutex<Option<Cached>> {
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Forget the cached declarations — called by the write handlers so a
/// `class set` is visible on the next request, not 30 s later.
pub fn invalidate_cache() {
    if let Ok(mut g) = cache().lock() {
        *g = None;
    }
}

async fn declared_and_placements(state: &AppState) -> Result<(Declarations, Vec<PlacementRow>)> {
    if let Ok(g) = cache().lock() {
        if let Some(c) = g.as_ref() {
            if c.at.elapsed() < CACHE_TTL {
                return Ok((c.decl.clone(), c.placements.clone()));
            }
        }
    }
    let fresh = async {
        let decl = load_declarations(&state.db).await?;
        let placements = load_placements(&state.db).await?;
        Ok::<_, sqlx::Error>((decl, placements))
    }
    .await;
    match fresh {
        Ok((decl, placements)) => {
            if let Ok(mut g) = cache().lock() {
                *g = Some(Cached { at: Instant::now(), decl: decl.clone(), placements: placements.clone() });
            }
            Ok((decl, placements))
        }
        Err(e) => {
            let stale = cache().lock().ok().and_then(|g| g.as_ref().map(|c| (c.decl.clone(), c.placements.clone())));
            match stale {
                Some(s) => {
                    tracing::warn!(error = %e, "model_classes_db_error_serving_stale");
                    Ok(s)
                }
                None => anyhow::bail!("model class declarations unavailable: {e}"),
            }
        }
    }
}

/// The live table: KV facts + placements + declarations.
pub async fn load_table(state: &AppState) -> Result<ClassTable> {
    let (decl, placements) = declared_and_placements(state).await?;
    let nodes = kv_node_facts(state, &placements).await;
    note_yaml_model_is_a_hint(state);
    Ok(build_table(&nodes, &placements, &decl))
}

/// Existing installs carry `cluster.default_backend: ollama` and
/// `cluster.backends.ollama.model: <tag>` from onboarding. That used to be
/// the undeclared `chat-default`; it no longer narrows unpinned routing.
/// Said once per process so an operator who reads the yaml knows.
fn note_yaml_model_is_a_hint(state: &AppState) {
    static ONCE: OnceLock<()> = OnceLock::new();
    let cfg = &state.config.cluster;
    let Some(model) = cfg.backends.get(cfg.default_backend.as_str()).map(|b| b.model.clone()).filter(|m| !m.is_empty()) else { return };
    ONCE.get_or_init(|| {
        tracing::info!(
            backend = %cfg.default_backend,
            model = %model,
            "cluster.backends.{}.model is a placement hint, not a routing pin: unpinned chat goes to every live chat node (chat-default dynamic); declare chat-default to narrow it",
            cfg.default_backend
        );
    });
}

// ── storage ──────────────────────────────────────────────────────────────

pub async fn load_placements(db: &sqlx::PgPool) -> Result<Vec<PlacementRow>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT node_id, backend, model, COALESCE(role, 'chat') FROM noo_backend_placements WHERE desired_state = 'running'",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn load_declarations(db: &sqlx::PgPool) -> Result<Declarations, sqlx::Error> {
    let rows: Vec<(String, i32, String, String, Option<String>, bool, bool)> = sqlx::query_as(
        "SELECT class, position, node_id, backend, model, degraded, pool FROM noo_model_classes ORDER BY class, position",
    )
    .fetch_all(db)
    .await?;
    let mut classes: Vec<DeclaredClass> = Vec::new();
    for (class, _pos, node_id, backend, model, degraded, pool) in rows {
        let c = match classes.iter_mut().find(|c| c.name == class) {
            Some(c) => c,
            None => {
                classes.push(DeclaredClass { name: class.clone(), candidates: Vec::new(), pool: false });
                classes.last_mut().expect("just pushed")
            }
        };
        // Written on every row of the class; any row saying pool means pool.
        c.pool |= pool;
        c.candidates.push(DeclaredCandidate { node_id, backend, model, degraded });
    }
    let aliases: Vec<(String, String)> = sqlx::query_as("SELECT alias, class FROM noo_model_aliases ORDER BY alias")
        .fetch_all(db)
        .await?;
    Ok(Declarations { classes, aliases })
}

/// Replace one class's declaration (candidates in order) and the aliases
/// that point at it. One transaction: a half-written class is never read.
pub async fn save_class(db: &sqlx::PgPool, class: &DeclaredClass, aliases: &[String]) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM noo_model_classes WHERE class = $1").bind(&class.name).execute(&mut *tx).await?;
    for (i, c) in class.candidates.iter().enumerate() {
        sqlx::query(
            "INSERT INTO noo_model_classes (class, position, node_id, backend, model, degraded, pool, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) \
             ON CONFLICT (class, node_id, backend) DO UPDATE SET position = EXCLUDED.position, \
               model = EXCLUDED.model, degraded = EXCLUDED.degraded, pool = EXCLUDED.pool, updated_at = NOW()",
        )
        .bind(&class.name)
        .bind(i as i32)
        .bind(&c.node_id)
        .bind(&c.backend)
        .bind(&c.model)
        .bind(c.degraded)
        .bind(class.pool)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM noo_model_aliases WHERE class = $1").bind(&class.name).execute(&mut *tx).await?;
    for a in aliases {
        sqlx::query(
            "INSERT INTO noo_model_aliases (alias, class, updated_at) VALUES ($1, $2, NOW()) \
             ON CONFLICT (alias) DO UPDATE SET class = EXCLUDED.class, updated_at = NOW()",
        )
        .bind(a)
        .bind(&class.name)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    invalidate_cache();
    Ok(())
}

/// Remove a class and its aliases. Returns how many candidate rows went.
pub async fn delete_class(db: &sqlx::PgPool, name: &str) -> Result<u64, sqlx::Error> {
    let mut tx = db.begin().await?;
    let res = sqlx::query("DELETE FROM noo_model_classes WHERE class = $1").bind(name).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM noo_model_aliases WHERE class = $1").bind(name).execute(&mut *tx).await?;
    tx.commit().await?;
    invalidate_cache();
    Ok(res.rows_affected())
}

// ── the public catalogue shape ───────────────────────────────────────────

/// The OpenAI `/v1/models` list for a table: every class and alias as an id
/// a consumer may send, owned by `noomesh`, with the class's candidate and
/// healthy counts. Never a node id, address or URL.
pub fn catalogue(table: &ClassTable) -> Vec<Value> {
    let mut out = Vec::new();
    for c in &table.classes {
        out.push(serde_json::json!({
            "id": c.name,
            "object": "model",
            "owned_by": "noomesh",
            "noo": {"class": c.name, "candidates": c.routable_count(), "healthy": c.healthy_count(), "declared": c.declared},
        }));
    }
    for (alias, class) in &table.aliases {
        if out.iter().any(|v| v["id"] == *alias) {
            continue;
        }
        let (n, h) = table.class(class).map(|c| (c.routable_count(), c.healthy_count())).unwrap_or((0, 0));
        out.push(serde_json::json!({
            "id": alias,
            "object": "model",
            "owned_by": "noomesh",
            "noo": {"class": class, "alias": true, "candidates": n, "healthy": h},
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HF: &str = "google/gemma-4-12B-it-qat-w4a16-ct";

    fn node(id: &str, ip: &str, running: &[(&str, &str)], available: &[&str], gpu: bool, tier: i64, load: f64) -> NodeFacts {
        NodeFacts {
            node_id: id.into(),
            ip: ip.into(),
            running: running.iter().map(|(b, m)| (b.to_string(), m.to_string())).collect(),
            available_models: available.iter().map(|s| s.to_string()).collect(),
            model_missing: vec![],
            non_chat: vec![],
            load,
            tier: Some(tier),
            gpu,
            heartbeat_age_secs: Some(5.0),
            inbound_ok: true,
            ..Default::default()
        }
    }

    /// The live fleet on 2026-10-07: host3 vLLM 12B, host6 ollama 26B
    /// running with the 12B pulled, host8 ollama e2b.
    fn fleet() -> Vec<NodeFacts> {
        vec![
            node("host3", "100.64.0.10", &[("vllm", HF)], &[], true, 1, 0.3),
            node("host6", "100.64.0.11", &[("ollama", "gemma4:26b")], &["gemma4:26b", "gemma4:12b"], true, 2, 0.1),
            node("host8", "100.64.0.12", &[("ollama", "gemma4:e2b-it-qat")], &["gemma4:e2b-it-qat"], false, 2, 0.2),
        ]
    }

    fn placements() -> Vec<PlacementRow> {
        vec![
            ("host3".into(), "vllm".into(), Some(HF.into()), "chat".into()),
            ("host6".into(), "ollama".into(), Some("gemma4:26b".into()), "chat".into()),
            ("host8".into(), "ollama".into(), Some("gemma4:e2b-it-qat".into()), "chat".into()),
        ]
    }

    fn names(cands: &[&Candidate]) -> Vec<String> {
        cands.iter().map(|c| format!("{}/{}={}", c.node_id, c.backend, c.model)).collect()
    }

    // ── derived defaults ─────────────────────────────────────────────

    #[test]
    fn nothing_declared_derives_one_class_per_model_and_a_dynamic_default_over_all_of_them() {
        let t = build_table(&fleet(), &placements(), &Declarations::default());
        let ids = t.ids();
        assert!(ids.contains(&CHAT_DEFAULT.to_string()), "{ids:?}");
        assert!(ids.contains(&HF.to_string()) && ids.contains(&"gemma4:26b".to_string()) && ids.contains(&"gemma4:e2b-it-qat".to_string()), "{ids:?}");
        assert!(ids.contains(&"default".to_string()) && ids.contains(&"auto".to_string()));
        // chat-default = every live chat candidate on every node, ranked:
        // vLLM, then the GPU ollama (26B), then the CPU e2b.
        let d = t.class(CHAT_DEFAULT).expect("chat-default");
        assert!(d.dynamic && !d.declared && !d.pool);
        assert_eq!(names(&ordered(d, &[])), vec![
            format!("host3/vllm={HF}"),
            "host6/ollama=gemma4:26b".to_string(),
            "host8/ollama=gemma4:e2b-it-qat".to_string(),
        ]);
        // Every MODEL class holds exactly one model — a concrete name narrows.
        for c in t.classes.iter().filter(|c| c.name != CHAT_DEFAULT) {
            let models: std::collections::HashSet<String> = c.candidates.iter().map(|c| norm_model(&c.model)).collect();
            assert_eq!(models.len(), 1, "class {} mixes models: {models:?}", c.name);
            assert!(!c.dynamic);
        }
        assert_eq!(t.classes.len(), 4, "{:?}", t.classes.iter().map(|c| &c.name).collect::<Vec<_>>());
    }

    #[test]
    fn derived_order_is_vllm_then_gpu_runtime_then_cpu_then_tier_then_load() {
        let nodes = vec![
            node("cpu", "10.0.0.1", &[("ollama", "m")], &[], false, 2, 0.0),
            node("gpu-busy", "10.0.0.2", &[("ollama", "m")], &[], true, 2, 0.9),
            node("gpu-idle-t3", "10.0.0.3", &[("ollama", "m")], &[], true, 3, 0.0),
            node("gpu-idle", "10.0.0.4", &[("ollama", "m")], &[], true, 2, 0.1),
            node("v", "10.0.0.5", &[("vllm", "m")], &[], true, 2, 0.99),
        ];
        let t = build_table(&nodes, &[], &Declarations::default());
        let c = t.class("m").unwrap();
        let order: Vec<&str> = ordered(c, &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["v", "gpu-idle", "gpu-busy", "gpu-idle-t3", "cpu"]);
    }


    #[test]
    fn an_ollama_with_a_chat_row_and_an_embed_row_stays_a_chat_target() {
        let rows: Vec<PlacementRow> = vec![
            ("host6".into(), "ollama".into(), Some("gemma4:26b-a4b-it-qat".into()), "chat".into()),
            ("host6".into(), "ollama".into(), Some("harrier".into()), "embed".into()),
            ("host2".into(), "ollama".into(), Some("harrier".into()), "embed".into()),
        ];
        assert_eq!(non_chat_pairs(&rows), vec![("host2".to_string(), "ollama".to_string())],
            "only the dedicated embedder is excluded from chat; host6 serves both");
    }

    /// rehearsal 0.6.7-rc.1 F1: the controller's adopted ollama hosts the
    /// embedder; the heartbeat reports whatever it has loaded.
    fn embed_node(reported: &str) -> NodeFacts {
        node("ctl", "10.0.0.2", &[("ollama", reported)], &["qwen2.5:0.5b", "harrier:latest"], false, 2, 0.1)
    }

    fn pool_has_only_chat(t: &ClassTable, model: &str) {
        let d = t.class(CHAT_DEFAULT).expect("chat-default");
        let got: Vec<String> = d.candidates.iter().map(|c| format!("{}={}", c.backend, c.model)).collect();
        assert_eq!(got, vec![format!("ollama={model}")], "{got:?}");
        assert!(t.class("harrier:latest").is_none() && t.class("harrier").is_none(), "no derived class for the embedder");
    }

    #[test]
    fn a_loaded_embedder_is_never_the_chat_candidate_the_placed_chat_model_is() {
        let rows: Vec<PlacementRow> = vec![
            ("ctl".into(), "ollama".into(), Some("qwen2.5:0.5b".into()), "chat".into()),
            ("ctl".into(), "ollama".into(), Some("harrier:latest".into()), "embed".into()),
        ];
        let t = build_table(&[embed_node("harrier:latest")], &rows, &Declarations::default());
        pool_has_only_chat(&t, "qwen2.5:0.5b");
        // And it does not flip when the chat model is the loaded one.
        let t = build_table(&[embed_node("qwen2.5:0.5b")], &rows, &Declarations::default());
        pool_has_only_chat(&t, "qwen2.5:0.5b");
    }

    #[test]
    fn an_old_agent_without_roles_still_excludes_the_embedder_by_placement_or_name() {
        // No model_presence at all (reported_non_chat_models empty): the
        // embed placement row names it.
        let placed_embed: Vec<PlacementRow> = vec![
            ("ctl".into(), "ollama".into(), Some("qwen2.5:0.5b".into()), "chat".into()),
            ("ctl".into(), "ollama".into(), Some("my-embedder".into()), "embed".into()),
        ];
        let t = build_table(&[embed_node("my-embedder")], &placed_embed, &Declarations::default());
        pool_has_only_chat(&t, "qwen2.5:0.5b");
        // No embed row either (the adopted noo-ollama-embed): the name does.
        let chat_only: Vec<PlacementRow> = vec![("ctl".into(), "ollama".into(), Some("qwen2.5:0.5b".into()), "chat".into())];
        let t = build_table(&[embed_node("harrier:latest")], &chat_only, &Declarations::default());
        pool_has_only_chat(&t, "qwen2.5:0.5b");
        // No chat placement at all: the embedder alone is no candidate.
        let t = build_table(&[embed_node("harrier:latest")], &[], &Declarations::default());
        assert!(t.class(CHAT_DEFAULT).is_none(), "{:?}", t.classes);
    }

    #[test]
    fn an_agent_reported_embed_role_excludes_a_model_no_placement_or_name_gives_away() {
        let data = serde_json::json!({"id": "ctl", "ip_address": "10.0.0.2", "running_backends": {"ollama": "zzz-model"},
            "model_presence": {"ollama": {"model": "qwen2.5:0.5b", "role": "chat", "present": true},
                               "ollama#embed": {"model": "zzz-model", "role": "embed", "present": true}}});
        let n = node_facts_from_kv("ctl", &data, &[], 0.0);
        assert_eq!(n.reported_non_chat_models, vec![("ollama".to_string(), "zzz-model".to_string())]);
        let rows: Vec<PlacementRow> = vec![("ctl".into(), "ollama".into(), Some("qwen2.5:0.5b".into()), "chat".into())];
        let t = build_table(&[n], &rows, &Declarations::default());
        pool_has_only_chat(&t, "qwen2.5:0.5b");
    }

    #[test]
    fn a_model_placed_as_chat_is_chat_whatever_its_name_and_chat_models_are_untouched() {
        assert!(is_embedding_model_name("harrier:latest") && is_embedding_model_name("nomic-embed-text") && is_embedding_model_name("BAAI/bge-m3"));
        for m in ["qwen2.5:0.5b", "gemma4:12b", "llama3.2:1b"] {
            assert!(!is_embedding_model_name(m), "{m}");
        }
        let rows: Vec<PlacementRow> = vec![("ctl".into(), "ollama".into(), Some("harrier-chat".into()), "chat".into())];
        let t = build_table(&[embed_node("harrier-chat")], &rows, &Declarations::default());
        pool_has_only_chat(&t, "harrier-chat");
    }

    #[test]
    fn non_chat_and_model_missing_backends_are_not_candidates() {
        let mut n = node("embedder", "10.0.0.9", &[("ollama", "harrier")], &[], false, 2, 0.0);
        n.non_chat = vec!["ollama".into()];
        let mut m = node("host9", "10.0.0.8", &[("ollama", "gemma3:1b")], &[], false, 4, 0.0);
        m.model_missing = vec!["ollama".into()];
        let t = build_table(&[n, m], &[], &Declarations::default());
        assert!(t.classes.is_empty(), "{:?}", t.classes);
    }

    // ── declared classes, aliases, degraded ───────────────────────────

    fn declared() -> Declarations {
        Declarations {
            classes: vec![DeclaredClass {
                name: CHAT_DEFAULT.into(),
                pool: false,
                candidates: vec![
                    DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                    DeclaredCandidate { node_id: "host8".into(), backend: "ollama".into(), model: None, degraded: true },
                ],
            }],
            aliases: vec![("gemma4:12b-any".into(), CHAT_DEFAULT.into())],
        }
    }

    #[test]
    fn alias_resolves_to_class_to_ordered_candidates() {
        let t = build_table(&fleet(), &placements(), &declared());
        let c = resolve_hint(&t, Some("gemma4:12b-any")).expect("alias resolves");
        assert_eq!(c.name, CHAT_DEFAULT);
        assert!(c.declared);
        let got = names(&ordered(c, &[]));
        assert_eq!(got, vec![
            format!("host3/vllm={HF}"),
            "host6/ollama=gemma4:12b".to_string(),
            "host8/ollama=gemma4:e2b-it-qat".to_string(),
        ]);
        // NULL model took the placement's; the declared one stayed.
        assert_eq!(c.candidates[0].model, HF);
        assert_eq!(c.candidates[1].status, CandidateStatus::Available, "12b is pulled, not running");
        assert_eq!(c.candidates[0].status, CandidateStatus::Placed);
        // The hint forms: absent and the built-ins land on the same class.
        assert_eq!(resolve_hint(&t, None).unwrap().name, CHAT_DEFAULT);
        assert_eq!(resolve_hint(&t, Some("chat-default")).unwrap().name, CHAT_DEFAULT);
        // A concrete model name is its own derived class (exact filter).
        assert_eq!(resolve_hint(&t, Some("gemma4:e2b-it-qat")).unwrap().candidates[0].node_id, "host8");
        assert_eq!(resolve_hint(&t, Some("GEMMA4:E2B-IT-QAT:latest")).unwrap().candidates[0].node_id, "host8", "ollama tag rules");
        assert!(resolve_hint(&t, Some("llama3.2:1b")).is_none(), "unknown concrete name is not served");
    }

    #[test]
    fn degraded_candidates_come_only_after_every_non_degraded_one_even_when_healthier() {
        let mut nodes = fleet();
        // Both non-degraded nodes are unhealthy; the degraded one is fine.
        nodes[0].heartbeat_age_secs = Some(500.0);
        nodes[1].inbound_ok = false;
        let t = build_table(&nodes, &placements(), &declared());
        let c = t.class(CHAT_DEFAULT).unwrap();
        let order: Vec<&str> = ordered(c, &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["host3", "host6", "host8"]);
        assert!(!c.candidates[0].healthy && !c.candidates[1].healthy && c.candidates[2].healthy);
        assert_eq!(c.healthy_count(), 1);
        // Healthy outranks declared position among the non-degraded.
        let mut nodes = fleet();
        nodes[0].heartbeat_age_secs = Some(500.0);
        let t = build_table(&nodes, &placements(), &declared());
        let order: Vec<&str> = ordered(t.class(CHAT_DEFAULT).unwrap(), &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["host6", "host3", "host8"]);
    }

    #[test]
    fn same_model_failover_across_nodes_excludes_the_failed_address() {
        let nodes = vec![
            node("a", "10.0.0.1", &[("ollama", "gemma4:12b")], &[], true, 2, 0.1),
            node("b", "10.0.0.2", &[("ollama", "gemma4:12b")], &[], true, 2, 0.2),
        ];
        let t = build_table(&nodes, &[], &Declarations::default());
        let c = resolve_hint(&t, Some("gemma4:12b")).unwrap();
        let first = ordered(c, &[]);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].url, "https://10.0.0.1:8081");
        let after = ordered(c, &[("https://10.0.0.1:8081".to_string(), "ollama".to_string())]);
        assert_eq!(after.len(), 1, "the failed node is out");
        assert_eq!(after[0].node_id, "b");
        assert_eq!(after[0].model, "gemma4:12b", "same model, other node — never another model");
    }

    /// vLLM and ollama on one node share the node-agent address; a vLLM
    /// failure must not take the node's ollama out of the class.
    #[test]
    fn exclusion_is_per_backend_not_per_node_address() {
        let nodes = vec![node("host3", "10.0.0.1", &[("vllm", "m"), ("ollama", "m")], &[], true, 1, 0.1)];
        let t = build_table(&nodes, &[], &Declarations::default());
        let c = t.class("m").unwrap();
        assert_eq!(ordered(c, &[]).len(), 2);
        let after = ordered(c, &[("https://10.0.0.1:8081".to_string(), "vllm".to_string())]);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].backend, "ollama");
    }

    /// An exact pin names the model even when an alias of the same spelling
    /// exists (PUT refuses such an alias; this is the belt to that brace).
    #[test]
    fn a_class_or_served_model_outranks_an_alias_of_the_same_name() {
        let decl = Declarations { classes: vec![], aliases: vec![("gemma4:26b".into(), CHAT_DEFAULT.into())] };
        let t = build_table(&fleet(), &placements(), &decl);
        let c = resolve_hint(&t, Some("gemma4:26b")).unwrap();
        assert_eq!(c.name, "gemma4:26b");
        assert_eq!(c.candidates[0].model, "gemma4:26b");
    }

    /// A declaration named after the HF id in another case replaces the
    /// derived class: one class, declared, and the exact pin routes to the
    /// declared candidates (the regression of #807 review fix 8).
    #[test]
    fn a_declared_class_replaces_the_derived_one_whatever_the_case() {
        let decl = Declarations {
            classes: vec![DeclaredClass {
                name: HF.to_ascii_lowercase(),
                pool: false,
                candidates: vec![
                    DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: true },
                ],
            }],
            aliases: vec![],
        };
        let t = build_table(&fleet(), &placements(), &decl);
        let matching: Vec<&Class> = t.classes.iter().filter(|c| same_model(&c.name, HF)).collect();
        assert_eq!(matching.len(), 1, "one class, not a derived and a declared one: {:?}", t.classes.iter().map(|c| &c.name).collect::<Vec<_>>());
        assert!(matching[0].declared);
        let c = resolve_hint(&t, Some(HF)).unwrap();
        assert!(c.declared, "the exact pin reaches the declaration");
        assert_eq!(ordered(c, &[]).len(), 2);
        assert_eq!(ordered(c, &[])[1].node_id, "host6");
        let ids = t.ids();
        assert_eq!(ids.iter().filter(|i| same_model(i, HF)).count(), 1, "{ids:?}");
    }

    // ── pools ────────────────────────────────────────────────────────

    /// chat-default as a pool of host3's vLLM 12B and host6's ollama 12B,
    /// with host8's e2b as a degraded last resort — the shape the operator
    /// asked for on 2026-10-16 (awolf + mcmini sharing chat).
    fn pool_decl(pool: bool) -> Declarations {
        Declarations {
            classes: vec![DeclaredClass {
                name: CHAT_DEFAULT.into(),
                pool,
                candidates: vec![
                    DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                    DeclaredCandidate { node_id: "host8".into(), backend: "ollama".into(), model: None, degraded: true },
                ],
            }],
            aliases: vec![],
        }
    }

    fn order_with(t: &ClassTable, busy: &[(&str, usize)]) -> Vec<String> {
        let c = t.class(CHAT_DEFAULT).unwrap();
        ordered_by(c, &[], &|cand| busy.iter().find(|(n, _)| *n == cand.node_id).map(|(_, b)| *b).unwrap_or(0))
            .iter()
            .map(|c| c.node_id.clone())
            .collect()
    }

    #[test]
    fn a_pool_sends_the_next_request_to_the_least_busy_peer() {
        let t = build_table(&fleet(), &placements(), &pool_decl(true));
        assert!(t.class(CHAT_DEFAULT).unwrap().pool);
        // Idle: heartbeat load breaks the tie (host6 0.1 < host3 0.3).
        assert_eq!(order_with(&t, &[]), ["host6", "host3", "host8"]);
        // host6 busy with two requests, host3 with one: host3 goes first.
        assert_eq!(order_with(&t, &[("host6", 2), ("host3", 1)]), ["host3", "host6", "host8"]);
        // The degraded candidate stays last however idle it is.
        assert_eq!(order_with(&t, &[("host6", 5), ("host3", 5)]), ["host6", "host3", "host8"]);
    }

    #[test]
    fn a_pool_still_puts_an_unhealthy_peer_after_a_healthy_one() {
        let mut nodes = fleet();
        nodes[1].heartbeat_age_secs = Some(600.0); // host6 silent
        let t = build_table(&nodes, &placements(), &pool_decl(true));
        assert_eq!(order_with(&t, &[("host3", 9)]), ["host3", "host6", "host8"]);
    }

    #[test]
    fn a_class_that_is_not_a_pool_keeps_its_declared_order_under_load() {
        let t = build_table(&fleet(), &placements(), &pool_decl(false));
        assert!(!t.class(CHAT_DEFAULT).unwrap().pool);
        assert_eq!(order_with(&t, &[("host3", 9)]), ["host3", "host6", "host8"]);
    }

    #[test]
    fn a_derived_class_is_never_a_pool() {
        let t = build_table(&fleet(), &placements(), &Declarations::default());
        assert!(t.classes.iter().all(|c| !c.pool));
    }

    #[test]
    fn an_in_flight_ticket_counts_until_dropped() {
        let (url, be) = ("https://192.0.2.77:8081", "pool-test-backend");
        assert_eq!(in_flight(url, be), 0);
        let a = InFlight::open(url, be);
        let b = InFlight::open(url, be);
        assert_eq!(in_flight(url, be), 2);
        drop(a);
        assert_eq!(in_flight(url, be), 1);
        drop(b);
        assert_eq!(in_flight(url, be), 0);
    }

    #[test]
    fn a_declared_model_is_carried_separately_from_the_resolved_one() {
        let t = build_table(&fleet(), &placements(), &declared());
        let c = t.class(CHAT_DEFAULT).unwrap();
        assert_eq!(c.candidates[0].declared_model, None, "the placement's");
        assert_eq!(c.candidates[0].model, HF);
        assert_eq!(c.candidates[1].declared_model.as_deref(), Some("gemma4:12b"));
        assert!(valid_model("google/gemma-4-12B-it-qat-w4a16-ct").is_ok() && valid_model("gemma4:12b").is_ok());
        assert!(valid_model("").is_err() && valid_model("has space").is_err());
    }

    #[test]
    fn an_unplaced_declared_candidate_is_skipped_at_routing_and_visible_in_the_table() {
        let decl = Declarations {
            classes: vec![DeclaredClass {
                name: "fast".into(),
                pool: false,
                candidates: vec![
                    DeclaredCandidate { node_id: "host8".into(), backend: "ollama".into(), model: Some("qwen2.5:0.5b".into()), degraded: false },
                    DeclaredCandidate { node_id: "ghost".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                ],
            }],
            aliases: vec![],
        };
        let t = build_table(&fleet(), &placements(), &decl);
        let c = t.class("fast").unwrap();
        assert_eq!(c.candidates[0].status, CandidateStatus::Unplaced, "not pulled on host8");
        assert_eq!(c.candidates[1].status, CandidateStatus::Unplaced, "no such node");
        assert_eq!(c.candidates[1].health, "no heartbeat record");
        assert_eq!(c.candidates[2].status, CandidateStatus::Available);
        let routable = ordered(c, &[]);
        assert_eq!(routable.len(), 1, "{:?}", names(&routable));
        assert_eq!(routable[0].node_id, "host6");
        assert_eq!(c.routable_count(), 1);
    }

    #[test]
    fn the_catalogue_names_classes_and_aliases_and_no_topology() {
        let t = build_table(&fleet(), &placements(), &declared());
        let list = catalogue(&t);
        let ids: Vec<&str> = list.iter().filter_map(|v| v["id"].as_str()).collect();
        for want in [CHAT_DEFAULT, "default", "auto", "gemma4:12b-any", HF, "gemma4:26b"] {
            assert!(ids.contains(&want), "{want} missing from {ids:?}");
        }
        let text = serde_json::to_string(&list).unwrap();
        for forbidden in ["100.64", "host3", "host6", "host8", ":8081", "https://"] {
            assert!(!text.contains(forbidden), "catalogue leaks {forbidden}: {text}");
        }
        let d = list.iter().find(|v| v["id"] == CHAT_DEFAULT).unwrap();
        assert_eq!(d["owned_by"], "noomesh");
        assert_eq!(d["noo"]["candidates"], 3);
        assert_eq!(d["noo"]["healthy"], 3);
        let a = list.iter().find(|v| v["id"] == "default").unwrap();
        assert_eq!(a["noo"]["alias"], true);
        assert_eq!(a["noo"]["class"], CHAT_DEFAULT);
    }

    #[test]
    fn names_are_validated_and_builtins_are_reserved() {
        assert!(valid_name("chat-default").is_ok());
        assert!(valid_name("google/gemma-4-12B-it-qat-w4a16-ct").is_ok());
        assert!(valid_name("gemma4:12b").is_ok());
        assert!(valid_name("").is_err());
        assert!(valid_name("has space").is_err());
        assert!(valid_name("default").is_err());
        assert!(valid_name("AUTO").is_err());
    }

    #[test]
    fn kv_record_becomes_facts() {
        let data = serde_json::json!({
            "id": "host6", "ip_address": "100.64.0.11", "load": 0.2, "tier": 2, "vram_gb": 0,
            "capabilities": {"unified_memory": true},
            "running_backends": {"ollama": "gemma4:26b"},
            "available_models": ["gemma4:26b", {"name": "gemma4:12b"}],
            "model_presence": {"ollama": {"model": "gemma4:26b", "present": true}},
            "last_heartbeat": 1000.0,
            "inbound": "failed",
        });
        let f = node_facts_from_kv("host6", &data, &[("host6".into(), "llamacpp".into())], 1010.0);
        assert_eq!(f.node_id, "host6");
        assert_eq!(f.ip, "100.64.0.11");
        assert_eq!(f.running, vec![("ollama".to_string(), "gemma4:26b".to_string())]);
        assert_eq!(f.available_models, vec!["gemma4:26b", "gemma4:12b"]);
        assert!(f.model_missing.is_empty());
        assert_eq!(f.non_chat, vec!["llamacpp"]);
        assert!(f.gpu, "unified memory counts as GPU-backed");
        assert_eq!(f.heartbeat_age_secs, Some(10.0));
        assert!(!f.inbound_ok);
        assert_eq!(f.tier, Some(2));
        // Absent on an older agent: nominal, not quarantined, GPU free.
        assert_eq!(f.thermal, None);
        assert!(!f.quarantined && !f.offline && !f.gpu_shared && f.paused_backends.is_empty());
    }

    // ── the dynamic default (operator rule 2026-10-17) ────────────────

    /// The 2026-10-17 fleet: the controller pop-os serving `gemma4:e2b-it-qat`
    /// from a CPU ollama (idle-looking load), mcmini an M4 (unified memory)
    /// serving `gemma4:12b`, busier by heartbeat. Onboarding wrote
    /// `ollama` + `gemma4:e2b-it-qat` into pop-os's yaml.
    fn incident() -> Vec<NodeFacts> {
        vec![
            node("pop-os", "100.64.1.1", &[("ollama", "gemma4:e2b-it-qat")], &[], false, 1, 0.05),
            node("mcmini", "100.64.1.2", &[("ollama", "gemma4:12b")], &[], true, 3, 0.4),
        ]
    }

    fn first_node(sel: &Selection) -> &str {
        sel.candidates[0].node_id.as_str()
    }

    fn idle(_: &Candidate) -> usize {
        0
    }

    fn fresh(_: &Candidate) -> bool {
        false
    }

    /// Reverting the dynamic default to a one-model derivation sends this to
    /// pop-os (the only model group that matches the yaml, or the single
    /// best group) and fails here.
    #[test]
    fn incident_mcmini_12b_gpu_beats_popos_e2b_cpu() {
        let t = build_table(&incident(), &[], &Declarations::default());
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.class, CHAT_DEFAULT);
        assert_eq!(sel.label, "chat-default(dynamic)");
        let order: Vec<&str> = sel.candidates.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["mcmini", "pop-os"], "both nodes are candidates, the GPU 12B first");
        assert_eq!(sel.candidates[0].rank, "rank=gpu,params=12,load=0.40");
        assert_eq!(sel.candidates[1].rank, "rank=cpu,params=2,load=0.05");
        // Even with a GPU on pop-os the bigger model wins (quality key).
        let mut nodes = incident();
        nodes[0].gpu = true;
        let t = build_table(&nodes, &[], &Declarations::default());
        assert_eq!(first_node(&select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap()), "mcmini");
        // The built-in aliases land on the same dynamic class.
        let t = build_table(&incident(), &[], &Declarations::default());
        for alias in BUILTIN_ALIASES {
            assert_eq!(first_node(&select_with(&t, Some(alias), None, false, &|_| false, &idle, &fresh).unwrap()), "mcmini");
        }
    }

    #[test]
    fn thermal_critical_is_excluded_unless_it_is_the_only_one_left() {
        let mut nodes = incident();
        nodes[1].thermal = Some("critical".into());
        let t = build_table(&nodes, &[], &Declarations::default());
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap();
        let order: Vec<&str> = sel.candidates.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["pop-os"], "the critical node is out while another is left");
        assert!(sel.skipped.iter().any(|s| s.starts_with("mcmini/ollama: thermal critical")), "{:?}", sel.skipped);
        assert!(!sel.last_resort);
        // pop-os already failed this request: mcmini is all that is left.
        let sel = select_with(&t, None, None, false, &|c| c.node_id == "pop-os", &idle, &fresh).unwrap();
        assert_eq!(first_node(&sel), "mcmini");
        assert!(sel.last_resort);
        // `serious` is a demotion, not an exclusion.
        let mut nodes = incident();
        nodes[1].thermal = Some("serious".into());
        let t = build_table(&nodes, &[], &Declarations::default());
        let order: Vec<String> = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap().candidates.iter().map(|c| c.node_id.clone()).collect();
        assert_eq!(order, ["pop-os", "mcmini"]);
    }

    #[test]
    fn a_stalled_node_is_demoted_for_five_minutes_then_back() {
        let t = build_table(&incident(), &[], &Declarations::default());
        let mcmini_stalled = |c: &Candidate| c.node_id == "mcmini";
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &mcmini_stalled).unwrap();
        let order: Vec<&str> = sel.candidates.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["pop-os", "mcmini"], "demoted, not dropped");
        assert!(sel.candidates[1].rank.contains("stalled"));
        assert!(sel.skipped.iter().any(|s| s.starts_with("mcmini/ollama: stalled")), "{:?}", sel.skipped);
        // The memory itself: 5 minutes from the stall, then gone.
        let at = Instant::now();
        assert_eq!(STALL_DEMOTION, Duration::from_secs(300));
        assert!(!stall_expired(at, at + Duration::from_secs(299)));
        assert!(stall_expired(at, at + Duration::from_secs(300)));
        // Through the process-wide registry, on an address no other test uses.
        let mut nodes = incident();
        nodes[1].ip = "192.0.2.201".into();
        let t = build_table(&nodes, &[], &Declarations::default());
        let d = t.class(CHAT_DEFAULT).unwrap();
        assert_eq!(ordered(d, &[])[0].node_id, "mcmini");
        note_stall("https://192.0.2.201:8081", "ollama");
        assert!(recently_stalled("https://192.0.2.201:8081", "ollama"));
        assert!(!recently_stalled("https://192.0.2.201:8081", "vllm"), "per backend");
        assert_eq!(ordered(d, &[])[0].node_id, "pop-os");
    }

    #[test]
    fn a_quarantined_node_is_excluded_unless_it_is_the_only_one_left() {
        let rec = |status: &str| {
            serde_json::json!({
                "id": "mcmini", "ip_address": "100.64.1.2", "status": status, "load": 0.1,
                "capabilities": {"unified_memory": true},
                "running_backends": {"ollama": "gemma4:12b"}, "last_heartbeat": 1000.0,
            })
        };
        let q = node_facts_from_kv("mcmini", &rec("quarantined"), &[], 1001.0);
        assert!(q.quarantined);
        let mut nodes = incident();
        nodes[1] = q;
        let t = build_table(&nodes, &[], &Declarations::default());
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["pop-os"]);
        assert!(sel.skipped.iter().any(|s| s == "mcmini/ollama: quarantined"), "{:?}", sel.skipped);
        let only = build_table(&nodes[1..], &[], &Declarations::default());
        let sel = select_with(&only, None, None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(first_node(&sel), "mcmini");
        assert!(sel.last_resort);
        assert!(!node_facts_from_kv("mcmini", &rec("online"), &[], 1001.0).quarantined);
    }

    #[test]
    fn a_concrete_model_name_narrows_to_its_group() {
        let t = build_table(&incident(), &[], &Declarations::default());
        let sel = select_with(&t, Some("gemma4:e2b-it-qat"), None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.class, "gemma4:e2b-it-qat");
        // The named model first, then the rest of the mesh behind it.
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["pop-os", "mcmini"]);
        assert!(!sel.candidates[0].rank.starts_with("fallback"));
        assert!(sel.candidates[1].rank.starts_with("fallback,"), "{}", sel.candidates[1].rank);
        assert_eq!(sel.candidates[1].class_label, "gemma4:e2b-it-qat+mesh");
        // A model class is not ranked by the dynamic key.
        assert!(!t.class("gemma4:12b").unwrap().dynamic);
    }

    /// 2026-10-19: trellion named awolf's vLLM model while awolf's GPU ran
    /// a voice test; every knowledge answer was a `model_not_found` although
    /// mcmini and pop-os served chat. A model name is a preference.
    #[test]
    fn a_model_nothing_serves_is_answered_by_the_mesh_not_refused() {
        let t = build_table(&incident(), &[], &Declarations::default());
        let sel = select_with(&t, Some("google/gemma-4-12B-it-qat-w4a16-ct"), None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.class, CHAT_DEFAULT);
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["mcmini", "pop-os"]);
        assert!(sel.skipped.iter().any(|s| s.contains("not served by any live node")), "{:?}", sel.skipped);
        // Every one of them is a fallback for the caller (raw chat's `noo.fallback`).
        assert!(sel.candidates.iter().all(|c| c.rank.starts_with("fallback,")), "{:?}", sel.candidates.iter().map(|c| &c.rank).collect::<Vec<_>>());
        // With nothing serving chat at all there is still nothing to answer with.
        let empty = build_table(&[], &[], &Declarations::default());
        assert!(matches!(select_with(&empty, Some("x"), None, false, &|_| false, &idle, &fresh), Err(Refusal::UnknownModel(_))));
    }

    /// A declared class whose every candidate is offline (awolf down,
    /// pop-os-ma gone) still answers from whatever is live.
    #[test]
    fn a_declared_class_with_nothing_live_falls_through_to_the_mesh() {
        let decl = Declarations {
            classes: vec![DeclaredClass {
                name: "fast".into(),
                pool: false,
                candidates: vec![DeclaredCandidate { node_id: "awolf".into(), backend: "vllm".into(), model: Some("google/gemma-4-12B-it-qat-w4a16-ct".into()), degraded: false }],
            }],
            aliases: vec![],
        };
        let t = build_table(&incident(), &[], &decl);
        let sel = select_with(&t, Some("fast"), None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["mcmini", "pop-os"]);
        assert!(sel.candidates.iter().all(|c| c.rank.starts_with("fallback,")));
        assert!(sel.skipped.iter().any(|s| s.contains("class 'fast' has nothing routable")), "{:?}", sel.skipped);
        // Excluded (already failed this request) stays excluded in the fallback too.
        let sel = select_with(&t, Some("fast"), None, false, &|c| c.node_id == "mcmini", &idle, &fresh).unwrap();
        assert_eq!(first_node(&sel), "pop-os");
        assert!(matches!(select_with(&t, Some("fast"), None, false, &|_| true, &idle, &fresh), Err(Refusal::NoCandidates(_))));
    }

    #[test]
    fn a_declared_chat_default_is_respected() {
        let decl = Declarations {
            classes: vec![DeclaredClass {
                name: CHAT_DEFAULT.into(),
                pool: false,
                candidates: vec![DeclaredCandidate { node_id: "pop-os".into(), backend: "ollama".into(), model: None, degraded: false }],
            }],
            aliases: vec![],
        };
        let t = build_table(&incident(), &[], &decl);
        let d = t.class(CHAT_DEFAULT).unwrap();
        assert!(d.declared && !d.dynamic);
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(sel.label, "chat-default(declared)");
        // The operator's choice first, not the ranking's; the mesh behind it.
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["pop-os", "mcmini"]);
        assert!(sel.candidates[1].rank.starts_with("fallback,"));
        // The dynamic pool is still there for a node pin.
        assert_eq!(first_node(&select_with(&t, None, Some("mcmini"), true, &|_| false, &idle, &fresh).unwrap()), "mcmini");
    }

    #[test]
    fn a_node_pin_filters_and_refuses_clearly() {
        let mut nodes = incident();
        let mut embedder = node("host2", "100.64.1.3", &[("ollama", "harrier")], &[], false, 2, 0.0);
        embedder.non_chat = vec!["ollama".into()];
        nodes.push(embedder);
        let t = build_table(&nodes, &[], &Declarations::default());
        let sel = select_with(&t, None, Some("pop-os"), true, &|_| false, &idle, &fresh).unwrap();
        // A strict node pin: no mesh fallback behind it.
        assert_eq!(sel.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["pop-os"]);
        assert_eq!(first_node(&select_with(&t, Some("default"), Some("POP-OS"), true, &|_| false, &idle, &fresh).unwrap()), "pop-os");
        assert!(matches!(select_with(&t, None, Some("ghost"), true, &|_| false, &idle, &fresh), Err(Refusal::UnknownNode(_))));
        assert!(matches!(select_with(&t, None, Some("host2"), true, &|_| false, &idle, &fresh), Err(Refusal::NodeServesNoChat(_))));
        match select_with(&t, Some("gemma4:12b"), Some("pop-os"), true, &|_| false, &idle, &fresh) {
            Err(Refusal::NodeCannotServe(m)) => assert!(m.contains("ollama=gemma4:e2b-it-qat"), "{m}"),
            other => panic!("{other:?}"),
        }
        // A pinned node that is thermal critical is still served: the caller named it.
        let mut nodes = incident();
        nodes[0].thermal = Some("critical".into());
        let t = build_table(&nodes, &[], &Declarations::default());
        assert_eq!(first_node(&select_with(&t, None, Some("pop-os"), true, &|_| false, &idle, &fresh).unwrap()), "pop-os");
    }

    /// Operator 2026-10-19 (option 1): a node pin is a preference — that node
    /// first, then the pool, flagged — and strict is the opt-in.
    #[test]
    fn a_node_pin_is_a_preference_unless_strict() {
        let mut nodes = incident();
        let mut embedder = node("host2", "100.64.1.3", &[("ollama", "harrier")], &[], false, 2, 0.0);
        embedder.non_chat = vec!["ollama".into()];
        nodes.push(embedder);
        let t = build_table(&nodes, &[], &Declarations::default());
        let order = |sel: &Selection| sel.candidates.iter().map(|c| c.node_id.clone()).collect::<Vec<_>>();

        // The preferred node is up: it answers first, not as a fallback.
        let sel = select_with(&t, None, Some("pop-os"), false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(order(&sel), ["pop-os", "mcmini"]);
        assert!(!sel.candidates[0].rank.starts_with("fallback"));
        assert!(sel.candidates[1].rank.starts_with("fallback,"));

        // The preferred node already failed this request (busy, down): the pool.
        let sel = select_with(&t, None, Some("pop-os"), false, &|c| c.node_id == "pop-os", &idle, &fresh).unwrap();
        assert_eq!(order(&sel), ["mcmini"]);
        assert!(sel.candidates[0].rank.starts_with("fallback,"), "flagged");

        // A node serving no chat (an embedder): the pool answers, the embedder never does.
        let sel = select_with(&t, None, Some("host2"), false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(order(&sel), ["mcmini", "pop-os"]);
        assert!(sel.candidates.iter().all(|c| c.rank.starts_with("fallback,")));
        assert!(sel.skipped.iter().any(|s| s.contains("the mesh answers instead")), "{:?}", sel.skipped);

        // Node + model, the node does not serve it: the model's nodes, then the pool.
        let sel = select_with(&t, Some("gemma4:12b"), Some("pop-os"), false, &|_| false, &idle, &fresh).unwrap();
        assert_eq!(order(&sel), ["mcmini", "pop-os"]);
        assert!(sel.candidates.iter().all(|c| c.rank.starts_with("fallback,")));

        // A name that is no node of this mesh: refused either way, a typo is not "any node".
        for strict in [false, true] {
            assert!(matches!(select_with(&t, None, Some("mcmnii"), strict, &|_| false, &idle, &fresh), Err(Refusal::UnknownNode(_))));
        }

        // Strict keeps today's refusals and never leaves the node.
        assert!(matches!(select_with(&t, None, Some("host2"), true, &|_| false, &idle, &fresh), Err(Refusal::NodeServesNoChat(_))));
        assert!(matches!(select_with(&t, Some("gemma4:12b"), Some("pop-os"), true, &|_| false, &idle, &fresh), Err(Refusal::NodeCannotServe(_))));
        let stalled_pop = |c: &Candidate| c.node_id == "pop-os";
        let sel = select_with(&t, None, Some("pop-os"), true, &|_| false, &idle, &stalled_pop).unwrap();
        assert_eq!(order(&sel), ["pop-os"], "a stalled strict node is still the only one");
        assert!(matches!(select_with(&t, None, Some("pop-os"), true, &|c| c.node_id == "pop-os", &idle, &fresh), Err(Refusal::NoCandidates(_))));
        // strict with no node means nothing.
        assert_eq!(order(&select_with(&t, None, None, true, &|_| false, &idle, &fresh).unwrap()), ["mcmini", "pop-os"]);
    }

    #[test]
    fn gpu_contention_shared_demotes_and_a_paused_lane_is_no_candidate() {
        let rec = serde_json::json!({
            "id": "mcmini", "ip_address": "100.64.1.2", "load": 0.1, "last_heartbeat": 1000.0,
            "capabilities": {"unified_memory": true},
            "running_backends": {"ollama": "gemma4:12b", "llamacpp": "gemma4:26b-a4b-it-qat"},
            "gpu_contention": {"state": "shared", "foreign_mb": 4000, "paused_backends": ["llamacpp"]},
            "thermal_state": "Serious",
            "model_stats": [{"name": "mystery-model", "size_bytes": 7_200_000_000u64}],
        });
        let f = node_facts_from_kv("mcmini", &rec, &[], 1001.0);
        assert!(f.gpu_shared);
        assert_eq!(f.paused_backends, vec!["llamacpp"]);
        assert_eq!(f.thermal.as_deref(), Some("serious"));
        assert_eq!(f.model_sizes, vec![("mystery-model".to_string(), 7_200_000_000)]);
        // size_bytes is the quality fallback when the name says nothing.
        assert!(quality_of(&f, "mystery-model").is_some_and(|q| (q - 12.0).abs() < 1e-6), "{:?}", quality_of(&f, "mystery-model"));
        let mut m = incident()[1].clone();
        m.gpu_shared = true;
        m.paused_backends = vec!["llamacpp".into()];
        m.running.push(("llamacpp".into(), "gemma4:26b-a4b-it-qat".into()));
        let mut gpu_pop = incident()[0].clone();
        gpu_pop.gpu = true;
        let t = build_table(&[gpu_pop, m], &[], &Declarations::default());
        let sel = select_with(&t, None, None, false, &|_| false, &idle, &fresh).unwrap();
        let order: Vec<String> = sel.candidates.iter().map(|c| format!("{}/{}", c.node_id, c.backend)).collect();
        assert_eq!(order, ["pop-os/ollama", "mcmini/ollama"], "shared GPU sorts after a free one; the paused lane is gone");
    }
}

/// Storage round trip against a real Postgres. Opt-in: `NOO_TEST_DSN` names a
/// scratch database (a pgvector container); without it the test says so and
/// passes, so CI without a database is not red for the wrong reason — but
/// a run WITH the variable asserts every step, including that migration
/// the chain head is what stamped the schema.
#[cfg(test)]
mod db_tests {
    use super::*;

    #[tokio::test]
    async fn declarations_round_trip_through_postgres() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — model-class storage round trip not exercised");
            return;
        };
        // Migrations land in schema `mesh` on a fresh install; the runtime
        // role finds them through its search_path, so this pool sets the same.
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect scratch db");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let rev = crate::mesh_migrate::current_revision(&admin).await.expect("revision").expect("stamped");
        assert_eq!(Some(rev.as_str()), crate::mesh_migrate::MIGRATIONS.last().map(|m| m.revision), "the head revision stamped the schema");
        // A fresh pool: the migrator resets search_path on the connection it used.
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch db");

        // Empty on a fresh schema.
        let d = load_declarations(&db).await.expect("load");
        assert!(d.classes.is_empty() && d.aliases.is_empty(), "{d:?}");

        let class = DeclaredClass {
            name: CHAT_DEFAULT.into(),
            pool: false,
            candidates: vec![
                DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false },
                DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                DeclaredCandidate { node_id: "host8".into(), backend: "ollama".into(), model: None, degraded: true },
            ],
        };
        save_class(&db, &class, &["gemma4:12b-any".to_string()]).await.expect("save");
        let d = load_declarations(&db).await.expect("load");
        assert_eq!(d.classes, vec![class.clone()], "order, NULL model and degraded survive the round trip");
        assert_eq!(d.aliases, vec![("gemma4:12b-any".to_string(), CHAT_DEFAULT.to_string())]);

        // Replacing drops the candidates and aliases that are no longer named.
        let shorter = DeclaredClass { name: CHAT_DEFAULT.into(), candidates: class.candidates[..1].to_vec(), pool: false };
        save_class(&db, &shorter, &[]).await.expect("replace");
        let d = load_declarations(&db).await.expect("load");
        assert_eq!(d.classes, vec![shorter]);
        assert!(d.aliases.is_empty());

        let n = delete_class(&db, CHAT_DEFAULT).await.expect("delete");
        assert_eq!(n, 1);
        assert_eq!(delete_class(&db, CHAT_DEFAULT).await.expect("delete again"), 0);
        let d = load_declarations(&db).await.expect("load");
        assert!(d.classes.is_empty());
    }
}
