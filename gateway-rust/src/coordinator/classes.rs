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
//!   model, holding only that model's candidates; `chat-default` is the
//!   configured default model's candidates. So an undeclared fleet never
//!   silently answers a request with a different model than the one at
//!   position 0 — it fails over across NODES, not across models.
//!
//! Resolution of a `model` hint: absent / `default` / `auto` → `chat-default`;
//! an alias → its class; a class name → that class; a concrete model name →
//! the derived class of that model (the same exact-match filter `apply_pin`
//! has always applied: serve it or 404). Candidate order: non-degraded
//! before degraded, healthy before not, declared position, then load.
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
    pub load: f64,
    pub tier: Option<i64>,
    /// `vram_gb > 0`, or unified memory (Apple silicon).
    pub gpu: bool,
    /// Seconds since the last heartbeat; `None` = no timestamp.
    pub heartbeat_age_secs: Option<f64>,
    /// `false` only when the reachability probe RECORDED a failure.
    pub inbound_ok: bool,
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
    #[serde(skip)]
    gpu: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Class {
    pub name: String,
    pub declared: bool,
    pub candidates: Vec<Candidate>,
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

fn health_of(n: &NodeFacts) -> (bool, String) {
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
        format!("https://{}:8081", n.ip)
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
    }
}

/// Build the class table from facts.
///
/// `default_model` is `cluster.backends.<default_backend>.model`;
/// `preferred_backend` is `cluster.default_backend`. Both only matter for
/// the derived `chat-default`.
pub fn build_table(
    nodes: &[NodeFacts],
    placements: &[PlacementRow],
    decl: &Declarations,
    default_model: &str,
    preferred_backend: &str,
) -> ClassTable {
    // Every served chat model, as the heartbeats report it.
    let mut served: Vec<Candidate> = Vec::new();
    for n in nodes {
        for (bt, m) in &n.running {
            if !INFERENCE_TYPES.contains(&bt.as_str()) || m.is_empty() {
                continue;
            }
            if n.non_chat.iter().any(|b| b == bt) || n.model_missing.iter().any(|b| b == bt) {
                continue;
            }
            served.push(candidate(n, bt, m, 0, false, CandidateStatus::Placed));
        }
    }

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
        classes.push(Class { name: spelling[&key].clone(), declared: false, candidates: cands });
    }

    // Derived chat-default: the default model's group, else the group the
    // legacy sort would have landed on (preferred type, then derive key) —
    // still ONE model's candidates.
    let derived_default: Option<Class> = classes
        .iter()
        .find(|c| same_model(&c.name, default_model))
        .or_else(|| {
            classes.iter().min_by_key(|c| {
                let first = &c.candidates[0];
                (if first.backend == preferred_backend { 0 } else { 1 }, derive_key(first))
            })
        })
        .map(|c| Class { name: CHAT_DEFAULT.into(), declared: false, candidates: c.candidates.clone() });

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
            let running_model = node.and_then(|n| n.running.iter().find(|(b, _)| b == &dc.backend).map(|(_, m)| m.clone()));
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
        let class = Class { name: d.name.clone(), declared: true, candidates: cands };
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
        if let Some(d) = derived_default {
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
    ClassTable { classes, aliases }
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
/// with its vLLM.
pub fn ordered<'a>(class: &'a Class, exclude: &[(String, String)]) -> Vec<&'a Candidate> {
    let mut out: Vec<&Candidate> = class
        .candidates
        .iter()
        .filter(|c| c.status != CandidateStatus::Unplaced)
        .filter(|c| !exclude.iter().any(|(u, b)| u == &c.url && b == &c.backend))
        .collect();
    out.sort_by_key(|c| order_key(c));
    out
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
        non_chat: non_chat.iter().filter(|(n, _)| n == &node_id).map(|(_, b)| b.clone()).collect(),
        load: data.get("load").and_then(Value::as_f64).map(|l| l.clamp(0.0, 1.0)).unwrap_or(0.0),
        tier: data.get("tier").and_then(Value::as_i64),
        gpu: vram > 0.0 || unified,
        heartbeat_age_secs: last.map(|t| (now_unix - t).max(0.0)),
        inbound_ok: data.get("inbound").and_then(Value::as_str) != Some("failed"),
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

/// The live table: KV facts + placements + declarations + config default.
pub async fn load_table(state: &AppState) -> Result<ClassTable> {
    let (decl, placements) = declared_and_placements(state).await?;
    let nodes = kv_node_facts(state, &placements).await;
    let cfg = &state.config.cluster;
    let default_model = cfg.backends.get(cfg.default_backend.as_str()).map(|b| b.model.clone()).unwrap_or_default();
    Ok(build_table(&nodes, &placements, &decl, &default_model, &cfg.default_backend))
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
    let rows: Vec<(String, i32, String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT class, position, node_id, backend, model, degraded FROM noo_model_classes ORDER BY class, position",
    )
    .fetch_all(db)
    .await?;
    let mut classes: Vec<DeclaredClass> = Vec::new();
    for (class, _pos, node_id, backend, model, degraded) in rows {
        let c = match classes.iter_mut().find(|c| c.name == class) {
            Some(c) => c,
            None => {
                classes.push(DeclaredClass { name: class.clone(), candidates: Vec::new() });
                classes.last_mut().expect("just pushed")
            }
        };
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
            "INSERT INTO noo_model_classes (class, position, node_id, backend, model, degraded, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (class, node_id, backend) DO UPDATE SET position = EXCLUDED.position, \
               model = EXCLUDED.model, degraded = EXCLUDED.degraded, updated_at = NOW()",
        )
        .bind(&class.name)
        .bind(i as i32)
        .bind(&c.node_id)
        .bind(&c.backend)
        .bind(&c.model)
        .bind(c.degraded)
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
    fn nothing_declared_derives_one_class_per_model_with_same_model_candidates_only() {
        let t = build_table(&fleet(), &placements(), &Declarations::default(), HF, "vllm");
        let ids = t.ids();
        assert!(ids.contains(&CHAT_DEFAULT.to_string()), "{ids:?}");
        assert!(ids.contains(&HF.to_string()) && ids.contains(&"gemma4:26b".to_string()) && ids.contains(&"gemma4:e2b-it-qat".to_string()), "{ids:?}");
        assert!(ids.contains(&"default".to_string()) && ids.contains(&"auto".to_string()));
        // chat-default = the configured default model's candidates, nothing else.
        let d = t.class(CHAT_DEFAULT).expect("chat-default");
        assert_eq!(names(&ordered(d, &[])), vec![format!("host3/vllm={HF}")]);
        assert!(!d.declared);
        // Every derived class holds exactly one model.
        for c in &t.classes {
            let models: std::collections::HashSet<String> = c.candidates.iter().map(|c| norm_model(&c.model)).collect();
            assert_eq!(models.len(), 1, "class {} mixes models: {models:?}", c.name);
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
        let t = build_table(&nodes, &[], &Declarations::default(), "m", "vllm");
        let c = t.class("m").unwrap();
        let order: Vec<&str> = ordered(c, &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["v", "gpu-idle", "gpu-busy", "gpu-idle-t3", "cpu"]);
    }

    #[test]
    fn an_unserved_default_model_still_yields_a_single_model_chat_default() {
        let t = build_table(&fleet(), &placements(), &Declarations::default(), "Qwen/Qwen3-8B-AWQ", "vllm");
        let d = t.class(CHAT_DEFAULT).unwrap();
        let models: std::collections::HashSet<String> = d.candidates.iter().map(|c| norm_model(&c.model)).collect();
        assert_eq!(models.len(), 1, "{models:?}");
        assert_eq!(d.candidates[0].backend, "vllm", "the preferred type wins when the default is not served");
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

    #[test]
    fn non_chat_and_model_missing_backends_are_not_candidates() {
        let mut n = node("embedder", "10.0.0.9", &[("ollama", "harrier")], &[], false, 2, 0.0);
        n.non_chat = vec!["ollama".into()];
        let mut m = node("host9", "10.0.0.8", &[("ollama", "gemma3:1b")], &[], false, 4, 0.0);
        m.model_missing = vec!["ollama".into()];
        let t = build_table(&[n, m], &[], &Declarations::default(), "", "vllm");
        assert!(t.classes.is_empty(), "{:?}", t.classes);
    }

    // ── declared classes, aliases, degraded ───────────────────────────

    fn declared() -> Declarations {
        Declarations {
            classes: vec![DeclaredClass {
                name: CHAT_DEFAULT.into(),
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
        let t = build_table(&fleet(), &placements(), &declared(), HF, "vllm");
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
        let t = build_table(&nodes, &placements(), &declared(), HF, "vllm");
        let c = t.class(CHAT_DEFAULT).unwrap();
        let order: Vec<&str> = ordered(c, &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["host3", "host6", "host8"]);
        assert!(!c.candidates[0].healthy && !c.candidates[1].healthy && c.candidates[2].healthy);
        assert_eq!(c.healthy_count(), 1);
        // Healthy outranks declared position among the non-degraded.
        let mut nodes = fleet();
        nodes[0].heartbeat_age_secs = Some(500.0);
        let t = build_table(&nodes, &placements(), &declared(), HF, "vllm");
        let order: Vec<&str> = ordered(t.class(CHAT_DEFAULT).unwrap(), &[]).iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(order, ["host6", "host3", "host8"]);
    }

    #[test]
    fn same_model_failover_across_nodes_excludes_the_failed_address() {
        let nodes = vec![
            node("a", "10.0.0.1", &[("ollama", "gemma4:12b")], &[], true, 2, 0.1),
            node("b", "10.0.0.2", &[("ollama", "gemma4:12b")], &[], true, 2, 0.2),
        ];
        let t = build_table(&nodes, &[], &Declarations::default(), "gemma4:12b", "vllm");
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
        let t = build_table(&nodes, &[], &Declarations::default(), "m", "vllm");
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
        let t = build_table(&fleet(), &placements(), &decl, HF, "vllm");
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
                candidates: vec![
                    DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: true },
                ],
            }],
            aliases: vec![],
        };
        let t = build_table(&fleet(), &placements(), &decl, HF, "vllm");
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

    #[test]
    fn a_declared_model_is_carried_separately_from_the_resolved_one() {
        let t = build_table(&fleet(), &placements(), &declared(), HF, "vllm");
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
                candidates: vec![
                    DeclaredCandidate { node_id: "host8".into(), backend: "ollama".into(), model: Some("qwen2.5:0.5b".into()), degraded: false },
                    DeclaredCandidate { node_id: "ghost".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                    DeclaredCandidate { node_id: "host6".into(), backend: "ollama".into(), model: Some("gemma4:12b".into()), degraded: false },
                ],
            }],
            aliases: vec![],
        };
        let t = build_table(&fleet(), &placements(), &decl, HF, "vllm");
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
        let t = build_table(&fleet(), &placements(), &declared(), HF, "vllm");
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
    }
}

/// Storage round trip against a real Postgres. Opt-in: `NOO_TEST_DSN` names a
/// scratch database (a pgvector container); without it the test says so and
/// passes, so CI without a database is not red for the wrong reason — but
/// a run WITH the variable asserts every step, including that migration
/// the chain head (`092_kiosk_seats`, over `091_token_budgets`) is what stamped the schema.
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
        assert_eq!(rev, crate::mesh_migrate::KIOSK_SEATS_REVISION, "the head revision is the kiosk-seats migration");
        // A fresh pool: the migrator resets search_path on the connection it used.
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch db");

        // Empty on a fresh schema.
        let d = load_declarations(&db).await.expect("load");
        assert!(d.classes.is_empty() && d.aliases.is_empty(), "{d:?}");

        let class = DeclaredClass {
            name: CHAT_DEFAULT.into(),
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
        let shorter = DeclaredClass { name: CHAT_DEFAULT.into(), candidates: class.candidates[..1].to_vec() };
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
