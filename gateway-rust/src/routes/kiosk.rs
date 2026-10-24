// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `/api/kiosk/*` — a read surface shaped to one unattended display.
//!
//! **Every handler here is a PROJECTION of a general route's own output, not
//! a second query.** `nodes` calls `cluster::cluster_status` and drops the
//! fields the display never draws; it does not re-read the mesh KV. That is
//! the whole design, and it buys three things:
//!
//! - it cannot show something the general route would not, because it starts
//!   from that route's answer;
//! - it cannot drift, because there is one query and one assembly;
//! - and it is auditable by reading a field list rather than SQL.
//!
//! ## Why a separate surface at all
//!
//! The display is a repurposed laptop in a corridor. It renders five fields
//! of a node and receives nine: `GET /api/cluster/status` also carries
//! `cert_not_after` and `vram_gb`, so a PKI expiry date travels to a screen
//! that never shows it. the design found the same shape on the graph side —
//! cluster names are entity-derived (an LLM label over the top entities,
//! falling back to concatenating them), and the kiosk fetched them whether or
//! not `?labels=1` rendered them, because `labels=0` was a render-time
//! decision and not a fetch-time one.
//!
//! Here it is a fetch-time decision, made by the controller: unless the
//! operator's `kiosk.graph_labels` setting is on, the wire carries no name
//! at all, which closes  by construction rather than by
//! asking the client to be careful.
//!
//! ## What this module deliberately does NOT do
//!
//! No auth change. These routes sit behind the same middleware as everything
//! else, so today they need the same credential `/api/cluster/status` needs.
//! Accepting a scoped service key on this prefix is the design mechanism 1
//! and lands separately — this module is safe to have without it precisely
//! because it exposes a strict subset of what the caller could already read.
//!
//! The shapes are `pai-mesh-ui`'s `kiosk/store.ts` `Snapshot*` types,
//! verbatim. The display's own types are the contract; that is what makes
//! "only what it draws" checkable rather than a matter of taste.

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio_stream::StreamExt as _;

use crate::state::AppState;
use super::AppResult;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // the design, the ONLY mint: the tailnet is the
        // credential, so the display stores no durable secret at all.
        // Literal, not `auth::KIOSK_TOKEN_TAILNET_PATH`: the OpenAPI
        // generator reads route strings; the auth test pins the two equal.
        //
        // The KEY lane (`POST /api/kiosk/token`, a `kiosk`-scoped service
        // key that never expired buying display tokens) was retired on
        // 2026-09-30 — 24 h of live logs showed every display minting here
        // and none there. It is not routed, not admitted by the middleware,
        // and the scope is no longer issuable
        // (`kiosk_key_lane_is_not_routed` below).
        .route("/api/kiosk/token/tailnet", post(token_tailnet))
        // Mechanism 3: the state stream.
        .route("/api/events/stream", get(events_stream))
        .route("/api/kiosk/nodes", get(nodes))
        .route("/api/kiosk/gpus", get(gpus))
        .route("/api/kiosk/jobs", get(jobs))
        .route("/api/kiosk/scheduler", get(scheduler))
        .route("/api/kiosk/heartbeat", get(heartbeat))
        .route("/api/kiosk/memory", get(memory))
        .route("/api/kiosk/rag", get(rag))
        .route("/api/kiosk/graph", get(graph))
        .route("/api/kiosk/addons", get(addons))
}

// ── The projector ────────────────────────────────────────────────────────

/// Keep `fields` from an object; recurse into an array of objects.
///
/// Absent keys are simply absent — never null-filled. A projection that
/// invents `{"tier": null}` for a payload that never had `tier` tells the
/// display "known to be unset" when the truth is "the source did not say",
/// and this repo has paid for that distinction more than once today.
fn pick(value: &Value, fields: &[&str]) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| pick(v, fields)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for f in fields {
                if let Some(v) = map.get(*f) {
                    out.insert((*f).to_string(), v.clone());
                }
            }
            Value::Object(out)
        }
        // A scalar where an object was expected is a shape change upstream.
        // Passing it through unchanged would hide that; the caller sees the
        // same scalar the general route produced and can tell.
        other => other.clone(),
    }
}

/// `pick` applied to `body[key]`, which is where most general routes put
/// their list. Missing key → an empty array, because "the route answered and
/// had none" and "the route did not answer" are already distinguished by the
/// HTTP status.
fn pick_from(body: &Value, key: &str, fields: &[&str]) -> Value {
    match body.get(key) {
        Some(v) => pick(v, fields),
        None => json!([]),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `SnapshotNode` — the five fields the display renders, of the nine
/// `/api/cluster/status` returns. `cert_not_after`, `vram_gb`, `load` and
/// `backends` stop leaving the controller.
async fn nodes(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::cluster::cluster_status(State(state)).await;
    Ok(Json(json!({
        "nodes": pick_from(&full.0, "nodes", &["id", "hostname", "status", "running_backends", "tier"]),
    })))
}

/// `SnapshotGpu`. Every field here IS drawn — the meter, the label and the
/// node join — so this projection is currently the identity. It exists so
/// that a field ADDED to the general route does not silently reach the
/// display: the list is the decision, and it has to be edited on purpose.
async fn gpus(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::cluster::cluster_gpu_metrics(State(state)).await;
    Ok(Json(json!({
        "gpus": pick_from(&full.0, "gpus", &[
            "node_id", "hostname", "index", "name",
            "utilization", "memory_used", "memory_total", "temperature",
        ]),
    })))
}

#[derive(Deserialize, Default)]
struct JobsParams {
    /// Passed through to the general route. The display shows a short list.
    limit: Option<u32>,
}

/// `SnapshotJob`. Notably drops `payload` and `result`, which can carry the
/// prompt text of whatever the mesh is working on.
async fn jobs(State(state): State<Arc<AppState>>, Query(p): Query<JobsParams>) -> AppResult {
    let params = super::admin::ListJobsParams {
        status: None,
        node_id: None,
        limit: Some(p.limit.unwrap_or(25).min(100) as usize),
        // The kiosk is an operator display, not a per-person view: it shows
        // the queue of the whole mesh, with the payload already stripped.
        // Unscoped on purpose: the mesh-wide queue is global by design
        // (`scope: None` is what `job_visible` treats as "every job").
        scope: None,
        fleet: false,
    };
    let full = super::admin::list_jobs_for(state, params).await?;
    Ok(Json(json!({
        "jobs": pick_from(&full, "jobs", &["job_id", "status", "type", "node_id", "created_at"]),
    })))
}

/// `SnapshotScheduler`.
async fn scheduler(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::admin::scheduler_status(State(state)).await;
    Ok(Json(pick(&full.0, &["running", "paused", "queue_depth", "active_jobs", "error"])))
}

/// `SnapshotHeartbeat` — two booleans out of a payload that otherwise names
/// every scheduled task on the mesh.
async fn heartbeat(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::intelligence::heartbeat_status(State(state)).await?;
    Ok(Json(pick(&full.0, &["enabled", "running"])))
}

/// `SnapshotMemory`. `warnings` is a list of operator-facing strings and is
/// drawn; anything else the health check returns is not.
async fn memory(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::memory::memory_health(State(state)).await?;
    Ok(Json(pick(&full.0, &["grade", "warnings", "error"])))
}

/// `SnapshotRag`.
async fn rag(State(state): State<Arc<AppState>>) -> AppResult {
    let full = super::knowledge::rag_status(State(state)).await?;
    Ok(Json(pick(&full.0, &["started", "unembedded_chunks", "doc_count"])))
}

/// How many entities the wall shows, and how connected one must be to
/// appear. 160 hubs at degree ≥ 2 is a legible cloud at three metres; the
/// general route's 200/2 defaults are tuned for a console with a mouse.
const KIOSK_GRAPH_LIMIT: i32 = 160;
const KIOSK_GRAPH_MIN_DEGREE: i32 = 2;

/// The most edges a display is sent.
///
/// The node cap was enforced from the start; nothing capped edges, and the
/// live display measured 160 nodes with **4,570** edges between them —
/// average degree 57. Two problems, one number. It is 4,570 strokes a
/// frame, which is why the quality governor parked that screen in its
/// cheapest tier and stayed there. And it is a hairball: nobody standing
/// in a corridor can read 4,570 lines between 160 dots.
const KIOSK_GRAPH_EDGE_LIMIT: usize = 480;

/// Each node keeps at least this many of its strongest edges, so the cap
/// thins the picture rather than tearing pieces off it. A dot with nothing
/// joining it says something false about the graph.
const KIOSK_EDGES_PER_NODE: usize = 3;

/// Thin a dense edge list down to something a wall can show.
///
/// Strongest first by confidence, keeping an edge while either endpoint is
/// still short of `per_node`, then the highest-confidence remainder up to
/// `cap`. Below the cap nothing is touched — a sparse graph must not be
/// silently thinned.
fn prune_edges(edges: &[Value], per_node: usize, cap: usize) -> Vec<Value> {
    if edges.len() <= cap {
        return edges.to_vec();
    }
    let conf = |e: &Value| e.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
    let mut ranked: Vec<&Value> = edges.iter().collect();
    // Descending, and stable so equal confidences keep the query's order
    // rather than shuffling between refreshes.
    ranked.sort_by(|a, b| conf(b).partial_cmp(&conf(a)).unwrap_or(std::cmp::Ordering::Equal));

    let ends = |e: &Value| {
        (
            e.get("src").and_then(Value::as_str).unwrap_or("").to_string(),
            e.get("dst").and_then(Value::as_str).unwrap_or("").to_string(),
        )
    };
    let mut per: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut kept: Vec<Value> = Vec::new();
    let mut rest: Vec<&Value> = Vec::new();
    for e in ranked {
        let (a, b) = ends(e);
        let ca = *per.get(&a).unwrap_or(&0);
        let cb = *per.get(&b).unwrap_or(&0);
        if ca < per_node || cb < per_node {
            *per.entry(a).or_insert(0) += 1;
            *per.entry(b).or_insert(0) += 1;
            kept.push(e.clone());
        } else {
            rest.push(e);
        }
    }
    // Fill any headroom with the next strongest, so a generous cap is used
    // rather than left on the table.
    for e in rest {
        if kept.len() >= cap {
            break;
        }
        kept.push(e.clone());
    }
    kept.truncate(cap);
    kept
}

/// `SnapshotGraph`, and the one projection that removes something sensitive
/// rather than merely superfluous.
///
/// ## Why the ENTITY level
///
/// This served `/api/v1/graph/clusters/overview`, and on the first real
/// display that produced 58 nodes and **zero links**. Two reasons
/// compounding: clustering covered 761 of 4,538 entities, and
/// `SQL_CLUSTER_EDGES` requires `COUNT(*) >= 2` shared edges AND both
/// endpoints already in `entity_cluster_members`. So the wall showed a
/// constellation with nothing joining it, on a graph with 8,475 edges in it.
///
/// Worse, it could not react. Clusters are written by a recluster pass, so
/// an ingest changes nothing on screen until someone runs one. The entity
/// view is built from `entities` and `edges` — which every tier writes, on
/// every ingest — so it needs no clustering and moves within a builder
/// cycle. `graph_clusters_overview_for`'s own `requires_intelligent_tier`
/// hint has been pointing here for two releases.
///
/// ## The privacy rule, which is the part not to get wrong
///
/// A hallway display must not publish what the knowledge base knows
/// At the cluster level a `name` was an LLM's summary of an
/// area. At the entity level a `name` **is a person, a document, a
/// customer** — strictly MORE sensitive, not less, so switching the source
/// tightens the rule rather than relaxing it.
///
/// Names stay off by default, and the decision is made HERE — at fetch
/// time, in the gateway — so that without it no name is ever put on the
/// wire for the browser to hold, cache, or hand to devtools. `rel_type`
/// goes with them: "employs", "diagnosed_with" between two opaque ids
/// still describes what is known.
///
/// ONE party decides, and it is the controller: the operator's
/// `kiosk.graph_labels` setting (`noo kiosk labels on|off`, or the
/// console's Settings → Kiosk), a `noo_settings` row that only an
/// Operator/Admin can write and that records who wrote it and when. The
/// caller here is the kiosk credential, and nothing it sends can widen its
/// own read: there is no query flag any more. `?labels=1` was the page's
/// half of a two-party rule, but the page never sent it, and a token lifted
/// off a corridor machine could have — so it is gone, and anything in the
/// query string is ignored.
///
/// `NOO_KIOSK_GRAPH_LABELS` on the gateway was the operator's half. It is
/// RETIRED and ignored: switching names on meant editing the gateway's
/// environment and restarting it, and recorded nobody. A gateway that still
/// has it set says so once in its log.
///
/// The response carries `labels: true|false`, so the page knows which it
/// was sent and can say `LABELS ON` where anyone at the display can see it.
///
/// What is left with the switch off is an id (a UUID — see
/// `entity_id::text`), a degree and a type. A guard asserts the id is not
/// the name, because if `entity_id` ever became the canonical name this
/// whole design would collapse silently.
pub(crate) fn graph_labels_on() -> bool {
    warn_if_retired_labels_env();
    crate::settings::db_flag(super::settings::KIOSK_GRAPH_LABELS, false)
}

/// The retired switch, named once per process if it is still set, so an
/// operator who set it learns it no longer does anything — and how to do
/// what they meant.
fn warn_if_retired_labels_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("NOO_KIOSK_GRAPH_LABELS").is_some() {
            tracing::warn!(
                "NOO_KIOSK_GRAPH_LABELS is retired and ignored: kiosk graph labels are the \
                 controller setting kiosk.graph_labels now — `noo kiosk labels on|off|status`"
            );
        }
    });
}

/// The display's wire shape from the general route's answer: names and
/// relation types only under `labels`, and `labels` itself either way.
fn project_graph(full: &Value, labels: bool) -> Value {
    let (node_fields, edge_fields): (&[&str], &[&str]) = if labels {
        (&["id", "name", "type", "degree"], &["src", "dst", "rel_type"])
    } else {
        (&["id", "type", "degree"], &["src", "dst"])
    };
    let all_edges = full.get("edges").and_then(Value::as_array).cloned().unwrap_or_default();
    let kept = prune_edges(&all_edges, KIOSK_EDGES_PER_NODE, KIOSK_GRAPH_EDGE_LIMIT);

    let mut out = Map::new();
    out.insert("nodes".into(), pick_from(full, "nodes", node_fields));
    out.insert("edges".into(), pick(&Value::Array(kept.clone()), edge_fields));
    // What the display is NOT being shown. Without this the page reports
    // stats.edge_count — the true total — beside a picture drawing a
    // fraction of it, which is a quieter version of the same lie the
    // liveness band used to tell.
    out.insert("edges_drawn".into(), Value::from(kept.len()));
    out.insert("edges_total".into(), Value::from(all_edges.len()));
    for k in ["stats", "reason", "entity_count", "hint"] {
        if let Some(v) = full.get(k) {
            out.insert(k.to_string(), v.clone());
        }
    }
    out.insert("labels".into(), Value::Bool(labels));
    Value::Object(out)
}

async fn graph(State(state): State<Arc<AppState>>) -> AppResult {
    let labels = graph_labels_on();
    // Unrestricted ON PURPOSE: the wall display is not a person. It is sent
    // structure only (id, type, degree) and entity names only while the
    // operator's `kiosk.graph_labels` is on, which is the
    // audience decision for it. the design records this as a deliberate
    // exception.
    let full = super::knowledge::graph_overview_for(
        state,
        &crate::memory::scope::Audience::Unrestricted,
        KIOSK_GRAPH_MIN_DEGREE,
        None,
        KIOSK_GRAPH_LIMIT,
    )
    .await?;
    Ok(Json(project_graph(&full, labels)))
}

/// The add-on state map, from the same table `/health` renders. The display
/// uses it to say "knowledge pack disabled" instead of "the graph is empty",
/// which is the distinction the design was about.
async fn addons(State(_state): State<Arc<AppState>>) -> AppResult {
    let map: Map<String, Value> = crate::addons::health_names()
        .into_iter()
        .map(|n| {
            let word = json!(crate::addons::health_word(&n));
            (n, word)
        })
        .collect();
    Ok(Json(json!({ "addons": Value::Object(map) })))
}


// ── Mechanism 2: the KEYLESS mint ───────────────────────────────────────

#[derive(Deserialize)]
struct TailnetMintBody {
    tailnet_ip: String,
    proof_nonce: String,
    #[serde(default = "default_proof_port")]
    proof_port: u16,
}

fn default_proof_port() -> u16 {
    8099
}

/// The tag a display must carry for the keyless mint. Env-overridable the
/// same way `NOO_ENROLL_TAILNET_TAG` is, and for the same reason: a tailnet
/// that names its display tag differently should not have to patch code.
fn kiosk_tailnet_tag() -> String {
    std::env::var("NOO_KIOSK_TAILNET_TAG")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "tag:kiosk".into())
}

/// POST /api/kiosk/token/tailnet — a kiosk token for a display that holds
/// NO durable secret. The tailnet is the credential.
///
/// This is `enroll_tailnet`'s admission, reused verbatim in shape, because
/// the reasoning is identical and was already paid for: the gateway
/// container cannot see real peer addresses through the docker SNAT path
/// (finding #52) and forwarded headers are spoofable, so **nothing the
/// caller asserts is trusted**. Both checks are performed by the
/// controller's SELF-AGENT, a host process beside tailscaled:
///
///   1. `whois(claimed tailnet_ip)` must carry `NOO_KIOSK_TAILNET_TAG`
///      (default `tag:kiosk`). Only a device an admin admitted to the
///      tailnet with that tag passes, and the display's IDENTITY — the
///      consumer name on the minted token — comes from the tailnet, never
///      from the body.
///   2. dialback: the display publishes a nonce on its own tailnet
///      address; the self-agent fetches it. WireGuard routing guarantees
///      only that address's true owner can answer, so a matching nonce
///      proves the caller IS that display. A LAN caller claiming a real
///      display's address fails here.
///
/// What this buys over the retired key lane: nothing durable sits on a
/// machine in a corridor. What it costs is availability, not secrecy: a
/// stored key needed only OUTBOUND reachability to mint, while this needs
/// both directions working at every renewal. It fails dark rather than
/// leaking, which is the trade the operator chose — and with the key lane
/// gone, it is the only way a display gets a token.
///
/// Kill switch: `NOO_KIOSK_TAILNET_MINT=0` (which now means "no kiosk").
/// Response: `{"token": "<jwt>", "expires_in": 900, "consumer": "<name>"}`.
async fn token_tailnet(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TailnetMintBody>,
) -> Response {
    let deny = |msg: &str| -> Response {
        (StatusCode::FORBIDDEN, Json(json!({"error": {"type": "tailnet_denied", "message": msg}})))
            .into_response()
    };
    let bad = |msg: &str| -> Response {
        (StatusCode::BAD_REQUEST, Json(json!({"error": {"type": "bad_request", "message": msg}})))
            .into_response()
    };
    let internal = |msg: String| -> Response {
        (StatusCode::SERVICE_UNAVAILABLE,
         Json(json!({"error": {"type": "self_agent", "message": msg}}))).into_response()
    };

    if std::env::var("NOO_KIOSK_TAILNET_MINT")
        .is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("false"))
    {
        return deny("the keyless kiosk mint is disabled on this controller (NOO_KIOSK_TAILNET_MINT=0)");
    }

    // Same validation as enroll_tailnet: 100.64/10 is the tailnet range.
    let ip_ok = body
        .tailnet_ip
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|v4| v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]));
    if !ip_ok {
        return bad("tailnet_ip must be a 100.64/10 IPv4 address");
    }
    if body.proof_nonce.len() < 16
        || body.proof_nonce.len() > 128
        || !body.proof_nonce.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return bad("proof_nonce must be 16–128 alphanumeric chars");
    }
    if body.proof_port == 0 {
        return bad("proof_port must be non-zero");
    }

    let link = match crate::node_link::NodeLink::self_agent() {
        Ok(l) => l,
        Err(e) => return internal(e),
    };
    let agent_base = link.base().to_string();

    // 1. whois: the tag, and the name we will mint under.
    let who: Value = match link
        .request(reqwest::Method::GET, &format!("/tailnet/whois?ip={}", body.tailnet_ip))
    .send()
    .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return internal(format!("self-agent whois: bad response: {e}")),
        },
        Err(e) => {
            // i11a: reqwest's Display stops at "error sending request"; the
            // cause (a certificate that does not name the host) is in the
            // source chain. Log it at WARN and return it.
            let chain = crate::addon_proxy::error_chain(&e);
            tracing::warn!(agent = %agent_base, error = %chain, "kiosk tailnet mint: controller self-agent call failed");
            return internal(format!(
                "controller self-agent unreachable at {agent_base}: {chain} — is noo-node-agent running on the controller host, and does its cert name this host?"
            ))
        }
    };
    let required_tag = kiosk_tailnet_tag();
    let tags: Vec<String> = who["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let audit_denied = |reason: &'static str, ip: String| {
        let db = state.db.clone();
        async move {
            crate::audit::record(
                &db,
                AuditEvent::new(AuditKind::KioskTailnetMintDenied, "anonymous", &format!("kiosk-mint:{ip}"))
                    .outcome(crate::audit::Outcome::Denied)
                    .details(json!({ "reason": reason })),
            )
            .await;
        }
    };
    if !tags.iter().any(|t| t == &required_tag) {
        tracing::info!(ip = %body.tailnet_ip, ?tags, %required_tag,
            "kiosk tailnet mint: device lacks the required tag");
        audit_denied("missing_required_tag", body.tailnet_ip.clone()).await;
        return deny(&format!(
            "the tailnet device at that address does not carry {required_tag}"
        ));
    }
    // Identity from the tailnet, never self-report.
    let node_name = match who["name"]
        .as_str()
        .and_then(|n| n.split('.').next())
        .map(str::to_string)
        .filter(|n| !n.is_empty())
    {
        Some(n) => n,
        None => return internal("self-agent whois returned no name".into()),
    };

    // 2. dialback: prove the caller OWNS the address it claimed.
    let db_resp: Value = match link
        .request(reqwest::Method::POST, "/tailnet/dialback")
        .json(&json!({
            "ip": body.tailnet_ip,
            "port": body.proof_port,
            "expect": body.proof_nonce,
        }))
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return internal(format!("self-agent dialback: bad response: {e}")),
        },
        Err(e) => return internal(format!("self-agent dialback failed: {e}")),
    };
    if db_resp["ok"].as_bool() != Some(true) {
        tracing::info!(ip = %body.tailnet_ip, reason = %db_resp["reason"],
            "kiosk tailnet mint: dialback did not verify");
        audit_denied("dialback_failed", body.tailnet_ip.clone()).await;
        return deny("dialback did not verify — the display did not answer with the nonce it sent");
    }

    let ttl = crate::auth::KIOSK_TOKEN_TTL_SECS;
    match crate::auth::mint_kiosk_jwt(&node_name, ttl) {
        Some(tok) => {
            tracing::info!(consumer = %node_name, ip = %body.tailnet_ip, ttl,
                "kiosk_token_minted_keyless");
            Json(json!({"token": tok, "expires_in": ttl, "consumer": node_name})).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {"type": "no_jwt_secret",
                "message": "the gateway has no usable NOO_JWT_SECRET; kiosk tokens cannot be minted"}})),
        )
            .into_response(),
    }
}

// ── Mechanism 3: the state stream ────────────────────────────────────────

/// Keepalive interval, announced in `hello` so the client's stall
/// detector is derived from it rather than guessed. Fixed, not adaptive:
/// the whole point is that silence past 3× this means *dead*.
const KEEPALIVE_MS: u64 = 15_000;
/// How often the sampled kinds are read.
const SAMPLE_SECS: u64 = 15;
/// Graph counts are two `COUNT(*)`s; half the rate of the rest.
const GRAPH_SAMPLE_SECS: u64 = 30;
/// Streams are cheap but not free (one NATS subscription + a sampler
/// each); a corridor has a handful of displays, not a fleet of them.
const MAX_STREAMS: usize = 32;

static OPEN_STREAMS: AtomicUsize = AtomicUsize::new(0);

/// Counts a stream open for its lifetime; the drop is what closes it, so
/// a client that vanishes mid-read still releases its slot.
struct StreamSlot;
impl Drop for StreamSlot {
    fn drop(&mut self) {
        let n = OPEN_STREAMS.fetch_sub(1, Ordering::SeqCst) - 1;
        tracing::info!(open = n, "kiosk_stream_closed");
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// One event on the wire: `id:` monotonic per connection, `event:` the
/// kind, `data:` a JSON object that always carries `ts`.
fn sse_event(id: u64, kind: &str, mut data: Map<String, Value>) -> Event {
    data.entry("ts").or_insert_with(|| json!(now_rfc3339()));
    Event::default()
        .id(id.to_string())
        .event(kind)
        .data(Value::Object(data).to_string())
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        other => {
            let mut m = Map::new();
            m.insert("payload".into(), other);
            m
        }
    }
}

/// `GET /api/events/stream` — system state as server-sent events, for an
/// unattended display (the design mechanism 3; the vocabulary is
/// pai-mesh-ui `contracts/proposed/api-events-stream.json`).
///
/// SSE and not a socket: unidirectional by protocol, so a read-only
/// credential holds without policing message types; a plain GET, so the
/// bearer travels in the header and passes mechanism 1 unchanged.
///
/// Wire: `Accept: text/event-stream`. `hello {keepalive_ms}` once per
/// connection, then a `: keepalive` comment every `keepalive_ms` — the
/// gap, not the absence of change, is what tells the client the stream
/// died. Every event carries `id:` and `event:`; `data:` is a JSON object
/// with `ts` (RFC 3339). Events: `node.state` {node_id, hostname, status,
/// previous} · `gpu.sample` {node_id, hostname, index, name, utilization,
/// memory_used, memory_total, temperature} · `job.state` {job_id, type?,
/// status, node_id?, error?} · `scheduler.state` {running, paused,
/// queue_depth, active_jobs} · `heartbeat.task` {task, ok, error?} ·
/// `graph.delta` {entities_added, edges_added}.
///
/// `Last-Event-ID` is accepted and IGNORED. A uniform replay would be a
/// lie: `job.state` is sourced from NATS and could replay, but the
/// sampled kinds are read out of live state and cannot, so honouring the
/// header would paint a stale-but-plausible frame instead of an obviously
/// reconnecting one. The client re-fetches the contracted GETs on every
/// connect, which already requires.
///
/// Connect-time state is NOT on the stream — fetch `/api/cluster/status`,
/// `/api/cluster/gpu-metrics`, `/api/jobs`, `/api/scheduler/status`,
/// `/api/heartbeat/status`, `/api/memory/health`, `/api/v1/rag/status`
/// once per connection (or their `/api/kiosk/*` projections).
async fn events_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(last) = headers.get("last-event-id").and_then(|v| v.to_str().ok()) {
        tracing::debug!(last_event_id = %last, "kiosk_stream_resume_ignored");
    }
    let open = OPEN_STREAMS.fetch_add(1, Ordering::SeqCst) + 1;
    if open > MAX_STREAMS {
        OPEN_STREAMS.fetch_sub(1, Ordering::SeqCst);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {"type": "too_many_streams",
                "message": format!("at most {MAX_STREAMS} event streams may be open")}})),
        )
            .into_response();
    }
    tracing::info!(open, "kiosk_stream_opened");

    let jobs = state.nats.subscribe("events.job.>").await.ok();
    if jobs.is_none() {
        tracing::warn!("kiosk_stream: could not subscribe events.job.> — job.state will not be emitted");
    }

    // A producer task feeds a bounded channel; the response is the
    // receiver. When the client goes away the receiver drops, the next
    // send fails, the task returns and its `StreamSlot` releases the
    // count — no explicit disconnect handling needed.
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(64);
    tokio::spawn(async move {
        let _slot = StreamSlot;
        let mut next_id: u64 = 0;
        let mut id = move || { next_id += 1; next_id };

        let mut hello = Map::new();
        hello.insert("keepalive_ms".into(), json!(KEEPALIVE_MS));
        if tx.send(sse_event(id(), "hello", hello)).await.is_err() { return; }

        let mut sampler = Sampler::default();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(SAMPLE_SECS));
        let mut graph_tick = tokio::time::interval(std::time::Duration::from_secs(GRAPH_SAMPLE_SECS));
        // The first tick of an interval fires immediately; prime the
        // baseline so the first sample announces nothing the snapshot did
        // not already say.
        tick.tick().await;
        graph_tick.tick().await;
        sampler.prime(&state).await;

        let mut jobs = jobs;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    for (kind, data) in sampler.sample(&state).await {
                        if tx.send(sse_event(id(), kind, data)).await.is_err() { return; }
                    }
                }
                _ = graph_tick.tick() => {
                    if let Some(data) = sampler.sample_graph(&state).await {
                        if tx.send(sse_event(id(), "graph.delta", data)).await.is_err() { return; }
                    }
                }
                msg = async {
                    match jobs.as_mut() {
                        Some(sub) => tokio_stream::StreamExt::next(sub).await,
                        None => std::future::pending().await,
                    }
                } => {
                    match msg {
                        Some(m) => {
                            if let Some(data) = job_state_from(&m.subject, &m.payload) {
                                if tx.send(sse_event(id(), "job.state", data)).await.is_err() { return; }
                            }
                        }
                        None => { jobs = None; }
                    }
                }
                _ = tx.closed() => { return; }
            }
        }
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(Ok::<Event, std::convert::Infallible>);

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_millis(KEEPALIVE_MS))
                .text("keepalive"),
        )
        .into_response()
}

/// `events.job.<kind>[.<node>]` + the Go agent's `{job_id, error?, ...}`
/// → a `job.state` event. `cancel` is a scheduler→node instruction, but to
/// a display it is still the job leaving the board, so it is mapped.
fn job_state_from(subject: &str, payload: &[u8]) -> Option<Map<String, Value>> {
    let rest = subject.strip_prefix("events.job.")?;
    let (kind, node_from_subject) = match rest.split_once('.') {
        None => (rest, None),
        Some((k, n)) => (k, Some(n)),
    };
    let status = match kind {
        "ack" => "running",
        "complete" => "completed",
        "failed" => "failed",
        "cancel" => "cancelled",
        _ => return None,
    };
    let body: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
    let job_id = body.get("job_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;
    let mut m = Map::new();
    m.insert("job_id".into(), json!(job_id));
    m.insert("status".into(), json!(status));
    if let Some(t) = body.get("type").or_else(|| body.get("job_type")).and_then(|v| v.as_str()) {
        m.insert("type".into(), json!(t));
    }
    if let Some(n) = body.get("node_id").and_then(|v| v.as_str()).or(node_from_subject) {
        m.insert("node_id".into(), json!(n));
    }
    if let Some(e) = body.get("error").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        m.insert("error".into(), json!(e));
    }
    Some(m)
}

/// The sampled kinds, with the last-seen state that makes "emit on
/// change" possible. Everything here goes through the same handler fns
/// the general routes use, so a sample can never say more than the route.
#[derive(Default)]
struct Sampler {
    nodes: std::collections::HashMap<String, String>,
    scheduler: Option<(bool, bool)>,
    tasks: std::collections::HashMap<String, bool>,
    graph: Option<(i64, i64)>,
    primed: bool,
}

impl Sampler {
    async fn prime(&mut self, state: &Arc<AppState>) {
        let _ = self.sample(state).await;
        let _ = self.sample_graph(state).await;
        self.primed = true;
    }

    async fn sample(&mut self, state: &Arc<AppState>) -> Vec<(&'static str, Map<String, Value>)> {
        let mut out = Vec::new();

        // node.state — on change only.
        let full = super::cluster::cluster_status(State(state.clone())).await.0;
        if let Some(nodes) = full.get("nodes").and_then(|v| v.as_array()) {
            for n in nodes {
                let Some(idv) = n.get("id").and_then(|v| v.as_str()) else { continue };
                let status = n.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let prev = self.nodes.insert(idv.to_string(), status.clone());
                if self.primed && prev.as_deref() != Some(status.as_str()) {
                    let mut m = Map::new();
                    m.insert("node_id".into(), json!(idv));
                    m.insert("hostname".into(), n.get("hostname").cloned().unwrap_or(json!(idv)));
                    m.insert("status".into(), json!(status));
                    m.insert("previous".into(), json!(prev.unwrap_or_else(|| "unknown".into())));
                    out.push(("node.state", m));
                }
            }
        }

        if !self.primed {
            // Baseline only; nothing below is change-detected on the first pass.
            let sched = super::admin::scheduler_status(State(state.clone())).await.0;
            self.scheduler = scheduler_pair(&sched);
            if let Ok(hb) = super::intelligence::heartbeat_status(State(state.clone())).await {
                for (task, ok, _) in heartbeat_tasks(&hb.0) { self.tasks.insert(task, ok); }
            }
            return out;
        }

        // gpu.sample — every sample, one event per GPU.
        let gpus = super::cluster::cluster_gpu_metrics(State(state.clone())).await.0;
        if let Some(list) = gpus.get("gpus").and_then(|v| v.as_array()) {
            for g in list {
                let m = obj(pick(g, &[
                    "node_id", "hostname", "index", "name",
                    "utilization", "memory_used", "memory_total", "temperature",
                ]));
                out.push(("gpu.sample", m));
            }
        }

        // scheduler.state — on change of running/paused.
        let sched = super::admin::scheduler_status(State(state.clone())).await.0;
        let pair = scheduler_pair(&sched);
        if pair.is_some() && pair != self.scheduler {
            self.scheduler = pair;
            out.push(("scheduler.state", obj(pick(&sched, &["running", "paused", "queue_depth", "active_jobs"]))));
        }

        // heartbeat.task — per task, on change of ok. The heartbeat exposes
        // per-task `last_run`/`enabled`, not a per-run verdict; "ok" here
        // is "enabled and its last run did not record an error", which is
        // the best the status route can say today.
        if let Ok(hb) = super::intelligence::heartbeat_status(State(state.clone())).await {
            for (task, ok, error) in heartbeat_tasks(&hb.0) {
                let prev = self.tasks.insert(task.clone(), ok);
                if prev != Some(ok) {
                    let mut m = Map::new();
                    m.insert("task".into(), json!(task));
                    m.insert("ok".into(), json!(ok));
                    if let Some(e) = error { m.insert("error".into(), json!(e)); }
                    out.push(("heartbeat.task", m));
                }
            }
        }
        out
    }

    /// `graph.delta` — positive deltas of the entity and edge counts,
    /// from the same query `/api/v1/rag/status` runs. `clusters` is
    /// deliberately absent: community detection is an Intelligent-tier
    /// capability and `member_count` moves on a recluster, not on an
    /// ingest (see the x-gateway answer on the proposed contract).
    async fn sample_graph(&mut self, state: &Arc<AppState>) -> Option<Map<String, Value>> {
        let rag = super::knowledge::rag_status(State(state.clone())).await.ok()?.0;
        let entities = rag.get("entity_count").and_then(|v| v.as_i64())?;
        let edges = rag.get("edge_count").and_then(|v| v.as_i64())?;
        let prev = self.graph.replace((entities, edges));
        let (pe, pd) = prev?;
        if !self.primed { return None; }
        let (de, dd) = (entities - pe, edges - pd);
        if de <= 0 && dd <= 0 { return None; }
        let mut m = Map::new();
        m.insert("entities_added".into(), json!(de.max(0)));
        m.insert("edges_added".into(), json!(dd.max(0)));
        Some(m)
    }
}

fn scheduler_pair(v: &Value) -> Option<(bool, bool)> {
    let running = v.get("running").and_then(|x| x.as_bool())?;
    // A null `paused` is "Redis was not readable", not "not paused": no pair,
    // so no `scheduler.state` event is invented from it.
    let paused = v.get("paused").and_then(|x| x.as_bool())?;
    Some((running, paused))
}

/// (task name, ok, error) per heartbeat task, from `/api/heartbeat/status`.
fn heartbeat_tasks(v: &Value) -> Vec<(String, bool, Option<String>)> {
    let Some(tasks) = v.get("tasks").and_then(|t| t.as_array()) else { return Vec::new() };
    tasks.iter().filter_map(|t| {
        let name = t.get("name").and_then(|n| n.as_str())
            .or_else(|| t.get("id").and_then(|n| n.as_str()))?;
        let enabled = t.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        let error = t.get("last_error").or_else(|| t.get("error"))
            .and_then(|e| e.as_str()).filter(|s| !s.is_empty()).map(str::to_string);
        Some((name.to_string(), enabled && error.is_none(), error))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retired KEY lane stays retired: `/api/kiosk/token` is not a
    /// route (so the router 404s it and the middleware admits no key for
    /// it), and the tailnet lane is the one mint. Read from the source
    /// because the router cannot be listed without a live state; the
    /// Python guard (`tests/test_mcp_token_and_kiosk_key_lane_retired.py`) checks the
    /// same thing across the whole router tree.
    #[test]
    fn kiosk_key_lane_is_not_routed() {
        let src = include_str!("kiosk.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let key_lane = ["\"/api/kiosk/", "token\""].concat();
        assert!(!code.contains(&key_lane), "the kiosk KEY lane is routed again");
        assert!(code.contains("\"/api/kiosk/token/tailnet\""), "the tailnet lane is gone");
        let key_extractor = ["Extension<", "Consumer>"].concat();
        assert!(!code.contains(&key_extractor), "a kiosk handler takes a service-key Consumer again");
    }


    // ── mechanism 3 ──

    #[test]
    fn a_job_event_maps_to_a_job_state_with_the_node_from_the_subject() {
        let m = job_state_from("events.job.failed.host9", br#"{"job_id":"j1","error":"oom"}"#).unwrap();
        assert_eq!(m["job_id"], "j1");
        assert_eq!(m["status"], "failed");
        assert_eq!(m["node_id"], "host9");
        assert_eq!(m["error"], "oom");
    }

    #[test]
    fn a_job_event_without_an_id_or_of_an_unknown_kind_is_dropped() {
        assert!(job_state_from("events.job.ack", br#"{}"#).is_none());
        assert!(job_state_from("events.job.whatever", br#"{"job_id":"j1"}"#).is_none());
        assert!(job_state_from("events.cluster.registered", br#"{"job_id":"j1"}"#).is_none());
    }

    #[test]
    fn every_event_carries_a_ts_and_the_ids_are_the_callers() {
        let ev = sse_event(7, "hello", Map::new());
        // `Event` exposes no getters; its Debug form shows the framed bytes.
        let s = format!("{:?}", ev);
        assert!(s.contains("id: 7"), "{s}");
        assert!(s.contains("event: hello"), "{s}");
        assert!(s.contains("ts"), "a data object with no ts was sent: {s}");
    }

    #[test]
    fn heartbeat_tasks_read_ok_from_enabled_and_no_error() {
        let v = json!({"tasks": [
            {"name": "digest", "enabled": true},
            {"name": "prune", "enabled": true, "last_error": "boom"},
            {"id": "t3", "enabled": false},
        ]});
        let got = heartbeat_tasks(&v);
        assert_eq!(got[0], ("digest".into(), true, None));
        assert_eq!(got[1], ("prune".into(), false, Some("boom".into())));
        assert_eq!(got[2], ("t3".into(), false, None));
    }

    #[test]
    fn pick_keeps_only_named_fields() {
        let full = json!({"id": "n1", "hostname": "a", "cert_not_after": "2027-01-01", "vram_gb": 24});
        let out = pick(&full, &["id", "hostname"]);
        assert_eq!(out, json!({"id": "n1", "hostname": "a"}));
    }

    #[test]
    fn pick_does_not_null_fill_absent_fields() {
        // "the source did not say" must not become "known to be unset".
        let out = pick(&json!({"id": "n1"}), &["id", "tier"]);
        assert_eq!(out, json!({"id": "n1"}));
        assert!(out.get("tier").is_none());
    }

    #[test]
    fn pick_recurses_into_a_list() {
        let full = json!([{"id": "a", "secret": 1}, {"id": "b", "secret": 2}]);
        assert_eq!(pick(&full, &["id"]), json!([{"id": "a"}, {"id": "b"}]));
    }

    #[test]
    fn a_missing_list_key_is_empty_not_absent() {
        assert_eq!(pick_from(&json!({}), "nodes", &["id"]), json!([]));
    }

    /// The projection that matters: no `name` without the flag.
    ///
    /// Tightened when the view moved to the entity level, because what is
    /// being withheld got more sensitive, not less. A cluster name was an
    /// LLM's summary of an area; an entity name is a person, a document, a
    /// customer. `rel_type` joins it — "employs" or "diagnosed_with"
    /// between two opaque ids still describes what is known.
    ///
    /// Asserted through the exact field lists `graph()` uses, not through
    /// a copy of them, so editing the handler is what this test reads.
    /// 160 nodes came back with 4,570 edges between them on the live
    /// display — average degree 57. That is a hairball no one can read and
    /// 4,570 strokes a frame to draw it, which is why the governor parked
    /// the screen in its cheapest tier and stayed there. The node cap was
    /// enforced; nothing capped edges.
    #[test]
    fn edges_are_capped_without_orphaning_a_node() {
        // 40 nodes, every pair joined: 780 edges, confidence descending.
        let mut edges = Vec::new();
        let mut c = 1.0_f64;
        for a in 0..40 {
            for b in (a + 1)..40 {
                c -= 0.001;
                edges.push(json!({"src": format!("n{a}"), "dst": format!("n{b}"), "rel_type": "R", "confidence": c}));
            }
        }
        assert_eq!(edges.len(), 780);

        let kept = prune_edges(&edges, 3, 200);
        assert!(kept.len() <= 200, "cap ignored: {}", kept.len());
        assert!(kept.len() >= 40, "pruned so hard the graph is dust: {}", kept.len());

        // Every node that had an edge still has one, or the display shows
        // dots with nothing joining them.
        let mut seen = std::collections::BTreeSet::new();
        for e in &kept {
            seen.insert(e["src"].as_str().unwrap().to_string());
            seen.insert(e["dst"].as_str().unwrap().to_string());
        }
        for n in 0..40 {
            assert!(seen.contains(&format!("n{n}")), "n{n} was orphaned by the prune");
        }

        // The strongest edge survives; confidence is the ranking.
        let best = kept.iter().map(|e| e["confidence"].as_f64().unwrap()).fold(f64::MIN, f64::max);
        assert!((best - 0.999).abs() < 1e-9, "the highest-confidence edge was dropped: {best}");
    }

    /// Under the cap, nothing is touched: a sparse graph must not be
    /// silently thinned.
    #[test]
    fn a_sparse_graph_passes_through_whole() {
        let edges: Vec<Value> = (0..12)
            .map(|i| json!({"src": format!("a{i}"), "dst": format!("b{i}"), "confidence": 0.5}))
            .collect();
        assert_eq!(prune_edges(&edges, 3, 200).len(), 12);
    }

    #[test]
    fn entity_names_are_off_the_wire_by_default() {
        // A realistic row: the general route always returns the name, and
        // the withholding happens HERE.
        let nodes = json!([
            {"id": "6f1a…-uuid", "name": "Dr Alice Marchetti", "type": "person", "degree": 9}
        ]);
        let edges = json!([
            {"src": "6f1a…-uuid", "dst": "b2c3…-uuid", "rel_type": "diagnosed_with", "confidence": 0.9}
        ]);

        let bare_nodes = pick(&nodes, &["id", "type", "degree"]);
        let bare_edges = pick(&edges, &["src", "dst"]);
        assert_eq!(
            bare_nodes,
            json!([{"id": "6f1a…-uuid", "type": "person", "degree": 9}])
        );
        for forbidden in ["Marchetti", "Alice", "diagnosed_with", "confidence"] {
            let wire = format!("{bare_nodes}{bare_edges}");
            assert!(
                !wire.contains(forbidden),
                "{forbidden} is on the wire to a hallway display: {wire}"
            );
        }

        // And the opt-in still works, or the flag would be decorative.
        let named = pick(&nodes, &["id", "name", "type", "degree"]);
        let typed = pick(&edges, &["src", "dst", "rel_type"]);
        assert!(named.to_string().contains("Marchetti"));
        assert!(typed.to_string().contains("diagnosed_with"));
        // `confidence` is superfluous rather than sensitive, and is
        // dropped either way — the display draws a line, not a score.
        assert!(!typed.to_string().contains("confidence"));
    }

    /// A realistic answer from the general route: it always carries names.
    fn named_overview() -> Value {
        json!({
            "nodes": [{"id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "name": "Dr Alice Marchetti",
                       "type": "person", "degree": 9}],
            "edges": [{"src": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
                       "dst": "b2c3d4e5-0000-4000-8000-000000000000",
                       "rel_type": "diagnosed_with", "confidence": 0.9}],
            "stats": {"node_count": 1, "edge_count": 1},
        })
    }

    /// Switch off: no name, no relation type, and the page is told so.
    #[test]
    fn with_labels_off_the_projection_withholds_names_and_says_so() {
        let out = project_graph(&named_overview(), false);
        assert_eq!(out["labels"], json!(false));
        let wire = out.to_string();
        for forbidden in ["Marchetti", "diagnosed_with", "rel_type", "\"name\""] {
            assert!(!wire.contains(forbidden), "{forbidden} reached a hallway display: {wire}");
        }
        assert_eq!(out["nodes"][0]["degree"], json!(9), "the structure must still be sent");
    }

    /// Switch on: names and relation types, and `labels: true` so the page
    /// shows LABELS ON.
    #[test]
    fn with_labels_on_the_projection_reveals_names_and_says_so() {
        let out = project_graph(&named_overview(), true);
        assert_eq!(out["labels"], json!(true));
        assert_eq!(out["nodes"][0]["name"], json!("Dr Alice Marchetti"));
        assert_eq!(out["edges"][0]["rel_type"], json!("diagnosed_with"));
        assert!(!out.to_string().contains("confidence"), "a score is not drawn, so it is not sent");
    }

    /// The decision is the controller's setting alone: off with no row,
    /// on/off as the row says, live — the very next read, no restart —
    /// and neither the retired env var nor anything the page could send
    /// turns it on. One test, because the override cache is process-wide
    /// and two tests flipping the same key would race.
    #[test]
    fn labels_follow_the_controller_setting_live_and_nothing_else() {
        let key = crate::routes::settings::KIOSK_GRAPH_LABELS;
        crate::settings::remove_override(key);
        std::env::remove_var("NOO_KIOSK_GRAPH_LABELS");
        assert!(!graph_labels_on(), "names are on with no setting at all");

        // The retired switch is ignored.
        std::env::set_var("NOO_KIOSK_GRAPH_LABELS", "1");
        assert!(!graph_labels_on(), "the retired env var still turns names on");
        std::env::remove_var("NOO_KIOSK_GRAPH_LABELS");

        // What `settings_flags_set` does after its DB write: no restart, no
        // wait for the 15 s reload.
        crate::settings::set_override(key, "1");
        assert!(graph_labels_on(), "turning the setting on did not take effect");
        crate::settings::set_override(key, "0");
        assert!(!graph_labels_on(), "turning the setting off did not take effect");

        crate::settings::remove_override(key);
        assert!(!graph_labels_on());
    }

    /// The handler takes no query at all: no parameter a kiosk token could
    /// add widens its read. `?labels=1` is gone from the signature, so a
    /// future one has to be added on purpose — and this says why not.
    #[test]
    fn the_graph_handler_reads_nothing_from_the_request() {
        let src = include_str!("kiosk.rs");
        let sig = src
            .split("async fn graph(")
            .nth(1)
            .and_then(|r| r.split(')').next())
            .expect("graph handler not found — this guard is stale");
        assert!(!sig.contains("Query"), "the kiosk graph handler reads the query string again: {sig}");
    }

    /// Withholding `name` only helps if the `id` is not the name.
    ///
    /// The entity id is a UUID — `entity_id::text` off a uuid column, see
    /// `repo::graph::top_entities_by_degree`. If it ever became the
    /// canonical name, every guard above would still pass while the wall
    /// displayed the contents of the knowledge base. So assert the shape
    /// of what the projection keeps, not just what it drops.
    #[test]
    fn the_id_the_display_gets_is_not_the_entity_name() {
        let row = json!([{"id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
                          "name": "Dr Alice Marchetti", "type": "person", "degree": 9}]);
        let out = pick(&row, &["id", "type", "degree"]);
        let id = out[0]["id"].as_str().expect("the projection kept no id");
        assert_ne!(id, "Dr Alice Marchetti");
        assert!(
            id.len() == 36 && id.matches('-').count() == 4 && !id.contains(' '),
            "the entity id is no longer a UUID ({id}) — withholding `name` \
             protects nothing if the id carries it"
        );
    }

    /// A field added upstream must not reach the display by default.
    #[test]
    fn a_new_upstream_field_does_not_flow_through() {
        let full = json!({"nodes": [{"id": "n1", "newly_added_secret": "x"}]});
        let out = pick_from(&full, "nodes", &["id", "hostname", "status", "running_backends", "tier"]);
        assert!(!out.to_string().contains("newly_added_secret"));
    }
}
