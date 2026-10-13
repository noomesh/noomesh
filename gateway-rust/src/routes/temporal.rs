// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Routes for the temporal knowledge graph (Phase 1, OSS-safe).
//!
//! Surfaces:
//!   GET  /api/temporal/facts              — current facts for an entity
//!   GET  /api/temporal/evolution          — history of (subject, predicate)
//!   GET  /api/temporal/user-profile/{uid} — convenience: user's current facts
//!   GET  /api/temporal/agent-self         — agent's current self-identity edges
//!   GET  /api/temporal/projects           — recent project decisions
//!
//! Write-side happens via NATS (worker.temporal.extract), not HTTP.
//!
//! ## These tables belong to the trellion add-on
//!
//! `noo_temporal_edges` and `noo_entities_typed` are created by TRELLION's
//! Alembic chain (`100_trellion_squash.py`), not the mesh chain — the mesh
//! chain only ever ALTERs them. So on an install running without the add-on
//! they do not exist, and every handler here would answer a raw Postgres
//! `relation "noo_temporal_edges" does not exist` as a 500.
//!
//! The gateway's trellion gate lives at the NATS boundary
//! (`worker_client::is_trellion_subject`), and these handlers reach the
//! tables directly over SQL, so it never saw them. `refuse_without_trellion`
//! closes that: the documented contract is an explained 503 naming the
//! add-on, so "you do not have this add-on" and "the knowledge plane is
//! broken" stay two different answers to an operator at 3am.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    middleware as axum_mw,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use axum::Extension;
use crate::auth::{scoped_user, ClusterNode, RequesterCtx};

use super::{AppError, AppResult};
use crate::state::AppState;
use crate::temporal_graph;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/temporal/facts", get(facts_for_entity))
        .route("/api/temporal/evolution", get(evolution))
        .route("/api/temporal/user-profile/{user_id}", get(user_profile))
        .route("/api/temporal/agent-self", get(agent_self))
        .route("/api/temporal/projects", get(recent_projects))
        .route("/api/temporal/adaptations", post(write_adaptations))
        // `route_layer`, not `layer`: it runs only for paths this router
        // MATCHES, so an unrelated 404 elsewhere in the gateway is not
        // answered with a trellion refusal.
        .route_layer(axum_mw::from_fn(super::require_trellion))
}

/// Body for POST /api/temporal/adaptations — matches what noo-evolve's
/// graph writer posts.
#[derive(Deserialize)]
struct AdaptationsBody {
    cycle_id: String,
    #[serde(default)]
    adaptations: Vec<Value>,
    #[serde(default)]
    composite_score: Option<f64>,
    #[serde(default)]
    score_delta: Option<f64>,
    #[serde(default)]
    reflection_summary: Option<String>,
}

/// Persist a batch of agent_self self-adaptation edges (write-side of the
/// temporal graph, used by the pro self-tuning loop). Requires write scope.
async fn write_adaptations(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AdaptationsBody>,
) -> AppResult {
    let inserted = temporal_graph::write_adaptations(
        &state.db,
        &body.cycle_id,
        &body.adaptations,
        body.composite_score,
        body.score_delta,
        body.reflection_summary.as_deref(),
    )
    .await
    .map_err(|e| AppError::Internal(format!("graph write failed: {e}")))?;

    Ok(Json(json!({ "inserted": inserted, "cycle_id": body.cycle_id })))
}


/// Refuse a subject entity that belongs to somebody else.
///
/// The temporal graph holds two different kinds of subject and they need two
/// different answers:
///
/// - `type = 'user'` is **per-person data** — the extracted standing facts
///   about one account, keyed by `canonical_name = username`. It is scoped
///   exactly the way `/api/temporal/user-profile/{user_id}` already scopes
///   it: a `User`-tier caller may read its own and nothing else.
/// - every other type (`project`, `topic`, `agent_self`, …) is the **shared
///   brain**. One deployment's knowledge about a project belongs to the
///   deployment, and `MULTI_USER_READINESS.md` states that as the product
///   decision, not an oversight. Those subjects stay global, and this
///   comment says so instead of implying it.
///
/// `403` rather than `404`: the caller named the subject by type and NAME
/// here (or by an id it already holds), so refusing by name confirms
/// nothing it did not supply — and it matches the `user-profile` route,
/// which is the same data through a different door.
async fn scope_entity(
    state: &AppState,
    entity_id: &str,
    requester: Option<&RequesterCtx>,
    cluster: Option<&ClusterNode>,
) -> Result<(), AppError> {
    let Some((etype, name)) = temporal_graph::entity_identity(&state.db, entity_id).await else {
        // The entity vanished between lookup and check; the fact query below
        // will return nothing. Nothing to scope.
        return Ok(());
    };
    if etype != "user" {
        return Ok(());
    }
    // Entity names are normalised (trim + lowercase) by `upsert_entity` and
    // `find_entity_id`; an account name is not. Compare on the normalised
    // form, or an account with a capital letter would be refused its OWN
    // profile — a fail-closed bug, but still a bug.
    let claimed = match requester {
        // The ACCOUNT, not the connection: `owner/laptop` asking for the
        // profile named `owner` is the person asking for their own.
        Some(r) if crate::auth::account_of(r.sub.trim()).to_lowercase() == name => {
            crate::auth::account_of(&r.sub).to_string()
        }
        _ => name,
    };
    scoped_user(requester, cluster, Some(&claimed))
        .map_err(AppError::Forbidden)
        .map(|_| ())
}

#[derive(Deserialize)]
struct FactsParams {
    entity_id: Option<String>,
    entity_type: Option<String>,
    canonical_name: Option<String>,
}

/// Return currently-valid facts for a subject entity.
/// Lookup by ?entity_id=... OR (?entity_type=...&canonical_name=...).
async fn facts_for_entity(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(p): Query<FactsParams>,
) -> AppResult {
    let entity_id = if let Some(id) = p.entity_id {
        id
    } else {
        let etype = p.entity_type.ok_or_else(|| {
            AppError::BadRequest("entity_id OR (entity_type+canonical_name) required".into())
        })?;
        let name = p.canonical_name.ok_or_else(|| {
            AppError::BadRequest("canonical_name required when entity_type given".into())
        })?;
        match temporal_graph::find_entity_id(&state.db, &etype, &name).await {
            Some(id) => id,
            None => return Ok(Json(json!({"facts": [], "entity_id": null}))),
        }
    };

    scope_entity(
        &state,
        &entity_id,
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .await?;

    let facts = temporal_graph::get_current_facts(&state.db, &entity_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    Ok(Json(json!({
        "entity_id": entity_id,
        "facts": facts.iter().map(|f| json!({
            "subject_type": f.subject_type,
            "subject_name": f.subject_name,
            "predicate": f.predicate,
            "object_value": f.object_value,
            "object_entity_name": f.object_entity_name,
            "confidence": f.confidence,
            "valid_from": f.valid_from,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct EvolutionParams {
    entity_id: Option<String>,
    entity_type: Option<String>,
    canonical_name: Option<String>,
    predicate: String,
}

/// Full history of a (subject, predicate), oldest-first.
async fn evolution(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(p): Query<EvolutionParams>,
) -> AppResult {
    let entity_id = if let Some(id) = p.entity_id {
        id
    } else {
        let etype = p.entity_type.ok_or_else(|| {
            AppError::BadRequest("entity_id OR (entity_type+canonical_name) required".into())
        })?;
        let name = p.canonical_name.ok_or_else(|| {
            AppError::BadRequest("canonical_name required when entity_type given".into())
        })?;
        match temporal_graph::find_entity_id(&state.db, &etype, &name).await {
            Some(id) => id,
            None => return Ok(Json(json!({"history": []}))),
        }
    };

    scope_entity(
        &state,
        &entity_id,
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .await?;

    let history = temporal_graph::get_evolution(&state.db, &entity_id, &p.predicate)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    Ok(Json(json!({
        "entity_id": entity_id,
        "predicate": p.predicate,
        "history": history,
    })))
}

/// Convenience: a user's current standing facts.
async fn user_profile(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(user_id): Path<String>,
) -> AppResult {
    // a user's extracted temporal facts are their own.
    scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        Some(&user_id),
    )
    .map_err(AppError::Forbidden)?;
    let entity_id = match temporal_graph::find_entity_id(&state.db, "user", &user_id).await {
        Some(id) => id,
        None => return Ok(Json(json!({"user_id": user_id, "facts": []}))),
    };

    let facts = temporal_graph::get_current_facts(&state.db, &entity_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    Ok(Json(json!({
        "user_id": user_id,
        "entity_id": entity_id,
        "facts": facts.iter().map(|f| json!({
            "predicate": f.predicate,
            "object_value": f.object_value,
            "object_entity_name": f.object_entity_name,
            "confidence": f.confidence,
            "valid_from": f.valid_from,
        })).collect::<Vec<_>>(),
    })))
}

/// Agent's current self-identity edges.
async fn agent_self(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let entity_id = match temporal_graph::find_entity_id(&state.db, "agent_self", "mesh").await {
        Some(id) => id,
        None => return Ok(Json(json!({"facts": []}))),
    };

    let facts = temporal_graph::get_current_facts(&state.db, &entity_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    Ok(Json(json!({
        "entity_id": entity_id,
        "facts": facts.iter().map(|f| json!({
            "predicate": f.predicate,
            "object_value": f.object_value,
            "object_entity_name": f.object_entity_name,
            "confidence": f.confidence,
            "valid_from": f.valid_from,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct ProjectParams {
    limit: Option<u32>,
}

/// Recent project state across all known projects.
async fn recent_projects(
    State(state): State<Arc<AppState>>,
    Query(p): Query<ProjectParams>,
) -> AppResult {
    let limit = p.limit.unwrap_or(20).min(100) as i32;
    let rows: Vec<(String, String, Option<String>, chrono::DateTime<chrono::Utc>, f64)> =
        sqlx::query_as(
            "SELECT s.canonical_name, e.predicate, e.object_value, \
                    e.valid_from, e.confidence \
             FROM noo_temporal_edges e \
             JOIN noo_entities_typed s ON e.subject_id = s.id \
             WHERE s.type = 'project' \
               AND e.valid_to IS NULL \
             ORDER BY e.valid_from DESC \
             LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&state.db)
        .await?;

    let entries: Vec<Value> = rows
        .into_iter()
        .map(|(proj, pred, obj, vf, conf)| {
            json!({
                "project": proj,
                "predicate": pred,
                "object_value": obj,
                "valid_from": vf,
                "confidence": conf,
            })
        })
        .collect();

    Ok(Json(json!({"decisions": entries})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    /// Every path this module serves. The gate is a `route_layer` so it
    /// covers whatever is registered; this list exists so that adding a route
    /// without thinking about the add-on is at least VISIBLE in a diff.
    const TEMPORAL_PATHS: &[&str] = &[
        "/api/temporal/facts",
        "/api/temporal/evolution",
        "/api/temporal/user-profile/{user_id}",
        "/api/temporal/agent-self",
        "/api/temporal/projects",
        "/api/temporal/adaptations",
    ];

    #[test]
    fn the_router_builds_with_the_gate_attached() {
        // axum panics at build time on a malformed path or a duplicate route;
        // this is the check that adding the layer did not break registration.
        let _ = router();
        assert_eq!(TEMPORAL_PATHS.len(), 6);
    }

    #[tokio::test]
    async fn the_refusal_carries_the_three_keys_the_contract_promises() {
        // The failure this guards: these tables belong to trellion's Alembic
        // chain, so without the add-on the handlers hit a relation that does
        // not exist and answer a raw Postgres error as a 500 — which an
        // operator cannot tell apart from a real outage.
        //
        // STRUCTURE here, CONTENT below. The body builder reads live add-on
        // state for its message, and in a test process trellion is enabled
        // (its polarity is opt-out and there is no config), so `refusal_msg`
        // correctly returns "" — an enabled add-on has nothing to refuse.
        // Asserting the message from here would be asserting the test
        // environment, not the contract.
        //
        // Add-ons are declared in the `addons:` map of noomesh.yaml now, so
        // the `NOO_TRELLION_ENABLED` this test used to set controls nothing:
        // it passed only while both changes were in different trees.
        // `crate::addons` owns the gate and tests it.
        let refusal = crate::routes::trellion_refusal_body();
        assert_eq!(refusal.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(refusal.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["addon"], "trellion");
        assert!(v["error"].is_string(), "an `error` key is always present");
        // `state` is what keeps "turned off" apart from "unlicensed".
        assert!(v["state"].is_string());
    }

    #[test]
    fn the_disabled_message_names_the_add_on_to_enable() {
        // The content half: whatever an operator reads has to tell them which
        // add-on to turn on. A refusal that says only "unavailable" sends them
        // to the logs.
        assert!(
            crate::addons::DISABLED_MSG.contains("trellion"),
            "the disabled message must name the add-on: {}",
            crate::addons::DISABLED_MSG
        );
    }
}
