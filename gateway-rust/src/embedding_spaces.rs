// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Embedding spaces (proposal i145, phase B): one embedding MODEL per named
//! purpose, recorded in the DB.
//!
//! Vectors are only comparable within one model. Mixing two in one index
//! raises no error; retrieval just gets quietly worse, and only a full
//! re-embed undoes it. So an embed request never falls back across models
//! the way chat falls back across the mesh. The unit that may not mix is a
//! **space**: `knowledge` (trellion's documents, memory, recall) is the
//! first; a `code` space with its own embedder can sit beside it (operator,
//! 2026-10-19: "embedding pool 1 for knowledge work but then embedding pool
//! 2 for coding work which each use a different embedder").
//!
//! * A space's POOL is every node that advertises its model (the role=embed
//!   placement, reported in the heartbeat). Joining is advertising; there is
//!   no registration step. The gateway spreads a space's requests across its
//!   pool and never sends them to a node on another model.
//! * Callers name the space (`knowledge`), never the model. `default`, blank
//!   or absent is [`DEFAULT_SPACE`]. A caller still sending the space's MODEL
//!   name (older clients send `harrier`) lands in that space.
//! * The record replaces the old majority vote in
//!   `embedding_client::consistent_candidates`, under which two of three
//!   nodes moving to another model flipped the fleet's model silently.
//! * Changing a space's model is a re-embed, not a setting: the PUT refuses
//!   it. A new purpose is a new space.
//!
//! Seeded once, on the first boot that has the table empty: `knowledge` =
//! the model the role=embed placements declare (most common), else the
//! configured one (`PAGEINDEX_EMBEDDING_MODEL` → `EMBEDDING_MODEL` →
//! `TEI_MODEL` → `harrier`). After that those env vars are not read for
//! routing; a value that disagrees with the record is logged at boot.

use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use serde::Serialize;

/// The space an unqualified embed request means.
pub const DEFAULT_SPACE: &str = "knowledge";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Space {
    pub space: String,
    pub model: String,
    /// Expected vector width; `None` = learn it from the first answer.
    pub dims: Option<u64>,
}

static SPACES: OnceLock<RwLock<Vec<Space>>> = OnceLock::new();

fn cache() -> &'static RwLock<Vec<Space>> {
    SPACES.get_or_init(|| RwLock::new(Vec::new()))
}

/// Every space this gateway knows, from the 15 s cache.
pub fn all() -> Vec<Space> {
    cache().read().map(|v| v.clone()).unwrap_or_default()
}

/// Replace the cache (the refresher, a write route, tests).
pub fn set_cache(spaces: Vec<Space>) {
    if let Ok(mut w) = cache().write() {
        *w = spaces;
    }
}

/// Same model modulo case and ollama's implicit `:latest` tag.
pub fn same_model(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().to_lowercase().trim_end_matches(":latest").to_string();
    norm(a) == norm(b)
}

/// What a caller's `model` field means: `Ok(space)` or `Err(message)` naming
/// the spaces there are. `None`, blank, `default` and `auto` are the default
/// space; a space name wins over a model name; a space's model name is that
/// space.
pub fn resolve<'a>(spaces: &'a [Space], requested: Option<&str>) -> Result<&'a Space, String> {
    let name = requested.map(str::trim).filter(|s| !s.is_empty());
    let name = match name {
        None => DEFAULT_SPACE,
        Some(n) if n.eq_ignore_ascii_case("default") || n.eq_ignore_ascii_case("auto") => DEFAULT_SPACE,
        Some(n) => n,
    };
    if let Some(s) = spaces.iter().find(|s| s.space.eq_ignore_ascii_case(name)) {
        return Ok(s);
    }
    if let Some(s) = spaces.iter().find(|s| same_model(&s.model, name)) {
        return Ok(s);
    }
    Err(format!(
        "'{name}' is not an embedding space or a space's model; spaces: {}",
        listing(spaces)
    ))
}

/// `knowledge=harrier, code=…` for messages.
pub fn listing(spaces: &[Space]) -> String {
    if spaces.is_empty() {
        return "none declared".into();
    }
    spaces.iter().map(|s| format!("{}={}", s.space, s.model)).collect::<Vec<_>>().join(", ")
}

/// Why an embed placement of `model` is refused, if it is: every embed node
/// serves a space's model, so a model no space uses would serve nobody (or,
/// worse, be mistaken for one). `None` = allowed. With no spaces recorded
/// (before the first boot seeds one) nothing is refused.
pub fn placement_refusal(spaces: &[Space], model: &str) -> Option<String> {
    if spaces.is_empty() || spaces.iter().any(|s| same_model(&s.model, model)) {
        return None;
    }
    Some(format!(
        "no embedding space uses model '{model}' (spaces: {}). Every embedding node serves its space's model, \
         so vectors stay comparable. To embed with '{model}' for another purpose, declare a space for it first: \
         noo cluster embedding-space set <space> {model}",
        listing(spaces)
    ))
}

/// A space or model name: the class-name charset, 1..=64 chars.
pub fn valid_space_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 64 {
        return Err("a space name is 1-64 characters".into());
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(format!("'{n}' has characters outside [A-Za-z0-9._-]"));
    }
    if n.eq_ignore_ascii_case("default") || n.eq_ignore_ascii_case("auto") {
        return Err(format!("'{n}' means the default space ({DEFAULT_SPACE}) and cannot be declared"));
    }
    Ok(())
}

/// What a PUT may do to an existing space: the same model (dims may be
/// filled in) is fine; another model is a re-embed and is refused.
pub fn change_refusal(existing: Option<&Space>, model: &str) -> Option<String> {
    let e = existing?;
    if same_model(&e.model, model) {
        return None;
    }
    Some(format!(
        "space '{}' embeds with '{}'; switching it to '{model}' would mix two models' vectors in its indexes. \
         Changing a space's model is a re-embed (not built yet), not a setting. Declare a new space for '{model}' instead.",
        e.space, e.model
    ))
}

/// The most common model among role=embed placements (ties: first seen),
/// or `fallback`. The seed for `knowledge` on an empty table.
pub fn seed_model(placement_models: &[String], fallback: &str) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for m in placement_models.iter().filter(|m| !m.trim().is_empty()) {
        match counts.iter_mut().find(|(k, _)| same_model(k, m)) {
            Some((_, n)) => *n += 1,
            None => counts.push((m.clone(), 1)),
        }
    }
    counts
        .iter()
        .fold(None::<&(String, usize)>, |best, c| match best {
            Some(b) if b.1 >= c.1 => Some(b),
            _ => Some(c),
        })
        .map(|(m, _)| m.clone())
        .unwrap_or_else(|| fallback.to_string())
}

pub async fn load(db: &sqlx::PgPool) -> Result<Vec<Space>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, Option<i32>)>(
        "SELECT space, model, dims FROM noo_embedding_spaces ORDER BY space",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(space, model, dims)| Space { space, model, dims: dims.filter(|d| *d > 0).map(|d| d as u64) })
        .collect())
}

pub async fn upsert(db: &sqlx::PgPool, s: &Space, by: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_embedding_spaces (space, model, dims, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (space) DO UPDATE SET model = EXCLUDED.model, dims = EXCLUDED.dims, \
         updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(&s.space)
    .bind(&s.model)
    .bind(s.dims.map(|d| d as i32))
    .bind(by)
    .execute(db)
    .await
    .map(|_| ())
}

pub async fn delete(db: &sqlx::PgPool, space: &str) -> Result<bool, sqlx::Error> {
    sqlx::query("DELETE FROM noo_embedding_spaces WHERE space = $1")
        .bind(space)
        .execute(db)
        .await
        .map(|r| r.rows_affected() > 0)
}

/// Seed `knowledge` when the table is empty. Idempotent (`ON CONFLICT DO
/// NOTHING`), so two gateways booting together seed once.
async fn seed_if_empty(db: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_embedding_spaces").fetch_one(db).await?;
    if n > 0 {
        return Ok(());
    }
    let models: Vec<String> = sqlx::query_scalar(
        "SELECT model FROM noo_backend_placements WHERE role = 'embed' AND model IS NOT NULL AND model <> ''",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let configured = crate::embedding_client::configured_model();
    let model = seed_model(&models, &configured);
    let dims = crate::config::env_or_yaml_u64("EMBEDDING_DIM", |c| c.services.embedding_dim, 0);
    let res = sqlx::query(
        "INSERT INTO noo_embedding_spaces (space, model, dims, updated_by, updated_at) \
         VALUES ($1, $2, $3, 'seed', now()) ON CONFLICT (space) DO NOTHING",
    )
    .bind(DEFAULT_SPACE)
    .bind(&model)
    .bind((dims > 0).then_some(dims as i32))
    .execute(db)
    .await?;
    if res.rows_affected() > 0 {
        tracing::info!(
            space = DEFAULT_SPACE, model = %model, dims,
            source = if models.is_empty() { "configured" } else { "placements" },
            "embedding_space_seeded"
        );
    }
    Ok(())
}

/// Seed, then keep the cache warm (every 15 s, like `settings`). A failed
/// reload keeps the previous spaces and is logged once per failure streak.
pub fn spawn_refresh(db: sqlx::PgPool) {
    tokio::spawn(async move {
        if let Err(e) = seed_if_empty(&db).await {
            tracing::warn!(error = %e, "embedding_space_seed_failed: embeds use the configured model until a space is recorded");
        }
        let mut warned_env = false;
        let mut failing: u64 = 0;
        loop {
            match load(&db).await {
                Ok(spaces) => {
                    if failing > 0 {
                        tracing::info!(failed_reloads = failing, "embedding_spaces_refresh_recovered");
                        failing = 0;
                    }
                    if !warned_env {
                        warned_env = true;
                        warn_env_disagrees(&spaces);
                    }
                    set_cache(spaces);
                }
                Err(e) => {
                    if failing == 0 {
                        tracing::warn!(error = %e, "embedding_spaces_refresh_failed: keeping the previous spaces");
                    }
                    failing += 1;
                }
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

/// Decision 4 of i145: an env var that once chose the embed model is
/// ignored after the seed, and says so once when it disagrees.
fn warn_env_disagrees(spaces: &[Space]) {
    let Ok(knowledge) = resolve(spaces, None) else { return };
    for var in ["PAGEINDEX_EMBEDDING_MODEL", "EMBEDDING_MODEL", "TEI_MODEL"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() && !same_model(&v, &knowledge.model) {
                tracing::warn!(
                    var, value = %v, space = %knowledge.space, model = %knowledge.model,
                    "embedding_env_ignored: the embedding space record decides the model, not this variable"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(space: &str, model: &str) -> Space {
        Space { space: space.into(), model: model.into(), dims: None }
    }

    fn two() -> Vec<Space> {
        vec![sp("knowledge", "harrier"), sp("code", "nomic-embed-code")]
    }

    #[test]
    fn a_caller_names_a_space_and_the_default_is_knowledge() {
        let s = two();
        for none in [None, Some(""), Some("default"), Some("AUTO")] {
            assert_eq!(resolve(&s, none).unwrap().space, "knowledge", "{none:?}");
        }
        assert_eq!(resolve(&s, Some("code")).unwrap().model, "nomic-embed-code");
        // An older client sending the model name lands in that model's space.
        assert_eq!(resolve(&s, Some("harrier:latest")).unwrap().space, "knowledge");
        let err = resolve(&s, Some("bge-m3")).unwrap_err();
        assert!(err.contains("knowledge=harrier") && err.contains("code=nomic-embed-code"), "{err}");
    }

    #[test]
    fn an_embed_placement_must_serve_some_spaces_model() {
        let s = two();
        assert_eq!(placement_refusal(&s, "harrier"), None);
        assert_eq!(placement_refusal(&s, "Nomic-Embed-Code:latest"), None);
        let why = placement_refusal(&s, "bge-m3").expect("refused");
        assert!(why.contains("noo cluster embedding-space set <space> bge-m3"), "{why}");
        assert_eq!(placement_refusal(&[], "anything"), None, "nothing recorded yet: nothing to hold it to");
    }

    #[test]
    fn a_spaces_model_does_not_change_by_setting() {
        let k = sp("knowledge", "harrier");
        assert_eq!(change_refusal(Some(&k), "harrier:latest"), None);
        assert_eq!(change_refusal(None, "anything"), None, "a new space is fine");
        let why = change_refusal(Some(&k), "bge-m3").expect("refused");
        assert!(why.contains("re-embed") && why.contains("new space"), "{why}");
    }

    #[test]
    fn the_seed_is_the_most_common_placement_else_the_configured_model() {
        let m = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(seed_model(&m(&["harrier", "bge-m3", "harrier:latest"]), "x"), "harrier");
        assert_eq!(seed_model(&m(&[]), "harrier"), "harrier");
        assert_eq!(seed_model(&m(&["", " "]), "harrier"), "harrier");
    }

    #[test]
    fn names_are_validated_and_default_is_reserved() {
        assert!(valid_space_name("code").is_ok());
        assert!(valid_space_name("knowledge-v2").is_ok());
        assert!(valid_space_name("default").is_err());
        assert!(valid_space_name("a b").is_err());
        assert!(valid_space_name("").is_err());
    }
}
