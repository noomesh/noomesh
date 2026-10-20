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
//! * A re-embed into a new model is a MIGRATION recorded on the space (i150):
//!   the gateway holds the state, trellion does the work (it embeds with
//!   `<space>@next` and reports progress), and the model swaps in one UPDATE
//!   once trellion says the cutover is done.
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
    /// A re-embed into `next_model` under way, if any.
    pub migration: Option<Migration>,
}

/// A space's re-embed into another model (i150). `state` is `filling`
/// (trellion embeds every row with `next_model` beside the live vectors) or
/// `cutover` (the operator completed it; trellion swaps the columns, then
/// reports `cutover_done` and the gateway flips the space's model).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Migration {
    pub next_model: String,
    pub next_dims: Option<u64>,
    pub state: String,
    /// trellion's last report: `{"next_model", "tables": {t: {done, total}}}`.
    pub progress: Option<serde_json::Value>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reported_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub const MIGRATION_FILLING: &str = "filling";
pub const MIGRATION_CUTOVER: &str = "cutover";

/// How stale trellion's last progress report may be when the operator
/// completes: older means the worker is not running, and "all done" is a
/// claim from the past.
pub const PROGRESS_FRESH_SECS: i64 = 600;

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
    // A migration's next model is placeable too: the new pool has to exist
    // before the re-embed can fill from it.
    let serves = |s: &Space| {
        same_model(&s.model, model) || s.migration.as_ref().is_some_and(|m| same_model(&m.next_model, model))
    };
    if spaces.is_empty() || spaces.iter().any(serves) {
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
         Changing a space's model is a re-embed, not a setting: noo cluster embedding-space migrate {} {model}. \
         Or declare a new space for '{model}' instead.",
        e.space, e.model, e.space
    ))
}

/// `<space>@next` -> `Some("<space>")`: the form a caller uses to embed with
/// a space's NEXT model during a migration. `None` for any other name.
pub fn parse_next(requested: Option<&str>) -> Option<&str> {
    let r = requested?.trim();
    let cut = r.len().checked_sub("@next".len())?;
    if !r.is_char_boundary(cut) || !r[cut..].eq_ignore_ascii_case("@next") {
        return None;
    }
    Some(r[..cut].trim()).filter(|s| !s.is_empty())
}

/// Why a migration of `space` into `model` cannot start, if it cannot.
/// `None` = fine to probe. The probe and the width check come after.
pub fn start_refusal(spaces: &[Space], space: &str, model: &str) -> Option<String> {
    let Some(s) = spaces.iter().find(|s| s.space == space) else {
        return Some(format!("no embedding space '{space}' (spaces: {})", listing(spaces)));
    };
    if let Some(m) = &s.migration {
        return Some(format!(
            "space '{space}' is already migrating to '{}' ({}); complete or cancel that first: \
             noo cluster embedding-space migrate {space} --complete | --cancel",
            m.next_model, m.state
        ));
    }
    if same_model(&s.model, model) {
        return Some(format!("space '{space}' already embeds with '{model}'"));
    }
    if let Some(o) = spaces.iter().find(|o| o.space != space && (same_model(&o.model, model) || o.migration.as_ref().is_some_and(|m| same_model(&m.next_model, model)))) {
        return Some(format!("space '{}' already uses '{model}': one model, one space", o.space));
    }
    None
}

/// The width trellion's `vector(N)` columns hold when the space records none.
pub const DEFAULT_VECTOR_DIMS: u64 = 1024;

/// A model whose vectors are not the width of the space's columns cannot be
/// migrated into: the columns would have to be retyped.
pub fn dims_refusal(space_dims: Option<u64>, probed: u64) -> Option<String> {
    let want = space_dims.unwrap_or(DEFAULT_VECTOR_DIMS);
    (probed != want).then(|| {
        format!(
            "the new model answers {probed}-dim vectors; trellion's vector columns are vector({want}), and a model of a \
             different width needs the columns retyped, which is not built"
        )
    })
}

/// Why the operator may not complete `space`'s migration yet, if so: it must
/// be filling, trellion's report must be about THIS next model, name at least
/// one table, have every table done == total, and be fresh.
pub fn complete_refusal(s: &Space, now: chrono::DateTime<chrono::Utc>) -> Option<String> {
    let Some(m) = &s.migration else {
        return Some(format!("space '{}' has no migration", s.space));
    };
    if m.state != MIGRATION_FILLING {
        return Some(format!("space '{}' is already in '{}'", s.space, m.state));
    }
    let Some(p) = &m.progress else {
        return Some("trellion has not reported progress yet (is its embedding worker running?)".into());
    };
    if p.get("next_model").and_then(|v| v.as_str()) != Some(m.next_model.as_str()) {
        return Some(format!("trellion's last report is not about '{}'", m.next_model));
    }
    match m.reported_at {
        Some(t) if (now - t).num_seconds() <= PROGRESS_FRESH_SECS => {}
        _ => return Some("trellion's last progress report is more than 10 minutes old".into()),
    }
    let tables = p.get("tables").and_then(|v| v.as_object());
    let Some(tables) = tables.filter(|t| !t.is_empty()) else {
        return Some("trellion's report names no tables".into());
    };
    let behind: Vec<String> = tables
        .iter()
        .filter_map(|(t, v)| {
            let done = v.get("done").and_then(|d| d.as_u64());
            let total = v.get("total").and_then(|d| d.as_u64());
            match (done, total) {
                (Some(d), Some(n)) if d == n => None,
                (Some(d), Some(n)) => Some(format!("{t} {d}/{n}")),
                _ => Some(format!("{t} unreadable")),
            }
        })
        .collect();
    (!behind.is_empty()).then(|| format!("not every table is re-embedded yet: {}", behind.join(", ")))
}

/// What trellion's progress PUT does to the migration.
#[derive(Debug, PartialEq, Eq)]
pub enum ProgressAction {
    /// Store the report (state `filling`, or `cutover` not yet done).
    Store,
    /// `cutover` and `cutover_done`: swap the space to the next model.
    Flip,
}

pub fn progress_action(m: &Migration, cutover_done: bool) -> ProgressAction {
    if m.state == MIGRATION_CUTOVER && cutover_done {
        ProgressAction::Flip
    } else {
        ProgressAction::Store
    }
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
    type Row = (
        String, String, Option<i32>, Option<String>, Option<i32>, Option<String>,
        Option<serde_json::Value>, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>,
    );
    let rows = sqlx::query_as::<_, Row>(
        "SELECT space, model, dims, next_model, next_dims, migration_state, migration_progress, \
         migration_started_at, migration_reported_at FROM noo_embedding_spaces ORDER BY space",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(space, model, dims, next_model, next_dims, state, progress, started_at, reported_at)| Space {
            space,
            model,
            dims: dims.filter(|d| *d > 0).map(|d| d as u64),
            migration: next_model.zip(state).map(|(next_model, state)| Migration {
                next_model,
                next_dims: next_dims.filter(|d| *d > 0).map(|d| d as u64),
                state,
                progress,
                started_at,
                reported_at,
            }),
        })
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

/// Start a migration: only if none is recorded (the WHERE makes two racing
/// starts one winner). `false` = lost the race or no such space.
pub async fn start_migration(db: &sqlx::PgPool, space: &str, next_model: &str, next_dims: u64) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE noo_embedding_spaces SET next_model = $2, next_dims = $3, migration_state = 'filling', \
         migration_progress = NULL, migration_started_at = now(), migration_reported_at = NULL, \
         updated_by = 'operator', updated_at = now() \
         WHERE space = $1 AND migration_state IS NULL",
    )
    .bind(space)
    .bind(next_model)
    .bind(next_dims as i32)
    .execute(db)
    .await
    .map(|r| r.rows_affected() > 0)
}

/// `filling` -> `cutover`. `false` = it was not filling any more.
pub async fn begin_cutover(db: &sqlx::PgPool, space: &str, next_model: &str) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE noo_embedding_spaces SET migration_state = 'cutover', updated_by = 'operator', updated_at = now() \
         WHERE space = $1 AND migration_state = 'filling' AND next_model = $2",
    )
    .bind(space)
    .bind(next_model)
    .execute(db)
    .await
    .map(|r| r.rows_affected() > 0)
}

/// Cancel: clear every migration column. Only while `filling` -- once the
/// cutover has begun trellion is swapping columns and the model must follow.
pub async fn cancel_migration(db: &sqlx::PgPool, space: &str) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE noo_embedding_spaces SET next_model = NULL, next_dims = NULL, migration_state = NULL, \
         migration_progress = NULL, migration_started_at = NULL, migration_reported_at = NULL, \
         updated_by = 'operator', updated_at = now() \
         WHERE space = $1 AND migration_state = 'filling'",
    )
    .bind(space)
    .execute(db)
    .await
    .map(|r| r.rows_affected() > 0)
}

/// Store trellion's report. `false` = the migration is gone or is for another model.
pub async fn store_progress(db: &sqlx::PgPool, space: &str, next_model: &str, progress: &serde_json::Value) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE noo_embedding_spaces SET migration_progress = $3, migration_reported_at = now() \
         WHERE space = $1 AND next_model = $2 AND migration_state IS NOT NULL",
    )
    .bind(space)
    .bind(next_model)
    .bind(progress)
    .execute(db)
    .await
    .map(|r| r.rows_affected() > 0)
}

/// The swap: one UPDATE (so one transaction) sets model = next_model,
/// dims = next_dims and clears every migration column. Every right-hand side
/// reads the OLD row. `false` = not in `cutover` for this model.
pub async fn flip_to_next(db: &sqlx::PgPool, space: &str, next_model: &str) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE noo_embedding_spaces SET model = next_model, dims = next_dims, next_model = NULL, next_dims = NULL, \
         migration_state = NULL, migration_progress = NULL, migration_started_at = NULL, \
         migration_reported_at = NULL, updated_by = 'trellion', updated_at = now() \
         WHERE space = $1 AND migration_state = 'cutover' AND next_model = $2",
    )
    .bind(space)
    .bind(next_model)
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
        Space { space: space.into(), model: model.into(), dims: None, migration: None }
    }

    fn migrating(state: &str, progress: Option<serde_json::Value>, reported_min_ago: Option<i64>) -> (Space, chrono::DateTime<chrono::Utc>) {
        let now = chrono::Utc::now();
        let mut s = sp("knowledge", "harrier");
        s.migration = Some(Migration {
            next_model: "bge-m3".into(),
            next_dims: Some(1024),
            state: state.into(),
            progress,
            started_at: Some(now),
            reported_at: reported_min_ago.map(|m| now - chrono::Duration::minutes(m)),
        });
        (s, now)
    }

    fn report(tables: serde_json::Value) -> Option<serde_json::Value> {
        Some(serde_json::json!({"next_model": "bge-m3", "tables": tables}))
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
        assert!(why.contains("noo cluster embedding-space migrate knowledge bge-m3"), "{why}");
        assert!(!why.contains("not built yet"), "{why}");
    }

    #[test]
    fn a_migrations_next_model_may_be_placed() {
        let (s, _) = migrating("filling", None, None);
        assert_eq!(placement_refusal(&[s.clone()], "BGE-M3:latest"), None);
        assert!(placement_refusal(&[s], "other").is_some());
    }

    #[test]
    fn migration_serializes_into_the_listing() {
        let (s, _) = migrating("filling", report(serde_json::json!({"chunk_embeddings": {"done": 1, "total": 2}})), Some(1));
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["migration"]["next_model"], "bge-m3");
        assert_eq!(v["migration"]["state"], "filling");
        assert_eq!(v["migration"]["progress"]["tables"]["chunk_embeddings"]["total"], 2);
        assert!(v["migration"]["started_at"].is_string());
        assert!(serde_json::to_value(sp("code", "x")).unwrap()["migration"].is_null());
    }

    #[test]
    fn next_form_is_parsed() {
        assert_eq!(parse_next(Some("knowledge@next")), Some("knowledge"));
        assert_eq!(parse_next(Some(" Code@NEXT ")), Some("Code"));
        assert_eq!(parse_next(Some("@next")), None);
        assert_eq!(parse_next(Some("knowledge")), None);
        assert_eq!(parse_next(Some("harrier@v2")), None);
        assert_eq!(parse_next(None), None);
        assert_eq!(parse_next(Some("é")), None, "no panic on a multibyte tail");
    }

    #[test]
    fn a_migration_start_is_refused_when_it_cannot_mean_anything() {
        let s = two();
        assert_eq!(start_refusal(&s, "knowledge", "bge-m3"), None);
        assert!(start_refusal(&s, "nope", "bge-m3").unwrap().contains("no embedding space"));
        assert!(start_refusal(&s, "knowledge", "Harrier:latest").unwrap().contains("already embeds"));
        assert!(start_refusal(&s, "knowledge", "nomic-embed-code").unwrap().contains("space 'code'"));
        let (m, _) = migrating("filling", None, None);
        assert!(start_refusal(&[m.clone()], "knowledge", "other").unwrap().contains("already migrating"));
        // Another space's NEXT model is taken too.
        let both = vec![m, sp("code", "c")];
        assert!(start_refusal(&both, "code", "bge-m3").unwrap().contains("space 'knowledge'"));
    }

    #[test]
    fn a_different_width_is_refused_with_the_retype_reason() {
        assert_eq!(dims_refusal(Some(1024), 1024), None);
        assert_eq!(dims_refusal(None, 1024), None, "NULL dims means the vector(1024) columns");
        let why = dims_refusal(None, 768).unwrap();
        assert!(why.contains("vector(1024)") && why.contains("retyped") && why.contains("768"), "{why}");
        assert!(dims_refusal(Some(768), 1024).unwrap().contains("vector(768)"));
    }

    #[test]
    fn complete_needs_every_table_done_fresh_and_about_this_model() {
        let ok = serde_json::json!({"chunk_embeddings": {"done": 5, "total": 5}, "noo_entries": {"done": 0, "total": 0}});
        let (s, now) = migrating("filling", report(ok), Some(2));
        assert_eq!(complete_refusal(&s, now), None);

        let behind = serde_json::json!({"a": {"done": 5, "total": 5}, "b": {"done": 3, "total": 9}});
        let (s, now) = migrating("filling", report(behind), Some(2));
        assert!(complete_refusal(&s, now).unwrap().contains("b 3/9"));

        let (s, now) = migrating("filling", report(serde_json::json!({"a": {"done": 1, "total": 1}})), Some(11));
        assert!(complete_refusal(&s, now).unwrap().contains("10 minutes"));
        let (s, now) = migrating("filling", report(serde_json::json!({"a": {"done": 1, "total": 1}})), None);
        assert!(complete_refusal(&s, now).unwrap().contains("10 minutes"));

        let (s, now) = migrating("filling", None, None);
        assert!(complete_refusal(&s, now).unwrap().contains("not reported"));
        let (s, now) = migrating("filling", report(serde_json::json!({})), Some(1));
        assert!(complete_refusal(&s, now).unwrap().contains("no tables"));
        let other = Some(serde_json::json!({"next_model": "old", "tables": {"a": {"done": 1, "total": 1}}}));
        let (s, now) = migrating("filling", other, Some(1));
        assert!(complete_refusal(&s, now).unwrap().contains("not about"));
        let (s, now) = migrating("cutover", report(serde_json::json!({"a": {"done": 1, "total": 1}})), Some(1));
        assert!(complete_refusal(&s, now).unwrap().contains("already in 'cutover'"));
        assert!(complete_refusal(&sp("code", "c"), now).unwrap().contains("no migration"));
    }

    #[test]
    fn progress_stores_while_filling_and_flips_only_on_cutover_done() {
        let (f, _) = migrating("filling", None, None);
        let (c, _) = migrating("cutover", None, None);
        let f = f.migration.unwrap();
        let c = c.migration.unwrap();
        assert_eq!(progress_action(&f, false), ProgressAction::Store);
        assert_eq!(progress_action(&f, true), ProgressAction::Store, "cutover_done before the cutover is ignored");
        assert_eq!(progress_action(&c, false), ProgressAction::Store);
        assert_eq!(progress_action(&c, true), ProgressAction::Flip);
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
