// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Behavioral-flag resolution with a DB override (peer of Python
//! `noomesh/settings.py`).
//!
//! [`flag`] resolves: `noo_settings` row (admin override) → env var → default.
//! The override map is kept warm by [`spawn_refresh`], a background task that
//! reloads `noo_settings` every 15s — so an admin UI toggle takes effect within
//! that window with no restart and no DB hit on the read path (the reads happen
//! inside the autonomy loop). Security-posture gates are NOT resolved here (see
//! `posture.rs` — those are read-once from the boot-applied env).

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

static OVERRIDES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn overrides() -> &'static RwLock<HashMap<String, String>> {
    OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn truthy(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "yes" | "on" | "TRUE" | "YES" | "ON")
}

/// Resolve a boolean behavioral flag: DB override → env → `default`.
pub fn flag(key: &str, default: bool) -> bool {
    if let Some(v) = overrides().read().ok().and_then(|m| m.get(key).cloned()) {
        return truthy(&v);
    }
    match std::env::var(key) {
        Ok(v) => truthy(&v),
        Err(_) => default,
    }
}

/// Resolve a STRING setting: `noo_settings` DB override → env var.
/// Returns `None` when neither layer sets it — callers append their own
/// YAML/compiled fallbacks (config-graduation phase 2).
pub fn get(key: &str) -> Option<String> {
    if let Some(v) = overrides().read().ok().and_then(|m| m.get(key).cloned()) {
        return Some(v);
    }
    std::env::var(key).ok()
}

/// The `noo_settings` row for `key`, from the override cache — and ONLY
/// that: no env fallback. For a setting whose only home is the database
/// (`kiosk.graph_labels`), an env var of the same name must not be able to
/// stand in for the operator's recorded decision.
pub fn db_value(key: &str) -> Option<String> {
    overrides().read().ok().and_then(|m| m.get(key).cloned())
}

/// A boolean read from the `noo_settings` row alone (see [`db_value`]):
/// absent row → `default`.
pub fn db_flag(key: &str, default: bool) -> bool {
    db_value(key).map_or(default, |v| truthy(&v))
}

/// Put a just-written value into this process's cache, so the gateway that
/// handled the write honours it on the very next read rather than after the
/// next 15 s reload. Other processes still converge on the reload; the DB
/// row stays the source of truth, which the next reload re-asserts.
pub fn set_override(key: &str, value: &str) {
    if let Ok(mut w) = overrides().write() {
        w.insert(key.to_string(), value.to_string());
    }
}

/// Drop a key from this process's cache (tests: put a setting back to
/// "no row").
#[cfg(test)]
pub fn remove_override(key: &str) {
    if let Ok(mut w) = overrides().write() {
        w.remove(key);
    }
}

/// Spawn the background refresher for the `noo_settings` override cache.
/// Called once at startup with the shared pool.
pub fn spawn_refresh(db: sqlx::PgPool) {
    tokio::spawn(async move {
        loop {
            if let Ok(rows) =
                sqlx::query_as::<_, (String, String)>("SELECT key, value FROM noo_settings")
                    .fetch_all(&db)
                    .await
            {
                let mut m = HashMap::with_capacity(rows.len());
                for (k, v) in rows {
                    m.insert(k, v);
                }
                if let Ok(mut w) = overrides().write() {
                    *w = m;
                }
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}
