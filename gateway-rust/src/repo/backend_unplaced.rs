// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Unplace tombstones: the explicit record that an operator removed a
//! backend placement, which is the ONLY thing that lets a node agent remove
//! the backend's container.
//!
//! The rule they serve: absence never reaps. A controller whose database is
//! empty, restored from an older backup or mid-restore answers every agent
//! with a good, stable "nothing placed", so a missing placement is never a
//! reason to remove a container. An unplace is: `placement_delete` writes one
//! tombstone per `(node, backend, role)` it removed, in the same transaction
//! as the DELETE; `placement_put` of the same slot deletes it in the
//! upsert's transaction; desired-config ships a node its own live tombstones
//! in a separate `unplaced` array (never in `placements`), and only for 24 h.
//!
//! Stored in `noo_settings` (no schema change): key
//! `backend_unplaced:<node>:<backend>:<role>`, value
//! `{"unplaced_at": <RFC 3339 UTC>, "by": <principal>}`, category `unplace`.
//! The generic settings writes refuse the key namespace ([`is_reserved`]), so
//! the authority to change a setting never becomes the authority to remove a
//! container. Every other reader of `noo_settings` reads by exact key, so a
//! leftover row is inert to a gateway that does not know it.
//!
//! Runtime-checked statements (`query` / `query_as`), like `settings.rs`.

use serde_json::{json, Value};

/// The key namespace. Nothing but this module writes a key that starts with it.
pub const PREFIX: &str = "backend_unplaced:";
/// The `noo_settings.category` of every tombstone.
pub const CATEGORY: &str = "unplace";
/// A tombstone is shipped for at most this long after its unplace.
pub const TTL_SECS: i64 = 24 * 3600;
/// Advertised in desired-config's `gateway_features`: this controller ships
/// tombstones, so an agent may act on them (a controller without it ships
/// none, and the agent then removes nothing).
pub const FEATURE: &str = "reap_unplaced_backends";

/// `backend_unplaced:<node>:<backend>:<role>`.
pub fn key(node: &str, backend: &str, role: &str) -> String {
    format!("{PREFIX}{node}:{backend}:{role}")
}

/// Whether `key` is in the tombstone namespace (refused by every generic
/// settings write).
pub fn is_reserved(key: &str) -> bool {
    key.trim_start().starts_with(PREFIX)
}

/// The stored value.
pub fn value(unplaced_at: &str, by: &str) -> String {
    json!({"unplaced_at": unplaced_at, "by": by}).to_string()
}

/// One tombstone of a node, parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct Tombstone {
    pub key: String,
    pub backend: String,
    pub role: String,
    /// As stored (RFC 3339): shipped and compared as this exact text.
    pub unplaced_at: String,
    pub unplaced_unix: i64,
}

/// Parse a row of `node`'s tombstones; `None` for a key that is not one of
/// this node's or a value that does not say when (never shipped).
pub fn parse(node: &str, key: &str, value: &str) -> Option<Tombstone> {
    let rest = key.strip_prefix(PREFIX)?.strip_prefix(node)?.strip_prefix(':')?;
    let (backend, role) = rest.split_once(':')?;
    if backend.is_empty() || role.is_empty() || role.contains(':') {
        return None;
    }
    let v: Value = serde_json::from_str(value).ok()?;
    let at = v.get("unplaced_at")?.as_str()?.to_string();
    let unix = chrono::DateTime::parse_from_rfc3339(&at).ok()?.timestamp();
    Some(Tombstone { key: key.to_string(), backend: backend.to_string(), role: role.to_string(), unplaced_at: at, unplaced_unix: unix })
}

/// What desired-config ships: `(unplaced, expired)`. `unplaced` is
/// `[{backend, role, unplaced_at}]` for every tombstone that is at most
/// [`TTL_SECS`] old and whose `(backend, role)` is not in `placements` (a
/// re-place wins, even before its PUT deleted the key). `expired` are the
/// keys past the TTL (or with a time in the future by more than the TTL,
/// a clock that cannot be trusted), for the caller to delete. Pure: the
/// placements array is the one desired-config sends, and nothing here ever
/// adds to it.
pub fn ship(tombstones: &[Tombstone], placements: &[Value], now_unix: i64) -> (Vec<Value>, Vec<String>) {
    let placed = |b: &str, r: &str| {
        placements.iter().any(|p| p["backend"].as_str() == Some(b) && p["role"].as_str().unwrap_or("chat") == r)
    };
    let mut unplaced = Vec::new();
    let mut expired = Vec::new();
    for t in tombstones {
        let age = now_unix - t.unplaced_unix;
        if age > TTL_SECS || age < -TTL_SECS {
            expired.push(t.key.clone());
            continue;
        }
        if placed(&t.backend, &t.role) {
            continue;
        }
        unplaced.push(json!({"backend": t.backend, "role": t.role, "unplaced_at": t.unplaced_at}));
    }
    (unplaced, expired)
}

/// The keys a heartbeat's `reaped_backends` acknowledges: a tombstone of
/// this node whose backend and `unplaced_at` (exact text) an entry names.
/// Only ever deleted: a node's report removes reap authority, never grants it.
pub fn acked(tombstones: &[Tombstone], reaped: &Value) -> Vec<String> {
    let Some(items) = reaped.as_array() else { return Vec::new() };
    tombstones
        .iter()
        .filter(|t| {
            items.iter().any(|r| r["backend"].as_str() == Some(t.backend.as_str()) && r["unplaced_at"].as_str() == Some(t.unplaced_at.as_str()))
        })
        .map(|t| t.key.clone())
        .collect()
}

/// Delete `node`'s `backend` placement rows the way `placement_delete` asks
/// (`role` None = every role; `embed_model` names one embed row) and return
/// the role of each row removed. Run in the caller's transaction.
pub async fn delete_placements<'e, E>(
    db: E,
    node: &str,
    backend: &str,
    role: Option<&str>,
    embed_model: Option<&str>,
) -> Result<Vec<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String,)> = match (role, embed_model) {
        (Some("embed"), Some(m)) => {
            sqlx::query_as(
                "DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 AND role = 'embed' AND model = $3 RETURNING role",
            )
            .bind(node)
            .bind(backend)
            .bind(m)
            .fetch_all(db)
            .await?
        }
        (Some(r), _) => {
            sqlx::query_as("DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 AND role = $3 RETURNING role")
                .bind(node)
                .bind(backend)
                .bind(r)
                .fetch_all(db)
                .await?
        }
        (None, _) => {
            sqlx::query_as("DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 RETURNING role")
                .bind(node)
                .bind(backend)
                .fetch_all(db)
                .await?
        }
    };
    Ok(rows.into_iter().map(|(r,)| r).collect())
}

/// Write (or refresh) the tombstone of one `(node, backend, role)`. The ONE
/// writer of the namespace; `placement_delete` calls it in the DELETE's
/// transaction, only for a row it removed.
pub async fn write<'e, E>(db: E, node: &str, backend: &str, role: &str, unplaced_at: &str, by: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO noo_settings (key, value, category, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, category = EXCLUDED.category, \
           updated_by = EXCLUDED.updated_by, updated_at = NOW()",
    )
    .bind(key(node, backend, role))
    .bind(value(unplaced_at, by))
    .bind(CATEGORY)
    .bind(by)
    .execute(db)
    .await?;
    Ok(())
}

/// Remove the tombstone of one `(node, backend, role)` (a re-place, in the
/// upsert's transaction).
pub async fn kill<'e, E>(db: E, node: &str, backend: &str, role: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query("DELETE FROM noo_settings WHERE key = $1")
        .bind(key(node, backend, role))
        .execute(db)
        .await?
        .rows_affected())
}

/// Every tombstone row of `node` as `(key, value)`.
pub async fn rows_for_node<'e, E>(db: E, node: &str) -> Result<Vec<(String, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let prefix = format!("{PREFIX}{node}:");
    sqlx::query_as::<_, (String, String)>(
        "SELECT key, value FROM noo_settings WHERE category = $2 AND left(key, length($1)) = $1 ORDER BY key",
    )
    .bind(prefix)
    .bind(CATEGORY)
    .fetch_all(db)
    .await
}

/// `node`'s tombstones, parsed (a row that does not parse is never shipped).
pub async fn for_node<'e, E>(db: E, node: &str) -> Result<Vec<Tombstone>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(rows_for_node(db, node).await?.iter().filter_map(|(k, v)| parse(node, k, v)).collect())
}

/// Delete these tombstone keys (expired, or acknowledged by the node). Only
/// keys in the namespace are ever deleted here.
pub async fn delete_keys<'e, E>(db: E, keys: &[String]) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let keys: Vec<String> = keys.iter().filter(|k| is_reserved(k)).cloned().collect();
    if keys.is_empty() {
        return Ok(0);
    }
    Ok(sqlx::query("DELETE FROM noo_settings WHERE category = $2 AND key = ANY($1)")
        .bind(&keys)
        .bind(CATEGORY)
        .execute(db)
        .await?
        .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_795_000_000;

    fn at(unix: i64) -> String {
        chrono::DateTime::from_timestamp(unix, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    fn tomb(backend: &str, role: &str, unix: i64) -> Tombstone {
        let k = key("node-a", backend, role);
        parse("node-a", &k, &value(&at(unix), "op")).expect("parses")
    }

    #[test]
    fn the_key_names_node_backend_and_role_and_parses_back() {
        assert_eq!(key("node-a", "reranker", "rerank"), "backend_unplaced:node-a:reranker:rerank");
        let t = tomb("reranker", "rerank", NOW);
        assert_eq!((t.backend.as_str(), t.role.as_str(), t.unplaced_unix), ("reranker", "rerank", NOW));
        // Another node's key is never this node's tombstone.
        assert!(parse("node-a", &key("node-ab", "ollama", "chat"), &value(&at(NOW), "op")).is_none());
        assert!(parse("node-a", &key("node-a", "ollama", "chat"), "{\"by\":\"op\"}").is_none(), "no time, no tombstone");
        assert!(parse("node-a", &key("node-a", "ollama", "chat"), "not json").is_none());
    }

    /// The generic settings writes refuse the namespace.
    #[test]
    fn the_namespace_is_reserved() {
        assert!(is_reserved("backend_unplaced:node-a:ollama:chat"));
        assert!(is_reserved("  backend_unplaced:x"));
        assert!(!is_reserved("CLOUD_PROVIDERS_ENABLED"));
        assert!(!is_reserved("backend_unplace"));
    }

    /// desired-config ships a live tombstone in `unplaced` with exactly
    /// {backend, role, unplaced_at}.
    #[test]
    fn a_live_tombstone_ships_in_its_own_shape() {
        let (u, e) = ship(&[tomb("llamacpp", "chat", NOW - 60)], &[], NOW);
        assert_eq!(u, vec![json!({"backend": "llamacpp", "role": "chat", "unplaced_at": at(NOW - 60)})]);
        assert!(e.is_empty());
    }

    /// TTL on read: a tombstone over 24 h old is never shipped, and is
    /// returned for deletion.
    #[test]
    fn a_tombstone_over_24h_is_not_shipped_and_is_deleted() {
        let old = tomb("vllm", "chat", NOW - TTL_SECS - 1);
        let edge = tomb("ollama", "embed", NOW - TTL_SECS);
        let (u, e) = ship(&[old.clone(), edge], &[], NOW);
        assert_eq!(u.len(), 1, "exactly 24 h is still live");
        assert_eq!(u[0]["backend"], "ollama");
        assert_eq!(e, vec![old.key]);
    }

    /// A tombstone whose (backend, role) is placed again is never shipped:
    /// the placement wins.
    #[test]
    fn a_placed_slot_is_never_shipped_as_unplaced() {
        let placements = vec![json!({"backend": "ollama", "role": "chat", "desired_state": "running"})];
        let (u, _) = ship(&[tomb("ollama", "chat", NOW - 5), tomb("ollama", "embed", NOW - 5)], &placements, NOW);
        assert_eq!(u.len(), 1);
        assert_eq!(u[0]["role"], "embed");
    }

    /// `ship` never touches `placements`: it takes them by reference and its
    /// answer is a separate array (the 0.6.29 agent reads only `placements`).
    #[test]
    fn a_tombstone_is_never_in_placements() {
        let placements: Vec<Value> = vec![];
        let (u, _) = ship(&[tomb("reranker", "rerank", NOW)], &placements, NOW);
        assert!(placements.is_empty());
        assert!(u.iter().all(|x| x.get("desired_state").is_none() && x.get("model").is_none()), "not placement-shaped");
    }

    #[test]
    fn a_heartbeat_ack_names_the_backend_and_its_exact_unplaced_at() {
        let t = tomb("reranker", "rerank", NOW - 100);
        let other = tomb("vllm", "chat", NOW - 100);
        let reaped = json!([{"backend": "reranker", "at": at(NOW), "unplaced_at": at(NOW - 100)}]);
        assert_eq!(acked(&[t.clone(), other], &reaped), vec![t.key.clone()]);
        let stale = json!([{"backend": "reranker", "at": at(NOW), "unplaced_at": at(NOW - 99)}]);
        assert!(acked(&[t], &stale).is_empty(), "a different unplace is not acknowledged");
        assert!(acked(&[], &json!({"not": "a list"})).is_empty());
    }
}
