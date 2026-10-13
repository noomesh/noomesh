// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster fleet state — `cluster_nodes`, `noo_backend_placements`,
//! `noo_node_config`.
//!
//! These three tables are the DECLARED fleet: which nodes exist, which
//! backends should run where, and which operator overrides beat detection.
//! They are read from five files (`routes/cluster.rs`, `autonomy_evaluators`,
//! `heartbeat_actions`, `coordinator/backend`, `channels/approvals`), which is
//! why they get a module — a rule about the fleet that lives in five places is
//! a rule that will disagree with itself.
//!
//! Statements are `sqlx::query!`, checked against the real schema at build
//! time. See `repo/mod.rs`; regenerate `.sqlx/` with `scripts/sqlx-prepare.sh`
//! and verify it against a migrated database with `scripts/sqlx-check.sh`.
//!
//! Converting these turned up three claims the schema contradicts, all of the
//! same shape — a hand-written type saying `Option` where the column is
//! `NOT NULL`:
//!
//! - `cluster_nodes.hostname` is `NOT NULL`; `autonomy_evaluators` typed it
//!   `Option<String>` and `routes/cluster.rs` typed both it and `ip_address`
//!   optional.
//! - `cluster_nodes.ip_address` is `NOT NULL`, so the revive query's
//!   `AND ip_address IS NOT NULL` predicate can never be false. It reads like
//!   a safety check and filters nothing.
//!
//! None of these were bugs — `Option<T>` decodes a non-null value happily, so
//! the code worked. They were false statements about the data that the next
//! reader had to disprove for themselves.

/// One row of the desired-state placement table: which backend the fleet has
/// declared should run on which node.
pub type Placement = (String, String);

/// Placements the fleet expects to be RUNNING, as `(node_id, backend)`.
///
/// Drives `autonomy.node_placement_drift` — declared work that is not being
/// done, whether the cause is a dead node, a stopped daemon, or a crash-looping
/// container. Placements are keyed (node, backend, ROLE), so one ollama serving
/// chat and embed is two rows; this is a list of backends to be running, so the
/// pair appears once.
pub async fn placements_desired_running<'e, E>(db: E) -> Result<Vec<Placement>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        "SELECT node_id, backend FROM noo_backend_placements \
         WHERE desired_state = 'running'"
    )
    .fetch_all(db)
    .await?;
    let mut out: Vec<Placement> = rows.into_iter().map(|r| (r.node_id, r.backend)).collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// `(node_id, backend)` pairs whose backend serves NO chat role, as
/// `(node_id, backend)`.
///
/// The coordinator uses this to exclude embed/rerank backends from chat
/// routing: a backend serving a role is not a general-purpose chat target just
/// because it is up. `role` is `NOT NULL DEFAULT 'chat'`, so `<> 'chat'` is a
/// total predicate and needs no NULL handling.
///
/// Placements are keyed (node, backend, role): ONE ollama may host a chat model
/// AND an embedder. Such a pair is a chat target (its chat model is what the
/// node reports as the backend's model), so a backend with a RUNNING chat row
/// is not in this set — only a backend whose every running row is non-chat.
/// A runtime query, not a `query!`: the NOT EXISTS shape is what changed, and
/// the offline cache is keyed by the query text.
pub async fn placements_non_chat<'e, E>(db: E) -> Result<Vec<Placement>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT p.node_id, p.backend FROM noo_backend_placements p \
         WHERE p.role <> 'chat' AND NOT EXISTS ( \
             SELECT 1 FROM noo_backend_placements c \
             WHERE c.node_id = p.node_id AND c.backend = p.backend \
               AND c.role = 'chat' AND c.desired_state = 'running')",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Does `node_id` have a RUNNING placement declared for `role`?
///
/// The gateway's own answer to "is this node an embedder", independent of what
/// the node's gossip still claims: a node that stops advertising `embed` only
/// after its agent next reconciles keeps drawing embed traffic until then.
pub async fn node_has_running_role<'e, E>(db: E, node_id: &str, role: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM noo_backend_placements \
         WHERE node_id = $1 AND role = $2 AND desired_state = 'running')",
    )
    .bind(node_id)
    .bind(role)
    .fetch_one(db)
    .await
}

/// `(node_id, ip_address, hostname)` for every enrolled node.
///
/// All three are `NOT NULL` in `cluster_nodes`. The previous call site typed
/// `ip_address` and `hostname` as `Option<String>` and then filtered empty
/// strings out — the emptiness check is still the caller's business (a column
/// can be non-null and blank), but the null check was never doing anything.
pub async fn all_nodes<'e, E>(db: E) -> Result<Vec<(String, String, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!("SELECT node_id, ip_address, hostname FROM cluster_nodes")
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.node_id, r.ip_address, r.hostname))
        .collect())
}

/// Online nodes whose heartbeat has gone stale — revive candidates.
///
/// `stale_secs` is bound as text and cast, matching the original
/// (`($1 || ' seconds')::interval`); `exclude_node` is the controller's own id,
/// since a node cannot SSH to itself to revive itself — the empty string means
/// "exclude nothing".
///
/// The original also carried `AND ip_address IS NOT NULL`. Dropped: the column
/// is `NOT NULL`, so that clause filtered nothing and implied a nullability
/// that does not exist.
pub async fn stale_online_nodes<'e, E>(
    db: E,
    stale_secs: i64,
    exclude_node: &str,
) -> Result<Vec<(String, String, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        "SELECT node_id, ip_address, hostname FROM cluster_nodes \
         WHERE status = 'online' \
           AND (last_heartbeat IS NULL OR last_heartbeat < NOW() - ($1 || ' seconds')::interval) \
           AND ($2 = '' OR node_id != $2)",
        stale_secs.to_string(),
        exclude_node,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.node_id, r.ip_address, r.hostname))
        .collect())
}

/// Operator GPU override for a node, as `(gpu_model, vram_gb)`.
///
/// Both columns are nullable and callers require BOTH to be present before the
/// override beats hardware detection — a GPU claim without VRAM is not a real
/// declaration. That rule mirrors the node-agent's, and stays at the call site
/// so this function keeps returning what the table actually holds.
pub async fn node_gpu_override<'e, E>(
    db: E,
    node_id: &str,
) -> Result<Option<(Option<String>, Option<f64>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(
        "SELECT gpu_model, vram_gb FROM noo_node_config WHERE node_id = $1",
        node_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| (r.gpu_model, r.vram_gb)))
}
