// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Repository layer — SQL lives here, not in route handlers.
//!
//! Motivation is maintenance first. Before this module, `sqlx::query` appeared
//! in 38 files with no shared access layer, so the same statement was written
//! several times in slightly different forms (`routes/users.rs` alone held
//! `DELETE FROM noo_kb_role_grants WHERE username = $1` four times and
//! `SELECT name FROM noo_kb_teams WHERE name = ANY($1)` three times). Every
//! duplicate is a place a future change has to be remembered.
//!
//! Two secondary benefits fall out of it:
//!
//! 1. **Tenant scoping becomes reviewable.** 13 tables carry `user_id`/`org_id`
//!    and are protected only by each call site remembering to filter. Once a
//!    table's access is funnelled through one module, "is this scoped?" is a
//!    question about a file rather than about the whole codebase. See
//!    the design — this does not replace RLS, it makes the audit finite.
//! 2. **`sqlx::query!` conversion gets a home.** Converting 208 scattered
//!    runtime-string queries to compile-checked macros is much easier when they
//!    are collected by domain.
//!
//! ## Compile-checked SQL
//!
//! Modules here use `sqlx::query!`, which verifies column names, types and
//! nullability against a real schema at build time. Builds have no database,
//! so `SQLX_OFFLINE=true` points the macros at the committed
//! `gateway-rust/.sqlx/` cache. **After changing any SQL, run
//! `scripts/sqlx-prepare.sh` and commit the result** — `cargo check` fails
//! closed when a query has no cached entry, so a forgotten regeneration is
//! caught rather than silently ignored.
//!
//! What this buys, concretely: converting the `kb_grants` pilot immediately
//! falsified two declared types. `roles` and `updated_at`/`created_at` are
//! `NOT NULL` in the schema but were typed `Option`, so call sites carried
//! null-handling branches for states the database cannot produce. Runtime
//! `query_as` never complains — `Option<T>` decodes a non-null value happily.
//! The same blindness is what let the `app_version` upsert silently drop a
//! column on 2026-07-30.
//!
//! ## Conventions
//!
//! - **Generic over the executor.** Every function takes
//!   `impl sqlx::PgExecutor<'_>` so it works with both `&state.db` and
//!   `&mut *tx`. Call sites that need transactional atomicity keep it.
//! - **No `AppState`, no HTTP types.** Repository functions take and return
//!   plain data, so they stay testable and cannot smuggle route concerns into
//!   the data layer.
//! - **Errors propagate as `sqlx::Error`.** Mapping to HTTP status is the
//!   route's job. Notably this means a repository function must not swallow an
//!   error into a default — `unwrap_or_default()` on a query result hides a
//!   broken database as an empty list, the same class of silent failure as
//!   #247. Where an existing call site did that, the behaviour is preserved at
//!   the call site, not moved in here.
//!
//! ## Tables this layer fully owns
//!
//! Outside `mesh_migrate.rs` (DDL), a few test fixtures, and the exceptions
//! each module's header names, no other file spells the columns of:
//!
//! - `noo_users` — [`users`]. Statements whose subject is ANOTHER table but
//!   that resolve an owner through a `(SELECT user_uuid FROM noo_users ...)`
//!   sub-select stay with that other table, and `erase_targets()` in
//!   `routes/users.rs` is deliberately outside the layer (see [`users`]).
//! - `noo_security_audit` — [`audit`] (reads and the one INSERT). The writer's
//!   policy stays in `audit.rs`/`audit_chain.rs`; partition management stays in
//!   `audit_partition.rs` (`pg_catalog`, `tableoid`, dynamic partition names).
//! - `noo_settings` — [`settings`].
//! - `noo_tasks` — [`tasks`] (single-table statements; the `Task` read model
//!   with its JOIN stays in `tasks.rs`).
//!
//! ## The ratchet
//!
//! Roughly a hundred files outside this directory still call `sqlx::query*`.
//! They are not blocked, they are capped: the `ratchet` test at the bottom of
//! this file pins every file's count of sqlx lines and fails if any file
//! exceeds its pin or a new file calls sqlx. Lower a count when you move a
//! query in; never raise one.

pub mod agent_messages;
pub mod agent_recipients;
pub mod audit;
pub mod caller_verifiers;
pub mod cluster;
pub mod graph;
pub mod heartbeat;
pub mod kb_grants;
pub mod prompt_skills;
pub mod settings;
pub mod tasks;
pub mod prompt_skill_proposals;
pub mod users;

// ── The ratchet ────────────────────────────────────────────────────────────

#[cfg(test)]
mod ratchet {
    use std::collections::BTreeMap;
    use std::path::Path;

    /// Per-file count of source LINES mentioning `sqlx::query` (which covers
    /// `query`, `query_as`, `query_scalar` and the `!` macros) for every `.rs`
    /// file under `gateway-rust/src` OUTSIDE `repo/`. DDL in `mesh_migrate.rs`
    /// and test fixtures are counted like anything else: the number is what the
    /// file spells today, not a judgement about it.
    ///
    /// **Lower a count when you move a query into `repo/`; never raise one.**
    /// A file not listed may not call sqlx at all — add its SQL to a `repo/`
    /// module instead. Regenerate honestly (from the repository root) with:
    ///
    /// ```text
    /// (cd gateway-rust/src && grep -rc 'sqlx::query' . --include=*.rs \
    ///    | sed 's|^\./||' | grep -v '^repo/' | grep -v ':0$' | sort)
    /// ```
    ///
    /// and paste the `file:count` pairs below, but ONLY after lowering counts:
    /// a regenerate that raises a number is the change this test exists to stop.
    /// This is a ratchet, not a ban — the files listed still own their SQL.
    const PINNED: &[(&str, usize)] = &[
    ("addon_auth.rs", 5),
    ("agent_activities.rs", 6),
    ("agent_mail_archive.rs", 11),
    ("agent_messages.rs", 1),
    ("audit.rs", 2),
    ("audit_chain.rs", 3),
    ("audit_integrity.rs", 16),
    ("audit_partition.rs", 8),
    ("auth_refresh.rs", 7),
    ("autonomy_audit.rs", 6),
    ("autonomy_evaluators.rs", 8),
    ("autonomy_loop.rs", 2),
    ("backup_completion.rs", 6),
    ("backup_overdue.rs", 6),
    ("channels/approvals.rs", 3),
    ("channels/identity.rs", 1),
    ("channels/mod.rs", 10),
    ("coordinator/agent_loop.rs", 5),
    ("coordinator/classes.rs", 11),
    ("coordinator/context.rs", 1),
    ("coordinator/dispatch.rs", 4),
    ("coordinator/runtime.rs", 1),
    ("coordinator/summary.rs", 3),
    ("dependency_watchdog.rs", 1),
    ("dlq_drain.rs", 4),
    ("embedding_spaces.rs", 13),
    ("entity_cleanup_task.rs", 9),
    ("erasure_archive.rs", 7),
    ("graph_prune.rs", 20),
    ("heartbeat_actions.rs", 18),
    ("heartbeat_loop.rs", 6),
    ("heartbeat_reconcile.rs", 1),
    ("held_column.rs", 1),
    ("mcp_bridge.rs", 5),
    ("mcp_session.rs", 9),
    ("memory/cluster_audit.rs", 14),
    ("memory/provider.rs", 36),
    ("memory/scope.rs", 35),
    ("mesh_migrate.rs", 18),
    ("metrics.rs", 1),
    ("middleware.rs", 4),
    ("node_name_claim.rs", 2),
    ("operator_auth.rs", 1),
    ("ops.rs", 22),
    ("ops/tests.rs", 65),
    ("placement_stuck.rs", 1),
    ("posture.rs", 2),
    ("preflight.rs", 4),
    ("research_pipeline.rs", 1),
    ("role_capability.rs", 1),
    ("role_provision.rs", 7),
    ("routes/admin.rs", 10),
    ("routes/agents.rs", 5),
    ("routes/bootstrap.rs", 17),
    ("routes/cluster.rs", 39),
    ("routes/communication.rs", 11),
    ("routes/core.rs", 3),
    ("routes/core/refresh_rotation_tests.rs", 8),
    ("routes/erase_kb.rs", 32),
    ("routes/external.rs", 1),
    ("routes/intelligence.rs", 19),
    ("routes/knowledge.rs", 5),
    ("routes/mcp_registry.rs", 14),
    ("routes/memory.rs", 30),
    ("routes/operator_certs.rs", 3),
    ("routes/ops.rs", 1),
    ("routes/other.rs", 1),
    ("routes/ownership_scoping_tests.rs", 11),
    ("routes/seats.rs", 23),
    ("routes/temporal.rs", 1),
    ("routes/ui.rs", 3),
    ("routes/usage.rs", 5),
    ("routes/users.rs", 98),
    ("routes/walks.rs", 13),
    ("scheduler_engine.rs", 2),
    ("service_keys.rs", 6),
    ("session.rs", 5),
    ("session_floor.rs", 4),
    ("system_provision.rs", 30),
    ("system_provision_cli.rs", 1),
    ("task_budget.rs", 2),
    ("task_context.rs", 4),
    ("task_events.rs", 15),
    ("task_guard.rs", 29),
    ("tasks.rs", 11),
    ("temporal_graph.rs", 10),
    ("usage.rs", 2),
    ("worker_client.rs", 1),
    ("worker_delegation.rs", 1),
    ];

    fn scan(dir: &Path, root: &Path, out: &mut BTreeMap<String, usize>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                scan(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                if rel.starts_with("repo/") {
                    continue;
                }
                let n = std::fs::read_to_string(&path)
                    .expect("read source")
                    .lines()
                    .filter(|l| l.contains("sqlx::query"))
                    .count();
                if n > 0 {
                    out.insert(rel, n);
                }
            }
        }
    }

    #[test]
    fn no_file_outside_repo_adds_sql() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = BTreeMap::new();
        scan(&root, &root, &mut found);
        let pinned: BTreeMap<&str, usize> = PINNED.iter().copied().collect();
        assert_eq!(pinned.len(), PINNED.len(), "a file is pinned twice");
        assert!(found.len() > 50, "the scan found {} files: the walk is broken, not the code", found.len());
        let mut bad = Vec::new();
        for (file, n) in &found {
            match pinned.get(file.as_str()) {
                None => bad.push(format!("{file}: {n} sqlx call line(s) but the file is not pinned — put the SQL in a repo/ module")),
                Some(max) if n > max => bad.push(format!("{file}: {n} sqlx call line(s), pinned at {max} — never raise a count; move the query into repo/")),
                Some(_) => {}
            }
        }
        assert!(bad.is_empty(), "the repo-layer ratchet:\n{}", bad.join("\n"));
    }
}
