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

pub mod agent_messages;
pub mod audit;
pub mod cluster;
pub mod graph;
pub mod heartbeat;
pub mod kb_grants;
pub mod prompt_skills;
pub mod settings;
pub mod prompt_skill_proposals;
pub mod users;
