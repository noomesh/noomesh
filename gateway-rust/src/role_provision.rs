// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Login roles, grants and table ownership for the mesh database.
//!
//! # Why this file exists
//!
//! Roles, grants and ownership used to live in Alembic revisions 033
//! (`noo_app`), 034 (`noo_evolve`) and 038 (`noo_trellion`). The sqlx cutover
//! replaced the chain with a `pg_dump --schema-only --no-owner --no-privileges`
//! baseline — and those two flags strip exactly what those revisions provided.
//! Three things were silently lost on the new default path:
//!
//!   1. the login roles themselves (nothing else creates them — not
//!      onboarding, not bootstrap; the Postgres image has no
//!      `docker-entrypoint-initdb.d`),
//!   2. grants and DEFAULT PRIVILEGES,
//!   3. table OWNERSHIP.
//!
//! Measured, not assumed. A database built by the sqlx baseline against one
//! built by the Alembic chain:
//!
//! | | sqlx | alembic |
//! | --- | --- | --- |
//! | `table_privileges` for `noo_app` | **0** | **348** |
//! | tables owned by `noo_trellion` | **0** | **29** |
//! | tables owned by `noo_evolve` | **0** | **5** |
//!
//! Existing installs never noticed: they hold all of this from the chain that
//! built them. A FRESH install got a gateway that migrated successfully and
//! then died in preflight on `only 0/6 core tables` — 0 because
//! `information_schema` only shows tables you hold a privilege on.
//!
//! # Why no gate caught it
//!
//! `generate-mesh-baseline.sh` and `verify-full-install-equivalence.sh` both
//! dump with `--no-privileges`, on BOTH sides. The equivalence gate is
//! structurally blind to the plane the defect lives in. Same shape as the
//! cross-domain FK miss, where mesh-only was compared against mesh-only.
//! A diff only catches what both sides are allowed to express.
//!
//! # The one behaviour that deliberately differs from the Python original
//!
//! **An existing role's password is never rewritten.** `role_provision.py`
//! ends with an unconditional `ALTER ROLE … WITH PASSWORD` whenever
//! `NOO_DB_SCHEMA_ONLY` is unset, so any replay of the chain against a live
//! cluster resets all three credentials. That has taken this cluster down
//! twice — most recently mid-cutover, with `noo_app`, `noo_evolve` and
//! `noo_trellion` all failing `scram-sha-256` while the secret store was
//! perfectly intact.
//!
//! The root cause is a scope mismatch, not a coding slip: a migration chain is
//! scoped to ONE DATABASE, while `CREATE`/`ALTER ROLE` is cluster-global. So
//! here, creation is the only write that touches a role, and it happens only
//! when the role is absent. Rotation is an operator action
//! (`noo security secrets resync`), which is where a cluster-global write
//! belongs.
//!
//! Grants and ownership are per-DATABASE and therefore genuinely belong with
//! the schema. They are re-asserted on every boot: idempotent, and it is what
//! makes a table added by a later migration reachable.
//!
//! # Scope, and what moves out next
//!
//! Mesh provisions all three roles today because nothing else does yet, which
//! is precisely the coupling to remove: `noo_evolve` is a login for a system
//! that may never be installed. The target is each system owning its own role
//! — mesh/`noo_app`, trellion/`noo_trellion`, evolve/`noo_evolve` — with
//! each chain keeping only its GRANTs, which are per-database and valid there.
//! This file reproduces today's behaviour so a fresh install works; the split
//! is the follow-up.

use sqlx::PgPool;

pub(crate) const APP_ROLE: &str = "noo_app";
const EVOLVE_ROLE: &str = "noo_evolve";
const TRELLION_ROLE: &str = "noo_trellion";

const ROLE_ATTRS: &str = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS";

/// Tables owned by `noo_evolve` — mirrors `034_evolve_role.EVOLVE_TABLES`.
const EVOLVE_TABLES: &[&str] = &[
    "noo_ga_genomes",
    "noo_ga_generations",
    "noo_rl_arms",
    "noo_rl_experiences",
    "noo_hofstadter_loop_cycles",
];

/// Tables owned by `noo_trellion`. Mirrors the union of THREE Python sources —
/// `038_trellion_role._memory_tables()` (`_PINNED_MEMORY_TABLES |
/// EXTRA_MEMORY_TABLES`) and `039_trellion_signals_ownership.TABLES`.
///
/// 039 is easy to miss, and was: an earlier cut of this list came from 038
/// alone and left `entity_graph_signals` owned by `noo` on a fresh install.
/// Nothing failed at boot — it would have surfaced later as a permission error
/// inside noo-trellion. Caught by diffing owned-table sets between a
/// sqlx-built database and the live Alembic-built one, which is the only check
/// that can see it; the schema dumps are taken with `--no-owner`.
///
/// Pinned rather than discovered, for the same reason the Python side pins it:
/// the memory env lives in the trellion package, which this container does not
/// carry. `tests/test_role_ownership_parity.py` keeps the lists in step, and
/// reads all three sources so a fourth migration cannot repeat this.
const TRELLION_TABLES: &[&str] = &[
    "chunk_embeddings",
    "docs",
    "edges",
    "entities",
    "entity_cluster_members",
    "entity_clusters",
    "entity_embeddings",
    "entity_graph_signals",
    "graph_edge_prune_staging",
    "graph_prune_staging",
    "mentions",
    "noo_context_retrievals",
    "noo_conversations",
    "noo_entities_typed",
    "noo_entries",
    "noo_feedback",
    "noo_semantic_relationships",
    "noo_temporal_edges",
    "noo_tool_executions",
    "page_chunks",
    "page_embeddings",
    "pages",
    "trellion_communities",
    "trellion_concepts",
    "trellion_dag_edges",
    "trellion_episodes",
    "trellion_provenance",
    "trellion_snapshots",
    "trellion_traversal_records",
];

/// Escape a value for a SQL string literal. `CREATE ROLE` does not accept bind
/// parameters, so the password has to be inlined. Same approach, and the same
/// constraint, as the Python original: the value comes from the operator's own
/// secret store, never from user input.
fn quote_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// True when *role* already exists in the cluster.
async fn role_exists(db: &PgPool, role: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(role)
        .fetch_one(db)
        .await
}

/// True when a table exists in `public`.
async fn table_exists(db: &PgPool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = $1)",
    )
    .bind(table)
    .fetch_one(db)
    .await
}

/// Create *role* if absent. Returns whether it was created.
///
/// Absent + no password configured is a hard error, not a default. Inventing a
/// credential for a login role is how you get a cluster with a password nobody
/// knows and every operator assumes is in the store.
async fn ensure_role(db: &PgPool, role: &str, password_env: &str) -> Result<bool, String> {
    if role_exists(db, role).await.map_err(|e| e.to_string())? {
        // Deliberately no ALTER. See the module docs.
        return Ok(false);
    }
    let password = crate::config::secret_env::secret(password_env)
        .map_err(|e| e.to_string())?
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "{password_env} is not set. The {role:?} login role does not exist and \
                 will not be created with an invented password. The value belongs in \
                 secrets/env.sops, and needs a passthrough in the gateway service env \
                 allowlist in docker-compose.cluster.yml."
            )
        })?;

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} {ROLE_ATTRS} PASSWORD '{}'",
        quote_literal(&password)
    )))
    .execute(db)
    .await
    .map_err(|e| format!("CREATE ROLE {role} failed: {e}"))?;
    tracing::info!(role, "login role created");
    Ok(true)
}

/// Re-assert per-database grants. Idempotent; safe on every boot.
async fn grant_runtime_access(db: &PgPool, role: &str) -> Result<(), String> {
    // Which schemas hold mesh tables on THIS install: `public` always, and
    // `mesh` once the layout move has run (fresh installs). Skipping an
    // absent schema rather than creating it — grants follow layout, they do
    // not decide it.
    let mut schemas = vec!["public"];
    let mesh_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'mesh')")
            .fetch_one(db)
            .await
            .map_err(|e| e.to_string())?;
    if mesh_exists {
        schemas.push("mesh");
    }
    // NOT `GRANT CREATE` — the runtime role must not be able to add tables.
    // That constraint is what makes "noo_app owns zero tables" checkable.
    for schema in schemas {
        for stmt in [
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}"
            ),
            format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
            // Without these, the NEXT migration to add a table breaks the
            // gateway — the failure lands nowhere near the change that
            // caused it.
            format!(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} \
                 GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} \
                 GRANT USAGE, SELECT ON SEQUENCES TO {role}"
            ),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(&*stmt))
                .execute(db)
                .await
                .map_err(|e| format!("{stmt} failed: {e}"))?;
        }
    }
    Ok(())
}

/// Give *role* USAGE + sequence access and ownership of the tables it owns.
///
/// A table that does not exist is SKIPPED, not an error. That is the normal
/// state, not an edge case: the evolve tables exist only where the evolve overlay
/// ran, and the memory tables are created by a different container that may
/// not have finished yet. A later boot assigns ownership once they appear.
async fn assign_ownership(db: &PgPool, role: &str, tables: &[&str]) -> Result<usize, String> {
    for stmt in [
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(&*stmt))
            .execute(db)
            .await
            .map_err(|e| format!("{stmt} failed: {e}"))?;
    }

    let mut owned = 0usize;
    for table in tables {
        if !table_exists(db, table).await.map_err(|e| e.to_string())? {
            continue;
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE public.{table} OWNER TO {role}")))
            .execute(db)
            .await
            .map_err(|e| format!("ALTER TABLE {table} OWNER TO {role} failed: {e}"))?;
        owned += 1;
    }
    Ok(owned)
}

/// Provision roles, grants and ownership. Called from the migration path with
/// the PRIVILEGED pool — the runtime role cannot grant itself anything.
///
/// Ordering matters and is the reason this runs where it does: grants use
/// `ON ALL TABLES`, which resolves at execution time against the tables that
/// exist right then. Running before the baseline would grant on nothing.
pub async fn run(db: &PgPool) -> Result<(), String> {
    let app_created = ensure_role(db, APP_ROLE, "NOO_APP_DB_PASSWORD").await?;
    grant_runtime_access(db, APP_ROLE).await?;

    // The other two are provisioned only when their credential is configured.
    // An OSS install has no noo-evolve and no NOO_EVOLVE_DB_PASSWORD; creating
    // a login role for a system that will never run is not a safe default.
    // Where the role already exists, ownership is re-asserted regardless — the
    // password is only needed to CREATE.
    let mut owned_evolve = 0;
    if role_exists(db, EVOLVE_ROLE).await.map_err(|e| e.to_string())?
        || crate::config::secret_env::secret_opt("NOO_EVOLVE_DB_PASSWORD").is_some_and(|v| !v.trim().is_empty())
    {
        ensure_role(db, EVOLVE_ROLE, "NOO_EVOLVE_DB_PASSWORD").await?;
        owned_evolve = assign_ownership(db, EVOLVE_ROLE, EVOLVE_TABLES).await?;
    }

    let mut owned_trellion = 0;
    if role_exists(db, TRELLION_ROLE).await.map_err(|e| e.to_string())?
        || crate::config::secret_env::secret_opt("NOO_TRELLION_DB_PASSWORD").is_some_and(|v| !v.trim().is_empty())
    {
        ensure_role(db, TRELLION_ROLE, "NOO_TRELLION_DB_PASSWORD").await?;
        owned_trellion = assign_ownership(db, TRELLION_ROLE, TRELLION_TABLES).await?;
    }

    tracing::info!(
        app_role_created = app_created,
        evolve_tables_owned = owned_evolve,
        trellion_tables_owned = owned_trellion,
        "roles, grants and ownership reconciled"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_literals_are_escaped() {
        assert_eq!(quote_literal("pa'ss"), "pa''ss");
        assert_eq!(quote_literal("plain"), "plain");
        // The shape that would end the literal early and inject.
        assert_eq!(quote_literal("'; DROP ROLE noo; --"), "''; DROP ROLE noo; --");
    }

    #[test]
    fn runtime_role_is_never_granted_create() {
        // GRANT CREATE on schema public would let the runtime role add tables,
        // which is exactly the property `noo_app owns zero tables` relies on.
        let stmts = ROLE_ATTRS.to_string();
        assert!(stmts.contains("NOSUPERUSER"));
        assert!(stmts.contains("NOCREATEDB"));
        assert!(stmts.contains("NOCREATEROLE"));
        assert!(stmts.contains("NOBYPASSRLS"));
    }

    #[test]
    fn owned_table_lists_have_no_overlap() {
        // A table owned by two roles is a contradiction; the last ALTER would
        // silently win and which one ran last is not something to rely on.
        for t in EVOLVE_TABLES {
            assert!(
                !TRELLION_TABLES.contains(t),
                "{t} is claimed by both noo_evolve and noo_trellion"
            );
        }
    }

    #[test]
    fn owned_table_lists_are_sorted_and_unique() {
        let mut sorted = TRELLION_TABLES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), TRELLION_TABLES, "keep the list sorted and unique");
    }
}
