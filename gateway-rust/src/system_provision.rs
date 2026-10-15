// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The broker: mesh provisions roles and schemas for the systems that extend
//! this database. the design.
//!
//! WHY A BROKER, AND NOT "EACH SYSTEM PROVISIONS ITSELF".
//!
//! The first cut said each system should create its own role.
//! That fails mechanically: creating a role requires privilege, so "provision
//! yourself" means every service holds a privileged credential. Trellion only
//! managed it because its Alembic env already runs as superuser `noo` — the
//! exact thing the proposal exists to remove. And it could never extend to
//! noo-evolve, which connects only as `noo_evolve`, has no privileged
//! connection, and has no migration env at all.
//!
//! So the privileged act and the ownership are separated. Mesh is the only
//! privileged component; each service then migrates as itself, into its own
//! schema.
//!
//! DECLARATIVE, NOT AN API. The manifest lives in `noomesh.yaml`. An
//! authenticated `POST /api/db/provision` would be a privilege-escalation
//! surface — compromise the gateway, mint any role. A manifest is reviewable
//! in git and has no runtime path.
//!
//! WHY NOT `initdb`. Postgres init scripts run once, at cluster creation. They
//! cannot serve the actual flow, which is *evolve gets activated later*.
//!
//! GATING IS ON INTENT, NOT ON WHETHER A SECRET EXISTS. `noo-cli` generates
//! every role password from an UNCONDITIONAL `SecretSpec` — its own
//! `consequence` string says "pro installs only", but every install gets one,
//! and the gateway passes it through unconditionally. So gating on credential
//! presence creates a `noo_evolve` login role on OSS installs that will never
//! run noo-evolve, which is the complaint the design opens with.
//!
//! TWO ROLES PER SYSTEM, NOT ONE.
//!
//! `noo_trellion_ddl` owns the schema and is the only identity that can create
//! in it. `noo_trellion` reads and writes, and holds no CREATE anywhere. They
//! are different privileges used at different moments — migrations, and every
//! other second — and collapsing them means the runtime holds DDL rights
//! permanently so that a migration can hold them briefly.
//!
//! It is also what makes the boundary checkable rather than conventional:
//! "the runtime role owns nothing and can create nothing" is a property you
//! can assert against the catalogue, and this module's tests do.
//!
//! THE DEFAULT PRIVILEGES ARE LOAD-BEARING. A table created by the DDL role is
//! owned by the DDL role, and the runtime role has NO access to it — not by
//! configuration, but by how Postgres works. `ALTER DEFAULT PRIVILEGES FOR
//! ROLE <ddl>` is what closes that, and without it the failure is silent until
//! the first query against a newly migrated table. That is why there is a test
//! which creates a table as the DDL role and then asserts the runtime role can
//! read it.
//!
//! Tables keep living in `public` until phase B′ moves them.

use sqlx::PgPool;

use crate::config::SystemConfig;

/// Attributes for every provisioned runtime role. No CREATEDB, no CREATEROLE,
/// no BYPASSRLS, no SUPERUSER — and note what is absent from the grants below:
/// CREATE on any schema. New tables arrive by migration, not by a service
/// bootstrapping schema at runtime.
const ROLE_ATTRS: &str = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS";

/// Values a truthy env flag may take. Mirrors the shell convention the
/// launchers use, so `NOO_PRO_ENABLED=1` and `=true` behave the same here as
/// they do in `lib-config.sh`.
const TRUE_VALUES: &[&str] = &["1", "true", "yes", "on"];

/// Escape a value for a SQL string literal. `CREATE ROLE` does not accept bind
/// parameters, so the password has to be inlined. The value comes from the
/// operator's own secret store, never from user input.
fn quote_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// Reject anything that is not a bare lowercase SQL identifier.
///
/// Role and schema names are interpolated into DDL that cannot take bind
/// parameters. They come from `noomesh.yaml`, which is operator-controlled
/// rather than user-controlled — but `noo config set` reaches that file with
/// only WRITE scope, so "operator-controlled" is weaker than it looks. This
/// keeps a config edit from becoming SQL.
fn valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// True when the operator has turned this system on.
///
/// `None` means unconditional — trellion, which is mandatory since the
/// container split and has no flag to check.
fn intent_declared(name: &str, spec: &SystemConfig) -> bool {
    // A system whose name matches a declared add-on follows the add-on. This
    // used to be `enabled_when: NOO_PRO_ENABLED` — a THIRD place the same
    // fact was written down (after the flag itself and the launcher), and the
    // one that failed live on 2026-08-05: the var never reached this
    // container, so evolve's schema was silently never provisioned while the
    // add-on was on everywhere else.
    //
    // Now there is one map. A system that is also an add-on cannot disagree
    // with it, because it is not asked twice.
    if crate::addons::ADDONS.iter().any(|a| a.name == name) {
        return crate::addons::enabled(name);
    }
    // A system that is NOT an add-on may still name a plain env flag.
    let Some(flag) = spec.enabled_when.as_deref() else {
        return true;
    };
    std::env::var(flag)
        .map(|v| TRUE_VALUES.contains(&v.trim().to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

async fn role_exists(db: &PgPool, role: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(role)
        .fetch_one(db)
        .await
}

async fn schema_exists(db: &PgPool, schema: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)",
    )
    .bind(schema)
    .fetch_one(db)
    .await
}

/// Create the role if absent. Returns whether this call created it.
///
/// An existing role is left ENTIRELY alone — no `ALTER`, so no password and no
/// attribute of a live credential can be rewritten by a schema run. Roles are
/// cluster-global while a migration chain is scoped to one database; that
/// mismatch reset all three production role passwords twice, most recently on
/// 2026-08-04. Rotation is `noo security secrets resync`, never a side effect.
async fn ensure_role(
    db: &PgPool,
    system: &str,
    role: &str,
    password_env: &str,
) -> Result<bool, String> {
    if role_exists(db, role).await.map_err(|e| e.to_string())? {
        return Ok(false);
    }

    let password = crate::config::secret_env::secret(password_env)
        .map_err(|e| e.to_string())?
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "system {system:?} is enabled but {password_env} is not set, so the \
                 {role:?} login role cannot be created. It will not be created with an \
                 invented password — that leaves a credential nobody knows and every \
                 operator assumes is in the store. Run `noo systems enable {system}`, \
                 which mints it."
            )
        })?;

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} {ROLE_ATTRS} PASSWORD '{}'",
        quote_literal(&password)
    )))
    .execute(db)
    .await
    .map_err(|e| format!("CREATE ROLE {role} failed: {e}"))?;
    tracing::info!(system, role, "login role created");
    Ok(true)
}

/// Create the schema owned by the DDL role, and wire the runtime role's access.
///
/// `CREATE SCHEMA IF NOT EXISTS` is not used: Postgres checks the privilege
/// BEFORE `IF NOT EXISTS`, so the guard does not make the statement safe to
/// issue blindly, and check-then-act keeps the log honest about what actually
/// changed (noo-evolve#7).
async fn ensure_schema(db: &PgPool, system: &str, spec: &SystemConfig) -> Result<bool, String> {
    let created = if schema_exists(db, &spec.schema)
        .await
        .map_err(|e| e.to_string())?
    {
        // An existing schema is re-owned rather than left alone. Ownership is
        // the thing being asserted, and a schema created before the DDL role
        // existed would otherwise keep whoever made it as owner forever.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER SCHEMA {} OWNER TO {}",
            spec.schema, spec.ddl_role
        )))
        .execute(db)
        .await
        .map_err(|e| format!("ALTER SCHEMA {} OWNER failed: {e}", spec.schema))?;
        false
    } else {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE SCHEMA {} AUTHORIZATION {}",
            spec.schema, spec.ddl_role
        )))
        .execute(db)
        .await
        .map_err(|e| format!("CREATE SCHEMA {} failed: {e}", spec.schema))?;
        tracing::info!(system, schema = %spec.schema, owner = %spec.ddl_role, "schema created");
        true
    };

    // The runtime role gets USAGE and nothing structural. No CREATE — that is
    // the whole point of the split, and `runtime_role_cannot_create` asserts
    // it against the catalogue.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA {} TO {}",
        spec.schema, spec.role
    )))
    .execute(db)
    .await
    .map_err(|e| format!("GRANT USAGE ON SCHEMA {} failed: {e}", spec.schema))?;

    // FOR ROLE <ddl>, not the current role. Default privileges are recorded
    // per granting-role: written without `FOR ROLE` they would apply to
    // objects the SUPERUSER creates, which is nothing here, and the setting
    // would look present while doing nothing at all.
    for stmt in [
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} \
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
            spec.ddl_role, spec.schema, spec.role
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} \
             GRANT USAGE, SELECT ON SEQUENCES TO {}",
            spec.ddl_role, spec.schema, spec.role
        ),
        // Default privileges only reach objects created AFTER they are set, so
        // anything already in the schema needs an explicit catch-up. Cheap,
        // idempotent, and the difference between a migration that works and
        // one that works only for installs provisioned in the right order.
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
            spec.schema, spec.role
        ),
        format!(
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}",
            spec.schema, spec.role
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(&*stmt))
            .execute(db)
            .await
            .map_err(|e| format!("{stmt} failed: {e}"))?;
    }

    // The GATEWAY's runtime role reads system tables directly — the memory
    // plane queries trellion tables unqualified through the pool's
    // search_path (the gateway's own evolve reads retired with routes/pro.rs
    // the evolve grants stay for legacy callers). On the legacy layout `public` grants
    // covered this invisibly; on the per-schema layout nothing did, and the
    // first virgin install came up with noo_app unable to even
    // RESOLVE those tables (search_path skips schemas without USAGE, so it
    // looks like "table does not exist", not "permission denied"). Same
    // grant shape as the system's own runtime role: DML, no CREATE.
    if role_exists(db, crate::role_provision::APP_ROLE)
        .await
        .map_err(|e| e.to_string())?
    {
        for stmt in [
            format!(
                "GRANT USAGE ON SCHEMA {} TO {}",
                spec.schema,
                crate::role_provision::APP_ROLE
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} \
                 GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
                spec.ddl_role,
                spec.schema,
                crate::role_provision::APP_ROLE
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} \
                 GRANT USAGE, SELECT ON SEQUENCES TO {}",
                spec.ddl_role,
                spec.schema,
                crate::role_provision::APP_ROLE
            ),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
                spec.schema,
                crate::role_provision::APP_ROLE
            ),
            format!(
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}",
                spec.schema,
                crate::role_provision::APP_ROLE
            ),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(&*stmt))
                .execute(db)
                .await
                .map_err(|e| format!("{stmt} failed: {e}"))?;
        }
    }

    Ok(created)
}

/// Install the extensions a system declares.
///
/// This is broker work for a mechanical reason: `vector` and `pg_trgm` are
/// UNTRUSTED in this image (no `trusted` line in their control files), so
/// `CREATE EXTENSION` requires superuser no matter who owns the schema.
/// Trellion's chain issuing these on every run is the one thing still
/// forcing it to connect as `noo` — moving the install here is what lets
/// that chain drop to `noo_trellion_ddl`.
///
/// Check-then-act rather than `IF NOT EXISTS`, per the standing lesson
/// (noo-evolve#7): Postgres checks the privilege BEFORE the guard, and a
/// check that only "usually" no-ops is a log that lies about what changed.
/// Here the connection is privileged so the guard WOULD hold — the shape is
/// kept anyway so this function stays safe to copy somewhere less
/// privileged.
async fn ensure_extensions(db: &PgPool, system: &str, spec: &SystemConfig) -> Result<(), String> {
    for ext in &spec.extensions {
        if !valid_identifier(ext) {
            return Err(format!(
                "system {system:?} declares extension {ext:?}, which is not a bare \
                 lowercase SQL identifier. These names are interpolated into DDL."
            ));
        }
        let installed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)",
        )
        .bind(ext)
        .fetch_one(db)
        .await
        .map_err(|e| e.to_string())?;
        if installed {
            continue;
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION {ext}")))
            .execute(db)
            .await
            .map_err(|e| format!("CREATE EXTENSION {ext} failed: {e}"))?;
        tracing::info!(system, extension = %ext, "extension installed");
    }
    Ok(())
}

/// Reconcile every declared system. Idempotent; safe on every boot.
///
/// Called from the migration path with the PRIVILEGED pool — a runtime role
/// cannot create roles or schemas, which is the entire point of the split.
pub async fn run(db: &PgPool) -> Result<(), String> {
    reconcile(db, &crate::config::global().systems).await
}

/// The reconciler proper, taking the manifest explicitly so it can be tested
/// against a real database without a config file on disk.
pub async fn reconcile(
    db: &PgPool,
    systems: &std::collections::BTreeMap<String, SystemConfig>,
) -> Result<(), String> {
    if systems.is_empty() {
        return Ok(());
    }

    let mut provisioned = 0usize;
    let mut skipped = 0usize;

    for (name, spec) in systems {
        if !intent_declared(name, spec) {
            // INFO, naming the system AND the flag. It was `debug!` with a
            // bare count in the summary, and that hid a real
            // misconfiguration: on 2026-08-05 evolve was skipped because
            // NOO_PRO_ENABLED never reached this container, and the only
            // evidence was `skipped=1`. An operator who has just run
            // `noo systems enable` needs to see WHICH system did not
            // provision and WHICH flag was not set.
            //
            // Still not a warning: a system that is off is the normal state of
            // an OSS install, and crying wolf about it is how a report becomes
            // noise people stop reading. The distinction is name-it-clearly
            // versus flag-it-as-broken.
            tracing::info!(
                system = name,
                gate = spec.enabled_when.as_deref().unwrap_or("addons map"),
                "system not enabled — skipping (its enable flag is unset in THIS container)"
            );
            skipped += 1;
            continue;
        }

        for ident in [&spec.role, &spec.ddl_role, &spec.schema] {
            if !valid_identifier(ident) {
                return Err(format!(
                    "system {name:?} declares {ident:?}, which is not a bare lowercase \
                     SQL identifier. These names are interpolated into DDL."
                ));
            }
        }

        // The DDL role first: it owns the schema, so it has to exist before
        // the schema can be created AUTHORIZATION it.
        ensure_role(db, name, &spec.ddl_role, &spec.ddl_password_env).await?;
        ensure_role(db, name, &spec.role, &spec.password_env).await?;
        ensure_schema(db, name, spec).await?;
        ensure_extensions(db, name, spec).await?;
        provisioned += 1;
    }

    tracing::info!(provisioned, skipped, "systems reconciled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(flag: Option<&str>) -> SystemConfig {
        SystemConfig {
            role: "noo_evolve".into(),
            ddl_role: "noo_evolve_ddl".into(),
            schema: "evolve".into(),
            enabled_when: flag.map(str::to_string),
            password_env: "NOO_EVOLVE_DB_PASSWORD".into(),
            ddl_password_env: "NOO_EVOLVE_DDL_PASSWORD".into(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn no_flag_means_unconditional() {
        // A system that is neither an add-on nor flagged provisions always.
        assert!(intent_declared("somethingelse", &spec(None)));
    }

    #[test]
    fn a_system_named_after_an_addon_follows_the_addon_not_a_flag() {
        // The 2026-08-05 failure in one assertion: `enabled_when` was a
        // SECOND declaration of "is evolve on", it disagreed with the add-on
        // map, and evolve's schema was silently never provisioned. A system
        // that shares an add-on's name is not asked twice — the flag it names
        // is ignored entirely, so the two cannot diverge.
        std::env::set_var("NOO_TEST_STALE_FLAG", "1");
        assert!(
            !intent_declared("evolve", &spec(Some("NOO_TEST_STALE_FLAG"))),
            "evolve is opt-in and unstated here, so a stale truthy flag must not enable it"
        );
        std::env::remove_var("NOO_TEST_STALE_FLAG");
    }

    #[test]
    fn intent_follows_the_flag_not_the_credential() {
        // The whole point. `noo-cli` mints NOO_EVOLVE_DB_PASSWORD on every
        // install, pro or not, so a credential being present says nothing
        // about whether the operator wants this system.
        std::env::set_var("NOO_EVOLVE_DB_PASSWORD", "present-on-every-install");
        std::env::remove_var("NOO_TEST_PRO_FLAG");
        assert!(
            !intent_declared("somethingelse", &spec(Some("NOO_TEST_PRO_FLAG"))),
            "a set password must not stand in for a declared intent"
        );

        std::env::set_var("NOO_TEST_PRO_FLAG", "1");
        assert!(intent_declared("somethingelse", &spec(Some("NOO_TEST_PRO_FLAG"))));
        std::env::remove_var("NOO_TEST_PRO_FLAG");
        std::env::remove_var("NOO_EVOLVE_DB_PASSWORD");
    }

    #[test]
    fn flag_accepts_the_shell_truthy_set() {
        for v in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var("NOO_TEST_TRUTHY", v);
            assert!(intent_declared("somethingelse", &spec(Some("NOO_TEST_TRUTHY"))), "{v}");
        }
        for v in ["0", "false", "no", "off", ""] {
            std::env::set_var("NOO_TEST_TRUTHY", v);
            assert!(!intent_declared("somethingelse", &spec(Some("NOO_TEST_TRUTHY"))), "{v}");
        }
        std::env::remove_var("NOO_TEST_TRUTHY");
    }

    #[test]
    fn identifiers_are_restricted_to_bare_lowercase() {
        for ok in ["evolve", "noo_trellion", "s3", "a_b_2"] {
            assert!(valid_identifier(ok), "{ok} should be accepted");
        }
        for bad in [
            "",
            "Evolve",                    // quoting-sensitive when unquoted
            "public; DROP SCHEMA mesh", // the reason this function exists
            "noo-trellion",              // hyphen needs quoting
            "2fast",                     // cannot start with a digit
            "schema name",
        ] {
            assert!(!valid_identifier(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn password_literals_are_escaped() {
        assert_eq!(quote_literal("pa'ss"), "pa''ss");
        assert_eq!(quote_literal("'; DROP ROLE noo; --"), "''; DROP ROLE noo; --");
    }

    #[test]
    fn runtime_roles_get_no_escalation() {
        for negative in ["NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOBYPASSRLS"] {
            assert!(ROLE_ATTRS.contains(negative), "{negative} missing");
        }
    }

    // ── against a real catalogue ─────────────────────────────────────────
    //
    // The tests above check intent. These check that the intent reaches
    // Postgres, which is a different question and the one that has actually
    // burned this repo: the sqlx cutover shipped with no roles, no grants and
    // no ownership while every schema gate passed, because both gates dump
    // `--no-privileges` on both sides. Roles, grants and schema membership
    // are invisible in a schema diff. They are only visible if you look.
    //
    // Gated on NOO_BROKER_TEST_DSN so the default suite stays offline. CI's
    // `sqlx-drift` job sets it — it already runs a real pg18 service.

    use std::collections::BTreeMap;

    fn dsn() -> Option<String> {
        std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())
    }

    /// Namespace every object so repeat runs and parallel jobs cannot collide,
    /// and so a failure never leaves debris that looks like production.
    fn manifest(tag: &str, flag: Option<&str>) -> BTreeMap<String, SystemConfig> {
        let mut m = BTreeMap::new();
        m.insert(
            format!("t{tag}"),
            SystemConfig {
                role: format!("brokertest_role_{tag}"),
                ddl_role: format!("brokertest_ddl_{tag}"),
                schema: format!("brokertest_schema_{tag}"),
                enabled_when: flag.map(str::to_string),
                password_env: format!("BROKERTEST_PW_{tag}"),
                ddl_password_env: format!("BROKERTEST_DDLPW_{tag}"),
                extensions: Vec::new(),
            },
        );
        m
    }

    async fn pool(dsn: &str) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(dsn)
            .await
            .expect("connect to NOO_BROKER_TEST_DSN")
    }

    async fn cleanup(db: &PgPool, tag: &str) {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA IF EXISTS brokertest_schema_{tag} CASCADE")))
            .execute(db)
            .await;
        for role in [
            format!("brokertest_role_{tag}"),
            format!("brokertest_ddl_{tag}"),
        ] {
            // Default privileges are recorded against the granting role and
            // block DROP ROLE until removed, so a plain DROP would fail and
            // leave debris for the next run to trip over.
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {role} IN SCHEMA brokertest_schema_{tag} \
                 REVOKE ALL ON TABLES FROM PUBLIC"
            )))
            .execute(db)
            .await;
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role} CASCADE"))).execute(db).await;
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}"))).execute(db).await;
        }
    }

    #[tokio::test]
    async fn ddl_role_owns_the_schema_and_the_runtime_role_cannot_create() {
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "basic";
        cleanup(&db, tag).await;
        std::env::set_var("BROKERTEST_PW_basic", "ephemeral-not-a-secret");
        std::env::set_var("BROKERTEST_DDLPW_basic", "ephemeral-not-a-secret");

        reconcile(&db, &manifest(tag, None)).await.expect("reconcile");

        for role in [format!("brokertest_role_{tag}"), format!("brokertest_ddl_{tag}")] {
            let (canlogin, sup, cdb, crole, bypass): (bool, bool, bool, bool, bool) =
                sqlx::query_as(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls \
                     FROM pg_roles WHERE rolname = $1",
                )
                .bind(&role)
                .fetch_one(&db)
                .await
                .unwrap_or_else(|_| panic!("{role} was not created"));
            assert!(canlogin, "{role} must be able to log in");
            assert!(!sup && !cdb && !crole && !bypass, "{role}: escalation must be withheld");
        }

        let owner: String = sqlx::query_scalar(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1",
        )
        .bind(format!("brokertest_schema_{tag}"))
        .fetch_one(&db)
        .await
        .expect("schema was not created");
        assert_eq!(owner, format!("brokertest_ddl_{tag}"), "the DDL role must own the schema");

        // The asymmetry IS the design. If these two ever agree, the split has
        // silently collapsed and the runtime holds DDL rights permanently.
        let ddl_create: bool = sqlx::query_scalar("SELECT has_schema_privilege($1, $2, 'CREATE')")
            .bind(format!("brokertest_ddl_{tag}"))
            .bind(format!("brokertest_schema_{tag}"))
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(ddl_create, "the DDL role must be able to create in its own schema");

        let runtime_create: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, $2, 'CREATE')")
                .bind(format!("brokertest_role_{tag}"))
                .bind(format!("brokertest_schema_{tag}"))
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(!runtime_create, "the runtime role must NOT hold CREATE");

        let usage: bool = sqlx::query_scalar("SELECT has_schema_privilege($1, $2, 'USAGE')")
            .bind(format!("brokertest_role_{tag}"))
            .bind(format!("brokertest_schema_{tag}"))
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(usage, "the runtime role needs USAGE to reach its own schema");

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_PW_basic");
        std::env::remove_var("BROKERTEST_DDLPW_basic");
    }

    #[tokio::test]
    async fn a_table_the_ddl_role_creates_is_reachable_by_the_runtime_role() {
        // The property the default privileges exist for, and the one that
        // fails SILENTLY without them: a table created by the DDL role is
        // owned by the DDL role, and the runtime role has no access to it by
        // default. Nothing complains at migration time. The first query
        // against the new table is where you find out.
        //
        // Asserting the ALTER DEFAULT PRIVILEGES statement ran would not catch
        // this — written without `FOR ROLE <ddl>` it applies to the superuser's
        // objects, succeeds, and grants nothing. So this creates a real table
        // as the real role and asks the catalogue.
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "reach";
        cleanup(&db, tag).await;
        std::env::set_var("BROKERTEST_PW_reach", "ephemeral-not-a-secret");
        std::env::set_var("BROKERTEST_DDLPW_reach", "ephemeral-not-a-secret");

        reconcile(&db, &manifest(tag, None)).await.expect("reconcile");

        // ONE connection, acquired explicitly. `SET ROLE` is connection state,
        // so issuing it against the POOL sets it on whichever connection that
        // query happened to get — and the CREATE TABLE then runs on another
        // one, as the superuser. It succeeds either way. The first version of
        // this test did exactly that, and the table came out owned by `noo`,
        // which looked precisely like the default privileges being broken.
        let mut conn = db.acquire().await.expect("acquire");
        sqlx::query(sqlx::AssertSqlSafe(format!("SET ROLE brokertest_ddl_{tag}")))
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TABLE brokertest_schema_{tag}.after_provision (id int primary key)"
        )))
        .execute(&mut *conn)
        .await
        .expect("the DDL role must be able to create in its own schema");
        sqlx::query("RESET ROLE").execute(&mut *conn).await.unwrap();

        // Guard the guard: if this ever comes back `noo`, the test has stopped
        // testing what it says and every assertion below is vacuous.
        let owner: String = sqlx::query_scalar(
            "SELECT pg_get_userbyid(relowner) FROM pg_class \
             WHERE relnamespace = $1::regnamespace AND relname = 'after_provision'",
        )
        .bind(format!("brokertest_schema_{tag}"))
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(
            owner,
            format!("brokertest_ddl_{tag}"),
            "the table was not created BY the DDL role, so this test proves nothing"
        );
        drop(conn);

        for priv_name in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            let ok: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT has_table_privilege($1, $2, '{priv_name}')"
            )))
            .bind(format!("brokertest_role_{tag}"))
            .bind(format!("brokertest_schema_{tag}.after_provision"))
            .fetch_one(&db)
            .await
            .unwrap();
            assert!(
                ok,
                "the runtime role cannot {priv_name} a table its own migration just \
                 created — ALTER DEFAULT PRIVILEGES FOR ROLE is missing or misapplied"
            );
        }

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_PW_reach");
        std::env::remove_var("BROKERTEST_DDLPW_reach");
    }

    #[tokio::test]
    async fn is_idempotent_and_never_rewrites_an_existing_role() {
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "existing";
        cleanup(&db, tag).await;

        // Pre-create the role with an attribute the reconciler would never
        // set. If anything ALTERs the role, CREATEDB disappears and this
        // fails — a proxy for "the password was not rewritten either", which
        // cannot be read back directly.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE brokertest_role_{tag} LOGIN CREATEDB PASSWORD 'pre-existing'"
        )))
        .execute(&db)
        .await
        .unwrap();

        // Deliberately NO password in the environment: an existing role must
        // reconcile without one, because the credential is only ever needed
        // to CREATE.
        std::env::remove_var("BROKERTEST_PW_existing");
        std::env::remove_var("BROKERTEST_DDLPW_existing");
        // The DDL role must exist too, or reconcile fails on the credential
        // rather than exercising the "existing role is untouched" path.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE ROLE brokertest_ddl_{tag} LOGIN PASSWORD 'pre-existing'")))
            .execute(&db)
            .await
            .unwrap();

        for pass in 1..=2 {
            reconcile(&db, &manifest(tag, None))
                .await
                .unwrap_or_else(|e| panic!("pass {pass} failed: {e}"));
        }

        let still_createdb: bool =
            sqlx::query_scalar("SELECT rolcreatedb FROM pg_roles WHERE rolname = $1")
                .bind(format!("brokertest_role_{tag}"))
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            still_createdb,
            "the existing role was altered — nothing here may rewrite a live credential"
        );

        cleanup(&db, tag).await;
    }

    #[tokio::test]
    async fn a_disabled_system_is_not_provisioned() {
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "disabled";
        cleanup(&db, tag).await;

        // The credential IS present — as it is on every install, pro or not,
        // because noo-cli mints it unconditionally. Intent is absent. Nothing
        // may be created.
        std::env::set_var("BROKERTEST_PW_disabled", "ephemeral-not-a-secret");
        std::env::set_var("BROKERTEST_DDLPW_disabled", "ephemeral-not-a-secret");
        std::env::remove_var("BROKERTEST_DISABLED_FLAG");

        reconcile(&db, &manifest(tag, Some("BROKERTEST_DISABLED_FLAG")))
            .await
            .expect("a disabled system is not an error");

        let role_there: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(format!("brokertest_role_{tag}"))
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            !role_there,
            "a login role was created for a system nobody turned on — \
             this is the OSS-install noo_evolve bug, reproduced"
        );

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_PW_disabled");
        std::env::remove_var("BROKERTEST_DDLPW_disabled");
    }

    #[tokio::test]
    async fn declared_extensions_are_installed_idempotently() {
        // pg_trgm, deliberately: the CI service image ships its control file
        // but nothing installs it there, so this test genuinely exercises the
        // CREATE path. `vector` would usually be pre-installed by the
        // migrations and prove only the skip branch.
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "ext";
        cleanup(&db, tag).await;
        let _ = sqlx::query("DROP EXTENSION IF EXISTS pg_trgm CASCADE")
            .execute(&db)
            .await;
        std::env::set_var("BROKERTEST_PW_ext", "ephemeral-not-a-secret");
        std::env::set_var("BROKERTEST_DDLPW_ext", "ephemeral-not-a-secret");

        let mut m = manifest(tag, None);
        m.values_mut().next().unwrap().extensions = vec!["pg_trgm".into()];

        for pass in 1..=2 {
            reconcile(&db, &m)
                .await
                .unwrap_or_else(|e| panic!("pass {pass}: {e}"));
        }
        let installed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(installed, "pg_trgm was not installed by the broker");

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_PW_ext");
        std::env::remove_var("BROKERTEST_DDLPW_ext");
    }

    #[tokio::test]
    async fn a_hostile_extension_name_is_rejected_before_ddl() {
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "extbad";
        cleanup(&db, tag).await;
        std::env::set_var("BROKERTEST_PW_extbad", "ephemeral-not-a-secret");
        std::env::set_var("BROKERTEST_DDLPW_extbad", "ephemeral-not-a-secret");

        let mut m = manifest(tag, None);
        m.values_mut().next().unwrap().extensions =
            vec!["pg_trgm; DROP SCHEMA public".into()];

        let err = reconcile(&db, &m).await.expect_err("must reject");
        assert!(err.contains("identifier"), "got: {err}");

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_PW_extbad");
        std::env::remove_var("BROKERTEST_DDLPW_extbad");
    }

    #[tokio::test]
    async fn enabled_without_a_credential_fails_loudly() {
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "nocred";
        cleanup(&db, tag).await;

        std::env::set_var("BROKERTEST_NOCRED_FLAG", "1");
        std::env::remove_var("BROKERTEST_PW_nocred");
        std::env::remove_var("BROKERTEST_DDLPW_nocred");

        let err = reconcile(&db, &manifest(tag, Some("BROKERTEST_NOCRED_FLAG")))
            .await
            .expect_err("intent without a credential must not be silently skipped");
        assert!(
            err.contains("BROKERTEST_DDLPW_nocred"),
            "the error must name the missing variable, got: {err}"
        );

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_NOCRED_FLAG");
    }
}
