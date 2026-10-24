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
//! ON-DEMAND, WITHOUT AN API. `noo addons enable <name> --provision-only` needs
//! one system's schema and roles NOW, without composing the add-on or
//! restarting the gateway. It runs [`provision_system`] (the very function the
//! boot reconcile calls) through `noo-gateway provision-system`, reachable only
//! by `docker exec` into the container: no listener, no route, and the request
//! is validated by `addon_decls` like a bundle. See `system_provision_cli`.
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

use std::collections::BTreeMap;

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

/// The variable whose FILE carries every declared system's enable flag and
/// role passwords that no named compose line delivers.
///
/// The gateway container has no `env_file`: only variables compose names one
/// by one reach it. That is right for the systems core knows (trellion,
/// evolve — each has its own `_FILE` line), and it can never be right for a
/// system core does not know: core never names an add-on's system, so its
/// flag and passwords had no way in. The launcher (`lib-secrets.sh`
/// `_systems_secrets_body`) writes ONE file for all of them — `KEY=VALUE`
/// lines, 0400 to this container's uid — and compose mounts it with one
/// pointer, `NOO_SYSTEMS_SECRETS_FILE`. A new system needs no compose line,
/// no gateway change, and no entry in any list.
pub const SYSTEMS_SECRETS: &str = "NOO_SYSTEMS_SECRETS";

/// Parse the systems file: one `KEY=VALUE` per line, the value verbatim to the
/// end of the line (no quoting — the launcher refuses a multi-line value
/// rather than encode it). Blank lines, `#` lines, a line with no `=`, a key
/// that is not an env-var name and an empty value are ignored. A later line
/// for the same key wins (the launcher never writes two).
pub(crate) fn parse_delivered(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in body.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let key_ok = !k.is_empty()
            && !k.starts_with(|c: char| c.is_ascii_digit())
            && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if key_ok && !v.is_empty() {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

/// The systems file's contents, read once per reconcile. Not delivered
/// (no declared system needs it, or an older compose) is empty. An unreadable
/// file is logged and read as empty here; preflight refuses the same broken
/// mount on its own (`NOO_SYSTEMS_SECRETS` is in `FILE_BACKED_SECRETS`).
fn delivered() -> BTreeMap<String, String> {
    match crate::config::secret_env::secret(SYSTEMS_SECRETS) {
        Ok(Some(body)) => parse_delivered(&body),
        Ok(None) => BTreeMap::new(),
        Err(e) => {
            tracing::error!(secret = SYSTEMS_SECRETS, error = %e, "systems secrets file unreadable");
            BTreeMap::new()
        }
    }
}

/// A system's flag value: this process's environment first (a flag compose
/// names explicitly), then the systems file. An empty env value counts as
/// unset — compose's `${FLAG:-}` hands an empty string, not an absence.
fn flag_value(
    flag: &str,
    get: impl Fn(&str) -> Option<String>,
    delivered: &BTreeMap<String, String>,
) -> Option<String> {
    get(flag)
        .filter(|v| !v.trim().is_empty())
        .or_else(|| delivered.get(flag).cloned())
}

/// A system's role password: everything `secret_env` resolves for the name
/// (`NAME_FILE`, `NOO_SECRET_NAME`, `NAME` — the named delivery trellion and
/// evolve use) first, then the systems file. `Err` only for a named `_FILE`
/// that cannot be read: a broken mount, not a missing credential.
fn password_from(
    var: &str,
    get: impl Fn(&str) -> Option<String>,
    delivered: &BTreeMap<String, String>,
) -> Result<Option<String>, crate::config::secret_env::SecretError> {
    if let Some(v) = crate::config::secret_env::secret_from(var, get)?.filter(|p| !p.trim().is_empty()) {
        return Ok(Some(v));
    }
    Ok(delivered.get(var).filter(|p| !p.trim().is_empty()).cloned())
}

/// True when the operator has turned this system on.
///
/// `None` means unconditional — trellion, which is mandatory since the
/// container split and has no flag to check.
fn intent_declared(name: &str, spec: &SystemConfig, delivered: &BTreeMap<String, String>) -> bool {
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
    // A system that is NOT an add-on may still name a plain env flag — read
    // from this container's env, or from the systems file the launcher
    // writes for exactly this case (the flag never reaches the env: no
    // compose line names it).
    let Some(flag) = spec.enabled_when.as_deref() else {
        return true;
    };
    flag_value(flag, |k| std::env::var(k).ok(), delivered)
        .map(|v| TRUE_VALUES.contains(&v.trim().to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Does a missing credential stop the gateway? Only for a system core itself
/// declares (a row of `addons::ADDONS`: trellion, evolve). Those are
/// delivered by named compose lines and checked before `up` by
/// `noo config launch-check system-credentials`, so reaching here without
/// one is a broken install — the fail-closed rule that has stood since the
/// broker landed. Every other system is declared at runtime (an operator's
/// manifest entry, later an add-on bundle): one of those missing a password
/// must not take the gateway down with it, so it is logged at ERROR,
/// reported on /health, and skipped.
fn missing_credential_is_fatal(name: &str) -> bool {
    crate::addons::ADDONS.iter().any(|a| a.name == name)
}

/// Systems the boot-time reconcile could not provision, by name, with the
/// reason. Read by `/health` (`dependencies.systems`).
static UNPROVISIONED: std::sync::Mutex<BTreeMap<String, String>> = std::sync::Mutex::new(BTreeMap::new());

/// The systems the broker skipped because a credential was missing.
pub fn unprovisioned() -> BTreeMap<String, String> {
    UNPROVISIONED.lock().map(|m| m.clone()).unwrap_or_default()
}

/// Why `ensure_role` did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleError {
    /// The role must be created and its password is nowhere this process can
    /// see. `var` is the variable; `message` the operator-facing sentence.
    MissingCredential { var: String, message: String },
    /// Anything else: a database error, an unreadable `_FILE`.
    Other(String),
}

impl RoleError {
    fn into_message(self) -> String {
        match self {
            RoleError::MissingCredential { message, .. } | RoleError::Other(message) => message,
        }
    }
}

/// The first credential missing among the roles a reconcile must CREATE
/// (`to_create`: role and password variable, for roles that do not exist
/// yet), or `None` when every one is available. Checked for both roles before
/// either is created. `Err` for an unreadable `_FILE` (a broken mount).
fn first_missing(
    system: &str,
    to_create: &[(&str, &str)],
    get: impl Fn(&str) -> Option<String>,
    delivered: &BTreeMap<String, String>,
) -> Result<Option<RoleError>, String> {
    for (role, var) in to_create {
        if password_from(var, &get, delivered).map_err(|e| e.to_string())?.is_none() {
            return Ok(Some(missing_credential(system, role, var)));
        }
    }
    Ok(None)
}

fn missing_credential(system: &str, role: &str, password_env: &str) -> RoleError {
    RoleError::MissingCredential {
        var: password_env.to_string(),
        message: format!(
            "system {system:?} is enabled but {password_env} is not set, so the \
             {role:?} login role cannot be created. It will not be created with an \
             invented password — that leaves a credential nobody knows and every \
             operator assumes is in the store. Run `noo systems enable {system}`, \
             which mints it."
        ),
    }
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
    delivered: &BTreeMap<String, String>,
) -> Result<bool, RoleError> {
    if role_exists(db, role).await.map_err(|e| RoleError::Other(e.to_string()))? {
        return Ok(false);
    }

    let password = password_from(password_env, |k| std::env::var(k).ok(), delivered)
        .map_err(|e| RoleError::Other(e.to_string()))?
        .ok_or_else(|| missing_credential(system, role, password_env))?;

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} {ROLE_ATTRS} PASSWORD '{}'",
        quote_literal(&password)
    )))
    .execute(db)
    .await
    .map_err(|e| RoleError::Other(format!("CREATE ROLE {role} failed: {e}")))?;
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

/// What provisioning one system did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Provisioned {
    /// Login roles THIS call created (an existing role is never touched).
    pub roles_created: Vec<String>,
    /// Whether this call created the schema (an existing one is re-owned).
    pub schema_created: bool,
}

/// How provisioning one system ended. A missing credential is an outcome, not
/// an error: whether it stops the caller is the caller's decision (the boot
/// reconcile stops only for a core system; the on-demand path always does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Provisioned(Provisioned),
    MissingCredential { var: String, message: String },
}

/// Provision ONE system: validate its identifiers, check every credential a
/// role this pass must create needs, then roles (DDL first), schema and
/// extensions. The single implementation both the boot reconcile ([`reconcile`])
/// and the on-demand path (`noo addons enable --provision-only`, via
/// `noo-gateway provision-system`) run, so the two can never diverge. It does
/// NOT consult the system's enable flag: intent is the caller's to decide.
pub(crate) async fn provision_system(
    db: &PgPool,
    name: &str,
    spec: &SystemConfig,
    delivered: &BTreeMap<String, String>,
) -> Result<Outcome, String> {
    for ident in [&spec.role, &spec.ddl_role, &spec.schema] {
        if !valid_identifier(ident) {
            return Err(format!(
                "system {name:?} declares {ident:?}, which is not a bare lowercase \
                 SQL identifier. These names are interpolated into DDL."
            ));
        }
    }

    // Every credential this pass needs, checked BEFORE either role is
    // created: a system whose runtime password is missing must not leave
    // a half-made migration role behind (and a skipped system creates
    // nothing at all). Only a role that does not exist yet needs one.
    let roles = [(&spec.ddl_role, &spec.ddl_password_env), (&spec.role, &spec.password_env)];
    let mut to_create: Vec<(&str, &str)> = Vec::new();
    for (role, var) in roles {
        if !role_exists(db, role).await.map_err(|e| e.to_string())? {
            to_create.push((role.as_str(), var.as_str()));
        }
    }
    match first_missing(name, &to_create, |k| std::env::var(k).ok(), delivered)? {
        None => {}
        Some(RoleError::MissingCredential { var, message }) => {
            return Ok(Outcome::MissingCredential { var, message })
        }
        Some(RoleError::Other(e)) => return Err(e),
    }

    // The DDL role first: it owns the schema, so it has to exist before
    // the schema can be created AUTHORIZATION it.
    let mut roles_created = Vec::new();
    for (role, var) in roles {
        if ensure_role(db, name, role, var, delivered).await.map_err(RoleError::into_message)? {
            roles_created.push(role.clone());
        }
    }
    let schema_created = ensure_schema(db, name, spec).await?;
    ensure_extensions(db, name, spec).await?;
    Ok(Outcome::Provisioned(Provisioned { roles_created, schema_created }))
}

/// Reconcile every declared system. Idempotent; safe on every boot.
///
/// Called from the migration path with the PRIVILEGED pool — a runtime role
/// cannot create roles or schemas, which is the entire point of the split.
pub async fn run(db: &PgPool) -> Result<(), String> {
    let (systems, conflicts) = with_addon_systems(&crate::config::global().systems, crate::addon_registry::declared_systems());
    for (name, why) in &conflicts {
        tracing::warn!(system = %name, "{why}");
    }
    let skipped = reconcile(db, &systems).await?;
    if let Ok(mut m) = UNPROVISIONED.lock() {
        *m = skipped;
    }
    Ok(())
}

/// The systems to reconcile: the `systems:` manifest in `noomesh.yaml`, plus
/// every system a REGISTERED add-on's signed bundle declares
/// (`addon_registry::declared_systems`, i163 E: switched on, lock verified,
/// `system.json` valid). Pure.
///
/// A name in both: `noomesh.yaml` wins and the bundle's entry is dropped,
/// with a warning returned per name. Why not refuse: the `noomesh.yaml` entry
/// is what this database was provisioned from until now (a hand-made entry
/// from before bundles declared systems), so keeping it changes nothing that
/// runs; refusing would take a working add-on's schema out of the reconcile
/// over a line the operator can delete. The bundle's names are fixed by the
/// add-on name, so the two can only differ in variable names or extensions,
/// and the warning says how to converge (delete the `systems:` entry).
pub(crate) fn with_addon_systems(
    manifest: &BTreeMap<String, SystemConfig>,
    bundle: BTreeMap<String, SystemConfig>,
) -> (BTreeMap<String, SystemConfig>, Vec<(String, String)>) {
    let mut out = manifest.clone();
    let mut conflicts = Vec::new();
    for (name, spec) in bundle {
        if out.contains_key(&name) {
            conflicts.push((
                name.clone(),
                format!(
                    "system {name:?} is declared both in noomesh.yaml `systems:` and by the add-on's signed bundle \
                     (system.json); the noomesh.yaml entry wins. Bundle-declared systems need no noomesh.yaml entry: \
                     remove `systems.{name}` from noomesh.yaml to provision it from the bundle"
                ),
            ));
            continue;
        }
        out.insert(name, spec);
    }
    (out, conflicts)
}

/// The reconciler proper, taking the manifest explicitly so it can be tested
/// against a real database without a config file on disk. Returns the
/// systems it skipped for a missing credential (name → reason); [`run`]
/// publishes them for `/health`.
pub async fn reconcile(
    db: &PgPool,
    systems: &BTreeMap<String, SystemConfig>,
) -> Result<BTreeMap<String, String>, String> {
    if systems.is_empty() {
        return Ok(BTreeMap::new());
    }

    let delivered = delivered();
    let mut provisioned = 0usize;
    let mut skipped = 0usize;
    let mut unprovisioned = BTreeMap::new();

    for (name, spec) in systems {
        if !intent_declared(name, spec, &delivered) {
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

        match provision_system(db, name, spec, &delivered).await? {
            Outcome::Provisioned(_) => provisioned += 1,
            Outcome::MissingCredential { message, .. } if missing_credential_is_fatal(name) => {
                return Err(message)
            }
            Outcome::MissingCredential { var, message } => {
                tracing::error!(
                    system = name,
                    variable = %var,
                    error = %message,
                    "system NOT provisioned: a role password is missing — skipping this system, the gateway keeps booting"
                );
                unprovisioned.insert(name.clone(), format!("{var} is not set"));
            }
        }
    }

    tracing::info!(provisioned, skipped, unprovisioned = unprovisioned.len(), "systems reconciled");
    Ok(unprovisioned)
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
        assert!(intent_declared("somethingelse", &spec(None), &BTreeMap::new()));
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
            !intent_declared("evolve", &spec(Some("NOO_TEST_STALE_FLAG")), &BTreeMap::new()),
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
            !intent_declared("somethingelse", &spec(Some("NOO_TEST_PRO_FLAG")), &BTreeMap::new()),
            "a set password must not stand in for a declared intent"
        );

        std::env::set_var("NOO_TEST_PRO_FLAG", "1");
        assert!(intent_declared("somethingelse", &spec(Some("NOO_TEST_PRO_FLAG")), &BTreeMap::new()));
        std::env::remove_var("NOO_TEST_PRO_FLAG");
        std::env::remove_var("NOO_EVOLVE_DB_PASSWORD");
    }

    #[test]
    fn flag_accepts_the_shell_truthy_set() {
        for v in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var("NOO_TEST_TRUTHY", v);
            assert!(intent_declared("somethingelse", &spec(Some("NOO_TEST_TRUTHY")), &BTreeMap::new()), "{v}");
        }
        for v in ["0", "false", "no", "off", ""] {
            std::env::set_var("NOO_TEST_TRUTHY", v);
            assert!(!intent_declared("somethingelse", &spec(Some("NOO_TEST_TRUTHY")), &BTreeMap::new()), "{v}");
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

    // ── the systems file: a system core does not name ───────────────────

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: BTreeMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn the_systems_file_parses_key_value_lines_verbatim() {
        let got = parse_delivered(
            "NOO_EXAMPLE_ADDON_ENABLED=1\nNOO_EXAMPLE_ADDON_DB_PASSWORD=a=b c'\"\\\n\n# note\nnot a line\nlower=x\n9BAD=x\nNOO_EMPTY=\n",
        );
        assert_eq!(got.get("NOO_EXAMPLE_ADDON_ENABLED").map(String::as_str), Some("1"));
        assert_eq!(
            got.get("NOO_EXAMPLE_ADDON_DB_PASSWORD").map(String::as_str),
            Some("a=b c'\"\\"),
            "the value runs to the end of the line, untouched"
        );
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn a_bundle_system_joins_the_manifest_and_noomesh_yaml_wins_a_clash() {
        let bundle_spec = |id: &str| SystemConfig {
            role: format!("noo_{id}"),
            ddl_role: format!("noo_{id}_ddl"),
            schema: id.to_string(),
            enabled_when: None,
            password_env: format!("NOO_{}_DB_PASSWORD", id.to_ascii_uppercase()),
            ddl_password_env: format!("NOO_{}_DDL_PASSWORD", id.to_ascii_uppercase()),
            extensions: vec!["pg_trgm".into()],
        };
        let manifest = BTreeMap::from([("evolve".to_string(), spec(None))]);
        let bundle = BTreeMap::from([("example_addon".to_string(), bundle_spec("example_addon"))]);
        let (merged, conflicts) = with_addon_systems(&manifest, bundle);
        assert!(conflicts.is_empty());
        assert_eq!(merged.len(), 2);
        assert_eq!(merged["example_addon"].password_env, "NOO_EXAMPLE_ADDON_DB_PASSWORD");
        assert!(intent_declared("example_addon", &merged["example_addon"], &BTreeMap::new()), "no flag: the registry gated it");
        assert!(!missing_credential_is_fatal("example_addon"), "a bundle system missing a password is skipped, never fatal");

        // Declared in both: noomesh.yaml's entry is kept, untouched, and the
        // clash is reported by name.
        let mut mine = bundle_spec("example_addon");
        mine.password_env = "NOO_HAND_MADE_PASSWORD".into();
        let manifest = BTreeMap::from([("example_addon".to_string(), mine)]);
        let bundle = BTreeMap::from([("example_addon".to_string(), bundle_spec("example_addon"))]);
        let (merged, conflicts) = with_addon_systems(&manifest, bundle);
        assert_eq!(merged["example_addon"].password_env, "NOO_HAND_MADE_PASSWORD");
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].1.contains("noomesh.yaml entry wins"), "{}", conflicts[0].1);
    }

    #[test]
    fn a_flag_only_the_systems_file_carries_enables_the_system() {
        // The bug this file exists for: `noo systems enable example_addon` set
        // the flag in .env, no compose line named it, and the broker read it
        // as off. With the file the flag arrives.
        let delivered = parse_delivered("NOO_TEST_EXAMPLE_ADDON_FLAG=1\n");
        std::env::remove_var("NOO_TEST_EXAMPLE_ADDON_FLAG");
        assert!(intent_declared("example_addon", &spec(Some("NOO_TEST_EXAMPLE_ADDON_FLAG")), &delivered));
        assert!(!intent_declared("example_addon", &spec(Some("NOO_TEST_EXAMPLE_ADDON_FLAG")), &BTreeMap::new()));
    }

    #[test]
    fn the_environment_wins_over_the_systems_file() {
        let delivered = parse_delivered("FLAG=1\nPW=from-file\n");
        // A flag compose names explicitly is the env's answer, including "off".
        assert_eq!(flag_value("FLAG", lookup(&[("FLAG", "0")]), &delivered).as_deref(), Some("0"));
        // compose's `${FLAG:-}` hands an EMPTY string: that is unset, not "off".
        assert_eq!(flag_value("FLAG", lookup(&[("FLAG", "")]), &delivered).as_deref(), Some("1"));
        assert_eq!(flag_value("FLAG", lookup(&[]), &delivered).as_deref(), Some("1"));
        assert_eq!(flag_value("FLAG", lookup(&[]), &BTreeMap::new()), None);

        // Passwords: the named delivery (plain, NOO_SECRET_, _FILE) first.
        assert_eq!(password_from("PW", lookup(&[("PW", "from-env")]), &delivered).unwrap().as_deref(), Some("from-env"));
        assert_eq!(
            password_from("PW", lookup(&[("NOO_SECRET_PW", "from-prefix")]), &delivered).unwrap().as_deref(),
            Some("from-prefix")
        );
        assert_eq!(password_from("PW", lookup(&[("PW", "  ")]), &delivered).unwrap().as_deref(), Some("from-file"));
        assert_eq!(password_from("PW", lookup(&[]), &delivered).unwrap().as_deref(), Some("from-file"));
        assert_eq!(password_from("PW", lookup(&[]), &BTreeMap::new()).unwrap(), None);
        // A named `_FILE` that cannot be read is a broken mount: an error,
        // never a quiet fall-through to the systems file.
        let broken = lookup(&[("PW_FILE", "/nonexistent/system-provision-test/pw")]);
        assert!(password_from("PW", broken, &delivered).is_err());
    }

    #[test]
    fn both_passwords_are_checked_before_either_role_is_created() {
        // The half-provisioned case: the DDL password is there, the runtime
        // one is not. The old reconcile created the DDL role, THEN found the
        // runtime password missing. Now the check covers both up front.
        let delivered = parse_delivered("NOO_EX_DDL=d\n");
        let both = [("noo_ex_ddl", "NOO_EX_DDL"), ("noo_ex", "NOO_EX_PW")];
        let got = first_missing("example_addon", &both, lookup(&[]), &delivered).unwrap();
        assert!(
            matches!(&got, Some(RoleError::MissingCredential { var, .. }) if var == "NOO_EX_PW"),
            "{got:?}"
        );
        // A role that already exists needs no password: only the ones to
        // create are checked.
        let ddl_only = [("noo_ex_ddl", "NOO_EX_DDL")];
        assert_eq!(first_missing("example_addon", &ddl_only, lookup(&[]), &delivered).unwrap(), None);
        assert_eq!(first_missing("example_addon", &[], lookup(&[]), &BTreeMap::new()).unwrap(), None);
        // An unreadable `_FILE` is an error, not a missing credential.
        let broken = lookup(&[("NOO_EX_PW_FILE", "/nonexistent/system-provision-test/pw")]);
        assert!(first_missing("example_addon", &both, broken, &delivered).is_err());
    }

    #[test]
    fn a_missing_password_stops_the_gateway_only_for_a_system_core_declares() {
        // trellion and evolve keep the fail-closed rule: named compose lines
        // deliver their credentials and the launcher checks them before `up`.
        for core in ["trellion", "evolve"] {
            assert!(missing_credential_is_fatal(core), "{core}");
        }
        // A system declared at runtime is skipped, not fatal.
        assert!(!missing_credential_is_fatal("example_addon"));
        let RoleError::MissingCredential { var, message } =
            missing_credential("example_addon", "noo_example_addon_ddl", "NOO_EXAMPLE_ADDON_DDL_PASSWORD")
        else {
            panic!("a missing password must be its own kind of error")
        };
        assert_eq!(var, "NOO_EXAMPLE_ADDON_DDL_PASSWORD");
        assert!(message.contains("example_addon") && message.contains("NOO_EXAMPLE_ADDON_DDL_PASSWORD"), "{message}");
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
    async fn enabled_without_a_credential_is_reported_and_skipped_not_fatal() {
        // A system core does not declare (not a row of addons::ADDONS) that
        // is enabled with no password: it used to fail the whole reconcile,
        // and mesh_migrate exits(1) on that — one runtime-declared system
        // took the gateway down. Now it is skipped, named, and nothing is
        // created for it. (trellion / evolve keep the fatal path:
        // `a_missing_password_stops_the_gateway_only_for_a_system_core_declares`.)
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "nocred";
        cleanup(&db, tag).await;

        std::env::set_var("BROKERTEST_NOCRED_FLAG", "1");
        std::env::remove_var("BROKERTEST_PW_nocred");
        std::env::remove_var("BROKERTEST_DDLPW_nocred");

        let why = reconcile(&db, &manifest(tag, Some("BROKERTEST_NOCRED_FLAG")))
            .await
            .expect("a runtime-declared system missing a credential must not fail the reconcile");
        assert!(
            why.get("tnocred").is_some_and(|r| r.contains("BROKERTEST_DDLPW_nocred")),
            "the skip must name the system and the missing variable, got: {why:?}"
        );
        assert!(!role_exists(&db, "brokertest_ddl_nocred").await.unwrap());
        assert!(!schema_exists(&db, "brokertest_schema_nocred").await.unwrap());

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_NOCRED_FLAG");
    }

    #[tokio::test]
    async fn a_missing_runtime_password_leaves_no_half_made_migration_role() {
        // The DDL password is present, the runtime one is not. Both are
        // checked before either role is created, so the system is skipped
        // with nothing created — not left with a DDL role and no schema.
        let Some(dsn) = dsn() else { return };
        let db = pool(&dsn).await;
        let tag = "halfcred";
        cleanup(&db, tag).await;

        std::env::set_var("BROKERTEST_HALFCRED_FLAG", "1");
        std::env::set_var("BROKERTEST_DDLPW_halfcred", "ddl-present");
        std::env::remove_var("BROKERTEST_PW_halfcred");

        let why = reconcile(&db, &manifest(tag, Some("BROKERTEST_HALFCRED_FLAG")))
            .await
            .expect("a runtime-declared system missing a credential must not fail the reconcile");
        assert!(
            why.get("thalfcred").is_some_and(|r| r.contains("BROKERTEST_PW_halfcred")),
            "got: {why:?}"
        );
        assert!(!role_exists(&db, "brokertest_ddl_halfcred").await.unwrap(), "a half-made migration role was left");
        assert!(!role_exists(&db, "brokertest_role_halfcred").await.unwrap());

        cleanup(&db, tag).await;
        std::env::remove_var("BROKERTEST_HALFCRED_FLAG");
        std::env::remove_var("BROKERTEST_DDLPW_halfcred");
    }
}
