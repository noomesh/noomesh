// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Native migration runner for the mesh schema — the design.
//!
//! This runner now owns the mesh migration chain for everything authored
//! after the frozen Alembic baseline ([`BASELINE_REVISION`], `046_...`): it reads the existing
//! Alembic state, computes what it would apply, and is provable against
//! `noo db current`. As of this writing [`MIGRATIONS`] holds 35 entries
//! starting at `047_audit_drop_partition_fn` with the chain head at
//! `081_host_login_tickets`. A schema change now means appending a
//! `Migration { revision, down_revision, sql }` entry to [`MIGRATIONS`],
//! not a new Python/Alembic revision.
//!
//! Porting the chain onto this runner was staged deliberately: a broken
//! migration runner means nothing starts, for everyone — it is the worst
//! blast radius in the system — so the mechanism was proven while it still
//! carried zero migrations and could do no damage, before the live chain
//! moved onto it.
//!
//! ## Why not `sqlx::migrate!`
//!
//! The obvious choice, and the wrong one. It tracks state in
//! `_sqlx_migrations`, which knows nothing about the 46 revisions already
//! stamped on every existing install. Adopting it means either re-running the
//! chain from empty (destructive) or hand-stamping every deployment.
//!
//! This runner keeps reading and writing **`alembic_version_mesh`**. That
//! buys three things:
//!   - existing installs need no stamping; they are already at the right
//!     revision
//!   - Python remains a working rollback for as long as both chains agree
//!   - `noo db current` / `history` keep working unchanged
//!
//! ## The version column is varchar(32)
//!
//! Measured 2026-08-03: the longest revision ids in the tree are 31
//! characters (`046_heartbeat_run_prune_staging`). One more character and an
//! INSERT fails at runtime. `revision_fits_version_column` pins this, because
//! the failure would otherwise land in a migration, at startup, in
//! production.

use sqlx::PgPool;

/// The Alembic version table this runner shares with Python. NOT
/// `_sqlx_migrations` — see the module docs.
pub const VERSION_TABLE: &str = "alembic_version_mesh";

/// Alembic's `version_num` column width. Revision ids must fit.
pub const VERSION_COLUMN_LEN: usize = 32;

/// One ported revision. `sql` runs inside the same transaction that advances
/// the version row, so a failure leaves the stamp untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub revision: &'static str,
    /// `None` marks the base of the chain.
    pub down_revision: Option<&'static str>,
    pub sql: &'static str,
}

/// The statements that make `noo_security_audit` INSERT/SELECT-only for the
/// application role: REVOKE UPDATE, DELETE and TRUNCATE on the parent and on
/// every partition (a partition is its own relation with its own ACL, and
/// default privileges hand the app role full DML on each new one).
///
/// A macro, not a const, so revision 092 (a `&'static str`, which `concat!`
/// builds) and the boot-time re-assertion ([`enforce_audit_append_only`]) share ONE
/// text. The re-assertion exists because `role_provision::grant_runtime_access`
/// and `system_provision` re-issue `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL
/// TABLES` on every migration run, which would otherwise undo the revoke the
/// next time the gateway boots.
///
/// Guarded by pg_roles like every other grant here: a role-less fixture DB
/// (schema-only replays) has no app role to restrict and must still migrate.
macro_rules! audit_append_only_sql {
    () => {
        r#"
DO $audit_append_only$
DECLARE
    r record;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        FOR r IN
            SELECT c.oid::regclass AS rel
              FROM pg_class c
             WHERE (c.relname = 'noo_security_audit' AND c.relkind = 'p')
                OR c.oid IN (SELECT i.inhrelid
                               FROM pg_inherits i
                               JOIN pg_class p ON p.oid = i.inhparent
                              WHERE p.relname = 'noo_security_audit' AND p.relkind = 'p')
        LOOP
            EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM noo_app', r.rel);
        END LOOP;
    END IF;
END
$audit_append_only$;
"#
    };
}

/// [`audit_append_only_sql`] as a string, for the boot-time re-assertion.
pub const AUDIT_APPEND_ONLY_SQL: &str = audit_append_only_sql!();

/// The audit hash chain and the append-only grant. See the entry in
/// [`MIGRATIONS`].
pub const AUDIT_CHAIN_REVISION: &str = "094_audit_chain_append_only";

/// Re-assert that the application role cannot UPDATE or DELETE an audit row.
/// Runs at the end of [`apply`], after every step that re-grants DML on all
/// tables. Idempotent; a no-op where `noo_app` does not exist.
pub async fn enforce_audit_append_only(db: &PgPool) -> Result<(), String> {
    sqlx::raw_sql(AUDIT_APPEND_ONLY_SQL)
        .execute(db)
        .await
        .map(|_| ())
        .map_err(|e| format!("could not restrict the application role on noo_security_audit: {e}"))
}

/// Revisions authored AFTER the cut-over. Everything up to and including
/// [`BASELINE_REVISION`] is covered by the baseline, not by entries here.
/// New schema changes are appended here as SQL from now on.
pub const MIGRATIONS: &[Migration] = &[Migration {
    revision: "047_audit_drop_partition_fn",
    down_revision: Some("046_heartbeat_run_prune_staging"),
    // The DROP twin of 036's `noo_ensure_audit_partition`, for the same
    // reason: partition DDL needs the table's OWNER, and the worker that
    // archives audit partitions is dropping to a non-superuser identity
    // SECURITY DEFINER runs as the function's owner (`noo`),
    // with the same hardening 036 documented — pinned search_path, the name
    // BUILT from integer arguments so the caller cannot touch an arbitrary
    // table, and range checks first.
    //
    // Two guards 036 does not need, because dropping is destructive where
    // creating is not:
    //   * refuses the current and next month outright — the live partitions
    //     an insert could be heading for, regardless of what the caller's
    //     retention arithmetic concluded;
    //   * DETACH + DROP in the function's own transaction, same as the
    //     Python original, so the planner never sees a half-removed child.
    //
    // EXECUTE is revoked from PUBLIC and granted to noo_app — the worker
    // plane's post-flip identity. Callers decide WHEN (after a verified
    // export); this function only bounds WHAT.
    sql: r#"
CREATE OR REPLACE FUNCTION noo_drop_audit_partition(p_year int, p_month int)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = mesh, public, pg_catalog
AS $body$
DECLARE
    v_name text;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;
    IF make_date(p_year, p_month, 1)
       >= date_trunc('month', now())::date THEN
        RAISE EXCEPTION
            'refusing to drop current or future audit partition %-%',
            p_year, p_month;
    END IF;

    v_name := format('noo_security_audit_%s_%s',
                     to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));

    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name AND relkind = 'r') THEN
        RETURN false;
    END IF;

    EXECUTE format(
        'ALTER TABLE noo_security_audit DETACH PARTITION %I', v_name);
    EXECUTE format('DROP TABLE %I', v_name);
    RETURN true;
END;
$body$;

REVOKE ALL ON FUNCTION noo_drop_audit_partition(int, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION noo_drop_audit_partition(int, int) TO noo_app;
"#,
},
Migration {
    revision: "048_token_usage",
    down_revision: Some("047_audit_drop_partition_fn"),
    // Token-usage accounting: one row per inference
    // completion — node, backend, model, source plane, prompt/completion
    // tokens. Partitioned by month from day one, like the audit table:
    // the per-month view falls out of partition pruning, and retention
    // later becomes a partition drop instead of a mass DELETE.
    //
    // `noo_ensure_usage_partition` is 036's `noo_ensure_audit_partition`
    // with the table swapped, hardening included: partition DDL needs the
    // table's OWNER, and the writer runs as `noo_app` — SECURITY DEFINER
    // runs as the function's owner (`noo`), with a pinned search_path,
    // range checks first, and the name BUILT from integer arguments so
    // the caller cannot touch an arbitrary table.
    //
    // Partitions are ensured lazily: `usage.rs` calls this function and
    // retries once when an INSERT lands in a month with no partition, so
    // there is no monthly cron to forget. The two SELECTs below only seed
    // the current and next month so the very first insert doesn't pay the
    // heal path.
    //
    // The grants are wrapped in a pg_roles guard: a role-less fixture DB
    // (schema-only baseline replays) must still migrate.
    sql: r#"
CREATE TABLE noo_token_usage (
    id                bigint GENERATED ALWAYS AS IDENTITY,
    ts                timestamptz NOT NULL DEFAULT now(),
    node_id           text,
    backend           text NOT NULL,
    model             text NOT NULL,
    source            text NOT NULL,
    user_id           uuid,
    prompt_tokens     integer NOT NULL,
    completion_tokens integer NOT NULL,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX noo_token_usage_ts_idx ON noo_token_usage (ts);
CREATE INDEX noo_token_usage_node_ts_idx ON noo_token_usage (node_id, ts);

CREATE FUNCTION noo_ensure_usage_partition(p_year integer, p_month integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'mesh', 'public', 'pg_catalog'
AS $body$
DECLARE
    v_name  text;
    v_start date;
    v_end   date;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;

    -- Name is BUILT here, never passed in: the caller cannot name an
    -- arbitrary table or re-parent the partition.
    v_name  := format('noo_token_usage_%s_%s',
                      to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    v_start := make_date(p_year, p_month, 1);
    v_end   := (v_start + interval '1 month')::date;

    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
        RETURN false;
    END IF;

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF noo_token_usage '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);
    RETURN true;
END;
$body$;

REVOKE ALL ON FUNCTION noo_ensure_usage_partition(integer, integer) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT INSERT, SELECT ON noo_token_usage TO noo_app;
        GRANT EXECUTE ON FUNCTION noo_ensure_usage_partition(integer, integer) TO noo_app;
    END IF;
END $$;

SELECT noo_ensure_usage_partition(
    EXTRACT(YEAR FROM now())::int, EXTRACT(MONTH FROM now())::int);
SELECT noo_ensure_usage_partition(
    EXTRACT(YEAR FROM now() + interval '1 month')::int,
    EXTRACT(MONTH FROM now() + interval '1 month')::int);
"#,
},
Migration {
    revision: "049_usage_rollup",
    down_revision: Some("048_token_usage"),
    // Retention layer for 048's raw usage rows, per the operator's spec:
    // RAW per-completion rows for the trailing ~3 months (daily and finer
    // grain), a MONTHLY rollup for the long term. `noo_token_usage_monthly`
    // holds one row per (month, node, backend, model, source) — the exact
    // grouping set the summary endpoint serves — so dropping a raw
    // partition loses grain, never totals. node_id is NOT NULL DEFAULT ''
    // where the raw column is nullable: '' means a cloud completion,
    // matching the endpoint's COALESCE convention, because a nullable
    // primary-key column is not a thing Postgres allows.
    //
    // `noo_drop_usage_partition` is 047's audit DROP twin with the table
    // swapped, hardening included: SECURITY DEFINER (partition DDL needs
    // the table's OWNER, and the rollup runs as `noo_app`), pinned
    // search_path, RANGE checks first, and the name BUILT from integer
    // arguments so the caller cannot touch an arbitrary table. It refuses
    // the current and future months OUTRIGHT — the live partitions an
    // insert could be heading for — regardless of what the caller's
    // retention arithmetic concluded; a bug in the rollup's cutoff math
    // must not be able to drop this month's rows.
    //
    // noo_app gets UPDATE on the monthly table because the rollup's
    // insert is `ON CONFLICT ... DO UPDATE` (a re-run after a failed drop
    // replaces the row rather than erroring). Grants are wrapped in the
    // same pg_roles guard as 048: a role-less fixture DB (schema-only
    // baseline replays) must still migrate.
    sql: r#"
CREATE TABLE noo_token_usage_monthly (
    month             date   NOT NULL,
    node_id           text   NOT NULL DEFAULT '',
    backend           text   NOT NULL,
    model             text   NOT NULL,
    source            text   NOT NULL,
    prompt_tokens     bigint NOT NULL,
    completion_tokens bigint NOT NULL,
    requests          bigint NOT NULL,
    PRIMARY KEY (month, node_id, backend, model, source)
);

CREATE OR REPLACE FUNCTION noo_drop_usage_partition(p_year integer, p_month integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = mesh, public, pg_catalog
AS $body$
DECLARE
    v_name text;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;
    IF make_date(p_year, p_month, 1)
       >= date_trunc('month', now())::date THEN
        RAISE EXCEPTION
            'refusing to drop current or future usage partition %-%',
            p_year, p_month;
    END IF;

    v_name := format('noo_token_usage_%s_%s',
                     to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));

    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name AND relkind = 'r') THEN
        RETURN false;
    END IF;

    EXECUTE format(
        'ALTER TABLE noo_token_usage DETACH PARTITION %I', v_name);
    EXECUTE format('DROP TABLE %I', v_name);
    RETURN true;
END;
$body$;

REVOKE ALL ON FUNCTION noo_drop_usage_partition(integer, integer) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE ON noo_token_usage_monthly TO noo_app;
        GRANT EXECUTE ON FUNCTION noo_drop_usage_partition(integer, integer) TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "050_user_roles",
    down_revision: Some("049_usage_rollup"),
    // Roles, not scopes: every account gets exactly one of
    // `user` / `operator` / `admin`, a STRICT cascade (Admin ⊃ Operator ⊃
    // User) enforced in `auth::Role` as an ordered enum — checks are
    // `role >= operator`, never scope-string enumerations. The `role` column
    // is the source of truth from here on; the `scopes` jsonb column stays
    // for the one-release dual-accept window (validators accept old scope
    // claims AND new role claims; token issuance emits both, deriving the
    // legacy scopes from the role: user→["read"], operator→["read","write"],
    // admin→["read","write","admin"]). Non-tier scopes ("ingest", "peer")
    // are NOT roles and keep living in `scopes`.
    //
    // Backfill maps the old grant to the role it always meant:
    // admin→admin, else write→operator, else user. `scopes` is jsonb
    // (an array of strings — see noo_users in the baseline), so containment
    // is jsonb `@>` against a one-element array, same operator the runtime
    // admin census uses.
    //
    // The CHECK is belt-and-braces under the app-level FromStr: a row a
    // migration or hand-edit pushes out of the enum must fail loudly here,
    // not silently resolve to `user` at validation time.
    sql: r#"
ALTER TABLE noo_users
    ADD COLUMN role text NOT NULL DEFAULT 'user'
    CONSTRAINT noo_users_role_check CHECK (role IN ('user', 'operator', 'admin'));

UPDATE noo_users SET role = CASE
    WHEN scopes @> '["admin"]'::jsonb THEN 'admin'
    WHEN scopes @> '["write"]'::jsonb THEN 'operator'
    ELSE 'user'
END;
"#,
},
Migration {
    revision: "051_bootstrap_tokens",
    down_revision: Some("050_user_roles"),
    // Bootstrap-token enrollment (the Kubernetes kubeadm
    // pattern): a short-lived, single-use token lets a brand-new host pull
    // the controller's SSH public key + sudoers line over
    // `POST /api/cluster/bootstrap` without any pre-shared credential.
    //
    // Only the sha256 HEX of the token is stored — the raw 32-byte value is
    // returned exactly once at mint time and never persisted, mirroring
    // `noo_refresh_tokens`. So a DB read yields nothing usable: the hash
    // cannot be replayed against the verifier, which hashes the presented
    // raw token and compares.
    //
    // Single-use is enforced by the consumer's
    // `UPDATE … SET used_at = now() WHERE … used_at IS NULL RETURNING id`
    // (routes/bootstrap.rs) — the row-level lock makes concurrent redeemers
    // serialize and exactly one observe `used_at IS NULL`. No DELETE grant:
    // spent/expired/revoked rows stay as the audit trail the followup asks
    // for (who minted, when used, from which IP).
    //
    // The grants are wrapped in a pg_roles guard: a role-less fixture DB
    // (schema-only baseline replays) must still migrate.
    sql: r#"
CREATE TABLE noo_bootstrap_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   text NOT NULL UNIQUE,
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    used_by_ip   text,
    revoked      boolean NOT NULL DEFAULT false,
    role_hint    text,
    allowed_cidr text
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE ON noo_bootstrap_tokens TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "052_bootstrap_node_binding",
    down_revision: Some("051_bootstrap_tokens"),
    // Bind a bootstrap token to ONE node name at mint time (operator
    // decision, 2026-08-18): a leaked token can then only enroll as that
    // name, and redemption records everything the fleet inventory needs
    // (name + source IP + enrolling user), which kills the manual
    // inventory edit in the fresh-onboard flow — provision-node resolves
    // the node from the redeemed token instead.
    sql: r#"
ALTER TABLE noo_bootstrap_tokens
    ADD COLUMN IF NOT EXISTS node_name  text,
    ADD COLUMN IF NOT EXISTS enroll_user text;
"#,
},
Migration {
    revision: "053_birth_pull_provisioning",
    down_revision: Some("052_bootstrap_node_binding"),
    // Pull provisioning: the enrolling node
    // generates a BIRTH keypair and sends its self-signed cert + machine
    // facts with the redemption; `noo cluster provision` then builds the
    // usual CA-signed bundle, ENCRYPTS it to that cert (CMS), and stages
    // the ciphertext here; the node's noo-fetch timer pulls, decrypts,
    // and noo-apply verifies the CA signature exactly as the push lane
    // did. The gateway only ever holds ciphertext.
    sql: r#"
ALTER TABLE noo_bootstrap_tokens
    ADD COLUMN IF NOT EXISTS birth_cert text,
    ADD COLUMN IF NOT EXISTS facts jsonb;

CREATE TABLE IF NOT EXISTS noo_provision_bundles (
    node_name  text PRIMARY KEY,
    blob       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    fetched_at timestamptz
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_provision_bundles TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "054_cli_assets",
    down_revision: Some("053_birth_pull_provisioning"),
    // the design rail work: the controller is the fleet's
    // update source. `noo upgrade --nodes` uploads the CLI release asset
    // for every node triple here; the gateway serves them at
    // /bootstrap/cli/<name> (+ .sha256 sidecar) so a node with no GitHub
    // access — private repo, or no internet at all — updates from its
    // controller, and provision puts the same bytes into each node's
    // bundle as the `cli-binary` kind.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_cli_assets (
    name       text PRIMARY KEY,
    blob       bytea NOT NULL,
    sha256     text NOT NULL,
    version    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_cli_assets TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "055_bundle_apply_report",
    down_revision: Some("054_cli_assets"),
    // 2026-09-03: the node's fetcher reports the applier's outcome back to
    // the controller. Until now `provision --wait` inferred success from
    // "agent registered" — true even when the applier refused the bundle
    // (HOST3, exit 76 on an unknown kind, reported as ✓).
    sql: r#"
ALTER TABLE noo_provision_bundles
    ADD COLUMN IF NOT EXISTS applied_at  timestamptz,
    ADD COLUMN IF NOT EXISTS applied_sha text,
    ADD COLUMN IF NOT EXISTS apply_rc    integer,
    ADD COLUMN IF NOT EXISTS apply_msg   text
"#,
},
Migration {
    revision: "056_agent_messages",
    down_revision: Some("055_bundle_apply_report"),
    // the trace of agent-to-agent messages. The
    // gateway's recorder (agent_messages.rs) writes every envelope it sees
    // on the AGENT_MESSAGES stream here; `id` is the envelope id so a
    // redelivered message is a no-op. Grants guarded like 048: a role-less
    // fixture DB must still migrate.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_agent_messages (
    id            text PRIMARY KEY,
    thread_id     text NOT NULL,
    from_agent    text NOT NULL,
    to_agent      text NOT NULL,
    kind          text NOT NULL DEFAULT 'message',
    body          jsonb NOT NULL DEFAULT '{}'::jsonb,
    refs          jsonb NOT NULL DEFAULT '[]'::jsonb,
    ts            timestamptz NOT NULL DEFAULT now(),
    delivered_at  timestamptz,
    read_at       timestamptz,
    enc           text NOT NULL DEFAULT 'none',
    sig           text
);
CREATE INDEX IF NOT EXISTS noo_agent_messages_thread_ts ON noo_agent_messages (thread_id, ts);
CREATE INDEX IF NOT EXISTS noo_agent_messages_to_ts     ON noo_agent_messages (to_agent, ts DESC);
CREATE INDEX IF NOT EXISTS noo_agent_messages_from_ts   ON noo_agent_messages (from_agent, ts DESC);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE ON noo_agent_messages TO noo_app;
    END IF;
END $$
"#,
},
Migration {
    revision: "057_agent_message_identity",
    down_revision: Some("056_agent_messages"),
    // WHO sent it, structurally — user / node / agent /
    // harness on both ends (operator: "user 1 with Hermes vs user 2 with
    // Claude"). `enc_meta` carries the sealed-body envelope for phase 2b.
    sql: r#"
ALTER TABLE noo_agent_messages
    ADD COLUMN IF NOT EXISTS from_user    text,
    ADD COLUMN IF NOT EXISTS from_node    text,
    ADD COLUMN IF NOT EXISTS from_harness text,
    ADD COLUMN IF NOT EXISTS to_user      text,
    ADD COLUMN IF NOT EXISTS to_node      text,
    ADD COLUMN IF NOT EXISTS to_harness   text,
    ADD COLUMN IF NOT EXISTS enc_meta     jsonb;
CREATE INDEX IF NOT EXISTS noo_agent_messages_from_user_ts ON noo_agent_messages (from_user, ts DESC);
CREATE INDEX IF NOT EXISTS noo_agent_messages_from_node_ts ON noo_agent_messages (from_node, ts DESC)
"#,
},
Migration {
    revision: "058_autonomy_audit",
    down_revision: Some("057_agent_message_identity"),
    // The autonomy engine can act on the fleet, and had NO audit trail: the
    // table every reader referenced was created by nothing and written by
    // nothing, so `/api/autonomy/audit` had always errored. It reported a
    // confident "0 actions" until that was corrected to say the store is
    // unreadable — which is how the gap was finally noticed.
    //
    // `armed` and `dry_run` are NULLABLE on purpose. An alert-only location
    // has no gate, and storing `false` there would say "its gate is off",
    // which is a different claim from "it has no gate". Readers must be able
    // to tell those apart; NULL is how the schema says "not applicable".
    //
    // `outcome` is text, not a boolean: 'fired' and 'would' are not the only
    // cases. 'error' is a location that could not evaluate — watching
    // nothing, which is neither an action nor a decision not to act, and is
    // exactly the state an operator must see before trusting the engine.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_autonomy_audit (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    location text NOT NULL,
    action   text,
    outcome  text NOT NULL,
    target   text,
    detail   text,
    armed    boolean,
    dry_run  boolean,
    metrics  jsonb
);
CREATE INDEX IF NOT EXISTS noo_autonomy_audit_at ON noo_autonomy_audit (at DESC);
CREATE INDEX IF NOT EXISTS noo_autonomy_audit_location_at ON noo_autonomy_audit (location, at DESC);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, DELETE ON noo_autonomy_audit TO noo_app;
        GRANT USAGE, SELECT ON SEQUENCE noo_autonomy_audit_id_seq TO noo_app;
    END IF;
END $$"#,
},
Migration {
    revision: "059_agent_messages_hardening",
    down_revision: Some("058_autonomy_audit"),
    // the design (security hardening, wave A). `received_at` is the
    // gateway's own clock — retention and ordering must not trust the
    // sender-supplied `ts`. `sig_verified` records whether the recorder
    // checked the envelope signature. Indexes for RTBF (`to_user`) and
    // the pruner (`received_at`).
    sql: r#"
ALTER TABLE noo_agent_messages
    ADD COLUMN IF NOT EXISTS received_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS sig_verified boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS noo_agent_messages_received_at ON noo_agent_messages (received_at);
CREATE INDEX IF NOT EXISTS noo_agent_messages_to_user_ts  ON noo_agent_messages (to_user, ts DESC);
-- The retention task, seeded here because nothing else seeds heartbeat
-- defaults on a Rust-primary install (the Python scheduler's start() never
-- runs there). Weekly, applies, 90 days. An operator's later edits win:
-- insert only when absent. Guarded like the grants: a role-less / legacy
-- fixture DB without the heartbeat table must still migrate.
DO $$
BEGIN
    IF to_regclass('noo_heartbeat_tasks') IS NOT NULL THEN
        INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, created_by)
        VALUES ('agent_messages_retention', 'Agent messages retention (weekly, 90d)', '0 5 * * 0',
                'agent_messages_retention', '{"dry_run": false, "days": 90}'::jsonb, true, 'system')
        ON CONFLICT (id) DO NOTHING;
    END IF;
END $$
"#,},
Migration {
    revision: "060_evolve_meta_loop_grants",
    down_revision: Some("059_agent_messages_hardening"),
    // The evolve add-on reads and writes two tables owned by this chain.
    // They stay where they are; evolve reaches them under these grants.
    //
    // DML, not ownership: the mesh chain owns their shape, and a role that
    // can DROP a table it merely writes to has a wider grant than it needs.
    //
    // No sequence grants: both tables key on a uuid the caller supplies, so
    // there is no sequence to advance. If a future column takes an identity
    // default, that grant belongs in the revision that adds it.
    //
    // Guarded on the role existing. `noo_evolve` is created by migration 034
    // in the Python chain, which an install that never enabled the add-on
    // has still run — but a GRANT to a missing role is a hard error, and this
    // revision must be replayable on a database that lacks the role.
    sql: r#"
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_evolve') THEN
        GRANT USAGE ON SCHEMA public TO noo_evolve;
        IF to_regclass('public.noo_agent_decisions') IS NOT NULL THEN
            GRANT SELECT, INSERT ON noo_agent_decisions TO noo_evolve;
        END IF;
        IF to_regclass('public.noo_activity_proposals') IS NOT NULL THEN
            GRANT SELECT, INSERT, UPDATE ON noo_activity_proposals TO noo_evolve;
        END IF;
    END IF;
END $$
"#,},
Migration {
    revision: "061_conversation_org",
    down_revision: Some("060_evolve_meta_loop_grants"),
    // Every conversation must belong to an org, because the read side has
    // already decided that it does.
    //
    // `conversation_store.py` applies a HARD org boundary: once a caller
    // resolves to an org, every conversation query gains `c.org_id = :org`
    // and nothing outside that org comes back — not even the org-shared
    // tier. `noo_users.org_id` is `text DEFAULT 'default' NOT NULL`, so
    // EVERY account has an org and every identified caller therefore
    // resolves one. But `noo_conversations.org_id` was nullable and the
    // gateway's two writers never set it, so the conversations the gateway
    // creates carried NULL — and `NULL = 'default'` is not true. The filter
    // did not narrow the result, it emptied it. That is the tell: an
    // org-scoped read returned NOTHING rather than fewer rows.
    //
    // A single-user install is not a special case. It is one user in one
    // org ('default'), running the same filter as a hundred-user install —
    // which is why the same NULL broke it there too.
    //
    // NOT NULL, deliberately. Migration 043 left `user_id` nullable for a
    // reason it spelled out: a user-scoped table is not a user-only table,
    // and NULL there means "shared / not a person's". `org_id` carries no
    // such meaning. There is no such thing as a conversation outside every
    // org; a system row belongs to the 'default' org exactly like the
    // operator does. And with the column NOT NULL, the boundary can be
    // trusted rather than re-checked.
    //
    // The DEFAULT and the trigger, together. `noo_conv_set_org` (trellion
    // squash, originally revision 009) is a BEFORE INSERT trigger that
    // derives `org_id` from the owner when the caller left it NULL. A bare
    // `SET DEFAULT 'default'` would SHADOW it: the column default is applied
    // before the trigger fires, so `NEW.org_id` would already be 'default',
    // the trigger's `IS NULL` test would be false, and a conversation owned
    // by a user in org 'acme' would silently land in 'default'. That is a
    // tenant-isolation regression dressed up as a safety net. So the trigger
    // is rewritten here to treat 'default' as what it is — the sentinel for
    // "nobody said" — and to re-derive over it. For a genuine member of the
    // 'default' org that is a no-op; for anyone else it is the correction.
    // It also COALESCEs its own result, so an owner who is not in
    // `noo_users` still yields a row, not a NOT NULL violation.
    //
    // Everything is resolved through `regclass` / `pg_proc` rather than
    // written unqualified. `noo_conversations` is TRELLION-owned (proposal
    // 17 draws that line, and 043 declined to reach across it) and lives in
    // schema `trellion` on a cluster install, `public` on a legacy one —
    // neither of which is on this runner's `search_path`. Unqualified DDL
    // would no-op on the exact installs that need it. And if the table is
    // absent altogether — a mesh-only fixture DB, or a fresh install whose
    // trellion chain has not run yet — this revision must still migrate, so
    // it returns early rather than failing.
    sql: r#"
DO $mig$
DECLARE
    conv      regclass := COALESCE(to_regclass('noo_conversations'),
                                   to_regclass('trellion.noo_conversations'),
                                   to_regclass('public.noo_conversations'));
    usr       regclass := COALESCE(to_regclass('noo_users'),
                                   to_regclass('mesh.noo_users'),
                                   to_regclass('public.noo_users'));
    fn_schema text;
    fn_body   text := $fn$
BEGIN
    IF (NEW.org_id IS NULL OR NEW.org_id = 'default')
       AND NEW.user_id IS NOT NULL THEN
        IF NEW.user_id LIKE 'team:%' THEN
            NEW.org_id := (SELECT org_id FROM noo_kb_teams
                           WHERE 'team:' || name = NEW.user_id);
        ELSE
            NEW.org_id := (SELECT org_id FROM noo_users
                           WHERE username = NEW.user_id);
        END IF;
    END IF;
    NEW.org_id := COALESCE(NEW.org_id, 'default');
    RETURN NEW;
END;
$fn$;
BEGIN
    IF conv IS NULL THEN
        RETURN;
    END IF;

    -- 1. The owning user already knows the answer.
    IF usr IS NOT NULL THEN
        EXECUTE format(
            'UPDATE %s c SET org_id = u.org_id FROM %s u '
            '  WHERE c.user_id = u.username AND c.org_id IS NULL', conv, usr);
    END IF;

    -- 2. What is left has no user at all: heartbeat runs, autonomy sweeps,
    --    system tool calls. They are not outside every org, they are in the
    --    default one — the same org a single-user install's only account is
    --    in.
    EXECUTE format(
        'UPDATE %s SET org_id = ''default'' WHERE org_id IS NULL', conv);

    -- 3. Safe going forward, in both directions: the default catches a
    --    writer that omits the column, the trigger catches one that passes
    --    an explicit NULL, and NOT NULL proves neither ever slipped.
    EXECUTE format(
        'ALTER TABLE %s ALTER COLUMN org_id SET DEFAULT ''default''', conv);

    SELECT n.nspname INTO fn_schema
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE p.proname = 'noo_conv_set_org'
     LIMIT 1;
    IF fn_schema IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE FUNCTION ' || quote_ident(fn_schema)
             || '.noo_conv_set_org() RETURNS trigger LANGUAGE plpgsql AS '
             || quote_literal(fn_body);
    END IF;

    EXECUTE format(
        'ALTER TABLE %s ALTER COLUMN org_id SET NOT NULL', conv);
END $mig$
"#,},
Migration {
    revision: "062_usage_actor",
    down_revision: Some("061_conversation_org"),
    // WHO is behind a completion, at last.
    //
    // 048 gave `noo_token_usage` a `user_id uuid` column. Nothing ever wrote
    // it — every writer passed NULL — and nothing could have: accounts are
    // keyed by `noo_users.username` (text), so there was no uuid to write.
    // "Token usage by user" was therefore unanswerable by construction,
    // for the CLI, the dashboard and the MCP doors alike.
    //
    // Two nullable text columns replace it. `username` is the canonical
    // account when a person is behind the call (JWT subject, WS session,
    // linked channel account, the user a service key or MCP key is bound
    // to). `consumer` is the credential or subsystem that made the call (a
    // service key's consumer name, a cluster actor such as `mcp-local`,
    // `heartbeat`). Either, both or neither may be set; NULL means "not
    // attributable", never a guess.
    //
    // The monthly rollup carries the same two columns so `group=user` and
    // `group=consumer` survive retention. They join the primary key with
    // '' for NULL — the same convention 048 chose for `node_id`.
    sql: r#"
ALTER TABLE noo_token_usage DROP COLUMN IF EXISTS user_id;
ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS username text;
ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS consumer text;
CREATE INDEX IF NOT EXISTS noo_token_usage_user_ts_idx ON noo_token_usage (username, ts);

ALTER TABLE noo_token_usage_monthly ADD COLUMN IF NOT EXISTS username text NOT NULL DEFAULT '';
ALTER TABLE noo_token_usage_monthly ADD COLUMN IF NOT EXISTS consumer text NOT NULL DEFAULT '';
ALTER TABLE noo_token_usage_monthly DROP CONSTRAINT IF EXISTS noo_token_usage_monthly_pkey;
ALTER TABLE noo_token_usage_monthly
    ADD PRIMARY KEY (month, node_id, backend, model, source, username, consumer);
"#,
},
Migration {
    revision: "063_usage_user_uuid",
    down_revision: Some("062_usage_actor"),
    // 062 keyed usage rows by `username`. That contradicts the design:
    // `noo_users.user_uuid` has been the account's stable identity since
    // 042 and its PRIMARY KEY since 044, precisely so a rename never
    // orphans a reference. 048's `user_id uuid` was that key by intent; 062
    // dropped it because no writer had ever filled it, and reached for the
    // name instead. This revision puts the uuid back — as the ONLY user
    // column — and resolves the name to it at write time (`usage::insert`
    // subselects `noo_users`), so a row means "this account" rather than
    // "whatever this string was called at the time".
    //
    // FK with ON DELETE SET NULL: a deleted account's usage stays counted
    // but stops naming anyone — the RTBF-correct outcome for accounting.
    // The monthly rollup cannot carry NULL in its key, so it uses the nil
    // uuid the way 048 used '' for node_id.
    //
    // 062 was merged to dev but never in a cut, so nothing ever wrote a
    // username-keyed row that the backfill below would not catch.
    sql: r#"
ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS user_uuid uuid
    REFERENCES noo_users(user_uuid) ON DELETE SET NULL;
UPDATE noo_token_usage t SET user_uuid = u.user_uuid
    FROM noo_users u WHERE t.username = u.username AND t.user_uuid IS NULL;
DROP INDEX IF EXISTS noo_token_usage_user_ts_idx;
ALTER TABLE noo_token_usage DROP COLUMN IF EXISTS username;
CREATE INDEX IF NOT EXISTS noo_token_usage_user_ts_idx
    ON noo_token_usage (user_uuid, ts) WHERE user_uuid IS NOT NULL;

ALTER TABLE noo_token_usage_monthly ADD COLUMN IF NOT EXISTS user_uuid uuid
    NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
UPDATE noo_token_usage_monthly t SET user_uuid = u.user_uuid
    FROM noo_users u WHERE t.username = u.username AND t.username <> '';
ALTER TABLE noo_token_usage_monthly DROP CONSTRAINT IF EXISTS noo_token_usage_monthly_pkey;
ALTER TABLE noo_token_usage_monthly DROP COLUMN IF EXISTS username;
ALTER TABLE noo_token_usage_monthly
    ADD PRIMARY KEY (month, node_id, backend, model, source, user_uuid, consumer);
"#,
},
Migration {
    revision: "064_node_companion_policy",
    down_revision: Some("063_usage_user_uuid"),
    // Companion gating becomes per-node DESIRED STATE
    // the design. The scheduler used a fixed Rust default while thirteen
    // `companion:` YAML fields nothing read described it; this column holds
    // the three values the scheduler actually enforces, as a jsonb object
    // (`min_battery_pct`, `require_wifi`, `blocked_thermal_states`),
    // validated on write. NULL = the gateway default. jsonb rather than
    // three columns because the MHS device policy will
    // land in the same place with keys this table need not predict.
    sql: r#"
ALTER TABLE noo_node_config ADD COLUMN IF NOT EXISTS companion_policy jsonb;
"#,
},
Migration {
    revision: "065_mcp_registry",
    down_revision: Some("064_node_companion_policy"),
    // The registry of EXTERNAL MCP servers. Third-
    // party tool servers and MHS device drivers arrive through the same
    // door, so the cluster keeps one record: what a server is, where it
    // runs (placements, in the shape of backend placements), and what it
    // offers (tools — filled by phase B's node-side discovery; empty
    // until then, which is the honest state of an unreached server).
    //
    // `spec` never holds a credential: the route refuses a literal under a
    // secret-looking key and accepts only `$NAME` references into the
    // secret store, which the hosting node resolves. `owner_uuid` follows
    // the design — a uuid, never a name. `audience` is the knowledge-base
    // vocabulary; `[]` = operators only.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_mcp_servers (
    id          text PRIMARY KEY,
    transport   text NOT NULL CHECK (transport IN ('stdio', 'streamable_http')),
    spec        jsonb NOT NULL DEFAULT '{}'::jsonb,
    kind        text NOT NULL DEFAULT 'tool' CHECK (kind IN ('tool', 'device')),
    owner_uuid  uuid REFERENCES noo_users(user_uuid) ON DELETE SET NULL,
    audience    jsonb NOT NULL DEFAULT '[]'::jsonb,
    note        text,
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS noo_mcp_server_placements (
    server_id     text NOT NULL REFERENCES noo_mcp_servers(id) ON DELETE CASCADE,
    node_id       text NOT NULL,
    desired_state text NOT NULL DEFAULT 'running' CHECK (desired_state IN ('running', 'stopped')),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, node_id)
);
CREATE TABLE IF NOT EXISTS noo_mcp_server_tools (
    server_id     text NOT NULL REFERENCES noo_mcp_servers(id) ON DELETE CASCADE,
    name          text NOT NULL,
    description   text NOT NULL DEFAULT '',
    input_schema  jsonb NOT NULL DEFAULT '{}'::jsonb,
    discovered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, name)
);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_mcp_servers, noo_mcp_server_placements, noo_mcp_server_tools TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "066_mcp_calls",
    down_revision: Some("065_mcp_registry"),
    // One row per external tool call through the bridge
    // phase C: who (user_uuid — NULL for an internal run),
    // which server and tool, did it succeed, how long. The audit table has
    // the event too; this is the countable shape `noo usage` can join.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_mcp_calls (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    server_id  text NOT NULL,
    tool       text NOT NULL,
    user_uuid  uuid,
    ok         boolean NOT NULL,
    ms         integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS noo_mcp_calls_server_ts_idx ON noo_mcp_calls (server_id, ts);
CREATE INDEX IF NOT EXISTS noo_mcp_calls_user_ts_idx ON noo_mcp_calls (user_uuid, ts) WHERE user_uuid IS NOT NULL;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT ON noo_mcp_calls TO noo_app;
    END IF;
END $$;
"#,
},
Migration {
    revision: "067_tasks_and_harness_policy",
    down_revision: Some("066_mcp_calls"),
    // a TASK is an objective a harness owns across
    // many loops. Owner by user_uuid. `conversation_id` is
    // the conversation the loops accumulate in; `thread_id` the agent-
    // message thread its notes and results post to. State machine:
    // open → running ⇄ checkpointed → done | failed | stopped.
    // `harness_policy` on a node's config row: `auto` — a
    // harness follows any running chat backend on the node; `manual` — only
    // an explicit `noo cluster place <node> harness`; `off` — never.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_tasks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    objective       text NOT NULL,
    owner_uuid      uuid REFERENCES noo_users(user_uuid) ON DELETE SET NULL,
    node            text,
    state           text NOT NULL DEFAULT 'open',
    conversation_id uuid NOT NULL,
    thread_id       text NOT NULL,
    channel         text NOT NULL DEFAULT 'task',
    model           text,
    loops           integer NOT NULL DEFAULT 0,
    loop_budget     integer NOT NULL DEFAULT 20,
    last_checkpoint timestamptz,
    last_note       text,
    result          text,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT noo_tasks_state_chk CHECK (state IN ('open','running','checkpointed','done','failed','stopped'))
);
CREATE INDEX IF NOT EXISTS noo_tasks_owner_idx ON noo_tasks (owner_uuid, created_at DESC);
CREATE INDEX IF NOT EXISTS noo_tasks_node_state_idx ON noo_tasks (node, state);
CREATE INDEX IF NOT EXISTS noo_tasks_conversation_idx ON noo_tasks (conversation_id);
ALTER TABLE noo_node_config ADD COLUMN IF NOT EXISTS harness_policy text NOT NULL DEFAULT 'manual';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'noo_node_config_harness_policy_chk') THEN
        ALTER TABLE noo_node_config ADD CONSTRAINT noo_node_config_harness_policy_chk CHECK (harness_policy IN ('auto','manual','off'));
    END IF;
END $$
"#,
},
Migration {
    revision: "068_task_tree",
    down_revision: Some("067_tasks_and_harness_policy"),
    // a task may have a parent (a coordinator that
    // delegated it, or the collaboration that fanned it out) and a role
    // (the system prompt its loops run under). Children share the
    // parent's thread, so a collaboration reads as one conversation.
    // A parent with loop_budget 0 is an aggregation only: it finishes when
    // its children do.
    sql: r#"
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS parent_id uuid REFERENCES noo_tasks(id) ON DELETE SET NULL;
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS role text;
CREATE INDEX IF NOT EXISTS noo_tasks_parent_idx ON noo_tasks (parent_id) WHERE parent_id IS NOT NULL
"#,
},
Migration {
    revision: "069_loop_budget_defaults",
    down_revision: Some("068_task_tree"),
    // a task's loop budget resolves explicit → the node's
    // default (this column) → the cluster default (NOO_TASK_LOOP_BUDGET).
    // `budget_default` marks a task whose budget was not given, so the
    // node's value can be applied when the task lands there.
    sql: r#"
ALTER TABLE noo_node_config ADD COLUMN IF NOT EXISTS default_loop_budget integer;
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS budget_default boolean NOT NULL DEFAULT false
"#,
},
Migration {
    revision: "070_approval_request_binding",
    down_revision: Some("069_loop_budget_defaults"),
    // an approval row said only "some tool wants to run".
    // With no requester, conversation or channel on it, `noo approval
    // pending` could not tell an operator whose call they were about to
    // approve, and a bare `y` typed in ANY chat resolved the globally
    // newest pending row — a request raised by one person, decided from a
    // conversation that never saw it.
    //
    // Nullable, because unattended turns (heartbeat, autonomy) genuinely
    // have no requester and no conversation; those rows are decidable only
    // by explicit id, which is the honest outcome. The partial index backs
    // the scoped shorthand lookup ("what is pending in THIS conversation").
    sql: r#"
ALTER TABLE noo_approval_requests ADD COLUMN IF NOT EXISTS requester text;
ALTER TABLE noo_approval_requests ADD COLUMN IF NOT EXISTS conversation_id text;
ALTER TABLE noo_approval_requests ADD COLUMN IF NOT EXISTS channel text;
ALTER TABLE noo_approval_requests ADD COLUMN IF NOT EXISTS chat_id text;
CREATE INDEX IF NOT EXISTS noo_approval_requests_pending_conv_idx
    ON noo_approval_requests (conversation_id, created_at DESC)
    WHERE status = 'pending'
"#,
},
Migration {
    revision: "071_recipient_owner",
    down_revision: Some("070_approval_request_binding"),
    // the saved-recipients address book had no owner, so
    // `GET /api/channels/saved-recipients` handed every User-tier caller
    // every other person's contacts — names, chat ids and notes. The tier
    // gate admits every GET regardless of role, so the handler's own scope
    // was the only boundary and there was nothing to scope BY.
    //
    // Nullable, and every existing row is left NULL on purpose. NULL means
    // "the shared address book": readable by everyone, writable by
    // Operator+ only. That is exactly today's behaviour for rows that
    // already exist (a single-operator install keeps its contacts), while a
    // row created by a User-tier caller is stamped with their name and is
    // theirs alone. Backfilling an owner would have to GUESS one, and a
    // guessed owner is worse than an honest NULL.
    sql: r#"
ALTER TABLE noo_channel_recipients ADD COLUMN IF NOT EXISTS owner text;
CREATE INDEX IF NOT EXISTS noo_channel_recipients_owner_idx
    ON noo_channel_recipients (owner)
    WHERE owner IS NOT NULL
"#,
}, Migration {
    revision: "072_username_is_one_segment",
    down_revision: Some("071_recipient_owner"),
    // An account name is ONE name segment:
    // `[A-Za-z0-9_-]`, 1-128 — the same class as a connection label and
    // an agent id (`auth::valid_name_segment`).
    //
    // `/` because it now separates an account from one of its
    // connections. `.` because `agent_messages::subject_token` maps `/`
    // to `.` to build the NATS subject, so a dot in a name makes that
    // mapping ambiguous and two agents can share an inbox — which is why
    // `first.last` was a legal account that could not send a message.
    // Narrowing the account rule was free: no account contained either
    // character when this was measured (operator, 2026-09-13).
    //
    // Nothing forbade it before, and after the account/connection split it
    // is silently destructive rather than merely odd: `auth::account_of`
    // reads everything before the first `/` as the owner, so an account
    // literally named `owner/ops` would have its history, memory and usage
    // attributed to `owner` — and if `owner` also exists, that is
    // cross-account attribution into a REAL account rather than a NULL.
    // Nothing errors. It is the exact failure the doc comment on
    // `effective_user_id` warns about, arriving through the one door that
    // comment does not cover.
    //
    // A CHECK rather than a Rust guard because `noo_users` has several
    // writers — three creation paths in Rust, the Python layer, and
    // whatever an operator types into psql — and a reader of `account_of`
    // should be able to see why the split is safe without auditing all of
    // them. One place, unbypassable.
    //
    // NOT VALID: existing rows are not scanned. A username containing `/`
    // is almost certainly nonexistent, but "almost certainly" is not worth
    // a migration that refuses to start the gateway on an install we have
    // not seen. New and updated rows are checked from here on, which is
    // what closes the hole; an operator can VALIDATE later.
    sql: r#"
ALTER TABLE noo_users DROP CONSTRAINT IF EXISTS noo_users_username_no_separator;
ALTER TABLE noo_users DROP CONSTRAINT IF EXISTS noo_users_username_is_one_segment;
ALTER TABLE noo_users ADD CONSTRAINT noo_users_username_is_one_segment
    CHECK (username ~ '^[A-Za-z0-9_-]{1,128}$') NOT VALID
"#,
}, Migration {
    revision: "073_agent_trust",
    down_revision: Some("072_username_is_one_segment"),
    // who may address an agent.
    //
    // The DEFAULT is not stored and deliberately so. An agent accepts
    // every identity its own owner holds — that is the operator steering
    // their own worker from whatever client is in front of them, which is
    // the point of the messaging system and must not need a row. This
    // table holds only the EXCEPTIONS: identities belonging to somebody
    // else that a particular agent will nonetheless accept.
    //
    // `allowed` is an account or a connection name. An account entry
    // covers every connection under it, by the same prefix rule that
    // governs ownership (`auth::owns_name`) — so trusting a person is one
    // row, not one row per window they have open.
    //
    // Team is the next widening and lands as a wider predicate over this
    // same table, not a second table: "an identity my owner holds" grows
    // to "an identity anyone on my team holds" without the storage
    // changing shape.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_agent_trust (
    agent       text NOT NULL,
    allowed     text NOT NULL,
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text,
    PRIMARY KEY (agent, allowed)
);
CREATE INDEX IF NOT EXISTS noo_agent_trust_agent_idx ON noo_agent_trust (agent)
"#,
}, Migration {
    revision: "074_posture_bridge_life",
    down_revision: Some("073_agent_trust"),
    // a compatibility bridge records when it opened and when
    // it is expected to be shut. `noo_security_posture` has separated a GATE
    // (a standing property) from a BRIDGE (a rollout window) since R43, and
    // each bridge names the value that closes it — but no row has ever
    // carried a lifetime, so a bridge opened this morning and one opened a
    // year ago were the same row. The only forcing function was memory.
    //
    // Both columns are nullable and are NOT backfilled to now(). A row that
    // predates them has an unknown open date; stamping it with today would
    // silently restart the clock on the oldest bridges in the fleet — the
    // ones most worth expiring. Readers fall back to `updated_at` and say so.
    //
    // This first went in as an Alembic revision `047_posture_bridge_life`
    // and was caught by `baseline_revision_matches_the_generated_dump`: the
    // Python chain is frozen at 046 and everything after it lives here.
    sql: r#"
ALTER TABLE noo_security_posture ADD COLUMN IF NOT EXISTS opened_at timestamptz;
ALTER TABLE noo_security_posture ADD COLUMN IF NOT EXISTS close_by  timestamptz
"#,}, Migration {
    revision: "075_agent_message_reads",
    down_revision: Some("074_posture_bridge_life"),
    // read state keyed by CONNECTION, not by message.
    //
    // `noo_agent_messages.read_at` is one column per message, so the first
    // window of a person to acknowledge cleared the message for every
    // window they had open — "a message addressed to you is consumed by
    // whichever of you looked first". Now that each MCP session is its own
    // connection, that is the collision the proposal named and this table
    // closes it: one row per (message, reader).
    //
    // `reader` is the acting identity — a connection (`owner/label-x`), a
    // bare account (the CLI), or a node agent. Each acknowledges for
    // itself. `read_at` on the message row is kept and still set on the
    // FIRST ack by anyone, as the "has this been seen at all" signal that
    // existing readers of the column expect; it no longer decides unread.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_agent_message_reads (
    message_id  text NOT NULL REFERENCES noo_agent_messages(id) ON DELETE CASCADE,
    reader      text NOT NULL,
    read_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, reader)
);
CREATE INDEX IF NOT EXISTS noo_agent_message_reads_reader_idx ON noo_agent_message_reads (reader)
"#,}, Migration {
    revision: "076_mcp_sessions",
    down_revision: Some("075_agent_message_reads"),
    // the design, first half: sessions get memory.
    //
    // `mcp_session.rs` kept sessions in process. That made every gateway
    // restart forget every window (each client re-initialised, which is
    // correct but noisy), made sessions invisible to anyone else (no
    // presence — a sender could not list which of a person's windows was
    // alive), and made provenance evaporate at the idle TTL: after a day
    // nobody could say which window sent a message beyond its key label.
    //
    // Now a row per session. The id is stored as a SHA-256 hash: the id is
    // a distinguisher the client echoes on every request, and a table of
    // plaintext ids would let anyone who could read it impersonate every
    // live window of every person. `display_name` is the client's own
    // `clientInfo.name` from `initialize` — DISPLAY ONLY, never compared,
    // as every display field in this design.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_mcp_sessions (
    id_hash       text PRIMARY KEY,
    account       text NOT NULL,
    consumer      text NOT NULL,
    label         text NOT NULL,
    display_name  text,
    opened_at     timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS noo_mcp_sessions_account_idx ON noo_mcp_sessions (account, last_seen DESC)
"#,
}, Migration {
    revision: "077_addon_caller_verify_view",
    down_revision: Some("076_mcp_sessions"),
    // The gateway signs its outbound add-on calls with a `noo_service_keys`
    // row under `addon-caller:gateway` (`addon_auth.rs`). For that to be
    // worth anything the add-on has to be able to CHECK it, and it cannot:
    // Alembic 034 gives `noo_evolve` ownership of five tables and no
    // privilege anywhere else, which is the scoping that made the role worth
    // creating.
    //
    // Granting SELECT on `noo_service_keys` itself would undo it. That table
    // holds every consumer's hash, the bound `user_id` and the rpm limit — an
    // add-on reading it could verify credentials issued to other callers
    // entirely, which is a larger authority than "tell me whether the gateway
    // called me".
    //
    // So: a view over the add-on-caller rows alone, with the columns a
    // verifier needs and no others. It deliberately exposes no `user_id`,
    // `user_uuid`, `rpm_limit`, `note` or `last_used_at` — these keys name a
    // PROGRAM, and who the call acts for rides in the request headers, bound
    // to the same bearer. The hashes it does expose are sha256 of a 32-byte
    // token minted at gateway start, not reversible and not replayable
    // anywhere else, because nothing but an add-on accepts this consumer.
    //
    // `starts_with` and not `LIKE '...%'`: this SQL also has to survive being
    // read by a placeholder parser, which takes a bare `%` for a malformed
    // placeholder.
    //
    // RLS would be the other shape. It would need a policy per reader and
    // would sit in the path of the gateway's own hot resolve; a view is one
    // object, its definition IS the filter, and revoking it is one REVOKE.
    //
    // The grants are conditional on the role existing. An OSS install has no
    // add-on roles at all, and that is the normal case, not a failure. USAGE
    // on the containing schema goes with them: this view lands in `mesh` on a
    // cluster install and `public` on a legacy one, and an add-on role holds
    // neither by default.
    //
    // The whole thing is one guarded block because `MIGRATIONS` also runs
    // against a database that has no baseline — `legacy_apply_...` applies
    // the post-cutover revisions alone, and unguarded DDL naming a baseline
    // table fails there. Absent source table, nothing to verify against:
    // return, exactly as 062 does for a trellion-owned table.
    sql: r#"
DO $mig$
DECLARE
    keys   regclass := to_regclass('noo_service_keys');
    view_  regclass;
    sch    text;
    r      text;
BEGIN
    IF keys IS NULL THEN
        RETURN;
    END IF;
    EXECUTE format(
        'CREATE OR REPLACE VIEW noo_addon_caller_keys AS '
        'SELECT consumer, key_hash, created_at FROM %s '
        'WHERE active = true AND starts_with(consumer, ''addon-caller:'')',
        keys::text);

    view_ := to_regclass('noo_addon_caller_keys');
    SELECT n.nspname INTO sch
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = view_;

    FOREACH r IN ARRAY ARRAY['noo_evolve'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', sch, r);
            EXECUTE format('GRANT SELECT ON %s TO %I', view_::text, r);
        END IF;
    END LOOP;
END
$mig$
"#,
}, Migration {
    revision: "078_service_key_overlap",
    down_revision: Some("077_addon_caller_verify_view"),
    // Rotation used to mint the new key and deactivate the old one in the
    // same request. For a human copying an MCP key that is right. For a
    // CONTAINER holding its key in an environment variable it is an outage:
    // the running process still presents the old value, which is now
    // inactive, and a refused bearer logs nothing — the four-day silence of
    // the design.
    //
    // So a rotation now SUPERSEDES: the previous rows stay active and get
    // stamped, and a separate step retires them once the new key has
    // actually been seen in use. This column is that stamp. Absent (NULL)
    // means "not superseded", which is every row that exists today.
    // ALTER TABLE **IF EXISTS**: MIGRATIONS also runs against a database with
    // no baseline — `legacy_apply_...` applies the post-cutover revisions
    // alone, and unguarded DDL naming a baseline table fails there. 077 makes
    // the same allowance with `to_regclass`; a one-statement ALTER can say it
    // in the statement itself.
    sql: r#"
ALTER TABLE IF EXISTS noo_service_keys ADD COLUMN IF NOT EXISTS superseded_at timestamptz
"#,
}, Migration {
    revision: "079_operator_client_certs",
    down_revision: Some("078_service_key_overlap"),
    // the operator client certificates this gateway admits
    // for posture writes. A certificate is identified by its RFC 8705
    // thumbprint (`x5t#S256`); the CA's signature proves it was issued on
    // the controller, this row proves it was registered by the account it
    // names and has not been revoked. Rows are never deleted: a revoked
    // thumbprint stays revoked, and "has an operator certificate ever been
    // registered" is what closes the routine shared-secret posture write.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_operator_certs (
    thumbprint    text PRIMARY KEY,
    operator      text NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoked_by    text
);
CREATE INDEX IF NOT EXISTS noo_operator_certs_operator ON noo_operator_certs (operator)
"#,
}, Migration {
    revision: "080_user_settings",
    down_revision: Some("079_operator_client_certs"),
    // Per-account settings, one row per (account, key). The first key is
    // `walks.save_threads`: whether the account's own graph
    // walks are saved as recallable threads. ABSENT means the default (ON);
    // a row of `false` is an opt-out and stops NEW saves only.
    //
    // Keyed by the ACCOUNT NAME, like `noo_kb_role_grants` and
    // `noo_user_channel_links`, so right-to-be-forgotten erases it with one
    // `username = $1` target (`users.rs::erase_targets`) and the worker, which
    // knows the account from the verified principal, reads it with no join.
    // `value` is jsonb so the next setting needs no migration. No foreign key
    // to `noo_users`: an erasure that keeps the account (`keep_account`) wipes
    // this table's rows too, and a settings row must never block a user delete.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_user_settings (
    username   text        NOT NULL,
    key        text        NOT NULL,
    value      jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, key)
)
"#,
}, Migration {
    revision: "081_host_login_tickets",
    down_revision: Some("080_user_settings"),
    // One-time login tickets minted ON THE CONTROLLER HOST (`noo` writes the
    // row through `docker exec <postgres> psql`, the same host-plane access
    // `noo db` and `secrets rotate` use) and exchanged once at `/auth/token`
    // (`grant_type=host_ticket`) for that account's ordinary login. They
    // replace the controller secret the CLI used to sign with when it held
    // no login: the onboard wizard on a re-run with no password, and
    // recovering a lost admin password. Whoever can write this table can
    // already write `noo_users`, so a ticket adds no authority — it turns
    // host access into a login the gateway audits, instead of a shared
    // secret it cannot attribute. Only the sha256 of a ticket is stored.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_host_login_tickets (
    token_hash text PRIMARY KEY,
    username   text NOT NULL,
    purpose    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, UPDATE ON noo_host_login_tickets TO noo_app;
    END IF;
END $$;
"#,
}, Migration {
    revision: "082_noo_ops",
    down_revision: Some("081_host_login_tickets"),
    // Asynchronous operations (`ops.rs`, `routes/ops.rs`): a long run is
    // STARTED, answered with an id at once, and polled for status and result.
    // This is the generic store; MCP tasks bind to it
    // (`task_id` = `op_id`), so it carries what that design asked of its own
    // table: a per-caller binding (`owner_uuid` + `consumer`), a TTL
    // (`expires_at`), restart reconciliation (`runner_instance` +
    // `heartbeat_at`) and cancel semantics (`cancel_note`).
    //
    // Why not the `jobs` table: its lifecycle is scheduler PLACEMENT (a job is
    // queued for a node to claim), not the capture of one request/response.
    //
    // Owned by `noo_users.user_uuid`, never a name (the usage tables'
    // lesson: a name column is a second identity that RTBF and renames both
    // have to remember). NULL owner = a controller-internal caller with no
    // account (heartbeat ingest, a cluster-HMAC script): visible to admins and
    // to other such callers only. `ON DELETE CASCADE`: a deleted account's results go
    // with it; `routes/users.rs::erase_targets` also lists this table so an
    // erasure that KEEPS the account wipes the ops too, archived first.
    //
    // `exclusive_key` + the partial unique index is the one-at-a-time rule
    // for an operation the worker itself refuses to run twice (recluster):
    // the second INSERT fails on the index, atomically, instead of the two
    // gateways racing a check-then-insert.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_ops (
    op_id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    op_type         text        NOT NULL,
    status          text        NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','succeeded','failed','cancelled','expired')),
    owner_uuid      uuid        REFERENCES noo_users(user_uuid) ON DELETE CASCADE,
    consumer        text,
    params          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    progress        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    result          jsonb,
    result_status   integer,
    error           text,
    cancel_note     jsonb,
    exclusive_key   text,
    runner_instance text        NOT NULL,
    heartbeat_at    timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS noo_ops_owner_created ON noo_ops (owner_uuid, created_at DESC);
CREATE INDEX IF NOT EXISTS noo_ops_status_expires ON noo_ops (status, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS noo_ops_one_exclusive_live
    ON noo_ops (exclusive_key)
    WHERE exclusive_key IS NOT NULL AND status IN ('queued','running')
"#,
}, Migration {
    revision: "083_ops_erase_pending",
    down_revision: Some("082_noo_ops"),
    // Right-to-be-forgotten vs asynchronous operations. Work already handed to
    // a worker finishes whatever the gateway does, so an erase REFUSES (409,
    // Retry-After) while the account has a write-side operation live or within
    // its `worker_may_run_until`. Without more, an account (or its MCP
    // consumers) that kept starting writes would starve the erase forever: the
    // first refusal therefore marks the account erase-PENDING here, and every
    // operation start for it is refused (423) until the erase succeeds. A
    // persisted row, not process memory, so it holds across gateways and
    // restarts; `expires_at` is twice the longest run limit so an abandoned
    // erase cannot lock an account forever. The successful erase deletes the
    // row (and the account's deletion cascades it). An admin clears one early
    // with `DELETE FROM noo_ops_erase_pending WHERE user_uuid = ...`.
    //
    // Also here: `worker_limit_secs` (the type's run limit, stamped at start) and
    // `worker_may_run_until`: until when a WORKER run may still be going after
    // the gateway stopped tracking it. Stamped on cancel, on a supervisor
    // timeout, on a boot reconcile and on a sweeper lost-run, so an op that
    // turned `failed` while its worker was mid-write still blocks an erase.
    sql: r#"
ALTER TABLE noo_ops ADD COLUMN IF NOT EXISTS worker_limit_secs integer;
ALTER TABLE noo_ops ADD COLUMN IF NOT EXISTS worker_may_run_until timestamptz;
CREATE TABLE IF NOT EXISTS noo_ops_erase_pending (
    user_uuid  uuid        PRIMARY KEY REFERENCES noo_users(user_uuid) ON DELETE CASCADE,
    marked_at  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
)
"#,
}, Migration {
    revision: "084_erasure_residue_stores",
    down_revision: Some("083_ops_erase_pending"),
    // what a right-to-be-forgotten erase still missed, and the
    // retention of the archive it writes.
    //
    //  * `noo_user_erasure_staging(staged_at)`: the daily purge (30 days,
    //    `erasure_archive.rs`) and the verify row's "oldest archived erasure"
    //    both range over it.
    //  * `graph_edge_prune_staging.user_id`: a pruned edge is a copy of the
    //    owner's data (its evidence is document or conversation text) and the
    //    table had no owner to erase by. Stamped from `edges.user_id` by the
    //    prune from now on. Rows staged before this migration carry NULL and
    //    cannot be attributed; they age out under the prune's own retention
    //    (default 30 days). The entity staging table needs no column: its
    //    payload now carries `user_id` (`payload->>'user_id'`).
    //  * `noo_uploads`: `POST /upload` kept raw files under `uploads/` with no
    //    record of who sent them, so nothing could target them. One row per
    //    (content hash, uploader): the file is named by its content hash, so two
    //    accounts uploading the same bytes share one file and an erase removes
    //    the file only when its last owner is gone.
    //
    // Guarded with to_regclass: the tables are created by the baseline, but
    // this chain also runs against a database with no baseline (see 076/077).
    sql: r#"
DO $$
BEGIN
    IF to_regclass('noo_user_erasure_staging') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS noo_user_erasure_staging_staged_at_idx ON noo_user_erasure_staging (staged_at);
    END IF;
    IF to_regclass('graph_edge_prune_staging') IS NOT NULL THEN
        ALTER TABLE graph_edge_prune_staging ADD COLUMN IF NOT EXISTS user_id text;
        CREATE INDEX IF NOT EXISTS graph_edge_prune_staging_user_idx ON graph_edge_prune_staging (user_id) WHERE user_id IS NOT NULL;
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS noo_uploads (
    file_id     text        NOT NULL,
    owner       text        NOT NULL,
    filename    text,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, owner)
);
CREATE INDEX IF NOT EXISTS noo_uploads_owner_idx ON noo_uploads (owner)
"#,
}, Migration {
    revision: "085_heartbeat_task_authorisation",
    down_revision: Some("084_erasure_residue_stores"),
    // The scheduled junk-entity cleanup (`entity_cleanup` heartbeat action) and the record of who
    // decided a destructive task.
    //
    // An automation that deletes data is a PERSON'S decision (operator, 2026-10-05): a write to such a
    // task by an MCP door or agent run is a proposal in `noo_user_proposals` (action `heartbeat_task`)
    // that a person approves. The decision is kept on the task, not in its config (config is what an
    // agent edits):
    //  * `authorised_by` / `authorised_at`: the account that decided, directly or by approving a
    //    proposal, and when. Null for a task that is not destructive.
    //  * `authorised_config`: for an `entity_cleanup` apply task, the normalised apply / max_delete /
    //    examples the person decided. The scheduler applies only while the config still matches it.
    // The weekly preview is seeded DISABLED: it needs the trellion worker, which an install may not
    // run, and a disabled row costs nothing; `noo heartbeat toggle entity_cleanup --on` turns it on.
    // It is never seeded with apply. Guarded like the grants: a legacy fixture without the table
    // migrates.
    sql: r#"
DO $$
BEGIN
    IF to_regclass('noo_heartbeat_tasks') IS NOT NULL THEN
        ALTER TABLE noo_heartbeat_tasks
            ADD COLUMN IF NOT EXISTS authorised_by text,
            ADD COLUMN IF NOT EXISTS authorised_at timestamptz,
            ADD COLUMN IF NOT EXISTS authorised_config text;
        -- Deleting a task keeps its run history: the runs' foreign key cascaded, so an agent (or
        -- anyone) could erase a task's history by deleting the task. `heartbeat_retention` ages
        -- history out on its own.
        ALTER TABLE IF EXISTS noo_heartbeat_runs DROP CONSTRAINT IF EXISTS noo_heartbeat_runs_task_id_fkey;
        -- Who created a saved recipient, when a person did: a scheduled task an agent writes may send
        -- only to targets a person registered. Existing rows stay NULL (their author is not known).
        ALTER TABLE IF EXISTS noo_channel_recipients ADD COLUMN IF NOT EXISTS created_by text;
        INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, created_by)
        VALUES ('entity_cleanup', 'Junk-entity cleanup (weekly, preview)', '30 7 * * 0',
                'entity_cleanup', '{"apply": false, "max_delete": 1000, "examples": 0}'::jsonb, false, 'system')
        ON CONFLICT (id) DO NOTHING;
    END IF;
END $$
"#,
}, Migration {
    revision: "086_model_classes",
    down_revision: Some("085_heartbeat_task_authorisation"),
    // Model classes and aliases: the names an external
    // consumer may send as `model`, each an ORDERED list of candidates.
    //  * `noo_model_classes`: one row per (class, node, backend); `position`
    //    is the declared order; `model` NULL means "the placement's model"
    //    (`noo_backend_placements` stays the one declaration of what a node
    //    serves — this table never restates it); `degraded` marks the only
    //    kind of candidate allowed to answer with a different model.
    //  * `noo_model_aliases`: a second name for a class (`default` and `auto`
    //    are built in and never stored).
    // Both empty on a fresh install: with nothing declared the gateway derives
    // one class per served model (`coordinator::classes`).
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_model_classes (
    class       text        NOT NULL,
    position    integer     NOT NULL,
    node_id     text        NOT NULL,
    backend     text        NOT NULL,
    model       text,
    degraded    boolean     NOT NULL DEFAULT false,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (class, node_id, backend)
);
CREATE INDEX IF NOT EXISTS noo_model_classes_order_idx ON noo_model_classes (class, position);
CREATE TABLE IF NOT EXISTS noo_model_aliases (
    alias       text        PRIMARY KEY,
    class       text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
)
"#,
}, Migration {
    revision: "087_placement_role_key",
    down_revision: Some("086_model_classes"),
    // Placements are keyed (node_id, backend, ROLE), not (node_id, backend).
    // The old unique pair made a second role on one backend REPLACE the first:
    // `noo cluster place host6 ollama harrier --role embed` overwrote the
    // chat model the same ollama was serving. One ollama can host
    // a chat model and an embedder; the key now says so.
    //  * backfill: a NULL/blank role becomes `chat`, the default every
    //    pre-role row already routes as (the column is NOT NULL DEFAULT 'chat'
    //    since 032, so this is belt and braces on a hand-edited table);
    //  * the unique CONSTRAINT is swapped for a unique INDEX on the triple
    //    (ON CONFLICT (node_id, backend, role) targets it);
    //  * no row is rewritten, moved or dropped: every old pair is unique, so
    //    it is trivially unique as a triple.
    // Guarded by to_regclass: the legacy-layout fixtures carry no placements.
    sql: r#"
DO $$
BEGIN
    IF to_regclass('noo_backend_placements') IS NOT NULL THEN
        UPDATE noo_backend_placements SET role = 'chat' WHERE role IS NULL OR role = '';
        ALTER TABLE noo_backend_placements DROP CONSTRAINT IF EXISTS uq_placement_node_backend;
        CREATE UNIQUE INDEX IF NOT EXISTS uq_placement_node_backend_role
            ON noo_backend_placements (node_id, backend, role);
    END IF;
END $$
"#,
}, Migration {
    revision: "088_placement_target_usage",
    down_revision: Some("087_placement_role_key"),
    // `noo cluster place --on cpu|gpu` and `noo cluster set-config --usage
    // shared|dedicated`.
    //  * noo_backend_placements.target: the hardware a placement runs on. NULL
    //    is "not declared" (every existing row): the fit check and the node
    //    agent then fall back to what they did before (N_GPU_LAYERS=0 means
    //    CPU, a node without a GPU is CPU, otherwise GPU). Not an env key: the
    //    agent must act on it OUTSIDE the env allow-list (no GPU device for the
    //    container) and fold it into the spec hash, and N_GPU_LAYERS is
    //    volatile in that hash, so a target change hidden in env would never
    //    recreate the container.
    //  * noo_backend_placements.memory_limit_bytes: the llama.cpp container's
    //    memory limit, from the same estimate (placement_fit::llamacpp_memory_limit).
    //  * noo_node_config.usage_profile: shared | dedicated, NULL = the default
    //    (dedicated on the controller's own node, shared elsewhere).
    // Additive, nullable, no rewrite. Guarded by to_regclass like 087.
    sql: r#"
DO $$
BEGIN
    IF to_regclass('noo_backend_placements') IS NOT NULL THEN
        ALTER TABLE noo_backend_placements ADD COLUMN IF NOT EXISTS target text;
        -- The llama.cpp container's memory limit, derived at place time from
        -- the fit estimate and capped by the usage profile; NULL = the agent's
        -- own default.
        ALTER TABLE noo_backend_placements ADD COLUMN IF NOT EXISTS memory_limit_bytes bigint;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'noo_backend_placements_target_chk') THEN
            ALTER TABLE noo_backend_placements ADD CONSTRAINT noo_backend_placements_target_chk
                CHECK (target IS NULL OR target IN ('cpu', 'gpu'));
        END IF;
    END IF;
    IF to_regclass('noo_node_config') IS NOT NULL THEN
        ALTER TABLE noo_node_config ADD COLUMN IF NOT EXISTS usage_profile text;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'noo_node_config_usage_profile_chk') THEN
            ALTER TABLE noo_node_config ADD CONSTRAINT noo_node_config_usage_profile_chk
                CHECK (usage_profile IS NULL OR usage_profile IN ('shared', 'dedicated'));
        END IF;
    END IF;
END $$
"#,
}, Migration {
    revision: "089_usage_harness_kind",
    down_revision: Some("088_placement_target_usage"),
    // i83 E1b: a foreign loop on a node harness (Copilot CLI, Claude Code)
    // makes its model calls through the harness's wire translator, which
    // counts them; the `usage` rail op records the totals here as the
    // turn's user on the harness's node. `harness_kind` names the loop
    // (`config/harness-kinds.json`): NULL for every row any other writer
    // makes, so nothing existing changes meaning.
    //
    // Raw rows only. The monthly rollup keeps its key; a harness row's
    // `backend` is `harness:<kind>`, so `group=backend` still separates
    // the kinds after retention. Adding the column on the partitioned
    // parent adds it to every partition; nullable, no default, no rewrite.
    sql: r#"
ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS harness_kind text;
"#,
}, Migration {
    revision: "090_service_key_expiry",
    down_revision: Some("089_usage_harness_kind"),
    // An expiry on a service key. Set only on the keys a node harness mints
    // for a foreign CLI (`service_keys::mint_door_key`): a user-door key that
    // lives as long as one turn. `service_keys::resolve` refuses a row past
    // it; NULL (every existing row) never expires. Additive, nullable, no
    // rewrite; IF EXISTS like 078.
    sql: r#"
ALTER TABLE IF EXISTS noo_service_keys ADD COLUMN IF NOT EXISTS expires_at timestamptz
"#,
}, Migration {
    revision: TOKEN_BUDGETS_REVISION,
    down_revision: Some("090_service_key_expiry"),
    // i83 G: token budgets as a switch at the loop boundary
    // (`task_budget.rs`).
    //
    // On a task: `token_budget` (NULL = no per-task cap), `tokens_spent`
    // (prompt + completion across its loops, native and harness, added one
    // loop at a time by an UPDATE … RETURNING), `budget_state` (NULL, or
    // `exhausted` / `awaiting_clarification` — set ONLY at the loop
    // boundary, so a set state means the runner has stopped) and
    // `clarification` (the question a loop asked, then the owner's answer
    // until the next loop reads it).
    //
    // `noo_token_allowances`: a person's standing allowance per period,
    // set by an operator. Keyed on the account's uuid like the usage rows
    // (063), so a rename keeps it and deleting the account drops it.
    //
    // `noo_token_usage.task_id`: the task a row was spent on, for both the
    // native loop and the `usage` rail op. On the partitioned parent, so
    // every partition gets it; nullable, no default, no rewrite.
    sql: r#"
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS token_budget bigint;
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS tokens_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS budget_state text;
ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS clarification jsonb;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'noo_tasks_budget_state_chk') THEN
        ALTER TABLE noo_tasks ADD CONSTRAINT noo_tasks_budget_state_chk
            CHECK (budget_state IS NULL OR budget_state IN ('exhausted', 'awaiting_clarification'));
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS noo_token_allowances (
    user_uuid    uuid PRIMARY KEY REFERENCES noo_users(user_uuid) ON DELETE CASCADE,
    period       text NOT NULL DEFAULT 'month',
    limit_tokens bigint NOT NULL,
    updated_by   text,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT noo_token_allowances_period_chk CHECK (period IN ('day', 'week', 'month')),
    CONSTRAINT noo_token_allowances_limit_chk CHECK (limit_tokens >= 0)
);
ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS task_id text;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_token_allowances TO noo_app;
    END IF;
END $$;
"#,
}, Migration {
    revision: KIOSK_SEATS_REVISION,
    down_revision: Some(TOKEN_BUDGETS_REVISION),
    // i77: kiosk SEATS. A display is a seat, a role that can never hold a
    // node's credentials, so seats get their OWN tables rather than a `role`
    // column on the node rows: no existing node selector (placement,
    // `cluster verify`, idle scale-down, fleet-secrets push, NATS principal
    // render) can treat a seat as a node, because a seat never appears in a
    // node query. The upgrade and verify lanes each join these explicitly.
    //
    // `noo_seat_tokens`: one-time enrolment tokens, sha256 only (the
    // bootstrap-token machinery, a distinct table). `role` is the token's
    // claim and the CHECK pins it: a row here can only ever mint a seat.
    // `noo_seats`: the registry — the seat's self-signed BIRTH cert (what its
    // bundles are encrypted to and its proofs verify against), facts, and the
    // last signed heartbeat. `noo_seat_bundles`: the staged CMS ciphertext
    // and the seat's signed fetch/apply receipts, the twin of
    // `noo_provision_bundles` for seats.
    sql: r#"
CREATE TABLE IF NOT EXISTS noo_seat_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  text NOT NULL UNIQUE,
    role        text NOT NULL DEFAULT 'seat',
    seat_name   text NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by_ip  text,
    revoked     boolean NOT NULL DEFAULT false,
    CONSTRAINT noo_seat_tokens_role_chk CHECK (role = 'seat')
);
CREATE TABLE IF NOT EXISTS noo_seats (
    seat_name    text PRIMARY KEY,
    birth_cert   text NOT NULL,
    facts        jsonb,
    enroll_user  text,
    token_id     uuid,
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz,
    heartbeat    jsonb
);
CREATE TABLE IF NOT EXISTS noo_seat_bundles (
    seat_name   text PRIMARY KEY REFERENCES noo_seats(seat_name) ON DELETE CASCADE,
    blob        bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    fetched_at  timestamptz,
    applied_at  timestamptz,
    applied_sha text,
    apply_rc    integer,
    apply_msg   text
);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT SELECT, INSERT, UPDATE ON noo_seat_tokens TO noo_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_seats TO noo_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON noo_seat_bundles TO noo_app;
    END IF;
END $$;
"#,
}, Migration {
    revision: MODEL_CLASS_POOL_REVISION,
    down_revision: Some(KIOSK_SEATS_REVISION),
    // A declared model class may be a POOL: its non-degraded candidates
    // share the load (least in flight, then heartbeat load) instead of
    // failing over in declared order (`coordinator::classes`). Written on
    // every row of the class. Additive, NOT NULL DEFAULT false: every
    // existing class keeps its failover order.
    sql: r#"
ALTER TABLE IF EXISTS noo_model_classes ADD COLUMN IF NOT EXISTS pool boolean NOT NULL DEFAULT false
"#,
}, Migration {
    revision: AUDIT_CHAIN_REVISION,
    down_revision: Some(MODEL_CLASS_POOL_REVISION),
    // Audit log: deletion evidence and an INSERT-only application role.
    //
    // 1. TWO COLUMNS for a hash chain over the rows. `chain_seq` is a
    //    gapless counter; `chain_hash` = HMAC(audit key, domain, seq, the
    //    previous row's chain_hash, this row's entry_hash)
    //    (`audit_chain.rs`). A deleted or reordered middle row breaks it,
    //    which the per-row `entry_hash` could not show. Both nullable: every
    //    existing row stays as written (they are covered by ONE signed digest
    //    in the genesis row the gateway appends at boot, since only the
    //    gateway holds the key and a migration does not). The index serves
    //    the writers' "newest chained row" read.
    //
    // 2. The application role loses UPDATE, DELETE and TRUNCATE on the table
    //    and its partitions (see `audit_append_only_sql`). It keeps INSERT and
    //    SELECT. The owner (`noo`, which runs migrations) is unchanged.
    //
    // 3. `noo_ensure_audit_partition` (036) revokes the same on each
    //    partition it creates, because default privileges would otherwise
    //    grant the app role full DML on the NEW partition directly.
    //
    // 4. `noo_drop_audit_partition` (047) refuses to drop a partition whose
    //    chained rows have no `audit_retention_checkpoint` row naming exactly
    //    their seq range. The checkpoint is a signed row the retention job
    //    writes first; the verifier then reads the gap as retention, not
    //    tampering. (The function cannot check the signature; the verifier
    //    does. It stops a retention job that does not write one, and an old
    //    worker image, from dropping history silently.)
    sql: concat!(r#"
ALTER TABLE noo_security_audit ADD COLUMN IF NOT EXISTS chain_seq bigint;
ALTER TABLE noo_security_audit ADD COLUMN IF NOT EXISTS chain_hash text;
CREATE INDEX IF NOT EXISTS noo_security_audit_chain_seq_idx
    ON noo_security_audit (chain_seq DESC) WHERE chain_seq IS NOT NULL;

CREATE OR REPLACE FUNCTION noo_ensure_audit_partition(p_year int, p_month int)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = mesh, public, pg_catalog
AS $fn$
DECLARE
    v_name  text;
    v_start date;
    v_end   date;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;

    v_name  := format('noo_security_audit_%s_%s',
                      to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    v_start := make_date(p_year, p_month, 1);
    v_end   := (v_start + interval '1 month')::date;

    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
        RETURN false;
    END IF;

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF noo_security_audit '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM noo_app', v_name);
    END IF;
    RETURN true;
END;
$fn$;

REVOKE ALL ON FUNCTION noo_ensure_audit_partition(int, int) FROM PUBLIC;
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT EXECUTE ON FUNCTION noo_ensure_audit_partition(int, int) TO noo_app;
    END IF;
END $grant$;

CREATE OR REPLACE FUNCTION noo_drop_audit_partition(p_year int, p_month int)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = mesh, public, pg_catalog
AS $body$
DECLARE
    v_name  text;
    v_start date;
    v_end   date;
    v_min   bigint;
    v_max   bigint;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;
    IF make_date(p_year, p_month, 1)
       >= date_trunc('month', now())::date THEN
        RAISE EXCEPTION
            'refusing to drop current or future audit partition %-%',
            p_year, p_month;
    END IF;

    v_name  := format('noo_security_audit_%s_%s',
                      to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    v_start := make_date(p_year, p_month, 1);
    v_end   := (v_start + interval '1 month')::date;

    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name AND relkind = 'r') THEN
        RETURN false;
    END IF;

    SELECT min(chain_seq), max(chain_seq) INTO v_min, v_max
      FROM noo_security_audit
     WHERE "timestamp" >= v_start AND "timestamp" < v_end AND chain_seq IS NOT NULL;
    IF v_min IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM noo_security_audit
         WHERE event_type = 'audit_retention_checkpoint'
           AND chain_seq IS NOT NULL
           AND resource LIKE format('audit-retention:from:%s;through:%s;%%', v_min, v_max)
    ) THEN
        RAISE EXCEPTION '%', format(
            'refusing to drop audit partition %s-%s: its chained rows (seq %s..%s) have no '
            'audit_retention_checkpoint row. Run the retention job from a current worker '
            'image (it writes the signed checkpoint before it drops); dropping without one '
            'would read as deleted history in the audit verify',
            p_year, p_month, v_min, v_max);
    END IF;

    EXECUTE format('ALTER TABLE noo_security_audit DETACH PARTITION %I', v_name);
    EXECUTE format('DROP TABLE %I', v_name);
    RETURN true;
END;
$body$;

REVOKE ALL ON FUNCTION noo_drop_audit_partition(int, int) FROM PUBLIC;
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN
        GRANT EXECUTE ON FUNCTION noo_drop_audit_partition(int, int) TO noo_app;
    END IF;
END $grant$;
"#, audit_append_only_sql!()),
} , Migration {
    revision: "095_conversation_sources",
    down_revision: Some(AUDIT_CHAIN_REVISION),
    sql: r#"
CREATE TABLE noo_conversation_sources (
    user_id text NOT NULL,
    publisher_id uuid NOT NULL,
    source_id uuid NOT NULL,
    conversation_id uuid NOT NULL UNIQUE,
    deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id,publisher_id,source_id)
);
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='noo_app') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON noo_conversation_sources TO noo_app;
    END IF;
END $$;
"#,
}];

/// The kiosk-seat revision (i77).
pub const KIOSK_SEATS_REVISION: &str = "092_kiosk_seats";

/// The token-budget revision (i83 G). A constant so a renumber at rebase is
/// one line.
pub const TOKEN_BUDGETS_REVISION: &str = "091_token_budgets";

/// The model-class pool revision. A constant so a renumber at
/// rebase is one line.
pub const MODEL_CLASS_POOL_REVISION: &str = "093_model_class_pool";

/// The Alembic revision the baselines reproduce.
///
/// An install stamped BELOW this cannot use the sqlx engine — the baseline
/// would recreate a schema it already partly has, and `MIGRATIONS` contains
/// nothing to bridge the gap. Such an install runs Alembic once to reach this
/// revision, then switches. [`plan`] refuses on `UnknownCurrent`, so getting
/// this wrong is loud rather than silent.
pub const BASELINE_REVISION: &str = "046_heartbeat_run_prune_staging";

/// OSS schema. Generated by `scripts/generate-mesh-baseline.sh` — never edit.
pub const BASELINE_OSS: &str = include_str!("../migrations/0001_baseline.sql");


/// Create the whole schema on an EMPTY database and stamp it at the
/// cut-over revision.
///
/// Only ever runs when `alembic_version_mesh` does not exist. An install that
/// already has it — whether stamped by Alembic or by a previous run of this —
/// is left alone; the baseline is not idempotent DDL and must not be replayed
/// over a live schema.
///
/// Everything happens in ONE transaction, so a partial apply cannot leave a
/// half-built schema stamped as complete.
pub async fn apply_baseline(db: &PgPool) -> Result<bool, sqlx::Error> {
    if current_revision(db).await?.is_some() {
        return Ok(false);
    }
    // Belt and braces: current_revision returns None both for "no table" and
    // "table exists but empty". The second case means someone stamped nothing
    // onto a real schema, and replaying the baseline there would fail
    // confusingly on the first CREATE TABLE. Check the table itself.
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables          WHERE table_schema = 'public' AND table_name = $1)",
    )
    .bind(VERSION_TABLE)
    .fetch_one(db)
    .await?;
    if table_exists {
        tracing::warn!(
            "mesh baseline skipped: {VERSION_TABLE} exists but is unstamped.              Refusing to replay the baseline over an existing schema."
        );
        return Ok(false);
    }

    // Mesh's own schema — symmetry with trellion and evolve, so `public`
    // stops being a segment nobody declared. Check-then-create (privilege is
    // checked before IF NOT EXISTS, noo-evolve#7; this connection is
    // privileged so the guard would hold, the shape is kept for consistency).
    // Ownership by noomesh_ddl arrives with the broker manifest entry —
    // ensure_schema re-owns an existing schema — and the CREATEROLE work in
    // the 2026-08-05 audit; created by the migrator until then.
    let have_schema: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'mesh')")
            .fetch_one(db)
            .await?;
    if !have_schema {
        sqlx::raw_sql("CREATE SCHEMA mesh").execute(db).await?;
    }

    let mut tx = db.begin().await?;
    // The baseline is UNQUALIFIED since the mesh-schema move (its pg_dump
    // set_config line is stripped too), so the search path decides layout:
    // `mesh` first puts every table there on a fresh install. The old
    // trap — the dump emptying the SESSION's path and starving the stamping
    // INSERT — cannot recur, because the path is now set by US, after the
    // dump text, in the same transaction.
    sqlx::raw_sql("SET search_path = mesh, public")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(BASELINE_OSS).execute(&mut *tx).await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {VERSION_TABLE} (version_num) VALUES ($1)"
    )))
    .bind(BASELINE_REVISION)
    .execute(&mut *tx)
    .await?;
    // Do not hand a rewritten search path back to the pool.
    sqlx::raw_sql("SET search_path TO public")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // No `pro` field: the baseline is OSS-only by construction now. Evolve's
    // five tables come from evolve's OWN chain, into its own schema, as its
    // own DDL role — tie (1) of the four is cut.
    tracing::info!(
        revision = BASELINE_REVISION,
        "mesh baseline applied to an empty database"
    );
    Ok(true)
}

/// Drop the cross-domain FK, and never create another.
///
/// `fk_temporal_edges_source_cycle` linked `noo_temporal_edges.source_cycle_id`
/// (trellion's table) to `noo_hofstadter_loop_cycles.id` (evolve's). While
/// it stood, mesh had to WAIT for trellion's migration head before it could
/// reconcile, so one system's boot depended on another system's schema.
///
/// WHY DROPPING IS SAFE, MEASURED RATHER THAN ASSUMED (2026-08-05, live):
///
/// * `noo_temporal_edges`: 4474 rows, **0** with a non-null `source_cycle_id`
/// * nothing deletes a cycle row, so `ON DELETE SET NULL` was unreachable
/// * RTBF (`routes/users.rs::erase_targets`) deletes the CHILD side, which an
///   FK never blocks
///
/// So it guarded zero rows and its cascade could not fire. Per the design the
/// link survives as a VALUE. Enforcement is deliberately not built yet: there
/// is no writer to enforce against, and a check written before its first
/// caller is a guess. It becomes required the moment `source_cycle_id` starts
/// being populated — `autonomy` gains a reconciliation check for exactly that,
/// so the obligation is detected rather than remembered.
///
/// Idempotent, and unconditional: an OSS install never had the constraint, so
/// this is a no-op there rather than something to gate behind the pro cfg.
pub async fn drop_cross_domain_fk(db: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::raw_sql(
        "ALTER TABLE IF EXISTS public.noo_temporal_edges \
         DROP CONSTRAINT IF EXISTS fk_temporal_edges_source_cycle",
    )
    .execute(db)
    .await?;

    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conname = 'fk_temporal_edges_source_cycle')",
    )
    .fetch_one(db)
    .await
}


/// Which engine owns the mesh schema this boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Python Alembic applies the chain (today's behaviour, and the default).
    Alembic,
    /// This runner applies it.
    Sqlx,
}

impl Engine {
    /// Parse `NOO_MESH_MIGRATOR`. **Default is now `sqlx`**
    /// step 4; `alembic` is the explicit opt-out, kept for one release.
    ///
    /// The predicate is deliberately "is it exactly `alembic`?" rather than
    /// "is it exactly `sqlx`?", because entrypoint.py has to make the SAME
    /// decision in Python and the dangerous disagreement is asymmetric: if
    /// Python hands mesh over and Rust does not take it, a fresh install
    /// gets NO schema at all. One negated literal is the easiest thing to
    /// mirror exactly, and a test pins both sides.
    ///
    /// An unrecognised value therefore lands on the default (sqlx) with a
    /// warning — the same place an unset value lands, so a typo cannot
    /// produce a THIRD behaviour.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("alembic") => Self::Alembic,
            None | Some("") | Some("sqlx") => Self::Sqlx,
            Some(other) => {
                tracing::warn!(
                    value = other,
                    "NOO_MESH_MIGRATOR unrecognized — using the default sqlx \
                     engine (valid: sqlx | alembic)"
                );
                Self::Sqlx
            }
        }
    }

    pub fn from_env() -> Self {
        Self::parse(std::env::var("NOO_MESH_MIGRATOR").ok().as_deref())
    }
}

/// Why a plan could not be computed. Every variant is a refusal to guess.
#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The database is stamped at a revision this binary does not know.
    ///
    /// Almost always "the deployed image is older than the database" — a
    /// rollback that skipped a migration. Applying anything here would be
    /// applying it out of order.
    UnknownCurrent(String),
    /// Two revisions claim the same `down_revision`, so the chain forks and
    /// "the next migration" is ambiguous.
    Branched { after: String, a: String, b: String },
    /// A revision names a `down_revision` that is not in the chain.
    DanglingParent { revision: String, parent: String },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCurrent(r) => write!(
                f,
                "database is stamped at revision {r:?}, which this binary does \
                 not know. The image is probably older than the database. \
                 Refusing to migrate rather than apply revisions out of order."
            ),
            Self::Branched { after, a, b } => write!(
                f,
                "migration chain branches after {after:?}: both {a:?} and \
                 {b:?} claim it as down_revision. Alembic allows branches; \
                 this runner does not, because 'the next migration' would be \
                 ambiguous."
            ),
            Self::DanglingParent { revision, parent } => write!(
                f,
                "revision {revision:?} names down_revision {parent:?}, which \
                 is not in the chain"
            ),
        }
    }
}

/// Order the chain and return everything after `current`.
///
/// Pure and total — no database, no I/O — because this is the part that can
/// silently corrupt a schema by applying the wrong thing, and it deserves to
/// be exhaustively testable.
pub fn plan<'a>(
    current: Option<&str>,
    migrations: &'a [Migration],
) -> Result<Vec<&'a Migration>, PlanError> {
    if migrations.is_empty() {
        // Step 1: nothing ported yet. An install already stamped by Alembic is
        // simply ahead of us, which is expected and not an error.
        return Ok(Vec::new());
    }

    // Link the chain by down_revision, checking for forks as we go.
    let mut by_parent: std::collections::HashMap<Option<&str>, &Migration> =
        std::collections::HashMap::new();
    for m in migrations {
        if let Some(prev) = by_parent.insert(m.down_revision, m) {
            return Err(PlanError::Branched {
                after: m.down_revision.unwrap_or("<base>").to_string(),
                a: prev.revision.to_string(),
                b: m.revision.to_string(),
            });
        }
    }

    // The BASELINE is implicitly known: the first post-baseline revision
    // anchors on BASELINE_REVISION, which is stamped by apply_baseline and
    // never appears in MIGRATIONS. This branch was unreachable while the
    // list was empty — 047, the first real entry, hit it on the first fresh
    // apply(), caught by the layout test rather than by an install.
    let known: std::collections::HashSet<&str> = migrations
        .iter()
        .map(|m| m.revision)
        .chain(std::iter::once(BASELINE_REVISION))
        .collect();
    for m in migrations {
        if let Some(p) = m.down_revision {
            if !known.contains(p) {
                return Err(PlanError::DanglingParent {
                    revision: m.revision.to_string(),
                    parent: p.to_string(),
                });
            }
        }
    }

    // Walk from the base, collecting everything after `current`. The walk
    // starts at the baseline anchor, not at None: post-baseline revisions
    // declare down_revision = BASELINE_REVISION, which is the real base of
    // this chain.
    let mut ordered: Vec<&Migration> = Vec::with_capacity(migrations.len());
    let mut cursor: Option<&str> = Some(BASELINE_REVISION);
    if !by_parent.contains_key(&cursor) {
        // Legacy shape: a chain whose first entry uses down_revision = None.
        cursor = None;
    }
    while let Some(next) = by_parent.get(&cursor) {
        ordered.push(next);
        cursor = Some(next.revision);
    }

    let Some(current) = current else {
        // Empty database — apply the whole chain.
        return Ok(ordered);
    };
    // Stamped exactly at the baseline: the normal state of every install the
    // moment a post-baseline revision first ships, and of every fresh
    // install right after apply_baseline. Everything in the chain is
    // pending. Unreachable while MIGRATIONS was empty (the is_empty()
    // early-return above answered first), so 047 — the first real entry —
    // was the first code path to ever get here.
    if current == BASELINE_REVISION {
        return Ok(ordered);
    }
    match ordered.iter().position(|m| m.revision == current) {
        Some(i) => Ok(ordered[i + 1..].to_vec()),
        None => Err(PlanError::UnknownCurrent(current.to_string())),
    }
}

/// Read the stamped revision, or `None` when the table does not exist yet.
///
/// A missing table means a fresh database, not a failure — Alembic creates it
/// on first upgrade and so would we.
/// Where `alembic_version_mesh` actually lives on THIS install.
///
/// Fresh installs (mesh-schema layout) stamp in `mesh.`; installs that
/// predate the layout keep `public.` until the cutover moves everything at
/// once. Checked per call rather than cached: the migration path runs once
/// per boot, and a cache invalidated by the very migration it guards is a
/// bug shaped like an optimisation.
async fn version_table_ref(db: &PgPool) -> Result<&'static str, sqlx::Error> {
    let in_mesh: bool = sqlx::query_scalar(
        "SELECT to_regclass('mesh.alembic_version_mesh') IS NOT NULL",
    )
    .fetch_one(db)
    .await?;
    Ok(if in_mesh {
        "mesh.alembic_version_mesh"
    } else {
        "public.alembic_version_mesh"
    })
}

pub async fn current_revision(db: &PgPool) -> Result<Option<String>, sqlx::Error> {
    let vt = version_table_ref(db).await?;
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(vt)
        .fetch_one(db)
        .await?;
    if !exists {
        return Ok(None);
    }
    let rev: Option<String> =
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT version_num FROM {vt} LIMIT 1")))
            .fetch_optional(db)
            .await?;
    Ok(rev)
}

/// Report what this runner sees, without changing anything.
///
/// Runs regardless of engine, so the stamped revision can be compared against
/// `noo db current` before the engine is ever flipped. Applying is
/// [`apply_baseline`], which only the sqlx engine calls.
/// Bring the mesh schema up to date. Only called when this engine owns it.
///
/// Fatal on error, by the caller's choice: a gateway that boots on a schema
/// it could not migrate is the failure mode with the widest blast radius in
/// the system, so it must not start.
///
/// Ordering: baseline (empty DB only) -> pending revisions -> cross-domain
/// FK. The FK is last because it is the only step that depends on a table
/// this env does not own.
pub async fn apply(db: &PgPool) -> Result<(), String> {
    let created = apply_baseline(db).await.map_err(|e| e.to_string())?;

    // Roles BEFORE revisions, grants included. Revision 047 — the first
    // post-baseline entry — grants EXECUTE to noo_app, and on a truly fresh
    // install that role did not exist yet under the old order (roles were
    // provisioned after the pending loop). Caught by the layout test, not by
    // CI: the shared CI database always carries noo_app from the chain
    // replay, which is exactly the kind of pre-warmed state that hides
    // ordering bugs. Grants issued here use ON ALL TABLES (covers the
    // baseline, which has run) plus default privileges (covers whatever the
    // revisions below create).
    crate::role_provision::run(db).await?;

    let current = current_revision(db).await.map_err(|e| e.to_string())?;
    let pending = plan(current.as_deref(), MIGRATIONS).map_err(|e| e.to_string())?;

    // Resolved BEFORE the loop opens a transaction. The migration pool has
    // exactly ONE connection; db.begin() holds it, and calling
    // version_table_ref(db) inside the loop then waits forever for a second
    // connection that cannot exist. That deadlock shipped in the mesh-schema
    // PR and crash-looped the live gateway the first time `pending` was
    // non-empty — which was also the first time it COULD be, 047 being the
    // first post-baseline revision. The table's location cannot change
    // between revisions of one run, so hoisting is correct, not just safe.
    let vt = version_table_ref(db).await.map_err(|e| e.to_string())?;
    for m in &pending {
        let mut tx = db.begin().await.map_err(|e| e.to_string())?;
        // Same layout rule as the baseline: revisions are unqualified, and
        // the path decides where objects land — schema `mesh` on a fresh
        // install, `public` on a legacy one, where the mesh schema does not
        // exist and Postgres silently skips the missing path entry. That
        // silence is doing work here: one revision text serves both layouts.
        sqlx::raw_sql("SET search_path = mesh, public")
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::raw_sql(m.sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("{} failed: {e}", m.revision))?;
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {vt} SET version_num = $1")))
            .bind(m.revision)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::raw_sql("SET search_path TO public")
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        tracing::info!(revision = m.revision, "mesh revision applied");
    }

    // Converges an install that still carries the constraint from before
    // the design. Idempotent, so it is a no-op everywhere else.
    let fk = drop_cross_domain_fk(db).await.map_err(|e| e.to_string())?;

    // The broker: roles and schemas for the systems
    // declared in the `systems:` manifest and turned on by the operator.
    //
    // AFTER role_provision, not instead of it. The two overlap deliberately
    // during A′ — both are create-if-absent and idempotent — so there is never
    // a window with neither. role_provision keeps owning table ownership until
    // B′ moves tables into per-system schemas, at which point ownership is
    // correct at birth and that pass deletes.
    crate::system_provision::run(db).await?;

    // LAST: role_provision and system_provision above re-grant UPDATE and
    // DELETE on every table to the application role on every run, so the
    // audit log's INSERT-only restriction is re-asserted after them.
    enforce_audit_append_only(db).await?;

    tracing::info!(
        baseline_created = created,
        applied = pending.len(),
        cross_domain_fk_present = fk,
        "mesh schema is up to date (sqlx engine)"
    );
    Ok(())
}

/// Resolve the PRIVILEGED migration DSN, mirroring docker/entrypoint.py.
///
/// The runtime pool is NOT usable for this. It connects as `noo_app`, which
/// deliberately has no CREATE on schema public and owns no tables — checked
/// on the live cluster: `has_schema_privilege('noo_app','public','CREATE')`
/// is false. Applying the baseline through it fails with a permission error
/// on the very first fresh install, which is the case the sqlx engine exists
/// to serve.
///
/// The order matches entrypoint.py exactly, including the legacy fallbacks,
/// so both engines migrate as the SAME role. Diverging here would mean the
/// two paths create tables with different owners, and the role migrations
/// (033/034/038) assume one.
fn migration_dsn() -> Option<String> {
    for key in [
        "NOO_MIGRATIONS_DSN",
        "PAGEINDEX_DSN",
        "PGVECTOR_URL",
        "DATABASE_URL",
    ] {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                // sqlx speaks postgresql://; the Python side tags a driver on.
                let v = v
                    .replace("postgresql+asyncpg://", "postgresql://")
                    .replace("postgresql+psycopg://", "postgresql://");
                // Same TLS treatment as the runtime pool — see
                // state::with_cluster_tls.
                return Some(crate::state::with_cluster_tls(v));
            }
        }
    }
    None
}

/// Startup entry point: migrate when we own the schema.
///
/// Takes NO pool and must run BEFORE AppState builds the runtime pool: the
/// broker inside `apply` is what CREATES `noo_app`, the role that pool
/// connects as. With this after AppState (its position until 2026-08-06), a
/// truly-fresh database crash-looped on "password authentication failed for
/// user noo_app" and the migration that would have fixed it never ran. Every
/// pre-existing install had the role already, so only a virgin data dir
/// exposes the cycle. Applying opens its OWN short-lived privileged
/// connection — see [`migration_dsn`].
pub async fn run() -> Result<(), String> {
    match Engine::from_env() {
        Engine::Sqlx => {
            let dsn = migration_dsn()
                .ok_or_else(|| "no migration DSN (NOO_MIGRATIONS_DSN/PAGEINDEX_DSN/PGVECTOR_URL/DATABASE_URL)".to_string())?;
            let admin = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&dsn)
                .await
                .map_err(|e| format!("migration connection failed: {e}"))?;
            let out = apply(&admin).await;
            admin.close().await;
            out
        }
        // entrypoint.py already migrated before exec'ing this binary; the
        // informational report runs later, once the runtime pool exists
        // (report_alembic).
        Engine::Alembic => Ok(()),
    }
}

/// The read-only migration report for the alembic engine — needs the runtime
/// pool, so it runs after AppState, unlike [`run`].
pub async fn report_alembic(db: &PgPool) {
    if matches!(Engine::from_env(), Engine::Alembic) {
        report(db).await;
    }
}

pub async fn report(db: &PgPool) {
    let engine = Engine::from_env();
    match current_revision(db).await {
        Ok(current) => match plan(current.as_deref(), MIGRATIONS) {
            Ok(pending) => tracing::info!(
                engine = ?engine,
                current = current.as_deref().unwrap_or("<none>"),
                ported = MIGRATIONS.len(),
                pending = pending.len(),
                "mesh migration runner"
            ),
            Err(e) => tracing::warn!(
                engine = ?engine,
                error = %e,
                "mesh migration runner: cannot compute a plan"
            ),
        },
        Err(e) => tracing::warn!(error = %e, "mesh migration runner: version read failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Migration = Migration { revision: "001_a", down_revision: None, sql: "" };
    const B: Migration = Migration { revision: "002_b", down_revision: Some("001_a"), sql: "" };
    const C: Migration = Migration { revision: "003_c", down_revision: Some("002_b"), sql: "" };
    const CHAIN: &[Migration] = &[A, B, C];

    #[test]
    fn empty_chain_plans_nothing_even_when_db_is_ahead() {
        // Step 1's real case: Alembic has stamped 046, we have ported none.
        // That is expected, not an error.
        assert_eq!(plan(Some("046_heartbeat_run_prune_staging"), &[]), Ok(vec![]));
        assert_eq!(plan(None, &[]), Ok(vec![]));
    }

    #[test]
    fn fresh_database_gets_the_whole_chain() {
        let p = plan(None, CHAIN).unwrap();
        assert_eq!(p.iter().map(|m| m.revision).collect::<Vec<_>>(), ["001_a", "002_b", "003_c"]);
    }

    #[test]
    fn plans_only_what_follows_current() {
        let p = plan(Some("002_b"), CHAIN).unwrap();
        assert_eq!(p.iter().map(|m| m.revision).collect::<Vec<_>>(), ["003_c"]);
    }

    #[test]
    fn at_head_plans_nothing() {
        assert_eq!(plan(Some("003_c"), CHAIN), Ok(vec![]));
    }

    // The dangerous case: the image is older than the database. Guessing here
    // would apply revisions out of order against a newer schema.
    #[test]
    fn unknown_current_refuses_rather_than_guessing() {
        let e = plan(Some("999_from_the_future"), CHAIN).unwrap_err();
        assert_eq!(e, PlanError::UnknownCurrent("999_from_the_future".into()));
        assert!(e.to_string().contains("older than the database"));
    }

    // Alembic permits branches; this runner must not silently pick one.
    #[test]
    fn a_branched_chain_is_rejected() {
        const FORK: &[Migration] = &[
            A,
            B,
            Migration { revision: "002_other", down_revision: Some("001_a"), sql: "" },
        ];
        match plan(None, FORK).unwrap_err() {
            PlanError::Branched { after, .. } => assert_eq!(after, "001_a"),
            other => panic!("expected Branched, got {other:?}"),
        }
    }

    #[test]
    fn a_dangling_parent_is_rejected() {
        const ORPHAN: &[Migration] = &[
            A,
            Migration { revision: "009_x", down_revision: Some("008_missing"), sql: "" },
        ];
        match plan(None, ORPHAN).unwrap_err() {
            PlanError::DanglingParent { revision, parent } => {
                assert_eq!((revision.as_str(), parent.as_str()), ("009_x", "008_missing"));
            }
            other => panic!("expected DanglingParent, got {other:?}"),
        }
    }

    /// The default flipped to sqlx.
    ///
    /// This test previously asserted the opposite and was the guard that made
    /// flipping deliberate rather than accidental. Updating it IS the flip;
    /// it is not collateral damage from one.
    #[test]
    fn engine_defaults_to_sqlx_and_only_alembic_opts_out() {
        assert_eq!(Engine::parse(None), Engine::Sqlx, "unset = the new default");
        assert_eq!(Engine::parse(Some("")), Engine::Sqlx);
        assert_eq!(Engine::parse(Some("sqlx")), Engine::Sqlx);
        assert_eq!(Engine::parse(Some("ALEMBIC")), Engine::Alembic);
        assert_eq!(Engine::parse(Some("  alembic  ")), Engine::Alembic);
        // A typo cannot invent a third behaviour — it lands on the default,
        // exactly where an unset value lands.
        assert_eq!(Engine::parse(Some("alembicc")), Engine::Sqlx, "typo != opt-out");
        assert_eq!(Engine::parse(Some("python")), Engine::Sqlx);
    }

    /// `version_num` is varchar(32) and the longest id in the tree is 31.
    /// An over-long revision would fail on INSERT — inside a migration, at
    /// startup. Cheaper to fail here.
    #[test]
    fn revision_fits_version_column() {
        for m in MIGRATIONS {
            assert!(
                m.revision.len() <= VERSION_COLUMN_LEN,
                "revision {:?} is {} chars; {VERSION_TABLE}.version_num is varchar({VERSION_COLUMN_LEN})",
                m.revision,
                m.revision.len()
            );
        }
    }

    /// The baseline must reproduce the revision it claims to.
    ///
    /// If the generator is re-run after a new Alembic revision lands, the
    /// dump advances but this constant does not — and the runner would then
    /// stamp a fresh install at a revision the schema does not match. That
    /// install would silently skip whatever the newer revision did.
    #[test]
    fn baseline_revision_matches_the_generated_dump() {
        let recorded = BASELINE_OSS
            .lines()
            .find_map(|l| l.strip_prefix("-- Alembic chain head at generation time: "))
            .expect("baseline must record the chain head it was generated from");
        assert_eq!(
            recorded.trim(),
            BASELINE_REVISION,
            "BASELINE_REVISION is stale — regenerate with \
             scripts/generate-mesh-baseline.sh and update the constant together"
        );
    }

    #[test]
    fn baseline_revision_fits_the_version_column() {
        assert!(BASELINE_REVISION.len() <= VERSION_COLUMN_LEN);
    }

    /// The OSS baseline must not carry pro DDL — of ANY object type.
    ///
    /// An earlier version of this test checked only `CREATE TABLE` and passed
    /// while four pro SEQUENCES (`noo_ga_generations_id_seq` and friends) sat
    /// in the OSS baseline: `--exclude-table` drops the table but not the
    /// sequence it owns. That was a licence leak the test declared clean, so
    /// it now matches the pro NAME PREFIXES anywhere in the file.
    #[test]
    fn oss_baseline_contains_no_pro_objects() {
        for prefix in ["noo_ga_", "noo_rl_", "noo_hofstadter_"] {
            let hit = BASELINE_OSS
                .lines()
                .find(|l| l.contains(prefix) && !l.trim_start().starts_with("--"));
            assert!(
                hit.is_none(),
                "pro object leaked into the OSS baseline: {:?}",
                hit.unwrap()
            );
        }
    }

    /// The baseline must create the version table it then stamps — otherwise
    /// apply_baseline's INSERT fails after the DDL has already run.
    #[test]
    fn baseline_creates_the_version_table() {
        assert!(BASELINE_OSS.contains(&format!("CREATE TABLE {VERSION_TABLE}")));
    }

    /// The REAL chain must plan from empty. `a_branched_chain_is_rejected`
    /// and its siblings only exercise synthetic fixtures — nothing asserted
    /// that `MIGRATIONS` itself is a straight line.
    ///
    /// That gap has teeth: `plan` returning `DanglingParent` or `Branched`
    /// means migrations never run, which means the gateway does not start.
    /// It is the worst blast radius in the system and it would first be
    /// observed as a dead fleet rather than a red build. Two ordinary edits
    /// reach it — a new revision naming a parent that is not merged yet, and
    /// two open PRs each adding a revision on the same parent — and both are
    /// invisible in review because each diff looks correct alone.
    #[test]
    fn the_real_chain_is_a_straight_line_from_empty() {
        let pending = plan(None, MIGRATIONS).unwrap_or_else(|e| {
            panic!(
                "MIGRATIONS is not a valid chain: {e}. A gateway carrying this \
                 build would refuse to migrate and therefore refuse to start."
            )
        });
        assert_eq!(
            pending.len(),
            MIGRATIONS.len(),
            "planning from empty must schedule every revision exactly once"
        );
        // Each revision's parent is its predecessor; the first one's parent
        // is the baseline, which is where the sqlx chain picks up from
        // Alembic.
        for (i, m) in pending.iter().enumerate() {
            let expected_parent =
                Some(if i == 0 { BASELINE_REVISION } else { pending[i - 1].revision });
            assert_eq!(
                m.down_revision, expected_parent,
                "{:?} does not follow {:?}",
                m.revision, expected_parent
            );
        }
    }

    /// 061 must sit on 060, and it must actually be IN the chain.
    ///
    /// `the_real_chain_is_a_straight_line_from_empty` proves the list is a
    /// line, but a line of the wrong revisions is still a line: a rebase that
    /// dropped this entry, or a second lane that claimed 061 and pushed this
    /// one onto a different parent, both leave the chain valid and leave
    /// `noo_conversations.org_id` nullable — which is invisible until an
    /// org-scoped read returns empty on a live install.
    #[test]
    fn conversation_org_revision_follows_the_evolve_grants() {
        let m = MIGRATIONS
            .iter()
            .find(|m| m.revision == "061_conversation_org")
            .expect("061_conversation_org must be in the chain");
        assert_eq!(
            m.down_revision,
            Some("060_evolve_meta_loop_grants"),
            "061 must follow 060; a different parent means another lane took \
             this slot and this revision needs renumbering"
        );
        // The three things the revision exists to do. Asserted on the SQL
        // because there is no Postgres in this crate's unit tests.
        assert!(m.sql.contains("SET DEFAULT ''default''"), "must set the column default");
        assert!(m.sql.contains("SET NOT NULL"), "must close the column to NULLs");
        assert!(
            m.sql.contains("noo_conv_set_org"),
            "must rewrite the derive trigger — a bare column DEFAULT shadows \
             it and silently files every user's conversation under 'default'"
        );
    }

    /// 089 sits on 088 and adds the column `usage::insert` writes.
    #[test]
    fn usage_harness_kind_revision_adds_the_column_the_writer_names() {
        let m = MIGRATIONS.iter().find(|m| m.revision == "089_usage_harness_kind").expect("089 must be in the chain");
        assert_eq!(m.down_revision, Some("088_placement_target_usage"));
        assert!(m.sql.contains("ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS harness_kind text"));
        let writer = include_str!("usage.rs");
        assert!(writer.contains("prompt_tokens, completion_tokens, harness_kind"), "usage::insert must write harness_kind");
    }

    /// 093 sits on the kiosk seats and adds the pool flag
    /// `classes::save_class` writes. (094, the audit chain, sits on it.)
    #[test]
    fn model_class_pool_revision_is_the_head_and_adds_the_column() {
        let m = MIGRATIONS.iter().find(|m| m.revision == MODEL_CLASS_POOL_REVISION).expect("093 must be in the chain");
        assert_eq!(m.revision, MODEL_CLASS_POOL_REVISION);
        assert_eq!(m.revision, "093_model_class_pool");
        assert_eq!(m.down_revision, Some(KIOSK_SEATS_REVISION));
        assert!(m.sql.contains("ADD COLUMN IF NOT EXISTS pool boolean NOT NULL DEFAULT false"));
        let classes = include_str!("coordinator/classes.rs");
        assert!(classes.contains("degraded, pool, updated_at"), "save_class must write pool");
    }

    /// 091 sits on 090 and adds what `task_budget` and `usage::insert` name.
    #[test]
    fn token_budgets_revision_sits_on_090_and_adds_the_columns() {
        let m = MIGRATIONS.iter().find(|m| m.revision == TOKEN_BUDGETS_REVISION).expect("091 must be in the chain");
        assert_eq!(m.revision, "091_token_budgets");
        assert_eq!(m.down_revision, Some("090_service_key_expiry"));
        assert!(MIGRATIONS.iter().any(|m| m.down_revision == Some(TOKEN_BUDGETS_REVISION)), "092 sits on 091");
        for col in ["token_budget bigint", "tokens_spent bigint NOT NULL DEFAULT 0", "budget_state text", "clarification jsonb"] {
            assert!(m.sql.contains(&format!("ALTER TABLE noo_tasks ADD COLUMN IF NOT EXISTS {col}")), "{col}");
        }
        assert!(m.sql.contains("CREATE TABLE IF NOT EXISTS noo_token_allowances"));
        assert!(m.sql.contains("ALTER TABLE noo_token_usage ADD COLUMN IF NOT EXISTS task_id text"));
        assert!(include_str!("usage.rs").contains("harness_kind, task_id)"), "usage::insert must write task_id");
    }

    /// 092 adds the chain columns and makes the app role INSERT-only, and the
    /// boot-time re-assertion runs the SAME text (the blanket re-grants that run
    /// on every migration pass would otherwise undo it).
    #[test]
    fn audit_chain_revision_adds_columns_and_revokes_dml_from_the_app_role() {
        let m = MIGRATIONS.iter().find(|m| m.revision == AUDIT_CHAIN_REVISION).expect("094 must be in the chain");
        assert_eq!(m.down_revision, Some(MODEL_CLASS_POOL_REVISION));
        for needle in [
            "ADD COLUMN IF NOT EXISTS chain_seq bigint",
            "ADD COLUMN IF NOT EXISTS chain_hash text",
            "REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM noo_app",
            // new partitions: default privileges would grant the app role DML on them
            "REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM noo_app",
            "audit_retention_checkpoint",
        ] {
            assert!(m.sql.contains(needle), "{needle}");
        }
        assert!(m.sql.contains(AUDIT_APPEND_ONLY_SQL), "the migration and the boot re-assertion share one text");
        assert!(AUDIT_APPEND_ONLY_SQL.contains("rolname = 'noo_app'"), "role-less fixture databases must still migrate");
        assert!(!AUDIT_APPEND_ONLY_SQL.contains("GRANT"), "it only takes privileges away");
        // The drop function's checkpoint pattern is the one audit_chain writes.
        let r = crate::audit_chain::Retention { from: 3, through: 9, chain: "x".into() };
        assert!(r.resource().starts_with("audit-retention:from:3;through:9;"));
        assert!(m.sql.contains("'audit-retention:from:%s;through:%s;%%'"));
    }

    /// `apply` re-asserts the restriction AFTER the steps that re-grant DML.
    #[test]
    fn apply_reasserts_append_only_after_the_regrants() {
        let src = include_str!("mesh_migrate.rs");
        let body = &src[src.find("pub async fn apply(db: &PgPool)").expect("apply")..];
        let grant = body.find("crate::system_provision::run(db)").expect("system_provision");
        let enforce = body.find("enforce_audit_append_only(db)").expect("enforce");
        assert!(enforce > grant, "the revoke must run after every blanket GRANT");
    }

    /// Post-cut-over revisions only. Anything up to BASELINE_REVISION is the
    /// baseline's job; adding it here would apply it twice on a fresh install.
    #[test]
    fn migrations_hold_only_post_baseline_revisions() {
        for m in MIGRATIONS {
            assert!(
                m.revision.as_bytes() > BASELINE_REVISION.as_bytes(),
                "{:?} is at or below the baseline revision {BASELINE_REVISION:?} — \
                 the baseline already covers it",
                m.revision
            );
        }
    }
}

/// Read the live database and prove this runner agrees with Alembic.
///
/// `#[ignore]`d because CI has no Postgres for this crate's unit tests, and
/// because the value is in running it against a REAL deployment — a synthetic
/// database cannot show that we read the same revision Alembic actually
/// stamped. That agreement is the whole acceptance criterion for step 1.
///
/// ```text
/// MESH_LIVE_DSN=postgresql://user:pw@host:5432/noomesh \
///   cargo test --release live_revision_matches_alembic -- --ignored --nocapture
/// ```
///
/// Compare the printed revision against `noo db current`.
#[cfg(test)]
#[tokio::test]
#[ignore]
async fn live_revision_matches_alembic() {
    let Ok(dsn) = std::env::var("MESH_LIVE_DSN") else {
        panic!("set MESH_LIVE_DSN to a real mesh database");
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&dsn)
        .await
        .expect("connect");

    let current = current_revision(&pool).await.expect("read version table");
    println!("alembic_version_mesh = {current:?}");
    let current = current.expect("a migrated database must have a stamped revision");

    assert!(
        current.len() <= VERSION_COLUMN_LEN,
        "stamped revision {current:?} exceeds varchar({VERSION_COLUMN_LEN})"
    );

    // Step 1 ports nothing, so a live database is always ahead of us and the
    // plan must be empty — never an error, and never work to do.
    let pending = plan(Some(&current), MIGRATIONS).expect("plan must succeed");
    assert!(pending.is_empty(), "step 1 must plan nothing, got {}", pending.len());
    println!("plan against live revision: {} pending (expected 0)", pending.len());
}

#[cfg(test)]
mod engine_ownership_tests {
    use super::*;

    /// The ONLY spelling that keeps mesh on Alembic.
    ///
    /// entrypoint.py makes the same decision independently, in Python. If the
    /// two ever disagree the failure is not symmetric: when Python hands over
    /// and Rust does not, a fresh install gets NO mesh schema and the
    /// gateway starts against an empty database. Keep the accepted set at
    /// exactly one literal so both parsers can be trivially identical, and so
    /// this test is a real constraint rather than a restatement.
    #[test]
    fn only_the_exact_string_alembic_opts_out() {
        assert_eq!(Engine::parse(Some("alembic")), Engine::Alembic);
        assert_eq!(Engine::parse(Some("  ALEMBIC  ")), Engine::Alembic, "trim + case");

        // Everything else is the default engine — including typos, so a
        // mistyped opt-out cannot invent a third behaviour.
        for defaulted in ["sqlx", "", "  ", "alembic2", "alem", "postgres", "rust", "true", "1"] {
            assert_eq!(
                Engine::parse(Some(defaulted)),
                Engine::Sqlx,
                "{defaulted:?} must land on the default engine — only an exact \
                 \"alembic\" opts out"
            );
        }
        assert_eq!(Engine::parse(None), Engine::Sqlx, "unset = the new default");
    }

}

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// The end-to-end proof for the mesh-schema layout, against a real
    /// database — because the equivalence gate applies the baseline via bare
    /// psql (deliberately, to check CONTENT in the legacy layout) and so
    /// never exercises the path-directed apply the runner actually performs.
    /// Without this, the layout half ships on inspection alone, which is the
    /// step-5 mistake with new coordinates.
    ///
    /// Gated on NOO_BROKER_TEST_DSN like the broker tests; builds its own
    /// scratch DATABASE because the job's shared one already carries the
    /// replayed chain, where apply_baseline correctly refuses to run.
    #[tokio::test]
    async fn fresh_apply_lands_everything_in_the_mesh_schema() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            return;
        };
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("connect");
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS mesh_layout_test (FORCE)")
            .execute(&admin)
            .await;
        sqlx::raw_sql("CREATE DATABASE mesh_layout_test")
            .execute(&admin)
            .await
            .expect("create scratch db");

        let scratch_dsn = {
            // swap the database path segment
            let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
            format!("{head}/mesh_layout_test")
        };
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&scratch_dsn)
            .await
            .expect("connect scratch");
        // role_provision inside apply() needs the app credential to mint
        // noo_app when the cluster has never seen one.
        std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret");
        // extensions are the broker's job; here that job is the test's
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
                .execute(&db)
                .await
                .expect("extension");
        }

        apply(&db).await.expect("apply");

        let (in_mesh, in_public): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE schemaname = 'mesh'),
                    count(*) FILTER (WHERE schemaname = 'public')
             FROM pg_tables
             WHERE schemaname IN ('mesh', 'public')",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            in_mesh > 40,
            "expected the full mesh table set in schema mesh, got {in_mesh}"
        );
        assert_eq!(
            in_public, 0,
            "a fresh install must put NOTHING in public — {in_public} table(s) leaked, \
             which is the two-layouts-at-once failure this test exists to catch"
        );

        let stamp: String =
            sqlx::query_scalar("SELECT version_num FROM mesh.alembic_version_mesh")
                .fetch_one(&db)
                .await
                .expect("stamp must live in the mesh schema on a fresh install");
        // Baseline + every pending revision: after apply() the stamp is the
        // chain HEAD, not the baseline revision.
        let head = MIGRATIONS
            .last()
            .map(|m| m.revision)
            .unwrap_or(BASELINE_REVISION);
        assert_eq!(stamp, head);

        // Re-run must be a clean no-op — the path every later boot takes.
        apply(&db).await.expect("second apply");

        // 047's definer landed in mesh and still refuses live months.
        let err = sqlx::query_scalar::<_, bool>(
            "SELECT mesh.noo_drop_audit_partition(2999, 1)",
        )
        .fetch_one(&db)
        .await
        .expect_err("current/future month must be refused");
        assert!(err.to_string().contains("refusing"), "{err}");

        db.close().await;
        let _ = sqlx::raw_sql("DROP DATABASE mesh_layout_test (FORCE)")
            .execute(&admin)
            .await;
    }
}

#[cfg(test)]
mod legacy_layout_tests {
    use super::*;

    /// The other half of the contract: an install whose stamp and tables
    /// live in `public` (every install that predates the mesh-schema move)
    /// is APPENDED TO in place — new revisions land in public, the stamp
    /// updates in public, and nothing is created in a mesh schema it does
    /// not have. The tables move at the cutover, never here.
    #[tokio::test]
    async fn legacy_apply_appends_in_public_and_creates_no_mesh_schema() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            return;
        };
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("connect");
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS mesh_legacy_test (FORCE)")
            .execute(&admin)
            .await;
        sqlx::raw_sql("CREATE DATABASE mesh_legacy_test")
            .execute(&admin)
            .await
            .expect("create");
        let (head, _) = dsn.rsplit_once('/').unwrap();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{head}/mesh_legacy_test"))
            .await
            .expect("connect scratch");

        // The minimum legacy shape apply() consults: a stamped version table
        // in PUBLIC, and 047's dependencies (parent table + noo_app, which
        // the shared cluster already has from the fresh-layout test).
        std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE TABLE public.{VERSION_TABLE} (version_num varchar(64) NOT NULL);
             INSERT INTO public.{VERSION_TABLE} VALUES ('{BASELINE_REVISION}');
             CREATE TABLE public.noo_security_audit (id bigserial, at timestamptz NOT NULL)
                 PARTITION BY RANGE (at);
             -- 050 ALTERs noo_users; the legacy fixture needs the minimal
             -- shape it touches (username + jsonb scopes), same reason the
             -- audit parent above exists for 047. 063 adds an FK to
             -- user_uuid, which every install has carried since 042 (and
             -- as its PK since 044), so the fixture carries it too.
             -- 064 ALTERs noo_node_config (companion_policy); the legacy
             -- fixture carries the one column that identifies a row.
             CREATE TABLE public.noo_node_config (node_id text PRIMARY KEY);
             -- 074 ALTERs noo_security_posture (opened_at, close_by); the
             -- fixture carries the shape 031 created, since the boot-time
             -- reader COALESCEs opened_at with updated_at.
             CREATE TABLE public.noo_security_posture (
                 key text PRIMARY KEY,
                 value text NOT NULL,
                 updated_at timestamptz NOT NULL DEFAULT now());
             -- 071 ALTERs noo_channel_recipients; the fixture carries the
             -- columns that revision keys on (nothing is read, so the
             -- minimal identifying shape is enough).
             CREATE TABLE public.noo_channel_recipients (
                 id text PRIMARY KEY,
                 channel text NOT NULL,
                 recipient_id text NOT NULL);
             -- 070 ALTERs noo_approval_requests and indexes it; the fixture
             -- carries the columns that revision reads or keys on.
             CREATE TABLE public.noo_approval_requests (
                 request_id text PRIMARY KEY,
                 status text NOT NULL DEFAULT 'pending',
                 created_at timestamptz NOT NULL DEFAULT now());
             CREATE TABLE public.noo_users (
                 username text PRIMARY KEY,
                 user_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
                 org_id text NOT NULL DEFAULT 'default',
                 scopes jsonb NOT NULL DEFAULT '[\"read\"]'::jsonb);
             -- 061 backfills conversations from their owner and closes the
             -- column. The fixture carries the three shapes that exist on a
             -- live install: owned by a user in a non-default org, owned by
             -- a user in the default org, and owned by nobody at all
             -- (heartbeat / autonomy / system tool records).
             INSERT INTO public.noo_users (username, org_id)
                 VALUES ('tenant', 'acme'), ('solo', 'default');
             CREATE TABLE public.noo_conversations (
                 id uuid PRIMARY KEY,
                 user_id text,
                 total_messages integer DEFAULT 0,
                 org_id text);
             -- Seeded with a NULL org, which is the state this revision
             -- exists to end: the rows land before the derive trigger is
             -- attached below, standing in for every conversation the
             -- gateway created without naming an org.
             INSERT INTO public.noo_conversations (id, user_id) VALUES
                 ('00000000-0000-0000-0000-000000000001', 'tenant'),
                 ('00000000-0000-0000-0000-000000000002', 'solo'),
                 ('00000000-0000-0000-0000-000000000003', NULL);
             -- The trellion-owned derive trigger, as it stands BEFORE this
             -- revision. It is here because 061 rewrites it: without the
             -- rewrite the column default fires first and the trigger's
             -- `IS NULL` test never matches, so every tenant's conversations
             -- would file under 'default'.
             CREATE FUNCTION public.noo_conv_set_org() RETURNS trigger
                 LANGUAGE plpgsql AS $trg$
             BEGIN
                 IF NEW.org_id IS NULL AND NEW.user_id IS NOT NULL THEN
                     NEW.org_id := (SELECT org_id FROM public.noo_users
                                    WHERE username = NEW.user_id);
                 END IF;
                 RETURN NEW;
             END;
             $trg$;
             CREATE TRIGGER noo_conv_set_org_trg BEFORE INSERT
                 ON public.noo_conversations
                 FOR EACH ROW EXECUTE FUNCTION public.noo_conv_set_org();"
        )))
        .execute(&db)
        .await
        .expect("legacy shape");

        apply(&db).await.expect("apply on legacy");

        let mesh_schema: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'mesh')",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            !mesh_schema,
            "legacy installs must NOT grow a mesh schema from a revision — \
             the layout moves at the cutover, not incrementally"
        );

        let fn_schema: String = sqlx::query_scalar(
            "SELECT n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE p.proname = 'noo_drop_audit_partition'",
        )
        .fetch_one(&db)
        .await
        .expect("047's function must exist after apply");
        assert_eq!(fn_schema, "public", "047 lands in public on a legacy install");

        // 061: every conversation now has an org, and the org came from the
        // OWNER where there was one. A NULL here is not "one row short" —
        // trellion's org filter is a hard boundary (`c.org_id = :org`), so a
        // NULL org makes the row invisible to every scoped read there is.
        let orgs: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id::text, org_id FROM public.noo_conversations ORDER BY id",
        )
        .fetch_all(&db)
        .await
        .expect("backfilled conversations");
        assert_eq!(
            orgs.iter().map(|(_, o)| o.as_deref()).collect::<Vec<_>>(),
            vec![Some("acme"), Some("default"), Some("default")],
            "user-owned rows take their owner's org; the ownerless one lands \
             in 'default' — a single-user install is one user in one org, on \
             the same code path"
        );

        // And going forward: a writer that names no org still lands in one.
        sqlx::raw_sql(
            "INSERT INTO public.noo_conversations (id, user_id) \
             VALUES ('00000000-0000-0000-0000-000000000004', 'tenant')",
        )
        .execute(&db)
        .await
        .expect("insert without an explicit org must succeed");
        let fresh: String = sqlx::query_scalar(
            "SELECT org_id FROM public.noo_conversations \
             WHERE id = '00000000-0000-0000-0000-000000000004'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        // 'acme', not 'default': the column default must not shadow the
        // derive trigger, or every tenant's conversations file under the
        // default org and cross-tenant isolation quietly inverts.
        assert_eq!(fresh, "acme");

        // The column is closed, so nothing has to re-check the boundary.
        let nullable: bool = sqlx::query_scalar(
            "SELECT is_nullable = 'YES' FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'noo_conversations' \
               AND column_name = 'org_id'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(!nullable, "061 must leave noo_conversations.org_id NOT NULL");

        let stamp: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT version_num FROM public.{VERSION_TABLE}"
        )))
        .fetch_one(&db)
        .await
        .unwrap();
        // Chain HEAD, not a pinned revision: this test is about WHERE the
        // stamp lives (public), and pinning 047 here made every appended
        // revision fail it for no layout-related reason.
        let head = MIGRATIONS
            .last()
            .map(|m| m.revision)
            .expect("chain is non-empty");
        assert_eq!(stamp, head);

        db.close().await;
        let _ = sqlx::raw_sql("DROP DATABASE mesh_legacy_test (FORCE)")
            .execute(&admin)
            .await;
    }
}
