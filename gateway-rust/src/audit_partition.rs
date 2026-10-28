// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Audit partition lifecycle — startup hook.
//!
//! `noo_security_audit` is a Postgres-level partitioned table (RANGE on
//! `timestamp`, monthly). At startup we ensure the current month and
//! next month partitions exist so inserts never fail with "no partition
//! for this range".
//!
//! Mirrors `gateway/audit_archive.py::ensure_current_and_next` — that
//! Python version was called from the Python lifespan, which doesn't run
//! in production (Rust gateway owns the port). This Rust version
//! restores the behavior.
//!
//! Retention runs here too. The Python `audit_archive.rotate` was only ever
//! reachable from a scheduler that does not run in production, so no
//! partition was ever exported or dropped. [`action_audit_log_rotate`] is the
//! Rust-native `audit_log_rotate` heartbeat action (seeded weekly by
//! [`seed_rotation_task`]): for each partition older than the retention
//! window it EXPORTS the rows to a JSONL file on the persistent `/data`
//! volume, verifies the file against the row count, and only then drops the
//! partition through the `noo_drop_audit_partition` definer function (which
//! itself refuses the current and future months). An export that cannot be
//! verified drops nothing.

use chrono::Datelike;

use crate::state::AppState;

/// Ensure partitions exist for current month + next month. Returns the
/// number of partitions created (0, 1, or 2).
///
/// Errors are logged, not fatal: a partition failure must not stop the
/// gateway booting. But the old comment here promised that "the next audit
/// insert will fail loudly if a partition is genuinely missing", and that
/// was never true — `audit_event` (now `audit::record`) discarded its result, so the insert
/// failed in total silence. The loudness now lives where it belongs, in
/// `audit::audit_insert`, which logs a lost audit row at `error!`
/// and heals the partition itself. This hook is the fast path, not the
/// guarantee.
pub async fn ensure_current_and_next(state: &AppState) -> usize {
    let now = chrono::Utc::now();
    let cur_year = now.year();
    let cur_month = now.month();
    let (next_year, next_month) = if cur_month == 12 {
        (cur_year + 1, 1u32)
    } else {
        (cur_year, cur_month + 1)
    };

    let mut created = 0usize;
    for (y, m) in [(cur_year, cur_month), (next_year, next_month)] {
        match ensure_partition(state, y, m as i32).await {
            Ok(true) => created += 1,
            Ok(false) => {} // already existed
            Err(e) => {
                tracing::warn!(year = y, month = m, error = %e, "audit_partition_ensure_failed");
            }
        }
    }
    if created > 0 {
        tracing::info!(created, "audit_partitions_ensured");
    }
    created
}

/// Ensure the monthly partition exists, via a SECURITY DEFINER function.
///
/// This used to run `CREATE TABLE ... PARTITION OF` directly, which only worked
/// because the gateway connected as a superuser — exactly what migration 033
/// exists to end. `noo_app` has no CREATE on the schema, and granting it would
/// let the role create any table at all.
///
/// `noo_ensure_audit_partition` (migration 036) runs as its owner and builds
/// the partition name internally from the year/month integers, so the caller
/// cannot name an arbitrary table or re-parent the partition. The existence
/// check lives inside the function too, so this is one round trip and there is
/// no check-then-create race between two gateway instances.
async fn ensure_partition(state: &AppState, year: i32, month: i32) -> Result<bool, sqlx::Error> {
    ensure_partition_on(&state.db, year, month).await
}

/// UNQUALIFIED, deliberately. This call used to name `public.` explicitly,
/// which was the whole bug: a fresh install puts the mesh schema — tables
/// AND functions — in `mesh`, so `public.noo_ensure_audit_partition` did
/// not exist, every startup logged one `audit_partition_ensure_failed`
/// warning, no partition was ever created, and the audit log was dead for
/// the life of the install.
///
/// Every other runtime query in the gateway is unqualified and resolves
/// through the `search_path` the pool pins in `state.rs`
/// (`mesh,public,trellion,evolve`), which is what makes one binary serve
/// both the fresh and the legacy layout. This was the only runtime query
/// that opted out of that, and it opted out of the only thing that made it
/// portable. `usage::record` calls its twin unqualified and was unaffected.
pub(crate) async fn ensure_partition_on(
    db: &sqlx::PgPool,
    year: i32,
    month: i32,
) -> Result<bool, sqlx::Error> {
    let created: bool = sqlx::query_scalar("SELECT noo_ensure_audit_partition($1, $2)")
        .bind(year)
        .bind(month)
        .fetch_one(db)
        .await?;
    if created {
        tracing::info!(year, month, "audit_partition_created");
    }
    Ok(created)
}

/// Heal path for a write that just hit a missing partition: ensure this
/// month and next, best-effort, so the caller can retry.
///
/// Separate from [`ensure_current_and_next`] only because that one takes an
/// `AppState` and the audit writer has a bare pool — the audit path is
/// reached from places with no `AppState` in hand.
pub(crate) async fn ensure_for_heal(db: &sqlx::PgPool) {
    let now = chrono::Utc::now();
    let (y, m) = (now.year(), now.month() as i32);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    for (year, month) in [(y, m), (ny, nm)] {
        if let Err(e) = ensure_partition_on(db, year, month).await {
            tracing::error!(year, month, error = %e, "audit_partition_heal_failed");
        }
    }
}

// ─── retention ───────────────────────────────────────────────────────────

/// Months of audit history kept in Postgres when the task names none.
pub const DEFAULT_RETENTION_MONTHS: u32 = 12;

/// Where expired partitions are exported. `/data` is the persistent
/// `noo-data` volume; a file written anywhere else in the container would die
/// with it, and the partition it replaced would be gone for good.
pub const DEFAULT_ARCHIVE_DIR: &str = "/data/audit-archive";

/// The heartbeat task id and action name.
pub const ROTATION_ACTION: &str = "audit_log_rotate";

/// `noo_security_audit_YYYY_MM` -> (year, month). Strict: anything else is
/// not ours to drop.
pub(crate) fn parse_partition_name(name: &str) -> Option<(i32, u32)> {
    let rest = name.strip_prefix("noo_security_audit_")?;
    let (y, m) = rest.split_once('_')?;
    if y.len() != 4 || m.len() != 2 || !y.bytes().all(|b| b.is_ascii_digit()) || !m.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    ((2000..=2999).contains(&y) && (1..=12).contains(&m)).then_some((y, m))
}

pub(crate) fn partition_name(year: i32, month: u32) -> String {
    format!("noo_security_audit_{year:04}_{month:02}")
}

/// (year, month) that is `n` months before `(year, month)`.
pub(crate) fn months_before(year: i32, month: u32, n: u32) -> (i32, u32) {
    let total = i64::from(year) * 12 + i64::from(month) - 1 - i64::from(n);
    ((total.div_euclid(12)) as i32, (total.rem_euclid(12) + 1) as u32)
}

/// The partitions strictly older than the retention window, oldest first.
/// With `retention_months = 12` in October 2026 the cutoff is October 2025:
/// September 2025 and earlier expire; October 2025 is still kept.
pub(crate) fn expired_partitions(parts: &[(i32, u32)], now: (i32, u32), retention_months: u32) -> Vec<(i32, u32)> {
    let cutoff = months_before(now.0, now.1, retention_months);
    let mut out: Vec<(i32, u32)> = parts.iter().copied().filter(|p| *p < cutoff).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The archive directory must be on the persistent volume (or `/tmp` for a
/// test) and lexically clean. `None` = acceptable.
pub(crate) fn archive_dir_problem(dir: &str) -> Option<String> {
    if dir.contains("..") {
        return Some(format!("archive_dir must not contain '..' (got {dir})"));
    }
    let ok = dir == "/data" || dir.starts_with("/data/") || dir == "/tmp" || dir.starts_with("/tmp/");
    (!ok).then(|| {
        format!("archive_dir must be under /data/ (the persistent volume) so the exported file outlives the container (got {dir})")
    })
}

/// What one rotation did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RotateOutcome {
    pub expired: Vec<String>,
    pub exported: Vec<String>,
    pub dropped: Vec<String>,
    /// Expired partitions KEPT because nothing can archive them (backend).
    pub retained: Vec<String>,
    pub errors: Vec<String>,
}

pub struct RotateConfig {
    pub retention_months: u32,
    pub archive_dir: String,
    pub backend: String,
    pub dry_run: bool,
}

impl RotateConfig {
    /// From the task's JSON config. Bad values are errors, not defaults.
    pub fn from_json(config: &serde_json::Value) -> Result<Self, String> {
        let retention_months = match config.get("retention_months") {
            None | Some(serde_json::Value::Null) => DEFAULT_RETENTION_MONTHS,
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=120).contains(n))
                .ok_or_else(|| format!("audit_log_rotate: retention_months must be 1..=120, got {v}"))? as u32,
        };
        let archive_dir = config
            .get("archive_dir")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_ARCHIVE_DIR)
            .to_string();
        if let Some(why) = archive_dir_problem(&archive_dir) {
            return Err(format!("audit_log_rotate: {why}"));
        }
        let backend = config.get("backend").and_then(|v| v.as_str()).unwrap_or("local_dir").to_string();
        // Default TRUE like every other destructive retention action; the
        // seeded task opts in with `dry_run: false`.
        let dry_run = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(true);
        Ok(Self { retention_months, archive_dir, backend, dry_run })
    }
}

/// Export one month's rows to `<dir>/noo_security_audit_YYYY_MM.jsonl`, one
/// `to_jsonb(row)` per line (EVERY column, `entry_hash` and `prev_hash`
/// included, so the archive can still be verified against the key). Returns
/// the final path and row count. Written to a temp file, counted twice (the
/// query's own count, and the lines read back from disk) and renamed only if
/// all three agree; a mismatch deletes the temp file and is an error.
async fn export_partition(db: &sqlx::PgPool, year: i32, month: u32, dir: &std::path::Path) -> Result<(std::path::PathBuf, u64), String> {
    use futures::TryStreamExt as _;
    use std::io::{BufRead as _, Write as _};

    let name = partition_name(year, month);
    // `name` is built from validated integers, never from input.
    let count_sql = format!("SELECT count(*) FROM noo_security_audit t WHERE t.tableoid = '{name}'::regclass");
    let expected: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(count_sql))
        .fetch_one(db)
        .await
        .map_err(|e| format!("{name}: count failed: {e}"))?;

    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!("{name}.jsonl.tmp"));
    let fin = dir.join(format!("{name}.jsonl"));
    let rows_sql = format!(
        "SELECT to_jsonb(t)::text FROM noo_security_audit t WHERE t.tableoid = '{name}'::regclass ORDER BY t.timestamp, t.id"
    );
    let result: Result<u64, String> = async {
        let file = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        let mut w = std::io::BufWriter::new(file);
        let mut n: u64 = 0;
        let mut stream = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(rows_sql)).fetch(db);
        while let Some(line) = stream.try_next().await.map_err(|e| format!("{name}: read failed: {e}"))? {
            writeln!(w, "{line}").map_err(|e| format!("write {}: {e}", tmp.display()))?;
            n += 1;
        }
        w.flush().map_err(|e| format!("flush {}: {e}", tmp.display()))?;
        w.get_ref().sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        drop(w);
        let on_disk = std::io::BufReader::new(std::fs::File::open(&tmp).map_err(|e| format!("reopen {}: {e}", tmp.display()))?)
            .lines()
            .count() as u64;
        if on_disk != n || i64::try_from(n).ok() != Some(expected) {
            return Err(format!(
                "{name}: export does not verify (query counted {expected}, streamed {n}, file holds {on_disk}) — nothing dropped"
            ));
        }
        Ok(n)
    }
    .await;
    match result {
        Ok(n) => {
            std::fs::rename(&tmp, &fin).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), fin.display()))?;
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok((fin, n))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Export-then-drop every partition older than the retention window.
pub async fn rotate(db: &sqlx::PgPool, cfg: &RotateConfig) -> Result<RotateOutcome, String> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i \
         JOIN pg_class c ON c.oid = i.inhrelid \
         JOIN pg_class p ON p.oid = i.inhparent \
         WHERE p.relname = 'noo_security_audit'",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("audit_log_rotate: cannot list partitions: {e}"))?;
    let parts: Vec<(i32, u32)> = names.iter().filter_map(|n| parse_partition_name(n)).collect();
    let now = chrono::Utc::now();
    let expired = expired_partitions(&parts, (now.year(), now.month()), cfg.retention_months);

    let expired_names: Vec<String> = expired.iter().map(|(y, m)| partition_name(*y, *m)).collect();
    let mut out = RotateOutcome { expired: expired_names.clone(), ..Default::default() };
    for (&(y, m), name) in expired.iter().zip(expired_names) {
        // Nothing can archive it: KEEP it. Dropping audit history because
        // no archive is configured is the failure this rotation exists to
        // avoid; the caller raises so the gap is visible.
        if cfg.backend != "local_dir" {
            out.retained.push(name);
            continue;
        }
        if cfg.dry_run {
            continue;
        }
        match export_partition(db, y, m, std::path::Path::new(&cfg.archive_dir)).await {
            Ok((path, rows)) => {
                tracing::info!(partition = %name, rows, path = %path.display(), "audit_partition_exported");
                out.exported.push(name.clone());
            }
            Err(e) => {
                tracing::error!(error = %e, "audit_partition_export_failed");
                out.errors.push(e);
                continue; // never drop what was not verified
            }
        }
        // The signed retention checkpoint goes in BEFORE the drop: it names the
        // chained rows about to vanish and the hash that links the rows after
        // them, so `noo security audit verify` reads the gap as retention. If it
        // cannot be written nothing is dropped (the drop function refuses too).
        if let Err(e) = crate::audit_chain::record_retention_checkpoint(db, y, m).await {
            tracing::error!(error = %e, "audit_retention_checkpoint_failed");
            out.errors.push(format!("{name}: exported but not dropped, no retention checkpoint: {e}"));
            continue;
        }
        match sqlx::query_scalar::<_, bool>("SELECT noo_drop_audit_partition($1, $2)")
            .bind(y)
            .bind(m as i32)
            .fetch_one(db)
            .await
        {
            Ok(true) => {
                tracing::info!(partition = %name, "audit_partition_dropped");
                out.dropped.push(name);
            }
            Ok(false) => {} // already gone
            Err(e) => out.errors.push(format!("{name}: exported but the drop failed: {e}")),
        }
    }
    Ok(out)
}

/// The `audit_log_rotate` heartbeat action. RAISES on any failure or on an
/// expired partition it could not archive: "no silent success" — a retention
/// job that quietly does nothing is how the table grew unbounded.
pub async fn action_audit_log_rotate(state: &AppState, config: &serde_json::Value) -> Result<String, String> {
    let cfg = RotateConfig::from_json(config)?;
    // Rollover duty first, as the Python original did: inserts need targets.
    ensure_current_and_next(state).await;
    let out = rotate(&state.db, &cfg).await?;
    let summary = format!(
        "Audit retention ({} months, {}, archive {}): {} expired, {} exported, {} dropped",
        cfg.retention_months,
        if cfg.dry_run { "DRY RUN" } else { "applied" },
        cfg.archive_dir,
        out.expired.len(),
        out.exported.len(),
        out.dropped.len()
    );
    if !out.errors.is_empty() {
        return Err(format!("{summary}; {} FAILED: {}", out.errors.len(), out.errors.join(" | ")));
    }
    if !out.retained.is_empty() {
        return Err(format!(
            "{summary}; {} expired partition(s) KEPT because backend '{}' cannot archive them here \
             (only local_dir does): {}. Set backend to local_dir, or archive them yourself",
            out.retained.len(),
            cfg.backend,
            out.retained.join(", ")
        ));
    }
    if cfg.dry_run && !out.expired.is_empty() {
        return Ok(format!("{summary}. Would export then drop: {}. Set `dry_run: false` to apply.", out.expired.join(", ")));
    }
    Ok(summary)
}

/// Seed the weekly rotation task once, when absent. A system task, enabled,
/// applying: the retention the docs state must not depend on an operator
/// remembering to create it. An operator who disables it stays disabled
/// (`ON CONFLICT DO NOTHING`); deleting the row re-creates it at next boot.
pub async fn seed_rotation_task(db: &sqlx::PgPool) {
    let r = sqlx::query(
        "INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, created_by) \
         VALUES ($1, 'Audit log retention (weekly, 12 months)', '0 4 * * 0', \
                 $1, '{\"dry_run\": false, \"retention_months\": 12}'::jsonb, true, 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(ROTATION_ACTION)
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "audit_rotation_task_seed_failed");
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn partition_names_parse_strictly() {
        assert_eq!(parse_partition_name("noo_security_audit_2025_09"), Some((2025, 9)));
        for bad in [
            "noo_security_audit",
            "noo_security_audit_2025_9",
            "noo_security_audit_25_09",
            "noo_security_audit_2025_13",
            "noo_security_audit_2025_00",
            "noo_security_audit_2025_09_x",
            "noo_security_audit_default",
            "noo_security_audit_backup_01",
            "noo_security_audit_20a5_09",
        ] {
            assert_eq!(parse_partition_name(bad), None, "{bad}");
        }
        assert_eq!(partition_name(2025, 9), "noo_security_audit_2025_09");
    }

    /// Retention boundary. October 2026 with 12 months keeps October 2025 and
    /// expires September 2025 and older — never the current or a future month.
    #[test]
    fn only_partitions_older_than_the_window_expire() {
        assert_eq!(months_before(2026, 10, 12), (2025, 10));
        assert_eq!(months_before(2026, 1, 1), (2025, 12));
        assert_eq!(months_before(2026, 3, 15), (2024, 12));
        let parts = [(2025, 8), (2025, 9), (2025, 10), (2026, 10), (2026, 11), (2024, 1)];
        assert_eq!(expired_partitions(&parts, (2026, 10), 12), vec![(2024, 1), (2025, 8), (2025, 9)]);
        assert!(expired_partitions(&[(2026, 10), (2026, 11)], (2026, 10), 1).is_empty());
    }

    /// The export must land on the persistent volume: a file in the
    /// container's own filesystem dies with it, after the partition is gone.
    #[test]
    fn the_archive_dir_must_be_on_the_data_volume() {
        assert!(archive_dir_problem("/data/audit-archive").is_none());
        assert!(archive_dir_problem("/data").is_none());
        for bad in ["./audit-archive", "audit-archive", "/app/audit", "/data/../etc", "/dataX/x", "/"] {
            assert!(archive_dir_problem(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn config_defaults_are_a_dry_run_on_the_data_volume_with_twelve_months() {
        let c = RotateConfig::from_json(&serde_json::json!({})).unwrap();
        assert!(c.dry_run && c.retention_months == 12 && c.archive_dir == DEFAULT_ARCHIVE_DIR && c.backend == "local_dir");
        let c = RotateConfig::from_json(&serde_json::json!({"dry_run": false, "retention_months": 6})).unwrap();
        assert!(!c.dry_run && c.retention_months == 6);
        assert!(RotateConfig::from_json(&serde_json::json!({"retention_months": 0})).is_err());
        assert!(RotateConfig::from_json(&serde_json::json!({"retention_months": "12"})).is_err());
        assert!(RotateConfig::from_json(&serde_json::json!({"archive_dir": "/app/x"})).is_err());
    }

    /// Retention RUNS in production: the action is Rust-native (the Python
    /// scheduler it used to need never runs), seeded weekly at boot, and
    /// called from the native dispatcher. On origin/dev it was a
    /// Python-delegated action with no task row.
    #[test]
    fn retention_is_scheduled_and_dispatched_natively() {
        assert_eq!(
            crate::heartbeat_actions::action_path(ROTATION_ACTION),
            crate::heartbeat_actions::ActionPath::RustNative
        );
        let dispatch = include_str!("heartbeat_actions.rs");
        assert!(dispatch.contains("\"audit_log_rotate\" => crate::audit_partition::action_audit_log_rotate"));
        let main = include_str!("main.rs");
        assert!(main.contains("audit_partition::seed_rotation_task"), "boot must seed the task");
    }
    /// The startup hook must work on a FRESH install, where the mesh schema
    /// — tables and functions alike — lives in `mesh` rather than `public`.
    ///
    /// This is the regression that killed the audit log: the call named
    /// `public.noo_ensure_audit_partition` explicitly, so on a fresh install
    /// it resolved to nothing, the failure was logged once as a warning at
    /// startup, and every later audit insert was discarded because no
    /// partition existed. Re-adding the qualifier fails this test with
    /// "function public.noo_ensure_audit_partition(integer, integer) does
    /// not exist".
    ///
    /// Gated on NOO_BROKER_TEST_DSN like the other real-catalogue suites; a
    /// mock cannot answer a question about schema resolution.
    #[tokio::test]
    async fn the_startup_hook_resolves_the_function_on_a_fresh_mesh_layout() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())
        else {
            return;
        };
        const DB: &str = "audit_partition_layout_test";
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("connect to NOO_BROKER_TEST_DSN");
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB} (FORCE)")))
            .execute(&admin)
            .await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {DB}")))
            .execute(&admin)
            .await
            .expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let scratch_dsn = format!("{head}/{DB}");

        let build = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&scratch_dsn)
            .await
            .expect("connect scratch");
        unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
                .execute(&build)
                .await
                .expect("extension");
        }
        crate::mesh_migrate::apply(&build).await.expect("apply migrations");
        build.close().await;

        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
            .expect("scratch dsn")
            // The search_path `state.rs` pins. The point of the test is that
            // the call relies on THIS and nothing else.
            .options([("search_path", "mesh,public,trellion,evolve")]);
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(opts)
            .await
            .expect("connect scratch");

        // The precondition that made the bug possible, asserted so the test
        // cannot quietly become vacuous if the layout ever changes.
        let schema: String = sqlx::query_scalar(
            "SELECT n.nspname FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE p.proname = 'noo_ensure_audit_partition'",
        )
        .fetch_one(&db)
        .await
        .expect("the function must exist somewhere");
        assert_eq!(
            schema, "mesh",
            "a fresh install puts the function in `mesh`; that is why a \
             `public.`-qualified call cannot find it"
        );

        // First call creates, second is idempotent.
        let created = super::ensure_partition_on(&db, 2026, 9)
            .await
            .expect("a fresh mesh-layout install must resolve the function");
        assert!(created, "the first call creates this month's partition");
        let again = super::ensure_partition_on(&db, 2026, 9)
            .await
            .expect("second call must succeed");
        assert!(!again, "the second call is a no-op, not a duplicate");

        db.close().await;
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB} (FORCE)")))
            .execute(&admin)
            .await;
    }
}
