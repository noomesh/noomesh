// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent-mail cold storage: archive, then delete.
//!
//! `agent_messages_retention` used to `DELETE` every `noo_agent_messages` row
//! older than `days`. Those rows are the only complete record of what the
//! agents said to each other, and they are exactly the corpus a later
//! fine-tune or evaluation would want. So the action now ARCHIVES an expiring
//! row before it deletes it, on the same "export, verify, then drop" footing
//! as the audit archive ([`crate::audit_partition`]).
//!
//! # Layout
//!
//! One file per UTC month of `received_at`, in the SAME directory the audit
//! archive uses (`/data/audit-archive` on the persistent `noo-data` volume, so
//! the existing backups and off-machine copies carry it):
//!
//! ```text
//! <archive_dir>/noo_agent_messages_YYYY_MM.jsonl.gz
//! ```
//!
//! Each line is `to_jsonb(row)` — EVERY column. The body is stored exactly as
//! the table holds it: still sealed (`enc: "sealed"|"e2e"`, `body: {"ct": …}`,
//! `enc_meta`). The archive never contains plaintext and never needs the
//! review key to be written; opening it is a separate, audited, operator-only
//! step ([`export`] with a key).
//!
//! # One file per month, rewritten atomically (not appended, not part files)
//!
//! A month's file is REWRITTEN on every run that has something new for it:
//! the existing lines are copied verbatim, the new rows are added, the whole
//! thing goes to `<file>.tmp`, is fsynced, read back, and renamed over the
//! old file. gzip would allow appending a second member, but an append that
//! crashes half way leaves a truncated member in the live file; a rename
//! never exposes a half-written file. Part files per run would avoid the
//! rewrite but make every reader merge and de-duplicate them. Months are
//! small (this is a trace of agent mail), the job is weekly, and a reader
//! that wants a month opens exactly one file.
//!
//! # Failure semantics and idempotency
//!
//! * A row is deleted ONLY after its month's file is on disk, was read back
//!   from disk, and that read-back contains the row's id. The delete names
//!   the exported ids (`WHERE id = ANY(..)`), not the retention predicate, so
//!   it can never delete a row that was not archived.
//! * Any export failure (unwritable dir, disk full, unreadable or corrupt
//!   existing file, count mismatch) deletes nothing for that month, removes
//!   the temp file, and is reported as an error; the heartbeat action raises.
//! * Re-running after a crash between the rename and the delete finds the
//!   rows already in the file. The merge de-duplicates BY MESSAGE ID: an id
//!   already present is not written again, and the run goes straight to the
//!   delete. The archive therefore holds each message id at most once, no
//!   matter how many times the run is interrupted. (The first writer wins; a
//!   message row is immutable apart from `read_at`/`delivered_at`.)

use crate::audit::{AuditEvent, AuditKind};
use std::collections::HashSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};

use chrono::TimeZone as _;
use serde_json::{json, Value};

pub(crate) use crate::audit_partition::{archive_dir_problem, DEFAULT_ARCHIVE_DIR};

pub const ACTION: &str = "agent_messages_retention";

/// `noo_agent_messages_YYYY_MM.jsonl.gz`
pub fn file_name(year: i32, month: u32) -> String {
    format!("noo_agent_messages_{year:04}_{month:02}.jsonl.gz")
}

/// Strict inverse of [`file_name`]; anything else is not ours.
pub fn parse_file_name(name: &str) -> Option<(i32, u32)> {
    let rest = name.strip_prefix("noo_agent_messages_")?.strip_suffix(".jsonl.gz")?;
    parse_ym(rest, '_')
}

fn parse_ym(s: &str, sep: char) -> Option<(i32, u32)> {
    let (y, m) = s.split_once(sep)?;
    if y.len() != 4 || m.len() != 2 || !y.bytes().all(|b| b.is_ascii_digit()) || !m.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    ((2000..=2999).contains(&y) && (1..=12).contains(&m)).then_some((y, m))
}

/// What a caller may name: `2026-09`, `2026_09`, or the archive file name.
/// Never a path — the file is always rebuilt from the parsed integers.
pub fn parse_month(arg: &str) -> Option<(i32, u32)> {
    let a = arg.trim();
    parse_file_name(a).or_else(|| parse_ym(a, '-')).or_else(|| parse_ym(a, '_'))
}

fn month_bounds(year: i32, month: u32) -> Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> {
    let start = chrono::Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).single()?;
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    Some((start, chrono::Utc.with_ymd_and_hms(ny, nm, 1, 0, 0, 0).single()?))
}

// ─── reading ─────────────────────────────────────────────────────────────

/// Every line of a gzip JSONL file. A truncated or corrupt file is an error.
fn read_lines(path: &Path) -> Result<Vec<String>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let r = BufReader::new(flate2::read::MultiGzDecoder::new(f));
    let mut out = Vec::new();
    for l in r.lines() {
        let l = l.map_err(|e| format!("read {}: {e}", path.display()))?;
        if !l.trim().is_empty() {
            out.push(l);
        }
    }
    Ok(out)
}

fn line_id(line: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("not JSON: {e}"))?;
    v.get("id").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "row without an id".to_string())
}

// ─── export (archive then delete) ────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Outcome {
    /// Messages past the window at the start of the run.
    pub expired: i64,
    /// Files written or confirmed, `(file name, rows in the file)`.
    pub files: Vec<(String, u64)>,
    /// Rows newly written to an archive file this run.
    pub archived: u64,
    /// Rows confirmed in an archive file (new + already there).
    pub verified: u64,
    pub deleted: u64,
    pub errors: Vec<String>,
}

/// The cutoff, taken ONCE from the DB clock so the export and the delete
/// agree on what "expired" means.
async fn cutoff(db: &sqlx::PgPool, days: i64) -> Result<chrono::DateTime<chrono::Utc>, String> {
    sqlx::query_scalar("SELECT now() - make_interval(days => $1::int)")
        .bind(days as i32)
        .fetch_one(db)
        .await
        .map_err(|e| format!("cutoff: {e}"))
}

async fn expiring_months(db: &sqlx::PgPool, before: chrono::DateTime<chrono::Utc>) -> Result<Vec<(i32, u32)>, String> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT to_char(received_at AT TIME ZONE 'UTC', 'YYYY_MM') FROM noo_agent_messages \
         WHERE received_at < $1 ORDER BY 1",
    )
    .bind(before)
    .fetch_all(db)
    .await
    .map_err(|e| format!("list months: {e}"))?;
    Ok(names.iter().filter_map(|n| parse_ym(n, '_')).collect())
}

/// Months holding expiring rows, with their counts — the dry-run view.
pub async fn plan(db: &sqlx::PgPool, days: i64) -> Result<Vec<(String, i64)>, String> {
    let before = cutoff(db, days).await?;
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT to_char(received_at AT TIME ZONE 'UTC', 'YYYY_MM'), count(*) FROM noo_agent_messages \
         WHERE received_at < $1 GROUP BY 1 ORDER BY 1",
    )
    .bind(before)
    .fetch_all(db)
    .await
    .map_err(|e| format!("plan: {e}"))?;
    Ok(rows)
}

/// Archive one month's expiring rows into its file and verify them.
/// Returns the ids now durably in the file, how many rows the file holds,
/// and how many were new. Writes nothing the caller can mistake for success
/// on error: the temp file is removed.
async fn archive_month(
    db: &sqlx::PgPool,
    before: chrono::DateTime<chrono::Utc>,
    (year, month): (i32, u32),
    dir: &Path,
) -> Result<(Vec<String>, u64, u64), String> {
    use futures::TryStreamExt as _;
    let name = file_name(year, month);
    let (start, end) = month_bounds(year, month).ok_or_else(|| format!("{name}: bad month"))?;
    let fin = dir.join(&name);
    let tmp = dir.join(format!("{name}.tmp"));

    let expected: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM noo_agent_messages WHERE received_at >= $1 AND received_at < $2 AND received_at < $3",
    )
    .bind(start)
    .bind(end)
    .bind(before)
    .fetch_one(db)
    .await
    .map_err(|e| format!("{name}: count failed: {e}"))?;

    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // What the month's file already holds. An unreadable file is NEVER
    // overwritten: that would destroy the only copy of rows already deleted.
    let existing: Vec<String> = if fin.exists() { read_lines(&fin).map_err(|e| format!("{name}: existing archive unreadable, left untouched: {e}"))? } else { Vec::new() };
    let mut have: HashSet<String> = HashSet::with_capacity(existing.len());
    for l in &existing {
        have.insert(line_id(l).map_err(|e| format!("{name}: existing archive has a bad line, left untouched: {e}"))?);
    }

    let result: Result<(Vec<String>, u64, u64), String> = async {
        let mut ids: Vec<String> = Vec::with_capacity(expected.max(0) as usize);
        let mut fresh: Vec<String> = Vec::new();
        let mut stream = sqlx::query_as::<_, (String, String)>(
            "SELECT id, to_jsonb(t)::text FROM noo_agent_messages t \
             WHERE received_at >= $1 AND received_at < $2 AND received_at < $3 ORDER BY received_at, id",
        )
        .bind(start)
        .bind(end)
        .bind(before)
        .fetch(db);
        while let Some((id, line)) = stream.try_next().await.map_err(|e| format!("{name}: read failed: {e}"))? {
            if !have.contains(&id) {
                fresh.push(line);
            }
            ids.push(id);
        }
        drop(stream);
        if i64::try_from(ids.len()).ok() != Some(expected) {
            return Err(format!("{name}: query counted {expected} but streamed {} — nothing deleted", ids.len()));
        }
        let new = fresh.len() as u64;
        let total = existing.len() as u64 + new;
        if new > 0 {
            let file = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
            let mut gz = flate2::write::GzEncoder::new(std::io::BufWriter::new(file), flate2::Compression::default());
            for l in existing.iter().chain(fresh.iter()) {
                writeln!(gz, "{l}").map_err(|e| format!("write {}: {e}", tmp.display()))?;
            }
            let mut bw = gz.finish().map_err(|e| format!("finish {}: {e}", tmp.display()))?;
            bw.flush().map_err(|e| format!("flush {}: {e}", tmp.display()))?;
            bw.get_ref().sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
            drop(bw);
        }
        // Verify from DISK: the temp file when we wrote one, else the live
        // file that already held every row.
        let check = if new > 0 { &tmp } else { &fin };
        let lines = read_lines(check).map_err(|e| format!("{name}: read-back failed: {e}"))?;
        let mut on_disk: HashSet<String> = HashSet::with_capacity(lines.len());
        for l in &lines {
            on_disk.insert(line_id(l).map_err(|e| format!("{name}: read-back: {e}"))?);
        }
        if lines.len() as u64 != total || on_disk.len() != lines.len() {
            return Err(format!(
                "{name}: read-back holds {} line(s) / {} distinct id(s), expected {total} — nothing deleted",
                lines.len(),
                on_disk.len()
            ));
        }
        if let Some(missing) = ids.iter().find(|i| !on_disk.contains(*i)) {
            return Err(format!("{name}: read-back is missing message {missing} — nothing deleted"));
        }
        Ok((ids, total, new))
    }
    .await;

    match result {
        Ok((ids, total, new)) => {
            if new > 0 {
                std::fs::rename(&tmp, &fin).map_err(|e| {
                    let _ = std::fs::remove_file(&tmp);
                    format!("{name}: rename {} -> {}: {e}", tmp.display(), fin.display())
                })?;
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
            Ok((ids, total, new))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Archive every message older than `days`, then delete exactly the rows the
/// archive was verified to hold. Months are independent: one month failing
/// leaves its rows in place and the others proceed; every failure is in
/// `errors`.
pub async fn archive_then_delete(db: &sqlx::PgPool, days: i64, dir: &Path) -> Result<Outcome, String> {
    let before = cutoff(db, days).await?;
    let months = expiring_months(db, before).await?;
    let mut out = Outcome::default();
    for ym in months {
        let name = file_name(ym.0, ym.1);
        let (ids, total, new) = match archive_month(db, before, ym, dir).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "agent_mail_archive_failed");
                out.errors.push(e);
                continue; // never delete what was not verified
            }
        };
        out.expired += ids.len() as i64;
        out.archived += new;
        out.verified += ids.len() as u64;
        out.files.push((name.clone(), total));
        tracing::info!(file = %name, rows = ids.len(), new, "agent_mail_archived");
        for chunk in ids.chunks(1000) {
            match crate::repo::agent_messages::delete_ids(db, chunk).await {
                Ok(n) => out.deleted += n,
                Err(e) => {
                    out.errors.push(format!("{name}: archived but the delete failed: {e}"));
                    break;
                }
            }
        }
    }
    Ok(out)
}

// ─── reading back ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFile {
    pub file: String,
    pub month: String,
    pub rows: u64,
    pub bytes: u64,
}

impl ArchiveFile {
    pub fn to_json(&self) -> Value {
        json!({ "file": self.file, "month": self.month, "rows": self.rows, "bytes": self.bytes })
    }
}

/// The archive files in `dir`, oldest month first. A missing directory is an
/// empty archive, not an error.
pub fn list(dir: &Path) -> Result<Vec<ArchiveFile>, String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {}: {e}", dir.display())),
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let fname = ent.file_name().to_string_lossy().to_string();
        let Some((y, m)) = parse_file_name(&fname) else { continue };
        let path = ent.path();
        let rows = read_lines(&path)?.len() as u64;
        let bytes = ent.metadata().map(|m| m.len()).unwrap_or(0);
        out.push(ArchiveFile { month: format!("{y:04}-{m:02}"), file: fname, rows, bytes });
    }
    out.sort_by(|a, b| a.month.cmp(&b.month));
    Ok(out)
}

/// Open one archived row's sealed body with the review key. On success the
/// row's `body` is the plaintext and `decrypted` is true. When the key cannot
/// open it the ciphertext stays and `enc` gains `:closed` (the same rule the
/// live review routes use). Returns whether it was opened.
pub fn decrypt_row(row: &mut Value, keys: &crate::agent_crypto::KeySet) -> bool {
    let enc = row.get("enc").and_then(Value::as_str).unwrap_or("none").to_string();
    if enc == "none" || enc.is_empty() {
        return false;
    }
    let s = |k: &str| row.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let aad = crate::agent_messages::envelope_aad(&s("id"), &s("thread_id"), &s("from_agent"), &s("to_agent"), &s("kind"));
    let opened = row.get("body").and_then(|b| b.get("ct")).and_then(Value::as_str).and_then(|ct| {
        let sealed = crate::agent_crypto::Sealed { ct: ct.to_string(), meta: row.get("enc_meta").cloned().unwrap_or(Value::Null) };
        crate::agent_crypto::open(&sealed, crate::agent_crypto::REVIEW_WRAP, &keys.seal, &aad).ok()
    });
    match opened {
        Some(body) => {
            row["body"] = body;
            row["decrypted"] = json!(true);
            true
        }
        None => {
            row["enc"] = json!(format!("{enc}:closed"));
            false
        }
    }
}

#[derive(Debug)]
pub enum ExportError {
    Forbidden(String),
    BadRequest(String),
    NotFound(String),
    /// The cluster has no review key, so nothing can be opened.
    NoKey(String),
    Internal(String),
}

/// One month, as parsed JSON rows. Sealed unless `keys` is `Some`.
///
/// This is the whole policy for reading the archive back, in one place so a
/// test can drive it without HTTP: the caller must be an operator for ANY
/// read; opening bodies (`keys`) additionally requires the audit row to be
/// written FIRST (a decrypt that cannot be recorded is refused), naming who
/// opened which month. Plaintext only ever leaves in the returned value.
pub async fn export(
    db: &sqlx::PgPool,
    dir: &Path,
    operator: bool,
    actor: &str,
    month_arg: &str,
    decrypt: Option<&crate::agent_crypto::KeySet>,
    wanted_decrypt: bool,
) -> Result<Value, ExportError> {
    if !operator {
        if wanted_decrypt {
            crate::audit::record(
                db,
                AuditEvent::new(AuditKind::AgentArchiveDecrypt, actor, month_arg)
                    .outcome(crate::audit::Outcome::Denied)
                    .details(json!({ "month": month_arg, "reason": "not an operator" })),
            )
            .await;
        }
        return Err(ExportError::Forbidden("the agent-mail archive is operator-only".into()));
    }
    let (y, m) = parse_month(month_arg).ok_or_else(|| ExportError::BadRequest(format!("'{month_arg}' is not a month (YYYY-MM) or archive file name")))?;
    let name = file_name(y, m);
    let path = dir.join(&name);
    if !path.is_file() {
        return Err(ExportError::NotFound(format!("no archive for {y:04}-{m:02}")));
    }
    let lines = read_lines(&path).map_err(ExportError::Internal)?;
    let mut rows: Vec<Value> = Vec::with_capacity(lines.len());
    for l in &lines {
        rows.push(serde_json::from_str(l).map_err(|e| ExportError::Internal(format!("{name}: bad line: {e}")))?);
    }
    let mut decrypted = 0usize;
    if wanted_decrypt {
        let Some(keys) = decrypt else {
            return Err(ExportError::NoKey("no review key on this controller, so sealed bodies cannot be opened".into()));
        };
        let recorded = crate::audit::record_required(
            db,
            AuditEvent::new(AuditKind::AgentArchiveDecrypt, actor, &format!("{y:04}-{m:02}"))
                .details(json!({ "month": format!("{y:04}-{m:02}"), "file": name, "rows": rows.len(), "by": actor })),
        )
        .await;
        if !recorded {
            return Err(ExportError::Internal("the decrypt could not be audited, so it was refused".into()));
        }
        for r in rows.iter_mut() {
            if decrypt_row(r, keys) {
                decrypted += 1;
            }
        }
    }
    Ok(json!({
        "month": format!("{y:04}-{m:02}"),
        "file": name,
        "count": rows.len(),
        "decrypted": wanted_decrypt,
        "opened": decrypted,
        "rows": rows,
    }))
}

/// Where the archive lives for the read routes: the retention task's
/// `archive_dir` when it names one, else the default.
pub async fn configured_dir(db: &sqlx::PgPool) -> PathBuf {
    let cfg: Option<Value> = sqlx::query_scalar("SELECT config FROM noo_heartbeat_tasks WHERE id = $1")
        .bind(ACTION)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    let dir = cfg
        .as_ref()
        .and_then(|c| c.get("archive_dir"))
        .and_then(Value::as_str)
        .filter(|d| archive_dir_problem(d).is_none())
        .unwrap_or(DEFAULT_ARCHIVE_DIR);
    PathBuf::from(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_crypto::{KeySet, Recipient};
    use crate::auth::Role;
    use crate::ops::tests::{scratch, DB_LOCK};
    use sqlx::PgPool;

    const SECRET: &str = "archive-test-review-secret-with-enough-entropy-01";
    const PLAIN: &str = "TOP-SECRET-PLAINTEXT-MARKER";

    fn keys() -> KeySet {
        KeySet::from_secret(SECRET).unwrap()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-mail-archive-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Insert one SEALED message received `days_ago` days ago.
    async fn seed(db: &PgPool, id: &str, days_ago: i64) {
        let ks = keys();
        let aad = crate::agent_messages::envelope_aad(id, "t1", "alice/a", "bob/b", "message");
        let sealed = crate::agent_crypto::seal(
            &json!({ "text": format!("{PLAIN} {id}") }),
            &[Recipient { label: crate::agent_crypto::REVIEW_WRAP, key: ks.seal_public() }],
            &aad,
        )
        .unwrap();
        sqlx::query(
            "INSERT INTO noo_agent_messages (id, thread_id, from_agent, to_agent, kind, body, enc, enc_meta, received_at) \
             VALUES ($1, 't1', 'alice/a', 'bob/b', 'message', $2, 'sealed', $3, now() - make_interval(days => $4::int))",
        )
        .bind(id)
        .bind(json!({ "ct": sealed.ct }))
        .bind(sealed.meta)
        .bind(days_ago as i32)
        .execute(db)
        .await
        .unwrap();
    }

    async fn count(db: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM noo_agent_messages").fetch_one(db).await.unwrap()
    }

    fn ids_in(dir: &Path) -> Vec<String> {
        let mut all = Vec::new();
        for f in list(dir).unwrap() {
            for l in read_lines(&dir.join(&f.file)).unwrap() {
                all.push(line_id(&l).unwrap());
            }
        }
        all.sort();
        all
    }

    #[test]
    fn file_names_and_month_arguments_parse_strictly() {
        assert_eq!(file_name(2026, 7), "noo_agent_messages_2026_07.jsonl.gz");
        assert_eq!(parse_file_name("noo_agent_messages_2026_07.jsonl.gz"), Some((2026, 7)));
        for bad in ["noo_agent_messages_2026_7.jsonl.gz", "noo_agent_messages_2026_13.jsonl.gz", "noo_agent_messages_2026_07.jsonl", "../noo_agent_messages_2026_07.jsonl.gz", "x"] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
        for ok in ["2026-07", "2026_07", "noo_agent_messages_2026_07.jsonl.gz"] {
            assert_eq!(parse_month(ok), Some((2026, 7)), "{ok}");
        }
        assert_eq!(parse_month("../../etc/passwd"), None);
        assert_eq!(parse_month("2026-7"), None);
    }

    /// The archive is written BEFORE the delete, from the rows themselves,
    /// grouped by month, every column, body still sealed; only the expired
    /// rows leave the table.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rows_are_archived_sealed_then_deleted() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("mail_archive_ok").await else { return };
        let dir = tmpdir("ok");
        seed(&db, "old-a", 200).await;
        seed(&db, "old-b", 200).await;
        seed(&db, "older", 400).await;
        seed(&db, "fresh", 1).await;

        let out = archive_then_delete(&db, 90, &dir).await.unwrap();
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!((out.archived, out.verified, out.deleted), (3, 3, 3));

        // Real effects: rows gone from the table, the fresh one kept ...
        assert_eq!(count(&db).await, 1);
        let left: String = sqlx::query_scalar("SELECT id FROM noo_agent_messages").fetch_one(&db).await.unwrap();
        assert_eq!(left, "fresh");
        // ... and the three are on disk, once each, in month files.
        assert_eq!(ids_in(&dir), vec!["old-a", "old-b", "older"]);
        let files = list(&dir).unwrap();
        assert_eq!(files.len(), 2, "200 and 400 days ago are different months: {files:?}");
        assert_eq!(files.iter().map(|f| f.rows).sum::<u64>(), 3);
        assert!(files.iter().all(|f| parse_file_name(&f.file).is_some()));

        // Sealed: no plaintext anywhere in the decompressed archive, every
        // row still says so, and all columns are there.
        for f in &files {
            for l in read_lines(&dir.join(&f.file)).unwrap() {
                assert!(!l.contains(PLAIN), "plaintext leaked into the archive: {l}");
                let v: Value = serde_json::from_str(&l).unwrap();
                assert_eq!(v["enc"], "sealed");
                assert!(v["body"]["ct"].is_string());
                assert!(v["enc_meta"].is_object());
                for col in ["id", "thread_id", "from_agent", "to_agent", "kind", "refs", "ts", "received_at", "sig_verified"] {
                    assert!(v.get(col).is_some(), "column {col} missing from {l}");
                }
            }
        }
        // No temp file is left behind.
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed export deletes nothing: the archive directory cannot be
    /// created, and then a month file that cannot be read is left alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_export_deletes_nothing() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("mail_archive_fail").await else { return };
        seed(&db, "x1", 200).await;
        seed(&db, "x2", 200).await;

        // 1. the "directory" is a regular file.
        let blocker = tmpdir("blocked");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let out = archive_then_delete(&db, 90, &blocker.join("sub")).await.unwrap();
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert_eq!((out.deleted, out.archived), (0, 0));
        assert_eq!(count(&db).await, 2, "nothing may be deleted when the export failed");
        let _ = std::fs::remove_file(&blocker);

        // 2. this month's file exists but is corrupt: left byte-for-byte alone.
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let (y, m): (i32, u32) = sqlx::query_as::<_, (String,)>("SELECT to_char(received_at AT TIME ZONE 'UTC','YYYY_MM') FROM noo_agent_messages LIMIT 1")
            .fetch_one(&db)
            .await
            .map(|(s,)| parse_ym(&s, '_').unwrap())
            .unwrap();
        let bad = dir.join(file_name(y, m));
        std::fs::write(&bad, b"garbage, not gzip").unwrap();
        let out = archive_then_delete(&db, 90, &dir).await.unwrap();
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert_eq!(out.deleted, 0);
        assert_eq!(count(&db).await, 2);
        assert_eq!(std::fs::read(&bad).unwrap(), b"garbage, not gzip", "an unreadable archive must not be overwritten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash between the export and the delete, then re-run: the rows are in
    /// the file already, the merge de-duplicates by id, nothing is written
    /// twice, the delete still happens. Rows that arrive for the same month
    /// before the re-run are added next to the old ones, once each.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crash_and_rerun_leaves_no_duplicates() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("mail_archive_rerun").await else { return };
        let dir = tmpdir("rerun");
        seed(&db, "r1", 200).await;
        seed(&db, "r2", 200).await;

        // The export half of a run that then "crashed": rows exported, not deleted.
        let before = cutoff(&db, 90).await.unwrap();
        let months = expiring_months(&db, before).await.unwrap();
        assert_eq!(months.len(), 1);
        let (ids, total, new) = archive_month(&db, before, months[0], &dir).await.unwrap();
        assert_eq!((ids.len(), total, new), (2, 2, 2));
        assert_eq!(count(&db).await, 2, "the crash left the rows in the table");

        // More mail for the same month appears (an older row, same month), then the re-run.
        seed(&db, "r3", 200).await;
        let out = archive_then_delete(&db, 90, &dir).await.unwrap();
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(out.archived, 1, "only r3 is new; r1 and r2 were already archived");
        assert_eq!(out.deleted, 3);
        assert_eq!(count(&db).await, 0);
        assert_eq!(ids_in(&dir), vec!["r1", "r2", "r3"], "each id exactly once");

        // A third run with nothing to do changes nothing.
        let out = archive_then_delete(&db, 90, &dir).await.unwrap();
        assert_eq!((out.archived, out.deleted, out.files.len()), (0, 0, 0));
        assert_eq!(ids_in(&dir), vec!["r1", "r2", "r3"]);

        // A second crash-rerun with no new mail adds nothing at all.
        seed(&db, "r1", 200).await; // same id comes back (e.g. a redelivery after a restore)
        let out = archive_then_delete(&db, 90, &dir).await.unwrap();
        assert_eq!((out.archived, out.verified, out.deleted), (0, 1, 1));
        assert_eq!(ids_in(&dir), vec!["r1", "r2", "r3"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn audit_rows(db: &PgPool, outcome: &str) -> Vec<(String, String, Value)> {
        sqlx::query_as("SELECT actor, resource, details FROM noo_security_audit WHERE event_type = 'agent_archive_decrypt' AND outcome = $1 ORDER BY \"timestamp\"")
            .bind(outcome)
            .fetch_all(db)
            .await
            .unwrap()
    }

    /// Reading back: sealed by default; decrypt is refused to a non-operator
    /// (and that refusal is audited), allowed to an operator with the key and
    /// then audited by name and month; the file on disk stays sealed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn decrypt_is_operator_only_and_audited() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("mail_archive_decrypt").await else { return };
        let _ = crate::ops::tests::account(&db, "root", Role::Admin).await;
        crate::audit_partition::ensure_for_heal(&db).await;
        let dir = tmpdir("decrypt");
        seed(&db, "d1", 200).await;
        archive_then_delete(&db, 90, &dir).await.unwrap();
        let f = list(&dir).unwrap().remove(0);
        let ks = keys();

        // not an operator: refused, no plaintext, a denied row
        let r = export(&db, &dir, false, "mallory", &f.month, Some(&ks), true).await;
        assert!(matches!(r, Err(ExportError::Forbidden(_))), "{r:?}");
        let r = export(&db, &dir, false, "mallory", &f.month, None, false).await;
        assert!(matches!(r, Err(ExportError::Forbidden(_))), "sealed export is operator-only too");
        let denied = audit_rows(&db, "denied").await;
        assert_eq!(denied.len(), 1, "{denied:?}");
        assert_eq!(denied[0].0, "mallory");
        assert!(audit_rows(&db, "ok").await.is_empty());

        // operator, no --decrypt: sealed, and no decrypt audit row
        let v = export(&db, &dir, true, "root", &f.month, None, false).await.unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["rows"][0]["enc"], "sealed");
        assert!(!v.to_string().contains(PLAIN));
        assert!(audit_rows(&db, "ok").await.is_empty());

        // operator, --decrypt but the cluster has no review key: refused, not audited as an open
        let r = export(&db, &dir, true, "root", &f.month, None, true).await;
        assert!(matches!(r, Err(ExportError::NoKey(_))), "{r:?}");
        assert!(audit_rows(&db, "ok").await.is_empty());

        // operator with the key: plaintext comes back, once, and it is recorded first
        let v = export(&db, &dir, true, "root", &f.month, Some(&ks), true).await.unwrap();
        assert_eq!(v["opened"], 1);
        assert_eq!(v["rows"][0]["body"]["text"], format!("{PLAIN} d1"));
        let ok = audit_rows(&db, "ok").await;
        assert_eq!(ok.len(), 1, "{ok:?}");
        assert_eq!(ok[0].0, "root");
        assert_eq!(ok[0].1, f.month);
        assert_eq!(ok[0].2["month"], f.month.as_str());

        // a wrong key leaves the ciphertext and marks it closed
        let other = KeySet::from_secret("a-completely-different-review-secret-0123456789").unwrap();
        let v = export(&db, &dir, true, "root", &f.month, Some(&other), true).await.unwrap();
        assert_eq!(v["opened"], 0);
        assert_eq!(v["rows"][0]["enc"], "sealed:closed");

        // and the archive on disk never changed: still sealed
        for l in read_lines(&dir.join(&f.file)).unwrap() {
            assert!(!l.contains(PLAIN));
        }
        // a path is never accepted as the month
        assert!(matches!(export(&db, &dir, true, "root", "../../etc/passwd", None, false).await, Err(ExportError::BadRequest(_))));
        assert!(matches!(export(&db, &dir, true, "root", "2001-01", None, false).await, Err(ExportError::NotFound(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
