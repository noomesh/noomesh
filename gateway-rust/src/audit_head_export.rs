// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The audit chain head, recorded where the database owner cannot reach it.
//!
//! The hash chain (`audit_chain`) shows a deleted or reordered middle row. It
//! cannot show that the NEWEST rows were cut off: what is left is a shorter,
//! valid chain. Only a copy of the head kept outside Postgres can. Every
//! [`INTERVAL_SECS`] this loop appends the current head to a file on the
//! gateway's data volume and publishes it to the operator event stream:
//!
//! ```text
//! {"seq":412,"chain_hash":"<hex>","time":"2026-10-19T04:00:00+00:00","mac":"<hex>"}
//! mac = HMAC(audit key, "noo-audit-head-v1" | seq | chain_hash | time)
//! ```
//!
//! `GET /api/security/audit/verify` (and so `noo security audit verify`) reads
//! the file back and compares:
//!
//! - the database head is OLDER than an exported head (or has no chain at all
//!   while an export exists): rows were truncated — a failure;
//! - the same seq with a different hash, or any exported head whose row is
//!   still in the table under another hash: history was rewritten — a failure;
//! - a line whose MAC does not verify, or does not parse: a failure naming the
//!   line and the remedy (it is either tampering or an audit-key rotation;
//!   after a rotation archive the file and the export starts a new one);
//! - no file yet, or no audit key: NOT CHECKED, said so, never "ok".
//!
//! ## What this does and does not give
//!
//! A holder of the Postgres owner or superuser credential (or `noo_app`'s
//! drop function) can still rewrite the table; they cannot reach this file
//! (the gateway's volume) nor forge a line (they lack the audit key, which
//! lives in the gateway's secrets, not in the database). The file is opened
//! append-only (`O_APPEND`), created 0600; an operator who wants the kernel to
//! enforce it can `chattr +a` it on the host. Someone who holds the gateway
//! volume AND the key can rewrite both — that is the operator, and the same
//! trust the audit key already has.
//!
//! The export never overwrites a newer line with an older head: when the
//! database head is behind the last exported one, the loop does NOT append,
//! and raises an operator alert instead.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::audit_integrity::{AuditRow, Report};
use crate::state::AppState;

/// Domain tag opening the head MAC.
pub const HEAD_DOMAIN: &str = "noo-audit-head-v1";
/// Where the heads go (the archive volume the retention job already uses).
pub const DEFAULT_HEAD_FILE: &str = "/data/audit-archive/chain-head.jsonl";
/// Override, for tests and unusual layouts.
pub const HEAD_FILE_ENV: &str = "NOO_AUDIT_HEAD_FILE";
/// How often the head is exported.
pub const INTERVAL_SECS: u64 = 900;
/// An unchanged head is re-recorded at least this often, so the file shows
/// the loop is alive and when the head was last seen unchanged.
const REFRESH_SECS: i64 = 24 * 3600;
/// The loop's `loop_health` name.
pub const LOOP_NAME: &str = "audit_head_export";
/// `events.ops.<kind>` of the stream copy.
pub const EVENT_KIND: &str = "audit.chain_head";

pub fn head_file() -> PathBuf {
    std::env::var(HEAD_FILE_ENV)
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_HEAD_FILE))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub seq: i64,
    pub chain_hash: String,
    /// When it was exported (RFC 3339), covered by the MAC.
    pub time: String,
    pub mac: String,
}

fn mac_of(key: &[u8], seq: i64, chain_hash: &str, time: &str) -> String {
    let canonical = format!(
        "{HEAD_DOMAIN}\nseq={seq}\nhash={}:{chain_hash}\ntime={}:{time}",
        chain_hash.len(),
        time.len()
    );
    let mut m = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(canonical.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

impl SignedHead {
    pub fn sign(key: &[u8], seq: i64, chain_hash: &str, time: &str) -> Self {
        Self { seq, chain_hash: chain_hash.into(), time: time.into(), mac: mac_of(key, seq, chain_hash, time) }
    }

    pub fn verifies(&self, key: &[u8]) -> bool {
        let want = mac_of(key, self.seq, &self.chain_hash, &self.time);
        want.len() == self.mac.len()
            && want.bytes().zip(self.mac.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
    }
}

/// The file read back: signed heads in file order, and the 1-based numbers of
/// lines that did not parse or whose MAC does not verify.
#[derive(Debug, Default)]
pub struct Parsed {
    pub heads: Vec<SignedHead>,
    pub bad_lines: Vec<usize>,
}

pub fn parse(text: &str, key: &[u8]) -> Parsed {
    let mut p = Parsed::default();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SignedHead>(line) {
            Ok(h) if h.verifies(key) => p.heads.push(h),
            _ => p.bad_lines.push(i + 1),
        }
    }
    p
}

/// Append one line. Created 0600, opened `O_APPEND`, flushed to disk before
/// returning: a head that is not durable is not a record.
pub fn append(path: &Path, head: &SignedHead) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let mut line = serde_json::to_string(head).map_err(std::io::Error::other)?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

// ── The verifier's half ──────────────────────────────────────────────────────

/// What `verify` says about the exported heads. Never "ok" by omission.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExportCheck {
    /// The database head was compared against at least one exported head.
    pub checked: bool,
    pub note: Option<String>,
    pub file: String,
    /// Verified heads in the file.
    pub exported_heads: u64,
    /// The newest exported head (highest seq).
    pub last_exported: Option<SignedHead>,
    /// The database head is behind, or disagrees with, an exported head.
    pub regression: bool,
}

/// What reading the file gave.
pub enum FileRead {
    Missing,
    Text(String),
    Unreadable(String),
}

pub fn read_file(path: &Path) -> FileRead {
    match std::fs::read_to_string(path) {
        Ok(t) => FileRead::Text(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileRead::Missing,
        Err(e) => FileRead::Unreadable(e.to_string()),
    }
}

/// Compare the database head with the exported ones and fold the result into
/// `r` (`r.chain.export`, plus `r.problems` / `r.warnings`). Pure.
pub fn check(file: &Path, read: FileRead, key: Option<&[u8]>, rows: &[AuditRow], r: &mut Report) {
    let mut ec = ExportCheck { file: file.display().to_string(), ..Default::default() };
    let Some(key) = key else {
        ec.note = Some("not checked against an exported head: this gateway holds no audit key".into());
        r.chain.export = ec;
        return;
    };
    let text = match read {
        FileRead::Missing => {
            ec.note = Some(format!(
                "NOT CHECKED against an exported head: {} does not exist yet (the export runs every {} minutes \
                 once the gateway is up; if it never appears, look for audit_head_export_error in the gateway log)",
                ec.file,
                INTERVAL_SECS / 60
            ));
            r.warnings.push(ec.note.clone().unwrap());
            r.chain.export = ec;
            return;
        }
        FileRead::Unreadable(e) => {
            ec.note = Some(format!("NOT CHECKED against an exported head: cannot read {}: {e}", ec.file));
            r.warnings.push(ec.note.clone().unwrap());
            r.chain.export = ec;
            return;
        }
        FileRead::Text(t) => t,
    };
    let parsed = parse(&text, key);
    ec.exported_heads = parsed.heads.len() as u64;
    if !parsed.bad_lines.is_empty() {
        let lines: Vec<String> = parsed.bad_lines.iter().take(10).map(|n| n.to_string()).collect();
        r.problems.push(format!(
            "exported chain heads: line(s) {} of {} do not parse or fail their signature — the file was altered, or \
             the audit key changed. After a deliberate key rotation, move the file aside (the export starts a new one)",
            lines.join(", "),
            ec.file
        ));
    }
    let Some(last) = parsed.heads.iter().max_by_key(|h| h.seq).cloned() else {
        ec.note = Some(format!("NOT CHECKED against an exported head: {} holds no verified head yet", ec.file));
        r.warnings.push(ec.note.clone().unwrap());
        r.chain.export = ec;
        return;
    };
    ec.last_exported = Some(last.clone());
    ec.checked = true;

    match r.chain.head.clone() {
        None => {
            ec.regression = true;
            r.problems.push(format!(
                "audit chain truncated: the table has no chained row, but a head at seq {} was exported at {}",
                last.seq, last.time
            ));
        }
        Some(db) if db.seq < last.seq => {
            ec.regression = true;
            r.problems.push(format!(
                "audit chain truncated: the table's newest chained row is seq {} but seq {} was exported at {} — \
                 {} newest row(s) are gone",
                db.seq,
                last.seq,
                last.time,
                last.seq - db.seq
            ));
        }
        Some(db) if db.seq == last.seq && db.chain_hash != last.chain_hash => {
            ec.regression = true;
            r.problems.push(format!(
                "audit chain rewritten: seq {} has chain_hash {} in the table but {} was exported at {}",
                db.seq, db.chain_hash, last.chain_hash, last.time
            ));
        }
        Some(_) => {}
    }
    // Any earlier exported head whose row is still in the table must match it.
    let by_seq: std::collections::HashMap<i64, &str> =
        rows.iter().filter_map(|x| Some((x.chain_seq?, x.chain_hash.as_deref()?))).collect();
    for h in &parsed.heads {
        if let Some(have) = by_seq.get(&h.seq) {
            if *have != h.chain_hash {
                ec.regression = true;
                r.problems.push(format!(
                    "audit chain rewritten: seq {} has chain_hash {have} in the table but {} was exported at {}",
                    h.seq, h.chain_hash, h.time
                ));
                break;
            }
        }
    }
    if !ec.regression {
        ec.note = Some(format!("database head is at or past the last exported head (seq {})", last.seq));
    }
    r.chain.export = ec;
}

// ── The exporter's half ──────────────────────────────────────────────────────

/// What one export tick decides. Pure.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Append this head.
    Record,
    /// Unchanged and recent: nothing to write.
    Unchanged,
    /// The table is behind the file: do NOT append; alert.
    Regressed { exported: i64, db: i64 },
    /// Same seq, different hash: do NOT append; alert.
    Rewritten { seq: i64 },
}

pub fn plan(db_seq: i64, db_hash: &str, last: Option<&SignedHead>, now: chrono::DateTime<chrono::Utc>) -> Plan {
    let Some(last) = last else { return Plan::Record };
    if db_seq < last.seq {
        return Plan::Regressed { exported: last.seq, db: db_seq };
    }
    if db_seq == last.seq {
        if db_hash != last.chain_hash {
            return Plan::Rewritten { seq: db_seq };
        }
        let age = chrono::DateTime::parse_from_rfc3339(&last.time)
            .map(|t| now.signed_duration_since(t).num_seconds())
            .unwrap_or(i64::MAX);
        return if age >= REFRESH_SECS { Plan::Record } else { Plan::Unchanged };
    }
    Plan::Record
}

async fn db_head(db: &sqlx::PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as::<_, (i64, String)>(
        "SELECT chain_seq, chain_hash FROM noo_security_audit \
         WHERE chain_seq IS NOT NULL AND chain_hash IS NOT NULL ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
}

pub fn spawn(state: std::sync::Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, INTERVAL_SECS)
        .startup_grace(90)
        .immediate_first_tick()
        .spawn(state, |state| async move { run_once(&state).await });
}

/// One export. An error is logged by the loop as `audit_head_export_error`
/// and makes the next `verify` say NOT CHECKED (no file) or show a stale head.
pub async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let Some(key) = crate::audit_integrity::current_key() else {
        anyhow::bail!("NOO_AUDIT_HMAC_KEY is not set: the audit chain head cannot be signed or exported");
    };
    let Some((seq, hash)) = db_head(&state.db).await? else {
        return Ok(()); // no chain yet (genesis is written at boot); nothing to record
    };
    let path = head_file();
    let last = match read_file(&path) {
        FileRead::Missing => None,
        FileRead::Text(t) => parse(&t, &key).heads.into_iter().max_by_key(|h| h.seq),
        FileRead::Unreadable(e) => anyhow::bail!("cannot read {}: {e}", path.display()),
    };
    let now = chrono::Utc::now();
    match plan(seq, &hash, last.as_ref(), now) {
        Plan::Unchanged => Ok(()),
        Plan::Record => {
            let head = SignedHead::sign(&key, seq, &hash, &now.to_rfc3339());
            append(&path, &head).map_err(|e| anyhow::anyhow!("cannot append to {}: {e}", path.display()))?;
            publish(state, &head).await;
            Ok(())
        }
        Plan::Regressed { exported, db } => {
            raise(state, format!("seq {db} is the newest chained audit row but seq {exported} was exported"), "truncated").await;
            anyhow::bail!("audit chain head regressed: table at seq {db}, exported seq {exported}")
        }
        Plan::Rewritten { seq } => {
            raise(state, format!("audit chain_hash at seq {seq} differs from the exported one"), "rewritten").await;
            anyhow::bail!("audit chain head at seq {seq} differs from the exported head")
        }
    }
}

async fn raise(state: &AppState, detail: String, what: &str) {
    let alert = crate::operator_alert::OperatorAlert::new(
        "audit.chain_head_regressed",
        "audit-chain",
        format!("The security audit log looks {what}: its newest rows do not match the head recorded outside the database."),
    )
    .detail(detail)
    .investigate("noo security audit verify")
    .persisting();
    crate::operator_alert::send_operator_alert_with(state, alert, 0).await;
}

/// The stream copy: `events.ops.audit.chain_head`, shaped like the other ops
/// events so a consumer replaying `events.ops.>` reads it unchanged. Best
/// effort — the file is the record, the stream is an observer.
async fn publish(state: &AppState, head: &SignedHead) {
    let payload = serde_json::json!({
        "kind": EVENT_KIND,
        "target": "audit-chain",
        "message": format!("Audit chain head recorded at seq {}", head.seq),
        "detail": serde_json::to_string(head).unwrap_or_default(),
        "ref": crate::egress::new_ref(),
        "outcome": "recorded",
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    if let Ok(bytes) = serde_json::to_vec(&payload) {
        if let Err(e) = state.js.publish(format!("events.ops.{EVENT_KIND}"), bytes.into()).await {
            tracing::debug!(error = %e, "audit_head_publish_failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_integrity::Report;

    const KEY: &[u8] = b"audit-key";

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-head-{}-{name}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("chain-head.jsonl")
    }

    fn head(seq: i64, hash: &str) -> SignedHead {
        SignedHead::sign(KEY, seq, hash, "2026-10-19T04:00:00+00:00")
    }

    fn report_with_db_head(seq: Option<i64>, hash: &str) -> Report {
        let mut r = Report::default();
        r.chain.head = seq.map(|s| crate::audit_chain::HeadView { seq: s, chain_hash: hash.into(), timestamp: "t".into() });
        r
    }

    fn file_of(heads: &[SignedHead]) -> FileRead {
        FileRead::Text(heads.iter().map(|h| serde_json::to_string(h).unwrap() + "\n").collect())
    }

    fn row(seq: i64, hash: &str) -> AuditRow {
        AuditRow {
            id: format!("r{seq}"),
            timestamp: "t".into(),
            ts_us: seq,
            event_type: "e".into(),
            severity: "info".into(),
            actor: "a".into(),
            resource: "r".into(),
            outcome: "ok".into(),
            request_id: None,
            details: None,
            prev_hash: None,
            entry_hash: None,
            chain_seq: Some(seq),
            chain_hash: Some(hash.into()),
        }
    }

    #[test]
    fn a_signed_head_verifies_and_any_changed_field_does_not() {
        let h = head(5, "abc");
        assert!(h.verifies(KEY));
        assert!(!h.verifies(b"other-key"));
        for tampered in [
            SignedHead { seq: 4, ..h.clone() },
            SignedHead { chain_hash: "abd".into(), ..h.clone() },
            SignedHead { time: "2026-10-19T05:00:00+00:00".into(), ..h.clone() },
        ] {
            assert!(!tampered.verifies(KEY));
        }
    }

    #[test]
    fn the_file_is_append_only_jsonl_created_0600() {
        let p = scratch("append");
        append(&p, &head(1, "a")).unwrap();
        append(&p, &head(2, "b")).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2, "the second head is a new line, not a rewrite");
        let parsed = parse(&text, KEY);
        assert_eq!(parsed.heads.iter().map(|h| h.seq).collect::<Vec<_>>(), vec![1, 2]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// The simulated truncation: heads 1..=10 were exported, then the newest
    /// rows were deleted from the table. Verify must FAIL and say how many.
    #[test]
    fn a_truncated_table_is_a_failure_naming_the_missing_rows() {
        let exported: Vec<SignedHead> = (1..=10).map(|n| head(n, &format!("h{n}"))).collect();
        let rows: Vec<AuditRow> = (1..=7).map(|n| row(n, &format!("h{n}"))).collect();
        let mut r = report_with_db_head(Some(7), "h7");
        check(Path::new("/x"), file_of(&exported), Some(KEY), &rows, &mut r);
        assert!(r.chain.export.regression);
        assert!(r.chain.export.checked);
        assert!(
            r.problems.iter().any(|p| p.contains("truncated") && p.contains("seq 7") && p.contains("seq 10") && p.contains("3 newest")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn an_untouched_table_ahead_of_the_export_passes() {
        let exported: Vec<SignedHead> = (1..=5).map(|n| head(n, &format!("h{n}"))).collect();
        let rows: Vec<AuditRow> = (1..=9).map(|n| row(n, &format!("h{n}"))).collect();
        let mut r = report_with_db_head(Some(9), "h9");
        check(Path::new("/x"), file_of(&exported), Some(KEY), &rows, &mut r);
        assert!(r.chain.export.checked && !r.chain.export.regression);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
    }

    #[test]
    fn a_table_with_no_chain_left_but_an_exported_head_is_a_failure() {
        let mut r = report_with_db_head(None, "");
        check(Path::new("/x"), file_of(&[head(3, "h3")]), Some(KEY), &[], &mut r);
        assert!(r.chain.export.regression);
        assert!(r.problems.iter().any(|p| p.contains("no chained row")));
    }

    #[test]
    fn the_same_seq_under_another_hash_is_a_rewrite() {
        let mut r = report_with_db_head(Some(4), "other");
        check(Path::new("/x"), file_of(&[head(4, "h4")]), Some(KEY), &[row(4, "other")], &mut r);
        assert!(r.chain.export.regression);
        assert!(r.problems.iter().any(|p| p.contains("rewritten")));
    }

    #[test]
    fn an_older_exported_head_whose_row_is_still_there_must_match_it() {
        // db head is ahead, but seq 2 was rewritten after it was exported
        let mut r = report_with_db_head(Some(5), "h5");
        let rows = vec![row(2, "forged"), row(5, "h5")];
        check(Path::new("/x"), file_of(&[head(2, "h2")]), Some(KEY), &rows, &mut r);
        assert!(r.chain.export.regression);
        assert!(r.problems.iter().any(|p| p.contains("rewritten") && p.contains("seq 2")));
    }

    #[test]
    fn a_dropped_partition_does_not_fail_an_old_exported_head() {
        // retention removed seq 1..=3; the export of seq 2 has no row to compare
        let mut r = report_with_db_head(Some(6), "h6");
        check(Path::new("/x"), file_of(&[head(2, "h2")]), Some(KEY), &[row(4, "h4"), row(6, "h6")], &mut r);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
    }

    #[test]
    fn a_forged_or_garbled_line_fails_and_names_the_remedy() {
        let mut text = serde_json::to_string(&head(1, "h1")).unwrap() + "\n";
        text.push_str(&serde_json::to_string(&SignedHead::sign(b"attacker", 9, "x", "t")).unwrap());
        text.push_str("\nnot json\n");
        let mut r = report_with_db_head(Some(1), "h1");
        check(Path::new("/x"), FileRead::Text(text), Some(KEY), &[row(1, "h1")], &mut r);
        let p = r.problems.iter().find(|p| p.contains("line(s) 2, 3")).expect("names the lines");
        assert!(p.contains("move the file aside"), "names the fix: {p}");
        // and the forged seq 9 grants nothing: the db head at 1 is not 'truncated'
        assert!(!r.chain.export.regression);
    }

    #[test]
    fn nothing_to_compare_against_says_not_checked_never_ok() {
        for read in [FileRead::Missing, FileRead::Unreadable("denied".into()), FileRead::Text(String::new())] {
            let mut r = report_with_db_head(Some(1), "h1");
            check(Path::new("/x"), read, Some(KEY), &[], &mut r);
            assert!(!r.chain.export.checked);
            assert!(r.chain.export.note.as_deref().unwrap().contains("NOT CHECKED"));
            assert!(!r.warnings.is_empty());
        }
        let mut r = report_with_db_head(Some(1), "h1");
        check(Path::new("/x"), file_of(&[head(1, "h1")]), None, &[], &mut r);
        assert!(!r.chain.export.checked && r.chain.export.note.as_deref().unwrap().contains("no audit key"));
    }

    #[test]
    fn the_exporter_never_writes_an_older_head_over_a_newer_one() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T04:05:00+00:00").unwrap().into();
        let last = head(10, "h10");
        assert_eq!(plan(7, "h7", Some(&last), now), Plan::Regressed { exported: 10, db: 7 });
        assert_eq!(plan(10, "zzz", Some(&last), now), Plan::Rewritten { seq: 10 });
        assert_eq!(plan(10, "h10", Some(&last), now), Plan::Unchanged);
        assert_eq!(plan(11, "h11", Some(&last), now), Plan::Record);
        assert_eq!(plan(1, "h1", None, now), Plan::Record);
        let next_day = chrono::DateTime::parse_from_rfc3339("2026-10-20T04:05:00+00:00").unwrap().into();
        assert_eq!(plan(10, "h10", Some(&last), next_day), Plan::Record, "an unchanged head is re-recorded daily");
    }

    #[test]
    fn the_loop_is_spawned_at_boot_and_the_verdict_reads_the_file() {
        assert!(include_str!("main.rs").contains("audit_head_export::spawn("));
        let integ = include_str!("audit_integrity.rs");
        let verify_db = &integ[integ.find("pub async fn verify_db").unwrap()..];
        assert!(verify_db.contains("audit_head_export::check("), "verify must compare against the exported head");
    }
}
