// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A hash chain over the security audit log: deletion and reordering evidence.
//!
//! `audit_integrity` signs every row on its own (`entry_hash`), which shows an
//! EDITED row but not a row that is simply gone. This module links the rows:
//!
//! ```text
//! chain_hash(n) = HMAC(audit key, "noo-audit-chain-v1" | seq=n | prev | entry_hash(n))
//! prev          = chain_hash(n-1), empty for seq 1
//! ```
//!
//! `chain_seq` is gapless. Delete a middle row and the next row's `chain_hash`
//! no longer follows from its predecessor and the sequence skips; swap two rows
//! and both fail. Only a holder of `NOO_AUDIT_HMAC_KEY` can mint a link.
//!
//! ## One sealing writer, without a sealer task
//!
//! Four processes write the table (the gateway and three Python containers),
//! so a naive chain forks. Each writer takes ONE transaction-scoped Postgres
//! advisory lock ([`CHAIN_LOCK_KEY`]), reads the newest chained row, picks its
//! time no earlier than that row's, signs, inserts and commits. The lock
//! serialises the "read tail, insert next" step across every writer and
//! process; it is released by commit or rollback, so a crashed writer cannot
//! wedge the log. The chain is sealed AT INSERT, not afterwards, because the
//! application role is INSERT-only (migration 092): nothing may update a row
//! later. Because a row's time is never earlier than its predecessor's, a
//! monthly partition holds a contiguous range of `chain_seq`, which is what
//! lets retention drop one without breaking the chain.
//!
//! ## Where the chain starts
//!
//! Only the gateway holds a key a migration could use, and a migration cannot
//! run HMAC, so existing rows are not re-written. On boot the gateway appends
//! ONE `audit_chain_genesis` row (seq 1) whose signed `resource` carries a
//! keyed digest and the count of every row written before it. Rows before the
//! genesis keep their per-row hash; deleting or swapping one of them changes
//! the digest, which the verifier recomputes. A writer that finds no chained
//! row yet (the genesis has not been written) inserts an unchained row, and
//! that row is covered by the digest if it landed before the genesis.
//!
//! ## Retention
//!
//! The retention job writes an `audit_retention_checkpoint` row BEFORE it
//! drops a partition: signed, chained, naming the dropped `from..through`
//! seq range and the `chain_hash` of the last dropped row. The verifier reads
//! a gap that exactly such a checkpoint covers as retention, and uses the
//! named hash as the predecessor of the row after the gap. A gap with no
//! checkpoint is reported as deleted rows. Migration 092 makes the drop
//! function refuse a partition without one.
//!
//! ## What it does not do
//!
//! Truncating the NEWEST rows leaves a shorter, valid chain. `verify` reports
//! the head (`seq`, `chain_hash`); record it somewhere the database owner
//! cannot write (a ticket, a signed message) to make a later truncation
//! visible. The verifier also holds the same key as the writers, so it proves
//! the log is intact, not who held the key.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::audit_integrity::{AuditRow, Break, Report, RowV2, ROLL_WINDOW_SECS};

/// Domain tag opening the chain hash (MUST match `audit_log.py::chain_hash`).
pub const CHAIN_DOMAIN: &str = "noo-audit-chain-v1";
/// Domain tag of the legacy-rows digest (gateway only).
pub const LEGACY_DOMAIN: &str = "noo-audit-legacy-v1";
/// `event_type` of the row that starts the chain (seq 1).
pub const GENESIS_EVENT: &str = "audit_chain_genesis";
/// `event_type` of the row that records rows removed by retention.
pub const RETENTION_EVENT: &str = "audit_retention_checkpoint";
/// The advisory lock every writer takes (MUST match `audit_log.py`).
/// ASCII "noo_audt".
pub const CHAIN_LOCK_KEY: i64 = 0x6e6f_6f5f_6175_6474;

/// Hex HMAC-SHA256 of one link. Length-prefixed so no field can shift a boundary.
///
/// ⚠️ MUST stay byte-identical to `audit_log.py::chain_hash`, pinned by
/// `tests/fixtures/audit_chain_vectors.json`.
pub fn chain_hash(key: &[u8], seq: i64, prev: &str, entry_hash: &str) -> String {
    let canonical = format!(
        "{CHAIN_DOMAIN}\nseq={seq}\nprev={}:{prev}\nentry={}:{entry_hash}",
        prev.len(),
        entry_hash.len()
    );
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Keyed digest over the rows that precede the chain: `(time µs, id, entry_hash)`.
/// Order is `(time, id)`, so the input order does not matter.
pub fn legacy_digest(key: &[u8], rows: &[(i64, String, Option<String>)]) -> String {
    let mut sorted: Vec<&(i64, String, Option<String>)> = rows.iter().collect();
    sorted.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(LEGACY_DOMAIN.as_bytes());
    for (_, id, hash) in sorted {
        mac.update(format!("\n{id}|{}", hash.as_deref().unwrap_or("-")).as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

// ── The two marker rows ──────────────────────────────────────────────────────

/// The genesis row's signed `resource`:
/// `audit-chain:v1;legacy_rows:<n>;legacy_through_us:<µs>;legacy_digest:<hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Genesis {
    pub legacy_rows: u64,
    pub legacy_through_us: i64,
    pub legacy_digest: String,
}

impl Genesis {
    pub fn resource(&self) -> String {
        format!(
            "audit-chain:v1;legacy_rows:{};legacy_through_us:{};legacy_digest:{}",
            self.legacy_rows, self.legacy_through_us, self.legacy_digest
        )
    }

    pub fn parse(resource: &str) -> Option<Genesis> {
        let mut parts = resource.split(';');
        if parts.next()? != "audit-chain:v1" {
            return None;
        }
        let rows = parts.next()?.strip_prefix("legacy_rows:")?.parse().ok()?;
        let through = parts.next()?.strip_prefix("legacy_through_us:")?.parse().ok()?;
        let digest = parts.next()?.strip_prefix("legacy_digest:")?.to_string();
        if parts.next().is_some() || digest.is_empty() {
            return None;
        }
        Some(Genesis { legacy_rows: rows, legacy_through_us: through, legacy_digest: digest })
    }
}

/// The retention checkpoint's signed `resource`:
/// `audit-retention:from:<seq>;through:<seq>;chain:<chain_hash of the row at through>`.
/// (Migration 092's drop function matches the `from`/`through` prefix.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Retention {
    pub from: i64,
    pub through: i64,
    pub chain: String,
}

impl Retention {
    pub fn resource(&self) -> String {
        format!("audit-retention:from:{};through:{};chain:{}", self.from, self.through, self.chain)
    }

    pub fn parse(resource: &str) -> Option<Retention> {
        let mut parts = resource.split(';');
        let from = parts.next()?.strip_prefix("audit-retention:from:")?.parse().ok()?;
        let through = parts.next()?.strip_prefix("through:")?.parse().ok()?;
        let chain = parts.next()?.strip_prefix("chain:")?.to_string();
        if parts.next().is_some() || chain.is_empty() || from > through {
            return None;
        }
        Some(Retention { from, through, chain })
    }
}

// ── Writing ──────────────────────────────────────────────────────────────────

/// One row to write. `details` is already Postgres's jsonb text (the caller
/// asked Postgres for `$1::jsonb::text`), which is what v2 hashes.
pub(crate) struct NewRow<'a> {
    pub event_type: &'a str,
    pub severity: &'a str,
    pub actor: &'a str,
    pub resource: &'a str,
    pub outcome: &'a str,
    pub details: &'a str,
    pub prev_hash: Option<&'a str>,
}

type Tail = (i64, String, DateTime<Utc>);

async fn fetch_tail(conn: &mut sqlx::PgConnection) -> Result<Option<Tail>, sqlx::Error> {
    sqlx::query_as::<_, Tail>(
        "SELECT chain_seq, chain_hash, \"timestamp\" FROM noo_security_audit \
         WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_optional(conn)
    .await
}

async fn take_lock(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(CHAIN_LOCK_KEY).execute(conn).await?;
    Ok(())
}

/// Sign and insert one row, linked after the newest chained row, in `tx`
/// (which already holds the lock). Returns the `chain_seq` it took, `None`
/// when the chain has not started and this is not the genesis (the row is
/// then written unchained).
///
/// `entry_key` signs the row (the retired key for the key hand-over row);
/// `chain_key` links it and is always the current audit key.
pub(crate) async fn insert_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entry_key: &[u8],
    chain_key: Option<&[u8]>,
    row: &NewRow<'_>,
    genesis: bool,
) -> Result<Option<i64>, sqlx::Error> {
    let tail = fetch_tail(&mut *tx).await?;
    let now = crate::routes::core::stored_now();
    // Never earlier than the predecessor: keeps a partition's seq range contiguous.
    let ts = match &tail {
        Some((_, _, t)) if *t > now => *t,
        _ => now,
    };
    let id = uuid::Uuid::new_v4().to_string();
    let entry_hash = crate::audit_integrity::row_hash_v2(
        entry_key,
        &RowV2 {
            id: &id,
            ts_us: ts.timestamp_micros(),
            event_type: row.event_type,
            severity: row.severity,
            actor: row.actor,
            resource: row.resource,
            outcome: row.outcome,
            request_id: None,
            details: Some(row.details),
            prev_hash: row.prev_hash,
        },
    );
    let link: Option<(i64, String)> = match (chain_key, &tail) {
        (Some(k), Some((seq, prev, _))) => {
            Some((seq + 1, chain_hash(k, seq + 1, prev, &entry_hash)))
        }
        (Some(k), None) if genesis => Some((1, chain_hash(k, 1, "", &entry_hash))),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO noo_security_audit \
           (id, \"timestamp\", event_type, severity, actor, resource, outcome, details, \
            request_id, entry_hash, prev_hash, chain_seq, chain_hash) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, NULL, $9, $10, $11, $12)",
    )
    .bind(&id)
    .bind(ts)
    .bind(row.event_type)
    .bind(row.severity)
    .bind(row.actor)
    .bind(row.resource)
    .bind(row.outcome)
    .bind(row.details)
    .bind(&entry_hash)
    .bind(row.prev_hash)
    .bind(link.as_ref().map(|l| l.0))
    .bind(link.as_ref().map(|l| l.1.as_str()))
    .execute(&mut **tx)
    .await?;
    Ok(link.map(|l| l.0))
}

/// The one write path for an audit row: lock, read the tail, insert, commit.
/// An `Err` from a missing monthly partition is for the caller to heal and retry.
pub(crate) async fn write_row(
    db: &sqlx::PgPool,
    entry_key: &[u8],
    chain_key: Option<&[u8]>,
    row: &NewRow<'_>,
) -> Result<Option<i64>, sqlx::Error> {
    let mut tx = db.begin().await?;
    take_lock(&mut tx).await?;
    let seq = insert_in_tx(&mut tx, entry_key, chain_key, row, false).await?;
    tx.commit().await?;
    Ok(seq)
}

/// Retention step: record, signed and chained, that `year`-`month`'s partition
/// is about to be dropped. Names the partition's chained seq range and the
/// `chain_hash` of its last row; the verifier then reads that gap as retention
/// and takes the named hash as the predecessor of the row after it.
///
/// `Ok(false)`: the partition holds no chained row, nothing to record.
/// `Ok(true)`: a checkpoint for exactly this range is in place (written now, or
/// by an earlier run). `Err`: none could be written (no audit key, no chain
/// tail, database error) and the caller MUST NOT drop. Called by
/// `audit_partition::rotate` after the export verifies and before the drop.
pub(crate) async fn record_retention_checkpoint(db: &sqlx::PgPool, year: i32, month: u32) -> Result<bool, String> {
    use chrono::TimeZone as _;
    let Some(key) = crate::audit_integrity::current_key() else {
        return Err("no NOO_AUDIT_HMAC_KEY: cannot sign the retention checkpoint".into());
    };
    let start = Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .ok_or_else(|| format!("bad partition {year}-{month}"))?;
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    let end = Utc.with_ymd_and_hms(ny, nm, 1, 0, 0, 0).single().ok_or_else(|| "bad partition end".to_string())?;
    let e = |what: &str, err: sqlx::Error| format!("retention checkpoint {year}-{month:02}: {what}: {err}");

    let mut tx = db.begin().await.map_err(|x| e("begin", x))?;
    take_lock(&mut tx).await.map_err(|x| e("lock", x))?;
    let span: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT min(chain_seq), max(chain_seq) FROM noo_security_audit \
         WHERE \"timestamp\" >= $1 AND \"timestamp\" < $2 AND chain_seq IS NOT NULL",
    )
    .bind(start)
    .bind(end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|x| e("range", x))?;
    let (Some(lo), Some(hi)) = span else { return Ok(false) };
    let last: Option<String> = sqlx::query_scalar(
        "SELECT chain_hash FROM noo_security_audit WHERE chain_seq = $1 \
         AND \"timestamp\" >= $2 AND \"timestamp\" < $3",
    )
    .bind(hi)
    .bind(start)
    .bind(end)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|x| e("last row", x))?
    .flatten();
    let last = last.ok_or_else(|| format!("retention checkpoint {year}-{month:02}: row seq {hi} has no chain_hash"))?;
    let resource = Retention { from: lo, through: hi, chain: last }.resource();
    let have: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM noo_security_audit WHERE event_type = $1 AND resource = $2 LIMIT 1",
    )
    .bind(RETENTION_EVENT)
    .bind(&resource)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|x| e("existing", x))?;
    if have.is_some() {
        return Ok(true);
    }
    let details = serde_json::json!({
        "what": "this month's partition was exported and verified, and is being dropped; its chained rows \
                 are accounted for by this row",
    })
    .to_string();
    let details: String = sqlx::query_scalar("SELECT $1::jsonb::text")
        .bind(&details)
        .fetch_one(&mut *tx)
        .await
        .map_err(|x| e("details", x))?;
    let outcome = format!("{year}-{month:02}");
    insert_in_tx(
        &mut tx,
        &key,
        Some(&key),
        &NewRow {
            event_type: RETENTION_EVENT,
            severity: "info",
            actor: "audit-retention",
            resource: &resource,
            outcome: &outcome,
            details: &details,
            prev_hash: None,
        },
        false,
    )
    .await
    .map_err(|x| e("insert", x))?;
    tx.commit().await.map_err(|x| e("commit", x))?;
    tracing::info!(year, month, seq_from = lo, seq_through = hi, "audit_retention_checkpoint_written");
    Ok(true)
}

/// What boot did about the genesis row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisOutcome {
    /// No `NOO_AUDIT_HMAC_KEY`: nothing written.
    KeyMissing,
    /// A chained row already exists.
    AlreadyPresent,
    /// Wrote seq 1, covering this many earlier rows.
    Written { legacy_rows: u64 },
    Failed(String),
}

/// Boot hook, after the key checkpoint and the hash-v2 marker: start the chain, once.
pub async fn ensure_genesis(db: &sqlx::PgPool) -> GenesisOutcome {
    let out = ensure_genesis_with(db, crate::audit_integrity::current_key()).await;
    match &out {
        GenesisOutcome::KeyMissing => {} // ensure_checkpoint already said so, at error
        GenesisOutcome::AlreadyPresent => tracing::info!("audit_chain_present"),
        GenesisOutcome::Written { legacy_rows } => tracing::info!(
            legacy_rows,
            "audit_chain_genesis_written: audit rows are hash-chained from here on; a deleted or \
             reordered row now fails `noo security audit verify`"
        ),
        GenesisOutcome::Failed(e) => tracing::error!(
            error = %e,
            "audit_chain_genesis_failed: rows are written unchained until the next gateway boot; \
             `noo security audit verify` reports the chain as not started"
        ),
    }
    out
}

pub(crate) async fn ensure_genesis_with(db: &sqlx::PgPool, key: Option<Vec<u8>>) -> GenesisOutcome {
    let Some(key) = key else { return GenesisOutcome::KeyMissing };
    for attempt in 0..2 {
        match try_genesis(db, &key).await {
            Ok(o) => return o,
            Err(e) if attempt == 0 && crate::routes::core::is_missing_partition(&e) => {
                crate::audit_partition::ensure_for_heal(db).await;
            }
            Err(e) => return GenesisOutcome::Failed(e.to_string()),
        }
    }
    GenesisOutcome::Failed("partition heal did not help".into())
}

async fn try_genesis(db: &sqlx::PgPool, key: &[u8]) -> Result<GenesisOutcome, sqlx::Error> {
    let mut tx = db.begin().await?;
    take_lock(&mut tx).await?;
    // Under the lock: of two gateways booting together, the second sees the first's row.
    if fetch_tail(&mut tx).await?.is_some() {
        return Ok(GenesisOutcome::AlreadyPresent);
    }
    let legacy: Vec<(String, DateTime<Utc>, Option<String>)> = sqlx::query_as(
        "SELECT id::text, \"timestamp\", entry_hash FROM noo_security_audit WHERE chain_seq IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?;
    let digest_rows: Vec<(i64, String, Option<String>)> =
        legacy.into_iter().map(|(id, t, h)| (t.timestamp_micros(), id, h)).collect();
    let genesis = Genesis {
        legacy_rows: digest_rows.len() as u64,
        legacy_through_us: digest_rows.iter().map(|r| r.0).max().unwrap_or(0),
        legacy_digest: legacy_digest(key, &digest_rows),
    };
    let details = serde_json::json!({
        "what": "the audit log is hash-chained from this row on (chain_seq 1); rows before it are \
                 covered by the keyed digest in `resource`",
    })
    .to_string();
    let details: String = sqlx::query_scalar("SELECT $1::jsonb::text")
        .bind(&details)
        .fetch_one(&mut *tx)
        .await?;
    let resource = genesis.resource();
    insert_in_tx(
        &mut tx,
        key,
        Some(key),
        &NewRow {
            event_type: GENESIS_EVENT,
            severity: "info",
            actor: "noo-gateway",
            resource: &resource,
            outcome: "seq:1",
            details: &details,
            prev_hash: None,
        },
        true,
    )
    .await?;
    tx.commit().await?;
    Ok(GenesisOutcome::Written { legacy_rows: genesis.legacy_rows })
}

// ── Verifying ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct GenesisView {
    pub id: String,
    pub timestamp: String,
    pub legacy_rows: u64,
    /// `Some(true)` the digest matched, `Some(false)` it did not, `None` not checkable (see `note`).
    pub legacy_digest_ok: Option<bool>,
}

/// The newest chained row. Record it somewhere the database owner cannot write
/// to make truncation of the newest rows visible later.
#[derive(Debug, Clone, Serialize)]
pub struct HeadView {
    pub seq: i64,
    pub chain_hash: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionView {
    pub id: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub range: Retention,
}

/// The chain's part of the verdict.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ChainReport {
    /// False when the chain could not be judged; `note` says why. Never "ok" by omission.
    pub checked: bool,
    pub note: Option<String>,
    pub chained_rows: u64,
    pub unchained_rows: u64,
    pub genesis: Option<GenesisView>,
    pub head: Option<HeadView>,
    /// Signed retention checkpoints found, and how many chained rows they account for as removed.
    pub retention: Vec<RetentionView>,
    pub retired_rows: u64,
    /// Unchained rows just after the genesis from a writer that predates the chain (a roll).
    pub unchained_roll_window_rows: u64,
    /// The first break in `chain_seq` order, if any.
    pub first_break: Option<Break>,
}

const MAX_UNCHAINED_BREAKS: usize = 20;

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The hash of the row just before a gap `lo..=hi`, if retention checkpoints
/// account for exactly that range end to end.
fn covered_by_retention(lo: i64, hi: i64, ckpts: &[Retention]) -> Option<String> {
    let mut cursor = lo;
    let mut last = None;
    while cursor <= hi {
        let c = ckpts.iter().find(|c| c.from == cursor && c.through <= hi)?;
        cursor = c.through + 1;
        last = Some(c.chain.clone());
    }
    last
}

/// Judge the chain over `rows` and fold the result into `r` (`r.chain`, plus
/// `r.breaks` / `r.problems` / `r.warnings`). Pure: pinned by tests, no database.
pub fn verify(rows: &[AuditRow], key: Option<&[u8]>, r: &mut Report) {
    let mut c = ChainReport::default();
    let Some(key) = key else {
        c.note = Some("not checked: this gateway holds no audit key".into());
        r.chain = c;
        return;
    };
    let mut chained: Vec<&AuditRow> = rows.iter().filter(|x| x.chain_seq.is_some()).collect();
    chained.sort_by(|a, b| (a.chain_seq, a.ts_us, &a.id).cmp(&(b.chain_seq, b.ts_us, &b.id)));
    let unchained: Vec<&AuditRow> = rows.iter().filter(|x| x.chain_seq.is_none()).collect();
    c.chained_rows = chained.len() as u64;
    c.unchained_rows = unchained.len() as u64;

    if chained.is_empty() {
        if rows.is_empty() {
            c.checked = true;
            c.note = Some("the log is empty".into());
        } else {
            c.note = Some("not checked: no row is chained yet".into());
            r.problems.push(
                "audit chain not started: rows exist and none is hash-chained — restart the gateway, \
                 which appends the audit_chain_genesis row on boot (audit_chain_genesis_failed in its \
                 log says why it did not)"
                    .into(),
            );
        }
        r.chain = c;
        return;
    }
    c.checked = true;

    let mut ckpts: Vec<Retention> = Vec::new();
    for row in rows.iter().filter(|x| x.event_type == RETENTION_EVENT && x.chain_seq.is_some()) {
        if !row.signed_by(key) {
            continue; // fails its own per-row check; it grants nothing here
        }
        if let Some(p) = Retention::parse(&row.resource) {
            c.retention.push(RetentionView { id: row.id.clone(), timestamp: row.timestamp.clone(), range: p.clone() });
            if !ckpts.contains(&p) {
                ckpts.push(p);
            }
        }
    }

    let push = |c: &mut ChainReport, r: &mut Report, row: &AuditRow, reason: String| {
        let b = Break { id: row.id.clone(), timestamp: row.timestamp.clone(), reason: format!("chain: {reason}") };
        if c.first_break.is_none() {
            c.first_break = Some(b.clone());
        }
        r.breaks.push(b);
    };

    let mut prev_seq: Option<i64> = None;
    let mut prev_chain = String::new();
    for row in &chained {
        let seq = row.chain_seq.expect("filtered");
        let (Some(stored), Some(entry)) = (row.chain_hash.as_deref(), row.entry_hash.as_deref()) else {
            push(&mut c, r, row, format!("seq {seq} has no chain_hash or entry_hash"));
            prev_seq = Some(seq);
            continue;
        };
        if prev_seq == Some(seq) {
            push(&mut c, r, row, format!(
                "two rows claim seq {seq}: the chain forked (a writer that did not take the chain lock, or a row copied in)"
            ));
            continue;
        }
        let expected_seq = prev_seq.map_or(1, |p| p + 1);
        let mut resync = false;
        if seq != expected_seq {
            let (lo, hi) = (expected_seq, seq - 1);
            match covered_by_retention(lo, hi, &ckpts) {
                Some(h) => {
                    c.retired_rows += (hi - lo + 1) as u64;
                    prev_chain = h;
                }
                None => {
                    push(&mut c, r, row, format!(
                        "seq {lo}..{hi} is missing before this row ({} row(s)) and no signed retention checkpoint \
                         accounts for it: rows were deleted",
                        hi - lo + 1
                    ));
                    resync = true;
                }
            }
        }
        let expected = chain_hash(key, seq, &prev_chain, entry);
        if resync {
            // Reported once, at the gap; continue from what the row says.
            prev_chain = stored.to_string();
        } else if !ct_eq(&expected, stored) {
            push(&mut c, r, row, format!(
                "seq {seq}: chain_hash does not follow from its predecessor — the row, its predecessor or \
                 its position was altered"
            ));
            prev_chain = expected;
        } else {
            prev_chain = expected;
        }
        prev_seq = Some(seq);
    }

    if let Some(last) = chained.last() {
        if let (Some(seq), Some(h)) = (last.chain_seq, last.chain_hash.clone()) {
            c.head = Some(HeadView { seq, chain_hash: h, timestamp: last.timestamp.clone() });
        }
    }

    // The rows before the chain, through the genesis row's digest.
    let genesis_row = chained
        .iter()
        .find(|x| x.chain_seq == Some(1) && x.event_type == GENESIS_EVENT && x.signed_by(key));
    match genesis_row.and_then(|g| Genesis::parse(&g.resource).map(|p| (*g, p))) {
        Some((g, gn)) => {
            let legacy: Vec<(i64, String, Option<String>)> = unchained
                .iter()
                .filter(|x| x.ts_us <= gn.legacy_through_us)
                .map(|x| (x.ts_us, x.id.clone(), x.entry_hash.clone()))
                .collect();
            let have = legacy.len() as u64;
            let mut view = GenesisView {
                id: g.id.clone(),
                timestamp: g.timestamp.clone(),
                legacy_rows: gn.legacy_rows,
                legacy_digest_ok: None,
            };
            if have == gn.legacy_rows {
                let ok = ct_eq(&legacy_digest(key, &legacy), &gn.legacy_digest);
                view.legacy_digest_ok = Some(ok);
                if !ok {
                    push(&mut c, r, g, format!(
                        "the {} row(s) written before the chain were altered or swapped: their digest no longer \
                         matches the genesis row",
                        gn.legacy_rows
                    ));
                }
            } else if have < gn.legacy_rows {
                if c.retired_rows > 0 || !ckpts.is_empty() {
                    r.warnings.push(format!(
                        "{} of the {} rows written before the chain are gone and a retention checkpoint exists: \
                         the pre-chain digest was not checked (retention removes the oldest rows)",
                        gn.legacy_rows - have,
                        gn.legacy_rows
                    ));
                } else {
                    view.legacy_digest_ok = Some(false);
                    push(&mut c, r, g, format!(
                        "{} of the {} rows written before the chain are missing and no retention checkpoint \
                         accounts for them: rows were deleted",
                        gn.legacy_rows - have,
                        gn.legacy_rows
                    ));
                }
            } else {
                r.warnings.push(format!(
                    "{} row(s) with a time inside the pre-chain range landed after the genesis row \
                     (an old-image writer committing late); the pre-chain digest was not checked",
                    have - gn.legacy_rows
                ));
            }
            c.genesis = Some(view);

            // Unchained rows after the chain began: a writer that predates it (a roll), or a
            // link that was stripped.
            let window_end = g.ts_us + ROLL_WINDOW_SECS * 1_000_000;
            let mut flagged = 0usize;
            for u in unchained.iter().filter(|x| x.ts_us > gn.legacy_through_us) {
                if u.ts_us <= window_end {
                    c.unchained_roll_window_rows += 1;
                } else if flagged < MAX_UNCHAINED_BREAKS {
                    flagged += 1;
                    push(&mut c, r, u, "written without a chain link after the chain began (a writer that \
                         predates the chain, or the link was removed)".into());
                }
            }
            if flagged == MAX_UNCHAINED_BREAKS {
                r.warnings.push("more unchained rows follow; only the first 20 are listed".into());
            }
            if c.unchained_roll_window_rows > 0 {
                r.warnings.push(format!(
                    "{} row(s) written without a chain link within the roll window after the genesis row \
                     (an old-image container still running)",
                    c.unchained_roll_window_rows
                ));
            }
        }
        None => {
            c.note = Some(
                "the genesis row is no longer in the table (retention), so rows before the chain were not \
                 checked"
                    .into(),
            );
        }
    }

    r.chain = c;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_integrity::{row_hash_v2, Keys, RowV2};

    const KEY: &[u8] = b"chain-test-key";

    /// A signed v2 row carrying its chain link, with the seq/prev the caller chose.
    fn linked(seq: i64, prev: &str, et: &str, resource: &str, secs: i64) -> AuditRow {
        let mut r = AuditRow {
            id: format!("00000000-0000-0000-0000-{seq:012}"),
            timestamp: format!("t{seq}"),
            ts_us: secs * 1_000_000,
            event_type: et.into(),
            severity: "info".into(),
            actor: "tester".into(),
            resource: resource.into(),
            outcome: "ok".into(),
            request_id: None,
            details: Some("{}".into()),
            prev_hash: None,
            entry_hash: None,
            chain_seq: Some(seq),
            chain_hash: None,
        };
        let eh = row_hash_v2(
            KEY,
            &RowV2 {
                id: &r.id,
                ts_us: r.ts_us,
                event_type: &r.event_type,
                severity: &r.severity,
                actor: &r.actor,
                resource: &r.resource,
                outcome: &r.outcome,
                request_id: None,
                details: r.details.as_deref(),
                prev_hash: None,
            },
        );
        r.chain_hash = Some(chain_hash(KEY, seq, prev, &eh));
        r.entry_hash = Some(eh);
        r
    }

    /// A chain of `n` ordinary rows after a genesis (seq 1) over zero legacy rows.
    fn chain(n: i64) -> Vec<AuditRow> {
        let g = Genesis { legacy_rows: 0, legacy_through_us: 0, legacy_digest: legacy_digest(KEY, &[]) };
        let mut rows = vec![linked(1, "", GENESIS_EVENT, &g.resource(), 1000)];
        for seq in 2..=n {
            let prev = rows.last().unwrap().chain_hash.clone().unwrap();
            rows.push(linked(seq, &prev, "tool_exec", "noo_x", 1000 + seq));
        }
        rows
    }

    fn judge(rows: &[AuditRow]) -> Report {
        let mut r = Report::default();
        verify(rows, Some(KEY), &mut r);
        r
    }

    fn keys() -> Keys {
        Keys { current: Some(KEY.to_vec()), retired: None }
    }

    #[test]
    fn an_intact_chain_verifies_and_reports_its_head() {
        let rows = chain(6);
        let r = judge(&rows);
        assert!(r.breaks.is_empty(), "{:?}", r.breaks);
        assert!(r.chain.checked);
        assert_eq!(r.chain.chained_rows, 6);
        let head = r.chain.head.expect("head");
        assert_eq!(head.seq, 6);
        assert_eq!(Some(head.chain_hash), rows[5].chain_hash);
        assert_eq!(r.chain.genesis.expect("genesis").legacy_digest_ok, Some(true));
    }

    #[test]
    fn a_deleted_middle_row_is_reported_at_the_row_after_the_gap() {
        let mut rows = chain(8);
        let gone = rows.remove(3); // seq 4
        let r = judge(&rows);
        assert_eq!(r.breaks.len(), 1, "one deletion is reported once: {:?}", r.breaks);
        let b = r.chain.first_break.clone().expect("first break");
        assert!(b.reason.contains("seq 4..4 is missing"), "{}", b.reason);
        assert_eq!(b.id, rows[3].id, "named at the first row after the gap");
        assert_ne!(b.id, gone.id);
    }

    #[test]
    fn swapped_rows_fail() {
        let mut rows = chain(6);
        // Swap the seq labels of rows 3 and 4 (a reorder); their links no longer fit.
        let (a, b) = (rows[2].chain_seq, rows[3].chain_seq);
        rows[2].chain_seq = b;
        rows[3].chain_seq = a;
        let r = judge(&rows);
        assert!(!r.breaks.is_empty());
        assert!(r.chain.first_break.expect("first").reason.contains("does not follow"));
    }

    #[test]
    fn an_edited_chain_hash_fails_at_that_row_only() {
        let mut rows = chain(6);
        rows[3].chain_hash = Some("00".repeat(32));
        let r = judge(&rows);
        assert_eq!(r.breaks.len(), 1, "{:?}", r.breaks);
        assert_eq!(r.breaks[0].id, rows[3].id);
    }

    #[test]
    fn a_fork_is_named() {
        let mut rows = chain(4);
        let mut dup = rows[2].clone();
        dup.id = "ffffffff-0000-0000-0000-000000000000".into();
        rows.push(dup);
        let r = judge(&rows);
        assert!(r.breaks.iter().any(|b| b.reason.contains("forked")), "{:?}", r.breaks);
    }

    #[test]
    fn a_missing_start_with_no_checkpoint_is_deleted_history() {
        let mut rows = chain(6);
        rows.drain(0..2); // seq 1 and 2
        let r = judge(&rows);
        assert!(r.chain.first_break.expect("break").reason.contains("seq 1..2 is missing"));
    }

    /// Retention: drop the oldest range and record it. The same table that
    /// failed above verifies once a signed checkpoint accounts for the gap.
    #[test]
    fn a_retention_checkpoint_makes_the_dropped_range_read_as_retention() {
        let mut rows = chain(5);
        let dropped_last = rows[2].chain_hash.clone().unwrap(); // seq 3
        let ck = Retention { from: 1, through: 3, chain: dropped_last };
        let prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let ck_row = linked(6, &prev, RETENTION_EVENT, &ck.resource(), 2000);
        rows.drain(0..3);
        rows.push(ck_row);
        let r = judge(&rows);
        assert!(r.breaks.is_empty(), "retention must not read as tampering: {:?}", r.breaks);
        assert_eq!(r.chain.retired_rows, 3);
        assert_eq!(r.chain.retention.len(), 1);
        // The genesis row went with the retention; that is said, not hidden.
        assert!(r.chain.note.as_deref().unwrap_or("").contains("genesis row is no longer"));
    }

    #[test]
    fn a_retention_checkpoint_naming_the_wrong_hash_does_not_launder_a_deletion() {
        let mut rows = chain(5);
        let ck = Retention { from: 1, through: 3, chain: "ab".repeat(32) };
        let prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let ck_row = linked(6, &prev, RETENTION_EVENT, &ck.resource(), 2000);
        rows.drain(0..3);
        rows.push(ck_row);
        let r = judge(&rows);
        assert!(!r.breaks.is_empty(), "the named hash must be the real predecessor of seq 4");
    }

    #[test]
    fn a_checkpoint_covering_less_than_the_gap_is_still_a_deletion() {
        let mut rows = chain(7);
        let ck = Retention { from: 1, through: 2, chain: rows[1].chain_hash.clone().unwrap() };
        let prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let ck_row = linked(8, &prev, RETENTION_EVENT, &ck.resource(), 2000);
        rows.drain(0..4); // seq 1..4 gone, checkpoint accounts for 1..2
        rows.push(ck_row);
        let r = judge(&rows);
        assert!(r.chain.first_break.expect("break").reason.contains("missing"));
    }

    #[test]
    fn a_forged_unsigned_checkpoint_grants_nothing() {
        let mut rows = chain(5);
        let ck = Retention { from: 1, through: 3, chain: rows[2].chain_hash.clone().unwrap() };
        let prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let mut ck_row = linked(6, &prev, RETENTION_EVENT, &ck.resource(), 2000);
        ck_row.entry_hash = Some(format!("v2:{}", "cd".repeat(32))); // not signed with the key
        rows.drain(0..3);
        rows.push(ck_row);
        let r = judge(&rows);
        assert!(r.chain.first_break.is_some(), "an unsigned checkpoint must not excuse the gap");
    }

    #[test]
    fn two_checkpoints_cover_two_dropped_months_end_to_end() {
        let mut rows = chain(8);
        let c1 = Retention { from: 1, through: 2, chain: rows[1].chain_hash.clone().unwrap() };
        let c2 = Retention { from: 3, through: 5, chain: rows[4].chain_hash.clone().unwrap() };
        let mut prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let r1 = linked(9, &prev, RETENTION_EVENT, &c1.resource(), 2000);
        prev = r1.chain_hash.clone().unwrap();
        let r2 = linked(10, &prev, RETENTION_EVENT, &c2.resource(), 2001);
        rows.drain(0..5);
        rows.push(r1);
        rows.push(r2);
        let r = judge(&rows);
        assert!(r.breaks.is_empty(), "{:?}", r.breaks);
        assert_eq!(r.chain.retired_rows, 5);
    }

    #[test]
    fn rows_before_the_chain_are_pinned_by_the_genesis_digest() {
        let legacy_ids = ["a", "b", "c"];
        let legacy: Vec<AuditRow> = legacy_ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let mut x = linked(0, "", "auth_failure", "gateway", 100 + i as i64);
                x.id = (*id).into();
                x.chain_seq = None;
                x.chain_hash = None;
                x.entry_hash = Some(format!("v2:{:064x}", i));
                x
            })
            .collect();
        let digest_in: Vec<(i64, String, Option<String>)> =
            legacy.iter().map(|x| (x.ts_us, x.id.clone(), x.entry_hash.clone())).collect();
        let g = Genesis {
            legacy_rows: 3,
            legacy_through_us: 102 * 1_000_000,
            legacy_digest: legacy_digest(KEY, &digest_in),
        };
        let mut rows = vec![linked(1, "", GENESIS_EVENT, &g.resource(), 1000)];
        rows.extend(legacy.clone());
        // Intact: the legacy region matches.
        let r = judge(&rows);
        assert!(r.breaks.iter().all(|b| !b.reason.contains("before the chain")), "{:?}", r.breaks);
        assert_eq!(r.chain.genesis.as_ref().unwrap().legacy_digest_ok, Some(true));
        // A legacy row swapped (hash changed): digest breaks.
        let mut swapped = rows.clone();
        swapped[2].entry_hash = Some(format!("v2:{:064x}", 99));
        let r = judge(&swapped);
        assert_eq!(r.chain.genesis.as_ref().unwrap().legacy_digest_ok, Some(false));
        assert!(r.breaks.iter().any(|b| b.reason.contains("written before the chain")));
        // A legacy row deleted with no retention: said so.
        let mut deleted = rows.clone();
        deleted.remove(2);
        let r = judge(&deleted);
        assert!(r.breaks.iter().any(|b| b.reason.contains("are missing")), "{:?}", r.breaks);
    }

    #[test]
    fn an_unchained_row_long_after_the_genesis_fails_but_one_in_the_roll_window_warns() {
        let mut rows = chain(3);
        let mut inside = linked(0, "", "audit_logger_started", "worker", 1000 + 60);
        inside.id = "00000000-0000-0000-0000-0000000000aa".into();
        inside.chain_seq = None;
        inside.chain_hash = None;
        let mut late = inside.clone();
        late.id = "00000000-0000-0000-0000-0000000000bb".into();
        late.ts_us = (1000 + ROLL_WINDOW_SECS + 120) * 1_000_000;
        rows.push(inside);
        let r = judge(&rows);
        assert!(r.breaks.is_empty(), "{:?}", r.breaks);
        assert_eq!(r.chain.unchained_roll_window_rows, 1);
        rows.push(late);
        let r = judge(&rows);
        assert_eq!(r.breaks.len(), 1);
        assert!(r.breaks[0].reason.contains("without a chain link"));
    }

    #[test]
    fn no_key_is_not_checked_not_ok() {
        let mut r = Report::default();
        verify(&chain(3), None, &mut r);
        assert!(!r.chain.checked);
        assert!(r.chain.note.unwrap().contains("not checked"));
    }

    #[test]
    fn rows_with_no_chain_yet_is_a_problem_not_a_pass() {
        let mut rows = chain(2);
        for x in rows.iter_mut() {
            x.chain_seq = None;
            x.chain_hash = None;
        }
        let mut r = Report::default();
        verify(&rows, Some(KEY), &mut r);
        assert!(!r.chain.checked);
        assert!(r.problems.iter().any(|p| p.contains("chain not started")));
    }

    /// Through `verify_all`: a chain break must turn the whole verdict to `fail`.
    #[test]
    fn a_chain_break_fails_the_report_verdict() {
        let mut rows = chain(5);
        rows.remove(2);
        let report = crate::audit_integrity::verify_all(&rows, &keys());
        assert_eq!(report.verdict, "fail");
        assert!(report.breaks.iter().any(|b| b.reason.starts_with("chain:")));
        let ok = crate::audit_integrity::verify_all(&chain(5), &keys());
        assert!(ok.breaks.is_empty(), "{:?}", ok.breaks);
    }

    /// The partition that held the key hand-over checkpoint (and the genesis
    /// and hash-v2 marker) can be dropped: the whole verdict stays ok when only
    /// current-key rows remain, a retention checkpoint accounts for the gap, and
    /// no `audit_key_checkpoint` row is left.
    #[test]
    fn dropping_the_partition_with_the_key_checkpoint_does_not_fail_verify() {
        let mut rows = chain(6);
        let ck = Retention { from: 1, through: 3, chain: rows[2].chain_hash.clone().unwrap() };
        let prev = rows.last().unwrap().chain_hash.clone().unwrap();
        let ck_row = linked(7, &prev, RETENTION_EVENT, &ck.resource(), 2000);
        rows.drain(0..3);
        rows.push(ck_row);
        let report = crate::audit_integrity::verify_all(&rows, &keys());
        assert_eq!(report.verdict, "ok", "{:?} {:?}", report.breaks, report.problems);
        assert_eq!(report.chain.retired_rows, 3);
    }

    #[test]
    fn marker_rows_round_trip() {
        let g = Genesis { legacy_rows: 7, legacy_through_us: 12345, legacy_digest: "ab".into() };
        assert_eq!(Genesis::parse(&g.resource()), Some(g));
        let r = Retention { from: 3, through: 9, chain: "cd".into() };
        assert_eq!(Retention::parse(&r.resource()), Some(r));
        assert_eq!(Retention::parse("audit-retention:from:9;through:3;chain:cd"), None);
        assert_eq!(Genesis::parse("audit-chain:v1;legacy_rows:x;legacy_through_us:1;legacy_digest:a"), None);
    }

    /// The vectors the Python writer must reproduce byte for byte.
    #[test]
    fn chain_hash_matches_the_shared_vectors() {
        const VECTORS: &str = include_str!("../../tests/fixtures/audit_chain_vectors.json");
        let v: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors parse");
        let key = v["key"].as_str().expect("key").as_bytes().to_vec();
        let cases = v["cases"].as_array().expect("cases");
        assert!(!cases.is_empty());
        for c in cases {
            let got = chain_hash(
                &key,
                c["seq"].as_i64().expect("seq"),
                c["prev"].as_str().expect("prev"),
                c["entry_hash"].as_str().expect("entry_hash"),
            );
            assert_eq!(got, c["chain_hash"].as_str().expect("chain_hash"), "{c}");
        }
    }
}
