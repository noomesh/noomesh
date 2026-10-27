// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Audit rows the database could not take RIGHT NOW, held and retried.
//!
//! Both audit writers are best-effort by design — an audit write must never
//! fail the caller's request — and both used to drop a row on any error. A
//! Postgres restart during a roll is exactly when that happens: on the
//! 2026-10-20 0.6.7 roll two `noo_external_requests` rows were lost in the
//! six seconds Postgres was down ("external audit insert failed").
//!
//! So a row that fails on a CONNECTION-class error (the database is down,
//! restarting or unreachable — [`is_transient`]) is queued here instead, and
//! [`spawn_drainer`] writes the queue back, oldest first, as soon as the
//! database answers. A row that fails for any other reason (bad data, a
//! constraint) would fail again, so it is lost as before, loudly.
//!
//! Bounded at [`CAP`] rows: past it the NEW row is lost (the queue keeps the
//! older evidence) and counted. The queue is memory: a gateway that stops
//! while rows are still queued loses them. In a roll Postgres restarts
//! before the gateway, and the drainer writes the queue back within
//! [`RETRY_EVERY`] of the database answering, so that window is seconds.
//! Every count — queued now, written back, lost — rides
//! `/api/security/audit/verify` as `spool`, which the `audit log` verify row
//! reads.
//!
//! A retried security row is signed and chained when it is WRITTEN (the
//! chain lock fixes its time), so its `details` carry `queued_at`: when the
//! event happened, as opposed to when the row landed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::Serialize;

/// The most rows held at once.
pub const CAP: usize = 10_000;
/// How often the drainer tries the queue while it is not empty.
pub const RETRY_EVERY: Duration = Duration::from_secs(2);

/// One row waiting for the database.
#[derive(Debug, Clone, PartialEq)]
pub enum Pending {
    /// A `noo_security_audit` row (signed at write time with the current key).
    Security {
        event_type: String,
        severity: String,
        actor: String,
        resource: String,
        outcome: String,
        details: String,
    },
    /// A `noo_external_requests` row.
    External(crate::service_keys::ExternalRequestRow),
}

static QUEUE: LazyLock<Mutex<VecDeque<Pending>>> = LazyLock::new(Default::default);
static QUEUED_TOTAL: AtomicU64 = AtomicU64::new(0);
static RETRIED_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOST_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Is this the database being away, rather than the row being wrong?
/// I/O, TLS, pool exhaustion or closure, and the server-side SQLSTATEs for a
/// connection failure (class 08) or an administrator / crash shutdown
/// (57P01–57P03).
pub fn is_transient(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
        sqlx::Error::Database(d) => d.code().is_some_and(|c| transient_sqlstate(&c)),
        _ => false,
    }
}

/// [`is_transient`]'s SQLSTATE half, for the tests.
pub fn transient_sqlstate(code: &str) -> bool {
    code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03")
}

/// Hold `row` for the drainer. `false` when the queue is full: the row is
/// lost (and counted), the caller logs it.
pub fn enqueue(row: Pending) -> bool {
    let Ok(mut q) = QUEUE.lock() else {
        LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if q.len() >= CAP {
        LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    q.push_back(row);
    QUEUED_TOTAL.fetch_add(1, Ordering::Relaxed);
    true
}

/// Count a row lost for a reason the spool does not handle (bad data, no
/// key), so the verify row's `lost_total` covers every lost row.
pub fn note_lost() {
    LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Rows held right now.
pub fn queued() -> usize {
    QUEUE.lock().map(|q| q.len()).unwrap_or(0)
}

/// What `/api/security/audit/verify` reports as `spool`.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct SpoolView {
    pub queued_now: u64,
    pub queued_total: u64,
    pub retried_total: u64,
    pub lost_total: u64,
    pub since_unix: u64,
}

pub fn view() -> SpoolView {
    SpoolView {
        queued_now: queued() as u64,
        queued_total: QUEUED_TOTAL.load(Ordering::Relaxed),
        retried_total: RETRIED_TOTAL.load(Ordering::Relaxed),
        lost_total: LOST_TOTAL.load(Ordering::Relaxed),
        since_unix: crate::legacy_lanes::process_start_unix(),
    }
}

/// The outcome of one write attempt, as the writers report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Landed,
    /// The database is away: try again later.
    Transient,
    /// This row cannot be written: do not retry.
    Lost,
}

/// Write the queue back, oldest first, until it is empty or the database
/// refuses again. The front row is only taken off once it landed (or failed
/// for good), so order holds and nothing is dropped between attempts.
async fn drain_once(db: &sqlx::PgPool) {
    loop {
        let Some(row) = QUEUE.lock().ok().and_then(|q| q.front().cloned()) else { return };
        let outcome = write(db, &row).await;
        if outcome == Outcome::Transient {
            return;
        }
        if let Ok(mut q) = QUEUE.lock() {
            if q.front() == Some(&row) {
                q.pop_front();
            }
        }
        match outcome {
            Outcome::Landed => {
                RETRIED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn write(db: &sqlx::PgPool, row: &Pending) -> Outcome {
    match row {
        Pending::Security { event_type, severity, actor, resource, outcome, details } => {
            let Some(key) = crate::audit_integrity::current_key() else { return Outcome::Lost };
            crate::audit::write_audit_row_outcome(
                db, &key, event_type, severity, actor, resource, outcome, details, None,
            )
            .await
        }
        Pending::External(r) => crate::service_keys::insert_external_request(db, r).await,
    }
}

/// The background writer: every [`RETRY_EVERY`] while anything is queued.
/// Logs when it starts holding rows and when the queue is written back.
pub fn spawn_drainer(db: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut was_holding = false;
        loop {
            tokio::time::sleep(RETRY_EVERY).await;
            let before = queued();
            if before == 0 {
                was_holding = false;
                continue;
            }
            if !was_holding {
                tracing::warn!(queued = before, "audit_spool_holding: audit rows are queued until the database answers");
                was_holding = true;
            }
            drain_once(&db).await;
            if queued() == 0 {
                tracing::info!(written = before, "audit_spool_drained: every queued audit row was written");
                was_holding = false;
            }
        }
    });
}

/// `details` with `queued_at` (RFC 3339, now) added, for a security row that
/// is about to wait: the row's own time will be when it lands.
pub fn stamp_queued_at(details: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    match serde_json::from_str::<serde_json::Value>(details) {
        Ok(serde_json::Value::Object(mut m)) => {
            m.insert("queued_at".into(), serde_json::Value::String(now));
            serde_json::Value::Object(m).to_string()
        }
        Ok(other) => serde_json::json!({ "value": other, "queued_at": now }).to_string(),
        Err(_) => details.to_string(),
    }
}

#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn reset_for_test() {
    if let Ok(mut q) = QUEUE.lock() {
        q.clear();
    }
    QUEUED_TOTAL.store(0, Ordering::Relaxed);
    RETRIED_TOTAL.store(0, Ordering::Relaxed);
    LOST_TOTAL.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(n: usize) -> Pending {
        Pending::Security {
            event_type: format!("e{n}"),
            severity: "info".into(),
            actor: "a".into(),
            resource: "r".into(),
            outcome: "ok".into(),
            details: "{}".into(),
        }
    }

    #[test]
    fn connection_failures_are_transient_and_bad_rows_are_not() {
        for c in ["08000", "08003", "08006", "08001", "57P01", "57P02", "57P03"] {
            assert!(transient_sqlstate(c), "{c}");
        }
        for c in ["23505", "22P02", "42P01", "23514", "57014"] {
            assert!(!transient_sqlstate(c), "{c} would fail again: not a retry");
        }
        assert!(is_transient(&sqlx::Error::PoolTimedOut));
        assert!(is_transient(&sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "x"))));
        assert!(!is_transient(&sqlx::Error::RowNotFound));
    }

    #[test]
    fn the_queue_is_bounded_and_counts_what_it_cannot_hold() {
        let _g = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        for i in 0..CAP {
            assert!(enqueue(sec(i)));
        }
        assert!(!enqueue(sec(CAP)), "a full queue refuses the new row");
        let v = view();
        assert_eq!((v.queued_now, v.queued_total, v.lost_total), (CAP as u64, CAP as u64, 1));
        if let Ok(q) = QUEUE.lock() {
            assert_eq!(q.front(), Some(&sec(0)), "the oldest evidence is kept");
        }
        reset_for_test();
    }

    #[test]
    fn a_queued_security_row_says_when_it_happened() {
        let d: serde_json::Value = serde_json::from_str(&stamp_queued_at(r#"{"ip":"1.2.3.4"}"#)).unwrap();
        assert_eq!(d["ip"], "1.2.3.4");
        assert!(d["queued_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{d}");
        let wrapped: serde_json::Value = serde_json::from_str(&stamp_queued_at("[1]")).unwrap();
        assert_eq!(wrapped["value"], serde_json::json!([1]));
        assert_eq!(stamp_queued_at("not json"), "not json", "a non-JSON detail is left for the writer to refuse");
    }
}
