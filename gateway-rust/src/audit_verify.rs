// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The audit chain's failures as Prometheus metrics, and the periodic full
//! verify that makes them move on their own (noomesh-internal i520).
//!
//! `audit_integrity::verify_db` judges the whole `noo_security_audit` table.
//! Until this module it ran only when someone asked
//! (`/api/security/audit/verify`, `noo cluster verify`'s audit row), and a
//! failure was a JSON answer nobody was told about. Now:
//!
//! * [`LOOP_NAME`] runs `verify_db` every [`INTERVAL_SECS`] (one fixed
//!   interval, no env knob), logging how long it took and how many rows it
//!   read on every run, so its cost is visible. The read is a plain `SELECT`
//!   with no lock (`repo::audit::all_for_verify`: no transaction, no
//!   `FOR UPDATE`/`FOR SHARE`/`LOCK`), which takes only the ACCESS SHARE
//!   lock and never blocks a writer.
//! * Every failed verdict, from the loop or the route, raises
//!   `noo_audit_verify_failures_total{source="verify"}`; a truncated or
//!   rewritten chain head found by the head export raises
//!   `{source="head_export"}`. The critical rule `AuditChainVerifyFailed`
//!   (`monitoring/alerts/security.yml`) reads `source="verify"` only: the head
//!   export already pages through its own PERSISTING operator alert
//!   (`audit_head_export::raise`), and one event pages once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;

pub const LOOP_NAME: &str = "audit_verify";
/// Six hours: one read of the whole audit table per run.
pub const INTERVAL_SECS: u64 = 6 * 60 * 60;
/// Let the gateway settle (migrations, checkpoint, head export) first.
const STARTUP_GRACE_SECS: u64 = 600;

/// Where a failure was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A `verify_db` verdict of `fail` (the loop or the route).
    Verify,
    /// The head export found the newest rows truncated or rewritten.
    HeadExport,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Source::Verify => "verify",
            Source::HeadExport => "head_export",
        }
    }
}

static VERIFY_FAILURES: AtomicU64 = AtomicU64::new(0);
static HEAD_EXPORT_FAILURES: AtomicU64 = AtomicU64::new(0);

fn counter(source: Source) -> &'static AtomicU64 {
    match source {
        Source::Verify => &VERIFY_FAILURES,
        Source::HeadExport => &HEAD_EXPORT_FAILURES,
    }
}

/// Count one failure found by `source`.
pub fn note_failure(source: Source) {
    counter(source).fetch_add(1, Ordering::Relaxed);
}

/// Count `report` if its verdict is a failure. Called by `verify_db`, so the
/// loop and the route both count.
pub fn count_report(report: &crate::audit_integrity::Report) {
    if report.verdict != "ok" {
        note_failure(Source::Verify);
    }
}

/// The counter's lines for `/metrics`. Both series are always present (a
/// series that appears only after its first failure cannot be told from a
/// scrape that lost it).
pub fn metrics_text() -> String {
    let mut out = String::from(
        "# HELP noo_audit_verify_failures_total Audit chain verify failures since the gateway started, by where they were found.\n\
         # TYPE noo_audit_verify_failures_total counter\n",
    );
    for s in [Source::Verify, Source::HeadExport] {
        out.push_str(&format!("noo_audit_verify_failures_total{{source=\"{}\"}} {}\n", s.label(), counter(s).load(Ordering::Relaxed)));
    }
    out
}

/// Should this tick be skipped? Runs never overlap (the loop awaits each
/// one), but the interval bursts its missed ticks: after a verify that took
/// longer than the interval, the next tick fires at once. Skip any tick
/// that comes less than half an interval after the last run finished,
/// rather than stack runs back to back.
pub fn should_skip(secs_since_last_finished: Option<u64>, interval_secs: u64) -> bool {
    secs_since_last_finished.is_some_and(|s| s < interval_secs / 2)
}

static LAST_FINISHED: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);

/// One periodic run: the full verify, timed and logged.
pub async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let since = LAST_FINISHED.lock().ok().and_then(|l| l.map(|t| t.elapsed().as_secs()));
    if should_skip(since, INTERVAL_SECS) {
        tracing::info!(secs_since_last = ?since, "audit_verify_skipped: the previous run finished less than half an interval ago");
        return Ok(());
    }
    let started = Instant::now();
    let result = crate::audit_integrity::verify_db(&state.db).await;
    let took_ms = started.elapsed().as_millis() as u64;
    if let Ok(mut l) = LAST_FINISHED.lock() {
        *l = Some(Instant::now());
    }
    let report = result.map_err(|e| anyhow::anyhow!("cannot read noo_security_audit: {e}"))?;
    if report.verdict == "ok" {
        tracing::info!(rows = report.checked, took_ms, verdict = %report.verdict, "audit_verify_ok");
    } else {
        tracing::warn!(
            rows = report.checked,
            took_ms,
            breaks = report.breaks.len(),
            problems = report.problems.len(),
            "audit_verify_failed: run `noo security audit verify` for the rows"
        );
    }
    Ok(())
}

pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .immediate_first_tick()
        .spawn(state, |state| async move { run_once(&state).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str, source: &str) -> u64 {
        let want = format!("noo_audit_verify_failures_total{{source=\"{source}\"}} ");
        text.lines().find_map(|l| l.strip_prefix(want.as_str())).and_then(|v| v.parse().ok()).expect("series present")
    }

    /// A failed verdict raises `source="verify"`, an ok one does not, and
    /// `head_export` is counted apart. Both series are always rendered.
    #[test]
    fn a_failed_verify_raises_its_counter_and_an_ok_one_does_not() {
        let before = metrics_text();
        assert!(before.contains("# TYPE noo_audit_verify_failures_total counter"), "{before}");
        let (v0, h0) = (line(&before, "verify"), line(&before, "head_export"));
        let ok = crate::audit_integrity::Report { verdict: "ok".into(), ..Default::default() };
        count_report(&ok);
        assert_eq!(line(&metrics_text(), "verify"), v0, "an ok verdict is not a failure");
        let fail = crate::audit_integrity::Report { verdict: "fail".into(), ..Default::default() };
        count_report(&fail);
        assert_eq!(line(&metrics_text(), "verify"), v0 + 1);
        note_failure(Source::HeadExport);
        let after = metrics_text();
        assert_eq!((line(&after, "verify"), line(&after, "head_export")), (v0 + 1, h0 + 1));
    }

    #[test]
    fn a_tick_right_after_a_long_run_is_skipped_never_stacked() {
        assert!(!should_skip(None, INTERVAL_SECS), "the first run is never skipped");
        assert!(should_skip(Some(0), INTERVAL_SECS), "a burst tick right after a run");
        assert!(should_skip(Some(INTERVAL_SECS / 2 - 1), INTERVAL_SECS));
        assert!(!should_skip(Some(INTERVAL_SECS / 2), INTERVAL_SECS));
        assert!(!should_skip(Some(INTERVAL_SECS), INTERVAL_SECS), "an on-time tick runs");
    }

    /// The verify read must never block a writer: a plain SELECT through the
    /// pool, no transaction, no row or table lock.
    #[test]
    fn the_verify_read_takes_no_lock() {
        let sel = crate::repo::audit::SELECT_ROWS.to_ascii_uppercase();
        assert!(sel.starts_with("SELECT ") && sel.contains("FROM NOO_SECURITY_AUDIT"), "{sel}");
        for bad in ["FOR UPDATE", "FOR SHARE", "FOR NO KEY", "FOR KEY SHARE", "LOCK "] {
            assert!(!sel.contains(bad), "the verify read takes a lock ({bad}): {sel}");
        }
        let src = include_str!("repo/audit.rs");
        let body = src.split("pub async fn all_for_verify").nth(1).and_then(|r| r.split("\npub ").next()).expect("all_for_verify");
        for bad in ["begin(", "FOR UPDATE", "FOR SHARE", "LOCK"] {
            assert!(!body.contains(bad), "all_for_verify must stay a plain read ({bad})");
        }
        assert!(body.contains("fetch_all(db)"), "{body}");
    }
}
