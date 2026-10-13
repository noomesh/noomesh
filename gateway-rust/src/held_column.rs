// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Does `docs.held_at` exist yet? (document hold, trellion migration 105)
//!
//! The gateway and trellion ship separately: a stack tag does not pin
//! trellion, and on any roll the gateway can start before trellion has
//! migrated. A query that names `held_at` against a database that lacks the
//! column ERRORS, and the queries that name it are the rag status, the
//! backlog gauge, the backpressure count and the graph/docs reads. So every
//! one of them asks [`present`] first and uses its plain form when the
//! column is absent.
//!
//! One `information_schema` lookup. A positive answer is cached for good (a
//! column does not go away). A negative one is re-checked at most every
//! [`RECHECK`], so the filters switch on after trellion migrates, with no
//! gateway restart. A failed lookup counts as "absent" and is not cached as
//! a positive: the plain form is always safe.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a negative answer stands before the column is looked for again.
pub const RECHECK: Duration = Duration::from_secs(60);

/// What the gateway has learned so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    present: bool,
    last_negative: Option<Instant>,
}

/// What [`State::decide`] says to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Use this answer; no lookup.
    Known(bool),
    /// Look the column up.
    Check,
}

impl State {
    /// Pure, so the caching rule can be pinned with a fake clock.
    pub fn decide(&self, now: Instant) -> Decision {
        if self.present {
            return Decision::Known(true);
        }
        match self.last_negative {
            Some(t) if now.saturating_duration_since(t) < RECHECK => Decision::Known(false),
            _ => Decision::Check,
        }
    }

    /// Record the outcome of a lookup made at `now`.
    pub fn record(&mut self, found: bool, now: Instant) {
        if found {
            self.present = true;
            self.last_negative = None;
        } else {
            self.last_negative = Some(now);
        }
    }
}

static STATE: Mutex<State> = Mutex::new(State { present: false, last_negative: None });

const LOOKUP: &str = "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
     WHERE table_name = 'docs' AND column_name = 'held_at' \
       AND table_schema = ANY (current_schemas(false)))";

/// Whether `docs.held_at` exists. Never errors: a failed lookup is "absent".
pub async fn present(db: &sqlx::PgPool) -> bool {
    let now = Instant::now();
    let decision = STATE.lock().map(|s| s.decide(now)).unwrap_or(Decision::Check);
    if let Decision::Known(v) = decision {
        return v;
    }
    let found = sqlx::query_scalar::<_, bool>(LOOKUP).fetch_one(db).await.unwrap_or(false);
    if let Ok(mut s) = STATE.lock() {
        s.record(found, now);
    }
    found
}

/// The "not held" predicate for a `docs` row aliased `alias`: the real filter
/// when the column exists, otherwise `TRUE` (the plain form).
pub fn not_held(alias: &str, present: bool) -> String {
    if present {
        format!("{alias}.held_at IS NULL")
    } else {
        "TRUE".to_string()
    }
}

/// The refusal a hold/unhold/held/purge call gets while the column is absent.
/// Same wording as the worker's (`workers/rag.py::HOLD_SKEW_MSG`).
pub const ROLL_TRELLION_FIRST: &str = "this trellion does not support document hold yet; roll trellion first \
(its migration 105 adds docs.held_at)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_positive_answer_is_kept_for_good() {
        let t0 = Instant::now();
        let mut s = State::default();
        assert_eq!(s.decide(t0), Decision::Check);
        s.record(true, t0);
        assert_eq!(s.decide(t0 + Duration::from_secs(86_400)), Decision::Known(true));
    }

    #[test]
    fn a_negative_answer_is_rechecked_after_a_minute_not_before() {
        let t0 = Instant::now();
        let mut s = State::default();
        s.record(false, t0);
        assert_eq!(s.decide(t0 + Duration::from_secs(1)), Decision::Known(false));
        assert_eq!(s.decide(t0 + Duration::from_secs(59)), Decision::Known(false));
        assert_eq!(s.decide(t0 + RECHECK), Decision::Check);
        // ... and it flips on once trellion has migrated
        s.record(true, t0 + RECHECK);
        assert_eq!(s.decide(t0 + RECHECK), Decision::Known(true));
    }

    #[test]
    fn without_the_column_no_query_text_names_held_at() {
        assert_eq!(not_held("d", false), "TRUE");
        assert_eq!(not_held("d", true), "d.held_at IS NULL");
    }
}
