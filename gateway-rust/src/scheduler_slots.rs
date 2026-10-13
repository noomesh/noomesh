// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node slot accounting for the job scheduler.
//!
//! Phase 2 of the scheduler port. These
//! are the pure functions — no Redis, no NATS — ported first so they can
//! be checked against the Python characterization tests
//! (`tests/test_scheduler_slots.py`) before any dispatch logic moves.
//!
//! Since phase 7 this IS the slot policy: the Python `_max_slots` /
//! `normalize_tier` / `_has_slots` it was ported from were deleted with the
//! Python dispatch loop, and `scheduler_engine` calls these directly.
//!
//! `dead_code` is allowed because the module deliberately keeps the full
//! ported surface (including helpers the engine does not call on every
//! path) so it stays checkable against the characterization tests.
#![allow(dead_code)]

use serde_json::Value;

/// Max concurrent jobs per tier. Was ported from `DEFAULT_SLOTS` in
/// `cluster/scheduler.py`; since phase 7 deleted that copy, this table is
/// the only slot policy in the system.
///
/// Tiers 5 (companion) and 6 (monitor) get ZERO deliberately: a sensor
/// proxy and a probe box must never receive scheduled inference work.
pub fn slots_for_tier(tier: i64) -> Option<u32> {
    match tier {
        1 => Some(2), // VRAM >= 10GB — can overlap inference + background
        2 => Some(1), // VRAM 4-10GB
        3 => Some(1), // CPU only
        4 => Some(1), // Edge — one job at a time
        5 => Some(0), // Companion — sensor tool calls only
        6 => Some(0), // Monitor — probes/meshsec only
        _ => None,    // unclassifiable → caller fails closed
    }
}

/// Coerce a tier from whatever the registry supplied into a plain int.
///
/// The tier arrives as a JSON number (NATS KV), a string (some registry
/// paths), or is absent entirely mid-registration. Normalising before the
/// lookup is what stops a stringified `"5"` being treated as an ordinary
/// worker instead of the companion it is — the fail-open bug this port
/// inherited from Python and fixed on 2026-07-31.
///
/// Booleans are rejected: JSON `true` must not become tier 1.
/// Non-integral floats are rejected rather than truncated — a tier of
/// `5.9` is corrupt data, not tier 5.
pub fn normalize_tier(raw: &Value) -> Option<i64> {
    match raw {
        Value::Null => None,
        Value::Bool(_) => None,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else {
                // Accept a float only when it is exactly integral.
                n.as_f64()
                    .filter(|f| f.fract() == 0.0 && f.is_finite())
                    .map(|f| f as i64)
            }
        }
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Max slots for a node, failing CLOSED on anything unclassifiable.
///
/// Returns 0 when the node is drained, when the tier cannot be
/// normalised, or when the tier has no policy entry. Withholding work
/// from one node costs a queued job; dispatching to a sensor proxy costs
/// a job that cannot run.
pub fn max_slots(raw_tier: &Value, drained: bool) -> u32 {
    if drained {
        return 0;
    }
    normalize_tier(raw_tier)
        .and_then(slots_for_tier)
        .unwrap_or(0)
}

/// Whether a node can accept another job.
///
/// `current` is the cardinality of `noo:jobs:node:<id>`. Uses `<` so an
/// over-occupied node (possible after a crash + recovery) reads as full
/// rather than wrapping into eligible.
pub fn has_slots(raw_tier: &Value, drained: bool, current: u32) -> bool {
    current < max_slots(raw_tier, drained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── tier → slots (must match DEFAULT_SLOTS in Python) ───────────

    #[test]
    fn worker_tiers_match_python_policy() {
        assert_eq!(slots_for_tier(1), Some(2));
        assert_eq!(slots_for_tier(2), Some(1));
        assert_eq!(slots_for_tier(3), Some(1));
        assert_eq!(slots_for_tier(4), Some(1));
    }

    #[test]
    fn companion_and_monitor_get_zero() {
        assert_eq!(slots_for_tier(5), Some(0), "companion is a sensor proxy");
        assert_eq!(slots_for_tier(6), Some(0), "monitor runs probes only");
    }

    #[test]
    fn unknown_tier_has_no_policy() {
        assert_eq!(slots_for_tier(0), None);
        assert_eq!(slots_for_tier(7), None);
        assert_eq!(slots_for_tier(99), None);
        assert_eq!(slots_for_tier(-1), None);
    }

    // ── normalisation ───────────────────────────────────────────────

    #[test]
    fn normalizes_numbers_and_strings() {
        assert_eq!(normalize_tier(&json!(1)), Some(1));
        assert_eq!(normalize_tier(&json!(5)), Some(5));
        assert_eq!(normalize_tier(&json!("3")), Some(3));
        assert_eq!(normalize_tier(&json!("  2  ")), Some(2));
        assert_eq!(normalize_tier(&json!(4.0)), Some(4), "integral float ok");
    }

    #[test]
    fn rejects_values_that_are_not_tiers() {
        assert_eq!(normalize_tier(&json!(null)), None);
        assert_eq!(normalize_tier(&json!("")), None);
        assert_eq!(normalize_tier(&json!("abc")), None);
        assert_eq!(normalize_tier(&json!("5.0")), None, "matches Python isdigit()");
        assert_eq!(normalize_tier(&json!(5.9)), None, "corrupt, not tier 5");
        assert_eq!(normalize_tier(&json!([])), None);
        assert_eq!(normalize_tier(&json!({})), None);
    }

    #[test]
    fn bool_is_never_a_tier() {
        // JSON true must not become tier 1 and earn two slots.
        assert_eq!(normalize_tier(&json!(true)), None);
        assert_eq!(normalize_tier(&json!(false)), None);
        assert_eq!(max_slots(&json!(true), false), 0);
    }

    // ── fail-closed behaviour (the 2026-07-31 fix) ──────────────────

    #[test]
    fn unclassifiable_tier_gets_no_slots() {
        for raw in [json!(null), json!(99), json!("abc"), json!({})] {
            assert_eq!(max_slots(&raw, false), 0, "must fail closed for {raw}");
        }
    }

    #[test]
    fn stringified_companion_is_still_a_companion() {
        // The exact bug: "5" missing an int-keyed lookup and defaulting to
        // schedulable.
        assert_eq!(max_slots(&json!("5"), false), 0);
        // …while a stringified worker keeps its real allowance.
        assert_eq!(max_slots(&json!("1"), false), 2);
    }

    // ── drain ───────────────────────────────────────────────────────

    #[test]
    fn drain_overrides_tier() {
        assert_eq!(max_slots(&json!(1), true), 0);
        assert!(!has_slots(&json!(1), true, 0), "drained beats idle");
    }

    // ── occupancy ───────────────────────────────────────────────────

    #[test]
    fn tier1_allows_two_concurrent() {
        assert!(has_slots(&json!(1), false, 0));
        assert!(has_slots(&json!(1), false, 1));
        assert!(!has_slots(&json!(1), false, 2));
    }

    #[test]
    fn tier2_allows_one() {
        assert!(has_slots(&json!(2), false, 0));
        assert!(!has_slots(&json!(2), false, 1));
    }

    #[test]
    fn over_occupancy_reads_as_full_not_negative() {
        // More assigned jobs than slots is possible after a crash; it must
        // not wrap into eligible.
        assert!(!has_slots(&json!(2), false, 5));
    }

    #[test]
    fn companion_never_eligible_even_when_idle() {
        assert!(!has_slots(&json!(5), false, 0));
    }
}
