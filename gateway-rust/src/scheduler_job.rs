// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Job record parsing and queue semantics for the scheduler port.
//!
//! Phase 3. Pure decoding + ordering
//! logic — no Redis calls, no dispatch — so it can be tested against the
//! exact shapes `cluster/scheduler.py::submit_job` writes.
//!
//! Everything in a job hash is stored as a STRING by Python's redis
//! client (`decode_responses=True`, all values coerced via `str()`), so
//! this parses defensively rather than trusting types. A field that is
//! absent, empty, or malformed must degrade to the same default Python
//! uses — a divergence here silently changes which job runs next.
//!
//! `scheduler_engine` is the caller. See the `allow(dead_code)` note in
//! `scheduler_slots.rs` for why the unused remainder of the ported surface
//! is kept.
#![allow(dead_code)]

use std::collections::HashMap;

/// Queue scoring, from `submit_job`: `zadd(QUEUE_KEY, {job_id: -priority})`.
///
/// So the score is the NEGATED priority, and a lower score pops first:
/// priority 9 → score -9, priority 0 → score 0.
///
/// `_dispatch_next` reads the queue in two passes:
///   1. regular    — `zrangebyscore(-inf, -1)`  i.e. priority >= 1
///   2. background — `zrangebyscore(0, 0)`      i.e. priority == 0
///
/// The split is why a background job can never jump ahead of a regular
/// one, and why background jobs additionally require a completely idle
/// node (`require_all_slots_free`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueClass {
    Regular,
    Background,
}

impl QueueClass {
    /// Classify by the ZSET score, matching the two `zrangebyscore` calls.
    pub fn from_score(score: f64) -> Option<Self> {
        if score <= -1.0 {
            Some(QueueClass::Regular)
        } else if score == 0.0 {
            Some(QueueClass::Background)
        } else {
            // Scores in (-1, 0) or > 0 match NEITHER range, so Python
            // would never dequeue them. Represent that rather than
            // guessing — a job stuck here is a bug worth surfacing, not
            // something to round into a class.
            None
        }
    }

    /// Background jobs may only start on a fully idle node.
    pub fn requires_all_slots_free(self) -> bool {
        matches!(self, QueueClass::Background)
    }
}

/// The subset of a job hash the dispatch decision actually reads.
///
/// Deliberately not the whole record — `payload`, `result`, timestamps
/// and retry bookkeeping don't influence placement, and modelling them
/// here would invite drift with no benefit.
#[derive(Debug, Clone, PartialEq)]
pub struct JobRecord {
    pub id: String,
    pub job_type: String,
    pub priority: i64,
    pub status: String,
    /// Pin to a specific node; empty in Python means "no pin".
    pub force_node: Option<String>,
    /// Required backend (vllm/llamacpp/ollama…); empty means "any".
    pub backend: Option<String>,
    pub min_vram_gb: f64,
    /// Node that most recently failed to ack this job. The first
    /// placement pass skips it; the second allows it again, since it may
    /// be the only node capable of running the job.
    pub last_failed_node: Option<String>,
}

/// Python writes `""` for "unset" on these fields, and `or None` treats
/// empty as absent. Mirror that exactly.
fn optional(map: &HashMap<String, String>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(v) if !v.trim().is_empty() => Some(v.clone()),
        _ => None,
    }
}

impl JobRecord {
    /// Parse a Redis hash. Returns `None` only when the hash is empty —
    /// which Python treats as a stale queue entry and removes.
    ///
    /// Defaults match `_try_dispatch_job`:
    ///   `priority` → 5, `min_vram_gb` → 0.0.
    pub fn from_hash(map: &HashMap<String, String>) -> Option<Self> {
        if map.is_empty() {
            return None;
        }
        Some(JobRecord {
            id: map.get("id").cloned().unwrap_or_default(),
            job_type: map.get("type").cloned().unwrap_or_default(),
            // `int(job.get("priority", "5"))` — a malformed value raises in
            // Python. Here it falls back to the same default rather than
            // panicking; a crashed scheduler is worse than a mis-prioritised
            // job.
            priority: map
                .get("priority")
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(5),
            status: map.get("status").cloned().unwrap_or_default(),
            force_node: optional(map, "force_node"),
            backend: optional(map, "backend"),
            min_vram_gb: map
                .get("min_vram_gb")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .filter(|f| f.is_finite() && *f >= 0.0)
                .unwrap_or(0.0),
            last_failed_node: optional(map, "last_failed_node"),
        })
    }

    /// Router priority bucket, from `_try_dispatch_job`:
    /// `>= 8` HIGH, `>= 4` MEDIUM, else LOW.
    pub fn task_priority(&self) -> TaskPriority {
        if self.priority >= 8 {
            TaskPriority::High
        } else if self.priority >= 4 {
            TaskPriority::Medium
        } else {
            TaskPriority::Low
        }
    }

    /// Queue class implied by the record's own priority.
    ///
    /// Note this is derived from `priority`, whereas `QueueClass::from_score`
    /// derives it from the ZSET score. They should agree; phase 5 compares
    /// them, because a mismatch means the hash and the queue have drifted
    /// (e.g. a reprioritise that updated one but not the other).
    pub fn queue_class(&self) -> QueueClass {
        if self.priority >= 1 {
            QueueClass::Regular
        } else {
            QueueClass::Background
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPriority {
    High,
    Medium,
    Low,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Exactly what `submit_job` writes, so the parser is tested against
    /// the real shape rather than an idealised one.
    fn submitted_job() -> HashMap<String, String> {
        hash(&[
            ("id", "abc-123"),
            ("type", "background_graph"),
            ("payload", r#"{"batch_size": 50}"#),
            ("priority", "5"),
            ("status", "queued"),
            ("created_at", "2026-07-31T00:00:00Z"),
            ("updated_at", "2026-07-31T00:00:00Z"),
            ("dispatched_at", ""),
            ("completed_at", ""),
            ("node_id", ""),
            ("result", ""),
            ("error", ""),
            ("retries", "0"),
            ("max_retries", "3"),
            ("timeout_sec", "300"),
            ("force_node", ""),
            ("min_vram_gb", "0"),
            ("backend", ""),
        ])
    }

    #[test]
    fn parses_a_real_submitted_job() {
        let job = JobRecord::from_hash(&submitted_job()).expect("should parse");
        assert_eq!(job.id, "abc-123");
        assert_eq!(job.job_type, "background_graph");
        assert_eq!(job.priority, 5);
        assert_eq!(job.status, "queued");
        assert_eq!(job.min_vram_gb, 0.0);
    }

    /// Python's `job.get("force_node") or None` — empty string is absent.
    #[test]
    fn empty_strings_are_absent_not_present() {
        let job = JobRecord::from_hash(&submitted_job()).unwrap();
        assert_eq!(job.force_node, None, "empty force_node must not pin a node");
        assert_eq!(job.backend, None, "empty backend must not filter candidates");
        assert_eq!(job.last_failed_node, None);
    }

    #[test]
    fn whitespace_only_is_also_absent() {
        let mut h = submitted_job();
        h.insert("force_node".into(), "   ".into());
        let job = JobRecord::from_hash(&h).unwrap();
        assert_eq!(job.force_node, None);
    }

    #[test]
    fn populated_optionals_survive() {
        let mut h = submitted_job();
        h.insert("force_node".into(), "host9".into());
        h.insert("backend".into(), "llamacpp".into());
        h.insert("last_failed_node".into(), "host8".into());
        h.insert("min_vram_gb".into(), "6.5".into());
        let job = JobRecord::from_hash(&h).unwrap();
        assert_eq!(job.force_node.as_deref(), Some("host9"));
        assert_eq!(job.backend.as_deref(), Some("llamacpp"));
        assert_eq!(job.last_failed_node.as_deref(), Some("host8"));
        assert_eq!(job.min_vram_gb, 6.5);
    }

    /// An empty hash is Python's "stale queue entry" case.
    #[test]
    fn empty_hash_is_none() {
        assert!(JobRecord::from_hash(&HashMap::new()).is_none());
    }

    #[test]
    fn malformed_numbers_fall_back_to_python_defaults() {
        let mut h = submitted_job();
        h.insert("priority".into(), "not-a-number".into());
        h.insert("min_vram_gb".into(), "".into());
        let job = JobRecord::from_hash(&h).unwrap();
        assert_eq!(job.priority, 5, "matches int(job.get('priority', '5'))");
        assert_eq!(job.min_vram_gb, 0.0);
    }

    #[test]
    fn negative_or_nonfinite_vram_is_rejected() {
        for bad in ["-4", "NaN", "inf"] {
            let mut h = submitted_job();
            h.insert("min_vram_gb".into(), bad.into());
            assert_eq!(JobRecord::from_hash(&h).unwrap().min_vram_gb, 0.0, "{bad}");
        }
    }

    // ── priority buckets ────────────────────────────────────────────

    #[test]
    fn task_priority_buckets_match_python() {
        let bucket = |p: i64| {
            let mut h = submitted_job();
            h.insert("priority".into(), p.to_string());
            JobRecord::from_hash(&h).unwrap().task_priority()
        };
        assert_eq!(bucket(9), TaskPriority::High);
        assert_eq!(bucket(8), TaskPriority::High, "boundary: >= 8");
        assert_eq!(bucket(7), TaskPriority::Medium);
        assert_eq!(bucket(4), TaskPriority::Medium, "boundary: >= 4");
        assert_eq!(bucket(3), TaskPriority::Low);
        assert_eq!(bucket(0), TaskPriority::Low);
    }

    // ── queue classes ───────────────────────────────────────────────

    #[test]
    fn score_is_the_negated_priority() {
        // submit_job: zadd(QUEUE_KEY, {job_id: -priority})
        assert_eq!(QueueClass::from_score(-9.0), Some(QueueClass::Regular));
        assert_eq!(QueueClass::from_score(-1.0), Some(QueueClass::Regular));
        assert_eq!(QueueClass::from_score(0.0), Some(QueueClass::Background));
    }

    /// Scores strictly between -1 and 0 match neither `zrangebyscore`
    /// range, so Python would never dequeue them. Surface that instead of
    /// silently classifying.
    #[test]
    fn scores_python_would_never_dequeue_are_unclassified() {
        assert_eq!(QueueClass::from_score(-0.5), None);
        assert_eq!(QueueClass::from_score(1.0), None, "positive score = priority < 0");
    }

    #[test]
    fn background_requires_an_idle_node() {
        assert!(QueueClass::Background.requires_all_slots_free());
        assert!(
            !QueueClass::Regular.requires_all_slots_free(),
            "a regular job only needs a free slot, not an idle node"
        );
    }

    #[test]
    fn record_and_score_classes_agree() {
        for p in [0i64, 1, 5, 9] {
            let mut h = submitted_job();
            h.insert("priority".into(), p.to_string());
            let job = JobRecord::from_hash(&h).unwrap();
            let from_score = QueueClass::from_score(-(p as f64)).unwrap();
            assert_eq!(
                job.queue_class(),
                from_score,
                "hash-derived and score-derived class must agree for priority {p}"
            );
        }
    }
}
