// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The authoritative job-type table: what a job type is, and **who executes it**.
//!
//! Before this module the set of job types was implied by three switch
//! statements that nobody had to keep in agreement:
//!
//! - `node-agent-go/internal/jobs/executor.go` — the `switch job.Type` that
//!   actually runs work on a node.
//! - `src/noomesh/cluster/scheduler.py` — the `JobType` enum.
//! - the submit routes here, which validated nothing at all.
//!
//! The gap was observable: `noo jobs submit --type test_run` was accepted,
//! queued, dispatched to a node whose executor has no `test_run` case, and
//! then rotted — the node either failed it repeatedly through the retry
//! budget or (with a stranded dispatch consumer) never answered and the
//! reaper eventually killed it. Meanwhile the gateway *does* execute
//! `test_run` — `POST /api/tests/run` runs pytest in-process and writes the
//! job hash with `node_id="gateway"`. So the type was real; the submit path
//! just sent it to the wrong executor.
//!
//! This table is the single declaration. Everything else derives from it:
//! the submit routes reject unknown types and route gateway-local ones to
//! the in-process executor, and
//! `tests/test_job_type_declarations.py` asserts the Go switch and the
//! Python enum still agree with it (a cross-language check, because the Go
//! and Python sources are not visible from this crate's build).

/// Who runs a job of a given type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executor {
    /// Dispatched over NATS to a node-agent (`tasks.dispatch.<node>`).
    Node,
    /// Executed in the gateway process; never dispatched to a node.
    Gateway,
}

/// Every job type the cluster can execute, and its executor.
///
/// Keep alphabetical within each executor group. Adding a row here is not
/// enough on its own: a `Node` row needs a case in the Go executor, a
/// `Gateway` row needs an arm in `routes::admin::run_gateway_local`.
pub const JOB_TYPES: &[(&str, Executor)] = &[
    // ── Node-executed (node-agent-go/internal/jobs/executor.go) ──
    ("background_cache", Executor::Node),
    ("background_graph", Executor::Node),
    ("fetch_bundle", Executor::Node),
    ("inference", Executor::Node),
    ("model_download", Executor::Node),
    ("model_file", Executor::Node),
    ("tool_exec", Executor::Node),
    // ── Gateway-executed (in-process, node_id="gateway") ──
    ("test_run", Executor::Gateway),
];

/// Job types that once existed and were retired, with the reason.
///
/// Not executable — `executor_for` returns `None` for every one — but kept
/// so the scheduler janitor can expire an entry still queued from before
/// the retirement with a reason that says WHY, instead of the generic
/// "unknown type", and so a reader grepping for the name finds this.
pub const RETIRED_JOB_TYPES: &[(&str, &str)] = &[
    (
        "background_embed",
        "retired: page/chunk embedding is trellion's own PageIndexEmbedder loop, and \
         conversation memory drains through the unembedded_conversations autonomy location — \
         this job only bounced a node back to the controller's /api/memory/embed/start",
    ),
];

/// Why a type that `executor_for` rejects is not runnable, for the
/// janitor's terminal reason.
pub fn unconsumed_reason(job_type: &str) -> String {
    match RETIRED_JOB_TYPES.iter().find(|(name, _)| *name == job_type) {
        Some((_, why)) => format!("job type '{job_type}' {why}"),
        None => format!("job type '{job_type}' has no executor (valid: {})", known_types()),
    }
}

/// The executor for `job_type`, or `None` if nothing can execute it.
pub fn executor_for(job_type: &str) -> Option<Executor> {
    JOB_TYPES
        .iter()
        .find(|(name, _)| *name == job_type)
        .map(|(_, ex)| *ex)
}

/// Comma-separated list of every executable type, for error messages.
pub fn known_types() -> String {
    JOB_TYPES
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The rejection message for a type nobody can execute.
///
/// One function so the route, the CLI contract test and the docs all quote
/// the same sentence.
pub fn unknown_type_error(job_type: &str) -> String {
    format!(
        "unknown job type '{job_type}' — no executor can run it. Valid types: {}",
        known_types()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_types_match_the_go_executor_switch() {
        // Mirror of the `switch job.Type` in
        // node-agent-go/internal/jobs/executor.go. The cross-language guard
        // that this list is still true lives in
        // tests/test_job_type_declarations.py; this one keeps the table
        // itself honest if someone edits a row here.
        let mut node: Vec<&str> = JOB_TYPES
            .iter()
            .filter(|(_, ex)| *ex == Executor::Node)
            .map(|(n, _)| *n)
            .collect();
        node.sort_unstable();
        assert_eq!(
            node,
            vec![
                "background_cache",
                "background_graph",
                "fetch_bundle",
                "inference",
                "model_download",
                "model_file",
                "tool_exec",
            ]
        );
    }

    #[test]
    fn test_run_is_gateway_local_not_node_dispatched() {
        assert_eq!(executor_for("test_run"), Some(Executor::Gateway));
    }

    #[test]
    fn inference_is_node_dispatched() {
        assert_eq!(executor_for("inference"), Some(Executor::Node));
    }

    #[test]
    fn unknown_type_has_no_executor() {
        assert_eq!(executor_for("smoke"), None);
        assert_eq!(executor_for(""), None);
        // warm_embeddings/warm_entities are *actions* inside a
        // background_cache payload, not job types of their own.
        assert_eq!(executor_for("warm_embeddings"), None);
    }

    #[test]
    fn error_message_names_the_valid_types() {
        let msg = unknown_type_error("smoke");
        assert!(msg.contains("'smoke'"));
        for (name, _) in JOB_TYPES {
            assert!(msg.contains(name), "error message omits {name}");
        }
    }

    #[test]
    fn retired_types_are_not_executable_and_say_why() {
        for (name, why) in RETIRED_JOB_TYPES {
            assert_eq!(executor_for(name), None, "{name} is retired but still in JOB_TYPES");
            assert!(unconsumed_reason(name).contains(why));
        }
        assert!(unconsumed_reason("smoke").contains("has no executor"));
    }

    #[test]
    fn table_has_no_duplicates() {
        let mut names: Vec<&str> = JOB_TYPES.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate job type in JOB_TYPES");
    }
}
