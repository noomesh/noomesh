// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The agent meta-loop — now an add-on call, not an engine.
//!
//! `agent_self_check` (in `heartbeat_actions.rs`) runs the SCAN: it queries
//! the audit tables for failed heartbeat runs, repeat-offender tasks, stuck
//! self-develop cycles and security spikes, and emits a digest. That half is
//! open-source and stays here — observing is not a licensed capability.
//!
//! ACTING on those findings is. The ~650 lines that used to live in this file
//! — phases 2a/2b/2d and the Phase C activity inference — moved to the evolve
//! add-on. What remains is the call site.
//!
//! ## Why this file still exists
//!
//! Because the gateway must be able to say WHY nothing happened. With the
//! add-on off, [`dispatch`] returns a sentence naming it — the same contract
//! `routes/evolve_proxy.rs` gives every proxied route: an explained refusal,
//! never a silent skip and never a 404. "The add-on is off" and "the engine
//! is broken" have to stay distinguishable in the digest an operator reads at
//! 6am.
//!
//! ## Where the pieces went
//!
//! | Was here | Is now |
//! |---|---|
//! | phase gates (nine `NOO_AGENT_*` env vars) | evolve's compose env, an explicit allowlist |
//! | `phase2_dispatch`, `phase_c_dispatch` | `POST /api/agent/meta-loop/dispatch` |
//! | `audit_decision`, `was_recently_acted` | evolve, against the same two tables |
//! | `noo_agent_decisions`, `noo_activity_proposals` | unchanged, in `public`; evolve reaches them under grants from migration `060_evolve_meta_loop_grants` |
//!
//! The tables deliberately did not move. Relocating them into evolve's schema
//! is a data migration on a live install, and doing the code move and the
//! table move at once means a failure cannot be attributed to either.
//!
//! The three flags with no reader — `NOO_AGENT_ENGINE_ESCALATE`,
//! `NOO_AGENT_SELF_EDIT`, `NOO_SELF_DEVELOP_AUTO_RESTART` — are gone from
//! `routes/settings.rs` with this change. They rendered as dashboard toggles
//! beside switches that worked, which is worse than absent.
//! evolve's `/api/agent/meta-loop/status` reports them as *unimplemented*
//! rather than *off*, because those are different claims.

use serde_json::{json, Value};

/// What the scan found. Both lists are aggregated by `agent_self_check`
/// before they get here; this type exists only to name the wire shape.
#[derive(Default)]
pub struct ScanFindings {
    /// `(task_id, task_name, error_text)`
    pub recent_failures: Vec<(String, Option<String>, Option<String>)>,
    /// `(task_id, task_name, failure_count_7d)`
    pub repeat_offenders: Vec<(String, Option<String>, i64)>,
}

impl ScanFindings {
    fn to_payload(&self) -> Value {
        json!({
            "recent_failures": self.recent_failures.iter().map(|(id, name, err)| json!({
                "task_id": id, "task_name": name, "error_text": err,
            })).collect::<Vec<_>>(),
            "repeat_offenders": self.repeat_offenders.iter().map(|(id, name, count)| json!({
                "task_id": id, "task_name": name, "count": count,
            })).collect::<Vec<_>>(),
        })
    }
}

/// The outcome of asking the add-on to act.
pub enum MetaLoopOutcome {
    /// The add-on ran. Carries the markdown to append to the digest, which
    /// evolve renders so the digest reads exactly as it did in-process.
    Acted { digest_markdown: String },
    /// The add-on is disabled, unlicensed, or unreachable. Carries the
    /// sentence to print — always a reason, never a blank.
    Unavailable { reason: String },
}

impl MetaLoopOutcome {
    /// The digest section for this outcome.
    ///
    /// An `Unavailable` renders as a visible line rather than nothing: a
    /// digest that silently omits the section is indistinguishable from one
    /// where the add-on ran and had nothing to do.
    pub fn format_for_digest(&self) -> String {
        match self {
            MetaLoopOutcome::Acted { digest_markdown } => digest_markdown.clone(),
            MetaLoopOutcome::Unavailable { reason } => {
                format!("\n## 🤖 Agent meta-loop\n\n_Not run: {reason}_\n")
            }
        }
    }
}

/// Hand one scan's findings to the add-on.
///
/// Goes through [`crate::addon_proxy::call`], naming the route by its manifest
/// key rather than a path. That matters more here than anywhere else: the
/// dispatch route is `internal`, so it is NOT mounted on the gateway's public
/// API — nothing outside should be able to make the fleet retry, escalate and
/// disable its own scheduled tasks — and a literal path would have been the
/// one copy of it that no test could see.
///
/// Never returns an error. A meta-loop that cannot run must not fail the
/// heartbeat task that was only reporting on it — that would turn
/// "self-management is off" into "your daily digest stopped arriving".
pub async fn dispatch(scan_id: &str, findings: &ScanFindings) -> MetaLoopOutcome {
    let body = json!({ "scan_id": scan_id, "findings": findings.to_payload() });
    match crate::addon_proxy::call("evolve", "meta_loop_dispatch", Some(body)).await {
        crate::addon_proxy::CallOutcome::Ok(v) => MetaLoopOutcome::Acted {
            digest_markdown: v
                .get("digest_markdown")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string(),
        },
        crate::addon_proxy::CallOutcome::Unavailable(reason) => {
            // Not an error log for the disabled case — an operator who did not
            // buy the add-on should not see errors about it every scan. The
            // add-on layer already logged the transport failures.
            tracing::debug!(%reason, "meta_loop_dispatch_unavailable");
            MetaLoopOutcome::Unavailable { reason }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_serialise_as_the_add_on_expects() {
        let f = ScanFindings {
            recent_failures: vec![("t1".into(), Some("nightly".into()), Some("boom".into()))],
            repeat_offenders: vec![("t2".into(), None, 4)],
        };
        let p = f.to_payload();
        assert_eq!(p["recent_failures"][0]["task_id"], "t1");
        assert_eq!(p["recent_failures"][0]["error_text"], "boom");
        assert_eq!(p["repeat_offenders"][0]["task_id"], "t2");
        // Null, not "" — the add-on drops rows it cannot attribute, and an
        // empty-string name would read as a task actually called "".
        assert!(p["repeat_offenders"][0]["task_name"].is_null());
        assert_eq!(p["repeat_offenders"][0]["count"], 4);
    }

    #[test]
    fn an_unavailable_add_on_still_prints_a_reason() {
        // The failure mode this guards: a digest that omits the section
        // entirely, which reads as "ran, nothing to do".
        let out = MetaLoopOutcome::Unavailable {
            reason: "the evolve add-on is disabled".into(),
        }
        .format_for_digest();
        assert!(out.contains("Not run"));
        assert!(out.contains("disabled"));
        assert!(!out.trim().is_empty());
    }

    #[test]
    fn an_acted_outcome_passes_the_add_ons_markdown_through_verbatim() {
        // The digest must read the same as when this ran in-process, so the
        // gateway does not re-render or reformat what evolve returned.
        let md = "\n## 🤖 Phase 2 actions taken\n\n- **Auto-retried** (1): t1\n";
        let out = MetaLoopOutcome::Acted {
            digest_markdown: md.to_string(),
        }
        .format_for_digest();
        assert_eq!(out, md);
    }
}
