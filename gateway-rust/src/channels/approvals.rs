// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster-proposal approvals from chat buttons — Rust, on the private
//! transports.
//!
//! ## Why this exists (it is fixing two live-ish bugs, not just moving code)
//!
//! Approval buttons were only ever handled on the **webhook** path, in
//! Python (`channels/approvals.py`, reached via each adapter's
//! `handle_interaction`). The live transports are Telegram long-polling and
//! Google Chat Pub/Sub pull, and on those two paths:
//!
//! 1. **Telegram silently fed the button id to the model.**
//!    `telegram::parse_update` treats a `callback_query` as an ordinary user
//!    turn and sets `text = callback_query.data`, so pressing Approve sent
//!    the literal string `noo-cluster-approve:<uuid>` to inference. No
//!    decision was recorded, the proposal stayed `pending`, and the user got
//!    whatever the model made of a button id. Telegram is a LIVE channel, so
//!    this is a current bug, not a hypothetical.
//! 2. **Google Chat dropped card clicks entirely.**
//!    `google_chat_pipeline::handle_event` returns early unless
//!    `event_type == "MESSAGE"`, so a `CARD_CLICKED` event arriving over
//!    Pub/Sub was skipped at `debug` level and vanished.
//!
//! Neither would look like a failure: no error, no log at info, just a
//! proposal that stays pending and a button that appears to do nothing.
//!
//! ## Parity
//!
//! Ack strings and the decide semantics are byte-identical to
//! `noomesh/channels/approvals.py` and
//! `workers/cluster.py::_cluster_proposals_decide`: a guarded
//! `UPDATE ... WHERE status = 'pending'` (so a double-click reports "not
//! found or not pending" rather than deciding twice), the same
//! `next_step` text on approval, and the same dashboard live-feed event.
//!
//! Note this does NOT reuse `routes::cluster::proposals_decide`: that
//! handler hardcodes `decided_by = 'dashboard'` / `decided_via = 'ui'` and
//! returns neither `host` nor `next_step`, both of which the chat ack needs.
//! Attribution is the point here — "approved by X via telegram" is the audit
//! trail.

use std::sync::Arc;

use serde_json::{json, Value};

use sqlx::PgPool;

use crate::state::AppState;

/// Button/action id prefixes emitted by `_notify_proposal`. Shared by
/// Telegram inline-keyboard `callback_data` and Google Chat card
/// `actionMethodName` — one vocabulary for both channels.
pub const APPROVE_PREFIX: &str = "noo-cluster-approve:";
pub const REJECT_PREFIX: &str = "noo-cluster-reject:";

/// Exec-approval card prefixes (approve-then-execute gate, 2026-08-08).
/// Same vocabulary rules as the cluster-proposal pair above; the ids are
/// emitted by routes::communication::notify_exec_approval and decided
/// against noo_approval_requests — the SAME row `noo approval` and the
/// dashboard decide, so the blocked tool call's poll sees any of them.
pub const EXEC_APPROVE_PREFIX: &str = "noo-exec-approve:";
pub const EXEC_DENY_PREFIX: &str = "noo-exec-deny:";

/// Split a button/action id into `(verdict, proposal_id)`.
///
/// `None` for anything unrecognized, which the callers treat as "not an
/// approval" and pass through to the normal message flow — matching Python.
pub fn parse_decision(action_id: &str) -> Option<(&'static str, String)> {
    if let Some(id) = action_id.strip_prefix(APPROVE_PREFIX) {
        return Some(("approve", id.to_string()));
    }
    if let Some(id) = action_id.strip_prefix(REJECT_PREFIX) {
        return Some(("reject", id.to_string()));
    }
    None
}

/// Parse a chat MESSAGE as an exec-approval decision: `approve` / `deny`,
/// optionally followed by a request id. This is the transport that works
/// everywhere — the first live card test showed Google never
/// delivers button clicks to a Pub/Sub-connected app ("MESH is unable to
/// process your request"), while plain messages arrive reliably. Only a
/// message that is NOTHING BUT a decision matches; anything longer flows
/// to the coordinator as conversation.
pub fn parse_text_decision(text: &str) -> Option<TextDecision> {
    let mut words = text.split_whitespace();
    let (verdict, soft) = match words.next()?.to_ascii_lowercase().as_str() {
        // Explicit commands: always a decision attempt, even with nothing
        // pending (the reply then says so).
        "approve" => ("approve", false),
        "deny" | "reject" => ("deny", false),
        // CLI-style shorthand: these are also ordinary conversation ("yes",
        // "n"), so they only act as decisions when something is actually
        // pending — the pipeline falls through to the coordinator otherwise.
        "y" | "yes" | "a" => ("approve", true),
        "n" | "no" | "d" | "r" => ("deny", true),
        _ => return None,
    };
    let id = words.next().map(|s| s.to_string());
    if words.next().is_some() {
        return None; // more than "<verdict> [id]" — it's a sentence, not a command
    }
    Some(TextDecision { verdict, id, soft })
}

/// A chat message parsed as an exec-approval decision.
pub struct TextDecision {
    pub verdict: &'static str,
    pub id: Option<String>,
    /// Shorthand forms (y/n/yes/no/a/d/r) double as ordinary conversation:
    /// the caller must treat them as a decision ONLY if a request is
    /// pending, and hand the message to the coordinator otherwise.
    pub soft: bool,
}

/// What a bare decision word refers to.
pub enum PendingResolution {
    One(String),
    None,
    Ambiguous,
}

/// Who, if anyone, this chat sender is allowed to decide approvals AS
///
///
/// The HTTP decision surface requires `role >= Operator` and refuses the
/// fleet-shared cluster token because it cannot be attributed to a person.
/// The chat surface used to require nothing at all: a bare `approve` from
/// any sender the adapter let through decided the newest pending row, and
/// recorded a sender-chosen display name as `resolved_by`.
///
/// **One rule, and only one:** the sender must be LINKED to a noomesh
/// account (`noo_user_channel_links`, via `noo security user link`) and
/// that account must be an operator or admin. The canonical username is
/// what gets recorded, not a display name the sender controls.
///
/// The env sender allow-lists (`NOO_APPROVAL_CHAT_SENDERS`,
/// `TELEGRAM_ALLOWED_USERS`) that used to be accepted here as
/// "equivalent to the operator role" are gone. They were a second, weaker
/// declaration of a role the account table already declares, they were
/// unattributable (`telegram:12345` is not a person), and in Telegram's
/// case the SAME variable was documented to operators as a talk
/// allow-list — so anyone allowed to talk silently gained the authority to
/// approve a blocked `python_exec`. If an operator needs approval
/// authority on a channel, the answer is a link plus a role, both of which
/// are auditable.
pub async fn chat_decider(
    db: &PgPool,
    channel: &str,
    channel_user_id: &str,
) -> Result<String, String> {
    let Some(username) = super::identity::resolve_user(db, channel, channel_user_id).await
    else {
        tracing::warn!(channel, channel_user_id, "chat_approval_refused_unlinked");
        return Err(format!(
            "\u{1F512} Approvals are operator-only, and I don't know who you are. \
             Ask an operator to run `noo security user link <username> {channel} \
             {channel_user_id}` and grant that account the operator role."
        ));
    };
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM noo_users WHERE username = $1")
        .bind(&username)
        .fetch_optional(db)
        .await
        // Tier 2 (crate::egress): the database error is logged under a
        // reference; the chat gets the general sentence and that reference.
        .map_err(|e| crate::egress::error_reply("check your account", &e))?
        .flatten();
    let role: crate::auth::Role = role
        .as_deref()
        .unwrap_or("user")
        .parse()
        .unwrap_or(crate::auth::Role::User);
    if role < crate::auth::Role::Operator {
        tracing::warn!(channel, channel_user_id, %username, ?role, "chat_approval_refused_not_operator");
        return Err(format!(
            "\u{1F512} '{username}' is not an operator \u{2014} approvals are operator-only."
        ));
    }
    Ok(username)
}

/// The request a bare decision refers to, **scoped to the conversation it
/// was typed in**.
///
/// An explicit id still names a row anywhere: an operator reading a request
/// notice in one place and deciding it from another is a real workflow, and
/// `chat_decider` has already established they are an operator.
///
/// A bare `y` / `approve` is different. It used to mean "the globally
/// newest pending row", so a shorthand typed in a group chat could decide a
/// `python_exec` raised in someone else's DM sixty seconds earlier — no id
/// was ever shown to the person typing it, and nothing in the ack told them
/// what they had just approved. Now it means "the one
/// request pending HERE", and with none or several pending here the caller
/// is told to name the id.
pub async fn resolve_pending_request(
    db: &PgPool,
    explicit_id: Option<&str>,
    conversation_id: &str,
) -> Result<PendingResolution, String> {
    if let Some(id) = explicit_id {
        return Ok(PendingResolution::One(id.to_string()));
    }
    // No conversation context (a surface that does not bind one) must not
    // fall back to "newest anywhere" — that is the behaviour being removed.
    if conversation_id.is_empty() {
        return Ok(PendingResolution::None);
    }
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT request_id FROM noo_approval_requests \
         WHERE status = 'pending' AND conversation_id = $1 \
         ORDER BY created_at DESC LIMIT 2",
    )
    .bind(conversation_id)
    .fetch_all(db)
    .await
    .map_err(|e| crate::egress::error_reply("look up pending approvals", &e))?;
    Ok(match rows.len() {
        0 => PendingResolution::None,
        1 => PendingResolution::One(rows[0].0.clone()),
        _ => PendingResolution::Ambiguous,
    })
}

/// The ambiguity reply shared by both channel pipelines.
pub const AMBIGUOUS_PENDING_REPLY: &str =
    "More than one approval is pending — reply with the id, e.g. \
     `approve <id>` (ids are in the request notices).";

/// Split an EXEC-approval button id into `(verdict, request_id)`.
/// Separate from `parse_decision` because the two queues are different
/// tables with different decide semantics; a caller checks both.
pub fn parse_exec_decision(action_id: &str) -> Option<(&'static str, String)> {
    if let Some(id) = action_id.strip_prefix(EXEC_APPROVE_PREFIX) {
        if id.is_empty() { return None; }
        return Some(("approve", id.to_string()));
    }
    if let Some(id) = action_id.strip_prefix(EXEC_DENY_PREFIX) {
        if id.is_empty() { return None; }
        return Some(("deny", id.to_string()));
    }
    None
}

/// Decide an exec-approval request from a chat card click and return the
/// user-facing ack. Card clicks are operator actions by construction —
/// the card is only ever posted to NOO_APPROVAL_GCHAT_SPACE, the
/// operator's own space (same trust model as decide_cluster_proposal,
/// where the HTTP-surface Operator extractor does not apply because
/// chat identity IS the operator's). The blocked tool call polls the same
/// row and proceeds/refuses on the flip.
pub async fn decide_exec_approval(
    db: &PgPool,
    request_id: &str,
    verdict: &str,
    decided_by: &str,
) -> String {
    let status = if verdict == "approve" { "approved" } else { "denied" };
    let result = sqlx::query(
        "UPDATE noo_approval_requests \
         SET status = $2, resolved_by = $3, resolved_at = NOW() \
         WHERE request_id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .bind(status)
    .bind(decided_by)
    .execute(db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::info!(request_id, verdict, by = decided_by, "exec_approval.card_decided");
            if verdict == "approve" {
                format!("\u{2705} Approved ({request_id}) \u{2014} running now.")
            } else {
                format!("\u{1F6AB} Denied ({request_id}) \u{2014} the agent will be told.")
            }
        }
        Ok(_) => format!(
            "\u{23F1} Request {request_id} was already decided or expired \u{2014} nothing changed."
        ),
        Err(e) => {
            tracing::warn!(request_id, error = %e, "exec_approval.card_decide_failed");
            crate::egress::error_reply(&format!("record the decision for {request_id}"), &e)
        }
    }
}

/// Apply an approve/reject decision and return the user-facing ack.
///
/// Never returns an error: a chat ack must always have something to say, so
/// failures come back as ack text. Strings match Python exactly.
pub async fn decide_cluster_proposal(
    state: &Arc<AppState>,
    proposal_id: &str,
    decision: &str,
    decided_by: &str,
    via: &str,
) -> String {
    let new_status = match decision {
        "approve" => "approved",
        "reject" => "rejected",
        other => return format!("Decision rejected: decision must be 'approve' or 'reject', got '{other}'"),
    };

    // Guarded on status='pending' so a double-click cannot decide twice —
    // the second press reports "not found or not pending" instead.
    let row: Result<Option<(String, String, String)>, _> = sqlx::query_as(
        "UPDATE noo_cluster_proposals \
         SET status = $2, decided_at = NOW(), decided_by = $3, decided_via = $4 \
         WHERE id = $1::uuid AND status = 'pending' \
         RETURNING host, user_name, role",
    )
    .bind(proposal_id)
    .bind(new_status)
    .bind(decided_by)
    .bind(via)
    .fetch_optional(&state.db)
    .await;

    let (host, user_name, role) = match row {
        Ok(Some(r)) => r,
        // Python: {"error": "proposal not found or not pending"} → this ack.
        Ok(None) => return "Decision rejected: proposal not found or not pending".to_string(),
        Err(e) => return crate::egress::error_reply("record that decision", &e),
    };

    let verb = if decision == "approve" { "Approved" } else { "Rejected" };
    let mut ack = format!("✓ {verb}: {host} (by {decided_by} via {via})");
    if new_status == "approved" {
        // The host-side executor that used to "pick this up on its next
        // poll" was deleted with the SSH lane. The one thing
        // it did for an enrolment row — write out the bootstrap procedure
        // — happens right here instead, so the chat ack is telling the
        // truth about a row that is already in its terminal state.
        crate::routes::cluster::resolve_enrolment_proposal(state, proposal_id).await;
        ack = format!(
            "{ack}\n\n{}",
            crate::routes::cluster::bootstrap_instructions(&host)
        );
    }

    crate::routes::cluster::emit_cluster_event(
        state,
        &format!("proposal.{new_status}"),
        json!({
            "id": proposal_id,
            "host": host,
            "user": user_name,
            "role": role,
            "status": new_status,
            "decided_by": decided_by,
            "decided_via": via,
        }),
    )
    .await;

    tracing::info!(
        proposal_id = %proposal_id,
        decision = %decision,
        via = %via,
        "channel_proposal_decided"
    );
    ack
}

/// Pull the clicked action id out of either Google Chat card-click shape.
///
/// v1 sends `type: CARD_CLICKED` with `action.actionMethodName` at top
/// level; v2 (Workspace Add-on) nests it under
/// `chat.buttonClickedPayload.clientActions[0].actionMethodName`. Both are
/// in the wild depending on how the app is configured, and the Python
/// implementation handled both — dropping either silently loses clicks.
pub fn extract_card_action_id(data: &Value) -> Option<String> {
    // Legacy (v1) interaction event: action.actionMethodName, which Google
    // also populates from a cardsV2 button's `function` — plus the v2
    // spelling action.function, and common.invokedFunction, which the
    // dialog/action event formats use instead.
    for path in [
        &["action", "actionMethodName"][..],
        &["action", "function"],
        &["common", "invokedFunction"],
    ] {
        let mut node = Some(data);
        for key in path {
            node = node.and_then(|n| n.get(key));
        }
        if let Some(m) = node.and_then(|m| m.as_str()) {
            return Some(m.to_string());
        }
    }
    // Workspace-Events (v2) envelope: chat.buttonClickedPayload carries the
    // click; accept both field spellings there too.
    let click = data
        .get("chat")
        .and_then(|c| c.get("buttonClickedPayload"))
        .and_then(|b| b.get("clientActions"))
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())?;
    click
        .get("actionMethodName")
        .or_else(|| click.get("function"))
        .and_then(|m| m.as_str())
        .map(|m| m.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_verdicts() {
        assert_eq!(
            parse_decision("noo-cluster-approve:abc-123"),
            Some(("approve", "abc-123".to_string()))
        );
        assert_eq!(
            parse_decision("noo-cluster-reject:abc-123"),
            Some(("reject", "abc-123".to_string()))
        );
    }

    #[test]
    fn unrecognized_ids_pass_through() {
        // Must be None, not a default verdict: these fall through to the
        // normal message flow, and defaulting either way would decide a
        // proposal off an unrelated button.
        assert_eq!(parse_decision("some-other-button"), None);
        assert_eq!(parse_decision(""), None);
        assert_eq!(parse_decision("noo-cluster-approve"), None); // no colon
    }

    #[test]
    fn empty_proposal_id_still_parses_but_is_empty() {
        // The DB lookup is what rejects this; parsing should not pretend the
        // prefix was absent.
        assert_eq!(
            parse_decision("noo-cluster-approve:"),
            Some(("approve", String::new()))
        );
    }

    #[test]
    fn parse_exec_decision_roundtrip() {
        assert_eq!(
            parse_exec_decision("noo-exec-approve:abc123"),
            Some(("approve", "abc123".to_string()))
        );
        assert_eq!(
            parse_exec_decision("noo-exec-deny:abc123"),
            Some(("deny", "abc123".to_string()))
        );
        // Empty ids and foreign prefixes are not decisions.
        assert_eq!(parse_exec_decision("noo-exec-approve:"), None);
        assert_eq!(parse_exec_decision("noo-cluster-approve:abc"), None);
        assert_eq!(parse_exec_decision("unrelated"), None);
        // The two vocabularies never cross-match.
        assert_eq!(parse_decision("noo-exec-approve:abc"), None);
    }

    #[test]
    fn text_decisions_are_whole_message_commands_only() {
        let d = parse_text_decision("approve").unwrap();
        assert_eq!((d.verdict, d.id, d.soft), ("approve", None, false));
        let d = parse_text_decision("  DENY  ").unwrap();
        assert_eq!((d.verdict, d.soft), ("deny", false));
        let d = parse_text_decision("reject").unwrap();
        assert_eq!((d.verdict, d.soft), ("deny", false));
        let d = parse_text_decision("approve abc-123").unwrap();
        assert_eq!(d.id.as_deref(), Some("abc-123"));
        // Shorthand is a decision only in context — parses as soft.
        for (word, verdict) in [
            ("y", "approve"),
            ("Yes", "approve"),
            ("a", "approve"),
            ("n", "deny"),
            ("NO", "deny"),
            ("d", "deny"),
            ("r", "deny"),
        ] {
            let d = parse_text_decision(word).unwrap();
            assert_eq!((d.verdict, d.soft), (verdict, true), "word: {word}");
        }
        // Sentences and other verbs flow to the coordinator untouched.
        assert!(parse_text_decision("approve the plan please").is_none());
        assert!(parse_text_decision("I approve").is_none());
        assert!(parse_text_decision("denyy").is_none());
        assert!(parse_text_decision("").is_none());
    }

    #[test]
    fn extracts_action_id_from_every_known_click_shape() {
        use serde_json::json;
        let id = "noo-exec-approve:abc123";
        let shapes = [
            json!({"action": {"actionMethodName": id}}),
            json!({"action": {"function": id}}),
            json!({"common": {"invokedFunction": id}}),
            json!({"chat": {"buttonClickedPayload": {"clientActions": [{"actionMethodName": id}]}}}),
            json!({"chat": {"buttonClickedPayload": {"clientActions": [{"function": id}]}}}),
        ];
        for shape in &shapes {
            assert_eq!(
                extract_card_action_id(shape).as_deref(),
                Some(id),
                "shape not recognized: {shape}"
            );
        }
        assert_eq!(extract_card_action_id(&json!({"action": {}})), None);
    }

    #[test]
    fn extracts_v1_card_action() {
        let ev = json!({
            "type": "CARD_CLICKED",
            "action": {"actionMethodName": "noo-cluster-approve:xyz"}
        });
        assert_eq!(
            extract_card_action_id(&ev).as_deref(),
            Some("noo-cluster-approve:xyz")
        );
    }

    #[test]
    fn extracts_v2_add_on_card_action() {
        let ev = json!({
            "chat": {"buttonClickedPayload": {"clientActions": [
                {"actionMethodName": "noo-cluster-reject:xyz"}
            ]}}
        });
        assert_eq!(
            extract_card_action_id(&ev).as_deref(),
            Some("noo-cluster-reject:xyz")
        );
    }

    #[test]
    fn no_action_id_when_absent_or_wrong_shape() {
        assert_eq!(extract_card_action_id(&json!({"type": "MESSAGE"})), None);
        assert_eq!(extract_card_action_id(&json!({"action": {}})), None);
        assert_eq!(
            extract_card_action_id(&json!({"chat": {"buttonClickedPayload": {"clientActions": []}}})),
            None
        );
    }
}
