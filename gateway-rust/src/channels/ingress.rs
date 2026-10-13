// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Chat ingress admission — who is allowed to talk to the agent.
//!
//! **Default deny, on every channel.** A sender who is not linked to a
//! noomesh account in `noo_user_channel_links` gets a short refusal telling
//! them how to get linked, and nothing else: no conversation row, no
//! coordinator turn, no tools.
//!
//! ## Why this is not "just an allow-list"
//!
//! Telegram used to have one (`TELEGRAM_ALLOWED_USERS`) that returned
//! **true when unset**, and Google Chat had none at all — it ran
//! `resolve_user(...).unwrap_or_else(|| sender_id)` and handed the raw
//! `users/1152…` string to the coordinator as the user. So a stranger who
//! could DM the bot got a tool-bearing session scoped to an INVENTED
//! identity: a KB/memory scope decided worker-side for a user that does not
//! exist, plus every Medium-risk tool (`python_tool`, `browser`,
//! `channel_send`, `inference`). Since the exec-approval default moved to
//! `strict` the HIGH-risk tools are gated, but "gated HIGH tools" is not
//! the same as "not admitted".
//!
//! The link table already declares who each channel id is. Two declarations
//! of the same fact drift, and the one in config wins by accident — the
//! duplicate-declaration trap. So the links ARE the allow-list, and
//! `TELEGRAM_ALLOWED_USERS` is retired: nothing delivers or reads it for
//! admission, and a value that still reaches the gateway earns one boot WARN
//! naming `noo security user link` ([`warn_retired_allowlist`]).
//!
//! ## Flood control
//!
//! A refusal writes a `channel_ingress_denied` audit row. A stranger with a
//! script could otherwise fill `noo_security_audit` from a single chat
//! client, so both the audit row and the outbound refusal are gated per
//! sender: [`AUDIT_WINDOW`] for the row, [`REPLY_WINDOW`] for the reply.
//! The windows are different on purpose — a person who tries twice in a
//! minute should get told twice; the audit trail only needs the pattern.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;

/// One audit row per sender per this window.
pub const AUDIT_WINDOW: Duration = Duration::from_secs(600);
/// One outbound refusal per sender per this window.
pub const REPLY_WINDOW: Duration = Duration::from_secs(60);

/// Entries older than this are dropped on the next sweep, so a bot that
/// cycles sender ids cannot grow the map without bound.
const SWEEP_AFTER: Duration = Duration::from_secs(3600);

/// What the pipeline should do with an inbound turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Linked sender — run the turn as this canonical username.
    Admitted(String),
    /// Not linked. `reply` is `Some` when this sender has not just been
    /// told (see [`REPLY_WINDOW`]); `None` means stay silent.
    Refused { reply: Option<String> },
}

/// Decide whether a channel sender may talk to the agent, and as whom.
///
/// The ONLY admitting rule is a row in `noo_user_channel_links`. There is
/// no env-var override and no "unset means open" branch: this returns
/// `Refused` for every sender the system cannot name.
pub async fn admit(db: &PgPool, channel: &str, channel_user_id: &str) -> Admission {
    if let Some(username) = super::identity::resolve_user(db, channel, channel_user_id).await {
        return Admission::Admitted(username);
    }

    if first_in_window("audit", channel, channel_user_id, AUDIT_WINDOW) {
        crate::routes::core::audit_event(
            db,
            "channel_ingress_denied",
            "warning",
            &format!("{channel}:{channel_user_id}"),
            &format!("channel:{channel}"),
            "denied",
            serde_json::json!({
                "channel": channel,
                "channel_user_id": channel_user_id,
                "reason": "sender is not linked to a noomesh account",
            }),
        )
        .await;
    }
    tracing::info!(channel, channel_user_id, "channel_ingress_denied");

    let reply = first_in_window("reply", channel, channel_user_id, REPLY_WINDOW)
        .then(|| refusal_text(channel, channel_user_id));
    Admission::Refused { reply }
}

/// The short message an unlinked sender gets back.
///
/// It names the exact command, with this sender's own channel id already
/// substituted, because the alternative is an operator guessing at the
/// `users/…` form of a Google Chat id from a log line.
pub fn refusal_text(channel: &str, channel_user_id: &str) -> String {
    format!(
        "\u{1F512} I don't know who you are, so I can't answer.\n\n\
         Ask an operator to link this account:\n\
         `noo security user link <your-noomesh-username> {channel} {channel_user_id}`\n\n\
         (or link it in the dashboard: Security \u{2192} Users \u{2192} channel links). \
         Message me again once it's done."
    )
}

/// `TELEGRAM_ALLOWED_USERS` is retired: it admits nobody, confers nothing,
/// and compose no longer delivers it. If it reaches this process anyway (an
/// operator's own override), say so ONCE at boot, naming the replacement.
/// The launcher says the same about a value left in `.env`
/// (`scripts/lib-addons.sh::warn_retired_env_keys`).
pub fn warn_retired_allowlist() {
    if std::env::var_os("TELEGRAM_ALLOWED_USERS").is_some() {
        tracing::warn!("{RETIRED_ALLOWLIST_WARNING}");
    }
}

/// The one line, shared with its test.
pub const RETIRED_ALLOWLIST_WARNING: &str =
    "TELEGRAM_ALLOWED_USERS is RETIRED and ignored — it admits nobody. Who may talk to the \
     bot is noo_user_channel_links: `noo security user link <username> telegram <id>`. Drop the \
     variable.";

/// True the first time this (bucket, channel, sender) is seen inside
/// `window`, false for repeats. The gate for both the audit row and the
/// outbound refusal.
fn first_in_window(bucket: &str, channel: &str, channel_user_id: &str, window: Duration) -> bool {
    static SEEN: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let map = SEEN.get_or_init(|| Mutex::new(HashMap::new()));
    let key = format!("{bucket}|{channel}|{channel_user_id}");
    let now = Instant::now();
    // A poisoned lock must not open the flood gate, so treat it as "already
    // seen": we lose a log line, not a refusal.
    let Ok(mut seen) = map.lock() else {
        return false;
    };
    if seen.len() > 1024 {
        seen.retain(|_, t| now.duration_since(*t) < SWEEP_AFTER);
    }
    match seen.get(&key) {
        Some(last) if now.duration_since(*last) < window => false,
        _ => {
            seen.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_hit_passes_and_the_second_is_suppressed() {
        // The bug this guards: without the gate a stranger's script writes
        // one audit row per message. Assert the gate actually FIRES (the
        // second call must be false) — a gate that always returns true
        // would pass a test that only checked the first call.
        let uniq = format!("t{}", std::process::id());
        assert!(first_in_window("test", &uniq, "1", Duration::from_secs(60)));
        assert!(!first_in_window("test", &uniq, "1", Duration::from_secs(60)));
        assert!(!first_in_window("test", &uniq, "1", Duration::from_secs(60)));
        // A different sender is independent.
        assert!(first_in_window("test", &uniq, "2", Duration::from_secs(60)));
        // A zero window always passes — used to prove the window, not the key,
        // is what suppresses.
        assert!(first_in_window("test", &uniq, "1", Duration::ZERO));
    }

    #[test]
    fn buckets_do_not_share_a_window() {
        let uniq = format!("b{}", std::process::id());
        assert!(first_in_window("audit", &uniq, "9", Duration::from_secs(60)));
        // Same sender, other bucket — the reply gate must not have been
        // consumed by the audit gate.
        assert!(first_in_window("reply", &uniq, "9", Duration::from_secs(60)));
    }

    #[test]
    fn the_refusal_names_the_link_command_with_this_senders_id() {
        let t = refusal_text("google_chat", "users/1152");
        assert!(
            t.contains("noo security user link <your-noomesh-username> google_chat users/1152"),
            "refusal must be actionable, got: {t}"
        );
    }

    #[test]
    fn the_retired_allowlist_warning_names_its_replacement() {
        assert!(RETIRED_ALLOWLIST_WARNING.contains("noo security user link <username> telegram"));
        assert!(RETIRED_ALLOWLIST_WARNING.contains("RETIRED"));
        // The per-sender hint is gone: admission never reads the variable.
        let admit = include_str!("ingress.rs").split("pub async fn admit(").nth(1).unwrap();
        let admit = admit.split("\n}\n").next().unwrap();
        assert!(admit.contains("resolve_user"), "parse missed admit()");
        assert!(!admit.contains(&["TELEGRAM_", "ALLOWED_USERS"].concat()));
    }
}
