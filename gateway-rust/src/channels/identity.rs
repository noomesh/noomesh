// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Channel identity — map a channel-native user id to the canonical user.
//!
//! `noo_user_channel_links` already declares this:
//!
//! ```text
//!   google_chat | users/1000...  -> alice
//!   telegram    | 1000000001     -> alice
//! ```
//!
//! It was populated and, until now, read by nobody on the message path:
//! `noomesh.identity.resolve_user` exists and is exported, but has no
//! callers outside its own package. So both the Python adapters and the
//! first cut of the Rust pipelines passed the RAW channel id downstream as
//! the user id.
//!
//! That is wrong in a way that is easy to miss, because everything still
//! answers: per-user memory scoping, model preferences and org/team
//! filtering all key on user id, so a raw `1000000001` silently behaves as
//! a different person from `alice` — the same human gets one identity per
//! channel, and none of them is the account they actually own.
//!
//! This table is a MESH table (baseline migration 001), owned and written
//! by this gateway (`routes/users.rs`), so reading it directly is correct.
//! That is the opposite of conversation identity, which lives in Trellion
//! and must go through `worker.memory.resolve_conversation`.

use sqlx::PgPool;

/// Canonical username for a channel user, or None when no link exists.
///
/// Callers decide the fallback. Deliberately not defaulted here: "unlinked"
/// means different things for attribution (use the raw id) and for access
/// control (do not treat an unknown user as known).
pub async fn resolve_user(
    db: &PgPool,
    channel: &str,
    channel_user_id: &str,
) -> Option<String> {
    if channel.is_empty() || channel_user_id.is_empty() {
        return None;
    }
    match sqlx::query_scalar::<_, String>(
        "SELECT username FROM noo_user_channel_links \
         WHERE channel = $1 AND channel_user_id = $2",
    )
    .bind(channel)
    .bind(channel_user_id)
    .fetch_optional(db)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            // A lookup failure must not silently downgrade to the raw id in
            // a security decision, so say so loudly and let the caller pick.
            tracing::warn!(channel, channel_user_id, error = %e, "identity_lookup_failed");
            None
        }
    }
}
