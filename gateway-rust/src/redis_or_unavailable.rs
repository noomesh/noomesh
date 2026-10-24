// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The one answer to "this route needs Redis and the gateway holds no client".
//!
//! Before this module the same condition had five answers depending on which
//! route you asked: a 503 `redis_reconnecting`, a 200 `{"error": "Redis not
//! connected"}`, a 200 `{"enabled": false}`, a 200 empty list with an `error`
//! key, and a prose `Unavailable`. A script that read a 200 as success treated
//! an unreadable queue as an empty one and a refused pause as a pause.
//!
//! There are now two, and only two:
//!
//!   1. The route CANNOT do its job without Redis (every write or action —
//!      submit, cancel, pause, drain, flag writes — and every list whose whole
//!      answer is Redis): call [`redis_or_unavailable`]. It answers 503 with
//!      `Retry-After` and `{"error":"redis_reconnecting","detail":…,
//!      "retry_after_secs":N}`. A caller retries on the code.
//!   2. The route is a STATUS with Redis as one row among others: it stays 200
//!      and reports the Redis-derived fields as `Measured` nulls with a
//!      `<field>_detail` sentence (`measured.rs`) — never a literal `false`
//!      or `0` standing in for "could not look".
//!
//! Best-effort uses (a cache that is skipped, a flag mirrored for another
//! process) are not answers and keep their `if let Some(redis)`.
//!
//! NOTE: the client is made once, at boot (`state.rs`): a gateway that came up
//! before Redis accepted connections keeps answering this until it is
//! restarted. The code says "reconnecting" because that is what a caller
//! should do about it (wait and retry).

use crate::cache::RedisCache;
use crate::routes::AppError;
use crate::state::AppState;

/// How long a caller is told to wait when the gateway has no Redis client.
pub(crate) const REDIS_RETRY_AFTER_SECS: u64 = 5;

/// The refusal itself: 503 + `Retry-After` + `{"error":"redis_reconnecting"}`.
///
/// The detail keeps the words "Redis not connected": `noo upgrade --all`'s
/// node poke (`poke_is_transient`) retries on them as well as on the code.
pub(crate) fn redis_not_connected() -> AppError {
    AppError::UnavailableRetry {
        code: "redis_reconnecting",
        detail: "Redis not connected: this needs the gateway's Redis client, which is not connected yet — retry shortly".into(),
        retry_after_secs: REDIS_RETRY_AFTER_SECS,
    }
}

/// The Redis client, or the one 503 answer.
pub(crate) fn redis_or_unavailable(state: &AppState) -> Result<&RedisCache, AppError> {
    state.redis.as_ref().ok_or_else(redis_not_connected)
}
