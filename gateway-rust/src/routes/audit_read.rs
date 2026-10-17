// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Reading the security audit log: `GET /api/security/audit/list`.
//!
//! Until this route the log could only be read with `psql`. The route is
//! Operator and above (an in-handler check, because GETs pass the tier gate for
//! every tier), filterable by time, event type and actor, newest first, and
//! paginated with an opaque cursor. Reading the log is itself recorded
//! (`audit_log_read`), written AFTER the read so a row does not list itself.
//!
//! Its own module, away from `routes/admin.rs`, so the audit stats and verify
//! routes there can be changed without touching this one.

use std::sync::Arc;

use axum::{extract::{Query, State}, routing::get, Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{AppError, AppResult};
use crate::auth::{RequesterCtx, Role};
use crate::state::AppState;

/// Rows returned when `limit` is absent / the most a caller may ask for.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/security/audit/list", get(security_audit_list))
}

#[derive(Debug, Deserialize)]
struct ListParams {
    /// RFC 3339 instant, or a trailing window such as `30m`, `24h`, `7d`.
    since: Option<String>,
    /// Exact `event_type`.
    event_type: Option<String>,
    /// Exact `actor`.
    actor: Option<String>,
    limit: Option<i64>,
    /// The `next_cursor` of the previous page.
    cursor: Option<String>,
}

/// `30m` / `24h` / `7d` / `2w` or an RFC 3339 time, as an instant.
pub(crate) fn parse_since(raw: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let raw = raw.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Ok(t.with_timezone(&Utc));
    }
    let bad = || format!("`since` must be an RFC 3339 time or a window like 30m, 24h, 7d (got {raw:?})");
    let Some((last, _)) = raw.char_indices().last() else { return Err(bad()) };
    let (digits, unit) = raw.split_at(last);
    let n: i64 = digits.parse().map_err(|_| bad())?;
    if n <= 0 {
        return Err(bad());
    }
    let span = match unit {
        "m" => Duration::try_minutes(n),
        "h" => Duration::try_hours(n),
        "d" => Duration::try_days(n),
        "w" => Duration::try_weeks(n),
        _ => return Err(bad()),
    }
    .ok_or_else(bad)?;
    now.checked_sub_signed(span).ok_or_else(bad)
}

/// A page boundary: the last row's `(timestamp, id)`, microsecond-exact.
pub(crate) fn encode_cursor(ts: DateTime<Utc>, id: &str) -> String {
    format!("{}|{id}", ts.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

pub(crate) fn decode_cursor(raw: &str) -> Result<(DateTime<Utc>, String), String> {
    let bad = || "`cursor` is not one this route returned".to_string();
    let (ts, id) = raw.split_once('|').ok_or_else(bad)?;
    let ts = DateTime::parse_from_rfc3339(ts).map_err(|_| bad())?.with_timezone(&Utc);
    uuid::Uuid::parse_str(id).map_err(|_| bad())?;
    Ok((ts, id.to_string()))
}

type Row = (
    String,
    DateTime<Utc>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

/// GET /api/security/audit/list
///
/// Rows of `noo_security_audit`, newest first. Operator and above. Query:
/// `since` (RFC 3339 or `30m`/`24h`/`7d`), `event_type`, `actor` (both exact),
/// `limit` (default 100, at most 500) and `cursor` (the previous page's
/// `next_cursor`). Answers `{events: [...], count, next_cursor}`; each event
/// carries `id`, `timestamp`, `event_type`, `severity`, `actor`, `resource`,
/// `outcome`, `request_id`, `details` (where `source_ip` and
/// `conversation_id` live), `chain_seq` and `entry_hash`. Listing does not
/// verify; `GET /api/security/audit/verify` does.
async fn security_audit_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Query(p): Query<ListParams>,
) -> AppResult {
    if let Some(axum::Extension(r)) = &ctx {
        if r.role < Role::Operator {
            return Err(AppError::Forbidden(
                "reading the security audit log is operator-only (Operator role or above)".into(),
            ));
        }
    }
    let now = Utc::now();
    let since = p
        .since
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_since(s, now))
        .transpose()
        .map_err(AppError::BadRequest)?;
    let cursor = p
        .cursor
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(decode_cursor)
        .transpose()
        .map_err(AppError::BadRequest)?;
    let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let event_type = p.event_type.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let actor = p.actor.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id::text, \"timestamp\", event_type, severity, actor, resource, outcome, \
                request_id, details::text, chain_seq, entry_hash \
           FROM noo_security_audit \
          WHERE ($1::timestamptz IS NULL OR \"timestamp\" >= $1) \
            AND ($2::text IS NULL OR event_type = $2) \
            AND ($3::text IS NULL OR actor = $3) \
            AND ($4::timestamptz IS NULL OR (\"timestamp\", id) < ($4::timestamptz, $5::uuid)) \
          ORDER BY \"timestamp\" DESC, id DESC \
          LIMIT $6",
    )
    .bind(since)
    .bind(event_type)
    .bind(actor)
    .bind(cursor.as_ref().map(|c| c.0))
    .bind(cursor.as_ref().map(|c| c.1.as_str()))
    // One extra row says whether another page exists.
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("cannot read noo_security_audit: {e}")))?;

    let more = rows.len() as i64 > limit;
    let page: Vec<&Row> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more { page.last().map(|r| encode_cursor(r.1, &r.0)) } else { None };
    let events: Vec<Value> = page
        .iter()
        .map(|r| {
            json!({
                "id": r.0,
                "timestamp": r.1.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                "event_type": r.2,
                "severity": r.3,
                "actor": r.4,
                "resource": r.5,
                "outcome": r.6,
                "request_id": r.7,
                "details": r.8.as_deref().and_then(|d| serde_json::from_str::<Value>(d).ok()),
                "chain_seq": r.9,
                "entry_hash": r.10,
            })
        })
        .collect();

    // Who read the log. Written after the read, so it never lists itself.
    let (reader, act) = match &ctx {
        Some(axum::Extension(r)) => (r.sub.clone(), r.act.as_ref().map(|a| json!(a))),
        None => ("cluster".to_string(), None),
    };
    super::core::audit_event(
        &state.db,
        "audit_log_read",
        "info",
        &reader,
        "noo_security_audit",
        "success",
        json!({
            "since": since.map(|t| t.to_rfc3339()),
            "event_type": event_type,
            "actor": actor,
            "limit": limit,
            "paged": cursor.is_some(),
            "returned": events.len(),
            "act": act,
        }),
    )
    .await;

    Ok(Json(json!({
        "events": events,
        "count": events.len(),
        "next_cursor": next_cursor,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).expect("time").with_timezone(&Utc)
    }

    #[test]
    fn since_takes_a_window_or_a_time() {
        let now = at("2026-10-16T12:00:00Z");
        assert_eq!(parse_since("30m", now).unwrap(), at("2026-10-16T11:30:00Z"));
        assert_eq!(parse_since("24h", now).unwrap(), at("2026-10-15T12:00:00Z"));
        assert_eq!(parse_since("7d", now).unwrap(), at("2026-10-09T12:00:00Z"));
        assert_eq!(parse_since("2026-10-01T00:00:00+02:00", now).unwrap(), at("2026-09-30T22:00:00Z"));
    }

    #[test]
    fn a_bad_since_is_refused_not_ignored() {
        let now = at("2026-10-16T12:00:00Z");
        for bad in ["", "yesterday", "0h", "-5m", "5x", "h", "99999999999999999999d", "5é"] {
            assert!(parse_since(bad, now).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_cursor_round_trips_to_the_microsecond() {
        let ts = at("2026-10-16T12:00:00.123456Z");
        let id = "0b9d6a1e-5f55-4a3c-9d57-0c3a3a3a3a3a";
        assert_eq!(decode_cursor(&encode_cursor(ts, id)).unwrap(), (ts, id.to_string()));
    }

    #[test]
    fn a_forged_cursor_is_refused() {
        for bad in ["", "nope", "2026-10-16T12:00:00Z|not-a-uuid", "x|0b9d6a1e-5f55-4a3c-9d57-0c3a3a3a3a3a"] {
            assert!(decode_cursor(bad).is_err(), "{bad:?}");
        }
    }
}
