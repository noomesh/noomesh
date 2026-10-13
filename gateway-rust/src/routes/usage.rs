// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Token-usage summary.
//!
//! One read endpoint over `noo_token_usage` (written fire-and-forget by
//! `crate::usage`) plus its long-term rollup `noo_token_usage_monthly`
//! (written by the `usage_rollup` heartbeat action, 049):
//!
//!   GET /api/usage/summary?window=month|all|YYYY-MM&group=node|model|backend|source|user|consumer|day
//!
//! Defaults: window=month (the current calendar month), group=node. Rows are
//! sums per group value, ordered by total tokens descending; a NULL node_id
//! (cloud completions, which no node served) renders as "cloud", as does the
//! monthly table's `''`. Auth is the normal token gate — deliberately NOT in
//! `PUBLIC_PATHS`.
//!
//! Retention makes two windows two-source: `window=all` unions the monthly
//! table in (only for months with NO raw rows, so the
//! insert-succeeded-drop-failed window cannot double count), and an explicit
//! `window=YYYY-MM` whose raw partition has been dropped is served from the
//! monthly table in the same shape. `group=day` is the exception — the
//! monthly table has no day grain, so day grouping always reads raw only,
//! and `window=all&group=day` says so in a `note` field.
//!
//! ## Whose usage
//!
//! This is an **operator report**: Operator+ sees the whole install, at every
//! grain. A `User`-tier caller sees ONLY their own consumption — the filter is
//! applied to both tables, for every `group`, so `group=user` returns exactly
//! one row (theirs) and `group=model|node|day` are their own numbers rather
//! than the fleet's. Before this, any `read`-scope account could read
//! `?group=user` and get every account's name and token volume, because the
//! tier gate admits every `GET` regardless of role.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::{scoped_user, ClusterNode, RequesterCtx};
use crate::routes::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/usage/summary", get(usage_summary))
}

#[derive(Deserialize, Default)]
struct SummaryParams {
    window: Option<String>,
    group: Option<String>,
}

/// The per-user narrowing, in the two tables' spellings.
///
/// Returns `("", "")` when the caller is unscoped (Operator+ and internal
/// cluster services), so an operator report stays exactly what it was.
///
/// The username is NEVER interpolated: it binds, and the only thing spliced
/// is the PLACEHOLDER NUMBER — `$3` when a `YYYY-MM` window has already
/// taken `$1`/`$2`, `$1` otherwise. Raw rows carry a nullable `user_uuid`;
/// the monthly rollup spells "nobody" as the nil uuid. Either way an
/// unattributed row belongs to no account, so `=` excludes it from a scoped
/// read rather than sharing it with everyone.
fn scope_predicates(scoped: bool, month_window: bool) -> (String, String) {
    if !scoped {
        return (String::new(), String::new());
    }
    let ph = if month_window { "$3" } else { "$1" };
    let lookup = format!("(SELECT u.user_uuid FROM noo_users u WHERE u.username = {ph})");
    (
        format!(" noo_token_usage.user_uuid = {lookup} "),
        format!(" m.user_uuid = {lookup} "),
    )
}

/// The two key expressions for a `group`, or a 400.
///
/// Lifted out of the handler so the SQL assembly below is reachable from a
/// test: `summary_sql` is string-building, and string-building that compiles
/// is not string-building that PARSES. The DSN-gated suite runs every
/// (group x window x scoped) combination through `EXPLAIN` against the real
/// schema.
pub(crate) fn group_exprs(group: &str) -> Result<(&'static str, Option<&'static str>), AppError> {
    Ok(match group {
        "node" => (
            "COALESCE(node_id, 'cloud')",
            Some("COALESCE(NULLIF(node_id, ''), 'cloud')"),
        ),
        "model" => ("model", Some("model")),
        "backend" => ("backend", Some("backend")),
        "source" => ("source", Some("source")),
        // WHO (063_usage_user_uuid). Rows key on the account's uuid; the
        // name shown is the account's CURRENT name, so a rename re-labels
        // history rather than splitting it. An account that no longer
        // exists shows its uuid — still one bucket, still not a guess. Raw
        // NULL and the monthly nil-uuid are the same '(unattributed)'.
        "user" => (
            "COALESCE((SELECT u.username FROM noo_users u WHERE u.user_uuid = noo_token_usage.user_uuid), \
                      noo_token_usage.user_uuid::text, '(unattributed)')",
            Some("COALESCE((SELECT u.username FROM noo_users u WHERE u.user_uuid = m.user_uuid), \
                      NULLIF(m.user_uuid, '00000000-0000-0000-0000-000000000000'::uuid)::text, '(unattributed)')"),
        ),
        "consumer" => (
            "COALESCE(consumer, '(unattributed)')",
            Some("COALESCE(NULLIF(consumer, ''), '(unattributed)')"),
        ),
        "day" => ("to_char(ts, 'YYYY-MM-DD')", None),
        other => {
            return Err(AppError::BadRequest(format!(
                "invalid group '{other}' (expected node|model|backend|source|user|consumer|day)"
            )))
        }
    })
}

/// Parse a `YYYY-MM` window into (year, month), or None for anything else.
fn parse_month(s: &str) -> Option<(i32, i32)> {
    let (y, m) = s.split_once('-')?;
    if y.len() != 4 || m.len() != 2 {
        return None;
    }
    let year: i32 = y.parse().ok()?;
    let month: i32 = m.parse().ok()?;
    if !(2000..=2999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    Some((year, month))
}

/// Assemble the summary statement.
///
/// `scoped` decides whether the per-user predicate is spliced in and where
/// its placeholder sits; `window` and `month_window` decide which tables are
/// read. Pure: no database, no state — so the DSN-gated suite can hand every
/// combination to `EXPLAIN` and prove the strings PARSE. A string that
/// compiles is not a string Postgres accepts, and the whole point of this
/// change is a predicate spliced into six different query shapes.
pub(crate) fn summary_sql(
    key_expr: &str,
    monthly_key_expr: Option<&str>,
    window: &str,
    month_window: bool,
    scoped: bool,
) -> (String, Option<&'static str>) {
    let filter = match (window, month_window) {
        ("month", _) => "WHERE ts >= date_trunc('month', now())",
        ("all", _) => "",
        _ => {
            "WHERE ts >= make_date($1, $2, 1) \
                   AND ts <  make_date($1, $2, 1) + interval '1 month'"
        }
    };
    // The per-user narrowing, as two predicates in the two tables' spellings.
    // The username is NEVER interpolated: it binds as the last parameter, and
    // the placeholder number depends on whether a YYYY-MM window already took
    // $1/$2. Raw rows carry a nullable `user_uuid`; the monthly table spells
    // "nobody" as the nil uuid. An unattributed row belongs to nobody, so it
    // is excluded from a scoped read rather than shared with everyone.
    let (raw_scope, monthly_scope) = scope_predicates(scoped, month_window);
    // `filter` already starts with WHERE (or is empty) — splice accordingly.
    let raw_filter = if raw_scope.is_empty() {
        filter.to_string()
    } else if filter.is_empty() {
        format!("WHERE {raw_scope}")
    } else {
        format!("{filter} AND {raw_scope}")
    };
    let raw_only_where = if raw_scope.is_empty() {
        String::new()
    } else {
        format!("WHERE {raw_scope}")
    };
    let monthly_and = if monthly_scope.is_empty() {
        String::new()
    } else {
        format!("AND {monthly_scope}")
    };

    let mut note: Option<&str> = None;
    let sql = match (window, monthly_key_expr) {
        // All time needs both tables. Monthly rows are taken ONLY for months
        // that have NO raw rows: during the insert-succeeded-drop-failed
        // window a month exists in both, and this predicate keeps the raw
        // side (the finer, authoritative one) instead of counting it twice.
        ("all", Some(monthly_key)) => format!(
            "SELECT key,
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
                    COALESCE(SUM(requests), 0)::bigint AS requests
             FROM (
                 SELECT {key_expr} AS key,
                        SUM(prompt_tokens)::bigint AS prompt_tokens,
                        SUM(completion_tokens)::bigint AS completion_tokens,
                        COUNT(*)::bigint AS requests
                 FROM noo_token_usage
                 {raw_only_where}
                 GROUP BY 1
                 UNION ALL
                 SELECT {monthly_key} AS key,
                        SUM(prompt_tokens)::bigint,
                        SUM(completion_tokens)::bigint,
                        SUM(requests)::bigint
                 FROM noo_token_usage_monthly m
                 WHERE NOT EXISTS (
                     SELECT 1 FROM noo_token_usage r
                     WHERE r.ts >= m.month
                       AND r.ts <  m.month + interval '1 month'
                     LIMIT 1)
                 {monthly_and}
                 GROUP BY 1
             ) u
             GROUP BY key
             ORDER BY SUM(prompt_tokens) + SUM(completion_tokens) DESC"
        ),
        // Day grain over "all" cannot reach the monthly table — those rows
        // have no days left. Serve the raw window and say so.
        ("all", None) => {
            note = Some("day grain covers the raw retention window only");
            format!(
                "SELECT {key_expr} AS key,
                        COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
                        COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
                        COUNT(*)::bigint AS requests
                 FROM noo_token_usage
                 {raw_only_where}
                 GROUP BY 1
                 ORDER BY SUM(prompt_tokens) + SUM(completion_tokens) DESC"
            )
        }
        // month / YYYY-MM: raw first; an explicit month whose partition has
        // been rolled and dropped falls back to the monthly table below.
        _ => format!(
            "SELECT {key_expr} AS key,
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
                    COUNT(*)::bigint AS requests
             FROM noo_token_usage
             {raw_filter}
             GROUP BY 1
             ORDER BY SUM(prompt_tokens) + SUM(completion_tokens) DESC"
        ),
    };
    (sql, note)
}

/// The rolled-up fallback for an explicit `YYYY-MM` whose raw partition has
/// been dropped. Always a month window, so the scope's placeholder is `$3`.
pub(crate) fn monthly_fallback_sql(monthly_key: &str, scoped: bool) -> String {
    let (_, monthly_scope) = scope_predicates(scoped, true);
    let monthly_and = if monthly_scope.is_empty() {
        String::new()
    } else {
        format!("AND {monthly_scope}")
    };
    format!(
        "SELECT {monthly_key} AS key,
                COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
                COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
                COALESCE(SUM(requests), 0)::bigint AS requests
         FROM noo_token_usage_monthly m
         WHERE month = make_date($1, $2, 1)
         {monthly_and}
         GROUP BY 1
         ORDER BY SUM(prompt_tokens) + SUM(completion_tokens) DESC"
    )
}

/// GET /api/usage/summary — grouped token totals over a time window.
async fn usage_summary(
    State(state): State<Arc<AppState>>,
    requester: Option<axum::Extension<RequesterCtx>>,
    cluster: Option<axum::Extension<ClusterNode>>,
    Query(params): Query<SummaryParams>,
) -> AppResult {
    // `None` = the whole install (Operator+, and internal cluster services).
    // `Some(u)` = a User-tier caller, pinned to itself. No `?user=` parameter
    // exists to name somebody else, so this cannot 403 — it narrows.
    let scope = scoped_user(
        requester.as_ref().map(|axum::Extension(r)| r),
        cluster.as_ref().map(|axum::Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    // The group column is picked from a whitelist by match — the raw
    // parameter is NEVER interpolated into SQL. Two expressions per group
    // because the same value spells differently per table: raw node_id is
    // nullable (NULL = cloud), the monthly table's is NOT NULL with '' for
    // cloud (a nullable PK column not being a thing Postgres allows). "day"
    // has no monthly expression at all — that grain only exists raw.
    let group = params.group.as_deref().unwrap_or("node");
    let (key_expr, monthly_key_expr) = group_exprs(group)?;

    // Window: current calendar month (default), all time, or an explicit
    // YYYY-MM as [first-of-month, first-of-next-month). The year/month
    // arrive as integer BINDS into make_date, not as SQL text. Validate it
    // HERE — `summary_sql` assembles, it does not judge.
    let window = params.window.as_deref().unwrap_or("month");
    let month_bind = match window {
        "month" | "all" => None,
        other => match parse_month(other) {
            Some(ym) => Some(ym),
            None => {
                return Err(AppError::BadRequest(format!(
                    "invalid window '{other}' (expected month|all|YYYY-MM)"
                )))
            }
        },
    };

    let (sql, note) = summary_sql(
        key_expr,
        monthly_key_expr,
        window,
        month_bind.is_some(),
        scope.is_some(),
    );
    let mut query = sqlx::query(&sql);
    if let Some((year, month)) = month_bind {
        query = query.bind(year).bind(month);
    }
    if let Some(ref u) = scope {
        query = query.bind(u.clone());
    }
    let mut rows = query.fetch_all(&state.db).await?;

    // An explicit YYYY-MM with no raw rows: the partition has been rolled up
    // (or the month simply predates raw retention) — serve the monthly table
    // in the same shape. Not for group=day: the monthly table has no day
    // grain, so an empty raw month is genuinely empty at that grain.
    if rows.is_empty() {
        if let (Some((year, month)), Some(monthly_key)) = (month_bind, monthly_key_expr) {
            let monthly_sql = monthly_fallback_sql(monthly_key, scope.is_some());
            let mut monthly_q = sqlx::query(&monthly_sql).bind(year).bind(month);
            if let Some(ref u) = scope {
                monthly_q = monthly_q.bind(u.clone());
            }
            rows = monthly_q.fetch_all(&state.db).await?;
        }
    }

    let (mut total_prompt, mut total_completion, mut total_requests) = (0i64, 0i64, 0i64);
    let rows_json: Vec<_> = rows
        .iter()
        .map(|r| {
            let prompt: i64 = r.get("prompt_tokens");
            let completion: i64 = r.get("completion_tokens");
            let requests: i64 = r.get("requests");
            total_prompt += prompt;
            total_completion += completion;
            total_requests += requests;
            json!({
                "key": r.get::<String, _>("key"),
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "requests": requests,
            })
        })
        .collect();

    let mut body = json!({
        "window": window,
        "group": group,
        // Say WHOSE numbers these are, so a User-tier caller is never left
        // reading their own row as if it were the install's total.
        "scope": scope.clone().map(Value::String).unwrap_or(Value::Null),
        "totals": {
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "requests": total_requests,
        },
        "rows": rows_json,
    });
    if let Some(n) = note {
        body["note"] = json!(n);
    }
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::{parse_month, scope_predicates};

    /// An unscoped caller must get the report it always
    /// got — an empty predicate, not a `TRUE` that changes the plan.
    #[test]
    fn an_unscoped_caller_gets_no_predicate() {
        assert_eq!(scope_predicates(false, false), (String::new(), String::new()));
        assert_eq!(scope_predicates(false, true), (String::new(), String::new()));
    }

    /// The placeholder has to step past the YYYY-MM window's own binds, or
    /// the username lands in `make_date` and the whole query changes
    /// meaning. This is the bug the test exists to catch.
    #[test]
    fn the_placeholder_steps_past_the_month_binds() {
        let (raw, monthly) = scope_predicates(true, false);
        assert!(raw.contains("= $1)"), "no month window: the scope binds $1 — {raw}");
        assert!(monthly.contains("= $1)"));
        assert!(!raw.contains("$3"));

        let (raw, monthly) = scope_predicates(true, true);
        assert!(raw.contains("= $3)"), "a YYYY-MM window already took $1/$2 — {raw}");
        assert!(monthly.contains("= $3)"));
        assert!(!raw.contains("$1"), "the scope must not reuse the year bind: {raw}");
    }

    /// Each predicate must name ITS OWN table's column. Raw rows are
    /// `noo_token_usage.user_uuid`; the rollup is aliased `m`. Swapping
    /// them yields SQL that still parses in one branch and silently scopes
    /// nothing in the other.
    #[test]
    fn each_predicate_names_its_own_table() {
        let (raw, monthly) = scope_predicates(true, false);
        assert!(raw.trim().starts_with("noo_token_usage.user_uuid ="), "{raw}");
        assert!(monthly.trim().starts_with("m.user_uuid ="), "{monthly}");
        // `=` and not `IS NOT DISTINCT FROM`: an unattributed row belongs to
        // nobody, so a scoped read must not collect it.
        for p in [&raw, &monthly] {
            assert!(!p.contains("IS NOT DISTINCT FROM"), "{p}");
        }
    }

    #[test]
    fn parse_month_accepts_only_yyyy_mm() {
        assert_eq!(parse_month("2026-08"), Some((2026, 8)));
        assert_eq!(parse_month("2026-12"), Some((2026, 12)));
        // Anything else is rejected — it would otherwise be silently
        // treated as an SQL-shaped window string.
        assert_eq!(parse_month("2026-13"), None);
        assert_eq!(parse_month("2026-8"), None);
        assert_eq!(parse_month("26-08"), None);
        assert_eq!(parse_month("month"), None);
        assert_eq!(parse_month("1999-01"), None);
    }
}
