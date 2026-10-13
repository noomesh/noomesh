// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Loki-backed log review (fleet logging plan, phase 5).
//!
//! Three operator doors — `noo logs …`, the MCP log tools and the HTTP
//! routes under `/api/logs/` — answer "what happened on host3 at 14:02" and
//! "every error across the fleet in the last hour" through the code here.
//! The handler never hands the model's or the operator's words to Loki as
//! LogQL: [`build`] turns a small, typed request into ONE selector over the
//! fixed label set the ingest route enforces (`logs_ingest::ALLOWED_LABELS`
//! plus the verified `node`), and free text becomes a `|=` line filter with
//! `"` and `\` escaped so a value can never close the string and open a
//! pipeline stage. A caller that sends `query` explicitly gets its LogQL
//! through unchanged — that is the raw-LogQL door `/api/logs/query` already
//! opens for operators — but still under the same limit and range caps,
//! because a limit of a million lines or a range of a year is a Loki outage
//! whoever asked for it.
//!
//! Every response says which backend answered (`"backend": "loki"` or
//! `"agent-scan"`): `errors` and `tail` fall back to scanning `docker logs`
//! through the node-agents when Loki is unconfigured or down, and a partial
//! scan must never be mistaken for the fleet view. `search` has no
//! fallback — a scan cannot answer a fleet query honestly — and returns 503
//! with the reason instead.

use chrono::{DateTime, Duration, SecondsFormat, TimeZone, Utc};
use serde_json::{json, Value};

/// Hard ceiling on lines per answer, above `limit` in the body.
pub const MAX_LIMIT: usize = 2000;
pub const DEFAULT_LIMIT: usize = 200;
/// Hard ceiling on the time range, whoever asked.
pub const MAX_RANGE: Duration = Duration::days(7);
/// The window when the caller gives neither `since` nor `minutes`.
pub const DEFAULT_SINCE: Duration = Duration::hours(1);
pub const LOKI_QUERY_TIMEOUT_SECS: u64 = 30;

pub const LEVELS: &[&str] = &["debug", "info", "warn", "error", "unknown"];
pub const SOURCES: &[&str] = &["docker", "journal", "self", "file"];

/// What a caller may ask for. Every field optional; see [`build`].
#[derive(Debug, Default, Clone)]
pub struct SearchSpec {
    /// Explicit LogQL — passed through (an operator's own query).
    pub query: Option<String>,
    /// Free text — becomes a `|=` line filter.
    pub text: Option<String>,
    pub node: Option<String>,
    /// Exact `name` label (container without its `noo-` prefix, or unit).
    pub name: Option<String>,
    /// Substring of `name` — the pre-Loki `container` contract.
    pub name_contains: Option<String>,
    pub source: Option<String>,
    /// One level or several comma-separated: `error,warn`.
    pub level: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<i64>,
    pub direction: Option<String>,
}

/// The LogQL the gateway will send, with its bounds resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltQuery {
    pub logql: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub limit: usize,
    pub direction: &'static str,
    /// The range was wider than [`MAX_RANGE`] and `start` was moved.
    pub range_clamped: bool,
}

/// Escape a value for a LogQL double-quoted string (label matcher or
/// line filter): `\` and `"` are the two characters that can end the
/// string; newlines cannot appear in a selector at all.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a value so it matches itself inside a `=~` regex, then quote it.
fn quote_regex_literal(s: &str) -> String {
    let mut lit = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        if r"\.+*?()|[]{}^$".contains(ch) {
            lit.push('\\');
        }
        lit.push(ch);
    }
    quote(&lit)
}

/// `30m`, `2h`, `1d`, `45s`, `-15m` (the sign is ignored — a duration is
/// always "ago"), or an RFC 3339 timestamp.
pub fn parse_time(s: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty time".into());
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    let body = s.trim_start_matches('-');
    let (num, unit) = body.split_at(body.trim_end_matches(|c: char| c.is_ascii_alphabetic()).len());
    let n: i64 = num.trim().parse().map_err(|_| format!("bad time {s:?}: want 30m, 2h, 1d or RFC 3339"))?;
    if n < 0 {
        return Err(format!("bad time {s:?}: negative"));
    }
    let d = match unit {
        "s" | "sec" | "secs" => Duration::seconds(n),
        "m" | "min" | "mins" => Duration::minutes(n),
        "h" | "hr" | "hrs" => Duration::hours(n),
        "d" | "day" | "days" => Duration::days(n),
        "" => Duration::minutes(n),
        _ => return Err(format!("bad time {s:?}: unit must be s, m, h or d")),
    };
    Ok(now - d)
}

fn validated(field: &str, value: &str, allowed: &[&str]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let low = part.to_ascii_lowercase();
        // The level matcher is `debug|info|warn|error|unknown`; `warning` is
        // what people type.
        let low = if field == "level" && low == "warning" { "warn".to_string() } else { low };
        if !allowed.contains(&low.as_str()) {
            return Err(format!("{field} must be one of {}; got {part:?}", allowed.join("|")));
        }
        if !out.contains(&low) {
            out.push(low);
        }
    }
    Ok(out)
}

fn label_matcher(label: &str, values: &[String]) -> String {
    if values.len() == 1 {
        format!("{label}={}", quote(&values[0]))
    } else {
        format!("{label}=~{}", quote(&values.join("|")))
    }
}

/// Build the LogQL and its bounds. Pure; `now` is passed so a test can pin
/// the arithmetic.
pub fn build(spec: &SearchSpec, now: DateTime<Utc>) -> Result<BuiltQuery, String> {
    let end = match spec.until.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) => parse_time(u, now)?,
        None => now,
    };
    let mut start = match spec.since.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_time(s, now)?,
        None => end - DEFAULT_SINCE,
    };
    if start >= end {
        return Err(format!(
            "since ({}) must be before until ({})",
            start.to_rfc3339_opts(SecondsFormat::Secs, true),
            end.to_rfc3339_opts(SecondsFormat::Secs, true)
        ));
    }
    let mut range_clamped = false;
    if end - start > MAX_RANGE {
        start = end - MAX_RANGE;
        range_clamped = true;
    }
    let limit = match spec.limit {
        None => DEFAULT_LIMIT,
        Some(n) if n < 1 => 1,
        Some(n) => (n as usize).min(MAX_LIMIT),
    };
    let direction = match spec.direction.as_deref().map(str::trim) {
        None | Some("") | Some("backward") => "backward",
        Some("forward") => "forward",
        Some(other) => return Err(format!("direction must be forward or backward; got {other:?}")),
    };

    let logql = match spec.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        Some(raw) => {
            if raw.contains('\n') || raw.len() > 4096 {
                return Err("query: one line, at most 4096 bytes".into());
            }
            raw.to_string()
        }
        None => {
            let mut matchers: Vec<String> = Vec::new();
            if let Some(v) = spec.node.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                matchers.push(format!("node={}", quote(v)));
            }
            if let Some(v) = spec.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                matchers.push(format!("name={}", quote(v)));
            } else if let Some(v) = spec.name_contains.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                let lit = quote_regex_literal(v);
                // `=~` is anchored in Loki; `.*x.*` is "contains".
                matchers.push(format!("name=~\"(?i).*{}.*\"", &lit[1..lit.len() - 1]));
            }
            if let Some(v) = spec.source.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                matchers.push(label_matcher("source", &validated("source", v, SOURCES)?));
            }
            if let Some(v) = spec.level.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                matchers.push(label_matcher("level", &validated("level", v, LEVELS)?));
            }
            if matchers.is_empty() {
                // Loki refuses an empty selector; every shipped stream has a
                // verified node.
                matchers.push("node=~\".+\"".to_string());
            }
            let mut q = format!("{{{}}}", matchers.join(", "));
            if let Some(t) = spec.text.as_deref().filter(|s| !s.trim().is_empty()) {
                q.push_str(" |= ");
                q.push_str(&quote(t));
            }
            q
        }
    };

    Ok(BuiltQuery { logql, start, end, limit, direction, range_clamped })
}

/// One line as the three doors show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub ts_ns: i64,
    pub node: String,
    pub name: String,
    pub source: String,
    pub level: String,
    pub line: String,
}

impl Line {
    pub fn ts_rfc3339(&self) -> String {
        Utc.timestamp_nanos(self.ts_ns).to_rfc3339_opts(SecondsFormat::Millis, true)
    }
    pub fn to_json(&self) -> Value {
        json!({
            "ts": self.ts_rfc3339(),
            "node": self.node,
            "name": self.name,
            "source": self.source,
            "level": self.level,
            "line": self.line,
        })
    }
}

/// What asking Loki came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LokiOutcome {
    /// Loki answered; lines ordered per `direction`, at most `limit`.
    Lines(Vec<Line>),
    /// Loki refused the query (4xx): the query is wrong, not Loki.
    Refused(String),
    /// Unconfigured, unreachable, timed out or 5xx.
    Down(String),
}

/// Parse a `query_range` body (`data.resultType == "streams"`).
pub fn parse_query_range(body: &str, direction: &str) -> Result<Vec<Line>, String> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("Loki answered non-JSON: {e}"))?;
    if v.get("status").and_then(Value::as_str) != Some("success") {
        return Err(format!(
            "Loki answered {}",
            v.get("error").and_then(Value::as_str).unwrap_or("an unsuccessful status")
        ));
    }
    let data = v.get("data").ok_or("Loki answer had no `data`")?;
    if let Some(rt) = data.get("resultType").and_then(Value::as_str) {
        if rt != "streams" {
            return Err(format!("Loki answered {rt}, not streams: a metric query is not a log search"));
        }
    }
    let Some(result) = data.get("result").and_then(Value::as_array) else {
        return Err("Loki answer had no `data.result` array".into());
    };
    let mut lines = Vec::new();
    for stream in result {
        let labels = stream.get("stream").and_then(Value::as_object);
        let label = |k: &str| -> String {
            labels
                .and_then(|m| m.get(k))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let (node, name, source, level) = (label("node"), label("name"), label("source"), label("level"));
        for pair in stream.get("values").and_then(Value::as_array).into_iter().flatten() {
            let ts_ns = pair
                .get(0)
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let text = pair.get(1).and_then(Value::as_str).unwrap_or("").to_string();
            lines.push(Line {
                ts_ns,
                node: node.clone(),
                name: name.clone(),
                source: source.clone(),
                level: level.clone(),
                line: text,
            });
        }
    }
    // Loki orders within a stream; across streams the merge is ours.
    if direction == "forward" {
        lines.sort_by_key(|l| l.ts_ns);
    } else {
        lines.sort_by_key(|l| std::cmp::Reverse(l.ts_ns));
    }
    Ok(lines)
}

/// `GET {loki_url}/loki/api/v1/query_range`. The caller passes the client
/// so a test can aim it at a local listener; the empty URL is "unconfigured".
pub async fn query_loki(client: &reqwest::Client, loki_url: &str, q: &BuiltQuery) -> LokiOutcome {
    let loki_url = loki_url.trim();
    if loki_url.is_empty() {
        return LokiOutcome::Down("Loki is not configured on this controller (NOO_LOKI_URL)".into());
    }
    let url = format!(
        "{}/loki/api/v1/query_range?query={}&limit={}&start={}&end={}&direction={}",
        loki_url.trim_end_matches('/'),
        urlencoding::encode(&q.logql),
        q.limit,
        q.start.timestamp_nanos_opt().unwrap_or(0),
        q.end.timestamp_nanos_opt().unwrap_or(0),
        q.direction,
    );
    let sent = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(LOKI_QUERY_TIMEOUT_SECS))
        .send()
        .await;
    match sent {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            match parse_query_range(&body, q.direction) {
                Ok(mut lines) => {
                    lines.truncate(q.limit);
                    LokiOutcome::Lines(lines)
                }
                Err(e) => LokiOutcome::Down(e),
            }
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text: String = resp.text().await.unwrap_or_default().chars().take(500).collect();
            if (400..500).contains(&status) {
                LokiOutcome::Refused(format!("Loki refused the query: {status} {text}"))
            } else {
                LokiOutcome::Down(format!("Loki answered {status} {text}"))
            }
        }
        Err(e) if e.is_timeout() => LokiOutcome::Down(format!("Loki timed out after {LOKI_QUERY_TIMEOUT_SECS}s")),
        Err(e) => LokiOutcome::Down(format!("Loki unreachable: {e}")),
    }
}

/// Ask Loki with the gateway's own leaf and the configured URL.
pub async fn query_configured_loki(q: &BuiltQuery) -> LokiOutcome {
    let loki_url = crate::config::env_or_yaml("NOO_LOKI_URL", |c| c.services.loki_url.clone(), "");
    query_loki(&crate::tls::cluster_client(), &loki_url, q).await
}

/// The bounds and provenance every Loki-backed answer carries.
pub fn loki_envelope(q: &BuiltQuery, lines: &[Line]) -> Value {
    json!({
        "backend": "loki",
        "query": q.logql,
        "start": q.start.to_rfc3339_opts(SecondsFormat::Secs, true),
        "end": q.end.to_rfc3339_opts(SecondsFormat::Secs, true),
        "limit": q.limit,
        "count": lines.len(),
        "truncated": lines.len() >= q.limit,
        "range_clamped": q.range_clamped,
    })
}

/// Whether `errors` / `tail` may fall back to the node-agent scan, and the
/// reason the caller will read. Only "Loki is not there" qualifies: a
/// refused query is a wrong query, and a scan would answer a different
/// question under the same name.
pub fn fallback_reason(outcome: &LokiOutcome) -> Option<String> {
    match outcome {
        LokiOutcome::Down(reason) => Some(reason.clone()),
        LokiOutcome::Lines(_) | LokiOutcome::Refused(_) => None,
    }
}

/// Mark a node-agent scan answer as such. `reason` is why Loki did not
/// answer; it is the operator's cue that this is a partial view.
pub fn fallback_envelope(mut answer: Value, reason: &str) -> Value {
    if let Some(obj) = answer.as_object_mut() {
        obj.insert("backend".into(), json!("agent-scan"));
        obj.insert("loki_error".into(), json!(reason));
    }
    answer
}

/// Merge the envelope fields into an answer.
pub fn merge(mut answer: Value, envelope: Value) -> Value {
    if let (Some(a), Some(e)) = (answer.as_object_mut(), envelope.as_object()) {
        for (k, v) in e {
            a.insert(k.clone(), v.clone());
        }
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 28, 15, 0, 0).unwrap()
    }

    fn spec() -> SearchSpec {
        SearchSpec::default()
    }

    // ── the LogQL builder ──

    #[test]
    fn labels_become_exact_matchers_in_a_fixed_order() {
        let q = build(
            &SearchSpec {
                node: Some("host3".into()),
                name: Some("gateway".into()),
                source: Some("docker".into()),
                level: Some("error".into()),
                ..spec()
            },
            now(),
        )
        .unwrap();
        assert_eq!(q.logql, r#"{node="host3", name="gateway", source="docker", level="error"}"#);
    }

    #[test]
    fn several_levels_become_one_regex_matcher_and_warning_is_warn() {
        let q = build(&SearchSpec { level: Some("error, warning".into()), ..spec() }, now()).unwrap();
        assert_eq!(q.logql, r#"{level=~"error|warn"}"#);
    }

    #[test]
    fn a_level_or_source_outside_the_vocabulary_is_refused() {
        let e = build(&SearchSpec { level: Some("critical".into()), ..spec() }, now()).unwrap_err();
        assert!(e.contains("level must be one of debug|info|warn|error|unknown"), "{e}");
        let e = build(&SearchSpec { source: Some("syslog".into()), ..spec() }, now()).unwrap_err();
        assert!(e.contains("source must be one of docker|journal|self|file"), "{e}");
    }

    #[test]
    fn no_labels_means_every_verified_node() {
        let q = build(&spec(), now()).unwrap();
        assert_eq!(q.logql, r#"{node=~".+"}"#);
    }

    #[test]
    fn free_text_is_a_line_filter_that_cannot_open_a_pipeline_stage() {
        // `"`, `\` and `|` in the text: the quote and the backslash are
        // escaped so the string cannot close; the pipe stays INSIDE the
        // string, so `| json` is text, not a stage.
        let q = build(&SearchSpec { text: Some(r#"say "hi" \ then | json"#.into()), ..spec() }, now()).unwrap();
        assert_eq!(q.logql, r#"{node=~".+"} |= "say \"hi\" \\ then | json""#);
        assert_eq!(q.logql.matches("|=").count(), 1);
        assert!(!q.logql.contains("\" | json"), "the pipe escaped the string: {}", q.logql);
    }

    #[test]
    fn a_label_value_cannot_break_out_of_its_matcher() {
        let q = build(&SearchSpec { node: Some(r#"a"} |= "x"#.into()), ..spec() }, now()).unwrap();
        assert_eq!(q.logql, r#"{node="a\"} |= \"x"}"#);
        assert!(!q.logql.contains(r#"a"}"#), "an unescaped quote closed the matcher: {}", q.logql);
    }

    #[test]
    fn a_container_substring_is_an_anchored_contains_regex_with_metachars_escaped() {
        let q = build(&SearchSpec { name_contains: Some("noo-gate.way".into()), ..spec() }, now()).unwrap();
        assert_eq!(q.logql, r#"{name=~"(?i).*noo-gate\\.way.*"}"#);
    }

    #[test]
    fn name_wins_over_the_substring_form() {
        let q = build(
            &SearchSpec { name: Some("gateway".into()), name_contains: Some("gate".into()), ..spec() },
            now(),
        )
        .unwrap();
        assert_eq!(q.logql, r#"{name="gateway"}"#);
    }

    // ── time ──

    #[test]
    fn since_accepts_durations_and_rfc3339() {
        let n = now();
        assert_eq!(parse_time("30m", n).unwrap(), n - Duration::minutes(30));
        assert_eq!(parse_time("-15m", n).unwrap(), n - Duration::minutes(15));
        assert_eq!(parse_time("2h", n).unwrap(), n - Duration::hours(2));
        assert_eq!(parse_time("1d", n).unwrap(), n - Duration::days(1));
        assert_eq!(parse_time("45s", n).unwrap(), n - Duration::seconds(45));
        assert_eq!(parse_time("15", n).unwrap(), n - Duration::minutes(15), "bare number = minutes");
        assert_eq!(
            parse_time("2026-09-28T14:02:00Z", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 28, 14, 2, 0).unwrap()
        );
        assert_eq!(
            parse_time("2026-09-28T16:02:00+02:00", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 28, 14, 2, 0).unwrap()
        );
        assert!(parse_time("yesterday", n).is_err());
        assert!(parse_time("3w", n).is_err());
        assert!(parse_time("", n).is_err());
    }

    #[test]
    fn what_happened_on_host3_at_14_02() {
        let q = build(
            &SearchSpec {
                node: Some("host3".into()),
                since: Some("2026-09-28T14:00:00Z".into()),
                until: Some("2026-09-28T14:05:00Z".into()),
                direction: Some("forward".into()),
                ..spec()
            },
            now(),
        )
        .unwrap();
        assert_eq!(q.logql, r#"{node="host3"}"#);
        assert_eq!(q.start, Utc.with_ymd_and_hms(2026, 9, 28, 14, 0, 0).unwrap());
        assert_eq!(q.end, Utc.with_ymd_and_hms(2026, 9, 28, 14, 5, 0).unwrap());
        assert_eq!(q.direction, "forward");
        assert!(!q.range_clamped);
    }

    #[test]
    fn default_window_is_an_hour_ending_now() {
        let q = build(&spec(), now()).unwrap();
        assert_eq!(q.end, now());
        assert_eq!(q.start, now() - Duration::hours(1));
    }

    #[test]
    fn since_after_until_is_refused() {
        let e = build(&SearchSpec { since: Some("1m".into()), until: Some("2h".into()), ..spec() }, now())
            .unwrap_err();
        assert!(e.contains("must be before"), "{e}");
    }

    #[test]
    fn a_range_wider_than_seven_days_is_clamped_and_said() {
        let q = build(&SearchSpec { since: Some("30d".into()), ..spec() }, now()).unwrap();
        assert_eq!(q.end - q.start, MAX_RANGE);
        assert!(q.range_clamped);
        // An explicit raw query gets the same clamp.
        let q = build(&SearchSpec { query: Some("{node=\"x\"}".into()), since: Some("400d".into()), ..spec() }, now())
            .unwrap();
        assert_eq!(q.end - q.start, MAX_RANGE);
        assert!(q.range_clamped);
    }

    // ── limits ──

    #[test]
    fn limit_is_capped_for_built_and_for_raw_queries() {
        let q = build(&SearchSpec { limit: Some(999_999), ..spec() }, now()).unwrap();
        assert_eq!(q.limit, MAX_LIMIT);
        let q = build(&SearchSpec { query: Some("{node=\"host3\"}".into()), limit: Some(999_999), ..spec() }, now())
            .unwrap();
        assert_eq!(q.limit, MAX_LIMIT, "an explicit LogQL still cannot ask for a million lines");
        let q = build(&SearchSpec { limit: Some(0), ..spec() }, now()).unwrap();
        assert_eq!(q.limit, 1);
        let q = build(&spec(), now()).unwrap();
        assert_eq!(q.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn raw_query_passes_through_unchanged_and_ignores_the_label_fields() {
        let raw = r#"{compose_service="gateway"} |= "backend_resolved""#;
        let q = build(&SearchSpec { query: Some(raw.into()), node: Some("host3".into()), ..spec() }, now())
            .unwrap();
        assert_eq!(q.logql, raw);
        assert!(build(&SearchSpec { query: Some("{a=\"b\"}\n{c=\"d\"}".into()), ..spec() }, now()).is_err());
    }

    #[test]
    fn direction_is_validated() {
        assert_eq!(build(&spec(), now()).unwrap().direction, "backward");
        assert!(build(&SearchSpec { direction: Some("sideways".into()), ..spec() }, now()).is_err());
    }

    // ── Loki answers ──

    const ANSWER: &str = r#"{"status":"success","data":{"resultType":"streams","result":[
      {"stream":{"node":"host3","name":"vllm","source":"docker","level":"error"},
       "values":[["1790000000000000000","CUDA error: device-side assert"],["1789999990000000000","earlier"]]},
      {"stream":{"node":"host8","name":"gateway","source":"docker","level":"warn"},
       "values":[["1790000005000000000","upstream 502"]]}
    ]}}"#;

    #[test]
    fn streams_are_flattened_and_merged_by_time() {
        let lines = parse_query_range(ANSWER, "backward").unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].node, "host8");
        assert_eq!(lines[0].line, "upstream 502");
        assert_eq!(lines[2].line, "earlier");
        let fwd = parse_query_range(ANSWER, "forward").unwrap();
        assert_eq!(fwd[0].line, "earlier");
        assert_eq!(fwd[2].line, "upstream 502");
        let j = lines[1].to_json();
        assert_eq!(j["node"], "host3");
        assert_eq!(j["name"], "vllm");
        assert_eq!(j["level"], "error");
        assert_eq!(j["ts"], "2026-09-21T14:13:20.000Z");
    }

    #[test]
    fn a_metric_or_failed_answer_is_an_error_not_an_empty_result() {
        assert!(parse_query_range(r#"{"status":"error","error":"parse error"}"#, "backward")
            .unwrap_err()
            .contains("parse error"));
        assert!(parse_query_range(r#"{"status":"success","data":{"resultType":"matrix","result":[]}}"#, "backward")
            .unwrap_err()
            .contains("metric"));
        assert!(parse_query_range("<html>", "backward").is_err());
        assert!(parse_query_range(r#"{"status":"success","data":{"resultType":"streams","result":[]}}"#, "backward")
            .unwrap()
            .is_empty());
    }

    /// A listener that answers one request with `status` and `body`, and
    /// hands back what it was sent.
    async fn one_shot_loki(status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                if n == 0 || String::from_utf8_lossy(&got).contains("\r\n\r\n") {
                    break;
                }
            }
            let reason = match status { 200 => "OK", 400 => "Bad Request", _ => "Server Error" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
            String::from_utf8_lossy(&got).to_string()
        });
        (url, handle)
    }

    #[tokio::test]
    async fn loki_is_asked_with_the_built_query_and_its_bounds() {
        let q = build(
            &SearchSpec { node: Some("host3".into()), level: Some("error,warn".into()), limit: Some(50), ..spec() },
            now(),
        )
        .unwrap();
        let (url, srv) = one_shot_loki(200, ANSWER).await;
        let got = query_loki(&reqwest::Client::new(), &url, &q).await;
        let seen = srv.await.unwrap();
        let first = seen.lines().next().unwrap().to_string();
        assert!(first.starts_with("GET /loki/api/v1/query_range?query="), "{first}");
        assert!(first.contains(&format!("query={}", urlencoding::encode(&q.logql))), "{first}");
        assert!(first.contains("&limit=50&"), "{first}");
        assert!(first.contains(&format!("&start={}&end={}&direction=backward", q.start.timestamp_nanos_opt().unwrap(), q.end.timestamp_nanos_opt().unwrap())), "{first}");
        let LokiOutcome::Lines(lines) = got else { panic!("{got:?}") };
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].node, "host8");
    }

    #[tokio::test]
    async fn the_limit_holds_after_the_merge() {
        let q = build(&SearchSpec { limit: Some(2), ..spec() }, now()).unwrap();
        let (url, srv) = one_shot_loki(200, ANSWER).await;
        let got = query_loki(&reqwest::Client::new(), &url, &q).await;
        srv.await.unwrap();
        let LokiOutcome::Lines(lines) = got else { panic!("{got:?}") };
        assert_eq!(lines.len(), 2, "three arrived, two were asked for");
        let env = loki_envelope(&q, &lines);
        assert_eq!(env["backend"], "loki");
        assert_eq!(env["truncated"], true);
        assert_eq!(env["count"], 2);
        assert_eq!(env["query"], q.logql);
    }

    #[tokio::test]
    async fn loki_down_or_unconfigured_is_down_and_a_bad_query_is_refused() {
        let q = build(&spec(), now()).unwrap();
        let client = reqwest::Client::new();
        let got = query_loki(&client, "", &q).await;
        assert!(matches!(got, LokiOutcome::Down(ref r) if r.contains("NOO_LOKI_URL")), "{got:?}");
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            drop(l);
            url
        };
        let got = query_loki(&client, &dead, &q).await;
        assert!(matches!(got, LokiOutcome::Down(_)), "{got:?}");
        let (url, srv) = one_shot_loki(500, "boom").await;
        let got = query_loki(&client, &url, &q).await;
        srv.await.unwrap();
        assert_eq!(got, LokiOutcome::Down("Loki answered 500 boom".into()));
        let (url, srv) = one_shot_loki(400, "parse error at line 1").await;
        let got = query_loki(&client, &url, &q).await;
        srv.await.unwrap();
        assert!(matches!(got, LokiOutcome::Refused(ref r) if r.contains("parse error")), "{got:?}");
    }

    // ── the fallback contract ──

    #[test]
    fn the_scan_is_the_fallback_only_when_loki_is_not_there() {
        assert!(fallback_reason(&LokiOutcome::Down("Loki unreachable".into())).is_some());
        assert!(fallback_reason(&LokiOutcome::Lines(vec![])).is_none(), "an empty answer is an answer");
        assert!(
            fallback_reason(&LokiOutcome::Refused("bad query".into())).is_none(),
            "a refused query is not a reason to answer a different question"
        );
    }

    #[test]
    fn a_fallback_answer_names_its_backend_and_why() {
        let answered = fallback_envelope(json!({"matches": [], "scanned": 3}), "Loki unreachable: connect refused");
        assert_eq!(answered["backend"], "agent-scan", "a partial scan must not pass for the fleet view");
        assert_eq!(answered["loki_error"], "Loki unreachable: connect refused");
        assert_eq!(answered["scanned"], 3, "the scan's own fields survive");
        let q = build(&spec(), now()).unwrap();
        let merged = merge(json!({"matches": []}), loki_envelope(&q, &[]));
        assert_eq!(merged["backend"], "loki");
        assert_eq!(merged["truncated"], false);
    }
}
