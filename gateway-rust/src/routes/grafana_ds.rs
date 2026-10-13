// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Grafana's Prometheus and Loki data sources, through the gateway, with the
//! viewing person's tier enforced on every query.
//!
//! In open-source Grafana every org member holds `datasources:query` on
//! every data source, so a Viewer can `POST /api/ds/query` with any PromQL
//! or LogQL it likes. No Grafana OSS setting closes that, and the gateway
//! keeps `/api/metrics/query` and `/api/logs/*` operator-only. So the data
//! sources point HERE (`configs/grafana/datasources/*.yml`), and the gateway
//! decides per query.
//!
//! ## Who is asking
//!
//! Only Grafana's own service leaf (`CN=grafana, O=Mesh Cluster Service`,
//! verified at the TLS handshake — `node_identity::VerifiedService`) opens
//! these routes; no bearer token does. On that connection, and only there,
//! `X-Grafana-User` is Grafana's word for the signed-in person: measured on
//! Grafana 12.4.11, Grafana sets it from the session on every
//! route that reaches a data source (`/api/ds/query`, server-side
//! expressions, `/resources/…`, the legacy `/api/datasources/proxy/…`),
//! with JWT logins too (`X-Grafana-User` = the token's `sub`), and REPLACES
//! a value the browser sent. Every other `X-*` header can be the
//! browser's: `X-Dashboard-Uid` and `X-Panel-Id` pass through from the
//! caller on every route, so nothing here keys on them. A request with no
//! `X-Grafana-User` is Grafana acting on its own (a Grafana-managed alert
//! rule's evaluation carries `X-Rule-*` and no user), and gets the
//! read-only policy.
//!
//! ## What each tier may run
//!
//! The tier is the LIVE `noo_users` row for that login, resolved like the
//! Grafana session itself (role column, raised by admin/operator scopes);
//! a disabled or missing account is refused, so a disable bites within
//! [`TIER_TTL`] rather than at the end of a 15-minute Grafana token.
//!
//! * Operator, Admin: the read APIs ([`operator_allows`]). Never an admin,
//!   write, push, delete or tail endpoint.
//! * User (Grafana Viewer), and Grafana with no user: exactly the
//!   provisioned dashboards' own queries ([`viewer_allows`]) — a query
//!   string byte-for-byte one of their panel expressions, or one of their
//!   template variables' label-value lists. No Loki at all. The list is
//!   compiled from `configs/grafana/dashboards/*.json`, never Grafana's
//!   database, so a panel added in the UI widens nothing.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde_json::{json, Value};

use crate::auth::Role;
use crate::node_identity::VerifiedService;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/grafana-ds/prometheus/{*path}", get(prometheus).post(prometheus))
        .route("/api/grafana-ds/loki/{*path}", get(loki).post(loki))
}

/// The provisioned dashboards whose queries a read-only person may run.
/// Every file in `configs/grafana/dashboards/` is listed here;
/// `tests/test_grafana_ds_allowlist_parity.py` fails when one is not, and
/// `docker/Dockerfile.gateway-rust` copies each into the build context.
const DASHBOARDS: &[(&str, &str)] = &[(
    "cluster-overview.json",
    include_str!("../../../configs/grafana/dashboards/cluster-overview.json"),
)];

/// The one data source behind each route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upstream {
    Prometheus,
    Loki,
}

impl Upstream {
    fn name(self) -> &'static str {
        match self {
            Upstream::Prometheus => "prometheus",
            Upstream::Loki => "loki",
        }
    }
}

/// What the provisioned dashboards read: their panel expressions, and their
/// template variables as `(label, match[] selector)` pairs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Allowlist {
    pub exprs: BTreeSet<String>,
    pub label_values: BTreeSet<(String, String)>,
    /// Panel expressions that use a template variable. An exact-match list
    /// cannot express them (the value is the viewer's to choose), so they
    /// are NOT allowed; a test fails while any exists.
    pub templated: BTreeSet<String>,
}

fn is_prometheus_ds(ds: &Value) -> bool {
    ds.get("uid").and_then(Value::as_str) == Some("prometheus")
        || ds.get("type").and_then(Value::as_str) == Some("prometheus")
}

fn walk_panels<'a>(panels: &'a [Value], out: &mut Vec<&'a Value>) {
    for p in panels {
        out.push(p);
        if let Some(Value::Array(inner)) = p.get("panels") {
            walk_panels(inner, out);
        }
    }
}

/// `label_values(<metric>, <label>)` → `(label, metric)`.
fn parse_label_values(q: &str) -> Option<(String, String)> {
    let inner = q.trim().strip_prefix("label_values(")?.strip_suffix(')')?;
    let (metric, label) = inner.rsplit_once(',')?;
    let (metric, label) = (metric.trim(), label.trim());
    (is_label_name(label) && !metric.is_empty() && !metric.contains('$'))
        .then(|| (label.to_string(), metric.to_string()))
}

/// Read one dashboard's Prometheus queries into `into`.
pub fn collect_dashboard(json_text: &str, into: &mut Allowlist) -> Result<(), String> {
    let d: Value = serde_json::from_str(json_text).map_err(|e| format!("not JSON: {e}"))?;
    let mut panels = Vec::new();
    if let Some(Value::Array(top)) = d.get("panels") {
        walk_panels(top, &mut panels);
    }
    for p in panels {
        let panel_ds = p.get("datasource").map(is_prometheus_ds).unwrap_or(false);
        for t in p.get("targets").and_then(Value::as_array).into_iter().flatten() {
            let prom = t.get("datasource").map(is_prometheus_ds).unwrap_or(panel_ds);
            let Some(expr) = t.get("expr").and_then(Value::as_str) else { continue };
            let expr = expr.trim();
            if !prom || expr.is_empty() {
                continue;
            }
            if expr.contains('$') {
                into.templated.insert(expr.to_string());
            } else {
                into.exprs.insert(expr.to_string());
            }
        }
    }
    for v in d.pointer("/templating/list").and_then(Value::as_array).into_iter().flatten() {
        if v.get("type").and_then(Value::as_str) != Some("query") {
            continue;
        }
        if !v.get("datasource").map(is_prometheus_ds).unwrap_or(false) {
            continue;
        }
        let q = v
            .pointer("/query/query")
            .and_then(Value::as_str)
            .or_else(|| v.get("query").and_then(Value::as_str))
            .or_else(|| v.get("definition").and_then(Value::as_str));
        if let Some(pair) = q.and_then(parse_label_values) {
            into.label_values.insert(pair);
        }
    }
    Ok(())
}

/// The compiled-in list, built once.
pub fn allowlist() -> &'static Allowlist {
    static LIST: OnceLock<Allowlist> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut a = Allowlist::default();
        for (name, text) in DASHBOARDS {
            if let Err(e) = collect_dashboard(text, &mut a) {
                // Compiled in and tested; a bad file means an EMPTY list
                // (everything refused to a viewer), never a wider one.
                tracing::error!(dashboard = name, "grafana_ds_allowlist_unreadable: {e}");
            }
        }
        a
    })
}

fn is_label_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// A sub-path we are willing to put in an upstream URL at all.
fn is_clean_subpath(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains("//")
        && p.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'))
}

const PROM_READS: &[&str] = &[
    "api/v1/query",
    "api/v1/query_range",
    "api/v1/query_exemplars",
    "api/v1/series",
    "api/v1/labels",
    "api/v1/metadata",
    "api/v1/status/buildinfo",
    "api/v1/format_query",
];

const LOKI_READS: &[&str] = &[
    "loki/api/v1/query",
    "loki/api/v1/query_range",
    "loki/api/v1/labels",
    "loki/api/v1/series",
    "loki/api/v1/index/stats",
    "loki/api/v1/index/volume",
    "loki/api/v1/index/volume_range",
    "loki/api/v1/detected_fields",
    "loki/api/v1/detected_labels",
    "loki/api/v1/patterns",
    "loki/api/v1/status/buildinfo",
];

/// `<prefix><label>/values` → the label.
fn label_values_path<'a>(p: &'a str, prefix: &str) -> Option<&'a str> {
    let label = p.strip_prefix(prefix)?.strip_suffix("/values")?;
    is_label_name(label).then_some(label)
}

/// Operator and Admin: the read APIs, nothing that writes, deletes,
/// administers or streams.
pub fn operator_allows(up: Upstream, path: &str) -> Result<(), String> {
    let ok = match up {
        Upstream::Prometheus => {
            PROM_READS.contains(&path) || label_values_path(path, "api/v1/label/").is_some()
        }
        Upstream::Loki => LOKI_READS.contains(&path) || label_values_path(path, "loki/api/v1/label/").is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{} read API only: /{path} is not one of them", up.name()))
    }
}

/// Parameters a viewer's query may carry besides the query itself. An
/// unknown key is refused rather than forwarded unread.
const VIEWER_QUERY_PARAMS: &[&str] = &["query", "time", "start", "end", "step", "timeout", "limit"];
const VIEWER_LABEL_PARAMS: &[&str] = &["match[]", "start", "end", "limit"];

fn only_one<'a>(params: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    let mut it = params.iter().filter(|(k, _)| k == key);
    match (it.next(), it.next()) {
        (Some((_, v)), None) => Ok(v.as_str()),
        (None, _) => Err(format!("`{key}` is required")),
        _ => Err(format!("`{key}` given more than once")),
    }
}

fn known_keys(params: &[(String, String)], allowed: &[&str]) -> Result<(), String> {
    match params.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        Some((k, _)) => Err(format!("parameter `{k}` is not one a dashboard sends")),
        None => Ok(()),
    }
}

/// The read-only tier, and Grafana acting with no user: the provisioned
/// dashboards' own queries, exactly. No Loki.
pub fn viewer_allows(list: &Allowlist, up: Upstream, path: &str, params: &[(String, String)]) -> Result<(), String> {
    if up == Upstream::Loki {
        return Err("logs are operator-only; no read-only dashboard reads Loki".into());
    }
    match path {
        "api/v1/status/buildinfo" => Ok(()),
        "api/v1/query" | "api/v1/query_range" => {
            known_keys(params, VIEWER_QUERY_PARAMS)?;
            let q = only_one(params, "query")?.trim();
            if list.exprs.contains(q) {
                Ok(())
            } else {
                Err("only the provisioned dashboards' own queries run for a read-only account; this one is not among them".into())
            }
        }
        _ => {
            if let Some(label) = label_values_path(path, "api/v1/label/") {
                known_keys(params, VIEWER_LABEL_PARAMS)?;
                let m = only_one(params, "match[]")?.trim();
                if list.label_values.contains(&(label.to_string(), m.to_string())) {
                    return Ok(());
                }
                return Err(format!("label `{label}` for `{m}` is not a provisioned dashboard variable"));
            }
            Err(format!("/{path} is not open to a read-only account: dashboards' own queries only"))
        }
    }
}

/// THE decision. `tier` is `None` for Grafana acting with no user, which
/// gets the read-only policy.
pub fn grafana_ds_allows(
    list: &Allowlist,
    tier: Option<Role>,
    up: Upstream,
    method: &Method,
    path: &str,
    params: &[(String, String)],
) -> Result<(), String> {
    if *method != Method::GET && *method != Method::POST {
        return Err(format!("{method} is not a data-source read"));
    }
    if !is_clean_subpath(path) {
        return Err("malformed data-source path".into());
    }
    operator_allows(up, path)?;
    match tier {
        Some(r) if r >= Role::Operator => Ok(()),
        _ => viewer_allows(list, up, path, params),
    }
}

// ── Live tier ─────────────────────────────────────────────────────────

/// How long a login's tier is cached. A demotion or disable reaches the
/// data sources within this, not at the end of the Grafana token.
pub const TIER_TTL: Duration = Duration::from_secs(10);

static TIERS: OnceLock<RwLock<HashMap<String, (Option<Role>, Instant)>>> = OnceLock::new();

/// The tier a `noo_users` row grants, `None` for a disabled account. Same
/// resolution as the Grafana session (`monitoring::grafana_session`): the
/// role column raised by admin/operator scopes; an unparseable role column
/// reads as Admin, never as User — the column is the operator's to write.
pub fn tier_of_row(role_col: &str, scopes: &Value, disabled: bool) -> Option<Role> {
    if disabled {
        return None;
    }
    let from_col: Role = role_col.trim().parse().unwrap_or(Role::Admin);
    let list: Vec<String> = serde_json::from_value(scopes.clone()).unwrap_or_default();
    Some(from_col.max(Role::from_scopes(&list)))
}

/// The LIVE tier of a Grafana login. `Err` = refuse (no such account, a
/// disabled one, or a database that cannot answer — never read as a tier).
async fn live_tier(db: &sqlx::PgPool, login: &str) -> Result<Role, String> {
    let account = crate::auth::account_of(login).to_string();
    let cache = TIERS.get_or_init(|| RwLock::new(HashMap::new()));
    let cached = cache.read().ok().and_then(|m| m.get(&account).copied());
    let tier = match cached {
        Some((t, at)) if at.elapsed() < TIER_TTL => t,
        _ => {
            let row: Option<(String, Value, bool)> =
                sqlx::query_as("SELECT role, scopes, COALESCE(disabled, false) FROM noo_users WHERE username = $1")
                    .bind(&account)
                    .fetch_optional(db)
                    .await
                    .map_err(|e| {
                        tracing::warn!(account = %account, error = %e, "grafana_ds_tier_lookup_failed");
                        "the account could not be checked; refusing".to_string()
                    })?;
            let t = row.and_then(|(r, s, d)| tier_of_row(&r, &s, d));
            if let Ok(mut m) = cache.write() {
                if m.len() > 10_000 {
                    m.clear();
                }
                m.insert(account.clone(), (t, Instant::now()));
            }
            t
        }
    };
    tier.ok_or_else(|| format!("account '{account}' is disabled or does not exist"))
}

// ── Handlers ──────────────────────────────────────────────────────────

fn refuse(status: StatusCode, why: String) -> Response {
    (status, Json(json!({ "status": "error", "errorType": "forbidden", "error": why }))).into_response()
}

/// Query-string and form-body parameters, in order. Grafana's Prometheus
/// data source POSTs a form by default; Loki GETs.
fn params_of(uri: &Uri, headers: &HeaderMap, body: &Bytes) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = match uri.query() {
        Some(q) => serde_urlencoded::from_str(q).map_err(|e| format!("bad query string: {e}"))?,
        None => Vec::new(),
    };
    if !body.is_empty() {
        let form = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
        if !form {
            return Err("a POST body must be application/x-www-form-urlencoded".into());
        }
        let more: Vec<(String, String)> =
            serde_urlencoded::from_bytes(body).map_err(|e| format!("bad form body: {e}"))?;
        out.extend(more);
    }
    Ok(out)
}

/// `GET|POST /api/grafana-ds/prometheus/{*path}` — Grafana's Prometheus
/// data source, through the gateway. Grafana's service leaf
/// only; no bearer token opens it. Shaped as Prometheus's read API
/// (`api/v1/query`, `query_range`, `label/<name>/values`, …). The person in
/// `X-Grafana-User` is re-checked against the live account: an operator or
/// admin gets the read API, a read-only account (and Grafana with no user)
/// only the provisioned dashboards' own queries. 401 without Grafana's
/// leaf, 403 with a sentence for a refused query, 502 when Prometheus is
/// unreachable.
async fn prometheus(
    State(state): State<Arc<AppState>>,
    svc: Option<Extension<Option<VerifiedService>>>,
    Path(path): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    serve(&state, svc, Upstream::Prometheus, path, method, uri, headers, body).await
}

/// `GET|POST /api/grafana-ds/loki/{*path}` — Grafana's Loki data source,
/// through the gateway. Grafana's service leaf only. Shaped
/// as Loki's read API (`loki/api/v1/query_range`, `labels`, …): an operator
/// or admin gets it; a read-only account, and Grafana with no user, get
/// nothing — logs stay operator-only, as `/api/logs/*` does. Never push,
/// delete or tail.
async fn loki(
    State(state): State<Arc<AppState>>,
    svc: Option<Extension<Option<VerifiedService>>>,
    Path(path): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    serve(&state, svc, Upstream::Loki, path, method, uri, headers, body).await
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    state: &AppState,
    svc: Option<Extension<Option<VerifiedService>>>,
    up: Upstream,
    path: String,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The middleware already admitted only Grafana's leaf; asked again here
    // so the handler cannot be reached around it.
    let service = svc.and_then(|Extension(s)| s);
    let login = match crate::auth::grafana_ds_identity(service.as_ref(), &headers) {
        Ok(l) => l,
        Err(why) => return refuse(StatusCode::UNAUTHORIZED, why),
    };
    let tier = match &login {
        Some(l) => match live_tier(&state.db, l).await {
            Ok(t) => Some(t),
            Err(why) => {
                tracing::info!(login = %l, upstream = up.name(), "grafana_ds_refused: {why}");
                return refuse(StatusCode::FORBIDDEN, why);
            }
        },
        None => None,
    };
    let params = match params_of(&uri, &headers, &body) {
        Ok(p) => p,
        Err(why) => return refuse(StatusCode::BAD_REQUEST, why),
    };
    if let Err(why) = grafana_ds_allows(allowlist(), tier, up, &method, &path, &params) {
        tracing::info!(
            login = login.as_deref().unwrap_or("-"),
            tier = tier.map(|t| t.as_str()).unwrap_or("none"),
            upstream = up.name(),
            path = %path,
            "grafana_ds_refused: {why}"
        );
        return refuse(StatusCode::FORBIDDEN, why);
    }
    forward(up, &path, method, &uri, &headers, body).await
}

fn upstream_base(up: Upstream) -> String {
    match up {
        Upstream::Prometheus => crate::config::env_or_yaml(
            "NOO_PROMETHEUS_URL",
            |c| c.services.prometheus_url.clone(),
            "https://prometheus:9090",
        ),
        // Empty = Loki is not configured on this controller, the same
        // default the other Loki readers use; answered as a 502, not guessed.
        Upstream::Loki => crate::config::env_or_yaml("NOO_LOKI_URL", |c| c.services.loki_url.clone(), ""),
    }
}

/// Headers passed upstream. Nothing else the browser could have set goes
/// through: not `X-Grafana-User`, not `X-Dashboard-Uid`, not a cookie.
const FORWARDED_HEADERS: &[&str] = &["content-type", "accept", "x-loki-response-encoding-flags"];

async fn forward(up: Upstream, path: &str, method: Method, uri: &Uri, headers: &HeaderMap, body: Bytes) -> Response {
    let base = upstream_base(up);
    if base.trim().is_empty() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "status": "error", "errorType": "unavailable", "error": format!("{} is not configured on this controller", up.name()) })),
        )
            .into_response();
    }
    let mut url = format!("{}/{path}", base.trim_end_matches('/'));
    if let Some(q) = uri.query() {
        url.push('?');
        url.push_str(q);
    }
    let client = crate::tls::cluster_client();
    let mut req = client.request(method, &url).timeout(Duration::from_secs(60));
    for name in FORWARDED_HEADERS {
        if let Some(v) = headers.get(*name) {
            req = req.header(*name, v.clone());
        }
    }
    if !body.is_empty() {
        req = req.body(body);
    }
    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp.headers().get(reqwest::header::CONTENT_TYPE).cloned();
            let mut out = Response::new(Body::from_stream(resp.bytes_stream()));
            *out.status_mut() = status;
            if let Some(ct) = ct.and_then(|v| axum::http::HeaderValue::from_bytes(v.as_bytes()).ok()) {
                out.headers_mut().insert(axum::http::header::CONTENT_TYPE, ct);
            }
            out
        }
        Err(e) => {
            tracing::warn!(upstream = up.name(), error = %e, "grafana_ds_upstream_unreachable");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "status": "error", "errorType": "unavailable", "error": format!("{} unreachable", up.name()) })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn get() -> Method {
        Method::GET
    }

    /// The compiled list is the shipped dashboard's, and it is not empty —
    /// a list that parsed nothing would refuse every panel and look safe.
    #[test]
    fn the_allowlist_is_the_shipped_dashboards_queries() {
        let a = allowlist();
        assert!(a.exprs.len() >= 20, "{:?}", a.exprs);
        assert!(a.exprs.contains("noo_cluster_nodes_total"));
        assert!(a.exprs.contains("100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"));
        assert!(a.label_values.contains(&("node_id".into(), "noo_node_load".into())));
        assert!(a.label_values.contains(&("tier".into(), "noo_node_tier".into())));
    }

    /// The template-variable guard. A panel expression with a `$` is the
    /// viewer's to fill in (`?var-node_id=…`), so an exact list cannot hold
    /// it; it is left out (refused), and this fails until the matcher
    /// learns the variable's grammar.
    #[test]
    fn no_provisioned_panel_uses_a_template_variable() {
        assert!(
            allowlist().templated.is_empty(),
            "a provisioned panel uses a template variable: {:?} — teach viewer_allows the variable's value grammar \
             before shipping it, or a read-only account can inject PromQL through the variable",
            allowlist().templated
        );
        let mut a = Allowlist::default();
        let d = r#"{"panels":[{"datasource":{"uid":"prometheus"},"targets":[{"expr":"up{node=~\"$node_id\"}"}]}]}"#;
        collect_dashboard(d, &mut a).unwrap();
        assert!(a.exprs.is_empty() && a.templated.len() == 1, "{a:?}");
    }

    #[test]
    fn a_viewers_own_promql_is_refused() {
        let a = allowlist();
        for q in [
            "up",
            "secret_metric",
            "noo_cluster_nodes_total or vector(1)",
            "noo_cluster_nodes_total{job=\"x\"}",
            "{__name__=~\".+\"}",
        ] {
            for path in ["api/v1/query", "api/v1/query_range"] {
                let e = grafana_ds_allows(a, Some(Role::User), Upstream::Prometheus, &Method::POST, path, &p(&[("query", q)]))
                    .expect_err(q);
                assert!(e.contains("provisioned dashboards"), "{e}");
            }
        }
    }

    #[test]
    fn a_viewers_dashboard_panel_query_passes() {
        let a = allowlist();
        for q in &a.exprs {
            for path in ["api/v1/query", "api/v1/query_range"] {
                let params = p(&[("query", q.as_str()), ("start", "1"), ("end", "2"), ("step", "15")]);
                grafana_ds_allows(a, Some(Role::User), Upstream::Prometheus, &Method::POST, path, &params)
                    .unwrap_or_else(|e| panic!("{q}: {e}"));
            }
        }
        // Whitespace Grafana might add around it does not matter.
        grafana_ds_allows(a, Some(Role::User), Upstream::Prometheus, &get(), "api/v1/query", &p(&[("query", " noo_node_load ")]))
            .unwrap();
        // The dashboard's variables.
        grafana_ds_allows(
            a,
            Some(Role::User),
            Upstream::Prometheus,
            &get(),
            "api/v1/label/node_id/values",
            &p(&[("match[]", "noo_node_load"), ("start", "1"), ("end", "2")]),
        )
        .unwrap();
        grafana_ds_allows(a, Some(Role::User), Upstream::Prometheus, &get(), "api/v1/status/buildinfo", &[]).unwrap();
    }

    #[test]
    fn a_viewer_cannot_smuggle_a_query_past_the_list() {
        let a = allowlist();
        let ok = "noo_node_load";
        let f = |path: &str, params: &[(&str, &str)]| {
            grafana_ds_allows(a, Some(Role::User), Upstream::Prometheus, &Method::POST, path, &p(params))
        };
        assert!(f("api/v1/query", &[("query", ok), ("query", "up")]).is_err(), "a second query");
        assert!(f("api/v1/query", &[("query", ok), ("match[]", "up")]).is_err(), "an unknown parameter");
        assert!(f("api/v1/query", &[]).is_err(), "no query");
        assert!(f("api/v1/series", &[("match[]", ok)]).is_err(), "series lists every label set");
        assert!(f("api/v1/labels", &[]).is_err());
        assert!(f("api/v1/metadata", &[]).is_err());
        assert!(f("api/v1/label/node_id/values", &[("match[]", "up")]).is_err(), "a variable with another selector");
        assert!(f("api/v1/label/instance/values", &[("match[]", ok)]).is_err(), "a label no variable lists");
        assert!(f("api/v1/label/node_id/values", &[]).is_err(), "no selector = every value");
    }

    #[test]
    fn a_viewer_reads_no_logs() {
        let a = allowlist();
        for path in ["loki/api/v1/query_range", "loki/api/v1/labels", "loki/api/v1/status/buildinfo"] {
            let e = grafana_ds_allows(a, Some(Role::User), Upstream::Loki, &get(), path, &p(&[("query", "{job=~\".+\"}")]))
                .expect_err(path);
            assert!(e.contains("operator-only"), "{e}");
        }
    }

    /// Grafana with no user (an alert evaluation): the read-only policy,
    /// never more.
    #[test]
    fn grafana_without_a_user_gets_the_read_only_policy() {
        let a = allowlist();
        assert!(grafana_ds_allows(a, None, Upstream::Prometheus, &Method::POST, "api/v1/query", &p(&[("query", "up")])).is_err());
        assert!(grafana_ds_allows(a, None, Upstream::Loki, &get(), "loki/api/v1/query_range", &p(&[("query", "{a=\"b\"}")])).is_err());
        grafana_ds_allows(a, None, Upstream::Prometheus, &Method::POST, "api/v1/query", &p(&[("query", "noo_node_load")])).unwrap();
    }

    #[test]
    fn an_operators_query_passes() {
        let a = allowlist();
        for r in [Role::Operator, Role::Admin] {
            grafana_ds_allows(a, Some(r), Upstream::Prometheus, &Method::POST, "api/v1/query", &p(&[("query", "up")])).unwrap();
            grafana_ds_allows(a, Some(r), Upstream::Prometheus, &get(), "api/v1/series", &p(&[("match[]", "up")])).unwrap();
            grafana_ds_allows(a, Some(r), Upstream::Prometheus, &get(), "api/v1/label/job/values", &[]).unwrap();
            grafana_ds_allows(a, Some(r), Upstream::Loki, &get(), "loki/api/v1/query_range", &p(&[("query", "{job=~\".+\"}")]))
                .unwrap();
        }
    }

    /// Reads only, for everyone: no admin, write, delete or tail endpoint,
    /// no other method, no path that could climb out of the API.
    #[test]
    fn nobody_writes_administers_or_escapes_the_api() {
        let a = allowlist();
        for r in [Some(Role::Admin), Some(Role::Operator), Some(Role::User), None] {
            for (up, path) in [
                (Upstream::Prometheus, "api/v1/admin/tsdb/delete_series"),
                (Upstream::Prometheus, "api/v1/admin/tsdb/snapshot"),
                (Upstream::Prometheus, "api/v1/write"),
                (Upstream::Prometheus, "-/quit"),
                (Upstream::Prometheus, "api/v1/../../-/quit"),
                (Upstream::Prometheus, "api/v1/label/a%2F/values"),
                (Upstream::Loki, "loki/api/v1/push"),
                (Upstream::Loki, "loki/api/v1/delete"),
                (Upstream::Loki, "loki/api/v1/tail"),
                (Upstream::Loki, "flush"),
            ] {
                assert!(grafana_ds_allows(a, r, up, &get(), path, &[]).is_err(), "{r:?} {path}");
            }
            assert!(grafana_ds_allows(a, r, Upstream::Prometheus, &Method::DELETE, "api/v1/query", &[]).is_err());
            assert!(grafana_ds_allows(a, r, Upstream::Prometheus, &Method::PUT, "api/v1/query", &[]).is_err());
        }
    }

    #[test]
    fn the_live_row_decides_the_tier() {
        let none = json!([]);
        assert_eq!(tier_of_row("user", &none, false), Some(Role::User));
        assert_eq!(tier_of_row("operator", &none, false), Some(Role::Operator));
        assert_eq!(tier_of_row("user", &json!(["admin"]), false), Some(Role::Admin), "scopes raise the tier");
        assert_eq!(tier_of_row("admin", &none, true), None, "disabled is refused");
        assert_eq!(tier_of_row("garbage", &none, false), Some(Role::Admin), "same as the Grafana session");
    }

    #[test]
    fn form_bodies_and_query_strings_are_both_read() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());
        let uri: Uri = "/api/grafana-ds/prometheus/api/v1/query?time=5".parse().unwrap();
        let got = params_of(&uri, &h, &Bytes::from_static(b"query=up%7Ba%3D%22b%22%7D")).unwrap();
        assert_eq!(got, p(&[("time", "5"), ("query", "up{a=\"b\"}")]));
        // A body of another type is not read — and not forwarded unread.
        assert!(params_of(&uri, &HeaderMap::new(), &Bytes::from_static(b"query=up")).is_err());
    }

    /// The registered literals are the prefix the middleware gates on.
    #[test]
    fn the_routes_sit_under_the_gated_prefix() {
        let src = include_str!("grafana_ds.rs");
        let routes: Vec<&str> = src.lines().filter(|l| l.trim_start().starts_with(".route(\"")).collect();
        assert_eq!(routes.len(), 2, "{routes:?}");
        for r in routes {
            assert!(r.contains(&format!(".route(\"{}", crate::auth::GRAFANA_DS_PREFIX)), "{r}");
        }
    }
}
