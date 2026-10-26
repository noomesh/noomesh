// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The router harness (followup i242): the REAL router, on a REAL migrated
//! Postgres, driven over a real socket.
//!
//! Three contracts are asserted that were, until now, each proven only against
//! a stand-in (a hand-built router with a fake auth layer, a source scan, or a
//! unit test of the pure function):
//!
//!   1. `authz`: every route whose handler takes an `Operator`,
//!      `OperatorOrInternal` or `Admin` extractor refuses a viewer (role
//!      `user`) with 403. The route list is DERIVED at test time by scanning
//!      `routes/*.rs` (handler signatures + `.route(...)` registrations), so a
//!      route added tomorrow is covered without anyone editing this file. The
//!      scan only decides WHAT to ask; the assertion is the response.
//!   2. `redis_or_unavailable`: with no Redis client, the named action routes
//!      (jobs list and history, scheduler pause/resume/drain/undrain) answer
//!      503 `{"error":"redis_reconnecting"}` with a `Retry-After` header.
//!   3. `Measured`: with no Redis client, the status routes answer 200 with the
//!      unmeasurable fields `null` and a `<field>_detail` sentence, never a
//!      literal `false` / `0` / `[]`.
//!   4. `i241`: the routes the operator decided (2026-10-26) must name a real
//!      user. A VALID cluster HMAC token (a node, no user context) is refused
//!      403 on each of them; an operator login is admitted to every row but
//!      the schema-changing one, which wants an admin. The bootstrap-token
//!      POST/revoke rows are only checked for the refusal (they stay
//!      `OperatorOrInternal` until an agent principal exists, and admitting
//!      an operator would mint a token).
//!
//! What it proves it through: `build_router` (every layer: rate limit, auth,
//! principal, security headers), `auth::require_any_auth` admitting a signed
//! JWT, and the real `mesh_migrate::apply` chain on a throwaway database
//! (`noo_router_<pid>`, created and dropped here).
//!
//! What it CANNOT prove, and does not pretend to:
//!   - There is no NATS server and no Python worker. The bus client is
//!     unconnected, so any route that needs a worker answers by ABSENCE (a
//!     timeout or 5xx). Nothing here asserts a worker-backed answer.
//!   - There is no Redis. That is the point of contracts 2 and 3; it also
//!     means a route's Redis-CONNECTED behaviour is not exercised.
//!   - Contract 1 asserts the refusal, not which lock gave it. A viewer is
//!     usually stopped by the tier gate in `auth::scope_allows` BEFORE the
//!     extractor runs (both answer 403); the per-route split is printed
//!     (`by extractor` vs `by tier gate`) so a drift in either is visible, but
//!     a route the tier gate covers would still pass if its extractor were
//!     deleted. The extractor's own table is `authz::tests`.
//!   - Routes registered outside `routes/*.rs` (the MCP doors, add-on proxy
//!     routes) are not enumerated. Fleet-HMAC and node-token callers are not
//!     driven.
//!
//! Gated on `NOO_BROKER_TEST_DSN` like the other real-catalogue suites: it
//! SKIPS (printing why) without it, because a developer box and the
//! `rust-gateway` job have no Postgres. CI's `sqlx-drift` job provides one and
//! sets `NOO_ROUTER_HARNESS_REQUIRED=1`, which turns the skip into a failure:
//! a harness that silently does not run looks exactly like one that passes.

#![cfg(test)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr as _;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::auth::Role;
use crate::config::AppConfig;
use crate::state::AppState;

/// Not a secret: signs the tokens this test mints and verifies, in this
/// process only. Long enough and not the insecure default.
const JWT_SECRET: &str = "router-harness-signing-key-not-a-secret-0001";

/// Substituted for every `{param}` in a route. A UUID parses as `String` and
/// `Uuid` alike, so a `Path<Uuid>` extractor that runs before the role
/// extractor does not turn the request into a 400. It names nothing.
const DUMMY_ID: &str = "00000000-0000-0000-0000-000000000000";

// ───────────────────────────── gating ─────────────────────────────

/// The scratch Postgres DSN, or `None` (skip). `NOO_ROUTER_HARNESS_REQUIRED=1`
/// turns "none" into a failure so CI cannot skip it by accident.
fn dsn_or_skip() -> Option<String> {
    match std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty()) {
        Some(d) => Some(d),
        None => {
            let required = std::env::var("NOO_ROUTER_HARNESS_REQUIRED").is_ok_and(|v| v == "1");
            assert!(
                !required,
                "router_harness: NOO_ROUTER_HARNESS_REQUIRED=1 but NOO_BROKER_TEST_DSN is unset — \
                 the harness would have skipped"
            );
            eprintln!(
                "router_harness: SKIPPED — NOO_BROKER_TEST_DSN is not set (no Postgres). \
                 CI's sqlx-drift job runs it."
            );
            None
        }
    }
}

// ───────────────────────────── the scratch database ─────────────────────────────

struct Scratch {
    admin: sqlx::PgPool,
    name: String,
    pool: sqlx::PgPool,
}

/// `CREATE DATABASE noo_router_<pid>`, the real migration chain to head, and a
/// pool pinned to the same search_path the gateway pins (`state.rs`).
async fn scratch(dsn: &str) -> Scratch {
    let name = format!("noo_router_{}", std::process::id());
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(dsn)
        .await
        .expect("connect to NOO_BROKER_TEST_DSN");
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} (FORCE)")))
        .execute(&admin)
        .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create scratch db");
    let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
    let scratch_dsn = format!("{head}/{name}");

    let build = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch_dsn)
        .await
        .expect("connect scratch");
    unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
    for ext in ["vector", "pg_trgm"] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
            .execute(&build)
            .await
            .expect("extension");
    }
    crate::mesh_migrate::apply(&build).await.expect("apply migrations");
    build.close().await;

    let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
        .expect("scratch dsn")
        .options([("search_path", "mesh,public,trellion,evolve")]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .expect("connect scratch");
    Scratch { admin, name, pool }
}

impl Scratch {
    async fn drop_db(self) {
        self.pool.close().await;
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {} (FORCE)", self.name)))
            .execute(&self.admin)
            .await;
    }
}

// ───────────────────────────── credentials ─────────────────────────────

/// A signed HS256 user token for `role`, the same claims `auth_token` mints,
/// verified by the real `require_any_auth`.
fn token_for(sub: &str, role: Role) -> String {
    let claims = crate::auth::scoped_claims(sub, role.as_str(), role.legacy_scopes(), 600, JWT_SECRET)
        .expect("claims");
    crate::auth::sign_hs256(&claims, JWT_SECRET).expect("sign")
}

/// A valid v1 cluster HMAC token for `actor`, signed with `secret`: the form
/// a node-agent presents. It carries no user.
fn cluster_token(secret: &str, actor: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("{actor}:{ts}").as_bytes());
    format!("{actor}:{ts}:{}", hex::encode(mac.finalize().into_bytes()))
}

/// Not a secret: the fleet secret this process verifies the harness's node
/// token against.
const FLEET_SECRET: &str = "router-harness-fleet-secret-not-a-secret-0001";

// ───────────────────────────── route enumeration ─────────────────────────────

/// One enumerated route: where it is registered, what extractor guards it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Guarded {
    method: String,
    path: String,
    handler: String,
    extractor: String,
    file: String,
}

/// Index of the matching `)` for the `(` at `open`, or `None`.
fn close_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Source with `//` comments removed. Handlers are read from ALL of it
/// (several routes files define handlers after their test module);
/// registrations only from [`production_prefix`], because a test module's
/// private router is not a gateway route.
fn without_comments(raw: &str) -> String {
    raw.lines()
        .map(|l| l.find("//").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The part of the stripped source before the first `#[cfg(test)]`. Every
/// routes file declares its router at the top, ahead of its tests (checked by
/// `grep`: no `.route(` registration follows a `#[cfg(test)]` in any file).
fn production_prefix(src: &str) -> &str {
    &src[..src.find("#[cfg(test)]").unwrap_or(src.len())]
}

/// Every `routes/*.rs` (and `routes/core/*.rs`) file as (name, comment-stripped source).
fn route_sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes");
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("readable routes dir") {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let name = p.strip_prefix(&dir).unwrap().to_string_lossy().replace('\\', "/");
                // This file mentions every extractor by name; scanning it
                // would enumerate its own string literals.
                if name == "router_harness_tests.rs" || name.ends_with("_tests.rs") {
                    continue;
                }
                let raw = std::fs::read_to_string(&p).expect("readable");
                out.push((name, without_comments(&raw)));
            }
        }
    }
    out.sort();
    out
}

/// The routes that carry a role extractor, from the source. Returns the routes
/// and the handlers that carry an extractor but were never registered in the
/// file that defines them (reported, not asserted: they may be mounted from
/// elsewhere).
fn guarded_routes() -> (Vec<Guarded>, Vec<String>) {
    let fn_re = regex::Regex::new(r"async fn (\w+)\s*(?:<[^>]*>)?\(").unwrap();
    let ex_re = regex::Regex::new(r":\s*(?:crate::authz::)?(OperatorOrInternal|Operator|Admin)\b").unwrap();
    let method_re = regex::Regex::new(r"\b(get|post|put|delete|patch)\(\s*(?:\w+::)*(\w+)\s*\)").unwrap();
    // Built from pieces: the OpenAPI drift scan reads literal route
    // registrations out of src/, and this is a search needle, not a route.
    let needle = concat!(".ro", "ute(");

    let mut found = BTreeSet::new();
    let mut unregistered = Vec::new();
    for (file, src) in route_sources() {
        let mut extractor_of = std::collections::BTreeMap::new();
        for m in fn_re.captures_iter(&src) {
            let whole = m.get(0).unwrap();
            let open = whole.end() - 1;
            let Some(close) = close_paren(&src, open) else { continue };
            if let Some(e) = ex_re.captures(&src[open..close]) {
                extractor_of.insert(m[1].to_string(), e[1].to_string());
            }
        }
        let mut registered = BTreeSet::new();
        let prod = production_prefix(&src);
        let mut at = 0;
        while let Some(i) = prod[at..].find(needle) {
            let open = at + i + needle.len() - 1;
            at = open + 1;
            let Some(close) = close_paren(prod, open) else { continue };
            let body = &prod[open + 1..close];
            let Some(rest) = body.trim_start().strip_prefix('"') else { continue };
            let Some(end) = rest.find('"') else { continue };
            let path = &rest[..end];
            for mm in method_re.captures_iter(&rest[end..]) {
                let handler = mm[2].to_string();
                if let Some(ex) = extractor_of.get(&handler) {
                    registered.insert(handler.clone());
                    found.insert(Guarded {
                        method: mm[1].to_uppercase(),
                        path: path.to_string(),
                        handler,
                        extractor: ex.clone(),
                        file: file.clone(),
                    });
                }
            }
        }
        for h in extractor_of.keys() {
            if !registered.contains(h) {
                unregistered.push(format!("{file}::{h}"));
            }
        }
    }
    (found.into_iter().collect(), unregistered)
}

fn concrete(path: &str) -> String {
    regex::Regex::new(r"\{[^}]*\}").unwrap().replace_all(path, DUMMY_ID).into_owned()
}

// ───────────────────────────── the client ─────────────────────────────

struct Reply {
    status: u16,
    retry_after: Option<String>,
    body: Value,
    text: String,
}

struct Client {
    http: reqwest::Client,
    base: String,
    seq: std::sync::atomic::AtomicU32,
}

impl Client {
    /// `bearer` None sends no credential. Each call carries its own
    /// `X-Forwarded-For` (honoured because the peer is loopback, a trusted
    /// proxy), so the per-IP limiter's process-local fallback bucket, 120 a
    /// minute with no Redis, never throttles the sweep.
    async fn call(&self, method: &str, path: &str, bearer: Option<&str>) -> Reply {
        let n = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("{}{}", self.base, path);
        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url).json(&json!({})),
            "PUT" => self.http.put(&url).json(&json!({})),
            "PATCH" => self.http.patch(&url).json(&json!({})),
            "DELETE" => self.http.delete(&url),
            other => panic!("unexpected method {other}"),
        };
        req = req.header("x-forwarded-for", format!("198.51.{}.{}", (n / 250) % 250, n % 250 + 1));
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
        let status = resp.status().as_u16();
        let retry_after = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_string);
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Reply { status, retry_after, body, text }
    }
}

// ───────────────────────────── the three contracts ─────────────────────────────

/// Contract 1. Returns failures; prints the tally.
async fn assert_viewer_refused(c: &Client, viewer: &str, routes: &[Guarded]) -> Vec<String> {
    let mut failures = Vec::new();
    let (mut by_extractor, mut by_tier, mut param_rejected) = (0usize, 0usize, 0usize);
    for r in routes {
        let has_param = r.path.contains('{');
        let reply = c.call(&r.method, &concrete(&r.path), Some(viewer)).await;
        match reply.status {
            403 if reply.text.contains("role required") => by_extractor += 1,
            403 => by_tier += 1,
            // A path or body extractor that runs before the role extractor
            // may reject the dummy id: acceptable ONLY on a route that has a
            // parameter, and counted so the tally shows how much of the sweep
            // proved a refusal.
            400 | 404 | 422 if has_param => param_rejected += 1,
            other => failures.push(format!(
                "viewer {} {} ({} in {}, handler {}): got {other}, want 403 — body {:?}",
                r.method, r.path, r.extractor, r.file, r.handler, reply.text
            )),
        }
    }
    let proven = by_extractor + by_tier;
    eprintln!(
        "router_harness: authz — {} routes enumerated; viewer refused 403 on {proven} \
         ({by_extractor} by extractor, {by_tier} by tier gate); {param_rejected} rejected 400/404/422 \
         on a dummy path parameter before the role check",
        routes.len()
    );
    if proven * 2 < routes.len() {
        failures.push(format!(
            "only {proven} of {} routes proved a 403: the dummy parameters are defeating the sweep",
            routes.len()
        ));
    }
    failures
}

/// Followup i241: routes that used to admit a caller with no user context
/// and now name a person. (method, path, extractor the scan must find).
const I241_ROWS: &[(&str, &str, &str)] = &[
    ("POST", "/api/db/migrations/apply", "Admin"),
    ("GET", "/api/mcp/servers", "Operator"),
    ("POST", "/api/mcp/servers", "Operator"),
    ("GET", "/api/mcp/servers/{id}", "Operator"),
    ("PUT", "/api/mcp/servers/{id}", "Operator"),
    ("DELETE", "/api/mcp/servers/{id}", "Operator"),
    ("PUT", "/api/mcp/servers/{id}/placements/{node}", "Operator"),
    ("DELETE", "/api/mcp/servers/{id}/placements/{node}", "Operator"),
    ("GET", "/api/security/bootstrap-tokens", "Operator"),
    ("GET", "/api/cluster/seat-tokens", "Operator"),
    ("GET", "/api/users", "Operator"),
    ("GET", "/api/security/service-keys", "Operator"),
    ("GET", "/api/security/user-proposals", "Operator"),
    ("GET", "/api/security/audit/list", "Operator"),
    ("GET", "/api/security/audit/verify", "Operator"),
    // Kept: the chat-onboarding agent mints and revokes with no user of its
    // own; no distinct agent principal exists to name instead (see the PR).
    ("POST", "/api/security/bootstrap-tokens", "OperatorOrInternal"),
    ("POST", "/api/security/bootstrap-tokens/{id}/revoke", "OperatorOrInternal"),
];

/// Contract 4. `node` is a valid cluster HMAC token (no user), `operator` and
/// `admin` are logins.
async fn assert_i241_rows(c: &Client, node: &str, operator: &str, admin: &str) -> Vec<String> {
    let mut failures = Vec::new();
    // Control: the node token verifies and is admitted to a node route. Without
    // it, a token the gateway never accepted would "prove" every refusal below.
    let ctl = c.call("GET", &format!("/api/cluster/nodes/{HARNESS_NODE}/desired-config"), Some(node)).await;
    if ctl.status == 401 || ctl.status == 403 {
        failures.push(format!(
            "control: the node token should be admitted to its own desired-config, got {} — {:?}",
            ctl.status, ctl.text
        ));
        return failures;
    }
    let (mut refused, mut admitted) = (0usize, 0usize);
    for (method, path, extractor) in I241_ROWS {
        let url = concrete(path);
        // 1. No user: refused. 403 is the node allow-list (`node_route_allowed`)
        //    or the extractor, whichever answers first; both are the contract.
        let r = c.call(method, &url, Some(node)).await;
        if r.status == 403 {
            refused += 1;
        } else {
            failures.push(format!("i241: a node token (no user) on {method} {path} should be 403, got {} — {:?}", r.status, r.text));
        }
        // 2. A login of the right role gets past the lock. Not asserted for the
        //    two bootstrap-token writes: an operator admitted there would mint
        //    or revoke a real token.
        if *extractor == "OperatorOrInternal" {
            continue;
        }
        if *extractor == "Admin" {
            let r = c.call(method, &url, Some(operator)).await;
            if r.status != 403 {
                failures.push(format!("i241: an operator on {method} {path} (Admin) should be 403, got {}", r.status));
            }
        }
        let who = if *extractor == "Admin" { admin } else { operator };
        let r = c.call(method, &url, Some(who)).await;
        if r.status == 401 || r.status == 403 {
            failures.push(format!("i241: {extractor} login on {method} {path} was refused: {} — {:?}", r.status, r.text));
        } else {
            admitted += 1;
        }
    }
    eprintln!(
        "router_harness: i241 — {} rows; node token refused 403 on {refused}; a login of the right role admitted on {admitted}",
        I241_ROWS.len()
    );
    failures
}

/// The node id the harness's cluster token claims.
const HARNESS_NODE: &str = "harness-node";

/// Contract 2. The named Redis action routes answer 503 `redis_reconnecting`.
async fn assert_redis_reconnecting(c: &Client, admin: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let actions: [(&str, String); 6] = [
        ("GET", "/api/jobs".into()),
        ("GET", "/api/jobs/history".into()),
        ("POST", "/api/scheduler/pause".into()),
        ("POST", "/api/scheduler/resume".into()),
        ("POST", format!("/api/scheduler/drain/{DUMMY_ID}")),
        ("POST", format!("/api/scheduler/undrain/{DUMMY_ID}")),
    ];
    for (method, path) in &actions {
        let r = c.call(method, path, Some(admin)).await;
        if r.status != 503 {
            failures.push(format!("{method} {path}: want 503, got {} — {:?}", r.status, r.text));
            continue;
        }
        if r.body["error"] != "redis_reconnecting" {
            failures.push(format!("{method} {path}: 503 but error is {:?}, want redis_reconnecting", r.body["error"]));
        }
        if r.retry_after.as_deref().and_then(|v| v.parse::<u64>().ok()).is_none() {
            failures.push(format!("{method} {path}: 503 without a numeric Retry-After header ({:?})", r.retry_after));
        }
        if r.body["retry_after_secs"].as_u64().is_none() {
            failures.push(format!("{method} {path}: body lacks retry_after_secs ({:?})", r.body));
        }
    }
    eprintln!("router_harness: redis_reconnecting — {} action routes checked", actions.len());
    failures
}

/// Contract 3. Status routes answer 200, with the unmeasurable fields null and
/// a `<field>_detail` sentence, never a literal 0 / false / [].
async fn assert_measured(c: &Client, admin: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut checked = 0usize;
    let cases: [(&str, &[&str]); 2] = [
        (
            "/api/scheduler/status",
            &["paused", "queue_depth", "active_jobs", "drained_nodes", "background_queue_depth", "history_size"],
        ),
        ("/api/cache/stats", &["enabled"]),
    ];
    for (path, fields) in cases {
        let r = c.call("GET", path, Some(admin)).await;
        if r.status != 200 {
            failures.push(format!("GET {path}: want 200 (a status, not a refusal), got {} — {:?}", r.status, r.text));
            continue;
        }
        for f in fields {
            checked += 1;
            if !r.body[*f].is_null() || !r.body.as_object().is_some_and(|o| o.contains_key(*f)) {
                failures.push(format!("GET {path}: `{f}` must be null with Redis absent, got {:?}", r.body.get(*f)));
            }
            let detail = r.body[format!("{f}_detail")].as_str().unwrap_or("");
            if detail.is_empty() {
                failures.push(format!("GET {path}: `{f}` is null but `{f}_detail` is missing or empty"));
            }
        }
    }
    eprintln!("router_harness: Measured — {checked} unmeasurable fields across 2 status routes");
    failures
}

// ───────────────────────────── the test ─────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_real_router_holds_authz_redis_and_measured_contracts() {
    let Some(dsn) = dsn_or_skip() else { return };

    unsafe { std::env::set_var("NOO_JWT_SECRET", JWT_SECRET) };
    unsafe { std::env::set_var("NOO_CLUSTER_SECRET", FLEET_SECRET) };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // The enumeration needs no database, so a scan that finds nothing fails
    // BEFORE the Postgres work, with its own message.
    let (routes, unregistered) = guarded_routes();
    assert!(
        routes.len() >= 20,
        "the route scan found only {} Operator/OperatorOrInternal/Admin routes — the scan is broken, not the gateway",
        routes.len()
    );
    for kind in ["Operator", "OperatorOrInternal", "Admin"] {
        assert!(
            routes.iter().any(|r| r.extractor == kind),
            "the scan found no route guarded by `{kind}` — it stopped recognising the extractor"
        );
    }
    if !unregistered.is_empty() {
        eprintln!("router_harness: extractor handlers with no registration in their own file (not swept): {unregistered:?}");
    }

    let db = scratch(&dsn).await;
    let state = Arc::new(
        AppState::for_router_harness(&AppConfig::default(), db.pool.clone())
            .await
            .expect("assemble state"),
    );
    let _ = state.self_handle.set(Arc::downgrade(&state));
    assert!(state.redis.is_none(), "the harness must run with Redis ABSENT");

    let app = crate::routes::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    let c = Client {
        http: reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("client"),
        base: format!("http://{addr}"),
        seq: std::sync::atomic::AtomicU32::new(0),
    };

    let viewer = token_for("harness-viewer", Role::User);
    let admin = token_for("harness-admin", Role::Admin);
    let operator = token_for("harness-operator", Role::Operator);
    let node = cluster_token(FLEET_SECRET, HARNESS_NODE);

    let mut failures: Vec<String> = Vec::new();

    // Controls first: the auth layer is live and the admin token is admitted.
    // Without these, a harness whose tokens never verify would "prove" every
    // 403 below (a 401 is not a 403, but a router that 403s everything for
    // another reason would pass contract 1).
    let anon = c.call("GET", "/api/cache/stats", None).await;
    if anon.status != 401 {
        failures.push(format!("control: no credential on /api/cache/stats should be 401, got {}", anon.status));
    }
    let adm = c.call("GET", "/api/cache/stats", Some(&admin)).await;
    if adm.status != 200 {
        failures.push(format!("control: an admin token on /api/cache/stats should be 200, got {} — {:?}", adm.status, adm.text));
    }

    if failures.is_empty() {
        failures.extend(assert_viewer_refused(&c, &viewer, &routes).await);
        failures.extend(assert_redis_reconnecting(&c, &admin).await);
        failures.extend(assert_measured(&c, &admin).await);
        failures.extend(assert_i241_rows(&c, &node, &operator, &admin).await);
    }

    server.abort();
    drop(state);
    db.drop_db().await;

    assert!(failures.is_empty(), "router harness failures ({}):\n  {}", failures.len(), failures.join("\n  "));
}

/// The scan is the harness's source of truth, so it gets a test that needs no
/// database: it must find the extractors and resolve a known route.
#[test]
fn the_route_scan_finds_the_guarded_routes() {
    let (routes, _) = guarded_routes();
    assert!(routes.len() >= 20, "found {}", routes.len());
    assert!(
        routes
            .iter()
            .any(|r| r.method == "GET" && r.path == "/api/v1/walks/stats" && r.extractor == "Operator"),
        "GET /api/v1/walks/stats (Operator) must be enumerated"
    );
    // i241: every row the operator tightened is found with the extractor it
    // was given, and the two kept bootstrap-token writes are still the
    // deliberate no-user policy. A drift either way fails here, with no database.
    for (method, path, extractor) in I241_ROWS {
        assert!(
            routes.iter().any(|r| r.method == *method && r.path == *path && r.extractor == *extractor),
            "{method} {path} must be guarded by `{extractor}` (followup i241); scan found {:?}",
            routes.iter().filter(|r| r.method == *method && r.path == *path).map(|r| &r.extractor).collect::<Vec<_>>()
        );
    }
    assert!(
        routes.iter().any(|r| r.path == "/api/v1/admin/walks" && r.extractor == "Admin"),
        "/api/v1/admin/walks (Admin) must be enumerated"
    );
    assert_eq!(concrete("/api/x/{id}/y/{node}"), format!("/api/x/{DUMMY_ID}/y/{DUMMY_ID}"));
}
