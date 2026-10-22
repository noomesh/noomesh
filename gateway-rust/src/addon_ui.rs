// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An HTTP add-on's own web UI, on an ORIGIN OF ITS OWN.
//!
//! The console keeps the person's access token in `localStorage` on the
//! console origin. An add-on's UI must never be able to read it, so it is
//! never served on that origin: each add-on whose manifest has a `ui` key gets
//! its own HTTPS listener on the gateway, on a port of its own (an origin is
//! scheme + host + PORT, and `localStorage` and script access are per origin).
//! The fleet is reached at one tailnet MagicDNS name, so a subdomain per
//! add-on is not available; the port is the boundary.
//!
//! ## Ports
//!
//! `NOO_ADDON_UI_PORTS` (default [`DEFAULT_PORT_RANGE`], `8450-8499`) is the
//! range. Each add-on with a `ui` gets the port its name hashes to, probing
//! upward (wrapping) past ports already given, in name order
//! ([`allocate_ports`]): the same set of add-ons always gets the same ports,
//! and adding one moves another only on a hash collision. The listener uses
//! the gateway's own certificate and serves the UI at `/` (no prefix).
//!
//! ## Session handoff
//!
//! 1. The console (on its own origin, holding the person's token) calls
//!    `POST /api/addons/<addon>/ui-session` with `Authorization: Bearer`. The
//!    gateway checks `ui.min_role` and answers a ONE-TIME CODE (random, 30 s,
//!    single use, bound to that person and that add-on) and the URL
//!    `https://<host>:<port>/__noo/session?code=<code>`.
//! 2. The browser navigates there (a tab, or the console's iframe). The
//!    add-on origin redeems the code and sets ITS OWN cookie,
//!    `noo_ui_<addon>=<opaque session id>`: HttpOnly, Secure,
//!    SameSite=Strict, host-only, `Path=/`, expiring with the access token
//!    the console presented. Then it redirects to `/`.
//! 3. On the add-on origin that cookie, and nothing else, authenticates
//!    ([`gate`]): the UI's pages and assets, the add-on's own manifest HTTP
//!    routes (`/api/…`, the same proxy handler as on the console port) and its
//!    WS routes (cookie on the upgrade, plus an `Origin` check). Every other
//!    path on that port is 404. A bearer token is NOT accepted there, and the
//!    console port never reads a `noo_ui_*` cookie.
//!
//! The cookie holds an opaque id, never the access token: the token stays on
//! the gateway, which re-checks it against the account's session floor
//! (logout, disable, demotion) on every request.
//!
//! ## CSRF and cross-add-on requests
//!
//! Cookies ignore ports, so the browser sends add-on A's cookie to add-on B's
//! port too (same host, same site). B's listener only reads `noo_ui_<B>`, and
//! on A's port: a request carrying an `Origin` must come from A's origin; a
//! WebSocket upgrade must carry A's origin; a write (`POST`, `PUT`, `PATCH`,
//! `DELETE`) must carry A's origin AND the header `X-Noo-Addon-Request: 1`
//! (a header no cross-origin page can send without a CORS preflight, which
//! this listener never approves).
//!
//! ## What the browser gets back from a UI path
//!
//! - status and body as the add-on sent them (streamed);
//! - response headers from an ALLOW-list ([`sanitise_response_headers`]):
//!   `Set-Cookie`, CORS, HSTS, `Clear-Site-Data`, `Service-Worker-Allowed`,
//!   `Refresh`, `Link`, reporting headers and anything unknown are dropped;
//! - the gateway's Content-Security-Policy ([`csp_for`]) always, beside any
//!   the add-on sent (both are enforced, so the add-on's can only narrow it):
//!   everything from this origin only, `connect-src 'self'` (its own API and
//!   sockets), `frame-ancestors` the console origin;
//! - `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
//!   `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control:
//!   private, no-cache` when the add-on sent none.
//!
//! A service-worker script fetch (`Service-Worker: script`) is refused.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, RawQuery, Request},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::addon_proxy::{AddonManifest, UiSpec};
use crate::state::AppState;

/// The default port range for add-on UI origins.
pub const DEFAULT_PORT_RANGE: &str = "8450-8499";
/// The variable that overrides it (`<first>-<last>`).
pub const PORT_RANGE_ENV: &str = "NOO_ADDON_UI_PORTS";
/// Where the add-on origin redeems a one-time code.
pub const SESSION_PATH: &str = "/__noo/session";
/// Every add-on cookie is `noo_ui_<addon>`.
pub const COOKIE_PREFIX: &str = "noo_ui_";
/// The header a write on an add-on origin must carry.
pub const ADDON_REQUEST_HEADER: &str = "x-noo-addon-request";
/// How long a one-time code may wait to be redeemed.
pub const CODE_TTL: Duration = Duration::from_secs(30);
/// Codes and sessions kept at most (a flood of mints cannot grow memory).
const MAX_ENTRIES: usize = 10_000;

/// Request headers passed on to the add-on (besides the gateway's own
/// identity headers). Nothing else from the browser reaches it: no cookie,
/// no `Authorization`, no forged `x-noo-requester-*`.
const PASSED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "if-none-match",
    "if-modified-since",
    "range",
    "if-range",
];

/// Response headers passed back to the browser. Anything not listed is
/// dropped (`set-cookie`, `access-control-*`, `strict-transport-security`,
/// `clear-site-data`, `service-worker-allowed`, `refresh`, `link`, `report-to`,
/// `nel`, `x-frame-options`, `permissions-policy`, `server`, …). `location` is
/// handled on its own.
const PASSED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "content-range",
    "content-disposition",
    "accept-ranges",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "vary",
    "content-security-policy",
];

// ── Ports ────────────────────────────────────────────────────────────────

/// `"8450-8499"` → `(8450, 8499)`. At most 1000 ports, all above 1024.
pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s.trim().split_once('-').ok_or_else(|| format!("{PORT_RANGE_ENV}={s:?} is not <first>-<last>"))?;
    let a: u16 = a.trim().parse().map_err(|_| format!("{PORT_RANGE_ENV}={s:?}: {a:?} is not a port"))?;
    let b: u16 = b.trim().parse().map_err(|_| format!("{PORT_RANGE_ENV}={s:?}: {b:?} is not a port"))?;
    if a <= 1024 || b < a || b - a >= 1000 {
        return Err(format!("{PORT_RANGE_ENV}={s:?}: want 1025 <= first <= last, at most 1000 ports"));
    }
    Ok((a, b))
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// A port for each add-on in `names`, inside `range`: the port its name
/// hashes to, else the next free one (wrapping). Names are taken in sorted
/// order, so the answer depends only on the set. Add-ons beyond the range's
/// size get none (and are logged by the caller).
pub fn allocate_ports(names: &[String], range: (u16, u16)) -> BTreeMap<String, u16> {
    let size = (range.1 - range.0) as u64 + 1;
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut taken = std::collections::HashSet::new();
    let mut out = BTreeMap::new();
    for name in sorted {
        let start = fnv1a(name) % size;
        for i in 0..size {
            let port = range.0 + ((start + i) % size) as u16;
            if taken.insert(port) {
                out.insert(name.clone(), port);
                break;
            }
        }
    }
    out
}

static PORTS: OnceLock<BTreeMap<String, u16>> = OnceLock::new();

/// The port of `addon`'s UI origin, once the listeners were started.
pub fn port_of(addon: &str) -> Option<u16> {
    PORTS.get().and_then(|p| p.get(addon).copied())
}

/// Start one HTTPS listener per add-on with a `ui`, with the gateway's own
/// certificate. Called once at startup, after the router (and so the add-on
/// registry) is built. A listener that cannot bind logs and leaves that UI
/// unavailable (`ui-session` answers 503); the gateway itself carries on.
pub fn spawn_origins(state: Arc<AppState>, tls: axum_server::tls_rustls::RustlsConfig) {
    let raw = std::env::var(PORT_RANGE_ENV).ok().filter(|v| !v.trim().is_empty());
    let range = match parse_port_range(raw.as_deref().unwrap_or(DEFAULT_PORT_RANGE)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("add-on UI origins: {e}; no add-on UI is served");
            let _ = PORTS.set(BTreeMap::new());
            return;
        }
    };
    let manifests: Vec<AddonManifest> = crate::addon_proxy::manifests().into_iter().filter(|m| m.ui.is_some()).collect();
    let names: Vec<String> = manifests.iter().map(|m| m.addon.clone()).collect();
    let ports = allocate_ports(&names, range);
    for n in names.iter().filter(|n| !ports.contains_key(*n)) {
        tracing::error!(addon = %n, "add-on UI origins: no free port in {PORT_RANGE_ENV} {}-{}; its UI is not served", range.0, range.1);
    }
    let _ = PORTS.set(ports.clone());
    for m in manifests {
        let Some(port) = ports.get(&m.addon).copied() else { continue };
        let app = origin_router(state.clone(), &m, port);
        let tls = tls.clone();
        let addon = m.addon.clone();
        tokio::spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            tracing::info!(addon = %addon, port, "add-on UI origin listening (TLS)");
            if let Err(e) = axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                tracing::error!(addon = %addon, port, error = %e, "add-on UI origin listener failed; its UI is unavailable");
            }
        });
    }
}

// ── Codes and sessions ───────────────────────────────────────────────────

/// What a code or a session stands for.
#[derive(Clone, Debug)]
pub struct Grant {
    pub addon: String,
    pub requester: crate::auth::RequesterCtx,
    /// The access token the console presented; kept on the gateway, re-checked
    /// against the session floor, never sent to the browser on this origin.
    pub token: String,
    pub token_exp: usize,
}

struct Entry {
    grant: Grant,
    expires: Instant,
}

static CODES: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);
static SESSIONS: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);

fn random_id() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

fn put(store: &Mutex<Option<HashMap<String, Entry>>>, grant: Grant, ttl: Duration) -> String {
    let id = random_id();
    let mut guard = match store.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    map.retain(|_, e| e.expires > now);
    if map.len() >= MAX_ENTRIES {
        map.clear();
    }
    map.insert(id.clone(), Entry { grant, expires: now + ttl });
    id
}

/// Seconds until a token's `exp`, at least 1.
fn secs_until(exp: usize) -> u64 {
    let now = chrono::Utc::now().timestamp().max(0) as usize;
    exp.saturating_sub(now).max(1) as u64
}

/// Mint a one-time code for `grant`.
pub fn mint_code(grant: Grant) -> String {
    put(&CODES, grant, CODE_TTL)
}

/// Redeem a code on `addon`'s origin. Single use: removed whether or not it
/// matches.
pub fn redeem_code(code: &str, addon: &str) -> Option<Grant> {
    let mut guard = match CODES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let e = guard.as_mut()?.remove(code)?;
    (e.expires > Instant::now() && e.grant.addon == addon).then_some(e.grant)
}

/// Open a session for `grant`, living until its token expires.
pub fn open_session(grant: Grant) -> String {
    let ttl = Duration::from_secs(secs_until(grant.token_exp));
    put(&SESSIONS, grant, ttl)
}

/// The live session `sid` on `addon`'s origin.
pub fn session(sid: &str, addon: &str) -> Option<Grant> {
    let guard = match SESSIONS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let e = guard.as_ref()?.get(sid)?;
    (e.expires > Instant::now() && e.grant.addon == addon).then(|| e.grant.clone())
}

fn end_session(sid: &str) {
    let mut guard = match SESSIONS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(m) = guard.as_mut() {
        m.remove(sid);
    }
}

/// The add-on's cookie name.
pub fn cookie_name(addon: &str) -> String {
    format!("{COOKIE_PREFIX}{addon}")
}

/// A cookie's value by exact name.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// The add-on origin's session cookie: HttpOnly, Secure, SameSite=Strict,
/// host-only (no `Domain`), `Path=/`.
pub fn session_cookie(addon: &str, sid: &str, max_age_secs: i64) -> axum_extra::extract::cookie::Cookie<'static> {
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let mut c = Cookie::new(cookie_name(addon), sid.to_string());
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Strict);
    c.set_path("/");
    c.set_max_age(time::Duration::seconds(max_age_secs));
    c
}

// ── The console port: minting the code ──────────────────────────────────

/// The core route on the console port. The console origin never serves an
/// add-on's UI itself.
pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/addons/{addon_id}/ui-session", post(ui_session))
}

/// Is `path` the ui-session route? (The tier gate lets a User POST it; the
/// handler applies the UI's own `min_role`.)
pub fn is_ui_session_path(path: &str) -> bool {
    path.strip_prefix("/api/addons/")
        .and_then(|r| r.strip_suffix("/ui-session"))
        .is_some_and(crate::addon_registry::name_ok)
}

/// The add-on's manifest when it declares a UI, or the answer that explains
/// why not (404 no UI, 503 off or refused).
fn ui_manifest(addon: &str) -> Result<(AddonManifest, UiSpec), Response> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(not_found(addon));
    }
    if let Some(m) = crate::addon_proxy::manifests().into_iter().find(|m| m.addon == addon) {
        if !crate::addons::enabled(addon) {
            return Err(unavailable(addon, crate::addons::refusal_msg(addon), crate::addons::health_word(addon)));
        }
        return match m.ui.clone() {
            Some(ui) => Ok((m, ui)),
            None => Err(not_found(addon)),
        };
    }
    match crate::addon_proxy::refusal(addon) {
        Some(why) => Err(unavailable(addon, why, "unhealthy")),
        None => Err(not_found(addon)),
    }
}

fn not_found(addon: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "detail": format!("add-on {addon:?} serves no UI"), "addon": addon })),
    )
        .into_response()
}

fn unavailable(addon: &str, error: String, state: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": error, "addon": addon, "state": state }))).into_response()
}

fn ui_forbidden(addon: &str, ui: &UiSpec) -> Response {
    let need = ui.required_role().as_str();
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "detail": format!("the {addon} UI needs the {need} role"),
            "addon": addon,
            "required_role": need,
        })),
    )
        .into_response()
}

/// The hostname of a `Host` value (port dropped), when it is a plain DNS name
/// or IPv4 address. Anything else is `None` and is never put in a header.
pub fn plain_hostname(host: &str) -> Option<&str> {
    let h = host.trim();
    let name = h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(n, _)| n).unwrap_or(h);
    (!name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        .then_some(name)
}

/// The host the browser used: `X-Forwarded-Host` (set by `tailscale serve`
/// or another front proxy) or `Host`.
fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(plain_hostname)
}

/// POST /api/addons/{addon_id}/ui-session — hand the signed-in person over to an add-on's web UI, which is served on an origin of its own (a port of its own on this host). Send the access token as `Authorization: Bearer`; checks the UI's `min_role` and answers a one-time code (30 s, single use, bound to this person and add-on) and the URL `https://<host>:<port>/__noo/session?code=<code>` to navigate to. The add-on origin redeems it and sets its own cookie. 401 without a person's bearer, 403 below the UI's role, 404 when the add-on serves no UI, 503 when it is off or its UI listener is not up.
async fn ui_session(
    Path(addon_id): Path<String>,
    headers: HeaderMap,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Response {
    let Some(axum::Extension(r)) = ctx else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "detail": "an add-on UI session is for a signed-in person; no verified caller" })),
        )
            .into_response();
    };
    if r.act.is_some() || r.harness.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "detail": "a delegated or harness credential cannot open an add-on UI" })),
        )
            .into_response();
    }
    let (_, ui) = match ui_manifest(&addon_id) {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    if !ui.permits(r.role) {
        return ui_forbidden(&addon_id, &ui);
    }
    let Some(port) = port_of(&addon_id) else {
        return unavailable(
            &addon_id,
            format!("the {addon_id} UI origin is not listening (no port in {PORT_RANGE_ENV}, or its listener failed; see the gateway log)"),
            "unhealthy",
        );
    };
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "detail": "send the access token as Authorization: Bearer" })))
            .into_response();
    };
    let Ok(claims) = crate::auth::verify_token(token, &crate::auth::jwt_secret()) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "detail": "not an access token" }))).into_response();
    };
    let code = mint_code(Grant { addon: addon_id.clone(), requester: r, token: token.to_string(), token_exp: claims.exp });
    let path = format!("{SESSION_PATH}?code={code}");
    let url = request_host(&headers).map(|h| format!("https://{h}:{port}{path}"));
    let mut resp = Json(json!({
        "code": code,
        "port": port,
        "path": path,
        "url": url,
        "expires_in": CODE_TTL.as_secs(),
        "session_expires_at": claims.exp,
    }))
    .into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ── The add-on origin ────────────────────────────────────────────────────

/// What one add-on origin's listener knows about itself.
#[derive(Clone)]
pub struct Origin {
    pub addon: String,
    pub port: u16,
    pub state: Arc<AppState>,
}

/// The session behind an add-on-origin request, for a socket's lifetime
/// (`addon_ws`): the token's `exp` and subject.
#[derive(Clone, Debug)]
pub struct OriginSession {
    pub exp: usize,
    pub sub: String,
}

/// The router of one add-on's origin: the add-on's own manifest routes (HTTP
/// and WS, the same handlers as on the console port), the session handoff,
/// and the UI for everything else. Behind [`gate`].
pub fn origin_router(state: Arc<AppState>, manifest: &AddonManifest, port: u16) -> Router {
    let origin = Arc::new(Origin { addon: manifest.addon.clone(), port, state: state.clone() });
    let o_session = origin.clone();
    let o_fallback = origin.clone();
    let o_gate = origin.clone();
    crate::addon_proxy::addon_router(manifest)
        .route(
            SESSION_PATH,
            get(move |RawQuery(q): RawQuery| {
                let o = o_session.clone();
                async move { redeem(&o, q.as_deref()) }
            }),
        )
        .fallback(
            move |method: Method,
                  uri: Uri,
                  RawQuery(q): RawQuery,
                  headers: HeaderMap,
                  ctx: Option<axum::Extension<crate::auth::RequesterCtx>>| {
                let o = o_fallback.clone();
                async move {
                    let path = uri.path();
                    if is_reserved_on_origin(path) {
                        return (StatusCode::NOT_FOUND, Json(json!({ "detail": "not found on this add-on origin" }))).into_response();
                    }
                    let requester = ctx.map(|axum::Extension(r)| r);
                    serve_ui(&o.addon, &method, path, q.as_deref(), &headers, requester.as_ref()).await
                }
            },
        )
        .layer(axum::middleware::from_fn(move |req: Request, next: Next| {
            let o = o_gate.clone();
            async move { gate(&o, req, next).await }
        }))
        .with_state(state)
}

/// Paths on an add-on origin that are never the UI: an unmatched one is 404.
pub fn is_reserved_on_origin(path: &str) -> bool {
    ["/api/", "/ws/", "/__noo/"].iter().any(|p| path.starts_with(p)) || path == "/api" || path == "/ws"
}

/// `GET /__noo/session?code=…` on the add-on origin: redeem the code, set
/// this origin's own cookie, go to `/`.
fn redeem(o: &Origin, query: Option<&str>) -> Response {
    let code = query.and_then(|q| q.split('&').find_map(|p| p.strip_prefix("code="))).unwrap_or("");
    let Some(grant) = redeem_code(code, &o.addon) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
            "This link is used, expired or for another add-on. Open the add-on again from the console.",
        )
            .into_response();
    };
    let max_age = secs_until(grant.token_exp) as i64;
    let sid = open_session(grant);
    let cookie = session_cookie(&o.addon, &sid, max_age);
    let mut resp = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    resp
}

/// Does `origin` (an `Origin` header) name this add-on origin: https, the
/// host the browser used, this listener's port?
pub fn origin_matches(origin: &str, host: Option<&str>, port: u16) -> bool {
    let Some(rest) = origin.trim().strip_prefix("https://") else { return false };
    let Some(host) = host else { return false };
    let (h, p) = match rest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h, p),
            Err(_) => return false,
        },
        None => (rest, 443),
    };
    p == port && h.eq_ignore_ascii_case(host)
}

fn is_ws_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
}

/// The CSRF / cross-origin rule of an add-on origin, before the session is
/// looked at. `Err` is the refusal.
pub fn origin_rule(method: &Method, headers: &HeaderMap, port: u16) -> Result<(), &'static str> {
    let host = request_host(headers);
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let write = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if write || is_ws_upgrade(headers) {
        let Some(o) = origin else { return Err("a write or a socket on an add-on origin must carry this origin's Origin header") };
        if !origin_matches(o, host, port) {
            return Err("cross-origin request refused");
        }
        if write && headers.get(ADDON_REQUEST_HEADER).is_none() {
            return Err("a write on an add-on origin must carry the X-Noo-Addon-Request header");
        }
        return Ok(());
    }
    match origin {
        Some(o) if !origin_matches(o, host, port) => Err("cross-origin request refused"),
        _ => Ok(()),
    }
}

/// Authenticate a request on an add-on origin: the origin rule, then this
/// add-on's cookie (and nothing else), then the account's session floor.
async fn gate(o: &Origin, mut req: Request, next: Next) -> Response {
    if req.uri().path() == SESSION_PATH {
        return next.run(req).await;
    }
    if let Err(why) = origin_rule(req.method(), req.headers(), o.port) {
        return (StatusCode::FORBIDDEN, Json(json!({ "detail": why }))).into_response();
    }
    let unauth = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
            "Not signed in to this add-on. Open it from the console.",
        )
            .into_response()
    };
    let Some(sid) = cookie_value(req.headers(), &cookie_name(&o.addon)) else { return unauth() };
    let Some(grant) = session(&sid, &o.addon) else { return unauth() };
    if crate::session_floor::refuses(&o.state, &grant.requester.sub, &grant.token).await {
        end_session(&sid);
        return unauth();
    }
    req.extensions_mut().insert(OriginSession { exp: grant.token_exp, sub: grant.requester.sub.clone() });
    req.extensions_mut().insert(grant.requester);
    next.run(req).await
}

/// The gateway's Content-Security-Policy for an add-on origin.
/// `frame-ancestors` is the console: `NOO_CONSOLE_ORIGIN` (space or comma
/// separated `https://…` origins) when set, else this host on 443 and on the
/// gateway port. `'wasm-unsafe-eval'` lets a UI run WebAssembly (an audio
/// codec) without `eval`; `blob:`/`mediastream:` cover audio worklets and
/// live capture.
pub fn csp_for(host: Option<&str>) -> String {
    let configured: Vec<String> = std::env::var("NOO_CONSOLE_ORIGIN")
        .ok()
        .map(|v| {
            v.split([',', ' '])
                .map(str::trim)
                .filter(|o| o.starts_with("https://") && o[8..].bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let ancestors = if !configured.is_empty() {
        configured.join(" ")
    } else if let Some(h) = host {
        let gw = std::env::var("NOO_PORT_GATEWAY")
            .ok()
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or_else(|| "8080".into());
        format!("https://{h} https://{h}:{gw}")
    } else {
        "'none'".into()
    };
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: blob:; media-src 'self' blob: mediastream:; font-src 'self' data:; \
         connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; \
         form-action 'self'; frame-ancestors {ancestors}"
    )
}

/// The rest of a UI path (the raw request path without its leading `/`), or
/// why it is refused. Each segment must be plain (`[A-Za-z0-9._~@+-]`, not
/// `.` or `..`); a `%` anywhere (an encoded `/`, `.` or `\`) is refused
/// outright rather than decoded, so nothing can climb out of the upstream
/// prefix. An empty rest is the index; a trailing `/` is kept.
pub fn ui_rest(raw_path: &str) -> Result<&str, &'static str> {
    let rest = raw_path.strip_prefix('/').ok_or("not an absolute path")?;
    if rest.len() > 1024 {
        return Err("path too long");
    }
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.len() > 32 {
        return Err("path too deep");
    }
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        if seg.is_empty() {
            if last {
                continue; // the index, or a trailing slash
            }
            return Err("empty path segment");
        }
        if *seg == "." || *seg == ".." {
            return Err("`.` and `..` segments are refused");
        }
        if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~@+-".contains(&b)) {
            return Err("a path segment may hold only [A-Za-z0-9._~@+-] (no percent-encoding)");
        }
    }
    Ok(rest)
}

/// A UI page or asset on the add-on origin, proxied from the add-on.
pub(crate) async fn serve_ui(
    addon: &str,
    method: &Method,
    raw_path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    requester: Option<&crate::auth::RequesterCtx>,
) -> Response {
    // Only reads. (axum routes HEAD to a GET handler.)
    if !matches!(*method, Method::GET | Method::HEAD) {
        return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET, HEAD")]).into_response();
    }
    let (manifest, ui) = match ui_manifest(addon) {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    // Permission before the path is read or anything is fetched. The origin
    // gate already required a session, so a requester is always present.
    let Some(r) = requester else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "detail": "no session" }))).into_response();
    };
    if !ui.permits(r.role) {
        return ui_forbidden(addon, &ui);
    }
    let rest = match ui_rest(raw_path) {
        Ok(rest) => rest,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({ "detail": format!("refused UI path: {why}") }))).into_response(),
    };
    if headers
        .get("service-worker")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("script"))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "detail": "an add-on UI cannot register a service worker" })),
        )
            .into_response();
    }
    let base = manifest.base_url();
    if let Some(reason) = crate::addon_proxy::plaintext_refusal(addon, &manifest.base_url_env, &base) {
        return unavailable(addon, reason, "misconfigured");
    }
    let mut url = format!("{}{}/{}", base.trim_end_matches('/'), ui.upstream_path.trim_end_matches('/'), rest);
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url = format!("{url}?{q}");
    }
    let timeout = Duration::from_secs(ui.timeout_secs.unwrap_or(manifest.timeout_secs));
    let up_method = if *method == Method::HEAD { reqwest::Method::HEAD } else { reqwest::Method::GET };
    let mut req = crate::tls::cluster_client().request(up_method, &url).timeout(timeout);
    for (name, value) in crate::addon_proxy::caller_headers(Some(r)) {
        req = req.header(name, value);
    }
    for name in PASSED_REQUEST_HEADERS {
        for v in headers.get_all(*name) {
            req = req.header(*name, v.as_bytes());
        }
    }
    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            let chain = crate::addon_proxy::error_chain(&e);
            let reason = crate::addon_proxy::classify_send_error(&chain, e.is_timeout());
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": format!("{} unreachable ({reason})", crate::addon_proxy::container_of(addon)),
                    "addon": addon,
                    "state": "unreachable",
                    "reason": reason,
                })),
            )
                .into_response();
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut upstream_headers = HeaderMap::new();
    for (k, v) in resp.headers() {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_str().as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
            upstream_headers.append(name, value);
        }
    }
    let csp = csp_for(request_host(headers));
    let out_headers = sanitise_response_headers(&upstream_headers, &ui.upstream_path, &csp);
    let body = if *method == Method::HEAD {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from_stream(resp.bytes_stream())
    };
    let mut out = Response::new(body);
    *out.status_mut() = status;
    *out.headers_mut() = out_headers;
    out
}

/// The browser-facing headers for an add-on UI response: the allow-list, a
/// `Location` only when it stays on this origin, and the gateway's own
/// security headers, always.
pub fn sanitise_response_headers(upstream: &HeaderMap, upstream_path: &str, csp: &str) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in PASSED_RESPONSE_HEADERS {
        for v in upstream.get_all(*name) {
            if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
                out.append(n, v.clone());
            }
        }
    }
    if let Some(loc) = upstream.get(header::LOCATION).and_then(|v| v.to_str().ok()) {
        if let Some(safe) = safe_location(loc, upstream_path) {
            if let Ok(v) = HeaderValue::from_str(&safe) {
                out.insert(header::LOCATION, v);
            }
        }
    }
    // The gateway's policy is ADDED, never replaced: with the add-on's own
    // (if any) the browser enforces both, so the add-on can only narrow it.
    if let Ok(v) = HeaderValue::from_str(csp) {
        out.append(header::CONTENT_SECURITY_POLICY, v);
    }
    out.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    out.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    out.insert(HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    if !out.contains_key(header::CACHE_CONTROL) {
        out.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    }
    out
}

/// A redirect the browser may follow: on this origin only (no scheme, no
/// `//host`, no `\`). The add-on's own `<upstream_path>/…` is rewritten to
/// the origin's `/…`.
pub fn safe_location(loc: &str, upstream_path: &str) -> Option<String> {
    let loc = loc.trim();
    if loc.is_empty() || loc.contains('\\') || loc.starts_with("//") || loc.chars().any(|c| c.is_control()) {
        return None;
    }
    // A scheme (`https:`, `javascript:`): a ':' before any '/', '?' or '#'.
    let head = loc.split(['/', '?', '#']).next().unwrap_or("");
    if head.contains(':') {
        return None;
    }
    let up = upstream_path.trim_end_matches('/');
    if !up.is_empty() {
        if let Some(tail) = loc.strip_prefix(up) {
            if tail.is_empty() || tail.starts_with('/') || tail.starts_with('?') {
                let tail = tail.strip_prefix('/').unwrap_or(tail);
                return Some(format!("/{tail}"));
            }
        }
    }
    Some(loc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use serde_json::{json, Value};

    fn ctx(sub: &str, role: Role) -> crate::auth::RequesterCtx {
        crate::auth::RequesterCtx { sub: sub.into(), scopes: vec!["read".into()], role, harness: None, act: None }
    }

    fn with_ui(ui: Value) -> Result<AddonManifest, String> {
        let mut v = crate::addon_proxy::tests::sample_json();
        v["ui"] = ui;
        let m: AddonManifest = serde_json::from_value(v).map_err(|e| e.to_string())?;
        crate::addon_proxy::validate(&m, "evolve").map(|()| m)
    }

    #[test]
    fn a_ui_key_parses_and_validates() {
        let m = with_ui(json!({"min_role": "user", "title": "Example"})).unwrap();
        let ui = m.ui.unwrap();
        assert_eq!(ui.upstream_path, "/", "the default strips the prefix and forwards the rest as is");
        assert!(ui.permits(Role::User));
        let m = with_ui(json!({"upstream_path": "/ui"})).unwrap();
        let ui = m.ui.unwrap();
        assert!(!ui.permits(Role::User) && ui.permits(Role::Operator), "absent min_role is operator");
    }

    #[test]
    fn a_bad_ui_key_refuses_the_manifest() {
        for (bad, needle) in [
            (json!({"upstream_path": "ui"}), "upstream_path"),
            (json!({"upstream_path": "/ui/../x"}), "upstream_path"),
            (json!({"upstream_path": "/ui/{id}"}), "{param}"),
            (json!({"min_role": "viewer"}), "never read as user"),
            (json!({"timeout_secs": 0}), "timeout"),
            (json!({"title": "<script>"}), "title"),
            (json!({"prefix": "/x"}), "prefix"),
        ] {
            let e = with_ui(bad.clone()).expect_err(&bad.to_string());
            assert!(e.contains(needle), "{bad}: {e}");
        }
    }

    #[test]
    fn a_ui_only_manifest_is_valid() {
        let mut v = crate::addon_proxy::tests::sample_json();
        v["routes"] = json!([]);
        assert!(serde_json::from_value::<AddonManifest>(v.clone())
            .map_err(|e| e.to_string())
            .and_then(|m| crate::addon_proxy::validate(&m, "evolve"))
            .unwrap_err()
            .contains("no routes"));
        v["ui"] = json!({"min_role": "user"});
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        crate::addon_proxy::validate(&m, "evolve").expect("a UI alone is something to serve");
    }

    #[test]
    fn ports_are_deterministic_distinct_and_inside_the_range() {
        assert_eq!(parse_port_range(DEFAULT_PORT_RANGE), Ok((8450, 8499)));
        for bad in ["8450", "80-90", "9000-8000", "x-y", "2000-4000"] {
            assert!(parse_port_range(bad).is_err(), "{bad}");
        }
        let names: Vec<String> = ["example-addon", "other", "third"].iter().map(|s| s.to_string()).collect();
        let a = allocate_ports(&names, (8450, 8499));
        let mut rev = names.clone();
        rev.reverse();
        assert_eq!(a, allocate_ports(&rev, (8450, 8499)), "order of discovery does not matter");
        let ports: std::collections::HashSet<u16> = a.values().copied().collect();
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().all(|p| (8450..=8499).contains(p)));
        // A range smaller than the set: the overflow gets no port.
        let tiny = allocate_ports(&names, (9000, 9001));
        assert_eq!(tiny.len(), 2);
    }

    #[test]
    fn a_code_is_single_use_bound_to_its_addon_and_opens_a_session() {
        let grant = |addon: &str| Grant { addon: addon.into(), requester: ctx("alice", Role::User), token: "tok".into(), token_exp: usize::MAX / 2 };
        let code = mint_code(grant("example-addon"));
        assert!(redeem_code(&code, "other").is_none(), "another add-on's origin");
        assert!(redeem_code(&code, "example-addon").is_none(), "tried once, gone");
        let code = mint_code(grant("example-addon"));
        let g = redeem_code(&code, "example-addon").expect("redeems once");
        assert!(redeem_code(&code, "example-addon").is_none());
        let sid = open_session(g);
        assert_eq!(session(&sid, "example-addon").unwrap().requester.sub, "alice");
        assert!(session(&sid, "other").is_none(), "a session opens only its own add-on");
        end_session(&sid);
        assert!(session(&sid, "example-addon").is_none());
        assert_eq!(CODE_TTL, Duration::from_secs(30));
    }

    #[test]
    fn the_cookie_is_per_addon_host_only_and_never_the_token() {
        let c = session_cookie("example-addon", "sid123", 600).to_string();
        assert!(c.starts_with("noo_ui_example-addon=sid123"), "{c}");
        assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Strict"), "{c}");
        assert!(c.contains("Path=/") && !c.contains("Domain"), "host-only: {c}");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("noo_ui_other=x; noo_ui_example-addon=sid123; noo_refresh=r"));
        assert_eq!(cookie_value(&h, &cookie_name("example-addon")).as_deref(), Some("sid123"));
        assert_eq!(cookie_value(&h, &cookie_name("example")).as_deref(), None, "exact name only");
    }

    #[test]
    fn the_origin_rule_refuses_cross_origin_writes_and_sockets() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("noo-controller.tail.ts.net:8461"));
        // A plain read with no Origin (a navigation, an <img>): fine.
        assert!(origin_rule(&Method::GET, &h, 8461).is_ok());
        // A write: needs our Origin AND the header.
        assert!(origin_rule(&Method::POST, &h, 8461).is_err());
        h.insert(header::ORIGIN, HeaderValue::from_static("https://noo-controller.tail.ts.net:8461"));
        assert!(origin_rule(&Method::POST, &h, 8461).unwrap_err().contains("X-Noo-Addon-Request"));
        h.insert(ADDON_REQUEST_HEADER, HeaderValue::from_static("1"));
        assert!(origin_rule(&Method::POST, &h, 8461).is_ok());
        assert!(origin_rule(&Method::DELETE, &h, 8461).is_ok());
        // Another add-on's origin (same host, other port), and the console.
        for evil in ["https://noo-controller.tail.ts.net:8462", "https://noo-controller.tail.ts.net", "https://evil.example:8461", "http://noo-controller.tail.ts.net:8461", "null"] {
            h.insert(header::ORIGIN, HeaderValue::from_str(evil).unwrap());
            assert!(origin_rule(&Method::POST, &h, 8461).is_err(), "{evil}");
            assert!(origin_rule(&Method::GET, &h, 8461).is_err(), "a cross-origin read carrying Origin: {evil}");
        }
        // A socket upgrade without Origin is refused (a browser always sends it).
        let mut ws = HeaderMap::new();
        ws.insert(header::HOST, HeaderValue::from_static("noo-controller.tail.ts.net:8461"));
        ws.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(origin_rule(&Method::GET, &ws, 8461).is_err());
        ws.insert(header::ORIGIN, HeaderValue::from_static("https://noo-controller.tail.ts.net:8461"));
        assert!(origin_rule(&Method::GET, &ws, 8461).is_ok());
        // The front proxy's X-Forwarded-Host wins over Host.
        let mut fwd = HeaderMap::new();
        fwd.insert(header::HOST, HeaderValue::from_static("100.64.0.1:8461"));
        fwd.insert("x-forwarded-host", HeaderValue::from_static("noo-controller.tail.ts.net:8461"));
        fwd.insert(header::ORIGIN, HeaderValue::from_static("https://noo-controller.tail.ts.net:8461"));
        fwd.insert(ADDON_REQUEST_HEADER, HeaderValue::from_static("1"));
        assert!(origin_rule(&Method::PUT, &fwd, 8461).is_ok());
    }

    #[test]
    fn only_the_addons_own_paths_are_served_on_its_origin() {
        for p in ["/api/config", "/api/auth/login", "/ws/collab", "/__noo/other", "/api"] {
            assert!(is_reserved_on_origin(p), "{p}");
        }
        for p in ["/", "/index.html", "/assets/app.js"] {
            assert!(!is_reserved_on_origin(p), "{p}");
        }
        assert!(is_ui_session_path("/api/addons/example-addon/ui-session"));
        assert!(!is_ui_session_path("/api/addons/a/b/ui-session"));
    }

    #[test]
    fn traversal_and_encoding_are_refused() {
        assert_eq!(ui_rest("/"), Ok(""));
        assert_eq!(ui_rest("/app.js"), Ok("app.js"));
        assert_eq!(ui_rest("/assets/v1.2/x.wasm"), Ok("assets/v1.2/x.wasm"));
        assert_eq!(ui_rest("/assets/"), Ok("assets/"));
        for bad in ["/../../etc/passwd", "/a/../../b", "/./x", "/%2e%2e/x", "/a%2fb", "/a%5cb", "/a\\b", "//etc/passwd", "/a b", "/a:b"] {
            assert!(ui_rest(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn response_headers_are_allow_listed_and_the_gateway_csp_is_always_added() {
        let mut up = HeaderMap::new();
        up.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        up.insert(header::ETAG, HeaderValue::from_static("\"v1\""));
        up.append(header::SET_COOKIE, HeaderValue::from_static("session=x; Path=/"));
        up.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        up.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=0"));
        up.insert(HeaderName::from_static("clear-site-data"), HeaderValue::from_static("\"*\""));
        up.insert(HeaderName::from_static("service-worker-allowed"), HeaderValue::from_static("/"));
        up.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("ALLOWALL"));
        up.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src *"));
        let csp = csp_for(Some("noo-controller.tail.ts.net"));
        let out = sanitise_response_headers(&up, "/", &csp);
        assert_eq!(out.get(header::CONTENT_TYPE).unwrap(), "text/html");
        assert_eq!(out.get(header::ETAG).unwrap(), "\"v1\"");
        for dropped in ["set-cookie", "access-control-allow-origin", "strict-transport-security", "clear-site-data", "service-worker-allowed", "x-frame-options"] {
            assert!(out.get(dropped).is_none(), "{dropped} must be dropped");
        }
        let all: Vec<&str> = out.get_all(header::CONTENT_SECURITY_POLICY).iter().map(|v| v.to_str().unwrap()).collect();
        assert!(all.contains(&csp.as_str()), "the gateway's policy is always present: {all:?}");
        assert!(all.contains(&"default-src *"), "the add-on's own policy is kept beside it");
        assert_eq!(out.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(out.get(header::CACHE_CONTROL).unwrap(), "private, no-cache");
    }

    #[test]
    fn the_csp_keeps_everything_on_this_origin_and_lets_only_the_console_frame_it() {
        if std::env::var("NOO_CONSOLE_ORIGIN").is_ok() {
            return;
        }
        let csp = csp_for(Some("noo-controller.tail.ts.net"));
        assert!(csp.contains("default-src 'self'") && csp.contains("connect-src 'self'") && csp.contains("script-src 'self'"));
        assert!(csp.contains("object-src 'none'") && csp.contains("base-uri 'none'"));
        assert!(csp.contains("frame-ancestors https://noo-controller.tail.ts.net https://noo-controller.tail.ts.net:"), "{csp}");
        assert!(csp_for(None).contains("frame-ancestors 'none'"));
        // A Host that is not a plain name never reaches the header.
        assert_eq!(plain_hostname("evil;script-src *"), None);
        assert_eq!(plain_hostname("noo-controller.tail.ts.net:8461"), Some("noo-controller.tail.ts.net"));
    }

    #[test]
    fn redirects_stay_on_this_origin() {
        assert_eq!(safe_location("app/", "/").as_deref(), Some("app/"));
        assert_eq!(safe_location("/x", "/").as_deref(), Some("/x"));
        assert_eq!(safe_location("/ui/login", "/ui").as_deref(), Some("/login"));
        for bad in ["https://evil.example/", "//evil.example/x", "javascript:alert(1)", "/\\evil"] {
            assert_eq!(safe_location(bad, "/"), None, "{bad}");
        }
    }

    /// Permission before the path is even looked at, and the identity sent
    /// upstream is the verified one only.
    #[test]
    fn serve_ui_checks_permission_before_the_path_or_the_fetch() {
        let src = include_str!("addon_ui.rs");
        let body = src.split("pub(crate) async fn serve_ui(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let permits = body.find("ui.permits(r.role)").unwrap();
        let rest = body.find("ui_rest(raw_path)").unwrap();
        let send = body.find(".send()").unwrap();
        assert!(permits < rest && rest < send);
        assert!(body.contains("caller_headers(Some(r))"));
        assert!(!body.contains("headers.iter()"), "client headers are allow-listed, never copied wholesale");
    }

    /// The origin gate reads this add-on's cookie and never a bearer.
    #[test]
    fn the_gate_takes_only_the_addons_cookie() {
        let src = include_str!("addon_ui.rs");
        let body = src.split("async fn gate(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(body.contains("cookie_name(&o.addon)"));
        assert!(!body.contains("AUTHORIZATION") && !body.contains("verify_token"), "no bearer on an add-on origin");
        assert!(body.find("origin_rule(").unwrap() < body.find("cookie_value(").unwrap());
        assert!(body.contains("session_floor::refuses"));
    }

    #[tokio::test]
    async fn a_write_is_refused_and_an_unknown_addon_has_no_ui() {
        let h = HeaderMap::new();
        let resp = serve_ui("example-addon", &Method::POST, "/", None, &h, None).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let resp = serve_ui("example-addon", &Method::GET, "/", None, &h, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
