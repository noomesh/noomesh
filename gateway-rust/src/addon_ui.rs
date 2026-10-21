// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An HTTP add-on's own web UI, served through the gateway.
//!
//! The manifest's top-level `ui` key (`{"upstream_path": "/ui", "min_role":
//! "user"}`) makes `/addons/<addon>/ui/<rest>` a proxied GET/HEAD to
//! `<upstream><upstream_path>/<rest>`. The gateway path is fixed: `/addons/`
//! is a namespace no core route uses, and the add-on's name is a segment of
//! it, so a UI can neither shadow a core path nor another add-on's UI.
//!
//! ## Authentication: a path-scoped cookie the console sets
//!
//! A browser navigating to a page sends no `Authorization` header, and the
//! console keeps its token in script memory (`localStorage`), not a cookie.
//! So the console opens a UI with `POST /api/addons/<addon>/ui-session`
//! (Bearer), which checks `ui.min_role` and answers with a cookie:
//! `noo_addon_ui=<the same access token>; Path=/addons/<addon>/ui; HttpOnly;
//! Secure; SameSite=Strict; Max-Age=<until the token expires>`. The front
//! door reads that cookie ONLY on a GET/HEAD under `/addons/<name>/ui`
//! ([`cookie_token`]), and from there the request is authenticated exactly as
//! a bearer would be (signature, session floor, the tier gate asking
//! [`crate::addon_proxy::mounted_get_allows`], which applies `ui.min_role`).
//! Nothing new is minted: the cookie holds no more than the console already
//! holds, it reaches only that add-on's UI paths, and those paths do nothing
//! but GET/HEAD. A logout refuses it like any token (session floor).
//!
//! ## What the browser gets back
//!
//! - status and body as the add-on sent them (streamed, not buffered);
//! - response headers from an ALLOW-list ([`sanitise_response_headers`]):
//!   `Set-Cookie`, CORS, HSTS, `Clear-Site-Data`, `Service-Worker-Allowed`,
//!   `Refresh`, `Link`, reporting headers and anything unknown are dropped;
//!   `Location` survives only when it stays inside this add-on's UI;
//! - the gateway's own Content-Security-Policy ([`GATEWAY_CSP`]) ALWAYS, in
//!   addition to any CSP the add-on sent. Two policies are both enforced by
//!   the browser, so the add-on's can only narrow the gateway's, never widen
//!   it: scripts, styles, fetches and sockets come from this origin only, no
//!   framing by anything but the console, no plugins, no `<base>`;
//! - `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
//!   `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control:
//!   private, no-cache` when the add-on sent none.
//!
//! A service-worker script fetch (`Service-Worker: script`) is refused: a
//! worker would outlive the page and keep intercepting this path after the
//! add-on is switched off.
//!
//! ## What a UI is trusted with
//!
//! The UI runs on the gateway's origin, so its scripts can read what the
//! console stored for this browser (the access token) and call the API as the
//! signed-in person. That is the point (its socket and API calls need the
//! person's credential), and it is also the trust an operator gives an add-on
//! by enabling it: the lock is signed and launcher-verified before any of
//! this is mounted. The CSP keeps that authority on this origin (no
//! exfiltration to another host, no third-party script).

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, RawQuery},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::addon_proxy::{AddonManifest, UiSpec};
use crate::state::AppState;

/// The cookie the front door accepts on a UI path.
pub const UI_COOKIE: &str = "noo_addon_ui";
/// Every add-on UI lives under here: `/addons/<addon>/ui/…`.
pub const UI_NAMESPACE: &str = "/addons/";

/// The policy added to every UI response. `'wasm-unsafe-eval'` lets a UI run
/// WebAssembly (an audio codec) without allowing `eval`; `blob:` and
/// `mediastream:` cover audio worklets, recorded media and live capture.
pub const GATEWAY_CSP: &str = "default-src 'self'; \
    script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self' 'unsafe-inline'; \
    img-src 'self' data: blob:; \
    media-src 'self' blob: mediastream:; \
    font-src 'self' data:; \
    connect-src 'self'; \
    worker-src 'self' blob:; \
    object-src 'none'; \
    base-uri 'none'; \
    form-action 'self'; \
    frame-ancestors 'self'";

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

/// The core routes that serve every add-on's UI. Mounted once; each request
/// finds its add-on's manifest, so an add-on with no `ui` key answers 404.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/addons/{addon_id}/ui-session", post(ui_session))
        .route("/addons/{addon_id}/ui", get(ui_root))
        .route("/addons/{addon_id}/ui/", get(ui_page))
        .route("/addons/{addon_id}/ui/{*rest}", get(ui_page))
}

/// The add-on a UI path belongs to: `/addons/<name>/ui` or anything under
/// `/addons/<name>/ui/`, with a valid add-on name. `None` for anything else.
pub fn ui_addon_of(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(UI_NAMESPACE)?;
    let (addon, tail) = rest.split_once('/')?;
    if !crate::addon_registry::name_ok(addon) {
        return None;
    }
    (tail == "ui" || tail.starts_with("ui/")).then_some(addon)
}

/// Is `path` the ui-session route? (The tier gate lets a User POST it; the
/// handler applies the UI's own `min_role`.)
pub fn is_ui_session_path(path: &str) -> bool {
    path.strip_prefix("/api/addons/")
        .and_then(|r| r.strip_suffix("/ui-session"))
        .is_some_and(crate::addon_registry::name_ok)
}

/// The UI cookie's token, on a GET/HEAD to a UI path only. Everywhere else a
/// cookie is not a credential.
pub fn cookie_token(method: &Method, path: &str, headers: &HeaderMap) -> Option<String> {
    if !matches!(*method, Method::GET | Method::HEAD) || ui_addon_of(path).is_none() {
        return None;
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(UI_COOKIE).and_then(|r| r.strip_prefix('=')))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// The rest of a UI path below `/addons/<addon>/ui/`, from the RAW request
/// path, or why it is refused. Each segment must be plain (`[A-Za-z0-9._~@+-]`,
/// not `.` or `..`); a `%` anywhere (an encoded `/`, `.` or `\`) is refused
/// outright rather than decoded, so nothing can climb out of the upstream
/// prefix. An empty rest is the index; a trailing `/` is kept.
pub fn ui_rest<'a>(raw_path: &'a str, addon: &str) -> Result<&'a str, &'static str> {
    let prefix = format!("{UI_NAMESPACE}{addon}/ui/");
    let rest = raw_path.strip_prefix(prefix.as_str()).ok_or("not a path of this add-on's UI")?;
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

/// POST /api/addons/{addon_id}/ui-session — open an add-on's web UI for the signed-in person: checks the UI's `min_role` and sets an HttpOnly, SameSite=Strict cookie scoped to `/addons/{addon_id}/ui` that lasts as long as the presented access token. The console calls it before linking to `/addons/{addon_id}/ui/`. 401 without a person's bearer token, 403 below the UI's role, 404 when the add-on serves no UI, 503 when it is off.
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
    // The bearer the front door just verified, from the header only (a UI
    // cookie is never accepted on this path, so it cannot renew itself).
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
    let now = chrono::Utc::now().timestamp().max(0) as usize;
    let max_age = claims.exp.saturating_sub(now).max(1);
    let cookie = session_cookie(&addon_id, token, max_age as i64);
    let mut resp = Json(json!({
        "url": format!("{UI_NAMESPACE}{addon_id}/ui/"),
        "expires_at": claims.exp,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The UI cookie: HttpOnly (UI scripts never see it), Secure (the gateway
/// serves TLS only), SameSite=Strict (another site cannot make the browser
/// send it), and scoped to this add-on's UI path.
pub fn session_cookie(addon: &str, token: &str, max_age_secs: i64) -> axum_extra::extract::cookie::Cookie<'static> {
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let mut c = Cookie::new(UI_COOKIE, token.to_string());
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Strict);
    c.set_path(format!("{UI_NAMESPACE}{addon}/ui"));
    c.set_max_age(time::Duration::seconds(max_age_secs));
    c
}

/// GET /addons/{addon_id}/ui — redirects to `/addons/{addon_id}/ui/`, so the UI's relative asset paths resolve under it.
async fn ui_root(Path(addon_id): Path<String>) -> Response {
    if !crate::addon_registry::name_ok(&addon_id) {
        return not_found(&addon_id);
    }
    (
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, format!("{UI_NAMESPACE}{addon_id}/ui/"))],
    )
        .into_response()
}

/// GET /addons/{addon_id}/ui/{rest} — an add-on's web UI, proxied from the add-on's own service (GET and HEAD only). Authenticated by bearer or the cookie `POST /api/addons/{addon_id}/ui-session` sets; the UI's `min_role` applies; path traversal and percent-encoded segments are refused with 400; response headers are allow-listed and the gateway's Content-Security-Policy is always added.
async fn ui_page(
    Path(params): Path<HashMap<String, String>>,
    method: Method,
    uri: Uri,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Response {
    let addon = params.get("addon_id").cloned().unwrap_or_default();
    let requester = ctx.map(|axum::Extension(r)| r);
    serve_ui(&addon, &method, uri.path(), query.as_deref(), &headers, requester.as_ref()).await
}

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
    // Permission before the path is read or anything is fetched.
    if let Some(r) = requester {
        if !ui.permits(r.role) {
            return ui_forbidden(addon, &ui);
        }
    }
    let rest = match ui_rest(raw_path, addon) {
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
    let timeout = std::time::Duration::from_secs(ui.timeout_secs.unwrap_or(manifest.timeout_secs));
    let up_method = if *method == Method::HEAD { reqwest::Method::HEAD } else { reqwest::Method::GET };
    let mut req = crate::tls::cluster_client().request(up_method, &url).timeout(timeout);
    for (name, value) in crate::addon_proxy::caller_headers(requester) {
        req = req.header(name, value);
    }
    for name in PASSED_REQUEST_HEADERS {
        for v in headers.get_all(*name) {
            req = req.header(*name, v.as_bytes());
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
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
    let out_headers = sanitise_response_headers(&upstream_headers, addon, &ui.upstream_path);
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
/// `Location` only when it stays in this add-on's UI, and the gateway's own
/// security headers, always.
pub fn sanitise_response_headers(upstream: &HeaderMap, addon: &str, upstream_path: &str) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in PASSED_RESPONSE_HEADERS {
        for v in upstream.get_all(*name) {
            if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
                out.append(n, v.clone());
            }
        }
    }
    if let Some(loc) = upstream.get(header::LOCATION).and_then(|v| v.to_str().ok()) {
        if let Some(safe) = safe_location(loc, addon, upstream_path) {
            if let Ok(v) = HeaderValue::from_str(&safe) {
                out.insert(header::LOCATION, v);
            }
        }
    }
    // The gateway's policy is ADDED, never replaced: with the add-on's own
    // (if any) the browser enforces both, so the add-on can only narrow it.
    out.append(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(GATEWAY_CSP));
    out.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    out.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    out.insert(HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    if !out.contains_key(header::CACHE_CONTROL) {
        out.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    }
    out
}

/// A redirect the browser may follow: relative (no scheme, no `//host`, no
/// `\`), and when it is an absolute path, inside this add-on's UI. The
/// add-on's own `<upstream_path>/…` is rewritten to the gateway path. Anything
/// else (another host, another gateway path) is dropped.
pub fn safe_location(loc: &str, addon: &str, upstream_path: &str) -> Option<String> {
    let loc = loc.trim();
    if loc.is_empty() || loc.contains('\\') || loc.starts_with("//") || loc.chars().any(|c| c.is_control()) {
        return None;
    }
    // A scheme (`https:`, `javascript:`): a ':' before any '/', '?' or '#'.
    let head = loc.split(['/', '?', '#']).next().unwrap_or("");
    if head.contains(':') {
        return None;
    }
    let ui = format!("{UI_NAMESPACE}{addon}/ui");
    if let Some(abs) = loc.strip_prefix('/') {
        let abs = format!("/{abs}");
        if abs == ui || abs.starts_with(&format!("{ui}/")) || abs.starts_with(&format!("{ui}?")) {
            return Some(abs);
        }
        let up = upstream_path.trim_end_matches('/');
        if let Some(tail) = abs.strip_prefix(up) {
            if tail.is_empty() || tail.starts_with('/') || tail.starts_with('?') {
                let tail = tail.strip_prefix('/').unwrap_or(tail);
                return Some(format!("{ui}/{tail}"));
            }
        }
        return None;
    }
    Some(loc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use serde_json::{json, Value};

    fn with_ui(ui: Value) -> Result<AddonManifest, String> {
        let mut v = crate::addon_proxy::tests::sample_json();
        v["ui"] = ui;
        let m: AddonManifest = serde_json::from_value(v).map_err(|e| e.to_string())?;
        crate::addon_proxy::validate(&m, "evolve").map(|()| m)
    }

    #[test]
    fn a_ui_key_parses_and_validates() {
        let m = with_ui(json!({"upstream_path": "/ui", "min_role": "user", "title": "Example"})).unwrap();
        let ui = m.ui.unwrap();
        assert_eq!(ui.upstream_path, "/ui");
        assert!(ui.permits(Role::User));
        // Absent min_role is operator, like a route.
        let m = with_ui(json!({"upstream_path": "/ui"})).unwrap();
        let ui = m.ui.unwrap();
        assert!(!ui.permits(Role::User) && ui.permits(Role::Operator));
    }

    #[test]
    fn a_bad_ui_key_refuses_the_manifest() {
        for (bad, needle) in [
            (json!({"upstream_path": "ui"}), "upstream_path"),
            (json!({"upstream_path": "/ui/../x"}), "upstream_path"),
            (json!({"upstream_path": "/ui/{id}"}), "{param}"),
            (json!({"upstream_path": "/ui", "min_role": "viewer"}), "never read as user"),
            (json!({"upstream_path": "/ui", "timeout_secs": 0}), "timeout"),
            (json!({"upstream_path": "/ui", "title": "<script>"}), "title"),
            (json!({"upstream_path": "/ui", "prefix": "/x"}), "prefix"),
            (json!({"path": "/ui"}), "upstream_path"),
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
        v["ui"] = json!({"upstream_path": "/ui", "min_role": "user"});
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        crate::addon_proxy::validate(&m, "evolve").expect("a UI alone is something to serve");
    }

    #[test]
    fn ui_paths_are_recognised_by_shape() {
        assert_eq!(ui_addon_of("/addons/example-addon/ui"), Some("example-addon"));
        assert_eq!(ui_addon_of("/addons/example-addon/ui/"), Some("example-addon"));
        assert_eq!(ui_addon_of("/addons/example-addon/ui/app.js"), Some("example-addon"));
        assert_eq!(ui_addon_of("/addons/example-addon/uix"), None);
        assert_eq!(ui_addon_of("/addons/example-addon/api"), None);
        assert_eq!(ui_addon_of("/addons/../ui/x"), None);
        assert_eq!(ui_addon_of("/api/addons/example-addon/ui/x"), None);
        assert!(is_ui_session_path("/api/addons/example-addon/ui-session"));
        assert!(!is_ui_session_path("/api/addons/example-addon/cli-piece"));
        assert!(!is_ui_session_path("/api/addons/a/b/ui-session"));
    }

    #[test]
    fn traversal_and_encoding_are_refused() {
        let a = "example-addon";
        assert_eq!(ui_rest("/addons/example-addon/ui/", a), Ok(""));
        assert_eq!(ui_rest("/addons/example-addon/ui/app.js", a), Ok("app.js"));
        assert_eq!(ui_rest("/addons/example-addon/ui/assets/v1.2/x.wasm", a), Ok("assets/v1.2/x.wasm"));
        assert_eq!(ui_rest("/addons/example-addon/ui/assets/", a), Ok("assets/"));
        for bad in [
            "/addons/example-addon/ui/../../api/config",
            "/addons/example-addon/ui/a/../../b",
            "/addons/example-addon/ui/./x",
            "/addons/example-addon/ui/%2e%2e/x",
            "/addons/example-addon/ui/a%2fb",
            "/addons/example-addon/ui/a%5cb",
            "/addons/example-addon/ui/a\\b",
            "/addons/example-addon/ui//etc/passwd",
            "/addons/example-addon/ui/a b",
            "/addons/example-addon/ui/a:b",
            "/addons/other/ui/x",
        ] {
            assert!(ui_rest(bad, a).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_cookie_is_a_credential_only_on_a_ui_read() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("theme=dark; noo_addon_ui=abc.def.ghi; x=1"));
        assert_eq!(cookie_token(&Method::GET, "/addons/example-addon/ui/app.js", &h).as_deref(), Some("abc.def.ghi"));
        assert_eq!(cookie_token(&Method::HEAD, "/addons/example-addon/ui/", &h).as_deref(), Some("abc.def.ghi"));
        assert_eq!(cookie_token(&Method::POST, "/addons/example-addon/ui/app.js", &h), None, "never on a write");
        assert_eq!(cookie_token(&Method::GET, "/api/config", &h), None, "never outside a UI");
        assert_eq!(cookie_token(&Method::GET, "/api/addons/example-addon/ui-session", &h), None);
        assert_eq!(cookie_token(&Method::GET, "/ws/addons/example-addon/stream", &h), None);
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("noo_addon_uix=zzz"));
        assert_eq!(cookie_token(&Method::GET, "/addons/example-addon/ui/", &h), None, "exact name only");
    }

    #[test]
    fn the_session_cookie_is_httponly_strict_secure_and_path_scoped() {
        let c = session_cookie("example-addon", "tok", 600).to_string();
        assert!(c.starts_with("noo_addon_ui=tok"), "{c}");
        assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Strict"), "{c}");
        assert!(c.contains("Path=/addons/example-addon/ui"), "{c}");
        assert!(c.contains("Max-Age=600"), "{c}");
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
        let out = sanitise_response_headers(&up, "example-addon", "/ui");
        assert_eq!(out.get(header::CONTENT_TYPE).unwrap(), "text/html");
        assert_eq!(out.get(header::ETAG).unwrap(), "\"v1\"");
        for dropped in ["set-cookie", "access-control-allow-origin", "strict-transport-security", "clear-site-data", "service-worker-allowed", "x-frame-options"] {
            assert!(out.get(dropped).is_none(), "{dropped} must be dropped");
        }
        let csp: Vec<&str> = out.get_all(header::CONTENT_SECURITY_POLICY).iter().map(|v| v.to_str().unwrap()).collect();
        assert!(csp.contains(&GATEWAY_CSP), "the gateway's policy is always present: {csp:?}");
        assert!(csp.contains(&"default-src *"), "the add-on's own policy is kept beside it (both are enforced, so it can only narrow)");
        assert_eq!(out.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(out.get(header::CACHE_CONTROL).unwrap(), "private, no-cache");
        // The gateway's CSP keeps every fetch on this origin.
        assert!(GATEWAY_CSP.contains("connect-src 'self'") && GATEWAY_CSP.contains("script-src 'self'"));
        assert!(GATEWAY_CSP.contains("frame-ancestors 'self'") && GATEWAY_CSP.contains("object-src 'none'"));
    }

    #[test]
    fn redirects_stay_inside_the_addons_ui() {
        let a = "example-addon";
        assert_eq!(safe_location("app/", a, "/ui").as_deref(), Some("app/"));
        assert_eq!(safe_location("/addons/example-addon/ui/x", a, "/ui").as_deref(), Some("/addons/example-addon/ui/x"));
        assert_eq!(safe_location("/ui/login", a, "/ui").as_deref(), Some("/addons/example-addon/ui/login"));
        assert_eq!(safe_location("/ui", a, "/ui").as_deref(), Some("/addons/example-addon/ui/"));
        for bad in ["https://evil.example/", "//evil.example/x", "javascript:alert(1)", "/api/config", "/addons/other/ui/x", "/uix", "/\\evil"] {
            assert_eq!(safe_location(bad, a, "/ui"), None, "{bad}");
        }
    }

    /// Permission before the path is even looked at: a User on an operator
    /// UI gets 403 (here the add-on is off in tests, so a permitted caller
    /// reaches the 503/404 instead, never a 403).
    #[test]
    fn serve_ui_checks_permission_before_the_path_or_the_fetch() {
        let src = include_str!("addon_ui.rs");
        let body = src.split("pub(crate) async fn serve_ui(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let permits = body.find("ui.permits(r.role)").unwrap();
        let rest = body.find("ui_rest(raw_path").unwrap();
        let send = body.find(".send()").unwrap();
        assert!(permits < rest && rest < send);
        assert!(body.contains("caller_headers(requester)"));
        assert!(!body.contains("headers.iter()"), "client headers are allow-listed, never copied wholesale");
    }

    #[tokio::test]
    async fn a_write_is_refused_and_an_unknown_addon_has_no_ui() {
        let h = HeaderMap::new();
        let resp = serve_ui("example-addon", &Method::POST, "/addons/example-addon/ui/", None, &h, None).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let resp = serve_ui("example-addon", &Method::GET, "/addons/example-addon/ui/", None, &h, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The front door's view: a User reads a UI exactly when `ui.min_role`
    /// says so (`mounted_get_allows` → `get_allows`).
    #[test]
    fn the_tier_gate_applies_the_ui_role() {
        let user_ui = with_ui(json!({"upstream_path": "/ui", "min_role": "user"})).unwrap();
        let op_ui = with_ui(json!({"upstream_path": "/ui"})).unwrap();
        let read = vec!["read".to_string()];
        assert!(crate::addon_proxy::tests::get_allows_for_test(&[user_ui.clone()], &read, Role::User, "/addons/evolve/ui/app.js"));
        assert!(!crate::addon_proxy::tests::get_allows_for_test(&[op_ui.clone()], &read, Role::User, "/addons/evolve/ui/app.js"));
        assert!(crate::addon_proxy::tests::get_allows_for_test(&[op_ui], &read, Role::Operator, "/addons/evolve/ui/"));
        assert!(!crate::addon_proxy::tests::get_allows_for_test(&[user_ui], &read, Role::User, "/addons/other/ui/"), "no UI, no read");
    }
}
