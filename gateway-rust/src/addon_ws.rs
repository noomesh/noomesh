// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket routes of an HTTP add-on: a manifest route with `"method": "WS"`.
//!
//! The add-on's socket is reached through the gateway exactly like the
//! gateway's own sockets are, and nothing about who is calling is left to
//! the add-on to work out:
//!
//! 1. **Authenticated before the upgrade.** A browser cannot set
//!    `Authorization` on a WebSocket, and a bearer in a URL lands in every
//!    access log on the way, so an add-on socket takes one of two
//!    credentials and never `?token=` (the front door ignores `?token=` under
//!    `/ws/addons/`):
//!    - a **ticket**: the page (holding the person's access token) calls
//!      `POST /api/addons/<addon>/ws-ticket` with `Authorization: Bearer`,
//!      which the front door authenticates in full (signature, session
//!      floor, tier gate), and gets a random, single-use ticket that lives
//!      [`TICKET_TTL`] and is bound to that add-on and that person. It then
//!      opens `wss://<gateway>/ws/addons/<addon>/…?ticket=<ticket>`. The
//!      front door lets a handshake carrying `ticket=` through to
//!      [`serve_ws`], which redeems it (gone after one use, valid or not);
//!    - the `Authorization` header, for a non-browser client, checked by the
//!      front door like any bearer.
//! 2. **Permission before anything is dialled.** [`serve_ws`] checks the
//!    route's `min_role` against the verified requester, then the per-user
//!    connection cap, and only then dials the add-on.
//! 3. **Dial, then upgrade.** The gateway opens `wss://noo-<addon>…` with the
//!    cluster CA and its own leaf (the same trust as every add-on door), the
//!    per-boot caller bearer and the `x-noo-requester-*` headers built from
//!    the verified requester (never copied from the client), and the
//!    delegated task token where the route opted in. The client's `?token=`
//!    is stripped from the forwarded query. Only when the add-on accepted the
//!    handshake is the client upgraded, so an add-on that is down, refuses or
//!    speaks plain HTTP is an HTTP answer with a reason, not a socket that
//!    opens and dies.
//! 4. **Frames both ways** ([`pipe`]): text, binary, ping, pong and close
//!    (codes carried across where they are sendable). Each direction is its
//!    own task that awaits the far side's write before reading the next frame,
//!    so a slow reader slows its writer through TCP, never through a buffer
//!    that grows. Bounded by `max_message_bytes` (both sides, message and
//!    frame), `idle_timeout_secs` (no frame either way, close 1001) and the
//!    token's own expiry or a logout (close 4401, the gateway's convention).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{
        ws::{self, WebSocket, WebSocketUpgrade},
        Path, RawQuery, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{self as ts, client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use crate::addon_proxy::{AddonManifest, RouteSpec};
use crate::state::AppState;

/// Default largest message (and frame) in either direction.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1 << 20;
/// The most a manifest may raise it to.
pub const MAX_MAX_MESSAGE_BYTES: usize = 16 << 20;
/// Default idle bound: no frame in either direction for this long closes.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;
/// Default sockets one account may hold open on one route.
pub const DEFAULT_MAX_CONNECTIONS_PER_USER: u32 = 4;
pub const MAX_CONNECTIONS_PER_USER: u32 = 64;
/// TCP connect + TLS + WebSocket handshake to the add-on, at most.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a close is given to reach each side before the sockets drop.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// At most this many subprotocols are passed on from the client.
const MAX_SUBPROTOCOLS: usize = 8;

/// The bounds one route's sockets live under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsLimits {
    pub max_message_bytes: usize,
    pub idle: Duration,
    pub per_user: u32,
}

impl WsLimits {
    pub fn of(spec: &RouteSpec) -> Self {
        Self {
            max_message_bytes: spec.max_message_bytes.unwrap_or(DEFAULT_MAX_MESSAGE_BYTES),
            idle: Duration::from_secs(spec.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)),
            per_user: spec.max_connections_per_user.unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_USER),
        }
    }
}

// ── Tickets ──────────────────────────────────────────────────────────────

/// The query parameter a browser hands its ticket over in.
pub const TICKET_PARAM: &str = "ticket";
/// How long a ticket may wait to be used.
pub const TICKET_TTL: Duration = Duration::from_secs(30);
/// Unredeemed tickets kept at most (a flood of mints cannot grow memory).
const MAX_TICKETS: usize = 10_000;

/// What a ticket stands for: the person (as the front door verified them when
/// it was minted), the add-on it opens, and when the access token behind it
/// expires (the socket's session ends then, like the gateway's own sockets).
#[derive(Clone, Debug)]
pub struct TicketGrant {
    pub addon: String,
    pub requester: crate::auth::RequesterCtx,
    pub token_exp: usize,
}

struct Ticket {
    grant: TicketGrant,
    expires: std::time::Instant,
}

static TICKETS: Mutex<Option<HashMap<String, Ticket>>> = Mutex::new(None);

/// Mint a single-use ticket for `grant`. 244 random bits (two v4 UUIDs).
pub fn mint_ticket(grant: TicketGrant) -> String {
    let id = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let mut guard = match TICKETS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = std::time::Instant::now();
    map.retain(|_, t| t.expires > now);
    if map.len() >= MAX_TICKETS {
        // Oldest first would need an order; dropping all is the closed answer
        // (outstanding tickets fail, their pages mint again).
        map.clear();
    }
    map.insert(id.clone(), Ticket { grant, expires: now + TICKET_TTL });
    id
}

/// Redeem a ticket for `addon`. Single use: the ticket is removed whether or
/// not it matches, so a ticket can be tried exactly once.
pub fn redeem_ticket(ticket: &str, addon: &str) -> Option<TicketGrant> {
    let mut guard = match TICKETS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let t = guard.as_mut()?.remove(ticket)?;
    (t.expires > std::time::Instant::now() && t.grant.addon == addon).then_some(t.grant)
}

/// The `ticket` query parameter, if present and non-empty.
pub fn query_ticket(q: &str) -> Option<&str> {
    q.split('&')
        .find_map(|p| p.strip_prefix("ticket="))
        .filter(|t| !t.is_empty())
}

/// May the front door pass this handshake through WITHOUT a bearer, for
/// [`serve_ws`] to redeem its ticket? Only an add-on socket path that carries
/// `ticket=`; the caller also requires a real `Upgrade: websocket`.
pub fn is_ticket_handshake(path: &str, query: Option<&str>) -> bool {
    path.starts_with("/ws/addons/") && query.and_then(query_ticket).is_some()
}

/// The core route that mints tickets for every add-on's sockets.
pub fn router() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/api/addons/{addon_id}/ws-ticket", axum::routing::post(ws_ticket))
}

/// Is `path` the ws-ticket route? (The tier gate lets a User POST it; each
/// socket's own `min_role` is checked when the ticket is redeemed.)
pub fn is_ws_ticket_path(path: &str) -> bool {
    path.strip_prefix("/api/addons/")
        .and_then(|r| r.strip_suffix("/ws-ticket"))
        .is_some_and(crate::addon_registry::name_ok)
}

/// POST /api/addons/{addon_id}/ws-ticket — a single-use ticket for opening one of the add-on's WebSocket routes from a browser, which cannot send an Authorization header on a WebSocket. Send the access token as `Authorization: Bearer`; open `/ws/addons/{addon_id}/…?ticket=<ticket>` within 30 seconds. The ticket is bound to this person and this add-on and is consumed by the first handshake that presents it. The route's own `min_role` is checked at the handshake. 401 without a person's bearer, 404 when the add-on declares no WebSocket route, 503 when it is off.
async fn ws_ticket(
    Path(addon_id): Path<String>,
    headers: HeaderMap,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Response {
    let Some(axum::Extension(r)) = ctx else {
        return refuse(StatusCode::UNAUTHORIZED, &addon_id, "a socket ticket is for a signed-in person; no verified caller".into());
    };
    if r.act.is_some() || r.harness.is_some() {
        return refuse(StatusCode::FORBIDDEN, &addon_id, "a delegated or harness credential cannot mint a socket ticket".into());
    }
    let Some(m) = crate::addon_proxy::manifests().into_iter().find(|m| m.addon == addon_id) else {
        return match crate::addon_proxy::refusal(&addon_id) {
            Some(why) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": why, "addon": addon_id, "state": "unhealthy" }))).into_response(),
            None => refuse(StatusCode::NOT_FOUND, &addon_id, format!("add-on {addon_id:?} declares no WebSocket route")),
        };
    };
    if !m.routes.iter().any(|r| r.method == crate::addon_proxy::METHOD_WS && !r.internal) {
        return refuse(StatusCode::NOT_FOUND, &addon_id, format!("add-on {addon_id:?} declares no WebSocket route"));
    }
    if !crate::addons::enabled(&addon_id) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": crate::addons::refusal_msg(&addon_id),
                "addon": addon_id,
                "state": crate::addons::health_word(&addon_id),
            })),
        )
            .into_response();
    }
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return refuse(StatusCode::UNAUTHORIZED, &addon_id, "send the access token as Authorization: Bearer".into());
    };
    let Ok(claims) = crate::auth::verify_token(token, &crate::auth::jwt_secret()) else {
        return refuse(StatusCode::UNAUTHORIZED, &addon_id, "not an access token".into());
    };
    let ticket = mint_ticket(TicketGrant { addon: addon_id.clone(), requester: r, token_exp: claims.exp });
    let mut resp = Json(json!({
        "ticket": ticket,
        "param": TICKET_PARAM,
        "expires_in": TICKET_TTL.as_secs(),
    }))
    .into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    resp
}

// ── Per-user connection cap ──────────────────────────────────────────────

static OPEN: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// One open socket counted against its account. Dropping it gives the slot
/// back, however the socket ended (close, error, panic in the pipe).
#[derive(Debug)]
pub struct Slot {
    key: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut guard = match OPEN.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(map) = guard.as_mut() {
            if let Some(n) = map.get_mut(&self.key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&self.key);
                }
            }
        }
    }
}

/// Take one of `cap` slots for `key`, or `None` when all are in use.
pub fn try_take_slot(key: String, cap: u32) -> Option<Slot> {
    let mut guard = match OPEN.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let n = map.entry(key.clone()).or_insert(0);
    if *n >= cap {
        return None;
    }
    *n += 1;
    Some(Slot { key })
}

/// The cap's key: add-on, route and ACCOUNT (every session of one person
/// shares the cap). A machine credential (no requester) is one bucket.
fn slot_key(addon: &str, route: &str, requester: Option<&crate::auth::RequesterCtx>) -> String {
    let who = requester.map(|r| crate::auth::account_of(&r.sub).to_string()).unwrap_or_else(|| "-machine-".into());
    format!("{addon}\u{1f}{route}\u{1f}{who}")
}

// ── Mounting and the handshake ───────────────────────────────────────────

/// The handler for one `WS` route (a GET that must be a WebSocket handshake).
pub fn method_router(
    manifest: &Arc<AddonManifest>,
    spec: &Arc<RouteSpec>,
) -> axum::routing::MethodRouter<Arc<AppState>> {
    let manifest = manifest.clone();
    let spec = spec.clone();
    axum::routing::get(
        move |State(state): State<Arc<AppState>>,
              ws: WebSocketUpgrade,
              params: Option<Path<HashMap<String, String>>>,
              RawQuery(q): RawQuery,
              headers: HeaderMap,
              ctx: Option<axum::Extension<crate::auth::RequesterCtx>>| {
            let manifest = manifest.clone();
            let spec = spec.clone();
            async move {
                let params = params.map(|Path(p)| p).unwrap_or_default();
                let requester = ctx.map(|axum::Extension(r)| r);
                serve_ws(state, &manifest, &spec, ws, params, q, &headers, requester).await
            }
        },
    )
}

fn refuse(status: StatusCode, addon: &str, detail: String) -> Response {
    (status, Json(json!({ "detail": detail, "addon": addon }))).into_response()
}

/// Who may open this socket, decided before anything is dialled. `Err` is
/// the answer to give instead (403 with the role needed).
pub(crate) fn admit(
    manifest: &AddonManifest,
    spec: &RouteSpec,
    requester: Option<&crate::auth::RequesterCtx>,
) -> Result<(), Response> {
    if let Some(r) = requester {
        if !spec.permits(r.role, &r.scopes) {
            return Err(crate::addon_proxy::forbidden(manifest, spec));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_ws(
    state: Arc<AppState>,
    manifest: &AddonManifest,
    spec: &RouteSpec,
    ws: WebSocketUpgrade,
    params: HashMap<String, String>,
    query: Option<String>,
    headers: &HeaderMap,
    requester: Option<crate::auth::RequesterCtx>,
) -> Response {
    let addon = manifest.addon.as_str();
    // 0. Who is calling. A `ticket=` is redeemed here (the front door let the
    //    handshake through for that); it wins over anything else, and a
    //    ticket that does not redeem is a 401, never an anonymous socket.
    let mut session_of: Option<(usize, String)> = None;
    let requester = match query.as_deref().and_then(query_ticket) {
        Some(t) => match redeem_ticket(t, addon) {
            Some(grant) => {
                session_of = Some((grant.token_exp, grant.requester.sub.clone()));
                Some(grant.requester)
            }
            None => {
                return refuse(
                    StatusCode::UNAUTHORIZED,
                    addon,
                    "the socket ticket is unknown, used, expired or for another add-on; mint a new one \
                     with POST /api/addons/<addon>/ws-ticket"
                        .into(),
                );
            }
        },
        None => {
            // A bearer the front door verified (header only: `?token=` is not
            // a credential under /ws/addons/).
            if requester.is_some() {
                session_of = bearer_session(headers);
            }
            requester
        }
    };
    // 1. Permission first: before a param is parsed, a slot taken or the
    //    add-on dialled.
    if let Err(resp) = admit(manifest, spec, requester.as_ref()) {
        return resp;
    }
    // 2. The add-on is usable, and its door is HTTPS.
    if !crate::addons::enabled(addon) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": crate::addons::refusal_msg(addon),
                "addon": addon,
                "state": crate::addons::health_word(addon),
            })),
        )
            .into_response();
    }
    let base = manifest.base_url();
    if let Some(reason) = crate::addon_proxy::plaintext_refusal(addon, &manifest.base_url_env, &base) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": reason, "addon": addon, "state": "misconfigured" })),
        )
            .into_response();
    }
    // 3. The upstream path: params validated, the client's `token` dropped.
    let mut path = match crate::addon_proxy::fill_path(spec, &params) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    if spec.query {
        if let Some(q) = query.as_deref().and_then(strip_token) {
            path = format!("{path}?{q}");
        }
    }
    // 4. The per-user cap.
    let limits = WsLimits::of(spec);
    let Some(slot) = try_take_slot(slot_key(addon, &spec.name, requester.as_ref()), limits.per_user) else {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            addon,
            format!(
                "{} {} allows {} open socket(s) per account; close one first",
                spec.method, spec.path, limits.per_user
            ),
        );
    };
    // 5. Dial the add-on with the verified identity, then upgrade.
    let mut outbound: Vec<(&'static str, String)> = crate::addon_proxy::caller_headers(requester.as_ref());
    if let Some(r) = requester.as_ref() {
        if let Some(entry) = crate::addon_registry::get(addon) {
            let route = path.split('?').next().unwrap_or(&path);
            if crate::addon_proxy::mints_delegation(
                Some(r),
                entry.route_receives_delegation(crate::addon_proxy::METHOD_WS, route),
                entry.operator_enabled(),
            ) {
                match crate::addon_delegation::mint(r, addon) {
                    Some(token) => outbound.push((crate::addon_delegation::HEADER, token)),
                    None => tracing::error!(addon, "add-on delegation: could not mint the delegated token; the add-on socket gets none and fails closed"),
                }
            }
        }
    }
    let protocols = requested_subprotocols(headers);
    let (upstream, selected) = match dial(&base, &path, &outbound, protocols.as_deref(), limits).await {
        Ok(ok) => ok,
        Err(e) => return e.into_response(addon, &base),
    };
    let session = session_end(&state, session_of);
    let mut ws = ws.max_message_size(limits.max_message_bytes).max_frame_size(limits.max_message_bytes);
    if let Some(p) = selected {
        ws = ws.protocols([p]);
    }
    let addon_name = addon.to_string();
    let route_name = spec.name.clone();
    ws.on_upgrade(move |socket| async move {
        let _slot = slot;
        let end = pipe(socket, upstream, limits.idle, session).await;
        tracing::debug!(addon = %addon_name, route = %route_name, ?end, "add-on socket closed");
    })
}

/// The query string with every `token` and `ticket` parameter removed (the
/// client's credential is the gateway's business, never the add-on's). `None`
/// when nothing is left.
pub(crate) fn strip_token(q: &str) -> Option<String> {
    let kept: Vec<&str> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .filter(|p| !matches!(p.split('=').next(), Some("token") | Some(TICKET_PARAM)))
        .collect();
    (!kept.is_empty()).then(|| kept.join("&"))
}

/// The subprotocols the client asked for, if every one is a plain token
/// (RFC 6455 / RFC 7230 `token`), comma-joined for the add-on's handshake.
/// Anything else is not passed on (the add-on then selects none).
pub(crate) fn requested_subprotocols(headers: &HeaderMap) -> Option<String> {
    let tchar = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    let list: Vec<String> = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if list.is_empty() || list.len() > MAX_SUBPROTOCOLS || !list.iter().all(|p| p.len() <= 64 && p.chars().all(tchar)) {
        return None;
    }
    Some(list.join(", "))
}

/// The session behind a header bearer: its `exp` and subject.
fn bearer_session(headers: &HeaderMap) -> Option<(usize, String)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;
    crate::auth::verify_token(token, &crate::auth::jwt_secret()).ok().map(|c| (c.exp, c.sub))
}

/// When the session behind the socket ends: the token's `exp` or a logout /
/// session revocation for that subject (the same rule as the gateway's own
/// sockets, `websocket::session_ended`). A credential that is not a person's
/// JWT (a machine credential the front door admitted) has no session to end;
/// the idle bound still applies.
fn session_end(state: &AppState, session_of: Option<(usize, String)>) -> Pin<Box<dyn Future<Output = &'static str> + Send>> {
    match session_of {
        Some((exp, sub)) => {
            let ends = state.alert_hub.subscribe_session_end();
            Box::pin(async move { crate::websocket::session_ended(exp, &sub, ends).await })
        }
        None => Box::pin(std::future::pending()),
    }
}

// ── Dialling the add-on ──────────────────────────────────────────────────

/// Why the add-on's socket could not be opened.
#[derive(Debug)]
pub(crate) enum DialError {
    /// No cluster TLS material: there is no plain door to fall back to.
    NoTls,
    /// The base URL does not parse into a host.
    BadBase(String),
    /// TCP, TLS or handshake did not finish in time.
    Timeout,
    /// TCP connect failed.
    Connect(String),
    /// TLS handshake failed (an add-on image serving plain HTTP, a leaf the
    /// cluster CA did not sign, no client certificate accepted).
    Tls(String),
    /// The add-on answered the handshake with an HTTP status instead of 101.
    Status(u16),
    /// Anything else in the WebSocket handshake.
    Handshake(String),
}

impl DialError {
    fn into_response(self, addon: &str, base: &str) -> Response {
        let container = crate::addon_proxy::container_of(addon);
        let (status, reason, hint) = match &self {
            DialError::Status(s) => {
                // The add-on's own refusal (403, 404, 429 …) keeps its status;
                // anything else is the gateway's 502.
                let code = StatusCode::from_u16(*s)
                    .ok()
                    .filter(|c| c.is_client_error())
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                (code, "refused", format!("{container} answered the WebSocket handshake with HTTP {s}"))
            }
            DialError::NoTls => (
                StatusCode::SERVICE_UNAVAILABLE,
                "tls",
                "the gateway has no cluster TLS material (NOO_TLS_CA/CERT/KEY) to dial an add-on door with".to_string(),
            ),
            DialError::BadBase(e) => (StatusCode::SERVICE_UNAVAILABLE, "misconfigured", e.clone()),
            DialError::Timeout => (StatusCode::SERVICE_UNAVAILABLE, "timeout", format!("{container} did not complete the handshake in time")),
            DialError::Connect(e) => (StatusCode::SERVICE_UNAVAILABLE, "connect", format!("nothing is listening at {base} — `docker logs {container}` ({e})")),
            DialError::Tls(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "tls",
                format!(
                    "the TLS handshake with {container} failed ({e}). It must serve HTTPS with its \
                     services/{addon} leaf and accept the gateway's cluster-CA client certificate"
                ),
            ),
            DialError::Handshake(e) => (StatusCode::BAD_GATEWAY, "handshake", format!("{container}: WebSocket handshake failed ({e})")),
        };
        (
            status,
            Json(json!({
                "error": format!("{container} socket unavailable ({reason}): {hint}"),
                "addon": addon,
                "state": "unreachable",
                "reason": reason,
            })),
        )
            .into_response()
    }
}

/// Host and port of an `https://host[:port]` base.
pub(crate) fn host_port(base: &str) -> Result<(String, u16), DialError> {
    let url = reqwest::Url::parse(base).map_err(|e| DialError::BadBase(format!("{base:?} is not a URL: {e}")))?;
    let host = url.host_str().ok_or_else(|| DialError::BadBase(format!("{base:?} names no host")))?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    Ok((host, port))
}

/// The upstream handshake request: `wss://host:port<path>` with the outbound
/// identity headers and the passed-on subprotocols. Built from nothing, so no
/// client header rides along.
pub(crate) fn upstream_request(
    host: &str,
    port: u16,
    path: &str,
    outbound: &[(&'static str, String)],
    protocols: Option<&str>,
) -> Result<ts::handshake::client::Request, DialError> {
    let url = format!("wss://{host}:{port}{path}");
    let mut req = url.into_client_request().map_err(|e| DialError::Handshake(e.to_string()))?;
    for (name, value) in outbound {
        let Ok(mut v) = ts::http::HeaderValue::from_str(value) else { continue };
        if name.eq_ignore_ascii_case(crate::addon_delegation::HEADER) || name.eq_ignore_ascii_case("authorization") {
            v.set_sensitive(true);
        }
        req.headers_mut().insert(*name, v);
    }
    if let Some(p) = protocols {
        if let Ok(v) = ts::http::HeaderValue::from_str(p) {
            req.headers_mut().insert("sec-websocket-protocol", v);
        }
    }
    Ok(req)
}

type Upstream = WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

async fn dial(
    base: &str,
    path: &str,
    outbound: &[(&'static str, String)],
    protocols: Option<&str>,
    limits: WsLimits,
) -> Result<(Upstream, Option<String>), DialError> {
    let tls = crate::tls::cluster_ws_tls_config().ok_or(DialError::NoTls)?;
    let (host, port) = host_port(base)?;
    let request = upstream_request(&host, port, path, outbound, protocols)?;
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| DialError::BadBase(format!("{host:?} is not a TLS server name: {e}")))?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(limits.max_message_bytes))
        .max_frame_size(Some(limits.max_message_bytes));
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| DialError::Connect(e.to_string()))?;
        let _ = tcp.set_nodelay(true);
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, tcp)
            .await
            .map_err(|e| DialError::Tls(crate::addon_proxy::error_chain(&e)))?;
        let (socket, resp) = tokio_tungstenite::client_async_with_config(request, stream, Some(config))
            .await
            .map_err(handshake_error)?;
        let selected = resp
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok::<_, DialError>((socket, selected))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await.map_err(|_| DialError::Timeout)?
}

fn handshake_error(e: ts::Error) -> DialError {
    match e {
        ts::Error::Http(resp) => DialError::Status(resp.status().as_u16()),
        other => DialError::Handshake(other.to_string()),
    }
}

// ── The pipe ─────────────────────────────────────────────────────────────

/// How a piped socket ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEnd {
    /// The client sent a close; it was passed on.
    ClientClosed,
    /// The add-on sent a close; it was passed on.
    UpstreamClosed,
    /// The client vanished without a close (or its stream failed).
    ClientGone,
    /// The add-on vanished without a close (or its stream failed).
    UpstreamGone,
    /// The client sent a message over the limit (closed 1009).
    ClientTooBig,
    /// The add-on sent a message over the limit (closed 1009 to the add-on).
    UpstreamTooBig,
    /// No frame either way for the idle bound (closed 1001).
    Idle,
    /// The token expired or the session was ended (closed 4401).
    SessionEnded,
}

/// What one frame becomes on the other side.
#[derive(Debug, PartialEq)]
pub(crate) enum Relay<M> {
    Frame(M),
    Close(M),
    Skip,
}

/// Close codes a peer may SEND (RFC 6455 §7.4): 1000–1003, 1007–1014 and the
/// registered/private 3000–4999. 1004/1005/1006/1015 and the rest are never
/// put on the wire; a close carrying one goes on without a code.
pub(crate) fn sendable_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// A close reason fits in a control frame (123 bytes after the code).
fn clip_reason(s: &str) -> &str {
    if s.len() <= 123 {
        return s;
    }
    let mut end = 123;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn client_to_upstream(m: ws::Message) -> Relay<ts::Message> {
    match m {
        ws::Message::Text(t) => Relay::Frame(ts::Message::Text(t.as_str().into())),
        ws::Message::Binary(b) => Relay::Frame(ts::Message::Binary(b)),
        ws::Message::Ping(b) => Relay::Frame(ts::Message::Ping(b)),
        ws::Message::Pong(b) => Relay::Frame(ts::Message::Pong(b)),
        ws::Message::Close(f) => Relay::Close(ts::Message::Close(f.filter(|f| sendable_code(f.code)).map(|f| {
            ts::protocol::CloseFrame { code: f.code.into(), reason: clip_reason(f.reason.as_str()).into() }
        }))),
    }
}

pub(crate) fn upstream_to_client(m: ts::Message) -> Relay<ws::Message> {
    match m {
        ts::Message::Text(t) => Relay::Frame(ws::Message::Text(t.as_str().into())),
        ts::Message::Binary(b) => Relay::Frame(ws::Message::Binary(b)),
        ts::Message::Ping(b) => Relay::Frame(ws::Message::Ping(b)),
        ts::Message::Pong(b) => Relay::Frame(ws::Message::Pong(b)),
        ts::Message::Close(f) => Relay::Close(ws::Message::Close(
            f.map(|f| (u16::from(f.code), f.reason))
                .filter(|(code, _)| sendable_code(*code))
                .map(|(code, reason)| ws::CloseFrame { code, reason: clip_reason(reason.as_str()).into() }),
        )),
        // A raw frame is never yielded by a read; nothing to relay.
        ts::Message::Frame(_) => Relay::Skip,
    }
}

fn ws_close(code: u16, reason: &str) -> ws::Message {
    ws::Message::Close(Some(ws::CloseFrame { code, reason: reason.into() }))
}

fn ts_close(code: u16, reason: &str) -> ts::Message {
    ts::Message::Close(Some(ts::protocol::CloseFrame { code: code.into(), reason: reason.into() }))
}

/// Was this read error the size limit?
fn is_capacity(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(ts::Error::Capacity(_)) = err.downcast_ref::<ts::Error>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Milliseconds since the pipe started at the last frame either way.
struct Clock {
    start: tokio::time::Instant,
    last_ms: AtomicU64,
}

impl Clock {
    fn new() -> Self {
        Self { start: tokio::time::Instant::now(), last_ms: AtomicU64::new(0) }
    }
    fn touch(&self) {
        self.last_ms.store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    async fn idle(&self, idle: Duration) {
        loop {
            let deadline = self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed)) + idle;
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Pipe frames between the client and the add-on until either side closes,
/// either side fails, the idle bound passes or `session` resolves. Generic
/// over the add-on's transport so a test can pipe to a plain listener.
pub(crate) async fn pipe<S>(
    client: WebSocket,
    upstream: WebSocketStream<S>,
    idle: Duration,
    session: Pin<Box<dyn Future<Output = &'static str> + Send>>,
) -> PipeEnd
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut c_tx, mut c_rx) = client.split();
    let (mut u_tx, mut u_rx) = upstream.split();
    let clock = Clock::new();
    let mut session = session;

    let end = {
        // Client → add-on. The send awaits the add-on's write, so a slow
        // add-on stops this loop reading, and TCP pushes back on the client.
        let up = async {
            loop {
                match c_rx.next().await {
                    None => return PipeEnd::ClientGone,
                    Some(Err(e)) => {
                        return if is_capacity(&e) { PipeEnd::ClientTooBig } else { PipeEnd::ClientGone };
                    }
                    Some(Ok(m)) => {
                        clock.touch();
                        match client_to_upstream(m) {
                            Relay::Frame(f) => {
                                if u_tx.send(f).await.is_err() {
                                    return PipeEnd::UpstreamGone;
                                }
                            }
                            Relay::Close(f) => {
                                let _ = u_tx.send(f).await;
                                return PipeEnd::ClientClosed;
                            }
                            Relay::Skip => {}
                        }
                    }
                }
            }
        };
        // Add-on → client, the same shape.
        let down = async {
            loop {
                match u_rx.next().await {
                    None => return PipeEnd::UpstreamGone,
                    Some(Err(e)) => {
                        return if matches!(e, ts::Error::Capacity(_)) { PipeEnd::UpstreamTooBig } else { PipeEnd::UpstreamGone };
                    }
                    Some(Ok(m)) => {
                        clock.touch();
                        match upstream_to_client(m) {
                            Relay::Frame(f) => {
                                if c_tx.send(f).await.is_err() {
                                    return PipeEnd::ClientGone;
                                }
                            }
                            Relay::Close(f) => {
                                let _ = c_tx.send(f).await;
                                return PipeEnd::UpstreamClosed;
                            }
                            Relay::Skip => {}
                        }
                    }
                }
            }
        };
        let idle_out = clock.idle(idle);
        tokio::pin!(up, down, idle_out);
        tokio::select! {
            e = &mut up => e,
            e = &mut down => e,
            _ = &mut idle_out => PipeEnd::Idle,
            _ = &mut session => PipeEnd::SessionEnded,
        }
    };

    // Say why to whichever side did not already close.
    let (to_client, to_upstream) = match end {
        PipeEnd::ClientClosed | PipeEnd::ClientGone => (None, Some(ts_close(1001, "client went away"))),
        PipeEnd::UpstreamClosed => (None, None),
        PipeEnd::UpstreamGone => (Some(ws_close(1011, "add-on stream ended")), None),
        PipeEnd::ClientTooBig => (Some(ws_close(1009, "message too big")), Some(ts_close(1001, "client went away"))),
        PipeEnd::UpstreamTooBig => (Some(ws_close(1011, "add-on stream ended")), Some(ts_close(1009, "message too big"))),
        PipeEnd::Idle => (Some(ws_close(1001, "idle timeout")), Some(ts_close(1001, "idle timeout"))),
        PipeEnd::SessionEnded => (Some(ws_close(4401, "session ended")), Some(ts_close(1001, "session ended"))),
    };
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        if let Some(m) = to_client {
            let _ = c_tx.send(m).await;
        }
        if let Some(m) = to_upstream {
            let _ = u_tx.send(m).await;
        }
        let _ = c_tx.close().await;
        let _ = u_tx.close().await;
    })
    .await;
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use serde_json::{json, Value};

    fn ctx(sub: &str, role: Role, scopes: &[&str]) -> crate::auth::RequesterCtx {
        crate::auth::RequesterCtx {
            sub: sub.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }
    }

    const TEST_PATH_STREAM: &str = "/ws/addons/evolve/stream";
    const TEST_PATH_IDLE: &str = "/ws/addons/evolve/idle";

    fn ws_manifest() -> AddonManifest {
        let mut v = crate::addon_proxy::tests::sample_json();
        v["routes"].as_array_mut().unwrap().push(json!({
            "name": "sample_stream", "method": "WS", "path": "/ws/addons/evolve/stream",
            "min_role": "operator", "query": true, "max_message_bytes": 65536,
            "idle_timeout_secs": 60, "max_connections_per_user": 2
        }));
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        crate::addon_proxy::validate(&m, "evolve").expect("a WS route validates");
        m
    }

    fn spec(m: &AddonManifest) -> RouteSpec {
        m.routes.iter().find(|r| r.name == "sample_stream").unwrap().clone()
    }

    #[test]
    fn limits_default_and_follow_the_manifest() {
        let m = ws_manifest();
        let l = WsLimits::of(&spec(&m));
        assert_eq!(l, WsLimits { max_message_bytes: 65536, idle: Duration::from_secs(60), per_user: 2 });
        let mut bare = spec(&m);
        bare.max_message_bytes = None;
        bare.idle_timeout_secs = None;
        bare.max_connections_per_user = None;
        let l = WsLimits::of(&bare);
        assert_eq!(l.max_message_bytes, 1 << 20, "1 MiB by default");
        assert_eq!(l.idle, Duration::from_secs(300));
        assert_eq!(l.per_user, 4);
    }

    /// Role refusal happens in `admit`, which `serve_ws` asks FIRST.
    #[tokio::test]
    async fn a_short_role_is_refused_before_anything_is_dialled() {
        let m = ws_manifest();
        let s = spec(&m);
        let user = ctx("alice", Role::User, &["read"]);
        let resp = admit(&m, &s, Some(&user)).expect_err("a User is short of an operator socket");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["required_role"], "operator");
        let op = ctx("olive", Role::Operator, &["read", "write"]);
        assert!(admit(&m, &s, Some(&op)).is_ok());
        assert!(admit(&m, &s, None).is_ok(), "a machine credential the front door admitted is not narrowed");
    }

    /// The ORDER inside serve_ws, pinned at the source: permission, then the
    /// add-on gate, then the cap, then the dial, then the upgrade. A refactor
    /// that dials (or upgrades) before the permission check fails here.
    #[test]
    fn serve_ws_checks_permission_before_it_dials_or_upgrades() {
        let src = include_str!("addon_ws.rs");
        let body = src.split("async fn serve_ws(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let at = |needle: &str| body.find(needle).unwrap_or_else(|| panic!("serve_ws no longer contains {needle:?}"));
        let admit_at = at("admit(manifest, spec");
        let enabled_at = at("crate::addons::enabled(addon)");
        let slot_at = at("try_take_slot(");
        let dial_at = at("dial(&base");
        let upgrade_at = at("on_upgrade(");
        assert!(admit_at < enabled_at && enabled_at < slot_at && slot_at < dial_at && dial_at < upgrade_at);
        // Identity comes from the verified requester only.
        assert!(body.contains("caller_headers(requester.as_ref())"));
        assert!(!body.contains("headers.iter()"), "client headers are never copied to the add-on");
    }

    #[test]
    fn a_ticket_is_single_use_bound_to_its_addon_and_short_lived() {
        let grant = |addon: &str| TicketGrant { addon: addon.into(), requester: ctx("alice", Role::User, &["read"]), token_exp: 1 };
        let t = mint_ticket(grant("example-addon"));
        assert!(t.len() >= 64 && t.bytes().all(|b| b.is_ascii_hexdigit()), "{t}");
        let g = redeem_ticket(&t, "example-addon").expect("first use redeems");
        assert_eq!(g.requester.sub, "alice");
        assert!(redeem_ticket(&t, "example-addon").is_none(), "second use refused");
        // Presented to another add-on: refused AND consumed.
        let t = mint_ticket(grant("example-addon"));
        assert!(redeem_ticket(&t, "other-addon").is_none());
        assert!(redeem_ticket(&t, "example-addon").is_none(), "a ticket can be tried exactly once");
        assert!(redeem_ticket("nonsense", "example-addon").is_none());
        assert_eq!(TICKET_TTL, Duration::from_secs(30));
    }

    #[test]
    fn only_an_addon_socket_with_a_ticket_skips_the_front_door_bearer() {
        assert!(is_ticket_handshake("/ws/addons/example-addon/stream", Some("ticket=abc")));
        assert!(is_ticket_handshake("/ws/addons/example-addon/stream", Some("lang=en&ticket=abc")));
        assert!(!is_ticket_handshake("/ws/addons/example-addon/stream", Some("ticket=")));
        assert!(!is_ticket_handshake("/ws/addons/example-addon/stream", Some("token=abc")));
        assert!(!is_ticket_handshake("/ws/addons/example-addon/stream", None));
        assert!(!is_ticket_handshake("/ws/collab", Some("ticket=abc")), "core sockets keep their own rule");
        assert!(!is_ticket_handshake("/api/addons/x", Some("ticket=abc")));
        assert!(is_ws_ticket_path("/api/addons/example-addon/ws-ticket"));
        assert!(!is_ws_ticket_path("/api/addons/a/b/ws-ticket"));
    }

    /// serve_ws redeems a presented ticket before anything else and refuses
    /// one that does not redeem; it never falls back to an anonymous socket.
    #[test]
    fn serve_ws_redeems_the_ticket_first_and_fails_closed() {
        let src = include_str!("addon_ws.rs");
        let body = src.split("async fn serve_ws(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let redeem = body.find("redeem_ticket(t, addon)").unwrap();
        let admit_at = body.find("admit(manifest, spec").unwrap();
        assert!(redeem < admit_at);
        assert!(body.contains("StatusCode::UNAUTHORIZED"));
    }

    #[test]
    fn the_client_token_never_reaches_the_addon() {
        assert_eq!(strip_token("ticket=abc&x=1").as_deref(), Some("x=1"));
        assert_eq!(strip_token("token=abc"), None);
        assert_eq!(strip_token("lang=en&token=abc&rate=16000").as_deref(), Some("lang=en&rate=16000"));
        assert_eq!(strip_token("tokens=1&token").as_deref(), Some("tokens=1"));
        assert_eq!(strip_token("").as_deref(), None);
    }

    #[test]
    fn the_upstream_request_carries_only_the_gateways_headers() {
        let outbound = crate::addon_proxy::caller_headers(Some(&ctx("alice", Role::User, &["read"])));
        let req = upstream_request("noo-evolve", 8090, "/ws/addons/evolve/stream?x=1", &outbound, Some("audio.v1")).unwrap();
        assert_eq!(req.uri().to_string(), "wss://noo-evolve:8090/ws/addons/evolve/stream?x=1");
        let h = req.headers();
        assert_eq!(h.get(crate::addon_proxy::REQUESTER_SUB).unwrap(), "alice");
        assert_eq!(h.get(crate::addon_proxy::REQUESTER_ROLE).unwrap(), "user");
        assert_eq!(h.get("sec-websocket-protocol").unwrap(), "audio.v1");
        assert!(h.get("cookie").is_none());
    }

    #[test]
    fn subprotocols_are_passed_on_only_when_plain() {
        let mut h = HeaderMap::new();
        assert_eq!(requested_subprotocols(&h), None);
        h.insert(header::SEC_WEBSOCKET_PROTOCOL, "audio.v1, json".parse().unwrap());
        assert_eq!(requested_subprotocols(&h).as_deref(), Some("audio.v1, json"));
        h.insert(header::SEC_WEBSOCKET_PROTOCOL, "bad proto".parse().unwrap());
        assert_eq!(requested_subprotocols(&h), None);
    }

    #[test]
    fn base_urls_split_into_host_and_port() {
        assert_eq!(host_port("https://noo-evolve:8090").unwrap(), ("noo-evolve".to_string(), 8090));
        assert_eq!(host_port("https://noo-evolve").unwrap(), ("noo-evolve".to_string(), 443));
        assert!(host_port("not a url").is_err());
    }

    #[test]
    fn the_cap_counts_per_account_and_gives_slots_back_on_drop() {
        let key = format!("test-cap-{}", std::process::id());
        let a = try_take_slot(key.clone(), 2).expect("first");
        let b = try_take_slot(key.clone(), 2).expect("second");
        assert!(try_take_slot(key.clone(), 2).is_none(), "the third is refused");
        drop(a);
        let c = try_take_slot(key.clone(), 2).expect("a dropped socket gives its slot back");
        drop((b, c));
        // Two sessions of one account share the cap.
        let s1 = ctx("alice:session-1", Role::User, &[]);
        let s2 = ctx("alice:session-2", Role::User, &[]);
        assert_eq!(slot_key("x", "r", Some(&s1)), slot_key("x", "r", Some(&s2)));
        assert_ne!(slot_key("x", "r", Some(&s1)), slot_key("x", "other", Some(&s1)));
    }

    #[test]
    fn frames_convert_both_ways_and_reserved_close_codes_are_never_sent() {
        let b = axum::body::Bytes::from_static(b"\x00\x01pcm");
        assert_eq!(client_to_upstream(ws::Message::Binary(b.clone())), Relay::Frame(ts::Message::Binary(b.clone())));
        assert_eq!(upstream_to_client(ts::Message::Binary(b.clone())), Relay::Frame(ws::Message::Binary(b)));
        assert_eq!(client_to_upstream(ws::Message::Text("hi".into())), Relay::Frame(ts::Message::Text("hi".into())));
        assert_eq!(upstream_to_client(ts::Message::Ping(axum::body::Bytes::from_static(b"p"))), Relay::Frame(ws::Message::Ping(axum::body::Bytes::from_static(b"p"))));
        // A close keeps its code when sendable…
        assert_eq!(
            upstream_to_client(ts_close(4000, "bye")),
            Relay::Close(ws_close(4000, "bye"))
        );
        assert_eq!(client_to_upstream(ws_close(1000, "done")), Relay::Close(ts_close(1000, "done")));
        // …and drops it when it is one no peer may send.
        for code in [1005u16, 1006, 1015, 999, 5000] {
            assert!(!sendable_code(code), "{code}");
        }
        assert_eq!(upstream_to_client(ts_close(1006, "x")), Relay::Close(ws::Message::Close(None)));
        // A long reason is clipped to fit a control frame, on a char boundary.
        let long = "é".repeat(100);
        match client_to_upstream(ws_close(1000, &long)) {
            Relay::Close(ts::Message::Close(Some(f))) => assert!(f.reason.as_str().len() <= 123),
            other => panic!("{other:?}"),
        }
    }

    /// End to end over real sockets: a test client → an axum server whose
    /// handler pipes to a fake add-on (plain ws:// on loopback; the TLS dial
    /// is the one part not exercised here). Binary and text echo, ping gets
    /// a pong, and the add-on's close code reaches the client.
    #[tokio::test]
    async fn frames_are_piped_both_ways_through_a_fake_upstream() {
        use tokio_tungstenite::tungstenite::Message as M;

        // The fake add-on: echoes data frames, closes with 4000 on "bye".
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = up.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(sock).await.unwrap();
            while let Some(Ok(m)) = ws.next().await {
                let bye = matches!(&m, M::Text(t) if t.as_str() == "bye");
                if bye {
                    let _ = ws.send(ts_close(4000, "done")).await;
                    break;
                }
                if matches!(&m, M::Text(_) | M::Binary(_)) {
                    let _ = ws.send(m).await;
                }
            }
        });

        // The gateway side: an axum server that dials the fake add-on and pipes.
        let app = axum::Router::new().route(
            // A variable, not a literal: the OpenAPI scanners read `.route("…")`.
            TEST_PATH_STREAM,
            axum::routing::get(move |ws: WebSocketUpgrade| async move {
                let (upstream, _) = tokio_tungstenite::connect_async(format!("ws://{up_addr}/")).await.unwrap();
                ws.on_upgrade(move |socket| async move {
                    let _ = pipe(socket, upstream, Duration::from_secs(30), Box::pin(std::future::pending())).await;
                })
            }),
        );
        let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(gw, app).await;
        });

        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{gw_addr}/ws/addons/evolve/stream")).await.unwrap();
        let audio = vec![0u8, 1, 2, 3, 254, 255];
        client.send(M::Binary(audio.clone().into())).await.unwrap();
        loop {
            match client.next().await.unwrap().unwrap() {
                M::Binary(b) => {
                    assert_eq!(b.as_ref(), audio.as_slice(), "binary arrives byte for byte");
                    break;
                }
                M::Pong(_) | M::Ping(_) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
        client.send(M::Text("hello".into())).await.unwrap();
        loop {
            match client.next().await.unwrap().unwrap() {
                M::Text(t) => {
                    assert_eq!(t.as_str(), "hello");
                    break;
                }
                M::Pong(_) | M::Ping(_) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
        client.send(M::Ping(axum::body::Bytes::from_static(b"k"))).await.unwrap();
        let mut got_pong = false;
        client.send(M::Text("bye".into())).await.unwrap();
        let mut close_code = None;
        while let Some(Ok(m)) = client.next().await {
            match m {
                M::Pong(_) => got_pong = true,
                M::Close(f) => {
                    close_code = f.map(|f| u16::from(f.code));
                    break;
                }
                _ => {}
            }
        }
        assert!(got_pong, "a ping is answered");
        assert_eq!(close_code, Some(4000), "the add-on's close code reaches the client");
    }

    /// The idle bound closes a socket nobody speaks on, 1001 to the client.
    #[tokio::test]
    async fn an_idle_socket_is_closed_1001() {
        use tokio_tungstenite::tungstenite::Message as M;
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = up.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(sock).await.unwrap();
            while let Some(Ok(_)) = ws.next().await {}
        });
        let app = axum::Router::new().route(
            // A variable, not a literal: the OpenAPI scanners read `.route("…")`.
            TEST_PATH_IDLE,
            axum::routing::get(move |ws: WebSocketUpgrade| async move {
                let (upstream, _) = tokio_tungstenite::connect_async(format!("ws://{up_addr}/")).await.unwrap();
                ws.on_upgrade(move |socket| async move {
                    let _ = pipe(socket, upstream, Duration::from_millis(200), Box::pin(std::future::pending())).await;
                })
            }),
        );
        let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(gw, app).await;
        });
        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{gw_addr}/ws/addons/evolve/idle")).await.unwrap();
        let started = std::time::Instant::now();
        let mut code = None;
        while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(5), client.next()).await {
            if let M::Close(f) = m {
                code = f.map(|f| u16::from(f.code));
                break;
            }
        }
        assert_eq!(code, Some(1001));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
