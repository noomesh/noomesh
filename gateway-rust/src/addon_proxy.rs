// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The add-on receiver — one implementation, every HTTP add-on.
//!
//! `addons.rs` answers "is this add-on supposed to be here?" for all of them.
//! This module answers "how do I reach it?" for the ones that speak HTTP, so
//! an add-on's surface is DATA (a route manifest) rather than a hand-written
//! handler per route.
//!
//! ## The manifest ships with the add-on
//!
//! Add-ons are pieces that extend the core at runtime; the core carries none
//! of their route names. An HTTP add-on ships its manifest in its own image,
//! and its compose overlay delivers it READ-ONLY at
//! `<ROUTES_DIR>/<addon>/routes.json` (a one-shot service from the add-on's
//! image fills a volume the gateway mounts; a dev overlay bind-mounts the
//! source file). The runtime registry ([`crate::addon_registry`]) reads it
//! ONCE, when the router is built at startup, for every add-on the operator
//! switched on (`addons.<name>: true`) whose launcher-verified lock lists
//! this stack: a third-party add-on needs no row in `addons.rs`. A file is
//! used, not a fetch from the add-on, so nothing at boot depends on the
//! network or on the add-on being up first.
//!
//! The gateway still decides what it exposes. The manifest declares paths, an
//! upstream and the PERMISSION each public route needs (`min_role`, `scopes`:
//! see "Who may call a route" below), and [`validate`] refuses anything else:
//!
//! - version 1, `addon` = the add-on it was delivered for;
//! - the upstream is that add-on's own service: `base_url_env` is
//!   `NOO_<ADDON>_URL` (`-` becomes `_`) and `base_url_default` is `https://noo-<addon>[:port]`
//!   with no credentials, path or query — no other host can be named;
//! - paths are plain (`/`-separated, no `..`, no wildcard), public ones live
//!   under `/api/` and outside the gateway's own namespaces
//!   ([`RESERVED_PREFIXES`]), and every `{param}` is declared;
//! - routes the gateway itself calls by name ([`CALLED_BY_NAME`]) are
//!   `internal`, so the add-on cannot publish them;
//! - a mutating public route is one the front door already refuses a
//!   User-tier caller ([`crate::auth::requester_allows`]), so a manifest can
//!   never place a write where a User could reach it. Scopes stay the
//!   gateway's: the global auth middleware runs before every mounted route.
//!
//! A route that collides with a core route is refused too ([`mount`]): the
//! add-on cannot replace a gateway handler.
//!
//! ## Fail loud, never partial
//!
//! An add-on that is switched on but whose manifest is missing, unreadable or
//! invalid gets NONE of its routes, and the reason is everywhere an operator
//! looks: an `error` log line at startup, `/health` `addons.<name>:
//! "unhealthy"`, and every internal [`call`] / [`forward_named`] answers with
//! it. The most likely cause is an add-on image from before manifests shipped
//! with the add-on, and the message says so. A switched-off add-on mounts
//! nothing and the gateway starts normally.
//!
//! ## Delegation keys
//!
//! Two top-level manifest keys prepare an add-on to act for a present person
//! through that person's own tasks (noomesh-internal i143). They are parsed
//! and validated here and exposed by the registry; nothing here mints a token.
//!
//! - `delegate: "tasks"`: the only accepted value. Declaring it grants
//!   nothing; the operator must also enable it (`addon_delegation.<name>.tasks`).
//! - `task_events: {"method": "POST", "path": "/..."}`: where the gateway
//!   POSTs task events. Valid only with `delegate`, POST only, a plain path
//!   without `{param}`, and it must not equal or match any PUBLIC route of the
//!   same manifest (an `internal` route's path is fine), so it is never
//!   reachable through the front door.
//!
//! ## What a route can say
//!
//! - `method` (`GET` | `POST` | `PUT` | `PATCH` | `DELETE` | `WS`), `path` —
//!   mounted verbatim, forwarded verbatim. Every method but `GET` (and `WS`)
//!   is a write and keeps the `POST` rule below. `WS` is a WebSocket route ([`crate::addon_ws`]): its path lives
//!   under `/ws/addons/<addon>/`, and `max_message_bytes`, `idle_timeout_secs`
//!   and `max_connections_per_user` bound it (WS routes only).
//! - `aliases` — extra gateway paths that reach the same upstream route.
//! - `params` — `{"cycle_id": "uuid"}` (`uuid` | `string`). A malformed uuid
//!   is rejected HERE with a 400, so garbage never reaches the upstream URL.
//! - `query` — pass the caller's query string through.
//! - `internal` — callable from gateway code via [`call`], NOT mounted.
//! - `timeout_secs` — per route, defaulting to the manifest's.
//! - `min_role` — `user` | `operator` | `admin`; absent means `operator`.
//! - `scopes` — add-on scopes (`<addon>:<word>`) that also open a GET route.
//! - `note` — free text, ignored.
//!
//! ## Who may call a route
//!
//! Add-on routes are scoped by permission like every core route. Each public
//! route carries `min_role`, enforced here BEFORE anything is forwarded, for
//! every method, from the same [`crate::auth::Role`] tiers core uses (a
//! requester's role is the one `Claims::resolved_role` derived at validation):
//!
//! - the requester's role is at least `min_role`; or
//! - a GET route lists `scopes` and the requester holds `read` plus one of
//!   them (an additive grant to a person's `read`, exactly the shape of core's
//!   `graph` scope: never a credential on its own).
//!
//! An ABSENT `min_role` is `operator`, for every method. An add-on that has
//! not said who may read a route (an older one, a third-party one) therefore
//! shows it to Operators and Admins only; a User never sees a route nobody
//! vouched for. An unknown role word refuses the whole manifest at load
//! ([`validate`]); it is never read as `user`. Writes keep their existing
//! rule and are never widened: a POST is `operator` or `admin`, and takes no
//! scopes (the tier gate refuses a User's writes before a scope is asked).
//!
//! The tier gate in `auth.rs` asks [`mounted_get_allows`] for a User's GET so
//! it answers at the front door; [`serve`] asks [`RouteSpec::permits`] again,
//! which also covers `admin` routes (Operators pass the front door) and every
//! alias. A requester with no `RequesterCtx` is a machine credential (cluster
//! HMAC, service key) that the front door already admitted as trusted; it is
//! not narrowed here. Gateway code that calls a route by NAME (`internal`)
//! has no requester and no role: the gateway decided to make that call.
//!
//! ## WebSocket routes and the add-on's UI
//!
//! A `WS` route is authenticated by the front door exactly like the
//! gateway's own `/ws/*` sockets (`?token=` on a real handshake, or the
//! `Authorization` header), checked against `min_role` BEFORE anything is
//! dialled, then dialled as `wss://` with the same per-request identity
//! headers, and only then upgraded; frames are piped both ways
//! ([`crate::addon_ws`]).
//!
//! The top-level `ui` key serves the add-on's own web UI at
//! `/addons/<addon>/ui/…`, a gateway-owned namespace no core route uses:
//! GET/HEAD only, `min_role` enforced, path traversal refused, response
//! headers sanitised and a gateway CSP added ([`crate::addon_ui`]).
//!
//! A gateway from before these keys refuses a manifest that uses them
//! (unknown method, unknown key), so an add-on that declares them ships with
//! a `supports_stack` starting at the release that reads them.
//!
//! ## The contract every mounted route keeps
//!
//! Upstream status and JSON body pass through verbatim; a non-JSON body is
//! wrapped as `{"raw": "..."}` with the status preserved. The request carries
//! the gateway's own bearer and the requester's identity, set here, never
//! forwarded.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path as FsPath;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, RawQuery},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;

/// Where the add-on overlays deliver manifests: `<ROUTES_DIR>/<addon>/routes.json`.
pub const ROUTES_DIR: &str = "/opt/noo/addon-routes";
/// The file name inside an add-on's directory.
pub const ROUTES_FILE: &str = "routes.json";

/// Routes the gateway calls by NAME from its own code. Each must be
/// `internal` when an add-on declares it: the gateway decides when they run
/// (`agent_meta_loop`, the console and CLI pieces it validates, the core
/// `POST /api/prompt-skills/evolve`), and a public copy would let a caller
/// reach them around that decision.
pub const CALLED_BY_NAME: &[&str] = &[
    "meta_loop_dispatch",
    "console_piece",
    "cli_piece",
    "prompt_skills_evolve",
];

/// Gateway-owned namespaces no add-on route may be published under. Most
/// would collide with a core route anyway; this also stops a STATIC add-on
/// path from shadowing a core `{param}` route (e.g. its own
/// `/api/addons/<id>/cli-piece`, which the gateway validates).
pub const RESERVED_PREFIXES: &[&str] = &[
    "/api/addons/",
    "/api/auth",
    "/api/security/",
    "/api/config",
    "/api/users",
    "/api/v1/settings/",
    "/api/cluster/",
    "/api/logs/",
    "/api/metrics/",
    "/api/grafana-ds/",
    // The harness task API: a delegated token is valid only on these
    // routes, and every account may write its own tasks here, so an add-on
    // path inside it would blur both rules.
    "/api/tasks",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonManifest {
    pub version: u32,
    /// Must be the add-on the file was delivered for (a plain name,
    /// [`crate::addon_registry::name_ok`]). The runtime registry
    /// ([`crate::addon_registry`]) decides whether it is registered at all:
    /// operator-enabled, and verified by the launcher.
    pub addon: String,
    pub base_url_env: String,
    pub base_url_default: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub routes: Vec<RouteSpec>,
    /// `"tasks"`: the add-on asks to act for a present person through that
    /// person's own tasks (noomesh-internal i143). Declaring it does nothing
    /// by itself: the operator must also enable it
    /// (`addon_delegation.<name>.tasks`, see [`crate::addon_registry`]). The
    /// only accepted value is `"tasks"`; [`validate`] refuses any other.
    #[serde(default)]
    pub delegate: Option<String>,
    /// Where the gateway POSTs task events for this add-on. Valid only with
    /// `delegate: "tasks"`, POST only, and never a public route of the same
    /// manifest: it is reachable by the gateway, not through the front door.
    #[serde(default)]
    pub task_events: Option<TaskEventsSpec>,
    /// The add-on's own web UI, served at `/addons/<addon>/ui/…`
    /// ([`crate::addon_ui`]). Absent: the add-on serves no UI.
    #[serde(default)]
    pub ui: Option<UiSpec>,
}

/// The manifest's `ui` key: `{"upstream_path": "/ui", "min_role": "user"}`.
///
/// `/addons/<addon>/ui/<rest>` is fetched from `<upstream><upstream_path>/<rest>`.
/// The gateway path is fixed (the add-on cannot choose where its UI is
/// mounted), so it can never shadow a core path.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiSpec {
    /// Where the add-on serves its UI on its own side: a plain path, no
    /// `{param}`. Default `/`: the gateway strips `/addons/<addon>/ui` and
    /// forwards the rest as it is (a UI built for a directory mount, with
    /// relative asset, API and socket paths, needs nothing else).
    #[serde(default = "default_ui_upstream")]
    pub upstream_path: String,
    /// The lowest role that may load the UI. Absent means `operator`, as on
    /// a route.
    #[serde(default)]
    pub min_role: Option<String>,
    /// A label the console may show on its link. Plain text, at most 64
    /// characters.
    #[serde(default)]
    pub title: Option<String>,
    /// Per request (1–600); falls back to the manifest's.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Free text, ignored.
    #[serde(default)]
    pub note: Option<String>,
}

fn default_ui_upstream() -> String {
    "/".into()
}

impl UiSpec {
    /// Absent is `operator`; an unknown word (refused at load) is `admin`.
    pub fn required_role(&self) -> crate::auth::Role {
        match self.min_role.as_deref() {
            None => crate::auth::Role::Operator,
            Some(w) => parse_role(w).unwrap_or(crate::auth::Role::Admin),
        }
    }

    /// May a requester of `role` load this UI? A UI takes no scopes.
    pub fn permits(&self, role: crate::auth::Role) -> bool {
        role >= self.required_role()
    }
}

/// The manifest's `task_events` route: `{"method": "POST", "path": "/..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEventsSpec {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    /// Stable key for [`call`]. Internal callers name this instead of a path
    /// literal, so a path change is one edit in one file.
    pub name: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// `name -> format`: `uuid` (validated) or `string`.
    #[serde(default)]
    pub params: HashMap<String, String>,
    #[serde(default)]
    pub query: bool,
    /// Reachable from gateway code only — never mounted on the public API.
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// The lowest role that may call this public route: `user`, `operator` or
    /// `admin`. Absent means `operator` (see "Who may call a route"). Kept as
    /// the manifest's own word so an unknown value is refused by
    /// [`validate`] with a sentence, not a serde variant error.
    #[serde(default)]
    pub min_role: Option<String>,
    /// Add-on scopes (`<addon>:<word>`) that also open this GET route to a
    /// requester holding `read` plus the scope, below `min_role`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Opt-in for a `POST` at `min_role: "user"`: the add-on promises to read
    /// and write only rows owned by the account the gateway forwards in
    /// `x-noo-requester-sub`. The gateway does NOT check that promise. Without
    /// it a `POST` is `operator` or `admin` (see "Who may call a route").
    #[serde(default)]
    pub owner_scoped: bool,
    /// This public route may be sent the add-on delegated task token
    /// (noomesh-internal i143), so a manifest can keep the token off routes
    /// that never need it (a GPU media route). Default false. Valid only when
    /// the manifest declares top-level `delegate: "tasks"`, only on a public
    /// route, and never on the `task_events` path. Declaring it grants
    /// nothing by itself: see `AddonEntry::route_receives_delegation`.
    #[serde(default)]
    pub receives_delegation: bool,
    /// `WS` routes only: the largest message (and frame) accepted in either
    /// direction, in bytes. Default 1 MiB, at most 16 MiB.
    #[serde(default)]
    pub max_message_bytes: Option<usize>,
    /// `WS` routes only: a socket with no frame in either direction for this
    /// long is closed (1001). Default 300, 1–3600.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// `WS` routes only: how many sockets one account may hold open on this
    /// route at once. Default 4, 1–64.
    #[serde(default)]
    pub max_connections_per_user: Option<u32>,
    /// Free text for whoever reads the manifest. Ignored by the code.
    #[serde(default)]
    pub note: Option<String>,
}

fn default_timeout() -> u64 {
    300
}

/// The role a manifest word names; `None` for anything else.
fn parse_role(word: &str) -> Option<crate::auth::Role> {
    match word {
        "user" => Some(crate::auth::Role::User),
        "operator" => Some(crate::auth::Role::Operator),
        "admin" => Some(crate::auth::Role::Admin),
        _ => None,
    }
}

impl RouteSpec {
    /// The role this route needs. Absent is `operator`; an unknown word (which
    /// [`validate`] refuses at load, so only a hand-built spec can hold one)
    /// is `admin`, so a bad value can only ever shut a route, never open it.
    pub fn required_role(&self) -> crate::auth::Role {
        match self.min_role.as_deref() {
            None => crate::auth::Role::Operator,
            Some(w) => parse_role(w).unwrap_or(crate::auth::Role::Admin),
        }
    }

    /// May a requester of `role` holding `held` scopes call this route?
    pub fn permits(&self, role: crate::auth::Role, held: &[String]) -> bool {
        if role >= self.required_role() {
            return true;
        }
        let has = |s: &str| held.iter().any(|h| h == s);
        has("read") && self.scopes.iter().any(|s| has(s))
    }
}

impl AddonManifest {
    pub(crate) fn base_url(&self) -> String {
        std::env::var(&self.base_url_env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.base_url_default.clone())
    }

    fn route(&self, name: &str) -> Option<&RouteSpec> {
        self.routes.iter().find(|r| r.name == name)
    }
}

// ── Validation ───────────────────────────────────────────────────────────

const MAX_TIMEOUT_SECS: u64 = 600;
const SAMPLE_PARAM: &str = "00000000-0000-0000-0000-000000000000";

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// The `{param}` names of a path, or why its shape is refused.
fn path_shape(path: &str) -> Result<Vec<String>, String> {
    if !path.starts_with('/') || path.len() > 200 {
        return Err(format!("path {path:?} must start with `/` and be at most 200 bytes"));
    }
    if path == "/" {
        return Err("path `/` is not a route".into());
    }
    let mut params = Vec::new();
    for seg in path[1..].split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("path {path:?} has an empty, `.` or `..` segment"));
        }
        if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if !name_ok(inner) {
                return Err(format!("path {path:?}: `{{{inner}}}` is not a plain parameter (no wildcards)"));
            }
            params.push(inner.to_string());
        } else if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
            return Err(format!("path {path:?}: segment {seg:?} may hold only [A-Za-z0-9._-]"));
        }
    }
    Ok(params)
}

/// The path with every `{param}` filled, for asking the front door about it.
fn sample_path(path: &str) -> String {
    path.split('/')
        .map(|seg| if seg.starts_with('{') { SAMPLE_PARAM } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

/// Would the front door let a User-tier caller (holding every scope a person
/// can hold) make this request? A mutating add-on route must answer no.
fn user_tier_could_call(method: &axum::http::Method, path: &str) -> bool {
    let user = crate::auth::RequesterCtx {
        sub: "addon-manifest-check".into(),
        scopes: ["read", "chat", "ingest", "graph"].iter().map(|s| s.to_string()).collect(),
        role: crate::auth::Role::User,
        harness: None,
        act: None,
    };
    crate::auth::requester_allows(&user, method, &sample_path(path))
}

fn check_upstream(m: &AddonManifest, addon: &str) -> Result<(), String> {
    // `-` is not legal in an environment variable name: `pai-voice` reads
    // `NOO_PAI_VOICE_URL`. The container stays `noo-<addon>` verbatim.
    let want_env = format!("NOO_{}_URL", addon.to_ascii_uppercase().replace('-', "_"));
    if m.base_url_env != want_env {
        return Err(format!(
            "base_url_env is {:?}; an add-on's override variable is {want_env}",
            m.base_url_env
        ));
    }
    let host = container_of(addon);
    let url = reqwest::Url::parse(&m.base_url_default)
        .map_err(|e| format!("base_url_default {:?} is not a URL: {e}", m.base_url_default))?;
    if url.scheme() != "https" {
        return Err(format!(
            "base_url_default {:?} must be https:// — add-on doors are mTLS, never plaintext",
            m.base_url_default
        ));
    }
    if url.host_str() != Some(host.as_str())
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "base_url_default {:?} must be https://{host}[:port] — the add-on's own service, \
             no other host, credentials, path or query",
            m.base_url_default
        ));
    }
    Ok(())
}

/// `<addon>:<word>`: namespaced, so no add-on can declare a core scope.
fn scope_ok(s: &str) -> bool {
    let Some((addon, word)) = s.split_once(':') else { return false };
    let plain = |t: &str| {
        !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    // The add-on part may hold `-` (`pai-voice:read`); a word never does.
    let plain_addon = |t: &str| plain(&t.replace('-', "_"));
    plain_addon(addon) && plain(word) && !word.contains(':')
}

/// Where every `WS` route of `addon` lives: `/ws/addons/<addon>/`. Under
/// `/ws/` so a browser may hand its token over as `?token=` on the handshake
/// (the front door accepts it nowhere else), and under the add-on's own name
/// so it can never shadow a core socket (`/ws/agent`, `/ws/collab`, …).
pub fn ws_prefix(addon: &str) -> String {
    format!("/ws/addons/{addon}/")
}

/// The WS-only knobs are within range, and absent on any other method.
fn check_ws_limits(r: &RouteSpec, ctx: &str) -> Result<(), String> {
    let declared = r.max_message_bytes.is_some() || r.idle_timeout_secs.is_some() || r.max_connections_per_user.is_some();
    if r.method != METHOD_WS {
        if declared {
            return Err(format!(
                "{ctx}: max_message_bytes, idle_timeout_secs and max_connections_per_user apply to a \"WS\" route only"
            ));
        }
        return Ok(());
    }
    if r.internal {
        return Err(format!(
            "{ctx}: a WS route cannot be internal — the gateway never opens a socket to an add-on by name"
        ));
    }
    if let Some(n) = r.max_message_bytes {
        if n == 0 || n > crate::addon_ws::MAX_MAX_MESSAGE_BYTES {
            return Err(format!(
                "{ctx}: max_message_bytes {n} outside 1..={}",
                crate::addon_ws::MAX_MAX_MESSAGE_BYTES
            ));
        }
    }
    if let Some(t) = r.idle_timeout_secs {
        if t == 0 || t > crate::addon_ws::MAX_IDLE_TIMEOUT_SECS {
            return Err(format!(
                "{ctx}: idle_timeout_secs {t} outside 1..={}",
                crate::addon_ws::MAX_IDLE_TIMEOUT_SECS
            ));
        }
    }
    if let Some(c) = r.max_connections_per_user {
        if c == 0 || c > crate::addon_ws::MAX_CONNECTIONS_PER_USER {
            return Err(format!(
                "{ctx}: max_connections_per_user {c} outside 1..={}",
                crate::addon_ws::MAX_CONNECTIONS_PER_USER
            ));
        }
    }
    Ok(())
}

/// The method word of a WebSocket route.
pub const METHOD_WS: &str = "WS";

/// The HTTP methods a route may declare, uppercase exactly. Every one but
/// `GET` is a WRITE: it follows the rule a `POST` always has (operator or
/// admin unless `owner_scoped`, no scopes, never where the front door admits a
/// User).
pub const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Is this manifest method a write (`POST`, `PUT`, `PATCH`, `DELETE`)?
pub fn is_write_method(method: &str) -> bool {
    method != "GET" && method != METHOD_WS && HTTP_METHODS.contains(&method)
}

fn check_route(r: &RouteSpec) -> Result<(), String> {
    let ctx = format!("route {:?}", r.name);
    if !name_ok(&r.name) {
        return Err(format!("{ctx}: names are [a-z][a-z0-9_]{{0,63}}"));
    }
    if !HTTP_METHODS.contains(&r.method.as_str()) && r.method != METHOD_WS {
        return Err(format!(
            "{ctx}: method {:?} — only GET, POST, PUT, PATCH and DELETE, or WS for a WebSocket \
             route (PUT/PATCH/DELETE/WS need a gateway from the release that reads them)",
            r.method
        ));
    }
    check_ws_limits(r, &ctx)?;
    if let Some(t) = r.timeout_secs {
        if t == 0 || t > MAX_TIMEOUT_SECS {
            return Err(format!("{ctx}: timeout_secs {t} outside 1..={MAX_TIMEOUT_SECS}"));
        }
    }
    for (p, format) in &r.params {
        if format != "uuid" && format != "string" {
            return Err(format!("{ctx}: param {p:?} has format {format:?} — uuid or string"));
        }
    }
    if let Some(word) = r.min_role.as_deref() {
        let Some(role) = parse_role(word) else {
            return Err(format!(
                "{ctx}: min_role {word:?} is not a role — use \"user\", \"operator\" or \"admin\" \
                 (an unknown value is refused, never read as user)"
            ));
        };
        if is_write_method(&r.method) && role == crate::auth::Role::User && !r.owner_scoped {
            return Err(format!(
                "{ctx}: a {} cannot be min_role \"user\" — writes are operator or admin, the \
                 front door refuses a User's writes and a manifest does not widen that. A route \
                 whose add-on keeps every row to the calling account may declare \
                 \"owner_scoped\": true (see \"Who may call a route\" in docs/development/addons.md)",
                r.method
            ));
        }
    }
    if r.owner_scoped {
        if !is_write_method(&r.method) || r.internal {
            return Err(format!(
                "{ctx}: owner_scoped applies to a public write route (POST, PUT, PATCH, DELETE) only"
            ));
        }
        if r.min_role.as_deref() != Some("user") {
            return Err(format!(
                "{ctx}: owner_scoped is the opt-in for min_role \"user\" on a write; on any other \
                 role it means nothing — remove it"
            ));
        }
    }
    if !r.scopes.is_empty() {
        if r.method != "GET" {
            return Err(format!("{ctx}: scopes open a GET route only — a scope never widens a write"));
        }
        if r.scopes.len() > 8 {
            return Err(format!("{ctx}: at most 8 scopes per route"));
        }
        for sc in &r.scopes {
            if !scope_ok(sc) {
                return Err(format!(
                    "{ctx}: scope {sc:?} must be `<addon>:<word>` ([a-z0-9_] words), so it can \
                     never be a core scope (read, write, admin, graph, ingest, …)"
                ));
            }
        }
    }
    let declared: HashSet<&str> = r.params.keys().map(String::as_str).collect();
    for path in std::iter::once(&r.path).chain(r.aliases.iter()) {
        let used = path_shape(path).map_err(|e| format!("{ctx}: {e}"))?;
        let used: HashSet<&str> = used.iter().map(String::as_str).collect();
        if used != declared {
            return Err(format!(
                "{ctx}: path {path:?} uses params {used:?} but the route declares {declared:?}"
            ));
        }
        if r.internal {
            continue;
        }
        if r.method == METHOD_WS {
            // The add-on's own `/ws/addons/<addon>/` is checked by
            // `validate`, which knows the add-on; nothing below applies to a
            // socket (the handshake is a GET the handler gates itself).
            if !path.starts_with("/ws/addons/") {
                return Err(format!("{ctx}: a WS path {path:?} must live under /ws/addons/<addon>/"));
            }
            continue;
        }
        if !path.starts_with("/api/") {
            return Err(format!("{ctx}: public path {path:?} must live under /api/"));
        }
        if let Some(p) = RESERVED_PREFIXES.iter().find(|p| path.starts_with(**p)) {
            return Err(format!("{ctx}: public path {path:?} is inside the gateway's own {p} namespace"));
        }
        if r.method != "GET" && !r.owner_scoped {
            let method = axum::http::Method::from_bytes(r.method.as_bytes()).expect("a validated HTTP method");
            if user_tier_could_call(&method, path) {
                return Err(format!(
                    "{ctx}: {} {path:?} would be callable by a User-tier caller — an add-on \
                     cannot place a write where the front door admits a User",
                    r.method
                ));
            }
        }
    }
    Ok(())
}

/// Is this manifest acceptable for `addon`? `Err` names the first problem.
pub fn validate(m: &AddonManifest, addon: &str) -> Result<(), String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!(
            "{addon:?} is not a valid add-on name ({})",
            crate::addon_registry::NAME_RULE
        ));
    }
    if m.version != 1 {
        return Err(format!("version {} — this gateway reads version 1", m.version));
    }
    if m.addon != addon {
        return Err(format!("it names add-on {:?}, but was delivered for {addon:?}", m.addon));
    }
    check_upstream(m, addon)?;
    if m.timeout_secs == 0 || m.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(format!("timeout_secs {} outside 1..={MAX_TIMEOUT_SECS}", m.timeout_secs));
    }
    if m.routes.is_empty() && m.ui.is_none() {
        return Err("it declares no routes".into());
    }
    check_delegation(m)?;
    if let Some(ui) = m.ui.as_ref() {
        check_ui(ui)?;
    }
    let mut names = HashSet::new();
    let mut mounted = HashSet::new();
    for r in &m.routes {
        if CALLED_BY_NAME.contains(&r.name.as_str()) && !r.internal {
            return Err(format!(
                "route {:?} must be internal: the gateway calls it by name and decides when it runs",
                r.name
            ));
        }
        check_route(r)?;
        if r.method == METHOD_WS {
            let want = ws_prefix(addon);
            for path in std::iter::once(&r.path).chain(r.aliases.iter()) {
                if !path.starts_with(&want) || path.len() == want.len() {
                    return Err(format!(
                        "route {:?}: WS path {path:?} must live under {want} (the add-on's own \
                         socket namespace) with at least one segment after it",
                        r.name
                    ));
                }
            }
        }
        for sc in &r.scopes {
            if sc.split(':').next() != Some(addon) {
                return Err(format!(
                    "route {:?}: scope {sc:?} must start with `{addon}:` — an add-on names only its own scopes",
                    r.name
                ));
            }
        }
        if !names.insert(r.name.as_str()) {
            return Err(format!("route name {:?} appears twice", r.name));
        }
        if !r.internal {
            for path in std::iter::once(&r.path).chain(r.aliases.iter()) {
                if !mounted.insert((r.method.as_str(), path.as_str())) {
                    return Err(format!("{} {path:?} is declared twice", r.method));
                }
            }
        }
    }
    Ok(())
}

/// The `ui` key is acceptable: a plain upstream path, a known role, a sane
/// timeout and a short plain title.
fn check_ui(ui: &UiSpec) -> Result<(), String> {
    if ui.upstream_path == "/" {
        // The default: the add-on serves its UI from its root.
    } else if !path_shape(&ui.upstream_path).map_err(|e| format!("ui.upstream_path: {e}"))?.is_empty() {
        return Err(format!("ui.upstream_path {:?} takes no {{param}} segments", ui.upstream_path));
    }
    if let Some(word) = ui.min_role.as_deref() {
        if parse_role(word).is_none() {
            return Err(format!(
                "ui.min_role {word:?} is not a role — use \"user\", \"operator\" or \"admin\" \
                 (an unknown value is refused, never read as user)"
            ));
        }
    }
    if let Some(t) = ui.timeout_secs {
        if t == 0 || t > MAX_TIMEOUT_SECS {
            return Err(format!("ui.timeout_secs {t} outside 1..={MAX_TIMEOUT_SECS}"));
        }
    }
    if let Some(title) = ui.title.as_deref() {
        if title.trim().is_empty() || title.chars().count() > 64 || title.chars().any(|c| c.is_control() || c == '<' || c == '>') {
            return Err(format!("ui.title {title:?} must be 1–64 plain characters (no control characters, no `<` `>`)"));
        }
    }
    Ok(())
}

// ── Delegation keys ──────────────────────────────────────────────────────

/// The only value `delegate` accepts.
pub const DELEGATE_TASKS: &str = "tasks";

/// Validate the manifest's `delegate` and `task_events` keys. `Err` is a
/// sentence naming the key and what to change; nothing here mints or grants
/// anything, it only decides whether the manifest is acceptable.
fn check_delegation(m: &AddonManifest) -> Result<(), String> {
    if let Some(d) = m.delegate.as_deref() {
        if d != DELEGATE_TASKS {
            return Err(format!(
                "delegate {d:?} is not supported — the only value is \"{DELEGATE_TASKS}\" \
                 (an unknown value is refused, never read as tasks)"
            ));
        }
    }
    for r in m.routes.iter().filter(|r| r.receives_delegation) {
        if m.delegate.as_deref() != Some(DELEGATE_TASKS) {
            return Err(format!(
                "route {:?}: receives_delegation is valid only when the manifest declares \
                 \"delegate\": \"{DELEGATE_TASKS}\" — add the delegate key or remove receives_delegation",
                r.name
            ));
        }
        if r.internal {
            return Err(format!(
                "route {:?}: receives_delegation applies to a public route; an internal route is \
                 called by the gateway, which sends no delegated token",
                r.name
            ));
        }
        if let Some(ev) = m.task_events.as_ref() {
            if std::iter::once(&r.path).chain(r.aliases.iter()).any(|p| *p == ev.path) {
                return Err(format!(
                    "route {:?}: receives_delegation is not allowed on the task_events path {:?} \
                     (the gateway calls it, and it carries no delegated token)",
                    r.name, ev.path
                ));
            }
        }
    }
    let Some(ev) = m.task_events.as_ref() else { return Ok(()) };
    if m.delegate.as_deref() != Some(DELEGATE_TASKS) {
        return Err(format!(
            "task_events is valid only with \"delegate\": \"{DELEGATE_TASKS}\" — without \
             delegation nothing is ever sent there; add the delegate key or remove task_events"
        ));
    }
    if ev.method != "POST" {
        return Err(format!(
            "task_events method {:?} — the gateway POSTs task events, so only \"POST\" is accepted",
            ev.method
        ));
    }
    let params = path_shape(&ev.path).map_err(|e| format!("task_events: {e}"))?;
    if !params.is_empty() {
        return Err(format!("task_events path {:?} takes no {{param}} segments", ev.path));
    }
    for r in m.routes.iter().filter(|r| !r.internal) {
        for pat in std::iter::once(&r.path).chain(r.aliases.iter()) {
            if pattern_matches(pat, &ev.path) {
                return Err(format!(
                    "task_events path {:?} equals or matches the public route {:?} ({}): it would \
                     be reachable through the front door. Give task events a path no public route \
                     of this manifest covers",
                    ev.path, pat, r.name
                ));
            }
        }
    }
    Ok(())
}

/// Does the route pattern `pat` (`{param}` segments match any non-empty
/// segment) cover `path`? The one matcher the tier gate and the
/// `task_events` check share.
fn pattern_matches(pat: &str, path: &str) -> bool {
    let p: Vec<&str> = pat.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    p.len() == segs.len() && p.iter().zip(&segs).all(|(a, b)| (a.starts_with('{') && !b.is_empty()) || a == b)
}

// ── Loading ──────────────────────────────────────────────────────────────

/// What startup found: the manifests that will be mounted, and the add-ons
/// that are on but refused, with why.
#[derive(Debug, Default)]
pub struct Loaded {
    pub manifests: Vec<AddonManifest>,
    pub refused: BTreeMap<String, String>,
}

fn missing_reason(addon: &str, path: &FsPath) -> String {
    let c = container_of(addon);
    format!(
        "add-on {addon:?} is enabled but its route manifest is missing ({}). The {addon} image \
         ships it and its overlay delivers it read-only; an {addon} image from before manifests \
         shipped with the add-on has none. Run the gateway and {c} from the same release \
         (`noo stack start` composes the add-on's overlay and refreshes the manifest), or switch \
         the add-on off with `noo addons disable {addon}`",
        path.display()
    )
}

/// Read and validate ONE add-on's manifest at `<dir>/<addon>/routes.json`.
///
/// - `Ok(Some(m))`: present and valid.
/// - `Ok(None)`: the file is not there and `required` is false (a NATS-only
///   add-on, or one that simply ships no routes): nothing to say.
/// - `Err(why)`: missing while `required`, unreadable, not a manifest, or
///   refused by [`validate`]; the sentence is the operator's.
///
/// `addon` must already be a plain name ([`crate::addon_registry::name_ok`]);
/// it is joined into a path.
pub fn read_manifest(dir: &FsPath, addon: &str, required: bool) -> Result<Option<AddonManifest>, String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!(
            "add-on name {addon:?} is not valid ({}); its route manifest was not read",
            crate::addon_registry::NAME_RULE
        ));
    }
    let path = dir.join(addon).join(ROUTES_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if required { Err(missing_reason(addon, &path)) } else { Ok(None) };
        }
        Err(e) => return Err(format!("add-on {addon:?}: cannot read its route manifest {}: {e}", path.display())),
    };
    serde_json::from_str::<AddonManifest>(&raw)
        .map_err(|e| format!("not a valid manifest: {e}"))
        .and_then(|m| validate(&m, addon).map(|()| m))
        .map(Some)
        .map_err(|why| {
            format!(
                "add-on {addon:?}: route manifest {} refused: {why}. None of its routes are \
                 mounted; fix the manifest in the add-on's image",
                path.display()
            )
        })
}

/// Read and validate the manifest of every compiled HTTP add-on whose switch
/// is on. Pure over `dir` and `flag_on`, so every outcome is testable without
/// a global. The runtime registry ([`crate::addon_registry`]) reads further
/// (operator-enabled add-ons the table has never heard of) through
/// [`read_manifest`]; this is the table-driven subset.
pub fn load_all(dir: &FsPath, flag_on: impl Fn(&str) -> bool) -> Loaded {
    let mut out = Loaded::default();
    for a in crate::addons::ADDONS.iter().filter(|a| a.routes_manifest) {
        if !flag_on(a.name) {
            continue; // off: mounts nothing, refuses nothing
        }
        match read_manifest(dir, a.name, true) {
            Ok(Some(m)) => out.manifests.push(m),
            Ok(None) => {}
            Err(why) => {
                out.refused.insert(a.name.to_string(), why);
            }
        }
    }
    out
}

/// Refusals found at MOUNT time (a collision with a core route). Refusals
/// found at load time live in the registry snapshot.
static REFUSED: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

fn refuse(addon: &str, why: String) {
    tracing::error!(addon, "add-on routes refused: {why}");
    if let Ok(mut r) = REFUSED.lock() {
        r.insert(addon.to_string(), why);
    }
}

/// Why this add-on's routes are refused, if they are: at load (the registry
/// snapshot) or at mount. `None` for an add-on that is off, has no manifest
/// by design, or loaded cleanly.
pub fn refusal(addon: &str) -> Option<String> {
    if let Some(why) = REFUSED.lock().ok().and_then(|r| r.get(addon).cloned()) {
        return Some(why);
    }
    crate::addon_registry::refusal(addon)
}

/// The manifests in force: registered, valid, and not refused at mount.
pub fn manifests() -> Vec<AddonManifest> {
    crate::addon_registry::all()
        .iter()
        .map(|e| e.manifest())
        .filter(|m| refusal(&m.addon).is_none())
        .cloned()
        .collect()
}

/// Every add-on scope (`<addon>:<word>`) a loaded manifest declares on some
/// route, sorted and unique. This is what may be GRANTED to an account or a
/// service key (`routes::users`): a scope no loaded add-on declares opens
/// nothing, so granting it would be a typo that reads as a permission.
pub fn declared_scopes() -> Vec<String> {
    declared_scopes_of(&manifests())
}

pub fn declared_scopes_of(manifests: &[AddonManifest]) -> Vec<String> {
    let set: std::collections::BTreeSet<String> = manifests
        .iter()
        .flat_map(|m| m.routes.iter())
        .flat_map(|r| r.scopes.iter().cloned())
        .collect();
    set.into_iter().collect()
}

/// May a requester of `role` holding `scopes` GET `path` through a loaded
/// add-on manifest? The tier gate asks this for a User-tier GET, so an
/// add-on's read surface is scoped by its own `min_role`/`scopes` instead of
/// being waved through. False when no mounted route matches. When more than
/// one pattern matches a path (a static route beside a `{param}` one), ALL of
/// them must permit: the stricter reading, never the wider.
pub fn mounted_get_allows(scopes: &[String], role: crate::auth::Role, path: &str) -> bool {
    get_allows(&manifests(), scopes, role, path)
}

/// May a requester of `role` holding `scopes` make a non-GET `method` call to
/// `path` through a loaded `owner_scoped` route? The tier gate asks this for a
/// User's write. False unless EVERY mounted route matching the method and path
/// is `owner_scoped` and permits the role: a static route beside a `{param}`
/// one that is not owner-scoped keeps the stricter reading.
pub fn mounted_owner_scoped_allows(
    method: &axum::http::Method,
    scopes: &[String],
    role: crate::auth::Role,
    path: &str,
) -> bool {
    owner_scoped_allows(&manifests(), method, scopes, role, path)
}

fn owner_scoped_allows(
    manifests: &[AddonManifest],
    method: &axum::http::Method,
    scopes: &[String],
    role: crate::auth::Role,
    path: &str,
) -> bool {
    let hits = matching_routes(manifests, method.as_str(), path);
    !hits.is_empty() && hits.iter().all(|r| r.owner_scoped && r.permits(role, scopes))
}

fn get_allows(manifests: &[AddonManifest], scopes: &[String], role: crate::auth::Role, path: &str) -> bool {
    // An add-on's UI (`/addons/<addon>/ui/…`) is scoped by its `ui.min_role`.
    if let Some(addon) = crate::addon_ui::ui_addon_of(path) {
        return manifests
            .iter()
            .find(|m| m.addon == addon)
            .and_then(|m| m.ui.as_ref())
            .is_some_and(|ui| ui.permits(role));
    }
    let hits = matching_routes(manifests, "GET", path);
    !hits.is_empty() && hits.iter().all(|r| r.permits(role, scopes))
}

#[cfg(test)]
fn manifests_get_match(manifests: &[AddonManifest], path: &str) -> bool {
    !matching_routes(manifests, "GET", path).is_empty()
}

pub(crate) fn matching_routes<'a>(manifests: &'a [AddonManifest], method: &str, path: &str) -> Vec<&'a RouteSpec> {
    manifests
        .iter()
        .flat_map(|m| m.routes.iter())
        .filter(|r| !r.internal && r.method == method)
        .filter(|r| {
            std::iter::once(&r.path).chain(r.aliases.iter()).any(|pat| pattern_matches(pat, path))
        })
        .collect()
}

// ── Mounting ─────────────────────────────────────────────────────────────

/// Every non-internal route of one manifest.
pub fn addon_router(manifest: &AddonManifest) -> Router<Arc<AppState>> {
    let manifest = Arc::new(manifest.clone());
    let mut router = Router::new();
    for spec in manifest.routes.iter().filter(|r| !r.internal) {
        let spec = Arc::new(spec.clone());
        for path in std::iter::once(&spec.path).chain(spec.aliases.iter()) {
            router = router.route(path, method_router(&manifest, &spec));
        }
    }
    router
}

/// Merge each loaded add-on's routes into the core router. An add-on whose
/// routes collide with a core route is refused as a whole (the merge panics
/// on an overlap; it is tried on a copy), so it can neither replace a gateway
/// handler nor take the gateway down at startup.
pub fn mount(core: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    // Boot: build the registry now so its refusals and registrations are in
    // the log before the first request, not at the first lookup.
    crate::addon_registry::reload();
    merge_each(core, manifests(), refuse)
}

fn merge_each(
    core: Router<Arc<AppState>>,
    manifests: Vec<AddonManifest>,
    mut on_refuse: impl FnMut(&str, String),
) -> Router<Arc<AppState>> {
    let mut router = core;
    for m in manifests {
        let piece = addon_router(&m);
        let candidate = router.clone();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || candidate.merge(piece))) {
            Ok(merged) => router = merged,
            Err(panic) => {
                let detail = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                on_refuse(
                    &m.addon,
                    format!(
                        "add-on {:?}: its routes collide with the gateway's own ({detail}); none \
                         are mounted",
                        m.addon
                    ),
                );
            }
        }
    }
    router
}

fn method_router(
    manifest: &Arc<AddonManifest>,
    spec: &Arc<RouteSpec>,
) -> axum::routing::MethodRouter<Arc<AppState>> {
    let handler = {
        let manifest = manifest.clone();
        let spec = spec.clone();
        move |params: Option<Path<HashMap<String, String>>>,
              RawQuery(q): RawQuery,
              ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
              body: Option<Json<Value>>| {
            let manifest = manifest.clone();
            let spec = spec.clone();
            async move {
                let params = params.map(|Path(p)| p).unwrap_or_default();
                let requester = ctx.map(|axum::Extension(r)| r);
                serve(
                    &manifest,
                    &spec,
                    params,
                    q,
                    body.map(|Json(b)| b),
                    requester.as_ref(),
                )
                .await
            }
        }
    };
    // `validate` admits HTTP_METHODS and WS only.
    match spec.method.as_str() {
        METHOD_WS => crate::addon_ws::method_router(manifest, spec),
        "POST" => post(handler),
        "PUT" => put(handler),
        "PATCH" => patch(handler),
        "DELETE" => delete(handler),
        _ => get(handler),
    }
}

async fn serve(
    manifest: &AddonManifest,
    spec: &RouteSpec,
    params: HashMap<String, String>,
    query: Option<String>,
    body: Option<Value>,
    requester: Option<&crate::auth::RequesterCtx>,
) -> Response {
    // An owner-scoped route is only safe because the add-on is handed the
    // verified account. No requester means no account to hand over: refuse
    // rather than forward a write the add-on cannot attribute.
    if spec.owner_scoped && requester.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "detail": "this route acts for the signed-in account; no verified caller" })),
        )
            .into_response();
    }
    // Permission first, before a param is parsed or anything is forwarded.
    if let Some(r) = requester {
        if !spec.permits(r.role, &r.scopes) {
            return forbidden(manifest, spec);
        }
    }
    let mut path = match fill_path(spec, &params) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    if spec.query {
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            path = format!("{path}?{q}");
        }
    }
    forward(manifest, spec, &path, body, requester).await
}

/// Substitute path params, validating each against its declared format so a
/// malformed id is a clean 400 here rather than whatever the upstream makes
/// of it.
pub(crate) fn fill_path(spec: &RouteSpec, params: &HashMap<String, String>) -> Result<String, Response> {
    let mut path = spec.path.clone();
    for (name, format) in &spec.params {
        let Some(value) = params.get(name) else {
            return Err(bad_request(format!("missing path parameter `{name}`")));
        };
        if format == "uuid" && uuid::Uuid::parse_str(value).is_err() {
            return Err(bad_request(format!("Invalid {name}: {value}")));
        }
        path = path.replace(&format!("{{{name}}}"), value);
    }
    Ok(path)
}

pub(crate) fn forbidden(manifest: &AddonManifest, spec: &RouteSpec) -> Response {
    let need = spec.required_role().as_str();
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "detail": format!(
                "{} {} needs the {need} role{}",
                spec.method,
                spec.path,
                if spec.scopes.is_empty() {
                    String::new()
                } else {
                    format!(" (or `read` plus one of: {})", spec.scopes.join(", "))
                }
            ),
            "addon": manifest.addon,
            "required_role": need,
            "scopes": spec.scopes,
        })),
    )
        .into_response()
}

fn bad_request(msg: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "detail": msg }))).into_response()
}

/// Gate, then forward. The gate is the whole reason a disabled add-on is
/// distinguishable from a broken one.
async fn forward(
    manifest: &AddonManifest,
    spec: &RouteSpec,
    path: &str,
    body: Option<Value>,
    requester: Option<&crate::auth::RequesterCtx>,
) -> Response {
    if !crate::addons::enabled(&manifest.addon) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": crate::addons::refusal_msg(&manifest.addon),
                "addon": manifest.addon,
                "state": crate::addons::health_word(&manifest.addon),
            })),
        )
            .into_response();
    }

    // HTTPS or nothing. The request carries the gateway's
    // own bearer and the requester identity headers, so a plaintext base URL
    // — the manifest default before 1256, or an operator's `NOO_EVOLVE_URL`
    // override — would put them on the compose network in the clear. Refused
    // BEFORE anything is sent, with a reason, never downgraded.
    let base = manifest.base_url();
    if let Some(reason) = plaintext_refusal(&manifest.addon, &manifest.base_url_env, &base) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": reason,
                "addon": manifest.addon,
                "state": "misconfigured",
            })),
        )
            .into_response();
    }
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let method = reqwest::Method::from_bytes(spec.method.to_ascii_uppercase().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let timeout = std::time::Duration::from_secs(spec.timeout_secs.unwrap_or(manifest.timeout_secs));

    let mut req = crate::tls::cluster_client().request(method, &url).timeout(timeout);
    for (name, value) in caller_headers(requester) {
        req = req.header(name, value);
    }
    // The delegated task token (i143), only where the route opted in and the
    // operator allowed it. The request is built from nothing, so a client's
    // own `x-noo-delegation` can never ride along; this is the only place the
    // header is set, and the token is never logged.
    if let Some(r) = requester {
        if let Some(entry) = crate::addon_registry::get(&manifest.addon) {
            let route = path.split('?').next().unwrap_or(path);
            if mints_delegation(Some(r), entry.route_receives_delegation(&spec.method, route), entry.operator_enabled()) {
                match crate::addon_delegation::mint(r, &manifest.addon) {
                    Some(token) => {
                        if let Ok(mut v) = reqwest::header::HeaderValue::from_str(&token) {
                            v.set_sensitive(true);
                            req = req.header(crate::addon_delegation::HEADER, v);
                        }
                    }
                    None => tracing::error!(addon = %manifest.addon, "add-on delegation: could not mint the delegated token (no NOO_JWT_SECRET on the gateway?); the add-on gets none and fails closed"),
                }
            }
        }
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    match req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let text = resp.text().await.unwrap_or_default();
            let json: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
            (status, Json(json)).into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(unreachable_body(&manifest.addon, &base, &e)),
        )
            .into_response(),
    }
}

/// `Some(reason)` when `base` is not an `https://` URL. The add-on doors are
/// mTLS (the gateway presents its leaf through [`crate::tls::cluster_client`]
/// and verifies the add-on's against the cluster CA); there is no plain door
/// to dial and no downgrade.
pub(crate) fn plaintext_refusal(addon: &str, env: &str, base: &str) -> Option<String> {
    if base.trim_start().to_ascii_lowercase().starts_with("https://") {
        return None;
    }
    Some(format!(
        "refusing to dial add-on {addon:?} at {base:?}: add-on doors are HTTPS with a \
         cluster-CA client certificate, and this request carries the gateway's bearer. \
         Set {env} to an https:// URL (or unset it for the manifest default)"
    ))
}

/// Why a dial failed, as one word an operator (or `call()`'s caller) can act
/// on. Read from the whole error chain: reqwest's own Display is only the top
/// frame ("error sending request"), and the fact that matters — rustls saw
/// plain HTTP where a ServerHello should be — is several `source()`s down.
pub(crate) fn classify_send_error(chain: &str, is_timeout: bool) -> &'static str {
    let c = chain.to_ascii_lowercase();
    if c.contains("invalidcontenttype")
        || c.contains("corrupt message")
        || c.contains("certificate")
        || c.contains("handshake")
        || c.contains("tls")
        || c.contains("alert")
        || c.contains("unknownissuer")
    {
        "tls"
    } else if is_timeout {
        "timeout"
    } else if c.contains("dns") || c.contains("resolve") || c.contains("lookup") {
        "dns"
    } else if c.contains("refused") || c.contains("connect") {
        "connect"
    } else {
        "other"
    }
}

pub(crate) fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(s) = cur {
        parts.push(s.to_string());
        cur = s.source();
    }
    parts.join(": ")
}

/// The structured add-on-unreachable answer. `reason: "tls"` carries the
/// roll-skew hint, because the one way a correctly configured install gets
/// there is a gateway and an add-on image from different releases: this
/// gateway dials `https://` and an add-on image built before the design
/// serves plain HTTP (or presents no cluster-CA leaf).
fn unreachable_body(addon: &str, base: &str, e: &reqwest::Error) -> Value {
    let chain = error_chain(e);
    let reason = classify_send_error(&chain, e.is_timeout());
    let container = container_of(addon);
    let hint = match reason {
        "tls" => format!(
            "the TLS handshake with {container} failed. It must serve HTTPS with its \
             services/{addon} leaf and accept the gateway's cluster-CA client certificate; \
             an {addon} image older than this gateway serves plain HTTP — upgrade the stack \
             so both come from the same release"
        ),
        "timeout" => format!("{container} did not answer in time"),
        "dns" => format!("{container} does not resolve — is the add-on overlay composed?"),
        "connect" => format!("nothing is listening at {base} — `docker logs {container}`"),
        _ => format!("see `docker logs {container}`"),
    };
    json!({
        "error": format!("{container} unreachable ({reason}): {hint}"),
        "addon": addon,
        "state": "unreachable",
        "reason": reason,
        "url": base,
        "detail": chain,
    })
}

/// The gateway's own bearer. An add-on resolves it through the
/// `noo_addon_caller_keys` view; see `addon_auth`.
pub const CALLER_HEADER: &str = "authorization";

/// Who the gateway is acting for. ABSENT means the gateway itself — a
/// heartbeat digest, the meta-loop, a scheduled evaluator — never "anyone".
/// An add-on that makes an access decision must treat a missing `sub` as an
/// internal caller with no human behind it, exactly as `Consumer::all` does
/// on the inbound side, and must not read it as unrestricted.
pub const REQUESTER_SUB: &str = "x-noo-requester-sub";
/// The live session, when the account was reached through one. `sub` is the
/// person; this is the connection, the same split `delegation.rs` writes into
/// `_requester` on the NATS leg.
pub const REQUESTER_CONNECTION: &str = "x-noo-requester-connection";
/// The role resolved AT VALIDATION TIME, never re-derived from the scopes.
pub const REQUESTER_ROLE: &str = "x-noo-requester-role";
/// Comma-separated, in the order the credential carries them.
pub const REQUESTER_SCOPES: &str = "x-noo-requester-scopes";

/// Build the outbound identity headers.
///
/// These are SET, never forwarded: the request to the add-on is constructed
/// here from nothing, so a client that sends its own `X-Noo-Requester-Sub` has
/// it dropped at the gateway rather than passed on. That is the whole reason
/// the add-on may trust them — they are only as good as the bearer beside
/// them, and both arrive from the same place.
///
/// A header value that will not encode is skipped rather than failing the
/// call. A username is checked at signup and cannot hold a control character;
/// skipping keeps a hypothetical one from turning an authorization detail into
/// a 500, and the add-on then sees "no requester", which is the closed answer.
pub(crate) fn caller_headers(requester: Option<&crate::auth::RequesterCtx>) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(t) = crate::addon_auth::token() {
        out.push((CALLER_HEADER, format!("Bearer {t}")));
    }
    if let Some(r) = requester {
        out.push((REQUESTER_SUB, crate::auth::account_of(&r.sub).to_string()));
        out.push((REQUESTER_CONNECTION, r.sub.clone()));
        out.push((REQUESTER_ROLE, r.role.as_str().to_string()));
        out.push((REQUESTER_SCOPES, r.scopes.join(",")));
    }
    out.retain(|(_, v)| reqwest::header::HeaderValue::from_str(v).is_ok());
    out
}

/// Does this proxied request carry a delegated task token? Only for an
/// authenticated person whose own token is not itself delegated (no `act`, so a
/// delegated token never mints another), on a route that declares
/// `receives_delegation`, for an add-on the operator enabled.
pub(crate) fn mints_delegation(requester: Option<&crate::auth::RequesterCtx>, route_receives: bool, operator_enabled: bool) -> bool {
    route_receives && operator_enabled && requester.is_some_and(|r| r.act.is_none())
}

/// The container name an operator would `docker logs`. Kept alongside the
/// add-on name so an unreachable-error names something they can act on.
pub(crate) fn container_of(addon: &str) -> String {
    format!("noo-{addon}")
}

/// What an internal caller got back.
pub enum CallOutcome {
    /// The add-on answered 2xx. Carries the parsed JSON body.
    Ok(Value),
    /// Disabled, unlicensed, refused, unreachable, or a non-2xx answer.
    /// Carries the sentence to show an operator — always a reason, never a
    /// blank.
    Unavailable(String),
}

/// The explained 503 for an add-on route the gateway cannot reach right now.
fn unavailable(addon: &str, error: String, state: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": error, "addon": addon, "state": state })),
    )
        .into_response()
}

/// Resolve `addon`'s route `route_name`, or the 503 that explains why not:
/// off or unlicensed (the add-on's own refusal text), refused at startup
/// (the reason), or loaded without that row.
fn resolve(addon: &str, route_name: &str) -> Result<(AddonManifest, RouteSpec), Response> {
    if !crate::addons::enabled(addon) {
        return Err(unavailable(
            addon,
            crate::addons::refusal_msg(addon),
            crate::addons::health_word(addon),
        ));
    }
    if let Some(why) = refusal(addon) {
        return Err(unavailable(addon, why, "unhealthy"));
    }
    let Some(manifest) = manifests().into_iter().find(|m| m.addon == addon) else {
        // On now but not when the router was built (the switch is read at
        // startup), or not an HTTP add-on at all.
        return Err(unavailable(
            addon,
            format!(
                "add-on {addon:?} has no route manifest loaded — it was off when the gateway \
                 started; restart the gateway (`noo stack start`) to mount its routes"
            ),
            "unhealthy",
        ));
    };
    let Some(spec) = manifest.route(route_name).cloned() else {
        // A typo'd route name, or an add-on image older than the gateway
        // code that calls it: say exactly what was asked for.
        return Err(unavailable(
            addon,
            format!("add-on {addon:?} declares no route named {route_name:?}"),
            "unhealthy",
        ));
    };
    if !spec.params.is_empty() {
        return Err(unavailable(
            addon,
            format!("route {route_name:?} takes path parameters; a named call does not substitute them"),
            "unhealthy",
        ));
    }
    Ok((manifest, spec))
}

/// Forward a request to one route by its manifest `name`, answering with the
/// add-on's status and body verbatim (or the explained 503). This is how a
/// CORE route that an add-on implements is served — the gateway owns the
/// path, and the add-on's row is `internal`.
pub async fn forward_named(
    addon: &str,
    route_name: &str,
    body: Option<Value>,
    requester: Option<&crate::auth::RequesterCtx>,
) -> Response {
    match resolve(addon, route_name) {
        Ok((manifest, spec)) => forward(&manifest, &spec, &spec.path, body, requester).await,
        Err(resp) => resp,
    }
}

/// Call one route from gateway code, naming it by its manifest `name`.
///
/// This is how an internal caller reaches an add-on without a path literal:
/// `call("evolve", "meta_loop_dispatch", body)`. It works for `internal`
/// routes, which is the point — they are reachable from here and from
/// nowhere on the public API.
///
/// Never returns an error type. A caller is normally something like a
/// heartbeat digest, and "the add-on is off" must not become "your digest
/// stopped arriving".
pub async fn call(addon: &str, route_name: &str, body: Option<Value>) -> CallOutcome {
    let resp = forward_named(addon, route_name, body, None).await;
    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return CallOutcome::Unavailable(format!("unreadable response: {e}")),
    };
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    if status.is_success() {
        CallOutcome::Ok(parsed)
    } else {
        // The gate and the transport failures both land here with their
        // reason already in `error`; a bare status is the fallback.
        let reason = parsed
            .get("error")
            .and_then(|e| e.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{} answered {status}", container_of(addon)));
        CallOutcome::Unavailable(reason)
    }
}

/// What the add-on answered to a pushed task event.
pub struct EventPost {
    /// The HTTP status, or `None` when nothing was sent or nothing came back.
    pub status: Option<u16>,
    /// The parsed JSON body, when there was one.
    pub body: Option<Value>,
    /// A short reason for a log line when the push did not succeed.
    pub detail: String,
}

/// Push one task event to the add-on's manifest `task_events` route (i143 D).
///
/// Same gates as [`forward`] (the add-on must be enabled, HTTPS only, the
/// cluster client certificate), the gateway's caller bearer, and the
/// `X-Noo-Requester-*` headers set to `requester` (the task's OWNER). It
/// returns what happened instead of a `Response`: the caller is the delivery
/// loop, which decides on the status.
pub async fn post_task_event(
    entry: &crate::addon_registry::AddonEntry,
    spec: &TaskEventsSpec,
    requester: &crate::auth::RequesterCtx,
    body: &Value,
) -> EventPost {
    let manifest = entry.manifest();
    let fail = |detail: String| EventPost { status: None, body: None, detail };
    if !crate::addons::enabled(&manifest.addon) {
        return fail(format!("add-on {} is {}", manifest.addon, crate::addons::health_word(&manifest.addon)));
    }
    let base = entry.upstream();
    if let Some(reason) = plaintext_refusal(&manifest.addon, &manifest.base_url_env, &base) {
        return fail(reason);
    }
    let url = format!("{}{}", base.trim_end_matches('/'), spec.path);
    let method = reqwest::Method::from_bytes(spec.method.to_ascii_uppercase().as_bytes()).unwrap_or(reqwest::Method::POST);
    let timeout = std::time::Duration::from_secs(manifest.timeout_secs.clamp(1, 30));
    let mut req = crate::tls::cluster_client().request(method, &url).timeout(timeout);
    for (name, value) in caller_headers(Some(requester)) {
        req = req.header(name, value);
    }
    match req.json(body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let parsed = serde_json::from_str::<Value>(&text).ok();
            EventPost { status: Some(status), body: parsed, detail: format!("{} answered {status}", container_of(&manifest.addon)) }
        }
        Err(e) => fail(format!("{} unreachable: {e}", container_of(&manifest.addon))),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(super) fn ctx(sub: &str, role: crate::auth::Role, scopes: &[&str]) -> crate::auth::RequesterCtx {
        crate::auth::RequesterCtx {
            sub: sub.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }
    }

    /// A manifest of the shape an HTTP add-on ships, with neutral routes.
    /// The core names no add-on's routes, tests included; `evolve` is used
    /// only because it is the declared HTTP add-on in `addons::ADDONS`.
    pub(crate) fn sample_json() -> Value {
        json!({
            "version": 1,
            "addon": "evolve",
            "base_url_env": "NOO_EVOLVE_URL",
            "base_url_default": "https://noo-evolve:8090",
            "timeout_secs": 300,
            "routes": [
                {"name": "sample_status", "method": "GET", "path": "/api/sample/status",
                 "aliases": ["/api/sample-alt/status"], "min_role": "user"},
                {"name": "sample_items", "method": "GET", "path": "/api/sample/items", "query": true,
                 "min_role": "operator", "scopes": ["evolve:read_items"]},
                {"name": "sample_item", "method": "GET", "path": "/api/sample/items/{item_id}",
                 "params": {"item_id": "uuid"}, "min_role": "admin"},
                {"name": "sample_run", "method": "POST", "path": "/api/sample/run", "min_role": "operator"},
                {"name": "sample_rollback", "method": "POST", "path": "/api/sample/rollback",
                 "timeout_secs": 30, "min_role": "admin"},
                {"name": "meta_loop_dispatch", "method": "POST", "path": "/api/sample/dispatch",
                 "internal": true, "timeout_secs": 120},
                {"name": "console_piece", "method": "GET", "path": "/console-piece",
                 "internal": true, "timeout_secs": 5},
                {"name": "cli_piece", "method": "GET", "path": "/cli-piece",
                 "internal": true, "timeout_secs": 5}
            ]
        })
    }

    /// The front door's add-on GET decision over given manifests (for tests
    /// in sibling modules).
    pub(crate) fn get_allows_for_test(m: &[AddonManifest], scopes: &[String], role: crate::auth::Role, path: &str) -> bool {
        get_allows(m, scopes, role, path)
    }

    pub(crate) fn sample() -> AddonManifest {
        serde_json::from_value(sample_json()).expect("sample manifest parses")
    }

    fn check(v: Value) -> Result<(), String> {
        let m: AddonManifest = serde_json::from_value(v).map_err(|e| e.to_string())?;
        validate(&m, "evolve")
    }

    fn refused_with(edit: impl FnOnce(&mut Value), needle: &str) {
        let mut v = sample_json();
        edit(&mut v);
        let e = check(v).expect_err("must be refused");
        assert!(e.contains(needle), "{e:?} should mention {needle:?}");
    }

    /// A unique scratch directory under the system temp dir.
    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("noo-addon-routes-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn plant(dir: &std::path::Path, addon: &str, text: &str) {
        std::fs::create_dir_all(dir.join(addon)).unwrap();
        std::fs::write(dir.join(addon).join(ROUTES_FILE), text).unwrap();
    }

    // ── identity headers ─────────────────────────────────────────────────

    #[test]
    fn an_internal_call_names_no_user() {
        let h = caller_headers(None);
        assert!(
            !h.iter().any(|(n, _)| *n == REQUESTER_SUB),
            "a gateway-initiated call must not claim to act for anyone"
        );
    }

    #[test]
    fn a_user_call_carries_account_connection_role_and_scopes() {
        let h = caller_headers(Some(&ctx(
            "alice",
            crate::auth::Role::User,
            &["read", "chat"],
        )));
        let get = |n: &str| {
            h.iter()
                .find(|(k, _)| *k == n)
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };
        assert_eq!(get(REQUESTER_SUB), "alice");
        assert_eq!(get(REQUESTER_CONNECTION), "alice");
        assert_eq!(get(REQUESTER_ROLE), "user");
        assert_eq!(get(REQUESTER_SCOPES), "read,chat");
    }

    #[test]
    fn the_account_and_the_connection_are_reported_separately() {
        let sub = "alice:session-7";
        let h = caller_headers(Some(&ctx(sub, crate::auth::Role::User, &[])));
        let get = |n: &str| h.iter().find(|(k, _)| *k == n).map(|(_, v)| v.as_str());
        assert_eq!(get(REQUESTER_CONNECTION), Some(sub));
        assert_eq!(get(REQUESTER_SUB), Some(crate::auth::account_of(sub)));
    }

    #[test]
    fn an_unencodable_value_is_dropped_not_sent() {
        let h = caller_headers(Some(&ctx(
            "bad\nname",
            crate::auth::Role::User,
            &[],
        )));
        assert!(!h.iter().any(|(n, _)| *n == REQUESTER_SUB));
    }

    // ── loading: present, missing, invalid, disabled ─────────────────────

    #[test]
    fn a_present_valid_manifest_loads() {
        let dir = scratch("present");
        plant(&dir, "evolve", &sample_json().to_string());
        let l = load_all(&dir, |n| n == "evolve");
        assert!(l.refused.is_empty(), "{:?}", l.refused);
        assert_eq!(l.manifests.len(), 1);
        assert_eq!(l.manifests[0].addon, "evolve");
    }

    #[test]
    fn an_enabled_addon_without_a_manifest_is_refused_loudly() {
        // The old-image case: the add-on runs, its overlay delivered nothing.
        let dir = scratch("missing");
        let l = load_all(&dir, |n| n == "evolve");
        assert!(l.manifests.is_empty(), "nothing may be mounted");
        let why = l.refused.get("evolve").expect("refused, not silently empty");
        assert!(why.contains("missing"), "{why}");
        assert!(why.contains("same release") && why.contains("noo stack start"), "names the fix: {why}");
        assert!(why.contains("noo addons disable evolve"), "{why}");
    }

    #[test]
    fn an_invalid_manifest_is_refused_with_the_reason() {
        let dir = scratch("invalid");
        plant(&dir, "evolve", "{ not json");
        let why = load_all(&dir, |_| true).refused.remove("evolve").expect("refused");
        assert!(why.contains("not a valid manifest") && why.contains("None of its routes"), "{why}");

        let dir = scratch("invalid-field");
        let mut v = sample_json();
        v["routes"][0]["scope"] = json!("public");
        plant(&dir, "evolve", &v.to_string());
        let why = load_all(&dir, |_| true).refused.remove("evolve").expect("refused");
        assert!(why.contains("scope"), "an unknown field (say, an auth claim) is refused: {why}");
    }

    #[test]
    fn a_disabled_addon_mounts_nothing_and_refuses_nothing() {
        let dir = scratch("disabled");
        plant(&dir, "evolve", &sample_json().to_string());
        let l = load_all(&dir, |_| false);
        assert!(l.manifests.is_empty() && l.refused.is_empty());
        // Nor does an absent one: no file, switch off, nothing to say.
        let l = load_all(&scratch("absent"), |_| false);
        assert!(l.manifests.is_empty() && l.refused.is_empty());
    }

    #[test]
    fn only_declared_http_addons_are_read() {
        // trellion is on by default and speaks NATS; a file planted for it
        // is never read, so it can never publish routes.
        let dir = scratch("nats");
        plant(&dir, "trellion", &sample_json().to_string());
        let l = load_all(&dir, |_| true);
        assert!(l.manifests.iter().all(|m| m.addon != "trellion"));
        assert!(!l.refused.contains_key("trellion"));
    }

    #[test]
    fn a_manifest_delivered_for_another_addon_is_refused() {
        let mut v = sample_json();
        v["addon"] = json!("trellion");
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert!(validate(&m, "evolve").unwrap_err().contains("delivered for"));
    }

    // ── delegation keys: delegate, task_events ───────────────────────────

    fn delegating(edit: impl FnOnce(&mut Value)) -> Value {
        let mut v = sample_json();
        v["delegate"] = json!("tasks");
        v["task_events"] = json!({"method": "POST", "path": "/internal/task-events"});
        edit(&mut v);
        v
    }

    #[test]
    fn delegate_tasks_with_task_events_is_valid_and_parsed() {
        let v = delegating(|_| {});
        check(v.clone()).expect("a delegating manifest with its events route is accepted");
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert_eq!(m.delegate.as_deref(), Some(DELEGATE_TASKS));
        assert_eq!(
            m.task_events,
            Some(TaskEventsSpec { method: "POST".into(), path: "/internal/task-events".into() })
        );
        // Both keys are optional: the plain sample declares neither.
        let plain = sample();
        assert!(plain.delegate.is_none() && plain.task_events.is_none());
        // delegate alone is fine; task_events is the optional second half.
        let mut only = sample_json();
        only["delegate"] = json!("tasks");
        check(only).expect("delegate without task_events is valid");
    }

    #[test]
    fn an_unknown_delegate_value_is_refused_never_read_as_tasks() {
        for bad in [json!("mcp"), json!("Tasks"), json!(""), json!("tasks,mcp")] {
            let e = check(delegating(|v| v["delegate"] = bad.clone())).expect_err("refused");
            assert!(e.contains("delegate") && e.contains("only value is \"tasks\""), "{bad}: {e}");
        }
        // A non-string is a parse error, still a refusal.
        assert!(check(delegating(|v| v["delegate"] = json!(true))).is_err());
        assert!(check(delegating(|v| v["delegate"] = json!(["tasks"]))).is_err());
    }

    #[test]
    fn task_events_without_delegate_tasks_is_refused() {
        let mut v = sample_json();
        v["task_events"] = json!({"method": "POST", "path": "/internal/task-events"});
        let e = check(v).expect_err("refused");
        assert!(e.contains("task_events") && e.contains("delegate"), "{e}");
    }

    #[test]
    fn task_events_must_be_post_and_well_formed() {
        for method in ["GET", "PUT", "post", ""] {
            let e = check(delegating(|v| v["task_events"]["method"] = json!(method))).expect_err("refused");
            assert!(e.contains("POST"), "{method:?}: {e}");
        }
        for path in ["internal/task-events", "/", "/a/../b", "/a//b", "/a/{id}", "/a b"] {
            let e = check(delegating(|v| v["task_events"]["path"] = json!(path))).expect_err("refused");
            assert!(e.contains("task_events"), "{path:?}: {e}");
        }
        // Unknown keys inside task_events, and a missing half, are refused.
        assert!(check(delegating(|v| v["task_events"]["scope"] = json!("public"))).is_err());
        assert!(check(delegating(|v| v["task_events"] = json!({"method": "POST"}))).is_err());
    }

    #[test]
    fn task_events_may_not_equal_or_match_a_public_route() {
        // Equal to a public route, an alias, and a `{param}` route it matches.
        for path in ["/api/sample/status", "/api/sample-alt/status", "/api/sample/run", "/api/sample/items/abc"] {
            let e = check(delegating(|v| v["task_events"]["path"] = json!(path))).expect_err("refused");
            assert!(e.contains("public route") && e.contains("front door"), "{path}: {e}");
        }
        // The method does not rescue it: a POST path that a public GET covers is still public.
        let e = check(delegating(|v| v["task_events"]["path"] = json!("/api/sample/status"))).unwrap_err();
        assert!(e.contains("/api/sample/status"), "{e}");
        // An internal route is not public: its path is a fine events path.
        check(delegating(|v| v["task_events"]["path"] = json!("/api/sample/dispatch")))
            .expect("an internal route's path is not reachable through the front door");
        // A path no public route covers.
        check(delegating(|v| v["task_events"]["path"] = json!("/api/sample/items/abc/extra"))).expect("no route covers it");
    }

    #[test]
    fn receives_delegation_is_valid_only_with_delegate_tasks_on_a_public_route() {
        // Accepted: delegating manifest, public route.
        check(delegating(|v| v["routes"][0]["receives_delegation"] = json!(true))).expect("accepted");
        // Default false and explicit false are always fine, delegate or not.
        let mut plain = sample_json();
        plain["routes"][0]["receives_delegation"] = json!(false);
        check(plain).expect("false needs no delegate");
        // True without the manifest-level declaration is refused.
        let mut v = sample_json();
        v["routes"][0]["receives_delegation"] = json!(true);
        let e = check(v).expect_err("refused");
        assert!(e.contains("receives_delegation") && e.contains("delegate"), "{e}");
        // On an internal route.
        let e = check(delegating(|v| {
            v["routes"][5]["receives_delegation"] = json!(true); // meta_loop_dispatch, internal
        }))
        .expect_err("refused");
        assert!(e.contains("public route"), "{e}");
        // On the task_events path (via a route that shares it).
        let e = check(delegating(|v| {
            v["task_events"]["path"] = json!("/api/sample/dispatch");
            v["routes"][5]["receives_delegation"] = json!(true);
        }))
        .expect_err("refused");
        assert!(e.contains("receives_delegation"), "{e}");
        // Not a bool.
        assert!(check(delegating(|v| v["routes"][0]["receives_delegation"] = json!("yes"))).is_err());
    }

    // ── add-on names beyond the compiled table ───────────────────────────

    #[test]
    fn a_hyphenated_third_party_name_validates_with_its_own_env_var_and_scopes() {
        let mut v = sample_json();
        v["addon"] = json!("pai-voice");
        v["base_url_env"] = json!("NOO_PAI_VOICE_URL");
        v["base_url_default"] = json!("https://noo-pai-voice:8090");
        v["routes"][1]["scopes"] = json!(["pai-voice:read_items"]);
        let m: AddonManifest = serde_json::from_value(v.clone()).unwrap();
        validate(&m, "pai-voice").expect("a name outside the compiled table is valid");
        // The env var and the host still have to be the add-on's own.
        v["base_url_env"] = json!("NOO_EVOLVE_URL");
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert!(validate(&m, "pai-voice").unwrap_err().contains("NOO_PAI_VOICE_URL"));
        // A bad name is refused before it is joined into a path.
        let m = sample();
        assert!(validate(&m, "../x").unwrap_err().contains("not a valid add-on name"));
    }

    #[test]
    fn read_manifest_reads_one_addon_and_distinguishes_absent_from_required() {
        let dir = scratch("read-one");
        assert_eq!(read_manifest(&dir, "evolve", false).unwrap().map(|m| m.addon), None, "absent and optional: nothing to say");
        assert!(read_manifest(&dir, "evolve", true).unwrap_err().contains("missing"));
        plant(&dir, "evolve", &sample_json().to_string());
        assert_eq!(read_manifest(&dir, "evolve", true).unwrap().unwrap().addon, "evolve");
        assert!(read_manifest(&dir, "../evolve", false).unwrap_err().contains("not valid"));
    }

    // ── validation ───────────────────────────────────────────────────────

    #[test]
    fn the_sample_manifest_is_valid() {
        validate(&sample(), "evolve").expect("valid");
    }

    #[test]
    fn every_addon_door_is_https() {
        // the gateway sends its bearer on every add-on call.
        // Planted: `http://noo-evolve:8090` in a manifest → refused.
        refused_with(|v| v["base_url_default"] = json!("http://noo-evolve:8090"), "https://");
    }

    #[test]
    fn the_upstream_is_the_addons_own_service_and_nothing_else() {
        for bad in [
            "https://gateway:8080",
            "https://noo-evolve.attacker.example:8090",
            "https://user:pw@noo-evolve:8090",
            "https://noo-evolve:8090/prefix",
            "https://noo-evolve:8090/?x=1",
            "https://169.254.169.254",
        ] {
            refused_with(|v| v["base_url_default"] = json!(bad), "noo-evolve");
        }
        // The override variable is the gateway's convention, not the
        // manifest's choice: naming another env var would dial (and echo in
        // errors) whatever that variable holds.
        refused_with(|v| v["base_url_env"] = json!("NOO_JWT_SECRET"), "NOO_EVOLVE_URL");
        let mut v = sample_json();
        v["base_url_default"] = json!("https://noo-evolve");
        check(v).expect("the port is the add-on's choice");
    }

    #[test]
    fn path_shapes_are_plain() {
        for bad in ["api/sample/x", "/api/sample/../security", "/api//x", "/api/sample/{*rest}", "/api/sample/x y", "/"] {
            refused_with(|v| v["routes"][0]["path"] = json!(bad), "path");
        }
        refused_with(|v| v["routes"][0]["aliases"] = json!(["/api/sample/./x"]), "path");
    }

    #[test]
    fn params_are_declared_both_ways() {
        refused_with(|v| v["routes"][2]["params"] = json!({}), "params");
        refused_with(|v| v["routes"][0]["params"] = json!({"x": "uuid"}), "params");
        refused_with(|v| v["routes"][2]["params"] = json!({"item_id": "regex"}), "format");
    }

    #[test]
    fn public_paths_live_under_api_and_outside_the_gateways_namespaces() {
        refused_with(|v| v["routes"][0]["path"] = json!("/health"), "/api/");
        for p in ["/api/addons/evolve/cli-piece", "/api/security/x", "/api/config/agent", "/api/auth/login", "/api/tasks", "/api/tasks/abc/stop"] {
            refused_with(|v| v["routes"][0]["path"] = json!(p), "namespace");
        }
        // An internal route may name any path on the add-on's side.
        let mut v = sample_json();
        v["routes"][6]["path"] = json!("/console-piece");
        check(v).expect("internal paths are the add-on's");
    }

    #[test]
    fn a_manifest_cannot_place_a_write_where_a_user_is_admitted() {
        // POSTs under a chat prefix are admitted for every tier by the front
        // door; an add-on route there would be a write any User could make.
        refused_with(
            |v| v["routes"][3]["path"] = json!("/api/conversations/sample-run"),
            "User-tier",
        );
        // The same path as a GET is a read, which the front door admits for
        // every route anyway: no widening.
        let mut v = sample_json();
        v["routes"][0]["path"] = json!("/api/conversations/sample-status");
        check(v).expect("a read is not a widening");
    }

    #[test]
    fn routes_the_gateway_calls_by_name_must_be_internal() {
        for i in [5usize, 6, 7] {
            refused_with(|v| v["routes"][i]["internal"] = json!(false), "must be internal");
        }
        let mut v = sample_json();
        v["routes"].as_array_mut().unwrap().push(json!(
            {"name": "prompt_skills_evolve", "method": "POST", "path": "/api/sample/evolve"}));
        assert!(check(v).unwrap_err().contains("must be internal"));
    }

    #[test]
    fn names_methods_versions_and_timeouts() {
        refused_with(|v| v["version"] = json!(2), "version");
        refused_with(|v| v["routes"][0]["name"] = json!("Bad-Name"), "names");
        refused_with(|v| v["routes"][1]["name"] = json!("sample_status"), "twice");
        refused_with(|v| v["routes"][0]["method"] = json!("OPTIONS"), "only GET, POST, PUT, PATCH and DELETE");
        refused_with(|v| v["routes"][0]["method"] = json!("get"), "only GET, POST, PUT, PATCH and DELETE");
        refused_with(|v| v["routes"][0]["method"] = json!("delete"), "only GET, POST, PUT, PATCH and DELETE");
        refused_with(|v| v["routes"][0]["timeout_secs"] = json!(0), "timeout");
        refused_with(|v| v["timeout_secs"] = json!(100000), "timeout");
        refused_with(|v| v["routes"] = json!([]), "no routes");
        refused_with(
            |v| v["routes"][1]["path"] = json!("/api/sample-alt/status"),
            "declared twice",
        );
    }

    // ── mounting ─────────────────────────────────────────────────────────

    #[test]
    fn the_router_mounts_without_panicking() {
        let _ = addon_router(&sample());
        let _ = mount(Router::new());
    }

    #[test]
    fn a_collision_with_a_core_route_refuses_the_addon_instead_of_crashing() {
        async fn core_handler() -> &'static str {
            "core"
        }
        // The path from the manifest, not a literal: a `.route("…")` literal
        // here would read as a core route to the OpenAPI scanners.
        let taken = sample().routes[0].path.clone();
        let core: Router<Arc<AppState>> = Router::new().route(&taken, get(core_handler));
        let mut refused = Vec::new();
        let _ = merge_each(core, vec![sample()], |a, why| refused.push((a.to_string(), why)));
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].0, "evolve");
        assert!(refused[0].1.contains("collide"), "{}", refused[0].1);
    }

    #[test]
    fn a_clean_addon_merges_without_a_refusal() {
        let mut refused = Vec::new();
        let _ = merge_each(Router::new(), vec![sample()], |a, why| refused.push((a.to_string(), why)));
        assert!(refused.is_empty(), "{refused:?}");
    }

    // ── the transport ────────────────────────────────────────────────────

    #[test]
    fn a_plaintext_override_is_refused_before_anything_is_sent() {
        assert!(plaintext_refusal("evolve", "NOO_EVOLVE_URL", "https://noo-evolve:8090").is_none());
        let why = plaintext_refusal("evolve", "NOO_EVOLVE_URL", "http://noo-evolve:8090")
            .expect("http:// must be refused");
        assert!(why.contains("NOO_EVOLVE_URL") && why.contains("https://"), "{why}");
        assert!(plaintext_refusal("evolve", "NOO_EVOLVE_URL", "noo-evolve:8090").is_some());
    }

    #[test]
    fn send_errors_are_classified() {
        assert_eq!(classify_send_error("error sending request: received corrupt message of type InvalidContentType", false), "tls");
        assert_eq!(classify_send_error("invalid peer certificate: UnknownIssuer", false), "tls");
        assert_eq!(classify_send_error("tcp connect error: Connection refused (os error 111)", false), "connect");
        assert_eq!(classify_send_error("dns error: failed to lookup address", false), "dns");
        assert_eq!(classify_send_error("operation timed out", true), "timeout");
    }

    /// The roll-skew case, end to end: a gateway that dials `https://` meets
    /// an add-on image that still serves plain HTTP. It must come back fast
    /// and as `reason: "tls"` with the release hint — not hang for the
    /// route's 300 s timeout, and not a bare "error sending request".
    #[tokio::test]
    async fn an_https_dial_to_a_plain_listener_is_a_prompt_tls_unreachable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    // What uvicorn/h11 answers to a TLS ClientHello.
                    let _ = sock
                        .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        let base = format!("https://127.0.0.1:{port}");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let err = client
            .get(format!("{base}/api/sample/status"))
            .send()
            .await
            .expect_err("a TLS dial to a plain listener must fail");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "it hung");
        let body = unreachable_body("evolve", &base, &err);
        assert_eq!(body["state"], "unreachable");
        assert_eq!(body["reason"], "tls", "{body}");
        assert!(body["error"].as_str().unwrap().contains("come from the same release"), "{body}");
    }

    #[tokio::test]
    async fn a_disabled_addon_answers_503_with_a_reason_not_a_404() {
        // The test environment does not switch evolve on.
        if crate::addons::enabled("evolve") {
            return;
        }
        let m = sample();
        let spec = m.route("sample_status").unwrap();
        let resp = forward(&m, spec, "/api/sample/status", None, None).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_named_call_to_a_disabled_addon_carries_its_refusal() {
        if crate::addons::enabled("evolve") {
            return;
        }
        let resp = forward_named("evolve", "prompt_skills_evolve", None, None).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        match call("evolve", "meta_loop_dispatch", None).await {
            CallOutcome::Unavailable(msg) => assert_eq!(msg, crate::addons::refusal_msg("evolve")),
            CallOutcome::Ok(_) => panic!("a disabled add-on must not answer"),
        }
    }

    #[tokio::test]
    async fn a_malformed_uuid_is_rejected_before_the_upstream_is_touched() {
        let m = sample();
        let spec = m.route("sample_item").unwrap().clone();
        let params = HashMap::from([("item_id".to_string(), "not-a-uuid".to_string())]);
        let resp = serve(&m, &spec, params, None, None, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod user_read_route_tests {
    use super::*;

    fn manifest(routes: &[(&str, &str, bool)]) -> AddonManifest {
        AddonManifest {
            version: 1,
            addon: "evolve".into(),
            base_url_env: "NOO_EVOLVE_URL".into(),
            base_url_default: "https://noo-evolve:8443".into(),
            timeout_secs: 30,
            delegate: None,
            task_events: None,
            ui: None,
            routes: routes
                .iter()
                .map(|(m, p, internal)| RouteSpec {
                    name: "r".into(),
                    method: m.to_string(),
                    path: p.to_string(),
                    aliases: vec![],
                    params: HashMap::new(),
                    query: false,
                    internal: *internal,
                    timeout_secs: None,
                    min_role: None,
                    scopes: vec![],
                    owner_scoped: false,
                    receives_delegation: false,
                    max_message_bytes: None,
                    idle_timeout_secs: None,
                    max_connections_per_user: None,
                    note: None,
                })
                .collect(),
        }
    }

    #[test]
    fn a_mounted_get_route_matches_with_params_and_nothing_else_does() {
        let m = [manifest(&[
            ("GET", "/api/evolve/status", false),
            ("GET", "/api/evolve/runs/{id}", false),
            ("POST", "/api/evolve/start", false),
            ("GET", "/api/evolve/hidden", true),
        ])];
        assert!(manifests_get_match(&m, "/api/evolve/status"));
        assert!(manifests_get_match(&m, "/api/evolve/runs/abc"));
        assert!(!manifests_get_match(&m, "/api/evolve/runs/"), "an empty param segment is not a match");
        assert!(!manifests_get_match(&m, "/api/evolve/runs/a/b"));
        assert!(!manifests_get_match(&m, "/api/evolve/start"), "POST routes are not read routes");
        assert!(!manifests_get_match(&m, "/api/evolve/hidden"), "internal routes are not mounted");
        assert!(!manifests_get_match(&m, "/api/other"));
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    use crate::auth::Role;

    fn route(method: &str, min_role: Option<&str>, scopes: &[&str]) -> RouteSpec {
        serde_json::from_value(json!({
            "name": "r", "method": method, "path": "/api/x/r",
            "min_role": min_role, "scopes": scopes,
        }))
        .unwrap()
    }
    fn held(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }
    const ROLES: [Role; 3] = [Role::User, Role::Operator, Role::Admin];

    /// requester role x route role: allowed exactly when role >= route role.
    #[test]
    fn the_role_matrix_mirrors_the_core_tiers() {
        for method in ["GET", "POST"] {
            for (word, need) in [("user", Role::User), ("operator", Role::Operator), ("admin", Role::Admin)] {
                if method == "POST" && need == Role::User {
                    continue; // refused at load, see below
                }
                let r = route(method, Some(word), &[]);
                for have in ROLES {
                    assert_eq!(
                        r.permits(have, &held(&["read"])),
                        have >= need,
                        "{method} min_role={word}, requester {have:?}"
                    );
                }
            }
        }
    }

    /// An absent field is Operator for every method: a User never reads a
    /// route nobody vouched for, an Operator and an Admin keep theirs.
    #[test]
    fn an_absent_min_role_is_operator_for_every_method() {
        for method in ["GET", "POST"] {
            let r = route(method, None, &[]);
            assert_eq!(r.required_role(), Role::Operator);
            assert!(!r.permits(Role::User, &held(&["read"])), "{method}: a User is refused");
            assert!(r.permits(Role::Operator, &held(&["read", "write"])));
            assert!(r.permits(Role::Admin, &held(&["read", "write", "admin"])));
        }
    }

    /// An unknown word is refused at load with the reason, never read as user;
    /// a hand-built spec holding one fails closed (admin).
    #[test]
    fn an_unknown_role_refuses_the_manifest_and_never_defaults_to_user() {
        for bad in ["superuser", "User", "", "viewer", "root"] {
            let mut v = tests::sample_json();
            v["routes"][0]["min_role"] = json!(bad);
            let m: AddonManifest = serde_json::from_value(v).unwrap();
            let e = validate(&m, "evolve").expect_err(bad);
            assert!(e.contains("min_role") && e.contains("not a role") && e.contains("never read as user"), "{e}");
        }
        let r = route("GET", Some("superuser"), &[]);
        assert_eq!(r.required_role(), Role::Admin);
        assert!(!r.permits(Role::Operator, &held(&["read", "write"])));
    }

    #[test]
    fn a_granted_scope_opens_a_get_for_a_user_who_also_holds_read() {
        let r = route("GET", Some("operator"), &["evolve:read_items"]);
        assert!(r.permits(Role::User, &held(&["read", "evolve:read_items"])));
        assert!(!r.permits(Role::User, &held(&["evolve:read_items"])), "a scope is an addition to read, never a credential");
        assert!(!r.permits(Role::User, &held(&["read", "graph"])), "another scope opens nothing here");
        assert!(!r.permits(Role::User, &held(&["read"])));
    }

    #[test]
    fn scopes_are_namespaced_and_never_widen_a_write() {
        for bad in ["graph", "read", "admin", "ingest", "other:x", ":x", "evolve:", "evolve:a:b", "evolve:Bad"] {
            let mut v = tests::sample_json();
            v["routes"][1]["scopes"] = json!([bad]);
            let m: AddonManifest = serde_json::from_value(v).unwrap();
            assert!(validate(&m, "evolve").is_err(), "scope {bad:?} must be refused");
        }
        let mut v = tests::sample_json();
        v["routes"][3]["scopes"] = json!(["evolve:run"]);
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert!(validate(&m, "evolve").unwrap_err().contains("GET route only"));
        let mut v = tests::sample_json();
        v["routes"][3]["min_role"] = json!("user");
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert!(validate(&m, "evolve").unwrap_err().contains("POST cannot be min_role"));
    }

    fn with_owner_route() -> AddonManifest {
        let mut v = tests::sample_json();
        v["routes"].as_array_mut().unwrap().push(json!({
            "name": "sample_note", "method": "POST", "path": "/api/sample/notes",
            "min_role": "user", "owner_scoped": true
        }));
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        validate(&m, "evolve").expect("an owner_scoped user POST is accepted");
        m
    }

    #[test]
    fn owner_scoped_user_post_is_accepted_and_only_with_the_flag() {
        with_owner_route();
        // Without the flag: refused at load, and the error names the way out.
        let mut v = tests::sample_json();
        v["routes"][3]["min_role"] = json!("user");
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        let e = validate(&m, "evolve").unwrap_err();
        assert!(e.contains("POST cannot be min_role") && e.contains("owner_scoped"), "{e}");
        // The flag means nothing on other shapes: refused, not ignored.
        for (idx, role) in [(3usize, "operator"), (0, "user")] {
            let mut v = tests::sample_json();
            v["routes"][idx]["owner_scoped"] = json!(true);
            v["routes"][idx]["min_role"] = json!(role);
            let m: AddonManifest = serde_json::from_value(v).unwrap();
            assert!(validate(&m, "evolve").unwrap_err().contains("owner_scoped"), "route {idx}");
        }
    }

    /// PUT, PATCH and DELETE are writes with the POST rule: accepted at
    /// operator/admin, refused at user unless owner_scoped, never scoped, and
    /// mounted with their own method.
    #[test]
    fn put_patch_and_delete_are_writes_with_the_post_rule() {
        for method in ["PUT", "PATCH", "DELETE"] {
            let mut v = tests::sample_json();
            v["routes"].as_array_mut().unwrap().push(json!({
                "name": "sample_write", "method": method, "path": "/api/sample/things/{thing_id}",
                "params": {"thing_id": "uuid"}, "min_role": "operator"
            }));
            let m: AddonManifest = serde_json::from_value(v.clone()).unwrap();
            validate(&m, "evolve").unwrap_or_else(|e| panic!("{method} at operator: {e}"));
            let _ = addon_router(&m); // mounts without panicking

            let mut user = v.clone();
            user["routes"][8]["min_role"] = json!("user");
            let m: AddonManifest = serde_json::from_value(user.clone()).unwrap();
            let e = validate(&m, "evolve").unwrap_err();
            assert!(e.contains(&format!("a {method} cannot be min_role")) && e.contains("owner_scoped"), "{e}");

            user["routes"][8]["owner_scoped"] = json!(true);
            let m: AddonManifest = serde_json::from_value(user).unwrap();
            validate(&m, "evolve").unwrap_or_else(|e| panic!("{method} owner_scoped user: {e}"));
            let meth = axum::http::Method::from_bytes(method.as_bytes()).unwrap();
            let id = "/api/sample/things/00000000-0000-0000-0000-000000000001";
            assert!(owner_scoped_allows(&[m.clone()], &meth, &held(&["read"]), Role::User, id));
            assert!(!owner_scoped_allows(&[m], &axum::http::Method::POST, &held(&["read"]), Role::User, id), "method must match");

            let mut scoped = v.clone();
            scoped["routes"][8]["scopes"] = json!(["evolve:things"]);
            let m: AddonManifest = serde_json::from_value(scoped).unwrap();
            assert!(validate(&m, "evolve").unwrap_err().contains("GET route only"), "{method}: a scope never widens a write");

            let mut chat = v;
            chat["routes"][8]["path"] = json!("/api/conversations/{thing_id}");
            let m: AddonManifest = serde_json::from_value(chat).unwrap();
            if let Err(e) = validate(&m, "evolve") {
                assert!(e.contains("User-tier") || e.contains("namespace"), "{method}: {e}");
            }
        }
    }

    #[test]
    fn ws_routes_live_in_the_addons_socket_namespace_with_bounded_limits() {
        let ok = json!({"name": "s", "method": "WS", "path": "/ws/addons/evolve/stream", "min_role": "user"});
        let with = |r: Value| {
            let mut v = tests::sample_json();
            v["routes"].as_array_mut().unwrap().push(r);
            serde_json::from_value::<AddonManifest>(v).map_err(|e| e.to_string()).and_then(|m| validate(&m, "evolve"))
        };
        with(ok.clone()).expect("a user WS route in its namespace");
        for (edit, needle) in [
            (json!({"path": "/api/sample/stream"}), "/ws/addons/"),
            (json!({"path": "/ws/addons/other/stream"}), "/ws/addons/evolve/"),
            (json!({"path": "/ws/collab"}), "/ws/addons/"),
            (json!({"internal": true}), "cannot be internal"),
            (json!({"scopes": ["evolve:x"]}), "GET route only"),
            (json!({"max_message_bytes": 0}), "max_message_bytes"),
            (json!({"max_message_bytes": 17 * 1024 * 1024}), "max_message_bytes"),
            (json!({"idle_timeout_secs": 0}), "idle_timeout_secs"),
            (json!({"idle_timeout_secs": 3601}), "idle_timeout_secs"),
            (json!({"max_connections_per_user": 0}), "max_connections_per_user"),
            (json!({"max_connections_per_user": 65}), "max_connections_per_user"),
            (json!({"owner_scoped": true}), "owner_scoped"),
        ] {
            let mut r = ok.clone();
            for (k, val) in edit.as_object().unwrap() {
                r[k] = val.clone();
            }
            let e = with(r).expect_err(&edit.to_string());
            assert!(e.contains(needle), "{edit}: {e}");
        }
        // The WS knobs mean nothing on an HTTP route: refused, not ignored.
        let e = with(json!({"name": "g", "method": "GET", "path": "/api/sample/g", "max_message_bytes": 10})).unwrap_err();
        assert!(e.contains("WS"), "{e}");
        // A WS route is never a GET read for the tier gate.
        let mut v = tests::sample_json();
        v["routes"].as_array_mut().unwrap().push(ok);
        let m: AddonManifest = serde_json::from_value(v).unwrap();
        assert!(!get_allows(&[m], &held(&["read"]), Role::User, "/ws/addons/evolve/stream"));
    }

    #[test]
    fn the_tier_gate_admits_a_user_only_to_an_owner_scoped_post() {
        let m = [with_owner_route()];
        let post = axum::http::Method::POST;
        let user = held(&["read"]);
        assert!(owner_scoped_allows(&m, &post, &user, Role::User, "/api/sample/notes"));
        // Operator-only POSTs are unchanged: a User is still refused.
        assert!(!owner_scoped_allows(&m, &post, &user, Role::User, "/api/sample/run"));
        assert!(!owner_scoped_allows(&m, &post, &user, Role::User, "/api/sample/rollback"));
        assert!(!owner_scoped_allows(&m, &post, &user, Role::User, "/api/unmounted"));
        // Method matters: the owner-scoped path is no GET route and no PUT route.
        assert!(!owner_scoped_allows(&m, &axum::http::Method::PUT, &user, Role::User, "/api/sample/notes"));
        assert!(!get_allows(&m, &user, Role::User, "/api/sample/notes"));
    }

    /// The add-on is handed the VERIFIED caller; the request to it is built
    /// from nothing, so a header the client forged is never in it.
    #[test]
    fn a_forged_identity_header_is_replaced_by_the_verified_one() {
        let h = caller_headers(Some(&super::tests::ctx("alice", Role::User, &["read"])));
        let all = |n: &str| h.iter().filter(|(k, _)| *k == n).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
        // The client's `x-noo-requester-sub: root` has no way in: there is exactly
        // one copy of each header and it is alice's.
        assert_eq!(all(REQUESTER_SUB), ["alice"]);
        assert_eq!(all(REQUESTER_ROLE), ["user"]);
        assert_eq!(all(REQUESTER_SCOPES), ["read"]);
        // forward() copies only caller_headers() onto a fresh request.
        let src = include_str!("addon_proxy.rs");
        let body = src.split("async fn forward(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(body.contains("for (name, value) in caller_headers(requester)"), "forward builds identity from the verified ctx");
        assert!(!body.contains("HeaderMap") && !body.contains("headers()"), "forward must not pass client headers through");
    }

    /// A client-sent `x-noo-delegation` is dropped: the upstream request is
    /// built from nothing, caller_headers never emits it, and the only place it
    /// is set is the mint branch in `forward`.
    #[test]
    fn a_client_sent_delegation_header_is_never_forwarded() {
        let h = caller_headers(Some(&super::tests::ctx("alice", Role::User, &["read"])));
        assert!(!h.iter().any(|(n, _)| n.eq_ignore_ascii_case(crate::addon_delegation::HEADER)));
        let src = include_str!("addon_proxy.rs");
        let body = src.split("async fn forward(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert_eq!(body.matches("crate::addon_delegation::HEADER").count(), 1, "one place sets it");
        let set = body.find("crate::addon_delegation::HEADER").unwrap();
        let guard = body.find("mints_delegation(").unwrap();
        assert!(guard < set, "set only behind the mint decision");
        assert!(!body.contains("HeaderMap") && !body.contains("headers()"));
    }

    #[test]
    fn a_token_is_minted_only_for_a_person_on_an_opted_in_route_of_an_enabled_addon() {
        let person = super::tests::ctx("alice", Role::User, &["read"]);
        assert!(mints_delegation(Some(&person), true, true));
        assert!(!mints_delegation(Some(&person), false, true), "route did not opt in");
        assert!(!mints_delegation(Some(&person), true, false), "operator has not enabled delegation");
        assert!(!mints_delegation(None, true, true), "no person, no token");
        let mut delegated = person.clone();
        delegated.act = Some(crate::auth::Actor { sub: "addon:voice".into(), iss_user: None, task: None });
        assert!(!mints_delegation(Some(&delegated), true, true), "a delegated token never mints another");
    }

    #[tokio::test]
    async fn an_owner_scoped_route_refuses_a_call_with_no_verified_caller() {
        let m = with_owner_route();
        let spec = m.route("sample_note").unwrap().clone();
        let resp = serve(&m, &spec, HashMap::new(), None, Some(json!({})), None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn declared_scopes_are_the_manifest_scopes_sorted_and_unique() {
        let m = [tests::sample()];
        assert_eq!(declared_scopes_of(&m), vec!["evolve:read_items".to_string()]);
        assert!(declared_scopes_of(&[]).is_empty());
    }

    /// An add-on scope is issuable only when declared, and holding it (with
    /// `read`) opens that GET route and nothing else.
    #[test]
    fn a_granted_addon_scope_opens_its_route_and_nothing_else() {
        let m = [tests::sample()];
        let granted = held(&["read", "evolve:read_items"]);
        assert!(get_allows(&m, &granted, Role::User, "/api/sample/items"));
        assert!(!get_allows(&m, &granted, Role::User, "/api/sample/items/00000000-0000-0000-0000-000000000001"));
        assert!(!get_allows(&m, &held(&["read"]), Role::User, "/api/sample/items"));
        assert!(!owner_scoped_allows(&m, &axum::http::Method::POST, &granted, Role::User, "/api/sample/run"));
    }

    /// The shipped-shape fixture: every public route says who may call it.
    /// (The evolve repo carries the same guard over its real manifest.)
    #[test]
    fn every_public_route_in_the_fixture_declares_a_role() {
        let m = tests::sample();
        for r in m.routes.iter().filter(|r| !r.internal) {
            assert!(r.min_role.is_some(), "route {:?} declares no min_role", r.name);
        }
        validate(&m, "evolve").unwrap();
    }

    /// The front door's view of an add-on GET (what `scope_allows` asks).
    #[test]
    fn the_front_door_scopes_an_addon_get_by_the_routes_own_role() {
        let m = [tests::sample()];
        let user = held(&["read"]);
        assert!(get_allows(&m, &user, Role::User, "/api/sample/status"), "min_role user");
        assert!(get_allows(&m, &user, Role::User, "/api/sample-alt/status"), "an alias is the same route");
        assert!(!get_allows(&m, &user, Role::User, "/api/sample/items"), "operator route");
        assert!(get_allows(&m, &held(&["read", "evolve:read_items"]), Role::User, "/api/sample/items"));
        let id = "/api/sample/items/00000000-0000-0000-0000-000000000001";
        assert!(!get_allows(&m, &user, Role::User, id));
        assert!(get_allows(&m, &held(&["read", "write"]), Role::Operator, "/api/sample/items"));
        assert!(!get_allows(&m, &held(&["read", "write"]), Role::Operator, id), "admin route: not an Operator");
        assert!(get_allows(&m, &held(&["read", "write", "admin"]), Role::Admin, id));
        assert!(!get_allows(&m, &user, Role::User, "/api/sample/run"), "a POST path is no read route");
        assert!(!get_allows(&m, &user, Role::User, "/api/unmounted"));
    }

    #[test]
    fn overlapping_patterns_must_all_permit() {
        let mut m = tests::sample();
        m.routes.push(route_named("static_one", "/api/sample/items/mine", "operator"));
        m.routes.push(route_named("param_one", "/api/sample/things/{id}", "user"));
        m.routes.push(route_named("static_two", "/api/sample/things/secret", "operator"));
        let m = [m];
        assert!(!get_allows(&m, &held(&["read"]), Role::User, "/api/sample/things/secret"));
        assert!(get_allows(&m, &held(&["read"]), Role::User, "/api/sample/things/abc"));
    }

    fn route_named(name: &str, path: &str, role: &str) -> RouteSpec {
        let mut r = route("GET", Some(role), &[]);
        r.name = name.into();
        r.path = path.into();
        r
    }

    /// The handler refuses before it forwards; a permitted caller goes on (to
    /// the add-on gate, which answers 503 while evolve is off in tests).
    #[tokio::test]
    async fn serve_refuses_a_short_role_before_forwarding() {
        let m = tests::sample();
        let spec = m.route("sample_items").unwrap().clone();
        let user = crate::auth::RequesterCtx {
            sub: "alice".into(), scopes: held(&["read"]), role: Role::User, harness: None, act: None,
        };
        let resp = serve(&m, &spec, HashMap::new(), None, None, Some(&user)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["required_role"], "operator");

        let admin_route = m.route("sample_item").unwrap().clone();
        let op = crate::auth::RequesterCtx { role: Role::Operator, ..user.clone() };
        let mut p = HashMap::new();
        p.insert("item_id".to_string(), "00000000-0000-0000-0000-000000000001".to_string());
        let resp = serve(&m, &admin_route, p, None, None, Some(&op)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "an Operator is short of an admin route");

        let ok = crate::auth::RequesterCtx { role: Role::Operator, ..user };
        let resp = serve(&m, &spec, HashMap::new(), None, None, Some(&ok)).await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }
}
