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
//! of their route names. An HTTP add-on (`Addon::routes_manifest` in
//! `addons.rs`) ships its manifest in its own image, and its compose overlay
//! delivers it READ-ONLY at `<ROUTES_DIR>/<addon>/routes.json` (a one-shot
//! service from the add-on's image fills a volume the gateway mounts; a dev
//! overlay bind-mounts the source file). It is read ONCE, when the router is
//! built at startup, and only for an add-on whose switch is on. A file is
//! used, not a fetch from the add-on, so nothing at boot depends on the
//! network or on the add-on being up first.
//!
//! The gateway still decides what it exposes. The manifest declares paths, an
//! upstream and the PERMISSION each public route needs (`min_role`, `scopes`:
//! see "Who may call a route" below), and [`validate`] refuses anything else:
//!
//! - version 1, `addon` = the add-on it was delivered for;
//! - the upstream is that add-on's own service: `base_url_env` is
//!   `NOO_<ADDON>_URL` and `base_url_default` is `https://noo-<addon>[:port]`
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
//! ## What a route can say
//!
//! - `method` (`GET` | `POST`), `path` — mounted verbatim, forwarded verbatim.
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
//! ## The contract every mounted route keeps
//!
//! Upstream status and JSON body pass through verbatim; a non-JSON body is
//! wrapped as `{"raw": "..."}` with the status preserved. The request carries
//! the gateway's own bearer and the requester's identity, set here, never
//! forwarded.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path as FsPath;
use std::sync::{Arc, Mutex, OnceLock};

use axum::{
    extract::{Path, RawQuery},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
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
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonManifest {
    pub version: u32,
    /// Must be the add-on the file was delivered for, and a row of
    /// [`crate::addons::ADDONS`] with `routes_manifest` — that table owns the
    /// enable flag, polarity, entitlement and refusal text.
    pub addon: String,
    pub base_url_env: String,
    pub base_url_default: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub routes: Vec<RouteSpec>,
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
    fn base_url(&self) -> String {
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
    let want_env = format!("NOO_{}_URL", addon.to_ascii_uppercase());
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
    plain(addon) && plain(word) && !word.contains(':')
}

fn check_route(r: &RouteSpec) -> Result<(), String> {
    let ctx = format!("route {:?}", r.name);
    if !name_ok(&r.name) {
        return Err(format!("{ctx}: names are [a-z][a-z0-9_]{{0,63}}"));
    }
    if r.method != "GET" && r.method != "POST" {
        return Err(format!("{ctx}: method {:?} — only GET and POST", r.method));
    }
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
        if r.method == "POST" && role == crate::auth::Role::User {
            return Err(format!(
                "{ctx}: a POST cannot be min_role \"user\" — writes are operator or admin, the \
                 front door refuses a User's writes and a manifest does not widen that"
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
        if !path.starts_with("/api/") {
            return Err(format!("{ctx}: public path {path:?} must live under /api/"));
        }
        if let Some(p) = RESERVED_PREFIXES.iter().find(|p| path.starts_with(**p)) {
            return Err(format!("{ctx}: public path {path:?} is inside the gateway's own {p} namespace"));
        }
        if r.method != "GET" {
            let method = axum::http::Method::from_bytes(r.method.as_bytes()).expect("GET or POST");
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
    if m.version != 1 {
        return Err(format!("version {} — this gateway reads version 1", m.version));
    }
    if m.addon != addon {
        return Err(format!("it names add-on {:?}, but was delivered for {addon:?}", m.addon));
    }
    if !crate::addons::ADDONS.iter().any(|a| a.name == addon && a.routes_manifest) {
        return Err(format!("{addon:?} is not declared as an HTTP add-on in addons::ADDONS"));
    }
    check_upstream(m, addon)?;
    if m.timeout_secs == 0 || m.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(format!("timeout_secs {} outside 1..={MAX_TIMEOUT_SECS}", m.timeout_secs));
    }
    if m.routes.is_empty() {
        return Err("it declares no routes".into());
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

/// Read and validate the manifest of every HTTP add-on whose switch is on.
/// Pure over `dir` and `flag_on`, so every outcome is testable without a
/// global.
pub fn load_all(dir: &FsPath, flag_on: impl Fn(&str) -> bool) -> Loaded {
    let mut out = Loaded::default();
    for a in crate::addons::ADDONS.iter().filter(|a| a.routes_manifest) {
        if !flag_on(a.name) {
            continue; // off: mounts nothing, refuses nothing
        }
        let path = dir.join(a.name).join(ROUTES_FILE);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                out.refused.insert(a.name.to_string(), missing_reason(a.name, &path));
                continue;
            }
            Err(e) => {
                out.refused.insert(
                    a.name.to_string(),
                    format!("add-on {:?}: cannot read its route manifest {}: {e}", a.name, path.display()),
                );
                continue;
            }
        };
        let parsed = serde_json::from_str::<AddonManifest>(&raw)
            .map_err(|e| format!("not a valid manifest: {e}"))
            .and_then(|m| validate(&m, a.name).map(|()| m));
        match parsed {
            Ok(m) => out.manifests.push(m),
            Err(why) => {
                out.refused.insert(
                    a.name.to_string(),
                    format!(
                        "add-on {:?}: route manifest {} refused: {why}. None of its routes are \
                         mounted; fix the manifest in the add-on's image",
                        a.name,
                        path.display()
                    ),
                );
            }
        }
    }
    out
}

static LOADED: OnceLock<Loaded> = OnceLock::new();
/// Refusals found at load AND at mount (a collision with a core route).
static REFUSED: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

fn flag_on(name: &str) -> bool {
    crate::addons::state(name) != crate::addons::AddonState::Disabled
}

fn loaded() -> &'static Loaded {
    LOADED.get_or_init(|| {
        let l = load_all(FsPath::new(ROUTES_DIR), flag_on);
        for m in &l.manifests {
            tracing::info!(addon = %m.addon, routes = m.routes.len(), "add-on route manifest loaded");
        }
        for (addon, why) in &l.refused {
            refuse(addon, why.clone());
        }
        l
    })
}

fn refuse(addon: &str, why: String) {
    tracing::error!(addon, "add-on routes refused: {why}");
    if let Ok(mut r) = REFUSED.lock() {
        r.insert(addon.to_string(), why);
    }
}

/// Why this add-on's routes are refused, if they are. `None` for an add-on
/// that is off, has no manifest by design, or loaded cleanly.
pub fn refusal(addon: &str) -> Option<String> {
    let _ = loaded();
    REFUSED.lock().ok()?.get(addon).cloned()
}

/// The manifests in force: loaded, valid, and not refused at mount.
pub fn manifests() -> Vec<AddonManifest> {
    loaded()
        .manifests
        .iter()
        .filter(|m| refusal(&m.addon).is_none())
        .cloned()
        .collect()
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

fn get_allows(manifests: &[AddonManifest], scopes: &[String], role: crate::auth::Role, path: &str) -> bool {
    let hits = matching_get_routes(manifests, path);
    !hits.is_empty() && hits.iter().all(|r| r.permits(role, scopes))
}

#[cfg(test)]
fn manifests_get_match(manifests: &[AddonManifest], path: &str) -> bool {
    !matching_get_routes(manifests, path).is_empty()
}

fn matching_get_routes<'a>(manifests: &'a [AddonManifest], path: &str) -> Vec<&'a RouteSpec> {
    let segs: Vec<&str> = path.split('/').collect();
    manifests
        .iter()
        .flat_map(|m| m.routes.iter())
        .filter(|r| !r.internal && r.method == "GET")
        .filter(|r| {
            std::iter::once(&r.path).chain(r.aliases.iter()).any(|pat| {
                let p: Vec<&str> = pat.split('/').collect();
                p.len() == segs.len()
                    && p.iter().zip(&segs).all(|(a, b)| (a.starts_with('{') && !b.is_empty()) || a == b)
            })
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
    // `validate` admits GET and POST only.
    if spec.method == "POST" {
        post(handler)
    } else {
        get(handler)
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
    // Permission first, before a param is parsed or anything is forwarded.
    if let Some(r) = requester {
        if !spec.permits(r.role, &r.scopes) {
            return forbidden(manifest, spec);
        }
    }
    // Substitute path params, validating each against its declared format so
    // a malformed id is a clean 400 here rather than whatever the upstream
    // makes of it.
    let mut path = spec.path.clone();
    for (name, format) in &spec.params {
        let Some(value) = params.get(name) else {
            return bad_request(format!("missing path parameter `{name}`"));
        };
        if format == "uuid" && uuid::Uuid::parse_str(value).is_err() {
            return bad_request(format!("Invalid {name}: {value}"));
        }
        path = path.replace(&format!("{{{name}}}"), value);
    }
    if spec.query {
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            path = format!("{path}?{q}");
        }
    }
    forward(manifest, spec, &path, body, requester).await
}

fn forbidden(manifest: &AddonManifest, spec: &RouteSpec) -> Response {
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
fn plaintext_refusal(addon: &str, env: &str, base: &str) -> Option<String> {
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
fn classify_send_error(chain: &str, is_timeout: bool) -> &'static str {
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
fn caller_headers(requester: Option<&crate::auth::RequesterCtx>) -> Vec<(&'static str, String)> {
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

/// The container name an operator would `docker logs`. Kept alongside the
/// add-on name so an unreachable-error names something they can act on.
fn container_of(addon: &str) -> String {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn ctx(sub: &str, role: crate::auth::Role, scopes: &[&str]) -> crate::auth::RequesterCtx {
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
        for p in ["/api/addons/evolve/cli-piece", "/api/security/x", "/api/config/agent", "/api/auth/login"] {
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
        refused_with(|v| v["routes"][0]["method"] = json!("DELETE"), "only GET and POST");
        refused_with(|v| v["routes"][0]["method"] = json!("get"), "only GET and POST");
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
