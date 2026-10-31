// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The add-on route manifest (`routes.json`) and every rule that refuses one.
//!
//! The gateway loads a manifest at startup and mounts nothing of an add-on
//! whose manifest [`validate`] refuses (`gateway-rust/src/addon_proxy.rs`
//! documents what each key means once mounted). `noo addons check` runs the
//! SAME [`validate`] on a bundle directory, so an add-on author's CI refuses
//! what the gateway would refuse, with the gateway's own sentence
//! (noomesh-internal i302). There is one definition; neither side restates a
//! rule.
//!
//! One rule needs the gateway itself: a public write route must not sit where
//! the front door admits a User-tier caller, and only the gateway's auth code
//! knows where that is. [`validate`] therefore takes a [`FrontDoor`]. The
//! gateway passes [`FrontDoor::Asks`] with its own answer; a caller that
//! cannot answer passes [`FrontDoor::NotHere`], and every route the rule
//! would have asked about comes back in [`Checked::unchecked`], never as a
//! pass.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

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

/// What an add-on name may be (it is joined into a path and an env var).
pub const ADDON_NAME_RULE: &str =
    "lowercase letters, digits, `-` and `_`, starting with a letter, at most 32 characters";

/// Is `s` a name an add-on may have? Checked before the name is joined into a
/// path, so a config key can never walk out of the manifest directory.
pub fn addon_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

/// The container name an operator would `docker logs`, and the only host an
/// add-on's `base_url_default` may name.
pub fn container_of(addon: &str) -> String {
    format!("noo-{addon}")
}

/// The most a `WS` route may raise its message (and frame) size to.
pub const MAX_MAX_MESSAGE_BYTES: usize = 16 << 20;
/// The longest idle bound a `WS` route may declare.
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;
/// The most sockets per account a `WS` route may allow.
pub const MAX_CONNECTIONS_PER_USER: u32 = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonManifest {
    pub version: u32,
    /// Must be the add-on the file was delivered for (a plain name,
    /// [`addon_name_ok`]). The gateway's runtime registry decides whether it
    /// is registered at all: operator-enabled, and verified by the launcher.
    pub addon: String,
    pub base_url_env: String,
    pub base_url_default: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub routes: Vec<RouteSpec>,
    /// `"tasks"`: the add-on asks to act for a present person through that
    /// person's own tasks (noomesh-internal i143). Declaring it does nothing
    /// by itself: the operator must also enable it
    /// (`addon_delegation.<name>.tasks`). The only accepted value is
    /// `"tasks"`; [`validate`] refuses any other.
    #[serde(default)]
    pub delegate: Option<String>,
    /// Where the gateway POSTs task events for this add-on. Valid only with
    /// `delegate: "tasks"`, POST only, and never a public route of the same
    /// manifest: it is reachable by the gateway, not through the front door.
    #[serde(default)]
    pub task_events: Option<TaskEventsSpec>,
    /// The add-on's own web UI, served on an origin of its own. Absent: the
    /// add-on serves no UI.
    #[serde(default)]
    pub ui: Option<UiSpec>,
}

/// The manifest's `ui` key: `{"upstream_path": "/", "min_role": "user"}`.
///
/// On the add-on's own origin (`https://<host>:<its port>`), `/<rest>` is
/// fetched from `<upstream><upstream_path>/<rest>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiSpec {
    /// Where the add-on serves its UI on its own side: a plain path, no
    /// `{param}`. Default `/`: the request path on the add-on origin is
    /// forwarded as it is.
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
    pub fn manifest_role(&self) -> ManifestRole {
        role_or_admin(self.min_role.as_deref())
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
    /// Stable key the gateway's internal callers name instead of a path
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
    /// `admin`. Absent means `operator`. Kept as the manifest's own word so an
    /// unknown value is refused by [`validate`] with a sentence, not a serde
    /// variant error.
    #[serde(default)]
    pub min_role: Option<String>,
    /// Add-on scopes (`<addon>:<word>`) that also open this GET route to a
    /// requester holding `read` plus the scope, below `min_role`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Opt-in for a `POST` at `min_role: "user"`: the add-on promises to read
    /// and write only rows owned by the account the gateway forwards in
    /// `x-noo-requester-sub`. The gateway does NOT check that promise. Without
    /// it a `POST` is `operator` or `admin`.
    #[serde(default)]
    pub owner_scoped: bool,
    /// This public route may be sent the add-on delegated task token
    /// (noomesh-internal i143), so a manifest can keep the token off routes
    /// that never need it (a GPU media route). Default false. Valid only when
    /// the manifest declares top-level `delegate: "tasks"`, only on a public
    /// route, and never on the `task_events` path. Declaring it grants
    /// nothing by itself.
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

/// The three role words a manifest may use, in rising order. The gateway
/// maps each to its own `auth::Role`; this crate knows only the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManifestRole {
    User,
    Operator,
    Admin,
}

/// The role a manifest word names; `None` for anything else.
pub fn role_word(word: &str) -> Option<ManifestRole> {
    match word {
        "user" => Some(ManifestRole::User),
        "operator" => Some(ManifestRole::Operator),
        "admin" => Some(ManifestRole::Admin),
        _ => None,
    }
}

/// Absent is `operator`; an unknown word (which [`validate`] refuses at load,
/// so only a hand-built spec can hold one) is `admin`, so a bad value can only
/// ever shut a route, never open it.
fn role_or_admin(word: Option<&str>) -> ManifestRole {
    match word {
        None => ManifestRole::Operator,
        Some(w) => role_word(w).unwrap_or(ManifestRole::Admin),
    }
}

impl RouteSpec {
    /// The role this route needs: absent is `operator`, unknown is `admin`.
    pub fn manifest_role(&self) -> ManifestRole {
        role_or_admin(self.min_role.as_deref())
    }
}

impl AddonManifest {
    /// The upstream: `$<base_url_env>` when set and not blank, else
    /// `base_url_default`.
    pub fn base_url(&self) -> String {
        std::env::var(&self.base_url_env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.base_url_default.clone())
    }

    /// The route called `name`, if the manifest declares one.
    pub fn route(&self, name: &str) -> Option<&RouteSpec> {
        self.routes.iter().find(|r| r.name == name)
    }
}

/// Parse a manifest's text. `Err` is the sentence the gateway logs.
pub fn parse(raw: &str) -> Result<AddonManifest, String> {
    serde_json::from_str::<AddonManifest>(raw).map_err(|e| format!("not a valid manifest: {e}"))
}

// ── Validation ───────────────────────────────────────────────────────────

pub const MAX_TIMEOUT_SECS: u64 = 600;
const SAMPLE_PARAM: &str = "00000000-0000-0000-0000-000000000000";

/// How [`validate`] learns whether the gateway's front door would let a
/// User-tier caller make a write request. A mutating add-on route must not
/// sit where the answer is yes.
pub enum FrontDoor<'a> {
    /// The gateway: `(method, path)` → would its front door admit a User
    /// holding every scope a person can hold? `path` has every `{param}`
    /// filled with a sample value.
    Asks(&'a dyn Fn(&str, &str) -> bool),
    /// No front door to ask (`noo addons check`): each route the rule applies
    /// to is listed in [`Checked::unchecked`] instead of passing.
    NotHere,
}

/// What a manifest that [`validate`] accepted was NOT checked for.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Checked {
    /// One sentence per route a rule could not be applied to here. Always
    /// empty under [`FrontDoor::Asks`].
    pub unchecked: Vec<String>,
}

/// Route names: `[a-z][a-z0-9_]{0,63}`. Also the `{param}` rule.
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

fn check_upstream(m: &AddonManifest, addon: &str) -> Result<(), String> {
    // `-` is not legal in an environment variable name: `rh-addon` reads
    // `NOO_RH_ADDON_URL`. The container stays `noo-<addon>` verbatim.
    let want_env = format!("NOO_{}_URL", addon.to_ascii_uppercase().replace('-', "_"));
    if m.base_url_env != want_env {
        return Err(format!(
            "base_url_env is {:?}; an add-on's override variable is {want_env}",
            m.base_url_env
        ));
    }
    let host = container_of(addon);
    let url = url::Url::parse(&m.base_url_default)
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
pub fn scope_ok(s: &str) -> bool {
    let Some((addon, word)) = s.split_once(':') else { return false };
    let plain = |t: &str| {
        !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    // The add-on part may hold `-` (`rh-addon:read`); a word never does.
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
        if n == 0 || n > MAX_MAX_MESSAGE_BYTES {
            return Err(format!("{ctx}: max_message_bytes {n} outside 1..={MAX_MAX_MESSAGE_BYTES}"));
        }
    }
    if let Some(t) = r.idle_timeout_secs {
        if t == 0 || t > MAX_IDLE_TIMEOUT_SECS {
            return Err(format!("{ctx}: idle_timeout_secs {t} outside 1..={MAX_IDLE_TIMEOUT_SECS}"));
        }
    }
    if let Some(c) = r.max_connections_per_user {
        if c == 0 || c > MAX_CONNECTIONS_PER_USER {
            return Err(format!("{ctx}: max_connections_per_user {c} outside 1..={MAX_CONNECTIONS_PER_USER}"));
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

fn check_route(r: &RouteSpec, door: &FrontDoor<'_>, checked: &mut Checked) -> Result<(), String> {
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
        let Some(role) = role_word(word) else {
            return Err(format!(
                "{ctx}: min_role {word:?} is not a role — use \"user\", \"operator\" or \"admin\" \
                 (an unknown value is refused, never read as user)"
            ));
        };
        if is_write_method(&r.method) && role == ManifestRole::User && !r.owner_scoped {
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
            match door {
                FrontDoor::Asks(user_tier_could_call) => {
                    if user_tier_could_call(r.method.as_str(), sample_path(path).as_str()) {
                        return Err(format!(
                            "{ctx}: {} {path:?} would be callable by a User-tier caller — an add-on \
                             cannot place a write where the front door admits a User",
                            r.method
                        ));
                    }
                }
                FrontDoor::NotHere => checked.unchecked.push(format!(
                    "{ctx}: whether {} {path:?} sits where the gateway's front door admits a User \
                     (the gateway refuses that at load)",
                    r.method
                )),
            }
        }
    }
    Ok(())
}

/// Is this manifest acceptable for `addon`? `Err` names the first problem;
/// `Ok` says what could not be checked with `door`.
pub fn validate(m: &AddonManifest, addon: &str, door: FrontDoor<'_>) -> Result<Checked, String> {
    if !addon_name_ok(addon) {
        return Err(format!("{addon:?} is not a valid add-on name ({ADDON_NAME_RULE})"));
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
    let mut checked = Checked::default();
    let mut names = HashSet::new();
    let mut mounted = HashSet::new();
    for r in &m.routes {
        if CALLED_BY_NAME.contains(&r.name.as_str()) && !r.internal {
            return Err(format!(
                "route {:?} must be internal: the gateway calls it by name and decides when it runs",
                r.name
            ));
        }
        check_route(r, &door, &mut checked)?;
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
    Ok(checked)
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
        if role_word(word).is_none() {
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
/// segment) cover `path`? The one matcher the gateway's tier gate and the
/// `task_events` check share.
pub fn pattern_matches(pat: &str, path: &str) -> bool {
    let p: Vec<&str> = pat.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    p.len() == segs.len() && p.iter().zip(&segs).all(|(a, b)| (a.starts_with('{') && !b.is_empty()) || a == b)
}
