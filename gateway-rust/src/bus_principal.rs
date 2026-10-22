// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Per-message principal on the NATS bus.
//!
//! The bus grant answers *which process* may publish `worker.>`; it cannot
//! answer *on whose behalf* a particular message is being sent. Until this
//! module the worker took that from the payload — `user_id`, `_requester` —
//! which is the publisher's own claim about itself. Anything that could get a
//! message onto `worker.tool.generic` could therefore also choose who it was.
//!
//! Every `worker.*` message now carries a `Noo-Principal` NATS header: a
//! compact token over the caller's identity, MACed (HMAC-SHA256) once PER
//! AUDIENCE — each process that verifies bus principals has a key of its own
//!
//!
//! | audience         | key (env.sops)               | held by                               |
//! |------------------|------------------------------|---------------------------------------|
//! | `worker`         | `NOO_BUS_KEY_WORKER`         | the gateway, noo-worker(-extra)       |
//! | `trellion`       | `NOO_BUS_KEY_TRELLION`       | the gateway, noo-trellion             |
//! | `trellion-intel` | `NOO_BUS_KEY_TRELLION_INTEL` | the gateway, noo-trellion-intel       |
//!
//! every verifier held `NOO_CONTROLLER_SECRET`, so a leak
//! from any one container forged principals for all of them AND signed HTTP
//! self-calls. Now trellion's bus key verifies — and so, if it leaks, can
//! forge — principals for trellion's audience only, and only for something
//! that can also publish on `worker.>` (the bus grant). It buys no HTTP
//! access and no other audience. (Nor does the worker plane hold the FLEET
//! secret any more: the browser door has its own key, and `noo cluster
//! verify --controller`'s `shared secrets` row fails if one turns up.) The
//! gateway, the only signer, holds every audience key;
//! a verifier holds only its own (`NOO_BUS_KEY` + `NOO_BUS_AUDIENCE`, see
//! `noomesh/gateway/bus_principal.py`). The worker verifies its own MAC
//! before dispatch and refuses the message otherwise.
//!
//! Wire format — one header value, two dot-separated fields:
//!
//! ```text
//! Noo-Principal: <base64url(claims json, no padding)>.<aud>=<hex hmac>[,<aud>=<hex hmac>…]
//! mac(aud) = HMAC-SHA256(key(aud), "<aud>.<base64url body>")
//! ```
//!
//! The audience is inside the MAC as well as beside it, so a MAC computed for
//! one audience does not verify when relabelled as another's. That is domain
//! separation, not a substitute for distinct keys: whoever holds a key can
//! compute a MAC for any label, so two audiences sharing a key would be one
//! audience — `noo cluster verify --controller` checks the store's three bus
//! keys are distinct from each other and from the shared secrets. The
//! MAC covers the base64url text exactly as transmitted, so the verifier
//! authenticates the bytes it is about to parse rather than a
//! re-serialisation of them (canonicalisation is not a thing we want to have
//! to agree on across two languages). The pre-702 format — one bare 64-hex
//! MAC under the controller secret — is refused by every verifier.
//!
//! The claims bind the message to its subject. Without `subj` a principal
//! lifted off a cheap subject (`worker.memory.search`) would be replayable,
//! within its freshness window, onto an expensive one (`worker.tool.generic`).
//!
//! ## Where the principal comes from
//!
//! [`principal_layer`] runs *inside* `require_any_auth` and scopes a
//! task-local for the life of the handler, so route code needs no changes and
//! cannot forget. Background work has no HTTP request to read, so each loop
//! names itself with [`with_internal`] and the scopes it actually needs — an
//! internal actor is not an admin.
//!
//! Task-locals do not cross `tokio::spawn`. That is deliberate here: every
//! spawn that then publishes captures [`current`] *before* spawning
//! ([`publish_fire_and_forget_inner`](crate::worker_client)). Anything that
//! forgets signs as [`UNATTRIBUTED`], which is a real, verifiable principal
//! with no scopes at all — so it is refused where scopes matter and shows up
//! in the worker's audit trail by name, rather than inheriting whatever the
//! payload claimed.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// NATS header carrying the signed principal.
pub const HEADER: &str = "Noo-Principal";

/// Signed lifetime. The verifier allows the same slack in either direction,
/// so this is the width of the replay window the nonce cache has to cover.
pub const TTL_SECS: u64 = 60;

/// The actor signed when a publish happens with no principal in scope.
/// Scopeless on purpose — see the module docs.
pub const UNATTRIBUTED: &str = "internal:unattributed";

/// What a principal *is*, which decides how much the payload is still
/// allowed to say. A `user` principal is the last word on tenancy: the
/// worker refuses a payload `user_id` that disagrees with it. An `internal`
/// principal is a loop acting for somebody, so it may still name the user it
/// is acting for in the payload — it just cannot name its own scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    User,
    Internal,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::User => "user",
            Kind::Internal => "internal",
        }
    }
}

/// The caller, independent of any one message. Cheap to clone and to carry
/// through a task-local; the per-message fields (nonce, iat, exp, subject)
/// are added at signing time by [`sign`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub sub: String,
    pub kind: Kind,
    pub role: String,
    pub scopes: Vec<String>,
}

impl Principal {
    /// A named human (or a token minted for one).
    pub fn user(sub: impl Into<String>, role: crate::auth::Role, scopes: Vec<String>) -> Self {
        Self { sub: sub.into(), kind: Kind::User, role: role.as_str().into(), scopes }
    }

    /// A loop or service acting on its own account. `actor` is bare — the
    /// `internal:` prefix is applied here so every internal subject on the
    /// bus reads the same way and cannot collide with a username.
    pub fn internal(actor: &str, scopes: &[&str]) -> Self {
        Self {
            sub: format!("internal:{actor}"),
            kind: Kind::Internal,
            // Deliberately NOT admin. An internal actor carries the scopes
            // the code it serves actually needs and nothing else; `role` is
            // the weakest one so any role comparison that leaks in fails
            // closed rather than open.
            role: crate::auth::Role::User.as_str().into(),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn unattributed() -> Self {
        Self {
            sub: UNATTRIBUTED.into(),
            kind: Kind::Internal,
            role: crate::auth::Role::User.as_str().into(),
            scopes: Vec::new(),
        }
    }
}

/// The signed claim set. Field names are the wire contract with
/// `noomesh/gateway/bus_principal.py`; the parity test pins them.
#[derive(Serialize)]
struct Claims<'a> {
    sub: &'a str,
    kind: Kind,
    role: &'a str,
    scopes: &'a [String],
    /// The NATS subject this principal is valid for. Binds the token to the
    /// request so it cannot be lifted onto a different handler.
    subj: &'a str,
    iat: u64,
    exp: u64,
    /// Single-use within the freshness window (the worker keeps a cache).
    nonce: String,
}

tokio::task_local! {
    static CURRENT: Principal;
}

/// The principal in scope, or [`Principal::unattributed`] when there is none.
///
/// Two sources, in order:
///
/// 1. [`principal_layer`]'s task-local — an authenticated HTTP caller, with
///    the role and scopes the credential actually proved.
/// 2. The coordinator's `TURN_PRINCIPAL`, which is bound for the whole turn
///    by `coordinator::agent_loop::run_inner` / `run_streaming` and therefore
///    covers the paths that have no HTTP request in scope: the dashboard
///    WebSocket, Google Chat, Telegram, and a node-hosted harness. It names
///    the requester but not their role.
pub fn current() -> Principal {
    if let Ok(p) = CURRENT.try_with(|p| p.clone()) {
        return p;
    }
    let turn = crate::routes::communication::turn_principal();
    if !turn.requester.is_empty() {
        // LEAST PRIVILEGE. This used to be `Operator, [read, write]` for
        // whoever the turn named, because resolving the real role needed a
        // DB read and there was nowhere to put it. Every caller that has a
        // person (a channel turn, a task owner) now resolves the real
        // principal with [`account_principal`] and scopes it with
        // [`with_principal`], and the unattended `system:*` turns name
        // themselves with [`unattended_principal`]. What reaches here is a
        // caller that did neither: it is a named user with `read` and
        // nothing else, so a missed call site loses a write, never gains
        // one.
        warn_turn_fallback(&turn.requester, &turn.channel);
        return Principal::user(turn.requester, crate::auth::Role::User, vec!["read".into()]);
    }
    Principal::unattributed()
}

/// Loud, rate-limited (once a minute per requester): a turn reached the bus
/// with no principal scoped and was given the floor.
fn warn_turn_fallback(requester: &str, channel: &str) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);
    let now = now_secs();
    let mut guard = match SEEN.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let seen = guard.get_or_insert_with(HashMap::new);
    if now.saturating_sub(seen.get(requester).copied().unwrap_or(0)) < 60 {
        return;
    }
    seen.insert(requester.to_string(), now);
    drop(guard);
    tracing::warn!(
        requester,
        channel,
        "turn_principal_fallback: no principal in scope; signing as role=user scopes=[read]. \
         The entry point must scope `bus_principal::account_principal` / `with_principal` \
         around the turn."
    );
}

/// The principal for gateway-owned turns that act as a `system:*` label (the
/// heartbeat) rather than for a person. It keeps the tier those turns have
/// always run at - `operator`, `read` + `write`, never `admin` and never
/// `kb:unrestricted` - but as an explicit declaration at the call site
/// instead of a side effect of the fallback.
pub fn unattended_principal(label: &str) -> Principal {
    Principal::user(
        label,
        crate::auth::Role::Operator,
        vec!["read".into(), "write".into()],
    )
}

/// What a linked channel account (or a task's owner) may do on the bus,
/// from its `noo_users` row. `None` when the account is disabled: such a
/// turn must not run at all.
///
/// - role = the higher of the `role` column and the role the `scopes`
///   column implies (the same "never the lower" rule as `effective_tier`),
///   an unparseable column reading as `User` - this grants authority, so it
///   fails to the floor, not the ceiling.
/// - scopes = the row's scopes plus the role's own, so a `user` row that
///   lists only `read` is exactly `[read]`.
/// - CAPPED AT OPERATOR. A chat message is not an admin session: `admin`
///   (the role and the scope) is withheld here, as it always was on this
///   path, so a prompt-injected channel turn cannot reach admin handlers.
///   An admin who needs those uses the dashboard.
pub fn principal_from_row(
    username: &str,
    role_col: &str,
    scopes_col: &serde_json::Value,
    disabled: bool,
) -> Option<Principal> {
    use crate::auth::Role;
    if disabled {
        return None;
    }
    let from_col: Role = role_col.trim().parse().unwrap_or(Role::User);
    let list: Vec<String> = serde_json::from_value(scopes_col.clone()).unwrap_or_default();
    let mut role = from_col.max(Role::from_scopes(&list));
    if role == Role::Admin {
        role = Role::Operator;
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in list
        .iter()
        .map(String::as_str)
        .chain(role.legacy_scopes().iter().copied())
    {
        if s != "admin" && s != SCOPE_KB_UNRESTRICTED && !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    Some(Principal::user(username, role, scopes))
}

/// How long a resolved account principal is reused. A role change or a
/// disable no longer waits this out: `session_floor::end_account_sessions`
/// (every route that changes an account's standing) calls
/// [`invalidate_account`], so the next turn re-reads `noo_users`. The TTL
/// still bounds a change made by another gateway instance or by SQL.
const ACCOUNT_PRINCIPAL_TTL_SECS: u64 = 30;

type AccountCache = std::collections::HashMap<String, (u64, Option<Principal>)>;

/// Bumped by every invalidation, so a lookup that started BEFORE one does not
/// write its (stale) answer back after it.
static ACCOUNT_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Forget `account`'s cached principal: its next channel turn re-reads the
/// row. Called when the account's role, scopes or disabled flag change.
pub fn invalidate_account(account: &str) {
    ACCOUNT_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut c) = account_cache().lock() {
        c.remove(account);
        c.remove(crate::auth::account_of(account));
    }
}

fn account_cache() -> &'static std::sync::Mutex<AccountCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<AccountCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Resolve `username`'s real principal: one `noo_users` read, cached for
/// [`ACCOUNT_PRINCIPAL_TTL_SECS`]. `None` = disabled, or no such account, or
/// the read failed (fail closed: the caller refuses the turn with a message,
/// it does not fall back to a wider identity). A failed read is not cached.
pub async fn account_principal(db: &sqlx::PgPool, username: &str) -> Option<Principal> {
    let now = now_secs();
    let gen = ACCOUNT_GEN.load(std::sync::atomic::Ordering::SeqCst);
    if let Ok(c) = account_cache().lock() {
        if let Some((at, p)) = c.get(username) {
            if now.saturating_sub(*at) < ACCOUNT_PRINCIPAL_TTL_SECS {
                return p.clone();
            }
        }
    }
    let row: Result<Option<(String, serde_json::Value, bool)>, _> = sqlx::query_as(
        "SELECT role, scopes, COALESCE(disabled, false) FROM noo_users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await;
    let resolved = match row {
        Ok(Some((role, scopes, disabled))) => principal_from_row(username, &role, &scopes, disabled),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(username, error = %e, "account_principal_lookup_failed");
            return None;
        }
    };
    if let Ok(mut c) = account_cache().lock() {
        if ACCOUNT_GEN.load(std::sync::atomic::Ordering::SeqCst) == gen {
            c.insert(username.to_string(), (now, resolved.clone()));
        }
    }
    resolved
}

/// Run `fut` with `principal` in scope.
pub async fn with_principal<F: std::future::Future>(principal: Principal, fut: F) -> F::Output {
    CURRENT.scope(principal, fut).await
}

/// Run `fut` as a named internal actor with exactly `scopes`.
pub async fn with_internal<F: std::future::Future>(
    actor: &str,
    scopes: &[&str],
    fut: F,
) -> F::Output {
    CURRENT.scope(Principal::internal(actor, scopes), fut).await
}

/// Every bus audience and the key the gateway signs for it with. A fixed
/// list: each row is a verifier the stack ships (the core worker, and the
/// worker_pool inside each knowledge add-on image). The CLI's secret registry
/// declares the same keys (`noo-cli/src/commands/secrets.rs`, the
/// `NOO_BUS_KEY_*` rows) and compose delivers them; a parity test pins the
/// three against each other.
pub const AUDIENCES: &[(&str, &str)] = &[
    ("worker", "NOO_BUS_KEY_WORKER"),
    ("trellion", "NOO_BUS_KEY_TRELLION"),
    ("trellion-intel", "NOO_BUS_KEY_TRELLION_INTEL"),
];

/// The audience keys this process holds, in [`AUDIENCES`] order. An absent
/// key is an audience this install does not sign for (an add-on minted
/// before its key existed is fixed by `noo upgrade`, which mints it).
fn audience_keys() -> Vec<(&'static str, String)> {
    AUDIENCES
        .iter()
        .filter_map(|(aud, var)| {
            crate::config::secret_env::secret_opt(var)
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .map(|k| (*aud, k))
        })
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One audience's MAC over the transmitted body.
pub fn audience_mac(audience: &str, key: &str, body: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).ok()?;
    mac.update(audience.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Sign `principal` for one message on `subject`, once per audience key.
/// Pure over its inputs so the tests can pin the wire format without a
/// clock, a bus or an environment. `None` when `keys` is empty.
pub fn sign_at(
    principal: &Principal,
    subject: &str,
    keys: &[(&str, &str)],
    now: u64,
    nonce: String,
) -> Option<String> {
    if keys.is_empty() {
        return None;
    }
    let claims = Claims {
        sub: &principal.sub,
        kind: principal.kind,
        role: &principal.role,
        scopes: &principal.scopes,
        subj: subject,
        iat: now,
        exp: now + TTL_SECS,
        nonce,
    };
    let json = serde_json::to_vec(&claims).ok()?;
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    let mut macs = Vec::with_capacity(keys.len());
    for (aud, key) in keys {
        macs.push(format!("{aud}={}", audience_mac(aud, key, &body)?));
    }
    Some(format!("{body}.{}", macs.join(",")))
}

/// Sign `principal` for `subject` with every audience key this process holds.
pub fn sign(principal: &Principal, subject: &str) -> Option<String> {
    let keys = audience_keys();
    let refs: Vec<(&str, &str)> = keys.iter().map(|(a, k)| (*a, k.as_str())).collect();
    sign_at(principal, subject, &refs, now_secs(), new_nonce())
}

fn new_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Headers for one `worker.*` message, or `None` when this process cannot
/// sign. `None` is not "send it unsigned and hope": the caller sends no
/// header, and every worker refuses the message — the intended outcome for a
/// gateway that holds no bus key (`noo upgrade` mints them; `noo cluster
/// verify --controller` names a missing one in its `shared secrets` row).
pub fn headers_for(subject: &str) -> Option<async_nats::HeaderMap> {
    let principal = current();
    if principal.sub == UNATTRIBUTED {
        warn_unattributed(subject);
    }
    headers_for_principal(&principal, subject)
}

/// Same, for a principal captured earlier (before a `tokio::spawn`, or
/// rebuilt from a DLQ row).
pub fn headers_for_principal(
    principal: &Principal,
    subject: &str,
) -> Option<async_nats::HeaderMap> {
    let token = sign(principal, subject).or_else(|| {
        warn_no_secret_once(subject);
        None
    })?;
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(HEADER, token.as_str());
    Some(headers)
}

fn warn_no_secret_once(subject: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::error!(
            subject,
            "no NOO_BUS_KEY_* is set — worker.* messages are going out with no \
             principal header, and every worker will refuse every one of them. \
             Mint them: `noo upgrade --stack` (mints any bus key the store lacks), then \
             `noo stack restart --force`."
        );
    });
}

/// Loud, but not once-only: each subject that publishes unattributed is a
/// separate gap to close, and collapsing them to one line hides the rest.
/// Rate-limited per subject to one line a minute.
fn warn_unattributed(subject: &str) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);
    let now = now_secs();
    let mut guard = match SEEN.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let seen = guard.get_or_insert_with(HashMap::new);
    let last = seen.get(subject).copied().unwrap_or(0);
    if now.saturating_sub(last) < 60 {
        return;
    }
    seen.insert(subject.to_string(), now);
    drop(guard);
    tracing::warn!(
        subject,
        principal = UNATTRIBUTED,
        "publishing with no principal in scope — the caller's identity was lost (most likely a \
         tokio::spawn between the request and the publish). The message is signed as a scopeless \
         internal actor, so scope-bearing handlers will refuse it."
    );
}

/// Middleware that puts the authenticated caller in scope for the handler.
///
/// Registered so it runs *after* `require_any_auth` (applied earlier in the
/// `.layer()` chain ⇒ closer to the handler), which is what lets it read the
/// extensions that middleware inserted.
pub async fn principal_layer(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let principal = from_extensions(request.extensions());
    match principal {
        Some(p) => with_principal(p, next.run(request)).await,
        None => next.run(request).await,
    }
}

/// The principal an authenticated requester signs as. One function for the
/// request path ([`from_extensions`]) and for work DETACHED from the request
/// (`ops.rs`), which re-binds this around its spawned future: the task-local
/// does not cross `tokio::spawn`, so a detached run that forgot would publish
/// as [`UNATTRIBUTED`] and the worker would answer for nobody in particular.
pub fn for_requester(ctx: &crate::auth::RequesterCtx) -> Principal {
    Principal::user(ctx.sub.clone(), ctx.role, ctx.scopes.clone())
}

/// Whether `p` is one of the controller's own internal services: what the auth
/// layer builds for a controller-secret caller (`ClusterNode(_, Internal)`).
/// Not a node credential, not a service key, not the unattributed fallback.
pub fn is_internal_cluster(p: &Principal) -> bool {
    p.kind == Kind::Internal && p.sub.starts_with("internal:cluster:")
}

/// Map the auth layer's extensions onto a bus principal.
pub fn from_extensions(ext: &axum::http::Extensions) -> Option<Principal> {
    if let Some(ctx) = ext.get::<crate::auth::RequesterCtx>() {
        return Some(for_requester(ctx));
    }
    if let Some(node) = ext.get::<crate::auth::ClusterNode>() {
        // A controller-signed caller is one of the stack's own services. It
        // is internal, and it gets the scopes an internal service needs —
        // not the blanket full access the HTTP rail still grants it.
        let actor = if node.0.is_empty() { "cluster" } else { node.0.as_str() };
        return Some(if node.is_internal() {
            Principal::internal(&format!("cluster:{actor}"), INTERNAL_SERVICE_SCOPES)
        } else {
            // A node's fleet credential is the weakest thing on the rail.
            Principal::internal(&format!("node:{actor}"), &[])
        });
    }
    if let Some(consumer) = ext.get::<crate::service_keys::Consumer>() {
        // `name` says which program is calling; `user` says on whose behalf.
        // A key issued with `--user` is that person on the bus too, or the
        // whole point of binding it would stop at the HTTP door.
        return Some(match &consumer.user {
            Some(user) => Principal::user(
                user.clone(),
                crate::auth::Role::from_scopes(&consumer.scopes),
                consumer.scopes.clone(),
            ),
            None => Principal::internal(
                &format!("key:{}", consumer.name),
                INTERNAL_SERVICE_SCOPES,
            ),
        });
    }
    None
}

/// Reserved payload key carrying a DLQ row's originating principal.
/// Stripped before the message is republished, so a worker never sees it.
pub const DLQ_KEY: &str = "_dlq_principal";

/// Copy `payload` with the principal's claims attached under [`DLQ_KEY`].
/// A non-object payload is returned untouched — there is nowhere to put it,
/// and the replay then falls back to the scopeless drain actor.
pub fn embed_for_dlq(payload: &serde_json::Value, principal: &Principal) -> serde_json::Value {
    let mut out = payload.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            DLQ_KEY.to_string(),
            serde_json::json!({
                "sub": principal.sub,
                "kind": principal.kind.as_str(),
                "role": principal.role,
                "scopes": principal.scopes,
            }),
        );
    }
    out
}

/// Split a DLQ row's payload back into `(payload without the key, principal)`.
/// A row with no key (written before this change, or a non-object payload)
/// replays as `internal:dlq-drain` with no scopes — the replay keeps the
/// authority the row can prove, which is none.
pub fn extract_from_dlq(payload: &serde_json::Value) -> (serde_json::Value, Principal) {
    let mut out = payload.clone();
    let raw = out.as_object_mut().and_then(|o| o.remove(DLQ_KEY));
    let Some(raw) = raw else {
        return (out, Principal::internal("dlq-drain", &[]));
    };
    let sub = raw.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if sub.is_empty() {
        return (out, Principal::internal("dlq-drain", &[]));
    }
    let kind = match raw.get("kind").and_then(|v| v.as_str()) {
        Some("user") => Kind::User,
        _ => Kind::Internal,
    };
    let role = raw
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::auth::Role::User.as_str())
        .to_string();
    let scopes = raw
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    (out, Principal { sub, kind, role, scopes })
}

/// What a controller-signed service may do on the bus. `read`/`write` and no
/// more: `admin` is what R32 was about, and `kb:unrestricted` (the successor
/// to the worker's old "no `_requester` means the whole corpus") is granted
/// only to the loops that are documented as needing it.
pub const INTERNAL_SERVICE_SCOPES: &[&str] = &["read", "write"];

/// The scope that replaces the worker's old "absent `_requester` ⇒ the whole
/// knowledge base". Only the internal actors listed in
/// the security architecture notes carry it.
pub const SCOPE_KB_UNRESTRICTED: &str = "kb:unrestricted";

#[cfg(test)]
mod publish_sites {
    //! Every `worker.*` message must leave through a signing call site.
    //!
    //! The rail is only worth what its narrowest point is, and the narrow
    //! point here is a convention: "publish worker subjects through
    //! `worker_client`". A convention is not enforcement — `nats.publish()`
    //! is one line and reviewers do not diff for absences. So this test
    //! walks the source and fails on a NATS publish/request that is not in
    //! the declared set below.
    //!
    //! Static parse for the same reason `test_posture_key_parity` is one:
    //! the fact lives in the source, and a test that needed a live bus to
    //! observe it would not run where it matters.

    use std::path::{Path, PathBuf};

    /// The NATS client calls that put bytes on a subject.
    const PUBLISH_CALLS: &[&str] = &[
        ".publish(",
        ".request(",
        ".publish_with_reply(",
        ".publish_with_headers(",
        ".request_with_headers(",
        ".publish_with_reply_and_headers(",
        // A request with a scoped reply inbox (i70) — still a publish.
        ".send_request(",
    ];

    /// Every file that may publish a `worker.*` subject, with the header-
    /// bearing call it uses. A new entry is a deliberate decision to open a
    /// fifth door; opening one without a header fails the second test.
    const SIGNING_SITES: &[(&str, &str)] = &[
        // `send_request` with `Request::headers` — the request carries the
        // worker principal's own reply inbox (i70).
        ("worker_client.rs", "send_request"),
        ("worker_client.rs", "publish_with_headers"),
        ("worker_client.rs", "publish_with_reply_and_headers"),
        ("dlq_drain.rs", "publish_with_headers"),
    ];

    /// Files whose publishes are on subjects no worker subscribes to —
    /// `events.*`, `agent.*`, `harness.*`, `mesh.*`, `tasks.*`. Listed
    /// rather than pattern-matched, so a `worker.` subject appearing in one
    /// of them has to be argued for in a diff.
    const NON_WORKER_PUBLISHERS: &[&str] = &[
        "websocket.rs",
        "ws_agent.rs",
        "harness_main.rs",
        "operator_alert.rs",
        "scheduler_engine.rs",
        "mesh/gossip.rs",
        "mesh/router.rs",
        "tasks.rs",
        "coordinator/dispatch.rs",
        "agent_messages.rs",
        "routes/admin.rs",
        "routes/cluster.rs",
        // Control over the bus (i131): publishes `node.<id>.rpc.<op>`, never `worker.*`.
        "node_rpc.rs",
        "autonomy_loop.rs",
        "bus.rs",
    ];

    fn src_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    fn rel(path: &Path) -> String {
        path.strip_prefix(src_dir())
            .expect("under src/")
            .to_string_lossy()
            .replace('\\', "/")
    }

    #[test]
    fn every_nats_publish_is_declared() {
        let mut files = Vec::new();
        rust_files(&src_dir(), &mut files);
        assert!(files.len() > 50, "walked only {} files — wrong root?", files.len());

        let mut found_any = false;
        let mut stray: Vec<String> = Vec::new();
        for path in &files {
            let name = rel(path);
            let source = std::fs::read_to_string(path).expect("readable");
            for (i, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if !PUBLISH_CALLS.iter().any(|c| line.contains(c)) {
                    continue;
                }
                // `.request(` is common on HTTP clients too; only a line
                // talking to a NATS client counts.
                if !line.contains("nats") {
                    continue;
                }
                found_any = true;
                let declared = SIGNING_SITES.iter().any(|(f, _)| *f == name)
                    || NON_WORKER_PUBLISHERS.contains(&name.as_str());
                if !declared {
                    stray.push(format!("{name}:{}: {}", i + 1, line.trim()));
                }
            }
        }
        assert!(
            found_any,
            "the scan matched NO NATS publish anywhere — the parse is broken, not the \
             code, and this test would then pass forever without checking anything"
        );
        assert!(
            stray.is_empty(),
            "a NATS publish appeared outside the declared sites. If it can carry a \
             `worker.*` subject it MUST attach a principal header \
             (`bus_principal::headers_for`); if it cannot, add the file to \
             NON_WORKER_PUBLISHERS and say why in the diff.\n  {}",
            stray.join("\n  ")
        );
    }

    #[test]
    fn each_signing_site_attaches_a_header() {
        for (file, call) in SIGNING_SITES {
            let source =
                std::fs::read_to_string(src_dir().join(file)).expect("declared site exists");
            assert!(
                source.contains(call),
                "{file} is declared as a signing site for `{call}` but never calls it — \
                 the worker.* publish there is going out unsigned"
            );
            assert!(
                source.contains("bus_principal::headers_for"),
                "{file} publishes worker.* but never builds a principal header"
            );
        }
    }

    #[test]
    fn the_worker_client_signs_all_three_of_its_paths() {
        // The unsigned calls survive as the `None` arm of each match (a
        // gateway with no controller secret). What must hold is that every
        // path asks for a header first.
        let source = std::fs::read_to_string(src_dir().join("worker_client.rs")).unwrap();
        for call in [
            "send_request",
            "request.headers(h)",
            "publish_with_headers",
            "publish_with_reply_and_headers",
        ] {
            assert!(source.contains(call), "worker_client lost its {call} path");
        }
        assert_eq!(
            source.matches("bus_principal::headers_for").count(),
            3,
            "worker_client has three publish paths; a signing call was added or lost"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[(&str, &str)] = &[("worker", "worker-bus-key"), ("trellion", "trellion-bus-key")];

    fn cached(name: &str) -> bool {
        account_cache().lock().unwrap().contains_key(name)
    }

    /// A role change or disable must not wait out the 30 s cache: the entry
    /// (under the account name and under a connection-labelled name) is gone
    /// the moment the account change ends its sessions.
    #[test]
    fn invalidating_an_account_drops_its_cached_principal_only() {
        let now = now_secs();
        {
            let mut c = account_cache().lock().unwrap();
            c.insert("inv-alice".into(), (now, Some(Principal::user("inv-alice", crate::auth::Role::Admin, vec![]))));
            c.insert("inv-alice/laptop".into(), (now, None));
            c.insert("inv-bob".into(), (now, None));
        }
        assert!(cached("inv-alice") && cached("inv-bob"));
        invalidate_account("inv-alice/laptop");
        assert!(!cached("inv-alice/laptop"));
        assert!(!cached("inv-alice"), "the account's entry goes with its connection label");
        assert!(cached("inv-bob"), "other accounts keep their cache");
    }

    /// The place every account change funnels through must call it, or the
    /// test above proves a function nobody runs.
    #[test]
    fn ending_an_accounts_sessions_invalidates_its_channel_principal() {
        let src = include_str!("session_floor.rs");
        let f = &src[src.find("pub async fn end_account_sessions").unwrap()..src.find("pub struct Summary").unwrap()];
        assert!(f.contains("bus_principal::invalidate_account(account)"));
    }

    fn split(token: &str) -> (String, String) {
        let (body, sig) = token.split_once('.').expect("two fields");
        (body.to_string(), sig.to_string())
    }

    fn decode(token: &str) -> serde_json::Value {
        let (body, _) = split(token);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .expect("base64url");
        serde_json::from_slice(&raw).expect("json")
    }

    #[test]
    fn signs_the_claims_the_worker_parses() {
        let p = Principal::user("alice", crate::auth::Role::User, vec!["read".into()]);
        let token = sign_at(&p, "worker.rag.query", KEYS, 1_000, "n1".into()).unwrap();
        let claims = decode(&token);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["kind"], "user");
        assert_eq!(claims["role"], "user");
        assert_eq!(claims["subj"], "worker.rag.query");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_000 + TTL_SECS);
        assert_eq!(claims["nonce"], "n1");
        assert_eq!(claims["scopes"][0], "read");
    }

    #[test]
    fn each_audience_gets_its_own_mac_over_the_transmitted_body() {
        let p = Principal::user("alice", crate::auth::Role::User, vec![]);
        let token = sign_at(&p, "worker.rag.query", KEYS, 1_000, "n1".into()).unwrap();
        let (body, sigs) = split(&token);
        let macs: Vec<(&str, &str)> = sigs.split(',').map(|e| e.split_once('=').expect("aud=mac")).collect();
        assert_eq!(macs.iter().map(|(a, _)| *a).collect::<Vec<_>>(), ["worker", "trellion"]);
        for ((aud, mac), (_, key)) in macs.iter().zip(KEYS) {
            let mut m = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
            m.update(format!("{aud}.{body}").as_bytes());
            assert_eq!(*mac, hex::encode(m.finalize().into_bytes()), "{aud}");
            assert_eq!(mac.len(), 64, "full-width HMAC, never a truncated prefix");
        }
        assert_ne!(macs[0].1, macs[1].1, "one key per audience: a leaked key forges for its holder only");
    }

    /// Review L5: the known-answer vector, shared with
    /// tests/test_bus_principal.py (`test_the_mac_matches_the_known_answer_vector`).
    #[test]
    fn the_mac_matches_the_known_answer_vector() {
        assert_eq!(
            audience_mac("trellion", "kat-key-0123456789abcdef", "eyJzdWIiOiJrYXQifQ").as_deref(),
            Some("3327620662d8835fbe27e8595ef9f10050d3477175dbb98a1644d0604140af2f")
        );
    }

    /// The audience is inside the MAC: the same key under another audience
    /// name yields a different MAC, so a MAC cannot be relabelled.
    #[test]
    fn a_mac_cannot_be_moved_to_another_audience() {
        let body = "eyJzdWIiOiJ4In0";
        assert_ne!(audience_mac("worker", "k", body), audience_mac("trellion", "k", body));
    }

    /// nothing here signs with the controller secret any
    /// more, and a gateway with no bus key sends no header rather than a
    /// controller-secret one.
    #[test]
    fn the_signer_never_uses_the_controller_secret() {
        let src = include_str!("bus_principal.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let code: String = code.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(!code.contains("controller_secret"), "the bus signer reads the controller secret again");
        assert!(!code.contains("NOO_CONTROLLER_SECRET"), "the bus signer names the controller secret again");
        assert!(sign_at(&Principal::unattributed(), "worker.x", &[], 1, "n".into()).is_none());
    }

    /// The fixed audience list, the CLI's registry and compose agree.
    #[test]
    fn every_audience_key_is_file_backed_and_delivered_to_the_gateway() {
        let compose = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker-compose.cluster.yml"),
        )
        .unwrap();
        for (aud, var) in AUDIENCES {
            assert!(crate::config::secret_env::FILE_BACKED_SECRETS.contains(var), "{var} ({aud}) is not file-backed");
            let pointer = format!("{var}_FILE=${{{var}:+/run/secrets/{}}}", var.to_ascii_lowercase());
            assert!(compose.contains(&pointer), "the gateway is not delivered {var}: `{pointer}` missing");
        }
    }

    #[test]
    fn the_subject_is_part_of_the_signature() {
        let p = Principal::user("alice", crate::auth::Role::User, vec![]);
        let a = sign_at(&p, "worker.memory.search", KEYS, 1_000, "n1".into()).unwrap();
        let b = sign_at(&p, "worker.tool.generic", KEYS, 1_000, "n1".into()).unwrap();
        assert_ne!(a, b, "a principal must not be replayable onto another subject");
    }

    #[test]
    fn an_internal_actor_is_never_an_admin() {
        let p = Principal::internal("heartbeat", &["read"]);
        assert_eq!(p.sub, "internal:heartbeat");
        assert_eq!(p.kind, Kind::Internal);
        assert_eq!(p.role, "user");
        assert!(!p.scopes.iter().any(|s| s == "admin"));
        assert!(!INTERNAL_SERVICE_SCOPES.contains(&"admin"));
        assert!(!INTERNAL_SERVICE_SCOPES.contains(&SCOPE_KB_UNRESTRICTED));
    }

    #[test]
    fn the_fallback_principal_has_no_scopes() {
        let p = Principal::unattributed();
        assert_eq!(p.sub, UNATTRIBUTED);
        assert!(p.scopes.is_empty(), "an unattributed publish must not carry authority");
    }

    #[test]
    fn nonces_do_not_repeat() {
        let a = new_nonce();
        let b = new_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[tokio::test]
    async fn the_task_local_scopes_the_caller() {
        assert_eq!(current().sub, UNATTRIBUTED);
        let p = Principal::user("bob", crate::auth::Role::Operator, vec!["write".into()]);
        with_principal(p.clone(), async {
            assert_eq!(current(), p);
        })
        .await;
        assert_eq!(current().sub, UNATTRIBUTED, "scope must not leak out");
    }

    #[test]
    fn a_requester_extension_becomes_a_user_principal() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(crate::auth::RequesterCtx {
            sub: "carol".into(),
            scopes: vec!["read".into(), "write".into()],
            role: crate::auth::Role::Operator,
            harness: None,
            act: None,
        });
        let p = from_extensions(&ext).expect("a principal");
        assert_eq!(p.sub, "carol");
        assert_eq!(p.kind, Kind::User);
        assert_eq!(p.role, "operator");
    }

    #[test]
    fn a_node_credential_carries_no_scopes() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(crate::auth::ClusterNode(
            "gpu-1".into(),
            crate::auth::ClusterKind::Node,
        ));
        let p = from_extensions(&ext).expect("a principal");
        assert_eq!(p.sub, "internal:node:gpu-1");
        assert!(p.scopes.is_empty());
    }

    #[test]
    fn a_controller_credential_is_internal_not_admin() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(crate::auth::ClusterNode(
            "gateway".into(),
            crate::auth::ClusterKind::Internal,
        ));
        let p = from_extensions(&ext).expect("a principal");
        assert_eq!(p.sub, "internal:cluster:gateway");
        assert!(!p.scopes.iter().any(|s| s == "admin"));
    }

    // ── channel / task turns sign as the account's real principal ──────

    #[test]
    fn a_read_scope_account_is_user_read_and_nothing_else() {
        let p = principal_from_row("ada", "user", &serde_json::json!(["read"]), false).unwrap();
        assert_eq!(p.role, "user");
        assert_eq!(p.scopes, vec!["read".to_string()]);
        assert_eq!(p.kind, Kind::User);
        assert_eq!(p.sub, "ada");
    }

    #[test]
    fn an_empty_scopes_column_takes_the_roles_own_scopes() {
        let p = principal_from_row("op", "operator", &serde_json::json!([]), false).unwrap();
        assert_eq!(p.role, "operator");
        assert_eq!(p.scopes, vec!["read".to_string(), "write".to_string()]);
    }

    #[test]
    fn a_channel_principal_is_capped_below_admin() {
        let p = principal_from_row("root", "admin", &serde_json::json!(["read", "write", "admin"]), false).unwrap();
        assert_eq!(p.role, "operator", "a chat turn is not an admin session");
        assert!(!p.scopes.iter().any(|s| s == "admin"));
        assert!(!p.scopes.iter().any(|s| s == SCOPE_KB_UNRESTRICTED));
    }

    #[test]
    fn a_disabled_account_has_no_principal_and_a_bad_role_reads_as_user() {
        assert!(principal_from_row("x", "operator", &serde_json::json!(["write"]), true).is_none());
        let p = principal_from_row("x", "???", &serde_json::json!([]), false).unwrap();
        assert_eq!(p.role, "user");
    }

    /// The fallback used to be `Operator, [read, write]` for any named
    /// requester. It is the floor now.
    #[tokio::test]
    async fn the_no_principal_fallback_is_not_operator() {
        let turn = crate::routes::communication::TurnPrincipal {
            requester: "ada".into(),
            channel: "telegram".into(),
            ..Default::default()
        };
        let p = crate::routes::communication::with_turn_principal(turn, async { current() }).await;
        assert_eq!(p.sub, "ada");
        assert_eq!(p.role, "user");
        assert_eq!(p.scopes, vec!["read".to_string()]);
        assert!(!p.scopes.iter().any(|s| s == "write"));
    }

    #[tokio::test]
    async fn a_scoped_principal_wins_over_the_fallback() {
        let turn = crate::routes::communication::TurnPrincipal { requester: "ada".into(), ..Default::default() };
        let real = Principal::user("ada", crate::auth::Role::Operator, vec!["read".into(), "write".into()]);
        let p = crate::routes::communication::with_turn_principal(turn, with_principal(real, async { current() })).await;
        assert_eq!(p.role, "operator");
    }

    #[test]
    fn unattended_turns_keep_operator_read_write_explicitly() {
        let p = unattended_principal("system:heartbeat");
        assert_eq!(p.sub, "system:heartbeat");
        assert_eq!(p.role, "operator");
        assert_eq!(p.scopes, vec!["read".to_string(), "write".to_string()]);
    }
}
