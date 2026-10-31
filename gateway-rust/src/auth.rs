// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Authentication — JWT tokens + HMAC cluster auth.
//!
//! Kept the same JWT secret and token format as the Python gateway during
//! the cutover, so tokens issued by either were valid in both. The Python
//! gateway has since been deleted; this is now the only issuer/verifier.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::Instant;

use crate::service_keys::{self, Consumer};
use crate::state::AppState;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

/// Authenticated principal (JWT `sub`), stashed in request extensions on every
/// JWT-authenticated request so handlers can attribute privileged actions
/// (config changes, deletions) to an actor in the audit trail (H-L1).
#[derive(Clone, Debug)]
pub struct AuthActor(pub String);

/// The node a request authenticated AS, via cluster token. Absent for operator
/// (JWT) callers, which is deliberate: an operator asking for a node's config
/// is a legitimate, different thing from a node asking for a peer's.
#[derive(Clone, Debug)]
pub struct ClusterNode(pub String, pub ClusterKind);

/// What a cluster-token caller IS (the design wave A′).
///
/// - `Internal`: one of the stack's own services on the controller —
///   gateway self-calls, the worker, trellion, the MCP doors, the CLI.
///   Proven by `NOO_CONTROLLER_SECRET`, which is never pushed to nodes.
///   Keeps fleet-wide privilege, exactly what every cluster token had
///   before.
/// - `Node`: a node-agent, proven by the fleet-wide `NOO_CLUSTER_SECRET`.
///   Admitted to [`NODE_ROUTES`] only, and only for its own node id.
///
/// Legacy mode: while `NOO_CONTROLLER_SECRET` is unset nothing can tell a
/// service from a node, so every fleet-secret token is `Internal` as
/// before and the boot log says how to close the door. Setting the
/// secret IS the switch — no separate flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterKind {
    Internal,
    Node,
}

/// The subject (`peer:<agent_id>`) of a peer-scoped token, inserted on the
/// peer surface only.
#[derive(Clone, Debug)]
pub struct PeerSub(pub String);

impl ClusterNode {
    pub fn is_internal(&self) -> bool {
        self.1 == ClusterKind::Internal
    }
}

/// `NOO_CONTROLLER_SECRET`, when configured.
pub fn controller_secret() -> Option<String> {
    crate::config::secret_env::secret_opt("NOO_CONTROLLER_SECRET")
}

/// A gateway with no controller secret does not serve.
///
/// Without it every token signed with the fleet secret — the one every node
/// holds — would have to be treated as an operator's, which is what the
/// handler-level guards behind the review exist to prevent. There
/// used to be a posture bridge (`NOO_CLUSTER_LEGACY_FULL_ACCESS`) that
/// granted exactly that for installs predating the secret; it is retired,
/// and a row or env value still opening it is itself a boot refusal
/// (`posture::retired_bridge_refusal`). So "no secret" has one answer.
pub const LEGACY_REFUSAL: &str =
    "NOO_CONTROLLER_SECRET is not set. Without it every token signed with the fleet secret — the \
     one every node holds — would authenticate as the OPERATOR, so the gateway refuses to start. \
     Mint it: `noo security secrets rotate NOO_CONTROLLER_SECRET`, then recreate the controller \
     services (nodes need nothing).";

pub fn boot_refusal() -> Option<&'static str> {
    controller_secret().is_none().then_some(LEGACY_REFUSAL)
}

/// Verify a `<actor>:<ts>:<hmac>` token against the controller-local
/// secret; the actor when it verifies.
pub fn verify_controller_token(token: &str) -> Option<String> {
    let secret = controller_secret()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !verify_cluster_token_inner(token, &secret, now) {
        return None;
    }
    token.split(':').next().map(str::to_string)
}

/// Every gateway route a node-agent needs (from the Go source: register,
/// heartbeat, desired-config pull, artifact pull, bundle apply report,
/// artifact manifests, embedding/extraction helpers, agent messaging for
/// its own agents). `{self}` must equal the token's actor. Anything not
/// here is 403 for a `Node` token — a node has no business in placements
/// of other nodes, posture, users, secrets, migrations or raw SQL.
pub const NODE_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/cluster/nodes/register"),
    ("POST", "/api/cluster/nodes/{self}/heartbeat"),
    // Log ingest (fleet logging phase 2): a node ships its own log lines
    // and nothing else's; the handler overwrites the `node` label with
    // `{self}` (routes/logs_ingest.rs).
    ("POST", "/api/cluster/nodes/{self}/logs"),
    ("GET", "/api/cluster/nodes/{self}/desired-config"),
    // External MCP discovery report: only for a
    // server placed on this node, which the handler checks.
    ("POST", "/api/cluster/nodes/{self}/mcp/*"),
    ("POST", "/api/cluster/nodes/{self}/pull"),
    ("POST", "/bootstrap/bundle/{self}/applied"),
    ("GET", "/api/artifacts/manifest/*"),
    ("POST", "/api/embed"),
    // NOT `/api/external/embeddings` or `/api/external/rerank`: nothing on a node calls them — the Go agent's
    // embedding helper is `/api/embed` above, and the agent SERVES rerank to
    // the gateway rather than calling it — and the live controller counted
    // 0 fleet-secret admissions on the inference surface
    // (`self_call_shared_secret`, retired) for seven days. Left listed, a
    // stolen fleet secret bought inference whenever the self-call bridge was
    // open; the bridge is deleted and the fleet door refuses the inference
    // surface outright (`self_call_shared_secret_refused`).
    ("POST", "/api/v1/rag/extract"),
    ("POST", "/api/v1/rag/build-edges"),
    ("POST", "/api/v1/graph/extract"),
    ("POST", "/api/v1/graph/build-edges"),
    ("GET", "/api/v1/rag/status"),
    ("POST", "/api/memory/embed/start"),
    ("GET", "/api/memory/embed/status"),
    // Agent messaging: handlers scope a Node caller to `<self>/…` agents.
    ("GET", "/api/agents/messages"),
    ("POST", "/api/agents/messages"),
    ("GET", "/api/agents/messages/*"),
    ("POST", "/api/agents/messages/*"),
    ("GET", "/api/agents/threads"),
    ("GET", "/api/agents/keys/*"),
    ("PUT", "/api/agents/keys/*"),
    // The node-held tunnel (i131 phase 2): a node opens it as ITSELF. The
    // handler additionally requires the TLS client certificate to name the
    // same node as this token's actor and a controller-verified challenge
    // response (`tunnel.rs`).
    ("GET", "/api/node/tunnel"),
];

/// Is `method path` on the node allow-list for `actor`? `{self}` segments
/// must equal the actor; a trailing `*` matches the rest of the path.
pub fn node_route_allowed(method: &str, path: &str, actor: &str) -> bool {
    NODE_ROUTES.iter().any(|(m, pattern)| {
        if *m != method {
            return false;
        }
        let mut want = pattern.split('/');
        let mut have = path.split('/');
        loop {
            match (want.next(), have.next()) {
                (None, None) => return true,
                // A trailing `*` needs at least one segment under it.
                (Some("*"), Some(_)) => return true,
                (Some("{self}"), Some(h)) => {
                    if h != actor {
                        return false;
                    }
                }
                (Some(w), Some(h)) => {
                    if w != h {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    })
}

/// Account role — the coarse permission tier. Strict cascade:
/// `User ⊂ Operator ⊂ Admin`, so authorization checks are ORDER comparisons
/// (`role >= Role::Operator`), never enumerations of scope strings.
///
/// | Role | Intent |
/// |---|---|
/// | `User` | UI + interaction: chat, RAG query, graph browse, own history |
/// | `Operator` | User + data ops + task setup (the old `write` scope) |
/// | `Admin` | Operator + identity & trust: users, keys, posture, PKI |
///
/// The legacy scopes (`read`/`write`/`admin`) become an implementation detail
/// the role expands to. During the one-release dual-accept window, validators
/// accept BOTH old scope claims and new role claims (see
/// [`Claims::resolved_role`]), and token issuance emits both (the role claim
/// plus [`Role::legacy_scopes`]).
///
/// Variant order is load-bearing: `PartialOrd`/`Ord` derive from declaration
/// order, and every enforcement site compares. Do not reorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    User,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// The legacy scope set a role expands to (dual-accept window). This is
    /// the 32+38 memo's dual-emit table, verbatim — issuance derives scopes
    /// from the role, never the other way round.
    pub fn legacy_scopes(self) -> &'static [&'static str] {
        match self {
            Role::User => &["read"],
            Role::Operator => &["read", "write"],
            Role::Admin => &["read", "write", "admin"],
        }
    }

    /// Derive a role from a legacy scope list: `admin`→Admin, `write`→
    /// Operator, anything else (including `read`, `ingest`, empty)→User.
    /// Same containment rule as migration 050's backfill.
    pub fn from_scopes<S: AsRef<str>>(scopes: &[S]) -> Role {
        if scopes.iter().any(|s| s.as_ref() == "admin") {
            Role::Admin
        } else if scopes.iter().any(|s| s.as_ref() == "write") {
            Role::Operator
        } else {
            Role::User
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    /// Strict: exactly the three canonical names. Anything else is an error —
    /// callers decide whether that fails closed to `User` (token validation)
    /// or is rejected outright (the role-assignment endpoint).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Role::User),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(format!(
                "unknown role '{other}' (known: user, operator, admin)"
            )),
        }
    }
}

/// Fuller requester context (sub + scopes + resolved role) stashed on
/// JWT-authenticated requests so the delegation layer can forward WHO is
/// asking to Python workers as `_requester` — used for KB role resolution —
/// and so in-handler authorization is a role comparison, not a scope-string
/// match. Cluster-HMAC / service-key callers deliberately get none: they are
/// internal/trusted and query the KB unrestricted.
#[derive(Clone, Debug)]
pub struct RequesterCtx {
    pub sub: String,
    pub scopes: Vec<String>,
    /// Resolved via [`Claims::resolved_role`] at validation time — handlers
    /// must compare against THIS, never re-derive from `scopes`.
    pub role: Role,
    /// Which door minted this credential, when the mint said so. Only the MCP external door sets it, and it sets it inside
    /// a JWT it signs with `NOO_JWT_SECRET` — so this is credential-bound,
    /// not a header a client can attach. `None` = an ordinary user token
    /// (CLI, dashboard, script), which names no verifiable software.
    pub harness: Option<String>,
    /// The delegation recorded in the credential: present
    /// only on a token minted by the identity exchange. Handlers that
    /// write an audit row should name it alongside `sub` — `sub` is who
    /// the call acts as, `act` is who caused it to happen.
    pub act: Option<Actor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // user ID
    pub exp: usize,         // expiry (Unix timestamp)
    #[serde(default)]
    pub role: String,       // "user" | "operator" | "admin" (also pre-scopes legacy tokens)
    #[serde(default)]
    pub scopes: Vec<String>, // ["read", "write", "admin"] (legacy, dual-emitted from role)
    /// Harness stamped in by the door that minted this token
    /// Signed, so it cannot be set by the party presenting the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// The one conversation a node-hosted harness token may act on
    /// Set only by [`mint_harness_jwt`]; signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conv: Option<String>,
    /// RFC 8693 — who obtained this token on the subject's behalf
    /// Set only by [`mint_agent_jwt`], so it is signed: a
    /// party presenting the token cannot add, remove or edit it.
    ///
    /// This is the honest form of the `on_behalf_of` request field the
    /// exchange deliberately does NOT accept. A body field lets a shared
    /// credential name any subject; a signed `act` claim records the
    /// delegation the gateway itself performed, and travels with the
    /// credential to every downstream handler and audit row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    /// RFC 8705 — the certificate this token is BOUND to. Present
    /// only when the exchange was called over a connection that presented
    /// a client certificate, and enforced on every later request: a token
    /// with `cnf` works from that client and nowhere else.
    ///
    /// This is what turns "bounded by a five-minute expiry" into "bounded
    /// by expiry AND possession of the right key". A stolen token is not
    /// merely short-lived, it is unusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Cnf>,
}

/// Inserted by the middleware on a JWT request whose token carried `cnf`
/// AND whose connection presented that very certificate: the thumbprint the
/// token is bound to. Absent for every unbound token. the design —
/// posture writes admit an Admin token only with this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBoundToken(pub String);

/// RFC 8705 confirmation claim. Only `x5t#S256` — the certificate
/// thumbprint — because that is the only confirmation method the mesh CA
/// can attest to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

/// The actor half of an exchanged token (RFC 8693. `sub` is the
/// provisioning consumer (`key:<consumer>`); `iss_user` is the mesh account
/// that consumer is bound to — the human or team answerable for the mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss_user: Option<String>,
    /// The agent RUN a worker-delegated token was minted for (the run id, shared by every tool
    /// call of the turn — `worker_delegation`). Absent on every
    /// other kind of delegated token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

/// The harness rail: a token minted for a node-hosted
/// harness is confined to this prefix. It is a USER token — `sub` is the
/// person whose turn is running — with `harness = "node:<id>"` and the
/// conversation pinned in `conv`, so every call it makes is audited and
/// permission-checked as that person, and can reach nothing else.
pub const HARNESS_PATH_PREFIX: &str = "/api/harness/";

/// The harness claim prefix that marks a node-hosted harness token.
pub const HARNESS_NODE_PREFIX: &str = "node:";

/// Present on a request authenticated by a node-harness token: which node
/// runs the turn and which conversation the token is pinned to. Handlers
/// on the harness rail take the conversation from HERE, never from the
/// body.
#[derive(Debug, Clone, PartialEq)]
pub struct HarnessTurn {
    pub node: String,
    pub conversation_id: String,
    /// The token's expiry (Unix seconds): nothing minted on the turn's
    /// behalf (`door_key`) may outlive it.
    pub exp: u64,
}

/// The harness rail's confinement, as a pure rule: a token whose
/// `harness` claim is `node:<id>` yields a [`HarnessTurn`] on the rail
/// and is refused (403) everywhere else, or when it carries no
/// conversation. Any other token yields `None` and is unaffected.
pub(crate) fn harness_turn_for(claims: &Claims, path: &str) -> Result<Option<HarnessTurn>, StatusCode> {
    let Some(node) = claims.harness.as_deref().and_then(|h| h.strip_prefix(HARNESS_NODE_PREFIX)) else {
        return Ok(None);
    };
    let Some(conv) = claims.conv.clone().filter(|c| !c.is_empty()) else {
        return Err(StatusCode::FORBIDDEN);
    };
    if node.is_empty() || !path.starts_with(HARNESS_PATH_PREFIX) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Some(HarnessTurn { node: node.to_string(), conversation_id: conv, exp: claims.exp as u64 }))
}

/// Mint the credential the gateway hands a node-hosted harness with a
/// turn. A user token for `user` at `role`, pinned
/// to `conversation_id`, stamped `harness = "node:<node>"`, expiring in
/// `ttl_secs`. Signed with `NOO_JWT_SECRET`; `None` when that is unset —
/// no secret, no harness rail.
/// The claim skeleton every minted token shares, and the one place the
/// secret is judged.
///
/// There were four mints before this — harness, agent, agent_with, kiosk —
/// each repeating the same six lines: reject an insecure secret, read the
/// clock, stamp `iss`/`aud`/`iat`/`exp`. Four copies of a credential's
/// skeleton is four places for one of them to drift, and the drift would be
/// silent: a token missing `aud`, or carrying an `exp` computed from a
/// different clock, verifies differently without anything failing to compile.
///
/// What it deliberately does NOT decide is the SIGNING. Agent tokens sign
/// ES256 from the JWKS key when one is configured so a third party can
/// verify without holding a minting secret; harness
/// and kiosk are HS256. Flattening that into the core is exactly the kind of
/// "tidying" that quietly downgrades a credential, so the caller signs.
pub(crate) fn scoped_claims(
    subject: &str,
    role: &str,
    // Generic so each caller passes what it already has — `&[&str]` from
    // `Role::legacy_scopes`, a `Vec` from kiosk — and the serialized JSON is
    // byte-identical to what each mint produced before.
    scopes: impl serde::Serialize,
    ttl_secs: u64,
    secret: &str,
) -> Option<serde_json::Value> {
    if jwt_secret_is_insecure(secret) {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(serde_json::json!({
        "sub": subject,
        "role": role,
        "scopes": scopes,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + ttl_secs,
    }))
}

/// Sign claims with the symmetric secret — the default for everything that
/// is not an exchanged agent token.
pub(crate) fn sign_hs256(claims: &serde_json::Value, secret: &str) -> Option<String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

pub fn mint_harness_jwt(user: &str, role: Role, node: &str, conversation_id: &str, ttl_secs: u64) -> Option<String> {
    let secret = configured_jwt_secret()?;
    mint_harness_jwt_with(user, role, node, conversation_id, ttl_secs, &secret)
}

/// [`mint_harness_jwt`] with the key passed in.
///
/// Same reason as [`mint_agent_jwt_with`]: a test that had to
/// `set_var("NOO_JWT_SECRET")` to reach this would mutate process-wide state
/// that every other test in the binary reads — a flake waiting for a busy
/// machine. The env-reading wrapper above is
/// the only production caller.
pub fn mint_harness_jwt_with(
    user: &str,
    role: Role,
    node: &str,
    conversation_id: &str,
    ttl_secs: u64,
    secret: &str,
) -> Option<String> {
    let mut claims = scoped_claims(user, role.as_str(), role.legacy_scopes(), ttl_secs, secret)?;
    claims["harness"] = serde_json::json!(format!("{HARNESS_NODE_PREFIX}{node}"));
    claims["conv"] = serde_json::json!(conversation_id);
    sign_hs256(&claims, secret)
}

/// The scope that marks a kiosk TOKEN. A token
/// carrying it is read-only BY CONSTRUCTION: the middleware refuses every
/// non-safe method before dispatch, so a route added next year is covered
/// without its author knowing kiosks exist.
///
/// It is no longer a SERVICE-KEY scope. Until 2026-09-30 a key carrying it
/// bought display tokens at `POST /api/kiosk/token` (the key lane) — a
/// credential that never expired, sitting on a machine in a corridor. That
/// route is gone, the scope is not issuable, and a key that still carries
/// it is refused on every route (`service_keys::RETIRED_KEY_SCOPES`).
pub const KIOSK_SCOPE: &str = "kiosk";

/// The KEYLESS mint — the only kiosk mint. Public, because a display that stores no secret has
/// nothing to present — the tailnet is the credential, and the route
/// authenticates fully in-handler through the self-agent's whois and
/// dialback. Listed in `PUBLIC_PATHS_EXACT` for exactly the reason
/// `/api/cluster/enroll-tailnet` is, and rate-limited for the same reason
/// too: an anonymous call costs an outbound whois and a dial-back.
pub const KIOSK_TOKEN_TAILNET_PATH: &str = "/api/kiosk/token/tailnet";

/// Lifetime of a minted kiosk token. Short on purpose: a stolen browser
/// profile yields something that expires on its own, and the display's
/// launcher re-mints well inside this window.
pub const KIOSK_TOKEN_TTL_SECS: u64 = 900;

/// The scope that lets an add-on trade its key for a short-lived token.
///
/// A third door on the exchange, beside kiosk and identity, and deliberately
/// NOT the identity plane's: that one issues `<account>/<label>` connections
/// which must also be usable agent IDs (`routes/identity.rs::connection_subject`).
/// An add-on container is not an account with personas, and dressing it as
/// one would have meant inventing a service account per add-on to satisfy a
/// rule that exists for agents.
///
/// What it reuses instead is the part that is genuinely common: the door
/// table, the claim core, and `noo_service_keys` for the long-lived
/// credential — which keeps `last_used_at`, the evidence the design
/// closes the shared-secret bridge on.
pub const ADDON_SCOPE: &str = "addon";

/// Where an add-on exchanges. Resolved in the middleware (`exchange_scope_for`)
/// so the handler cannot be reached by another credential.
pub const ADDON_TOKEN_PATH: &str = "/api/addon/token";
/// Subject prefix of an exchanged add-on token: `addon:<consumer>`. The
/// middleware reads it back to recognise the token it minted.
pub const ADDON_SUBJECT_PREFIX: &str = "addon:";

/// Ten minutes. Long enough that a busy add-on is not exchanging on every
/// call (an add-on can run ~300 requests/minute), short enough that a token lifted from a container's memory is
/// worth little. The KEY is what gets revoked; this bounds what is already
/// out.
pub const ADDON_TOKEN_TTL_SECS: u64 = 600;

/// An add-on's short-lived token: subject `addon:<name>`, carrying the scopes
/// its KEY carries and no others.
///
/// Signed asymmetrically when a JWKS key is configured, exactly as an
/// exchanged agent token is — an add-on is the case
/// where a third party verifying without being able to mint is the point, and
/// the design is the argument for taking that everywhere.
pub fn mint_addon_jwt(
    name: &str,
    scopes: &[String],
    ttl_secs: u64,
    secret: &str,
    signing: Option<&crate::jwks::SigningKey>,
) -> Option<String> {
    use jsonwebtoken::{encode, Header};
    let claims = scoped_claims(
        &format!("{ADDON_SUBJECT_PREFIX}{name}"),
        Role::User.as_str(),
        scopes,
        ttl_secs,
        secret,
    )?;
    if let Some(key) = signing {
        let mut header = Header::new(crate::jwks::ALG);
        header.kid = Some(key.kid.clone());
        return encode(&header, &claims, &key.encoding).ok();
    }
    sign_hs256(&claims, secret)
}

/// On the inference surface an exchanged add-on token IS the consumer whose
/// key bought it: same name, the key's scopes, no quota, no bound account.
///
/// The token is a JWT, so it takes the JWT branch of the middleware — and
/// that branch ended in the User-tier RBAC, where a POST to
/// `/api/external/embeddings` is not on the chat/query allowlist and gets
/// 403. trellion-intel found this on 2026-09-22: its key was re-issued with
/// `addon` (the provisioning default), it duly exchanged, and every embedding
/// call after 13:53Z was refused at 0 ms — 1,801 refusals in one log tail,
/// graph embedding dead for the afternoon, nothing audited because the
/// refusal came before the handler. The scope check the handler already
/// does (`missing scope`) is the right gate for this credential, and it
/// needs a `Consumer` to run against.
///
/// Off the inference surface the token is an ordinary user-tier token and
/// this returns `None`; the RBAC below keeps applying to it.
pub(crate) fn addon_consumer(claims: &Claims, is_inference_surface: bool) -> Option<Consumer> {
    let name = claims.sub.strip_prefix(ADDON_SUBJECT_PREFIX)?;
    if !is_inference_surface || name.is_empty() {
        return None;
    }
    Some(Consumer {
        name: name.to_string(),
        scopes: claims.scopes.clone(),
        rpm_limit: None,
        user: None,
        user_scopes: Vec::new(),
        user_role: None,
    })
}

/// The scopes an exchanged add-on token carries: everything its key holds
/// EXCEPT the one that opened the door.
///
/// `addon` buys a token and nothing else. Leaving it on the minted token
/// would let that token exchange again — a credential that renews itself past
/// the revocation of the key it came from, which is the property the short
/// lifetime exists to deny.
pub fn addon_token_scopes(key_scopes: &[String]) -> Vec<String> {
    addon_token_scopes_with(key_scopes, &crate::addon_proxy::declared_scopes())
}

/// A key holding a declared add-on scope (`<addon>:<word>`) gets `read` on the
/// exchanged token: an add-on scope opens a GET route only together with
/// `read`, and `read` is not a service-key scope, so without this the granted
/// scope could never open anything. `read` is the User tier's own baseline.
fn addon_token_scopes_with(key_scopes: &[String], declared: &[String]) -> Vec<String> {
    let mut out: Vec<String> =
        key_scopes.iter().filter(|s| s.as_str() != ADDON_SCOPE).cloned().collect();
    if out.iter().any(|s| declared.contains(s)) && !out.iter().any(|s| s == "read") {
        out.push("read".to_string());
    }
    out
}

/// The service-key scope that marks a **provisioning credential** for the
/// agent identity exchange. Operator-issued only, and only
/// onto a key bound to an account (`--user`): the binding is what makes the
/// mint attributable, and the exchange refuses an unbound key for exactly
/// that reason.
pub const IDENTITY_SCOPE: &str = "identity";

/// The one route an identity-scoped service key is accepted on: it buys a
/// short-lived token for an account it may manage, and nothing else.
/// Resolved in the middleware (`exchange_scope_for`) so the handler is
/// unreachable by any other credential class.
pub const IDENTITY_TOKEN_PATH: &str = "/api/identity/token";

/// Default lifetime of an exchanged agent token. Five minutes: long enough
/// for a turn, short enough that a leaked token is a bounded incident
/// rather than a standing credential. This number is the whole argument for
/// the exchange over per-agent long-lived keys.
pub const AGENT_TOKEN_TTL_SECS: u64 = 300;

/// The longest lifetime the exchange will grant, whatever the caller asks
/// for. An hour is already generous for something minted on demand; beyond
/// it the caller should be re-exchanging, not holding.
pub const AGENT_TOKEN_MAX_TTL_SECS: u64 = 3600;

/// Clamp a requested lifetime into `[60, AGENT_TOKEN_MAX_TTL_SECS]`.
///
/// A floor as well as a ceiling: a caller asking for a 1-second token is
/// almost always a units mistake, and granting it produces a credential
/// that expires in flight and reads as an auth outage.
pub fn clamp_agent_ttl(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(AGENT_TOKEN_TTL_SECS)
        .clamp(60, AGENT_TOKEN_MAX_TTL_SECS)
}

/// The role an exchanged token carries: the subject's own live tier, never
/// above the issuer's.
///
/// The clamp is the part that matters. Without it a provisioning key bound
/// to an operator could mint for an admin persona and hand itself a tier it
/// does not hold — privilege escalation through a credential it is allowed
/// to ask for. `may_manage` already refuses that pairing, so this is the
/// second of two independent barriers, not the only one.
pub fn agent_token_role(subject_role: Role, issuer_role: Role) -> Role {
    subject_role.min(issuer_role)
}

/// Mint the credential the identity exchange hands out.
///
/// A plain user token for `subject` — `sub` is the account, so every
/// downstream handler, scope check and usage row treats it as that person
/// with no new trust class to reason about — plus a signed RFC 8693 `act`
/// claim naming the provisioning consumer and the account it is bound to.
///
/// Signed with `NOO_JWT_SECRET`; `None` when that is unset or still the
/// well-known placeholder, in which case there is no exchange (fail closed,
/// exactly as the kiosk mint does).
pub fn mint_agent_jwt(
    subject: &str,
    role: Role,
    consumer: &str,
    issuer_user: Option<&str>,
    ttl_secs: u64,
    bind_to_cert: Option<&str>,
) -> Option<String> {
    let secret = configured_jwt_secret()?;
    mint_agent_jwt_with(
        subject,
        role,
        consumer,
        issuer_user,
        ttl_secs,
        bind_to_cert,
        &secret,
        crate::jwks::signing_key(),
    )
}

/// [`mint_agent_jwt`] with both keys passed in.
///
/// Same reason as [`verify_token_with`]: a test that had to
/// `set_var("NOO_JWT_SECRET")` to exercise the mint would be mutating
/// process-wide state that every other test in the binary reads, which is
/// a flake waiting for a busy machine. The env-reading wrapper above is
/// the only production caller.
#[allow(clippy::too_many_arguments)]
pub fn mint_agent_jwt_with(
    subject: &str,
    role: Role,
    consumer: &str,
    issuer_user: Option<&str>,
    ttl_secs: u64,
    bind_to_cert: Option<&str>,
    secret: &str,
    signing: Option<&crate::jwks::SigningKey>,
) -> Option<String> {
    use jsonwebtoken::{encode, Header};
    let mut claims = scoped_claims(subject, role.as_str(), role.legacy_scopes(), ttl_secs, secret)?;
    claims["act"] = serde_json::json!({ "sub": format!("key:{consumer}"), "iss_user": issuer_user });
    let claims = claims;
    // RFC 8705: bind the token to the certificate that asked for it, when
    // there was one. Nothing to configure — the binding is a property of
    // HOW the exchange was called, never a flag, so a deployment that
    // presents no client certificate is unaffected.
    let mut claims = claims;
    if let Some(tp) = bind_to_cert {
        claims["cnf"] = serde_json::json!({ "x5t#S256": tp });
    }
    // sign asymmetrically when a key is configured,
    // so a third party can verify an exchanged token from the published
    // JWKS without holding anything that could mint one. Only exchanged
    // tokens take this path; login stays HS256 (see `crate::jwks`).
    if let Some(key) = signing {
        let mut header = Header::new(crate::jwks::ALG);
        header.kid = Some(key.kid.clone());
        return encode(&header, &claims, &key.encoding).ok();
    }
    sign_hs256(&claims, secret)
}


/// Does a token bound to a certificate match the certificate actually
/// presented? (RFC 8705
///
/// A pure decision so the three outcomes can be pinned without TLS: an
/// unbound token is unaffected; a bound token needs the right
/// certificate; and a bound token presented over a connection with NO
/// certificate is refused. That last case is the one that matters —
/// otherwise turning mTLS off would silently downgrade every bound token
/// back to a plain bearer.
pub fn cert_binding_holds(bound: Option<&Cnf>, presented: Option<&str>) -> bool {
    match bound {
        None => true,
        Some(c) => presented == Some(c.x5t_s256.as_str()),
    }
}

// ── Grafana session tokens ──────────────────────────
//
// Grafana authenticates people with noomesh accounts through `[auth.jwt]`:
// the console asks `POST /api/monitoring/grafana-session`, the gateway
// mints a short ES256 token for the LIVE account, and the browser opens
// Grafana with it (`?auth_token=`). Grafana verifies it against the public
// half of a DEDICATED key pair (`${NOO_PKI_DIR}/sso/grafana.pub`), never
// the JWKS exchange key: that one is optional, operator-supplied and gated
// by a licensed add-on, and coupling a dashboard login to it would be one
// string answering two questions.
//
// The token carries `aud = "noo-grafana"`, so the gateway's own verifier
// refuses it by construction (`verify_token_with` requires `aud ==
// JWT_AUDIENCE`, and an ES256 token without a `kid` is refused before the
// audience is even read). A leaked Grafana token is worth nothing here.

/// The audience Grafana expects (`expect_claims` in `grafana.ini`), and the
/// one audience the gateway's verifier will never accept.
pub const GRAFANA_AUDIENCE: &str = "noo-grafana";

/// Default Grafana session length in minutes, and the ceiling. Five, not the
/// console login token's fifteen: this token travels in the URL
/// (`?auth_token=`, Grafana's `url_login` — the only way a browser
/// NAVIGATION can hand Grafana a credential, since it cannot set the
/// `X-JWT-Assertion` header and the console opens Grafana's own origin
/// directly, not through the gateway), so it lands in browser history,
/// `Referer` and any proxy log on the way. JWT auth in Grafana is stateless,
/// so the TTL is both the exposure of that URL and exactly how long a
/// disabled account's outstanding tab keeps working. When the tab expires
/// the fix is to click "Open Grafana" again. `NOO_GRAFANA_SESSION_TTL` (minutes) moves it, clamped
/// to [1, 60].
pub const GRAFANA_SESSION_TTL_ENV: &str = "NOO_GRAFANA_SESSION_TTL";
pub const GRAFANA_SESSION_DEFAULT_MINUTES: u64 = 5;
pub const GRAFANA_SESSION_MAX_MINUTES: u64 = 60;

/// The session TTL in seconds from the env value (minutes), clamped. An
/// unparsable value is the default, not zero and not unbounded.
pub fn grafana_session_ttl_secs(env_minutes: Option<&str>) -> u64 {
    let minutes = env_minutes
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(GRAFANA_SESSION_DEFAULT_MINUTES)
        .clamp(1, GRAFANA_SESSION_MAX_MINUTES);
    minutes * 60
}

/// THE tier → Grafana org-role table, and the ONE place to
/// tighten it. Which noomesh tiers open Grafana at all, and as what:
/// the gateway admits only a tier listed here (anything else is refused
/// with a body naming these tiers), and stamps the Grafana role into the
/// token's `grafana_role` claim. `grafana.ini`'s `role_attribute_path`
/// only passes that claim through, strictly, so it carries no mapping of
/// its own (`tests/test_grafana_sso_parity.py` holds it to this table).
///
/// By design every tier
/// gets in; a User is a Viewer — dashboards only, no edit, no Explore, no
/// data-source or admin pages (`[users]` in `grafana.ini`). The User row
/// stands ONLY because Grafana's Prometheus and Loki data sources dial the
/// gateway (`routes::grafana_ds`), which runs a read-only account's query
/// only when it is one of the provisioned dashboards' own and gives it no
/// logs: in open-source Grafana any Viewer can `POST /api/ds/query` with
/// its own PromQL/LogQL, and that is where it is refused. (2026-10-01 to
/// 10-02 the row was absent for exactly that gap.)
/// `tests/test_grafana_sso_parity.py` fails if the row exists while a data
/// source dials Prometheus or Loki directly. Dropping a row refuses that
/// tier; changing a Grafana role here changes it at the next "Open Grafana"
/// (Grafana re-syncs the org role per request).
pub const GRAFANA_ORG_ROLES: &[(Role, &str)] = &[
    (Role::User, "Viewer"),
    (Role::Operator, "Editor"),
    (Role::Admin, "Admin"),
];

/// The Grafana org role [`GRAFANA_ORG_ROLES`] gives a tier; `None` = that
/// tier does not open Grafana.
pub fn grafana_org_role(role: Role) -> Option<&'static str> {
    GRAFANA_ORG_ROLES.iter().find(|(r, _)| *r == role).map(|(_, g)| *g)
}

/// What a refusal says is needed: the tiers the table admits, spelled out.
pub fn grafana_needs() -> String {
    let tiers: Vec<String> = GRAFANA_ORG_ROLES
        .iter()
        .map(|(r, g)| format!("{} (as Grafana {g})", r.as_str()))
        .collect();
    format!(
        "opening Grafana needs a person's own login to an enabled noomesh account at one of these tiers: {}",
        tiers.join(", ")
    )
}

/// The role a Grafana session is minted with, from the LIVE account row —
/// never from the access token's `role` claim, so a demotion or a disable
/// takes effect at the next "Open Grafana" even while the old login JWT is
/// still valid. Returns the tier and its Grafana role from
/// [`GRAFANA_ORG_ROLES`]. `None` is an account with no row — a token whose
/// subject was deleted — and is refused like a disabled one. Every refusal
/// names what is needed. A pure function so the table is pinned; a
/// source-grep test holds the handler to calling it.
///
/// `viewer` is [`grafana_viewer_gate`]'s answer, and it is asked ONLY of
/// the read-only tier: the User → Viewer row in
/// [`GRAFANA_ORG_ROLES`] is safe only while Grafana's data sources go
/// through the gateway, and the gateway refuses the Viewer unless that is
/// both declared and proven. Operators and admins never depend on it.
pub fn grafana_session_role(
    live: Option<Role>,
    disabled: bool,
    viewer: &Result<(), String>,
) -> Result<(Role, &'static str), String> {
    match live {
        None => Err(format!("account not found — {}", grafana_needs())),
        Some(_) if disabled => Err(format!("account is disabled — {}", grafana_needs())),
        Some(Role::User) if viewer.is_err() => Err(format!(
            "the read-only {} tier opens Grafana only while Grafana's data sources go through the gateway, \
             and this stack has not shown that they do: {} — {}",
            Role::User.as_str(),
            viewer.as_ref().err().map(String::as_str).unwrap_or(""),
            grafana_needs()
        )),
        Some(role) => match grafana_org_role(role) {
            Some(g) => Ok((role, g)),
            None => Err(format!("the {} tier does not open Grafana — {}", role.as_str(), grafana_needs())),
        },
    }
}

/// The compose declaration: set to `1` on the gateway
/// service by the compose file that ships in the SAME CLI release as the
/// Grafana configs pointing its data sources at the gateway. An older CLI
/// rolling a newer gateway image renders its own older compose, which lacks
/// it, while laying down its own older Grafana configs (data sources direct).
/// Absent = the read-only tier gets no Grafana.
pub const GRAFANA_DS_GATE_ENV: &str = "NOO_GRAFANA_DS_VIA_GATEWAY";

/// The header Grafana reads its JWT from (`[auth.jwt] header_name` in
/// `grafana.ini`; `tests/test_grafana_sso_parity.py` holds the two equal).
pub const GRAFANA_JWT_HEADER: &str = "X-JWT-Assertion";

/// Whether the compose declaration is set. Only the literal `1` counts.
pub fn grafana_ds_gate_declared(value: Option<&str>) -> bool {
    value.map(str::trim) == Some("1")
}

/// May a read-only account be a Grafana Viewer right now? BOTH halves, or
/// no (fail closed):
/// 1. the compose declaration [`GRAFANA_DS_GATE_ENV`] (`flag`), and
/// 2. live evidence that the RUNNING Grafana's data sources point at the
///    gateway (`evidence`; `None` = not asked, because the flag already
///    failed — the probe is not worth a round trip then).
/// `Err` names what is missing and the fix.
pub fn grafana_viewer_gate(flag: Option<&str>, evidence: Option<Result<(), String>>) -> Result<(), String> {
    if !grafana_ds_gate_declared(flag) {
        return Err(format!(
            "the running gateway's compose file does not declare {GRAFANA_DS_GATE_ENV}=1, so the Grafana configs beside it \
             may still dial Prometheus and Loki directly (an older CLI release rolled this stack). \
             Fix: noo upgrade --all, run from the current CLI release"
        ));
    }
    match evidence {
        Some(Ok(())) => Ok(()),
        Some(Err(why)) => Err(why),
        None => Err("Grafana's data sources were not checked".into()),
    }
}

/// Mint the Grafana session token. ES256 with the DEDICATED SSO key, header
/// `{alg, typ}` only — no `kid`, because Grafana builds a one-key set from
/// `key_file` and a `kid` that does not match its (unset) `key_id` fails.
/// Claims are exactly `{iss, aud, sub, role, grafana_role, iat, exp, jti}`:
/// `role` is the noomesh tier (for the audit trail), `grafana_role` is the
/// org role from [`GRAFANA_ORG_ROLES`] that `grafana.ini` reads. `None`
/// for a tier the table does not admit. Not [`scoped_claims`], which
/// stamps `aud = JWT_AUDIENCE` and `scopes`, and the whole point is the
/// OTHER audience.
pub fn mint_grafana_jwt_with(
    subject: &str,
    role: Role,
    ttl_secs: u64,
    key: &jsonwebtoken::EncodingKey,
) -> Option<String> {
    use jsonwebtoken::{encode, Algorithm, Header};
    let grafana_role = grafana_org_role(role)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let claims = serde_json::json!({
        "iss": JWT_ISSUER,
        "aud": GRAFANA_AUDIENCE,
        "sub": subject,
        "role": role.as_str(),
        "grafana_role": grafana_role,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(&Header::new(Algorithm::ES256), &claims, key).ok()
}

/// How long a delegated token's "is the subject still enabled?" answer is
/// cached. Short on purpose: this is the lookup that makes the kill switch
/// real, so the window between disabling an account and its outstanding
/// tokens going dead has to be small enough to describe in a sentence.
const DELEGATED_SUBJECT_TTL: std::time::Duration = std::time::Duration::from_secs(10);

static DELEGATED_SUBJECTS: OnceLock<RwLock<HashMap<String, (Option<Role>, Instant)>>> = OnceLock::new();

/// Is the subject of a DELEGATED token still an enabled account?
///
/// Only exchanged tokens (the ones carrying `act`) and node-harness
/// tokens are checked, and that narrowness is the design. An ordinary JWT
/// is stateless by choice and stays that way; an exchanged one is minted
/// on demand for an account somebody else controls, so "stop this agent"
/// has to mean something before the token expires. Revoking the
/// provisioning key stops the next mint; THIS is what makes the one
/// already in flight stop working.
///
/// One indexed lookup by username, cached for [`DELEGATED_SUBJECT_TTL`],
/// and only on agent traffic. A missing account reads as disabled: an
/// account erased out from under a live token must not keep working.
pub async fn delegated_subject_enabled(db: &sqlx::PgPool, subject: &str) -> bool {
    live_account_role(db, subject).await.is_some()
}

/// The account's role as the database holds it NOW, or `None` when it is
/// disabled, absent, holds a role this build cannot read, or the database
/// cannot answer. Shares [`delegated_subject_enabled`]'s cache and bound.
pub async fn live_account_role(db: &sqlx::PgPool, subject: &str) -> Option<Role> {
    // A connection subject is checked against its OWNER: the account is
    // the row in `noo_users`, and disabling the person must stop every
    // connection they hold. Without this the lookup would search for
    // `owner/session` as a username, find nothing, and fail closed on
    // every request — the kill switch would look like a total outage.
    let subject = account_of(subject);
    let cache = DELEGATED_SUBJECTS.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(map) = cache.read() {
        if let Some((live, at)) = map.get(subject) {
            if at.elapsed() < DELEGATED_SUBJECT_TTL {
                return *live;
            }
        }
    }
    let row: Result<Option<(bool, String)>, _> =
        crate::repo::users::role_and_disabled(db, subject).await;
    let live = match row {
        Ok(Some((false, role))) => role.parse::<Role>().ok(),
        // Disabled, or no such account — fail closed.
        Ok(_) => None,
        // A database that cannot answer must not be read as "enabled":
        // that would turn a DB blip into a window where a killed agent
        // works again. Not cached, so it re-asks on the next request.
        Err(e) => {
            tracing::warn!(subject = %subject, error = %e, "delegated subject check failed; refusing");
            return None;
        }
    };
    if let Ok(mut map) = cache.write() {
        if map.len() > 10_000 {
            map.clear();
        }
        map.insert(subject.to_string(), (live, Instant::now()));
    }
    live
}

/// Does a node-harness token still speak for its account? Only while the
/// account is enabled AND the token's role is no higher than the account's
/// live role: a downgrade or a disable reaches a turn already running
/// within [`DELEGATED_SUBJECT_TTL`], not at the token's exp (the turn
/// deadline plus a minute). An upgrade is not propagated; it waits for the
/// next mint (checkpoint renewal or the next dispatch).
pub(crate) fn rail_token_admitted(token_role: Role, live: Option<Role>) -> bool {
    live.is_some_and(|l| token_role <= l)
}

/// Which service-key scope, if any, opens a token-exchange route.
///
/// A pure function of method and path so the mapping can be pinned by a
/// test without a database, and so adding a door is one row rather than
/// another branch in the middleware.
pub fn exchange_scope_for(path: &str, method: &axum::http::Method) -> Option<&'static str> {
    if *method != axum::http::Method::POST {
        return None;
    }
    // No kiosk row: the kiosk KEY lane was retired. A display
    // mints at KIOSK_TOKEN_TAILNET_PATH, which is public and proves itself
    // in-handler; `/api/kiosk/token` admits no key and is not routed.
    match path {
        IDENTITY_TOKEN_PATH => Some(IDENTITY_SCOPE),
        ADDON_TOKEN_PATH => Some(ADDON_SCOPE),
        _ => None,
    }
}

/// Whether these claims are a kiosk credential.
pub fn is_kiosk(claims: &Claims) -> bool {
    claims.scopes.iter().any(|s| s == KIOSK_SCOPE)
}

/// Exactly what a display reads. **An allowlist, because a kiosk is not a
/// user with the writes taken away** — it is a screen that draws nine
/// things, and anything else it can reach is reach it does not need.
///
/// Method-only enforcement made every GET in the API available to a
/// credential sitting on an unattended machine in a corridor: conversations,
/// memory, retrieval, the knowledge base. None of that is on the screen.
/// The blast radius of a token lifted from that laptop was "everything a
/// person can read"; it is now "the dashboard".
///
/// Adding a route does not widen this. That is the same property the write
/// refusal already had, now true for reads as well: a route added next year
/// is closed to kiosks until someone puts it here on purpose.
pub const KIOSK_READ_PATHS: &[&str] = &[
    // The health view's sources, fetched once per stream connection.
    "/api/cluster/status",
    "/api/cluster/gpu-metrics",
    "/api/jobs",
    "/api/scheduler/status",
    "/api/heartbeat/status",
    "/api/memory/health",
    "/api/v1/rag/status",
    // NOT here: `/health`. It was, briefly, for the add-ons tile. The tile
    // now reads `/api/kiosk/addons` — covered by KIOSK_READ_PREFIXES, and
    // built to return the add-on map and nothing else. `/health` answers
    // with no credential at all, so putting it in the kiosk's scope gave
    // the display the gateway version, the engine, the peer count and the
    // dependency health in order to render four words.
    // The stream itself.
    "/api/events/stream",
];
// NOT here, deliberately: `/api/v1/graph/clusters/overview`. The display
// read it directly until the graph view moved to the entity level, and it
// returns cluster NAMES unconditionally — there is no `?labels=` gate on
// the general route. A path on this list is readable by anyone who pulls
// the token off a machine standing in a corridor, so leaving a
// names-carrying route on it after nothing fetches it is a hole kept open
// for nostalgia. The display reads `/api/kiosk/graph`, which projects the
// entity view and withholds names unless asked.

/// Prefixes a kiosk may read. `/api/kiosk/` is the projection surface built
/// for exactly this: each handler returns a named subset of a general
/// route's own answer, so a field added upstream cannot reach the display
/// without someone editing the field list.
pub const KIOSK_READ_PREFIXES: &[&str] = &["/api/kiosk/"];
// One of those projections, `/api/kiosk/graph`, can carry entity NAMES —
// but only while the controller switch `kiosk.graph_labels` is on (a DB
// setting only an Operator/Admin can flip: `noo kiosk labels on|off`, #906).
// Nothing the kiosk sends can turn it on: the caller is this credential, and
// a leaked one must not be able to widen its own read to the knowledge
// base's names.

/// Why a kiosk request was refused. Two different answers, because the
/// display should render them differently and the launcher must not treat
/// either as "re-mint and retry".
#[derive(Debug, PartialEq, Eq)]
pub enum KioskRefusal {
    /// A write. Any method that is not safe, on any path.
    ReadOnly,
    /// A safe method on a path no display needs.
    OutOfScope,
}

/// Mechanism 1, as a pure decision so it can be pinned by a test without a
/// database: a kiosk credential may read THE DISPLAY'S ROUTES, and may do
/// nothing else anywhere.
///
/// Both halves are deny-by-default and both are checked before dispatch.
/// The method check runs first so that a write to an allowlisted path still
/// reports `ReadOnly` — the more specific answer for the same refusal.
pub fn kiosk_may(method: &axum::http::Method, path: &str) -> Result<(), KioskRefusal> {
    use axum::http::Method;
    if !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Err(KioskRefusal::ReadOnly);
    }
    if KIOSK_READ_PATHS.contains(&path)
        || KIOSK_READ_PREFIXES.iter().any(|p| path.starts_with(p))
    {
        return Ok(());
    }
    Err(KioskRefusal::OutOfScope)
}

/// The refusal a kiosk credential gets. A 403 with its own `type`, so a
/// display can render "not permitted" rather than "logged out" — a 401
/// would make the host launcher re-mint for nothing.
/// The answer to a controller-secret HMAC signed by the `noo` CLI
/// ([`crate::operator_auth::is_cli_actor`]): 403, the reason, and the
/// upgrade that ends it. `detail` is what every `noo` since the design
/// prints from a refused posture write; `hint` carries the command alone.
pub fn old_cli_refusal() -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "detail": crate::operator_auth::OLD_CLI_REFUSAL,
            "hint": crate::operator_auth::OLD_CLI_UPGRADE,
            "code": "cli_shared_secret_retired",
        })),
    )
        .into_response()
}

pub fn kiosk_refusal(why: KioskRefusal) -> Response {
    use axum::response::IntoResponse;
    let (kind, msg) = match why {
        KioskRefusal::ReadOnly => ("read_only", "kiosk credentials are read-only"),
        KioskRefusal::OutOfScope => (
            "out_of_scope",
            "kiosk credentials may read only the display's own routes",
        ),
    };
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": {"type": kind, "message": msg} })),
    )
        .into_response()
}

/// Mint the credential a display holds in its browser
/// mechanism 2. `sub = "kiosk:<consumer>"`, `role = user`, `scopes =
/// ["kiosk"]` and nothing broader — the marker is signed, so the page
/// cannot widen it. Signed with `NOO_JWT_SECRET`; `None` when that is
/// unset or insecure, in which case there is no kiosk (fail closed).
pub fn mint_kiosk_jwt(consumer: &str, ttl_secs: u64) -> Option<String> {
    let secret = configured_jwt_secret()?;
    mint_kiosk_jwt_with(consumer, ttl_secs, &secret)
}

/// [`mint_kiosk_jwt`] with the key passed in — see [`mint_harness_jwt_with`].
pub fn mint_kiosk_jwt_with(consumer: &str, ttl_secs: u64, secret: &str) -> Option<String> {
    let claims = scoped_claims(
        &format!("kiosk:{consumer}"),
        Role::User.as_str(),
        [KIOSK_SCOPE],
        ttl_secs,
        secret,
    )?;
    sign_hs256(&claims, secret)
}

/// Mint an operator's CERTIFICATE-BOUND Admin token: the
/// credential posture writes admit. `sub` is the operator's account,
/// `role = admin`, and `cnf.x5t#S256` is the thumbprint of the operator leaf
/// the mint was called over — so the token works only from a connection
/// that presents that same leaf (RFC 8705, enforced by the middleware for
/// every bound token). Short-lived; the CLI mints one per posture write.
pub fn mint_operator_jwt(operator: &str, thumbprint: &str, ttl_secs: u64) -> Option<String> {
    let secret = configured_jwt_secret()?;
    mint_operator_jwt_with(operator, thumbprint, ttl_secs, &secret)
}

/// [`mint_operator_jwt`] with the key passed in — see [`mint_harness_jwt_with`].
pub fn mint_operator_jwt_with(operator: &str, thumbprint: &str, ttl_secs: u64, secret: &str) -> Option<String> {
    if thumbprint.trim().is_empty() {
        // An operator token is BOUND by definition. A mint without a
        // thumbprint would be a plain Admin bearer wearing this name.
        return None;
    }
    let mut claims = scoped_claims(operator, Role::Admin.as_str(), Role::Admin.legacy_scopes(), ttl_secs, secret)?;
    claims["cnf"] = serde_json::json!({ "x5t#S256": thumbprint });
    sign_hs256(&claims, secret)
}

impl Claims {
    /// Resolve the effective [`Role`] of a token (dual-accept window).
    ///
    /// - **scopes empty** → the role claim, if it parses; else `User`. This is
    ///   the pre-scopes legacy path: `scopes=[] role="admin"` keeps working.
    /// - **scopes present, no valid role claim** → derived from scopes
    ///   (`admin`→Admin, `write`→Operator, else User). Old scope-only tokens.
    /// - **both present** → the LOWER of the two. Dual-emitted tokens carry a
    ///   consistent pair, so this changes nothing for them; for an
    ///   inconsistent pair the role claim must not out-privilege the scopes
    ///   (or vice versa) — a token minted before a demotion, or a forged
    ///   claim riding alongside narrow scopes, degrades instead of escalating.
    ///   (Stricter than "role claim wins": preserves the pre-existing rule
    ///   that `role="admin"` cannot override explicit read-only scopes.)
    pub fn resolved_role(&self) -> Role {
        let claimed: Option<Role> = self.role.parse().ok();
        if self.scopes.is_empty() {
            return claimed.unwrap_or(Role::User);
        }
        let derived = Role::from_scopes(&self.scopes);
        match claimed {
            Some(c) => c.min(derived),
            None => derived,
        }
    }
}

/// Resolve the JWT secret from environment — same precedence as Python's
/// `get_secret("NOO_JWT_SECRET", "dev-secret-change-in-production")`.
///
/// Resolution order (`secret_env`, shared with every other tier-1 secret):
///   1. `NOO_JWT_SECRET_FILE`       (a file, `/run/secrets/…` once compose delivers one)
///   2. `NOO_SECRET_NOO_JWT_SECRET` (Python SecretsManager prefix convention)
///   3. `NOO_JWT_SECRET`            (primary env var)
///   4. `"dev-secret-change-in-production"` (insecure default, matches Python)
pub fn jwt_secret() -> String {
    // NOTE: no fallback to NOO_CLUSTER_SECRET (H-A2). Reusing the cluster HMAC
    // secret to sign user/peer JWTs means one key mints identities across
    // surfaces (a cluster-token secret could forge user JWTs, and vice-versa).
    // The JWT secret must be its own key; if NOO_JWT_SECRET is unset the auth
    // layer fails CLOSED on the insecure default (see jwt_secret_is_insecure).
    // (The legacy `JWT_SECRET` alias was removed in config-graduation phase 1 —
    // it was set nowhere and only widened the attack surface.)
    configured_jwt_secret().unwrap_or_else(|| INSECURE_DEFAULT_JWT_SECRET.into())
}

/// The configured JWT secret, `None` when nothing is set — the minters
/// (`mint_harness_jwt`, `mint_agent_jwt`, `mint_kiosk_jwt`) refuse rather
/// than sign with the insecure default. Same reader as [`jwt_secret`]:
/// `NOO_JWT_SECRET_FILE` > `NOO_SECRET_NOO_JWT_SECRET` > `NOO_JWT_SECRET`,
/// through `secret_env` so the order has one home.
pub fn configured_jwt_secret() -> Option<String> {
    crate::config::secret_env::secret_opt("NOO_JWT_SECRET")
}

/// The insecure fallback returned by `jwt_secret()` when nothing is configured.
/// It is a public, well-known string, so any JWT signed with it is forgeable.
pub const INSECURE_DEFAULT_JWT_SECRET: &str = "dev-secret-change-in-production";

/// Reconcile the authenticated principal with a client-supplied `user_id` and
/// return the effective identity to scope data by (`None` = unscoped/global).
///
/// Rules (H-D1 / multi-user identity binding):
/// - When the request is authenticated as a specific user (JWT `sub`, i.e.
///   [`AuthActor`]), that subject is **authoritative**. A `claimed` value that
///   disagrees is a spoofing attempt — it is ignored and logged. This holds in
///   both single- and multi-user mode (in single-user the sub *is* the user, so
///   it is never wrong), which is why it closes the `/ws/coordinator`
///   impersonation hole unconditionally.
/// - When there is no authenticated user (trusted internal caller: cluster-HMAC
///   or service key, which deliberately carry no [`AuthActor`]), the `claimed`
///   value is accepted as **delegation** — an internal channel adapter
///   legitimately submits on behalf of an already-resolved user.
/// The separator between an account and one of its connections
/// `owner/laptop` — the account is the part
/// before it.
pub const CONNECTION_SEP: char = '/';

/// The account a name belongs to: itself for a bare account, the prefix
/// for a connection.
///
/// This is the derivation the proposal's two-key rule rests on. Anything
/// that accumulates into a PERSON — history, memory, usage, entitlement,
/// "who is responsible" — resolves through here. Anything that describes
/// one LIVE SESSION — routing, presence, unread state, the trust list —
/// uses the full name. A reviewer should be able to point at any new
/// write and say which it is.
pub fn account_of(name: &str) -> &str {
    match name.split_once(CONNECTION_SEP) {
        Some((account, _)) => account,
        None => name,
    }
}

/// The character class every name segment obeys: `[A-Za-z0-9_-]`, 1–128.
///
/// One definition for BOTH halves of a connection name. The account half
/// was already constrained twice — `routes::users::valid_username` on two
/// creation paths, migration 072 as the backstop — while the label half
/// was checked only for "non-empty, no separator". That asymmetry does
/// not survive contact with a trust list: `owner/ session`, a trailing
/// non-breaking space and a Cyrillic lookalike each mint a DISTINCT
/// identity from the name they resemble, and a trust list is exactly
/// where two visually identical entries are worth something to an
/// attacker.
///
/// ASCII-only is the point, not a limitation. A name that has to be
/// compared by eye — in a trust list, in a presence listing, in an audit
/// row — must not have two spellings that look the same.
///
/// **`.` is excluded, and that is the consolidation.** There used to be
/// three rules: account names allowed `.`, agent ids did not, capability
/// tokens did not. The dot could not be allowed in an id because
/// `agent_messages::subject_token` maps `/` to `.` to build the NATS
/// subject, so permitting both makes `owner/my.laptop` and
/// `owner/my/laptop` the same subject and two agents share an inbox.
///
/// Narrowing the account rule to match was free — no account contained a
/// dot when this was measured (operator, 2026-09-13) — and it is the only
/// direction that ends with ONE rule rather than a mapping between three.
/// Anything else leaves a name that is legal in one plane and illegal in
/// the next, which is how `first.last` became an account that could not
/// send a message.
/// Derive a connection LABEL from a service-key consumer name. A consumer is operator-named and may carry
/// characters a name segment forbids — the self-issued key is `self:<user>`
/// — so every disallowed character becomes `-`, runs collapse, ends are
/// trimmed, and the result is capped at the segment limit.
///
/// Not injective: `a:b` and `a-b` map to one label. Acceptable because
/// consumer names are operator-chosen and unique per install, and the
/// alternative — refusing the door to a key whose name has a colon — would
/// take every self-issued key offline the day this shipped. Stated so the
/// next person does not assume the mapping is reversible.
pub fn connection_label(consumer: &str) -> Option<String> {
    let mut out = String::with_capacity(consumer.len());
    let mut last_dash = true; // trims a leading run
    for c in consumer.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let out = out.trim_end_matches('-').to_string();
    let out: String = out.chars().take(128).collect();
    if valid_name_segment(&out) { Some(out) } else { None }
}

pub fn valid_name_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg.len() <= 128
        && seg.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

/// Why an account name may not contain [`CONNECTION_SEP`], as a rule a
/// caller can check before the database refuses it.
///
/// The CHECK constraint (migration 072) is the boundary — `noo_users` has
/// several writers and only the database sees them all. This exists so a
/// creation path can say *why* instead of surfacing a constraint
/// violation, and so the reason sits next to [`account_of`], which is the
/// function that makes the rule necessary.
pub fn valid_account_name(name: &str) -> Result<(), String> {
    if name.contains(CONNECTION_SEP) {
        return Err(format!(
            "account name '{name}' may not contain '{CONNECTION_SEP}' — that character separates \
             an account from one of its connections, so such a name would have its history and \
             usage attributed to '{}'",
            account_of(name)
        ));
    }
    Ok(())
}

/// Does the credential named `holder` own `name`? (the design's shared
/// predicate.)
///
/// **The rule is deliberately ASYMMETRIC, and that asymmetry is the whole
/// safety property:**
///
/// - an **account** holder (`owner`) owns its own name and everything
///   under its prefix (`owner/laptop`, `owner/claude-s1`);
/// - a **connection** holder (`owner/laptop`) owns **exactly
///   itself** — not its siblings, not its account.
///
/// Read that second line twice before changing this function. The naive
/// version derives the account from the CALLER and then grants everything
/// under it, which would let one of a person's sessions act as — and,
/// because `may_read` shares this predicate, read the mail of — every
/// other session they have open. The account is recoverable from a
/// connection for ATTRIBUTION ([`account_of`]); that must never be turned
/// around into AUTHORITY.
///
/// It falls out of comparing against `account_of(name)`, which is always
/// the FIRST segment: a holder that is itself compound can never equal it,
/// so the prefix arm is unreachable for a connection. Pinned by
/// `a_connection_owns_only_itself`.
///
/// **This is not [`may_manage`]** and the two must never collapse: this
/// asks "is this name mine", `may_manage` asks "may I act for someone
/// else". A connection type that inherited `may_manage` would be an
/// authorization change disguised as a naming change.
///
/// The same rule a NODE has always had for its own agents
/// (`routes::agents::Caller::owns`), now available to an account. One
/// definition, so if the rule changes it changes once.
pub fn owns_name(holder: &str, name: &str) -> bool {
    if holder.is_empty() {
        return false;
    }
    if name == holder {
        return true;
    }
    // Only an ACCOUNT reaches here: `account_of` returns the first
    // segment, which a compound holder never equals.
    account_of(name) == holder && name.len() > holder.len()
}

#[cfg(test)]
mod ownership_tests {
    use super::{account_of, owns_name};

    /// The consolidation, pinned. One class for account names, connection
    /// labels and agent ids — `[A-Za-z0-9_-]`.
    ///
    /// The `.` case is the one that matters: it was legal in an account
    /// name and illegal in an agent id, which made `first.last` an account
    /// that could not send a message. Narrowing was free (no account had
    /// one) and is the only direction that ends with one rule instead of a
    /// mapping between three.
    #[test]
    fn one_character_class_governs_every_name() {
        use super::valid_name_segment;
        assert!(valid_name_segment("owner"));
        assert!(valid_name_segment("my-laptop"));
        assert!(valid_name_segment("claude_s1"));

        assert!(!valid_name_segment("first.last"), "the dot is the consolidation");
        assert!(!valid_name_segment(""));
        assert!(!valid_name_segment("has space"));
        assert!(!valid_name_segment("sl/ash"));
        assert!(!valid_name_segment(&"a".repeat(129)));

        // The id rule is the same class, per segment — one definition,
        // not two that happen to agree.
        use crate::agent_messages::is_valid_id;
        assert!(is_valid_id("owner/laptop"));
        assert!(is_valid_id("host8/agent"));
        assert!(!is_valid_id("first.last"));
        assert!(!is_valid_id("owner/my.laptop"));
        assert!(!is_valid_id("/leading"));
        assert!(!is_valid_id("trailing/"));
        assert!(!is_valid_id("double//slash"));
    }

    #[test]
    fn an_account_name_may_not_look_like_a_connection() {
        use super::valid_account_name;
        assert!(valid_account_name("owner").is_ok());
        assert!(valid_account_name("owner_ops-1").is_ok());
        // The destructive case: this account's history would be filed
        // under `owner`, and if `owner` exists that is cross-account
        // attribution into a real account rather than a null.
        let err = valid_account_name("owner/ops").unwrap_err();
        assert!(err.contains("owner"), "the refusal should name where the history would have gone");
    }

    #[test]
    fn an_account_owns_itself_and_its_connections() {
        assert!(owns_name("alice", "alice"));
        assert!(owns_name("alice", "alice/laptop"));
        assert!(owns_name("alice", "alice/claude-s1"));
        // A different account, and a name that merely starts with the
        // same letters — `alicex` is not `alice`'s.
        assert!(!owns_name("alice", "other"));
        assert!(!owns_name("alice", "alicex"));
        assert!(!owns_name("alice", "alicex/session"));
        assert!(!owns_name("", "anything"));
    }

    /// The trap. A connection credential owns itself and NOTHING else
    /// under its own account. Because `routes::agents::Caller::may_read`
    /// is `owns(from) || owns(to)`, the naive symmetric rule would let one
    /// of a person's sessions both act as and READ THE MAIL OF every other
    /// session they have open.
    #[test]
    fn a_connection_owns_only_itself() {
        let me = "alice/laptop";
        assert!(owns_name(me, me));
        assert!(!owns_name(me, "alice/claude-s1"), "a session must not own its siblings");
        assert!(!owns_name(me, "alice"), "a session must not own the account that minted it");
        assert!(!owns_name(me, "alice/laptop/child"));
    }

    /// Attribution derives the account from a connection; authority never
    /// runs the other way. Both directions asserted together so the pair
    /// is read as one rule.
    #[test]
    fn attribution_derives_the_account_but_authority_does_not() {
        assert_eq!(account_of("alice/laptop"), "alice");
        assert_eq!(account_of("alice"), "alice");
        assert_eq!(account_of(""), "");
        // …and the reverse is refused:
        assert!(!owns_name("alice/laptop", "alice"));
    }
}

/// **Before adding a subject type whose `sub` is not a bare account name**
/// (the design's `<owner>/<connection>`, or anything like it): this
/// function returns `sub` VERBATIM, and what it returns is the storage
/// key. `usage.rs` resolves the row's owner with
/// `SELECT user_uuid FROM noo_users WHERE username = $5`, and memory and
/// KB audience scope off the same string.
///
/// So a compound subject does not merely scope narrowly — it matches no
/// account row at all, and attribution goes NULL without erroring. Five
/// sessions of one person become five people with no past, and nothing
/// in the logs says so. Verified against the tree 2026-09-13.
///
/// The account has to be recoverable from the credential (a prefix, or a
/// separate claim) and every storage-facing caller has to use THAT.
/// Routing, presence and ack state may key on the connection; anything
/// that accumulates into a person may not.
pub fn effective_user_id(authenticated: Option<&str>, claimed: Option<&str>) -> Option<String> {
    effective_user_id_raw(authenticated, claimed).map(|s| account_of(&s).to_string())
}

/// [`effective_user_id`] before the account derivation — the raw subject.
/// Private on purpose: a caller that wants the connection should say so by
/// reading the credential, not by reaching past the rule.
fn effective_user_id_raw(authenticated: Option<&str>, claimed: Option<&str>) -> Option<String> {
    let auth = authenticated.map(str::trim).filter(|s| !s.is_empty());
    let claimed = claimed.map(str::trim).filter(|s| !s.is_empty());
    match auth {
        Some(a) => {
            if let Some(c) = claimed {
                if c != a {
                    tracing::warn!(
                        authenticated = %a,
                        claimed = %c,
                        "ignoring client-supplied user_id that does not match the authenticated subject (possible impersonation)"
                    );
                }
            }
            Some(a.to_string())
        }
        None => claimed.map(|c| c.to_string()),
    }
}

/// Whose data a per-user read may touch.
///
/// `Ok(None)` means "every user" — the unscoped view. `Ok(Some(u))` means
/// exactly that user's rows.
///
/// - **Operator and above** may name any user, or none for the global view:
///   the dashboard and the CLI are operator tools.
/// - **User tier** is pinned to its own subject. Naming someone else is a
///   403 rather than a silent narrowing, so a caller is never quietly
///   handed the wrong person's data — and never anyone else's.
/// - **Internal cluster services** (no `RequesterCtx`) keep today's
///   behaviour: whatever they ask for. A **node** token is refused; it has
///   no business reading conversations.
///
/// This is the enforcement the retired `NOO_MULTI_USER` flag documented and
/// never implemented: before it, every one of these routes took the user id
/// straight from the path or query. It is unconditional, because a
/// single-user install has no User-tier accounts to narrow and a multi-user
/// one must not wait for a flag to isolate tenants.
pub fn scoped_user(
    requester: Option<&RequesterCtx>,
    cluster: Option<&ClusterNode>,
    requested: Option<&str>,
) -> Result<Option<String>, String> {
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    match requester {
        Some(r) if r.role >= Role::Operator => Ok(requested.map(str::to_string)),
        Some(r) => match requested {
            Some(w) if w != r.sub => Err(format!(
                "'{}' may only read their own data, not '{w}'",
                r.sub
            )),
            _ => Ok(Some(r.sub.clone())),
        },
        None => match cluster {
            Some(c) if !c.is_internal() => {
                Err(format!("node '{}' may not read user data", c.0))
            }
            _ => Ok(requested.map(str::to_string)),
        },
    }
}

/// [`scoped_user`] for a resource that accumulates to a PERSON, not a session
/// (jobs): the caller's ACCOUNT, `account_of(sub)`, instead of the raw `sub`.
///
/// A user-door token carries `sub = <user>/<label>` with a label per MCP
/// session (`mcp_external::mint_caller_jwt`); comparing the raw `sub` made a
/// job visible only to the one session that submitted it. Same rule as
/// everything else that belongs to a person ([`account_of`]).
/// `None` = Operator+ and internal services, exactly as [`scoped_user`].
/// [`scoped_user`] itself is unchanged: communication, memory, temporal, usage
/// and approval routes keep their own meaning.
pub fn scoped_account(
    requester: Option<&RequesterCtx>,
    cluster: Option<&ClusterNode>,
) -> Result<Option<String>, String> {
    Ok(scoped_user(requester, cluster, None)?.map(|s| account_of(&s).to_string()))
}

/// The account-management tier clamp.
///
/// One rule, used by every endpoint that names ANOTHER account — create,
/// password, disable/enable, erase, scopes, role, KB-role grant/revoke, org
/// assignment, channel links, and service keys bound to a user:
///
/// > A caller may manage an account whose **effective tier is strictly below
/// > its own**, plus itself. `Admin` is the exception: it manages every tier,
/// > including other Admins — somebody has to be able to reset an admin.
///
/// Concretely:
///
/// | caller | may manage |
/// |---|---|
/// | `Admin`    | everyone, including other Admins and itself |
/// | `Operator` | `User`-tier accounts, and itself |
/// | `User`     | only itself (self-service password, self keys) |
///
/// Before this existed, `Operator` and `Admin` were one privilege in
/// practice: the user-CRUD surface was `is_operator`-gated and passed the
/// requested scopes through, so an Operator could create an account with
/// `scopes: ["admin"]` (the `role` column is derived from scopes in
/// `repo::users::create`), reset any Admin's password, disable every Admin,
/// or bind a service key to an Admin and then act as them on `/mcp/user`
/// and `/v1/*`. The tier boundary was decorative.
///
/// Self is allowed here because refusing it would break self-service password
/// changes for an Operator. The *dangerous* self-mutations are refused by the
/// per-endpoint guards that already exist and are unchanged: you cannot
/// disable your own account, drop your own operator scope, or drop your own
/// admin role.
///
/// **Cluster-HMAC callers are not subject to this.** They carry no
/// [`RequesterCtx`] at all; the controller secret is a stack service's
/// credential (the CLI's own HMAC actors are refused at the middleware —
/// `--break-glass` is gone), and the secret is already root on the host
/// plane. Every JWT caller — which is what the CLI always sends, after
/// `noo auth login` — goes through the clamp.
pub fn may_manage(
    caller_role: Role,
    caller_sub: &str,
    target_role: Role,
    target_sub: &str,
) -> Result<(), String> {
    if caller_sub == target_sub && !caller_sub.is_empty() {
        return Ok(());
    }
    if caller_role >= Role::Admin {
        return Ok(());
    }
    if target_role < caller_role {
        return Ok(());
    }
    Err(format!(
        "'{caller_sub}' is {} and may only manage accounts below that tier; \
         '{target_sub}' is {} — an admin must make this change",
        caller_role.as_str(),
        target_role.as_str(),
    ))
}

/// The creation/promotion half of [`may_manage`]: may this caller hand out
/// `granted`?
///
/// Same rule with the self-escape removed, because there is no "self" when
/// the account does not exist yet (and a caller must never mint a peer or a
/// superior). `Admin` grants any tier; anyone else grants strictly below its
/// own — so `Operator` creates `User` accounts and nothing else.
///
/// `user_set_role` / `user_set_scopes` are already `Admin`-only
/// (`scope_mutation_guard`), so in practice this binds account CREATION and
/// the proposal-approval path, which both take a scope list verbatim.
pub fn may_grant_tier(caller_role: Role, granted: Role) -> Result<(), String> {
    if caller_role >= Role::Admin || granted < caller_role {
        return Ok(());
    }
    Err(format!(
        "a caller at tier '{}' may not create an account at tier '{}' \
         (accounts may only be created below the creator's own tier)",
        caller_role.as_str(),
        granted.as_str(),
    ))
}

/// JWT issuer/audience binding (H-A2). All gateway-issued JWTs carry these, and
/// verify_token requires them — so a token signed with the same secret for a
/// different service/purpose (no matching iss/aud) is rejected. Confinement no
/// longer rests only on the runtime scopes check.
pub const JWT_ISSUER: &str = "noo-gateway";
pub const JWT_AUDIENCE: &str = "noo-gateway";

/// True when the effective JWT secret cannot be trusted for auth: empty, or the
/// well-known development placeholder. Callers MUST refuse to accept bearer JWTs
/// in this state (fail-closed) rather than validate against a public secret.
pub fn jwt_secret_is_insecure(secret: &str) -> bool {
    secret.is_empty() || secret == INSECURE_DEFAULT_JWT_SECRET
}

/// Emit a single loud error the first time a JWT is presented while the secret
/// is unconfigured. Rate-limited to once per process so a probing client can't
/// flood the log.
/// Public wrapper so surfaces outside the middleware (`/auth/me`) emit the
/// same one-shot error when they refuse a token for the same reason.
pub fn warn_insecure_jwt() {
    warn_insecure_jwt_once();
}

fn warn_insecure_jwt_once() {
    static WARN: std::sync::Once = std::sync::Once::new();
    WARN.call_once(|| {
        tracing::error!(
            "NOO_JWT_SECRET is unset or the insecure default — bearer JWT auth is \
             DISABLED (fail-closed). Set NOO_JWT_SECRET to enable JWT/peer/WS auth."
        );
    });
}

// NOTE (config graduation): the `NOO_AUTH_DISABLE`
// dev bypass (`auth_disable_honored` / `auth_disable_active`) was removed
// entirely. Authentication is an invariant, not a knob — release AND debug
// builds are always fail-closed. For local dev, set NOO_JWT_SECRET and mint a
// token via the existing helpers (`create_token` / `noo auth`), same as prod.

/// Extract and verify JWT from Authorization header or query param.
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, String> {
    verify_token_with(token, secret, crate::jwks::signing_key())
}

/// [`verify_token`] with the signing key passed in rather than read from
/// the process.
///
/// Split out so the dual-accept rules can be tested for what they are —
/// a decision about which key answers for which algorithm — without an
/// env var or a `OnceLock` whose value the first test to run would fix
/// for every other. The env-reading wrapper above is the only caller in
/// production.
pub fn verify_token_with(
    token: &str,
    secret: &str,
    signing: Option<&crate::jwks::SigningKey>,
) -> Result<Claims, String> {
    // Pick the key from the token's OWN algorithm, and restrict the
    // validation to that one algorithm. This is what closes alg
    // confusion: with a public key published at the JWKS, a verifier that
    // chose its key any other way would accept an HS256 token signed with
    // that public key as the HMAC secret (`jwks::tests` executes the
    // attack). An ES256 token is never checked against the HMAC secret,
    // an HS256 token is never checked against the public key, and a token
    // claiming ES256 when no signing key is configured is REFUSED rather
    // than falling back to the secret.
    let header = jsonwebtoken::decode_header(token).map_err(|e| format!("Invalid token: {e}"))?;
    let (key, alg) = match header.alg {
        Algorithm::ES256 => match signing {
            // `kid` is REQUIRED to match, not merely informational.
            //
            // With one key it changes nothing — a wrong `kid` would fail
            // on the signature anyway. It exists for the rotation this
            // JWKS is published to make possible: with two keys live, a
            // verifier that ignores `kid` either holds one key or tries
            // them all, and trying them all is how a key you revoked
            // keeps working. Enforcing it while there is one key means
            // whoever adds the second has to extend the lookup here on
            // purpose — the compiler and this check both point at the
            // place — rather than discovering at 3am that retirement did
            // nothing.
            Some(k) => match header.kid.as_deref() {
                Some(kid) if kid == k.kid => (k.decoding.clone(), Algorithm::ES256),
                Some(kid) => {
                    return Err(format!(
                        "Invalid token: kid '{kid}' is not a key this gateway signs with"
                    ))
                }
                None => return Err("Invalid token: ES256 without a kid".into()),
            },
            None => return Err("Invalid token: ES256 presented but no signing key is configured".into()),
        },
        Algorithm::HS256 => (DecodingKey::from_secret(secret.as_bytes()), Algorithm::HS256),
        other => return Err(format!("Invalid token: unsupported algorithm {other:?}")),
    };
    let mut validation = Validation::new(alg);
    validation.validate_exp = true;
    // Bind tokens to this gateway (H-A2): the JWT must carry iss=JWT_ISSUER and
    // aud=JWT_AUDIENCE. set_issuer/set_audience only check the VALUE when the
    // claim is present, so mark iss+aud REQUIRED — otherwise a token with no
    // iss/aud (a pre-H-A2 token, or one minted for another service) would slip
    // through. NOTE: this invalidates any JWT issued before this change — users
    // re-authenticate once.
    validation.required_spec_claims.insert("iss".to_string());
    validation.required_spec_claims.insert("aud".to_string());
    validation.set_issuer(&[JWT_ISSUER]);
    validation.set_audience(&[JWT_AUDIENCE]);
    validation.validate_aud = true;

    decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| format!("Invalid token: {e}"))
}

/// The one route prefix that upgrades to a WebSocket. Everything the gateway
/// serves over WS lives under it: `/ws/coordinator`, `/ws/collab` and
/// `/ws/agent` natively (`routes::websocket::router`), plus the not-yet-ported
/// `/ws/companion/{node_id}`, `/ws/terminal/{session_id}` and bare `/ws`, which
/// reach the Python gateway through the catch-all. A prefix rather than an
/// enumerated list because the unported three are registered nowhere in Rust —
/// an exact list would silently stop authenticating them.
pub(crate) const WS_PATH_PREFIX: &str = "/ws";

/// Is this path on the WebSocket surface? `/ws` itself, or anything below it.
/// Deliberately NOT `starts_with("/ws")`, which would also match `/wsdl` or a
/// future `/wsapi`.
fn is_ws_path(path: &str) -> bool {
    path == WS_PATH_PREFIX || path.starts_with("/ws/")
}

/// Does the request carry a real WebSocket handshake header? RFC 6455 requires
/// `Upgrade: websocket` on every browser and library handshake, so this is not
/// a heuristic. Token-list aware (`Upgrade: websocket, foo`) and
/// case-insensitive, because the header is both by spec.
fn has_websocket_upgrade_header(request: &Request) -> bool {
    request
        .headers()
        .get_all(header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
}

/// The WebSocket routes whose HANDLER verifies the token itself and answers
/// a bad one by completing the upgrade and closing with code 4401
/// (`ws_coordinator.rs`, `ws_collab.rs`, `ws_agent.rs`). A real handshake to
/// one of these is passed through where this middleware would otherwise
/// answer 401: an HTTP 401 on an upgrade reaches the browser as close code
/// 1006, indistinguishable from a network drop, so a console tab whose
/// session had lapsed retried every 30 s for hours with an expired JWT in
/// the URL. Enumerated, not a prefix — any other `/ws/*` path
/// keeps the 401, because nothing behind it is known to verify.
pub(crate) const HANDLER_VERIFIED_WS_ROUTES: &[&str] =
    &["/ws/coordinator", "/ws/collab", "/ws/agent"];

/// A genuine handshake to a route in [`HANDLER_VERIFIED_WS_ROUTES`].
fn defers_to_ws_handler(request: &Request) -> bool {
    (HANDLER_VERIFIED_WS_ROUTES.contains(&request.uri().path())
        // An add-on socket handshake carrying a single-use `ticket=`: the
        // handler (`addon_ws::serve_ws`) redeems it and answers 401 when it
        // does not redeem. Only reached when no bearer was presented.
        || crate::addon_ws::is_ticket_handshake(request.uri().path(), request.uri().query()))
        && has_websocket_upgrade_header(request)
}

/// May this request carry its JWT in `?token=`?
///
/// **Both** conditions, not either. The old rule was
/// path-OR-header, so *any* request on *any* path that carried an
/// `Upgrade: websocket` header could hand its JWT over in the query string —
/// `POST /api/config?token=<jwt>` with a stray upgrade header authenticated,
/// and the JWT landed in every access log between the client and here
/// (`tailscale serve`, any reverse proxy) and in browser history. The header
/// is free for a client to set; the path is not.
///
/// Requiring the header as well as the path costs nothing: a handshake that
/// omits it is not a WebSocket and would be refused by the upgrade extractor
/// three layers down anyway.
fn query_token_allowed(request: &Request) -> bool {
    // Add-on sockets take a single-use ticket instead (`addon_ws`): a bearer
    // in an add-on socket URL is never a credential.
    is_ws_path(request.uri().path())
        && !request.uri().path().starts_with(ADDON_WS_PREFIX)
        && has_websocket_upgrade_header(request)
}

/// Every add-on WebSocket route lives under here (`addon_proxy::ws_prefix`).
const ADDON_WS_PREFIX: &str = "/ws/addons/";

/// The `token` query parameter, if present.
fn query_param_token(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|p| p.strip_prefix("token=").map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}

/// Warn once per path that a `?token=` was ignored — a JWT reached a log it
/// should not have, and the operator (or whoever wrote the client) needs to
/// know the credential is now burnt, even though the request itself is not
/// refused. Per-path rather than per-request so a polling client cannot turn
/// this into its own log flood, and bounded so a scanner walking distinct
/// paths cannot grow the set without limit.
fn warn_query_token_ignored(path: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match seen.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned — still warn, never brick auth
    };
    // Cap: past this, new paths go unwarned rather than unbounded. 256 distinct
    // paths is already far more than this ever wants to be.
    if guard.len() >= 256 || !guard.insert(path.to_string()) {
        return;
    }
    drop(guard);
    tracing::warn!(
        target: "security",
        path = %path,
        "ignored a ?token= query parameter on a request that is not a WebSocket \
         handshake. The request was NOT refused, but the token \
         is in the query string and therefore in every access log on the way \
         here — treat it as disclosed and rotate. Send credentials in the \
         Authorization header; ?token= is accepted only on a real /ws/* upgrade."
    );
}

/// Extract a bearer token from a request. The `Authorization: Bearer` header is
/// always honored; the `?token=` query param is honored ONLY on a genuine
/// WebSocket handshake to a `/ws/*` route.
/// Restricting the query fallback keeps JWTs out of HTTP
/// access/proxy/browser-history logs on every non-WS route.
///
/// A stray `?token=` elsewhere is IGNORED, not an error: a query parameter must
/// never be able to break an otherwise well-formed request. It is warned about
/// instead — see [`warn_query_token_ignored`].
fn bearer_token(request: &Request) -> Option<String> {
    if let Some(t) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(t.to_string());
    }
    let token = request.uri().query().and_then(query_param_token)?;
    if query_token_allowed(request) {
        return Some(token);
    }
    warn_query_token_ignored(request.uri().path());
    None
}

// `require_auth` was DELETED. It passed every request
// through when the JWT secret was unset or still the default — the exact
// fail-open `require_any_auth` was written to replace. It was registered
// nowhere, so it changed nothing at runtime; it was one `.layer()` away
// from silently reinstating the bypass. Use `require_any_auth`.

// `verify_cluster_hmac` was DELETED for the same reason as `require_auth`
// above: registered nowhere, and strictly weaker than the thing that IS
// registered. It verified a raw-payload HMAC with no actor, no timestamp and
// no replay window, while the live path — `verify_cluster_token_inner` below
// — binds `<actor>:<ts>`, enforces a 300s freshness window, and rejects any
// signature that is not exactly 32 or 64 hex chars (the check that closed the
// CRIT-1 empty-prefix bypass). A future caller reaching for the shorter,
// friendlier-looking name would have silently opted out of all three.

/// Verify an HMAC time-bearer token of the form `<actor>:<ts>:<hmac32>`,
/// the same format produced by `routes::cluster::mint_cluster_token`.
/// Rejects tokens older than `MAX_TOKEN_AGE_SECS` to bound replay window.
///
/// This lets cluster-internal callers authenticate without a JWT —
/// they sign with the shared `NOO_CLUSTER_SECRET` instead of the
/// gateway's per-user JWT secret.
/// The node identity a cluster token asserts, IF the token verifies.
///
/// `verify_cluster_token` answers "is this a valid cluster token" and throws
/// the subject away. That was fine while every cluster-token caller was
/// equally privileged — but the token format has always been
/// `<actor>:<ts>:<hmac>`, so the caller's identity is signed and simply was
/// not being read.
///
/// Returning it lets a handler ask the question that matters for per-node
/// endpoints: not "is this a node?" but "is this THAT node?". Without it,
/// `/api/cluster/nodes/{id}/desired-config` served any node's configuration to
/// any holder of the (currently fleet-wide) secret — see the design
///
/// Verification is unchanged and shared: this calls the same inner routine, so
/// the two cannot drift on signature width, clock skew, or the CRIT-1
/// empty-signature bypass.
pub fn cluster_token_subject(token: &str) -> Option<String> {
    if !verify_cluster_token(token) {
        return None;
    }
    // Verified above, so the split is guaranteed to yield three parts.
    token.split(':').next().map(str::to_string)
}

pub fn verify_cluster_token(token: &str) -> bool {
    let Some(secret) = crate::config::secret_env::secret_opt("NOO_CLUSTER_SECRET") else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_cluster_token_inner(token, &secret, now)
}

/// Seconds between a refused v1 token's timestamp and now (signed: a
/// negative age is a caller clock ahead of this one). `None` when the token
/// does not parse.
fn v1_token_age_secs(token: &str) -> Option<i64> {
    let ts: i64 = token.split(':').nth(1)?.parse().ok()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(now - ts)
}

/// Replay window; matches the node-agent generator's 5-minute freshness.
const CLUSTER_MAX_TOKEN_AGE_SECS: u64 = 300;

/// Pure core of `verify_cluster_token`: no env / no wall-clock, so it is
/// deterministically testable. `now` is the current unix time in seconds.
pub(crate) fn verify_cluster_token_inner(token: &str, secret: &str, now: u64) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    if secret.is_empty() {
        return false;
    }

    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }
    let (actor, ts_str, sig_hex) = (parts[0], parts[1], parts[2]);

    let Ok(ts) = ts_str.parse::<u64>() else {
        return false;
    };
    // Symmetric clock-skew check (matches Go side's time.Since(ts).Abs()).
    let age = now.abs_diff(ts);
    if age > CLUSTER_MAX_TOKEN_AGE_SECS {
        return false;
    }

    // Compute the full 64-hex-char HMAC and constant-time compare against
    // the presented signature. ONE width is valid: the full 64 hex that every
    // generator emits (routes/cluster.rs mint_cluster_token, noo-cli auth.rs,
    // the Go node-agent's CreateClusterToken, Python create_cluster_token).
    // The 32-char truncated prefix was accepted for one release after the
    // last truncating minter was fixed and is now REFUSED
    // like any other length — including empty or a short prefix, which is
    // what closes the CRIT-1 bypass (the old `starts_with("")` was always
    // true, letting `actor:<now>:` authenticate with no secret at all).
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(format!("{actor}:{ts}").as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes()); // 64 hex chars
    sig_hex.len() == expected.len() && ct_eq(sig_hex.as_bytes(), expected.as_bytes())
}

/// Constant-time byte-slice equality. Returns false on length mismatch
/// (callers must length-check first if that must also be constant-time; here
/// both operands are fixed 32-byte hex prefixes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Path prefixes that are intentionally public (bypass `require_any_auth`).
///
/// - `/health`, `/metrics`: infra endpoints scraped without credentials.
/// - `/static/`: dashboard assets (HTML/JS/CSS); the dashboard's own
///   JWT-in-localStorage flow gates the API calls it makes.
/// - `/auth/`, `/api/auth/`: login/refresh/logout endpoints — must be
///   reachable BEFORE the user has a token (otherwise login is impossible).
/// There are NO webhook entries here any more. `/api/heartbeat/webhook/`
/// used to be one, documented as carrying a "per-task webhook secret,
/// verified inside the handler" — that control DID NOT EXIST. The handler
/// delegated straight to `heartbeat_run_task` with no check, so any caller
/// who could reach the gateway could execute any heartbeat task by id, and
/// the ids are guessable (`daily_log`, `graph_prune`, `cluster_health`).
/// The route is deleted; `/api/heartbeat/tasks/{id}/run` does the same thing
/// behind auth.
///
/// Channel webhooks used to be here too. They are gone: the inbound channel
/// transports are Telegram long-polling and Google Chat Pub/Sub pull, both
/// outbound-initiated, so no channel needs a publicly reachable endpoint.
/// Removing them removes the auth bypass with them — a bypass is a standing
/// liability even when the handler behind it verifies a signature, and the
/// deleted route took ZERO requests in the 24h before it was removed.
pub const PUBLIC_PATH_PREFIXES: &[&str] = &[
    // NOTE: `/health` is NOT here. It was, as a PREFIX, which made every
    // future `/health...` route public by accident — the same trap the
    // `/metrics` note below describes. It is now in
    // CREDENTIAL_OPTIONAL_PATHS: reachable with no credential, and
    // answering a SMALLER body to a caller that presents none.
    // NOTE: `/metrics` is NOT here. It is an EXACT public path below.
    // A prefix entry made every future `/metrics...` route public by
    // accident — `/metrics/raw`, `/metrics-admin`, anything — and the
    // gateway's metrics already carry more than a liveness bit
    // (noo_auth_failures_5m, noo_exec_denials_5m, conversations_total,
    // and every node id with its tier and VRAM). One route is public
    // because Prometheus needs it; its neighbours are not.
    "/assets/", // versioned mesh-UI artifact assets — same trust class as /static/
    "/auth/",
    "/api/auth/",
    "/.well-known/", // A2A AgentCard — discovery before authentication
    // NOTE: "/bootstrap/bundle/" used to be here. It is now in
    // PUBLIC_GET_PATH_PREFIXES — read-only — so the `…/applied` POST falls
    // through to the node rail. See that list.
    // CLI release assets mirrored by the controller (the design rail work,
    // 35 slice B): public RELEASE binaries plus the release-signed
    // sha256sums manifest — a node's `noo upgrade` holds no credential
    // and verifies everything it installs against the key baked into the
    // binary. Uploading (PUT /api/cluster/cli-asset/…) stays authenticated.
    // Found live 2026-09-03: without this every node fell through to
    // GitHub while the controller mirror answered 401.
    "/bootstrap/cli/",
];

/// Path prefixes that are public for **safe methods only** (GET/HEAD/OPTIONS).
///
/// The distinction exists because. `/bootstrap/bundle/`
/// was a method-agnostic public prefix, which made three routes anonymous, not
/// one:
///
/// | route | what it does | wants auth? |
/// |---|---|---|
/// | `GET /bootstrap/bundle/{node}` | serves CMS ciphertext encrypted to the node's birth key | no — see below |
/// | `POST /bootstrap/bundle/{node}/applied` | WRITES `applied_at`/`apply_rc`/`apply_msg` and audits as `node:<name>` | **yes** |
///
/// The GET genuinely cannot be authenticated with the fleet credential: at
/// that moment the node holds only its birth key and the CA anchor, and
/// `NOO_CLUSTER_SECRET` is delivered *inside* the bundle it is fetching
/// (`noo-cli/src/commands/provision.rs` renders it into the `agent-env`
/// member). What a stranger gets is ciphertext they cannot decrypt, and
/// authenticity is the CA signature `noo-apply` verifies after decryption.
///
/// The POST is a different story: by the time a node reports a full-bundle
/// apply it HAS the secret (`/etc/noo-node-agent.env`, root 0600), and the
/// route was already on the node allow-list (`NODE_ROUTES`) — it simply
/// never reached the check. It does now.
///
/// Keep this list tiny. A prefix here is still a hole for reads.
pub const PUBLIC_GET_PATH_PREFIXES: &[&str] = &["/bootstrap/bundle/"];

/// Routes that carry their OWN credential, checked inside the handler, and so
/// must not be turned away by this middleware first.
///
/// There is exactly one credential this covers: a node's **birth key**. On the
/// provisioning pull lane the node has no fleet secret —
/// `NOO_CLUSTER_SECRET` is rendered into the `agent-env` member of the very
/// bundle it is fetching — so `require_any_auth` has nothing to check and 401s
/// a legitimate node. The birth key is the one thing it does hold
/// (`/etc/noo/birth.key`, written at enrollment; the controller kept the cert
/// in `noo_bootstrap_tokens.birth_cert`), and `birth_proof.rs` verifies a
/// signature over `(purpose, node, bundle_sha, ts)` against it.
///
/// **This is not a public list.** Every entry here is a route whose handler
/// refuses on a bad or absent credential; passing the middleware buys nothing
/// but the chance to be checked. The two routes are:
///
/// | route | who it is for |
/// |---|---|
/// | `POST …/fetched` | the node's signed receipt — the only thing that stamps `fetched_at` |
/// | `POST …/applied` | the apply report, recorded only with a verified birth-key proof (the fleet bearer alone is refused) |
///
/// `…/applied` is here for the two legitimate 401s #95 recorded and accepted:
/// the first-phase applier-only bundle, and a failed apply on a
/// never-provisioned host. Both run before the node has a fleet secret and both
/// hold the birth key. The handler refuses everything but a verified proof, so
/// the hole #95 closed stays closed.
///
/// The middleware steps aside for these ONLY when the request carries no
/// bearer at all — there is then nothing for it to check. A request that does
/// present one is authenticated normally, so the apply report keeps its
/// fleet-HMAC lane and a bad token is still a 401 before the handler.
///
/// Matched as `<prefix><one non-empty segment><suffix>` — never as a bare
/// prefix, which would re-open every neighbour the way `/metrics` once did.
pub const HANDLER_AUTHENTICATED_PATHS: &[(&str, &str)] = &[
    ("/bootstrap/bundle/", "/fetched"),
    ("/bootstrap/bundle/", "/applied"),
    // Kiosk SEATS (i77): the seat's whole rail. A seat holds its birth key
    // and nothing else — never a fleet secret, never a JWT — so these are the
    // only routes it can call, and each handler (`routes/seats.rs`) refuses
    // anything but a `noo-seat-*` proof that verifies against the cert in
    // `noo_seats`. A node's proof, or a node's fleet token, buys nothing here.
    ("/bootstrap/seat/", "/bundle"),
    ("/bootstrap/seat/", "/fetched"),
    ("/bootstrap/seat/", "/applied"),
    ("/bootstrap/seat/", "/heartbeat"),
];

/// Paths that answer WITHOUT a credential, and answer MORE with one.
///
/// The middleware steps aside only when the request carries no bearer at
/// all — the same rule as [`HANDLER_AUTHENTICATED_PATHS`], for a different
/// reason. A request that does present one is authenticated normally, so
/// the handler can see who is asking and a bad token is a 401 rather than
/// a silent downgrade to the anonymous answer.
///
/// `/health` is here because every probe that gates a deploy or a rollback
/// reads only the status code and holds no credential — the container
/// healthcheck, the compose healthcheck, the host watchdog, the hostd
/// recreate gate — while the body it used to hand those same anonymous
/// callers carried the gateway version, the engine, the live peer count
/// and the dependency map. Liveness is public; the inventory is not.
pub const CREDENTIAL_OPTIONAL_PATHS: &[&str] = &["/health"];

/// Whether `path` answers anonymously but says more to a credential.
pub fn is_credential_optional(path: &str) -> bool {
    CREDENTIAL_OPTIONAL_PATHS.contains(&path)
}

/// The middleware's first decision, as a pure function: does this request go
/// to its handler WITHOUT the middleware checking a credential?
///
/// True for the public lists, and for the handler-authenticated and
/// credential-optional paths when the caller presents no bearer at all (see
/// those lists). Everything else needs a credential the middleware itself
/// verifies — which is what a kiosk SEAT never holds: a seat has a birth key
/// and nothing else, so a route that is not here is a 401 for it before any
/// handler runs (`seat_cannot_reach_node_routes`).
pub fn passes_without_bearer_check(path: &str, safe_method: bool, has_bearer: bool) -> bool {
    PUBLIC_PATHS_EXACT.contains(&path)
        || PUBLIC_PATH_PREFIXES.iter().any(|p| path.starts_with(p))
        || (safe_method && PUBLIC_GET_PATH_PREFIXES.iter().any(|p| path.starts_with(p)))
        // Not public: these carry a birth-key proof the HANDLER verifies,
        // because the node holds no fleet credential yet — and ONLY when the
        // caller presents nothing for this middleware to check. A request that
        // DOES carry a bearer goes down the normal path, so the apply report's
        // existing fleet-HMAC lane still attaches its ClusterNode extension and
        // a bad token is still a 401 here rather than a maybe in the handler.
        // See HANDLER_AUTHENTICATED_PATHS.
        || (is_handler_authenticated(path) && !has_bearer)
        // Anonymous is allowed and gets the smaller answer; a bearer is
        // checked like anywhere else, so the handler knows who is asking.
        || (is_credential_optional(path) && !has_bearer)
}

/// Whether `path` is one of [`HANDLER_AUTHENTICATED_PATHS`].
pub fn is_handler_authenticated(path: &str) -> bool {
    HANDLER_AUTHENTICATED_PATHS.iter().any(|(prefix, suffix)| {
        let Some(rest) = path.strip_prefix(prefix) else { return false };
        let Some(seg) = rest.strip_suffix(suffix) else { return false };
        // Exactly one path segment between the two — `/a/b/fetched` is not a
        // node named "a/b".
        !seg.is_empty() && !seg.contains('/')
    })
}

/// Paths that are intentionally public on EXACT match (not prefix).
///
/// `/` cannot be in `PUBLIC_PATH_PREFIXES` because every URL starts with
/// `/`, so prefix-match would let everything through. Same for the
/// dashboard shell URLs that don't have a trailing slash.
pub const PUBLIC_PATHS_EXACT: &[&str] = &[
    // The PUBLIC half of the API spec — the ~31 endpoints reachable without a
    // credential, derived from these very lists by
    // `scripts/gen-public-openapi.py`. An OAuth client reading
    // `/.well-known/oauth-authorization-server`, an A2A peer reading
    // `agent.json`, or a node part-way through enrolling has no credential by
    // construction and still needs the shape of what it may call.
    //
    // The FULL spec is not here. `/static/` was a public PREFIX until
    // 2026-09-19, which made `/static/openapi.json` — every route the gateway
    // serves, with parameters and descriptions — readable by anything that
    // could reach the port. Not a breach, since each of those routes
    // authenticates, but a complete inventory of the surface handed to every
    // node, device and tailnet member for free. It is served
    // authenticated now, at `GET /api/docs/openapi`.
    "/static/openapi.public.json",
    "/",            // dashboard root HTML shell
    // `/metrics` is NOT here (2026-09-25 B). It was public
    // because the scraper had no credential the gateway checked; with
    // mTLS enforced (the default; `NOO_MTLS_GATEWAY=false` opts out) the gateway reads the
    // scraper's service leaf, so the scrape authenticates by certificate and
    // everyone else by an Operator-or-Admin login — see METRICS_READ_PATHS.
    "/dashboard",   // alias for /
    // The kiosk page. A top-level navigation cannot carry
    // an Authorization header and the bundle is not the secret: the page
    // holds nothing until the host launcher injects a kiosk token, and
    // every `/api/*` call it then makes is authenticated as usual. Exact
    // paths — `/kiosk.html/anything` is not public.
    "/kiosk",
    "/kiosk.html",
    "/favicon.ico", // browser auto-fetched
    "/docs",        // human-readable API docs
    // Bootstrap-token enrollment. (`/bootstrap-node.sh`, the
    // retired pre-token lane, was listed here until 2026-09-27.) Public
    // because the enrolling host has no credential of ANY kind
    // yet — no JWT, no cluster secret, no cert. (`/bootstrap`, the shell
    // enrollment script, was retired and is not listed.)
    // `/api/cluster/bootstrap` authenticates FULLY on its
    // own inside the handler: the single-use token in the body (256 bits of
    // entropy, sha256-verified against noo_bootstrap_tokens, expiry + revoke
    // + optional CIDR checks, uniform 403 on any failure). Exact paths, not
    // prefixes: nothing else under /api/cluster/ is self-authenticating.
    // Tailnet-native enrollment: public for the same
    // reason as /api/cluster/bootstrap — the caller has no credential yet.
    // It authenticates FULLY in-handler, and NOT via anything the caller
    // asserts: the controller self-agent (host-side, next to tailscaled)
    // whois-checks the claimed tailnet address for the required tag AND
    // dials back to it to fetch a caller-published nonce — WireGuard
    // routing means only the address's true owner can answer. Forwarded
    // headers are never consulted (spoofable through the docker SNAT path).
    "/api/cluster/enroll-tailnet",
    // The KEYLESS kiosk mint — the same admission as enroll-tailnet, for
    // the same reason, applied to a display instead of a node. A display
    // that stores no durable secret has nothing to present, so the route
    // must be reachable anonymously; it then proves the caller IS the
    // tagged tailnet device before minting anything. Exact path: nothing
    // else under /api/kiosk/ is self-authenticating. (/api/kiosk/token, the
    // retired KEY lane, is neither public nor routed.)
    "/api/kiosk/token/tailnet",
    // The ROOT host-prep phase: an inert shell script, fetched by
    // `noo enroll` and run under the operator's attended sudo. Serving it
    // publicly discloses nothing the repo does not.
    "/bootstrap/prep",
    "/bootstrap/apply",
    "/bootstrap/deenroll",
    "/bootstrap/fetch",
    // The cluster CA CERTIFICATE (public half): the trust anchor a fresh
    // node fetches during token-authenticated enrollment, before any signed
    // bundle can verify. Certificates are public by construction.
    "/bootstrap/ca.crt",
    "/api/cluster/bootstrap",
    // Kiosk SEAT enrolment (i77): public for the reason the node redemption
    // above is — the seat holds nothing yet. It authenticates FULLY in the
    // handler on the single-use seat token in the body (`noo_seat_tokens`,
    // its own table, so a node's bootstrap token never redeems here and a
    // seat token never redeems at `/api/cluster/bootstrap`), uniform 403 on
    // any failure. What it returns carries no credential of any kind.
    "/api/cluster/seat-enroll",
    // External MCP door. NOT unauthenticated — it authenticates FULLY on its
    // own (`mcp_external::authenticate`): bearer required, must resolve to an
    // active `noo_service_keys` row, must carry the `mcp` scope, and must be
    // bound to a non-disabled `noo_users` account. It is listed here because
    // its credential is a service key, which this middleware only resolves on
    // the inference surface (`/v1/*`, `/api/external/*`) — routing it through
    // here would 401 every valid MCP client before the door ever saw it.
    // Exact paths, not a prefix: nothing else under /mcp/ is
    // self-authenticating. `/mcp/user` says what the door does — the caller
    // acts AS a user account. Its original alias `/mcp/external` was
    // removed in stack-v0.2.40; a stale client now gets the router's 404
    // instead of a self-authenticating path that quietly kept working.
    "/mcp/user",
    // The OPERATOR door served over the gateway's own TLS. Also
    // self-authenticating (`mcp_local`): an `mcp:operator` service key bound
    // to an admin, mandatory — for the same reason as /mcp/user, this
    // middleware only resolves service keys on the inference surface. (The
    // shared NOO_MCP_TOKEN bearer was retired on 2026-09-30.)
    "/mcp/operator",
];

/// Chat + query surface: paths where read-scope users may also use mutating
/// methods (POST/PUT/DELETE). This is conversational use of the assistant —
/// chatting, querying knowledge, uploading attachments — as opposed to the
/// operational control plane (cluster/jobs/scheduler/config), which requires
/// the `write` or `admin` scope to mutate. See `scope_allows`.
pub const CHAT_QUERY_PREFIXES: &[&str] = &[
    // "/chat" was here until PR #316 deleted the route. A
    // prefix naming a path the router does not serve reads as a live
    // permission and grants nothing; every other entry below resolves to
    // a registered route.
    "/api/inference",   // also covers /api/inference/stream
    "/api/conversations",
    "/api/voice/",
    "/upload",
    "/api/v1/rag/query",
    "/api/memory/search",
    "/api/v1/graph/entities/resolve",
    "/tools/select",
];

/// Paths a caller holding the `ingest` scope may POST to, on top of the
/// read tier. One entry on purpose: this is a scope for CONTRIBUTING
/// documents, not a junior operator tier. Everything a widened list would
/// reach (config, cluster, users) is what `write` already means, and `write`
/// is the thing callers are trying to avoid needing.
///
/// The audience tags an ingested document lands with are NOT decided here —
/// `workers/rag.py::_rag_ingest` clamps them to the caller's own audience, so
/// holding `ingest` cannot write into `system` or another user's tier.
pub const INGEST_PREFIXES: &[&str] = &["/api/v1/docs/ingest"];

/// The six graph query routes a User holding the `graph` scope may POST to
/// (the user-door `noo_graph_*` tools). EXACT paths, never a prefix: the rest
/// of `/api/v1/graph/*` (recluster, entity-cleanup, extract-relations, prune
/// and restore) mutates or reads installation-wide and stays `write`.
///
/// A plain `read` account is refused all of these on purpose
/// "read-only accounts do NOT get the graph query routes"; `graph` is the
/// per-account grant that lifts that for exactly these six. Every result is
/// audience-scoped to what the caller may read: the gateway resolves the
/// caller's audience (`memory::scope`), `workers/graph.py` scopes the query
/// in SQL and sanitises edge evidence, and `graph_reply` fails closed (503)
/// if the reply does not carry the `audience_filtered` stamp.
pub const GRAPH_QUERY_PATHS: &[&str] = &[
    "/api/v1/graph/classify-intent",
    "/api/v1/graph/explain-path",
    "/api/v1/graph/navigate",
    "/api/v1/graph/search-clusters",
    "/api/v1/graph/semantic-search",
    "/api/v1/graph/traverse",
];

/// Control scopes: what an add-on's key may be granted beyond inference, and
/// exactly which writes each one opens (and, for the read scopes in
/// `CONTROL_READ_SCOPE_ROUTES`, which aggregate reads).
///
/// The gateway owns this vocabulary; an add-on only picks from it. A new
/// add-on that needs a control-plane write asks for a scope at provisioning
/// (`noo security service-key provision <addon>`), and the operator grants
/// it there. It never needs its own branch in this middleware. That is the
/// point: until 2026-09-24 evolve did all of this on the shared cluster HMAC,
/// a full-access credential nothing could attribute or revoke on its own
/// and the first per-consumer fix opened only the temporal
/// write, which left the other five routes evolve calls refusing its token.
///
/// Additive like `ingest`: a caller without these scopes is unaffected, and
/// none is ever a default (`routes::users::SERVICE_KEY_SCOPES`). Path
/// patterns match segment by segment; `*` is exactly one non-empty segment.
pub const TEMPORAL_SCOPE: &str = "temporal";
pub const HEARTBEAT_SCOPE: &str = "heartbeat";
pub const ACTIVITIES_SCOPE: &str = "activities";
pub const CHANNELS_SEND_SCOPE: &str = "channels:send";
pub const METRICS_SCOPE: &str = "metrics";
pub const CONVERSATION_STATS_SCOPE: &str = "conversation_stats";
/// The prompt-skill store's write side: create, rewrite, retire and score an
/// EVOLVED skill. Evolve decides what a skill should say; the gateway holds
/// the store, so evolve writes through these four rows. Core skills are
/// refused by the handlers regardless of who holds the scope.
pub const PROMPT_SKILLS_WRITE_SCOPE: &str = "prompt_skills:write";
/// Speech-to-text for a SERVICE: the two transcribe routes. A person needs no
/// scope (`/api/voice/` is on the chat/query surface); a service key does,
/// and unlike every other control scope it is also accepted AS THE KEY, on
/// exactly these two routes (`DIRECT_KEY_SCOPES`). trellion's audio ingest
/// (`POST /api/voice/transcribe/detailed`) presents its own key.
pub const VOICE_TRANSCRIBE_SCOPE: &str = "voice:transcribe";
pub const CONTROL_SCOPE_ROUTES: &[(&str, &str, &str)] = &[
    (TEMPORAL_SCOPE, "POST", "/api/temporal/adaptations"),
    (HEARTBEAT_SCOPE, "POST", "/api/heartbeat/tasks/*/run"),
    (HEARTBEAT_SCOPE, "PUT", "/api/heartbeat/tasks/*/toggle"),
    (ACTIVITIES_SCOPE, "POST", "/api/activities"),
    (CHANNELS_SEND_SCOPE, "POST", "/api/channels/send"),
    (METRICS_SCOPE, "POST", "/api/metrics/increment"),
    (METRICS_SCOPE, "POST", "/api/metrics/gauge"),
    (PROMPT_SKILLS_WRITE_SCOPE, "POST", "/api/prompt-skills"),
    (PROMPT_SKILLS_WRITE_SCOPE, "PUT", "/api/prompt-skills/*"),
    (PROMPT_SKILLS_WRITE_SCOPE, "POST", "/api/prompt-skills/*/retire"),
    (PROMPT_SKILLS_WRITE_SCOPE, "POST", "/api/prompt-skills/*/fitness"),
    (VOICE_TRANSCRIBE_SCOPE, "POST", "/api/voice/transcribe"),
    (VOICE_TRANSCRIBE_SCOPE, "POST", "/api/voice/transcribe/detailed"),
];

/// The control scopes whose routes a service key may call DIRECTLY, with the
/// key itself as the bearer. Every other control scope is exercised by an
/// exchanged add-on token (the key is only accepted on the inference surface
/// and the exchange doors), so this list is deliberately short and each word
/// in it is a decision: the routes it opens come from the same
/// `CONTROL_SCOPE_ROUTES` rows, and a key WITHOUT the word is refused with the
/// inference surface's scope-refusal body. No "any service key" path exists.
pub const DIRECT_KEY_SCOPES: &[&str] = &[VOICE_TRANSCRIBE_SCOPE];

/// The scope a raw service key must hold for `method path`, if that route is a
/// direct-key door. Pure, so the mapping is pinned without a database.
pub fn direct_key_scope_for(path: &str, method: &axum::http::Method) -> Option<&'static str> {
    CONTROL_SCOPE_ROUTES
        .iter()
        .find(|(s, m, p)| DIRECT_KEY_SCOPES.contains(s) && method.as_str() == *m && path_matches(p, path))
        .map(|(s, _, _)| *s)
}

/// What a direct-key door decides about a resolved bearer.
pub enum DirectKey {
    /// Not a service key: fall through to the 401 every other bearer gets.
    NotAKey,
    /// A service key without the scope: 403, same body as the inference
    /// surface's `service key lacks '<scope>' scope`.
    Forbidden(Response),
    /// A service key holding the scope.
    Admit(Consumer),
}

/// Pure decision for a direct-key door (the lookup and quota stay in the
/// middleware).
pub fn direct_key_admission(found: Option<Consumer>, required: &str) -> DirectKey {
    let Some(consumer) = found else { return DirectKey::NotAKey };
    if !consumer.has_scope(required) {
        tracing::warn!(consumer = %consumer.name, scope = %required, "service key refused: lacks the scope this route needs");
        return DirectKey::Forbidden(direct_key_forbidden(required));
    }
    DirectKey::Admit(consumer)
}

fn direct_key_forbidden(scope: &str) -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": {"message": format!("service key lacks '{scope}' scope"), "type": "forbidden"}
        })),
    )
        .into_response()
}

/// Control scopes that open READS. The table above is method + path for
/// WRITES, and a read scope is a different promise, so it has its own table
/// rather than a flag on a write row: a GET row there would read as a write
/// permission to everything that walks the table for one. Both tables are the
/// one vocabulary (`control_scope_rows`): the issuer, the scopes listing and
/// the declaration guards read them together.
///
/// A read scope opens FLEET-WIDE AGGREGATES only (counts, sums, averages),
/// never a row that belongs to a person. `conversation_stats` is the evolve
/// composite score's input: tool usage, conversation totals and feedback
/// ratios across every user. Most of these GETs already pass the User tier
/// (`scope_allows` waves every GET through); what the scope adds is the
/// overview's fleet-wide view, which `routes::memory::conv_stats_overview`
/// grants to its holder and to nobody else below Operator. It never names a
/// user's own rows and is never a default.
pub const CONTROL_READ_SCOPE_ROUTES: &[(&str, &str, &str)] = &[
    (CONVERSATION_STATS_SCOPE, "GET", "/api/conversations/stats/tools"),
    (CONVERSATION_STATS_SCOPE, "GET", "/api/conversations/stats/overview"),
    (CONVERSATION_STATS_SCOPE, "GET", "/api/conversations/feedback/stats"),
];

/// Every control-scope row, writes then reads.
pub fn control_scope_rows() -> impl Iterator<Item = &'static (&'static str, &'static str, &'static str)> {
    CONTROL_SCOPE_ROUTES.iter().chain(CONTROL_READ_SCOPE_ROUTES.iter())
}

/// Whether the requester holds control scope `scope`. Role does not matter:
/// callers that already see everything (Operator and above) never need it.
pub fn holds_control_scope(requester: Option<&RequesterCtx>, scope: &str) -> bool {
    requester.is_some_and(|r| r.scopes.iter().any(|s| s == scope))
}

/// `config:<section>` opens `PUT /api/config/<section>` and nothing else. The
/// grant is per section, so the key's scope list IS the allowlist of what the
/// add-on may tune. A gate-bearing section (`GATED_CONFIG_SECTIONS`) is never
/// issuable: only an admin person writes those, so granting one would read
/// as a permission and open nothing.
pub const CONFIG_SCOPE_PREFIX: &str = "config:";

/// Whether `scope` is a control scope a key may be issued with.
pub fn is_control_scope(scope: &str) -> bool {
    if control_scope_rows().any(|(s, _, _)| *s == scope) {
        return true;
    }
    scope.strip_prefix(CONFIG_SCOPE_PREFIX).is_some_and(|section| {
        !section.is_empty()
            && section.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && !crate::routes::settings::GATED_CONFIG_SECTIONS.contains(&section)
    })
}

/// Whether any of `scopes` opens `method path` through a control scope.
pub fn control_scope_allows(scopes: &[String], method: &axum::http::Method, path: &str) -> bool {
    let has = |s: &str| scopes.iter().any(|x| x == s);
    if control_scope_rows()
        .any(|(s, m, p)| method.as_str() == *m && path_matches(p, path) && has(s))
    {
        return true;
    }
    *method == axum::http::Method::PUT
        && path
            .strip_prefix("/api/config/")
            .filter(|section| !section.is_empty() && !section.contains('/'))
            .is_some_and(|section| {
                // A renamed section answers to either spelling's scope for the
                // transition: `config:video_memory` (what evolve
                // declares today) and `config:recall_memory` both open
                // `PUT /api/config/{video_memory,recall_memory}`.
                crate::routes::settings::config_section_spellings(section).iter().any(|name| {
                    let scope = format!("{CONFIG_SCOPE_PREFIX}{name}");
                    has(&scope) && is_control_scope(&scope)
                })
            })
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let (mut p, mut q) = (pattern.split('/'), path.split('/'));
    loop {
        match (p.next(), q.next()) {
            (None, None) => return true,
            (Some("*"), Some(seg)) if !seg.is_empty() => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// The one account-administration endpoint any authenticated JWT may POST:
/// filing a proposal for operator approval (`routes::users::api_users_propose`
/// on its `/api/security/*` path — the design). It mutates nothing but
/// the queue itself; every proposed action still executes only when a named
/// operator approves it. The legacy `/api/users/propose` is deliberately NOT
/// listed — that surface is slated for deprecation and stays agent-only
/// (cluster-HMAC callers bypass this tier gate entirely).
pub const USER_PROPOSAL_ESCALATION_PATH: &str = "/api/security/users/propose";

/// `POST /api/monitoring/grafana-session` (`routes::monitoring`): mints a
/// Grafana session for the caller's OWN live account. A non-operator JWT
/// may POST it — exact match; see `scope_allows`.
pub const GRAFANA_SESSION_PATH: &str = "/api/monitoring/grafana-session";

/// The refusal for `POST /api/monitoring/grafana-session` when a credential
/// class `require_any_auth` turns away with a bare 403 (a peer token, a
/// harness token off its rail, a node's fleet token) asks for Grafana: a
/// body saying why and which tiers open it, in the
/// gateway's `{"error": …}` shape.
pub fn grafana_refusal() -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": format!("this credential cannot open Grafana — {}", grafana_needs())
        })),
    )
        .into_response()
}

/// Is this a bare refusal — a 403 with no body type — rather than a
/// handler's own explained one?
pub fn is_bare_forbidden(r: &Response) -> bool {
    r.status() == StatusCode::FORBIDDEN && !r.headers().contains_key(axum::http::header::CONTENT_TYPE)
}

/// Layered OUTSIDE `require_any_auth` (routes/mod.rs): on the Grafana
/// session route, a bare 403 from the auth layer becomes
/// [`grafana_refusal`]. Every other route and every explained refusal
/// passes through untouched.
pub async fn explain_grafana_refusal(request: Request, next: Next) -> Response {
    let grafana = request.uri().path() == GRAFANA_SESSION_PATH;
    let r = next.run(request).await;
    if grafana && is_bare_forbidden(&r) {
        return grafana_refusal();
    }
    r
}

/// Self-service MCP key management: the only other `/api/security/*` paths a
/// non-operator JWT may POST.
///
/// These mint and revoke a key for the CALLER and nobody else — the handler
/// takes the consumer and the bound user from `RequesterCtx`, never from the
/// body, and pins the scope set to `["mcp"]`. So the issued key is a bearer
/// form of the account the caller already holds: strictly no new capability,
/// which is what makes it safe to expose below the Operator tier.
///
/// Matched EXACTLY, never by prefix. `/api/security/service-keys` (issue for
/// an arbitrary consumer, with arbitrary scopes) sits one segment up and must
/// stay operator-gated; a `starts_with` here would hand a `User` the power to
/// mint themselves an unbound key with the full scope set.
pub const SELF_SERVICE_KEY_PATHS: &[&str] = &[
    "/api/security/service-keys/self",
    "/api/security/service-keys/self/revoke",
];

/// The asynchronous-operations API, as exact (method, path) pairs from
/// `routes/ops.rs`: POST/GET `/api/v1/ops`, GET `/api/v1/ops/types`,
/// GET/DELETE `/api/v1/ops/{id}`. Not a prefix: a route added there later
/// (a `/retry`) is closed to the User tier until it is listed HERE. See the
/// comment where `scope_allows` admits it.
pub fn is_ops_api(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if path == "/api/v1/ops" {
        return matches!(*method, Method::GET | Method::POST);
    }
    match path.strip_prefix("/api/v1/ops/") {
        Some("types") => *method == Method::GET,
        Some(id) if !id.is_empty() && !id.contains('/') => matches!(*method, Method::GET | Method::DELETE),
        _ => false,
    }
}

/// Agent mail writes a User may make: `POST /api/agents/messages` (send),
/// `POST /api/agents/messages/{id}/ack`, and `POST /api/agents/name` (name
/// the caller's own MCP session; the handler renames only the session the
/// credential IS, so it cannot touch a sibling). Exact pairs, not a prefix: a prefix
/// would also open `/collaborate`, `/trust`, `/trust/remove`, `PUT /keys/{agent}`,
/// `/peer/*` and any route added later. The handlers (`routes/agents.rs`)
/// enforce ownership for a non-privileged caller: `from` must be the caller's
/// own, no broadcast, a seat to post into a thread, recipient exists and is the
/// same owner or has trusted the sender; ack requires owning the recipient address.
pub fn is_agent_message_write(method: &axum::http::Method, path: &str) -> bool {
    if *method != axum::http::Method::POST {
        return false;
    }
    if path == "/api/agents/messages" || path == "/api/agents/name" {
        return true;
    }
    match path.strip_prefix("/api/agents/messages/").and_then(|r| r.strip_suffix("/ack")) {
        Some(id) => !id.is_empty() && !id.contains('/'),
        None => false,
    }
}

/// The two job routes a User-tier account may call, as exact (method, path)
/// pairs: `POST /api/jobs/submit` and `DELETE /api/jobs/{job_id}` where the id
/// is UUID-shaped (job keys are `noo:jobs:{id}` and share the prefix with
/// `noo:jobs:queue`, `active`, `history`, `drained_nodes`, so a word is never
/// an id). Deliberately NOT a prefix: `/api/jobs/{id}/reprioritize`,
/// the scheduler's `/api/tasks/submit` and `/api/tasks/inference`, and
/// `/api/scheduler/*` stay operator-only (a person's own harness tasks are
/// [`is_task_owner_api`]). The handlers
/// restrict what a User may submit and make cancel owner-only
/// (`routes::admin`); this only lets the request reach them.
pub fn is_job_user_api(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if path == "/api/jobs/submit" {
        return *method == Method::POST;
    }
    match path.strip_prefix("/api/jobs/") {
        Some(id) => *method == Method::DELETE && id.len() == 36 && uuid::Uuid::parse_str(id).is_ok(),
        None => false,
    }
}

/// The task writes any account may make on its OWN tasks: create, stop
/// (one, or its own by `via`), ask, answer, context, resubmit — the same set
/// the user MCP door's `noo_task_*` tools reach. `routes/tasks.rs` answers
/// 404 for a task the caller does not own and keeps answer, context and
/// resubmit owner-only, so opening the tier gate grants nothing beyond them
/// (operator decision 2026-10-19, i143 requirement C).
pub fn is_task_owner_api(method: &axum::http::Method, path: &str) -> bool {
    if *method != axum::http::Method::POST {
        return false;
    }
    if path == "/api/tasks" || path == "/api/tasks/stop" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/api/tasks/") else { return false };
    let mut parts = rest.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(id), Some(op), None) => {
            uuid::Uuid::parse_str(id).is_ok() && matches!(op, "stop" | "ask" | "answer" | "context" | "resubmit")
        }
        _ => false,
    }
}

/// `PUT /api/v1/walks/settings`: any signed-in account turns saving of its own
/// walks on or off (`walks.save_threads`). Exact path, not a prefix.
pub const WALKS_SETTINGS_PATH: &str = "/api/v1/walks/settings";

/// App-layer RBAC for human JWTs.
///
/// - role >= `Operator` (the old `write`/`admin` scopes, via
///   [`Claims::resolved_role`]) → unrestricted control plane.
/// - otherwise (`User` tier): full visibility — every GET works, so the
///   whole dashboard renders — but mutating methods are confined to the
///   chat/query surface. Everything else 403s, including unported routes
///   behind the `/api/{*path}` Python catch-all (fail closed).
/// - legacy tokens with an empty scopes list fall back to the `role` claim;
///   anything non-admin degrades to the `User` tier rather than 401ing.
///
/// `ingest` stays a SCOPE, deliberately outside the role cascade: it is an
/// additive capability (contribute documents), not a tier, and folding it
/// into `Operator` would grant far more than it means.
///
/// Machine credentials never reach this check: cluster-HMAC tokens, service
/// keys, and peer tokens are scoped by their own branches in
/// `require_any_auth`.
pub(crate) fn scope_allows(claims: &Claims, method: &axum::http::Method, path: &str) -> bool {
    scope_allows_for(&claims.scopes, claims.resolved_role(), Some(account_of(&claims.sub)), method, path)
}

/// Whether an already-authenticated requester may make `method path` — the
/// SAME decision [`scope_allows`] makes at the front door, asked later and
/// from inside a handler.
///
/// The async-operation API (`routes/ops.rs`) needs it: `POST /api/v1/ops`
/// starts "what `POST /api/v1/graph/recluster` does", and the front door only
/// ever saw the path `/api/v1/ops`. So the start asks THIS function about the
/// operation's own route and gets the answer that route would have given —
/// the rule is not restated in the ops code, so it cannot drift from this one.
/// `RequesterCtx.role` is `Claims::resolved_role` evaluated at validation, so
/// the two entry points agree by construction.
pub fn requester_allows(requester: &RequesterCtx, method: &axum::http::Method, path: &str) -> bool {
    // An add-on's own token reaches the proxy to ITS OWN reserved workload
    // (`addon_workloads::proxy_allows`); the handler then checks the
    // reservation. Nothing else about the token changes.
    if crate::addon_workloads::proxy_allows(&requester.sub, path) {
        return true;
    }
    scope_allows_for(&requester.scopes, requester.role, Some(account_of(&requester.sub)), method, path)
}

/// `account` is the caller's account: a features add-on route (f99) is
/// decided per account, every other path by role and scopes.
fn scope_allows_for(scopes: &[String], role: Role, account: Option<&str>, method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    let has = |s: &str| scopes.iter().any(|x| x == s);
    if role >= Role::Operator {
        return true;
    }
    if METRICS_READ_PATHS.contains(&path) || path.starts_with(LOGS_READ_PREFIX) || path.starts_with(TRACES_READ_PREFIX) {
        return false;
    }
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        // An add-on's GET is scoped by the route's own `min_role`/`scopes`
        // (addon_proxy), not waved through with the allow-list.
        return user_may_read(path) || crate::addon_proxy::mounted_get_allows(scopes, role, account, path);
    }
    // A write the add-on's manifest opted in with `owner_scoped` (the add-on
    // keeps every row to the forwarded account). Exact manifest match only.
    if crate::addon_proxy::mounted_owner_scoped_allows(method, scopes, role, account, path) {
        return true;
    }
    if CHAT_QUERY_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    // filing a user-management proposal is the designated
    // sub-operator escalation path (User files, Operator decides), and the
    // security-surface mutation guards point their rejections at exactly this
    // path — so the tier gate must not 403 the endpoint its own error message
    // recommends. Exact match, filing only: listing the queue and deciding
    // stay operator-gated (in-handler guards + this tier gate).
    if path == USER_PROPOSAL_ESCALATION_PATH {
        return true;
    }
    // Minting/revoking one's OWN mcp key. Exact match, and the handler
    // re-derives every identity field from the JWT — see SELF_SERVICE_KEY_PATHS.
    if SELF_SERVICE_KEY_PATHS.contains(&path) {
        return true;
    }
    // The per-account switch for saving one's OWN walks as threads. Exact match; the handler reads the account from the verified
    // credential and the body has no field that names another.
    if path == WALKS_SETTINGS_PATH {
        return true;
    }
    // The asynchronous-operations API (`routes/ops.rs`). Open to every tier
    // because it decides for itself, per request: starting an op asks
    // `requester_allows` about the OPERATION'S OWN route (so a User gets
    // exactly the refusal that route gives), and an op can be read or
    // cancelled only by its owner (anyone else gets "not found"). Without this
    // the tier gate would 403 a caller who started an op through a route they
    // ARE allowed (the `ingest` scope's `/api/v1/docs/ingest`) when they
    // came to poll or cancel it. Exact path and a `/` boundary, never a
    // bare prefix: `/api/v1/opsx` is not this.
    if is_ops_api(method, path) {
        return true;
    }
    // Sending and acking agent mail as oneself. Exact pairs; ownership is
    // enforced in the handlers (see `is_agent_message_write`).
    if is_agent_message_write(method, path) {
        return true;
    }
    // Creating and steering one's OWN tasks (`is_task_owner_api`).
    if is_task_owner_api(method, path) {
        return true;
    }
    // Submitting an inference job and cancelling one's own (`is_job_user_api`).
    // Exact pairs; the handlers confine the type and the owner.
    if is_job_user_api(method, path) {
        return true;
    }
    // Opening Grafana as oneself. Every tier gets in
    // (a User is a Grafana Viewer; its queries are held to the dashboards'
    // own at the gateway), and the handler re-reads the live
    // account and refuses a disabled one with a body. Without this the gate
    // answers a User with a bare 403 before the handler ever runs.
    if path == GRAFANA_SESSION_PATH {
        return true;
    }
    // Opening an add-on's UI or socket as oneself. Exact shapes, POST only;
    // the handlers apply the UI's / the socket's own `min_role` and refuse a
    // delegated credential (`addon_ui::ui_session`, `addon_ws::ws_ticket`).
    if *method == Method::POST && (crate::addon_ui::is_ui_session_path(path) || crate::addon_ws::is_ws_ticket_path(path)) {
        return true;
    }
    // Additive and last: a caller without `ingest` is unaffected, and a
    // caller with it gains these paths and nothing else.
    if has("ingest") && INGEST_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    // Additive, exact paths, POST only (a GET never reaches this line).
    // `graph` is an ADDITION to a person's `read`, never a credential of its
    // own: a token carrying `graph` without `read` gets nothing from it, so no
    // graph-only token (a service key, an odd mint) can exist in effect.
    if has("graph") && has("read") && *method == Method::POST && GRAPH_QUERY_PATHS.contains(&path) {
        return true;
    }
    control_scope_allows(scopes, method, path)
}

/// GET paths a `User`-tier token may read, exact match. Everything a person
/// needs to chat, search, browse the graph, see their own history, and have
/// the dashboard render. This is an ALLOW-LIST like the kiosk's
/// ([`KIOSK_READ_PATHS`]): a route added next year is closed to a User until
/// someone puts it here on purpose. Until 2026-10 the tier gate waved every
/// GET through, which let a `read` account list the audit/violation/PKI
/// views, every node's desired config and the whole `noomesh.yaml`.
///
/// Handlers that return installation-wide data ALSO guard themselves
/// (`routes/admin.rs`, `routes/settings.rs`, `routes/cluster.rs`): the tier
/// gate is the front door, the in-handler guard is the second lock.
pub const USER_READ_PATHS: &[&str] = &[
    "/health",
    "/auth/me",
    "/v1/models",
    "/tools/list",
    "/api/version",
    "/api/events/stream",
    // Dashboard overview sources. `desired-config`, `maintenance`,
    // `model-classes`, `provision-bundle`, `proposals` are NOT here.
    "/api/cluster/status",
    "/api/cluster/nodes",
    "/api/cluster/backends",
    "/api/cluster/gpu-metrics",
    "/api/cluster/replication-status",
    "/api/scheduler/status",
    "/api/models/cached",
    "/api/ollama/models",
    "/api/jobs",
    "/api/jobs/history",
    "/api/heartbeat/status",
    "/api/heartbeat/tasks",
    "/api/heartbeat/history",
    "/api/heartbeat/actions",
    "/api/heartbeat/artifacts",
    "/api/autonomy/status",
    "/api/autonomy/decisions",
    "/api/alerts/clients",
    "/api/approval/stats",
    "/api/channels/status",
    "/api/coordinator/context",
    "/api/memory/health",
    "/api/memory/status",
    "/api/memory/storage-stats",
    "/api/memory/embed/status",
    "/api/memory/search",
    "/api/v1/rag/status",
    "/api/v1/settings/user-dirs",
    "/api/v1/settings/preference",
    "/api/docs/openapi",
    "/api/docs/runbooks",
    "/api/skills/list",
    "/api/prompt-skills",
    "/api/tags",
    "/api/workflows",
    "/api/usage/me",
    "/api/usage/summary",
    "/api/voice/status",
    "/api/voice/voices",
    "/api/agent/loops",
    "/api/external/capabilities",
    "/api/external/models",
    "/api/external/usage",
    "/api/activities",
    "/api/tasks",
    "/api/cloud-providers/status",
    "/api/mcp/status",
    "/api/security/service-keys/self",
];

/// GET prefixes a `User` may read (boundary-aware: see [`user_may_read`]).
pub const USER_READ_PREFIXES: &[&str] = &[
    "/ws/",
    "/upload/",
    "/api/conversations",
    "/api/inference",
    "/api/memory/relationships/",
    "/api/memory/stats/",
    "/api/v1/docs",
    "/api/v1/graph/",
    "/api/v1/recall/",
    "/api/v1/video-memory/",
    "/api/v1/walks",
    "/api/v1/ops",
    "/api/agents/messages",
    "/api/agents/threads",
    "/api/agents/presence",
    "/api/agents/whoami",
    "/api/agents/roles",
    "/api/agents/peer/",
    "/api/heartbeat/tasks/",
    "/api/jobs/",
    "/api/docs/runbooks/",
    "/api/skills/",
    "/api/prompt-skills/",
    "/api/persona/",
    "/api/temporal/",
    "/api/proactive/",
    "/api/tasks/",
    "/api/activities/",
    "/api/addons/",
    "/api/artifacts/manifest/",
    "/api/users/",
    "/v1/models/",
];

/// Whether a `User`-tier token may GET `path` by the allow-list above. An
/// add-on's mounted GET routes are NOT here: each declares its own `min_role`
/// and `scopes`, which `scope_allows_for` asks `addon_proxy::mounted_get_allows`
/// (absent means Operator, so a User reads none an add-on did not vouch for).
/// Operator-only reads that sit under a User-readable prefix: the skill
/// promotion queue lives below `/api/prompt-skills`, which a User may list.
const USER_READ_EXCLUDED_PREFIXES: &[&str] = &["/api/prompt-skills/proposals"];

pub fn user_may_read(path: &str) -> bool {
    if USER_READ_EXCLUDED_PREFIXES
        .iter()
        .any(|p| path == *p || path.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
    {
        return false;
    }
    USER_READ_PATHS.contains(&path)
        || USER_READ_PREFIXES.iter().any(|p| {
            // `/x/` prefixes match by starts_with; a bare `/x` entry matches
            // `/x` and `/x/...` only (a directory, not a stem).
            if p.ends_with('/') {
                path.starts_with(p)
            } else {
                path == *p || path.strip_prefix(p).is_some_and(|r| r.starts_with('/'))
            }
        })
}

/// Metric READS: Operator and Admin only. The metrics describe the whole
/// installation (nodes, VRAM, load, auth failures, corpus sizes, add-on
/// counters), which is an operator's view, not a user's. A User-tier token
/// reads every other GET; not these.
///
/// `/api/metrics/range`, `/api/metrics/discover` and `/api/alerts/list` are the
/// same view (Prometheus ranges, series names, rule and Alertmanager state)
/// and the same rule.
pub const METRICS_READ_PATHS: &[&str] = &[
    "/metrics",
    "/api/metrics/query",
    "/api/metrics/range",
    "/api/metrics/discover",
    "/api/alerts/list",
];

/// Log READS: Operator and Admin only, the same rule as metrics. Every
/// `/api/logs/*` route proxies Loki or a node's container logs — the whole
/// installation's output, including other users' sessions and every node's
/// errors. Five of these are GETs, and a User-tier token reads every other
/// GET; until 2026-09-28 that meant any signed-in user could run LogQL
/// against Loki. A prefix, so a log route added later is closed by default.
pub const LOGS_READ_PREFIX: &str = "/api/logs/";

/// Request-trace READS (i359): Operator and Admin only, like logs. A trace
/// names who made each request and which routes they used, across every
/// account. A prefix, so a trace route added later is closed by default.
pub const TRACES_READ_PREFIX: &str = "/api/traces/";

/// The one service leaf that may read `/metrics` by certificate alone:
/// `noo security pki issue-service prometheus` (CN=prometheus,
/// O=Mesh Cluster Service). Nothing else is opened to it.
pub const METRICS_SCRAPER_SERVICE: &str = "prometheus";

/// Whether this request is the scraper reading `/metrics` with its leaf.
fn is_metrics_scrape(method: &axum::http::Method, path: &str, service: Option<&crate::node_identity::VerifiedService>) -> bool {
    *method == axum::http::Method::GET
        && path == "/metrics"
        && service.is_some_and(|s| s.0 == METRICS_SCRAPER_SERVICE)
}

/// Grafana's data sources, through the gateway: every path
/// under this prefix answers Grafana's own service leaf and nothing else —
/// no bearer token, no other certificate (`routes::grafana_ds`).
pub const GRAFANA_DS_PREFIX: &str = "/api/grafana-ds/";

/// The service leaf that opens [`GRAFANA_DS_PREFIX`]:
/// `noo security pki issue-service grafana` (CN=grafana,
/// O=Mesh Cluster Service), the leaf Grafana's data sources dial with.
pub const GRAFANA_SERVICE: &str = "grafana";

/// The header Grafana sets to the signed-in person's login on every request
/// it makes to a data source (`[dataproxy] send_user_header = true`).
/// Measured on Grafana 12.4.11: set from the session, with JWT
/// logins too, and a value the browser sent is REPLACED, not appended to.
/// Absent when Grafana acts on its own (an alert rule's evaluation).
pub const GRAFANA_USER_HEADER: &str = "x-grafana-user";

/// Who is asking on a [`GRAFANA_DS_PREFIX`] request. `Err` unless the
/// connection presented Grafana's verified service leaf: from anyone else
/// `X-Grafana-User` is a claim, and is never read. `Ok(None)` is Grafana
/// with no user; `Ok(Some(login))` the person Grafana says is signed in.
/// Every other header — `X-Dashboard-Uid`, `X-Panel-Id`, `X-Forwarded-User`
/// — can be the browser's (measured), so nothing else is read.
pub fn grafana_ds_identity(
    service: Option<&crate::node_identity::VerifiedService>,
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, String> {
    if !service.is_some_and(|s| s.0 == GRAFANA_SERVICE) {
        return Err(format!(
            "{GRAFANA_DS_PREFIX}* answers Grafana's own service leaf only (`noo security pki issue-service {GRAFANA_SERVICE}`); \
             no token and no other certificate opens it"
        ));
    }
    let mut values = headers.get_all(GRAFANA_USER_HEADER).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => {
            let login = v.to_str().map_err(|_| "X-Grafana-User is not text".to_string())?.trim();
            if login.is_empty() || login.len() > 256 || login.chars().any(char::is_control) {
                return Err("X-Grafana-User is empty or malformed".into());
            }
            Ok(Some(login.to_string()))
        }
        _ => Err("X-Grafana-User given more than once".into()),
    }
}

/// The rate-limit bucket for a Grafana data-source request: one per
/// person, `svc:grafana:<login>` (`svc:grafana:-` for Grafana with no
/// user). Every Grafana user arrives from Grafana's one compose address,
/// so a per-IP bucket would make every viewer share one 600/min budget.
/// `None` (the caller's ordinary per-IP bucket) for anything else,
/// including a forged header on a connection without Grafana's leaf.
pub fn grafana_ds_rate_key(request: &Request) -> Option<String> {
    if !request.uri().path().starts_with(GRAFANA_DS_PREFIX) {
        return None;
    }
    let service = request
        .extensions()
        .get::<Option<crate::node_identity::VerifiedService>>()
        .and_then(|s| s.clone());
    let login = grafana_ds_identity(service.as_ref(), request.headers()).ok()?;
    Some(format!("svc:{GRAFANA_SERVICE}:{}", login.as_deref().unwrap_or("-")))
}

/// The controller-secret door: it ADMITS NOTHING. Called
/// by [`require_any_auth`] once a bearer verifies under the controller
/// secret, so a refusal can say who and be counted. The CLI's actors are told
/// to upgrade, an add-on's are told to provision its key, and everyone else
/// is refused as a container without its key. Every arm is a 403.
pub async fn controller_door(
    metrics: &crate::metrics::MetricsState,
    actor: &str,
    path: &str,
    peer: &crate::legacy_lanes::PeerFacts,
) -> Response {
    // The `noo` CLI no longer signs with the controller secret, on any
    // route (by design: no break-glass, no onboard
    // bootstrap). An actor it used — `cli`, `cli-posture`,
    // `cli-onboard`, `cli-break-glass` — is an old binary: refused,
    // told to upgrade, and counted as a refusal. No grace path.
    if crate::operator_auth::is_cli_actor(actor) {
        let u = crate::legacy_lanes::cli_refusal_use(actor, path);
        crate::legacy_lanes::observe(metrics, &[u], peer).await;
        return old_cli_refusal();
    }
    // An add-on (trellion, trellion-intel, evolve) on either shared
    // secret: refused and counted, before anything is admitted
    // Its images present their own key since then.
    if let Some(r) = crate::addon_hmac_refusal::refuse_addon_hmac(metrics, crate::legacy_lanes::HmacDoor::Controller, actor, path, peer).await {
        return r;
    }
    // Everyone else: refused and counted. No route,
    // the inference surface included, admits a controller-secret HMAC.
    crate::controller_hmac_refusal::refuse(metrics, actor, path, peer).await
}

/// Global "require some form of auth" middleware. Accepts:
///   - JWT bearer token (Authorization header or `?token=` query)
///   - Cluster HMAC time-bearer token (same `Authorization: Bearer …`
///     header, format `<actor>:<ts>:<hmac>`)
///   - On the inference surface (`/v1/*`, `/api/external/*`) ONLY: a named
///     service key from `noo_service_keys`, resolved to a `Consumer` with
///     its own scopes and quota. See `service_keys::resolve`.
///
/// The single anonymous `NOO_SERVICE_API_KEY` env bearer that used to be
/// accepted here was RETIRED: it authenticated as the
/// unattributed consumer "legacy", so external traffic could not be
/// attributed, scoped, quota'd or revoked. Every consumer now holds an
/// issued key (`noo security service-key issue <name>`).
///
/// Returns 401 for everything else. Skips path prefixes in
/// `PUBLIC_PATH_PREFIXES`. There is no auth-disable override: auth is
/// always on (fail-closed), in dev and prod alike.
///
/// Replaces the old `require_auth` fail-open behavior where unset/dev
/// JWT secret caused every protected route to silently bypass auth —
/// the source of the meshsec scanner findings.
pub async fn require_any_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    // Safe methods only for PUBLIC_GET_PATH_PREFIXES — a public READ must not
    // imply a public WRITE (R4/D5).
    let safe_method = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if passes_without_bearer_check(&path, safe_method, bearer_token(&request).is_some()) {
        return Ok(next.run(request).await);
    }

    // The inference surface (`/v1/*` legacy + `/api/external/*` canonical) is
    // where external service consumers authenticate with a service key and
    // where calls are attributed to a named `Consumer` for scope checks +
    // audit. Other paths never carry a Consumer.
    let is_inference_surface = path.starts_with("/v1/") || path.starts_with("/api/external/");

    // The scraper, by its service leaf, on `/metrics` only.
    // Checked before the bearer: Prometheus presents a certificate, not a
    // token. Any other service leaf, or this one anywhere else, falls through
    // to the ordinary checks below and is refused like any caller without a
    // credential.
    let scraper = request
        .extensions()
        .get::<Option<crate::node_identity::VerifiedService>>()
        .and_then(|s| s.clone());
    if is_metrics_scrape(request.method(), &path, scraper.as_ref()) {
        request.extensions_mut().insert(AuthActor(format!("svc:{METRICS_SCRAPER_SERVICE}")));
        return Ok(next.run(request).await);
    }

    // Grafana's data sources, by Grafana's service leaf
    // ALONE, and before the bearer: no token opens these paths, and a
    // request without the leaf is refused before its X-Grafana-User is read.
    // The handler resolves the person's live tier and decides per query.
    if path.starts_with(GRAFANA_DS_PREFIX) {
        return match grafana_ds_identity(scraper.as_ref(), request.headers()) {
            Ok(login) => {
                let actor = format!("svc:{GRAFANA_SERVICE}:{}", login.as_deref().unwrap_or("-"));
                request.extensions_mut().insert(AuthActor(actor));
                Ok(next.run(request).await)
            }
            Err(why) => {
                tracing::info!(path = %path, "grafana_ds_refused: {why}");
                Err(StatusCode::UNAUTHORIZED)
            }
        };
    }

    // Authorization header always; `?token=` only for WebSocket upgrades (M-A2).
    let token = bearer_token(&request);

    let Some(t) = token else {
        if defers_to_ws_handler(&request) {
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Cluster token v2: a fleet-secret HMAC bound to THIS request (method,
    // path+query, body hash) with a single-use nonce. Verified here, before
    // any other credential class, because the token is never a JWT or a key.
    // What the doors below see is a freshly minted v1-shaped token for the
    // verified actor, so the fleet door is one code path for both forms;
    // `from_v2` records which form really arrived (v1 is refused and counted
    // as `cluster_hmac_v1_refused`). A malformed or failing v2 token is a 401.
    let mut from_v2 = false;
    let t = if crate::cluster_token_v2::is_v2(&t) {
        match admit_cluster_token_v2(&state, &mut request, &t).await {
            Ok(v1_shaped) => {
                from_v2 = true;
                v1_shaped
            }
            Err(status) => return Err(status),
        }
    } else {
        t
    };

    let secret = jwt_secret();
    // Fail CLOSED on the insecure default: if `NOO_JWT_SECRET` is unset (or
    // still the well-known "dev-secret-change-in-production" placeholder),
    // bearer JWTs are forgeable by anyone, so we must NOT accept them. Skip the
    // JWT branch entirely and fall through to cluster-HMAC / service-key auth,
    // which don't depend on the JWT secret — the gateway keeps working for
    // authenticated infra, but the forgeable-token door is shut.
    if !jwt_secret_is_insecure(&secret) {
        if let Ok(claims) = verify_token(&t, &secret) {
            // The per-account not-before floor: a still-valid access token of
            // an account that was since disabled, demoted, re-passworded or
            // logged out is refused HERE, on every bearer path — including the
            // `/ws/*` handshake, so a socket closed with 4401 cannot simply
            // reconnect with the same JWT. See `session_floor`.
            if crate::session_floor::refuses(&state, &claims.sub, &t).await {
                tracing::info!(target: "security", sub = %claims.sub, "token refused: issued before the account's session floor");
                return Err(StatusCode::UNAUTHORIZED);
            }
            // Peer tokens (scopes=["peer"], sub="peer:{id}") are confined to the
            // peer surface (/ws/agent + /api/agents/peer/*). Without this a peer
            // token is effectively a full-access token: it would receive
            // Consumer::all on the inference surface and pass every other
            // authenticated route (admin/cluster/etc.). User tokens carry
            // ["read","write","admin"] (not "peer"), so they are unaffected.
            // A node-hosted harness token is confined to the
            // harness rail, and must carry the conversation it was minted
            // for. It is a user token in every other respect; the rail's
            // handlers take the conversation from the claim, not the body.
            if let Some(turn) = harness_turn_for(&claims, &path)? {
                // The account behind the turn is re-read on every rail
                // call: disabling the person, or lowering their role,
                // stops a turn already running (i143 decision 4).
                let live = live_account_role(&state.db, &claims.sub).await;
                if !rail_token_admitted(claims.resolved_role(), live) {
                    tracing::warn!(sub = %claims.sub, node = %turn.node, live = ?live, "harness token refused: account disabled, absent or below the token's role");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                request.extensions_mut().insert(turn);
            }
            // A worker-delegated token reaches the tool
            // routes and nothing else — the same shape as the harness rail.
            crate::worker_delegation::confine(&claims, request.method().as_str(), &path)?;
            // An add-on delegated token (i143) reaches the task routes and
            // nothing else, only while its add-on is registered with
            // delegation on, and only while the account is enabled and no
            // lower than the token's role. Handlers key their isolation on the
            // extension: the add-on sees its own tasks for this person.
            if let Some(addon) = crate::addon_delegation::addon_of(&claims) {
                crate::addon_delegation::confine(&claims, request.method().as_str(), &path)?;
                if !crate::addon_registry::get(addon).is_some_and(|e| e.delegates_tasks() && e.operator_enabled()) {
                    tracing::warn!(sub = %claims.sub, addon, "add-on delegated token refused: the add-on does not delegate tasks (unregistered, undeclared or not enabled)");
                    return Err(StatusCode::FORBIDDEN);
                }
                let live = live_account_role(&state.db, &claims.sub).await;
                if !rail_token_admitted(claims.resolved_role(), live) {
                    tracing::warn!(sub = %claims.sub, addon, live = ?live, "add-on delegated token refused: account disabled, absent or below the token's role");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                request.extensions_mut().insert(crate::addon_delegation::AddonDelegation { addon: addon.to_string() });
            }
            if claims.scopes.iter().any(|s| s == "peer") {
                let on_peer_surface = path.starts_with("/api/agents/peer")
                    || path.starts_with("/ws/agent");
                if !on_peer_surface {
                    return Err(StatusCode::FORBIDDEN);
                }
                // Handlers on the peer surface bind actions to THIS peer
                // (a peer may re-register only its own agent id).
                request.extensions_mut().insert(PeerSub(claims.sub.clone()));
                return Ok(next.run(request).await);
            }
            // A kiosk token reads THE DISPLAY'S
            // ROUTES and does nothing else anywhere. Both halves are
            // decided before dispatch and both deny by default, so a route
            // added after this line was written is closed to kiosks until
            // someone adds it to KIOSK_READ_PATHS on purpose.
            //
            // This branch is TERMINAL — it never reaches the tier gate
            // below. That is deliberate: a kiosk is not a User with the
            // writes removed, and inheriting the user tier is precisely
            // what made every GET in the API readable from a corridor.
            // `Role::User` remains in the context only because handlers
            // read it for their own gating and there is no tier beneath
            // it; the allowlist above, not the role, is what bounds this
            // credential.
            if is_kiosk(&claims) {
                if let Err(why) = kiosk_may(request.method(), &path) {
                    return Ok(kiosk_refusal(why));
                }
                request.extensions_mut().insert(AuthActor(claims.sub.clone()));
                request.extensions_mut().insert(RequesterCtx {
                    sub: claims.sub.clone(),
                    scopes: claims.scopes.clone(),
                    role: Role::User,
                    harness: None,
                    act: None,
                });
                return Ok(next.run(request).await);
            }
            // An exchanged add-on token on the inference surface is the
            // consumer that bought it, scoped exactly as its key was — the
            // handler's own scope check is its gate, not the tier gate
            // below (which has no entry for /api/external and refused it).
            if let Some(consumer) = addon_consumer(&claims, is_inference_surface) {
                // the comparator for the add-ons' HMAC
                // fallback — this is the add-on on its own key.
                if let Some(u) = crate::legacy_lanes::addon_token_use(&claims.sub, &path) {
                    crate::legacy_lanes::observe(&state.metrics, &[u], &crate::legacy_lanes::PeerFacts::default()).await;
                }
                request.extensions_mut().insert(AuthActor(claims.sub.clone()));
                request.extensions_mut().insert(RequesterCtx {
                    sub: claims.sub.clone(),
                    scopes: claims.scopes.clone(),
                    role: Role::User,
                    harness: None,
                    act: None,
                });
                request.extensions_mut().insert(consumer);
                return Ok(next.run(request).await);
            }
            // App-layer RBAC: User-tier callers see everything (GET) but can
            // only mutate the chat/query surface. Operator and above pass
            // (role claim or the legacy write/admin scopes — dual-accept).
            // An add-on delegated token passes this gate exactly as its
            // person would: it never opens a route the person cannot.
            if !scope_allows(&claims, request.method(), &path) {
                return Err(StatusCode::FORBIDDEN);
            }
            // Attribute privileged actions (config/admin/delete) to the caller
            // in the audit trail. Present on every JWT-authenticated route, not
            // just the inference surface (H-L1).
            // A DELEGATED token is checked against the
            // account it acts as, on every request. This is the half of
            // the kill switch that reaches a token already in flight;
            // without it, "disable the agent" would only stop the next
            // mint and the operator would be told otherwise.
            // RFC 8705: a token bound to a certificate is refused unless
            // that certificate is on this connection. Checked before the
            // account lookup — it is a pure comparison and cannot be
            // rescued by anything the database says.
            {
                let presented = request
                    .extensions()
                    .get::<Option<crate::node_identity::PeerThumbprint>>()
                    .and_then(|t| t.as_ref())
                    .map(|t| t.0.clone());
                if !cert_binding_holds(claims.cnf.as_ref(), presented.as_deref()) {
                    tracing::warn!(sub = %claims.sub, "token refused: certificate binding does not hold");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                // tell handlers the token was BOUND (and that
                // the binding held — the line above refused it otherwise).
                // Posture writes require exactly this; an unbound token
                // never carries the extension.
                if let Some(c) = claims.cnf.as_ref() {
                    request.extensions_mut().insert(CertBoundToken(c.x5t_s256.clone()));
                }
            }
            if claims.act.is_some() && !delegated_subject_enabled(&state.db, &claims.sub).await {
                tracing::warn!(subject = %claims.sub, "delegated token refused: subject disabled or absent");
                return Err(StatusCode::UNAUTHORIZED);
            }
            if crate::worker_delegation::is_worker_delegated(&claims) {
                tracing::info!(
                    sub = %claims.sub,
                    act = crate::worker_delegation::WORKER_ACTOR,
                    task = claims.act.as_ref().and_then(|a| a.task.as_deref()).unwrap_or(""),
                    method = %request.method(),
                    path = %path,
                    "worker-delegated token accepted"
                );
            }
            request.extensions_mut().insert(AuthActor(claims.sub.clone()));
            request.extensions_mut().insert(RequesterCtx {
                sub: claims.sub.clone(),
                scopes: claims.scopes.clone(),
                role: claims.resolved_role(),
                harness: claims.harness.clone(),
                act: claims.act.clone(),
            });
            if is_inference_surface {
                request.extensions_mut().insert(Consumer::all(&claims.sub));
            }
            // an exchanged add-on token off the inference
            // surface — the comparator for the add-on HMAC fallback (refused
            // as `addon_shared_secret_refused`).
            if let Some(u) = crate::legacy_lanes::addon_token_use(&claims.sub, &path) {
                crate::legacy_lanes::observe(&state.metrics, &[u], &crate::legacy_lanes::PeerFacts::default()).await;
            }
            return Ok(next.run(request).await);
        }
    } else {
        warn_insecure_jwt_once();
    }
    // Controller-local secret: ADMITS NOTHING. Every
    // controller service presents its own key; the last caller on this
    // secret, the worker plane's fallback, is deleted. The door still
    // verifies the signature so a refusal can say WHO and be counted — an
    // unverified token falls through to the fleet door and the 401 below.
    if let Some(actor) = verify_controller_token(&t) {
        let peer = crate::legacy_lanes::PeerFacts::of(&request);
        return Ok(controller_door(&state.metrics, &actor, &path, &peer).await);
    }
    if verify_cluster_token(&t) {
        let actor = cluster_token_subject(&t).unwrap_or_default();
        let peer = crate::legacy_lanes::PeerFacts::of(&request);
        // Which wire form arrived. v2 is the only one admitted: a v1 token
        // (`<actor>:<ts>:<hmac>`, not bound to its request) is always refused,
        // counted as `cluster_hmac_v1_refused` so a stale caller is visible.
        // The HMAC still verifies (above) so the counted `caller` is a real
        // actor, never attacker-chosen text.
        if from_v2 {
            crate::legacy_lanes::observe(&state.metrics, &[crate::legacy_lanes::hmac_v2_use(&actor)], &peer).await;
        } else {
            let u = crate::legacy_lanes::hmac_v1_refused_use(&actor, &path);
            crate::legacy_lanes::observe(&state.metrics, std::slice::from_ref(&u), &peer).await;
            if crate::legacy_lanes::log_due(&format!("hmac_v1_refused_detail|{actor}"), crate::legacy_lanes::HMAC_V1_DETAIL_LOG_EVERY) {
                let headers = request.headers();
                tracing::warn!(
                    actor = %actor, method = %request.method(), path = %path,
                    body_sha_header = headers.contains_key(crate::cluster_token_v2::BODY_SHA_HEADER),
                    token_age_secs = v1_token_age_secs(&t),
                    user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("-"),
                    "v1 cluster token refused: the caller must upgrade to sign v2"
                );
            }
            return Ok(v1_refusal());
        }
        // The fleet door refuses an add-on's actor too: the
        // same decision as the controller door's, and one door guarded would
        // leave the other open while reading as done.
        if let Some(r) = crate::addon_hmac_refusal::refuse_addon_hmac(&state.metrics, crate::legacy_lanes::HmacDoor::Cluster, &actor, &path, &peer).await {
            return Ok(r);
        }
        // the design (review H1): the fleet secret is a NODE's credential.
        // A controller service leaf, or a container beside the gateway with
        // no node leaf, presenting it is the worker plane — refused, counted.
        {
            let service_leaf = request
                .extensions()
                .get::<Option<crate::node_identity::VerifiedService>>()
                .and_then(|s| s.as_ref())
                .map(|s| s.0.clone());
            let node_leaf = request
                .extensions()
                .get::<Option<crate::node_identity::VerifiedPeer>>()
                .is_some_and(|p| p.is_some());
            let compose_peer = peer.ip.as_deref().is_some_and(crate::middleware::is_compose_peer);
            // With mTLS enforced, a fleet token must also come with the
            // node's own leaf (loopback self-calls excepted): without one the
            // actor is only a claim any node can make about another. Not
            // enforcing, it is admitted and counted as `node_token_no_cert`.
            let loopback = crate::controller_hmac_refusal::is_loopback_peer(peer.ip.as_deref());
            if let Some((why, lane)) = crate::controller_hmac_refusal::fleet_token_placement(
                service_leaf.as_deref(), node_leaf, compose_peer, loopback, crate::tls::mtls_enabled(),
            ) {
                return Ok(crate::controller_hmac_refusal::refuse_fleet(&state.metrics, lane, &actor, &path, &peer, &why).await);
            }
        }
        // A verified client certificate outranks the token's actor field
        // The token is signed with the FLEET secret,
        // so its actor is a claim every node can make about any other node;
        // the certificate is per-node and the CA verified it at the
        // handshake. Where they disagree, the claim loses.
        //
        // Absent certificate = absent extension = today's behaviour, so
        // the CLI, the dashboard and the MCP doors are unaffected, and so
        // is every node until mTLS is turned on.
        if let Some(peer) = request
            .extensions()
            .get::<Option<crate::node_identity::VerifiedPeer>>()
            .and_then(|p| p.clone())
        {
            if !actor.is_empty() && actor != peer.node {
                let enforcing = crate::tls::mtls_enabled();
                tracing::warn!(
                    claimed = %actor, presented = %peer.node, enforcing,
                    "cluster token actor does not match the presented client certificate"
                );
                // Observe before enforcing. Refusing on the release that
                // introduces this would lock out any node whose existing
                // cert does not name its registered id — real drift, which
                // provisioning now repairs going forward but which
                // already-issued certs still carry. The warning names both
                // sides so an operator can see whether their fleet is clean
                // BEFORE turning enforcement on.
                if enforcing {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
        // The inference surface (`/v1/*`, `/api/external/*`) is not a node
        // route and the shared secret never buys it: refused, counted, and
        // told to present a service key of its own. This was the
        // `NOO_SELF_CALL_SHARED_SECRET` bridge (closed by default, 0 uses
        // live); it is deleted, not merely closed. The controller door
        // refuses the same surface for every caller
        // (`controller_hmac_refusal::refuse`) and counts it there.
        if is_inference_surface {
            let u = crate::legacy_lanes::self_call_refusal_use(&actor, crate::legacy_lanes::HmacDoor::Cluster);
            crate::legacy_lanes::observe(&state.metrics, std::slice::from_ref(&u), &peer).await;
            return Err(StatusCode::FORBIDDEN);
        }
        // Strict: the fleet secret proves "a node", nothing more. There is no
        // other arm: a gateway without a controller secret refused to start
        // (`boot_refusal`), and the bridge that once made every fleet token
        // an operator's (`NOO_CLUSTER_LEGACY_FULL_ACCESS`) is retired.
        if !node_route_allowed(request.method().as_str(), &path, &actor) {
            tracing::warn!(actor = %actor, method = %request.method(), path = %path, "cluster token refused: not a node route");
            return Err(StatusCode::FORBIDDEN);
        }
        let kind = ClusterKind::Node;
        // count the lane(s) this admission used — including
        // whether a node token came with the node's certificate.
        let presented_node = request
            .extensions()
            .get::<Option<crate::node_identity::VerifiedPeer>>()
            .and_then(|p| p.as_ref())
            .map(|p| p.node.clone());
        let uses = crate::legacy_lanes::hmac_lane_uses(&crate::legacy_lanes::HmacAdmission {
            // The fleet secret only ever grants `Node` (the design retired
            // the full-access arm), and the inference surface is refused above.
            path: &path,
            actor: &actor,
            presented_node: presented_node.as_deref(),
        });
        crate::legacy_lanes::observe(&state.metrics, &uses, &peer).await;
        // Record WHICH actor authenticated and as what. Handlers that serve
        // per-node data check caller-against-subject with it.
        request.extensions_mut().insert(ClusterNode(actor, kind));
        return Ok(next.run(request).await);
    }

    // The exchange doors: a key carrying one of these narrow scopes is
    // accepted on exactly one POST route, to buy a short-lived token, and
    // NOWHERE else. Resolved here rather than in the handler so the handler
    // cannot be reached by any other credential class by accident; the
    // Consumer inserted here is what the handler mints from.
    //
    // Identity is the design, add-on is the design. They are one branch
    // because they are one rule — the difference is entirely in what the
    // handler mints, which is where it belongs. (The kiosk key lane, the
    // first door here, was retired on 2026-09-30.)
    if let Some(required) = exchange_scope_for(&path, request.method()) {
        if let Some(consumer) = service_keys::resolve(&state.db, &t).await {
            if !consumer.has_scope(required) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            if let Some(limit) = consumer.rpm_limit {
                if let Some(redis) = state.redis.as_ref() {
                    if let Ok(crate::cache::RateResult::Limited { retry_after }) =
                        redis.check_consumer_quota(&consumer.name, limit).await
                    {
                        return Ok(consumer_quota_exceeded(&consumer.name, retry_after));
                    }
                }
            }
            request.extensions_mut().insert(consumer);
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Direct-key doors: the key itself, as the bearer, on the exact routes a
    // control scope in `DIRECT_KEY_SCOPES` opens (today the two transcribe
    // routes). Not a widening of the inference surface: only a key holding the
    // route's scope gets in, a key without it gets the scope refusal, and a
    // bearer that is no key falls through to the 401 below.
    if let Some(required) = direct_key_scope_for(&path, request.method()) {
        match direct_key_admission(service_keys::resolve(&state.db, &t).await, required) {
            DirectKey::Forbidden(r) => return Ok(r),
            DirectKey::Admit(consumer) => {
                if let Some(limit) = consumer.rpm_limit {
                    if let Some(redis) = state.redis.as_ref() {
                        if let Ok(crate::cache::RateResult::Limited { retry_after }) =
                            redis.check_consumer_quota(&consumer.name, limit).await
                        {
                            return Ok(consumer_quota_exceeded(&consumer.name, retry_after));
                        }
                    }
                }
                request.extensions_mut().insert(consumer);
                return Ok(next.run(request).await);
            }
            DirectKey::NotAKey => {}
        }
    }

    // Service credentials are SCOPED to the inference surface: an inference
    // key must not unlock admin/cluster routes.
    if is_inference_surface {
        // Named per-consumer service keys (`noo_service_keys`): resolve the
        // bearer to a Consumer + scopes (cached 60s). See service_keys.rs.
        if let Some(consumer) = service_keys::resolve(&state.db, &t).await {
            // Per-consumer quota: stop one named consumer from monopolising the
            // shared inference surface. Only named keys with an rpm_limit are
            // capped; internal callers (rpm_limit=None) are never throttled here.
            if let Some(limit) = consumer.rpm_limit {
                if let Some(redis) = state.redis.as_ref() {
                    if let Ok(crate::cache::RateResult::Limited { retry_after }) =
                        redis.check_consumer_quota(&consumer.name, limit).await
                    {
                        return Ok(consumer_quota_exceeded(&consumer.name, retry_after));
                    }
                }
            }
            request.extensions_mut().insert(consumer);
            return Ok(next.run(request).await);
        }
    }

    // No credential class accepted the bearer. A WebSocket handshake to a
    // handler-verified route is let through so the browser gets a 4401
    // close it can act on; everything else is the plain 401.
    if defers_to_ws_handler(&request) {
        return Ok(next.run(request).await);
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// The answer to a v1 cluster token (always refused): a 401 whose
/// body names the cause and the fix, so a node that missed its upgrade says
/// why in its own log instead of looking like a bad secret.
fn v1_refusal() -> Response {
    use axum::response::IntoResponse;
    let body = axum::Json(serde_json::json!({
        "error": "v1 cluster tokens are refused: this caller signs the old, replayable form",
        "code": "cluster_token_v1_refused",
        "fix": "upgrade the node agents (`noo upgrade --nodes`) so they sign v2; there is no switch to re-admit v1",
    }));
    (StatusCode::UNAUTHORIZED, body).into_response()
}

/// Verify a v2 cluster token against the request it arrived on and spend its
/// nonce. On success returns a v1-shaped token for the verified actor (see
/// the call site); every failure is a 401 and says nothing about which check
/// failed. Fleet secret only: the controller secret admits nothing, so a v2
/// token under it is simply invalid.
///
/// Buffers the body (bounded) to hash it and puts it back for the handler.
async fn admit_cluster_token_v2(
    state: &Arc<AppState>,
    request: &mut Request,
    presented: &str,
) -> Result<String, StatusCode> {
    // Header only: a `?token=` bearer cannot be bound to a URI that contains it.
    let from_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|h| h == presented);
    let Some(secret) = crate::config::secret_env::secret_opt("NOO_CLUSTER_SECRET") else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if !from_header {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cheap refusals first (shape, window) so a flood of junk never buffers a body.
    let Some(parsed) = crate::cluster_token_v2::parse(presented) else { return Err(StatusCode::UNAUTHORIZED) };
    if now.abs_diff(parsed.ts) > crate::cluster_token_v2::WINDOW_SECS {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let req = std::mem::replace(request, Request::new(axum::body::Body::empty()));
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, crate::cluster_token_v2::MAX_SIGNED_BODY).await {
        Ok(b) => b,
        Err(_) => {
            *request = Request::from_parts(parts, axum::body::Body::empty());
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    let uri = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| parts.uri.path().to_string());
    let verdict = crate::cluster_token_v2::verify_and_spend(
        state.redis.as_ref(),
        &secret,
        presented,
        parts.method.as_str(),
        &uri,
        &bytes,
        now,
    )
    .await;
    *request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let Some(actor) = verdict else {
        tracing::warn!(path = %request.uri().path(), "cluster token v2 refused: bad signature, wrong request, or nonce already used (replay)");
        return Err(StatusCode::UNAUTHORIZED);
    };
    crate::routes::cluster::mint_cluster_token(&actor, &secret, now).ok_or(StatusCode::UNAUTHORIZED)
}

/// Build a 429 for a consumer that has exceeded its per-minute quota.
/// `retry_after` is seconds until the window resets (always >= 0 from
/// `check_consumer_quota`).
pub(crate) fn consumer_quota_exceeded(consumer: &str, retry_after: i64) -> Response {
    use axum::response::IntoResponse;
    let body = axum::Json(serde_json::json!({
        "error": {
            "message": format!("consumer '{consumer}' exceeded its per-minute request quota"),
            "type": "rate_limit_exceeded",
            "retry_after": retry_after,
        }
    }));
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
    if let Ok(v) = retry_after.to_string().parse() {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

/// Test-only token minting, mirroring the Go node-agent's CreateClusterToken
/// (`<node>:<ts>:<full 64-hex hmac>`), so the tests exercise the real format
/// rather than a hand-rolled approximation of it.
#[cfg(test)]
mod tests_support {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    pub fn mint(secret: &str, node: &str, ts: u64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{node}:{ts}").as_bytes());
        format!("{node}:{ts}:{}", hex::encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod credential_optional_tests {
    use super::*;

    /// `/health` was a public PREFIX, which made every future `/health…`
    /// route public by accident — the same trap `/metrics` was moved out
    /// of. It is an EXACT credential-optional path now.
    #[test]
    fn health_is_no_longer_a_public_prefix() {
        assert!(
            !PUBLIC_PATH_PREFIXES.contains(&"/health"),
            "/health is a public prefix again: /healthz, /health-admin and any future \
             neighbour would bypass auth with it"
        );
        assert!(is_credential_optional("/health"));
    }

    /// Exact match, so a neighbour cannot inherit the carve-out.
    #[test]
    fn a_health_lookalike_is_not_credential_optional() {
        for p in ["/healthz", "/health/detail", "/health-admin", "/healthcheck"] {
            assert!(!is_credential_optional(p), "{p} inherited /health's carve-out");
        }
    }

    /// The whole point: anonymous passes through, a bearer does not. If
    /// this flips, the handler never sees a RequesterCtx and every
    /// authenticated caller silently gets the anonymous body.
    #[test]
    fn the_carve_out_applies_only_when_nothing_is_presented() {
        // Mirrors the middleware's condition rather than restating it:
        // `is_credential_optional(path) && bearer is none`.
        let bypasses = |has_bearer: bool| is_credential_optional("/health") && !has_bearer;
        assert!(bypasses(false), "an anonymous /health must not need a credential");
        assert!(!bypasses(true), "a /health WITH a bearer must be authenticated normally");
    }
}


#[cfg(test)]
mod tests {

    fn addon_claims(sub: &str, scopes: &[&str]) -> super::Claims {
        super::Claims {
            sub: sub.into(),
            exp: 4_102_444_800,
            role: "user".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            harness: None,
            conv: None,
            act: None,
            cnf: None,
        }
    }

    /// The token the door mints must be able to use the surface it was
    /// minted for. The tier gate alone refuses it (that is the 2026-09-22
    /// failure, pinned here so it stays a failure of the gate and not of
    /// the door); `addon_consumer` is what admits it.
    #[test]
    fn an_exchanged_addon_token_is_its_consumer_on_the_external_door() {
        use axum::http::Method;
        let c = addon_claims("addon:svc:trellion-intel", &["chat", "embeddings"]);
        assert!(
            !super::scope_allows(&c, &Method::POST, "/api/external/embeddings"),
            "the tier gate would admit it on its own — this test no longer pins anything"
        );
        let consumer = super::addon_consumer(&c, true).expect("admitted on the inference surface");
        assert_eq!(consumer.name, "svc:trellion-intel", "audited under the key's own name");
        assert_eq!(consumer.scopes, vec!["chat".to_string(), "embeddings".to_string()]);
        assert!(!consumer.scopes.iter().any(|s| s == "rerank"), "the key's scopes, not Consumer::all");
        assert!(consumer.rpm_limit.is_none() && consumer.user.is_none());
    }

    #[test]
    fn an_addon_token_off_the_inference_surface_stays_a_user_token() {
        let c = addon_claims("addon:svc:trellion-intel", &["chat", "embeddings"]);
        assert!(super::addon_consumer(&c, false).is_none());
        // Not an add-on token at all: the prefix decides, not the scopes.
        let u = addon_claims("alice", &["chat", "embeddings"]);
        assert!(super::addon_consumer(&u, true).is_none());
        // A bare prefix names nobody.
        let bare = addon_claims("addon:", &["chat"]);
        assert!(super::addon_consumer(&bare, true).is_none());
    }

    /// An exchanged add-on token must not be able to exchange again.
    ///
    /// `addon` is the scope that opens the door. Leaving it on the minted
    /// token would make that token self-renewing — it would outlive the
    /// revocation of the key it came from, which is the one property the
    /// short lifetime exists to deny.
    #[test]
    fn an_exchanged_addon_token_cannot_open_the_door_again() {
        let key_scopes = vec!["addon".to_string(), "chat".to_string(), "embeddings".to_string()];
        let minted = super::addon_token_scopes(&key_scopes);
        assert!(!minted.contains(&super::ADDON_SCOPE.to_string()),
            "the minted token still carries `addon` and can renew itself past a revocation");
        assert_eq!(minted, vec!["chat".to_string(), "embeddings".to_string()],
            "everything else the key carries must survive");
    }

    /// The door table is what makes a third consumer cheap. If the add-on
    /// path stopped resolving, the handler would be reachable by any
    /// credential the middleware happens to accept next.
    #[test]
    fn a_key_with_a_declared_addon_scope_exchanges_for_a_token_that_can_read_it() {
        let declared = vec!["evolve:read_items".to_string()];
        let key = vec!["addon".to_string(), "evolve:read_items".to_string()];
        let t = super::addon_token_scopes_with(&key, &declared);
        assert_eq!(t, vec!["evolve:read_items".to_string(), "read".to_string()]);
        let plain = super::addon_token_scopes_with(&["addon".to_string(), "chat".to_string()], &declared);
        assert_eq!(plain, vec!["chat".to_string()], "no add-on scope, no read");
    }

    #[test]
    fn the_addon_path_is_an_exchange_door_and_only_for_post() {
        use axum::http::Method;
        assert_eq!(
            super::exchange_scope_for(super::ADDON_TOKEN_PATH, &Method::POST),
            Some(super::ADDON_SCOPE)
        );
        assert_eq!(super::exchange_scope_for(super::ADDON_TOKEN_PATH, &Method::GET), None);
    }

    /// Every exchange door names its own scope, and none is the kiosk
    /// token's marker. A shared scope would let one door's key mint
    /// another's token, which is the whole reason each door names its own.
    #[test]
    fn the_exchange_doors_do_not_share_a_scope() {
        let scopes = [super::KIOSK_SCOPE, super::IDENTITY_SCOPE, super::ADDON_SCOPE];
        let mut sorted = scopes;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), scopes.len(), "two doors share a scope: {scopes:?}");
    }

    /// The subject is namespaced, so `addon:trellion` can never be mistaken
    /// for a user named `trellion` by anything reading `sub`.
    #[test]
    fn an_addon_token_is_namespaced_and_carries_only_its_own_scopes() {
        let t = super::mint_addon_jwt(
            "trellion-intel", &["chat".to_string()], 600, T_SECRET, None,
        )
        .expect("mint");
        let c = claims_of(&t);
        assert_eq!(c["sub"], "addon:trellion-intel");
        assert_eq!(c["scopes"], serde_json::json!(["chat"]));
        assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 600);
        assert_eq!(alg_of(&t), "HS256", "no signing key configured -> symmetric");
    }

    /// Same rule as an exchanged agent token: asymmetric when a key exists,
    /// so an add-on's token can be verified by something that cannot mint one.
    #[test]
    fn an_addon_token_is_signed_from_the_jwks_key_when_there_is_one() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key = crate::jwks::parse(&kp.serialize_pem()).expect("generated key parses");
        let t = super::mint_addon_jwt("evolve", &["write".to_string()], 600, T_SECRET, Some(&key))
            .expect("mint");
        assert_eq!(alg_of(&t), "ES256", "a configured signing key must be used");
    }

    // ── Characterisation: what each mint PRODUCES ────────────────────────
    //
    // Written to pin the claim sets before four copies of the skeleton became
    // one, and kept because that is exactly what a future tidy-up would
    // flatten. Each credential is verified by a different rule; a claim that
    // quietly changes shape here changes who a token authenticates as.
    //
    // Keys are passed in, never set through the environment: tests share one
    // process, and `set_var` from one is read by all the others.

    const T_SECRET: &str = "characterisation-secret-not-a-real-key-000000";

    fn claims_of(token: &str) -> serde_json::Value {
        let mid = token.split('.').nth(1).expect("a jwt has three parts");
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mid)
            .expect("payload is base64url");
        serde_json::from_slice(&raw).expect("payload is json")
    }

    fn alg_of(token: &str) -> String {
        let head = token.split('.').next().expect("a jwt has a header");
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(head).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        v["alg"].as_str().unwrap_or_default().to_string()
    }

    #[test]
    fn a_harness_token_carries_exactly_these_claims() {
        let t = super::mint_harness_jwt_with("an-operator", Role::Operator, "host3", "conv-1", 300, T_SECRET)
            .expect("mint");
        let c = claims_of(&t);
        let mut keys: Vec<&str> = c.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["aud", "conv", "exp", "harness", "iat", "iss", "role", "scopes", "sub"]);
        assert_eq!(c["sub"], "an-operator");
        assert_eq!(c["conv"], "conv-1");
        assert_eq!(c["harness"], format!("{}{}", super::HARNESS_NODE_PREFIX, "host3"));
        assert_eq!(c["iss"], super::JWT_ISSUER);
        assert_eq!(c["aud"], super::JWT_AUDIENCE);
        assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 300);
        assert_eq!(alg_of(&t), "HS256", "the harness token is symmetric");
    }

    /// What a harness token's `sub` IS. `tasks::start` mints
    /// it for the task's OWNER (`noo_users.username`, a bare account), and
    /// `scoped_claims` writes the subject verbatim: there is no
    /// `<account>/<connection>` suffix on a harness token (that shape is the
    /// identity plane's `connection_subject`, for door credentials). The
    /// loop's `mcp_bridge::CALLER` is this `sub`, so a node loop reads as
    /// the bare account, whose account-wide rule is `Filter::owner`.
    #[test]
    fn a_harness_token_for_an_owner_is_the_bare_account_not_a_connection() {
        let t = super::mint_harness_jwt_with("bob", Role::User, "node-a", "conv-9", 300, T_SECRET).expect("mint");
        let c = claims_of(&t);
        assert_eq!(c["sub"], "bob");
        assert_eq!(super::account_of(c["sub"].as_str().unwrap()), "bob");
        assert!(!c["sub"].as_str().unwrap().contains(super::CONNECTION_SEP));
        assert_eq!(c["harness"], "node:node-a");
    }

    #[test]
    fn a_kiosk_token_carries_exactly_these_claims() {
        let t = super::mint_kiosk_jwt_with("host5", 600, T_SECRET).expect("mint");
        let c = claims_of(&t);
        let mut keys: Vec<&str> = c.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["aud", "exp", "iat", "iss", "role", "scopes", "sub"]);
        assert_eq!(c["sub"], "kiosk:host5", "the kiosk subject is prefixed");
        assert_eq!(c["scopes"], serde_json::json!([super::KIOSK_SCOPE]));
        assert_eq!(c["role"], Role::User.as_str());
        assert_eq!(alg_of(&t), "HS256");
    }

    // ── Grafana session token ──────────────────────────

    fn grafana_test_key() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey, crate::jwks::SigningKey) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = kp.serialize_pem();
        let parsed = crate::jwks::parse(&pem).expect("a generated P-256 key parses");
        let enc = jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let dec = parsed.decoding.clone();
        (enc, dec, parsed)
    }

    fn header_of(token: &str) -> serde_json::Value {
        let head = token.split('.').next().expect("a jwt has a header");
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(head).unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    /// The claim set Grafana's `expect_claims` + `username_claim` +
    /// `role_attribute_path` read, and nothing else. ES256, and NO `kid`:
    /// Grafana builds a one-key set from `key_file` with `KeyID = key_id`
    /// (unset), and a token `kid` that does not match it fails.
    #[test]
    fn the_grafana_token_claim_shape_is_pinned() {
        let (enc, dec, _) = grafana_test_key();
        let t = super::mint_grafana_jwt_with("an-operator", Role::Operator, 900, &enc).expect("mint");
        let c = claims_of(&t);
        let mut keys: Vec<&str> = c.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["aud", "exp", "grafana_role", "iat", "iss", "jti", "role", "sub"]);
        assert_eq!(c["grafana_role"], "Editor");
        assert_eq!(c["aud"], super::GRAFANA_AUDIENCE);
        assert_eq!(c["iss"], super::JWT_ISSUER);
        assert_eq!(c["sub"], "an-operator");
        assert_eq!(c["role"], "operator");
        assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 900);
        assert!(!c["jti"].as_str().unwrap().is_empty());
        let h = header_of(&t);
        assert_eq!(h["alg"], "ES256");
        assert!(h.get("kid").is_none(), "no kid: Grafana's key_file set has no key_id — {h}");

        // Grafana's side of the contract: the public half alone verifies it,
        // with exactly the issuer/audience grafana.ini expects.
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        v.set_issuer(&[super::JWT_ISSUER]);
        v.set_audience(&[super::GRAFANA_AUDIENCE]);
        jsonwebtoken::decode::<serde_json::Value>(&t, &dec, &v).expect("the public half verifies it");

        // Every tier in the table is mintable, carrying the table's role.
        for (r, g) in super::GRAFANA_ORG_ROLES {
            let c = claims_of(&super::mint_grafana_jwt_with("x", *r, 60, &enc).unwrap());
            assert_eq!(c["role"], r.as_str());
            assert_eq!(c["grafana_role"], *g);
        }
    }

    /// The gateway REFUSES its own Grafana token — with a signing key
    /// configured and without one. Planted: minting with `aud =
    /// JWT_AUDIENCE` and the JWKS kid makes the with-key case verify.
    #[test]
    fn the_gateway_refuses_a_grafana_token() {
        let (enc, _, signing) = grafana_test_key();
        let t = super::mint_grafana_jwt_with("an-admin", Role::Admin, 900, &enc).expect("mint");
        // No signing key: ES256 is refused outright.
        let err = super::verify_token_with(&t, T_SECRET, None).expect_err("must refuse");
        assert!(err.contains("ES256"), "{err}");
        // The SAME key configured as the exchange's signing key: still
        // refused — no kid, and the audience is Grafana's.
        let err = super::verify_token_with(&t, T_SECRET, Some(&signing)).expect_err("must refuse");
        assert!(err.contains("kid"), "{err}");
        // The audience check on its own: the MINTED claims, re-signed with
        // the gateway's kid so the only thing standing between this token
        // and acceptance is `aud`. Planted (mint with `aud: JWT_AUDIENCE`)
        // this arm verifies and the test goes red — the two arms above stay
        // red on the kid alone, which is why they cannot prove the audience.
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(signing.kid.clone());
        let with_kid = jsonwebtoken::encode(&header, &claims_of(&t), &signing.encoding).unwrap();
        let err = super::verify_token_with(&with_kid, T_SECRET, Some(&signing))
            .expect_err("the gateway must refuse its own Grafana token on the audience alone");
        assert!(err.to_lowercase().contains("aud"), "{err}");
        assert_ne!(super::GRAFANA_AUDIENCE, super::JWT_AUDIENCE, "the two audiences must differ");
    }

    /// The live-row table: disabled and missing accounts are refused, every
    /// tier that exists is minted as itself.
    #[test]
    fn the_grafana_session_role_comes_from_the_live_row() {
        let open: Result<(), String> = Ok(());
        let f = |l, d| super::grafana_session_role(l, d, &open);
        assert!(f(None, false).is_err(), "no row → refused");
        assert!(f(Some(Role::Admin), true).is_err(), "disabled admin → refused");
        assert!(f(Some(Role::User), true).is_err(), "disabled user → refused");
        assert_eq!(f(Some(Role::User), false), Ok((Role::User, "Viewer")));
        assert_eq!(f(Some(Role::Operator), false), Ok((Role::Operator, "Editor")));
        assert_eq!(f(Some(Role::Admin), false), Ok((Role::Admin, "Admin")));
        // Every refusal says what is needed, never just "no".
        for e in [f(None, false).unwrap_err(), f(Some(Role::User), true).unwrap_err()] {
            assert!(e.contains("needs") && e.contains("user (as Grafana Viewer)"), "{e}");
        }
    }

    /// the design, fail closed. The read-only tier is a Viewer only when
    /// the compose declares the gateway-routed data sources AND the running
    /// Grafana proves it; operators and admins never depend on either.
    #[test]
    fn a_read_only_viewer_needs_the_declaration_and_the_evidence() {
        use super::grafana_viewer_gate as gate;
        let direct = || Some(Err("the prometheus data source dials https://prometheus:9090".to_string()));
        let unreachable = || Some(Err("Grafana did not answer at https://grafana:3000".to_string()));
        // Old compose (an older CLI rolled the stack) + new gateway: refused,
        // whatever the evidence would have said.
        for flag in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
            let e = gate(flag, Some(Ok(()))).expect_err("no declaration, no Viewer");
            assert!(e.contains(super::GRAFANA_DS_GATE_ENV) && e.contains("noo upgrade --all"), "{e}");
        }
        // Declared, but Grafana's data sources still dial directly: refused.
        assert!(gate(Some("1"), direct()).unwrap_err().contains("dials https://prometheus:9090"));
        // Declared, Grafana unreachable: refused.
        assert!(gate(Some("1"), unreachable()).unwrap_err().contains("did not answer"));
        // Declared but never checked: refused.
        assert!(gate(Some("1"), None).is_err());
        // Both: a Viewer.
        assert_eq!(gate(Some(" 1 "), Some(Ok(()))), Ok(()));

        // Through the session-role function: the user tier is refused with
        // the reason; operators and admins are untouched by a closed gate.
        for closed in [gate(None, None), gate(Some("1"), direct()), gate(Some("1"), unreachable())] {
            let e = super::grafana_session_role(Some(Role::User), false, &closed).expect_err("refused");
            assert!(e.contains("opens Grafana only while Grafana's data sources go through the gateway"), "{e}");
            assert!(e.contains("needs"), "{e}");
            assert_eq!(super::grafana_session_role(Some(Role::Operator), false, &closed), Ok((Role::Operator, "Editor")));
            assert_eq!(super::grafana_session_role(Some(Role::Admin), false, &closed), Ok((Role::Admin, "Admin")));
        }
        assert_eq!(
            super::grafana_session_role(Some(Role::User), false, &gate(Some("1"), Some(Ok(())))),
            Ok((Role::User, "Viewer"))
        );
    }

    /// The Grafana role mapping (once the data
    /// sources sat behind the gateway), pinned where it
    /// lives: read-only users are Grafana Viewers, operators Editors, admins
    /// Admins — and never a Grafana SERVER admin.
    #[test]
    fn the_tier_to_grafana_role_table_is_the_operator_decision() {
        assert_eq!(super::grafana_org_role(Role::User), Some("Viewer"));
        assert_eq!(
            super::GRAFANA_ORG_ROLES,
            &[(Role::User, "Viewer"), (Role::Operator, "Editor"), (Role::Admin, "Admin")]
        );
        assert_eq!(super::grafana_org_role(Role::Operator), Some("Editor"));
        assert_eq!(super::grafana_org_role(Role::Admin), Some("Admin"));
        for (_, g) in super::GRAFANA_ORG_ROLES {
            assert!(["Viewer", "Editor", "Admin"].contains(g), "{g} is not a Grafana org role");
        }
        assert!(super::grafana_needs().contains("user (as Grafana Viewer)"));
    }

    #[test]
    fn the_grafana_session_ttl_is_clamped() {
        use super::grafana_session_ttl_secs as f;
        assert_eq!(f(None), 5 * 60);
        assert_eq!(f(Some("junk")), 5 * 60);
        assert_eq!(f(Some("15")), 15 * 60);
        assert_eq!(f(Some("0")), 60);
        assert_eq!(f(Some("600")), super::GRAFANA_SESSION_MAX_MINUTES * 60);
    }

    #[test]
    fn an_agent_token_carries_its_delegation_claim() {
        let t = super::mint_agent_jwt_with(
            "acct/session", Role::User, "svc:thing", Some("an-operator"), 120, None, T_SECRET, None,
        )
        .expect("mint");
        let c = claims_of(&t);
        let mut keys: Vec<&str> = c.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["act", "aud", "exp", "iat", "iss", "role", "scopes", "sub"]);
        assert_eq!(c["act"]["sub"], "key:svc:thing");
        assert_eq!(c["act"]["iss_user"], "an-operator");
        assert_eq!(alg_of(&t), "HS256", "no signing key configured -> symmetric");
    }

    #[test]
    fn a_certificate_bound_agent_token_gains_cnf_and_nothing_else() {
        let t = super::mint_agent_jwt_with(
            "acct/session", Role::User, "svc:thing", None, 120, Some("thumb"), T_SECRET, None,
        )
        .expect("mint");
        let c = claims_of(&t);
        assert_eq!(c["cnf"]["x5t#S256"], "thumb", "RFC 8705 binding must survive");
        assert!(c.get("act").is_some(), "binding must not displace the delegation claim");
    }

    /// An exchanged agent token signs ES256 from the JWKS key when one is
    /// configured — that is the whole phase 3: a third party
    /// verifies from the published JWKS without holding anything that could
    /// mint a token.
    ///
    /// Nothing in the 1094-test suite noticed when that branch was removed.
    /// A downgrade to HS256 keeps every claim identical and every other test
    /// green, and the only visible difference is a header field — so the
    /// header is what this asserts.
    #[test]
    fn an_exchanged_agent_token_is_signed_from_the_jwks_key_when_there_is_one() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key = crate::jwks::parse(&kp.serialize_pem()).expect("a generated P-256 key parses");

        let with_key = super::mint_agent_jwt_with(
            "acct/session", Role::User, "svc:thing", None, 120, None, T_SECRET, Some(&key),
        )
        .expect("mint");
        assert_eq!(
            alg_of(&with_key),
            "ES256",
            "a configured signing key must be USED — HS256 here is a silent downgrade of \
             every exchanged token to a credential only the gateway can verify"
        );

        let head = with_key.split('.').next().unwrap();
        use base64::Engine as _;
        let h: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(head).unwrap(),
        )
        .unwrap();
        assert_eq!(h["kid"], key.kid, "without a kid a verifier cannot pick the key across a rotation");

        // Same call, no key: the symmetric fallback is still there.
        let without = super::mint_agent_jwt_with(
            "acct/session", Role::User, "svc:thing", None, 120, None, T_SECRET, None,
        )
        .expect("mint");
        assert_eq!(alg_of(&without), "HS256", "no key configured must still mint");
    }

    /// The skeleton is shared; the SIGNING is not. Flattening that is the
    /// tidy-up that would quietly downgrade an exchanged agent token from a
    /// key a third party can verify to one that needs the minting secret.
    #[test]
    fn every_mint_refuses_an_insecure_secret() {
        // The literal the gateway ships as a placeholder — not a guess at
        // what "weak" means. `jwt_secret_is_insecure` is empty-or-default,
        // so a made-up weak-looking string would make this test pass for the
        // wrong reason and prove nothing.
        let weak = super::INSECURE_DEFAULT_JWT_SECRET;
        assert!(super::jwt_secret_is_insecure(weak), "fixture must actually be refused");
        assert!(super::jwt_secret_is_insecure(""), "an empty secret is refused too");
        assert!(super::mint_harness_jwt_with("u", Role::User, "n", "c", 60, weak).is_none());
        assert!(super::mint_kiosk_jwt_with("k", 60, weak).is_none());
        assert!(
            super::mint_agent_jwt_with("a/b", Role::User, "c", None, 60, None, weak, None).is_none()
        );
    }

    // ── cluster_token_subject: identity that was always on the wire ────────
    //
    // The token has always been `<node>:<ts>:<hmac>`; nothing read the first
    // field. These pin that reading it cannot become a way IN — the subject is
    // returned only for a token that already verifies.

    #[test]
    fn subject_is_returned_only_for_a_token_that_verifies() {
        let secret = "s3cret";
        let now = 1_700_000_000u64;
        let good = super::tests_support::mint(secret, "host8", now);
        assert!(super::verify_cluster_token_inner(&good, secret, now));

        // Same token, wrong secret: no subject, because no verification.
        assert!(!super::verify_cluster_token_inner(&good, "other", now));
    }

    /// The whole point: a node's own name, not one it asks for.
    #[test]
    fn subject_is_the_signed_field_not_an_arbitrary_prefix() {
        let secret = "s3cret";
        let now = 1_700_000_000u64;
        let tok = super::tests_support::mint(secret, "host9", now);
        assert_eq!(tok.split(':').next(), Some("host9"));

        // Rewriting the subject invalidates the signature — which is what
        // makes the handler's caller==node_id check meaningful rather than
        // decorative. Without this property a node could simply claim to be
        // its neighbour.
        let forged = format!("host8:{}", tok.split_once(':').unwrap().1);
        assert!(
            !super::verify_cluster_token_inner(&forged, secret, now),
            "a rewritten subject must not verify — otherwise per-node authz is theatre"
        );
    }
    use super::*;
    use axum::http::Method;

    fn req(uri: &str, header: Option<(&str, &str)>) -> Request {
        let mut b = axum::http::Request::builder().uri(uri);
        if let Some((k, v)) = header {
            b = b.header(k, v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn query_token_only_honored_for_real_websocket_handshakes() {
        // The rule is path AND header, not path OR header:
        // `?token=` is honoured only on a genuine WebSocket handshake to a
        // `/ws/*` route. Everywhere else the JWT would land in every access
        // log between the client and here, and in browser history.

        // Plain HTTP route, no upgrade → ignored (M-A2, unchanged).
        assert_eq!(bearer_token(&req("/api/config?token=leakme", None)), None);

        // A real handshake on the WS surface → accepted. This is the only
        // shape that may use the query string, because a browser cannot set
        // an Authorization header on `new WebSocket(...)`.
        for path in ["/ws", "/ws/agent", "/ws/coordinator", "/ws/collab"] {
            assert_eq!(
                bearer_token(&req(
                    &format!("{path}?token=wsjwt"),
                    Some(("upgrade", "websocket"))
                ))
                .as_deref(),
                Some("wsjwt"),
                "{path} is a WebSocket route and a real handshake must still \
                 authenticate from ?token=; breaking this logs every dashboard \
                 socket out"
            );
        }

        // THE FIX (R7): an `Upgrade: websocket` header on a NON-WS path no
        // longer unlocks the query string. Previously this authenticated,
        // which meant any route at all could be called as
        // `?token=<jwt>` — the header is free for a client to set.
        assert_eq!(
            bearer_token(&req("/api/config?token=up", Some(("upgrade", "websocket")))),
            None,
            "an Upgrade header on a non-/ws path must NOT unlock ?token=: the \
             header is client-controlled, so path-OR-header let a JWT ride the \
             query string of every route into the proxy logs"
        );

        // ...and the mirror image: a `/ws/*` path with NO handshake header is
        // not a WebSocket, so it gets no query-string credential either.
        assert_eq!(
            bearer_token(&req("/ws/agent?token=notahandshake", None)),
            None,
            "a /ws path without Upgrade: websocket is a plain HTTP request and \
             must not authenticate from the query string"
        );

        // `/wsdl` is not the WebSocket surface — the prefix test must be
        // path-segment aware, not a bare starts_with(\"/ws\").
        assert_eq!(
            bearer_token(&req("/wsdl?token=nope", Some(("upgrade", "websocket")))),
            None,
            "/wsdl must not count as the /ws surface"
        );

        // Token-list and casing, both of which the spec permits.
        assert_eq!(
            bearer_token(&req("/ws/agent?token=t", Some(("upgrade", "WebSocket")))).as_deref(),
            Some("t"),
            "the Upgrade header is case-insensitive by spec"
        );
        assert_eq!(
            bearer_token(&req("/ws/agent?token=t", Some(("upgrade", "websocket, h2c"))))
                .as_deref(),
            Some("t"),
            "the Upgrade header is a token list by spec"
        );

        // Authorization header always wins, on any route.
        assert_eq!(
            bearer_token(&req("/api/config", Some(("authorization", "Bearer hdr")))).as_deref(),
            Some("hdr")
        );

        // A stray `?token=` must not break a request that authenticates
        // properly: the header is honoured and the query param is ignored.
        assert_eq!(
            bearer_token(&req(
                "/api/config?token=stray",
                Some(("authorization", "Bearer hdr"))
            ))
            .as_deref(),
            Some("hdr"),
            "a stray ?token= is ignored, never an error"
        );
    }

    #[test]
    fn channel_webhook_paths_are_no_longer_public() {
        // Regression guard for the ingress removal: these used to bypass
        // bearer auth. Nothing should re-add them without a deliberate
        // decision, because inbound channels are pull-based and need no
        // public endpoint at all.
        for path in [
            "/api/channels/whatsapp/webhook",
            "/api/channels/google_chat/webhook",
            "/api/channels/telegram/webhook",
            "/api/channels/slack/webhook",
        ] {
            assert!(
                !PUBLIC_PATHS_EXACT.contains(&path),
                "{path} must not be public"
            );
            assert!(
                !PUBLIC_PATH_PREFIXES.iter().any(|p| path.starts_with(p)),
                "{path} must not be public"
            );
        }
    }

    // `/metrics` was a PREFIX, so anything a
    // ── the kiosk credential ────────────────────────────────

    fn kiosk_claims() -> Claims {
        Claims { sub: "kiosk:hall".into(), exp: 4_102_444_800, role: "user".into(),
                 scopes: vec![KIOSK_SCOPE.into()], harness: None, conv: None, act: None, cnf: None }
    }

    /// Acceptance 1. A write is refused on every path, including one that
    /// did not exist when this was written and one the display is allowed
    /// to READ. Doing it in middleware rather than per handler is what
    /// makes the future-route case hold.
    #[test]
    fn a_kiosk_credential_may_read_and_may_do_nothing_else() {
        use axum::http::Method;
        let c = kiosk_claims();
        assert!(is_kiosk(&c));
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(kiosk_may(&m, "/api/cluster/status"), Ok(()), "{m}");
        }
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            // …on an allowlisted path, on an unrelated one, and on a route
            // nobody has registered.
            for p in ["/api/cluster/status", "/api/users", "/api/invented/next/year"] {
                assert_eq!(
                    kiosk_may(&m, p),
                    Err(KioskRefusal::ReadOnly),
                    "{m} {p} must be refused for every path, present or future"
                );
            }
        }
        // The refusal is a 403 with its own type, not a 401: the display
        // renders "not permitted" and the launcher does not re-mint.
        assert_eq!(kiosk_refusal(KioskRefusal::ReadOnly).status(), StatusCode::FORBIDDEN);
        assert_eq!(kiosk_refusal(KioskRefusal::OutOfScope).status(), StatusCode::FORBIDDEN);
    }

    /// Acceptance 1b, and the reason this scope exists. Method-only
    /// enforcement left every GET in the API open to a credential on an
    /// unattended machine. These are the reads a display has no business
    /// making, and each one was reachable before the allowlist.
    #[test]
    fn a_kiosk_credential_cannot_read_what_is_not_on_the_screen() {
        use axum::http::Method;
        for p in [
            "/api/security/service-keys",
            "/api/users",
            "/api/conversations",
            "/api/v1/rag/query",
            "/api/memory/search",
            // A route added after this line was written: closed by default,
            // which is the property the write refusal already had.
            "/api/invented/next/year",
        ] {
            assert_eq!(
                kiosk_may(&Method::GET, p),
                Err(KioskRefusal::OutOfScope),
                "{p} is readable by a kiosk token — a display draws a dashboard, not the API"
            );
        }
    }

    /// The display must still be able to draw. Every source the page
    /// fetches, plus the projection surface, must pass — otherwise this
    /// scope is a blank screen rather than a boundary.
    #[test]
    fn every_source_the_display_actually_fetches_is_allowed() {
        use axum::http::Method;
        for p in KIOSK_READ_PATHS {
            assert_eq!(kiosk_may(&Method::GET, p), Ok(()), "{p}");
        }
        for p in ["/api/kiosk/nodes", "/api/kiosk/gpus", "/api/kiosk/graph"] {
            assert_eq!(kiosk_may(&Method::GET, p), Ok(()), "{p}");
        }
        // Guard the guard: an empty allowlist would make the loop above
        // vacuous and the refusal test pass for the wrong reason.
        assert!(KIOSK_READ_PATHS.len() >= 8, "the allowlist lost entries");
    }

    /// Acceptance 2. Whatever the bound account holds, the token the key
    /// buys carries `["kiosk"]` and `user` — and resolves to `User`, so the
    /// tier gate cannot be argued upward from the role claim either.
    #[test]
    fn a_minted_kiosk_token_carries_exactly_the_kiosk_scope() {
        std::env::set_var("NOO_JWT_SECRET", "a-secret-long-enough-to-not-be-the-insecure-default-0123456789");
        let tok = mint_kiosk_jwt("hall", 900).expect("mints with a secret");
        let claims = verify_token(&tok, &jwt_secret()).expect("verifies");
        assert_eq!(claims.sub, "kiosk:hall");
        assert_eq!(claims.scopes, vec![KIOSK_SCOPE.to_string()]);
        assert_eq!(claims.role, "user");
        assert_eq!(claims.resolved_role(), Role::User);
        assert!(claims.harness.is_none() && claims.conv.is_none());
        assert!(is_kiosk(&claims));
        std::env::remove_var("NOO_JWT_SECRET");
    }

    /// Fail closed: no usable secret, no token. A kiosk on a gateway whose
    /// JWTs are forgeable would be a kiosk on a gateway that accepts no
    /// JWTs at all, so there is nothing sensible to mint.
    #[test]
    fn no_secret_no_kiosk_token() {
        std::env::remove_var("NOO_JWT_SECRET");
        assert!(mint_kiosk_jwt("hall", 900).is_none());
        std::env::set_var("NOO_JWT_SECRET", "dev-secret-change-in-production");
        assert!(mint_kiosk_jwt("hall", 900).is_none());
        std::env::remove_var("NOO_JWT_SECRET");
    }

    /// The retired kiosk KEY lane admits nothing. No exchange door opens
    /// on `/api/kiosk/token` for any method, so a kiosk-scoped key reaching
    /// the middleware there matches no credential class and gets the plain
    /// 401 (and the router has no such route). If the door row comes back,
    /// this fails.
    #[test]
    fn the_kiosk_key_lane_is_not_an_exchange_door() {
        use axum::http::Method;
        for m in [Method::POST, Method::GET] {
            assert_eq!(super::exchange_scope_for("/api/kiosk/token", &m), None, "{m}");
        }
        // No door takes the kiosk scope, under any path.
        for path in [super::IDENTITY_TOKEN_PATH, super::ADDON_TOKEN_PATH, KIOSK_TOKEN_TAILNET_PATH] {
            assert_ne!(super::exchange_scope_for(path, &Method::POST), Some(KIOSK_SCOPE), "{path}");
        }
    }

    /// The keyless mint is public, and the retired KEY lane's path is not:
    /// if `/api/kiosk/token` ever became public, a stranger would reach
    /// whatever answered there with no credential and no tailnet proof.
    #[test]
    fn the_keyless_mint_is_public_and_the_key_lane_is_not() {
        assert_eq!(KIOSK_TOKEN_TAILNET_PATH, "/api/kiosk/token/tailnet");
        assert!(
            PUBLIC_PATHS_EXACT.contains(&KIOSK_TOKEN_TAILNET_PATH),
            "the keyless mint must be reachable without a credential — the display has none"
        );
        assert!(
            !PUBLIC_PATHS_EXACT.contains(&"/api/kiosk/token"),
            "the retired KEY lane's path must never be public"
        );
        // Exact, not prefix: a neighbour under the same path must not
        // inherit the exemption.
        for neighbour in ["/api/kiosk/token/tailnet/x", "/api/kiosk/nodes", "/api/kiosk/"] {
            assert!(
                !PUBLIC_PATHS_EXACT.contains(&neighbour),
                "{neighbour} must not be public"
            );
        }
    }

    /// Acceptance 4. The page is public on its two exact paths; a
    /// neighbour is not, and neither path is a prefix entry.
    #[test]
    fn the_kiosk_page_is_public_on_exact_paths_only() {
        let is_public = |path: &str| {
            PUBLIC_PATHS_EXACT.contains(&path)
                || PUBLIC_PATH_PREFIXES.iter().any(|p| path.starts_with(p))
        };
        assert!(is_public("/kiosk.html"));
        assert!(is_public("/kiosk"));
        for path in ["/kiosk.html/x", "/kiosk/", "/kiosk/x", "/kioskadmin", "/api/kiosk/nodes", "/api/kiosk/token", "/api/events/stream"] {
            assert!(!is_public(path), "{path} must stay authenticated");
        }
        assert!(!PUBLIC_PATH_PREFIXES.contains(&"/kiosk"));
    }

    // `/metrics` was an exact public path until 2026-09-25; the scraper now
    // authenticates by its service leaf and people by an operator login.
    #[test]
    fn metrics_is_not_public_anywhere() {
        let is_public = |path: &str| {
            PUBLIC_PATHS_EXACT.contains(&path)
                || PUBLIC_PATH_PREFIXES.iter().any(|p| path.starts_with(p))
                || PUBLIC_GET_PATH_PREFIXES.iter().any(|p| path.starts_with(p))
        };
        for path in ["/metrics", "/metrics/raw", "/api/metrics/query", "/api/metrics/range", "/api/metrics/discover", "/api/alerts/list", "/api/metrics/increment", "/api/metrics/gauge"] {
            assert!(!is_public(path), "{path} must authenticate");
        }
    }

    /// Operators read metrics; a User-tier token, which reads every other
    /// GET, does not — and neither does an add-on's exchanged token.
    #[test]
    fn metric_reads_are_operator_and_admin_only() {
        let user = claims_with(&["read"]);
        let operator = Claims { role: "operator".into(), ..claims_with(&[]) };
        let admin = Claims { role: "admin".into(), ..claims_with(&[]) };
        for path in METRICS_READ_PATHS {
            assert!(!scope_allows(&user, &Method::GET, path), "user tier must not read {path}");
            assert!(scope_allows(&operator, &Method::GET, path), "operator reads {path}");
            assert!(scope_allows(&admin, &Method::GET, path), "admin reads {path}");
        }
        let addon = claims_with(&["metrics", "temporal"]);
        assert!(!scope_allows(&addon, &Method::GET, "/metrics"), "the add-on WRITE scope reads nothing");
        assert!(scope_allows(&user, &Method::GET, "/api/cluster/status"), "other reads are unchanged");
    }

    /// The user door (`POST /mcp/user`) serves `mcp-tools.json` and runs each
    /// call under the caller's own User-tier JWT. A tool on that manifest
    /// whose route the tier gate refuses to a User is a tool that is
    /// advertised and can never work (`noo_metrics_query` was: tagged
    /// `external`, path in `METRICS_READ_PATHS`). This asks the REAL
    /// classifier, for every manifest entry, with the richest token the door
    /// mints for a User (`read` + `ingest`, `mint_caller_jwt`).
    #[test]
    fn user_door_manifest_tools_are_callable_by_a_user_token() {
        // Tools deliberately listed although the User tier is refused.
        // An entry here is a decision, not a convenience: new tools get no pass.
        const KNOWN_REFUSED: &[&str] = &[
            // Found by this test: advertised on the user door,
            // refused to a User-tier token by the tier gate (POST/DELETE
            // outside CHAT_QUERY_PREFIXES). Each is a decision the operator
            // owes: widen the User tier for it, or take it off the user
            // manifest. This list may only SHRINK.
            "noo_agentic_inference",
        ];

        let raw = include_str!("../mcp-tools.json");
        let v: serde_json::Value = serde_json::from_str(raw).expect("mcp-tools.json parses");
        let tools = v.get("tools").and_then(|t| t.as_array()).cloned()
            .or_else(|| v.as_array().cloned())
            .expect("mcp-tools.json has a tools array");
        assert!(tools.len() >= 20, "the parse found {} tools - vacuous", tools.len());

        // `graph` is modelled on purpose: the six `noo_graph_*` query tools are
        // callable by a User token THAT HOLDS THE SCOPE they need (per account,
        // `noo security user set-scopes`). The plain-read refusal is pinned
        // separately below and in `a_plain_read_user_is_refused_every_graph_post`.
        let user = Claims { role: "user".into(), ..claims_with(&["read", "ingest", "graph"]) };
        assert_eq!(user.resolved_role(), Role::User);
        let plain_read = Claims { role: "user".into(), ..claims_with(&["read"]) };
        for t in &tools {
            let name = t["name"].as_str().unwrap();
            if name.starts_with("noo_graph_") && GRAPH_QUERY_PATHS.contains(&t["path"].as_str().unwrap()) {
                let m = Method::from_bytes(t["method"].as_str().unwrap().to_uppercase().as_bytes()).unwrap();
                assert!(!scope_allows(&plain_read, &m, t["path"].as_str().unwrap()), "{name}: plain read must stay refused");
            }
        }

        let mut checked = 0;
        let mut refused: Vec<String> = Vec::new();
        for t in &tools {
            let name = t["name"].as_str().expect("tool name");
            // `{job_id}`-style templates are filled the way the door does, with a
            // concrete id (the job routes accept only a UUID-shaped one).
            let templated = t["path"].as_str().expect("tool path").replace("{job_id}", "0f9c1d2e-0000-4000-8000-000000000001");
            let path = templated.as_str();
            let method = Method::from_bytes(t["method"].as_str().expect("tool method").to_uppercase().as_bytes())
                .expect("tool method is an HTTP method");
            assert!(path.starts_with('/'), "{name}: path {path:?}");
            checked += 1;
            if !scope_allows(&user, &method, path) && !KNOWN_REFUSED.contains(&name) {
                refused.push(format!("{name} ({method} {path})"));
            }
        }
        assert!(checked >= 20, "only {checked} tools checked");
        // The tripwire is live: the classifier does refuse a User something.
        assert!(!scope_allows(&user, &Method::GET, "/api/metrics/query"));
        assert!(
            refused.is_empty(),
            "user-door tools the gateway refuses to a User-tier token (drop `external` from their tags, or list them in KNOWN_REFUSED on purpose): {refused:?}"
        );
    }

    /// Logs are the whole installation's output; operators read them and a
    /// User-tier token does not, whether the route is a GET or a POST.
    #[test]
    fn log_reads_are_operator_and_admin_only() {
        let user = claims_with(&["read"]);
        let operator = Claims { role: "operator".into(), ..claims_with(&[]) };
        let admin = Claims { role: "admin".into(), ..claims_with(&[]) };
        for (m, path) in [
            (Method::GET, "/api/logs/query"),
            (Method::GET, "/api/logs/status"),
            (Method::GET, "/api/logs/containers"),
            (Method::GET, "/api/logs/docker-stats"),
            (Method::GET, "/api/logs/node/host3/noo-vllm"),
            (Method::POST, "/api/logs/tail"),
            (Method::POST, "/api/logs/errors"),
        ] {
            assert!(!scope_allows(&user, &m, path), "user tier must not read {path}");
            assert!(scope_allows(&operator, &m, path), "operator reads {path}");
            assert!(scope_allows(&admin, &m, path), "admin reads {path}");
        }
        let addon = claims_with(&["metrics", "temporal", "heartbeat"]);
        assert!(!scope_allows(&addon, &Method::GET, "/api/logs/query"), "no add-on scope reads logs");
        // Request traces (i359) are the same kind of read: every account's routes.
        for path in ["/api/traces/status", "/api/traces/requests"] {
            assert!(!scope_allows(&user, &Method::GET, path), "user tier must not read {path}");
            assert!(!scope_allows(&addon, &Method::GET, path), "no add-on scope reads {path}");
            assert!(scope_allows(&operator, &Method::GET, path), "operator reads {path}");
        }
        // The logs gate is a directory prefix, not a stem. (A User tier no longer
        // reads /api/logsomething for another reason: its GETs are an allow-list.)
        assert!(!"/api/logsomething".starts_with(LOGS_READ_PREFIX), "the prefix is a directory, not a stem");
    }

    /// on the Grafana data-source routes `X-Grafana-User` is
    /// believed from Grafana's verified leaf ONLY. A forged header from any
    /// other caller — no certificate, the scraper's leaf, a node's — is
    /// refused, whatever login it names.
    #[test]
    fn a_forged_grafana_user_header_is_refused_from_anyone_but_grafana() {
        use crate::node_identity::VerifiedService;
        let mut h = axum::http::HeaderMap::new();
        h.insert(GRAFANA_USER_HEADER, "an-operator".parse().unwrap());
        let graf = VerifiedService(GRAFANA_SERVICE.into());
        let prom = VerifiedService("prometheus".into());
        let node_named_grafana_is_not_a_service = None;
        for svc in [None, Some(&prom), node_named_grafana_is_not_a_service] {
            let e = grafana_ds_identity(svc, &h).expect_err("a header from a non-Grafana caller is a claim");
            assert!(e.contains("Grafana's own service leaf only"), "{e}");
        }
        assert_eq!(grafana_ds_identity(Some(&graf), &h), Ok(Some("an-operator".into())));
        // Grafana acting on its own (an alert evaluation) carries no user.
        assert_eq!(grafana_ds_identity(Some(&graf), &axum::http::HeaderMap::new()), Ok(None));
        // Two values, an empty one: refused, not guessed.
        h.append(GRAFANA_USER_HEADER, "admin".parse().unwrap());
        assert!(grafana_ds_identity(Some(&graf), &h).is_err());
        let mut e = axum::http::HeaderMap::new();
        e.insert(GRAFANA_USER_HEADER, " ".parse().unwrap());
        assert!(grafana_ds_identity(Some(&graf), &e).is_err());
    }

    /// The middleware asks Grafana's leaf on the data-source prefix BEFORE it
    /// looks at a bearer, and returns there either way: no token opens these
    /// paths, and a token cannot carry a forged header past the leaf check.
    #[test]
    fn the_grafana_ds_prefix_is_leaf_only_and_decided_before_the_bearer() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).expect("middleware");
        let branch = body.find("if path.starts_with(GRAFANA_DS_PREFIX) {").expect("the grafana-ds branch");
        let bearer = body.find("let token = bearer_token(&request);").expect("the bearer read");
        assert!(branch < bearer, "the leaf check must come before the bearer");
        let arm = &body[branch..bearer];
        assert!(arm.contains("return match grafana_ds_identity(scraper.as_ref(), request.headers())"), "{arm}");
        assert!(arm.contains("Err(StatusCode::UNAUTHORIZED)"), "{arm}");
        // The public lists never name it.
        assert!(!PUBLIC_PATH_PREFIXES.iter().any(|p| GRAFANA_DS_PREFIX.starts_with(p) || p.starts_with(GRAFANA_DS_PREFIX)));
        assert!(!PUBLIC_PATHS_EXACT.iter().any(|p| p.starts_with(GRAFANA_DS_PREFIX)));
    }

    /// One rate-limit bucket per Grafana user, and only on Grafana's leaf.
    #[test]
    fn grafana_ds_requests_are_rate_limited_per_person() {
        use crate::node_identity::VerifiedService;
        let req = |svc: Option<VerifiedService>, path: &str, user: Option<&str>| {
            let mut b = axum::http::Request::builder().uri(path);
            if let Some(u) = user {
                b = b.header(GRAFANA_USER_HEADER, u);
            }
            let mut r = b.body(axum::body::Body::empty()).unwrap();
            r.extensions_mut().insert(svc);
            r
        };
        let graf = || Some(VerifiedService(GRAFANA_SERVICE.into()));
        let p = "/api/grafana-ds/prometheus/api/v1/query";
        assert_eq!(grafana_ds_rate_key(&req(graf(), p, Some("alice"))).as_deref(), Some("svc:grafana:alice"));
        assert_eq!(grafana_ds_rate_key(&req(graf(), p, None)).as_deref(), Some("svc:grafana:-"));
        assert_eq!(grafana_ds_rate_key(&req(None, p, Some("alice"))), None, "forged: the per-IP bucket");
        assert_eq!(grafana_ds_rate_key(&req(graf(), "/api/cluster/status", Some("alice"))), None);
    }

    /// The scraper's leaf opens GET /metrics and nothing else; no other
    /// service leaf opens it at all.
    #[test]
    fn the_scraper_leaf_reads_metrics_and_nothing_else() {
        use crate::node_identity::VerifiedService;
        let prom = VerifiedService("prometheus".into());
        let graf = VerifiedService("grafana".into());
        assert!(is_metrics_scrape(&Method::GET, "/metrics", Some(&prom)));
        assert!(!is_metrics_scrape(&Method::POST, "/metrics", Some(&prom)));
        assert!(!is_metrics_scrape(&Method::GET, "/api/metrics/query", Some(&prom)));
        assert!(!is_metrics_scrape(&Method::GET, "/api/cluster/status", Some(&prom)));
        assert!(!is_metrics_scrape(&Method::GET, "/metrics", Some(&graf)));
        assert!(!is_metrics_scrape(&Method::GET, "/metrics", None));
    }

    // The birth-proof routes step past this middleware because
    // the node has no fleet credential at that moment — but the exemption must
    // be exactly two routes, not the neighbourhood they live in. `/metrics`
    // taught this lesson once already: a prefix entry re-opens every
    // path that happens to start the same way.
    #[test]
    fn the_birth_proof_exemption_is_two_routes_not_a_prefix() {
        assert!(is_handler_authenticated("/bootstrap/bundle/host9/fetched"));
        assert!(is_handler_authenticated("/bootstrap/bundle/host9/applied"));
        for path in [
            "/bootstrap/bundle/host9",          // the GET — public, separately
            "/bootstrap/bundle//fetched",        // no node
            "/bootstrap/bundle/a/b/fetched",     // not a node name
            "/bootstrap/bundle/host9/fetchedx", // suffix must be exact
            "/bootstrap/bundle/host9/blob",
            "/bootstrap/bundlefoo/x/fetched",
            "/api/cluster/provision-bundle/host9",
        ] {
            assert!(!is_handler_authenticated(path), "{path} must not be exempt");
        }
    }

    // The exemption is not a public list: neither route may appear on one, or
    // the handler's own check would be decorative.
    #[test]
    fn the_birth_proof_routes_are_not_public() {
        for (prefix, suffix) in HANDLER_AUTHENTICATED_PATHS {
            let path = format!("{prefix}host9{suffix}");
            assert!(!PUBLIC_PATHS_EXACT.contains(&path.as_str()), "{path}");
            assert!(
                !PUBLIC_PATH_PREFIXES.iter().any(|p| path.starts_with(p)),
                "{path} must not be public for every method"
            );
            // The node routes sit under the read-only bundle prefix, which
            // covers only safe methods — these are POSTs. The seat routes sit
            // under no public prefix at all: the seat's GET is signed too.
            let under_get_prefix = PUBLIC_GET_PATH_PREFIXES.iter().any(|p| path.starts_with(p));
            assert_eq!(under_get_prefix, *prefix == "/bootstrap/bundle/", "{path}");
        }
    }

    /// The seat exemption (i77) is the same shape as the node one: exact
    /// `<prefix><one segment><suffix>` routes, never a neighbourhood.
    #[test]
    fn the_seat_proof_exemption_is_four_routes_not_a_prefix() {
        for suffix in ["/bundle", "/fetched", "/applied", "/heartbeat"] {
            assert!(is_handler_authenticated(&format!("/bootstrap/seat/lobby{suffix}")), "{suffix}");
        }
        for path in [
            "/bootstrap/seat/lobby",
            "/bootstrap/seat//bundle",
            "/bootstrap/seat/a/b/bundle",
            "/bootstrap/seat/lobby/bundlex",
            "/bootstrap/seat/lobby/status",
            "/bootstrap/seats/lobby/bundle",
            "/api/cluster/seats/lobby/bundle",
            "/api/cluster/seats",
        ] {
            assert!(!is_handler_authenticated(path), "{path} must not be exempt");
        }
    }

    /// i77's hard rule, as the middleware sees it: a kiosk SEAT holds a birth
    /// key and nothing else — no fleet secret, no controller secret, no JWT,
    /// no service key. So every route a seat can reach is a route that admits
    /// a request carrying NO bearer. This walks every node-only route (the
    /// `NODE_ROUTES` allow-list, with `{self}` and `*` filled in as the seat's
    /// own name) and the operator's seat surface, and asserts each one is a
    /// 401 for a bearer-less caller — except the two node birth-proof routes,
    /// whose handlers verify against `noo_bootstrap_tokens` (where no seat's
    /// cert is ever written) over a `noo-bundle-*` message (which no seat
    /// signs; `birth_proof::seat_and_node_proofs_never_cross`). The seat's own
    /// four routes are the only other bearer-less doors, and they accept only
    /// `noo-seat-*` proofs. The NATS half of the rule is
    /// `nats_users::tests::seat_has_no_bus_principal` (noo-cli).
    #[test]
    fn seat_cannot_reach_node_routes() {
        let seat = "lobby";
        let fill = |pattern: &str| pattern.replace("{self}", seat).replace('*', "x");
        let mut checked = 0;
        for (method, pattern) in NODE_ROUTES {
            let path = fill(pattern);
            let safe = matches!(*method, "GET" | "HEAD" | "OPTIONS");
            let admitted = passes_without_bearer_check(&path, safe, false);
            if *pattern == "/bootstrap/bundle/{self}/applied" {
                // Handler-authenticated: it verifies a NODE birth proof
                // against the node table, which a seat cannot produce.
                assert!(admitted, "the node apply report stays reachable for a node's birth proof");
                assert!(!path.starts_with("/bootstrap/seat/"));
                continue;
            }
            assert!(!admitted, "{method} {path} is a node route a credential-less seat must not reach");
            checked += 1;
        }
        assert!(checked >= 20, "the walk must cover the node allow-list, not an empty slice ({checked})");
        // The other node pull-lane writes and the node bundle GET.
        for path in ["/bootstrap/bundle/lobby/fetched", "/bootstrap/bundle/lobby/applied"] {
            assert!(is_handler_authenticated(path));
        }
        // Node control surfaces that are not on the allow-list at all.
        for (method, path) in [
            ("POST", "/api/cluster/nodes/register"),
            ("POST", "/api/cluster/provision-bundle/lobby"),
            ("GET", "/api/cluster/provision-bundle/lobby/status"),
            ("GET", "/api/cluster/nodes/lobby/desired-config"),
            ("POST", "/api/cluster/mint-join-key"),
            ("POST", "/api/security/bootstrap-tokens"),
            ("GET", "/api/security/fleet-secrets"),
            ("POST", "/api/harness/turn"),
            ("GET", "/api/cluster/seats"),
            ("POST", "/api/cluster/seats/lobby/bundle"),
            ("GET", "/api/cluster/seats/lobby/status"),
            ("POST", "/api/cluster/seat-tokens"),
        ] {
            let safe = method == "GET";
            assert!(!passes_without_bearer_check(path, safe, false), "{method} {path}");
        }
        // And a seat's own doors are not node doors: a node's fleet token on
        // them is a Node-kind caller, which `node_route_allowed` refuses.
        for suffix in ["/bundle", "/fetched", "/applied", "/heartbeat"] {
            let path = format!("/bootstrap/seat/{seat}{suffix}");
            for m in ["GET", "POST"] {
                assert!(!node_route_allowed(m, &path, seat), "{m} {path} must not be a node route");
            }
        }
    }

    fn claims(scopes: &[&str], role: &str) -> Claims {
        Claims {
            sub: "test".into(),
            exp: 4102444800,
            role: role.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            harness: None,
            conv: None,
        
            act: None,
            cnf: None,
        }
    }

    // ── cluster-token verification (CRIT-1 regression) ──────────────────
    const TEST_SECRET: &str = "cluster-secret-for-tests";
    const TEST_NOW: u64 = 1_000_000;

    /// Build a valid token: HMAC-SHA256 of `actor:ts`, full 64-hex width —
    /// the only width any generator emits and the only one accepted.
    fn make_cluster_token(secret: &str, actor: &str, ts: u64) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{actor}:{ts}").as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        format!("{actor}:{ts}:{sig}")
    }

    #[test]
    fn per_user_reads_are_scoped_to_the_caller() {
        let user = RequesterCtx { sub: "alice".into(), scopes: vec!["read".into()], role: Role::User, harness: None, act: None };
        let op = RequesterCtx { sub: "alice".into(), scopes: vec!["admin".into()], role: Role::Operator, harness: None, act: None };
        // A user reads their own rows whether or not they name themselves,
        // and naming someone else is refused rather than silently narrowed.
        assert_eq!(scoped_user(Some(&user), None, None).unwrap(), Some("alice".into()));
        assert_eq!(scoped_user(Some(&user), None, Some("alice")).unwrap(), Some("alice".into()));
        assert!(scoped_user(Some(&user), None, Some("bob")).is_err());
        // An operator may name anyone, or take the global view.
        assert_eq!(scoped_user(Some(&op), None, Some("bob")).unwrap(), Some("bob".into()));
        assert_eq!(scoped_user(Some(&op), None, None).unwrap(), None);
        // Internal services keep the unscoped behaviour; a node does not.
        let internal = ClusterNode("gateway".into(), ClusterKind::Internal);
        let node = ClusterNode("host3".into(), ClusterKind::Node);
        assert_eq!(scoped_user(None, Some(&internal), Some("bob")).unwrap(), Some("bob".into()));
        assert_eq!(scoped_user(None, None, None).unwrap(), None);
        assert!(scoped_user(None, Some(&node), Some("bob")).is_err());
        assert!(scoped_user(None, Some(&node), None).is_err());
    }

    #[test]
    fn node_routes_are_self_scoped_and_nothing_else() {
        // Its own node rail.
        assert!(node_route_allowed("POST", "/api/cluster/nodes/register", "host3"));
        assert!(node_route_allowed("POST", "/api/cluster/nodes/host3/heartbeat", "host3"));
        assert!(node_route_allowed("GET", "/api/cluster/nodes/host3/desired-config", "host3"));
        assert!(node_route_allowed("POST", "/api/cluster/nodes/host3/logs", "host3"));
        assert!(node_route_allowed("POST", "/api/cluster/nodes/host3/mcp/git/tools", "host3"));
        assert!(!node_route_allowed("POST", "/api/cluster/nodes/host9/mcp/git/tools", "host3"), "a node reports only for itself");
        assert!(node_route_allowed("POST", "/bootstrap/bundle/host3/applied", "host3"));
        assert!(node_route_allowed("GET", "/api/artifacts/manifest/cli/noo", "host3"));
        assert!(node_route_allowed("PUT", "/api/agents/keys/host3/claude-code-1", "host3"));
        // Another node's rail.
        assert!(!node_route_allowed("POST", "/api/cluster/nodes/host8/heartbeat", "host3"));
        assert!(!node_route_allowed("POST", "/api/cluster/nodes/host8/logs", "host3"), "a node ships only its own logs");
        assert!(!node_route_allowed("GET", "/api/cluster/nodes/host8/desired-config", "host3"));
        // The things the review found reachable.
        assert!(!node_route_allowed("PUT", "/api/cluster/nodes/host8/placements/vllm", "host3"));
        assert!(!node_route_allowed("PUT", "/api/cluster/nodes/host3/placements/vllm", "host3"));
        assert!(!node_route_allowed("POST", "/api/mesh/rebuild", "host3"));
        assert!(!node_route_allowed("POST", "/api/security/posture", "host3"));
        assert!(!node_route_allowed("POST", "/api/security/service-keys", "host3"));
        assert!(!node_route_allowed("POST", "/api/security/bootstrap-tokens", "host3"));
        assert!(!node_route_allowed("POST", "/api/agents/peer/register", "host3"));
        assert!(!node_route_allowed("POST", "/api/agents/agent/run", "host3"));
        assert!(!node_route_allowed("DELETE", "/api/cluster/nodes/host3/heartbeat", "host3"));
        // Wildcards only match a tail, never a middle segment.
        assert!(!node_route_allowed("GET", "/api/artifacts/manifest", "host3"));
    }

    #[test]
    fn cluster_token_rejects_empty_signature() {
        // The bypass: `actor:<now>:` (empty sig) must NOT authenticate. The old
        // `expected.starts_with("")` accepted this with no secret knowledge.
        let tok = format!("gateway:{TEST_NOW}:");
        assert!(!verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW));
    }

    #[test]
    fn cluster_token_rejects_short_signature() {
        // Any prefix of the full signature (even a correct one) is rejected.
        let valid = make_cluster_token(TEST_SECRET, "gateway", TEST_NOW);
        let sig = valid.rsplit(':').next().unwrap();
        for n in [1usize, 2, 8, 16, 31] {
            let tok = format!("gateway:{TEST_NOW}:{}", &sig[..n]);
            assert!(
                !verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW),
                "sig prefix len {n} must be rejected"
            );
        }
    }

    #[test]
    fn minted_cluster_token_is_full_width_and_verifies() {
        // Cross-module contract: the token the gateway mints for
        // node-agent-bound (and loopback) calls must carry the FULL 64-hex
        // signature — the Go node-agent verifier rejects 32-hex — and must
        // still verify against this gateway's own verifier.
        let tok =
            crate::routes::cluster::mint_cluster_token("gateway", TEST_SECRET, TEST_NOW).unwrap();
        let sig = tok.rsplit(':').next().unwrap();
        assert_eq!(sig.len(), 64, "node-agent-bound tokens must be full 64-hex");
        assert!(verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW));
    }

    #[test]
    fn cluster_token_accepts_only_the_full_64_hex_width() {
        // One width: the full 64 hex every generator emits. The 32-char
        // truncated prefix had a one-release window and is
        // now refused even when it is the CORRECT prefix — that is the case
        // that proves the arm is gone rather than merely unexercised.
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET.as_bytes()).unwrap();
        mac.update(format!("gateway:{TEST_NOW}").as_bytes());
        let full = hex::encode(mac.finalize().into_bytes());
        assert_eq!(full.len(), 64, "the setup must produce a full-width digest");

        assert!(verify_cluster_token_inner(
            &format!("gateway:{TEST_NOW}:{full}"), TEST_SECRET, TEST_NOW));
        // The correct 32-char prefix: REFUSED.
        assert!(
            !verify_cluster_token_inner(
                &format!("gateway:{TEST_NOW}:{}", &full[..32]), TEST_SECRET, TEST_NOW),
            "a 32-hex truncated signature must be refused (P13 window closed)"
        );
        // Wrong 64-char sig rejected.
        assert!(!verify_cluster_token_inner(
            &format!("gateway:{TEST_NOW}:{}", "f".repeat(64)), TEST_SECRET, TEST_NOW));
        // Every other correct prefix, and an over-long one, rejected.
        for n in [16usize, 32, 48, 63] {
            assert!(!verify_cluster_token_inner(
                &format!("gateway:{TEST_NOW}:{}", &full[..n]), TEST_SECRET, TEST_NOW),
                "prefix len {n} must be refused");
        }
        assert!(!verify_cluster_token_inner(
            &format!("gateway:{TEST_NOW}:{full}0"), TEST_SECRET, TEST_NOW));
    }

    #[test]
    fn cluster_token_accepts_valid_signature() {
        let tok = make_cluster_token(TEST_SECRET, "gateway", TEST_NOW);
        assert!(verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW));
    }

    #[test]
    fn cluster_token_rejects_wrong_secret_and_empty_secret() {
        let tok = make_cluster_token(TEST_SECRET, "gateway", TEST_NOW);
        assert!(!verify_cluster_token_inner(&tok, "different-secret", TEST_NOW));
        assert!(!verify_cluster_token_inner(&tok, "", TEST_NOW));
    }

    #[test]
    fn cluster_token_enforces_replay_window() {
        let tok = make_cluster_token(TEST_SECRET, "gateway", TEST_NOW);
        // within ±300s (both directions) → accepted
        assert!(verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW + 299));
        assert!(verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW - 299));
        // outside the window → rejected
        assert!(!verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW + 301));
        assert!(!verify_cluster_token_inner(&tok, TEST_SECRET, TEST_NOW - 301));
    }

    #[test]
    fn cluster_token_rejects_malformed() {
        assert!(!verify_cluster_token_inner("only-two:parts", TEST_SECRET, TEST_NOW));
        assert!(!verify_cluster_token_inner(
            "gateway:not-a-number:0123456789abcdef0123456789abcdef",
            TEST_SECRET,
            TEST_NOW
        ));
        assert!(!verify_cluster_token_inner("", TEST_SECRET, TEST_NOW));
    }

    // ── Role cascade ───────────────────────────────────────

    #[test]
    fn role_ordering_is_a_strict_cascade() {
        assert!(Role::User < Role::Operator);
        assert!(Role::Operator < Role::Admin);
        assert!(Role::Admin >= Role::Operator && Role::Admin >= Role::User);
        // The exact comparisons every enforcement site uses.
        assert!(!(Role::User >= Role::Operator));
        assert!(!(Role::Operator >= Role::Admin));
    }

    #[test]
    fn role_from_str_is_strict() {
        assert_eq!("user".parse::<Role>().unwrap(), Role::User);
        assert_eq!("operator".parse::<Role>().unwrap(), Role::Operator);
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        for bad in ["", "Admin", "ADMIN", "root", "write", "read", "peer"] {
            assert!(bad.parse::<Role>().is_err(), "{bad:?} must not parse");
        }
        // Round-trip through as_str.
        for r in [Role::User, Role::Operator, Role::Admin] {
            assert_eq!(r.as_str().parse::<Role>().unwrap(), r);
        }
    }

    /// The mode a gateway falls into with NO controller secret is a refusal —
    /// there is no opt-in any more, and the message must not offer one.
    #[test]
    fn no_controller_secret_is_a_refusal_with_no_bridge_offered() {
        assert!(LEGACY_REFUSAL.contains("secrets rotate NOO_CONTROLLER_SECRET"));
        assert!(
            !LEGACY_REFUSAL.contains("NOO_CLUSTER_LEGACY_FULL_ACCESS"),
            "the refusal must not advertise the retired bridge"
        );
    }

    /// The fleet-secret branch of `require_any_auth` grants `Node` and
    /// nothing else. The retired bridge's arm handed out `Internal` (full
    /// access) when the controller secret was unset; restoring it must fail
    /// here, not in production.
    #[test]
    fn the_fleet_secret_branch_has_no_full_access_arm() {
        let src = include_str!("auth.rs");
        let start = src.find("    if verify_cluster_token(&t) {").expect("fleet-secret branch present");
        let branch = &src[start..];
        let branch = &branch[..branch.find("        return Ok(next.run(request).await);").expect("branch end")];
        assert!(branch.contains("node_route_allowed"), "the parse did not find the branch body");
        assert!(
            !branch.contains("ClusterKind::Internal"),
            "a fleet-secret token must never be Internal (retired NOO_CLUSTER_LEGACY_FULL_ACCESS arm)"
        );
        assert!(!branch.contains("warn_legacy_cluster_mode_once"));
    }

    #[test]
    fn legacy_scopes_match_the_dual_emit_table() {
        assert_eq!(Role::User.legacy_scopes(), &["read"]);
        assert_eq!(Role::Operator.legacy_scopes(), &["read", "write"]);
        assert_eq!(Role::Admin.legacy_scopes(), &["read", "write", "admin"]);
        // Emitted scopes must derive back to the same role, or a dual-emitted
        // token would resolve differently on the two claim paths.
        for r in [Role::User, Role::Operator, Role::Admin] {
            assert_eq!(Role::from_scopes(r.legacy_scopes()), r);
        }
    }

    #[test]
    fn claim_resolution_matrix() {
        // New dual-emitted tokens: role claim + consistent legacy scopes.
        assert_eq!(claims(&["read"], "user").resolved_role(), Role::User);
        assert_eq!(claims(&["read", "write"], "operator").resolved_role(), Role::Operator);
        assert_eq!(claims(&["read", "write", "admin"], "admin").resolved_role(), Role::Admin);
        // Old scope-only tokens: derived per the mapping.
        assert_eq!(claims(&["read", "write", "admin"], "").resolved_role(), Role::Admin);
        assert_eq!(claims(&["read", "write"], "").resolved_role(), Role::Operator);
        assert_eq!(claims(&["write"], "").resolved_role(), Role::Operator);
        assert_eq!(claims(&["read"], "").resolved_role(), Role::User);
        assert_eq!(claims(&["read", "ingest"], "").resolved_role(), Role::User);
        // Pre-scopes legacy tokens: empty scopes fall back to the role claim.
        assert_eq!(claims(&[], "admin").resolved_role(), Role::Admin);
        assert_eq!(claims(&[], "user").resolved_role(), Role::User);
        assert_eq!(claims(&[], "").resolved_role(), Role::User);
        assert_eq!(claims(&[], "garbage").resolved_role(), Role::User);
        // Inconsistent pairs degrade to the LOWER of the two — a role claim
        // must never out-privilege explicit scopes, nor vice versa.
        assert_eq!(claims(&["read"], "admin").resolved_role(), Role::User);
        assert_eq!(claims(&["read", "write"], "admin").resolved_role(), Role::Operator);
        assert_eq!(claims(&["read", "write", "admin"], "user").resolved_role(), Role::User);
        // Junk role claim alongside scopes: scopes decide.
        assert_eq!(claims(&["read", "write"], "garbage").resolved_role(), Role::Operator);
    }

    #[test]
    fn admin_and_write_scopes_are_unrestricted() {
        for scopes in [&["admin"][..], &["read", "write"][..]] {
            let c = claims(scopes, "");
            assert!(scope_allows(&c, &Method::POST, "/api/cluster/backends/start"));
            assert!(scope_allows(&c, &Method::DELETE, "/api/config"));
        }
    }

    #[test]
    fn read_scope_sees_everything_via_get() {
        let c = claims(&["read"], "");
        assert!(scope_allows(&c, &Method::GET, "/api/cluster/status"));
        assert!(scope_allows(&c, &Method::GET, "/api/jobs/list"));
        // `/api/logs/*` left the User tier on 2026-09-28 (LOGS_READ_PREFIX);
        // `log_reads_are_operator_and_admin_only` pins that side.
        assert!(scope_allows(&c, &Method::GET, "/api/conversations"));
    }

    #[test]
    fn read_scope_can_mutate_chat_and_query_surface() {
        let c = claims(&["read"], "");
        assert!(scope_allows(&c, &Method::POST, "/api/inference/stream"));
        assert!(scope_allows(&c, &Method::POST, "/api/v1/rag/query"));
        assert!(scope_allows(&c, &Method::POST, "/upload"));
        assert!(scope_allows(&c, &Method::POST, "/api/conversations/abc/feedback"));
    }

    #[test]
    fn read_scope_cannot_mutate_control_plane() {
        let c = claims(&["read"], "");
        assert!(!scope_allows(&c, &Method::POST, "/api/cluster/backends/start"));
        assert!(!scope_allows(&c, &Method::POST, "/api/scheduler/pause"));
        assert!(!scope_allows(&c, &Method::PUT, "/api/settings"));
        assert!(!scope_allows(&c, &Method::POST, "/api/mesh/rebuild"));
        assert!(!scope_allows(&c, &Method::DELETE, "/api/memory/cleanup"));
        // Unported route behind the Python catch-all — must fail closed
        assert!(!scope_allows(&c, &Method::POST, "/api/some/unported/route"));
    }

    /// a read-only account opens Grafana (as a Viewer);
    /// the tier gate must not refuse it before the handler can answer.
    /// Exact match: nothing else under /api/monitoring widens with it.
    #[test]
    fn the_grafana_refusal_has_a_body_naming_the_tiers() {
        let r = super::grafana_refusal();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let body = rt.block_on(axum::body::to_bytes(r.into_body(), 1 << 16)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let e = v["error"].as_str().unwrap();
        assert!(e.contains("user (as Grafana Viewer)") && e.contains("needs"), "{e}");
        // Bare = the auth layer's `Err(StatusCode::FORBIDDEN)`; a handler's
        // explained refusal carries a JSON body and is left alone.
        use axum::response::IntoResponse;
        assert!(super::is_bare_forbidden(&StatusCode::FORBIDDEN.into_response()));
        assert!(!super::is_bare_forbidden(&super::grafana_refusal()));
        // The layer sits outside the auth middleware, or it never sees the 403.
        let routes = include_str!("routes/mod.rs");
        let auth = routes.find("crate::auth::require_any_auth))").expect("auth layer");
        let explain = routes.find("crate::auth::explain_grafana_refusal").expect("explain layer registered");
        assert!(explain > auth, "axum layers added later wrap earlier ones: explain_grafana_refusal must come after require_any_auth");
    }

    #[test]
    fn read_scope_can_open_grafana_and_nothing_else_there() {
        let c = claims(&["read"], "user");
        assert!(scope_allows(&c, &Method::POST, GRAFANA_SESSION_PATH));
        assert!(!scope_allows(&c, &Method::POST, "/api/monitoring/grafana-session/x"));
        assert!(!scope_allows(&c, &Method::POST, "/api/monitoring/other"));
    }

    /// a sub-operator JWT may FILE a proposal on the
    /// security surface (the escalation path), but not touch the direct
    /// mutation routes, the legacy propose path, or the queue itself.
    #[test]
    fn read_scope_can_file_a_security_proposal_but_nothing_else() {
        let c = claims(&["read"], "");
        assert!(scope_allows(&c, &Method::POST, USER_PROPOSAL_ESCALATION_PATH));
        assert!(!scope_allows(&c, &Method::POST, "/api/security/users"));
        assert!(!scope_allows(&c, &Method::POST, "/api/security/users/alice/disable"));
        assert!(!scope_allows(&c, &Method::PUT, "/api/security/users/alice/password"));
        assert!(!scope_allows(&c, &Method::POST, "/api/security/user-proposals/1/decide"));
        // Legacy propose stays agent-only: not widened on a deprecating surface.
        assert!(!scope_allows(&c, &Method::POST, "/api/users/propose"));
        // Exact match — no prefix shadowing of sibling paths.
        assert!(!scope_allows(&c, &Method::POST, "/api/security/users/proposex"));
    }

    #[test]
    fn legacy_role_fallback_applies_only_with_empty_scopes() {
        let legacy_admin = claims(&[], "admin");
        assert!(scope_allows(&legacy_admin, &Method::POST, "/api/cluster/backends/start"));
        let legacy_user = claims(&[], "user");
        assert!(scope_allows(&legacy_user, &Method::GET, "/api/cluster/status"));
        assert!(!scope_allows(&legacy_user, &Method::POST, "/api/cluster/backends/start"));
        // role=admin must NOT override explicit read-only scopes
        let demoted = claims(&["read"], "admin");
        assert!(!scope_allows(&demoted, &Method::POST, "/api/cluster/backends/start"));
    }

    fn claims_with(scopes: &[&str]) -> Claims {
        Claims {
            sub: "claude-ext".into(),
            exp: 4102444800,
            role: String::new(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            harness: None,
            conv: None,
        
            act: None,
            cnf: None,
        }
    }

    #[test]
    fn ingest_scope_opens_the_ingest_path() {
        let c = claims_with(&["read", "ingest"]);
        assert!(scope_allows(&c, &Method::POST, "/api/v1/docs/ingest"));
    }

    /// Evolve's exchanged token: subject `addon:svc:evolve`, the key's scopes
    /// minus `addon`. With `temporal` it writes the graph; without it, or on
    /// any other mutation, it is the plain user-tier token it always was.
    #[test]
    fn the_temporal_scope_opens_the_temporal_writes_and_nothing_else() {
        let c = claims_with(&["temporal"]);
        assert!(scope_allows(&c, &Method::POST, "/api/temporal/adaptations"));
        assert!(!scope_allows(&c, &Method::POST, "/api/cluster/backends/start"));
        assert!(!scope_allows(&c, &Method::DELETE, "/api/config"));
    }

    #[test]
    fn without_the_temporal_scope_an_addon_token_cannot_write_the_graph() {
        // What every exchanged add-on token carried.
        let c = claims_with(&["chat", "embeddings"]);
        assert!(!scope_allows(&c, &Method::POST, "/api/temporal/adaptations"));
    }

    /// Evolve's whole reach, one scope per write it makes. Every row of the
    /// table opens its own route and no other: the scopes are not a tier.
    #[test]
    fn each_control_scope_opens_its_own_writes_and_nothing_else() {
        let cases: &[(&str, Method, &str)] = &[
            ("temporal", Method::POST, "/api/temporal/adaptations"),
            ("heartbeat", Method::POST, "/api/heartbeat/tasks/research/run"),
            ("heartbeat", Method::PUT, "/api/heartbeat/tasks/research/toggle"),
            ("activities", Method::POST, "/api/activities"),
            ("channels:send", Method::POST, "/api/channels/send"),
            ("metrics", Method::POST, "/api/metrics/increment"),
            ("metrics", Method::POST, "/api/metrics/gauge"),
            ("config:self_identity", Method::PUT, "/api/config/self_identity"),
        ];
        for (scope, method, path) in cases {
            let c = claims_with(&[scope]);
            assert!(scope_allows(&c, method, path), "{scope} must open {method} {path}");
            for (other, m2, p2) in cases {
                if other != scope {
                    assert!(!scope_allows(&c, m2, p2), "{scope} must not open {m2} {p2}");
                }
            }
        }
    }

    /// `PUT /api/heartbeat/tasks/*/schedule` is operator-only. A User tier is refused at the front
    /// door, and the `heartbeat` control scope (evolve's run + toggle) does NOT open it: changing
    /// when a task fires is not something a scope meant for flipping a task grants.
    #[test]
    fn changing_a_task_schedule_is_operator_only() {
        let path = "/api/heartbeat/tasks/database_backup/schedule";
        let mut user = claims_with(&[]);
        user.role = "user".into();
        assert!(!scope_allows(&user, &Method::PUT, path), "a User is refused");
        let mut op = claims_with(&[]);
        op.role = "operator".into();
        assert!(scope_allows(&op, &Method::PUT, path), "an Operator may");
        assert!(!scope_allows(&claims_with(&["heartbeat"]), &Method::PUT, path), "the heartbeat control scope does not open it");
        assert!(
            !CONTROL_SCOPE_ROUTES.iter().any(|(_, _, p)| p.ends_with("/schedule")),
            "no control scope lists the schedule route"
        );
    }

    #[test]
    fn a_control_scope_holds_its_method_and_its_shape() {
        let hb = claims_with(&["heartbeat"]);
        assert!(!scope_allows(&hb, &Method::DELETE, "/api/heartbeat/tasks/research/run"));
        assert!(!scope_allows(&hb, &Method::POST, "/api/heartbeat/tasks//run"), "`*` is one NON-empty segment");
        assert!(!scope_allows(&hb, &Method::POST, "/api/heartbeat/tasks/a/b/run"), "`*` is ONE segment");
        assert!(!scope_allows(&hb, &Method::POST, "/api/heartbeat/tasks"));
        let cfg = claims_with(&["config:self_identity"]);
        assert!(!scope_allows(&cfg, &Method::PUT, "/api/config/cluster"), "one section per scope");
        assert!(!scope_allows(&cfg, &Method::PUT, "/api/config/self_identity/extra"));
        assert!(!scope_allows(&cfg, &Method::DELETE, "/api/config/self_identity"));
    }

    /// evolve's declared `config:video_memory` keeps opening the
    /// section under both names, and so does the new `config:recall_memory`;
    /// neither opens any other section.
    #[test]
    fn a_renamed_config_section_answers_to_either_scope() {
        for scope in ["config:video_memory", "config:recall_memory"] {
            assert!(is_control_scope(scope), "{scope} must be issuable");
            let c = claims_with(&[scope]);
            assert!(scope_allows(&c, &Method::PUT, "/api/config/video_memory"), "{scope} -> old path");
            assert!(scope_allows(&c, &Method::PUT, "/api/config/recall_memory"), "{scope} -> new path");
            assert!(!scope_allows(&c, &Method::PUT, "/api/config/memory"), "{scope} opens one section");
            assert!(!scope_allows(&c, &Method::DELETE, "/api/config/recall_memory"));
        }
        let other = claims_with(&["config:memory"]);
        assert!(!scope_allows(&other, &Method::PUT, "/api/config/recall_memory"));
    }

    /// A gate-bearing section is not a control scope, so a token that somehow
    /// carries one still cannot write it here — and the handler's admin wall
    /// stands behind this regardless.
    #[test]
    fn a_gated_config_section_is_never_a_control_scope() {
        for gated in crate::routes::settings::GATED_CONFIG_SECTIONS {
            let scope = format!("config:{gated}");
            assert!(!is_control_scope(&scope), "{scope} must not be issuable");
            let c = claims_with(&[scope.as_str()]);
            assert!(!scope_allows(&c, &Method::PUT, &format!("/api/config/{gated}")));
        }
        for bad in ["config:", "config:Self", "config:a/b", "config:../x", "temporal:write"] {
            assert!(!is_control_scope(bad), "{bad:?}");
        }
        assert!(is_control_scope("config:self_identity"));
    }

    /// `conversation_stats` is a READ scope: it names the three aggregate
    /// GETs, is a control scope the issuer knows, and is never a default.
    #[test]
    fn conversation_stats_opens_exactly_its_three_gets() {
        let c = claims_with(&[CONVERSATION_STATS_SCOPE]);
        assert!(is_control_scope(CONVERSATION_STATS_SCOPE));
        for path in [
            "/api/conversations/stats/tools",
            "/api/conversations/stats/overview",
            "/api/conversations/feedback/stats",
        ] {
            assert!(control_scope_allows(&c.scopes, &Method::GET, path), "must open GET {path}");
            assert!(scope_allows(&c, &Method::GET, path), "and the tier gate passes it");
            assert!(!control_scope_allows(&c.scopes, &Method::POST, path), "a read scope is not POST {path}");
            assert!(!control_scope_allows(&c.scopes, &Method::PUT, path), "nor PUT {path}");
        }
        // The same rows without the scope open nothing through the table.
        let other = claims_with(&["metrics"]);
        assert!(!control_scope_allows(&other.scopes, &Method::GET, "/api/conversations/stats/tools"));
    }

    /// It opens no per-user row and no other route: a conversation, its
    /// feedback write, the DPO export, and the write routes the other control
    /// scopes name all stay shut to a token holding only this scope.
    #[test]
    fn conversation_stats_opens_nothing_else() {
        let c = claims_with(&[CONVERSATION_STATS_SCOPE]);
        for (m, path) in [
            (Method::POST, "/api/conversations/abc/feedback"),
            (Method::GET, "/api/conversations/abc"),
            (Method::GET, "/api/conversations"),
            (Method::GET, "/api/conversations/feedback/export/dpo"),
            (Method::GET, "/api/conversations/stats/tools/extra"),
            (Method::GET, "/api/conversations/stats"),
            (Method::POST, "/api/temporal/adaptations"),
            (Method::POST, "/api/metrics/increment"),
            (Method::PUT, "/api/config/self_identity"),
        ] {
            assert!(!control_scope_allows(&c.scopes, &m, path), "must not open {m} {path}");
        }
        // The write table kept its meaning: it holds no GET row.
        assert!(CONTROL_SCOPE_ROUTES.iter().all(|(_, m, _)| *m != "GET"));
        assert!(CONTROL_READ_SCOPE_ROUTES.iter().all(|(_, m, _)| *m == "GET"));
        // And it is never a default key scope's neighbour by accident.
        assert!(control_scope_rows().any(|(s, _, _)| *s == CONVERSATION_STATS_SCOPE));
    }

    /// `prompt_skills:write` opens exactly the four skill-store writes and
    /// nothing else: no DELETE, no config, no other POST under the prefix.
    #[test]
    fn prompt_skills_write_opens_exactly_its_four_routes() {
        let c = claims_with(&[PROMPT_SKILLS_WRITE_SCOPE]);
        assert!(is_control_scope(PROMPT_SKILLS_WRITE_SCOPE));
        for (m, path) in [
            (Method::POST, "/api/prompt-skills"),
            (Method::PUT, "/api/prompt-skills/my-skill"),
            (Method::POST, "/api/prompt-skills/my-skill/retire"),
            (Method::POST, "/api/prompt-skills/my-skill/fitness"),
        ] {
            assert!(control_scope_allows(&c.scopes, &m, path), "must open {m} {path}");
            assert!(scope_allows(&c, &m, path), "and the tier gate passes {m} {path}");
        }
        for (m, path) in [
            (Method::DELETE, "/api/prompt-skills/my-skill"),
            (Method::DELETE, "/api/prompt-skills"),
            (Method::PUT, "/api/prompt-skills"),
            (Method::POST, "/api/prompt-skills/my-skill"),
            (Method::POST, "/api/prompt-skills/my-skill/other"),
            (Method::POST, "/api/prompt-skills/my-skill/retire/extra"),
            (Method::PUT, "/api/prompt-skills/my-skill/retire"),
            (Method::POST, "/api/prompt-skills//retire"),
            // Promotion is a person's decision: the writer's scope never opens it.
            (Method::POST, "/api/prompt-skills/proposals/7/decide"),
            (Method::GET, "/api/prompt-skills/proposals"),
            (Method::PUT, "/api/config/prompt_skills"),
            (Method::PUT, "/api/config/agent"),
            (Method::POST, "/api/temporal/adaptations"),
            (Method::POST, "/api/metrics/increment"),
        ] {
            assert!(!control_scope_allows(&c.scopes, &m, path), "must not open {m} {path}");
            assert!(!scope_allows(&c, &m, path), "tier gate must not pass {m} {path}");
        }
        // Without the scope the same rows open nothing.
        let other = claims_with(&["metrics"]);
        assert!(!control_scope_allows(&other.scopes, &Method::PUT, "/api/prompt-skills/my-skill"));
    }

    #[test]
    fn holding_the_scope_is_read_off_the_requester() {
        let with = RequesterCtx { sub: "svc:evolve".into(), scopes: vec![CONVERSATION_STATS_SCOPE.into()], role: Role::User, harness: None, act: None };
        let without = RequesterCtx { sub: "svc:evolve".into(), scopes: vec!["metrics".into()], role: Role::User, harness: None, act: None };
        assert!(holds_control_scope(Some(&with), CONVERSATION_STATS_SCOPE));
        assert!(!holds_control_scope(Some(&without), CONVERSATION_STATS_SCOPE));
        assert!(!holds_control_scope(None, CONVERSATION_STATS_SCOPE), "an internal service has no requester");
    }

    #[test]
    fn read_alone_still_cannot_ingest() {
        // The whole point of the scope: it has to be the thing that grants
        // this, not a side effect of being logged in.
        let c = claims_with(&["read"]);
        assert!(!scope_allows(&c, &Method::POST, "/api/v1/docs/ingest"));
    }

    #[test]
    fn any_user_may_manage_their_own_mcp_key() {
        // The point of the feature: a plain `read` account self-serves,
        // without an operator in the loop.
        let c = claims_with(&["read"]);
        for p in SELF_SERVICE_KEY_PATHS {
            assert!(scope_allows(&c, &Method::POST, p), "User tier should reach {p}");
        }
    }

    #[test]
    fn self_service_does_not_open_the_operator_key_surface() {
        // The exact-match requirement, asserted rather than trusted. Each of
        // these mints or mutates a key for an ARBITRARY consumer with
        // ARBITRARY scopes — a prefix match on "/api/security/service-keys"
        // would hand a User the ability to issue itself an unbound key with
        // the full scope set, which is a straight privilege escalation.
        let c = claims_with(&["read"]);
        for path in [
            "/api/security/service-keys",
            "/api/security/service-keys/noo-trading/revoke",
            "/api/security/service-keys/noo-trading/rotate",
            "/api/security/service-keys/noo-trading/quota",
            // A consumer literally named to straddle the allow-list.
            "/api/security/service-keys/self-other/revoke",
            "/api/security/service-keys/selfx",
        ] {
            assert!(
                !scope_allows(&c, &Method::POST, path),
                "User tier must not reach POST {path}"
            );
        }
    }

    #[test]
    fn the_user_door_has_exactly_one_self_authenticating_path() {
        // `/mcp/external` was the user door's original path and an alias
        // until stack-v0.2.40. It sat in this list, so a client on it
        // bypassed the JWT middleware and reached the door; once the route
        // is gone the entry would be a self-authenticating path to a 404 —
        // harmless today, and the first thing to become a hole when someone
        // mounts a route there. The list names the door's one path only.
        assert!(PUBLIC_PATHS_EXACT.contains(&"/mcp/user"));
        assert!(
            !PUBLIC_PATHS_EXACT.contains(&"/mcp/external"),
            "the removed alias must not stay self-authenticating"
        );
    }

    /// any signed-in account may flip its OWN save switch, by that
    /// exact path and nothing beside it.
    #[test]
    fn a_user_may_write_the_walks_settings_path_and_no_sibling() {
        let c = claims_with(&["read"]);
        assert!(scope_allows(&c, &Method::PUT, WALKS_SETTINGS_PATH));
        for path in ["/api/v1/walks", "/api/v1/walks/stats", "/api/v1/admin/walks", "/api/v1/walks/settings/x", "/api/v1/walks/other"] {
            assert!(!scope_allows(&c, &Method::PUT, path), "PUT {path}");
            assert!(!scope_allows(&c, &Method::POST, path), "POST {path}");
            assert!(!scope_allows(&c, &Method::DELETE, path), "DELETE {path}");
        }
    }

    /// A User sends and acks agent mail as itself, by those exact method+path
    /// pairs. Every sibling under /api/agents stays closed.
    #[test]
    fn a_user_may_send_and_ack_agent_mail_and_nothing_beside_it() {
        use axum::http::Method;
        let user = claims(&["read"], "user");
        for (m, p) in [(Method::POST, "/api/agents/messages"), (Method::POST, "/api/agents/messages/msg_1/ack"), (Method::POST, "/api/agents/name")] {
            assert!(scope_allows(&user, &m, p), "{m} {p}");
            assert!(requester_allows(&RequesterCtx { sub: "u".into(), scopes: vec!["read".into()], role: Role::User, harness: None, act: None }, &m, p));
        }
        for (m, p) in [
            (Method::POST, "/api/agents/collaborate"),
            (Method::POST, "/api/agents/trust"),
            (Method::POST, "/api/agents/trust/remove"),
            (Method::PUT, "/api/agents/keys/x"),
            (Method::POST, "/api/agents/messages/x"),
            (Method::POST, "/api/agents/messages/x/ack/y"),
            (Method::POST, "/api/agents/messages//ack"),
            (Method::POST, "/api/agents/messages/a/b/ack"),
            (Method::POST, "/api/agents/messagesx"),
            (Method::PUT, "/api/agents/messages"),
            (Method::DELETE, "/api/agents/messages"),
            (Method::PUT, "/api/agents/messages/msg_1/ack"),
            (Method::PUT, "/api/agents/name"),
            (Method::POST, "/api/agents/name/x"),
            (Method::POST, "/api/agents/names"),
        ] {
            assert!(!scope_allows(&user, &m, p), "{m} {p} must not be open to a User");
        }
        let op = claims(&["read", "write"], "operator");
        assert!(scope_allows(&op, &Method::POST, "/api/agents/collaborate"));
        assert!(scope_allows(&op, &Method::POST, "/api/agents/messages"));
    }

    /// The ops API is open to every tier at the front door because it authorises
    /// per request (the type's own route, and ownership). It is NOT a back door:
    /// the routes an op wraps stay as closed to a User as they were.
    #[test]
    fn a_user_reaches_the_ops_api_but_not_the_routes_it_wraps() {
        use axum::http::Method;
        let user = claims(&["read"], "user");
        for (m, p) in [
            (Method::POST, "/api/v1/ops"),
            (Method::GET, "/api/v1/ops"),
            (Method::GET, "/api/v1/ops/0f9c1d2e-0000-4000-8000-000000000001"),
            (Method::DELETE, "/api/v1/ops/0f9c1d2e-0000-4000-8000-000000000001"),
            (Method::GET, "/api/v1/ops/types"),
        ] {
            assert!(scope_allows(&user, &m, p), "{m} {p}");
        }
        // The prefix has a boundary, and only the listed method+path pairs are open: a route
        // added under /api/v1/ops later is closed to a User until it is listed.
        assert!(!scope_allows(&user, &Method::POST, "/api/v1/opsx"));
        for (m, p) in [
            (Method::PUT, "/api/v1/ops/x"),
            (Method::POST, "/api/v1/ops/x"),
            (Method::DELETE, "/api/v1/ops"),
            (Method::POST, "/api/v1/ops/types"),
            (Method::POST, "/api/v1/ops/x/retry"),
            (Method::DELETE, "/api/v1/ops/"),
        ] {
            assert!(!scope_allows(&user, &m, p), "{m} {p} must not be open to a User");
        }
        assert!(!scope_allows(&user, &Method::DELETE, "/api/v1/operators/x"));
        // And the routes the ops wrap are exactly as closed as before.
        for p in ["/api/v1/graph/recluster", "/api/v1/graph/extract-relations", "/api/snapshots/consolidate", "/api/v1/rag/ingest"] {
            assert!(!scope_allows(&user, &Method::POST, p), "a User must still be refused POST {p}");
            assert!(!requester_allows(&RequesterCtx { sub: "u".into(), scopes: vec!["read".into()], role: Role::User, harness: None, act: None }, &Method::POST, p));
        }
    }

    #[test]
    fn a_user_may_submit_and_cancel_jobs_and_nothing_else_under_jobs() {
        use axum::http::Method;
        let id = "0f9c1d2e-0000-4000-8000-000000000001";
        let user = claims(&["read"], "user");
        assert_eq!(user.resolved_role(), Role::User);
        let open = [
            (Method::POST, "/api/jobs/submit".to_string()),
            (Method::DELETE, format!("/api/jobs/{id}")),
        ];
        assert_eq!(open.len(), 2, "vacuous");
        for (m, p) in &open {
            assert!(scope_allows(&user, m, p), "{m} {p}");
        }
        let closed = [
            (Method::POST, format!("/api/jobs/{id}/reprioritize")),
            (Method::POST, "/api/jobs/a/b".to_string()),
            (Method::DELETE, "/api/jobs/".to_string()),
            (Method::DELETE, "/api/jobs/submit".to_string()),
            (Method::DELETE, "/api/jobs/history".to_string()),
            (Method::DELETE, "/api/jobs/queue".to_string()),
            (Method::DELETE, format!("/api/jobs/{id}/")),
            (Method::PUT, format!("/api/jobs/{id}")),
            (Method::POST, format!("/api/jobs/{id}")),
            (Method::GET, "/api/jobs/submit/x".to_string()),
            (Method::POST, "/api/tasks/submit".to_string()),
            (Method::POST, "/api/tasks/inference".to_string()),
            (Method::POST, "/api/scheduler/pause".to_string()),
            (Method::POST, "/api/scheduler/drain".to_string()),
        ];
        for (m, p) in &closed {
            // GET on the odd path is a read and so passes the generic read rule;
            // the pure predicate is what must refuse it.
            assert!(!is_job_user_api(m, p), "{m} {p} must not be a User job route");
            if *m != Method::GET {
                assert!(!scope_allows(&user, m, p), "{m} {p} must be refused to a User");
            }
        }
        // An operator is unaffected.
        let op = claims(&["read", "write"], "operator");
        for (m, p) in open.iter().chain(closed.iter()) {
            assert!(scope_allows(&op, m, p), "operator {m} {p}");
        }
    }

    #[test]
    fn ingest_scope_grants_nothing_else_that_mutates() {
        // A scope for CONTRIBUTING documents must not become a junior
        // operator tier. Every path here is one `write` would allow.
        let c = claims_with(&["read", "ingest"]);
        for path in [
            "/api/config/compose_env",
            "/api/security/users",
            "/api/security/posture",
            "/api/cluster/nodes",
            "/api/v1/rag/deduplicate",
        ] {
            assert!(
                !scope_allows(&c, &Method::POST, path),
                "ingest must not grant POST {path}"
            );
            assert!(
                !scope_allows(&c, &Method::DELETE, path),
                "ingest must not grant DELETE {path}"
            );
        }
    }

    #[test]
    fn ingest_scope_does_not_grant_sibling_doc_paths_by_prefix() {
        // INGEST_PREFIXES is matched with starts_with, so a careless entry
        // like "/api/v1/docs" would hand over every future /docs/* route.
        let c = claims_with(&["read", "ingest"]);
        assert!(!scope_allows(&c, &Method::POST, "/api/v1/docs/delete"));
        assert!(!scope_allows(&c, &Method::POST, "/api/v1/docs"));
    }

    /// Document hold and purge hide and DELETE knowledge: the global write
    /// rule only, so an Operator may and nobody narrower can. No user, no
    /// `ingest` key and no add-on control scope reaches them.
    #[test]
    fn document_hold_routes_are_operator_only() {
        let paths = ["/api/v1/docs/hold", "/api/v1/docs/unhold", "/api/v1/docs/purge"];
        let operator = claims_with(&["read", "write"]);
        let user = claims_with(&["read"]);
        let ingest = claims_with(&["read", "ingest"]);
        for p in paths {
            assert!(scope_allows(&operator, &Method::POST, p), "operator must reach POST {p}");
            assert!(!scope_allows(&user, &Method::POST, p), "a user must not reach POST {p}");
            assert!(!scope_allows(&ingest, &Method::POST, p), "an ingest key must not reach POST {p}");
            // every add-on control scope, one at a time
            for scope in control_scope_rows().map(|(s, _, _)| s.to_string()).collect::<std::collections::BTreeSet<_>>() {
                let c = claims_with(&["read", scope.as_str()]);
                assert!(!scope_allows(&c, &Method::POST, p), "control scope {scope} must not reach POST {p}");
            }
        }
    }

    fn graph_requester(scopes: &[&str], role: Role) -> RequesterCtx {
        RequesterCtx {
            sub: "u".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }
    }

    /// Security review of #1001. `graph` adds to `read`; on its own it opens
    /// nothing, and a service-style subject only gets the six routes when its
    /// declaration carries BOTH scopes. (A service key cannot be issued
    /// `graph` at all: see `routes::users::a_service_key_cannot_be_issued_the_graph_scope`.)
    #[test]
    fn graph_without_read_opens_nothing_and_a_declared_service_gets_the_six() {
        use axum::http::Method;
        let tok = |sub: &str, scopes: &[&str]| Claims {
            sub: sub.into(),
            role: "user".into(),
            ..claims_with(scopes)
        };
        for p in GRAPH_QUERY_PATHS {
            // graph-only: refused, on the claims path and the requester path
            assert!(!scope_allows(&tok("u", &["graph"]), &Method::POST, p), "graph alone must not reach {p}");
            assert!(!requester_allows(&graph_requester(&["graph"], Role::User), &Method::POST, p));
            // a service that did not declare graph: refused
            assert!(!scope_allows(&tok("svc:evolve", &["read"]), &Method::POST, p));
            assert!(!scope_allows(&tok("svc:evolve", &[]), &Method::POST, p));
            // a service whose declaration lists read + graph: allowed
            assert!(scope_allows(&tok("svc:evolve", &["read", "graph"]), &Method::POST, p));
            assert!(requester_allows(&graph_requester(&["read", "graph"], Role::User), &Method::POST, p));
        }
    }

    /// a plain read-only account is refused every graph POST,
    /// the six query routes included. Without this the six would open to a
    /// User silently.
    #[test]
    fn a_plain_read_user_is_refused_every_graph_post() {
        let user = claims_with(&["read"]);
        assert_eq!(GRAPH_QUERY_PATHS.len(), 6);
        let mut paths: Vec<&str> = GRAPH_QUERY_PATHS.to_vec();
        paths.extend(["/api/v1/graph/recluster", "/api/v1/graph/entity-cleanup", "/api/v1/graph/extract-relations"]);
        for p in paths {
            assert!(!scope_allows(&user, &Method::POST, p), "a plain read User must be refused POST {p}");
            assert!(!requester_allows(&graph_requester(&["read"], Role::User), &Method::POST, p), "requester_allows agrees: {p}");
            // other scopes that are not `graph` do not open them either
            let ing = claims_with(&["read", "ingest"]);
            assert!(!scope_allows(&ing, &Method::POST, p), "ingest must not open POST {p}");
        }
    }

    #[test]
    fn graph_scope_opens_exactly_the_six_query_routes_by_post() {
        let c = claims_with(&["read", "graph"]);
        assert_eq!(c.resolved_role(), Role::User);
        let r = graph_requester(&["read", "graph"], Role::User);
        for p in GRAPH_QUERY_PATHS {
            assert!(scope_allows(&c, &Method::POST, p), "read+graph must reach POST {p}");
            assert!(requester_allows(&r, &Method::POST, p), "requester_allows agrees: {p}");
            // exact path: no suffix, no trailing slash, no child
            for bad in [format!("{p}/"), format!("{p}/x"), format!("{p}x")] {
                assert!(!scope_allows(&c, &Method::POST, &bad), "graph must not open POST {bad}");
            }
            // only POST (DELETE/PUT/PATCH are not query verbs)
            for m in [Method::DELETE, Method::PUT, Method::PATCH] {
                assert!(!scope_allows(&c, &m, p), "graph must not open {m} {p}");
            }
        }
        // Siblings stay closed.
        for p in [
            "/api/v1/graph/recluster",
            "/api/v1/graph/entity-cleanup",
            "/api/v1/graph/extract-relations",
            "/api/v1/graph/prune/restore",
            "/api/v1/graph/entities/delete",
            "/api/v1/graph",
            "/api/v1/graph/",
            "/api/snapshots/consolidate",
            "/api/config/compose_env",
        ] {
            assert!(!scope_allows(&c, &Method::POST, p), "graph must not open POST {p}");
            assert!(!requester_allows(&r, &Method::POST, p), "requester_allows: graph must not open POST {p}");
        }
        // A reader still reads, and the scope grants nothing else mutating.
        assert!(scope_allows(&c, &Method::GET, "/api/cluster/nodes"));
        assert!(!scope_allows(&c, &Method::POST, "/api/security/users"));
        // `graph` without `read` is still the User tier and still opens them
        // (scopes are additive; the role cascade is untouched).
        assert_eq!(claims_with(&["graph"]).resolved_role(), Role::User);
    }

    #[test]
    fn graph_scope_leaves_operators_unaffected() {
        let op = claims_with(&["read", "write"]);
        for p in GRAPH_QUERY_PATHS.iter().chain(["/api/v1/graph/recluster"].iter()) {
            assert!(scope_allows(&op, &Method::POST, p));
        }
        assert!(requester_allows(&graph_requester(&["write"], Role::Operator), &Method::POST, "/api/v1/graph/recluster"));
    }

    #[test]
    fn ingest_scope_keeps_the_read_tier_intact() {
        let c = claims_with(&["read", "ingest"]);
        assert!(scope_allows(&c, &Method::GET, "/api/cluster/nodes"));
        assert!(scope_allows(&c, &Method::POST, "/api/v1/rag/query"));
    }

    #[test]
    fn write_reaches_ingest_without_the_scope() {
        // Operators must not need a new scope to keep doing what they do.
        let c = claims_with(&["write"]);
        assert!(scope_allows(&c, &Method::POST, "/api/v1/docs/ingest"));
    }

    #[test]
    fn jwt_requires_matching_issuer_and_audience() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let secret = "test-secret-ha2b";
        let mk = |iss: Option<&str>, aud: Option<&str>| -> String {
            let mut c = serde_json::json!({
                "sub": "alice", "scopes": ["read"], "exp": 4102444800u64,
            });
            let obj = c.as_object_mut().unwrap();
            if let Some(i) = iss { obj.insert("iss".into(), i.into()); }
            if let Some(a) = aud { obj.insert("aud".into(), a.into()); }
            encode(&Header::new(Algorithm::HS256), &c,
                   &EncodingKey::from_secret(secret.as_bytes())).unwrap()
        };

        // Correct iss + aud → accepted.
        assert!(verify_token(&mk(Some(JWT_ISSUER), Some(JWT_AUDIENCE)), secret).is_ok());
        // Missing iss/aud (a pre-H-A2 token) → rejected.
        assert!(verify_token(&mk(None, None), secret).is_err());
        // Wrong audience / issuer → rejected.
        assert!(verify_token(&mk(Some(JWT_ISSUER), Some("other-service")), secret).is_err());
        assert!(verify_token(&mk(Some("evil"), Some(JWT_AUDIENCE)), secret).is_err());
    }

    /// PINNED (jsonwebtoken 11 port): the verifier accepts HS256 only on the
    /// secret path, refuses every other algorithm including `none`, refuses an
    /// expired token past the default 60s leeway, and still tolerates a few
    /// seconds of clock skew. A bump that changed any default fails here.
    #[test]
    fn jwt_pins_algorithm_expiry_and_leeway() {
        use base64::Engine as _;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let secret = "test-secret-jwt11";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let claims = |exp: u64| serde_json::json!({
            "sub": "alice", "scopes": ["read"], "exp": exp,
            "iss": JWT_ISSUER, "aud": JWT_AUDIENCE,
        });
        let sign = |alg: Algorithm, exp: u64| encode(
            &Header::new(alg), &claims(exp), &EncodingKey::from_secret(secret.as_bytes())).unwrap();

        // Baseline: HS256, unexpired.
        assert!(verify_token(&sign(Algorithm::HS256, now + 3600), secret).is_ok());
        // Other HMAC algorithms signed with the same secret are refused.
        for alg in [Algorithm::HS384, Algorithm::HS512] {
            let e = verify_token(&sign(alg, now + 3600), secret).unwrap_err();
            assert!(e.contains("unsupported algorithm"), "{alg:?}: {e}");
        }
        // `alg: none` (unsigned) is refused, with or without an empty signature.
        let b64 = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let body = b64(&claims(now + 3600).to_string());
        let head = b64(r#"{"alg":"none","typ":"JWT"}"#);
        assert!(verify_token(&format!("{head}.{body}."), secret).is_err());
        assert!(verify_token(&format!("{head}.{body}"), secret).is_err());
        // A tampered signature is refused.
        let good = sign(Algorithm::HS256, now + 3600);
        let tampered = format!("{}x", &good[..good.len() - 1]);
        assert!(verify_token(&tampered, secret).is_err());
        // Expiry: well past the 60s default leeway is refused; a few seconds
        // of skew is tolerated, exactly as before the port.
        assert!(verify_token(&sign(Algorithm::HS256, now - 3600), secret).is_err());
        assert!(verify_token(&sign(Algorithm::HS256, now - 10), secret).is_ok());
        assert!(verify_token(&sign(Algorithm::HS256, now - 120), secret).is_err());
    }
}

#[cfg(test)]
mod harness_rail_tests {
    use super::*;

    fn claims(harness: Option<&str>, conv: Option<&str>) -> Claims {
        Claims {
            sub: "alice".into(),
            exp: 4_102_444_800,
            role: "user".into(),
            scopes: vec!["read".into()],
            harness: harness.map(str::to_string),
            conv: conv.map(str::to_string),
        
            act: None,
            cnf: None,
        }
    }

    /// PINNED: a node-harness token exists only on the rail.
    #[test]
    fn a_node_harness_token_is_confined_to_the_rail() {
        let c = claims(Some("node:host8"), Some("c1"));
        let t = harness_turn_for(&c, "/api/harness/call").unwrap().unwrap();
        assert_eq!((t.node.as_str(), t.conversation_id.as_str()), ("host8", "c1"));
        for path in ["/api/inference", "/api/conversations/c1", "/api/usage/summary", "/mcp/user", "/api/harnessx", "/api/cluster/nodes"] {
            assert_eq!(harness_turn_for(&c, path), Err(StatusCode::FORBIDDEN), "{path}");
        }
    }

    #[test]
    fn a_node_harness_token_without_a_conversation_is_refused_everywhere() {
        assert_eq!(harness_turn_for(&claims(Some("node:host8"), None), "/api/harness/call"), Err(StatusCode::FORBIDDEN));
        assert_eq!(harness_turn_for(&claims(Some("node:host8"), Some("")), "/api/harness/call"), Err(StatusCode::FORBIDDEN));
        assert_eq!(harness_turn_for(&claims(Some("node:"), Some("c1")), "/api/harness/call"), Err(StatusCode::FORBIDDEN));
    }

    #[test]
    fn a_person_may_write_only_their_own_task_shapes() {
        use axum::http::Method;
        let id = "3f2a9c10-1111-4222-8333-444455556666";
        for p in ["/api/tasks", "/api/tasks/stop"] {
            assert!(is_task_owner_api(&Method::POST, p), "{p}");
        }
        for op in ["stop", "ask", "answer", "context", "resubmit"] {
            assert!(is_task_owner_api(&Method::POST, &format!("/api/tasks/{id}/{op}")), "{op}");
        }
        assert!(!is_task_owner_api(&Method::DELETE, "/api/tasks"));
        assert!(!is_task_owner_api(&Method::POST, "/api/tasks/submit"), "the scheduler's submit is not a person's task");
        assert!(!is_task_owner_api(&Method::POST, "/api/tasks/inference"));
        assert!(!is_task_owner_api(&Method::POST, &format!("/api/tasks/{id}")));
        assert!(!is_task_owner_api(&Method::POST, &format!("/api/tasks/{id}/stop/x")));
        assert!(!is_task_owner_api(&Method::POST, "/api/tasks/not-a-uuid/stop"));
    }

    #[test]
    fn a_harness_token_needs_an_enabled_account_at_or_above_its_role() {
        assert!(rail_token_admitted(Role::User, Some(Role::User)));
        assert!(rail_token_admitted(Role::User, Some(Role::Admin)), "an upgrade does not refuse; it waits for the next mint");
        assert!(rail_token_admitted(Role::Operator, Some(Role::Operator)));
        assert!(!rail_token_admitted(Role::Operator, Some(Role::User)), "a downgrade stops the running turn");
        assert!(!rail_token_admitted(Role::Admin, Some(Role::Operator)));
        assert!(!rail_token_admitted(Role::User, None), "disabled or absent");
    }

    /// The live-account check sits on the harness branch itself, before the
    /// turn is attached: a turn the check refuses never reaches the rail.
    #[test]
    fn the_harness_branch_rechecks_the_live_account() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let branch = body.find("harness_turn_for(&claims, &path)").expect("harness branch");
        let check = body[branch..].find("live_account_role(&state.db, &claims.sub)").expect("live check") + branch;
        let attach = body[branch..].find("request.extensions_mut().insert(turn)").expect("attach") + branch;
        assert!(check < attach);
        assert!(body[check..attach].contains("rail_token_admitted(claims.resolved_role(), live)"));
        assert!(body[check..attach].contains("StatusCode::UNAUTHORIZED"));
    }

    /// An add-on delegated token is confined, must belong to an add-on that
    /// delegates tasks, and is held to the account's live role, all before
    /// the extension handlers key their isolation on is attached.
    #[test]
    fn the_addon_delegation_branch_confines_then_checks_the_registry_then_the_live_role() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let branch = body.find("crate::addon_delegation::addon_of(&claims)").expect("addon branch");
        let confine = body[branch..].find("crate::addon_delegation::confine(").expect("confine") + branch;
        let registry = body[branch..].find("crate::addon_registry::get(addon)").expect("registry") + branch;
        let live = body[branch..].find("live_account_role(&state.db, &claims.sub)").expect("live check") + branch;
        let attach = body[branch..].find("AddonDelegation { addon: addon.to_string() }").expect("attach") + branch;
        assert!(confine < registry && registry < live && live < attach);
        assert!(body[registry..live].contains("e.delegates_tasks() && e.operator_enabled()"));
        assert!(body[registry..live].contains("StatusCode::FORBIDDEN"));
        assert!(body[live..attach].contains("rail_token_admitted(claims.resolved_role(), live)"));
        assert!(body[live..attach].contains("StatusCode::UNAUTHORIZED"));
        // The branch is before the terminal peer / kiosk / add-on-consumer
        // returns, so none of them can carry an ADT past it.
        let peer = body.find("claims.scopes.iter().any(|s| s == \"peer\")").expect("peer branch");
        assert!(attach < peer);
        // The existing disabled-account check on any delegated token stays.
        assert!(body.contains("claims.act.is_some() && !delegated_subject_enabled(&state.db, &claims.sub).await"));
    }

    #[test]
    fn other_tokens_are_untouched_by_the_rule() {
        assert_eq!(harness_turn_for(&claims(None, None), "/api/inference").unwrap(), None);
        assert_eq!(harness_turn_for(&claims(Some("mcp-external:laptop"), None), "/api/harness/call").unwrap(), None);
        // A plain user token that somehow carries `conv` is still not a harness token.
        assert_eq!(harness_turn_for(&claims(None, Some("c1")), "/api/harness/call").unwrap(), None);
    }

    #[test]
    fn mint_round_trips_and_refuses_an_insecure_secret() {
        let secret = "a-long-and-unguessable-test-secret-value-1234567890";
        std::env::set_var("NOO_JWT_SECRET", secret);
        let tok = mint_harness_jwt("alice", Role::User, "host8", "c1", 60).expect("minted");
        let c = verify_token(&tok, secret).expect("verifies");
        assert_eq!(c.sub, "alice");
        assert_eq!(c.harness.as_deref(), Some("node:host8"));
        assert_eq!(c.conv.as_deref(), Some("c1"));
        assert_eq!(c.resolved_role(), Role::User);
        assert!(harness_turn_for(&c, "/api/harness/call").unwrap().is_some());
        std::env::set_var("NOO_JWT_SECRET", "dev-secret-change-in-production");
        assert!(mint_harness_jwt("alice", Role::User, "host8", "c1", 60).is_none());
        std::env::remove_var("NOO_JWT_SECRET");
    }

    // ── The tier clamp ───────────────────────────
    //
    // Every one of these FAILS on the pre-clamp code, because there was no
    // clamp: the user-CRUD surface was `is_operator`-gated and an Operator
    // reached every account in the install, Admins included.

    /// The headline escalation: Operator → Admin in one request.
    #[test]
    fn operator_may_not_create_or_manage_an_admin() {
        assert!(
            may_grant_tier(Role::Operator, Role::Admin).is_err(),
            "an Operator minting an admin account is THE R1 finding"
        );
        assert!(
            may_manage(Role::Operator, "op", Role::Admin, "root").is_err(),
            "an Operator resetting an admin's password is account takeover"
        );
    }

    /// Peers are not below each other. Two Operators must not be able to
    /// disable or reset one another — that is a lateral takeover, and the
    /// rule is STRICTLY below, not "at or below".
    #[test]
    fn operator_may_not_manage_a_peer_operator() {
        assert!(may_manage(Role::Operator, "op-a", Role::Operator, "op-b").is_err());
        assert!(may_grant_tier(Role::Operator, Role::Operator).is_err());
    }

    /// What the Operator tier IS for.
    #[test]
    fn operator_manages_the_user_tier() {
        assert!(may_manage(Role::Operator, "op", Role::User, "alice").is_ok());
        assert!(may_grant_tier(Role::Operator, Role::User).is_ok());
    }

    /// Admin manages everyone — including other Admins. Somebody has to be
    /// able to reset an admin, or the tier is unrecoverable.
    #[test]
    fn admin_manages_every_tier_including_admins() {
        for target in [Role::User, Role::Operator, Role::Admin] {
            assert!(
                may_manage(Role::Admin, "root", target, "someone").is_ok(),
                "admin must manage {target:?}"
            );
            assert!(may_grant_tier(Role::Admin, target).is_ok());
        }
    }

    /// Self-service survives the clamp: an Operator changing its OWN
    /// password is not an escalation. (The dangerous self-mutations —
    /// self-disable, self-demotion — are refused by the per-endpoint guards
    /// in routes/users.rs, which this does not touch.)
    #[test]
    fn self_management_is_always_allowed() {
        assert!(may_manage(Role::Operator, "op", Role::Operator, "op").is_ok());
        assert!(may_manage(Role::User, "alice", Role::User, "alice").is_ok());
        assert!(may_manage(Role::Admin, "root", Role::Admin, "root").is_ok());
    }

    /// The User tier manages nobody but itself.
    #[test]
    fn user_tier_manages_only_itself() {
        assert!(may_manage(Role::User, "alice", Role::User, "bob").is_err());
        assert!(may_manage(Role::User, "alice", Role::Operator, "op").is_err());
        assert!(may_grant_tier(Role::User, Role::User).is_err());
    }

    /// An EMPTY caller subject must not make everyone "self". The
    /// cluster-HMAC path carries no RequesterCtx at all, but a malformed
    /// token with a blank `sub` would otherwise match every target with a
    /// blank name.
    #[test]
    fn an_empty_subject_is_not_a_self_match() {
        assert!(
            may_manage(Role::Operator, "", Role::Admin, "").is_err(),
            "a blank sub must not collapse into the self-escape"
        );
    }

    /// The clamp is strictly stricter than the `is_operator` check it sits
    /// behind: anything it admits below Admin, the old gate admitted too.
    /// Pins the DIRECTION, so a future "simplification" fails here rather
    /// than silently reopening the boundary.
    #[test]
    fn the_clamp_never_widens_what_operator_gating_allowed() {
        for caller in [Role::User, Role::Operator, Role::Admin] {
            for target in [Role::User, Role::Operator, Role::Admin] {
                if may_manage(caller, "a", target, "b").is_ok() && caller < Role::Admin {
                    assert!(
                        target < caller,
                        "clamp admitted {caller:?} → {target:?}, which is not strictly below"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod ws_deferral_tests {
    use super::*;
    use axum::body::Body;

    fn req(path: &str, upgrade: Option<&str>) -> Request {
        let mut b = Request::builder().uri(path);
        if let Some(u) = upgrade {
            b = b.header("upgrade", u);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn only_a_real_handshake_to_a_handler_verified_route_defers() {
        for path in HANDLER_VERIFIED_WS_ROUTES {
            assert!(defers_to_ws_handler(&req(path, Some("websocket"))), "{path}");
            assert!(defers_to_ws_handler(&req(&format!("{path}?token=stale"), Some("websocket"))));
            assert!(!defers_to_ws_handler(&req(path, None)), "{path}: no upgrade header, plain 401");
        }
        // Not enumerated → still the plain 401, upgrade header or not.
        for path in ["/ws", "/ws/companion/x", "/ws/terminal/1", "/api/config"] {
            assert!(!defers_to_ws_handler(&req(path, Some("websocket"))), "{path}");
        }
    }
}

#[cfg(test)]
mod old_cli_refusal_tests {
    /// An old `noo` binary signing with the controller secret is answered
    /// 403 with the reason and the upgrade, in the field every `noo` since
    /// the design prints (`detail`) and on its own (`hint`).
    #[tokio::test]
    async fn the_refusal_names_the_upgrade() {
        let r = super::old_cli_refusal();
        assert_eq!(r.status(), axum::http::StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["detail"].as_str().unwrap().contains("noo upgrade --all"), "{v}");
        assert_eq!(v["hint"], "noo upgrade --all");
        assert_eq!(v["code"], "cli_shared_secret_retired");
    }

    /// The controller door is the ONLY door a CLI actor is refused at, and
    /// the door admits nothing at all: the CLI and add-on
    /// refusals come first (their remedies are more specific), then every
    /// other caller is refused. No inference admission, no lane count of an
    /// admission, no Internal classification is left inside it.
    #[test]
    fn the_controller_door_admits_nothing() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let branch = body.split("if let Some(actor) = verify_controller_token(&t) {").nth(1).unwrap();
        let branch = branch.split("    if verify_cluster_token(&t) {").next().unwrap();
        assert!(branch.contains("return Ok(controller_door(&state.metrics, &actor, &path, &peer).await);"),
            "require_any_auth must hand a controller-secret bearer to controller_door and return its answer:\n{branch}");
        let door = src.split("pub async fn controller_door(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let cli = door.find("if crate::operator_auth::is_cli_actor(actor) {").expect("CLI refusal");
        let addon = door.find("crate::addon_hmac_refusal::refuse_addon_hmac(").expect("add-on refusal");
        let all = door.find("crate::controller_hmac_refusal::refuse(metrics, actor, path, peer).await")
            .expect("the controller door must refuse every remaining caller");
        assert!(cli < addon && addon < all, "CLI, then add-on, then everyone");
        for admission in ["next.run(", "if is_inference_surface {", "hmac_lane_uses(", "ClusterKind::Internal", "Consumer::all("] {
            assert!(!door.contains(admission) && !branch.contains(admission), "the controller door admits again: `{admission}` is back");
        }
    }

    /// Second review, item 7: the inference surface is not a node route.
    #[test]
    fn a_node_token_buys_no_inference_route() {
        for p in ["/api/external/embeddings", "/api/external/rerank", "/v1/chat/completions", "/api/external/chat/completions"] {
            assert!(!super::NODE_ROUTES.iter().any(|(_, r)| *r == p), "{p} is a node route again");
            assert!(!super::node_route_allowed("POST", p, "host8"), "{p}");
        }
        assert!(super::node_route_allowed("POST", "/api/embed", "host8"), "the agent's embedding helper stays");
    }

    /// Second review: the fleet door's out-of-place check (a controller
    /// service leaf, or a keyless compose peer) runs FIRST — after the add-on
    /// refusal, before the certificate/actor check, `node_route_allowed` and
    /// the inference refusal — and returns its refusal.
    #[test]
    fn the_fleet_door_refuses_an_out_of_place_token_before_anything_else() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let door = body.split("    if verify_cluster_token(&t) {").nth(1).expect("the fleet door");
        let addon = door.find("crate::addon_hmac_refusal::refuse_addon_hmac(").expect("add-on refusal");
        let check = door.find("crate::controller_hmac_refusal::fleet_token_placement(").expect("the out-of-place check");
        let refuse = door.find("return Ok(crate::controller_hmac_refusal::refuse_fleet(").expect("its refusal is returned");
        assert!(addon < check && check < refuse);
        for later in ["actor != peer.node", "node_route_allowed(", "if is_inference_surface {", "hmac_lane_uses("] {
            let at = door.find(later).unwrap_or_else(|| panic!("{later} missing from the fleet door"));
            assert!(refuse < at, "the out-of-place refusal must precede `{later}`");
        }
    }

    /// Review L5: a VALID controller-signed token, sent over HTTP to an axum
    /// router whose middleware does exactly what `require_any_auth` does with
    /// one — verify it under the controller secret, then hand it to
    /// `controller_door` — is a 403 for every actor and every route, and the
    /// handler behind never runs. (The full middleware needs live Postgres and
    /// NATS to build its state; the door is the whole of its decision, and
    /// `the_controller_door_admits_nothing` pins that require_any_auth calls it.)
    #[tokio::test]
    async fn a_valid_controller_token_is_refused_through_the_door() {
        let secret: &'static str = "controller-secret-for-the-test";
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let metrics = std::sync::Arc::new(crate::metrics::MetricsState::new());
        let m = metrics.clone();
        let app = axum::Router::new()
            .fallback(|| async { (axum::http::StatusCode::OK, "ADMITTED") })
            .layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
                let m = m.clone();
                async move {
                    let t = req.headers().get("authorization").and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default().to_string();
                    if super::verify_cluster_token_inner(&t, secret, now) {
                        let actor = t.split(':').next().unwrap_or_default().to_string();
                        let path = req.uri().path().to_string();
                        return super::controller_door(&m, &actor, &path, &crate::legacy_lanes::PeerFacts::default()).await;
                    }
                    next.run(req).await
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::new();
        // The control: an unsigned request reaches the handler.
        let ok = client.get(format!("http://{addr}/api/config")).send().await.unwrap();
        assert_eq!(ok.status().as_u16(), 200, "the harness admits what the door does not see");
        for (actor, path) in [("worker", "/api/v1/graph/extract"), ("internal", "/v1/chat/completions"),
                              ("heartbeat", "/api/channels/send"), ("trellion", "/api/external/embeddings"), ("cli", "/api/config")] {
            let token = crate::routes::cluster::mint_cluster_token(actor, secret, now).unwrap();
            assert!(super::verify_cluster_token_inner(&token, secret, now), "the token must be VALID for this to mean anything");
            let resp = client.get(format!("http://{addr}{path}")).bearer_auth(&token).send().await.unwrap();
            assert_eq!(resp.status().as_u16(), 403, "{actor} on {path}");
            assert_ne!(resp.text().await.unwrap(), "ADMITTED");
        }
        let out = metrics.render().await;
        assert!(out.contains("controller_shared_secret_refused") && out.contains("cli_shared_secret_refused")
            && out.contains("addon_shared_secret_refused"), "{out}");
        assert!(!out.contains("cluster_hmac_non_inference") && !out.contains(r#"lane="self_call_shared_secret""#), "{out}");
    }
}

/// The tier gate's GET default for a `User` is an allow-list (`USER_READ_PATHS`
/// / `USER_READ_PREFIXES`), not "every GET". These tests pin both halves: the
/// console still renders for a User, and the installation-wide reads that used
/// to pass (audit views, violations, PKI, config, fleet desired-config) do not.
#[cfg(test)]
mod user_read_allowlist_tests {
    use super::*;
    use axum::http::Method;

    fn tier(role: &str, scopes: &[&str]) -> Claims {
        Claims {
            sub: "alice".into(),
            exp: 4102444800,
            role: role.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            harness: None,
            conv: None,
            act: None,
            cnf: None,
        }
    }

    /// Every GET `ui/apps/web` makes for a signed-in person (typed client +
    /// `apiGet` + raw fetches), minus the admin-only panes' sources (below).
    /// If a console pane for a plain account stops rendering, a path is
    /// missing from `USER_READ_PATHS` / `USER_READ_PREFIXES`.
    const CONSOLE_GETS_FOR_A_USER: &[&str] = &[
        "/health",
        "/auth/me",
        "/v1/models",
        "/api/version",
        "/api/events/stream",
        "/api/cluster/status",
        "/api/cluster/nodes",
        "/api/cluster/backends",
        "/api/cluster/gpu-metrics",
        "/api/scheduler/status",
        "/api/models/cached",
        "/api/jobs",
        "/api/jobs/history",
        "/api/jobs/0f9c1d2e-0000-4000-8000-000000000001",
        "/api/heartbeat/status",
        "/api/heartbeat/tasks",
        "/api/heartbeat/tasks/t1/artifacts",
        "/api/autonomy/status",
        "/api/autonomy/decisions",
        "/api/alerts/clients",
        "/api/approval/stats",
        "/api/channels/status",
        "/api/coordinator/context",
        "/api/conversations",
        "/api/conversations/with-preview",
        "/api/conversations/c1",
        "/api/conversations/stats/overview",
        "/api/conversations/stats/tools",
        "/api/memory/health",
        "/api/memory/status",
        "/api/memory/storage-stats",
        "/api/memory/embed/status",
        "/api/memory/search",
        "/api/v1/rag/status",
        "/api/v1/docs",
        "/api/v1/docs/d1",
        "/api/v1/graph/overview",
        "/api/v1/graph/stats",
        "/api/v1/graph/prune/staged",
        "/api/v1/graph/entities",
        "/api/v1/recall/status",
        "/api/v1/walks",
        "/api/v1/walks/settings",
        "/api/v1/ops",
        "/api/v1/ops/op1",
        "/api/v1/settings/user-dirs",
        "/api/docs/openapi",
        "/api/docs/runbooks",
        "/api/docs/runbooks/upgrade",
        "/api/addons/trellion/console-piece",
        "/api/usage/summary",
        "/api/usage/me",
        "/api/agents/messages",
        "/api/security/service-keys/self",
        "/ws/coordinator",
        "/upload/f1",
    ];

    /// Reads that describe the installation, not the person. Closed to a
    /// `User`; open to Operator and Admin.
    const OPERATOR_ONLY_GETS: &[&str] = &[
        "/api/security/audit-history",
        "/api/security/audit/stats",
        "/api/security/audit/verify",
        "/api/security/violations",
        "/api/security/pki/status",
        "/api/security/posture",
        "/api/security/users",
        "/api/security/service-keys",
        "/api/config",
        "/api/config/search",
        "/api/settings",
        "/api/settings/export",
        "/api/settings/flags",
        "/api/v1/settings",
        "/api/v1/settings/export",
        "/api/v1/settings/browse",
        "/api/v1/settings/restart-status",
        "/api/cluster/nodes/host3/desired-config",
        "/api/cluster/maintenance",
        "/api/cluster/model-classes",
        "/api/cluster/self-node",
        "/api/cluster/proposals/p1",
        "/api/cluster/provision-bundle/host3/status",
        "/api/db/migrations",
        "/api/snapshots",
        "/api/kb/rules",
        "/api/kb/grants",
        "/api/agents/trust",
        "/api/agents/keys/review",
        "/api/channels/telegram/messages",
        "/api/users",
        "/api/mesh/status",
        "/api/tools/registry/raw",
        "/api/exec-approval/status",
        "/api/v1/admin/walks",
        "/api/an/invented/route/next/year",
    ];

    #[test]
    fn the_console_still_renders_for_a_user() {
        let user = tier("user", &["read"]);
        for p in CONSOLE_GETS_FOR_A_USER {
            assert!(scope_allows(&user, &Method::GET, p), "User must still GET {p}");
        }
    }

    #[test]
    fn a_user_cannot_read_installation_wide_data() {
        let user = tier("user", &["read"]);
        for p in OPERATOR_ONLY_GETS {
            assert!(!scope_allows(&user, &Method::GET, p), "User must NOT GET {p}");
            assert!(!scope_allows(&user, &Method::HEAD, p), "User must NOT HEAD {p}");
        }
    }

    #[test]
    fn operators_and_admins_read_all_of_it() {
        let op = tier("operator", &["read", "write"]);
        let admin = tier("admin", &["read", "write", "admin"]);
        for p in OPERATOR_ONLY_GETS.iter().chain(CONSOLE_GETS_FOR_A_USER) {
            assert!(scope_allows(&op, &Method::GET, p), "operator GET {p}");
            assert!(scope_allows(&admin, &Method::GET, p), "admin GET {p}");
        }
    }

    /// A route added next year is closed to a User until it is listed.
    #[test]
    fn an_unlisted_route_is_closed_to_a_user_by_default() {
        let user = tier("user", &["read"]);
        assert!(!user_may_read("/api/brand/new/route"));
        assert!(!scope_allows(&user, &Method::GET, "/api/brand/new/route"));
        // prefixes are directories, not stems
        assert!(!user_may_read("/api/conversationsx"));
        assert!(!user_may_read("/wsdl"));
    }

    /// The writes a User had before are untouched by the GET change.
    #[test]
    fn user_writes_are_unchanged() {
        let user = tier("user", &["read"]);
        assert!(scope_allows(&user, &Method::POST, "/api/inference"));
        assert!(!scope_allows(&user, &Method::PUT, "/api/config/search"));
    }

    /// The allow-list entries all resolve: no entry names a prefix or path
    /// that is not a clean absolute path (typo guard).
    #[test]
    fn allow_list_entries_are_absolute_paths() {
        for p in USER_READ_PATHS.iter().chain(USER_READ_PREFIXES) {
            assert!(p.starts_with('/'), "{p}");
            assert!(!p.contains("//") && !p.contains(' '), "{p}");
        }
    }

    /// The floor is checked on the JWT branch before any role, kiosk, peer or
    /// harness handling, so it covers every bearer path and the `/ws/*`
    /// handshake (which passes the same middleware).
    #[test]
    fn the_session_floor_is_checked_right_after_the_token_verifies() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let verify = body.find("if let Ok(claims) = verify_token(&t, &secret) {").expect("jwt branch");
        let floor = body.find("crate::session_floor::refuses(&state, &claims.sub, &t)").expect("floor check");
        let first_branch = body.find("harness_turn_for(&claims, &path)").expect("harness branch");
        assert!(verify < floor && floor < first_branch, "floor must precede every other use of the claims");
        assert!(body[floor..first_branch].contains("StatusCode::UNAUTHORIZED"));
    }
}

/// A token on the v2 wire form is decided as v2 — admitted, or a 401 — and
/// never reaches the v1 verifier or the `cluster_hmac_v1_refused` count. The 0.6.7
/// roll counted v1 on agents' heartbeats with no agent-side fallback, and
/// "the gateway read a v2 token as v1" was the first suspect; these pin
/// that it cannot.
#[cfg(test)]
mod v2_never_counts_as_v1_tests {
    use super::*;

    const SECRET: &str = "fleet-secret-for-tests";
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_signed_v2_token_never_verifies_as_v1() {
        for actor in ["host2", "pop-os", "mcmini", "1800000000", "v2", "a"] {
            for (method, uri, body) in [("POST", "/api/cluster/nodes/x/heartbeat", &b"{}"[..]), ("GET", "/api/cluster/nodes/x/desired-config", &b""[..])] {
                let tok = crate::cluster_token_v2::sign(SECRET, method, uri, body, actor, NOW, "00112233445566778899aabbccddeeff").unwrap();
                assert!(crate::cluster_token_v2::is_v2(&tok), "{tok}");
                assert!(!verify_cluster_token_inner(&tok, SECRET, NOW), "a v2 token passed the v1 verifier: {tok}");
            }
        }
    }

    /// The one string that is both: a v1 token whose actor is literally
    /// `v2`. It takes the v2 branch (prefix), does not parse as v2, and is
    /// a 401 — it is not counted as v1 either.
    #[test]
    fn a_v1_token_with_the_v2_prefix_is_refused_not_counted() {
        let v1 = crate::routes::cluster::mint_cluster_token("v2", SECRET, NOW).unwrap();
        assert!(verify_cluster_token_inner(&v1, SECRET, NOW), "precondition: it is a valid v1 token");
        assert!(crate::cluster_token_v2::is_v2(&v1), "precondition: it carries the v2 prefix");
        assert!(crate::cluster_token_v2::parse(&v1).is_none(), "it must not parse as v2, so admit refuses it");
    }

    /// Structural: in `require_any_auth`, a v2-prefixed token goes to
    /// `admit_cluster_token_v2` and a failure there RETURNS (no fall-through
    /// to the v1 path), and a token that did not arrive as v2 is ALWAYS
    /// refused (counted as `cluster_hmac_v1_refused`) with no gate to re-admit it.
    #[test]
    fn the_middleware_decides_a_v2_token_and_refuses_v1_unconditionally() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let v2 = body.find("if crate::cluster_token_v2::is_v2(&t) {").expect("the v2 branch");
        let admit = body[v2..].find("admit_cluster_token_v2(").expect("admit") + v2;
        let arm = &body[admit..admit + 400];
        assert!(arm.contains("from_v2 = true") && arm.contains("Err(status) => return Err(status)"),
            "a v2 token must be admitted (from_v2) or refused, never handed on: {arm}");
        // There is no admitted-v1 count and no gate left.
        assert!(!src.contains(&["legacy_lanes::hmac_v1", "_use("].concat()), "the admitted v1 count is deleted");
        assert!(!body.contains(&["v1_", "allowed"].concat()), "the NOO_CLUSTER_TOKEN_V1 gate is deleted");
        let gate = body.find("if from_v2 {").expect("the from_v2 split");
        let refused = body.find("legacy_lanes::hmac_v1_refused_use(").expect("the v1 refusal count");
        assert!(gate < refused, "the refusal must be the not-from-v2 branch");
        assert!(body[gate..].contains("} else {") && body[refused..].contains("return Ok(v1_refusal());"),
            "the not-from-v2 branch must return the refusal");
    }

    /// A gateway that has just started has no Redis connection yet: a fresh
    /// v2 token is still admitted (the local nonce set), and a replay is
    /// still refused — neither outcome is "not v2".
    #[tokio::test]
    async fn at_startup_with_no_redis_a_v2_token_is_still_decided() {
        let n = "0123456789abcdef0123456789abcdef";
        let t = crate::cluster_token_v2::sign(SECRET, "POST", "/api/cluster/nodes/host7/heartbeat", b"{\"a\":1}", "host7", NOW, n).unwrap();
        let go = || crate::cluster_token_v2::verify_and_spend(None, SECRET, &t, "POST", "/api/cluster/nodes/host7/heartbeat", b"{\"a\":1}", NOW + 1);
        assert_eq!(go().await.as_deref(), Some("host7"));
        assert_eq!(go().await, None, "the replay is refused without Redis");
    }
}

/// A service key calling the transcribe routes with its own key as the bearer
/// (trellion's audio ingest, `POST /api/voice/transcribe/detailed`).
///
/// The middleware itself needs a database to resolve a key, so these drive the
/// SAME decision functions it calls (`direct_key_scope_for`,
/// `direct_key_admission`) from a router-level layer in front of a stub STT
/// upstream, over real HTTP: the transport is real, the STT upstream is the
/// stub. A structural test pins that `require_any_auth` is wired to them.
#[cfg(test)]
mod voice_direct_key_tests {
    use super::*;
    use axum::http::Method;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;
    use std::sync::{Arc, Mutex};

    fn key(scopes: &[&str]) -> Consumer {
        Consumer {
            name: "svc:trellion".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            rpm_limit: None,
            user: None,
            user_scopes: Vec::new(),
            user_role: None,
        }
    }

    const DETAILED: &str = "/api/voice/transcribe/detailed";
    const PLAIN: &str = "/api/voice/transcribe";

    #[test]
    fn only_the_two_transcribe_posts_are_direct_key_doors() {
        assert_eq!(direct_key_scope_for(DETAILED, &Method::POST), Some("voice:transcribe"));
        assert_eq!(direct_key_scope_for(PLAIN, &Method::POST), Some("voice:transcribe"));
        for (m, p) in [
            (Method::GET, DETAILED),
            (Method::POST, "/api/voice/synthesize"),
            (Method::GET, "/api/voice/status"),
            (Method::POST, "/api/voice/transcribe/other"),
            (Method::POST, "/api/config/voice"),
            (Method::POST, "/api/external/embeddings"),
            (Method::POST, "/api/channels/send"),
        ] {
            assert_eq!(direct_key_scope_for(p, &m), None, "{m} {p} must not be a direct-key door");
        }
    }

    #[test]
    fn the_scope_is_in_the_issuable_vocabulary_and_never_a_default() {
        assert!(is_control_scope(VOICE_TRANSCRIBE_SCOPE));
        assert_eq!(DIRECT_KEY_SCOPES, &[VOICE_TRANSCRIBE_SCOPE]);
        // Only the voice rows are direct-key doors: no other control scope leaks in.
        for (s, m, p) in control_scope_rows() {
            let door = direct_key_scope_for(&p.replace('*', "x"), &m.parse::<Method>().unwrap());
            assert_eq!(door.is_some(), *s == VOICE_TRANSCRIBE_SCOPE, "{s} {m} {p}");
        }
    }

    #[test]
    fn the_decision_admits_the_scope_refuses_its_absence_and_ignores_non_keys() {
        assert!(matches!(direct_key_admission(Some(key(&["chat", "voice:transcribe"])), "voice:transcribe"), DirectKey::Admit(_)));
        for scopes in [&["chat", "embeddings", "metrics"][..], &[][..], &["voice"][..], &["voice:transcribe:x"][..]] {
            assert!(
                matches!(direct_key_admission(Some(key(scopes)), "voice:transcribe"), DirectKey::Forbidden(_)),
                "{scopes:?} must be refused"
            );
        }
        assert!(matches!(direct_key_admission(None, "voice:transcribe"), DirectKey::NotAKey));
    }

    /// Persons keep their access: the tier gate is untouched by the new scope.
    #[test]
    fn a_person_token_is_unchanged() {
        let person = Claims {
            sub: "alice".into(),
            exp: 4102444800,
            role: "user".into(),
            scopes: vec!["read".into()],
            harness: None,
            conv: None,
            act: None,
            cnf: None,
        };
        for p in [DETAILED, PLAIN, "/api/voice/synthesize"] {
            assert!(scope_allows(&person, &Method::POST, p), "a person still reaches POST {p}");
        }
        // and the new scope opens nothing outside the two routes
        let holder = Claims { scopes: vec!["voice:transcribe".into()], ..person };
        assert!(!control_scope_allows(&holder.scopes, &Method::POST, "/api/voice/synthesize"));
        assert!(!control_scope_allows(&holder.scopes, &Method::POST, "/api/config/voice"));
        assert!(!scope_allows(&holder, &Method::POST, "/api/cluster/nodes"));
    }

    #[test]
    fn require_any_auth_routes_the_door_through_the_pure_decision() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).unwrap().split("\npub async fn ").next().unwrap();
        let door = body.find("direct_key_scope_for(&path, request.method())").expect("the direct-key door");
        let admission = body.find("direct_key_admission(service_keys::resolve(&state.db, &t).await, required)").expect("the decision");
        let inference = body.find("    if is_inference_surface {\n        // Named per-consumer").expect("the inference block");
        assert!(door < admission && admission < inference, "the door precedes the inference block");
        // A non-key bearer must fall through (to the 401), not be admitted.
        assert!(body[door..inference].contains("DirectKey::NotAKey => {}"));
    }

    /// Stub STT upstream + the real decision in a layer, over real HTTP.
    async fn serve(found: Option<Consumer>) -> (String, Arc<Mutex<u32>>) {
        let reached = Arc::new(Mutex::new(0u32));
        let hits = reached.clone();
        let found = Arc::new(found);
        let upstream = move || {
            let hits = hits.clone();
            async move {
                *hits.lock().unwrap() += 1;
                axum::Json(serde_json::json!({"text": "hello", "segments": []}))
            }
        };
        let gate = move |req: axum::extract::Request, next: axum::middleware::Next| {
            let found = found.clone();
            async move {
                let Some(required) = direct_key_scope_for(req.uri().path(), req.method()) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                match direct_key_admission((*found).clone(), required) {
                    DirectKey::Admit(_) => next.run(req).await,
                    DirectKey::Forbidden(r) => r,
                    DirectKey::NotAKey => StatusCode::UNAUTHORIZED.into_response(),
                }
            }
        };
        let app = Router::new()
            .route(DETAILED, post(upstream))
            .layer(axum::middleware::from_fn(gate));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}{DETAILED}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await });
        (url, reached)
    }

    #[tokio::test]
    async fn a_key_with_the_scope_reaches_the_stt_upstream_and_one_without_does_not() {
        let (url, reached) = serve(Some(key(&["chat", "voice:transcribe"]))).await;
        let r = reqwest::Client::new().post(&url).send().await.unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::OK);
        assert_eq!(r.json::<serde_json::Value>().await.unwrap()["text"], "hello");
        assert_eq!(*reached.lock().unwrap(), 1, "the upstream must be reached");

        let (url, reached) = serve(Some(key(&["chat", "embeddings", "metrics"]))).await;
        let r = reqwest::Client::new().post(&url).send().await.unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::FORBIDDEN);
        let body = r.json::<serde_json::Value>().await.unwrap();
        assert_eq!(body["error"]["type"], "forbidden");
        assert_eq!(body["error"]["message"], "service key lacks 'voice:transcribe' scope");
        assert_eq!(*reached.lock().unwrap(), 0, "a refused key must never reach the upstream");

        let (url, reached) = serve(None).await;
        let r = reqwest::Client::new().post(&url).send().await.unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(*reached.lock().unwrap(), 0);
    }
}
