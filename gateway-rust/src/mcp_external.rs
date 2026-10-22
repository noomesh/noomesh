// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The user MCP door — `/mcp/user`, served natively by the gateway.
//!
//! Replaces the Python hub's external endpoint. Three things motivated the
//! move, in order of how much they cost us:
//!
//! 1. **Identity.** The Python door authenticated every call as the shared
//!    cluster-HMAC actor `mcp-server`. The gateway scopes HMAC callers in
//!    their own branch of `require_any_auth`, so a read-scope collaborator
//!    holding an MCP key got operator-tier access to every tool. Here, a key
//!    MUST name a user and the call runs under that user's own JWT.
//! 2. **The shared token.** `NOO_MCP_EXTERNAL_TOKEN` doubled as the door's
//!    on-switch AND a valid credential, so the door could not be enabled
//!    without also minting an unattributed operator key. Gone: enabling is
//!    [`ENABLED_ENV`], authenticating is a named key, and they are separate.
//! 3. **Protocol surface.** The hub broke on 2026-07-29 when the `mcp`
//!    package floated to 2.0 and deleted `Server.list_tools`.
//!
//! **Tools are data, not code.** `gateway-rust/mcp-tools.json` is generated
//! from the Python `ToolDef` registry by `scripts/build-mcp-manifest.py` and
//! embedded at compile time. Across all 129 ToolDefs exactly one overrides
//! `get_body` and one overrides `get_params`, so path templating and
//! body/param construction are fully derivable from metadata — one generic
//! dispatcher covers the whole surface, and adding a tool on the Python side
//! is a manifest regen, not Rust work.
//!
//! Responses are the gateway's JSON, unchanged. The Python door ran 16 of
//! these 24 tools through bespoke prose formatters. Those formatters were dropped
//! (four returned a single field; two truncated lists silently).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::mcp_protocol::{self, Envelope};
use crate::state::AppState;

pub(crate) use crate::mcp_protocol::rpc_error;

/// Opt-in switch. Deliberately NOT "is a token configured" — conflating the
/// two is what made the Python door impossible to run without also creating
/// an operator-tier credential.
const ENABLED_ENV: &str = "NOO_MCP_EXTERNAL_ENABLED";
/// Largest JSON-RPC request either door accepts (256 KiB).
pub(crate) const MAX_RPC_BODY: usize = 256 * 1024;

/// Server name reported in `serverInfo`. Unchanged from the Python hub.
const SERVER_NAME: &str = "mesh-external";

// No session state, deliberately. Legacy MCP Streamable HTTP let a server
// assign a session id on initialize; this door never did, so identity is
// re-resolved from the presented credential on EVERY request. That means a
// revoked or narrowed key stops working immediately instead of at session
// end, and there is no session id to hijack or to bind a second caller onto.
// The Python hub had to hold a per-session identity map and re-verify on
// reuse precisely because it kept sessions; not keeping them removes the
// whole class — and is what spec 2026-07-28 now mandates. Protocol-era
// handling (legacy `initialize` vs modern per-request `_meta`) lives in
// `mcp_protocol`; this file is only about WHO is calling.

/// Short-lived: minted per tool call, never leaves the process.
const CALLER_JWT_TTL_SECS: u64 = 300;

// ───────────────────────────── manifest ─────────────────────────────

// Manifest structs + the request-building/dispatch helpers below are
// pub(crate): the LOCAL door (`mcp_local.rs`, MCP_HUB_PORT.md phase 2)
// serves the full-registry manifest through the same machinery — only
// auth and self-call identity differ per door.
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) version: u32,
    pub(crate) tools: Vec<ToolSpec>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ToolSpec {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) input_schema: Value,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) timeout_secs: u64,
    /// python field name → wire key, for tools declaring `Field(alias=…)`.
    #[serde(default)]
    pub(crate) aliases: HashMap<String, String>,
    /// When set, names the single argument whose value IS the request body,
    /// instead of the body being an object of every non-path argument.
    ///
    /// Needed because a route can take the payload directly:
    /// `PUT /api/config/{section}` deep-merges the body INTO the section, so
    /// wrapping it in the argument's own name wrote a key literally called
    /// `updates` and left the real keys untouched. The Python `ToolDef` can
    /// express that with a `get_body` override, but these doors never run
    /// Python — they build the request from this manifest — so the shape has
    /// to travel as data.
    #[serde(default)]
    pub(crate) body_field: String,
}

/// Bumped by the generator when the consumer contract changes. Asserted here
/// so a stale checked-in manifest fails at startup instead of silently
/// serving a shape this code cannot honour.
pub(crate) const EXPECTED_MANIFEST_VERSION: u32 = 2;

static MANIFEST: LazyLock<Manifest> = LazyLock::new(|| {
    let raw = include_str!("../mcp-tools.json");
    let m: Manifest = serde_json::from_str(raw)
        .expect("mcp-tools.json is malformed — regenerate with scripts/build-mcp-manifest.py");
    assert_eq!(
        m.version, EXPECTED_MANIFEST_VERSION,
        "mcp-tools.json version {} != expected {} — regenerate it",
        m.version, EXPECTED_MANIFEST_VERSION
    );
    m
});

pub(crate) fn tool(name: &str) -> Option<&'static ToolSpec> {
    MANIFEST.tools.iter().find(|t| t.name == name)
}

pub fn enabled() -> bool {
    matches!(
        std::env::var(ENABLED_ENV).unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // `/mcp/user` is the name that says what this door IS: the caller's
        // key resolves to a noomesh ACCOUNT and every tool call runs under
        // that user's own scopes and KB roles. `/mcp/external`, the original
        // path, was an alias from 2026-07-28 until stack-v0.2.40 and is gone:
        // a client still on it gets the router's 404, not a silent door.
        // GET was the legacy standalone SSE stream and DELETE the legacy
        // session teardown; this door has neither (spec 2026-07-28 → 405).
        .route(
            "/mcp/user",
            post(handle).get(mcp_protocol::method_not_allowed).delete(mcp_protocol::method_not_allowed),
        )
        // A JSON-RPC call is small. The default 2 MiB body is a free
        // amplifier for an authenticated-but-hostile client.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_RPC_BODY))
}

// ───────────────────────────── identity ─────────────────────────────

/// Who a request is acting for. There is no operator variant on purpose:
/// every call through this door is attributable to a `noo_users` account.
struct Caller {
    consumer: String,
    user: String,
    user_scopes: Vec<String>,
    /// The bound account's CURRENT role, resolved by
    /// `service_keys::resolve` at validation time — the tier this door acts
    /// with is never the one captured when the key was issued (#408).
    user_role: crate::auth::Role,
}

/// Resolve the bearer to a named, user-bound key.
///
/// An unbound (machine) key is REFUSED rather than falling back to the
/// operator credential. That fallback is precisely the escalation this door
/// exists to remove: it would let anyone holding a machine key act with more
/// authority than any human account on the system. A machine that needs MCP
/// gets its own `noo_users` account and a key bound to it.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Caller, Response> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| rpc_http_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;

    let consumer = crate::service_keys::resolve(&state.db, bearer)
        .await
        .ok_or_else(|| rpc_http_error(StatusCode::FORBIDDEN, "unknown or revoked key"))?;

    let redis = state.redis.as_ref();
    admit(consumer, |name, limit| async move {
        // Redis absent or erroring: meter in-process instead of not at all.
        let Some(redis) = redis else {
            return crate::service_keys::local_quota_exceeded(&name, limit);
        };
        match redis.check_consumer_quota(&name, limit).await {
            Ok(crate::cache::RateResult::Limited { retry_after }) => Some(retry_after),
            Ok(_) => None,
            Err(_) => crate::service_keys::local_quota_exceeded(&name, limit),
        }
    })
    .await
}

/// Decide whether a resolved key may use the user door. `charge` is the quota
/// counter: it returns `Some(retry_after)` when the consumer is over its cap.
/// Split out so the ORDER of the checks is testable without Redis.
async fn admit<F, Fut>(consumer: crate::service_keys::Consumer, charge: F) -> Result<Caller, Response>
where
    F: FnOnce(String, i64) -> Fut,
    Fut: std::future::Future<Output = Option<i64>>,
{
    if !consumer.has_scope("mcp") {
        return Err(rpc_http_error(
            StatusCode::FORBIDDEN,
            "key lacks the 'mcp' scope",
        ));
    }

    let Some(user) = consumer.user.clone() else {
        tracing::warn!(
            consumer = %consumer.name,
            "mcp_external_unbound_key_refused"
        );
        return Err(rpc_http_error(
            StatusCode::FORBIDDEN,
            "this key is not bound to a user, so there is no identity to run \
             tool calls as. `noo security service-key issue <consumer>` mints unbound \
             machine keys for /api/external and cannot bind one. The account \
             owner mints a bound key for themselves: `noo auth login` then \
             `noo security service-key self` (or the dashboard's MCP key \
             button, which is the same endpoint)",
        ));
    };

    // Per-consumer quota, charged LAST: only a request that will be served
    // spends the bound account's budget (a wrong-scope or unbound key used to
    // burn it before being refused). This door is a PUBLIC path, so it returns from
    // `require_any_auth` before the service-key branch where the quota is
    // normally applied — meaning a `--quota` on an MCP key was silently
    // unenforced, and only the coarse per-IP limiter applied (which is
    // skipped for a loopback peer). the design.
    // Every consumer is metered: a key with no cap of its own gets the door
    // default (`service_keys::door_rpm`), not an unbounded budget.
    let limit = crate::service_keys::door_rpm(&consumer);
    if let Some(retry_after) = charge(consumer.name.clone(), limit).await {
        return Err(crate::auth::consumer_quota_exceeded(&consumer.name, retry_after));
    }

    // A bound user always resolves with a role (`service_keys::resolve`
    // fails closed to User); `None` here would mean the invariant broke, so
    // take the strict floor rather than guessing.
    let user_role = consumer.user_role.unwrap_or(crate::auth::Role::User);

    Ok(Caller {
        consumer: consumer.name,
        user,
        user_scopes: consumer.user_scopes,
        user_role,
    })
}

/// Loopback base for the door's self-call, when NOO_SELF_URL is unset.
///
/// The scheme has to FOLLOW the listener. A hardcoded `http://` shipped in
/// #420 and broke every tool call on any TLS deployment — the door
/// authenticated the caller correctly and then could not reach the API it
/// proxies to:
///
///   gateway unreachable: error sending request for url
///     (http://127.0.0.1:8080/api/v1/rag/query)
///
/// which reads like the gateway is down rather than like a scheme mismatch.
/// The scheme is https, always: the gateway has exactly one listener, the
/// TLS acceptor (main.rs; `tls::require_server_material`), so `NOO_TLS_CERT`
/// no longer decides anything here — it is required to be set for this
/// process to be running at all.
///
/// Loopback regardless of NOO_BIND_ADDR: the process listens on 0.0.0.0
/// inside the container, so 127.0.0.1 always reaches it, and a self-call has
/// no business leaving the host even when the public bind is a tailnet IP.
pub(crate) fn self_url_default() -> String {
    let port = std::env::var("NOO_PORT").unwrap_or_else(|_| "8080".into());
    format!("https://127.0.0.1:{port}")
}

/// Mint a short-lived JWT for the caller.
///
/// `iss`/`aud` are REQUIRED spec claims in `auth::verify_token`; a token
/// without them is rejected outright, so omitting them would 401 every call.
///
/// Dual-emit: the token carries the user's CURRENT role plus
/// the legacy scopes derived from it — never the stored scopes verbatim, so
/// the tier scopes cannot outlive a demotion. Non-tier scopes (`ingest`) ride
/// along from the live-joined `user_scopes` because they are capabilities the
/// role neither grants nor revokes.
pub(crate) fn mint_caller_jwt(
    user: &str,
    role: crate::auth::Role,
    user_scopes: &[String],
    consumer: &str,
    // The session's label when the client presented a live
    // `Mcp-Session-Id`. `None` = the per-key label.
    session_label: Option<&str>,
) -> Option<String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    // Through secret_env, not std::env: compose delivers NOO_JWT_SECRET as a
    // FILE (NOO_JWT_SECRET_FILE), and a raw env read here minted nothing —
    // every /mcp/user call would have lost its session token.
    let secret = crate::config::secret_env::secret_opt("NOO_JWT_SECRET")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let mut scopes: Vec<String> =
        role.legacy_scopes().iter().map(|s| s.to_string()).collect();
    for s in user_scopes {
        if !matches!(s.as_str(), "read" | "write" | "admin") && !scopes.contains(s) {
            scopes.push(s.clone());
        }
    }
    // the design, option A: the door mints a CONNECTION, not the
    // bare account. `sub` is `<user>/<label from the key name>`, so two
    // clients holding two keys are two identities — two inboxes, two
    // presence records, replies that land in the window that asked —
    // while history, memory, usage and KB roles still resolve to `user`
    // through `auth::account_of`. One key per client is the whole
    // configuration; server-assigned MCP sessions would make it automatic
    // and are a followup.
    //
    // `act` is what makes this a delegated token: the auth layer re-checks
    // the account on every request (the kill switch reaches MCP sessions),
    // and the self-service key routes refuse it (a five-minute door token
    // may not mint itself a standing key — previously it could).
    //
    // A consumer name that cannot yield a label falls back to the bare
    // account, loudly, rather than refusing the door: the pre-A behaviour
    // is degraded, not broken.
    let sub = match session_label.map(str::to_string).or_else(|| crate::auth::connection_label(consumer)) {
        Some(label) => format!("{user}{}{label}", crate::auth::CONNECTION_SEP),
        None => {
            tracing::warn!(consumer, user, "mcp door: consumer name yields no connection label; minting the bare account");
            user.to_string()
        }
    };
    let claims = json!({
        "sub": sub,
        "act": { "sub": format!("key:{consumer}"), "iss_user": user },
        "role": role.as_str(),
        "scopes": scopes,
        "iss": crate::auth::JWT_ISSUER,
        "aud": crate::auth::JWT_AUDIENCE,
        "iat": now,
        "exp": now + CALLER_JWT_TTL_SECS,
        // Stamp the door into the credential. The
        // messaging surface used to take `harness` from the request body
        // and print it as fact, so any sender could label itself
        // `claude-code`. Minted here it is signed with NOO_JWT_SECRET and
        // names the key that actually authenticated, which is the only
        // thing about the calling software the gateway can prove.
        "harness": format!("mcp-external:{consumer}"),
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

// ─────────────────────────── request building ───────────────────────────

/// Wire key for a field, honouring `Field(alias=…)` from the Python side.
pub(crate) fn wire_key<'a>(spec: &'a ToolSpec, field: &'a str) -> &'a str {
    spec.aliases.get(field).map(String::as_str).unwrap_or(field)
}

/// Refuse an argument the tool's schema does not declare.
///
/// The request is built from the arguments the client sent, so an unknown
/// one used to be silently dropped: `noo_agent_thread(thread_id=…)` (the
/// parameter is `thread`) ran with NO thread filter and returned every
/// message. A dropped filter widens a read, so it is an error naming what
/// the tool does accept. A schema with no declared properties (the
/// no-argument tools) or with `additionalProperties: true` is not checked;
/// an alias wire key is accepted as well as the field name.
pub(crate) fn unknown_args(spec: &ToolSpec, args: &Map<String, Value>) -> Option<String> {
    let props = spec.input_schema.get("properties")?.as_object()?;
    if props.is_empty() || spec.input_schema.get("additionalProperties") == Some(&Value::Bool(true)) {
        return None;
    }
    let bad: Vec<&str> = args
        .keys()
        .map(String::as_str)
        .filter(|k| !props.contains_key(*k) && !spec.aliases.values().any(|v| v == k))
        .collect();
    if bad.is_empty() {
        return None;
    }
    let mut expected: Vec<&str> = props.keys().map(String::as_str).collect();
    expected.sort_unstable();
    Some(format!(
        "unknown argument{} {} for {}; expected one of: {}",
        if bad.len() > 1 { "s" } else { "" },
        bad.iter().map(|b| format!("'{b}'")).collect::<Vec<_>>().join(", "),
        spec.name,
        expected.join(", ")
    ))
}

/// Substitute `{placeholder}` segments in the path from the arguments, and
/// return the keys consumed so they are not ALSO sent as body/query params.
pub(crate) fn build_path(
    spec: &ToolSpec,
    args: &Map<String, Value>,
) -> Result<(String, Vec<String>), String> {
    let mut path = spec.path.clone();
    let mut consumed = Vec::new();
    for (field, value) in args {
        let key = wire_key(spec, field);
        let placeholder = format!("{{{key}}}");
        if path.contains(&placeholder) {
            let rendered = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            // A path segment is ONE segment. Without this, a templated
            // argument like `../../../api/config` walks out of the curated
            // manifest into routes it deliberately excludes — reqwest
            // normalises the `..` before the gateway ever sees it
            //
            if rendered.contains('/') || rendered.contains('\\') || rendered.contains("..") {
                return Err(format!(
                    "'{field}' must be a single path segment (no '/', '\\' or '..')"
                ));
            }
            path = path.replace(&placeholder, &percent_encode_segment(&rendered));
            consumed.push(field.clone());
        }
    }
    Ok((path, consumed))
}

/// Percent-encode everything outside the unreserved set, so a substituted
/// value cannot introduce a query string, a fragment or a new segment.
fn percent_encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Arguments minus the path-substituted ones.
///
/// Python skipped "fields with default values that weren't explicitly set".
/// Here that distinction is free and exact: an argument the client did not
/// send simply is not a key in this map, so absence already means unset. No
/// default tracking needed.
pub(crate) fn remaining_args(spec: &ToolSpec, args: &Map<String, Value>, consumed: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    for (field, value) in args {
        if consumed.contains(field) || value.is_null() {
            continue;
        }
        out.insert(wire_key(spec, field).to_string(), value.clone());
    }
    out
}

/// The body for a tool that declares `body_field`: that argument's object,
/// sent as the request body itself rather than nested under its own name.
///
/// `None` means the tool does not declare one, so the caller keeps the normal
/// every-argument body. An argument that is present but not an object is an
/// error rather than a silent fallback — falling back would send the wrapped
/// shape, which is the exact bug this exists to stop, and it would do it
/// invisibly.
pub(crate) fn body_payload(
    spec: &ToolSpec,
    args: &Map<String, Value>,
) -> Option<Result<Map<String, Value>, String>> {
    if spec.body_field.is_empty() {
        return None;
    }
    match args.get(&spec.body_field) {
        None | Some(Value::Null) => Some(Ok(Map::new())),
        Some(Value::Object(o)) => Some(Ok(o.clone())),
        Some(other) => Some(Err(format!(
            "{}: `{}` must be an object, got {}",
            spec.name,
            spec.body_field,
            match other {
                Value::Array(_) => "an array",
                Value::String(_) => "a string",
                Value::Number(_) => "a number",
                Value::Bool(_) => "a boolean",
                _ => "another type",
            }
        ))),
    }
}

/// Execute one tool: manifest → HTTP request against this gateway, carrying
/// the caller's own JWT.
async fn call_tool(
    caller: &Caller,
    session: Option<&str>,
    name: &str,
    args: &Map<String, Value>,
) -> Result<Value, String> {
    let spec = tool(name).ok_or_else(|| format!("unknown tool: {name}"))?;

    let token = mint_caller_jwt(&caller.user, caller.user_role, &caller.user_scopes, &caller.consumer, session).ok_or_else(|| {
        // Fail closed. Falling back to the cluster credential here would run
        // a named user's call with operator rights at exactly the moment the
        // safer path is unavailable.
        tracing::error!(user = %caller.user, "mcp_external_jwt_mint_failed");
        "cannot mint caller credential (NOO_JWT_SECRET unset?)".to_string()
    })?;

    execute_spec(spec, args, ("Authorization".into(), format!("Bearer {token}"))).await
}

/// Manifest → HTTP request against this gateway, with the given auth header.
///
/// Shared by both doors: the external door passes the caller's own JWT
/// (minted above), the local door (`mcp_local.rs`) passes the cluster-HMAC
/// bearer — WHO calls is each door's decision, HOW the call is made is not.
pub(crate) async fn execute_spec(
    spec: &ToolSpec,
    args: &Map<String, Value>,
    auth_header: (String, String),
) -> Result<Value, String> {
    if let Some(e) = unknown_args(spec, args) {
        return Err(e);
    }
    let (path, consumed) = build_path(spec, args)?;
    let rest = remaining_args(spec, args, &consumed);
    let rest = match body_payload(spec, args) {
        Some(Ok(payload)) => payload,
        Some(Err(e)) => return Err(e),
        None => rest,
    };

    // `.filter(non-empty)`: compose sets `NOO_SELF_URL=${NOO_SELF_URL:-}`,
    // which reaches the process as an EMPTY string, and env::var returns
    // Ok("") for that — so unwrap_or_else alone would build "/api/...".
    let base = std::env::var("NOO_SELF_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(self_url_default);
    let url = format!("{}{}", base.trim_end_matches('/'), path);

    // VERIFY the self-call, do not bypass it. The first cut disabled
    // validation for loopback on the reasoning that the connection never
    // leaves the host — true, but unnecessary here: the gateway's cert is
    // cluster-CA signed, the CA is already mounted at NOO_TLS_CA, and the
    // cert's SANs already include `IP Address:127.0.0.1`. Nothing had to be
    // shipped; it was all present.
    //
    // It matters because `danger_accept_invalid_certs` is not scoped to the
    // handshake it was reasoned about — it disables validation for every
    // request this client makes, and the base URL is operator-settable via
    // NOO_SELF_URL. A misconfiguration pointing off-host would then be
    // silently unauthenticated rather than a loud TLS error.
    let mut builder =
        crate::tls::client_builder().timeout(std::time::Duration::from_secs(spec.timeout_secs));
    if base.starts_with("https://") {
        // No cluster CA configured — a public cert (tailscale serve) or
        // plain dev. Leave the system roots in place rather than weakening
        // anything.
        if let Some(ca) = std::env::var("NOO_TLS_CA").ok().filter(|s| !s.is_empty()) {
            match std::fs::read(&ca) {
                Ok(pem) => match crate::tls::certificate_from_pem(&pem) {
                    Ok(cert) => builder = builder.tls_certs_merge([cert]),
                    Err(e) => return Err(format!("NOO_TLS_CA at {ca} is not valid PEM: {e}")),
                },
                Err(e) => return Err(format!("cannot read NOO_TLS_CA at {ca}: {e}")),
            }
        }
    }
    let client = builder.build().map_err(|e| format!("http client: {e}"))?;

    let req = match spec.method.as_str() {
        "GET" => client.get(&url).query(&rest),
        "DELETE" => client.delete(&url).query(&rest),
        "PUT" => client.put(&url).json(&rest),
        _ => client.post(&url).json(&rest),
    }
    .header(&auth_header.0, &auth_header.1);

    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        let msg = describe_send_error(&e, &base, spec.timeout_secs);
        tracing::warn!(
            tool = %spec.name,
            elapsed_ms = started.elapsed().as_millis() as u64,
            timeout_secs = spec.timeout_secs,
            timed_out = e.is_timeout(),
            connect = e.is_connect(),
            "mcp_self_call_failed: {msg}"
        );
        msg
    })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // Surface the status verbatim. A 403 here is meaningful and must not
        // be smoothed over: it means the user's scopes genuinely do not allow
        // this tool, which is the door working as intended.
        return Err(format!("gateway returned {}: {}", status.as_u16(), truncate(&body, 500)));
    }

    Ok(serde_json::from_str::<Value>(&body).unwrap_or(Value::String(body)))
}

/// Say what happened to a failed self-call. reqwest's Display for a send
/// error is just "error sending request for url (..)" for a timeout, a refused
/// connection and a TLS failure alike: the cause is in the `source()` chain.
/// A timeout in particular must not read as "unreachable": the route may well
/// still be running (or have finished) behind it.
pub(crate) fn describe_send_error(e: &reqwest::Error, base: &str, timeout_secs: u64) -> String {
    if e.is_timeout() {
        return format!(
            "the gateway did not answer within {timeout_secs}s (the tool may still be running; check its result)"
        );
    }
    let mut chain = String::new();
    let mut src = std::error::Error::source(e);
    while let Some(inner) = src {
        chain.push_str(": ");
        chain.push_str(&inner.to_string());
        src = inner.source();
    }
    if e.is_connect() {
        return format!("cannot reach the gateway at {base}: {e}{chain}");
    }
    format!("gateway request failed: {e}{chain}")
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    // Slice on a CHARACTER boundary: `&s[..n]` panics when byte n lands
    // mid-UTF-8, and this runs on gateway error bodies we do not control
    //
    let cut = s.char_indices().map(|(i, _)| i).take_while(|i| *i <= n).last().unwrap_or(0);
    format!("{}…", &s[..cut])
}

// ───────────────────────────── JSON-RPC ─────────────────────────────

/// The tool array for `tools/list`. Manifest order, which the generator
/// sorts by name — deterministic across requests, as the spec asks, so
/// clients can cache and prompt caches hit.
fn tools_list() -> Value {
    let tools: Vec<Value> = MANIFEST
        .tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    Value::Array(tools)
}

/// Transport-level failure (auth, disabled door) — an HTTP status, not a
/// JSON-RPC error object, since there may be no valid request to answer.
pub(crate) fn rpc_http_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct RpcRequest {
    #[serde(default)]
    pub(crate) id: Value,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Value,
}

/// POST /mcp/user — the USER MCP door (JSON-RPC over HTTP).
///
/// Speaks MCP — legacy (`initialize` / `ping`) and 2026-07-28 (per-request
/// `_meta`, `server/discover`) alike — for third-party agents. Gated twice: NOO_MCP_EXTERNAL_ENABLED must be on (a posture
/// gate), and the caller needs an `mcp`-scoped service key. The tool set
/// is the curated `external`-tagged manifest (mcp-tools.json) — a subset
/// of the operator door, with admin and self-modify tools excluded
/// by construction. Per-consumer rate limits apply.
async fn handle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !enabled() {
        return rpc_http_error(
            StatusCode::NOT_FOUND,
            "external MCP door is disabled (set NOO_MCP_EXTERNAL_ENABLED=1)",
        );
    }

    let caller = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let env: Envelope = match mcp_protocol::parse(mcp_protocol::Door::Tls, &headers, &body) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let req = &env.req;

    // a live session names this window. Resolved before
    // dispatch so an unknown id is a 404 on every method, which is what
    // tells a compliant client to re-initialize.
    let session = match crate::mcp_session::from_headers(&state.db, &headers, &caller.consumer).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    match req.method.as_str() {
        "initialize" => {
            // The client's own name for itself, display-only.
            let client_name = req.params.pointer("/clientInfo/name").and_then(Value::as_str);
            match crate::mcp_session::open(&state.db, &caller.user, &caller.consumer, client_name).await {
                Some((id, _)) => crate::mcp_session::attach(env.initialize(SERVER_NAME), &id),
                None => env.initialize(SERVER_NAME),
            }
        }

        // Notifications carry no id and expect no response body.
        m if m.starts_with("notifications/") => StatusCode::ACCEPTED.into_response(),

        "ping" => env.ping(),

        "server/discover" => env.discover(
            SERVER_NAME,
            "noomesh user door: tools run as the account this key is bound to.",
        ),

        "tools/list" => {
            let mut tools = tools_list();
            if let Some(arr) = tools.as_array_mut() {
                // The task tools (i83 E1d): in process, owner-scoped to
                // this caller — see `mcp_user_tasks`.
                arr.extend(crate::mcp_user_tasks::tool_list());
                for t in crate::mcp_bridge::catalog_for(&state, Some(&caller.user)).await {
                    arr.push(t.mcp_tool());
                }
            }
            env.tools_list(tools, SERVER_NAME)
        }

        "tools/call" => {
            let name = req.params.get("name").and_then(Value::as_str).unwrap_or_default();
            let empty = Map::new();
            let args = req
                .params
                .get("arguments")
                .and_then(Value::as_object)
                .unwrap_or(&empty);

            // External MCP tool: the bridge checks the
            // caller's audience and runs it on the hosting node.
            if name.starts_with(crate::mcp_bridge::PREFIX) {
                let ids = crate::mcp_bridge::server_ids(&state).await;
                if let Some((server, tool_name)) = crate::mcp_bridge::split_name(name, &ids) {
                    let argv = Value::Object(args.clone());
                    return match crate::mcp_bridge::call(&state, Some(&caller.user), &server, &tool_name, &argv).await {
                        Ok(text) => env.result(json!({ "content": [{"type": "text", "text": text}], "isError": false }), SERVER_NAME),
                        Err(e) => env.result(json!({ "content": [{"type": "text", "text": e}], "isError": true }), SERVER_NAME),
                    };
                }
            }
            let task_tool = crate::mcp_user_tasks::is_tool(name);
            if !task_tool && tool(name).is_none() {
                return rpc_error(req.id.clone(), -32602, &format!("unknown tool: {name}"));
            }

            tracing::info!(
                consumer = %caller.consumer, user = %caller.user, tool = %name, era = env.era.as_str(),
                "mcp_external_tool_call"
            );
            // A durable record of who ran what through this door: the
            // tracing line lives as long as the log buffer, and "which key
            // called which tool" is exactly what an operator needs after
            // handing a key to someone.
            crate::routes::core::audit_event(
                &state.db,
                "mcp_tool_call",
                "info",
                &format!("{}:{}", caller.consumer, caller.user),
                name,
                "ok",
                json!({ "door": "user", "consumer": caller.consumer, "user": caller.user, "tool": name, "era": env.era.as_str() }),
            )
            .await;

            let outcome = if task_tool {
                crate::mcp_user_tasks::call(&state, &caller.user, name, args).await
            } else {
                call_tool(&caller, session.as_deref(), name, args).await
            };
            match outcome {
                // Content is the raw gateway JSON, serialised, with no prose
                // formatting layered on top.
                Ok(v) => env.result(
                    json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
                        }],
                        "isError": false,
                    }),
                    SERVER_NAME,
                ),
                Err(e) => env.result(
                    json!({
                        "content": [{"type": "text", "text": e}],
                        "isError": true,
                    }),
                    SERVER_NAME,
                ),
            }
        }

        _ => env.method_not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn failed_send(url: &str, timeout_ms: u64) -> reqwest::Error {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .unwrap()
            .post(url)
            .json(&json!({}))
            .send()
            .await
            .expect_err("the call must fail")
    }

    #[tokio::test]
    async fn a_gateway_that_never_answers_is_a_timeout_not_unreachable() {
        // Accepts the connection and holds it open: the shape of a route that
        // runs past the door's timeout.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let _held = tokio::spawn(async move {
            let mut keep = Vec::new();
            while let Ok((sock, _)) = l.accept().await {
                keep.push(sock);
            }
        });
        let e = failed_send(&format!("http://{addr}/api/v1/graph/navigate"), 200).await;
        let msg = describe_send_error(&e, &format!("http://{addr}"), 30);
        assert_eq!(
            msg,
            "the gateway did not answer within 30s (the tool may still be running; check its result)"
        );
        assert!(!msg.contains("unreachable"));
    }

    #[tokio::test]
    async fn a_closed_port_names_the_base_and_the_cause() {
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        }; // dropped: nothing listens
        let base = format!("http://{addr}");
        let e = failed_send(&format!("{base}/x"), 2000).await;
        let msg = describe_send_error(&e, &base, 30);
        assert!(msg.starts_with(&format!("cannot reach the gateway at {base}: ")), "{msg}");
        // reqwest's own Display hides the cause; the chain must carry it.
        assert!(msg.to_lowercase().contains("refused"), "cause missing from: {msg}");
    }

    #[test]
    fn manifest_parses_and_is_the_expected_version() {
        assert_eq!(MANIFEST.version, EXPECTED_MANIFEST_VERSION);
        assert!(!MANIFEST.tools.is_empty(), "manifest served no tools");
    }

    #[test]
    fn every_tool_has_a_schema_and_a_path() {
        for t in &MANIFEST.tools {
            assert!(!t.name.is_empty());
            assert!(t.path.starts_with('/'), "{}: path must be absolute", t.name);
            assert!(
                t.input_schema.get("type").is_some(),
                "{}: input_schema is not a JSON Schema object",
                t.name
            );
            assert!(t.timeout_secs > 0, "{}: zero timeout", t.name);
        }
    }

    #[test]
    fn tools_list_exposes_every_manifest_tool() {
        let listed = tools_list();
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), MANIFEST.tools.len());
        // camelCase per the MCP schema — `input_schema` would be silently
        // ignored by clients, leaving every tool apparently argument-less.
        assert!(listed[0].get("inputSchema").is_some());
    }

    #[test]
    fn path_templating_substitutes_and_consumes() {
        let spec = ToolSpec {
            name: "t".into(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "GET".into(),
            path: "/api/v1/graph/entities/{entity_id}".into(),
            timeout_secs: 30,
            aliases: HashMap::new(),
            body_field: String::new(),
        };
        let mut args = Map::new();
        args.insert("entity_id".into(), json!("abc-123"));
        args.insert("depth".into(), json!(2));

        let (path, consumed) = build_path(&spec, &args).unwrap();
        assert_eq!(path, "/api/v1/graph/entities/abc-123");
        assert_eq!(consumed, vec!["entity_id".to_string()]);

        // The templated field must NOT be resent as a query param.
        let rest = remaining_args(&spec, &args, &consumed);
        assert!(!rest.contains_key("entity_id"));
        assert_eq!(rest.get("depth"), Some(&json!(2)));
    }

    #[test]
    fn string_path_params_are_not_json_quoted() {
        // `Value::to_string()` on a string yields `"abc"` WITH quotes, which
        // would build /entities/%22abc%22 and 404. Guard the unwrap.
        let spec = ToolSpec {
            name: "t".into(), description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "GET".into(), path: "/x/{id}".into(),
            timeout_secs: 30, aliases: HashMap::new(), body_field: String::new(),
        };
        let mut args = Map::new();
        args.insert("id".into(), json!("abc"));
        assert_eq!(build_path(&spec, &args).unwrap().0, "/x/abc");
    }

    #[test]
    fn path_arguments_cannot_escape_their_segment() {
        let spec = ToolSpec {
            name: "t".into(), description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "GET".into(), path: "/api/v1/graph/entities/{id}".into(),
            timeout_secs: 30, aliases: HashMap::new(), body_field: String::new(),
        };
        for escape in ["../../../api/config", "a/b", "..", "x\\y"] {
            let mut args = Map::new();
            args.insert("id".into(), json!(escape));
            assert!(build_path(&spec, &args).is_err(), "{escape} was accepted");
        }
        // Everything else is percent-encoded, so a value cannot start a
        // query string or a fragment either.
        let mut args = Map::new();
        args.insert("id".into(), json!("a b?c#d"));
        assert_eq!(build_path(&spec, &args).unwrap().0, "/api/v1/graph/entities/a%20b%3Fc%23d");
    }

    #[test]
    fn truncate_never_splits_a_character() {
        // 3-byte characters straddling the cut: this used to panic.
        let s = "日本語のテキスト";
        for n in 0..s.len() {
            let out = truncate(s, n);
            assert!(out.len() <= s.len() + 3);
        }
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn aliases_map_field_names_to_wire_keys() {
        let mut aliases = HashMap::new();
        aliases.insert("name_field".to_string(), "name".to_string());
        let spec = ToolSpec {
            name: "t".into(), description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "POST".into(), path: "/x".into(),
            timeout_secs: 30, aliases, body_field: String::new(),
        };
        let mut args = Map::new();
        args.insert("name_field".into(), json!("v"));
        let rest = remaining_args(&spec, &args, &[]);
        assert!(rest.contains_key("name"), "alias not applied: {rest:?}");
        assert!(!rest.contains_key("name_field"));
    }

    #[test]
    fn nulls_are_dropped_not_sent() {
        let spec = ToolSpec {
            name: "t".into(), description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "POST".into(), path: "/x".into(),
            timeout_secs: 30, aliases: HashMap::new(), body_field: String::new(),
        };
        let mut args = Map::new();
        args.insert("set".into(), json!("v"));
        args.insert("unset".into(), Value::Null);
        let rest = remaining_args(&spec, &args, &[]);
        assert!(rest.contains_key("set"));
        assert!(!rest.contains_key("unset"), "null leaked into the request");
    }

    #[test]
    fn enabled_requires_explicit_optin() {
        let _guard = env_guard();
        // The door must not come up just because a token happens to be set —
        // that conflation is what this replaces.
        std::env::remove_var(ENABLED_ENV);
        assert!(!enabled());
        std::env::set_var(ENABLED_ENV, "1");
        assert!(enabled());
        std::env::set_var(ENABLED_ENV, "0");
        assert!(!enabled());
        std::env::remove_var(ENABLED_ENV);
    }

    #[test]
    fn self_url_is_https_whatever_the_env_says() {
        let _guard = env_guard();
        // The listener is TLS-only, so the self-URL does not consult
        // NOO_TLS_CERT any more: set, empty or absent, it is https.
        std::env::set_var("NOO_TLS_CERT", "/pki/gateway.crt");
        assert_eq!(self_url_default(), "https://127.0.0.1:8080");
        std::env::set_var("NOO_TLS_CERT", "");
        assert_eq!(self_url_default(), "https://127.0.0.1:8080");
        std::env::remove_var("NOO_TLS_CERT");
        assert_eq!(self_url_default(), "https://127.0.0.1:8080");
    }

    #[test]
    fn self_url_honours_port() {
        let _guard = env_guard();
        std::env::remove_var("NOO_TLS_CERT");
        std::env::set_var("NOO_PORT", "9090");
        assert_eq!(self_url_default(), "https://127.0.0.1:9090");
        std::env::remove_var("NOO_PORT");
    }

    /// Serialises EVERY test in this module that mutates process env.
    ///
    /// Rust runs a test binary's tests on parallel threads of ONE process, so
    /// `set_var`/`remove_var` are shared global state. Five tests here mutate
    /// four variables — `NOO_JWT_SECRET`, `NOO_TLS_CERT`, `NOO_PORT` and the
    /// enable flag — and several assert OPPOSITE things about the same one:
    /// that a token mints and that it does not; that the URL is https and
    /// that it is http. Whichever pair interleaves loses.
    ///
    /// This is scoped to the module rather than to one pair on purpose. The
    /// first cut guarded only the JWT pair, four consecutive runs passed, and
    /// then `self_url_follows_the_tls_setting` failed instead — a different
    /// pair, the same bug. Guarding the variable that happened to fail first
    /// would just have moved it.
    ///
    /// A lock rather than `--test-threads=1`: the cost stays on the tests that
    /// need it instead of the whole 462-test suite.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the env lock. Poison is deliberately ignored — the lock guards an
    /// environment variable, not data, and a panicking sibling must not
    /// cascade into a second failure that buries the first.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The self-issued key is `self:<user>` — a colon a name segment forbids
    /// — so the label is derived, not copied. If this mapping refused, every
    /// self-issued key would have gone offline the day option A shipped.
    #[test]
    fn a_consumer_name_becomes_a_connection_label() {
        use crate::auth::connection_label;
        assert_eq!(connection_label("acme").as_deref(), Some("acme"));
        assert_eq!(connection_label("self:owner").as_deref(), Some("self-owner"));
        assert_eq!(connection_label("owner-claude-s1").as_deref(), Some("owner-claude-s1"));
        // Runs collapse, ends trim, so the label is one tidy segment.
        assert_eq!(connection_label("::a  b::").as_deref(), Some("a-b"));
        // Nothing usable → None, so the door falls back to the bare
        // account (loudly) rather than minting a garbage identity.
        assert_eq!(connection_label(":::"), None);
        assert_eq!(connection_label(""), None);
        // Whatever comes out is a valid agent id under the account.
        let lbl = connection_label("self:owner").unwrap();
        assert!(crate::agent_messages::is_valid_id(&format!("owner/{lbl}")));
    }

    /// a live session names the window, and the per-key
    /// label is the fallback for a client that sent no session id.
    #[test]
    fn a_session_label_names_the_window_and_per_key_is_the_fallback() {
        let _guard = env_guard();
        use crate::auth::Role;
        std::env::set_var("NOO_JWT_SECRET", "test-secret-mcp-door");
        let with = mint_caller_jwt("owner", Role::User, &[], "self:owner", Some("self-owner-k3f9qz")).unwrap();
        let c = crate::auth::verify_token(&with, "test-secret-mcp-door").unwrap();
        assert_eq!(c.sub, "owner/self-owner-k3f9qz");
        assert_eq!(crate::auth::account_of(&c.sub), "owner", "permissions scope to the person");
        assert_eq!(c.act.as_ref().unwrap().sub, "key:self:owner", "provenance names the key too");

        let without = mint_caller_jwt("owner", Role::User, &[], "self:owner", None).unwrap();
        let c = crate::auth::verify_token(&without, "test-secret-mcp-door").unwrap();
        assert_eq!(c.sub, "owner/self-owner", "no session → per-key label, not the bare account");
    }

    /// Both doors must open a session on `initialize` and consult the
    /// header BEFORE dispatch, so an unknown id is a 404 on every method.
    /// Pinned as source because the handlers need a live AppState; the
    /// registry itself is tested directly in `mcp_session`.
    #[test]
    fn both_doors_open_and_resolve_sessions() {
        for (name, src) in [("user door", include_str!("mcp_external.rs")), ("operator door", include_str!("mcp_local.rs"))] {
            let handler = src.split("let req = &env.req;").nth(1).unwrap_or_else(|| panic!("{name}: no handler body"));
            let head = &handler[..handler.find("\"tools/call\"").unwrap_or_else(|| panic!("{name}: no tools/call arm"))];
            assert!(head.contains("mcp_session::from_headers("), "{name} must resolve the session before dispatch");
            assert!(head.contains("mcp_session::open("), "{name} must open a session on initialize");
            assert!(head.contains("mcp_session::attach("), "{name} must return the id on the initialize response");
        }
    }

    #[test]
    fn jwt_carries_issuer_audience_subject_and_role() {
        let _guard = env_guard();
        use crate::auth::Role;
        std::env::set_var("NOO_JWT_SECRET", "test-secret-mcp-door");
        let token =
            mint_caller_jwt("alice", Role::User, &["read".to_string()], "acme", None).expect("mint");
        let claims = crate::auth::verify_token(&token, "test-secret-mcp-door")
            .expect("gateway must accept its own minted token");
        // the door mints a CONNECTION under the
        // account, labelled by the key that authenticated. The account is
        // recoverable by prefix — that is what keeps history and KB roles
        // whole — and `act` records the delegation so the auth layer
        // re-checks the account per request and the self-service key
        // routes refuse it.
        assert_eq!(claims.sub, "alice/acme");
        assert_eq!(crate::auth::account_of(&claims.sub), "alice");
        let act = claims.act.as_ref().expect("a door token is a delegated token");
        assert_eq!(act.sub, "key:acme");
        assert_eq!(act.iss_user.as_deref(), Some("alice"));
        assert_eq!(claims.role, "user");
        assert_eq!(claims.scopes, vec!["read".to_string()]);
        assert_eq!(claims.resolved_role(), Role::User);
        // The door stamps the harness into the credential so the messaging
        // surface can attribute the call without believing the body
        //
        assert_eq!(claims.harness.as_deref(), Some("mcp-external:acme"));
        std::env::remove_var("NOO_JWT_SECRET");
    }

    #[test]
    fn jwt_scopes_derive_from_the_current_role_not_stored_scopes() {
        let _guard = env_guard();
        use crate::auth::Role;
        std::env::set_var("NOO_JWT_SECRET", "test-secret-mcp-door");
        // Demoted account: stored scopes still say operator, role says User.
        // The minted token must carry the ROLE's scopes (+ non-tier extras),
        // or the demotion silently doesn't apply on this surface (#408).
        let stale = vec!["read".to_string(), "write".to_string(), "ingest".to_string()];
        let token = mint_caller_jwt("alice", Role::User, &stale, "acme", None).expect("mint");
        let claims = crate::auth::verify_token(&token, "test-secret-mcp-door").unwrap();
        assert_eq!(claims.scopes, vec!["read".to_string(), "ingest".to_string()]);
        assert_eq!(claims.resolved_role(), Role::User);
        std::env::remove_var("NOO_JWT_SECRET");
    }

    #[test]
    fn jwt_carries_the_graph_scope_and_a_demotion_still_drops_the_tier() {
        let _guard = env_guard();
        use crate::auth::Role;
        std::env::set_var("NOO_JWT_SECRET", "test-secret-mcp-door");
        let stored = vec!["read".to_string(), "graph".to_string()];
        let token = mint_caller_jwt("alice", Role::User, &stored, "acme", None).expect("mint");
        let claims = crate::auth::verify_token(&token, "test-secret-mcp-door").unwrap();
        assert_eq!(claims.scopes, vec!["read".to_string(), "graph".to_string()]);
        assert_eq!(claims.resolved_role(), Role::User);
        // The minted credential is what the tier gate sees: it opens the six.
        assert!(crate::auth::scope_allows(&claims, &axum::http::Method::POST, "/api/v1/graph/navigate"));
        // A plain read account's token does not carry it.
        let plain = mint_caller_jwt("bob", Role::User, &["read".to_string()], "acme", None).expect("mint");
        let pc = crate::auth::verify_token(&plain, "test-secret-mcp-door").unwrap();
        assert!(!pc.scopes.iter().any(|s| s == "graph"));
        assert!(!crate::auth::scope_allows(&pc, &axum::http::Method::POST, "/api/v1/graph/navigate"));
        std::env::remove_var("NOO_JWT_SECRET");
    }

    #[test]
    fn no_jwt_secret_means_no_token_not_a_fallback() {
        let _guard = env_guard();
        std::env::remove_var("NOO_JWT_SECRET");
        assert!(
            mint_caller_jwt("alice", crate::auth::Role::User, &["read".to_string()], "acme", None).is_none(),
            "must fail closed rather than dispatch as the operator"
        );
    }
}

#[cfg(test)]
mod body_field_tests {
    use super::{body_payload, remaining_args, unknown_args, ToolSpec};
    use serde_json::{json, Map, Value};
    use std::collections::HashMap;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn spec_with(body_field: &str) -> ToolSpec {
        ToolSpec {
            name: "t".into(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
            method: "PUT".into(),
            path: "/api/config/{section}".into(),
            timeout_secs: 30,
            aliases: HashMap::new(),
            body_field: body_field.into(),
        }
    }

    /// `PUT /api/config/{section}` deep-merges the body INTO the section, so
    /// the payload must arrive unwrapped. Wrapping it wrote a key literally
    /// called `updates` into noomesh.yaml and left the real keys unset.
    #[test]
    fn a_declared_body_field_is_sent_unwrapped() {
        let spec = spec_with("updates");
        let a = args(json!({"section": "compose_env", "updates": {"NOO_X": "1"}}));
        let got = body_payload(&spec, &a).expect("declared").expect("object");
        assert_eq!(got.get("NOO_X").and_then(Value::as_str), Some("1"));
        assert!(!got.contains_key("updates"), "must not wrap: {got:?}");
        assert!(!got.contains_key("section"), "path arg must not leak in");
    }

    /// `thread_id` for a tool whose parameter is `thread` used to be dropped,
    /// running the read unfiltered. It must be refused, naming the real keys.
    #[test]
    fn an_undeclared_argument_is_refused_not_dropped() {
        let mut spec = spec_with("");
        spec.name = "noo_agent_thread".into();
        spec.input_schema = json!({"type": "object", "properties": {"thread": {}, "limit": {}}});
        let e = unknown_args(&spec, &args(json!({"thread_id": "thr_x"}))).expect("refused");
        assert!(e.contains("unknown argument 'thread_id' for noo_agent_thread"), "{e}");
        assert!(e.contains("expected one of: limit, thread"), "{e}");
        assert!(unknown_args(&spec, &args(json!({"thread": "thr_x", "limit": 5}))).is_none());
        // no declared properties (no-argument tools) is not checked
        spec.input_schema = json!({"type": "object", "properties": {}});
        assert!(unknown_args(&spec, &args(json!({"anything": 1}))).is_none());
    }

    /// The opt-in must not change every other tool.
    #[test]
    fn a_tool_without_body_field_is_unchanged() {
        let spec = spec_with("");
        let a = args(json!({"action": "x", "payload": {"k": "v"}}));
        assert!(body_payload(&spec, &a).is_none());
        let rest = remaining_args(&spec, &a, &[]);
        assert!(rest.contains_key("payload"), "named fields stay named");
    }

    /// A non-object payload must fail loudly. Falling back would send the
    /// wrapped shape — the exact bug — and do it invisibly.
    #[test]
    fn a_non_object_payload_is_an_error() {
        let spec = spec_with("updates");
        let a = args(json!({"section": "compose_env", "updates": "NOO_X=1"}));
        let err = body_payload(&spec, &a).unwrap().unwrap_err();
        assert!(err.contains("must be an object"), "{err}");
        assert!(err.contains("a string"), "{err}");
    }

    #[test]
    fn an_absent_payload_is_an_empty_body() {
        let spec = spec_with("updates");
        let a = args(json!({"section": "compose_env"}));
        assert!(body_payload(&spec, &a).unwrap().unwrap().is_empty());
    }

    /// The shape has to actually travel. `noo_config_set` is a LOCAL-door
    /// tool, so it lives in the full-registry manifest, which is the one the
    /// operator door serves — and the door where this bug was observed.
    #[test]
    fn the_local_manifest_carries_the_shape_for_config_set() {
        let raw = include_str!("../mcp-tools-local.json");
        let m: super::Manifest = serde_json::from_str(raw).unwrap();
        let t = m
            .tools
            .iter()
            .find(|t| t.name == "noo_config_set")
            .expect("noo_config_set in the local manifest");
        assert_eq!(t.body_field, "updates");
        let propose = m.tools.iter().find(|t| t.name == "noo_user_propose");
        if let Some(p) = propose {
            assert_eq!(p.body_field, "", "a tool that nests on purpose must not declare one");
        }
    }
}

#[cfg(test)]
mod admit_order_tests {
    use super::admit;
    use crate::service_keys::Consumer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn consumer(scopes: &[&str], user: Option<&str>) -> Consumer {
        Consumer {
            name: "k".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            rpm_limit: Some(10),
            user: user.map(str::to_string),
            user_scopes: vec![],
            user_role: user.map(|_| crate::auth::Role::User),
        }
    }

    async fn charges(c: Consumer) -> (bool, usize) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let r = admit(c, |_, _| async move {
            n2.fetch_add(1, Ordering::SeqCst);
            None
        })
        .await;
        (r.is_ok(), n.load(Ordering::SeqCst))
    }

    /// A key without the `mcp` scope is refused WITHOUT burning the bound
    /// account's quota.
    #[tokio::test]
    async fn wrong_scope_key_is_refused_without_charging_quota() {
        let (ok, charged) = charges(consumer(&["inference"], Some("alice"))).await;
        assert!(!ok);
        assert_eq!(charged, 0, "a refused request must not consume quota");
    }

    #[tokio::test]
    async fn unbound_key_is_refused_without_charging_quota() {
        let (ok, charged) = charges(consumer(&["mcp"], None)).await;
        assert!(!ok);
        assert_eq!(charged, 0);
    }

    #[tokio::test]
    async fn served_request_is_charged_exactly_once() {
        let (ok, charged) = charges(consumer(&["mcp"], Some("alice"))).await;
        assert!(ok);
        assert_eq!(charged, 1);
    }

    #[tokio::test]
    async fn over_quota_is_refused() {
        let r = admit(consumer(&["mcp"], Some("alice")), |_, _| async { Some(7) }).await;
        assert!(r.is_err());
    }
}
