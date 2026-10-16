// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The operator MCP door — `/mcp/operator` on the gateway's HTTPS port.
//!
//! Until stack-v0.2.40 this module also bound its own plain-HTTP listener
//! (`NOO_MCP_HOST:NOO_MCP_PORT`, published on the controller's loopback)
//! where the token was OPTIONAL because "the binding is the boundary". It
//! was not one: every process on the controller (the CI runners included)
//! and every container on the cluster network could reach it and hold the
//! full operator catalog with no credential and no audit row —.
//! That listener is gone; this door has one path, one listener, and a
//! credential on every request.
//!
//! Differences from the user door (`mcp_external.rs`), and nothing else:
//!
//! - **Catalog**: the FULL ToolDef registry (`mcp-tools-local.json`), not
//!   the curated user subset. Same generated shape, same drift gate.
//! - **Auth**: a named service key carrying the `mcp:operator` scope and
//!   bound to an account that holds the admin role NOW — see
//!   [`OPERATOR_SCOPE`] — so several people can hold the operator toolset
//!   without sharing one string, and every call is attributed. Nothing
//!   else: the shared `NOO_MCP_TOKEN` bearer was retired on 2026-09-30
//!   (24 h of live logs: every operator-door call already carried a
//!   per-admin key, none the token). A gateway that still finds it
//!   configured says so once at boot ([`warn_retired_token`]) and never
//!   compares a bearer against it.
//! - **Identity**: each tool call runs as the admin who holds the key — a
//!   five-minute JWT minted for that account, so the gateway scopes, audits
//!   and charges the call to them. There is no cluster-HMAC identity: the
//!   caller-less `mcp-local` path that signed with the controller secret
//!   went with the loopback listener.
//!
//! Dispatch, path templating and the JSON-RPC surface are shared with the
//! external door — WHO calls is each door's decision, HOW is not.

use std::sync::{Arc, LazyLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::{json, Map, Value};

use crate::mcp_external::{
    execute_spec, rpc_error, rpc_http_error, Manifest, ToolSpec, EXPECTED_MANIFEST_VERSION,
};
use crate::mcp_protocol::{self, Envelope};

/// Server name reported in `serverInfo`. Unchanged from the Python hub.
const SERVER_NAME: &str = "mesh-hub";

static MANIFEST: LazyLock<Manifest> = LazyLock::new(|| {
    let raw = include_str!("../mcp-tools-local.json");
    let mut m: Manifest = serde_json::from_str(raw).expect(
        "mcp-tools-local.json is malformed — regenerate with scripts/build-mcp-manifest.py",
    );
    assert_eq!(
        m.version, EXPECTED_MANIFEST_VERSION,
        "mcp-tools-local.json version {} != expected {} — regenerate it",
        m.version, EXPECTED_MANIFEST_VERSION
    );
    merge_extra_manifest(&mut m);
    m
});

/// Add-on tool delivery: an add-on overlay may mount a
/// manifest FRAGMENT and name it in NOO_MCP_EXTRA_MANIFEST (the evolve
/// overlay ships mcp-tools-evolve.json this way — built by that repo's
/// scripts/build-mcp-fragment.py). Merged into the LOCAL catalog only; the
/// external door's surface is a security decision and stays compiled-in.
///
/// Deliberately tolerant where the compiled-in manifest asserts: a broken
/// or version-skewed fragment must degrade to "pro tools not advertised"
/// (the addon contract's explained-503 routes still work), never take the
/// gateway down. Duplicate names keep the compiled-in tool and warn.
fn merge_extra_manifest(m: &mut Manifest) {
    let Some(path) = std::env::var("NOO_MCP_EXTRA_MANIFEST")
        .ok()
        .filter(|p| !p.trim().is_empty())
    else {
        return;
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%path, error = %e, "mcp_extra_manifest_unreadable");
            return;
        }
    };
    let extra: Manifest = match serde_json::from_str(&raw) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(%path, error = %e, "mcp_extra_manifest_malformed");
            return;
        }
    };
    if extra.version != EXPECTED_MANIFEST_VERSION {
        tracing::warn!(
            %path,
            fragment_version = extra.version,
            expected = EXPECTED_MANIFEST_VERSION,
            "mcp_extra_manifest_version_skew — not merged; regenerate the fragment"
        );
        return;
    }
    let mut added = 0usize;
    for t in extra.tools {
        if m.tools.iter().any(|have| have.name == t.name) {
            tracing::warn!(tool = %t.name, "mcp_extra_manifest_duplicate_tool_skipped");
            continue;
        }
        m.tools.push(t);
        added += 1;
    }
    tracing::info!(%path, added, "mcp_extra_manifest_merged");
}

fn tool(name: &str) -> Option<&'static ToolSpec> {
    MANIFEST.tools.iter().find(|t| t.name == name)
}

/// The operator door on the gateway listener: reachable over **HTTPS** with
/// the certificate the gateway already has — no second port to publish, no
/// plaintext hop, nothing to bind. A credential is ALWAYS required: this
/// port is reachable by anything that can reach the gateway, so nothing
/// but the credential is a boundary. ONE kind opens it — a per-person
/// `mcp:operator` service key bound to an admin (`authenticate_over_tls`).
///
/// `/mcp/operator` is the name that says what this door IS: every caller
/// acts with the OPERATOR identity and gets the full tool catalog. The
/// plain `/mcp` name lived only on the removed loopback listener.
pub fn shared_router() -> Router<Arc<crate::state::AppState>> {
    Router::new()
        .route(
            "/mcp/operator",
            post(handle_over_tls)
                .get(mcp_protocol::method_not_allowed)
                .delete(mcp_protocol::method_not_allowed),
        )
        .layer(axum::extract::DefaultBodyLimit::max(crate::mcp_external::MAX_RPC_BODY))
}

/// Every name under which the retired shared token could still reach
/// this process: the plain variable, the `NOO_SECRET_` indirection, the
/// file path compose delivered from #559 until its retirement, and the
/// rotation grace value. None is READ for its value — only for presence.
pub(crate) const RETIRED_TOKEN_VARS: &[&str] = &[
    "NOO_MCP_TOKEN",
    "NOO_SECRET_NOO_MCP_TOKEN",
    "NOO_MCP_TOKEN_FILE",
    "NOO_MCP_TOKEN_PREVIOUS",
];

/// The retired names that are set (non-empty) under `get`. Pure over the
/// lookup so the boot warning is testable without touching the process
/// environment.
pub(crate) fn retired_token_vars_set(get: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    RETIRED_TOKEN_VARS
        .iter()
        .copied()
        .filter(|k| get(k).is_some_and(|v| !v.trim().is_empty()))
        .collect()
}

/// The one boot-time line for an install whose store (or compose file)
/// still carries the shared operator token. It is IGNORED — the door
/// compares no bearer against it — and this says so, once, naming what to
/// remove and what to use instead. Called from `main` before the listener
/// binds.
pub fn warn_retired_token() {
    let set = retired_token_vars_set(|k| std::env::var(k).ok());
    if set.is_empty() {
        return;
    }
    tracing::warn!(
        vars = %set.join(","),
        "NOO_MCP_TOKEN is retired and ignored — remove it from the store \
         (`noo security secrets tidy` drops it from secrets/env.sops) and give each \
         /mcp/operator client its own key: {MINT_HINT}"
    );
}

/// The command that mints the only credential this door accepts. Named in
/// every refusal so a client still configured with the retired shared
/// token is told what replaces it, not just that it failed.
pub const MINT_HINT: &str =
    "noo security service-key issue <you>-mcp --scopes mcp:operator --user <admin>";

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

/// Service-key scope that opens the operator door. Deliberately NOT the
/// user door's `mcp`: that scope is self-issuable and inherits the bound
/// account's tier, whereas a key with this scope acts as THE OPERATOR for
/// every tool in the full catalog. So issuing is operator-only
/// (`routes::users::service_key_issue` refuses it from the self-service
/// path), the key must be bound to a user, and that user must currently
/// hold the `admin` role — checked live on every call, like the user door,
/// so demoting or disabling the account closes the door within the key
/// cache TTL. What that buys over the retired shared token: per-person
/// revoke, a per-key rate cap, and an audit row naming who ran what.
pub const OPERATOR_SCOPE: &str = "mcp:operator";

/// Who opened the HTTPS operator door: the consumer (key) name and the
/// admin account behind it. There is no anonymous caller any more — the
/// shared-token variant went with the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorCaller {
    pub(crate) consumer: String,
    pub(crate) user: String,
}

impl OperatorCaller {
    /// Audit/log label: `<consumer>:<admin>`.
    fn actor(&self) -> String {
        format!("{}:{}", self.consumer, self.user)
    }
}

/// The pure decision for a resolved key: scope + bound admin, nothing else.
/// Split out so it is testable without a database.
pub(crate) fn operator_key_check(
    consumer: &crate::service_keys::Consumer,
) -> Result<OperatorCaller, (StatusCode, String)> {
    if !consumer.has_scope(OPERATOR_SCOPE) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("key lacks the '{OPERATOR_SCOPE}' scope — this is the operator door; a plain 'mcp' key belongs on /mcp/user"),
        ));
    }
    let Some(user) = consumer.user.clone() else {
        return Err((
            StatusCode::FORBIDDEN,
            "this key is not bound to a user; an operator key must name the admin it acts for".to_string(),
        ));
    };
    if consumer.user_role != Some(crate::auth::Role::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("account '{user}' no longer holds the admin role, so its operator key is refused"),
        ));
    }
    Ok(OperatorCaller { consumer: consumer.name.clone(), user })
}

/// HTTPS operator door auth: the bearer must resolve to an active service
/// key that passes [`operator_key_check`]. Anything else is 401/403 with the
/// mint command — in particular a client still presenting the retired
/// shared `NOO_MCP_TOKEN` gets "not an active service key", because that is
/// exactly what it is, even when the value is still configured here.
///
/// Takes the pool and cache rather than `AppState` so the refusal is
/// testable with a lazy pool and no server.
async fn authenticate_over_tls(
    db: &sqlx::PgPool,
    redis: Option<&crate::cache::RedisCache>,
    headers: &HeaderMap,
) -> Result<OperatorCaller, Response> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            rpc_http_error(
                StatusCode::UNAUTHORIZED,
                &format!(
                    "missing bearer: this door takes an '{OPERATOR_SCOPE}' service key bound to an admin — mint one with `{MINT_HINT}`"
                ),
            )
        })?;

    let Some(consumer) = crate::service_keys::resolve(db, presented).await else {
        return Err(rpc_http_error(
            StatusCode::UNAUTHORIZED,
            &format!(
                "invalid bearer: not an active service key. The shared NOO_MCP_TOKEN is retired; \
                 this door takes only an '{OPERATOR_SCOPE}' key bound to an admin — mint one with `{MINT_HINT}`"
            ),
        ));
    };
    // Metered per consumer even without a cap of its own (see
    // `service_keys::door_rpm`); in-process when Redis is absent or erroring.
    let limit = crate::service_keys::door_rpm(&consumer);
    let over = match redis {
        Some(redis) => match redis.check_consumer_quota(&consumer.name, limit).await {
            Ok(crate::cache::RateResult::Limited { retry_after }) => Some(retry_after),
            Ok(_) => None,
            Err(_) => crate::service_keys::local_quota_exceeded(&consumer.name, limit),
        },
        None => crate::service_keys::local_quota_exceeded(&consumer.name, limit),
    };
    if let Some(retry_after) = over {
        return Err(crate::auth::consumer_quota_exceeded(&consumer.name, retry_after));
    }
    operator_key_check(&consumer).map_err(|(code, msg)| {
        tracing::warn!(consumer = %consumer.name, %msg, "mcp_operator_key_refused");
        rpc_http_error(code, &msg)
    })
}

/// Operator door on the shared HTTPS listener: a credential is mandatory.
async fn handle_over_tls(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let caller = match authenticate_over_tls(&state.db, state.redis.as_ref(), &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    dispatch(mcp_protocol::Door::Tls, &headers, &body, &state, caller).await
}

/// The JSON-RPC surface. The caller is mandatory: the door has one
/// listener and it authenticates every request, so there is no caller-less
/// dispatch — and no cluster-HMAC identity to fall back to (the design:
/// the `mcp-local` controller-secret self-call was reachable only from the
/// loopback listener removed in stack-v0.2.40). Every tool call writes a
/// `mcp_tool_call` audit row naming the operator caller, matching what the
/// user door does.
async fn dispatch(
    door: mcp_protocol::Door,
    headers: &HeaderMap,
    body: &[u8],
    state: &crate::state::AppState,
    caller: OperatorCaller,
) -> Response {
    let env: Envelope = match mcp_protocol::parse(door, headers, body) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let req = &env.req;

    // a keyed operator is a person with windows; each
    // window is its own session.
    let consumer = caller.consumer.as_str();
    let db = &state.db;
    let session = match crate::mcp_session::from_headers(db, headers, &format!("operator:{consumer}")).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    match req.method.as_str() {
        "initialize" => {
            let client_name = req.params.pointer("/clientInfo/name").and_then(Value::as_str);
            match crate::mcp_session::open(db, &caller.user, &format!("operator:{consumer}"), client_name).await {
                Some((id, _)) => crate::mcp_session::attach(env.initialize(SERVER_NAME), &id),
                None => env.initialize(SERVER_NAME),
            }
        }

        m if m.starts_with("notifications/") => StatusCode::ACCEPTED.into_response(),

        "ping" => env.ping(),

        "server/discover" => env.discover(
            SERVER_NAME,
            "noomesh operator door: the full tool catalog, run with operator authority.",
        ),

        "tools/list" => {
            let mut tools = tools_list();
            // External MCP tools — the operator sees
            // every enabled, placed server.
            if let Some(arr) = tools.as_array_mut() {
                for t in crate::mcp_bridge::catalog_for(state, None).await {
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

            // External MCP tool.
            if name.starts_with(crate::mcp_bridge::PREFIX) {
                let ids = crate::mcp_bridge::server_ids(state).await;
                if let Some((server, tool_name)) = crate::mcp_bridge::split_name(name, &ids) {
                    let user = Some(caller.user.as_str());
                    let argv = Value::Object(args.clone());
                    return match crate::mcp_bridge::call(state, user, &server, &tool_name, &argv).await {
                        Ok(text) => env.result(json!({ "content": [{"type": "text", "text": text}], "isError": false }), SERVER_NAME),
                        Err(e) => env.result(json!({ "content": [{"type": "text", "text": e}], "isError": true }), SERVER_NAME),
                    };
                }
            }
            let Some(spec) = tool(name) else {
                return rpc_error(req.id.clone(), -32602, &format!("unknown tool: {name}"));
            };

            // WHO the self-call runs as. The caller is a named admin: mint
            // their own five-minute JWT (as the user door does) so the
            // gateway scopes, audits and CHARGES the call to that account —
            // an admin JWT reaches everything the operator identity does,
            // so nothing is lost and attribution is gained. Fail closed
            // rather than sending an unauthenticated self-call that 401s
            // confusingly. There is no other identity: never the
            // controller secret.
            let auth = match crate::mcp_external::mint_caller_jwt(
                &caller.user,
                crate::auth::Role::Admin,
                &[],
                &format!("operator:{consumer}"),
                session.as_deref(),
            ) {
                Some(t) => ("Authorization".to_string(), format!("Bearer {t}")),
                None => {
                    return env.result(
                        json!({
                            "content": [{"type": "text", "text":
                                "cannot mint caller credential (NOO_JWT_SECRET unset?)"}],
                            "isError": true,
                        }),
                        SERVER_NAME,
                    );
                }
            };

            let actor = caller.actor();
            tracing::info!(tool = %name, %actor, era = env.era.as_str(), "mcp_local_tool_call");
            crate::routes::core::audit_event(
                &state.db,
                "mcp_tool_call",
                "info",
                &actor,
                name,
                "ok",
                json!({ "door": "operator", "actor": actor, "tool": name, "era": env.era.as_str() }),
            )
            .await;

            match execute_spec(spec, args, auth).await {
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


    #[test]
    fn local_manifest_parses_and_is_full_registry() {
        // 129 at the time of the port, 109 after the pro tools left for the
        // evolve add-on's fragment; assert a floor, not
        // equality, so adding a tool is a manifest regen, not a Rust edit.
        assert!(
            MANIFEST.tools.len() >= 100,
            "local manifest suspiciously small: {} tools",
            MANIFEST.tools.len()
        );
        assert_eq!(MANIFEST.version, EXPECTED_MANIFEST_VERSION);
    }

    #[test]
    fn local_catalog_supersets_external() {
        // Every tool the curated external door serves must exist here too —
        // the local door is the operator's full view.
        let ext: Manifest = serde_json::from_str(include_str!("../mcp-tools.json")).unwrap();
        for t in &ext.tools {
            assert!(
                tool(&t.name).is_some(),
                "external tool {} missing from the local manifest",
                t.name
            );
        }
    }

    fn consumer(scopes: &[&str], user: Option<&str>, role: Option<crate::auth::Role>) -> crate::service_keys::Consumer {
        crate::service_keys::Consumer {
            name: "k".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            rpm_limit: None,
            user: user.map(str::to_string),
            user_scopes: Vec::new(),
            user_role: role,
        }
    }

    #[test]
    fn operator_key_needs_scope_binding_and_admin() {
        use crate::auth::Role;
        // A plain user-door key never opens this door, whatever the account.
        let e = operator_key_check(&consumer(&["mcp"], Some("root"), Some(Role::Admin))).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert!(e.1.contains(OPERATOR_SCOPE), "{}", e.1);
        // Right scope, no bound user: refused — nothing to attribute to.
        let e = operator_key_check(&consumer(&[OPERATOR_SCOPE], None, None)).unwrap_err();
        assert!(e.1.contains("not bound"), "{}", e.1);
        // Bound, but the account was demoted after issue: refused live.
        for r in [Role::User, Role::Operator] {
            let e = operator_key_check(&consumer(&[OPERATOR_SCOPE], Some("bob"), Some(r))).unwrap_err();
            assert!(e.1.contains("admin"), "{}", e.1);
        }
        // Disabled account resolves with user = None (service_keys LEFT JOIN).
        assert!(operator_key_check(&consumer(&[OPERATOR_SCOPE], None, Some(Role::Admin))).is_err());
        // The one shape that opens the door.
        assert_eq!(
            operator_key_check(&consumer(&[OPERATOR_SCOPE], Some("root"), Some(Role::Admin))).unwrap(),
            OperatorCaller { consumer: "k".into(), user: "root".into() }
        );
    }

    #[test]
    fn operator_caller_actor_labels() {
        assert_eq!(
            OperatorCaller { consumer: "alice-laptop".into(), user: "alice".into() }.actor(),
            "alice-laptop:alice"
        );
    }

    /// A pool that is never reachable: `service_keys::resolve` fails its
    /// query and answers None, so a bearer reaches the refusal exactly as
    /// an unknown key would — with no database in the test.
    fn unreachable_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
            .expect("lazy pool")
    }

    fn bearer(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, format!("Bearer {v}").parse().unwrap());
        h
    }

    async fn refusal_text(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// THE retirement. The shared token is still configured here (an
    /// install that has not tidied its store yet), the client presents it
    /// byte for byte, and the door refuses it — naming the key it takes
    /// instead. If the token compare comes back, this returns Ok before the
    /// key lookup and the test fails.
    #[tokio::test]
    async fn the_shared_token_is_refused_even_while_configured() {
        // SAFETY: test-local env mutation; only this test touches these names.
        std::env::set_var("NOO_MCP_TOKEN", "sekrit-shared");
        std::env::set_var("NOO_MCP_TOKEN_PREVIOUS", "sekrit-old");
        let db = unreachable_pool();
        for presented in ["sekrit-shared", "sekrit-old"] {
            let err = authenticate_over_tls(&db, None, &bearer(presented))
                .await
                .expect_err("the retired shared token must not open the operator door");
            let (status, text) = refusal_text(err).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
            assert!(text.contains("service-key issue"), "the refusal must name the mint command: {text}");
            assert!(text.contains(OPERATOR_SCOPE), "{text}");
        }
        std::env::remove_var("NOO_MCP_TOKEN");
        std::env::remove_var("NOO_MCP_TOKEN_PREVIOUS");
    }

    #[tokio::test]
    async fn no_bearer_is_refused_with_the_mint_command() {
        let err = authenticate_over_tls(&unreachable_pool(), None, &HeaderMap::new())
            .await
            .expect_err("no credential, no door");
        let (status, text) = refusal_text(err).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(text.contains("service-key issue"), "{text}");
    }

    /// The mint hint names the scope this door checks. That it is a real
    /// CLI verb is pinned from the Python side
    /// (`tests/test_mcp_token_and_kiosk_key_lane_retired.py`): the CLI's
    /// usage table is outside this crate's Docker build context.
    #[test]
    fn the_mint_hint_names_this_doors_scope() {
        assert!(MINT_HINT.starts_with("noo security service-key issue "), "{MINT_HINT}");
        assert!(MINT_HINT.contains(&format!("--scopes {OPERATOR_SCOPE}")), "{MINT_HINT}");
        assert!(MINT_HINT.contains("--user"), "{MINT_HINT}");
    }

    #[test]
    fn a_leftover_token_is_noticed_under_every_name_it_could_arrive_by() {
        let none = retired_token_vars_set(|_| None);
        assert!(none.is_empty());
        let blank = retired_token_vars_set(|_| Some("  ".into()));
        assert!(blank.is_empty(), "a blank slot is not a configured token");
        for name in RETIRED_TOKEN_VARS {
            let got = retired_token_vars_set(|k| (k == *name).then(|| "x".to_string()));
            assert_eq!(got, vec![*name]);
        }
    }

    /// Nothing in the door reads the retired value any more — presence is
    /// checked by `retired_token_vars_set`, and no code path compares it.
    #[test]
    fn nothing_reads_the_retired_token_value() {
        let src = include_str!("mcp_local.rs");
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        let needle_a = ["secret_or_empty(\"NOO_MCP_", "TOKEN\")"].concat();
        let needle_b = ["env::var(\"NOO_MCP_", "TOKEN"].concat();
        assert!(!code.contains(&needle_a), "the shared token is read again");
        assert!(!code.contains(&needle_b), "the shared token is read again");
    }

    /// the operator door has no caller-less path, so there
    /// is nothing left to sign as `mcp-local` with the controller secret —
    /// and no gateway code mints a controller-secret HMAC for a self-call.
    /// `dispatch` takes the authenticated caller by value, never an Option.
    #[test]
    fn no_gateway_code_signs_a_self_call_with_the_controller_secret() {
        let strip = |src: &str| -> String {
            src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
        };
        let this = strip(include_str!("mcp_local.rs"));
        let body = &this[..this.find("#[cfg(test)]").expect("tests follow the code")];
        let sig = &body[body.find("async fn dispatch(").expect("dispatch")..];
        let sig = &sig[..sig.find(") -> Response").expect("dispatch signature")];
        assert!(sig.contains("caller: OperatorCaller"), "dispatch must take its caller by value:\n{sig}");
        assert!(!sig.contains("Option<"), "a caller-less dispatch is back:\n{sig}");
        let actor = ["\"mcp", "-local\""].concat();
        for forbidden in [actor.as_str(), "cluster_hmac", "controller_secret", "mint_cluster_token", "NOO_CLUSTER_SECRET"] {
            assert!(!body.contains(forbidden), "mcp_local.rs contains `{forbidden}` — the operator door signs nothing with a shared secret");
        }

        let helper = ["cluster_hmac_auth", "_header("].concat();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let (mut scanned, mut offenders) = (0usize, Vec::new());
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    scanned += 1;
                    if strip(&std::fs::read_to_string(&p).unwrap()).contains(&helper) {
                        offenders.push(p.display().to_string());
                    }
                }
            }
        }
        assert!(scanned > 50, "scanned only {scanned} files");
        assert!(offenders.is_empty(), "a controller-secret self-call header is minted at: {offenders:?}");
    }
}
