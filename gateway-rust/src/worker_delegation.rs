// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The per-dispatch credential a worker uses to act as the requesting user
//! (option 1 of the delegation design).
//!
//! `worker.tool.generic` runs Python `ToolDef`s, and most of those are thin
//! HTTP proxies back to this gateway. The worker has to make those calls AS
//! THE PERSON WHO ASKED, so RBAC and the approval gate bind to the right
//! subject. It used to do that by minting its own HS256
//! user JWT with `NOO_JWT_SECRET` — which meant every worker container held
//! the login signing secret, and with HS256 whoever can verify can forge.
//!
//! Now the GATEWAY mints, at dispatch, and the token rides in the request
//! envelope beside `arguments`:
//!
//! * `sub`, `role`, `scopes` — the principal the gateway already resolved
//!   for this call (`bus_principal::current`), nothing the worker chose;
//! * `iss`/`aud` — this gateway's, so the ordinary verifier
//!   (`auth::verify_token`) accepts it; there is no second verifier;
//! * `act: {sub: "svc:worker", task: <tool call id>}` — RFC 8693: who
//!   holds it and for which dispatch. Because it carries `act`, the auth
//!   layer re-checks the account on every request (the kill switch reaches
//!   a token in flight), and the self-service key routes refuse it;
//! * `jti` — unique per mint;
//! * `exp` — the worker timeout plus a little, never more than
//!   [`MAX_TTL_SECS`].
//!
//! Signed ES256 with `NOO_JWT_SIGNING_KEY` when one is configured, so a
//! leaked token cannot be used to mint another; HS256 under the gateway's
//! own secret otherwise. Either way the secret never leaves the gateway.
//!
//! The auth layer confines it: a token whose actor is [`WORKER_ACTOR`] is
//! accepted only on the routes the tool manifest declares
//! ([`route_allowed`]), and refused (403) everywhere else.
//!
//! It is a bearer, so it is NEVER persisted. It exists in the NATS request
//! and in the worker's memory for one dispatch; [`strip`] removes it from
//! anything that is stored (the DLQ row builder calls it), and the worker
//! pops it out of the envelope before its handler sees the request.

use std::sync::LazyLock;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{json, Value};

use crate::auth::Claims;
use crate::bus_principal::{Kind, Principal};

/// The actor a worker-delegated token names. `svc:` because it is a service
/// acting for the subject, not a key a person holds.
pub const WORKER_ACTOR: &str = "svc:worker";

/// Prefix of the `harness` claim a delegated token carries (`worker:<task>`).
pub const HARNESS_PREFIX: &str = "worker:";

/// The envelope key the token rides under — a sibling of `arguments`, never
/// inside it (the model writes `arguments`). The worker pops it by this name.
pub const ENVELOPE_KEY: &str = "delegated_token";

/// The subjects whose handler presents the token. Only these get one: a
/// bearer on a subject whose handler never uses it is exposure for nothing.
pub const DELEGATED_SUBJECTS: &[&str] = &["worker.tool.generic"];

/// The longest a delegated token lives, whatever the worker timeout says.
pub const MAX_TTL_SECS: u64 = 300;

// Five minutes is the ceiling the design set; a longer one fails the build.
const _: () = assert!(MAX_TTL_SECS <= 300);

/// The shortest: a token that expires mid-dispatch reads as an auth outage.
pub const MIN_TTL_SECS: u64 = 60;

/// Slack over the dispatch timeout, for the worker's own HTTP round trip.
const TTL_SLACK_SECS: u64 = 30;

/// Lifetime for a dispatch that may run for `timeout`: the timeout plus a
/// little, clamped into `[MIN_TTL_SECS, MAX_TTL_SECS]`.
pub fn ttl_for(timeout: Duration) -> u64 {
    timeout
        .as_secs()
        .saturating_add(TTL_SLACK_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

/// The claims, unsigned. `None` when the secret is insecure (the same
/// judgement every mint makes, in `auth::scoped_claims`).
pub(crate) fn claims(principal: &Principal, task: &str, ttl_secs: u64, secret: &str) -> Option<Value> {
    let mut c = crate::auth::scoped_claims(&principal.sub, &principal.role, &principal.scopes, ttl_secs, secret)?;
    c["act"] = json!({ "sub": WORKER_ACTOR, "task": task });
    // Bind the token to ONE dispatch for the asynchronous-operations API: an op
    // started with it is owned by `worker:<task>`, and the same token sees only
    // those. An agentic run (prompt-injectable) therefore cannot list or cancel
    // the account's other ops (web, or another MCP consumer's). The Python
    // dispatcher follows the handle of the op it started with this same token.
    c["harness"] = json!(format!("{HARNESS_PREFIX}{task}"));
    c["jti"] = json!(uuid::Uuid::new_v4().to_string());
    Some(c)
}

/// Sign: ES256 under the JWKS key when there is one, HS256 otherwise.
pub(crate) fn sign(claims: &Value, secret: &str, signing: Option<&crate::jwks::SigningKey>) -> Option<String> {
    if let Some(key) = signing {
        let mut header = jsonwebtoken::Header::new(crate::jwks::ALG);
        header.kid = Some(key.kid.clone());
        return jsonwebtoken::encode(&header, claims, &key.encoding).ok();
    }
    crate::auth::sign_hs256(claims, secret)
}

/// [`mint`] with the keys passed in (tests; see `auth::mint_agent_jwt_with`
/// for why nothing here sets process env).
pub(crate) fn mint_with(
    principal: &Principal,
    task: &str,
    ttl_secs: u64,
    secret: &str,
    signing: Option<&crate::jwks::SigningKey>,
) -> Option<String> {
    sign(&claims(principal, task, ttl_secs, secret)?, secret, signing)
}

/// Mint for one dispatch with the gateway's own keys.
pub fn mint(principal: &Principal, task: &str, ttl_secs: u64) -> Option<String> {
    let secret = crate::auth::configured_jwt_secret()?;
    mint_with(principal, task, ttl_secs, &secret, crate::jwks::signing_key())
}

/// Put a token in `envelope` when `subject` is one whose handler acts as the
/// user and `principal` IS a user. Internal principals get nothing: the
/// worker dispatches those with its own service key, as before.
///
/// Returns whether a token was attached. A user dispatch that could not be
/// given one is logged here; the worker then refuses the call loudly rather
/// than running it as anyone else.
pub fn attach_with(
    envelope: &mut Value,
    subject: &str,
    principal: &Principal,
    task: &str,
    mint: impl FnOnce(&Principal, &str) -> Option<String>,
) -> bool {
    if !DELEGATED_SUBJECTS.contains(&subject) || principal.kind != Kind::User {
        return false;
    }
    let Some(obj) = envelope.as_object_mut() else { return false };
    match mint(principal, task) {
        Some(token) => {
            obj.insert(ENVELOPE_KEY.to_string(), Value::String(token));
            true
        }
        None => {
            tracing::error!(
                subject,
                sub = %principal.sub,
                "worker delegation: could not mint the per-dispatch user token (no NOO_JWT_SECRET \
                 on the gateway?) — the worker will refuse this call rather than run it as anyone else"
            );
            false
        }
    }
}

/// [`attach_with`] using the gateway's keys and a TTL from `timeout`.
pub fn attach(envelope: &mut Value, subject: &str, principal: &Principal, task: &str, timeout: Duration) -> bool {
    let ttl = ttl_for(timeout);
    attach_with(envelope, subject, principal, task, |p, t| mint(p, t, ttl))
}

/// Remove the token from a payload about to be stored. Idempotent; a
/// payload without one is unchanged.
pub fn strip(payload: &mut Value) {
    if let Some(obj) = payload.as_object_mut() {
        obj.remove(ENVELOPE_KEY);
    }
}

/// Is this a worker-delegated token?
pub fn is_worker_delegated(claims: &Claims) -> bool {
    claims.act.as_ref().is_some_and(|a| a.sub == WORKER_ACTOR)
}

/// Every `(METHOD, path template)` a Python `ToolDef` can call, from the
/// manifests `scripts/build-mcp-manifest.py` generates from those same
/// `ToolDef`s — the declaration, not a hand-kept list.
static TOOL_ROUTES: LazyLock<Vec<(String, String)>> = LazyLock::new(|| {
    let mut out = Vec::new();
    for raw in [include_str!("../mcp-tools-local.json"), include_str!("../mcp-tools.json")] {
        if let Ok(m) = serde_json::from_str::<crate::mcp_external::Manifest>(raw) {
            for t in m.tools {
                let route = (t.method.to_ascii_uppercase(), t.path);
                if !out.contains(&route) {
                    out.push(route);
                }
            }
        }
    }
    out
});

/// Does `path` match `template`? A `{name}` segment matches exactly one
/// non-empty segment; everything else is literal.
pub(crate) fn template_matches(template: &str, path: &str) -> bool {
    let t: Vec<&str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    t.len() == p.len()
        && t.iter().zip(&p).all(|(ts, ps)| {
            if ts.starts_with('{') && ts.ends_with('}') {
                !ps.is_empty()
            } else {
                ts == ps
            }
        })
}

/// May a worker-delegated token be used for `method path`?
pub fn route_allowed(method: &str, path: &str) -> bool {
    TOOL_ROUTES
        .iter()
        .any(|(m, t)| m.eq_ignore_ascii_case(method) && template_matches(t, path))
}

/// The auth layer's rule: a worker-delegated token off the tool routes is
/// refused (403). Any other token is unaffected.
pub fn confine(claims: &Claims, method: &str, path: &str) -> Result<(), StatusCode> {
    if !is_worker_delegated(claims) || route_allowed(method, path) {
        return Ok(());
    }
    tracing::warn!(
        sub = %claims.sub,
        method,
        path,
        "worker-delegated token refused: not a tool route"
    );
    Err(StatusCode::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{verify_token_with, Role};

    const SECRET: &str = "delegation-test-secret-not-a-real-one";

    fn alice() -> Principal {
        Principal::user("alice", Role::User, vec!["read".into()])
    }

    fn es256() -> crate::jwks::SigningKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        crate::jwks::parse(&kp.serialize_pem()).expect("a generated P-256 key parses")
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    fn unverified(token: &str) -> Value {
        use base64::Engine;
        let body = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap()
    }

    #[test]
    fn ttl_is_the_timeout_plus_slack_and_capped() {
        assert_eq!(ttl_for(Duration::from_secs(120)), 150);
        assert_eq!(ttl_for(Duration::from_secs(1)), MIN_TTL_SECS);
        assert_eq!(ttl_for(Duration::from_secs(3600)), MAX_TTL_SECS);
    }

    #[test]
    fn the_token_carries_the_resolved_principal_and_the_delegation() {
        let key = es256();
        let p = Principal::user("alice/laptop", Role::Operator, vec!["read".into(), "write".into()]);
        let tok = mint_with(&p, "call_42", 150, SECRET, Some(&key)).expect("mints");
        let header = jsonwebtoken::decode_header(&tok).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256, "prefers the asymmetric key");
        assert_eq!(header.kid.as_deref(), Some(key.kid.as_str()));

        let c = unverified(&tok);
        assert_eq!(c["sub"], "alice/laptop");
        assert_eq!(c["role"], "operator");
        assert_eq!(c["scopes"], json!(["read", "write"]));
        assert_eq!(c["iss"], crate::auth::JWT_ISSUER);
        assert_eq!(c["aud"], crate::auth::JWT_AUDIENCE);
        assert_eq!(c["act"]["sub"], WORKER_ACTOR);
        assert_eq!(c["act"]["task"], "call_42");
        assert!(c["jti"].as_str().is_some_and(|j| !j.is_empty()));
        let ttl = c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap();
        assert_eq!(ttl, 150);
        assert!(c["exp"].as_u64().unwrap() <= now() + MAX_TTL_SECS);

        // Two mints for the same dispatch are two tokens.
        let again = mint_with(&p, "call_42", 150, SECRET, Some(&key)).unwrap();
        assert_ne!(unverified(&again)["jti"], c["jti"]);
    }

    #[test]
    fn without_a_signing_key_it_is_hs256_under_the_gateways_secret() {
        let tok = mint_with(&alice(), "t", 150, SECRET, None).unwrap();
        assert_eq!(jsonwebtoken::decode_header(&tok).unwrap().alg, jsonwebtoken::Algorithm::HS256);
        assert!(verify_token_with(&tok, SECRET, None).is_ok());
        assert!(mint_with(&alice(), "t", 150, crate::auth::INSECURE_DEFAULT_JWT_SECRET, None).is_none());
    }

    /// The gateway's ONE verifier accepts it — ES256 through the JWKS key —
    /// and the confinement then decides where.
    #[test]
    fn the_verifier_accepts_it_on_tool_routes_and_refuses_it_elsewhere() {
        let key = es256();
        let tok = mint_with(&alice(), "t", 150, SECRET, Some(&key)).unwrap();
        let claims = verify_token_with(&tok, SECRET, Some(&key)).expect("the ordinary verifier accepts it");
        assert!(is_worker_delegated(&claims));
        assert_eq!(claims.act.as_ref().and_then(|a| a.task.as_deref()), Some("t"));
        assert_eq!(claims.resolved_role(), Role::User);

        for (m, p) in [
            ("GET", "/api/v1/graph/stats"),
            ("GET", "/api/heartbeat/status"),
            ("GET", "/api/jobs/abc-123"),
            ("POST", "/api/heartbeat/tasks/t1/run"),
            ("get", "/api/scheduler/status"),
        ] {
            assert_eq!(confine(&claims, m, p), Ok(()), "{m} {p}");
        }
        for (m, p) in [
            ("POST", "/api/identity/token"),
            ("POST", "/api/addon/token"),
            ("POST", "/api/users/me/service-keys"),
            ("GET", "/api/users"),
            ("DELETE", "/api/v1/graph/stats"),
            ("GET", "/api/jobs/"),
            ("GET", "/api/jobs/a/b"),
            ("POST", "/v1/chat/completions"),
        ] {
            assert_eq!(confine(&claims, m, p), Err(StatusCode::FORBIDDEN), "{m} {p}");
        }
    }

    #[test]
    fn expired_wrong_audience_and_foreign_keys_are_refused() {
        let key = es256();
        let mut c = claims(&alice(), "t", 150, SECRET).unwrap();
        c["exp"] = json!(now() - 3600);
        c["iat"] = json!(now() - 3750);
        let expired = sign(&c, SECRET, Some(&key)).unwrap();
        assert!(verify_token_with(&expired, SECRET, Some(&key)).is_err(), "expired");

        let mut c = claims(&alice(), "t", 150, SECRET).unwrap();
        c["aud"] = json!("noo-grafana");
        let wrong_aud = sign(&c, SECRET, Some(&key)).unwrap();
        assert!(verify_token_with(&wrong_aud, SECRET, Some(&key)).is_err(), "wrong aud");

        let other = es256();
        let foreign = mint_with(&alice(), "t", 150, SECRET, Some(&other)).unwrap();
        assert!(verify_token_with(&foreign, SECRET, Some(&key)).is_err(), "another key");
    }

    #[test]
    fn other_tokens_are_not_confined() {
        let tok = crate::auth::sign_hs256(
            &crate::auth::scoped_claims("alice", "user", ["read"], 60, SECRET).unwrap(),
            SECRET,
        )
        .unwrap();
        let claims = verify_token_with(&tok, SECRET, None).unwrap();
        assert!(!is_worker_delegated(&claims));
        assert_eq!(confine(&claims, "POST", "/api/identity/token"), Ok(()));
    }

    #[test]
    fn a_user_dispatch_on_the_tool_subject_gets_a_token_and_nothing_else_does() {
        let fake = |_: &Principal, t: &str| Some(format!("tok-for-{t}"));
        let mut env = json!({"name": "noo_graph_stats", "arguments": {}});
        assert!(attach_with(&mut env, "worker.tool.generic", &alice(), "c1", fake));
        assert_eq!(env[ENVELOPE_KEY], "tok-for-c1");
        assert!(env["arguments"].get(ENVELOPE_KEY).is_none(), "never inside the model-written arguments");

        let internal = Principal::internal("heartbeat", &["read"]);
        let mut env = json!({"name": "x", "arguments": {}});
        assert!(!attach_with(&mut env, "worker.tool.generic", &internal, "c1", fake));
        assert!(env.get(ENVELOPE_KEY).is_none());

        let mut env = json!({"name": "x", "arguments": {}});
        assert!(!attach_with(&mut env, "worker.rag.query", &alice(), "c1", fake));
        assert!(env.get(ENVELOPE_KEY).is_none());

        let mut env = json!({"name": "x", "arguments": {}});
        assert!(!attach_with(&mut env, "worker.tool.generic", &alice(), "c1", |_, _| None));
        assert!(env.get(ENVELOPE_KEY).is_none());
    }

    #[test]
    fn strip_removes_the_token_and_nothing_else() {
        let mut env = json!({"name": "x", "arguments": {"a": 1}, ENVELOPE_KEY: "secret-bearer"});
        strip(&mut env);
        assert_eq!(env, json!({"name": "x", "arguments": {"a": 1}}));
        strip(&mut env);
        assert_eq!(env, json!({"name": "x", "arguments": {"a": 1}}));
    }

    /// The manifest the confinement reads is the tool declaration: if it
    /// parsed to nothing, every delegated call would 403 and look like an
    /// auth outage.
    #[test]
    fn the_tool_route_table_is_the_manifest() {
        assert!(TOOL_ROUTES.len() > 50, "{}", TOOL_ROUTES.len());
        assert!(template_matches("/api/jobs/{job_id}", "/api/jobs/x"));
        assert!(!template_matches("/api/jobs/{job_id}", "/api/jobs/"));
    }
}

#[cfg(test)]
mod dispatch_site {
    /// The dispatch attaches the token to the envelope it SENDS: the call
    /// sits between building the envelope and the NATS request.
    #[test]
    fn execute_tool_attaches_the_token_before_the_request() {
        let src = include_str!("tools.rs");
        let body = src.split("pub async fn execute_tool(").nth(1).expect("execute_tool exists");
        let envelope = body.find("let mut request = tool_envelope(").expect("envelope built");
        let attach = body.find("crate::worker_delegation::attach(").expect("token attached");
        let send = body.find("worker_client::request(&state.nats, &subject, &request)").expect("request sent");
        assert!(envelope < attach && attach < send, "attach must sit between building and sending the envelope");
    }
}

/// The scratch proof: the REAL gateway state, router and auth
/// middleware (plain TCP listener instead of TLS — the only substitution),
/// a scratch Postgres and NATS, and a worker-shaped Python process whose
/// environment has NO `NOO_JWT_SECRET`, running the real
/// `worker_pool._handle_request` → `_tool_generic` → `ToolDef` dispatch.
///
/// Run (values are throwaway):
/// ```text
/// DATABASE_URL=postgresql://noo:<pw>@127.0.0.1:<pg>/noomesh?sslmode=disable \
/// NATS_URL=tls://localhost:<nats> NOO_TLS_CA=<scratch CA> NOO_NATS_ALLOW_ANONYMOUS=1 \
/// NOO_JWT_SECRET=<gateway only> NOO_CONTROLLER_SECRET=<gateway only> \
/// NOO_BUS_KEY_WORKER=<the worker's bus key, gateway + worker> \
/// NOO_JWT_SIGNING_KEY=<P-256 PEM, optional> NOO_PROOF_SRC=<repo>/src \
/// cargo test --bin noo-gateway proof_ -- --ignored --nocapture
/// ```
#[cfg(test)]
mod proof {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            std::io::stderr().write_all(b)?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const WORKER: &str = r#"
import asyncio, os, sys
sys.path.insert(0, os.environ["NOO_PROOF_SRC"])
assert not any(k.startswith("NOO_JWT_SECRET") for k in os.environ), "the worker must not hold the secret"
import nats
from noomesh.gateway import worker_pool
import noomesh.workers.tools  # registers worker.tool.generic
async def main():
    import ssl
    ctx = ssl.create_default_context(cafile=os.environ["NOO_TLS_CA"])
    nc = await nats.connect(os.environ["NATS_URL"], tls=ctx)
    await nc.subscribe("worker.tool.generic", queue="workers", cb=worker_pool._handle_request)
    await nc.flush()
    print("WORKER_READY env_has_jwt_secret=%s" % any(k.startswith("NOO_JWT_SECRET") for k in os.environ), flush=True)
    await asyncio.sleep(120)
asyncio.run(main())
"#;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "scratch proof: needs Postgres + NATS + python3 — see the doc comment"]
    async fn proof_a_worker_without_the_secret_dispatches_as_the_user() {
        let logs = Buf::default();
        let sink = logs.clone();
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .try_init();

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        crate::mesh_migrate::run().await.expect("migrate the scratch database");
        let config = crate::config::load_config().expect("config");
        let state = Arc::new(crate::state::AppState::new(&config).await.expect("state"));
        let _ = state.self_handle.set(Arc::downgrade(&state));
        sqlx::query(
            "INSERT INTO noo_users (username, hashed_password, scopes) VALUES ('alice', 'x', '[\"read\"]') \
             ON CONFLICT DO NOTHING",
        )
        .execute(&state.db)
        .await
        .expect("seed alice");

        let app = crate::routes::build_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await
        });

        let mut child = tokio::process::Command::new("python3")
            .arg("-c")
            .arg(WORKER)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("NOO_PROOF_SRC", std::env::var("NOO_PROOF_SRC").expect("NOO_PROOF_SRC"))
            .env("NATS_URL", std::env::var("NATS_URL").expect("NATS_URL"))
            .env("NOO_TLS_CA", std::env::var("NOO_TLS_CA").expect("NOO_TLS_CA: the bus is TLS-only"))
            // The worker's OWN bus key and audience —
            // never the controller secret.
            .env("NOO_BUS_KEY", std::env::var("NOO_BUS_KEY_WORKER").expect("NOO_BUS_KEY_WORKER"))
            .env("NOO_BUS_AUDIENCE", "worker")
            .env("NOO_GATEWAY_URL", format!("http://127.0.0.1:{port}"))
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn the worker");
        {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
            let ready = tokio::time::timeout(std::time::Duration::from_secs(60), lines.next_line())
                .await
                .expect("worker ready in time")
                .unwrap()
                .unwrap_or_default();
            eprintln!("worker: {ready}");
            assert!(ready.contains("WORKER_READY env_has_jwt_secret=False"), "{ready}");
            // Keep draining: a full stdout pipe would block the worker.
            tokio::spawn(async move {
                while let Ok(Some(l)) = lines.next_line().await {
                    eprintln!("worker: {l}");
                }
            });
        }

        eprintln!(
            "gateway signs delegated tokens with {}",
            if crate::jwks::signing_key().is_some() { "ES256 (NOO_JWT_SIGNING_KEY)" } else { "HS256" }
        );
        let call = crate::tools::ToolCall {
            id: "call_proof_1".into(),
            name: "noo_approval_stats".into(),
            arguments: serde_json::json!({}),
        };
        let alice = crate::bus_principal::Principal::user("alice", crate::auth::Role::User, vec!["read".into()]);
        let result = crate::bus_principal::with_principal(alice, crate::tools::execute_tool(&state, &call)).await;
        eprintln!("tool result: success={} error={:?} output={}", result.success, result.error, crate::text::clip(&result.output, 300));

        let text = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        let accepted: Vec<&str> = text.lines().filter(|l| l.contains("worker-delegated token accepted")).collect();
        eprintln!("--- gateway lines naming the delegation ---");
        for l in &accepted {
            eprintln!("{l}");
        }
        assert!(result.success, "{:?}", result.error);
        assert!(
            accepted.iter().any(|l| l.contains("sub=alice") && l.contains("svc:worker") && l.contains("call_proof_1")),
            "no gateway line shows the delegated subject"
        );
        let _ = child.kill().await;
    }
}
