// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo-gateway harness` — the loop, on a node.
//!
//! Same binary, a different life: no config file, no Postgres, no Redis,
//! no JetStream, no HTTP listener. It connects to the bus under the
//! node's principal, takes turns on `harness.run.<node>`, and runs each
//! one with [`RemoteRuntime`] against the gateway's rail under the token
//! the turn arrived with, pointed at the ONE model endpoint it was placed
//! next to. Events go back on `harness.turn.<node>.<conversation>`; the result
//! goes last as `harness_result`.
//!
//! Environment (the node agent sets all of it from the placement):
//!
//! | var | meaning |
//! |---|---|
//! | `NODE_ID` | this node's id — the subject it listens on |
//! | `NOO_GATEWAY_URL` | the controller, e.g. `https://gateway:8080` |
//! | `NOO_TLS_CA` | the cluster CA (HTTPS to the gateway, TLS to the bus) |
//! | `NATS_URL`, `NATS_NODE_USER`, `NATS_NODE_PASSWORD` | the node's bus principal — the ONLY credential it presents (the shared pair was retired); the password also as `NATS_NODE_PASSWORD_FILE` |
//! | `NOO_HARNESS_MODEL_URL`, `NOO_HARNESS_MODEL`, `NOO_HARNESS_BACKEND` | the model endpoint, its name, its backend type |
//! | `NOO_HARNESS_MAX_TURNS` | concurrent turns (default 8) |
//! | `NOO_HARNESS_KIND` | the loop: `noo` (default) runs ours; any other kind runs that vendor's headless CLI through [`crate::harness::driver`] |
//!
//! openapi-drift: not-gateway-routes — this is the harness entry point: it mounts nothing on the
//! gateway's listener, and its tests stand up a fake NODE AGENT (`/harness/placement`) whose
//! route is the agent's, not the gateway's (`scripts/check-openapi-drift.py`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use serde_json::json;

use crate::coordinator::{self, ResolvedBackend, RemoteRuntime};
use crate::websocket::{NatsTurnSink, TurnSink, HARNESS_RESULT_EVENT};

fn env(name: &str) -> Result<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty()).ok_or_else(|| anyhow!("{name} is required"))
}

/// The node principal's inbox prefix, as the bus permission spells it:
/// `_INBOX_node_<id>` with the id reduced to `[A-Za-z0-9_-]`.
pub fn inbox_prefix(node: &str) -> String {
    let tok: String = node
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    format!("_INBOX_node_{tok}")
}

/// The node's bus credential: its own pair, and nothing else.
///
/// The harness acts as the person whose task it is running, on a node's
/// principal. It never presents a wider credential than the node's own —
/// the shared `>`/`>` pair it could once fall back to behind a posture
/// bridge was retired — and a missing pair is a refusal that
/// names the delivering verb, not an anonymous connect.
///
/// The password is read through `secret_env`: the applier
/// turns `/etc/noo-harness.env`'s values into `NAME_FILE` pointers once the
/// installed binary carries [`HARNESS_SECRET_FILES_CAPABILITY`]. A pointer
/// that cannot be read is an error here — never a fall-through to the plain
/// variable, and never "no password".
fn bus_credential_from(
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<crate::nats_credentials::NatsCredential>, String> {
    let password = crate::config::secret_env::secret_from("NATS_NODE_PASSWORD", get).map_err(|e| e.to_string())?;
    crate::nats_credentials::resolve_node(|k| if k == "NATS_NODE_PASSWORD" { password.clone() } else { get(k) })
}

/// Every secret the harness reads through `secret_env` — the NATS pair here,
/// and the node-agent bearer (`NOO_NODE_AGENT_TOKEN`, `NOO_CLUSTER_SECRET`)
/// that `node_agent_auth::header_for` attaches to the model
/// endpoint while its agent has not said it admits this node's leaf alone
/// (`node_agent_auth::watch_own_agent`). `scripts/noo-apply.sh` `HARNESS_SECRET_KEYS` and the macOS
/// applier move exactly these into files; `tests/test_file_reader_parity.py`
/// keeps the three lists equal.
pub const HARNESS_SECRET_KEYS: &[&str] =
    &["NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NATS_NODE_PASSWORD"];

/// The marker the appliers grep for in the installed gateway binary before
/// they point the harness env at files: a harness without it reads the NATS
/// pair only from the plain variable. Logged at startup, which is also what
/// keeps the string in the binary. The binary is never executed to ask.
pub const HARNESS_SECRET_FILES_CAPABILITY: &str = "noo-harness-reads-secret-files/1";

/// The boot-time refusal: every [`HARNESS_SECRET_KEYS`] name whose `_FILE`
/// cannot be read, and every one set both as `NAME` and `NAME_FILE` (two
/// writers disagreeing about delivery), joined into one error — the Go
/// agent's `config.CheckSecrets`, for the harness.
pub fn check_harness_secrets(get: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    use crate::config::secret_env::{both_set_conflicts_from, secret_from};
    let mut errs: Vec<String> = both_set_conflicts_from(HARNESS_SECRET_KEYS, get)
        .into_iter()
        .map(|n| {
            format!(
                "both {n} and {n}_FILE are set — refusing to choose between a plain value and a \
                 secret file; `noo cluster provision <node>` rewrites this node's harness env"
            )
        })
        .collect();
    errs.extend(HARNESS_SECRET_KEYS.iter().filter_map(|n| secret_from(n, get).err()).map(|e| e.to_string()));
    if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
}

pub async fn run() -> Result<()> {
    // i119: the environment systemd loaded (bus password, agent bearer)
    // stays out of /proc/<pid>/environ for every other process of this uid
    // — above all a foreign CLI the driver started. Costs core dumps only.
    if let Err(e) = crate::harness::jail::make_undumpable() {
        tracing::warn!(error = %e, "harness: could not make the process non-dumpable");
    }
    let node = env("NODE_ID")?;
    let gateway = env("NOO_GATEWAY_URL")?;
    let nats_url = env("NATS_URL")?;
    let model_url = env("NOO_HARNESS_MODEL_URL")?;
    let model = env("NOO_HARNESS_MODEL")?;
    let backend_type = std::env::var("NOO_HARNESS_BACKEND").unwrap_or_else(|_| "openai".into());
    let max_turns: usize = std::env::var("NOO_HARNESS_MAX_TURNS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let pinned = ResolvedBackend {
        url: model_url.clone(),
        model: model.clone(),
        backend_type: backend_type.clone(),
        api_format: coordinator::api_format_for(&backend_type, &model_url),
    };
    let get = |k: &str| std::env::var(k).ok();
    check_harness_secrets(&get).map_err(|e| anyhow!("harness: secrets: {e}"))?;
    tracing::info!(capability = HARNESS_SECRET_FILES_CAPABILITY, "harness: secret reader");
    let cred = bus_credential_from(&get)
        .map_err(|e| anyhow!("harness: bus credential: {e}"))?;
    match &cred {
        Some(c) => tracing::info!(user = %c.user, source = c.source, "harness: bus credential resolved"),
        None => tracing::warn!(
            "harness: connecting ANONYMOUSLY — {}=1 is set",
            crate::nats_credentials::ALLOW_ANONYMOUS_VAR
        ),
    }
    let nats = crate::bus::connect(&nats_url, cred, &inbox_prefix(&node), Duration::from_secs(30)).await?;
    tracing::info!(node = %node, gateway = %gateway, model = %model, endpoint = %model_url, "harness: online");

    let client = crate::tls::cluster_client();
    // The model endpoint is this node's own agent: ask it whether it admits
    // this node's leaf over loopback with no bearer, and drop
    // NOO_NODE_AGENT_TOKEN only if it says so. Re-asked every
    // minute, so a rolled-back agent gets the bearer again. Before the
    // subscriptions: no turn is taken until the first answer is in.
    if coordinator::is_node_agent_url(&model_url) {
        crate::node_agent_auth::watch_own_agent(client.clone(), model_url.clone()).await;
    }
    // Which loop: ours, or a vendor's CLI through the driver. After the
    // agent watch, so the placement read carries the right credential. A
    // foreign kind this binary cannot drive is a refusal at start, not a
    // turn failure.
    let (kind, source) = resolve_kind(std::env::var("NOO_HARNESS_KIND").ok(), &model_url, &client).await;
    tracing::info!("harness: kind={kind} source={source}");
    let driver: Option<Arc<crate::harness::driver::DriverCtx>> = if kind == "noo" {
        None
    } else {
        let ctx = crate::harness::driver::DriverCtx::from_env(&node, &gateway, &kind, pinned.clone())
            .map_err(|e| anyhow!("harness: kind {kind}: {e}"))?;
        tracing::info!(kind = %kind, cli = ?ctx.kind.cli, workdir = %ctx.workdir_root.display(), timeout_secs = ctx.timeout.as_secs(), "harness: driving a foreign CLI");
        // Said once at start, before any task: a node that cannot jail the
        // CLI checkpoints every task with the reason instead of running it.
        match crate::harness::jail::probe() {
            Ok(a) => tracing::info!("harness jail: {a}"),
            Err(r) => tracing::error!(event = "harness_jail_refused", reason = %r, "harness_jail_refused: {}", r.note()),
        }
        // Then the jail is PROVED here, not trusted: a jailed shell must
        // fail to read a planted secret, a sibling's and this process's
        // environment, and the node's key dir. The verdict is kept for the
        // process (`jail::gate`, the driver's probe): a failure refuses
        // every foreign task and turn until the harness restarts.
        match crate::harness::jail::self_test(&ctx.workdir_root).await {
            Ok(r) => tracing::info!(elapsed_ms = r.elapsed.as_millis() as u64, proved = ?r.proved, unproved = ?r.unproved, "harness jail self-test: {r}"),
            Err(r) => tracing::error!(event = "harness_jail_selftest_failed", reason = %r, "harness_jail_selftest_failed: {r}"),
        }
        Some(Arc::new(ctx))
    };
    let subject = coordinator::harness_run_subject(&node);
    let mut turns = nats.queue_subscribe(subject.clone(), "harness".to_string()).await?;
    let mut tasks = nats.queue_subscribe(crate::tasks::task_subject(&node), "harness".to_string()).await?;
    let limit = Arc::new(tokio::sync::Semaphore::new(max_turns.max(1)));

    // Tasks: the same slot, many loops. A task holds
    // one concurrency permit for its whole life.
    {
        let nats_t = nats.clone();
        let gateway_t = gateway.clone();
        let client_t = client.clone();
        let pinned_t = pinned.clone();
        let limit_t = limit.clone();
        let node_t = node.clone();
        let driver_t = driver.clone();
        tokio::spawn(async move {
            while let Some(msg) = tasks.next().await {
                let req: crate::tasks::TaskRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "harness: unreadable task request");
                        continue;
                    }
                };
                let Ok(permit) = limit_t.clone().try_acquire_owned() else {
                    tracing::warn!(task = %req.task_id, "harness: at capacity; not taking this task");
                    continue;
                };
                if let Some(reply) = msg.reply.clone() {
                    let _ = nats_t.publish(reply, serde_json::to_vec(&json!({"ack": true, "node": node_t})).unwrap_or_default().into()).await;
                }
                let gateway = gateway_t.clone();
                let client = client_t.clone();
                let pinned = pinned_t.clone();
                let driver = driver_t.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let outcome = async {
                        // One CLI invocation per loop, same checkpoints.
                        if let Some(ctx) = driver.as_deref() {
                            return crate::harness::driver::run_task(ctx, client, &req).await;
                        }
                        let rt = RemoteRuntime::connect(&gateway, &req.token, client).await?.pin_backend(pinned);
                        crate::tasks::run_task_loops(rt, &req).await
                    }
                    .await;
                    match outcome {
                        Ok(state) => tracing::info!(task = %req.task_id, state = %state, "harness: task finished"),
                        Err(e) => tracing::error!(task = %req.task_id, error = %e, "harness: task failed"),
                    }
                });
            }
        });
    }
    // Announce: the gateway hands back this node's checkpointed tasks.
    let _ = nats.publish(crate::tasks::ready_subject(&node), serde_json::to_vec(&json!({"node": node})).unwrap_or_default().into()).await;

    while let Some(msg) = turns.next().await {
        let req: coordinator::TurnRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "harness: unreadable turn request");
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Full: do not ack, and the gateway runs the turn itself.
            tracing::warn!(conversation = %req.conversation_id, "harness: at capacity; not taking this turn");
            continue;
        };
        if let Some(reply) = msg.reply.clone() {
            let _ = nats.publish(reply, serde_json::to_vec(&json!({"ack": true, "node": node})).unwrap_or_default().into()).await;
        }
        let nats = nats.clone();
        let gateway = gateway.clone();
        let client = client.clone();
        let pinned = pinned.clone();
        let node = node.clone();
        let driver = driver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Our OWN node id on the subject — the grant is written against it.
            let sink = NatsTurnSink::new(nats.clone(), &node, &req.conversation_id);
            let outcome = match driver.as_deref() {
                // Nothing streams mid-run: one `content` with the answer,
                // then the result.
                Some(ctx) => crate::harness::driver::run_turn(ctx, client, &req).await,
                None => run_turn(&gateway, client, pinned, &sink, &req).await,
            };
            if let (Some(_), Ok(r), true) = (driver.as_deref(), &outcome, req.stream) {
                let _ = sink.send_event("content", json!(r.response)).await;
            }
            match outcome {
                Ok(result) => {
                    let _ = sink.send_event(HARNESS_RESULT_EVENT, json!({"result": result, "node": node})).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, conversation = %req.conversation_id, "harness: turn failed");
                    let _ = sink.send_event("error", json!(format!("{e}"))).await;
                }
            }
        });
    }
    Err(anyhow!("harness: the turn subscription ended"))
}

/// Which loop this harness runs, and where that came from.
///
/// `NOO_HARNESS_KIND` is NOT in the harness's env file (the template omits
/// it on purpose), so: the variable when set (dev and tests), else the
/// node agent's own answer — `GET {agent}/harness/placement` on the same
/// loopback proxy the model calls go to — else `noo`. A 404, `placed:
/// false`, an empty kind or an unreachable agent is `noo` with a warning:
/// running our own loop is never the wrong thing to fall back to.
async fn resolve_kind(env_kind: Option<String>, model_url: &str, client: &reqwest::Client) -> (String, &'static str) {
    if let Some(k) = env_kind.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        return (k, "env");
    }
    if !coordinator::is_node_agent_url(model_url) {
        tracing::warn!(endpoint = %model_url, "harness: the model endpoint is not a node agent; no placement to read, running kind noo");
        return ("noo".into(), "default");
    }
    match placement_kind(client, model_url).await {
        Ok(Some(k)) => (k, "agent"),
        Ok(None) => ("noo".into(), "default"),
        Err(e) => {
            tracing::warn!(error = %e, "harness: could not read the placement from the node agent; running kind noo");
            ("noo".into(), "default")
        }
    }
}

/// `GET {base of agent_url}/harness/placement` → the placed kind. `Ok(None)`
/// = the agent answered that nothing (or nothing with a kind) is placed.
async fn placement_kind(client: &reqwest::Client, agent_url: &str) -> Result<Option<String>> {
    let mut u = reqwest::Url::parse(agent_url.trim())?;
    u.set_path("/harness/placement");
    u.set_query(None);
    let mut req = client.get(u).timeout(Duration::from_secs(10));
    if let Some((k, v)) = crate::node_agent_auth::header_for(agent_url) {
        req = req.header(k, v);
    }
    let resp = req.send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::warn!("harness: the node agent has no harness placement route (404); running kind noo");
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {}", resp.status().as_u16()));
    }
    Ok(kind_from_placement(&resp.json::<serde_json::Value>().await?))
}

/// The kind in a placement answer `{"kind", "env", "desired_state",
/// "placed"}`; `None` when not placed or no kind is named.
fn kind_from_placement(v: &serde_json::Value) -> Option<String> {
    if v.get("placed").and_then(|p| p.as_bool()) != Some(true) {
        tracing::warn!("harness: the node agent says no harness is placed; running kind noo");
        return None;
    }
    v.get("kind").and_then(|k| k.as_str()).map(str::trim).filter(|k| !k.is_empty()).map(str::to_string)
}

async fn run_turn<S: TurnSink>(
    gateway: &str,
    client: reqwest::Client,
    pinned: ResolvedBackend,
    sink: &S,
    req: &coordinator::TurnRequest,
) -> Result<coordinator::CoordinatorResult> {
    let rt = RemoteRuntime::connect(gateway, &req.token, client).await?.pin_backend(pinned);
    // The person is the token's subject on the gateway side; the loop still
    // wants the name for its own task-locals (external-tool audience).
    let user = Some(req.user.as_str());
    if req.stream {
        coordinator::run_streaming_on(
            sink,
            &rt,
            &req.prompt,
            &req.conversation_id,
            req.max_iterations,
            req.model.as_deref(),
            user,
            req.enable_thinking,
        )
        .await
    } else {
        coordinator::run_inner(
            &rt,
            &req.prompt,
            &req.conversation_id,
            &req.channel,
            req.max_iterations,
            req.model.as_deref(),
            user,
            req.role_prompt.as_deref(),
            req.enable_thinking,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in node agent answering `/harness/placement` with `status`
    /// and `body`; returns its base URL.
    async fn fake_agent(status: u16, body: serde_json::Value) -> String {
        use axum::{routing::get, Json, Router};
        let app = Router::new().route(
            "/harness/placement",
            get(move || {
                let body = body.clone();
                async move { (axum::http::StatusCode::from_u16(status).unwrap(), Json(body)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/v1")
    }

    #[tokio::test]
    async fn the_kind_comes_from_env_then_the_agent_then_noo() {
        let c = reqwest::Client::new();
        // The variable wins, and needs no agent at all.
        assert_eq!(resolve_kind(Some(" copilot ".into()), "http://127.0.0.1:9/v1", &c).await, ("copilot".into(), "env"));
        // A model endpoint that is not a node agent has no placement to read.
        assert_eq!(resolve_kind(Some("  ".into()), "http://vllm:8000/v1", &c).await, ("noo".into(), "default"));

        let placed = fake_agent(200, json!({"kind": "claude-code", "env": {"X": "1"}, "desired_state": "running", "placed": true})).await;
        assert_eq!(placement_kind(&c, &placed).await.unwrap().as_deref(), Some("claude-code"));
        let unplaced = fake_agent(200, json!({"kind": "copilot", "env": {}, "desired_state": "stopped", "placed": false})).await;
        assert_eq!(placement_kind(&c, &unplaced).await.unwrap(), None);
        let old_agent = fake_agent(404, json!({"error": "not found"})).await;
        assert_eq!(placement_kind(&c, &old_agent).await.unwrap(), None);
        let broken = fake_agent(500, json!({})).await;
        assert!(placement_kind(&c, &broken).await.is_err());
        assert!(placement_kind(&c, "http://127.0.0.1:9/v1").await.is_err(), "unreachable is an error, resolved to noo");
        assert_eq!(kind_from_placement(&json!({"placed": true, "kind": ""})), None);
        assert_eq!(kind_from_placement(&json!({"kind": "copilot"})), None, "no placed flag is not placed");
    }

    #[test]
    fn the_inbox_prefix_matches_the_bus_permission() {
        assert_eq!(inbox_prefix("host8"), "_INBOX_node_host8");
        assert_eq!(inbox_prefix("a.b c"), "_INBOX_node_a_b_c");
    }

    // ── the secret reader ────────────────────────────────

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    fn secret_file(tag: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("harness_secret_{tag}_{}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn the_node_password_follows_file_then_prefix_then_plain() {
        let f = secret_file("prec", "from-file\n");
        let fp = f.to_str().unwrap();
        let user = ("NATS_NODE_USER", "node-x");
        let cases: [(&[(&str, &str)], &str); 3] = [
            (&[user, ("NATS_NODE_PASSWORD_FILE", fp), ("NOO_SECRET_NATS_NODE_PASSWORD", "pref")], "from-file"),
            (&[user, ("NOO_SECRET_NATS_NODE_PASSWORD", "pref"), ("NATS_NODE_PASSWORD", "plain")], "pref"),
            (&[user, ("NATS_NODE_PASSWORD", "plain")], "plain"),
        ];
        for (pairs, want) in cases {
            let c = bus_credential_from(&env(pairs)).unwrap().expect("a credential");
            assert_eq!((c.user.as_str(), c.password.as_str(), c.source), ("node-x", want, "node"), "{pairs:?}");
        }
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn an_unreadable_password_file_is_an_error_never_the_plain_value() {
        let missing = std::env::temp_dir().join(format!("harness_secret_absent_{}", std::process::id()));
        let mp = missing.to_str().unwrap();
        for fallback in ["NATS_NODE_PASSWORD", "NOO_SECRET_NATS_NODE_PASSWORD"] {
            let got = bus_credential_from(&env(&[
                ("NATS_NODE_USER", "node-x"),
                ("NATS_NODE_PASSWORD_FILE", mp),
                (fallback, "must-not-be-used"),
            ]));
            let err = got.map(|c| c.map(|c| c.password)).expect_err("an unreadable pointer must refuse");
            assert!(err.contains(mp) && err.contains("NATS_NODE_PASSWORD_FILE"), "{err}");
        }
        // the retired shared pair is never a fallback: a node
        // with only NATS_USER/NATS_PASSWORD gets no credential from them
        let shared = bus_credential_from(&env(&[("NATS_USER", "noo"), ("NATS_PASSWORD", "x")]));
        assert!(!matches!(shared, Ok(Some(ref c)) if c.user == "noo"), "the shared pair must not be used");
    }

    #[test]
    fn the_boot_check_names_every_broken_delivery_and_passes_a_plain_env() {
        let missing = std::env::temp_dir().join(format!("harness_secret_gone_{}", std::process::id()));
        let mp = missing.to_str().unwrap();
        let f = secret_file("both", "x");
        let err = check_harness_secrets(&env(&[
            ("NOO_CLUSTER_SECRET_FILE", mp),
            ("NATS_NODE_PASSWORD_FILE", f.to_str().unwrap()),
            ("NATS_NODE_PASSWORD", "plain"),
        ]))
        .unwrap_err();
        assert!(err.contains(mp) && err.contains("both NATS_NODE_PASSWORD and NATS_NODE_PASSWORD_FILE"), "{err}");
        check_harness_secrets(&env(&[("NATS_NODE_PASSWORD", "plain"), ("NOO_NODE_AGENT_TOKEN", "t")]))
            .expect("an old plain env must still boot");
        let _ = std::fs::remove_file(f);
    }

    /// the harness asks its own agent before every model
    /// call can drop the bearer. Without the watch, `header_for` has no
    /// entry for the model URL and sends the token unconditionally.
    #[test]
    fn the_harness_watches_its_own_agent_before_taking_turns() {
        let code = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/harness_main.rs")).unwrap();
        let run = &code[code.find("pub async fn run()").expect("run()")..code.find("async fn run_turn").expect("run_turn")];
        let watch = run.find("node_agent_auth::watch_own_agent(").expect("run() must watch its own agent");
        let turns = run.find("queue_subscribe(").expect("run() subscribes");
        assert!(watch < turns, "the watch must start before the first turn is taken");
    }

    /// The jail self-test runs after the process is made non-dumpable and
    /// before the first task or turn can be taken.
    #[test]
    fn the_jail_self_test_runs_before_any_task_is_taken() {
        let code = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/harness_main.rs")).unwrap();
        let run = &code[code.find("pub async fn run()").expect("run()")..code.find("async fn run_turn").expect("run_turn")];
        let dump = run.find("jail::make_undumpable()").expect("undumpable");
        let test = run.find("jail::self_test(&ctx.workdir_root).await").expect("run() must self-test the jail");
        let subs = run.find("queue_subscribe(").expect("run() subscribes");
        assert!(dump < test && test < subs, "undumpable, then the self-test, then the subscriptions");
        assert!(run.contains("harness_jail_selftest_failed: {r}") && run.contains("harness jail self-test: {r}"));
    }

    #[test]
    fn every_harness_secret_is_in_the_crate_manifest() {
        // Preflight's `file_errors` and the bypass scan (the parity guard)
        // both walk FILE_BACKED_SECRETS; a harness name outside it would
        // have a reader nobody checks.
        for n in HARNESS_SECRET_KEYS {
            assert!(crate::config::secret_env::FILE_BACKED_SECRETS.contains(n), "{n}");
        }
        assert!(HARNESS_SECRET_FILES_CAPABILITY.starts_with("noo-harness-reads-secret-files/"));
    }
}
