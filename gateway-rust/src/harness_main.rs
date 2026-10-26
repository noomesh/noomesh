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
//! | `NOO_HARNESS_THINKING` | `on`/`off`/`auto` (default): reasoning control for every model call; else the placement's env, else the profile's `thinking` |
//! | `NOO_BACKEND_STREAM_IDLE_SECS` | how long a streamed model answer may go silent before it counts as cut; else the placement's env, else the profile's `stream_idle_secs`, else 300 |
//!
//! The node's harness profile (`profile` in the agent's `/harness/placement`
//! answer, resolved by the gateway from the node's tier, measured speed and
//! overrides; [`crate::harness::profile`]) fills what the env and the
//! placement leave unset: `thinking`, `stream_idle_secs` (fixed at start for
//! the whole process, `tls::set_stream_idle_override`; a later change waits
//! for the next restart) and `claude_prompt` (full or slim Claude Code,
//! re-read every minute with the rest).
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

/// Default `NOO_HARNESS_DRAIN_SECS`: on SIGTERM the harness stops taking
/// work and gives what it holds this long to finish before it exits. The
/// node agent restarts the harness on a kind change (`convergeHarness`), and
/// until this a restart killed every turn and task mid-flight; a drained
/// restart hands the gateway finished work and re-takes nothing twice. The
/// unit's `TimeoutStopSec` and the Mac plist's `ExitTimeOut` leave 30 s more
/// than this bound (noomesh-internal i256).
pub const DEFAULT_DRAIN_SECS: u64 = 120;

/// The drain bound from the environment: whole seconds, 1..=3600, else the
/// default.
pub fn drain_bound(get: &dyn Fn(&str) -> Option<String>) -> Duration {
    Duration::from_secs(
        get("NOO_HARNESS_DRAIN_SECS").and_then(|v| v.trim().parse::<u64>().ok()).filter(|s| (1..=3600).contains(s)).unwrap_or(DEFAULT_DRAIN_SECS),
    )
}

/// Resolves once the process is asked to stop (SIGTERM from the service
/// manager, or Ctrl-C). Every loop that takes work selects on it.
fn stop_signal() -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, "harness: cannot listen for SIGTERM; a stop will not drain");
                    return;
                }
            };
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        tracing::info!("harness: stop requested; taking no new work");
        let _ = tx.send(true);
    });
    rx
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
    // A placement the agent could not be ASKED about is not "nothing
    // placed": guessing `noo` would run our loop under a foreign placement
    // and corrupt every kind comparison. Exit instead: the service manager
    // restarts us, and the agent's crash-loop check reports the refusal.
    let (kind, source) = match resolve_kind(std::env::var("NOO_HARNESS_KIND").ok(), &model_url, &client, KIND_RETRY_DELAYS).await {
        Ok(k) => k,
        Err(e) => {
            let msg = refusal_message(&e);
            tracing::error!(event = "harness_kind_unknown", "{}", msg);
            return Err(anyhow!(msg));
        }
    };
    tracing::info!("harness: kind={kind} source={source}");
    // The placement once more, for the env keys and the node's harness
    // profile. Read BEFORE anything builds a stream client: the profile's
    // stream idle bound is fixed for the process here.
    let placement = read_placement(&model_url, &client).await;
    let profile = profile_of(&placement);
    match &profile {
        Some(p) => tracing::info!(
            tier = ?p.tier, first_byte_secs = ?p.first_byte_secs, stream_idle_secs = ?p.stream_idle_secs,
            thinking = ?p.thinking, ollama_context = ?p.ollama_context, claude_prompt = ?p.claude_prompt,
            foreign_kinds = ?p.foreign_kinds, "harness: profile from the node agent"
        ),
        None => tracing::info!("harness: no harness profile from the node agent; built-in defaults"),
    }
    let started_idle = {
        let env_idle = std::env::var(crate::tls::STREAM_IDLE_ENV).ok();
        let placement_idle = placement.as_ref().ok().and_then(|p| p.as_ref()).and_then(|p| placement_env(p, crate::tls::STREAM_IDLE_ENV));
        let (secs, idle_source) =
            crate::harness::profile::resolve_stream_idle(env_idle.as_deref(), placement_idle.as_deref(), profile.as_ref());
        if let Some(secs) = secs {
            if !crate::tls::set_stream_idle_override(Duration::from_secs(secs)) {
                tracing::warn!(seconds = secs, "harness: the stream idle bound was already fixed; the profile's value is not applied");
            }
        }
        tracing::info!("harness: stream_idle={}s source={idle_source}", crate::tls::stream_idle().as_secs());
        secs
    };
    // NOO_HARNESS_THINKING for every model call this harness makes, ours
    // and a foreign CLI's (the translator): the process env, else the
    // placement's env, else the profile, else `auto`.
    let (thinking, thinking_source) =
        thinking_after_read(std::env::var(coordinator::thinking::THINKING_ENV).ok(), &placement);
    coordinator::thinking::set_process_mode(thinking);
    tracing::info!("harness: thinking={thinking:?} source={thinking_source}");
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
        // full or slim Claude Code: the profile, else full. Only a kind
        // with a `launch_slim` is affected.
        let (variant, variant_source) = crate::harness::profile::resolve_claude_prompt(None, profile.as_ref());
        ctx.prompt.set(variant);
        if ctx.launch_slim.is_some() {
            tracing::info!("harness: claude_prompt={} source={variant_source}", variant.name());
        }
        // The model's real window for a CLI that takes one (i147): the
        // node agent's `model_context`, else the CLI's own default.
        if let Some(var) = ctx.launch.context_window_env.as_deref() {
            let (window, window_source) = crate::harness::profile::resolve_context_window(None, model_context_of(&placement));
            ctx.context_window.set(window);
            tracing::info!("harness: {var}={} source={window_source}", window.map_or("unset".into(), |n| n.to_string()));
        }
        Some(Arc::new(ctx))
    };
    // A placement or profile change does not restart the harness (only a
    // kind change does), so re-read both every minute: `noo cluster place
    // <node> harness <model> --env NOO_HARNESS_THINKING=off` or `noo cluster
    // profile <node> --set claude_prompt=slim` then lands within one. The
    // stream idle bound is the exception: the stream clients bake it in.
    {
        let client = client.clone();
        let model_url = model_url.clone();
        let switch = driver.as_ref().filter(|d| d.launch_slim.is_some()).map(|d| d.prompt.clone());
        let window = driver.as_ref().filter(|d| d.launch.context_window_env.is_some()).map(|d| d.context_window.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            let mut idle_warned = false;
            loop {
                tick.tick().await;
                let placement = read_placement(&model_url, &client).await;
                let (mode, source) =
                    thinking_after_read(std::env::var(coordinator::thinking::THINKING_ENV).ok(), &placement);
                if source == "unreachable" {
                    continue;
                }
                if coordinator::thinking::set_process_mode(mode) != Some(mode) {
                    tracing::info!("harness: thinking={mode:?} source={source} (changed)");
                }
                let profile = profile_of(&placement);
                if let Some(sw) = &switch {
                    let (variant, src) = crate::harness::profile::resolve_claude_prompt(None, profile.as_ref());
                    if sw.set(variant) != variant {
                        tracing::info!("harness: claude_prompt={} source={src} (changed; from the next run)", variant.name());
                    }
                }
                if let Some(w) = &window {
                    let (now, src) = crate::harness::profile::resolve_context_window(None, model_context_of(&placement));
                    if w.set(now) != now {
                        tracing::info!("harness: context window={} source={src} (changed; from the next run)", now.map_or("unset".into(), |n| n.to_string()));
                    }
                }
                let placement_idle = placement.as_ref().ok().and_then(|p| p.as_ref()).and_then(|p| placement_env(p, crate::tls::STREAM_IDLE_ENV));
                let (idle, _) = crate::harness::profile::resolve_stream_idle(None, placement_idle.as_deref(), profile.as_ref());
                let idle_moved = idle != started_idle && std::env::var(crate::tls::STREAM_IDLE_ENV).ok().is_none_or(|v| v.trim().is_empty());
                if idle_moved && !idle_warned {
                    tracing::warn!(now = ?idle, started = ?started_idle, "harness: the profile's stream_idle_secs changed; it applies when the harness restarts");
                }
                idle_warned = idle_moved;
            }
        });
    }
    let subject = coordinator::harness_run_subject(&node);
    let mut turns = nats.queue_subscribe(subject.clone(), "harness".to_string()).await?;
    let mut tasks = nats.queue_subscribe(crate::tasks::task_subject(&node), "harness".to_string()).await?;
    let limit = Arc::new(tokio::sync::Semaphore::new(max_turns.max(1)));
    let drain = drain_bound(&|k| std::env::var(k).ok());
    let mut stop = stop_signal();
    // The tasks this harness holds right now, by id: a hand-back of a task
    // that is already here (the gateway hands a node's unfinished tasks
    // back on every `harness.ready`) is acknowledged as taken and never
    // started a second time, so it can neither run twice nor hold a second
    // permit (noomesh-internal i176).
    let running: Arc<std::sync::Mutex<std::collections::HashSet<String>>> = Arc::default();

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
        let running_t = running.clone();
        let capacity = max_turns.max(1);
        let mut stop_t = stop.clone();
        tokio::spawn(async move {
            loop {
                let msg = tokio::select! {
                    _ = stop_t.changed() => break,
                    m = tasks.next() => match m { Some(m) => m, None => break },
                };
                let req: crate::tasks::TaskRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "harness: unreadable task request");
                        continue;
                    }
                };
                if running_t.lock().map(|r| r.contains(&req.task_id)).unwrap_or(false) {
                    // Already here: say so, do not start it again.
                    tracing::info!(task = %req.task_id, "harness: task already running here; acknowledged, not started again");
                    if let Some(reply) = msg.reply.clone() {
                        let _ = nats_t.publish(reply, serde_json::to_vec(&json!({"ack": true, "already": true, "node": node_t})).unwrap_or_default().into()).await;
                    }
                    continue;
                }
                let Ok(permit) = limit_t.clone().try_acquire_owned() else {
                    // Busy is not dead: the gateway keeps the task for this
                    // node and hands it back when a slot frees.
                    let held: Vec<String> = running_t.lock().map(|r| r.iter().cloned().collect()).unwrap_or_default();
                    tracing::info!(task = %req.task_id, capacity, running = held.len(), holding = ?held, "harness: at capacity; task stays queued for this node");
                    if let Some(reply) = msg.reply.clone() {
                        let _ = nats_t.publish(reply, serde_json::to_vec(&json!({"ack": false, "busy": true, "node": node_t, "capacity": capacity, "running": held.len()})).unwrap_or_default().into()).await;
                    }
                    continue;
                };
                if let Ok(mut r) = running_t.lock() {
                    r.insert(req.task_id.clone());
                }
                let in_hand = running_t.lock().map(|r| r.len()).unwrap_or(0);
                tracing::info!(task = %req.task_id, running = in_hand, capacity, "harness: task taken");
                if let Some(reply) = msg.reply.clone() {
                    let _ = nats_t.publish(reply, serde_json::to_vec(&json!({"ack": true, "node": node_t})).unwrap_or_default().into()).await;
                }
                let gateway = gateway_t.clone();
                let client = client_t.clone();
                let pinned = pinned_t.clone();
                let driver = driver_t.clone();
                let running_done = running_t.clone();
                let nats_done = nats_t.clone();
                let node_done = node_t.clone();
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
                    if let Ok(mut r) = running_done.lock() {
                        r.remove(&req.task_id);
                    }
                    drop(_permit);
                    // A slot freed: the gateway hands this node's queued
                    // tasks back on the same subject a start announces on.
                    let _ = nats_done
                        .publish(crate::tasks::ready_subject(&node_done), serde_json::to_vec(&json!({"node": node_done, "slot_freed": true})).unwrap_or_default().into())
                        .await;
                });
            }
        });
    }
    // Announce: the gateway hands back this node's checkpointed tasks.
    let _ = nats.publish(crate::tasks::ready_subject(&node), serde_json::to_vec(&json!({"node": node})).unwrap_or_default().into()).await;

    let mut stopping = false;
    loop {
        let msg = tokio::select! {
            _ = stop.changed() => { stopping = true; break }
            m = turns.next() => match m { Some(m) => m, None => break },
        };
        let req: coordinator::TurnRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "harness: unreadable turn request");
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Full: say busy (a turn cannot wait, so the gateway runs it
            // itself, and its log says busy rather than dead).
            tracing::info!(conversation = %req.conversation_id, "harness: at capacity; not taking this turn (busy)");
            if let Some(reply) = msg.reply.clone() {
                let _ = nats.publish(reply, serde_json::to_vec(&json!({"ack": false, "busy": true, "node": node})).unwrap_or_default().into()).await;
            }
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
                    // A CLI killed before its first model call ran no tool:
                    // the gateway may run the turn itself (i233). Said on
                    // the event; an older gateway ignores the field and
                    // forwards the error as before.
                    let retry_safe = e.downcast_ref::<crate::harness::driver::NeverReachedTheModel>().is_some();
                    tracing::error!(error = %e, conversation = %req.conversation_id, retry_safe, "harness: turn failed");
                    let _ = sink.send_event("error", json!({"text": format!("{e}"), "retry_safe": retry_safe})).await;
                }
            }
        });
    }
    if !stopping {
        return Err(anyhow!("harness: the turn subscription ended"));
    }
    // Drain: nothing new is taken (the subscriptions are dropped here and
    // in the task loop), what is held may finish within the bound, then exit
    // so the service manager's restart brings the new kind up.
    drop(turns);
    let capacity = max_turns.max(1) as u32;
    let held = capacity.saturating_sub(limit.available_permits() as u32);
    tracing::info!(held, bound_secs = drain.as_secs(), "harness: draining");
    match tokio::time::timeout(drain, limit.clone().acquire_many_owned(capacity)).await {
        Ok(Ok(_)) => tracing::info!("harness: drained; exiting"),
        Ok(Err(e)) => tracing::warn!(error = %e, "harness: drain wait failed; exiting"),
        Err(_) => {
            let still = capacity.saturating_sub(limit.available_permits() as u32);
            tracing::warn!(still, bound_secs = drain.as_secs(), "harness: drain bound reached with work still running; exiting");
        }
    }
    Ok(())
}

/// Which loop this harness runs, and where that came from.
///
/// `NOO_HARNESS_KIND` is NOT in the harness's env file (the template omits
/// it on purpose), so: the variable when set (dev and tests), else the
/// node agent's own answer — `GET {agent}/harness/placement` on the same
/// loopback proxy the model calls go to, through [`crate::node_link`].
///
/// - a 200 naming a placed kind: that kind;
/// - a 404 (an agent with no such route), `placed: false` or a placement
///   naming no kind: `noo` — nothing foreign is placed, so our loop is right;
/// - anything else (unreachable, 401/403, 5xx, a body that does not parse):
///   asked again after each of `retry`, then an `Err` — the caller exits
///   rather than guess, because `noo` under a foreign placement would run
///   the wrong loop silently.
///
/// A model endpoint that is not a node agent has no placement to read:
/// `noo` (dev setups against a bare model server).
async fn resolve_kind(
    env_kind: Option<String>,
    model_url: &str,
    client: &reqwest::Client,
    retry: &[Duration],
) -> Result<(String, &'static str)> {
    if let Some(k) = env_kind.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        return Ok((k, "env"));
    }
    if !coordinator::is_node_agent_url(model_url) {
        tracing::warn!(endpoint = %model_url, "harness: the model endpoint is not a node agent; no placement to read, running kind noo");
        return Ok(("noo".into(), "default"));
    }
    ask_agent_kind(client, model_url, retry).await
}

/// Ask the agent at `agent_url` for the placed kind, again after each of
/// `retry` while it does not answer (see [`resolve_kind`]).
async fn ask_agent_kind(client: &reqwest::Client, agent_url: &str, retry: &[Duration]) -> Result<(String, &'static str)> {
    let mut delays = retry.iter();
    loop {
        match placement_kind(client, agent_url).await {
            Ok(Some(k)) => return Ok((k, "agent")),
            Ok(None) => return Ok(("noo".into(), "default")),
            Err(e) => match delays.next() {
                Some(d) => {
                    tracing::warn!(error = %e, retry_in_ms = d.as_millis() as u64, "harness: could not read the placement from the node agent; asking again");
                    tokio::time::sleep(*d).await;
                }
                None => return Err(e),
            },
        }
    }
}

/// The pauses between asks before the harness gives up on learning its
/// kind: about 15 s in all, then the service manager's restart takes over.
const KIND_RETRY_DELAYS: &[Duration] = &[Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4), Duration::from_secs(8)];

/// The refusal a harness exits with when the agent never answered.
fn refusal_message(cause: &anyhow::Error) -> String {
    format!("harness: cannot learn this node's harness kind from its agent: {cause:#}; refusing to guess")
}

/// `GET {base of agent_url}/harness/placement` → the placed kind. `Ok(None)`
/// = the agent answered that nothing (or nothing with a kind) is placed.
async fn placement_kind(client: &reqwest::Client, agent_url: &str) -> Result<Option<String>> {
    Ok(fetch_placement(client, agent_url).await?.as_ref().and_then(kind_from_placement))
}

/// Reasoning control for this harness: `NOO_HARNESS_THINKING` from the
/// process env when set (dev, tests), else from the harness placement's env
/// (`noo cluster place <node> harness <model> --env NOO_HARNESS_THINKING=off`,
/// which the node agent serves at `/harness/placement` with its other
/// non-secret keys), else `auto`. An unreachable agent is `auto` with the
/// source `unreachable`, which the minute re-read ignores (it keeps what it
/// had rather than flip a node's setting on a missed answer).
///
/// Between the placement's env and `auto` sits the node's harness profile
/// (`profile.thinking`, source `profile`).
#[cfg_attr(not(test), allow(dead_code))]
async fn resolve_thinking(
    env_val: Option<String>,
    model_url: &str,
    client: &reqwest::Client,
) -> (coordinator::thinking::ThinkingMode, &'static str) {
    if env_val.as_deref().is_some_and(|v| !v.trim().is_empty()) {
        return thinking_after_read(env_val, &Ok(None));
    }
    thinking_after_read(env_val, &read_placement(model_url, client).await)
}

/// [`resolve_thinking`] on a placement already read ([`read_placement`]):
/// env > the placement's env > the profile > `auto`; `unreachable` when the
/// read failed and the env did not decide.
fn thinking_after_read(
    env_val: Option<String>,
    placement: &Result<Option<serde_json::Value>>,
) -> (coordinator::thinking::ThinkingMode, &'static str) {
    use crate::coordinator::thinking::{parse_thinking_mode, ThinkingMode};
    if let Some(v) = env_val.filter(|v| !v.trim().is_empty()) {
        return (parse_thinking_mode(Some(&v)), "env");
    }
    match placement {
        Ok(Some(p)) => match thinking_from_placement(p) {
            Some(v) => (parse_thinking_mode(Some(&v)), "placement"),
            None => match crate::harness::profile::HarnessProfile::from_placement(p).and_then(|pr| pr.thinking) {
                Some(m) => (m, "profile"),
                None => (ThinkingMode::Auto, "default"),
            },
        },
        Ok(None) => (ThinkingMode::Auto, "default"),
        Err(e) => {
            tracing::warn!(error = %e, "harness: could not read the placement for NOO_HARNESS_THINKING");
            (ThinkingMode::Auto, "unreachable")
        }
    }
}

/// The placement answer of this harness's own agent: `Ok(None)` when the
/// model endpoint is not a node agent (nothing to read) or the agent has no
/// such route; `Err` when it could not be asked.
async fn read_placement(model_url: &str, client: &reqwest::Client) -> Result<Option<serde_json::Value>> {
    if !coordinator::is_node_agent_url(model_url) {
        return Ok(None);
    }
    fetch_placement(client, model_url).await
}

/// The harness profile in a placement read, if the agent sent one.
fn profile_of(placement: &Result<Option<serde_json::Value>>) -> Option<crate::harness::profile::HarnessProfile> {
    placement.as_ref().ok().and_then(|p| p.as_ref()).and_then(crate::harness::profile::HarnessProfile::from_placement)
}

/// `model_context` in a placement read, if the agent sent one.
fn model_context_of(placement: &Result<Option<serde_json::Value>>) -> Option<u64> {
    placement.as_ref().ok().and_then(|p| p.as_ref()).and_then(crate::harness::profile::model_context_of)
}

/// `env.NOO_HARNESS_THINKING` of a placement answer, when set.
fn thinking_from_placement(v: &serde_json::Value) -> Option<String> {
    placement_env(v, coordinator::thinking::THINKING_ENV)
}

/// `env.<key>` of a placement answer, when set and not blank.
fn placement_env(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get("env").and_then(|e| e.get(key)).and_then(|t| t.as_str()).map(str::trim).filter(|t| !t.is_empty()).map(str::to_string)
}

/// `GET {base of agent_url}/harness/placement`. `Ok(None)` = the agent has
/// no such route (404, an older agent).
pub(crate) async fn fetch_placement(client: &reqwest::Client, agent_url: &str) -> Result<Option<serde_json::Value>> {
    let mut u = reqwest::Url::parse(agent_url.trim())?;
    u.set_path("");
    u.set_query(None);
    let req = crate::node_link::NodeLink::for_base(u.as_str().trim_end_matches('/'))
        .request_on(client, reqwest::Method::GET, "/harness/placement")
        .timeout(Duration::from_secs(10));
    let resp = req.send().await.map_err(|e| anyhow!("GET /harness/placement: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::warn!("harness: the node agent has no harness placement route (404); running kind noo");
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("GET /harness/placement answered HTTP {}", resp.status().as_u16()));
    }
    let body = resp.json::<serde_json::Value>().await.map_err(|e| anyhow!("GET /harness/placement: the body does not parse: {e}"))?;
    Ok(Some(body))
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

    #[test]
    fn the_drain_bound_is_whole_seconds_within_an_hour_else_the_default() {
        fn with(v: Option<&'static str>) -> Duration {
            drain_bound(&move |_: &str| v.map(str::to_string))
        }
        assert_eq!(with(None), Duration::from_secs(DEFAULT_DRAIN_SECS));
        assert_eq!(with(Some("45")), Duration::from_secs(45));
        for bad in ["0", "3601", "soon", ""] {
            assert_eq!(with(Some(bad)), Duration::from_secs(DEFAULT_DRAIN_SECS), "{bad:?}");
        }
    }

    /// Both loops that take work select on the stop signal, and the drain
    /// waits for every permit before run() returns Ok: a stop never kills a
    /// turn or task that could have finished (i256).
    #[test]
    fn a_stop_drains_before_the_harness_exits() {
        let code = include_str!("harness_main.rs");
        let run = &code[code.find("pub async fn run()").unwrap()..code.find("/// Which loop this harness runs").unwrap()];
        assert_eq!(run.matches("stop_t.changed()").count(), 1, "the task loop selects on the stop");
        assert_eq!(run.matches("_ = stop.changed() => { stopping = true; break }").count(), 1, "the turn loop selects on the stop");
        let drain_wait = run.find("acquire_many_owned(capacity)").expect("the drain waits for every permit");
        assert!(run.find("harness: draining").unwrap() < drain_wait && drain_wait < run.rfind("Ok(())").unwrap());
        assert!(run.find("the turn subscription ended").unwrap() < drain_wait, "a dead subscription is still an error, not a drain");
    }

    /// noomesh-internal i176: at capacity the harness says busy (a reply,
    /// not silence); a task already here is acknowledged, not started
    /// twice; a finished task re-announces ready so the gateway hands the
    /// node's queued tasks back.
    #[test]
    fn a_busy_harness_says_so_and_never_runs_a_task_twice() {
        let src = include_str!("harness_main.rs").split("fn a_busy_harness_says_so_and_never_runs_a_task_twice").next().unwrap();
        let tasks = src.split("queue_subscribe(crate::tasks::task_subject(&node)").nth(1).unwrap();
        // The task loop now selects on the stop signal (i256); its body
        // starts after the select that yields `msg`.
        let loop_body = tasks.split("m = tasks.next() => match m").nth(1).expect("the task loop takes from the subscription");
        let dedupe = loop_body.find("\"already\": true").expect("an already-running task is acknowledged as taken");
        let permit = loop_body.find("try_acquire_owned()").expect("the permit");
        assert!(dedupe < permit, "the dedupe runs before a permit is taken");
        let busy = loop_body.find("\"busy\": true").expect("at capacity: a busy reply");
        assert!(permit < busy && busy < loop_body.find("\"ack\": true, \"node\"").unwrap(), "busy is answered on the refusal path");
        assert!(loop_body.contains("\"slot_freed\": true"), "a finished task re-announces ready");
        assert!(loop_body.find("r.remove(&req.task_id)").unwrap() < loop_body.find("\"slot_freed\": true").unwrap(), "the id leaves the running set before the re-announce");
        let turns = src.split("harness: at capacity; not taking this turn").nth(1).unwrap();
        assert!(turns[..300].contains("\"busy\": true"), "a turn at capacity is answered busy too");
    }


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
        assert_eq!(resolve_kind(Some(" copilot ".into()), "http://127.0.0.1:9/v1", &c, &[]).await.unwrap(), ("copilot".into(), "env"));
        // A model endpoint that is not a node agent has no placement to read.
        assert_eq!(resolve_kind(Some("  ".into()), "http://vllm:8000/v1", &c, &[]).await.unwrap(), ("noo".into(), "default"));

        let placed = fake_agent(200, json!({"kind": "claude-code", "env": {"X": "1"}, "desired_state": "running", "placed": true})).await;
        assert_eq!(placement_kind(&c, &placed).await.unwrap().as_deref(), Some("claude-code"));
        let unplaced = fake_agent(200, json!({"kind": "copilot", "env": {}, "desired_state": "stopped", "placed": false})).await;
        assert_eq!(placement_kind(&c, &unplaced).await.unwrap(), None);
        let old_agent = fake_agent(404, json!({"error": "not found"})).await;
        assert_eq!(placement_kind(&c, &old_agent).await.unwrap(), None);
        let broken = fake_agent(500, json!({})).await;
        assert!(placement_kind(&c, &broken).await.is_err());
        assert!(placement_kind(&c, "http://127.0.0.1:9/v1").await.is_err(), "unreachable is an error");
        assert_eq!(kind_from_placement(&json!({"placed": true, "kind": ""})), None);
        assert_eq!(kind_from_placement(&json!({"kind": "copilot"})), None, "no placed flag is not placed");
    }

    /// The node agent's port is what makes a URL "a node agent" to
    /// `is_node_agent_url`; a fake agent on a random port is not one, so
    /// these drive `resolve_kind`'s ask loop (`ask_agent_kind`) directly.
    #[tokio::test]
    async fn only_nothing_placed_is_noo_and_an_unanswered_ask_is_a_refusal() {
        let c = reqwest::Client::new();
        let quick = [Duration::from_millis(1), Duration::from_millis(1)];
        let placed = fake_agent(200, json!({"kind": "copilot", "env": {}, "desired_state": "running", "placed": true})).await;
        assert_eq!(ask_agent_kind(&c, &placed, &quick).await.unwrap(), ("copilot".into(), "agent"));
        // Legitimately nothing placed: our loop.
        let unplaced = fake_agent(200, json!({"placed": false})).await;
        assert_eq!(ask_agent_kind(&c, &unplaced, &quick).await.unwrap(), ("noo".into(), "default"));
        let old_agent = fake_agent(404, json!({})).await;
        assert_eq!(ask_agent_kind(&c, &old_agent, &quick).await.unwrap(), ("noo".into(), "default"));
        // Asked and not answered: never a guess.
        for (status, body) in [(403, json!({"error": "no client certificate"})), (401, json!({})), (503, json!({}))] {
            let a = fake_agent(status, body).await;
            let e = ask_agent_kind(&c, &a, &quick).await.unwrap_err();
            assert!(e.to_string().contains(&format!("HTTP {status}")), "{e}");
        }
        let garbled = fake_text_agent("not json").await;
        assert!(ask_agent_kind(&c, &garbled, &quick).await.unwrap_err().to_string().contains("does not parse"));
        let e = ask_agent_kind(&c, "http://127.0.0.1:9/v1", &quick).await.unwrap_err();
        let msg = refusal_message(&e);
        assert!(msg.starts_with("harness: cannot learn this node's harness kind from its agent: GET /harness/placement")
            && msg.ends_with("; refusing to guess"), "{msg}");
        // The retries are taken: a flaky agent that answers on the third ask wins.
        let flaky = flaky_agent(2, json!({"kind": "codex", "placed": true})).await;
        assert_eq!(ask_agent_kind(&c, &flaky, &quick).await.unwrap(), ("codex".into(), "agent"));
        let flakier = flaky_agent(3, json!({"kind": "codex", "placed": true})).await;
        assert!(ask_agent_kind(&c, &flakier, &quick).await.is_err(), "three failures outlast two retries");
    }

    async fn fake_text_agent(body: &'static str) -> String {
        use axum::{routing::get, Router};
        let app = Router::new().route("/harness/placement", get(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/v1")
    }

    /// Answers 503 `fails` times, then `body`.
    async fn flaky_agent(fails: usize, body: serde_json::Value) -> String {
        use axum::{routing::get, Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let n = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/harness/placement",
            get(move || {
                let body = body.clone();
                let n = n.clone();
                async move {
                    if n.fetch_add(1, Ordering::SeqCst) < fails {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({})))
                    } else {
                        (axum::http::StatusCode::OK, Json(body))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/v1")
    }

    #[tokio::test]
    async fn thinking_comes_from_env_then_the_placement_then_auto() {
        use crate::coordinator::thinking::ThinkingMode;
        let c = reqwest::Client::new();
        assert_eq!(resolve_thinking(Some("off".into()), "http://127.0.0.1:9/v1", &c).await, (ThinkingMode::Off, "env"));
        assert_eq!(resolve_thinking(None, "http://vllm:8000/v1", &c).await, (ThinkingMode::Auto, "default"));
        let off = fake_agent(200, json!({"kind": "noo", "env": {"NOO_HARNESS_THINKING": "off"}, "desired_state": "running", "placed": true})).await;
        assert_eq!(placement_kind(&c, &off).await.unwrap().as_deref(), Some("noo"));
        let p = fetch_placement(&c, &off).await.unwrap().expect("a placement");
        assert_eq!(thinking_from_placement(&p).as_deref(), Some("off"));
        assert_eq!(thinking_from_placement(&json!({"env": {}})), None);
        assert_eq!(thinking_from_placement(&json!({"env": {"NOO_HARNESS_THINKING": "  "}})), None);
        // The fake agent's URL is not on the agent port, so resolve_thinking
        // itself stops at "not a node agent"; the env wins over everything.
        assert_eq!(resolve_thinking(Some(" on ".into()), &off, &c).await, (ThinkingMode::On, "env"));
    }

    /// PINNED (the harness profile contract): thinking is the process env,
    /// else the placement's env, else the profile, else auto; an unread
    /// placement is `unreachable` (the minute re-read keeps what it had).
    #[test]
    fn thinking_is_env_then_placement_env_then_profile_then_auto() {
        use crate::coordinator::thinking::ThinkingMode;
        let both = Ok(Some(json!({"placed": true, "kind": "noo", "env": {"NOO_HARNESS_THINKING": "on"}, "profile": {"thinking": "off"}})));
        let profile_only = Ok(Some(json!({"placed": true, "kind": "noo", "env": {}, "profile": {"thinking": "off"}})));
        let neither = Ok(Some(json!({"placed": true, "kind": "noo", "env": {}, "profile": {"thinking": "sometimes"}})));
        let old_agent = Ok(Some(json!({"placed": true, "kind": "noo", "env": {}})));
        assert_eq!(thinking_after_read(Some("auto".into()), &both), (ThinkingMode::Auto, "env"));
        assert_eq!(thinking_after_read(Some(" ".into()), &both), (ThinkingMode::On, "placement"));
        assert_eq!(thinking_after_read(None, &profile_only), (ThinkingMode::Off, "profile"));
        assert_eq!(thinking_after_read(None, &neither), (ThinkingMode::Auto, "default"), "an unknown profile word is no value");
        assert_eq!(thinking_after_read(None, &old_agent), (ThinkingMode::Auto, "default"));
        assert_eq!(thinking_after_read(None, &Ok(None)), (ThinkingMode::Auto, "default"));
        assert_eq!(thinking_after_read(None, &Err(anyhow!("down"))), (ThinkingMode::Auto, "unreachable"));
        assert_eq!(thinking_after_read(Some("off".into()), &Err(anyhow!("down"))), (ThinkingMode::Off, "env"), "the env needs no agent");
    }

    /// The profile rides the placement answer the harness already reads.
    #[tokio::test]
    async fn the_profile_comes_from_the_placement_answer() {
        use crate::harness::profile::{ClaudePrompt, HarnessProfile};
        let c = reqwest::Client::new();
        let body = json!({"kind": "claude-code", "env": {"NOO_BACKEND_STREAM_IDLE_SECS": "450"}, "desired_state": "running", "placed": true,
                          "profile": {"tier": 2, "stream_idle_secs": 300, "thinking": "off", "claude_prompt": "slim", "sources": {}, "bench": null}});
        let agent = fake_agent(200, body).await;
        let read = fetch_placement(&c, &agent).await;
        let p: HarnessProfile = profile_of(&read).expect("a profile");
        assert_eq!((p.tier, p.stream_idle_secs, p.claude_prompt), (Some(2), Some(300), Some(ClaudePrompt::Slim)));
        let placed = read.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(placement_env(placed, crate::tls::STREAM_IDLE_ENV).as_deref(), Some("450"));
        assert_eq!(profile_of(&Ok(Some(json!({"placed": true})))), None, "an older agent sends none");
        assert_eq!(profile_of(&Err(anyhow!("down"))), None);
        // A model endpoint that is not a node agent has nothing to read.
        assert!(read_placement("http://vllm:8000/v1", &c).await.unwrap().is_none());
    }

    /// The profile is read, and the stream idle bound fixed, BEFORE the
    /// driver (whose translator builds the stream client) and before any
    /// turn is taken; the slim switch is set on the driver it built.
    #[test]
    fn the_profile_is_applied_before_any_stream_client_or_turn() {
        let code = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/harness_main.rs")).unwrap();
        let run = &code[code.find("pub async fn run()").expect("run()")..code.find("async fn run_turn").expect("run_turn")];
        let read = run.find("read_placement(&model_url, &client).await").expect("run() reads the placement");
        let idle = run.find("tls::set_stream_idle_override(").expect("run() applies the profile's stream idle");
        let driver = run.find("DriverCtx::from_env(").expect("driver");
        let slim = run.find("ctx.prompt.set(variant)").expect("run() sets the launch variant");
        let subs = run.find("queue_subscribe(").expect("subscribes");
        assert!(read < idle && idle < driver && driver < slim && slim < subs, "read, idle, driver, variant, then turns");
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
