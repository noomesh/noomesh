// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Mesh Gateway — Rust implementation
//!
//! The gateway. The Python gateway this replaced was deleted (see below);
//! this binary speaks:
//! - HTTP API (port 8080)
//! - WebSocket protocol (chat, collab)
//! - NATS subjects (mesh gossip, worker delegation, events)
//! - Postgres schema (conversations, heartbeat tasks)
//! - Redis keys (session cache, rate limiting)
//!
//! There is no longer a Python gateway to switch to: `GATEWAY_ENGINE` selected
//! between two implementations, and the other one was deleted.
//! This binary IS the gateway.
//!
//! ## Lint gate
//!
//! CI runs `cargo clippy --all-targets -- -D warnings` on this crate. It was
//! the last crate without one, which is how `idle_scaledown` shipped a
//! `node`/`node_id` mismatch and how `verify_cluster_hmac` — a weaker
//! duplicate of the live cluster-token verifier, with no replay window — sat
//! here unreferenced for months.
//!
//! The allows below are the pre-existing debt the gate would otherwise trip
//! on, declared once here rather than sprinkled as local attributes so the
//! list is auditable and can be burned down.
//!
//! All but one are STYLE lints — no correctness lint is on this list. The
//! exception is `dead_code`, and it is the one that CAN hide a defect, so it
//! is the one to remove first. It is here because ~45 pre-existing items need
//! individual judgement rather than a blanket delete: the `config.rs` structs
//! whose fields are "never read" are a serde SCHEMA — dropping a field
//! changes what `noomesh.yaml` parses — while others are genuinely orphaned
//! helpers. the design carries the triaged list; when it is empty this line
//! comes off and the gate starts catching new rot.
// The channel turn wraps its future in the principal and shared-room scopes;
// the in-process task runner nests those again, and the layout of that async
// block passes the default query depth (128).
#![recursion_limit = "256"]

#![allow(unknown_lints)]
#![allow(dead_code)]
// Doc-comment formatting across ~55 sites (list indentation and lazy
// continuation). Cosmetic, and reflowing them all would bury the real diff.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
// 19 sites, nearly all `Vec<(String, String, Option<i64>, …)>` sqlx row
// tuples. A type alias per query would name a shape used exactly once.
#![allow(clippy::type_complexity)]
// 6 sites at 8-11 args, all internal helpers threading request context. The
// fix is a context struct, which is a refactor, not a lint fix.
#![allow(clippy::too_many_arguments)]
// `AppError` is a large enum by design (it carries response bodies); boxing
// it changes every `?` in the crate.
#![allow(clippy::result_large_err)]
// One site in the KV scan of `coordinator/backend.rs`, where the nesting
// separates "read the key" from "parse the value" for a reason.
#![allow(clippy::collapsible_match)]

mod auth;
mod birth_proof;
mod bus;
mod bus_principal;
mod harness_kinds;
mod harness_profile;
mod harness;
mod harness_main;
mod tasks;
mod task_budget;
mod task_context;
mod task_events;
mod text;
mod auth_refresh;
mod cache;
mod cluster_token_v2;
mod cert_expiry;
mod config;
mod coordinator;
mod config_mount;
mod dependency_watchdog;
mod node_agent_auth;
mod node_link;
mod node_rpc;
mod maintenance;
mod node_reachability;
mod model_presence;
mod placement_fit;
mod role_capability;
mod backup_completion;
mod placement_stuck;
mod self_node;
mod node_name_claim;
mod redact;
mod egress;
mod dlq_drain;
mod drive;
mod embedding_client;
mod embedding_spaces;
mod google_auth;
mod host_daemon;
mod mcp_external;
mod mcp_local;
mod mcp_user_tasks;
mod mcp_bridge;
mod mcp_protocol;
mod confine;
mod entity_cleanup_task;
mod task_guard;
mod graph_prune;
mod addon_auth;
mod alert_digest;
mod addons;
mod addon_proxy;
mod addon_delegation;
mod addon_registry;
mod google_drive;
mod agent_activities;
mod agent_meta_loop;
mod audit_partition;
mod audit_integrity;
mod audit_chain;
mod audit_head_export;
mod audit_context;
mod audit_spool;
mod autonomy_audit;
mod autonomy_evaluators;
mod held_column;
mod autonomy_loop;
mod cluster_manager;
mod scheduler_candidates;
mod nats_credentials;
mod scheduler_completions;
mod scheduler_engine;
mod scheduler_job;
mod scheduler_slots;
mod heartbeat_actions;
mod heartbeat_loop;
mod research_pipeline;
mod heartbeat_reconcile;
mod agent_crypto;
mod agent_messages;
mod mesh_migrate;
mod entitlement;
mod jwks;
mod mcp_session;
mod role_provision;
mod system_provision;
mod startup_tasks;
mod repo;
mod ingest_loop;
mod local_files;
mod job_types;
mod recall_archive_loop;
// llm_client archived 2026-04-30 — was a standalone OpenAI SSE streaming
// client built before the coordinator inlined its own streaming path.
// Zero callers, all functionality replaced by coordinator.rs::run_streaming.
// Source preserved at archive/rust-gateway-deprecated/llm_client.rs in
// case the dedicated streaming-client design is wanted later.
mod legacy_lanes;
mod addon_hmac_refusal;
mod controller_hmac_refusal;
mod operator_auth;
mod log_gate;
mod loop_health;
mod ops;
mod erasure_archive;
mod ported;
mod agent_roles;
mod workflows;
mod llm_rerank;
mod prompt_skills;
mod channels;
mod google_chat_pubsub;
mod managed_loop;
mod memory;
mod mesh;
mod metrics;
mod middleware;
mod node_tier;
mod operator_alert;
mod posture;
mod preflight;
pub mod paths;
mod routes;
mod security;
mod settings;
mod service_keys;
mod password_policy;
mod session_floor;
mod session;
mod state;
mod stt_client;
mod temporal_graph;
mod tls;
mod node_identity;
mod tools;
mod web_search;
mod tts_client;
mod usage;
mod verify;
mod websocket;
mod worker_client;
mod worker_delegation;
mod ws_agent;
mod ws_collab;
mod ws_coordinator;

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};





/// Probe `/health` and exit 0 (healthy) or 1 (not), for Docker HEALTHCHECK.
///
/// This exists because the image no longer has a Python interpreter to run
/// the old `HEALTHCHECK CMD python -c "import urllib.request…"` — and the
/// shell-less hardened base has no curl or wget either. The binary is the
/// only executable in the image, so the probe has to live here.
///
/// The scheme is https, unconditionally: the server has exactly one
/// listener, the TLS acceptor (`tls::require_server_material` refuses to
/// start without it), so there is no plain listener this probe could ever
/// be right to dial. Until 2026-09-29 the scheme followed the same
/// predicate the server used to choose between TLS and plain; that
/// predicate is gone with the plain branch.
async fn health_probe() -> ! {
    let url = "https://localhost:8080/health".to_string();

    // Verify. This probe decides whether Docker calls the
    // gateway alive, and with verification off it could not tell the
    // gateway from anything else that binds :8080 in the namespace. The
    // gateway's leaf is cluster-CA signed and names `localhost`, so the
    // anchor is already on disk at NOO_TLS_CA — nothing had to be shipped.
    //
    // A configured-but-unusable NOO_TLS_CA exits non-zero with a named
    // reason, rather than reporting healthy against an unidentified peer:
    // "unhealthy because I cannot establish who answered" is the honest
    // verdict, and the message says which file to fix.
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
    match tls::cluster_ca_certificate() {
        Ok(Some(cert)) => builder = builder.add_root_certificate(cert),
        Ok(None) => {}
        Err(e) => {
            eprintln!("health: {e}");
            std::process::exit(1);
        }
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("health: client build failed: {e}");
            std::process::exit(1);
        }
    };

    match client.get(&url).send().await {
        // Any 2xx is healthy. /health returns 503 when a hard dependency
        // (Postgres, NATS) is gone — see dependency_watchdog.rs — and that
        // SHOULD mark the container unhealthy, so status is checked rather
        // than just "did the request complete".
        Ok(resp) if resp.status().is_success() => std::process::exit(0),
        Ok(resp) => {
            eprintln!("health: {url} -> HTTP {}", resp.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("health: {url} -> {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Pin the process start for `/metrics`' noo_gateway_start_time_seconds
    // the window the legacy-lane counters are counted over.
    let _ = legacy_lanes::process_start_unix();
    // Install rustls crypto provider BEFORE any TLS connections
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // `--health` short-circuits everything below. It must not load config,
    // touch Postgres, or run startup_tasks: the HEALTHCHECK fires every 30s
    // against an already-running gateway, and a probe with side effects
    // would be a second process racing the real one over PKI staging and
    // migrations.
    if std::env::args().nth(1).as_deref() == Some("--health") {
        health_probe().await;
    }

    // `harness probe`: one operator-run check of a vendor CLI against the
    // node's model or a mock. Its report is stdout, so its logs go to
    // stderr (warnings only unless RUST_LOG says otherwise); bare `harness`
    // is untouched below.
    {
        let argv: Vec<String> = std::env::args().collect();
        if argv.get(1).map(String::as_str) == Some("harness") && argv.get(2).map(String::as_str) == Some("probe") {
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .init();
            std::process::exit(harness::probe::main(&argv[3..]).await);
        }
    }

    // Structured logging (matches Python structlog output)
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "noo_gateway=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // `harness`: the loop on a node. No config file,
    // no database, no listener — it takes turns from the bus and speaks to
    // the gateway's rail. Everything below this line is the gateway's
    // life, none of which a harness has.
    if std::env::args().nth(1).as_deref() == Some("harness") {
        return harness_main::run().await;
    }

    // Container startup tasks, ported from docker/entrypoint.py.
    //
    // AFTER tracing init so their logs are actually emitted — an earlier cut
    // ran this first and every info! inside it went to a subscriber that did
    // not exist yet. Still BEFORE AppState/TLS: stage_pki publishes NOO_TLS_*
    // into the environment, which tls.rs and the Postgres TLS probe read, and
    // before any thread is spawned.
    startup_tasks::run_all();

    tracing::info!("Mesh Gateway (Rust) starting");

    // Refuse to start without TLS material — HERE, after stage_pki has
    // published NOO_TLS_* and before migrations, AppState or any loop: the
    // gateway has no plaintext listener (below), so a process that cannot
    // bind TLS must not touch the database first and die later.
    if let Err(e) = tls::require_server_material() {
        tracing::error!("{e}");
        return Err(e);
    }

    // Launcher sentinel (onboard audit item 11). The sanctioned launchers
    // (noo stack start/restart/rebuild via lib-config.sh, and the onboard
    // wizard's compose wrapper) export NOO_LAUNCHED=1, which compose passes
    // through. A container recreated by a BARE `docker compose up` lacks it
    // — and lacks every other launcher-exported interpolation var, i.e. its
    // secrets were baked EMPTY. The auth layer still fails closed on an
    // empty JWT secret; this warning exists so the diagnosis takes seconds
    // instead of the crash-loop session it cost on 2026-08-06. Warn-only:
    // worker-node compose paths never start the gateway, but failing hard
    // here would still be wrong for images run outside compose entirely.
    if std::env::var("NOO_LAUNCHED").unwrap_or_default().is_empty() {
        tracing::warn!(
            "NOO_LAUNCHED is not set — this container was recreated WITHOUT the \
             launcher (bare `docker compose up`?). Launcher-injected env (secrets, \
             compose_env) may be EMPTY in this process. Recreate via 'noo stack start'."
        );
    }

    // Load config (same noomesh.yaml as Python)
    let config = config::load_config()?;

    // MIGRATE FIRST — before AppState, before preflight, before posture,
    // before anything that reads a table or connects as an app role.
    //
    // Before APPSTATE specifically: the broker inside the migrator CREATES
    // noo_app, the role AppState's runtime pool connects as. With this call
    // after AppState (its position until 2026-08-06), a truly-fresh database
    // crash-looped on noo_app auth and the migration that would have created
    // the role never ran — invisible on every install where the role already
    // existed, i.e. all of them until the first virgin data dir.
    //
    // Under NOO_MESH_MIGRATOR=alembic this is a no-op (entrypoint.py
    // already migrated; the informational report runs after AppState below).
    // Under `sqlx` it APPLIES on its own privileged connection.
    //
    // The earlier lesson stands too: with this after preflight, a fresh
    // install aborted on preflight.critical_fail check=baseline_tables
    // having never run the migration that creates them.
    //
    // Fatal on failure: serving requests against a schema we could not
    // migrate is worse than not starting, and it is the one failure here that
    // corrupts rather than merely interrupts.
    if let Err(e) = mesh_migrate::run().await {
        tracing::error!(error = %e, "mesh migration failed — refusing to start");
        std::process::exit(1);
    }

    // Initialize shared state (Postgres, NATS, mesh)
    let state = state::AppState::new(&config).await?;
    let state = Arc::new(state);
    let _ = state.self_handle.set(Arc::downgrade(&state));

    // Which node agents admit this gateway's leaf with no bearer, from the node records — before any loop dials an agent, so a
    // restart does not resend the legacy bearer until every node beats.
    crate::node_agent_auth::seed(&state).await;

    // Read-only migration report for the alembic engine (needs the pool).
    mesh_migrate::report_alembic(&state.db).await;

    // Apply DB-authoritative security posture (overrides .env for the app-tier
    // gates) before the server accepts traffic, so read-once gate accessors
    // capture the DB value. Operator-managed; restart-to-apply.
    crate::posture::apply_security_posture(&state.db).await;

    // Mint this boot's add-on caller credential. Before the router is built,
    // so the first proxied request already carries it, and after the pool is
    // open because the credential IS a database row.
    crate::addon_auth::init(&state.db).await;

    // Operator decisions on runtime prompt skills (promoted / rejected). Until
    // loaded every runtime skill is framed as data, so a failure here demotes
    // promoted skills, loudly, and never the other way round.
    if let Err(e) = crate::routes::settings::refresh_skill_decisions(&state).await {
        tracing::error!(error = %e, "prompt_skill_decisions_unavailable: promoted skills are framed as data until this loads (is migration 096 applied?)");
    }

    // A retired gate key left in noomesh.yaml does not serve either.
    // Checked AFTER the posture pass so the message can be about the yaml
    // alone: by this point posture has already had its say, and anything the
    // yaml says about these keys is guaranteed to be ignored.
    {
        let yaml = state.config_yaml.read().await;
        if let Some(msg) = crate::posture::yaml_gate_refusal(&yaml) {
            tracing::error!("{msg}");
            eprintln!("noo-gateway: {msg}");
            std::process::exit(2);
        }
    }

    // A RETIRED compatibility bridge still held open — in the posture table
    // or the env — does not serve either: its code path is gone, and an
    // operator who believes it is open must hear that it is not. AFTER the
    // posture pass, because that pass is what reads the table.
    if let Some(msg) = crate::posture::retired_bridge_refusal() {
        tracing::error!("{msg}");
        eprintln!("noo-gateway: {msg}");
        std::process::exit(2);
    }

    // A gateway with no controller secret does not serve: in that state
    // every node's credential would be an operator's.
    if let Some(msg) = crate::auth::boot_refusal() {
        tracing::error!("{msg}");
        eprintln!("noo-gateway: {msg}");
        std::process::exit(2);
    }

    // A gateway with no audit key does not serve either: every audit row
    // would be refused, i.e. "audit logging on by default" would be false.
    if let Some(msg) = crate::audit_integrity::boot_refusal() {
        tracing::error!("{msg}");
        eprintln!("noo-gateway: {msg}");
        std::process::exit(2);
    }

    // A NOO_TRUSTED_PROXIES entry covering this gateway's own attachment
    // point does not serve either: on a published port every remote
    // client arrives from the docker bridge, so trusting the bridge hands the
    // client its own rate-limit key and its own audit IP. There is no partly
    // working version of that, so it is a refusal and not a warning.
    if let Some(msg) = crate::middleware::trusted_proxy_refusal() {
        tracing::error!("{msg}");
        eprintln!("noo-gateway: {msg}");
        std::process::exit(2);
    }

    // Bus isolation needs no boot decision here any more: the shared `>`/`>`
    // bus credential and its posture bridge were retired, so
    // `nats_credentials::resolve` either returned the gateway's OWN pair or
    // refused at connect time.

    // Keep the behavioral-flag (noo_settings) override cache warm so admin UI
    // toggles take effect within ~15s (no restart) for Rust-read flags.
    crate::settings::spawn_refresh(state.db.clone());
    // Embedding spaces (i145): seed `knowledge` on an empty table, then keep
    // the space cache warm the same way.
    crate::embedding_spaces::spawn_refresh(state.clone());

    // Re-assert the NATS KV buckets periodically. A NATS server that comes
    // back with a fresh JetStream store (what a container recreate does)
    // leaves `mesh_nodes`/`peer_agents` gone, and every reader treats a
    // missing bucket as "no nodes" — an empty fleet, not an error.
    state::spawn_kv_bucket_watchdog(state.js.clone());
    // agent-to-agent messaging — the stream and its recorder.
    agent_messages::ensure_stream(&state.js).await;
    // The job plane's streams: the worker used to declare them and its grant
    // no longer allows it (see scheduler_engine.rs).
    scheduler_engine::ensure_job_plane_streams(&state.js).await;
    agent_messages::spawn_recorder(state.clone());
    // tasks resume when a harness announces itself, and the
    // controller's own resume at boot.
    tasks::spawn_ready_watcher(state.clone());
    tasks::spawn_stale_sweep(state.clone());
    task_events::spawn_delivery(state.clone());

    // Start gossip mesh (uses interior mutability — safe from Arc)
    //
    // Gossip is how this gateway confirms node liveness: a node present in
    // KV but absent from gossip is reported "unknown". So a gossip
    // subscriber that failed to start once at boot would make the ENTIRE
    // fleet read as unknown, permanently, behind a single WARN line. Retry
    // instead of giving up.
    if let Err(e) = state.gossip.start().await {
        tracing::error!(error = %e, "Gossip mesh failed to start — retrying in the background");
        let retry_state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                match retry_state.gossip.start().await {
                    Ok(_) => {
                        tracing::info!("Gossip mesh started on retry");
                        break;
                    }
                    Err(e) => tracing::warn!(error = %e, "Gossip mesh retry failed"),
                }
            }
        });
    }

    // Drain noo_nats_dlq — recovers fire-and-forget publishes that exhausted
    // the in-process retry budget. Concurrent-safe via SELECT FOR UPDATE
    // SKIP LOCKED; multiple gateway replicas can run this without contention.
    dlq_drain::spawn(state.clone());

    // Pre-flight health manifest: verify critical deps before serving.
    // Critical-check failures abort startup; optional failures log WARN.
    let report = preflight::run(&state).await;
    // Subject wiring is answered later — the Python worker pool subscribes
    // ~40s after this point (see spawn_subject_verification).
    preflight::spawn_subject_verification(state.clone());
    report.log();
    if !report.critical_failures().is_empty() {
        let names: Vec<&str> = report
            .critical_failures()
            .iter()
            .map(|c| c.name)
            .collect();
        return Err(anyhow::anyhow!(
            "Pre-flight checks failed (critical): {}",
            names.join(", ")
        ));
    }

    // The Python worker pool is NOT started here. It runs as the
    // noo-trellion container, always — see the design.
    //
    // This container used to spawn and supervise it as a child, which meant
    // the gateway image had to carry trellion's entire dependency tree:
    // 2724 MB of nvidia, 1072 MB of torch, 689 MB of triton, in a process
    // that runs no models. Removing the in-process path is what lets the
    // image drop that weight.
    //
    // The trade is explicit: a single-container mesh is no longer a
    // supported shape. If noo-trellion is absent every worker.* delegation
    // degrades per-capability, and the subject verification below warns.
    tracing::info!(
        "worker pool: EXTERNAL (noo-trellion container) — this gateway never \
         spawns Python; if trellion is not running, worker.* delegations \
         degrade per-capability"
    );

    // Background task: evict stale session cache entries every 60s.
    // Immediate first tick — historical behavior (first eviction pass
    // runs right at startup).
    managed_loop::ManagedLoop::new("session_eviction", 60)
        .immediate_first_tick()
        .spawn(state.clone(), |state| async move {
            coordinator::evict_stale_sessions(&state).await;
            Ok(())
        });

    // Background task(s): poll watched_folders + watched_drives, submit
    // new files via NATS worker.rag.ingest. No-ops if both are disabled.
    // (Restores the autonomy ingestion behavior that was lost when the
    // Python AutonomyEngine's monitor loop wasn't ported to Rust —
    // see memory project_rust_port_gap_autonomy_loop.md)
    // Ensure audit partitions exist for current + next month before any
    // audit insert runs. Mirrors gateway/audit_archive.py::ensure_current_and_next
    // (Python lifespan was dead in prod; this restores it).
    audit_partition::ensure_current_and_next(&state).await;
    // Audit rows the database could not take while it was away are held
    // and written back as soon as it answers (audit_spool).
    audit_spool::spawn_drainer(state.db.clone());
    // The retention job (export then drop) as a seeded weekly heartbeat task.
    audit_partition::seed_rotation_task(&state.db).await;
    // The audit key's one-time hand-over row (or genesis row), before any
    // loop can write an audit row under the new key. Idempotent. A missing
    // NOO_AUDIT_HMAC_KEY never reaches here: it is a boot refusal above.
    audit_integrity::ensure_checkpoint(&state.db).await;
    // Then the hash-v2 marker: after it, a row hashed v1
    // (time not covered) fails verification. Once; idempotent.
    audit_integrity::ensure_hash_v2_marker(&state.db).await;
    // Then the hash chain's first row: from here a deleted or reordered audit
    // row fails `noo security audit verify`. Once; idempotent.
    audit_chain::ensure_genesis(&state.db).await;
    // The durable session floors: a restart must not forget an account change.
    let floors = session_floor::load_durable(&state.db).await;
    tracing::info!(floors, "durable session floors loaded");

    // Log initial cluster snapshot (proof-of-wiring for cluster_manager.rs).
    // Same data is available to autonomy actions, heartbeat tasks, and
    // anything else that needs in-process cluster status without a NATS
    // round-trip. LLM-facing access goes through MCP tools instead.
    let initial_status = cluster_manager::ClusterStatus::snapshot(&state).await;
    tracing::info!(
        alive_nodes = initial_status.alive_node_count,
        running_backends = initial_status.running_backend_count,
        avg_load = initial_status.avg_load,
        queue_depth = initial_status.job_queue_depth,
        "cluster_initial_snapshot"
    );

    // The signed audit chain head, recorded outside the database.
    audit_head_export::spawn(state.clone());
    ingest_loop::spawn(state.clone());
    recall_archive_loop::spawn(state.clone());

    // Heartbeat scheduler — fires due tasks from noo_heartbeat_tasks every
    // 60s. Restores the cron-tick that was lost when Python's
    // HeartbeatScheduler.start() stopped running (Rust gateway intercepts
    // the request path; the Python lifespan that called .start() never fires
    // in production). Without this, scheduled tasks (daily_briefing,
    // cluster_health, custom_prompt, etc.) only run when manually triggered
    // via /api/heartbeat/tasks/{id}/run.
    // report what the native migration runner sees.
    // Applies NOTHING — it exists so the stamped revision can be compared
    // against `noo db current` on a real deployment before the engine is
    // ever flipped.

    heartbeat_loop::spawn(state.clone());
    // Finishes the database_backup runs the heartbeat queued (async backup).
    backup_completion::spawn(state.clone());
    // Resolves the outcome of fire-and-forget Python delegations. Without
    // this, a delegated task that fails — or whose worker dies — alerts
    // nobody, since Python raises no operator alerts of its own.
    heartbeat_reconcile::spawn(state.clone());
    // Asynchronous operations: fail this instance's orphaned runs, then sweep
    // (heartbeats, lost runs, expiry). See ops.rs.
    ops::spawn(state.clone());
    // The erasure archive keeps an erased user's copy 30 days, then purges it daily.
    erasure_archive::spawn(state.clone());
    // Bounds noo_autonomy_audit (90 days), daily.
    autonomy_audit::spawn(state.clone());

    // Autonomy engine — periodic evaluation of monitor locations
    // (cluster health, backend availability, cert expiry, etc.). All
    // default locations have Rust evaluators; alert-action locations
    // notify the operator via operator_alert (cooldown-deduplicated).
    // See gateway-rust/src/autonomy_loop.rs.
    autonomy_loop::spawn(state.clone());
    // Scheduler port phases 6-7 — the dispatch/reap/janitor loops and the
    // job-lifecycle consumer. Unconditional since phase 7 deleted the Python
    // dispatch loop: this process is the only publisher of
    // tasks.dispatch.* — see scheduler_engine.rs.
    scheduler_engine::spawn(state.clone());
    scheduler_completions::spawn(state.clone());
    // Google Chat inbound (Pub/Sub pull). No-op unless
    // GOOGLE_CHAT_PUBSUB_SUBSCRIPTION is set.
    google_chat_pubsub::spawn(state.clone());
    // Telegram inbound (getUpdates long-poll). No-op unless
    // TELEGRAM_BOT_TOKEN is set. Unconditional otherwise: the
    // NOO_TELEGRAM_ENGINE=python hatch is obsolete
    // retired the Python poll loop and is warned about and ignored —
    // honouring it would leave the bot token with zero pollers.
    channels::telegram::start(state.clone());

    // Loop-liveness monitor — every background loop above stamps its tick
    // into loop_health; this task alerts the operator when one goes stale
    // (>3× its interval). Registry exposed at /api/agent/loops.
    loop_health::spawn_monitor(state.clone());

    // Dependency watchdog — loop_health covers the loops; this covers what
    // they all depend on. /health can now say 503 when Postgres or NATS is
    // gone, but nothing was consuming that, so a four-hour database outage
    // on 2026-08-03 reached nobody. See dependency_watchdog.rs.
    dependency_watchdog::spawn(state.clone());
    // say so when the config file bind mount points at an
    // unlinked inode (host file replaced by rename). Re-checked after every
    // config write in routes/settings.rs.
    {
        let st = state.clone();
        tokio::spawn(async move {
            config_mount::check_and_alert(&st, &routes::settings::config_path(), "startup").await;
        });
    }
    // Measures the direction WORK travels. A node's status is asserted by
    // its own outbound heartbeat, so a node that accepts no inbound
    // connection still reads healthy (2026-09-04: a cert naming a stale
    // address, every inference failing, the fleet looking fine).
    node_reachability::spawn(state.clone());
    placement_stuck::spawn(state.clone());

    // The operator MCP door has no listener of its own. Until stack-v0.2.40
    // it also ran as plain HTTP on NOO_MCP_HOST:NOO_MCP_PORT, published on
    // the controller's loopback, with the token OPTIONAL because "the
    // binding is the boundary". The binding was not a boundary: every
    // process on the controller — four CI runners among them — and every
    // container on the cluster network could reach it and hold the full
    // operator catalog with no credential and no audit row. The
    // door is `/mcp/operator` on the gateway port (`mcp_local::shared_router`),
    // where a credential is mandatory on every request.
    //
    // Its only credential is a per-admin `mcp:operator` service key. The
    // shared NOO_MCP_TOKEN was retired on 2026-09-30; an install that still
    // carries it is told so ONCE here, and the value is never compared.
    mcp_local::warn_retired_token();

    // Build router with all routes + TLS
    let app = routes::build_router(state);

    // The ONE listener: TLS, with the peer's certificate identity attached.
    //
    // There is no plain-HTTP branch. Until 2026-09-29 an unset NOO_TLS_CERT
    // bound `0.0.0.0:8080` in the clear behind a warn! — a wizard run that
    // skipped the security step got a working-looking install whose every
    // login crossed the wire unencrypted. The
    // operator's rule is "TLS and https default everywhere, fail loud", so
    // the fallback is gone and the refusal below is the loud part: it names
    // each missing or unreadable file and the command that mints them
    // (`tls::require_server_material`, called at the top of main).
    // `tests/test_gateway_refuses_plaintext.py` pins the absence of the
    // branch (no `TcpListener::bind` / `axum::serve` in this file).
    let addr = "0.0.0.0:8080";
    let tls_config = tls::load_rustls_config().await?;
    tracing::info!(addr, tls = true, "Listening");

    // Client certs are verified when presented (tls.rs), so the handshake
    // knows WHO connected. The acceptor carries that identity onto every
    // request: a node's cert is proof, where its token's actor field is only
    // a claim signed with a fleet-wide secret. The CA is mandatory now
    // (require_server_material), so the acceptor is always installed.
    let acceptor = node_identity::NodeIdentityAcceptor::new(
        axum_server::tls_rustls::RustlsAcceptor::new(tls_config),
    );
    match tls::mtls_mode() {
        tls::MtlsMode::On | tls::MtlsMode::OnButCaMissing => tracing::info!(
            "TLS: peer certificate identity attached and ENFORCED (the default when a cluster CA exists) — a token whose actor disagrees with the presented cert is refused, and so is a fleet token with no node certificate (loopback excepted)"
        ),
        // The WARN naming what this leaves open was already logged by
        // `tls::load_rustls_config`; this line says what is still true.
        tls::MtlsMode::OffExplicit | tls::MtlsMode::OffNoCa => tracing::info!(
            "TLS: peer certificate identity attached (observe only) — NOT enforced; unset NOO_MTLS_GATEWAY (with NOO_TLS_CA present) to enforce"
        ),
    }
    // `into_make_service_with_connect_info` injects the peer `SocketAddr` into
    // each request's extensions so the rate limiter can key on the real client
    // IP (see middleware::extract_client_ip) instead of one shared "unknown"
    // bucket.
    axum_server::bind(addr.parse()?)
        .acceptor(acceptor)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}
