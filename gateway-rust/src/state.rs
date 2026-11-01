// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Shared application state — database pools, NATS client, Redis, mesh.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use anyhow::Result;
use serde_json::Value;
use tokio::sync::{broadcast, RwLock, mpsc};
use crate::cache::RedisSlot;
use crate::config::AppConfig;
use crate::mesh::gossip::GossipMesh;
use crate::paths;
use crate::ws_collab::CollabCache;

/// Broadcast channel for pushing alerts to all connected WebSocket clients.
///
/// Each WS task calls `alert_tx.subscribe()` to get a receiver, then relays
/// alerts to its socket.  The `ws_client_count` atomic tracks how many WS
/// connections are currently active (incremented on connect, decremented on
/// disconnect) so `/api/alerts/clients` can answer without iterating.
pub struct AlertHub {
    pub tx: broadcast::Sender<Value>,
    pub client_count: AtomicUsize,
    /// A session ended for the subject carried (logout). Every open socket
    /// for that subject closes with 4401 — a WebSocket authenticates once,
    /// at the handshake, so without this a logout left every open chat
    /// socket live and writable until the network dropped it.
    pub session_end: broadcast::Sender<String>,
}

impl AlertHub {
    pub fn new() -> Self {
        // 64-slot buffer — alerts are small and infrequent; lagged receivers
        // simply miss stale alerts (acceptable for notification fanout).
        let (tx, _) = broadcast::channel(64);
        let (session_end, _) = broadcast::channel(64);
        Self {
            tx,
            client_count: AtomicUsize::new(0),
            session_end,
        }
    }

    /// Close every open socket authenticated as `sub`. Returns how many
    /// sockets were listening.
    pub fn end_sessions(&self, sub: &str) -> usize {
        self.session_end.send(sub.to_string()).unwrap_or(0)
    }

    pub fn subscribe_session_end(&self) -> broadcast::Receiver<String> {
        self.session_end.subscribe()
    }

    /// Broadcast an alert payload to all subscribers. Returns the number of
    /// receivers that were notified (may be less than client_count if some
    /// receivers have been dropped between the count read and the send).
    pub fn broadcast(&self, payload: Value) -> usize {
        self.tx.send(payload).unwrap_or(0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.tx.subscribe()
    }

    pub fn register_client(&self) {
        self.client_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn deregister_client(&self) {
        self.client_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> usize {
        self.client_count.load(Ordering::Relaxed)
    }
}

/// May a socket authenticated as (`sub`, `role`) receive this alert?
///
/// The hub is one broadcast channel, so every socket sees every payload;
/// until 2026-09-18 that meant an exec-approval alert (tool name, request
/// id) reached every connected tab of every user, read-scope colleagues
/// included. A payload may now carry an `audience`:
///
/// ```json
/// {"audience": {"sub": "<requester>", "min_role": "operator"}}
/// ```
///
/// It is delivered to that subject, and to anyone at or above `min_role`.
/// No `audience` at all is the legacy shape and still goes to everyone (an
/// operator's own `POST /api/alerts` broadcast). An `audience` that names
/// nobody the socket matches is not delivered; an unparseable `min_role`
/// fails closed.
pub fn audience_allows(payload: &Value, sub: &str, role: crate::auth::Role) -> bool {
    let Some(aud) = payload.get("audience") else {
        return true;
    };
    if aud.get("sub").and_then(Value::as_str) == Some(sub) {
        return true;
    }
    match aud.get("min_role").and_then(Value::as_str) {
        Some(min) => min
            .parse::<crate::auth::Role>()
            .map(|min| role >= min)
            .unwrap_or(false),
        None => false,
    }
}

#[cfg(test)]
mod audience_tests {
    use super::audience_allows;
    use crate::auth::Role;
    use serde_json::json;

    #[test]
    fn no_audience_is_the_legacy_broadcast_to_everyone() {
        let p = json!({"type": "alert", "alert": {"title": "hi"}});
        assert!(audience_allows(&p, "alice", Role::User));
    }

    #[test]
    fn an_approval_alert_reaches_the_requester_and_operators_only() {
        let p = json!({"type": "alert", "audience": {"sub": "alice", "min_role": "operator"}});
        assert!(audience_allows(&p, "alice", Role::User), "the requester");
        assert!(audience_allows(&p, "bob", Role::Operator), "an operator");
        assert!(audience_allows(&p, "bob", Role::Admin), "an admin");
        assert!(!audience_allows(&p, "carol", Role::User), "a read-scope colleague");
    }

    #[test]
    fn a_malformed_audience_fails_closed() {
        let p = json!({"audience": {"min_role": "superuser"}});
        assert!(!audience_allows(&p, "bob", Role::Admin));
        let p = json!({"audience": {}});
        assert!(!audience_allows(&p, "bob", Role::Admin));
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub db: sqlx::PgPool,
    pub nats: async_nats::Client,
    /// Which NATS credential this process actually presented — `"gateway"`
    /// for its own principal, `None` for a deliberately anonymous connection
    /// (the shared fleet pair was retired). Recorded at connect
    /// time for the `nats_isolation` preflight row.
    pub nats_cred_source: Option<&'static str>,
    pub js: async_nats::jetstream::Context,
    /// Filled once the first Redis connection lands (boot or later);
    /// `state.redis.as_ref()` is the `Option<&RedisCache>` every caller reads.
    pub redis: RedisSlot,
    pub gossip: GossipMesh,
    pub collab_cache: CollabCache,
    /// Alert broadcast hub — WebSocket client registry + fanout channel.
    pub alert_hub: AlertHub,
    /// Cached YAML config as JSON (read from noomesh.yaml at startup).
    /// Many concurrent readers, rare writers (only on PUT/POST config updates).
    pub config_yaml: Arc<RwLock<Value>>,
    /// Cached tool schemas from config/tools.json (loaded at startup).
    /// Prompt skills, scanned once at startup.
    ///
    /// Held here rather than re-read per request: selection used to be a
    /// NATS round trip to Python that re-scanned the directory each call.
    /// A restart picks up new skill files, which is the same cadence the
    /// Python registry had (it scanned at worker-pool startup).
    pub prompt_skills: Arc<crate::prompt_skills::SkillRegistry>,
    /// Skill usage counts. Process-local, matching the Python behaviour the
    /// port replaced — nothing persisted them there either.
    pub prompt_skill_usage: Arc<crate::prompt_skills::UsageCounters>,
    pub tool_schemas: Arc<RwLock<Vec<Value>>>,
    /// Raw parsed tools.json data for NATS subject lookups.
    pub tools_json_raw: Arc<RwLock<Value>>,
    /// Cached operational runbooks (loaded from docs/operating/runbooks/*.md at startup).
    /// Vec of (filename_stem, content) pairs for keyword-based injection.
    pub runbooks: Vec<(String, String)>,
    /// Active A2A peer WebSocket connections — agent_id → send channel.
    /// Populated by ws_agent.rs on connect; removed on disconnect.
    /// In-memory only (lost on restart); NATS KV `peer_agents` holds
    /// durable registration records.
    pub peer_connections: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Value>>>>,
    /// In-memory session cache — avoids Postgres round-trip on every request.
    /// TTL-based eviction runs periodically. Key: conversation_id.
    pub session_cache: Arc<RwLock<std::collections::HashMap<String, CachedSession>>>,
    /// Pre/post-inference hook registry for extensibility (add-ons).
    pub hooks: Arc<RwLock<HookRegistry>>,
    /// Prometheus metrics registry — in-process counters/gauges. Python ML
    /// modules push events here via NATS (`metrics.>` subjects); the
    /// `/metrics` route renders this in exposition format.
    pub metrics: Arc<crate::metrics::MetricsState>,
    /// A weak handle to the `Arc` this state lives in, set once by `main`
    /// after wrapping it. For a call site that holds `&AppState` and must
    /// spawn work that outlives it (a tool starting a task runner,
    /// ). `arc()` is `None` only before `main` set it.
    pub self_handle: std::sync::OnceLock<std::sync::Weak<AppState>>,
}

/// Cached session with TTL for eviction.
pub struct CachedSession {
    pub session: crate::session::Session,
    pub last_access: std::time::Instant,
}

/// Hook registry for pre/post-inference extensibility.
/// Add-ons register hooks here.
#[derive(Default)]
pub struct HookRegistry {
    /// Functions called before LLM inference (can modify messages/tools).
    pub pre_inference: Vec<HookEntry>,
    /// Functions called after LLM response (for feedback/learning).
    pub post_response: Vec<HookEntry>,
}

/// A registered hook with name and NATS subject for async dispatch.
pub struct HookEntry {
    pub name: String,
    /// NATS subject to publish hook event to (fire-and-forget).
    pub nats_subject: String,
}

/// Log every NATS connection lifecycle event.
///
/// async-nats reconnects forever by default and replays core subscriptions,
/// so the gateway's client already self-heals — but until now it did so
/// completely silently: the only NATS log lines in the whole process were
/// emitted once at startup. A bus outage left no trace, which is precisely
/// what made the 2026-08-02 node incident take two days to notice.
pub(crate) async fn nats_event_logger(event: async_nats::Event) {
    match event {
        async_nats::Event::Connected => {
            tracing::info!("nats.connected — gateway bus is live (subscriptions replayed)");
            BUS_UP.notify_one();
        }
        async_nats::Event::Disconnected => {
            tracing::warn!(
                "nats.disconnected — gateway lost the bus; worker RPC, gossip and \
                 job dispatch are down until it reconnects"
            );
        }
        async_nats::Event::Closed => {
            tracing::error!("nats.closed — gateway connection closed permanently");
        }
        async_nats::Event::LameDuckMode => {
            tracing::warn!("nats.lame_duck — server is draining; expect a reconnect");
        }
        async_nats::Event::SlowConsumer(sid) => {
            tracing::warn!(sid, "nats.slow_consumer — messages are being dropped");
        }
        other => {
            tracing::warn!(event = %other, "nats.event");
        }
    }
}

/// Bind (or create) the KV buckets the cluster view depends on.
///
/// Called at startup and then periodically by [`spawn_kv_bucket_watchdog`].
/// The bootstrap used to run exactly once: if NATS came back with its
/// JetStream store recreated — which is what `noo stack start` does to the
/// container — the buckets were gone and nothing ever recreated them. Every
/// reader uses `if let Ok(kv) = js.get_key_value(...)`, so the fleet would
/// have rendered as an empty cluster rather than an error, indefinitely.
pub async fn ensure_kv_buckets(js: &async_nats::jetstream::Context, verbose: bool) {
    // Config must match Python's mesh_registry.py exactly to avoid conflicts.
    const EXPECTED_TTL_SECS: u64 = 120; // NODE_TTL_SEC in Python
    match js.get_key_value("mesh_nodes").await {
        Ok(store) => {
            if verbose {
                match store.status().await {
                    Ok(status) => {
                        let max_age = status.max_age().as_secs();
                        if max_age == 0 {
                            tracing::warn!(
                                "NATS KV 'mesh_nodes' has max_age=0 (no TTL) — \
                                 nodes will never expire. This may indicate misconfiguration \
                                 or tampering. Expected TTL: {EXPECTED_TTL_SECS}s"
                            );
                        } else if max_age > 600 {
                            tracing::warn!(
                                max_age_secs = max_age,
                                expected = EXPECTED_TTL_SECS,
                                "NATS KV 'mesh_nodes' TTL unexpectedly high — \
                                 stale nodes may persist longer than expected"
                            );
                        } else {
                            tracing::info!(
                                max_age_secs = max_age,
                                "NATS KV bucket 'mesh_nodes' ready"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "NATS KV 'mesh_nodes' bound but status check failed");
                    }
                }
            }
        }
        Err(_) => {
            // Bucket doesn't exist — create with config matching Python's MeshRegistry
            match js.create_key_value(async_nats::jetstream::kv::Config {
                bucket: "mesh_nodes".into(),
                max_age: std::time::Duration::from_secs(EXPECTED_TTL_SECS),
                description: "Distributed node registry for mesh routing".into(),
                ..Default::default()
            }).await {
                Ok(_) => tracing::warn!(
                    "NATS KV bucket 'mesh_nodes' created — it was missing, so the \
                     cluster view was empty until now"
                ),
                Err(e) => tracing::warn!(error = %e, "NATS KV bucket 'mesh_nodes' unavailable"),
            }
        }
    }

    // NATS KV bucket for peer agent registrations (A2A).
    // TTL is advisory — registrations refresh on each WS reconnect.
    // Agent messaging key registry: an agent's public
    // sealing + signing keys, keyed by its subject token. No TTL — a key is
    // valid until replaced; the registry is the only way a message can be
    // wrapped to the agent itself (end-to-end) rather than only to the
    // controller's review key.
    match js.get_key_value(crate::agent_crypto::KEYS_BUCKET).await {
        Ok(_) => {
            if verbose {
                tracing::info!(bucket = crate::agent_crypto::KEYS_BUCKET, "NATS KV bucket ready");
            }
        }
        Err(_) => {
            match js.create_key_value(async_nats::jetstream::kv::Config {
                bucket: crate::agent_crypto::KEYS_BUCKET.into(),
                description: "agent messaging public keys".into(),
                history: 3,
                ..Default::default()
            }).await {
                Ok(_) => tracing::warn!(bucket = crate::agent_crypto::KEYS_BUCKET, "NATS KV bucket created — it was missing"),
                Err(e) => tracing::warn!(error = %e, bucket = crate::agent_crypto::KEYS_BUCKET, "NATS KV bucket unavailable"),
            }
        }
    }

    const PEER_AGENTS_TTL_SECS: u64 = 7200; // 2h — longer than default 1h TTL so registrations survive brief outages
    match js.get_key_value("peer_agents").await {
        Ok(_) => {
            if verbose {
                tracing::info!("NATS KV bucket 'peer_agents' ready");
            }
        }
        Err(_) => {
            match js.create_key_value(async_nats::jetstream::kv::Config {
                bucket: "peer_agents".into(),
                max_age: std::time::Duration::from_secs(PEER_AGENTS_TTL_SECS),
                description: "A2A peer agent registrations".into(),
                ..Default::default()
            }).await {
                Ok(_) => tracing::warn!("NATS KV bucket 'peer_agents' created — it was missing"),
                Err(e) => tracing::warn!(error = %e, "NATS KV bucket 'peer_agents' unavailable"),
            }
        }
    }
}

/// How long the gateway waits for its first NATS connection before it serves
/// degraded (i301 a.3).
pub const BUS_BOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Is the client connected to the bus right now?
pub fn bus_connected(nats: &async_nats::Client) -> bool {
    nats.connection_state() == async_nats::connection::State::Connected
}

/// Wait up to `max` for `nats` to connect; true when it did.
pub async fn wait_for_bus(nats: &async_nats::Client, max: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + max;
    while !bus_connected(nats) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    true
}

/// Woken by every `Connected` event ([`nats_event_logger`]): the bus objects
/// are re-asserted at once, not at the next tick.
static BUS_UP: std::sync::LazyLock<tokio::sync::Notify> = std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Bind (or create) everything on the bus the gateway depends on: the KV
/// buckets, the agent-message stream and the job plane's streams.
/// Idempotent. Skipped while disconnected (each call would only fail).
pub async fn ensure_bus_objects(nats: &async_nats::Client, js: &async_nats::jetstream::Context, verbose: bool) {
    if !bus_connected(nats) {
        return;
    }
    ensure_kv_buckets(js, verbose).await;
    crate::agent_messages::ensure_stream(js).await;
    crate::scheduler_engine::ensure_job_plane_streams(js).await;
}

/// Bind the bus objects now (when connected), on every reconnect, and every
/// 60 s. Before i301 a.3 the streams were created once at boot and the KV
/// buckets re-asserted every 60 s, so a gateway that started without NATS
/// never had its streams until a restart, and a NATS recreated with a fresh
/// JetStream store (what `noo stack start` does) left them gone too.
pub fn spawn_bus_objects(nats: async_nats::Client, js: async_nats::jetstream::Context) {
    tokio::spawn(async move {
        ensure_bus_objects(&nats, &js, true).await;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // the immediate first tick: the call above just ran
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = BUS_UP.notified() => {
                    tracing::info!("nats.connected — binding the KV buckets and streams");
                }
            }
            ensure_bus_objects(&nats, &js, false).await;
        }
    });
}

/// Complete a Postgres URL's transport parameters from the staged PKI.
///
/// Shared so every Postgres connection in this process trusts the cluster CA
/// and presents the controller leaf the same way. The migration runner opens
/// its OWN privileged pool, and without this it connected in the clear and
/// died with `invalid peer certificate: UnknownIssuer` — found by booting a
/// gateway, not by a test. Two places building a DSN two ways is how that
/// happens, so there is now one place.
///
/// Since 2026-09-28 the compose DSNs carry the full set themselves
/// (`sslmode=verify-full&sslrootcert=…&sslcert=…&sslkey=…`, the paths on the
/// ro mount — sqlx reads the 0644 key as-is, it has no libpq perms rule), and
/// Postgres refuses any TCP client without a cluster-CA client certificate
/// (`docker/postgres/pg_hba.conf`). This fills in whichever of the four a
/// bare DSN (yaml `services.database_url`, a dev override) lacks, each
/// independently, from `NOO_TLS_CA` / `NOO_TLS_CERT` / `NOO_TLS_KEY` as
/// `startup_tasks::stage_pki` published them. A param already in the URL
/// wins; nothing is ever removed or weakened.
pub fn with_cluster_tls(url: String) -> String {
    let ca = crate::tls::ca_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let mut cert = std::env::var("NOO_TLS_CERT").unwrap_or_default();
    let mut key = std::env::var("NOO_TLS_KEY").unwrap_or_default();
    // Postgres requires the client certificate's CN to BE the role being
    // asked for (pg_hba `clientcert=verify-full`), so a bare DSN presents the
    // leaf issued for its user (`$NOO_TLS_PG_DIR/<user>.crt|key`) when there
    // is one, and the gateway's own leaf otherwise — which a role with a
    // `verify-full` rule refuses at the handshake, naming the CN.
    if let Some((c, k)) = pg_role_leaf(&url, &std::env::var("NOO_TLS_PG_DIR").unwrap_or_default()) {
        cert = c;
        key = k;
    }
    complete_pg_tls(url, &ca, &cert, &key)
}

/// `<dir>/<user>.crt` and `.key` for the user in a `scheme://user[:pw]@host/…`
/// DSN, when both files exist. Only a bare `[A-Za-z0-9_]` user names a file:
/// nothing in a DSN can steer the path out of `dir`.
pub(crate) fn pg_role_leaf(url: &str, dir: &str) -> Option<(String, String)> {
    if dir.is_empty() {
        return None;
    }
    let authority = url.split_once("://")?.1.split(['/', '?']).next()?;
    let user = authority.rsplit_once('@')?.0.split(':').next()?;
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let (cert, key) = (format!("{}/{user}.crt", dir.trim_end_matches('/')), format!("{}/{user}.key", dir.trim_end_matches('/')));
    (std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists()).then_some((cert, key))
}

/// The pure half of [`with_cluster_tls`]: `ca`/`cert`/`key` are used only
/// when non-empty AND present on disk, so a stale path never turns into a
/// connection that fails on a file sqlx cannot open.
pub(crate) fn complete_pg_tls(url: String, ca: &str, cert: &str, key: &str) -> String {
    let has = |name: &str| url.contains(&format!("?{name}=")) || url.contains(&format!("&{name}="));
    let present = |p: &str| !p.is_empty() && std::path::Path::new(p).exists();
    let mut add: Vec<String> = Vec::new();
    if present(ca) {
        if !has("sslmode") {
            add.push("sslmode=verify-full".into());
        }
        if !has("sslrootcert") {
            add.push(format!("sslrootcert={ca}"));
        }
    }
    if present(cert) && present(key) && !has("sslcert") && !has("sslkey") {
        add.push(format!("sslcert={cert}"));
        add.push(format!("sslkey={key}"));
    }
    if add.is_empty() {
        return url;
    }
    let sep = if url.contains('?') { "&" } else { "?" };
    tracing::info!(added = %add.join("&"), "Postgres TLS params completed from the cluster PKI");
    format!("{url}{sep}{}", add.join("&"))
}

impl AppState {
    /// The shared `Arc` of this state, once `main` has registered it.
    pub fn arc(&self) -> Option<Arc<AppState>> {
        self.self_handle.get().and_then(|w| w.upgrade())
    }

    /// The registered memory provider. Augmentation-plane
    /// call sites — KB query/ingest, graph tools, snapshots, semantic
    /// relationships — MUST go through this rather than `worker_client`
    /// or direct SQL against trellion's tables; transcript-plane and
    /// observability SQL stays direct by design (see `memory/mod.rs`).
    ///
    /// Phase 1: unconditionally `NatsTrellion`, built on demand from the
    /// shared handles (all cheap borrows). Provider selection
    /// (`memory: provider:` config) is phase 4; until then constructing
    /// here rather than caching a field keeps AppState construction
    /// untouched.
    pub fn memory(&self) -> crate::memory::MemoryProvider<'_> {
        crate::memory::MemoryProvider::nats_trellion(&self.nats, &self.db, &self.metrics)
    }

    pub async fn new(config: &AppConfig) -> Result<Self> {
        // Postgres — auto-enable TLS when cluster CA exists (no flag needed)
        let mut db_url = crate::config::env_or_yaml(
            "DATABASE_URL",
            |c| c.services.database_url.clone(),
            "postgresql://noo:noo@postgres:5432/noomesh",
        );

        db_url = with_cluster_tls(db_url);

        // The pool pins its search_path: mesh's tables (schema `mesh` on
        // fresh installs, `public` on legacy ones) and the legacy
        // memory-plane in `public`, then the per-system schemas from
        // the design. On a fresh install evolve's five tables live
        // in schema `evolve`; the gateway's own evolve reads retired with
        // routes/pro.rs (the proxy forwards instead of
        // querying), but `evolve` stays on the path for the memory plane's
        // cross-schema joins and any legacy caller. `trellion` is included
        // ahead of its own move for the same reason. Table names are unique across all three, so order decides
        // nothing except lookup priority.
        //
        // Pinned HERE, by the consumer, not by ALTER ROLE from the broker:
        // each service declares where the tables it reads live. A role-level
        // setting would be a second declaration of the same fact.
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&db_url)?
            .options([("search_path", "mesh,public,trellion,evolve")]);
        let db = sqlx::PgPool::connect_with(opts).await?;
        tracing::info!("Postgres connected");

        // NATS (with TLS if cluster CA is available)
        let nats_url = crate::config::env_or_yaml(
            "NATS_URL",
            |c| c.services.nats_url.clone(),
            // The bus serves mTLS only (monitoring/nats/nats-tls.conf).
            "tls://nats:4222",
        );

        // Which credential this process presents on the bus
        // stage 1. Resolved once, before either TLS branch, so the "which
        // pair was used" line is logged exactly once per connect and both
        // branches cannot drift apart.
        let nats_cred = crate::nats_credentials::resolve(crate::config::secret_env::secret_opt)
            .map_err(|e| anyhow::anyhow!(e))?;
        let nats_cred_source: Option<&'static str> = nats_cred.as_ref().map(|c| c.source);
        match &nats_cred {
            Some(c) => tracing::info!(
                role = c.source,
                user = %c.user,
                "NATS credential resolved"
            ),
            None => tracing::warn!(
                "NATS connecting ANONYMOUSLY — {}=1 is set",
                crate::nats_credentials::ALLOW_ANONYMOUS_VAR
            ),
        }

        let nats_request_timeout = std::time::Duration::from_secs(
            crate::config::env_or_yaml_u64("NOO_WORKER_TIMEOUT_SECS", |c| c.worker.timeout_secs, 120),
        );
        // In the background (i301 a.3): a gateway without NATS used to exit
        // and crash-loop ("failed to lookup address ... nats"), taking the
        // UI, the MCP doors and every non-bus route down with the bus. It
        // now waits a bounded while, then serves degraded: `/health` says
        // so, bus routes answer 503 `bus_unavailable`, and the KV buckets
        // and streams are bound when the bus comes up (`spawn_bus_objects`).
        let nats = crate::bus::connect(
            &nats_url,
            nats_cred.clone(),
            crate::nats_credentials::INBOX_PREFIX,
            nats_request_timeout,
            true,
        )
        .await?;

        let js = async_nats::jetstream::new(nats.clone());
        // Userinfo scrubbed: an operator may put the password in the URL.
        if wait_for_bus(&nats, BUS_BOOT_WAIT).await {
            tracing::info!(url = %crate::redact::scrub_url_userinfo(&nats_url), "NATS connected");
        } else {
            tracing::error!(
                url = %crate::redact::scrub_url_userinfo(&nats_url),
                waited_secs = BUS_BOOT_WAIT.as_secs(),
                "nats.unavailable — the gateway starts DEGRADED: worker dispatch, gossip and agent messages \
                 are down (503 bus_unavailable), /health reports degraded; it connects by itself when NATS is up \
                 (is the nats container running? noo stack start)"
            );
        }

        // Redis (optional — graceful degradation if unavailable). Waits a
        // bounded while for the first connection, then serves without it and
        // fills `state.redis` from the background when Redis comes up.
        let redis = {
            let redis_url = crate::config::env_or_yaml(
                "REDIS_URL",
                |c| c.services.redis_url.clone(),
                // Redis serves TLS only (`tls-port 6379`, `port 0`).
                "rediss://redis:6379",
            );
            RedisSlot::connect(&redis_url, crate::cache::REDIS_BOOT_BUDGET).await
        };

        Self::assemble(config, db, nats, nats_cred_source, js, redis).await
    }

    /// Everything `new` does AFTER the three connections are open: the gossip
    /// handle, the caches read from disk, the registries. One body, so the
    /// router harness (`routes::router_harness_tests`), which hands in an
    /// unconnected NATS client and an empty Redis slot, cannot drift from the
    /// state production builds.
    async fn assemble(
        config: &AppConfig,
        db: sqlx::PgPool,
        nats: async_nats::Client,
        nats_cred_source: Option<&'static str>,
        js: async_nats::jetstream::Context,
        redis: RedisSlot,
    ) -> Result<Self> {
        // Gossip mesh
        let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "gateway".into());
        let gossip = GossipMesh::new(nats.clone(), node_id);

        // Collab event cache
        let collab_cache = CollabCache::new();

        // Cache: load YAML config as JSON Value (avoids re-reading on every request)
        let config_yaml = match load_yaml_config_to_json().await {
            Ok(val) => {
                tracing::info!("Config YAML cached in AppState");
                crate::web_search::refresh_live_config(&val);
                val
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to pre-cache YAML config, starting with empty object");
                serde_json::json!({})
            }
        };

        // Cache: load tool schemas from config/tools.json
        let (tool_schemas, tools_json_raw) = load_tool_schemas_cached();

        Ok(Self {
            config: config.clone(),
            db,
            nats,
            nats_cred_source,
            js,
            redis,
            gossip,
            collab_cache,
            alert_hub: AlertHub::new(),
            config_yaml: Arc::new(RwLock::new(config_yaml)),
            prompt_skills: {
                let root = crate::prompt_skills::find_root();
                let reg = crate::prompt_skills::SkillRegistry::scan(&root);
                tracing::info!(count = reg.len(), root = %root.display(), "prompt_skills.scanned");
                Arc::new(reg)
            },
            prompt_skill_usage: {
                let mut u = crate::prompt_skills::UsageCounters::default();
                let root = crate::prompt_skills::find_root();
                u.prime(crate::prompt_skills::SkillRegistry::scan(&root)
                    .list_all().into_iter().map(|s| s.name.clone()));
                Arc::new(u)
            },
            tool_schemas: Arc::new(RwLock::new(tool_schemas)),
            tools_json_raw: Arc::new(RwLock::new(tools_json_raw)),
            runbooks: load_runbooks(),
            peer_connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            session_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            hooks: Arc::new(RwLock::new(HookRegistry::default())),
            metrics: Arc::new(crate::metrics::MetricsState::new()),
            self_handle: std::sync::OnceLock::new(),
        })
    }

    /// A state for the router harness: the REAL Postgres pool and the real
    /// assembly, but NO NATS server (an unconnected client that keeps
    /// retrying, so every request to the bus fails fast) and NO Redis (an
    /// empty slot, which is exactly the condition `redis_or_unavailable` and
    /// `Measured` answer for). Test-only.
    #[cfg(test)]
    pub(crate) async fn for_router_harness(config: &AppConfig, db: sqlx::PgPool) -> Result<Self> {
        let nats = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .request_timeout(Some(std::time::Duration::from_secs(1)))
            .connect("nats://127.0.0.1:1")
            .await?;
        let js = async_nats::jetstream::new(nats.clone());
        Self::assemble(config, db, nats, None, js, RedisSlot::default()).await
    }
}

/// Load all operational runbooks from docs/operating/runbooks/*.md at startup.
fn load_runbooks() -> Vec<(String, String)> {
    let dirs = ["/app/docs/runbooks", "docs/operating/runbooks"];
    for dir in &dirs {
        let path = std::path::Path::new(dir);
        if path.is_dir() {
            let mut books = Vec::new();
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().map(|e| e == "md").unwrap_or(false) {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            let stem = p.file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            books.push((stem, content));
                        }
                    }
                }
            }
            if !books.is_empty() {
                tracing::info!(count = books.len(), dir = dir, "runbooks_loaded");
                return books;
            }
        }
    }
    Vec::new()
}

/// Read noomesh.yaml and convert to serde_json::Value.
/// Used once at startup and again after config writes to refresh the cache.
pub async fn load_yaml_config_to_json() -> Result<Value> {
    let path = std::env::var("NOO_CONFIG_PATH")
        .unwrap_or_else(|_| {
            paths::resolve(paths::CONFIG_YAML_CANDIDATES)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| paths::CONFIG_YAML_CANDIDATES[0].to_string())
        });
    let contents = tokio::fs::read_to_string(&path).await
        .map_err(|e| anyhow::anyhow!("Failed to read config {path}: {e}"))?;
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse YAML: {e}"))?;
    let json_val: Value = serde_json::to_value(&yaml_val)
        .map_err(|e| anyhow::anyhow!("YAML->JSON conversion failed: {e}"))?;
    Ok(json_val)
}

/// Load config/tools.json, returning (tool_schemas for LLM, raw JSON for subject lookups).
fn load_tool_schemas_cached() -> (Vec<Value>, Value) {
    if let Some(path) = paths::resolve(paths::TOOLS_JSON_CANDIDATES) {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(data) = serde_json::from_str::<Value>(&contents) {
                if let Some(tools) = data.get("core_tools").and_then(|t| t.as_array()) {
                    let schemas: Vec<Value> = tools.iter()
                        .map(|t| {
                            serde_json::json!({
                                "type": t.get("type").unwrap_or(&serde_json::json!("function")),
                                "function": t.get("function").unwrap_or(&serde_json::json!({})),
                            })
                        })
                        .collect();
                    tracing::info!(path = %path.display(), tools = schemas.len(), "tool_schemas.cached");
                    return (schemas, data);
                }
            }
        }
    }

    tracing::warn!("tool_schemas.not_found, using built-in fallback");
    let fallback = vec![
        serde_json::json!({"type": "function", "function": {
            "name": "noo_tool_search",
            "description": "Search for tools by capability.",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        }}),
        serde_json::json!({"type": "function", "function": {
            "name": "noo_rag_query",
            "description": "Search the knowledge base.",
            "parameters": {"type": "object", "properties": {"question": {"type": "string"}}, "required": ["question"]}
        }}),
    ];
    (fallback, serde_json::json!({}))
}

#[cfg(test)]
mod pg_tls_url_tests {
    use super::complete_pg_tls;

    /// Three real files in a per-test directory (no tempfile crate here):
    /// the completion only adds a param whose file exists.
    fn files() -> (std::path::PathBuf, String, String, String) {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("noo-pg-tls-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mk = |n: &str| {
            let p = d.join(n);
            std::fs::write(&p, "x").unwrap();
            p.to_string_lossy().into_owned()
        };
        let (ca, cert, key) = (mk("ca.crt"), mk("gateway.crt"), mk("gateway.key"));
        (d, ca, cert, key)
    }

    #[test]
    fn a_bare_dsn_gets_verify_full_and_the_client_pair() {
        let (_d, ca, cert, key) = files();
        let out = complete_pg_tls("postgresql://u:p@postgres:5432/db".into(), &ca, &cert, &key);
        assert_eq!(out, format!("postgresql://u:p@postgres:5432/db?sslmode=verify-full&sslrootcert={ca}&sslcert={cert}&sslkey={key}"));
    }

    #[test]
    fn a_compose_dsn_that_carries_everything_is_untouched() {
        let (_d, ca, cert, key) = files();
        let url = "postgresql://u:p@postgres:5432/db?options=-c%20search_path%3Dmesh&sslmode=verify-full&sslrootcert=/app/pki/ca.crt&sslcert=/app/pki/gateway/gateway.crt&sslkey=/app/pki/gateway/gateway.key";
        assert_eq!(complete_pg_tls(url.into(), &ca, &cert, &key), url);
    }

    /// The 2026-09-28 gap in the old builder: `url.contains("sslmode")`
    /// returned early, so a DSN with sslmode but no client pair connected
    /// without a certificate — which pg_hba now refuses.
    #[test]
    fn sslmode_alone_still_gains_the_client_pair() {
        let (_d, ca, cert, key) = files();
        let out = complete_pg_tls("postgresql://u:p@postgres:5432/db?sslmode=verify-ca".into(), &ca, &cert, &key);
        assert!(out.ends_with(&format!("?sslmode=verify-ca&sslrootcert={ca}&sslcert={cert}&sslkey={key}")), "{out}");
        assert_eq!(out.matches("sslmode=").count(), 1);
    }

    /// A bare DSN presents the leaf issued for ITS user, never the gateway's,
    /// and a user with no leaf (or a hostile one) falls back unchanged.
    #[test]
    fn a_bare_dsn_presents_the_leaf_of_its_own_role() {
        let (d, ca, gw_cert, gw_key) = files();
        let pg = d.join("pg");
        std::fs::create_dir_all(&pg).unwrap();
        for f in ["noo_app.crt", "noo_app.key"] {
            std::fs::write(pg.join(f), "x").unwrap();
        }
        let dir = pg.to_string_lossy().into_owned();
        let (c, k) = crate::state::pg_role_leaf("postgresql://noo_app:pw@postgres:5432/db", &dir).expect("noo_app has a leaf");
        assert_eq!((c.as_str(), k.as_str()), (format!("{dir}/noo_app.crt").as_str(), format!("{dir}/noo_app.key").as_str()));
        let out = complete_pg_tls("postgresql://noo_app:pw@postgres:5432/db".into(), &ca, &c, &k);
        assert!(out.contains(&format!("sslcert={dir}/noo_app.crt")) && !out.contains(&gw_cert), "{out}");
        assert!(crate::state::pg_role_leaf("postgresql://noo@postgres/db", &dir).is_none(), "no leaf for `noo` here: fall back");
        assert!(crate::state::pg_role_leaf("postgresql://../x@postgres/db", &dir).is_none());
        assert!(crate::state::pg_role_leaf("postgresql://noo_app@postgres/db", "").is_none(), "no NOO_TLS_PG_DIR: unchanged behaviour");
        assert!(crate::state::pg_role_leaf("postgresql://postgres/db", &dir).is_none(), "no user in the DSN");
        let _ = gw_key;
    }

    #[test]
    fn a_missing_file_adds_nothing_for_that_param() {
        let (_d, ca, _cert, key) = files();
        let out = complete_pg_tls("postgresql://u:p@postgres:5432/db".into(), &ca, "/nope/gateway.crt", &key);
        assert_eq!(out, format!("postgresql://u:p@postgres:5432/db?sslmode=verify-full&sslrootcert={ca}"));
        assert_eq!(complete_pg_tls("postgresql://u:p@h/db".into(), "", "", ""), "postgresql://u:p@h/db");
    }
}

/// A client that never connects (nothing listens on port 1): the gateway's
/// view of a NATS that is down. Test-only, shared by the i301 a.3 tests.
#[cfg(test)]
pub(crate) async fn unconnected_bus() -> async_nats::Client {
    async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .request_timeout(Some(std::time::Duration::from_secs(1)))
        .connect("nats://127.0.0.1:1")
        .await
        .expect("a background client is built without a server")
}

#[cfg(test)]
mod bus_down_tests {
    use super::*;

    /// i301 a.3: a gateway with no NATS gets a client at once, reports it
    /// unconnected, and the bounded boot wait gives up instead of hanging.
    #[tokio::test]
    async fn a_missing_bus_is_waited_for_a_bounded_while_then_reported() {
        let nats = unconnected_bus().await;
        assert!(!bus_connected(&nats));
        let t = std::time::Instant::now();
        assert!(!wait_for_bus(&nats, std::time::Duration::from_millis(600)).await);
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "the wait is bounded: {:?}", t.elapsed());
        assert_eq!(BUS_BOOT_WAIT, std::time::Duration::from_secs(20));
    }

    /// The bus objects are bound by one task, on every reconnect and every
    /// 60 s, never once at boot: main no longer creates the streams itself.
    #[test]
    fn the_streams_and_buckets_are_bound_by_the_bus_task() {
        let main = include_str!("main.rs");
        assert!(main.contains("state::spawn_bus_objects(state.nats.clone(), state.js.clone())"));
        assert!(!main.contains("agent_messages::ensure_stream(&state.js)"), "a boot-only stream create is back");
        assert!(!main.contains("scheduler_engine::ensure_job_plane_streams(&state.js)"), "a boot-only stream create is back");
        let src = include_str!("state.rs");
        let objs = src.split("pub async fn ensure_bus_objects").nth(1).unwrap().split("\npub fn ").next().unwrap();
        for call in ["ensure_kv_buckets(js, verbose)", "agent_messages::ensure_stream(js)", "scheduler_engine::ensure_job_plane_streams(js)"] {
            assert!(objs.contains(call), "{call}");
        }
        let logger = src.split("pub(crate) async fn nats_event_logger").nth(1).unwrap();
        assert!(logger.split("Event::Disconnected").next().unwrap().contains("BUS_UP.notify_one()"), "Connected wakes the task");
        let new = src.split("pub async fn new(").nth(1).unwrap().split("Self::assemble(").next().unwrap();
        assert!(new.contains("nats_request_timeout,\n            true,"), "the gateway connects in the background");
        assert!(!new.contains("ensure_kv_buckets("), "no bus call before the bus is known to be up");
    }
}
