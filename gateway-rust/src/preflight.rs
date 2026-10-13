// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Pre-flight health manifest.
//!
//! Run once after ``AppState::new`` completes. Each subsystem is probed
//! with a bounded timeout; critical failures abort startup (so the
//! operator gets a clear error instead of serving requests against a
//! broken stack), and optional failures log a WARN but keep going.
//!
//! Why this exists: the old startup path initialises DB, NATS, RAG, the
//! autonomy engine, recall memory, etc. in sequence with try/except
//! around each block. If the configured embedding backend (default:
//! ollama/harrier; TEI is optional legacy) is down, steps 4-8 still
//! "succeed" but with broken assumptions — e.g. autonomy polls a
//! location that queries a table it can't reach and logs at DEBUG.
//! Nobody notices. Pre-flight converts that silent degradation into a
//! visible report.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub critical: bool,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub checks: Vec<CheckResult>,
}

impl PreflightReport {
    pub fn critical_failures(&self) -> Vec<&CheckResult> {
        self.checks.iter().filter(|c| c.critical && !c.ok).collect()
    }

    pub fn optional_failures(&self) -> Vec<&CheckResult> {
        self.checks.iter().filter(|c| !c.critical && !c.ok).collect()
    }

    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }

    /// Emit each result to tracing at the appropriate level.
    pub fn log(&self) {
        for c in &self.checks {
            match (c.ok, c.critical) {
                (true, _) => tracing::info!(check = c.name, detail = %c.detail, "preflight.ok"),
                (false, true) => tracing::error!(check = c.name, detail = %c.detail, "preflight.critical_fail"),
                (false, false) => tracing::warn!(check = c.name, detail = %c.detail, "preflight.optional_fail"),
            }
        }
        if self.all_passed() {
            tracing::info!(count = self.checks.len(), "preflight.complete");
        } else {
            tracing::warn!(
                total = self.checks.len(),
                critical_failures = self.critical_failures().len(),
                optional_failures = self.optional_failures().len(),
                "preflight.complete_with_failures"
            );
        }
    }
}

/// Run every check and return a report. Does not abort — caller decides
/// how to react based on ``critical_failures()``.
pub async fn run(state: &Arc<AppState>) -> PreflightReport {
    let mut checks = Vec::new();
    checks.push(check_secret_files());
    checks.push(check_postgres(state).await);
    checks.push(check_pgvector(state).await);
    checks.push(check_baseline_tables(state).await);
    checks.push(check_nats(state).await);
    checks.push(check_embedding_service(state).await);
    checks.push(check_embedding_dims(state).await);
    checks.push(check_tool_schemas(state).await);
    checks.push(check_tool_subjects(state).await);
    checks.push(check_ported_subjects().await);
    checks.push(check_nats_monitoring().await);
    checks.push(check_nats_isolation(state).await);
    PreflightReport { checks }
}

/// Names in `/connz?auth=1` that mean "nobody has rolled the bus over".
///
/// `noo` is the historical shared user the whole fleet presented;
/// `noo-unconfigured` is the committed placeholder in `users.conf`, which
/// exists only so a stack that never rendered fails loudly — if a session
/// is somehow authenticated as it, the server is serving the baseline.
const LEGACY_BUS_USERS: &[&str] = &["noo", "noo-unconfigured"];

/// Who is REALLY on the bus, asked of the server rather than of our own env.
///
/// Two different claims, and the second is the one only the server can
/// settle:
///
/// 1. this process is connected as its own principal, not the shared one —
///    already decided at boot, restated here so one row carries the whole
///    posture;
/// 2. no OTHER session is presenting the legacy shared user. A gateway that
///    moved to its own credential while a worker, a trellion or a forgotten
///    node still holds `noo` has not isolated anything: that credential is
///    granted `>`/`>`, so one holder is one holder too many. Our own
///    environment cannot see that. `/connz?auth=1` can.
///
/// Always critical: the shared user and its bridge were retired, so there is no rollout window in which a legacy session is
/// expected — one means the server is still serving a users.conf rendered
/// before the retirement. Advisory only when monitoring is unreachable: an
/// endpoint we cannot read is not evidence of a legacy session, and
/// `check_nats_monitoring` already reports the unreachability as its own row.
async fn check_nats_isolation(state: &Arc<AppState>) -> CheckResult {
    let critical = true;
    let mine = state.nats_cred_source.unwrap_or("anonymous");

    let (base, client) = nats_monitor_endpoint();
    let url = format!("{base}/connz?auth=1");
    let body = match tokio::time::timeout(Duration::from_secs(5), client.get(&url).send()).await {
        Ok(Ok(r)) => match r.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                return ok(
                    "nats_isolation",
                    false,
                    format!("presenting '{mine}'; could not read {url} ({e}) — the SERVER-side \
                             check (is anyone still on the legacy user?) did not run"),
                )
            }
        },
        Ok(Err(e)) => {
            return ok(
                "nats_isolation",
                false,
                format!("presenting '{mine}'; {url} unreachable ({e}) — the SERVER-side check \
                         (is anyone still on the legacy user?) did not run"),
            )
        }
        Err(_) => {
            return ok(
                "nats_isolation",
                false,
                format!("presenting '{mine}'; 5s timeout on {url} — the SERVER-side check did not run"),
            )
        }
    };

    let legacy = legacy_sessions(&body);
    if legacy.is_empty() {
        return ok(
            "nats_isolation",
            critical,
            format!(
                "presenting '{mine}'; no session on the legacy bus user ({})",
                LEGACY_BUS_USERS.join("/")
            ),
        );
    }
    fail(
        "nats_isolation",
        critical,
        format!(
            "{} session(s) still presenting the RETIRED shared bus user: {} — that credential is \
             granted `>`/`>`, so per-principal permissions are not in force for them, and the \
             server is still serving a users.conf rendered. Give each holder \
             its own pair (`noo cluster nats-creds rotate <node>`), then `noo cluster nats-users \
             render` (which never renders the shared user) and `docker kill -s HUP noo-nats`",
            legacy.len(),
            legacy.join(", ")
        ),
    )
}

/// `user@ip` for every connection in a `/connz?auth=1` body that presents a
/// legacy bus user. Pure, so the test can feed it a recorded body.
fn legacy_sessions(body: &serde_json::Value) -> Vec<String> {
    body.get("connections")
        .and_then(|v| v.as_array())
        .map(|conns| {
            conns
                .iter()
                .filter_map(|c| {
                    let user = c.get("authorized_user").and_then(|v| v.as_str())?;
                    if !LEGACY_BUS_USERS.contains(&user) {
                        return None;
                    }
                    let ip = c.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    Some(if name.is_empty() {
                        format!("{user}@{ip}")
                    } else {
                        format!("{user}@{ip} ({name})")
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn check_postgres(state: &Arc<AppState>) -> CheckResult {
    let fut = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db);
    match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(Ok(_)) => ok("postgres", true, "SELECT 1"),
        Ok(Err(e)) => fail("postgres", true, format!("query failed: {e}")),
        Err(_) => fail("postgres", true, "5s timeout on SELECT 1".into()),
    }
}

async fn check_pgvector(state: &Arc<AppState>) -> CheckResult {
    let fut = sqlx::query_scalar::<_, Option<String>>(
        "SELECT extversion FROM pg_extension WHERE extname = 'vector'",
    )
    .fetch_optional(&state.db);
    match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(Ok(Some(Some(v)))) => ok("pgvector", true, format!("version {v}")),
        Ok(Ok(_)) => fail("pgvector", true, "extension not installed".into()),
        Ok(Err(e)) => fail("pgvector", true, format!("query failed: {e}")),
        Err(_) => fail("pgvector", true, "5s timeout".into()),
    }
}

/// Tables the MESH chain creates. Required on every install, always.
const MESH_BASELINE_TABLES: &[&str] = &["noo_nats_dlq", "noo_security_audit"];

/// Tables the TRELLION add-on's memory Alembic env creates. Required only
/// when trellion is enabled.
const TRELLION_BASELINE_TABLES: &[&str] =
    &["noo_conversations", "noo_entries", "pages", "noo_temporal_edges"];

async fn check_baseline_tables(state: &Arc<AppState>) -> CheckResult {
    // Sanity check that the migrations ran. Resolved via to_regclass so the
    // pool's search_path decides the schema: these span mesh AND trellion,
    // which on fresh installs live in their own schemas (a
    // table_schema='public' filter here crash-looped the first virgin install
    // on 2026-08-06, right after a clean migration).
    //
    // The trellion four are conditional, and that is a FIX rather than a
    // relaxation. This check required all six unconditionally, so a
    // `addons: {trellion: false}` install could never boot: the launcher
    // correctly did not start trellion, its migrations therefore never ran,
    // and the gateway aborted on a critical failure. Every other surface —
    // the 503 degradation contract, the launcher's trellion-off path,
    // `/health`'s addons.trellion=disabled — said trellion was optional while
    // this one made it mandatory in fact. Turning it off appeared to work
    // only on an established install, where the tables already existed from
    // before.
    //
    // With trellion ON the requirement is unchanged, so the case this check
    // was written for (migrations have not run yet) still fails closed.
    let trellion_on = crate::addons::enabled("trellion");
    let mut wanted: Vec<&str> = MESH_BASELINE_TABLES.to_vec();
    if trellion_on {
        wanted.extend_from_slice(TRELLION_BASELINE_TABLES);
    }
    let total = wanted.len() as i64;
    let owned: Vec<String> = wanted.iter().map(|s| s.to_string()).collect();

    let fut = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM unnest($1::text[]) AS t(name) \
         WHERE to_regclass(t.name) IS NOT NULL",
    )
    .bind(&owned)
    .fetch_one(&state.db);
    match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(Ok(n)) if n == total => ok(
            "baseline_tables",
            true,
            format!(
                "{n}/{total} present ({})",
                if trellion_on { "mesh + trellion" } else { "mesh; trellion add-on off" }
            ),
        ),
        Ok(Ok(n)) => fail(
            "baseline_tables",
            true,
            format!(
                "only {n}/{total} core tables — {} migrations have not run",
                if trellion_on { "mesh/trellion" } else { "mesh" }
            ),
        ),
        Ok(Err(e)) => fail("baseline_tables", true, format!("query failed: {e}")),
        Err(_) => fail("baseline_tables", true, "5s timeout".into()),
    }
}

async fn check_nats(state: &Arc<AppState>) -> CheckResult {
    // Flush publishes a short message and waits for the server to ack —
    // a cheap end-to-end probe that the connection is healthy.
    let fut = state.nats.flush();
    match tokio::time::timeout(Duration::from_secs(3), fut).await {
        Ok(Ok(())) => ok("nats", false, "flush ok"),
        Ok(Err(e)) => fail("nats", false, format!("flush failed: {e}")),
        Err(_) => fail("nats", false, "3s timeout — NATS may be degraded".into()),
    }
}

async fn check_embedding_service(_state: &Arc<AppState>) -> CheckResult {
    // Embedding URL from env/yaml — same resolution as every embed call
    // site (embedding_client). If no URL is configured the check passes
    // as "not applicable". TEI_URL is a legacy env alias kept for parity
    // with Python's embedding worker.
    let has_url = std::env::var("TEI_URL").ok().filter(|v| !v.is_empty()).is_some()
        || !crate::config::env_or_yaml(
            "PAGEINDEX_EMBEDDING_URL",
            |c| c.services.embedding_url.clone(),
            "",
        )
        .is_empty();
    if !has_url {
        return ok("embedding_service", false, "no URL configured (skipped)");
    }
    // Health path depends on the wire format (tei /health, openai
    // /v1/models, ollama /api/tags).
    let probe_url = crate::embedding_client::resolve().health_url();
    let client = crate::tls::cluster_client();
    match client.get(&probe_url).timeout(Duration::from_secs(3)).send().await {
        Ok(r) if r.status().is_success() => {
            ok("embedding_service", false, format!("{probe_url} → {}", r.status()))
        }
        Ok(r) => fail(
            "embedding_service",
            false,
            format!("{probe_url} → HTTP {}", r.status()),
        ),
        Err(e) => fail("embedding_service", false, format!("probe failed: {e}")),
    }
}

/// Dims preflight: embed one probe text and compare the returned vector
/// length against the pgvector column dims actually in the store
/// (`noo_entries.embedding` — the chunk/conversation store; entity
/// vectors live in a separate store but share EMBEDDING_DIM). On
/// mismatch this logs LOUDLY and the failure is surfaced in the
/// preflight report; embedding WRITERS (the Python/trellion embed
/// workers) run the same guard and refuse to write. Reads are unaffected.
///
/// On success the served model + dims are recorded in `noo_settings`
/// (keys `embedding_model` / `embedding_dims`) so operators and the UI
/// can see what the store was embedded with.
async fn check_embedding_dims(state: &Arc<AppState>) -> CheckResult {
    let endpoint = crate::embedding_client::resolve();
    if endpoint.url.is_empty() {
        return ok("embedding_dims", false, "no URL configured (skipped)");
    }

    // Store-side dims: atttypmod of a vector column IS its dimension.
    let store_dims: Option<i32> = sqlx::query_scalar(
        "SELECT a.atttypmod FROM pg_attribute a \
         JOIN pg_class c ON a.attrelid = c.oid \
         WHERE c.relname = 'noo_entries' AND a.attname = 'embedding'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(store_dims) = store_dims.filter(|d| *d > 0) else {
        return ok("embedding_dims", false, "no vector column found (skipped)");
    };

    let served_dims = match endpoint
        .embed_one("dimension probe", Duration::from_secs(10))
        .await
    {
        Ok(v) => v.len() as i32,
        Err(e) => {
            return fail("embedding_dims", false, format!("probe embed failed: {e}"));
        }
    };

    if served_dims != store_dims {
        tracing::error!(
            served_dims,
            store_dims,
            url = %endpoint.url,
            api_format = %endpoint.api_format,
            model = %endpoint.model,
            "EMBEDDING DIMENSION MISMATCH — the configured embedding backend \
             returns {served_dims}-dim vectors but the store columns are \
             vector({store_dims}). Embedding WRITES are refused by the embed \
             workers until this is fixed (searches over existing vectors still \
             work). Either point PAGEINDEX_EMBEDDING_URL/_BACKEND/_MODEL back \
             at a {store_dims}-dim model, or re-embed the store via \
             POST /api/memory/embed/start (batch-index machinery) after \
             migrating the vector columns to the new dimension."
        );
        return fail(
            "embedding_dims",
            false,
            format!(
                "backend serves {served_dims}-dim vectors, store is vector({store_dims}) — \
                 embed writes refused; see log for re-embed instructions"
            ),
        );
    }

    // Record what the store is embedded with (best-effort).
    let _ = sqlx::query(
        "INSERT INTO noo_settings (key, value, category, updated_by) \
         VALUES ('embedding_model', $1, 'memory', 'preflight'), \
                ('embedding_dims', $2, 'memory', 'preflight') \
         ON CONFLICT (key) DO UPDATE \
         SET value = EXCLUDED.value, updated_by = 'preflight', updated_at = NOW()",
    )
    .bind(&endpoint.model)
    .bind(served_dims.to_string())
    .execute(&state.db)
    .await;

    ok(
        "embedding_dims",
        false,
        format!("{served_dims} dims (model {}, {})", endpoint.model, endpoint.api_format),
    )
}

async fn check_tool_schemas(state: &Arc<AppState>) -> CheckResult {
    let schemas = state.tool_schemas.read().await;
    let n = schemas.len();
    if n > 0 {
        ok("tool_schemas", false, format!("{n} tools loaded"))
    } else {
        fail(
            "tool_schemas",
            false,
            "zero tool schemas — config/tools.json missing or empty".into(),
        )
    }
}


/// Every tool declared in `config/tools.json` must have something serving its
/// NATS subject — and specifically an EXACT subscription, not the wildcard.
///
/// Why the wildcard distinction matters: `worker_pool.py` subscribes to
/// `worker.>` as a last-resort fallback, so *every* `worker.*` subject has a
/// responder whether or not a handler exists. A tool pointing at a subject
/// nobody implements therefore does not fail loudly — it is answered by
/// `_handle_catchall_api`, which is degradation dressed as success. This
/// check looks past the wildcard and asks whether the subject is really
/// implemented.
///
/// The inverse is reported too: `worker.tool.*` subjects with a responder
/// that no tool selects. Those are dead handlers — five of them were found
/// this way, including `worker.tool.record`, which Rust stopped
/// publishing in April 2026 while the handler stayed behind.
///
/// Reads NATS's monitoring endpoint (`/subsz`) rather than probing with a
/// request, because probing a tool subject would EXECUTE the tool —
/// `worker.tool.python` runs arbitrary code. Never critical: a monitoring
/// endpoint that is unreachable is not a reason to refuse to serve.
async fn check_tool_subjects(state: &Arc<AppState>) -> CheckResult {
    let raw = state.tools_json_raw.read().await;
    let n = raw
        .get("core_tools")
        .and_then(|t| t.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    drop(raw);
    // Cannot be answered here: the Python worker pool subscribes ~40s AFTER
    // preflight runs, so every subject would look unimplemented. Verified by
    // `verify_subjects_when_ready`, spawned after startup.
    ok(
        "tool_subjects",
        false,
        format!("{n} tool(s) declared — responders verified after worker pool registers"),
    )
}

/// Report Python handlers that a Rust route has already replaced.
///
/// The ledger (`crate::ported`) records what each port superseded; this asks
/// NATS which of those subjects still have a Python subscriber. Anything
/// listed here is dead code with a Rust owner — deletable, with the route
/// that replaced it named.
///
/// Wildcards are ignored for the same reason as `check_tool_subjects`:
/// `worker_pool.py` subscribes to `worker.>`, so a subject "having a
/// responder" is meaningless unless the subscription is exact.
///
/// Never critical, and never a failure: leftover Python is untidy, not
/// broken. It reports `ok` either way and puts the work in the detail line.
async fn check_ported_subjects() -> CheckResult {
    // Same startup race as check_tool_subjects — deferred.
    ok(
        "ported_subjects",
        false,
        format!(
            "{} ported route(s) — Python leftovers reported after worker pool registers",
            crate::ported::all().len()
        ),
    )
}

/// Exact (non-wildcard) subject subscriptions, from NATS monitoring.
///
/// Shared by the tool and ledger checks so they cannot disagree about what
/// "has a responder" means.
async fn nats_exact_subjects() -> Result<std::collections::BTreeSet<String>, String> {
    let (base, client) = nats_monitor_endpoint();
    let url = format!("{base}/subsz?subs=1");

    let body = match tokio::time::timeout(Duration::from_secs(5), client.get(&url).send()).await {
        Ok(Ok(r)) => r
            .json::<serde_json::Value>()
            .await
            .map_err(|e| format!("monitoring returned non-JSON: {e}"))?,
        Ok(Err(e)) => return Err(format!("monitoring unreachable at {url}: {e}")),
        Err(_) => return Err(format!("5s timeout on {url}")),
    };

    let mut exact = std::collections::BTreeSet::new();
    if let Some(list) = body.get("subscriptions_list").and_then(|v| v.as_array()) {
        for sub in list {
            if let Some(s) = sub.get("subject").and_then(|v| v.as_str()) {
                if !s.contains('>') && !s.contains('*') {
                    exact.insert(s.to_string());
                }
            }
        }
    }
    if exact.is_empty() {
        return Err("monitoring reported no exact subscriptions".into());
    }
    Ok(exact)
}

/// Base URL of the NATS monitoring endpoint, and the client that may read
/// it.
///
/// `:8222` was plain HTTP with no auth, and every container
/// on `noo-cluster` could read it — `/connz?auth=1` lists the bus username
/// and each client's IP, `/subsz` every subject, `/jsz` every stream. That
/// network carries third-party images (vllm, ollama, grafana, loki, the
/// headless browser that fetches untrusted pages), none of which has any
/// business enumerating the bus. Binding the listener to the container's
/// loopback would close it to them, but it also breaks the operator's
/// host-side `curl 127.0.0.1:8222` diagnostic (Docker's published port
/// forwards to the container's routable address, not its loopback) — that
/// trade was examined and rejected once already, in audit M-3.
///
/// So the TLS profile serves monitoring as `https_port` behind the SAME
/// `tls { verify: true }` block the bus uses: reading it now takes a
/// cluster-CA client certificate. The gateway has one; the third-party
/// containers do not. The scheme follows `NATS_URL` because the same config
/// file decides both listeners. `NOO_NATS_MONITOR_URL` overrides the whole
/// base for an operator who has moved or closed the endpoint.
fn nats_monitor_endpoint() -> (String, reqwest::Client) {
    if let Ok(u) = std::env::var("NOO_NATS_MONITOR_URL") {
        let u = u.trim().trim_end_matches('/').to_string();
        if !u.is_empty() {
            let client = if u.starts_with("https://") {
                crate::tls::cluster_client()
            } else {
                crate::tls::external_client()
            };
            return (u, client);
        }
    }
    let nats_url =
        crate::config::env_or_yaml("NATS_URL", |c| c.services.nats_url.clone(), "tls://nats:4222");
    let host = nats_url
        .rsplit('/')
        .next()
        .unwrap_or("nats:4222")
        .split(':')
        .next()
        .unwrap_or("nats");
    // Always mTLS: NATS runs the one shipped config (`nats-tls.conf`,
    // `https_port` behind `tls { verify: true }`), so the cluster client
    // presents this gateway's cert. The plaintext `nats.conf` profile that
    // used to make this follow the NATS_URL scheme no longer exists; a
    // `nats://` URL is a misconfiguration the bus connect refuses, not a
    // reason to probe monitoring in the clear.
    (format!("https://{host}:8222"), crate::tls::cluster_client())
}

/// Probe the monitoring endpoint at startup.
///
/// Advisory, never critical — nothing the gateway serves depends on it.
/// It exists so that closing or hardening `:8222` (N9) can never be a
/// SILENT loss: `spawn_subject_verification` reads `/subsz` to answer "which
/// declared tool subjects have no responder" and "which ported Python
/// handlers are still registered", and both of those questions simply stop
/// being asked if the endpoint is unreachable. This row says so at boot,
/// with the URL it tried.
async fn check_nats_monitoring() -> CheckResult {
    let (base, client) = nats_monitor_endpoint();
    let url = format!("{base}/varz");
    match tokio::time::timeout(Duration::from_secs(5), client.get(&url).send()).await {
        Ok(Ok(r)) if r.status().is_success() => ok("nats_monitoring", false, format!("{base} reachable")),
        Ok(Ok(r)) => fail(
            "nats_monitoring",
            false,
            format!("{url} returned {} — subject verification will be skipped", r.status()),
        ),
        Ok(Err(e)) => fail(
            "nats_monitoring",
            false,
            format!(
                "{url} unreachable ({e}) — subject verification is DISABLED (declared-but-unimplemented                  tool subjects and superseded Python handlers will not be reported). Set                  NOO_NATS_MONITOR_URL if the endpoint moved; the TLS profile needs this gateway's                  client certificate"
            ),
        ),
        Err(_) => fail(
            "nats_monitoring",
            false,
            format!("5s timeout on {url} — subject verification will be skipped"),
        ),
    }
}

/// File-backed secrets (`secret_env`): refuse to start when a name in the
/// manifest is delivered BOTH as `NAME` and as `NAME_FILE` (a compose /
/// launcher skew — one of them is stale and nothing says which), or when a
/// named file cannot be read or is empty (a broken mount, reported here
/// once with its path instead of as a scatter of auth failures downstream).
///
/// Critical: with env delivery — every install today — neither condition
/// can occur, so this costs nothing; after the compose flip a mis-mounted
/// secret is exactly the kind of failure preflight exists to make visible.
fn check_secret_files() -> CheckResult {
    let both = crate::config::secret_env::both_set_conflicts();
    let broken = crate::config::secret_env::file_errors();
    if both.is_empty() && broken.is_empty() {
        return ok(
            "secret_files",
            true,
            format!(
                "{} file-backed secret names checked, no env/file skew",
                crate::config::secret_env::FILE_BACKED_SECRETS.len()
            ),
        );
    }
    let mut parts = Vec::new();
    if !both.is_empty() {
        parts.push(format!(
            "both NAME and NAME_FILE are set for {} — a compose/launcher skew, \
             not a choice; deliver each secret ONE way (unset the env value, or \
             the _FILE pointer)",
            both.join(", ")
        ));
    }
    for e in &broken {
        parts.push(e.to_string());
    }
    fail("secret_files", true, parts.join("; "))
}

fn ok(name: &'static str, critical: bool, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name,
        critical,
        ok: true,
        detail: detail.into(),
    }
}

fn fail(name: &'static str, critical: bool, detail: String) -> CheckResult {
    CheckResult {
        name,
        critical,
        ok: false,
        detail,
    }
}

/// Verify subject wiring once the Python worker pool has actually subscribed.
///
/// Split out of preflight because of a real startup race: preflight runs
/// immediately after `AppState::new`, but `worker_pool.py` registers its
/// subjects roughly 40 seconds later. Asking at preflight time reports every
/// subject as unimplemented — the first deployment of these checks did
/// exactly that, warning that all four tool subjects had no responder while
/// the Python side was still booting.
///
/// A check that cries wolf on every start is worse than no check, so this
/// waits for the worker pool to appear (any exact `worker.*` subscription),
/// then answers both questions once:
///
///   - tool subjects declared in `tools.json` with no exact responder
///   - Python handlers superseded by a Rust route (`crate::ported`) that are
///     still registered, i.e. deletable
///
/// Advisory only: it logs and never affects startup or health.
pub fn spawn_subject_verification(state: Arc<AppState>) {
    tokio::spawn(async move {
        // Poll for the worker pool. Generous ceiling — a cold Python start
        // with ML imports is slow, and being late costs nothing here.
        const MAX_WAIT: Duration = Duration::from_secs(180);
        const INTERVAL: Duration = Duration::from_secs(10);
        let started = tokio::time::Instant::now();

        let exact = loop {
            match nats_exact_subjects().await {
                Ok(e) if e.iter().any(|s| s.starts_with("worker.")) => break e,
                Ok(_) | Err(_) if started.elapsed() < MAX_WAIT => {
                    tokio::time::sleep(INTERVAL).await;
                }
                Ok(_) => {
                    tracing::warn!(
                        "subject_verification skipped: no worker.* subscriptions after {}s — is the Python worker pool running? (NOO_WORKER_SUPERVISOR=inprocess: check this container's logs for spawn failures; =external: is the noo-trellion container up?)",
                        MAX_WAIT.as_secs()
                    );
                    return;
                }
                Err(e) => {
                    // Loud on purpose: the monitoring
                    // endpoint is now mTLS-only on the TLS profile, so a
                    // missing or wrong client certificate would otherwise
                    // just make these two checks quietly stop happening.
                    tracing::warn!(
                        error = %e,
                        "subject_verification skipped: NATS monitoring unreachable — declared-but-unimplemented tool subjects and superseded Python handlers are NOT being reported. See the nats_monitoring preflight row"
                    );
                    return;
                }
            }
        };

        // ── tools declared but unimplemented ──
        let raw = state.tools_json_raw.read().await;
        let mut required: std::collections::BTreeSet<String> = Default::default();
        if let Some(tools) = raw.get("core_tools").and_then(|t| t.as_array()) {
            for t in tools {
                required.insert(
                    t.get("nats_subject")
                        .and_then(|s| s.as_str())
                        .unwrap_or("worker.tool.generic")
                        .to_string(),
                );
            }
        }
        drop(raw);

        let missing: Vec<&String> = required.difference(&exact).collect();
        if missing.is_empty() {
            tracing::info!(count = required.len(), "subject_verification.tools_ok");
        } else {
            tracing::warn!(
                missing = %missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                "subject_verification.tools_missing: declared in tools.json with no exact responder — \
                 the worker.> wildcard would absorb these silently"
            );
        }

        let orphans: Vec<&String> = exact
            .iter()
            .filter(|s| s.starts_with("worker.tool.") && !required.contains(*s))
            .collect();
        if !orphans.is_empty() {
            tracing::info!(
                orphans = %orphans.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                "subject_verification.tool_orphans: handlers no tool selects — deletable"
            );
        }

        // ── Python handlers a Rust route already replaced ──
        let removable: Vec<String> = crate::ported::all()
            .iter()
            .filter(|p| exact.contains(p.supersedes))
            .map(|p| format!("{} (replaced by {} {})", p.supersedes, p.method, p.path))
            .collect();
        if removable.is_empty() {
            tracing::info!("subject_verification.ported_clean: no superseded Python handlers remain");
        } else {
            tracing::info!(
                removable = %removable.join("; "),
                "subject_verification.ported_removable: superseded by Rust, still registered in Python"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded `/connz?auth=1` body. The field names are the server's,
    /// not ours: `authorized_user` is what NATS calls the user a session
    /// presented, and it is only present with `auth=1`.
    fn connz(users: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "connections": users.iter().enumerate().map(|(i, u)| serde_json::json!({
                "cid": i + 1,
                "ip": format!("172.20.0.{}", i + 10),
                "name": "",
                "authorized_user": u,
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn a_legacy_session_is_seen_even_when_we_are_not_the_one_on_it() {
        // The whole point of asking the SERVER: this gateway can be on its
        // own principal while a worker or a stale node still holds `noo`,
        // and nothing in this process's environment says so.
        let found = legacy_sessions(&connz(&["gateway", "node-host9", "noo"]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("noo@"), "{found:?}");
    }

    #[test]
    fn the_committed_placeholder_counts_as_legacy() {
        // A session authenticated as `noo-unconfigured` means the server is
        // serving the committed baseline users.conf — the render never ran.
        assert_eq!(legacy_sessions(&connz(&["noo-unconfigured"])).len(), 1);
    }

    #[test]
    fn a_fully_isolated_bus_reports_nothing() {
        assert!(legacy_sessions(&connz(&["gateway", "worker", "node-host3"])).is_empty());
    }

    #[test]
    fn a_body_without_auth_1_is_not_read_as_clean_by_accident() {
        // Without `auth=1` the server omits `authorized_user` entirely. The
        // filter must key on that field's ABSENCE meaning "unknown", never
        // on a default that silently reads as a non-legacy user.
        let body = serde_json::json!({"connections": [{"cid": 1, "ip": "1.2.3.4"}]});
        assert!(legacy_sessions(&body).is_empty());
        // ...and the guard above must actually be capable of finding one:
        assert!(!legacy_sessions(&connz(&["noo"])).is_empty());
    }

    /// the monitoring scheme has to FOLLOW the bus config,
    /// because one config file decides both listeners. Getting this wrong
    /// does not fail loudly — it just makes subject verification stop
    /// happening — so it is pinned here.
    #[test]
    fn monitor_endpoint_is_always_mtls_and_follows_the_nats_host() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NOO_NATS_MONITOR_URL");

        std::env::set_var("NATS_URL", "tls://nats:4222");
        assert_eq!(nats_monitor_endpoint().0, "https://nats:8222");

        // No plaintext profile exists: the scheme of NATS_URL does not
        // change the monitoring endpoint, only its host.
        std::env::set_var("NATS_URL", "nats://elsewhere:4222");
        assert_eq!(nats_monitor_endpoint().0, "https://elsewhere:8222");

        // The override wins outright, trailing slash and all.
        std::env::set_var("NOO_NATS_MONITOR_URL", "https://elsewhere:9222/");
        assert_eq!(nats_monitor_endpoint().0, "https://elsewhere:9222");

        std::env::remove_var("NOO_NATS_MONITOR_URL");
        std::env::remove_var("NATS_URL");
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[test]
    fn the_baseline_split_matches_who_owns_each_table() {
        // The mesh chain creates exactly two of the six (verified against
        // migrations/0001_baseline.sql); the other four come from trellion's
        // memory Alembic env. Getting this list wrong is silent in both
        // directions: too many in MESH_ and a trellion-less install cannot
        // boot again, too many in TRELLION_ and a real "migrations did not
        // run" goes unreported on the install that needs to hear it.
        assert_eq!(MESH_BASELINE_TABLES, &["noo_nats_dlq", "noo_security_audit"]);
        assert_eq!(
            TRELLION_BASELINE_TABLES,
            &["noo_conversations", "noo_entries", "pages", "noo_temporal_edges"]
        );
        for t in TRELLION_BASELINE_TABLES {
            assert!(
                !MESH_BASELINE_TABLES.contains(t),
                "{t} is claimed by both chains; the count arithmetic assumes it is not"
            );
        }
    }
}
