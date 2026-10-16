// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The foreign-CLI driver: a vendor's headless CLI (Copilot CLI, Claude
//! Code, Codex CLI) as the node's task executor.
//!
//! `noo-gateway harness` stays the runner for every kind: it holds the bus,
//! acks, takes the concurrency permit, publishes `harness_result` and
//! checkpoints through the rail. For a kind other than `noo` it hands each
//! task (and each turn) here instead of to the native loop. One CLI
//! invocation is one loop:
//!
//! 1. the loopback wire translator starts in front of the pinned endpoint;
//! 2. a user-door key is minted over the rail (`door_key`): an ordinary,
//!    short-lived `noo_service_keys` row bound to the turn's person;
//! 3. the CLI runs in the task's own workspace, with a HOME of its own, an
//!    environment built from NOTHING (no bus pair, no node-agent bearer, no
//!    turn token), the kind's `lane` and `telemetry_off` merged last, and an
//!    MCP config naming `{NOO_GATEWAY_URL}/mcp/user` with the door key
//!    (`launch.mcp`: `config-file`, a `{"mcpServers": ...}` JSON file; or
//!    `config-file:codex-toml`, Codex's whole `$CODEX_HOME/config.toml`,
//!    which also carries the model provider, since Codex takes its base URL
//!    from no variable);
//! 4. its verdict (`NOO_RESULT:` / `NOO_FAILED:` on the last such line) is
//!    the task's `noo_task_done`, carried by the rail op `task_done`;
//! 5. usage is reported, the loop is checkpointed, the key revoked, the
//!    translator stopped.
//!
//! Before each invocation the driver asks the gateway's token switch
//! (`budget_check`, i83 G) whether another loop may start — never during
//! one. A CLI that cannot go on without its owner ends with `NOO_QUESTION:`;
//! the question goes over the rail (`task_ask`) and the task waits for the
//! answer.
//!
//! Nothing streams mid-run in this cut: a turn gets one `content` event with
//! the answer, then `harness_result` (sent by the caller).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use crate::coordinator::{CoordinatorResult, HarnessOp, RemoteRuntime, ResolvedBackend, TaskRuntime, TurnRequest, UsageStats};
use crate::harness::translator::{Translator, UsageTotals};
use crate::harness_kinds::{HarnessKind, Launch};
use crate::tasks::TaskRequest;

/// Bytes kept of each of the CLI's stdout and stderr; the rest is read and
/// dropped, so a chatty CLI cannot fill the harness's memory (the unit caps
/// it at 1 GiB).
pub const OUTPUT_CAP: usize = 256 * 1024;
/// The line a CLI ends with when the task's objective is achieved.
pub const RESULT_MARK: &str = "NOO_RESULT:";
/// The line a CLI ends with when the objective cannot be achieved.
pub const FAILED_MARK: &str = "NOO_FAILED:";
/// The line a CLI ends with when it needs its owner to decide something.
pub const QUESTION_MARK: &str = "NOO_QUESTION:";
/// What goes in a CLI's provider-key variable: the loopback translator takes
/// no key, but a CLI may refuse to start without one.
pub const PLACEHOLDER_KEY: &str = "noo-loopback-no-key";
/// The MCP server name the CLI sees noomesh's tools under. The kind table's
/// tool allowlists (`mcp__noomesh`, `--allow-tool=noomesh`) name it too.
pub const MCP_SERVER_NAME: &str = "noomesh";
/// The `launch.mcp` value for a CLI that reads a `{"mcpServers": ...}`
/// file named on its command line (`{mcp_config}`).
pub const MCP_CONFIG_FILE: &str = "config-file";
/// The `launch.mcp` value for Codex CLI: the driver writes the whole
/// `config.toml` in the CLI's home (`launch.home_env`), with the loopback
/// translator as the model provider and the user door as an MCP server.
pub const MCP_CODEX_TOML: &str = "config-file:codex-toml";
/// The model provider id the Codex config names (`openai`, `ollama` and
/// `lmstudio` are Codex's reserved ids).
pub const CODEX_PROVIDER: &str = "noomesh";

/// Whether a run gets noomesh's tools. Production always wires the user door
/// ([`McpWiring::Door`]); `noo-gateway harness probe` runs a CLI with NO MCP
/// server and no gateway at all ([`McpWiring::None`]): no door key is
/// minted, no `mcpServers` file is written, and the command's
/// `{mcp_config}` arguments (with the flag that takes each) are left out.
#[derive(Debug, Clone, Copy)]
pub enum McpWiring<'a> {
    Door { gateway: &'a str, key: &'a str },
    None,
}

/// Everything a driven invocation needs that does not change per task.
#[derive(Debug, Clone)]
pub struct DriverCtx {
    pub node: String,
    pub gateway: String,
    pub kind: HarnessKind,
    pub launch: Launch,
    pub pinned: ResolvedBackend,
    /// Where per-task workspaces go (`NOO_HARNESS_WORKDIR`).
    pub workdir_root: PathBuf,
    /// `NOO_HARNESS_KEEP_WORKDIR=1`: leave workspaces for debugging.
    pub keep_workdir: bool,
    /// One invocation's wall-clock limit (`NOO_HARNESS_TURN_TIMEOUT_SECS`).
    pub timeout: Duration,
    /// The cluster CA, handed to the CLI as `NODE_EXTRA_CA_CERTS` so it can
    /// reach the user door over the cluster's TLS.
    pub ca_path: Option<String>,
    /// `PATH` and `LANG` for the CLI: the only values taken from the
    /// harness's own environment.
    pub path: String,
    pub lang: String,
    /// Whether a jail can be built here and, once the startup self-test
    /// has run, whether it passed (i119, `jail::gate`); a refusal
    /// checkpoints the task with the reason and the CLI never runs.
    pub jail_probe: crate::harness::jail::Probe,
}

impl DriverCtx {
    /// Build from the harness's environment. Refuses a kind this driver
    /// cannot run: `noo`, an unknown kind, or a launch recipe that is
    /// missing, still `unverified:`, or wants an MCP wiring not implemented.
    pub fn from_env(node: &str, gateway: &str, kind_name: &str, pinned: ResolvedBackend) -> Result<Self> {
        let kind = crate::harness_kinds::get(kind_name).ok_or_else(|| anyhow!("unknown harness kind {kind_name:?}"))?;
        Self::new(node, gateway, kind, pinned, &|k| std::env::var(k).ok())
    }

    pub fn new(node: &str, gateway: &str, kind: &HarnessKind, pinned: ResolvedBackend, get: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let launch = validate_kind(kind)?;
        let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let workdir_root = set("NOO_HARNESS_WORKDIR").map(PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("noo-harness"));
        let timeout = Duration::from_secs(set("NOO_HARNESS_TURN_TIMEOUT_SECS").and_then(|v| v.trim().parse().ok()).filter(|s| *s > 0).unwrap_or(900));
        Ok(Self {
            node: node.to_string(),
            gateway: gateway.trim_end_matches('/').to_string(),
            kind: kind.clone(),
            launch,
            pinned,
            workdir_root,
            keep_workdir: set("NOO_HARNESS_KEEP_WORKDIR").is_some_and(|v| v.trim() == "1"),
            timeout,
            ca_path: set("NOO_TLS_CA"),
            path: set("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into()),
            lang: set("LANG").unwrap_or_else(|| "C.UTF-8".into()),
            jail_probe: crate::harness::jail::gate,
        })
    }
}

/// The launch recipe of a kind this driver can run, or why not.
pub fn validate_kind(kind: &HarnessKind) -> Result<Launch> {
    if kind.kind == "noo" {
        bail!("kind noo runs the native loop, not the driver");
    }
    let launch = kind.launch.clone().ok_or_else(|| anyhow!("kind {} has no launch recipe", kind.kind))?;
    if launch.command.is_empty() {
        bail!("kind {}: launch.command is empty", kind.kind);
    }
    let mut fields: Vec<&str> = vec![&launch.model_url_env, &launch.model_env, &launch.mcp, &launch.model_url_suffix];
    fields.extend(launch.command.iter().map(String::as_str));
    if let Some(v) = fields.iter().find(|v| v.starts_with("unverified:")) {
        bail!("kind {}: its launch recipe is not verified yet ({v})", kind.kind);
    }
    match launch.mcp.as_str() {
        MCP_CONFIG_FILE => {
            if launch.model_url_env.trim().is_empty() || launch.model_env.trim().is_empty() {
                bail!("kind {}: launch names no model variables", kind.kind);
            }
        }
        // The config file carries the model; a home is where it goes.
        MCP_CODEX_TOML => {
            if launch.home_env.as_deref().is_none_or(|h| h.trim().is_empty()) {
                bail!("kind {}: {MCP_CODEX_TOML} needs launch.home_env, the directory its config.toml goes in", kind.kind);
            }
        }
        other => bail!("kind {}: MCP wiring {other:?} is not one this driver implements ({MCP_CONFIG_FILE:?}, {MCP_CODEX_TOML:?})", kind.kind),
    }
    Ok(launch)
}

// ── the rail, as the driver needs it ────────────────────────────────────

/// A door key as the rail hands it over.
#[derive(Debug, Clone)]
pub struct DoorKey {
    pub key: String,
    pub key_id: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// What the driver asks of the gateway. [`RemoteRuntime`] in production; a
/// recording double in the tests.
#[allow(async_fn_in_trait)]
pub(crate) trait DriverRail {
    /// `task_checkpoint`; returns the task's state after it.
    async fn checkpoint(&mut self, task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String>;
    /// `task_done`: the CLI's verdict on its task.
    async fn task_done(&self, task_id: &str, result: &str, failed: bool) -> Result<String>;
    async fn door_key(&self) -> Result<DoorKey>;
    /// Best effort: an unrevoked key still dies at its expiry.
    async fn door_key_revoke(&self, key_id: &str);
    /// `session_save`, best effort.
    async fn save(&self, role: &str, content: &str);
    async fn report_usage(&self, usage: &UsageTotals, model: &str, kind: &str, task_id: Option<&str>);
    /// `budget_check`: the loop-boundary token switch.
    async fn budget_check(&mut self, task_id: &str) -> Result<crate::task_budget::BudgetCheck>;
    /// `task_ask`: the CLI's question to the task's owner.
    async fn task_ask(&self, task_id: &str, question: &str) -> Result<()>;
}

impl DriverRail for RemoteRuntime {
    async fn checkpoint(&mut self, task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String> {
        TaskRuntime::checkpoint(self, task_id, loops, note, exhausted).await
    }

    async fn task_done(&self, task_id: &str, result: &str, failed: bool) -> Result<String> {
        let v = self.call(HarnessOp::TaskDone { task_id: task_id.to_string(), result: result.to_string(), failed }).await?;
        Ok(v.get("state").and_then(|s| s.as_str()).unwrap_or("").to_string())
    }

    async fn door_key(&self) -> Result<DoorKey> {
        let v = self.call(HarnessOp::DoorKey).await?;
        parse_door_key(&v)
    }

    async fn door_key_revoke(&self, key_id: &str) {
        if let Err(e) = self.call(HarnessOp::DoorKeyRevoke { key_id: key_id.to_string() }).await {
            tracing::warn!(error = %e, key_id, "harness driver: door key not revoked; it dies at its expiry");
        }
    }

    async fn save(&self, role: &str, content: &str) {
        if let Err(e) = self.call(HarnessOp::SessionSave { role: role.to_string(), content: content.to_string(), metadata: None }).await {
            tracing::warn!(error = %e, role, "harness driver: session message not saved");
        }
    }

    async fn report_usage(&self, usage: &UsageTotals, model: &str, kind: &str, task_id: Option<&str>) {
        if let Err(e) = RemoteRuntime::report_usage(self, usage, model, kind, task_id).await {
            tracing::warn!(error = %e, kind, "harness driver: usage not reported");
        }
    }

    async fn budget_check(&mut self, task_id: &str) -> Result<crate::task_budget::BudgetCheck> {
        RemoteRuntime::budget_check(self, task_id).await
    }

    async fn task_ask(&self, task_id: &str, question: &str) -> Result<()> {
        RemoteRuntime::task_ask(self, task_id, question).await
    }
}

fn parse_door_key(v: &Value) -> Result<DoorKey> {
    let key = v.get("key").and_then(|k| k.as_str()).filter(|k| !k.is_empty()).ok_or_else(|| anyhow!("door_key: reply has no key"))?;
    let key_id = v.get("key_id").and_then(|k| k.as_str()).unwrap_or_default();
    let expires_at = v
        .get("expires_at")
        .and_then(|e| e.as_str())
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
        .map(|e| e.with_timezone(&chrono::Utc));
    Ok(DoorKey { key: key.to_string(), key_id: key_id.to_string(), expires_at })
}

// ── the workspace ───────────────────────────────────────────────────────

/// One task's (or turn's) directory: `work/` is the CLI's cwd, `home/` its
/// HOME (and its config dir), `tmp/` its TMPDIR, and the MCP config file
/// with the door key sits beside them, mode 0600, removed after each run.
#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub work: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    keep: bool,
}

impl Workspace {
    pub fn create(base: &Path, id: &str, keep: bool) -> Result<Self> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("workspace id {id:?} is not a plain name");
        }
        let root = base.join(id);
        let ws = Self { work: root.join("work"), home: root.join("home"), tmp: root.join("tmp"), root, keep };
        for d in [&ws.work, &ws.home, &ws.tmp] {
            std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ws.root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(ws)
    }

    pub fn mcp_path(&self) -> PathBuf {
        self.root.join("noomesh-mcp.json")
    }

    /// The CLI's own config/state directory (`launch.home_env`), inside HOME.
    pub fn cli_home(&self, cli: &str) -> PathBuf {
        self.home.join(format!(".{cli}"))
    }

    /// Where `config-file:codex-toml` writes: `$CODEX_HOME/config.toml`.
    pub fn codex_config_path(&self, cli: &str) -> PathBuf {
        self.cli_home(cli).join("config.toml")
    }

    /// The config a kind's `launch.mcp` asks for, written 0600; its path is
    /// `{mcp_config}` in the command. Removed after each run.
    pub fn write_cli_config(&self, ctx: &DriverCtx, translator_url: &str, key: &str) -> Result<PathBuf> {
        self.write_cli_config_wired(ctx, translator_url, McpWiring::Door { gateway: &ctx.gateway, key })?
            .ok_or_else(|| anyhow!("kind {}: no CLI config written", ctx.kind.kind))
    }

    /// [`write_cli_config`](Self::write_cli_config) for either wiring.
    /// `None` = nothing to pass as `{mcp_config}` (a `config-file` kind run
    /// without MCP); Codex always gets its `config.toml`, which carries the
    /// model provider, with the `mcp_servers` table only under a door.
    pub fn write_cli_config_wired(&self, ctx: &DriverCtx, translator_url: &str, wiring: McpWiring<'_>) -> Result<Option<PathBuf>> {
        if ctx.launch.mcp != MCP_CODEX_TOML {
            return match wiring {
                McpWiring::Door { gateway, key } => self.write_mcp_config(gateway, key).map(Some),
                McpWiring::None => Ok(None),
            };
        }
        let cli = ctx.kind.cli.as_deref().unwrap_or(&ctx.kind.kind);
        let base = format!("{}{}", translator_url.trim_end_matches('/'), ctx.launch.model_url_suffix);
        let path = self.codex_config_path(cli);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let door = match wiring {
            McpWiring::Door { gateway, key } => Some((gateway, key)),
            McpWiring::None => None,
        };
        write_private(&path, codex_config(&base, &ctx.pinned.model, door).as_bytes())?;
        Ok(Some(path))
    }

    /// Write the MCP config naming the user door, readable by this user only.
    pub fn write_mcp_config(&self, gateway: &str, key: &str) -> Result<PathBuf> {
        let path = self.mcp_path();
        write_private(&path, serde_json::to_string_pretty(&mcp_config(gateway, key))?.as_bytes())?;
        Ok(path)
    }

    /// The jail for one run in this workspace: work, HOME and TMP
    /// read-write, the CLI config file and the cluster CA file read-only.
    pub fn jail_spec(&self, ctx: &DriverCtx, cli_config: &Path) -> crate::harness::jail::JailSpec {
        crate::harness::jail::JailSpec {
            workspace: self.work.clone(),
            home: self.home.clone(),
            tmp: self.tmp.clone(),
            ca_file: ctx.ca_path.as_deref().map(PathBuf::from),
            // The Codex config is inside HOME already; the MCP file is not.
            extra_ro: if cli_config.starts_with(&self.home) { Vec::new() } else { vec![cli_config.to_path_buf()] },
            data_root: None,
        }
    }

    /// Remove the workspace, unless it is kept for debugging.
    pub fn finish(self) {
        if self.keep {
            tracing::info!(path = %self.root.display(), "harness driver: workspace kept (NOO_HARNESS_KEEP_WORKDIR=1)");
        } else if let Err(e) = std::fs::remove_dir_all(&self.root) {
            tracing::warn!(path = %self.root.display(), error = %e, "harness driver: workspace not removed");
        }
    }
}

/// Write `bytes` to a fresh file at `path`, mode 0600 from creation.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

/// A TOML basic string. A JSON string literal is one: JSON's escapes
/// (`\"`, `\\`, `\n`, `\uXXXX`, ...) are all TOML escapes.
fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Codex CLI's `config.toml` for one run (`config-file:codex-toml`).
///
/// - The loopback translator is the model provider (`wire_api =
///   "responses"`, the only wire Codex speaks); no `env_key`, so no API
///   key is asked for, and no websocket transport, so every request is a
///   stateless `POST /responses`.
/// - The user door is the one MCP server, a streamable-HTTP server with the
///   door key as its bearer: the key is in this 0600 file only, never in
///   the CLI's environment.
/// - No approvals (`never`: a headless run has nobody to ask), and Codex's
///   OWN sandbox off (`danger-full-access`): every foreign CLI already runs
///   inside the harness's Landlock jail (harness/jail.rs), which confines
///   writes to the task's workspace, HOME and TMP and refuses to start the
///   CLI at all when it cannot jail. Codex's sandbox is bubblewrap, which
///   needs to mount; a process inside a Landlock domain may not change its
///   mounts, so the nested sandbox fails and Codex's shell tool silently
///   does nothing (seen in `harness probe`, 2026-10-16). One jail, ours.
/// - Every vendor channel off (docs/security/telemetry.md): analytics,
///   feedback, the OpenTelemetry exporters (metrics default to Statsig),
///   the update check, saved history, hosted web search.
///
/// `door` is the user door's `(gateway, key)`; `None` writes no
/// `[mcp_servers]` table at all (`harness probe`'s no-MCP run).
pub fn codex_config(base_url: &str, model: &str, door: Option<(&str, &str)>) -> String {
    let mcp = match door {
        Some((gateway, key)) => {
            let mcp_url = format!("{}/mcp/user", gateway.trim_end_matches('/'));
            let bearer = format!("Bearer {key}");
            format!(
                "[mcp_servers.{MCP_SERVER_NAME}]\n\
                 url = {mcp_url}\n\
                 http_headers = {{ Authorization = {bearer} }}\n\
                 \n",
                mcp_url = toml_str(&mcp_url),
                bearer = toml_str(&bearer),
            )
        }
        None => String::new(),
    };
    format!(
        "# Written by the noomesh harness for one run; removed when it ends.\n\
         model = {model}\n\
         model_provider = {provider}\n\
         approval_policy = \"never\"\n\
         sandbox_mode = \"danger-full-access\"\n\
         web_search = \"disabled\"\n\
         check_for_update_on_startup = false\n\
         \n\
         [model_providers.{CODEX_PROVIDER}]\n\
         name = {provider}\n\
         base_url = {base}\n\
         wire_api = \"responses\"\n\
         \n\
         {mcp}\
         [analytics]\n\
         enabled = false\n\
         \n\
         [feedback]\n\
         enabled = false\n\
         \n\
         [history]\n\
         persistence = \"none\"\n\
         \n\
         [otel]\n\
         exporter = \"none\"\n\
         trace_exporter = \"none\"\n\
         metrics_exporter = \"none\"\n",
        model = toml_str(model),
        provider = toml_str(CODEX_PROVIDER),
        base = toml_str(base_url),
    )
}

/// The MCP config a CLI loads: one HTTP server, the user door, the door key
/// as the bearer. The `{"mcpServers": {...}}` shape both Claude Code
/// (`--mcp-config`) and Copilot CLI (`--additional-mcp-config`) read; `tools`
/// is Copilot's required field, ignored by Claude Code.
pub fn mcp_config(gateway: &str, key: &str) -> Value {
    json!({"mcpServers": {MCP_SERVER_NAME: {
        "type": "http",
        "url": format!("{}/mcp/user", gateway.trim_end_matches('/')),
        "headers": {"Authorization": format!("Bearer {key}")},
        "tools": ["*"],
    }}})
}

// ── the environment ─────────────────────────────────────────────────────

/// A variable the CLI must never receive, whatever a table row says: the
/// bus pair and everything of noomesh's own (the node-agent bearer, the
/// cluster secret, the gateway's secrets, the turn token's carriers).
pub fn is_forbidden(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.starts_with("NATS_") || n.starts_with("NOO_")
}

/// The CLI's whole environment, built from nothing. Order matters and is
/// pinned by a test: the driver's own values, then the kind's `lane`, then
/// its `telemetry_off` LAST (a value earlier in the chain cannot switch a
/// vendor's reporting back on, as the node agent merges it), then every
/// forbidden name is stripped.
pub fn build_env(ctx: &DriverCtx, ws: &Workspace, translator_url: &str) -> BTreeMap<String, String> {
    let l = &ctx.launch;
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), ctx.path.clone());
    env.insert("HOME".to_string(), ws.home.display().to_string());
    env.insert("LANG".to_string(), ctx.lang.clone());
    env.insert("TMPDIR".to_string(), ws.tmp.display().to_string());
    env.insert("NO_COLOR".to_string(), "1".to_string());
    // Empty for a CLI that takes its model from the config the driver
    // writes (`config-file:codex-toml`).
    if !l.model_url_env.trim().is_empty() {
        env.insert(l.model_url_env.clone(), format!("{}{}", translator_url.trim_end_matches('/'), l.model_url_suffix));
    }
    if !l.model_env.trim().is_empty() {
        env.insert(l.model_env.clone(), ctx.pinned.model.clone());
    }
    for alias in &l.model_alias_envs {
        env.insert(alias.clone(), ctx.pinned.model.clone());
    }
    if let Some(k) = l.api_key_env.as_deref().filter(|k| !k.is_empty()) {
        env.insert(k.to_string(), PLACEHOLDER_KEY.to_string());
    }
    if let Some(h) = l.home_env.as_deref().filter(|h| !h.is_empty()) {
        let cli = ctx.kind.cli.as_deref().unwrap_or(&ctx.kind.kind);
        env.insert(h.to_string(), ws.cli_home(cli).display().to_string());
    }
    if let Some(ca) = &ctx.ca_path {
        env.insert("NODE_EXTRA_CA_CERTS".to_string(), ca.clone());
        if let Some(v) = l.ca_env.as_deref().filter(|v| !v.is_empty()) {
            env.insert(v.to_string(), ca.clone());
        }
    }
    for (k, v) in &ctx.kind.lane {
        env.insert(k.clone(), v.clone());
    }
    for (k, v) in &ctx.kind.telemetry_off {
        env.insert(k.clone(), v.clone());
    }
    env.retain(|k, _| !is_forbidden(k));
    env
}

/// `launch.command` with `{prompt}` and `{mcp_config}` filled in.
pub fn fill_command(command: &[String], prompt: &str, mcp_config: &Path) -> Vec<String> {
    let mcp = mcp_config.display().to_string();
    command.iter().map(|a| a.replace("{mcp_config}", &mcp).replace("{prompt}", prompt)).collect()
}

/// `launch.command` for a run with no MCP config ([`McpWiring::None`]): every
/// argument naming `{mcp_config}` is dropped, with the flag before it when
/// that flag takes it as its value (`--mcp-config {mcp_config}`); then
/// `{prompt}` is filled in. A flag that only switches MCP behaviour
/// (`--strict-mcp-config`) stays: strict with no config is no servers.
pub fn fill_command_without_mcp(command: &[String], prompt: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(command.len());
    for a in command {
        if a.contains("{mcp_config}") {
            if !a.starts_with('-') && out.last().is_some_and(|p| p.starts_with('-') && !p.contains('=')) {
                out.pop();
            }
            continue;
        }
        out.push(a.replace("{prompt}", prompt));
    }
    out
}

/// An invocation's limit: the configured timeout, cut to the door key's
/// expiry — a CLI never runs on past the credential it was given.
pub fn effective_timeout(configured: Duration, key_expires: Option<chrono::DateTime<chrono::Utc>>, now: chrono::DateTime<chrono::Utc>) -> Duration {
    match key_expires {
        Some(e) => {
            let left = (e - now).to_std().unwrap_or(Duration::ZERO);
            configured.min(left).max(Duration::from_secs(1))
        }
        None => configured,
    }
}

// ── running the CLI ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RunOutput {
    /// `None` when killed by a signal (the timeout included).
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub elapsed: Duration,
}

impl RunOutput {
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }

    /// Why the run failed, for a checkpoint note or a turn's error.
    pub fn failure(&self) -> String {
        let tail = tail_lines(&self.stderr, 8);
        let what = if self.timed_out {
            format!("timed out after {}s", self.elapsed.as_secs())
        } else {
            match self.code {
                Some(c) => format!("exit {c}"),
                None => "killed by a signal".into(),
            }
        };
        if tail.is_empty() { what } else { format!("{what}: {tail}") }
    }
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(mut r: R, cap: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
            }
        }
    }
    buf
}

/// Run `argv` in `cwd` with exactly `env`, stdin closed, output captured up
/// to [`OUTPUT_CAP`], in a process group of its own that is killed whole at
/// `timeout`.
pub async fn spawn_cli(argv: &[String], env: &BTreeMap<String, String>, cwd: &Path, timeout: Duration, jail: &crate::harness::jail::JailSpec) -> Result<RunOutput> {
    spawn_cli_as(argv, env, cwd, timeout, jail, None).await
}

/// Who a CLI runs as when it is not the harness's own uid: the child
/// switches to `gid` then `uid` before exec (std drops supplementary groups
/// when it changes uid from root). Never uid 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

/// [`spawn_cli`], optionally as another user. The ONE place a CLI process
/// is constructed: the production driver and `harness probe` both come
/// through here, and so both run the CLI inside the jail. Order in the
/// child (std's `do_exec`): setgid/setuid first, then the `pre_exec` hook
/// that applies the jail, then exec — so the jail binds the dropped user.
pub async fn spawn_cli_as(argv: &[String], env: &BTreeMap<String, String>, cwd: &Path, timeout: Duration, jail: &crate::harness::jail::JailSpec, run_as: Option<RunAs>) -> Result<RunOutput> {
    let (prog, args) = argv.split_first().ok_or_else(|| anyhow!("empty command"))?;
    if run_as.is_some_and(|r| r.uid == 0) {
        bail!("refusing to run a CLI as uid 0");
    }
    // The program is looked up on the CLI's PATH, not the harness's.
    let resolved = resolve_program(prog, env.get("PATH").map(String::as_str)).unwrap_or_else(|| PathBuf::from(prog));
    let mut cmd = crate::harness::jail::command(&resolved, jail).map_err(|r| anyhow!(r.note()))?;
    cmd.args(args)
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(unix)]
    if let Some(r) = run_as {
        cmd.gid(r.gid).uid(r.uid);
    }
    let started = Instant::now();
    let mut child = cmd.spawn().with_context(|| format!("starting {prog}"))?;
    let out = child.stdout.take().map(|s| tokio::spawn(read_capped(s, OUTPUT_CAP)));
    let err = child.stderr.take().map(|s| tokio::spawn(read_capped(s, OUTPUT_CAP)));
    let (status, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(s) => (s.ok(), false),
        Err(_) => {
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                // SAFETY: kill(2) on the process group this child leads.
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            let _ = child.start_kill();
            (child.wait().await.ok(), true)
        }
    };
    // A grandchild that left the group could hold a pipe open: bound the wait.
    let collect = |h: Option<tokio::task::JoinHandle<Vec<u8>>>| async move {
        match h {
            Some(h) => tokio::time::timeout(Duration::from_secs(5), h).await.ok().and_then(|r| r.ok()).unwrap_or_default(),
            None => Vec::new(),
        }
    };
    let stdout = collect(out).await;
    let stderr = collect(err).await;
    Ok(RunOutput {
        code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        timed_out,
        elapsed: started.elapsed(),
    })
}

fn resolve_program(prog: &str, path: Option<&str>) -> Option<PathBuf> {
    if prog.contains('/') {
        return Some(PathBuf::from(prog));
    }
    path?.split(':').filter(|d| !d.is_empty()).map(|d| Path::new(d).join(prog)).find(|p| p.is_file())
}

// ── reading the answer ──────────────────────────────────────────────────

/// What a run said about its task.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Done(String),
    Failed(String),
    /// The CLI needs its owner: the task waits for the answer.
    Ask(String),
    Continue,
}

/// The LAST `NOO_RESULT:` / `NOO_FAILED:` / `NOO_QUESTION:` line decides.
pub fn verdict(stdout: &str) -> Verdict {
    for line in stdout.lines().rev() {
        let t = line.trim().trim_matches('`').trim();
        if let Some(r) = t.strip_prefix(RESULT_MARK) {
            return Verdict::Done(r.trim().to_string());
        }
        if let Some(r) = t.strip_prefix(FAILED_MARK) {
            return Verdict::Failed(r.trim().to_string());
        }
        if let Some(r) = t.strip_prefix(QUESTION_MARK).filter(|r| !r.trim().is_empty()) {
            return Verdict::Ask(r.trim().to_string());
        }
    }
    Verdict::Continue
}

/// The last `n` non-empty lines, joined.
pub fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// A run's result: the verdict's text if there is one, else the last lines
/// of what it printed.
pub fn result_text(stdout: &str) -> String {
    match verdict(stdout) {
        Verdict::Done(t) | Verdict::Failed(t) | Verdict::Ask(t) if !t.is_empty() => t,
        _ => tail_lines(stdout, 20),
    }
}

/// One task loop's prompt.
pub fn task_prompt(req: &TaskRequest, loop_no: u32, last_note: Option<&str>, clarification: Option<&crate::task_budget::Clarification>) -> String {
    let mut p = String::new();
    if let Some(role) = req.role_prompt.as_deref().filter(|r| !r.trim().is_empty()) {
        p.push_str(role.trim());
        p.push_str("\n\n");
    }
    p.push_str(&format!(
        "You are working on a TASK (loop {loop_no} of {budget}). Objective:\n\n{objective}\n\n",
        budget = req.loop_budget,
        objective = req.objective.trim()
    ));
    if let Some(n) = last_note.filter(|n| !n.trim().is_empty()) {
        p.push_str(&format!("Where the previous loop left off:\n{}\n\n", n.trim()));
    }
    if let Some(c) = clarification {
        p.push_str(&format!(
            "In an earlier loop you asked the owner:\n{}\nThe owner answered:\n{}\nTake the answer into account.\n\n",
            c.question.trim(),
            c.answer.as_deref().unwrap_or("").trim()
        ));
    }
    p.push_str(&format!(
        "Your working directory persists between loops of this task. noomesh's tools (knowledge base, memory, \
         agent messages to thread {thread}) are available as the MCP server `{MCP_SERVER_NAME}`.\n\
         When the objective is fully achieved, end your answer with one line:\n{RESULT_MARK} <one-line summary>\n\
         If it cannot be achieved, end with:\n{FAILED_MARK} <reason>\n\
         If you cannot go on without the owner deciding something, end with:\n{QUESTION_MARK} <one clear question>\n\
         If more work remains, end with none of these; you will be run again.",
        thread = req.thread_id
    ));
    p
}

// ── one invocation ──────────────────────────────────────────────────────

/// Translator up, door key minted, CLI run, usage reported, key revoked,
/// translator down — in that order whatever the CLI did.
async fn invoke<R: DriverRail>(ctx: &DriverCtx, rail: &R, ws: &Workspace, prompt: &str, task_id: Option<&str>) -> Result<(RunOutput, UsageTotals)> {
    let translator = Translator::start(ctx.pinned.clone()).await.context("starting the wire translator")?;
    let key = match rail.door_key().await {
        Ok(k) => k,
        Err(e) => {
            translator.shutdown().await;
            return Err(e.context("minting the user-door key"));
        }
    };
    let run = async {
        let mcp = ws.write_cli_config(ctx, translator.base_url(), &key.key)?;
        let env = build_env(ctx, ws, translator.base_url());
        let argv = fill_command(&ctx.launch.command, prompt, &mcp);
        let timeout = effective_timeout(ctx.timeout, key.expires_at, chrono::Utc::now());
        tracing::info!(kind = %ctx.kind.kind, cli = %argv[0], task = task_id.unwrap_or(""), timeout_secs = timeout.as_secs(), "harness driver: running the CLI");
        spawn_cli(&argv, &env, &ws.work, timeout, &ws.jail_spec(ctx, &mcp)).await
    }
    .await;
    let _ = std::fs::remove_file(ws.mcp_path());
    let _ = std::fs::remove_file(ws.codex_config_path(ctx.kind.cli.as_deref().unwrap_or(&ctx.kind.kind)));
    let usage = translator.usage();
    rail.report_usage(&usage, &ctx.pinned.model, &ctx.kind.kind, task_id).await;
    rail.door_key_revoke(&key.key_id).await;
    translator.shutdown().await;
    if let Ok(o) = &run {
        tracing::info!(kind = %ctx.kind.kind, task = task_id.unwrap_or(""), code = ?o.code, timed_out = o.timed_out, secs = o.elapsed.as_secs(), "harness driver: CLI finished");
    }
    run.map(|o| (o, usage))
}

// ── a task ──────────────────────────────────────────────────────────────

/// Run a task to its end on the driven CLI: one invocation per loop, a
/// checkpoint after each, until a verdict, the budget, three failures in a
/// row, or a state that is no longer live.
pub async fn run_task(ctx: &DriverCtx, client: reqwest::Client, req: &TaskRequest) -> Result<String> {
    let mut rt = RemoteRuntime::connect(&ctx.gateway, &req.token, client).await?;
    run_task_on(ctx, &mut rt, req).await
}

pub(crate) async fn run_task_on<R: DriverRail>(ctx: &DriverCtx, rail: &mut R, req: &TaskRequest) -> Result<String> {
    if let Err(r) = (ctx.jail_probe)() {
        tracing::error!(event = "harness_jail_refused", task = %req.task_id, reason = %r, "harness_jail_refused: {}", r.note());
        return rail.checkpoint(&req.task_id, req.loops_done, Some(&r.note()), false).await;
    }
    let ws = Workspace::create(&ctx.workdir_root, &req.task_id, ctx.keep_workdir)?;
    let out = task_loops(ctx, rail, req, &ws).await;
    ws.finish();
    out
}

async fn task_loops<R: DriverRail>(ctx: &DriverCtx, rail: &mut R, req: &TaskRequest, ws: &Workspace) -> Result<String> {
    let mut loops = req.loops_done;
    let mut failures = 0u32;
    let mut last_note: Option<String> = None;
    loop {
        if loops >= req.loop_budget {
            return rail.checkpoint(&req.task_id, loops, Some("loop budget exhausted"), true).await;
        }
        // THE TOKEN SWITCH (i83 G): asked before the CLI runs, never while
        // it does. A no parks the task on the gateway; the driver stops.
        let check = match rail.budget_check(&req.task_id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(task = %req.task_id, error = %e, "harness driver: budget check failed; stopping at the checkpoint");
                return rail.checkpoint(&req.task_id, loops, Some(&format!("budget check failed: {e:#}")), false).await;
            }
        };
        if !check.proceed {
            tracing::info!(task = %req.task_id, reason = check.reason.as_deref().unwrap_or(""), "harness driver: budget switch says no more loops");
            return Ok(check.state);
        }
        let prompt = task_prompt(req, loops + 1, last_note.as_deref(), check.clarification.as_ref());
        let outcome = invoke(ctx, &*rail, ws, &prompt, Some(&req.task_id)).await;
        loops += 1;
        let mut decided = false;
        let note = match &outcome {
            Ok((o, _)) if o.succeeded() => {
                failures = 0;
                rail.save("user", &prompt).await;
                rail.save("assistant", o.stdout.trim()).await;
                match verdict(&o.stdout) {
                    Verdict::Done(r) => {
                        decided = true;
                        rail.task_done(&req.task_id, &r, false).await?;
                    }
                    Verdict::Failed(r) => {
                        decided = true;
                        rail.task_done(&req.task_id, &r, true).await?;
                    }
                    // The question parks the task at the next boundary:
                    // this loop still checkpoints like any other.
                    Verdict::Ask(q) => {
                        if let Err(e) = rail.task_ask(&req.task_id, &q).await {
                            tracing::warn!(task = %req.task_id, error = %e, "harness driver: question not recorded");
                        }
                    }
                    Verdict::Continue => {}
                }
                crate::tasks::excerpt(&result_text(&o.stdout))
            }
            Ok((o, _)) => {
                failures += 1;
                format!("loop {loops} failed: {}", o.failure())
            }
            Err(e) => {
                failures += 1;
                format!("loop {loops} failed: {e:#}")
            }
        };
        let exhausted = !decided && loops >= req.loop_budget;
        let after = rail.checkpoint(&req.task_id, loops, Some(&note), exhausted).await?;
        if failures >= 3 && !exhausted {
            return rail.checkpoint(&req.task_id, loops, Some("three consecutive loop failures; giving up"), true).await;
        }
        if !crate::tasks::keep_looping(&after, loops, req.loop_budget) {
            return Ok(after);
        }
        last_note = Some(note);
    }
}

// ── a turn ──────────────────────────────────────────────────────────────

/// One turn on the driven CLI: its answer is the turn's response.
pub async fn run_turn(ctx: &DriverCtx, client: reqwest::Client, req: &TurnRequest) -> Result<CoordinatorResult> {
    let rt = RemoteRuntime::connect(&ctx.gateway, &req.token, client).await?;
    run_turn_on(ctx, &rt, req).await
}

pub(crate) async fn run_turn_on<R: DriverRail>(ctx: &DriverCtx, rail: &R, req: &TurnRequest) -> Result<CoordinatorResult> {
    if let Err(r) = (ctx.jail_probe)() {
        tracing::error!(event = "harness_jail_refused", reason = %r, "harness_jail_refused: {}", r.note());
        bail!("{}", r.note());
    }
    let id = format!("turn-{}", uuid::Uuid::new_v4().simple());
    let ws = Workspace::create(&ctx.workdir_root, &id, ctx.keep_workdir)?;
    let prompt = match req.role_prompt.as_deref().filter(|r| !r.trim().is_empty()) {
        Some(role) => format!("{}\n\n{}", role.trim(), req.prompt),
        None => req.prompt.clone(),
    };
    let outcome = invoke(ctx, rail, &ws, &prompt, None).await;
    ws.finish();
    let (o, usage) = outcome?;
    if !o.succeeded() {
        bail!("{} CLI: {}", ctx.kind.kind, o.failure());
    }
    let response = o.stdout.trim().to_string();
    rail.save("user", &req.prompt).await;
    rail.save("assistant", &response).await;
    let clamp = |v: u64| v.min(u32::MAX as u64) as u32;
    Ok(CoordinatorResult {
        response,
        model: ctx.pinned.model.clone(),
        backend: ctx.pinned.backend_type.clone(),
        node: Some(ctx.node.clone()),
        iterations: 1,
        tool_calls: Vec::new(),
        elapsed_secs: o.elapsed.as_secs_f64(),
        usage: UsageStats {
            prompt_tokens: clamp(usage.prompt_tokens),
            completion_tokens: clamp(usage.completion_tokens),
            total_tokens: clamp(usage.total_tokens),
            total_tool_calls: 0,
            total_latency_ms: o.elapsed.as_millis().min(u64::MAX as u128) as u64,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const TURN_TOKEN: &str = "eyJturn.token.secret";

    fn kind(command: &[&str], lane: &[(&str, &str)], telemetry: &[(&str, &str)]) -> HarnessKind {
        serde_json::from_value(json!({
            "kind": "fake",
            "title": "a fake CLI",
            "wire": "OpenAI's Chat Completions API",
            "wires": ["llamacpp"],
            "runner": "noo-gateway",
            "cli": command[0],
            "lane": lane.iter().cloned().collect::<BTreeMap<_, _>>(),
            "launch": {
                "command": command,
                "model_url_env": "FAKE_BASE_URL",
                "model_env": "FAKE_MODEL",
                "mcp": "config-file",
                "model_url_suffix": "/v1",
                "api_key_env": "FAKE_API_KEY",
                "model_alias_envs": ["FAKE_SMALL_MODEL"],
                "home_env": "FAKE_HOME"
            },
            "telemetry_off": telemetry.iter().cloned().collect::<BTreeMap<_, _>>(),
        }))
        .unwrap()
    }

    fn pinned() -> ResolvedBackend {
        ResolvedBackend { url: "http://127.0.0.1:8085".into(), model: "gemma-4".into(), backend_type: "llamacpp".into(), api_format: "openai".into() }
    }

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("noo-driver-test-{tag}-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn ctx_for(k: &HarnessKind, root: &Path, timeout_secs: &str) -> DriverCtx {
        let root = root.display().to_string();
        let timeout = timeout_secs.to_string();
        // The harness's own env as the unit hands it: the bus pair, the
        // node-agent bearer, the cluster secret. None of it may reach the CLI.
        let parent: BTreeMap<&str, String> = [
            ("NOO_HARNESS_WORKDIR", root),
            ("NOO_HARNESS_TURN_TIMEOUT_SECS", timeout),
            ("NOO_TLS_CA", "/etc/noo/pki/ca.crt".to_string()),
            ("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())),
            ("NATS_NODE_PASSWORD", "bus-secret".into()),
            ("NOO_NODE_AGENT_TOKEN", "agent-bearer".into()),
            ("NOO_CLUSTER_SECRET", "cluster-secret".into()),
        ]
        .into_iter()
        .collect();
        DriverCtx::new("awolf", "https://gateway:8080/", k, pinned(), &|n| parent.get(n).cloned()).unwrap()
    }

    #[derive(Default)]
    struct Calls {
        checkpoints: Vec<(u32, Option<String>, bool)>,
        done: Vec<(String, bool)>,
        keys_minted: u32,
        keys_revoked: Vec<String>,
        saved: Vec<(String, String)>,
        usage: Vec<(String, String, Option<String>)>,
        checks: u32,
        asked: Vec<String>,
    }

    struct FakeRail {
        calls: Mutex<Calls>,
        key_ttl_secs: i64,
        /// The switch says no from this check on (1-based); `None` = always yes.
        stop_at_check: Option<u32>,
        /// A question parks the task: every check after one says no.
        parks_on_ask: bool,
    }

    impl FakeRail {
        fn new() -> Self {
            Self { calls: Mutex::new(Calls::default()), key_ttl_secs: 900, stop_at_check: None, parks_on_ask: true }
        }
    }

    impl DriverRail for FakeRail {
        async fn checkpoint(&mut self, _task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String> {
            let mut c = self.calls.lock().unwrap();
            c.checkpoints.push((loops, note.map(str::to_string), exhausted));
            Ok(match (c.done.last(), exhausted) {
                (Some((_, false)), _) => "done",
                (Some((_, true)), _) | (None, true) => "failed",
                (None, false) => "checkpointed",
            }
            .to_string())
        }
        async fn task_done(&self, _task_id: &str, result: &str, failed: bool) -> Result<String> {
            self.calls.lock().unwrap().done.push((result.to_string(), failed));
            Ok(if failed { "failed" } else { "done" }.to_string())
        }
        async fn door_key(&self) -> Result<DoorKey> {
            let mut c = self.calls.lock().unwrap();
            c.keys_minted += 1;
            Ok(DoorKey {
                key: format!("noo-sk-door-{}", c.keys_minted),
                key_id: format!("key-{}", c.keys_minted),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(self.key_ttl_secs)),
            })
        }
        async fn door_key_revoke(&self, key_id: &str) {
            self.calls.lock().unwrap().keys_revoked.push(key_id.to_string());
        }
        async fn save(&self, role: &str, content: &str) {
            self.calls.lock().unwrap().saved.push((role.to_string(), content.to_string()));
        }
        async fn report_usage(&self, _usage: &UsageTotals, model: &str, kind: &str, task_id: Option<&str>) {
            self.calls.lock().unwrap().usage.push((model.to_string(), kind.to_string(), task_id.map(str::to_string)));
        }
        async fn budget_check(&mut self, _task_id: &str) -> Result<crate::task_budget::BudgetCheck> {
            let mut c = self.calls.lock().unwrap();
            c.checks += 1;
            let no = self.stop_at_check.is_some_and(|n| c.checks >= n) || (self.parks_on_ask && !c.asked.is_empty());
            Ok(crate::task_budget::BudgetCheck {
                proceed: !no,
                reason: no.then(|| "token budget exhausted".to_string()),
                state: "checkpointed".into(),
                ..Default::default()
            })
        }
        async fn task_ask(&self, _task_id: &str, question: &str) -> Result<()> {
            self.calls.lock().unwrap().asked.push(question.to_string());
            Ok(())
        }
    }

    fn task(id: &str, budget: u32) -> TaskRequest {
        TaskRequest {
            task_id: id.into(),
            objective: "count the documents".into(),
            conversation_id: "c0ffee00-0000-0000-0000-000000000000".into(),
            thread_id: "thr_1".into(),
            channel: "task".into(),
            user: "alice".into(),
            model: None,
            loops_done: 0,
            loop_budget: budget,
            max_iterations: 10,
            token: TURN_TOKEN.into(),
            role_prompt: Some("You are the researcher.".into()),
        }
    }

    #[tokio::test]
    async fn a_cli_that_reports_a_result_finishes_its_task_in_one_loop() {
        let root = scratch("ok");
        let k = kind(&["sh", "-c", "echo hello; echo NOO_RESULT: ok"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        let state = run_task_on(&ctx, &mut rail, &task("t-ok", 3)).await.unwrap();
        assert_eq!(state, "done");
        let c = rail.calls.lock().unwrap();
        assert_eq!(c.done, vec![("ok".to_string(), false)]);
        assert_eq!(c.checkpoints, vec![(1, Some("ok".to_string()), false)]);
        assert_eq!(c.keys_minted, 1);
        assert_eq!(c.keys_revoked, vec!["key-1".to_string()], "every minted key is revoked");
        assert_eq!(c.usage, vec![("gemma-4".to_string(), "fake".to_string(), Some("t-ok".to_string()))]);
        assert_eq!(c.saved.len(), 2);
        assert!(c.saved[0].1.contains("count the documents") && c.saved[0].1.contains("You are the researcher."));
        assert!(c.saved[1].1.contains("hello"));
        assert!(!root.join("t-ok").exists(), "the workspace is removed when the task ends");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_failing_cli_is_a_failed_loop_with_its_stderr_and_exhausts_the_budget() {
        let root = scratch("fail");
        let k = kind(&["sh", "-c", "echo partial; echo 'boom: no provider' >&2; exit 3"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        let state = run_task_on(&ctx, &mut rail, &task("t-fail", 1)).await.unwrap();
        assert_eq!(state, "failed");
        let c = rail.calls.lock().unwrap();
        assert!(c.done.is_empty(), "a failed run is no verdict");
        assert_eq!(c.checkpoints.len(), 1);
        let (loops, note, exhausted) = &c.checkpoints[0];
        assert_eq!(*loops, 1);
        assert!(*exhausted, "the loop that reaches the budget exhausts it");
        let note = note.as_deref().unwrap();
        assert!(note.contains("exit 3") && note.contains("boom: no provider"), "{note}");
        assert_eq!(c.keys_revoked.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn three_failed_loops_in_a_row_end_the_task() {
        let root = scratch("three");
        let k = kind(&["sh", "-c", "exit 1"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        let state = run_task_on(&ctx, &mut rail, &task("t-three", 10)).await.unwrap();
        assert_eq!(state, "failed");
        let c = rail.calls.lock().unwrap();
        assert_eq!(c.keys_minted, 3);
        let last = c.checkpoints.last().unwrap();
        assert!(last.2 && last.1.as_deref().unwrap().contains("three consecutive"), "{last:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_cli_past_its_deadline_is_killed() {
        let root = scratch("slow");
        let k = kind(&["sh", "-c", "sleep 30; echo NOO_RESULT: too late"], &[], &[]);
        let ctx = ctx_for(&k, &root, "1");
        let mut rail = FakeRail::new();
        let started = Instant::now();
        let state = run_task_on(&ctx, &mut rail, &task("t-slow", 1)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(15), "the sleep was not killed: {:?}", started.elapsed());
        assert_eq!(state, "failed");
        let c = rail.calls.lock().unwrap();
        assert!(c.done.is_empty());
        let note = c.checkpoints[0].1.as_deref().unwrap();
        assert!(note.contains("timed out"), "{note}");
        assert_eq!(c.keys_revoked.len(), 1, "a killed run still revokes its key");
        let _ = std::fs::remove_dir_all(root);
    }

    /// PINNED (i83 G): the token switch is asked before each CLI run, and a
    /// no stops the task BEFORE the next run starts — the run in progress
    /// was never interrupted, and its usage and checkpoint stand.
    #[tokio::test]
    async fn the_budget_switch_stops_the_task_between_runs_never_during_one() {
        let root = scratch("budget");
        let k = kind(&["sh", "-c", "echo working"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        rail.stop_at_check = Some(3);
        let state = run_task_on(&ctx, &mut rail, &task("t-budget", 10)).await.unwrap();
        assert_eq!(state, "checkpointed", "parked, not failed");
        let c = rail.calls.lock().unwrap();
        assert_eq!(c.checks, 3, "one check per loop, and the third said no");
        assert_eq!(c.keys_minted, 2, "the CLI ran twice: no run started after the no");
        assert_eq!(c.checkpoints.len(), 2, "both runs finished and checkpointed");
        assert!(c.checkpoints.iter().all(|cp| !cp.2), "nothing was failed for budget");
        assert_eq!(c.usage.len(), 2, "both runs' tokens were reported");
        let _ = std::fs::remove_dir_all(root);
    }

    /// PINNED: in the driver's loop the check comes before the CLI runs, once.
    #[test]
    fn the_driver_checks_before_it_invokes() {
        let src = include_str!("driver.rs");
        let body = &src[src.find("async fn task_loops<").unwrap()..src.find("// ── a turn ──").unwrap()];
        assert_eq!(body.matches("rail.budget_check(").count(), 1);
        assert!(body.find("rail.budget_check(").unwrap() < body.find("invoke(ctx,").unwrap());
        let invoke_fn = &src[src.find("async fn invoke<").unwrap()..src.find("// ── a task ──").unwrap()];
        assert!(!invoke_fn.contains("budget_check"), "a run is never interrupted for budget");
    }

    /// A switch that says no before the first loop runs nothing at all.
    #[tokio::test]
    async fn an_exhausted_task_runs_no_cli() {
        let root = scratch("budget0");
        let k = kind(&["sh", "-c", "echo NOO_RESULT: ok"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        rail.stop_at_check = Some(1);
        assert_eq!(run_task_on(&ctx, &mut rail, &task("t-budget0", 10)).await.unwrap(), "checkpointed");
        let c = rail.calls.lock().unwrap();
        assert_eq!((c.keys_minted, c.checkpoints.len()), (0, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    /// `NOO_QUESTION:` goes to the owner over the rail; the loop still
    /// checkpoints, and the next boundary stops the task to wait.
    #[tokio::test]
    async fn a_cli_question_is_asked_and_the_task_waits() {
        let root = scratch("ask");
        let k = kind(&["sh", "-c", "echo looked; echo 'NOO_QUESTION: eu or us?'"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        assert_eq!(run_task_on(&ctx, &mut rail, &task("t-ask", 10)).await.unwrap(), "checkpointed");
        let c = rail.calls.lock().unwrap();
        assert_eq!(c.asked, vec!["eu or us?".to_string()]);
        assert!(c.done.is_empty(), "a question is not a verdict");
        assert_eq!(c.checkpoints, vec![(1, Some("eu or us?".to_string()), false)]);
        assert_eq!(c.checks, 2, "the boundary after the question said no");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_answer_rides_the_next_prompt() {
        let c = crate::task_budget::Clarification { question: "eu or us?".into(), answer: Some("eu".into()) };
        let p = task_prompt(&task("t", 5), 2, Some("looked"), Some(&c));
        assert!(p.contains("eu or us?") && p.contains("The owner answered:\neu") && p.contains(QUESTION_MARK));
        assert_eq!(verdict("x\nNOO_QUESTION: which one?"), Verdict::Ask("which one?".into()));
        assert_eq!(verdict("NOO_QUESTION:   "), Verdict::Continue, "an empty question is no question");
    }

    /// PINNED (i119): where no jail can be built, a foreign task checkpoints
    /// with the reason and the CLI never starts — no key, no translator, no
    /// process. A turn is an error with the same words.
    #[tokio::test]
    async fn a_refused_jail_checkpoints_and_never_spawns() {
        let root = scratch("nojail");
        let marker = root.join("ran");
        let script = format!("touch {}; echo NOO_RESULT: ok", marker.display());
        let k = kind(&["sh", "-c", &script], &[], &[]);
        let mut ctx = ctx_for(&k, &root, "30");
        ctx.jail_probe = || Err(crate::harness::jail::Refusal("this kernel has no Landlock".into()));
        let mut rail = FakeRail::new();
        assert_eq!(run_task_on(&ctx, &mut rail, &task("t-nojail", 10)).await.unwrap(), "checkpointed");
        {
            let c = rail.calls.lock().unwrap();
            let note = "harness jail unavailable: this kernel has no Landlock; foreign CLIs never run unjailed";
            assert_eq!(c.checkpoints, vec![(0, Some(note.to_string()), false)], "checkpointed, not failed, not exhausted");
            assert_eq!((c.keys_minted, c.checks, c.done.len(), c.saved.len()), (0, 0, 0, 0), "nothing ran");
        }
        assert!(!marker.exists(), "the CLI never started");
        let turn = TurnRequest {
            conversation_id: "c1".into(),
            prompt: "hi".into(),
            channel: "dashboard".into(),
            max_iterations: 5,
            model: None,
            user: "alice".into(),
            enable_thinking: false,
            role_prompt: None,
            stream: false,
            token: TURN_TOKEN.into(),
        };
        let e = run_turn_on(&ctx, &rail, &turn).await.unwrap_err();
        assert!(e.to_string().contains("foreign CLIs never run unjailed"), "{e}");
        assert!(!marker.exists());
        assert_eq!(rail.calls.lock().unwrap().keys_minted, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A failed startup self-test is the gate's answer for the process: the
    /// task checkpoints with the leak named and the CLI never starts.
    #[tokio::test]
    async fn a_failed_jail_self_test_checkpoints_with_the_leak_named() {
        let root = scratch("selftest-failed");
        let marker = root.join("ran");
        let script = format!("touch {}; echo NOO_RESULT: ok", marker.display());
        let k = kind(&["sh", "-c", &script], &[], &[]);
        let mut ctx = ctx_for(&k, &root, "30");
        ctx.jail_probe = || Err(crate::harness::jail::Refusal("jail self-test failed: the planted secret /tmp/p/node.key was readable inside the jail".into()));
        let mut rail = FakeRail::new();
        assert_eq!(run_task_on(&ctx, &mut rail, &task("t-selftest", 10)).await.unwrap(), "checkpointed");
        let c = rail.calls.lock().unwrap();
        let note = c.checkpoints[0].1.clone().unwrap();
        assert!(note.contains("the planted secret /tmp/p/node.key was readable inside the jail") && note.contains("never run unjailed"), "{note}");
        assert_eq!(c.keys_minted, 0);
        assert!(!marker.exists(), "the CLI never started");
        drop(c);
        let _ = std::fs::remove_dir_all(root);
    }

    /// PINNED: what the CLI process actually sees carries none of the
    /// harness's secrets and not the turn token — `env_clear`, not hope.
    #[tokio::test]
    async fn the_cli_process_sees_no_harness_secret() {
        let root = scratch("env");
        let k = kind(&["sh", "-c", "env; echo NOO_RESULT: ok"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let mut rail = FakeRail::new();
        run_task_on(&ctx, &mut rail, &task("t-env", 1)).await.unwrap();
        let c = rail.calls.lock().unwrap();
        let seen = &c.saved[1].1;
        for bad in ["NATS_", "NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "bus-secret", "agent-bearer", "cluster-secret", TURN_TOKEN, "noo-sk-door"] {
            assert!(!seen.contains(bad), "the CLI saw {bad}:\n{seen}");
        }
        assert!(seen.contains("FAKE_MODEL=gemma-4"), "{seen}");
        // The CLI is pointed at the loopback translator, never at the model
        // endpoint itself.
        let base = seen.lines().find_map(|l| l.strip_prefix("FAKE_BASE_URL=")).expect("FAKE_BASE_URL set");
        assert!(base.starts_with("http://127.0.0.1:") && base.ends_with("/v1") && !base.contains(":8085"), "{base}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// PINNED: lane and telemetry_off are merged LAST, telemetry after lane,
    /// and a forbidden name never survives, whoever set it.
    #[test]
    fn the_env_is_built_from_nothing_and_telemetry_is_merged_last() {
        let root = scratch("envunit");
        let k = kind(
            &["fake"],
            &[("DO_NOT_TRACK", "0"), ("FAKE_AUTO_UPDATE", "false"), ("NATS_URL", "nats://leak"), ("FAKE_MODEL", "lane-model")],
            &[("DO_NOT_TRACK", "1"), ("NOO_CLUSTER_SECRET", "leak")],
        );
        let ctx = ctx_for(&k, &root, "30");
        let ws = Workspace::create(&root, "t-envunit", false).unwrap();
        let env = build_env(&ctx, &ws, "http://127.0.0.1:41234/");
        assert!(env.keys().all(|k| !is_forbidden(k)), "{env:?}");
        assert!(env.values().all(|v| !v.contains(TURN_TOKEN) && !v.contains("secret") && !v.contains("bearer")), "{env:?}");
        assert_eq!(env["DO_NOT_TRACK"], "1", "telemetry_off wins over the lane");
        assert_eq!(env["FAKE_AUTO_UPDATE"], "false");
        assert_eq!(env["FAKE_MODEL"], "lane-model", "the lane is merged after the driver's own values");
        assert_eq!(env["FAKE_BASE_URL"], "http://127.0.0.1:41234/v1");
        assert_eq!(env["FAKE_SMALL_MODEL"], "gemma-4");
        assert_eq!(env["FAKE_API_KEY"], PLACEHOLDER_KEY);
        assert_eq!(env["HOME"], ws.home.display().to_string());
        assert!(env["FAKE_HOME"].starts_with(&ws.home.display().to_string()));
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], "/etc/noo/pki/ca.crt");
        for n in ["NATS_URL", "NATS_NODE_PASSWORD", "NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NOO_GATEWAY_URL"] {
            assert!(!env.contains_key(n), "{n}");
        }
        ws.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_door_key_reaches_the_cli_only_through_the_mcp_file() {
        let root = scratch("mcp");
        let ws = Workspace::create(&root, "t-mcp", false).unwrap();
        let p = ws.write_mcp_config("https://gateway:8080/", "noo-sk-door-1").unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let s = &v["mcpServers"][MCP_SERVER_NAME];
        assert_eq!(s["url"], "https://gateway:8080/mcp/user");
        assert_eq!(s["headers"]["Authorization"], "Bearer noo-sk-door-1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(!p.starts_with(&ws.work), "the key file is outside the CLI's working directory");
        let argv = fill_command(&["c".into(), "-p".into(), "{prompt}".into(), "@{mcp_config}".into()], "do it", &p);
        assert_eq!(argv[2], "do it");
        assert_eq!(argv[3], format!("@{}", p.display()));
        ws.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    /// PINNED: one workspace per task; a task id cannot climb out of the root.
    #[test]
    fn workspaces_are_per_task() {
        let root = scratch("ws");
        let a = Workspace::create(&root, "task-a", false).unwrap();
        let b = Workspace::create(&root, "task-b", false).unwrap();
        assert_ne!(a.root, b.root);
        assert!(a.root.starts_with(&root) && b.root.starts_with(&root));
        for bad in ["../x", "a/b", "", "."] {
            assert!(Workspace::create(&root, bad, false).is_err(), "{bad:?}");
        }
        a.finish();
        b.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_run_never_outlives_its_door_key() {
        let now = chrono::Utc::now();
        let t = Duration::from_secs(900);
        assert_eq!(effective_timeout(t, None, now), t);
        assert_eq!(effective_timeout(t, Some(now + chrono::Duration::seconds(120)), now), Duration::from_secs(120));
        assert_eq!(effective_timeout(t, Some(now + chrono::Duration::seconds(5000)), now), t);
        assert_eq!(effective_timeout(t, Some(now - chrono::Duration::seconds(5)), now), Duration::from_secs(1));
    }

    #[test]
    fn the_last_marker_line_is_the_verdict() {
        assert_eq!(verdict("a\nNOO_RESULT: 42 documents\n"), Verdict::Done("42 documents".into()));
        assert_eq!(verdict("NOO_RESULT: early\nthen\nNOO_FAILED: no access"), Verdict::Failed("no access".into()));
        assert_eq!(verdict("`NOO_RESULT: fenced`"), Verdict::Done("fenced".into()));
        assert_eq!(verdict("working on it"), Verdict::Continue);
        assert_eq!(result_text("x\n\ny\nz\n"), "x\ny\nz");
        assert_eq!(tail_lines("a\nb\nc", 2), "b\nc");
    }

    /// The shipped table: Copilot, Claude Code and Codex are runnable,
    /// `noo` is never driven.
    #[test]
    fn the_shipped_foreign_kinds_validate() {
        for name in ["copilot", "claude-code", "codex"] {
            let k = crate::harness_kinds::get(name).unwrap();
            let l = validate_kind(k).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(l.command.iter().any(|a| a.contains("{prompt}")), "{name}: no {{prompt}}");
            if l.mcp == MCP_CONFIG_FILE {
                assert!(l.command.iter().any(|a| a.contains("{mcp_config}")), "{name}: no {{mcp_config}}");
            }
            assert_eq!(l.command[0], k.cli.clone().unwrap(), "{name}");
            let ctx = DriverCtx::new("n", "https://g", k, pinned(), &|_| None).unwrap();
            let root = scratch(name);
            let ws = Workspace::create(&root, "t", false).unwrap();
            let env = build_env(&ctx, &ws, "http://127.0.0.1:1");
            for (tk, tv) in &k.telemetry_off {
                assert_eq!(env.get(tk), Some(tv), "{name}: telemetry switch {tk}");
            }
            ws.finish();
            let _ = std::fs::remove_dir_all(root);
        }
        assert!(validate_kind(crate::harness_kinds::get("noo").unwrap()).is_err());

        // Codex: headless, approval-free inside its sandbox, its home the
        // task's own, the config the driver writes carrying the model.
        let codex = crate::harness_kinds::get("codex").unwrap();
        let l = validate_kind(codex).unwrap();
        assert_eq!(l.mcp, MCP_CODEX_TOML);
        assert_eq!(&l.command[..2], ["codex", "exec"]);
        for flag in ["--skip-git-repo-check", "--ephemeral", "--sandbox"] {
            assert!(l.command.iter().any(|a| a == flag), "codex: {flag}");
        }
        assert!(!l.command.iter().any(|a| a.contains("dangerously") || a == "--yolo" || a == "--full-auto"), "no blanket bypass: {:?}", l.command);
        assert_eq!(l.home_env.as_deref(), Some("CODEX_HOME"));
        assert_eq!(codex.wires, crate::harness_kinds::get("copilot").unwrap().wires, "every node backend, through the translator");
    }

    fn codex_kind(command: &[&str]) -> HarnessKind {
        serde_json::from_value(json!({
            "kind": "codex", "title": "t", "wire": "OpenAI's Responses API", "wires": ["llamacpp"],
            "runner": "noo-gateway", "cli": "codex", "lane": {},
            "launch": {"command": command, "model_url_env": "", "model_env": "", "mcp": MCP_CODEX_TOML,
                       "model_url_suffix": "/v1", "home_env": "CODEX_HOME", "ca_env": "CODEX_CA_CERTIFICATE"},
            "telemetry_off": {},
        }))
        .unwrap()
    }

    /// PINNED: `config-file:codex-toml` writes Codex's whole config in the
    /// task's own CODEX_HOME, 0600: the translator as a Responses provider,
    /// the pinned model, the user door with the door key, and every vendor
    /// channel off. No model variable is set; the key is not in the env.
    #[test]
    fn the_codex_mode_writes_its_config_toml_in_the_task_home() {
        let root = scratch("codex");
        let k = codex_kind(&["codex", "exec", "{prompt}"]);
        let ctx = ctx_for(&k, &root, "30");
        let ws = Workspace::create(&root, "t-codex", false).unwrap();
        let p = ws.write_cli_config(&ctx, "http://127.0.0.1:41234/", "noo-sk-door-1").unwrap();
        assert_eq!(p, ws.home.join(".codex").join("config.toml"));
        assert!(p.starts_with(&ws.home) && !p.starts_with(&ws.work), "inside the task HOME, outside the working directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let text = std::fs::read_to_string(&p).unwrap();
        for line in [
            "model = \"gemma-4\"",
            "model_provider = \"noomesh\"",
            "approval_policy = \"never\"",
            "sandbox_mode = \"danger-full-access\"",
            "web_search = \"disabled\"",
            "check_for_update_on_startup = false",
            "[model_providers.noomesh]",
            "base_url = \"http://127.0.0.1:41234/v1\"",
            "wire_api = \"responses\"",
            "[mcp_servers.noomesh]",
            "url = \"https://gateway:8080/mcp/user\"",
            "http_headers = { Authorization = \"Bearer noo-sk-door-1\" }",
            "[analytics]",
            "[feedback]",
            "persistence = \"none\"",
            "metrics_exporter = \"none\"",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line:?} in:\n{text}");
        }
        assert_eq!(text.matches("enabled = false").count(), 2, "analytics and feedback off");
        assert!(!text.contains("env_key"), "the loopback provider asks for no key");

        let env = build_env(&ctx, &ws, "http://127.0.0.1:41234/");
        assert_eq!(env["CODEX_HOME"], ws.home.join(".codex").display().to_string(), "CODEX_HOME is the directory the config is in");
        assert_eq!(env["CODEX_CA_CERTIFICATE"], "/etc/noo/pki/ca.crt");
        assert!(!env.contains_key(""), "an empty model variable is not set");
        assert!(env.values().all(|v| !v.contains("noo-sk-door")), "the door key is in the file only");
        ws.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    /// A run in the codex mode sees its config while it runs; it is gone after.
    #[tokio::test]
    async fn a_codex_run_reads_its_config_and_the_file_is_removed_after() {
        let root = scratch("codexrun");
        let k = codex_kind(&["sh", "-c", "grep -c '^wire_api = \"responses\"$' \"$CODEX_HOME/config.toml\"; echo NOO_RESULT: ok"]);
        let mut ctx = ctx_for(&k, &root, "30");
        ctx.keep_workdir = true;
        let mut rail = FakeRail::new();
        let state = run_task_on(&ctx, &mut rail, &task("t-codexrun", 1)).await.unwrap();
        assert_eq!(state, "done");
        let c = rail.calls.lock().unwrap();
        assert!(c.saved[1].1.starts_with('1'), "the CLI read its provider block: {:?}", c.saved[1].1);
        assert!(root.join("t-codexrun/home/.codex").is_dir());
        assert!(!root.join("t-codexrun/home/.codex/config.toml").exists(), "the key file is removed when the run ends");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn without_mcp_no_door_is_written_and_the_mcp_arguments_are_dropped() {
        let root = scratch("nomcp");
        // config-file kinds: nothing to write, the flag and its value go.
        let k = kind(&["fake", "-p", "{prompt}", "--mcp-config", "{mcp_config}", "--strict-mcp-config", "--x=@{mcp_config}", "--allow"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let ws = Workspace::create(&root, "t-nomcp", false).unwrap();
        assert_eq!(ws.write_cli_config_wired(&ctx, "http://127.0.0.1:1", McpWiring::None).unwrap(), None);
        assert!(!ws.mcp_path().exists());
        assert_eq!(fill_command_without_mcp(&ctx.launch.command, "hi"), ["fake", "-p", "hi", "--strict-mcp-config", "--allow"]);
        // The shipped rows lose exactly their MCP arguments.
        let copilot = crate::harness_kinds::get("copilot").unwrap().launch.clone().unwrap();
        let argv = fill_command_without_mcp(&copilot.command, "P");
        assert!(!argv.iter().any(|a| a.contains("mcp_config") || a == "--additional-mcp-config"), "{argv:?}");
        assert_eq!(argv.len(), copilot.command.len() - 2);
        let claude = crate::harness_kinds::get("claude-code").unwrap().launch.clone().unwrap();
        let argv = fill_command_without_mcp(&claude.command, "P");
        assert!(!argv.iter().any(|a| a.contains("mcp_config") || a == "--mcp-config"), "{argv:?}");
        assert_eq!(argv.len(), claude.command.len() - 2);
        // The door path is unchanged.
        let p = ws.write_cli_config(&ctx, "http://127.0.0.1:1", "noo-sk-door-9").unwrap();
        assert_eq!(p, ws.mcp_path());
        ws.finish();

        // Codex: the provider still, the MCP table not.
        let k = codex_kind(&["codex", "exec", "{prompt}"]);
        let ctx = ctx_for(&k, &root, "30");
        let ws = Workspace::create(&root, "t-nomcp-codex", false).unwrap();
        let p = ws.write_cli_config_wired(&ctx, "http://127.0.0.1:41234", McpWiring::None).unwrap().unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("base_url = \"http://127.0.0.1:41234/v1\"") && text.contains("[analytics]"), "{text}");
        assert!(!text.contains("mcp_servers") && !text.contains("Bearer"), "{text}");
        assert!(codex_config("b", "m", Some(("https://g", "k"))).contains("[mcp_servers.noomesh]"));
        ws.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_cli_is_never_run_as_root() {
        let env: BTreeMap<String, String> = [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect();
        let jail = crate::harness::jail::JailSpec { workspace: PathBuf::from("/nonexistent-ws"), home: PathBuf::from("/nonexistent-home"), tmp: PathBuf::from("/nonexistent-tmp"), ca_file: None, extra_ro: Vec::new(), data_root: None };
        let err = spawn_cli_as(&["true".to_string()], &env, Path::new("/"), Duration::from_secs(5), &jail, Some(RunAs { uid: 0, gid: 0 })).await.unwrap_err();
        assert!(err.to_string().contains("uid 0"), "{err}");
    }

    #[test]
    fn a_codex_mode_without_a_home_is_refused() {
        let mut k = codex_kind(&["codex", "exec", "{prompt}"]);
        k.launch.as_mut().unwrap().home_env = None;
        assert!(validate_kind(&k).unwrap_err().to_string().contains("home_env"));
        k.launch.as_mut().unwrap().mcp = "config-file:yaml".into();
        assert!(validate_kind(&k).is_err());
    }

    #[tokio::test]
    async fn a_turn_returns_the_cli_answer_and_saves_both_sides() {
        let root = scratch("turn");
        let k = kind(&["sh", "-c", "echo the answer is 42"], &[], &[]);
        let ctx = ctx_for(&k, &root, "30");
        let rail = FakeRail::new();
        let req = TurnRequest {
            conversation_id: "c1".into(),
            prompt: "what is it?".into(),
            channel: "dashboard".into(),
            max_iterations: 5,
            model: None,
            user: "alice".into(),
            enable_thinking: false,
            role_prompt: None,
            stream: true,
            token: TURN_TOKEN.into(),
        };
        let r = run_turn_on(&ctx, &rail, &req).await.unwrap();
        assert_eq!(r.response, "the answer is 42");
        assert_eq!(r.node.as_deref(), Some("awolf"));
        let c = rail.calls.lock().unwrap();
        assert_eq!(c.saved, vec![("user".to_string(), "what is it?".to_string()), ("assistant".to_string(), "the answer is 42".to_string())]);
        assert_eq!(c.keys_revoked.len(), 1);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "the turn's workspace is removed");
        let _ = std::fs::remove_dir_all(root);
    }
}
