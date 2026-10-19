// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Configuration — reads noomesh.yaml (the same file format the now-deleted
//! Python gateway used to read).
//!
//! Uses #[serde(default)] everywhere so missing fields don't break
//! deserialization. The Rust gateway can run with a minimal config.

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

use crate::paths;

/// The one reader for tier-1 secrets (`NAME_FILE` > `NOO_SECRET_NAME` >
/// `NAME`). It lives at `src/secret_env.rs` and is declared from here, not
/// `main.rs`, only because the PR that added it could not touch `main.rs`
/// (parallel edits landing on the same lines); moving this line up to the
/// crate root is a one-line follow-on. Reach it as `crate::config::secret_env`.
#[path = "secret_env.rs"]
pub mod secret_env;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AppConfig {
    /// Which add-ons this install runs. The ONE declaration — there is no
    /// per-add-on environment variable any more. A name absent from the map
    /// means "the operator did not say", which resolves to the add-on's own
    /// polarity in `addons::ADDONS` (trellion opt-out, licensed ones opt-in).
    ///
    /// Read by `addons::state` for routing and refusals, and by the launcher
    /// for compose profiles and overlays — the same map, so what got deployed
    /// and what the gateway will route to cannot disagree.
    #[serde(default)]
    pub addons: std::collections::HashMap<String, bool>,
    /// What an operator allows each add-on to do on a present person's behalf.
    /// Separate from `addons:` on purpose: that map is `name: bool`, read as
    /// such by the launcher and the CLI (and by an older gateway, which would
    /// refuse a whole config it could not parse), and a switch that widens an
    /// add-on's authority deserves its own gated section
    /// (`settings::GATED_CONFIG_SECTIONS`). Absent = nothing is delegated.
    /// Read by `addon_registry`; see "Delegation" there.
    #[serde(default)]
    pub addon_delegation: std::collections::HashMap<String, AddonDelegationConfig>,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub coordinator: CoordinatorConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub watched_folders: WatchedFoldersConfig,
    #[serde(default)]
    pub watched_drives: WatchedDrivesConfig,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub worker: WorkerConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    /// Absent means "not stated" → the ddg default, so an install that never
    /// mentions search keeps working exactly as before.
    #[serde(default)]
    pub search: Option<SearchConfig>,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub inference: InferenceConfig,
    #[serde(default)]
    pub workspace: WorkspaceConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    /// Systems that extend this database — the design's broker manifest.
    #[serde(default)]
    pub systems: std::collections::BTreeMap<String, SystemConfig>,
}

/// `addon_delegation.<name>` in noomesh.yaml. The manifest declares
/// (`delegate: "tasks"`), the operator allows (`tasks: true`); both are
/// needed, and the default is off.
///
/// Unknown keys are ignored, not refused: a config with a key a newer
/// release added must still parse on this one (an unparseable noomesh.yaml
/// reads as an EMPTY config).
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AddonDelegationConfig {
    /// Let this add-on create and steer a present person's tasks.
    #[serde(default)]
    pub tasks: bool,
}

/// One entry in the `systems:` manifest.
///
/// The manifest DECLARES; it does not activate. Every system the stack knows
/// about is listed here on every install, and `enabled_when` decides which of
/// them mesh actually provisions. Same shape the voice profile already uses —
/// the whisper/piper service blocks are always in compose, and
/// `NOO_VOICE_ENABLED` is what deploys them.
///
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SystemConfig {
    /// Runtime login role. Reads and writes this system's tables; holds no
    /// CREATE, so a runtime bug cannot add tables.
    pub role: String,
    /// Migration login role. Owns the schema and is the only identity that
    /// can create in it. Separate from `role` on purpose: they are different
    /// privileges used at different times, and collapsing them means the
    /// runtime holds DDL rights every second it is up.
    pub ddl_role: String,
    /// Schema this system's tables live in. Owned by `ddl_role`.
    pub schema: String,
    /// Env var whose truthiness means "the operator turned this on". Absent =
    /// unconditional (trellion, which is mandatory since the container split).
    ///
    /// Deliberately NOT "is the password set". `noo-cli` generates every role
    /// password from an unconditional `SecretSpec`, so credential presence is
    /// not evidence of intent — gating on it creates a `noo_evolve` login role
    /// on OSS installs that will never run noo-evolve.
    #[serde(default)]
    pub enabled_when: Option<String>,
    /// Env var holding the runtime role's password. Read only when the role
    /// must be CREATED; an existing role is never touched.
    pub password_env: String,
    /// Env var holding the migration role's password. Same rule.
    pub ddl_password_env: String,
    /// Postgres extensions this system's schema needs (e.g. `vector`,
    /// `pg_trgm`). Installed by the BROKER, because both are untrusted in
    /// this image and `CREATE EXTENSION` therefore needs superuser — which
    /// is the one reason trellion's migration chain still runs privileged.
    /// Declaring them here is what lets that chain drop to its DDL role.
    #[serde(default)]
    pub extensions: Vec<String>,
}

/// Writable directory where agents save reports, artifacts, and logs.
///
/// Distinct from `watched_folders`, which are read-only and auto-ingested;
/// workspace content is ingested only on explicit request.
///
/// Mirrors `config.py::WorkspaceConfig`. Both sides must agree, because a
/// heartbeat action can run on either — a Rust/Python disagreement here would
/// write artifacts to two different directories depending on the path taken.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct WorkspaceConfig {
    /// Host-side absolute path (empty = not configured). Informational to the
    /// gateway, which only ever sees the container-internal mount.
    #[serde(default)]
    pub host: String,
    /// Container-internal mount path (e.g. `/workspace`).
    #[serde(default)]
    pub mount: String,
    #[serde(default)]
    pub enabled: bool,
}

/// Tool-facing settings the gateway reads from `noomesh.yaml`.
///
/// Only the fields the native tools need are modeled; the Python side owns
/// the richer `ToolsConfig` (enabled list, always_include) for its registry.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ToolsConfig {
    /// Read allow-list for `local_files` (merged with watched-folder
    /// mounts + workspace by `local_files::FilePolicy::from_config`,
    /// mirroring Python `get_file_allowed_paths`).
    #[serde(default)]
    pub allowed_paths: Vec<String>,
}

/// Default container mount when `workspace.enabled` is set without an explicit
/// `mount`. Matches `config.py::_WORKSPACE_DEFAULT_MOUNT`.
const WORKSPACE_DEFAULT_MOUNT: &str = "/workspace";

impl WorkspaceConfig {
    /// Container-internal path for runtime use; empty when not configured.
    ///
    /// Port of the `path` property in `config.py::WorkspaceConfig`.
    pub fn path(&self) -> String {
        if !self.enabled {
            return String::new();
        }
        if self.mount.is_empty() {
            WORKSPACE_DEFAULT_MOUNT.to_string()
        } else {
            self.mount.clone()
        }
    }
}

/// Infrastructure/service endpoints (config-graduation phase 2).
///
/// Every field is optional: the resolution order at each read site is
/// env var → this YAML section → the compiled-in default (see
/// [`env_or_yaml`]). Secrets (DSN passwords, tokens) stay in .env — the
/// URL forms here are hostname/port topology only.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ServicesConfig {
    #[serde(default)]
    pub nats_url: Option<String>,          // env NATS_URL
    #[serde(default)]
    pub redis_url: Option<String>,         // env REDIS_URL (password injected from secrets)
    #[serde(default)]
    pub database_url: Option<String>,      // env DATABASE_URL (prefer secret file for creds)
    #[serde(default)]
    pub ollama_url: Option<String>,        // env OLLAMA_URL
    #[serde(default)]
    pub gateway_url: Option<String>,       // env NOO_GATEWAY_URL
    #[serde(default)]
    pub prometheus_url: Option<String>,    // env NOO_PROMETHEUS_URL
    #[serde(default)]
    pub loki_url: Option<String>,          // env NOO_LOKI_URL
    #[serde(default)]
    pub alertmanager_url: Option<String>,  // env NOO_ALERTMANAGER_URL
    #[serde(default)]
    pub embedding_url: Option<String>,     // env PAGEINDEX_EMBEDDING_URL
    #[serde(default)]
    pub embedding_backend: Option<String>, // env PAGEINDEX_EMBEDDING_BACKEND (wire format: tei | openai | ollama)
    #[serde(default)]
    pub embedding_model: Option<String>,   // env PAGEINDEX_EMBEDDING_MODEL (sent to openai/ollama backends)
    #[serde(default)]
    pub embedding_dim: Option<u64>,        // env EMBEDDING_DIM (expected vector dims; must match the store)
    #[serde(default)]
    pub embedding_extra_urls: Option<String>, // env PAGEINDEX_EMBEDDING_EXTRA_URLS (comma-separated extra static embed endpoints, same model/format as embedding_url)
    #[serde(default)]
    pub nvidia_exporter_url: Option<String>, // env NVIDIA_EXPORTER_URL
    #[serde(default)]
    pub stt_url: Option<String>,           // env NOO_STT_URL (STT provider base URL)
    #[serde(default)]
    pub stt_backend: Option<String>,       // env NOO_STT_BACKEND (wire format: openai | whisper)
    #[serde(default)]
    pub stt_model: Option<String>,         // env NOO_STT_MODEL (pin; empty = honour client hint)
    #[serde(default)]
    pub stt_api_key_env: Option<String>,   // env NOO_STT_API_KEY_ENV (NAME of the key-holding env var)
    #[serde(default)]
    pub tts_url: Option<String>,           // env NOO_TTS_URL (TTS provider base URL)
    #[serde(default)]
    pub tts_backend: Option<String>,       // env NOO_TTS_BACKEND (wire format: openai | piper)
    #[serde(default)]
    pub tts_voice: Option<String>,         // env NOO_TTS_VOICE (pin; empty = honour client hint)
    #[serde(default)]
    pub tts_api_key_env: Option<String>,   // env NOO_TTS_API_KEY_ENV (NAME of the key-holding env var)
}

/// Python worker-pool supervision limits (env NOO_WORKER_*).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct WorkerConfig {
    #[serde(default)]
    pub rss_limit_mb: Option<u64>,     // env NOO_WORKER_RSS_LIMIT_MB (0 = disabled)
    #[serde(default)]
    pub timeout_secs: Option<u64>,     // env NOO_WORKER_TIMEOUT_SECS
}

/// `search:` — which backend `web_search` uses.
///
/// Scraping a public HTML endpoint is best-effort and gets blocked, so the backend is selectable. Only non-secret values live here: an
/// API key is a secret and belongs in the secret store, read from env.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SearchConfig {
    /// `ddg` (default), `searxng`, `brave` or `tavily`.
    /// Env override NOO_SEARCH_PROVIDER.
    #[serde(default)]
    pub provider: Option<String>,
    /// Base URL of a SearXNG instance, e.g. `http://noo-searxng:8080`.
    /// Env override NOO_SEARCH_SEARXNG_URL.
    #[serde(default)]
    pub searxng_url: Option<String>,
}

/// Heartbeat scheduler settings.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HeartbeatConfig {
    /// IANA timezone for cron evaluation. Env override NOO_HEARTBEAT_TZ;
    /// a noo_settings DB row wins over both (hot-reloadable).
    #[serde(default)]
    pub tz: Option<String>,
    #[serde(default)]
    /// Retired, not read: heartbeat actions call the
    /// gateway in process. Kept so an existing yaml key still parses.
    pub gateway_url: Option<String>,
}

/// MCP settings. `port` named the dedicated plain-HTTP operator-door
/// listener, removed in stack-v0.2.40 (the door is `/mcp/operator` on the
/// gateway port). The key is still PARSED so an older `noomesh.yaml` keeps
/// loading; nothing reads it.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct McpConfig {
    #[serde(default)]
    pub port: Option<u16>,             // retired: no listener to bind
}

/// Inference token-budget knobs shared by the Rust agent loop.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct InferenceConfig {
    #[serde(default)]
    pub vllm_max_model_len: Option<u32>,  // env VLLM_MAX_MODEL_LEN
    #[serde(default)]
    pub vllm_max_tokens: Option<u32>,     // env VLLM_MAX_TOKENS (output reserve)
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ClusterConfig {
    #[serde(default = "default_backend")]
    pub default_backend: String,
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
    /// Shard identity for this node. Conversations created here get tagged
    /// with this key in metadata.shard_key. Future distributed routing can
    /// use it to send writes/reads to the owning node's local Postgres.
    /// Defaults: env NOO_SHARD_KEY → env NODE_ID → "default".
    #[serde(default)]
    pub shard_key: Option<String>,
}

fn default_backend() -> String { "vllm".into() }

#[derive(Debug, Deserialize, Clone, Default)]
pub struct BackendConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CoordinatorConfig {
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    #[serde(default = "default_max_session_messages")]
    pub max_session_messages: u32,
    #[serde(default)]
    pub enabled: bool,
    /// Maximum input tokens for the context window (output reserve is subtracted separately).
    /// Defaults to 12288 (16K context minus 4K output reserve).
    #[serde(default)]
    pub max_context_tokens: Option<u32>,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            system_prompt: default_system_prompt(),
            max_iterations: default_max_iterations(),
            max_session_messages: default_max_session_messages(),
            enabled: true,
            max_context_tokens: None,
        }
    }
}

fn default_system_prompt() -> String {
    "You are Mesh, a helpful AI assistant with access to tools, \
     a knowledge base, and conversation memory.".into()
}
fn default_max_iterations() -> u32 { 10 }
fn default_max_session_messages() -> u32 { 20 }

#[derive(Deserialize, Clone, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub jwt_secret: String,
    #[serde(default)]
    pub cluster_secret: String,
}

/// Both fields are credentials (the JWT signing key and the fleet HMAC
/// secret), and `AppConfig` derives `Debug`, so a derived impl here would
/// print them from any `{:?}` of the config — a startup log, a panic message,
/// a test failure. Printed as `<redacted>` (or `<empty>` when unset, which is
/// useful to see and is not a secret).
impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown = |v: &str| if v.is_empty() { "<empty>" } else { "<redacted>" };
        f.debug_struct("SecurityConfig")
            .field("jwt_secret", &format_args!("{}", shown(&self.jwt_secret)))
            .field("cluster_secret", &format_args!("{}", shown(&self.cluster_secret)))
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub ca: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct MemoryConfig {
    #[serde(default)]
    pub session_top_k: Option<u32>,
    #[serde(default)]
    pub global_top_k: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WatchedFoldersConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub folders: Vec<FolderEntry>,
    #[serde(default = "default_doc_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_folders_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_recursive")]
    pub recursive: bool,
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    #[serde(default)]
    pub notify_channels: Vec<String>,
    #[serde(default)]
    pub notify_recipients: Vec<String>,
}

impl Default for WatchedFoldersConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            folders: vec![],
            patterns: default_doc_patterns(),
            poll_interval_seconds: default_folders_poll_interval(),
            recursive: default_recursive(),
            max_batch_size: default_max_batch_size(),
            max_file_size_mb: default_max_file_size_mb(),
            notify_channels: vec![],
            notify_recipients: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum FolderEntry {
    Simple(String),
    Detailed {
        host: String,
        mount: String,
        #[serde(default)]
        label: String,
        #[serde(default)]
        writable: bool,
    },
}

impl FolderEntry {
    /// Container-internal path used at runtime. Simple variant returns the
    /// string as-is; Detailed returns the mount path.
    pub fn mount_path(&self) -> &str {
        match self {
            FolderEntry::Simple(s) => s,
            FolderEntry::Detailed { mount, .. } => mount,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            FolderEntry::Simple(_) => "",
            FolderEntry::Detailed { label, .. } => label,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WatchedDrivesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub drives: Vec<WatchedDriveEntry>,
    #[serde(default = "default_doc_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_drives_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default)]
    pub notify_channels: Vec<String>,
    #[serde(default)]
    pub notify_recipients: Vec<String>,
}

impl Default for WatchedDrivesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            drives: vec![],
            patterns: default_doc_patterns(),
            poll_interval_seconds: default_drives_poll_interval(),
            max_file_size_mb: default_max_file_size_mb(),
            max_batch_size: default_max_batch_size(),
            notify_channels: vec![],
            notify_recipients: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WatchedDriveEntry {
    pub drive_id: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub label: String,
    /// Walk subfolders within the drive (or within `folder_id` if pinned).
    /// Default true — matches `watched_folders` behavior.
    #[serde(default = "default_recursive")]
    pub recursive: bool,
}

fn default_doc_patterns() -> Vec<String> {
    vec![
        "*.pdf".into(), "*.md".into(), "*.txt".into(), "*.html".into(),
        "*.docx".into(), "*.pptx".into(), "*.xlsx".into(), "*.csv".into(),
    ]
}
fn default_folders_poll_interval() -> u64 { 60 }
fn default_drives_poll_interval() -> u64 { 300 }
fn default_recursive() -> bool { true }
fn default_max_batch_size() -> usize { 10 }
fn default_max_file_size_mb() -> u64 { 25 }

pub fn load_config() -> Result<AppConfig> {
    let cfg = if let Some(path) = paths::resolve(paths::CONFIG_YAML_CANDIDATES) {
        let contents = std::fs::read_to_string(&path)?;
        let config: AppConfig = serde_yaml::from_str(&contents)?;
        tracing::info!(path = %path.display(), "Config loaded");
        config
    } else {
        tracing::warn!("No noomesh.yaml found, using defaults");
        AppConfig::default()
    };
    let _ = GLOBAL.set(cfg.clone());
    Ok(cfg)
}

/// Process-wide config snapshot for free-function read sites that have no
/// `AppState` handle (config-graduation phase 2). Populated by the first
/// `load_config()` call in `main`; falls back to a lazy load so early
/// readers (pre-main spawns, tests) still see the YAML.
static GLOBAL: std::sync::OnceLock<AppConfig> = std::sync::OnceLock::new();

pub fn global() -> &'static AppConfig {
    GLOBAL.get_or_init(|| load_config_unlogged().unwrap_or_default())
}

fn load_config_unlogged() -> Result<AppConfig> {
    if let Some(path) = paths::resolve(paths::CONFIG_YAML_CANDIDATES) {
        let contents = std::fs::read_to_string(&path)?;
        return Ok(serde_yaml::from_str(&contents)?);
    }
    Ok(AppConfig::default())
}

/// Config-graduation phase 2 resolution helper: env var → YAML value →
/// compiled default. `yaml` is a projection out of the global config
/// (e.g. `|c| c.services.nats_url.clone()`).
pub fn env_or_yaml(
    env_key: &str,
    yaml: impl Fn(&AppConfig) -> Option<String>,
    default: &str,
) -> String {
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return v;
        }
    }
    if let Some(v) = yaml(global()) {
        if !v.is_empty() {
            return v;
        }
    }
    default.to_string()
}

/// Numeric variant of [`env_or_yaml`]: env var (parseable) → YAML → default.
pub fn env_or_yaml_u64(
    env_key: &str,
    yaml: impl Fn(&AppConfig) -> Option<u64>,
    default: u64,
) -> u64 {
    if let Some(v) = std::env::var(env_key).ok().and_then(|s| s.parse().ok()) {
        return v;
    }
    yaml(global()).unwrap_or(default)
}

/// Default ports for inference backends — single source of truth for Rust.
/// Mirrors `BACKEND_PORTS` in `noomesh.gateway.constants`.
pub fn backend_port(backend_type: &str) -> Option<u16> {
    match backend_type {
        "vllm" | "vllm-secondary" => Some(8000),
        "ollama" => Some(11434),
        "llamacpp" => Some(8085),
        _ => None,
    }
}

#[cfg(test)]
mod security_config_debug_tests {
    use super::*;

    #[test]
    fn debug_never_prints_a_secret_value() {
        let c = SecurityConfig { jwt_secret: "jwt-AAAA-do-not-print".into(), cluster_secret: "fleet-BBBB-do-not-print".into() };
        let out = format!("{c:?} {:#?}", c);
        assert!(!out.contains("AAAA") && !out.contains("BBBB"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(format!("{:?}", SecurityConfig::default()).contains("<empty>"));
    }

    #[test]
    fn the_whole_config_debug_is_redacted_too() {
        let mut cfg = AppConfig::default();
        cfg.security.jwt_secret = "jwt-CCCC-do-not-print".into();
        assert!(!format!("{cfg:?}").contains("CCCC"));
    }
}
