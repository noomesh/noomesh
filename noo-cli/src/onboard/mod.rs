// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo onboard` — the setup wizard, ported to the Rust front door so a fresh
//! machine can bootstrap Noomesh from the static binary with NO Python venv
//! present (the zero-Python-bootstrap milestone).
//!
//! Mirrors `src/noomesh/onboard/` step-for-step: prerequisites, environment
//! (.env), security (secrets + native PKI + CA trust), storage, services
//! (docker compose + LLM placement), first model, channels, summary. What
//! shells out (docker/compose, CA-trust install) matches the Python steps;
//! PKI is issued natively via `crate::pki` (no `cryptography` dep), secrets are
//! generated natively (`token_urlsafe` parity), and the .env writer matches
//! Python's key names + sectioned format byte-for-byte.
//!
//! Frontends — the step code is identical behind all of them; each implements
//! the [`event::WizardUi`] event/prompt seam (the Rust mirror of Python's
//! `StepRunner`/`WizardEvent` protocol):
//!   - plain console (default): `prompt::PlainUi` — output to stdout,
//!     prompts to stderr, reads stdin.
//!   - `--tui`: `tui::TuiUi` — full-screen ratatui frontend (WP-W1).
//!     Requires a real terminal (non-TTY → exit 2 with a hint).
//!   - `--web [--port N]`: `web::WebUi` over the SSE `Bridge` — the browser
//!     wizard served from the binary itself (WP-W2).
//!
//! Modes:
//!   - `--non-interactive`/`--ci`: accept defaults + env, never blocks.
//!   - non-TTY + a required value with no default → hard error (exit 1),
//!     same contract as the destructive-confirm commands.
//!   - `--dry-run`: print what each step WOULD do; mutate nothing (the safe
//!     path to demo/verify against an already-live host).
//!
//! Idempotent: a re-run detects existing secrets/services and offers to
//! skip or reconfigure — a bare `noo onboard` on a configured host does NOT
//! blindly rewrite .env or bounce services.

pub(crate) mod env;
pub(crate) mod event;
pub(crate) mod google_chat;
pub(crate) mod prompt;
pub(crate) mod sh;
pub(crate) mod standalone;
pub(crate) mod steps;
mod tui;
pub(crate) mod util;
pub(crate) mod web;
mod yamlcfg;

use std::path::PathBuf;

use crate::{Globals, Unhandled};
use event::{UiEvent, WizardUi};

/// The auto-generated secrets → env var mapping (parity with `_SECRETS`).
/// `agent_review_key` seals agent-to-agent messages;
/// minted here so a fresh onboard never runs the messaging layer in
/// plaintext by accident. `controller_secret` is the
/// controller-local signing secret that scopes fleet-wide node tokens to
/// node routes — minted here so a fresh install never runs in legacy
/// full-access mode.
pub(crate) const SECRETS: &[(&str, &str)] = &[
    ("jwt_secret", "NOO_JWT_SECRET"),
    ("integrations_key", "NOO_INTEGRATIONS_KEY"),
    ("agent_review_key", "NOO_AGENT_REVIEW_KEY"),
    ("controller_secret", "NOO_CONTROLLER_SECRET"),
    ("cluster_secret", "NOO_CLUSTER_SECRET"),
    ("redis_password", "REDIS_PASSWORD"),
    // (`nats_password` → NATS_PASSWORD was minted here until an earlier release
    // retired the shared bus user it was the password of.)
    ("node_agent_token", "NOO_NODE_AGENT_TOKEN"),
    ("postgres_password", "POSTGRES_PASSWORD"),
    // No operator MCP token: the shared NOO_MCP_TOKEN was retired on
    // 2026-09-30. The operator door (/mcp/operator) takes only a per-admin
    // `mcp:operator` service key, issued once the gateway is up
    // (`noo security service-key issue <you>-mcp --scopes mcp:operator
    // --user <admin>`), so a fresh install mints nothing for it here.
    // Per-principal bus credentials. A FRESH install is simply
    // born with them — there is no mixed fleet to carry across, no legacy
    // user to retire, nothing to back-fill. The staged rollout
    // (`noo cluster nats-users render`) exists for installs that predate
    // this and is not something a new box ever runs. Same shape as
    // NOO_CONTROLLER_SECRET: fresh installs are born
    // correct, upgrades opt in. Node credentials are NOT here — a node does
    // not exist at onboard time; `noo cluster provision` mints each node's
    // own credential into its bundle.
    ("nats_gateway_password", "NATS_GATEWAY_PASSWORD"),
    ("nats_worker_password", "NATS_WORKER_PASSWORD"),
];

/// FLOOR of the storage subdirectories under NOO_DATA_ROOT. The step derives
/// its list from the composed config's bind sources
/// (`bind_sources::directory_sources_under`, the preflight's own reader) and
/// uses this only when the config cannot be rendered. It must name every
/// directory source the projection has under the root:
/// tests/test_onboard_storage_dirs_cover_compose.py fails when it does not.
pub(crate) const STORAGE_SUBDIRS: &[&str] = &[
    "noo-data", "redis", "nats", "ollama", "hf-cache", "models", "prometheus", "grafana", "loki", "postgres", "images",
    // The voice add-on's read-only staged-model mounts (i105): created even
    // when voice is off, so turning it on later never hits the bind check.
    "models/voice/whisper", "models/voice/piper",
];

/// The subset of [`STORAGE_SUBDIRS`] that is SENSITIVE STATE and so lives under
/// `NOO_STATE_ROOT` (default: the data root) rather than `NOO_DATA_ROOT`
/// (i10a). Mirrors the compose volumes bound under
/// `${NOO_STATE_ROOT:-${NOO_DATA_ROOT}}`; models, hf-cache, ollama and images
/// are not here and always stay under the data root.
/// tests/test_state_root_groundwork.py holds this to the compose file.
pub(crate) const STATE_SUBDIRS: &[&str] = &["noo-data", "redis", "nats", "prometheus", "grafana", "loki", "postgres"];

/// The eleven step titles, in wizard order — the single source for both
/// `run_all`'s banners and the TUI's step list. DEPENDENCY-ORDERED
/// (finding #16, operator design 2026-08-20): Secrets (credential gen +
/// sops store — zero tailnet deps) runs BEFORE Tailscale so store failures
/// surface before any admin-console time is invested; PKI & Enrollment
/// runs AFTER Tailscale because the gateway cert's SANs need the MagicDNS
/// name + tailnet IP at issuance (access model decision 2026-08-06), and
/// enrollment needs BOTH the store and the tailnet.
pub(crate) const STEP_TITLES: [&str; 11] = [
    "Prerequisites Check",
    "Environment Configuration",
    "Secrets & Admin Account",
    "Tailscale Access",
    "PKI & Cluster Enrollment",
    "Storage Configuration",
    "Service Setup",
    "First Model",
    "Channel Setup (Optional)",
    "Add-ons (free & licensed)",
    "Setup Summary",
];

/// Wizard options threaded to every frontend (historically just the skip
/// flags, hence the name).
#[derive(Default, Clone)]
pub(crate) struct Skip {
    pub tailscale: bool,
    /// `--skip-trellion` — pre-answers NO to the knowledge add-on
    /// question; absent = ask, default yes.
    pub trellion: bool,
    /// `--skip-addons` — leave every add-on flag as it is.
    pub addons: bool,
    pub security: bool,
    pub storage: bool,
    pub services: bool,
    pub model: bool,
    pub channels: bool,
    /// `--mcp-door` / `--no-mcp-door` — pre-answers the MCP user-door
    /// question. None = ask; under --ci, None = closed.
    pub mcp_door: Option<bool>,
    /// `--secrets-backend sops` — accepted for scripts that pass it; `sops`
    /// is the only backend. `env` (plaintext `.env`) is RETIRED and refused
    /// at parse time ([`secrets_backend_flag`]).
    pub secrets_backend: String,
    /// `--only a,b,c` (finding #40): run ONLY the named sections on a
    /// reconfigure — everything else is a no-touch skip. Section names:
    /// prereqs, env, secrets, tailscale, enrollment, storage, services,
    /// model, channels. Empty = the full sequence, as ever.
    pub only: Vec<String>,
}

/// Mutable wizard state (subset of Python's `OnboardState` this port tracks).
#[derive(Default)]
pub(crate) struct State {
    pub mode: String,
    pub tier: u8,
    pub gpu_model: String,
    pub vram_gb: f64,
    pub controller_url: String,
    pub data_root: String,
    /// Failures no later step can recover from (storage root unusable, the
    /// stack did not start). The driver prints them and exits 1 — a wizard
    /// that says "done" and exits 0 over a stack that never came up is the
    /// silent-success shape (2026-09-27 newcomer rehearsal: --ci exited 0
    /// with nine storage failures and no gateway).
    pub hard_failures: Vec<String>,
    /// Secrets the environment step collected (provider API keys) before the
    /// encrypted store existed. The secrets step saves them into the store
    /// right after arming it; never written to `.env`. Wizard memory only.
    pub pending_secrets: Vec<(String, String)>,
    pub env_written: bool,
    pub security_configured: bool,
    pub tls_enabled: bool,
    pub services_started: bool,
    /// The person said no to encrypting at rest (i10a). Held here until the
    /// gateway is up, then recorded by `steps::at_rest_record` (the setting
    /// lives in the gateway's database).
    pub at_rest_opt_out: bool,
    /// The person retyped the state volume's recovery key in the storage
    /// step (i10a PR-C). Recorded with `at_rest_record` once the gateway is
    /// up (`at_rest.recovery_key_acknowledged`, person-only).
    pub at_rest_recovery_ack: bool,
    pub model_pulled: String,
    pub backend_used: String,
    pub admin_username: String,
    /// In-memory ONLY for this run (finding #32): step 3's password so the
    /// services step can log the CLI in the moment the gateway answers.
    /// Never written anywhere — the bcrypt file is the durable record.
    pub admin_password: String,
    pub docker_root_changed: bool,
    pub channels: Vec<String>,
    /// Some(true) = the MCP user door was opened (posture gate set, gateway
    /// restarted); Some(false) = deliberately left closed; None = not asked.
    pub mcp_door: Option<bool>,
    pub user_dir_count: usize,
    pub interrupted: bool,
    /// Why the wizard stopped before the last step, when it did. Set by the
    /// site that stops (`run_all` returns early); `Outcome::of` turns it
    /// into the verdict that BOTH the closing line and the exit code read.
    pub aborted: Option<Abort>,
    /// Tailnet identity detected in the Tailscale step; consumed by the
    /// security step (gateway-cert SANs) and the final summary. Empty =
    /// LAN-only install (tailscale absent, not joined, or step skipped).
    pub ts_dnsname: String,
    pub ts_ip: String,
    pub ts_serve_applied: bool,
    /// Whether the enrollment step set up multinode: None = not asked (`--ci`, dry run), Some(false) = declined.
    pub multinode: Option<bool>,
    /// Converged flow (`--from-archive`): extracted archive dir + the DB
    /// dump to restore in the services step. Empty/None = plain onboard.
    pub archive_dir: Option<std::path::PathBuf>,
    pub restore_db: Option<std::path::PathBuf>,
    /// Persisted dev-vs-dist answer from the services step ("dist" = released
    /// GHCR images, "dev" = build from source). Empty = step skipped/never asked.
    pub install_mode: String,
    /// Instance name + port offset chosen in the environment
    /// step, consumed by the tailscale serve mapping (path mount + gateway
    /// port). Carried in state — envfile::instance() caches the pre-wizard
    /// .env via OnceLock, so re-reading it here would be stale. Empty
    /// instance = default; offset 0 = stock ports.
    pub instance: String,
    pub port_offset: u32,
}

/// What a `--skip-*` flag left UNAPPLIED, for the closing summary. A skipped
/// section is not a clean install: "setup complete" over a run that never
/// created the PKI, minted the service keys or applied the posture profile is
/// the silent success this wizard exists to avoid. One line per skip, naming
/// what is forgone and the command that does it later.
pub(crate) fn not_applied_lines(skip: &Skip) -> Vec<String> {
    let mut lines = Vec::new();
    if skip.security {
        lines.push(
            "NOT applied (--skip-security): secret minting and the encrypted store (JWT, cluster, controller, \
             audit, database, bus), the admin account, and the cluster PKI with enrollment (TLS, mTLS). The gateway \
             will not start without TLS material and the audit key — run: noo onboard --only secrets, then noo onboard --only enrollment"
                .to_string(),
        );
    }
    if skip.services {
        lines.push(
            "NOT applied (--skip-services): starting the stack, the per-service keys, and the hardened posture \
             profile (exec approval, unprivileged node-agent). Until applied, gates sit at code defaults — run: \
             noo stack start, then noo security service-key provision <name> and noo security posture apply-profile hardened"
                .to_string(),
        );
    }
    lines
}

impl State {
    fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Mode: {}", self.mode), format!("Tier: {}", self.tier)];
        if !self.gpu_model.is_empty() {
            lines.push(format!("GPU: {} ({:.0} GB VRAM)", self.gpu_model, self.vram_gb));
        }
        if !self.data_root.is_empty() {
            lines.push(format!("Storage: {}", self.data_root));
        }
        if self.docker_root_changed {
            lines.push("Docker data-root: relocated (restart Docker to apply)".to_string());
        }
        if !self.ts_dnsname.is_empty() {
            let serve = if self.ts_serve_applied { "serve mapping applied" } else { "serve mapping NOT applied" };
            lines.push(format!("Tailscale: {} ({serve})", self.ts_dnsname));
        } else {
            lines.push("Tailscale: not configured — LAN-only access".to_string());
        }
        if self.security_configured {
            if self.tls_enabled {
                lines.push("Security: Fully configured (auth + TLS + mTLS)".to_string());
            } else {
                lines.push("Security: Configured (auth enabled) — NO TLS material: the gateway refuses to start until `noo onboard --only enrollment` mints it".to_string());
            }
        } else {
            lines.push("Security: Skipped — the gateway refuses to start without TLS material; run `noo onboard --only enrollment`".to_string());
        }
        if self.env_written {
            lines.push("Env: .env written".to_string());
        }
        if self.services_started {
            lines.push("Services: started".to_string());
        }
        if !self.install_mode.is_empty() {
            let how = if self.install_mode == "dist" { "released images" } else { "build from source" };
            lines.push(format!("Install mode: {} ({how})", self.install_mode));
        }
        if !self.model_pulled.is_empty() {
            let via = if self.backend_used.is_empty() {
                String::new()
            } else {
                format!(" via {}", self.backend_used)
            };
            lines.push(format!("Model: {}{}", self.model_pulled, via));
        } else if self.services_started {
            // The model step was skipped (--skip-model) or declined, so no
            // chat model was pulled here — and the services step's own
            // default-model pull is now gated on a model already existing
            // (2026-09-28 rehearsal: --skip-model still downloaded a
            // multi-GB chat model without that gate). Say so.
            lines.push(
                "Model: none installed — pick one: noo models recommended or noo models pull <model>"
                    .to_string(),
            );
        }
        if self.user_dir_count > 0 {
            lines.push(format!("User directories: {} configured", self.user_dir_count));
        }
        if !self.channels.is_empty() {
            lines.push(format!("Channels: {}", self.channels.join(", ")));
        }
        lines
    }
}

/// Wizard context: config + I/O + mutable state. All output flows through
/// `ui` (the [`WizardUi`] frontend); the emit helpers below keep the step
/// code identical across the console, the TUI, and the web wizard.
pub(crate) struct Ctx<'a> {
    pub g: &'a Globals,
    pub non_interactive: bool,
    pub dry_run: bool,
    pub repo_root: PathBuf,
    pub env_path: PathBuf,
    pub compose_file: PathBuf,
    pub override_file: PathBuf,
    pub pki_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub ui: &'a dyn WizardUi,
    pub asker: prompt::Asker<'a>,
    pub skip: Skip,
    pub state: State,
    /// The decrypted store, loaded at most once per wizard run and dropped
    /// whenever this wizard writes to it. `secret_present` is the only
    /// reader; values never leave the process.
    store_cache: std::cell::RefCell<Option<Result<crate::commands::secrets::SecretStore, String>>>,
    /// Credentials `update_env` REFUSED to write — no encrypted store to put
    /// them in, or the store write failed. `drive` turns a non-empty list
    /// into a hard failure: a wizard that could not save a secret it was
    /// given does not finish green (names only, never values).
    pub unsaved_secrets: std::cell::RefCell<Vec<String>>,
}

impl Ctx<'_> {
    // ── emit helpers (each frontend renders its own glyphs; the plain
    // console reproduces the historical `  ✓ …` format exactly) ──
    pub fn step(&self, n: u8, total: u8, title: &str) {
        self.ui.emit(UiEvent::StepStart { step: n, total, title: title.to_string() });
    }
    /// Pause between steps: emits `step_done`, then waits for the frontend's
    /// Next click where one exists (the web wizard's per-step navigation
    /// pause — parity with the Python web wizard). Console and TUI don't
    /// wait (`wait_next` defaults to a no-op); non-interactive never waits.
    pub fn pause(&self, n: u8, total: u8) {
        self.ui.emit(UiEvent::StepDone { step: n, ok: true });
        if !self.non_interactive {
            self.ui.wait_next(n, total);
        }
    }
    pub fn info(&self, msg: &str) {
        self.ui.emit(UiEvent::Info(msg.to_string()));
    }
    pub fn success(&self, msg: &str) {
        self.ui.emit(UiEvent::Success(msg.to_string()));
    }
    pub fn warn(&self, msg: &str) {
        self.ui.emit(UiEvent::Warning(msg.to_string()));
    }
    pub fn error(&self, msg: &str) {
        self.ui.emit(UiEvent::Error(msg.to_string()));
    }
    pub fn progress(&self, msg: &str) {
        self.ui.emit(UiEvent::Progress(msg.to_string()));
    }
    pub fn dry(&self, action: &str) {
        self.ui.emit(UiEvent::Dry(action.to_string()));
    }
    /// Unindented console line (guard/summary text); an info event elsewhere.
    pub fn raw(&self, line: &str) {
        self.ui.emit(UiEvent::Line(line.to_string()));
    }

    /// Read a key from the live .env.
    pub fn read_env(&self, key: &str) -> String {
        env::read_env_key(&self.env_path, key)
    }

    /// Update-or-append a key in .env (dry-run: print only). `secret` masks the
    /// value in dry-run output.
    pub fn update_env(&self, key: &str, value: &str) {
        if self.dry_run {
            self.dry(&format!("set {key}=<value>"));
            return;
        }
        // NO PLAINTEXT AT ALL. Once the sops store exists, a credential-shaped
        // key goes there and its .env slot is blanked — one choke point for
        // every caller, so the admin password (steps.rs) and the WhatsApp
        // tokens cannot each re-learn the rule separately. The 2026-09-02
        // install had 22 encrypted secrets duplicated in plaintext .env
        // because the wizard wrote them here first and encrypted the whole
        // file afterwards; `secrets audit` reported every one and nothing
        // ran it. A failed store write is a REFUSAL, not a fallback: writing
        // the value to .env "for now" is exactly how the copies appeared.
        if self.sops_active() && !value.is_empty()
            && crate::commands::secrets::looks_like_credential(key)
        {
            match crate::commands::secrets::store_upsert(&[(key.to_string(), value.to_string())]) {
                Ok(()) => {
                    self.store_cache.borrow_mut().take();
                    if let Err(e) = env::update_env_key(&self.env_path, key, "") {
                        self.warn(&format!("could not blank {key} in .env: {e}"));
                    }
                    self.info(&format!("{key} stored encrypted (secrets/env.sops); no plaintext copy"));
                }
                Err(e) => {
                    self.warn(&format!(
                        "{key} NOT stored: sops write failed ({e}). Refusing to write it to \
                         plaintext .env — re-run the step once the store is writable"));
                    self.unsaved_secrets.borrow_mut().push(key.to_string());
                }
            }
            return;
        }
        // And no store at all is the same refusal, not a fallback. The
        // secrets step arms the store BEFORE anything is minted,
        // so reaching here means that step was skipped or refused on
        // an install that is not on the store yet. Blanking a slot is fine.
        if !value.is_empty() && crate::commands::plaintext_env::secret_class(key) {
            self.warn(&format!(
                "{key} NOT stored: this install has no encrypted store, and a secret is never \
                 written to plaintext .env — run: {}",
                crate::commands::plaintext_env::REMEDY_ONBOARD));
            self.unsaved_secrets.borrow_mut().push(key.to_string());
            return;
        }
        if let Err(e) = env::update_env_key(&self.env_path, key, value) {
            self.warn(&format!("could not write {key} to .env: {e}"));
            return;
        }
        self.warn_sops_once();
    }

    /// Does this install hold a value for `key` — in the encrypted store when
    /// the sops backend is armed, or in `.env` before it is (a fresh install
    /// mints into `.env` and encrypts the file one step later)?
    ///
    /// This is the wizard's ONLY notion of "already has this secret". It
    /// used to be the existence of `secrets/<name>.txt`, which meant the
    /// wizard had to keep writing those plaintext files to recognise its
    /// own install — sixteen credentials in the clear beside the encrypted
    /// store, on every box, forever.
    pub fn secret_present(&self, key: &str) -> bool {
        if !self.read_env(key).trim().is_empty() {
            return true;
        }
        if !self.sops_active() {
            return false;
        }
        let mut cache = self.store_cache.borrow_mut();
        let loaded = cache.get_or_insert_with(|| {
            crate::commands::secrets::SecretStore::load_sops(&self.repo_root.join("secrets/env.sops"))
        });
        match loaded {
            Ok(store) => store.state(key) == crate::commands::secrets::State::Set,
            Err(_) => false,
        }
    }

    /// The encrypted store is the live secrets backend for this install.
    /// Drop the cached store after a write that bypassed `update_env`
    /// (`secrets::store_provisioned` writes `env.sops` directly).
    pub fn forget_store_cache(&self) {
        self.store_cache.borrow_mut().take();
    }

    pub fn sops_active(&self) -> bool {
        self.read_env("NOO_SECRETS_BACKEND") == "sops"
            && self.repo_root.join("secrets/env.sops").exists()
    }

    /// Surface the sops-backend .env trap once per wizard run, through the
    /// frontend's warn channel (eprintln would corrupt the TUI screen).
    /// Setting `NOO_SECRETS_BACKEND=sops` itself goes through `update_env`
    /// too, so a re-onboard on a sops install warns exactly once.
    pub fn warn_sops_once(&self) {
        if SOPS_WARNED.get().is_none() && crate::envfile::sops_backend_active() {
            SOPS_WARNED.get_or_init(|| {});
            self.warn(crate::envfile::SOPS_EDIT_WARNING);
        }
    }

    /// Consume the once-per-run sops warning WITHOUT printing it. The
    /// fresh-encryption path calls this right before flipping
    /// `NOO_SECRETS_BACKEND=sops`: warning "re-encrypt after this change"
    /// about the very write that ARMS the backend — one second after the
    /// .env was encrypted — told a fresh operator to fix a problem that
    /// does not exist (readability, finding #69).
    pub fn suppress_sops_warning(&self) {
        SOPS_WARNED.get_or_init(|| {});
    }
}

static SOPS_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Assemble a wizard context for the given frontend.
pub(crate) fn build_ctx<'a>(
    g: &'a Globals,
    ui: &'a dyn WizardUi,
    non_interactive: bool,
    dry_run: bool,
    skip: Skip,
) -> Ctx<'a> {
    let repo_root = crate::envfile::repo_root();
    Ctx {
        g,
        non_interactive,
        dry_run,
        env_path: repo_root.join(".env"),
        compose_file: repo_root.join("docker-compose.cluster.yml"),
        override_file: repo_root.join("docker-compose.override.yml"),
        pki_dir: repo_root.join("pki"),
        secrets_dir: repo_root.join("secrets"),
        ui,
        asker: prompt::Asker { non_interactive, ui },
        skip,
        state: State::default(),
        repo_root,
        store_cache: std::cell::RefCell::new(None),
        unsaved_secrets: std::cell::RefCell::new(Vec::new()),
    }
}

/// `--secrets-backend <v>`: `sops` is the only backend. `env` — secrets in
/// plaintext `.env` — is RETIRED (operator rule: "always sops, never
/// plaintext"), refused with the sops path named, exit 2 like every other
/// bad flag. `Err` carries the exit code after the message is printed.
pub(crate) fn secrets_backend_flag(v: Option<&str>) -> Result<String, i32> {
    match v.map(|v| v.trim().to_lowercase()) {
        Some(v) if v == "sops" => Ok(v),
        Some(v) if v == "env" => {
            crate::ui::failed(
                "--secrets-backend env is retired: secrets are never kept in plaintext .env. \
                 Every install encrypts them at rest with SOPS+age (secrets/env.sops)",
                Some("noo onboard --secrets-backend sops   (or drop the flag: sops is the default)"),
            );
            Err(2)
        }
        _ => {
            crate::ui::failed("--secrets-backend takes 'sops' (the only backend)", None);
            Err(2)
        }
    }
}

/// Entry point. Parses onboard-specific flags. Every frontend is native now:
/// plain console (default), `--tui` (ratatui, WP-W1), `--web [--port N]`
/// (embedded server + SSE, WP-W2). There is no second implementation to fall
/// through to — the Python wizard left the tree — so an unrecognized flag is
/// an ERROR: it prints "unknown onboard flag: …" and exits 2.
pub fn onboard(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut non_interactive = false;
    let mut dry_run = false;
    let mut reconfigure = false;
    let mut tui_mode = false;
    let mut web = false;
    let mut port: u16 = 7080; // Python web wizard default (NOT 8080 — that's the gateway)
    let mut skip = Skip::default();
    // Standalone: run a controller with NO repo checkout — materialise the
    // embedded deploy slice under ~/.noo and drive the wizard from there.
    let mut standalone = false;
    let mut bundle: Option<String> = None;
    let mut from_archive: Option<String> = None;
    let mut archive_pass_file: Option<String> = None;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--non-interactive" | "--ci" => non_interactive = true,
            "--dry-run" => dry_run = true,
            "--reconfigure" => reconfigure = true,
            "--standalone" => standalone = true,
            // Converged migration (operator, 2026-09-01: "import is the
            // onboard/standalone with just a different entrypoint right?"):
            // the archive pre-fills answers (secrets, yaml, PKI, data root)
            // and adds ONE step (DB restore) — every other step (tailnet
            // tags, serve, OAuth capture, cert SANs, embedder) is the same
            // machinery as a fresh onboard, so import can never again miss
            // a step onboard has.
            "--from-archive" => match it.next() {
                Some(a) => from_archive = Some(a.clone()),
                None => {
                    crate::ui::failed("--from-archive needs a path", None);
                    return Ok(2);
                }
            },
            "--passphrase-file" => match it.next() {
                Some(f) => archive_pass_file = Some(f.clone()),
                None => {
                    crate::ui::failed("--passphrase-file needs a path", None);
                    return Ok(2);
                }
            },
            // Retired 2026-09-28: the monitoring set (Grafana/Prometheus/
            // Loki/…) rides the `standalone` profile itself now, so every
            // install runs it. Accepted so an old script keeps working;
            // it changes nothing.
            "--with-monitoring" => {
                eprintln!("• --with-monitoring is no longer needed: every install runs the monitoring set");
            }
            // Mode B: materialise from an EXTERNAL bundle (url|path)
            // instead of the embedded assets — config unpinned from the CLI
            // version. Produce one with `noo bundle export`.
            "--bundle" => match it.next() {
                Some(b) => bundle = Some(b.clone()),
                None => {
                    crate::ui::failed("--bundle needs a url or path (see `noo bundle export <out.tar.gz>`)", None);
                    return Ok(2);
                }
            },
            t if t.starts_with("--bundle=") => {
                bundle = Some(t["--bundle=".len()..].to_string());
            }
            "--tui" => tui_mode = true,
            "--web" => web = true,
            "--port" => match it.next().and_then(|v| v.parse::<u16>().ok()) {
                Some(p) => port = p,
                None => {
                    crate::ui::failed("--port needs a port number (1-65535)", None);
                    return Ok(2);
                }
            },
            "--only" => match it.next() {
                Some(v) => {
                    skip.only = v.split(',').map(|x| x.trim().to_lowercase())
                        .filter(|x| !x.is_empty()).collect();
                    const VALID: [&str; 10] = ["prereqs","env","secrets","tailscale",
                        "enrollment","storage","services","model","channels","addons"];
                    if let Some(bad) = skip.only.iter().find(|x| !VALID.contains(&x.as_str())) {
                        crate::ui::failed(&format!("--only: unknown section '{bad}' (valid: {})", VALID.join(", ")), None);
                        return Ok(2);
                    }
                }
                None => { crate::ui::failed("--only needs section name(s), e.g. --only enrollment", None); return Ok(2); }
            },
            "--skip-tailscale" => skip.tailscale = true,
            "--skip-addons" => skip.addons = true,
            "--skip-security" => skip.security = true,
            "--skip-storage" => skip.storage = true,
            "--skip-services" => skip.services = true,
            "--skip-trellion" => skip.trellion = true,
            "--skip-model" => skip.model = true,
            "--skip-channels" => skip.channels = true,
            "--mcp-door" => skip.mcp_door = Some(true),
            "--no-mcp-door" => skip.mcp_door = Some(false),
            "--secrets-backend" => match secrets_backend_flag(it.next().map(String::as_str)) {
                Ok(v) => skip.secrets_backend = v,
                Err(code) => return Ok(code),
            },
            t if t.starts_with("--port=") => match t["--port=".len()..].parse::<u16>() {
                Ok(p) => port = p,
                Err(_) => {
                    crate::ui::failed("--port needs a port number (1-65535)", None);
                    return Ok(2);
                }
            },
            t if t.starts_with("--secrets-backend=") => {
                match secrets_backend_flag(Some(&t["--secrets-backend=".len()..])) {
                    Ok(v) => skip.secrets_backend = v,
                    Err(code) => return Ok(code),
                }
            }
            // The Rust wizard is the ONLY wizard — the Python reference was
            // archived (legacy/python-onboard) after its dead tailscale-SAN
            // code shipped a broken cert. Unknown flags are an error, not a
            // silent fallthrough to a second implementation.
            t => {
                crate::ui::failed(&format!("unknown onboard flag: {t}"), None);
                return Ok(2);
            }
        }
    }

    if tui_mode && web {
        crate::ui::failed("choose one frontend: --tui (terminal) or --web (browser), not both", None);
        return Ok(2);
    }

    // Flag/TTY guards fire BEFORE any standalone side effects: `--tui`
    // without a terminal must exit 2 regardless of repo context — the
    // auto-detect below otherwise shadows it (crate-only CI has no repo, so
    // it flipped standalone and died 1 in the empty-assets refusal; caught
    // by tests/onboard_tui.rs on PR #792's first run).
    if tui_mode && (!prompt::stdin_is_tty() || !prompt::stdout_is_tty()) {
        eprintln!(
            "✗ `noo onboard --tui` needs an interactive terminal (stdin/stdout is not a TTY)."
        );
        eprintln!(
            "  hint: run plain `noo onboard` for console prompts, or `noo onboard --ci` for non-interactive setup"
        );
        return Ok(2);
    }

    // ── Auto-detect standalone ──────────────
    // A bare `noo onboard` with NO repo anywhere used to fall through to the
    // nonexistent ~/pai-assistant and fail confusingly — exactly the fresh
    // product box. Standalone becomes the DEFAULT for that case only;
    // standing inside a checkout (or having the canonical ~/pai-assistant, or
    // an existing standalone home) keeps today's behaviour untouched.
    // --standalone stays the explicit override in the other direction.
    if !standalone && std::env::var("NOO_REPO_ROOT").is_err() {
        let root = crate::envfile::repo_root();
        if root.join(".noo-standalone").exists() {
            // Re-onboard of an existing standalone home: repo_root() resolves
            // to ~/.noo via the marker fallback and a compose file IS there
            // (materialised) — but the run still needs prepare()'s env
            // plumbing (dist force, overlay noops), so it must be standalone.
            println!("{}", crate::ui::status_line(crate::ui::Glyph::Bullet, &format!("existing standalone install at {} — continuing in STANDALONE mode", root.display())));
            standalone = true;
        } else if !root.join("docker-compose.cluster.yml").exists() {
            println!("{}", crate::ui::status_line(crate::ui::Glyph::Bullet, "no repo checkout found — onboarding in STANDALONE mode (embedded deploy slice)"));
            eprintln!("  (run from a checkout, or set NOO_REPO_ROOT, for a repo-based install)");
            standalone = true;
        }
    }
    if from_archive.is_some() {
        standalone = true; // the converged flow targets the state home
    }

    // `standalone` is now settled (explicit or auto-detected), so this guard
    // must run AFTER the auto-detect block above — otherwise a bare
    // `noo onboard --bundle …` on a fresh box (which auto-detects standalone
    // a few lines up) was refused before that detection ran.
    if bundle.is_some() && !standalone {
        crate::ui::failed("--bundle only applies to --standalone onboarding", None);
        return Ok(2);
    }

    // ── --from-archive: open + stage BEFORE any home mutation ───────────
    // Fail-fast contract: a bad archive/passphrase must error with its
    // real name and ZERO side effects — before the deploy slice
    // materialises, before any file lands (CI pinned this ordering).
    // The archive supplies what a fresh wizard would ask for or mint:
    // age key (guarded), secret store, noomesh.yaml, PKI (CA continuity —
    // workers stay trusted; the enrollment step re-issues SAN-correct leaf
    // certs on top), the data-root default, and the DB dump the services
    // step restores. Everything else — tailnet join/tags/serve, OAuth
    // capture, embedder, watcher — is the SAME code path as plain onboard.
    let mut archive_state: (Option<std::path::PathBuf>, Option<std::path::PathBuf>) = (None, None);
    let mut _archive_stage: Option<std::path::PathBuf> = None;
    if let Some(ref arch) = from_archive {
        match crate::commands::migrate::open_archive(g, arch, &archive_pass_file) {
            Err(e) => {
                crate::ui::failed(&format!("could not open the archive: {e}"), None);
                return Ok(1);
            }
            Ok((stage, extracted, manifest)) => {
                let home = standalone::default_home();
                let _ = std::fs::create_dir_all(&home);
                // Age key first, with the different-key guard.
                // A restore writes the plaintext home, never the sealed
                // runtime file (that one belongs to noo-unseal.service).
                let key_dst = crate::age_key::default_path();
                let src_key = extracted.join("age/keys.txt");
                if key_dst.exists()
                    && std::fs::read(&key_dst).ok() != std::fs::read(&src_key).ok()
                {
                    crate::ui::failed(&format!("a DIFFERENT age key already exists at {} — move it aside first", key_dst.display()), None);
                    let _ = std::fs::remove_dir_all(&stage);
                    return Ok(1);
                }
                let _ = std::fs::create_dir_all(key_dst.parent().unwrap());
                let _ = std::fs::copy(&src_key, &key_dst);
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&key_dst, std::fs::Permissions::from_mode(0o600));
                // Carried state files land only where nothing exists yet —
                // live files always win over the archive.
                for rel in ["noomesh.yaml", ".sops.yaml"] {
                    let dst = home.join(rel);
                    if !dst.exists() {
                        let _ = std::fs::copy(extracted.join("home").join(rel), &dst);
                    }
                }
                // The WHOLE secrets dir — env.sops alone missed the SA key
                // and the generated password files (operator catch,
                // 2026-09-01, before this flow's first live run). Per-file,
                // live-beats-archive.
                let src_secrets = extracted.join("home/secrets");
                if src_secrets.is_dir() {
                    let dst_secrets = home.join("secrets");
                    let _ = std::fs::create_dir_all(&dst_secrets);
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ = std::fs::set_permissions(
                        &dst_secrets, std::fs::Permissions::from_mode(0o700));
                    if let Ok(rd) = std::fs::read_dir(&src_secrets) {
                        for e in rd.flatten() {
                            let dst = dst_secrets.join(e.file_name());
                            if e.path().is_file() && !dst.exists() {
                                let _ = std::fs::copy(e.path(), &dst);
                            }
                        }
                    }
                }
                let src_pki = extracted.join("home/pki");
                if src_pki.is_dir() && !home.join("pki/ca.crt").exists() {
                    let _ = std::process::Command::new("cp")
                        .args(["-a"])
                        .arg(&src_pki)
                        .arg(home.join("pki"))
                        .status();
                }
                // Data-root default for the storage step (env is its
                // first-choice lane) — only when the carried path exists.
                if let Some(dr) = manifest["data_root"].as_str() {
                    if !dr.is_empty() && std::path::Path::new(dr).is_dir() {
                        std::env::set_var("NOO_DATA_ROOT", dr);
                    }
                }
                let dump = extracted.join("db/pg.sql.gz");
                let restore = dump.is_file().then(|| dump.clone());
                eprintln!(
                    "• archive staged: secrets/config/PKI pre-filled{} — the wizard runs normally on top",
                    if restore.is_some() { ", database restore queued for the services step" } else { "" }
                );
                archive_state = (Some(extracted), restore);
                _archive_stage = Some(stage);
            }
        }
    }

    // Standalone setup happens BEFORE frontend dispatch so every frontend
    // (plain/tui/web) picks up the materialised home via repo_root(). It
    // materialises the deploy slice (embedded by default, an external bundle
    // with --bundle), points repo_root at ~/.noo, forces dist, and noops the
    // dev-only source overlays.
    if standalone {
        let home = standalone::default_home();
        if let Some(ref b) = bundle {
            if let Err(e) = standalone::prepare_from_bundle(&home, b) {
                crate::ui::failed(&format!("standalone (bundle) setup failed: {e}"), None);
                return Ok(1);
            }
            eprintln!("• standalone: materialised bundle {b} under {} (dist)", home.display());
        } else {
            if let Err(e) = standalone::prepare(&home) {
                crate::ui::failed(&format!("standalone setup failed: {e}"), None);
                return Ok(1);
            }
            eprintln!(
                "• standalone: materialised {} assets under {} (dist)",
                standalone::asset_count(),
                home.display(),
            );
        }
    }

    if from_archive.is_some() && (tui_mode || web) {
        crate::ui::failed("--from-archive drives the plain CLI wizard (drop --tui/--web)", None);
        if let Some(stage) = _archive_stage { let _ = std::fs::remove_dir_all(&stage); }
        return Ok(2);
    }
    if tui_mode {
        // (TTY guard hoisted above the standalone auto-detect.)
        return Ok(tui::run(g, tui::TuiOptions { non_interactive, dry_run, reconfigure, skip }));
    }

    if web {
        return Ok(web::run_web(g, port, non_interactive, dry_run, reconfigure, skip, web::GRACE));
    }

    let ui = prompt::PlainUi;
    let mut ctx = build_ctx(g, &ui, non_interactive, dry_run, skip);
    ctx.state.archive_dir = archive_state.0;
    ctx.state.restore_db = archive_state.1;
    let code = drive(&mut ctx, reconfigure);
    if let Some(stage) = _archive_stage {
        let _ = std::fs::remove_dir_all(&stage);
    }
    Ok(code)
}

/// Why the wizard stopped early. Which variant is the whole point: a missing
/// prerequisite is a failure (exit 1), a user answering "no" to a question
/// that was theirs to answer is a cancellation (exit 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Abort {
    Failed { step: &'static str, reason: String },
    Cancelled { reason: String },
}

/// The one verdict of a wizard run. The closing "did NOT complete" text and
/// the process exit code are both derived from it (`exit_code`,
/// `closing_failures`), never decided separately, so they cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Completed,
    Failed(Vec<String>),
    Cancelled(String),
}

impl Outcome {
    /// An early stop wins over later hard failures (nothing after it ran);
    /// otherwise any recorded hard failure fails the run.
    pub(crate) fn of(state: &State) -> Outcome {
        match &state.aborted {
            Some(Abort::Failed { step, reason }) => Outcome::Failed(vec![format!("{step}: {reason}")]),
            Some(Abort::Cancelled { reason }) => Outcome::Cancelled(reason.clone()),
            None if !state.hard_failures.is_empty() => Outcome::Failed(state.hard_failures.clone()),
            None => Outcome::Completed,
        }
    }

    /// 0 completed, 1 failed (the CLI's generic failure code, NOO_CLI.md),
    /// 0 cancelled: the user declined a question that was theirs to
    /// answer, and nothing is broken.
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Outcome::Completed | Outcome::Cancelled(_) => 0,
            Outcome::Failed(_) => 1,
        }
    }

    /// The failures the closing block lists; empty exactly when the
    /// process exits 0.
    pub(crate) fn closing_failures(&self) -> &[String] {
        match self {
            Outcome::Failed(f) => f,
            _ => &[],
        }
    }
}

/// A required step cannot proceed. (A user's own "no" is recorded where it
/// is asked, as `Abort::Cancelled`, e.g. the Tailscale step.)
fn abort_failed(ctx: &mut Ctx, step: &'static str, reason: &str) {
    ctx.state.interrupted = true;
    ctx.state.aborted = Some(Abort::Failed { step, reason: reason.to_string() });
}

/// The full onboard flow behind any frontend: idempotent-install guard,
/// dry-run banner, all steps, final summary. Output/prompts route through
/// `ctx.ui` / `ctx.asker`. Returns the process exit code.
pub(crate) fn drive(ctx: &mut Ctx, reconfigure: bool) -> i32 {
    // ── Idempotent-install guard ─────────────────────────────────────────
    // A bare re-run on a configured host must NOT blindly rewrite .env or
    // bounce services. Detect the existing install and default to "no".
    if !reconfigure && is_configured(ctx) {
        ctx.raw("This machine appears to be already onboarded:");
        for line in detected_summary(ctx) {
            ctx.raw(&format!("  {line}"));
        }
        if ctx.non_interactive {
            // "Configured" reads .env + secrets only; the stack can still be
            // down. Exiting 0 with "nothing to do" beside "core services: not
            // all running" was a silent success (rc.3 rehearsal): the same
            // health check the summary above prints decides the exit code.
            let verdict = configured_rerun_verdict(is_worker_host(ctx), core_services_running());
            match verdict {
                RerunVerdict::Healthy => {
                    ctx.raw("\nNon-interactive re-run on a configured, running host — nothing to do.");
                    ctx.raw("Re-run with --reconfigure to re-apply, or --dry-run to preview.");
                }
                RerunVerdict::StackDown => {
                    ctx.raw("");
                    ctx.error("Core services not all running on this configured host — not \"nothing to do\"");
                    ctx.raw("  Start the stack: `noo stack start` — or re-apply the setup: `noo onboard --reconfigure`");
                    ctx.raw("  `noo health` is the proof.");
                }
            }
            return verdict.exit_code();
        }
        let proceed = ctx
            .asker
            .confirm(
                "Reconfigure this installation? (existing secrets are preserved; \
                 ONE step instead: noo onboard --only \
                 prereqs|env|secrets|tailscale|enrollment|storage|services|model|channels)",
                false,
            );
        if !proceed {
            ctx.raw("\nNo changes made. Use 'noo stack status' to inspect the running stack.");
            return 0;
        }
        ctx.raw("");
    }

    // ── Data-plane guard ─────────────────────────────────────────────────
    // is_configured() looks only at .env + secrets, but the stateful stores
    // are bind mounts under NOO_DATA_ROOT that survive `clean --deep`'s
    // volume-record removal. On 2026-08-06 that turned a "fresh install"
    // into an onboard straight onto the previous database. Never claim
    // fresh while those directories still hold data.
    if !reconfigure && !is_configured(ctx) && !confirm_data_plane_is_fresh(ctx) {
        return 2;
    }

    if ctx.dry_run {
        ctx.warn("dry run — no files written, no services touched");
    }

    run_all(ctx);
    // Provider keys still waiting for a store the secrets step never armed
    // (skipped, or refused): not saved anywhere, and said so.
    for (k, _) in std::mem::take(&mut ctx.state.pending_secrets) {
        ctx.unsaved_secrets.borrow_mut().push(k);
    }
    let unsaved = ctx.unsaved_secrets.borrow().clone();
    if !unsaved.is_empty() {
        ctx.state.hard_failures.push(format!(
            "secrets: {} value(s) NOT saved — no encrypted store to hold them ({}); run: {}",
            unsaved.len(),
            unsaved.join(", "),
            crate::commands::plaintext_env::REMEDY_ONBOARD,
        ));
    }
    // Stopped at the secrets step: there is no install to summarise or
    // verify, and the summary's "partial setup" line would bury the reason.
    let outcome = Outcome::of(&ctx.state);
    if !(ctx.state.interrupted && !outcome.closing_failures().is_empty()) {
        print_final_summary(ctx);
    }
    let failures = outcome.closing_failures();
    if !failures.is_empty() {
        ctx.raw("");
        ctx.error(&format!(
            "onboarding did NOT complete — {} step(s) failed in a way later steps cannot repair:",
            failures.len()
        ));
        for f in failures {
            ctx.raw(&format!("  - {f}"));
        }
        ctx.raw("  Fix the cause and re-run `noo onboard --reconfigure`; `noo health` is the proof.");
    }
    outcome.exit_code()
}

/// Fully-configured signal: .env present + every `SECRETS` file (the four
/// DB-role passwords are generated separately and are not part of this
/// check).
/// (Auth is always on — the old NOO_AUTH_ENABLED .env sentinel is gone, so
/// the secrets themselves are the signal.)
fn is_configured(ctx: &Ctx) -> bool {
    if !ctx.env_path.exists() {
        return false;
    }
    SECRETS.iter().all(|(_, env_var)| ctx.secret_present(env_var))
}

/// True when the stateful data directories are empty (or the user accepts
/// onboarding onto existing data). Reads NOO_DATA_ROOT / NOO_PG_DATA from
/// .env when present — clean --deep removes secrets but leaves .env, so the
/// half-cleaned machine this guard exists for still knows its own paths.
fn confirm_data_plane_is_fresh(ctx: &mut Ctx) -> bool {
    let data_root = match ctx.read_env("NOO_DATA_ROOT") {
        v if v.is_empty() => crate::commands::data_root::DEFAULT_DATA_ROOT.to_string(),
        v => v,
    };
    // The state set (postgres, redis, nats) lives under NOO_STATE_ROOT, which
    // defaults to the data root (i10a).
    let state_root = crate::commands::data_root::state_root_of(Some(ctx.read_env("NOO_STATE_ROOT").as_str()), &data_root);
    let pg_data = match ctx.read_env("NOO_PG_DATA") {
        v if v.is_empty() => format!("{state_root}/postgres"),
        v => v,
    };
    let populated: Vec<String> = [pg_data, format!("{state_root}/redis"), format!("{state_root}/nats")]
        .into_iter()
        .filter(|d| {
            std::fs::read_dir(d)
                .map(|mut it| it.next().is_some())
                .unwrap_or(false)
        })
        .collect();
    if populated.is_empty() {
        return true;
    }
    ctx.raw("");
    ctx.raw("WARNING: no config or secrets found, but the data directories are NOT empty:");
    for d in &populated {
        ctx.raw(&format!("  {d}"));
    }
    ctx.raw("Onboarding would run against this EXISTING data (old database, old users,");
    ctx.raw("old knowledge base) — it would not be a fresh install.");
    if ctx.non_interactive {
        // REFUSE, not "continue anyway". This exact branch is how the
        // 2026-08-14 incident shipped: a --ci fresh-clone onboard saw
        // production's populated postgres/redis/nats dirs right here, printed
        // the warning nobody was watching, and proceeded — the resulting
        // instance opened the live prod database files. A guard that yields
        // in the unattended path guards nothing: CI is exactly where nobody
        // reads the warning.
        if std::env::var("NOO_ONBOARD_ADOPT_DATA").ok().as_deref() == Some("1") {
            ctx.raw("NOO_ONBOARD_ADOPT_DATA=1: adopting the existing data deliberately.");
            return true;
        }
        ctx.error("Refusing non-interactive onboard onto existing data.");
        ctx.raw("Either this machine already runs an install (a second one would SHARE");
        ctx.raw("its database — the 2026-08-14 incident), or stale data survived a");
        ctx.raw("partial clean. Choose deliberately:");
        ctx.raw("  fresh install:   noo stack clean --deep   (offers to wipe these dirs)");
        ctx.raw("  adopt the data:  NOO_ONBOARD_ADOPT_DATA=1 noo onboard --ci …");
        ctx.raw("  second install:  set NOO_DATA_ROOT to a path this machine does not use");
        return false;
    }
    if ctx.asker.confirm("Continue onboarding onto this existing data?", false) {
        return true;
    }
    ctx.raw("");
    ctx.raw("Aborted. For a true fresh install run 'noo stack clean --deep' — it offers");
    ctx.raw("to wipe the bind-mounted data directories — then re-run 'noo onboard'.");
    false
}

fn detected_summary(ctx: &Ctx) -> Vec<String> {
    let mut out = Vec::new();
    let secrets = SECRETS
        .iter()
        .filter(|(_, env_var)| ctx.secret_present(env_var))
        .count();
    out.push(format!("secrets: {secrets}/{} present", SECRETS.len()));
    out.push("auth: always on (invariant)".to_string());
    let ca = ctx.pki_dir.join("ca.crt").exists();
    out.push(format!("PKI: {}", if ca { "CA present" } else { "none" }));
    let running = core_services_running();
    out.push(format!(
        "core services: {}",
        if running { "running" } else { "not all running" }
    ));
    out
}

/// The core containers a controller install runs; the re-run guard's
/// health check and the "core services" summary line read the same set.
const CORE_SERVICES: &[&str] = &["noo-postgres", "noo-redis", "noo-nats", "noo-gateway"];

fn core_services_running() -> bool {
    sh::are_services_running(CORE_SERVICES)
}

/// A worker's core services run on its controller (`CONTROLLER_URL` is
/// written only in worker mode), so their absence here is not a fault.
fn is_worker_host(ctx: &Ctx) -> bool {
    !ctx.read_env("CONTROLLER_URL").trim().is_empty()
}

/// What a non-interactive re-run on an already-configured host concludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RerunVerdict {
    /// Configured and running (or a worker): nothing to do, exit 0.
    Healthy,
    /// Configured, but the core services are not all running: exit 1 and
    /// name the remedy — never "nothing to do".
    StackDown,
}

impl RerunVerdict {
    pub(crate) fn exit_code(self) -> i32 {
        match self {
            RerunVerdict::Healthy => 0,
            RerunVerdict::StackDown => 1,
        }
    }
}

pub(crate) fn configured_rerun_verdict(worker: bool, core_running: bool) -> RerunVerdict {
    if worker || core_running { RerunVerdict::Healthy } else { RerunVerdict::StackDown }
}

/// Drive the steps in order, honoring skip flags. Prerequisites failure in
/// non-interactive aborts (Python parity).
fn run_all(ctx: &mut Ctx) {
    const TOTAL: u8 = 11;
    // --only (finding #40): reconfigure one section without walking the
    // other nine. Config/secrets/tailnet/PKI all persist, so a targeted
    // section is safe — the full walk is only needed at birth.
    let only_wants = |name: &str, ctx: &Ctx| -> bool {
        ctx.skip.only.is_empty() || ctx.skip.only.iter().any(|o| o == name)
    };

    ctx.step(1, TOTAL, STEP_TITLES[0]);
    let prereqs_ok = if only_wants("prereqs", ctx) { steps::prerequisites(ctx) } else {
        ctx.info("Skipped (--only)."); true
    };
    if !prereqs_ok {
        if ctx.non_interactive {
            ctx.error("Prerequisites missing — aborting (non-interactive).");
            abort_failed(ctx, "prerequisites", "required tools are missing (see the list above)");
            return;
        }
        if !ctx.asker.confirm("Continue despite failures?", false) {
            ctx.info("Setup aborted.");
            // Declining to go on does not make the missing prerequisite
            // any less missing: nothing was installed.
            abort_failed(ctx, "prerequisites", "required tools are missing and setup was not continued");
            return;
        }
    }
    ctx.pause(1, TOTAL);

    ctx.step(2, TOTAL, STEP_TITLES[1]);
    if only_wants("env", ctx) { steps::environment(ctx); } else { ctx.info("Skipped (--only)."); }
    ctx.pause(2, TOTAL);

    ctx.step(3, TOTAL, STEP_TITLES[2]);
    if ctx.skip.security || !only_wants("secrets", ctx) {
        ctx.info("Skipped.");
    } else if !steps::secrets_setup(ctx) {
        // No encrypted store: every later step would mint or collect a
        // secret with nowhere to put it. Stop here; `drive` prints why.
        ctx.state.interrupted = true;
        return;
    }
    ctx.pause(3, TOTAL);

    ctx.step(4, TOTAL, STEP_TITLES[3]);
    if ctx.skip.tailscale || !only_wants("tailscale", ctx) {
        ctx.info("Skipped.");
    } else if !steps::tailscale(ctx) {
        return;
    }
    // Asked here, not in the security step: the answer depends on whether
    // the box just joined a tailnet, and a LAN-only install needs it most.
    if only_wants("tailscale", ctx) {
        steps::bind_mode(ctx);
    }
    ctx.pause(4, TOTAL);

    ctx.step(5, TOTAL, STEP_TITLES[4]);
    if ctx.skip.security || !only_wants("enrollment", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::pki_enrollment(ctx);
    }
    ctx.pause(5, TOTAL);

    ctx.step(6, TOTAL, STEP_TITLES[5]);
    if ctx.skip.storage || !only_wants("storage", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::storage(ctx);
        // A "yes" to encryption at rest whose volume could not be made
        // stops here, before any service starts (i10a): never carry on
        // unencrypted after the person said yes.
        if ctx.state.interrupted {
            return;
        }
    }
    ctx.pause(6, TOTAL);

    ctx.step(7, TOTAL, STEP_TITLES[6]);
    if ctx.skip.services || !only_wants("services", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::services(ctx);
        // The gates this install runs under. Needs the gateway (the posture
        // table is its database), which the line above just started, so it
        // rides along here rather than becoming an eleventh step.
        steps::provision_service_keys(ctx);
        steps::security_posture(ctx);
        // The at-rest decision from the storage step, now that there is a
        // gateway to record it in.
        steps::at_rest_record(ctx);
    }
    ctx.pause(7, TOTAL);

    ctx.step(8, TOTAL, STEP_TITLES[7]);
    if ctx.skip.model || !only_wants("model", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::first_model(ctx);
    }
    ctx.pause(8, TOTAL);

    ctx.step(9, TOTAL, STEP_TITLES[8]);
    if ctx.skip.channels || !only_wants("channels", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::channels(ctx);
    }
    // The MCP user door is its own question in the same step: `--skip-channels`
    // is about messaging apps, not about Claude Code on another machine.
    if only_wants("channels", ctx) {
        steps::mcp_door(ctx);
    }
    ctx.pause(9, TOTAL);

    // Add-ons come LAST and stand apart from the core: the free ones are
    // extras you may not want, the licensed ones need an entitlement. They
    // used to be questions buried inside "Service Setup", which made the
    // paid tier read like part of the free install (operator, 2026-09-03).
    ctx.step(10, TOTAL, STEP_TITLES[9]);
    if ctx.skip.addons || !only_wants("addons", ctx) {
        ctx.info("Skipped.");
    } else {
        steps::addons(ctx);
        steps::provision_service_keys(ctx);
        steps::stage_voice_models(ctx);
    }
    ctx.pause(10, TOTAL);
}

fn print_final_summary(ctx: &Ctx) {
    const TOTAL: u8 = 11;
    ctx.step(11, TOTAL, STEP_TITLES[10]);
    // The last thing an operator reads. Run the secrets audit here so a fresh
    // install that ends with "N errors" gets fixed that day, not five days
    // later by eye. Its own output goes to stdout; the verdict goes through
    // the wizard's channel so every frontend shows it.
    if !ctx.dry_run && ctx.sops_active() {
        match crate::commands::secrets::secrets_audit(ctx.g, &[]) {
            Ok(0) => ctx.success("secrets audit: no errors (nothing encrypted is also in plaintext)"),
            // The audit has several ERROR kinds (a plaintext credential, a
            // required key absent, …); name none of them here — the table
            // above already did, and "plaintext" was wrong for the fresh
            // --ci install whose only error was a missing HF_TOKEN.
            Ok(_) => ctx.warn("secrets audit found ERRORS above — read the table; fix before relying on this install"),
            Err(_) => ctx.warn("secrets audit could not run — check the store with: noo security secrets audit"),
        }
    }
    // #45: an --only run leaves the skipped steps' state empty and the
    // summary printed fiction ("Tailscale: not configured", Tier 0) about
    // an install that is fully configured. Suppress the identity lines
    // when the steps that establish them did not run — a targeted run
    // reports only what it touched.
    // The running posture must be the declared one before anyone walks
    // away. The posture step lands rows the gateway reads at START and
    // deliberately does not restart mid-wizard (see `security_posture`);
    // without this, every fresh install ended on a red posture row, and the
    // first `noo stack restart` days later changed behaviour silently.
    if !ctx.dry_run && ctx.state.services_started {
        match posture_pending_restart(ctx.g) {
            None => ctx.warn("could not read the security posture listing — check it with: noo security posture list"),
            Some(pending) if !pending.is_empty() => {
                ctx.progress(&format!("Restarting the gateway so the posture takes effect ({})...", pending.join(", ")));
                let code = sh::run_script_streamed(ctx, "noomesh-restart.sh", &["--force", "gateway"]);
                // https always — the gateway has no plaintext listener.
                let health = "https://localhost:8080/health".to_string();
                if code == 0 && sh::wait_for_http(ctx, &health, 120) {
                    ctx.success("Gateway restarted — posture active");
                } else {
                    ctx.warn("Gateway restart did not complete — run: noo stack restart --force gateway");
                }
            }
            Some(_) => {}
        }
    }
    // An install is not done until it verifies: the same
    // invariants `noo cluster verify --controller` asserts, printed here so
    // the last thing the operator reads is what still needs doing.
    if !ctx.dry_run {
        let args: Vec<String> = FINAL_VERIFY_ARGS.iter().map(|a| a.to_string()).collect();
        match crate::commands::cluster_verify(ctx.g, &args) {
            Ok(0) => ctx.success("cluster verify: every controller invariant holds"),
            Ok(_) => ctx.warn("cluster verify: an invariant does not hold — the remedy is beside each failing row above"),
            Err(_) => ctx.warn("cluster verify could not run — noo cluster verify --controller"),
        }
    }
    if !ctx.skip.only.is_empty() {
        ctx.success(&format!("reconfigured section(s): {}", ctx.skip.only.join(", ")));
        ctx.info("untouched settings are unchanged");
        ctx.info("noo stack status — full service status");
        ctx.info("noo cluster status — full node status");
        return;
    }
    // Outcome first, then the facts as an aligned key-value block, then
    // add-ons, then guidance (`noo … — why` infos render as ▸ hints on the
    // console), then endpoints. The same events drive the TUI and web
    // frontends, which render them in their own way.
    if ctx.state.interrupted {
        ctx.warn("partial setup (interrupted)");
    } else if ctx.dry_run {
        ctx.success("dry run complete — nothing was changed");
    } else {
        ctx.success("setup complete");
    }
    ctx.raw("");
    for line in aligned_kv(&ctx.state.summary_lines()) {
        ctx.raw(&format!("    {line}"));
    }
    for line in not_applied_lines(&ctx.skip) {
        ctx.warn(&line);
    }
    let addons = steps::addons_summary(ctx);
    if !addons.is_empty() {
        ctx.raw("");
        ctx.info("Add-ons");
        for line in addons {
            ctx.raw(&format!("    {line}"));
        }
    }
    ctx.raw("");
    for (cmd, desc) in [
        ("noo stack start", "start all Docker services"),
        ("noo stack status", "show service status"),
        ("noo cluster status", "show cluster node status"),
        ("noo models pull <model>", "pull a model"),
        ("noo rag query \"...\"", "query the knowledge base"),
        ("noo security pki status", "inspect cluster certificates"),
    ] {
        ctx.info(&format!("{cmd} — {desc}"));
    }
    if ctx.state.services_started {
        // The gateway only ever started over TLS (it refuses without the
        // material), so a started stack means an https endpoint.
        let proto = "https";
        ctx.raw("");
        ctx.info("Endpoints");
        let mut rows: Vec<String> = Vec::new();
        // Only when the serve mapping was actually written. Without it the
        // ts.net URL is a closed port — the MCP row below already checked
        // this, the dashboard row did not.
        if !ctx.state.ts_dnsname.is_empty() && ctx.state.ts_serve_applied {
            rows.push(format!("Dashboard (tailnet): https://{}", ctx.state.ts_dnsname));
        } else if !ctx.state.ts_dnsname.is_empty() {
            rows.push(format!(
                "Dashboard (tailnet): not fronted yet — https://{} answers after `noo controller promote`",
                ctx.state.ts_dnsname
            ));
        }
        rows.push(format!("Dashboard: {proto}://localhost:8080"));
        // Only when it runs (an install that has not rolled to a stack
        // with monitoring on the standalone profile has no Grafana yet,
        // and the row sent a stranger to a port that refuses).
        if sh::are_services_running(&[&crate::envfile::container("grafana")]) {
            // The door onboarding derived, not a guess.
            let door = ctx.read_env(crate::commands::grafana_door::ROOT_URL_KEY);
            rows.push(if door.is_empty() { format!("Grafana: {proto}://localhost:3000") } else { format!("Grafana: {door}  (Open Grafana in the console signs you in)") });
        }
        match ctx.state.mcp_door {
            Some(true) => {
                let door = if !ctx.state.ts_dnsname.is_empty() && ctx.state.ts_serve_applied {
                    format!("https://{}/mcp/user", ctx.state.ts_dnsname)
                } else if !ctx.state.ts_ip.is_empty() {
                    format!("https://{}:8080/mcp/user", ctx.state.ts_ip)
                } else {
                    format!("{proto}://<this-host>:8080/mcp/user")
                };
                rows.push(format!("MCP user door: {door}  (open — key: noo security service-key issue <name> --user <you> --scopes mcp)"));
            }
            Some(false) => rows.push("MCP user door: closed  (open later: noo security posture set NOO_MCP_EXTERNAL_ENABLED 1, then noo stack restart gateway)".to_string()),
            None => {}
        }
        for line in aligned_kv(&rows) {
            ctx.raw(&format!("    {line}"));
        }
    }
    if !ctx.dry_run && !ctx.state.interrupted {
        ctx.raw("");
        ctx.info("You're all set. Welcome to Noomesh!");
    }
}

/// `Key: value` lines → `Key    value` with the labels padded to the
/// longest, so a summary block reads as a table in every frontend.
fn aligned_kv(lines: &[String]) -> Vec<String> {
    let split: Vec<(String, String)> = lines
        .iter()
        .map(|l| match l.split_once(": ") {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (l.clone(), String::new()),
        })
        .collect();
    // A fact with no value (an interrupted run never set it) is noise.
    let split: Vec<(String, String)> = split.into_iter().filter(|(_, v)| !v.trim().is_empty()).collect();
    let w = split.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    split.into_iter().map(|(k, v)| format!("{k:<w$}  {v}")).collect()
}

/// The key GET /api/security/posture lists the gates under
/// (`gateway-rust/src/routes/users.rs::posture_list`). Pinned against the
/// route's source by `posture_tests::the_listing_key_is_the_gateways`: the
/// end-of-onboard restart once read `gates` here, matched nothing, and so
/// never fired — every hardened install ran with its posture unapplied.
pub(crate) const POSTURE_LIST_KEY: &str = "posture";

/// The gate keys whose DB row is not what the running gateway booted with
/// (`pending_restart`), read off the posture listing. `None` = the body has
/// no gate list at all — a shape the CLI does not know, which must be said,
/// not read as "nothing pending".
pub(crate) fn pending_restart_keys(posture: &serde_json::Value) -> Option<Vec<String>> {
    let gates = posture[POSTURE_LIST_KEY].as_array()?;
    Some(
        gates
            .iter()
            .filter(|g| g["pending_restart"].as_bool().unwrap_or(false))
            .filter_map(|g| g["key"].as_str().map(str::to_string))
            .collect(),
    )
}

/// Ask the gateway which posture rows wait on a restart.
pub(crate) fn posture_pending_restart(g: &Globals) -> Option<Vec<String>> {
    // The wizard's own login (never a shared secret). Unreadable is `None`,
    // which the caller says out loud.
    pending_restart_keys(&crate::http::get_json_try(g, "/api/security/posture", true, 10).ok()?)
}

/// The arguments of onboard's last step, `noo cluster verify`. Onboard
/// has just started the stack, so `--wait` lets the services that are
/// still starting (Loki answers `/ready` 1-2 min in) settle before the
/// verdict. Otherwise a fresh install ends on a warm-up false failure
pub(crate) const FINAL_VERIFY_ARGS: &[&str] = &["--controller", "--wait"];

#[cfg(test)]
mod final_verify_tests {
    #[test]
    fn onboard_verifies_the_controller_after_warm_up() {
        assert!(super::FINAL_VERIFY_ARGS.contains(&"--controller"));
        assert!(super::FINAL_VERIFY_ARGS.contains(&"--wait"), "onboard must let a fresh stack warm up before judging it");
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::{Abort, Outcome, State};

    fn state_with(aborted: Option<Abort>, hard: &[&str]) -> State {
        State {
            aborted,
            hard_failures: hard.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn each_outcome_maps_to_its_documented_code() {
        assert_eq!(Outcome::Completed.exit_code(), 0);
        assert_eq!(Outcome::Cancelled("said no".into()).exit_code(), 0);
        assert_eq!(Outcome::Failed(vec!["x".into()]).exit_code(), 1);
    }

    #[test]
    fn a_missing_prerequisite_is_a_failure_not_a_cancel() {
        let st = state_with(
            Some(Abort::Failed { step: "prerequisites", reason: "docker compose missing".into() }),
            &[],
        );
        let o = Outcome::of(&st);
        assert_eq!(o.exit_code(), 1);
        assert!(o.closing_failures()[0].contains("prerequisites"));
    }

    #[test]
    fn hard_failures_alone_fail_the_run_and_a_clean_state_completes() {
        assert_eq!(Outcome::of(&state_with(None, &["storage: unusable"])).exit_code(), 1);
        assert_eq!(Outcome::of(&state_with(None, &[])), Outcome::Completed);
    }

    #[test]
    fn the_closing_block_and_the_exit_code_agree_for_every_outcome() {
        // One derivation: "did NOT complete" is printed exactly when the
        // failures list is non-empty, and that list is non-empty exactly
        // when the code is non-zero. Cancelled exits 0 and prints no
        // failure block.
        let cases = [
            state_with(None, &[]),
            state_with(None, &["a"]),
            state_with(Some(Abort::Cancelled { reason: "no".into() }), &[]),
            state_with(Some(Abort::Failed { step: "prerequisites", reason: "r".into() }), &[]),
            state_with(Some(Abort::Cancelled { reason: "no".into() }), &["a"]),
        ];
        for st in &cases {
            let o = Outcome::of(st);
            assert_eq!(
                !o.closing_failures().is_empty(),
                o.exit_code() != 0,
                "summary and exit code disagree for {o:?}"
            );
        }
    }
}

#[cfg(test)]
mod summary_tests {
    use super::State;

    /// A skipped security or services section is reported in the closing
    /// summary with what it forgoes and the command that applies it.
    #[test]
    fn skips_are_listed_as_not_applied_with_the_remedy() {
        use super::{not_applied_lines, Skip};
        assert!(not_applied_lines(&Skip::default()).is_empty());
        let l = not_applied_lines(&Skip { security: true, ..Default::default() });
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("--skip-security") && l[0].contains("PKI") && l[0].contains("noo onboard --only enrollment"), "{l:?}");
        let l = not_applied_lines(&Skip { services: true, ..Default::default() });
        assert!(l[0].contains("service keys") && l[0].contains("posture") && l[0].contains("apply-profile hardened"), "{l:?}");
        assert_eq!(not_applied_lines(&Skip { security: true, services: true, ..Default::default() }).len(), 2);
    }

    /// `--skip-model` (or declining the model step): services ran, nothing
    /// was pulled here. The summary must say so with a next step, not stay
    /// silent (2026-09-28 rehearsal: a stranger had no chat model and no
    /// hint why `noo chat` had nothing to answer with).
    #[test]
    fn no_model_after_services_notes_it_with_a_next_step() {
        let state = State { services_started: true, ..Default::default() };
        let lines = state.summary_lines();
        let line = lines.iter().find(|l| l.starts_with("Model:")).expect("a Model: line");
        assert!(line.contains("none installed"), "line: {line}");
        assert!(line.contains("noo models recommended"), "line: {line}");
        assert!(line.contains("noo models pull"), "line: {line}");
    }

    /// A model WAS pulled — the normal line, not the "none installed" hint.
    #[test]
    fn model_pulled_shows_the_model_not_the_hint() {
        let state = State {
            services_started: true,
            model_pulled: "gemma4:e2b".to_string(),
            backend_used: "ollama".to_string(),
            ..Default::default()
        };
        let lines = state.summary_lines();
        let line = lines.iter().find(|l| l.starts_with("Model:")).expect("a Model: line");
        assert_eq!(line, "Model: gemma4:e2b via ollama");
    }

    /// Services never started (e.g. `--skip-services`, or `--only` ran a
    /// different section) — no model line at all; there is nothing to
    /// react to yet.
    #[test]
    fn no_services_no_model_line() {
        let state = State::default();
        let lines = state.summary_lines();
        assert!(!lines.iter().any(|l| l.starts_with("Model:")), "lines: {lines:?}");
    }
}

#[cfg(test)]
mod posture_tests {
    use super::{pending_restart_keys, posture_pending_restart, POSTURE_LIST_KEY};
    use std::io::{Read, Write};

    /// The listing as `posture_list` builds it: one gate whose DB row the
    /// hardened profile just wrote (pending), one untouched.
    fn real_shape(pending: bool) -> serde_json::Value {
        serde_json::json!({ "count": 2, "retired": [], "posture": [
            { "key": "NOO_EXEC_APPROVAL_MODE", "kind": "gate", "why": "", "running": if pending { serde_json::Value::Null } else { "approval".into() },
              "db_value": "approval", "source": "db", "requires_restart": true, "pending_restart": pending, "bridge": null },
            { "key": "NOO_MCP_EXTERNAL_ENABLED", "kind": "gate", "why": "", "running": null,
              "db_value": null, "source": "default", "requires_restart": true, "pending_restart": false, "bridge": null },
        ]})
    }

    /// A one-request fake gateway on an ephemeral port, plain HTTP.
    fn fake_gateway(body: String) -> (u16, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            req
        });
        (port, h)
    }

    fn globals(port: u16) -> crate::Globals {
        crate::Globals {
            json: false,
            verbose: false,
            gateway_override: Some(format!("http://127.0.0.1:{port}")),
            timeout_secs: None,
            token: None,
            quiet: false,
        }
    }

    /// The gateway answers with the real shape and a pending gate: onboard
    /// must schedule the restart (a non-empty pending list is the trigger).
    #[test]
    fn a_pending_gate_from_the_gateway_schedules_the_restart() {
        let (port, h) = fake_gateway(real_shape(true).to_string());
        let pending = posture_pending_restart(&globals(port));
        let req = h.join().unwrap();
        assert!(req.starts_with("GET /api/security/posture "), "request: {req}");
        assert_eq!(pending, Some(vec!["NOO_EXEC_APPROVAL_MODE".to_string()]));
    }

    /// Nothing set, or everything already running as declared: no restart.
    #[test]
    fn an_empty_or_applied_posture_skips_the_restart() {
        let (port, h) = fake_gateway(serde_json::json!({"count": 0, "posture": [], "retired": []}).to_string());
        assert_eq!(posture_pending_restart(&globals(port)), Some(vec![]));
        h.join().unwrap();
        assert_eq!(pending_restart_keys(&real_shape(false)), Some(vec![]));
    }

    /// A body with no gate list is not "nothing pending" — the old bug read
    /// the wrong key, got nothing, and stayed silent.
    #[test]
    fn a_listing_without_the_gate_list_is_unreadable_not_empty() {
        assert_eq!(pending_restart_keys(&serde_json::json!({"gates": real_shape(true)["posture"]})), None);
    }

    /// Parity with the route: the key onboard reads, and the per-gate fields
    /// it filters on, are the ones `posture_list` writes.
    #[test]
    fn the_listing_key_is_the_gateways() {
        let src = include_str!("../../../gateway-rust/src/routes/users.rs");
        let start = src.find("async fn posture_list(").expect("posture_list in users.rs");
        let body = &src[start..];
        let body = &body[..body.find("\nasync fn ").unwrap_or(body.len())];
        let ret = format!("json!({{ \"{POSTURE_LIST_KEY}\": gates");
        assert!(body.contains(&ret), "posture_list no longer returns the gates under `{POSTURE_LIST_KEY}`");
        assert!(body.contains("\"key\": key,"), "posture_list gate rows lost `key`");
        assert!(body.contains("\"pending_restart\": pending,"), "posture_list gate rows lost `pending_restart`");
    }
}

#[cfg(test)]
mod rerun_tests {
    use super::{configured_rerun_verdict, RerunVerdict};

    #[test]
    fn a_configured_host_with_its_stack_down_is_not_nothing_to_do() {
        let v = configured_rerun_verdict(false, false);
        assert_eq!(v, RerunVerdict::StackDown);
        assert_ne!(v.exit_code(), 0, "a non-interactive re-run over a down stack must not exit 0");
    }

    #[test]
    fn a_running_controller_or_a_worker_is_nothing_to_do() {
        assert_eq!(configured_rerun_verdict(false, true).exit_code(), 0);
        assert_eq!(configured_rerun_verdict(true, false).exit_code(), 0, "a worker's core services run on its controller");
    }

    #[test]
    fn the_non_interactive_guard_exits_on_the_verdict() {
        let src = include_str!("mod.rs");
        let body = &src[src.find("pub(crate) fn drive(").expect("drive")..];
        let guard = &body[..body.find("let proceed = ctx").expect("interactive branch")];
        assert!(guard.contains("return verdict.exit_code();"), "the non-interactive re-run exits on the health verdict");
        assert!(!guard.contains("return 0;"), "no unconditional success in the non-interactive re-run");
    }
}

/// i10a PR-A: the at-rest question is asked in the storage step, and its
/// answer is recorded after the services start, next to the posture.
#[cfg(test)]
mod at_rest_tests {
    use super::State;

    #[test]
    fn no_decision_is_recorded_until_someone_says_no() {
        assert!(!State::default().at_rest_opt_out);
    }

    #[test]
    fn the_answer_is_recorded_after_services_start_and_the_question_is_asked_in_storage() {
        let m = include_str!("mod.rs");
        let posture = m.find("steps::security_posture(ctx);").expect("posture call");
        let record = m.find("steps::at_rest_record(ctx);").expect("the opt-out is never recorded");
        assert!(record > posture, "the flag is written where posture is applied, after the gateway is up");
        let steps = include_str!("steps.rs");
        let storage = &steps[steps.find("pub fn storage(").unwrap()..];
        let storage = &storage[..storage.find("\n}\n").unwrap()];
        assert!(storage.contains("at_rest_choice(ctx, &chosen_root)"), "the storage step does not ask about encryption at rest");
        // the wizard never writes the flag before the gateway exists
        let choice = &steps[steps.find("fn at_rest_choice(").unwrap()..];
        let choice = &choice[..choice.find("\n}\n").unwrap()];
        assert!(!choice.contains("flags/set"), "at_rest_choice must only remember the answer");
        assert!(choice.contains("state.at_rest_opt_out = true"));
        assert!(choice.contains("at_rest_encrypt_fresh(ctx, data_root)"), "'yes' makes the encrypted volume");
    }

    /// i10a PR-C: a "yes" makes the volume BEFORE any state directory and
    /// before any service: the choice is the first thing after the data root
    /// exists, ahead of the state root, postgres' path and the directories;
    /// the storage step runs before the services step; and a failed volume
    /// stops the wizard there.
    #[test]
    fn a_yes_makes_the_volume_before_any_state_or_service() {
        let steps = include_str!("steps.rs");
        let storage = &steps[steps.find("pub fn storage(").unwrap()..];
        let storage = &storage[..storage.find("\n}\n").unwrap()];
        let at = |needle: &str| storage.find(needle).unwrap_or_else(|| panic!("storage() lacks {needle}"));
        let choice = at("if !at_rest_choice(ctx, &chosen_root) {");
        assert!(at("ensure_root_dir(ctx, Path::new(&chosen_root));") < choice, "the data root must exist first (the backing file lives in it)");
        for later in ["state_root_path(ctx,", "ensure_pg_data_path(", "create_storage_dirs(ctx,", "verify_bind_mount("] {
            assert!(choice < at(later), "{later} ran before the at-rest choice: state could be written in the clear");
        }
        assert!(storage[choice..].starts_with("if !at_rest_choice(ctx, &chosen_root) {\n        return;"), "a failed volume must stop the step");
        let m = include_str!("mod.rs");
        let run = &m[m.find("steps::storage(ctx);").unwrap()..];
        let stop = run.find("if ctx.state.interrupted {").expect("run_all must stop after a failed volume");
        assert!(stop < run.find("steps::services(ctx);").unwrap(), "the stop must come before the services start");
        // the yes path is the trait-driven setup_fresh, and a failure is a hard failure
        let enc = &steps[steps.find("fn at_rest_encrypt_fresh(").unwrap()..];
        let enc = &enc[..enc.find("\n}\n").unwrap()];
        assert!(enc.contains("vol::setup_fresh(&mut io, plan)"));
        assert!(enc.contains("Err(e) => at_rest_stop(ctx, &e)"));
        let stop_fn = &steps[steps.find("fn at_rest_stop(").unwrap()..];
        assert!(stop_fn[..stop_fn.find("\n}\n").unwrap()].contains("ctx.state.interrupted = true"));
        assert!(!State::default().at_rest_recovery_ack, "no acknowledgement until the person retypes the key");
    }

    #[test]
    fn the_onboard_prompt_asks_the_operators_question() {
        let c = crate::commands::at_rest::ONBOARD_PROMPT;
        assert!(c.starts_with("Encrypt your data, keys and secrets on disk, unlocked only on this machine?"));
        assert!(c.ends_with("(recommended)"));
    }
}
