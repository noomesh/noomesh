// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Repo `.env` loading + gateway URL resolution.
//! Mirrors `noomesh/cli_utils.py::ensure_repo_env` / `get_gateway_url` —
//! keep the two in sync until the Python CLI retires.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Repo root WITHOUT deriving it from the Python CLI path: `$NOO_REPO_ROOT`,
/// else the standalone state home, else the checkout the process stands in,
/// else the (possibly absent) state home directory. This is the
/// non-recursive core that `python_cli_path`'s venv fallback uses — see the
/// note on [`repo_root`].
///
/// The former last resort — a blind guess at `~/pai-assistant` — is gone
/// It was the trap that made a dev clone
/// the install root of a box whose install lives elsewhere: on HOST3
/// (2026-09-01, freshly a WORKER) every `noo` run from `~` loaded the
/// clone's `.env`, whose `NOO_TLS_CA` still named the RETIRED
/// controller's CA, and died `UnknownIssuer`. A clone is source; it is the
/// root only when you stand in it (git rule) or say so (`NOO_REPO_ROOT`).
/// With nothing found, the state home is returned unmarked: nothing is
/// loaded from it, and the enrollment record + system trust carry a
/// worker's CLI on their own.
pub fn repo_root_static() -> PathBuf {
    if let Ok(r) = std::env::var("NOO_REPO_ROOT") {
        return PathBuf::from(r);
    }
    if let Some(d) = standalone_home() {
        return d;
    }
    if let Some(d) = cwd_repo_root() {
        return d;
    }
    state_home_dir()
}

/// `$NOO_HOME`, else `~/.noo` — the state root, whether or not it has been
/// materialised yet.
pub(crate) fn state_home_dir() -> PathBuf {
    match std::env::var("NOO_HOME") {
        Ok(h) if !h.trim().is_empty() => PathBuf::from(h.trim()),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            PathBuf::from(home).join(".noo")
        }
    }
}

/// A standalone install materialised by `noo onboard --standalone`:
/// `$NOO_HOME`, else `~/.noo`, accepted only when it carries the
/// `.noo-standalone` marker written at materialise time. Ranked BELOW an
/// explicit $NOO_REPO_ROOT but ABOVE standing inside a checkout: the state home is the INSTALL; a checkout is source.
/// The old cwd-first ranking meant `noo stack`/`noo health` run from inside
/// a clone silently targeted the clone's (empty) state instead of the live
/// install — the host8 fresh-setup footgun, 2026-08-31. A dev who wants
/// the checkout while a state home exists says so explicitly:
/// `NOO_REPO_ROOT=$PWD`. Boxes with no `~/.noo` marker are unaffected.
pub(crate) fn standalone_home() -> Option<PathBuf> {
    let dir = state_home_dir();
    if dir.join(".noo-standalone").exists() && dir.join("docker-compose.cluster.yml").exists() {
        Some(dir)
    } else {
        None
    }
}

/// The checkout the process is STANDING IN, if any — walk up from the cwd
/// looking for the repo's fingerprint. This outranks the canonical
/// `~/pai-assistant` fallback: a fresh install cloned anywhere else
/// otherwise writes .env into and runs compose against a NONEXISTENT
/// home-dir path (the first sandbox rehearsal failed exactly there —
/// checkout at /opt/pai-assistant, wizard writing to /root/pai-assistant).
fn cwd_repo_root() -> Option<PathBuf> {
    let mut d = std::env::current_dir().ok()?;
    loop {
        if d.join("docker-compose.cluster.yml").exists() && d.join("noo-cli").is_dir() {
            return Some(d);
        }
        if !d.pop() {
            return None;
        }
    }
}

/// Locate the install root: $NOO_REPO_ROOT, else the standalone state home
/// (`~/.noo` with its marker: the state home IS the install),
/// else the checkout the process stands in, else derived from the Python CLI
/// path (…/venv/bin/noo-py → repo), else the state home directory itself
/// (no more `~/pai-assistant` guess — see [`repo_root_static`]).
///
/// The python-derivation step calls [`crate::passthrough::python_cli_path`],
/// whose own venv fallback needs a repo root. To avoid mutual recursion
/// (repo_root → python_cli_path → repo_root → …, which stack-overflows on any
/// host with no `$NOO_REPO_ROOT` and no Python `noo` on PATH — i.e. the
/// standalone binary's core scenario), that fallback uses the non-recursive
/// [`repo_root_static`] instead. Behaviour is unchanged for hosts that DON'T
/// hit the recursion: whenever python_cli_path reaches its venv fallback the
/// python-derivation branch here would have recursed forever anyway, so it
/// could never have legitimately returned a python-derived path.
pub fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("NOO_REPO_ROOT") {
        return PathBuf::from(r);
    }
    // Standalone install first: the state home
    // IS the install — see standalone_home for the ranking rationale and
    // the NOO_REPO_ROOT escape for devs who mean the checkout.
    if let Some(d) = standalone_home() {
        return d;
    }
    // In-checkout beats python-derived and canonical: standing inside a
    // repo means THAT repo, same rule as git. See cwd_repo_root.
    if let Some(d) = cwd_repo_root() {
        return d;
    }
    if let Some(py) = crate::passthrough::python_cli_path() {
        // <repo>/venv/bin/noo-py → <repo>
        if let Some(root) = py.ancestors().nth(3) {
            if root.join(".env").exists() || root.join("pyproject.toml").exists() {
                return root.to_path_buf();
            }
        }
    }
    repo_root_static()
}

/// How [`repo_root`] decided, i.e. how much authority the files under it
/// have. `Declared` and `Standalone` are the operator SAYING which install
/// this is; `Cwd` is the process merely standing somewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSource {
    /// `$NOO_REPO_ROOT` — an explicit declaration.
    Declared,
    /// The standalone state home (`~/.noo` with its `.noo-standalone` marker).
    Standalone,
    /// A checkout the cwd happens to be inside.
    Cwd,
    /// Derived from the Python CLI's venv path, or the bare state home.
    Derived,
}

impl RootSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Standalone => "standalone",
            Self::Cwd => "cwd",
            Self::Derived => "derived",
        }
    }
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Declared => "$NOO_REPO_ROOT",
            Self::Standalone => "the standalone install home (~/.noo, .noo-standalone marker)",
            Self::Cwd => "the checkout this command was run from",
            Self::Derived => "derived (python venv path / state home)",
        }
    }
}

/// [`repo_root`] plus the rung that answered. Same order, one extra fact.
pub fn repo_root_source() -> (PathBuf, RootSource) {
    if let Ok(r) = std::env::var("NOO_REPO_ROOT") {
        return (PathBuf::from(r), RootSource::Declared);
    }
    if let Some(d) = standalone_home() {
        return (d, RootSource::Standalone);
    }
    if let Some(d) = cwd_repo_root() {
        return (d, RootSource::Cwd);
    }
    (repo_root(), RootSource::Derived)
}

/// The keys that decide WHO the CLI talks to and WHAT vouches for it.
///
/// Everything else a config file sets is a knob; these are the security
/// boundary. A file that can set them can point an authenticated CLI —
/// bearer token attached — at a gateway of its choosing and name the CA that
/// will vouch for it. So they are honoured only from a config plane the
/// operator DECLARED, never from a checkout the process happens to be
/// standing in on a box whose real answer lives outside it.
pub const TRANSPORT_KEYS: &[&str] =
    &["NOO_GATEWAY_URL", "CONTROLLER_URL", "NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY"];

/// Is this box ENROLLED — does an authoritative answer to "which controller"
/// already exist outside any checkout?
fn is_enrolled() -> bool {
    Path::new(ENROLLED_CONTROLLER_URL).exists()
}

/// Config-file keys deliberately NOT loaded, each naming the file and the
/// reason. Surfaced by `noo auth status`, so the refusal is never silent.
/// Empty on every ordinary run.
static IGNORED: OnceLock<Vec<String>> = OnceLock::new();

pub fn ignored_config_notes() -> &'static [String] {
    IGNORED.get().map(|v| v.as_slice()).unwrap_or(&[])
}

/// May the config files under a root of this provenance set
/// [`TRANSPORT_KEYS`]? Split out from [`ensure_repo_env`] so both arms are
/// testable without a `/etc/noo` on the test machine.
pub(crate) fn config_plane_trusted(root_from: RootSource, enrolled: bool) -> bool {
    root_from != RootSource::Cwd || !enrolled
}

/// Should `key`, read out of `file`, be honoured? Records a note when not.
fn accept_key(key: &str, file: &Path, trusted: bool, notes: &mut Vec<String>) -> bool {
    if trusted || !TRANSPORT_KEYS.contains(&key) {
        return true;
    }
    notes.push(format!(
        "{key} in {} was IGNORED — this box is enrolled through {}, and that file is in a \
         checkout this command merely ran from, not a declared install. Pass --gateway, export \
         the variable, or set NOO_REPO_ROOT to this checkout if you mean it.",
        file.display(),
        ENROLLED_CONTROLLER_URL,
    ));
    false
}

/// Load `<repo>/.env` into the process env. Already-exported vars win.
/// Values may be quoted; lines starting with `#` are skipped.
///
/// **Trust boundary.** The repo root can come from the cwd (see
/// [`cwd_repo_root`]), so on a box with several checkouts — a dev clone next
/// to the install, a worktree, a tarball someone dropped in `/tmp` — `cd`
/// alone used to choose the CLI's gateway URL and its TLS trust anchor.
/// Together with `http.rs`'s old unverified-TLS fallback that was a whole
/// credential-exfiltration path: point `NOO_GATEWAY_URL` anywhere, leave
/// `NOO_TLS_CA` unset, and the next `noo` command posted the operator's
/// stored JWT to it without verifying anything. The loaders below therefore
/// refuse [`TRANSPORT_KEYS`] from a cwd-derived root on an ENROLLED box, and
/// say so ([`ignored_config_notes`], printed by `noo auth status`). A box
/// that is NOT enrolled has no other authority to fall back on, so its
/// checkout still speaks for it — unchanged for every dev box.
pub fn ensure_repo_env() {
    static LOADED: OnceLock<()> = OnceLock::new();
    LOADED.get_or_init(|| {
        let (_root, root_from) = repo_root_source();
        let trusted = config_plane_trusted(root_from, is_enrolled());
        let mut notes: Vec<String> = Vec::new();
        // Secrets BEFORE `.env`, deliberately: both fill only unset vars, so
        // whichever loads first wins an overlap. `.env` must not hold
        // credentials at all (doctrine: 5 bootstrap flags), but it has
        // drifted back into holding them twice now — and a stale
        // NOO_CLUSTER_SECRET in `.env` shadowing the store's current one
        // produced 401s that read like a gateway auth fault (live
        // 2026-08-12). The store is authoritative for every key it holds;
        // an explicit export / launcher-provided value still wins over both.
        // (Best-effort and silent: an operator without the age key just
        // gets the per-user credential path via `noo auth login`.)
        load_sops_secrets(trusted, &mut notes);

        // Config plane next: the `compose_env:` section of noomesh.yaml.
        // This is what lets `.env` shrink to its five bootstrap flags — the
        // CLI used to depend on `.env` for NOO_GATEWAY_URL / TLS paths,
        // which forced every config value to be duplicated there, and the
        // duplicates drifted (a stale PAGEINDEX_EMBEDDING_URL in `.env`
        // kept resurrecting a retired endpoint via compose interpolation).
        // Resolution order overall: process env > secret store > yaml
        // config > `.env` bootstrap.
        load_yaml_compose_env(trusted, &mut notes);

        let path = repo_root().join(".env");
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let line = line.strip_prefix("export ").unwrap_or(line);
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                let value = value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if key.is_empty() || std::env::var_os(key).is_some() {
                    continue;
                }
                if !accept_key(key, &path, trusted, &mut notes) {
                    continue;
                }
                std::env::set_var(key, value);
            }
        }
        let _ = IGNORED.set(notes);
    });
}

/// Fill any unset variable from the `compose_env:` section of the repo's
/// `noomesh.yaml`. Config-plane values (endpoints, node identity, TLS
/// paths) live there — this reader is what frees `.env` from having to
/// duplicate them for the CLI's benefit. Best-effort and silent, like the
/// other loaders: a missing yaml or missing section simply contributes
/// nothing.
fn load_yaml_compose_env(trusted: bool, notes: &mut Vec<String>) {
    let path = repo_root().join("noomesh.yaml");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return;
    };
    let Some(map) = doc.get("compose_env").and_then(|v| v.as_mapping()) else {
        return;
    };
    for (k, v) in map {
        let Some(key) = k.as_str() else { continue };
        // Values may be yaml strings, numbers, or bools — env is strings.
        let value = match v {
            serde_yaml::Value::String(s) => s.clone(),
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        if key.is_empty() || std::env::var_os(key).is_some() {
            continue;
        }
        if !accept_key(key, &path, trusted, notes) {
            continue;
        }
        std::env::set_var(key, value);
    }
}

/// Re-read `secrets/env.sops` into the process environment (fill-only-unset,
/// same rules as startup). `ensure_repo_env` runs ONCE, at startup — on a
/// fresh box that is before the wizard has written the store, so the
/// wizard's own operator-only calls (service-key provisioning) resolved no
/// cluster credential and died with a 401 while the stack it had just
/// started was healthy (2026-09-27 newcomer rehearsal, `--ci` standalone).
/// Call this after the store has been (re)written and before the first
/// call that needs it.
pub fn reload_sops_secrets() {
    let (_root, root_from) = repo_root_source();
    let trusted = config_plane_trusted(root_from, is_enrolled());
    let mut notes: Vec<String> = Vec::new();
    load_sops_secrets(trusted, &mut notes);
}

/// What became of `secrets/env.sops` at startup. `load_sops_secrets` is
/// best-effort and silent by design (a command on a box with no age key
/// must still run), but "silent" must not mean "forgotten": a
/// posture check that reads the environment afterwards has to know whether
/// an empty `NOO_JWT_SECRET` is the store's word or the reader's failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreState {
    /// No `secrets/env.sops` under the repo root.
    Absent,
    /// Decrypted; `keys` is how many lines it contributed or would have.
    Loaded { keys: usize },
    /// The file is there and could not be read — the reader's failure,
    /// classified. Nothing read from the environment after this is
    /// evidence about the store's contents.
    Unreadable(crate::commands::secrets::StoreLoadError),
}

static STORE_STATE: std::sync::Mutex<Option<StoreState>> = std::sync::Mutex::new(None);

/// The store's fate at the most recent load (startup, or
/// [`reload_sops_secrets`]). `Absent` before any load has run.
pub fn secret_store_state() -> StoreState {
    STORE_STATE
        .lock()
        .map(|g| g.clone())
        .unwrap_or(None)
        .unwrap_or(StoreState::Absent)
}

fn record_store_state(state: StoreState) {
    if let Ok(mut g) = STORE_STATE.lock() {
        *g = Some(state);
    }
}

fn load_sops_secrets(trusted: bool, notes: &mut Vec<String>) {
    let store = repo_root().join("secrets/env.sops");
    if !store.exists() {
        record_store_state(StoreState::Absent);
        return;
    }
    // One decrypt path with `SecretStore::load_sops`, so a failure here is
    // the same classified fact `noo security scan` reports — not a bare
    // `return` that leaves every credential looking unset.
    let text = match crate::commands::secrets::decrypt_store_dotenv(&store) {
        Ok(t) => t,
        Err(e) => {
            record_store_state(StoreState::Unreadable(e));
            return;
        }
    };
    let mut keys = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        // The stack pin is CONFIG, not a secret — it only lives in env.sops
        // because the wizard encrypts the whole .env. Loading it here (before
        // .env, fill-only-unset) made the FROZEN copy shadow the real pin and
        // silently downgraded a v0.1.76 stack back to the SIGILL v0.1.75
        // postgres mid-wizard (live 2026-08-25, first-contact finding #36).
        // Declaration beats config: the pin's home is .env / the launcher's
        // resolution, never the secret store.
        if key == "NOO_IMAGE_TAG" {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if key.is_empty() {
            continue;
        }
        keys += 1;
        if std::env::var_os(key).is_none() {
            if !accept_key(key, &store, trusted, notes) {
                continue;
            }
            std::env::set_var(key, value);
        }
    }
    record_store_state(StoreState::Loaded { keys });
}

/// The one-line trap warning every `.env` writer must surface when the sops
/// secrets backend is active (the launchers inject secrets/env.sops OVER
/// .env — see CLAUDE.md "Configuration" — so a bare .env edit is a no-op
/// for the running stack until re-encrypted).
pub const SOPS_EDIT_WARNING: &str =
    "NOO_SECRETS_BACKEND=sops — the running stack reads secrets/env.sops, not .env; \
     re-encrypt after this change (see scripts/noo-secrets-sops-init.sh) or it will not take effect.";

/// True when the sops secrets backend is active — process env first (set by
/// `ensure_repo_env`), falling back to reading the repo `.env` directly.
pub fn sops_backend_active() -> bool {
    if std::env::var("NOO_SECRETS_BACKEND").as_deref() == Ok("sops") {
        return true;
    }
    std::fs::read_to_string(repo_root().join(".env"))
        .map(|t| t.lines().any(|l| l.trim() == "NOO_SECRETS_BACKEND=sops"))
        .unwrap_or(false)
}

/// Print [`SOPS_EDIT_WARNING`] to stderr when applicable, at most once per
/// process. Call after every direct `.env` write outside the onboard UI
/// (onboard frontends route the same text through their own warn channel
/// so the TUI screen is not corrupted).
pub fn warn_sops_env_edit() {
    static WARNED: OnceLock<()> = OnceLock::new();
    if sops_backend_active() {
        WARNED.get_or_init(|| {
            crate::ui::warned(SOPS_EDIT_WARNING);
        });
    }
}

/// The instance this invocation targets: `NOO_INSTANCE`
/// from the process env (the `--instance` flag sets it, so one code path),
/// else the checkout's `.env`. Returns "" for the default instance —
/// an explicit `mesh` canonicalizes to "" so both spellings behave
/// identically everywhere.
pub fn instance() -> String {
    // ensure_repo_env() loads the checkout's .env into the process env,
    // so one lookup covers both the --instance flag and the file.
    ensure_repo_env();
    let v = std::env::var("NOO_INSTANCE").unwrap_or_default();
    let v = v.trim().to_string();
    if v == "mesh" {
        String::new()
    } else {
        v
    }
}

/// Container-name prefix for this instance — mirrors
/// `scripts/lib-instance.sh` exactly: `noo-<name>` for a named instance;
/// for the default one, `NOO_CONTAINER_PREFIX` when set (the launcher
/// exports `${NOO_CONTAINER_PREFIX:-noo}` and compose names every
/// container from it), else `noo`. Ignoring that variable let the CLI
/// inspect `noo-loki` while compose had named the container otherwise.
pub fn container_prefix() -> String {
    let i = instance();
    prefix_for(&i, std::env::var("NOO_CONTAINER_PREFIX").ok().as_deref())
}

/// [`container_prefix`], pure over the instance and `NOO_CONTAINER_PREFIX`.
pub(crate) fn prefix_for(instance: &str, env_prefix: Option<&str>) -> String {
    if !instance.is_empty() {
        return format!("noo-{instance}");
    }
    match env_prefix.map(|p| p.trim().trim_matches('"')).filter(|p| !p.is_empty()) {
        Some(p) => p.to_string(),
        None => "noo".to_string(),
    }
}

/// A controller container's name under the instance prefix:
/// `container("gateway")` → `noo-gateway` / `noo-galaxy-gateway`.
/// Every docker exec/inspect/logs target in the CLI goes through this —
/// a hardcoded `noo-gateway` operates on the WRONG instance the moment
/// two stacks share a host.
pub fn container(suffix: &str) -> String {
    format!("{}-{suffix}", container_prefix())
}

/// Remap a default-instance container name (`noo-X`, incl. `noo-stunnel-X`)
/// to this instance's (`noo-<name>-X`). Identity on the default instance,
/// so every existing table of `noo-*` literals keeps working; consumption
/// points (docker exec/inspect/restart) apply this instead of each table
/// being rewritten. A name without the `noo-` prefix passes through.
pub fn instanced(name: &str) -> String {
    let prefix = container_prefix();
    if prefix == "noo" {
        return name.to_string();
    }
    match name.strip_prefix("noo-") {
        Some(rest) => format!("{prefix}-{rest}"),
        None => name.to_string(),
    }
}

/// The instance port offset — mirrors lib-instance.sh (0 default).
pub fn port_offset() -> u32 {
    ensure_repo_env();
    std::env::var("NOO_PORT_OFFSET")
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Where prep-host.sh records the URL a worker enrolled through.
pub const ENROLLED_CONTROLLER_URL: &str = "/etc/noo/controller-url";

/// First non-empty line of the enrollment record, as a base URL (no
/// trailing slash). `None` when the file is absent, unreadable, empty, or
/// not an http(s) URL — the caller falls through to the localhost default.
pub fn controller_url_from_file(path: &Path) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    let line = body.lines().map(str::trim).find(|l| !l.is_empty())?;
    if !(line.starts_with("https://") || line.starts_with("http://")) {
        return None;
    }
    Some(line.trim_end_matches('/').to_string())
}

/// Which rung of [`gateway_url`]'s precedence answered.
///
/// `https://localhost:8080` is a correct answer on the controller and a
/// wrong one on a laptop, and the URL alone cannot tell those apart. Every
/// verb that shows the operator a target should be able to say where it
/// came from, so the resolver reports it instead of each caller guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewaySource {
    /// `--gateway` on the command line.
    Override,
    /// `$CONTROLLER_URL` or `$NOO_GATEWAY_URL` (repo `.env` counts: it is
    /// loaded into the environment before this runs).
    Env(&'static str),
    /// The enrollment record at [`ENROLLED_CONTROLLER_URL`].
    Enrolled,
    /// Nothing said otherwise — the localhost fallback.
    Default,
}

impl GatewaySource {
    /// A phrase that completes "the gateway URL came from …", for display.
    pub fn describe(&self) -> String {
        match self {
            Self::Override => "--gateway".to_string(),
            Self::Env(var) => format!("${var}"),
            Self::Enrolled => format!("{ENROLLED_CONTROLLER_URL}, written at enrollment"),
            Self::Default => "the default: nothing set a gateway URL".to_string(),
        }
    }
    /// Machine-readable tag for `--json`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Env(_) => "env",
            Self::Enrolled => "enrolled",
            Self::Default => "default",
        }
    }
}

/// Resolve the gateway base URL, same precedence as the Python CLI:
/// CONTROLLER_URL / NOO_GATEWAY_URL (ignoring docker-internal `://gateway:`
/// hosts), then `https://localhost:<port>` — never plain HTTP (the gateway
/// serves no such listener).
pub fn gateway_url(override_url: &Option<String>) -> String {
    gateway_url_source(override_url).0
}

/// [`gateway_url`] plus the rung that answered. See [`GatewaySource`].
pub fn gateway_url_source(override_url: &Option<String>) -> (String, GatewaySource) {
    if let Some(u) = override_url {
        return (u.trim_end_matches('/').to_string(), GatewaySource::Override);
    }
    ensure_repo_env();
    for var in ["CONTROLLER_URL", "NOO_GATEWAY_URL"] {
        if let Ok(u) = std::env::var(var) {
            if !u.is_empty() && !u.contains("://gateway:") {
                return (u.trim_end_matches('/').to_string(), GatewaySource::Env(var));
            }
        }
    }
    // Enrolled worker: prep-host records the controller this box enrolled
    // through at /etc/noo/controller-url (644). Without this, a worker's
    // CLI fell through to https://localhost:8080 and every `noo cluster
    // status` from a node box was "connection refused" (HOST3, 2026-09-01)
    // unless the operator hand-exported NOO_GATEWAY_URL.
    if let Some(u) = controller_url_from_file(Path::new(ENROLLED_CONTROLLER_URL)) {
        return (u, GatewaySource::Enrolled);
    }
    // The default port tracks the instance offset — a `galaxy`
    // checkout at +1000 serves on :9080, and a CLI defaulting to :8080
    // would silently talk to the OTHER instance.
    let port = 8080 + port_offset();
    // https, unconditionally: the gateway has no plaintext listener (it
    // refuses to start without NOO_TLS_CERT/KEY/CA), so the old
    // NOO_TLS_CERT sniff that picked `http://` when the key was absent
    // from this shell could only ever dial a door that does not exist.
    (format!("https://localhost:{port}"), GatewaySource::Default)
}

/// Set or clear a boolean flag in the repo `.env`, in place.
///
/// `.env` is the bootstrap plane and holds a tiny permitted set — today
/// `NOO_SECRETS_BACKEND`, `NOO_PRO_ENABLED`, `NOO_INSTALL_MODE`, and the
/// the instance pair `NOO_INSTANCE` / `NOO_PORT_OFFSET`. This
/// writes only flags, never
/// a credential: a secret in `.env` is the rule that cost 23 plaintext
/// duplicates of sops entries, and `noo systems enable` mints into
/// `secrets/env.sops` precisely so this function never has to.
///
/// Rewrites the existing line if the key is present (preserving position, so a
/// reader's mental model of the file survives) and appends otherwise. Every
/// other line — comments included — is passed through untouched, because this
/// file is hand-maintained and a rewrite that reformatted it would be a
/// diff nobody can review.
/// Set `key=value` in `.env`, or drop the line entirely when `value` is
/// `None`.
///
/// [`set_env_flag`] is the boolean special case of this and stays as it is:
/// for a flag, absent and `=0` mean the same thing, so clearing writes
/// nothing. A VALUE is different — an empty `NOO_BACKUP_OFFSITE=` would
/// read as "set but nowhere", which is the one state the backup script
/// treats as an error. So clearing removes the line and restores "nobody
/// has decided" rather than inventing a third, broken meaning.
pub fn set_env_value(key: &str, value: Option<&str>) -> Result<(), String> {
    let path = repo_root().join(".env");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        let bare = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let is_this_key = bare
            .split_once('=')
            .map(|(k, _)| k.trim() == key)
            .unwrap_or(false);
        if is_this_key && !bare.starts_with('#') {
            if let Some(v) = value {
                out.push(format!("{key}={v}"));
            }
            replaced = true;
        } else {
            out.push(line.to_string());
        }
    }
    if let Some(v) = value {
        if !replaced {
            out.push(format!("{key}={v}"));
        }
    }

    let mut body = out.join("\n");
    if !body.ends_with('\n') {
        body.push('\n');
    }
    std::fs::write(&path, body).map_err(|e| format!("could not write {}: {e}", path.display()))
}

pub fn set_env_flag(key: &str, on: bool) -> Result<(), String> {
    let path = repo_root().join(".env");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        let bare = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let is_this_key = bare
            .split_once('=')
            .map(|(k, _)| k.trim() == key)
            .unwrap_or(false);
        if is_this_key && !bare.starts_with('#') {
            if on {
                out.push(format!("{key}=1"));
            }
            // When clearing, the line is DROPPED rather than set to 0. An
            // absent flag and `=0` mean the same thing to every reader, and
            // leaving `NOO_PRO_ENABLED=0` behind invites someone to "fix" it
            // by editing the value instead of using the command.
            replaced = true;
        } else {
            out.push(line.to_string());
        }
    }
    if on && !replaced {
        out.push(format!("{key}=1"));
    }

    let mut body = out.join("\n");
    if !body.ends_with('\n') {
        body.push('\n');
    }
    std::fs::write(&path, body).map_err(|e| format!("could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod container_prefix_tests {
    use super::prefix_for;

    /// Mirrors scripts/lib-instance.sh `noo_instance_env`: a named instance
    /// forces `noo-<name>`; the default honours NOO_CONTAINER_PREFIX, the
    /// variable compose's `container_name: ${NOO_CONTAINER_PREFIX:-noo}-x`
    /// actually reads.
    #[test]
    fn the_prefix_is_the_one_compose_names_containers_with() {
        assert_eq!(prefix_for("", None), "noo");
        assert_eq!(prefix_for("", Some("")), "noo");
        assert_eq!(prefix_for("", Some("  ")), "noo");
        assert_eq!(prefix_for("", Some("noo")), "noo");
        assert_eq!(prefix_for("", Some("acme")), "acme");
        assert_eq!(prefix_for("", Some("\"acme\"")), "acme");
        assert_eq!(prefix_for("galaxy", None), "noo-galaxy");
        assert_eq!(prefix_for("galaxy", Some("acme")), "noo-galaxy", "a named instance overrides, as the launcher does");
    }
}

#[cfg(test)]
mod controller_url_tests {
    use super::controller_url_from_file;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("noo-envfile-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn reads_first_url_line_and_strips_trailing_slash() {
        let p = tmp("ok", "\n  https://host8.example.ts.net:8080/  \n");
        assert_eq!(controller_url_from_file(&p).as_deref(), Some("https://host8.example.ts.net:8080"));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn absent_empty_or_non_url_is_none() {
        assert_eq!(controller_url_from_file(std::path::Path::new("/nonexistent/noo/controller-url")), None);
        let e = tmp("empty", "\n\n");
        assert_eq!(controller_url_from_file(&e), None);
        let n = tmp("nourl", "host8:8080\n");
        assert_eq!(controller_url_from_file(&n), None);
        let _ = std::fs::remove_file(e);
        let _ = std::fs::remove_file(n);
    }
}

#[cfg(test)]
mod state_home_tests {
    use super::state_home_dir;

    /// `NOO_HOME` names the state root; otherwise it is `~/.noo`. Either
    /// way it is what root resolution returns when nothing else matches —
    /// never a guessed clone path.
    #[test]
    fn state_home_follows_noo_home_then_home() {
        let tmp = std::env::temp_dir().join(format!("noo-state-home-{}", std::process::id()));
        std::env::set_var("NOO_HOME", &tmp);
        assert_eq!(state_home_dir(), tmp);
        std::env::set_var("NOO_HOME", "   ");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        assert_eq!(state_home_dir(), std::path::PathBuf::from(home).join(".noo"));
        std::env::remove_var("NOO_HOME");
    }
}

#[cfg(test)]
mod config_plane_trust_tests {
    use super::*;

    /// The rule: an ENROLLED box does not let a checkout it merely stands in
    /// choose the gateway or the CA. Everything else is unchanged.
    #[test]
    fn only_a_cwd_checkout_on_an_enrolled_box_is_untrusted() {
        assert!(!config_plane_trusted(RootSource::Cwd, true), "the whole point of the guard");
        // A dev box that is not enrolled has no other authority: its
        // checkout still speaks for it.
        assert!(config_plane_trusted(RootSource::Cwd, false));
        // Declared roots are the operator's word, enrolled or not.
        for src in [RootSource::Declared, RootSource::Standalone, RootSource::Derived] {
            assert!(config_plane_trusted(src, true), "{src:?} is a declared plane");
            assert!(config_plane_trusted(src, false), "{src:?} is a declared plane");
        }
    }

    /// A `.env` from a non-matching checkout must not set the gateway URL or
    /// the trust anchor — and must SAY it did not. Non-transport keys are
    /// unaffected, or every `noo` run from a clone would change behaviour.
    #[test]
    fn transport_keys_are_dropped_from_an_untrusted_file_with_a_named_reason() {
        let file = Path::new("/tmp/some-random-clone/.env");
        let mut notes = Vec::new();
        for key in TRANSPORT_KEYS {
            assert!(
                !accept_key(key, file, false, &mut notes),
                "{key} must NOT be honoured from an untrusted checkout"
            );
        }
        assert_eq!(notes.len(), TRANSPORT_KEYS.len(), "every refusal must be reported");
        assert!(
            notes.iter().all(|n| n.contains("/tmp/some-random-clone/.env")),
            "each note must name the file that was ignored: {notes:?}"
        );
        assert!(
            notes.iter().all(|n| n.contains("NOO_REPO_ROOT")),
            "each note must say how to opt in: {notes:?}"
        );

        // Knobs are still knobs.
        let mut notes = Vec::new();
        assert!(accept_key("NOO_IMAGE_TAG", file, false, &mut notes));
        assert!(accept_key("NOO_PRO_ENABLED", file, false, &mut notes));
        assert!(notes.is_empty());

        // And a trusted plane sets everything, as before.
        let mut notes = Vec::new();
        for key in TRANSPORT_KEYS {
            assert!(accept_key(key, file, true, &mut notes));
        }
        assert!(notes.is_empty());
    }

    /// Standing inside a checkout must READ as standing inside one — the
    /// guard is inert if this rung is misreported.
    #[test]
    fn repo_root_source_reports_a_declared_root_as_declared() {
        let prev = std::env::var("NOO_REPO_ROOT").ok();
        std::env::set_var("NOO_REPO_ROOT", "/opt/noomesh");
        let (root, src) = repo_root_source();
        assert_eq!(root, PathBuf::from("/opt/noomesh"));
        assert_eq!(src, RootSource::Declared);
        match prev {
            Some(v) => std::env::set_var("NOO_REPO_ROOT", v),
            None => std::env::remove_var("NOO_REPO_ROOT"),
        }
    }
}
