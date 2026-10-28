// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons enable <name> --provision-only`: the add-on's database, none of
//! its services.
//!
//! ## Why
//!
//! `noo addons enable` pins the signed lock, mints the add-on's credentials
//! and declares it ON; the schema and roles are only created by the systems
//! broker on the gateway's next start, which ALSO composes the add-on's
//! overlay and starts its services. A third-party add-on under development
//! needs its isolated schema BEFORE its services may run (a connected-DB
//! acceptance test from a private runner), and nothing in the old flow could
//! give it one.
//!
//! ## The order, and what is deliberately absent
//!
//!   0. **verify and pin the signed lock** exactly as `enable` does
//!      ([`addon_enable::Live::pin_lock`]), with one extra refusal: the
//!      verified bundle must declare a database (`system.json`), checked
//!      BEFORE the pin is written. Anything but a verified pin refuses: a
//!      development checkout that pins no stack tag, an add-on that ships no
//!      bundle, `--force` (which skips verification, so it is refused here).
//!   1. **preconditions** (read-only): the add-on is not already switched ON;
//!      `noomesh.yaml` has no `systems:` entry for it (the gateway would
//!      prefer that entry to the bundle's); the database container and the
//!      gateway are running; the private database network is found.
//!   2. **mint credentials**: [`systems::mint_credentials`] through the same
//!      step `enable` runs. Mint-if-absent, never rotate.
//!   3. **the broker**: the gateway's own broker, for exactly this one system,
//!      through `docker exec -i noo-gateway noo-gateway provision-system`
//!      (see `gateway-rust/src/system_provision_cli.rs`). The request carries
//!      the system and its two passwords on stdin. It is the function the
//!      gateway runs at boot, not SQL written here, so the two cannot diverge.
//!   4. **credential files** for a private runner, at a fixed path in RAM
//!      ([`provision_rundir`]).
//!   5. **record** the `provisioned` state ([`crate::addons::provisioned`]).
//!
//! NOT done, on purpose: the add-on's switch is never written (the launcher
//! composes an add-on only when `addons.<name>` is true, so a later `noo stack
//! restart --force` cannot start its services); no gateway service key is
//! issued, no NATS principal is rendered, and nothing is restarted. A later
//! plain `noo addons enable <name>` finds the credentials, the roles and the
//! pin waiting and turns it fully on.
//!
//! ## The credential files
//!
//! `<rundir>/<addon>/`, where `<rundir>` is `$NOO_PROVISION_RUNDIR`, else
//! `/run/noo/provision` as root, else `/dev/shm/noo-provision-<uid>`: tmpfs
//! only (checked), the directory 0700 and owned by the operator, like the
//! launcher's secret rundir. They are gone at reboot; the command is
//! idempotent and rewrites them.
//!
//! | file | what | mode |
//! |---|---|---|
//! | `ca.crt` | the cluster CA | 0444 |
//! | `client.crt` / `client.key` | the add-on's own client leaf (`pki/addons/<addon>/db-client`, `CN=addon:<addon>/db-client`) | 0444 / 0400 |
//! | `pgpass.<runtime role>` / `pgpass.<ddl role>` | one libpq pgpass line each | 0400 |
//!
//! The runner runs as the operator's uid (`--user "$(id -u):$(id -g)"`), which
//! is also what libpq's key rule wants: a key owned by anyone but root must be
//! 0600 or tighter, and libpq does not check the owner is the caller. The
//! add-on roles' `pg_hba` line is `verify-ca` (any cluster-CA leaf plus the
//! password), so the add-on's own leaf is the right client identity. Its CN
//! is namespaced (`crate::pki::ADDON_CN_PREFIX`): before 0.6.13 it was the
//! bare add-on name under `services/`, the namespace core's grants are keyed
//! on, and an add-on provisioned then is re-issued and its old leaf retired
//! here (`resources::retire_legacy_leaf`). Values
//! are written to these files and to the broker's stdin and nowhere else;
//! nothing here prints, logs or returns one.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::json;

use crate::addons::decls::{self, System};
use crate::addons::provisioned::{self, Marker};
use crate::commands::addon_enable::{self, PinStep, Refusal};
use crate::commands::secrets::SecretStore;
use crate::commands::systems;
use crate::Globals;

/// The database, as the compose DSNs and the launcher's pgpass bodies name
/// it (`postgres:5432:noomesh`, scripts/lib-secrets.sh `_pgpass_body`;
/// tests/test_addon_provision_only.py holds the two equal).
pub(crate) const DB_NAME: &str = "noomesh";
pub(crate) const DB_HOST: &str = "postgres";
pub(crate) const DB_PORT: u16 = 5432;
/// The controller containers, under this instance's prefix (`noo-gateway`,
/// `noo-postgres` by default).
pub(crate) fn gateway_container() -> String {
    crate::envfile::container("gateway")
}
pub(crate) fn postgres_container() -> String {
    crate::envfile::container("postgres")
}
pub(crate) const GATEWAY_BIN: &str = "/usr/local/bin/noo-gateway";
/// The compose network Postgres answers on (`noo-db`, internal). Compose
/// prefixes it with the project name, so it is found, not assumed.
pub(crate) const DB_NETWORK_SUFFIX: &str = "noo-db";
/// Where the runner sees the credential directory.
pub(crate) const RUNNER_MOUNT: &str = "/run/noo-db";

pub(crate) const CA_FILE: &str = "ca.crt";
pub(crate) const CERT_FILE: &str = "client.crt";
pub(crate) const KEY_FILE: &str = "client.key";

// ── the broker transport ────────────────────────────────────────────────

/// How a request reaches the gateway's broker. The seam the tests fake: the
/// request and the answer are the real ones, only the pipe is replaced.
pub(crate) trait BrokerTransport {
    /// Send `request` (JSON), return the broker's stdout.
    fn exchange(&mut self, request: &str) -> Result<String, String>;
}

/// `docker exec -i noo-gateway noo-gateway provision-system`, the request on
/// stdin. Never argv, never env: the request holds the role passwords.
pub(crate) struct DockerExec;

impl BrokerTransport for DockerExec {
    fn exchange(&mut self, request: &str) -> Result<String, String> {
        let gateway = gateway_container();
        let mut child = Command::new("docker")
            .args(["exec", "-i", gateway.as_str(), GATEWAY_BIN, "provision-system"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run docker: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(request.as_bytes()).map_err(|e| format!("could not hand the request to the gateway: {e}"))?;
        }
        let out = child.wait_with_output().map_err(|e| format!("docker exec failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout.is_empty() {
            let err: String = String::from_utf8_lossy(&out.stderr).trim().chars().take(400).collect();
            return Err(if err.is_empty() { format!("the gateway answered nothing (exit {})", out.status) } else { err });
        }
        // A failed provision still reports on stdout (`ok: false`); the
        // caller reads the verdict, not the exit code.
        Ok(stdout)
    }
}

/// What the broker did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerReport {
    pub roles_created: Vec<String>,
    pub schema_created: bool,
}

/// The broker request for `sys`: exactly one system and its two passwords.
/// `verify_callers` is sent only when declared: the broker refuses an unknown
/// field, so a gateway from before it still accepts every other bundle.
pub(crate) fn broker_request(addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> String {
    let mut system = json!({
        "schema": sys.schema,
        "role": sys.role,
        "ddl_role": sys.ddl_role,
        "extensions": sys.extensions,
    });
    if sys.verify_callers {
        system["verify_callers"] = json!(true);
    }
    json!({
        "addon": addon,
        "system": system,
        "secrets": secrets,
    })
    .to_string()
}

/// `text` with every secret value replaced, so a broker error can be shown.
pub(crate) fn redact(text: &str, secrets: &BTreeMap<String, String>) -> String {
    let mut out = text.to_string();
    for v in secrets.values().filter(|v| !v.is_empty()) {
        out = out.replace(v.as_str(), "<redacted>");
    }
    out
}

/// Ask the broker to provision `sys` and check it provisioned THAT system.
pub(crate) fn broker_exchange(
    transport: &mut dyn BrokerTransport,
    addon: &str,
    sys: &System,
    secrets: &BTreeMap<String, String>,
) -> Result<BrokerReport, Refusal> {
    let fix = format!(
        "noo stack status   # the gateway must be running and recent enough to carry `provision-system`; then re-run: noo addons enable {addon} --provision-only"
    );
    let answer = transport.exchange(&broker_request(addon, sys, secrets)).map_err(|e| Refusal {
        why: format!(
            "the gateway's broker could not be reached ({}). Credentials are minted and the lock is pinned; no schema or role was created",
            redact(&e, secrets)
        ),
        fix: fix.clone(),
    })?;
    let v: serde_json::Value = serde_json::from_str(&answer).map_err(|_| Refusal {
        why: format!(
            "the gateway's broker answered something that is not its report ({}). It may predate `provision-system`",
            redact(&answer.chars().take(200).collect::<String>(), secrets)
        ),
        fix: "noo upgrade --stack   # the gateway image must carry `provision-system` (0.6.11)".into(),
    })?;
    if v["ok"] != true {
        let why = v["error"].as_str().unwrap_or("it gave no reason");
        let fix = match v["missing"].as_str() {
            Some(_) => format!("noo security secrets audit   # then re-run: noo addons enable {addon} --provision-only"),
            None => fix,
        };
        return Err(Refusal { why: format!("the broker refused: {}", redact(why, secrets)), fix });
    }
    let same = v["schema"] == sys.schema.as_str() && v["role"] == sys.role.as_str() && v["ddl_role"] == sys.ddl_role.as_str();
    if !same {
        return Err(Refusal {
            why: "the broker provisioned a different system than the one asked for; refusing to record it".into(),
            fix: "noo upgrade --stack".into(),
        });
    }
    let names = |k: &str| -> Vec<String> {
        v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    Ok(BrokerReport { roles_created: names("roles_created"), schema_created: v["schema_created"].as_bool().unwrap_or(false) })
}

// ── the credential files ────────────────────────────────────────────────

/// Where an add-on's credential files live (see the module docs). Pure.
pub(crate) fn provision_rundir(env_override: Option<&str>, euid: u32) -> PathBuf {
    match env_override.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => PathBuf::from(d),
        None if euid == 0 => PathBuf::from("/run/noo/provision"),
        None => PathBuf::from(format!("/dev/shm/noo-provision-{euid}")),
    }
}

/// Re-issue `addon`'s client leaf under the add-on namespace and retire its
/// pre-0.6.13 `services/<addon>` leaf, on this box's PKI, refreshing the
/// runner's files when `--provision-only` wrote them
/// (`addons::resources::retire_legacy_leaf`). Run by `noo addons enable` and
/// `noo upgrade --stack`. Returns what the operator is told; never fails the
/// caller (the old leaf holds no grant: it is hygiene, not a gate).
pub(crate) fn retire_legacy_leaf_here(addon: &str) -> Option<Result<String, String>> {
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    crate::addons::resources::legacy_leaf_dir(&ca, addon)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let prov = provision_rundir(std::env::var("NOO_PROVISION_RUNDIR").ok().as_deref(), euid).join(addon);
    match crate::addons::resources::retire_legacy_leaf(&ca, addon, Some(&prov)) {
        Ok(Some(said)) => Some(Ok(said)),
        Ok(None) => None,
        Err(e) => Some(Err(format!("{addon}: its pre-0.6.13 client certificate could not be retired: {e}"))),
    }
}

/// One pgpass line for `role`, the password escaped the way libpq reads it
/// (`\` and `:` escaped; scripts/lib-secrets.sh `_pgpass_body libpq`).
pub(crate) fn pgpass_line(role: &str, password: &str) -> String {
    let pw = password.replace('\\', "\\\\").replace(':', "\\:");
    format!("{DB_HOST}:{DB_PORT}:{DB_NAME}:{role}:{pw}\n")
}

/// The PEM material a runner needs, read from the PKI by the caller.
pub(crate) struct Pki {
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

/// The files written, by path. No content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Files {
    pub dir: PathBuf,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// `(role, path)`: the runtime role first, then the DDL role.
    pub pgpass: Vec<(String, PathBuf)>,
}

pub(crate) fn write_private(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<PathBuf, String> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dest = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&tmp, &dest)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", dest.display()));
    }
    Ok(dest)
}

/// Create `dir` (and its parent) 0700 and refuse a symlink there.
pub(crate) fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("{} is a symlink - refusing to put credentials behind it", dir.display()));
    }
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Write the runner's files into `dir` (already the add-on's directory).
/// Caller checks the filesystem is RAM; this is the content and the modes.
pub(crate) fn write_credential_files(
    dir: &Path,
    sys: &System,
    secrets: &BTreeMap<String, String>,
    addon: &str,
    pki: &Pki,
) -> Result<Files, String> {
    private_dir(dir)?;
    let (pw_var, ddl_var) = decls::password_envs(addon);
    let want = |var: &str| secrets.get(var).filter(|v| !v.is_empty()).ok_or_else(|| format!("{var} has no value"));
    let (pw, ddl) = (want(&pw_var)?, want(&ddl_var)?);
    let ca = write_private(dir, CA_FILE, &pki.ca, 0o444)?;
    let cert = write_private(dir, CERT_FILE, &pki.cert, 0o444)?;
    let key = write_private(dir, KEY_FILE, &pki.key, 0o400)?;
    let mut pgpass = Vec::new();
    for (role, password) in [(&sys.role, pw), (&sys.ddl_role, ddl)] {
        let p = write_private(dir, &format!("pgpass.{role}"), pgpass_line(role, password).as_bytes(), 0o400)?;
        pgpass.push((role.clone(), p));
    }
    Ok(Files { dir: dir.to_path_buf(), ca, cert, key, pgpass })
}

/// Is `dir` on tmpfs or ramfs? Linux only.
#[cfg(target_os = "linux")]
pub(crate) fn ram_backed(dir: &Path) -> Result<bool, String> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: `st` is a zeroed plain struct statfs fills; `c` is NUL-terminated.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(format!("{}: {}", dir.display(), std::io::Error::last_os_error()));
    }
    const TMPFS: u32 = 0x0102_1994;
    const RAMFS: u32 = 0x8584_58f6;
    let t = st.f_type as u32;
    Ok(t == TMPFS || t == RAMFS)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn ram_backed(_dir: &Path) -> Result<bool, String> {
    Err("cannot verify a RAM filesystem on this OS".into())
}

// ── the receipt ─────────────────────────────────────────────────────────

/// What the operator is handed. Names and paths only: no secret value is a
/// field of this type, so none can be printed from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub addon: String,
    pub version: String,
    pub stack: String,
    pub schema: String,
    pub role: String,
    pub ddl_role: String,
    pub extensions: Vec<String>,
    pub network: String,
    pub files: Files,
    pub created_roles: Vec<String>,
    pub schema_created: bool,
    pub minted: Vec<String>,
}

impl Receipt {
    /// `docker run` for a private runner: on the database network only, no
    /// ports, no GPU, no Docker socket, a read-only root and read-only
    /// credential mount, as the operator's own uid.
    pub fn docker_run(&self) -> String {
        let pgpass = self.files.pgpass.first().map(|(r, _)| format!("pgpass.{r}")).unwrap_or_default();
        [
            "docker run --rm -i".to_string(),
            format!("--network {}", self.network),
            "--user \"$(id -u):$(id -g)\"".to_string(),
            "--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges".to_string(),
            format!("-v {}:{RUNNER_MOUNT}:ro", self.files.dir.display()),
            format!("-e PGHOST={DB_HOST} -e PGPORT={DB_PORT} -e PGDATABASE={DB_NAME} -e PGUSER={}", self.role),
            format!(
                "-e PGSSLMODE=verify-full -e PGSSLROOTCERT={RUNNER_MOUNT}/{CA_FILE} -e PGSSLCERT={RUNNER_MOUNT}/{CERT_FILE} -e PGSSLKEY={RUNNER_MOUNT}/{KEY_FILE}"
            ),
            format!("-e PGPASSFILE={RUNNER_MOUNT}/{pgpass}"),
            "<runner-image> <command>".to_string(),
        ]
        .join(" \\\n  ")
    }

    pub fn json(&self) -> serde_json::Value {
        let pgpass: serde_json::Map<String, serde_json::Value> =
            self.files.pgpass.iter().map(|(r, p)| (r.clone(), json!(p.display().to_string()))).collect();
        json!({
            "addon": self.addon,
            "state": "provisioned",
            "state_text": provisioned::WORDS,
            "switch": "off",
            "pin": { "version": self.version, "stack": self.stack },
            "database": {
                "name": DB_NAME,
                "host": DB_HOST,
                "port": DB_PORT,
                "schema": self.schema,
                "runtime_role": self.role,
                "ddl_role": self.ddl_role,
                "extensions": self.extensions,
            },
            "network": self.network,
            "created": { "roles": self.created_roles, "schema": self.schema_created },
            "credentials_minted": self.minted,
            "files": {
                "dir": self.files.dir.display().to_string(),
                "ca": self.files.ca.display().to_string(),
                "client_cert": self.files.cert.display().to_string(),
                "client_key": self.files.key.display().to_string(),
                "pgpass": pgpass,
                "mount": RUNNER_MOUNT,
                "read_only": true,
            },
            "runner": { "docker_run": self.docker_run() },
        })
    }

    pub fn print(&self) {
        use crate::ui;
        println!("{}", ui::header(&format!("add-on {}: {}", self.addon, provisioned::WORDS), None));
        println!(
            "{}",
            ui::kv(&[
                ("database", format!("{DB_NAME} on {DB_HOST}:{DB_PORT}, from the private network {}", self.network)),
                ("schema", self.schema.clone()),
                ("runtime role", self.role.clone()),
                ("ddl role", self.ddl_role.clone()),
                (
                    "created",
                    if self.created_roles.is_empty() && !self.schema_created {
                        "nothing: it was already there".to_string()
                    } else {
                        format!(
                            "{}{}",
                            if self.created_roles.is_empty() { String::new() } else { format!("roles {}; ", self.created_roles.join(", ")) },
                            if self.schema_created { "schema" } else { "schema existed" }
                        )
                    },
                ),
                ("switch", "off - a restart does not start its services".to_string()),
            ])
        );
        println!("{}", ui::section("credential files (read-only; names only, no value is printed)"));
        let mut rows = vec![
            ("directory", self.files.dir.display().to_string()),
            ("cluster CA", self.files.ca.display().to_string()),
            ("client cert", self.files.cert.display().to_string()),
            ("client key", self.files.key.display().to_string()),
        ];
        for (role, p) in &self.files.pgpass {
            rows.push(("pgpass", format!("{role}: {}", p.display())));
        }
        println!("{}", ui::kv(&rows));
        println!("{}", ui::section("a private runner"));
        println!("{}", self.docker_run());
        println!();
        ui::guide(&[
            ("noo addons show <name>", "the state, the database and the roles"),
            ("noo addons enable <name>", "later: turn it fully on (composes and starts its services)"),
        ]);
    }
}

// ── the flow ────────────────────────────────────────────────────────────

/// The side effects, behind a seam so the ORDER and the promise that the
/// switch is never written are testable. [`Live`] is the production one.
pub(crate) trait ProvisionOps {
    /// Verify and pin the signed lock (the bundle must declare a database).
    fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal>;
    /// The verified bundle's database declaration.
    fn system(&mut self, addon: &str) -> Result<System, Refusal>;
    /// Read-only preconditions; returns the private database network.
    fn preflight(&mut self, addon: &str) -> Result<String, Refusal>;
    fn mint(&mut self, addon: &str) -> Result<Vec<String>, Refusal>;
    /// The two role passwords, by variable name.
    fn secrets(&mut self, addon: &str) -> Result<BTreeMap<String, String>, Refusal>;
    fn broker(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<BrokerReport, Refusal>;
    fn write_files(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<Files, Refusal>;
    fn mark(&mut self, addon: &str, sys: &System, version: &str) -> Result<(), Refusal>;
}

/// Is `addons.<name>` already declared true in `config`?
fn declared_on(config: &Path, name: &str) -> bool {
    std::fs::read_to_string(config)
        .map(|t| crate::commands::addons::declared_in(&t).get(name) == Some(&true))
        .unwrap_or(false)
}

/// Provision `addon`'s database and nothing else. `config` is only READ (to
/// refuse an add-on that is already on); it is never written.
pub(crate) fn provision_only(config: &Path, addon: &str, ops: &mut dyn ProvisionOps) -> Result<Receipt, Refusal> {
    if declared_on(config, addon) {
        return Err(Refusal {
            why: format!(
                "{addon} is already switched on in {}; the gateway provisions an add-on that is on when it starts, \
                 and --provision-only is for one that is not",
                config.display()
            ),
            fix: format!("noo addons show {addon}"),
        });
    }
    let pin = ops.pin_lock(addon)?;
    let (version, stack) = match pin {
        PinStep::Pinned { version, stack, .. } => (version, stack),
        other => {
            let why = match other {
                PinStep::Skipped(w) => w,
                _ => format!("{addon} ships no signed bundle with this CLI, so there is no verified database declaration"),
            };
            return Err(Refusal {
                why: format!("the signed lock was not verified ({why}); --provision-only never provisions from an unverified bundle. Nothing was changed"),
                fix: format!("noo addons enable {addon} --lock <path|https-url> --provision-only"),
            });
        }
    };
    let sys = ops.system(addon)?;
    let network = ops.preflight(addon)?;
    let minted = ops.mint(addon)?;
    let secrets = ops.secrets(addon)?;
    let report = ops.broker(addon, &sys, &secrets)?;
    let files = ops.write_files(addon, &sys, &secrets).map_err(|r| Refusal {
        why: format!("{} (the schema and roles ARE created; this step is repeatable)", r.why),
        fix: r.fix,
    })?;
    ops.mark(addon, &sys, &version)?;
    Ok(Receipt {
        addon: addon.to_string(),
        version,
        stack,
        schema: sys.schema.clone(),
        role: sys.role.clone(),
        ddl_role: sys.ddl_role.clone(),
        extensions: sys.extensions.clone(),
        network,
        files,
        created_roles: report.roles_created,
        schema_created: report.schema_created,
        minted,
    })
}

// ── the live side ───────────────────────────────────────────────────────

/// The private database network, from `docker inspect`'s `Networks` object of
/// the Postgres container: the one network named `noo-db` or `<project>_noo-db`.
pub(crate) fn db_network_from(networks_json: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(networks_json).map_err(|e| format!("not JSON: {e}"))?;
    let names: Vec<&String> = v
        .as_object()
        .ok_or("not an object")?
        .keys()
        .filter(|k| k.as_str() == DB_NETWORK_SUFFIX || k.ends_with(&format!("_{DB_NETWORK_SUFFIX}")))
        .collect();
    match names.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("the database container is on no `{DB_NETWORK_SUFFIX}` network")),
        many => Err(format!("the database container is on several `{DB_NETWORK_SUFFIX}` networks ({})", many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))),
    }
}

fn docker_out(args: &[&str]) -> Result<String, String> {
    let out = Command::new("docker").args(args).output().map_err(|e| format!("could not run docker: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().chars().take(300).collect());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(crate) struct Live<'a> {
    pub enable: addon_enable::Live<'a>,
    pub g: &'a Globals,
    pub root: PathBuf,
}

impl Live<'_> {
    fn sops(&self) -> PathBuf {
        crate::envfile::repo_root().join("secrets/env.sops")
    }
    fn rundir(&self) -> PathBuf {
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        provision_rundir(std::env::var("NOO_PROVISION_RUNDIR").ok().as_deref(), euid)
    }
}

impl ProvisionOps for Live<'_> {
    fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal> {
        addon_enable::EnableOps::pin_lock(&mut self.enable, addon)
    }

    fn system(&mut self, addon: &str) -> Result<System, Refusal> {
        let d = decls::materialised(&self.root, addon).map_err(|e| Refusal {
            why: format!("{e}. Nothing was changed"),
            fix: format!("noo addons upgrade {addon}   # re-materialises the signed bundle"),
        })?;
        d.system.ok_or_else(|| Refusal {
            why: format!("{addon}'s signed bundle declares no database (system.json). Nothing was changed"),
            fix: format!("noo addons show {addon}"),
        })
    }

    fn preflight(&mut self, addon: &str) -> Result<String, Refusal> {
        let manifest_path = systems::manifest_path();
        let text = std::fs::read_to_string(&manifest_path).unwrap_or_default();
        let manifest = systems::parse_systems(&text).map_err(|e| Refusal {
            why: format!("{}: {e}. Nothing was changed", manifest_path.display()),
            fix: "noo systems status".into(),
        })?;
        if manifest.contains_key(&decls::system_id(addon)) || manifest.contains_key(addon) {
            return Err(Refusal {
                why: format!(
                    "{} declares a `systems:` entry for {addon}, and the gateway prefers that entry to the bundle's. \
                     Remove it so the database is provisioned from the signed bundle",
                    manifest_path.display()
                ),
                fix: format!("noo systems disable {addon}   # then delete systems.{} from noomesh.yaml", decls::system_id(addon)),
            });
        }
        let down = |c: &str| Refusal {
            why: format!("{c} is not running, so there is no database to provision in. Nothing was changed"),
            fix: format!("noo stack start   # then: noo addons enable {addon} --provision-only"),
        };
        let (postgres, gateway) = (postgres_container(), gateway_container());
        for c in [&postgres, &gateway] {
            if !matches!(docker_out(&["inspect", "-f", "{{.State.Running}}", c.as_str()]).as_deref(), Ok("true")) {
                return Err(down(c));
            }
        }
        let networks = docker_out(&["inspect", "-f", "{{json .NetworkSettings.Networks}}", postgres.as_str()]).map_err(|e| Refusal {
            why: format!("could not read {postgres}'s networks ({e}). Nothing was changed"),
            fix: "noo stack status".into(),
        })?;
        db_network_from(&networks).map_err(|e| Refusal { why: format!("{e}. Nothing was changed"), fix: "noo stack status".into() })
    }

    fn mint(&mut self, addon: &str) -> Result<Vec<String>, Refusal> {
        addon_enable::EnableOps::mint_credentials(&mut self.enable, addon)
    }

    fn secrets(&mut self, addon: &str) -> Result<BTreeMap<String, String>, Refusal> {
        let (pw, ddl) = decls::password_envs(addon);
        let store = SecretStore::load_sops(&self.sops()).map_err(|e| Refusal {
            why: format!("the encrypted store could not be read ({e}). Credentials were minted if they were absent"),
            fix: "noo security secrets audit".into(),
        })?;
        let mut out = BTreeMap::new();
        for k in [pw, ddl] {
            match store.get(&k).filter(|v| !v.trim().is_empty()) {
                Some(v) => {
                    out.insert(k, v.to_string());
                }
                None => {
                    return Err(Refusal {
                        why: format!("{k} has no value in the encrypted store after minting"),
                        fix: "noo security secrets audit".into(),
                    })
                }
            }
        }
        Ok(out)
    }

    fn broker(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<BrokerReport, Refusal> {
        if !self.g.json {
            crate::ui::step(&format!("{addon}: the gateway's broker creates schema {} and its roles", sys.schema));
        }
        broker_exchange(&mut DockerExec, addon, sys, secrets)
    }

    fn write_files(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<Files, Refusal> {
        let base = self.rundir();
        let dir = base.join(addon);
        let fix = "noo security pki status".to_string();
        let refuse = |why: String| Refusal { why, fix: fix.clone() };
        private_dir(&base).map_err(refuse)?;
        match ram_backed(&base) {
            Ok(true) => {}
            Ok(false) => {
                return Err(refuse(format!(
                    "{} is not on tmpfs; credentials are only written to RAM. Set NOO_PROVISION_RUNDIR to a directory on tmpfs",
                    base.display()
                )))
            }
            Err(e) => return Err(refuse(e)),
        }
        let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
        if !ca.ca_exists() {
            return Err(Refusal { why: "this box has no cluster CA to issue the add-on's client certificate from".into(), fix: "noo security pki init".into() });
        }
        // The add-on's own client leaf (`CN=addon:<addon>/db-client`, key
        // 0600 for this CLI), the one the launcher's `db` resource hands out
        // too. Never `services/<addon>`: that namespace is core's, and its
        // CN is what the gateway's grants are keyed on.
        let (cert, key) = crate::addons::resources::db_client_leaf(&ca, addon)
            .map_err(|e| Refusal { why: format!("could not issue {addon}'s client certificate: {e}"), fix: "noo security pki status".into() })?;
        let read = |p: PathBuf| {
            std::fs::read(&p).map_err(|e| Refusal {
                why: format!("{}: {e}", p.display()),
                fix: "noo security pki fix-modes".into(),
            })
        };
        let pki = Pki { ca: read(ca.ca_cert_path())?, cert, key };
        let files = write_credential_files(&dir, sys, secrets, addon, &pki).map_err(refuse)?;
        // An add-on provisioned before 0.6.13 still has the old leaf
        // (`services/<addon>`, CN = its bare name): retired now that the new
        // one is in place and in the runner's files.
        match crate::addons::resources::retire_legacy_leaf(&ca, addon, None) {
            Ok(Some(said)) if !self.g.json => crate::ui::done(&said),
            Ok(_) => {}
            Err(e) => crate::ui::warned(&format!("{addon}: {e}")),
        }
        Ok(files)
    }

    fn mark(&mut self, addon: &str, sys: &System, version: &str) -> Result<(), Refusal> {
        let lock_sha256 = crate::addons::pins::read(&self.root)
            .ok()
            .and_then(|p| p.get(addon).map(|p| p.lock_sha256.clone()))
            .unwrap_or_default();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        provisioned::mark(
            &self.root,
            &Marker {
                addon: addon.to_string(),
                schema: sys.schema.clone(),
                role: sys.role.clone(),
                ddl_role: sys.ddl_role.clone(),
                version: version.to_string(),
                lock_sha256,
                provisioned_at: now,
            },
        )
        .map_err(|e| Refusal {
            why: format!("{e} (the schema, roles and files ARE in place; this step is repeatable)"),
            fix: format!("noo addons enable {addon} --provision-only"),
        })
    }
}

/// `noo addons enable <addon> --provision-only [--lock X]`.
pub(crate) fn run(g: &Globals, addon: &'static str, lock: Option<String>) -> i32 {
    use crate::output::{fail, ExitCode};
    let root = crate::envfile::repo_root();
    let config = crate::commands::addons::config_path();
    let mut ops = Live {
        enable: addon_enable::Live { g, force: false, lock, require_system: true },
        g,
        root,
    };
    match provision_only(&config, addon, &mut ops) {
        Ok(receipt) => {
            if g.json {
                println!("{}", receipt.json());
            } else {
                if receipt.minted.is_empty() {
                    crate::ui::done(&format!("{addon}: credentials present - nothing minted"));
                } else {
                    crate::ui::done(&format!("{addon}: minted {} into the encrypted store", receipt.minted.join(", ")));
                }
                receipt.print();
            }
            0
        }
        Err(r) => fail(
            g.json,
            ExitCode::Generic,
            "provision_refused",
            &format!("{addon} not provisioned: {} - noomesh.yaml is unchanged and no service was started", r.why),
            Some(&r.fix),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::addon_enable::tests::{scratch, CONFIG};

    #[test]
    fn the_broker_request_carries_verify_callers_only_when_declared() {
        let mut sys = System {
            schema: "rhaddon".into(), role: "noo_rhaddon".into(), ddl_role: "noo_rhaddon_ddl".into(), extensions: vec![], verify_callers: false,
        };
        let v: serde_json::Value = serde_json::from_str(&broker_request("rhaddon", &sys, &BTreeMap::new())).unwrap();
        assert!(v["system"].get("verify_callers").is_none(), "an undeclared field must not reach an older gateway: {v}");
        sys.verify_callers = true;
        let v: serde_json::Value = serde_json::from_str(&broker_request("rhaddon", &sys, &BTreeMap::new())).unwrap();
        assert_eq!(v["system"]["verify_callers"], serde_json::json!(true));
    }

    const ADDON: &str = "pai-voice";
    const V_DB: &str = "THROWAWAY-runtime-pw-aaaa1111";
    const V_DDL: &str = "THROWAWAY-ddl:pw\\bbbb2222";

    fn sys() -> System {
        System { schema: "pai_voice".into(), role: "noo_pai_voice".into(), ddl_role: "noo_pai_voice_ddl".into(), extensions: vec![], verify_callers: false }
    }

    fn secrets() -> BTreeMap<String, String> {
        let (pw, ddl) = decls::password_envs(ADDON);
        [(pw, V_DB.to_string()), (ddl, V_DDL.to_string())].into()
    }

    /// A gateway stand-in at the PIPE: it answers what `provision-system`
    /// answers, from the request it was actually sent.
    #[derive(Default)]
    struct FakeTransport {
        requests: Vec<String>,
        existing_roles: Vec<String>,
        schema_exists: bool,
        fail: Option<String>,
        answer_override: Option<String>,
    }

    impl BrokerTransport for FakeTransport {
        fn exchange(&mut self, request: &str) -> Result<String, String> {
            self.requests.push(request.to_string());
            if let Some(e) = &self.fail {
                return Err(e.clone());
            }
            if let Some(a) = &self.answer_override {
                return Ok(a.clone());
            }
            let r: serde_json::Value = serde_json::from_str(request).unwrap();
            let created: Vec<String> = [r["system"]["ddl_role"].as_str().unwrap(), r["system"]["role"].as_str().unwrap()]
                .iter()
                .filter(|x| !self.existing_roles.iter().any(|e| e == **x))
                .map(|x| x.to_string())
                .collect();
            Ok(json!({
                "ok": true, "addon": r["addon"], "schema": r["system"]["schema"], "role": r["system"]["role"],
                "ddl_role": r["system"]["ddl_role"], "roles_created": created, "schema_created": !self.schema_exists,
            })
            .to_string())
        }
    }

    struct Fake {
        calls: Vec<String>,
        transport: FakeTransport,
        out: PathBuf,
        pin: PinStep,
        has_system: bool,
        network: Result<String, String>,
        fail_mint: bool,
        marked: Vec<String>,
        store: Vec<String>,
    }

    impl Fake {
        fn new(tag: &str) -> Fake {
            let out = std::env::temp_dir().join(format!("noo-provision-it-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&out);
            Fake {
                calls: vec![],
                transport: FakeTransport::default(),
                out,
                pin: PinStep::Pinned { version: "0.1.0".into(), stack: "v0.6.11".into(), key_index: 0, pulled: 1 },
                has_system: true,
                network: Ok("pai-assistant_noo-db".into()),
                fail_mint: false,
                marked: vec![],
                store: vec![],
            }
        }
    }

    impl ProvisionOps for Fake {
        fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal> {
            self.calls.push(format!("pin:{addon}"));
            if !self.has_system {
                return Err(Refusal { why: "declares no database (system.json). Nothing was changed".into(), fix: "x".into() });
            }
            Ok(self.pin.clone())
        }
        fn system(&mut self, addon: &str) -> Result<System, Refusal> {
            self.calls.push(format!("system:{addon}"));
            Ok(sys())
        }
        fn preflight(&mut self, addon: &str) -> Result<String, Refusal> {
            self.calls.push(format!("preflight:{addon}"));
            self.network.clone().map_err(|e| Refusal { why: e, fix: "noo stack start".into() })
        }
        fn mint(&mut self, addon: &str) -> Result<Vec<String>, Refusal> {
            self.calls.push(format!("mint:{addon}"));
            if self.fail_mint {
                return Err(Refusal { why: "sops refused".into(), fix: "noo security secrets audit".into() });
            }
            let (pw, ddl) = decls::password_envs(addon);
            let mut minted = vec![];
            for k in [pw, ddl] {
                if !self.store.contains(&k) {
                    self.store.push(k.clone());
                    minted.push(k);
                }
            }
            Ok(minted)
        }
        fn secrets(&mut self, _addon: &str) -> Result<BTreeMap<String, String>, Refusal> {
            self.calls.push("secrets".into());
            Ok(secrets())
        }
        fn broker(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<BrokerReport, Refusal> {
            self.calls.push(format!("broker:{addon}"));
            // the REAL exchange, over the fake pipe
            broker_exchange(&mut self.transport, addon, sys, secrets)
        }
        fn write_files(&mut self, addon: &str, sys: &System, secrets: &BTreeMap<String, String>) -> Result<Files, Refusal> {
            self.calls.push("files".into());
            let pki = Pki {
                ca: b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n".to_vec(),
                cert: b"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_vec(),
                key: b"-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n".to_vec(),
            };
            write_credential_files(&self.out.join(addon), sys, secrets, addon, &pki)
                .map_err(|e| Refusal { why: e, fix: "x".into() })
        }
        fn mark(&mut self, addon: &str, _sys: &System, _version: &str) -> Result<(), Refusal> {
            self.calls.push(format!("mark:{addon}"));
            self.marked.push(addon.to_string());
            Ok(())
        }
    }

    fn config_with(tag: &str, addon_line: &str) -> PathBuf {
        let p = scratch(&format!("prov-{tag}"));
        std::fs::write(&p, format!("{CONFIG}{addon_line}")).unwrap();
        p
    }

    #[test]
    fn provisioning_mints_calls_the_broker_for_exactly_that_system_and_never_flips_the_switch() {
        let p = config_with("flow", "");
        let before = std::fs::read_to_string(&p).unwrap();
        let mut ops = Fake::new("flow");
        let r = provision_only(&p, ADDON, &mut ops).expect("provision");

        assert_eq!(ops.calls, ["pin:pai-voice", "system:pai-voice", "preflight:pai-voice", "mint:pai-voice", "secrets", "broker:pai-voice", "files", "mark:pai-voice"]);
        assert_eq!(r.minted, ["NOO_PAI_VOICE_DB_PASSWORD", "NOO_PAI_VOICE_DDL_PASSWORD"], "credentials minted by name");

        // one request, for exactly that one system, carrying exactly its two passwords
        assert_eq!(ops.transport.requests.len(), 1);
        let req: serde_json::Value = serde_json::from_str(&ops.transport.requests[0]).unwrap();
        assert_eq!(req["addon"], ADDON);
        assert_eq!(req["system"]["schema"], "pai_voice");
        assert_eq!(req["system"]["role"], "noo_pai_voice");
        assert_eq!(req["system"]["ddl_role"], "noo_pai_voice_ddl");
        let keys: Vec<&String> = req["secrets"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["NOO_PAI_VOICE_DB_PASSWORD", "NOO_PAI_VOICE_DDL_PASSWORD"]);
        assert_eq!(r.created_roles, ["noo_pai_voice_ddl", "noo_pai_voice"]);
        assert!(r.schema_created);

        // NOT composable: the file is byte-identical, and add-on is not declared on
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before, "provision-only must never write noomesh.yaml");
        assert_ne!(crate::commands::addons::declared_in(&before).get(ADDON), Some(&true));
        assert_eq!(ops.marked, [ADDON]);
        assert_eq!(r.json()["switch"], "off");
        assert_eq!(r.json()["state"], "provisioned");
    }

    #[test]
    fn the_module_never_writes_the_switch() {
        let src = include_str!("addon_provision.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        for forbidden in ["write_addon_at(", "write_addon(", "set_addon(", "issue_key(", "reconcile_principals"] {
            assert!(!body.contains(forbidden), "{forbidden} would make provision-only start something");
        }
    }

    /// The launcher composes an add-on only when `addons.<name>` renders `=1`.
    /// A provisioned add-on's config renders no `=1` line for it.
    #[test]
    fn the_launchers_addon_map_has_no_on_line_for_a_provisioned_addon() {
        let p = config_with("map", "");
        let mut ops = Fake::new("map");
        provision_only(&p, ADDON, &mut ops).expect("provision");
        let rendered = crate::commands::launch_render::render_addons(&std::fs::read_to_string(&p).unwrap());
        assert!(!rendered.lines().any(|l| l == "pai-voice=1"), "{rendered}");
    }

    #[test]
    fn a_plain_enable_afterwards_turns_it_fully_on_and_the_state_follows() {
        let p = config_with("then-enable", "");
        let root = p.parent().unwrap().to_path_buf();
        let mut ops = Fake::new("then-enable");
        let r = provision_only(&p, ADDON, &mut ops).expect("provision");
        // the CLI records the marker in `mark`; do the same here against `root`
        provisioned::mark(
            &root,
            &Marker { addon: ADDON.into(), schema: r.schema, role: r.role, ddl_role: r.ddl_role, version: "0.1.0".into(), lock_sha256: "ab".repeat(32), provisioned_at: 1 },
        )
        .unwrap();
        let declared = |p: &Path| crate::commands::addons::declared_map_at(p).unwrap();
        assert_eq!(provisioned::only(&provisioned::read_all(&root), &declared(&p)).len(), 1, "provisioned before");

        let mut en = addon_enable::tests::Fake { declares_key: false, ..Default::default() };
        let e = addon_enable::enable(&p, ADDON, &mut en).expect("plain enable");
        assert!(e.flipped);
        assert_eq!(declared(&p).get(ADDON), Some(&true), "the switch is on");
        assert!(provisioned::only(&provisioned::read_all(&root), &declared(&p)).is_empty(), "no longer merely provisioned");
        let rendered = crate::commands::launch_render::render_addons(&std::fs::read_to_string(&p).unwrap());
        assert!(rendered.lines().any(|l| l == "pai-voice=1"), "{rendered}");
    }

    #[test]
    fn an_addon_that_is_already_on_is_refused_before_anything_runs() {
        let p = config_with("on", "  pai-voice: true\n");
        let mut ops = Fake::new("on");
        // CONFIG ends with the addons block, so the appended line is inside it
        assert_eq!(crate::commands::addons::declared_in(&std::fs::read_to_string(&p).unwrap()).get(ADDON), Some(&true));
        let r = provision_only(&p, ADDON, &mut ops).expect_err("must refuse");
        assert!(r.why.contains("already switched on"), "{r:?}");
        assert!(ops.calls.is_empty(), "{:?}", ops.calls);
    }

    #[test]
    fn a_bundle_without_system_json_refuses_before_a_credential_is_minted() {
        let p = config_with("nosys", "");
        let mut ops = Fake::new("nosys");
        ops.has_system = false;
        let r = provision_only(&p, ADDON, &mut ops).expect_err("must refuse");
        assert!(r.why.contains("declares no database"), "{r:?}");
        assert!(ops.store.is_empty() && ops.transport.requests.is_empty() && ops.marked.is_empty());
    }

    /// An unverified lock is never enough: `--force`/dev-checkout/no-bundle
    /// results all surface as a non-`Pinned` step.
    #[test]
    fn anything_but_a_verified_pin_refuses() {
        for pin in [PinStep::NotLicensed, PinStep::Skipped("this install pins no stack tag".into())] {
            let p = config_with("unverified", "");
            let mut ops = Fake::new("unverified");
            ops.pin = pin;
            let r = provision_only(&p, ADDON, &mut ops).expect_err("must refuse");
            assert!(r.why.contains("never provisions from an unverified bundle"), "{r:?}");
            assert_eq!(ops.calls, ["pin:pai-voice"], "nothing after the lock");
        }
    }

    #[test]
    fn a_missing_database_network_or_a_failed_mint_stops_before_the_broker() {
        let p = config_with("nonet", "");
        let mut ops = Fake::new("nonet");
        ops.network = Err("noo-postgres is not running".into());
        provision_only(&p, ADDON, &mut ops).expect_err("no network");
        assert!(ops.store.is_empty(), "preconditions come before minting");

        let mut ops = Fake::new("nomint");
        ops.fail_mint = true;
        provision_only(&p, ADDON, &mut ops).expect_err("mint fails");
        assert!(ops.transport.requests.is_empty(), "no broker call over missing credentials");
    }

    #[test]
    fn a_second_run_creates_nothing_and_mints_nothing() {
        let p = config_with("twice", "");
        let mut ops = Fake::new("twice");
        provision_only(&p, ADDON, &mut ops).expect("first");
        ops.transport.existing_roles = vec!["noo_pai_voice".into(), "noo_pai_voice_ddl".into()];
        ops.transport.schema_exists = true;
        let r = provision_only(&p, ADDON, &mut ops).expect("second");
        assert!(r.minted.is_empty(), "{:?}", r.minted);
        assert!(r.created_roles.is_empty() && !r.schema_created, "{r:?}");
    }

    #[test]
    fn a_broker_that_cannot_be_reached_or_refuses_is_a_refusal_with_no_value_in_it() {
        let mut t = FakeTransport { fail: Some(format!("boom {V_DB} {V_DDL}")), ..Default::default() };
        let r = broker_exchange(&mut t, ADDON, &sys(), &secrets()).expect_err("unreachable");
        assert!(!r.why.contains(V_DB) && !r.why.contains(V_DDL), "{r:?}");
        assert!(r.why.contains("<redacted>"));

        let mut t = FakeTransport {
            answer_override: Some(json!({"ok": false, "error": format!("CREATE ROLE failed near {V_DB}"), "missing": null}).to_string()),
            ..Default::default()
        };
        let r = broker_exchange(&mut t, ADDON, &sys(), &secrets()).expect_err("refused");
        assert!(r.why.starts_with("the broker refused"), "{r:?}");
        assert!(!r.why.contains(V_DB));

        let mut t = FakeTransport { answer_override: Some("not json".into()), ..Default::default() };
        let r = broker_exchange(&mut t, ADDON, &sys(), &secrets()).expect_err("garbage");
        assert!(r.why.contains("not its report"), "{r:?}");
    }

    /// The broker is asked for one system and must answer for that one.
    #[test]
    fn a_broker_answer_for_another_system_is_refused() {
        let wrong = json!({"ok": true, "schema": "mesh", "role": "noo_pai_voice", "ddl_role": "noo_pai_voice_ddl", "roles_created": [], "schema_created": false});
        let mut t = FakeTransport { answer_override: Some(wrong.to_string()), ..Default::default() };
        let r = broker_exchange(&mut t, ADDON, &sys(), &secrets()).expect_err("mismatch");
        assert!(r.why.contains("different system"), "{r:?}");
    }

    #[test]
    fn the_receipt_has_every_field_and_no_secret_value() {
        let p = config_with("receipt", "");
        let mut ops = Fake::new("receipt");
        let r = provision_only(&p, ADDON, &mut ops).expect("provision");
        let j = r.json();
        let text = j.to_string();
        let shape = r.docker_run();

        // every field the operator needs
        assert_eq!(j["database"]["name"], "noomesh");
        assert_eq!(j["database"]["host"], "postgres");
        assert_eq!(j["database"]["port"], 5432);
        assert_eq!(j["database"]["schema"], "pai_voice");
        assert_eq!(j["database"]["runtime_role"], "noo_pai_voice");
        assert_eq!(j["database"]["ddl_role"], "noo_pai_voice_ddl");
        assert_eq!(j["network"], "pai-assistant_noo-db");
        let dir = ops.out.join(ADDON);
        assert_eq!(j["files"]["dir"], dir.display().to_string());
        assert_eq!(j["files"]["ca"], dir.join("ca.crt").display().to_string());
        assert_eq!(j["files"]["client_cert"], dir.join("client.crt").display().to_string());
        assert_eq!(j["files"]["client_key"], dir.join("client.key").display().to_string());
        assert_eq!(j["files"]["pgpass"]["noo_pai_voice"], dir.join("pgpass.noo_pai_voice").display().to_string());
        assert_eq!(j["files"]["pgpass"]["noo_pai_voice_ddl"], dir.join("pgpass.noo_pai_voice_ddl").display().to_string());
        assert_eq!(j["files"]["read_only"], true);
        assert_eq!(j["state_text"], "provisioned (services not started)");

        // the runner shape: private network, nothing published, no GPU, no socket, read-only
        assert!(shape.contains("--network pai-assistant_noo-db"), "{shape}");
        assert!(shape.contains(":/run/noo-db:ro"), "{shape}");
        assert!(shape.contains("--read-only") && shape.contains("--cap-drop ALL"), "{shape}");
        for forbidden in ["-p ", "--publish", "--gpus", "docker.sock", "--privileged", "--network host", "--device"] {
            assert!(!shape.contains(forbidden), "{forbidden} in {shape}");
        }

        // no secret value anywhere the operator can see
        for v in [V_DB, V_DDL] {
            assert!(!text.contains(v) && !shape.contains(v), "a minted value reached the receipt");
        }
        let all_output = format!("{text}\n{shape}\n{:?}\n{:?}", r, ops.calls);
        assert!(!all_output.contains(V_DB) && !all_output.contains(V_DDL));
    }

    #[test]
    fn the_credential_files_hold_the_passwords_and_nothing_else_does() {
        use std::os::unix::fs::PermissionsExt as _;
        let p = config_with("files", "");
        let mut ops = Fake::new("files");
        let r = provision_only(&p, ADDON, &mut ops).expect("provision");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&r.files.dir), 0o700);
        assert_eq!(mode(&r.files.key), 0o400, "libpq needs a non-root-owned key at 0600 or tighter");
        assert_eq!(mode(&r.files.ca), 0o444);
        for (role, path) in &r.files.pgpass {
            assert_eq!(mode(path), 0o400, "{role}");
        }
        // libpq escaping: `:` and `\` in the password are escaped
        let ddl = std::fs::read_to_string(&r.files.pgpass[1].1).unwrap();
        assert_eq!(ddl, "postgres:5432:noomesh:noo_pai_voice_ddl:THROWAWAY-ddl\\:pw\\\\bbbb2222\n");
        let rt = std::fs::read_to_string(&r.files.pgpass[0].1).unwrap();
        assert_eq!(rt, format!("postgres:5432:noomesh:noo_pai_voice:{V_DB}\n"));
        // the role each file serves is the only role it names
        assert!(!rt.contains("noo_pai_voice_ddl"));
        // no password in the public files
        for f in [&r.files.ca, &r.files.cert, &r.files.key] {
            let t = std::fs::read_to_string(f).unwrap();
            assert!(!t.contains("THROWAWAY"), "{}", f.display());
        }
        // re-running rewrites in place without leaving temp files
        let names: Vec<String> = std::fs::read_dir(&r.files.dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
        assert_eq!(names.len(), 5, "{names:?}");
    }

    #[test]
    fn the_credential_directory_is_a_fixed_documented_path() {
        assert_eq!(provision_rundir(None, 0), PathBuf::from("/run/noo/provision"));
        assert_eq!(provision_rundir(None, 1000), PathBuf::from("/dev/shm/noo-provision-1000"));
        assert_eq!(provision_rundir(Some("/x/y"), 1000), PathBuf::from("/x/y"));
        assert_eq!(provision_rundir(Some("  "), 1000), PathBuf::from("/dev/shm/noo-provision-1000"));
    }

    #[test]
    fn the_database_network_is_found_not_assumed() {
        let one = r#"{"pai-assistant_noo-db":{"IPAddress":"172.19.0.2"},"pai-assistant_noo-pg-host":{}}"#;
        assert_eq!(db_network_from(one).unwrap(), "pai-assistant_noo-db");
        assert_eq!(db_network_from(r#"{"noo-db":{}}"#).unwrap(), "noo-db");
        assert!(db_network_from(r#"{"pai-assistant_noo-pg-host":{}}"#).is_err());
        assert!(db_network_from(r#"{"a_noo-db":{},"b_noo-db":{}}"#).is_err(), "ambiguity is refused, not guessed");
        assert!(db_network_from("[]").is_err());
    }

    #[test]
    fn the_receipt_is_wired_into_the_command_and_the_state_into_the_readers() {
        let addons = include_str!("addons.rs");
        assert!(addons.contains("\"--provision-only\""), "the flag is parsed");
        assert!(addons.contains("addon_provision::run("), "and dispatched");
        let enable = include_str!("addon_enable.rs");
        assert!(enable.contains("require_system"), "the lock gate for the bundle's database declaration");
    }
}
