// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Docker / docker-compose shell-outs for the wizard. Same commands the
//! Python steps invoke (`onboard/helpers.py`), so behaviour matches the
//! reference wizard — but every mutation is gated on `ctx.dry_run`, which
//! prints the intended command instead of running it (the safe demo/verify
//! path on an already-live host).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::Ctx;

/// Base `docker compose -f cluster [-f override]` argv (cwd handled by caller).
fn compose_prefix(ctx: &Ctx) -> Vec<String> {
    let mut v = vec!["compose".to_string()];
    for f in compose_files(ctx) {
        v.push("-f".to_string());
        v.push(f);
    }
    v
}

/// The compose file list, from the ONE home: `scripts/lib-compose.sh`.
///
/// This used to be base + override, hardcoded — a ninth copy of a decision
/// the launchers each made differently. On a dist
/// install that omitted the dist overlay, so every image ref resolved to
/// `:latest`; it omitted the GPU overlay and every add-on overlay. Asking the
/// shell helper means the onboard recreate composes exactly what
/// `noo stack start` composes. Falls back to base + override only when the
/// helper is not on disk (a checkout with no scripts/ is not an install).
pub(crate) fn compose_files(ctx: &Ctx) -> Vec<String> {
    compose_files_in(&ctx.repo_root, ctx.dry_run, &ctx.compose_file, &ctx.override_file)
}

/// The list itself, with the install root and the fallback pair passed in so
/// a test can point it at a scratch tree. Asks `scripts/lib-compose.sh`
/// (the ONE home) and only falls back to base+override
/// on a tree too old to carry the helper, or on a dry run.
fn compose_files_in(
    repo_root: &Path,
    dry_run: bool,
    compose_file: &Path,
    override_file: &Path,
) -> Vec<String> {
    let lib = repo_root.join("scripts/lib-compose.sh");
    if lib.is_file() && !dry_run {
        let out = Command::new("bash")
            .arg("-c")
            .arg(". scripts/lib-compose.sh && compose_file_list .")
            .current_dir(repo_root)
            .stdin(Stdio::null())
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let files: Vec<String> = String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(|l| repo_root.join(l).to_string_lossy().into_owned())
                    .collect();
                if !files.is_empty() {
                    return files;
                }
            }
        }
    }
    let mut v = vec![compose_file.to_string_lossy().into_owned()];
    if override_file.exists() {
        v.push(override_file.to_string_lossy().into_owned());
    }
    v
}

/// The add-on image environment for this install's composed overlays, with
/// the launcher's semantics (`commands::addon_pins::addon_image_env`, the
/// Rust side of `scripts/lib-dist.sh` `require_addon_pins`): on a dist
/// install only verified, local pins; on a dev one the dev build's names.
/// `Err` lists each refusal as `(add-on, why, remedy)`.
pub(crate) fn addon_pin_env(ctx: &Ctx) -> Result<Vec<(String, String)>, Vec<crate::commands::addon_pins::PinRefusal>> {
    let files = compose_files(ctx);
    let texts: Vec<String> = files.iter().filter_map(|f| std::fs::read_to_string(f).ok()).collect();
    let composed: Vec<String> = addons_on(ctx).into_iter().map(|(k, _)| k).collect();
    let tag = ctx.read_env("NOO_IMAGE_TAG");
    let prefix = std::env::var("NOO_IMAGE_PREFIX").ok().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "noomesh".into());
    let input = crate::commands::addon_pins::PinEnvInput {
        root: &ctx.repo_root,
        dist: ctx.read_env("NOO_INSTALL_MODE") == "dist",
        tag: tag.trim(),
        image_prefix: &prefix,
        compose_texts: texts,
        composed_addons: composed,
    };
    crate::commands::addon_pins::addon_image_env(
        &input,
        &|a| crate::addons::resolve::installed_anchor(a),
        &|r| crate::addons::resolve::Docker::image_present(&mut crate::addons::resolve::LiveDocker::new(&ctx.repo_root), r),
    )
}

/// The wizard is a sanctioned launcher, so its compose calls carry the same
/// env noomesh-start.sh exports before compose:
/// - NOO_LAUNCHED=1 — the bare-`docker compose up` sentinel (secrets are in
///   .env at this point of onboarding, so interpolation is complete);
/// - the launcher pair. (NOO_MCP_GATEWAY_HOST_PORT used to sit here so the
///   gateway's :3100 publish would not collide with noo-trellion's MCP hub
///   — defect #18. Neither publishes 3100 since stack-v0.2.40; the gateway's
///   loopback MCP listener is gone.) Pre-set values in the environment win.
fn launcher_env(ctx: &Ctx, cmd: &mut Command) {
    cmd.env("NOO_LAUNCHED", "1");
    // Add-on images: exactly what the launcher would export. A refusal
    // leaves the variables unset, so the overlay renders its unpinned
    // sentinel and nothing unverified runs; the caller that recreates
    // add-ons asks `addon_pin_env` first and says why (steps.rs).
    for (k, v) in addon_pin_env(ctx).unwrap_or_default() {
        cmd.env(k, v);
    }
    // File-backed secrets (2026-09-29): the same two things
    // lib-secrets.sh `derive_file_secrets` does for every other launcher —
    // derive the pgpass bodies, and make every `secrets:` source variable
    // SET (empty when neither this process nor .env holds it), or compose
    // refuses to create the service that uses it. Values reach only the
    // compose child's environment; nothing is written to disk.
    let composes = compose_texts_beside(&ctx.compose_file);
    let composes: Vec<&str> = composes.iter().map(String::as_str).collect();
    let dotenv = std::fs::read_to_string(&ctx.env_path).unwrap_or_default();
    for (k, v) in file_secret_env(&composes, &|k| std::env::var(k).ok(), &dotenv) {
        cmd.env(k, v);
    }
    for (k, v) in [
        ("NOO_WORKER_SUPERVISOR", "external"),
        ("NOO_MIGRATIONS_ENVS", "mesh"),
    ] {
        if std::env::var(k).unwrap_or_default().is_empty() {
            cmd.env(k, v);
        }
    }
    // Dev-only trellion source overlay (defect #20) — same detection as
    // lib-config.sh: no sibling checkout → inert mount, or the empty
    // docker-created source dir shadows the image's trellion package.
    let tpath = std::env::var("TRELLION_PATH").unwrap_or_else(|_| "../noo-trellion".into());
    let tsrc = if Path::new(&tpath).is_absolute() {
        PathBuf::from(&tpath).join("src/trellion")
    } else {
        ctx.repo_root.join(&tpath).join("src/trellion")
    };
    // Content check, not bare existence: a previous bare `up` may have left
    // a docker-created EMPTY dir at exactly this path, which is the very
    // artifact this guard exists to neutralize.
    if !tsrc.join("__init__.py").is_file() && std::env::var("TRELLION_SRC").unwrap_or_default().is_empty() {
        cmd.env("TRELLION_SRC", "./.trellion-src-placeholder");
        cmd.env("TRELLION_SRC_DEST", "/tmp/.trellion-src-unused");
    }
}

/// Before an `up`: the same bind-source check the shell launchers run
/// (`scripts/lib-bind-sources.sh` → `commands::bind_sources`), over the
/// config THIS `up` will use — the argv before `up` (profiles), the named
/// services after it. `Some(text)` = refuse; `None` = fine, not an `up`, or
/// the config could not be rendered (then `up` reports compose's own error).
fn bind_sources_refusal(ctx: &Ctx, args: &[&str]) -> Option<String> {
    let (render, services, no_deps) = up_selection(args)?;
    let (code, out) = run_compose(ctx, &render);
    if code != 0 {
        return None;
    }
    // `out` is stdout then stderr; the config is the first JSON document.
    let cfg: serde_json::Value = serde_json::Deserializer::from_str(&out).into_iter().next()?.ok()?;
    let data_root = ctx.read_env("NOO_DATA_ROOT");
    let root = if data_root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { data_root };
    // No systemd = no hostd to create the host spool: make it here, as the
    // user, rather than refuse (and rather than let Docker make it root-owned).
    crate::commands::bind_sources::ensure_hostd_spool(&cfg, &services, no_deps, crate::commands::bind_sources::systemd_present());
    // The add-on declarations directories the launcher fills (i163): empty
    // is normal, so make them as the user rather than refuse.
    crate::commands::bind_sources::ensure_launcher_dirs(&cfg, &services, no_deps);
    let findings = crate::commands::bind_sources::check(&cfg, &services, no_deps, Some(&root));
    (!findings.is_empty()).then(|| crate::commands::bind_sources::refusal(&findings))
}

/// For an `up` argv: the argv that renders its config (everything before
/// `up`, then `config --format json`), the services it names, and whether
/// it passes `--no-deps`. `None` when the argv is not an `up`.
fn up_selection<'a>(args: &[&'a str]) -> Option<(Vec<&'a str>, Vec<String>, bool)> {
    let at = args.iter().position(|a| *a == "up")?;
    let mut render: Vec<&'a str> = args[..at].to_vec();
    render.extend(["config", "--format", "json"]);
    let after = &args[at + 1..];
    let services = after
        .iter()
        .filter(|a| !a.starts_with('-') && !a.contains('='))
        .map(|s| s.to_string())
        .collect();
    Some((render, services, after.contains(&"--no-deps")))
}

/// The pgpass bodies the launcher derives: `(variable, driver that reads it,
/// [(role, password variable)])`. The SAME declaration as
/// `NOO_PGPASS_ROLES_GATEWAY` / `NOO_PGPASS_ROLES_WORKER` in
/// scripts/lib-secrets.sh — tests/test_compose_secret_files.py parses both
/// and fails when they differ. The driver decides the password's escaping:
/// libpq de-escapes backslashes in it, sqlx 0.8.6 takes it verbatim.
pub(crate) type PgpassSpec = (&'static str, &'static str, &'static [(&'static str, &'static str)]);
pub(crate) const PGPASS_ROLES: &[PgpassSpec] = &[
    ("NOO_PGPASS_GATEWAY", "sqlx", &[("noo", "POSTGRES_PASSWORD"), ("noo_app", "NOO_APP_DB_PASSWORD")]),
    ("NOO_PGPASS_WORKER", "libpq", &[("noo_app", "NOO_APP_DB_PASSWORD")]),
    (
        "NOO_PGPASS_TRELLION",
        "libpq",
        &[
            ("noo_app", "NOO_APP_DB_PASSWORD"),
            ("noo_trellion", "NOO_TRELLION_DB_PASSWORD"),
            ("noo_trellion_ddl", "NOO_TRELLION_DDL_PASSWORD"),
        ],
    ),
    ("NOO_PGPASS_EVOLVE", "libpq", &[("noo_evolve", "NOO_EVOLVE_DB_PASSWORD"), ("noo_evolve_ddl", "NOO_EVOLVE_DDL_PASSWORD")]),
];

/// The base compose file's text, then every `docker-compose.*.yml` beside it
/// (the add-on overlays declare their own top-level `secrets:`, which compose
/// merges across `-f` files). Same reading as lib-secrets.sh
/// `file_secret_sources`: a source for an overlay that is not composed is
/// inert; one missed for an overlay that is stops compose creating it. A
/// licensed add-on's overlay sits under `addons/<name>/docker-compose.yml`
/// (its signed bundle, N6) and is read after those.
fn compose_texts_beside(base: &Path) -> Vec<String> {
    let mut out = vec![std::fs::read_to_string(base).unwrap_or_default()];
    let dir = base.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut overlays: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    n.starts_with("docker-compose.") && n.ends_with(".yml") && Some(p.as_path()) != Some(base)
                })
                .collect()
        })
        .unwrap_or_default();
    overlays.sort();
    let mut bundled: Vec<PathBuf> = std::fs::read_dir(dir.join(crate::addons::pins::ADDONS_DIR))
        .map(|rd| rd.flatten().map(|e| e.path().join(crate::addon_lock::OVERLAY_FILE)).filter(|p| p.is_file()).collect())
        .unwrap_or_default();
    bundled.sort();
    overlays.extend(bundled);
    out.extend(overlays.iter().filter_map(|p| std::fs::read_to_string(p).ok()));
    out
}

/// The variable each top-level compose `secrets:` entry is sourced from
/// (`environment: VAR`), in file order.
pub(crate) fn file_secret_sources(compose: &str) -> Vec<String> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(compose) else {
        return Vec::new();
    };
    let Some(secrets) = doc.get("secrets").and_then(|v| v.as_mapping()) else {
        return Vec::new();
    };
    secrets
        .values()
        // A secret is sourced from the env var compose reads (`environment:`)
        // or, for the RAM-file form the read-only services need, the one the
        // launcher writes the file from (`x-noo-source:`).
        .filter_map(|v| {
            v.get("environment")
                .or_else(|| v.get("x-noo-source"))
                .and_then(|e| e.as_str())
                .map(str::to_string)
        })
        .collect()
}

/// `.env`'s value for `key` — the LAST assignment, one pair of surrounding
/// quotes removed — or None when `.env` does not assign it. Same reading as
/// lib-secrets.sh `_secret_value`.
fn dotenv_value(dotenv: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let raw = dotenv.lines().filter_map(|l| l.trim_start().strip_prefix(&prefix)).next_back()?;
    let v = raw.strip_suffix('\r').unwrap_or(raw);
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return Some(v[1..v.len() - 1].to_string());
        }
    }
    Some(v.to_string())
}

/// A pgpass body: one `postgres:5432:noomesh:<role>:<password>` line per role
/// whose password is non-empty. For libpq the password is escaped like any
/// field (`\` → `\\`, `:` → `\:`); sqlx 0.8.6 takes the rest of the line
/// verbatim, so its body is raw (measured, see lib-secrets.sh).
pub(crate) fn pgpass_body(driver: &str, roles: &[(&str, &str)], value: &dyn Fn(&str) -> Option<String>) -> String {
    let mut body = String::new();
    for (role, var) in roles {
        let pw = value(var).unwrap_or_default();
        if pw.is_empty() {
            continue;
        }
        let pw = if driver == "libpq" { pw.replace('\\', "\\\\").replace(':', "\\:") } else { pw };
        body.push_str(&format!("postgres:5432:noomesh:{role}:{pw}\n"));
    }
    // The launcher builds its body in a command substitution, which drops
    // the final newline; do the same so both bodies are byte-identical.
    body.pop();
    body
}

/// What the compose child needs in its environment for the file-backed
/// secrets: the derived pgpass bodies, and an EMPTY value for every source
/// variable neither the process (`env`) nor `.env` assigns.
pub(crate) fn file_secret_env(composes: &[&str], env: &dyn Fn(&str) -> Option<String>, dotenv: &str) -> Vec<(String, String)> {
    let value = |k: &str| env(k).or_else(|| dotenv_value(dotenv, k));
    let mut out: Vec<(String, String)> = PGPASS_ROLES
        .iter()
        .map(|(var, driver, roles)| (var.to_string(), pgpass_body(driver, roles, &value)))
        .collect();
    for src in composes.iter().flat_map(|c| file_secret_sources(c)) {
        if out.iter().any(|(k, _)| *k == src) {
            continue;
        }
        if env(&src).is_none() && dotenv_value(dotenv, &src).is_none() {
            out.push((src, String::new()));
        }
    }
    out
}

/// `docker <args>` for a wizard compose call. On a SOPS install the store's
/// values are not in this process (the wizard never decrypts into its own
/// environment), and compose needs them to create any service that takes a
/// `secrets:` entry — the postgres-only restore step's `POSTGRES_PASSWORD`
/// above all. So the call runs through the launcher's own loader in a child
/// bash, exactly as noo-hostd does (`withSecrets`): the values live in that
/// child and the compose process it execs, never here and never on disk, and
/// `load_secrets` derives the pgpass bodies and writes the secret FILES to
/// tmpfs itself (it reads `.env` for an install without the store).
fn compose_command(ctx: &Ctx, args: &[String]) -> Command {
    let lib = ctx.repo_root.join("scripts/lib-secrets.sh");
    // Every install, not only SOPS ones: since the read-only-rootfs change the
    // `secrets:` sources are FILES the loader writes to tmpfs
    // (`write_secret_files`, from `load_secrets`), and on an .env install
    // `load_secrets` writes them from .env. A bare `docker` here would run
    // compose with NOO_SECRET_RUNDIR unset and fail creating any service that
    // takes a secret.
    if lib.is_file() {
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg(r#"source "$0" >/dev/null 2>&1 && load_secrets >/dev/null || { echo "could not load the secret store or write the secret files (is NOO_SECRET_RUNDIR on tmpfs?) — refusing to run compose without them" >&2; exit 1; }; exec docker "$@""#)
            .arg(&lib)
            .args(args);
        return cmd;
    }
    let mut cmd = Command::new("docker");
    cmd.args(args);
    cmd
}

/// Run `docker compose … args`, capturing output. Returns `(exit_code, combined
/// stdout+stderr)`. In dry-run mode prints the command and returns `(0, "")`.
pub fn run_compose(ctx: &Ctx, args: &[&str]) -> (i32, String) {
    let mut full = compose_prefix(ctx);
    full.extend(args.iter().map(|s| s.to_string()));
    if ctx.dry_run {
        ctx.dry(&format!("docker {}", full.join(" ")));
        return (0, String::new());
    }
    if let Some(refused) = bind_sources_refusal(ctx, args) {
        return (1, refused);
    }
    let mut cmd = compose_command(ctx, &full);
    cmd.current_dir(&ctx.repo_root).stdin(Stdio::null());
    launcher_env(ctx, &mut cmd);
    match cmd.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(1), s)
        }
        Err(e) => (1, format!("failed to spawn docker: {e}")),
    }
}

/// Run `docker compose … args` with live output: inherited stdio on the
/// plain console, captured-and-forwarded `Line` events when the frontend
/// owns the terminal (TUI). Dry-run prints and returns 0.
pub fn run_compose_streamed(ctx: &Ctx, args: &[&str]) -> i32 {
    let mut full = compose_prefix(ctx);
    full.extend(args.iter().map(|s| s.to_string()));
    if ctx.dry_run {
        ctx.dry(&format!("docker {}", full.join(" ")));
        return 0;
    }
    if let Some(refused) = bind_sources_refusal(ctx, args) {
        for line in refused.lines() {
            ctx.error(line);
        }
        return 1;
    }
    let mut cmd = compose_command(ctx, &full);
    cmd.current_dir(&ctx.repo_root).stdin(Stdio::null());
    launcher_env(ctx, &mut cmd);
    // Only `up` prints the per-container churn worth collapsing; pull and
    // build progress stays live.
    if args.contains(&"up") {
        stream_status_summarised(ctx, cmd)
    } else {
        stream_status(ctx, cmd)
    }
}

/// Spawn a long-running command whose output the user should see live.
/// Plain frontend: inherited stdio (`.status()`), byte-identical to the
/// historical behaviour. Full-screen frontends (`!ctx.ui.inherit_stdio()`):
/// stdout/stderr are piped and every line is forwarded as a `Line` event so
/// build/pull progress lands in the TUI log instead of corrupting the frame.
pub fn stream_status(ctx: &Ctx, mut cmd: Command) -> i32 {
    if ctx.ui.inherit_stdio() {
        return match cmd.status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("failed to spawn command: {e}");
                1
            }
        };
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            ctx.warn(&format!("failed to spawn command: {e}"));
            return 1;
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let ui = ctx.ui;
    std::thread::scope(|s| {
        for pipe in [stdout.map(box_read), stderr.map(box_read)].into_iter().flatten() {
            s.spawn(move || forward_lines(ui, pipe));
        }
    });
    child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
}

/// Where one container ended up, by compose's last progress word for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerEnd {
    Started,
    Gone,
    Failed,
    Unfinished,
}

/// Running tally of a `docker compose up/restart` transcript: the final state
/// of every container, and which lines are NOT per-container progress.
#[derive(Default, Debug)]
pub struct ComposeTally {
    containers: std::collections::BTreeMap<String, ContainerEnd>,
}

impl ComposeTally {
    /// Feed one output line. Returns true when the line must reach the
    /// operator verbatim: anything that is not a recognised progress line,
    /// and any line (progress or not) that mentions an error, a failure or
    /// an unhealthy container. Recognised progress is counted and absorbed.
    pub fn feed(&mut self, line: &str) -> bool {
        let t = line.trim().trim_start_matches(['✔', '✘', '⠿', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏', '⠋']).trim();
        if t.is_empty() {
            return false;
        }
        let lower = t.to_ascii_lowercase();
        let loud = ["error", "failed", "unhealthy", "warn"].iter().any(|k| lower.contains(k));
        let mut words = t.split_whitespace();
        let progress = match words.next() {
            Some("Container") => {
                if let Some(name) = words.next() {
                    let state = words.collect::<Vec<_>>().join(" ").to_ascii_lowercase();
                    let end = match state.as_str() {
                        // Compose prints a bare `Exited` with no exit code, so a one-shot that
                        // finished cleanly (noo-evolve-routes) looks the same as a crash. Count
                        // it done: an `up` whose container really died still surfaces through
                        // compose's own exit status and its loud error/unhealthy lines. Only
                        // an `Exited` that carries a code (`Exited (1)`) is a failure below.
                        "started" | "exited" | "healthy" | "running" | "recreated" | "created" | "restarted" => ContainerEnd::Started,
                        "stopped" | "removed" | "killed" => ContainerEnd::Gone,
                        s if s.contains("error") || s.contains("fail") || s.contains("unhealthy") || s.contains("exited") => {
                            ContainerEnd::Failed
                        }
                        _ => ContainerEnd::Unfinished,
                    };
                    self.containers.insert(name.to_string(), end);
                    true
                } else {
                    false
                }
            }
            // Network/Volume/Image lines and the legacy "[+] Running 3/3" header.
            Some("Network") | Some("Volume") | Some("Image") => words.next().is_some(),
            Some("[+]") => true,
            _ => false,
        };
        !progress || loud
    }

    /// Containers whose last state was a failure.
    pub fn failed(&self) -> usize {
        self.count(ContainerEnd::Failed)
    }

    fn count(&self, end: ContainerEnd) -> usize {
        self.containers.values().filter(|e| **e == end).count()
    }

    /// `25 containers: 25 started, 0 failed`; None when no container line was seen.
    pub fn summary(&self) -> Option<String> {
        let total = self.containers.len();
        if total == 0 {
            return None;
        }
        let mut s = format!(
            "{total} container{}: {} started, {} failed",
            if total == 1 { "" } else { "s" },
            self.count(ContainerEnd::Started),
            self.failed()
        );
        let names: Vec<&str> = self.containers.iter().filter(|(_, e)| **e == ContainerEnd::Failed).map(|(n, _)| n.as_str()).collect();
        if !names.is_empty() {
            s.push_str(&format!(" ({})", names.join(", ")));
        }
        let gone = self.count(ContainerEnd::Gone);
        if gone > 0 {
            s.push_str(&format!(", {gone} removed"));
        }
        let open = self.count(ContainerEnd::Unfinished);
        if open > 0 {
            s.push_str(&format!(", {open} unfinished"));
        }
        Some(s)
    }
}

/// Pure form of the summariser: the one-line summary (empty when the
/// transcript had no container lines) and every line to show verbatim.
/// The live path feeds `ComposeTally` line by line; this is its test seam.
#[cfg(test)]
pub fn summarise_compose(lines: &[&str]) -> (String, Vec<String>) {
    let mut tally = ComposeTally::default();
    let mut pass = Vec::new();
    for l in lines {
        if tally.feed(l) {
            pass.push((*l).to_string());
        }
    }
    (tally.summary().unwrap_or_default(), pass)
}

/// Run `cmd` with its output piped: passthrough lines are printed live on the
/// stream they came from, progress lines are only counted. A muted line every
/// 30 s of silence says it is alive. Returns the exit status and the tally.
pub fn run_summarised(mut cmd: Command) -> std::io::Result<(std::process::ExitStatus, ComposeTally)> {
    use std::io::BufRead as _;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let mut readers = Vec::new();
    if let Some(p) = child.stdout.take() {
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            for l in std::io::BufReader::new(p).split(b'\n').map_while(Result::ok) {
                if tx.send((false, String::from_utf8_lossy(&l).into_owned())).is_err() {
                    break;
                }
            }
        }));
    }
    if let Some(p) = child.stderr.take() {
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            for l in std::io::BufReader::new(p).split(b'\n').map_while(Result::ok) {
                if tx.send((true, String::from_utf8_lossy(&l).into_owned())).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);
    let mut tally = ComposeTally::default();
    loop {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok((is_err, line)) => {
                if tally.feed(&line) {
                    if is_err {
                        eprintln!("{line}");
                    } else {
                        println!("{line}");
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                println!("  {}", crate::ui::muted("still working (pulling or starting containers; --verbose shows each line)"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    for r in readers {
        let _ = r.join();
    }
    let status = child.wait()?;
    Ok((status, tally))
}

/// [`stream_status`] for a compose-driving command: on the plain console,
/// and without `--verbose`, the per-container lines collapse into one
/// summary line. The TUI and `--verbose` keep the live stream unchanged.
pub fn stream_status_summarised(ctx: &Ctx, cmd: Command) -> i32 {
    if !ctx.ui.inherit_stdio() || ctx.g.verbose {
        return stream_status(ctx, cmd);
    }
    match run_summarised(cmd) {
        Ok((status, tally)) => {
            let code = status.code().unwrap_or(1);
            if let Some(s) = tally.summary() {
                if tally.failed() > 0 || code != 0 {
                    ctx.error(&s);
                } else {
                    ctx.success(&s);
                }
            }
            code
        }
        Err(e) => {
            eprintln!("failed to spawn command: {e}");
            1
        }
    }
}

fn box_read(r: impl std::io::Read + Send + 'static) -> Box<dyn std::io::Read + Send> {
    Box::new(r)
}

fn forward_lines(ui: &dyn crate::onboard::event::WizardUi, pipe: Box<dyn std::io::Read + Send>) {
    use std::io::BufRead as _;
    let reader = std::io::BufReader::new(pipe);
    for line in reader.lines().map_while(Result::ok) {
        // emit() unwinds with AbortPanic after a user abort — contain it here
        // so the reader thread just stops instead of poisoning the scope.
        let emitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ui.emit(crate::onboard::event::UiEvent::Line(format!("  {line}")));
        }));
        if emitted.is_err() {
            break;
        }
    }
}

/// `docker <args>` capturing output; `(code, combined)`. Read-only probes use
/// this directly regardless of dry-run.
///
/// Every arg that IS a default-instance container/network
/// name (`noo-x`, exactly) is remapped to this instance's name here, at
/// the choke point — so the many static `noo-*` tables upstream stay
/// literal and a second instance's wizard/checks still target ITS
/// containers. Image refs (`ghcr.io/…`, `pai-assistant/x`), volumes
/// (`…_noo-data`) and flags never match the shape.
pub fn docker(args: &[&str]) -> (i32, String) {
    let remapped: Vec<String> = args
        .iter()
        .map(|a| {
            let looks_like_name = a.starts_with("noo-")
                && a.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if looks_like_name {
                crate::envfile::instanced(a)
            } else {
                (*a).to_string()
            }
        })
        .collect();
    let args: Vec<&str> = remapped.iter().map(String::as_str).collect();
    match Command::new("docker").args(&args).stdin(Stdio::null()).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(1), s)
        }
        Err(e) => (1, format!("failed to spawn docker: {e}")),
    }
}

/// A mutating `docker <args>` (e.g. `docker exec … reset-password`), dry-run aware.
pub fn docker_mut(ctx: &Ctx, args: &[&str]) -> (i32, String) {
    if ctx.dry_run {
        ctx.dry(&format!("docker {}", args.join(" ")));
        return (0, String::new());
    }
    docker(args)
}

pub fn docker_daemon_running() -> bool {
    docker(&["info"]).0 == 0
}

/// Docker Hub creds present in ~/.docker/config.json (parity with `_check_docker_login`).
pub fn docker_logged_in() -> bool {
    let Ok(home) = std::env::var("HOME") else { return false };
    let path = std::path::Path::new(&home).join(".docker/config.json");
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&text) else { return false };
    cfg.get("auths")
        .and_then(|a| a.as_object())
        .map(|m| m.keys().any(|k| k.contains("docker.io") || k.contains("index.docker.io")))
        .unwrap_or(false)
}

/// ghcr.io creds present in ~/.docker/config.json. Informational only: the core
/// images are public, so no login is required; it matters for licensed add-ons
/// (private packages), where the wizard tells the operator to log in.
pub fn ghcr_logged_in() -> bool {
    let Ok(home) = std::env::var("HOME") else { return false };
    let path = std::path::Path::new(&home).join(".docker/config.json");
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&text) else { return false };
    cfg.get("auths")
        .and_then(|a| a.as_object())
        .map(|m| m.keys().any(|k| k.contains("ghcr.io")))
        .unwrap_or(false)
}

/// Run a launcher script (`bash scripts/<name> <args>`) with live output.
/// The services step's dist path delegates the WHOLE launch to
/// noomesh-start.sh --dist so the dist logic (tag resolution, ghcr login
/// check, compose overlay) lives in exactly one place. No [`launcher_env`]:
/// the script IS the launcher and exports that env itself. Dry-run prints
/// and returns 0.
pub fn run_script_streamed(ctx: &Ctx, script: &str, args: &[&str]) -> i32 {
    if ctx.dry_run {
        ctx.dry(&format!("bash scripts/{script} {}", args.join(" ")));
        return 0;
    }
    let mut cmd = Command::new("bash");
    cmd.arg(ctx.repo_root.join("scripts").join(script))
        .args(args)
        .current_dir(&ctx.repo_root)
        .stdin(Stdio::null());
    // Same binary, not whatever's on PATH — see mesh.rs::run_script for why.
    if let Ok(exe) = std::env::current_exe() {
        cmd.env("NOO_CLI_BIN", exe);
    }
    stream_status_summarised(ctx, cmd)
}

pub fn docker_image_exists(image: &str) -> bool {
    docker(&["image", "inspect", image]).0 == 0
}

/// True when EVERY named container is running (parity with `_are_services_running`).
pub fn are_services_running(names: &[&str]) -> bool {
    names.iter().all(|n| {
        let (code, out) = docker(&["inspect", "--format", "{{.State.Running}}", n]);
        code == 0 && out.trim() == "true"
    })
}

/// Poll a container's healthcheck until healthy or timeout (parity with
/// `_wait_for_health_docker`). Dry-run returns true immediately.
pub fn wait_for_health_docker(ctx: &Ctx, container: &str, timeout_secs: u64) -> bool {
    if ctx.dry_run {
        return true;
    }
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        let (code, out) = docker(&["inspect", "--format", "{{.State.Health.Status}}", container]);
        if code == 0 && out.trim() == "healthy" {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

/// Poll an HTTP(S) URL for a 200 (self-signed TLS accepted), until timeout.
/// Dry-run returns true. Parity with `helpers._wait_for_health`.
pub fn wait_for_http(ctx: &Ctx, url: &str, timeout_secs: u64) -> bool {
    if ctx.dry_run {
        return true;
    }
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if http_get_ok(url) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

/// Single GET, true on 2xx — VERIFIED, like every other request this CLI
/// makes. It used to disable TLS verification "matching the Python health
/// checks' verify=False"; the gateway cert carries `localhost` and
/// `127.0.0.1` among its SANs (`pki::issue_gateway_cert`) and the cluster CA
/// is on the box that runs onboarding, so there was never anything to gain.
/// An unresolvable anchor reads as "not healthy", which is the honest
/// answer: a health probe that cannot identify what answered has not
/// established that the right thing answered.
pub fn http_get_ok(url: &str) -> bool {
    let Ok(agent) = crate::http::agent_for(url, 5) else {
        return false;
    };
    match agent.get(url).call() {
        Ok(resp) => (200..=299).contains(&resp.status().as_u16()),
        Err(_) => false,
    }
}

/// Sync postgres + redis in-container passwords to match .env (parity with
/// `_sync_db_passwords`). Returns the services updated.
pub fn sync_db_passwords(ctx: &Ctx, pg_password: &str, redis_password: &str) -> Vec<String> {
    let mut updated = Vec::new();
    if !pg_password.is_empty() {
        let escaped = pg_password.replace('\'', "''");
        let sql = format!("ALTER USER noo PASSWORD '{escaped}'");
        let (code, _) = docker_mut(
            ctx,
            &["exec", "noo-postgres", "psql", "-U", "noo", "-d", "noo", "-c", &sql],
        );
        if code == 0 {
            updated.push("postgres".to_string());
        }
    }
    if !redis_password.is_empty() {
        // Try unauth first, then with -a (old password may still be active).
        for auth in [vec![], vec!["-a", redis_password]] {
            let mut args: Vec<&str> = vec!["exec", "noo-redis", "redis-cli"];
            args.extend(auth);
            args.extend(["CONFIG", "SET", "requirepass", redis_password]);
            let (code, out) = docker_mut(ctx, &args);
            if code == 0 && out.contains("OK") {
                updated.push("redis".to_string());
                break;
            }
        }
    }
    updated
}

// ── Which add-ons a whole-stack recreate must reach ──────────────────────

/// One add-on's compose footprint: the profile that selects it and the
/// services it brings.
pub(crate) struct AddonCompose {
    pub key: &'static str,
    /// `true` = opt-OUT (absent declaration means on). Only trellion.
    pub default_on: bool,
    pub services: &'static [&'static str],
}

/// The table, mirroring `addon_compose_overlay_args` in `scripts/lib-addons.sh`.
///
/// Two copies of one decision is what this repo keeps paying for, so the
/// copies are pinned to each other by
/// `tests::the_rust_and_shell_addon_tables_agree` rather than by anyone
/// remembering. An add-on delivered as an OVERLAY (`-f`, see
/// `compose_files`) has an empty `profile`: composing its file is the
/// switch, so a recreate names its services and no
/// `--profile`.
pub(crate) const ADDON_COMPOSE: &[AddonCompose] = &[
    // Every add-on is an OVERLAY: composed by file, no profile.
    // Same order as scripts/lib-addons.sh::addon_compose_overlay_args — trellion
    // first because a licensed add-on's overlay may extend its service. Only
    // the overlays that ship in this tree: a licensed add-on's services are
    // read from the overlay its signed bundle brought ([`addons_on`]).
    AddonCompose { key: "trellion", default_on: true, services: &["trellion"] },
    AddonCompose { key: "voice", default_on: false, services: &["whisper", "piper"] },
];

/// The `services:` keys of one compose text, in file order.
fn compose_service_names(text: &str) -> Vec<String> {
    serde_yaml::from_str::<serde_yaml::Value>(text)
        .ok()
        .and_then(|d| d.get("services").and_then(|s| s.as_mapping()).cloned())
        .map(|m| m.keys().filter_map(|k| k.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The services a licensed add-on's overlay ADDS (its `services:` keys that
/// the base and this tree's overlays do not define) — lib-addons.sh
/// `addon_own_services`, in Rust. Read from its bundled overlay;
/// empty when it is not there.
pub(crate) fn licensed_addon_services(root: &Path, addon: &str) -> Vec<String> {
    let bundled = crate::addons::pins::addon_dir(root, addon).join(crate::addon_lock::OVERLAY_FILE);
    let Ok(text) = std::fs::read_to_string(&bundled) else {
        return Vec::new();
    };
    let core: Vec<String> = ["docker-compose.cluster.yml", "docker-compose.trellion.yml", "docker-compose.voice.yml"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(root.join(f)).ok())
        .flat_map(|t| compose_service_names(&t))
        .collect();
    compose_service_names(&text).into_iter().filter(|s| !core.contains(s)).collect()
}

/// Every add-on that is ON for this install with the services it runs: the
/// core overlays (`ADDON_COMPOSE`), then each licensed add-on declared on,
/// with its services from its overlay.
pub(crate) fn addons_on(ctx: &Ctx) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = ADDON_COMPOSE
        .iter()
        .filter(|a| crate::onboard::yamlcfg::read_yaml_addon(ctx, a.key).unwrap_or(a.default_on))
        .map(|a| (a.key.to_string(), a.services.iter().map(|s| s.to_string()).collect()))
        .collect();
    for r in crate::commands::addons::ADDON_ROWS.iter().filter(|r| r.licensed.is_some()) {
        if crate::onboard::yamlcfg::read_yaml_addon(ctx, r.key).unwrap_or(false) {
            out.push((r.key.to_string(), licensed_addon_services(&ctx.repo_root, r.key)));
        }
    }
    out
}

/// `--profile X` flags and service names for every add-on that is ON.
///
/// A recreate that changes a credential must reach EVERY consumer of it, and
/// `compose up --force-recreate` silently skips a service whose profile it
/// was not given — four days of 401s from an add-on after a
/// rotation. The profile alone is not enough
/// either: a service absent from the argument list is not recreated even when
/// its profile is selected, which is why this returns both.
pub(crate) fn addon_recreate_targets(ctx: &Ctx) -> Vec<String> {
    addons_on(ctx).into_iter().flat_map(|(_, s)| s).collect()
}

/// Services in the `controller` profile that the wizard must NOT name on a
/// `compose up`, and why. This is the ONLY way a controller-profile service
/// stays out of what onboard starts and recreates; `recreate_set_tests`
/// reads docker-compose.cluster.yml and fails if a monitoring service ever
/// lands here.
///
/// - `node-agent`: the containerised agent cannot work
///   docker.sock away; it publishes :8081, which the host-native agent
///   owns). The launchers `--scale node-agent=0`; the wizard leaves it out.
/// - `nvidia-exporter`: carries a hard nvidia device reservation, and
///   compose aborts the WHOLE up on "could not select device driver" when
///   the host has no NVIDIA container runtime. Left out only then.
pub(crate) const HOST_OWNED_SERVICES: &[&str] = &["node-agent"];
pub(crate) const GPU_ONLY_SERVICES: &[&str] = &["nvidia-exporter"];

/// Every service the selected profile projects, from compose itself
/// (`docker compose … --profile <p> config --services`). `None` when the
/// projection could not be read — the caller says so; it never guesses a
/// list, because a guessed list is exactly the fixed six that left the
/// monitoring set stopped on the live controller (2026-09-28).
pub(crate) fn profile_services(ctx: &Ctx, profile: &str) -> Option<Vec<String>> {
    let (code, out) = run_compose(ctx, &["--profile", profile, "config", "--services"]);
    if code != 0 {
        return None;
    }
    let v: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(str::to_string)
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

/// What onboard starts and recreates: the projected services minus the
/// host-owned ones, minus the GPU-only ones on a host without the NVIDIA
/// runtime. Pure so the decision is pinned by a test.
pub(crate) fn recreate_set(projected: &[String], nvidia_runtime: bool) -> Vec<String> {
    projected
        .iter()
        .filter(|s| !HOST_OWNED_SERVICES.contains(&s.as_str()))
        .filter(|s| nvidia_runtime || !GPU_ONLY_SERVICES.contains(&s.as_str()))
        .cloned()
        .collect()
}

/// Does this host's Docker have the `nvidia` runtime? Same probe as
/// noomesh-start.sh. A dry run says no, so the printed plan is the CPU one.
pub(crate) fn nvidia_runtime_present(ctx: &Ctx) -> bool {
    if ctx.dry_run {
        return false;
    }
    Command::new("docker")
        .args(["info", "--format", "{{json .Runtimes}}"])
        .stdin(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("nvidia"))
        .unwrap_or(false)
}

/// Build a whole-stack recreate argument list: the core services plus every
/// enabled add-on's profile and services, in a stable order and deduplicated
/// (the core list already names `trellion`).
pub(crate) fn recreate_args(ctx: &Ctx, core: &[&str]) -> Vec<String> {
    let addon_services = addon_recreate_targets(ctx);
    // Every add-on is an overlay in `compose_files`: its
    // services are visible whenever it is on, so only the base profile is
    // selected here.
    let mut out: Vec<String> = vec!["--profile".into(), "controller".into()];
    out.extend(["up", "-d", "--no-build", "--force-recreate"].iter().map(|s| s.to_string()));
    let mut seen = std::collections::BTreeSet::new();
    for s in core.iter().map(|s| s.to_string()).chain(addon_services) {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod recreate_set_tests {
    use super::*;

    /// Services carrying `profile` in docker-compose.cluster.yml, read from
    /// the file as written (a line scan: `  name:` then `profiles: [...]`).
    /// The composed projection is the Python guard's
    /// (tests/test_monitoring_profile_parity.py); this test is about the
    /// exclusion list above, and needs only the names.
    fn compose_services_with_profile(profile: &str) -> Vec<String> {
        let path = crate::test_support::repo_file("docker-compose.cluster.yml");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} unreadable: {e}", path.display()));
        let mut current = String::new();
        let mut out = Vec::new();
        for line in body.lines() {
            if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') && !line.trim().starts_with('#') {
                current = line.trim().trim_end_matches(':').to_string();
                continue;
            }
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("profiles:") {
                let quoted = format!("\"{profile}\"");
                if rest.contains(&quoted) && !current.is_empty() {
                    out.push(current.clone());
                }
            }
        }
        out
    }

    /// The property the live controller lacked: every service the
    /// `controller` profile projects is one onboard starts, unless it is on
    /// the two documented lists — and neither list may hold a monitoring
    /// service. Planted by adding "loki" to HOST_OWNED_SERVICES.
    #[test]
    fn every_controller_profile_service_is_recreated_by_onboard() {
        let projected = compose_services_with_profile("controller");
        assert!(projected.len() >= 10, "parsed only {} controller-profile services out of the compose file — the line scan broke", projected.len());
        for must in ["loki", "prometheus", "alertmanager", "grafana", "node-exporter", "gateway", "postgres"] {
            assert!(projected.iter().any(|s| s == must), "{must} is no longer in the controller profile");
        }
        let set = recreate_set(&projected, true);
        for svc in &projected {
            if HOST_OWNED_SERVICES.contains(&svc.as_str()) {
                continue;
            }
            assert!(set.contains(svc), "{svc} carries the controller profile but onboard would not recreate it");
        }
        for svc in HOST_OWNED_SERVICES.iter().chain(GPU_ONLY_SERVICES) {
            assert!(
                !["loki", "prometheus", "alertmanager", "grafana", "node-exporter"].contains(svc),
                "{svc} is a monitoring service; it may not be excluded from what onboard recreates"
            );
        }
        assert!(!set.iter().any(|s| s == "node-agent"), "the containerised node-agent must never be named (it publishes :8081, the host agent's)");
    }

    #[test]
    fn the_gpu_exporter_is_skipped_only_without_the_runtime() {
        let projected: Vec<String> = ["gateway", "nvidia-exporter", "loki"].iter().map(|s| s.to_string()).collect();
        assert_eq!(recreate_set(&projected, false), vec!["gateway", "loki"]);
        assert_eq!(recreate_set(&projected, true), vec!["gateway", "nvidia-exporter", "loki"]);
    }
}

#[cfg(test)]
mod addon_compose_tests {
    use super::*;

    /// The shell's copy of the same decision. Runtime read, not
    /// `include_str!`: the file is outside this crate, and a crate-only build
    /// (`cargo install`) must not fail to compile over a test fixture.
    fn shell_helper() -> String {
        let path = crate::test_support::repo_file("scripts/lib-addons.sh");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("lib-addons.sh unreadable at {}: {e}", path.display()));
        let start = body
            .find("addon_compose_overlay_args() {")
            .unwrap_or_else(|| panic!("{} has no addon_compose_overlay_args — did it move?", path.display()));
        let rest = &body[start..];
        let end = rest.find("\n}").expect("unterminated addon_compose_overlay_args");
        rest[..end].to_string()
    }

    /// Two copies of one decision, pinned to each other.
    ///
    /// The Rust table drives onboard's credential recreate; the shell helper
    /// composes the overlays for the launchers. They were ONE table's worth
    /// of truth living in two places, which is the drift that cost four days
    ///  — so neither is allowed to move without the other.
    /// Since an earlier release every add-on is an overlay, so the shell side is
    /// `addon_compose_overlay_args`: one `addon_on <key> <default>` per add-on.
    #[test]
    fn the_rust_and_shell_addon_tables_agree() {
        let helper = shell_helper();
        let mut shell: Vec<(String, bool)> = Vec::new();
        for line in helper.lines() {
            let t = line.trim_start();
            if t.starts_with('#') {
                continue;
            }
            let Some(i) = t.find("addon_on ") else { continue };
            let mut it = t[i + "addon_on ".len()..].split_whitespace();
            let (Some(key), Some(default)) = (it.next(), it.next()) else { continue };
            // The licensed add-ons' generic loop (`addon_on "$_aco_n" 0`):
            // no name in core, pinned below.
            if key.contains('$') {
                continue;
            }
            shell.push((key.to_string(), default.trim_end_matches(';') == "1"));
        }
        assert!(
            helper.contains("for _aco_n in $(addon_licensed_names); do") && helper.contains("addon_on \"$_aco_n\" 0"),
            "addon_compose_overlay_args no longer composes the licensed add-ons generically (default off)"
        );
        assert!(
            !shell.is_empty(),
            "parsed ZERO add-ons out of addon_compose_overlay_args — the parse broke, and an \
             empty list would make every assertion below vacuously true"
        );
        let rust: Vec<(String, bool)> =
            ADDON_COMPOSE.iter().map(|a| (a.key.to_string(), a.default_on)).collect();
        assert_eq!(
            rust, shell,
            "the Rust ADDON_COMPOSE table and scripts/lib-addons.sh addon_compose_overlay_args \
             disagree — key, order or opt-out polarity. Change both."
        );
    }

    /// trellion is opt-OUT: an install that has never declared add-ons still
    /// recreates it. Everything else is opt-in.
    #[test]
    fn an_undeclared_install_still_reaches_trellion_only() {
        let on: Vec<&str> = ADDON_COMPOSE.iter().filter(|a| a.default_on).map(|a| a.key).collect();
        assert_eq!(on, vec!["trellion"], "only trellion may default to on");
    }

    /// Every add-on must name at least one service. A profile (or a file)
    /// with no service selects nothing to recreate — the half-fix that reads
    /// as a fix.
    #[test]
    fn every_addon_names_a_service() {
        for a in ADDON_COMPOSE {
            assert!(!a.services.is_empty(), "{} names no service", a.key);
        }
    }

    /// A licensed add-on's services come from its bundled overlay: what it
    /// adds, never a base service it patches (evolve's overlay patches the
    /// gateway; recreating "gateway" as an add-on service would be wrong).
    #[test]
    fn a_licensed_addons_services_are_what_its_overlay_adds() {
        let d = std::env::temp_dir().join(format!("noo-addon-svcs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("addons/evolve")).unwrap();
        std::fs::write(d.join("docker-compose.cluster.yml"), "services:\n  gateway: {}\n  postgres: {}\n").unwrap();
        std::fs::write(
            d.join("addons/evolve/docker-compose.yml"),
            "services:\n  gateway:\n    volumes: []\n  noo-evolve-routes: {}\n  noo-evolve: {}\n",
        )
        .unwrap();
        assert_eq!(licensed_addon_services(&d, "evolve"), ["noo-evolve-routes", "noo-evolve"]);
        assert!(licensed_addon_services(&d, "trellion_intel").is_empty(), "no overlay, no services");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod compose_files_tests {
    use super::*;
    use std::sync::Mutex;

    /// The helper reads its knobs from the environment, which is
    /// process-wide; tests that set it must not interleave.
    static ENV: Mutex<()> = Mutex::new(());

    /// A scratch install: the real lib-*.sh helpers, empty compose files, and
    /// a noomesh.yaml declaring evolve. The CLI's list must be the SHELL's
    /// list — the wizard is a sanctioned launcher, and a wizard that composes
    /// a different set of files than `noo stack start` recreates a different
    /// stack.
    struct Scratch(PathBuf);
    impl Scratch {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmpdir(tag: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("noo-compose-files-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    fn scratch(evolve: bool) -> Scratch {
        let t = tmpdir(if evolve { "evolve" } else { "plain" });
        std::fs::create_dir(t.path().join("scripts")).unwrap();
        for lib in ["lib-compose.sh", "lib-addons.sh", "lib-dist.sh"] {
            std::fs::copy(crate::test_support::repo_file(&format!("scripts/{lib}")), t.path().join("scripts").join(lib))
                .unwrap_or_else(|e| panic!("{lib}: {e}"));
        }
        for f in [
            "docker-compose.cluster.yml",
            "docker-compose.gpu-embed.yml",
            "docker-compose.override.yml",
            // evolve's overlay as its signed bundle materialises it (N6).
            "addons/evolve/docker-compose.yml",
        ] {
            let p = t.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "services: {}\n").unwrap();
        }
        // The declaration, through lib-addons' explicit override seam rather
        // than noomesh.yaml: the yaml reader needs python3-yaml, which the
        // CI container running this test need not have.
        std::env::set_var("NOO_ADDON_MAP_OVERRIDE", "1");
        std::env::set_var("NOO_ADDON_MAP", if evolve { "evolve=1" } else { "evolve=0" });
        t
    }

    fn clear_env() {
        for k in ["NOO_ADDON_MAP_OVERRIDE", "NOO_ADDON_MAP", "NOO_COMPOSE_GPU"] {
            std::env::remove_var(k);
        }
    }

    fn names(v: &[String]) -> Vec<String> {
        v.iter()
            .map(|p| Path::new(p).file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn the_cli_composes_the_shells_list_in_the_shells_order() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let t = scratch(true);
        let root = t.path();
        // NOO_COMPOSE_GPU is read by the helper's probe; force it so the test
        // does not depend on the box having nvidia-smi.
        std::env::set_var("NOO_COMPOSE_GPU", "1");
        let got = compose_files_in(
            root,
            false,
            &root.join("docker-compose.cluster.yml"),
            &root.join("docker-compose.override.yml"),
        );
        clear_env();
        assert_eq!(
            names(&got),
            [
                "docker-compose.cluster.yml",
                "docker-compose.gpu-embed.yml",
                "docker-compose.override.yml",
                "docker-compose.yml",
            ],
            "the CLI must take base → gpu → override → add-on overlays from lib-compose.sh; got {got:?}"
        );
        assert!(got[3].ends_with("/addons/evolve/docker-compose.yml"), "{got:?}");
        assert!(
            got.iter().all(|p| Path::new(p).is_absolute()),
            "paths must be absolute — compose is invoked from the wizard's cwd, not the install: {got:?}"
        );
    }

    #[test]
    fn a_root_slice_overlay_is_never_composed_without_a_bundle() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let t = scratch(true);
        let root = t.path();
        std::fs::write(root.join("docker-compose.evolve.yml"), "services: {}\n").unwrap();
        std::env::set_var("NOO_COMPOSE_GPU", "0");
        let args = (root, false, root.join("docker-compose.cluster.yml"), root.join("docker-compose.override.yml"));
        let with_bundle = compose_files_in(args.0, args.1, &args.2, &args.3);
        assert!(with_bundle.last().unwrap().ends_with("/addons/evolve/docker-compose.yml"), "{with_bundle:?}");
        std::fs::remove_dir_all(root.join("addons")).unwrap();
        let without = compose_files_in(args.0, args.1, &args.2, &args.3);
        clear_env();
        assert_eq!(names(&without), ["docker-compose.cluster.yml", "docker-compose.override.yml"], "{without:?}");
    }

    #[test]
    fn an_undeclared_addon_is_not_composed() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let t = scratch(false);
        let root = t.path();
        std::env::set_var("NOO_COMPOSE_GPU", "0");
        let got = compose_files_in(
            root,
            false,
            &root.join("docker-compose.cluster.yml"),
            &root.join("docker-compose.override.yml"),
        );
        clear_env();
        assert_eq!(names(&got), ["docker-compose.cluster.yml", "docker-compose.override.yml"]);
    }

    #[test]
    fn a_tree_without_the_helper_falls_back_to_base_and_override() {
        let t = tmpdir("bare");
        let root = t.path();
        std::fs::write(root.join("docker-compose.cluster.yml"), "").unwrap();
        let got = compose_files_in(
            root,
            false,
            &root.join("docker-compose.cluster.yml"),
            &root.join("docker-compose.override.yml"),
        );
        assert_eq!(names(&got), ["docker-compose.cluster.yml"], "no override on disk → base only");
    }
}

#[cfg(test)]
mod bind_sources_tests {
    use super::*;

    #[test]
    fn an_up_argv_renders_its_own_config_and_names_its_services() {
        let (render, svcs, no_deps) =
            up_selection(&["--profile", "controller", "up", "-d", "--no-build", "--force-recreate", "gateway", "trellion"]).unwrap();
        assert_eq!(render, ["--profile", "controller", "config", "--format", "json"]);
        assert_eq!(svcs, ["gateway", "trellion"]);
        assert!(!no_deps);
        let (_, svcs, no_deps) = up_selection(&["up", "-d", "--no-deps", "--scale", "x=0", "postgres"]).unwrap();
        assert_eq!(svcs, ["postgres"]);
        assert!(no_deps);
        // Not an `up`: no check (config/ps/pull never create a bind source).
        assert!(up_selection(&["--profile", "controller", "config", "--services"]).is_none());
    }
}

#[cfg(test)]
mod file_secret_env_tests {
    use super::*;

    const COMPOSE: &str = "services: {}\nsecrets:\n  noo_jwt_secret:\n    environment: NOO_JWT_SECRET\n  postgres_password:\n    environment: POSTGRES_PASSWORD\n  pgpass_gateway:\n    environment: NOO_PGPASS_GATEWAY\n  redis_password:\n    environment: REDIS_PASSWORD\n";

    #[test]
    fn sources_come_from_the_top_level_secrets_block() {
        assert_eq!(
            file_secret_sources(COMPOSE),
            vec!["NOO_JWT_SECRET", "POSTGRES_PASSWORD", "NOO_PGPASS_GATEWAY", "REDIS_PASSWORD"]
        );
        assert!(file_secret_sources("services: {}\n").is_empty());
    }

    /// The SAME inputs and expected bytes as
    /// tests/test_compose_secret_files.py::test_launcher_derives_pgpass_bodies,
    /// which runs lib-secrets.sh — the two derivations must agree byte for byte.
    #[test]
    fn pgpass_bodies_escape_per_driver_and_skip_empty() {
        let env = |k: &str| match k {
            "POSTGRES_PASSWORD" => Some("superpw".to_string()),
            _ => None,
        };
        let dotenv = "NOO_APP_DB_PASSWORD=\"app:pw\\x\"\nREDIS_PASSWORD=r1\n";
        let out: std::collections::BTreeMap<String, String> =
            file_secret_env(&[COMPOSE], &env, dotenv).into_iter().collect();
        // sqlx body: the password verbatim; libpq body: `\` and `:` escaped.
        assert_eq!(out["NOO_PGPASS_GATEWAY"], "postgres:5432:noomesh:noo:superpw\npostgres:5432:noomesh:noo_app:app:pw\\x");
        assert_eq!(out["NOO_PGPASS_WORKER"], "postgres:5432:noomesh:noo_app:app\\:pw\\\\x");
        // unset everywhere → exported empty so compose creates the service
        assert_eq!(out.get("NOO_JWT_SECRET").map(String::as_str), Some(""));
        // set in the process or in .env → left alone for compose to read
        assert!(!out.contains_key("POSTGRES_PASSWORD"));
        assert!(!out.contains_key("REDIS_PASSWORD"));
        // no role password anywhere → an empty body (no file, no pointer)
        let none = file_secret_env(&[COMPOSE], &|_| None, "");
        assert!(none.iter().any(|(k, v)| k == "NOO_PGPASS_WORKER" && v.is_empty()));
    }

    /// The add-on bodies are libpq (psycopg) and carry
    /// one line per role their DSNs log in as; an add-on overlay's own
    /// top-level source (its gateway key) is exported empty like the base's.
    #[test]
    fn add_on_pgpass_bodies_and_overlay_sources() {
        let env = |k: &str| match k {
            "NOO_APP_DB_PASSWORD" => Some("a".to_string()),
            "NOO_TRELLION_DB_PASSWORD" => Some("t:1".to_string()),
            "NOO_TRELLION_DDL_PASSWORD" => Some("d\\2".to_string()),
            "NOO_EVOLVE_DB_PASSWORD" => Some("e".to_string()),
            _ => None,
        };
        let overlay = "secrets:\n  noo_svc_key_trellion:\n    environment: NOO_SVC_KEY_TRELLION\n";
        let out: std::collections::BTreeMap<String, String> =
            file_secret_env(&[COMPOSE, overlay], &env, "").into_iter().collect();
        assert_eq!(
            out["NOO_PGPASS_TRELLION"],
            "postgres:5432:noomesh:noo_app:a\npostgres:5432:noomesh:noo_trellion:t\\:1\npostgres:5432:noomesh:noo_trellion_ddl:d\\\\2"
        );
        // the DDL password is unset: its line is skipped, not written empty
        assert_eq!(out["NOO_PGPASS_EVOLVE"], "postgres:5432:noomesh:noo_evolve:e");
        assert_eq!(out.get("NOO_SVC_KEY_TRELLION").map(String::as_str), Some(""));
    }

    #[test]
    fn overlays_beside_the_base_are_read_too() {
        let dir = std::env::temp_dir().join(format!("noo-sh-beside-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("docker-compose.cluster.yml"), COMPOSE).unwrap();
        std::fs::write(dir.join("docker-compose.evolve.yml"), "secrets:\n  k:\n    environment: NOO_SVC_KEY_EVOLVE\n").unwrap();
        std::fs::write(dir.join("unrelated.yml"), "secrets:\n  x:\n    environment: NOT_ME\n").unwrap();
        std::fs::create_dir_all(dir.join("addons/trellion_intel")).unwrap();
        std::fs::write(dir.join("addons/trellion_intel/docker-compose.yml"), "secrets:\n  k:\n    environment: NOO_SVC_KEY_TRELLION_INTEL\n").unwrap();
        let texts = compose_texts_beside(&dir.join("docker-compose.cluster.yml"));
        let srcs: Vec<String> = texts.iter().flat_map(|t| file_secret_sources(t)).collect();
        std::fs::remove_dir_all(&dir).ok();
        assert!(srcs.iter().any(|s| s == "NOO_SVC_KEY_EVOLVE"), "{srcs:?}");
        assert!(srcs.iter().any(|s| s == "NOO_SVC_KEY_TRELLION_INTEL"), "a bundled overlay was not read: {srcs:?}");
        assert!(srcs.iter().any(|s| s == "NOO_JWT_SECRET"), "{srcs:?}");
        assert!(!srcs.iter().any(|s| s == "NOT_ME"), "{srcs:?}");
        assert_eq!(srcs.iter().filter(|s| *s == "NOO_JWT_SECRET").count(), 1, "the base is read once: {srcs:?}");
    }

    #[test]
    fn the_shipped_compose_sources_every_pgpass_variable() {
        let srcs: Vec<String> = [
            include_str!("../../../docker-compose.cluster.yml"),
            include_str!("../../../docker-compose.trellion.yml"),
        ]
        .iter()
        .flat_map(|c| file_secret_sources(c))
        .collect();
        assert!(srcs.len() >= 20, "{srcs:?}");
        for (var, _, _) in PGPASS_ROLES {
            // evolve's overlay (which sources it) travels in evolve's bundle.
            if *var == "NOO_PGPASS_EVOLVE" {
                continue;
            }
            assert!(srcs.iter().any(|s| s == var), "{var} is derived but no compose secret uses it");
        }
    }
}

#[cfg(test)]
mod compose_summary_tests {
    use super::*;

    /// A realistic `docker compose up -d --force-recreate` transcript (plain
    /// progress, as compose prints when stdout is not a terminal).
    const HAPPY: &str = " Network noomesh_default  Creating
 Network noomesh_default  Created
 Volume noomesh_noo-data  Creating
 Volume noomesh_noo-data  Created
 Container noo-postgres  Recreate
 Container noo-postgres  Recreated
 Container noo-nats  Recreate
 Container noo-nats  Recreated
 Container noo-postgres  Starting
 Container noo-postgres  Started
 Container noo-nats  Starting
 Container noo-nats  Started
 Container noo-gateway  Waiting
 Container noo-postgres  Waiting
 Container noo-postgres  Healthy
 Container noo-nats  Healthy
 Container noo-gateway  Recreated
 Container noo-gateway  Starting
 Container noo-gateway  Started
 Container noo-gateway  Healthy";

    fn lines(t: &str) -> Vec<&str> {
        t.lines().collect()
    }

    #[test]
    fn a_clean_transcript_is_one_summary_line_and_no_passthrough() {
        let (summary, pass) = summarise_compose(&lines(HAPPY));
        assert_eq!(summary, "3 containers: 3 started, 0 failed");
        assert!(pass.is_empty(), "progress must be absorbed: {pass:?}");
    }

    #[test]
    fn an_error_and_an_unhealthy_container_are_counted_and_passed_through() {
        let t = format!(
            "{HAPPY}\n Container noo-redis  Starting\nError response from daemon: driver failed programming external connectivity on endpoint noo-redis\n Container noo-redis  Error\ndependency failed to start: container noo-redis is unhealthy"
        );
        let (summary, pass) = summarise_compose(&lines(&t));
        assert_eq!(summary, "4 containers: 3 started, 1 failed (noo-redis)");
        assert_eq!(
            pass,
            vec![
                "Error response from daemon: driver failed programming external connectivity on endpoint noo-redis".to_string(),
                " Container noo-redis  Error".to_string(),
                "dependency failed to start: container noo-redis is unhealthy".to_string(),
            ]
        );
    }

    #[test]
    fn a_one_shot_that_exited_cleanly_is_not_a_failure() {
        let t = format!("{HAPPY}\n Container noo-evolve-routes  Starting\n Container noo-evolve-routes  Exited");
        let (summary, pass) = summarise_compose(&lines(&t));
        assert_eq!(summary, "4 containers: 4 started, 0 failed");
        assert!(pass.is_empty(), "progress must be absorbed: {pass:?}");
    }

    #[test]
    fn a_real_failure_is_counted_and_named_beside_a_clean_one_shot() {
        let t = format!(
            "{HAPPY}\n Container noo-evolve-routes  Exited\n Container noo-worker  Exited (1)\n Container noo-redis  Error"
        );
        let (summary, _pass) = summarise_compose(&lines(&t));
        assert_eq!(summary, "6 containers: 4 started, 2 failed (noo-redis, noo-worker)");
    }

    #[test]
    fn unknown_lines_are_passed_through_not_dropped() {
        let t = "==> pulling images\n Container noo-nats  Started\nsome new compose message we have never seen\n";
        let (summary, pass) = summarise_compose(&lines(t));
        assert_eq!(summary, "1 container: 1 started, 0 failed");
        assert_eq!(pass, vec!["==> pulling images".to_string(), "some new compose message we have never seen".to_string()]);
    }

    #[test]
    fn a_transcript_with_no_container_lines_has_no_summary() {
        let (summary, pass) = summarise_compose(&["hello"]);
        assert_eq!(summary, "");
        assert_eq!(pass, vec!["hello".to_string()]);
    }
}
