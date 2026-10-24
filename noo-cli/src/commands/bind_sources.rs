// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Bind-mount sources must exist, and be the right type, BEFORE `compose up`.
//!
//! When a service bind-mounts a host path that does not exist, Docker does
//! not refuse: it CREATES it — as an empty, root-owned DIRECTORY, even when
//! the container expects a file. The container then dies far from the cause
//! (stack-v0.2.78 roll on host8, 2026-09-29: grafana crash-looped on
//! `read /app/pki/sso/grafana.pub: is a directory`, because an upgraded
//! install never got the SSO key pair; a root-owned empty
//! `pki/services/model-cache` left by an earlier start made the CLI's cert
//! reconcile hit EACCES). The ghost directory also survives: every later
//! start mounts it again, and the tool that would write the real file now
//! finds a root-owned directory in its way.
//!
//! Compose's own answer (`bind: create_host_path: false`, long syntax only)
//! refuses per CONTAINER, in the middle of `up` — with `--force-recreate`
//! the containers before it are already recreated — and it says nothing
//! about a ghost directory that already exists where a file belongs. So the
//! launchers ask this module first, over the EFFECTIVE compose config
//! (`docker compose <same -f files> <same profiles> config --format json`),
//! and refuse the whole start with one line per offending source.
//!
//! ONE implementation, two callers: the shell launchers reach it through the
//! hidden `noo config launch-check bind-sources` (via
//! `scripts/lib-bind-sources.sh`), and the onboard wizard's own compose
//! wrapper (`onboard::sh::run_compose`) calls [`check`] directly.
//!
//! The same pass refuses a bind-mounted NATS `users.conf` that names an
//! environment variable its service is not handed. That is
//! the OTHER half of the stack-v0.2.78 roll: the compose stopped handing
//! nats `NATS_USER`/`NATS_PASSWORD` while the users.conf on disk — rendered
//! by an older CLI — still said `user: $NATS_USER`, and NATS refused to
//! parse it and took the bus down. A mounted file the container cannot
//! read correctly is a bind source that breaks the start, so it is refused
//! here, before `up`, naming `noo cluster nats-users render`.
//!
//! Nothing here creates anything. Fail loud, name the path, give the fix.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// Exit code of `noo config launch-check bind-sources` when it refuses.
/// Distinct from 1 (generic failure) and 2 (usage / an older `noo` that
/// does not know the subcommand), so the shell can tell "the check said no"
/// from "the check could not run".
pub const EXIT_REFUSED: i32 = 3;

/// Extensions that make a mount path a FILE. A target like
/// `/etc/nginx/conf.d` or `/tls/services/nats` has no listed extension and
/// is treated as a directory — only a positive signal says "file".
const FILE_EXTS: &[&str] = &[
    "pub", "crt", "key", "pem", "csr", "conf", "cnf", "cfg", "yml", "yaml", "json", "ini", "sh", "toml",
    "txt", "env", "html", "js", "py", "lua", "sql",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The source path does not exist; Docker would create a directory.
    Missing { expects_file: bool },
    /// The source is a directory but the mount is a file (the ghost of an
    /// earlier start). `empty` decides the remedy (`rmdir` vs. inspect).
    DirWhereFile { empty: bool },
    /// A device-bound NAMED volume's device is a file where a directory is
    /// expected (`driver_opts: {type: none, o: bind, device: …}`).
    FileWhereDir,
    /// A NATS `users.conf` that names `$<var>`, which the service is not
    /// handed — NATS refuses to parse it ("variable reference for '<var>'
    /// can not be found") and the bus does not start.
    UnresolvedVar { var: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub service: String,
    pub source: String,
    pub target: String,
    pub problem: Problem,
    pub remedy: String,
}

impl Finding {
    /// One line: service, target <- source, what is wrong, the fix.
    pub fn line(&self) -> String {
        let what = match &self.problem {
            Problem::Missing { expects_file: true } => "missing (a file is expected; Docker would create an empty directory)".to_string(),
            Problem::Missing { expects_file: false } => "missing (Docker would create it root-owned)".to_string(),
            Problem::DirWhereFile { empty: true } => "is an EMPTY DIRECTORY where a file is expected (left by an earlier start)".to_string(),
            Problem::DirWhereFile { empty: false } => "is a DIRECTORY where a file is expected".to_string(),
            Problem::FileWhereDir => "is a FILE where a directory is expected (a named volume's device)".to_string(),
            Problem::UnresolvedVar { var } => format!(
                "names ${var}, which the {} service is not handed — NATS refuses to parse it and the bus does not start",
                self.service
            ),
        };
        format!("  {}: {} <- {}: {} — fix: {}", self.service, self.target, self.source, what, self.remedy)
    }
}

fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

/// Does this path name a file? Only a listed extension says yes.
fn looks_like_file(p: &str) -> bool {
    let b = basename(p);
    match b.rfind('.') {
        // A leading dot alone (".noo-host-spool") is a hidden name, not an extension.
        Some(i) if i > 0 => FILE_EXTS.contains(&b[i + 1..].to_ascii_lowercase().as_str()),
        _ => false,
    }
}

fn under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    !root.is_empty() && (path == root || path.starts_with(&format!("{root}/")))
}

/// What produces this source — the command an operator runs, never a
/// generic "create it". `data_root` is NOO_DATA_ROOT as the launcher sees it.
fn produce(source: &str, expects_file: bool, data_root: Option<&str>) -> String {
    // First: under the placeholder, every PKI path has the same cause.
    if source.contains("/.pki-placeholder") {
        return "NOO_PKI_DIR is not set, so the stack has no PKI — run: noo onboard --only enrollment".into();
    }
    // The gateway's certificate-only view: an install
    // upgraded by an older `noo` has never had `public/`. The current CLI
    // lays it down (fix-modes, and `upgrade --stack` before it launches).
    if source.contains("/pki/public/") || source.ends_with("/pki/public") {
        return "noo security pki fix-modes (lays down pki/public/, the gateway's certificate-only view; noo upgrade --stack does the same)".into();
    }
    if source.contains("/sso/") || source.ends_with("/pki/sso") {
        return "noo security pki issue-sso-key".into();
    }
    if let Some(i) = source.find("/pki/services/") {
        let leaf = source[i + "/pki/services/".len()..].split('/').next().unwrap_or("");
        if !leaf.is_empty() {
            return format!("noo security pki issue-service {leaf}");
        }
    }
    if source.contains("/pki/") || source.ends_with("/pki") {
        return "noo onboard --only enrollment (mints the CA and the gateway leaf)".into();
    }
    // The host executor's spool. noo-hostd's unit is installed here, so the
    // spool is its (it makes it as the same user); every other case
    // (no systemd, or systemd but no hostd unit) has the launcher create it
    // before this check runs, so reaching this means that failed.
    if basename(source) == ".noo-host-spool" {
        return format!(
            "noo-hostd's unit is installed here and its spool is missing: noo onboard --only services reinstalls hostd, which recreates it (every start without hostd creates it as you, so if this names a box without hostd, that failed: mkdir -p '{source}' (as you))"
        );
    }
    // Onboard's storage step creates exactly [`directory_sources_under`]
    // (one derivation, one reader of the composed config): directories under
    // the data root. A FILE under the root is not its to make.
    if let Some(root) = data_root {
        if under(source, root) && !expects_file {
            return "noo onboard --only storage (creates the data directories as you, not root)".into();
        }
    }
    if expects_file {
        format!(
            "restore {} (a standalone install: noo upgrade --stack re-lays the files the stack ships)",
            basename(source)
        )
    } else {
        let outside = match data_root {
            Some(root) if !under(source, root) => {
                format!("; it is outside NOO_DATA_ROOT ({root}), so `noo onboard --only storage` does not create it")
            }
            _ => String::new(),
        };
        format!("mkdir -p '{source}' (as you — the directory Docker would make is root-owned){outside}")
    }
}

/// The host DIRECTORIES under `data_root` that the composed config bind-mounts:
/// the set onboard's storage step creates (ONE derivation — the step and the
/// preflight read the same projection, so a mount added to compose cannot be
/// refused at `up` yet missed by step 6; `images`/`bin` were).
/// Excluded, because something else owns them: file mounts, `pki/` (the
/// enrollment step) and the root itself. Every service is read, whatever its
/// profile — the caller renders the config for the profile it will start.
pub fn directory_sources_under(cfg: &Value, data_root: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let root_trim = data_root.trim_end_matches('/');
    // Device-bound named volumes (postgres-data, redis-data, …) are directories
    // under the root just like bind sources; the preflight checks them too.
    for dev in cfg.get("volumes").and_then(Value::as_object).into_iter().flat_map(|m| m.values()).filter_map(device_bound) {
        let dev = dev.trim_end_matches('/');
        if under(dev, data_root) && dev != root_trim {
            out.insert(dev.to_string());
        }
    }
    let Some(services) = cfg.get("services").and_then(Value::as_object) else { return out };
    for svc in services.values() {
        for v in svc.get("volumes").and_then(Value::as_array).into_iter().flatten() {
            if v.get("type").and_then(Value::as_str) != Some("bind") {
                continue;
            }
            let (Some(source), Some(target)) =
                (v.get("source").and_then(Value::as_str), v.get("target").and_then(Value::as_str))
            else {
                continue;
            };
            let source = source.trim_end_matches('/');
            if !under(source, data_root) || source == data_root.trim_end_matches('/') {
                continue;
            }
            if looks_like_file(source) || looks_like_file(target) || source.contains("/pki/") || source.ends_with("/pki") {
                continue;
            }
            out.insert(source.to_string());
        }
    }
    out
}

fn remedy(source: &str, problem: &Problem, data_root: Option<&str>) -> String {
    match problem {
        Problem::Missing { expects_file } => produce(source, *expects_file, data_root),
        Problem::UnresolvedVar { .. } => "noo cluster nats-users render (re-renders users.conf from the store; \
             the retired shared user is never rendered, and every per-principal password is reused, none \
             re-minted), then start again"
            .into(),
        Problem::FileWhereDir => {
            format!("move it aside (sudo mv '{source}' '{source}.file'), then {}", produce(source, false, data_root))
        }
        Problem::DirWhereFile { empty } => {
            let clear = if *empty {
                format!("sudo rmdir '{source}'")
            } else {
                format!("look inside '{source}', move it aside (sudo mv '{source}' '{source}.ghost')")
            };
            format!("{clear}, then {}", produce(source, true, data_root))
        }
    }
}

/// The service set to check: the named ones plus everything they
/// `depends_on` (compose starts those too) unless `no_deps`; every service
/// in the config when none are named.
fn selected(cfg: &Value, services: &[String], no_deps: bool) -> BTreeSet<String> {
    let all = cfg.get("services").and_then(Value::as_object);
    let Some(all) = all else { return BTreeSet::new() };
    if services.is_empty() {
        return all.keys().cloned().collect();
    }
    let mut out = BTreeSet::new();
    let mut stack: Vec<String> = services.iter().filter(|s| all.contains_key(s.as_str())).cloned().collect();
    while let Some(s) = stack.pop() {
        if !out.insert(s.clone()) || no_deps {
            continue;
        }
        if let Some(deps) = all.get(&s).and_then(|v| v.get("depends_on")) {
            let names: Vec<String> = match deps {
                Value::Object(m) => m.keys().cloned().collect(),
                Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                _ => vec![],
            };
            stack.extend(names.into_iter().filter(|n| all.contains_key(n.as_str())));
        }
    }
    out
}

/// The host path of a device-bound named volume (`driver_opts: {type: none,
/// o: bind, device: <path>}`), or None for any other volume. Compose creates
/// no such directory and the daemon refuses the mount when it is absent
/// ("failed to mount local volume") — the postgres-data case.
fn device_bound(vol: &Value) -> Option<&str> {
    let opts = vol.get("driver_opts")?;
    let o = opts.get("o").and_then(Value::as_str)?;
    (opts.get("type").and_then(Value::as_str) == Some("none") && o.split(',').any(|f| f.trim() == "bind"))
        .then(|| opts.get("device").and_then(Value::as_str))
        .flatten()
        .filter(|d| d.starts_with('/'))
}

/// Check every `type: bind` volume of the selected services in a rendered
/// compose config (`docker compose … config --format json`). Named volumes,
/// tmpfs and anything that is not a bind are ignored.
pub fn check(cfg: &Value, services: &[String], no_deps: bool, data_root: Option<&str>) -> Vec<Finding> {
    check_except(cfg, services, no_deps, &[], data_root)
}

/// [`check`], leaving out `skip` — the services the caller scales to zero
/// (`--scale node-agent=0`), which `up` will not start.
pub fn check_except(
    cfg: &Value,
    services: &[String],
    no_deps: bool,
    skip: &[String],
    data_root: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let data_root = data_root.filter(|d| !d.is_empty());
    for svc in selected(cfg, services, no_deps).into_iter().filter(|s| !skip.contains(s)) {
        let vols = cfg["services"][&svc]["volumes"].as_array().cloned().unwrap_or_default();
        for v in vols {
            // A named volume bound to a host device: the same existence and
            // type rule as a bind of a directory.
            if v.get("type").and_then(Value::as_str) == Some("volume") {
                let (Some(name), Some(target)) =
                    (v.get("source").and_then(Value::as_str), v.get("target").and_then(Value::as_str))
                else {
                    continue;
                };
                let Some(device) = cfg.get("volumes").and_then(|m| m.get(name)).and_then(device_bound) else {
                    continue;
                };
                let problem = match std::fs::metadata(Path::new(device)) {
                    Ok(m) if m.is_file() => Some(Problem::FileWhereDir),
                    Ok(_) => None,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Problem::Missing { expects_file: false }),
                    Err(_) => None,
                };
                if let Some(problem) = problem {
                    let remedy = remedy(device, &problem, data_root);
                    findings.push(Finding {
                        service: svc.clone(),
                        source: device.to_string(),
                        target: format!("{target} (volume {name})"),
                        problem,
                        remedy,
                    });
                }
                continue;
            }
            if v.get("type").and_then(Value::as_str) != Some("bind") {
                continue;
            }
            let (Some(source), Some(target)) =
                (v.get("source").and_then(Value::as_str), v.get("target").and_then(Value::as_str))
            else {
                continue;
            };
            let expects_file = looks_like_file(target) || looks_like_file(source);
            let problem = match std::fs::metadata(Path::new(source)) {
                Ok(m) if m.is_dir() && expects_file => {
                    let empty = std::fs::read_dir(source).map(|mut d| d.next().is_none()).unwrap_or(false);
                    Some(Problem::DirWhereFile { empty })
                }
                Ok(_) => None,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Problem::Missing { expects_file }),
                // Cannot stat it as this user (a parent we cannot traverse):
                // the daemon, as root, may well see it. Not ours to refuse.
                Err(_) => None,
            };
            if let Some(problem) = problem {
                let remedy = remedy(source, &problem, data_root);
                findings.push(Finding {
                    service: svc.clone(),
                    source: source.to_string(),
                    target: target.to_string(),
                    problem,
                    remedy,
                });
                continue;
            }
            for var in unresolved_nats_vars(&cfg["services"][&svc], source, target) {
                let problem = Problem::UnresolvedVar { var };
                let remedy = remedy(source, &problem, data_root);
                findings.push(Finding {
                    service: svc.clone(),
                    source: source.to_string(),
                    target: target.to_string(),
                    problem,
                    remedy,
                });
            }
        }
    }
    findings
}

/// The `$VAR`s a bind-mounted NATS `users.conf` names that `service` is not
/// handed in its `environment`. Empty for any other mount, or when the file
/// cannot be read as this user (the daemon may well see it — not ours to
/// refuse). Compose renders `environment` as a map; the list form is read
/// too, so a hand-built config cannot slip past on shape.
fn unresolved_nats_vars(service: &Value, source: &str, target: &str) -> Vec<String> {
    if basename(target) != "users.conf" {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(source) else { return Vec::new() };
    let refs = crate::commands::nats_users::env_refs_in_conf(&text);
    if refs.is_empty() {
        return refs;
    }
    let handed: BTreeSet<String> = match service.get("environment") {
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|e| e.split('=').next().unwrap_or(e).to_string())
            .collect(),
        _ => BTreeSet::new(),
    };
    refs.into_iter().filter(|v| !handed.contains(v)).collect()
}

/// This host runs systemd, so `noo onboard --only services` can install
/// noo-hostd (which owns the host spool).
pub fn systemd_present() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// noo-hostd's unit is installed on this host: controller mode writes a
/// user unit, `--system` a system one (node-agent-go/internal/hostd/install.go).
/// Only then is the controller spool hostd's to make.
pub fn hostd_unit_present() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    (!home.is_empty() && Path::new(&home).join(".config/systemd/user/noo-hostd.service").is_file())
        || Path::new("/etc/systemd/system/noo-hostd.service").is_file()
}

/// Who makes the controller's host spool: hostd, when it is installed (its
/// unit exists; it needs systemd to run), else the launcher. i251: with
/// systemd present but hostd not installed (`noo onboard --ci` could not
/// install it before, and still cannot without passwordless sudo) the old
/// rule "systemd => hostd's" refused every start. The spool is the user's
/// own directory either way — controller-mode hostd is a USER unit that
/// runs as the same uid — so the launcher making it hands nothing to root;
/// the root-consumed spool is the worker's, elsewhere, and not bind-mounted
/// here. Pure, so the rule is pinned.
pub fn hostd_owns_spool(systemd: bool, hostd_unit: bool) -> bool {
    systemd && hostd_unit
}

/// When no hostd is installed to create the host executor's spool, Docker
/// would create the bind source root-owned. Create each MISSING
/// `.noo-host-spool` bind source here, as the invoking user, and return what
/// was created. A no-op when hostd owns it ([`hostd_owns_spool`]) and for
/// every other source (those keep their refusal).
pub fn ensure_hostd_spool(cfg: &Value, services: &[String], no_deps: bool, hostd_owns: bool) -> Vec<String> {
    let mut made = Vec::new();
    if hostd_owns {
        return made;
    }
    for svc in selected(cfg, services, no_deps) {
        let vols = cfg["services"][&svc]["volumes"].as_array().cloned().unwrap_or_default();
        for v in vols {
            if v.get("type").and_then(Value::as_str) != Some("bind") {
                continue;
            }
            let Some(source) = v.get("source").and_then(Value::as_str) else { continue };
            let source = source.trim_end_matches('/');
            if basename(source) != ".noo-host-spool" || Path::new(source).exists() || made.iter().any(|m| m == source) {
                continue;
            }
            if std::fs::create_dir_all(source).is_ok() {
                made.push(source.to_string());
            }
        }
    }
    made
}

/// Bind sources the LAUNCHER owns and fills: the add-on bundle declaration
/// directories the gateway mounts read-only (i163 E/B: `lib-addons.sh`
/// `addon_decls_materialise` copies `<addon>/system.json` and
/// `<addon>/workloads.json` into them). Empty is their normal state, so a
/// missing one is created here, as the invoking user, rather than refused
/// (Docker would create it root-owned and the launcher could not fill it).
pub const LAUNCHER_DIRS: &[&str] = &[".noo-addon-systems", ".noo-addon-workloads"];

/// Create each MISSING bind source named in [`LAUNCHER_DIRS`] for the
/// selected services, as the invoking user; return what was created.
pub fn ensure_launcher_dirs(cfg: &Value, services: &[String], no_deps: bool) -> Vec<String> {
    let mut made = Vec::new();
    for svc in selected(cfg, services, no_deps) {
        let vols = cfg["services"][&svc]["volumes"].as_array().cloned().unwrap_or_default();
        for v in vols {
            if v.get("type").and_then(Value::as_str) != Some("bind") {
                continue;
            }
            let Some(source) = v.get("source").and_then(Value::as_str) else { continue };
            let source = source.trim_end_matches('/');
            if !LAUNCHER_DIRS.contains(&basename(source)) || Path::new(source).exists() || made.iter().any(|m| m == source) {
                continue;
            }
            if std::fs::create_dir_all(source).is_ok() {
                made.push(source.to_string());
            }
        }
    }
    made
}

/// The refusal text, header to footer. Empty when there is nothing to refuse.
pub fn refusal(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut s = format!(
        "REFUSED: {} bind-mount source(s) would break this start (missing or the wrong type — Docker would invent a root-owned directory — or a config naming a variable its service is not handed):\n",
        findings.len()
    );
    for f in findings {
        s.push_str(&f.line());
        s.push('\n');
    }
    s.push_str("Nothing was started or recreated; the running stack is untouched. Fix the lines above and start again.\n");
    s
}

/// `noo config launch-check bind-sources [--data-root DIR] [--no-deps] [--skip SVC]… [SERVICE…]`
/// with the rendered compose config on stdin. 0 = every source is fine,
/// [`EXIT_REFUSED`] = findings printed to stderr, 65 = stdin is not a
/// compose config.
pub fn run(args: &[String]) -> Result<i32, ()> {
    let mut data_root: Option<String> = None;
    let mut no_deps = false;
    let mut skip = Vec::new();
    let mut services = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--data-root" => data_root = Some(it.next().ok_or(())?.clone()),
            "--no-deps" => no_deps = true,
            "--skip" => skip.push(it.next().ok_or(())?.clone()),
            s if s.starts_with('-') => return Err(()),
            s => services.push(s.to_string()),
        }
    }
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        eprintln!("noo config launch-check bind-sources: could not read the compose config from stdin");
        return Ok(65);
    }
    let cfg: Value = match serde_json::from_str(&input) {
        Ok(v @ Value::Object(_)) if v.get("services").is_some() => v,
        _ => {
            eprintln!("noo config launch-check bind-sources: stdin is not `docker compose config --format json` output");
            return Ok(65);
        }
    };
    let (code, text) = launch_check(&cfg, &services, no_deps, &skip, data_root.as_deref(), systemd_present(), hostd_unit_present());
    eprint!("{text}");
    Ok(code)
}

/// The launch check over a parsed config: exit code and what to print.
/// When no hostd is installed to make the host spool (no systemd: i76c, the
/// dist launcher in dind; systemd but no hostd unit: i251, `--ci` on a real
/// box) it is created here first, as the user.
fn launch_check(
    cfg: &Value,
    services: &[String],
    no_deps: bool,
    skip: &[String],
    data_root: Option<&str>,
    systemd: bool,
    hostd_unit: bool,
) -> (i32, String) {
    let mut text = String::new();
    let why = if systemd {
        "noo-hostd is not installed here; host commands wait until: noo onboard --only services"
    } else {
        "no systemd, so no noo-hostd to own it"
    };
    for made in ensure_hostd_spool(cfg, services, no_deps, hostd_owns_spool(systemd, hostd_unit)) {
        text.push_str(&format!("created the host executor spool {made} ({why})\n"));
    }
    for made in ensure_launcher_dirs(cfg, services, no_deps) {
        text.push_str(&format!("created {made} (the add-on declarations directory; the launcher fills it)\n"));
    }
    let findings = check_except(cfg, services, no_deps, skip, data_root);
    if findings.is_empty() {
        return (0, text);
    }
    text.push_str(&refusal(&findings));
    (EXIT_REFUSED, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn the_addon_declaration_dirs_are_created_as_the_user_not_refused() {
        let d = scratch("launcher-dirs");
        let sys = d.join(".noo-addon-systems");
        let wl = d.join(".noo-addon-workloads");
        let other = d.join("not-ours");
        let cfg = json!({"services": {"gateway": {"volumes": [
            {"type": "bind", "source": sys.display().to_string(), "target": "/opt/noo/addon-systems", "read_only": true},
            {"type": "bind", "source": wl.display().to_string(), "target": "/opt/noo/addon-workloads", "read_only": true},
            {"type": "bind", "source": other.display().to_string(), "target": "/x"},
        ]}}});
        let made = ensure_launcher_dirs(&cfg, &[], false);
        assert_eq!(made.len(), 2, "{made:?}");
        assert!(sys.is_dir() && wl.is_dir());
        assert!(!other.exists(), "only the launcher's own directories are created");
        assert!(ensure_launcher_dirs(&cfg, &[], false).is_empty(), "idempotent");
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-bind-sources-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The shape `docker compose config --format json` renders (short
    /// syntax comes back as `type: bind` with an empty `bind: {}`).
    fn cfg(dir: &Path) -> Value {
        let p = |s: &str| dir.join(s).to_string_lossy().into_owned();
        json!({
            "name": "t",
            "services": {
                "grafana": {
                    "volumes": [
                        {"type": "bind", "source": p("pki/sso/grafana.pub"), "target": "/app/pki/sso/grafana.pub", "read_only": true, "bind": {}},
                        {"type": "bind", "source": p("configs/grafana.ini"), "target": "/etc/grafana/grafana.ini", "bind": {}},
                        {"type": "volume", "source": "grafana-data", "target": "/var/lib/grafana", "volume": {}}
                    ]
                },
                "model-cache": {
                    "depends_on": {"grafana": {"condition": "service_started"}},
                    "volumes": [
                        {"type": "bind", "source": p("pki/services/model-cache"), "target": "/tls/services/model-cache", "bind": {}}
                    ]
                },
                "other": {"volumes": [{"type": "bind", "source": p("nope.conf"), "target": "/etc/x.conf", "bind": {}}]}
            }
        })
    }

    fn all_present(dir: &Path) {
        std::fs::create_dir_all(dir.join("pki/sso")).unwrap();
        std::fs::create_dir_all(dir.join("configs")).unwrap();
        std::fs::create_dir_all(dir.join("pki/services/model-cache")).unwrap();
        std::fs::write(dir.join("pki/sso/grafana.pub"), "k").unwrap();
        std::fs::write(dir.join("configs/grafana.ini"), "x").unwrap();
        std::fs::write(dir.join("nope.conf"), "x").unwrap();
    }

    #[test]
    fn all_present_passes_and_named_volume_is_ignored() {
        let d = scratch("ok");
        all_present(&d);
        // `grafana-data` is a named volume whose "source" is no path at all:
        // were it checked, this would be a finding.
        assert_eq!(check(&cfg(&d), &[], false, None), vec![]);
        assert_eq!(refusal(&[]), "");
    }

    #[test]
    fn missing_file_source_is_refused_naming_it() {
        let d = scratch("missing");
        all_present(&d);
        std::fs::remove_file(d.join("pki/sso/grafana.pub")).unwrap();
        let f = check(&cfg(&d), &[], false, None);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].service, "grafana");
        assert_eq!(f[0].problem, Problem::Missing { expects_file: true });
        assert_eq!(f[0].remedy, "noo security pki issue-sso-key");
        let text = refusal(&f);
        assert!(text.contains(&d.join("pki/sso/grafana.pub").to_string_lossy().into_owned()), "{text}");
        assert!(text.contains("/app/pki/sso/grafana.pub"), "{text}");
        assert!(text.starts_with("REFUSED: 1 bind-mount source(s)"), "{text}");
    }

    #[test]
    fn dir_where_file_expected_is_refused_with_rmdir_remedy() {
        let d = scratch("ghost");
        all_present(&d);
        let pubkey = d.join("pki/sso/grafana.pub");
        std::fs::remove_file(&pubkey).unwrap();
        std::fs::create_dir(&pubkey).unwrap();
        let f = check(&cfg(&d), &[], false, None);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].problem, Problem::DirWhereFile { empty: true });
        assert_eq!(
            f[0].remedy,
            format!("sudo rmdir '{}', then noo security pki issue-sso-key", pubkey.display())
        );
        // A non-empty one is not rmdir-able: say so instead.
        std::fs::write(pubkey.join("junk"), "x").unwrap();
        let f = check(&cfg(&d), &[], false, None);
        assert_eq!(f[0].problem, Problem::DirWhereFile { empty: false });
        assert!(f[0].remedy.starts_with("look inside"), "{}", f[0].remedy);
    }

    /// The gateway mounts `pki/public/{nodes,services}` and
    /// `pki/sso`. Missing on an install an older `noo` upgraded, each is
    /// refused naming the verb that lays it down — not "onboard", which
    /// the generic `/pki/` rule would say.
    #[test]
    fn missing_gateway_view_names_fix_modes() {
        let d = scratch("gwview");
        let p = |s: &str| d.join(s).to_string_lossy().into_owned();
        let cfg = json!({"services": {"gateway": {"volumes": [
            {"type": "bind", "source": p("pki/public/nodes"), "target": "/app/pki/nodes", "read_only": true, "bind": {}},
            {"type": "bind", "source": p("pki/public/services"), "target": "/app/pki/services", "read_only": true, "bind": {}},
            {"type": "bind", "source": p("pki/sso"), "target": "/app/pki/sso", "read_only": true, "bind": {}}
        ]}}});
        let f = check(&cfg, &[], false, None);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f[0].remedy.starts_with("noo security pki fix-modes"), "{}", f[0].remedy);
        assert!(f[1].remedy.starts_with("noo security pki fix-modes"), "{}", f[1].remedy);
        assert_eq!(f[2].remedy, "noo security pki issue-sso-key");
        let ca = crate::pki::ClusterCa::new(d.join("pki"));
        assert!(ca.sync_public_view().errors.is_empty());
        assert_eq!(check(&cfg, &[], false, None), vec![], "the sync lays down every gateway source");
    }

    #[test]
    fn missing_leaf_dir_names_its_issue_command() {
        let d = scratch("leaf");
        all_present(&d);
        std::fs::remove_dir(d.join("pki/services/model-cache")).unwrap();
        let f = check(&cfg(&d), &[], false, None);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].problem, Problem::Missing { expects_file: false });
        assert_eq!(f[0].remedy, "noo security pki issue-service model-cache");
    }

    #[test]
    fn only_the_services_being_started_and_their_dependencies() {
        let d = scratch("scope");
        // Nothing exists: every bind is a finding if its service is checked.
        let c = cfg(&d);
        let svcs = |f: Vec<Finding>| f.into_iter().map(|f| f.service).collect::<BTreeSet<_>>();
        assert_eq!(svcs(check(&c, &["other".into()], false, None)), BTreeSet::from(["other".to_string()]));
        // model-cache depends_on grafana → grafana is started too.
        assert_eq!(
            svcs(check(&c, &["model-cache".into()], false, None)),
            BTreeSet::from(["grafana".to_string(), "model-cache".to_string()])
        );
        assert_eq!(svcs(check(&c, &["model-cache".into()], true, None)), BTreeSet::from(["model-cache".to_string()]));
        // A service scaled to zero is not started, so not checked.
        assert_eq!(
            svcs(check_except(&c, &[], false, &["grafana".into(), "model-cache".into()], None)),
            BTreeSet::from(["other".to_string()])
        );
        // A name not in the rendered config (another profile) is not ours.
        assert!(check(&c, &["not-in-profile".into()], false, None).is_empty());
    }

    #[test]
    fn directory_sources_under_the_root_only() {
        let c = serde_json::json!({"services": {
            "gateway": {"volumes": [
                {"type":"bind","source":"/srv/noo/images","target":"/artifacts/images"},
                {"type":"bind","source":"/srv/noo/models/","target":"/artifacts/models"},
                {"type":"bind","source":"/srv/noo/pki/ca","target":"/pki"},
                {"type":"bind","source":"/srv/noo/x/users.conf","target":"/etc/users.conf"},
                {"type":"bind","source":"/srv/other/y","target":"/y"},
                {"type":"bind","source":"/srv/noo","target":"/root"},
                {"type":"volume","source":"named","target":"/n"}]},
            "model-cache": {"volumes": [{"type":"bind","source":"/srv/noo/images","target":"/images-store"}]}}});
        let got: Vec<_> = directory_sources_under(&c, "/srv/noo/").into_iter().collect();
        assert_eq!(got, ["/srv/noo/images", "/srv/noo/models"]);
        assert!(directory_sources_under(&serde_json::json!({}), "/srv/noo").is_empty());
    }

    #[test]
    fn device_bound_volume_missing_is_refused_present_ok_file_wrong_type() {
        let d = scratch("devvol");
        let dev = d.join("postgres");
        let c = serde_json::json!({
            "services": {"postgres": {"volumes": [{"type":"volume","source":"postgres-data","target":"/var/lib/postgresql/data"}]}},
            "volumes": {"postgres-data": {"driver":"local","driver_opts":{"type":"none","o":"bind","device": dev.to_str().unwrap()}}}
        });
        let root = d.to_str().unwrap();
        let f = check(&c, &[], false, Some(root));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].problem, Problem::Missing { expects_file: false });
        assert!(f[0].remedy.starts_with("noo onboard --only storage"), "{}", f[0].remedy);
        assert!(f[0].line().contains("volume postgres-data"));
        std::fs::create_dir_all(&dev).unwrap();
        assert!(check(&c, &[], false, Some(root)).is_empty());
        std::fs::remove_dir(&dev).unwrap();
        std::fs::write(&dev, "x").unwrap();
        let f = check(&c, &[], false, Some(root));
        assert_eq!(f[0].problem, Problem::FileWhereDir);
        // a plain named volume, or a non-bind driver, is none of our business
        let plain = serde_json::json!({"services": {"a": {"volumes": [{"type":"volume","source":"v","target":"/v"}]}}, "volumes": {"v": {"driver":"local"}}});
        assert!(check(&plain, &[], false, Some(root)).is_empty());
        // and the storage derivation sees the device
        std::fs::remove_file(&dev).unwrap();
        assert_eq!(directory_sources_under(&c, root).into_iter().collect::<Vec<_>>(), [dev.to_str().unwrap()]);
    }

    #[test]
    fn outside_root_remedy_says_who_owns_it() {
        let r = produce("/x/prompts", false, Some("/srv/noo"));
        assert!(r.contains("outside NOO_DATA_ROOT (/srv/noo)"), "{r}");
        assert!(produce("/h/.noo/.noo-host-spool", false, Some("/srv/noo")).contains("noo-hostd"));
        // a file under the root is not storage's to create
        assert!(produce("/srv/noo/a/b.conf", true, Some("/srv/noo")).starts_with("restore"));
    }

    #[test]
    fn data_root_and_placeholder_remedies() {
        assert_eq!(
            produce("/srv/noo/models", false, Some("/srv/noo")),
            "noo onboard --only storage (creates the data directories as you, not root)"
        );
        assert!(produce("/home/u/.noo/.pki-placeholder/ca.crt", true, None).contains("NOO_PKI_DIR is not set"));
        assert!(produce("/home/u/.noo/.pki-placeholder/sso/grafana.pub", true, None).contains("NOO_PKI_DIR is not set"));
        assert!(produce("/home/u/.noo/pki/ca.crt", true, None).starts_with("noo onboard --only enrollment"));
        assert!(produce("/x/prompts", false, Some("/srv/noo")).starts_with("mkdir -p '/x/prompts' (as you — the directory Docker would make is root-owned)"));
        assert!(produce("/x/docker/redis-entrypoint.sh", true, None).starts_with("restore redis-entrypoint.sh"));
    }

    /// the earlier roll order, the half that broke stack-v0.2.78: the
    /// users.conf on disk still names the legacy `$NATS_USER` while the new
    /// compose hands nats no environment. Refused BEFORE `up` — not NATS
    /// crash-looping after it — and passing once the file is re-rendered.
    #[test]
    fn a_legacy_users_conf_under_the_new_compose_is_refused_until_re_rendered() {
        let d = scratch("natslegacy");
        std::fs::create_dir_all(d.join("monitoring/nats")).unwrap();
        let conf = d.join("monitoring/nats/users.conf");
        let rendered = crate::commands::nats_users::render_users_conf(&[
            crate::commands::nats_users::Principal {
                user: "gateway".into(),
                hash: "$2b$11$g".into(),
                role: crate::commands::nats_users::Role::Gateway,
            },
        ]);
        let legacy = rendered.replace(
            "    ]\n",
            "      {\n        user: $NATS_USER\n        password: $NATS_PASSWORD\n      }\n    ]\n",
        );
        std::fs::write(&conf, &legacy).unwrap();
        let src = conf.to_string_lossy().into_owned();
        let nats = |env: Value| json!({"services": {"nats": {
            "environment": env,
            "volumes": [{"type": "bind", "source": src, "target": "/etc/nats/users.conf", "read_only": true, "bind": {}}]
        }}});

        // The new compose: no environment at all.
        let f = check(&nats(json!({})), &[], false, None);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(f[0].problem, Problem::UnresolvedVar { var: "NATS_USER".into() });
        assert_eq!(f[1].problem, Problem::UnresolvedVar { var: "NATS_PASSWORD".into() });
        assert!(f[0].remedy.starts_with("noo cluster nats-users render"), "{}", f[0].remedy);
        let text = refusal(&f);
        assert!(text.contains("names $NATS_USER, which the nats service is not handed"), "{text}");
        // Scoped like every bind: starting only the gateway does not judge nats.
        assert!(check(&nats(json!({})), &["gateway".into()], false, None).is_empty());
        // The OLD compose handed both: the same file was startable then.
        assert!(check(&nats(json!({"NATS_USER": "noo", "NATS_PASSWORD": "x"})), &[], false, None).is_empty());
        assert!(check(&nats(json!(["NATS_USER=noo", "NATS_PASSWORD=x"])), &[], false, None).is_empty());

        // Re-rendered by the current renderer: no variable, nothing refused.
        std::fs::write(&conf, &rendered).unwrap();
        assert_eq!(check(&nats(json!({})), &[], false, None), vec![]);
    }

    #[test]
    fn file_inference_needs_a_positive_signal() {
        for f in ["/app/pki/sso/grafana.pub", "/etc/grafana/grafana.ini", "/usr/local/bin/redis-entrypoint.sh", "/app/noomesh.yaml", "/tls/ca.crt"] {
            assert!(looks_like_file(f), "{f}");
        }
        for d in ["/etc/nginx/conf.d", "/tls/services/nats", "/var/run/noo-spool", "/home/u/.noo/.noo-host-spool", "/", "/app/pki", "/tmp/.ui-index-unused"] {
            assert!(!looks_like_file(d), "{d}");
        }
    }

    #[test]
    fn hostd_spool_is_created_only_without_systemd_and_only_that_source() {
        let d = scratch("spool");
        let spool = d.join(".noo-host-spool");
        let other = d.join("configs");
        let cfg = json!({"services": {"gateway": {"volumes": [
            {"type": "bind", "source": spool.to_string_lossy(), "target": "/spool", "bind": {}},
            {"type": "bind", "source": other.to_string_lossy(), "target": "/etc/cfg", "bind": {}}
        ]}}});
        let svcs: Vec<String> = Vec::new();
        assert!(ensure_hostd_spool(&cfg, &svcs, false, true).is_empty());
        assert!(!spool.exists());
        let made = ensure_hostd_spool(&cfg, &svcs, false, false);
        assert_eq!(made, vec![spool.to_string_lossy().to_string()]);
        assert!(spool.is_dir());
        assert!(!other.exists());
        // The other missing source still refuses.
        let findings = check(&cfg, &svcs, false, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, other.to_string_lossy());
        // Idempotent.
        assert!(ensure_hostd_spool(&cfg, &svcs, false, false).is_empty());
    }

    #[test]
    fn launch_check_creates_the_spool_without_systemd_and_refuses_with_it() {
        // The dist launcher's path (lib-bind-sources.sh -> `run`): no
        // systemd, a fresh tree, the spool missing -> created, not refused.
        let d = scratch("launch-spool");
        let spool = d.join(".noo-host-spool");
        let cfg = json!({"services": {"gateway": {"volumes": [
            {"type": "bind", "source": spool.to_string_lossy(), "target": "/spool", "bind": {}}
        ]}}});
        let root = d.to_string_lossy().to_string();
        let (code, text) = launch_check(&cfg, &[], false, &[], Some(&root), false, false);
        assert_eq!(code, 0, "{text}");
        assert!(spool.is_dir());
        assert!(text.contains("created the host executor spool") && text.contains("no systemd"), "{text}");
        // Present now: silent.
        assert_eq!(launch_check(&cfg, &[], false, &[], Some(&root), false, false), (0, String::new()));
        // With systemd AND hostd's unit installed it is hostd's: not
        // created, refused, and the text says who owns it.
        std::fs::remove_dir(&spool).unwrap();
        let (code, text) = launch_check(&cfg, &[], false, &[], Some(&root), true, true);
        assert_eq!(code, EXIT_REFUSED);
        assert!(!spool.exists());
        assert!(text.contains("noo-hostd's unit is installed here"), "{text}");
    }

    /// i251: systemd present, hostd NOT installed (`noo onboard --ci` on a
    /// real Ubuntu box before this change, or any --ci run without
    /// passwordless sudo). The old rule refused every start; now the
    /// launcher makes the spool, as it does without systemd, and says that
    /// host commands wait for hostd.
    #[test]
    fn launch_check_creates_the_spool_with_systemd_when_hostd_is_not_installed() {
        let d = scratch("launch-spool-nohostd");
        let spool = d.join(".noo-host-spool");
        let cfg = json!({"services": {"gateway": {"volumes": [
            {"type": "bind", "source": spool.to_string_lossy(), "target": "/spool", "bind": {}}
        ]}}});
        let root = d.to_string_lossy().to_string();
        assert!(!hostd_owns_spool(true, false) && hostd_owns_spool(true, true) && !hostd_owns_spool(false, true));
        let (code, text) = launch_check(&cfg, &[], false, &[], Some(&root), true, false);
        assert_eq!(code, 0, "{text}");
        assert!(spool.is_dir(), "the spool is the user's directory; the launcher makes it when hostd is absent");
        assert!(text.contains("noo-hostd is not installed here") && text.contains("noo onboard --only services"), "{text}");
        assert_eq!(launch_check(&cfg, &[], false, &[], Some(&root), true, false), (0, String::new()), "idempotent");
    }
}
