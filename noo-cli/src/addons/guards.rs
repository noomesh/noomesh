// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What an add-on's overlay may take from core, and which names an add-on
//! may hold (0.6.13).
//!
//! ## Secrets: a positive allowlist, computed from the add-on's name
//!
//! An add-on's compose overlay arrives in its signed bundle and is composed
//! beside core's. Compose merges the top-level `secrets:` of every file, and
//! the launcher exports every value of the encrypted store before `compose
//! up`, so without a rule an overlay could declare `secrets: x: x-noo-source:
//! NOO_JWT_SECRET` (the launcher writes that file for it), list a secret core
//! declares (`- source: <core secret>`), or interpolate `${NOO_JWT_SECRET}`
//! into its environment. A signature says who shipped the overlay, not that
//! it only asks for its own.
//!
//! An add-on may take only what was minted FOR it ([`owned_secret_vars`]),
//! every name derived from the add-on's name and its declarations, never
//! read from the bundle:
//!
//! | variable | what |
//! |---|---|
//! | `NOO_SVC_KEY_<ID>` | its gateway key (`x-noo-addon`, minted by `noo addons enable`) |
//! | `NOO_BUS_KEY_<ID>` | its bus-principal key |
//! | `NOO_<ID>_DB_PASSWORD`, `NOO_<ID>_DDL_PASSWORD` | its database roles' passwords (`system.json`, `noo systems`) |
//! | `NOO_PGPASS_<ID>` | the pgpass body the launcher builds from those two |
//! | `NATS_<ID>_PASSWORD` | its NATS principal, when `x-noo-addon.nats_principal` names it |
//! | `NOO_ADDON_SECRET_<ID>__<NAME>` | each `shared_secret` its `resources.json` declares |
//!
//! `<ID>` is the add-on name upper-cased, `-` as `_`. [`check_overlay`]
//! refuses an overlay that sources, references or interpolates anything
//! else that is a secret, and an `x-noo-addon.key` that is not its own. It
//! runs at `noo addons enable | upgrade` (`addons::prepare_from`, before an
//! image is pulled or a pin written), `noo addons upgrade --check`, `noo
//! addons verify`, and again at every launch (`noo addons launch-resources`,
//! which the launcher runs before `compose up`; a refused add-on is left out
//! of that start, and a launcher whose CLI could not check refuses them all).
//!
//! For a THIRD-PARTY add-on (one the CLI ships no row for, so its lock is
//! verified against a key the operator trusted with `noo addons trust-key`,
//! never against the entitlement) two more doors are shut: `extends:` from
//! another compose file (it would inherit that service's secrets whole), and
//! a service of its overlay named like a core service (compose would merge
//! it INTO core's: an add-on could re-image the gateway). The add-ons the CLI
//! ships use both today (trellion-intel extends trellion; evolve adds a
//! volume to the gateway), so for them those two stay as they were.
//!
//! A third-party add-on's services also reach the host only through what is
//! its own ([`check_runtime`]): named volumes its overlay declares and the
//! mount directories its `resources.json` declares. Any other bind mount,
//! `env_file`, `volumes_from`, a core volume, devices, host namespaces,
//! added capabilities, unconfined profiles and host `configs:` are refused
//! (operator 2026-10-27). The shipped add-ons bind the PKI and are unchanged.
//! The first-party `extends` inheritance (trellion-intel inherits trellion's
//! pgpass) is allowed by decision (operator 2026-10-27); intel gets its own
//! database role later.
//!
//! ## Names
//!
//! [`name_collision`] refuses a third-party add-on whose name, or any name
//! derived from it, is core's: a compose service or container (`noo-<x>`), a
//! service leaf the CA issues, a database role (`noo_<id>`, `noo_<id>_ddl`),
//! or a variable core reads (`NOO_PGPASS_WORKER`, `NATS_GATEWAY_PASSWORD`…).
//! The core lists are read from where core declares them ([`Core`]), never
//! copied here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_yaml::Value;

/// The add-on's variable id: its name upper-cased, `-` as `_`.
pub fn addon_id(addon: &str) -> String {
    addon.to_ascii_uppercase().replace('-', "_")
}

/// The variables an add-on's overlay may take a secret from (see the module
/// table). `shared_secrets` are the `shared_secret` resource names its
/// `resources.json` declares; `nats_principal` is whether its overlay's
/// `x-noo-addon.nats_principal` names the add-on itself.
pub fn owned_secret_vars(addon: &str, shared_secrets: &[String], nats_principal: bool) -> BTreeSet<String> {
    let id = addon_id(addon);
    let (db, ddl) = super::decls::password_envs(addon);
    let mut out = BTreeSet::from([format!("NOO_SVC_KEY_{id}"), format!("NOO_BUS_KEY_{id}"), format!("NOO_PGPASS_{id}"), db, ddl]);
    if nats_principal {
        out.insert(format!("NATS_{id}_PASSWORD"));
    }
    for n in shared_secrets {
        out.insert(super::resources::shared_secret_var(addon, n));
    }
    out
}

/// Is `var` named the way core names a credential it mints, for core or for
/// any add-on? Such a variable is a secret whether or not this install's
/// lists name it (another add-on's key, a node's NATS password).
pub fn credential_shaped(var: &str) -> bool {
    ["NOO_SVC_KEY_", "NOO_BUS_KEY_", "NOO_PGPASS_", "NOO_ADDON_SECRET_"].iter().any(|p| var.starts_with(p))
        || (var.starts_with("NATS_") && var.contains("_PASSWORD"))
        || (var.starts_with("NOO_") && (var.ends_with("_DB_PASSWORD") || var.ends_with("_DDL_PASSWORD")))
}

/// What core declares, read from core's own declarations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Core {
    /// Top-level compose secrets core declares: name to the variable it is
    /// sourced from (`x-noo-source:` or `environment:`).
    pub secrets: BTreeMap<String, String>,
    /// Every variable core treats as a secret: its compose secret sources
    /// and the secret registry's keys.
    pub secret_vars: BTreeSet<String>,
    /// Every variable a core compose file reads (`${VAR`).
    pub compose_vars: BTreeSet<String>,
    /// The services core's compose files define (what an add-on service of
    /// the same name would be merged INTO).
    pub compose_services: BTreeSet<String>,
    /// Every core service name: the compose services, their container names
    /// (with the default `noo` prefix), and the service leaves the CA issues.
    pub services: BTreeSet<String>,
    /// Core's database roles (the Postgres role leaves).
    pub roles: BTreeSet<String>,
    /// The top-level volumes core's compose files declare (its data).
    pub volumes: BTreeSet<String>,
}

fn untag(v: &Value) -> &Value {
    match v {
        Value::Tagged(t) => untag(&t.value),
        other => other,
    }
}

fn mapping(v: Option<&Value>) -> Option<&serde_yaml::Mapping> {
    v.map(untag).and_then(Value::as_mapping)
}

/// The variable a top-level compose secret entry is sourced from.
fn secret_source(entry: &Value) -> Option<String> {
    let e = untag(entry);
    e.get("x-noo-source").or_else(|| e.get("environment")).and_then(Value::as_str).map(|s| s.trim().to_string())
}

impl Core {
    /// From the texts of core's compose files. A text that is not YAML is
    /// an error: an unread core file would be a list with holes in it.
    pub fn from_texts(texts: &[String]) -> Result<Core, String> {
        let mut c = Core { compose_vars: super::resources::core_compose_vars(texts), ..Core::default() };
        for t in texts {
            let doc: Value = serde_yaml::from_str(t).map_err(|e| format!("a core compose file is not valid YAML ({e})"))?;
            if let Some(m) = mapping(doc.get("secrets")) {
                for (k, v) in m {
                    if let (Some(name), Some(var)) = (k.as_str(), secret_source(v)) {
                        c.secret_vars.insert(var.clone());
                        c.secrets.insert(name.to_string(), var);
                    }
                }
            }
            if let Some(m) = mapping(doc.get("volumes")) {
                c.volumes.extend(m.keys().filter_map(Value::as_str).map(str::to_string));
            }
            if let Some(m) = mapping(doc.get("services")) {
                for (k, v) in m {
                    if let Some(name) = k.as_str() {
                        c.compose_services.insert(name.to_string());
                        c.services.insert(name.to_string());
                    }
                    if let Some(cn) = untag(v).get("container_name").and_then(Value::as_str) {
                        c.services.insert(cn.replace("${NOO_CONTAINER_PREFIX:-noo}", "noo"));
                    }
                }
            }
        }
        Ok(c)
    }

    /// Add what core declares in this binary: the service leaves the CA
    /// issues, the Postgres role leaves, and the secret registry's keys.
    pub fn with_tables(mut self) -> Core {
        for (svc, _) in crate::pki::SERVICE_KEY_READERS {
            self.services.insert(svc.to_string());
        }
        for leaf in crate::pki::PG_LEAVES {
            self.services.insert(leaf.owner.to_string());
            self.roles.insert(leaf.role.to_string());
        }
        for spec in crate::commands::secrets::CORE_REGISTRY.iter().chain(crate::commands::secrets::ADDON_KEY_SPECS.iter()) {
            self.secret_vars.insert(spec.key.to_string());
        }
        self
    }

    /// The install's core: every `docker-compose*.yml` at `root` (add-on
    /// overlays live under `addons/`, never here), plus [`Core::with_tables`].
    /// No core compose file at all is an error: the names could not be
    /// checked, and an unchecked add-on is refused, not waved through.
    pub fn of_install(root: &Path) -> Result<Core, String> {
        let mut texts = Vec::new();
        let rd = std::fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
        let mut names: Vec<_> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("docker-compose") && n.ends_with(".yml"))
            .collect();
        names.sort();
        for n in &names {
            let p = root.join(n);
            texts.push(std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?);
        }
        if texts.is_empty() {
            return Err(format!("no core compose file (docker-compose*.yml) under {}, so an add-on's secrets cannot be checked", root.display()));
        }
        Ok(Core::from_texts(&texts)?.with_tables())
    }
}

/// What [`check_overlay`] looked at, so a test can assert the parse found
/// what it was meant to check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checked {
    /// Top-level secrets the overlay declares.
    pub declared: usize,
    /// Secret references in its services' `secrets:` lists.
    pub referenced: usize,
    /// Variables it interpolates (`$VAR`, `${VAR…}`).
    pub interpolated: usize,
    /// Volume entries its services declare (third-party only: [`check_runtime`]).
    pub mounts: usize,
}

/// Every variable compose would interpolate in `s`: `$NAME` and `${NAME…}`,
/// nested defaults included; `$$` is a literal dollar.
pub fn interpolated_vars(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        if b.get(i + 1) == Some(&b'$') {
            i += 2;
            continue;
        }
        let start = if b.get(i + 1) == Some(&b'{') { i + 2 } else { i + 1 };
        let mut j = start;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
        if j > start {
            out.push(s[start..j].to_string());
        }
        i = j.max(i + 1);
    }
    out
}

fn walk_values<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Sequence(seq) => seq.iter().for_each(|x| walk_values(x, out)),
        Value::Mapping(m) => m.values().for_each(|x| walk_values(x, out)),
        Value::Tagged(t) => walk_values(&t.value, out),
        _ => {}
    }
}

fn owned_list(owned: &BTreeSet<String>) -> String {
    owned.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// Check one add-on overlay (`docker-compose.yml` of its bundle) against
/// [`owned_secret_vars`]. `Err` is the plain refusal, naming the add-on and
/// the variable or secret; callers add what was (not) done.
pub fn check_overlay(addon: &str, text: &str, shared_secrets: &[String], third_party: bool, core: &Core) -> Result<Checked, String> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| format!("add-on {addon}: its overlay is not valid YAML ({e})"))?;
    let nats = crate::commands::nats_users::overlay_declares_principal(text, addon);
    let owned = owned_secret_vars(addon, shared_secrets, nats);
    let not_own = |var: &str, what: String| {
        format!(
            "add-on {addon}: its overlay {what} {var}, which is not one of {addon}'s own secrets. An add-on gets only what \
             was minted for it ({}); anything else is core's or another add-on's",
            owned_list(&owned)
        )
    };
    let mut seen = Checked::default();

    // Its gateway key: the one derived from its name, never another's.
    if let Some(k) = doc.get("x-noo-addon").map(untag).and_then(|b| b.get("key")).and_then(Value::as_str) {
        let want = format!("NOO_SVC_KEY_{}", addon_id(addon));
        if k != want {
            return Err(format!("add-on {addon}: its x-noo-addon names key {k}; an add-on's own key is {want}, and no other is delivered to it"));
        }
    }

    // Top-level secrets it declares: sourced from its own variables, written
    // by the launcher into its secret directory (never a host file).
    let mut declared: BTreeSet<String> = BTreeSet::new();
    if let Some(m) = mapping(doc.get("secrets")) {
        for (k, v) in m {
            let name = k.as_str().ok_or_else(|| format!("add-on {addon}: its overlay declares a secret whose name is not text"))?;
            seen.declared += 1;
            let e = untag(v);
            if e.get("external").is_some() {
                return Err(format!("add-on {addon}: its overlay declares secret `{name}` as external; an add-on's secrets come only from the launcher"));
            }
            match secret_source(v) {
                Some(var) if owned.contains(&var) => {}
                Some(var) => return Err(not_own(&var, format!("sources secret `{name}` from"))),
                None => {
                    return Err(format!(
                        "add-on {addon}: its overlay declares secret `{name}` with no `x-noo-source:` variable of its own"
                    ))
                }
            }
            if let Some(f) = e.get("file").and_then(Value::as_str) {
                if !(f.contains("NOO_SECRET_RUNDIR") && f.ends_with(&format!("/{name}"))) {
                    return Err(format!(
                        "add-on {addon}: its overlay reads secret `{name}` from the host file {f}; an add-on's secret files are \
                         written by the launcher only (`file: ${{NOO_SECRET_RUNDIR}}/{name}`)"
                    ));
                }
            }
            declared.insert(name.to_string());
        }
    }

    // What its services take: its own declarations, or a secret core declares
    // that is sourced from one of its own variables (a bus key core lists).
    if let Some(m) = mapping(doc.get("services")) {
        for (k, svc) in m {
            let svc_name = k.as_str().unwrap_or_default();
            let svc = untag(svc);
            if third_party {
                if core.compose_services.contains(svc_name) {
                    return Err(format!(
                        "add-on {addon}: its overlay defines service `{svc_name}`, which is core's; compose would merge it into core's service"
                    ));
                }
                if let Some(x) = svc.get("extends").map(untag) {
                    if x.get("file").is_some() {
                        return Err(format!(
                            "add-on {addon}: its service `{svc_name}` extends a service of another compose file, and would inherit that \
                             service's secrets; a third-party add-on extends only services of its own overlay"
                        ));
                    }
                }
            }
            let Some(list) = svc.get("secrets").map(untag).and_then(Value::as_sequence) else { continue };
            for item in list {
                let item = untag(item);
                let Some(src) = item.as_str().or_else(|| item.get("source").and_then(Value::as_str)) else { continue };
                seen.referenced += 1;
                if declared.contains(src) {
                    continue;
                }
                match core.secrets.get(src) {
                    Some(var) if owned.contains(var) => {}
                    Some(var) => return Err(not_own(var, format!("gives service `{svc_name}` core's secret `{src}`, sourced from"))),
                    None => {
                        return Err(format!(
                            "add-on {addon}: its service `{svc_name}` takes secret `{src}`, which neither its overlay nor core declares"
                        ))
                    }
                }
            }
        }
    }

    // Interpolation: the launcher's environment holds every value of the
    // store, so `${NOO_JWT_SECRET}` in an add-on's environment would be the
    // secret itself.
    let mut strings = Vec::new();
    walk_values(&doc, &mut strings);
    for s in strings {
        for var in interpolated_vars(s) {
            seen.interpolated += 1;
            if (core.secret_vars.contains(&var) || credential_shaped(&var)) && !owned.contains(&var) {
                return Err(not_own(&var, "interpolates".to_string()));
            }
        }
    }
    Ok(seen)
}

/// Why `addon`'s name, or a name derived from it, is core's (`None`: it is
/// free). Asked of third-party add-ons only: an add-on the CLI ships owns
/// the core rows that name it.
pub fn name_collision(addon: &str, core: &Core) -> Option<String> {
    let kebab = addon.replace('_', "-");
    let snake = addon.replace('-', "_");
    for n in [addon.to_string(), kebab.clone(), snake.clone(), format!("noo-{kebab}")] {
        if core.services.contains(&n) {
            return Some(format!("add-on name `{addon}` is core's: `{n}` is a core service, container or certificate name"));
        }
    }
    let role = format!("noo_{snake}");
    for r in [role.clone(), format!("{role}_ddl")] {
        if core.roles.contains(&r) {
            return Some(format!("add-on name `{addon}` is core's: its database role would be `{r}`, a core role"));
        }
    }
    let derived = owned_secret_vars(addon, &[], true);
    for v in &derived {
        if core.secret_vars.contains(v) || core.compose_vars.contains(v) {
            return Some(format!("add-on name `{addon}` is core's: its secret variable would be {v}, which core already uses"));
        }
    }
    None
}

/// The plain refusal of a colliding name, with the way out.
pub fn name_refusal(why: &str) -> String {
    format!("{why}. An add-on cannot share a name with core: the vendor must ship it under another name. Nothing was changed")
}

/// Every guard a bundle passes, over its files (name to bytes): the
/// overlay's secrets and, for a third-party add-on, its name. Pure: the
/// live callers go through [`guard_install`].
pub fn check_bundle_files(addon: &str, files: &BTreeMap<String, Vec<u8>>, third_party: bool, core: &Core) -> Result<Checked, String> {
    if third_party {
        if let Some(why) = name_collision(addon, core) {
            return Err(name_refusal(&why));
        }
    }
    let Some(bytes) = files.get("docker-compose.yml") else { return Ok(Checked::default()) };
    let text = std::str::from_utf8(bytes).map_err(|_| format!("add-on {addon}: its overlay is not UTF-8"))?;
    let (shared, mount_envs): (Vec<String>, Vec<String>) = match files.get(super::resources::RESOURCES_FILE) {
        Some(b) => {
            let facts = super::resources::bundle_facts(addon, files);
            let res = super::resources::parse(addon, b, &facts)?;
            (
                res.resources.iter().filter(|r| r.what == super::resources::What::SharedSecret).map(|r| r.name.clone()).collect(),
                res.mounts.iter().map(|m| m.env.clone()).collect(),
            )
        }
        None => (Vec::new(), Vec::new()),
    };
    let mut checked = check_overlay(addon, text, &shared, third_party, core)?;
    if third_party {
        checked.mounts = check_runtime(addon, text, &mount_envs, core)?;
    }
    Ok(checked)
}

/// Is `src` exactly one of the add-on's declared mount variables
/// (`${VAR}`, `${VAR:?…}`, `${VAR?…}`, or a default under `/nonexistent/`):
/// the tmpfs generation directory the launcher hands over, and nothing else
/// even when the variable is unset?
fn declared_mount_source(src: &str, mount_envs: &[String]) -> bool {
    let Some(inner) = src.strip_prefix("${").and_then(|r| r.strip_suffix('}')) else { return false };
    let name: String = inner.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if !mount_envs.contains(&name) {
        return false;
    }
    let rest = &inner[name.len()..];
    if rest.contains('$') || rest.contains('{') || rest.contains('}') {
        return false;
    }
    rest.is_empty()
        || rest.starts_with(":?")
        || rest.starts_with('?')
        || rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-')).is_some_and(|d| d.starts_with("/nonexistent/"))
}

/// Is this compose key set to something (a non-empty list, or any scalar)?
fn set_nonempty(v: Option<&Value>) -> bool {
    match v.map(untag) {
        None | Some(Value::Null) => false,
        Some(Value::Sequence(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// Split a short-form volume (`src:dst[:mode]`) at the colons that are not
/// inside a `${…}`.
fn split_volume(v: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), 0usize);
    let b: Vec<char> = v.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '$' && b.get(i + 1) == Some(&'{') {
            depth += 1;
            cur.push_str("${");
            i += 2;
            continue;
        }
        if c == '}' && depth > 0 {
            depth -= 1;
        }
        if c == ':' && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    out.push(cur);
    out
}

/// What a third-party add-on's services may reach on the host: named volumes
/// of its own, and the mount directories its `resources.json` declares.
/// Nothing else: no bind mount of a host path (short or long form, literal or
/// interpolated), no `env_file`, no `volumes_from`, no core volume, no
/// device, no host namespace, no added capability, no unconfined profile,
/// no cgroup parent, no host `configs:` file. Returns the number of mounts
/// it read. A GPU reservation and `privileged` stay HELD (the launcher never
/// starts them, `resources::holds`); a Docker socket mount, a bind mount,
/// is refused here first.
pub fn check_runtime(addon: &str, text: &str, mount_envs: &[String], core: &Core) -> Result<usize, String> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| format!("add-on {addon}: its overlay is not valid YAML ({e})"))?;
    let mut own_volumes: BTreeSet<String> = BTreeSet::new();
    if let Some(m) = mapping(doc.get("volumes")) {
        for (k, v) in m {
            let name = k.as_str().unwrap_or_default();
            if core.volumes.contains(name) {
                return Err(format!("add-on {addon}: its overlay declares volume `{name}`, which is core's; an add-on never attaches core's data"));
            }
            let v = untag(v);
            if let Some(key) = ["external", "name", "driver", "driver_opts"].into_iter().find(|k| v.get(*k).is_some()) {
                return Err(format!(
                    "add-on {addon}: its volume `{name}` sets `{key}`; an add-on's named volumes are plain volumes of its own (no external, renamed or driver-backed volume)"
                ));
            }
            own_volumes.insert(name.to_string());
        }
    }
    if let Some(m) = mapping(doc.get("configs")) {
        for (k, v) in m {
            let name = k.as_str().unwrap_or_default();
            if let Some(key) = ["file", "environment", "external"].into_iter().find(|key| untag(v).get(*key).is_some()) {
                return Err(format!("add-on {addon}: its config `{name}` is read from `{key}`; an add-on's config may only be inline `content`"));
            }
        }
    }
    let mut mounts = 0;
    let Some(services) = mapping(doc.get("services")) else { return Ok(0) };
    for (k, svc) in services {
        let svc_name = k.as_str().unwrap_or_default();
        let svc = untag(svc);
        let refuse = |what: String| format!("add-on {addon}: its service `{svc_name}` {what}; a third-party add-on gets no host access beyond its own volumes and declared mounts");
        let named = |src: &str| -> Result<(), String> {
            if core.volumes.contains(src) {
                return Err(refuse(format!("mounts core's volume `{src}`")));
            }
            if !own_volumes.contains(src) {
                return Err(refuse(format!("mounts volume `{src}`, which its overlay does not declare")));
            }
            Ok(())
        };
        for key in ["env_file", "volumes_from", "cgroup_parent"] {
            if svc.get(key).is_some() {
                return Err(refuse(format!("sets `{key}`")));
            }
        }
        if set_nonempty(svc.get("devices")) {
            return Err(refuse("asks for host devices (`devices:`)".to_string()));
        }
        if set_nonempty(svc.get("cap_add")) {
            return Err(refuse("adds capabilities (`cap_add:`)".to_string()));
        }
        for key in ["pid", "ipc", "network_mode", "userns_mode", "uts", "cgroup"] {
            if let Some(v) = svc.get(key).and_then(Value::as_str) {
                let v = v.trim();
                if v == "host" || v.starts_with("service:") || v.starts_with("container:") || (key == "ipc" && v == "shareable") {
                    return Err(refuse(format!("sets `{key}: {v}`")));
                }
            }
        }
        if let Some(opts) = svc.get("security_opt").and_then(Value::as_sequence) {
            for o in opts.iter().filter_map(Value::as_str) {
                let l = o.to_ascii_lowercase().replace('=', ":");
                if l.contains("unconfined") || l.starts_with("label:disable") || l.starts_with("label:type:") {
                    return Err(refuse(format!("loosens its confinement (`security_opt: {o}`)")));
                }
            }
        }
        let Some(vols) = svc.get("volumes").map(untag).and_then(Value::as_sequence) else { continue };
        for vol in vols {
            mounts += 1;
            let vol = untag(vol);
            if let Some(short) = vol.as_str() {
                let parts = split_volume(short);
                if parts.len() < 2 {
                    continue; // an anonymous volume: a container path only
                }
                let src = parts[0].trim();
                if declared_mount_source(src, mount_envs) {
                    continue;
                }
                let bind = src.contains('/') || src.starts_with('.') || src.starts_with('~') || src.contains('$') || src.is_empty();
                if bind {
                    return Err(refuse(format!("bind-mounts the host path `{src}`")));
                }
                named(src)?;
                continue;
            }
            let ty = vol.get("type").and_then(Value::as_str).unwrap_or_default();
            let src = vol.get("source").and_then(Value::as_str).unwrap_or_default().trim();
            match ty {
                "bind" if declared_mount_source(src, mount_envs) => {}
                "bind" => return Err(refuse(format!("bind-mounts the host path `{src}`"))),
                "volume" if src.is_empty() => {}
                "volume" => named(src)?,
                "tmpfs" => {}
                other => return Err(refuse(format!("mounts a `{other}` volume, which an add-on may not use"))),
            }
        }
    }
    Ok(mounts)
}

/// [`check_bundle_files`] against the install at `root` ([`Core::of_install`]),
/// third-party as `resolve::third_party` decides: whether the lock is
/// verified against the operator's trusted key or the entitlement's. The one
/// call the pin path (`addons::prepare_from`: enable, upgrade), `noo addons
/// upgrade --check`, `noo addons verify` and the launcher make.
pub fn guard_install(root: &Path, addon: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Checked, String> {
    let core = Core::of_install(root).map_err(|e| format!("add-on {addon} could not be checked: {e}"))?;
    check_bundle_files(addon, files, super::resolve::third_party(addon), &core)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A core shaped like the real one: the base declares the JWT secret and
    /// the worker's pgpass, and lists a bus key it sources for an add-on.
    fn core() -> Core {
        let base = "services:\n  gateway:\n    container_name: ${NOO_CONTAINER_PREFIX:-noo}-gateway\n    environment:\n      X: ${NOO_JWT_SECRET:+/run/secrets/jwt}\n  prometheus:\n    image: p\n  worker:\n    image: w\nsecrets:\n  noo_jwt_secret:\n    file: ${NOO_SECRET_RUNDIR:-/x}/noo_jwt_secret\n    x-noo-source: NOO_JWT_SECRET\n  pgpass_worker:\n    file: ${NOO_SECRET_RUNDIR:-/x}/pgpass_worker\n    x-noo-source: NOO_PGPASS_WORKER\n  noo_bus_key_rhaddon:\n    file: ${NOO_SECRET_RUNDIR:-/x}/noo_bus_key_rhaddon\n    x-noo-source: NOO_BUS_KEY_RHADDON\n";
        let c = Core::from_texts(&[base.to_string()]).unwrap().with_tables();
        assert!(c.secrets.contains_key("noo_jwt_secret") && c.services.contains("noo-gateway") && c.roles.contains("noo_app"), "{c:?}");
        c
    }

    const OWN: &str = "x-noo-addon:\n  addon: rhaddon\n  consumer: svc:rhaddon\n  key: NOO_SVC_KEY_RHADDON\n  containers: [noo-rhaddon]\n  scopes: [metrics]\n  nats_principal: rhaddon\nsecrets:\n  rh_key:\n    file: ${NOO_SECRET_RUNDIR:-/x}/rh_key\n    x-noo-source: NOO_SVC_KEY_RHADDON\n  rh_nats:\n    file: ${NOO_SECRET_RUNDIR:-/x}/rh_nats\n    x-noo-source: NATS_RHADDON_PASSWORD\n  rh_peer:\n    environment: NOO_ADDON_SECRET_RHADDON__PEER_KEY\nservices:\n  noo-rhaddon:\n    image: ${NOO_ADDON_IMAGE_RHADDON:-x}\n    environment:\n      KEY_FILE: ${NOO_SVC_KEY_RHADDON:+/run/secrets/k}\n      DB: ${NOO_PGPASS_RHADDON:+/run/secrets/p}\n      LIT: \"$$NOO_JWT_SECRET is literal\"\n    secrets:\n      - rh_key\n      - { source: rh_nats, target: nats }\n      - noo_bus_key_rhaddon\n";

    fn peer() -> Vec<String> {
        vec!["peer-key".to_string()]
    }

    #[test]
    fn an_overlay_that_takes_only_its_own_passes_and_every_part_was_read() {
        let c = check_overlay("rhaddon", OWN, &peer(), true, &core()).unwrap();
        assert_eq!(c, Checked { declared: 3, referenced: 3, interpolated: 5, mounts: 0 }, "the parse must find what it checks");
    }

    /// The gap: an overlay sourcing a core secret. Each form is refused,
    /// naming the add-on and the variable. Reverting the declaration check
    /// in `check_overlay` passes the first case; the reference check, the
    /// second; the interpolation check, the third and fourth.
    #[test]
    fn every_way_of_taking_a_core_secret_is_refused_by_name() {
        let cases: Vec<(String, &str)> = vec![
            (OWN.replace("x-noo-source: NATS_RHADDON_PASSWORD", "x-noo-source: NOO_JWT_SECRET"), "sources secret `rh_nats` from NOO_JWT_SECRET"),
            (OWN.replace("      - noo_bus_key_rhaddon\n", "      - noo_bus_key_rhaddon\n      - pgpass_worker\n"), "core's secret `pgpass_worker`, sourced from NOO_PGPASS_WORKER"),
            (OWN.replace("LIT: \"$$NOO_JWT_SECRET is literal\"", "LIT: ${NOO_JWT_SECRET}"), "interpolates NOO_JWT_SECRET"),
            (OWN.replace("LIT: \"$$NOO_JWT_SECRET is literal\"", "LIT: \"x $NOO_SVC_KEY_TRELLION y\""), "interpolates NOO_SVC_KEY_TRELLION"),
            (OWN.replace("environment: NOO_ADDON_SECRET_RHADDON__PEER_KEY", "environment: NOO_ADDON_SECRET_OTHER__PEER_KEY"), "NOO_ADDON_SECRET_OTHER__PEER_KEY"),
            (OWN.replace("key: NOO_SVC_KEY_RHADDON", "key: NOO_SVC_KEY_TRELLION"), "names key NOO_SVC_KEY_TRELLION"),
            (OWN.replace("file: ${NOO_SECRET_RUNDIR:-/x}/rh_key", "file: /home/op/.config/sops/age/keys.txt"), "from the host file"),
            (OWN.replace("      - noo_bus_key_rhaddon\n", "      - noo_bus_key_rhaddon\n      - nowhere\n"), "neither its overlay nor core declares"),
            (OWN.replace("    environment: NOO_ADDON_SECRET_RHADDON__PEER_KEY\n", "    external: true\n"), "as external"),
        ];
        assert_eq!(cases.len(), 9);
        for (text, needle) in cases {
            assert_ne!(text, OWN, "the case did not change the overlay: {needle}");
            let e = check_overlay("rhaddon", &text, &peer(), true, &core()).unwrap_err();
            assert!(e.starts_with("add-on rhaddon:") && e.contains(needle), "{e:?} should name {needle:?}");
        }
        // A shared secret it did not declare is not its own either.
        let e = check_overlay("rhaddon", OWN, &[], true, &core()).unwrap_err();
        assert!(e.contains("NOO_ADDON_SECRET_RHADDON__PEER_KEY"), "{e}");
        // Its NATS password is its own only when it declares the principal.
        let no_principal = OWN.replace("  nats_principal: rhaddon\n", "");
        assert!(check_overlay("rhaddon", &no_principal, &peer(), true, &core()).unwrap_err().contains("NATS_RHADDON_PASSWORD"));
    }

    /// Third-party only: no `extends` from another file, no core service.
    #[test]
    fn a_third_party_overlay_cannot_extend_or_redefine_core() {
        let ext = OWN.replace("    image: ${NOO_ADDON_IMAGE_RHADDON:-x}\n", "    extends:\n      file: docker-compose.cluster.yml\n      service: gateway\n");
        assert!(check_overlay("rhaddon", &ext, &peer(), true, &core()).unwrap_err().contains("extends a service of another compose file"));
        let redefine = format!("{OWN}  gateway:\n    image: evil\n");
        assert!(check_overlay("rhaddon", &redefine, &peer(), true, &core()).unwrap_err().contains("defines service `gateway`, which is core's"));
        // An add-on the CLI ships keeps both (trellion-intel extends trellion,
        // evolve mounts its routes into the gateway).
        assert!(check_overlay("rhaddon", &ext, &peer(), false, &core()).is_ok());
        assert!(check_overlay("rhaddon", &redefine, &peer(), false, &core()).is_ok());
    }

    /// The first-party overlays as their repos ship them (trimmed to what the
    /// guard reads): each takes only its own, through every form it uses.
    #[test]
    fn the_shipped_addon_overlays_pass() {
        let base = "services:\n  trellion:\n    image: t\n  gateway:\n    image: g\nsecrets:\n  noo_bus_key_trellion_intel:\n    file: ${NOO_SECRET_RUNDIR:-/x}/noo_bus_key_trellion_intel\n    x-noo-source: NOO_BUS_KEY_TRELLION_INTEL\n  pgpass_trellion:\n    file: ${NOO_SECRET_RUNDIR:-/x}/pgpass_trellion\n    x-noo-source: NOO_PGPASS_TRELLION\n";
        let core = Core::from_texts(&[base.to_string()]).unwrap().with_tables();
        let intel = "x-noo-addon:\n  addon: trellion_intel\n  consumer: svc:trellion-intel\n  key: NOO_SVC_KEY_TRELLION_INTEL\n  containers: [noo-trellion-intel]\n  scopes: [chat]\n  nats_principal: trellion_intel\nsecrets:\n  noo_svc_key_trellion_intel:\n    file: ${NOO_SECRET_RUNDIR:-/n}/noo_svc_key_trellion_intel\n    x-noo-source: NOO_SVC_KEY_TRELLION_INTEL\n  nats_trellion_intel_password:\n    file: ${NOO_SECRET_RUNDIR:-/n}/nats_trellion_intel_password\n    x-noo-source: NATS_TRELLION_INTEL_PASSWORD\nservices:\n  trellion:\n    environment:\n      TRELLION_BACKGROUND_WORKERS: '0'\n  trellion-intel:\n    extends:\n      file: docker-compose.trellion.yml\n      service: trellion\n    profiles: !reset []\n    build: !reset null\n    image: ${NOO_ADDON_IMAGE_TRELLION_INTEL:-x}\n    container_name: ${NOO_CONTAINER_PREFIX:-noo}-trellion-intel\n    environment:\n      NOO_GATEWAY_KEY_FILE: '${NOO_SVC_KEY_TRELLION_INTEL:+/run/secrets/noo_gateway_key}'\n      NOO_BUS_KEY_FILE: '${NOO_BUS_KEY_TRELLION_INTEL:+/run/secrets/noo_bus_key}'\n      NATS_ADDON_PASSWORD_FILE: '${NATS_TRELLION_INTEL_PASSWORD:+/run/secrets/nats_addon_password}'\n    secrets:\n      - { source: noo_svc_key_trellion_intel, target: noo_gateway_key, uid: \"65532\", gid: \"65532\", mode: 0400 }\n      - { source: noo_bus_key_trellion_intel, target: noo_bus_key, uid: \"65532\", gid: \"65532\", mode: 0400 }\n      - { source: nats_trellion_intel_password, target: nats_addon_password, uid: \"65532\", gid: \"65532\", mode: 0400 }\n    volumes:\n      - ${NOO_PKI_DIR:-./.pki-placeholder}/services/trellion-intel:/app/pki/leaf:ro\n";
        let c = check_overlay("trellion_intel", intel, &[], false, &core).unwrap();
        assert_eq!((c.declared, c.referenced), (2, 3));
        let evolve = "x-noo-addon:\n  addon: evolve\n  consumer: svc:evolve\n  key: NOO_SVC_KEY_EVOLVE\n  containers: [noo-evolve]\n  scopes: [chat]\nsecrets:\n  noo_svc_key_evolve:\n    environment: NOO_SVC_KEY_EVOLVE\n  pgpass_evolve:\n    environment: NOO_PGPASS_EVOLVE\nservices:\n  gateway:\n    volumes:\n      - evolve-routes-65532:/opt/noo/addon-routes/evolve:ro\n  noo-evolve:\n    image: ${NOO_ADDON_IMAGE_EVOLVE:-x}\n    secrets:\n      - { source: noo_svc_key_evolve, target: noo_gateway_key }\n      - { source: pgpass_evolve, target: pgpass }\n    environment:\n      - PGPASSFILE=${NOO_PGPASS_EVOLVE:+/run/secrets/pgpass}\n      - NOO_GATEWAY_KEY_FILE=${NOO_SVC_KEY_EVOLVE:+/run/secrets/noo_gateway_key}\n      - NOO_TLS_CA=${NOO_TLS_CA:+/tls/ca.crt}\n      - NOO_EVOLVE_CONTROLLER_HOSTNAME=${NODE_ID:-controller}\n";
        let c = check_overlay("evolve", evolve, &[], false, &core).unwrap();
        assert_eq!((c.declared, c.referenced), (2, 2));
        assert!(c.interpolated >= 5);
    }

    /// Gap 2's name rule: every name derived from a third-party add-on's
    /// name must be free in core. Reverting `name_collision` to `None` fails
    /// every refused case.
    #[test]
    fn a_name_core_already_uses_is_refused_and_a_free_one_is_not() {
        let c = core();
        for (name, needle) in [
            ("prometheus", "`prometheus` is a core service"),
            ("gateway", "`gateway` is a core service"),
            ("noo-gateway", "`noo-gateway` is a core service"),
            ("app", "database role would be `noo_app`"),
            ("trellion-ddl", "database role would be `noo_trellion_ddl`"),
            ("worker", "core service"),
        ] {
            let why = name_collision(name, &c).unwrap_or_else(|| panic!("{name} should collide"));
            assert!(why.contains(needle), "{why:?} should mention {needle:?}");
        }
        // An add-on whose derived key is a variable core reads is refused too.
        let mut c2 = c.clone();
        c2.compose_vars.insert("NOO_SVC_KEY_MAILER".into());
        assert!(name_collision("mailer", &c2).unwrap().contains("NOO_SVC_KEY_MAILER"));
        for free in ["rh-addon-two", "mailer", "noomail"] {
            assert_eq!(name_collision(free, &c), None, "{free}");
        }
        // Through the bundle check: refused before the overlay is even read,
        // for a third-party add-on only.
        let files = BTreeMap::from([("docker-compose.yml".to_string(), b"services: {}\n".to_vec())]);
        let e = check_bundle_files("grafana", &files, true, &c).unwrap_err();
        assert!(e.contains("grafana") && e.contains("core service") && e.contains("Nothing was changed"), "{e}");
        assert!(check_bundle_files("grafana", &files, false, &c).is_ok());
    }

    fn plain_core() -> Core {
        Core::from_texts(&["services:\n  gateway:\n    image: g\nvolumes:\n  pgdata:\n  noo-models:\n".to_string()]).unwrap().with_tables()
    }

    const RUNTIME_OK: &str = "volumes:\n  rh-cache:\nservices:\n  noo-rhaddon:\n    image: x\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    volumes:\n      - ${RHADDON_WORK_DIR:-/nonexistent/rh-work}:/run/rhaddon:ro\n      - rh-cache:/cache\n      - /tmp/anonymous\n      - { type: bind, source: \"${RHADDON_COORD_DIR:?declared}\", target: /run/coord, read_only: true }\n      - { type: volume, source: rh-cache, target: /cache2 }\n      - { type: tmpfs, target: /scratch }\n";

    fn mounts() -> Vec<String> {
        vec!["RHADDON_WORK_DIR".to_string(), "RHADDON_COORD_DIR".to_string()]
    }

    /// The mount gap, third-party only: every way a service could reach the
    /// host is refused, naming the add-on, the service and the mount.
    /// Reverting `check_runtime` (or its call in `check_bundle_files`)
    /// passes every case.
    #[test]
    fn a_third_party_service_reaches_the_host_only_through_its_own_mounts() {
        let c = plain_core();
        assert_eq!(check_runtime("rhaddon", RUNTIME_OK, &mounts(), &c).unwrap(), 6, "every volume entry was read");
        let vol = |line: &str| RUNTIME_OK.replace("      - /tmp/anonymous\n", &format!("      - {line}\n"));
        let svc = |line: &str| RUNTIME_OK.replace("    cap_drop: [ALL]\n", &format!("    cap_drop: [ALL]\n    {line}\n"));
        let cases: Vec<(String, &str)> = vec![
            (vol("${NOO_PKI_DIR:-./.pki}:/pki:ro"), "bind-mounts the host path `${NOO_PKI_DIR:-./.pki}`"),
            (vol("${NOO_DATA_ROOT}/x:/data"), "bind-mounts the host path `${NOO_DATA_ROOT}/x`"),
            (vol("/:/host"), "bind-mounts the host path `/`"),
            (vol("/var/run/docker.sock:/var/run/docker.sock"), "bind-mounts the host path `/var/run/docker.sock`"),
            (vol("~/.ssh:/k"), "bind-mounts the host path `~/.ssh`"),
            (vol("./secrets:/s"), "bind-mounts the host path `./secrets`"),
            (vol("${RHADDON_WORK_DIR:-/home/op}:/w"), "bind-mounts the host path `${RHADDON_WORK_DIR:-/home/op}`"),
            (vol("${RHADDON_UNDECLARED}:/w"), "bind-mounts the host path `${RHADDON_UNDECLARED}`"),
            (vol("{ type: bind, source: /etc, target: /etc }"), "bind-mounts the host path `/etc`"),
            (vol("pgdata:/var/lib/postgresql/data"), "mounts core's volume `pgdata`"),
            (vol("{ type: volume, source: noo-models, target: /m }"), "mounts core's volume `noo-models`"),
            (vol("other:/o"), "mounts volume `other`, which its overlay does not declare"),
            (vol("{ type: npipe, source: x, target: /x }"), "mounts a `npipe` volume"),
            (svc("env_file: ../../.env"), "sets `env_file`"),
            (svc("volumes_from: [noo-gateway]"), "sets `volumes_from`"),
            (svc("cgroup_parent: /"), "sets `cgroup_parent`"),
            (svc("devices: [/dev/sda]"), "asks for host devices"),
            (svc("pid: host"), "sets `pid: host`"),
            (svc("network_mode: host"), "sets `network_mode: host`"),
            (svc("network_mode: service:gateway"), "sets `network_mode: service:gateway`"),
            (svc("network_mode: container:noo-postgres"), "sets `network_mode: container:noo-postgres`"),
            (svc("ipc: host"), "sets `ipc: host`"),
            (svc("userns_mode: host"), "sets `userns_mode: host`"),
            (svc("cap_add: [SYS_ADMIN]"), "adds capabilities"),
            (RUNTIME_OK.replace("[no-new-privileges:true]", "[no-new-privileges:true, seccomp:unconfined]"), "loosens its confinement"),
            (RUNTIME_OK.replace("[no-new-privileges:true]", "[no-new-privileges:true, apparmor=unconfined]"), "loosens its confinement"),
            (RUNTIME_OK.replace("  rh-cache:\n", "  rh-cache:\n    external: true\n    name: noomesh_pgdata\n"), "sets `external`"),
            (RUNTIME_OK.replace("  rh-cache:\n", "  rh-cache:\n    driver_opts: { type: none, o: bind, device: / }\n"), "sets `driver_opts`"),
            (RUNTIME_OK.replace("volumes:\n  rh-cache:\n", "volumes:\n  rh-cache:\n  pgdata:\n"), "declares volume `pgdata`, which is core's"),
            (format!("{RUNTIME_OK}configs:\n  c:\n    file: /etc/shadow\n"), "is read from `file`"),
        ];
        assert_eq!(cases.len(), 30);
        for (text, needle) in cases {
            assert_ne!(text, RUNTIME_OK, "the case did not change the overlay: {needle}");
            let e = check_runtime("rhaddon", &text, &mounts(), &c).unwrap_err();
            assert!(e.starts_with("add-on rhaddon: its ") && e.contains(needle), "{e:?} should name {needle:?}");
            // Through the bundle check, for a third-party add-on only.
            let files = BTreeMap::from([("docker-compose.yml".to_string(), text.clone().into_bytes())]);
            assert!(check_bundle_files("rhaddon", &files, true, &c).is_err(), "{needle}");
            assert!(check_bundle_files("rhaddon", &files, false, &c).is_ok(), "first-party is unchanged: {needle}");
        }
        // A service-level error names the service.
        let e = check_runtime("rhaddon", &svc("pid: host"), &mounts(), &c).unwrap_err();
        assert!(e.contains("service `noo-rhaddon`"), "{e}");
    }

    /// The fixture add-on as its bundle ships it (overlay, resources.json,
    /// system.json) passes as a third-party add-on: its mounts are the ones
    /// its resources.json declares.
    #[test]
    fn the_fixture_bundle_passes_as_third_party() {
        let files = BTreeMap::from([
            ("docker-compose.yml".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/docker-compose.yml").to_vec()),
            ("resources.json".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/resources.json").to_vec()),
            ("system.json".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/system.json").to_vec()),
        ]);
        let c = check_bundle_files("rhaddon", &files, true, &plain_core()).unwrap();
        assert_eq!(c.mounts, 2, "both declared mounts were read");
        // Without its resources.json the same overlay binds host paths.
        let mut bare = files.clone();
        bare.remove("resources.json");
        assert!(check_bundle_files("rhaddon", &bare, true, &plain_core()).unwrap_err().contains("bind-mounts the host path `${RHADDON_WORK_DIR"));
    }

    /// The shipped add-ons stay as they are (first-party: intel binds its PKI
    /// leaf directory, evolve attaches a volume to the gateway); the same
    /// shapes as a third-party add-on are refused.
    #[test]
    fn the_shipped_mount_shapes_pass_first_party_only() {
        let intel = "services:\n  trellion-intel:\n    image: x\n    volumes:\n      - ${NOO_PKI_DIR:-./.pki-placeholder}/services/trellion-intel:/app/pki/leaf:ro\n";
        let evolve = "volumes:\n  evolve-routes-65532:\nservices:\n  noo-evolve:\n    image: x\n    volumes:\n      - ${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt:/tls/ca.crt:ro\n      - ${NOO_PKI_DIR:-./.pki-placeholder}/services/evolve:/tls/services/evolve:ro\n";
        for (addon, text) in [("trellion_intel", intel), ("evolve", evolve)] {
            let files = BTreeMap::from([("docker-compose.yml".to_string(), text.as_bytes().to_vec())]);
            assert!(check_bundle_files(addon, &files, false, &plain_core()).is_ok(), "{addon}");
            assert!(check_runtime(addon, text, &[], &plain_core()).unwrap_err().contains("NOO_PKI_DIR"), "{addon}");
        }
    }

    #[test]
    fn interpolation_is_read_the_way_compose_reads_it() {
        assert_eq!(interpolated_vars("a ${X} $Y ${Z:-${W}} $$NOT ${}"), ["X", "Y", "Z", "W"]);
        assert!(credential_shaped("NOO_SVC_KEY_ANY") && credential_shaped("NATS_NODE_PASSWORD_H8") && credential_shaped("NOO_X_DB_PASSWORD"));
        assert!(!credential_shaped("NOO_PKI_DIR") && !credential_shaped("NODE_ID"));
    }

    #[test]
    fn the_install_core_is_read_from_its_compose_files() {
        let root = std::env::temp_dir().join(format!("noo-guards-core-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("addons/rhaddon")).unwrap();
        assert!(Core::of_install(&root).unwrap_err().contains("no core compose file"), "no core file: refused, not empty");
        std::fs::write(root.join("docker-compose.cluster.yml"), "services:\n  gateway:\n    image: g\n").unwrap();
        std::fs::write(root.join("addons/rhaddon/docker-compose.yml"), "services:\n  noo-rhaddon:\n    image: r\n").unwrap();
        let c = Core::of_install(&root).unwrap();
        assert!(c.services.contains("gateway") && !c.services.contains("noo-rhaddon"), "add-on overlays are not core");
        assert!(c.secret_vars.contains("NOO_JWT_SECRET") || c.secret_vars.contains("POSTGRES_PASSWORD"), "the registry is read");
        let _ = std::fs::remove_dir_all(&root);
    }
}
