// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An add-on's runtime inputs: `resources.json`, a declaration file of its
//! signed bundle (noomesh-internal i239 section 10, slice 1).
//!
//! Core never names an add-on. It produces a small set of GENERIC resource
//! kinds, and the add-on's signed bundle says which ones it wants and where
//! each one goes: an environment variable of its own, or a file in a
//! directory its overlay mounts read-only.
//!
//! ```json
//! {
//!   "format": "noo-addon-resources/1",
//!   "uid": 1000,
//!   "mounts": [{"name": "work", "env": "RHADDON_WORK_DIR", "target": "/run/rhaddon"}],
//!   "resources": [
//!     {"name": "gateway-url", "kind": "gateway", "part": "url", "deliver": {"env": "RHADDON_GATEWAY_URL"}},
//!     {"name": "peer-key", "kind": "shared_secret", "deliver": [{"file": "work/peer-key"}]}
//!   ]
//! }
//! ```
//!
//! | kind | parts | value |
//! |---|---|---|
//! | `gateway` | `url`, `ca`, `public_origin` | [`GATEWAY_URL`]; the cluster CA; the console origin(s) |
//! | `tls_leaf` | `cert`, `key`, `ca` | a service leaf for `hostname` (`noo-<addon>[-<suffix>]`) |
//! | `addon_key` | - | the add-on's outbound key, minted by `noo addons enable` |
//! | `shared_secret` | - | 32 random bytes in the store as [`shared_secret_var`] |
//! | `db` | `url`, `ca`, `cert`, `key`, `passfile` | the RUNTIME role only (needs `system.json`) |
//! | `network` | (`network`: `gateway` or `db`) | a Docker network name (`db` needs `system.json`) |
//!
//! A resource marked `"optional": true` that cannot be produced at launch
//! is skipped with a notice (`notice` line); a required one refuses the
//! add-on. `db` parts are produced together and are never optional.
//!
//! Secret material (`tls_leaf` key, `addon_key`, `shared_secret`, `db` key
//! and passfile) is delivered as a FILE only. Every file is 0400 and every
//! mount directory 0700, both owned by the bundle's `uid` (never 0), on
//! tmpfs ([`rundir`]). Nothing here prints, logs or records a value: the
//! launcher's protocol lines carry environment values only for the parts
//! that are not secret, and the receipt holds names and paths.
//!
//! [`check`] refuses a bundle at `noo addons enable | upgrade | verify`
//! (through `decls::check_bundle`, before anything is pinned). [`plan`] and
//! [`write_generation`] produce the files at launch (`noo addons
//! launch-resources`, `scripts/lib-dist.sh` `addon_resources_materialise`).
//! [`holds`] names the services of a third-party add-on that ask for a GPU,
//! the Docker socket or `privileged`: the launcher never starts those.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

pub const RESOURCES_FILE: &str = "resources.json";
/// The declaration format. A bundle names it in `format`; any other value
/// is refused, so a later format can never be read as this one.
pub const FORMAT: &str = "noo-addon-resources/1";
pub const MAX_FILE_BYTES: usize = 64 * 1024;
pub const MAX_MOUNTS: usize = 8;
pub const MAX_RESOURCES: usize = 64;
pub const MAX_DELIVER: usize = 4;
/// Prefixes no add-on variable may use, whatever its name: core's own.
pub const RESERVED_ENV_PREFIXES: &[&str] = &["NOO_", "COMPOSE_", "DOCKER_"];
/// The gateway as an add-on container on the cluster network reaches it
/// (the same URL the trellion overlay defaults to).
pub const GATEWAY_URL: &str = "https://gateway:8080";
/// The database as the compose DSNs name it (`addon_provision::DB_*`).
pub const DB_HOST: &str = "postgres";
pub const DB_PORT: u16 = 5432;
pub const DB_NAME: &str = "noomesh";
/// A fresh leaf is issued when the stored one has this many days or fewer left.
pub const LEAF_RENEW_DAYS: i64 = 30;
/// The marker the launcher writes into a generation once its files are
/// handed to the add-on's uid. A generation without it is never reused.
pub const COMPLETE_MARKER: &str = ".complete";
pub const RECEIPT_FILE: &str = "receipt.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayPart {
    Url,
    Ca,
    PublicOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafPart {
    Cert,
    Key,
    Ca,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DbPart {
    Url,
    Ca,
    Cert,
    Key,
    Passfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Gateway,
    Db,
}

/// What one resource is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    Gateway(GatewayPart),
    TlsLeaf { hostname: String, part: LeafPart },
    AddonKey,
    SharedSecret,
    Db(DbPart),
    Network(Net),
}

impl What {
    pub fn kind(&self) -> &'static str {
        match self {
            What::Gateway(_) => "gateway",
            What::TlsLeaf { .. } => "tls_leaf",
            What::AddonKey => "addon_key",
            What::SharedSecret => "shared_secret",
            What::Db(_) => "db",
            What::Network(_) => "network",
        }
    }

    /// The part (or network) word, for listings.
    pub fn part(&self) -> Option<&'static str> {
        Some(match self {
            What::Gateway(GatewayPart::Url) | What::Db(DbPart::Url) => "url",
            What::Gateway(GatewayPart::Ca) | What::Db(DbPart::Ca) | What::TlsLeaf { part: LeafPart::Ca, .. } => "ca",
            What::Gateway(GatewayPart::PublicOrigin) => "public_origin",
            What::TlsLeaf { part: LeafPart::Cert, .. } | What::Db(DbPart::Cert) => "cert",
            What::TlsLeaf { part: LeafPart::Key, .. } | What::Db(DbPart::Key) => "key",
            What::Db(DbPart::Passfile) => "passfile",
            What::Network(Net::Gateway) => "gateway",
            What::Network(Net::Db) => "db",
            What::AddonKey | What::SharedSecret => return None,
        })
    }

    /// Secret material: delivered as a file, never in the environment.
    pub fn secret(&self) -> bool {
        matches!(
            self,
            What::TlsLeaf { part: LeafPart::Key, .. } | What::AddonKey | What::SharedSecret | What::Db(DbPart::Key) | What::Db(DbPart::Passfile)
        )
    }
}

/// Where a value goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Env(String),
    /// `<mount>/<path>`: `path` is relative to the mount's directory.
    File { mount: String, path: String },
}

impl Target {
    pub fn describe(&self) -> String {
        match self {
            Target::Env(v) => format!("env {v}"),
            Target::File { mount, path } => format!("file {mount}/{path}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub name: String,
    /// The variable that receives the directory's host path.
    pub env: String,
    /// Where the overlay mounts it in the container (used to write the paths
    /// a `db` URL names).
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub name: String,
    pub what: What,
    pub deliver: Vec<Target>,
    /// Skipped with a notice, not refused, when it cannot be produced.
    pub optional: bool,
}

/// A validated `resources.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resources {
    pub uid: u32,
    pub mounts: Vec<Mount>,
    pub resources: Vec<Resource>,
}

/// What the rest of the bundle says, which some rules need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleFacts {
    /// The bundle declares a database (`system.json`).
    pub has_system: bool,
    /// The store key of the add-on's own gateway key, from its overlay's
    /// `x-noo-addon` block (`NOO_SVC_KEY_*`), when it declares one.
    pub addon_key_var: Option<String>,
}

/// The facts of a bundle, from its files (name to bytes).
pub fn bundle_facts(addon: &str, files: &BTreeMap<String, Vec<u8>>) -> BundleFacts {
    let addon_key_var = files
        .get("docker-compose.yml")
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|t| crate::addon_decl_parse::parse_decl(&format!("{addon}'s overlay"), t, None).ok().flatten())
        .map(|d| d.key);
    BundleFacts { has_system: files.contains_key(super::decls::SYSTEM_FILE), addon_key_var }
}

/// The add-on's own variable prefix: its name upper-cased, `-` as `_`, then `_`.
pub fn env_prefix(addon: &str) -> String {
    format!("{}_", addon.to_ascii_uppercase().replace('-', "_"))
}

/// The store key of a `shared_secret` resource:
/// `NOO_ADDON_SECRET_<ADDON>__<NAME>` (`-` as `_`; the double underscore
/// keeps `a-b`/`c` apart from `a`/`b-c`). Generic: it is derived from the
/// two names, never declared, and core lists no add-on's.
pub fn shared_secret_var(addon: &str, resource: &str) -> String {
    format!(
        "NOO_ADDON_SECRET_{}__{}",
        addon.to_ascii_uppercase().replace('-', "_"),
        resource.to_ascii_uppercase().replace('-', "_")
    )
}

/// The runtime role and its password variable for `addon`'s database.
pub fn db_runtime(addon: &str) -> (String, String) {
    let id = super::decls::system_id(addon);
    (format!("noo_{id}"), super::decls::password_envs(addon).0)
}

fn word_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

/// A variable name an add-on may set: its own prefix, no core prefix.
fn env_rule(addon: &str, var: &str) -> Result<(), String> {
    let prefix = env_prefix(addon);
    let shape = !var.is_empty()
        && var.len() <= 64
        && var.as_bytes()[0].is_ascii_uppercase()
        && var.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
    if !shape {
        return Err(format!("variable {var:?} must be upper-case letters, digits and `_` (at most 64)"));
    }
    if let Some(p) = RESERVED_ENV_PREFIXES.iter().find(|p| var.starts_with(*p)) {
        return Err(format!("variable {var} collides with core's variables ({p}*); use the add-on's own prefix {prefix}"));
    }
    if !var.starts_with(&prefix) || var.len() == prefix.len() {
        return Err(format!("variable {var} must start with the add-on's own prefix {prefix}, so it can never collide with a core variable"));
    }
    Ok(())
}

fn hostname_ok(addon: &str, h: &str) -> bool {
    let base = format!("noo-{}", addon.replace('_', "-"));
    if h.len() > 63 {
        return false;
    }
    if h == base {
        return true;
    }
    let Some(suffix) = h.strip_prefix(&format!("{base}-")) else { return false };
    !suffix.is_empty() && !suffix.ends_with('-') && suffix.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn obj<'a>(v: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a serde_json::Map<String, Value>, String> {
    let m = v.as_object().ok_or_else(|| format!("{what} is not a JSON object"))?;
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{what} has an unknown field `{k}` (allowed: {})", allowed.join(", ")));
    }
    Ok(m)
}

fn req_str<'a>(m: &'a serde_json::Map<String, Value>, k: &str, what: &str) -> Result<&'a str, String> {
    m.get(k).and_then(Value::as_str).ok_or_else(|| format!("{what}: `{k}` is required and must be a string"))
}

fn parse_target(v: &Value, at: &str, mounts: &BTreeMap<String, Mount>) -> Result<Target, String> {
    let m = obj(v, &format!("{at}: a delivery"), &["env", "file"])?;
    match (m.get("env"), m.get("file")) {
        (Some(e), None) => Ok(Target::Env(e.as_str().ok_or_else(|| format!("{at}: `env` must be a string"))?.to_string())),
        (None, Some(f)) => {
            let f = f.as_str().ok_or_else(|| format!("{at}: `file` must be a string"))?;
            let (mount, path) = f.split_once('/').unwrap_or((f, ""));
            if !mounts.contains_key(mount) {
                let names: Vec<&str> = mounts.keys().map(String::as_str).collect();
                return Err(format!(
                    "{at}: file {f:?} is outside the declared mounts ({}); a file is `<mount>/<path>`",
                    if names.is_empty() { "none declared".to_string() } else { names.join(", ") }
                ));
            }
            let segs: Vec<&str> = path.split('/').collect();
            if path.is_empty() || path.len() > 128 || segs.len() > 4 || !segs.iter().all(|s| segment_ok(s)) {
                return Err(format!(
                    "{at}: file {f:?} must name a path inside mount {mount} (segments of letters, digits, `.`, `_`, `-`, \
                     not starting with `.`; at most 4 deep)"
                ));
            }
            Ok(Target::File { mount: mount.to_string(), path: path.to_string() })
        }
        _ => Err(format!("{at}: a delivery is exactly one of {{\"env\": VAR}} or {{\"file\": \"<mount>/<path>\"}}")),
    }
}

fn parse_what(addon: &str, m: &serde_json::Map<String, Value>, at: &str) -> Result<What, String> {
    let kind = req_str(m, "kind", at)?;
    let allowed: &[&str] = match kind {
        "gateway" => &["name", "kind", "part", "deliver", "optional"],
        "db" => &["name", "kind", "part", "deliver"],
        "tls_leaf" => &["name", "kind", "hostname", "part", "deliver", "optional"],
        "addon_key" | "shared_secret" => &["name", "kind", "deliver", "optional"],
        "network" => &["name", "kind", "network", "deliver", "optional"],
        other => {
            return Err(format!(
                "{at}: kind {other:?} is not one core produces (gateway, tls_leaf, addon_key, shared_secret, db, network)"
            ))
        }
    };
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{at}: kind {kind} has no field `{k}` (allowed: {})", allowed.join(", ")));
    }
    let part = || req_str(m, "part", at);
    let bad_part = |p: &str, ok: &str| format!("{at}: kind {kind} has no part {p:?} (one of {ok})");
    Ok(match kind {
        "gateway" => What::Gateway(match part()? {
            "url" => GatewayPart::Url,
            "ca" => GatewayPart::Ca,
            "public_origin" => GatewayPart::PublicOrigin,
            p => return Err(bad_part(p, "url, ca, public_origin")),
        }),
        "tls_leaf" => {
            let hostname = req_str(m, "hostname", at)?.to_string();
            if !hostname_ok(addon, &hostname) {
                let base = format!("noo-{}", addon.replace('_', "-"));
                return Err(format!("{at}: hostname {hostname:?} must be {base} or {base}-<suffix> (the add-on's own names only)"));
            }
            let part = match part()? {
                "cert" => LeafPart::Cert,
                "key" => LeafPart::Key,
                "ca" => LeafPart::Ca,
                p => return Err(bad_part(p, "cert, key, ca")),
            };
            What::TlsLeaf { hostname, part }
        }
        "addon_key" => What::AddonKey,
        "shared_secret" => What::SharedSecret,
        "db" => What::Db(match part()? {
            "url" => DbPart::Url,
            "ca" => DbPart::Ca,
            "cert" => DbPart::Cert,
            "key" => DbPart::Key,
            "passfile" => DbPart::Passfile,
            p => return Err(bad_part(p, "url, ca, cert, key, passfile")),
        }),
        _ => What::Network(match req_str(m, "network", at)? {
            "gateway" => Net::Gateway,
            "db" => Net::Db,
            n => return Err(format!("{at}: network {n:?} is not one core hands out (gateway, db)")),
        }),
    })
}

/// Parse and validate `resources.json` for `addon`. `Err` refuses the bundle.
pub fn parse(addon: &str, bytes: &[u8], facts: &BundleFacts) -> Result<Resources, String> {
    let what = format!("{RESOURCES_FILE} of add-on {addon}");
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("{what} is larger than {MAX_FILE_BYTES} bytes"));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("{what} is not JSON: {e}"))?;
    let top = obj(&v, &what, &["format", "uid", "mounts", "resources"])?;
    match top.get("format").and_then(Value::as_str) {
        Some(FORMAT) => {}
        Some(f) => return Err(format!("{what}: format {f:?} is not one this CLI reads ({FORMAT})")),
        None => return Err(format!("{what}: `format` is required and must be {FORMAT:?}")),
    }
    let uid = match top.get("uid") {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(0) => return Err(format!("{what}: uid 0 (root) is refused; declare the non-root uid the add-on's services run as")),
            Some(u) if u < u64::from(u32::MAX) => u as u32,
            _ => return Err(format!("{what}: `uid` must be a non-root uid (1 to {})", u32::MAX - 1)),
        },
        _ => return Err(format!("{what}: `uid` is required: the uid the add-on's services run as (never 0)")),
    };
    let mut mounts: BTreeMap<String, Mount> = BTreeMap::new();
    let mut envs: BTreeSet<String> = BTreeSet::new();
    let mlist = match top.get("mounts") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err(format!("{what}: `mounts` must be an array")),
    };
    if mlist.len() > MAX_MOUNTS {
        return Err(format!("{what} declares {} mounts (at most {MAX_MOUNTS})", mlist.len()));
    }
    for item in &mlist {
        let m = obj(item, &format!("{what}: a mount"), &["name", "env", "target"])?;
        let name = req_str(m, "name", &what)?.to_string();
        let at = format!("{what}, mount {name:?}");
        if !word_ok(&name) {
            return Err(format!("{at}: the name must be lowercase letters, digits and `-`, starting with a letter, at most 32"));
        }
        let env = req_str(m, "env", &at)?.to_string();
        env_rule(addon, &env).map_err(|e| format!("{at}: {e}"))?;
        let target = req_str(m, "target", &at)?.to_string();
        let segs: Vec<&str> = target.strip_prefix('/').unwrap_or("").split('/').collect();
        if !target.starts_with('/') || target.len() > 128 || !segs.iter().all(|s| segment_ok(s)) || matches!(segs[0], "proc" | "sys" | "dev") {
            return Err(format!("{at}: target {target:?} must be an absolute container path (not /, /proc, /sys or /dev)"));
        }
        if !envs.insert(env.clone()) {
            return Err(format!("{at}: variable {env} is declared twice"));
        }
        if mounts.insert(name.clone(), Mount { name: name.clone(), env, target }).is_some() {
            return Err(format!("{at}: the mount is declared twice"));
        }
    }
    let rlist = top.get("resources").and_then(Value::as_array).ok_or_else(|| format!("{what}: `resources` must be an array"))?;
    if rlist.len() > MAX_RESOURCES {
        return Err(format!("{what} declares {} resources (at most {MAX_RESOURCES})", rlist.len()));
    }
    let (mut names, mut files, mut db_parts, mut out) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), Vec::new());
    for item in rlist {
        let m = item.as_object().ok_or_else(|| format!("{what}: a resource is not a JSON object"))?;
        let name = req_str(m, "name", &what)?.to_string();
        let at = format!("{what}, resource {name:?}");
        if !word_ok(&name) {
            return Err(format!("{what}: resource name {name:?} must be lowercase letters, digits and `-`, starting with a letter, at most 32"));
        }
        if !names.insert(name.clone()) {
            return Err(format!("{at}: the name is declared twice"));
        }
        let w = parse_what(addon, m, &at)?;
        let optional = match m.get("optional") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(format!("{at}: `optional` must be true or false")),
        };
        let raw = m.get("deliver").ok_or_else(|| format!("{at}: `deliver` is required"))?;
        let list: Vec<Value> = match raw {
            Value::Array(a) => a.clone(),
            one => vec![one.clone()],
        };
        if list.is_empty() || list.len() > MAX_DELIVER {
            return Err(format!("{at}: `deliver` names 1 to {MAX_DELIVER} destinations"));
        }
        let mut deliver = Vec::new();
        for d in &list {
            let t = parse_target(d, &at, &mounts)?;
            match &t {
                Target::Env(v) => {
                    if w.secret() {
                        return Err(format!(
                            "{at}: {} is secret material and is delivered as a file only, never in the environment",
                            describe(&w)
                        ));
                    }
                    env_rule(addon, v).map_err(|e| format!("{at}: {e}"))?;
                    if !envs.insert(v.clone()) {
                        return Err(format!("{at}: variable {v} is declared twice"));
                    }
                }
                Target::File { mount, path } => {
                    if !files.insert(format!("{mount}/{path}")) {
                        return Err(format!("{at}: file {mount}/{path} is delivered twice"));
                    }
                }
            }
            deliver.push(t);
        }
        match &w {
            What::Db(_) | What::Network(Net::Db) if !facts.has_system => {
                return Err(format!(
                    "{at}: {} needs the bundle to declare its database (system.json)",
                    describe(&w)
                ))
            }
            What::AddonKey if facts.addon_key_var.is_none() => {
                return Err(format!(
                    "{at}: addon_key needs the overlay to declare the add-on's key (x-noo-addon with key: NOO_SVC_KEY_*)"
                ))
            }
            What::Db(p) if !db_parts.insert(*p) => {
                return Err(format!("{at}: db part {} is declared twice", w.part().unwrap_or("")))
            }
            _ => {}
        }
        out.push(Resource { name, what: w, deliver, optional });
    }
    let res = Resources { uid, mounts: mounts.into_values().collect(), resources: out };
    if db_parts.contains(&DbPart::Url) {
        db_url_paths(&res).map_err(|e| format!("{what}: {e}"))?;
    }
    Ok(res)
}

fn describe(w: &What) -> String {
    match w.part() {
        Some(p) => format!("{} {p}", w.kind()),
        None => w.kind().to_string(),
    }
}

/// The container paths a `db` URL names: `(sslrootcert, sslcert, sslkey,
/// passfile)`. Each part must be delivered as a file; when the URL itself is
/// delivered as a file, into the SAME mount (the reader of the URL must see
/// the files it names).
pub fn db_url_paths(res: &Resources) -> Result<[String; 4], String> {
    let mount_of = |name: &str| res.mounts.iter().find(|m| m.name == name);
    let url = res.resources.iter().find(|r| r.what == What::Db(DbPart::Url)).ok_or("no db url is declared")?;
    let home = url.deliver.iter().find_map(|t| match t {
        Target::File { mount, .. } => Some(mount.clone()),
        Target::Env(_) => None,
    });
    let mut out: [String; 4] = Default::default();
    for (i, part) in [DbPart::Ca, DbPart::Cert, DbPart::Key, DbPart::Passfile].into_iter().enumerate() {
        let word = What::Db(part).part().unwrap_or("");
        let r = res
            .resources
            .iter()
            .find(|r| r.what == What::Db(part))
            .ok_or_else(|| format!("the db url names its {word}, so a `db` resource with part {word:?} must be declared"))?;
        let files: Vec<(&String, &String)> = r
            .deliver
            .iter()
            .filter_map(|t| match t {
                Target::File { mount, path } => Some((mount, path)),
                Target::Env(_) => None,
            })
            .collect();
        let pick = match &home {
            Some(h) => files.iter().find(|(m, _)| *m == h).copied().ok_or_else(|| {
                format!("db {word} ({}) must be delivered into mount {h}, where the db url that names it is read", r.name)
            })?,
            None => *files.first().ok_or_else(|| format!("db {word} ({}) must be delivered as a file", r.name))?,
        };
        let m = mount_of(pick.0).ok_or("a delivery names an undeclared mount")?;
        out[i] = format!("{}/{}", m.target.trim_end_matches('/'), pick.1);
    }
    Ok(out)
}

/// The URL itself (no password: libpq reads it from the passfile).
pub fn db_url(addon: &str, paths: &[String; 4]) -> String {
    let (role, _) = db_runtime(addon);
    format!(
        "postgresql://{role}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode=verify-full&sslrootcert={}&sslcert={}&sslkey={}&passfile={}",
        paths[0], paths[1], paths[2], paths[3]
    )
}

/// The variables a core compose file reads (`${VAR`), from the texts of the
/// install root's `docker-compose*.yml`. An add-on variable among them is
/// refused at launch: exported for the add-on, it would change core.
pub fn core_compose_vars(texts: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for t in texts {
        let mut rest = t.as_str();
        while let Some(i) = rest.find("${") {
            rest = &rest[i + 2..];
            let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

/// Every variable `res` sets (mount directories and environment deliveries).
pub fn declared_vars(res: &Resources) -> Vec<String> {
    let mut v: Vec<String> = res.mounts.iter().map(|m| m.env.clone()).collect();
    for r in &res.resources {
        for t in &r.deliver {
            if let Target::Env(e) = t {
                v.push(e.clone());
            }
        }
    }
    v
}

// ── launch: the values ──────────────────────────────────────────────────

/// Where the values come from. [`LiveSources`] is the production one; the
/// tests fake it, so [`plan`] is pure over it.
pub trait Sources {
    /// The cluster CA certificate (PEM).
    fn ca(&mut self) -> Result<Vec<u8>, String>;
    /// `(cert, key)` PEM of the leaf for `hostname`, issued when absent or close to expiry.
    fn leaf(&mut self, addon: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// `(cert, key)` PEM of the add-on's database client leaf
    /// ([`db_client_leaf`]: `CN=addon:<addon>/db-client`).
    fn db_leaf(&mut self, addon: &str, role: &str) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// A value of the encrypted store; `None` when absent or blank.
    fn secret(&mut self, var: &str) -> Option<String>;
    /// The browser origin(s) allowed to reach the add-on (space separated).
    fn public_origins(&mut self) -> Result<String, String>;
    fn network(&mut self, which: Net) -> String;
}

/// Everything one launch hands the add-on: file contents by `(mount, path)`,
/// and the environment. Values live only here and in the files written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub uid: u32,
    pub files: BTreeMap<(String, String), Vec<u8>>,
    /// Non-secret values only (secret parts cannot be delivered by env).
    pub env: Vec<(String, String)>,
    /// `(variable, mount name)`: set to the mount directory's host path.
    pub mounts: Vec<(String, String)>,
    /// One line per optional resource that could not be produced and was
    /// skipped (no value in it).
    pub notices: Vec<String>,
}

fn pgpass_line(role: &str, password: &str) -> String {
    let pw = password.replace('\\', "\\\\").replace(':', "\\:");
    format!("{DB_HOST}:{DB_PORT}:{DB_NAME}:{role}:{pw}\n")
}

/// The values for every declared resource. `Err` names the resource that
/// could not be produced and why; the launcher refuses the add-on with it.
pub fn plan(addon: &str, res: &Resources, facts: &BundleFacts, src: &mut dyn Sources) -> Result<Plan, String> {
    let mut p = Plan { uid: res.uid, ..Plan::default() };
    for m in &res.mounts {
        p.mounts.push((m.env.clone(), m.name.clone()));
    }
    let mut leaves: BTreeMap<String, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut db_leaf: Option<(Vec<u8>, Vec<u8>)> = None;
    let (role, pw_var) = db_runtime(addon);
    for r in &res.resources {
        let at = |e: String| format!("resource {} ({}): {e}", r.name, describe(&r.what));
        let produced = (|| -> Result<Vec<u8>, String> {
            Ok(match &r.what {
                What::Gateway(GatewayPart::Url) => GATEWAY_URL.as_bytes().to_vec(),
                What::Gateway(GatewayPart::Ca) | What::TlsLeaf { part: LeafPart::Ca, .. } | What::Db(DbPart::Ca) => src.ca().map_err(at)?,
                What::Gateway(GatewayPart::PublicOrigin) => src.public_origins().map_err(at)?.into_bytes(),
                What::TlsLeaf { hostname, part } => {
                    if !leaves.contains_key(hostname) {
                        let l = src.leaf(addon, hostname).map_err(at)?;
                        leaves.insert(hostname.clone(), l);
                    }
                    let (c, k) = &leaves[hostname];
                    if *part == LeafPart::Cert { c.clone() } else { k.clone() }
                }
                What::AddonKey => {
                    let var = facts.addon_key_var.clone().ok_or_else(|| at("the overlay declares no add-on key (x-noo-addon)".into()))?;
                    src.secret(&var)
                        .ok_or_else(|| at(format!("{var} is not in the encrypted store; `noo addons enable {addon}` mints it")))?
                        .into_bytes()
                }
                What::SharedSecret => {
                    let var = shared_secret_var(addon, &r.name);
                    src.secret(&var)
                        .ok_or_else(|| at(format!("{var} is not in the encrypted store; `noo addons enable {addon}` mints it")))?
                        .into_bytes()
                }
                What::Db(DbPart::Url) => db_url(addon, &db_url_paths(res).map_err(at)?).into_bytes(),
                What::Db(part @ (DbPart::Cert | DbPart::Key)) => {
                    if db_leaf.is_none() {
                        db_leaf = Some(src.db_leaf(addon, &role).map_err(at)?);
                    }
                    let (c, k) = db_leaf.as_ref().expect("just set");
                    if *part == DbPart::Cert { c.clone() } else { k.clone() }
                }
                What::Db(DbPart::Passfile) => {
                    let pw = src.secret(&pw_var).ok_or_else(|| {
                        at(format!("{pw_var} is not in the encrypted store; `noo addons enable {addon} --provision-only` creates the database and mints it"))
                    })?;
                    pgpass_line(&role, &pw).into_bytes()
                }
                What::Network(n) => src.network(*n).into_bytes(),
            })
        })();
        let value = match produced {
            Ok(v) => v,
            Err(e) if r.optional => {
                p.notices.push(format!("{e} (optional: skipped, nothing delivered)"));
                continue;
            }
            Err(e) => return Err(e),
        };
        for t in &r.deliver {
            match t {
                Target::Env(v) => {
                    let s = String::from_utf8(value.clone()).map_err(|_| at("the value is not text".into()))?;
                    if s.contains('\n') || s.contains('\r') {
                        return Err(at("the value spans lines and cannot be an environment value".into()));
                    }
                    p.env.push((v.clone(), s));
                }
                Target::File { mount, path } => {
                    p.files.insert((mount.clone(), path.clone()), value.clone());
                }
            }
        }
    }
    Ok(p)
}

/// A short digest over everything a plan writes: the generation's name. The
/// same inputs (store, leaves, declaration) give the same generation, so a
/// launch that changes nothing writes nothing and a running add-on keeps its
/// files.
pub fn generation(p: &Plan) -> String {
    let mut buf: Vec<u8> = format!("uid {}\n", p.uid).into_bytes();
    for ((m, path), v) in &p.files {
        buf.extend_from_slice(format!("file {m}/{path} {}\n", v.len()).as_bytes());
        buf.extend_from_slice(v);
    }
    let hex = super::pins::sha256_hex(&buf);
    format!("g-{}", &hex[..16])
}

/// The per-add-on base directory: `$NOO_ADDON_RUNDIR`, else
/// `/run/noo/addons` as root, else `/dev/shm/noo-addons-<uid>`. Pure.
pub fn rundir(env_override: Option<&str>, euid: u32) -> PathBuf {
    match env_override.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => PathBuf::from(d),
        None if euid == 0 => PathBuf::from("/run/noo/addons"),
        None => PathBuf::from(format!("/dev/shm/noo-addons-{euid}")),
    }
}

/// What [`write_generation`] did, by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub gen_dir: PathBuf,
    /// `(variable, host path)` per mount.
    pub mounts: Vec<(String, PathBuf)>,
    /// True when the files were written now (the launcher hands them to the
    /// uid, then marks the generation complete); false when reused.
    pub fresh: bool,
    /// Older generations of this add-on, for the launcher to remove.
    pub stale: Vec<PathBuf>,
}

/// Write `p` under `<base>/<addon>/<generation>/<mount>/…`: directories
/// 0700, files 0400, all still owned by this process (the launcher hands the
/// mount directories to `p.uid`). A generation already marked complete is
/// reused untouched. `base` must be on tmpfs (checked by the caller).
pub fn write_generation(base: &Path, addon: &str, res: &Resources, p: &Plan) -> Result<Written, String> {
    use crate::commands::addon_provision::{private_dir, write_private};
    let addon_dir = base.join(addon);
    private_dir(&addon_dir)?;
    let gen = generation(p);
    let gen_dir = addon_dir.join(&gen);
    let mounts: Vec<(String, PathBuf)> = p.mounts.iter().map(|(var, m)| (var.clone(), gen_dir.join(m))).collect();
    let stale: Vec<PathBuf> = std::fs::read_dir(&addon_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("g-") && n != gen))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    if gen_dir.join(COMPLETE_MARKER).is_file() {
        return Ok(Written { gen_dir, mounts, fresh: false, stale });
    }
    if gen_dir.exists() {
        // Written by an earlier launch that never finished handing it over.
        std::fs::remove_dir_all(&gen_dir).map_err(|e| {
            format!("{} is a partial generation that could not be removed ({e}); remove it as root and start again", gen_dir.display())
        })?;
    }
    private_dir(&gen_dir)?;
    for m in &res.mounts {
        private_dir(&gen_dir.join(&m.name))?;
    }
    for ((m, path), bytes) in &p.files {
        let dest = gen_dir.join(m).join(path);
        let dir = dest.parent().ok_or("a file path has no directory")?;
        private_dir(dir)?;
        let name = dest.file_name().and_then(|n| n.to_str()).ok_or("a file path has no name")?;
        write_private(dir, name, bytes, 0o400)?;
    }
    Ok(Written { gen_dir, mounts, fresh: true, stale })
}

/// The receipt: names, kinds, destinations and paths. No value is a field
/// of anything it reads, so none can reach it.
pub fn receipt(addon: &str, res: &Resources, w: &Written) -> Value {
    serde_json::json!({
        "addon": addon,
        "uid": res.uid,
        "generation": w.gen_dir.display().to_string(),
        "mounts": res.mounts.iter().map(|m| serde_json::json!({
            "name": m.name,
            "env": m.env,
            "target": m.target,
            "host_path": w.gen_dir.join(&m.name).display().to_string(),
        })).collect::<Vec<_>>(),
        "resources": listing(res),
    })
}

/// `{name, kind, part?, deliver: [...]}` per resource: what `noo addons
/// show` and the receipt print. Names and destinations only.
pub fn listing(res: &Resources) -> Vec<Value> {
    res.resources
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "kind": r.what.kind(),
                "part": r.what.part(),
                "hostname": match &r.what { What::TlsLeaf { hostname, .. } => Some(hostname.clone()), _ => None },
                "secret": r.what.secret(),
                "deliver": r.deliver.iter().map(Target::describe).collect::<Vec<_>>(),
            })
        })
        .collect()
}

// ── holds: what a third-party add-on never starts ───────────────────────

/// `(service, why)` for every service of an overlay that asks for a GPU, the
/// Docker socket or `privileged`. The launcher scales those to zero for a
/// third-party add-on and `noo stack restart <name>` refuses them by name:
/// a GPU needs a reservation path core does not have for add-ons yet.
/// Since 0.6.13 a third-party overlay that bind-mounts the Docker socket, or
/// asks for `devices:`, is REFUSED before this runs (`guards::check_runtime`,
/// no host bind mounts); what is left to hold is a GPU reservation (`gpus`,
/// `runtime: nvidia`, `deploy…devices`) and `privileged`.
pub fn holds(overlay: &str) -> Result<Vec<(String, String)>, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(overlay).map_err(|e| format!("the overlay is not valid YAML ({e})"))?;
    let mut out = Vec::new();
    let Some(services) = doc.get("services").and_then(|s| s.as_mapping()) else { return Ok(out) };
    for (k, svc) in services {
        let Some(name) = k.as_str() else { continue };
        let mut why: Vec<&str> = Vec::new();
        if svc.get("gpus").is_some() || svc.get("runtime").and_then(|r| r.as_str()) == Some("nvidia") {
            why.push("asks for a GPU");
        }
        let devices_reserved = svc
            .get("deploy")
            .and_then(|d| d.get("resources"))
            .and_then(|r| r.get("reservations"))
            .and_then(|r| r.get("devices"))
            .is_some();
        let gpu_device = svc
            .get("devices")
            .and_then(|d| d.as_sequence())
            .is_some_and(|s| s.iter().any(|d| d.as_str().is_some_and(|d| d.contains("nvidia") || d.contains("/dev/dri"))));
        if (devices_reserved || gpu_device) && !why.contains(&"asks for a GPU") {
            why.push("asks for a GPU");
        }
        let socket = svc.get("volumes").and_then(|v| v.as_sequence()).is_some_and(|vols| {
            vols.iter().any(|v| {
                v.as_str().is_some_and(|s| s.contains("docker.sock"))
                    || v.get("source").and_then(|s| s.as_str()).is_some_and(|s| s.contains("docker.sock"))
            })
        });
        if socket {
            why.push("mounts the Docker socket");
        }
        if svc.get("privileged").and_then(|p| p.as_bool()) == Some(true) {
            why.push("is privileged");
        }
        if !why.is_empty() {
            out.push((name.to_string(), why.join(", ")));
        }
    }
    Ok(out)
}

// ── the live sources ────────────────────────────────────────────────────

pub struct LiveSources<'a> {
    pub ca: &'a crate::pki::ClusterCa,
    pub store: &'a crate::commands::secrets::SecretStore,
    pub project: String,
    pub cluster_network: String,
    /// `NOO_CONSOLE_ORIGIN`, as the launcher's environment or `.env` has it.
    pub console_origin: Option<String>,
    /// `NOO_PORT_GATEWAY`, else 8080.
    pub gateway_port: String,
}

fn days_left(cert: &Path) -> Option<i64> {
    let data = std::fs::read(cert).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data).ok()?;
    let c = pem.parse_x509().ok()?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Some((c.validity().not_after.timestamp() - now).div_euclid(86_400))
}

fn cert_cn(cert: &Path) -> Option<String> {
    let data = std::fs::read(cert).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data).ok()?;
    let c = pem.parse_x509().ok()?;
    let cn = c.subject().iter_common_name().next()?.as_str().ok()?.trim().to_string();
    Some(cn)
}

/// `(cert, key)` PEM of `addon`'s leaf `stem`, issued when absent, close to
/// expiry, or carrying any CN but [`crate::pki::addon_leaf_cn`] (a leaf
/// issued before 0.6.13 is re-issued under the add-on namespace here).
fn leaf_pair(ca: &crate::pki::ClusterCa, addon: &str, stem: &str, dns: &[String]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if !ca.ca_exists() {
        return Err("this controller has no cluster CA to issue the leaf from (`noo security pki init`)".into());
    }
    let (cert, key) = ca.addon_leaf_paths(addon, stem);
    let fresh = days_left(&cert).is_some_and(|d| d > LEAF_RENEW_DAYS)
        && key.is_file()
        && cert_cn(&cert).as_deref() == Some(crate::pki::addon_leaf_cn(addon, stem).as_str());
    if !fresh {
        ca.issue_addon_leaf(addon, stem, dns, crate::pki::DEFAULT_DAYS)?;
    }
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    Ok((read(&cert)?, read(&key)?))
}

/// The leaf stem of an add-on's database client certificate:
/// `pki/addons/<addon>/db-client.crt|key`, `CN=addon:<addon>/db-client`.
pub const DB_CLIENT_STEM: &str = "db-client";

/// `(cert, key)` PEM of `addon`'s database client leaf: the one leaf both the
/// launcher's `db` resource and `noo addons enable --provision-only` hand
/// out. Its only DNS SAN is `pg-<addon>-<role>`, which no door pins on, so
/// it can never pass a hostname check either. Postgres takes it under the
/// `verify-ca` line every add-on role uses (any cluster-CA leaf plus the
/// role's password), so the CN is free to say whose it is.
pub fn db_client_leaf(ca: &crate::pki::ClusterCa, addon: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (role, _) = db_runtime(addon);
    let san = format!("pg-{}-{}", addon.replace('_', "-"), role.replace('_', "-"));
    leaf_pair(ca, addon, DB_CLIENT_STEM, &[san])
}

/// The leaf `noo addons enable --provision-only` issued before 0.6.13:
/// `pki/services/<addon>/service.{crt,key}`, `CN=<addon>`, a key the reader
/// table did not name (so 0644). Retired by [`retire_legacy_leaf`].
pub fn legacy_leaf_dir(ca: &crate::pki::ClusterCa, addon: &str) -> Option<PathBuf> {
    // A leaf core issues (onboard's SVC_LIST, the reader table) is core's,
    // whatever add-on shares its name: never touched here.
    if crate::pki::SERVICE_KEY_READERS.iter().any(|(svc, _)| *svc == addon) {
        return None;
    }
    let dir = ca.dir.join("services").join(addon);
    let cert = dir.join("service.crt");
    if !cert.is_file() && !dir.join("service.key").exists() {
        return None;
    }
    // Only the shape provision-only wrote: CN = the bare add-on name. A leaf
    // an operator issued by hand under another CN is not ours to remove.
    match cert_cn(&cert) {
        Some(cn) if cn == addon => Some(dir),
        None if !cert.exists() => Some(dir),
        _ => None,
    }
}

/// Re-issue `addon`'s database client leaf under the add-on namespace and
/// retire the pre-0.6.13 `services/<addon>/` leaf: the new leaf is issued
/// FIRST, `provision_dir` (the runner's credential directory, when it has
/// one) gets the new pair, and only then is the old directory removed and
/// the gateway's certificate view re-synced. `Ok(None)` when there is
/// nothing to retire. The old certificate stays cryptographically valid
/// until it expires (the cluster CA keeps no revocation list); it holds no
/// grant (`CN=<addon>` is no core service: `noo addons enable` refuses an
/// add-on named like one).
pub fn retire_legacy_leaf(ca: &crate::pki::ClusterCa, addon: &str, provision_dir: Option<&Path>) -> Result<Option<String>, String> {
    let Some(old) = legacy_leaf_dir(ca, addon) else { return Ok(None) };
    let (cert, key) = db_client_leaf(ca, addon)?;
    if let Some(dir) = provision_dir.filter(|d| d.join(crate::commands::addon_provision::CERT_FILE).is_file()) {
        use crate::commands::addon_provision::{write_private, CERT_FILE, KEY_FILE};
        write_private(dir, CERT_FILE, &cert, 0o444)?;
        write_private(dir, KEY_FILE, &key, 0o400)?;
    }
    std::fs::remove_dir_all(&old).map_err(|e| {
        format!("{} could not be removed ({e}); its new leaf is issued, remove the old one by hand: rm -r {}", old.display(), old.display())
    })?;
    let _ = ca.sync_public_view();
    Ok(Some(format!(
        "{addon}: its client certificate is now {} (pki/addons/{addon}/{DB_CLIENT_STEM}.crt); the old pki/services/{addon}/ leaf (CN={addon}) is retired",
        crate::pki::addon_leaf_cn(addon, DB_CLIENT_STEM)
    )))
}

impl Sources for LiveSources<'_> {
    fn ca(&mut self) -> Result<Vec<u8>, String> {
        std::fs::read(self.ca.ca_cert_path()).map_err(|e| format!("the cluster CA certificate could not be read ({e})"))
    }

    fn leaf(&mut self, addon: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        leaf_pair(self.ca, addon, hostname, &[hostname.to_string()])
    }

    fn db_leaf(&mut self, addon: &str, _role: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        db_client_leaf(self.ca, addon)
    }

    fn secret(&mut self, var: &str) -> Option<String> {
        self.store.get(var).filter(|v| !v.trim().is_empty()).map(str::to_string)
    }

    fn public_origins(&mut self) -> Result<String, String> {
        let valid = |o: &str| o.starts_with("https://") && o.len() > 8 && o[8..].bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
        if let Some(v) = self.console_origin.as_deref().filter(|v| !v.trim().is_empty()) {
            let list: Vec<&str> = v.split([',', ' ']).map(str::trim).filter(|o| !o.is_empty()).collect();
            if let Some(bad) = list.iter().find(|o| !valid(o)) {
                return Err(format!("NOO_CONSOLE_ORIGIN holds {bad:?}, which is not an https:// origin"));
            }
            return Ok(list.join(" "));
        }
        // The gateway's own default (addon_ui.rs `csp_for`): this host on
        // 443 and on the gateway port. The host is the gateway leaf's CN.
        let cn = cert_cn(&self.ca.dir.join("gateway").join("gateway.crt")).filter(|c| !c.is_empty());
        match cn {
            Some(h) => Ok(format!("https://{h} https://{h}:{}", self.gateway_port)),
            None => Err("no console origin is known: set NOO_CONSOLE_ORIGIN (compose_env in noomesh.yaml), or issue the gateway certificate".into()),
        }
    }

    fn network(&mut self, which: Net) -> String {
        match which {
            Net::Gateway => self.cluster_network.clone(),
            Net::Db => format!("{}_noo-db", self.project),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ADDON: &str = "rhaddon";

    fn facts() -> BundleFacts {
        BundleFacts { has_system: true, addon_key_var: Some("NOO_SVC_KEY_RHADDON".into()) }
    }

    /// The fixture declaration (tests/fixtures/addons/rhaddon): every kind,
    /// every part, one optional resource. The launcher test and the
    /// rehearsal read the same file.
    pub(crate) fn every_kind() -> Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/addons/rhaddon/resources.json")).expect("fixture is JSON")
    }

    struct Fake;
    impl Sources for Fake {
        fn ca(&mut self) -> Result<Vec<u8>, String> {
            Ok(b"CA-PEM".to_vec())
        }
        fn leaf(&mut self, _: &str, h: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
            Ok((format!("CERT {h}").into_bytes(), b"LEAF-KEY-VALUE".to_vec()))
        }
        fn db_leaf(&mut self, _: &str, role: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
            Ok((format!("CERT {role}").into_bytes(), b"DB-KEY-VALUE".to_vec()))
        }
        fn secret(&mut self, var: &str) -> Option<String> {
            match var {
                "NOO_SVC_KEY_RHADDON" => Some("ADDON-KEY-VALUE".into()),
                "NOO_ADDON_SECRET_RHADDON__PEER_KEY" => Some("PEER-SECRET-VALUE".into()),
                "NOO_RHADDON_DB_PASSWORD" => Some("DB:PASS\\VALUE".into()),
                _ => None,
            }
        }
        fn public_origins(&mut self) -> Result<String, String> {
            Ok("https://ctl.example https://ctl.example:8080".into())
        }
        fn network(&mut self, n: Net) -> String {
            match n {
                Net::Gateway => "noo-cluster".into(),
                Net::Db => "noomesh_noo-db".into(),
            }
        }
    }

    fn bytes(v: &Value) -> Vec<u8> {
        v.to_string().into_bytes()
    }

    #[test]
    fn every_kind_parses_and_plans_with_the_paths_the_url_names() {
        let res = parse(ADDON, &bytes(&every_kind()), &facts()).unwrap();
        assert_eq!(res.uid, 1000);
        assert_eq!(res.resources.len(), 15);
        let p = plan(ADDON, &res, &facts(), &mut Fake).unwrap();
        let url = String::from_utf8(p.files[&("coord".to_string(), "runtime-url".to_string())].clone()).unwrap();
        assert_eq!(
            url,
            "postgresql://noo_rhaddon@postgres:5432/noomesh?sslmode=verify-full&sslrootcert=/run/rhaddon-coord/db/ca.crt\
             &sslcert=/run/rhaddon-coord/db/client.crt&sslkey=/run/rhaddon-coord/db/client.key&passfile=/run/rhaddon-coord/db/pgpass"
        );
        assert_eq!(p.files[&("coord".to_string(), "db/pgpass".to_string())], b"postgres:5432:noomesh:noo_rhaddon:DB\\:PASS\\\\VALUE\n");
        assert_eq!(p.files[&("work".to_string(), "peer-key".to_string())], p.files[&("coord".to_string(), "peer-key".to_string())]);
        let env: BTreeMap<_, _> = p.env.iter().cloned().collect();
        assert_eq!(env["RHADDON_GATEWAY_URL"], GATEWAY_URL);
        assert_eq!(env["RHADDON_DB_NETWORK"], "noomesh_noo-db");
        assert_eq!(env["RHADDON_GATEWAY_NETWORK"], "noo-cluster");
        assert_eq!(p.mounts, vec![("RHADDON_COORD_DIR".into(), "coord".into()), ("RHADDON_WORK_DIR".into(), "work".into())]);
        // No secret is ever an environment value.
        for (_, v) in &p.env {
            for secret in ["ADDON-KEY-VALUE", "PEER-SECRET-VALUE", "LEAF-KEY-VALUE", "DB-KEY-VALUE", "PASS"] {
                assert!(!v.contains(secret), "{v}");
            }
        }
    }

    #[test]
    fn refusals_name_their_reason() {
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(Edit, &str)> = vec![
            (Box::new(|v| v["resources"][0]["kind"] = json!("kubeconfig")), "is not one core produces"),
            (Box::new(|v| v["resources"][1]["deliver"] = json!({"file": "elsewhere/ca.crt"})), "outside the declared mounts"),
            (Box::new(|v| v["resources"][1]["deliver"] = json!({"file": "work/../x"})), "must name a path inside mount"),
            (Box::new(|v| v["resources"][0]["deliver"] = json!({"env": "NOO_JWT_SECRET"})), "collides with core's variables"),
            (Box::new(|v| v["resources"][0]["deliver"] = json!({"env": "POSTGRES_PASSWORD"})), "own prefix RHADDON_"),
            (Box::new(|v| v["mounts"][0]["env"] = json!("DOCKER_HOST")), "collides with core's variables"),
            (Box::new(|v| v["uid"] = json!(0)), "uid 0 (root) is refused"),
            (Box::new(|v| { v.as_object_mut().unwrap().remove("uid"); }), "`uid` is required"),
            (Box::new(|v| v["resources"][7]["deliver"] = json!({"env": "RHADDON_PEER"})), "delivered as a file only"),
            (Box::new(|v| v["resources"][4]["hostname"] = json!("noo-gateway")), "the add-on's own names only"),
            (Box::new(|v| v["resources"][0]["part"] = json!("token")), "has no part"),
            (Box::new(|v| v["resources"][0]["extra"] = json!(1)), "has no field `extra`"),
            (Box::new(|v| v["resources"][10]["deliver"] = json!({"file": "work/client.crt"})), "must be delivered into mount coord"),
            (Box::new(|v| v["resources"][14]["network"] = json!("host")), "not one core hands out"),
            (Box::new(|v| v["mounts"][0]["target"] = json!("/proc/x")), "absolute container path"),
            (Box::new(|v| v["resources"][2]["deliver"] = json!({"env": "RHADDON_GATEWAY_URL"})), "declared twice"),
            (Box::new(|v| v["format"] = json!("noo-addon-resources/2")), "is not one this CLI reads"),
            (Box::new(|v| { v.as_object_mut().unwrap().remove("format"); }), "`format` is required"),
            (Box::new(|v| v["resources"][9]["optional"] = json!(true)), "has no field `optional`"),
        ];
        for (edit, needle) in cases {
            let mut v = every_kind();
            edit(&mut v);
            let e = parse(ADDON, &bytes(&v), &facts()).unwrap_err();
            assert!(e.contains(needle), "{e:?} should mention {needle:?}");
        }
        let no_db = BundleFacts { has_system: false, ..facts() };
        assert!(parse(ADDON, &bytes(&every_kind()), &no_db).unwrap_err().contains("system.json"));
        let no_key = BundleFacts { addon_key_var: None, ..facts() };
        assert!(parse(ADDON, &bytes(&every_kind()), &no_key).unwrap_err().contains("x-noo-addon"));
    }

    #[test]
    fn a_missing_value_names_the_resource_and_the_command_that_mints_it() {
        struct Empty;
        impl Sources for Empty {
            fn ca(&mut self) -> Result<Vec<u8>, String> { Ok(b"CA".to_vec()) }
            fn leaf(&mut self, _: &str, _: &str) -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![], vec![])) }
            fn db_leaf(&mut self, _: &str, _: &str) -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![], vec![])) }
            fn secret(&mut self, _: &str) -> Option<String> { None }
            fn public_origins(&mut self) -> Result<String, String> { Ok("https://x".into()) }
            fn network(&mut self, _: Net) -> String { "n".into() }
        }
        let res = parse(ADDON, &bytes(&every_kind()), &facts()).unwrap();
        // addon-key is optional in the fixture: skipped; peer-key is required.
        let e = plan(ADDON, &res, &facts(), &mut Empty).unwrap_err();
        assert!(e.starts_with("resource peer-key (shared_secret):") && e.contains("noo addons enable rhaddon"), "{e}");
        let only_optional = json!({"format": FORMAT, "uid": 1000, "mounts": [{"name": "w", "env": "RHADDON_W", "target": "/w"}],
            "resources": [{"name": "k", "kind": "addon_key", "optional": true, "deliver": {"file": "w/k"}}]});
        let res = parse(ADDON, &bytes(&only_optional), &facts()).unwrap();
        let p = plan(ADDON, &res, &facts(), &mut Empty).unwrap();
        assert!(p.files.is_empty() && p.notices.len() == 1 && p.notices[0].contains("optional: skipped"), "{:?}", p.notices);
    }

    #[test]
    fn generations_write_private_files_and_are_reused_when_nothing_changed() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = std::env::temp_dir().join(format!("noo-res-gen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let res = parse(ADDON, &bytes(&every_kind()), &facts()).unwrap();
        let p = plan(ADDON, &res, &facts(), &mut Fake).unwrap();
        let w = write_generation(&base, ADDON, &res, &p).unwrap();
        assert!(w.fresh && w.stale.is_empty());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&w.gen_dir.join("work")), 0o700);
        assert_eq!(mode(&w.gen_dir.join("coord/db")), 0o700);
        assert_eq!(mode(&w.gen_dir.join("work/leaf.key")), 0o400);
        assert_eq!(mode(&w.gen_dir.join("coord/db/pgpass")), 0o400);
        std::fs::write(w.gen_dir.join(COMPLETE_MARKER), b"").unwrap();
        let again = write_generation(&base, ADDON, &res, &p).unwrap();
        assert!(!again.fresh && again.gen_dir == w.gen_dir);
        // A changed value is a new generation; the old one is stale.
        let mut p2 = p.clone();
        p2.files.insert(("work".into(), "peer-key".into()), b"ROTATED".to_vec());
        let w2 = write_generation(&base, ADDON, &res, &p2).unwrap();
        assert!(w2.fresh && w2.gen_dir != w.gen_dir && w2.stale == vec![w.gen_dir.clone()]);
        // The receipt names paths and never a value.
        let r = receipt(ADDON, &res, &w2).to_string();
        for v in ["ADDON-KEY-VALUE", "PEER-SECRET-VALUE", "LEAF-KEY-VALUE", "DB-KEY-VALUE", "ROTATED", "PASS"] {
            assert!(!r.contains(v), "{r}");
        }
        assert!(r.contains("work/peer-key") && r.contains("RHADDON_WORK_DIR"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn holds_name_gpu_socket_and_privileged_services_only() {
        let overlay = "services:\n  noo-rhaddon:\n    image: x\n  noo-rhaddon-gpu:\n    image: x\n    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n  noo-rhaddon-sock:\n    image: x\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n  noo-rhaddon-priv:\n    image: x\n    privileged: true\n";
        let h = holds(overlay).unwrap();
        let names: Vec<&str> = h.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(names, ["noo-rhaddon-gpu", "noo-rhaddon-sock", "noo-rhaddon-priv"]);
        assert!(h[0].1.contains("GPU") && h[1].1.contains("Docker socket") && h[2].1.contains("privileged"));
    }

    #[test]
    fn core_vars_are_read_from_core_compose_text() {
        let v = core_compose_vars(&["  x: ${NOO_JWT_SECRET:-}\n  y: ${RHADDON_LEAKED}\n".to_string()]);
        assert!(v.contains("NOO_JWT_SECRET") && v.contains("RHADDON_LEAKED"));
    }

    /// The migration of an add-on provisioned before 0.6.13: its
    /// `services/<addon>` leaf (CN = the bare name, key 0644) is replaced by
    /// the namespaced client leaf, the runner's files get the new pair, and
    /// the old directory is gone. Core's own leaves are never touched.
    #[test]
    fn a_pre_0613_provision_leaf_is_reissued_under_the_namespace_and_retired() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("noo-res-retire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ca = crate::pki::ClusterCa::new(dir.join("pki"));
        ca.generate_ca("t", 3650).unwrap();
        // What --provision-only wrote before: CN=rhaddon, no reader row.
        ca.issue_service_cert("rhaddon", &[], &[], 30).unwrap();
        let legacy = ca.dir.join("services").join("rhaddon");
        assert_eq!(cert_cn(&legacy.join("service.crt")).as_deref(), Some("rhaddon"), "the fixture is the legacy shape");
        assert_eq!(std::fs::metadata(legacy.join("service.key")).unwrap().permissions().mode() & 0o777, 0o644, "the legacy key mode");
        let prov = dir.join("provision").join("rhaddon");
        std::fs::create_dir_all(&prov).unwrap();
        std::fs::write(prov.join("client.crt"), b"OLD-CERT").unwrap();
        std::fs::write(prov.join("client.key"), b"OLD-KEY").unwrap();

        let said = retire_legacy_leaf(&ca, "rhaddon", Some(&prov)).unwrap().expect("a legacy leaf was retired");
        assert!(said.contains("addon:rhaddon/db-client") && said.contains("retired"), "{said}");
        assert!(!legacy.exists(), "the old leaf directory is removed");
        let (crt, key) = ca.addon_leaf_paths("rhaddon", DB_CLIENT_STEM);
        assert_eq!(cert_cn(&crt).as_deref(), Some("addon:rhaddon/db-client"));
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(prov.join("client.crt")).unwrap(), std::fs::read(&crt).unwrap(), "the runner gets the new leaf");
        assert_eq!(std::fs::metadata(prov.join("client.key")).unwrap().permissions().mode() & 0o777, 0o400);
        // Idempotent: nothing left to retire.
        assert!(retire_legacy_leaf(&ca, "rhaddon", None).unwrap().is_none());
        // A leaf core issues is core's, whatever add-on shares its name.
        ca.issue_service_cert("evolve", &[], &[], 30).unwrap();
        assert!(retire_legacy_leaf(&ca, "evolve", None).unwrap().is_none());
        assert!(ca.dir.join("services/evolve/service.crt").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_derive_without_naming_an_addon() {
        assert_eq!(shared_secret_var("a-b", "c"), "NOO_ADDON_SECRET_A_B__C");
        assert_ne!(shared_secret_var("a-b", "c"), shared_secret_var("a", "b-c"));
        assert_eq!(env_prefix("rh-addon"), "RH_ADDON_");
        assert_eq!(rundir(None, 1000), PathBuf::from("/dev/shm/noo-addons-1000"));
        assert_eq!(rundir(None, 0), PathBuf::from("/run/noo/addons"));
    }
}
