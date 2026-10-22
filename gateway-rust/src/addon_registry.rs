// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The runtime add-on registry.
//!
//! Add-ons are pieces that extend the core at runtime, so the core must not
//! carry their names or their routes. `addons::ADDONS` is a compiled table of
//! the add-ons that shipped with the stack (their polarity, licence feature and
//! refusal text); it can never describe a third-party add-on. This module is
//! what the gateway asks instead: "which HTTP add-ons are registered right
//! now, where do they live, and what did they declare?"
//!
//! ## What registers an add-on
//!
//! An add-on is registered when ALL of these hold:
//!
//! 1. the operator switched it on: `addons.<name>: true` in `noomesh.yaml`
//!    (a compiled row keeps its own polarity and licence check);
//! 2. its image delivered a route manifest at
//!    `<ROUTES_DIR>/<name>/routes.json` ([`crate::addon_proxy::read_manifest`]),
//!    which [`crate::addon_proxy::validate`] accepted;
//! 3. the launcher vouches for it: it holds a verified signed lock that lists
//!    this stack ([`Reported`], below).
//!
//! An add-on that fails 2 or 3 is REFUSED, not skipped: it gets no routes, the
//! reason is in the log and in [`refusal`] (so `/health` reads `unhealthy`),
//! and it never loads silently.
//!
//! ## A registered add-on's database
//!
//! Its signed bundle may also declare a database system (`system.json`),
//! delivered by the launcher for enabled + verified add-ons
//! ([`crate::addon_decls`], i163 E). It is read here, for a registered
//! add-on only, and an invalid one refuses the add-on like an invalid
//! manifest. The systems broker reads [`declared_systems`].
//!
//! ## Where the verified lock comes from
//!
//! The CLI verifies a lock (`noo addons enable | upgrade`: `addon_lock::verify`
//! against the key in the installed entitlement, then `supports_stack`),
//! pins it in `addons.lock`, and the LAUNCHER re-verifies it offline on every
//! `noo stack start | restart` (`noo addons launch-pins`) and refuses to start
//! a composed add-on without a good pin. The launcher then hands the gateway
//! the result it just computed, in `NOO_ADDONS_VERIFIED`:
//!
//! | value | meaning |
//! |---|---|
//! | `evolve=1.2.0@v0.6.8,pai-voice=0.3.0@v0.6.8` | these add-ons hold a verified lock for these stacks |
//! | `none` | the launcher verified and no add-on has a lock |
//! | `dev` | a source checkout: add-on images are built locally, nothing is signed |
//! | unset or empty | a launcher from before this hand-off ([`Verification::LegacyLauncher`]) |
//!
//! Beside it, `NOO_ADDONS_DEV` (i163 part A): `name=<unix>,...` names the
//! add-ons whose lock only a temporary DEVELOPMENT key vouches for, with
//! that key's expiry. Such an add-on registers as [`Verification::DevKey`];
//! `/health` reports it in `addons_dev` (`"dev (expires <date>)"`), and once
//! the instant passes it reads `unhealthy` with the reason and its routes are
//! refused, without waiting for a restart (the launcher refuses it at the
//! next start). An entry for a name the verdict does not hold vouches for
//! nothing; an unreadable value is a note, never a reason to trust more.
//!
//! The gateway reads the launcher's verdict; it does not verify the signature
//! again. Why: the gateway container cannot see the install root
//! (`addons.lock`, the cached locks and the entitlement are host files, and
//! a mount of them would widen the gateway's reach for no new guarantee); a
//! second verifier in the gateway would be a second copy of `noo-sig1` and
//! the canonical-lock rules (two homes for one decision); and anything that
//! can forge the launcher's environment can already edit `noomesh.yaml` and
//! `.env`. What the gateway DOES check itself: the add-on is named in the
//! verdict, and the stack the launcher verified for equals the stack this
//! gateway runs (`NOO_STACK_TAG`) when that is known.
//!
//! ## Upgrade safety
//!
//! An install that upgrades into this keeps its enabled add-ons on the first
//! boot: the new launcher's `launch-pins` already verifies every composed
//! licensed add-on (a pin that does not verify stopped the start before the
//! gateway came up), so the verdict names them. A gateway started WITHOUT a
//! verdict (an older launcher on the first boot) keeps loading the compiled
//! HTTP add-ons exactly as before and says so ([`Verification::LegacyLauncher`]);
//! it never extends that grandfathering to a name the table does not know.
//!
//! ## Delegation
//!
//! A manifest may declare `delegate: "tasks"` and `task_events`
//! (noomesh-internal i143). Declaring is not enough: the operator must also
//! enable it, `addon_delegation.<name>.tasks: true` in `noomesh.yaml`, default
//! off. [`AddonEntry::operator_enabled`] is true only when BOTH are present.
//! This module parses, validates and exposes; it mints nothing.
//!
//! The switch lives in config, not in posture. A posture gate is a stricter
//! default that must not strand a working install, and a new gate cannot be
//! set before the roll that introduces it. Delegation is the opposite shape:
//! off by default, so no install is stranded, and keyed by add-on name, which
//! a static posture catalog cannot enumerate. Config is also where the add-on
//! was switched on (one home, next to `addons:`). Because it widens what an
//! add-on may do for a person, the `addon_delegation` section is a gated
//! config section (`settings::GATED_CONFIG_SECTIONS`): Admin only, never a
//! cluster credential.
//!
//! ## Reads are cheap
//!
//! The registry is an immutable [`Snapshot`] behind `RwLock<Arc<..>>`. A read
//! clones the `Arc` under a lock held for that clone alone, never across an
//! await, and touches no database. The harness side may call [`get`] on every
//! delegated request. [`reload`] builds a new snapshot off to the side and
//! swaps it in one step. The mounted ROUTES are the one thing a reload cannot
//! change: the HTTP router is built once at startup, so an add-on that appears
//! later is registered (and reported) but its routes mount at the next start.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path as FsPath;
use std::sync::{Arc, RwLock};

use crate::addon_proxy::{AddonManifest, TaskEventsSpec};
use crate::config::AddonDelegationConfig;

/// The environment variable the launcher sets from `noo addons launch-pins`.
pub const VERIFIED_ENV: &str = "NOO_ADDONS_VERIFIED";
/// The stack tag this gateway was started for (the launcher's `NOO_IMAGE_TAG`).
pub const STACK_ENV: &str = "NOO_STACK_TAG";
/// The add-ons only a development key vouches for, with its expiry (i163 A).
pub const DEV_ENV: &str = "NOO_ADDONS_DEV";

/// What an add-on name may be (it is joined into a path and an env var).
pub const NAME_RULE: &str =
    "lowercase letters, digits, `-` and `_`, starting with a letter, at most 32 characters";

/// Is `s` a name an add-on may have? Checked before the name is joined into a
/// path, so a config key can never walk out of the manifest directory.
pub fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

// ── The launcher's verdict ───────────────────────────────────────────────

/// What the launcher reported in [`VERIFIED_ENV`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reported {
    /// Unset or empty: a launcher from before the hand-off, or the gateway run
    /// by hand.
    Unreported,
    /// `dev`: a source checkout, nothing is signed.
    Dev,
    /// `name=version@stack,...` (or `none`, which is empty): name to
    /// `(version, stack)` the launcher verified.
    Verified(BTreeMap<String, (String, String)>),
    /// Set but unparseable. Never read as "nothing to check".
    Malformed(String),
}

/// Parse the value of [`VERIFIED_ENV`]. Pure.
pub fn parse_reported(raw: Option<&str>) -> Reported {
    let v = raw.unwrap_or("").trim();
    match v {
        "" => return Reported::Unreported,
        "dev" => return Reported::Dev,
        "none" => return Reported::Verified(BTreeMap::new()),
        _ => {}
    }
    let mut out = BTreeMap::new();
    for tok in v.split(',') {
        let tok = tok.trim();
        let parsed = tok.split_once('=').and_then(|(name, rest)| {
            let (version, stack) = rest.split_once('@')?;
            let plain = |t: &str| !t.is_empty() && !t.chars().any(|c| c.is_whitespace() || c == '@' || c == '=');
            (name_ok(name) && plain(version) && plain(stack))
                .then(|| (name.to_string(), (version.to_string(), stack.to_string())))
        });
        match parsed {
            Some((n, vs)) => {
                out.insert(n, vs);
            }
            None => {
                return Reported::Malformed(format!(
                    "{VERIFIED_ENV} entry {tok:?} is not `<add-on>=<version>@<stack>`"
                ))
            }
        }
    }
    Reported::Verified(out)
}

/// Parse the value of [`DEV_ENV`]: `name=<unix seconds>,...`. Unset or empty
/// is no development add-on. Pure.
pub fn parse_dev(raw: Option<&str>) -> Result<BTreeMap<String, i64>, String> {
    let v = raw.unwrap_or("").trim();
    let mut out = BTreeMap::new();
    if v.is_empty() {
        return Ok(out);
    }
    for tok in v.split(',') {
        let tok = tok.trim();
        let parsed = tok
            .split_once('=')
            .and_then(|(name, at)| (name_ok(name) && !at.is_empty() && at.bytes().all(|b| b.is_ascii_digit())).then_some((name, at)))
            .and_then(|(name, at)| at.parse::<i64>().ok().map(|at| (name.to_string(), at)));
        match parsed {
            Some((n, at)) => {
                out.insert(n, at);
            }
            None => return Err(format!("{DEV_ENV} entry {tok:?} is not `<add-on>=<unix seconds>`")),
        }
    }
    Ok(out)
}

/// `YYYY-MM-DD HH:MM UTC` for a unix time (the CLI prints expiries the same way).
pub fn utc_minute(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("unix {unix}"))
}

/// Seconds since the epoch, now.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn dev_expired_reason(name: &str, version: &str, expires_at: i64) -> String {
    format!(
        "add-on {name:?} {version} is vouched for only by a development key, which expired {}, so none \
         of its routes are served. Renew it with `noo addons trust-key {name} <pubkey> --dev --expires 14d` \
         and `noo stack restart --force`, or ship it signed by its release key",
        utc_minute(expires_at)
    )
}

/// How an add-on's lock was vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The launcher verified a signed lock at `version` for `stack`.
    Launcher { version: String, stack: String },
    /// As [`Verification::Launcher`], but only a temporary development key
    /// vouches for it, until `expires_at` (unix seconds; i163 part A).
    DevKey { version: String, stack: String, expires_at: i64 },
    /// A source checkout (`dev`): images are built locally, nothing is signed.
    DevBuild,
    /// The launcher reported nothing (older than this hand-off) and the add-on
    /// is one the compiled table already knew, so it loads as it always did.
    LegacyLauncher,
}

fn upgrade_hint(name: &str) -> String {
    format!(
        "Run `noo addons upgrade {name}` (it fetches the add-on's signed lock, checks that it \
         lists this stack, and pins it), then `noo stack restart --force`; or switch the add-on \
         off with `noo addons disable {name}`"
    )
}

/// Decide whether `name` may be registered. `in_table` is "a compiled row the
/// gateway already knew before the registry existed". Pure.
pub fn verify(
    name: &str,
    in_table: bool,
    reported: &Reported,
    gateway_stack: Option<&str>,
) -> Result<Verification, String> {
    match reported {
        Reported::Dev => Ok(Verification::DevBuild),
        Reported::Unreported if in_table => Ok(Verification::LegacyLauncher),
        Reported::Unreported => Err(format!(
            "add-on {name:?} is enabled in noomesh.yaml, but this gateway was started by a launcher \
             that does not report verified add-on locks, so it cannot vouch for a third-party \
             add-on. None of its routes are mounted. Update the CLI (`noo upgrade`), then {}",
            upgrade_hint(name)
        )),
        Reported::Malformed(why) => Err(format!(
            "add-on {name:?} is enabled in noomesh.yaml, but its verified lock could not be read: \
             {why}. None of its routes are mounted. Restart the stack with the launcher \
             (`noo stack restart --force`)"
        )),
        Reported::Verified(map) => {
            let Some((version, stack)) = map.get(name) else {
                return Err(format!(
                    "add-on {name:?} is enabled in noomesh.yaml but has no verified lock for this \
                     stack, so none of its routes are mounted. {}",
                    upgrade_hint(name)
                ));
            };
            if let Some(g) = gateway_stack.map(str::trim).filter(|g| !g.is_empty()) {
                if g != stack.as_str() {
                    return Err(format!(
                        "add-on {name:?} {version} is verified for stack {stack}, and this gateway \
                         runs {g}, so none of its routes are mounted. {}",
                        upgrade_hint(name)
                    ));
                }
            }
            Ok(Verification::Launcher { version: version.clone(), stack: stack.clone() })
        }
    }
}

// ── One registered add-on ────────────────────────────────────────────────

/// A registered HTTP add-on: operator-enabled, manifest valid, lock verified.
#[derive(Debug, Clone)]
pub struct AddonEntry {
    name: String,
    manifest: AddonManifest,
    delegate_enabled: bool,
    verification: Verification,
    system: Option<crate::addon_decls::AddonSystem>,
}

impl AddonEntry {
    pub(crate) fn new(
        name: &str,
        manifest: AddonManifest,
        delegate_enabled: bool,
        verification: Verification,
    ) -> Self {
        Self { name: name.to_string(), manifest, delegate_enabled, verification, system: None }
    }

    /// Attach the database system its bundle declares.
    pub(crate) fn with_system(mut self, system: Option<crate::addon_decls::AddonSystem>) -> Self {
        self.system = system;
        self
    }

    /// The database system its bundle declares (`system.json`), validated.
    pub fn system(&self) -> Option<&crate::addon_decls::AddonSystem> {
        self.system.as_ref()
    }

    /// The add-on's name (`addons.<name>`, `noo-<name>`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the add-on's door is: the manifest's `base_url_env` override when
    /// set, else its `base_url_default` (`https://noo-<name>[:port]`). HTTPS
    /// with the cluster client certificate is enforced where it is dialled.
    pub fn upstream(&self) -> String {
        self.manifest.base_url()
    }

    /// The validated manifest as the add-on delivered it.
    pub fn manifest(&self) -> &AddonManifest {
        &self.manifest
    }

    /// Did the manifest declare `delegate: "tasks"`? A declaration alone
    /// grants nothing: ask [`AddonEntry::operator_enabled`].
    pub fn delegates_tasks(&self) -> bool {
        self.manifest.delegate.as_deref() == Some(crate::addon_proxy::DELEGATE_TASKS)
    }

    /// True only when the manifest declares `delegate: "tasks"` AND the
    /// operator enabled it (`addon_delegation.<name>.tasks: true`). The
    /// default is false, and each half alone is false.
    pub fn operator_enabled(&self) -> bool {
        self.delegates_tasks() && self.delegate_enabled
    }

    /// Would a request `method` `path` (a gateway path, as the proxy matches
    /// it: `{param}` segments match any non-empty segment, aliases count) be
    /// sent the delegated task token? True only when some public route matches
    /// and EVERY matching route declares `receives_delegation` (the stricter
    /// reading, like the tier gate). This is the route half only: the token is
    /// minted when this AND [`AddonEntry::operator_enabled`] are both true.
    /// In-memory, no allocation beyond a small Vec.
    pub fn route_receives_delegation(&self, method: &str, path: &str) -> bool {
        let hits = crate::addon_proxy::matching_routes(std::slice::from_ref(&self.manifest), method, path);
        !hits.is_empty() && hits.iter().all(|r| r.receives_delegation)
    }

    /// The manifest's `task_events` route, exactly as declared. Present only
    /// when the manifest also declared `delegate: "tasks"` (validation refuses
    /// it otherwise). It does NOT imply the operator enabled delegation:
    /// callers that start new delegated work check
    /// [`AddonEntry::operator_enabled`] first.
    pub fn task_events(&self) -> Option<&TaskEventsSpec> {
        self.manifest.task_events.as_ref()
    }

    /// How the add-on's lock was vouched for.
    pub fn verification(&self) -> &Verification {
        &self.verification
    }

    /// The development key's expiry when only one vouches for this add-on.
    pub fn dev_expires_at(&self) -> Option<i64> {
        match &self.verification {
            Verification::DevKey { expires_at, .. } => Some(*expires_at),
            _ => None,
        }
    }

    /// Why this add-on is refused at `now` because its development key
    /// expired, if it is.
    pub fn dev_expired_at(&self, now: i64) -> Option<String> {
        match &self.verification {
            Verification::DevKey { version, expires_at, .. } if now >= *expires_at => {
                Some(dev_expired_reason(&self.name, version, *expires_at))
            }
            _ => None,
        }
    }
}

// ── The snapshot ─────────────────────────────────────────────────────────

/// An immutable view of the registry. Built by [`build`], swapped whole.
#[derive(Debug, Default)]
pub struct Snapshot {
    entries: BTreeMap<String, Arc<AddonEntry>>,
    refused: BTreeMap<String, String>,
    notes: Vec<String>,
}

impl Snapshot {
    pub fn get(&self, name: &str) -> Option<Arc<AddonEntry>> {
        self.entries.get(name).cloned()
    }

    pub fn all(&self) -> Vec<Arc<AddonEntry>> {
        self.entries.values().cloned().collect()
    }

    pub fn refusal(&self, name: &str) -> Option<String> {
        self.refused.get(name).cloned()
    }

    pub fn refusals(&self) -> &BTreeMap<String, String> {
        &self.refused
    }

    /// [`Snapshot::get`] at `now`: an add-on whose development key has
    /// expired is no longer served.
    pub fn get_at(&self, name: &str, now: i64) -> Option<Arc<AddonEntry>> {
        self.get(name).filter(|e| e.dev_expired_at(now).is_none())
    }

    /// [`Snapshot::all`] at `now`, without expired development add-ons.
    pub fn all_at(&self, now: i64) -> Vec<Arc<AddonEntry>> {
        self.entries.values().filter(|e| e.dev_expired_at(now).is_none()).cloned().collect()
    }

    /// [`Snapshot::refusal`] at `now`: also an expired development key.
    pub fn refusal_at(&self, name: &str, now: i64) -> Option<String> {
        self.refusal(name).or_else(|| self.entries.get(name).and_then(|e| e.dev_expired_at(now)))
    }

    /// [`Snapshot::refusals`] at `now`, with every expired development add-on.
    pub fn refusals_at(&self, now: i64) -> BTreeMap<String, String> {
        let mut out = self.refused.clone();
        for (n, e) in &self.entries {
            if let Some(why) = e.dev_expired_at(now) {
                out.insert(n.clone(), why);
            }
        }
        out
    }

    /// `dev (expires <date>)` for an add-on only a live development key
    /// vouches for at `now`; `None` otherwise.
    pub fn dev_label_at(&self, name: &str, now: i64) -> Option<String> {
        let e = self.entries.get(name)?;
        let at = e.dev_expires_at()?;
        (now < at).then(|| format!("dev (expires {})", utc_minute(at)))
    }

    /// Operator-facing observations that are not refusals (a switch that
    /// names nothing).
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
}

/// Everything [`build`] reads, so every outcome is testable without a global.
pub struct Inputs<'a> {
    /// Where manifests are delivered: `<dir>/<name>/routes.json`.
    pub dir: &'a FsPath,
    /// Where the launcher delivers `system.json`: `<dir>/<name>/system.json`.
    pub systems_dir: &'a FsPath,
    /// `addons:` from `noomesh.yaml`.
    pub declared: &'a HashMap<String, bool>,
    /// `addon_delegation:` from `noomesh.yaml`.
    pub delegation: &'a HashMap<String, AddonDelegationConfig>,
    /// The launcher's verdict.
    pub reported: &'a Reported,
    /// The stack tag this gateway runs, when known.
    pub gateway_stack: Option<&'a str>,
    /// [`DEV_ENV`], parsed: add-ons only a development key vouches for.
    pub dev: &'a Result<BTreeMap<String, i64>, String>,
    /// Unix seconds, now (a development key is judged against it).
    pub now: i64,
}

/// Build a snapshot. `table_on` answers "is this compiled row switched on?"
/// (flag and polarity, `addons::state`), injected so the function is pure.
///
/// Candidates: every compiled row that requires a manifest, plus every name
/// the operator set to `true` in `addons:`. A compiled row that speaks NATS
/// (no `routes_manifest`) is never read, so a file planted for it publishes
/// nothing.
pub fn build(inp: &Inputs, table_on: &dyn Fn(&str) -> bool) -> Snapshot {
    let mut snap = Snapshot::default();
    let mut candidates: BTreeSet<&str> = crate::addons::ADDONS
        .iter()
        .filter(|a| a.routes_manifest)
        .map(|a| a.name)
        .collect();
    candidates.extend(inp.declared.iter().filter(|(_, on)| **on).map(|(n, _)| n.as_str()));

    for name in candidates {
        let row = crate::addons::ADDONS.iter().find(|a| a.name == name);
        if row.is_some_and(|a| !a.routes_manifest) {
            continue; // NATS or core: no manifest to read
        }
        let on = match row {
            Some(a) => table_on(a.name),
            None => true, // candidates from `declared` are the true ones
        };
        if !on {
            continue; // off: registers nothing, refuses nothing
        }
        let required = row.is_some_and(|a| a.routes_manifest);
        let manifest = match crate::addon_proxy::read_manifest(inp.dir, name, required) {
            Ok(Some(m)) => m,
            Ok(None) => {
                snap.notes.push(format!(
                    "addons.{name} is on in noomesh.yaml, but its image delivered no route manifest \
                     ({}/{name}/routes.json), so no routes are registered for it. If it is not an \
                     HTTP add-on this is expected; otherwise check that its overlay is composed",
                    inp.dir.display()
                ));
                continue;
            }
            Err(why) => {
                snap.refused.insert(name.to_string(), why);
                continue;
            }
        };
        let verdict = verify(name, row.is_some(), inp.reported, inp.gateway_stack).and_then(|v| match (v, inp.dev) {
            (Verification::Launcher { version, stack }, Ok(dev)) if dev.contains_key(name) => {
                let expires_at = dev[name];
                if inp.now >= expires_at {
                    Err(dev_expired_reason(name, &version, expires_at))
                } else {
                    Ok(Verification::DevKey { version, stack, expires_at })
                }
            }
            (v, _) => Ok(v),
        });
        match verdict {
            Ok(v) => {
                let enabled = inp.delegation.get(name).is_some_and(|d| d.tasks);
                if enabled && manifest.delegate.is_none() {
                    snap.notes.push(format!(
                        "addon_delegation.{name}.tasks is on, but {name}'s manifest does not declare \
                         `delegate: \"tasks\"`, so nothing is delegated"
                    ));
                }
                // The database its bundle declares: read for a registered
                // add-on only, and an invalid declaration refuses the whole
                // add-on (never a partial surface).
                let system = match crate::addon_decls::read_system(inp.systems_dir, name) {
                    Ok(d) => d,
                    Err(why) => {
                        snap.refused.insert(name.to_string(), why);
                        continue;
                    }
                };
                snap.entries.insert(
                    name.to_string(),
                    Arc::new(AddonEntry::new(name, manifest, enabled, v).with_system(system)),
                );
            }
            Err(why) => {
                snap.refused.insert(name.to_string(), why);
            }
        }
    }
    if let Err(why) = inp.dev {
        snap.notes.push(format!("{why}; no add-on is reported as dev-signed"));
    }
    for name in inp.delegation.iter().filter(|(_, d)| d.tasks).map(|(n, _)| n) {
        if !snap.entries.contains_key(name.as_str()) {
            snap.notes.push(format!(
                "addon_delegation.{name}.tasks is on, but {name} is not a registered add-on, so \
                 nothing is delegated"
            ));
        }
    }
    snap
}

// ── The process-wide registry ────────────────────────────────────────────

static SNAPSHOT: RwLock<Option<Arc<Snapshot>>> = RwLock::new(None);

thread_local! {
    /// True on a thread that is inside [`reload`]. Validating a manifest asks
    /// the front door whether a User could call each of its writes
    /// (`addon_proxy::user_tier_could_call` -> `auth::requester_allows`),
    /// and that answer reads the registry. While the registry is being built
    /// no add-on route is mounted yet, so the honest answer is "none": the
    /// re-entrant read sees an empty snapshot instead of building another one.
    static BUILDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct Building;

impl Building {
    fn enter() -> Self {
        BUILDING.with(|b| b.set(true));
        Building
    }
}

impl Drop for Building {
    fn drop(&mut self) {
        BUILDING.with(|b| b.set(false));
    }
}

fn current() -> Arc<Snapshot> {
    if BUILDING.with(|b| b.get()) {
        return Arc::new(Snapshot::default());
    }
    let held = SNAPSHOT.read().unwrap_or_else(|e| e.into_inner()).clone();
    held.unwrap_or_else(reload)
}

/// Build a fresh snapshot from this process's configuration and environment
/// and swap it in. Called at boot (by [`crate::addon_proxy::mount`]) and
/// wherever configuration is re-read; every other reader sees either the old
/// snapshot or the new one, never a mixture.
pub fn reload() -> Arc<Snapshot> {
    let cfg = crate::config::global();
    let reported = parse_reported(std::env::var(VERIFIED_ENV).ok().as_deref());
    let stack = std::env::var(STACK_ENV).ok();
    let dev = parse_dev(std::env::var(DEV_ENV).ok().as_deref());
    let building = Building::enter();
    let snap = build(
        &Inputs {
            dir: FsPath::new(crate::addon_proxy::ROUTES_DIR),
            systems_dir: FsPath::new(crate::addon_decls::SYSTEMS_DIR),
            declared: &cfg.addons,
            delegation: &cfg.addon_delegation,
            reported: &reported,
            gateway_stack: stack.as_deref(),
            dev: &dev,
            now: now_unix(),
        },
        &|n| crate::addons::state(n) != crate::addons::AddonState::Disabled,
    );
    drop(building);
    for e in snap.entries.values() {
        tracing::info!(
            addon = e.name(),
            routes = e.manifest().routes.len(),
            verification = ?e.verification(),
            delegates_tasks = e.delegates_tasks(),
            operator_enabled = e.operator_enabled(),
            system = e.system().map(|s| s.schema.as_str()).unwrap_or("-"),
            "add-on registered"
        );
        if matches!(e.verification(), Verification::LegacyLauncher) {
            tracing::warn!(
                addon = e.name(),
                "{VERIFIED_ENV} is not set: this gateway was started by a launcher that does not \
                 report verified add-on locks, so {} loads as it always did. `noo upgrade` updates the launcher",
                e.name()
            );
        }
    }
    for (addon, why) in snap.refused.iter() {
        tracing::error!(addon = addon.as_str(), "add-on routes refused: {why}");
    }
    for note in snap.notes.iter() {
        tracing::warn!("{note}");
    }
    let snap = Arc::new(snap);
    *SNAPSHOT.write().unwrap_or_else(|e| e.into_inner()) = Some(snap.clone());
    snap
}

/// The registered add-on `name`, or `None`. Cheap: an `Arc` clone, no
/// database, no await. An add-on whose development key has expired since
/// load is `None` here and refused in [`refusal`].
pub fn get(name: &str) -> Option<Arc<AddonEntry>> {
    current().get_at(name, now_unix())
}

/// Every registered add-on, ordered by name.
pub fn all() -> Vec<Arc<AddonEntry>> {
    current().all_at(now_unix())
}

/// Why `name` was refused at load (or, for a development key, has expired
/// since), if it was.
pub fn refusal(name: &str) -> Option<String> {
    current().refusal_at(name, now_unix())
}

/// Every add-on refused at load or expired since, with why.
pub fn refusals() -> BTreeMap<String, String> {
    current().refusals_at(now_unix())
}

/// `dev (expires <date>)` for an add-on only a live development key vouches
/// for; `None` for every other add-on (i163 part A; `/health` `addons_dev`).
pub fn dev_label(name: &str) -> Option<String> {
    current().dev_label_at(name, now_unix())
}

impl Snapshot {
    /// The database systems registered add-ons declare, by system name (the
    /// add-on name with `-` as `_`), as `systems:` entries.
    pub fn declared_systems(&self) -> BTreeMap<String, crate::config::SystemConfig> {
        self.entries
            .values()
            .filter_map(|e| {
                e.system().map(|s| (crate::addon_decls::system_id(e.name()), crate::addon_decls::to_system_config(e.name(), s)))
            })
            .collect()
    }
}

/// The database systems registered add-ons declare (i163 E), for the
/// systems broker. Keyed by system name.
pub fn declared_systems() -> BTreeMap<String, crate::config::SystemConfig> {
    current().declared_systems()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addon_proxy::tests::sample_json;
    use serde_json::{json, Value};

    const STACK: &str = "v0.6.8";

    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("noo-addon-registry-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn plant(dir: &FsPath, addon: &str, v: &Value) {
        std::fs::create_dir_all(dir.join(addon)).unwrap();
        std::fs::write(dir.join(addon).join(crate::addon_proxy::ROUTES_FILE), v.to_string()).unwrap();
    }

    /// A manifest for a third-party add-on the compiled table has never
    /// heard of, with neutral routes.
    fn third_party(name: &str) -> Value {
        let mut v = sample_json();
        v["addon"] = json!(name);
        v["base_url_env"] = json!(format!("NOO_{}_URL", name.to_ascii_uppercase().replace('-', "_")));
        v["base_url_default"] = json!(format!("https://noo-{name}:8090"));
        v["routes"][1]["scopes"] = json!([format!("{name}:read_items")]);
        v
    }

    fn declared(pairs: &[(&str, bool)]) -> HashMap<String, bool> {
        pairs.iter().map(|(n, b)| (n.to_string(), *b)).collect()
    }

    fn delegation(pairs: &[(&str, bool)]) -> HashMap<String, AddonDelegationConfig> {
        pairs.iter().map(|(n, b)| (n.to_string(), AddonDelegationConfig { tasks: *b })).collect()
    }

    fn verified(pairs: &[(&str, &str, &str)]) -> Reported {
        Reported::Verified(pairs.iter().map(|(n, v, s)| (n.to_string(), (v.to_string(), s.to_string()))).collect())
    }

    fn run(
        dir: &FsPath,
        decl: &[(&str, bool)],
        deleg: &[(&str, bool)],
        reported: &Reported,
        table_on: &dyn Fn(&str) -> bool,
    ) -> Snapshot {
        run_dev(dir, decl, deleg, reported, &Ok(BTreeMap::new()), NOW, table_on)
    }

    const NOW: i64 = 1_790_000_000;

    fn run_dev(
        dir: &FsPath,
        decl: &[(&str, bool)],
        deleg: &[(&str, bool)],
        reported: &Reported,
        dev: &Result<BTreeMap<String, i64>, String>,
        now: i64,
        table_on: &dyn Fn(&str) -> bool,
    ) -> Snapshot {
        build(
            &Inputs {
                dir,
                systems_dir: &dir.join(".no-systems"),
                declared: &declared(decl),
                delegation: &delegation(deleg),
                reported,
                gateway_stack: Some(STACK),
                dev,
                now,
            },
            table_on,
        )
    }

    // ── the verdict ──────────────────────────────────────────────────────

    #[test]
    fn the_launchers_verdict_parses_and_a_bad_one_is_never_read_as_nothing() {
        assert_eq!(parse_reported(None), Reported::Unreported);
        assert_eq!(parse_reported(Some("  ")), Reported::Unreported);
        assert_eq!(parse_reported(Some("dev")), Reported::Dev);
        assert_eq!(parse_reported(Some("none")), verified(&[]));
        assert_eq!(
            parse_reported(Some("evolve=1.2.0@v0.6.8, pai-voice=0.3.0@v0.6.8-rc.1")),
            verified(&[("evolve", "1.2.0", "v0.6.8"), ("pai-voice", "0.3.0", "v0.6.8-rc.1")])
        );
        for bad in ["evolve", "evolve=1.2.0", "=1@v1", "Evolve=1@v1", "evolve=@v1", "evolve=1@", "a=1@v1,,b=2@v1", "../x=1@v1"] {
            assert!(matches!(parse_reported(Some(bad)), Reported::Malformed(_)), "{bad:?} must be Malformed");
        }
    }

    // ── registration: enabled / unsigned / wrong stack / disabled ────────

    #[test]
    fn an_enabled_verified_third_party_addon_is_registered_with_its_upstream() {
        let dir = scratch("enabled");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let snap = run(&dir, &[("pai-voice", true)], &[], &verified(&[("pai-voice", "0.3.0", STACK)]), &|_| false);
        assert!(snap.refused.is_empty(), "{:?}", snap.refused);
        let e = snap.get("pai-voice").expect("registered");
        assert_eq!(e.name(), "pai-voice");
        assert_eq!(e.manifest().addon, "pai-voice");
        assert_eq!(e.upstream(), "https://noo-pai-voice:8090");
        assert_eq!(e.verification(), &Verification::Launcher { version: "0.3.0".into(), stack: STACK.into() });
        assert_eq!(snap.all().len(), 1);
    }

    #[test]
    fn an_enabled_addon_with_no_verified_lock_is_refused_and_names_the_fix() {
        let dir = scratch("unsigned");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        // The launcher verified, and this add-on is not among the verified.
        let snap = run(&dir, &[("pai-voice", true)], &[], &verified(&[("other", "1.0.0", STACK)]), &|_| false);
        assert!(snap.get("pai-voice").is_none(), "an unverified add-on must never register");
        let why = snap.refusal("pai-voice").expect("refused, not silently skipped");
        assert!(why.contains("no verified lock"), "{why}");
        assert!(why.contains("noo addons upgrade pai-voice"), "names the fix: {why}");
        assert!(why.contains("noo addons disable pai-voice"), "names the opt-out: {why}");
        // `none` is the same answer.
        let snap = run(&dir, &[("pai-voice", true)], &[], &verified(&[]), &|_| false);
        assert!(snap.get("pai-voice").is_none() && snap.refusal("pai-voice").is_some());
    }

    #[test]
    fn a_lock_verified_for_another_stack_is_refused() {
        let dir = scratch("wrong-stack");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let snap = run(&dir, &[("pai-voice", true)], &[], &verified(&[("pai-voice", "0.3.0", "v0.6.7")]), &|_| false);
        assert!(snap.get("pai-voice").is_none());
        let why = snap.refusal("pai-voice").unwrap();
        assert!(why.contains("v0.6.7") && why.contains(STACK) && why.contains("noo addons upgrade pai-voice"), "{why}");
        // With the gateway's own tag unknown, the launcher's word stands.
        let r = verified(&[("pai-voice", "0.3.0", "v0.6.7")]);
        assert!(verify("pai-voice", false, &r, None).is_ok());
    }

    #[test]
    fn a_disabled_addon_registers_nothing_and_refuses_nothing() {
        let dir = scratch("disabled");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let r = verified(&[("pai-voice", "0.3.0", STACK)]);
        for decl in [&[("pai-voice", false)][..], &[][..]] {
            let snap = run(&dir, decl, &[], &r, &|_| false);
            assert!(snap.all().is_empty() && snap.refused.is_empty(), "{decl:?}: {snap:?}");
        }
    }

    #[test]
    fn an_enabled_addon_that_delivered_no_manifest_is_noted_not_registered() {
        let snap = run(&scratch("nomanifest"), &[("pai-voice", true)], &[], &verified(&[]), &|_| false);
        assert!(snap.all().is_empty() && snap.refused.is_empty());
        assert!(snap.notes().iter().any(|n| n.contains("addons.pai-voice") && n.contains("no route manifest")), "{:?}", snap.notes());
    }

    #[test]
    fn a_name_that_could_leave_the_manifest_directory_is_never_joined_into_a_path() {
        let dir = scratch("traversal");
        for bad in ["../etc", "a/b", "A", "", "x y", "-x"] {
            assert!(!name_ok(bad), "{bad:?}");
        }
        let snap = run(&dir, &[("../etc", true)], &[], &Reported::Dev, &|_| false);
        assert!(snap.all().is_empty());
        assert!(snap.refusal("../etc").is_some_and(|w| w.contains("not valid")), "{:?}", snap.refused);
    }

    #[test]
    fn an_invalid_manifest_is_refused_with_its_reason() {
        let dir = scratch("invalid");
        let mut v = third_party("pai-voice");
        v["addon"] = json!("someone-else");
        plant(&dir, "pai-voice", &v);
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        let why = snap.refusal("pai-voice").expect("refused");
        assert!(why.contains("delivered for") && why.contains("None of its routes"), "{why}");
    }

    // ── the compiled add-ons ride the registry unchanged ─────────────────

    #[test]
    fn a_compiled_http_addon_loads_through_the_registry_like_before() {
        // `evolve` is the compiled HTTP add-on; its fixture is the neutral sample.
        let dir = scratch("compiled");
        plant(&dir, "evolve", &sample_json());
        let on = |n: &str| n == "evolve";
        // New launcher, lock verified: Launcher.
        let snap = run(&dir, &[("evolve", true)], &[], &verified(&[("evolve", "1.0.0", STACK)]), &on);
        let e = snap.get("evolve").expect("registered");
        assert_eq!(e.manifest().routes.len(), sample_json()["routes"].as_array().unwrap().len());
        assert_eq!(e.upstream(), "https://noo-evolve:8090");
        // Old launcher, nothing reported: the first boot after an upgrade
        // keeps working exactly as before.
        let snap = run(&dir, &[], &[], &Reported::Unreported, &on);
        assert_eq!(snap.get("evolve").expect("grandfathered").verification(), &Verification::LegacyLauncher);
        // Off: nothing.
        let snap = run(&dir, &[("evolve", true)], &[], &Reported::Dev, &|_| false);
        assert!(snap.all().is_empty() && snap.refused.is_empty());
    }

    #[test]
    fn a_compiled_addon_the_launcher_did_not_verify_is_refused_naming_the_fix() {
        let dir = scratch("compiled-unverified");
        plant(&dir, "evolve", &sample_json());
        let snap = run(&dir, &[], &[], &verified(&[]), &|n| n == "evolve");
        assert!(snap.get("evolve").is_none());
        assert!(snap.refusal("evolve").unwrap().contains("noo addons upgrade evolve"));
    }

    #[test]
    fn a_missing_manifest_of_a_compiled_http_addon_is_still_refused_loudly() {
        let snap = run(&scratch("compiled-missing"), &[], &[], &Reported::Dev, &|n| n == "evolve");
        let why = snap.refusal("evolve").expect("the old-image diagnostic survives");
        assert!(why.contains("missing") && why.contains("noo addons disable evolve"), "{why}");
    }

    #[test]
    fn grandfathering_never_reaches_a_name_the_table_does_not_know() {
        let dir = scratch("no-grandfather");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Unreported, &|_| false);
        assert!(snap.get("pai-voice").is_none());
        let why = snap.refusal("pai-voice").unwrap();
        assert!(why.contains("noo upgrade") && why.contains("noo addons upgrade pai-voice"), "{why}");
        // A malformed verdict refuses everything, including a compiled add-on.
        let dir2 = scratch("malformed");
        plant(&dir2, "evolve", &sample_json());
        let bad = parse_reported(Some("garbage"));
        let snap = run(&dir2, &[], &[], &bad, &|n| n == "evolve");
        assert!(snap.get("evolve").is_none() && snap.refusal("evolve").unwrap().contains("could not be read"));
    }

    #[test]
    fn a_planted_file_for_a_nats_addon_is_never_read() {
        let dir = scratch("nats");
        plant(&dir, "trellion", &sample_json());
        let snap = run(&dir, &[("trellion", true)], &[], &Reported::Dev, &|n| n == "trellion");
        assert!(snap.all().is_empty() && snap.refused.is_empty(), "{:?}", snap.refused);
    }

    // ── delegation ───────────────────────────────────────────────────────

    #[test]
    fn operator_enabled_is_true_only_with_the_declaration_and_the_enable() {
        for (declares, enables, want) in [(false, false, false), (true, false, false), (false, true, false), (true, true, true)] {
            let dir = scratch("truth");
            let mut v = third_party("pai-voice");
            if declares {
                v["delegate"] = json!("tasks");
            }
            plant(&dir, "pai-voice", &v);
            let snap = run(&dir, &[("pai-voice", true)], &[("pai-voice", enables)], &Reported::Dev, &|_| false);
            let e = snap.get("pai-voice").unwrap();
            assert_eq!(e.delegates_tasks(), declares, "declares={declares} enables={enables}");
            assert_eq!(e.operator_enabled(), want, "declares={declares} enables={enables}");
        }
    }

    #[test]
    fn delegation_is_off_by_default() {
        let dir = scratch("default-off");
        let mut v = third_party("pai-voice");
        v["delegate"] = json!("tasks");
        plant(&dir, "pai-voice", &v);
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        let e = snap.get("pai-voice").unwrap();
        assert!(e.delegates_tasks() && !e.operator_enabled());
    }

    #[test]
    fn route_receives_delegation_truth_table() {
        let dir = scratch("route-deleg");
        let mut v = third_party("pai-voice");
        v["delegate"] = json!("tasks");
        v["routes"][0]["receives_delegation"] = json!(true); // GET /api/sample/status (+ alias)
        v["routes"][2]["receives_delegation"] = json!(true); // GET /api/sample/items/{item_id}
        plant(&dir, "pai-voice", &v);
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        let e = snap.get("pai-voice").unwrap();
        assert!(e.route_receives_delegation("GET", "/api/sample/status"));
        assert!(e.route_receives_delegation("GET", "/api/sample-alt/status"), "an alias is the same route");
        assert!(e.route_receives_delegation("GET", "/api/sample/items/abc"), "a {{param}} route matches");
        assert!(!e.route_receives_delegation("GET", "/api/sample/items"), "declared without the flag: default false");
        assert!(!e.route_receives_delegation("POST", "/api/sample/run"));
        assert!(!e.route_receives_delegation("POST", "/api/sample/status"), "method must match");
        assert!(!e.route_receives_delegation("GET", "/api/unknown"), "no route, no token");
        assert!(!e.route_receives_delegation("GET", "/api/sample/dispatch"), "internal routes never match");
        // The accessor is the route half only; the operator half is separate.
        assert!(!e.operator_enabled());
        // A static route beside a {param} one: every match must opt in.
        let mut w = third_party("pai-voice");
        w["delegate"] = json!("tasks");
        w["routes"][1]["receives_delegation"] = json!(true); // GET /api/sample/items (static)
        w["routes"][2]["receives_delegation"] = json!(false);
        plant(&dir, "pai-voice", &w);
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        let e = snap.get("pai-voice").unwrap();
        assert!(e.route_receives_delegation("GET", "/api/sample/items"));
        assert!(!e.route_receives_delegation("GET", "/api/sample/items/abc"));
    }

    #[test]
    fn task_events_are_exposed_as_declared() {
        let dir = scratch("events");
        let mut v = third_party("pai-voice");
        v["delegate"] = json!("tasks");
        v["task_events"] = json!({"method": "POST", "path": "/internal/task-events"});
        plant(&dir, "pai-voice", &v);
        let snap = run(&dir, &[("pai-voice", true)], &[("pai-voice", true)], &Reported::Dev, &|_| false);
        let e = snap.get("pai-voice").unwrap();
        assert_eq!(e.task_events(), Some(&TaskEventsSpec { method: "POST".into(), path: "/internal/task-events".into() }));
        assert!(e.operator_enabled());
        // No task_events in the manifest: none exposed.
        let dir = scratch("no-events");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        assert!(snap.get("pai-voice").unwrap().task_events().is_none());
    }

    #[test]
    fn an_enable_that_names_nothing_is_reported_not_silent() {
        let dir = scratch("dangling");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        // Enabled in config, manifest does not declare it.
        let snap = run(&dir, &[("pai-voice", true)], &[("pai-voice", true), ("ghost", true)], &Reported::Dev, &|_| false);
        assert!(!snap.get("pai-voice").unwrap().operator_enabled());
        let notes = snap.notes().join("\n");
        assert!(notes.contains("does not declare") && notes.contains("addon_delegation.ghost"), "{notes}");
    }

    // ── development keys (i163 part A) ───────────────────────────────────

    #[test]
    fn the_dev_variable_parses_and_a_bad_one_is_an_error() {
        assert_eq!(parse_dev(None), Ok(BTreeMap::new()));
        assert_eq!(parse_dev(Some(" ")), Ok(BTreeMap::new()));
        let m = parse_dev(Some("pai-voice=1790003600,b=7")).unwrap();
        assert_eq!((m["pai-voice"], m["b"]), (1_790_003_600, 7));
        for bad in ["pai-voice", "pai-voice=", "pai-voice=soon", "pai-voice=-1", "../x=1", "a=1,,b=2"] {
            assert!(parse_dev(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_dev_signed_addon_registers_as_dev_until_its_key_expires() {
        let dir = scratch("devkey");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let at = NOW + 3600;
        let dev = Ok(BTreeMap::from([("pai-voice".to_string(), at)]));
        let rep = verified(&[("pai-voice", "0.3.0", STACK)]);
        let snap = run_dev(&dir, &[("pai-voice", true)], &[], &rep, &dev, NOW, &|_| false);
        let e = snap.get("pai-voice").expect("registered while the key is live");
        assert_eq!(e.verification(), &Verification::DevKey { version: "0.3.0".into(), stack: STACK.into(), expires_at: at });
        assert_eq!(snap.dev_label_at("pai-voice", NOW), Some(format!("dev (expires {})", utc_minute(at))));
        assert!(snap.get_at("pai-voice", NOW).is_some() && snap.refusal_at("pai-voice", NOW).is_none());
        // Past the instant, while still running: no longer served, refused with the reason.
        assert!(snap.get_at("pai-voice", at).is_none());
        assert!(snap.all_at(at).is_empty());
        assert_eq!(snap.dev_label_at("pai-voice", at), None);
        let why = snap.refusal_at("pai-voice", at).expect("refused once expired");
        assert!(why.contains("expired") && why.contains(&utc_minute(at)) && why.contains("--dev --expires"), "{why}");
        assert!(snap.refusals_at(at).contains_key("pai-voice"));
        // Already expired at load: refused outright.
        let snap = run_dev(&dir, &[("pai-voice", true)], &[], &rep, &dev, at, &|_| false);
        assert!(snap.get("pai-voice").is_none());
        assert!(snap.refusal("pai-voice").is_some_and(|w| w.contains("development key")));
    }

    #[test]
    fn a_dev_entry_never_vouches_by_itself_and_a_release_addon_is_not_dev() {
        let dir = scratch("devstray");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let dev = Ok(BTreeMap::from([("pai-voice".to_string(), NOW + 3600)]));
        // Not in the verdict: refused exactly as without the dev entry.
        let snap = run_dev(&dir, &[("pai-voice", true)], &[], &verified(&[]), &dev, NOW, &|_| false);
        assert!(snap.get("pai-voice").is_none() && snap.refusal("pai-voice").is_some());
        // In the verdict with no dev entry: a release verification, no label.
        let snap = run(&dir, &[("pai-voice", true)], &[], &verified(&[("pai-voice", "0.3.0", STACK)]), &|_| false);
        assert!(matches!(snap.get("pai-voice").unwrap().verification(), Verification::Launcher { .. }));
        assert_eq!(snap.dev_label_at("pai-voice", NOW), None);
        // An unreadable dev variable is a note and trusts nothing more.
        let bad = Err("NOO_ADDONS_DEV entry \"x\" is not `<add-on>=<unix seconds>`".to_string());
        let snap = run_dev(&dir, &[("pai-voice", true)], &[], &verified(&[("pai-voice", "0.3.0", STACK)]), &bad, NOW, &|_| false);
        assert!(matches!(snap.get("pai-voice").unwrap().verification(), Verification::Launcher { .. }));
        assert!(snap.notes().iter().any(|n| n.contains("NOO_ADDONS_DEV")), "{:?}", snap.notes());
    }

    // ── reads are cheap ──────────────────────────────────────────────────

    #[test]
    fn get_works_without_a_database_or_a_runtime() {
        // A plain #[test]: no tokio runtime, no AppState, no pool. The free
        // functions read the process snapshot, which is built from files and
        // environment alone.
        assert!(get("no-such-addon").is_none());
        let _ = all();
        let _ = refusal("no-such-addon");
        let dir = scratch("nodb");
        plant(&dir, "pai-voice", &third_party("pai-voice"));
        let snap = run(&dir, &[("pai-voice", true)], &[], &Reported::Dev, &|_| false);
        assert!(snap.get("pai-voice").is_some());
    }

    #[test]
    fn the_read_path_never_awaits_or_touches_a_database() {
        let src = include_str!("addon_registry.rs");
        let prod = &src[..src.find("#[cfg(test)]").unwrap()];
        // Strip comments so the doc text above may name what it forbids.
        let code: String = prod.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for banned in [".await", "async fn", "sqlx", "PgPool", "AppState", "tokio::"] {
            assert!(!code.contains(banned), "the registry read path must stay synchronous and DB-free: found {banned:?}");
        }
    }

    // ── the core names no add-on's routes ────────────────────────────────

    /// Route prefixes of the one add-on whose manifest used to be compiled
    /// into expectations. A test may name them (here); no other core source
    /// may. Third-party add-ons' routes are unknowable, so the registry is
    /// the only place that learns a route, at runtime, from a manifest.
    const ADDON_ROUTE_PREFIXES: &[&str] = &[
        "/api/hofstadter-loop",
        "/api/ga/",
        "/api/rl-policy",
        "/api/agent/meta-loop",
    ];

    fn rust_files(dir: &FsPath, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let p = entry.unwrap().path();
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    // ── bundle declaration: system.json (i163 E) ─────────────────────────

    const EX: &str = "example-addon";

    /// Plant `system.json` the way the launcher delivers it, and build.
    fn run_decls(dir: &FsPath, system: Option<&Value>, decl: &[(&str, bool)], reported: &Reported) -> Snapshot {
        let sys = dir.join("systems");
        if let Some(s) = system {
            std::fs::create_dir_all(sys.join(EX)).unwrap();
            std::fs::write(sys.join(EX).join(crate::addon_decls::SYSTEM_FILE), s.to_string()).unwrap();
        }
        build(
            &Inputs {
                dir,
                systems_dir: &sys,
                declared: &declared(decl),
                delegation: &delegation(&[]),
                reported,
                gateway_stack: Some(STACK),
                dev: &Ok(BTreeMap::new()),
                now: NOW,
            },
            &|_| false,
        )
    }

    fn ex_system() -> Value {
        json!({"schema": "example_addon", "role": "noo_example_addon", "ddl_role": "noo_example_addon_ddl"})
    }

    #[test]
    fn a_registered_addon_contributes_its_system() {
        let dir = scratch("decls-ok");
        plant(&dir, EX, &third_party(EX));
        let snap = run_decls(&dir, Some(&ex_system()), &[(EX, true)], &verified(&[(EX, "0.1.0", STACK)]));
        assert!(snap.refused.is_empty(), "{:?}", snap.refused);
        let systems = snap.declared_systems();
        let s = systems.get("example_addon").expect("its system is declared under the underscored name");
        assert_eq!((s.role.as_str(), s.ddl_role.as_str()), ("noo_example_addon", "noo_example_addon_ddl"));
        assert_eq!(s.password_env, "NOO_EXAMPLE_ADDON_DB_PASSWORD");
        assert_eq!(s.enabled_when, None);
        // A dev build registers too (a source checkout signs nothing).
        let dir = scratch("decls-dev");
        plant(&dir, EX, &third_party(EX));
        let snap = run_decls(&dir, Some(&ex_system()), &[(EX, true)], &Reported::Dev);
        assert!(snap.declared_systems().contains_key("example_addon"));
    }

    #[test]
    fn an_unverified_disabled_or_wrong_stack_addon_contributes_nothing() {
        let dir = scratch("decls-unverified");
        plant(&dir, EX, &third_party(EX));
        let snap = run_decls(&dir, Some(&ex_system()), &[(EX, true)], &verified(&[]));
        assert!(snap.refusal(EX).is_some());
        assert!(snap.declared_systems().is_empty());

        let dir = scratch("decls-off");
        plant(&dir, EX, &third_party(EX));
        let snap = run_decls(&dir, Some(&ex_system()), &[(EX, false)], &verified(&[(EX, "0.1.0", STACK)]));
        assert!(snap.refusal(EX).is_none());
        assert!(snap.declared_systems().is_empty());

        let dir = scratch("decls-stack");
        plant(&dir, EX, &third_party(EX));
        let snap = run_decls(&dir, Some(&ex_system()), &[(EX, true)], &verified(&[(EX, "0.1.0", "v0.0.1")]));
        assert!(snap.declared_systems().is_empty());
    }

    #[test]
    fn an_invalid_system_refuses_the_whole_addon() {
        let dir = scratch("decls-bad-system");
        plant(&dir, EX, &third_party(EX));
        let mut bad = ex_system();
        bad["role"] = json!("noo_app");
        let snap = run_decls(&dir, Some(&bad), &[(EX, true)], &verified(&[(EX, "0.1.0", STACK)]));
        assert!(snap.get(EX).is_none(), "no routes for an add-on whose system.json is refused");
        assert!(snap.refusal(EX).unwrap().contains("`role`"));
        assert!(snap.declared_systems().is_empty());
    }

    #[test]
    fn core_source_names_no_addon_route_path() {
        let src = FsPath::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 50, "the scan found only {} files: wrong directory?", files.len());
        let mut hits = Vec::new();
        for f in files {
            // This file holds the list; fixtures under tests/ are not scanned.
            if f.file_name().is_some_and(|n| n == "addon_registry.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            for (i, line) in text.lines().enumerate() {
                if let Some(p) = ADDON_ROUTE_PREFIXES.iter().find(|p| line.contains(**p)) {
                    hits.push(format!("{}:{}: {p}", f.strip_prefix(&src).unwrap().display(), i + 1));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "core must not name an add-on's route path (the add-on's manifest declares it at runtime):\n  {}",
            hits.join("\n  ")
        );
    }
}
