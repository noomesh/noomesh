// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security secrets` — audit and rotate the application secret store.
//!
//! # Why this exists
//!
//! On 2026-08-03 an operator session leaked **every value in
//! `secrets/env.sops`** into a terminal transcript. Not by dumping the store
//! on purpose — by decrypting it to a plaintext file and running `diff`
//! against it to check for drift. `diff` prints the lines it disagrees about,
//! and those lines are `KEY=<credential>`. One command, whole store exposed,
//! and the plaintext copy outlived the session on disk.
//!
//! The lesson is not "be careful with diff". It is that **there was no safe
//! tool to reach for**, so every question about the store ("is this key set?
//! does .env still hold a credential? do the two agree?") was answered by
//! decrypting it. This module is that tool.
//!
//! # The invariant
//!
//! **No code path here prints, logs, or writes a secret VALUE.** Not to
//! stdout, not to stderr, not to a file, not into a test fixture. Values
//! exist only:
//!   - in memory, inside [`SecretStore`];
//!   - on the stdin pipe of a `sops -e` child (never a file, never argv);
//!   - on the stdin pipe of a `psql` child running `ALTER ROLE`.
//!
//! What may be reported: the key NAME, whether it is present in each store,
//! whether the value is set/blank/missing, its length in bytes, and the first
//! 8 hex chars of its sha256. That is enough to answer every drift question
//! (`sha256[:8]` equal ⇒ the two stores agree) and reveals nothing usable.
//!
//! [`render_audit`] and [`render_plan`] are pure string builders precisely so
//! a test can hand them values with known sentinels and assert that none of
//! those sentinels ever appear in the output. See `no_value_ever_reaches_output`.
//!
//! # Rotation model — prepare-all, verify-all, then commit
//!
//! Copied deliberately from `scripts/noo-backup-rotate-passphrase.sh`, whose
//! philosophy is: *"It
//! prepares every file before committing any … If anything fails, nothing
//! changes."* A half-applied rotation — store updated but the datastore still
//! on the old password, or vice versa — is worse than no rotation, because
//! the system is now down AND nobody knows the working credential.
//!
//! So [`secrets_rotate`] runs strictly in phases: plan (pure) → prepare (a
//! fully-encrypted, decrypt-verified replacement file next to the original,
//! original untouched) → apply (the datastore-side consequence, revertible)
//! → commit (one `rename(2)`) → report. Any failure before the rename leaves
//! the store byte-identical.
//!
//! # Why `sops -e` is fed on stdin
//!
//! The documented secrets procedure warns never to run the documented
//! `sops -e … > secrets/env.sops` form: the shell opens (and truncates) the
//! target before sops runs, so a sops failure destroys the store. The usual
//! fix is "encrypt to a temp file first" — but that writes PLAINTEXT to disk
//! on the way in. `sops -e --filename-override <target> /dev/stdin` avoids
//! both: plaintext arrives on a pipe, ciphertext leaves on a pipe, and only
//! ciphertext is ever written. `--filename-override` is mandatory — sops
//! matches `.sops.yaml`'s `creation_rules` against the *input* path, and
//! `/dev/stdin` matches no rule ("no matching creation rules found").

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::envfile;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

// ─────────────────────────────────────────────────────────────────────────
// Classification — what rotating a given secret actually COSTS
// ─────────────────────────────────────────────────────────────────────────

/// What kind of thing a secret is, which determines whether this tool can
/// rotate it at all and what has to happen after the value changes.
///
/// The distinction that matters most is [`Class::FleetWide`]: those values
/// are held by every node in the cluster, not just the controller. Changing
/// one centrally and restarting is not a rotation — it is an outage, because
/// every node still presents the old credential. This tool refuses those
/// loudly rather than half-doing them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// A Postgres role password. Rotatable: generate → `ALTER ROLE` →
    /// verify a login with the new value → recreate the consumers.
    DbPassword {
        /// Role whose password this is. `None` = read from `POSTGRES_USER`
        /// at runtime (the superuser role the image creates; default `noo`).
        role: Option<&'static str>,
    },
    /// A shared-service credential (Redis / NATS) that is BOTH the server's
    /// configured password and every client's. There is no window in which
    /// old and new both work, so server and clients must come up together —
    /// a coordinated recreate of the whole controller stack.
    SharedService,
    /// Controller-local: changing the value and recreating the controller is
    /// the entire rotation. No datastore step, no fleet step.
    ControllerLocal,
    /// Held by EVERY node, not just the controller. Refused — see the module
    /// docs and [`fleet_refusal`].
    FleetWide,
    /// Issued by a third party (Anthropic, HuggingFace, Telegram, …). Cannot
    /// be generated locally at all; the operator revokes and re-issues at the
    /// provider, then injects the new value with `--set-from-stdin`.
    ProviderIssued,
    /// A dedicated tool already rotates this correctly, doing work this one
    /// does not. Refused, with a pointer — duplicating that logic badly is
    /// how credentials get lost.
    ExternalTool {
        tool: &'static str,
    },
    /// A backup-encryption passphrase. Rotatable HERE, and only here.
    ///
    /// These were `ExternalTool`, pointing at
    /// `scripts/noo-backup-rotate-passphrase.sh`, on the grounds that the
    /// script did work this command did not: re-encrypting every existing
    /// backup old → new. The grounds were sound and the conclusion was
    /// wrong. That script treated `.env` as the plaintext source and
    /// re-encrypted `secrets/env.sops` FROM it — a full replace — so on a
    /// sops-first install, where `.env` holds two bootstrap flags and the
    /// store holds thirty secrets, running it would have reduced the store
    /// to those two flags and written both passphrases to `.env` in
    /// plaintext. Caught in dry-run on the live controller, 2026-09-12
    /// Meanwhile `rotate` refused them, so there was no safe
    /// path to these two values anywhere in the product.
    ///
    /// Rather than fix the store write in a second implementation, the
    /// missing capability moved here: this class carries the artifact glob,
    /// and rotation re-encrypts every matching file old → new, verifies each,
    /// and commits them only after the store commit succeeds. One
    /// implementation, and it is the one that already writes the store
    /// correctly (`prepare_store`: key-set diff, round-trip verify, atomic
    /// rename, plaintext only ever on a pipe).
    BackupPassphrase {
        /// Filename glob, relative to `NOO_BACKUP_DIR`, of the artifacts this
        /// passphrase opens.
        glob: &'static str,
    },
    /// **Not an independent secret.** Its value is a FUNCTION of `parent`, so
    /// it cannot be minted here and — more importantly — it is silently
    /// invalidated the moment `parent` rotates.
    ///
    /// That ordering is the whole reason this variant exists. A derived
    /// credential looks like any other opaque string in the store, so a
    /// "rotate the parent, recreate the containers" run reports success while
    /// leaving the dependent service holding a token that no longer verifies.
    /// Encoding the edge lets [`derived_children`] surface the re-mint step in
    /// the parent's own plan, before the operator walks away.
    ///
    /// No member since 2026-09-24: the one derived credential,
    /// NOO_EVOLVE_GATEWAY_TOKEN, was never minted by anything and became a
    /// per-consumer key. The class and its plan rendering stay
    /// for the next value that is computed from another — the shape is real
    /// even while the registry has none.
    #[allow(dead_code)]
    Derived {
        /// Registry key this value is computed from.
        parent: &'static str,
        /// How to re-mint it once the parent has changed.
        mint: &'static str,
    },
}

impl Class {
    pub fn label(&self) -> &'static str {
        match self {
            Class::DbPassword { .. } => "db-password",
            Class::SharedService => "shared-service",
            Class::ControllerLocal => "controller-local",
            Class::FleetWide => "fleet-wide",
            Class::ProviderIssued => "provider-issued",
            Class::ExternalTool { .. } => "external-tool",
            Class::BackupPassphrase { .. } => "backup-passphrase",
            Class::Derived { .. } => "derived",
        }
    }

    /// How `rotate` treats this class, as a one-word machine field.
    pub fn disposition(&self) -> &'static str {
        match self {
            Class::DbPassword { .. }
            | Class::SharedService
            | Class::ControllerLocal
            | Class::BackupPassphrase { .. } => "auto",
            Class::FleetWide | Class::ExternalTool { .. } => "refused",
            // Cannot be generated here, but CAN be installed with
            // `--set-from-stdin` once the operator obtains the new value —
            // from the provider, or by re-minting it from the parent secret.
            Class::ProviderIssued | Class::Derived { .. } => "manual",
        }
    }

    /// True when this tool can mint a replacement value itself.
    pub fn self_generatable(&self) -> bool {
        matches!(
            self,
            Class::DbPassword { .. }
                | Class::SharedService
                | Class::ControllerLocal
                | Class::BackupPassphrase { .. }
        )
    }
}

/// One entry in the secret registry.
/// When an install actually needs a secret.
///
/// Declared HERE, beside the key it governs, rather than in a second table.
/// A parallel list of exceptions is the drift bug this whole registry exists
/// to avoid — `registry_is_well_formed` can check a field, it cannot check
/// that someone remembered to update a match arm somewhere else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Requirement {
    /// Every install needs this one.
    Always,
    /// Needed only when the named env flag is truthy. An install with the
    /// flag off does not want the credential and should not be nagged about
    /// it; an install with the flag ON and no credential is broken.
    WhenEnabled(&'static str),
    /// Needed only when the named ADD-ON is declared on in noomesh.yaml
    /// (`addons.<name>`). This used to be `WhenEnabled("NOO_PRO_ENABLED")`:
    /// the launcher refuses to start on that flag since 2026-09-04, so the
    /// evolve credentials were required by a switch nobody could set and an
    /// evolve install with no `NOO_EVOLVE_DB_PASSWORD` audited clean.
    WhenAddon(&'static str),
    /// Needed unless the install profile is `standalone` (Ollama-only: no
    /// vllm/llamacpp placement or profile, no HuggingFace-backed model
    /// preseed). Resolved through the `"profile.not-standalone"` gate name
    /// (see `secrets_audit`'s `flag_on`), true when `.env`'s
    /// `NOO_DEFAULT_PROFILE` is anything other than `standalone`. Added
    /// 2026-09-29 after a standalone, Ollama-only rehearsal reported
    /// `ERROR required-key-absent HF_TOKEN` for a credential nothing on
    /// that install could ever consume.
    WhenNotStandalone,
    /// Never required: a provider key or a passphrase the operator supplies
    /// only when they use that feature (cloud fallback, Telegram, backups).
    /// Absent is the normal state of a fresh install, so it is reported at
    /// Info — the fresh walk on 2026-09-07 printed six of these as ERROR.
    Optional,
}

impl Requirement {
    /// Whether this install needs the key. `on` resolves a gate name — an
    /// env flag, or `addons.<name>` for an add-on — passed in rather than
    /// read here, for the same reason `sops_backend` is a parameter of
    /// `audit_findings`: a pure function stays testable.
    pub fn required(&self, on: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Requirement::Always => true,
            Requirement::WhenEnabled(flag) => on(flag),
            Requirement::WhenAddon(name) => on(&Self::addon_gate(name)),
            Requirement::WhenNotStandalone => on("profile.not-standalone"),
            Requirement::Optional => false,
        }
    }

    /// The gate name an add-on requirement resolves through: `addons.<name>`,
    /// the key's spelling in noomesh.yaml.
    pub fn addon_gate(name: &str) -> String {
        format!("addons.{name}")
    }
}

/// Registry rows only this CLI reads (no container holds them, so a rotation
/// recreates nothing): `consumers` is empty on purpose, and
/// `registry_is_well_formed` allows exactly these.
/// The "must be recreated" block of a rotation report: `None` when no
/// container holds the key (a CLI-only key, `recreate: (none)`), so the
/// heading is never printed over an empty list (i57b).
fn recreate_notice(consumers: &[String]) -> Option<String> {
    if consumers.is_empty() {
        return None;
    }
    Some(format!(
        "these containers hold the old value and must be recreated (an env change does not survive a plain docker restart): {}",
        consumers.join(", ")
    ))
}

#[cfg(test)]
pub(crate) const CLI_ONLY_SECRETS: &[&str] = &["NOO_ADDON_REGISTRY_TOKEN"];

pub struct SecretSpec {
    pub key: &'static str,
    pub class: Class,
    /// Bytes of entropy for a generated replacement (`token_urlsafe(n)`).
    /// **0 means this tool never mints a value for this key** — enforced by
    /// `registry_is_well_formed`, so a key cannot be moved into a refused
    /// class while quietly keeping a generator.
    pub gen_bytes: usize,
    /// What the operator must know before/after rotating this value.
    pub consequence: &'static str,
    /// Containers that hold this value in their environment and therefore
    /// need a RECREATE (not a restart) once the store changes.
    pub consumers: &'static [&'static str],
    /// Whether this install needs the key at all. See [`Requirement`].
    pub required_when: Requirement,
}

/// One add-on overlay's `x-noo-addon` block, parsed and validated
/// (`crate::addon_decl_parse`). Two sources, each an authority the operator
/// did not type: the overlays this binary embeds (build.rs: trellion), and a
/// licensed add-on's overlay that arrived in its SIGNED bundle (N6), read
/// only while its bytes still hash to the pinned lock ([`addon_decls`]). A
/// hand-edited `~/.noo` overlay therefore cannot widen what `provision` asks
/// for: an edited file no longer matches its lock and declares nothing.
#[derive(Debug)]
pub struct AddonDecl {
    /// The overlay file that declares it, relative to the install root:
    /// `docker-compose.trellion.yml`, or `addons/<name>/docker-compose.yml`
    /// for an add-on's bundled overlay.
    pub overlay: &'static str,
    /// The `addons:<name>` key in noomesh.yaml (`addons::ADDON_ROWS`).
    pub addon: &'static str,
    /// The `noo_service_keys` consumer the key is minted under.
    pub consumer: &'static str,
    /// The store key; compose delivers it as `NOO_GATEWAY_KEY`.
    pub key: &'static str,
    /// Every container that holds it — recreated on provision and rotate.
    pub containers: &'static [&'static str],
    /// What the add-on ASKS for, in the gateway's words. `addon` is never
    /// here: `provisioned_scopes` always adds it.
    pub scopes: &'static [&'static str],
    /// Optional plain-language reason, shown by `provision`.
    pub why: Option<&'static str>,
}

// `ADDON_DECLS` and `ADDON_KEY_SPECS`, generated from the embedded overlays.
include!(concat!(env!("OUT_DIR"), "/addon_decls.rs"));

/// Every registry row: the hand-written core rows, then the add-on key rows
/// derived from the overlays (embedded, then bundled). The ONE way to read
/// the registry.
pub fn registry() -> impl Iterator<Item = &'static SecretSpec> {
    let bundled: Vec<&'static SecretSpec> = runtime_addon_rows().into_iter().map(|(_, s)| s).collect();
    CORE_REGISTRY.iter().chain(ADDON_KEY_SPECS.iter()).chain(bundled)
}

/// Every add-on declaration: the embedded ones (`ADDON_DECLS`), then each
/// licensed add-on's from the overlay its signed bundle brought. Readers
/// never iterate `ADDON_DECLS` directly: that would skip every licensed
/// add-on, whose overlay no longer ships in this tree.
pub fn addon_decls() -> Vec<&'static AddonDecl> {
    ADDON_DECLS.iter().chain(runtime_addon_rows().into_iter().map(|(d, _)| d)).collect()
}

/// The registry row text for one declaration (build.rs writes the same
/// sentence for the embedded ones).
fn addon_key_consequence(overlay: &str, d: &crate::addon_decl_parse::ParsedDecl) -> String {
    let holders = d.containers.join(", ");
    let why = d.why.as_deref().map(|w| format!(" Why: {w}")).unwrap_or_default();
    format!(
        "{holders}'s OWN gateway key ({consumer}), delivered to that container only as \
         NOO_GATEWAY_KEY and exchanged at /api/addon/token for a 10-minute token carrying: \
         {scopes}. Declared in {overlay} (x-noo-addon), which is what this row is derived \
         from. It is the add-on's ONLY gateway credential: absent, every call it makes \
         is refused (the shared-secret fallback is retired, and the gateway refuses an \
         add-on's HMAC). `noo security service-key provision {name}` shows the request, mints, \
         stores, recreates and proves it: a key that is stored but never presented is \
         indistinguishable from no key at all.{why}",
        consumer = d.consumer,
        scopes = d.scopes.join(", "),
        name = d.addon.replace('_', "-"),
    )
}

/// The overlay text a licensed add-on's declaration may be read from, and
/// the label it is reported under, or `None`. In order:
///   1. its bundle, `<root>/addons/<addon>/docker-compose.yml`, only while
///      the bytes hash to the `files` entry of the cached lock its pin names
///      (the signature was checked when the pin was written; `noo addons
///      verify` re-checks it);
///   2. a development install (no `NOO_IMAGE_TAG`): the add-on checkout's own
///      overlay, `${NOO_<ADDON>_PATH:-../noo-<addon>}/docker-compose.<addon>.yml`.
pub(crate) fn trusted_addon_overlay(root: &std::path::Path, addon: &str) -> Option<(String, String)> {
    use crate::addons::pins;
    let bundle = pins::addon_dir(root, addon).join(crate::addon_lock::OVERLAY_FILE);
    if let Ok(bytes) = std::fs::read(&bundle) {
        let pinned = pins::read(root).ok().and_then(|all| all.get(addon).cloned());
        let signed = pinned
            .and_then(|pin| pins::cached_lock(root, addon, &pin).ok())
            .and_then(|(lock, _)| serde_json::from_slice::<crate::addon_lock::AddonLock>(&lock).ok())
            .and_then(|l| l.files.get(crate::addon_lock::OVERLAY_FILE).cloned());
        if signed.as_deref() == Some(crate::addon_lock::sha256_ref(&bytes).as_str()) {
            let label = format!("{}/{addon}/{}", pins::ADDONS_DIR, crate::addon_lock::OVERLAY_FILE);
            return String::from_utf8(bytes).ok().map(|t| (label, t));
        }
        return None;
    }
    if crate::addons::current_tag(root).is_none() {
        let kebab = addon.replace('_', "-");
        let var = format!("NOO_{}_PATH", addon.to_ascii_uppercase());
        let base = std::env::var(&var).ok().filter(|v| !v.trim().is_empty()).map(std::path::PathBuf::from)
            .unwrap_or_else(|| root.join("..").join(format!("noo-{kebab}")));
        let base = if base.is_absolute() { base } else { root.join(base) };
        let p = base.join(format!("docker-compose.{kebab}.yml"));
        if let Ok(t) = std::fs::read_to_string(&p) {
            return Some((p.display().to_string(), t));
        }
    }
    None
}

/// The licensed add-ons' declarations and registry rows, read at run time
/// from [`trusted_addon_overlay`]. Leaked once per (label, bytes): the CLI is
/// short-lived and a declaration is a few hundred bytes, and `&'static` keeps
/// one row type for embedded and bundled declarations alike. A malformed
/// block warns on stderr and declares nothing.
fn runtime_addon_rows() -> Vec<(&'static AddonDecl, &'static SecretSpec)> {
    #[cfg(test)]
    {
        test_runtime_rows()
    }
    #[cfg(not(test))]
    {
        runtime_addon_rows_at(&crate::envfile::repo_root())
    }
}

type RuntimeRow = (&'static AddonDecl, &'static SecretSpec);
static RUNTIME_ROWS: std::sync::Mutex<Vec<(String, RuntimeRow)>> = std::sync::Mutex::new(Vec::new());

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak_strs(v: &[String]) -> &'static [&'static str] {
    Box::leak(v.iter().map(|s| leak_str(s.clone())).collect::<Vec<_>>().into_boxed_slice())
}

/// One declaration text to its leaked row (cached by label and bytes).
fn runtime_row(label: &str, text: &str, addon: &str) -> Option<RuntimeRow> {
    let cache_key = format!("{label}\0{}", crate::addons::pins::sha256_hex(text.as_bytes()));
    let mut cache = RUNTIME_ROWS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, row)) = cache.iter().find(|(k, _)| *k == cache_key) {
        return Some(*row);
    }
    let d = match crate::addon_decl_parse::parse_decl(label, text, Some(addon)) {
        Ok(Some(d)) => d,
        Ok(None) => return None,
        Err(e) => {
            eprintln!("warning: {e}; the add-on's key declaration is ignored");
            return None;
        }
    };
    let decl: &'static AddonDecl = Box::leak(Box::new(AddonDecl {
        overlay: leak_str(label.to_string()),
        addon: leak_str(d.addon.clone()),
        consumer: leak_str(d.consumer.clone()),
        key: leak_str(d.key.clone()),
        containers: leak_strs(&d.containers),
        scopes: leak_strs(&d.scopes),
        why: d.why.clone().map(leak_str),
    }));
    let spec: &'static SecretSpec = Box::leak(Box::new(SecretSpec {
        key: decl.key,
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: leak_str(addon_key_consequence(label, &d)),
        consumers: decl.containers,
        required_when: Requirement::Optional,
    }));
    cache.push((cache_key, (decl, spec)));
    Some((decl, spec))
}

/// [`runtime_addon_rows`] for the install at `root`: each licensed add-on
/// (`ADDON_ROWS`) that no embedded overlay declares, then each third-party
/// add-on with a pin (`addons.lock`), from its trusted overlay. Duplicates of
/// an embedded key, consumer or add-on, and a core key, are dropped.
///
/// The third-party ones matter as much as the licensed ones: `noo addons
/// enable` plans and issues the gateway key from this table, so an add-on
/// missing here is enabled with no `NOO_SVC_KEY_<ID>`, and the launcher then
/// refuses its `addon_key` resource (the 0.6.13-rc.2 rehearsal, rhres). Its
/// declaration was checked at enable (`addons::guards`: the key is the one
/// derived from its name), and is read only while it matches the signed lock.
pub(crate) fn runtime_addon_rows_at(root: &std::path::Path) -> Vec<RuntimeRow> {
    let licensed = crate::commands::addons::ADDON_ROWS.iter().filter(|r| r.licensed.is_some()).map(|r| r.key.to_string());
    let third_party: Vec<String> = crate::addons::pins::read(root)
        .map(|p| p.into_keys().filter(|a| crate::addons::resolve::third_party(a)).collect())
        .unwrap_or_default();
    let mut out: Vec<RuntimeRow> = Vec::new();
    for addon in licensed.chain(third_party) {
        if ADDON_DECLS.iter().any(|d| d.addon == addon) {
            continue;
        }
        let Some((label, text)) = trusted_addon_overlay(root, &addon) else { continue };
        let Some((d, spec)) = runtime_row(&label, &text, &addon) else { continue };
        let clash = ADDON_DECLS.iter().chain(out.iter().map(|(d, _)| *d))
            .any(|o| o.key == d.key || o.consumer == d.consumer)
            || CORE_REGISTRY.iter().any(|c| c.key == d.key);
        if clash {
            eprintln!("warning: {label} declares a key or consumer another add-on already declares; ignored");
            continue;
        }
        out.push((d, spec));
    }
    out
}

/// Tests see the two licensed add-ons' declarations as their bundles carry
/// them (the add-on repos hold the overlays; these are their x-noo-addon
/// blocks, so the provision and verify tests keep real shapes).
#[cfg(test)]
pub(crate) const TEST_BUNDLED_DECLS: &[(&str, &str)] = &[
    (
        "trellion_intel",
        "x-noo-addon:\n  addon: trellion_intel\n  consumer: svc:trellion-intel\n  key: NOO_SVC_KEY_TRELLION_INTEL\n  \
         containers: [noo-trellion-intel]\n  scopes: [chat, embeddings, metrics]\n  why: >-\n    the graph engine's \
         extraction calls the gateway's chat and embeddings, and its counters post to the gateway's metrics door.\n",
    ),
    (
        "evolve",
        "x-noo-addon:\n  addon: evolve\n  consumer: svc:evolve\n  key: NOO_SVC_KEY_EVOLVE\n  containers: [noo-evolve]\n  \
         scopes: [temporal, heartbeat, activities, channels:send, metrics, config:agent, config:memory, config:cluster, \
         config:cache, config:web_search, config:self_identity, config:prompt_skills, config:recall_memory, config:ga, \
         conversation_stats, prompt_skills:write]\n  why: >-\n    the evolve loop writes temporal edges, runs and toggles \
         heartbeat tasks, files activities, sends operator alerts, posts its counters, tunes these config sections and \
         reads fleet-wide conversation stats aggregates for its composite score, and writes evolved prompt skills.\n",
    ),
];

#[cfg(test)]
fn test_runtime_rows() -> Vec<RuntimeRow> {
    TEST_BUNDLED_DECLS
        .iter()
        .filter_map(|(addon, text)| runtime_row(&format!("addons/{addon}/docker-compose.yml"), text, addon))
        .collect()
}

/// The add-on declaration `by` names: an add-on key (`trellion_intel`), its
/// hyphenated spelling (`trellion-intel`), its consumer (`svc:trellion-intel`)
/// or its store key (`NOO_SVC_KEY_TRELLION_INTEL`).
pub fn addon_decl(by: &str) -> Option<&'static AddonDecl> {
    let by = by.trim();
    addon_decls().into_iter().find(|d| {
        d.addon == by
            || d.addon.replace('_', "-") == by
            || d.consumer == by
            || d.key.eq_ignore_ascii_case(by)
    })
}

/// The CORE registry: every hand-written row. A key absent from `registry()`
/// is still audited — it just has no rotation plan, which the audit reports
/// as `unclassified-credential` so the gap is visible rather than silently
/// unrotatable.
///
/// Readers never iterate this directly: `registry()` is this plus the add-on
/// key rows derived from the overlays (`ADDON_KEY_SPECS`), and a reader of
/// only the core rows would skip every add-on key — the earlier silence.
///
/// Consumer lists come from `docker-compose.cluster.yml`.
/// `node_held` comes from `ansible/templates/worker.env.j2` — the ONLY thing
/// that ever writes a credential onto a node — cross-checked against
/// the per-leg table of what each node holds.
pub const CORE_REGISTRY: &[SecretSpec] = &[
    SecretSpec {
        key: "POSTGRES_PASSWORD",
        class: Class::DbPassword { role: None },
        gen_bytes: 32,
        consequence: "superuser role (POSTGRES_USER, default `noo`); migrations and the \
                      service DSNs use it. worker.env.j2 also writes a copy into each node's \
                      .env, but no node connects to Postgres — that copy is inert, and stale \
                      after this rotation",
        // Not trellion: its DSNs are `noo_app` / `noo_trellion_ddl`
        // (docker-compose.trellion.yml), and no holder of the superuser
        // password exists outside the two named here.
        consumers: &["noo-postgres", "noo-gateway"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_APP_DB_PASSWORD",
        class: Class::DbPassword {
            role: Some("noo_app"),
        },
        gen_bytes: 32,
        consequence: "scoped role `noo_app` from migration 033 (NOSUPERUSER NOCREATEDB \
                      NOCREATEROLE NOBYPASSRLS, table-scoped grants)",
        // Reached through a DSN, not under its own name: these carry it inside
        // `postgresql://noo_app:${NOO_APP_DB_PASSWORD}@...`. A rotation that
        // skips them leaves a stale password in a connection string.
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_EVOLVE_DB_PASSWORD",
        class: Class::DbPassword {
            role: Some("noo_evolve"),
        },
        gen_bytes: 32,
        consequence: "scoped role `noo_evolve` from migration 034; pro installs only — if the \
                      role was never created, the ALTER fails and nothing is committed",
        consumers: &["noo-gateway", "noo-evolve"],
        // The consequence string above has said "pro installs only" since it
        // was written, while the spec generated this on EVERY install. That
        // gap is why an OSS install ends up with a `noo_evolve` login role for
        // a service it will never run.
        required_when: Requirement::WhenAddon("evolve"),
    },
    SecretSpec {
        key: "NOO_TRELLION_DDL_PASSWORD",
        class: Class::DbPassword {
            role: Some("noo_trellion_ddl"),
        },
        gen_bytes: 32,
        consequence: "migration role `noo_trellion_ddl`: owns schema \
                      `trellion` and is the only identity that can create in it. Distinct \
                      from the runtime role on purpose — collapsing them would leave the \
                      runtime holding DDL rights permanently",
        // Same DSN interpolation as above — held inside a connection string.
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        // Minted by `noo systems enable`, and needed only once a `systems:`
        // manifest declares trellion. An install without one never reads it,
        // so demanding it everywhere would be a false alarm on every OSS box.
        required_when: Requirement::WhenEnabled("NOO_SYSTEMS_MANIFEST"),
    },
    SecretSpec {
        key: "NOO_EVOLVE_DDL_PASSWORD",
        class: Class::DbPassword {
            role: Some("noo_evolve_ddl"),
        },
        gen_bytes: 32,
        consequence: "migration role `noo_evolve_ddl`: owns schema \
                      `evolve`. Evolve installs with a systems manifest only",
        consumers: &["noo-gateway", "noo-evolve"],
        required_when: Requirement::WhenAddon("evolve"),
    },
    SecretSpec {
        key: "NOO_TRELLION_DB_PASSWORD",
        class: Class::DbPassword {
            role: Some("noo_trellion"),
        },
        gen_bytes: 32,
        consequence: "scoped role `noo_trellion` from migration 038; used only when \
                      NOO_TRELLION_ENABLED=1 moves the worker pool to its own container",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "REDIS_PASSWORD",
        class: Class::SharedService,
        gen_bytes: 32,
        consequence: "IS the server's `requirepass` AND every client's — there is no window in \
                      which both old and new work, so server and clients must come up together. \
                      worker.env.j2 writes an inert copy onto nodes (no node talks to Redis)",
        consumers: &[
            "noo-gateway",
            "noo-redis",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_JWT_SIGNING_KEY",
        // Operator-supplied, not generated: an EC private key this tool has
        // no business minting. `rotate --set-from-stdin` takes a new one
        // (base64 of a P-256 PKCS8 PEM — jwks.rs also accepts the raw or
        // \n-escaped PEM). The audit previously reported this key as an
        // unclassified credential, so nothing could say which container to
        // recreate when it changed.
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "re-signs every EXCHANGED agent token under the new key: tokens already \
                      issued (≤5 min, hard cap 1 h) fail verification the moment the gateway \
                      restarts, the published `kid` changes, and any third party verifying \
                      against /.well-known/jwks.json must re-fetch. Login and CLI tokens are \
                      untouched — they stay HS256 under NOO_JWT_SECRET. Optional: absent means \
                      HS256 for exchanged tokens too and an empty JWKS",
        consumers: &["noo-gateway"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "NOO_JWT_SECRET",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "INVALIDATES EVERY ISSUED TOKEN — every user must `noo auth login` again \
                      and stored CLI credentials stop working. \
                      AND audit rows written before the NOO_AUDIT_HMAC_KEY checkpoint \
                      were signed with a key derived from it, which the gateway keeps \
                      only to verify them: after this rotation `noo security audit \
                      verify` reports that epoch UNVERIFIABLE (not tampered). Run the \
                      verify first if you need a record that it held. \
                      Controller-only: node-agents never hold it",
        // The gateway alone: workers act as a user with the
        // per-dispatch token the gateway mints, and `cluster verify` FAILS
        // this secret in any other container (secrets_delivery.rs).
        consumers: &["noo-gateway"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_AUDIT_HMAC_KEY",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "The security audit log's signing key — the ONLY one: without it every \
                      audit row is REFUSED (both engines log `audit_write_refused_no_key`), \
                      never signed with a derivation of NOO_JWT_SECRET. The first gateway boot \
                      with a key appends one `audit_key_checkpoint` row naming its fingerprint, \
                      which is how `noo security audit verify` links the rows before it (signed \
                      under the retired derivation) to the rows after. ROTATING it starts an \
                      epoch the gateway cannot hand over to (it no longer holds the old key), \
                      so rows signed under the previous value stop verifying — do it \
                      deliberately, after a verify, and record when",
        // Every process that WRITES audit rows: the gateway, and each image
        // running `worker_pool` (the worker, and the two knowledge add-ons).
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_AGENT_REVIEW_KEY",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "Seals every agent-to-agent message body and is the \
                      ONLY key that opens them for review. ROTATING IT MAKES EVERY PREVIOUSLY \
                      SEALED MESSAGE UNREADABLE in `noo agents messages` and the dashboard — \
                      keep the old value if you need that history. Controller-only",
        consumers: &["noo-gateway"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_CONTROLLER_SECRET",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "The gateway's own secret: while it is set, a fleet-wide \
                      cluster token is only ever a NODE, scoped to node routes; the gateway refuses \
                      to start without it. It now signs nothing and nobody else \
                      holds it — the gateway refuses an HMAC signed with it from every caller. \
                      Rotating it needs only the gateway recreated. Controller-only: never pushed \
                      to nodes",
        // The gateway ALONE. The worker and the trellion pair
        // held it to verify bus principals; each verifies with its own
        // NOO_BUS_KEY_* now, and the worker's self-call fallback is retired.
        consumers: &["noo-gateway"],
        required_when: Requirement::Always,
    },
    // ── The bus-principal keys, one per audience. The
    //    gateway signs every worker.* message once per audience
    //    (gateway-rust/src/bus_principal.rs AUDIENCES); each verifier holds
    //    its own key and no other, so a leak forges for its holder only.
    //    Minted on onboard and by `noo upgrade` when absent; all three on
    //    every install, so enabling an add-on never needs a gateway recreate.
    SecretSpec {
        key: "NOO_BUS_KEY_WORKER",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "noo-worker's bus-principal key: the gateway MACs every \
                      worker.* message with it and the worker refuses one it cannot verify. \
                      Rotating it recreates the gateway and the worker together; messages in \
                      flight across the recreate are refused once and retried by their callers",
        consumers: &["noo-gateway", "noo-worker", "noo-worker-extra"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_BUS_KEY_TRELLION",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "noo-trellion's bus-principal key: the gateway MACs every \
                      worker.* message for trellion's worker_pool with it. Rotating it recreates \
                      the gateway and noo-trellion together",
        consumers: &["noo-gateway", "noo-trellion"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_BUS_KEY_TRELLION_INTEL",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "noo-trellion-intel's bus-principal key: the gateway MACs \
                      every worker.* message for the Intelligent tier's worker_pool with it. \
                      Rotating it recreates the gateway and noo-trellion-intel together",
        consumers: &["noo-gateway", "noo-trellion-intel"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_SVC_KEY_WORKER",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "noo-worker's OWN gateway key. Every Python self-call this container \
                      makes to the gateway goes through one function — \
                      cluster_auth.internal_gateway_headers, which presents this and nothing \
                      else: with no key the self-call carries no credential and is refused \
                      (the shared-HMAC fallback is retired). Issue with \
                      `noo security service-key issue svc:worker --scopes chat --scopes \
                      embeddings`, install with `--set-from-stdin`, recreate the container, \
                      then CONFIRM last_used_at moves — a key that is stored but never \
                      presented is indistinguishable from no key at all",
        // worker-extra too: it is noo-worker scaled and merges
        // the same environment, so it receives this key by interpolation.
        // Naming only noo-worker recreates one and strands every replica.
        consumers: &["noo-worker", "noo-worker-extra"],
        // Always since an earlier release: with the shared-HMAC fallback retired an
        // absent key is a worker whose self-calls are all refused — broken,
        // not weaker. `noo upgrade` mints it before the roll when absent.
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_BROWSER_KEY",
        class: Class::ControllerLocal,
        gen_bytes: 32,
        consequence: "the browser container's door key: the gateway and \
                      noo-worker sign their browser calls with it, and the gateway hands it to \
                      the browser containers it starts on nodes. Rotating it recreates the \
                      gateway, the worker and the browser; a browser session a node started \
                      before the rotation refuses the new bearer until it is restarted",
        consumers: &["noo-gateway", "noo-worker", "noo-worker-extra", "noo-browser"],
        required_when: Requirement::Always,
    },
    // ── Fleet-wide: written onto every node by ansible/templates/worker.env.j2
    //    and used there. Refused — see fleet_refusal(). ──
    SecretSpec {
        key: "NOO_CLUSTER_SECRET",
        class: Class::FleetWide,
        gen_bytes: 0,
        consequence: "the HMAC key EVERY node signs inter-node requests with (300s replay \
                      window). Changing it centrally breaks gateway→node-agent on every node \
                      at once, and the failure surfaces as heartbeat timeouts, not auth errors",
        // A NODE's credential, so the gateway (which verifies
        // node tokens) and the node agents only. The worker plane and the
        // browser container left this list: the browser door has its own
        // key (NOO_BROWSER_KEY), and the gateway refuses the fleet secret
        // from a controller service.
        consumers: &["noo-gateway", "noo-node-agent", "noo-node-agent-sensors"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_NODE_AGENT_TOKEN",
        class: Class::FleetWide,
        gen_bytes: 0,
        consequence: "the bearer token EVERY node-agent presents to the gateway and accepts \
                      back; lives in each node's own env file (mode 0644)",
        consumers: &[
            "noo-gateway",
            "noo-node-agent",
            "noo-node-agent-sensors",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        required_when: Requirement::Always,
    },
    // NATS_PASSWORD (the shared bus user's password) was a fleet-wide row
    // here until an earlier release retired the user. A stored value is now a
    // `retired-key` audit finding — see RETIRED_STORE_KEYS — never a rotation plan.
    SecretSpec {
        key: "NATS_GATEWAY_PASSWORD",
        class: Class::ExternalTool { tool: "noo cluster nats-creds rotate gateway --restart" },
        gen_bytes: 0,
        consequence: "the GATEWAY's own bus user. Held by exactly one process and \
                      by the NATS server as a bcrypt digest in monitoring/nats/users.conf, so a \
                      rotation is controller-local — but the server verifies the DIGEST, not this \
                      value: change it here alone and the gateway loops on 'Authorization \
                      Violation'. Rotate it with `noo cluster nats-creds rotate gateway --restart`, \
                      which mints, re-renders the digest, HUPs the server and recreates the \
                      gateway — never by hand",
        consumers: &["noo-nats", "noo-gateway"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NATS_WORKER_PASSWORD",
        class: Class::ExternalTool { tool: "noo cluster nats-creds rotate worker --restart" },
        gen_bytes: 0,
        consequence: "noo-worker's bus user — denied `tasks.>`, `$KV.>` and stream \
                      administration, and every add-on subject whose add-on has a principal of \
                      its own. noo-trellion and noo-trellion-intel still hold it for ONE release, \
                      as the fallback when their own password is not in the store. The same \
                      digest caveat as NATS_GATEWAY_PASSWORD applies — \
                      `noo cluster nats-creds rotate worker --restart` is the rotation, not this tool",
        consumers: &[
            "noo-nats",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Always,
    },
    // The add-ons' OWN bus users (i70 residue): each subscribes on exactly
    // the subjects its add-on serves and replies on its own prefix
    // (noo-cli nats_users.rs ADDON_PRINCIPALS). Minted by the render that
    // first renders the principal (`noo upgrade --stack`, `noo addons
    // enable`, `noo cluster nats-users render`, onboarding).
    SecretSpec {
        key: "NATS_TRELLION_PASSWORD",
        class: Class::ExternalTool { tool: "noo cluster nats-creds rotate trellion --restart" },
        gen_bytes: 0,
        consequence: "noo-trellion's own bus user `trellion`: subscribe on the knowledge pack's \
                      subjects (worker.rag/memory/recall/api.snapshots, worker.autonomy.check_rag) \
                      and publish only its replies on `_INBOX_gw.trellion.>`. The server verifies a \
                      bcrypt DIGEST of it — `noo cluster nats-creds rotate trellion --restart` \
                      re-renders and recreates; never change it by hand. Absent, noo-trellion \
                      presents the worker principal (one release)",
        consumers: &["noo-nats", "noo-trellion"],
        // Optional: absent is the one-release fallback (the add-on presents
        // the worker), which `cluster verify`'s `nats principals` row WARNs on.
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "NATS_TRELLION_INTEL_PASSWORD",
        class: Class::ExternalTool { tool: "noo cluster nats-creds rotate trellion_intel --restart" },
        gen_bytes: 0,
        consequence: "noo-trellion-intel's own bus user `trellion_intel`: subscribe on the \
                      Intelligent tier's subjects (worker.graph/temporal/retrieval, \
                      worker.api.heartbeat.run_ml) and publish only its replies on \
                      `_INBOX_gw.trellion_intel.>`. Rendered once the add-on's signed bundle \
                      declares the principal; the same digest caveat as NATS_GATEWAY_PASSWORD — \
                      `noo cluster nats-creds rotate trellion_intel --restart`",
        consumers: &["noo-nats", "noo-trellion-intel"],
        // Optional: absent is the one-release fallback (the add-on presents
        // the worker), which `cluster verify`'s `nats principals` row WARNs on.
        required_when: Requirement::Optional,
    },
    // NATS_NODE_PASSWORD_<NODE> is deliberately NOT listed: there is one per
    // node, minted and delivered by `noo cluster nats-creds rotate <node>`
    // (and by `noo cluster provision` when a node is born). A static spec
    // cannot name a fleet that changes, and `secrets audit` reporting them
    // as "unexpected keys" is the correct, honest answer for a value this
    // tool must not rotate — rotating one without delivering it takes that
    // node off the bus, which is exactly the failure this guard exists
    // to prevent.
    //
    // NATS_NODE_PASSWORD (no suffix) is different: it is the name the value
    // arrives UNDER on a node — compose hands it to noo-node-agent and
    // noo-node-agent-sensors, and node-agent-go/internal/messaging/nats.go
    // reads it. Listed so a holder is declared and the audit does not call
    // it an unclassified credential; refused here for the same reason as
    // the per-node rows above.
    SecretSpec {
        key: "NATS_NODE_PASSWORD",
        class: Class::ExternalTool { tool: "noo cluster nats-creds rotate <node>" },
        gen_bytes: 0,
        consequence: "this node's OWN bus principal, the value of the \
                      controller's NATS_NODE_PASSWORD_<NODE> as delivered over the rail. \
                      The server verifies a bcrypt digest, so a value changed on the node \
                      alone loops on 'Authorization Violation'; `noo cluster nats-creds \
                      rotate <node>` mints, re-renders the digest, HUPs the server and \
                      delivers the new value — never this tool. Absent from a controller \
                      store that runs no node-agent",
        consumers: &["noo-node-agent", "noo-node-agent-sensors"],
        required_when: Requirement::Optional,
    },
    // ── Provider-issued: cannot be generated here at all. ──
    SecretSpec {
        key: "ANTHROPIC_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued by console.anthropic.com — mint the new key FIRST, install it, \
                      verify, and only then revoke the old one; revoking first takes out cloud \
                      fallback and `noo_coding_task` with no way back",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        required_when: Requirement::Optional,
    },
    // The other two cloud providers. Delivered beside ANTHROPIC_API_KEY
    // since the WP-T23 env audit and read by coordinator/cloud.rs (gateway)
    // and gateway/cloud_providers.py (the Python images) — but absent from
    // this registry until 2026-09-29, so the audit reported a stored key as
    // an unclassified credential and `rotate --set-from-stdin` refused it.
    SecretSpec {
        key: "OPENAI_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued at platform.openai.com — cloud fallback when \
                      CLOUD_PROVIDERS_ENABLED names openai (or OPENAI_BASE_URL points at a \
                      compatible endpoint). Mint the new key first, install, verify, then \
                      revoke the old one",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "GOOGLE_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued at aistudio.google.com — cloud fallback when \
                      CLOUD_PROVIDERS_ENABLED names google. Same mint-first order as the \
                      Anthropic key",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
        ],
        required_when: Requirement::Optional,
    },
    // The controller's read credential for the licensed add-ons' registry
    // packages (i33): `noo addons enable|upgrade` and `noo upgrade --stack`
    // fetch each add-on's signed lock and pull its images by digest with it,
    // through a throwaway docker config. No container holds it, so it is a
    // CLI_ONLY_SECRETS row and names no consumer.
    SecretSpec {
        key: "NOO_ADDON_REGISTRY_TOKEN",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued with the licence: a registry token that can read the licensed add-on \
                      packages (read:packages on GHCR). Install the new token, then run \
                      `noo addons verify`, then revoke the old one",
        consumers: &[],
        required_when: Requirement::Optional,
    },
    // ── Web search: the provider is `search.provider` /
    //    NOO_SEARCH_PROVIDER in noomesh.yaml or .env; the credential is a
    //    secret and lives here. Documented since 348 shipped the providers,
    //    but until 2026-09-27 neither key was in this registry (so
    //    `secrets rotate --set-from-stdin` refused it as unknown) nor passed
    //    to the gateway by compose (so a stored key never reached the
    //    process) — a documented control that did not exist.
    SecretSpec {
        key: "TAVILY_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued at app.tavily.com — the gateway's web_search when \
                      NOO_SEARCH_PROVIDER=tavily. Absent with that provider set, every \
                      research run fails loudly (\"TAVILY_API_KEY is empty\"); absent with \
                      the default `ddg`, unused. The wizard asks for it beside the cloud keys",
        consumers: &["noo-gateway"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "BRAVE_SEARCH_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued at api.search.brave.com — the gateway's web_search when \
                      NOO_SEARCH_PROVIDER=brave. Same shape as the Tavily key beside it",
        consumers: &["noo-gateway"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "HF_TOKEN",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued by huggingface.co/settings/tokens. Also written onto every node by \
                      worker.env.j2 and used there for gated model pulls — so after installing \
                      it centrally, re-provision the node (`noo cluster provision <node>`) or update each \
                      node's .env, or gated pulls keep failing on the fleet. On a `standalone` \
                      (Ollama-only) install nothing here consumes it at all — see \
                      Requirement::WhenNotStandalone",
        consumers: &[
            "noo-vllm",
            "noo-vllm-secondary",
            "noo-tei",
            "noo-tei-gpu",
            "noo-whisper",
            "noo-reranker",
            "noo-node-agent",
        ],
        required_when: Requirement::WhenNotStandalone,
    },
    SecretSpec {
        key: "TELEGRAM_BOT_TOKEN",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued by @BotFather; /revoke mints the new one and kills the old \
                      IMMEDIATELY — there is no overlap, so the channel is down from revoke \
                      until the gateway is recreated. Have the new value ready to pipe in",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Optional,
    },
    // The remaining channel credentials. Each was delivered and read (the
    // WhatsApp Cloud API token by routes/communication.rs and
    // channels/gateway_client.py; the two Google Chat credentials by
    // google_auth.rs and the same client) yet absent from this registry
    // until 2026-09-29. WHATSAPP_VERIFY_TOKEN / WHATSAPP_APP_SECRET /
    // SLACK_BOT_TOKEN / TELEGRAM_SECRET_TOKEN are NOT rows: nothing reads
    // them, so compose no longer delivers them either.
    SecretSpec {
        key: "WHATSAPP_TOKEN",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "the Meta Cloud API bearer for outbound WhatsApp sends (with \
                      WHATSAPP_PHONE_ID). Issued in the Meta developer console; a system-user \
                      token does not expire, a temporary one dies in 24 h. Revoke after the \
                      new value is installed",
        consumers: &["noo-gateway", "noo-worker", "noo-worker-extra"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "GOOGLE_CHAT_BEARER_TOKEN",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "a static bearer for the Google Chat channel, used when no \
                      service-account credential is present (google_auth.rs prefers the \
                      service account). Issued by Google; replace and recreate",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        // The STORE key. Compose delivers it as GOOGLE_CHAT_CREDENTIALS_JSON
        // (`${NOO_FILECRED_GOOGLE_CHAT_B64:-}`), which is what the readers
        // name; the consumer list is what the interpolation reaches.
        key: "NOO_FILECRED_GOOGLE_CHAT_B64",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "the Google Chat service-account key itself, base64 of the JSON, \
                      absorbed from the file by `noo security secrets absorb-files`. Rotate \
                      by minting a new key for the service account in the Google Cloud \
                      console, absorbing it, recreating the consumers, then deleting the \
                      old key there — deleting first stops every Chat send and the Pub/Sub \
                      pull at once",
        consumers: &[
            "noo-gateway",
            "noo-trellion",
            "noo-trellion-intel",
            "noo-worker",
            "noo-worker-extra",
        ],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "NOO_TAILSCALE_API_KEY",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "issued by login.tailscale.com/admin/settings/keys and they EXPIRE \
                      (typically 90d); `cluster invite` / `set-primary` start failing \
                      once it lapses, which looks like a network fault",
        // Gateway-only since an earlier release: the Python reader
        // (cluster/tailscale.py, behind the Python CLI) is deleted, so the
        // trellion overlay no longer delivers it.
        consumers: &["noo-gateway"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "NOO_TAILSCALE_OAUTH_CLIENT_SECRET",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "the OAuth client secret (with NOO_TAILSCALE_OAUTH_CLIENT_ID) that \
                      routes/cluster.rs exchanges for a short-lived API token per \
                      mint_join_key call — the preferred credential, because it does not \
                      expire. Revoke at login.tailscale.com/admin/settings/oauth AFTER the \
                      replacement is installed. Gateway-only: nothing else reads it",
        consumers: &["noo-gateway"],
        required_when: Requirement::Optional,
    },
    SecretSpec {
        key: "GRAFANA_PASSWORD",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "Grafana copies GF_SECURITY_ADMIN_PASSWORD into its OWN database on first \
                      boot, so changing the env var alone does NOT change the login. Change it \
                      in Grafana (or reset via grafana-cli), then record it here to match",
        consumers: &["noo-grafana"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_ADMIN_PASSWORD",
        class: Class::ProviderIssued,
        gen_bytes: 0,
        consequence: "the operator's own login. The hash of record is bcrypt in the users \
                      table, not this variable — change it with `noo security user \
                      set-password <username>`, then record it here to match",
        // The bootstrap login is routes/core.rs; the Python images only
        // read NOO_ADMIN_USER (heartbeat.py), never the password.
        consumers: &["noo-gateway"],
        required_when: Requirement::Always,
    },
    // ── Backup passphrases: held by a PERSON, rotated with their artifacts. ──
    SecretSpec {
        key: "NOO_BACKUP_PASSPHRASE",
        class: Class::BackupPassphrase { glob: "pg_*.sql.gz.enc" },
        gen_bytes: 32,
        consequence: "encrypts the Postgres dumps in ~/noo-backups. Changing the value alone \
                      leaves every EXISTING backup encrypted with the old passphrase — \
                      silently unopenable the moment it is forgotten. REQUIRED: \
                      backup-controller.sh refuses to run without it rather than write a \
                      plaintext dump, so a missing value means no backups at all",
        consumers: &["(host backup script)"],
        required_when: Requirement::Always,
    },
    SecretSpec {
        key: "NOO_AGE_BACKUP_PASSPHRASE",
        class: Class::BackupPassphrase { glob: "age-key_*.txt.enc" },
        gen_bytes: 32,
        consequence: "encrypts the age-key backup — the key that opens EVERY sops secret. \
                      Changing the value alone makes the off-site encrypted key an opaque blob, \
                      which is unrecoverable rather than merely inconvenient. REQUIRED: \
                      backup-controller.sh refuses to run when an age key is present and this \
                      is not set, because the alternative it used to take was copying the \
                      private key to ~/noo-backups in the clear. Must DIFFER from \
                      NOO_BACKUP_PASSPHRASE, and must be kept OFF-BOX — it lives in env.sops, \
                      which the very key it protects is what decrypts",
        consumers: &["(host backup script)"],
        required_when: Requirement::Always,
    },
];

pub fn spec_for(key: &str) -> Option<&'static SecretSpec> {
    registry().find(|s| s.key == key)
}

/// Registry entries whose value is DERIVED from `parent` and are therefore
/// invalidated the instant it rotates.
///
/// This is the ordering dependency made mechanical. Rotating `NOO_JWT_SECRET`
/// and recreating the controller looks completely successful — every check
/// this tool runs passes — while noo-evolve carries on holding a JWT signed by
/// a key that no longer exists. Nothing fails at rotation time; the graph just
/// silently stops receiving edges. So the plan for a parent names its children
/// and the re-mint step, in the same output, before the operator moves on.
pub fn derived_children(parent: &str) -> Vec<&'static SecretSpec> {
    registry()
        .filter(|s| matches!(s.class, Class::Derived { parent: p, .. } if p == parent))
        .collect()
}

/// The `--all-generated` set: every key this tool can mint AND apply on its
/// own. Deliberately excludes fleet-wide and provider-issued keys — a "rotate
/// everything" flag that quietly skipped half the store would be a lie, so
/// the plan prints the excluded keys and why.
///
/// It also excludes the backup passphrases, even though this tool can now
/// mint and apply those too. Two reasons, both about what a sweep IS:
/// rotating one re-encrypts every backup file on the box, so a sweep would
/// quietly rewrite artifacts the operator did not mention; and each one
/// REQUIRES a terminal handover (the value has no consumer here — a person is
/// the consumer), so a sweep would either block on two prompts or refuse
/// outright on a non-TTY. `--all-generated` is for the credentials the
/// containers hold. A backup passphrase is rotated by naming it.
pub fn all_generated() -> Vec<&'static str> {
    registry()
        .filter(|s| s.class.self_generatable())
        .filter(|s| !matches!(s.class, Class::BackupPassphrase { .. }))
        // NOO_AUDIT_HMAC_KEY is generatable and rotatable BY NAME, and must
        // never be swept: rotating it breaks verification of every audit row
        // written under the previous key, and a sweep is exactly where that
        // would happen without anyone deciding to. Same reasoning as the
        // backup passphrases above — a flag that quietly took the audit
        // chain with it is the shape this filter exists to prevent.
        .filter(|s| s.key != "NOO_AUDIT_HMAC_KEY")
        .map(|s| s.key)
        .collect()
}

/// Heuristic "this name looks like a credential", used to flag keys the
/// registry does not know.
///
/// Biased toward false positives — one extra INFO line costs nothing, while
/// a false negative means a plaintext credential in `.env` goes unreported,
/// which is the failure this whole module exists to catch.
///
/// But the bias is not unlimited: a rule that flagged `NOO_SECRETS_BACKEND`
/// (contains "SECRET") as a credential would put a noisy ERROR on a key that
/// MUST live in `.env` — it is one of the three bootstrap flags read before
/// the secret store can be opened at all. An audit whose errors are routinely
/// wrong stops being read, so the known-config exclusions below matter as
/// much as the needles.
pub fn looks_like_credential(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "PASSPHRASE",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTHTOKEN",
        "_KEY",
    ];
    /// Names that contain a needle but are configuration, not credentials.
    const NOT_CREDENTIALS: &[&str] = &[
        "NOO_SECRETS_BACKEND", // bootstrap flag; `.env` is its correct home
        "SOPS_AGE_KEY_FILE",   // a path
        "NOO_TOKEN_TTL",
        "NOO_JWT_ALGORITHM",
    ];
    /// Suffixes that name a location, a switch, or an identity — never the
    /// secret itself. `..._KEY_FILE` is a path; `..._TOKEN_ENABLED` is a bool.
    const CONFIG_SUFFIXES: &[&str] = &[
        "_FILE", "_PATH", "_DIR", "_ENABLED", "_BACKEND", "_MODE", "_URL", "_HOST", "_PORT",
        "_USER", "_NAME", "_TTL", "_ALGORITHM", "_TIMEOUT", "_LENGTH",
    ];
    let k = key.to_ascii_uppercase();
    if NOT_CREDENTIALS.contains(&k.as_str()) {
        return false;
    }
    if CONFIG_SUFFIXES.iter().any(|s| k.ends_with(s)) {
        return false;
    }
    NEEDLES.iter().any(|n| k.contains(n))
}

// ─────────────────────────────────────────────────────────────────────────
// Store access — decrypt into memory, never to a file
// ─────────────────────────────────────────────────────────────────────────

/// An in-memory view of a dotenv-shaped store.
///
/// Deliberately has no `Debug`, no `Display`, and no accessor that returns a
/// value to a caller outside this module: everything public about a value is
/// derived (`state`, `len`, `sha8`). That is a compile-time guard on the
/// module's central invariant, not just a convention.
pub struct SecretStore {
    map: BTreeMap<String, String>,
    pub path: PathBuf,
    pub existed: bool,
}

impl SecretStore {
    fn from_map(map: BTreeMap<String, String>, path: PathBuf, existed: bool) -> Self {
        SecretStore { map, path, existed }
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// set / BLANK / missing — the only three things an operator needs, and
    /// none of them reveal the value.
    pub fn state(&self, key: &str) -> State {
        match self.map.get(key) {
            None => State::Missing,
            Some(v) if v.trim().is_empty() => State::Blank,
            Some(_) => State::Set,
        }
    }

    pub fn value_len(&self, key: &str) -> Option<usize> {
        self.map.get(key).map(|v| v.len())
    }

    /// First 8 hex chars of sha256(value). Enough to compare two stores for
    /// equality; 32 bits of a hash of a high-entropy secret is not a
    /// meaningful brute-force target.
    ///
    /// A BLANK value gets no digest. `sha256("")` is the famous constant
    /// `e3b0c442…`, so printing it would both look like a real value and
    /// silently confirm the emptiness to anyone who recognises it — while the
    /// `BLANK` state column already says so plainly.
    pub fn sha8(&self, key: &str) -> Option<String> {
        match self.map.get(key) {
            Some(v) if !v.is_empty() => Some(sha8_of(v)),
            _ => None,
        }
    }

    /// Salted digest of a stored value, for comparing this store against a
    /// value held somewhere else (a node's `.env`, a running container's
    /// environment) WITHOUT either side transmitting the value.
    ///
    /// This is a derived form, so it does not breach the module's invariant:
    /// the caller learns whether two values are equal, never what they are.
    /// The salt is per-run and non-secret; see `cluster_push_secrets`.
    pub fn salted_digest(&self, key: &str, salt: &str) -> Option<String> {
        match self.map.get(key) {
            Some(v) if !v.is_empty() => {
                Some(super::cluster_push_secrets::salted_digest(salt, v))
            }
            _ => None,
        }
    }

    /// Plaintext of a stored value, for a signed bundle payload.
    ///
    /// This IS an escape hatch from "no accessor returns a value" — one of
    /// exactly two (see `value_for_provider_api` below) — deliberately named
    /// so that `grep` finds every use. Its one legitimate caller is
    /// `cluster_push_secrets`, which places it in a `fleet-secrets` fragment
    /// inside a CA-signed bundle that is then CMS-encrypted to the receiving
    /// node's own certificate — never a log, a file, an argv, or a shell.
    ///
    /// It used to return base64, because the value went to an `ssh` child's
    /// stdin and a careless `println!` of a b64 blob is at least not legible.
    /// The bundle needs the real bytes, and the wrapping was never the thing
    /// keeping the value safe — not naming it in a process table was.
    pub fn value_for_bundle_payload(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(|v| v.as_str())
    }

    /// Plaintext of a stored value, for use as a bearer credential in an
    /// API call made by THIS process. The second and last deliberate escape
    /// hatch from "no accessor returns a value": `cluster invite` /
    /// `set-primary` call the Tailscale API from the CLI itself, and
    /// NOO_TAILSCALE_API_KEY lives in the sops store — NOT in `.env`, which
    /// is exactly where the old "add it to .env" hint invited it (the
    /// 2026-08-02 cleanup removed 23 such duplicates). Named to grep; the
    /// result goes into a request header, never a log, a file, or an argv.
    pub fn value_for_provider_api(&self, key: &str) -> Option<String> {
        self.map.get(key).cloned()
    }

    /// Plaintext of a stored value, to be shown ONCE to the human being who
    /// has to hold it. The third and last deliberate escape hatch from "no
    /// accessor returns a value", named — like the other two — so that `grep`
    /// finds every use.
    ///
    /// Its one legitimate caller is `secrets_reveal`, which is allow-listed to
    /// the two backup passphrases (secrets whose only consumer is a person on
    /// a different machine), refuses any destination that is not a terminal,
    /// and writes an audit line. This is not a widening of the invariant: the
    /// value was already readable to that caller by hand — `secrets/env.sops`
    /// plus the local age key is all `sops -d` needs — and the alternative the
    /// wizard used instead was a plaintext file that nothing ever removed.
    pub fn value_for_operator_reveal(&self, key: &str) -> Option<String> {
        self.map.get(key).cloned()
    }

    /// Load `<repo>/.env` (plain text, no decryption).
    pub fn load_env(path: &Path) -> SecretStore {
        match std::fs::read_to_string(path) {
            Ok(text) => SecretStore::from_map(parse_dotenv(&text), path.to_path_buf(), true),
            Err(_) => SecretStore::from_map(BTreeMap::new(), path.to_path_buf(), false),
        }
    }

    /// Read one value (the wizard's Google Chat discovery reads the absorbed
    /// SA key). Values never leave the process.
    pub fn get(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(String::as_str)
    }

    pub fn load_sops(path: &Path) -> Result<SecretStore, String> {
        Self::load_sops_classified(path).map_err(|e| e.to_string())
    }

    /// [`Self::load_sops`] with the failure kept as a value, for the callers
    /// that must tell "the store could not be read" apart from "the store
    /// says nothing" — `noo security scan` above all. Every failure used to
    /// fold into one string, and the caller that did not fail hard on it
    /// (the startup env loader) fell through to an empty environment: over
    /// a non-interactive ssh, where `~/.local/bin` is not on PATH, `scan`
    /// then reported "JWT secret unset" CRITICAL for every key the store
    /// holds (2026-09-28). A false alarm at the loudest severity is the
    /// silent-success shape inverted, and it trains people to ignore
    /// CRITICAL.
    pub fn load_sops_classified(path: &Path) -> Result<SecretStore, StoreLoadError> {
        if !path.exists() {
            return Ok(SecretStore::from_map(
                BTreeMap::new(),
                path.to_path_buf(),
                false,
            ));
        }
        let text = decrypt_store_dotenv(path)?;
        Ok(SecretStore::from_map(
            parse_dotenv(&text),
            path.to_path_buf(),
            true,
        ))
    }
}

/// Why `secrets/env.sops` could not be read, as three DIFFERENT facts —
/// each with its own remedy, none of them "set the secret".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreLoadError {
    /// No `sops` binary on PATH or in any of the places the installer puts
    /// one. `searched` is the list, for the message.
    SopsNotFound { searched: String },
    /// `sops` exists but could not be started.
    SopsFailedToRun { detail: String },
    /// `sops` ran and refused. `age_key_present` is whether an age key file
    /// was found where sops would look — a missing key and a wrong key are
    /// both "exit 1" to sops, and only the first has a one-line fix.
    DecryptFailed { path: PathBuf, exit: i32, age_key_present: bool },
}

impl std::fmt::Display for StoreLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreLoadError::SopsNotFound { searched } => write!(
                f,
                "sops not found (searched {searched}) — install it with \
                 scripts/noo-secrets-sops-init.sh, or put its directory on PATH"
            ),
            StoreLoadError::SopsFailedToRun { detail } => write!(f, "could not run sops: {detail}"),
            // The path is `crate::age_key::path()`: SOPS_AGE_KEY_FILE, the
            // TPM-sealed runtime key (i10a), or ~/.config/sops/age/keys.txt.
            StoreLoadError::DecryptFailed { path, exit, age_key_present: false } => write!(
                f,
                "sops could not decrypt {} (exit {exit}): no age key at {} — restore the key \
                 from its backup (docs/security/secrets.md, 'Back up and restore the age key') \
                 or point SOPS_AGE_KEY_FILE at it; if it is sealed to this machine's TPM: \
                 systemctl status {}",
                path.display(),
                crate::age_key::path().display(),
                crate::age_key::UNSEAL_UNIT
            ),
            StoreLoadError::DecryptFailed { path, exit, age_key_present: true } => write!(
                f,
                "sops could not decrypt {} (exit {exit}) with the age key that is present — \
                 the key does not open this store (wrong key, or the store was re-encrypted \
                 to another recipient)",
                path.display()
            ),
        }
    }
}

impl StoreLoadError {
    /// A short, stable label for JSON output and tests.
    pub fn kind(&self) -> &'static str {
        match self {
            StoreLoadError::SopsNotFound { .. } => "sops_not_found",
            StoreLoadError::SopsFailedToRun { .. } => "sops_failed_to_run",
            StoreLoadError::DecryptFailed { age_key_present: false, .. } => "age_key_missing",
            StoreLoadError::DecryptFailed { age_key_present: true, .. } => "decrypt_failed",
        }
    }
}

/// Where `sops` may live besides PATH, in lookup order. The installer
/// (`scripts/noo-secrets-sops-init.sh`) puts it in `~/.local/bin` on purpose
/// so onboarding needs no sudo; that directory is on an interactive shell's
/// PATH and on nothing else's — a systemd unit, cron, the host watcher, or
/// `ssh host noo …` all run with `/usr/local/bin:/usr/bin:/bin`. The launcher
/// (`scripts/lib-secrets.sh::secrets_sops_path_repair`) has looked there since
/// the host watcher wrote unencrypted backups for want of it; the CLI now
/// looks in the same places, plus its own directory (a `noo` installed
/// beside its tools).
fn sops_candidates(home: Option<&Path>, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join(".local/bin"));
    }
    v.push(PathBuf::from("/usr/local/bin"));
    v.push(PathBuf::from("/opt/homebrew/bin"));
    if let Some(d) = exe_dir {
        v.push(d.to_path_buf());
    }
    v
}

/// Pure resolver: first executable `sops` on `path_var`, then in the
/// candidate directories. `is_exe` is injected so the test can plant a
/// filesystem.
pub(crate) fn find_sops_in(
    path_var: &str,
    home: Option<&Path>,
    exe_dir: Option<&Path>,
    is_exe: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, StoreLoadError> {
    let mut searched: Vec<String> = Vec::new();
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        let cand = Path::new(dir).join("sops");
        if is_exe(&cand) {
            return Ok(cand);
        }
    }
    searched.push("PATH".into());
    for dir in sops_candidates(home, exe_dir) {
        let cand = dir.join("sops");
        if is_exe(&cand) {
            return Ok(cand);
        }
        searched.push(dir.display().to_string());
    }
    Err(StoreLoadError::SopsNotFound { searched: searched.join(", ") })
}

/// The `sops` binary this process will run, or why there is none.
pub fn sops_path() -> Result<PathBuf, StoreLoadError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path_var = std::env::var("PATH").unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let is_exe = |p: &Path| {
        std::fs::metadata(p)
            .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    find_sops_in(&path_var, home.as_deref(), exe_dir.as_deref(), &is_exe)
}

/// A `Command` for `sops`, resolved through [`sops_path`]. Every `sops`
/// invocation in the CLI goes through here so that "not on PATH" means the
/// same thing — and is repaired the same way — everywhere.
pub fn sops_command() -> Result<Command, StoreLoadError> {
    Ok(Command::new(sops_path()?))
}

/// Is there an age key where sops will look for one? Used only to word the
/// failure; sops itself decides.
fn age_key_present() -> bool {
    if std::env::var_os("SOPS_AGE_KEY").is_some() {
        return true;
    }
    // SOPS_AGE_KEY_FILE, the sealed runtime key, or the default (i10a).
    crate::age_key::path().is_file()
}

/// Decrypt the store to dotenv TEXT, in memory. The one decrypt path for
/// both [`SecretStore::load_sops_classified`] and the startup env loader
/// (`envfile::load_sops_secrets`), so a failure is classified once. The
/// text carries values — it is `pub(crate)`, never printed, and its two
/// callers parse it straight into a map.
///
/// BOTH `--input-type dotenv` and `--output-type dotenv` are required —
/// the file is dotenv but named `.sops`, so a bare `sops -d` guesses JSON
/// and fails. A partially-specified invocation fails DIFFERENTLY (it
/// yields zero keys), which reads exactly like "the store is empty"; that
/// ambiguity has cost debugging time before, so a decrypt failure here is
/// an explicit `Err`, never an empty string.
pub(crate) fn decrypt_store_dotenv(path: &Path) -> Result<String, StoreLoadError> {
    let out = sops_command()?
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(path)
        .output()
        .map_err(|e| StoreLoadError::SopsFailedToRun { detail: e.to_string() })?;
    if !out.status.success() {
        // sops' own stderr can echo file content on some errors, so it is
        // NOT forwarded. The exit status plus a pointer is enough.
        return Err(StoreLoadError::DecryptFailed {
            path: path.to_path_buf(),
            exit: out.status.code().unwrap_or(-1),
            age_key_present: age_key_present(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Set,
    Blank,
    Missing,
}

impl State {
    pub fn label(&self) -> &'static str {
        match self {
            State::Set => "set",
            State::Blank => "BLANK",
            State::Missing => "missing",
        }
    }
}

/// Parse dotenv text. Mirrors `envfile::ensure_repo_env`'s tolerance
/// (`export ` prefix, surrounding quotes) so the audit sees the same keys the
/// CLI itself would load — an audit that parsed differently from the loader
/// would report drift that does not exist, or miss drift that does.
pub fn parse_dotenv(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        map.insert(key.to_string(), value.to_string());
    }
    map
}

/// Serialize back to dotenv. Only ever handed to a sops stdin pipe.
fn to_dotenv(map: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    for (k, v) in map {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    s
}

pub fn sha8_of(value: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    let d = h.finalize();
    hex::encode(&d[..4])
}

// ─────────────────────────────────────────────────────────────────────────
// Audit
// ─────────────────────────────────────────────────────────────────────────

/// One audited key. Every field is derived — there is deliberately nowhere
/// in this struct for a value to live.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditRow {
    pub key: String,
    pub in_sops: bool,
    pub in_env: bool,
    /// State in the AUTHORITATIVE store for this key (sops if present there,
    /// otherwise `.env`).
    pub state: State,
    pub sops_state: State,
    pub env_state: State,
    pub length: Option<usize>,
    pub sha8: Option<String>,
    /// sha8 of the `.env` copy when the key is in both — equal digests prove
    /// the two agree without comparing, printing, or diffing any plaintext.
    pub env_sha8: Option<String>,
    pub class: Option<&'static str>,
    pub disposition: Option<&'static str>,
    pub credential_shaped: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Error,
    Warn,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warn => "WARN",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub kind: &'static str,
    pub key: String,
    pub message: String,
}

/// Build the audited rows. Pure over the two stores.
pub fn audit_rows(sops: &SecretStore, env: &SecretStore) -> Vec<AuditRow> {
    let keys: BTreeSet<&String> = sops.keys().chain(env.keys()).collect();
    keys.into_iter()
        .map(|k| {
            let in_sops = sops.contains(k);
            let in_env = env.contains(k);
            let sops_state = sops.state(k);
            let env_state = env.state(k);
            // sops is authoritative when the key exists there — the launcher
            // exports it OVER whatever compose resolved from .env.
            let (state, length, sha8) = if in_sops {
                (sops_state, sops.value_len(k), sops.sha8(k))
            } else {
                (env_state, env.value_len(k), env.sha8(k))
            };
            let spec = spec_for(k);
            AuditRow {
                key: k.clone(),
                in_sops,
                in_env,
                state,
                sops_state,
                env_state,
                length,
                sha8,
                env_sha8: if in_sops && in_env { env.sha8(k) } else { None },
                class: spec.map(|s| s.class.label()),
                disposition: spec.map(|s| s.class.disposition()),
                credential_shaped: spec.is_some() || looks_like_credential(k),
            }
        })
        .collect()
}

/// Credentials that were RETIRED: nothing reads them, and a value still in
/// the store is a live secret with no consumer — nothing will ever prompt a
/// rotation, and a later change could quietly give it a reader again.
/// `secrets audit` and `security scan` report each one with
/// [`RETIRED_REMOVE_CMD`], which drops it from the store (and blanks it in
/// `.env`). Add a row when a credential is retired; never re-add it to the
/// registry (`retired_credentials_stay_out_of_the_registry`).
pub const RETIRED_STORE_KEYS: &[(&str, &str)] = &[
    ("NATS_USER", "retired: the shared NATS bus user"),
    ("NATS_PASSWORD", "retired: the shared NATS bus user"),
    ("NOO_NATS_LEGACY_SHARED_CREDS", "retired: the shared-NATS-user bridge"),
    (
        "NOO_MCP_TOKEN",
        "the operator MCP door's shared bearer, retired 2026-09-30 — /mcp/operator takes only a \
         per-admin `mcp:operator` service key (noo security service-key issue <you>-mcp \
         --scopes mcp:operator --user <admin>), and the gateway ignores this value",
    ),
    (
        "NOO_MCP_TOKEN_PREVIOUS",
        "the rotation grace value of the retired NOO_MCP_TOKEN; ignored",
    ),
    (
        "NOO_SELF_CALL_SHARED_SECRET",
        "the self-call bridge's shared secret, retired in 0.6.11 (the bridge is gone); nothing \
         reads it",
    ),
];

/// The command that removes every [`RETIRED_STORE_KEYS`] entry from the store.
pub const RETIRED_REMOVE_CMD: &str = "noo security secrets tidy";

/// Why `key` is retired, when it is.
pub fn retired_store_key(key: &str) -> Option<&'static str> {
    RETIRED_STORE_KEYS.iter().find(|(k, _)| *k == key).map(|(_, why)| *why)
}

/// Derive the findings. `sops_backend` is whether `NOO_SECRETS_BACKEND=sops`
/// — it changes what "key missing from .env" means, so it must be an input
/// rather than something read from the environment inside a pure function.
pub fn audit_findings(
    rows: &[AuditRow],
    sops_backend: bool,
    flag_on: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in rows {
        // (0) A retired credential still held. Reported once, with the
        // command that removes it, and none of the findings below: "not in
        // the rotation registry" is the point, not a gap to fill.
        if let Some(why) = retired_store_key(&r.key) {
            if r.sops_state == State::Set || r.env_state == State::Set {
                out.push(Finding {
                    severity: Severity::Warn,
                    kind: "retired-key",
                    key: r.key.clone(),
                    message: format!(
                        "retired — {why}. Remove it: `{RETIRED_REMOVE_CMD}` (drops it from \
                         secrets/env.sops and blanks it in .env), then update any client that \
                         still sends it"
                    ),
                });
            }
            continue;
        }
        // (1) Credentials in .env violate the config-only policy (the rule
        // set on 2026-08-02, after 23 plaintext duplicates were found there).
        // A BLANK .env slot is not a copy: the wizard deliberately blanks each
        // credential's slot once the store holds it (#18), and the launcher
        // exports the store over it. Only a value counts.
        if r.in_env && r.credential_shaped && r.env_state != State::Blank {
            let same = match (&r.sha8, &r.env_sha8) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            out.push(Finding {
                severity: Severity::Error,
                kind: "credential-in-env",
                key: r.key.clone(),
                message: if r.in_sops && same {
                    "present in BOTH .env and sops with the same digest — a plaintext duplicate \
                     of an encrypted secret; delete it from .env"
                        .into()
                } else if r.in_sops {
                    "present in BOTH .env and sops with DIFFERENT digests — .env is a stale \
                     shadow that compose will use whenever the launcher is bypassed; \
                     delete it from .env"
                        .into()
                } else {
                    "credential-shaped key living ONLY in plaintext .env — not encrypted at \
                     rest; move it to secrets/env.sops"
                        .into()
                },
            });
        }
        // (2) A key in sops that no consumer can see. With the sops backend
        // OFF, the launcher exports nothing, so compose resolves `${VAR}` from
        // .env — absent there, services start with an EMPTY credential. That
        // failure looks like a 401/auth fault, not a config fault: exactly how
        // this class of bug consumed an operator session.
        if r.in_sops && !r.in_env && !sops_backend && r.credential_shaped {
            out.push(Finding {
                severity: Severity::Warn,
                kind: "consumer-gap",
                key: r.key.clone(),
                message: "in sops but NOT in .env, and NOO_SECRETS_BACKEND is not `sops` — \
                          nothing exports it, so consumers see an empty value (401s, not \
                          config errors). Set NOO_SECRETS_BACKEND=sops, or launch via \
                          `noo stack start` which sources scripts/lib-secrets.sh"
                    .into(),
            });
        }
        // (3) Present-but-blank. Fails SILENTLY at runtime: the var exists, so
        // every "is it set?" check passes, and the auth attempt fails later.
        if r.state == State::Blank && r.credential_shaped {
            out.push(Finding {
                severity: Severity::Error,
                kind: "blank-value",
                key: r.key.clone(),
                message: format!(
                    "present in {} but EMPTY — presence checks pass and the credential fails \
                     later, which is the hardest shape to diagnose",
                    if r.in_sops { "sops" } else { ".env" }
                ),
            });
        }
        // (4) Drift: same key, two stores, two different values.
        if let (Some(a), Some(b)) = (&r.sha8, &r.env_sha8) {
            if a != b {
                out.push(Finding {
                    severity: Severity::Warn,
                    kind: "value-drift",
                    key: r.key.clone(),
                    message: "sops and .env hold DIFFERENT values (digests differ). sops wins \
                              under the launcher; .env wins under a bare `docker compose up`"
                        .into(),
                });
            }
        }
        // (5) A credential-shaped key with no rotation plan.
        if r.credential_shaped && r.class.is_none() {
            out.push(Finding {
                severity: Severity::Info,
                kind: "unclassified-credential",
                key: r.key.clone(),
                message: "looks like a credential but is not in the rotation registry — \
                          `noo security secrets rotate` has no plan for it (add it to \
                          noo-cli/src/commands/secrets.rs CORE_REGISTRY, or an add-on overlay's x-noo-addon)"
                    .into(),
            });
        }
    }
    // (6) Registry keys absent from the store entirely.
    //
    // This was a flat INFO worded "fine if the feature is not enabled on this
    // install" — which is true when the feature is off and badly wrong when it
    // is on. A credential that a RUNNING system needs, absent from both
    // stores, was reported at the same severity as one belonging to something
    // nobody switched on. `required_when` is what tells the two apart.
    for spec in registry() {
        if !rows.iter().any(|r| r.key == spec.key) {
            let required = spec.required_when.required(flag_on);
            out.push(Finding {
                severity: if required { Severity::Error } else { Severity::Info },
                kind: if required {
                    "required-key-absent"
                } else {
                    "registry-key-absent"
                },
                key: spec.key.into(),
                message: if required {
                    match spec.required_when {
                        Requirement::Always => "required on every install, and absent from \
                             both stores — whatever consumes it sees an empty value"
                            .to_string(),
                        Requirement::WhenEnabled(flag) => format!(
                            "{flag} is on, so this install NEEDS this credential, and it is \
                             absent from both stores — whatever consumes it sees an empty value"
                        ),
                        Requirement::WhenAddon(name) => format!(
                            "addons.{name} is on in noomesh.yaml, so this install NEEDS this \
                             credential, and it is absent from both stores — whatever consumes \
                             it sees an empty value"
                        ),
                        Requirement::WhenNotStandalone => format!(
                            "this install is not `standalone` (a vllm/llamacpp placement or \
                             profile, or a HuggingFace-backed model preseed, is active), so it \
                             NEEDS {}, and it is absent from both stores — whatever consumes it \
                             sees an empty value",
                            spec.key
                        ),
                        Requirement::Optional => unreachable!("Optional is never required"),
                    }
                } else {
                    match spec.required_when {
                        Requirement::WhenEnabled(flag) => format!(
                            "known secret, absent from both stores — expected, because {flag} \
                             is off on this install"
                        ),
                        Requirement::WhenAddon(name) => format!(
                            "known secret, absent from both stores — expected, because \
                             addons.{name} is off on this install; `noo addons enable {name}` \
                             mints it before switching the add-on on"
                        ),
                        Requirement::WhenNotStandalone => format!(
                            "{} not set — needed only for gated HuggingFace models (a \
                             vllm/llamacpp placement or profile, or a HuggingFace-backed model \
                             preseed); this is a `standalone` (Ollama-only) install, so absent \
                             is expected",
                            spec.key
                        ),
                        Requirement::Optional => "optional — supplied only when you use the \
                             feature it unlocks; absent is the normal state of a fresh install"
                            .to_string(),
                        Requirement::Always => unreachable!("Always is always required"),
                    }
                },
            });
        }
    }
    out
}

/// Render the human audit. **Pure**, and the only place audit text is built —
/// so `no_value_ever_reaches_output` covering this function covers the
/// command's entire human output surface.
pub fn render_audit(
    rows: &[AuditRow],
    findings: &[Finding],
    sops: &SecretStore,
    env: &SecretStore,
    sops_backend: bool,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Secret audit — {} ({} keys) vs {} ({} keys)\n",
        sops.path.display(),
        sops.len(),
        env.path.display(),
        env.len()
    ));
    s.push_str(&format!(
        "NOO_SECRETS_BACKEND={}\n\n",
        if sops_backend { "sops" } else { "env (or unset)" }
    ));

    let kw = rows.iter().map(|r| r.key.len()).max().unwrap_or(3).max(3);
    s.push_str(&format!(
        "{:<kw$}  {:<4}  {:<4}  {:<7}  {:>4}  {:<8}  {}\n",
        "KEY",
        "SOPS",
        "ENV",
        "STATE",
        "LEN",
        "SHA256",
        "CLASS",
        kw = kw
    ));
    s.push_str(&format!("{}\n", "-".repeat(kw + 42)));
    for r in rows {
        s.push_str(&format!(
            "{:<kw$}  {:<4}  {:<4}  {:<7}  {:>4}  {:<8}  {}\n",
            r.key,
            if r.in_sops { "yes" } else { "no" },
            if r.in_env { "yes" } else { "no" },
            r.state.label(),
            r.length.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            r.sha8.clone().unwrap_or_else(|| "-".into()),
            r.class.unwrap_or("-"),
            kw = kw
        ));
    }

    s.push('\n');
    if findings.is_empty() {
        s.push_str("Findings: none.\n");
    } else {
        let errs = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        s.push_str(&format!(
            "Findings ({} total, {} error):\n",
            findings.len(),
            errs
        ));
        for f in findings {
            s.push_str(&format!(
                "  {:<5}  {:<24}  {}\n         {}\n",
                f.severity.label(),
                f.kind,
                f.key,
                f.message
            ));
        }
    }
    s.push_str(
        "\nNo secret values were printed. Digests are sha256[:8] — equal digests prove two \
         stores agree\nwithout revealing either. NEVER `sops -d … > file` and NEVER diff \
         plaintext: on 2026-08-03\nthat leaked the whole store into a terminal transcript. \
         Use this command instead.\n",
    );
    s
}

fn audit_json(
    rows: &[AuditRow],
    findings: &[Finding],
    sops: &SecretStore,
    env: &SecretStore,
    sops_backend: bool,
) -> serde_json::Value {
    serde_json::json!({
        "sops_file": sops.path.to_string_lossy(),
        "sops_present": sops.existed,
        "env_file": env.path.to_string_lossy(),
        "env_present": env.existed,
        "secrets_backend": if sops_backend { "sops" } else { "env" },
        "counts": {
            "keys": rows.len(),
            "in_sops": rows.iter().filter(|r| r.in_sops).count(),
            "in_env": rows.iter().filter(|r| r.in_env).count(),
            "blank": rows.iter().filter(|r| r.state == State::Blank).count(),
            "errors": findings.iter().filter(|f| f.severity == Severity::Error).count(),
            "warnings": findings.iter().filter(|f| f.severity == Severity::Warn).count(),
        },
        "keys": rows.iter().map(|r| serde_json::json!({
            "key": r.key,
            "in_sops": r.in_sops,
            "in_env": r.in_env,
            "state": r.state.label(),
            "sops_state": r.sops_state.label(),
            "env_state": r.env_state.label(),
            "length": r.length,
            "sha256_8": r.sha8,
            "env_sha256_8": r.env_sha8,
            "class": r.class,
            "rotation": r.disposition,
            "credential_shaped": r.credential_shaped,
        })).collect::<Vec<_>>(),
        "findings": findings.iter().map(|f| serde_json::json!({
            "severity": f.severity.label().to_ascii_lowercase(),
            "kind": f.kind,
            "key": f.key,
            "message": f.message,
        })).collect::<Vec<_>>(),
    })
}

/// `noo security secrets audit [--sops-file P] [--env-file P] [--json]`
/// Probe every `Class::DbPassword` secret against the role it actually
/// controls, and report the ones that do not authenticate.
///
/// **Why this is not covered by the rest of the audit.** Everything else here
/// asks "do the stores agree?", compared by digest, without materialising a
/// value. That is the right question for almost every class and the wrong one
/// for a db-password: the store can agree with itself perfectly while the
/// Postgres role sits on a different password entirely.
///
/// That is not hypothetical. On 2026-08-03 `NOO_APP_DB_PASSWORD` was rotated by
/// hand — `env.sops` and every consumer took the new value, the `noo_app` role
/// kept the old one. The gateway lost ALL database access for four hours (1,641
/// auth failures across nine subsystems), and the *leaked* password it had been
/// rotated away from stayed valid on the database the whole time. This audit
/// reported **0 errors** throughout. 
///
/// The probe is safe to run: the value is already in the store the operator
/// just decrypted, and the result is a boolean. Nothing is printed.
///
/// Absence of Postgres is NOT a finding — this must stay useful on a machine
/// where the stack is down, and "cannot check" is not "is broken".
///
/// **Expected side effect:** each run writes one `password authentication
/// failed` line per db-password to the POSTGRES log — that is the negative
/// control being correctly rejected, and it is the evidence the check is real.
/// Anyone auditing those logs should not read a `secrets audit` run as an
/// intrusion attempt. It does not touch the gateway's own auth-failure
/// telemetry (`noo_auth_failures_5m` / the `failed_auth_spike` autonomy check),
/// which is fed from the application audit table, not Postgres's log.
fn db_password_liveness_findings(sops: &SecretStore) -> Vec<Finding> {
    let mut out = Vec::new();
    let pg_container = &crate::envfile::container("postgres") as &str;
    if !container_running(pg_container) {
        return out;
    }
    // Loopback was `trust` in the stock pg_hba, so a check over 127.0.0.1 could
    // not fail. Verified 2026-08-03: it returned NotPasswordAuthenticated for all
    // four db-passwords. The shipped pg_hba (docker/postgres/pg_hba.conf,
    // 2026-09-28) trusts only the unix socket, but the routable address stays:
    // it is a real TCP path — TLS, client certificate, then the password — and
    // the negative control below is still what proves the check can fail.
    let Some(pg_host) = container_routable_host(pg_container) else {
        return out;
    };
    let pg_db = postgres_db();

    for spec in registry() {
        // `role: None` means the superuser role the image creates, named by
        // POSTGRES_USER — resolved the same way the rotate path resolves it.
        let role = match spec.class {
            Class::DbPassword { role: Some(r) } => r.to_string(),
            Class::DbPassword { role: None } => {
                std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into())
            }
            _ => continue,
        };
        let Some(value) = sops.map.get(spec.key) else {
            continue;
        };
        if value.is_empty() {
            continue; // already reported as `blank-value`
        }
        match verify_login_via(pg_container, &role, &pg_db, value, &pg_host) {
            Ok(Verify::Verified) => {}
            // The negative control passed, so this connection path accepts any
            // password and the probe proved nothing. Say so — a check that
            // cannot fail must never be reported as a check that passed.
            Ok(Verify::NotPasswordAuthenticated) => out.push(Finding {
                severity: Severity::Info,
                kind: "db-password-not-verifiable",
                key: spec.key.to_string(),
                message: format!(
                    "role \"{role}\" could not be verified: this connection path accepts any \
                     password (a `trust` rule in pg_hba on this path), so the login test proves nothing"
                ),
            }),
            // Same class: we learned nothing. Reported so the audit never
            // implies it checked a secret it could not reach.
            Ok(Verify::Unreachable) => out.push(Finding {
                severity: Severity::Info,
                kind: "db-password-not-verifiable",
                key: spec.key.to_string(),
                message: format!(
                    "role \"{role}\" could not be verified: Postgres was not reachable at \
                     {pg_host} — this is NOT evidence that the password is wrong"
                ),
            }),
            Ok(Verify::Misconfigured(why)) => out.push(Finding {
                severity: Severity::Warn,
                kind: "db-password-check-misconfigured",
                key: spec.key.to_string(),
                message: format!(
                    "role \"{role}\" could not be verified because the CHECK asked for something \
                     that does not exist ({why}); it dialled database `{pg_db}`. Set POSTGRES_DB \
                     in .env to the real database name — until then this audit verifies no \
                     password, and says so here rather than as `unreachable`"
                ),
            }),
            Err(_) => out.push(Finding {
                severity: Severity::Error,
                kind: "db-password-does-not-authenticate",
                key: spec.key.to_string(),
                message: format!(
                    "the stored value does NOT authenticate as role \"{role}\" — the store and \
                     the database disagree. Anything using this secret is locked out, and \
                     whatever password the role still holds is live. Converge it with \
                     `noo security secrets resync {}` (never by hand: editing the store alone \
                     is what causes this). Prefer that over `rotate`: the store and every \
                     consumer already agree, so only the ROLE is behind — resync moves it \
                     onto the stored value without minting a new secret or needing any \
                     container recreated",
                    spec.key
                ),
            }),
        }
    }
    out
}

/// Whether `.env` declares the standalone profile (`NOO_DEFAULT_PROFILE=standalone`).
/// A local copy of models.rs's `is_standalone_install` rather than a
/// cross-module import — the two commands share no other dependency, and a
/// shared helper would be odd coupling for one line of logic. Used to gate
/// `Requirement::WhenNotStandalone` (HF_TOKEN): an Ollama-only install
/// consumes no HuggingFace-gated backend, so it should not be nagged for a
/// credential nothing on it can ever use.
fn is_standalone_install(root: &std::path::Path) -> bool {
    std::fs::read_to_string(root.join(".env"))
        .map(|env| env.lines().any(|l| l.trim() == "NOO_DEFAULT_PROFILE=standalone"))
        .unwrap_or(false)
}

pub fn secrets_audit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut sops_path: Option<PathBuf> = None;
    let mut env_path: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--sops-file" => sops_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            "--env-file" => env_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            _ => return Err(Unhandled),
        }
    }
    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    let env_path = env_path.unwrap_or_else(|| root.join(".env"));

    let sops = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "sops_decrypt_failed",
            &e,
            Some("the audit needs to decrypt in memory; it never writes plaintext to disk"),
        ),
    };
    let env = SecretStore::load_env(&env_path);
    let backend = envfile::sops_backend_active();
    let rows = audit_rows(&sops, &env);
    // The only place a gate is read from the real install. Truthiness of an
    // env flag matches the shell convention the launchers use, so =1 and
    // =true mean the same here as they do in lib-config.sh.
    let flag_on = |gate: &str| {
        // `addons.<name>` resolves through noomesh.yaml (default polarity
        // when silent); `profile.not-standalone` reads `.env`'s
        // NOO_DEFAULT_PROFILE (Requirement::WhenNotStandalone); anything
        // else is an env flag.
        if let Some(name) = gate.strip_prefix("addons.") {
            let default_on = crate::commands::addons::row(name).map(|r| r.default_on).unwrap_or(false);
            return crate::commands::addons::effective(name).unwrap_or(default_on);
        }
        if gate == "profile.not-standalone" {
            return !is_standalone_install(&root);
        }
        std::env::var(gate)
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    };
    let mut findings = audit_findings(&rows, backend, &flag_on);
    // Store-vs-store agreement is not the whole question for a db-password.
    // Appended here rather than inside `audit_findings` because that function
    // is pure over the two stores and its tests depend on that.
    findings.extend(db_password_liveness_findings(&sops));
    // Same reason: reads the filesystem, so it cannot live in the pure function.
    findings.extend(store_backup_findings(&sops_path));
    findings.extend(secret_age_findings(&sops_path, &sops, now_unix()));
    // Every file compose delivers is in its consumer, and no `_FILE`
    // pointer names a missing one (a stat through the docker API, never a read).
    findings.extend(super::secrets_delivery::file_delivery_findings());
    if let Ok(conf) = std::fs::read_to_string(root.join(super::nats_users::USERS_CONF)) {
        findings.extend(orphaned_node_password_findings(&sops, &conf));
    }

    if g.json {
        println!("{}", audit_json(&rows, &findings, &sops, &env, backend));
    } else if rows.is_empty() {
        println!("{}", ui::muted(&format!("no keys found in {} or {}", sops_path.display(), env_path.display())));
    } else {
        print!("{}", render_audit(&rows, &findings, &sops, &env, backend));
    }
    // Exit 1 on any ERROR finding. This used to be "exit 0 regardless, parity
    // with `security scan`" — and the 2026-09-02 install carried 22 plaintext
    // duplicates of encrypted secrets for five days while this command
    // reported all 22, correctly, to nobody: it only runs when typed, and a
    // zero exit means no script can notice. A detector with no trigger and no
    // exit code is documentation.
    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    Ok(if errors > 0 { 1 } else { 0 })
}

// ─────────────────────────────────────────────────────────────────────────
// Rotation
// ─────────────────────────────────────────────────────────────────────────

/// What will happen to one key, decided before anything is touched.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanItem {
    pub key: String,
    pub class_label: &'static str,
    pub disposition: &'static str,
    pub consequence: String,
    pub consumers: Vec<String>,
    /// Set when this key cannot proceed; the whole run aborts if any is set.
    pub refusal: Option<String>,
    /// Role to `ALTER` (resolved: `POSTGRES_USER` already substituted).
    pub db_role: Option<String>,
    /// Backup artifacts this passphrase opens, which must be re-encrypted
    /// old → new in the same run. `Some` only for
    /// [`Class::BackupPassphrase`]; an empty Vec inside it means the glob
    /// matched nothing, which is normal on a box that has not backed up yet.
    pub artifacts: Option<Vec<PathBuf>>,
    /// This key is absent from the store and rotation will CREATE it.
    ///
    /// Rotation otherwise refuses a key it cannot find, because inventing one
    /// is not rotation. A backup passphrase is the exception: `noo onboard`
    /// mints these, but an install that predates that has neither, and the
    /// backup now refuses to run without them — so "create it" is the whole
    /// point of the first invocation on such a box.
    pub first_set: bool,
    pub source: ValueSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueSource {
    /// Minted locally by `token_urlsafe`.
    Generated,
    /// Supplied by the operator on stdin (`--set-from-stdin`).
    Stdin,
    /// Typed by the operator at the terminal with the echo turned OFF
    /// (`--prompt`). Never reaches the shell's history, the process list or
    /// the scrollback.
    Prompt,
}

/// The refusal text for a fleet-wide secret, with the sequence the operator
/// must drive by hand.
///
/// **There was no fleet push for these values** when this refusal was
/// written. That was checked rather than assumed, on 2026-08-03:
///   - `noo cluster init-secret` (`commands/cluster.rs`) only PRINTS a fresh
///     `token_urlsafe(32)`. It writes no file and contacts no node — its own
///     output tells you to add it to the worker `.env` files yourself.
///   - `noo cluster issue-token` likewise prints a token that nothing
///     persists or validates.
///   - `noo cluster upgrade-agents`
///     (`commands/cluster_provision_subprocess.rs`) was a binary roll that
///     never touched the node's env. Since an earlier release retired that swap
///     it restages the provision bundle — which renders the value the
///     controller ALREADY runs, so it converges nodes but cannot rotate.
///   - The only thing that has ever written a credential onto a node is node
///     PROVISIONING itself (`noo cluster provision` / `noo enroll`; the
///     retired `add-node` did it via `ansible/templates/worker.env.j2`).
///
/// So a fleet-wide rotation is inherently a multi-host, briefly-destructive
/// operation. Implementing it as a silent side effect of a `rotate` flag
/// would mean this tool taking down the cluster from inside a command whose
/// output an operator might not even be watching. Refusing loudly, with the
/// real sequence, is the honest answer — and it is a correct one.
///
/// **Update (WP-FS):** `noo cluster push-secrets` now exists and performs the
/// per-node half of that sequence — staging a `fleet-secrets` bundle each
/// node collects and merges into its agent env. It does NOT
/// change the refusal here, and deliberately so: `push-secrets` converges
/// nodes onto the value the controller is ALREADY running, which is safe in
/// any order, whereas rotating mints a NEW value and opens a window in which
/// the fleet is genuinely down. `cluster_push_secrets::rotation_hazard_note`
/// records why no online rotation of these keys is possible today — read from
/// the verifiers, not assumed. `rotate` still refuses to open that window
/// unattended; it just no longer leaves the operator without a tool for the
/// second half.
pub fn fleet_refusal(key: &str) -> String {
    format!(
        "{key} is held by EVERY node, not just the controller \
         (node provisioning writes it into each node's /etc/noo-node-agent.env). \
         Rotating it here would update the controller and leave every node presenting the old \
         credential — the fleet stops heartbeating and the failure surfaces as timeouts, not \
         as auth errors.\n\
         \n\
         There is NO fleet push for it today (verified, not assumed):\n\
         \x20 - `noo cluster init-secret` only PRINTS a value — it writes nothing, pushes nothing\n\
         \x20 - `noo cluster upgrade-agents` restages provision bundles: it writes the value the\n\
         \x20   controller ALREADY runs, so it converges nodes but cannot rotate one\n\
         \x20 - only node provisioning ever writes it, once, at enrollment time\n\
         \n\
         This tool refuses rather than half-doing it. Drive it yourself, from a session you \
         can watch:\n\
         \x20 1. noo security secrets audit                    # confirm the current state\n\
         \x20 2. noo cluster status                            # list EVERY node to be reached\n\
         \x20 3. noo security generate-secret cluster          # mint once; keep it off scrollback\n\
         \x20 4. sops secrets/env.sops                         # set {key} on the controller\n\
         \x20 5. noo stack restart                             # controller picks up the new value\n\
         \x20 6. noo cluster push-secrets --dry-run           # confirm the plan, stage nothing\n\
         \x20 7. noo cluster push-secrets                     # stage a bundle for every node\n\
         \x20 8. noo cluster status                            # every node back to online\n\
         \n\
         Steps 6-7 are `noo cluster push-secrets`: it stages one CA-signed bundle per node, \
         encrypted to that node's own certificate, which the node collects on its fetch timer \
         and merges into /etc/noo-node-agent.env before restarting its agent. It converges \
         every fleet key at once — there is no per-key flag, because the bundle is the unit \
         of delivery. It will REFUSE to run at all until \
         step 5 has happened, because it checks the RUNNING gateway's value against the \
         store first — pushing a store the controller is not using would break every node \
         that still works.\n\
         \n\
         Expect the fleet to be offline between step 4 and the moment each node's fetch \
         timer collects (60s on Linux, up to 5 minutes on a Mac). There is no online rotation \
         of this key: both verifiers read a single secret with no previous-value slot. Do \
         this with console access to the nodes, not over a link that depends on the cluster \
         being up."
    )
}

/// Build the plan. Pure over the store + requested keys, so the refusal and
/// classification logic is unit-testable without a store, a database, or a
/// container.
pub fn build_plan(
    keys: &[String],
    sops: &SecretStore,
    stdin_key: Option<&str>,
    supplied: ValueSource,
    postgres_role: &str,
) -> Vec<PlanItem> {
    keys.iter()
        .map(|key| {
            let spec = spec_for(key);
            let from_stdin = stdin_key == Some(key.as_str());
            let mut refusal = None;
            let (class_label, disposition, consequence, consumers) = match spec {
                Some(s) => (
                    s.class.label(),
                    s.class.disposition(),
                    s.consequence.to_string(),
                    s.consumers.iter().map(|c| c.to_string()).collect(),
                ),
                None => {
                    refusal = Some(format!(
                        "{key} is not in the rotation registry — this tool does not know what \
                         breaks when it changes, so it will not change it. Add a SecretSpec in \
                         noo-cli/src/commands/secrets.rs, or edit the store by hand \
                         (`sops secrets/env.sops`)."
                    ));
                    ("unknown", "refused", String::new(), Vec::new())
                }
            };
            if let Some(s) = spec {
                match s.class {
                    Class::FleetWide if !from_stdin => refusal = Some(fleet_refusal(key)),
                    Class::FleetWide => {
                        refusal = Some(format!(
                            "{}\n\nEven with --set-from-stdin: putting a new value in the store \
                             does not reach the nodes. Use the sequence above.",
                            fleet_refusal(key)
                        ))
                    }
                    Class::ProviderIssued if !from_stdin => {
                        refusal = Some(format!(
                            "{key} is issued by a third party — it CANNOT be generated locally. \
                             Re-issue it at the provider, then give it to this command without \
                             it ever touching disk, scrollback or shell history:\n\
                             \n\
                             \x20 noo security secrets rotate {key} --prompt\n\
                             \x20   type it at the terminal; nothing is echoed, and you type \
                             it twice so a slip cannot be stored\n\
                             \n\
                             \x20 <your password manager> | noo security secrets rotate {key} \
                             --set-from-stdin --yes\n\
                             \x20   the same thing non-interactively, for a script\n\
                             \n\
                             Consequence: {}",
                            s.consequence
                        ))
                    }
                    // A dedicated tool already does this correctly, including
                    // work this one does not. Pointing at it beats a
                    // half-equivalent reimplementation.
                    Class::ExternalTool { tool } => {
                        refusal = Some(format!(
                            "{key} is rotated by a dedicated tool, not by this one:\n\
                             \n\
                             \x20 {tool}\n\
                             \n\
                             That tool does something this one does not: it re-encrypts every \
                             existing artifact old→new and verifies each before committing any. \
                             Just changing the value here would leave those artifacts locked to \
                             a passphrase that is no longer recorded anywhere.\n\
                             \n\
                             Consequence: {}",
                            s.consequence
                        ))
                    }
                    // Not a secret in its own right: minting a fresh random
                    // value here would produce a token the gateway rejects.
                    Class::Derived { parent, mint } if !from_stdin => {
                        refusal = Some(format!(
                            "{key} is DERIVED from {parent} — it is not an independent value, \
                             so there is nothing here to regenerate. A random replacement \
                             would simply fail verification.\n\
                             \n\
                             Rotate {parent} instead; this token is then re-minted as part of \
                             that, in this order:\n\
                             \x20 1. noo security secrets rotate {parent}\n\
                             \x20 2. {mint}\n\
                             \x20 3. install it: <the minted token> | noo security secrets \
                             rotate {key} --set-from-stdin --yes\n\
                             \x20 4. recreate its consumers\n\
                             \n\
                             Consequence: {}",
                            s.consequence
                        ))
                    }
                    _ => {}
                }
            }
            // A backup passphrase may legitimately be absent: see
            // `PlanItem::first_set`. So may a provider-issued key the
            // operator is handing over: an optional one (a search API key,
            // a Telegram token) is ABSENT on every install until the day the
            // feature is wanted, and nothing holds an old value that a first
            // set could break. Without this, the only way to add one after
            // onboarding was hand-editing the encrypted store (2026-09-28,
            // TAVILY_API_KEY on host8). It still needs the value supplied —
            // an unsupplied provider key was refused above.
            let first_settable = match spec.map(|s| s.class) {
                Some(Class::BackupPassphrase { .. }) => true,
                Some(Class::ProviderIssued) => from_stdin,
                _ => false,
            };
            let first_set = first_settable && !sops.contains(key);
            // A key not in the store is a typo or a feature that was never
            // configured; either way, inventing it is not "rotation".
            if refusal.is_none() && !first_settable && !sops.contains(key) {
                refusal = Some(format!(
                    "{key} is not present in {} — rotation replaces an existing value, it does \
                     not create one. Add it with `sops secrets/env.sops` first.",
                    sops.path.display()
                ));
            }
            let db_role = spec.and_then(|s| match s.class {
                Class::DbPassword { role } => {
                    Some(role.map(str::to_string).unwrap_or_else(|| postgres_role.to_string()))
                }
                _ => None,
            });
            let artifacts = spec.and_then(|s| match s.class {
                Class::BackupPassphrase { glob } => Some(backup_artifacts(glob)),
                _ => None,
            });
            PlanItem {
                key: key.clone(),
                class_label,
                disposition,
                consequence,
                consumers,
                refusal,
                db_role,
                artifacts,
                first_set,
                source: if from_stdin { supplied } else { ValueSource::Generated },
            }
        })
        .collect()
}

/// Would this rotation leave the two backup passphrases EQUAL?
///
/// `backup-controller.sh` refuses to run when they are, because
/// `NOO_BACKUP_PASSPHRASE` lives in the store and the store is opened by the
/// age key — so if the same value also protected the age-key backup, opening
/// that backup would require the key it contains. Recovery would be circular.
///
/// Pure over "what this run sets" and "what the store already holds", because
/// the interesting case is rotating ONE of them to the value the OTHER already
/// has — which is what happens when an operator copies between two panes of a
/// password manager, and which no amount of care at the prompt would catch.
///
/// Generated values never collide; `--set-from-stdin` is the real path.
pub fn backup_passphrases_would_collide(
    new_values: &BTreeMap<String, String>,
    existing: &BTreeMap<String, String>,
) -> bool {
    const PG: &str = "NOO_BACKUP_PASSPHRASE";
    const AGE: &str = "NOO_AGE_BACKUP_PASSPHRASE";
    if !new_values.contains_key(PG) && !new_values.contains_key(AGE) {
        return false;
    }
    let eff = |k: &str| new_values.get(k).or_else(|| existing.get(k));
    match (eff(PG), eff(AGE)) {
        (Some(a), Some(b)) => !a.is_empty() && a == b,
        _ => false,
    }
}

/// The backup directory a passphrase's artifacts live in.
pub fn backup_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NOO_BACKUP_DIR") {
        if !d.trim().is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("noo-backups")
}

/// Files in [`backup_dir`] matching a `<prefix>*<suffix>` glob, newest first.
///
/// Hand-rolled rather than a glob crate: the two patterns in the registry are
/// both `prefix_*suffix`, and a dependency for that is not worth it. Anything
/// more complex than one `*` is rejected loudly rather than silently matching
/// nothing — a glob that quietly matches no files would make rotation report
/// "0 artifacts re-encrypted" on a box full of backups, and leave every one of
/// them locked to a passphrase no longer recorded anywhere.
pub fn backup_artifacts(glob: &str) -> Vec<PathBuf> {
    let (prefix, suffix) = match glob.split_once('*') {
        Some((p, s)) if !s.contains('*') => (p, s),
        _ => panic!("backup glob {glob:?} must contain exactly one '*'"),
    };
    let dir = backup_dir();
    let mut out: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.path().is_file())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.len() >= prefix.len() + suffix.len()
                    && n.starts_with(prefix)
                    && n.ends_with(suffix)
            })
            .map(|e| e.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out.reverse();
    out
}

/// One artifact re-encrypted old → new, verified, and not yet installed.
///
/// Same prepare-then-commit shape as [`PreparedStore`], for the same reason:
/// re-encrypting in place one file at a time means a failure halfway through
/// leaves the finished ones locked to a passphrase that may never have been
/// written down. Dropping without [`PreparedArtifact::commit`] removes the
/// temp file, so every early return in `secrets_rotate` cleans up on its own.
pub struct PreparedArtifact {
    target: PathBuf,
    tmp: PathBuf,
}

impl PreparedArtifact {
    fn commit(self) -> Result<(), String> {
        std::fs::rename(&self.tmp, &self.target)
            .map_err(|e| format!("installing {}: {e}", self.target.display()))?;
        set_600(&self.target);
        std::mem::forget(self);
        Ok(())
    }
}

impl Drop for PreparedArtifact {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// `openssl enc` the way `backup-controller.sh` writes these files:
/// AES-256-CBC, PBKDF2, random salt, passphrase on an ENV VAR and never in
/// argv. `decrypt = true` reverses it.
///
/// The output path is a sibling of the input so the eventual install is a
/// same-filesystem `rename(2)`.
fn openssl_enc(
    input: &Path,
    output: &Path,
    passphrase: &str,
    decrypt: bool,
) -> Result<(), String> {
    let mut cmd = Command::new("openssl");
    cmd.arg("enc");
    if decrypt {
        cmd.arg("-d");
    }
    cmd.args(["-aes-256-cbc", "-pbkdf2"]);
    if !decrypt {
        cmd.arg("-salt");
    }
    cmd.args(["-pass", "env:NOO_ENC_PASS"])
        .arg("-in")
        .arg(input)
        .arg("-out")
        .arg(output)
        .env("NOO_ENC_PASS", passphrase)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = cmd.output().map_err(|e| format!("could not run openssl: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(output);
        // openssl's own message ("bad decrypt") is the useful part; it never
        // contains the passphrase.
        return Err(String::from_utf8_lossy(&out.stderr).trim().lines().last().unwrap_or("openssl failed").to_string());
    }
    Ok(())
}

/// What an artifact's plaintext must start with, derived from its name.
///
/// `openssl enc -d` exiting 0 is NOT proof the passphrase was right. With
/// AES-256-CBC and PKCS#7 the only check openssl performs is that the last
/// block ends in valid padding, and decryption under a WRONG key produces
/// uniformly random bytes, which end in a valid pad about 1 time in 256.
/// Measured against an artifact encrypted exactly the way `openssl_enc`
/// writes them: 4 wrong passphrases accepted out of 1500.
///
/// That matters here more than anywhere else in this file. `prepare_artifact`
/// decrypts with the OLD passphrase and re-encrypts with the NEW one, so a
/// wrong-but-lucky decrypt re-encrypts RANDOM BYTES — producing a backup that
/// opens cleanly under the new passphrase and contains nothing. Across the 35
/// dumps on the live controller, one rotation had roughly a 13% chance of
/// destroying at least one, and it would be discovered at restore time.
///
/// The fix is to stop asking openssl whether the padding looked plausible and
/// check the plaintext is what the artifact is supposed to be. The filename
/// already says: the dumps are gzip, the age-key backup is an age key file.
/// A magic check turns a 1-in-256 coin flip into a certainty for those bytes.
fn expected_magic(name: &str) -> Option<(&'static [&'static [u8]], &'static str)> {
    if name.contains(".gz.") || name.ends_with(".gz") {
        // gzip member header. Every pg dump this tool writes is `pg_dump |
        // gzip | openssl enc`, so the first two bytes are fixed.
        return Some((&[&[0x1f, 0x8b]], "a gzip stream"));
    }
    if name.starts_with("age-key") {
        // EITHER form is a real age key file: `age-keygen -o` writes a
        // `# created:` / `# public key:` header, and a hand-made or
        // stripped file is the bare key line. Both are long fixed strings,
        // so accepting the pair costs nothing against the 1-in-256 it
        // replaces, and refusing a legitimate shape would be worse than
        // the flaw — a rotation that will not run gets worked around.
        return Some((&[b"# created:", b"AGE-SECRET-KEY-"], "an age key file"));
    }
    // Unknown shape: no check possible. Say so at the call site rather than
    // implying a verification that did not happen.
    None
}

/// Decrypt, and verify the plaintext is what this artifact should hold.
///
/// Returns `Ok(true)` when the content was checked, `Ok(false)` when the
/// name implies no known shape — the caller decides what to say about an
/// unverifiable artifact. See [`expected_magic`] for why the exit status
/// alone is not enough.
fn decrypt_and_verify(enc: &Path, out: &Path, pass: &str, name: &str) -> Result<bool, String> {
    openssl_enc(enc, out, pass, true)?;
    let Some((accepted, what)) = expected_magic(name) else { return Ok(false) };
    let longest = accepted.iter().map(|m| m.len()).max().unwrap_or(0);
    use std::io::Read as _;
    let mut f = std::fs::File::open(out).map_err(|e| format!("cannot re-read the decrypted copy: {e}"))?;
    let mut head = vec![0u8; longest];
    // A SHORT read is not a failure to read — a legitimate artifact can be
    // shorter than the longest accepted prefix. Take what is there and
    // compare against it.
    let n = f.read(&mut head).map_err(|e| format!("cannot re-read the decrypted copy: {e}"))?;
    head.truncate(n);
    if accepted.iter().any(|m| head.starts_with(m)) {
        return Ok(true);
    }
    Err(format!(
        "it decrypted, but the result is not {what} — the passphrase is wrong. \
         `openssl enc -d` exits 0 for a wrong key about 1 time in 256; \
         this is that case, caught"
    ))
}

/// Re-encrypt one artifact old → new and prove the result opens with the new
/// passphrase, AND that what comes out is what the artifact should hold.
/// The original is not touched.
pub fn prepare_artifact(
    file: &Path,
    old: &str,
    new: &str,
) -> Result<PreparedArtifact, String> {
    let dir = file.parent().unwrap_or_else(|| Path::new("."));
    let stem = file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let plain = dir.join(format!(".{stem}{PLAIN_INFIX}{}", std::process::id()));
    let tmp = dir.join(format!(".{stem}{ROTATING_INFIX}{}", std::process::id()));
    // The plaintext of a pg dump or an age private key exists for the length
    // of this function and nowhere else. 0600 from creation: openssl creates
    // the file, so the mode has to be fixed immediately after, and the file is
    // removed on every path out.
    let guard = TempPlain(plain.clone());
    let checked = decrypt_and_verify(file, &plain, old, &stem)
        .map_err(|e| format!("{stem}: the CURRENT passphrase does not open it ({e})"))?;
    set_600(&plain);
    openssl_enc(&plain, &tmp, new, false).map_err(|e| format!("{stem}: re-encrypt failed ({e})"))?;
    set_600(&tmp);
    drop(guard);
    let prepared = PreparedArtifact { target: file.to_path_buf(), tmp: tmp.clone() };
    // Verify the file we are about to install, not the bytes we think we
    // wrote. Decrypt to /dev/null: we only need the exit status.
    // Verify the re-encrypted copy the same way — and against the CONTENT,
    // not /dev/null, which could only ever have told us the exit status.
    let verify_plain = dir.join(format!(".{stem}{VERIFY_INFIX}{}", std::process::id()));
    let vguard = TempPlain(verify_plain.clone());
    decrypt_and_verify(&tmp, &verify_plain, new, &stem)
        .map_err(|e| format!("{stem}: re-encrypted copy does not open with the new passphrase ({e})"))?;
    drop(vguard);
    if !checked {
        // An artifact whose name implies no known shape got the old, weaker
        // check. Better to say that than to let "rotated" imply "verified".
        eprintln!(
            "  note: {stem} has no known content signature — verified only that openssl \
             exited 0, which accepts a wrong passphrase about 1 time in 256"
        );
    }
    Ok(prepared)
}

/// Removes its path on drop. The plaintext of a backup artifact must not
/// survive an early return.
struct TempPlain(PathBuf);
impl Drop for TempPlain {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Render the plan. **Pure**, and — like [`render_audit`] — the only place
/// rotation text is built, so the no-value test covers the whole surface.
pub fn render_plan(plan: &[PlanItem], dry_run: bool) -> String {
    let mut s = String::new();
    s.push_str(if dry_run {
        "Rotation plan (--dry-run — nothing will be touched)\n\n"
    } else {
        "Rotation plan\n\n"
    });
    for p in plan {
        s.push_str(&format!(
            "  {} [{}, {}]\n",
            p.key, p.class_label, p.disposition
        ));
        if let Some(r) = &p.refusal {
            for line in r.lines() {
                s.push_str(&format!("      {line}\n"));
            }
            s.push('\n');
            continue;
        }
        s.push_str(&format!(
            "      new value:   {}\n",
            match p.source {
                ValueSource::Generated => "generated locally (token_urlsafe)",
                ValueSource::Stdin => "read from stdin (never echoed, never written to disk)",
                ValueSource::Prompt =>
                    "typed at the terminal with the echo off (never echoed, never in shell history)",
            }
        ));
        if let Some(role) = &p.db_role {
            s.push_str(&format!(
                "      apply:       ALTER ROLE \"{role}\" WITH PASSWORD, then verify a login \
                 with the new value\n"
            ));
        } else {
            s.push_str("      apply:       store only — takes effect when consumers are recreated\n");
        }
        if p.first_set && p.artifacts.is_none() {
            s.push_str("      first set:   not in the store yet — this ADDS it\n");
        }
        s.push_str(&format!("      consequence: {}\n", p.consequence));
        s.push_str(&format!(
            "      recreate:    {}\n",
            if p.consumers.is_empty() {
                "(none)".to_string()
            } else {
                p.consumers.join(", ")
            }
        ));
        // A backup passphrase's blast radius is FILES, not containers, and
        // the operator has to see the count before confirming: this is the
        // step that rewrites every backup they hold.
        if let Some(files) = &p.artifacts {
            s.push_str(&format!(
                "      artifacts:   {} file(s) in {} re-encrypted old → new, each verified \
                 before any is replaced\n",
                files.len(),
                backup_dir().display()
            ));
            if p.first_set {
                s.push_str(
                    "      first set:   not in the store yet — this CREATES it (the backup \
                     refuses to run without it)\n",
                );
            }
            if p.source == ValueSource::Generated {
                s.push_str(
                    "      handover:    the generated value is shown ONCE on the terminal and \
                     written to no file;\n                   nobody else can recover it, so \
                     store it before confirming\n",
                );
            }
        }
        // Derived children of this key are invalidated by the rotation and
        // fail LATER, in another service, with no error at rotation time.
        // Printing the re-mint here is the only place the operator sees the
        // dependency while they still have the new parent value to hand.
        for child in derived_children(&p.key) {
            if let Class::Derived { mint, .. } = child.class {
                s.push_str(&format!(
                    "      then:        re-mint {} — {}\n",
                    child.key, mint
                ));
                s.push_str(&format!(
                    "                   install with `… | noo security secrets rotate {} \
                     --set-from-stdin --yes`, then recreate {}\n",
                    child.key,
                    child.consumers.join(", ")
                ));
            }
        }
        s.push('\n');
    }
    let refused = plan.iter().filter(|p| p.refusal.is_some()).count();
    if refused > 0 {
        s.push_str(&format!(
            "{refused} of {} key(s) REFUSED — nothing will be rotated. Rotation is all-or-nothing: \
             a partial\nrun would leave the store and the running system disagreeing, which is \
             worse than not\nrotating at all.\n",
            plan.len()
        ));
    }
    s
}

fn plan_json(plan: &[PlanItem], dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "dry_run": dry_run,
        "refused": plan.iter().filter(|p| p.refusal.is_some()).count(),
        "items": plan.iter().map(|p| serde_json::json!({
            "key": p.key,
            "class": p.class_label,
            "disposition": p.disposition,
            "value_source": match p.source {
                ValueSource::Generated => "generated",
                ValueSource::Stdin => "stdin",
                ValueSource::Prompt => "prompt",
            },
            "db_role": p.db_role,
            "first_set": p.first_set,
            "artifacts": p.artifacts.as_ref().map(|f| f.iter().map(|x| x.to_string_lossy().into_owned()).collect::<Vec<_>>()),
            "consequence": p.consequence,
            "recreate": p.consumers,
            "refusal": p.refusal,
        })).collect::<Vec<_>>(),
    })
}

/// Mint any of `keys` that the store does not already have, and write it back.
///
/// Lives HERE, not in the caller, because `SecretStore` deliberately exposes
/// no accessor that returns a value — that absence is a compile-time guard on
/// this module's central invariant, and an `as_map()` for the convenience of
/// one caller would quietly remove it. So the plaintext never leaves.
///
/// Returns the keys actually minted (empty when everything was present) and
/// the backup path. MINT ONLY IF ABSENT: an existing credential is never
/// touched, because the broker deliberately never `ALTER`s an existing role,
/// so rewriting the stored password would strand it.
///
/// Refuses on a failed decrypt rather than treating it as an empty store. A
/// broken decrypt returns ZERO keys, which is indistinguishable from "no
/// secrets yet" — and writing at that point replaces every credential on the
/// install with just the new ones.
pub fn mint_missing(keys: &[&str], target: &Path) -> Result<(Vec<String>, Option<PathBuf>), String> {
    mint_where(keys, target, |store, k| !store.contains(k))
}

/// [`mint_missing`], but every key gets a NEW value whether or not it has
/// one: an explicit rotation (`noo addons rotate-secret`). Same writer and
/// round-trip proof; the previous store is kept as the backup it returns.
pub fn mint_replace(keys: &[&str], target: &Path) -> Result<(Vec<String>, Option<PathBuf>), String> {
    mint_where(keys, target, |_, _| true)
}

/// [`mint_missing`], but a BLANK value counts as missing too: for keys whose
/// empty value is simply no key (the bus-principal keys
/// L2), never for a credential an operator may have blanked on purpose.
pub fn mint_unset(keys: &[&str], target: &Path) -> Result<(Vec<String>, Option<PathBuf>), String> {
    mint_where(keys, target, |store, k| !matches!(store.state(k), State::Set))
}

fn mint_where(
    keys: &[&str],
    target: &Path,
    absent: impl Fn(&SecretStore, &str) -> bool,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let store = SecretStore::load_sops(target)?;
    let missing: Vec<String> = keys
        .iter()
        .filter(|k| absent(&store, k))
        .map(|k| (*k).to_string())
        .collect();
    if missing.is_empty() {
        return Ok((missing, None));
    }

    let mut map = store.map.clone();
    for k in &missing {
        map.insert(k.clone(), crate::commands::security_local::token_urlsafe(32));
    }
    let prepared = prepare_store(&map, target)?;
    let backup = prepared.commit(target)?;

    // Prove it round-tripped. `prepare_store` already verifies the ciphertext
    // decrypts to the same map, but re-reading the INSTALLED file is what
    // catches a bad rename or a permissions problem after the fact.
    let after = SecretStore::load_sops(target)?;
    for k in &missing {
        if !matches!(after.state(k), State::Set) {
            return Err(format!(
                "{k} is absent after the write — the store did not round-trip. \
                 The previous store is at {}.",
                backup.display()
            ));
        }
    }
    Ok((missing, Some(backup)))
}

/// Remove `keys` from the sops store at `target` and write it back.
///
/// Same writer as rotate and `mint_missing`: decrypt to memory only, drop the
/// keys, re-encrypt on a pipe, prove the sibling temp file decrypts to
/// EXACTLY the remaining key set and values, keep a timestamped encrypted
/// backup of the prior file, rename atomically. (`sops unset` is not used: it
/// edits the ciphertext in place with no key-set proof, and which sops
/// versions accept it on a dotenv store varies; the verified full write is
/// the one path every other mutation here already trusts.)
///
/// A key that is not in the store is an error, never a silent no-op, and a
/// failed decrypt is an error rather than an empty store (see `mint_missing`).
/// Returns the backup path.
pub fn remove_keys(keys: &[String], target: &Path) -> Result<PathBuf, String> {
    let store = SecretStore::load_sops(target)?;
    let mut map = store.map.clone();
    for k in keys {
        if map.remove(k).is_none() {
            return Err(format!("{k} is not in {} — nothing removed", target.display()));
        }
    }
    let prepared = prepare_store(&map, target)?;
    let backup = prepared.commit(target)?;
    let after = SecretStore::load_sops(target)?;
    for k in keys {
        if after.contains(k) {
            return Err(format!(
                "{k} is still present after the write. The previous store is at {}.",
                backup.display()
            ));
        }
    }
    if after.map.len() != map.len() {
        return Err(format!(
            "the store holds {} keys after the write, expected {}. The previous store is at {}.",
            after.map.len(),
            map.len(),
            backup.display()
        ));
    }
    Ok(backup)
}

// ── sops write path ──────────────────────────────────────────────────────

/// Encrypt a map to ciphertext, plaintext going in on a PIPE.
///
/// `--filename-override` makes sops match `.sops.yaml`'s `creation_rules`
/// against `target` rather than the literal input path `/dev/stdin` (which
/// matches nothing and fails with "no matching creation rules found").
/// `--age <recipient>` does NOT bypass that check, so the override is not
/// optional.
fn sops_encrypt(map: &BTreeMap<String, String>, target: &Path) -> Result<Vec<u8>, String> {
    // sops discovers .sops.yaml by walking UP FROM ITS WORKING DIRECTORY —
    // not from the target path. The wizard inherits the operator's shell
    // cwd (often $HOME), where no .sops.yaml exists, and the encrypt dies
    // exit 1 "no matching creation rules" (first-contact finding #7,
    // 2026-08-20: the standalone store lives under ~/.noo). Pin the cwd to
    // the store root (target's grandparent: <root>/secrets/env.sops) so
    // discovery is location-independent.
    let store_root = target.parent().and_then(|p| p.parent())
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut child = sops_command()
        .map_err(|e| e.to_string())?
        .current_dir(&store_root)
        .arg("-e")
        .arg("--filename-override")
        .arg(target)
        .args(["--input-type", "dotenv", "--output-type", "dotenv"])
        .arg("/dev/stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run sops: {e}"))?;
    {
        let mut sin = child.stdin.take().ok_or("sops stdin unavailable")?;
        crate::child_stdin::write_child_stdin(&mut sin, to_dotenv(map).as_bytes())
            .map_err(|e| format!("writing to sops: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for sops: {e}"))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!(
            "sops encrypt failed (exit {}). Check that the age key is present and that \
             .sops.yaml has a creation_rule matching {}",
            out.status.code().unwrap_or(-1),
            target.display()
        ));
    }
    Ok(out.stdout)
}

/// Write ciphertext to a sibling temp path and prove it decrypts back to
/// exactly `expected` — same key SET and same value for every key.
///
/// The key-set check is the one that matters: a re-encrypt that silently
/// DROPS keys is the documented failure mode of this store (a full replace,
/// not a merge). A dropped credential is not visible until the service that
/// needed it fails at some later restart.
///
/// The temp file is a SIBLING of the target so the final commit is a
/// same-filesystem `rename(2)` — atomic, so there is no instant at which
/// `env.sops` is truncated or partial.
fn prepare_store(
    map: &BTreeMap<String, String>,
    target: &Path,
) -> Result<PreparedStore, String> {
    let ciphertext = sops_encrypt(map, target)?;
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.rotating.{}",
        target
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "env.sops".into()),
        std::process::id()
    ));
    std::fs::write(&tmp, &ciphertext).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    set_600(&tmp);

    // Verify by decrypting the file we are actually about to install — not
    // the bytes we think we wrote.
    let back = SecretStore::load_sops(&tmp).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("prepared file does not decrypt: {e}")
    })?;
    let want: BTreeSet<&String> = map.keys().collect();
    let got: BTreeSet<&String> = back.map.keys().collect();
    if want != got {
        let dropped: Vec<&str> = want.difference(&got).map(|k| k.as_str()).collect();
        let added: Vec<&str> = got.difference(&want).map(|k| k.as_str()).collect();
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "prepared file has the WRONG KEY SET — dropped: {dropped:?}, unexpected: {added:?}. \
             Nothing was changed."
        ));
    }
    // Values, compared by digest so no value is materialized for comparison
    // in a form that could reach an error message.
    let mismatched: Vec<&str> = map
        .iter()
        .filter(|(k, v)| back.map.get(*k).map(|b| b != *v).unwrap_or(true))
        .map(|(k, _)| k.as_str())
        .collect();
    if !mismatched.is_empty() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "prepared file round-trips the wrong VALUE for {mismatched:?}. Nothing was changed."
        ));
    }
    Ok(PreparedStore { tmp })
}

/// A verified replacement file, not yet installed. Dropping without
/// [`PreparedStore::commit`] removes it — so every early-return path in
/// `secrets_rotate` cleans up without needing its own handler.
/// Merge `pairs` into the sops store (create it if absent), never dropping
/// an existing key — the documented catastrophic failure mode of this file
/// is a full replace. Used by the onboarding wizard's optional branches
/// Round-trip-verified and committed atomically like every other write.
pub fn store_upsert(pairs: &[(String, String)]) -> Result<(), String> {
    let target = crate::envfile::repo_root().join("secrets/env.sops");
    let store = SecretStore::load_sops(&target)?;
    // Same-module field access, deliberately NOT the value escape hatches:
    // the plaintext never leaves this module — it goes straight back onto
    // the sops stdin pipe.
    let mut map: BTreeMap<String, String> = store.map.clone();
    for (k, v) in pairs {
        map.insert(k.clone(), v.clone());
    }
    let prepared = prepare_store(&map, &target)?;
    prepared.commit(&target).map(|_| ())
}

/// Move every NON-credential key out of the store and into `.env` (when
/// `.env` has no value for it). The sops-init script encrypts the whole
/// `.env`, so config rode along — and a config key in the store SHADOWS
/// `.env` at every launch: `NOO_IMAGE_PREFIX` in the store pinned the old
/// registry namespace through two rolls, and `NODE_IP` in the store held
/// the pre-tailnet LAN address on the 2026-09-07 walk. Secrets only.
/// Returns the keys moved.
pub fn store_move_config_to_env(env_path: &Path) -> Result<Vec<String>, String> {
    let target = crate::envfile::repo_root().join("secrets/env.sops");
    let store = SecretStore::load_sops(&target)?;
    let mut map: BTreeMap<String, String> = store.map.clone();
    let config = config_keys_in_store(&map);
    if config.is_empty() {
        return Ok(Vec::new());
    }
    for k in &config {
        let v = map.remove(k).unwrap_or_default();
        if crate::onboard::env::read_env_key(env_path, k).is_empty() && !v.is_empty() {
            crate::onboard::env::update_env_key(env_path, k, &v).map_err(|e| format!("{k}: {e}"))?;
        }
    }
    let prepared = prepare_store(&map, &target)?;
    prepared.commit(&target)?;
    Ok(config)
}

/// Which of `keys` the sops store holds. A config key in the store SHADOWS
/// `.env` at every launch (see [`store_move_config_to_env`]), so a release
/// channel written to `.env` while the old one is pinned here would be undone
/// at the next launch. `None` = the store could not be read (not an error for
/// the caller: say so, do not guess); no store = `Some(vec![])`.
pub fn store_pins_of(keys: &[&str]) -> Option<Vec<String>> {
    let target = crate::envfile::repo_root().join("secrets/env.sops");
    if !target.exists() {
        return Some(Vec::new());
    }
    let store = SecretStore::load_sops(&target).ok()?;
    Some(pins_in(&store.map, keys))
}

fn pins_in(map: &BTreeMap<String, String>, keys: &[&str]) -> Vec<String> {
    keys.iter().filter(|k| map.contains_key(**k)).map(|k| (*k).to_string()).collect()
}

/// The store keys that are configuration, not secrets — what
/// [`store_move_config_to_env`] moves to `.env`.
///
/// "Secret" is `plaintext_env::secret_class`, the ONE definition the
/// `secrets at rest` verify row, `security scan` and the `upgrade --stack`
/// refusal judge `.env` by. This used to be `looks_like_credential` alone —
/// a name test — so a registered secret with an ordinary name
/// (`NOO_ENTITLEMENT`, on the delivery TIER1 list; `NOO_FILECRED_GOOGLE_CHAT_B64`,
/// a registry spec) was "config": `secrets tidy` moved both into plaintext
/// `.env`, and verify then failed them as plaintext secrets, its remedy
/// running tidy again (host8, 2026-10-02 08:44).
fn config_keys_in_store(map: &BTreeMap<String, String>) -> Vec<String> {
    map.keys().filter(|k| !super::plaintext_env::secret_class(k)).cloned().collect()
}

/// Drop every [`RETIRED_STORE_KEYS`] entry from the store, and blank it in
/// `.env` if it has a value there. Returns the keys that were present. A
/// missing store is not an error (nothing to drop); the `.env` side still
/// runs, since an install without sops keeps its credentials there.
pub fn store_drop_retired(env_path: &Path) -> Result<Vec<String>, String> {
    let mut dropped: Vec<String> = Vec::new();
    let target = crate::envfile::repo_root().join("secrets/env.sops");
    if target.exists() {
        let store = SecretStore::load_sops(&target)?;
        let mut map: BTreeMap<String, String> = store.map.clone();
        for (k, _) in RETIRED_STORE_KEYS {
            if map.remove(*k).is_some() {
                dropped.push((*k).to_string());
            }
        }
        if !dropped.is_empty() {
            let prepared = prepare_store(&map, &target)?;
            prepared.commit(&target)?;
        }
    }
    for (k, _) in RETIRED_STORE_KEYS {
        if !crate::onboard::env::read_env_key(env_path, k).is_empty() {
            crate::onboard::env::update_env_key(env_path, k, "").map_err(|e| format!("{k}: {e}"))?;
            if !dropped.iter().any(|d| d == k) {
                dropped.push((*k).to_string());
            }
        }
    }
    Ok(dropped)
}

/// `noo security secrets tidy` — the thinning the wizard does at sops-init,
/// for an install that predates it (the 2026-09-07 walk: `NODE_IP` and the
/// image namespace in the store shadowed .env at every launch). Also blanks
/// every secret-class value in `.env` the store already holds
/// (`plaintext_env::blank_stored`).
pub fn secrets_tidy(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    // It rewrites the encrypted store, drops retired credentials from it and
    // blanks plaintext copies in .env: confirm before the first write.
    super::confirm_prompt(
        g,
        yes,
        "Tidy the secret store? This moves config keys from env.sops to .env, drops retired credentials \
         from the store, and blanks the .env copies of secrets the store already holds",
    );
    super::plaintext_env::tidy_plaintext(g);
    let env_path = crate::envfile::repo_root().join(".env");
    let dropped = match store_drop_retired(&env_path) {
        Ok(d) => d,
        Err(e) => crate::output::fail(g.json, crate::output::ExitCode::Generic, "tidy_failed", &e, None),
    };
    if !dropped.is_empty() && !g.json {
        crate::ui::done(&format!(
            "{} retired credential(s) removed from the store: {}",
            dropped.len(),
            dropped.join(", ")
        ));
    }
    match store_move_config_to_env(&env_path) {
        Ok(moved) if moved.is_empty() => {
            if g.json { println!("{}", serde_json::json!({"moved": [], "dropped": dropped})); }
            else { crate::ui::done("store holds secrets only — nothing to move"); }
            Ok(0)
        }
        Ok(moved) => {
            if g.json { println!("{}", serde_json::json!({"moved": moved, "dropped": dropped})); }
            else {
                crate::ui::done(&format!("{} config key(s) moved out of the store into .env: {}", moved.len(), moved.join(", ")));
                crate::ui::guide(&[("noo stack restart --force", "so the containers see .env's values instead of the store's")]);
            }
            Ok(0)
        }
        Err(e) => crate::output::fail(g.json, crate::output::ExitCode::Generic, "tidy_failed", &e, None),
    }
}

/// Report `NATS_NODE_PASSWORD_*` keys that no principal on the bus uses.
///
/// `NATS_NODE_PASSWORD_HOST8` has sat in the live store since the cutover —
/// the canonical key for that node is `NATS_NODE_PASSWORD_HOST8`, and the
/// bus authorises `node-host8`. A live credential nothing consumes is a
/// credential nobody will think to rotate.
///
/// The authority is the RENDERED `users.conf`, not the gateway registry. It
/// is the file NATS actually verifies against, it can be read with the
/// gateway down, and "the gateway said nothing" is indistinguishable from
/// "there are no nodes" — which here would mean reporting every node
/// password in the fleet as orphaned and inviting the operator to delete the
/// lot. An unreadable or principal-less file says nothing at all.
///
/// Direction matters: node id → key name, never key name → node id. The
/// folding is lossy (`host8` and `host8` both give `HOST8`), so un-folding
/// a key would have to guess, and a wrong guess here reads as "this live
/// node's password is unused".
#[cfg(test)]
pub(crate) fn orphaned_node_password_findings_for_test(keys: &[&str], users_conf: &str) -> Vec<Finding> {
    let m: BTreeMap<String, String> = keys.iter().map(|k| (k.to_string(), "x".into())).collect();
    let store = SecretStore::from_map(m, PathBuf::from("/f/secrets/env.sops"), true);
    orphaned_node_password_findings(&store, users_conf)
}

fn orphaned_node_password_findings(sops: &SecretStore, users_conf: &str) -> Vec<Finding> {
    let expected: BTreeSet<String> = super::nats_users::node_users_in_conf(users_conf)
        .iter()
        .map(|id| super::nats_users::node_secret_key(id))
        .collect();
    if expected.is_empty() {
        return Vec::new(); // no principals read: say nothing rather than everything
    }
    sops.keys()
        .filter(|k| k.starts_with("NATS_NODE_PASSWORD_"))
        .filter(|k| !expected.contains(*k))
        .map(|k| Finding {
            severity: Severity::Warn,
            kind: "node-password-unused",
            key: k.clone(),
            message: format!(
                "no principal in {} uses this password — the bus authorises {}. It is a live \
                 credential nothing consumes, so nothing will prompt you to rotate it. Confirm \
                 the node is gone, then remove the key from the store: \
                 `noo security secrets remove {}`.",
                super::nats_users::USERS_CONF,
                expected
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                k,
            ),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// When each secret was last changed
// ─────────────────────────────────────────────────────────────────────────

/// A record of when each key last got a new value.
///
/// The access-review policy commits to rotating most of these
/// every ninety days. Nothing recorded when anything was rotated, so the
/// policy could not be checked by a person or a script — and the first review
/// has never happened. An unmeasurable policy is a sentence in a document.
///
/// Deliberately NOT inside the store: `rotate` verifies that the encrypted
/// key set is identical before and after, and a timestamp that lived among
/// the secrets would either break that check or hide inside it. It also holds
/// no secret values, so keeping it readable without the age key is a feature
/// — the operator can see what is overdue on a box where SOPS is broken.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RotationLog {
    /// When this ledger first existed. Every key with no entry of its own is
    /// AT LEAST this old, which is the honest floor: tracking cannot invent
    /// history it never saw.
    pub tracking_since: u64,
    pub rotated: BTreeMap<String, u64>,
}

/// Where the ledger lives, given the store. Beside it, so a store moved by
/// `NOO_SECRETS_FILE` takes its history with it.
fn rotation_log_path(store: &Path) -> PathBuf {
    store.with_file_name(ROTATION_LEDGER)
}

/// The rotation ledger's file name, beside the store. Declared ONCE: verify's
/// `secrets not in env` row allows exactly the files the CLI writes under
/// `secrets/`, and a second spelling there is how the v0.2.80 rehearsal saw
/// this file flagged as plaintext residue with a "shred it" remedy.
pub(crate) const ROTATION_LEDGER: &str = "rotations.json";

/// Mid-rotation temp files beside an artifact, `.<name><INFIX><pid>`.
/// `.rotating.` holds the re-encrypted CIPHERTEXT about to replace the
/// original; `.plain.` and `.verify.` hold PLAINTEXT for the length of one
/// function. Verify's residue check allows only the first — by these consts.
pub(crate) const ROTATING_INFIX: &str = ".rotating.";
pub(crate) const PLAIN_INFIX: &str = ".plain.";
pub(crate) const VERIFY_INFIX: &str = ".verify.";

impl RotationLog {
    /// Parse, tolerating anything. A ledger that cannot be read is an empty
    /// ledger, never an error: this is observability, and it must not be able
    /// to fail a rotation or an audit.
    pub fn parse(raw: &str) -> Self {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
            return Self::default();
        };
        let tracking_since = v.get("tracking_since").and_then(|x| x.as_u64()).unwrap_or(0);
        let rotated = v
            .get("rotated")
            .and_then(|x| x.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_u64().map(|t| (k.clone(), t)))
                    .collect()
            })
            .unwrap_or_default();
        Self { tracking_since, rotated }
    }

    pub fn render(&self) -> String {
        let rotated: serde_json::Map<String, serde_json::Value> = self
            .rotated
            .iter()
            .map(|(k, t)| (k.clone(), serde_json::json!(t)))
            .collect();
        format!(
            "{}\n",
            serde_json::json!({
                "_comment": "When each secret last got a new value. No secret values are in \
                             this file. Written by `noo security secrets rotate`.",
                "tracking_since": self.tracking_since,
                "rotated": rotated,
            })
        )
    }

    pub fn load(store: &Path) -> Self {
        std::fs::read_to_string(rotation_log_path(store))
            .map(|s| Self::parse(&s))
            .unwrap_or_default()
    }

    /// Age of `key` in days, and whether that is exact or a floor.
    ///
    /// A key with no entry returns the age of the ledger itself as a floor.
    /// Saying "unknown" instead would leave every pre-existing secret
    /// permanently exempt from the policy; a floor that grows every day
    /// eventually trips it, which is the behaviour the policy needs.
    pub fn age_days(&self, key: &str, now: u64) -> Option<(u64, bool)> {
        let (stamp, exact) = match self.rotated.get(key) {
            Some(t) => (*t, true),
            None if self.tracking_since > 0 => (self.tracking_since, false),
            None => return None,
        };
        Some((now.saturating_sub(stamp) / 86_400, exact))
    }
}

/// Record that `keys` just got new values. Best-effort, and deliberately so:
/// the store is already committed by the time this runs, and a ledger that
/// cannot be written must not turn a successful rotation into a reported
/// failure. Returns the error text for the caller to mention, not to abort on.
fn record_rotations(store: &Path, keys: &[String], now: u64) -> Result<(), String> {
    let mut log = RotationLog::load(store);
    if log.tracking_since == 0 {
        log.tracking_since = now;
    }
    for k in keys {
        log.rotated.insert(k.clone(), now);
    }
    let path = rotation_log_path(store);
    std::fs::write(&path, log.render()).map_err(|e| format!("{}: {e}", path.display()))?;
    set_600(&path);
    Ok(())
}

/// u64 view of the one clock (`host_exec::now_unix`); the age math here is unsigned.
fn now_unix() -> u64 {
    crate::host_exec::now_unix().max(0) as u64
}

/// The review interval the policy commits to.
fn max_secret_age_days() -> u64 {
    std::env::var("NOO_SECRETS_MAX_AGE_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(90)
}

/// Report secrets that are past the review interval, and the fact that
/// nothing is being tracked at all.
///
/// Impure — it reads the ledger from disk — so it is appended at the run site
/// rather than living in `audit_findings`, which stays pure over the two
/// stores.
fn secret_age_findings(store: &Path, sops: &SecretStore, now: u64) -> Vec<Finding> {
    secret_age_findings_with(&RotationLog::load(store), sops, now, max_secret_age_days())
}

fn secret_age_findings_with(
    log: &RotationLog,
    sops: &SecretStore,
    now: u64,
    max_days: u64,
) -> Vec<Finding> {
    if log.tracking_since == 0 {
        return vec![Finding {
            severity: Severity::Info,
            kind: "rotation-age-untracked",
            key: "*".to_string(),
            message: format!(
                "no rotation dates are recorded, so the {max_days}-day review interval of the \
                 access-review policy cannot be checked. The ledger starts \
                 itself on the next `noo security secrets rotate`."
            ),
        }];
    }
    let mut out = Vec::new();
    for key in sops.keys() {
        // Only keys this tool knows how to rotate. Reporting a key with no
        // rotation path as overdue would be telling the operator to do
        // something the command refuses to do.
        let Some(spec) = spec_for(key) else { continue };
        if matches!(spec.class, Class::Derived { .. }) {
            continue; // rotates with its parent; the parent is what is measured
        }
        let Some((days, exact)) = log.age_days(key, now) else {
            continue;
        };
        if days <= max_days {
            continue;
        }
        out.push(Finding {
            severity: Severity::Warn,
            kind: "rotation-overdue",
            key: key.to_string(),
            message: if exact {
                format!("last rotated {days} days ago, past the {max_days}-day review interval")
            } else {
                format!(
                    "no rotation recorded in the {days} days since tracking began, which is \
                     past the {max_days}-day review interval. It may be older still — the \
                     ledger cannot see before itself."
                )
            },
        });
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Store backups, and their bound
// ─────────────────────────────────────────────────────────────────────────

/// How many `.bak_*` copies of the store to keep.
///
/// Every commit copies the store aside before swapping the new one in, and
/// every copy is encrypted to the SAME age recipient — so an unbounded pile
/// means a rotated secret stays readable forever from a file nothing ever
/// deletes. Rotation then revokes nothing; it only changes what the live
/// store says.
///
/// The bound cannot be zero. A rotation that goes wrong is recoverable only
/// from the copy taken moments earlier, so "keep none" would trade a slow
/// leak for an unrecoverable store. Three is the same floor
/// `backup-controller.sh` uses for dumps, for the same reason.
fn store_backups_kept() -> usize {
    keep_from(std::env::var("NOO_SECRETS_KEEP_BACKUPS").ok())
}

/// The bound, decided from the raw override. Split out so the floor is
/// testable without a process-wide environment variable: these tests run in
/// parallel with every other test in the crate.
fn keep_from(raw: Option<String>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(3)
        .max(1)
}

/// The `.bak_*` siblings of `target`, newest first.
///
/// Both writers land here: `PreparedStore::commit` writes `<store>.bak_<unix>`
/// and `scripts/noo-secrets-absorb-files.sh` writes
/// `<store>.bak_absorb_<unix>`. Ordering is by mtime, with the file name as
/// the tiebreak — two copies made inside the same second are ordinary on a
/// fast box, and an arbitrary order there would make the bound itself
/// nondeterministic.
fn store_backups(target: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return Vec::new();
    };
    let prefix = format!("{}.bak_", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| {
            let mtime = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (mtime, e.path())
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    found.into_iter().map(|(_, p)| p).collect()
}

/// Delete every store backup past the newest `keep`. Returns what went.
///
/// Best-effort by design: this runs immediately after the store has been
/// installed successfully, and a backup that cannot be unlinked is not a
/// reason to report a good rotation as failed. What is left over is reported
/// by `audit` instead, so it cannot go unnoticed either.
fn prune_store_backups(target: &Path, keep: usize) -> Vec<PathBuf> {
    store_backups(target)
        .into_iter()
        .skip(keep)
        .filter(|p| std::fs::remove_file(p).is_ok())
        .collect()
}

/// Report a pile of store backups that pruning did not manage to clear.
///
/// Impure — it reads the directory — so it is appended at the run site rather
/// than living in `audit_findings`, which stays pure over the two stores.
fn store_backup_findings(target: &Path) -> Vec<Finding> {
    store_backup_findings_with(target, store_backups_kept())
}

fn store_backup_findings_with(target: &Path, keep: usize) -> Vec<Finding> {
    let found = store_backups(target);
    if found.len() <= keep {
        return Vec::new();
    }
    vec![Finding {
        severity: Severity::Warn,
        kind: "store-backups-unpruned",
        key: "*".to_string(),
        message: format!(
            "{} backup copies of the store are beside it, past the {keep} that are kept. \
             Each one is encrypted to the same age recipient as the live store, so every \
             secret ever rotated is still readable from them. Remove the extras: \
             ls -t {}.bak_* | tail -n +{} | xargs -r shred -u",
            found.len(),
            target.display(),
            keep + 1,
        ),
    }]
}

struct PreparedStore {
    tmp: PathBuf,
}

impl PreparedStore {
    /// Back up the current store, then swap in the prepared one atomically.
    fn commit(self, target: &Path) -> Result<PathBuf, String> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = target.with_extension(format!("sops.bak_{stamp}"));
        if target.exists() {
            std::fs::copy(target, &backup)
                .map_err(|e| format!("could not back up {}: {e}", target.display()))?;
            set_600(&backup);
        }
        std::fs::rename(&self.tmp, target).map_err(|e| {
            format!(
                "could not install the prepared store ({e}). The original is untouched; the \
                 prepared file is at {}",
                self.tmp.display()
            )
        })?;
        set_600(target);
        std::mem::forget(self); // renamed, nothing left to clean up
        // Only now, with the new store installed and the fresh copy safely
        // among them, is it safe to bound the pile. Pruning before the rename
        // would narrow the set of files the operator could recover from at
        // exactly the moment the rename might fail.
        prune_store_backups(target, store_backups_kept());
        Ok(backup)
    }
}

impl Drop for PreparedStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

fn set_600(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
}

// ── Postgres apply path ──────────────────────────────────────────────────

/// SQL string-literal escaping: double every `'`. Generated values are
/// base64url and contain none, but an operator-supplied `--set-from-stdin`
/// value can contain anything, and a password is not something to be
/// careless about quoting.
pub fn sql_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

/// `ALTER ROLE` inside the postgres container.
///
/// The SQL — which contains the new password — goes in on **stdin**, never
/// as an argv element. `docker exec … psql -c "ALTER ROLE … PASSWORD 'x'"`
/// would put the credential in the process table for every user on the host
/// to read, and in the shell history of whoever typed it.
///
/// `ON_ERROR_STOP=1` makes a failed statement a non-zero exit rather than a
/// warning psql prints and moves past.
pub(crate) fn psql_stdin(container: &str, superuser: &str, db: &str, sql: &str) -> Result<(), String> {
    let mut child = Command::new("docker")
        .args(["exec", "-i", container, "psql", "-v", "ON_ERROR_STOP=1"])
        .args(["-U", superuser, "-d", db, "-q", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run docker exec: {e}"))?;
    {
        let mut sin = child.stdin.take().ok_or("psql stdin unavailable")?;
        crate::child_stdin::write_child_stdin(&mut sin, sql.as_bytes())
            .map_err(|e| format!("writing SQL: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for psql: {e}"))?;
    if !out.status.success() {
        // psql echoes the failing statement on error, which for ALTER ROLE
        // contains the password — so stderr is NOT forwarded. Report the
        // status and let the operator look at the container logs, which do
        // not log statement text for a failed ALTER ROLE.
        return Err(format!(
            "psql exited {} (stderr withheld: a failed ALTER ROLE echoes the statement, \
             which contains the new password)",
            out.status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Outcome of the post-`ALTER` login check.
#[derive(Debug, PartialEq, Eq)]
pub enum Verify {
    /// A login with the new password succeeded AND a login with a wrong
    /// password was rejected — so the success actually means something.
    Verified,
    /// A deliberately WRONG password was also accepted, so this connection
    /// path does not check passwords at all and the check proves nothing.
    NotPasswordAuthenticated,
    /// The check asked for a database or role that does not exist. Not the
    /// store's fault and not the network's: the CHECK is wrong, and it is
    /// reported that way so it gets fixed rather than waited out.
    Misconfigured(String),
    /// Postgres could not be reached, or failed before authentication. Like
    /// [`Verify::NotPasswordAuthenticated`] this is "we learned nothing" — NOT
    /// "the password is wrong". It exists so `rotate` can tell a network fault
    /// from a real rejection, because it reverts the role on a real rejection
    /// and must not do that for a fault.
    Unreachable,
}

/// Outcome of a single login attempt.
///
/// `Rejected` and `Unreachable` are separated because the caller must treat
/// them oppositely: a rejection is evidence about the PASSWORD, while an
/// unreachable server is evidence about nothing at all. Collapsing them into
/// one "it failed" is what makes a verification step dangerous — `rotate`
/// reverts the role when verification fails, so a network hiccup that looked
/// like a rejection would undo a rotation that had actually succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Login {
    Accepted,
    /// The server answered and refused this password.
    Rejected,
    /// The server could not be reached, or failed before authentication.
    /// Proves nothing either way.
    Unreachable,
    /// The server answered, the password was NOT the problem, and the check
    /// itself asked for something that does not exist — a database or a role.
    /// This is the check being wrong, not the store: from 2026-09-02 to
    /// 2026-09-23 the audit dialled database `noo` (its hardcoded default)
    /// on installs whose database is `noomesh`, every role came back
    /// "unreachable", and no password was ever verified on the controller.
    /// Unreachable would hide that again; it is named so it cannot.
    Misconfigured(String),
}

/// The database the liveness check logs in to. The compose file's default
/// is `noomesh`; the CLI's own environment rarely carries `POSTGRES_DB`, so
/// `.env` is asked before the default is assumed.
pub(crate) fn postgres_db() -> String {
    if let Ok(v) = std::env::var("POSTGRES_DB") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    let env_path = crate::envfile::repo_root().join(".env");
    if let Ok(text) = std::fs::read_to_string(&env_path) {
        for line in text.lines() {
            let bare = line.trim().strip_prefix("export ").unwrap_or(line.trim());
            if let Some(v) = bare.strip_prefix("POSTGRES_DB=") {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    "noomesh".to_string()
}

/// What one `psql` attempt proved, from what it printed. Pure, so the
/// classification — which is the whole liveness check — is testable
/// against real stderr text rather than a live database.
pub(crate) fn classify_login(exit_ok: bool, stdout: &str, stderr: &str) -> Login {
    if exit_ok && stdout.trim().starts_with('1') {
        return Login::Accepted;
    }
    if stderr.contains("password authentication failed") {
        return Login::Rejected;
    }
    // Past authentication, then refused for what was asked: the store may be
    // right and the CHECK wrong. Say which.
    // The probe itself arrived without a usable client certificate (or over
    // plaintext): pg_hba refused it before judging any password, so the
    // store may be right and the CHECK is what is broken.
    for needle in [
        "does not exist",
        "no pg_hba.conf entry",
        "requires a valid client certificate",
        "pg_hba.conf rejects connection",
        "private key file",
    ] {
        if let Some(line) = stderr.lines().find(|l| l.contains(needle)) {
            let reason = line.trim().trim_start_matches("psql: error: ").to_string();
            return Login::Misconfigured(reason);
        }
    }
    Login::Unreachable
}

/// Try one login as `role`.
///
/// The password reaches `psql` through `PGPASSWORD` set INSIDE the container
/// by a shell that reads it from stdin. `docker exec -e PGPASSWORD=<value>`
/// would put the credential in the host process table for every user to read.
///
/// Classifying by stderr is safe here in a way it is NOT for the `ALTER ROLE`
/// path: psql echoes the failing *statement* on error, which is why
/// [`psql_stdin`] withholds its stderr — but this statement is a literal
/// `SELECT 1`, and an auth failure prints only
/// `FATAL: password authentication failed for user "…"`. No secret can appear
/// in it.
fn try_login(
    container: &str,
    role: &str,
    db: &str,
    password: &str,
    host: &str,
) -> Result<Login, String> {
    let mut child = Command::new("docker")
        .args(["exec", "-i", container, "sh", "-c"])
        .arg(
            // PGCONNECT_TIMEOUT bounds the connect, and `-w` forbids the
            // interactive password prompt. Without them a host that blackholes
            // packets hangs psql indefinitely — measured at >120s against an
            // unroutable address — and `audit` runs two of these per
            // db-password, so one unreachable server would hang the command
            // rather than reporting that it could not check.
            // Since 2026-09-28 pg_hba requires TLS and a cluster-CA client
            // certificate from every TCP client (docker/postgres/pg_hba.conf).
            // From inside its own container the probe presents the SERVER's
            // leaf — it chains to the same CA, and its 0600 key copy
            // (/tmp/pg-server.key, made by the compose command) is readable
            // by the `postgres` user docker exec runs as. verify-ca, not
            // verify-full: the routable address is the container's, which
            // no leaf names. The password check after the handshake is
            // unchanged — that is still what the probe is about.
            "IFS= read -r PGPASSWORD; export PGPASSWORD; \
             if [ -f /tmp/pg-server.key ]; then \
               export PGSSLMODE=verify-ca PGSSLROOTCERT=/tls/ca.crt \
                      PGSSLCERT=/tls/services/postgres/service.crt PGSSLKEY=/tmp/pg-server.key; \
             fi; \
             PGCONNECT_TIMEOUT=5 exec psql -w -h \"$2\" -U \"$0\" -d \"$1\" -tAc 'SELECT 1'",
        )
        .arg(role)
        .arg(db)
        .arg(host)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run docker exec: {e}"))?;
    {
        let mut sin = child.stdin.take().ok_or("stdin unavailable")?;
        crate::child_stdin::write_child_stdin(&mut sin, format!("{password}\n").as_bytes()).map_err(|e| format!("writing password: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for psql: {e}"))?;
    // Only the exact refusal counts as evidence about the password; a
    // missing database or role is the check's mistake and says so; anything
    // else is Unreachable, and the caller must not conclude the password is
    // wrong.
    Ok(classify_login(
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    ))
}

/// Prove the new password actually works — and prove that the proof is real.
///
/// The naive version of this check (log in with the new password; if it works,
/// declare success) is **vacuous on a default Postgres image**. `initdb`
/// writes `host all all 127.0.0.1/32 trust` into `pg_hba.conf`, and the
/// entrypoint appends its `scram-sha-256` line *after* it — so every loopback
/// connection matches `trust` first and is accepted with any password at all,
/// including no password. Verified empirically on `postgres:16-alpine` while
/// building this: a deliberately wrong password returned `1` just as happily
/// as the right one.
///
/// A verification step that can pass without verifying anything is worse than
/// no verification, because it converts "I hope this worked" into "the tool
/// confirmed it worked". So this runs a NEGATIVE control first: a login with
/// a password that cannot be correct. If that is also accepted, the connection
/// path is not password-authenticated and this reports
/// [`Verify::NotPasswordAuthenticated`] — the caller surfaces that to the
/// operator rather than claiming a confirmation it does not have.
///
/// Verification runs against a specific `host` as seen from inside the container.
///
/// The host matters more than it looks. `-h 127.0.0.1` matches the `trust` line
/// `initdb` writes into `pg_hba.conf` before the entrypoint appends its
/// `scram-sha-256` rule, so a loopback login is accepted with ANY password —
/// which is what the negative control below exists to catch. Measured on this
/// deployment 2026-08-03: every `db-password` came back
/// [`Verify::NotPasswordAuthenticated`] over loopback, i.e. the check could not
/// fail. Connecting to the container's routable address instead falls through
/// to the `host … scram-sha-256` rule and actually tests the password.
fn verify_login_via(
    container: &str,
    role: &str,
    db: &str,
    password: &str,
    host: &str,
) -> Result<Verify, String> {
    // Negative control. 32 bytes of fresh randomness — it is not the new
    // password, and it is not the old one either.
    let wrong = format!("noo-negative-control-{}", super::security_local::token_urlsafe(24));
    match try_login(container, role, db, &wrong, host)? {
        Login::Accepted => return Ok(Verify::NotPasswordAuthenticated),
        // The server never got as far as judging the password, so neither
        // this control nor the real attempt below would mean anything.
        Login::Unreachable => return Ok(Verify::Unreachable),
        Login::Misconfigured(why) => return Ok(Verify::Misconfigured(why)),
        Login::Rejected => {}
    }
    match try_login(container, role, db, password, host)? {
        Login::Accepted => return Ok(Verify::Verified),
        // Only reachable when the control was REJECTED and this was not —
        // i.e. the server is answering and refuses the password we just set.
        Login::Rejected => {}
        Login::Unreachable => return Ok(Verify::Unreachable),
        // The wrong password was rejected but the right one hit a missing
        // database: scram authenticates BEFORE the database is opened, so
        // this is the shape a wrong `POSTGRES_DB` produces every time.
        Login::Misconfigured(why) => return Ok(Verify::Misconfigured(why)),
    }
    Err(format!(
        "role \"{role}\" could NOT log in with the new password, while a wrong password was \
         correctly rejected — the ALTER did not take effect as expected"
    ))
}

/// The container's own address on a Docker network, as reachable from inside
/// it. Used to reach Postgres over a path `pg_hba` actually password-checks.
///
/// Returns `None` when the container has no network address — the caller then
/// declines to check rather than falling back to loopback, because a loopback
/// fallback would silently turn a real check into a vacuous one.
pub(crate) fn container_routable_host(name: &str) -> Option<String> {
    let out = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            name,
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// The container's `Created` stamp, or `None` when there is no such container.
/// Docker assigns a new one on recreate and never on restart, which is exactly
/// the distinction `rotate` has to prove: a restart keeps the old environment.
fn container_created(name: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["inspect", "-f", "{{.Created}}", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// What happened to one consumer across a recreate, judged by its `Created`
/// stamp before and after — never by the launcher's exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecreateVerdict {
    /// A new container: the stamp moved. The only outcome that means the
    /// consumer holds the rotated value.
    Recreated,
    /// Same container as before. The launcher reported success and this one
    /// was not touched — the earlier-change shape (an add-on in an unselected
    /// profile, left on the old secret for four days).
    Unchanged,
    /// Not present before or after: a consumer that is not part of this
    /// install (an add-on that is off). Reported, never a failure.
    NotRunning,
    /// Present before, gone after. The recreate removed it and did not bring
    /// it back — a failure, and a louder one than Unchanged.
    Vanished,
}

// ═══════════════════════════════════════════════════════════════
// `noo security service-key provision`
// ═══════════════════════════════════════════════════════════════

/// `container_created` for callers outside this module — the Created stamp is
/// the evidence a recreate actually happened (#258), and the provision verb
/// needs the same evidence a rotation does.
pub(crate) fn container_created_pub(name: &str) -> Option<String> {
    container_created(name)
}

/// Write one provisioned value into the store, atomically.
///
/// Separate from `rotate` because the value is not generated here — the
/// gateway minted it and showed it once — and because the caller must be able
/// to tell a store failure from a mint failure to decide whether to revoke.
pub(crate) fn store_provisioned(key: &str, value: &str) -> Result<(), String> {
    let target = crate::envfile::repo_root().join("secrets/env.sops");
    if !target.exists() {
        return Err(format!("{} does not exist", target.display()));
    }
    let store = SecretStore::load_sops(&target)?;
    let mut map = store.map.clone();
    map.insert(key.to_string(), value.to_string());
    let prepared = prepare_store(&map, &target)?;
    prepared.commit(&target).map(|_| ())
}

/// Which three names one consumer answers to.
///
/// A per-consumer key is spelled differently in each of the three places it
/// lives — `svc:trellion-intel` in `noo_service_keys`, `NOO_SVC_KEY_TRELLION_INTEL`
/// in the store, `noo-trellion-intel` as a container. Deriving all three from
/// one word is the whole reason the verb can be one command; getting the
/// derivation wrong quietly provisions the wrong thing, so it is pure and
/// pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionTargets {
    /// The `noo_service_keys` consumer to mint under.
    pub consumer: String,
    /// The registry secret the value is stored as.
    pub secret_key: String,
    /// Every container that must be recreated to pick it up.
    pub containers: Vec<String>,
    /// The add-on (`addons:<name>`) whose overlay declared this key; `None`
    /// for a core service key (the worker), which no overlay declares.
    pub addon: Option<String>,
    /// The overlay that declared it, for the request `provision` shows.
    pub overlay: Option<String>,
}

/// Resolve `trellion-intel` (or `NOO_SVC_KEY_TRELLION_INTEL`, `svc:…`,
/// `trellion_intel`) to its three names.
///
/// An add-on resolves through its overlay's declaration (`addon_decl`): the
/// consumer and containers are what the overlay says, and are the same values
/// its derived registry row carries — one source, so `rotate` and
/// `provision` cannot disagree about who holds the key (PR 333's drift).
/// A core key (the worker) resolves through `CORE_REGISTRY`, deriving the
/// consumer from the key name as it always has.
pub(crate) fn provision_targets(name: &str) -> Option<ProvisionTargets> {
    if let Some(d) = addon_decl(name) {
        return Some(ProvisionTargets {
            consumer: d.consumer.to_string(),
            secret_key: d.key.to_string(),
            containers: d.containers.iter().map(|c| (*c).to_string()).collect(),
            addon: Some(d.addon.to_string()),
            overlay: Some(d.overlay.to_string()),
        });
    }
    let bare = name.trim().strip_prefix("svc:").unwrap_or(name.trim());
    let upper = bare.to_ascii_uppercase().replace(['-', '.'], "_");
    let secret_key = if upper.starts_with("NOO_SVC_KEY_") {
        upper
    } else {
        format!("NOO_SVC_KEY_{upper}")
    };
    let spec = CORE_REGISTRY.iter().find(|s| s.key == secret_key)?;
    let short = secret_key
        .trim_start_matches("NOO_SVC_KEY_")
        .to_ascii_lowercase()
        .replace('_', "-");
    Some(ProvisionTargets {
        consumer: format!("svc:{short}"),
        secret_key: spec.key.to_string(),
        containers: spec.consumers.iter().map(|c| (*c).to_string()).collect(),
        addon: None,
        overlay: None,
    })
}

// ── Scoped recreate (a key change is not a stack restart) ───────────────

/// What `noomesh-restart.sh --force` must be asked to do so the holders of a
/// changed secret read it. The plan the operator is shown and the argv the
/// launcher gets are BOTH derived from this one value, so they cannot
/// disagree (2026-10-08: the plan said "Recreates noo-evolve" and the action
/// restarted 31 containers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LauncherScope {
    /// Recreate exactly these containers (`services` are their compose names).
    Scoped { containers: Vec<String>, services: Vec<String> },
    /// None of the holders exists on this box (an add-on that is off):
    /// nothing to recreate, and the launcher must not be run.
    Nothing { absent: Vec<String> },
    /// A scoped recreate would be unsafe or unanswerable; restart the stack.
    Full { reason: String },
}

/// The questions the scope decision asks of the container runtime. A trait so
/// the decision is testable without a daemon.
pub(crate) trait StackProbe {
    /// A container of this name exists (running or not).
    fn present(&self, container: &str) -> bool;
    fn running(&self, container: &str) -> bool;
    /// Compose service names this container's service `depends_on`
    /// (compose records them on the container as a label).
    fn depends_on(&self, container: &str) -> Vec<String>;
}

pub(crate) struct DockerProbe;

impl StackProbe for DockerProbe {
    fn present(&self, container: &str) -> bool {
        container_created(container).is_some()
    }
    fn running(&self, container: &str) -> bool {
        container_running(container)
    }
    fn depends_on(&self, container: &str) -> Vec<String> {
        let out = Command::new("docker")
            .args(["inspect", "-f", "{{index .Config.Labels \"com.docker.compose.depends_on\"}}", container])
            .output();
        match out {
            Ok(o) if o.status.success() => parse_depends_on(&String::from_utf8_lossy(&o.stdout)),
            _ => Vec::new(),
        }
    }
}

/// `postgres:service_healthy:false,nats:service_started:false` -> [postgres, nats]
pub(crate) fn parse_depends_on(label: &str) -> Vec<String> {
    label
        .trim()
        .split(',')
        .filter_map(|e| e.split(':').next())
        .map(str::trim)
        .filter(|n| !n.is_empty() && *n != "<no value>")
        .map(str::to_string)
        .collect()
}

/// Decide how to recreate `containers` so they read a changed secret.
///
/// Scoped when every holder that exists maps to a compose service and every
/// dependency of those services is already running (the launcher passes
/// `--no-deps`, so a dependency that is down would stay down and the consumer
/// would come up against nothing). Otherwise a full restart, with the reason.
pub(crate) fn launcher_scope(containers: &[String], prefix: &str, probe: &dyn StackProbe) -> LauncherScope {
    let present: Vec<&String> = containers.iter().filter(|c| probe.present(c)).collect();
    if present.is_empty() {
        return LauncherScope::Nothing { absent: containers.to_vec() };
    }
    let lead = format!("{prefix}-");
    let mut services: Vec<String> = Vec::new();
    for c in &present {
        let Some(svc) = c.strip_prefix(&lead) else {
            return LauncherScope::Full {
                reason: format!("{c} is not a {lead}* container, so its compose service is unknown"),
            };
        };
        if !services.iter().any(|s| s == svc) {
            services.push(svc.to_string());
        }
    }
    for c in &present {
        for dep in probe.depends_on(c) {
            if services.contains(&dep) {
                continue;
            }
            let dep_container = format!("{lead}{dep}");
            if !probe.running(&dep_container) {
                return LauncherScope::Full {
                    reason: format!("{c} depends on {dep}, which is not running, and a scoped recreate would not start it"),
                };
            }
        }
    }
    LauncherScope::Scoped {
        containers: present.into_iter().cloned().collect(),
        services,
    }
}

impl LauncherScope {
    /// The one line the plan prints.
    pub(crate) fn plan_line(&self) -> String {
        match self {
            LauncherScope::Scoped { containers, .. } => containers.join(", "),
            LauncherScope::Nothing { absent } => {
                format!("nothing — {} not present on this box", absent.join(", "))
            }
            LauncherScope::Full { reason } => format!("Restarts the stack: {reason}"),
        }
    }

    /// The launcher argv (`None` = do not run it).
    pub(crate) fn launcher_args(&self) -> Option<Vec<String>> {
        match self {
            LauncherScope::Scoped { services, .. } => {
                let mut v = vec!["--force".to_string()];
                v.extend(services.iter().cloned());
                Some(v)
            }
            LauncherScope::Nothing { .. } => None,
            LauncherScope::Full { .. } => Some(vec!["--force".to_string()]),
        }
    }
}

/// Whether a provision mints a fresh row or supersedes an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MintMode {
    /// No active key for this consumer: `POST /service-keys`.
    Issue,
    /// An active key exists: `POST /service-keys/{consumer}/rotate`, which
    /// leaves the previous one live until `retire` (#325). Re-running
    /// `provision` used to `issue` a SECOND active row beside the first —
    /// two live keys, neither superseded, and nothing for `retire` to act on.
    Rotate,
}

pub(crate) fn mint_mode(has_active_key: bool) -> MintMode {
    if has_active_key { MintMode::Rotate } else { MintMode::Issue }
}

/// The scopes a provisioned key carries: what was asked for, plus `addon`.
///
/// Without `addon` the key cannot open the exchange door, so the consumer
/// presents the long-lived key on every request instead of a ten-minute
/// token. The first key provisioned on the controller (2026-09-22) was
/// minted `chat, embeddings` and did exactly that: `last_used_at` moved, the
/// exchange never ran, and nothing said why. The door is the point of the
/// key; a key that cannot reach it is half-provisioned.
pub(crate) fn provisioned_scopes(consumer: &str, requested: &[String]) -> Vec<String> {
    let mut out: Vec<String> = if !requested.is_empty() {
        requested.to_vec()
    } else {
        default_scopes_for(consumer).iter().map(|s| (*s).to_string()).collect()
    };
    if !out.iter().any(|s| s == "addon") {
        out.insert(0, "addon".into());
    }
    out
}

/// What a CORE service key is issued with when the operator names no
/// scopes. A declared fact, not whatever an `unwrap_or` returns: the worker
/// ships in the same release as the CLI and gateway, so no overlay declares
/// it. Add-on grants come from each overlay's
/// `x-noo-addon` (`ADDON_DECLS`).
pub(crate) const CORE_DEFAULT_SCOPES: &[(&str, &[&str])] = &[("svc:worker", &["chat", "embeddings"])];

/// The grant a consumer asks for by default: its overlay's declaration, else
/// its core row, else the inference pair — never a control scope, which only
/// a declaration or an explicit `--scopes` can ask for.
pub(crate) fn default_scopes_for(consumer: &str) -> &'static [&'static str] {
    if let Some(d) = addon_decls().into_iter().find(|d| d.consumer == consumer) {
        return d.scopes;
    }
    CORE_DEFAULT_SCOPES
        .iter()
        .find(|(c, _)| *c == consumer)
        .map(|(_, s)| *s)
        .unwrap_or(&["chat", "embeddings"])
}

/// Scope words that are ONE grant under two spellings while a config section
/// is renamed. The gateway
/// opens the same writes for either (`auth::control_scope_allows`), so a key
/// holding one satisfies a declaration asking for the other. Removed with the
/// old section name in the release after 0.6.0.
pub(crate) const EQUIVALENT_SCOPES: &[(&str, &str)] = &[("config:video_memory", "config:recall_memory")];

/// Does `has` carry `wanted`, directly or under its equivalent spelling?
pub(crate) fn scope_held(has: &[String], wanted: &str) -> bool {
    has.iter().any(|h| {
        h == wanted
            || EQUIVALENT_SCOPES.iter().any(|(a, b)| (h == a && wanted == *b) || (h == b && wanted == *a))
    })
}

/// What a key has that its declaration no longer asks for, and what the
/// declaration asks for that the key lacks: `(added, removed)` going from
/// `current` to `wanted`. `addon` is compared like any other word.
pub(crate) fn scope_diff(current: &[String], wanted: &[String]) -> (Vec<String>, Vec<String>) {
    let added = wanted.iter().filter(|w| !current.contains(w)).cloned().collect();
    let removed = current.iter().filter(|c| !wanted.contains(c)).cloned().collect();
    (added, removed)
}

/// What one scope word opens, according to the gateway's own listing
/// (`GET /api/security/service-keys/scopes`). `None` means the issuer would
/// REFUSE the word — `provision` stops before minting and says which overlay
/// asked for it, instead of letting the mint's 400 speak after the fact.
pub(crate) fn scope_opens_from(vocab: &serde_json::Value, scope: &str) -> Option<Vec<String>> {
    for k in ["plain", "control", "operator_only"] {
        if let Some(row) = vocab[k].as_array().and_then(|a| a.iter().find(|r| r["scope"] == scope)) {
            let opens = row["opens"].as_array().map(|o| {
                o.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
            });
            return Some(opens.unwrap_or_default());
        }
    }
    let prefix = vocab["config"]["prefix"].as_str().unwrap_or("config:");
    let section = scope.strip_prefix(prefix)?;
    let gated = vocab["config"]["gated_sections"].as_array().is_some_and(|g| g.iter().any(|x| x == section));
    let valid = !section.is_empty()
        && section.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    (valid && !gated).then(|| vec![format!("PUT /api/config/{section}")])
}

/// The newest active, non-superseded key row for `consumer`: the one in use.
pub(crate) fn current_key<'a>(keys: &'a serde_json::Value, consumer: &str) -> Option<&'a serde_json::Value> {
    keys["keys"].as_array()?.iter().rev().find(|k| {
        k["consumer"].as_str() == Some(consumer)
            && k["active"].as_bool().unwrap_or(false)
            && k["superseded_at"].is_null()
    })
}

/// What `provision` shows before minting: who is
/// asking, where it was declared, every word with the route it opens, and on
/// a rotate what changes against the key in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionRequest {
    /// `(scope, routes it opens)`; routes empty when the gateway could not
    /// say (an older gateway without the listing).
    pub rows: Vec<(String, Vec<String>)>,
    /// Words the gateway's listing says it would refuse.
    pub refused: Vec<String>,
    /// What the declaration (or the core default) asks for, before `addon`.
    pub declared: Vec<String>,
    /// `--scopes` replaced the declared request.
    pub overridden: bool,
    /// On a rotate: `(added, removed)` against the current key's scopes.
    pub diff: Option<(Vec<String>, Vec<String>)>,
}

pub(crate) fn provision_request(
    consumer: &str,
    requested: &[String],
    vocab: Option<&serde_json::Value>,
    current: Option<&serde_json::Value>,
) -> ProvisionRequest {
    let scopes = provisioned_scopes(consumer, requested);
    let mut rows = Vec::new();
    let mut refused = Vec::new();
    for s in &scopes {
        match vocab.map(|v| scope_opens_from(v, s)) {
            Some(Some(opens)) => rows.push((s.clone(), opens)),
            Some(None) => {
                refused.push(s.clone());
                rows.push((s.clone(), Vec::new()));
            }
            None => rows.push((s.clone(), Vec::new())),
        }
    }
    let diff = current.map(|k| {
        let has: Vec<String> = k["scopes"].as_array().map(|a| {
            a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
        }).unwrap_or_default();
        scope_diff(&has, &scopes)
    });
    ProvisionRequest {
        rows,
        refused,
        declared: default_scopes_for(consumer).iter().map(|s| (*s).to_string()).collect(),
        overridden: !requested.is_empty(),
        diff,
    }
}

/// The on-disk overlay's `x-noo-addon.scopes`, when it differs from what this
/// binary embeds. The embedded copy is what `provision` asks for — a stale or
/// hand-edited `~/.noo` must not widen a grant — but a difference means the
/// deploy slice and the CLI are from different releases, which the operator
/// should hear about.
pub(crate) fn on_disk_scopes_differ(overlay_text: &str, embedded: &[&str]) -> Option<Vec<String>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(overlay_text).ok()?;
    let on_disk: Vec<String> = doc.get("x-noo-addon")?.get("scopes")?.as_sequence()?
        .iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    (on_disk.iter().map(String::as_str).ne(embedded.iter().copied())).then_some(on_disk)
}

/// Has the CURRENT key for `consumer` been presented?
///
/// After a rotation there are two active rows: the superseded one, which has
/// been in use for days, and the new one, which has not. "any active row
/// with a last_used_at" is satisfied by the OLD one — so a rotation whose
/// new key nothing ever presented would read as PRESENTED, retire would be
/// asked, and the verb would report a success the consumer never delivered.
/// Only the active, non-superseded row counts, and only its own stamp.
pub(crate) fn proven_in_use(keys: &[serde_json::Value], consumer: &str) -> bool {
    keys.iter().any(|k| {
        k["consumer"].as_str() == Some(consumer)
            && k["active"].as_bool().unwrap_or(false)
            && k["superseded_at"].is_null()
            && k["last_used_at"].is_string()
    })
}

/// What a provision actually achieved.
///
/// Four outcomes because there are four ways for the sequence to stop, and
/// three of them look like success if you only check the step you just ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvisionOutcome {
    /// Minted, stored, recreated, and the consumer has PRESENTED the key.
    /// The only outcome that means the credential is live.
    InUse,
    /// Installed correctly, but the consumer has not called within the wait.
    /// Not a failure of the install and NOT a success: a key that is stored
    /// but never presented is indistinguishable from no key at all.
    InstalledNotYetUsed,
    /// The mint succeeded and the store did not. A key row now exists that no
    /// container holds and nobody has written down — the raw value is shown
    /// once. It must be revoked before returning, or it sits in
    /// `service-key list` forever as a row whose `last_used_at` is `never`,
    /// which looks exactly like the outcome above.
    MintedThenRevoked,
    /// Stored, but a container did not come back on the new value. Safe — the
    /// consumer keeps its fallback — but not success: the next reader of
    /// `secrets audit` sees a stored key and assumes it is live.
    StoredNotRecreated,
    /// A ROTATION minted a new key and the store failed. Unlike a fresh issue
    /// this cannot be undone by revoking: `/revoke` takes every active key
    /// for the consumer, the previous one included, and `/retire` takes the
    /// superseded one — the previous one again. So the new row stays active
    /// and unused while the previous keeps working, and the honest remedy is
    /// to run `provision` again, which supersedes both and retires both.
    MintedNotStored,
}

impl ProvisionOutcome {
    /// Only one of the four is success. Stated as a method so a caller cannot
    /// accidentally treat three-of-four as "well, mostly worked".
    pub(crate) fn is_success(&self) -> bool {
        matches!(self, ProvisionOutcome::InUse)
    }

    /// The process exit: 0 for `InUse` and for `InstalledNotYetUsed` (an idle
    /// consumer is not a failed command; the `!` note still says it has not
    /// presented the key), 1 for every real failure. `is_success` stays
    /// strict - it gates retiring the old key on a rotation.
    pub(crate) fn exits_zero(&self) -> bool {
        matches!(self, ProvisionOutcome::InUse | ProvisionOutcome::InstalledNotYetUsed)
    }
}

/// The decision, pure so every branch can be pinned without a gateway.
///
/// `stored` and `recreated` are what the two write steps reported; `used` is
/// whether `last_used_at` moved after the recreate. The order of the checks
/// is the order the steps run, so the FIRST thing that went wrong is what
/// gets reported — a later success cannot paper over an earlier failure.
pub(crate) fn classify_provision(
    mode: MintMode,
    stored: bool,
    recreated: bool,
    used: bool,
) -> ProvisionOutcome {
    if !stored {
        return match mode {
            MintMode::Issue => ProvisionOutcome::MintedThenRevoked,
            MintMode::Rotate => ProvisionOutcome::MintedNotStored,
        };
    }
    if !recreated {
        return ProvisionOutcome::StoredNotRecreated;
    }
    if !used {
        return ProvisionOutcome::InstalledNotYetUsed;
    }
    ProvisionOutcome::InUse
}

/// Judge every named consumer. Pure, so the decision is testable without a
/// daemon; the two maps come from [`container_created`] taken either side of
/// the launcher run.
pub(crate) fn recreate_verdicts(
    consumers: &[String],
    before: &BTreeMap<String, Option<String>>,
    after: &BTreeMap<String, Option<String>>,
) -> Vec<(String, RecreateVerdict)> {
    consumers
        .iter()
        .map(|c| {
            let b = before.get(c).cloned().flatten();
            let a = after.get(c).cloned().flatten();
            let v = match (b, a) {
                (None, None) => RecreateVerdict::NotRunning,
                (Some(_), None) => RecreateVerdict::Vanished,
                (None, Some(_)) => RecreateVerdict::Recreated,
                (Some(x), Some(y)) if x != y => RecreateVerdict::Recreated,
                (Some(_), Some(_)) => RecreateVerdict::Unchanged,
            };
            (c.clone(), v)
        })
        .collect()
}

pub(crate) fn container_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

// ── The command ──────────────────────────────────────────────────────────

/// `noo security secrets rotate <KEY>… [--all-generated] [--dry-run] [--yes]
///  [--set-from-stdin] [--restart] [--json] [--sops-file P]
///  [--pg-container C] [--pg-db D] [--pg-superuser U]`
pub fn secrets_rotate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut keys: Vec<String> = Vec::new();
    let mut all_generated = false;
    let mut dry_run = false;
    let mut yes = false;
    let mut from_stdin = false;
    let mut prompt = false;
    let mut restart = false;
    let mut allow_stdout = false;
    let mut sops_path: Option<PathBuf> = None;
    let mut pg_container = crate::envfile::container("postgres");
    let mut pg_db: Option<String> = None;
    let mut pg_superuser: Option<String> = None;

    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--all-generated" => all_generated = true,
            "--dry-run" | "-n" => dry_run = true,
            "--yes" | "-y" => yes = true,
            "--set-from-stdin" => from_stdin = true,
            "--prompt" => prompt = true,
            "--restart" => restart = true,
            "--stdout" => allow_stdout = true,
            "--sops-file" => sops_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            "--pg-container" => pg_container = iter.next().ok_or(Unhandled)?.clone(),
            "--pg-db" => pg_db = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--pg-superuser" => pg_superuser = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => keys.push(t.to_string()),
        }
    }

    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    envfile::ensure_repo_env();
    let pg_superuser =
        pg_superuser.unwrap_or_else(|| std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into()));
    let pg_db = pg_db.unwrap_or_else(postgres_db);

    if all_generated {
        for k in all_generated_keys() {
            if !keys.iter().any(|x| x == k) {
                keys.push(k.to_string());
            }
        }
    }
    if keys.is_empty() {
        fail(
            g.json,
            ExitCode::Usage,
            "no_keys",
            "no keys given",
            Some("pass one or more KEY names, or --all-generated. \
                  `noo security secrets audit` lists every key and its class."),
        );
    }
    if prompt && from_stdin {
        fail(
            g.json,
            ExitCode::Usage,
            "one_input_at_a_time",
            "--prompt and --set-from-stdin both supply the value; pass one",
            Some("--prompt types it at the terminal with the echo off; \
                  --set-from-stdin reads it from a pipe"),
        );
    }
    // --prompt is the interactive spelling of "I will supply this value", so
    // it sets the same flag the rest of the command already understands.
    if prompt {
        from_stdin = true;
    }
    if from_stdin && keys.len() != 1 {
        fail(
            g.json,
            ExitCode::Usage,
            "stdin_needs_one_key",
            "supplying a value takes exactly one KEY",
            Some("one value is read per run; rotate provider-issued keys one at a time"),
        );
    }

    let sops = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "sops_decrypt_failed", &e, None),
    };
    if !sops.existed {
        fail(
            g.json,
            ExitCode::Generic,
            "no_store",
            &format!("no secret store at {}", sops_path.display()),
            Some("run scripts/noo-secrets-sops-init.sh first"),
        );
    }

    // Both flags mean "the operator supplies this value"; they differ only in
    // WHERE it is read from, so everything downstream treats them alike.
    let supplied_key = if from_stdin { Some(keys[0].as_str()) } else { None };
    let supplied_source =
        if prompt { ValueSource::Prompt } else { ValueSource::Stdin };
    let plan = build_plan(&keys, &sops, supplied_key, supplied_source, &pg_superuser);

    if g.json {
        println!("{}", plan_json(&plan, dry_run));
    } else {
        print!("{}", render_plan(&plan, dry_run));
    }
    // Refusals abort BEFORE anything is touched — including the other keys in
    // the same invocation. All-or-nothing is the point.
    if plan.iter().any(|p| p.refusal.is_some()) {
        return Ok(1);
    }
    // The image floor, checked BEFORE any ALTER ROLE / CONFIG SET / store
    // write: the recreate that makes a rotation real is refused below
    // `x-noo-secrets-floor` (noomesh-restart.sh), and a rotation whose
    // recreate cannot run leaves the database, redis and the store on the
    // new value while every container holds the old one.
    if let Some((why, floor)) = super::upgrade::install_secrets_floor_refusal() {
        fail(g.json, ExitCode::Generic, "below_secrets_floor",
            &format!("refusing to rotate: {why}"),
            Some(&super::upgrade::secrets_floor_remedy(&floor)));
    }
    if dry_run {
        return Ok(0);
    }

    let targets: Vec<String> = plan.iter().map(|p| p.key.clone()).collect();
    super::confirm_destructive(g, yes, "Rotate", &format!("{} secret(s): {}", targets.len(), targets.join(", ")));

    // ── Phase 1: mint the new values (memory only) ──
    if !g.json {
        println!("{}", ui::phase("prepare"));
    }
    let mut new_values: BTreeMap<String, String> = BTreeMap::new();
    for p in &plan {
        let v = match p.source {
            ValueSource::Stdin => read_secret_from_stdin(g)?,
            ValueSource::Prompt => read_secret_from_prompt(g, &p.key)?,
            ValueSource::Generated => {
                let n = spec_for(&p.key).map(|s| s.gen_bytes).unwrap_or(32);
                super::security_local::token_urlsafe(n)
            }
        };
        if v.trim().is_empty() {
            fail(
                g.json,
                ExitCode::Generic,
                "empty_value",
                &format!("refusing to set {} to an empty value", p.key),
                Some("a present-but-blank secret fails silently at runtime — see the \
                      `blank-value` finding in `noo security secrets audit`"),
            );
        }
        new_values.insert(p.key.clone(), v);
    }

    // ── Phase 1b: the two backup passphrases must DIFFER ──
    //
    // `backup-controller.sh` refuses to run when they are equal, because
    // NOO_BACKUP_PASSPHRASE lives in the store and the store is opened by the
    // age key — so if the same value also protected the age-key backup,
    // opening that backup would require the key it contains. Catch it here
    // rather than at the next scheduled backup, six hours later, as an alert.
    //
    // Generated values collide with probability zero; `--set-from-stdin` is
    // the real path, and it is the path an operator takes while copying
    // values between panes of a password manager.
    {
        if backup_passphrases_would_collide(&new_values, &sops.map) {
            fail(
                g.json,
                ExitCode::Generic,
                "backup_passphrases_equal",
                "NOO_BACKUP_PASSPHRASE and NOO_AGE_BACKUP_PASSPHRASE would end up EQUAL",
                Some("they must be independent or disaster recovery is circular: the pg                       passphrase lives in the store, and the store is opened by the age key                       that the age-key backup contains. Nothing was changed."),
            );
        }
    }

    // ── Phase 1c: hand a GENERATED backup passphrase to the operator ──
    //
    // These two secrets have no consumer on this box (see
    // `secrets_reveal::ALLOW_LIST`): they exist so a PERSON can open a backup
    // on a DIFFERENT machine, months from now. So a generated value that does
    // not reach a human has not been rotated — it has been destroyed, along
    // with access to every artifact this run is about to re-encrypt.
    //
    // Same guard as `noo security secrets reveal`, deliberately: terminal
    // only, no --json override, audited before it is printed. It runs BEFORE
    // anything is prepared, so a refusal changes nothing.
    let reveal_needed: Vec<&PlanItem> = plan
        .iter()
        .filter(|p| p.artifacts.is_some() && p.source == ValueSource::Generated)
        .collect();
    if !reveal_needed.is_empty() {
        use std::io::IsTerminal as _;
        match super::secrets_reveal::reveal_guard(
            std::io::stdout().is_terminal(),
            allow_stdout,
            g.json,
        ) {
            super::secrets_reveal::Guard::Refuse(why) => {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "reveal_refused",
                    why,
                    Some("a generated backup passphrase has to reach you or the backups it                           re-encrypts are lost, so this cannot proceed silently. Run it from a                           terminal, or pass --set-from-stdin with a value you already hold.                           Nothing was changed."),
                );
            }
            super::secrets_reveal::Guard::Show => {
                for p in &reveal_needed {
                    let v = &new_values[&p.key];
                    if let Err(e) = super::secrets_reveal::hand_to_operator(&root, &p.key, v) {
                        fail(
                            g.json,
                            ExitCode::Generic,
                            "reveal_aborted",
                            &e,
                            Some("nothing was changed"),
                        );
                    }
                }
            }
        }
    }

    // ── Phase 2: prepare the replacement store, original untouched ──
    let mut merged = sops.map.clone();
    for (k, v) in &new_values {
        merged.insert(k.clone(), v.clone());
    }
    let prepared = match prepare_store(&merged, &sops_path) {
        Ok(p) => p,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "prepare_failed",
            &e,
            Some("the store was not modified"),
        ),
    };
    report(g, "prepared", "replacement store encrypted and decrypt-verified (not yet installed)");

    // ── Phase 2b: re-encrypt the backup artifacts, originals untouched ──
    //
    // Every matching file is decrypted with the CURRENT passphrase and
    // re-encrypted to the new one as a sibling temp, and each temp is proved
    // to open with the new value. Nothing is installed until the store is,
    // and if ANY file fails the whole run aborts with every original intact
    // and still opening with the passphrase the store still holds.
    //
    // This is the capability that used to justify pointing at
    // `scripts/noo-backup-rotate-passphrase.sh`. Changing the value without
    // it would leave every existing backup locked to a passphrase that is no
    // longer recorded anywhere — which is not a rotation, it is a deletion.
    let mut prepared_artifacts: Vec<PreparedArtifact> = Vec::new();
    for p in plan.iter().filter(|p| p.artifacts.is_some()) {
        let files = p.artifacts.as_ref().unwrap();
        if files.is_empty() {
            report(
                g,
                "prepared",
                &format!(
                    "{}: no existing artifacts in {} — nothing to re-encrypt",
                    p.key,
                    backup_dir().display()
                ),
            );
            continue;
        }
        // Re-encrypting needs the OLD value. On a first set there is none,
        // and there must also be no artifacts — otherwise those artifacts
        // are locked to a passphrase this box has no record of, and only the
        // operator can say what it was.
        let old_value = match sops.map.get(&p.key) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                drop(prepared_artifacts);
                drop(prepared);
                fail(
                    g.json,
                    ExitCode::Generic,
                    "artifacts_without_passphrase",
                    &format!(
                        "{} existing artifact(s) match {} but {} is not in the store, so they                          cannot be re-encrypted",
                        files.len(),
                        p.key,
                        p.key
                    ),
                    Some("install the passphrase those files were encrypted with first                           (`<value> | noo security secrets rotate <KEY> --set-from-stdin`), or                           move them aside if it is genuinely lost. Nothing was changed."),
                );
            }
        };
        let newv = &new_values[&p.key];
        for f in files {
            match prepare_artifact(f, &old_value, newv) {
                Ok(pa) => prepared_artifacts.push(pa),
                Err(e) => {
                    drop(prepared_artifacts);
                    drop(prepared);
                    fail(
                        g.json,
                        ExitCode::Generic,
                        "artifact_reencrypt_failed",
                        &e,
                        Some("no file was replaced: every original still opens with the                               passphrase the store still holds. Fix or move aside the failing                               file and re-run."),
                    );
                }
            }
        }
        report(
            g,
            "prepared",
            &format!("{}: {} artifact(s) re-encrypted and verified (not yet installed)", p.key, files.len()),
        );
    }

    // ── Phase 3: apply datastore-side consequences, revertibly ──
    if !g.json && plan.iter().any(|p| p.db_role.is_some()) {
        println!("{}", ui::phase("apply"));
    }
    let db_items: Vec<&PlanItem> = plan.iter().filter(|p| p.db_role.is_some()).collect();
    let mut altered: Vec<(&str, &str)> = Vec::new(); // (role, OLD value) for revert
    // Roles whose new password was set but could NOT be independently proven
    // (see verify_login). Surfaced in the final report so "rotated" is never
    // silently conflated with "confirmed working".
    let mut unverified: Vec<String> = Vec::new();
    if !db_items.is_empty() {
        if !container_running(&pg_container) {
            drop(prepared);
            fail(
                g.json,
                ExitCode::Generic,
                "postgres_down",
                &format!("{pg_container} is not running — cannot ALTER ROLE"),
                Some("start it first (`noo stack start`); the store was not modified"),
            );
        }
        for p in &db_items {
            let role = p.db_role.as_deref().unwrap();
            let newv = &new_values[&p.key];
            let sql = format!("ALTER ROLE \"{role}\" WITH PASSWORD {};\n", sql_quote(newv));
            if let Err(e) = psql_stdin(&pg_container, &pg_superuser, &pg_db, &sql) {
                revert_roles(&altered, &pg_container, &pg_superuser, &pg_db);
                drop(prepared);
                fail(
                    g.json,
                    ExitCode::Generic,
                    "alter_role_failed",
                    &format!("ALTER ROLE \"{role}\" failed: {e}"),
                    Some("any earlier role in this run was reverted; the store was not modified"),
                );
            }
            // Verify over the container's routable address, not loopback.
            // `pg_hba` trusts 127.0.0.1, so the loopback form accepted ANY
            // password and this step reported "NOT VERIFIED" on every rotation
            // it has ever run here — a verification that could not fail.
            // Falling back to loopback when there is no routable address keeps
            // the old (honest, useless) answer rather than inventing one.
            let verify_host =
                container_routable_host(&pg_container).unwrap_or_else(|| "127.0.0.1".to_string());
            match verify_login_via(&pg_container, role, &pg_db, newv, &verify_host) {
                Ok(Verify::Verified) => report(
                    g,
                    "applied",
                    &format!(
                        "ALTER ROLE \"{role}\" — login with the new password verified \
                         (wrong password correctly rejected)"
                    ),
                ),
                // Not a failure: the ALTER did run. But say plainly that the
                // check proved nothing, instead of implying it did.
                Ok(Verify::NotPasswordAuthenticated) => {
                    unverified.push(role.to_string());
                    report(
                        g,
                        "applied",
                        &format!(
                            "ALTER ROLE \"{role}\" — NOT VERIFIED: this connection path accepts \
                             any password (a `trust` rule in pg_hba on this path), so a login test proves \
                             nothing here"
                        ),
                    )
                }
                // Deliberately NOT a revert. The server never judged the
                // password, so this is no evidence the ALTER failed — and
                // reverting on it would undo a good rotation because of a
                // network fault, leaving the store and the database disagreeing
                // in the opposite direction. That is exactly the half-applied
                // state this command exists to avoid.
                Ok(Verify::Unreachable) => {
                    unverified.push(role.to_string());
                    report(
                        g,
                        "applied",
                        &format!(
                            "ALTER ROLE \"{role}\" — NOT VERIFIED: could not reach Postgres at \
                             {verify_host} to test the login. The ALTER itself succeeded and has \
                             NOT been reverted; confirm with `noo security secrets audit`"
                        ),
                    )
                }
                Ok(Verify::Misconfigured(why)) => {
                    unverified.push(role.to_string());
                    report(
                        g,
                        "applied",
                        &format!(
                            "ALTER ROLE \"{role}\" — NOT VERIFIED: the login test asked for \
                             something that does not exist ({why}); set POSTGRES_DB in .env. The \
                             ALTER itself succeeded and has NOT been reverted"
                        ),
                    )
                }
                Err(e) => {
                    revert_roles(&altered, &pg_container, &pg_superuser, &pg_db);
                    // Revert this one too — it was changed but does not work.
                    if let Some(old) = sops.map.get(&p.key) {
                        let sql =
                            format!("ALTER ROLE \"{role}\" WITH PASSWORD {};\n", sql_quote(old));
                        let _ = psql_stdin(&pg_container, &pg_superuser, &pg_db, &sql);
                    }
                    drop(prepared);
                    fail(
                        g.json,
                        ExitCode::Generic,
                        "verify_failed",
                        &format!("new password for \"{role}\" does not work: {e}"),
                        Some("every role in this run was reverted; the store was not modified"),
                    );
                }
            }
            altered.push((
                p.db_role.as_deref().unwrap(),
                sops.map.get(&p.key).map(String::as_str).unwrap_or(""),
            ));
        }
    }

    // ── Phase 4: commit — one atomic rename ──
    if !g.json {
        println!("{}", ui::phase("commit"));
    }
    let backup = match prepared.commit(&sops_path) {
        Ok(b) => b,
        Err(e) => {
            revert_roles(&altered, &pg_container, &pg_superuser, &pg_db);
            fail(
                g.json,
                ExitCode::Generic,
                "commit_failed",
                &e,
                Some("every role change in this run was reverted"),
            );
        }
    };

    // The store is installed, so these keys have new values as of now. Record
    // it — the ninety-day interval of the access-review policy has never been
    // measurable because nothing ever wrote this down. Best-effort on
    // purpose: the rotation already happened, and a ledger that cannot be
    // written is a reporting problem, not a reason to call a good rotation
    // failed. Say so rather than swallowing it.
    // `new_values` rather than `plan`, because it is exactly the set whose
    // ciphertext this commit replaced.
    let rotated_keys: Vec<String> = new_values.keys().cloned().collect();
    if let Err(e) = record_rotations(&sops_path, &rotated_keys, now_unix()) {
        report(
            g,
            "committed",
            &format!(
                "the rotation SUCCEEDED, but its date could not be recorded ({e}). \
                 `noo security secrets audit` will keep reporting these keys by their \
                 previous age."
            ),
        );
    }

    // ── Phase 4b: install the re-encrypted artifacts ──
    //
    // AFTER the store, deliberately. The store is the only record of the
    // current passphrase, so if the two cannot both be installed, the
    // survivable order is "store new, files old": the operator can re-run,
    // and the previous store is beside it as `.bak_<stamp>`. The other order
    // leaves files openable only by a value held in one person's memory.
    //
    // Each rename is of a file already decrypt-verified, so the realistic
    // failures here are a full disk or a permissions change mid-run. Say
    // exactly what to do if one happens, because a half-installed set is the
    // one state this command cannot clean up by itself.
    let artifact_count = prepared_artifacts.len();
    for (installed, pa) in prepared_artifacts.into_iter().enumerate() {
        let target = pa.target.clone();
        if let Err(e) = pa.commit() {
            ui::close_failed(
                &format!(
                    "the store IS rotated, but only {installed} of {artifact_count} backup files                      were replaced ({e})"
                ),
                None,
            );
            println!(
                "{}",
                ui::note(&format!(
                    "re-run this command with --set-from-stdin and the NEW passphrase to finish                      the remaining files; they still open with the OLD one, which is in                      {}.bak_* next to the store. Stopped at {}",
                    sops_path.display(),
                    target.display()
                ))
            );
            return Ok(1);
        }
    }
    if artifact_count > 0 {
        report(g, "commit", &format!("{artifact_count} backup file(s) re-encrypted in place"));
    }

    // ── Phase 5: report. Values are gone; only names, lengths, digests. ──
    let mut consumers: BTreeSet<String> = BTreeSet::new();
    for p in &plan {
        consumers.extend(p.consumers.iter().cloned());
    }
    let consumers: Vec<String> = consumers.into_iter().collect();

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "rotated": plan.iter().map(|p| serde_json::json!({
                    "key": p.key,
                    "class": p.class_label,
                    "length": new_values[&p.key].len(),
                    "sha256_8": sha8_of(&new_values[&p.key]),
                    "db_role": p.db_role,
                })).collect::<Vec<_>>(),
                "store": sops_path.to_string_lossy(),
                "backup": backup.to_string_lossy(),
                "recreate_required": consumers,
                "restarted": restart,
                "unverified_roles": unverified,
            })
        );
    } else {
        for p in &plan {
            println!(
                "{}",
                ui::sub(&format!(
                    "{} {:<28} {}",
                    ui::glyph(Glyph::Ok),
                    p.key,
                    ui::muted(&format!("len {:>3}  sha256 {}", new_values[&p.key].len(), sha8_of(&new_values[&p.key])))
                ))
            );
        }
        ui::close_done(&format!("rotated {} key(s)  {}", plan.len(), ui::muted("values not shown; verify with noo security secrets audit")));
        print!("{}", ui::kv(&[("store", sops_path.display().to_string()), ("backup", backup.display().to_string())]));
        if !unverified.is_empty() {
            ui::close_warned(&format!("not independently verified: {}", unverified.join(", ")));
            println!("{}", ui::note("the ALTER ROLE ran, but this Postgres accepts any password over loopback (a `trust` line in pg_hba.conf precedes the scram one), so the login test proves nothing; confirm from a real client path before trusting it"));
        }
        if let Some(notice) = recreate_notice(&consumers) {
            ui::close_warned(&notice);
        }
        if !restart {
            if consumers.is_empty() {
                ui::guide(&[("noo security secrets audit", "confirms store, gateway env and Postgres roles agree")]);
            } else {
                ui::guide(&[
                    ("noo stack restart --force", "RECREATES the consumers above with the new values (sources scripts/lib-secrets.sh so the new store is decrypted first). Without --force this is `docker compose restart`, which keeps the old environment — the line above says so, and this used to name it anyway"),
                    ("noo security secrets audit", "confirms store, gateway env and Postgres roles agree"),
                ]);
            }
        }
    }

    if restart {
        if !g.json {
            println!("{}", ui::phase("restart"));
        }
        let script = root.join("scripts/noomesh-restart.sh");
        // --force, because the whole point is that the containers are holding
        // a value that changed. Without it the script runs `docker compose
        // restart`, which keeps the old environment — and this path then
        // printed "stack recreated with the new values", which was a claim
        // about something that had not happened.
        //
        // Cost, live: a rotated Telegram token left the gateway on the OLD
        // value after a restart the tool itself recommended. The old token had
        // been revoked at the provider, so the channel stayed down and the
        // symptom was a 401 that reads as "you typed it wrong"
        // (2026-09-13). Proven by digest: the container's value only changed
        // after --force.
        report(g, "restart", &format!("running {} --force", script.display()));
        // The launcher's exit status says the launcher ran. It does not say
        // every consumer was recreated: `compose up --force-recreate` skips a
        // service in a profile it was not given, exits 0, and the consumer
        // keeps the old value. That is a real failure mode — four days of silent
        // 401s from an add-on after a rotation this path reported as
        // "recreated with the new values". So the verdict is taken from each
        // consumer's `Created` stamp, before and after, not from the script.
        let before: BTreeMap<String, Option<String>> =
            consumers.iter().map(|c| (c.clone(), container_created(c))).collect();
        // Same binary as this process — see mesh.rs::run_script for why.
        let cli_bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
        let st = Command::new("bash")
            .arg(&script)
            .arg("--force")
            .current_dir(&root)
            .env("NOO_CLI_BIN", &cli_bin)
            .status();
        if !matches!(st, Ok(s) if s.success()) {
            if !g.json {
                ui::close_failed("stack recreate failed — the store IS rotated", Some("noo stack restart --force"));
            }
            return Ok(1);
        }
        let after: BTreeMap<String, Option<String>> =
            consumers.iter().map(|c| (c.clone(), container_created(c))).collect();
        let verdicts = recreate_verdicts(&consumers, &before, &after);
        let stale: Vec<&str> = verdicts
            .iter()
            .filter(|(_, v)| matches!(v, RecreateVerdict::Unchanged | RecreateVerdict::Vanished))
            .map(|(c, _)| c.as_str())
            .collect();
        let off: Vec<&str> = verdicts
            .iter()
            .filter(|(_, v)| *v == RecreateVerdict::NotRunning)
            .map(|(c, _)| c.as_str())
            .collect();
        if g.json {
            println!("{}", serde_json::json!({
                "restart": "ran",
                "recreated": verdicts.iter().filter(|(_, v)| *v == RecreateVerdict::Recreated).map(|(c, _)| c).collect::<Vec<_>>(),
                "not_recreated": stale,
                "not_running": off,
            }));
            return Ok(if stale.is_empty() { 0 } else { 1 });
        }
        for (c, v) in &verdicts {
            let line = match v {
                RecreateVerdict::Recreated => ui::status_line(Glyph::Ok, &format!("{c}  recreated")),
                RecreateVerdict::NotRunning => ui::status_line(Glyph::Bullet, &format!("{c}  {}", ui::muted("not running here (add-on off) — nothing to recreate"))),
                RecreateVerdict::Unchanged => ui::status_line(Glyph::Err, &format!("{c}  NOT recreated — same container as before; it still holds the OLD value")),
                RecreateVerdict::Vanished => ui::status_line(Glyph::Err, &format!("{c}  gone — it was running before the recreate and is not now")),
            };
            println!("{line}");
        }
        if stale.is_empty() {
            ui::close_done("every running consumer was recreated with the new values");
        } else {
            ui::close_failed(
                &format!("the launcher exited 0 but {} consumer(s) still hold the old value: {}", stale.len(), stale.join(", ")),
                Some("noo stack restart --force <service>   (if it is profile-gated, the launcher must select its profile)"),
            );
            return Ok(1);
        }
    }
    Ok(0)
}

/// Keys `--all-generated` covers, as a slice of `&'static str`.
fn all_generated_keys() -> Vec<&'static str> {
    all_generated()
}

/// Read one operator-supplied value from stdin.
///
/// Requires stdin to be a PIPE. Reading from a terminal would echo the
/// credential into the scrollback — the exact failure this module exists to
/// prevent — and this crate has no termios dependency to turn echo off. A
/// pipe from a password manager keeps the value off the disk, out of argv,
/// and out of the transcript.
/// The controlling terminal with its echo turned off, restored on drop.
///
/// Restoring in `Drop` rather than at the end of the happy path is the whole
/// point: a refusal, an early return or a signal during the confirmation must
/// not leave the operator typing blind into a shell that no longer echoes.
struct TtyPrompt {
    file: std::fs::File,
    saved: libc::termios,
    fd: i32,
}

impl TtyPrompt {
    fn open() -> Option<Self> {
        use std::os::unix::io::AsRawFd as _;
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
        let fd = file.as_raw_fd();
        // SAFETY: tcgetattr fills a termios we own, for a fd we just opened.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        // ECHONL keeps the Enter key's newline visible, so the cursor still
        // moves down as the operator types each entry.
        quiet.c_lflag |= libc::ECHONL;
        // SAFETY: same fd, a termios we own. TCSAFLUSH so anything already
        // typed ahead is discarded rather than echoed under the old mode.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return None;
        }
        Some(Self { file, saved, fd })
    }

    fn say(&mut self, msg: &str) {
        use std::io::Write as _;
        let _ = self.file.write_all(msg.as_bytes());
        let _ = self.file.flush();
    }

    /// Prompt, then read one line with the echo already off. `None` on a read
    /// failure or EOF.
    fn read_hidden(&mut self, prompt: &str) -> Option<String> {
        use std::io::{BufRead as _, BufReader, Write as _};
        let _ = self.file.write_all(prompt.as_bytes());
        let _ = self.file.flush();
        let mut reader = BufReader::new(self.file.try_clone().ok()?);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        }
    }
}

impl Drop for TtyPrompt {
    fn drop(&mut self) {
        // SAFETY: restoring the mode we saved, on the fd we opened.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

/// Read a provider-issued value by TYPING it, with the terminal's echo off.
///
/// `--set-from-stdin` refuses a terminal, and correctly: reading a typed line
/// normally would put the credential in the scrollback. But the pipe it demands
/// is not always available, and the fallback an operator reaches for is
/// `printf '%s' '<token>' | …`, which puts the secret in shell history and, for
/// a moment, in the process list where any user on the box can read it. The
/// safe path should not be the inconvenient one.
///
/// So: read from `/dev/tty` rather than stdin (the prompt still works with
/// stdin redirected), with `ECHO` cleared for the duration. The value is typed
/// twice and the two must match, because nothing is echoed to check against and
/// a mistyped token fails later as an authentication error that looks like a
/// revoked credential.
///
/// The terminal's original mode is restored by a guard, so a failure, a refusal
/// or a ^C on the confirmation cannot leave the operator with an invisible
/// shell.
fn read_secret_from_prompt(g: &Globals, key: &str) -> Result<String, Unhandled> {
    let mut tty = match TtyPrompt::open() {
        Some(t) => t,
        None => {
            fail(
                g.json,
                ExitCode::Usage,
                "no_terminal",
                "--prompt needs a terminal to type into, and this process has none",
                Some("in a script, pipe the value instead: \
                      <your password manager> | noo security secrets rotate <KEY> \
                      --set-from-stdin --yes"),
            );
        }
    };
    tty.say(&format!(
        "{key} is issued by a third party, so it is typed, not generated.\n\
         Nothing you type is shown, stored in shell history, or visible in the process list.\n"
    ));
    let first = tty.read_hidden(&format!("New value for {key}: "));
    let again = tty.read_hidden("Type it again to confirm: ");
    drop(tty);
    let (first, again) = (first, again);
    match validate_typed_secret(first.as_deref(), again.as_deref()) {
        Ok(v) => Ok(v),
        Err(TypedSecretError::ReadFailed) => fail(
            g.json,
            ExitCode::Generic,
            "tty_read_failed",
            "could not read from the terminal",
            None,
        ),
        Err(TypedSecretError::Empty) => fail(
            g.json,
            ExitCode::Usage,
            "empty_value",
            "an empty value is not a secret — nothing was written",
            Some("re-run when you have the value from the provider"),
        ),
        Err(TypedSecretError::Mismatch) => fail(
            g.json,
            ExitCode::Usage,
            "entries_differ",
            "the two entries do not match — nothing was written",
            Some("re-run and type the same value twice; the store is unchanged"),
        ),
    }
}

/// Why a typed value was rejected. Separated from the terminal handling so the
/// RULES are testable without a tty.
#[derive(Debug, PartialEq, Eq)]
pub enum TypedSecretError {
    ReadFailed,
    Empty,
    Mismatch,
}

/// The rules for a value typed twice: both reads must succeed, agree, and be
/// non-empty once the line ending is off.
///
/// Trailing CR/LF go — they are the Enter key, not the secret. Interior
/// whitespace is kept, because some provider keys legitimately contain it, and
/// LEADING whitespace is kept too: trimming it would silently accept a
/// mis-pasted value and store something the provider never issued.
pub fn validate_typed_secret(
    first: Option<&str>,
    again: Option<&str>,
) -> Result<String, TypedSecretError> {
    let (Some(a), Some(b)) = (first, again) else {
        return Err(TypedSecretError::ReadFailed);
    };
    let strip = |s: &str| s.trim_end_matches('\n').trim_end_matches('\r').to_string();
    let (a, b) = (strip(a), strip(b));
    if a != b {
        return Err(TypedSecretError::Mismatch);
    }
    if a.is_empty() {
        return Err(TypedSecretError::Empty);
    }
    Ok(a)
}

fn read_secret_from_stdin(g: &Globals) -> Result<String, Unhandled> {
    if unsafe { libc::isatty(0) } == 1 {
        fail(
            g.json,
            ExitCode::Usage,
            "stdin_is_a_tty",
            "--set-from-stdin needs the value on a PIPE, not a terminal",
            Some("typing it here would echo the credential into your scrollback. Either use \
                  --prompt, which reads it from the terminal with the echo OFF, or pipe it: \
                  pass show anthropic/api | noo security secrets rotate ANTHROPIC_API_KEY \
                  --set-from-stdin --yes"),
        );
    }
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        fail(
            g.json,
            ExitCode::Generic,
            "stdin_read_failed",
            "could not read the value from stdin",
            None,
        );
    }
    // One trailing newline is the shell's, not part of the secret. Interior
    // whitespace is preserved — some provider keys legitimately contain it.
    Ok(buf.trim_end_matches('\n').trim_end_matches('\r').to_string())
}

fn revert_roles(altered: &[(&str, &str)], container: &str, superuser: &str, db: &str) {
    for (role, old) in altered {
        if old.is_empty() {
            continue;
        }
        let sql = format!("ALTER ROLE \"{role}\" WITH PASSWORD {};\n", sql_quote(old));
        let _ = psql_stdin(container, superuser, db, &sql);
    }
}

/// Progress line. Goes to stderr so `--json` stdout stays parseable, and is
/// suppressed in json mode entirely.
fn report(g: &Globals, phase: &str, msg: &str) {
    if !g.json {
        ui::step(&format!("{}  {msg}", ui::muted(phase)));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Resync — converge the ROLE onto the STORE, without minting anything
// ─────────────────────────────────────────────────────────────────────────
//
// `rotate` is the wrong tool for a drifted db-password, and reaching for it
// is what the 2026-08-03 audit finding used to tell you to do.
//
// Rotation mints a NEW value: it rewrites the store, ALTERs the role, and
// leaves every consumer container holding a stale environment until it is
// recreated. Applied to a drift, that is a bigger, riskier operation than the
// problem — and it is a fleet-visible change made in order to fix a
// controller-local disagreement.
//
// The drift itself is narrower than that. The store and every consumer
// already agree; it is only the Postgres role that is behind, because the
// role's password is set by a migration that runs once and hand-editing
// `env.sops` afterwards never reaches it. So the fix is to make the role
// match the store. No new secret, no store write, no consumer recreate — the
// consumers are already correct, which is why they start working the instant
// the role catches up.
//
// It is also idempotent and convergent: run it when nothing has drifted and
// it verifies and does nothing.

/// What the login probe established about one role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeVerdict {
    /// The stored value logs in, and a wrong password is rejected.
    Authenticates,
    /// The stored value does NOT log in, and a wrong password IS rejected —
    /// so the rejection means something. This is the drift.
    Drifted,
    /// A deliberately wrong password was also accepted, so this connection
    /// path does not check passwords and the probe proved nothing.
    CannotTell,
    /// Postgres could not be reached. Like [`ProbeVerdict::CannotTell`] this
    /// is "we learned nothing" — emphatically NOT "the password is wrong".
    /// Keeping it separate matters here for the same reason `rotate` keeps it
    /// separate: acting on a network fault as if it were a rejection is how a
    /// repair tool turns a blip into damage.
    Unreachable,
}

/// What to do about one role.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResyncAction {
    /// Already correct.
    Skip,
    /// `ALTER ROLE` it onto the stored value.
    Alter,
    /// Declined, with the reason.
    Refuse(&'static str),
}

/// The decision table, pure so it can be tested without Docker or Postgres.
///
/// `CannotTell` refuses rather than proceeding. An `ALTER` there would be
/// harmless in itself, but it could not be verified afterwards either, so the
/// command would have to report "resynced" on the strength of nothing. On a
/// `trust` pg_hba the password is not what is keeping anyone out, and saying
/// so is more useful than a reassuring no-op.
fn resync_action(verdict: ProbeVerdict, dry_run: bool) -> ResyncAction {
    match verdict {
        ProbeVerdict::Authenticates => ResyncAction::Skip,
        ProbeVerdict::CannotTell => ResyncAction::Refuse(
            "this connection path accepts any password (pg_hba `trust`), so neither the \
             drift nor the fix can be verified here",
        ),
        ProbeVerdict::Unreachable => ResyncAction::Refuse(
            "Postgres was not reachable — that is not evidence the password is wrong, \
             and converging a role on the strength of a network fault is not a repair",
        ),
        ProbeVerdict::Drifted if dry_run => ResyncAction::Refuse("--dry-run"),
        ProbeVerdict::Drifted => ResyncAction::Alter,
    }
}

fn probe_role(container: &str, role: &str, db: &str, value: &str, host: &str) -> ProbeVerdict {
    match verify_login_via(container, role, db, value, host) {
        Ok(Verify::Verified) => ProbeVerdict::Authenticates,
        Ok(Verify::NotPasswordAuthenticated) => ProbeVerdict::CannotTell,
        // A misconfigured check learned nothing either; refusing to ALTER on
        // it is the same safety as refusing on a network fault.
        Ok(Verify::Unreachable) | Ok(Verify::Misconfigured(_)) => ProbeVerdict::Unreachable,
        // A rejection with the negative control correctly refused. This is the
        // only verdict that is actual evidence about the password.
        Err(_) => ProbeVerdict::Drifted,
    }
}

/// Resolve a `DbPassword` spec's role name the same way the rotate and audit
/// paths do — `None` means the superuser role the image creates.
fn db_role_of(class: Class) -> Option<String> {
    match class {
        Class::DbPassword { role: Some(r) } => Some(r.to_string()),
        Class::DbPassword { role: None } => {
            Some(std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into()))
        }
        _ => None,
    }
}

/// `noo security secrets resync [KEY…] [--all] [--dry-run] [--json]
///  [--sops-file P] [--pg-container C] [--pg-db D] [--pg-superuser U]`
///
/// Make each Postgres role's password match the value already in the store.
/// Exits non-zero if any role could not be brought into sync.
pub fn secrets_resync(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut keys: Vec<String> = Vec::new();
    let mut all = false;
    let mut dry_run = false;
    let mut sops_path: Option<PathBuf> = None;
    let mut pg_container = crate::envfile::container("postgres");
    let mut pg_db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "noo".into());
    let mut pg_superuser = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into());

    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--all" => all = true,
            "--dry-run" => dry_run = true,
            "--sops-file" => sops_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            "--pg-container" => pg_container = iter.next().ok_or(Unhandled)?.clone(),
            "--pg-db" => pg_db = iter.next().ok_or(Unhandled)?.clone(),
            "--pg-superuser" => pg_superuser = iter.next().ok_or(Unhandled)?.clone(),
            s if s.starts_with('-') => return Err(Unhandled),
            s => keys.push(s.to_string()),
        }
    }
    if keys.is_empty() && !all {
        return Err(Unhandled);
    }
    if !keys.is_empty() && all {
        fail(
            g.json,
            ExitCode::Usage,
            "usage",
            "pass either explicit keys or --all, not both",
            None,
        );
    }

    // Select the specs to act on. Anything that is not a db-password has no
    // role to converge, so naming one is a usage error rather than a no-op.
    let selected: Vec<&SecretSpec> = if all {
        registry()
            .filter(|s| matches!(s.class, Class::DbPassword { .. }))
            .collect()
    } else {
        let mut out = Vec::new();
        for k in &keys {
            match registry().find(|s| s.key == k) {
                Some(s) if matches!(s.class, Class::DbPassword { .. }) => out.push(s),
                Some(s) => fail(
                    g.json,
                    ExitCode::Usage,
                    "not_a_db_password",
                    &format!("{k} is {} — there is no Postgres role to converge", s.class.label()),
                    Some("resync only applies to db-password secrets; see `noo security secrets audit`"),
                ),
                None => fail(
                    g.json,
                    ExitCode::Usage,
                    "unknown_key",
                    &format!("{k} is not in the secret registry"),
                    None,
                ),
            }
        }
        out
    };

    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    let sops = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "sops_decrypt_failed",
            &e,
            Some("resync needs to decrypt in memory; it never writes plaintext to disk"),
        ),
    };

    if !container_running(&pg_container) {
        fail(
            g.json,
            ExitCode::Generic,
            "postgres_down",
            &format!("{pg_container} is not running — nothing to converge against"),
            Some("this failure means Postgres is DOWN, which is a different problem from a \
                  drifted password: start it first (`noo stack start`)"),
        );
    }
    // Same reasoning as the audit probe: loopback is `trust` in the stock
    // pg_hba, so a check over 127.0.0.1 cannot fail and would make every
    // verdict meaningless. Decline rather than run a vacuous probe.
    let Some(pg_host) = container_routable_host(&pg_container) else {
        fail(
            g.json,
            ExitCode::Generic,
            "no_routable_host",
            &format!("{pg_container} has no routable address, so a login test would be \
                      answered by the pg_hba `trust` rule and prove nothing"),
            Some("refusing to report a result that could not have failed"),
        );
    };

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut failures = 0usize;
    let mut changed = 0usize;

    for spec in selected {
        let Some(role) = db_role_of(spec.class) else {
            continue;
        };
        let Some(value) = sops.map.get(spec.key) else {
            results.push(serde_json::json!({
                "key": spec.key, "role": role, "outcome": "absent",
                "detail": "not present in the store",
            }));
            continue;
        };
        if value.is_empty() {
            results.push(serde_json::json!({
                "key": spec.key, "role": role, "outcome": "absent",
                "detail": "stored value is blank",
            }));
            continue;
        }

        let verdict = probe_role(&pg_container, &role, &pg_db, value, &pg_host);
        let (outcome, detail) = match resync_action(verdict, dry_run) {
            ResyncAction::Skip => (
                "in-sync",
                format!("role \"{role}\" already authenticates with the stored value"),
            ),
            ResyncAction::Refuse("--dry-run") => {
                changed += 1;
                (
                    "would-resync",
                    format!(
                        "role \"{role}\" does NOT authenticate with the stored value — \
                         drift confirmed; re-run without --dry-run to converge it"
                    ),
                )
            }
            ResyncAction::Refuse(why) => {
                ("not-verifiable", format!("role \"{role}\": {why}"))
            }
            ResyncAction::Alter => {
                let sql = format!("ALTER ROLE \"{role}\" WITH PASSWORD {};\n", sql_quote(value));
                match psql_stdin(&pg_container, &pg_superuser, &pg_db, &sql) {
                    Err(e) => {
                        failures += 1;
                        ("failed", format!("ALTER ROLE \"{role}\" failed: {e}"))
                    }
                    // Re-probe rather than trust the exit status. The whole
                    // point of this command is that a store and a role can
                    // disagree while every individual step reports success.
                    Ok(()) => match probe_role(&pg_container, &role, &pg_db, value, &pg_host) {
                        ProbeVerdict::Authenticates => {
                            changed += 1;
                            (
                                "resynced",
                                format!(
                                    "role \"{role}\" now authenticates with the stored value \
                                     (wrong password still rejected)"
                                ),
                            )
                        }
                        _ => {
                            failures += 1;
                            (
                                "failed",
                                format!(
                                    "ALTER ROLE \"{role}\" ran but the stored value still does \
                                     not log in — something else is rewriting this role"
                                ),
                            )
                        }
                    },
                }
            }
        };
        if !g.json {
            let glyph = match outcome {
                "in-sync" | "resynced" => Glyph::Ok,
                "failed" => Glyph::Err,
                _ => Glyph::Warn,
            };
            println!("{}", ui::item(spec.key));
            println!("{}", ui::sub(&ui::status_line(glyph, &format!("{outcome}  {}", ui::muted(&detail)))));
        }
        results.push(serde_json::json!({
            "key": spec.key, "role": role, "outcome": outcome, "detail": detail,
        }));
    }

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": dry_run,
                "changed": changed,
                "failed": failures,
                "results": results,
            })
        );
    } else {
        let summary = format!(
            "{} role(s) {}, {} failed  {}",
            changed,
            if dry_run { "would change" } else { "converged" },
            failures,
            ui::muted("the store was not modified and no container needs recreating: consumers already hold these values"),
        );
        if failures > 0 {
            ui::close_failed(&summary, Some("noo security secrets audit"));
        } else {
            ui::close_done(&summary);
        }
    }
    Ok(if failures > 0 { 1 } else { 0 })
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn recreate_notice_only_when_a_container_holds_the_key() {
        assert_eq!(recreate_notice(&[]), None, "no consumer, no heading");
        let n = recreate_notice(&["gateway".to_string(), "worker".to_string()]).unwrap();
        assert!(n.starts_with("these containers hold the old value and must be recreated"), "{n}");
        assert!(n.ends_with("gateway, worker"), "{n}");
    }

    // ── scoped recreate (a key change is not a stack restart) ──

    struct FakeStack {
        present: Vec<&'static str>,
        running: Vec<&'static str>,
        deps: Vec<(&'static str, Vec<&'static str>)>,
    }
    impl StackProbe for FakeStack {
        fn present(&self, c: &str) -> bool { self.present.contains(&c) }
        fn running(&self, c: &str) -> bool { self.running.contains(&c) }
        fn depends_on(&self, c: &str) -> Vec<String> {
            self.deps.iter().find(|(k, _)| *k == c)
                .map(|(_, v)| v.iter().map(|s| s.to_string()).collect()).unwrap_or_default()
        }
    }
    fn names(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn provisioning_a_consumer_recreates_only_its_own_service() {
        let t = provision_targets("evolve").unwrap();
        let stack = FakeStack {
            present: vec!["noo-evolve", "noo-gateway", "noo-postgres", "noo-nats"],
            running: vec!["noo-gateway", "noo-postgres", "noo-nats", "noo-evolve"],
            deps: vec![("noo-evolve", vec!["gateway", "postgres"])],
        };
        let scope = launcher_scope(&t.containers, "noo", &stack);
        assert_eq!(scope.launcher_args(), Some(names(&["--force", "evolve"])),
            "the launcher must be asked for the consumer's service, not the stack");
        assert_eq!(scope.plan_line(), "noo-evolve", "the plan names what the action does");
    }

    #[test]
    fn a_multi_service_consumer_names_all_of_its_services() {
        let t = provision_targets("worker").unwrap();
        let stack = FakeStack {
            present: vec!["noo-worker", "noo-worker-extra", "noo-nats"],
            running: vec!["noo-nats"],
            deps: vec![("noo-worker", vec!["nats"]), ("noo-worker-extra", vec!["nats", "worker"])],
        };
        let scope = launcher_scope(&t.containers, "noo", &stack);
        assert_eq!(scope.launcher_args(), Some(names(&["--force", "worker", "worker-extra"])));
    }

    #[test]
    fn a_dependency_that_is_down_falls_back_to_a_full_restart_with_the_reason() {
        let stack = FakeStack {
            present: vec!["noo-evolve"],
            running: vec!["noo-gateway"],
            deps: vec![("noo-evolve", vec!["gateway", "postgres"])],
        };
        let scope = launcher_scope(&names(&["noo-evolve"]), "noo", &stack);
        assert_eq!(scope.launcher_args(), Some(names(&["--force"])));
        let line = scope.plan_line();
        assert!(line.starts_with("Restarts the stack:") && line.contains("postgres"), "{line}");
    }

    #[test]
    fn an_absent_consumer_runs_no_launcher_at_all() {
        let stack = FakeStack { present: vec![], running: vec![], deps: vec![] };
        let scope = launcher_scope(&names(&["noo-evolve"]), "noo", &stack);
        assert_eq!(scope.launcher_args(), None, "an add-on that is off must not be started or restarted around");
    }

    #[test]
    fn the_prefix_decides_the_service_name() {
        let stack = FakeStack { present: vec!["acme-evolve"], running: vec![], deps: vec![] };
        let scope = launcher_scope(&names(&["acme-evolve"]), "acme", &stack);
        assert_eq!(scope.launcher_args(), Some(names(&["--force", "evolve"])));
        let off = launcher_scope(&names(&["acme-evolve"]), "noo", &stack);
        assert!(matches!(off, LauncherScope::Full { .. }), "a container outside the prefix has an unknown service");
    }

    #[test]
    fn the_depends_on_label_parses() {
        assert_eq!(parse_depends_on("postgres:service_healthy:false,nats:service_started:false\n"), ["postgres", "nats"]);
        assert!(parse_depends_on("<no value>").is_empty());
        assert!(parse_depends_on("").is_empty());
    }

    #[test]
    fn provision_runs_the_launcher_through_the_scope_not_a_bare_force() {
        let src = include_str!("security.rs");
        let body = &src[src.find("pub fn security_service_key_provision").unwrap()..];
        let body = &body[..body.find("fn provision_request_json").unwrap()];
        assert!(body.contains("launcher_scope(") && body.contains("scope.launcher_args()"));
        assert!(!body.contains(".arg(\"--force\")"), "a bare --force restarts the whole stack");
    }

    /// host8, 2026-10-02: tidy moved NOO_ENTITLEMENT and the Google Chat
    /// file credential into plaintext `.env` because their NAMES do not look
    /// like credentials. Tidy and the plaintext check now share one answer.
    #[test]
    fn tidy_keeps_every_secret_class_key_in_the_store() {
        let map: BTreeMap<String, String> = [
            ("NOO_ENTITLEMENT", "noo-ent-…"),
            ("NOO_FILECRED_GOOGLE_CHAT_B64", "eyJ…"),
            ("POSTGRES_PASSWORD", "p"),
            ("NOO_TAILSCALE_OAUTH_CLIENT_ID", "kXYZ"),
            ("NOO_IMAGE_PREFIX", "ghcr.io/x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let moved = config_keys_in_store(&map);
        assert_eq!(moved, vec!["NOO_IMAGE_PREFIX".to_string(), "NOO_TAILSCALE_OAUTH_CLIENT_ID".to_string()]);
        for k in &moved {
            assert!(!super::super::plaintext_env::secret_class(k), "{k} moved to .env but the plaintext check calls it a secret");
        }
    }

    /// `secrets rotate` must check the image floor BEFORE its first
    /// mutation (minting, ALTER ROLE, the store commit): a
    /// rotation whose recreate the launcher then refuses leaves the database
    /// and the store on the new value and every container on the old one.
    /// Read from this file's own source, in order — the check has no other
    /// observable than where it sits.
    #[test]
    fn rotate_checks_the_secrets_floor_before_any_mutation() {
        let src = include_str!("secrets.rs");
        let body_start = src.find("pub fn secrets_rotate(").expect("secrets_rotate");
        let body = &src[body_start..];
        let body = &body[..body.find("\n}\n").expect("end of secrets_rotate")];
        let check = body.find("install_secrets_floor_refusal()").expect("rotate no longer checks the secrets floor");
        for mutation in ["psql_stdin(", ".commit(&sops_path)", "confirm_destructive(", "Phase 1: mint"] {
            let at = body.find(mutation).unwrap_or_else(|| panic!("{mutation} not found in secrets_rotate — update this test"));
            assert!(check < at, "the secrets-floor check comes AFTER `{mutation}` in secrets_rotate");
        }
    }

    // ── typing a provider-issued secret (--prompt) ───────────────────────
    //
    // The safe path must not be the inconvenient one. `--set-from-stdin`
    // refuses a terminal because a typed line would echo into the scrollback,
    // and the fallback an operator reaches for is
    // `printf '%s' '<token>' | …` — which puts the credential in shell history
    // and, briefly, in the process list where any user on the box can read it.
    // `--prompt` reads it from /dev/tty with ECHO off instead. These tests pin
    // the RULES; the terminal handling is a thin wrapper around termios.

    use super::{validate_typed_secret, TypedSecretError};

    // ── rotate proves each consumer was recreated ───────────

    fn stamps(pairs: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.map(str::to_string))).collect()
    }

    /// The earlier-change shape, exactly: the launcher exits 0, the core
    /// consumer's stamp moved, the profile-gated add-on's did not. The
    /// verdict must name the add-on as NOT recreated, whatever the script said.
    #[test]
    fn an_untouched_consumer_is_reported_as_not_recreated() {
        let consumers = vec!["noo-gateway".to_string(), "noo-trellion-intel".to_string()];
        let before = stamps(&[("noo-gateway", Some("t1")), ("noo-trellion-intel", Some("t1"))]);
        let after = stamps(&[("noo-gateway", Some("t2")), ("noo-trellion-intel", Some("t1"))]);
        let v = recreate_verdicts(&consumers, &before, &after);
        assert_eq!(v[0], ("noo-gateway".into(), RecreateVerdict::Recreated));
        assert_eq!(v[1], ("noo-trellion-intel".into(), RecreateVerdict::Unchanged));
    }

    /// An add-on that is OFF has no container before or after. That is not a
    /// failure — rotating with the intel add-on disabled must not refuse.
    #[test]
    fn a_consumer_that_was_never_running_is_not_a_failure() {
        let consumers = vec!["noo-trellion-intel".to_string()];
        let v = recreate_verdicts(&consumers, &stamps(&[("noo-trellion-intel", None)]), &stamps(&[("noo-trellion-intel", None)]));
        assert_eq!(v[0].1, RecreateVerdict::NotRunning);
        // and a consumer the maps do not even mention reads the same way
        let v = recreate_verdicts(&consumers, &stamps(&[]), &stamps(&[]));
        assert_eq!(v[0].1, RecreateVerdict::NotRunning);
    }

    #[test]
    fn a_consumer_that_disappears_is_louder_than_unchanged() {
        let consumers = vec!["noo-worker".to_string()];
        let v = recreate_verdicts(&consumers, &stamps(&[("noo-worker", Some("t1"))]), &stamps(&[("noo-worker", None)]));
        assert_eq!(v[0].1, RecreateVerdict::Vanished);
    }

    /// A consumer that only exists AFTER the run was created by it — that is
    /// a recreate, not an anomaly (first start of a newly enabled add-on).
    #[test]
    fn a_consumer_that_appears_counts_as_recreated() {
        let consumers = vec!["noo-whisper".to_string()];
        let v = recreate_verdicts(&consumers, &stamps(&[("noo-whisper", None)]), &stamps(&[("noo-whisper", Some("t2"))]));
        assert_eq!(v[0].1, RecreateVerdict::Recreated);
    }

    #[test]
    fn a_value_typed_the_same_way_twice_is_accepted() {
        assert_eq!(
            validate_typed_secret(Some("123456:AA-bb_cc\n"), Some("123456:AA-bb_cc\n")),
            Ok("123456:AA-bb_cc".to_string())
        );
    }

    #[test]
    fn a_slip_on_either_entry_writes_nothing() {
        // Nothing is echoed, so the second entry is the only check there is.
        assert_eq!(
            validate_typed_secret(Some("token-a\n"), Some("token-b\n")),
            Err(TypedSecretError::Mismatch)
        );
    }

    #[test]
    fn an_empty_entry_is_refused_rather_than_stored() {
        // Enter pressed twice must not blank a live credential.
        assert_eq!(validate_typed_secret(Some("\n"), Some("\n")), Err(TypedSecretError::Empty));
        assert_eq!(validate_typed_secret(Some(""), Some("")), Err(TypedSecretError::Empty));
    }

    #[test]
    fn a_failed_read_is_not_an_empty_secret() {
        // EOF (^D) and a read error arrive as None. Treating either as "" would
        // store an empty value for a key that had a working one.
        assert_eq!(validate_typed_secret(None, Some("x\n")), Err(TypedSecretError::ReadFailed));
        assert_eq!(validate_typed_secret(Some("x\n"), None), Err(TypedSecretError::ReadFailed));
        assert_eq!(validate_typed_secret(None, None), Err(TypedSecretError::ReadFailed));
    }

    #[test]
    fn only_the_line_ending_is_stripped() {
        // Interior spaces are part of some provider keys. Leading whitespace is
        // KEPT deliberately: trimming it would quietly accept a mis-pasted
        // value and store something the provider never issued.
        assert_eq!(
            validate_typed_secret(Some("a b\r\n"), Some("a b\r\n")),
            Ok("a b".to_string())
        );
        assert_eq!(
            validate_typed_secret(Some(" lead\n"), Some(" lead\n")),
            Ok(" lead".to_string())
        );
        // ...and a leading space on ONE entry is a mismatch, not a match.
        assert_eq!(
            validate_typed_secret(Some(" x\n"), Some("x\n")),
            Err(TypedSecretError::Mismatch)
        );
    }

    #[test]
    fn a_typed_value_is_planned_the_same_way_a_piped_one_is() {
        // --prompt and --set-from-stdin differ only in where the value is read
        // from; everything downstream must treat them alike.
        let mut m = BTreeMap::new();
        m.insert("TELEGRAM_BOT_TOKEN".to_string(), "SENTINEL-old".to_string());
        let sops = SecretStore::from_map(m, PathBuf::from("/fixture/secrets/env.sops"), true);
        let typed = build_plan(
            &["TELEGRAM_BOT_TOKEN".to_string()],
            &sops,
            Some("TELEGRAM_BOT_TOKEN"),
            ValueSource::Prompt,
            "noo",
        );
        let piped = build_plan(
            &["TELEGRAM_BOT_TOKEN".to_string()],
            &sops,
            Some("TELEGRAM_BOT_TOKEN"),
            ValueSource::Stdin,
            "noo",
        );
        assert_eq!(typed[0].source, ValueSource::Prompt);
        assert_eq!(piped[0].source, ValueSource::Stdin);
        assert_eq!(typed[0].refusal, piped[0].refusal, "same key, same refusal");
    }

    use super::*;

    /// Distinctive fixture values. Any one of these appearing in rendered
    /// output means a value escaped.
    const V_PG: &str = "SENTINEL-postgres-value-9f3a";
    const V_JWT: &str = "SENTINEL-jwt-value-1c7d";
    const V_HF: &str = "SENTINEL-hf-token-value-44b1";
    const V_CLUSTER: &str = "SENTINEL-cluster-secret-value-e2";
    const V_ENVDUP: &str = "SENTINEL-anthropic-value-ab90";
    const SENTINELS: &[&str] = &[V_PG, V_JWT, V_HF, V_CLUSTER, V_ENVDUP];

    fn fixture_sops() -> SecretStore {
        let mut m = BTreeMap::new();
        m.insert("POSTGRES_PASSWORD".into(), V_PG.into());
        m.insert("NOO_APP_DB_PASSWORD".into(), "SENTINEL-app-db-7788".into());
        m.insert("NOO_JWT_SECRET".into(), V_JWT.into());
        m.insert("HF_TOKEN".into(), V_HF.into());
        m.insert("NOO_CLUSTER_SECRET".into(), V_CLUSTER.into());
        m.insert("ANTHROPIC_API_KEY".into(), V_ENVDUP.into());
        m.insert("NATS_WORKER_PASSWORD".into(), String::new()); // blank
        // Retired by an earlier release — still in an older install's store.
        m.insert("NATS_PASSWORD".into(), "SENTINEL-retired-nats-5361".into());
        m.insert("SOME_UNKNOWN_TOKEN".into(), "SENTINEL-unknown-3311".into());
        SecretStore::from_map(m, PathBuf::from("/fixture/secrets/env.sops"), true)
    }

    fn fixture_env() -> SecretStore {
        let mut m = BTreeMap::new();
        m.insert("NOO_SECRETS_BACKEND".into(), "sops".into());
        m.insert("NOO_NODE_NAME".into(), "controller".into());
        // A credential that should NOT be here — the config-only violation.
        m.insert("ANTHROPIC_API_KEY".into(), V_ENVDUP.into());
        SecretStore::from_map(m, PathBuf::from("/fixture/.env"), true)
    }

    /// THE test this module exists for. Every rendered surface is fed known
    /// values and checked, character for character, for their absence.
    #[test]
    fn no_value_ever_reaches_output() {
        let sops = fixture_sops();
        let env = fixture_env();
        let rows = audit_rows(&sops, &env);
        let findings = audit_findings(&rows, true, &|_| false);

        let human = render_audit(&rows, &findings, &sops, &env, true);
        let json = audit_json(&rows, &findings, &sops, &env, true).to_string();

        let plan = build_plan(
            &[
                "POSTGRES_PASSWORD".to_string(),
                "NOO_JWT_SECRET".to_string(),
                "NOO_CLUSTER_SECRET".to_string(),
                "HF_TOKEN".to_string(),
            ],
            &sops,
            None,
            ValueSource::Stdin,
            "noo",
        );
        let plan_human = render_plan(&plan, true);
        let plan_json_s = plan_json(&plan, true).to_string();

        for surface in [&human, &json, &plan_human, &plan_json_s] {
            for sentinel in SENTINELS {
                assert!(
                    !surface.contains(sentinel),
                    "a secret VALUE reached output: {sentinel} in:\n{surface}"
                );
            }
            // Also catch a truncated leak (a prefix long enough to matter).
            for sentinel in SENTINELS {
                assert!(
                    !surface.contains(&sentinel[..12]),
                    "a secret value PREFIX reached output: {} in:\n{surface}",
                    &sentinel[..12]
                );
            }
        }
    }

    /// The under-report `required_when` exists to fix.
    ///
    /// Before it, a credential absent from BOTH stores was always an INFO
    /// reading "fine if the feature is not enabled on this install" — which
    /// is true when the feature is off, and badly wrong when it is on. On a
    /// pro install with `noo-evolve` running, a vanished
    /// NOO_EVOLVE_DB_PASSWORD was reported at the same severity as a
    /// credential nobody had switched on.
    #[test]
    fn an_absent_credential_is_an_error_when_its_system_is_enabled() {
        let rows: Vec<AuditRow> = Vec::new(); // nothing in either store

        let off = audit_findings(&rows, true, &|_| false);
        let evolve_off = off
            .iter()
            .find(|f| f.key == "NOO_EVOLVE_DB_PASSWORD")
            .expect("evolve key should still be reported");
        assert_eq!(evolve_off.severity, Severity::Info, "pro off: not this install's problem");
        assert_eq!(evolve_off.kind, "registry-key-absent");
        assert!(
            evolve_off.message.contains("addons.evolve"),
            "the message must name the switch that makes it expected: {}",
            evolve_off.message
        );

        let on = audit_findings(&rows, true, &|f| f == "addons.evolve");
        let evolve_on = on
            .iter()
            .find(|f| f.key == "NOO_EVOLVE_DB_PASSWORD")
            .expect("evolve key should be reported");
        assert_eq!(
            evolve_on.severity,
            Severity::Error,
            "pro ON with no credential is broken, not informational"
        );
        assert_eq!(evolve_on.kind, "required-key-absent");
    }

    /// An unconditional key does not care about any flag.
    #[test]
    fn an_always_required_key_is_an_error_regardless_of_flags() {
        let rows: Vec<AuditRow> = Vec::new();
        for flags_on in [false, true] {
            let f = audit_findings(&rows, true, &|_| flags_on);
            let pg = f
                .iter()
                .find(|x| x.key == "POSTGRES_PASSWORD")
                .expect("POSTGRES_PASSWORD is in the registry");
            assert_eq!(pg.severity, Severity::Error, "flags_on={flags_on}");
            assert_eq!(pg.kind, "required-key-absent");
        }
    }

    /// Conditional secrets, enumerated. Adding one is a deliberate act — it
    /// changes what an install is expected to carry, and what the audit stays
    /// quiet about.
    /// A secret the gateway READS must be a variable the gateway RECEIVES.
    ///
    /// The registry says which container consumes each secret; compose says
    /// which variables each container gets. Nothing tied the two together,
    /// and on 2026-09-14 that gap shipped: `NOO_JWT_SIGNING_KEY` had a
    /// reader in the gateway, a row in the operator's `env.sops`, docs
    /// telling the operator where to put it — and no line in the gateway's
    /// compose `environment:` block. The launcher decrypted the key and
    /// handed it to nothing. From inside the container the variable was
    /// simply unset, which is the silent default, so there was no error to
    /// find; two sessions diagnosed it independently from opposite ends.
    ///
    /// Interpolation counts: `POSTGRES_PASSWORD` reaches the gateway inside
    /// `PGVECTOR_URL=postgresql://noo:${POSTGRES_PASSWORD}@…`, which is a
    /// delivery, not an omission.
    ///
    /// Read at test time, not `include_str!`, so the release build of this
    /// crate does not depend on a file outside it. Missing file is a FAIL,
    /// not a skip: a guard that skips is decoration.
    #[test]
    fn every_gateway_secret_is_delivered_by_compose() {
        let path = crate::test_support::repo_file("docker-compose.cluster.yml");
        let compose = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("this guard needs {}: {e}", path.display()));
        let start = compose
            .find("\n  gateway:\n")
            .expect("docker-compose.cluster.yml must declare a `gateway:` service");
        let body = &compose[start + 1..];
        // The block ends at the next 2-space-indented service key.
        let end = body[1..]
            .lines()
            .scan(0usize, |pos, l| { let p = *pos; *pos += l.len() + 1; Some((p, l)) })
            .find(|(_, l)| l.len() > 2 && l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':'))
            .map(|(p, _)| p + 1)
            .unwrap_or(body.len());
        let gateway = &body[..end];

        let missing: Vec<&str> = registry()
            .filter(|s| s.consumers.contains(&"noo-gateway"))
            .map(|s| s.key)
            .filter(|k| {
                let named = gateway.lines().any(|l| {
                    let t = l.trim_start();
                    t.starts_with(&format!("- {k}=")) || t.starts_with(&format!("{k}:"))
                });
                let interpolated = gateway.contains(&format!("${{{k}}}")) || gateway.contains(&format!("${{{k}:"));
                // Since 2026-09-29 a role password reaches the gateway inside
                // the launcher-DERIVED pgpass (`PGPASSFILE=${NOO_PGPASS_GATEWAY:+…}`),
                // never under its own name.
                let derived = crate::onboard::sh::PGPASS_ROLES.iter().any(|(var, _, roles)| {
                    roles.iter().any(|(_, v)| *v == *k) && gateway.contains(&format!("${{{var}:"))
                });
                !named && !interpolated && !derived
            })
            .collect();
        assert!(
            missing.is_empty(),
            "registry says the gateway consumes {missing:?}, but the gateway's compose \
             `environment:` block never delivers it — the launcher will decrypt the value \
             and hand it to nothing, with no error anywhere"
        );
    }

    #[test]
    fn the_conditionally_required_secrets_are_exactly_these() {
        let conditional: Vec<&str> = registry()
            .filter(|s| matches!(s.required_when, Requirement::WhenEnabled(_) | Requirement::WhenAddon(_)))
            .map(|s| s.key)
            .collect();
        assert_eq!(
            conditional,
            vec![
                "NOO_EVOLVE_DB_PASSWORD",
                "NOO_TRELLION_DDL_PASSWORD",
                "NOO_EVOLVE_DDL_PASSWORD",
            ],
            "adding a conditional secret is a deliberate act — update this test with it"
        );
        // WhenNotStandalone: needed unless the install profile is
        // `standalone` (Ollama-only). Kept separate from the WhenEnabled/
        // WhenAddon list above because it gates on `.env`'s
        // NOO_DEFAULT_PROFILE rather than a flag or an addon.
        let unless_standalone: Vec<&str> = registry()
            .filter(|s| matches!(s.required_when, Requirement::WhenNotStandalone))
            .map(|s| s.key)
            .collect();
        assert_eq!(
            unless_standalone,
            vec!["HF_TOKEN"],
            "adding a WhenNotStandalone secret is a deliberate act — update this test with it"
        );
        // Optional = the operator supplies it only when they use the feature;
        // absent is the normal state of a fresh install (walk 2026-09-07).
        // The CORE rows only: every add-on key row is derived from its
        // overlay and pinned Optional by `every_addon_key_row_is_optional`.
        let optional: Vec<&str> = CORE_REGISTRY
            .iter()
            .filter(|s| matches!(s.required_when, Requirement::Optional))
            .map(|s| s.key)
            .collect();
        assert_eq!(
            optional,
            vec![
                // The ES256 signing key for exchanged
                // agent tokens. Absent = HS256, which is the fresh-install
                // state, so Optional — and the audit no longer reports it
                // as an unclassified credential.
                "NOO_JWT_SIGNING_KEY",
                // NOO_AUDIT_HMAC_KEY left this list with the earlier PR:
                // it is now the ONLY key an audit row can be signed with
                // (no derivation from NOO_JWT_SECRET any more), so absent
                // means every audit row is refused — broken, not weaker. And
                // setting it no longer breaks the old rows' verification: the
                // gateway's checkpoint row hands the log over.
                // NOO_SVC_KEY_WORKER left this list with an earlier release: the
                // shared-HMAC fallback that made "absent" a working state is
                // retired, so absent is broken. The add-on keys beside it are
                // derived rows.
                // A node's own bus principal, delivered over the rail; a
                // controller store that runs no node-agent never holds it.
                // The add-ons' own bus passwords (i70 residue): absent is the
                // one-release fallback, which `nats principals` WARNs on.
                "NATS_TRELLION_PASSWORD",
                "NATS_TRELLION_INTEL_PASSWORD",
                "NATS_NODE_PASSWORD",
                "ANTHROPIC_API_KEY",
                // The other two cloud providers (rows added 2026-09-29; the
                // keys were delivered and read long before).
                "OPENAI_API_KEY",
                "GOOGLE_API_KEY",
                // The controller's read token for the licensed add-on
                // packages (i33); only an install running one needs it.
                "NOO_ADDON_REGISTRY_TOKEN",
                // Search provider keys, asked for by the wizard.
                "TAVILY_API_KEY",
                "BRAVE_SEARCH_API_KEY",
                "TELEGRAM_BOT_TOKEN",
                // The remaining channel credentials that have a reader
                // (rows added 2026-09-29 beside the delivery guard).
                "WHATSAPP_TOKEN",
                "GOOGLE_CHAT_BEARER_TOKEN",
                "NOO_FILECRED_GOOGLE_CHAT_B64",
                "NOO_TAILSCALE_API_KEY",
                "NOO_TAILSCALE_OAUTH_CLIENT_SECRET",
                // The two backup passphrases left this list on 2026-09-11
                // Backup-controller.sh refuses to run
                // without them, so "absent" is no longer a box that simply
                // isn't using the feature — it is a box with no backups.
                // `noo onboard` mints both.
            ],
            "making a secret optional is a deliberate act — update this test with it"
        );
    }

    /// The wizard blanks each credential's .env slot once the store holds it
    /// (#18). That slot is the DESIGN, not a plaintext copy — and a config
    /// key that is blank in the store is not a credential that will fail.
    #[test]
    fn a_blanked_env_slot_and_a_blank_config_key_are_not_findings() {
        let mut sops = BTreeMap::new();
        sops.insert("NOO_JWT_SECRET".to_string(), V_JWT.to_string());
        sops.insert("LOKI_URL".to_string(), String::new());
        let mut env = BTreeMap::new();
        env.insert("NOO_SECRETS_BACKEND".to_string(), "sops".to_string());
        env.insert("NOO_JWT_SECRET".to_string(), String::new()); // blanked slot
        let rows = audit_rows(
            &SecretStore::from_map(sops, PathBuf::from("/f/env.sops"), true),
            &SecretStore::from_map(env, PathBuf::from("/f/.env"), true),
        );
        let f = audit_findings(&rows, true, &|_| false);
        assert!(!f.iter().any(|x| x.kind == "credential-in-env"), "{:?}", f.iter().map(|x| (x.kind, x.key.clone())).collect::<Vec<_>>());
        assert!(!f.iter().any(|x| x.kind == "blank-value"), "a blank config key is not a blank credential");
    }

    #[test]
    fn audit_reports_presence_and_digests_only() {
        let sops = fixture_sops();
        let env = fixture_env();
        let rows = audit_rows(&sops, &env);

        let pg = rows.iter().find(|r| r.key == "POSTGRES_PASSWORD").unwrap();
        assert!(pg.in_sops && !pg.in_env);
        assert_eq!(pg.state, State::Set);
        assert_eq!(pg.length, Some(V_PG.len()));
        assert_eq!(pg.sha8.as_deref(), Some(sha8_of(V_PG).as_str()));
        assert_eq!(pg.sha8.as_ref().unwrap().len(), 8);
        assert_eq!(pg.class, Some("db-password"));
        assert_eq!(pg.disposition, Some("auto"));

        // A blank value is reported as BLANK, not as a zero-length "set".
        let nats = rows.iter().find(|r| r.key == "NATS_WORKER_PASSWORD").unwrap();
        assert_eq!(nats.state, State::Blank);

        // Present in both, same value → digests match, which is how drift is
        // checked without decrypting to a file.
        let anth = rows.iter().find(|r| r.key == "ANTHROPIC_API_KEY").unwrap();
        assert!(anth.in_sops && anth.in_env);
        assert_eq!(anth.sha8, anth.env_sha8);
    }

    /// A retired credential still in the store is reported as RETIRED, with
    /// the command that removes it — not as an unclassified credential to
    /// be given a rotation plan, which would invite it back. A blank slot
    /// is not a finding.
    #[test]
    fn a_retired_key_in_the_store_is_reported_with_its_removal_command() {
        let mut sops = fixture_sops().map.clone();
        sops.insert("NOO_MCP_TOKEN".into(), "SENTINEL-retired-4455".into());
        let sops = SecretStore::from_map(sops, PathBuf::from("/fixture/secrets/env.sops"), true);
        let rows = audit_rows(&sops, &fixture_env());
        let f = audit_findings(&rows, true, &|_| false);
        let mine: Vec<&Finding> = f.iter().filter(|x| x.key == "NOO_MCP_TOKEN").collect();
        assert_eq!(mine.len(), 1, "exactly one finding for a retired key: {:?}", mine.iter().map(|x| x.kind).collect::<Vec<_>>());
        assert_eq!(mine[0].kind, "retired-key");
        assert!(mine[0].message.contains(RETIRED_REMOVE_CMD), "{}", mine[0].message);
        assert!(mine[0].message.contains("mcp:operator"), "{}", mine[0].message);
        assert!(!mine[0].message.contains("SENTINEL"), "a finding never carries the value");

        let mut blank = fixture_sops().map.clone();
        blank.insert("NOO_MCP_TOKEN".into(), String::new());
        let blank = SecretStore::from_map(blank, PathBuf::from("/fixture/secrets/env.sops"), true);
        let f = audit_findings(&audit_rows(&blank, &fixture_env()), true, &|_| false);
        assert!(!f.iter().any(|x| x.key == "NOO_MCP_TOKEN"), "a blank retired slot is not a finding");
        // The removal command is a real verb.
        assert!(
            crate::usage::USAGE.iter().any(|(path, _, _)| path.join(" ") == RETIRED_REMOVE_CMD.trim_start_matches("noo ")),
            "{RETIRED_REMOVE_CMD} is not a CLI verb"
        );
    }

    /// 0.6.11-rc.1 move rehearsal: a 0.6.10 install whose .env still holds
    /// an empty `NOO_SELF_CALL_SHARED_SECRET=` slot (the self-call bridge was
    /// retired by #371) got an ERROR `blank-value` from the audit, failing
    /// `cluster verify`. A retired slot is not a credential waiting for a
    /// value: blank is silent, held is a `retired-key` warning.
    #[test]
    fn the_retired_self_call_secret_is_retired_not_a_blank_credential() {
        let mut env = fixture_env().map.clone();
        env.insert("NOO_SELF_CALL_SHARED_SECRET".into(), String::new());
        let env = SecretStore::from_map(env, PathBuf::from("/fixture/.env"), true);
        let f = audit_findings(&audit_rows(&fixture_sops(), &env), true, &|_| false);
        assert!(
            !f.iter().any(|x| x.key == "NOO_SELF_CALL_SHARED_SECRET"),
            "a blank retired slot is not a finding: {:?}",
            f.iter().filter(|x| x.key == "NOO_SELF_CALL_SHARED_SECRET").map(|x| x.kind).collect::<Vec<_>>()
        );

        let mut sops = fixture_sops().map.clone();
        sops.insert("NOO_SELF_CALL_SHARED_SECRET".into(), "SENTINEL-selfcall-9911".into());
        let sops = SecretStore::from_map(sops, PathBuf::from("/fixture/secrets/env.sops"), true);
        let f = audit_findings(&audit_rows(&sops, &fixture_env()), true, &|_| false);
        let mine: Vec<&Finding> = f.iter().filter(|x| x.key == "NOO_SELF_CALL_SHARED_SECRET").collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].kind, "retired-key");
        assert_eq!(mine[0].severity, Severity::Warn);
        assert!(!mine[0].message.contains("SENTINEL"), "a finding never carries the value");
    }

    #[test]
    fn findings_flag_the_four_things_that_bite() {
        let rows = audit_rows(&fixture_sops(), &fixture_env());
        let f = audit_findings(&rows, true, &|_| false);
        let kinds: Vec<&str> = f.iter().map(|x| x.kind).collect();

        // (1) credential in .env — the config-only violation
        assert!(f
            .iter()
            .any(|x| x.kind == "credential-in-env" && x.key == "ANTHROPIC_API_KEY"));
        // (3) blank-but-present
        assert!(f
            .iter()
            .any(|x| x.kind == "blank-value" && x.key == "NATS_WORKER_PASSWORD"));
        // (0) a retired key: ONE finding, naming the removal command — not
        // "unclassified credential" noise, and never the value.
        let retired: Vec<&Finding> = f.iter().filter(|x| x.key == "NATS_PASSWORD").collect();
        assert_eq!(retired.len(), 1, "{retired:?}");
        assert_eq!((retired[0].kind, retired[0].severity), ("retired-key", Severity::Warn));
        assert!(retired[0].message.contains(RETIRED_REMOVE_CMD),
            "{}", retired[0].message);
        assert!(!retired[0].message.contains("SENTINEL"), "never the value");
        // (5) unclassified credential-shaped key
        assert!(f
            .iter()
            .any(|x| x.kind == "unclassified-credential" && x.key == "SOME_UNKNOWN_TOKEN"));
        // (6) known key absent from the store
        // REDIS_PASSWORD is Requirement::Always, so absent-from-both is now
        // `required-key-absent` (an ERROR) rather than the flat informational
        // `registry-key-absent`. The old kind survives for keys whose system
        // is switched off — see `an_absent_credential_is_an_error_when_its_
        // system_is_enabled`.
        assert!(f
            .iter()
            .any(|x| x.kind == "required-key-absent" && x.key == "REDIS_PASSWORD"));
        // Non-credential config keys are never flagged as credentials.
        assert!(!f
            .iter()
            .any(|x| x.kind == "credential-in-env" && x.key == "NOO_NODE_NAME"));
        assert!(kinds.contains(&"credential-in-env"));
    }

    /// HF_TOKEN on a `standalone` (Ollama-only) install: nothing consumes
    /// it, so absent must be an Info `registry-key-absent`, never the ERROR
    /// `required-key-absent` a newcomer rehearsal hit on 2026-09-29.
    #[test]
    fn hf_token_is_info_not_error_on_standalone() {
        // HF_TOKEN absent from BOTH stores (no fixture value at all) — the
        // newcomer rehearsal's exact shape: a fresh, Ollama-only install
        // with nothing gated-HuggingFace configured.
        let sops = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/fixture/secrets/env.sops"), true);
        let env = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/fixture/.env"), true);
        let rows = audit_rows(&sops, &env);
        // `profile.not-standalone` resolves false on a standalone install.
        let f = audit_findings(&rows, true, &|_| false);
        let hf = f.iter().find(|x| x.key == "HF_TOKEN").expect("HF_TOKEN must still be reported");
        assert_eq!(hf.kind, "registry-key-absent");
        assert_eq!(hf.severity, Severity::Info);
    }

    /// HF_TOKEN when the install is NOT standalone (a vllm/llamacpp
    /// placement, profile, or gated HuggingFace preseed is active): absent
    /// must be the ERROR `required-key-absent`, same as any other
    /// consumed-but-missing credential.
    #[test]
    fn hf_token_is_error_when_not_standalone() {
        let sops = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/fixture/secrets/env.sops"), true);
        let env = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/fixture/.env"), true);
        let rows = audit_rows(&sops, &env);
        let f = audit_findings(&rows, true, &|gate| gate == "profile.not-standalone");
        let hf = f.iter().find(|x| x.key == "HF_TOKEN").expect("HF_TOKEN must be reported");
        assert_eq!(hf.kind, "required-key-absent");
        assert_eq!(hf.severity, Severity::Error);
    }

    /// `Requirement::WhenNotStandalone` itself: required() must ask for
    /// exactly the `"profile.not-standalone"` gate, so the audit's resolver
    /// and this variant agree on the name.
    #[test]
    fn when_not_standalone_asks_for_its_gate_name() {
        let asked = std::cell::RefCell::new(Vec::new());
        let required = Requirement::WhenNotStandalone.required(&|g: &str| {
            asked.borrow_mut().push(g.to_string());
            true
        });
        assert!(required);
        assert_eq!(*asked.borrow(), vec!["profile.not-standalone".to_string()]);
    }

    /// `is_standalone_install` reads `.env`'s exact `NOO_DEFAULT_PROFILE=standalone`
    /// line — the same format models.rs's copy checks — so the two never
    /// diverge on what "standalone" means for an install.
    #[test]
    fn is_standalone_install_reads_the_default_profile_line() {
        let dir = std::env::temp_dir().join(format!("noo-secrets-standalone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join(".env"), "NOO_INSTALL_MODE=dist\nNOO_DEFAULT_PROFILE=standalone\n").unwrap();
        assert!(is_standalone_install(&dir));

        std::fs::write(dir.join(".env"), "NOO_DEFAULT_PROFILE=cluster\n").unwrap();
        assert!(!is_standalone_install(&dir));

        std::fs::remove_file(dir.join(".env")).unwrap();
        assert!(!is_standalone_install(&dir), "no .env at all is not standalone");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (2) The consumer gap: in sops, not in .env, launcher not active.
    #[test]
    fn consumer_gap_only_when_the_sops_backend_is_off() {
        let rows = audit_rows(&fixture_sops(), &fixture_env());
        assert!(!audit_findings(&rows, true, &|_| false)
            .iter()
            .any(|f| f.kind == "consumer-gap"));
        let off = audit_findings(&rows, false, &|_| false);
        assert!(off
            .iter()
            .any(|f| f.kind == "consumer-gap" && f.key == "POSTGRES_PASSWORD"));
        // A non-credential key is not a consumer gap.
        assert!(!off
            .iter()
            .any(|f| f.kind == "consumer-gap" && f.key == "NOO_NODE_NAME"));
    }

    #[test]
    fn value_drift_is_detected_by_digest() {
        let sops = fixture_sops();
        let mut em = BTreeMap::new();
        em.insert("ANTHROPIC_API_KEY".into(), "a-DIFFERENT-value".to_string());
        let env = SecretStore::from_map(em, PathBuf::from("/fixture/.env"), true);
        let rows = audit_rows(&sops, &env);
        let f = audit_findings(&rows, true, &|_| false);
        assert!(f
            .iter()
            .any(|x| x.kind == "value-drift" && x.key == "ANTHROPIC_API_KEY"));
    }

    /// The audit chain's integrity key must be a secret in its own right.
    ///
    /// It used to be derived from NOO_JWT_SECRET when unset, so the tamper
    /// evidence for every audit row hung off the login secret four
    /// containers held. Now it is the only signing key, delivered to every
    /// audit writer, and required.
    #[test]
    fn the_audit_key_is_a_secret_the_registry_knows() {
        let s = spec_for("NOO_AUDIT_HMAC_KEY").expect("NOO_AUDIT_HMAC_KEY missing from REGISTRY");
        assert!(s.class.self_generatable(), "it must be generatable, not operator-supplied");
        assert!(s.gen_bytes >= 32, "an integrity key under 32 bytes is not one");
        for writer in ["noo-gateway", "noo-worker", "noo-worker-extra", "noo-trellion", "noo-trellion-intel"] {
            assert!(
                s.consumers.contains(&writer),
                "every audit writer must be named ({writer} missing): {:?}",
                s.consumers
            );
        }
        // Absent = every audit row refused. Not optional.
        assert!(matches!(s.required_when, Requirement::Always));
    }

    /// The parent has to SAY so. An operator reading the plan for
    /// `rotate NOO_JWT_SECRET` must be told that the audit rows signed
    /// before the audit-key checkpoint stop verifying — that is the whole
    /// warning.
    #[test]
    fn rotating_the_jwt_secret_warns_about_the_audit_chain() {
        let jwt = spec_for("NOO_JWT_SECRET").expect("NOO_JWT_SECRET missing");
        assert!(
            jwt.consequence.contains("NOO_AUDIT_HMAC_KEY"),
            "the JWT secret's consequence must name the audit key: {}",
            jwt.consequence
        );
        assert!(
            jwt.consequence.contains("audit"),
            "and say what happens to the audit rows: {}",
            jwt.consequence
        );
    }

    #[test]
    fn classification_matches_the_documented_table() {
        let expect: &[(&str, &str, &str)] = &[
            ("POSTGRES_PASSWORD", "db-password", "auto"),
            ("NOO_APP_DB_PASSWORD", "db-password", "auto"),
            ("NOO_EVOLVE_DB_PASSWORD", "db-password", "auto"),
            ("NOO_TRELLION_DDL_PASSWORD", "db-password", "auto"),
            ("NOO_EVOLVE_DDL_PASSWORD", "db-password", "auto"),
            ("NOO_TRELLION_DB_PASSWORD", "db-password", "auto"),
            ("REDIS_PASSWORD", "shared-service", "auto"),
            ("NOO_JWT_SECRET", "controller-local", "auto"),
            ("NOO_AGENT_REVIEW_KEY", "controller-local", "auto"),
            ("NOO_CONTROLLER_SECRET", "controller-local", "auto"),
            ("NOO_BUS_KEY_WORKER", "controller-local", "auto"),
            ("NOO_BUS_KEY_TRELLION", "controller-local", "auto"),
            ("NOO_BUS_KEY_TRELLION_INTEL", "controller-local", "auto"),
            ("NOO_BROWSER_KEY", "controller-local", "auto"),
            ("NOO_CLUSTER_SECRET", "fleet-wide", "refused"),
            ("NOO_NODE_AGENT_TOKEN", "fleet-wide", "refused"),
            // the earlier per-principal users. Refused here NOT because
            // they are fleet-wide (both are controller-only) but because
            // the NATS server verifies a bcrypt DIGEST of the value: a new
            // password that never reaches monitoring/nats/users.conf leaves
            // the holder looping on 'Authorization Violation'. Rendering the
            // digest and HUPing the server is a dedicated tool's job.
            ("NATS_GATEWAY_PASSWORD", "external-tool", "refused"),
            ("NATS_WORKER_PASSWORD", "external-tool", "refused"),
            ("NATS_TRELLION_PASSWORD", "external-tool", "refused"),
            ("NATS_TRELLION_INTEL_PASSWORD", "external-tool", "refused"),
            ("NATS_NODE_PASSWORD", "external-tool", "refused"),
            ("ANTHROPIC_API_KEY", "provider-issued", "manual"),
            ("OPENAI_API_KEY", "provider-issued", "manual"),
            ("GOOGLE_API_KEY", "provider-issued", "manual"),
            ("HF_TOKEN", "provider-issued", "manual"),
            ("TELEGRAM_BOT_TOKEN", "provider-issued", "manual"),
            ("WHATSAPP_TOKEN", "provider-issued", "manual"),
            ("GOOGLE_CHAT_BEARER_TOKEN", "provider-issued", "manual"),
            ("NOO_FILECRED_GOOGLE_CHAT_B64", "provider-issued", "manual"),
            ("NOO_TAILSCALE_API_KEY", "provider-issued", "manual"),
            ("NOO_TAILSCALE_OAUTH_CLIENT_SECRET", "provider-issued", "manual"),
            ("GRAFANA_PASSWORD", "provider-issued", "manual"),
            ("NOO_ADMIN_PASSWORD", "provider-issued", "manual"),
            // Were external-tool/refused until 2026-09-12, pointing at
            // scripts/noo-backup-rotate-passphrase.sh — which turned out to
            // destroy the store, while `rotate` refused them.
            // There was no safe path to either value anywhere. Now rotated
            // here, artifacts and all.
            ("NOO_AUDIT_HMAC_KEY", "controller-local", "auto"),
            ("NOO_BACKUP_PASSPHRASE", "backup-passphrase", "auto"),
            ("NOO_AGE_BACKUP_PASSPHRASE", "backup-passphrase", "auto"),
        ];
        for (key, class, disp) in expect {
            let s = spec_for(key).unwrap_or_else(|| panic!("{key} missing from REGISTRY"));
            assert_eq!(s.class.label(), *class, "{key} class");
            assert_eq!(s.class.disposition(), *disp, "{key} disposition");
        }
        // --all-generated covers exactly the auto set and nothing else — a
        // sweep flag that quietly included a fleet-wide key would be the
        // single worst bug this module could ship.
        let gen = all_generated();
        assert_eq!(
            gen,
            vec![
                "POSTGRES_PASSWORD",
                "NOO_APP_DB_PASSWORD",
                "NOO_EVOLVE_DB_PASSWORD",
                // The two migration-role credentials.
                // In the auto set deliberately: they are generated locally and
                // rotate like the runtime roles they sit beside.
                "NOO_TRELLION_DDL_PASSWORD",
                "NOO_EVOLVE_DDL_PASSWORD",
                "NOO_TRELLION_DB_PASSWORD",
                "REDIS_PASSWORD",
                "NOO_JWT_SECRET",
                "NOO_AGENT_REVIEW_KEY",
                "NOO_CONTROLLER_SECRET",
                // The per-audience bus keys. Generated
                // locally and rotated with their consumers recreated.
                "NOO_BUS_KEY_WORKER",
                "NOO_BUS_KEY_TRELLION",
                "NOO_BUS_KEY_TRELLION_INTEL",
                // The browser door's own key.
                "NOO_BROWSER_KEY",
            ]
        );
        for forbidden in [
            // Rotating this breaks verification of every audit row written
            // under the previous key. It is rotatable BY NAME and must never
            // ride along in a sweep.
            "NOO_AUDIT_HMAC_KEY",
            "NOO_CLUSTER_SECRET",
            "NOO_NODE_AGENT_TOKEN",
            "NATS_PASSWORD",
            "NATS_GATEWAY_PASSWORD",
            "NATS_WORKER_PASSWORD",
            "ANTHROPIC_API_KEY",
            "NOO_AGE_BACKUP_PASSPHRASE",
        ] {
            assert!(
                !gen.contains(&forbidden),
                "{forbidden} must never be swept into --all-generated"
            );
        }
    }

    #[test]
    fn db_roles_match_migrations_033_034_038() {
        for (key, want) in [
            ("NOO_APP_DB_PASSWORD", "noo_app"),
            ("NOO_EVOLVE_DB_PASSWORD", "noo_evolve"),
            ("NOO_TRELLION_DB_PASSWORD", "noo_trellion"),
        ] {
            let got = match spec_for(key).unwrap().class {
                Class::DbPassword { role } => role,
                _ => panic!("{key} should be a db password"),
            };
            assert_eq!(got, Some(want), "{key} role");
        }
        let sops = fixture_sops();
        let plan = build_plan(&["NOO_APP_DB_PASSWORD".to_string()], &sops, None, ValueSource::Stdin, "noo");
        assert_eq!(plan[0].db_role.as_deref(), Some("noo_app"));
        // POSTGRES_PASSWORD's role is NOT hardcoded — it is whatever
        // POSTGRES_USER says (compose defaults it to `noo`, not `postgres`).
        let p = build_plan(&["POSTGRES_PASSWORD".to_string()], &sops, None, ValueSource::Stdin, "custom_su");
        assert_eq!(p[0].db_role.as_deref(), Some("custom_su"));
    }

    #[test]
    fn a_backup_passphrase_is_rotatable_here_and_carries_its_artifacts() {
        // It used to REFUSE, pointing at
        // scripts/noo-backup-rotate-passphrase.sh. That script re-encrypted
        // secrets/env.sops FROM .env — a full replace that would have reduced
        // a 30-secret store to .env's two bootstrap flags and written both
        // passphrases in plaintext
        // live controller). A refusal that points at a destructive tool is
        // worse than no refusal.
        let mut m = BTreeMap::new();
        m.insert("NOO_AGE_BACKUP_PASSPHRASE".to_string(), "SENTINEL-x".to_string());
        let sops = SecretStore::from_map(m, PathBuf::from("/f/env.sops"), true);
        let plan = build_plan(&["NOO_AGE_BACKUP_PASSPHRASE".to_string()], &sops, None, ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.is_none(), "must not refuse: {:?}", plan[0].refusal);
        assert_eq!(plan[0].disposition, "auto");
        assert_eq!(plan[0].source, ValueSource::Generated);
        assert!(plan[0].artifacts.is_some(), "must carry the artifact list to re-encrypt");
        assert!(!plan[0].first_set, "it IS in the store here");
        assert!(plan[0].db_role.is_none());
    }

    #[test]
    fn a_backup_passphrase_absent_from_the_store_is_a_first_set_not_a_refusal() {
        // Rotation refuses a key it cannot find, because inventing one is not
        // rotation. These two are the exception: an install predating
        // `noo onboard` minting them has neither, and backup-controller.sh
        // now REFUSES TO RUN without them — so the first invocation on such a
        // box has to be able to create them.
        let sops = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/f/env.sops"), true);
        for k in ["NOO_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE"] {
            let plan = build_plan(&[k.to_string()], &sops, None, ValueSource::Stdin, "noo");
            assert!(plan[0].refusal.is_none(), "{k}: {:?}", plan[0].refusal);
            assert!(plan[0].first_set, "{k} must be marked first_set");
        }
        // Every OTHER key keeps the refusal — this exemption is two keys wide,
        // not a hole.
        let plan = build_plan(&["NOO_JWT_SECRET".to_string()], &sops, None, ValueSource::Stdin, "noo");
        let r = plan[0].refusal.as_ref().expect("must still refuse");
        assert!(r.contains("does not create one"), "{r}");
    }

    #[test]
    fn a_provider_key_absent_from_the_store_is_added_when_its_value_is_supplied() {
        // An optional provider key is absent on every install until the
        // feature is wanted. Handing it over must ADD it — refusing left
        // hand-editing the encrypted store as the only path (2026-09-28).
        let sops = SecretStore::from_map(BTreeMap::new(), PathBuf::from("/f/env.sops"), true);
        for (k, src) in [("TAVILY_API_KEY", ValueSource::Stdin), ("TELEGRAM_BOT_TOKEN", ValueSource::Prompt)] {
            let plan = build_plan(&[k.to_string()], &sops, Some(k), src, "noo");
            assert!(plan[0].refusal.is_none(), "{k}: {:?}", plan[0].refusal);
            assert!(plan[0].first_set, "{k} must be marked first_set");
            assert!(render_plan(&plan, false).contains("this ADDS it"), "{k}: the plan must say it adds");
        }
        // With no value supplied it still refuses — and the refusal is the
        // one that says how to supply it, not the store-editing one.
        let plan = build_plan(&["TAVILY_API_KEY".to_string()], &sops, None, ValueSource::Stdin, "noo");
        let r = plan[0].refusal.as_ref().expect("an unsupplied provider key must refuse");
        assert!(r.contains("--prompt"), "{r}");
        // A generated key handed a value is still not created: minting a
        // missing controller secret is `onboard`'s job, not a rotation.
        let plan = build_plan(&["NOO_JWT_SECRET".to_string()], &sops, Some("NOO_JWT_SECRET"), ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.as_ref().is_some_and(|r| r.contains("does not create one")));
    }

    #[test]
    fn the_two_backup_passphrases_may_not_end_up_equal() {
        let mut store = BTreeMap::new();
        store.insert("NOO_BACKUP_PASSPHRASE".to_string(), "pg-value".to_string());
        store.insert("NOO_AGE_BACKUP_PASSPHRASE".to_string(), "age-value".to_string());

        // Nothing being rotated: not this function's business.
        assert!(!backup_passphrases_would_collide(&BTreeMap::new(), &store));

        // Two fresh, different values: fine.
        let mut nv = BTreeMap::new();
        nv.insert("NOO_BACKUP_PASSPHRASE".to_string(), "a".to_string());
        nv.insert("NOO_AGE_BACKUP_PASSPHRASE".to_string(), "b".to_string());
        assert!(!backup_passphrases_would_collide(&nv, &store));

        // Two fresh, identical values.
        let mut nv = BTreeMap::new();
        nv.insert("NOO_BACKUP_PASSPHRASE".to_string(), "same".to_string());
        nv.insert("NOO_AGE_BACKUP_PASSPHRASE".to_string(), "same".to_string());
        assert!(backup_passphrases_would_collide(&nv, &store));

        // The case the prompt cannot catch: rotate ONE of them to the value
        // the OTHER already holds in the store. This is what `--set-from-stdin`
        // twice, out of a password manager, does by mistake.
        let mut nv = BTreeMap::new();
        nv.insert("NOO_AGE_BACKUP_PASSPHRASE".to_string(), "pg-value".to_string());
        assert!(
            backup_passphrases_would_collide(&nv, &store),
            "rotating the age passphrase onto the pg passphrase's value must be caught"
        );

        // An unrelated key in the same run does not trip it.
        let mut nv = BTreeMap::new();
        nv.insert("NOO_JWT_SECRET".to_string(), "pg-value".to_string());
        assert!(!backup_passphrases_would_collide(&nv, &store));

        // An install that has neither yet: a first set of one cannot collide.
        let mut nv = BTreeMap::new();
        nv.insert("NOO_BACKUP_PASSPHRASE".to_string(), "x".to_string());
        assert!(!backup_passphrases_would_collide(&nv, &BTreeMap::new()));
    }

    #[test]
    fn artifacts_are_listed_from_the_backup_dir_by_glob() {
        let dir = std::env::temp_dir().join(format!("noo-artifact-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        for n in [
            "pg_20260101_000000.sql.gz.enc",
            "pg_20260102_000000.sql.gz.enc",
            "age-key_20260101_000000.txt.enc",
            // Neither glob may match these: a PLAINTEXT leftover from before
            // the encryption requirement, and an unrelated file.
            "age-key_20260101_000000.txt",
            "notes.txt",
        ] {
            let _ = std::fs::write(dir.join(n), b"x");
        }
        // Scoped env mutation: these tests share a process.
        std::env::set_var("NOO_BACKUP_DIR", &dir);
        let pg = backup_artifacts("pg_*.sql.gz.enc");
        let age = backup_artifacts("age-key_*.txt.enc");
        std::env::remove_var("NOO_BACKUP_DIR");
        let _ = std::fs::remove_dir_all(&dir);

        let names = |v: Vec<PathBuf>| -> Vec<String> {
            v.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect()
        };
        // Newest first, so the report and the prepare order match what an
        // operator sees in `ls -t`.
        assert_eq!(
            names(pg),
            vec!["pg_20260102_000000.sql.gz.enc", "pg_20260101_000000.sql.gz.enc"]
        );
        assert_eq!(names(age), vec!["age-key_20260101_000000.txt.enc"]);
    }

    /// The smallest valid gzip member: header, empty deflate block, crc,
    /// size. Enough to carry the magic the verification checks, without
    /// pulling in a compression crate for a fixture.
    fn gzip_fixture() -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        v.extend_from_slice(&[0x03, 0x00]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    /// THE FINDING. `openssl enc -d` exits 0 for a wrong key
    /// about 1 time in 256, because PKCS#7 gives it one check — the final
    /// pad byte — and random bytes satisfy it that often. Rotation then
    /// re-encrypts the garbage, producing a backup that opens cleanly and
    /// holds nothing.
    ///
    /// This does not wait for luck. It hands `prepare_artifact` a file whose
    /// plaintext is NOT what its name says, which is exactly the state a
    /// lucky decrypt produces, and requires the refusal.
    #[test]
    fn a_decrypt_that_yields_the_wrong_shape_is_refused() {
        let dir = std::env::temp_dir().join(format!("noo-artifact-shape-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plain = dir.join("plain");
        // Right passphrase, wrong CONTENT: stands in for the random bytes a
        // wrong-but-lucky decrypt hands back.
        std::fs::write(&plain, b"\x00\x01not-a-gzip-stream").unwrap();
        let enc = dir.join("pg_shape.sql.gz.enc");
        super::openssl_enc(&plain, &enc, "pass", false).unwrap();

        let err = match super::prepare_artifact(&enc, "pass", "new") {
            Err(e) => e,
            Ok(_) => panic!("a decrypt that produced non-gzip bytes was accepted"),
        };
        assert!(err.contains("not a gzip stream"), "must name the shape: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The shapes are derived from the filename, and an unknown one is not
    /// silently treated as verified.
    #[test]
    fn the_expected_shape_comes_from_the_name() {
        assert_eq!(super::expected_magic("pg_2026.sql.gz.enc").unwrap().0, &[&[0x1f, 0x8b][..]]);
        let age = super::expected_magic("age-key_2026.txt.enc").unwrap().0;
        assert!(age.contains(&&b"# created:"[..]), "the age-keygen header form");
        assert!(age.contains(&&b"AGE-SECRET-KEY-"[..]), "and the bare key-line form");
        assert!(
            super::expected_magic("something-else.enc").is_none(),
            "an unknown artifact must report NO known shape, not a wrong one"
        );
    }

    #[test]
    fn a_missing_backup_dir_is_empty_not_an_error() {
        // A box that has never backed up is the normal first-set case; the
        // rotation must set the passphrase, not refuse because no files exist.
        std::env::set_var("NOO_BACKUP_DIR", "/nonexistent/noo-backups-xyz");
        let v = backup_artifacts("pg_*.sql.gz.enc");
        std::env::remove_var("NOO_BACKUP_DIR");
        assert!(v.is_empty());
    }

    #[test]
    fn an_artifact_round_trips_through_a_rotation() {
        // openssl is how backup-controller.sh writes these files, so the
        // re-encrypt has to be byte-compatible with it. Prove it by writing
        // one the same way and reading it back after the rotation.
        let dir = std::env::temp_dir().join(format!("noo-artifact-rt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plain = dir.join("plain");
        std::fs::write(&plain, b"AGE-SECRET-KEY-PLACEHOLDER-CONTENT\n").unwrap();
        let enc = dir.join("age-key_x.txt.enc");
        super::openssl_enc(&plain, &enc, "old-pass", false).expect("seed encrypt");

        let prepared = super::prepare_artifact(&enc, "old-pass", "new-pass").expect("prepare");
        // The ORIGINAL is untouched until commit — that is the whole
        // prepare/commit contract.
        super::openssl_enc(&enc, &dir.join("check-old"), "old-pass", true)
            .expect("original must still open with the OLD passphrase");
        prepared.commit().expect("commit");
        let back = dir.join("back");
        super::openssl_enc(&enc, &back, "new-pass", true).expect("must open with the NEW passphrase");
        assert_eq!(std::fs::read(&back).unwrap(), b"AGE-SECRET-KEY-PLACEHOLDER-CONTENT\n");
        // And the old passphrase must no longer open it. Judged by CONTENT,
        // not exit status: `openssl enc -d` with a wrong passphrase exits 0
        // about one time in 256
        // was fixed for), and this assertion flaked on exactly that (2026-09-24).
        let nope = dir.join("nope");
        let opened = super::openssl_enc(&enc, &nope, "old-pass", true).is_ok()
            && std::fs::read(&nope).ok().as_deref() == Some(&b"AGE-SECRET-KEY-PLACEHOLDER-CONTENT\n"[..]);
        assert!(!opened, "the old passphrase still yields the plaintext");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_current_passphrase_is_refused_without_touching_the_file() {
        let dir = std::env::temp_dir().join(format!("noo-artifact-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plain = dir.join("plain");
        // A REAL gzip member, because the verification is now on content:
        // the old fixture was `b"payload"` under a `.gz.` name, which no
        // actual dump ever looks like. A test whose fixture cannot pass the
        // check it is exercising proves nothing about the check.
        std::fs::write(&plain, gzip_fixture()).unwrap();
        let enc = dir.join("pg_x.sql.gz.enc");
        super::openssl_enc(&plain, &enc, "real", false).unwrap();
        let before = std::fs::read(&enc).unwrap();

        let err = match super::prepare_artifact(&enc, "wrong", "new") {
            Err(e) => e,
            Ok(_) => panic!("prepare_artifact accepted the WRONG current passphrase"),
        };
        assert!(err.contains("CURRENT passphrase does not open it"), "{err}");
        assert_eq!(std::fs::read(&enc).unwrap(), before, "the original was modified");
        // No temp litter left behind.
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("rotating") || n.contains(".plain."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_glob_for_each_backup_passphrase_names_what_backup_controller_writes() {
        // The passphrase and the files it opens are declared together, and
        // these are the exact two names scripts/backup-controller.sh emits.
        // A glob that matches nothing would make rotation report "0 artifacts"
        // on a box full of backups and leave every one of them locked to a
        // value no longer recorded anywhere.
        let mut seen = Vec::new();
        for s in registry() {
            if let Class::BackupPassphrase { glob } = s.class {
                seen.push((s.key, glob));
                assert_eq!(glob.matches('*').count(), 1, "{}: exactly one '*'", s.key);
            }
        }
        assert_eq!(
            seen,
            vec![
                ("NOO_BACKUP_PASSPHRASE", "pg_*.sql.gz.enc"),
                ("NOO_AGE_BACKUP_PASSPHRASE", "age-key_*.txt.enc"),
            ]
        );
    }

    #[test]
    fn fleet_wide_secrets_are_refused_with_the_full_sequence() {
        let sops = fixture_sops();
        let plan = build_plan(&["NOO_CLUSTER_SECRET".to_string()], &sops, None, ValueSource::Stdin, "noo");
        let r = plan[0].refusal.as_ref().expect("must refuse");
        assert!(r.contains("EVERY node"));
        assert!(r.contains("cluster init-secret"));
        assert!(r.contains("cluster upgrade-agents"));
        assert_eq!(plan[0].disposition, "refused");
        // The sequence now hands the per-node half to a real command instead
        // of leaving the operator to hand-edit four `.env` files — but the
        // REFUSAL itself must survive that. `push-secrets` converges nodes
        // onto what the controller already runs; it does not make minting a
        // new fleet-wide value safe, and this test exists so a future edit
        // cannot quietly turn the handoff into an auto-push.
        assert!(r.contains("noo cluster push-secrets"), "must name the tool for the second half");
        assert!(
            r.contains("no online rotation"),
            "must keep saying the fleet is DOWN during the window"
        );
        assert!(
            r.contains("RUNNING gateway"),
            "must warn that push-secrets refuses until the controller is on the new value"
        );
        // --set-from-stdin does NOT unlock it: the store is not the problem,
        // the nodes are.
        let plan =
            build_plan(&["NOO_CLUSTER_SECRET".into()], &sops, Some("NOO_CLUSTER_SECRET"), ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.is_some());
    }

    #[test]
    fn provider_issued_needs_stdin_and_says_how() {
        let sops = fixture_sops();
        let plan = build_plan(&["HF_TOKEN".to_string()], &sops, None, ValueSource::Stdin, "noo");
        let r = plan[0].refusal.as_ref().expect("must refuse without stdin");
        assert!(r.contains("--set-from-stdin"));
        assert!(r.contains("CANNOT be generated"));
        // With --set-from-stdin it is allowed through.
        let plan = build_plan(&["HF_TOKEN".into()], &sops, Some("HF_TOKEN"), ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.is_none());
        assert_eq!(plan[0].source, ValueSource::Stdin);
    }

    #[test]
    fn unknown_and_absent_keys_are_refused_not_invented() {
        let sops = fixture_sops();
        let plan = build_plan(&["WHO_KNOWS".to_string()], &sops, None, ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.as_ref().unwrap().contains("not in the rotation registry"));
        // Known key, but not present in this store → refuse (do not create).
        let plan = build_plan(&["REDIS_PASSWORD".to_string()], &sops, None, ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.as_ref().unwrap().contains("not present in"));
    }

    #[test]
    fn a_single_refusal_aborts_the_whole_batch() {
        let sops = fixture_sops();
        let plan = build_plan(&["POSTGRES_PASSWORD".into(), "NOO_CLUSTER_SECRET".into()], &sops, None, ValueSource::Stdin, "noo");
        assert!(plan[0].refusal.is_none());
        assert!(plan[1].refusal.is_some());
        let rendered = render_plan(&plan, false);
        assert!(rendered.contains("1 of 2 key(s) REFUSED"));
        assert!(rendered.contains("all-or-nothing"));
    }

    #[test]
    fn dotenv_parsing_matches_the_loader() {
        let m = parse_dotenv(
            "# comment\n\
             export FOO=bar\n\
             QUOTED=\"has spaces\"\n\
             SINGLE='sq'\n\
             BLANK=\n\
             not a line\n\
             BAD-KEY=x\n\
             WITH_EQ=a=b\n",
        );
        assert_eq!(m.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(m.get("QUOTED").map(String::as_str), Some("has spaces"));
        assert_eq!(m.get("SINGLE").map(String::as_str), Some("sq"));
        assert_eq!(m.get("BLANK").map(String::as_str), Some(""));
        assert_eq!(m.get("WITH_EQ").map(String::as_str), Some("a=b"));
        assert!(!m.contains_key("BAD-KEY"));
        assert_eq!(m.len(), 5);
    }

    #[test]
    fn dotenv_round_trips_through_the_serializer() {
        let text = "A=1\nB=two\nC=\n";
        let m = parse_dotenv(text);
        assert_eq!(parse_dotenv(&to_dotenv(&m)), m);
    }

    #[test]
    fn credential_shape_heuristic() {
        for k in [
            "POSTGRES_PASSWORD",
            "NOO_JWT_SECRET",
            "TELEGRAM_BOT_TOKEN",
            "SOME_API_KEY",
            "X_PASSPHRASE",
            "SOME_AUTHTOKEN",
        ] {
            assert!(looks_like_credential(k), "{k} should look like a credential");
        }
        for k in [
            "NOO_NODE_NAME",
            "NOO_TLS_CERT_FILE",
            "SOPS_AGE_KEY_FILE",
            "NOO_PKI_DIR",
            "POSTGRES_USER",
            // The one that matters: a bootstrap flag whose correct home IS
            // `.env`. Flagging it would put a permanent false ERROR on every
            // healthy install.
            "NOO_SECRETS_BACKEND",
            "NOO_TRELLION_ENABLED",
            // The Intelligent-tier switch, same shape.
            "NOO_TRELLION_INTEL_ENABLED",
            // The third live bootstrap flag (dev vs dist install) — covered
            // by the `_MODE` config suffix, pinned here so a suffix-list
            // edit cannot silently start flagging it.
            "NOO_INSTALL_MODE",
            // the bootstrap pair: the instance name + port offset are
            // needed before compose files are chosen, so `.env` is their
            // sanctioned home (scripts/lib-instance.sh reads them there).
            "NOO_INSTANCE",
            "NOO_PORT_OFFSET",
            "NOO_GATEWAY_URL",
        ] {
            assert!(!looks_like_credential(k), "{k} should NOT be flagged");
        }
    }

    #[test]
    fn blank_values_get_no_digest() {
        let mut m = BTreeMap::new();
        m.insert("REDIS_PASSWORD".to_string(), String::new());
        let s = SecretStore::from_map(m, PathBuf::from("/f/env.sops"), true);
        assert_eq!(s.state("REDIS_PASSWORD"), State::Blank);
        // sha256("") = e3b0c442… — printing it would look like a real digest
        // AND confirm the emptiness to anyone who recognises the constant.
        assert_eq!(s.sha8("REDIS_PASSWORD"), None);
        let rendered = render_audit(
            &audit_rows(&s, &SecretStore::from_map(BTreeMap::new(), PathBuf::from("/f/.env"), false)),
            &[],
            &s,
            &SecretStore::from_map(BTreeMap::new(), PathBuf::from("/f/.env"), false),
            true,
        );
        assert!(!rendered.contains("e3b0c442"));
    }

    #[test]
    fn sql_quoting_escapes_embedded_quotes() {
        assert_eq!(sql_quote("abc"), "'abc'");
        assert_eq!(sql_quote("a'b"), "'a''b'");
        assert_eq!(sql_quote("';DROP TABLE x;--"), "''';DROP TABLE x;--'");
    }

    #[test]
    fn sha8_is_stable_and_short() {
        let a = sha8_of("hello");
        assert_eq!(a.len(), 8);
        assert_eq!(a, sha8_of("hello"));
        assert_ne!(a, sha8_of("hellp"));
    }

    /// The registry is the contract the docs describe; keep them in step.
    #[test]
    fn registry_is_well_formed() {
        let mut seen = BTreeSet::new();
        for s in registry() {
            assert!(seen.insert(s.key), "duplicate registry key {}", s.key);
            assert!(!s.consequence.is_empty(), "{} has no consequence", s.key);
            assert!(!s.consumers.is_empty() || CLI_ONLY_SECRETS.contains(&s.key), "{} lists no consumers", s.key);
            if s.class.self_generatable() {
                assert!(s.gen_bytes >= 32, "{} generates too little entropy", s.key);
            } else {
                assert_eq!(s.gen_bytes, 0, "{} must not claim generation", s.key);
            }
            // Every Derived entry must point at a parent that actually exists
            // in the registry — a dangling edge would silently drop the
            // re-mint step from the parent's plan, which is the entire
            // failure this class was added to prevent.
            if let Class::Derived { parent, mint } = s.class {
                assert!(
                    spec_for(parent).is_some(),
                    "{} derives from unknown key {parent}",
                    s.key
                );
                assert!(!mint.is_empty(), "{} has no mint recipe", s.key);
            }
        }
    }



    /// The four credentials retired on 2026-08-03 must not creep back into
    /// the registry: a rotation plan for a variable nothing reads is a
    /// standing invitation to re-introduce the variable.
    #[test]
    fn retired_credentials_stay_out_of_the_registry() {
        for gone in [
            "NOO_API_KEY",
            "NOO_SERVICE_API_KEY",
            "NOO_MCP_EXTERNAL_TOKEN",
            "NGROK_AUTHTOKEN",
            // 2026-09-30: the operator door takes per-admin keys only.
            "NOO_MCP_TOKEN",
            "NOO_MCP_TOKEN_PREVIOUS",
        ] {
            assert!(
                spec_for(gone).is_none(),
                "{gone} was retired — it must not have a rotation plan"
            );
        }
    }

    // ── resync decision table ────────────────────────────────────────────

    /// The only verdict that may trigger an `ALTER ROLE` is a confirmed
    /// rejection. Everything else — including both flavours of "we could not
    /// tell" — must decline.
    ///
    /// This is the whole safety argument for letting resync run unattended,
    /// so it is asserted exhaustively rather than by example.
    #[test]
    fn only_a_confirmed_drift_alters_a_role() {
        for verdict in [
            ProbeVerdict::Authenticates,
            ProbeVerdict::CannotTell,
            ProbeVerdict::Unreachable,
            ProbeVerdict::Drifted,
        ] {
            let action = resync_action(verdict, false);
            let alters = action == ResyncAction::Alter;
            assert_eq!(
                alters,
                verdict == ProbeVerdict::Drifted,
                "verdict {verdict:?} produced {action:?}"
            );
        }
    }

    /// An unreachable Postgres is evidence about the network, not the
    /// password. Treating it as drift would make the repair tool fire during
    /// exactly the outage it is meant to sit out.
    #[test]
    fn an_unreachable_database_is_never_treated_as_drift() {
        assert!(matches!(
            resync_action(ProbeVerdict::Unreachable, false),
            ResyncAction::Refuse(_)
        ));
        assert!(matches!(
            resync_action(ProbeVerdict::CannotTell, false),
            ResyncAction::Refuse(_)
        ));
    }

    #[test]
    fn dry_run_never_alters_anything() {
        for verdict in [
            ProbeVerdict::Authenticates,
            ProbeVerdict::CannotTell,
            ProbeVerdict::Unreachable,
            ProbeVerdict::Drifted,
        ] {
            assert_ne!(resync_action(verdict, true), ResyncAction::Alter);
        }
    }

    #[test]
    fn an_already_correct_role_is_a_no_op() {
        assert_eq!(
            resync_action(ProbeVerdict::Authenticates, false),
            ResyncAction::Skip
        );
    }

    /// `role: None` means the superuser the image creates, named by
    /// POSTGRES_USER — resolved identically by rotate, audit and resync. A
    /// divergence here would have resync converge a different role than the
    /// audit reported on.
    #[test]
    fn superuser_role_resolves_from_the_environment() {
        std::env::set_var("POSTGRES_USER", "pgadmin-test");
        assert_eq!(
            db_role_of(Class::DbPassword { role: None }).as_deref(),
            Some("pgadmin-test")
        );
        std::env::remove_var("POSTGRES_USER");
        assert_eq!(
            db_role_of(Class::DbPassword {
                role: Some("noo_app")
            })
            .as_deref(),
            Some("noo_app")
        );
        assert_eq!(db_role_of(Class::SharedService), None);
    }

    /// The audit's remedy must name the command that actually exists and is
    /// the right shape for the problem. It pointed at `rotate` until
    /// 2026-08-03, which mints a new secret and needs every consumer
    /// recreated to fix a disagreement the consumers are not part of.
    #[test]
    fn the_audit_remedy_points_at_resync() {
        let src = include_str!("secrets.rs");
        let marker = "db-password-does-not-authenticate";
        let at = src.find(marker).expect("finding kind not found");
        let window = &src[at..at + 900];
        assert!(
            window.contains("noo security secrets resync"),
            "the drift finding must point at resync"
        );
    }
}

#[cfg(test)]
mod provision_tests {
    use super::{
        addon_decl, classify_provision, mint_mode, provision_request, provision_targets,
        provisioned_scopes, registry,
        scope_diff, MintMode, ProvisionOutcome, Requirement, ADDON_DECLS, ADDON_KEY_SPECS,
        CORE_REGISTRY, addon_decls, runtime_addon_rows_at, trusted_addon_overlay, TEST_BUNDLED_DECLS,
    };

    /// One word resolves to all three names a per-consumer key answers to.
    /// Getting this wrong provisions the wrong thing quietly.
    #[test]
    fn one_word_resolves_to_consumer_secret_and_containers() {
        let t = provision_targets("trellion-intel").expect("a known per-consumer key");
        assert_eq!(t.consumer, "svc:trellion-intel");
        assert_eq!(t.secret_key, "NOO_SVC_KEY_TRELLION_INTEL");
        assert!(t.containers.contains(&"noo-trellion-intel".to_string()));
        assert_eq!(t.addon.as_deref(), Some("trellion_intel"));
        assert_eq!(t.overlay.as_deref(), Some("addons/trellion_intel/docker-compose.yml"));
        // Every spelling of the same add-on lands on the same declaration.
        for word in ["trellion_intel", "svc:trellion-intel", "NOO_SVC_KEY_TRELLION_INTEL"] {
            assert_eq!(provision_targets(word).as_ref(), Some(&t), "{word}");
        }
    }

    /// A crate-only build (no repo tree) embeds no overlays and so derives no
    /// add-on rows. That must fail these tests, not let every test below that
    /// iterates the declarations pass over an empty table.
    #[test]
    fn addon_declarations_are_embedded() {
        assert!(!ADDON_DECLS.is_empty(), "no declaration embedded");
        assert!(ADDON_DECLS.iter().any(|d| d.addon == "trellion"), "trellion's overlay ships in this tree");
        for a in ["trellion", "trellion_intel", "evolve"] {
            assert!(addon_decl(a).is_some(), "{a} declares no key");
        }
        for d in addon_decls() {
            assert!(crate::commands::addons::row(d.addon).is_some(),
                "{} declares addon {:?}, which is not an ADDON_ROWS key", d.overlay, d.addon);
        }
        // N6: no licensed add-on's overlay is embedded; each comes from its bundle.
        for d in ADDON_DECLS {
            assert!(crate::commands::addons::row(d.addon).and_then(|r| r.licensed).is_none(),
                "{} is a licensed add-on's overlay embedded in core", d.overlay);
        }
    }

    /// The run-time reader trusts a bundled overlay only while it hashes to
    /// the pinned lock. An edited file declares nothing.
    #[test]
    fn a_bundled_declaration_is_read_only_while_it_matches_its_signed_lock() {
        use crate::addons::{pins, resolve};
        let d = std::env::temp_dir().join(format!("noo-runtime-decls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".env"), "NOO_IMAGE_TAG=v0.6.0\n").unwrap();
        let text = TEST_BUNDLED_DECLS[0].1;
        let mut l = resolve::tests::lock("1.2.0", &["v0.6.0"], None);
        l.format = crate::addon_lock::FORMAT_V2.into();
        let files = std::collections::BTreeMap::from([(crate::addon_lock::OVERLAY_FILE.to_string(), text.as_bytes().to_vec())]);
        l.files = files.iter().map(|(n, b)| (n.clone(), crate::addon_lock::sha256_ref(b))).collect();
        let (bytes, sig) = crate::addon_lock::sign(&l, &resolve::tests::seed()).unwrap();
        let f = crate::addons::lock_fetch::Fetched { lock: bytes, sig, files };
        let want = resolve::Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock: None, pinned: None, pin: None, allow_downgrade: false };
        let v = resolve::check(&f, &resolve::tests::anchor(), &want).unwrap();
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0", None).unwrap();

        let rows = runtime_addon_rows_at(&d);
        assert_eq!(rows.len(), 1, "{:?}", rows.iter().map(|r| r.0).collect::<Vec<_>>());
        assert_eq!(rows[0].0.key, "NOO_SVC_KEY_TRELLION_INTEL");
        assert_eq!(rows[0].0.overlay, "addons/trellion_intel/docker-compose.yml");
        assert!(rows[0].1.consequence.contains("addons/trellion_intel/docker-compose.yml"));

        // Widened on disk: no longer the signed bytes, so nothing is declared.
        let overlay = pins::addon_dir(&d, "trellion_intel").join("docker-compose.yml");
        std::fs::write(&overlay, text.replace("metrics]", "metrics, config:agent]")).unwrap();
        assert!(trusted_addon_overlay(&d, "trellion_intel").is_none());
        assert!(runtime_addon_rows_at(&d).is_empty());

        // A slice-root overlay an earlier CLI left behind declares nothing.
        std::fs::remove_dir_all(pins::addon_dir(&d, "trellion_intel")).unwrap();
        std::fs::write(d.join("docker-compose.evolve.yml"), TEST_BUNDLED_DECLS[1].1).unwrap();
        assert!(trusted_addon_overlay(&d, "evolve").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A third-party add-on (no `ADDON_ROWS` row) whose verified bundle
    /// declares `x-noo-addon` + resources.json (addon_key, shared_secret) +
    /// system.json: after its lock is pinned, the table `noo addons enable`
    /// plans and issues the gateway key from declares that key, the same
    /// variable the launcher's `addon_key` resource reads, and the bundle's
    /// shared secret is readable for the enable's mint. The 0.6.13-rc.2
    /// rehearsal (rhres): the table read only licensed rows, the enable
    /// planned `NotDeclared` and issued no key, and the launcher refused
    /// `addon-key: NOO_SVC_KEY_RHRES is not in the encrypted store`.
    #[test]
    fn a_pinned_third_party_bundle_declares_its_gateway_key() {
        use crate::addons::{decls, resolve};
        let addon = "rhaddon";
        assert!(resolve::third_party(addon), "the fixture must be an add-on the CLI does not ship");
        let d = std::env::temp_dir().join(format!("noo-runtime-decls-3p-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".env"), "NOO_IMAGE_TAG=v0.6.0\n").unwrap();
        let files = std::collections::BTreeMap::from([
            ("docker-compose.yml".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/docker-compose.yml").to_vec()),
            ("resources.json".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/resources.json").to_vec()),
            ("system.json".to_string(), include_bytes!("../../../tests/fixtures/addons/rhaddon/system.json").to_vec()),
        ]);
        let mut l = resolve::tests::lock("0.1.0", &["v0.6.0"], None);
        l.format = crate::addon_lock::FORMAT_V2.into();
        l.addon = addon.into();
        l.files = files.iter().map(|(n, b)| (n.clone(), crate::addon_lock::sha256_ref(b))).collect();
        let (bytes, sig) = crate::addon_lock::sign(&l, &resolve::tests::seed()).unwrap();
        let f = crate::addons::lock_fetch::Fetched { lock: bytes, sig, files: files.clone() };
        let want = resolve::Want { addon, stack_tag: "v0.6.0", stack_lock: None, pinned: None, pin: None, allow_downgrade: false };
        let v = resolve::check(&f, &resolve::tests::anchor(), &want).unwrap();
        resolve::record(&d, addon, &v, &f, "v0.6.0", None).unwrap();

        let rows = runtime_addon_rows_at(&d);
        let row = rows.iter().find(|(r, _)| r.addon == addon).unwrap_or_else(|| {
            panic!("a pinned third-party add-on declares no key: {:?}", rows.iter().map(|r| r.0.addon).collect::<Vec<_>>())
        });
        assert_eq!(row.0.key, "NOO_SVC_KEY_RHADDON");
        assert_eq!(row.0.consumer, "svc:rhaddon");
        assert_eq!(row.0.containers, ["noo-rhaddon"]);
        assert_eq!(row.0.scopes, ["metrics"], "the grant is the bundle's, not a default");
        assert_eq!(row.1.key, "NOO_SVC_KEY_RHADDON", "a registry row, so audit and rotate know the key");

        // The launcher reads the same variable for the `addon_key` resource.
        let facts = crate::addons::resources::bundle_facts(addon, &files);
        assert_eq!(facts.addon_key_var.as_deref(), Some(row.0.key));
        // And the enable's shared-secret mint finds the declaration where the
        // pin materialised it.
        let declared = decls::materialised(&d, addon).expect("the materialised bundle validates");
        let secrets: Vec<String> = declared
            .resources
            .expect("resources.json is materialised")
            .resources
            .iter()
            .filter(|r| r.what == crate::addons::resources::What::SharedSecret)
            .map(|r| crate::addons::resources::shared_secret_var(addon, &r.name))
            .collect();
        assert_eq!(secrets, ["NOO_ADDON_SECRET_RHADDON__PEER_KEY"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Each declaration yields exactly one registry row, holding exactly the
    /// declared containers — so `rotate` recreates what the overlay says.
    #[test]
    fn addon_rows_are_derived_from_overlays() {
        for d in addon_decls() {
            let rows: Vec<_> = registry().filter(|s| s.key == d.key).collect();
            assert_eq!(rows.len(), 1, "{} has {} registry rows", d.key, rows.len());
            assert_eq!(rows[0].consumers, d.containers, "{}", d.key);
            assert!(rows[0].consequence.contains(d.overlay), "the row names where it came from");
        }
        assert_eq!(ADDON_KEY_SPECS.len(), ADDON_DECLS.len());
        assert_eq!(registry().filter(|s| s.key.starts_with("NOO_SVC_KEY_") && !CORE_REGISTRY.iter().any(|c| c.key == s.key)).count(),
            addon_decls().len());
    }

    /// A resurrected hand-written row would be a second answer to "who holds
    /// this key" — the drift the derivation exists to end.
    #[test]
    fn no_addon_row_is_hand_written() {
        for d in addon_decls() {
            assert!(!CORE_REGISTRY.iter().any(|s| s.key == d.key),
                "{} is hand-written in CORE_REGISTRY and declared by {}", d.key, d.overlay);
        }
    }

    /// An add-on key is never required: absent falls back to the shared
    /// secret while the bridge is open, which is every install that has not
    /// provisioned yet.
    #[test]
    fn every_addon_key_row_is_optional() {
        for s in ADDON_KEY_SPECS {
            assert!(matches!(s.required_when, Requirement::Optional), "{} is not Optional", s.key);
            assert_eq!(s.gen_bytes, 0, "{} is gateway-issued; this tool never mints it", s.key);
        }
    }

    /// The registry is the single source for WHO holds a secret. Deriving the
    /// container list here instead would be a second answer to that question,
    /// which is the drift that left thirteen secrets with undeclared holders
    /// (PR 333) — and a rotation that skips a holder is silent.
    /// `worker` is the case that makes this real: the registry names
    /// noo-worker AND noo-worker-extra, because the key reaches the replica
    /// by interpolation. A naive `noo-{name}` derivation yields one of the
    /// two and recreates half the holders — silently, which is the whole
    /// failure class. An earlier version of this test used a single-container
    /// consumer and PASSED against exactly that plant.
    #[test]
    fn the_containers_come_from_the_registry_not_from_the_name() {
        let t = provision_targets("worker").expect("the worker key");
        assert!(t.containers.len() > 1, "pick a consumer with several holders or this proves nothing");
        assert!(!t.containers.contains(&"noo-worker".to_string()) || t.containers.len() >= 2);
        let spec = registry().find(|s| s.key == "NOO_SVC_KEY_WORKER").unwrap();
        let mut from_registry: Vec<String> =
            spec.consumers.iter().map(|c| (*c).to_string()).collect();
        from_registry.sort();
        let mut got = t.containers.clone();
        got.sort();
        assert_eq!(got, from_registry);
    }

    #[test]
    fn the_full_secret_name_is_accepted_too() {
        assert_eq!(
            provision_targets("NOO_SVC_KEY_TRELLION").map(|t| t.consumer),
            Some("svc:trellion".to_string())
        );
    }

    /// A name with no registry entry must not be invented into one — that
    /// would mint a key for a consumer nothing is wired to read.
    #[test]
    fn an_unknown_name_resolves_to_nothing() {
        assert!(provision_targets("not-a-service").is_none());
        assert!(provision_targets("NOO_SVC_KEY_NOPE").is_none());
    }

    /// Only one of four outcomes is success. Three of them LOOK like success
    /// if you check only the step you just ran, which is why each is named.
    #[test]
    fn an_idle_consumer_exits_zero_and_every_real_failure_exits_one() {
        use ProvisionOutcome as O;
        assert!(O::InUse.exits_zero());
        assert!(O::InstalledNotYetUsed.exits_zero());
        assert!(!O::InstalledNotYetUsed.is_success(), "still not proven in use");
        for o in [O::MintedThenRevoked, O::StoredNotRecreated, O::MintedNotStored] {
            assert!(!o.exits_zero(), "{o:?} is a real failure");
        }
    }

    #[test]
    fn exactly_one_outcome_is_success() {
        assert!(classify_provision(MintMode::Issue, true, true, true).is_success());
        for o in [
            classify_provision(MintMode::Issue, false, false, false),
            classify_provision(MintMode::Rotate, false, false, false),
            classify_provision(MintMode::Issue, true, false, false),
            classify_provision(MintMode::Issue, true, true, false),
        ] {
            assert!(!o.is_success(), "{o:?} must not read as success");
        }
    }

    /// The first failure wins. A later step cannot paper over an earlier one:
    /// "recreated" after a failed store would otherwise report the container
    /// as live on a value that was never written.
    #[test]
    fn the_earliest_failure_is_what_gets_reported() {
        assert_eq!(classify_provision(MintMode::Issue, false, true, true), ProvisionOutcome::MintedThenRevoked);
        assert_eq!(classify_provision(MintMode::Issue, true, false, true), ProvisionOutcome::StoredNotRecreated);
    }

    /// Installed-but-unused is its own outcome, not a success and not an
    /// error. A key that is stored but never presented is indistinguishable
    /// from no key at all — the rule #258 applied to a rotation, applied here
    /// to a mint.
    #[test]
    fn installed_but_never_presented_is_not_success() {
        let o = classify_provision(MintMode::Issue, true, true, false);
        assert_eq!(o, ProvisionOutcome::InstalledNotYetUsed);
        assert!(!o.is_success());
    }

    /// A key that cannot open the exchange door is half-provisioned: the
    /// consumer presents the long-lived key on every call instead of a
    /// ten-minute token, and nothing says so. The first key provisioned on
    /// the controller was minted without `addon` and did exactly that.
    #[test]
    fn a_provisioned_key_can_always_open_the_door() {
        assert!(provisioned_scopes("svc:worker", &[]).contains(&"addon".to_string()), "the default set");
        let asked = vec!["chat".to_string()];
        let got = provisioned_scopes("svc:worker", &asked);
        assert!(got.contains(&"addon".to_string()), "an explicit set gains it");
        assert!(got.contains(&"chat".to_string()), "and keeps what was asked");
        let already = vec!["addon".to_string(), "chat".to_string()];
        assert_eq!(provisioned_scopes("svc:worker", &already).iter().filter(|s| *s == "addon").count(), 1,
            "never duplicated");
    }

    /// Evolve's default is its whole reach: the graph write
    /// AND the five other writes its client makes, which the first cut left
    /// refusing its token. Inference consumers keep theirs.
    #[test]
    fn evolves_default_is_every_write_it_makes_and_the_inference_consumers_keep_chat() {
        let evolve = provisioned_scopes("svc:evolve", &[]);
        for s in ["addon", "temporal", "heartbeat", "activities", "channels:send", "metrics",
                  "config:self_identity", "config:ga", "config:cluster"] {
            assert!(evolve.contains(&s.to_string()), "{s} missing from {evolve:?}");
        }
        assert!(!evolve.iter().any(|s| s == "config:tools"), "tools is admin-only: a grant would open nothing");
        assert!(!evolve.iter().any(|s| s == "chat"), "evolve calls no inference surface");
        // Read from the overlay, not restated: the default IS the declaration.
        let declared = addon_decl("evolve").unwrap().scopes;
        assert_eq!(evolve[1..], declared.iter().map(|s| s.to_string()).collect::<Vec<_>>()[..]);
        assert_eq!(provisioned_scopes("svc:trellion-intel", &[]),
            vec!["addon".to_string(), "chat".to_string(), "embeddings".to_string(), "metrics".to_string()],
            "trellion-intel: inference plus metrics (phase C moves its counters onto the gateway)");
        // trellion also transcribes audio it ingests, through the gateway's STT routes.
        assert_eq!(provisioned_scopes("svc:trellion", &[]),
            vec!["addon".to_string(), "chat".to_string(), "embeddings".to_string(), "metrics".to_string(),
                 "voice:transcribe".to_string()],
            "trellion: inference, metrics, and the transcribe routes");
        // The core worker's default is a declared row, not a fallthrough.
        assert_eq!(provisioned_scopes("svc:worker", &[]),
            vec!["addon".to_string(), "chat".to_string(), "embeddings".to_string()]);
        // an explicit request is honoured for evolve too
        assert_eq!(provisioned_scopes("svc:evolve", &["chat".to_string()]), vec!["addon".to_string(), "chat".to_string()]);
    }

    /// The request shown before minting: every word with its route, words
    /// the issuer would refuse named BEFORE anything is minted, and the
    /// rotate diff against the key in use.
    #[test]
    fn the_request_names_each_route_and_refuses_before_minting() {
        let vocab = serde_json::json!({
            "plain": [{ "scope": "addon", "opens": ["POST /api/addon/token"] },
                      { "scope": "chat", "opens": ["POST /v1/chat/completions"] }],
            "control": [{ "scope": "metrics", "opens": ["POST /api/metrics/increment"] }],
            "config": { "prefix": "config:", "gated_sections": ["tools"] },
            "operator_only": [],
        });
        let r = provision_request("svc:x", &["chat".into(), "config:ga".into(), "config:tools".into(), "bogus".into()],
            Some(&vocab), None);
        assert_eq!(r.rows[0], ("addon".to_string(), vec!["POST /api/addon/token".to_string()]));
        assert!(r.rows.contains(&("config:ga".to_string(), vec!["PUT /api/config/ga".to_string()])));
        assert_eq!(r.refused, vec!["config:tools".to_string(), "bogus".to_string()], "gated and unknown");
        assert!(r.overridden);
        assert!(r.diff.is_none(), "an issue has nothing to diff against");

        // Rotate: trellion's key predates `metrics` in its declaration.
        let key = serde_json::json!({ "scopes": ["addon", "chat", "embeddings"] });
        let r = provision_request("svc:trellion", &[], Some(&vocab), Some(&key));
        assert!(!r.overridden);
        assert_eq!(r.declared, vec!["chat", "embeddings", "metrics", "voice:transcribe"]);
        assert_eq!(r.diff, Some((vec!["metrics".to_string(), "voice:transcribe".to_string()], vec![])));

        // An older gateway without the listing: no routes, no refusals —
        // the mint's own 400 speaks, as before.
        let r = provision_request("svc:trellion", &[], None, None);
        assert!(r.refused.is_empty() && r.rows.iter().all(|(_, o)| o.is_empty()));
    }

    #[test]
    fn a_stale_on_disk_overlay_is_noticed_and_not_obeyed() {
        let text = "x-noo-addon:\n  scopes: [chat, embeddings, temporal]\nservices: {}\n";
        assert_eq!(super::on_disk_scopes_differ(text, &["chat", "embeddings"]),
            Some(vec!["chat".to_string(), "embeddings".to_string(), "temporal".to_string()]));
        assert_eq!(super::on_disk_scopes_differ(text, &["chat", "embeddings", "temporal"]), None);
        assert_eq!(super::on_disk_scopes_differ("services: {}\n", &["chat"]), None, "no block: nothing to compare");
    }

    /// The rotate diff: what the new grant adds and what it drops.
    #[test]
    fn a_rotation_shows_what_the_grant_gains_and_loses() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let (added, removed) = scope_diff(&s(&["addon", "chat", "embeddings"]), &s(&["addon", "chat", "metrics"]));
        assert_eq!(added, s(&["metrics"]));
        assert_eq!(removed, s(&["embeddings"]));
        assert_eq!(scope_diff(&s(&["a"]), &s(&["a"])), (vec![], vec![]));
    }

    /// Re-running on an already-provisioned consumer must supersede, not
    /// issue a second active row.
    #[test]
    fn a_second_provision_rotates_rather_than_issuing_beside_the_first() {
        assert_eq!(mint_mode(false), MintMode::Issue);
        assert_eq!(mint_mode(true), MintMode::Rotate);
    }

    /// A rotation whose store failed cannot be undone by revoking — that
    /// would take the previous, working key with it. It is its own outcome,
    /// not success, and not the Issue-mode outcome that implies a revoke
    /// happened.
    #[test]
    fn a_rotation_that_could_not_be_stored_does_not_claim_a_revoke() {
        let o = classify_provision(MintMode::Rotate, false, true, true);
        assert_eq!(o, ProvisionOutcome::MintedNotStored);
        assert!(!o.is_success());
        assert_ne!(o, ProvisionOutcome::MintedThenRevoked, "no revoke happened; do not say one did");
    }

    /// The rotation case: the OLD key has a last_used_at from days of use;
    /// the NEW one has never been presented. As shipped, that read as proven.
    #[test]
    fn a_superseded_keys_history_does_not_prove_the_new_one() {
        let keys = vec![
            serde_json::json!({"consumer": "svc:x", "active": true, "superseded_at": "2026-09-22T13:53:07Z",
                               "last_used_at": "2026-09-22T13:52:22Z"}),
            serde_json::json!({"consumer": "svc:x", "active": true, "superseded_at": null,
                               "last_used_at": null}),
        ];
        assert!(!super::proven_in_use(&keys, "svc:x"),
            "the old key's use must not stand in for the new key's");
    }

    #[test]
    fn the_current_key_being_presented_is_proof() {
        let keys = vec![
            serde_json::json!({"consumer": "svc:x", "active": true, "superseded_at": "2026-09-22T13:53:07Z",
                               "last_used_at": "2026-09-22T13:52:22Z"}),
            serde_json::json!({"consumer": "svc:x", "active": true, "superseded_at": null,
                               "last_used_at": "2026-09-22T14:12:05Z"}),
        ];
        assert!(super::proven_in_use(&keys, "svc:x"));
        assert!(!super::proven_in_use(&keys, "svc:other"), "another consumer's rows say nothing");
    }

    #[test]
    fn a_revoked_or_absent_current_key_is_not_proof() {
        let revoked = vec![serde_json::json!({"consumer": "svc:x", "active": false, "superseded_at": null,
                                              "last_used_at": "2026-09-22T14:12:05Z"})];
        assert!(!super::proven_in_use(&revoked, "svc:x"));
        assert!(!super::proven_in_use(&[], "svc:x"));
    }
}

#[cfg(test)]
mod addon_requirement_tests {
    use super::*;

    /// No conditional secret may gate on a flag the launcher refuses to
    /// start on. `NOO_PRO_ENABLED` did, from 2026-09-04 until this test.
    #[test]
    fn no_secret_gates_on_a_retired_flag() {
        let retired = ["NOO_PRO_ENABLED", "NOO_TRELLION_ENABLED", "NOO_TRELLION_INTEL_ENABLED", "NOO_VOICE_ENABLED"];
        for s in registry() {
            if let Requirement::WhenEnabled(flag) = s.required_when {
                assert!(!retired.contains(&flag), "{} gates on retired flag {flag} — use WhenAddon", s.key);
            }
        }
    }

    /// An add-on requirement resolves through `addons.<name>` — the spelling
    /// in noomesh.yaml — so the audit's resolver and the message agree.
    #[test]
    fn an_addon_requirement_asks_for_its_map_key() {
        let asked = std::cell::RefCell::new(Vec::new());
        let r = Requirement::WhenAddon("evolve");
        let on = r.required(&|g: &str| {
            asked.borrow_mut().push(g.to_string());
            true
        });
        assert!(on);
        assert_eq!(*asked.borrow(), vec!["addons.evolve".to_string()]);
    }
}

// ── the store's own backups are bounded ───────────────────────────────────
//
// Every commit copies the store aside, every copy is encrypted to the same age
// recipient, and until this landed nothing ever deleted one. Eighteen had
// accumulated on the live controller since the store was created, which meant
// a rotated secret was still readable from a file on disk — rotation looked
// like it worked and revoked nothing.
#[cfg(test)]
mod store_backup_retention_tests {
    use super::{
        keep_from, prune_store_backups, store_backup_findings_with, store_backups,
    };
    use std::path::{Path, PathBuf};

    /// A store plus `n` backups beside it, each a second older than the last so
    /// the ordering under test is the one the filesystem reports, not the one
    /// the names happen to sort into.
    fn planted(tag: &str, names: &[&str]) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("noo-bak-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let store = dir.join("env.sops");
        std::fs::write(&store, b"store").expect("write store");
        for (i, n) in names.iter().enumerate() {
            let p = dir.join(n);
            std::fs::write(&p, b"backup").expect("write backup");
            // Oldest first: index 0 is the furthest in the past.
            let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + i as u64);
            filetime_set(&p, t);
        }
        (dir, store)
    }

    fn filetime_set(p: &Path, t: std::time::SystemTime) {
        let f = std::fs::File::options().write(true).open(p).expect("open");
        f.set_modified(t).expect("set mtime");
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn pruning_keeps_the_newest_and_deletes_the_rest() {
        let (dir, store) = planted(
            "prune",
            &[
                "env.sops.bak_1", "env.sops.bak_2", "env.sops.bak_3",
                "env.sops.bak_4", "env.sops.bak_5", "env.sops.bak_6",
            ],
        );
        let gone = prune_store_backups(&store, 3);
        assert_eq!(gone.len(), 3, "expected three to be pruned, got {gone:#?}");
        assert_eq!(
            names_in(&dir),
            vec![
                "env.sops".to_string(),
                "env.sops.bak_4".to_string(),
                "env.sops.bak_5".to_string(),
                "env.sops.bak_6".to_string(),
            ],
            "the newest three backups and the store itself must be what survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The absorb script writes `.bak_absorb_<unix>`, a different name for the
    /// same hazard. If only the rotate-shaped name were counted, the pile would
    /// still grow — unbounded, and silently, because the audit would agree it
    /// was within the limit.
    #[test]
    fn an_absorb_copy_is_a_store_backup_too() {
        let (dir, store) = planted(
            "absorb",
            &["env.sops.bak_1", "env.sops.bak_absorb_2", "env.sops.bak_3"],
        );
        let found = store_backups(&store);
        assert_eq!(found.len(), 3, "absorb copies were not counted: {found:#?}");
        assert!(
            found[0].ends_with("env.sops.bak_3"),
            "newest-first ordering is wrong: {found:#?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The store is the only copy of the age-encrypted values, and a rotation
    /// that goes wrong is recoverable only from the copy taken moments before.
    /// "Keep none" would trade a slow leak for an unrecoverable store.
    #[test]
    fn the_bound_is_never_zero() {
        assert_eq!(keep_from(Some("0".into())), 1);
        assert_eq!(keep_from(None), 3);
        assert_eq!(keep_from(Some("  5 ".into())), 5);
        assert_eq!(keep_from(Some("banana".into())), 3, "junk falls back, it does not disable the bound");
    }

    /// Pruning is best-effort, so the audit has to be able to see what it left
    /// behind — otherwise a directory that cannot be written to goes unnoticed
    /// forever.
    #[test]
    fn an_unpruned_pile_is_reported_and_a_bounded_one_is_not() {
        let (dir, store) = planted(
            "audit",
            &["env.sops.bak_1", "env.sops.bak_2", "env.sops.bak_3", "env.sops.bak_4"],
        );
        let over = store_backup_findings_with(&store, 3);
        assert_eq!(over.len(), 1, "four backups past a bound of three went unreported");
        assert_eq!(over[0].kind, "store-backups-unpruned");
        assert!(over[0].message.contains('4'), "the count belongs in the message: {}", over[0].message);

        assert!(
            store_backup_findings_with(&store, 4).is_empty(),
            "a pile within the bound must not be reported"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store with no backups beside it yet — a fresh install — must not trip
    /// anything, and must not panic on a directory it cannot read.
    #[test]
    fn nothing_beside_the_store_is_nothing_to_do() {
        let (dir, store) = planted("empty", &[]);
        assert!(store_backups(&store).is_empty());
        assert!(prune_store_backups(&store, 3).is_empty());
        assert!(store_backup_findings_with(&store, 3).is_empty());
        assert!(store.exists(), "the store itself must never be a prune candidate");

        let missing = dir.join("nope").join("env.sops");
        assert!(store_backups(&missing).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ── secrets have a measurable age ─────────────────────────────────────────
//
// The access-review policy commits to a ninety-day rotation interval. Nothing ever
// recorded when anything was rotated, so no person and no script could tell
// whether the policy was being kept — and the first review never happened.
#[cfg(test)]
mod rotation_age_tests {
    use super::{record_rotations, secret_age_findings_with, RotationLog, SecretStore, Severity};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_800_000_000;

    fn log(since: u64, pairs: &[(&str, u64)]) -> RotationLog {
        RotationLog {
            tracking_since: since,
            rotated: pairs.iter().map(|(k, t)| (k.to_string(), *t)).collect(),
        }
    }

    fn store(keys: &[&str]) -> SecretStore {
        let map: BTreeMap<String, String> =
            keys.iter().map(|k| (k.to_string(), "x".to_string())).collect();
        SecretStore::from_map(map, PathBuf::from("/fixture/secrets/env.sops"), true)
    }

    #[test]
    fn a_secret_past_the_interval_is_reported_by_name() {
        let l = log(NOW - 400 * DAY, &[("NOO_JWT_SECRET", NOW - 120 * DAY)]);
        let f = secret_age_findings_with(&l, &store(&["NOO_JWT_SECRET"]), NOW, 90);
        assert_eq!(f.len(), 1, "a 120-day-old secret was not reported: {f:#?}");
        assert_eq!(f[0].kind, "rotation-overdue");
        assert_eq!(f[0].key, "NOO_JWT_SECRET");
        assert!(f[0].message.contains("120"), "the age belongs in the message: {}", f[0].message);
    }

    #[test]
    fn a_secret_inside_the_interval_is_not_reported() {
        let l = log(NOW - 400 * DAY, &[("NOO_JWT_SECRET", NOW - 89 * DAY)]);
        assert!(
            secret_age_findings_with(&l, &store(&["NOO_JWT_SECRET"]), NOW, 90).is_empty(),
            "an 89-day-old secret is inside a 90-day interval"
        );
    }

    /// The reason the ledger reports a floor rather than "unknown": every
    /// secret that existed before tracking began would otherwise be exempt
    /// from the policy forever, which is the opposite of what the policy is
    /// for.
    #[test]
    fn a_key_with_no_entry_ages_from_when_tracking_began() {
        let sops = store(&["NOO_JWT_SECRET"]);
        let young = log(NOW - 10 * DAY, &[]);
        assert!(
            secret_age_findings_with(&young, &sops, NOW, 90).is_empty(),
            "ten days of tracking cannot prove a secret is overdue"
        );

        let old = log(NOW - 200 * DAY, &[]);
        let f = secret_age_findings_with(&old, &sops, NOW, 90);
        assert_eq!(f.len(), 1, "200 days with no recorded rotation is overdue: {f:#?}");
        assert!(
            f[0].message.contains("since tracking began"),
            "a floor must not be reported as an exact age: {}",
            f[0].message
        );
        assert!(
            f[0].message.contains("older still"),
            "the message must say the ledger cannot see before itself: {}",
            f[0].message
        );
    }

    /// An empty ledger must say the policy is unmeasurable, not report every
    /// secret as fine. Silence here is what the previous state looked like.
    #[test]
    fn no_ledger_at_all_is_itself_the_finding() {
        let f = secret_age_findings_with(&RotationLog::default(), &store(&["NOO_JWT_SECRET"]), NOW, 90);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "rotation-age-untracked");
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].message.contains("90"), "the interval belongs in the message: {}", f[0].message);
    }


    /// A key the registry does not know has no rotation path in this tool.
    #[test]
    fn an_unregistered_key_is_not_reported() {
        let l = log(NOW - 400 * DAY, &[]);
        assert!(secret_age_findings_with(&l, &store(&["SOMETHING_ELSE"]), NOW, 90).is_empty());
    }

    /// A ledger that cannot be parsed must read as empty, never as an error —
    /// this is observability, and it must not be able to fail a rotation.
    #[test]
    fn junk_reads_as_an_empty_ledger() {
        assert_eq!(RotationLog::parse("not json at all"), RotationLog::default());
        assert_eq!(RotationLog::parse("{}"), RotationLog::default());
        let partial = RotationLog::parse(r#"{"tracking_since": 5, "rotated": {"A": 7, "B": "x"}}"#);
        assert_eq!(partial.tracking_since, 5);
        assert_eq!(partial.rotated, [("A".to_string(), 7u64)].into_iter().collect());
    }

    #[test]
    fn recording_starts_the_ledger_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("noo-rotlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let store_path = dir.join("env.sops");

        record_rotations(&store_path, &["NOO_JWT_SECRET".into()], NOW).expect("record");
        let first = RotationLog::load(&store_path);
        assert_eq!(first.tracking_since, NOW, "the ledger must start itself");
        assert_eq!(first.rotated.get("NOO_JWT_SECRET"), Some(&NOW));

        // A later rotation updates its key and leaves the start date alone —
        // otherwise every rotation would reset the floor for every OTHER key
        // and nothing could ever age past the interval.
        record_rotations(&store_path, &["REDIS_PASSWORD".into()], NOW + 10 * DAY).expect("record");
        let second = RotationLog::load(&store_path);
        assert_eq!(second.tracking_since, NOW, "the start date moved");
        assert_eq!(second.rotated.get("NOO_JWT_SECRET"), Some(&NOW), "an untouched key changed");
        assert_eq!(second.rotated.get("REDIS_PASSWORD"), Some(&(NOW + 10 * DAY)));

        // No secret values are in it — that is why it is readable without the
        // age key.
        let raw = std::fs::read_to_string(dir.join("rotations.json")).expect("read");
        assert!(!raw.contains("\"x\""), "a value leaked into the ledger: {raw}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ── a node password nothing uses ──────────────────────────────────────────
//
// `NATS_NODE_PASSWORD_ALPHA1` has sat in the live store since the cutover.
// The canonical key for that node is `NATS_NODE_PASSWORD_ALPHA_1` and the bus
// authorises `node-alpha-1`, so the orphan authenticates nobody — and nothing
// ever pointed at it, so nobody would think to rotate it.
#[cfg(test)]
mod orphaned_node_password_tests {
    use super::super::nats_users::{render_users_conf, Principal, Role};
    use super::{orphaned_node_password_findings, SecretStore};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// Rendered by the real renderer rather than hand-written. A hand-written
    /// fixture guessed the line shape wrong on the first try — it produced no
    /// principals at all, which this check reads as "say nothing", so a
    /// hand-written fixture could have gone green while the parser matched
    /// nothing in the real file.
    fn conf() -> String {
        render_users_conf(&[
            Principal { user: "gateway".into(), hash: "$2b$11$g".into(), role: Role::Gateway },
            Principal { user: "node-alpha-1".into(), hash: "$2b$11$a".into(), role: Role::Node },
            Principal { user: "node-beta".into(), hash: "$2b$11$b".into(), role: Role::Node },
        ])
    }

    fn store(keys: &[&str]) -> SecretStore {
        let m: BTreeMap<String, String> =
            keys.iter().map(|k| (k.to_string(), "x".into())).collect();
        SecretStore::from_map(m, PathBuf::from("/fixture/secrets/env.sops"), true)
    }

    #[test]
    fn the_live_orphan_is_reported_and_the_real_keys_are_not() {
        let f = orphaned_node_password_findings(
            &store(&[
                "NATS_NODE_PASSWORD_ALPHA1",
                "NATS_NODE_PASSWORD_ALPHA_1",
                "NATS_NODE_PASSWORD_BETA",
                "NATS_GATEWAY_PASSWORD",
            ]),
            &conf(),
        );
        assert_eq!(f.len(), 1, "expected exactly the orphan: {f:#?}");
        assert_eq!(f[0].key, "NATS_NODE_PASSWORD_ALPHA1");
        assert_eq!(f[0].kind, "node-password-unused");
        assert!(
            f[0].message.contains("NATS_NODE_PASSWORD_ALPHA_1"),
            "the message must name what the bus does use: {}",
            f[0].message
        );
    }

    /// The `-` → `_` fold is lossy, so this walks node id → key name. Going
    /// the other way would have to guess whether `ALPHA_1` came from `alpha-1`
    /// or `alpha_1`, and a wrong guess reads as "this live node's password is
    /// unused" — an invitation to delete a working credential.
    #[test]
    fn a_hyphenated_node_matches_its_folded_key() {
        assert!(
            orphaned_node_password_findings(&store(&["NATS_NODE_PASSWORD_ALPHA_1"]), &conf())
                .is_empty(),
            "the canonical key for node-alpha-1 was reported as unused"
        );
    }

    /// An unreadable or principal-less file must say nothing. Saying
    /// "everything is orphaned" when the authority could not be read would
    /// invite deleting every node credential in the fleet.
    #[test]
    fn no_principals_means_no_finding() {
        for c in ["", "not a config at all", "authorization { users = [] }"] {
            assert!(
                orphaned_node_password_findings(
                    &store(&["NATS_NODE_PASSWORD_ALPHA1", "NATS_NODE_PASSWORD_BETA"]),
                    c,
                )
                .is_empty(),
                "an empty authority produced findings for {c:?}"
            );
        }
    }

    /// Only node passwords. The gateway and worker principals are named
    /// differently and are not derivable from the node list.
    #[test]
    fn only_node_passwords_are_judged() {
        let f = orphaned_node_password_findings(
            &store(&["NATS_GATEWAY_PASSWORD", "NATS_WORKER_PASSWORD", "NATS_PASSWORD"]),
            &conf(),
        );
        assert!(f.is_empty(), "a non-node key was judged against the node list: {f:#?}");
    }
}

#[cfg(test)]
mod login_classification_tests {
    use super::*;

    /// The exact stderr the controller's Postgres 18 printed on 2026-09-23.
    const WRONG_PW: &str = "psql: error: connection to server at \"172.19.0.4\", port 5432 failed: \
        FATAL:  password authentication failed for user \"noo_trellion\"\nconnection to server at \
        \"172.19.0.4\", port 5432 failed: FATAL:  password authentication failed for user \"noo_trellion\"\n";

    #[test]
    fn a_wrong_password_is_rejected() {
        assert_eq!(classify_login(false, "", WRONG_PW), Login::Rejected);
    }

    #[test]
    fn the_right_password_is_accepted() {
        assert_eq!(classify_login(true, "1\n", ""), Login::Accepted);
    }

    /// The shape that hid for three weeks: authentication passes, then the
    /// database the check hardcoded is not there. `Unreachable` here made
    /// every role on the controller read as "could not be verified".
    #[test]
    fn a_missing_database_is_the_checks_mistake_not_the_networks() {
        let err = "psql: error: connection to server at \"172.19.0.4\", port 5432 failed: \
            FATAL:  database \"noo\" does not exist\n";
        match classify_login(false, "", err) {
            Login::Misconfigured(why) => assert!(why.contains("database \"noo\" does not exist"), "{why}"),
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        let err = "psql: error: FATAL:  role \"nope\" does not exist\n";
        assert!(matches!(classify_login(false, "", err), Login::Misconfigured(_)));
        let err = "psql: error: FATAL:  no pg_hba.conf entry for host \"172.19.0.9\", user \"noo\"\n";
        assert!(matches!(classify_login(false, "", err), Login::Misconfigured(_)));
    }

    /// 2026-09-28: pg_hba requires a client certificate from every TCP
    /// client. A probe that arrives without one is refused BEFORE the
    /// password is looked at — that is the check's fault, not the store's,
    /// and must not read as "unreachable" (which would hide a broken probe
    /// behind "could not be verified" forever). Exact stderr from a real
    /// Postgres 18 with the shipped pg_hba.
    #[test]
    fn a_probe_without_a_client_certificate_is_the_checks_mistake() {
        let err = "psql: error: connection to server at \"172.17.0.3\", port 5432 failed: \
            FATAL:  connection requires a valid client certificate\n";
        assert!(matches!(classify_login(false, "", err), Login::Misconfigured(_)));
        let err = "psql: error: connection to server at \"127.0.0.1\", port 5432 failed: \
            FATAL:  pg_hba.conf rejects connection for host \"127.0.0.1\", user \"noo\", database \"noomesh\", no encryption\n";
        assert!(matches!(classify_login(false, "", err), Login::Misconfigured(_)));
        let err = "psql: error: connection to server at \"127.0.0.1\", port 5432 failed: \
            private key file \"/p/gateway.key\" has group or world access; file must have permissions u=rw (0600) or less\n";
        assert!(matches!(classify_login(false, "", err), Login::Misconfigured(_)));
    }

    #[test]
    fn a_server_that_is_down_is_unreachable() {
        let err = "psql: error: connection to server at \"172.19.0.4\", port 5432 failed: Connection refused\n";
        assert_eq!(classify_login(false, "", err), Login::Unreachable);
    }

    #[test]
    fn the_database_name_never_defaults_to_the_old_hardcode() {
        std::env::remove_var("POSTGRES_DB");
        assert_ne!(postgres_db(), "noo", "the old hardcoded default is what broke the check");
    }
}

#[cfg(test)]
mod sops_resolution_tests {
    use super::*;

    /// `~/.local/bin` is where the installer puts sops and where a
    /// non-interactive PATH does not look. The CLI looks there, then in
    /// /usr/local/bin, then beside itself — and says where it looked.
    #[test]
    fn find_sops_looks_past_path_into_the_installer_dirs() {
        let home = Path::new("/home/u");
        let exe = Path::new("/opt/noo/bin");
        let planted = |where_: &'static str| move |p: &Path| p == Path::new(where_);

        // On PATH: PATH wins.
        assert_eq!(
            find_sops_in("/usr/bin:/bin", Some(home), Some(exe), &planted("/usr/bin/sops")).unwrap(),
            PathBuf::from("/usr/bin/sops")
        );
        // Off PATH, in ~/.local/bin — the ssh case.
        assert_eq!(
            find_sops_in("/usr/bin:/bin", Some(home), Some(exe), &planted("/home/u/.local/bin/sops")).unwrap(),
            PathBuf::from("/home/u/.local/bin/sops")
        );
        // Beside the CLI.
        assert_eq!(
            find_sops_in("/usr/bin", Some(home), Some(exe), &planted("/opt/noo/bin/sops")).unwrap(),
            PathBuf::from("/opt/noo/bin/sops")
        );
        // Nowhere: a classified error that lists the places.
        let err = find_sops_in("/usr/bin::", Some(home), Some(exe), &|_| false).unwrap_err();
        assert_eq!(err.kind(), "sops_not_found");
        let text = err.to_string();
        for needle in ["PATH", "/home/u/.local/bin", "/usr/local/bin", "/opt/noo/bin", "noo-secrets-sops-init.sh"] {
            assert!(text.contains(needle), "missing {needle:?}: {text}");
        }
    }

    /// The three failures are three different sentences with three
    /// different remedies — none of them "set the secret".
    #[test]
    fn store_load_errors_are_distinguishable() {
        let not_found = StoreLoadError::SopsNotFound { searched: "PATH".into() };
        let no_key = StoreLoadError::DecryptFailed { path: "/r/secrets/env.sops".into(), exit: 1, age_key_present: false };
        let wrong_key = StoreLoadError::DecryptFailed { path: "/r/secrets/env.sops".into(), exit: 1, age_key_present: true };
        let kinds = [not_found.kind(), no_key.kind(), wrong_key.kind()];
        assert_eq!(kinds, ["sops_not_found", "age_key_missing", "decrypt_failed"]);
        let texts = [not_found.to_string(), no_key.to_string(), wrong_key.to_string()];
        assert_ne!(texts[0], texts[1]);
        assert_ne!(texts[1], texts[2]);
        assert!(texts[1].contains("no age key"), "{}", texts[1]);
        assert!(texts[2].contains("does not open this store"), "{}", texts[2]);
        for t in &texts {
            assert!(!t.to_ascii_lowercase().contains("unset"), "a reader failure is never 'unset': {t}");
        }
        // The String form callers get is the same sentence.
        assert_eq!(
            SecretStore::load_sops(Path::new("/definitely/not/here/env.sops")).map(|s| s.existed),
            Ok(false),
            "a missing store is not an error"
        );
    }
}

#[cfg(test)]
mod clifix_security_tests {
    #[test]
    fn tidy_confirms_before_it_writes_anything() {
        let src = include_str!("secrets.rs");
        let start = src.find("pub fn secrets_tidy(").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        let c = body.find("confirm_prompt(").expect("tidy never confirms");
        let w = body.find("tidy_plaintext(").expect("tidy no longer thins .env");
        assert!(c < w, "the confirmation must precede the first write");
        assert!(body.contains("\"--yes\"") && body.contains("\"-y\""));
    }
    #[test]
    fn pins_in_names_only_the_channel_keys_the_store_holds() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("NOO_IMAGE_PREFIX".to_string(), "x".to_string());
        m.insert("OTHER".to_string(), "y".to_string());
        let keys = ["NOO_CLI_REPO", "NOO_IMAGE_PREFIX", "NOO_BASE_REGISTRY"];
        assert_eq!(super::pins_in(&m, &keys), ["NOO_IMAGE_PREFIX"]);
        assert!(super::pins_in(&std::collections::BTreeMap::new(), &keys).is_empty());
    }

}
