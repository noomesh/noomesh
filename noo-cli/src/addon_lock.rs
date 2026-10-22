// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Signed add-on locks.
//!
//! An add-on (an `ADDON_ROWS` key such as `evolve`) releases from its own
//! repository with its own lock: which images, by digest, make up one
//! add-on version, and which stack versions it runs against. The lock is
//! JSON in one canonical form (struct fields in declaration order, maps
//! sorted, no whitespace), signed in the same `noo-sig1` envelope as the
//! stack lock (`release_sig::sign` / `release_sig::verify_with_keys`, over
//! the exact bytes). The crypto is not forked.
//!
//! What this module does NOT decide is whom to trust. The caller hands
//! [`verify`] a [`TrustAnchor`]: the add-on's public keys (current key
//! first, the `RELEASE_PUBKEYS_HEX` rotation rule) and the registry root
//! its images must sit under. The CLI verb takes both from flags; the
//! controller path takes them from whatever names the add-on's signer for
//! this install. `TrustAnchor` deserialises from
//! `{"keys": ["<hex>"], "registry": "<root>"}`, so a block of that shape
//! can be read straight into it. The public tree therefore names no
//! add-on key and no add-on registry.
//!
//! Verification refuses, in order: a signature that does not verify
//! against the anchor's keys, bytes that are not the canonical form, an
//! unknown `format`, an `addon` other than the one asked for, an empty
//! `supports_stack`, an unreadable version or stack tag, no images, an
//! image or base digest that is not `sha256:<64 hex>`, and an image ref
//! outside the registry root or not in digest form. Stack membership, the
//! base digest and downgrades are separate pure helpers, because the
//! caller knows the stack tag, the stack lock and the pinned version; the
//! lock alone does not.
//!
//! Two formats. `noo-addon-lock/1` pins images only. `noo-addon-lock/2`
//! (N6, the add-on BUNDLE) adds `files`: every file core used to ship for
//! the add-on (its compose overlay first of all), by name and sha256, so the
//! one signature covers them too. The files travel as extra layers of the
//! same OCI artifact (`crate::addons::lock_fetch`) and are materialised under
//! `<install root>/addons/<addon>/`; [`verify_files`] holds their bytes to
//! the signed hashes. A release publishes both forms side by side, because
//! a CLI from before v2 refuses an unknown field and an unknown format.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::commands::upgrade::cmp_cli_semver;
use crate::release_sig;

/// The images-only lock format.
pub const FORMAT: &str = "noo-addon-lock/1";
/// The bundle format: [`FORMAT`] plus `files`.
pub const FORMAT_V2: &str = "noo-addon-lock/2";
/// The one file every bundle carries: the add-on's compose overlay, which
/// the launcher composes from `<install root>/addons/<addon>/`.
pub const OVERLAY_FILE: &str = "docker-compose.yml";

/// The base image an add-on is built `FROM`, by its stack-lock row name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseImage {
    /// The stack lock's row name (`trellion`).
    pub image: String,
    /// `sha256:<64 hex>`.
    pub digest: String,
}

/// One add-on version, as signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonLock {
    pub format: String,
    /// The add-on's `ADDON_ROWS` key.
    pub addon: String,
    /// The add-on's own semver (`1.2.0`).
    pub version: String,
    /// The 40-hex commit the images were built from.
    pub source_commit: String,
    /// Stack tags this version runs on, exactly (`v0.6.0`, `v0.6.0-rc.1`).
    pub supports_stack: Vec<String>,
    /// Image name to its digest-form ref (`<root>/<name>@sha256:<hex>`).
    pub images: BTreeMap<String, String>,
    /// Set when the add-on is built on a stack image and must match it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<BaseImage>,
    /// Bundle files (v2 only): file name to `sha256:<64 hex>` of its bytes.
    /// Empty, and absent from the canonical bytes, in a v1 lock.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
}

/// Whom to trust for one add-on: its signing keys (current first) and the
/// registry root every image ref must sit under. `pull`, when the licence
/// names one, is where the controller pulls from instead (the vendor's
/// add-on registry proxy): the same path on another host. It never changes
/// what is trusted: locks and image refs are still held to `registry`.
///
/// `dev` holds the add-on's temporary DEVELOPMENT keys (i163 part A,
/// `noo addons trust-key <name> <pubkey> --dev --expires <dur>`): each is
/// trusted until its `expires_at` and refused like an untrusted key after.
/// It is `serde(skip)`: an anchor read from JSON (the entitlement's `addons`
/// block, `security addon-lock verify` flags) can never carry one. Only the
/// operator's own `addon_trust` section in noomesh.yaml fills it
/// (`addons::trust::read`), so a development key is mesh-local by
/// construction and never part of a release's trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub keys: Vec<String>,
    pub registry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull: Option<String>,
    #[serde(skip)]
    pub dev: Vec<DevKey>,
}

/// A temporary development signing key for one add-on on this mesh (i163
/// part A). Never a release key: `noo addons trust-key` refuses a key that
/// is both, and release verification (`security addon-lock verify`) refuses
/// a key this install holds as a development key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevKey {
    /// 64 lowercase hex, an ed25519 public key.
    pub key: String,
    /// Unix seconds, UTC. The key verifies strictly before this instant.
    pub expires_at: i64,
}

/// `YYYY-MM-DD HH:MM UTC` for a unix time: how an expiry is shown to an
/// operator. Hand-rolled: the crate carries no date library.
pub fn utc_minute(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, (secs % 3600) / 60)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a unix time: how an expiry is stored.
pub fn utc_rfc3339(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Howard Hinnant's days-to-civil; 0 is 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Seconds since the epoch, now.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl TrustAnchor {
    /// Where this add-on's lock and images are fetched from: `pull` when
    /// the licence names one, else `registry`.
    pub fn location(&self) -> &str {
        self.pull.as_deref().map(str::trim).filter(|p| !p.is_empty()).unwrap_or_else(|| self.registry.trim())
    }

    /// `Ok(())` when `pull` is absent or a pure host swap of `registry`
    /// (same path, another host). Anything else would pull from a path the
    /// lock was not signed for.
    pub fn check_pull(&self) -> Result<(), String> {
        let Some(p) = self.pull.as_deref().map(str::trim) else { return Ok(()) };
        let path = |r: &str| r.split_once('/').map(|(_, p)| p.to_string());
        match (path(p), path(self.registry.trim())) {
            (Some(a), Some(b)) if a == b && !a.is_empty() => Ok(()),
            _ => Err(format!(
                "pull {p:?} must name the same path as registry {:?} (only the host may differ)",
                self.registry
            )),
        }
    }
}

/// `reference` (`<root>/<name>@sha256:…`, under `from`) re-rooted under
/// `to`. `None` when it does not sit under `from`.
pub fn relocate(reference: &str, from: &str, to: &str) -> Option<String> {
    let (from, to) = (from.trim(), to.trim());
    let rest = reference.strip_prefix(from)?;
    if !(rest.starts_with('/') || rest.starts_with('@') || rest.starts_with(':')) {
        return None;
    }
    Some(format!("{to}{rest}"))
}

/// A lock that passed [`verify`], with the index of the anchor key that
/// signed it (0 is the current key). A development key's index counts on
/// from the release keys (`keys.len() + i`), and `dev_expires_at` is then
/// that key's expiry: the lock is trusted only until it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLock {
    pub lock: AddonLock,
    pub key_index: usize,
    pub dev_expires_at: Option<i64>,
}

/// Why a lock was refused. `Display` is the operator-facing message
/// (sentence case, object then state, no trailing period); the remedy is
/// the caller's, because it depends on where the lock came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddonLockError {
    /// The anchor names no key.
    NoTrustedKeys,
    /// The registry root is empty or malformed.
    BadRegistryRoot(String),
    /// The signature does not verify against any trusted key.
    BadSignature(String),
    /// The bytes are not JSON of this shape.
    Malformed(String),
    /// The bytes parse but are not the canonical serialisation.
    NotCanonical,
    UnknownFormat(String),
    AddonMismatch { expected: String, found: String },
    EmptySupports,
    BadStackTag(String),
    BadVersion(String),
    BadSourceCommit(String),
    NoImages,
    BadDigest { image: String, digest: String },
    /// The ref is not `<repo>@sha256:<hex>`.
    NotDigestRef { image: String, reference: String },
    OutsideRegistry { image: String, reference: String, root: String },
    BaseMismatch { image: String, locked: String, stack: String },
    /// A v1 lock carries `files`, or a v2 lock carries none.
    FilesFormat(String),
    /// A bundle file name that is not a plain file name.
    BadFileName(String),
    /// A v2 lock without the compose overlay.
    NoOverlay,
    /// A bundle file is missing, extra, or does not hash to the lock.
    FileMismatch { name: String, why: String },
    /// The only key the lock verifies against is a development key whose
    /// `expires_at` has passed (i163 part A). Refused like an untrusted key.
    DevKeyExpired { key: String, expires_at: i64 },
}

impl fmt::Display for AddonLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AddonLockError::*;
        match self {
            NoTrustedKeys => write!(f, "Add-on lock trust has no signing key"),
            BadRegistryRoot(r) => write!(f, "Add-on registry root {r:?} is not a registry path"),
            BadSignature(e) => write!(f, "Add-on lock signature invalid: {e}"),
            Malformed(e) => write!(f, "Add-on lock unreadable: {e}"),
            NotCanonical => write!(f, "Add-on lock is not in canonical form, so its signed bytes are ambiguous"),
            UnknownFormat(v) => write!(f, "Add-on lock format {v:?} unknown to this build (reads {FORMAT})"),
            AddonMismatch { expected, found } => write!(f, "Add-on lock is for {found}, not {expected}"),
            EmptySupports => write!(f, "Add-on lock names no stack version it supports"),
            BadStackTag(t) => write!(f, "Add-on lock stack tag {t:?} is not a stack version (vX.Y.Z or vX.Y.Z-rc.N)"),
            BadVersion(v) => write!(f, "Add-on version {v:?} is not a semver version"),
            BadSourceCommit(c) => write!(f, "Add-on lock source commit {c:?} is not a 40-hex commit"),
            NoImages => write!(f, "Add-on lock names no images"),
            BadDigest { image, digest } => write!(f, "Add-on image {image} digest {digest:?} is not sha256:<64 hex>"),
            NotDigestRef { image, reference } => write!(f, "Add-on image {image} ref {reference} is not pinned by digest"),
            OutsideRegistry { image, reference, root } => {
                write!(f, "Add-on image {image} ref {reference} is outside the trusted registry {root}")
            }
            BaseMismatch { image, locked, stack } => write!(
                f,
                "Add-on base {image} mismatch: built on {locked}, the stack lock pins {stack}"
            ),
            FilesFormat(why) => write!(f, "Add-on lock files invalid: {why}"),
            BadFileName(n) => write!(f, "Add-on bundle file name {n:?} is not a plain file name"),
            NoOverlay => write!(f, "Add-on bundle carries no {OVERLAY_FILE}"),
            FileMismatch { name, why } => write!(f, "Add-on bundle file {name} {why}"),
            DevKeyExpired { key, expires_at } => write!(
                f,
                "Add-on lock is signed only by development key {}… which expired {}",
                &key[..12.min(key.len())],
                utc_minute(*expires_at)
            ),
        }
    }
}

impl std::error::Error for AddonLockError {}

/// `sha256:` followed by 64 lowercase hex characters.
pub fn is_sha256_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn is_stack_tag(t: &str) -> bool {
    t.starts_with('v') && cmp_cli_semver(t, t).is_some()
}

/// A bundle file name: one path component of `[A-Za-z0-9._-]`, not
/// starting with a dot or dash, at most 128 bytes. Never a path.
pub fn valid_file_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// `sha256:<hex>` of `bytes`.
pub fn sha256_ref(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let h: String = sha2::Sha256::digest(bytes).iter().map(|x| format!("{x:02x}")).collect();
    format!("sha256:{h}")
}

fn is_commit(c: &str) -> bool {
    c.len() == 40 && c.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A registry root is `host/path` with no tag, digest, scheme or trailing
/// slash: `ghcr.io/example/addon`.
pub fn valid_registry_root(root: &str) -> bool {
    !root.is_empty()
        && root.contains('/')
        && !root.contains("://")
        && !root.contains('@')
        && !root.contains(':')
        && !root.starts_with('/')
        && !root.ends_with('/')
        && !root.split('/').any(str::is_empty)
        && !root.chars().any(char::is_whitespace)
}

impl AddonLock {
    /// The one byte form that is signed: compact JSON, fields in declaration
    /// order, `images` sorted by name (a `BTreeMap`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Serialising a struct of strings, vectors and string maps cannot fail.
        serde_json::to_vec(self).expect("an add-on lock always serialises")
    }

    /// True when this version declares `stack_tag` (exact match: an rc and
    /// its final are different entries).
    pub fn supports(&self, stack_tag: &str) -> bool {
        let t = stack_tag.trim();
        self.supports_stack.iter().any(|s| s == t)
    }

    /// For an add-on built on a stack image, its base digest must equal the
    /// digest the stack's verified lock pins for that image. `stack_digest`
    /// may be the bare digest or a full `<repo>@sha256:…` ref. An add-on
    /// with no base (it does not build on the stack) always matches.
    pub fn base_matches(&self, stack_digest: &str) -> Result<(), AddonLockError> {
        let Some(base) = &self.base else { return Ok(()) };
        let stack = stack_digest.trim();
        let stack = stack.rsplit_once('@').map(|(_, d)| d).unwrap_or(stack);
        if stack == base.digest {
            Ok(())
        } else {
            Err(AddonLockError::BaseMismatch {
                image: base.image.clone(),
                locked: base.digest.clone(),
                stack: stack.to_string(),
            })
        }
    }

    /// Every check that needs only the lock and a registry root. [`verify`]
    /// runs it with the anchor's root; a signer runs it before signing, with
    /// `None` when it has no root to hold the refs to.
    pub fn validate(&self, expected_addon: &str, registry_root: Option<&str>) -> Result<(), AddonLockError> {
        match self.format.as_str() {
            FORMAT if !self.files.is_empty() => {
                return Err(AddonLockError::FilesFormat(format!("a {FORMAT} lock carries no files ({FORMAT_V2} does)")));
            }
            FORMAT => {}
            FORMAT_V2 => {
                if self.files.is_empty() {
                    return Err(AddonLockError::FilesFormat(format!("a {FORMAT_V2} lock lists its files")));
                }
                for (name, digest) in &self.files {
                    if !valid_file_name(name) {
                        return Err(AddonLockError::BadFileName(name.clone()));
                    }
                    if !is_sha256_digest(digest) {
                        return Err(AddonLockError::BadDigest { image: name.clone(), digest: digest.clone() });
                    }
                }
                if !self.files.contains_key(OVERLAY_FILE) {
                    return Err(AddonLockError::NoOverlay);
                }
            }
            _ => return Err(AddonLockError::UnknownFormat(self.format.clone())),
        }
        if self.addon != expected_addon {
            return Err(AddonLockError::AddonMismatch { expected: expected_addon.to_string(), found: self.addon.clone() });
        }
        if cmp_cli_semver(&self.version, &self.version).is_none() {
            return Err(AddonLockError::BadVersion(self.version.clone()));
        }
        if !is_commit(&self.source_commit) {
            return Err(AddonLockError::BadSourceCommit(self.source_commit.clone()));
        }
        if self.supports_stack.is_empty() {
            return Err(AddonLockError::EmptySupports);
        }
        if let Some(t) = self.supports_stack.iter().find(|t| !is_stack_tag(t)) {
            return Err(AddonLockError::BadStackTag(t.clone()));
        }
        if self.images.is_empty() {
            return Err(AddonLockError::NoImages);
        }
        for (name, reference) in &self.images {
            let Some((repo, digest)) = reference.rsplit_once('@') else {
                return Err(AddonLockError::NotDigestRef { image: name.clone(), reference: reference.clone() });
            };
            if !is_sha256_digest(digest) {
                return Err(AddonLockError::BadDigest { image: name.clone(), digest: digest.to_string() });
            }
            // A tag next to the digest (`repo:tag@sha256:…`) is refused: the
            // digest alone names the image, and a tag invites reading it.
            let last = repo.rsplit('/').next().unwrap_or(repo);
            if last.contains(':') {
                return Err(AddonLockError::NotDigestRef { image: name.clone(), reference: reference.clone() });
            }
            let Some(registry_root) = registry_root else { continue };
            let inside = repo == registry_root
                || repo.strip_prefix(registry_root).is_some_and(|rest| rest.starts_with('/'));
            if !inside {
                return Err(AddonLockError::OutsideRegistry {
                    image: name.clone(),
                    reference: reference.clone(),
                    root: registry_root.to_string(),
                });
            }
        }
        if let Some(b) = &self.base {
            if !is_sha256_digest(&b.digest) {
                return Err(AddonLockError::BadDigest { image: b.image.clone(), digest: b.digest.clone() });
            }
        }
        Ok(())
    }
}

/// Hold bundle files to a verified lock: exactly the names it lists, each
/// hashing to its signed digest. A v1 lock (no `files`) accepts only no
/// files. `files` is name to bytes.
pub fn verify_files(lock: &AddonLock, files: &BTreeMap<String, Vec<u8>>) -> Result<(), AddonLockError> {
    for name in files.keys() {
        if !lock.files.contains_key(name) {
            return Err(AddonLockError::FileMismatch { name: name.clone(), why: "is not listed in the signed lock".into() });
        }
    }
    for (name, want) in &lock.files {
        let Some(bytes) = files.get(name) else {
            return Err(AddonLockError::FileMismatch { name: name.clone(), why: "is missing".into() });
        };
        let got = sha256_ref(bytes);
        if &got != want {
            return Err(AddonLockError::FileMismatch {
                name: name.clone(),
                why: format!("hashes to {got}, and the signed lock says {want}"),
            });
        }
    }
    Ok(())
}

/// Sign a lock with an add-on seed (64 hex). Returns the canonical bytes
/// (write them as the lock file) and the `noo-sig1` text (its `.sig`).
pub fn sign(lock: &AddonLock, seed_hex: &str) -> Result<(Vec<u8>, String), String> {
    let key = release_sig::signing_key_from_seed_hex(seed_hex)?;
    let bytes = lock.canonical_bytes();
    let sig = release_sig::sign(&key, &bytes);
    Ok((bytes, sig))
}

/// Verify a lock's bytes and signature against one add-on's trust anchor,
/// now. See [`verify_at`].
pub fn verify(
    lock_bytes: &[u8],
    sig_text: &str,
    anchor: &TrustAnchor,
    expected_addon: &str,
) -> Result<VerifiedLock, AddonLockError> {
    verify_at(lock_bytes, sig_text, anchor, expected_addon, now_unix())
}

/// Verify a lock's bytes and signature against one add-on's trust anchor at
/// unix time `now`. The signature is checked first, over the exact bytes,
/// before anything in them is believed.
///
/// The release keys (`anchor.keys`) are tried first. Only when none of them
/// verifies are the anchor's development keys (`anchor.dev`) tried: a lock
/// one of them signed verifies while `now < expires_at` and is refused with
/// [`AddonLockError::DevKeyExpired`] after; a lock no key signed is
/// [`AddonLockError::BadSignature`] as always.
pub fn verify_at(
    lock_bytes: &[u8],
    sig_text: &str,
    anchor: &TrustAnchor,
    expected_addon: &str,
    now: i64,
) -> Result<VerifiedLock, AddonLockError> {
    if anchor.keys.is_empty() && anchor.dev.is_empty() {
        return Err(AddonLockError::NoTrustedKeys);
    }
    let root = anchor.registry.trim();
    if !valid_registry_root(root) {
        return Err(AddonLockError::BadRegistryRoot(anchor.registry.clone()));
    }
    let keys: Vec<&str> = anchor.keys.iter().map(String::as_str).collect();
    let (key_index, dev_expires_at) = match release_sig::verify_with_keys(lock_bytes, sig_text, &keys) {
        Ok(i) => (i, None),
        Err(e) => {
            let dev: Vec<&str> = anchor.dev.iter().map(|d| d.key.as_str()).collect();
            match (!dev.is_empty()).then(|| release_sig::verify_with_keys(lock_bytes, sig_text, &dev)) {
                Some(Ok(j)) => {
                    let d = &anchor.dev[j];
                    if now >= d.expires_at {
                        return Err(AddonLockError::DevKeyExpired { key: d.key.clone(), expires_at: d.expires_at });
                    }
                    (anchor.keys.len() + j, Some(d.expires_at))
                }
                _ => {
                    // release_sig speaks of release keys; here the anchor is the add-on's.
                    let e = e.replace("any release key baked into this build", "any key trusted for this add-on");
                    return Err(AddonLockError::BadSignature(e));
                }
            }
        }
    };
    let lock: AddonLock =
        serde_json::from_slice(lock_bytes).map_err(|e| AddonLockError::Malformed(e.to_string()))?;
    if lock.canonical_bytes() != lock_bytes {
        return Err(AddonLockError::NotCanonical);
    }
    lock.validate(expected_addon, Some(root))?;
    Ok(VerifiedLock { lock, key_index, dev_expires_at })
}

/// Release-side guard (i163 part A, "never ships"): `release_keys` are the
/// keys a release is about to be verified or published against, `dev` every
/// development key this install knows. A key in both is refused: a release
/// that trusted it would ship a lock nobody but one developer can sign for.
pub fn refuse_dev_in_release(release_keys: &[String], dev: &[DevKey]) -> Result<(), String> {
    for k in release_keys {
        let k = k.trim().to_ascii_lowercase();
        if let Some(d) = dev.iter().find(|d| d.key == k) {
            return Err(format!(
                "key {}… is a development key on this install (expires {}); a release is never verified \
                 against a development key. Sign the lock with the add-on's release key",
                &k[..12.min(k.len())],
                utc_minute(d.expires_at)
            ));
        }
    }
    Ok(())
}

/// True when `candidate` orders below `current` by the CLI's semver
/// precedence (`cmp_cli_semver`: a release outranks its own pre-releases).
/// An unreadable version is an error, never "not a downgrade": a caller
/// that cannot order two versions must not move between them silently.
pub fn is_downgrade(current: &str, candidate: &str) -> Result<bool, AddonLockError> {
    if cmp_cli_semver(current, current).is_none() {
        return Err(AddonLockError::BadVersion(current.to_string()));
    }
    match cmp_cli_semver(candidate, current) {
        Some(o) => Ok(o == std::cmp::Ordering::Less),
        None => Err(AddonLockError::BadVersion(candidate.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "ghcr.io/example/addon";
    fn seed() -> String {
        "ab".repeat(32)
    }
    fn pk(seed: &str) -> String {
        release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(seed).unwrap())
    }
    fn d(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }
    fn lock() -> AddonLock {
        let mut images = BTreeMap::new();
        images.insert("addon".to_string(), format!("{ROOT}@{}", d('a')));
        images.insert("addon-worker".to_string(), format!("{ROOT}/worker@{}", d('b')));
        AddonLock {
            format: FORMAT.into(),
            addon: "example_addon".into(),
            version: "1.2.0".into(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            supports_stack: vec!["v0.6.0".into(), "v0.6.1-rc.1".into()],
            images,
            base: Some(BaseImage { image: "trellion".into(), digest: d('c') }),
            files: BTreeMap::new(),
        }
    }
    fn bundle() -> (AddonLock, BTreeMap<String, Vec<u8>>) {
        let mut l = lock();
        l.format = FORMAT_V2.into();
        let files: BTreeMap<String, Vec<u8>> =
            BTreeMap::from([(OVERLAY_FILE.to_string(), b"services: {}\n".to_vec())]);
        l.files = files.iter().map(|(n, b)| (n.clone(), sha256_ref(b))).collect();
        (l, files)
    }

    #[test]
    fn a_bundle_signs_verifies_and_holds_its_files_to_the_signature() {
        let (l, files) = bundle();
        let (bytes, sig) = signed(&l);
        let v = verify(&bytes, &sig, &anchor(), "example_addon").unwrap();
        assert_eq!(v.lock, l);
        assert!(String::from_utf8(bytes.clone()).unwrap().ends_with(&format!(r#""files":{{"{OVERLAY_FILE}":"{}"}}}}"#, l.files[OVERLAY_FILE])));
        assert_eq!(verify_files(&v.lock, &files), Ok(()));
        // A changed byte, a missing file and an unlisted file are each refused.
        let mut tampered = files.clone();
        tampered.get_mut(OVERLAY_FILE).unwrap().push(b'#');
        assert!(matches!(verify_files(&v.lock, &tampered), Err(AddonLockError::FileMismatch { ref why, .. }) if why.contains("hashes to")));
        assert!(matches!(verify_files(&v.lock, &BTreeMap::new()), Err(AddonLockError::FileMismatch { ref why, .. }) if why == "is missing"));
        let mut extra = files.clone();
        extra.insert("routes.json".into(), b"{}".to_vec());
        assert!(matches!(verify_files(&v.lock, &extra), Err(AddonLockError::FileMismatch { ref name, .. }) if name == "routes.json"));
        // A v1 lock accepts no files at all.
        assert_eq!(verify_files(&lock(), &BTreeMap::new()), Ok(()));
        assert!(verify_files(&lock(), &files).is_err());
    }

    #[test]
    fn bundle_format_rules() {
        type Mutate = fn(&mut AddonLock);
        let cases: Vec<Mutate> = vec![
            |l| l.format = FORMAT.into(),                       // v1 with files
            |l| l.files.clear(),                                // v2 without files
            |l| { let d = l.files.remove(OVERLAY_FILE).unwrap(); l.files.insert("other.yml".into(), d); }, // no overlay
            |l| { l.files.insert("../x".into(), d('a')); },     // a path
            |l| { l.files.insert(".hidden".into(), d('a')); },
            |l| { l.files.insert("a/b".into(), d('a')); },
            |l| { l.files.insert("x.yml".into(), "sha256:no".into()); },
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let (mut l, _) = bundle();
            mutate(&mut l);
            let (bytes, sig) = signed(&l);
            assert!(verify(&bytes, &sig, &anchor(), "example_addon").is_err(), "case {i} verified");
        }
        assert!(valid_file_name("docker-compose.yml") && valid_file_name("routes.json"));
    }
    fn anchor() -> TrustAnchor {
        TrustAnchor { keys: vec![pk(&seed())], registry: ROOT.into(), pull: None, dev: vec![] }
    }
    fn signed(l: &AddonLock) -> (Vec<u8>, String) {
        sign(l, &seed()).unwrap()
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let l = lock();
        let (bytes, sig) = signed(&l);
        let v = verify(&bytes, &sig, &anchor(), "example_addon").unwrap();
        assert_eq!(v.lock, l);
        assert_eq!(v.key_index, 0);
    }

    #[test]
    fn an_older_anchor_key_still_verifies_and_reports_its_index() {
        let (bytes, sig) = signed(&lock());
        let a = TrustAnchor { keys: vec![pk(&"cd".repeat(32)), pk(&seed())], registry: ROOT.into(), pull: None, dev: vec![] };
        assert_eq!(verify(&bytes, &sig, &a, "example_addon").unwrap().key_index, 1);
    }

    #[test]
    fn a_tampered_byte_is_refused() {
        let (mut bytes, sig) = signed(&lock());
        let i = bytes.iter().position(|&b| b == b'2').unwrap();
        bytes[i] = b'3';
        let e = verify(&bytes, &sig, &anchor(), "example_addon").unwrap_err();
        assert!(matches!(e, AddonLockError::BadSignature(_)), "{e:?}");
        assert!(e.to_string().contains("trusted for this add-on"), "{e}");
    }

    #[test]
    fn a_key_outside_the_anchor_is_refused() {
        let (bytes, sig) = signed(&lock());
        let a = TrustAnchor { keys: vec![pk(&"cd".repeat(32))], registry: ROOT.into(), pull: None, dev: vec![] };
        assert!(matches!(verify(&bytes, &sig, &a, "example_addon"), Err(AddonLockError::BadSignature(_))));
        let none = TrustAnchor { keys: vec![], registry: ROOT.into(), pull: None, dev: vec![] };
        assert_eq!(verify(&bytes, &sig, &none, "example_addon"), Err(AddonLockError::NoTrustedKeys));
    }

    #[test]
    fn another_addons_lock_is_refused() {
        let (bytes, sig) = signed(&lock());
        let e = verify(&bytes, &sig, &anchor(), "other_addon").unwrap_err();
        assert_eq!(e, AddonLockError::AddonMismatch { expected: "other_addon".into(), found: "example_addon".into() });
    }

    #[test]
    fn an_image_outside_the_registry_root_is_refused() {
        for bad in [
            format!("ghcr.io/example/other@{}", d('a')),
            format!("ghcr.io/example/addon-evil@{}", d('a')),
            format!("evil.io/ghcr.io/example/addon@{}", d('a')),
        ] {
            let mut l = lock();
            l.images.insert("addon".into(), bad.clone());
            let (bytes, sig) = signed(&l);
            let e = verify(&bytes, &sig, &anchor(), "example_addon").unwrap_err();
            assert!(matches!(e, AddonLockError::OutsideRegistry { .. }), "{bad}: {e:?}");
        }
    }

    #[test]
    fn an_image_not_pinned_by_digest_is_refused() {
        for (bad, tagged) in [
            (format!("{ROOT}:v1"), false),
            (format!("{ROOT}:v1@{}", d('a')), true),
            (format!("{ROOT}@sha256:short"), false),
        ] {
            let mut l = lock();
            l.images.insert("addon".into(), bad.clone());
            let (bytes, sig) = signed(&l);
            let e = verify(&bytes, &sig, &anchor(), "example_addon").unwrap_err();
            let ok = if tagged {
                matches!(e, AddonLockError::NotDigestRef { .. })
            } else {
                matches!(e, AddonLockError::NotDigestRef { .. } | AddonLockError::BadDigest { .. })
            };
            assert!(ok, "{bad}: {e:?}");
        }
    }

    #[test]
    fn empty_supports_and_no_images_are_refused() {
        let mut l = lock();
        l.supports_stack.clear();
        let (bytes, sig) = signed(&l);
        assert_eq!(verify(&bytes, &sig, &anchor(), "example_addon"), Err(AddonLockError::EmptySupports));
        let mut l = lock();
        l.images.clear();
        let (bytes, sig) = signed(&l);
        assert_eq!(verify(&bytes, &sig, &anchor(), "example_addon"), Err(AddonLockError::NoImages));
    }

    #[test]
    fn unreadable_fields_are_refused() {
        type Mutate = fn(&mut AddonLock);
        type Expect = fn(&AddonLockError) -> bool;
        let cases: Vec<(Mutate, Expect)> = vec![
            (|l| l.format = "noo-addon-lock/9".into(), |e| matches!(e, AddonLockError::UnknownFormat(_))),
            (|l| l.version = "one".into(), |e| matches!(e, AddonLockError::BadVersion(_))),
            (|l| l.source_commit = "main".into(), |e| matches!(e, AddonLockError::BadSourceCommit(_))),
            (|l| l.supports_stack = vec!["0.6.0".into()], |e| matches!(e, AddonLockError::BadStackTag(_))),
            (|l| l.supports_stack = vec!["latest".into()], |e| matches!(e, AddonLockError::BadStackTag(_))),
            (|l| l.base.as_mut().unwrap().digest = "sha256:x".into(), |e| matches!(e, AddonLockError::BadDigest { .. })),
        ];
        for (mutate, expect) in cases {
            let mut l = lock();
            mutate(&mut l);
            let (bytes, sig) = signed(&l);
            let e = verify(&bytes, &sig, &anchor(), "example_addon").unwrap_err();
            assert!(expect(&e), "{e:?}");
        }
    }

    #[test]
    fn a_bad_registry_root_is_refused_before_anything_else() {
        let (bytes, sig) = signed(&lock());
        for root in ["", "ghcr.io", "ghcr.io/example/", "https://ghcr.io/example", "ghcr.io/example:v1"] {
            let a = TrustAnchor { keys: anchor().keys, registry: root.into(), pull: None, dev: vec![] };
            assert!(matches!(verify(&bytes, &sig, &a, "example_addon"), Err(AddonLockError::BadRegistryRoot(_))), "{root}");
        }
    }

    #[test]
    fn non_canonical_bytes_are_refused_even_when_signed() {
        let l = lock();
        let pretty = serde_json::to_vec_pretty(&l).unwrap();
        let key = release_sig::signing_key_from_seed_hex(&seed()).unwrap();
        let sig = release_sig::sign(&key, &pretty);
        assert_eq!(verify(&pretty, &sig, &anchor(), "example_addon"), Err(AddonLockError::NotCanonical));
        // An unknown field is not silently ignored.
        let mut v: serde_json::Value = serde_json::from_slice(&l.canonical_bytes()).unwrap();
        v["extra"] = serde_json::json!(1);
        let b = serde_json::to_vec(&v).unwrap();
        let sig = release_sig::sign(&key, &b);
        assert!(matches!(verify(&b, &sig, &anchor(), "example_addon"), Err(AddonLockError::Malformed(_))));
    }

    #[test]
    fn canonical_bytes_do_not_depend_on_insertion_order() {
        let a = lock();
        let mut b = lock();
        b.images = BTreeMap::new();
        b.images.insert("addon-worker".to_string(), format!("{ROOT}/worker@{}", d('b')));
        b.images.insert("addon".to_string(), format!("{ROOT}@{}", d('a')));
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        // A reordered JSON object parses to the same lock and reserialises
        // to the same bytes.
        let shuffled = format!(
            r#"{{"images":{{"addon-worker":"{ROOT}/worker@{b}","addon":"{ROOT}@{a}"}},"base":{{"digest":"{c}","image":"trellion"}},"version":"1.2.0","addon":"example_addon","format":"{FORMAT}","source_commit":"0123456789abcdef0123456789abcdef01234567","supports_stack":["v0.6.0","v0.6.1-rc.1"]}}"#,
            a = d('a'), b = d('b'), c = d('c')
        );
        let parsed: AddonLock = serde_json::from_str(&shuffled).unwrap();
        assert_eq!(parsed.canonical_bytes(), a.canonical_bytes());
        let text = String::from_utf8(a.canonical_bytes()).unwrap();
        assert!(text.starts_with(r#"{"format":"noo-addon-lock/1","addon":"example_addon","#), "{text}");
        assert!(text.find("\"addon\":\"ghcr").unwrap() < text.find("\"addon-worker\"").unwrap());
    }

    #[test]
    fn no_base_is_omitted_and_always_matches() {
        let mut l = lock();
        l.base = None;
        assert!(!String::from_utf8(l.canonical_bytes()).unwrap().contains("base"));
        assert_eq!(l.base_matches(&d('f')), Ok(()));
        let (bytes, sig) = signed(&l);
        assert!(verify(&bytes, &sig, &anchor(), "example_addon").is_ok());
    }

    #[test]
    fn supports_is_an_exact_tag_match() {
        let l = lock();
        assert!(l.supports("v0.6.0"));
        assert!(l.supports(" v0.6.1-rc.1 "));
        assert!(!l.supports("v0.6.1"), "an rc entry does not cover its final");
        assert!(!l.supports("0.6.0"));
        assert!(!l.supports("v0.6.2"));
    }

    #[test]
    fn base_matches_the_stack_lock_digest_bare_or_as_a_ref() {
        let l = lock();
        assert_eq!(l.base_matches(&d('c')), Ok(()));
        assert_eq!(l.base_matches(&format!("ghcr.io/noomesh/trellion@{}", d('c'))), Ok(()));
        assert_eq!(
            l.base_matches(&d('e')),
            Err(AddonLockError::BaseMismatch { image: "trellion".into(), locked: d('c'), stack: d('e') })
        );
    }

    #[test]
    fn downgrade_uses_cli_semver_precedence() {
        assert_eq!(is_downgrade("1.2.0", "1.1.9"), Ok(true));
        assert_eq!(is_downgrade("1.2.0", "1.2.0"), Ok(false));
        assert_eq!(is_downgrade("1.2.0", "1.10.0"), Ok(false));
        assert_eq!(is_downgrade("1.2.0", "1.2.0-rc.1"), Ok(true), "a pre-release is below its release");
        assert_eq!(is_downgrade("1.2.0-rc.1", "1.2.0"), Ok(false));
        assert_eq!(is_downgrade("v1.2.0", "1.2.1"), Ok(false));
        assert!(matches!(is_downgrade("1.2.0", "next"), Err(AddonLockError::BadVersion(_))));
        assert!(matches!(is_downgrade("??", "1.0.0"), Err(AddonLockError::BadVersion(_))));
    }

    #[test]
    fn trust_anchor_reads_the_keys_and_registry_block() {
        let a: TrustAnchor = serde_json::from_str(r#"{"keys":["aa","bb"],"registry":"ghcr.io/example/addon"}"#).unwrap();
        assert_eq!(a.keys, vec!["aa", "bb"]);
        assert_eq!(a.registry, ROOT);
    }

    #[test]
    fn messages_are_sentence_case_without_a_trailing_period() {
        let errs = [
            AddonLockError::NoTrustedKeys,
            AddonLockError::NotCanonical,
            AddonLockError::EmptySupports,
            AddonLockError::NoImages,
            AddonLockError::AddonMismatch { expected: "a".into(), found: "b".into() },
            AddonLockError::BaseMismatch { image: "trellion".into(), locked: d('a'), stack: d('b') },
        ];
        for e in errs {
            let s = e.to_string();
            assert!(s.chars().next().unwrap().is_uppercase(), "{s}");
            assert!(!s.ends_with('.'), "{s}");
        }
    }

    // ── development keys (i163 part A) ──────────────────────────────────

    const NOW: i64 = 1_790_000_000;

    fn dev_anchor(release: Vec<String>, dev_seed: &str, expires_at: i64) -> TrustAnchor {
        TrustAnchor { keys: release, registry: ROOT.into(), pull: None, dev: vec![DevKey { key: pk(dev_seed), expires_at }] }
    }

    #[test]
    fn a_lock_signed_by_a_dev_key_verifies_until_it_expires() {
        let (bytes, sig) = signed(&lock());
        // Only a dev key is trusted, and it is still good.
        let a = dev_anchor(vec![], &seed(), NOW + 3600);
        let v = verify_at(&bytes, &sig, &a, "example_addon", NOW).unwrap();
        assert_eq!(v.dev_expires_at, Some(NOW + 3600));
        assert_eq!(v.key_index, 0, "a dev key counts on from the release keys");
        // Beside a release key it did not sign with, the index counts on.
        let a = dev_anchor(vec![pk(&"cd".repeat(32))], &seed(), NOW + 3600);
        let v = verify_at(&bytes, &sig, &a, "example_addon", NOW).unwrap();
        assert_eq!((v.key_index, v.dev_expires_at), (1, Some(NOW + 3600)));
        // At and after the instant it expires, it is refused, naming the expiry.
        for t in [NOW + 3600, NOW + 86_400] {
            let e = verify_at(&bytes, &sig, &a, "example_addon", t).unwrap_err();
            assert_eq!(e, AddonLockError::DevKeyExpired { key: pk(&seed()), expires_at: NOW + 3600 });
            assert!(e.to_string().contains(&utc_minute(NOW + 3600)), "{e}");
        }
    }

    #[test]
    fn a_release_key_wins_over_a_dev_key_and_an_unrelated_dev_key_changes_nothing() {
        let (bytes, sig) = signed(&lock());
        // Signed by the release key: release verdict, even with an expired dev key present.
        let a = dev_anchor(vec![pk(&seed())], &"cd".repeat(32), NOW - 1);
        let v = verify_at(&bytes, &sig, &a, "example_addon", NOW).unwrap();
        assert_eq!((v.key_index, v.dev_expires_at), (0, None));
        // Signed by neither: a bad signature, not an expiry.
        let a = dev_anchor(vec![pk(&"ef".repeat(32))], &"cd".repeat(32), NOW + 3600);
        assert!(matches!(verify_at(&bytes, &sig, &a, "example_addon", NOW), Err(AddonLockError::BadSignature(_))));
    }

    #[test]
    fn a_dev_signed_lock_is_still_held_to_every_other_rule() {
        let mut l = lock();
        l.images.insert("addon".into(), format!("ghcr.io/example/other@{}", d('a')));
        let (bytes, sig) = signed(&l);
        let a = dev_anchor(vec![], &seed(), NOW + 3600);
        assert!(matches!(verify_at(&bytes, &sig, &a, "example_addon", NOW), Err(AddonLockError::OutsideRegistry { .. })));
        assert!(matches!(verify_at(&bytes, &sig, &a, "other_addon", NOW), Err(AddonLockError::AddonMismatch { .. })));
    }

    #[test]
    fn an_anchor_from_json_never_carries_a_dev_key() {
        let mut a = dev_anchor(vec![pk(&seed())], &"cd".repeat(32), NOW + 3600);
        let text = serde_json::to_string(&a).unwrap();
        assert!(!text.contains("dev") && !text.contains(&pk(&"cd".repeat(32))), "{text}");
        let back: TrustAnchor = serde_json::from_str(&format!(
            r#"{{"keys":["{}"],"registry":"{ROOT}","dev":[{{"key":"{}","expires_at":9999999999}}]}}"#,
            pk(&seed()), pk(&"cd".repeat(32))
        )).unwrap();
        assert!(back.dev.is_empty(), "a JSON anchor (an entitlement, a flag) cannot smuggle a dev key in");
        a.dev.clear();
        assert_eq!(back, a);
    }

    #[test]
    fn release_verification_refuses_a_dev_key() {
        let dev = vec![DevKey { key: pk(&"cd".repeat(32)), expires_at: NOW + 3600 }];
        assert!(refuse_dev_in_release(&[pk(&seed())], &dev).is_ok());
        let e = refuse_dev_in_release(&[pk(&seed()), pk(&"cd".repeat(32)).to_uppercase()], &dev).unwrap_err();
        assert!(e.contains("development key") && e.contains(&utc_minute(NOW + 3600)), "{e}");
    }

    #[test]
    fn utc_formatting_is_exact() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_minute(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(utc_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
