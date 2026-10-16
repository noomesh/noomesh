// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Licensed add-ons on the controller: their signed locks, the pins those
//! locks produce, and the images pulled by digest. The verbs live in
//! `commands::addon_pins`; this is the machinery they share with
//! `noo upgrade --stack` and the launcher's reader.

pub mod lock_fetch;
pub mod pins;
pub mod pop;
pub mod resolve;

use std::path::Path;

use crate::addon_lock::VerifiedLock;

use lock_fetch::{Credential, Fetched};
use resolve::{Docker, Refusal, Want};

/// The stack tag this install runs: `NOO_IMAGE_TAG` in its `.env`. `None`
/// on a development checkout that pins no tag (it builds its images).
pub fn current_tag(root: &Path) -> Option<String> {
    let t = crate::onboard::env::read_env_key(&root.join(".env"), "NOO_IMAGE_TAG");
    let t = t.trim().trim_matches('"').trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// The licensed add-ons declared on in `root`'s noomesh.yaml (each one's own
/// default when silent). An unreadable or unparseable file is an error, never
/// "no add-ons": that would skip every hold and every check.
pub fn licensed_on(root: &Path) -> Result<Vec<&'static str>, String> {
    let declared = crate::commands::addons::declared_map_at(&root.join("noomesh.yaml"))?;
    Ok(crate::commands::addons::ADDON_ROWS
        .iter()
        .filter(|r| r.licensed.is_some())
        .filter(|r| crate::commands::addons::resolve(declared.get(r.key).copied(), r.default_on))
        .map(|r| r.key)
        .collect())
}

/// A lock that passed every check and whose images are local, ready to be
/// recorded.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub addon: String,
    pub verified: VerifiedLock,
    pub fetched: Fetched,
    pub pulled: usize,
    /// The proxy root the images were pulled from (`None` = the registry).
    pub pulled_from: Option<String>,
    /// Which host and credential the lock and images came through.
    pub via: String,
}

/// The lock client for the verbs that pull, with the credentials the route
/// selector needs (`lock_fetch::Route`): the vendor token when the store
/// holds one, and only then nothing else; otherwise the entitlement
/// credential for anchors that name a `pull` root.
pub fn installed_client() -> Result<lock_fetch::Client, String> {
    let cred = lock_fetch::installed_credential()?;
    let proxy = if cred.is_some() { None } else { lock_fetch::installed_proxy_auth()? };
    Ok(lock_fetch::Client::new(cred).with_proxy(proxy))
}

/// Where and against what one or more add-ons are resolved.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub tag: &'a str,
    /// The verified stack lock text for `tag`, when one is published.
    pub stack_lock: Option<&'a str>,
    pub allow_downgrade: bool,
    pub client: &'a lock_fetch::Client,
}

/// Steps 1-7 for one add-on against `ctx.tag`: anchor, fetch, verify, stack
/// membership, base, downgrade, pull. Writes nothing.
pub fn prepare(ctx: &Ctx, addon: &str, docker: &mut dyn Docker) -> Result<Prepared, Refusal> {
    let anchor = resolve::installed_anchor(addon)?;
    let current = pins::read(ctx.root).map_err(Refusal::Write)?;
    let pinned = current.get(addon).map(|p| p.version.clone());
    let want = Want {
        addon,
        stack_tag: ctx.tag,
        stack_lock: ctx.stack_lock,
        pinned: pinned.as_deref(),
        allow_downgrade: ctx.allow_downgrade,
    };
    let route = ctx.client.route(&anchor).map_err(Refusal::Route)?;
    let (verified, fetched) = resolve::fetch_and_check(ctx.client, &anchor, &want)?;
    let mut cred = || -> Result<Option<Credential>, String> {
        ctx.client.docker_credential(&route).map_err(|e| format!("{}: {}", route.host(), e.summary()))
    };
    let pulled = resolve::pull_images(docker, &verified, &route, &mut cred)?;
    Ok(Prepared {
        addon: addon.to_string(),
        verified,
        fetched,
        pulled,
        pulled_from: route.pulled_from(),
        via: ctx.client.describe(&route),
    })
}

/// Step 8 for a prepared add-on.
pub fn commit(root: &Path, p: &Prepared, tag: &str) -> Result<pins::Pin, Refusal> {
    resolve::record(root, &p.addon, &p.verified, &p.fetched, tag, p.pulled_from.clone())
}
