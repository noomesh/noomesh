// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo upgrade --channel`: move an install between release channels
//!
//! A channel is three values an install carries itself: the release repo
//! `noo upgrade` reads (`NOO_CLI_REPO`) and the image namespace
//! (`NOO_IMAGE_PREFIX`, `NOO_BASE_REGISTRY`). An install that predates a move
//! keeps its old values after any upgrade, because an operator's own value
//! wins over the compiled default. This step rewrites them, with rules:
//!
//! 1. show the change before making it, and ask (`--yes` skips the question);
//! 2. probe the target first: it must serve a release, and
//! 3. that release must not be OLDER than the installed CLI (database
//!    migrations only go forward);
//! 4. the public CLI knows only the public channel. A private channel is
//!    values the operator supplies (`--channel custom`), never a literal here;
//! 5. keep the previous values so one command undoes it (`--channel rollback`).
//!
//! The values are written to `~/.noo/.env`, the file `release_var` reads, so
//! the same `noo upgrade` run continues against the new channel.

use std::path::{Path, PathBuf};

use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::Globals;

pub(crate) const KEYS: [&str; 3] = ["NOO_CLI_REPO", "NOO_IMAGE_PREFIX", "NOO_BASE_REGISTRY"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Channel {
    pub repo: String,
    pub image_prefix: String,
    pub base_registry: String,
}

impl Channel {
    pub(crate) fn public() -> Self {
        Channel {
            repo: crate::registry::PUBLIC_RELEASE_REPO.into(),
            image_prefix: crate::registry::PUBLIC_IMAGE_NAMESPACE.into(),
            base_registry: crate::registry::PUBLIC_IMAGE_NAMESPACE.into(),
        }
    }

    fn value(&self, key: &str) -> &str {
        match key {
            "NOO_CLI_REPO" => &self.repo,
            "NOO_IMAGE_PREFIX" => &self.image_prefix,
            _ => &self.base_registry,
        }
    }
}

/// What the operator asked for on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    Public,
    Custom(Channel),
    Rollback,
}

/// Flags gathered while `upgrade` parses its arguments.
#[derive(Debug, Default, Clone)]
pub(crate) struct Flags {
    pub channel: Option<String>,
    pub release_repo: Option<String>,
    pub image_prefix: Option<String>,
    pub base_registry: Option<String>,
}

pub(crate) fn request(f: &Flags) -> Result<Option<Request>, String> {
    let Some(name) = f.channel.as_deref() else {
        if f.release_repo.is_some() || f.image_prefix.is_some() || f.base_registry.is_some() {
            return Err("--release-repo / --image-prefix / --base-registry need --channel custom".into());
        }
        return Ok(None);
    };
    match name {
        "public" | "rollback" if f.release_repo.is_some() || f.image_prefix.is_some() || f.base_registry.is_some() => {
            Err(format!("--channel {name} takes no values; use --channel custom to supply your own"))
        }
        "public" => Ok(Some(Request::Public)),
        "rollback" => Ok(Some(Request::Rollback)),
        "custom" => {
            let repo = f.release_repo.clone().ok_or("--channel custom needs --release-repo <owner/repo>")?;
            let prefix = f.image_prefix.clone().ok_or("--channel custom needs --image-prefix <registry/path>")?;
            let base = f.base_registry.clone().unwrap_or_else(|| prefix.clone());
            let ok_repo = repo.split('/').count() == 2 && !repo.contains(' ') && !repo.starts_with('/');
            if !ok_repo {
                return Err(format!("--release-repo must look like owner/repo, got {repo:?}"));
            }
            if prefix.trim().is_empty() || prefix.contains(' ') || prefix.ends_with('/') {
                return Err(format!("--image-prefix must be a registry path without a trailing slash, got {prefix:?}"));
            }
            Ok(Some(Request::Custom(Channel { repo, image_prefix: prefix, base_registry: base })))
        }
        other => Err(format!("unknown channel {other:?}: use public, custom or rollback")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub key: &'static str,
    pub old: String,
    pub new: String,
}

/// The keys that would change. `current` is the effective value of each key
/// (the install's own, else the compiled default), so a value already on the
/// target is not listed.
pub(crate) fn plan(current: &Channel, target: &Channel) -> Vec<Change> {
    KEYS.iter()
        .filter(|k| current.value(k) != target.value(k))
        .map(|k| Change { key: k, old: current.value(k).to_string(), new: target.value(k).to_string() })
        .collect()
}

/// The offered release must not be older than what is installed: database
/// migrations only go forward, and the public line starts above every
/// private release. Equal is fine (same version, different source).
pub(crate) fn check_not_downgrade(installed: &str, offered: &str) -> Result<(), String> {
    match super::upgrade::cmp_cli_semver(installed, offered) {
        Some(std::cmp::Ordering::Greater) => Err(format!(
            "the target channel's latest release is {offered}, older than the installed {installed}: \
             moving to it would be a downgrade, and database migrations only go forward"
        )),
        None if installed != offered => Err(format!(
            "cannot compare the installed {installed} with the target's {offered}; refusing to guess"
        )),
        _ => Ok(()),
    }
}

pub(crate) fn snapshot_path() -> PathBuf {
    crate::onboard::standalone::default_home().join("channel.prev")
}

pub(crate) fn env_path() -> PathBuf {
    crate::onboard::standalone::default_home().join(".env")
}

/// The effective channel now: each key from env/`.env`, else the default.
pub(crate) fn current() -> Channel {
    let get = |k: &str, d: &str| {
        let v = super::provision::release_var(k);
        if v.is_empty() { d.to_string() } else { v }
    };
    Channel {
        repo: get("NOO_CLI_REPO", crate::registry::RELEASE_REPO),
        image_prefix: get("NOO_IMAGE_PREFIX", crate::registry::IMAGE_NAMESPACE),
        base_registry: get("NOO_BASE_REGISTRY", crate::registry::IMAGE_NAMESPACE),
    }
}

pub(crate) fn write_snapshot(path: &Path, c: &Channel) -> std::io::Result<()> {
    let body = KEYS.iter().map(|k| format!("{k}={}\n", c.value(k))).collect::<String>();
    std::fs::write(path, body)
}

pub(crate) fn read_snapshot(path: &Path) -> Option<Channel> {
    let body = std::fs::read_to_string(path).ok()?;
    let get = |k: &str| {
        body.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(|v| v.trim().to_string())
    };
    Some(Channel {
        repo: get("NOO_CLI_REPO").filter(|v| !v.is_empty())?,
        image_prefix: get("NOO_IMAGE_PREFIX").filter(|v| !v.is_empty())?,
        base_registry: get("NOO_BASE_REGISTRY").filter(|v| !v.is_empty())?,
    })
}

pub(crate) fn apply(env: &Path, changes: &[Change]) -> std::io::Result<()> {
    if let Some(dir) = env.parent() {
        std::fs::create_dir_all(dir)?;
    }
    for c in changes {
        crate::onboard::env::update_env_key(env, c.key, &c.new)?;
    }
    Ok(())
}

/// Run the channel step. Returns `Some(code)` when the run should end here
/// (`--check`, or already on the channel with nothing else asked), else
/// `None` and the normal upgrade continues against the new channel.
pub(crate) fn run(g: &Globals, req: Request, yes: bool, check_only: bool, installed: &str) -> Option<i32> {
    let now = current();
    let target = match &req {
        Request::Public => Channel::public(),
        Request::Custom(c) => c.clone(),
        Request::Rollback => match read_snapshot(&snapshot_path()) {
            Some(c) => c,
            None => fail(g.json, ExitCode::Generic, "no_channel_snapshot",
                "nothing to roll back: no previous channel was recorded",
                Some("a switch records the old values in ~/.noo/channel.prev")),
        },
    };
    let changes = plan(&now, &target);
    if changes.is_empty() {
        if !g.json {
            println!("{}", ui::status_line(Glyph::Ok, "already on this channel"));
        }
        return None;
    }

    // Probe the target before anything is written. Rollback goes back to a
    // channel that served this install; it is not probed or downgrade-checked.
    let mut offered = String::new();
    let mut stack_note = String::new();
    if req != Request::Rollback {
        std::env::set_var("NOO_CLI_REPO", &target.repo);
        offered = match super::upgrade::resolve_latest(g) {
            Ok(v) => v,
            Err(e) => fail(g.json, ExitCode::Generic, "channel_unreachable",
                &format!("the target channel ({}) does not serve a release: {e}", target.repo),
                Some("nothing was changed; a private channel needs gh or a token with read access")),
        };
        if let Err(e) = check_not_downgrade(installed, &offered) {
            fail(g.json, ExitCode::Generic, "channel_downgrade", &e, Some("nothing was changed"));
        }
        // A release with no images behind it would pass the probe above and
        // then fail the roll. The image prefix is read from the process env.
        std::env::set_var("NOO_IMAGE_PREFIX", &target.image_prefix);
        stack_note = match super::upgrade::probe_channel_stack(g) {
            Ok(tag) => format!("stack {tag}: signed lock verifies, gateway image published"),
            Err(e) => fail(g.json, ExitCode::Generic, "channel_not_ready",
                &format!("the target channel cannot serve a roll yet: {e}"),
                Some("nothing was changed")),
        };
    }
    // Config keys in the secrets store beat `.env` at every launch.
    let pins = super::secrets::store_pins_of(&KEYS);

    if g.json && check_only {
        println!("{}", serde_json::json!({
            "channel_change": changes.iter().map(|c| serde_json::json!({"key": c.key, "old": c.old, "new": c.new})).collect::<Vec<_>>(),
            "offered": offered, "installed": installed, "stack": stack_note, "secrets_store_pins": pins, "written": false,
        }));
        return Some(0);
    }
    if !g.json {
        println!("{}", ui::phase("Channel"));
        for c in &changes {
            println!("  {}: {} -> {}", c.key, c.old, c.new);
        }
        if !offered.is_empty() {
            println!("{}", ui::status_line(Glyph::Ok, &format!("target serves noo {offered} (installed {installed})")));
        }
        if !stack_note.is_empty() {
            println!("{}", ui::status_line(Glyph::Ok, &stack_note));
        }
        match &pins {
            Some(p) if !p.is_empty() => println!("{}", ui::status_line(Glyph::Warn, &format!(
                "{} also set in the secrets store, which beats .env at every launch: run `noo security secrets tidy` first or the old value comes back",
                p.join(", ")))),
            None => println!("{}", ui::status_line(Glyph::Warn,
                "could not read the secrets store: if it pins these keys, run `noo security secrets tidy`")),
            _ => {}
        }
    }
    if check_only {
        if !g.json {
            println!("{}", ui::status_line(Glyph::Warn, "dry run: nothing was written"));
        }
        return Some(0);
    }

    super::confirm_prompt(g, yes, "Switch this install to the channel above?");
    if let Err(e) = write_snapshot(&snapshot_path(), &now) {
        fail(g.json, ExitCode::Generic, "snapshot_failed",
            &format!("could not record the previous channel: {e}"), Some("nothing was changed"));
    }
    if let Err(e) = apply(&env_path(), &changes) {
        fail(g.json, ExitCode::Generic, "channel_write_failed",
            &format!("could not write {}: {e}", env_path().display()),
            Some("run `noo upgrade --channel rollback` to restore the recorded values"));
    }
    if !g.json {
        println!("{}", ui::status_line(Glyph::Ok, "channel switched"));
        ui::guide(&[("noo upgrade --channel rollback", "restores the previous values")]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(r: &str, p: &str, b: &str) -> Channel {
        Channel { repo: r.into(), image_prefix: p.into(), base_registry: b.into() }
    }

    #[test]
    fn plan_lists_only_what_changes() {
        let now = ch("o/old", "ghcr.io/x/old", "ghcr.io/x/old");
        let to = ch("o/new", "ghcr.io/x/new", "ghcr.io/x/old");
        let p = plan(&now, &to);
        assert_eq!(p.iter().map(|c| c.key).collect::<Vec<_>>(), vec!["NOO_CLI_REPO", "NOO_IMAGE_PREFIX"]);
        assert!(plan(&to, &to).is_empty());
    }

    #[test]
    fn a_downgrade_is_refused_and_equal_or_newer_is_not() {
        assert!(check_not_downgrade("0.6.0", "0.5.91").is_err());
        assert!(check_not_downgrade("0.5.91", "0.5.91").is_ok());
        assert!(check_not_downgrade("0.5.91", "0.6.0").is_ok());
        // Unparseable on one side: refuse rather than guess.
        assert!(check_not_downgrade("0.5.91", "latest").is_err());
    }

    #[test]
    fn public_is_the_declared_public_channel() {
        let p = Channel::public();
        assert_eq!(p.repo, crate::registry::PUBLIC_RELEASE_REPO);
        assert_eq!(p.image_prefix, crate::registry::PUBLIC_IMAGE_NAMESPACE);
        assert_eq!(p.base_registry, p.image_prefix);
    }

    #[test]
    fn request_parsing() {
        let f = |c: Option<&str>, r: Option<&str>, p: Option<&str>| Flags {
            channel: c.map(Into::into), release_repo: r.map(Into::into),
            image_prefix: p.map(Into::into), base_registry: None,
        };
        assert_eq!(request(&f(None, None, None)).unwrap(), None);
        assert_eq!(request(&f(Some("public"), None, None)).unwrap(), Some(Request::Public));
        assert_eq!(request(&f(Some("rollback"), None, None)).unwrap(), Some(Request::Rollback));
        let c = request(&f(Some("custom"), Some("o/r"), Some("ghcr.io/o/p"))).unwrap();
        assert_eq!(c, Some(Request::Custom(ch("o/r", "ghcr.io/o/p", "ghcr.io/o/p"))));
        // values without custom, custom without values, bad shapes
        assert!(request(&f(None, Some("o/r"), None)).is_err());
        assert!(request(&f(Some("public"), Some("o/r"), None)).is_err());
        assert!(request(&f(Some("custom"), None, Some("ghcr.io/o/p"))).is_err());
        assert!(request(&f(Some("custom"), Some("o/r"), None)).is_err());
        assert!(request(&f(Some("custom"), Some("not a repo"), Some("ghcr.io/o/p"))).is_err());
        assert!(request(&f(Some("custom"), Some("o/r"), Some("ghcr.io/o/p/"))).is_err());
        assert!(request(&f(Some("nope"), None, None)).is_err());
    }

    #[test]
    fn apply_writes_the_env_and_a_snapshot_round_trips() {
        let dir = std::env::temp_dir().join(format!("noo-channel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join(".env");
        std::fs::write(&env, "NOO_IMAGE_TAG=v1\nNOO_CLI_REPO=o/old\n").unwrap();
        let now = ch("o/old", "ghcr.io/x/old", "ghcr.io/x/old");
        let to = ch("o/new", "ghcr.io/x/new", "ghcr.io/x/new");
        let snap = dir.join("channel.prev");
        write_snapshot(&snap, &now).unwrap();
        apply(&env, &plan(&now, &to)).unwrap();
        let body = std::fs::read_to_string(&env).unwrap();
        assert!(body.contains("NOO_IMAGE_TAG=v1"), "unrelated keys survive: {body}");
        assert!(body.contains("NOO_CLI_REPO=o/new") && !body.contains("o/old"));
        assert!(body.contains("NOO_IMAGE_PREFIX=ghcr.io/x/new"));
        assert_eq!(read_snapshot(&snap), Some(now));
        assert_eq!(read_snapshot(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
