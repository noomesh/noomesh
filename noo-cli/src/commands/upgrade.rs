// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo upgrade` — in-process self-update of the `noo` binary.
//!
//! Native equivalent of re-running `noo-cli/install.sh`: resolve the target
//! release, download the musl asset + its `.sha256`, verify, and atomically
//! swap the running binary. The point is a discoverable, apt-like verb that
//! works on a box with NO repo checkout — so this must not shell out to the
//! repo's install.sh.
//!
//! Asset selection mirrors install.sh exactly: Linux only, musl target
//! (`{arch}-unknown-linux-musl`), asset name `noo-{target}`, `.sha256` sidecar
//! of the form `<hex>  <name>`.
//!
//! Private-repo auth also mirrors install.sh's `download()` precedence:
//!   1. `NOO_CLI_BASE_URL` — a mirror serving `noo-<target>` + `.sha256`
//!      directly (no auth), used for internal/air-gapped mirrors.
//!   2. `gh release download` when `gh` is on PATH — the reliable private-repo
//!      path (handles the token dance GitHub requires for asset downloads).
//!   3. a direct token'd fetch (`GH_TOKEN`/`GITHUB_TOKEN`/`PAI_REPOS_PAT`).
//! With none of these and a private repo, it fails with actionable guidance
//! rather than a bare 404 — same posture as the installer.

use std::process::Command;
use crate::output::{fail, ExitCode};
use crate::release_fetch::{self, FetchError};
use crate::{Globals, Unhandled};
use crate::ui::{self, Glyph};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// The DEFAULT release repo. `NOO_CLI_REPO` overrides it — the distribution
/// CHANNEL knob: internal installs use this default (private,
/// gh/token-authenticated); the public noomesh channel is a config flip,
/// not a code change. `NOO_CLI_BASE_URL` (a full asset mirror) still
/// outranks both.
const DEFAULT_REPO: &str = crate::registry::RELEASE_REPO;
const TAG_PREFIX: &str = "noo-cli-v";
/// The release installer, served by the controller mirror as `install.sh`.
const INSTALLER: &str = include_str!("../../install.sh");
const UPGRADE_USAGE: &str =
    "usage: noo upgrade [--check] [--version X.Y.Z] [--stack] [--nodes] [--all] [--tag vX.Y.Z] [--controller] [--allow-unsigned] [--skip-gateway-key-check] [--allow-downgrade] [--channel public|rollback|custom [--release-repo <owner/repo> --image-prefix <registry/path> [--base-registry <registry/path>]]] [--yes]";

/// THE release repo, for every caller. `NOO_CLI_REPO` overrides the default.
///
/// pub(crate) because five other call sites had the literal typed out and so
/// silently ignored the override — including the darwin agent download, which
/// is the lane that already shipped a three-month-stale agent to a Mac. Moving
/// the release location would have moved SOME traffic and left the rest
/// pointing at the old repo, reporting success either way.
/// Resolution order is `release_var`'s, not a second one written here:
/// process env, then `~/.noo/.env`, then the compiled default.
///
/// It used to read the env var directly, so `NOO_CLI_REPO` was settable only
/// for the life of one shell — while its sibling `NOO_IMAGE_PREFIX` was
/// persistable in `~/.noo/.env`. Two release variables, two resolvers, one of
/// them forgetting between invocations. That gap matters exactly once and at
/// the worst moment: moving the release channel needs ONE bridging upgrade
/// run with the new repo set, on a binary whose compiled default is still the
/// old one. Retry it in a fresh shell without the export and it silently
/// queries the old repository again and reports "already up to date".
pub(crate) fn repo() -> String {
    let v = super::provision::release_var("NOO_CLI_REPO");
    if v.is_empty() { DEFAULT_REPO.into() } else { v }
}
fn releases_api() -> String {
    format!("https://api.github.com/repos/{}/releases", repo())
}
fn dl_base() -> String {
    format!("https://github.com/{}/releases/download", repo())
}

/// `noo upgrade [--version X.Y.Z] [--check] [--stack] [--nodes] [--all] [--tag vX.Y.Z]`
///
/// Fleet upgrade: the CLI already knows which stack
/// release it is PAIRED with (STANDALONE_STACK_TAG, baked at build), and the
/// pull-provisioning channel already carries node-agent binaries — so:
///   --stack  after the self-update, bump the standalone install's
///            NOO_IMAGE_TAG pin to the paired tag, refresh the embedded
///            assets, and re-run the launcher (compose recreates changed
///            containers — on standalone, compose owns every container).
///   --controller  build + install the controller host daemons
///            (noo-node-agent, noo-hostd, noo-apply) from this checkout
///            and restart them — attended (sudo prompts)..
///   --nodes  restage a provision bundle for every pull-capable mesh node
///            (nodes fetch + apply on their own timer; no SSH).
///   --all    both.
///   --tag    override the paired stack tag (e.g. a hotfix stack release).
/// After the binary swap the OLD process is still running — it re-execs the
/// NEW binary (`upgrade --stage2 …`) so the paired tag and embedded assets
/// used are the new release's, not the old one's.
pub fn upgrade(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut check_only = false;
    let mut pin: Option<String> = None;
    let mut stack = false;
    let mut nodes = false;
    let mut stage2 = false;
    let mut tag_override: Option<String> = None;
    let mut allow_unsigned = std::env::var("NOO_ALLOW_UNSIGNED").map(|v| v == "1").unwrap_or(false);
    // Overrides the gateway-older-than-nodes refusal (see gateway_older_than_bundle).
    let mut force = false;
    // Skips ONLY the running gateway's
    // service-key listing in the pre-roll check — the store check stays.
    // Separate from --force, which overrides unrelated refusals.
    let mut skip_gw_key_check = false;
    // `--stack` only: an explicit rollback may take a licensed add-on back to
    // an older signed version with it. Refused by default (add-ons may carry
    // database migrations).
    let mut allow_downgrade = false;
    // Move this install between release channels.
    let mut chan = super::channel::Flags::default();
    let mut yes = false;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--check" => check_only = true,
            "--stack" => stack = true,
            "--controller" => return upgrade_controller(g),
            "--nodes" => nodes = true,
            "--all" => { stack = true; nodes = true; }
            "--stage2" => stage2 = true,
            "--allow-unsigned" => allow_unsigned = true,
            "--force" => force = true,
            "--skip-gateway-key-check" => skip_gw_key_check = true,
            "--allow-downgrade" => allow_downgrade = true,
            "--yes" | "-y" => yes = true,
            "--channel" | "--release-repo" | "--image-prefix" | "--base-registry" => match it.next() {
                Some(v) => {
                    let slot = match tok.as_str() {
                        "--channel" => &mut chan.channel,
                        "--release-repo" => &mut chan.release_repo,
                        "--image-prefix" => &mut chan.image_prefix,
                        _ => &mut chan.base_registry,
                    };
                    *slot = Some(v.clone());
                }
                None => fail(g.json, ExitCode::Usage, "usage", &format!("{tok} needs a value"),
                    Some(UPGRADE_USAGE)),
            },
            "--tag" => match it.next() {
                Some(v) => tag_override = Some(v.clone()),
                None => fail(g.json, ExitCode::Usage, "usage", "--tag needs a value",
                    Some(UPGRADE_USAGE)),
            },
            v if v.starts_with("--tag=") => {
                tag_override = Some(v["--tag=".len()..].to_string());
            }
            "--version" => match it.next() {
                Some(v) => pin = Some(v.trim_start_matches("noo-cli-v").to_string()),
                None => fail(g.json, ExitCode::Usage, "usage", "--version needs a value",
                    Some(UPGRADE_USAGE)),
            },
            v if v.starts_with("--version=") => {
                pin = Some(v["--version=".len()..].trim_start_matches("noo-cli-v").to_string());
            }
            // Native-only command: bad args must print usage HERE. Returning
            // Unhandled fell through to the Python CLI, which has no
            // `upgrade` at all — an operator on an older binary running a
            // newer flag got "noo-py: No such command 'upgrade'" (live
            // 2026-08-23 with 0.2.23 + --all).
            // `noo upgrade --stack v0.2.8` — a bare stack version is the tag
            // (the operator typed exactly this on the first rail walk).
            v if v.starts_with('v') && v.len() > 1
                && v[1..].chars().all(|c| c.is_ascii_digit() || c == '.') => {
                tag_override = Some(v.to_string());
            }
            t => fail(g.json, ExitCode::Usage, "usage",
                &format!("unknown argument: {t}"), Some(UPGRADE_USAGE)),
        }
    }

    if allow_downgrade && !stack {
        fail(g.json, ExitCode::Usage, "usage", "--allow-downgrade applies to the stack roll only (--stack or --all)",
            Some(UPGRADE_USAGE));
    }

    // Stage 2: we ARE the freshly-installed binary; run the stack/node
    // stages with THIS build's paired tag + embedded assets.
    if stage2 {
        return run_fleet_stages(g, stack, nodes, tag_override.as_deref(), force, skip_gw_key_check, allow_downgrade);
    }

    let current = env!("CARGO_PKG_VERSION").to_string();
    // The channel step runs first, so the rest of this run
    // (self-update, --stack, --nodes) reads the new channel from `~/.noo/.env`.
    match super::channel::request(&chan) {
        Err(e) => fail(g.json, ExitCode::Usage, "usage", &e, Some(UPGRADE_USAGE)),
        Ok(Some(req)) => {
            if let Some(code) = super::channel::run(g, req, yes, check_only, &current) {
                return Ok(code);
            }
        }
        Ok(None) => {}
    }
    let target = match target_triple() {
        Some(t) => t,
        None => fail(g.json, ExitCode::Generic, "unsupported_platform",
            &format!("no published noo binary for {}/{} — releases carry Linux x86_64/aarch64 and Apple Silicon",
                std::env::consts::OS, std::env::consts::ARCH),
            Some("build from source, or install via noo-cli/install.sh")),
    };

    // Resolve the target version: an explicit pin, else the latest noo-cli-v*
    // release tag. A mirror (NOO_CLI_BASE_URL) with no version is treated as
    // "whatever the mirror serves" — we cannot enumerate it, so require a pin
    // or just fetch (the mirror decides).
    let mut base_url = std::env::var("NOO_CLI_BASE_URL").ok().filter(|s| !s.trim().is_empty());
    // A node asks its controller first: the
    // controller serves the assets `noo upgrade --nodes` uploaded, so a node
    // with no GitHub access — private repo, or no internet — still updates.
    // Only when the controller has nothing does the GitHub path run.
    let role = crate::role::detect();
    if base_url.is_none() && pin.is_none() {
        if let Some(n) = role.node_only() {
            if let Some(ctl) = &n.controller_url {
                let mirror = format!("{}/bootstrap/cli", ctl.trim_end_matches('/'));
                if let Some(t) = target_triple() {
                    if controller_has_asset(&mirror, &format!("noo-{t}")) {
                        if !g.json { ui::step(&format!("update source: controller ({mirror})")); }
                        base_url = Some(mirror);
                    }
                }
            }
        }
    }
    let version = match (&pin, &base_url) {
        (Some(v), _) => v.clone(),
        (None, Some(_)) => current.clone(), // mirror mode: no enumeration; label as current
        (None, None) => match resolve_latest(g) {
            Ok(v) => v,
            Err(e) => fail(g.json, ExitCode::Generic, "resolve_failed",
                &format!("could not resolve the latest release: {e}"),
                Some("pin one with --version X.Y.Z, or check network/auth")),
        },
    };

    let mut action = decide_cli_action(&current, &version, pin.is_some());
    // A mirror serves "whatever it has": today's behaviour is to fetch.
    if base_url.is_some() && action == CliAction::Noop {
        action = CliAction::Upgrade;
    }

    if check_only {
        let up_to_date = matches!(action, CliAction::Noop | CliAction::KeepNewer);
        // `--check --stack`: is a newer stack published, and does an add-on
        // that is on hold this controller back (no lock for it yet)?
        let stack_check = if stack { stack_hold_check(g) } else { None };
        if g.json {
            let mut o = serde_json::json!({
                "current": current, "latest": version, "up_to_date": up_to_date, "target": target,
                "action": action.as_str(),
            });
            if let Some((cur, newest, holds)) = &stack_check {
                o["stack"] = serde_json::json!({
                    "current": cur, "newest": newest,
                    "holds": holds.iter().map(|(a, w)| serde_json::json!({"addon": a, "why": w})).collect::<Vec<_>>(),
                });
            }
            println!("{o}");
        } else if action == CliAction::KeepNewer {
            println!("{}", ui::status_line(Glyph::Ok, &format!(
                "noo {current} is newer than the latest release {version}")));
        } else if up_to_date {
            println!("{}", ui::status_line(Glyph::Ok, &format!("noo {current} is {}", ui::state("up to date"))));
        } else {
            println!("{}", ui::status_line(Glyph::Warn, &format!("noo {current} installed; {version} available")));
            ui::guide(&[
                ("noo upgrade", "replaces this binary in place and refreshes shell completion"),
                ("noo upgrade --all", "also rolls the stack to the paired images and restages the nodes"),
            ]);
        }
        if !g.json {
            if let Some((cur, newest, holds)) = &stack_check {
                let glyph = if holds.is_empty() { Glyph::Ok } else { Glyph::Warn };
                println!("{}", ui::status_line(glyph, &hold_line(cur, newest, holds)));
                for (a, why) in holds {
                    println!("{}", ui::note(&format!("{a}: {why}")));
                }
            }
        }
        return Ok(0);
    }

    // Phases (guide §5 Rhythm): only a multi-phase run (--stack/--nodes/
    // --all) gets `◆ CLI`; a plain self-upgrade is one unit of work.
    let phased = stack || nodes;
    if phased && !g.json {
        println!("{}", ui::phase("CLI"));
    }

    if action == CliAction::Unparsable && !g.json {
        ui::warned(&format!("cannot compare {current} and {version}; treating as different"));
    }
    if action == CliAction::DowngradePinned && !g.json {
        ui::step(&format!("installing the older release {version} over {current}"));
    }

    if matches!(action, CliAction::Noop | CliAction::KeepNewer) {
        if action == CliAction::KeepNewer {
            if !g.json {
                ui::done(&format!(
                    "noo {current} is newer than the latest release {version} — keeping it (use --version {version} to install the release)"));
            } else {
                println!("{}", serde_json::json!({"status":"noop","version":current,"latest":version,"action":action.as_str()}));
            }
        } else if !g.json {
            ui::done(&format!("no change: noo {current} is already current (use --version to force a specific build)"));
        } else {
            println!("{}", serde_json::json!({"status":"noop","version":current,"action":action.as_str()}));
        }
        // No swap, but a box can still be missing its completion (one
        // installed by enroll before 0.3.27, or a failed refresh) — install
        // when absent, never rewrite here.
        if let Some(p) = crate::shell_completion::ensure_installed(false) {
            if !g.json {
                println!("{}", ui::note(&format!("installed tab completion: {}", p.display())));
            }
        }
        if stack || nodes {
            // No swap happened — this process IS the current build, so its
            // paired tag and assets are already the right ones.
            return run_fleet_stages(g, stack, nodes, tag_override.as_deref(), force, skip_gw_key_check, allow_downgrade);
        }
        return Ok(0);
    }

    let asset = format!("noo-{target}");
    if !g.json { ui::step(&format!("downloading {asset} @ {version}")); }

    // Fetch the binary + its sha256 sidecar.
    let (bin, sha_line) = match download_asset(g, &version, &asset, base_url.as_deref()) {
        Ok(pair) => pair,
        // The class-specific cause and next step, not a
        // blanket "private repo" guess over whatever went wrong.
        Err(e) => fail(g.json, ExitCode::Generic, "download_failed", &e.summary(), Some(&e.hint())),
    };

    // Verify: the SIGNED manifest is the trust. The
    // sidecar is only a fallback for pre-signing releases, and only when the
    // operator says so — a mirror that serves a matching asset+sidecar pair
    // proves nothing about where the bytes came from.
    let expected = match fetch_signed_manifest(g, &version, base_url.as_deref()) {
        Ok(Some((manifest, sig))) => {
            if let Err(e) = crate::release_sig::verify(manifest.as_bytes(), &sig) {
                fail(g.json, ExitCode::Generic, "release_signature_invalid",
                    &format!("{} for {version}: {e} — refusing to install", crate::release_sig::MANIFEST),
                    Some("the release or the mirror serving it was altered; do not retry with --allow-unsigned"));
            }
            match crate::release_sig::manifest_sha_for(&manifest, &asset) {
                Some(h) => h,
                None => fail(g.json, ExitCode::Generic, "asset_not_in_manifest",
                    &format!("{asset} is not listed in the signed {} for {version} — refusing", crate::release_sig::MANIFEST), None),
            }
        }
        Ok(None) if allow_unsigned => {
            if !g.json { ui::warned(&format!("{version} carries no signed manifest — installing on the sidecar only (--allow-unsigned)")); }
            sha_line.split_whitespace().next().unwrap_or("").to_lowercase()
        }
        Ok(None) => fail(g.json, ExitCode::Generic, "unsigned_release",
            &format!("{version} publishes no signed {} — refusing to install", crate::release_sig::MANIFEST),
            Some("releases before 0.3.70 are unsigned: pass --allow-unsigned to pin one deliberately")),
        Err(e) => fail(g.json, ExitCode::Generic, "manifest_fetch_failed", &e.summary(), Some(&e.hint())),
    };
    let got = {
        let mut h = Sha256::new();
        h.update(&bin);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    if expected.is_empty() || expected != got {
        fail(g.json, ExitCode::Generic, "checksum_mismatch",
            &format!("sha256 mismatch (expected {expected}, got {got}) — refusing to install"),
            Some("the download may be corrupt or tampered; retry"));
    }

    // Atomically swap the running binary: write a temp in the SAME dir, chmod
    // 755, rename over the current exe. A failed download must never leave a
    // half-written binary — hence temp-then-rename, never truncate-in-place.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "no_current_exe",
            &format!("cannot locate the running binary: {e}"), None),
    };
    match swap_binary(&exe, &bin) {
        Ok(()) => {}
        Err(e) => fail(g.json, ExitCode::Generic, "install_failed", &e,
            Some("if the install dir is root-owned, re-run with sudo or set NOO_INSTALL_DIR")),
    }

    if g.json {
        println!("{}", serde_json::json!({
            "status":"upgraded","from":current,"to":version,"path":exe.display().to_string(),
        }));
    } else {
        // Closing line of the CLI unit: blank line first (guide §5).
        ui::close_done(&format!("noo upgraded {current} → {version}"));
        // The installed path is the value a script captures.
        ui::value(&exe.display().to_string());
    }

    // #14: a standalone install's deploy slice (scripts, compose, templates)
    // rides the binary and is MATERIALISED into ~/.noo — swapping the binary
    // alone leaves the slice at the old version, so a script the new binary
    // invokes may simply not exist yet ("script not found" after every
    // upgrade until an onboard run happened to re-materialise; host8 hit it
    // twice on 2026-09-01). NOTE: this run still EXECUTES as the old binary;
    // re-exec the NEW one to materialise ITS assets, not ours.
    let sh = crate::onboard::standalone::default_home();
    if sh.join(".noo-standalone").is_file() {
        let refreshed = Command::new(&exe)
            .args(["stack", "sync-assets"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if refreshed {
            if !g.json {
                println!("{}", ui::note(&format!("deploy slice refreshed under {}", sh.display())));
            }
        } else if !g.json {
            ui::warned("could not refresh the deploy slice");
            ui::guide(&[("noo onboard --only prereqs", "re-extracts the standalone deploy slice from this binary")]);
        }
    }

    // Refresh the installed shell completion from the NEW binary (finding
    // #55): install.sh drops the file once; upgrades left it frozen at the
    // install-day verb list (onboard/offboard invisible to tab on a box
    // installed at 0.2.16). Best-effort, silent on failure.
    // Both completion refreshes collapse into ONE note (at most three
    // notes hang under a ✓ — guide §5).
    let mut completion: Vec<String> = Vec::new();
    let legacy = std::path::PathBuf::from("/etc/bash_completion.d/pai");
    if legacy.exists() {
        if let Ok(out) = std::process::Command::new(&exe).args(["completions", "bash"]).output() {
            if out.status.success() && std::fs::write(&legacy, &out.stdout).is_ok() {
                completion.push(legacy.display().to_string());
            }
        }
    }
    // Install when MISSING, not only refresh when present: a box that got
    // its binary through enroll (not onboard) had no completion to refresh
    // (HOST3, 2026-09-01). shell_completion.rs is the one installer.
    if let Some(p) = crate::shell_completion::ensure_installed_with(&exe, true) {
        completion.push(p.display().to_string());
    }
    if !completion.is_empty() && !g.json {
        println!("{}", ui::note(&format!("tab completion refreshed: {}", completion.join(", "))));

    // A second `noo` earlier on PATH silently wins from here on. The
    // divergence is durable and self-deepening: on a Mac node the rail writes
    // /usr/local/bin/noo (node_fetch.rs hardcodes it) while a leftover
    // ~/.local/bin/noo keeps answering the shell — so the fleet reports the new
    // version, the terminal runs the old one, and the NEXT `noo upgrade`
    // upgrades the shadow rather than the copy the rail maintains. Seen on
    // host6 2026-09-05.
    if let Some(shadow) = shadowing_noo(&exe) {
        if !g.json {
            ui::warned(&format!(
                "another noo earlier on PATH will be used instead of the one just upgraded: \
                 {} runs, {} was upgraded",
                shadow.display(), exe.display()));
            ui::guide(&[("rm -f <the shadowing noo> && hash -r",
                "removes the stale copy so `noo` is the one this upgraded")]);
        }
    }
    }

    if stack || nodes {
        // The running process is still the OLD build — its baked stack tag
        // and embedded assets are stale. Re-exec the binary we just
        // installed so the fleet stages use the NEW release's pairing.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(&exe);
            cmd.arg("upgrade").arg("--stage2");
            if stack { cmd.arg("--stack"); }
            if nodes { cmd.arg("--nodes"); }
            if let Some(t) = &tag_override { cmd.arg("--tag").arg(t); }
            if skip_gw_key_check { cmd.arg("--skip-gateway-key-check"); }
            if allow_downgrade { cmd.arg("--allow-downgrade"); }
            let err = cmd.exec(); // only returns on failure
            fail(g.json, ExitCode::Generic, "reexec_failed",
                &format!("could not re-exec the new binary: {err}"),
                Some("run `noo upgrade --stage2 --stack`/`--nodes` manually"));
        }
        #[cfg(not(unix))]
        {
            fail(g.json, ExitCode::Generic, "unsupported_platform",
                "--stack/--nodes need unix re-exec", None);
        }
    }
    if !g.json {
        println!("{}", ui::note("stack images pair with this release"));
        ui::guide(&[
            ("noo upgrade --stack", "rolls the running stack to the paired images"),
            ("noo upgrade --nodes", "then restages every pull-capable node on the new bundle"),
        ]);
    }
    Ok(0)
}

// ── Controller self-upgrade ────────────────
//
// The upgrade family managed everything except the machine it runs on:
// --stack refuses repo checkouts, upgrade-agents excludes the controller
// (it IS the rail), and nothing touched the controller's own
// /usr/local/bin/{noo-node-agent,noo-hostd,noo-apply} — which drifted to
// three vintages on the very host that builds everyone else's bundles
// (2026-08-27). This is the manual recipe that fixed it, as a command.
//
// ATTENDED on purpose: installs go through `sudo install`, which prompts
// on the operator's terminal — the controller has no NOPASSWD and this
// command must never need one. Traps encoded from the live session:
//   - noo-hostd is a USER unit (`systemctl --user`; so was the retired
//     noo-host-watcher;
//     `sudo systemctl` answers "Unit not found", which reads like they
//     don't exist);
//   - the agent binary has no --version flag — probing it STARTS a second
//     agent; version truth is the hostd log stamp + the DB app_version;
//   - build-cross.sh selects the binary via BINARY= env, not argv.

fn sh(cmd: &str, dir: Option<&str>, envs: &[(&str, &str)]) -> Result<(), String> {
    let mut c = std::process::Command::new("bash");
    c.arg("-c").arg(cmd);
    if let Some(d) = dir {
        c.current_dir(d);
    }
    for (k, v) in envs {
        c.env(k, v);
    }
    let st = c.status().map_err(|e| format!("{cmd}: {e}"))?;
    if st.success() { Ok(()) } else { Err(format!("`{cmd}` exited {st}")) }
}

fn file_sha(path: &str) -> Option<String> {
    let out = std::process::Command::new("sha256sum").arg(path).output().ok()?;
    if !out.status.success() { return None; }
    String::from_utf8_lossy(&out.stdout).split_whitespace().next().map(String::from)
}

fn upgrade_controller(g: &Globals) -> Result<i32, Unhandled> {
    // Must run from a noomesh checkout — the builds and the applier
    // source live here.
    if !std::path::Path::new("node-agent-go/build-cross.sh").exists()
        || !std::path::Path::new("scripts/noo-apply.sh").exists()
    {
        fail(g.json, ExitCode::Usage, "not_checkout",
            "`noo upgrade --controller` must run from the checkout root \
             (node-agent-go/build-cross.sh and scripts/noo-apply.sh not found here)",
            None);
    }
    let arch = match std::process::Command::new("uname").arg("-m").output() {
        Ok(o) => match String::from_utf8_lossy(&o.stdout).trim() {
            "x86_64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            other => {
                fail(g.json, ExitCode::Generic, "arch",
                    &format!("unsupported controller arch: {other}"), None);
            }
        },
        Err(e) => fail(g.json, ExitCode::Generic, "arch", &format!("uname failed: {e}"), None),
    };

    ui::step(&format!("building the controller daemons for {arch}"));
    if let Err(e) = sh(&format!("./build-cross.sh {arch}"), Some("node-agent-go"), &[]) {
        fail(g.json, ExitCode::Generic, "build", &e, None);
    }
    if let Err(e) = sh(&format!("./build-cross.sh {arch}"), Some("node-agent-go"),
        &[("BINARY", "noo-hostd")])
    {
        fail(g.json, ExitCode::Generic, "build", &e, None);
    }

    // Install what changed (sudo prompts on the operator's tty). sha-compare
    // first so a no-op upgrade needs no password at all.
    let installs: [(&str, String); 3] = [
        ("/usr/local/bin/noo-node-agent", format!("node-agent-go/noo-node-agent-{arch}")),
        ("/usr/local/bin/noo-hostd", format!("node-agent-go/noo-hostd-{arch}")),
        ("/usr/local/bin/noo-apply", "scripts/noo-apply.sh".to_string()),
    ];
    let mut changed: Vec<&str> = Vec::new();
    for (dst, src) in &installs {
        if file_sha(src).is_some() && file_sha(src) == file_sha(dst) {
            println!("{}", ui::note(&format!("{dst}: already current")));
            continue;
        }
        ui::step(&format!("installing {src} → {dst} (sudo may prompt)"));
        if let Err(e) = sh(&format!("sudo install -m 0755 {src} {dst}"), None, &[]) {
            fail(g.json, ExitCode::Generic, "install", &e, None);
        }
        changed.push(dst);
    }

    if changed.is_empty() {
        ui::done("no change: controller daemons already current, no restarts");
        return Ok(0);
    }

    // Restarts: the agent is a SYSTEM unit; hostd is a USER unit (it runs
    // as the operator, driving docker/compose on their behalf).
    if changed.contains(&"/usr/local/bin/noo-node-agent") {
        ui::step("restarting noo-node-agent (system unit, sudo)");
        if let Err(e) = sh("sudo systemctl restart noo-node-agent", None, &[]) {
            fail(g.json, ExitCode::Generic, "restart", &e, None);
        }
    }
    if changed.contains(&"/usr/local/bin/noo-hostd") {
        ui::step("restarting noo-hostd (user unit)");
        if let Err(e) = sh("systemctl --user restart noo-hostd", None, &[]) {
            fail(g.json, ExitCode::Generic, "restart", &e, None);
        }
    }
    // The bash host watcher is RETIRED and no longer shipped (noo-hostd
    // took its spool). This used to `systemctl --user restart
    // noo-host-watcher` unconditionally — and restart STARTS a stopped
    // unit, so every controller self-upgrade put a second executor on
    // noo-hostd's spool, the one thing onboard's stop_watcher exists to
    // prevent. A watcher still running now is a leftover: say so and how
    // to stop it, never restart it.
    if sh("systemctl --user is-active --quiet noo-host-watcher", None, &[]).is_ok() {
        ui::warned(
            "the retired noo-host-watcher is still running beside noo-hostd — two executors claim from one spool; \
             stop it: systemctl --user disable --now noo-host-watcher",
        );
    }

    // Verify what can be verified locally; the fleet view is one command away.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let units = [("noo-node-agent", false), ("noo-hostd", true)];
    for (unit, user) in units {
        let cmd = if user {
            format!("systemctl --user is-active {unit}")
        } else {
            format!("systemctl is-active {unit}")
        };
        let ok = sh(&format!("{cmd} >/dev/null"), None, &[]).is_ok();
        if ok {
            ui::done(&format!("{unit} {}", ui::state("running")));
        } else {
            ui::failed(&format!("{unit} is not active — check its journal"), None);
        }
    }
    if let Ok(log) = std::fs::read_to_string(".noo-host-spool/hostd.log") {
        if let Some(line) = log.lines().rev().find(|l| l.contains("started;")) {
            println!("{}", ui::note(&format!("hostd: {}", line.trim())));
        }
    }
    ui::done("controller daemons upgraded");
    ui::guide(&[
        ("noo cluster status", "verify the agent re-registered: bus connected, fresh heartbeat"),
        ("noo cluster logs <node>", "if it did not, the agent log on that node names the cause"),
    ]);
    Ok(0)
}

// ── Fleet stages ──────

/// Refuse to push a node bundle NEWER than the running gateway.
///
/// Node agents publish job completions on `events.job.<kind>.<node_id>`
/// A gateway from before that filters
/// `events.job.*`, and `*` matches exactly ONE token — so it does not match
/// the node-scoped subject at all. A node upgraded ahead of the gateway has
/// every completion silently ignored and every job reaped as a timeout:
/// jobs run, the node's own log shows them completing, and the controller
/// calls them failed. Nothing names the cause, and the symptom appears on
/// the node just touched while the fault is on the machine that was not.
///
/// The check is DELIBERATELY ASYMMETRIC. Gateway NEWER than nodes is the
/// safe direction and is not refused: the new gateway filters
/// `events.job.>`, which matches both subject shapes, precisely so a fleet
/// can sit mixed while the nodes are walked. A symmetric "versions must
/// match" guard would block the staged rollout it exists to protect.
///
/// Unknown on either side (a dev build, a hand-rolled container) skips the
/// check rather than guessing — this refuses a known-bad ordering, it does
/// not assert a known-good one.
fn gateway_older_than_bundle(force: bool) -> Option<String> {
    let bundle = std::env::var("NOO_IMAGE_TAG").unwrap_or_default();
    let bundle = bundle.trim();
    if bundle.is_empty() {
        return None;
    }
    let running = running_gateway_tag()?;
    if !version_less_than(&running, bundle) {
        return None;
    }
    if force {
        ui::warned(&format!(
            "gateway is {running} but the node bundle carries {bundle} — proceeding on --force; \
             completions from upgraded nodes will be dropped until the gateway is rolled"
        ));
        return None;
    }
    Some(format!(
        "the gateway is running {running} but the node bundle carries {bundle}. Upgrading nodes \
         first makes the gateway drop their job completions — the jobs run, the node logs them \
         complete, and the controller reaps them as timeouts. Roll the stack first, then nodes \
         (`noo upgrade --all` does both in that order); --force overrides"
    ))
}

/// The tag of the image the running gateway container was created from.
/// `None` when docker is unreachable, the container is absent, or the ref
/// carries no recognisable tag.
fn running_gateway_tag() -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(["inspect", "noo-gateway", "--format", "{{.Config.Image}}"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let image = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // `ghcr.io/…/gateway:v0.2.21@sha256:…` → `v0.2.21`
    let no_digest = image.split('@').next()?;
    let tag = no_digest.rsplit_once(':').map(|(_, t)| t.to_string())?;
    (tag.starts_with('v') && tag.chars().nth(1).is_some_and(|c| c.is_ascii_digit())).then_some(tag)
}

/// `v0.2.19 < v0.2.21`. Compares numeric components; a component that does
/// not parse makes the comparison give up (returns false — do not refuse on
/// something we cannot read).
fn version_less_than(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Option<Vec<u64>> {
        s.trim_start_matches('v').split('.').map(|p| p.parse::<u64>().ok()).collect()
    };
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x < y,
        _ => false,
    }
}

/// Run the requested fleet stages from a binary whose paired tag/assets are
/// current (either freshly re-exec'd, or already-current with no swap).
fn run_fleet_stages(g: &Globals, stack: bool, nodes: bool, tag_override: Option<&str>, force: bool, skip_gw_key_check: bool, allow_downgrade: bool)
    -> Result<i32, Unhandled>
{
    let mut rc = 0;
    let mut failed_stage = "";
    // `--stack` alone is one unit of work; anything with `--nodes` has at
    // least Gateway · CLI Assets · Nodes, so every stage gets its phase.
    let phased = nodes;
    if stack {
        if phased && !g.json { println!("{}", ui::phase("Stack")); }
        rc = upgrade_stack(g, tag_override, force, skip_gw_key_check, allow_downgrade)?;
        if rc != 0 { failed_stage = "stack"; }
        else if !nodes {
            // The roll returns the moment compose is up; the gateway reports
            // healthy 20-40 s later. `noo upgrade --stack` used to return
            // inside that window, so the very next command — `noo cluster
            // provision host8 --wait`, 2026-09-18 — met "connection refused"
            // and failed. With `--nodes` the Gateway phase below already
            // waits; without it, wait here, so "Stack now on" means serving.
            if phased && !g.json { println!("{}", ui::phase("Gateway")); }
            if !wait_for_gateway(g, 180) {
                ui::close_failed(
                    "the gateway did not report healthy within 180s after the stack roll",
                    Some("noo stack status"),
                );
                rc = 1;
                failed_stage = "stack";
            }
        }
    }
    if nodes && rc == 0 {
        // The stack stage just recreated the gateway; it reports healthy
        // ~20-40 s later. Running the nodes stage the same instant hit
        // "cannot reach gateway: unexpected end of file" (host8,
        // 2026-09-03) and exited before any resume hint could print. A
        // bare `--nodes` typed right after a start meets the same thing:
        // one Gateway phase covers both, with a longer budget after a roll.
        if !g.json { println!("{}", ui::phase("Gateway")); }
        let budget = if stack { 180 } else { 60 };
        if !wait_for_gateway(g, budget) {
            ui::close_failed(
                &format!("the gateway did not report healthy within {budget}s{}", if stack { " after the stack roll" } else { " — is the stack running?" }),
                Some("noo stack status"),
            );
            rc = 1;
            failed_stage = "nodes";
        } else if let Some(err) = gateway_older_than_bundle(force) {
            ui::close_failed(&err, Some("noo upgrade --stack"));
            rc = 1;
            failed_stage = "nodes";
        } else if let Some(err) = lock_stage_blocker(
            g,
            &crate::commands::image_stage::lock_stage_failures(&crate::commands::provision::release_var("NOO_IMAGE_TAG")),
            force,
        ) {
            // Nodes on the rail pull their images from the controller's
            // store; rolling them on top of a failed stage strands them.
            ui::close_failed(&err, Some("noo cluster stage-images --lock"));
            rc = 1;
            failed_stage = "nodes";
        } else {
            rc = upgrade_nodes(g)?;
            if rc != 0 { failed_stage = "nodes"; }
        }
    }
    if rc != 0 && !g.json {
        // Every stage is idempotent, so the honest hint is the SAME verb
        // again: the CLI stays current, the stack re-pulls on the moved pin
        // (the lock is re-verified), nodes that already applied re-register
        // in seconds. Pointing at `noo stack start` (the old hint) dropped
        // the operator out of the flow and skipped the nodes stage.
        let mut resume = String::from("noo upgrade");
        resume.push_str(if stack && nodes { " --all" } else if stack { " --stack" } else { " --nodes" });
        if let Some(t) = tag_override { resume.push_str(&format!(" --tag {t}")); }
        ui::close_failed(&format!("upgrade stopped at the {failed_stage} stage — fix the cause above, then resume"), Some(&resume));
        eprintln!("{}", ui::note("stages are idempotent — the CLI stays current, the stack re-pulls on the moved pin, nodes restage"));
    }
    Ok(rc)
}

/// Normalize a stack tag: `stack-v0.1.74` / `v0.1.74` / `0.1.74` → `v0.1.74`.
fn norm_stack_tag(t: &str) -> String {
    let t = t.trim().trim_start_matches("stack-");
    if t.starts_with('v') { t.to_string() } else { format!("v{t}") }
}

/// Bump the standalone install to this build's paired stack release:
/// refresh embedded assets, upsert the NOO_IMAGE_TAG pin, re-run the
/// launcher (compose recreates exactly the containers whose image changed —
/// on a standalone box compose owns every container, so this is the blessed
/// path, unlike repo/reconciler installs).
/// Step 0.5 of `upgrade --stack` — see the call site. Refuses the roll (before
/// anything has moved) when users.conf names a variable and cannot be
/// re-rendered without minting; says nothing when the file is already clean.
fn rerender_nats_users_for_roll(g: &Globals, root: &std::path::Path) {
    use crate::commands::nats_users as nu;
    match nu::rerender_for_roll(g, root) {
        Ok(None) => {}
        Ok(Some(out)) => {
            let reloaded = nu::hup_nats();
            if !g.json {
                ui::done(&format!(
                    "users.conf re-rendered without the retired shared NATS user ({} principals, none re-minted){}",
                    out.users,
                    if reloaded { "; noo-nats reloaded" } else { "" }
                ));
            }
        }
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "nats_users_rerender",
            &format!(
                "{} still names the retired shared NATS user, and it could not be re-rendered: {e} — \
                 nothing was rolled (the new compose no longer hands nats that variable, and NATS \
                 would refuse the file). Render it, then re-run noo upgrade --stack",
                nu::USERS_CONF
            ),
            Some("noo cluster nats-users render"),
        ),
    }
}

fn upgrade_stack(g: &Globals, tag_override: Option<&str>, force: bool, skip_gw_key_check: bool, allow_downgrade: bool) -> Result<i32, Unhandled> {
    // repo_root() ranks a python-venv-derived root above the standalone
    // home, so a STALE clone (e.g. ~/pai-assistant left from an early
    // manual attempt) shadowed a healthy ~/.noo and --stack refused a
    // machine that IS standalone (live on host1, 2026-08-23). For
    // this command the standalone home is authoritative whenever the
    // ranked root isn't one.
    let mut root = crate::envfile::repo_root();
    if !root.join(".noo-standalone").is_file() {
        if let Some(sh) = crate::envfile::standalone_home() {
            ui::warned(&format!("{} is not standalone — using the standalone install at {}",
                root.display(), sh.display()));
            root = sh;
        } else {
            fail(g.json, ExitCode::Generic, "not_standalone",
                &format!("{} is not a standalone install — `noo upgrade --stack` \
                          manages standalone controllers only", root.display()),
                Some("repo checkouts: git pull + scripts/noomesh-start.sh --dist; \
                      reconciler-owned gateways: see the split-recipe runbook"));
        }
    }
    let tag = match tag_override {
        Some(t) => norm_stack_tag(t),
        None => {
            let baked = crate::onboard::standalone::STANDALONE_STACK_TAG;
            if baked.is_empty() {
                fail(g.json, ExitCode::Generic, "no_paired_tag",
                    "this noo binary carries no paired stack tag",
                    Some("pass one explicitly: noo upgrade --stack --tag vX.Y.Z"));
            }
            // The baked pairing is a floor, not the answer: a stack tag cut
            // AFTER this CLI (stack-v0.2.8 after 0.3.67, 2026-09-03) would
            // otherwise be invisible and `--stack` rolls vX → vX. The CLI
            // itself was upgraded a moment ago in this same verb, so the
            // newest published stack is what this binary is meant to run.
            let paired = norm_stack_tag(baked);
            let complete = newest_published_stack_tag();
            // A release can be TAGGED before every image carries the tag: the
            // stack was cut at 13:12Z on 2026-09-22 and a roll minutes later
            // found v0.2.69 published but not yet complete on GHCR, chose the
            // newest complete v0.2.68, and said nothing — so the operator
            // watched "rolling v0.2.69 → v0.2.68" with no idea why.
            if let Some(newer) = newer_published_but_incomplete(&published_stack_tags(), complete.as_deref()) {
                ui::warned(&format!(
                    "{newer} is published but not yet on every image at ghcr.io — \
                     rolling to the newest COMPLETE stack instead; re-run in a few \
                     minutes, or pass --tag {newer} once `docker pull` succeeds"));
            }
            match complete {
                Some(newest) if newer_than_pairing(&newest, &paired) => {
                    println!("{}", ui::note(&format!("newest published stack is {newest} (this noo was paired with {paired})")));
                    newest
                }
                Some(_) => paired,
                None => {
                    ui::warned(&format!("could not list published stack tags — using the paired {paired} (pass --tag to override)"));
                    paired
                }
            }
        }
    };

    // The compose file this binary is about to materialise delivers the
    // gateway's and worker's secrets as FILES; images below its
    // `x-noo-secrets-floor` do not read them and would boot with no
    // credentials. Refused BEFORE anything moves — slice, pin, lock — and
    // regardless of --tag or --force: a rollback below the floor needs the CLI
    // that shipped that release. The launcher refuses the same pairing again
    // (scripts/lib-dist.sh require_secrets_floor); this is the early word.
    if let Some(floor) = embedded_secrets_floor() {
        if !tag_meets_floor(&tag, &floor) {
            fail(g.json, ExitCode::Generic, "below_secrets_floor",
                &format!("{tag} is below {floor}, the oldest stack whose images read the secret \
                          files this CLI's compose file delivers — refusing to pair them"),
                Some(&secrets_floor_remedy(&floor)));
        }
    }

    // Finding #99: an offboard-residue ~/.noo (env pin survives, secrets
    // gone) sailed into a blank-password deploy. Refuse the stub HERE,
    // before any pull — the launcher's require_core_secrets is the deep
    // guard; this is the early, cheaper message.
    {
        let env_text = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
        let backend = env_text.lines()
            .find_map(|l| l.trim().strip_prefix("NOO_SECRETS_BACKEND=").map(str::trim).map(str::to_string))
            .unwrap_or_default();
        let has_plain_pg = env_text.lines()
            .any(|l| l.trim().strip_prefix("POSTGRES_PASSWORD=").is_some_and(|v| !v.trim().is_empty()));
        let sops_ok = backend == "sops" && root.join("secrets/env.sops").is_file();
        if !sops_ok && !has_plain_pg {
            fail(g.json, ExitCode::Generic, "install_incomplete",
                "this install has NO core secrets (offboard residue, or never onboarded) — \
                 refusing to deploy a stack with blank credentials",
                Some("fresh setup: noo onboard · restore a controller: noo migrate import <archive> · \
                      audit: noo offboard --check"));
        }
    }
    // The plaintext .env backend is retired. An install still
    // on it (or holding a secret in .env beside the store) is refused BEFORE
    // anything moves, with the verbs that fix it — never auto-migrated here.
    if let Some(why) = crate::commands::plaintext_env::AtRest::read(&root).controller_problem() {
        fail(g.json, ExitCode::Generic, "plaintext_secrets",
            &format!("{why} — refusing to roll a stack whose secrets are not all encrypted at rest; nothing was changed"),
            Some(crate::commands::plaintext_env::REMEDY));
    }
    let prev = std::fs::read_to_string(root.join(".env")).unwrap_or_default()
        .lines().find_map(|l| l.trim().strip_prefix("NOO_IMAGE_TAG=").map(str::to_string))
        .unwrap_or_default();
    // "rolling v0.2.43 → v0.2.43" is not a roll, it is a re-apply, and printing
    // it as an arrow reads as a typo in the operator's own command (2026-09-13).
    // Re-applying the same tag is a legitimate and common act — it is how a
    // recreate with new env is done — so it gets its own sentence.
    // A roll BACKWARDS is never what `--stack` with no arguments means. The
    // pin says where the controller is; the resolved tag can be older when
    // the newest published stack is not yet complete on GHCR (see above) or
    // when a stale binary's paired tag wins. Either way, silently downgrading
    // a controller that is ahead — and pruning the newer images afterwards —
    // is an outage with a green tick. An explicit --tag is a decision and is
    // honoured with a loud word; --force overrides the rest.
    if is_downgrade(&prev, &tag) && tag_override.is_none() && !force {
        fail(g.json, ExitCode::Generic, "stack_downgrade_refused",
            &format!("the controller is on {prev}; resolving `--stack` would roll it BACK to {tag}"),
            Some(&format!("that usually means {prev} is published but not yet complete on ghcr.io — \
                           wait a few minutes and re-run, or `noo upgrade --stack --tag {prev}` to \
                           re-apply it, or --force to downgrade on purpose")));
    }
    if prev == tag {
        ui::step(&format!("re-applying {tag}  (install {}) — same tag, containers recreated",
            root.display()));
    } else if is_downgrade(&prev, &tag) {
        ui::warned(&format!("rolling BACK {prev} → {tag}  (install {}) — an explicit downgrade",
            root.display()));
    } else {
        ui::step(&format!("rolling {} → {tag}  (install {})",
            if prev.is_empty() { "unpinned".into() } else { prev.clone() }, root.display()));
    }

    // -2. Every controller service must hold its own gateway key BEFORE the
    //    roll: this release's gateway refuses the
    //    controller-secret HMAC a keyless worker used to fall back to, and the
    //    fallback itself is gone. FIRST, before any stage below mints or
    //    moves anything, so its refusal can truly say "nothing was changed".
    //    Two sources, both required: the store must hold each required
    //    NOO_SVC_KEY_* (what compose delivers), and the running gateway must
    //    list an active key for each consumer (what it will accept). A
    //    gateway that cannot be asked fails CLOSED: refused unless
    //    --skip-gateway-key-check, which skips only that listing — the store
    //    check stays. (The listing exposes no key prefix or fingerprint, so
    //    the store's key cannot be compared with the row; an active row per
    //    consumer is what can be shown.)
    let required = required_consumers();
    let store_short = keyless_in_store(&root, &required);
    let db_short = match crate::http::get_json_try(g, "/api/security/service-keys", true, 10) {
        Ok(listing) if listing["keys"].as_array().is_some() => Some(keyless_of(&required, &listing)),
        _ => None,
    };
    match pre_roll_key_verdict(&store_short, db_short.as_deref(), skip_gw_key_check) {
        PreRollKeys::Go => {}
        PreRollKeys::GoUnverified => if !g.json {
            ui::warned("--skip-gateway-key-check: could not read the service-key list from the running gateway, so only the \
                        store was checked — after the roll, `noo cluster verify --controller` (row `service keys`) \
                        must show every consumer on its own key");
        },
        PreRollKeys::Missing(names) => fail(g.json, ExitCode::Generic, "service_keys_missing",
            &format!("{} hold(s) no gateway key of its own — this release refuses the shared-secret fallback \
                      they would use, so rolling now would cut them off. Nothing was changed",
                names.join(", ")),
            Some(&format!("noo security service-key provision {}   # then re-run: noo upgrade --stack", names[0]))),
        PreRollKeys::Unverifiable => fail(g.json, ExitCode::Generic, "service_keys_unverifiable",
            "could not read the service-key list from the running gateway, so it cannot be shown that every \
             consumer holds a key this release accepts. Nothing was changed",
            Some("noo auth login   # then re-run: noo upgrade --stack (or add --skip-gateway-key-check to roll on the store check alone)")),
    }

    // -1z. Licensed add-ons release from their own repositories with their
    //    own signed lock. Before anything below mints or moves, every add-on
    //    declared on must have a lock for the TARGET tag that verifies
    //    against the entitlement's trust anchor, lists the tag, matches the
    //    target stack lock's base row, and is not a downgrade; its images are
    //    pulled by digest here (pulls change nothing that runs). One that
    //    cannot is a hold: the roll is refused naming it, with nothing
    //    changed. The pins are written beside stack.lock in step 2.
    let target_stack_lock = fetch_stack_lock(g, &tag);
    let addon_prep = addon_preflight(g, &root, &tag, target_stack_lock.as_deref(), allow_downgrade);

    // -1. The audit log's signing key. A release whose
    //    gateway signs audit rows ONLY with NOO_AUDIT_HMAC_KEY refuses every
    //    row on an install that never had one — every install before it.
    //    Minted here, before anything else moves, so a store that cannot be
    //    written stops the roll with the slice, pin and stack untouched. Mint
    //    only if absent: an existing key is never rotated (the gateway's
    //    checkpoint hands the old rows over on its first boot with it).
    match reconcile_audit_key(&root) {
        Ok(AuditKeyStage::AlreadyPresent) => {}
        Ok(AuditKeyStage::Minted) => if !g.json {
            ui::done("minted NOO_AUDIT_HMAC_KEY into the encrypted store (new in this release: the audit log's own signing key)");
        },
        Err(AuditKeyRefusal::NoStore) => {
            fail(g.json, ExitCode::Generic, "audit_key_no_store",
                &format!("{} does not exist, so there is no encrypted store to mint NOO_AUDIT_HMAC_KEY \
                          into — and it is never written to plaintext .env. Nothing was changed",
                    root.join("secrets/env.sops").display()),
                // Moves a plaintext-.env install onto the encrypted store:
                // the wizard's secrets section mints what is absent (this key
                // included) and runs the SOPS+age init, which encrypts .env
                // and blanks the plaintext copies. A literal, so the hint
                // lint checks it against usage.rs.
                Some("noo onboard --reconfigure --only secrets --secrets-backend sops   # then re-run: noo upgrade --stack"));
        }
        Err(AuditKeyRefusal::Store(e)) => {
            fail(g.json, ExitCode::Generic, "audit_key_mint_failed",
                &format!("could not mint NOO_AUDIT_HMAC_KEY into the encrypted store: {e} — nothing was changed"),
                Some("noo security secrets audit   # then re-run: noo upgrade --stack"));
        }
    }

    // -1a. The bus-principal keys. This release's gateway
    //    signs worker.* messages per audience and its workers verify only
    //    their own key — a store without them is a bus on which every
    //    message is refused. Minted HERE, before anything moves, by the same
    //    mint-only-if-absent writer as the audit key; the launcher below then
    //    recreates the gateway and every verifier with them in one `up`.
    match reconcile_bus_keys(&root) {
        Ok(minted) if minted.is_empty() => {}
        Ok(minted) => if !g.json {
            ui::done(&format!("minted {} into the encrypted store (new in this release: one key per service, so no controller service holds a shared secret)", minted.join(", ")));
        },
        Err(AuditKeyRefusal::NoStore) => {
            fail(g.json, ExitCode::Generic, "bus_keys_no_store",
                &format!("{} does not exist, so there is no encrypted store to mint the bus keys into — and they \
                          are never written to plaintext .env. Nothing was changed",
                    root.join("secrets/env.sops").display()),
                Some("noo onboard --reconfigure --only secrets --secrets-backend sops   # then re-run: noo upgrade --stack"));
        }
        Err(AuditKeyRefusal::Store(e)) => {
            fail(g.json, ExitCode::Generic, "bus_keys_mint_failed",
                &format!("could not mint the bus keys into the encrypted store: {e} — nothing was changed"),
                Some("noo security secrets audit   # then re-run: noo upgrade --stack"));
        }
    }

    // -1b. Enabled systems' credentials: mint what is absent
    //    — never rotate — before anything moves, so the launcher's refusal is
    //    a backstop and never a manual pre-roll step.
    match crate::commands::systems::reconcile_credentials(&root) {
        Ok(minted) => for (name, keys) in minted.iter().filter(|(_, k)| !k.is_empty()) {
            if !g.json { ui::done(&format!("minted {} into the encrypted store ({name} is enabled)", keys.join(", "))); }
        },
        Err(crate::commands::systems::CredRefusal::NoStore(missing)) => fail(g.json, ExitCode::Generic, "system_credentials_no_store",
            &format!("{} does not exist, so there is no encrypted store to mint {} into — and it is never written \
                      to plaintext .env. Nothing was changed", root.join("secrets/env.sops").display(),
                missing.iter().flat_map(|(_, k)| k.iter().cloned()).collect::<Vec<_>>().join(", ")),
            Some("noo onboard --reconfigure --only secrets --secrets-backend sops   # then re-run: noo upgrade --stack")),
        Err(crate::commands::systems::CredRefusal::Store(e)) => fail(g.json, ExitCode::Generic, "system_credentials_mint_failed",
            &format!("could not mint an enabled system's credentials: {e} — nothing was changed"),
            Some("noo systems status   # then re-run: noo upgrade --stack")),
    }

    // 0. Move any RETIRED gate key out of noomesh.yaml BEFORE the roll,
    //    while the old gateway is still up to accept the write.
    migrate_retired_yaml_gates(g, &root);

    // 0.5 Re-render users.conf WITHOUT the retired shared NATS user, before
    //     anything moves. The compose this
    //     binary materialises hands nats no NATS_USER/NATS_PASSWORD; a
    //     users.conf an older CLI rendered still names them, and NATS refuses
    //     to parse it — the stack-v0.2.78 outage. Store-first, idempotent,
    //     mints nothing; the HUP makes the RUNNING server drop the shared
    //     user now, which is safe because nothing may present it (verify
    //     with /connz?auth=1 first — the runbook's step). The launcher's
    //     pre-`up` check refuses the start if this did not happen.
    rerender_nats_users_for_roll(g, &root);

    // 1. Refresh the deploy slice to THIS binary's assets (compose/scripts
    //    track the release; secrets/PKI/noomesh.yaml are never embedded so
    //    never touched). materialize() is idempotent by design, and also
    //    retires a file a PAST release shipped that this one does not
    //     — print whatever it has to say, never fail the
    //    roll over it.
    match crate::onboard::standalone::materialize(&root) {
        Ok(report) => {
            if !g.json {
                for line in report.retired.iter().chain(&report.moved_aside).chain(&report.skipped) {
                    println!("{}", ui::note(line));
                }
            }
        }
        Err(e) => {
            fail(g.json, ExitCode::Generic, "assets_failed",
                &format!("could not refresh embedded assets: {e}"), None);
        }
    }
    // 2. Move the pin.
    // The signed digest lock for this tag, or an
    // explicit "unpinned" when the release predates locks; and, in the same
    // step, the add-on pins resolved for this tag in -1z.
    write_stack_lock(g, &tag, &root, target_stack_lock.as_deref());
    commit_addon_pins(g, &root, &tag, &addon_prep);
    if let Err(e) = crate::onboard::standalone::upsert_env(&root, "NOO_IMAGE_TAG", &tag) {
        fail(g.json, ExitCode::Generic, "pin_failed",
            &format!("could not update NOO_IMAGE_TAG in .env: {e}"), None);
    }
    // 3. Relaunch. The tag is passed EXPLICITLY in the child environment:
    //    the CLI loads .env into its own process env at startup
    //    (ensure_repo_env), so the launcher child inherits the OLD
    //    NOO_IMAGE_TAG — which outranks the freshly-updated .env in the
    //    launcher's resolution order. Live 2026-08-23 (finding #30): the
    //    pin moved to v0.1.76, the launcher deployed v0.1.75, and the
    //    command printed "✓ stack now on v0.1.76" — a false success on the
    //    exact hotfix the operator was waiting for.
    // 2.5. Reconcile service certs a NEW release's compose expects but an
    //    upgraded (not freshly onboarded) install never issued — see
    //    reconcile_service_certs. Before the launcher, so the leaf exists
    //    before Docker can create the bind-mount source as root.
    reconcile_service_certs(g);
    // 2.55. Grafana single sign-on and its door: an install
    //    onboarded before this has no GRAFANA_ROOT_URL, so SSO is off. Before
    //    2.6, so a re-issued grafana leaf reaches pki/public/ in this roll.
    reconcile_grafana_door(g, &root);
    // 2.6. The gateway's certificate-only view. A release
    //    with this compose mounts `pki/public/{nodes,services}` and
    //    `pki/sso` into the gateway instead of the PKI root; an upgraded
    //    install has never had `public/`. Laid down HERE, as the operator,
    //    before the launcher: its bind-source check refuses a missing
    //    source, and Docker would otherwise create it as root.
    sync_gateway_pki_view(g);

    // The launcher's own output (compose pull/up progress) follows this
    // line; it is the one child whose stdout is shown as-is (guide §5).
    if !g.json { ui::step("starting the stack (launcher)"); }
    // Same binary as this process — see mesh.rs::run_script for why
    // (`NOO_CLI_BIN`, resolved by the launcher's `noo_bin` helper).
    let cli_bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let launch = || std::process::Command::new("bash")
        .arg(root.join("scripts/noomesh-start.sh")).arg("--dist")
        .env("NOO_IMAGE_TAG", &tag)
        .env("NOO_CLI_BIN", &cli_bin)
        .current_dir(&root)
        .status();
    let mut status = launch();
    // One automatic retry: the first rail walk died on a GHCR blob timeout
    // over IPv6 (host8, 2026-09-03) — a transient the second attempt sails
    // through, and compose resumes the pull rather than restarting it.
    if matches!(&status, Ok(s) if !s.success()) {
        ui::warned("launcher failed — retrying once in 5s (transient registry errors are common)");
        std::thread::sleep(Duration::from_secs(5));
        status = launch();
    }
    match status {
        Ok(s) if s.success() => {
            // The process's idea of NOO_IMAGE_TAG is now STALE, and the
            // nodes stage runs next in this same process.
            //
            // ensure_repo_env() loads .env into the process environment at CLI
            // startup, so NOO_IMAGE_TAG there is the tag from BEFORE this roll.
            // The launcher has just rewritten .env to `tag`, but release_var()
            // reads the process environment FIRST and only falls back to the
            // file — so every later reader still sees the old value.
            //
            // That is how the bundle shipped the PREVIOUS release's node-agent
            // twice: first through a raw std::env::var (#1181), and then again
            // through image_tag(), because moving to image_tag() changed which
            // function was consulted but not which value it preferred. The
            // second attempt also defeated its own guard — the extracted binary
            // was compared against the tag it had ASKED for, and both were the
            // stale one, so a consistent-but-wrong pair passed (2026-09-06:
            // stack rolled to v0.2.24, three linux nodes stayed on v0.2.23).
            //
            // Correcting it at the source rather than at each reader: the tag
            // just deployed is the truth, so say so once, here, where it
            // changes.
            std::env::set_var("NOO_IMAGE_TAG", &tag);
            if !g.json {
                ui::close_done(&format!("stack now on {tag}"));
                ui::guide(&[("noo cluster verify --wait",
                    "checks the stack, every node and the PKI once the rolled services settle")]);
            }
            // A roll recreates the gateway; the tailnet front door in front
            // of it is written by onboard and promote and by nothing else, so
            // a controller that lost it stays lost while every line above
            // says success. Idempotent and silent when the mapping is already
            // correct; never fails the roll.
            // A named instance mounts under /<instance> on an offset port
            // The same resolution onboard uses — writing the
            // default shape here would claim `/` from another stack.
            if !g.json {
                crate::tailnet_serve::ensure_fronted(
                    8080 + crate::envfile::port_offset(),
                    &crate::envfile::instance(),
                );
                crate::tailnet_serve::print_front_door(
                    8080 + crate::envfile::port_offset(),
                    &crate::envfile::instance(),
                );
            }
            // Prune superseded release images (finding #93: 13 upgrades
            // quietly accumulated 78 tags — gigabytes). Best-effort — a prune
            // failure must never taint a successful roll.
            //
            // Selected by REFERENCE, not by tag text. The old rule kept
            // anything whose text after the last `:` was neither the new tag
            // nor the previous one — which worked until digest pinning
            //  made every stack image arrive UNTAGGED.
            // `docker images` then reports `repo:<none>`, so `<none>` matched
            // neither tag and the whole set was marked stale INCLUDING the
            // images the running containers were built from. `docker rmi -f`
            // refused those, the command exited non-zero, and the operator was
            // told all 51 could not be pruned — while nothing was reclaimed at
            // all, so the count climbed every release (44 → 51 → 52, live
            // 2026-09-05, with 11.6 GB reclaimable sitting there).
            //
            // Note these images are NOT dangling — they have a repository and
            // no tag — so `docker image prune` skips them too. The question
            // this code actually wants to ask is "does any container use it",
            // and that is now the question it asks.
            let in_use = docker_image_ids_in_use();
            let stale = superseded_images(&docker_image_lines(), &in_use, &tag, &prev);
            if !stale.is_empty() {
                // Per-image, so one in-use image cannot report the whole batch
                // as failed. The previous all-or-nothing status was the reason
                // "could not prune 51" was mostly untrue.
                let mut pruned = 0usize;
                let mut kept = 0usize;
                for id in &stale {
                    let ok = std::process::Command::new("docker")
                        .args(["rmi", id])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|st| st.success())
                        .unwrap_or(false);
                    if ok { pruned += 1 } else { kept += 1 }
                }
                if !g.json {
                    // "kept v0.2.43 + previous v0.2.43" names one tag twice and
                    // reads as a bug in the pruner. When the previous tag IS the
                    // one being applied there is no previous to keep, and saying
                    // so is shorter than saying it twice.
                    let kept_label = if prev.is_empty() || prev == tag {
                        format!("kept {tag}")
                    } else {
                        format!("kept {tag} + previous {prev}")
                    };
                    if kept == 0 {
                        ui::done(&format!("pruned {pruned} superseded image(s) ({kept_label})"));
                    } else {
                        ui::done(&format!(
                            "pruned {pruned} superseded image(s); {kept} still referenced and left alone \
                             ({kept_label})"));
                    }
                }
            }
            // Stage the release's node images on the artifact rail (pulled
            // by lock digest with THIS controller's registry login, exported
            // for every fleet architecture). Nodes pull images only from
            // there and hold no registry credential.
            // Best-effort: never taints the roll, names the retry.
            crate::commands::image_stage::stage_after_roll(g, &root, &tag);
            Ok(0)
        }
        Ok(s) => {
            ui::close_failed(&format!("launcher exited with {} twice; the pin IS moved to {tag}", s.code().unwrap_or(-1)), Some("noo stack logs"));
            Ok(1)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "launch_failed",
            &format!("could not run the launcher: {e}"), None),
    }
}

/// The key the audit log signs with. Minted by `noo onboard` on a fresh
/// install and by [`reconcile_audit_key`] on an upgraded one.
pub(crate) const AUDIT_KEY: &str = "NOO_AUDIT_HMAC_KEY";

/// What the stage did — the one line it prints. Never carries the value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditKeyStage {
    AlreadyPresent,
    Minted,
}

/// Why the stage stopped the roll.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditKeyRefusal {
    /// No `secrets/env.sops`: an install that predates the encrypted store
    /// (or opted out with `--secrets-backend env`, or whose SOPS init
    /// failed). "Always sops, never plaintext" — the key is not written to
    /// `.env`; the install is moved onto the store first.
    NoStore,
    /// The store exists but could not be read or written.
    Store(String),
}

/// The decision, with the store behind two closures so the "present → never
/// touched" half is tested without sops.
fn audit_key_stage(
    present: impl FnOnce() -> Result<bool, String>,
    mint: impl FnOnce() -> Result<(), String>,
) -> Result<AuditKeyStage, String> {
    if present()? {
        return Ok(AuditKeyStage::AlreadyPresent);
    }
    mint()?;
    Ok(AuditKeyStage::Minted)
}

/// Stage: mint `NOO_AUDIT_HMAC_KEY` into this install's ENCRYPTED store when
/// it is absent. Runs before anything else in the roll moves; an `Err` stops
/// it. There is no plaintext branch: an install without `secrets/env.sops`
/// is refused with the command that moves it onto the store.
fn reconcile_audit_key(root: &std::path::Path) -> Result<AuditKeyStage, AuditKeyRefusal> {
    let sops = root.join("secrets/env.sops");
    if !sops.is_file() {
        return Err(AuditKeyRefusal::NoStore);
    }
    // mint_missing re-reads the store, mints only absent keys, commits
    // atomically and proves the round trip — and refuses on a failed
    // decrypt rather than writing over an unreadable store.
    audit_key_stage(
        || crate::commands::secrets::SecretStore::load_sops(&sops).map(|s| s.contains(AUDIT_KEY)),
        || crate::commands::secrets::mint_missing(&[AUDIT_KEY], &sops).map(|_| ()),
    )
    .map_err(AuditKeyRefusal::Store)
}

/// Every consumer that must hold its own gateway key, as `(provision name,
/// consumer)` (`cluster_verify::required_service_keys`: the worker always,
/// each add-on that is on).
fn required_consumers() -> Vec<(String, String)> {
    let addon_on = |name: &str| {
        crate::commands::addons::effective(name)
            .unwrap_or_else(|| crate::commands::addons::row(name).map(|r| r.default_on).unwrap_or(false))
    };
    crate::commands::cluster_verify::required_service_keys(&addon_on)
}

/// The provision names whose store key (`NOO_SVC_KEY_*`) is missing or
/// BLANK in this install's encrypted store. An unreadable store answers
/// "all of them": it cannot be shown otherwise.
fn keyless_in_store(root: &std::path::Path, required: &[(String, String)]) -> Vec<String> {
    let store = crate::commands::secrets::SecretStore::load_sops(&root.join("secrets/env.sops")).ok();
    keyless_in_store_of(required, &|key: &str| {
        store.as_ref().is_some_and(|s| matches!(s.state(key), crate::commands::secrets::State::Set))
    })
}

/// Pure half of [`keyless_in_store`].
fn keyless_in_store_of(required: &[(String, String)], set: &dyn Fn(&str) -> bool) -> Vec<String> {
    required
        .iter()
        .filter(|(name, _)| match crate::commands::secrets::provision_targets(name) {
            Some(t) => !set(&t.secret_key),
            None => true,
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The pre-roll decision.
#[derive(Debug, PartialEq, Eq)]
enum PreRollKeys {
    Go,
    /// `--skip-gateway-key-check` and the gateway could not be asked: the
    /// store check passed.
    GoUnverified,
    Missing(Vec<String>),
    /// The gateway could not be asked and there is no `--skip-gateway-key-check`.
    Unverifiable,
}

fn pre_roll_key_verdict(store_short: &[String], db_short: Option<&[String]>, skip_gw_key_check: bool) -> PreRollKeys {
    let mut missing: Vec<String> = store_short.to_vec();
    for n in db_short.unwrap_or_default() {
        if !missing.contains(n) {
            missing.push(n.clone());
        }
    }
    if !missing.is_empty() {
        return PreRollKeys::Missing(missing);
    }
    match (db_short, skip_gw_key_check) {
        (Some(_), _) => PreRollKeys::Go,
        (None, true) => PreRollKeys::GoUnverified,
        (None, false) => PreRollKeys::Unverifiable,
    }
}

/// The provision names in `required` with no active key in the gateway's `listing`.
fn keyless_of(required: &[(String, String)], listing: &serde_json::Value) -> Vec<String> {
    crate::onboard::steps::consumers_to_mint(required, listing).into_iter().map(|(n, _)| n.clone()).collect()
}

/// The per-service keys added since 0.2.x, all controller-local: the
/// bus-principal keys, one per audience (`gateway-rust/src/bus_principal.rs`
/// AUDIENCES), and the browser door's key. Minted on onboard and by
/// [`reconcile_bus_keys`] on an upgraded install; the launcher's
/// `require_bus_keys` refuses a start without any of them.
pub(crate) const PER_SERVICE_KEYS: &[&str] =
    &["NOO_BUS_KEY_WORKER", "NOO_BUS_KEY_TRELLION", "NOO_BUS_KEY_TRELLION_INTEL", "NOO_BROWSER_KEY"];

/// Stage: mint every [`PER_SERVICE_KEYS`] entry the ENCRYPTED store lacks or holds
/// BLANK (review L2: an empty value is no key). Never rotates one that is
/// set; refuses (like the audit key) when there is no store, rather than
/// writing plaintext. Returns the keys minted.
fn reconcile_bus_keys(root: &std::path::Path) -> Result<Vec<String>, AuditKeyRefusal> {
    let sops = root.join("secrets/env.sops");
    if !sops.is_file() {
        return Err(AuditKeyRefusal::NoStore);
    }
    crate::commands::secrets::mint_unset(PER_SERVICE_KEYS, &sops)
        .map(|(minted, _)| minted)
        .map_err(AuditKeyRefusal::Store)
}

/// `SVC_LIST` names the mounted service certs the CURRENT release's compose
/// expects; `existing` is whichever of those this install has already
/// issued (a `service.crt` file on disk). Pure so the decision is tested
/// without a CA or a filesystem walk — the newcomer-upgrade rehearsal
/// (2026-09-29) needs exactly one thing right: which services in a release's
/// list an OLD install has never seen.
fn missing_service_certs<'a>(
    all: &[&'a str],
    existing: &std::collections::HashSet<&str>,
) -> Vec<&'a str> {
    all.iter().copied().filter(|s| !existing.contains(s)).collect()
}

/// A release can add a service whose compose mounts
/// `${NOO_PKI_DIR}/services/<svc>` before that service ever had a
/// certificate — onboarding's `ensure_pki` loop issues one for every name
/// in `onboard::steps::SVC_LIST`, but an UPGRADED install never runs that
/// loop. Left alone, the launcher starts the new stack, Docker creates the
/// missing bind-mount source as ROOT, and the service dies on its own
/// missing certificate (v0.2.76 → v0.2.77, `model-cache`, newcomer-upgrade
/// rehearsal 2026-09-29) — `noo cluster verify` then names the remedy, but
/// the remedy itself fails with EACCES against the root-owned directory it
/// just diagnosed (see `pki_issue_service`'s permission hint).
///
/// Runs BEFORE the launcher so the certificate exists before Docker can
/// create the mount point as root. Best-effort: a failure to issue is a
/// warn with the remedy, never an abort of the roll.
fn reconcile_service_certs(g: &Globals) {
    let pki_dir = crate::pki::pki_dir();
    let existing: std::collections::HashSet<&str> = crate::onboard::steps::SVC_LIST
        .iter()
        .copied()
        .filter(|svc| pki_dir.join("services").join(svc).join("service.crt").is_file())
        .collect();
    let missing = missing_service_certs(crate::onboard::steps::SVC_LIST, &existing);
    let ca = crate::pki::ClusterCa::new(pki_dir);
    if !ca.ca_exists() {
        // No CA means onboarding never completed on this box — the
        // install_incomplete guard earlier in upgrade_stack already
        // refuses that case, so this is unreachable in practice.
        return;
    }
    reconcile_grafana_sso_key(g, &ca);
    // Every key, directory and certificate mode this CLI owns: an older install had 0644 leaf keys.
    let _ = super::pki::reconcile_key_modes(g, &ca);
    let (hostname, node_ip, ts_dnsname) = crate::onboard::steps::local_cert_identity();
    // Leaves that EXIST but fall short of today's derived names
    // 1342: model-cache issued before it joined EXTERNALLY_REACHABLE was
    // kept forever, and every remote node's fetch failed hostname
    // verification). The launcher below force-recreates the stack, which is
    // what makes each consumer load the new leaf.
    reconcile_short_service_certs(g, &ca, &existing, &hostname, &node_ip, &ts_dnsname);
    if missing.is_empty() {
        return;
    }
    for svc in missing {
        let (extra, extra_ips) =
            crate::onboard::steps::service_cert_sans(svc, &hostname, &node_ip, &ts_dnsname);
        match ca.issue_service_cert(svc, &extra, &extra_ips, crate::pki::DEFAULT_DAYS) {
            Ok(_) => {
                if !g.json {
                    ui::done(&format!("issued the {svc} service certificate (new in this release)"));
                }
            }
            Err(e) => {
                if !g.json {
                    let dir = crate::pki::pki_dir().join("services").join(svc);
                    // A root-owned dir (Docker created the bind source on an
                    // earlier start) is the actionable fact: name the chown.
                    let why = super::pki::permission_denied_hint(&e, &dir).unwrap_or(e);
                    ui::warned(&format!(
                        "{svc} service certificate: {why} — then: noo security pki issue-service {svc}, then: noo stack restart --force"
                    ));
                }
            }
        }
    }
}

/// Re-issue every existing service leaf whose SANs miss the derived set,
/// one line each. Best-effort like the rest of the pass: a failure is a warn
/// naming the exact remedy, never an abort of the roll.
fn reconcile_short_service_certs(
    g: &Globals,
    ca: &crate::pki::ClusterCa,
    existing: &std::collections::HashSet<&str>,
    hostname: &str,
    node_ip: &str,
    ts_dnsname: &str,
) {
    use crate::onboard::steps::NamesOutcome;
    for svc in crate::onboard::steps::SVC_LIST.iter().filter(|s| existing.contains(*s)) {
        let outcome = crate::onboard::steps::ensure_service_cert_names(ca, svc, hostname, node_ip, ts_dnsname);
        if g.json {
            continue;
        }
        match outcome {
            Ok(NamesOutcome::NoLeaf | NamesOutcome::Covered) => {}
            Ok(NamesOutcome::Reissued { missing, unreadable }) => match unreadable {
                Some(why) => ui::warned(&format!(
                    "the {svc} service certificate could not be read ({why}) — re-issued it"
                )),
                None => ui::done(&format!(
                    "re-issued the {svc} service certificate to add {}",
                    missing.join(", ")
                )),
            },
            Err(e) => {
                let dir = ca.dir.join("services").join(svc);
                let why = super::pki::permission_denied_hint(&e, &dir).unwrap_or(e);
                ui::warned(&format!(
                    "{svc} service certificate is missing names and could not be re-issued: {why} — then: noo security pki issue-service {svc}, then: noo stack restart --force {svc}"
                ));
            }
        }
    }
}

/// Fill `GRAFANA_ROOT_URL` + `NOO_GRAFANA_BIND_ADDR` from the install's
/// declared door when SSO is off, put a published address wider than that
/// door back on it, and give Grafana's leaf the tailnet name the URL uses —
/// before the launcher, so the roll recreates the gateway and Grafana with
/// them. One line per change; silent when there is none. Never fails the
/// roll: `noo cluster verify` FAILs the `grafana door` row instead.
fn reconcile_grafana_door(g: &Globals, root: &std::path::Path) {
    use super::grafana_door as gd;
    let env_path = root.join(".env");
    let declared = gd::declared_door(&env_path);
    // The tailnet door: `tailscale serve` on Grafana's own port, so the
    // browser gets the tailnet's certificate (tailnet_serve.rs). ADDITIVE:
    // only that port's handler is written, never over an entry already
    // there. Grafana moves to loopback only once the entry is CONFIRMED; a
    // failed write (no tailscale, tailscaled down) keeps today's tailnet-IP
    // publish and never fails the roll. `-n` sudo only, never a prompt.
    // Before the launcher: serve config is static and proxies the moment
    // the loopback Grafana the launcher recreates answers.
    // Plus `/login` on that port → the console's Open Grafana, so a bookmark
    // of Grafana is not a dead end (tailnet_serve.rs); only once `/` is ours.
    let report = gd::reconcile_door(
        &env_path,
        &declared,
        &crate::envfile::instance(),
        &|port| crate::tailnet_serve::ensure_grafana_fronted(port, true),
        &|port| crate::tailnet_serve::ensure_grafana_login(port, true),
    );
    let door = report.door.clone();
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let leaf = gd::ensure_leaf_names_door(&ca, &door, &hostname, &crate::onboard::util::detect_ip());
    if g.json {
        return;
    }
    if let Some((port, Ok(crate::tailnet_serve::Fronting::Written))) = &report.front {
        ui::done(&format!("tailscale serve now fronts Grafana on :{port} ({})", door.root_url));
    }
    if let Some(w) = report.warning() {
        ui::warned(&w);
    }
    if let Some(Ok(crate::tailnet_serve::Fronting::Written)) = &report.login {
        ui::done(&format!("a bookmark of {} now leads to the console's Open Grafana", door.root_url));
    }
    if let Some(w) = report.login_warning() {
        ui::warned(&w);
    }
    match &report.said {
        Ok(lines) => lines.iter().for_each(|l| ui::done(l)),
        Err(e) => ui::warned(&format!("Grafana single sign-on stays off: {e}")),
    }
    match leaf {
        Ok(true) => ui::done(&format!("re-issued the grafana service certificate to name {}", door.host())),
        Ok(false) => {}
        Err(e) => ui::warned(&format!("grafana service certificate: {e} — then: noo security pki issue-service grafana --san {}", door.host())),
    }
}

/// Create and fill `pki/public/` (the gateway's certificate-only view,
// Before the launcher runs. Best-effort like the cert
/// reconcile: a failure is a warn naming the fix, and the launcher's own
/// bind-source check then refuses loudly, naming the directory.
fn sync_gateway_pki_view(g: &Globals) {
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    if !ca.ca_cert_path().is_file() {
        return;
    }
    let view = ca.sync_public_view();
    if g.json {
        return;
    }
    if view.errors.is_empty() {
        if !view.copied.is_empty() || !view.removed.is_empty() {
            ui::done(&format!(
                "gateway certificate view (pki/public/): {} certificate(s), {} written",
                view.total,
                view.copied.len()
            ));
        }
        return;
    }
    for e in &view.errors {
        let why = super::pki::public_view_hint(&ca, e).unwrap_or_else(|| e.clone());
        ui::warned(&format!("gateway certificate view (pki/public/): {why} — then: noo security pki fix-modes"));
    }
}

/// The Grafana SSO key pair arrived with the monitoring
/// set, and like a new service certificate an UPGRADED install never ran
/// the onboarding step that mints it. Left alone, compose bind-mounts the
/// missing `sso/grafana.pub`, Docker creates it as a root-owned DIRECTORY,
/// and Grafana dies on `read /app/pki/sso/grafana.pub: is a directory`
/// (v0.2.77 → v0.2.78 on the controller, 2026-09-29). Minted here, before
/// the launcher, for the same reason the service certificates are.
/// Best-effort: a failure is a warn naming the exact remedy.
fn reconcile_grafana_sso_key(g: &Globals, ca: &crate::pki::ClusterCa) {
    if ca.grafana_sso_key_exists() {
        return;
    }
    // An earlier roll already let Docker invent the directory: we cannot
    // remove a root-owned dir, so name the one command that can.
    if let Some(fix) = sso_pub_blocker(&ca.grafana_sso_pub_path()) {
        if !g.json {
            ui::warned(&format!(
                "Grafana SSO key: {} is a directory Docker created — fix: {fix}, then: noo security pki issue-sso-key, then: noo stack restart --force",
                ca.grafana_sso_pub_path().display()
            ));
        }
        return;
    }
    match ca.ensure_grafana_sso_key() {
        Ok(_) => {
            if !g.json {
                ui::done("issued the Grafana SSO key pair (new in this release)");
            }
            if let Err(cmd) = ca.grafana_sso_key_grant_gateway_read() {
                if !g.json {
                    ui::warned(&format!("Grafana SSO key: the gateway cannot read it yet — fix: {cmd}"));
                }
            }
        }
        Err(e) => {
            if !g.json {
                let dir = ca.grafana_sso_key_path().parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let why = super::pki::permission_denied_hint(&e, &dir).unwrap_or(e);
                ui::warned(&format!("Grafana SSO key: {why} — then: noo security pki issue-sso-key"));
            }
        }
    }
}

/// A bind-mount source Docker created because the file did not exist yet
/// is a root-owned directory where a file belongs. `Some(remedy)` when
/// `path` is such a directory.
///
/// Docker creates the PARENT (`sso/`) as root too, so removing the pub
/// alone still leaves `issue-sso-key` with EACCES — the upgrade sandbox
/// walked exactly that loop (2026-09-29). One line hands both back.
fn sso_pub_blocker(path: &std::path::Path) -> Option<String> {
    let dir = path.parent().unwrap_or(path);
    path.is_dir().then(|| {
        format!("sudo rm -r {} && sudo chown \"$(id -un):$(id -gn)\" {}", path.display(), dir.display())
    })
}


/// The nodes `upgrade --nodes` restages over the rail: every live
/// enrollment, minus the controller's own node when this box is the
/// controller (it is upgraded by the local lane), with any self node that
/// remains last so its restage lands after every remote one.
fn rail_names(mut names: Vec<String>, is_self: impl Fn(&str) -> bool, on_controller: bool) -> Vec<String> {
    if on_controller {
        names.retain(|n| !is_self(n));
    }
    names.sort_by_key(|n| is_self(n));
    names
}

/// Restage a provision bundle for every pull-capable node on record (has a
/// redeemed enrollment WITH a birth cert). Nodes collect + apply on their
/// own noo-fetch timer — no SSH, no waiting here. Self/local agents are
/// upgraded through the local lane at the end of this phase, not the rail.
fn upgrade_nodes(g: &Globals) -> Result<i32, Unhandled> {
    // The gateway wait is the caller's Gateway phase (run_fleet_stages).
    let doc = crate::http::get_json(g, "/api/security/bootstrap-tokens", true, 15);
    let Some(toks) = doc.get("tokens").and_then(|t| t.as_array()) else {
        fail(g.json, ExitCode::Generic, "gateway_unreachable",
            "could not list enrollments from the gateway",
            Some("is the controller stack running? (noo stack status)"));
    };
    let mut names: Vec<String> = toks.iter()
        .filter(|t| super::provision::is_live_enrollment(t))
        .filter_map(|t| t.get("node_name").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    names.sort();
    names.dedup();
    // i11a: on a controller, its own node is never a rail node. It does not
    // enroll with itself, so a record under its name is another machine
    // that announced the same name, and restaging from it re-issued the
    // controller's cert without the controller names (and kept the local
    // lane below from running, since the name looked "on the rail").
    let names = rail_names(names, crate::role::is_self_node, crate::role::detect().controller.is_some());
    // Put this controller's CLI release assets where the fleet can reach
    // them: the cache (bundles carry them) and the gateway (/bootstrap/cli
    // serves them to a node-side `noo upgrade`). This always covers this
    // controller's own platform plus linux/x86_64 and linux/aarch64 — not
    // only what's already enrolled — so a fresh controller with zero or one
    // node still stages hostd and the harness for the platforms a first
    // node is likely to be. Deriving the set from enrolled facts alone left
    // a zero-node fleet with an empty cache, and the first provision bundle
    // with neither (newcomer rehearsal, 2026-09-28). Run this BEFORE the
    // no-nodes check below, not after it.
    if !g.json { println!("{}", ui::phase("CLI Assets")); }
    upload_cli_assets(g, toks);

    if names.is_empty() {
        let platforms = asset_platforms(toks, std::env::consts::OS, std::env::consts::ARCH);
        let list = platforms.iter()
            .map(|(os, arch)| format!("{os}/{arch}"))
            .collect::<Vec<_>>()
            .join(", ");
        ui::done(&format!("no nodes yet — staged assets for {list} so the first provision bundle carries hostd and the harness"));
        ui::guide(&[("noo cluster provision <node> --local", "local/self agents are provisioned directly, not through the pull rail")]);
        return Ok(0);
    }
    // Macs whose applier predates the svc-* kinds get this pass's bundle
    // WITHOUT their backend door leaves (the child decides on the same
    // records, `provision::redemption_record` + `live_node_record`). Read
    // BEFORE staging: the reported version is what the child will see.
    let leaf_budget = mac_leaves_budget(std::env::var(MAC_LEAVES_WAIT_ENV).ok().as_deref());
    let leafless: Vec<String> = leafless_macs(&names.iter().map(|n| {
        let darwin = super::provision::enrolled_os(super::provision::redemption_record(g, n).as_ref()) == "macos";
        let version = super::provision::live_app_version(super::provision::live_node_record(g, n).as_ref());
        (n.clone(), darwin, version)
    }).collect::<Vec<_>>());
    if !leafless.is_empty() && leaf_budget > 0 {
        // The child's "leaves withheld" note then says this run restages
        // the node, instead of asking the operator to (node_leaves.rs).
        std::env::set_var(super::node_leaves::UPGRADE_RESTAGES_LEAVES_ENV, "1");
    }
    if !g.json { println!("{}", ui::phase("Nodes")); }
    println!("{}", ui::note(&format!("restaging provision bundles for {} node(s): {}", names.len(), names.join(", "))));
    let mut failed: Vec<String> = Vec::new();
    // Nodes already offline BEFORE the roll cannot fetch anything: staging
    // for them only burns the wait window and fails the whole stage
    // (host8-ma, v0.2.93 roll). Skip them loudly, with the one command that
    // catches them up. Judged once, up front, from the registry.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let read_records = || -> Vec<(String, Option<serde_json::Value>)> {
        names.iter().map(|n| (n.clone(), super::provision::live_node_record(g, n))).collect()
    };
    let records = read_records();
    // Right after the gateway (re)starts every node's record is stale, so a
    // stale heartbeat only means "offline" once the gateway has been up long
    // enough to have heard one (v0.2.95 roll: host6 skipped, online a minute
    // later). Same `last_heartbeat` that `noo cluster verify` trusts.
    let uptime = crate::http::get_raw_opt(g, "/metrics", true, 10)
        .filter(|(status, _)| (200..300).contains(status))
        .and_then(|(_, text)| super::cluster_verify::parse_legacy_lane_metrics(&text).start_unix)
        .map(|start| now - start);
    let mut drew_wait = false;
    let skipped = judge_offline_after_grace(
        records, uptime, now,
        &mut |_| read_records(),
        &mut |secs| std::thread::sleep(std::time::Duration::from_secs(secs)),
        &mut || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        &mut |line| match (g.json, ui::stderr_is_tty()) {
            (true, _) => {}
            // One line counting down, not a new line every 5 s.
            (false, true) => {
                ui::rewrite_line(&ui::note(line));
                drew_wait = true;
            }
            (false, false) => println!("{}", ui::note(line)),
        },
    );
    if drew_wait {
        ui::clear_line();
    }
    for n in &names {
        if let Some((_, why)) = skipped.iter().find(|(s, _)| s == n) {
            println!();
            println!("{}", ui::item(n));
            println!("{}", ui::sub(&ui::status_line(Glyph::Warn,
                &format!("{n}: skipped — offline before the roll ({why}); nothing to wait for"))));
            continue;
        }
        // Each node is an item; cluster provision prints the `ui::item`
        // label and its indented steps. A blank line separates nodes.
        println!();
        match provision_one(g, n, &[]) {
            Ok(0) => {}
            _ => failed.push(n.clone()),
        }
    }
    // The controller's OWN agent, which the rail structurally cannot reach.
    if let Some(me) = local_agent_node(&names) {
        // The child prints its own `ui::item` label, as the rail nodes do.
        println!();
        upgrade_local_agent(g, &me, &mut failed);
    }
    // A node whose first staging failed is already in `failed`; waiting
    // for it to apply a bundle it never got would only burn the budget.
    let waiting: Vec<String> = leafless.into_iter()
        .filter(|n| !failed.contains(n) && !skipped.iter().any(|(s, _)| s == n)).collect();
    let mut remaining: Vec<String> = Vec::new();
    if !waiting.is_empty() {
        let outcomes = mac_leaves_pass(g, &waiting, leaf_budget);
        if g.json {
            println!("{}", serde_json::json!({
                "mac_leaves": outcomes.iter().map(|(n, o)| serde_json::json!({"node": n, "outcome": o.word()})).collect::<Vec<_>>(),
            }));
        }
        for (n, o) in outcomes {
            if o != MacLeaves::Restaged {
                failed.push(n.clone());
                remaining.push(n);
            }
        }
    }
    let skipped_names: Vec<String> = skipped.iter().map(|(n, _)| n.clone()).collect();
    if g.json && !skipped.is_empty() {
        println!("{}", serde_json::json!({
            "skipped_offline": skipped.iter().map(|(n, why)| serde_json::json!({"node": n, "reason": why})).collect::<Vec<_>>(),
        }));
    }
    let staged_failed: Vec<String> = failed.iter().filter(|n| !remaining.contains(n)).cloned().collect();
    let (rc, msg) = nodes_outcome(names.len(), &skipped_names, &staged_failed, &remaining);
    if !skipped.is_empty() && !g.json {
        let cmds: Vec<String> = skipped_names.iter().map(|n| format!("noo cluster provision {n} --wait")).collect();
        let why = "once the node is back online, catches it up";
        if rc == 0 {
            ui::close_warned(&msg);
        } else {
            ui::close_failed(&msg, None);
        }
        ui::guide(&cmds.iter().map(|c| (c.as_str(), why)).collect::<Vec<_>>());
    } else if rc == 0 {
        ui::close_done(&msg);
    } else {
        ui::close_failed(&msg, None);
    }
    if rc != 0 && !remaining.is_empty() && !g.json {
        // A Mac that never reported the new CLI is reported like a staging
        // failure — its leaves are not on it — with the one command left.
        let cmds: Vec<String> = remaining.iter().map(|n| format!("noo cluster provision {n}")).collect();
        let why = "stages the backend door leaves once the Mac reports the new CLI";
        ui::guide(&cmds.iter().map(|c| (c.as_str(), why)).collect::<Vec<_>>());
    }
    Ok(rc)
}

/// A gateway younger than this has not had time to hear every node's
/// heartbeat (two intervals plus margin), so a stale record proves nothing.
const GATEWAY_SETTLE_SECS: i64 = 300;
/// The most the nodes stage waits for heartbeats to land.
const HEARTBEAT_GRACE_SECS: u64 = 90;
const HEARTBEAT_GRACE_POLL_SECS: u64 = 5;

/// `offline_nodes`, but while the gateway is too young (or its age unknown)
/// to trust stale heartbeats, wait (bounded) and re-read before judging. A
/// node is offline before the roll only if it is STILL stale after the grace.
fn judge_offline_after_grace(
    mut records: Vec<(String, Option<serde_json::Value>)>,
    gateway_uptime: Option<i64>,
    now_unix: i64,
    reread: &mut dyn FnMut(u64) -> Vec<(String, Option<serde_json::Value>)>,
    sleep: &mut dyn FnMut(u64),
    clock: &mut dyn FnMut() -> i64,
    progress: &mut dyn FnMut(&str),
) -> Vec<(String, String)> {
    let mut now = now_unix;
    let skipped = offline_nodes(&records, now);
    let young = gateway_uptime.is_none_or(|u| u < GATEWAY_SETTLE_SECS);
    if skipped.is_empty() || !young {
        return skipped;
    }
    // Only a node the restart could explain is worth the wait. One already
    // silent for LONG_GONE_SECS when the gateway started (host2, 21 h, on
    // the v0.2.97 roll) was offline before the roll whatever the gateway's
    // age: it is judged at once, not after 90 s of "waiting for heartbeats".
    let started_ago = gateway_uptime.unwrap_or(GATEWAY_SETTLE_SECS);
    let (gone, mut pending): (Vec<_>, Vec<_>) = skipped.into_iter().partition(|(n, _)| {
        let rec = records.iter().find(|(r, _)| r == n).and_then(|(_, r)| r.as_ref());
        match rec.and_then(|r| heartbeat_age(r, now)) {
            Some(age) => age - started_ago > LONG_GONE_SECS,
            None => true, // offline with no heartbeat on record: nothing to wait for
        }
    });
    let mut waited = 0;
    while !pending.is_empty() && waited < HEARTBEAT_GRACE_SECS {
        let names: Vec<&str> = pending.iter().map(|(n, _)| n.as_str()).collect();
        progress(&format!("the gateway just started — waiting for heartbeats from {} (up to {}s)",
            names.join(", "), HEARTBEAT_GRACE_SECS - waited));
        sleep(HEARTBEAT_GRACE_POLL_SECS);
        waited += HEARTBEAT_GRACE_POLL_SECS;
        records = reread(waited);
        now = clock();
        let still = offline_nodes(&records, now);
        pending.retain(|(n, _)| still.iter().any(|(s, _)| s == n));
        for (n, why) in still {
            if let Some(p) = pending.iter_mut().find(|(s, _)| *s == n) {
                p.1 = why;
            }
        }
    }
    let mut out = gone;
    out.extend(pending);
    out.sort_by_key(|(n, _)| records.iter().position(|(r, _)| r == n).unwrap_or(usize::MAX));
    out
}

/// A node silent this long before the gateway started was offline before the
/// roll; no restart explains it. Generous: a roll's own downtime has left a
/// record 28 min stale (host6, v0.2.95) and that node still came back.
const LONG_GONE_SECS: i64 = 3600;

/// Seconds since the record's last heartbeat, if it carries one.
fn heartbeat_age(rec: &serde_json::Value, now_unix: i64) -> Option<i64> {
    use super::cluster_verify::parse_rfc3339_unix;
    rec["last_heartbeat"].as_str().and_then(parse_rfc3339_unix).map(|t| now_unix - t)
}

/// Nodes that were offline before the roll started: `(name, why)` for a
/// registry record whose status is "offline" or whose last heartbeat is older
/// than the offline threshold. A node with no record, or no heartbeat stamp
/// yet (freshly provisioned), is NOT skipped — absent evidence is not
/// evidence of absence, and staging it is the old behaviour.
fn offline_nodes(records: &[(String, Option<serde_json::Value>)], now_unix: i64) -> Vec<(String, String)> {
    use super::cluster_verify::{parse_rfc3339_unix, HEARTBEAT_MAX_AGE_SECS};
    let mut out = Vec::new();
    for (name, rec) in records {
        let Some(rec) = rec else { continue };
        let age = rec["last_heartbeat"].as_str().and_then(parse_rfc3339_unix).map(|t| now_unix - t);
        let status = rec["status"].as_str().unwrap_or("");
        let why = match (status, age) {
            (_, Some(a)) if a > HEARTBEAT_MAX_AGE_SECS => Some(format!("last heartbeat {} ago", age_words(a))),
            ("offline", Some(a)) => Some(format!("status offline, last heartbeat {} ago", age_words(a))),
            ("offline", None) => Some("status offline".to_string()),
            _ => None,
        };
        if let Some(w) = why {
            out.push((name.clone(), w));
        }
    }
    out
}

fn age_words(secs: i64) -> String {
    match secs {
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 86_400 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

/// The nodes stage's verdict. Skipped-offline nodes warn but do not fail
/// (exit 0: the CLI has no partial-success code, and nothing the operator
/// must fix is blocking the roll); any node that was online and did not take
/// its bundle still fails the stage.
fn nodes_outcome(total: usize, skipped: &[String], staged_failed: &[String], remaining: &[String]) -> (i32, String) {
    let mut parts: Vec<String> = Vec::new();
    if !staged_failed.is_empty() { parts.push(format!("staging failed for: {}", staged_failed.join(", "))); }
    if !remaining.is_empty() { parts.push(format!("backend door leaves not staged for: {}", remaining.join(", "))); }
    if !parts.is_empty() {
        if !skipped.is_empty() { parts.push(format!("skipped offline: {}", skipped.join(", "))); }
        return (1, parts.join("; "));
    }
    if skipped.is_empty() {
        return (0, format!("bundles staged for all {total} node(s) — each applies on its next fetch tick"));
    }
    (0, format!("bundles staged for {} of {total} node(s); skipped offline: {} — each online node applies on its next fetch tick",
        total - skipped.len(), skipped.join(", ")))
}

/// Env override for how long `noo upgrade --nodes` waits for a leafless Mac
/// to report the new CLI before restaging it (seconds; 0 = do not wait).
const MAC_LEAVES_WAIT_ENV: &str = "NOO_UPGRADE_MAC_LEAVES_WAIT_SECS";
/// Default: ten minutes — a Mac collects on a 60 s LaunchDaemon tick
/// (`node_fetch::fetch_daemon_plist`), then its agent restarts and
/// heartbeats; a healthy Mac is back well inside this.
const MAC_LEAVES_WAIT_DEFAULT: u64 = 600;
const MAC_LEAVES_POLL_SECS: u64 = 15;

fn mac_leaves_budget(env: Option<&str>) -> u64 {
    env.and_then(|v| v.trim().parse().ok()).unwrap_or(MAC_LEAVES_WAIT_DEFAULT)
}

/// Would `cluster provision` withhold this node's backend door leaves? The
/// SAME predicate the child stages by (`node_leaves::applier_knows_leaf_kinds`):
/// only a Mac, only on a known version below the floor.
fn needs_leaf_restage(darwin: bool, app_version: &str) -> bool {
    darwin && !super::node_leaves::applier_knows_leaf_kinds(darwin, app_version)
}

/// `(node, darwin, reported app_version)` → the nodes this pass stages
/// without leaves, which need a second pass once they report the new CLI.
fn leafless_macs(nodes: &[(String, bool, String)]) -> Vec<String> {
    nodes.iter().filter(|(_, d, v)| needs_leaf_restage(*d, v)).map(|(n, _, _)| n.clone()).collect()
}

/// Has the node reported a CLI whose applier installs the svc-* kinds?
/// Stricter than the stager: an empty or unparseable version (offline, not
/// yet heartbeated) is NOT there yet — this is a wait, not a staging guess.
fn reached_leaf_floor(app_version: &str) -> bool {
    super::node_leaves::cli_version_triple(app_version)
        .is_some_and(|v| v >= super::node_leaves::LEAF_KINDS_MAC_FLOOR)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacLeaves {
    /// Reported the new CLI; restaged with its leaves.
    Restaged,
    /// Reported the new CLI, but the second staging failed.
    RestageFailed,
    /// Never reported the new CLI within the budget.
    TimedOut,
}

impl MacLeaves {
    fn word(self) -> &'static str {
        match self {
            MacLeaves::Restaged => "restaged",
            MacLeaves::RestageFailed => "restage_failed",
            MacLeaves::TimedOut => "timed_out",
        }
    }
}

fn floor_str() -> String {
    let (a, b, c) = super::node_leaves::LEAF_KINDS_MAC_FLOOR;
    format!("{a}.{b}.{c}")
}

/// The "Mac leaves" phase: wait (one shared budget) for each leafless Mac
/// to report the new CLI, then restage it — this bundle carries the leaves.
/// Not unit-tested (network loop); its decisions are the pure fns above.
fn mac_leaves_pass(g: &Globals, nodes: &[String], budget: u64) -> Vec<(String, MacLeaves)> {
    if !g.json { println!("{}", ui::phase("Mac Leaves")); }
    let floor = floor_str();
    if !g.json {
        println!("{}", ui::note(&format!(
            "{} staged without backend door leaves (applier below noo-cli {floor}); \
             restaging once each reports the new CLI", nodes.join(", "))));
    }
    let start = std::time::Instant::now();
    let mut out = Vec::new();
    for n in nodes {
        if !g.json { println!(); println!("{}", ui::item(n)); }
        let mut poll: Option<ui::Poll> = None;
        let reached = loop {
            let v = super::provision::live_app_version(super::provision::live_node_record(g, n).as_ref());
            if reached_leaf_floor(&v) {
                if !g.json {
                    let msg = format!("{n} reports {v}");
                    match poll.take() { Some(p) => p.done(&msg), None => println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &msg))) }
                }
                break true;
            }
            let elapsed = start.elapsed().as_secs();
            if elapsed >= budget {
                drop(poll);
                break false;
            }
            if !g.json {
                let p = poll.get_or_insert_with(|| ui::Poll::start_under(&format!(
                    "waiting for {n} to report noo-cli {floor} or later (up to {}m)", budget.div_ceil(60))));
                p.tick(elapsed);
            }
            std::thread::sleep(Duration::from_secs(MAC_LEAVES_POLL_SECS.min(budget - elapsed)));
        };
        if !reached {
            if !g.json {
                println!("{}", ui::sub(&ui::status_line(Glyph::Warn, &format!(
                    "{n} did not report noo-cli {floor} within {}s — its leaves are not staged", budget))));
            }
            out.push((n.clone(), MacLeaves::TimedOut));
            continue;
        }
        // The child prints its own item label and steps.
        if !g.json { println!(); }
        let rc = provision_one(g, n, &[]);
        out.push((n.clone(), if matches!(rc, Ok(0)) { MacLeaves::Restaged } else { MacLeaves::RestageFailed }));
    }
    out
}

/// This host's own node name, when it runs an agent the pull rail cannot see.
///
/// A standalone controller runs `noo-node-agent` as a host systemd service
/// exactly like every worker — the agents are not different. What differs is
/// DELIVERY: workers are enrolled, so they hold a birth cert and run a
/// `noo-fetch` timer that collects staged bundles. The controller mints its own
/// certs from the local PKI and never enrolls with itself, so it has neither.
///
/// `upgrade_nodes` filters on the enrollment record, which made the controller
/// invisible to `--all`. On 2026-09-05 it was the one machine in the fleet on a
/// stale agent (stack-v0.2.4 against a v0.2.22 fleet) and nothing said so —
/// `--all` reads as "everything" and silently meant "the stack, plus enrolled
/// nodes".
///
/// `None` when there is no local agent, or when this host IS on the rail (a
/// worker running `noo upgrade` for itself must not also try the local lane).
fn local_agent_node(rail: &[String]) -> Option<String> {
    let present = std::path::Path::new(LOCAL_AGENT_BIN).is_file();
    let me = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    local_agent_name(present, &me, rail)
}

/// The decision itself, with the machine's two facts passed in so it can be
/// tested without a node-agent installed or a particular hostname.
fn local_agent_name(agent_present: bool, hostname: &str, rail: &[String]) -> Option<String> {
    if !agent_present {
        return None;
    }
    let me = hostname.trim();
    if me.is_empty() || rail.iter().any(|n| n == me) {
        return None;
    }
    Some(me.to_string())
}

const LOCAL_AGENT_BIN: &str = "/usr/local/bin/noo-node-agent";

/// Upgrade the local agent through `provision --local`, or say why not.
///
/// `provision_local` shells out to sudo. Under an unattended run that could
/// block forever on a password prompt, so it is attempted only when sudo is
/// known not to prompt, or when an operator is present at a TTY to answer.
/// Otherwise this REPORTS the skip and the command — silence is the bug being
/// fixed here, and a skip the operator can see is a fix; a hang is not.
fn upgrade_local_agent(g: &Globals, me: &str, failed: &mut Vec<String>) {
    let sudo_quiet = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo_quiet && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        println!("{}", ui::item(me));
        println!("{}", ui::sub(&ui::status_line(Glyph::Warn, &format!(
            "{me} runs a local agent the pull rail cannot reach, and sudo would prompt here — not upgraded"))));
        ui::guide(&[("noo cluster provision <node> --local",
            "upgrades this controller's own agent; needs sudo, so run it attended")]);
        failed.push(format!("{me} (local)"));
        return;
    }
    // Same child-process isolation as the rail nodes: `provision --local`
    // reports its failures through `fail` too, and an exit here would drop the
    // summary line for every node staged before it.
    match provision_one(g, me, &["--local"]) {
        Ok(0) => {}
        _ => failed.push(format!("{me} (local)")),
    }
}

/// Restage ONE node, in a child process.
///
/// `cluster_provision` reports every runtime failure through `fail`/
/// `fail_guided`, which are `-> !` and call `std::process::exit`. Called
/// in-process from the loop above, the FIRST node that failed took the whole
/// `noo upgrade --all` with it: the remaining nodes were never staged and the
/// `staging failed for: …` summary below was unreachable code.
///
/// That is not hypothetical. host6's applier predates bundle format 2, so it
/// refuses every bundle and cannot self-heal (the bundle carries the CLI that
/// would fix it). Nodes are staged in sorted order — host3, host6, host9 —
/// so host9 could never be reached, and sat three stack releases behind while
/// the operator saw no mention of it (2026-09-05).
///
/// A child process contains the exit. This also holds for the 26th `fail` site
/// and any added later, which a return-type refactor would not: the guarantee
/// is structural rather than by convention. The binary re-execs itself the
/// same way `--stage2` does above.
/// The path to re-exec THIS binary by, or None to run in-process. On Linux
/// `current_exe` is `/proc/self/exe`, and once the file has been replaced
/// underneath a running process it reads `…/noo (deleted)` — a name that
/// exists nowhere. That happened mid-`noo upgrade --nodes` on 2026-09-11:
/// the controller's own self-node bundle installed the CLI over
/// `~/.local/bin/noo`, and every node after it failed with "No such file or
/// directory". The new file at the original path is the right binary to
/// run (it is this release's); when even that is gone, run in-process.
pub(crate) fn reexec_path(current: &std::path::Path) -> Option<std::path::PathBuf> {
    let shown = current.to_string_lossy();
    let path = match shown.strip_suffix(" (deleted)") {
        Some(orig) => std::path::PathBuf::from(orig),
        None => current.to_path_buf(),
    };
    if path.is_file() { Some(path) } else { None }
}

fn provision_one(g: &Globals, node: &str, extra: &[&str]) -> Result<i32, Unhandled> {
    let exe = match std::env::current_exe().map(|p| reexec_path(&p)) {
        Ok(Some(p)) => p,
        // No path to ourselves: fall back to in-process, which is exactly the
        // old behaviour. Losing isolation beats not staging the node at all.
        _ => {
            let mut args = vec![node.to_string()];
            args.extend(extra.iter().map(|s| s.to_string()));
            return crate::commands::provision::cluster_provision(g, &args);
        }
    };
    let mut cmd = std::process::Command::new(&exe);
    // Globals FIRST, then the command: the parser accepts them interleaved,
    // but leading is the documented form. --quiet is deliberately NOT
    // forwarded — the per-node steps are this phase's output.
    if g.json { cmd.arg("--json"); }
    if g.verbose { cmd.arg("--verbose"); }
    if let Some(u) = &g.gateway_override { cmd.arg("--gateway").arg(u); }
    // The token goes in the child's environment ($NOO_TOKEN, which
    // auth::resolve reads), never its argv: a command line is readable by
    // every local user through /proc/<pid>/cmdline.
    if let Some(t) = &g.token { cmd.env("NOO_TOKEN", t); }
    if let Some(t) = g.timeout_secs { cmd.arg("--timeout").arg(t.to_string()); }
    cmd.arg("cluster").arg("provision").arg(node);
    cmd.args(extra);
    match cmd.status() {
        Ok(s) => Ok(s.code().unwrap_or(1)),
        Err(e) => {
            ui::warned(&format!("{node}: could not run `cluster provision`: {e}"));
            Ok(1)
        }
    }
}

/// `docker images` as `<id> <repo>:<tag>` lines. Empty when docker is absent —
/// pruning is best-effort and must never fail a roll.
fn docker_image_lines() -> Vec<String> {
    std::process::Command::new("docker")
        .args(["images", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Image ids any container (running OR stopped) was created from.
///
/// Stopped containers count: `docker rmi` refuses an image a stopped container
/// still references, and a stopped container is often one the operator intends
/// to start again.
fn docker_image_ids_in_use() -> std::collections::HashSet<String> {
    std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Image}}"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|r| {
                    let out = std::process::Command::new("docker")
                        .args(["inspect", "-f", "{{.Id}}", r.trim()])
                        .output()
                        .ok()?;
                    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if id.is_empty() { None } else { Some(short_id(&id)) }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `docker images` prints 12-char ids; `docker inspect` prints the full
/// `sha256:…`. Compare on the short form so the two agree.
fn short_id(id: &str) -> String {
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    hex.chars().take(12).collect()
}

/// Which of our release images are superseded AND unreferenced.
///
/// Pure, so the rule can be tested without a docker daemon — the previous rule
/// could not be, which is part of why it survived digest pinning.
fn superseded_images(
    lines: &[String],
    in_use: &std::collections::HashSet<String>,
    tag: &str,
    prev: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let Some((id, name)) = line.split_once(' ') else { continue };
        if !crate::registry::is_registry_image(name) {
            continue;
        }
        // Referenced by a container: never a candidate, whatever its tag says.
        if in_use.contains(id) {
            continue;
        }
        // Keep the tag just deployed and the previous pin, so an instant
        // rollback stays warm. An UNTAGGED image (`<none>`, which is what a
        // digest-pinned pull leaves behind) is kept only by the in-use test
        // above — it carries no tag to compare, so tag rules cannot save it.
        let t = name.rsplit(':').next().unwrap_or("");
        if t == tag || (!prev.is_empty() && t == prev) {
            continue;
        }
        out.push(id.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The `noo` PATH would run, when that is NOT `exe`.
///
/// `None` when we are first on PATH, or not on it at all — being absent from
/// PATH is a different problem and the installer already reports it.
fn shadowing_noo(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH").ok()?;
    let first = first_noo_on_path(&path, &|p| p.is_file())?;
    if first == exe {
        return None;
    }
    // Compare RESOLVED paths too: /usr/local/bin/noo reached through a
    // symlinked directory is the same binary, not a shadow, and warning about
    // it would be noise the operator cannot act on. Only a resolution that
    // actually succeeded proves sameness — two failures are not a match.
    match (std::fs::canonicalize(&first), std::fs::canonicalize(exe)) {
        (Ok(a), Ok(b)) if a == b => None,
        _ => Some(first),
    }
}

/// First `noo` on a PATH string, in order. Existence is injected so the
/// ordering rule can be tested without touching the filesystem.
fn first_noo_on_path(
    path_var: &str,
    exists: &dyn Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    path_var
        .split(':')
        // An empty PATH entry means "the current directory" to the shell. We
        // deliberately do NOT honour that: resolving a tool from cwd is a
        // footgun, and reporting `./noo` as the winner would be misleading.
        .filter(|d| !d.is_empty())
        .map(|d| std::path::Path::new(d).join("noo"))
        .find(|c| exists(c))
}

/// Musl target triple for this host — matches what install.sh selects and what
/// noo-cli-release.yml publishes. `None` = unsupported platform.
/// HEAD-ish probe: does the controller serve this asset's sha256 sidecar?
fn controller_has_asset(mirror: &str, asset: &str) -> bool {
    let has = |n: &str| mirror_get_bytes(&format!("{mirror}/{n}")).map(|b| !b.is_empty()).unwrap_or(false);
    // A mirror without the signed manifest is an old controller: fall
    // through to GitHub, where the release IS signed.
    has(&format!("{asset}.sha256")) && has(&format!("{}.sig", crate::release_sig::MANIFEST))
}

/// `sha256sums.txt` + `.sig` for `version` from the same source the asset
/// comes from. Ok(None) when the release publishes no signature (pre-0.3.70).
///
/// Only a genuine not-found means "unsigned release": a
/// network or auth failure used to surface as a 404 here, which turned a
/// GitHub blip into "this release publishes no signature".
fn fetch_signed_manifest(g: &Globals, version: &str, base_url: Option<&str>) -> Result<Option<(String, String)>, FetchError> {
    let m = crate::release_sig::MANIFEST;
    let sig_name = format!("{m}.sig");
    let manifest = match fetch_release_file(g, version, m, base_url) {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => return Err(e),
    };
    let sig = match fetch_release_file(g, version, &sig_name, base_url) {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some((manifest, sig)))
}

/// One small release file (manifest, signature) via the same three lanes as
/// `download_asset`: mirror, gh, direct.
pub(crate) fn fetch_release_file(g: &Globals, version: &str, name: &str, base_url: Option<&str>) -> Result<Vec<u8>, FetchError> {
    if let Some(base) = base_url {
        return mirror_get_bytes(&format!("{}/{name}", base.trim_end_matches('/')));
    }
    fetch_tag_file(g, &format!("{TAG_PREFIX}{version}"), name)
}

/// One asset of the GitHub release on `tag`: gh, then the direct GET only
/// where it can help ([`release_fetch::gh_then_direct`]). Transient failures
/// are retried with backoff on each lane; the error names the real cause
/// The bytes are unverified here — every caller checks
/// them against a signed manifest or signed lock, as before.
pub(crate) fn fetch_tag_file(g: &Globals, tag: &str, name: &str) -> Result<Vec<u8>, FetchError> {
    let repo = repo();
    let gh = which("gh");
    let mut sleep = release_fetch::real_sleep;
    release_fetch::gh_then_direct(
        gh.as_deref(),
        &mut |gh| {
            let r = release_fetch::gh_download_with_retry(gh, &repo, tag, name, &release_fetch::DEFAULT_RETRY, &mut sleep);
            if let (Err(e), true) = (&r, g.verbose) {
                eprintln!("{}", e.summary());
            }
            r
        },
        &mut || http_get_bytes(&format!("{}/{tag}/{name}", dl_base()), gh_token().as_deref()),
    )
}

/// The (os, arch) platforms to stage assets for: this controller's own
/// platform, the two common linux platforms (so a zero-node fleet still
/// stages what a typical first node needs), and every platform already on
/// record in the fleet's bootstrap-token facts.
///
/// Pure, so the derivation can be tested without a gateway or a fleet.
/// `own_os`/`own_arch` take `std::env::consts::OS`/`ARCH` at the call site —
/// those already speak the same "linux"/"macos", "x86_64"/"aarch64" strings
/// `cli_asset_for`/`gateway_asset_for`/`hostd_asset_for` expect.
fn asset_platforms(toks: &[serde_json::Value], own_os: &str, own_arch: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![
        (own_os.to_string(), own_arch.to_string()),
        ("linux".to_string(), "x86_64".to_string()),
        ("linux".to_string(), "aarch64".to_string()),
    ];
    v.extend(toks.iter().filter_map(|t| t.get("facts")).map(|f| {
        let os = f.get("os").and_then(|v| v.as_str()).unwrap_or("linux").to_string();
        let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64").to_string();
        (os, arch)
    }));
    v.sort();
    v.dedup();
    v
}

/// For every platform in the fleet (plus the always-staged set above): fetch
/// the CLI asset of THIS version into the controller's cache (if missing)
/// and upload it to the gateway.
fn upload_cli_assets(g: &Globals, toks: &[serde_json::Value]) {
    let root = crate::envfile::repo_root();
    let cache = crate::commands::provision::cli_asset_cache_dir(&root);
    let _ = std::fs::create_dir_all(&cache);
    let version = env!("CARGO_PKG_VERSION").to_string();
    let platforms = asset_platforms(toks, std::env::consts::OS, std::env::consts::ARCH);
    let mut assets: Vec<String> = platforms
        .iter()
        .filter_map(|(os, arch)| crate::commands::provision::cli_asset_for(os, arch))
        .collect();
    assets.sort();
    assets.dedup();
    // The gateway binary per platform rides the same release:
    // it is what a node runs as its harness, and it goes to the
    // controller's cache so the next bundle can carry it as
    // `harness-binary`. Not mirrored to the gateway — no fresh node needs
    // it before it is a node. Missing on an old release is a note, not a
    // failure: bundles simply carry no harness until a release has it.
    let gateway_assets: Vec<String> = {
        let mut v: Vec<String> = platforms
            .iter()
            .filter_map(|(os, arch)| crate::commands::provision::gateway_asset_for(os, arch))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    // hostd rides the same cache for the same reason: the harness lifecycle
    // is a hostd op, so a node without the helper cannot start a harness.
    // Linux only — darwin's hostsvc drives launchctl as the enrolling user
    // and needs no privileged helper.
    let hostd_assets: Vec<String> = {
        let mut v: Vec<String> = platforms
            .iter()
            .filter_map(|(os, arch)| crate::commands::provision::hostd_asset_for(os, arch))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    for name in gateway_assets.iter().chain(hostd_assets.iter()) {
        let path = cache.join(name);
        if std::fs::read(&path).ok().filter(|b| !b.is_empty()).is_some() {
            continue;
        }
        match fetch_release_file(g, &version, name, None) {
            Ok(b) => {
                let _ = std::fs::write(&path, &b);
                if !g.json { println!("{}", ui::note(&format!("{name}: cached for the rail ({} bytes)", b.len()))); }
            }
            // "not in release" only when it is not; any other
            // failure is said as itself, so a GitHub blip is not mistaken
            // for a release without the asset.
            Err(e) if e.is_not_found() => {
                if !g.json { println!("{}", ui::note(&format!("{name}: not in release {version} ({}) — bundles carry no harness or helper for that platform", e.summary()))); }
            }
            Err(e) => ui::warned(&format!("{name}: not fetched ({e}) — bundles carry no harness or helper for that platform until a re-run fetches it")),
        }
    }
    // The signed manifest rides along: without it a node treats this mirror
    // as an old controller and goes to GitHub instead.
    let m = crate::release_sig::MANIFEST;
    for name in [m.to_string(), format!("{m}.sig")] {
        let path = cache.join(&name);
        let bytes = match std::fs::read(&path).ok().filter(|b| !b.is_empty()) {
            Some(b) => b,
            None => match fetch_release_file(g, &version, &name, None) {
                Ok(b) => { let _ = std::fs::write(&path, &b); b }
                Err(e) => { ui::warned(&format!("{name}: not fetched ({e}) — nodes will verify against GitHub instead")); continue; }
            },
        };
        let sha = { use sha2::{Digest, Sha256}; format!("{:x}", Sha256::digest(&bytes)) };
        if let Err(e) = crate::commands::provision::put_bytes(
            g, &format!("/api/cluster/cli-asset/{name}?sha256={sha}&version={version}"), &bytes) {
            ui::warned(&format!("{name}: upload failed ({e})"));
        }
    }
    // The installer rides too, so a fresh node's Step 1 is served by the
    // controller (no GitHub, no scp): curl …/bootstrap/cli/install.sh.
    {
        let bytes = INSTALLER.as_bytes();
        let sha = { use sha2::{Digest, Sha256}; format!("{:x}", Sha256::digest(bytes)) };
        if let Err(e) = crate::commands::provision::put_bytes(
            g, &format!("/api/cluster/cli-asset/install.sh?sha256={sha}&version={version}"), bytes) {
            ui::warned(&format!("install.sh: upload failed ({e}) — new nodes fall back to the GitHub installer line"));
        }
    }
    let mut uploaded: Vec<String> = Vec::new();
    for asset in assets {
        let path = cache.join(&asset);
        let have = std::fs::read(&path).ok().filter(|b| !b.is_empty());
        let bytes = match have {
            Some(b) => b,
            None => match download_asset(g, &version, &asset, None) {
                Ok((bin, sha)) => {
                    let _ = std::fs::write(&path, &bin);
                    let _ = std::fs::write(cache.join(format!("{asset}.sha256")), &sha);
                    bin
                }
                Err(e) => {
                    ui::warned(&format!("{asset}: not fetched ({e}) — nodes on that platform keep their CLI"));
                    continue;
                }
            },
        };
        let sha = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&bytes))
        };
        match crate::commands::provision::put_bytes(
            g,
            &format!("/api/cluster/cli-asset/{asset}?sha256={sha}&version={version}"),
            &bytes,
        ) {
            Ok(_) => uploaded.push(asset.clone()),
            Err(e) => ui::warned(&format!("{asset}: upload failed ({e}) — bundles still carry it from the cache")),
        }
    }
    // One summary line, the names as its single note (guide §5: summarise
    // per-item work; details hang under the closing line).
    if !uploaded.is_empty() {
        ui::done(&format!("{} CLI asset(s) uploaded to the controller ({version})", uploaded.len()));
        println!("{}", ui::note(&uploaded.join(", ")));
    }
}

fn target_triple() -> Option<String> {
    target_triple_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Release asset triple for an (os, arch), or `None` when the release
/// publishes no binary for it.
///
/// Darwin was refused outright until 2026-09-05, which was stale rather than
/// deliberate: `noo-aarch64-apple-darwin` IS published, `install.sh:313` maps
/// `Darwin/arm64` to it, `cli_asset_for` hands it to Mac nodes, and
/// `upload_cli_assets` puts it on the controller mirror. Every lane in the
/// pipeline carried a darwin build except the one a Mac would run for itself —
/// so a Mac node could be given a new CLI but could not go and get one.
///
/// Everything after the swap is darwin-safe: the deploy slice is gated on
/// `.noo-standalone` (a Mac node has none), completion install is best-effort,
/// and the stage-2 re-exec is `cfg(unix)`. A root-owned `/usr/local/bin/noo`
/// still fails honestly in `swap_binary`, telling the operator to use sudo.
///
/// Intel Macs stay `None` on purpose: no `x86_64-apple-darwin` asset is
/// published, and inventing a triple would trade a clear refusal for a 404.
fn target_triple_for(os: &str, arch: &str) -> Option<String> {
    match (os, arch) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl".into()),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl".into()),
        ("macos", "aarch64") => Some("aarch64-apple-darwin".into()),
        _ => None,
    }
}

/// A plain external HTTPS agent (verification ON via platform-verifier — the
/// gateway agent disables it for the self-signed controller; GitHub is public
/// PKI and must be verified).
fn ext_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into()
}

pub(crate) fn gh_token() -> Option<String> {
    for k in ["GH_TOKEN", "GITHUB_TOKEN", "PAI_REPOS_PAT"] {
        if let Ok(v) = std::env::var(k) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// What the CLI phase of `noo upgrade` does with the running binary
/// Decided on semver ORDER, not string equality: a build
/// newer than the latest release must never be replaced by the older one.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CliAction {
    /// Same version: nothing to do.
    Noop,
    /// Target is newer (or, unpinned/unparsable, simply different): install it.
    Upgrade,
    /// Running build is newer than the latest release and no pin was given.
    KeepNewer,
    /// An explicit `--version` older than the running build: install it.
    DowngradePinned,
    /// A version did not parse as semver and the two differ: treated as
    /// different (today's behaviour), with a warning.
    Unparsable,
}

impl CliAction {
    fn as_str(self) -> &'static str {
        match self {
            CliAction::Noop => "noop",
            // An unparsable difference installs the target, like an upgrade.
            CliAction::Upgrade | CliAction::Unparsable => "upgrade",
            CliAction::KeepNewer => "keep_newer",
            CliAction::DowngradePinned => "downgrade_pinned",
        }
    }
}

/// `MAJOR.MINOR.PATCH[-pre][+build]` (optional leading `v`) -> comparable parts.
fn parse_cli_semver(v: &str) -> Option<((u64, u64, u64), Vec<String>)> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() != 3 {
        return None;
    }
    let n = |i: usize| nums[i].parse::<u64>().ok();
    let pre: Vec<String> = match pre {
        Some("") => return None,
        Some(p) => p.split('.').map(str::to_string).collect(),
        None => Vec::new(),
    };
    if pre.iter().any(|x| x.is_empty()) {
        return None;
    }
    Some(((n(0)?, n(1)?, n(2)?), pre))
}

/// Semver precedence (a release outranks its own pre-releases).
pub(crate) fn cmp_cli_semver(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    let ((ac, ap), (bc, bp)) = (parse_cli_semver(a)?, parse_cli_semver(b)?);
    if ac != bc {
        return Some(ac.cmp(&bc));
    }
    Some(match (ap.is_empty(), bp.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in ap.iter().zip(bp.iter()) {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return Some(o);
                }
            }
            ap.len().cmp(&bp.len())
        }
    })
}

/// The decision, pure: running version, resolved target, was it pinned?
fn decide_cli_action(current: &str, target: &str, pinned: bool) -> CliAction {
    use std::cmp::Ordering;
    match cmp_cli_semver(current, target) {
        None if current == target => CliAction::Noop,
        None => CliAction::Unparsable,
        Some(Ordering::Equal) => CliAction::Noop,
        Some(Ordering::Less) => CliAction::Upgrade,
        Some(Ordering::Greater) if pinned => CliAction::DowngradePinned,
        Some(Ordering::Greater) => CliAction::KeepNewer,
    }
}

/// The newest FINAL CLI release among `(tag, is_prerelease)` pairs, as a bare
/// version. A release candidate (`noo-cli-vA.B.C-rc.N`, published from
/// staging as a GitHub prerelease so a rehearsal can fetch its node binaries)
/// is never "latest": it is skipped when GitHub marks it a prerelease AND when
/// its version carries any pre-release suffix, so a mislabelled release
/// cannot slip through either way. The highest version wins, not the first
/// listed — list order is creation order, and an rc can be created after the
/// final it precedes.
fn pick_latest_cli(releases: &[(String, bool)]) -> Option<String> {
    releases
        .iter()
        .filter(|(_, pre)| !pre)
        .filter_map(|(tag, _)| tag.trim().strip_prefix(TAG_PREFIX))
        .filter(|v| !v.contains('-') && parse_cli_semver(v).is_some())
        .max_by(|a, b| cmp_cli_semver(a, b).unwrap_or(std::cmp::Ordering::Equal))
        .map(str::to_string)
}

/// Latest final `noo-cli-v*` release → bare version (e.g. "0.2.14"). Prefers
/// `gh` (auth), falls back to the token'd releases API. Never a prerelease
/// ([`pick_latest_cli`]).
pub(crate) fn resolve_latest(g: &Globals) -> Result<String, String> {
    let mut gh_err: Option<FetchError> = None;
    if which("gh").is_some() {
        let out = std::process::Command::new("gh")
            .args(["release", "list", "--repo", &repo(), "--limit", "50",
                   "--json", "tagName,isPrerelease", "-q",
                   ".[] | select(.tagName | startswith(\"noo-cli-v\")) | \"\\(.tagName) \\(.isPrerelease)\""])
            .output()
            .map_err(|e| format!("gh: {e}"))?;
        if out.status.success() {
            let rels: Vec<(String, bool)> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.trim().split_once(' ').map(|(t, p)| (t.to_string(), p == "true")))
                .collect();
            if let Some(v) = pick_latest_cli(&rels) {
                if g.verbose { eprintln!("latest release: {TAG_PREFIX}{v}"); }
                return Ok(v);
            }
        } else {
            gh_err = Some(gh_list_error(&out));
        }
        // fall through to the API on gh failure
    }
    let body = releases_api_body(&releases_api(), gh_err)?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("parse: {e}"))?;
    let rels: Vec<(String, bool)> = v
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|rel| {
                    let tag = rel.get("tag_name")?.as_str()?.to_string();
                    let pre = rel.get("prerelease").and_then(|p| p.as_bool()).unwrap_or(false);
                    Some((tag, pre))
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(v) = pick_latest_cli(&rels) {
        if g.verbose { eprintln!("latest release: {TAG_PREFIX}{v}"); }
        return Ok(v);
    }
    Err("no final noo-cli-v* release found".into())
}

/// gh's `release list` failure, classified — kept so that if
/// the API lane fails too, gh's cause is the one reported.
fn gh_list_error(out: &std::process::Output) -> FetchError {
    let err = String::from_utf8_lossy(&out.stderr);
    FetchError::new(
        release_fetch::classify_gh_stderr(&err),
        format!("gh release list --repo {}: {}", repo(), release_fetch::gh_reason(&err)),
    )
}

/// The releases API listing, classified and retried. When gh failed
/// first, gh's cause leads and the API's follows: an unauthenticated API
/// 404 is what a private repo answers to anyone.
fn releases_api_body(url: &str, gh_err: Option<FetchError>) -> Result<String, String> {
    let tok = gh_token();
    match release_fetch::get_with_retry(&ext_agent(), url, tok.as_deref(), &release_fetch::DEFAULT_RETRY, &mut release_fetch::real_sleep) {
        Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        Err(api) => Err(match gh_err {
            Some(ge) => ge.with_also(format!("the releases API also failed ({})", api.summary())).to_string(),
            None => format!("{} ({})", api, repo()),
        }),
    }
}

/// `stack-vA.B.C` finals among `(tag, is_prerelease)` pairs, newest first
/// pick, as the bare `A.B.C`. Same rules as [`pick_latest_cli`]: a prerelease
/// or a suffixed version is never "latest".
fn pick_latest_stack(releases: &[(String, bool)]) -> Option<String> {
    releases
        .iter()
        .filter(|(_, pre)| !pre)
        .filter_map(|(tag, _)| tag.trim().strip_prefix("stack-v"))
        .filter(|v| !v.contains('-') && parse_cli_semver(v).is_some())
        .max_by(|a, b| cmp_cli_semver(a, b).unwrap_or(std::cmp::Ordering::Equal))
        .map(str::to_string)
}

/// `(tag, is_prerelease)` for the releases of [`repo`] whose tag starts with
/// `prefix`: gh first, then the token'd API. Kept apart from
/// [`resolve_latest`] on purpose, which every upgrade runs.
fn release_pairs(g: &Globals, prefix: &str) -> Result<Vec<(String, bool)>, String> {
    let mut gh_err: Option<FetchError> = None;
    if which("gh").is_some() {
        let jq = format!(".[] | select(.tagName | startswith(\"{prefix}\")) | \"\\(.tagName) \\(.isPrerelease)\"");
        let out = std::process::Command::new("gh")
            .args(["release", "list", "--repo", &repo(), "--limit", "100", "--json", "tagName,isPrerelease", "-q", &jq])
            .output()
            .map_err(|e| format!("gh: {e}"))?;
        if out.status.success() {
            let rels: Vec<(String, bool)> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.trim().split_once(' ').map(|(t, p)| (t.to_string(), p == "true")))
                .collect();
            if !rels.is_empty() {
                return Ok(rels);
            }
        } else {
            gh_err = Some(gh_list_error(&out));
        }
    }
    let body = releases_api_body(&format!("{}?per_page=100", releases_api()), gh_err)?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("parse: {e}"))?;
    let _ = g;
    Ok(v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|rel| {
                    let tag = rel.get("tag_name")?.as_str()?.to_string();
                    if !tag.starts_with(prefix) { return None; }
                    Some((tag, rel.get("prerelease").and_then(|p| p.as_bool()).unwrap_or(false)))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Rule 2: before an install is pointed at a channel, that
/// channel must be able to serve a roll — not just have a CLI release. Reads
/// the channel in force (`NOO_CLI_REPO`, `NOO_IMAGE_PREFIX` in the process
/// env, as the other readers in this file do) and checks that its newest final
/// stack release (1) publishes a digest lock whose signature verifies against
/// the baked release key, (2) names a gateway image, and (3) has that image
/// published at the image prefix. Returns the stack tag. Read-only.
pub(crate) fn probe_channel_stack(g: &Globals) -> Result<String, String> {
    let pairs = release_pairs(g, "stack-v")?;
    let ver = pick_latest_stack(&pairs).ok_or_else(|| format!("{} has no final stack-v* release", repo()))?;
    let tag = format!("v{ver}");
    let rel = format!("stack-{tag}");
    let name = format!("{rel}.lock");
    let lock = fetch_tag_file(g, &rel, &name).map_err(|e| format!("{name}: {e}"))?;
    let sig = fetch_tag_file(g, &rel, &format!("{name}.sig")).map_err(|e| format!("{name}.sig: {e}"))?;
    crate::release_sig::verify(&lock, &String::from_utf8_lossy(&sig))
        .map_err(|e| format!("{name}: the signature does not verify ({e})"))?;
    let rows = super::image_stage::parse_lock(&String::from_utf8_lossy(&lock));
    if !rows.iter().any(|r| r.name == "gateway") {
        return Err(format!("{name} is signed but names no gateway image"));
    }
    let basic = docker_registry_basic("ghcr.io");
    match ghcr_image_tags(&ext_agent(), basic.as_deref(), "gateway") {
        Some(tags) if tags.iter().any(|t| t == &tag || t == &rel) => Ok(tag),
        Some(_) => Err(format!("{rel} is released but its gateway image is not published at {}", ghcr_repo_path())),
        None => Err(format!(
            "the registry did not list the gateway image at {} (not published yet, or private: `docker login ghcr.io`)",
            ghcr_repo_path())),
    }
}

/// Returns (binary bytes, sha256 sidecar line).
fn download_asset(
    g: &Globals, version: &str, asset: &str, base_url: Option<&str>,
) -> Result<(Vec<u8>, String), FetchError> {
    // 1. Mirror: <base>/<asset> and <base>/<asset>.sha256, no auth.
    if let Some(base) = base_url {
        let base = base.trim_end_matches('/');
        let bin = mirror_get_bytes(&format!("{base}/{asset}"))?;
        let sha = String::from_utf8_lossy(
            &mirror_get_bytes(&format!("{base}/{asset}.sha256"))?).to_string();
        return Ok((bin, sha));
    }
    // 2./3. gh, then the direct token'd fetch where it can help — one lane
    // per file, each classified and retried.
    let tag = format!("{TAG_PREFIX}{version}");
    let bin = fetch_tag_file(g, &tag, asset)?;
    let sha = String::from_utf8_lossy(&fetch_tag_file(g, &tag, &format!("{asset}.sha256"))?).to_string();
    Ok((bin, sha))
}

/// A direct HTTPS GET of a release file (TLS verified, token in a header
/// only), classified and retried on transient failures.
pub(crate) fn http_get_bytes(url: &str, token: Option<&str>) -> Result<Vec<u8>, FetchError> {
    release_fetch::get_with_retry(&ext_agent(), url, token, &release_fetch::DEFAULT_RETRY, &mut release_fetch::real_sleep)
}

/// Write `bytes` to a temp file beside `exe`, mark it 0755, and rename over
/// `exe`. Replacing the file of a running process is fine on Linux — the
/// inode stays open for this process; the new name resolves on next exec.
fn swap_binary(exe: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let dir = exe.parent().ok_or_else(|| "binary has no parent dir".to_string())?;
    let tmp = dir.join(format!(".noo-upgrade.{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write to {} ({e})", dir.display())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chmod failed: {e}"));
        }
    }
    std::fs::rename(&tmp, exe).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {} ({e})", exe.display())
    })?;
    Ok(())
}

/// First `name` on PATH, if any.
fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

/// Would rolling from `prev` (the .env pin) to `tag` move the controller
/// BACKWARDS? Only a decision when both are real stack versions: an unpinned
/// or malformed pin is not "ahead" of anything.
/// The `x-noo-secrets-floor` stack tag declared by the compose file this
/// binary embeds (`stack-vX.Y.Z`), or None for a crate-only build (no
/// embedded slice — the launcher still enforces the floor from the file on
/// disk).
pub(crate) fn embedded_secrets_floor() -> Option<String> {
    crate::onboard::standalone::STANDALONE_ASSETS
        .iter()
        .find(|(rel, _, _)| *rel == "docker-compose.cluster.yml")
        .and_then(|(_, bytes, _)| secrets_floor_in(&String::from_utf8_lossy(bytes)))
}

/// `x-noo-secrets-floor: <tag>` from a compose file's text.
pub(crate) fn secrets_floor_in(compose: &str) -> Option<String> {
    compose.lines().find_map(|l| {
        l.strip_prefix("x-noo-secrets-floor:")
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Does `tag` sort at or above `floor`? A tag that is not `vX.Y.Z` cannot be
/// shown to meet it and does not — the same rule as the launcher's
/// `require_secrets_floor`.
pub(crate) fn tag_meets_floor(tag: &str, floor: &str) -> bool {
    let t = rc_core(&norm_stack_tag(tag));
    is_stack_version(&t) && stack_semver(&t) >= stack_semver(&norm_stack_tag(floor))
}

/// A release candidate `vX.Y.Z-rc.N` (promotion model: cut on staging and
/// rehearsed before `vX.Y.Z` is cut on main) is built from the code `vX.Y.Z`
/// ships, so the floor and downgrade checks judge it as `vX.Y.Z`. Default
/// discovery never sees one: `is_stack_version` stays strict, so only an
/// explicit `--tag` reaches a candidate. Any other suffix is left alone and
/// still fails `is_stack_version`.
fn rc_core(t: &str) -> String {
    match t.split_once("-rc.") {
        Some((core, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => core.to_string(),
        _ => t.to_string(),
    }
}

/// The refusal every compose-recreating verb gives when THIS install would
/// pair its compose file with images below `x-noo-secrets-floor` — the same
/// rule as the launcher's `require_secrets_floor`, which only applies it on
/// a dist install (dev builds the images from this very tree). `None` = go.
/// `floor` None = the compose file declares none.
pub(crate) fn secrets_floor_refusal(install_mode: &str, tag: &str, floor: Option<&str>) -> Option<String> {
    let floor = floor?;
    if install_mode.trim() != "dist" || tag_meets_floor(tag, floor) {
        return None;
    }
    Some(format!(
        "the stack is pinned to {} and this install's compose file needs images at or above {floor} \
         (it delivers the gateway's and worker's secrets as files) — the recreate would be refused",
        if tag.is_empty() { "<no tag>" } else { tag }
    ))
}

/// [`secrets_floor_refusal`] for the install at the repo root: its
/// NOO_INSTALL_MODE and pinned NOO_IMAGE_TAG (process env first, then .env —
/// the launcher's order), against the floor the compose file ON DISK
/// declares (what `noomesh-restart.sh` will run), else the embedded one.
pub(crate) fn install_secrets_floor_refusal() -> Option<(String, String)> {
    let root = crate::envfile::repo_root();
    let dotenv = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    let from = |k: &str| {
        std::env::var(k).ok().filter(|v| !v.trim().is_empty()).or_else(|| {
            dotenv.lines().rev().find_map(|l| l.trim().strip_prefix(&format!("{k}=")).map(|v| v.trim().trim_matches('"').to_string()))
        }).unwrap_or_default()
    };
    let floor = std::fs::read_to_string(root.join("docker-compose.cluster.yml"))
        .ok()
        .and_then(|c| secrets_floor_in(&c))
        .or_else(embedded_secrets_floor);
    let floor = floor?;
    secrets_floor_refusal(&from("NOO_INSTALL_MODE"), &from("NOO_IMAGE_TAG"), Some(&floor)).map(|why| (why, floor))
}

/// The remedy that goes with a [`secrets_floor_refusal`] — one text for
/// `upgrade --stack`, `secrets rotate` and the launcher.
pub(crate) fn secrets_floor_remedy(floor: &str) -> String {
    format!(
        "noo upgrade --stack (no --tag) rolls to the newest stack; or pass --tag {} or newer. \
         To run an older stack, use the noo CLI that shipped it.",
        floor.trim_start_matches("stack-")
    )
}

fn is_downgrade(prev: &str, tag: &str) -> bool {
    let (p, t) = (rc_core(&norm_stack_tag(prev)), rc_core(&norm_stack_tag(tag)));
    is_stack_version(&p) && is_stack_version(&t) && stack_semver(&t) < stack_semver(&p)
}

/// The newest tag that is PUBLISHED as a release but not yet on every stack
/// image at ghcr.io — the state a controller sees in the minutes after a cut,
/// and the one that made `--stack` pick an older tag without saying why.
/// `complete` is the newest tag present on every image (None = unknown).
fn newer_published_but_incomplete(published: &[String], complete: Option<&str>) -> Option<String> {
    let newest_pub = published.iter().filter(|t| is_stack_version(t)).max_by_key(|t| stack_semver(t))?;
    match complete {
        Some(c) if stack_semver(newest_pub) > stack_semver(c) => Some(newest_pub.clone()),
        None => Some(newest_pub.clone()),
        _ => None,
    }
}

/// Every `stack-v*` release tag GitHub knows about — published, whether or
/// not its images have all landed. Empty when `gh` is unavailable; the caller
/// then simply cannot name an incomplete tag, which is the prior behaviour.
fn published_stack_tags() -> Vec<String> {
    Command::new("gh")
        .args(["release", "list", "--repo", &repo(), "--limit", "80",
               "--json", "tagName", "--jq", ".[].tagName"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines()
            .filter_map(|l| l.trim().strip_prefix("stack-").map(str::to_string))
            .filter(|t| is_stack_version(t))
            .collect())
        .unwrap_or_default()
}

/// Whether the newest published FINAL stack tag should replace this binary's
/// baked pairing. A candidate CLI (`noo-cli-vA.B.C-rc.N`) is paired with a
/// candidate stack (`vX.Y.Z-rc.N`): compare its RELEASE core, or
/// `stack_semver` reads `89-rc` as 0 and every final above `vX.Y.0` would
/// win — an rc rehearsal would silently roll to the previous release.
fn newer_than_pairing(newest: &str, paired: &str) -> bool {
    stack_semver(newest) > stack_semver(&rc_core(paired))
}

fn stack_semver(t: &str) -> (u64, u64, u64) {
    let v = t.trim().trim_start_matches("stack-").trim_start_matches('v');
    let mut it = v.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}

fn is_stack_version(t: &str) -> bool {
    let v = t.trim_start_matches('v');
    v.split('.').count() == 3 && v.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// The newest published stack tag (`vX.Y.Z`), or None when nothing can
/// be listed. Sources in order: the GHCR tag list of the gateway image
/// (the same registry the pull uses, authenticated with the docker login
/// already on this host, so it works on a customer box with no gh), then
/// `gh release list` on the install repo. Silent on failure — a hint at
/// the call site, never a gate.
fn newest_published_stack_tag() -> Option<String> {
    let mut tags: Vec<String> = ghcr_complete_stack_tags().unwrap_or_default();
    if tags.is_empty() {
        if let Ok(out) = Command::new("gh")
            .args(["release", "list", "--repo", &repo(), "--limit", "80",
                   "--json", "tagName", "--jq", ".[].tagName"])
            .output()
        {
            if out.status.success() {
                tags = String::from_utf8_lossy(&out.stdout).lines()
                    .filter_map(|l| l.trim().strip_prefix("stack-").map(str::to_string))
                    .collect();
            }
        }
    }
    tags.retain(|t| is_stack_version(t));
    tags.into_iter().max_by_key(|t| stack_semver(t))
}

/// Every image a standalone start pulls. A stack tag is "published" only
/// when ALL of them carry it: the gateway image is also pushed by the
/// per-commit Gateway workflow and lands minutes before the rest, so
/// gateway alone reported v0.2.11 while the images run was still queued
/// and `noo upgrade --stack` walked into "not found" for four services
/// (host8, 2026-09-03). The intersection is the honest signal.
///
/// CORE images only. The stack release is core-only: the licensed add-ons
/// (trellion-intel, evolve) are released from their own repositories with
/// their own lock, so a stack tag never carries them. Listing one here made
/// every core-only tag look unpublished and `--stack` could never roll to it.
const STACK_IMAGES: &[&str] = &[
    "gateway", "worker", "trellion", "node-agent",
    "sandbox", "postgres-pgvector",
];

/// Tags present on every image in `STACK_IMAGES` (registry token flow; the
/// Basic credential comes from ~/.docker/config.json — inline `auth` or a
/// credential helper; anonymous is attempted too for the public-image day).
fn ghcr_complete_stack_tags() -> Option<Vec<String>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .build()
        .into();
    let basic = docker_registry_basic("ghcr.io");
    complete_stack_tags(|image| ghcr_image_tags(&agent, basic.as_deref(), image))
}

/// The tags every `STACK_IMAGES` image carries, given a per-image tag lister.
/// None when any image cannot be listed (unknown, not "no tags").
fn complete_stack_tags(mut list: impl FnMut(&str) -> Option<Vec<String>>) -> Option<Vec<String>> {
    let mut common: Option<std::collections::BTreeSet<String>> = None;
    for image in STACK_IMAGES {
        let set: std::collections::BTreeSet<String> = list(image)?.into_iter().collect();
        common = Some(match common {
            None => set,
            Some(c) => c.intersection(&set).cloned().collect(),
        });
    }
    Some(common.unwrap_or_default().into_iter().collect())
}

/// The GHCR repository PATH (owner + any nesting) the stack images actually
/// live under, without the `ghcr.io/` host. This must be derived from the same
/// prefix the pull uses, never written out again: a probe that asks a different
/// path than the pull does can answer 200 from stale packages and silently pin
/// the CLI's own baked pairing instead of the newest stack (host8, v0.2.72).
fn ghcr_repo_path() -> String {
    repo_path_from_prefix(&std::env::var("NOO_IMAGE_PREFIX").unwrap_or_default())
}

/// `ghcr.io/noomesh` → `noomesh`; empty → the
/// same default `scripts/lib-dist.sh` and `cluster_provision_subprocess` use.
fn repo_path_from_prefix(prefix: &str) -> String {
    let prefix = prefix.trim().trim_end_matches('/');
    if prefix.is_empty() {
        return crate::registry::image_repo_path().to_string();
    }
    prefix.strip_prefix("ghcr.io/").unwrap_or(prefix).to_string()
}


fn ghcr_image_tags(agent: &ureq::Agent, basic: Option<&str>, image: &str) -> Option<Vec<String>> {
    let repo = ghcr_repo_path();
    let mut req = agent.get(&format!("https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}/{image}:pull"));
    if let Some(b) = basic { req = req.header("Authorization", &format!("Basic {b}")); }
    let tok: serde_json::Value = req.call().ok()?.body_mut().read_json().ok()?;
    let token = tok.get("token").and_then(|t| t.as_str())?.to_string();
    let v: serde_json::Value = agent
        .get(&format!("https://ghcr.io/v2/{repo}/{image}/tags/list?n=1000"))
        .header("Authorization", &format!("Bearer {token}"))
        .call().ok()?.body_mut().read_json().ok()?;
    Some(v.get("tags")?.as_array()?.iter()
        .filter_map(|t| t.as_str().map(str::to_string)).collect())
}

/// The base64 `user:secret` docker would send to `registry`, from
/// ~/.docker/config.json — inline `auths[registry].auth`, else the
/// credential helper named by `credHelpers[registry]` / `credsStore`.
pub(crate) fn docker_registry_basic(registry: &str) -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let cfg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(&home).join(".docker/config.json")).ok()?).ok()?;
    if let Some(a) = cfg.pointer(&format!("/auths/{registry}/auth")).and_then(|a| a.as_str()) {
        if !a.is_empty() { return Some(a.to_string()); }
    }
    let helper = cfg.pointer(&format!("/credHelpers/{registry}")).and_then(|h| h.as_str())
        .or_else(|| cfg.get("credsStore").and_then(|h| h.as_str()))?;
    let mut child = Command::new(format!("docker-credential-{helper}"))
        .arg("get")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn().ok()?;
    crate::child_stdin::write_child_stdin(&mut child.stdin.take()?, registry.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() { return None; }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let (u, p) = (v.get("Username")?.as_str()?, v.get("Secret")?.as_str()?);
    use base64::Engine as _;
    Some(base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))
}



/// Fetch + verify `stack-<tag>.lock` for the stack release: the verified
/// text, or `None` when the release publishes no lock (said out loud; the
/// pull is then by tag). A lock that fails verification is fatal: that is
/// exactly the tamper this exists to catch.
fn fetch_stack_lock(g: &Globals, tag: &str) -> Option<String> {
    match try_stack_lock(g, tag) {
        Ok(Some(text)) => Some(text),
        Ok(None) => {
            if !g.json { ui::warned(&format!("stack-{tag} publishes no digest lock — images pulled by tag (locks start at v0.2.11)")); }
            None
        }
        Err((code, msg, fix)) => fail(g.json, ExitCode::Generic, code, &msg, fix),
    }
}

/// [`fetch_stack_lock`] without the exit: `Err((code, message, remedy))`.
type StackLockErr = (&'static str, String, Option<&'static str>);
fn try_stack_lock(g: &Globals, tag: &str) -> Result<Option<String>, StackLockErr> {
    let rel = format!("stack-{tag}");
    let name = format!("{rel}.lock");
    let lock = match fetch_tag_file(g, &rel, &name) {
        Ok(b) => b,
        // Only a genuine not-found means "no lock published"
        // i11b): a network or auth failure must not quietly downgrade the
        // roll to by-tag pulls.
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => return Err(("stack_lock_fetch_failed", format!("{name}: {e}"),
            Some("retry; or NOO_ALLOW_UNSIGNED=1 to deploy by tag only"))),
    };
    let sig = match fetch_tag_file(g, &rel, &format!("{name}.sig")) {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(e) => return Err(("stack_lock_unsigned",
            format!("{name} is published without a signature ({e}) — refusing"), None)),
    };
    if let Err(e) = crate::release_sig::verify(&lock, &sig) {
        return Err(("stack_lock_invalid", format!("{name}: {e} — refusing to deploy"),
            Some("the release was altered after signing; do not work around this")));
    }
    let text = String::from_utf8_lossy(&lock).to_string();
    if !text.lines().any(|l| l.contains("@sha256:")) {
        return Err(("stack_lock_empty", format!("{name} names no images"), None));
    }
    Ok(Some(text))
}

/// Write the verified lock as `<root>/stack.lock` (header `# tag <tag>`),
/// which the launcher turns into per-image digest pins; remove it when the
/// release publishes none.
fn write_stack_lock(g: &Globals, tag: &str, root: &std::path::Path, lock: Option<&str>) {
    let dst = root.join("stack.lock");
    let Some(text) = lock else {
        let _ = std::fs::remove_file(&dst);
        return;
    };
    let n = text.lines().filter(|l| l.contains("@sha256:")).count();
    if let Err(e) = std::fs::write(&dst, format!("# tag {tag}\n{text}")) {
        fail(g.json, ExitCode::Generic, "stack_lock_write_failed", &format!("{}: {e}", dst.display()), None);
    }
    if !g.json { ui::done(&format!("digest lock verified: {n} image(s) pinned from stack-{tag} (release-signed)")); }
}

/// The licensed add-ons declared on in `root`'s noomesh.yaml. An unreadable
/// or unparseable file refuses (it would otherwise read as "no add-on on" and
/// skip every hold).
fn addons_on(g: &Globals, root: &std::path::Path) -> Vec<&'static str> {
    match crate::addons::licensed_on(root) {
        Ok(l) => l,
        Err(e) => fail(g.json, ExitCode::Generic, "config",
            &format!("{e} — refusing to roll without knowing which add-ons are on. Nothing was changed"),
            Some("noo addons list")),
    }
}

/// The registry credential, or a refusal: an unreadable store is never "no
/// token".
fn addon_credential(g: &Globals) -> Option<crate::addons::lock_fetch::Credential> {
    match crate::addons::lock_fetch::installed_credential() {
        Ok(c) => c,
        Err(e) => fail(g.json, ExitCode::Generic, "store_unreadable", &format!("{e}. Nothing was changed"),
            Some("noo security secrets audit")),
    }
}

/// Remedy for an add-on that holds a stack roll.
fn addon_hold_fix(addon: &str, r: &crate::addons::resolve::Refusal) -> String {
    if r.is_auth() {
        return crate::addons::resolve::TOKEN_FIX.to_string();
    }
    if matches!(r, crate::addons::resolve::Refusal::Downgrade { .. }) {
        return "noo upgrade --stack --allow-downgrade   # an explicit rollback of the add-on with the stack".to_string();
    }
    format!("noo addons disable {addon}   # or wait for its release for this stack, or roll to an older one: noo upgrade --stack --tag <vX.Y.Z> (add --allow-downgrade to take the add-on back with it)")
}

/// Step -1z of `upgrade_stack`: resolve, verify and pull every add-on that
/// is on for the TARGET tag, or refuse the roll naming the add-on and why.
fn addon_preflight(
    g: &Globals,
    root: &std::path::Path,
    tag: &str,
    stack_lock: Option<&str>,
    allow_downgrade: bool,
) -> Vec<crate::addons::Prepared> {
    let on = addons_on(g, root);
    if on.is_empty() {
        return Vec::new();
    }
    let cred = addon_credential(g);
    let client = crate::addons::lock_fetch::Client::new(cred.clone());
    let ctx = crate::addons::Ctx { root, tag, stack_lock, allow_downgrade, client: &client, cred: cred.as_ref() };
    let mut out = Vec::new();
    for addon in on {
        if !g.json { ui::step(&format!("{addon}: resolving its signed lock for {tag}")); }
        match crate::addons::prepare(&ctx, addon, &mut crate::addons::resolve::LiveDocker::new(root)) {
            Ok(p) => out.push(p),
            Err(r) => fail(g.json, ExitCode::Generic, "addon_hold",
                &format!("refusing to roll to {tag}: the {addon} add-on is on and {}. Nothing was changed",
                    lowercase_first(&r.why(addon))),
                Some(&addon_hold_fix(addon, &r))),
        }
    }
    out
}

fn lowercase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Write the add-on pins resolved in the preflight, beside `stack.lock`.
fn commit_addon_pins(g: &Globals, root: &std::path::Path, tag: &str, prepared: &[crate::addons::Prepared]) {
    for p in prepared {
        match crate::addons::commit(root, p, tag) {
            Ok(pin) => if !g.json {
                ui::done(&format!("{} {} pinned for {tag} (add-on key #{}; {} image(s) pulled by digest)",
                    p.addon, pin.version, pin.key_index, p.pulled));
            },
            Err(r) => fail(g.json, ExitCode::Generic, "addon_pin_write_failed",
                &format!("{} — stack.lock is already written for {tag}; the launcher refuses {} until it is pinned",
                    r.why(&p.addon), p.addon),
                Some("noo addons upgrade")),
        }
    }
}

/// The add-ons that hold a roll to `target`: `(addon, why)` for each one on
/// that has no lock for it that verifies. Read-only (no pull, no pin).
fn addon_holds(g: &Globals, root: &std::path::Path, target: &str) -> Vec<(String, String)> {
    let on = addons_on(g, root);
    if on.is_empty() {
        return Vec::new();
    }
    let stack_lock = match try_stack_lock(g, target) {
        Ok(t) => t,
        Err((_, msg, _)) => return on.iter().map(|a| (a.to_string(), format!("the stack lock for {target} did not verify ({msg})"))).collect(),
    };
    let client = crate::addons::lock_fetch::Client::new(addon_credential(g));
    let pins = match crate::addons::pins::read(root) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "pins_unreadable", &e, Some("noo addons verify")),
    };
    on.into_iter()
        .filter_map(|addon| {
            let pinned = pins.get(addon).map(|p| p.version.clone());
            let want = crate::addons::resolve::Want {
                addon, stack_tag: target, stack_lock: stack_lock.as_deref(), pinned: pinned.as_deref(), allow_downgrade: false,
            };
            crate::addons::resolve::installed_anchor(addon)
                .and_then(|a| crate::addons::resolve::fetch_and_check(&client, &a, &want))
                .err()
                .map(|r| (addon.to_string(), r.why(addon)))
        })
        .collect()
}

/// `(current, newest, holds)` when a stack newer than this controller's is
/// published; `None` when it is current or nothing could be listed.
type StackHold = (String, String, Vec<(String, String)>);
fn stack_hold_check(g: &Globals) -> Option<StackHold> {
    let root = crate::envfile::repo_root();
    let current = crate::addons::current_tag(&root)?;
    let newest = newest_published_stack_tag()?;
    if !newer_than_pairing(&newest, &norm_stack_tag(&current)) {
        return None;
    }
    let holds = addon_holds(g, &root, &newest);
    Some((current, newest, holds))
}

/// The `--check --stack` line: the newest published stack, and whether an
/// add-on holds this controller at its current one.
pub(crate) fn hold_line(current: &str, newest: &str, holds: &[(String, String)]) -> String {
    if holds.is_empty() {
        return format!("stack {newest} published (this controller runs {current}); every add-on that is on has a lock for it");
    }
    let names: Vec<&str> = holds.iter().map(|(a, _)| a.as_str()).collect();
    format!("{newest} published; held at {current} by {}", names.join(", "))
}

/// What a failed lock stage means for the node roll.
#[derive(Debug, PartialEq, Eq)]
enum LockStageVerdict {
    /// Staged clean (or never staged): roll.
    Clean,
    /// Failures, but nothing depends on them yet (no online node on
    /// NOO_IMAGE_SOURCE=rail), or the operator passed --force: roll, and say
    /// so loudly with the images and the remedy.
    Warn(String),
    /// Failures and at least one online rail node: refuse unless --force.
    Refuse(String),
}

/// The pure decision. `rail_nodes` are online nodes reporting
/// `image_source_mode=rail` — only they pull from the rail, so only they make
/// a failed stage a reason to stop. While every node is on `legacy` (the
/// default for the release that ships the rail) a controller-disk or
/// registry blip must not block upgrades.
fn lock_stage_verdict(failed: &[String], rail_nodes: &[String], force: bool) -> LockStageVerdict {
    if failed.is_empty() {
        return LockStageVerdict::Clean;
    }
    let what = format!(
        "{} image(s) of this release failed to stage on the artifact rail: {}. Retry: `noo cluster stage-images --lock`",
        failed.len(),
        failed.join("; "),
    );
    if rail_nodes.is_empty() {
        return LockStageVerdict::Warn(format!(
            "{what} — no online node runs NOO_IMAGE_SOURCE=rail, so nothing pulls them yet; rolling nodes"));
    }
    let who = format!("online rail node(s) {} cannot pull them", rail_nodes.join(", "));
    if force {
        return LockStageVerdict::Warn(format!("{what} — {who}; rolling nodes anyway (--force)"));
    }
    LockStageVerdict::Refuse(format!("{what} — {who}. Stage them first, or pass --force"))
}

/// Online nodes whose agent reports `image_source_mode=rail`. A gateway
/// that cannot be asked yields none (the gateway wait above already passed).
fn online_rail_nodes(g: &Globals) -> Vec<String> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|b| b["nodes"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter(|n| n["status"].as_str() == Some("online") && n["image_source_mode"].as_str() == Some("rail"))
        .filter_map(|n| n["id"].as_str().or_else(|| n["node_id"].as_str()).map(str::to_string))
        .collect()
}

/// Applies the verdict: None to roll (after a loud warning when there is
/// one), Some(refusal) to stop.
fn lock_stage_blocker(g: &Globals, failed: &[String], force: bool) -> Option<String> {
    if failed.is_empty() {
        return None;
    }
    match lock_stage_verdict(failed, &online_rail_nodes(g), force) {
        LockStageVerdict::Clean => None,
        LockStageVerdict::Warn(m) => {
            ui::warned(&m);
            None
        }
        LockStageVerdict::Refuse(m) => Some(m),
    }
}

/// Poll `/health` until the gateway answers, up to `secs`. Quiet on the
/// first try (the common case), one line when it has to wait.
fn wait_for_gateway(g: &Globals, secs: u64) -> bool {
    let start = std::time::Instant::now();
    let mut poll: Option<ui::Poll> = None;
    loop {
        if crate::http::get_json_try(g, "/health", false, 5).is_ok() {
            if !g.json {
                match poll.take() {
                    Some(p) => p.done(&format!("gateway healthy after {}s", start.elapsed().as_secs())),
                    None => ui::done("gateway healthy"),
                }
            }
            return true;
        }
        let elapsed = start.elapsed().as_secs();
        if elapsed >= secs {
            return false;
        }
        if !g.json {
            // One live line on a TTY, one line per minute otherwise (§5).
            let p = poll.get_or_insert_with(|| ui::Poll::start(&format!("waiting for the gateway to report healthy (up to {secs}s)")));
            p.tick(elapsed);
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// GET from the controller mirror (or NOO_CLI_BASE_URL). The gateway's cert
/// is issued by the CLUSTER CA, which the platform verifier does not know —
/// so the probe silently failed and every node went to GitHub (HOST3,
/// 2026-09-03). Trust order: the CA anchor the node pinned at enroll
/// (~/noomesh/pki/ca.crt on the Mac lane), else the shared CLI trust
/// resolution (`http::resolve_trust`: /etc/noo/pki, $NOO_TLS_CA, the PKI
/// dir, WebPKI). Never an unverified transport: the release bytes are
/// Ed25519-verified against the signed manifest either way, but an
/// unverified channel is still a channel nobody authenticated.
fn mirror_get_bytes(url: &str) -> Result<Vec<u8>, FetchError> {
    // The Mac lane keeps its own anchor outside the two places
    // `http::resolve_trust` looks, so try it first; otherwise the shared
    // resolution applies, and its failure is returned rather than downgraded
    // (this used to fall back to `disable_verification(true)` on the grounds
    // that the payload is signature-checked anyway — true, and still no
    // reason to hand the mirror an unauthenticated channel).
    let home = std::env::var("HOME").unwrap_or_default();
    let mac_anchor = std::path::PathBuf::from(format!("{home}/noomesh/pki/ca.crt"));
    let agent: ureq::Agent = match std::fs::read(&mac_anchor)
        .ok()
        .and_then(|p| ureq::tls::Certificate::from_pem(&p).ok())
    {
        Some(cert) => ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(vec![cert])))
                    .build(),
            )
            .build()
            .into(),
        // No anchor resolved is a trust problem, said as one — never an
        // unverified fallback.
        None => crate::http::agent_for(url, 120)
            .map_err(|e| FetchError::new(release_fetch::FetchClass::Tls, format!("GET {url}: {e}")))?,
    };
    release_fetch::get_with_retry(&agent, url, None, &release_fetch::DEFAULT_RETRY, &mut release_fetch::real_sleep)
}

/// Gate keys that used to live in `noomesh.yaml` and are now posture-only.
/// `(section, key, posture key)`, mirroring `RETIRED_YAML_GATES` in
/// gateway-rust/src/posture.rs — the two are pinned together by
/// tests/test_retired_yaml_gates_parity.py, because the crates share no
/// library and a list that drifts is worse than no list.
pub(crate) const RETIRED_YAML_GATES: &[(&str, &str, &str)] =
    &[("security", "exec_approval_mode", "NOO_EXEC_APPROVAL_MODE")];

/// Move retired gate keys from `noomesh.yaml` into the posture table, then
/// delete them from the file — before the stack rolls.
///
/// The gateway REFUSES TO START while one of these keys is present, and that
/// refusal is right: a gate the operator set in YAML and the gateway ignores
/// is a control that exists only in their head. But the refusal lands at the
/// worst possible moment if nothing migrates first. On host8 (2026-09-12)
/// `noo upgrade --stack` rolled onto a gateway that then exited 2 on the
/// leftover `security.exec_approval_mode`; the controller stayed down, and
/// `noo security posture set` — the documented fix — needs a gateway to talk
/// to. The operator had to hand-edit the file and restart a container to get
/// the API back. This runs one step earlier, while the OLD gateway is still
/// serving, which is the only moment both halves are possible.
///
/// The value is carried across, not dropped: the whole point of the refusal
/// is that a security decision must not change silently, and an unset gate
/// means `strict`.
///
/// Refuses the roll if a key is present and cannot be migrated. Rolling
/// anyway is the outage above, and an operator who has just been told the
/// exact command can act on it.
fn migrate_retired_yaml_gates(g: &Globals, root: &std::path::Path) {
    let path = root.join("noomesh.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
        // An unparseable file is not this command's to fix, and guessing at
        // it with string edits is how a config gets truncated.
        ui::warned(&format!("{} does not parse as YAML — skipping the retired-gate check", path.display()));
        return;
    };
    for (section, key, posture_key, value) in retired_gates_present(&doc) {
        ui::step(&format!(
            "migrating {section}.{key} out of noomesh.yaml — it is posture-only now, and the new gateway refuses to start while it is there"
        ));
        let body = serde_json::json!({"key": posture_key, "value": value});
        match crate::http::post_json_operator_try(g, "/api/security/posture", &body, 15) {
            Ok(_) => {
                let stripped = strip_yaml_gate(&text, section, key);
                if std::fs::write(&path, &stripped).is_err() {
                    fail(g.json, ExitCode::Generic, "yaml_write_failed",
                        &format!("posture {posture_key} = {value} was written, but {} could not be updated", path.display()),
                        Some("remove the key by hand, then re-run: the gateway refuses to start while it is present"));
                }
                ui::done(&format!("posture {posture_key} = {value}; {section}.{key} removed from noomesh.yaml"));
            }
            Err(e) => {
                fail(g.json, ExitCode::Generic, "retired_gate_not_migrated",
                    &format!("{section}.{key} is in noomesh.yaml and the new gateway refuses to start while it is there, \
                              but the posture write failed ({e}) — refusing to roll into a controller that will not come up"),
                    Some(&format!("with the gateway up: noo security posture set {posture_key} {value} (your operator certificate — on the controller: noo security pki issue-client <you>), \
                                   remove {section}.{key} from noomesh.yaml, then re-run. \
                                   With the gateway already down, the host-level posture upsert is in docs/operating/runbooks/security-release-upgrade.md")));
            }
        }
    }
}

/// The retired gates a parsed config actually carries, with their values.
/// Pure so the decision is testable without a gateway or a filesystem.
fn retired_gates_present(doc: &serde_yaml::Value) -> Vec<(&'static str, &'static str, &'static str, String)> {
    let mut out = Vec::new();
    for (section, key, posture_key) in RETIRED_YAML_GATES {
        let Some(v) = doc.get(section).and_then(|s| s.get(key)) else { continue };
        let value = match v {
            serde_yaml::Value::String(s) => s.clone(),
            serde_yaml::Value::Bool(b) => b.to_string(),
            serde_yaml::Value::Number(n) => n.to_string(),
            _ => continue, // an explicit null, or a shape no gate has, sets nothing
        };
        if value.trim().is_empty() {
            continue;
        }
        out.push((*section, *key, *posture_key, value));
    }
    out
}

/// Remove `section.key` from a YAML document by LINE, keeping every comment
/// and every other key byte-for-byte.
///
/// A serde round-trip would drop the file's comments, and this file is one
/// an operator reads. The shape being removed is a scalar under a top-level
/// section, so the line-level rule is exact: inside the section's block,
/// drop the line whose key matches at that indent.
fn strip_yaml_gate(text: &str, section: &str, key: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut in_section = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 0 && !trimmed.is_empty() && !trimmed.starts_with('#') {
            in_section = trimmed.starts_with(&format!("{section}:"));
        } else if in_section
            && indent > 0
            && (trimmed.starts_with(&format!("{key}:")) || trimmed.starts_with(&format!("{key} :")))
        {
            continue; // the retired gate
        }
        out.push(line);
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

#[cfg(test)]
mod reexec_tests {
    use super::reexec_path;

    #[test]
    fn reexec_path_strips_the_deleted_marker_and_requires_a_file() {
        let dir = std::env::temp_dir().join(format!("noo-reexec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("noo");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let deleted = std::path::PathBuf::from(format!("{} (deleted)", bin.display()));
        assert_eq!(reexec_path(&deleted).as_deref(), Some(bin.as_path()), "the replacement at the original path is what runs");
        assert_eq!(reexec_path(&bin).as_deref(), Some(bin.as_path()));
        std::fs::remove_file(&bin).unwrap();
        assert!(reexec_path(&deleted).is_none(), "nothing at the path: run in-process");
        let _ = std::fs::remove_dir(&dir);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_failed_lock_stage_only_warns_while_no_node_runs_the_rail() {
        use super::{lock_stage_verdict, LockStageVerdict};
        assert_eq!(lock_stage_verdict(&[], &[], false), LockStageVerdict::Clean);
        let f = vec!["reg/a/llamacpp:v1 (amd64): docker pull: timeout".to_string()];
        // Every node on legacy (the default this release): warn, roll.
        match lock_stage_verdict(&f, &[], false) {
            LockStageVerdict::Warn(m) => {
                assert!(m.contains("reg/a/llamacpp:v1") && m.contains("noo cluster stage-images --lock"), "{m}");
                assert!(m.contains("no online node runs NOO_IMAGE_SOURCE=rail"), "{m}");
            }
            other => panic!("legacy fleet must warn, not refuse: {other:?}"),
        }
    }

    #[test]
    fn a_failed_lock_stage_blocks_the_roll_when_a_rail_node_is_online() {
        use super::{lock_stage_verdict, LockStageVerdict};
        let f = vec!["reg/a/llamacpp:v1 (amd64): no space left on device".to_string()];
        let rail = vec!["host8-ma".to_string()];
        match lock_stage_verdict(&f, &rail, false) {
            LockStageVerdict::Refuse(m) => {
                assert!(m.contains("host8-ma") && m.contains("--force") && m.contains("reg/a/llamacpp:v1"), "{m}");
            }
            other => panic!("a rail node must block the roll: {other:?}"),
        }
        assert!(matches!(lock_stage_verdict(&f, &rail, true), LockStageVerdict::Warn(m) if m.contains("--force")));
    }


    #[test]
    fn the_secrets_floor_is_read_from_the_compose_text_and_compared_as_a_version() {
        use super::{secrets_floor_in, tag_meets_floor};
        let compose = "name: noomesh\nx-noo-secrets-floor: stack-v0.2.79\nservices: {}\n";
        let floor = secrets_floor_in(compose).expect("floor");
        assert_eq!(floor, "stack-v0.2.79");
        assert!(secrets_floor_in("services: {}\n").is_none());
        for ok in ["v0.2.79", "stack-v0.2.79", "v0.2.80", "0.2.100", "v0.3.0", "v1.0.0"] {
            assert!(tag_meets_floor(ok, &floor), "{ok} should meet {floor}");
        }
        // --tag of an older stack, and anything that is not a version, is refused.
        for bad in ["v0.2.78", "v0.1.99", "latest", "", "v0.2", "dev-abc123"] {
            assert!(!tag_meets_floor(bad, &floor), "{bad} must NOT meet {floor}");
        }
    }

    #[test]
    fn rotate_refuses_below_the_floor_only_on_a_dist_install() {
        use super::secrets_floor_refusal;
        let f = Some("stack-v0.2.79");
        assert!(secrets_floor_refusal("dist", "v0.2.78", f).is_some());
        assert!(secrets_floor_refusal("dist", "", f).is_some(), "an unpinned dist install cannot be shown to meet it");
        assert!(secrets_floor_refusal("dist", "v0.2.79", f).is_none());
        assert!(secrets_floor_refusal("dev", "v0.2.78", f).is_none(), "dev builds its images from this tree");
        assert!(secrets_floor_refusal("dist", "v0.2.78", None).is_none());
    }

    /// The compose file this crate embeds declares the floor, and it is the
    /// same text the launcher's `secrets_floor` reads.
    #[test]
    fn the_shipped_compose_declares_a_secrets_floor() {
        let compose = include_str!("../../../docker-compose.cluster.yml");
        let floor = super::secrets_floor_in(compose).expect("x-noo-secrets-floor missing from the shipped compose");
        assert!(floor.starts_with("stack-v"), "{floor}");
    }


    /// The probe once asked a stale path that still answered 200, so `--stack`
    /// quietly pinned the CLI's baked pairing. The path must come from the
    /// same prefix the pull uses.
    #[test]
    fn the_tag_probe_asks_the_path_the_pull_uses() {
        assert_eq!(super::repo_path_from_prefix(""), "noomesh");
        assert_eq!(super::repo_path_from_prefix("ghcr.io/noomesh"), "noomesh");
        assert_eq!(super::repo_path_from_prefix("ghcr.io/noomesh/"), "noomesh",
                   "a trailing slash is the launcher's spelling");
        // An install pointed at its own mirror must probe THAT mirror.
        assert_eq!(super::repo_path_from_prefix("ghcr.io/acme/mesh"), "acme/mesh");
    }

    /// A release adds a service to the mounted-cert list; an install that
    /// upgraded rather than freshly onboarded has never issued one for it —
    /// exactly the `model-cache` gap from the newcomer-upgrade rehearsal
    /// (2026-09-29). The decision names only what's missing, and never
    /// re-flags a cert this install already has.
    /// `noo upgrade --all` is the whole instruction for a Mac below the
    /// leaf floor: it is staged leafless, so it needs a second pass. A Linux
    /// node on the same old version does not (its shell applier self-updates
    /// first), and neither does a Mac whose version is unknown (the stager
    /// assumes a capable applier and includes the leaves).
    #[test]
    fn only_a_mac_below_the_leaf_floor_needs_a_second_pass() {
        let rec = |n: &str, d: bool, v: &str| (n.to_string(), d, v.to_string());
        let nodes = vec![
            rec("host3", false, "noo-cli-v0.5.40+abc"),
            rec("host6", true, "noo-cli-v0.5.62+def"),
            rec("mcnew", true, "noo-cli-v0.5.63+aaa"),
            rec("mcdev", true, "dev"),
            rec("host9", false, "noo-cli-v0.5.62"),
        ];
        assert_eq!(super::leafless_macs(&nodes), vec!["host6".to_string()]);
        // Agrees with the stager, node by node.
        for (n, d, v) in &nodes {
            assert_eq!(super::needs_leaf_restage(*d, v),
                !crate::commands::node_leaves::applier_knows_leaf_kinds(*d, v), "{n}");
        }
    }

    /// The wait ends only on a PARSED version at or above the floor: an
    /// offline Mac (empty) or an unstamped one is not "there" yet.
    #[test]
    fn a_node_reaches_the_leaf_floor_only_on_a_reported_version_at_or_above_it() {
        assert!(super::reached_leaf_floor("noo-cli-v0.5.63+abc"));
        assert!(super::reached_leaf_floor("noo-cli-v0.6.0"));
        assert!(!super::reached_leaf_floor("noo-cli-v0.5.62+abc"));
        assert!(!super::reached_leaf_floor(""));
        assert!(!super::reached_leaf_floor("dev"));
    }

    #[test]
    fn the_mac_leaves_budget_defaults_to_ten_minutes_and_env_overrides() {
        assert_eq!(super::mac_leaves_budget(None), 600);
        assert_eq!(super::mac_leaves_budget(Some("120")), 120);
        assert_eq!(super::mac_leaves_budget(Some("0")), 0);
        assert_eq!(super::mac_leaves_budget(Some("soon")), 600);
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-upgrade-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_docker_invented_sso_pub_dir_is_named_not_written_over() {
        let t = scratch_dir("sso-blocker");
        let pub_path = t.join("sso").join("grafana.pub");
        assert!(sso_pub_blocker(&pub_path).is_none(), "absent is mintable, not blocked");
        std::fs::create_dir_all(&pub_path).unwrap();
        let fix = sso_pub_blocker(&pub_path).unwrap();
        assert!(fix.starts_with(&format!("sudo rm -r {} && ", pub_path.display())), "{fix}");
        // the parent Docker also made root-owned is handed back in the same line
        assert!(fix.ends_with(&format!("sudo chown \"$(id -un):$(id -gn)\" {}", t.join("sso").display())), "{fix}");
    }

    #[test]
    fn an_upgrade_mints_a_missing_sso_pair() {
        let t = scratch_dir("sso-mint");
        let ca = crate::pki::ClusterCa::new(t.clone());
        assert!(!ca.grafana_sso_key_exists());
        assert!(sso_pub_blocker(&ca.grafana_sso_pub_path()).is_none());
        assert_eq!(ca.ensure_grafana_sso_key(), Ok(true));
        assert!(ca.grafana_sso_pub_path().is_file() && ca.grafana_sso_key_path().is_file());
        assert_eq!(ca.ensure_grafana_sso_key(), Ok(false), "idempotent: a second roll leaves it alone");
    }

    /// Enabled systems' credentials are minted inside
    /// `upgrade_stack` BEFORE anything moves (slice, pin, launcher), so no
    /// supported roll reaches the launcher's refusal.
    #[test]
    fn system_credentials_are_minted_before_anything_in_the_roll_moves() {
        let src = include_str!("upgrade.rs");
        let body = &src[src.find("fn upgrade_stack(").expect("upgrade_stack")..];
        let body = &body[..body.find("\nfn ").expect("end of upgrade_stack")];
        let at = |needle: &str| body.find(needle).unwrap_or_else(|| panic!("{needle} not in upgrade_stack"));
        let mint = at("systems::reconcile_credentials(&root)");
        for later in ["migrate_retired_yaml_gates(", "standalone::materialize(", "NOO_IMAGE_TAG\", &tag", "root.join(\"scripts/noomesh-start.sh\")"] {
            assert!(mint < at(later), "enabled systems' credentials must be minted before `{later}`");
        }
    }

    #[test]
    fn the_audit_key_stage_mints_only_when_absent() {
        use super::{audit_key_stage, AuditKeyStage};
        // Present: the mint is never called — an existing key is never rotated.
        let out = audit_key_stage(|| Ok(true), || panic!("minted over a present key"));
        assert_eq!(out, Ok(AuditKeyStage::AlreadyPresent));
        // Absent: minted, once.
        let mut calls = 0;
        let out = audit_key_stage(|| Ok(false), || { calls += 1; Ok(()) });
        assert_eq!((out, calls), (Ok(AuditKeyStage::Minted), 1));
        // An unreadable store is an error, never "absent, so mint".
        let out = audit_key_stage(|| Err("decrypt failed".into()), || panic!("minted into an unreadable store"));
        assert!(out.is_err());
        // A failed write is an error the roll stops on.
        assert!(audit_key_stage(|| Ok(false), || Err("EACCES".into())).is_err());
    }

    /// "Always sops, never plaintext": an install with no encrypted store is
    /// refused, and its `.env` is left byte-for-byte as it was — the key is
    /// never minted into plaintext.
    #[test]
    fn without_an_encrypted_store_the_audit_key_stage_refuses_and_writes_nothing() {
        let root = std::env::temp_dir().join(format!("noo-audit-key-nostore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let env_before = "NOO_SECRETS_BACKEND=env\nNOO_JWT_SECRET=plaintext-install\n";
        std::fs::write(root.join(".env"), env_before).unwrap();
        let out = super::reconcile_audit_key(&root);
        let env_after = std::fs::read_to_string(root.join(".env")).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(out, Err(super::AuditKeyRefusal::NoStore));
        assert_eq!(env_after, env_before, ".env was written — the key must never go to plaintext");
    }

    /// The stage runs inside `upgrade_stack` BEFORE anything moves — the
    /// slice refresh, the pin, and the launcher — so a store that cannot be
    /// written stops the roll with nothing changed, and the new gateway never
    /// boots without its key.
    #[test]
    fn the_audit_key_is_minted_before_anything_in_the_roll_moves() {
        let src = include_str!("upgrade.rs");
        let body = &src[src.find("fn upgrade_stack(").expect("upgrade_stack")..];
        let body = &body[..body.find("\nfn ").expect("end of upgrade_stack")];
        let at = |needle: &str| body.find(needle).unwrap_or_else(|| panic!("{needle} not in upgrade_stack"));
        let mint = at("reconcile_audit_key(&root)");
        for later in ["migrate_retired_yaml_gates(", "standalone::materialize(", "NOO_IMAGE_TAG\", &tag", "root.join(\"scripts/noomesh-start.sh\")"] {
            assert!(mint < at(later), "the audit key must be minted before `{later}`");
        }
    }

    #[test]
    fn missing_service_certs_names_only_what_isnt_issued_yet() {
        let all = ["redis", "nats", "model-cache"];
        let mut existing = std::collections::HashSet::new();
        existing.insert("redis");
        existing.insert("nats");
        assert_eq!(super::missing_service_certs(&all, &existing), vec!["model-cache"]);
    }

    #[test]
    fn missing_service_certs_is_empty_when_every_service_is_covered() {
        let all = ["redis", "nats"];
        let mut existing = std::collections::HashSet::new();
        existing.insert("redis");
        existing.insert("nats");
        assert!(super::missing_service_certs(&all, &existing).is_empty());
    }

    #[test]
    fn missing_service_certs_names_everything_on_a_fresh_pki_dir() {
        let all = ["redis", "nats", "model-cache"];
        let existing = std::collections::HashSet::new();
        assert_eq!(
            super::missing_service_certs(&all, &existing),
            vec!["redis", "nats", "model-cache"]
        );
    }

    /// The exact event: the pin said v0.2.69, the resolver said v0.2.68, and
    /// the tool rolled backwards and pruned the newer images with a green tick.
    #[test]
    fn a_roll_to_an_older_tag_than_the_pin_is_a_downgrade() {
        assert!(super::is_downgrade("v0.2.69", "v0.2.68"));
        assert!(super::is_downgrade("stack-v0.2.69", "0.2.68"), "any spelling of both");
        assert!(!super::is_downgrade("v0.2.68", "v0.2.69"), "forward is not a downgrade");
        assert!(!super::is_downgrade("v0.2.68", "v0.2.68"), "re-apply is not a downgrade");
    }

    /// An unpinned or malformed pin is not "ahead" of anything — refusing
    /// there would block the very first roll of a fresh install.
    #[test]
    fn an_unpinned_controller_cannot_be_downgraded() {
        assert!(!super::is_downgrade("", "v0.2.68"));
        assert!(!super::is_downgrade("unpinned", "v0.2.68"));
        assert!(!super::is_downgrade("latest", "v0.2.68"));
    }

    /// Published-but-incomplete is the state a controller sees for the
    /// minutes after a stack is cut. It must be NAMED, not silently skipped.
    #[test]
    fn a_published_tag_missing_from_some_image_is_named() {
        let published = vec!["v0.2.68".to_string(), "v0.2.69".to_string()];
        assert_eq!(
            super::newer_published_but_incomplete(&published, Some("v0.2.68")).as_deref(),
            Some("v0.2.69")
        );
        assert_eq!(super::newer_published_but_incomplete(&published, Some("v0.2.69")), None,
            "complete == newest published: nothing to say");
        assert_eq!(super::newer_published_but_incomplete(&[], Some("v0.2.68")), None,
            "no release list: nothing to name");
        assert_eq!(
            super::newer_published_but_incomplete(&published, None).as_deref(),
            Some("v0.2.69"),
            "registry unknown: the newest published tag is the one to mention"
        );
    }
    /// A core-only stack tag (no add-on image carries it) counts as published
    /// once every core image has it; the add-ons are never asked about.
    #[test]
    fn a_core_only_tag_is_complete() {
        let mut asked: Vec<String> = Vec::new();
        let tags = super::complete_stack_tags(|image| {
            asked.push(image.to_string());
            Some(match image {
                // The per-commit gateway push lands ahead of the rest.
                "gateway" => vec!["v0.6.0".into(), "v0.6.1".into()],
                "trellion-intel" | "evolve" => vec!["v0.5.0".into()],
                _ => vec!["v0.5.9".into(), "v0.6.0".into()],
            })
        })
        .expect("every image listed");
        assert_eq!(tags, vec!["v0.6.0".to_string()]);
        for addon in ["trellion-intel", "trellion-evolve", "evolve"] {
            assert!(!asked.iter().any(|a| a == addon), "{addon} is an add-on, not a stack image");
            assert!(!super::STACK_IMAGES.contains(&addon));
        }
        assert!(asked.iter().any(|a| a == "trellion"), "trellion is a core image");
    }

    /// One image the registry cannot list makes the answer unknown, never an
    /// empty "nothing is published".
    #[test]
    fn an_unlistable_image_makes_completeness_unknown() {
        assert_eq!(super::complete_stack_tags(|i| (i != "worker").then(|| vec!["v0.6.0".into()])), None);
    }

    use super::{first_noo_on_path, local_agent_name, target_triple_for, version_less_than, running_gateway_tag};

    fn ids(v: &[&str]) -> std::collections::HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The regression: a digest-pinned pull leaves the image UNTAGGED, so
    /// `docker images` reports `repo:<none>`.
    ///
    /// The old rule kept anything whose text after the last `:` was neither
    /// the new tag nor the previous one, so `<none>` matched neither and the
    /// RUNNING images were marked stale. `docker rmi -f` refused them, the
    /// batch reported failure, and nothing was ever reclaimed — the count
    /// climbed 44 → 51 → 52 across releases with 11.6 GB sitting idle.
    #[test]
    fn an_untagged_image_in_use_is_never_pruned() {
        let lines = vec![
            "aaaaaaaaaaaa ghcr.io/noomesh/gateway:<none>".to_string(),
            "bbbbbbbbbbbb ghcr.io/noomesh/worker:<none>".to_string(),
        ];
        // The gateway image is the one the running container was created from.
        let got = superseded_images(&lines, &ids(&["aaaaaaaaaaaa"]), "v0.2.24", "v0.2.23");
        assert_eq!(got, vec!["bbbbbbbbbbbb".to_string()],
            "an in-use image must be left alone, and an unused one must still be reclaimed");
    }

    /// The current and previous tags stay warm so a rollback needs no pull.
    #[test]
    fn the_deployed_and_previous_tags_are_kept() {
        let lines = vec![
            "999999999999 ghcr.io/noomesh/gateway:v0.2.19".to_string(),
            "111111111111 ghcr.io/noomesh/gateway:v0.2.24".to_string(),
            "222222222222 ghcr.io/noomesh/gateway:v0.2.23".to_string(),
            "333333333333 ghcr.io/noomesh/gateway:v0.2.20".to_string(),
        ];
        let got = superseded_images(&lines, &Default::default(), "v0.2.24", "v0.2.23");
        // Both superseded tags are candidates; the deployed and previous stay.
        assert_eq!(got, vec!["333333333333".to_string(), "999999999999".to_string()]);
    }

    /// Images from other publishers are not ours to reclaim. Deleting
    /// postgres or nats here would be a rude surprise on a shared host.
    #[test]
    fn only_our_own_images_are_candidates() {
        let lines = vec![
            "444444444444 nats:latest".to_string(),
            "555555555555 ollama/ollama:latest".to_string(),
            "666666666666 ghcr.io/ggml-org/llama.cpp:server".to_string(),
        ];
        assert!(superseded_images(&lines, &Default::default(), "v0.2.24", "").is_empty());
    }

    /// docker images prints a 12-char id; docker inspect prints sha256:<64>.
    /// Comparing those unequal would make the in-use test never match, and
    /// every running image would become a prune candidate again.
    #[test]
    fn ids_compare_on_the_short_form() {
        assert_eq!(short_id("sha256:aaaaaaaaaaaabbbbbbbbbbbb"), "aaaaaaaaaaaa");
        assert_eq!(short_id("aaaaaaaaaaaa"), "aaaaaaaaaaaa");
    }

    /// The controller is skipped by the RAIL filter, so the local lane must
    /// pick it up — and must NOT double-handle a node the rail already has.
    ///
    /// This is the shape of the 2026-09-05 gap: host8 ran the same
    /// `noo-node-agent` as every worker, on a three-release-old build, and
    /// `noo upgrade --all` never mentioned it, because the stage filtered on
    /// the enrollment record rather than on "is there an agent here".
    #[test]
    fn the_controllers_own_agent_is_picked_up() {
        let rail = vec!["host3".to_string(), "host9".to_string()];
        assert_eq!(
            local_agent_name(true, "host8\n", &rail),
            Some("host8".to_string()),
            "the controller runs an agent and is not on the rail — it must be handled",
        );
    }

    /// A worker upgrading ITSELF must not also run the controller-only local
    /// lane: the rail already delivers to it, and `--local` would bypass the
    /// signed-bundle path that makes the rail trustworthy.
    #[test]
    fn a_rail_node_is_not_also_a_local_one() {
        let rail = vec!["host3".to_string(), "host9".to_string()];
        assert_eq!(local_agent_name(true, "host3", &rail), None);
    }

    /// i11a, the live case: a second Pop!_OS machine enrolled under the
    /// controller's own node name `host8`. On the controller that name is
    /// dropped from the rail, so the controller's agent is upgraded by the
    /// local lane (which re-issues its cert WITH the controller names)
    /// instead of being restaged from the other machine's record.
    #[test]
    fn the_controllers_name_never_rides_the_rail_on_the_controller() {
        let is_self = |n: &str| n.eq_ignore_ascii_case("host8");
        let names = vec!["host3".to_string(), "host8".to_string(), "host8-ma".to_string()];
        let rail = rail_names(names.clone(), is_self, true);
        assert_eq!(rail, vec!["host3".to_string(), "host8-ma".to_string()]);
        assert_eq!(local_agent_name(true, "host8\n", &rail), Some("host8".to_string()));
        // Not a controller (a worker running `noo upgrade` for itself):
        // unchanged, its own name stays on the rail and goes last.
        let rail = rail_names(names, is_self, false);
        assert_eq!(rail, vec!["host3".to_string(), "host8-ma".to_string(), "host8".to_string()]);
        assert_eq!(local_agent_name(true, "host8", &rail), None);
    }

    /// No agent installed → no claim that there is one to upgrade.
    #[test]
    fn no_agent_means_no_local_lane() {
        assert_eq!(local_agent_name(false, "host8", &[]), None);
    }

    /// An unreadable /etc/hostname yields "", which must not become a node
    /// named "" that the child is then asked to provision.
    #[test]
    fn a_blank_hostname_is_not_a_node() {
        assert_eq!(local_agent_name(true, "  \n", &[]), None);
    }

    /// Every platform the release actually publishes must resolve, and the
    /// names must be the ones on the release — a triple that does not match
    /// an asset is a 404 at download time, not a refusal the operator can read.
    #[test]
    fn published_platforms_resolve_to_their_asset_names() {
        assert_eq!(target_triple_for("linux", "x86_64").unwrap(), "x86_64-unknown-linux-musl");
        assert_eq!(target_triple_for("linux", "aarch64").unwrap(), "aarch64-unknown-linux-musl");
        // The regression: a Mac node could be HANDED this asset by the rail
        // but could not fetch it for itself.
        assert_eq!(target_triple_for("macos", "aarch64").unwrap(), "aarch64-apple-darwin");
    }

    /// Absence must stay absence. Intel Macs and everything else publish no
    /// asset, and guessing a triple would turn a clear refusal into a 404.
    #[test]
    fn unpublished_platforms_still_refuse() {
        assert_eq!(target_triple_for("macos", "x86_64"), None);
        assert_eq!(target_triple_for("windows", "x86_64"), None);
        assert_eq!(target_triple_for("linux", "riscv64"), None);
    }

    /// The guard is asymmetric ON PURPOSE and the asymmetry is the whole
    /// point: gateway OLDER than the node bundle is the unsafe ordering;
    /// gateway NEWER is the normal staged rollout and must not be refused.
    /// A symmetric "versions must match" rule would block the very thing
    /// this protects — walking the nodes after rolling the controller.
    #[test]
    fn only_an_older_gateway_is_unsafe() {
        assert!(version_less_than("v0.2.19", "v0.2.21"), "older gateway → refuse");
        assert!(!version_less_than("v0.2.21", "v0.2.19"), "newer gateway → allow (staged rollout)");
        assert!(!version_less_than("v0.2.21", "v0.2.21"), "same → allow");
        assert!(version_less_than("v0.2.9", "v0.2.10"), "components are numeric, not lexical");
    }

    /// Unreadable versions must NOT refuse. This guard exists to stop one
    /// known-bad ordering, not to assert that every other state is good —
    /// refusing on a dev build or a hand-rolled tag would break installs
    /// that were never at risk.
    #[test]
    fn an_unreadable_version_never_refuses() {
        assert!(!version_less_than("dev-local-build", "v0.2.21"));
        assert!(!version_less_than("v0.2.21", "latest"));
        assert!(!version_less_than("", "v0.2.21"));
    }

    /// Absent docker / absent container is None, not a panic and not a
    /// refusal: the CLI runs on machines that are not the controller.
    #[test]
    fn a_missing_gateway_container_is_unknown_not_unsafe() {
        // Whatever this box has, the call must not panic and must return an
        // Option — a tag only when it could actually read one.
        if let Some(tag) = running_gateway_tag() {
            assert!(tag.starts_with('v'), "a returned tag is version-shaped: {tag}");
        }
    }

    use super::*;

    #[test]
    fn a_release_candidate_is_judged_as_its_release_but_never_discovered() {
        // Explicit `--tag v0.2.89-rc.1` must pass the secrets floor (a
        // rehearsal rolls exactly this), but default discovery must never pick it.
        assert!(tag_meets_floor("v0.2.89-rc.1", "v0.2.80"));
        assert!(tag_meets_floor("stack-v0.2.89-rc.12", "stack-v0.2.89"));
        assert!(!tag_meets_floor("v0.2.79-rc.1", "v0.2.80"));
        assert!(!tag_meets_floor("v0.2.89-beta", "v0.2.80"), "only -rc.N is understood");
        assert!(!is_downgrade("v0.2.88", "v0.2.89-rc.1"));
        assert!(is_downgrade("v0.2.89", "v0.2.88-rc.3"));
        assert!(!is_stack_version("v0.2.89-rc.1"), "discovery stays strict");
        let published = vec!["v0.2.88".to_string(), "v0.2.89-rc.1".to_string()];
        assert_eq!(newer_published_but_incomplete(&published, Some("v0.2.88")), None);
    }

    #[test]
    fn stack_tags_normalize() {
        for (input, want) in [
            ("stack-v0.1.74", "v0.1.74"),
            ("v0.1.74", "v0.1.74"),
            ("0.1.74", "v0.1.74"),
            ("  stack-v0.2.0 ", "v0.2.0"),
        ] {
            assert_eq!(norm_stack_tag(input), want, "input: {input:?}");
        }
    }

    #[test]
    fn upsert_env_replaces_moves_and_appends() {
        let home = std::env::temp_dir().join(format!("noo-upsert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".env"),
            "NOO_INSTALL_MODE=dist\nNOO_IMAGE_TAG=v0.1.70\nNOO_IMAGE_TAG=v0.1.71\nOTHER=x\n").unwrap();
        crate::onboard::standalone::upsert_env(&home, "NOO_IMAGE_TAG", "v0.1.74").unwrap();
        crate::onboard::standalone::upsert_env(&home, "NEW_KEY", "y").unwrap();
        let got = std::fs::read_to_string(home.join(".env")).unwrap();
        assert_eq!(got.matches("NOO_IMAGE_TAG=").count(), 1, "dupes must collapse: {got}");
        assert!(got.contains("NOO_IMAGE_TAG=v0.1.74"));
        assert!(got.contains("OTHER=x"));
        assert!(got.contains("NEW_KEY=y"));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// PATH ORDER decides which binary runs, so the check must return the
    /// FIRST match, not any match.
    ///
    /// host6, 2026-09-05: `~/.local/bin/noo` (0.3.92) sat ahead of
    /// `/usr/local/bin/noo` (0.3.95, just installed). `noo --version` reported
    /// the old one and the install looked like it had failed. On a Mac node
    /// this is durable — the rail only ever writes /usr/local/bin/noo — so the
    /// fleet reports one version while the operator's shell runs another.
    #[test]
    fn the_first_noo_on_path_is_the_one_that_runs() {
        let present = |p: &std::path::Path| {
            p == std::path::Path::new("/home/u/.local/bin/noo")
                || p == std::path::Path::new("/usr/local/bin/noo")
        };
        assert_eq!(
            first_noo_on_path("/home/u/.local/bin:/usr/bin:/usr/local/bin", &present).unwrap(),
            std::path::Path::new("/home/u/.local/bin/noo"),
        );
        // Reverse the order and the answer must reverse with it.
        assert_eq!(
            first_noo_on_path("/usr/local/bin:/home/u/.local/bin", &present).unwrap(),
            std::path::Path::new("/usr/local/bin/noo"),
        );
    }

    /// An empty PATH entry means cwd to the shell. Reporting `./noo` as the
    /// winner would name a path the operator cannot act on, so it is skipped.
    #[test]
    fn an_empty_path_entry_is_not_the_current_directory() {
        let any = |_: &std::path::Path| true;
        assert_eq!(
            first_noo_on_path(":/usr/local/bin", &any).unwrap(),
            std::path::Path::new("/usr/local/bin/noo"),
        );
    }

    /// No noo anywhere on PATH is not a shadow — the installer reports the
    /// separate "not on PATH" case, and this must not invent a second warning.
    #[test]
    fn no_noo_on_path_is_not_a_shadow() {
        let none = |_: &std::path::Path| false;
        assert_eq!(first_noo_on_path("/usr/bin:/bin", &none), None);
    }

    /// A ZERO-node fleet must still stage the platforms a first node is
    /// likely to be — own platform plus both linux arches — or the first
    /// provision bundle carries no hostd and no harness (newcomer rehearsal,
    /// 2026-09-28: deriving the set from enrolled facts alone left this
    /// empty on a fresh controller).
    #[test]
    fn zero_nodes_still_stages_own_platform_and_both_linux_arches() {
        let got = asset_platforms(&[], "linux", "x86_64");
        assert!(got.contains(&("linux".to_string(), "x86_64".to_string())));
        assert!(got.contains(&("linux".to_string(), "aarch64".to_string())));
        // No duplicate: the controller's own platform IS one of the two.
        assert_eq!(got.len(), 2, "{got:?}");
    }

    /// A darwin controller's own platform is included alongside the two
    /// linux arches, not instead of them — a Mac controller still needs to
    /// stage what a linux first node needs.
    #[test]
    fn own_darwin_platform_is_added_to_the_linux_floor() {
        let got = asset_platforms(&[], "macos", "aarch64");
        assert_eq!(got, vec![
            ("linux".to_string(), "aarch64".to_string()),
            ("linux".to_string(), "x86_64".to_string()),
            ("macos".to_string(), "aarch64".to_string()),
        ]);
    }

    /// Enrolled fleet facts add to the floor rather than replacing it, and
    /// duplicates (an enrolled node on a platform already in the floor)
    /// collapse to one entry.
    #[test]
    fn fleet_facts_extend_the_floor_and_dedup() {
        let toks = serde_json::json!([
            {"facts": {"os": "linux", "arch": "x86_64"}},
            {"facts": {"os": "macos", "arch": "aarch64"}},
        ]);
        let got = asset_platforms(toks.as_array().unwrap(), "linux", "x86_64");
        assert_eq!(got, vec![
            ("linux".to_string(), "aarch64".to_string()),
            ("linux".to_string(), "x86_64".to_string()),
            ("macos".to_string(), "aarch64".to_string()),
        ]);
    }

    /// Missing facts default to linux/x86_64 (same fallback `upload_cli_assets`
    /// used before this change), so a token with no `facts` block still yields
    /// a usable platform rather than being silently dropped.
    #[test]
    fn missing_facts_default_to_linux_x86_64() {
        let toks = serde_json::json!([{"node_name": "no-facts-yet"}]);
        let got = asset_platforms(toks.as_array().unwrap(), "linux", "aarch64");
        assert_eq!(got, vec![
            ("linux".to_string(), "aarch64".to_string()),
            ("linux".to_string(), "x86_64".to_string()),
        ]);
    }
}

#[cfg(test)]
mod retired_gate_tests {
    use super::{retired_gates_present, strip_yaml_gate, RETIRED_YAML_GATES};

    const CFG: &str = "# a comment the operator wrote\nsecurity:\n  exec_approval_mode: auto\n  exec_approval_timeout: 300\nmemory:\n  enabled: true\n";

    #[test]
    fn a_retired_gate_is_found_with_its_value() {
        let doc: serde_yaml::Value = serde_yaml::from_str(CFG).unwrap();
        let found = retired_gates_present(&doc);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].0, found[0].1, found[0].2, found[0].3.as_str()),
                   ("security", "exec_approval_mode", "NOO_EXEC_APPROVAL_MODE", "auto"));
    }

    #[test]
    fn a_clean_config_migrates_nothing() {
        let doc: serde_yaml::Value =
            serde_yaml::from_str("security:\n  exec_approval_timeout: 300\nmemory:\n  enabled: true\n").unwrap();
        assert!(retired_gates_present(&doc).is_empty());
        // An explicit null is not a setting, so there is nothing to carry.
        let doc: serde_yaml::Value = serde_yaml::from_str("security:\n  exec_approval_mode:\n").unwrap();
        assert!(retired_gates_present(&doc).is_empty());
    }

    #[test]
    fn stripping_keeps_comments_and_every_other_key() {
        let out = strip_yaml_gate(CFG, "security", "exec_approval_mode");
        assert!(out.contains("# a comment the operator wrote"), "{out}");
        assert!(out.contains("exec_approval_timeout: 300"), "{out}");
        assert!(out.contains("memory:"), "{out}");
        assert!(!out.contains("exec_approval_mode"), "{out}");
        assert!(out.ends_with('\n'));
        // And the result is what the gateway will accept: nothing left to find.
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert!(retired_gates_present(&doc).is_empty());
    }

    #[test]
    fn a_same_named_key_in_another_section_is_left_alone() {
        let cfg = "other:\n  exec_approval_mode: keep-me\nsecurity:\n  exec_approval_mode: auto\n";
        let out = strip_yaml_gate(cfg, "security", "exec_approval_mode");
        assert!(out.contains("keep-me"), "{out}");
        assert_eq!(out.matches("exec_approval_mode").count(), 1, "{out}");
    }

    #[test]
    fn the_list_is_not_empty_while_the_gateway_refuses() {
        // If this ever empties, the migration is dead code and the parity
        // test against posture.rs is what will say so.
        assert!(!RETIRED_YAML_GATES.is_empty());
    }
}

#[cfg(test)]
mod cli_action_tests {
    use super::*;

    #[test]
    fn newer_running_build_is_kept() {
        assert_eq!(decide_cli_action("0.5.68", "0.5.67", false), CliAction::KeepNewer);
        assert_eq!(decide_cli_action("0.6.0", "0.5.99", false), CliAction::KeepNewer);
        assert_eq!(decide_cli_action("0.5.10", "0.5.9", false), CliAction::KeepNewer);
    }

    #[test]
    fn older_running_build_upgrades() {
        assert_eq!(decide_cli_action("0.5.65", "0.5.67", false), CliAction::Upgrade);
        assert_eq!(decide_cli_action("0.5.65", "0.5.67", true), CliAction::Upgrade);
    }

    #[test]
    fn equal_is_noop() {
        assert_eq!(decide_cli_action("0.5.67", "0.5.67", false), CliAction::Noop);
        assert_eq!(decide_cli_action("0.5.67", "0.5.67", true), CliAction::Noop);
    }

    #[test]
    fn pinned_older_installs_as_downgrade() {
        assert_eq!(decide_cli_action("0.5.68", "0.5.60", true), CliAction::DowngradePinned);
    }

    #[test]
    fn unparsable_never_crashes_and_is_treated_as_different() {
        assert_eq!(decide_cli_action("0.5.68", "nightly", false), CliAction::Unparsable);
        assert_eq!(decide_cli_action("weird", "0.5.68", true), CliAction::Unparsable);
        assert_eq!(decide_cli_action("0.5", "0.5.68", false), CliAction::Unparsable);
        assert_eq!(decide_cli_action("0.5.x", "0.5.x", false), CliAction::Noop);
        assert_eq!(CliAction::Unparsable.as_str(), "upgrade");
    }

    #[test]
    fn prerelease_orders_below_its_release() {
        assert_eq!(decide_cli_action("0.5.68-rc.1", "0.5.68", false), CliAction::Upgrade);
        assert_eq!(decide_cli_action("0.5.68", "0.5.68-rc.1", false), CliAction::KeepNewer);
        assert_eq!(decide_cli_action("0.5.68-rc.2", "0.5.68-rc.10", false), CliAction::Upgrade);
        assert_eq!(decide_cli_action("0.5.68-alpha", "0.5.68-1", false), CliAction::KeepNewer);
        assert_eq!(decide_cli_action("0.5.68+abc", "0.5.68", false), CliAction::Noop);
    }

    #[test]
    fn latest_is_the_highest_final_never_a_candidate() {
        let r = |t: &str, p: bool| (t.to_string(), p);
        // List order is creation order: the rc was created after 0.5.75's final.
        let rels = vec![r("noo-cli-v0.5.76-rc.1", true), r("stack-v0.2.89", false),
                        r("noo-cli-v0.5.75", false), r("noo-cli-v0.5.74", false)];
        assert_eq!(pick_latest_cli(&rels).as_deref(), Some("0.5.75"));
        // A candidate GitHub forgot to mark is still skipped by its suffix.
        let rels = vec![r("noo-cli-v0.5.76-rc.1", false), r("noo-cli-v0.5.75", false)];
        assert_eq!(pick_latest_cli(&rels).as_deref(), Some("0.5.75"));
        // Highest wins, not first listed.
        let rels = vec![r("noo-cli-v0.5.9", false), r("noo-cli-v0.5.10", false)];
        assert_eq!(pick_latest_cli(&rels).as_deref(), Some("0.5.10"));
        // Only candidates: nothing to upgrade to.
        assert_eq!(pick_latest_cli(&[r("noo-cli-v0.5.76-rc.1", true)]), None);
    }

    #[test]
    fn a_candidate_build_upgrades_to_its_final() {
        assert_eq!(decide_cli_action("0.5.76-rc.1", "0.5.76", false), CliAction::Upgrade);
        assert_eq!(decide_cli_action("0.5.76-rc.1", "0.5.75", false), CliAction::KeepNewer);
    }

    #[test]
    fn a_candidate_pairing_is_not_replaced_by_the_previous_final() {
        // rc CLI paired with v0.2.89-rc.1; v0.2.88 is the newest final.
        assert!(!newer_than_pairing("v0.2.88", "v0.2.89-rc.1"));
        // A final above the candidate's release still wins.
        assert!(newer_than_pairing("v0.2.90", "v0.2.89-rc.1"));
        // Finals behave as before.
        assert!(newer_than_pairing("v0.2.89", "v0.2.88"));
        assert!(!newer_than_pairing("v0.2.88", "v0.2.88"));
    }

    #[test]
    fn action_strings() {
        assert_eq!(CliAction::KeepNewer.as_str(), "keep_newer");
        assert_eq!(CliAction::DowngradePinned.as_str(), "downgrade_pinned");
        assert_eq!(CliAction::Noop.as_str(), "noop");
        assert_eq!(CliAction::Upgrade.as_str(), "upgrade");
    }
}

#[cfg(test)]
mod short_cert_reconcile_tests {
    /// The short-leaf pass must run BEFORE the early return
    /// for "nothing missing", or an upgrade with every leaf present (the
    /// common case) never reaches it.
    #[test]
    fn the_short_leaf_pass_runs_before_the_nothing_missing_return() {
        let src = include_str!("upgrade.rs");
        let f = src.split("fn reconcile_service_certs(").nth(1).expect("reconcile_service_certs exists");
        let f = f.split("\nfn ").next().unwrap();
        let short = f.find("reconcile_short_service_certs(").expect("calls the short-leaf pass");
        let early = f.find("if missing.is_empty()").expect("keeps the early return");
        assert!(short < early, "the short-leaf pass must precede `if missing.is_empty()`");
    }
}

#[cfg(test)]
mod offline_roll_tests {
    use super::{judge_offline_after_grace, nodes_outcome, offline_nodes};
    use crate::commands::cluster_verify::parse_rfc3339_unix;
    use serde_json::json;

    fn now() -> i64 { parse_rfc3339_unix("2026-10-06T12:00:00Z").unwrap() }

    #[test]
    fn a_node_offline_before_the_roll_is_skipped_with_its_age_and_online_ones_are_not() {
        let recs = vec![
            ("host3".to_string(), Some(json!({"status": "online", "last_heartbeat": "2026-10-06T11:59:30Z"}))),
            ("host8-ma".to_string(), Some(json!({"status": "offline", "last_heartbeat": "2026-10-06T08:00:00Z"}))),
            // Stamped online but silent for hours: the heartbeat is the evidence.
            ("stale".to_string(), Some(json!({"status": "online", "last_heartbeat": "2026-10-06T09:00:00Z"}))),
            // No record / no stamp yet: not evidence of absence — staged as before.
            ("ghost".to_string(), None),
            ("fresh".to_string(), Some(json!({"status": "online"}))),
        ];
        let skipped = offline_nodes(&recs, now());
        let names: Vec<&str> = skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["host8-ma", "stale"]);
        assert!(skipped[0].1.contains("4 h"), "{}", skipped[0].1);
    }

    fn rec(stamp: &str) -> Vec<(String, Option<serde_json::Value>)> {
        vec![("host6".to_string(), Some(json!({"status": "online", "last_heartbeat": stamp})))]
    }

    /// v0.2.95 roll: gateway just restarted, record 28 min stale, then the
    /// node's heartbeat lands during the grace: staged, not skipped.
    #[test]
    fn a_stale_node_that_heartbeats_during_the_grace_is_not_skipped() {
        let t = std::cell::Cell::new(now());
        let mut reads = 0;
        let mut said = Vec::new();
        let skipped = judge_offline_after_grace(
            rec("2026-10-06T11:32:00Z"), Some(20), t.get(),
            &mut |_| { reads += 1; rec(if reads >= 2 { "2026-10-06T12:00:09Z" } else { "2026-10-06T11:32:00Z" }) },
            &mut |s| t.set(t.get() + s as i64),
            &mut || t.get(),
            &mut |l| said.push(l.to_string()),
        );
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(reads >= 2 && said[0].contains("waiting for heartbeats from host6"), "{said:?}");
    }

    #[test]
    fn a_node_still_stale_after_the_grace_is_skipped_and_the_wait_is_bounded() {
        let t = std::cell::Cell::new(now());
        let mut slept = 0u64;
        let skipped = judge_offline_after_grace(
            rec("2026-10-06T11:32:00Z"), Some(20), t.get(),
            &mut |_| rec("2026-10-06T11:32:00Z"),
            &mut |s| { slept += s; t.set(t.get() + s as i64) },
            &mut || t.get(),
            &mut |_| {},
        );
        assert_eq!(skipped.len(), 1);
        assert!(slept <= 90, "{slept}");
    }

    #[test]
    fn an_old_gateway_is_trusted_at_once_with_no_wait() {
        let mut slept = 0u64;
        let skipped = judge_offline_after_grace(
            rec("2026-10-06T11:32:00Z"), Some(3600), now(),
            &mut |_| panic!("no re-read"), &mut |s| slept += s, &mut || now(), &mut |_| {},
        );
        assert_eq!((skipped.len(), slept), (1, 0));
    }

    /// v0.2.97 roll: the gateway had just restarted, and host2 (silent
    /// 21 h) and host8-ma (2 d) cost 90 s of "waiting for heartbeats".
    #[test]
    fn a_node_long_gone_before_the_restart_is_skipped_at_once() {
        let mut slept = 0u64;
        let mut said = Vec::new();
        let recs = vec![
            ("host2".to_string(), Some(json!({"status": "offline", "last_heartbeat": "2026-10-05T15:00:00Z"}))),
            ("host8-ma".to_string(), Some(json!({"status": "offline"}))),
        ];
        let skipped = judge_offline_after_grace(
            recs, Some(20), now(),
            &mut |_| panic!("no re-read for nodes no restart explains"),
            &mut |s| slept += s, &mut || now(), &mut |l| said.push(l.to_string()),
        );
        let names: Vec<&str> = skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["host2", "host8-ma"]);
        assert_eq!(slept, 0, "{said:?}");
        assert!(said.is_empty(), "{said:?}");
    }

    /// The wait still covers the node the restart can explain, and only it.
    #[test]
    fn only_a_recently_seen_node_is_waited_for() {
        let t = std::cell::Cell::new(now());
        let mut said = Vec::new();
        let recs = |fresh: bool| vec![
            ("host2".to_string(), Some(json!({"status": "offline", "last_heartbeat": "2026-10-05T15:00:00Z"}))),
            ("host6".to_string(), Some(json!({"status": "online",
                "last_heartbeat": if fresh { "2026-10-06T12:00:09Z" } else { "2026-10-06T11:32:00Z" }}))),
        ];
        let mut reads = 0;
        let skipped = judge_offline_after_grace(
            recs(false), Some(20), t.get(),
            &mut |_| { reads += 1; recs(reads >= 2) },
            &mut |s| t.set(t.get() + s as i64), &mut || t.get(),
            &mut |l| said.push(l.to_string()),
        );
        let names: Vec<&str> = skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["host2"]);
        assert!(said.iter().all(|l| l.contains("host6") && !l.contains("host2")), "{said:?}");
    }

    #[test]
    fn skipping_an_offline_node_warns_and_exits_zero() {
        let (rc, msg) = nodes_outcome(3, &["host8-ma".into()], &[], &[]);
        assert_eq!(rc, 0);
        assert!(msg.contains("2 of 3") && msg.contains("skipped offline: host8-ma"), "{msg}");
        let (rc, msg) = nodes_outcome(2, &[], &[], &[]);
        assert_eq!((rc, msg.contains("all 2 node(s)")), (0, true));
    }

    #[test]
    fn an_online_node_that_fails_still_fails_the_stage_even_beside_a_skipped_one() {
        let (rc, msg) = nodes_outcome(3, &["host8-ma".into()], &["host3".into()], &[]);
        assert_eq!(rc, 1);
        assert!(msg.contains("staging failed for: host3") && msg.contains("skipped offline: host8-ma"), "{msg}");
        let (rc, _) = nodes_outcome(2, &[], &[], &["host6".into()]);
        assert_eq!(rc, 1, "an unstaged Mac leaf pass still fails");
    }
}

#[cfg(test)]
mod keyless_tests {
    use super::keyless_of;
    use serde_json::json;

    fn req() -> Vec<(String, String)> {
        vec![("worker".into(), "svc:worker".into()), ("trellion".into(), "svc:trellion".into())]
    }

    /// The roll refuses while a consumer would be left with
    /// no credential the new gateway accepts.
    #[test]
    fn a_consumer_without_an_active_key_stops_the_roll() {
        let listing = json!({"keys": [{"consumer": "svc:trellion", "active": true}, {"consumer": "svc:worker", "active": false}]});
        assert_eq!(keyless_of(&req(), &listing), ["worker"]);
        let none = json!({"keys": []});
        assert_eq!(keyless_of(&req(), &none), ["worker", "trellion"]);
    }

    #[test]
    fn every_consumer_on_its_own_key_rolls() {
        let listing = json!({"keys": [{"consumer": "svc:worker", "active": true}, {"consumer": "svc:trellion", "active": true}]});
        assert!(keyless_of(&req(), &listing).is_empty());
    }

    #[test]
    fn the_check_runs_before_anything_moves() {
        let src = include_str!("upgrade.rs");
        let body = &src[src.find("fn upgrade_stack(").unwrap()..];
        let check = body.find("match pre_roll_key_verdict(").expect("the pre-roll key check");
        for later in ["match reconcile_audit_key(&root)", "crate::commands::systems::reconcile_credentials(&root)",
                      "crate::onboard::standalone::materialize(&root)"] {
            let at = body.find(later).unwrap_or_else(|| panic!("{later} missing"));
            assert!(check < at, "the key check must run before `{later}` — its refusal says nothing was changed");
        }
    }

    /// Review M2: the check fails CLOSED. An unreadable gateway refuses the
    /// roll unless --skip-gateway-key-check, which never skips the store
    /// check — and plain --force does not reach this check at all.
    #[test]
    fn an_unverifiable_gateway_refuses_unless_forced_and_the_store_always_counts() {
        use super::{pre_roll_key_verdict, PreRollKeys};
        let none: Vec<String> = vec![];
        assert_eq!(pre_roll_key_verdict(&none, Some(&none), false), PreRollKeys::Go);
        assert_eq!(pre_roll_key_verdict(&none, None, false), PreRollKeys::Unverifiable);
        assert_eq!(pre_roll_key_verdict(&none, None, true), PreRollKeys::GoUnverified);
        let worker = vec!["worker".to_string()];
        assert_eq!(pre_roll_key_verdict(&worker, None, true), PreRollKeys::Missing(worker.clone()), "the skip keeps the store check");
        let src = include_str!("upgrade.rs");
        let body = &src[src.find("fn upgrade_stack(").unwrap()..];
        assert!(body.contains("pre_roll_key_verdict(&store_short, db_short.as_deref(), skip_gw_key_check)"),
            "the pre-roll check must be steered by its own flag, not --force");
        assert_eq!(pre_roll_key_verdict(&worker, Some(&none), false), PreRollKeys::Missing(worker.clone()),
            "an active DB row is not enough: compose delivers from the store");
        let both = pre_roll_key_verdict(&worker, Some(&["trellion".to_string(), "worker".to_string()]), false);
        assert_eq!(both, PreRollKeys::Missing(vec!["worker".into(), "trellion".into()]));
    }

    #[test]
    fn a_blank_store_key_is_a_missing_one() {
        let req = vec![("worker".to_string(), "svc:worker".to_string())];
        assert_eq!(super::keyless_in_store_of(&req, &|_| false), ["worker"]);
        assert!(super::keyless_in_store_of(&req, &|k| k == "NOO_SVC_KEY_WORKER").is_empty());
    }

    /// i33: the add-on preflight runs before anything in the roll mints or
    /// moves, and the add-on pins are written in the same step as stack.lock.
    #[test]
    fn the_addon_preflight_runs_before_anything_moves_and_pins_land_with_stack_lock() {
        let src = include_str!("upgrade.rs");
        let body = &src[src.find("fn upgrade_stack(").unwrap()..];
        let body = &body[..body.find("\nfn ").expect("end of upgrade_stack")];
        let at = |needle: &str| body.find(needle).unwrap_or_else(|| panic!("{needle} not in upgrade_stack"));
        let pre = at("addon_preflight(g, &root, &tag");
        assert!(body.contains("addon_preflight(g, &root, &tag, target_stack_lock.as_deref(), allow_downgrade)"),
            "--allow-downgrade is the only way past the add-on downgrade rule on a roll");
        for later in ["reconcile_audit_key(&root)", "systems::reconcile_credentials(&root)", "standalone::materialize(&root)",
                      "NOO_IMAGE_TAG\", &tag", "root.join(\"scripts/noomesh-start.sh\")"] {
            assert!(pre < at(later), "the add-on preflight must run before `{later}`");
        }
        let lock = at("write_stack_lock(g, &tag, &root");
        let pins = at("commit_addon_pins(g, &root, &tag");
        assert!(lock < pins && pins < at("NOO_IMAGE_TAG\", &tag"), "add-on pins are written with stack.lock, before the tag moves");
    }

    #[test]
    fn hold_lines() {
        assert_eq!(super::hold_line("v0.6.0", "v0.6.1", &[("trellion_intel".into(), "x".into())]),
            "v0.6.1 published; held at v0.6.0 by trellion_intel");
        assert!(super::hold_line("v0.6.0", "v0.6.1", &[]).contains("every add-on that is on has a lock for it"));
        let r = crate::addons::resolve::Refusal::NoAnchor;
        assert!(super::addon_hold_fix("evolve", &r).starts_with("noo addons disable evolve"));
        let d = crate::addons::resolve::Refusal::Downgrade { pinned: "2.0.0".into(), offered: "1.0.0".into() };
        assert!(super::addon_hold_fix("evolve", &d).starts_with("noo upgrade --stack --allow-downgrade"));
    }

    #[test]
    fn pick_latest_stack_takes_the_highest_final() {
        let rels = vec![
            ("stack-v0.2.9".to_string(), false),
            ("stack-v0.2.104".to_string(), false),
            ("stack-v0.2.105-rc.1".to_string(), true),
            ("stack-v0.2.106".to_string(), true), // marked prerelease: never latest
            ("stack-v0.2.103".to_string(), false),
            ("noo-cli-v0.9.0".to_string(), false), // other line
        ];
        assert_eq!(super::pick_latest_stack(&rels).as_deref(), Some("0.2.104"));
        assert_eq!(super::pick_latest_stack(&[]), None);
    }
}
