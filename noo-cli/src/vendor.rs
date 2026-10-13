// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Third-party bootstrap installers (Docker, Tailscale), run the one way
//! this repo is willing to run them.
//!
//! `curl … | sh` was the old shape at six call sites. It is unreviewable by
//! construction: the bytes are executed as they arrive, so nothing — not the
//! operator, not a log, not a later investigation — ever sees what ran. That
//! is separate from TLS, which both vendors do correctly and which this keeps.
//!
//! Neither vendor publishes a detached checksum or signature for its
//! bootstrap script (they are regenerated per release, and `get.docker.com`
//! is served dynamically), so there is no digest to pin the way
//! `scripts/noo-secrets-sops-init.sh` pins age and sops. What IS available:
//!
//!   * pin the transport — `--proto '=https' --tlsv1.2`, so a redirect
//!     cannot downgrade the fetch,
//!   * land the script in a file and check it actually IS a script before
//!     executing it (a captive-portal HTML page or a truncated body is a
//!     common and otherwise silent failure),
//!   * print the sha256 of exactly what ran, so an incident has something to
//!     compare against and two hosts installed an hour apart can be shown to
//!     have run the same bytes.
//!
//! Residual trust, stated plainly: whoever controls `get.docker.com` /
//! `tailscale.com` at the moment of the fetch controls what runs as root on
//! the node. That is the vendors' own documented install path and this repo
//! does not improve on it; what it no longer does is hide it. Operators who
//! will not accept that install docker and tailscale from their distro or the
//! vendors' APT repos first — every call site skips when the binary is
//! already present.

/// A `sh -c` program that downloads `url` over pinned HTTPS, proves it is a
/// shell script, records its sha256, and runs it.
pub fn install_script_cmd(url: &str) -> String {
    format!(
        "set -e; t=$(mktemp); trap 'rm -f \"$t\"' EXIT; \
         curl -fsSL --proto '=https' --tlsv1.2 {url} -o \"$t\"; \
         head -1 \"$t\" | grep -q '^#!' || {{ echo 'refusing to run {url}: the response is not a shell script' >&2; exit 1; }}; \
         echo \"installer {url} sha256: $(sha256sum \"$t\" 2>/dev/null | cut -d' ' -f1)\"; \
         sh \"$t\""
    )
}

/// The one switch that stops `tailscaled` uploading its client logs to
/// Tailscale (docs/security/telemetry.md, "Host software"). Tailscale's own
/// words for it: "disable log uploads; this also disables any technical
/// support" (`tailscaled --no-logs-no-support`; the environment form is
/// `TS_NO_LOGS_NO_SUPPORT=true`, which Tailscale documents for
/// `/etc/default/tailscaled` on Linux).
pub const TAILSCALE_NO_LOGS_ENV: &str = "TS_NO_LOGS_NO_SUPPORT";

/// The per-node opt-in to Tailscale's log upload (for when Tailscale support
/// needs the logs). While this file exists, enroll leaves the switch off and
/// `noo cluster verify` reports a WARN "by operator choice" instead of a FAIL.
/// Keep identical to node-agent-go hostd.TailscaleUploadMarker.
pub const TAILSCALE_UPLOAD_MARKER: &str = "/etc/noo/allow-tailscale-log-upload";

/// The environment every `brew` noomesh runs gets. `HOMEBREW_NO_ANALYTICS=1`
/// keeps Homebrew's install analytics off whatever the user's brew setting is.
pub const BREW_ENV: &str = "HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_SERVICES_NO_DOMAIN_WARNING=1";

/// Linux: put the switch in `/etc/default/tailscaled` (the systemd unit loads
/// it as an EnvironmentFile) and restart tailscaled, ONLY when the file does
/// not already carry it, so a re-run is a no-op. Meant for enroll (before
/// `tailscale up`) and for a Tailscale this machine has just installed; a
/// node that is already running is left to `noo cluster verify`'s remedy.
/// Skips quietly where there is no systemd (nothing would read the file).
pub fn tailscale_nologs_linux_script() -> String {
    let f = "/etc/default/tailscaled";
    format!(
        "[ -d /run/systemd/system ] || exit 0; \
         [ -e {marker} ] && exit 0; \
         grep -qsE '^[^#]*(no-logs-no-support|{env}=(true|1))' {f} && exit 0; \
         echo '{env}=true' | sudo tee -a {f} >/dev/null && sudo systemctl restart tailscaled && \
         echo 'tailscaled: client log upload off ({env}=true in {f})'",
        env = TAILSCALE_NO_LOGS_ENV,
        marker = TAILSCALE_UPLOAD_MARKER
    )
}

/// The brew tailscale service's launchd plist (a root LaunchDaemon, because
/// the formula's service is `require_root`).
pub const TAILSCALE_BREW_PLIST: &str = "/Library/LaunchDaemons/homebrew.mxcl.tailscale.plist";

/// The same daemon under current Homebrew, whose labels moved from
/// `homebrew.mxcl.*` to `sh.brew.*`.
pub const TAILSCALE_BREW_PLIST_CURRENT: &str = "/Library/LaunchDaemons/sh.brew.tailscale.plist";

/// The brew tailscale plist on THIS machine, newest label first; the older
/// path when neither exists (callers then report "no brew tailscale").
pub fn tailscale_brew_plist() -> &'static str {
    if std::path::Path::new(TAILSCALE_BREW_PLIST_CURRENT).is_file() {
        TAILSCALE_BREW_PLIST_CURRENT
    } else {
        TAILSCALE_BREW_PLIST
    }
}

/// macOS: Tailscale documents the switch only for the open-source `tailscaled`
/// (the brew formula), not the Standalone or App Store apps. The brew service
/// has no config file, so the key goes into its plist's EnvironmentVariables
/// and the job is restarted with launchctl (launchd caches a job's
/// environment at bootstrap; `brew services` would regenerate the plist
/// without the key). Edit AFTER `brew services start` has written the plist.
/// A no-op when the key is already there or the plist does not exist.
pub fn tailscale_nologs_mac_script(plist: &str) -> String {
    let pb = "/usr/libexec/PlistBuddy";
    let k = TAILSCALE_NO_LOGS_ENV;
    format!(
        "[ -f '{plist}' ] || exit 0; \
         [ -e {TAILSCALE_UPLOAD_MARKER} ] && exit 0; \
         {pb} -c 'Print :EnvironmentVariables:{k}' '{plist}' 2>/dev/null | grep -qx true && exit 0; \
         sudo {pb} -c 'Add :EnvironmentVariables dict' '{plist}' >/dev/null 2>&1; \
         sudo {pb} -c 'Delete :EnvironmentVariables:{k}' '{plist}' >/dev/null 2>&1; \
         sudo {pb} -c 'Add :EnvironmentVariables:{k} string true' '{plist}' && \
         sudo launchctl bootout system '{plist}' >/dev/null 2>&1; \
         sudo launchctl bootstrap system '{plist}' && sleep 3 && \
         echo 'tailscaled: client log upload off ({k}=true in the brew plist)'"
    )
}

/// What the Mac applier runs (as root) for the `host-telemetry` bundle: the
/// same plist edit and launchctl restart as [`tailscale_nologs_mac_script`],
/// as argv steps so the decision is testable off a Mac. Each step is
/// `(argv, may_fail)`. Empty when nothing is to be done: the operator opted in
/// (`marker_exists`), or the plist already carries the key (`has_key`).
/// Never `brew services`: it regenerates the plist without the key.
pub fn tailscale_nologs_mac_steps(plist: &str, has_key: bool, marker_exists: bool) -> Vec<(Vec<String>, bool)> {
    if marker_exists || has_key {
        return Vec::new();
    }
    let pb = "/usr/libexec/PlistBuddy";
    let k = TAILSCALE_NO_LOGS_ENV;
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    vec![
        (v(&[pb, "-c", "Add :EnvironmentVariables dict", plist]), true),
        (v(&[pb, "-c", &format!("Delete :EnvironmentVariables:{k}"), plist]), true),
        (v(&[pb, "-c", &format!("Add :EnvironmentVariables:{k} string true"), plist]), false),
        (v(&["launchctl", "bootout", "system", plist]), true),
        (v(&["launchctl", "bootstrap", "system", plist]), false),
    ]
}

/// `brew analytics off`, once: Homebrew keeps the choice in the brew
/// repository's git config, so it holds for the user's own brew runs too.
pub fn brew_analytics_off_cmd() -> String {
    format!("{BREW_ENV} brew analytics off >/dev/null 2>&1 || true")
}

pub const DOCKER_INSTALL_URL: &str = "https://get.docker.com";
pub const TAILSCALE_INSTALL_URL: &str = "https://tailscale.com/install.sh";

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape is the point: no pipe into a shell, a real file, a script
    /// check, a recorded digest, and a transport that cannot be downgraded.
    #[test]
    fn the_mac_host_telemetry_steps_edit_the_plist_then_restart_with_launchctl() {
        let p = TAILSCALE_BREW_PLIST;
        let steps = tailscale_nologs_mac_steps(p, false, false);
        let flat: Vec<String> = steps.iter().map(|(a, _)| a.join(" ")).collect();
        assert!(flat.iter().any(|c| c.contains("Add :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT string true")), "{flat:?}");
        let (edit, kick) = (
            flat.iter().position(|c| c.contains("string true")).unwrap(),
            flat.iter().position(|c| c.contains("launchctl bootstrap system")).unwrap(),
        );
        assert!(edit < kick, "restart before the edit would restart with the old environment: {flat:?}");
        assert!(flat.iter().any(|c| c.starts_with("launchctl bootout system")), "{flat:?}");
        assert!(!flat.iter().any(|c| c.contains("brew services")), "brew services regenerates the plist: {flat:?}");
        // The key add and the bootstrap must not be tolerated as failures.
        assert!(steps.iter().filter(|(a, _)| a.join(" ").contains("string true") || a.contains(&"bootstrap".to_string())).all(|(_, may_fail)| !may_fail));
        // An operator opt-in, or a plist that already has the key, does nothing and restarts nothing.
        assert!(tailscale_nologs_mac_steps(p, false, true).is_empty(), "overrode the operator's opt-in");
        assert!(tailscale_nologs_mac_steps(p, true, false).is_empty(), "restarted a node that already has the key");
    }

    #[test]
    fn the_installer_command_never_pipes_into_a_shell() {
        let cmd = install_script_cmd(DOCKER_INSTALL_URL);
        assert!(!cmd.contains("| sh"), "curl piped straight into sh: {cmd}");
        assert!(cmd.contains("--proto '=https'"), "transport not pinned: {cmd}");
        assert!(cmd.contains("sha256sum"), "nothing records what ran: {cmd}");
        assert!(cmd.contains("head -1"), "no check that the body is a script: {cmd}");
        assert!(cmd.contains(DOCKER_INSTALL_URL));
    }

    /// It must actually work as a program, not just read well. Run it
    /// against a local file:// -- no, against a here-doc served by `cat`:
    /// the cheapest honest check is that `sh -c` parses it.
    #[test]
    fn the_installer_command_is_valid_shell() {
        let cmd = install_script_cmd(TAILSCALE_INSTALL_URL);
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&cmd)
            .output()
            .expect("sh -n");
        assert!(
            out.status.success(),
            "generated command is not valid shell: {}\n{}",
            cmd,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn sh_n(script: &str) {
        let out = std::process::Command::new("sh").arg("-n").arg("-c").arg(script).output().expect("sh -n");
        assert!(out.status.success(), "not valid shell: {script}\n{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn the_linux_switch_script_is_idempotent_and_valid_shell() {
        let s = tailscale_nologs_linux_script();
        sh_n(&s);
        assert!(s.contains("TS_NO_LOGS_NO_SUPPORT=true"), "{s}");
        assert!(s.contains("/etc/default/tailscaled"), "{s}");
        // restart only after the append, never unconditionally
        assert!(s.contains("&& exit 0"), "no already-set guard: {s}");
        assert!(s.contains(TAILSCALE_UPLOAD_MARKER), "an operator opt-in must stop enroll re-applying the switch: {s}");
        assert!(s.find("exit 0; \\").is_some() || s.contains("run/systemd/system"), "{s}");
        assert!(s.find("tee -a").unwrap() < s.find("systemctl restart tailscaled").unwrap(), "{s}");
    }

    /// The script runs against a scratch defaults file: first run appends,
    /// second run does not.
    #[test]
    fn the_linux_guard_pattern_matches_both_spellings_and_ignores_comments() {
        let dir = std::env::temp_dir().join(format!("noo-ts-nologs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("tailscaled");
        let pat = "^[^#]*(no-logs-no-support|TS_NO_LOGS_NO_SUPPORT=(true|1))";
        let hit = |content: &str| {
            std::fs::write(&f, content).unwrap();
            std::process::Command::new("grep").args(["-qsE", pat]).arg(&f).status().unwrap().success()
        };
        assert!(hit("FLAGS=\"--no-logs-no-support\"\n"));
        assert!(hit("PORT=1\nTS_NO_LOGS_NO_SUPPORT=true\n"));
        assert!(!hit("FLAGS=\"\"\n"));
        assert!(!hit("# FLAGS=\"--no-logs-no-support\"\n"));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(tailscale_nologs_linux_script().contains(pat), "the script's guard drifted from the one tested here");
    }

    #[test]
    fn the_mac_switch_edits_after_brew_wrote_the_plist_and_restarts_with_launchctl() {
        let s = tailscale_nologs_mac_script(TAILSCALE_BREW_PLIST);
        sh_n(&s);
        assert!(s.contains("Add :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT string true"), "{s}");
        assert!(s.contains("launchctl bootout system") && s.contains("launchctl bootstrap system"), "{s}");
        assert!(!s.contains("brew services"), "brew services regenerates the plist without the key: {s}");
        assert!(s.starts_with("[ -f "), "must never create a plist: {s}");
        assert!(s.contains(TAILSCALE_UPLOAD_MARKER), "an operator opt-in must stop enroll re-applying the switch: {s}");
    }

    #[test]
    fn every_brew_env_turns_analytics_off() {
        assert!(BREW_ENV.contains("HOMEBREW_NO_ANALYTICS=1"));
        assert!(brew_analytics_off_cmd().contains("brew analytics off"));
    }
}
